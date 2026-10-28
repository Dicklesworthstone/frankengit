//! Runtime-owned continuous maintenance using the standalone durable controller.
//!
//! This adapter does not spawn a thread. Its caller owns the blocking service
//! lane, requests stop and joins the returned result before shutting down its
//! parent. Every native attempt retains one original finite request context.
use super::*;
use fgit_runtime::BudgetClass;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const DEFAULT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(300);

/// An explicit, immutable profile and reference scope for one progress owner.
#[derive(Clone, Debug)]
pub struct MaintenanceConfig {
    kind: IndexKind,
    format: GitHashAlgorithm,
    directory: PathBuf,
    initialize: bool,
    interval: Duration,
    refs: Vec<RefName>,
    attempt_timeout: Duration,
}
impl MaintenanceConfig {
    /// Validate the complete scope before opening a node or taking ownership.
    /// The interval follows a completed pass, rather than a fixed wall clock.
    pub fn try_new(
        kind: IndexKind,
        format: GitHashAlgorithm,
        directory: PathBuf,
        initialize: bool,
        interval: Duration,
        mut refs: Vec<RefName>,
    ) -> io::Result<Self> {
        if directory.as_os_str().is_empty() || directory.as_os_str().len() > 4096 {
            return Err(invalid("Invalid maintenance progress directory."));
        }
        if interval.as_secs() == 0 || interval.as_secs() > 3600 || interval.subsec_nanos() != 0 {
            return Err(invalid(
                "Maintenance interval must be a whole number of seconds from 1 through 3600.",
            ));
        }
        if refs.is_empty() || refs.len() > state::MAX_REFS {
            return Err(invalid(
                "Maintenance requires 1 through 32 explicit references.",
            ));
        }
        refs.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        if refs.windows(2).any(|pair| pair[0] == pair[1])
            || refs
                .iter()
                .any(|r| r.as_bytes().len() > 1024 || !r.as_bytes().starts_with(b"refs/"))
            || refs.iter().map(|r| r.as_bytes().len()).sum::<usize>() > 16 * 1024
        {
            return Err(invalid("Invalid or duplicate maintenance reference scope."));
        }
        Ok(Self {
            kind,
            format,
            directory,
            initialize,
            interval,
            refs,
            attempt_timeout: DEFAULT_ATTEMPT_TIMEOUT,
        })
    }

    #[must_use]
    pub const fn kind(&self) -> IndexKind {
        self.kind
    }

    #[must_use]
    pub const fn format(&self) -> GitHashAlgorithm {
        self.format
    }

    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    #[must_use]
    pub const fn initialize(&self) -> bool {
        self.initialize
    }

    #[must_use]
    pub const fn interval(&self) -> Duration {
        self.interval
    }

    #[must_use]
    pub fn refs(&self) -> &[RefName] {
        &self.refs
    }

    /// Tighten each native attempt's background-controller timeout. This never
    /// widens an inherited timeout, work/cost quota or any other runtime class.
    pub fn with_attempt_timeout(mut self, timeout: Duration) -> io::Result<Self> {
        if timeout.as_secs() == 0 || timeout.as_secs() > 3600 || timeout.subsec_nanos() != 0 {
            return Err(invalid(
                "Maintenance attempt timeout must be whole seconds from 1 through 3600.",
            ));
        }
        self.attempt_timeout = timeout;
        Ok(self)
    }

    #[must_use]
    pub const fn attempt_timeout(&self) -> Duration {
        self.attempt_timeout
    }
}

/// One or both independently checkpointed index profiles owned by a service.
///
/// Each profile retains its own reference scope, finite attempt policy and
/// private progress directory. Grouping only coordinates their lifetime; it
/// does not merge their generation authorities or make a mixed-source query
/// valid. Queries still require their normal exact-source generation join.
#[derive(Clone, Debug)]
pub struct MaintenanceGroup {
    configs: Vec<MaintenanceConfig>,
}

impl MaintenanceGroup {
    /// Validate a bounded group before acquiring any progress ownership.
    /// Aliased filesystem directories are additionally refused by each native
    /// progress owner's existing exclusive lock and namespace binding.
    pub fn try_new(mut configs: Vec<MaintenanceConfig>) -> io::Result<Self> {
        if configs.is_empty() || configs.len() > 2 {
            return Err(invalid("Maintenance requires one or two index profiles."));
        }
        if configs.len() == 2 {
            let left = &configs[0];
            let right = &configs[1];
            if left.kind == right.kind {
                return Err(invalid("Maintenance profiles must be distinct."));
            }
            if left.directory == right.directory {
                return Err(invalid(
                    "Maintenance profiles require separate progress directories.",
                ));
            }
            if left.format != right.format {
                return Err(invalid(
                    "Maintenance profiles must use the same Git object format.",
                ));
            }
        }
        configs.sort_by_key(|config| match config.kind {
            IndexKind::Lexical => 0,
            IndexKind::Symbols => 1,
        });
        Ok(Self { configs })
    }

    #[must_use]
    pub fn configs(&self) -> &[MaintenanceConfig] {
        &self.configs
    }

    /// Consume the group and return its configurations in profile order.
    #[must_use]
    pub fn into_configs(self) -> Vec<MaintenanceConfig> {
        self.configs
    }
}

impl From<MaintenanceConfig> for MaintenanceGroup {
    fn from(config: MaintenanceConfig) -> Self {
        Self {
            configs: vec![config],
        }
    }
}

/// Irreversible cooperative stop shared with the service's owning parent.
#[derive(Clone, Debug, Default)]
pub struct MaintenanceControl {
    requested: Arc<AtomicBool>,
}
impl MaintenanceControl {
    /// Request cancellation between attempts and on the original active context.
    /// The owner must still wait for the service result; this is not a join.
    pub fn request_stop(&self) {
        self.requested.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_stop_requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }
}

/// Bounded counters for observations made before the service explicitly drained.
/// They do not assert that a ref is still current when the receipt is returned.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MaintenanceReceipt {
    /// Passes started, including a pass interrupted between references.
    pub passes: u64,
    pub attempts: u64,
    pub observed_current: u64,
    pub recovered: u64,
    pub refused: u64,
    /// References still carrying their original unresolved candidate.
    pub pending: usize,
}

/// Startup, controller and cleanup failures retain their distinct ownership stage.
#[derive(Debug)]
pub enum MaintenanceError {
    Configuration(io::Error),
    Open(String),
    Authority(String),
    Progress(io::Error),
    Ready(io::Error),
    Controller(io::Error),
    Shutdown {
        error: String,
        preceding: Option<Box<Self>>,
    },
    Release {
        error: io::Error,
        preceding: Option<Box<Self>>,
    },
}
impl Display for MaintenanceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(error) => write!(formatter, "Maintenance configuration: {error}"),
            Self::Open(error) => write!(formatter, "Maintenance node open: {error}"),
            Self::Authority(error) => write!(formatter, "Maintenance authority: {error}"),
            Self::Progress(error) => write!(formatter, "Maintenance progress: {error}"),
            Self::Ready(error) => write!(formatter, "Maintenance readiness: {error}"),
            Self::Controller(error) => write!(formatter, "Maintenance controller: {error}"),
            Self::Shutdown { error, preceding } => {
                write!(
                    formatter,
                    "Maintenance shutdown failed; ownership retained: {error}"
                )?;
                if let Some(preceding) = preceding {
                    write!(formatter, "; preceding failure: {preceding}")?;
                }
                Ok(())
            }
            Self::Release { error, preceding } => {
                write!(formatter, "Maintenance progress release: {error}")?;
                if let Some(preceding) = preceding {
                    write!(formatter, "; preceding failure: {preceding}")?;
                }
                Ok(())
            }
        }
    }
}
impl Error for MaintenanceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Configuration(error)
            | Self::Progress(error)
            | Self::Ready(error)
            | Self::Controller(error)
            | Self::Release { error, .. } => Some(error),
            Self::Shutdown { preceding, .. } => preceding
                .as_deref()
                .map(|error| error as &(dyn Error + 'static)),
            Self::Open(_) | Self::Authority(_) => None,
        }
    }
}

pub(super) fn increment(value: &mut u64) -> io::Result<()> {
    *value = value
        .checked_add(1)
        .ok_or_else(|| invalid("Maintenance receipt counter exhausted."))?;
    Ok(())
}

/// Meet the service ceiling with the actual background class before opening its
/// runtime. Preserve every inherited non-time dimension and every other class.
fn bounded_node_config(
    node_config: NodeConfig,
    timeout: Duration,
) -> Result<NodeConfig, MaintenanceError> {
    let inherited = node_config.runtime_budgets();
    let mut background = inherited.limits_for(BudgetClass::BackgroundController);
    background.timeout = Some(
        background
            .timeout
            .map_or(timeout, |limit| limit.min(timeout)),
    );
    let narrowed = inherited
        .with_class_limits(BudgetClass::BackgroundController, background)
        .map_err(|error| MaintenanceError::Configuration(invalid(error.to_string())))?;
    Ok(node_config.with_runtime_budgets(narrowed))
}

/// Run the service on the caller's owned blocking lane until cooperative stop.
pub fn run_service(
    node_config: NodeConfig,
    config: MaintenanceConfig,
    control: MaintenanceControl,
) -> Result<MaintenanceReceipt, MaintenanceError> {
    run_service_with_ready(node_config, config, control, || Ok(()))
}

/// Announce readiness only after the existing node, canonical authority and
/// exclusive bound progress have all opened successfully. No native index
/// attempt starts before the callback returns successfully. The callback must
/// not block waiting for work from this same lane.
pub fn run_service_with_ready(
    node_config: NodeConfig,
    config: MaintenanceConfig,
    control: MaintenanceControl,
    on_ready: impl FnOnce() -> io::Result<()>,
) -> Result<MaintenanceReceipt, MaintenanceError> {
    if !cfg!(unix)
        || internal_algorithm_id(IdentityDomain::Generation).code_point() != 2
        || CANONICAL_CODEC_VERSION != fgit_types::CodecVersion::new(1, 0)
    {
        return Err(MaintenanceError::Configuration(io::Error::new(
            io::ErrorKind::Unsupported,
            "Maintenance progress requires Unix and SHA-256 generation codec v1.",
        )));
    }
    let node_config = bounded_node_config(node_config, config.attempt_timeout)?;
    let mut node = OneNode::open_existing(node_config.with_object_format(config.format))
        .map_err(|error| MaintenanceError::Open(error.to_string()))?;
    let ready = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .map_err(|error| error.to_string())
        .and_then(|head| {
            node.bring_into_service(head.receipt().generation())
                .map_err(|error| error.to_string())
        });
    if let Err(error) = ready {
        return finish(node, None, Err(MaintenanceError::Authority(error)), false);
    }
    let binding = config.kind.bind(format!(
        "{} {} {} {}",
        node.tenant_id(),
        node.repository_id(),
        node.repository_incarnation_id(),
        config.format.as_str()
    ));
    let refs = config
        .refs
        .iter()
        .map(|reference| reference.as_bytes().to_vec())
        .collect::<Vec<_>>();
    let progress = State::new(binding, &refs)
        .and_then(|state| ProgressFile::open(&config.directory, config.initialize, state));
    let mut progress = match progress {
        Ok(progress) => progress,
        Err(error) => {
            return finish(node, None, Err(MaintenanceError::Progress(error)), false);
        }
    };
    if progress.state.rows.values().any(|row| row.running) {
        return finish(
            node,
            Some(progress),
            Err(MaintenanceError::Controller(invalid(
                "An interrupted attempt has no recorded candidate. Inspect it before resuming; do not reset the checkpoint.",
            ))),
            false,
        );
    }
    let mut stop = Stop {
        control: Some(control.clone()),
        ..Stop::default()
    };
    stop.observe(&config.directory);
    if stop.requested {
        // A service owner can stop while this child is still authenticating
        // or acquiring progress. It has started no index work. Release its
        // healthy ownership and retain any pending recovery debt in the
        // drained receipt, without announcing readiness.
        if control.is_stop_requested() && stop.error.is_none() {
            let receipt = MaintenanceReceipt {
                pending: progress
                    .state
                    .rows
                    .values()
                    .filter(|row| row.pending.is_some())
                    .count(),
                ..MaintenanceReceipt::default()
            };
            return finish(node, Some(progress), Ok(receipt), true);
        }
        let error = invalid(
            stop.error
                .unwrap_or_else(|| "Maintenance was stopped before readiness.".to_owned()),
        );
        return finish(
            node,
            Some(progress),
            Err(MaintenanceError::Ready(error)),
            true,
        );
    }
    let announced = catch_unwind(AssertUnwindSafe(on_ready))
        .unwrap_or_else(|_| Err(io::Error::other("Maintenance readiness callback panicked.")));
    if let Err(error) = announced {
        return finish(
            node,
            Some(progress),
            Err(MaintenanceError::Ready(error)),
            true,
        );
    }
    let options = Options {
        root: PathBuf::new(),
        tenant: node.tenant_id(),
        repository: node.repository_id(),
        format: config.format,
        directory: config.directory,
        initialize: config.initialize,
        passes: 1,
        interval: config.interval,
        refs: config.refs,
        profile: config.kind,
        output: ProgressOutput::Stderr,
    };
    let mut receipt = MaintenanceReceipt::default();
    let result = (|| {
        loop {
            stop.observe(&options.directory);
            if stop.requested {
                break;
            }
            // Ordinary native refusal is a bounded observation. A future pass
            // may try again only after the previous owner has returned.
            let _ = run_controlled(
                &node,
                &options,
                &mut progress,
                Some(control.clone()),
                &mut receipt,
            )
            .map_err(MaintenanceError::Controller)?;
            stop.observe(&options.directory);
            wait(&node, &options.directory, options.interval, &mut stop);
        }
        if let Some(error) = stop.error {
            return Err(MaintenanceError::Controller(invalid(format!(
                "Stop control failed after drain: {error}"
            ))));
        }
        receipt.pending = progress
            .state
            .rows
            .values()
            .filter(|row| row.pending.is_some())
            .count();
        Ok(receipt)
    })();
    finish(node, Some(progress), result, false)
}

/// Only an observed native shutdown permits progress release. Controller
/// failures preserve the original owner/marker, matching the standalone worker.
/// Effect-free readiness failure may release after that same explicit shutdown.
fn finish(
    node: OneNode,
    progress: Option<ProgressFile>,
    result: Result<MaintenanceReceipt, MaintenanceError>,
    release_after_error: bool,
) -> Result<MaintenanceReceipt, MaintenanceError> {
    if let Err(error) = node.shutdown() {
        return Err(MaintenanceError::Shutdown {
            error: error.to_string(),
            preceding: result.err().map(Box::new),
        });
    }
    if result.is_ok() || release_after_error {
        if let Some(progress) = progress {
            if let Err(error) = progress.release() {
                return Err(MaintenanceError::Release {
                    error,
                    preceding: result.err().map(Box::new),
                });
            }
        }
    }
    result
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
