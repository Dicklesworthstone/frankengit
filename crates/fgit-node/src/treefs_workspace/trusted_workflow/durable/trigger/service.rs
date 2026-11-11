//! An explicitly configured trusted workflow controller on an owned service lane.
//! Canonical event selection, execution custody and check admission remain in
//! the existing native watcher. No remote request can configure this service.

use super::super::super::validate_inputs;
pub use super::pull_request_merge::PullRequestMergeWatchConfig;
pub use super::queue_landing::TrustedQueueLanding;
pub use super::queue_refresh::{QueueRefreshMode, TrustedQueueRefresh};
use super::{
    Owner, check_directory, hex, lower_hash, merge_queue, pull_request, pull_request_merge,
    queue_refresh, reporting,
};
use crate::treefs_workspace::TrustedWorkflowArtifactConfig;
use crate::{GitDaemonSessionTimeout, NodeConfig, NodeRequestContext, OneNode};
use fgit_runner::workflow::WorkflowLimits;
use fgit_types::{GitHashAlgorithm, PrincipalId, RefName};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const STOP_POLL: Duration = Duration::from_millis(10);
mod pull_requests;

/// Immutable operator selection for one trusted branch, tag or same-repository PR.
///
/// Constructing this configuration authorizes every future selected script to
/// run with the host user's privileges. It must never be built from an HTTP,
/// MCP or other untrusted request. Inputs select source files, not isolation.
#[derive(Clone, Debug)]
pub struct WorkflowWatchConfig {
    format: GitHashAlgorithm,
    reference: RefName,
    directory: Vec<u8>,
    run_parent: PathBuf,
    inputs: Vec<Vec<u8>>,
    interval: Duration,
    attempt_timeout: GitDaemonSessionTimeout,
    publisher: Option<PrincipalId>,
    landing_principal: Option<PrincipalId>,
    queue_refresh_principal: Option<PrincipalId>,
    pull_request: Option<u64>,
    pull_requests: Option<usize>,
    merge_queue: Option<u64>,
    merge_candidate: Option<PullRequestMergeWatchConfig>,
    limits: WorkflowLimits,
    artifacts: Option<TrustedWorkflowArtifactConfig>,
}

impl WorkflowWatchConfig {
    /// Validate the bounded selection without opening storage or executing code.
    pub fn try_new(
        format: GitHashAlgorithm,
        reference: RefName,
        directory: Vec<u8>,
        run_parent: PathBuf,
        inputs: Vec<Vec<u8>>,
        interval: Duration,
    ) -> io::Result<Self> {
        if !(reference.as_bytes().starts_with(b"refs/heads/")
            || reference.as_bytes().starts_with(b"refs/tags/"))
            || reference.as_bytes().len() > 4096
            || directory.len() > 4096
            || run_parent.as_os_str().as_bytes().len() > 4096
            || interval < Duration::from_millis(10)
            || interval > Duration::from_secs(60)
        {
            return Err(invalid(
                "workflow service selection exceeds its bounded profile",
            ));
        }
        validate_inputs(&directory, [1; 16], &run_parent, &inputs)
            .map_err(|error| invalid(error.to_string()))?;
        Ok(Self {
            format,
            reference,
            directory,
            run_parent,
            inputs,
            interval,
            attempt_timeout: GitDaemonSessionTimeout::DEFAULT,
            publisher: None,
            landing_principal: None,
            queue_refresh_principal: None,
            pull_request: None,
            pull_requests: None,
            merge_queue: None,
            merge_candidate: None,
            limits: WorkflowLimits::default(),
            artifacts: None,
        })
    }

    /// One finite deadline covers reconciliation, source selection, execution,
    /// check publication and optional landing. A later poll starts only after
    /// this attempt drains.
    pub fn with_attempt_timeout(mut self, timeout: Duration) -> io::Result<Self> {
        if timeout > Duration::from_secs(3600) {
            return Err(invalid(
                "workflow service attempt timeout exceeds 3600 seconds",
            ));
        }
        self.attempt_timeout = GitDaemonSessionTimeout::try_new(timeout)
            .map_err(|error| invalid(error.to_string()))?;
        Ok(self)
    }

    /// The caller must be authorized to publish as this principal. The first
    /// native publication binds it permanently to the existing custody scope.
    /// Tag execution cannot publish checks; [`Self::validate`] and service
    /// startup refuse that combination before opening storage or custody.
    #[must_use]
    pub const fn with_publisher(mut self, publisher: PrincipalId) -> Self {
        self.publisher = Some(publisher);
        self
    }

    /// Explicit trusted-operator authority to land the exact tested queue head
    /// through ordinary protected queue admission. This identity is separate
    /// from the CI branch writer and check publisher and binds durably on first
    /// use. [`Self::validate`] requires a complete queue candidate and publisher;
    /// this option does not grant an HTTP caller any additional permission.
    #[must_use]
    pub const fn with_landing_principal(mut self, principal: PrincipalId) -> Self {
        self.landing_principal = Some(principal);
        self
    }

    /// Separate trusted-operator authority for queue-head metadata management
    /// and its sole PR Update after the target advances. No CI, check, read or
    /// landing identity implies this grant. The first retained intent binds it
    /// permanently; omitted authority cannot bypass pending original custody.
    /// This initial profile requires the complete automatic queue landing mode.
    #[must_use]
    pub const fn with_queue_refresh_principal(mut self, principal: PrincipalId) -> Self {
        self.queue_refresh_principal = Some(principal);
        self
    }

    pub fn with_pull_request(mut self, number: u64) -> io::Result<Self> {
        if !self.reference.as_bytes().starts_with(b"refs/heads/")
            || number == 0
            || self.merge_queue.is_some()
            || self.pull_requests.is_some()
        {
            return Err(invalid(
                "workflow service requires a branch and positive PR number and excludes a queue selector",
            ));
        }
        self.pull_request = Some(number);
        Ok(self)
    }

    /// Discover visible open native PRs targeting the fixed `reference`.
    /// Every retained PR, including closed or hidden members, counts toward
    /// this lifetime custody bound and is reconciled before new execution.
    /// Source-head execution is the default. Explicit collection candidate
    /// configuration selects a distinct CI branch for each canonical PR.
    pub fn with_pull_requests(mut self, max_members: usize) -> io::Result<Self> {
        if !self.reference.as_bytes().starts_with(b"refs/heads/")
            || !(1..=64).contains(&max_members)
            || self.pull_request.is_some()
            || self.merge_queue.is_some()
        {
            return Err(invalid(
                "PR collection requires a branch and 1..64 retained members and excludes fixed PR and queue selectors",
            ));
        }
        self.pull_requests = Some(max_members);
        Ok(self)
    }

    /// Follow the current head of one canonical queue bound to `reference`,
    /// which is the fixed target branch in this mode. A two-parent candidate
    /// configuration is mandatory before this service can start. Queue changes
    /// do not change its permanent custody scope or grant target publication.
    pub fn with_merge_queue(mut self, number: u64) -> io::Result<Self> {
        if !self.reference.as_bytes().starts_with(b"refs/heads/")
            || number == 0
            || self.pull_request.is_some()
            || self.pull_requests.is_some()
        {
            return Err(invalid(
                "workflow service requires a branch and positive queue number and excludes a PR selector",
            ));
        }
        if self.merge_candidate.as_ref().is_some_and(|merge| {
            merge.style() != fgit_forge::preparation::MergeCommitStyle::TwoParent
        }) {
            return Err(invalid(
                "queue workflow service requires two-parent candidates",
            ));
        }
        self.merge_queue = Some(number);
        Ok(self)
    }

    /// Select exact merge-candidate execution after choosing the canonical PR.
    /// The fixed CI ref must differ from the source; its target is checked when
    /// the current PR is selected. This authorizes ordinary exact-old rewrites.
    pub fn with_merge_candidate(mut self, config: PullRequestMergeWatchConfig) -> io::Result<Self> {
        if !self.reference.as_bytes().starts_with(b"refs/heads/")
            || self.pull_requests.is_some()
            || (self.pull_request.is_none() && self.merge_queue.is_none())
            || config.reference() == &self.reference
        {
            return Err(invalid(
                "merge candidate requires a PR and a distinct CI branch",
            ));
        }
        merge_queue::validate_selection(
            &self.reference,
            self.pull_request,
            self.merge_queue,
            Some(&config),
        )
        .map_err(|error| invalid(error.to_string()))?;
        self.merge_candidate = Some(config);
        Ok(self)
    }

    /// Test each discovered PR's actual combined tree on a distinct CI ref.
    /// The configuration's reference is an operator-owned namespace stem:
    /// PR `n` uses `<stem>/pr-<n>`, never the stem itself. This separately
    /// authorizes ordinary exact-old creation/replacement of those CI refs.
    /// The namespace, writer and deterministic commit inputs bind permanently
    /// to the collection's existing custody scope; changing modes cannot
    /// abandon source-head executions already owned by that collection.
    pub fn with_pull_request_merge_candidates(
        mut self,
        config: PullRequestMergeWatchConfig,
    ) -> io::Result<Self> {
        if self.pull_requests.is_none() || self.pull_request.is_some() || self.merge_queue.is_some()
        {
            return Err(invalid(
                "collection merge candidates require a PR collection selector",
            ));
        }
        pull_requests::validate_candidate_namespace(&config, &self.reference)?;
        self.merge_candidate = Some(config);
        Ok(self)
    }

    /// Validate the complete operator configuration without opening storage,
    /// acquiring custody or admitting execution. Call after composing operator
    /// options; this final check also guards infallible publisher selection.
    pub fn validate(&self) -> io::Result<()> {
        if self.pull_requests.is_some()
            && let Some(merge) = &self.merge_candidate
        {
            pull_requests::validate_candidate_namespace(merge, &self.reference)?;
        }
        if self.reference.as_bytes().starts_with(b"refs/tags/")
            && (self.publisher.is_some()
                || self.landing_principal.is_some()
                || self.queue_refresh_principal.is_some()
                || self.pull_request.is_some()
                || self.pull_requests.is_some()
                || self.merge_queue.is_some()
                || self.merge_candidate.is_some())
        {
            return Err(invalid(
                "tag workflow service supports ordinary execution only; check publication, PR and queue modes require a branch",
            ));
        }
        if self.queue_refresh_principal.is_some()
            && (self.merge_queue.is_none()
                || self.merge_candidate.is_none()
                || self.publisher.is_none()
                || self.landing_principal.is_none())
        {
            return Err(invalid(
                "automatic queue refresh requires a queue, merge candidate, check publisher and explicit landing principal",
            ));
        }
        if self.landing_principal.is_some()
            && (self.merge_queue.is_none()
                || self.merge_candidate.is_none()
                || self.publisher.is_none())
        {
            return Err(invalid(
                "automatic queue landing requires a queue, merge candidate and check publisher",
            ));
        }
        merge_queue::validate_selection(
            &self.reference,
            self.pull_request,
            self.merge_queue,
            self.merge_candidate.as_ref(),
        )
        .map_err(|error| invalid(error.to_string()))
    }

    pub fn with_limits(mut self, limits: WorkflowLimits) -> io::Result<Self> {
        limits
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        self.limits = limits;
        Ok(self)
    }

    #[must_use]
    pub fn with_artifacts(mut self, artifacts: TrustedWorkflowArtifactConfig) -> Self {
        self.artifacts = Some(artifacts);
        self
    }

    #[must_use]
    pub const fn format(&self) -> GitHashAlgorithm {
        self.format
    }
    #[must_use]
    pub const fn reference(&self) -> &RefName {
        &self.reference
    }
    #[must_use]
    pub fn directory(&self) -> &[u8] {
        &self.directory
    }
    #[must_use]
    pub fn run_parent(&self) -> &Path {
        &self.run_parent
    }
    #[must_use]
    pub fn inputs(&self) -> &[Vec<u8>] {
        &self.inputs
    }
    #[must_use]
    pub const fn interval(&self) -> Duration {
        self.interval
    }
    #[must_use]
    pub const fn attempt_timeout(&self) -> Duration {
        self.attempt_timeout.duration()
    }
    #[must_use]
    pub const fn publisher(&self) -> Option<PrincipalId> {
        self.publisher
    }
    #[must_use]
    pub const fn landing_principal(&self) -> Option<PrincipalId> {
        self.landing_principal
    }
    #[must_use]
    pub const fn queue_refresh_principal(&self) -> Option<PrincipalId> {
        self.queue_refresh_principal
    }
    #[must_use]
    pub const fn pull_request(&self) -> Option<u64> {
        self.pull_request
    }
    #[must_use]
    pub const fn pull_requests(&self) -> Option<usize> {
        self.pull_requests
    }
    #[must_use]
    pub const fn merge_queue(&self) -> Option<u64> {
        self.merge_queue
    }
    #[must_use]
    pub const fn merge_candidate(&self) -> Option<&PullRequestMergeWatchConfig> {
        self.merge_candidate.as_ref()
    }
    #[must_use]
    pub const fn artifacts(&self) -> Option<&TrustedWorkflowArtifactConfig> {
        self.artifacts.as_ref()
    }
}

/// Irreversible cooperative stop. The executable owns signals and stop files;
/// this library only observes its listener or embedding owner's explicit token.
#[derive(Clone, Debug, Default)]
pub struct WorkflowWatchControl(Arc<AtomicBool>);

impl WorkflowWatchControl {
    pub fn request_stop(&self) {
        self.0.store(true, Ordering::Release);
    }
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Service observations, not a passing check or proof of transaction rollback.
/// Canonical check decisions and original execution custody remain authoritative.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WorkflowWatchReceipt {
    pub polls: u64,
    pub dispatched: u64,
    pub checks_committed: u64,
    pub checks_refused: u64,
    pub refreshes_committed: u64,
    pub refreshes_refused: u64,
    pub refreshes_previously_decided: u64,
    pub refreshes_waiting: u64,
    pub refresh_pending: bool,
    pub landings_committed: u64,
    pub landings_refused: u64,
    pub landings_previously_decided: u64,
    pub landings_waiting: u64,
    pub landings_stale: u64,
    pub non_green: bool,
    pub interrupted: bool,
    pub requires_reconciliation: bool,
    /// Observed publication responsibility not yet cleared by a complete pass.
    /// Cancellation of a read-only recovery scan alone does not create it.
    pub publication_pending: bool,
    /// Last observed retained candidate intents still awaiting a completed
    /// first dispatch. A partial scan cannot clear prior pending responsibility.
    pub pending_execution: u64,
    pub node_closed: bool,
    pub service_failed: bool,
}

impl WorkflowWatchReceipt {
    #[must_use]
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                "{{\"type\":\"workflow_service_drained\",\"schema_version\":1,",
                "\"polls\":{},\"dispatched\":{},\"checks_committed\":{},",
                "\"checks_refused\":{},\"refreshes_committed\":{},\"refreshes_refused\":{},",
                "\"refreshes_previously_decided\":{},\"refreshes_waiting\":{},\"refresh_pending\":{},",
                "\"landings_committed\":{},\"landings_refused\":{},",
                "\"landings_previously_decided\":{},\"landings_waiting\":{},\"landings_stale\":{},",
                "\"non_green\":{},\"interrupted\":{},",
                "\"requires_reconciliation\":{},\"publication_pending\":{},\"pending_execution\":{},",
                "\"node_closed\":{},\"service_failed\":{},\"execution_retried\":false}}"
            ),
            self.polls,
            self.dispatched,
            self.checks_committed,
            self.checks_refused,
            self.refreshes_committed,
            self.refreshes_refused,
            self.refreshes_previously_decided,
            self.refreshes_waiting,
            self.refresh_pending,
            self.landings_committed,
            self.landings_refused,
            self.landings_previously_decided,
            self.landings_waiting,
            self.landings_stale,
            self.non_green,
            self.interrupted,
            self.requires_reconciliation,
            self.publication_pending,
            self.pending_execution,
            self.node_closed,
            self.service_failed,
        )
    }
}

#[derive(Debug)]
pub enum WorkflowWatchError {
    Configuration(String),
    Open(String),
    Authority(String),
    Custody(String),
    StoppedBeforeReadiness,
    /// Internal bounded discovery/metadata checkpoint, before new execution.
    CollectionSelectionStopped,
    Ready(io::Error),
    Attempt(String),
    Shutdown {
        error: String,
        preceding: Option<Box<Self>>,
    },
    WithReceipt {
        error: Box<Self>,
        receipt: WorkflowWatchReceipt,
    },
}

impl WorkflowWatchError {
    /// Retain observed counts even when later execution, output or shutdown
    /// fails. Failure never erases an earlier canonical publication observation.
    #[must_use]
    pub const fn receipt(&self) -> Option<&WorkflowWatchReceipt> {
        match self {
            Self::WithReceipt { receipt, .. } => Some(receipt),
            _ => None,
        }
    }

    /// A typed owner-requested startup stop, with native shutdown completed.
    /// Independent custody, publication and shutdown errors never match it.
    #[must_use]
    pub fn stopped_before_readiness(&self) -> bool {
        match self {
            Self::StoppedBeforeReadiness => true,
            Self::WithReceipt { error, receipt } => {
                receipt.node_closed && error.stopped_before_readiness()
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for WorkflowWatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Configuration(error) => write!(f, "configure workflow service: {error}"),
            Self::Open(error) => write!(f, "open workflow service: {error}"),
            Self::Authority(error) => write!(f, "authenticate workflow service: {error}"),
            Self::Custody(error) => write!(f, "workflow service custody: {error}"),
            Self::StoppedBeforeReadiness => write!(f, "workflow service stopped before readiness"),
            Self::CollectionSelectionStopped => write!(
                f,
                "workflow collection request stopped before further admission"
            ),
            Self::Ready(error) => write!(f, "workflow service readiness: {error}"),
            Self::Attempt(error) => write!(
                f,
                "workflow service stopped; preserve original event custody: {error}"
            ),
            Self::Shutdown { error, preceding } => {
                if let Some(preceding) = preceding {
                    write!(f, "{preceding}; ")?;
                }
                write!(f, "workflow service node shutdown failed: {error}")
            }
            Self::WithReceipt { error, .. } => error.fmt(f),
        }
    }
}
impl std::error::Error for WorkflowWatchError {}

fn invalid(detail: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, detail.into())
}

/// Run on the caller's owned service lane. No thread, process-wide signal
/// handler, listener, or alternative workflow executor is created here.
pub fn run_service(
    node_config: NodeConfig,
    config: WorkflowWatchConfig,
    control: WorkflowWatchControl,
) -> Result<WorkflowWatchReceipt, WorkflowWatchError> {
    run_service_with_ready(node_config, config, control, || Ok(()))
}

/// Readiness follows authority authentication, exclusive service ownership,
/// validation of retained execution custody and pending check reconciliation.
/// Verified never-started candidate intents remain pending through readiness;
/// neither their CI publication nor their first script starts before the
/// readiness callback succeeds.
pub fn run_service_with_ready(
    node_config: NodeConfig,
    config: WorkflowWatchConfig,
    control: WorkflowWatchControl,
    on_ready: impl FnOnce() -> io::Result<()>,
) -> Result<WorkflowWatchReceipt, WorkflowWatchError> {
    config
        .validate()
        .map_err(|error| WorkflowWatchError::Configuration(error.to_string()))?;
    let mut node = OneNode::open_existing(node_config.with_object_format(config.format))
        .map_err(|error| WorkflowWatchError::Open(error.to_string()))?;
    let mut custody = None;
    let mut receipt = WorkflowWatchReceipt::default();
    let result = (|| {
        let head = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .map_err(|error| WorkflowWatchError::Authority(error.to_string()))?;
        node.bring_into_service(head.receipt().generation())
            .map_err(|error| WorkflowWatchError::Authority(error.to_string()))?;
        custody = Some(ServiceCustody::open(
            &node,
            &config,
            &control,
            &mut receipt,
        )?);
        if control.is_stopped() {
            return Err(WorkflowWatchError::StoppedBeforeReadiness);
        }
        if config.publisher.is_some() && config.pull_requests.is_none() {
            controlled(&node, &config, &control, &mut receipt, false)?;
        }
        if control.is_stopped() || receipt.interrupted {
            return Err(WorkflowWatchError::StoppedBeforeReadiness);
        }
        catch_unwind(AssertUnwindSafe(on_ready))
            .unwrap_or_else(|_| Err(io::Error::other("workflow readiness callback panicked")))
            .map_err(WorkflowWatchError::Ready)?;
        while !control.is_stopped() {
            custody.as_mut().expect("opened custody").poll(
                &node,
                &config,
                &control,
                &mut receipt,
            )?;
            if control.is_stopped() {
                break;
            }
            let waiting = Instant::now();
            while !control.is_stopped() && waiting.elapsed() < config.interval {
                node.runtime()
                    .wait_for(STOP_POLL.min(config.interval.saturating_sub(waiting.elapsed())));
            }
        }
        Ok(())
    })();
    // Readiness failure or an operator stop may occur before the first
    // recovery pass. Retained refresh responsibility remains visible on exit,
    // without a sticky flag blocking a successfully recovered active poll.
    receipt.requires_reconciliation |= receipt.refresh_pending;
    if let Err(error) = node.shutdown() {
        // Keep this controller's lock until process exit when node quiescence
        // was not established. Existing event markers also prohibit reexecution.
        if let Some(custody) = custody {
            std::mem::forget(custody);
        }
        receipt.service_failed = true;
        return Err(WorkflowWatchError::WithReceipt {
            error: Box::new(WorkflowWatchError::Shutdown {
                error: error.to_string(),
                preceding: result.err().map(Box::new),
            }),
            receipt,
        });
    }
    receipt.node_closed = true;
    drop(custody);
    match result {
        Ok(()) => Ok(receipt),
        Err(error) => {
            receipt.service_failed = !error.stopped_before_readiness();
            Err(WorkflowWatchError::WithReceipt {
                error: Box::new(error),
                receipt,
            })
        }
    }
}

fn controlled(
    node: &OneNode,
    config: &WorkflowWatchConfig,
    control: &WorkflowWatchControl,
    receipt: &mut WorkflowWatchReceipt,
    execute: bool,
) -> Result<(), WorkflowWatchError> {
    controlled_operation(node, config, control, |request| {
        attempt(node, request, config, control, receipt, execute)
    })
}

/// All collection discovery, member reconciliation and one selected dispatch
/// share this exact same finite request and drained stop observer.
fn controlled_operation<T>(
    node: &OneNode,
    config: &WorkflowWatchConfig,
    control: &WorkflowWatchControl,
    work: impl FnOnce(&NodeRequestContext) -> Result<T, WorkflowWatchError>,
) -> Result<T, WorkflowWatchError> {
    let parent = node.command_request_context(Some(config.attempt_timeout));
    let stopping = control.clone();
    let (result, cleanup) = parent
        .run_until_stopped(
            node.runtime(),
            move || stopping.is_stopped(),
            |request| {
                let result = work(request);
                // Idle source/custody observation and completed publication
                // share the same finite attempt. Check its final boundary even
                // without a dispatch or publisher before admitting another one.
                if result.is_ok() && !control.is_stopped() && !request.checkpoint_is_live() {
                    return Err(WorkflowWatchError::Attempt(
                        "workflow attempt budget exhausted; no later poll admitted".into(),
                    ));
                }
                result
            },
        )
        .map_err(|error| WorkflowWatchError::Attempt(error.to_string()))?;
    match (result, cleanup) {
        (Ok(result), Ok(())) => Ok(result),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(WorkflowWatchError::Attempt(format!(
            "stop observer did not drain: {error}"
        ))),
        (Err(error), Err(cleanup)) => Err(WorkflowWatchError::Attempt(format!(
            "{error}; stop observer did not drain: {cleanup}"
        ))),
    }
}

fn attempt(
    node: &OneNode,
    request: &NodeRequestContext,
    config: &WorkflowWatchConfig,
    control: &WorkflowWatchControl,
    receipt: &mut WorkflowWatchReceipt,
    execute: bool,
) -> Result<(), WorkflowWatchError> {
    if control.is_stopped() {
        return Ok(());
    }
    if execute
        && refresh(
            node,
            request,
            config,
            receipt,
            QueueRefreshMode::RecoverOnly,
        )?
    {
        return stopped(control, "attempt budget stopped queue refresh recovery");
    }
    if publish(node, request, config, receipt)? {
        return stopped(
            control,
            "attempt budget stopped pending check reconciliation",
        );
    }
    if !execute || control.is_stopped() {
        return Ok(());
    }
    // The startup reconciliation pass uses execute=false. Fresh target
    // publication, like script execution, begins only after readiness succeeds.
    if land(node, request, config, receipt)? {
        return stopped(
            control,
            "attempt budget stopped queue landing reconciliation",
        );
    }
    if control.is_stopped() {
        return Ok(());
    }
    if refresh(
        node,
        request,
        config,
        receipt,
        QueueRefreshMode::RecoverAndSelect,
    )? {
        return stopped(control, "attempt budget stopped queue target refresh");
    }
    if control.is_stopped() {
        return Ok(());
    }
    if !request.checkpoint_is_live() {
        return stopped(control, "attempt budget stopped before queue selection");
    }
    let poll = node
        .runtime()
        .block_on(async {
            match (
                config.pull_request,
                config.merge_queue,
                config.merge_candidate.as_ref(),
            ) {
                (_, Some(number), Some(merge)) => {
                    node.poll_trusted_queue_head_merge_workflows_in(
                        request,
                        &config.reference,
                        number,
                        &config.directory,
                        &config.run_parent,
                        &config.inputs,
                        config.limits,
                        config.artifacts.as_ref(),
                        merge,
                    )
                    .await
                }
                (_, Some(_), None) => Err(super::invalid(
                    "queue service requires merge candidate configuration",
                )),
                (Some(number), None, Some(merge)) => {
                    node.poll_trusted_pull_request_merge_workflows_in(
                        request,
                        &config.reference,
                        number,
                        &config.directory,
                        &config.run_parent,
                        &config.inputs,
                        config.limits,
                        config.artifacts.as_ref(),
                        merge,
                    )
                    .await
                }
                (Some(number), None, None) => {
                    node.poll_trusted_pull_request_workflows_in(
                        request,
                        &config.reference,
                        number,
                        &config.directory,
                        &config.run_parent,
                        &config.inputs,
                        config.limits,
                        config.artifacts.as_ref(),
                    )
                    .await
                }
                (None, None, _) => {
                    node.poll_trusted_ref_workflows_in(
                        request,
                        &config.reference,
                        &config.directory,
                        &config.run_parent,
                        &config.inputs,
                        config.limits,
                        config.artifacts.as_ref(),
                    )
                    .await
                }
            }
        })
        .map_err(|error| {
            if matches!(&error, super::TrustedWorkflowFailure::Journal { .. }) {
                receipt.requires_reconciliation = true;
            }
            WorkflowWatchError::Attempt(error.to_string())
        })?;
    add(&mut receipt.polls, 1)?;
    if poll.stopped_before_reservation() {
        return stopped(control, "attempt budget stopped before event reservation");
    }
    if let Some(dispatch) = poll.dispatch() {
        add(&mut receipt.dispatched, 1)?;
        if poll.execution_settled() {
            receipt.pending_execution = receipt.pending_execution.saturating_sub(1);
        }
        receipt.publication_pending |= config.publisher.is_some();
        receipt.non_green |= !dispatch.succeeded();
        receipt.interrupted |= dispatch.runs().iter().any(|run| run.request_interrupted);
        if !request.checkpoint_is_live() {
            // Interruption is still non-green, but a completed durable handoff
            // already discharged this producer's execution responsibility.
            receipt.interrupted = true;
            receipt.requires_reconciliation |= !poll.execution_settled();
            receipt.non_green = true;
        }
    }
    receipt.non_green |= poll.non_green();
    receipt.requires_reconciliation |= poll.requires_reconciliation();
    if receipt.requires_reconciliation {
        // This is a returned native execution observation, not an operation
        // error coincident with cancellation. Uncertain custody stays blocked.
        if receipt.interrupted && control.is_stopped() {
            return Ok(());
        }
        return Err(WorkflowWatchError::Attempt(
            "incomplete execution requires operator reconciliation; no later event admitted".into(),
        ));
    }
    if control.is_stopped() {
        return Ok(());
    }
    if config.publisher.is_some() && !request.checkpoint_is_live() {
        return Err(WorkflowWatchError::Attempt(
            "attempt stopped before check publication completed".into(),
        ));
    }
    if publish(node, request, config, receipt)? {
        return stopped(
            control,
            "attempt budget stopped before completed checks could be reported",
        );
    }
    if control.is_stopped() {
        return Ok(());
    }
    if land(node, request, config, receipt)? {
        return stopped(
            control,
            "attempt budget stopped before queue landing completed",
        );
    }
    Ok(())
}

fn stopped(control: &WorkflowWatchControl, detail: &str) -> Result<(), WorkflowWatchError> {
    if control.is_stopped() {
        Ok(())
    } else {
        Err(WorkflowWatchError::Attempt(detail.into()))
    }
}

fn publish(
    node: &OneNode,
    request: &NodeRequestContext,
    config: &WorkflowWatchConfig,
    receipt: &mut WorkflowWatchReceipt,
) -> Result<bool, WorkflowWatchError> {
    let Some(publisher) = config.publisher else {
        return Ok(false);
    };
    let result = node.runtime().block_on(async {
        match (
            config.pull_request,
            config.merge_queue,
            config.merge_candidate.as_ref(),
        ) {
            (_, Some(number), Some(merge)) => {
                node.publish_trusted_queue_head_merge_workflow_checks_in(
                    request,
                    &config.reference,
                    number,
                    &config.directory,
                    &config.run_parent,
                    publisher,
                    merge,
                    |_| Ok(()),
                )
                .await
            }
            (_, Some(_), None) => reporting::TrustedRefCheckPublication {
                error: Some("queue service requires merge candidate configuration".into()),
                ..Default::default()
            },
            (Some(number), None, Some(merge)) => {
                node.publish_trusted_pull_request_merge_workflow_checks_in(
                    request,
                    &config.reference,
                    number,
                    &config.directory,
                    &config.run_parent,
                    publisher,
                    merge,
                    |_| Ok(()),
                )
                .await
            }
            (Some(number), None, None) => {
                node.publish_trusted_pull_request_workflow_checks_in(
                    request,
                    &config.reference,
                    number,
                    &config.directory,
                    &config.run_parent,
                    publisher,
                    |_| Ok(()),
                )
                .await
            }
            (None, None, _) => {
                node.publish_trusted_ref_workflow_checks_in(
                    request,
                    &config.reference,
                    &config.directory,
                    &config.run_parent,
                    publisher,
                    |_| Ok(()),
                )
                .await
            }
        }
    });
    add(&mut receipt.checks_committed, result.committed)?;
    add(&mut receipt.checks_refused, result.refused)?;
    receipt.non_green |= result.refused != 0;
    let pending_execution = u64::try_from(result.pending_execution).map_err(|_| {
        WorkflowWatchError::Attempt("pending workflow observation counter exhausted".into())
    })?;
    // A stopped or failed scan can observe only a prefix. It may add pending
    // responsibility but cannot erase the preceding complete observation.
    if result.error.is_none() && !result.request_stopped {
        receipt.pending_execution = pending_execution;
    } else {
        receipt.pending_execution = receipt.pending_execution.max(pending_execution);
    }
    if let Some(error) = result.error {
        receipt.requires_reconciliation = true;
        receipt.publication_pending = true;
        return Err(WorkflowWatchError::Attempt(error));
    }
    // Preserve an observed dispatch's responsibility across cancellation, but
    // do not turn an idle recovery scan into new pending publication. Startup
    // still refuses readiness until the recovery pass completes without stop.
    if !result.request_stopped {
        receipt.publication_pending = receipt.refresh_pending;
    }
    Ok(result.request_stopped)
}

/// This pass follows a complete check publication pass under the SAME finite
/// request. The retained execution and canonical admission determine readiness;
/// no aggregate counter or local "reported" marker authorizes target mutation.
fn refresh(
    node: &OneNode,
    request: &NodeRequestContext,
    config: &WorkflowWatchConfig,
    receipt: &mut WorkflowWatchReceipt,
    mode: QueueRefreshMode,
) -> Result<bool, WorkflowWatchError> {
    let Some(refresher) = config.queue_refresh_principal else {
        return Ok(false);
    };
    if !request.checkpoint_is_live() {
        return Ok(true);
    }
    let (Some(number), Some(publisher), Some(lander), Some(merge)) = (
        config.merge_queue,
        config.publisher,
        config.landing_principal,
        config.merge_candidate.as_ref(),
    ) else {
        return Err(WorkflowWatchError::Attempt(
            "automatic queue refresh requires its complete operator configuration".into(),
        ));
    };
    let result = node
        .runtime()
        .block_on(node.refresh_trusted_queue_head_merge_workflows_in(
            request,
            &config.reference,
            number,
            &config.directory,
            &config.run_parent,
            merge,
            publisher,
            lander,
            refresher,
            mode,
            |_| Ok(()),
        ));
    receipt.non_green |= result.refused != 0;
    receipt.interrupted |= result.request_stopped;
    receipt.requires_reconciliation |= result.error.is_some();
    if result.error.is_none() && !result.request_stopped {
        receipt.refresh_pending = result.pending;
    } else {
        receipt.refresh_pending |= result.pending || result.error.is_some();
    }
    receipt.publication_pending |= receipt.refresh_pending;
    add(&mut receipt.refreshes_committed, result.committed)?;
    add(&mut receipt.refreshes_refused, result.refused)?;
    add(
        &mut receipt.refreshes_previously_decided,
        result.previously_decided,
    )?;
    add(&mut receipt.refreshes_waiting, result.waiting)?;
    if let Some(error) = result.error {
        return Err(WorkflowWatchError::Attempt(error));
    }
    Ok(result.request_stopped)
}

fn land(
    node: &OneNode,
    request: &NodeRequestContext,
    config: &WorkflowWatchConfig,
    receipt: &mut WorkflowWatchReceipt,
) -> Result<bool, WorkflowWatchError> {
    let Some(lander) = config.landing_principal else {
        return Ok(false);
    };
    if !request.checkpoint_is_live() {
        return Ok(true);
    }
    let (Some(number), Some(publisher), Some(merge)) = (
        config.merge_queue,
        config.publisher,
        config.merge_candidate.as_ref(),
    ) else {
        return Err(WorkflowWatchError::Attempt(
            "automatic queue landing requires its complete operator configuration".into(),
        ));
    };
    let result = node
        .runtime()
        .block_on(node.land_trusted_queue_head_merge_workflows_in(
            request,
            &config.reference,
            number,
            &config.directory,
            &config.run_parent,
            publisher,
            merge,
            lander,
            |_| Ok(()),
        ));
    receipt.non_green |= result.refused != 0;
    receipt.interrupted |= result.request_stopped;
    receipt.requires_reconciliation |= result.error.is_some();
    receipt.publication_pending |= result.error.is_some();
    add(&mut receipt.landings_committed, result.committed)?;
    add(&mut receipt.landings_refused, result.refused)?;
    add(
        &mut receipt.landings_previously_decided,
        result.previously_decided,
    )?;
    add(&mut receipt.landings_waiting, result.waiting)?;
    add(&mut receipt.landings_stale, result.stale)?;
    if let Some(error) = result.error {
        return Err(WorkflowWatchError::Attempt(error));
    }
    Ok(result.request_stopped)
}

fn add(value: &mut u64, amount: usize) -> Result<(), WorkflowWatchError> {
    *value = u64::try_from(amount)
        .ok()
        .and_then(|amount| value.checked_add(amount))
        .ok_or_else(|| {
            WorkflowWatchError::Attempt("service observation counter exhausted".into())
        })?;
    Ok(())
}

/// The service lock is separate from the existing event lock, which every
/// native poll/publication continues to acquire. Its inode is never replaced.
/// This excludes competing service owners while retaining old CLI custody.
enum ServiceCustody {
    Single(Custody),
    PullRequests(pull_requests::Controller),
}

impl ServiceCustody {
    fn open(
        node: &OneNode,
        config: &WorkflowWatchConfig,
        control: &WorkflowWatchControl,
        receipt: &mut WorkflowWatchReceipt,
    ) -> Result<Self, WorkflowWatchError> {
        if config.pull_requests.is_some() {
            pull_requests::Controller::open(node, config, control, receipt).map(Self::PullRequests)
        } else {
            let custody = Custody::open(node, config, control)?;
            receipt.pending_execution = custody.pending_execution;
            receipt.refresh_pending = custody.refresh_pending;
            receipt.publication_pending |= custody.refresh_pending;
            Ok(Self::Single(custody))
        }
    }
    fn poll(
        &mut self,
        node: &OneNode,
        config: &WorkflowWatchConfig,
        control: &WorkflowWatchControl,
        receipt: &mut WorkflowWatchReceipt,
    ) -> Result<(), WorkflowWatchError> {
        match self {
            Self::Single(custody) => {
                custody.check()?;
                controlled(node, config, control, receipt, true)
            }
            Self::PullRequests(controller) => controller.poll(node, config, control, receipt),
        }
    }
}

struct Custody {
    parent: PathBuf,
    parent_metadata: fs::Metadata,
    root: PathBuf,
    owner: Owner,
    watch_root: PathBuf,
    watch_metadata: fs::Metadata,
    watch_owner: fs::File,
    pending_execution: u64,
    refresh_pending: bool,
}

impl Custody {
    fn open(
        node: &OneNode,
        config: &WorkflowWatchConfig,
        control: &WorkflowWatchControl,
    ) -> Result<Self, WorkflowWatchError> {
        controlled_operation(node, config, control, |request| {
            if control.is_stopped() {
                return Err(WorkflowWatchError::StoppedBeforeReadiness);
            }
            Self::open_in(node, config, control, request)
        })
    }

    fn open_in(
        node: &OneNode,
        config: &WorkflowWatchConfig,
        control: &WorkflowWatchControl,
        request: &NodeRequestContext,
    ) -> Result<Self, WorkflowWatchError> {
        let custody =
            |error: super::TrustedWorkflowFailure| WorkflowWatchError::Custody(error.to_string());
        merge_queue::validate_selection(
            &config.reference,
            config.pull_request,
            config.merge_queue,
            config.merge_candidate.as_ref(),
        )
        .map_err(custody)?;
        check_directory(&config.run_parent).map_err(custody)?;
        let parent_metadata = fs::symlink_metadata(&config.run_parent)
            .map_err(|error| WorkflowWatchError::Custody(error.to_string()))?;
        let scope = match (
            config.pull_request,
            config.merge_queue,
            config.merge_candidate.as_ref(),
        ) {
            (_, Some(number), _) => {
                merge_queue::scope(node, &config.reference, &config.directory, number)
            }
            (Some(number), None, Some(_)) => {
                pull_request_merge::scope(node, &config.reference, &config.directory, number)
            }
            (Some(number), None, None) => {
                pull_request::scope(node, &config.reference, &config.directory, number)
            }
            (None, None, _) => reporting::scope(node, &config.reference, &config.directory),
        };
        let root = config.run_parent.join(format!("service-{}", hex(&scope)));
        let owner = Owner::open(&root).map_err(custody)?;
        let events = config.run_parent.join(format!("watch-{}", hex(&scope)));
        let _event_owner = Owner::open(&events).map_err(custody)?;
        if let Some(merge) = &config.merge_candidate {
            merge.bind(&events).map_err(custody)?;
        }
        let watch_metadata = fs::symlink_metadata(&events)
            .map_err(|error| WorkflowWatchError::Custody(error.to_string()))?;
        let watch_owner = fs::File::open(events.join("owner.lock"))
            .map_err(|error| WorkflowWatchError::Custody(error.to_string()))?;
        let refresh_pending = match (config.merge_queue, config.merge_candidate.as_ref()) {
            (Some(number), Some(merge)) => node
                .runtime()
                .block_on(queue_refresh::validated_pending_in(
                    node,
                    request,
                    &config.reference,
                    number,
                    &events,
                    &scope,
                    merge,
                    config.queue_refresh_principal,
                ))
                .map_err(|error| {
                    if control.is_stopped()
                        && matches!(
                            &error,
                            super::TrustedWorkflowFailure::InvalidInput(
                                "queue refresh custody verification stopped"
                            )
                        )
                    {
                        WorkflowWatchError::StoppedBeforeReadiness
                    } else {
                        custody(error)
                    }
                })?,
            _ => false,
        };
        let mut result = Self {
            parent: config.run_parent.clone(),
            parent_metadata,
            root,
            owner,
            watch_root: events.clone(),
            watch_metadata,
            watch_owner,
            pending_execution: 0,
            refresh_pending,
        };
        result.check()?;
        drop(_event_owner);
        result.reconcile_execution(node, config, control, request)?;
        Ok(result)
    }

    /// Caller owns this member's service lock. The event lock also excludes
    /// a competing one-shot poll while original execution evidence is checked.
    fn reconcile_execution(
        &mut self,
        node: &OneNode,
        config: &WorkflowWatchConfig,
        control: &WorkflowWatchControl,
        request: &NodeRequestContext,
    ) -> Result<(), WorkflowWatchError> {
        self.check()?;
        let custody =
            |error: super::TrustedWorkflowFailure| WorkflowWatchError::Custody(error.to_string());
        let events = &self.watch_root;
        let _event_owner = Owner::open(events).map_err(custody)?;
        let scope = match (
            config.pull_request,
            config.merge_queue,
            config.merge_candidate.as_ref(),
        ) {
            (_, Some(number), _) => {
                merge_queue::scope(node, &config.reference, &config.directory, number)
            }
            (Some(number), None, Some(_)) => {
                pull_request_merge::scope(node, &config.reference, &config.directory, number)
            }
            (Some(number), None, None) => {
                pull_request::scope(node, &config.reference, &config.directory, number)
            }
            (None, None, _) => reporting::scope(node, &config.reference, &config.directory),
        };
        self.pending_execution = 0;
        let live = || !control.is_stopped() && request.checkpoint_is_live();
        for entry in reporting::event_entries(&events).map_err(custody)? {
            if control.is_stopped() {
                return Err(WorkflowWatchError::StoppedBeforeReadiness);
            }
            let name = entry.file_name();
            let key = name
                .to_str()
                .and_then(|name| name.strip_prefix("event-"))
                .filter(|key| lower_hash(key))
                .ok_or_else(|| WorkflowWatchError::Custody("unknown watch custody entry".into()))?;
            check_directory(&entry.path()).map_err(custody)?;
            if !reporting::recover_settlement(
                node,
                config
                    .merge_candidate
                    .as_ref()
                    .map_or(&config.reference, |merge| merge.reference()),
                &config.directory,
                &entry.path(),
                &scope,
                key,
                &live,
            )
            .map_err(|error| {
                if control.is_stopped() {
                    WorkflowWatchError::StoppedBeforeReadiness
                } else {
                    custody(error)
                }
            })? {
                if let Some(merge) = &config.merge_candidate
                    && super::prestart::pending(
                        node,
                        &config.reference,
                        &config.directory,
                        &entry.path(),
                        &scope,
                        key,
                        merge,
                        Some((&config.inputs, config.limits, config.artifacts.as_ref())),
                        &live,
                    )
                    .map_err(|error| {
                        if control.is_stopped() {
                            WorkflowWatchError::StoppedBeforeReadiness
                        } else {
                            custody(error)
                        }
                    })?
                {
                    self.pending_execution =
                        self.pending_execution.checked_add(1).ok_or_else(|| {
                            WorkflowWatchError::Custody(
                                "pending workflow observation counter exhausted".into(),
                            )
                        })?;
                    continue;
                }
                return Err(WorkflowWatchError::Custody(
                    "unresolved event blocks startup; preserve original execution custody".into(),
                ));
            }
        }
        self.check()
    }

    fn check(&self) -> Result<(), WorkflowWatchError> {
        let check = || -> io::Result<()> {
            let parent = fs::symlink_metadata(&self.parent)?;
            let watch = fs::symlink_metadata(&self.watch_root)?;
            if !parent.is_dir()
                || parent.mode() & 0o777 != 0o700
                || (parent.dev(), parent.ino())
                    != (self.parent_metadata.dev(), self.parent_metadata.ino())
                || !watch.is_dir()
                || watch.mode() & 0o777 != 0o700
                || (watch.dev(), watch.ino())
                    != (self.watch_metadata.dev(), self.watch_metadata.ino())
            {
                return Err(io::Error::other("workflow service custody owner changed"));
            }
            for (root, held) in [
                (&self.root, &self.owner.0),
                (&self.watch_root, &self.watch_owner),
            ] {
                let named = fs::symlink_metadata(root.join("owner.lock"))?;
                let held = held.metadata()?;
                if !named.is_file()
                    || !held.is_file()
                    || named.mode() & 0o777 != 0o600
                    || held.mode() & 0o777 != 0o600
                    || named.nlink() != 1
                    || held.nlink() != 1
                    || (named.dev(), named.ino()) != (held.dev(), held.ino())
                {
                    return Err(io::Error::other("workflow service custody owner changed"));
                }
            }
            Ok(())
        };
        check().map_err(|error| WorkflowWatchError::Custody(error.to_string()))
    }
}

#[cfg(test)]
mod tests;
