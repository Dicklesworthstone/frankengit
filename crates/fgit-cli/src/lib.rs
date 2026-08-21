#![forbid(unsafe_code)]

//! Minimal command-line surface for the one-process node slice.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::PathBuf;

use fgit_node::{DoctorReport, NodeConfig, NodeInitialization, OneNode};
use fgit_types::{RepositoryId, TenantId};

/// Typed refusal from the minimal `fg` command parser.
#[derive(Debug)]
pub enum CliRefusal {
    /// The command line did not identify a supported command.
    Usage,
    /// Serving cannot start until the canonical projection and socket gateway
    /// are both published as production surfaces.
    ServeUnavailable,
    /// The supplied tenant identity was not canonical lowercase hex.
    Tenant(fgit_types::TypeRefusal),
    /// The supplied repository identity was not canonical lowercase hex.
    Repository(fgit_types::TypeRefusal),
    /// Node initialization refused before a usable service existed.
    Node(fgit_node::NodeRefusal),
    /// Doctor inspection refused and the following mandatory node shutdown
    /// also failed, so neither failure is discarded.
    DoctorCleanup {
        /// The failed authenticated inspection.
        inspection: Box<fgit_node::NodeRefusal>,
        /// The failed explicit lifecycle close.
        cleanup: Box<fgit_node::NodeRefusal>,
    },
}

impl Display for CliRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => formatter.write_str(
                "usage: fg init|doctor <storage-root> <tenant-id-hex> <repository-id-hex>; fg serve",
            ),
            Self::ServeUnavailable => formatter.write_str(
                "fg serve is unavailable: no published raw-socket gateway and canonical admission projection are available",
            ),
            Self::Tenant(error) => Display::fmt(error, formatter),
            Self::Repository(error) => Display::fmt(error, formatter),
            Self::Node(error) => Display::fmt(error, formatter),
            Self::DoctorCleanup {
                inspection,
                cleanup,
            } => write!(
                formatter,
                "doctor inspection failed ({inspection}) and node shutdown also failed ({cleanup})"
            ),
        }
    }
}

impl Error for CliRefusal {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Tenant(error) | Self::Repository(error) => Some(error),
            Self::Node(error) => Some(error),
            Self::DoctorCleanup { inspection, .. } => Some(inspection),
            Self::Usage | Self::ServeUnavailable => None,
        }
    }
}

/// The observable result of one supported `fg` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliOutcome {
    /// `fg init` created or found the durable authority head.
    Initialized(NodeInitialization),
    /// `fg doctor` authenticated the current authority receipt.
    ///
    /// This first doctor slice does not claim an RCR replay proof or a storage
    /// scan. It opens an already initialized node, authenticates its current
    /// head receipt, and then shuts the node down cleanly.
    Doctor(DoctorReport),
}

/// Executes a bounded command invocation without ambient configuration.
pub fn run(arguments: &[String]) -> Result<CliOutcome, CliRefusal> {
    match arguments {
        [command] if command == "serve" => Err(CliRefusal::ServeUnavailable),
        [command, storage_root, tenant, repository] if command == "init" => {
            let (node, initialization) =
                OneNode::init(node_config(storage_root, tenant, repository)?)
                    .map_err(CliRefusal::Node)?;
            node.shutdown().map_err(CliRefusal::Node)?;
            Ok(CliOutcome::Initialized(initialization))
        }
        [command, storage_root, tenant, repository] if command == "doctor" => {
            let node = OneNode::open_existing(node_config(storage_root, tenant, repository)?)
                .map_err(CliRefusal::Node)?;
            let inspection = node.runtime().block_on(node.doctor(None));
            let cleanup = node.shutdown();
            match (inspection, cleanup) {
                (Ok(report), Ok(())) => Ok(CliOutcome::Doctor(report)),
                (Err(inspection), Ok(())) => Err(CliRefusal::Node(inspection)),
                (Ok(_), Err(cleanup)) => Err(CliRefusal::Node(cleanup)),
                (Err(inspection), Err(cleanup)) => Err(CliRefusal::DoctorCleanup {
                    inspection: Box::new(inspection),
                    cleanup: Box::new(cleanup),
                }),
            }
        }
        _ => Err(CliRefusal::Usage),
    }
}

fn node_config(
    storage_root: &str,
    tenant: &str,
    repository: &str,
) -> Result<NodeConfig, CliRefusal> {
    let tenant_id = TenantId::from_hex(tenant).map_err(CliRefusal::Tenant)?;
    let repository_id = RepositoryId::from_hex(repository).map_err(CliRefusal::Repository)?;
    Ok(NodeConfig::new(
        PathBuf::from(storage_root),
        tenant_id,
        repository_id,
    ))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{CliOutcome, CliRefusal, run};

    static NEXT_SCRATCH_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct ScratchDirectory(PathBuf);

    impl ScratchDirectory {
        fn new() -> Self {
            let sequence = NEXT_SCRATCH_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "frankengit-cli-doctor-{}-{sequence}",
                std::process::id()
            )))
        }
    }

    impl Drop for ScratchDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn serve_is_a_typed_refusal_until_a_real_gateway_is_published() {
        assert!(matches!(
            run(&["serve".to_owned()]),
            Err(CliRefusal::ServeUnavailable)
        ));
    }

    #[test]
    fn doctor_opens_only_an_initialized_authority_head() {
        let scratch = ScratchDirectory::new();
        let storage_root = scratch.0.to_string_lossy().into_owned();
        let tenant = "11111111111111111111111111111111".to_owned();
        let repository = "22222222222222222222222222222222".to_owned();
        let init = vec![
            "init".to_owned(),
            storage_root.clone(),
            tenant.clone(),
            repository.clone(),
        ];
        assert!(matches!(run(&init), Ok(CliOutcome::Initialized(_))));
        let doctor = vec!["doctor".to_owned(), storage_root, tenant, repository];
        assert!(matches!(run(&doctor), Ok(CliOutcome::Doctor(_))));
    }
}
