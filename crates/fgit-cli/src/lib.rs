#![forbid(unsafe_code)]

//! Minimal command-line surface for the one-process node slice.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_node::{
    DoctorReport, GitDaemonSessionOutcome, NodeConfig, NodeGitDaemonServeRefusal,
    NodeInitialization, OneNode,
};
use fgit_types::{GitHashAlgorithm, GitOid, RepositoryId, TenantId};

const EXPORT_TEMPORARY_ATTEMPTS: usize = 16;

static NEXT_EXPORT_TEMPORARY: AtomicU64 = AtomicU64::new(1);

/// Typed refusal from the minimal `fg` command parser.
#[derive(Debug)]
pub enum CliRefusal {
    /// The command line did not identify a supported command.
    Usage,
    /// The supplied tenant identity was not canonical lowercase hex.
    Tenant(fgit_types::TypeRefusal),
    /// The supplied repository identity was not canonical lowercase hex.
    Repository(fgit_types::TypeRefusal),
    /// The supplied doctor sample was not a native SHA-1 object identity.
    Object(fgit_types::TypeRefusal),
    /// Node initialization refused before a usable service existed.
    Node(fgit_node::NodeRefusal),
    /// The requested listener address could not become a bounded local socket.
    Listener(io::Error),
    /// A one-session git-daemon serve attempt refused.
    Serve(NodeGitDaemonServeRefusal),
    /// The authority-selected pack could not be materialized for export.
    ExportMaterialization(Box<fgit_node::NodePackMaterializationRefusal>),
    /// The export destination had no final filename component.
    ExportDestination,
    /// A new export must never replace a pre-existing file.
    ExportDestinationExists(Box<PathBuf>),
    /// Staging or publishing an export file refused.
    ExportFile {
        /// The root-last export operation that failed.
        operation: &'static str,
        /// The file involved in that operation.
        path: Box<PathBuf>,
        /// The operating-system refusal.
        source: Box<io::Error>,
    },
    /// A staged export failed and its temporary artifact could not be reaped.
    ExportFileCleanup {
        /// The original failed export operation.
        operation: &'static str,
        /// The temporary artifact that still needs operator attention.
        temporary: Box<PathBuf>,
        /// The original export refusal.
        source: Box<io::Error>,
        /// The failed cleanup refusal.
        cleanup: Box<io::Error>,
    },
    /// The output became visible, but its staged hard link could not be reaped.
    ///
    /// The error intentionally does not claim the export failed: the named
    /// destination is already visible and the retained staging path must be
    /// reported rather than silently leaked.
    ExportVisibleCleanup {
        /// The visible, completed destination.
        destination: Box<PathBuf>,
        /// The orphaned staging link to the same immutable bytes.
        temporary: Box<PathBuf>,
        /// The failed staging cleanup.
        cleanup: Box<io::Error>,
    },
    /// Doctor inspection refused and the following mandatory node shutdown
    /// also failed, so neither failure is discarded.
    DoctorCleanup {
        /// The failed authenticated inspection.
        inspection: Box<fgit_node::NodeRefusal>,
        /// The failed explicit lifecycle close.
        cleanup: Box<fgit_node::NodeRefusal>,
    },
    /// Serving refused and mandatory node shutdown also failed, so neither
    /// failure is discarded.
    ServeCleanup {
        /// The session refusal before cleanup.
        serving: Box<NodeGitDaemonServeRefusal>,
        /// The failed explicit lifecycle close.
        cleanup: Box<fgit_node::NodeRefusal>,
    },
    /// Export refused and mandatory node shutdown also failed, so neither
    /// failure is discarded.
    ExportCleanup {
        /// The export failure before lifecycle cleanup.
        export: Box<Self>,
        /// The failed explicit lifecycle close.
        cleanup: Box<fgit_node::NodeRefusal>,
    },
}

impl Display for CliRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => formatter.write_str(
                "usage: fg init <storage-root> <tenant-id-hex> <repository-id-hex>; fg doctor <storage-root> <tenant-id-hex> <repository-id-hex> [sample-object-oid-hex]; fg export <storage-root> <tenant-id-hex> <repository-id-hex> <new-pack-path>; fg serve <storage-root> <tenant-id-hex> <repository-id-hex> <listen-address>",
            ),
            Self::Tenant(error) | Self::Repository(error) | Self::Object(error) => {
                Display::fmt(error, formatter)
            }
            Self::Node(error) => Display::fmt(error, formatter),
            Self::Listener(error) => write!(formatter, "cannot bind fg serve listener: {error}"),
            Self::Serve(error) => Display::fmt(error, formatter),
            Self::ExportMaterialization(error) => {
                write!(formatter, "cannot materialize authority-selected export: {error}")
            }
            Self::ExportDestination => {
                formatter.write_str("export destination must name a new file")
            }
            Self::ExportDestinationExists(path) => {
                write!(formatter, "export destination already exists: {}", path.display())
            }
            Self::ExportFile {
                operation,
                path,
                source,
            } => write!(formatter, "cannot {operation} {}: {source}", path.display()),
            Self::ExportFileCleanup {
                operation,
                temporary,
                source,
                cleanup,
            } => write!(
                formatter,
                "cannot {operation} {} ({source}); cannot reap staged export {}: {cleanup}",
                temporary.display(),
                temporary.display(),
            ),
            Self::ExportVisibleCleanup {
                destination,
                temporary,
                cleanup,
            } => write!(
                formatter,
                "export is visible at {}; cannot reap staged export {}: {cleanup}",
                destination.display(),
                temporary.display(),
            ),
            Self::DoctorCleanup {
                inspection,
                cleanup,
            } => write!(
                formatter,
                "doctor inspection failed ({inspection}) and node shutdown also failed ({cleanup})"
            ),
            Self::ServeCleanup { serving, cleanup } => write!(
                formatter,
                "serve session failed ({serving}) and node shutdown also failed ({cleanup})"
            ),
            Self::ExportCleanup { export, cleanup } => write!(
                formatter,
                "export failed ({export}) and node shutdown also failed ({cleanup})"
            ),
        }
    }
}

impl Error for CliRefusal {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Tenant(error) | Self::Repository(error) | Self::Object(error) => Some(error),
            Self::Node(error) => Some(error),
            Self::Listener(error) => Some(error),
            Self::Serve(error) => Some(error),
            Self::ExportMaterialization(error) => Some(error.as_ref()),
            Self::ExportFile { source, .. } | Self::ExportFileCleanup { source, .. } => {
                Some(source.as_ref())
            }
            Self::ExportVisibleCleanup { cleanup, .. } => Some(cleanup.as_ref()),
            Self::DoctorCleanup { inspection, .. } => Some(inspection),
            Self::ServeCleanup { serving, .. } => Some(serving),
            Self::ExportCleanup { export, .. } => Some(export.as_ref()),
            Self::Usage | Self::ExportDestination | Self::ExportDestinationExists(_) => None,
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
    /// `fg serve` completed one fully drained git-daemon session.
    Served {
        /// Socket address actually bound for this bounded session.
        listen_address: SocketAddr,
        /// Whether the session completed an empty advertisement or a pack.
        session: GitDaemonSessionOutcome,
    },
    /// `fg export` made a completed authority-selected Git pack visible at a
    /// previously absent local path.
    Exported {
        /// Destination that was linked only after pack materialization and a
        /// successful temporary-file sync.
        destination: PathBuf,
        /// Exact byte count of the completed pack.
        bytes: usize,
    },
}

/// Executes a bounded command invocation without ambient configuration.
pub fn run(arguments: &[String]) -> Result<CliOutcome, CliRefusal> {
    match arguments {
        [command, storage_root, tenant, repository] if command == "init" => {
            let (node, initialization) =
                OneNode::init(node_config(storage_root, tenant, repository)?)
                    .map_err(CliRefusal::Node)?;
            node.shutdown().map_err(CliRefusal::Node)?;
            Ok(CliOutcome::Initialized(initialization))
        }
        [command, storage_root, tenant, repository] if command == "doctor" => {
            run_doctor(storage_root, tenant, repository, None)
        }
        [command, storage_root, tenant, repository, sample] if command == "doctor" => {
            let sample =
                GitOid::from_hex(GitHashAlgorithm::Sha1, sample).map_err(CliRefusal::Object)?;
            run_doctor(storage_root, tenant, repository, Some(sample))
        }
        [command, storage_root, tenant, repository, destination] if command == "export" => {
            run_export(storage_root, tenant, repository, PathBuf::from(destination))
        }
        [command, storage_root, tenant, repository, listen_address] if command == "serve" => {
            let listener = TcpListener::bind(listen_address).map_err(CliRefusal::Listener)?;
            let listen_address = listener.local_addr().map_err(CliRefusal::Listener)?;
            let node = OneNode::open_existing(node_config(storage_root, tenant, repository)?)
                .map_err(CliRefusal::Node)?;
            let serving = node.serve_git_daemon_once(&listener);
            let cleanup = node.shutdown();
            match (serving, cleanup) {
                (Ok(session), Ok(())) => Ok(CliOutcome::Served {
                    listen_address,
                    session,
                }),
                (Err(serving), Ok(())) => Err(CliRefusal::Serve(serving)),
                (Ok(_), Err(cleanup)) => Err(CliRefusal::Node(cleanup)),
                (Err(serving), Err(cleanup)) => Err(CliRefusal::ServeCleanup {
                    serving: Box::new(serving),
                    cleanup: Box::new(cleanup),
                }),
            }
        }
        _ => Err(CliRefusal::Usage),
    }
}

fn run_export(
    storage_root: &str,
    tenant: &str,
    repository: &str,
    destination: PathBuf,
) -> Result<CliOutcome, CliRefusal> {
    let node = OneNode::open_existing(node_config(storage_root, tenant, repository)?)
        .map_err(CliRefusal::Node)?;
    let exported = node
        .runtime()
        .block_on(node.authority_selected_pack_payload())
        .map_err(|error| CliRefusal::ExportMaterialization(Box::new(error)))
        .and_then(|payload| {
            let bytes = payload.into_bytes();
            write_new_export(&destination, &bytes)?;
            Ok(CliOutcome::Exported {
                destination,
                bytes: bytes.len(),
            })
        });
    let cleanup = node.shutdown();
    match (exported, cleanup) {
        (Ok(outcome), Ok(())) => Ok(outcome),
        (Err(export), Ok(())) => Err(export),
        (Ok(_), Err(cleanup)) => Err(CliRefusal::Node(cleanup)),
        (Err(export), Err(cleanup)) => Err(CliRefusal::ExportCleanup {
            export: Box::new(export),
            cleanup: Box::new(cleanup),
        }),
    }
}

/// Writes a completed pack through a same-directory staging file and publishes
/// it only by linking to a previously absent destination.
///
/// `hard_link` is deliberately used rather than `rename`: it fails if another
/// writer made the destination visible first, so this command cannot silently
/// replace an operator's prior export.  Both paths share a directory, making
/// the publication one filesystem operation over the synced completed bytes.
fn write_new_export(destination: &Path, bytes: &[u8]) -> Result<(), CliRefusal> {
    let (temporary, mut staged) = create_export_staging_file(destination)?;
    if let Err(source) = staged.write_all(bytes) {
        return abort_staged_export("write staged export", temporary, source);
    }
    if let Err(source) = staged.sync_all() {
        return abort_staged_export("sync staged export", temporary, source);
    }
    drop(staged);

    if let Err(source) = fs::hard_link(&temporary, destination) {
        if source.kind() == io::ErrorKind::AlreadyExists {
            // Another writer published this exact destination first, and a
            // new export never replaces one. Reap the staged bytes and name
            // the collision with its purpose-built typed refusal rather
            // than the generic staging-operation error.
            return match fs::remove_file(&temporary) {
                Ok(()) => Err(CliRefusal::ExportDestinationExists(Box::new(
                    destination.to_path_buf(),
                ))),
                Err(cleanup) => Err(CliRefusal::ExportFileCleanup {
                    operation: "publish staged export",
                    temporary: Box::new(temporary),
                    source: Box::new(source),
                    cleanup: Box::new(cleanup),
                }),
            };
        }
        return abort_staged_export("publish staged export", temporary, source);
    }
    if let Err(cleanup) = fs::remove_file(&temporary) {
        return Err(CliRefusal::ExportVisibleCleanup {
            destination: Box::new(destination.to_path_buf()),
            temporary: Box::new(temporary),
            cleanup: Box::new(cleanup),
        });
    }
    Ok(())
}

fn create_export_staging_file(destination: &Path) -> Result<(PathBuf, File), CliRefusal> {
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = destination
        .file_name()
        .ok_or(CliRefusal::ExportDestination)?;
    for _ in 0..EXPORT_TEMPORARY_ATTEMPTS {
        let sequence = NEXT_EXPORT_TEMPORARY.fetch_add(1, Ordering::Relaxed);
        let mut temporary_name = file_name.to_os_string();
        temporary_name.push(format!(
            ".fgit-export-{}-{sequence}.tmp",
            std::process::id()
        ));
        let temporary = parent.join(temporary_name);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(file) => return Ok((temporary, file)),
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(CliRefusal::ExportFile {
                    operation: "create staged export",
                    path: Box::new(temporary),
                    source: Box::new(source),
                });
            }
        }
    }
    Err(CliRefusal::ExportFile {
        operation: "create a unique staged export",
        path: Box::new(destination.to_path_buf()),
        source: Box::new(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "all bounded export staging names already exist",
        )),
    })
}

fn abort_staged_export(
    operation: &'static str,
    temporary: PathBuf,
    source: io::Error,
) -> Result<(), CliRefusal> {
    match fs::remove_file(&temporary) {
        Ok(()) => Err(CliRefusal::ExportFile {
            operation,
            path: Box::new(temporary),
            source: Box::new(source),
        }),
        Err(cleanup) => Err(CliRefusal::ExportFileCleanup {
            operation,
            temporary: Box::new(temporary),
            source: Box::new(source),
            cleanup: Box::new(cleanup),
        }),
    }
}

fn run_doctor(
    storage_root: &str,
    tenant: &str,
    repository: &str,
    sampled_object: Option<GitOid>,
) -> Result<CliOutcome, CliRefusal> {
    let node = OneNode::open_existing(node_config(storage_root, tenant, repository)?)
        .map_err(CliRefusal::Node)?;
    let inspection = node.runtime().block_on(node.doctor(sampled_object));
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
    fn serve_requires_a_complete_bounded_listener_configuration() {
        assert!(matches!(run(&["serve".to_owned()]), Err(CliRefusal::Usage)));
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

    #[test]
    fn doctor_refuses_a_noncanonical_sample_object_before_opening_the_node() {
        let command = vec![
            "doctor".to_owned(),
            "/unused".to_owned(),
            "11111111111111111111111111111111".to_owned(),
            "22222222222222222222222222222222".to_owned(),
            "not-an-object".to_owned(),
        ];
        assert!(matches!(run(&command), Err(CliRefusal::Object(_))));
    }

    #[test]
    fn export_writes_a_new_authority_selected_pack_without_replacing_a_file() {
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

        let destination = scratch.0.join("empty.pack");
        let export = vec![
            "export".to_owned(),
            storage_root,
            tenant,
            repository,
            destination.to_string_lossy().into_owned(),
        ];
        let outcome = run(&export).expect("empty canonical closure exports as a real pack");
        let CliOutcome::Exported {
            destination: reported,
            bytes,
        } = outcome
        else {
            panic!("export command reports its completed pack");
        };
        assert_eq!(reported, destination);
        let pack = fs::read(&destination).expect("new export is visible at its requested path");
        assert_eq!(pack.len(), bytes);
        assert_eq!(&pack[..4], b"PACK");
        assert!(matches!(
            run(&export),
            Err(CliRefusal::ExportDestinationExists(existing)) if *existing == destination
        ));
    }
}
