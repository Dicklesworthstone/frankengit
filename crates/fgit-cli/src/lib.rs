#![forbid(unsafe_code)]

//! Minimal command-line surface for the one-process node slice.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_forge::snapshot::{
    ForgeSnapshot, ForgeSnapshotDiff, PositionTarget, SnapshotDisclosurePolicy, SnapshotLimits,
    SnapshotRefusal, project_snapshot_from_history,
};
use fgit_node::{
    DoctorReport, GitDaemonServerLimits, GitDaemonServerReceipt, NodeConfig,
    NodeGitDaemonServeRefusal, NodeGitDaemonServerRefusal, NodeInitialization,
    NodeSourceImportRefusal, OneNode, RepositoryResolutionInput,
};
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::numeric::{CodecVersion, DecisionSequence, HeadGeneration, RepositorySequence};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DecisionOutcome, GitHashAlgorithm, GitOid, PrincipalId, RefusalCode,
    RepositoryAuthorityHeadId, RepositoryCapsuleId, RepositoryCommitId, RepositoryId,
    RepositoryIncarnationId, TenantId,
};

const EXPORT_TEMPORARY_ATTEMPTS: usize = 16;

static NEXT_EXPORT_TEMPORARY: AtomicU64 = AtomicU64::new(1);

/// Typed refusal from the minimal `fg` command parser.
#[derive(Debug)]
pub enum CliRefusal {
    /// The command line did not identify a supported command.
    Usage,
    /// The command line named an object format this build does not support.
    ///
    /// Selecting a format is explicit precisely so an unrecognised token cannot
    /// quietly fall back to SHA-1: a repository's object format is permanent,
    /// and a silent default would mint the wrong one irreversibly.
    UnsupportedObjectFormat(String),
    /// The supplied tenant identity was not canonical lowercase hex.
    Tenant(fgit_types::TypeRefusal),
    /// The supplied repository identity was not canonical lowercase hex.
    Repository(fgit_types::TypeRefusal),
    /// The supplied repository-incarnation identity was not canonical lowercase hex.
    RepositoryIncarnation(fgit_types::TypeRefusal),
    /// The supplied caller principal identity was not canonical lowercase hex.
    Principal(fgit_types::TypeRefusal),
    /// The supplied doctor sample was not a native SHA-1 object identity.
    Object(fgit_types::TypeRefusal),
    /// Node initialization refused before a usable service existed.
    Node(fgit_node::NodeRefusal),
    /// A verified loose source could not become an authenticated source-import
    /// decision.
    Import(Box<NodeSourceImportRefusal>),
    /// Source-import admission reached an authenticated terminal refusal.
    ///
    /// This is deliberately distinct from source verification or authority
    /// infrastructure failure: callers may safely retry a terminal decision
    /// with the same explicit idempotency key, but must not treat it as an
    /// imported repository.
    ImportRefused(RefusalCode),
    /// The requested listener address could not become a bounded local socket.
    Listener(io::Error),
    /// A one-session git-daemon serve attempt refused.
    Serve(NodeGitDaemonServeRefusal),
    /// A bounded multi-session git-daemon service run refused before it could
    /// drain its accepted children.
    ServeServer(NodeGitDaemonServerRefusal),
    /// A bounded multi-session daemon refusal and the required node shutdown
    /// both failed, so neither lifecycle outcome is discarded.
    ServeServerCleanup {
        /// The service-run refusal before cleanup.
        serving: Box<NodeGitDaemonServerRefusal>,
        /// The failed explicit lifecycle close.
        cleanup: Box<fgit_node::NodeRefusal>,
    },
    /// A requested daemon-service bound was not a non-zero decimal integer.
    InvalidServeLimit {
        /// The command-line field that was invalid.
        field: &'static str,
        /// The caller-supplied token.
        value: String,
    },
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
    /// Import refused and mandatory node shutdown also failed, so neither
    /// failure is discarded.
    ImportCleanup {
        /// The import refusal before lifecycle cleanup.
        import: Box<NodeSourceImportRefusal>,
        /// The failed explicit lifecycle close.
        cleanup: Box<fgit_node::NodeRefusal>,
    },
    /// Source import reached a terminal refusal and mandatory node shutdown
    /// also failed, so neither outcome is discarded.
    ImportRefusedCleanup {
        /// The authenticated terminal decision.
        code: RefusalCode,
        /// The failed explicit lifecycle close.
        cleanup: Box<fgit_node::NodeRefusal>,
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
    /// The supplied snapshot position was invalid.
    InvalidPosition(String),
    /// A snapshot query or disclosure evaluation failed.
    Snapshot(SnapshotRefusal),
    /// Snapshot query failed and node shutdown also failed.
    AtCleanup {
        /// The snapshot inspection failure.
        inspection: Box<Self>,
        /// The failed node cleanup.
        cleanup: Box<fgit_node::NodeRefusal>,
    },
}

impl Display for CliRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => formatter.write_str(
                "usage: fg init <storage-root> <tenant-id-hex> <repository-id-hex> [sha1|sha256] | fg init <storage-root> <tenant-id-hex> <repository-id-hex> --creation-idempotency-key <key> [sha1|sha256]; fg import <storage-root> <tenant-id-hex> <repository-id-hex> <principal-id-hex> <idempotency-key> <source-git-directory> [--expected-incarnation <id>]; fg doctor <storage-root> <tenant-id-hex> <repository-id-hex> [sample-object-oid-hex] [--expected-incarnation <id>]; fg export <storage-root> <tenant-id-hex> <repository-id-hex> <new-pack-path> [--expected-incarnation <id>]; fg serve <storage-root> <tenant-id-hex> <repository-id-hex> <listen-address> [--expected-incarnation <id>] [--max-sessions <non-zero> --max-in-flight <non-zero>]; fg at <storage-root> <tenant-id-hex> <repository-id-hex> <position> [refs|prs|diff <other-position>] [--actor <principal-id-hex>] [--expected-incarnation <id>]",
            ),
            Self::UnsupportedObjectFormat(token) => write!(
                formatter,
                "unsupported object format `{token}`: expected `sha1` or `sha256`"
            ),
            Self::Tenant(error)
            | Self::Repository(error)
            | Self::RepositoryIncarnation(error)
            | Self::Principal(error)
            | Self::Object(error) => {
                Display::fmt(error, formatter)
            }
            Self::Node(error) => Display::fmt(error, formatter),
            Self::Import(error) => Display::fmt(error, formatter),
            Self::ImportRefused(code) => {
                write!(formatter, "source import reached terminal refusal: {code:?}")
            }
            Self::Listener(error) => write!(formatter, "cannot bind fg serve listener: {error}"),
            Self::Serve(error) => Display::fmt(error, formatter),
            Self::ServeServer(error) => Display::fmt(error, formatter),
            Self::ServeServerCleanup { serving, cleanup } => write!(
                formatter,
                "bounded serve failed ({serving}) and node shutdown also failed ({cleanup})"
            ),
            Self::InvalidServeLimit { field, value } => {
                write!(formatter, "invalid fg serve {field} `{value}`: expected a non-zero decimal integer")
            }
            Self::ExportMaterialization(error) => {
                write!(formatter, "cannot materialize authority-selected export: {error}")
            }
            Self::ExportDestination => {
                formatter.write_str("export destination must name a new file")
            }
            Self::ExportDestinationExists(path) => {
                write!(formatter, "export destination `{}` already exists", path.display())
            }
            Self::ExportFile {
                operation,
                path,
                source,
            } => write!(formatter, "export {operation} on `{}` failed: {source}", path.display()),
            Self::ExportFileCleanup {
                operation,
                temporary,
                source,
                cleanup,
            } => write!(
                formatter,
                "export {operation} on `{}` failed ({source}) and temporary file cleanup also failed ({cleanup})",
                temporary.display()
            ),
            Self::ExportVisibleCleanup {
                destination,
                temporary,
                cleanup,
            } => write!(
                formatter,
                "export output became visible at `{}`, but staged hard link `{}` could not be reaped: {cleanup}",
                destination.display(),
                temporary.display(),
            ),
            Self::ImportCleanup { import, cleanup } => write!(
                formatter,
                "source import failed ({import}) and node shutdown also failed ({cleanup})"
            ),
            Self::ImportRefusedCleanup { code, cleanup } => write!(
                formatter,
                "import reached terminal refusal {code:?} and node shutdown also failed ({cleanup})"
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
            Self::InvalidPosition(pos) => write!(
                formatter,
                "invalid snapshot position `{pos}`: expected `latest`, `decision:N`, `commit:<oid>`, `sequence:N`, `head:<id>`, or `capsule:<id>`"
            ),
            Self::Snapshot(error) => write!(formatter, "snapshot projection failed: {error}"),
            Self::AtCleanup {
                inspection,
                cleanup,
            } => write!(
                formatter,
                "snapshot query failed ({inspection}) and node shutdown also failed ({cleanup})"
            ),
        }
    }
}

impl Error for CliRefusal {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Tenant(error)
            | Self::Repository(error)
            | Self::RepositoryIncarnation(error)
            | Self::Principal(error)
            | Self::Object(error) => Some(error),
            Self::Node(error) => Some(error),
            Self::Import(error) => Some(error.as_ref()),
            Self::Listener(error) => Some(error),
            Self::Serve(error) => Some(error),
            Self::ServeServer(error) => Some(error),
            Self::ServeServerCleanup { serving, .. } => Some(serving.as_ref()),
            Self::ExportMaterialization(error) => Some(error.as_ref()),
            Self::ExportFile { source, .. } | Self::ExportFileCleanup { source, .. } => {
                Some(source.as_ref())
            }
            Self::ExportVisibleCleanup { cleanup, .. } => Some(cleanup.as_ref()),
            Self::ImportCleanup { import, .. } => Some(import.as_ref()),
            Self::ImportRefusedCleanup { cleanup, .. } => Some(cleanup.as_ref()),
            Self::DoctorCleanup { inspection, .. } => Some(inspection),
            Self::ServeCleanup { serving, .. } => Some(serving),
            Self::ExportCleanup { export, .. } => Some(export.as_ref()),
            Self::Snapshot(error) => Some(error),
            Self::AtCleanup { inspection, .. } => Some(inspection.as_ref()),
            Self::Usage
            | Self::UnsupportedObjectFormat(_)
            | Self::ExportDestination
            | Self::ExportDestinationExists(_)
            | Self::ImportRefused(_)
            | Self::InvalidServeLimit { .. }
            | Self::InvalidPosition(_) => None,
        }
    }
}

/// Detailed result of one position-addressed forge snapshot query (`fg at`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtReport {
    /// Summary view of the snapshot aggregate.
    Summary {
        /// Human-readable summary string.
        snapshot_summary: String,
        /// Formatted target position.
        target: String,
        /// Canonical authority head ID as of snapshot.
        head_id: String,
        /// Decision sequence if known.
        decision_sequence: Option<u64>,
        /// Count of visible references.
        refs_count: usize,
        /// Count of visible pull requests.
        prs_count: usize,
    },
    /// Detailed listing of references as of snapshot position.
    Refs {
        /// Formatted target position.
        position: String,
        /// List of (ref_name, target_oid).
        refs: Vec<(String, String)>,
    },
    /// Detailed listing of pull requests as of snapshot position.
    PullRequests {
        /// Formatted target position.
        position: String,
        /// List of (pr_number, title, state_desc, target_branch).
        pull_requests: Vec<(u64, String, String, String)>,
    },
    /// Difference between two snapshot positions.
    Diff {
        /// Formatted older position.
        older: String,
        /// Formatted newer position.
        newer: String,
        /// Count of changed references.
        ref_changes_count: usize,
        /// Count of changed pull requests.
        pr_changes_count: usize,
    },
}

/// The observable result of one supported `fg` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliOutcome {
    /// `fg init` created or found the durable authority head.
    Initialized(NodeInitialization),
    /// `fg import` published every source ref as an authenticated terminal
    /// source-import decision.
    Imported {
        /// Number of source ref commands represented in the admission result.
        command_count: usize,
    },
    /// `fg doctor` authenticated the current authority receipt.
    ///
    /// This first doctor slice does not claim an RCR replay proof or a storage
    /// scan. It opens an already initialized node, authenticates its current
    /// head receipt, and then shuts the node down cleanly.
    Doctor(DoctorReport),
    /// `fg serve` completed one bounded, fully drained git-daemon service run.
    Served {
        /// Socket address actually bound for this bounded service run.
        listen_address: SocketAddr,
        /// The exact accepted/completed/refused counts after all admitted
        /// session children drained.
        service: GitDaemonServerReceipt,
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
    /// `fg at` projected forge aggregate state as of a specified position.
    At(AtReport),
}

/// Executes a bounded command invocation without ambient configuration.
pub fn run(arguments: &[String]) -> Result<CliOutcome, CliRefusal> {
    match arguments {
        [command, storage_root, tenant, repository] if command == "init" => run_init(
            storage_root,
            tenant,
            repository,
            GitHashAlgorithm::Sha1,
            None,
        ),
        [command, storage_root, tenant, repository, format] if command == "init" => run_init(
            storage_root,
            tenant,
            repository,
            object_format(format)?,
            None,
        ),
        [command, storage_root, tenant, repository, flag, key]
            if command == "init" && flag == "--creation-idempotency-key" =>
        {
            run_init(
                storage_root,
                tenant,
                repository,
                GitHashAlgorithm::Sha1,
                Some(key.as_bytes()),
            )
        }
        [command, storage_root, tenant, repository, flag, key, format]
            if command == "init" && flag == "--creation-idempotency-key" =>
        {
            run_init(
                storage_root,
                tenant,
                repository,
                object_format(format)?,
                Some(key.as_bytes()),
            )
        }
        [
            command,
            storage_root,
            tenant,
            repository,
            principal,
            idempotency_key,
            source,
        ] if command == "import" => {
            let principal = PrincipalId::from_hex(principal).map_err(CliRefusal::Principal)?;
            run_import(
                storage_root,
                tenant,
                repository,
                principal,
                idempotency_key.as_bytes(),
                Path::new(source),
                None,
            )
        }
        [
            command,
            storage_root,
            tenant,
            repository,
            principal,
            idempotency_key,
            source,
            flag,
            incarnation,
        ] if command == "import" && flag == "--expected-incarnation" => {
            let principal = PrincipalId::from_hex(principal).map_err(CliRefusal::Principal)?;
            run_import(
                storage_root,
                tenant,
                repository,
                principal,
                idempotency_key.as_bytes(),
                Path::new(source),
                Some(parse_resolution_input(
                    incarnation,
                    RepositoryResolutionInput::CapabilityToken,
                )?),
            )
        }
        [command, storage_root, tenant, repository] if command == "doctor" => {
            run_doctor(storage_root, tenant, repository, None, None)
        }
        [command, storage_root, tenant, repository, sample] if command == "doctor" => {
            let sample =
                GitOid::from_hex(GitHashAlgorithm::Sha1, sample).map_err(CliRefusal::Object)?;
            run_doctor(storage_root, tenant, repository, Some(sample), None)
        }
        [command, storage_root, tenant, repository, flag, incarnation]
            if command == "doctor" && flag == "--expected-incarnation" =>
        {
            run_doctor(
                storage_root,
                tenant,
                repository,
                None,
                Some(parse_resolution_input(
                    incarnation,
                    RepositoryResolutionInput::CacheEntry,
                )?),
            )
        }
        [
            command,
            storage_root,
            tenant,
            repository,
            sample,
            flag,
            incarnation,
        ] if command == "doctor" && flag == "--expected-incarnation" => {
            let sample =
                GitOid::from_hex(GitHashAlgorithm::Sha1, sample).map_err(CliRefusal::Object)?;
            run_doctor(
                storage_root,
                tenant,
                repository,
                Some(sample),
                Some(parse_resolution_input(
                    incarnation,
                    RepositoryResolutionInput::CacheEntry,
                )?),
            )
        }
        [command, storage_root, tenant, repository, destination] if command == "export" => {
            run_export(
                storage_root,
                tenant,
                repository,
                PathBuf::from(destination),
                None,
            )
        }
        [
            command,
            storage_root,
            tenant,
            repository,
            destination,
            flag,
            incarnation,
        ] if command == "export" && flag == "--expected-incarnation" => run_export(
            storage_root,
            tenant,
            repository,
            PathBuf::from(destination),
            Some(parse_resolution_input(
                incarnation,
                RepositoryResolutionInput::ObjectLocation,
            )?),
        ),
        [command, storage_root, tenant, repository, listen_address] if command == "serve" => {
            run_serve(
                storage_root,
                tenant,
                repository,
                listen_address,
                None,
                GitDaemonServerLimits::DEFAULT,
            )
        }
        [
            command,
            storage_root,
            tenant,
            repository,
            listen_address,
            flag,
            incarnation,
        ] if command == "serve" && flag == "--expected-incarnation" => run_serve(
            storage_root,
            tenant,
            repository,
            listen_address,
            Some(parse_resolution_input(
                incarnation,
                RepositoryResolutionInput::TransportTarget,
            )?),
            GitDaemonServerLimits::DEFAULT,
        ),
        [
            command,
            storage_root,
            tenant,
            repository,
            listen_address,
            sessions_flag,
            sessions,
            in_flight_flag,
            in_flight,
        ] if command == "serve"
            && sessions_flag == "--max-sessions"
            && in_flight_flag == "--max-in-flight" =>
        {
            run_serve(
                storage_root,
                tenant,
                repository,
                listen_address,
                None,
                parse_server_limits(sessions, in_flight)?,
            )
        }
        [
            command,
            storage_root,
            tenant,
            repository,
            listen_address,
            incarnation_flag,
            incarnation,
            sessions_flag,
            sessions,
            in_flight_flag,
            in_flight,
        ] if command == "serve"
            && incarnation_flag == "--expected-incarnation"
            && sessions_flag == "--max-sessions"
            && in_flight_flag == "--max-in-flight" =>
        {
            run_serve(
                storage_root,
                tenant,
                repository,
                listen_address,
                Some(parse_resolution_input(
                    incarnation,
                    RepositoryResolutionInput::TransportTarget,
                )?),
                parse_server_limits(sessions, in_flight)?,
            )
        }
        [command, ..] if command == "at" => parse_and_run_at(arguments),
        _ => Err(CliRefusal::Usage),
    }
}

/// Creates one repository in the explicitly selected object format.
fn run_init(
    storage_root: &str,
    tenant: &str,
    repository: &str,
    format: GitHashAlgorithm,
    creation_idempotency_key: Option<&[u8]>,
) -> Result<CliOutcome, CliRefusal> {
    let configuration = node_config(storage_root, tenant, repository, Some(format), None)?;
    let configuration = match creation_idempotency_key {
        Some(key) => configuration.with_creation_idempotency_key(key.to_vec()),
        None => configuration,
    };
    let (node, initialization) = OneNode::init(configuration).map_err(CliRefusal::Node)?;
    node.shutdown().map_err(CliRefusal::Node)?;
    Ok(CliOutcome::Initialized(initialization))
}

/// Serves one explicitly bounded multi-session git-daemon run.
///
/// The repository's object format is selected from its authenticated canonical
/// configuration, not supplied by this open-path command.
fn run_serve(
    storage_root: &str,
    tenant: &str,
    repository: &str,
    listen_address: &str,
    resolution_input: Option<RepositoryResolutionInput>,
    server_limits: GitDaemonServerLimits,
) -> Result<CliOutcome, CliRefusal> {
    {
        {
            let listener = TcpListener::bind(listen_address).map_err(CliRefusal::Listener)?;
            let listen_address = listener.local_addr().map_err(CliRefusal::Listener)?;
            let node = OneNode::open_existing(node_config(
                storage_root,
                tenant,
                repository,
                None,
                resolution_input,
            )?)
            .map_err(CliRefusal::Node)?;
            let serving =
                node.serve_git_daemon_bounded(&listener, server_limits, Default::default());
            let cleanup = node.shutdown();
            match (serving, cleanup) {
                (Ok(service), Ok(())) => Ok(CliOutcome::Served {
                    listen_address,
                    service,
                }),
                (Err(serving), Ok(())) => Err(CliRefusal::ServeServer(serving)),
                (Ok(_), Err(cleanup)) => Err(CliRefusal::Node(cleanup)),
                (Err(serving), Err(cleanup)) => Err(CliRefusal::ServeServerCleanup {
                    serving: Box::new(serving),
                    cleanup: Box::new(cleanup),
                }),
            }
        }
    }
}

fn parse_server_limits(
    sessions: &str,
    in_flight: &str,
) -> Result<GitDaemonServerLimits, CliRefusal> {
    let sessions = sessions
        .parse::<usize>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| CliRefusal::InvalidServeLimit {
            field: "--max-sessions",
            value: sessions.to_owned(),
        })?;
    let in_flight = in_flight
        .parse::<usize>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| CliRefusal::InvalidServeLimit {
            field: "--max-in-flight",
            value: in_flight.to_owned(),
        })?;
    GitDaemonServerLimits::try_new(sessions, in_flight).map_err(|refusal| match refusal {
        fgit_node::GitDaemonServerLimitRefusal::ZeroSessionLimit => CliRefusal::InvalidServeLimit {
            field: "--max-sessions",
            value: sessions.to_string(),
        },
        fgit_node::GitDaemonServerLimitRefusal::ZeroInFlightLimit => {
            CliRefusal::InvalidServeLimit {
                field: "--max-in-flight",
                value: in_flight.to_string(),
            }
        }
    })
}

fn run_import(
    storage_root: &str,
    tenant: &str,
    repository: &str,
    principal: PrincipalId,
    idempotency_key: &[u8],
    source: &Path,
    resolution_input: Option<RepositoryResolutionInput>,
) -> Result<CliOutcome, CliRefusal> {
    let mut node = OneNode::open_existing(node_config(
        storage_root,
        tenant,
        repository,
        None,
        resolution_input,
    )?)
    .map_err(CliRefusal::Node)?;
    // BRING THIS CELL INTO SERVICE, EXPLICITLY. `frankengit-fg036b`,
    // `GoldLotus`'s option (A) ruling: the cell lifecycle is operator-driven, so
    // `open_existing` leaves the cell in `CellState::Bootstrapping` and the
    // source import below refuses to publish from there. Nothing transitions a
    // node silently at construction — a node that came up is not a node someone
    // put into service, and deleting that distinction inside `init` would
    // delete it for every consumer at once.
    //
    // `CellTransitionCause::ServiceBringUp` rather than `Operator`, because
    // that is what happened: no control-plane instruction arrived, this process
    // was started to import and decided about itself. Recording `Operator`
    // would put an instruction in the audit that nobody gave.
    //
    // Refusals travel as `CliRefusal::Import`, which already carries a
    // source-import refusal, so a cell that cannot be brought into service
    // reports through the same channel as a source that cannot be imported.
    if let Err(refusal) = node.bring_into_service(HeadGeneration::FIRST) {
        let cleanup = node.shutdown();
        return Err(match cleanup {
            Ok(()) => CliRefusal::Import(Box::new(NodeSourceImportRefusal::CellState(refusal))),
            Err(cleanup) => CliRefusal::ImportCleanup {
                import: Box::new(NodeSourceImportRefusal::CellState(refusal)),
                cleanup: Box::new(cleanup),
            },
        });
    }
    let node = node;
    let request = node.request_context();
    let imported = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &request,
            source,
            principal,
            idempotency_key,
        ));
    let cleanup = node.shutdown();
    match (imported, cleanup) {
        (Ok(admission), Ok(())) => {
            if let Some(code) = admission.commands.iter().find_map(|command| {
                let DecisionOutcome::Refused { code, .. } = command.terminal.outcome else {
                    return None;
                };
                Some(code)
            }) {
                Err(CliRefusal::ImportRefused(code))
            } else {
                Ok(CliOutcome::Imported {
                    command_count: admission.commands.len(),
                })
            }
        }
        (Err(import), Ok(())) => Err(CliRefusal::Import(Box::new(import))),
        (Ok(admission), Err(cleanup)) => {
            if let Some(code) = admission.commands.iter().find_map(|command| {
                let DecisionOutcome::Refused { code, .. } = command.terminal.outcome else {
                    return None;
                };
                Some(code)
            }) {
                Err(CliRefusal::ImportRefusedCleanup {
                    code,
                    cleanup: Box::new(cleanup),
                })
            } else {
                Err(CliRefusal::Node(cleanup))
            }
        }
        (Err(import), Err(cleanup)) => Err(CliRefusal::ImportCleanup {
            import: Box::new(import),
            cleanup: Box::new(cleanup),
        }),
    }
}

fn run_export(
    storage_root: &str,
    tenant: &str,
    repository: &str,
    destination: PathBuf,
    resolution_input: Option<RepositoryResolutionInput>,
) -> Result<CliOutcome, CliRefusal> {
    let node = OneNode::open_existing(node_config(
        storage_root,
        tenant,
        repository,
        None,
        resolution_input,
    )?)
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
    resolution_input: Option<RepositoryResolutionInput>,
) -> Result<CliOutcome, CliRefusal> {
    let node = OneNode::open_existing(node_config(
        storage_root,
        tenant,
        repository,
        None,
        resolution_input,
    )?)
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

fn parse_hex_bytes(hex: &str) -> Result<Vec<u8>, CliRefusal> {
    if hex.len() % 2 != 0 {
        return Err(CliRefusal::InvalidPosition(hex.to_string()));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks_exact(2) {
        let high = match chunk[0] {
            b'0'..=b'9' => chunk[0] - b'0',
            b'a'..=b'f' => chunk[0] - b'a' + 10,
            b'A'..=b'F' => chunk[0] - b'A' + 10,
            _ => return Err(CliRefusal::InvalidPosition(hex.to_string())),
        };
        let low = match chunk[1] {
            b'0'..=b'9' => chunk[1] - b'0',
            b'a'..=b'f' => chunk[1] - b'a' + 10,
            b'A'..=b'F' => chunk[1] - b'A' + 10,
            _ => return Err(CliRefusal::InvalidPosition(hex.to_string())),
        };
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn parse_derived_id_from_hex<T>(
    token: &str,
    hex_str: &str,
    ctor: fn(DigestAlgorithmId, CodecVersion, DigestBytes) -> T,
) -> Result<T, CliRefusal> {
    let bytes = parse_hex_bytes(hex_str)?;
    let digest =
        DigestBytes::try_new(&bytes).map_err(|_| CliRefusal::InvalidPosition(token.to_string()))?;
    let alg = DigestAlgorithmId::try_new(1)
        .map_err(|_| CliRefusal::InvalidPosition(token.to_string()))?;
    Ok(ctor(alg, CANONICAL_CODEC_VERSION, digest))
}

fn parse_position_target(token: &str) -> Result<PositionTarget, CliRefusal> {
    if token.eq_ignore_ascii_case("latest") {
        return Ok(PositionTarget::Latest);
    }
    if let Some(rest) = token.strip_prefix("decision:") {
        let seq = rest
            .parse::<u64>()
            .map_err(|_| CliRefusal::InvalidPosition(token.to_string()))?;
        let seq = DecisionSequence::try_new(seq)
            .map_err(|_| CliRefusal::InvalidPosition(token.to_string()))?;
        return Ok(PositionTarget::Decision(seq));
    }
    if let Some(rest) = token.strip_prefix("commit:") {
        let id = parse_derived_id_from_hex(token, rest, RepositoryCommitId::from_digest)?;
        return Ok(PositionTarget::Commit(id));
    }
    if let Some(rest) = token.strip_prefix("sequence:") {
        let seq = rest
            .parse::<u64>()
            .map_err(|_| CliRefusal::InvalidPosition(token.to_string()))?;
        let seq = RepositorySequence::try_new(seq)
            .map_err(|_| CliRefusal::InvalidPosition(token.to_string()))?;
        return Ok(PositionTarget::Sequence(seq));
    }
    if let Some(rest) = token.strip_prefix("head:") {
        let id = parse_derived_id_from_hex(token, rest, RepositoryAuthorityHeadId::from_digest)?;
        return Ok(PositionTarget::Head(id));
    }
    if let Some(rest) = token.strip_prefix("capsule:") {
        let id = parse_derived_id_from_hex(token, rest, RepositoryCapsuleId::from_digest)?;
        return Ok(PositionTarget::Capsule(id));
    }
    if let Ok(seq) = token.parse::<u64>() {
        if let Ok(seq) = DecisionSequence::try_new(seq) {
            return Ok(PositionTarget::Decision(seq));
        }
    }
    Err(CliRefusal::InvalidPosition(token.to_string()))
}

fn parse_and_run_at(arguments: &[String]) -> Result<CliOutcome, CliRefusal> {
    if arguments.len() < 5 {
        return Err(CliRefusal::Usage);
    }
    let storage_root = &arguments[1];
    let tenant = &arguments[2];
    let repository = &arguments[3];
    let position = &arguments[4];

    let rest = &arguments[5..];
    let mut verb: Option<&str> = None;
    let mut diff_pos: Option<&str> = None;
    let mut actor: Option<&str> = None;
    let mut incarnation: Option<RepositoryResolutionInput> = None;

    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "refs" | "prs" => {
                if verb.is_some() {
                    return Err(CliRefusal::Usage);
                }
                verb = Some(rest[i].as_str());
                i += 1;
            }
            "diff" => {
                if verb.is_some() || i + 1 >= rest.len() {
                    return Err(CliRefusal::Usage);
                }
                verb = Some("diff");
                diff_pos = Some(rest[i + 1].as_str());
                i += 2;
            }
            "--actor" => {
                if i + 1 >= rest.len() {
                    return Err(CliRefusal::Usage);
                }
                actor = Some(rest[i + 1].as_str());
                i += 2;
            }
            "--expected-incarnation" => {
                if i + 1 >= rest.len() {
                    return Err(CliRefusal::Usage);
                }
                incarnation = Some(parse_resolution_input(
                    &rest[i + 1],
                    RepositoryResolutionInput::CacheEntry,
                )?);
                i += 2;
            }
            _ => return Err(CliRefusal::Usage),
        }
    }

    let opts = AtOptions {
        storage_root,
        tenant,
        repository,
        position,
        subcommand: verb,
        diff_position: diff_pos,
        actor,
        resolution_input: incarnation,
    };
    run_at(opts)
}

struct AtOptions<'a> {
    storage_root: &'a str,
    tenant: &'a str,
    repository: &'a str,
    position: &'a str,
    subcommand: Option<&'a str>,
    diff_position: Option<&'a str>,
    actor: Option<&'a str>,
    resolution_input: Option<RepositoryResolutionInput>,
}

fn run_at(opts: AtOptions<'_>) -> Result<CliOutcome, CliRefusal> {
    let position_target = parse_position_target(opts.position)?;
    let diff_target = opts.diff_position.map(parse_position_target).transpose()?;
    let actor_id = opts
        .actor
        .map(|hex| PrincipalId::from_hex(hex).map_err(CliRefusal::Principal))
        .transpose()?;

    let node = OneNode::open_existing(node_config(
        opts.storage_root,
        opts.tenant,
        opts.repository,
        None,
        opts.resolution_input,
    )?)
    .map_err(CliRefusal::Node)?;

    let result = node.runtime().block_on(async {
        let request = node.request_context();
        let head_read = node
            .read_authority_head_in(&request)
            .await
            .map_err(CliRefusal::Node)?;
        let receipt = match head_read {
            fgit_authority::HeadRead::Present(receipt) => receipt,
            fgit_authority::HeadRead::Absent => {
                return Err(CliRefusal::Node(
                    fgit_node::NodeRefusal::AuthorityHeadAbsent,
                ));
            }
        };
        let head_body: fgit_codec::schema::RepositoryAuthorityHeadBody =
            fgit_codec::decode_body(receipt.body(), fgit_codec::DecodeLimits::DEFAULT).map_err(
                |e| {
                    CliRefusal::Node(fgit_node::NodeRefusal::AdmissionMaterialization(Box::new(
                        fgit_node::AdmissionMaterializationRefusal::HeadBody(
                            fgit_authority::HeadBodyRefusal::Codec(e),
                        ),
                    )))
                },
            )?;
        let head_id = fgit_codec::body_id(&fgit_codec::CryptoBodyIdentity, &head_body)
            .map_err(|e| {
                CliRefusal::Node(fgit_node::NodeRefusal::AdmissionMaterialization(Box::new(
                    fgit_node::AdmissionMaterializationRefusal::HeadIdentity(e),
                )))
            })
            .and_then(|identity| {
                fgit_types::RepositoryAuthorityHeadId::from_internal_object_id(identity).map_err(
                    |e| {
                        CliRefusal::Node(fgit_node::NodeRefusal::AdmissionMaterialization(
                            Box::new(
                                fgit_node::AdmissionMaterializationRefusal::HeadIdentityDomain(e),
                            ),
                        ))
                    },
                )
            })?;

        let admission = node.materialize_admission_in(&request).await.map_err(|e| {
            CliRefusal::Node(fgit_node::NodeRefusal::AdmissionMaterialization(Box::new(
                e,
            )))
        })?;

        let live_refs: std::collections::BTreeMap<Vec<u8>, GitOid> = admission
            .snapshot()
            .refs
            .iter()
            .map(|(k, v)| (k.as_bytes().to_vec(), *v))
            .collect();

        let live_snapshot = ForgeSnapshot {
            target_position: PositionTarget::Latest,
            repository_id: head_body.repository_id,
            effective_decision_sequence: head_body.latest_decision_sequence,
            effective_head_id: head_id,
            effective_head_generation: head_body.generation,
            effective_committed_rcr_id: head_body.latest_committed_rcr_id,
            ref_root: head_body.ref_root,
            forge_position_root: head_body.forge_position_root,
            historical_policy_epoch: head_body.policy_epoch,
            refs: live_refs.clone(),
            pull_requests: Default::default(),
            check_receipts: Default::default(),
            replayed_batches_count: 0,
            used_capsule_id: head_body.last_checkpoint_id,
        };

        let mut snapshot = match &position_target {
            PositionTarget::Latest => live_snapshot.clone(),
            PositionTarget::Decision(seq) if Some(*seq) == head_body.latest_decision_sequence => {
                live_snapshot.clone()
            }
            PositionTarget::Head(id) if *id == head_id => live_snapshot.clone(),
            _ => project_snapshot_from_history(
                position_target,
                head_id,
                &head_body,
                &[],
                &[],
                &live_refs,
                &SnapshotLimits::default(),
            )
            .map_err(CliRefusal::Snapshot)?,
        };

        if let Some(_actor) = actor_id {
            let policy = SnapshotDisclosurePolicy::Restricted {
                allowed_refs: Some(live_refs.keys().cloned().collect()),
                revoked_refs: std::collections::BTreeSet::new(),
                allowed_prs: None,
                revoked_prs: std::collections::BTreeSet::new(),
                repository_access_revoked: false,
            };
            snapshot = policy
                .filter_snapshot(snapshot)
                .map_err(CliRefusal::Snapshot)?;
        }

        match opts.subcommand {
            None => {
                let summary = snapshot.summary();
                Ok(CliOutcome::At(AtReport::Summary {
                    snapshot_summary: summary,
                    target: format!("{position_target}"),
                    head_id: format!("{}", snapshot.effective_head_id),
                    decision_sequence: snapshot.effective_decision_sequence.map(|s| s.get()),
                    refs_count: snapshot.refs.len(),
                    prs_count: snapshot.pull_requests.len(),
                }))
            }
            Some("refs") => {
                let refs = snapshot
                    .refs
                    .iter()
                    .map(|(name, oid)| {
                        (String::from_utf8_lossy(name).into_owned(), oid.to_string())
                    })
                    .collect();
                Ok(CliOutcome::At(AtReport::Refs {
                    position: format!("{position_target}"),
                    refs,
                }))
            }
            Some("prs") => {
                let prs = snapshot
                    .pull_requests
                    .iter()
                    .map(|(num, pr)| {
                        (
                            num.get(),
                            String::from_utf8_lossy(&pr.source_ref).into_owned(),
                            format!("{}", pr.state),
                            String::from_utf8_lossy(&pr.target_ref).into_owned(),
                        )
                    })
                    .collect();
                Ok(CliOutcome::At(AtReport::PullRequests {
                    position: format!("{position_target}"),
                    pull_requests: prs,
                }))
            }
            Some("diff") => {
                let other_target = diff_target.ok_or(CliRefusal::Usage)?;
                let older_snapshot = snapshot;
                let diff = ForgeSnapshotDiff::diff(&older_snapshot, &live_snapshot);
                Ok(CliOutcome::At(AtReport::Diff {
                    older: format!("{position_target}"),
                    newer: format!("{other_target}"),
                    ref_changes_count: diff.ref_changes.len(),
                    pr_changes_count: diff.pr_changes.len(),
                }))
            }
            _ => Err(CliRefusal::Usage),
        }
    });

    let cleanup = node.shutdown();
    match (result, cleanup) {
        (Ok(outcome), Ok(())) => Ok(outcome),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(cleanup)) => Err(CliRefusal::Node(cleanup)),
        (Err(error), Err(cleanup)) => Err(CliRefusal::AtCleanup {
            inspection: Box::new(error),
            cleanup: Box::new(cleanup),
        }),
    }
}

fn node_config(
    storage_root: &str,
    tenant: &str,
    repository: &str,
    object_format: Option<GitHashAlgorithm>,
    resolution_input: Option<RepositoryResolutionInput>,
) -> Result<NodeConfig, CliRefusal> {
    let tenant_id = TenantId::from_hex(tenant).map_err(CliRefusal::Tenant)?;
    let repository_id = RepositoryId::from_hex(repository).map_err(CliRefusal::Repository)?;
    let configuration = NodeConfig::new(PathBuf::from(storage_root), tenant_id, repository_id);
    let configuration = match object_format {
        Some(object_format) => configuration.with_object_format(object_format),
        None => configuration,
    };
    Ok(match resolution_input {
        Some(input) => configuration.with_resolution_input(input),
        None => configuration,
    })
}

/// Decodes a caller-provided repository incarnation for one concrete existing
/// resolution path.  The path marker stays explicit, so an operator cannot
/// accidentally present a cache proof as a transport target.
fn parse_resolution_input(
    token: &str,
    wrap: fn(RepositoryIncarnationId) -> RepositoryResolutionInput,
) -> Result<RepositoryResolutionInput, CliRefusal> {
    RepositoryIncarnationId::from_hex(token)
        .map(wrap)
        .map_err(CliRefusal::RepositoryIncarnation)
}

/// Parses the explicit object-format token accepted by `fg init`.
///
/// Only Git's two defined repository formats are accepted, and anything else is
/// a typed refusal rather than a default.
fn object_format(token: &str) -> Result<GitHashAlgorithm, CliRefusal> {
    match token {
        "sha1" => Ok(GitHashAlgorithm::Sha1),
        "sha256" => Ok(GitHashAlgorithm::Sha256),
        other => Err(CliRefusal::UnsupportedObjectFormat(other.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use fgit_crypto::{GitObjectKind, git_object_id};
    use fgit_node::{NodeConfig, NodeRefusal, OneNode};
    use fgit_types::{GitHashAlgorithm, GitOid, RepositoryId, RepositoryIncarnationId, TenantId};

    use super::{CliOutcome, CliRefusal, run};

    static NEXT_SCRATCH_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    fn write_loose_commit_repository(root: &Path) -> GitOid {
        fs::create_dir_all(root).expect("source repository directory creates");
        let blob = write_loose_object(root, GitObjectKind::Blob, b"first clone fixture\n");
        let mut tree = b"100644 README\0".to_vec();
        tree.extend_from_slice(blob.require_sha1().expect("fixture is SHA-1").as_bytes());
        let tree = write_loose_object(root, GitObjectKind::Tree, &tree);
        let commit = format!(
            "tree {tree}\nauthor FrankenGit <fg@example.invalid> 0 +0000\ncommitter FrankenGit <fg@example.invalid> 0 +0000\n\nfirst clone fixture\n"
        );
        let commit = write_loose_object(root, GitObjectKind::Commit, commit.as_bytes());
        let ref_path = root.join("refs/heads/main");
        fs::create_dir_all(ref_path.parent().expect("source ref parent exists"))
            .expect("source ref directory creates");
        fs::write(ref_path, format!("{commit}\n")).expect("source direct ref writes");
        fs::write(root.join("HEAD"), b"ref: refs/heads/main\n").expect("source HEAD writes");
        commit
    }

    fn write_loose_object(root: &Path, kind: GitObjectKind, body: &[u8]) -> GitOid {
        let identity = git_object_id(GitHashAlgorithm::Sha1, kind, body);
        let text = identity.to_string();
        let (directory, file) = text.split_at(2);
        let path = root.join("objects").join(directory).join(file);
        fs::create_dir_all(path.parent().expect("loose object parent exists"))
            .expect("loose object directory creates");
        let mut framed = format!("{} {}\0", kind.label(), body.len()).into_bytes();
        framed.extend_from_slice(body);
        fs::write(path, zlib_stored_member(&framed)).expect("loose object writes");
        identity
    }

    fn zlib_stored_member(bytes: &[u8]) -> Vec<u8> {
        let length = u16::try_from(bytes.len()).expect("fixture member fits one stored block");
        let mut member = Vec::with_capacity(bytes.len() + 11);
        member.extend_from_slice(&[0x78, 0x01, 0x01]);
        member.extend_from_slice(&length.to_le_bytes());
        member.extend_from_slice(&(!length).to_le_bytes());
        member.extend_from_slice(bytes);
        member.extend_from_slice(&adler32(bytes).to_be_bytes());
        member
    }

    fn adler32(bytes: &[u8]) -> u32 {
        let mut a = 1_u32;
        let mut b = 0_u32;
        for byte in bytes {
            a = (a + u32::from(*byte)) % 65_521;
            b = (b + a) % 65_521;
        }
        (b << 16) | a
    }

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
    fn serve_refuses_zero_session_or_in_flight_bounds_before_opening_a_node() {
        let zero_sessions = vec![
            "serve".to_owned(),
            "/missing".to_owned(),
            "11111111111111111111111111111111".to_owned(),
            "22222222222222222222222222222222".to_owned(),
            "127.0.0.1:9418".to_owned(),
            "--max-sessions".to_owned(),
            "0".to_owned(),
            "--max-in-flight".to_owned(),
            "1".to_owned(),
        ];
        assert!(matches!(
            run(&zero_sessions),
            Err(CliRefusal::InvalidServeLimit {
                field: "--max-sessions",
                ..
            })
        ));

        let zero_in_flight = vec![
            "serve".to_owned(),
            "/missing".to_owned(),
            "11111111111111111111111111111111".to_owned(),
            "22222222222222222222222222222222".to_owned(),
            "127.0.0.1:9418".to_owned(),
            "--max-sessions".to_owned(),
            "1".to_owned(),
            "--max-in-flight".to_owned(),
            "0".to_owned(),
        ];
        assert!(matches!(
            run(&zero_in_flight),
            Err(CliRefusal::InvalidServeLimit {
                field: "--max-in-flight",
                ..
            })
        ));
    }

    /// `fg init` accepts Git's two defined repository formats explicitly.
    ///
    /// What this can and cannot assert: the *outcome* is observable, the
    /// resulting repository's format is not. Nothing persists a repository's
    /// object format yet (`NodeConfig::with_object_format` is config-only), so
    /// no API reads it back. That gap is recorded in
    /// `docs/D3_SHA256_REPOSITORY_DECISION.md`; when the format lands in the
    /// persisted `RepositoryConfigurationBody`, this test should assert the
    /// read-back value rather than merely a successful init.
    #[test]
    fn init_accepts_both_defined_object_formats_explicitly() {
        for format in ["sha1", "sha256"] {
            let scratch = ScratchDirectory::new();
            let command = vec![
                "init".to_owned(),
                scratch.0.to_string_lossy().into_owned(),
                "11111111111111111111111111111111".to_owned(),
                "22222222222222222222222222222222".to_owned(),
                format.to_owned(),
            ];
            assert!(
                matches!(run(&command), Ok(CliOutcome::Initialized(_))),
                "fg init must accept the explicit `{format}` repository format"
            );
        }
    }

    #[test]
    fn creation_recovery_and_cache_resolution_are_incarnation_bound() {
        let scratch = ScratchDirectory::new();
        let storage_root = scratch.0.to_string_lossy().into_owned();
        let tenant = "11111111111111111111111111111111".to_owned();
        let repository = "22222222222222222222222222222222".to_owned();
        let keyed_init = vec![
            "init".to_owned(),
            storage_root.clone(),
            tenant.clone(),
            repository.clone(),
            "--creation-idempotency-key".to_owned(),
            "incarnation-create-once".to_owned(),
            "sha256".to_owned(),
        ];

        assert!(matches!(
            run(&keyed_init),
            Ok(CliOutcome::Initialized(
                fgit_node::NodeInitialization::Created
            ))
        ));
        assert!(matches!(
            run(&keyed_init),
            Ok(CliOutcome::Initialized(
                fgit_node::NodeInitialization::IdenticalRetry
            ))
        ));

        let node = OneNode::open_existing(NodeConfig::new(
            scratch.0.clone(),
            TenantId::from_bytes([0x11; 16]),
            RepositoryId::from_bytes([0x22; 16]),
        ))
        .expect("a key-recovered repository opens through its authenticated configuration");
        let current = node.repository_incarnation_id();
        node.shutdown().expect("current-incarnation reader closes");

        let permitted = vec![
            "doctor".to_owned(),
            storage_root.clone(),
            tenant.clone(),
            repository.clone(),
            "--expected-incarnation".to_owned(),
            current.to_string(),
        ];
        assert!(matches!(run(&permitted), Ok(CliOutcome::Doctor(_))));

        let stale = RepositoryIncarnationId::from_bytes([0x59; 16]);
        let stale_cache = vec![
            "doctor".to_owned(),
            storage_root.clone(),
            tenant.clone(),
            repository.clone(),
            "--expected-incarnation".to_owned(),
            stale.to_string(),
        ];
        assert!(matches!(
            run(&stale_cache),
            Err(CliRefusal::Node(NodeRefusal::RepositoryIncarnationMismatch {
                expected,
                observed,
            })) if expected == stale && observed == current
        ));

        let mismatched_retry = vec![
            "init".to_owned(),
            storage_root,
            tenant,
            repository,
            "--creation-idempotency-key".to_owned(),
            "incarnation-create-once".to_owned(),
            "sha1".to_owned(),
        ];
        assert!(matches!(
            run(&mismatched_retry),
            Err(CliRefusal::Node(NodeRefusal::Authority(_)))
        ));
    }

    /// The load-bearing case. An object format is permanent for the life of a
    /// repository, so an unrecognised token must REFUSE and name itself rather
    /// than quietly minting a SHA-1 repository the caller never asked for.
    ///
    /// A test asserting only "init fails" would pass against a refusal for any
    /// reason at all, so this pins the variant and its payload.
    #[test]
    fn init_refuses_an_unrecognised_object_format_instead_of_defaulting() {
        let scratch = ScratchDirectory::new();
        let command = vec![
            "init".to_owned(),
            scratch.0.to_string_lossy().into_owned(),
            "11111111111111111111111111111111".to_owned(),
            "22222222222222222222222222222222".to_owned(),
            "sha512".to_owned(),
        ];

        let refusal = run(&command).expect_err("an unknown object format cannot initialize");
        assert!(
            matches!(&refusal, CliRefusal::UnsupportedObjectFormat(token) if token == "sha512"),
            "the refusal must name the rejected token, got {refusal:?}"
        );
    }

    /// The permitted twin of the refusal above, and the backward-compatibility
    /// guard: the pre-existing four-argument form keeps working untouched.
    /// Without this, a change that broke every `fg init` invocation would still
    /// satisfy the refusal test.
    #[test]
    fn init_without_an_object_format_still_succeeds() {
        let scratch = ScratchDirectory::new();
        let command = vec![
            "init".to_owned(),
            scratch.0.to_string_lossy().into_owned(),
            "11111111111111111111111111111111".to_owned(),
            "22222222222222222222222222222222".to_owned(),
        ];
        assert!(matches!(run(&command), Ok(CliOutcome::Initialized(_))));
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
    fn import_publishes_a_verified_loose_commit_then_doctor_and_export_follow_it() {
        let scratch = ScratchDirectory::new();
        let storage_root = scratch.0.join("node").to_string_lossy().into_owned();
        let source = scratch.0.join("source.git");
        let imported_commit = write_loose_commit_repository(&source);
        let tenant = "11111111111111111111111111111111".to_owned();
        let repository = "22222222222222222222222222222222".to_owned();
        let principal = "33333333333333333333333333333333".to_owned();
        let init = vec![
            "init".to_owned(),
            storage_root.clone(),
            tenant.clone(),
            repository.clone(),
        ];
        assert!(matches!(run(&init), Ok(CliOutcome::Initialized(_))));

        let import = vec![
            "import".to_owned(),
            storage_root.clone(),
            tenant.clone(),
            repository.clone(),
            principal,
            "one-node-import-fixture".to_owned(),
            source.to_string_lossy().into_owned(),
        ];
        assert!(matches!(
            run(&import),
            Ok(CliOutcome::Imported { command_count: 1 })
        ));
        assert!(matches!(
            run(&import),
            Ok(CliOutcome::Imported { command_count: 1 })
        ));

        let doctor = vec![
            "doctor".to_owned(),
            storage_root.clone(),
            tenant.clone(),
            repository.clone(),
            imported_commit.to_string(),
        ];
        assert!(matches!(run(&doctor), Ok(CliOutcome::Doctor(_))));

        let destination = scratch.0.join("imported.pack");
        let export = vec![
            "export".to_owned(),
            storage_root,
            tenant,
            repository,
            destination.to_string_lossy().into_owned(),
        ];
        let outcome = run(&export).expect("imported authority closure exports as a real pack");
        let CliOutcome::Exported { bytes, .. } = outcome else {
            panic!("export reports a completed imported pack");
        };
        let pack = fs::read(destination).expect("imported pack is visible");
        assert_eq!(pack.len(), bytes);
        assert_eq!(&pack[..4], b"PACK");
    }

    #[test]
    fn import_never_reports_an_expected_old_refusal_as_success() {
        let scratch = ScratchDirectory::new();
        let storage_root = scratch.0.join("node").to_string_lossy().into_owned();
        let first_source = scratch.0.join("first.git");
        let second_source = scratch.0.join("second.git");
        write_loose_commit_repository(&first_source);
        write_loose_commit_repository(&second_source);
        let tenant = "11111111111111111111111111111111".to_owned();
        let repository = "22222222222222222222222222222222".to_owned();
        let principal = "33333333333333333333333333333333".to_owned();
        let init = vec![
            "init".to_owned(),
            storage_root.clone(),
            tenant.clone(),
            repository.clone(),
        ];
        assert!(matches!(run(&init), Ok(CliOutcome::Initialized(_))));

        let first_import = vec![
            "import".to_owned(),
            storage_root.clone(),
            tenant.clone(),
            repository.clone(),
            principal.clone(),
            "first-import".to_owned(),
            first_source.to_string_lossy().into_owned(),
        ];
        assert!(matches!(
            run(&first_import),
            Ok(CliOutcome::Imported { command_count: 1 })
        ));

        let conflicting_import = vec![
            "import".to_owned(),
            storage_root,
            tenant,
            repository,
            principal,
            "second-import".to_owned(),
            second_source.to_string_lossy().into_owned(),
        ];
        assert!(matches!(
            run(&conflicting_import),
            Err(CliRefusal::ImportRefused(
                fgit_types::RefusalCode::ExpectedOldRefMismatch
            ))
        ));
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
