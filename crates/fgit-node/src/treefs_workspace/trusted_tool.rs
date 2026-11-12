//! Local-operator workspace execution, not an untrusted agent/CI sandbox.
//!
//! The operator owns the whole repository. Only declared top-level input
//! prefixes are materialized for the tool, while the publisher retains the
//! complete tree scope needed to preserve unselected siblings during export.
//! No Git engine is invoked, and the resulting candidate never moves a ref.

use super::{NodeTreeSource, NodeWorkspaceRefusal, candidate, workspace_request_live};
use crate::{NodeRequestContext, OneNode};
use fgit_crypto::{
    GitHashAlgorithm, GitObjectKind, NativeObjectIdentity, Sha1, Sha256, git_object_id,
};
use fgit_git_object::{AcceptanceProfile, ObjectType, parse_object_body, parse_tree};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, PackLimits, PackPlanner, PackWriteError,
    PackWriteProfile, PackWriter,
};
use fgit_resource::{
    LeakDisposition, ObligationLedger, RegionCloseOutcome, RegionId, TerminalEvidence,
};
use fgit_runner::sparse_workspace::{
    HostClosed, HostRefusal, SharedInputCache, SharedInputCachePlan, SharedInputCacheStats,
    SharedInputPolicy, SparseWorkspace, SparseWorkspacePlan,
};
use fgit_treefs::{BaseView, SparseLimits, SparseManifest, TreeCapability, TreePath, WorkspaceId};
use fgit_types::numeric::ByteCount;
use fgit_types::{
    GitHashAlgorithm as ObjectFormat, GitOid as AnyOid, RefName, RepositoryAuthorityHeadId,
    RepositoryCommitId,
};
use fgit_wire::visibility::RefVisibility;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const FETCH_BYTES: u64 = 256 * 1024 * 1024;
const FETCH_OBJECTS: u64 = 100_000;
const PAYLOAD_BYTES: usize = 64 * 1024 * 1024;
const MAX_BATCH_JOBS: usize = 64;

/// Host input-materialization policy for sparse TreeFS workspaces.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum WorkspaceInputSharing {
    /// Clone extents from sealed anonymous descriptors when supported by the
    /// host filesystem, falling back to private byte copies otherwise.
    #[default]
    PreferReflink,
    /// Require kernel copy-on-write cloning (`FICLONE`); refuse before tool
    /// execution when the host filesystem cannot share immutable extents.
    RequireReflink,
    /// Copy every materialized file privately without probing or seeding a
    /// shared-input descriptor cache.
    Copy,
}
impl WorkspaceInputSharing {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PreferReflink => "prefer-reflink",
            Self::RequireReflink => "require-reflink",
            Self::Copy => "copy",
        }
    }

    const fn cache_policy(self) -> Option<SharedInputPolicy> {
        match self {
            Self::PreferReflink => Some(SharedInputPolicy::PreferReflink),
            Self::RequireReflink => Some(SharedInputPolicy::RequireReflink),
            Self::Copy => None,
        }
    }
}

/// Measured host materialization, sharing, import, and cleanup telemetry for
/// one settled workspace lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkspaceHostTelemetry {
    pub sharing_mode: WorkspaceInputSharing,
    pub reflink_supported: bool,
    pub copied_bytes: u64,
    pub shared_host_bytes: u64,
    pub metadata_bytes: u64,
    pub imported_bytes: u64,
    pub created_entries: u64,
    pub imported_entries: u64,
    pub removed_entries: u64,
    pub seeded_bytes: u64,
    pub cloned_bytes: u64,
    pub fallback_bytes: u64,
    pub creation_ns: u64,
    pub execution_ns: u64,
    pub cleanup_ns: u64,
}

/// One isolated tool job in a shared-base parallel workspace batch.
#[derive(Debug)]
pub struct WorkspaceBatchJob {
    pub workspace_id: [u8; 16],
    pub output_paths: Vec<Vec<u8>>,
    pub command: Command,
    pub author: String,
    pub timestamp: u64,
    pub message: Vec<u8>,
}

/// Settled batch execution over one authority-selected immutable TreeFS base.
#[derive(Debug)]
pub struct WorkspaceBatchResult {
    pub sharing_mode: WorkspaceInputSharing,
    pub cache_stats: SharedInputCacheStats,
    pub results: Vec<WorkspaceToolResult>,
}

/// A complete incremental candidate pack. Reused objects remain in the base
/// repository named by `source_commit`; this is not a standalone clone bundle.
#[derive(Debug)]
pub struct WorkspaceToolResult {
    pub object_format: ObjectFormat,
    pub source_commit: AnyOid,
    pub source_rcr: RepositoryCommitId,
    pub candidate_commit: AnyOid,
    pub root_tree: AnyOid,
    pub changed_paths: Vec<Vec<u8>>,
    pub object_count: usize,
    pub telemetry: WorkspaceHostTelemetry,
    pack: Vec<u8>,
}
impl WorkspaceToolResult {
    /// The fully finalized Git pack, including its native-format checksum.
    #[must_use]
    pub fn pack_bytes(&self) -> &[u8] {
        &self.pack
    }
}

/// Failures retain cleanup state. Timeout/cancellation drains the owned process
/// group, but cannot prove escaped-descendant quiescence: its workspace is
/// deliberately retained and reported instead of erased underneath a child.
#[derive(Debug)]
pub enum WorkspaceToolFailure {
    InvalidInput(&'static str),
    Node(NodeWorkspaceRefusal),
    Host(HostRefusal),
    Pack(PackWriteError),
    Io {
        operation: &'static str,
        source: std::io::Error,
    },
    ToolExited {
        code: Option<i32>,
    },
    Containment {
        workspace: PathBuf,
        detail: String,
    },
    Cleanup {
        workspace: PathBuf,
        operation: Option<Box<Self>>,
        cleanup: Box<Self>,
    },
}
impl WorkspaceToolFailure {
    /// A retained host directory requiring explicit operator reconciliation.
    #[must_use]
    pub fn retained_workspace(&self) -> Option<&Path> {
        match self {
            Self::Containment { workspace, .. } | Self::Cleanup { workspace, .. } => {
                Some(workspace)
            }
            _ => None,
        }
    }
}
impl std::fmt::Display for WorkspaceToolFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "trusted workspace operation failed: {self:?}")
    }
}
impl std::error::Error for WorkspaceToolFailure {}

impl OneNode {
    /// Run one explicitly trusted, foreground local tool and export its
    /// declared outputs into a native candidate commit and Git pack.
    ///
    /// This is an operator interface for a caller already authorized to read
    /// the entire local repository. It MUST NOT be exposed as an authenticated
    /// agent or hostile-job endpoint. The tool runs with host-user privileges;
    /// it must join its own descendants before exiting. No namespace, cgroup,
    /// secret broker or network isolation is claimed.
    ///
    /// Read prefixes name top-level files/directories; output paths are exact
    /// regular-file targets underneath those prefixes. The existing Linux
    /// descriptor-relative host adapter enforces path/import/lease rules.
    /// `commit_metadata` is (author identity, Unix timestamp, message); the
    /// committer equals the explicitly supplied author and timestamps use UTC.
    /// Every phase shares the request's cancellation and a finite wall budget.
    /// The environment is cleared except for the fixed /usr/bin:/bin PATH.
    pub async fn run_trusted_workspace_tool_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        workspace_id: [u8; 16],
        parent: &Path,
        read_prefixes: &[Vec<u8>],
        output_paths: &[Vec<u8>],
        command: &mut Command,
        timeout: Duration,
        commit_metadata: (&str, u64, &[u8]),
    ) -> Result<WorkspaceToolResult, WorkspaceToolFailure> {
        self.run_trusted_workspace_tool_at_in(
            request,
            reference,
            (None, None),
            workspace_id,
            parent,
            read_prefixes,
            output_paths,
            command,
            timeout,
            commit_metadata,
        )
        .await
    }

    /// Execute only when the selected authority head and commit match the
    /// supplied expectations. Both checks share the same authenticated source
    /// selection, before workspace creation or tool spawn; no check-then-reread.
    pub async fn run_trusted_workspace_tool_at_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        expected: (Option<RepositoryAuthorityHeadId>, Option<AnyOid>),
        workspace_id: [u8; 16],
        parent: &Path,
        read_prefixes: &[Vec<u8>],
        output_paths: &[Vec<u8>],
        command: &mut Command,
        timeout: Duration,
        commit_metadata: (&str, u64, &[u8]),
    ) -> Result<WorkspaceToolResult, WorkspaceToolFailure> {
        self.run_trusted_workspace_tool_shared_at_in(
            request,
            reference,
            expected,
            workspace_id,
            parent,
            read_prefixes,
            output_paths,
            WorkspaceInputSharing::PreferReflink,
            command,
            timeout,
            commit_metadata,
        )
        .await
    }

    /// Execute one bounded trusted local tool under an explicit host input
    /// sharing policy (`PreferReflink`, `RequireReflink`, or `Copy`).
    pub async fn run_trusted_workspace_tool_shared_at_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        expected: (Option<RepositoryAuthorityHeadId>, Option<AnyOid>),
        workspace_id: [u8; 16],
        parent: &Path,
        read_prefixes: &[Vec<u8>],
        output_paths: &[Vec<u8>],
        sharing: WorkspaceInputSharing,
        command: &mut Command,
        timeout: Duration,
        commit_metadata: (&str, u64, &[u8]),
    ) -> Result<WorkspaceToolResult, WorkspaceToolFailure> {
        if expected
            .1
            .is_some_and(|commit| commit.algorithm() != self.object_format || commit.is_zero())
        {
            return Err(WorkspaceToolFailure::InvalidInput(
                "invalid expected workspace commit",
            ));
        }
        validate_inputs(
            read_prefixes,
            output_paths,
            command,
            timeout,
            commit_metadata,
        )?;
        match self.object_format {
            ObjectFormat::Sha1 => {
                self.run_workspace_format::<Sha1>(
                    request,
                    reference,
                    expected,
                    workspace_id,
                    parent,
                    read_prefixes,
                    output_paths,
                    sharing,
                    command,
                    timeout,
                    commit_metadata,
                )
                .await
            }
            ObjectFormat::Sha256 => {
                self.run_workspace_format::<Sha256>(
                    request,
                    reference,
                    expected,
                    workspace_id,
                    parent,
                    read_prefixes,
                    output_paths,
                    sharing,
                    command,
                    timeout,
                    commit_metadata,
                )
                .await
            }
        }
    }

    /// Materialize `1..=64` parallel sparse workspaces from one authenticated
    /// canonical selection, sharing the immutable base through one bounded
    /// `SharedInputCache` when `sharing != Copy`, run all bounded tools in
    /// parallel without cross-workspace overlay leakage, and export each job's
    /// semantic changes into an independent native candidate commit and pack.
    pub async fn run_trusted_workspace_batch_at_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        expected: (Option<RepositoryAuthorityHeadId>, Option<AnyOid>),
        parent: &Path,
        read_prefixes: &[Vec<u8>],
        sharing: WorkspaceInputSharing,
        timeout: Duration,
        jobs: &mut [WorkspaceBatchJob],
    ) -> Result<WorkspaceBatchResult, WorkspaceToolFailure> {
        if expected
            .1
            .is_some_and(|commit| commit.algorithm() != self.object_format || commit.is_zero())
        {
            return Err(WorkspaceToolFailure::InvalidInput(
                "invalid expected workspace commit",
            ));
        }
        if jobs.is_empty() || jobs.len() > MAX_BATCH_JOBS {
            return Err(WorkspaceToolFailure::InvalidInput(
                "require 1..64 batch workspace jobs",
            ));
        }
        let mut seen_ids = BTreeSet::new();
        for job in jobs.iter() {
            if !seen_ids.insert(job.workspace_id) {
                return Err(WorkspaceToolFailure::InvalidInput(
                    "duplicate workspace id in batch",
                ));
            }
            validate_inputs(
                read_prefixes,
                &job.output_paths,
                &job.command,
                timeout,
                (&job.author, job.timestamp, &job.message),
            )?;
        }
        match self.object_format {
            ObjectFormat::Sha1 => {
                self.run_workspace_batch_format::<Sha1>(
                    request,
                    reference,
                    expected,
                    parent,
                    read_prefixes,
                    sharing,
                    timeout,
                    jobs,
                )
                .await
            }
            ObjectFormat::Sha256 => {
                self.run_workspace_batch_format::<Sha256>(
                    request,
                    reference,
                    expected,
                    parent,
                    read_prefixes,
                    sharing,
                    timeout,
                    jobs,
                )
                .await
            }
        }
    }

    async fn run_workspace_format<A: GitHashAlgorithm>(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        expected: (Option<RepositoryAuthorityHeadId>, Option<AnyOid>),
        id: [u8; 16],
        parent: &Path,
        reads: &[Vec<u8>],
        writes: &[Vec<u8>],
        sharing: WorkspaceInputSharing,
        command: &mut Command,
        timeout: Duration,
        metadata: (&str, u64, &[u8]),
    ) -> Result<WorkspaceToolResult, WorkspaceToolFailure> {
        let reads = parse_paths(reads)?;
        let writes = parse_paths(writes)?;
        if reads.iter().any(|path| path.component_count() != 1) {
            return Err(WorkspaceToolFailure::InvalidInput(
                "read prefixes must be top-level files or directories",
            ));
        }
        if writes
            .iter()
            .any(|path| !reads.iter().any(|prefix| path.starts_with(prefix)))
        {
            return Err(WorkspaceToolFailure::InvalidInput(
                "every output must be within a declared read prefix",
            ));
        }
        let started = Instant::now();
        let mut seed = budgeted_capability(
            WorkspaceId::from_bytes(id),
            self.repository_id(),
            reads.clone(),
            writes.clone(),
            FETCH_BYTES,
            FETCH_OBJECTS,
        )?;
        // Preserve a host/containment failure even if the shared read boundary
        // observes cancellation at its final checkpoint afterwards.
        let operation = Mutex::new(None);
        let selection = self
            .with_workspace_snapshot_in::<A, _>(
                request,
                reference,
                &RefVisibility::new(),
                &mut seed,
                0,
                expected.0,
                expected.1,
                usize::MAX,
                |base, source, seed, _head, _metadata_bytes| {
                    let result = run_at_base(
                        base, source, seed, request, parent, &reads, &writes, sharing, command,
                        started, timeout, metadata,
                    );
                    *operation
                        .lock()
                        .map_err(|_| NodeWorkspaceRefusal::UnsupportedWorkspaceEdit)? =
                        Some(result);
                    Ok(())
                },
            )
            .await;
        let operation = operation
            .into_inner()
            .map_err(|_| WorkspaceToolFailure::InvalidInput("workspace result lock poisoned"))?;
        match (selection, operation) {
            (_, Some(Err(error))) => Err(error),
            (Ok(()), Some(Ok(result))) => Ok(result),
            (Err(error), _) => Err(WorkspaceToolFailure::Node(error)),
            (Ok(()), None) => Err(WorkspaceToolFailure::InvalidInput(
                "workspace operation did not complete",
            )),
        }
    }

    async fn run_workspace_batch_format<A>(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        expected: (Option<RepositoryAuthorityHeadId>, Option<AnyOid>),
        parent: &Path,
        reads: &[Vec<u8>],
        sharing: WorkspaceInputSharing,
        timeout: Duration,
        jobs: &mut [WorkspaceBatchJob],
    ) -> Result<WorkspaceBatchResult, WorkspaceToolFailure>
    where
        A: GitHashAlgorithm + Send + Sync,
        A::Oid: Send + Sync,
    {
        let reads = parse_paths(reads)?;
        if reads.iter().any(|path| path.component_count() != 1) {
            return Err(WorkspaceToolFailure::InvalidInput(
                "read prefixes must be top-level files or directories",
            ));
        }
        let mut parsed_job_writes = Vec::with_capacity(jobs.len());
        for job in jobs.iter() {
            let writes = parse_paths(&job.output_paths)?;
            if writes
                .iter()
                .any(|path| !reads.iter().any(|prefix| path.starts_with(prefix)))
            {
                return Err(WorkspaceToolFailure::InvalidInput(
                    "every output must be within a declared read prefix",
                ));
            }
            parsed_job_writes.push(writes);
        }
        let started = Instant::now();
        let mut seed = budgeted_capability(
            WorkspaceId::from_bytes(jobs[0].workspace_id),
            self.repository_id(),
            reads.clone(),
            Vec::new(),
            FETCH_BYTES,
            FETCH_OBJECTS,
        )?;
        let operation = Mutex::new(None);
        let selection = self
            .with_workspace_snapshot_in::<A, _>(
                request,
                reference,
                &RefVisibility::new(),
                &mut seed,
                0,
                expected.0,
                expected.1,
                usize::MAX,
                |base, source, seed, _head, _metadata_bytes| {
                    let result = run_batch_at_base(
                        base,
                        source,
                        seed,
                        request,
                        parent,
                        &reads,
                        &parsed_job_writes,
                        sharing,
                        started,
                        timeout,
                        jobs,
                    );
                    *operation
                        .lock()
                        .map_err(|_| NodeWorkspaceRefusal::UnsupportedWorkspaceEdit)? =
                        Some(result);
                    Ok(())
                },
            )
            .await;
        let operation = operation
            .into_inner()
            .map_err(|_| WorkspaceToolFailure::InvalidInput("workspace result lock poisoned"))?;
        match (selection, operation) {
            (_, Some(Err(error))) => Err(error),
            (Ok(()), Some(Ok(result))) => Ok(result),
            (Err(error), _) => Err(WorkspaceToolFailure::Node(error)),
            (Ok(()), None) => Err(WorkspaceToolFailure::InvalidInput(
                "workspace batch operation did not complete",
            )),
        }
    }
}

fn validate_inputs(
    reads: &[Vec<u8>],
    writes: &[Vec<u8>],
    command: &Command,
    timeout: Duration,
    (author, timestamp, message): (&str, u64, &[u8]),
) -> Result<(), WorkspaceToolFailure> {
    if reads.is_empty() || reads.len() > 1024 || writes.len() > 10_000 {
        return Err(WorkspaceToolFailure::InvalidInput(
            "require 1..1024 read prefixes and at most 10000 outputs",
        ));
    }
    if timeout.is_zero() || timeout > Duration::from_secs(3600) {
        return Err(WorkspaceToolFailure::InvalidInput(
            "timeout must be greater than zero and no more than one hour",
        ));
    }
    if !Path::new(command.get_program()).is_absolute()
        || command.get_args().count() > 128
        || command
            .get_args()
            .any(|arg| arg.as_bytes().len() > 16 * 1024)
    {
        return Err(WorkspaceToolFailure::InvalidInput(
            "tool must be an absolute executable with bounded argv",
        ));
    }
    if author.is_empty()
        || author.len() > 1024
        || author.bytes().any(|b| b.is_ascii_control())
        || !author.contains('<')
        || !author.ends_with('>')
        || timestamp > 9_223_372_036_854_775_807
        || message.len() > 1024 * 1024
        || message.contains(&0)
    {
        return Err(WorkspaceToolFailure::InvalidInput(
            "invalid bounded Git author, timestamp or message",
        ));
    }
    Ok(())
}

fn parse_paths(paths: &[Vec<u8>]) -> Result<Vec<TreePath>, WorkspaceToolFailure> {
    let mut result = BTreeSet::new();
    for bytes in paths {
        let path = TreePath::parse_default(bytes)
            .map_err(|_| WorkspaceToolFailure::InvalidInput("invalid repository path"))?;
        if !result.insert(path) {
            return Err(WorkspaceToolFailure::InvalidInput(
                "duplicate repository path",
            ));
        }
    }
    Ok(result.into_iter().collect())
}

fn budgeted_capability(
    id: WorkspaceId,
    repository: fgit_types::RepositoryId,
    reads: Vec<TreePath>,
    writes: Vec<TreePath>,
    bytes: u64,
    objects: u64,
) -> Result<TreeCapability, WorkspaceToolFailure> {
    let bytes = ByteCount::try_new("workspace_fetch_bytes", bytes, FETCH_BYTES)
        .map_err(|_| WorkspaceToolFailure::InvalidInput("fetch budget exhausted"))?;
    Ok(TreeCapability::new(id, repository, reads, writes)
        .with_fetch_budget(bytes)
        .with_file_budget(objects))
}

fn elapsed_ns(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

struct SharedCacheOwner {
    cache: Option<SharedInputCache>,
    ledger: Option<ObligationLedger>,
}

impl SharedCacheOwner {
    fn open<A: GitHashAlgorithm>(
        source: &SparseWorkspacePlan<A>,
        parent: &File,
        policy: SharedInputPolicy,
        live: &dyn Fn() -> bool,
    ) -> Result<Self, WorkspaceToolFailure> {
        let parent = parent
            .try_clone()
            .map_err(|source| WorkspaceToolFailure::Io {
                operation: "retain shared workspace input parent",
                source,
            })?;
        let plan = SharedInputCachePlan::for_workspace(source, policy);
        let ledger = ObligationLedger::root(
            RegionId::new(u64::MAX),
            LeakDisposition::RecordAndContinue,
            plan.budget(),
        );
        let reserved = ledger
            .grant(plan.budget())
            .map_err(|_| HostRefusal::ReservationMismatch)
            .and_then(|grant| {
                ledger
                    .reserve(plan.reservation(), grant)
                    .map_err(|_| HostRefusal::ReservationMismatch)
            });
        let opened = reserved
            .and_then(|reserved| SharedInputCache::create(plan, parent, reserved, &|| !live()));
        match opened {
            Ok(cache) => Ok(Self {
                cache: Some(cache),
                ledger: Some(ledger),
            }),
            Err(error) => match ledger.close() {
                RegionCloseOutcome::Quiescent(_) => Err(WorkspaceToolFailure::Host(error)),
                _ => Err(WorkspaceToolFailure::Host(
                    HostRefusal::SharedInputCacheUnusable,
                )),
            },
        }
    }

    fn cache_mut(&mut self) -> Result<&mut SharedInputCache, WorkspaceToolFailure> {
        self.cache.as_mut().ok_or(WorkspaceToolFailure::Host(
            HostRefusal::SharedInputCacheUnusable,
        ))
    }

    fn close(mut self) -> Result<SharedInputCacheStats, WorkspaceToolFailure> {
        let cache = self.cache.take().ok_or(WorkspaceToolFailure::Host(
            HostRefusal::SharedInputCacheUnusable,
        ))?;
        let ledger = self.ledger.take().ok_or(WorkspaceToolFailure::Host(
            HostRefusal::SharedInputCacheUnusable,
        ))?;
        let closed = cache.close();
        let quiescent = matches!(ledger.close(), RegionCloseOutcome::Quiescent(_));
        let closed = closed.map_err(WorkspaceToolFailure::Host)?;
        if !quiescent {
            return Err(WorkspaceToolFailure::Host(
                HostRefusal::SharedInputCacheUnusable,
            ));
        }
        match closed.into_evidence() {
            TerminalEvidence::Acknowledged(receipt, _)
                if receipt.stats.resident_bytes == 0 && receipt.stats.resident_entries == 0 =>
            {
                Ok(receipt.stats)
            }
            _ => Err(WorkspaceToolFailure::Host(
                HostRefusal::SharedInputCacheUnusable,
            )),
        }
    }
}

fn close_workspace_and_ledger<A: GitHashAlgorithm>(
    workspace: SparseWorkspace<A>,
    ledger: ObligationLedger,
) -> Result<HostClosed, WorkspaceToolFailure> {
    let cleanup = workspace.close().map_err(WorkspaceToolFailure::Host);
    let close = ledger.close();
    match (cleanup, close) {
        (Ok(settled), RegionCloseOutcome::Quiescent(_)) => match settled.into_evidence() {
            TerminalEvidence::Acknowledged(receipt, _) => Ok(receipt),
            _ => Err(WorkspaceToolFailure::InvalidInput(
                "workspace close receipt unavailable",
            )),
        },
        (Err(error), _) => Err(error),
        (Ok(_), _) => Err(WorkspaceToolFailure::InvalidInput(
            "workspace obligation did not settle",
        )),
    }
}

fn discover_complete_top_level_paths<A: GitHashAlgorithm>(
    base: &BaseView<A>,
    source: &NodeTreeSource<'_>,
    seed: &mut TreeCapability,
    reads: &[TreePath],
) -> Result<Vec<TreePath>, WorkspaceToolFailure> {
    let grant = seed
        .authorize_root(0)
        .map_err(|_| WorkspaceToolFailure::InvalidInput("root not authorized"))?;
    let root_body = base
        .read_object(source, base.base_tree_oid(), GitObjectKind::Tree, &grant)
        .map_err(|e| WorkspaceToolFailure::Node(NodeWorkspaceRefusal::Object(e)))?;
    seed.charge_fetch(root_body.len() as u64)
        .map_err(|_| WorkspaceToolFailure::InvalidInput("root discovery exceeds fetch budget"))?;
    let entries = parse_tree(
        &root_body,
        AcceptanceProfile::GitCompatibleImport,
        &source.inner.parse_limits(),
    )
    .map_err(|_| WorkspaceToolFailure::InvalidInput("source tree cannot be exported"))?;
    let mut complete = BTreeSet::new();
    for entry in entries {
        complete.insert(
            TreePath::parse(&entry.name, base.path_policy()).map_err(|_| {
                WorkspaceToolFailure::InvalidInput("source tree contains an unsupported host path")
            })?,
        );
    }
    complete.extend(reads.iter().cloned());
    Ok(complete.into_iter().collect())
}

fn run_at_base<A: GitHashAlgorithm>(
    base: &BaseView<A>,
    source: &NodeTreeSource<'_>,
    seed: &mut TreeCapability,
    request: &NodeRequestContext,
    parent: &Path,
    reads: &[TreePath],
    writes: &[TreePath],
    sharing: WorkspaceInputSharing,
    command: &mut Command,
    started: Instant,
    timeout: Duration,
    metadata: (&str, u64, &[u8]),
) -> Result<WorkspaceToolResult, WorkspaceToolFailure> {
    let live = || started.elapsed() < timeout && workspace_request_live(request);
    if !live() {
        return Err(WorkspaceToolFailure::InvalidInput(
            "request expired before workspace creation",
        ));
    }
    // This is the local operator's complete tree scope, NOT a widening of the
    // tool's delegated capability. Account discovery before minting the
    // remaining finite allowance, then share that allowance with the tool.
    let complete = discover_complete_top_level_paths(base, source, seed, reads)?;
    let mut owner = budgeted_capability(
        seed.workspace_id(),
        base.repository_id(),
        complete,
        writes.to_vec(),
        FETCH_BYTES.saturating_sub(seed.fetched_bytes()),
        FETCH_OBJECTS.saturating_sub(seed.fetched_files()),
    )?;
    let mut tool = owner
        .attenuate(reads.to_vec(), writes.to_vec())
        .map_err(|_| WorkspaceToolFailure::InvalidInput("invalid tool delegation"))?;
    let limits = SparseLimits {
        max_entries: 10_000,
        max_entry_bytes: 16 * 1024 * 1024,
        max_payload_bytes: PAYLOAD_BYTES,
    };
    let manifest = Arc::new(
        SparseManifest::build(base, source, &mut tool, 0, limits)
            .map_err(|e| WorkspaceToolFailure::Node(NodeWorkspaceRefusal::Manifest(e)))?,
    );
    let plan = SparseWorkspacePlan::new(manifest, writes.to_vec(), &tool, 0, limits)
        .map_err(WorkspaceToolFailure::Host)?;
    let parent_file = File::open(parent).map_err(|source| WorkspaceToolFailure::Io {
        operation: "open private workspace parent",
        source,
    })?;
    let mut cache_owner = match sharing.cache_policy() {
        Some(policy) => Some(SharedCacheOwner::open(&plan, &parent_file, policy, &live)?),
        None => None,
    };
    let slot = format!("workspace-{}", hex(seed.workspace_id().as_bytes()));
    let slot = TreePath::parse_default(slot.as_bytes())
        .map_err(|_| WorkspaceToolFailure::InvalidInput("workspace slot"))?;
    let workspace_path = parent.join(slot.to_string());
    let ledger = ObligationLedger::root(
        RegionId::new(1),
        LeakDisposition::RecordAndContinue,
        plan.budget(),
    );
    let granted = match ledger.grant(plan.budget()) {
        Ok(granted) => granted,
        Err(_) => {
            if let Some(owner) = cache_owner {
                let _ = owner.close();
            }
            let _ = ledger.close();
            return Err(WorkspaceToolFailure::InvalidInput("workspace budget grant"));
        }
    };
    let reserved = match ledger.reserve(plan.reservation(), granted) {
        Ok(reserved) => reserved,
        Err(_) => {
            if let Some(owner) = cache_owner {
                let _ = owner.close();
            }
            let _ = ledger.close();
            return Err(WorkspaceToolFailure::InvalidInput("workspace reservation"));
        }
    };
    let creation_started = Instant::now();
    let workspace = match cache_owner.as_mut() {
        Some(owner) => SparseWorkspace::materialize_with_cache(
            plan,
            parent_file,
            slot,
            reserved,
            &tool,
            0,
            &|_| !live(),
            owner.cache_mut()?,
        ),
        None => {
            SparseWorkspace::materialize(plan, parent_file, slot, reserved, &tool, 0, &|_| !live())
        }
    };
    let creation_ns = elapsed_ns(creation_started);
    let cache_close = match cache_owner {
        Some(owner) => owner.close().map(Some),
        None => Ok(None),
    };
    let mut workspace = match workspace {
        Ok(workspace) => workspace,
        Err(error) => {
            let original = WorkspaceToolFailure::Host(error);
            let ws_quiescent = matches!(ledger.close(), RegionCloseOutcome::Quiescent(_));
            if let Err(cache_err) = cache_close {
                return Err(WorkspaceToolFailure::Cleanup {
                    workspace: workspace_path,
                    operation: Some(Box::new(original)),
                    cleanup: Box::new(cache_err),
                });
            }
            return if ws_quiescent {
                Err(original)
            } else {
                Err(WorkspaceToolFailure::Cleanup {
                    workspace: workspace_path,
                    operation: Some(Box::new(original)),
                    cleanup: Box::new(WorkspaceToolFailure::InvalidInput(
                        "workspace obligation did not settle",
                    )),
                })
            };
        }
    };
    let cache_stats = match cache_close {
        Ok(stats) => stats.unwrap_or_default(),
        Err(cache_err) => {
            return match close_workspace_and_ledger(workspace, ledger) {
                Ok(_) => Err(cache_err),
                Err(ws_err) => Err(WorkspaceToolFailure::Cleanup {
                    workspace: workspace_path,
                    operation: Some(Box::new(cache_err)),
                    cleanup: Box::new(ws_err),
                }),
            };
        }
    };
    command
        .current_dir(workspace.tool_directory())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let exec_started = Instant::now();
    let operation = (|| {
        // Keep the caller's stdout available for a machine-readable receipt.
        // Neither stream is accumulated in unbounded in-memory buffers.
        let diagnostics = File::options()
            .write(true)
            .open("/proc/self/fd/2")
            .map_err(|source| WorkspaceToolFailure::Io {
                operation: "open tool diagnostics",
                source,
            })?;
        command.stdout(diagnostics);
        execute_foreground(command, &live, &workspace_path)?;
        let log = workspace
            .import(&tool, 0, &|_| !live())
            .map_err(WorkspaceToolFailure::Host)?;
        let source_commit = native_id(
            source.inner.object_format,
            base.base_commit_oid().digest_bytes(),
        )?;
        candidate::export_from_base(
            base,
            source,
            &mut owner,
            &log,
            source_commit,
            0,
            fgit_treefs::ExportLimits {
                max_objects: 100_000,
                max_total_bytes: PAYLOAD_BYTES,
                max_tree_entries: 100_000,
            },
            &|| !live(),
        )
        .map_err(WorkspaceToolFailure::Node)
    })();
    let execution_ns = elapsed_ns(exec_started);
    if matches!(&operation, Err(WorkspaceToolFailure::Containment { .. })) {
        // Group cleanup was attempted; unresolved descendants may retain filesystem
        // access. Never delete the directory or claim that lease close passed.
        drop(workspace);
        let _unsettled = ledger.close();
        return operation.map(|_| unreachable!());
    }
    let cleanup_started = Instant::now();
    let cleanup = close_workspace_and_ledger(workspace, ledger);
    let cleanup_ns = elapsed_ns(cleanup_started);
    match (operation, cleanup) {
        (Ok(exported), Ok(closed)) => {
            let telemetry = WorkspaceHostTelemetry {
                sharing_mode: sharing,
                reflink_supported: cache_stats.reflink_supported,
                copied_bytes: closed.copied_bytes,
                shared_host_bytes: closed.shared_host_bytes,
                metadata_bytes: closed.metadata_bytes,
                imported_bytes: closed.imported_bytes,
                created_entries: closed.created_entries,
                imported_entries: closed.imported_entries,
                removed_entries: closed.removed_entries,
                seeded_bytes: cache_stats.seeded_bytes,
                cloned_bytes: cache_stats.cloned_bytes,
                fallback_bytes: cache_stats.fallback_bytes,
                creation_ns,
                execution_ns,
                cleanup_ns,
            };
            make_pack(
                source.inner.object_format,
                exported,
                metadata,
                telemetry,
                &live,
            )
        }
        (Err(error), Ok(_)) => Err(error),
        (operation, Err(cleanup)) => Err(WorkspaceToolFailure::Cleanup {
            workspace: workspace_path,
            operation: operation.err().map(Box::new),
            cleanup: Box::new(cleanup),
        }),
    }
}

struct PreparedBatchWorkspace<A: GitHashAlgorithm> {
    workspace: SparseWorkspace<A>,
    ledger: ObligationLedger,
    tool_capability: TreeCapability,
    workspace_path: PathBuf,
    creation_ns: u64,
    seeded_bytes: u64,
    cloned_bytes: u64,
    fallback_bytes: u64,
}

fn reap_prepared_batch<A: GitHashAlgorithm>(
    prepared: Vec<PreparedBatchWorkspace<A>>,
    primary: WorkspaceToolFailure,
) -> WorkspaceToolFailure {
    let mut failure = primary;
    for item in prepared {
        if let Err(cleanup) = close_workspace_and_ledger(item.workspace, item.ledger) {
            failure = WorkspaceToolFailure::Cleanup {
                workspace: item.workspace_path,
                operation: Some(Box::new(failure)),
                cleanup: Box::new(cleanup),
            };
        }
    }
    failure
}

fn run_batch_at_base<A>(
    base: &BaseView<A>,
    source: &NodeTreeSource<'_>,
    seed: &mut TreeCapability,
    request: &NodeRequestContext,
    parent: &Path,
    reads: &[TreePath],
    job_writes: &[Vec<TreePath>],
    sharing: WorkspaceInputSharing,
    started: Instant,
    timeout: Duration,
    jobs: &mut [WorkspaceBatchJob],
) -> Result<WorkspaceBatchResult, WorkspaceToolFailure>
where
    A: GitHashAlgorithm + Send + Sync,
    A::Oid: Send + Sync,
{
    let live = || started.elapsed() < timeout && workspace_request_live(request);
    if !live() {
        return Err(WorkspaceToolFailure::InvalidInput(
            "request expired before workspace batch creation",
        ));
    }
    let complete = discover_complete_top_level_paths(base, source, seed, reads)?;
    let shared_owner = budgeted_capability(
        seed.workspace_id(),
        base.repository_id(),
        complete.clone(),
        Vec::new(),
        FETCH_BYTES.saturating_sub(seed.fetched_bytes()),
        FETCH_OBJECTS.saturating_sub(seed.fetched_files()),
    )?;
    let mut shared_reader = shared_owner
        .attenuate(reads.to_vec(), Vec::new())
        .map_err(|_| {
            WorkspaceToolFailure::InvalidInput("invalid shared batch reader delegation")
        })?;
    let limits = SparseLimits {
        max_entries: 10_000,
        max_entry_bytes: 16 * 1024 * 1024,
        max_payload_bytes: PAYLOAD_BYTES,
    };
    let manifest = Arc::new(
        SparseManifest::build(base, source, &mut shared_reader, 0, limits)
            .map_err(|e| WorkspaceToolFailure::Node(NodeWorkspaceRefusal::Manifest(e)))?,
    );
    let mut remaining_fetch_bytes = FETCH_BYTES
        .saturating_sub(seed.fetched_bytes())
        .saturating_sub(shared_reader.fetched_bytes());
    let mut remaining_fetch_objects = FETCH_OBJECTS
        .saturating_sub(seed.fetched_files())
        .saturating_sub(shared_reader.fetched_files());

    let mut job_plans = Vec::with_capacity(jobs.len());
    for (job, writes) in jobs.iter().zip(job_writes.iter()) {
        let tool_cap = budgeted_capability(
            WorkspaceId::from_bytes(job.workspace_id),
            base.repository_id(),
            reads.to_vec(),
            writes.clone(),
            FETCH_BYTES,
            FETCH_OBJECTS,
        )?;
        let plan =
            SparseWorkspacePlan::new(Arc::clone(&manifest), writes.clone(), &tool_cap, 0, limits)
                .map_err(WorkspaceToolFailure::Host)?;
        job_plans.push((tool_cap, plan));
    }

    let root_parent = File::open(parent).map_err(|source| WorkspaceToolFailure::Io {
        operation: "open private workspace parent",
        source,
    })?;
    let mut cache_owner = match sharing.cache_policy() {
        Some(policy) => Some(SharedCacheOwner::open(
            &job_plans[0].1,
            &root_parent,
            policy,
            &live,
        )?),
        None => None,
    };

    let mut prepared = Vec::with_capacity(jobs.len());
    for (index, (job, (tool_capability, plan))) in jobs.iter().zip(job_plans).enumerate() {
        let slot_text = format!("workspace-{}", hex(&job.workspace_id));
        let slot = match TreePath::parse_default(slot_text.as_bytes()) {
            Ok(slot) => slot,
            Err(_) => {
                if let Some(owner) = cache_owner {
                    let _ = owner.close();
                }
                return Err(reap_prepared_batch(
                    prepared,
                    WorkspaceToolFailure::InvalidInput("workspace slot"),
                ));
            }
        };
        let workspace_path = parent.join(slot.to_string());
        let parent_fd = match root_parent.try_clone() {
            Ok(fd) => fd,
            Err(source) => {
                if let Some(owner) = cache_owner {
                    let _ = owner.close();
                }
                return Err(reap_prepared_batch(
                    prepared,
                    WorkspaceToolFailure::Io {
                        operation: "clone workspace parent descriptor",
                        source,
                    },
                ));
            }
        };
        let ledger = ObligationLedger::root(
            RegionId::new((index as u64) + 1),
            LeakDisposition::RecordAndContinue,
            plan.budget(),
        );
        let reserved = ledger
            .grant(plan.budget())
            .map_err(|_| WorkspaceToolFailure::InvalidInput("workspace budget grant"))
            .and_then(|granted| {
                ledger
                    .reserve(plan.reservation(), granted)
                    .map_err(|_| WorkspaceToolFailure::InvalidInput("workspace reservation"))
            });
        let reserved = match reserved {
            Ok(reserved) => reserved,
            Err(err) => {
                let _ = ledger.close();
                if let Some(owner) = cache_owner {
                    let _ = owner.close();
                }
                return Err(reap_prepared_batch(prepared, err));
            }
        };
        let before_stats = cache_owner
            .as_ref()
            .and_then(|owner| owner.cache.as_ref().map(SharedInputCache::stats))
            .unwrap_or_default();
        let creation_started = Instant::now();
        let materialized = match cache_owner.as_mut() {
            Some(owner) => match owner.cache_mut() {
                Ok(cache) => SparseWorkspace::materialize_with_cache(
                    plan,
                    parent_fd,
                    slot,
                    reserved,
                    &tool_capability,
                    0,
                    &|_| !live(),
                    cache,
                )
                .map_err(WorkspaceToolFailure::Host),
                Err(err) => {
                    let _ = reserved.abort_unused(HostRefusal::SharedInputCacheUnusable);
                    Err(err)
                }
            },
            None => SparseWorkspace::materialize(
                plan,
                parent_fd,
                slot,
                reserved,
                &tool_capability,
                0,
                &|_| !live(),
            )
            .map_err(WorkspaceToolFailure::Host),
        };
        let creation_ns = elapsed_ns(creation_started);
        let after_stats = cache_owner
            .as_ref()
            .and_then(|owner| owner.cache.as_ref().map(SharedInputCache::stats))
            .unwrap_or_default();
        match materialized {
            Ok(workspace) => {
                prepared.push(PreparedBatchWorkspace {
                    workspace,
                    ledger,
                    tool_capability,
                    workspace_path,
                    creation_ns,
                    seeded_bytes: after_stats
                        .seeded_bytes
                        .saturating_sub(before_stats.seeded_bytes),
                    cloned_bytes: after_stats
                        .cloned_bytes
                        .saturating_sub(before_stats.cloned_bytes),
                    fallback_bytes: after_stats
                        .fallback_bytes
                        .saturating_sub(before_stats.fallback_bytes),
                });
            }
            Err(original) => {
                let ws_quiescent = matches!(ledger.close(), RegionCloseOutcome::Quiescent(_));
                let cache_err = cache_owner.and_then(|owner| owner.close().err());
                let base_err = if let Some(cache_err) = cache_err {
                    WorkspaceToolFailure::Cleanup {
                        workspace: workspace_path,
                        operation: Some(Box::new(original)),
                        cleanup: Box::new(cache_err),
                    }
                } else if ws_quiescent {
                    original
                } else {
                    WorkspaceToolFailure::Cleanup {
                        workspace: workspace_path,
                        operation: Some(Box::new(original)),
                        cleanup: Box::new(WorkspaceToolFailure::InvalidInput(
                            "workspace obligation did not settle",
                        )),
                    }
                };
                return Err(reap_prepared_batch(prepared, base_err));
            }
        }
    }

    let cache_stats = match cache_owner {
        Some(owner) => match owner.close() {
            Ok(stats) => stats,
            Err(cache_err) => return Err(reap_prepared_batch(prepared, cache_err)),
        },
        None => SharedInputCacheStats::default(),
    };
    let reflink_supported = cache_stats.reflink_supported;

    let outcomes = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(jobs.len());
        for (job, item) in jobs.iter_mut().zip(prepared) {
            handles.push(scope.spawn(move || {
                let live_job = || started.elapsed() < timeout && workspace_request_live(request);
                let PreparedBatchWorkspace {
                    mut workspace,
                    ledger,
                    tool_capability,
                    workspace_path,
                    creation_ns,
                    seeded_bytes,
                    cloned_bytes,
                    fallback_bytes,
                } = item;
                job.command
                    .current_dir(workspace.tool_directory())
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .stdin(Stdio::null())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit());
                let exec_started = Instant::now();
                let operation = (|| {
                    let diagnostics = File::options()
                        .write(true)
                        .open("/proc/self/fd/2")
                        .map_err(|source| WorkspaceToolFailure::Io {
                            operation: "open tool diagnostics",
                            source,
                        })?;
                    job.command.stdout(diagnostics);
                    execute_foreground(&mut job.command, &live_job, &workspace_path)?;
                    workspace
                        .import(&tool_capability, 0, &|_| !live_job())
                        .map_err(WorkspaceToolFailure::Host)
                })();
                let execution_ns = elapsed_ns(exec_started);
                if matches!(&operation, Err(WorkspaceToolFailure::Containment { .. })) {
                    drop(workspace);
                    let _unsettled = ledger.close();
                    return operation.map(|_| unreachable!());
                }
                let cleanup_started = Instant::now();
                let cleanup = close_workspace_and_ledger(workspace, ledger);
                let cleanup_ns = elapsed_ns(cleanup_started);
                match (operation, cleanup) {
                    (Ok(log), Ok(closed)) => Ok((
                        log,
                        WorkspaceHostTelemetry {
                            sharing_mode: sharing,
                            reflink_supported,
                            copied_bytes: closed.copied_bytes,
                            shared_host_bytes: closed.shared_host_bytes,
                            metadata_bytes: closed.metadata_bytes,
                            imported_bytes: closed.imported_bytes,
                            created_entries: closed.created_entries,
                            imported_entries: closed.imported_entries,
                            removed_entries: closed.removed_entries,
                            seeded_bytes,
                            cloned_bytes,
                            fallback_bytes,
                            creation_ns,
                            execution_ns,
                            cleanup_ns,
                        },
                    )),
                    (Err(error), Ok(_)) => Err(error),
                    (operation, Err(cleanup)) => Err(WorkspaceToolFailure::Cleanup {
                        workspace: workspace_path,
                        operation: operation.err().map(Box::new),
                        cleanup: Box::new(cleanup),
                    }),
                }
            }));
        }
        let mut collected = Vec::with_capacity(handles.len());
        for handle in handles {
            collected.push(
                handle
                    .join()
                    .unwrap_or(Err(WorkspaceToolFailure::InvalidInput(
                        "workspace batch worker panicked",
                    ))),
            );
        }
        collected
    });

    let mut retained_failure = None;
    let mut first_failure = None;
    let mut imported_jobs = Vec::with_capacity(outcomes.len());
    for outcome in outcomes {
        match outcome {
            Ok(pair) => imported_jobs.push(pair),
            Err(err) => {
                if err.retained_workspace().is_some() && retained_failure.is_none() {
                    retained_failure = Some(err);
                } else if first_failure.is_none() {
                    first_failure = Some(err);
                }
            }
        }
    }
    if let Some(err) = retained_failure.or(first_failure) {
        return Err(err);
    }

    let source_commit = native_id(
        source.inner.object_format,
        base.base_commit_oid().digest_bytes(),
    )?;
    let mut results = Vec::with_capacity(jobs.len());
    for ((job, writes), (log, telemetry)) in jobs.iter().zip(job_writes.iter()).zip(imported_jobs) {
        let mut job_owner = budgeted_capability(
            seed.workspace_id(),
            base.repository_id(),
            complete.clone(),
            writes.clone(),
            remaining_fetch_bytes,
            remaining_fetch_objects,
        )?;
        let exported = candidate::export_from_base(
            base,
            source,
            &mut job_owner,
            &log,
            source_commit,
            0,
            fgit_treefs::ExportLimits {
                max_objects: 100_000,
                max_total_bytes: PAYLOAD_BYTES,
                max_tree_entries: 100_000,
            },
            &|| !live(),
        )
        .map_err(WorkspaceToolFailure::Node)?;
        remaining_fetch_bytes = remaining_fetch_bytes.saturating_sub(job_owner.fetched_bytes());
        remaining_fetch_objects = remaining_fetch_objects.saturating_sub(job_owner.fetched_files());
        results.push(make_pack(
            source.inner.object_format,
            exported,
            (&job.author, job.timestamp, &job.message),
            telemetry,
            &live,
        )?);
    }
    Ok(WorkspaceBatchResult {
        sharing_mode: sharing,
        cache_stats,
        results,
    })
}

fn execute_foreground(
    command: &mut Command,
    live: &dyn Fn() -> bool,
    workspace: &Path,
) -> Result<(), WorkspaceToolFailure> {
    use fgit_runner::workflow::{TrustedCommandOutcome, run_trusted_command};
    // The original source/workspace deadline is already included in `live`.
    // This adapter owns the PID until group observation and signalling finish.
    let observation =
        run_trusted_command(command, Duration::from_secs(3600), live).map_err(|failure| {
            if failure.retain_workspace {
                WorkspaceToolFailure::Containment {
                    workspace: workspace.to_owned(),
                    detail: failure.detail,
                }
            } else {
                WorkspaceToolFailure::Io {
                    operation: "execute trusted command",
                    source: std::io::Error::other(failure.detail),
                }
            }
        })?;
    if observation.retain_workspace {
        return Err(WorkspaceToolFailure::Containment {
            workspace: workspace.to_owned(),
            detail: format!(
                "trusted command {:?}; status={:?}; workspace retained, escaped-descendant quiescence unproved",
                observation.outcome, observation.status
            ),
        });
    }
    match (observation.outcome, observation.status) {
        (TrustedCommandOutcome::Exited, Some(status)) if status.success() => Ok(()),
        (TrustedCommandOutcome::Exited, Some(status)) => Err(WorkspaceToolFailure::ToolExited {
            code: status.code(),
        }),
        _ => Err(WorkspaceToolFailure::InvalidInput(
            "request expired before candidate import",
        )),
    }
}

fn native_id(format: ObjectFormat, bytes: &[u8]) -> Result<AnyOid, WorkspaceToolFailure> {
    AnyOid::from_hex(format, &hex(bytes))
        .map_err(|_| WorkspaceToolFailure::InvalidInput("native identity width"))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct CandidateObjects(BTreeMap<AnyOid, CanonicalPackObject>);
impl CanonicalObjectSource for CandidateObjects {
    fn load(&self, id: &AnyOid) -> Result<CanonicalPackObject, PackWriteError> {
        self.0
            .get(id)
            .cloned()
            .ok_or(PackWriteError::MissingCanonicalObject(*id))
    }
}
fn make_pack<A: GitHashAlgorithm>(
    format: ObjectFormat,
    exported: candidate::WorkspaceEditExport<A>,
    (author, timestamp, message): (&str, u64, &[u8]),
    telemetry: WorkspaceHostTelemetry,
    live: &dyn Fn() -> bool,
) -> Result<WorkspaceToolResult, WorkspaceToolFailure> {
    let source_commit = native_id(format, exported.source_commit.digest_bytes())?;
    let root_tree = native_id(format, exported.plan.root_tree().digest_bytes())?;
    let mut commit_body = format!("tree {root_tree}\nparent {source_commit}\nauthor {author} {timestamp} +0000\ncommitter {author} {timestamp} +0000\n\n").into_bytes();
    commit_body.extend_from_slice(message);
    let limits = PackLimits {
        max_input_bytes: 128 * 1024 * 1024,
        max_entries: 100_002,
        max_object_bytes: PAYLOAD_BYTES,
        max_total_expanded_bytes: PAYLOAD_BYTES + 2 * 1024 * 1024,
        ..PackLimits::default()
    };
    let parse_limits = fgit_git_object::ParseLimits {
        tree_reference_bytes: format.digest_len(),
        max_object_bytes: limits.max_object_bytes,
        ..fgit_git_object::ParseLimits::default()
    };
    parse_object_body(
        ObjectType::Commit,
        &commit_body,
        AcceptanceProfile::StrictCreate,
        &parse_limits,
    )
    .map_err(|_| WorkspaceToolFailure::InvalidInput("candidate Git commit metadata is invalid"))?;
    let commit = git_object_id(format, GitObjectKind::Commit, &commit_body);
    let mut objects = BTreeMap::new();
    for object in exported.plan.objects() {
        let id = native_id(format, object.oid().digest_bytes())?;
        let references = if object.kind() == GitObjectKind::Tree {
            parse_tree(
                object.body(),
                AcceptanceProfile::StrictCreate,
                &parse_limits,
            )
            .map_err(|_| WorkspaceToolFailure::InvalidInput("candidate tree is invalid"))?
            .into_iter()
            .filter(|entry| entry.mode != b"160000")
            .map(|entry| native_id(format, &entry.object_id))
            .collect::<Result<Vec<_>, _>>()?
        } else {
            Vec::new()
        };
        objects.insert(
            id,
            CanonicalPackObject::new(id, object.kind(), object.body().to_vec(), references, 0, 0),
        );
    }
    objects.insert(
        commit,
        CanonicalPackObject::new(
            commit,
            ObjectType::Commit,
            commit_body,
            vec![root_tree, source_commit],
            0,
            0,
        ),
    );
    let selected = objects.keys().copied().collect::<Vec<_>>();
    let mut deadline = || live();
    let plan = PackPlanner::new(
        format,
        PackWriteProfile::COMPRESSED_NO_DELTA_V1,
        limits.clone(),
    )
    .plan_selected(&CandidateObjects(objects), &selected, &mut deadline)
    .map_err(WorkspaceToolFailure::Pack)?;
    let (pack, _) = PackWriter::new(limits)
        .write(&plan, &mut deadline)
        .map_err(WorkspaceToolFailure::Pack)?;
    Ok(WorkspaceToolResult {
        object_format: format,
        source_commit,
        source_rcr: exported.source_rcr,
        candidate_commit: commit,
        root_tree,
        changed_paths: exported
            .changed_paths
            .into_iter()
            .map(|p| p.as_bytes().to_vec())
            .collect(),
        object_count: selected.len(),
        telemetry,
        pack,
    })
}
