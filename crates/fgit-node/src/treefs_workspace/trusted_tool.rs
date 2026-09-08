//! Local-operator workspace execution, not an untrusted agent/CI sandbox.
//!
//! The operator owns the whole repository. Only declared top-level input
//! prefixes are materialized for the tool, while the publisher retains the
//! complete tree scope needed to preserve unselected siblings during export.
//! No Git engine is invoked, and the resulting candidate never moves a ref.

use super::{NodeTreeSource, NodeWorkspaceRefusal, candidate, workspace_request_live};
use crate::{NodeRequestContext, OneNode};
use fgit_crypto::{GitHashAlgorithm, GitObjectKind, NativeObjectIdentity, Sha1, Sha256, git_object_id};
use fgit_git_object::{AcceptanceProfile, ObjectType, parse_object_body, parse_tree};
use fgit_pack::{CanonicalObjectSource, CanonicalPackObject, PackLimits, PackPlanner,
    PackWriteError, PackWriteProfile, PackWriter};
use fgit_resource::{LeakDisposition, ObligationLedger, RegionCloseOutcome, RegionId};
use fgit_runner::sparse_workspace::{HostRefusal, SparseWorkspace, SparseWorkspacePlan};
use fgit_treefs::{BaseView, SparseLimits, SparseManifest, TreeCapability, TreePath, WorkspaceId};
use fgit_types::numeric::ByteCount;
use fgit_types::{GitHashAlgorithm as ObjectFormat, GitOid as AnyOid, RefName, RepositoryCommitId};
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
    pack: Vec<u8>,
}
impl WorkspaceToolResult {
    /// The fully finalized Git pack, including its native-format checksum.
    #[must_use]
    pub fn pack_bytes(&self) -> &[u8] { &self.pack }
}

/// Failures retain cleanup state. Timeout/cancellation kills and waits for the
/// direct child, but cannot prove descendant quiescence: its workspace is
/// deliberately retained and reported instead of erased underneath a child.
#[derive(Debug)]
pub enum WorkspaceToolFailure {
    InvalidInput(&'static str),
    Node(NodeWorkspaceRefusal),
    Host(HostRefusal),
    Pack(PackWriteError),
    Io { operation: &'static str, source: std::io::Error },
    ToolExited { code: Option<i32> },
    Containment { workspace: PathBuf, detail: String },
    Cleanup { workspace: PathBuf, operation: Option<Box<Self>>, cleanup: Box<Self> },
}
impl WorkspaceToolFailure {
    /// A retained host directory requiring explicit operator reconciliation.
    #[must_use]
    pub fn retained_workspace(&self) -> Option<&Path> {
        match self {
            Self::Containment { workspace, .. } | Self::Cleanup { workspace, .. } => Some(workspace),
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
        validate_inputs(read_prefixes, output_paths, command, timeout, commit_metadata)?;
        match self.object_format {
            ObjectFormat::Sha1 => self.run_workspace_format::<Sha1>(
                request, reference, workspace_id, parent, read_prefixes, output_paths,
                command, timeout, commit_metadata,
            ).await,
            ObjectFormat::Sha256 => self.run_workspace_format::<Sha256>(
                request, reference, workspace_id, parent, read_prefixes, output_paths,
                command, timeout, commit_metadata,
            ).await,
        }
    }

    async fn run_workspace_format<A: GitHashAlgorithm>(
        &self, request: &NodeRequestContext, reference: &RefName, id: [u8; 16],
        parent: &Path, reads: &[Vec<u8>], writes: &[Vec<u8>], command: &mut Command,
        timeout: Duration, metadata: (&str, u64, &[u8]),
    ) -> Result<WorkspaceToolResult, WorkspaceToolFailure> {
        let reads = parse_paths(reads)?;
        let writes = parse_paths(writes)?;
        if reads.iter().any(|path| path.component_count() != 1) {
            return Err(WorkspaceToolFailure::InvalidInput("read prefixes must be top-level files or directories"));
        }
        if writes.iter().any(|path| !reads.iter().any(|prefix| path.starts_with(prefix))) {
            return Err(WorkspaceToolFailure::InvalidInput("every output must be within a declared read prefix"));
        }
        let started = Instant::now();
        let mut seed = budgeted_capability(WorkspaceId::from_bytes(id), self.repository_id(),
            reads.clone(), writes.clone(), FETCH_BYTES, FETCH_OBJECTS)?;
        // Preserve a host/containment failure even if the shared read boundary
        // observes cancellation at its final checkpoint afterwards.
        let operation = Mutex::new(None);
        let selection = self.with_workspace_base_in::<A, _>(
            request, reference, &RefVisibility::new(), &mut seed, 0,
            |base, source, seed| {
                let result = run_at_base(base, source, seed, request, parent, &reads,
                    &writes, command, started, timeout, metadata);
                *operation.lock().map_err(|_| NodeWorkspaceRefusal::UnsupportedWorkspaceEdit)? = Some(result);
                Ok(())
            },
        ).await;
        let operation = operation.into_inner().map_err(|_| WorkspaceToolFailure::InvalidInput("workspace result lock poisoned"))?;
        match (selection, operation) {
            (_, Some(Err(error))) => Err(error),
            (Ok(()), Some(Ok(result))) => Ok(result),
            (Err(error), _) => Err(WorkspaceToolFailure::Node(error)),
            (Ok(()), None) => Err(WorkspaceToolFailure::InvalidInput("workspace operation did not complete")),
        }
    }
}

fn validate_inputs(
    reads: &[Vec<u8>], writes: &[Vec<u8>], command: &Command, timeout: Duration,
    (author, timestamp, message): (&str, u64, &[u8]),
) -> Result<(), WorkspaceToolFailure> {
    if reads.is_empty() || reads.len() > 1024 || writes.len() > 10_000 {
        return Err(WorkspaceToolFailure::InvalidInput("require 1..1024 read prefixes and at most 10000 outputs"));
    }
    if timeout.is_zero() || timeout > Duration::from_secs(3600) {
        return Err(WorkspaceToolFailure::InvalidInput("timeout must be greater than zero and no more than one hour"));
    }
    if !Path::new(command.get_program()).is_absolute() || command.get_args().count() > 128
        || command.get_args().any(|arg| arg.as_bytes().len() > 16 * 1024)
    {
        return Err(WorkspaceToolFailure::InvalidInput("tool must be an absolute executable with bounded argv"));
    }
    if author.is_empty() || author.len() > 1024 || author.bytes().any(|b| b.is_ascii_control())
        || !author.contains('<') || !author.ends_with('>') || timestamp > 9_223_372_036_854_775_807
        || message.len() > 1024 * 1024 || message.contains(&0)
    {
        return Err(WorkspaceToolFailure::InvalidInput("invalid bounded Git author, timestamp or message"));
    }
    Ok(())
}

fn parse_paths(paths: &[Vec<u8>]) -> Result<Vec<TreePath>, WorkspaceToolFailure> {
    let mut result = BTreeSet::new();
    for bytes in paths {
        let path = TreePath::parse_default(bytes)
            .map_err(|_| WorkspaceToolFailure::InvalidInput("invalid repository path"))?;
        if !result.insert(path) {
            return Err(WorkspaceToolFailure::InvalidInput("duplicate repository path"));
        }
    }
    Ok(result.into_iter().collect())
}

fn budgeted_capability(
    id: WorkspaceId, repository: fgit_types::RepositoryId,
    reads: Vec<TreePath>, writes: Vec<TreePath>, bytes: u64, objects: u64,
) -> Result<TreeCapability, WorkspaceToolFailure> {
    let bytes = ByteCount::try_new("workspace_fetch_bytes", bytes, FETCH_BYTES)
        .map_err(|_| WorkspaceToolFailure::InvalidInput("fetch budget exhausted"))?;
    Ok(TreeCapability::new(id, repository, reads, writes)
        .with_fetch_budget(bytes).with_file_budget(objects))
}

fn run_at_base<A: GitHashAlgorithm>(
    base: &BaseView<A>, source: &NodeTreeSource<'_>, seed: &mut TreeCapability,
    request: &NodeRequestContext, parent: &Path, reads: &[TreePath], writes: &[TreePath],
    command: &mut Command, started: Instant, timeout: Duration,
    metadata: (&str, u64, &[u8]),
) -> Result<WorkspaceToolResult, WorkspaceToolFailure> {
    let live = || started.elapsed() < timeout && workspace_request_live(request);
    if !live() { return Err(WorkspaceToolFailure::InvalidInput("request expired before workspace creation")); }
    // This is the local operator's complete tree scope, NOT a widening of the
    // tool's delegated capability. Account discovery before minting the
    // remaining finite allowance, then share that allowance with the tool.
    let grant = seed.authorize_root(0).map_err(|_| WorkspaceToolFailure::InvalidInput("root not authorized"))?;
    let root_body = base.read_object(source, base.base_tree_oid(), GitObjectKind::Tree, &grant)
        .map_err(|e| WorkspaceToolFailure::Node(NodeWorkspaceRefusal::Object(e)))?;
    seed.charge_fetch(root_body.len() as u64).map_err(|_| WorkspaceToolFailure::InvalidInput("root discovery exceeds fetch budget"))?;
    let entries = parse_tree(&root_body, AcceptanceProfile::GitCompatibleImport, &source.inner.parse_limits())
        .map_err(|_| WorkspaceToolFailure::InvalidInput("source tree cannot be exported"))?;
    let mut complete = BTreeSet::new();
    for entry in entries {
        complete.insert(TreePath::parse(&entry.name, base.path_policy())
            .map_err(|_| WorkspaceToolFailure::InvalidInput("source tree contains an unsupported host path"))?);
    }
    complete.extend(reads.iter().cloned());
    let mut owner = budgeted_capability(seed.workspace_id(), base.repository_id(),
        complete.into_iter().collect(), writes.to_vec(),
        FETCH_BYTES.saturating_sub(seed.fetched_bytes()), FETCH_OBJECTS.saturating_sub(seed.fetched_files()))?;
    let mut tool = owner.attenuate(reads.to_vec(), writes.to_vec())
        .map_err(|_| WorkspaceToolFailure::InvalidInput("invalid tool delegation"))?;
    let limits = SparseLimits { max_entries: 10_000, max_entry_bytes: 16 * 1024 * 1024,
        max_payload_bytes: PAYLOAD_BYTES };
    let manifest = Arc::new(SparseManifest::build(base, source, &mut tool, 0, limits)
        .map_err(|e| WorkspaceToolFailure::Node(NodeWorkspaceRefusal::Manifest(e)))?);
    let plan = SparseWorkspacePlan::new(manifest, writes.to_vec(), &tool, 0, limits)
        .map_err(WorkspaceToolFailure::Host)?;
    let parent_file = File::open(parent).map_err(|source| WorkspaceToolFailure::Io { operation: "open private workspace parent", source })?;
    let slot = format!("workspace-{}", hex(seed.workspace_id().as_bytes()));
    let slot = TreePath::parse_default(slot.as_bytes()).map_err(|_| WorkspaceToolFailure::InvalidInput("workspace slot"))?;
    let workspace_path = parent.join(slot.to_string());
    let ledger = ObligationLedger::root(RegionId::new(1), LeakDisposition::RecordAndContinue, plan.budget());
    let granted = ledger.grant(plan.budget()).map_err(|_| WorkspaceToolFailure::InvalidInput("workspace budget grant"))?;
    let reserved = ledger.reserve(plan.reservation(), granted).map_err(|_| WorkspaceToolFailure::InvalidInput("workspace reservation"))?;
    let workspace = SparseWorkspace::materialize(plan, parent_file, slot, reserved, &tool, 0, &|_| !live());
    let mut workspace = match workspace {
        Ok(workspace) => workspace,
        Err(error) => {
            let original = WorkspaceToolFailure::Host(error);
            return match ledger.close() {
                RegionCloseOutcome::Quiescent(_) => Err(original),
                _ => Err(WorkspaceToolFailure::Cleanup { workspace: workspace_path,
                    operation: Some(Box::new(original)), cleanup: Box::new(WorkspaceToolFailure::InvalidInput("workspace obligation did not settle")) }),
            };
        }
    };
    command.current_dir(workspace.tool_directory()).env_clear().env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit());
    let operation = (|| {
        // Keep the caller's stdout available for a machine-readable receipt.
        // Neither stream is accumulated in unbounded in-memory buffers.
        let diagnostics = File::options().write(true).open("/proc/self/fd/2")
            .map_err(|source| WorkspaceToolFailure::Io { operation: "open tool diagnostics", source })?;
        command.stdout(diagnostics);
        execute_foreground(command, &live, &workspace_path)?;
        let log = workspace.import(&tool, 0, &|_| !live()).map_err(WorkspaceToolFailure::Host)?;
        let source_commit = native_id(source.inner.object_format, base.base_commit_oid().digest_bytes())?;
        let exported = candidate::export_from_base(base, source, &mut owner, &log, source_commit,
            0, fgit_treefs::ExportLimits { max_objects: 100_000, max_total_bytes: PAYLOAD_BYTES, max_tree_entries: 100_000 },
            &|| !live()).map_err(WorkspaceToolFailure::Node)?;
        make_pack(source.inner.object_format, exported, metadata, &live)
    })();
    if matches!(&operation, Err(WorkspaceToolFailure::Containment { .. })) {
        // The leader is reaped, but its descendants may retain filesystem
        // access. Never delete the directory or claim that lease close passed.
        drop(workspace);
        let _unsettled = ledger.close();
        return operation;
    }
    let cleanup = workspace.close().map_err(WorkspaceToolFailure::Host);
    let close = ledger.close();
    let cleanup = match (cleanup, close) {
        (Ok(_), RegionCloseOutcome::Quiescent(_)) => Ok(()),
        (Err(error), _) => Err(error),
        (Ok(_), _) => Err(WorkspaceToolFailure::InvalidInput("workspace obligation did not settle")),
    };
    match (operation, cleanup) {
        (Ok(result), Ok(())) => Ok(result),
        (Err(error), Ok(())) => Err(error),
        (operation, Err(cleanup)) => Err(WorkspaceToolFailure::Cleanup {
            workspace: workspace_path, operation: operation.err().map(Box::new), cleanup: Box::new(cleanup),
        }),
    }
}

fn execute_foreground(command: &mut Command, live: &dyn Fn() -> bool, workspace: &Path)
    -> Result<(), WorkspaceToolFailure>
{
    if !live() { return Err(WorkspaceToolFailure::InvalidInput("request expired before tool spawn")); }
    let mut child = command.spawn().map_err(|source| WorkspaceToolFailure::Io { operation: "spawn tool", source })?;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) if status.code().is_some() => return Err(WorkspaceToolFailure::ToolExited { code: status.code() }),
            Ok(Some(status)) => return Err(WorkspaceToolFailure::Containment { workspace: workspace.to_owned(),
                detail: format!("tool terminated by signal ({status}); descendant quiescence is unproved, workspace retained") }),
            Ok(None) if live() => std::thread::sleep(Duration::from_millis(10)),
            result => {
                let cause = match result { Err(error) => error.to_string(), _ => "deadline or request cancellation".to_owned() };
                let killed = child.kill();
                let waited = child.wait();
                return Err(WorkspaceToolFailure::Containment { workspace: workspace.to_owned(),
                    detail: format!("{cause}; direct-child kill={killed:?}, wait={waited:?}; descendant quiescence is unproved, workspace retained") });
            }
        }
    }
}

fn native_id(format: ObjectFormat, bytes: &[u8]) -> Result<AnyOid, WorkspaceToolFailure> {
    AnyOid::from_hex(format, &hex(bytes)).map_err(|_| WorkspaceToolFailure::InvalidInput("native identity width"))
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

struct CandidateObjects(BTreeMap<AnyOid, CanonicalPackObject>);
impl CanonicalObjectSource for CandidateObjects {
    fn load(&self, id: &AnyOid) -> Result<CanonicalPackObject, PackWriteError> {
        self.0.get(id).cloned().ok_or(PackWriteError::MissingCanonicalObject(*id))
    }
}
fn make_pack<A: GitHashAlgorithm>(
    format: ObjectFormat, exported: candidate::WorkspaceEditExport<A>,
    (author, timestamp, message): (&str, u64, &[u8]), live: &dyn Fn() -> bool,
) -> Result<WorkspaceToolResult, WorkspaceToolFailure> {
    let source_commit = native_id(format, exported.source_commit.digest_bytes())?;
    let root_tree = native_id(format, exported.plan.root_tree().digest_bytes())?;
    let mut commit_body = format!("tree {root_tree}\nparent {source_commit}\nauthor {author} {timestamp} +0000\ncommitter {author} {timestamp} +0000\n\n").into_bytes();
    commit_body.extend_from_slice(message);
    let limits = PackLimits { max_input_bytes: 128 * 1024 * 1024, max_entries: 100_002,
        max_object_bytes: PAYLOAD_BYTES, max_total_expanded_bytes: PAYLOAD_BYTES + 2 * 1024 * 1024,
        ..PackLimits::default() };
    let parse_limits = fgit_git_object::ParseLimits { tree_reference_bytes: format.digest_len(),
        max_object_bytes: limits.max_object_bytes, ..fgit_git_object::ParseLimits::default() };
    parse_object_body(ObjectType::Commit, &commit_body, AcceptanceProfile::StrictCreate, &parse_limits)
        .map_err(|_| WorkspaceToolFailure::InvalidInput("candidate Git commit metadata is invalid"))?;
    let commit = git_object_id(format, GitObjectKind::Commit, &commit_body);
    let mut objects = BTreeMap::new();
    for object in exported.plan.objects() {
        let id = native_id(format, object.oid().digest_bytes())?;
        let references = if object.kind() == GitObjectKind::Tree {
            parse_tree(object.body(), AcceptanceProfile::StrictCreate, &parse_limits)
                .map_err(|_| WorkspaceToolFailure::InvalidInput("candidate tree is invalid"))?
                .into_iter().filter(|entry| entry.mode != b"160000")
                .map(|entry| native_id(format, &entry.object_id)).collect::<Result<Vec<_>, _>>()?
        } else { Vec::new() };
        objects.insert(id, CanonicalPackObject::new(id, object.kind(), object.body().to_vec(), references, 0, 0));
    }
    objects.insert(commit, CanonicalPackObject::new(commit, ObjectType::Commit, commit_body,
        vec![root_tree, source_commit], 0, 0));
    let selected = objects.keys().copied().collect::<Vec<_>>();
    let mut deadline = || live();
    let plan = PackPlanner::new(format, PackWriteProfile::COMPRESSED_NO_DELTA_V1, limits.clone())
        .plan_selected(&CandidateObjects(objects), &selected, &mut deadline).map_err(WorkspaceToolFailure::Pack)?;
    let (pack, _) = PackWriter::new(limits).write(&plan, &mut deadline).map_err(WorkspaceToolFailure::Pack)?;
    Ok(WorkspaceToolResult { object_format: format, source_commit, source_rcr: exported.source_rcr,
        candidate_commit: commit, root_tree, changed_paths: exported.changed_paths.into_iter().map(|p| p.as_bytes().to_vec()).collect(),
        object_count: selected.len(), pack })
}
