//! Repository-bound execution of the existing trusted workflow profile.
//! Never expose this local-owner operation as a remote or hostile CI endpoint.

mod candidate;
use candidate::WorkflowInputs;

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use fgit_crypto::{GitHashAlgorithm, NativeObjectIdentity, Sha1, Sha256};
use fgit_resource::{LeakDisposition, ObligationLedger, RegionCloseOutcome, RegionId};
use fgit_runner::sparse_workspace::{HostRefusal, SparseWorkspace, SparseWorkspacePlan};
use fgit_runner::workflow::{
    StepLimits, StepObservation, WorkerFailure, WorkflowExecutor, WorkflowJob,
    WorkflowLimits, WorkflowPlan, WorkflowReport, run_trusted_step,
};
use fgit_treefs::{BaseView, SparseEntryKind, SparseLimits, SparseManifest, TreeCapability,
    TreePath, WorkspaceId};
use fgit_types::{ByteCount, GitHashAlgorithm as Format, GitOid, RefName,
    RepositoryAuthorityHeadId, RepositoryCommitId, RepositoryId,
    RepositoryIncarnationId, TenantId};

use crate::{NodeRequestContext, OneNode};
use super::{NodeTreeSource, NodeWorkspaceRefusal, workspace_request_live};

const FETCH_BYTES: u64 = 256 * 1024 * 1024;
const FETCH_OBJECTS: u64 = 100_000;
const SOURCE_LIMITS: SparseLimits = SparseLimits {
    max_entries: 10_000,
    max_entry_bytes: 16 * 1024 * 1024,
    max_payload_bytes: 64 * 1024 * 1024,
};
const MAX_REPLICATED_BYTES: usize = 256 * 1024 * 1024;
const MAX_REPLICATED_ENTRIES: usize = 100_000;

#[derive(Debug)]
pub enum TrustedWorkflowFailure {
    InvalidInput(&'static str),
    Source(NodeWorkspaceRefusal),
    Candidate(Box<super::candidate_inspection::BundleInspectionRefusal>),
    Workflow(fgit_runner::workflow::WorkflowError),
    Host(HostRefusal),
    /// Never reuse an occupied slot: it can contain an interrupted execution.
    AttemptExists(PathBuf),
    Io { operation: &'static str, source: std::io::Error },
    /// An attempt directory was created. This does not prove non-execution;
    /// inspect its marker/report and reconcile external effects before retry.
    Journal { directory: PathBuf, detail: String },
}
impl std::fmt::Display for TrustedWorkflowFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "trusted workflow failed: {self:?}")
    }
}
impl std::error::Error for TrustedWorkflowFailure {}

/// Exact unpublished inputs, not an RCR admitting their native identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedWorkflowCandidate {
    pub commit: GitOid,
    pub tree: GitOid,
    pub bundle_sha256: [u8; 32],
}

/// A local observation, not a forge check, approval, or signed runner evidence.
/// Source fields identify the canonical BASE from one authenticated head.
/// A candidate is recorded separately; executed_commit/tree identify actual input.
#[derive(Debug)]
pub struct TrustedWorkflowRun {
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub incarnation: RepositoryIncarnationId,
    pub source_head: RepositoryAuthorityHeadId,
    pub source_rcr: RepositoryCommitId,
    pub source_commit: GitOid,
    pub source_tree: GitOid,
    pub source_reference: Vec<u8>,
    pub candidate: Option<TrustedWorkflowCandidate>,
    pub workflow_blob: GitOid,
    pub workflow_path: Vec<u8>,
    pub read_prefixes: Vec<Vec<u8>>,
    pub run_id: [u8; 16],
    pub run_directory: PathBuf,
    pub workspaces_closed: bool,
    pub request_interrupted: bool,
    pub execution: WorkflowReport,
}
impl TrustedWorkflowRun {
    pub fn succeeded(&self) -> bool {
        self.workspaces_closed && !self.request_interrupted && self.execution.succeeded()
    }
    pub fn executed_commit(&self) -> GitOid { self.candidate.map_or(self.source_commit, |c| c.commit) }
    pub fn executed_tree(&self) -> GitOid { self.candidate.map_or(self.source_tree, |c| c.tree) }
    fn identity_json(&self) -> String {
        let prefixes = self.read_prefixes.iter().map(|p| format!("\"{}\"", hex(p)))
            .collect::<Vec<_>>().join(",");
        let candidate = self.candidate.map_or_else(|| "null".to_owned(), |c|
            format!("{{\"commit\":\"{}\",\"tree\":\"{}\",\"bundle_sha256\":\"{}\",\"admitted\":false}}", c.commit, c.tree, hex(&c.bundle_sha256)));
        format!(concat!("\"schema_version\":1,\"tenant_id\":\"{}\",\"repository_id\":\"{}\",",
            "\"repository_incarnation\":\"{}\",\"source_head\":\"{}\",\"source_rcr\":\"{}\",",
            "\"object_format\":\"{}\",\"source_commit\":\"{}\",\"source_tree\":\"{}\",\"source_ref_hex\":\"{}\",",
            "\"workflow_blob\":\"{}\",\"workflow_path_hex\":\"{}\",\"read_prefixes_hex\":[{}],",
            "\"run_id\":\"{}\",\"run_directory_hex\":\"{}\",",
            "\"hostile_code_isolated\":false,\"authoritative_check\":false,\"published\":false,",
            "\"input_kind\":\"{}\",\"executed_commit\":\"{}\",\"executed_tree\":\"{}\",\"candidate\":{}"),
            self.tenant, self.repository, self.incarnation, self.source_head, self.source_rcr,
            self.source_commit.algorithm().as_str(), self.source_commit, self.source_tree,
            hex(&self.source_reference), self.workflow_blob, hex(&self.workflow_path), prefixes,
            hex(&self.run_id), hex(self.run_directory.as_os_str().as_bytes()),
            if self.candidate.is_some() { "unpublished_candidate" } else { "canonical" },
            self.executed_commit(), self.executed_tree(), candidate)
    }
    /// Output stays bounded by the native workflow report and source profile.
    /// All arbitrary source/output/path bytes use lossless hexadecimal encoding.
    pub fn to_json(&self) -> String {
        format!(concat!("{{\"type\":\"trusted_workflow_run\",{},\"succeeded\":{},",
            "\"workspaces_closed\":{},\"request_interrupted\":{},\"execution\":{}}}"),
            self.identity_json(), self.succeeded(), self.workspaces_closed,
            self.request_interrupted, self.execution.to_json())
    }
}

impl OneNode {
    /// Compile and execute a repository workflow at one verified source head.
    ///
    /// The caller MUST be the explicitly trusted local owner. Scripts run with
    /// host-user privileges and must join their own descendants. Read prefixes
    /// select inputs, NOT a process sandbox. No secrets, network isolation,
    /// canonical check publication, or automatic retry is provided.
    ///
    /// The workflow itself must be a regular file within the declared top-level
    /// input prefixes. Validate the entire graph and all host inputs before any
    /// script starts. Each job gets a fresh descriptor-relative TreeFS copy;
    /// steps in one job share only that job's copy. No edited source is imported.
    ///
    /// An exclusive, persistent workflow-<run_id> directory prevents accidental
    /// replay. A synced attempt marker precedes all processes. report.json is
    /// installed without replacement after every started workspace is closed or
    /// explicitly retained. An incomplete attempt is never automatically rerun.
    pub async fn run_trusted_workflow_in(
        &self, request: &NodeRequestContext, reference: &RefName, workflow_path: &[u8],
        run_id: [u8; 16], parent: &Path, read_prefixes: &[Vec<u8>],
        expected: (Option<RepositoryAuthorityHeadId>, Option<GitOid>),
        limits: WorkflowLimits,
    ) -> Result<TrustedWorkflowRun, TrustedWorkflowFailure> {
        limits.validate().map_err(TrustedWorkflowFailure::Workflow)?;
        let paths = validate_inputs(workflow_path, run_id, parent, read_prefixes)?;
        let started = Instant::now();
        match self.object_format {
            Format::Sha1 => self.run_workflow_format::<Sha1>(request, reference, workflow_path,
                run_id, parent, paths, expected, limits, started).await,
            Format::Sha256 => self.run_workflow_format::<Sha256>(request, reference, workflow_path,
                run_id, parent, paths, expected, limits, started).await,
        }
    }

    async fn run_workflow_format<A: GitHashAlgorithm>(
        &self, request: &NodeRequestContext, reference: &RefName, workflow_path: &[u8],
        run_id: [u8; 16], parent: &Path, paths: Vec<TreePath>,
        expected: (Option<RepositoryAuthorityHeadId>, Option<GitOid>),
        limits: WorkflowLimits, started: Instant,
    ) -> Result<TrustedWorkflowRun, TrustedWorkflowFailure> {
        let bytes = ByteCount::try_new("workflow source", FETCH_BYTES, FETCH_BYTES)
            .map_err(|_| TrustedWorkflowFailure::InvalidInput("source budget"))?;
        let declared = paths.iter().map(|p| p.as_bytes().to_vec()).collect::<Vec<_>>();
        let mut capability = TreeCapability::new(WorkspaceId::from_bytes(run_id),
            self.repository_id(), paths, Vec::new()).with_fetch_budget(bytes)
            .with_file_budget(FETCH_OBJECTS);
        // Preserve execution/cleanup observations if the shared read boundary
        // notices cancellation at its final checkpoint. Nothing is published.
        let observed = Mutex::new(None);
        let selected = self.with_workspace_snapshot_in::<A, _>(request, reference,
            &Default::default(), &mut capability, 0, expected.0, expected.1,
            SOURCE_LIMITS.max_entry_bytes,
            |base, source, capability, head, _| {
                let result = run_at(self, request, base, source, capability, head,
                    reference, workflow_path, &declared, run_id, parent, limits, started);
                *observed.lock().map_err(|_| NodeWorkspaceRefusal::UnsupportedWorkspaceEdit)? = Some(result);
                Ok(())
            }).await;
        let observed = observed.into_inner().map_err(|_| TrustedWorkflowFailure::InvalidInput("result lock poisoned"))?;
        match (selected, observed) {
            (_, Some(Err(error))) => Err(error),
            (Ok(()) | Err(NodeWorkspaceRefusal::Cancelled { .. }), Some(Ok(report))) => {
                // A completed local observation wins over cancellation noticed
                // after its report was persisted. Do not contradict that report
                // or treat a lost response as permission to execute again.
                Ok(report)
            }
            (Err(error), Some(Ok(report))) => Err(TrustedWorkflowFailure::Journal {
                directory: report.run_directory,
                detail: format!("source finalization failed after execution: {error}; inspect report.json, do not replay"),
            }),
            (Err(error), None) => Err(TrustedWorkflowFailure::Source(error)),
            (Ok(()), None) => Err(TrustedWorkflowFailure::InvalidInput("source consumer did not complete")),
        }
    }
}

fn validate_inputs(workflow: &[u8], run_id: [u8; 16], parent: &Path, prefixes: &[Vec<u8>])
    -> Result<Vec<TreePath>, TrustedWorkflowFailure>
{
    let invalid = TrustedWorkflowFailure::InvalidInput;
    if run_id == [0; 16] || !parent.is_absolute() || prefixes.is_empty() || prefixes.len() > 1024 {
        return Err(invalid("nonzero run ID, absolute private parent and 1..1024 input prefixes required"));
    }
    if prefixes.iter().try_fold(0_usize, |n, p| n.checked_add(p.len())).is_none_or(|n| n > 64 * 1024) {
        return Err(invalid("input prefix bytes exceed 64 KiB"));
    }
    let workflow = TreePath::parse_default(workflow).map_err(|_| invalid("invalid workflow path"))?;
    let mut paths = BTreeSet::new();
    for prefix in prefixes {
        let path = TreePath::parse_default(prefix).map_err(|_| invalid("invalid input prefix"))?;
        if path.component_count() != 1 || !paths.insert(path) {
            return Err(invalid("input prefixes must be distinct top-level paths"));
        }
    }
    if !paths.iter().any(|path| workflow.starts_with(path)) {
        return Err(invalid("workflow must be within declared inputs"));
    }
    Ok(paths.into_iter().collect())
}

fn run_at<A: GitHashAlgorithm>(node: &OneNode, request: &NodeRequestContext,
    base: &BaseView<A>, source: &NodeTreeSource<'_>, capability: &mut TreeCapability,
    head: RepositoryAuthorityHeadId, reference: &RefName, workflow_path: &[u8],
    declared: &[Vec<u8>], run_id: [u8; 16], parent: &Path,
    limits: WorkflowLimits, started: Instant,
) -> Result<TrustedWorkflowRun, TrustedWorkflowFailure> {
    if !workspace_request_live(request) || started.elapsed() >= limits.run_timeout {
        return Err(TrustedWorkflowFailure::InvalidInput("request stopped before source discovery"));
    }
    let manifest = Arc::new(SparseManifest::build(base, source, capability, 0, SOURCE_LIMITS)
        .map_err(|error| TrustedWorkflowFailure::Source(NodeWorkspaceRefusal::Manifest(error)))?);
    run_inputs(node, request, WorkflowInputs::Canonical(manifest), capability, head,
        reference, workflow_path, declared, run_id, parent, limits, started)
}

fn run_inputs<A: GitHashAlgorithm>(node: &OneNode, request: &NodeRequestContext,
    inputs: WorkflowInputs<A>, capability: &TreeCapability,
    head: RepositoryAuthorityHeadId, reference: &RefName, workflow_path: &[u8],
    declared: &[Vec<u8>], run_id: [u8; 16], parent: &Path,
    limits: WorkflowLimits, started: Instant,
) -> Result<TrustedWorkflowRun, TrustedWorkflowFailure> {
    let live = || workspace_request_live(request) && started.elapsed() < limits.run_timeout;
    if !live() { return Err(TrustedWorkflowFailure::InvalidInput("request stopped before workflow preflight")); }
    let entry = inputs.entries().iter().find(|entry| entry.path().as_bytes() == workflow_path)
        .ok_or(TrustedWorkflowFailure::InvalidInput("workflow is not in the selected inputs"))?;
    let SparseEntryKind::File { body, .. } = entry.kind() else {
        return Err(TrustedWorkflowFailure::InvalidInput("workflow must be a regular file"));
    };
    let plan = WorkflowPlan::compile(std::str::from_utf8(body)
        .map_err(|_| TrustedWorkflowFailure::InvalidInput("workflow is not UTF-8"))?)
        .map_err(TrustedWorkflowFailure::Workflow)?;
    if inputs.payload_bytes().checked_mul(plan.graph().jobs.len())
        .is_none_or(|n| n > MAX_REPLICATED_BYTES)
        || inputs.entries().len().checked_mul(plan.graph().jobs.len())
        .is_none_or(|n| n > MAX_REPLICATED_ENTRIES)
    { return Err(TrustedWorkflowFailure::InvalidInput("aggregate job materialization exceeds profile")); }
    // Refuse unsupported host entries before even the first independent job.
    // Each job clones this immutable plan, then rechecks capability at materialize.
    let host_plan = inputs.host_plan(capability).map_err(TrustedWorkflowFailure::Host)?;
    let format = node.object_format;
    let native = |bytes: &[u8]| GitOid::from_hex(format, &hex(bytes))
        .map_err(|_| TrustedWorkflowFailure::InvalidInput("source identity width"));
    let (source_rcr, source_commit, source_tree, candidate) = inputs.coordinates(format)?;
    let mut report = TrustedWorkflowRun {
        tenant: node.tenant_id, repository: node.repository_id(), incarnation: node.repository_incarnation_id(),
        source_head: head, source_rcr, source_commit, source_tree, candidate,
        source_reference: reference.as_bytes().to_vec(), workflow_blob: native(entry.source_oid().digest_bytes())?,
        workflow_path: workflow_path.to_vec(), read_prefixes: declared.to_vec(),
        run_id, run_directory: parent.join(format!("workflow-{}", hex(&run_id))),
        workspaces_closed: false, request_interrupted: false,
        execution: WorkflowReport { source: plan.source_commitment(), graph: plan.graph_commitment(), limits, jobs: Vec::new() },
    };
    if !live() { return Err(TrustedWorkflowFailure::InvalidInput("request stopped during preflight")); }
    let metadata = fs::symlink_metadata(parent).map_err(|source| TrustedWorkflowFailure::Io { operation: "inspect private run parent", source })?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(TrustedWorkflowFailure::InvalidInput("run parent must be a nonsymlink 0700 directory"));
    }
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(&report.run_directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Err(TrustedWorkflowFailure::AttemptExists(report.run_directory)),
        Err(source) => return Err(TrustedWorkflowFailure::Io { operation: "reserve unique workflow attempt", source }),
    }
    let run_directory = report.run_directory.clone();
    let journal_error = |detail| TrustedWorkflowFailure::Journal { directory: run_directory.clone(), detail };
    let root = File::open(&report.run_directory).map_err(|e| journal_error(e.to_string()))?;
    let marker = format!("{{\"type\":\"trusted_workflow_attempt\",{},\"state\":\"started\",\"execution_plan\":{}}}",
        report.identity_json(), report.execution.to_json());
    write_new(&report.run_directory.join("attempt.json"), marker.as_bytes())
        .and_then(|()| root.sync_all()).and_then(|()| File::open(parent)?.sync_all())
        .map_err(|e| journal_error(format!("attempt marker durability failed before any job: {e}")))?;
    let mut worker = Executor { plan: host_plan, capability, parent: root, directory: report.run_directory.clone(),
        current: None, capture_paths: Vec::new(), retained: false, job_index: 0 };
    // This outer predicate also charges source discovery against the run budget.
    // The scheduler owns every begun job and always calls non-cancellable close.
    report.execution = plan.execute(limits, &mut worker, &live)
        .map_err(|e| journal_error(format!("workflow driver failed: {e}")))?;
    report.workspaces_closed = !worker.retained && worker.current.is_none();
    report.request_interrupted = !workspace_request_live(request) || started.elapsed() >= limits.run_timeout;
    let json = report.to_json();
    publish_report(&worker.parent, &report.run_directory, json.as_bytes())
        .map_err(|e| journal_error(format!("execution finished but report durability failed: {e}; do not replay this attempt")))?;
    Ok(report)
}

fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
fn publish_report(root: &File, directory: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let temporary = directory.join(".report.pending");
    write_new(&temporary, bytes)?;
    // A completed result can never be replaced by a rerun or later failure.
    fs::hard_link(&temporary, directory.join("report.json"))?;
    root.sync_all()?;
    fs::remove_file(temporary)?;
    root.sync_all()
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

struct Executor<'a, A: GitHashAlgorithm> {
    plan: SparseWorkspacePlan<A>,
    capability: &'a TreeCapability,
    parent: File,
    directory: PathBuf,
    current: Option<(SparseWorkspace<A>, ObligationLedger)>,
    capture_paths: Vec<PathBuf>,
    retained: bool,
    job_index: usize,
}
impl<A: GitHashAlgorithm> WorkflowExecutor for Executor<'_, A> {
    fn begin_job(&mut self, index: usize, _job: &WorkflowJob, live: &dyn Fn() -> bool) -> Result<(), WorkerFailure> {
        if self.current.is_some() || self.retained { return Err(WorkerFailure::new("previous job is not quiescent", true)); }
        self.job_index = index;
        let plan = self.plan.clone();
        let parent = self.parent.try_clone().map_err(|e| WorkerFailure::new(e.to_string(), false))?;
        let slot = TreePath::parse_default(format!("job-{index:03}").as_bytes())
            .map_err(|e| WorkerFailure::new(e.to_string(), false))?;
        let ledger = ObligationLedger::root(RegionId::new(index as u64 + 1), LeakDisposition::RecordAndContinue, plan.budget());
        let granted = ledger.grant(plan.budget()).map_err(|e| WorkerFailure::new(e.to_string(), false))?;
        let reserved = ledger.reserve(plan.reservation(), granted).map_err(|e| WorkerFailure::new(e.to_string(), false))?;
        match SparseWorkspace::materialize(plan, parent, slot, reserved, self.capability, 0, &|_| !live()) {
            Ok(workspace) => { self.current = Some((workspace, ledger)); Ok(()) }
            Err(error) => {
                let settled = matches!(ledger.close(), RegionCloseOutcome::Quiescent(_));
                self.retained |= matches!(&error, HostRefusal::Containment { .. }) || !settled;
                Err(WorkerFailure::new(error.to_string(), self.retained))
            }
        }
    }
    fn execute_step(&mut self, index: usize, script: &str, limits: StepLimits, live: &dyn Fn() -> bool)
        -> Result<StepObservation, WorkerFailure>
    {
        let (workspace, _) = self.current.as_ref().ok_or_else(|| WorkerFailure::new("no active job", true))?;
        let mut open = |stream: &str| {
            let path = self.directory.join(format!("job-{:03}-step-{index:03}-{stream}", self.job_index));
            let file = OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&path)
                .map_err(|e| WorkerFailure::new(format!("create capture: {e}"), false))?;
            self.capture_paths.push(path);
            Ok::<_, WorkerFailure>(file)
        };
        let stdout = open("stdout")?;
        let stderr = open("stderr")?;
        run_trusted_step(&workspace.tool_directory(), script, limits, &stdout, &stderr, live)
    }
    fn finish_job(&mut self, retain: bool) -> Result<(), WorkerFailure> {
        let Some((workspace, ledger)) = self.current.take() else {
            self.retained = true;
            return Err(WorkerFailure::new("job responsibility missing during close", true));
        };
        if retain {
            self.retained = true;
            drop(workspace);
            let _unsettled = ledger.close();
            return Err(WorkerFailure::new("workspace and captures retained: descendant quiescence is unproved", true));
        }
        let closed = workspace.close();
        let settled = matches!(ledger.close(), RegionCloseOutcome::Quiescent(_));
        if let Err(error) = closed {
            self.retained = true;
            return Err(WorkerFailure::new(format!("workspace close: {error}"), true));
        }
        if !settled {
            self.retained = true;
            return Err(WorkerFailure::new("workspace obligation did not settle", true));
        }
        for path in &self.capture_paths {
            if let Err(error) = fs::remove_file(path) {
                self.retained = true;
                return Err(WorkerFailure::new(format!("capture cleanup: {error}"), true));
            }
        }
        self.capture_paths.clear();
        Ok(())
    }
}
