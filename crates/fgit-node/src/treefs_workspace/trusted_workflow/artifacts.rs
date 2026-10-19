//! Explicit output custody for the trusted local script profile.
//! Stored bytes and provenance do not grant a BuildInputCapsule cache hit or a
//! canonical check. The producing attempt must still close and publish normally.

use super::*;
use fgit_crypto::{DigestAlgorithm, sha256_digest};
use fgit_object_fabric::artifact::storage::{ArtifactOperation, ArtifactScope, LocalArtifactStore};
use fgit_object_fabric::artifact::{
    ArtifactIdentity, ArtifactPayloadKind, MediaType, RetentionProfile,
};
use fgit_treefs::FileMode;
use fgit_types::{Digest, DigestBytes};
use std::cell::Cell;
use std::time::Duration;

/// Filesystem namespace selected with fg artifact inspect/export --trust-domain.
pub const TRUSTED_WORKFLOW_ARTIFACT_TRUST: &str = "trusted-workflow-local-owner";
pub const DEFAULT_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_ARTIFACT_TOTAL_BYTES: usize = 64 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
const MAX_ARTIFACT_TOTAL_BYTES: usize = 512 * 1024 * 1024;
const MAX_SELECTIONS: usize = 64;
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;

/// An exact workflow, expanded job ID and regular output path, never a glob.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct TrustedWorkflowArtifactSelection {
    workflow: TreePath,
    job: String,
    output: TreePath,
}
impl TrustedWorkflowArtifactSelection {
    pub fn new(workflow: &[u8], job: &str, output: &[u8]) -> Result<Self, &'static str> {
        if job.is_empty()
            || job.len() > 256
            || !job
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            return Err("artifact job must be a 1..256-byte ASCII identifier");
        }
        let parse = |bytes: &[u8]| {
            if bytes.len() > 4096 {
                return Err("artifact path exceeds 4096 bytes");
            }
            TreePath::parse_default(bytes).map_err(|_| "invalid artifact path")
        };
        let workflow = parse(workflow)?;
        let output = parse(output)?;
        if output.as_bytes() == b".fgit-host-receipt" {
            return Err("workspace ownership marker is not an artifact");
        }
        Ok(Self {
            workflow,
            job: job.to_owned(),
            output,
        })
    }
    pub fn workflow_path(&self) -> &[u8] {
        self.workflow.as_bytes()
    }
    pub fn job_id(&self) -> &str {
        &self.job
    }
    pub fn output_path(&self) -> &[u8] {
        self.output.as_bytes()
    }
}

/// Operator-owned output contract. Construction is bounded and performs no I/O.
/// The root and its ancestors must be protected by the trusted local owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedWorkflowArtifactConfig {
    root: PathBuf,
    selections: Vec<TrustedWorkflowArtifactSelection>,
    maximum_bytes: usize,
    total_bytes: usize,
}
impl TrustedWorkflowArtifactConfig {
    pub fn new(
        root: PathBuf,
        mut selections: Vec<TrustedWorkflowArtifactSelection>,
        maximum_bytes: usize,
        total_bytes: usize,
    ) -> Result<Self, &'static str> {
        if !root.is_absolute() || root.as_os_str().as_bytes().len() > 4096 {
            return Err("artifact root must be an absolute bounded private directory");
        }
        if selections.is_empty()
            || selections.len() > MAX_SELECTIONS
            || maximum_bytes == 0
            || maximum_bytes > MAX_ARTIFACT_BYTES
            || total_bytes == 0
            || total_bytes > MAX_ARTIFACT_TOTAL_BYTES
        {
            return Err("artifact contract exceeds its file, byte or selection envelope");
        }
        let path_bytes = selections.iter().try_fold(0usize, |n, s| {
            n.checked_add(s.workflow.as_bytes().len())?
                .checked_add(s.output.as_bytes().len())
        });
        if path_bytes.is_none_or(|n| n > 64 * 1024) {
            return Err("artifact selection paths exceed 64 KiB");
        }
        selections.sort();
        if selections.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err("artifact selections must be distinct");
        }
        Ok(Self {
            root,
            selections,
            maximum_bytes,
            total_bytes,
        })
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn selections(&self) -> &[TrustedWorkflowArtifactSelection] {
        &self.selections
    }
    pub const fn maximum_bytes(&self) -> usize {
        self.maximum_bytes
    }
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub(super) fn to_json(&self) -> String {
        let selections = self.selections.iter().map(|s| format!(
            "{{\"workflow_path_hex\":\"{}\",\"job_id_hex\":\"{}\",\"output_path_hex\":\"{}\"}}",
            hex(s.workflow_path()), hex(s.job.as_bytes()), hex(s.output_path()),
        )).collect::<Vec<_>>().join(",");
        format!(
            "{{\"schema_version\":1,\"root_hex\":\"{}\",\"trust_domain\":\"{}\",\"maximum_file_bytes\":{},\"total_payload_bytes\":{},\"retention_ttl_seconds\":86400,\"selections\":[{}]}}",
            hex(self.root.as_os_str().as_bytes()),
            TRUSTED_WORKFLOW_ARTIFACT_TRUST,
            self.maximum_bytes,
            self.total_bytes,
            selections,
        )
    }

    pub(super) fn validate_workflow(
        &self,
        path: &[u8],
        plan: &WorkflowPlan,
    ) -> Result<(), TrustedWorkflowFailure> {
        if self
            .selections
            .iter()
            .filter(|s| s.workflow_path() == path)
            .any(|s| !plan.graph().jobs.iter().any(|job| job.id == s.job))
        {
            return Err(TrustedWorkflowFailure::InvalidInput(
                "artifact selection names an absent expanded workflow job",
            ));
        }
        Ok(())
    }
}

/// One cumulative output allowance, shared by every child in a dispatch.
pub(super) struct Session<'a> {
    pub(super) config: &'a TrustedWorkflowArtifactConfig,
    store: LocalArtifactStore,
    remaining: Cell<usize>,
}
impl<'a> Session<'a> {
    pub(super) fn open(
        node: &OneNode,
        config: &'a TrustedWorkflowArtifactConfig,
    ) -> Result<Self, TrustedWorkflowFailure> {
        let scope = ArtifactScope::new(
            node.tenant_id,
            node.repository_id(),
            node.repository_incarnation_id(),
            TRUSTED_WORKFLOW_ARTIFACT_TRUST,
        )
        .map_err(TrustedWorkflowFailure::Artifacts)?;
        let store = LocalArtifactStore::open(&config.root, scope)
            .map_err(TrustedWorkflowFailure::Artifacts)?;
        Ok(Self {
            config,
            store,
            remaining: Cell::new(config.total_bytes),
        })
    }

    fn charge(&self, bytes: usize) -> Result<(), String> {
        let remaining = self
            .remaining
            .get()
            .checked_sub(bytes)
            .ok_or_else(|| "aggregate artifact payload limit exceeded".to_owned())?;
        self.remaining.set(remaining);
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct TrustedWorkflowArtifactOutput {
    pub path: Vec<u8>,
    pub artifact_id: Digest,
    pub payload_sha256: Digest,
    pub payload_bytes: usize,
    pub executable: bool,
}
impl TrustedWorkflowArtifactOutput {
    fn to_json(&self) -> String {
        format!(
            "{{\"path_hex\":\"{}\",\"artifact_id_sha256\":\"{}\",\"payload_sha256\":\"{}\",\"payload_bytes\":{},\"executable\":{}}}",
            hex(&self.path),
            digest_hex(self.artifact_id),
            digest_hex(self.payload_sha256),
            self.payload_bytes,
            self.executable,
        )
    }
}

/// A durable provenance manifest for one producing attempt/job, not a check.
#[derive(Clone, Debug)]
pub struct TrustedWorkflowJobArtifacts {
    pub job_id: String,
    pub manifest_id: Digest,
    pub outputs: Vec<TrustedWorkflowArtifactOutput>,
}
impl TrustedWorkflowJobArtifacts {
    pub(super) fn to_json(&self) -> String {
        format!(
            "{{\"job_id_hex\":\"{}\",\"manifest_id_sha256\":\"{}\",\"outputs\":[{}]}}",
            hex(self.job_id.as_bytes()),
            digest_hex(self.manifest_id),
            self.outputs
                .iter()
                .map(TrustedWorkflowArtifactOutput::to_json)
                .collect::<Vec<_>>()
                .join(","),
        )
    }
}

pub(super) struct Collector<'a> {
    session: &'a Session<'a>,
    producer: String,
    attempt_sha256: [u8; 32],
    workflow_source: String,
    workflow_graph: String,
    workflow: Vec<u8>,
    source_rcr: Option<Digest>,
    pub(super) jobs: Vec<TrustedWorkflowJobArtifacts>,
}
impl<'a> Collector<'a> {
    pub(super) fn new(session: &'a Session<'a>, report: &TrustedWorkflowRun) -> Self {
        let source = report.source_rcr.as_internal_object_id();
        // The current local payload codec only accepts SHA-256 optional IDs.
        // Never relabel another algorithm's bytes. The complete qualified RCR
        // always remains in the immutable producer manifest, including its codec.
        let source_rcr = (source.algorithm() == DigestAlgorithm::Sha256.id()
            && source.digest().as_bytes().len() == 32)
            .then(|| Digest::new(source.algorithm(), *source.digest()));
        Self {
            session,
            producer: report.identity_json(),
            attempt_sha256: sha256_digest(report.attempt_marker().as_bytes()),
            workflow_source: hex(report.execution.source.digest().bytes().as_bytes()),
            workflow_graph: hex(report.execution.graph.digest().bytes().as_bytes()),
            workflow: report.workflow_path.clone(),
            source_rcr,
            jobs: Vec::new(),
        }
    }

    pub(super) fn selects(&self, job: &str) -> bool {
        self.session
            .config
            .selections
            .iter()
            .any(|s| s.workflow_path() == self.workflow && s.job == job)
    }

    pub(super) fn capture<A: GitHashAlgorithm>(
        &mut self,
        workspace: &SparseWorkspace<A>,
        index: usize,
        job: &str,
        root: &File,
        directory: &Path,
        stages: &mut Vec<PathBuf>,
        live: &dyn Fn() -> bool,
    ) -> Result<(), WorkerFailure> {
        self.capture_inner(workspace, index, job, root, directory, stages, live)
            .map_err(|detail| WorkerFailure::new(format!("artifact custody: {detail}"), false))
    }

    fn capture_inner<A: GitHashAlgorithm>(
        &mut self,
        workspace: &SparseWorkspace<A>,
        index: usize,
        job: &str,
        root: &File,
        directory: &Path,
        stages: &mut Vec<PathBuf>,
        live: &dyn Fn() -> bool,
    ) -> Result<(), String> {
        let selected = self
            .session
            .config
            .selections
            .iter()
            .filter(|s| s.workflow_path() == self.workflow && s.job == job)
            .collect::<Vec<_>>();
        if selected.is_empty() {
            return Ok(());
        }
        if self.jobs.iter().any(|saved| saved.job_id == job) {
            return Err("job outputs were already captured; replay refused".into());
        }
        let op = ArtifactOperation::new(
            self.session.config.maximum_bytes.max(MAX_MANIFEST_BYTES) as u64,
            Duration::from_secs(3600),
            live,
        )
        .map_err(|e| e.to_string())?;
        let mut outputs = Vec::new();
        for (number, selection) in selected.into_iter().enumerate() {
            let maximum = self
                .session
                .config
                .maximum_bytes
                .min(self.session.remaining.get());
            let (body, mode) = workspace
                .read_artifact_output(&selection.output, maximum, &|_| !live())
                .map_err(|e| e.to_string())?
                .ok_or_else(|| {
                    format!(
                        "selected output is missing: {}",
                        hex(selection.output_path())
                    )
                })?;
            self.session.charge(body.len())?;
            let identity = self.identity(
                &body,
                ArtifactPayloadKind::CiArtifact,
                "application/octet-stream",
            );
            self.store_payload(
                directory,
                &format!("job-{index:03}-artifact-{number:03}.pending"),
                &body,
                &identity,
                stages,
                &op,
                live,
            )?;
            outputs.push(TrustedWorkflowArtifactOutput {
                path: selection.output_path().to_vec(),
                artifact_id: *identity.artifact_id(),
                payload_sha256: *identity.payload_digest(),
                payload_bytes: body.len(),
                executable: mode == FileMode::Executable,
            });
        }
        let manifest = format!(
            "{{\"type\":\"trusted_workflow_artifact_provenance\",\"schema_version\":1,\"producer\":{{{}}},\"attempt_sha256\":\"{}\",\"workflow_source_sha256\":\"{}\",\"workflow_graph_sha256\":\"{}\",\"job_id_hex\":\"{}\",\"build_input_capsule_id\":null,\"check_receipt_id\":null,\"cache_reuse_authorized\":false,\"job_success_asserted\":false,\"outputs\":[{}]}}",
            self.producer,
            hex(&self.attempt_sha256),
            self.workflow_source,
            self.workflow_graph,
            hex(job.as_bytes()),
            outputs
                .iter()
                .map(TrustedWorkflowArtifactOutput::to_json)
                .collect::<Vec<_>>()
                .join(","),
        );
        if manifest.len() > MAX_MANIFEST_BYTES {
            return Err("artifact provenance manifest exceeds 1 MiB".into());
        }
        let identity = self.identity(
            manifest.as_bytes(),
            ArtifactPayloadKind::Provenance,
            "application/json",
        );
        self.store_payload(
            directory,
            &format!("job-{index:03}-provenance.pending"),
            manifest.as_bytes(),
            &identity,
            stages,
            &op,
            live,
        )?;
        let saved = TrustedWorkflowJobArtifacts {
            job_id: job.to_owned(),
            manifest_id: *identity.artifact_id(),
            outputs,
        };
        let receipt = format!(
            "{{\"type\":\"trusted_workflow_artifact_receipt\",\"manifest_id_sha256\":\"{}\",\"manifest\":{}}}",
            digest_hex(saved.manifest_id),
            manifest,
        );
        if !live() {
            return Err("request stopped before artifact receipt publication".into());
        }
        let pending = format!(".job-{index:03}-artifacts.pending");
        stage_bytes(directory, &pending, receipt.as_bytes(), stages, live)?;
        fs::hard_link(
            directory.join(&pending),
            directory.join(format!("job-{index:03}-artifacts.json")),
        )
        .and_then(|()| root.sync_all())
        .map_err(|e| format!("artifact receipt durability: {e}"))?;
        remove_stage(stages)?;
        root.sync_all()
            .map_err(|e| format!("artifact receipt cleanup durability: {e}"))?;
        // This immutable local manifest and the verified payload roots precede
        // the durable successful job observation. A lost response never replays.
        self.jobs.push(saved);
        Ok(())
    }

    fn identity(&self, bytes: &[u8], kind: ArtifactPayloadKind, media: &str) -> ArtifactIdentity {
        ArtifactIdentity::new(
            digest(bytes),
            bytes.len() as u64,
            MediaType::parse(media).expect("static media type"),
            kind,
            None,
            None,
            self.source_rcr,
            RetentionProfile::HotEphemeral { ttl_seconds: 86400 },
        )
    }

    fn store_payload(
        &self,
        directory: &Path,
        name: &str,
        bytes: &[u8],
        identity: &ArtifactIdentity,
        stages: &mut Vec<PathBuf>,
        op: &ArtifactOperation<'_>,
        live: &dyn Fn() -> bool,
    ) -> Result<(), String> {
        let mut file = stage_bytes(directory, name, bytes, stages, live)?;
        self.session
            .store
            .put(identity, &mut file, op)
            .map_err(|e| e.to_string())?;
        drop(file);
        remove_stage(stages)
    }
}

fn stage_bytes(
    directory: &Path,
    name: &str,
    bytes: &[u8],
    stages: &mut Vec<PathBuf>,
    live: &dyn Fn() -> bool,
) -> Result<File, String> {
    if !live() {
        return Err("request stopped before artifact staging".into());
    }
    let path = directory.join(name);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| format!("create artifact stage: {e}"))?;
    stages.push(path);
    for chunk in bytes.chunks(64 * 1024) {
        if !live() {
            return Err("request stopped during artifact staging".into());
        }
        file.write_all(chunk)
            .map_err(|e| format!("write artifact stage: {e}"))?;
    }
    if !live() {
        return Err("request stopped before artifact stage sync".into());
    }
    file.sync_all()
        .map_err(|e| format!("sync artifact stage: {e}"))?;
    Ok(file)
}
fn remove_stage(stages: &mut Vec<PathBuf>) -> Result<(), String> {
    let path = stages
        .last()
        .ok_or_else(|| "artifact stage responsibility missing".to_owned())?;
    fs::remove_file(path).map_err(|e| format!("artifact stage cleanup: {e}"))?;
    stages.pop();
    Ok(())
}
fn digest(bytes: &[u8]) -> Digest {
    Digest::new(
        DigestAlgorithm::Sha256.id(),
        DigestBytes::try_new(&sha256_digest(bytes)).expect("SHA-256 width"),
    )
}
fn digest_hex(value: Digest) -> String {
    hex(value.bytes().as_bytes())
}

#[cfg(test)]
mod tests;
