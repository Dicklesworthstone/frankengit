//! Bounded custody of normalized observations, after the process/workspace closes.
//! Logs use the artifact owner's existing namespace, permissions and retention.
//! A receipt records bytes and observed outcomes; it does not publish a check.

use super::*;
use fgit_runner::Commitment;
use fgit_runner::workflow::{JobOutcome, JobReport, StepOutcome};

/// The exact process stream represented by a retained binary payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustedWorkflowLogStream {
    Stdout,
    Stderr,
}
impl TrustedWorkflowLogStream {
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

/// An exact bounded stream from an already-normalized step observation.
/// output_complete is copied from that observation, including false for a
/// truncated or otherwise incomplete pair of streams; custody cannot upgrade it.
#[derive(Clone, Debug)]
pub struct TrustedWorkflowStepLog {
    pub step_index: usize,
    pub step_name: Option<String>,
    pub script: Commitment,
    pub stream: TrustedWorkflowLogStream,
    pub observed_outcome: StepOutcome,
    pub exit_code: Option<i32>,
    pub output_complete: bool,
    pub artifact_id: Digest,
    pub payload_sha256: Digest,
    pub payload_bytes: usize,
}
impl TrustedWorkflowStepLog {
    fn to_json(&self) -> String {
        let name = self.step_name.as_ref().map_or_else(
            || "null".to_owned(),
            |name| format!("\"{}\"", hex(name.as_bytes())),
        );
        let exit_code = self
            .exit_code
            .map_or_else(|| "null".to_owned(), |code| code.to_string());
        format!(
            "{{\"step_index\":{},\"step_name_hex\":{},\"script_sha256\":\"{}\",\"stream\":\"{}\",\"observed_step_outcome\":\"{}\",\"exit_code\":{},\"output_complete\":{},\"artifact_id_sha256\":\"{}\",\"payload_sha256\":\"{}\",\"payload_bytes\":{}}}",
            self.step_index,
            name,
            hex(self.script.digest().bytes().as_bytes()),
            self.stream.token(),
            self.observed_outcome.token(),
            exit_code,
            self.output_complete,
            digest_hex(self.artifact_id),
            digest_hex(self.payload_sha256),
            self.payload_bytes,
        )
    }
}

/// Root-last custody for one job's logs. The observed outcome precedes custody
/// settlement; the final workflow report and durable journal own job success.
#[derive(Clone, Debug)]
pub struct TrustedWorkflowJobLogs {
    pub job_id: String,
    pub manifest_id: Digest,
    pub observed_outcome: JobOutcome,
    pub logs: Vec<TrustedWorkflowStepLog>,
}
impl TrustedWorkflowJobLogs {
    pub(in crate::treefs_workspace::trusted_workflow) fn to_json(&self) -> String {
        format!(
            "{{\"job_id_hex\":\"{}\",\"manifest_id_sha256\":\"{}\",\"observed_job_outcome\":\"{}\",\"logs\":[{}]}}",
            hex(self.job_id.as_bytes()),
            digest_hex(self.manifest_id),
            self.observed_outcome.token(),
            logs_json(&self.logs),
        )
    }
}

impl Collector<'_> {
    pub(in crate::treefs_workspace::trusted_workflow) fn logs_enabled(&self) -> bool {
        self.session.config.capture_logs
    }

    /// Uses only owned report bytes, never reopened process captures or workspace
    /// paths. The caller supplies its finite finalization allowance separately
    /// from execution cancellation. This method cannot start or replay a step.
    /// Newly acquired stage responsibility is settled even when that allowance
    /// expires. Earlier stages remain owned by their original caller.
    pub(in crate::treefs_workspace::trusted_workflow) fn capture_logs(
        &mut self,
        index: usize,
        report: &JobReport,
        root: &File,
        directory: &Path,
        stages: &mut Vec<PathBuf>,
        live: &dyn Fn() -> bool,
    ) -> Result<(), WorkerFailure> {
        let prior_stages = stages.len();
        let result = self.capture_logs_inner(index, report, root, directory, stages, live);
        while stages.len() > prior_stages {
            if let Err(cleanup) = remove_stage(stages) {
                let detail = match &result {
                    Ok(()) => cleanup,
                    Err(original) => format!("{original}; log stage cleanup: {cleanup}"),
                };
                return Err(WorkerFailure::new(format!("log custody: {detail}"), true));
            }
        }
        result.map_err(|detail| WorkerFailure::new(format!("log custody: {detail}"), false))
    }

    fn capture_logs_inner(
        &mut self,
        index: usize,
        report: &JobReport,
        root: &File,
        directory: &Path,
        stages: &mut Vec<PathBuf>,
        live: &dyn Fn() -> bool,
    ) -> Result<(), String> {
        if !self.logs_enabled() || report.steps.is_empty() {
            return Ok(());
        }
        if self.logs.iter().any(|saved| saved.job_id == report.id) {
            return Err("job logs were already captured; replay refused".into());
        }
        // Reserve the complete job's payload allowance before publishing even
        // its first stream. Outputs and all dispatch children share this budget.
        let mut total = 0usize;
        for step in &report.steps {
            if !live() {
                return Err("log finalization stopped before payload reservation".into());
            }
            for bytes in [&step.observation.stdout, &step.observation.stderr] {
                if bytes.len() > self.session.config.maximum_bytes {
                    return Err("retained log stream exceeds the per-artifact byte limit".into());
                }
                total = total
                    .checked_add(bytes.len())
                    .ok_or_else(|| "retained log byte count overflow".to_owned())?;
            }
        }
        self.session.charge(total)?;
        let op = ArtifactOperation::new(
            self.session.config.maximum_bytes.max(MAX_MANIFEST_BYTES) as u64,
            Duration::from_secs(3600),
            live,
        )
        .map_err(|error| error.to_string())?;
        let mut logs = Vec::new();
        for step in &report.steps {
            for (stream, bytes) in [
                (TrustedWorkflowLogStream::Stdout, &step.observation.stdout),
                (TrustedWorkflowLogStream::Stderr, &step.observation.stderr),
            ] {
                if !live() {
                    return Err("log finalization stopped before stream publication".into());
                }
                let identity = self.identity(
                    bytes,
                    ArtifactPayloadKind::BuildLog,
                    "application/octet-stream",
                );
                self.store_payload(
                    directory,
                    &format!(
                        "job-{index:03}-step-{:03}-{}.log.pending",
                        step.index,
                        stream.token()
                    ),
                    bytes,
                    &identity,
                    stages,
                    &op,
                    live,
                )?;
                logs.push(TrustedWorkflowStepLog {
                    step_index: step.index,
                    step_name: step.name.clone(),
                    script: step.script,
                    stream,
                    observed_outcome: step.observation.outcome,
                    exit_code: step.observation.exit_code,
                    output_complete: step.observation.output_complete,
                    artifact_id: *identity.artifact_id(),
                    payload_sha256: *identity.payload_digest(),
                    payload_bytes: bytes.len(),
                });
            }
        }
        let manifest = self.log_manifest(report, &logs);
        if manifest.len() > MAX_MANIFEST_BYTES {
            return Err("log provenance manifest exceeds 1 MiB".into());
        }
        let identity = self.identity(
            manifest.as_bytes(),
            ArtifactPayloadKind::Provenance,
            "application/json",
        );
        self.store_payload(
            directory,
            &format!("job-{index:03}-log-provenance.pending"),
            manifest.as_bytes(),
            &identity,
            stages,
            &op,
            live,
        )?;
        let saved = TrustedWorkflowJobLogs {
            job_id: report.id.clone(),
            manifest_id: *identity.artifact_id(),
            observed_outcome: report.outcome,
            logs,
        };
        let receipt = format!(
            "{{\"type\":\"trusted_workflow_log_receipt\",\"manifest_id_sha256\":\"{}\",\"manifest\":{}}}",
            digest_hex(saved.manifest_id),
            manifest,
        );
        if !live() {
            return Err("log finalization stopped before receipt publication".into());
        }
        let pending = format!(".job-{index:03}-logs.pending");
        stage_bytes(directory, &pending, receipt.as_bytes(), stages, live)?;
        fs::hard_link(
            directory.join(&pending),
            directory.join(format!("job-{index:03}-logs.json")),
        )
        .and_then(|()| root.sync_all())
        .map_err(|error| format!("log receipt durability: {error}"))?;
        remove_stage(stages)?;
        root.sync_all()
            .map_err(|error| format!("log receipt cleanup durability: {error}"))?;
        self.logs.push(saved);
        Ok(())
    }

    fn log_manifest(&self, report: &JobReport, logs: &[TrustedWorkflowStepLog]) -> String {
        let mut manifest = format!(
            "{{\"type\":\"trusted_workflow_log_provenance\",\"schema_version\":1,\"producer\":{{{}}},\"attempt_sha256\":\"{}\",\"workflow_source_sha256\":\"{}\",\"workflow_graph_sha256\":\"{}\",\"job_id_hex\":\"{}\",\"observed_job_outcome\":\"{}\",\"build_input_capsule_id\":null,\"check_receipt_id\":null,\"cache_reuse_authorized\":false,\"job_success_asserted\":false,\"logs\":[{}]}}",
            self.producer,
            hex(&self.attempt_sha256),
            self.workflow_source,
            self.workflow_graph,
            hex(report.id.as_bytes()),
            report.outcome.token(),
            logs_json(logs),
        );
        if let Some(inputs) = self.inputs.iter().find(|inputs| inputs.job_id == report.id) {
            manifest.pop();
            manifest.push_str(&format!(",\"artifact_inputs\":{}}}", inputs.to_json()));
        }
        manifest
    }
}

fn logs_json(logs: &[TrustedWorkflowStepLog]) -> String {
    logs.iter()
        .map(TrustedWorkflowStepLog::to_json)
        .collect::<Vec<_>>()
        .join(",")
}
