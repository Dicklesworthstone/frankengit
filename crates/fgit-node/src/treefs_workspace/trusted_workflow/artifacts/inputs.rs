//! Verified same-attempt artifact delivery, before the consumer workspace opens.
//! Current normalized producer outcomes select eligible custody; local stored
//! objects never authorize execution by their existence alone.

use super::*;
use fgit_runner::Commitment;
use fgit_runner::sparse_workspace::JobInput;
use fgit_runner::workflow::{JobOutcome, JobReport};

const ARTIFACT_INPUT_NAMESPACE: &[u8] = b".fgit-artifacts";

pub const DEFAULT_ARTIFACT_INPUT_TOTAL_BYTES: usize = 64 * 1024 * 1024;

/// Exact producer output copied to a direct dependent's private namespace.
/// destination is relative to .fgit-artifacts/, never a canonical source path.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct TrustedWorkflowArtifactInput {
    workflow: TreePath,
    consumer: String,
    producer: String,
    output: TreePath,
    destination: TreePath,
}
impl TrustedWorkflowArtifactInput {
    pub fn new(
        workflow: &[u8],
        consumer_job: &str,
        producer_job: &str,
        output: &[u8],
        destination: &[u8],
    ) -> Result<Self, &'static str> {
        let selected = TrustedWorkflowArtifactSelection::new(workflow, producer_job, output)?;
        let target = TrustedWorkflowArtifactSelection::new(workflow, consumer_job, destination)?;
        if consumer_job == producer_job {
            return Err("artifact input requires different producer and consumer jobs");
        }
        if destination.len() > 4000 {
            return Err("artifact input destination exceeds its namespace path limit");
        }
        Ok(Self {
            workflow: selected.workflow,
            consumer: consumer_job.to_owned(),
            producer: producer_job.to_owned(),
            output: selected.output,
            destination: target.output,
        })
    }
    #[must_use]
    pub fn workflow_path(&self) -> &[u8] {
        self.workflow.as_bytes()
    }
    #[must_use]
    pub fn consumer_job_id(&self) -> &str {
        &self.consumer
    }
    #[must_use]
    pub fn producer_job_id(&self) -> &str {
        &self.producer
    }
    #[must_use]
    pub fn output_path(&self) -> &[u8] {
        self.output.as_bytes()
    }
    #[must_use]
    pub fn destination(&self) -> &[u8] {
        self.destination.as_bytes()
    }

    fn to_json(&self) -> String {
        format!(
            "{{\"workflow_path_hex\":\"{}\",\"consumer_job_id_hex\":\"{}\",\"producer_job_id_hex\":\"{}\",\"output_path_hex\":\"{}\",\"destination_hex\":\"{}\"}}",
            hex(self.workflow_path()),
            hex(self.consumer.as_bytes()),
            hex(self.producer.as_bytes()),
            hex(self.output_path()),
            hex(self.destination()),
        )
    }
}

impl TrustedWorkflowArtifactConfig {
    /// Enable bounded same-workflow dependencies. This explicit local-owner
    /// contract authorizes only copies inside .fgit-artifacts; it grants no
    /// canonical source read/write capability or cross-run reuse permission.
    pub fn with_inputs(
        mut self,
        mut inputs: Vec<TrustedWorkflowArtifactInput>,
        maximum_total_delivery_bytes: usize,
    ) -> Result<Self, &'static str> {
        if !self.inputs.is_empty()
            || inputs.is_empty()
            || inputs.len() > MAX_SELECTIONS
            || maximum_total_delivery_bytes == 0
            || maximum_total_delivery_bytes > MAX_ARTIFACT_TOTAL_BYTES
        {
            return Err("artifact input contract exceeds its selection or delivery envelope");
        }
        let path_bytes = self
            .selections
            .iter()
            .map(|s| s.workflow_path().len() + s.output_path().len())
            .sum::<usize>();
        let path_bytes = inputs.iter().try_fold(path_bytes, |n, input| {
            n.checked_add(input.workflow_path().len())?
                .checked_add(input.output_path().len())?
                .checked_add(input.destination().len())
        });
        if path_bytes.is_none_or(|n| n > 64 * 1024) {
            return Err("combined artifact input/output paths exceed 64 KiB");
        }
        inputs.sort();
        for (index, input) in inputs.iter().enumerate() {
            if !self.selections.iter().any(|output| {
                output.workflow == input.workflow
                    && output.job == input.producer
                    && output.output == input.output
            }) {
                return Err("artifact input producer output must be explicitly captured");
            }
            if inputs[..index].iter().any(|previous| {
                previous.workflow == input.workflow
                    && previous.consumer == input.consumer
                    && paths_overlap(previous.destination(), input.destination())
            }) {
                return Err("artifact input destinations overlap within a consumer");
            }
        }
        self.inputs = inputs;
        self.input_total_bytes = maximum_total_delivery_bytes;
        Ok(self)
    }

    #[must_use]
    pub fn inputs(&self) -> &[TrustedWorkflowArtifactInput] {
        &self.inputs
    }
    #[must_use]
    pub const fn input_total_bytes(&self) -> usize {
        self.input_total_bytes
    }

    pub(super) fn inputs_json(&self) -> String {
        format!(
            "{{\"schema_version\":1,\"namespace_hex\":\"{}\",\"total_delivery_bytes\":{},\"selections\":[{}]}}",
            hex(ARTIFACT_INPUT_NAMESPACE),
            self.input_total_bytes,
            self.inputs
                .iter()
                .map(TrustedWorkflowArtifactInput::to_json)
                .collect::<Vec<_>>()
                .join(","),
        )
    }

    pub(super) fn validate_inputs(
        &self,
        workflow: &[u8],
        plan: &WorkflowPlan,
    ) -> Result<(), TrustedWorkflowFailure> {
        for input in self
            .inputs
            .iter()
            .filter(|input| input.workflow_path() == workflow)
        {
            let Some(consumer) = plan
                .graph()
                .jobs
                .iter()
                .find(|job| job.id == input.consumer)
            else {
                return Err(TrustedWorkflowFailure::InvalidInput(
                    "artifact input consumer job is absent",
                ));
            };
            if !consumer.needs.contains(&input.producer) {
                return Err(TrustedWorkflowFailure::InvalidInput(
                    "artifact input producer must be a direct declared needs dependency",
                ));
            }
        }
        Ok(())
    }
}
fn paths_overlap(a: &[u8], b: &[u8]) -> bool {
    a == b
        || a.strip_prefix(b).is_some_and(|rest| rest.starts_with(b"/"))
        || b.strip_prefix(a).is_some_and(|rest| rest.starts_with(b"/"))
}

/// Immutable source and destination binding for one delivered file.
#[derive(Clone, Debug)]
pub struct TrustedWorkflowArtifactInputReceipt {
    pub producer_job_id: String,
    pub producer_manifest_id: Digest,
    pub output: TrustedWorkflowArtifactOutput,
    /// Full relative workspace path, including the reserved namespace.
    pub destination: Vec<u8>,
}
impl TrustedWorkflowArtifactInputReceipt {
    fn to_json(&self) -> String {
        format!(
            "{{\"producer_job_id_hex\":\"{}\",\"producer_manifest_id_sha256\":\"{}\",\"output\":{},\"destination_path_hex\":\"{}\"}}",
            hex(self.producer_job_id.as_bytes()),
            digest_hex(self.producer_manifest_id),
            self.output.to_json(),
            hex(&self.destination),
        )
    }
}

/// Files verified for one consumer before any of its scripts execute.
/// The report includes this only after its workspace materialized successfully.
#[derive(Clone, Debug)]
pub struct TrustedWorkflowJobArtifactInputs {
    pub job_id: String,
    pub workspace_plan_sha256: [u8; 32],
    pub inputs: Vec<TrustedWorkflowArtifactInputReceipt>,
}
impl TrustedWorkflowJobArtifactInputs {
    pub(in crate::treefs_workspace::trusted_workflow) fn to_json(&self) -> String {
        format!(
            "{{\"job_id_hex\":\"{}\",\"workspace_plan_sha256\":\"{}\",\"inputs\":[{}]}}",
            hex(self.job_id.as_bytes()),
            hex(&self.workspace_plan_sha256),
            self.inputs
                .iter()
                .map(TrustedWorkflowArtifactInputReceipt::to_json)
                .collect::<Vec<_>>()
                .join(","),
        )
    }
}

impl Collector<'_> {
    pub(in crate::treefs_workspace::trusted_workflow) fn observe(&mut self, report: &JobReport) {
        // The durable coordinator invokes this after the original normalized
        // job observation is retained, and before a dependent may open.
        self.completed.insert(report.id.clone(), report.outcome);
    }

    pub(in crate::treefs_workspace::trusted_workflow) fn prepare_inputs<A: GitHashAlgorithm>(
        &self,
        plan: SparseWorkspacePlan<A>,
        source_bytes: usize,
        index: usize,
        job: &WorkflowJob,
        root: &File,
        directory: &Path,
        live: &dyn Fn() -> bool,
    ) -> Result<
        (
            SparseWorkspacePlan<A>,
            Option<TrustedWorkflowJobArtifactInputs>,
        ),
        WorkerFailure,
    > {
        let selected = self
            .session
            .config
            .inputs
            .iter()
            .filter(|input| input.workflow_path() == self.workflow && input.consumer == job.id)
            .collect::<Vec<_>>();
        if selected.is_empty() {
            return Ok((plan, None));
        }
        let refused =
            |detail| WorkerFailure::new(format!("artifact input delivery: {detail}"), false);
        if !live() {
            return Err(refused(
                "request stopped before input preparation".to_owned(),
            ));
        }
        // This newly created directory is owned exclusively by this invocation.
        // Every staged receipt is cleaned on both result paths before
        // responsibility returns to the job scheduler.
        let staging = directory.join(format!(".job-{index:03}-artifact-inputs"));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&staging)
            .map_err(|e| refused(format!("reserve input staging: {e}")))?;
        let result = (|| {
            let op = ArtifactOperation::new(
                self.session.config.maximum_bytes.max(MAX_MANIFEST_BYTES) as u64,
                Duration::from_secs(3600),
                live,
            )
            .map_err(|e| e.to_string())?;
            let mut workspace_remaining =
                SOURCE_LIMITS.max_payload_bytes.saturating_sub(source_bytes);
            let contract = Commitment::of_bytes(self.session.config.to_json().as_bytes());
            let mut supplements = Vec::new();
            let mut receipts = Vec::new();
            let mut manifests = BTreeSet::new();
            for input in selected {
                if !live() {
                    return Err("request stopped during input preparation".to_owned());
                }
                if !job.needs.contains(&input.producer)
                    || self.completed.get(&input.producer) != Some(&JobOutcome::Succeeded)
                {
                    return Err(
                        "producer has no completed successful dependency observation".into(),
                    );
                }
                let producer = self
                    .jobs
                    .iter()
                    .find(|saved| saved.job_id == input.producer)
                    .ok_or_else(|| "producer has no completed artifact custody".to_owned())?;
                let output = producer
                    .outputs
                    .iter()
                    .find(|output| output.path == input.output_path())
                    .ok_or_else(|| {
                        "producer output is not in its exact custody receipt".to_owned()
                    })?;
                if manifests.insert(input.producer.clone()) {
                    let manifest = self.manifest(&producer.job_id, &producer.outputs);
                    if manifest.len() > MAX_MANIFEST_BYTES {
                        return Err("producing provenance exceeds its envelope".into());
                    }
                    let expected = self.identity(
                        manifest.as_bytes(),
                        ArtifactPayloadKind::Provenance,
                        "application/json",
                    );
                    if *expected.artifact_id() != producer.manifest_id {
                        return Err(
                            "producing manifest does not bind this attempt and output set".into(),
                        );
                    }
                    let actual = self
                        .session
                        .store
                        .inspect(&producer.manifest_id, &op)
                        .map_err(|e| format!("verify producer provenance: {e}"))?;
                    if actual != expected {
                        return Err("producing manifest identity differs from this attempt".into());
                    }
                }
                if output.payload_bytes
                    > self
                        .session
                        .config
                        .maximum_bytes
                        .min(SOURCE_LIMITS.max_entry_bytes)
                {
                    return Err("producer output exceeds the selected file envelope".into());
                }
                workspace_remaining = workspace_remaining
                    .checked_sub(output.payload_bytes)
                    .ok_or_else(|| {
                        "artifact inputs exceed the consumer workspace envelope".to_owned()
                    })?;
                // Charge attempted disclosure once, even if a later operation
                // refuses. A retry cannot replenish an invocation's allowance.
                self.session.charge_input(output.payload_bytes)?;
                let (actual, body) = self
                    .session
                    .store
                    .read_payload(&output.artifact_id, &op)
                    .map_err(|e| format!("verify producer payload: {e}"))?;
                let expected = ArtifactIdentity::new(
                    output.payload_sha256,
                    output.payload_bytes as u64,
                    MediaType::parse("application/octet-stream").expect("static media type"),
                    ArtifactPayloadKind::CiArtifact,
                    None,
                    None,
                    self.source_rcr,
                    RetentionProfile::HotEphemeral { ttl_seconds: 86400 },
                );
                if actual != expected || *actual.artifact_id() != output.artifact_id {
                    return Err("producer payload identity differs from its provenance".into());
                }
                let mut destination = ARTIFACT_INPUT_NAMESPACE.to_vec();
                destination.push(b'/');
                destination.extend_from_slice(input.destination());
                let receipt = TrustedWorkflowArtifactInputReceipt {
                    producer_job_id: producer.job_id.clone(),
                    producer_manifest_id: producer.manifest_id,
                    output: output.clone(),
                    destination,
                };
                let binding = format!(
                    "{}:{}:{}",
                    hex(contract.digest().bytes().as_bytes()),
                    hex(job.id.as_bytes()),
                    receipt.to_json()
                );
                let supplement = JobInput::new(
                    input.destination(),
                    body,
                    if output.executable {
                        FileMode::Executable
                    } else {
                        FileMode::Regular
                    },
                    Commitment::of_bytes(binding.as_bytes()),
                )
                .map_err(|e| e.to_string())?;
                supplements.push(supplement);
                receipts.push(receipt);
            }
            let plan = plan
                .with_job_inputs(supplements)
                .map_err(|e| e.to_string())?;
            let receipt = TrustedWorkflowJobArtifactInputs {
                job_id: job.id.clone(),
                workspace_plan_sha256: plan
                    .reservation()
                    .plan
                    .digest()
                    .bytes()
                    .as_bytes()
                    .try_into()
                    .map_err(|_| "workspace plan digest width".to_owned())?,
                inputs: receipts,
            };
            let record = format!(
                "{{\"type\":\"trusted_workflow_artifact_inputs\",\"schema_version\":1,\"state\":\"verified_inputs_prepared\",\"attempt_sha256\":\"{}\",\"consumer\":{}}}",
                hex(&self.attempt_sha256),
                receipt.to_json(),
            );
            if record.len() > MAX_MANIFEST_BYTES {
                return Err("artifact input receipt exceeds 1 MiB".into());
            }
            let mut stages = Vec::new();
            stage_bytes(
                &staging,
                "receipt.pending",
                record.as_bytes(),
                &mut stages,
                live,
            )?;
            if !live() {
                return Err("request stopped before input receipt publication".into());
            }
            fs::hard_link(
                staging.join("receipt.pending"),
                directory.join(format!("job-{index:03}-artifact-inputs.json")),
            )
            .and_then(|()| root.sync_all())
            .map_err(|e| format!("input receipt durability: {e}"))?;
            if !live() {
                return Err("request stopped after input receipt publication".into());
            }
            Ok((plan, Some(receipt)))
        })();
        // This directory was created above, never adopted from another attempt.
        // Cleanup is unconditional and non-cancellable, including after a stop.
        if let Err(error) = fs::remove_dir_all(&staging).and_then(|()| root.sync_all()) {
            return Err(WorkerFailure::new(
                format!(
                    "artifact input staging retained at {}: {error}",
                    staging.display()
                ),
                true,
            ));
        }
        result.map_err(refused)
    }
}
