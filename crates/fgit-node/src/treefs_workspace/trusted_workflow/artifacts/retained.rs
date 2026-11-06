//! Explicit inputs from immutable custody in a previous attempt. A manifest
//! proves the selected bytes and their provenance, never a successful check.

use super::{
    ArtifactIdentity, ArtifactOperation, ArtifactPayloadKind, Collector, Digest, DigestAlgorithm,
    DigestBytes, Duration, MAX_ARTIFACT_TOTAL_BYTES, MAX_MANIFEST_BYTES, MAX_SELECTIONS, MediaType,
    PathBuf, RetentionProfile, TreePath, TrustedWorkflowArtifactConfig,
    TrustedWorkflowArtifactInputReceipt, TrustedWorkflowArtifactOutput,
    TrustedWorkflowArtifactSelection, TrustedWorkflowFailure, WorkflowPlan, digest, digest_hex,
    hex,
};
use fgit_schema::json::{self, Object, Value};
use fgit_types::{GitHashAlgorithm, GitOid, RepositoryCommitId};

/// An operator-selected immutable output, copied into one fresh consumer.
/// Both the original provenance object and selected payload identity are pinned.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct TrustedWorkflowRetainedArtifactInput {
    workflow: TreePath,
    consumer: String,
    manifest_id: Digest,
    artifact_id: Digest,
    output: TreePath,
    destination: TreePath,
}
impl TrustedWorkflowRetainedArtifactInput {
    pub fn new(
        workflow: &[u8],
        consumer_job: &str,
        producer_manifest_id: Digest,
        artifact_id: Digest,
        output: &[u8],
        destination: &[u8],
    ) -> Result<Self, &'static str> {
        for id in [producer_manifest_id, artifact_id] {
            if id.algorithm() != DigestAlgorithm::Sha256.id() || id.bytes().as_bytes().len() != 32 {
                return Err("retained artifact identities must be SHA-256");
            }
        }
        let selected = TrustedWorkflowArtifactSelection::new(workflow, consumer_job, output)?;
        let target = TrustedWorkflowArtifactSelection::new(workflow, consumer_job, destination)?;
        if destination.len() > 4000 {
            return Err("retained artifact destination exceeds its namespace path limit");
        }
        Ok(Self {
            workflow: selected.workflow,
            consumer: consumer_job.to_owned(),
            manifest_id: producer_manifest_id,
            artifact_id,
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
    pub const fn producer_manifest_id(&self) -> Digest {
        self.manifest_id
    }
    #[must_use]
    pub const fn artifact_id(&self) -> Digest {
        self.artifact_id
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
            "{{\"workflow_path_hex\":\"{}\",\"consumer_job_id_hex\":\"{}\",\"producer_manifest_id_sha256\":\"{}\",\"artifact_id_sha256\":\"{}\",\"output_path_hex\":\"{}\",\"destination_hex\":\"{}\"}}",
            hex(self.workflow_path()),
            hex(self.consumer.as_bytes()),
            digest_hex(self.manifest_id),
            digest_hex(self.artifact_id),
            hex(self.output_path()),
            hex(self.destination()),
        )
    }
}

impl TrustedWorkflowArtifactConfig {
    /// Retain explicit prior outputs as inputs. Capturing new outputs or logs is
    /// optional; with_inputs can additionally select same-attempt dependencies.
    /// The delivery allowance is shared by both kinds of input.
    pub fn new_with_retained_inputs(
        root: PathBuf,
        selections: Vec<TrustedWorkflowArtifactSelection>,
        maximum_bytes: usize,
        total_bytes: usize,
        capture_logs: bool,
        mut retained_inputs: Vec<TrustedWorkflowRetainedArtifactInput>,
        maximum_total_delivery_bytes: usize,
    ) -> Result<Self, &'static str> {
        if retained_inputs.is_empty()
            || retained_inputs.len() > MAX_SELECTIONS
            || maximum_total_delivery_bytes == 0
            || maximum_total_delivery_bytes > MAX_ARTIFACT_TOTAL_BYTES
        {
            return Err(
                "retained artifact input contract exceeds its selection or delivery envelope",
            );
        }
        let mut config = Self::build(
            root,
            selections,
            maximum_bytes,
            total_bytes,
            capture_logs,
            true,
        )?;
        retained_inputs.sort();
        config.retained_inputs = retained_inputs;
        config.input_total_bytes = maximum_total_delivery_bytes;
        config.validate_delivery_contract()?;
        Ok(config)
    }
    #[must_use]
    pub fn retained_inputs(&self) -> &[TrustedWorkflowRetainedArtifactInput] {
        &self.retained_inputs
    }
    pub(super) fn retained_inputs_json(&self) -> String {
        format!(
            "{{\"schema_version\":1,\"namespace_hex\":\"{}\",\"total_delivery_bytes\":{},\"producer_success_required\":false,\"selections\":[{}]}}",
            hex(super::inputs::ARTIFACT_INPUT_NAMESPACE),
            self.input_total_bytes,
            self.retained_inputs
                .iter()
                .map(TrustedWorkflowRetainedArtifactInput::to_json)
                .collect::<Vec<_>>()
                .join(","),
        )
    }
    pub(super) fn validate_delivery_contract(&self) -> Result<(), &'static str> {
        if self.inputs.len() + self.retained_inputs.len() > MAX_SELECTIONS {
            return Err("combined artifact inputs exceed 64 selections");
        }
        let paths =
            self.selections
                .iter()
                .map(|s| s.workflow_path().len() + s.output_path().len())
                .chain(self.inputs.iter().map(|s| {
                    s.workflow_path().len() + s.output_path().len() + s.destination().len()
                }))
                .chain(self.retained_inputs.iter().map(|s| {
                    s.workflow_path().len() + s.output_path().len() + s.destination().len()
                }))
                .sum::<usize>();
        if paths > 64 * 1024 {
            return Err("combined artifact input/output paths exceed 64 KiB");
        }
        for (index, input) in self.retained_inputs.iter().enumerate() {
            let overlap = |workflow: &[u8], consumer: &str, destination: &[u8]| {
                workflow == input.workflow_path()
                    && consumer == input.consumer
                    && super::inputs::paths_overlap(destination, input.destination())
            };
            if self.retained_inputs[..index].iter().any(|old| {
                overlap(
                    old.workflow_path(),
                    old.consumer_job_id(),
                    old.destination(),
                )
            }) || self.inputs.iter().any(|old| {
                overlap(
                    old.workflow_path(),
                    old.consumer_job_id(),
                    old.destination(),
                )
            }) {
                return Err("artifact input destinations overlap within a consumer");
            }
        }
        Ok(())
    }
    pub(super) fn validate_retained_inputs(
        &self,
        workflow: &[u8],
        plan: &WorkflowPlan,
    ) -> Result<(), TrustedWorkflowFailure> {
        if self
            .retained_inputs
            .iter()
            .filter(|s| s.workflow_path() == workflow)
            .any(|s| !plan.graph().jobs.iter().any(|job| job.id == s.consumer))
        {
            return Err(TrustedWorkflowFailure::InvalidInput(
                "retained artifact consumer job is absent",
            ));
        }
        Ok(())
    }
}

/// Original custody selected by a local operator; this is not evidence that the
/// producer succeeded or that the consumer can skip its own execution.
#[derive(Clone, Debug)]
pub struct TrustedWorkflowRetainedArtifactProvenance {
    pub run_id: [u8; 16],
    pub attempt_sha256: [u8; 32],
    pub workflow_path: Vec<u8>,
    pub source_rcr: String,
    pub executed_commit: GitOid,
}
impl TrustedWorkflowRetainedArtifactProvenance {
    pub(super) fn to_json(&self) -> String {
        format!(
            "{{\"source\":\"retained_artifact\",\"run_id\":\"{}\",\"attempt_sha256\":\"{}\",\"workflow_path_hex\":\"{}\",\"source_rcr\":\"{}\",\"executed_commit\":\"{}\",\"producer_success_asserted\":false}}",
            hex(&self.run_id),
            hex(&self.attempt_sha256),
            hex(&self.workflow_path),
            self.source_rcr,
            self.executed_commit,
        )
    }
}

impl Collector<'_> {
    pub(super) fn retained_input(
        &self,
        input: &TrustedWorkflowRetainedArtifactInput,
        live: &dyn Fn() -> bool,
    ) -> Result<TrustedWorkflowArtifactInputReceipt, String> {
        let operation =
            ArtifactOperation::new(MAX_MANIFEST_BYTES as u64, Duration::from_secs(3600), live)
                .map_err(|e| e.to_string())?;
        let (identity, bytes) = self
            .session
            .store
            .read_payload(&input.manifest_id, &operation)
            .map_err(|e| format!("verify retained producer manifest: {e}"))?;
        let parsed = json::parse_with(
            &bytes,
            json::Limits {
                input: MAX_MANIFEST_BYTES,
                depth: 16,
                nodes: 32_768,
                items: 2048,
                string: 128 * 1024,
            },
        )
        .map_err(str::to_owned)?;
        let fields = parsed
            .object()
            .ok_or("retained manifest must be an object")?;
        equal(fields, "type", "trusted_workflow_artifact_provenance")?;
        if fields.get("schema_version").and_then(Value::unsigned) != Some(1)
            || fields.get("build_input_capsule_id") != Some(&Value::Null)
            || fields.get("check_receipt_id") != Some(&Value::Null)
            || fields.get("cache_reuse_authorized") != Some(&Value::Bool(false))
            || fields.get("job_success_asserted") != Some(&Value::Bool(false))
        {
            return Err("unsupported retained manifest profile".into());
        }
        let producer = fields
            .get("producer")
            .and_then(Value::object)
            .ok_or("retained producer missing")?;
        let scope = self.session.store.scope();
        equal(producer, "tenant_id", &scope.tenant().to_string())?;
        equal(producer, "repository_id", &scope.repository().to_string())?;
        equal(
            producer,
            "repository_incarnation",
            &scope.incarnation().to_string(),
        )?;
        let contract = producer
            .get("artifact_contract")
            .and_then(Value::object)
            .ok_or("retained capture contract missing")?;
        equal(contract, "trust_domain", scope.trust_domain())?;
        let source_rcr = text(producer, "source_rcr")?;
        let source = source_identity(source_rcr)?;
        let expected = ArtifactIdentity::new(
            digest(&bytes),
            bytes.len() as u64,
            MediaType::parse("application/json").expect("static media"),
            ArtifactPayloadKind::Provenance,
            None,
            None,
            source,
            RetentionProfile::HotEphemeral { ttl_seconds: 86400 },
        );
        if identity != expected || *identity.artifact_id() != input.manifest_id {
            return Err("retained manifest metadata differs from its producer".into());
        }
        let job_bytes = unhex(text(fields, "job_id_hex")?, 256)?;
        let job = std::str::from_utf8(&job_bytes).map_err(|_| "invalid retained producer job")?;
        let workflow = unhex(text(producer, "workflow_path_hex")?, 4096)?;
        TrustedWorkflowArtifactSelection::new(&workflow, job, input.output_path())?;
        let format = match text(producer, "object_format")? {
            "sha1" => GitHashAlgorithm::Sha1,
            "sha256" => GitHashAlgorithm::Sha256,
            _ => return Err("unsupported retained source object format".into()),
        };
        if format != self.object_format {
            return Err(
                "retained producer object format differs from repository incarnation".into(),
            );
        }
        let provenance = TrustedWorkflowRetainedArtifactProvenance {
            run_id: unhex(text(producer, "run_id")?, 16)?
                .try_into()
                .map_err(|_| "retained run ID width")?,
            attempt_sha256: unhex(text(fields, "attempt_sha256")?, 32)?
                .try_into()
                .map_err(|_| "retained attempt digest width")?,
            workflow_path: workflow,
            source_rcr: source_rcr.to_owned(),
            executed_commit: GitOid::from_hex(format, text(producer, "executed_commit")?)
                .map_err(|_| "invalid retained executed commit")?,
        };
        if provenance.run_id == [0; 16] || provenance.executed_commit.is_zero() {
            return Err("retained producer has a null run or commit identity".into());
        }
        let Some(Value::Array(captured)) = contract.get("selections") else {
            return Err("retained producer capture selections missing".into());
        };
        if captured.len() > MAX_SELECTIONS
            || !captured.iter().any(|selection| {
                selection.object().is_some_and(|selection| {
                    selection.get("workflow_path_hex").and_then(Value::text)
                        == Some(hex(&provenance.workflow_path).as_str())
                        && selection.get("job_id_hex").and_then(Value::text)
                            == Some(hex(job.as_bytes()).as_str())
                        && selection.get("output_path_hex").and_then(Value::text)
                            == Some(hex(input.output_path()).as_str())
                })
            })
        {
            return Err(
                "retained output was not selected by the producing capture contract".into(),
            );
        }
        for field in ["workflow_source_sha256", "workflow_graph_sha256"] {
            parse_digest(text(fields, field)?)?;
        }
        let Some(Value::Array(outputs)) = fields.get("outputs") else {
            return Err("retained outputs missing".into());
        };
        if outputs.is_empty() || outputs.len() > MAX_SELECTIONS {
            return Err("retained output count exceeds profile".into());
        }
        let mut chosen = None;
        let mut paths = std::collections::BTreeSet::new();
        for value in outputs {
            let output = value.object().ok_or("retained output must be an object")?;
            if output.len() != 5 {
                return Err("unsupported retained output fields".into());
            }
            let path = unhex(text(output, "path_hex")?, 4096)?;
            TrustedWorkflowArtifactSelection::new(&provenance.workflow_path, job, &path)?;
            if !paths.insert(path.clone()) {
                return Err("duplicate retained output path".into());
            }
            let artifact_id = parse_digest(text(output, "artifact_id_sha256")?)?;
            let payload_sha256 = parse_digest(text(output, "payload_sha256")?)?;
            let payload_bytes = output
                .get("payload_bytes")
                .and_then(Value::unsigned)
                .and_then(|n| usize::try_from(n).ok())
                .ok_or("retained payload length missing")?;
            let Some(Value::Bool(executable)) = output.get("executable") else {
                return Err("retained output mode missing".into());
            };
            let expected = payload_identity(payload_sha256, payload_bytes, source);
            if *expected.artifact_id() != artifact_id {
                return Err("retained output identity differs from its metadata".into());
            }
            if path == input.output_path() {
                if artifact_id != input.artifact_id {
                    return Err(
                        "selected retained artifact differs from the original output".into(),
                    );
                }
                chosen = Some(TrustedWorkflowArtifactOutput {
                    path,
                    artifact_id,
                    payload_sha256,
                    payload_bytes,
                    executable: *executable,
                });
            }
        }
        let output = chosen.ok_or("selected output is absent from retained manifest")?;
        let mut destination = super::inputs::ARTIFACT_INPUT_NAMESPACE.to_vec();
        destination.push(b'/');
        destination.extend_from_slice(input.destination());
        Ok(TrustedWorkflowArtifactInputReceipt {
            producer_job_id: job.to_owned(),
            producer_manifest_id: input.manifest_id,
            output,
            destination,
            retained_producer: Some(provenance),
        })
    }
}

pub(super) fn payload_identity(
    payload: Digest,
    bytes: usize,
    source_rcr: Option<Digest>,
) -> ArtifactIdentity {
    ArtifactIdentity::new(
        payload,
        bytes as u64,
        MediaType::parse("application/octet-stream").expect("static media"),
        ArtifactPayloadKind::CiArtifact,
        None,
        None,
        source_rcr,
        RetentionProfile::HotEphemeral { ttl_seconds: 86400 },
    )
}
pub(super) fn source_identity(value: &str) -> Result<Option<Digest>, String> {
    let (prefix, digest) = value
        .rsplit_once('/')
        .ok_or("invalid retained source RCR")?;
    let (prefix, algorithm) = prefix
        .rsplit_once('/')
        .ok_or("invalid retained source RCR algorithm")?;
    let (domain, version) = prefix
        .rsplit_once('/')
        .ok_or("invalid retained source RCR version")?;
    if domain != RepositoryCommitId::DOMAIN {
        return Err("retained source identity is not an RCR".into());
    }
    let version = version
        .strip_prefix('v')
        .ok_or("invalid retained RCR codec")?;
    let (major, minor) = version
        .split_once('.')
        .ok_or("invalid retained RCR codec")?;
    for part in [major, minor] {
        if json::decimal(part).ok().is_none_or(|n| n > u16::MAX as u64) {
            return Err("invalid retained RCR codec".into());
        }
    }
    let code = json::decimal(
        algorithm
            .strip_prefix("alg:")
            .ok_or("invalid retained RCR algorithm")?,
    )?;
    if code == 0 || code > u16::MAX as u64 {
        return Err("invalid retained RCR algorithm".into());
    }
    let bytes = unhex(digest, 64)?;
    if code == u64::from(DigestAlgorithm::Sha256.id().code_point()) {
        if bytes.len() != 32 {
            return Err("invalid retained RCR digest width".into());
        }
        Ok(Some(Digest::new(
            DigestAlgorithm::Sha256.id(),
            DigestBytes::try_new(&bytes).map_err(|_| "retained RCR width")?,
        )))
    } else {
        Ok(None)
    }
}
fn text<'a>(fields: &'a Object, field: &str) -> Result<&'a str, String> {
    fields
        .get(field)
        .and_then(Value::text)
        .ok_or_else(|| format!("retained manifest field missing: {field}"))
}
fn equal(fields: &Object, field: &str, expected: &str) -> Result<(), String> {
    if text(fields, field)? == expected {
        Ok(())
    } else {
        Err(format!("retained manifest binding differs: {field}"))
    }
}
fn parse_digest(value: &str) -> Result<Digest, String> {
    let bytes = unhex(value, 32)?;
    if bytes.len() != 32 {
        return Err("retained digest width".into());
    }
    Ok(Digest::new(
        DigestAlgorithm::Sha256.id(),
        DigestBytes::try_new(&bytes).map_err(|_| "retained digest width")?,
    ))
}
fn unhex(value: &str, maximum: usize) -> Result<Vec<u8>, String> {
    if value.is_empty() || value.len() > maximum * 2 || !value.len().is_multiple_of(2) {
        return Err("invalid retained hex width".into());
    }
    let digit = |c| match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err("noncanonical retained hex".to_owned()),
    };
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok((digit(pair[0])? << 4) | digit(pair[1])?))
        .collect()
}

#[cfg(test)]
mod tests;
