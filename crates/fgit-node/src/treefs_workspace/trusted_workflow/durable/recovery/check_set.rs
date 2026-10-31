//! Snapshot-bound whole-run publication through the existing per-check admission.
//! Local custody supplies exact evidence, never publisher authority or permission.
use super::TrustedWorkflowFailure;
use super::inspect::{checked_pin, checked_scope, failure};
use crate::{LoopbackReceiveSession, NodeRequestContext, OneNode};
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_crypto::{Digest, DigestHasher, Sha256Hasher, sha256_digest};
use fgit_forge::event::workflow_check::{
    MAX_CHECK_EVIDENCE_BYTES, NativeWorkflowCheck, WorkflowCheckConclusion,
};
use fgit_runner::coordinator::{CheckRunStatus, CoordinatorExecutionProfile};
use fgit_types::{
    DecisionOutcome, PrincipalId, RefName, RepositoryId, RepositoryIncarnationId, TenantId, TxId,
};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

const MAX_JOBS: usize = 128;
const MAX_EVIDENCE: usize = 16 * 1024 * 1024;
const MAX_BATCHES: usize = 1024;
const MAX_METADATA: usize = 8 * 1024 * 1024;

#[derive(Debug)]
struct Check {
    batch: String,
    fact: usize,
    key: IdempotencyKey,
    observation: NativeWorkflowCheck,
}

/// Immutable, fully verified selected jobs. Preparing it admits no check.
/// The journal lock is released before canonical admission. Retain the original
/// journal ID and exact snapshot pin to reconstruct this same set on restart.
#[derive(Debug)]
pub struct TrustedWorkflowCheckSet {
    tenant: TenantId,
    repository: RepositoryId,
    incarnation: RepositoryIncarnationId,
    publisher: PrincipalId,
    journal: String,
    snapshot: String,
    identity: [u8; 32],
    checks: Vec<Check>,
    nonterminal_facts: usize,
}
impl TrustedWorkflowCheckSet {
    pub const fn len(&self) -> usize {
        self.checks.len()
    }
    pub(crate) fn evidence_bytes(&self) -> usize {
        self.checks
            .iter()
            .map(|c| c.observation.record.evidence.len())
            .sum()
    }
    pub(crate) fn targets_commit(&self, commit: fgit_types::GitOid) -> bool {
        self.checks
            .iter()
            .all(|c| c.observation.record.source_commit == commit)
    }
    pub const fn is_empty(&self) -> bool {
        self.checks.is_empty()
    }
    pub const fn identity(&self) -> [u8; 32] {
        self.identity
    }
    /// This manifest excludes evidence bodies and cannot be submitted as a check.
    pub fn to_json(&self) -> String {
        let checks = self.checks.iter().enumerate().map(|(i, c)| format!(
            "{{\"index\":{i},\"batch_sha256\":{},\"fact_index\":{},\"check_id\":{},\"job\":{},\"source_ref_hex\":{},\"source_commit\":{},\"conclusion\":{},\"idempotency_key_hex\":{},\"evidence_sha256\":{},\"evidence_bytes\":{}}}",
            quote(&c.batch), c.fact, quote(&c.observation.id().to_string()), quote(&c.observation.record.job),
            quote(&hex(c.observation.record.source_ref.as_bytes())), quote(&c.observation.record.source_commit.to_string()),
            quote(conclusion(c.observation.record.conclusion)), quote(&hex(c.key.as_bytes())),
            quote(&hex(&sha256_digest(&c.observation.record.evidence))), c.observation.record.evidence.len(),
        )).collect::<Vec<_>>().join(",");
        format!(
            "{{\"type\":\"workflow_check_set\",\"schema_version\":1,\"set_sha256\":{},\"journal_id\":{},\"snapshot\":{},\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},\"principal_id\":{},\"selected_checks\":{},\"historical_nonterminal_facts\":{},\"execution_complete\":null,\"checks\":[{checks}]}}",
            quote(&hex(&self.identity)),
            quote(&self.journal),
            quote(&self.snapshot),
            quote(&self.tenant.to_string()),
            quote(&self.repository.to_string()),
            quote(&self.incarnation.to_string()),
            quote(&self.publisher.to_string()),
            self.checks.len(),
            self.nonterminal_facts
        )
    }
}

/// A real historical terminal decision from ordinary canonical admission.
#[derive(Debug)]
pub struct TrustedWorkflowCheckDecision {
    pub index: usize,
    pub tx_id: TxId,
    pub terminal: TerminalOutcome,
    check_id: String,
    job: String,
    conclusion: &'static str,
}
impl TrustedWorkflowCheckDecision {
    pub fn to_json(&self) -> String {
        let (committed, rcr, refusal) = match self.terminal.outcome {
            DecisionOutcome::Committed {
                repository_commit_id,
            } => (
                true,
                quote(&repository_commit_id.to_string()),
                "null".into(),
            ),
            DecisionOutcome::Refused { code, .. } => {
                (false, "null".into(), quote(&format!("{code:?}")))
            }
        };
        format!(
            "{{\"type\":\"workflow_check_set_decision\",\"index\":{},\"check_id\":{},\"job\":{},\"conclusion\":{},\"tx_id\":{},\"decision_sequence\":{},\"command_committed\":{committed},\"repository_commit_id\":{rcr},\"refusal_code\":{refusal},\"historical_outcome\":true,\"execution_retried\":false,\"refs_changed\":false}}",
            self.index,
            quote(&self.check_id),
            quote(&self.job),
            quote(self.conclusion),
            quote(&self.tx_id.to_string()),
            quote(&self.terminal.decision_sequence.get().to_string())
        )
    }
}

/// Partial decisions survive cancellation, unavailable admission, and a failed
/// receipt consumer. Retrying the same set resolves already-decided child keys.
#[derive(Debug)]
pub struct TrustedWorkflowCheckSetResult {
    pub decisions: Vec<TrustedWorkflowCheckDecision>,
    pub error: Option<String>,
    selected: usize,
    identity: [u8; 32],
}
impl TrustedWorkflowCheckSetResult {
    pub fn all_committed(&self) -> bool {
        self.error.is_none()
            && self.decisions.len() == self.selected
            && self
                .decisions
                .iter()
                .all(|d| matches!(d.terminal.outcome, DecisionOutcome::Committed { .. }))
    }
    pub fn to_json(&self) -> String {
        format!(
            "{{\"type\":\"workflow_check_set_result\",\"schema_version\":1,\"set_sha256\":{},\"selected_checks\":{},\"decided_checks\":{},\"all_committed\":{},\"error\":{},\"execution_retried\":false,\"journal_acknowledged\":false,\"refs_changed\":false,\"historical_outcomes\":true}}",
            quote(&hex(&self.identity)),
            self.selected,
            self.decisions.len(),
            self.all_committed(),
            self.error
                .as_ref()
                .map_or_else(|| "null".into(), |e| quote(e))
        )
    }
}

impl OneNode {
    /// Verify ALL completed facts in one exact saved snapshot before any check
    /// admission. `limits` bounds (unique jobs, aggregate evidence bytes), up to
    /// (128, 16 MiB). The history scan also has 1024-batch/8-MiB metadata ceilings.
    /// Queued/in-progress facts are counted, not promoted. A prefix can contain
    /// useful completed jobs without proving the workflow finished or drained.
    /// This is an explicitly authorized whole-repository local-owner API; the
    /// supplied publisher must come from that caller, never from workflow text.
    pub fn prepare_trusted_workflow_check_set(
        &self,
        request: &NodeRequestContext,
        directory: &Path,
        journal_id: Digest,
        snapshot: (u64, Digest),
        publisher: PrincipalId,
        source_ref: RefName,
        limits: (usize, usize),
    ) -> Result<TrustedWorkflowCheckSet, TrustedWorkflowFailure> {
        let invalid = TrustedWorkflowFailure::InvalidInput;
        if limits.0 == 0 || limits.0 > MAX_JOBS || limits.1 == 0 || limits.1 > MAX_EVIDENCE {
            return Err(invalid("invalid saved check-set limits"));
        }
        if !source_ref.as_bytes().starts_with(b"refs/heads/") || source_ref.as_bytes().len() > 4096
        {
            return Err(invalid(
                "saved check set requires a bounded reporting branch",
            ));
        }
        let live = || request.checkpoint_is_live();
        let scope = checked_scope((self.tenant_id(), self.repository_id(), journal_id))?;
        let pin = checked_pin(snapshot)?;
        let mut journal = Self::open_trusted_workflow_journal(directory, scope, Some(pin), &live)?;
        if journal.pin() != pin {
            return Err(invalid("saved check-set snapshot changed"));
        }
        if journal.retained_batches() > MAX_BATCHES {
            return Err(invalid("saved check-set batch limit exceeded"));
        }
        let mut checks: Vec<Check> = Vec::new();
        let mut identities = BTreeMap::new();
        let mut after = None;
        let mut metadata_left = MAX_METADATA;
        let mut evidence_left = limits.1;
        let mut nonterminal_facts = 0;
        let mut binding = None;
        loop {
            if metadata_left == 0 {
                return Err(invalid("saved check-set metadata limit exceeded"));
            }
            let page = journal
                .read_history(Some(pin), after, 64, metadata_left, &live)
                .map_err(|e| failure(directory, e))?;
            for entry in page.entries() {
                let batch = entry.batch();
                metadata_left = metadata_left
                    .checked_sub(
                        batch.body().len() + usize::from(entry.delivery_receipt().is_some()) * 32,
                    )
                    .ok_or_else(|| invalid("saved check-set metadata limit exceeded"))?;
                if !matches!(
                    batch.execution_profile(),
                    CoordinatorExecutionProfile::TrustedWorkflow { .. }
                ) {
                    return Err(invalid(
                        "saved check set requires trusted-workflow evidence",
                    ));
                }
                let coordinates = (
                    batch.run_id(),
                    batch.attempt_id(),
                    batch.source_commit(),
                    batch.graph_commitment(),
                );
                if binding.as_ref().is_some_and(|b| *b != coordinates) {
                    return Err(invalid("saved check set spans different executions"));
                }
                binding = Some(coordinates);
                if batch.source_commit().algorithm() != self.object_format() {
                    return Err(invalid("saved check-set object format mismatch"));
                }
                for (fact_index, fact) in batch.facts().iter().enumerate() {
                    if fact.status != CheckRunStatus::Completed {
                        nonterminal_facts += 1;
                        continue;
                    }
                    if checks.len() >= limits.0 || evidence_left == 0 {
                        return Err(invalid("saved check-set job or evidence limit exceeded"));
                    }
                    // This existing reader enforces the evidence length BEFORE allocation.
                    journal
                        .read_trusted_job(
                            pin,
                            batch.id(),
                            fact_index,
                            evidence_left.min(MAX_CHECK_EVIDENCE_BYTES),
                            &live,
                        )
                        .map_err(|e| failure(directory, e))?;
                    let evidence = journal
                        .read_evidence(
                            fact.receipt_commitment
                                .ok_or_else(|| invalid("completed fact lacks evidence"))?,
                        )
                        .map_err(|e| failure(directory, e))?;
                    let record = Self::workflow_check_record_from_batch(
                        source_ref.clone(),
                        batch,
                        fact_index,
                        &evidence,
                        &live,
                    )
                    .map_err(|e| failure(directory, e))?;
                    let observation = NativeWorkflowCheck {
                        actor: publisher,
                        record,
                    };
                    // A duplicate completion is never used to select a different winner.
                    if identities.insert(observation.id(), checks.len()).is_some() {
                        return Err(invalid("duplicate completed check identity in saved set"));
                    }
                    evidence_left -= observation.record.evidence.len();
                    let key = child_key(
                        self.tenant_id(),
                        self.repository_id(),
                        self.repository_incarnation_id(),
                        &observation,
                    )?;
                    checks.push(Check {
                        batch: hex(batch.id().digest().bytes().as_bytes()),
                        fact: fact_index,
                        key,
                        observation,
                    });
                }
            }
            after = page.next_after();
            if after.is_none() {
                break;
            }
        }
        if !live() {
            return Err(invalid("saved check-set preparation cancelled"));
        }
        let mut set = TrustedWorkflowCheckSet {
            tenant: self.tenant_id(),
            repository: self.repository_id(),
            incarnation: self.repository_incarnation_id(),
            publisher,
            journal: hex(journal_id.bytes().as_bytes()),
            snapshot: format!(
                "{}:{}",
                pin.byte_len(),
                hex(pin.tail().digest().bytes().as_bytes())
            ),
            identity: [0; 32],
            checks,
            nonterminal_facts,
        };
        let mut manifest = Sha256Hasher::new();
        for part in [
            b"frankengit/workflow-check-set/v1".as_slice(),
            set.tenant.as_bytes(),
            set.repository.as_bytes(),
            set.incarnation.as_bytes(),
            set.publisher.as_bytes(),
            set.journal.as_bytes(),
            set.snapshot.as_bytes(),
            source_ref.as_bytes(),
        ] {
            manifest.update(&(part.len() as u64).to_be_bytes());
            manifest.update(part);
        }
        manifest.update(&(set.checks.len() as u64).to_be_bytes());
        for check in &set.checks {
            for part in [
                check.batch.as_bytes(),
                &(check.fact as u64).to_be_bytes(),
                check.key.as_bytes(),
                &sha256_digest(&check.observation.record.evidence),
            ] {
                manifest.update(&(part.len() as u64).to_be_bytes());
                manifest.update(part);
            }
        }
        set.identity = manifest.finish();
        Ok(set)
    }

    /// Publish verified jobs serially with their deterministic original child
    /// keys. An observer runs AFTER each real decision; its failure stops later
    /// admission without discarding the already-known terminal result. The set
    /// is not atomic: each check and its outbox effect are one ordinary RCR.
    pub async fn publish_trusted_workflow_check_set_in(
        &self,
        request: &NodeRequestContext,
        set: &TrustedWorkflowCheckSet,
        mut observe: impl FnMut(&TrustedWorkflowCheckDecision) -> Result<(), String>,
    ) -> TrustedWorkflowCheckSetResult {
        let mut result = TrustedWorkflowCheckSetResult {
            decisions: Vec::new(),
            error: None,
            selected: set.len(),
            identity: set.identity,
        };
        if (set.tenant, set.repository, set.incarnation)
            != (
                self.tenant_id(),
                self.repository_id(),
                self.repository_incarnation_id(),
            )
        {
            result.error = Some("saved check-set repository incarnation mismatch".into());
            return result;
        }
        for (index, check) in set.checks.iter().enumerate() {
            if !request.checkpoint_is_live() {
                result.error = Some(
                    "publication stopped before next check; preserve the original set and keys"
                        .into(),
                );
                break;
            }
            let session = LoopbackReceiveSession::authenticated(set.publisher, check.key.clone());
            let (tx_id, terminal) = match self
                .admit_trusted_workflow_check_in(
                    request,
                    &session,
                    &check.observation.record,
                    Default::default(),
                )
                .await
            {
                Ok(decision) => decision,
                Err(error) => {
                    result.error = Some(format!(
                        "check {index} returned no terminal outcome: {error}; this is not evidence of non-commit; retry the same saved set"
                    ));
                    break;
                }
            };
            let decision = TrustedWorkflowCheckDecision {
                index,
                tx_id,
                terminal,
                check_id: check.observation.id().to_string(),
                job: check.observation.record.job.clone(),
                conclusion: conclusion(check.observation.record.conclusion),
            };
            let output = observe(&decision);
            result.decisions.push(decision);
            if let Err(error) = output {
                result.error = Some(format!(
                    "terminal observation delivery failed: {error}; retry the same saved set, never the workflow"
                ));
                break;
            }
        }
        result
    }
}

fn child_key(
    tenant: TenantId,
    repository: RepositoryId,
    incarnation: RepositoryIncarnationId,
    observation: &NativeWorkflowCheck,
) -> Result<IdempotencyKey, TrustedWorkflowFailure> {
    let mut h = Sha256Hasher::new();
    for part in [
        b"frankengit/workflow-check-set-child/v1".as_slice(),
        tenant.as_bytes(),
        repository.as_bytes(),
        incarnation.as_bytes(),
        observation.id().as_bytes(),
        observation.record.source_ref.as_bytes(),
    ] {
        h.update(&(part.len() as u64).to_be_bytes());
        h.update(part);
    }
    // Key excludes evidence/graph/result, so changing a report cannot evade the
    // ordinary seal's same-key/different-request refusal. No truncated digests.
    IdempotencyKey::new(h.finish().to_vec())
        .map_err(|_| TrustedWorkflowFailure::InvalidInput("check-set child identity refused"))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn quote(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c <= '\u{1f}' => {
                write!(out, "\\u{:04x}", c as u32).expect("writing to a String cannot fail");
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
const fn conclusion(value: WorkflowCheckConclusion) -> &'static str {
    match value {
        WorkflowCheckConclusion::Success => "success",
        WorkflowCheckConclusion::ActionRequired => "action_required",
        WorkflowCheckConclusion::Failure => "failure",
        WorkflowCheckConclusion::Cancelled => "cancelled",
        WorkflowCheckConclusion::TimedOut => "timed_out",
    }
}
