//! Offline, non-consuming node recovery reads. No execution or acknowledgement.
//! The CLI uses this composition rather than bypassing the original node marker.
use super::*;
use fgit_crypto::{Digest, DigestAlgorithm};
use fgit_runner::coordinator::delivery::journal::history::{
    CheckHistoryEntry, MAX_HISTORY_BATCHES, MAX_HISTORY_BYTES,
};
use fgit_runner::coordinator::{CheckRunConclusion, CheckRunStatus, CoordinatorExecutionProfile};
use fgit_types::{RepositoryId, TenantId};

impl OneNode {
    /// Read one page of saved custody history, including acknowledged batches.
    /// `expected` is (tenant, repository, original attempt-marker digest).
    /// Pins are (journal byte length, SHA-256 tail); `minimum` is an ancestry
    /// witness, while `snapshot` must match exactly for pagination. `after` is
    /// an accepted batch digest, not an arbitrary offset. `limits` is the page's
    /// maximum batch count and sum of encoded batch/acknowledgement bytes.
    ///
    /// The returned JSON describes local custody, never execution completion,
    /// reaping, producer authorization or canonical check acceptance. No source,
    /// final report, running node or workflow recompilation is needed. Reading
    /// does not dequeue facts, record acknowledgements or rerun jobs. The lock
    /// is released before the result leaves this function.
    pub fn trusted_workflow_history_json(
        directory: &Path,
        expected: (TenantId, RepositoryId, Digest),
        minimum: Option<(u64, Digest)>,
        snapshot: Option<(u64, Digest)>,
        after: Option<Digest>,
        limits: (usize, usize),
        live: &dyn Fn() -> bool,
    ) -> Result<String, TrustedWorkflowFailure> {
        if limits.0 == 0
            || limits.0 > MAX_HISTORY_BATCHES
            || limits.1 == 0
            || limits.1 > MAX_HISTORY_BYTES
        {
            return Err(TrustedWorkflowFailure::InvalidInput(
                "invalid custody history page limits",
            ));
        }
        let expected = checked_scope(expected)?;
        let minimum = minimum.map(checked_pin).transpose()?;
        let snapshot = snapshot.map(checked_pin).transpose()?;
        let after = after.map(checked_root).transpose()?;
        let mut journal = Self::open_trusted_workflow_journal(directory, expected, minimum, live)?;
        let page = journal
            .read_history(snapshot, after, limits.0, limits.1, live)
            .map_err(|e| failure(directory, e))?;
        let mut entries = Vec::new();
        for entry in page.entries() {
            if !live() {
                return Err(failure(directory, "custody history rendering cancelled"));
            }
            entries.push(entry_json(entry));
        }
        let entries = entries.join(",");
        if !live() {
            return Err(failure(directory, "custody history rendering cancelled"));
        }
        let continuation = page
            .next_after()
            .map_or_else(|| "null".to_owned(), |id| quoted(&root_hex(id)));
        Ok(format!(
            "{{\"type\":\"workflow_custody_history\",\"schema_version\":1,\"authoritative_check\":false,\"execution_retried\":false,\"execution_completion\":\"not_asserted\",\"evidence_payloads_included\":false,\"scope\":{},\"snapshot\":{},\"retained_batches\":{},\"pending_batches\":{},\"next_after\":{continuation},\"entries\":[{entries}]}}",
            scope_json(expected),
            pin_json(page.snapshot()),
            journal.retained_batches(),
            journal.pending_batches(),
        ))
    }

    /// Recover exact bytes of one accepted batch, or one evidence body referenced
    /// by that batch. Return (bytes, JSON provenance). `expected` and `minimum`
    /// have the same meaning as in `trusted_workflow_history_json`.
    ///
    /// Missing/foreign evidence is refused, including orphaned evidence stored
    /// before a rejected submission. The returned body is bounded by the existing
    /// journal profile. This method does not publish a file or settle delivery;
    /// the caller owns disclosure and no-overwrite output publication. All saved
    /// batches remain readable, including those already delivered downstream.
    pub fn trusted_workflow_artifact(
        directory: &Path,
        expected: (TenantId, RepositoryId, Digest),
        minimum: Option<(u64, Digest)>,
        batch: Digest,
        evidence: Option<Digest>,
        live: &dyn Fn() -> bool,
    ) -> Result<(Vec<u8>, String), TrustedWorkflowFailure> {
        let expected = checked_scope(expected)?;
        let minimum = minimum.map(checked_pin).transpose()?;
        let batch = checked_root(batch)?;
        let evidence = evidence.map(checked_root).transpose()?;
        let mut journal = Self::open_trusted_workflow_journal(directory, expected, minimum, live)?;
        let entry = journal
            .read_retained_batch(batch)
            .map_err(|e| failure(directory, e))?;
        if !live() {
            return Err(failure(directory, "custody artifact read cancelled"));
        }
        let (bytes, id, kind) = match evidence {
            Some(id) => (
                journal
                    .read_batch_evidence(batch, id)
                    .map_err(|e| failure(directory, e))?,
                id,
                "evidence",
            ),
            None => (entry.batch().body().to_vec(), batch, "proposal_batch"),
        };
        if Commitment::of_bytes(&bytes) != id {
            return Err(failure(
                directory,
                "saved custody artifact commitment mismatch",
            ));
        }
        if !live() {
            return Err(failure(directory, "custody artifact read cancelled"));
        }
        let metadata = format!(
            "{{\"type\":\"workflow_custody_artifact\",\"schema_version\":1,\"authoritative_check\":false,\"execution_retried\":false,\"execution_completion\":\"not_asserted\",\"scope\":{},\"snapshot\":{},\"kind\":\"{kind}\",\"batch_sha256\":\"{}\",\"sha256\":\"{}\",\"bytes\":{},\"delivery_receipt_sha256\":{}}}",
            scope_json(expected),
            pin_json(journal.pin()),
            root_hex(batch),
            root_hex(id),
            bytes.len(),
            optional_root(entry.delivery_receipt()),
        );
        Ok((bytes, metadata))
    }
}

fn checked_root(value: Digest) -> Result<Commitment, TrustedWorkflowFailure> {
    if value.algorithm() != DigestAlgorithm::Sha256.id() || value.bytes().as_bytes().len() != 32 {
        return Err(TrustedWorkflowFailure::InvalidInput(
            "custody recovery requires a 32-byte SHA-256 digest",
        ));
    }
    Commitment::try_from_digest(value)
        .map_err(|_| TrustedWorkflowFailure::InvalidInput("unsupported custody recovery digest"))
}
fn checked_scope(
    value: (TenantId, RepositoryId, Digest),
) -> Result<CheckJournalScope, TrustedWorkflowFailure> {
    Ok(CheckJournalScope {
        tenant: value.0,
        repository: value.1,
        journal_id: checked_root(value.2)?,
    })
}
fn checked_pin(value: (u64, Digest)) -> Result<CheckJournalPin, TrustedWorkflowFailure> {
    if !(72..=4 * 1024 * 1024 * 1024).contains(&value.0) {
        return Err(TrustedWorkflowFailure::InvalidInput(
            "invalid custody recovery pin length",
        ));
    }
    Ok(CheckJournalPin::new(value.0, checked_root(value.1)?))
}
fn failure(directory: &Path, error: impl std::fmt::Display) -> TrustedWorkflowFailure {
    TrustedWorkflowFailure::Journal {
        directory: directory.to_path_buf(),
        detail: error.to_string(),
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn root_hex(root: Commitment) -> String {
    hex(root.digest().bytes().as_bytes())
}
fn optional_root(root: Option<Commitment>) -> String {
    root.map_or_else(|| "null".to_owned(), |root| quoted(&root_hex(root)))
}
fn scope_json(scope: CheckJournalScope) -> String {
    format!(
        "{{\"tenant\":\"{}\",\"repository\":\"{}\",\"journal_id\":\"{}\"}}",
        hex(scope.tenant.as_bytes()),
        hex(scope.repository.as_bytes()),
        root_hex(scope.journal_id)
    )
}
fn pin_json(pin: CheckJournalPin) -> String {
    // The portable token is directly accepted by the CLI's --at-pin/minimum-pin.
    quoted(&format!("{}:{}", pin.byte_len(), root_hex(pin.tail())))
}
fn entry_json(entry: &CheckHistoryEntry) -> String {
    let batch = entry.batch();
    let profile = match batch.execution_profile() {
        CoordinatorExecutionProfile::CommandOnly => {
            "{\"name\":\"coordinator-command-only-v1\"}".to_owned()
        }
        CoordinatorExecutionProfile::TrustedWorkflow { source, limits } => format!(
            "{{\"name\":\"trusted-local-foreground-v1\",\"source_sha256\":\"{}\",\"step_timeout_nanos\":{},\"run_timeout_nanos\":{},\"stream_bytes\":{},\"total_output_bytes\":{}}}",
            root_hex(source),
            limits.step_timeout.as_nanos(),
            limits.run_timeout.as_nanos(),
            limits.stream_bytes,
            limits.total_output_bytes,
        ),
    };
    let facts = batch.facts().iter().map(|fact| {
        let status = match fact.status {
            CheckRunStatus::Queued => "queued", CheckRunStatus::InProgress => "in_progress", CheckRunStatus::Completed => "completed",
        };
        let conclusion = fact.conclusion.map_or_else(|| "null".to_owned(), |conclusion| quoted(match conclusion {
            CheckRunConclusion::Success => "success", CheckRunConclusion::Failure => "failure",
            CheckRunConclusion::Neutral => "neutral", CheckRunConclusion::Cancelled => "cancelled",
            CheckRunConclusion::TimedOut => "timed_out", CheckRunConclusion::ActionRequired => "action_required",
        }));
        format!("{{\"job\":{},\"status\":\"{status}\",\"conclusion\":{conclusion},\"evidence_sha256\":{},\"logical_millis\":{}}}",
            quoted(&fact.job_id), optional_root(fact.receipt_commitment), fact.timestamp_millis)
    }).collect::<Vec<_>>().join(",");
    format!(
        "{{\"batch_sha256\":\"{}\",\"body_bytes\":{},\"ordinal\":{},\"delivery\":\"{}\",\"delivery_receipt_sha256\":{},\"run_sha256\":\"{}\",\"attempt_sha256\":\"{}\",\"authority_basis_sha256\":\"{}\",\"object_format\":\"{}\",\"source_commit\":\"{}\",\"workflow_graph_sha256\":\"{}\",\"trust_domain\":{},\"profile\":{profile},\"facts\":[{facts}]}}",
        root_hex(batch.id()),
        batch.body().len(),
        batch.ordinal(),
        if entry.delivery_receipt().is_some() {
            "acknowledged"
        } else {
            "pending"
        },
        optional_root(entry.delivery_receipt()),
        root_hex(batch.run_id().commitment()),
        root_hex(batch.attempt_id().commitment()),
        root_hex(batch.authority_head()),
        batch.source_commit().algorithm().as_str(),
        batch.source_commit(),
        root_hex(batch.graph_commitment()),
        quoted(batch.trust_domain().name().as_str()),
    )
}
fn quoted(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c < '\u{20}' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests;
