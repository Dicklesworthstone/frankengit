//! A view of the native terminal decision, never a new source of truth.
use super::Options;
use crate::publication_support::quote;
use fgit_authority::TerminalOutcome;
use fgit_types::{DecisionOutcome, RepositoryIncarnationId, TxId};

#[derive(Debug, Eq, PartialEq)]
pub(super) struct AtomicImportDecision {
    pub(super) tx_id: TxId,
    pub(super) terminal: TerminalOutcome,
    pub(super) command_count: usize,
}

/// Source import returns the same authenticated transaction for every command.
/// Do not compress an empty, non-atomic or internally inconsistent result into
/// a successful atomic receipt. Refusing to render says nothing about rollback.
pub(super) fn checked_atomic(
    atomic: bool,
    tx_ids: &[TxId],
    commands: &[(TxId, TerminalOutcome)],
) -> Result<AtomicImportDecision, &'static str> {
    let [tx_id] = tx_ids else {
        return Err("import result does not identify exactly one transaction");
    };
    let Some((first_tx, terminal)) = commands.first() else {
        return Err("import result contains no terminal command outcomes");
    };
    if !atomic || first_tx != tx_id
        || commands.iter().any(|(id, outcome)| id != tx_id || outcome != terminal)
    {
        return Err("import result disagrees with its atomic transaction mapping");
    }
    Ok(AtomicImportDecision {
        tx_id: *tx_id,
        terminal: *terminal,
        command_count: commands.len(),
    })
}

pub(super) fn render(
    options: &Options,
    incarnation: RepositoryIncarnationId,
    decision: &AtomicImportDecision,
    cleanup: Option<&str>,
) -> String {
    let (state, record, refusal, code, code_point) = match decision.terminal.outcome {
        DecisionOutcome::Committed { repository_commit_id } => (
            "committed", quote(&repository_commit_id.to_string()), "null".into(),
            "null".into(), "null".into(),
        ),
        DecisionOutcome::Refused { code, refusal_record_id } => (
            "refused", "null".into(), quote(&refusal_record_id.to_string()),
            quote(&format!("{code:?}")), code.code_point().to_string(),
        ),
    };
    // No retry key, source path, mutable HEAD, guessed ref names or inferred
    // durability epoch. This describes an immutable decision; a later update
    // does not change it. Cleanup is a separate lifecycle observation.
    format!(
        concat!(
            "{{\"type\":\"source_import_outcome\",\"schema_version\":1,",
            "\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation_id\":{},",
            "\"principal_id\":{},\"atomic\":true,\"command_count\":{},",
            "\"tx_id\":{},\"state\":{},\"terminal\":true,\"decision_sequence\":{},",
            "\"repository_commit_id\":{},\"refusal_record_id\":{},",
            "\"refusal_code\":{},\"refusal_code_point\":{},",
            "\"node_closed\":{},\"cleanup_error\":{}}}"
        ),
        quote(&options.tenant.to_string()),
        quote(&options.repository.to_string()),
        quote(&incarnation.to_string()),
        quote(&options.principal.to_string()),
        decision.command_count,
        quote(&decision.tx_id.to_string()),
        quote(state),
        decision.terminal.decision_sequence.get(),
        record, refusal, code, code_point,
        cleanup.is_none(),
        cleanup.map(quote).unwrap_or_else(|| "null".into()),
    )
}

#[cfg(test)]
mod tests;
