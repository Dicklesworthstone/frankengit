use super::{PROFILE, RecoveryObservation, options::Options};
use fgit_agent::ref_publication::ObservedRefTransaction;
use fgit_resource::{Grade, ObligationState, ResourceVector};
use fgit_schema::json::{Value, number, object, text};
use fgit_types::DecisionOutcome;

pub(super) fn canonical_status(observed: Option<&ObservedRefTransaction>) -> &'static str {
    match observed
        .map(ObservedRefTransaction::terminal)
        .map(|terminal| terminal.outcome)
    {
        Some(DecisionOutcome::Committed { .. }) => "committed",
        Some(DecisionOutcome::Refused { .. }) => "refused",
        None => "undecided",
    }
}

pub(super) fn render(
    options: &Options,
    observation: &RecoveryObservation,
    cleanup_error: Option<&str>,
) -> Result<(String, u8), String> {
    let recovered = &observation.recovered;
    let run = recovered.original_run();
    let journal = recovered.journal();
    let binding = journal
        .ref_transactions()
        .get(&options.effect)
        .ok_or("selected publication binding disappeared")?;
    let record = journal
        .records()
        .iter()
        .find(|record| record.effect_id == options.effect)
        .ok_or("selected publication responsibility disappeared")?;
    let authority = run
        .authority_read_receipt()
        .ok_or("recovered run has no authenticated authority")?;
    let canonical = observation.canonical.as_ref();
    let terminal = match canonical {
        None => Value::Null,
        Some(observed) => {
            let terminal = observed.terminal();
            let (rcr, refusal, code, name) = match terminal.outcome {
                DecisionOutcome::Committed {
                    repository_commit_id,
                } => (
                    text(repository_commit_id.to_string()),
                    Value::Null,
                    Value::Null,
                    Value::Null,
                ),
                DecisionOutcome::Refused {
                    code,
                    refusal_record_id,
                } => (
                    Value::Null,
                    text(refusal_record_id.to_string()),
                    number(u64::from(code.code_point())),
                    text(format!("{code:?}")),
                ),
            };
            object([
                (
                    "decision_sequence",
                    number(terminal.decision_sequence.get()),
                ),
                ("repository_commit_id", rcr),
                ("refusal_record_id", refusal),
                ("refusal_code", code),
                ("refusal_name", name),
                (
                    "observation_commitment",
                    text(observed.commitment().to_string()),
                ),
            ])
        }
    };
    let (state, debt_retained) = journal_state(record.obligation_state);
    let value = object([
        ("type", text("agent_recovery")),
        ("schema_version", number(1)),
        ("profile", text(PROFILE)),
        ("complete", Value::Bool(cleanup_error.is_none())),
        ("scope", text("one_publication_effect")),
        ("read_only", Value::Bool(true)),
        ("publication_authorized", Value::Bool(false)),
        ("resumption_authorized", Value::Bool(false)),
        ("run_quiescence_established", Value::Bool(false)),
        (
            "operator",
            object([
                ("principal_id", text(options.principal.to_string())),
                ("authentication", text("operator-asserted")),
                ("authorization_host", text("trusted-local-cli")),
            ]),
        ),
        (
            "original_run",
            object([
                ("run_id", text(format!("{:032x}", run.run_id().value()))),
                ("commitment", text(hex(&options.expected_run))),
                ("expires_at_logical_time", number(run.expiry().value())),
                (
                    "authority_head_id",
                    text(authority.authority_head_id().to_string()),
                ),
                (
                    "authority_generation",
                    number(authority.authority_head_generation().get()),
                ),
                ("tenant_id", text(options.tenant.to_string())),
                ("repository_id", text(options.repository.to_string())),
                ("refreshed", Value::Bool(false)),
            ]),
        ),
        (
            "journal",
            object([
                ("anchor_source", text("independently-supplied")),
                ("anchor_matched", Value::Bool(journal.is_anchored())),
                ("entries", number(options.expected_tail.entries)),
                ("bytes", number(options.expected_tail.bytes)),
                ("digest", text(hex(&options.expected_tail.digest))),
                ("mutated", Value::Bool(false)),
            ]),
        ),
        (
            "publication",
            object([
                (
                    "effect_id",
                    text(format!("{:032x}", options.effect.value())),
                ),
                ("tx_id", text(binding.tx_id().to_string())),
                (
                    "principal_id",
                    text(binding.seal().authenticated_principal_id.to_string()),
                ),
                (
                    "key_digest",
                    text(binding.seal().idempotency_key_digest.to_string()),
                ),
                (
                    "request_digest",
                    text(binding.seal().canonical_request_digest.to_string()),
                ),
                (
                    "publication_binding",
                    text(hex(binding.publication_binding())),
                ),
                (
                    "custody_commitment",
                    binding
                        .custody_commitment()
                        .map_or(Value::Null, |digest| text(hex(&digest))),
                ),
                ("canonical_status", text(canonical_status(canonical))),
                ("canonical_terminal", terminal),
            ]),
        ),
        (
            "journal_responsibility",
            object([
                ("state", text(state)),
                ("debt_retained", Value::Bool(debt_retained)),
                (
                    "terminal_acknowledged",
                    Value::Bool(record.obligation_state == ObligationState::Acknowledged),
                ),
                ("budget_reserved", budget(record.budget_reserved)),
                ("budget_consumed", budget(record.budget_consumed)),
                ("acknowledgement_appended", Value::Bool(false)),
                ("settlement_performed", Value::Bool(false)),
            ]),
        ),
        ("cleanup_error", cleanup_error.map_or(Value::Null, text)),
    ]);
    let status = if cleanup_error.is_some() {
        2
    } else {
        match canonical
            .map(ObservedRefTransaction::terminal)
            .map(|terminal| terminal.outcome)
        {
            Some(DecisionOutcome::Committed { .. }) => 0,
            Some(DecisionOutcome::Refused { .. }) => 3,
            None => 4,
        }
    };
    // Include the newline in the caller's byte ceiling. Build the complete
    // document before writing anything; a small ceiling never emits half JSON.
    Ok((
        value
            .encode(options.maximum.saturating_sub(1))
            .map_err(str::to_owned)?,
        status,
    ))
}

fn budget(value: ResourceVector) -> Value {
    Value::Object(
        Grade::ALL
            .into_iter()
            .map(|grade| (grade.as_str().into(), number(value.get(grade))))
            .collect(),
    )
}

fn journal_state(state: ObligationState) -> (&'static str, bool) {
    match state {
        ObligationState::Reserved => ("reserved", true),
        ObligationState::Committed => ("committed", true),
        ObligationState::DeferredExternally => ("deferred_externally", true),
        ObligationState::Escalated => ("escalated", true),
        ObligationState::Acknowledged => ("acknowledged", false),
        ObligationState::Aborted => ("aborted", false),
        ObligationState::TerminallyFailed => ("terminally_failed", false),
        ObligationState::Leaked => ("leaked", true),
    }
}

fn hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        result.push(char::from(ALPHABET[(byte >> 4) as usize]));
        result.push(char::from(ALPHABET[(byte & 15) as usize]));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unresolved_journal_lifecycles_do_not_become_settled_from_an_observation() {
        for state in [
            ObligationState::Reserved,
            ObligationState::Committed,
            ObligationState::DeferredExternally,
            ObligationState::Escalated,
            ObligationState::Leaked,
        ] {
            assert!(journal_state(state).1);
        }
        for state in [
            ObligationState::Acknowledged,
            ObligationState::Aborted,
            ObligationState::TerminallyFailed,
        ] {
            assert!(!journal_state(state).1);
        }
    }
}
