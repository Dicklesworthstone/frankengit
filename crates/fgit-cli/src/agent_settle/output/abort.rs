//! Reservation cleanup receipts deliberately contain no canonical outcome.

use fgit_node::agent_publication::NativeRecoveredRefTransactionAbort;

use super::{
    ObligationState, Options, Value, bounded_diagnostic, budget, hex, number, object, position,
    text,
};
use crate::agent_settle::{ABORT_PROFILE, options::Action};

pub(in crate::agent_settle) fn render(
    options: &Options,
    result: &NativeRecoveredRefTransactionAbort,
    cleanup_error: Option<&str>,
) -> Result<(String, u8), String> {
    let original = &options.original;
    let binding = &result.binding;
    let recovered = &result.recovered;
    let run = recovered.original_run();
    let journal = recovered.journal();
    if options.action != Action::AbortReserved
        || binding.effect_id() != original.effect
        || binding.seal().authenticated_principal_id != original.principal
        || binding.seal().tenant_id != original.tenant
        || binding.seal().repository_id != original.repository
        || run.run_id() != original.run
        || run
            .commitment()
            .map_err(|error| error.to_string())?
            .as_bytes()
            != &original.expected_run
        || journal.ref_transactions().get(&original.effect) != Some(binding)
    {
        return Err("abort receipt does not match the requested original reservation".into());
    }
    let record = journal
        .records()
        .iter()
        .find(|record| record.effect_id == original.effect)
        .ok_or("aborted publication responsibility disappeared")?;
    if record.obligation_state != ObligationState::Aborted {
        return Err("abort returned an unsettled reservation".into());
    }
    let report = recovered
        .reconciliation_report(options.observed_at)
        .map_err(|error| error.to_string())?;
    let authority = run
        .authority_read_receipt()
        .ok_or("aborted original run has no authenticated authority")?;
    let document = object([
        ("type", text("agent_settlement")),
        ("schema_version", number(1)),
        ("profile", text(ABORT_PROFILE)),
        ("action", text("abort-reserved")),
        ("complete", Value::Bool(cleanup_error.is_none())),
        ("scope", text("one_publication_reservation")),
        ("read_only", Value::Bool(false)),
        ("publication_authorized", Value::Bool(false)),
        ("resumption_authorized", Value::Bool(false)),
        ("run_quiescence_established", Value::Bool(false)),
        (
            "observed_at_logical_time",
            number(options.observed_at.value()),
        ),
        (
            "operator",
            object([
                ("principal_id", text(original.principal.to_string())),
                ("authentication", text("operator-asserted")),
                ("authorization_host", text("trusted-local-cli")),
            ]),
        ),
        (
            "original_run",
            object([
                ("run_id", text(format!("{:032x}", original.run.value()))),
                ("commitment", text(hex(&original.expected_run))),
                ("tenant_id", text(original.tenant.to_string())),
                ("repository_id", text(original.repository.to_string())),
                (
                    "authenticated_inventory",
                    object([
                        ("expires_at_logical_time", number(run.expiry().value())),
                        (
                            "authority_head_id",
                            text(authority.authority_head_id().to_string()),
                        ),
                        (
                            "authority_generation",
                            number(authority.authority_head_generation().get()),
                        ),
                        ("refreshed", Value::Bool(false)),
                    ]),
                ),
            ]),
        ),
        (
            "journal",
            object([
                ("anchor_source", text("independently-supplied")),
                ("input_tail", position(original.expected_tail)),
                ("current_tail", position(journal.position())),
                ("abort_confirmed", Value::Bool(true)),
                ("input_already_aborted", Value::Bool(result.already_aborted)),
                ("acknowledgement_confirmed", Value::Bool(false)),
                ("input_already_acknowledged", Value::Null),
                ("inventory_complete", Value::Bool(true)),
            ]),
        ),
        (
            "publication",
            object([
                (
                    "effect_id",
                    text(format!("{:032x}", original.effect.value())),
                ),
                ("tx_id", text(binding.tx_id().to_string())),
                ("principal_id", text(original.principal.to_string())),
                ("canonical_status", text("not_observed")),
                ("canonical_terminal", Value::Null),
                ("canonical_cancellation_established", Value::Bool(false)),
            ]),
        ),
        (
            "journal_responsibility",
            object([
                ("state", text("aborted")),
                ("debt_retained", Value::Bool(false)),
                ("budget_reserved", budget(record.budget_reserved)),
                ("budget_consumed", budget(record.budget_consumed)),
                (
                    "journal_has_unsettled_effects",
                    Value::Bool(report.has_unsettled_effects()),
                ),
            ]),
        ),
        (
            "cleanup_error",
            cleanup_error.map_or(Value::Null, |error| text(bounded_diagnostic(error))),
        ),
    ]);
    Ok((
        document
            .encode(original.maximum.saturating_sub(1))
            .map_err(str::to_owned)?,
        if cleanup_error.is_some() { 2 } else { 0 },
    ))
}
