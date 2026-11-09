use super::{PROFILE, bounded_diagnostic, options::Options};
use fgit_agent::{effect_journal::EffectJournalPosition, ref_publication::ObservedRefTransaction};
use fgit_node::agent_publication::NativeRecoveredRefTransactionSettlement;
use fgit_resource::{Grade, ObligationState, ResourceVector};
use fgit_schema::json::{Value, number, object, text};
use fgit_types::DecisionOutcome;

mod abort;
pub(super) use abort::render as render_abort;

pub(super) fn canonical_status(observed: Option<&ObservedRefTransaction>) -> &'static str {
    match observed.map(|observed| observed.terminal().outcome) {
        Some(DecisionOutcome::Committed { .. }) => "committed",
        Some(DecisionOutcome::Refused { .. }) => "refused",
        None => "undecided",
    }
}

fn terminal(observed: &ObservedRefTransaction) -> Value {
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

fn position(position: EffectJournalPosition) -> Value {
    object([
        ("entries", number(position.entries)),
        ("bytes", number(position.bytes)),
        ("digest", text(hex(&position.digest))),
    ])
}

fn budget(value: ResourceVector) -> Value {
    Value::Object(
        Grade::ALL
            .into_iter()
            .map(|grade| (grade.as_str().into(), number(value.get(grade))))
            .collect(),
    )
}

pub(super) fn render(
    options: &Options,
    result: &NativeRecoveredRefTransactionSettlement,
    cleanup_error: Option<&str>,
) -> Result<(String, u8), String> {
    if options.action != super::options::Action::Acknowledge {
        return Err("acknowledgement result does not match the requested cleanup action".into());
    }
    let original = &options.original;
    let (tx, observed, current_tail, already_acknowledged, responsibility, run, status) =
        match result {
            NativeRecoveredRefTransactionSettlement::Undecided { effect_id, tx_id } => {
                if *effect_id != original.effect {
                    return Err("settlement returned another effect".into());
                }
                // The native owner withholds its private prefix when no terminal is
                // known. Neither a complete inventory nor an unchanged *full* tail
                // can be inferred from the externally supplied old anchor.
                (
                    *tx_id,
                    None,
                    Value::Null,
                    Value::Null,
                    Value::Null,
                    Value::Null,
                    4,
                )
            }
            NativeRecoveredRefTransactionSettlement::Acknowledged {
                observation,
                recovered,
                already_acknowledged,
            } => {
                let binding = observation.binding();
                let run = recovered.original_run();
                let journal = recovered.journal();
                if binding.effect_id() != original.effect
                    || binding.seal().authenticated_principal_id != original.principal
                    || run.run_id() != original.run
                {
                    return Err("settlement returned another original publication".into());
                }
                let record = journal
                    .records()
                    .iter()
                    .find(|record| record.effect_id == original.effect)
                    .ok_or("acknowledged publication responsibility disappeared")?;
                if record.obligation_state != ObligationState::Acknowledged {
                    return Err("settlement returned an unacknowledged responsibility".into());
                }
                let report = recovered
                    .reconciliation_report(options.observed_at)
                    .map_err(|error| error.to_string())?;
                let authority = run
                    .authority_read_receipt()
                    .ok_or("settled original run has no authenticated authority")?;
                let responsibility = object([
                    ("state", text("acknowledged")),
                    ("debt_retained", Value::Bool(false)),
                    ("budget_reserved", budget(record.budget_reserved)),
                    ("budget_consumed", budget(record.budget_consumed)),
                    (
                        "journal_has_unsettled_effects",
                        Value::Bool(report.has_unsettled_effects()),
                    ),
                ]);
                let run = object([
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
                ]);
                let status = match observation.terminal().outcome {
                    DecisionOutcome::Committed { .. } => 0,
                    DecisionOutcome::Refused { .. } => 3,
                };
                (
                    binding.tx_id(),
                    Some(observation),
                    position(journal.position()),
                    Value::Bool(*already_acknowledged),
                    responsibility,
                    run,
                    status,
                )
            }
        };
    let acknowledged = observed.is_some();
    let document = object([
        ("type", text("agent_settlement")),
        ("schema_version", number(1)),
        ("profile", text(PROFILE)),
        ("action", text("acknowledge")),
        ("complete", Value::Bool(cleanup_error.is_none())),
        ("scope", text("one_publication_effect")),
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
                ("authenticated_inventory", run),
            ]),
        ),
        (
            "journal",
            object([
                ("anchor_source", text("independently-supplied")),
                ("input_tail", position(original.expected_tail)),
                ("current_tail", current_tail),
                ("acknowledgement_confirmed", Value::Bool(acknowledged)),
                ("input_already_acknowledged", already_acknowledged),
                ("inventory_complete", Value::Bool(acknowledged)),
            ]),
        ),
        (
            "publication",
            object([
                (
                    "effect_id",
                    text(format!("{:032x}", original.effect.value())),
                ),
                ("tx_id", text(tx.to_string())),
                ("principal_id", text(original.principal.to_string())),
                ("canonical_status", text(canonical_status(observed))),
                ("canonical_terminal", observed.map_or(Value::Null, terminal)),
            ]),
        ),
        ("journal_responsibility", responsibility),
        (
            "cleanup_error",
            cleanup_error.map_or(Value::Null, |error| text(bounded_diagnostic(error))),
        ),
    ]);
    Ok((
        document
            .encode(original.maximum.saturating_sub(1))
            .map_err(str::to_owned)?,
        if cleanup_error.is_some() { 2 } else { status },
    ))
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_agent::EffectId;
    use fgit_types::{CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, TxId};

    fn transaction() -> TxId {
        TxId::from_digest(
            DigestAlgorithmId::try_new(1).unwrap(),
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[1; 32]).unwrap(),
        )
    }

    fn undecided(options: &Options) -> NativeRecoveredRefTransactionSettlement {
        NativeRecoveredRefTransactionSettlement::Undecided {
            effect_id: options.original.effect,
            tx_id: transaction(),
        }
    }

    #[test]
    fn undecided_never_exposes_a_complete_journal_or_infers_quiescence() {
        let options =
            super::super::options::parse(&super::super::options::tests::arguments()).unwrap();
        let (document, status) = render(&options, &undecided(&options), None).unwrap();
        let value = fgit_schema::json::parse(document.as_bytes()).unwrap();
        let object = value.object().unwrap();
        let journal = object["journal"].object().unwrap();
        assert_eq!(status, 4);
        assert_eq!(journal["current_tail"], Value::Null);
        assert_eq!(journal["input_already_acknowledged"], Value::Null);
        assert_eq!(journal["inventory_complete"], Value::Bool(false));
        assert_eq!(journal["acknowledgement_confirmed"], Value::Bool(false));
        assert_eq!(object["journal_responsibility"], Value::Null);
        assert_eq!(object["run_quiescence_established"], Value::Bool(false));
        let different = NativeRecoveredRefTransactionSettlement::Undecided {
            effect_id: EffectId::new(0),
            tx_id: transaction(),
        };
        assert!(render(&options, &different, None).is_err());
    }

    #[test]
    fn cleanup_failures_preserve_the_observation_but_never_report_completion() {
        let mut options =
            super::super::options::parse(&super::super::options::tests::arguments()).unwrap();
        options.original.maximum = super::super::MIN_OUTPUT_BYTES;
        for diagnostic in ["x", "\0", "🧪"] {
            let (document, status) = render(
                &options,
                &undecided(&options),
                Some(&diagnostic.repeat(20000)),
            )
            .unwrap();
            assert_eq!(status, 2);
            assert!(document.len() < options.original.maximum);
            let value = fgit_schema::json::parse(document.as_bytes()).unwrap();
            let object = value.object().unwrap();
            assert_eq!(object["complete"], Value::Bool(false));
            assert!(
                object["cleanup_error"]
                    .text()
                    .unwrap()
                    .ends_with("[diagnostic truncated]")
            );
        }
    }
}
