//! Principal-scoped read-only recovery. Looking up a key never re-seals,
//! reconstructs, resubmits or cancels the original mutation.
use super::super::json::{self, Object, Value, object, text};
use super::super::protocol::{Tool, ToolError};
use super::mutations as common;
use super::{NodeTools, hex, require_fields};
use fgit_admission::evidence::{AdmissionAuthentication, PrincipalSnapshotRecord};
use fgit_authority::{OutcomeLookup, key_recovery::RequestRecovery};

pub(super) const NAME: &str = "frankengit_transaction_outcome";
pub(super) fn tools() -> Vec<Tool> {
    let mut properties = Object::new();
    properties.insert("idempotency_key".into(), common::key_schema());
    vec![Tool {
        name: NAME,
        description: "Read the launch-bound principal's original transaction by its stable key. Never retries or mutates. Missing or undecided observations are not proof of non-commit; a recovered result belongs to the original key binding, not a changed command.",
        schema: common::input_schema(properties, &["idempotency_key"]),
    }]
}
pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    if !backend.options.outcomes {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    require_fields(args, &["idempotency_key"])?;
    if backend.options.agent_token_file.is_some() || backend.agent.is_some() {
        super::agent::check_operation(backend, fgit_identity::agent::OUTCOMES_READ)?;
    }
    let session = common::session(backend, common::key(args)?)?;
    let principal = session
        .authenticated_session()
        .ok_or(ToolError::invalid("principal_not_bound"))?
        .principal_id();
    let request = backend.command_context();
    let recovery = backend
        .node
        .runtime()
        .block_on(backend.node.recover_transaction_in(&request, &session))
        .map_err(|_| ToolError::failed("outcome_read_failed"))?;
    // Sponsorship belongs to the original canonical decision, not the current
    // bearer used to recover it. Optional evidence failure must preserve the
    // already established outcome and never imply non-publication.
    let provenance = backend.node.runtime().block_on(
        backend
            .node
            .recover_transaction_principal_in(&request, &session, &recovery),
    );
    let mut result = common::binding(backend, principal, true);
    append_principal_provenance(
        &mut result,
        provenance
            .as_ref()
            .map(|value| value.as_ref())
            .map_err(|_| ()),
    );
    result.insert("type".into(), text("transaction_outcome"));
    result.insert("scope".into(), text("original_principal_key_binding"));
    result.insert("absence_proves_non_commit".into(), Value::Bool(false));
    result.insert("repository_changed".into(), Value::Bool(false));
    result.insert("terminal".into(), Value::Bool(false));
    result.insert("complete".into(), Value::Bool(false));
    result.insert("outcome_unknown".into(), Value::Bool(true));
    result.insert("tx_id".into(), Value::Null);
    result.insert("seal_id".into(), Value::Null);
    result.insert("canonical_request_digest".into(), Value::Null);
    let state = match recovery {
        RequestRecovery::KeyNotObserved => "key_not_observed",
        RequestRecovery::SealNotObserved => "seal_not_observed",
        RequestRecovery::Recovered(recovered) => {
            result.insert("tx_id".into(), text(recovered.tx_id().to_string()));
            result.insert("seal_id".into(), text(recovered.seal_id().to_string()));
            result.insert(
                "canonical_request_digest".into(),
                text(recovered.seal().canonical_request_digest.to_string()),
            );
            match recovered.outcome() {
                OutcomeLookup::Undecided => "undecided",
                OutcomeLookup::Decided(terminal) => {
                    result.extend(common::terminal(recovered.tx_id(), &terminal));
                    result.insert("complete".into(), Value::Bool(true));
                    "decided"
                }
            }
        }
    };
    result.insert("observation".into(), text(state));
    Ok(Value::Object(result))
}

// Keep the public witness shape consistent with native CLI/HTTP recovery.
// It contains only recorded evidence; token bytes and the recovery credential
// are never included or substituted for missing historical authentication.
fn append_principal_provenance(
    result: &mut Object,
    provenance: Result<Option<&PrincipalSnapshotRecord>, ()>,
) {
    let (provenance, error) = match provenance {
        Err(()) => (
            object([("state", text("unavailable"))]),
            text("original_principal_evidence_unavailable"),
        ),
        Ok(None) => (object([("state", text("not_terminal"))]), Value::Null),
        Ok(Some(snapshot)) => {
            let authentication = match snapshot.authentication() {
                None => Value::Null,
                Some(AdmissionAuthentication::OperatorAssertion) => text("operator_assertion"),
                Some(AdmissionAuthentication::HttpToken) => text("http_token"),
                Some(AdmissionAuthentication::SshDeployKey) => text("ssh_deploy_key"),
                Some(AdmissionAuthentication::AgentCredential(_)) => text("agent_credential"),
            };
            let witness = snapshot.agent_provenance().map_or(Value::Null, |agent| {
                let root = agent.grant_root();
                object([
                    ("agent", text(agent.agent().to_string())),
                    ("sponsor", text(agent.sponsor().to_string())),
                    ("sponsor_kind", text(agent.sponsor_kind().name())),
                    ("credential_id", text(agent.credential_id().to_string())),
                    (
                        "grant_root",
                        object([
                            (
                                "algorithm",
                                json::number(root.algorithm().code_point().into()),
                            ),
                            ("hex", text(hex(root.bytes().as_bytes()))),
                        ]),
                    ),
                    ("run_commitment", text(hex(agent.run_commitment()))),
                    ("authenticated_at", json::number(agent.authenticated_at())),
                    ("expires_at", json::number(agent.expires_at())),
                ])
            });
            (
                object([
                    (
                        "state",
                        text(if snapshot.authentication().is_some() {
                            "recorded"
                        } else {
                            "legacy_unknown"
                        }),
                    ),
                    ("principal_id", text(snapshot.principal_id().to_string())),
                    ("authentication", authentication),
                    ("agent_provenance", witness),
                ]),
                Value::Null,
            )
        }
    };
    result.insert("principal_provenance".into(), provenance);
    result.insert("provenance_error".into(), error);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_optional_principal_evidence_preserves_a_known_terminal_decision() {
        let mut result = object([
            ("outcome", text("committed")),
            ("terminal", Value::Bool(true)),
            ("outcome_unknown", Value::Bool(false)),
        ])
        .object()
        .unwrap()
        .clone();
        append_principal_provenance(&mut result, Err(()));
        assert_eq!(result["outcome"], text("committed"));
        assert_eq!(result["terminal"], Value::Bool(true));
        assert_eq!(result["outcome_unknown"], Value::Bool(false));
        assert_eq!(
            result["principal_provenance"],
            object([("state", text("unavailable"))])
        );
        assert_eq!(
            result["provenance_error"],
            text("original_principal_evidence_unavailable")
        );

        let mut undecided = Object::new();
        append_principal_provenance(&mut undecided, Ok(None));
        assert_eq!(
            undecided["principal_provenance"],
            object([("state", text("not_terminal"))])
        );
        assert_eq!(undecided["provenance_error"], Value::Null);
    }
}
