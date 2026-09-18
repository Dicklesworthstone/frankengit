//! Principal-scoped read-only recovery. Looking up a key never re-seals,
//! reconstructs, resubmits or cancels the original mutation.
use fgit_authority::{OutcomeLookup, key_recovery::RequestRecovery};
use super::{NodeTools, require_fields};
use super::mutations as common;
use super::super::json::{Object, Value, text};
use super::super::protocol::{Tool, ToolError};

pub(super) const NAME: &str = "frankengit_transaction_outcome";
pub(super) fn tools() -> Vec<Tool> {
    let mut properties = Object::new();
    properties.insert("idempotency_key".into(), common::key_schema());
    vec![Tool { name: NAME,
        description: "Read the launch-bound principal's original transaction by its stable key. Never retries or mutates. Missing or undecided observations are not proof of non-commit; a recovered result belongs to the original key binding, not a changed command.",
        schema: common::input_schema(properties, &["idempotency_key"]),
    }]
}
pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    if !backend.options.outcomes { return Err(ToolError::invalid("tool_not_granted")); }
    require_fields(args, &["idempotency_key"])?;
    let session = common::session(backend, common::key(args)?)?;
    let principal = session.authenticated_session().ok_or(ToolError::invalid("principal_not_bound"))?.principal_id();
    let request = backend.node.request_context();
    let recovery = backend.node.runtime().block_on(backend.node.recover_transaction_in(&request, &session))
        .map_err(|_| ToolError::failed("outcome_read_failed"))?;
    let mut result = common::binding(backend, principal, true);
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
            result.insert("canonical_request_digest".into(), text(recovered.seal().canonical_request_digest.to_string()));
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
