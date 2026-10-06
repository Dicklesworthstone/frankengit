//! Explicit absent-branch publication. Do not infer creation from a missing or
//! zero base, and do not pre-read branch freshness before historical recovery.
use super::*;
use fgit_types::{GitOid, RefName};

// Keep the established top-level discovery fields and add a disjoint
// predecessor choice. The boolean must be true; neither branch can accept
// both explicit creation and an existing-base contract.
pub(super) fn schema(legacy: Value) -> Value {
    let Value::Object(mut fields) = legacy else { unreachable!() };
    let Some(Value::Object(properties)) = fields.get_mut("properties") else { unreachable!() };
    properties.insert("initial".into(), object([
        ("type", text("boolean")), ("const", Value::Bool(true)),
        ("description", text("Explicit zero-parent, expected-absent publication. Omit expected_base. Does not overwrite an existing branch.")),
    ]));
    let Some(Value::Array(required)) = fields.get_mut("required") else { unreachable!() };
    required.retain(|value| value.text() != Some("expected_base"));
    fields.insert("oneOf".into(), Value::Array(vec![
        object([
            ("required", Value::Array(vec![text("expected_base")])),
            ("not", object([("required", Value::Array(vec![text("initial")]))])),
        ]),
        object([
            ("required", Value::Array(vec![text("initial")])),
            ("not", object([("required", Value::Array(vec![text("expected_base")]))])),
        ]),
    ]));
    Value::Object(fields)
}

#[derive(Debug)]
struct Input {
    reference: RefName,
    candidate: GitOid,
    bytes: Vec<u8>,
}
fn parse(args: &Object, format: GitHashAlgorithm) -> Result<Input, ToolError> {
    require_fields(args, &[
        "initial", "reference", "reference_hex", "expected_candidate",
        "bundle_hex_chunks", "idempotency_key",
    ])?;
    if args.get("initial") != Some(&Value::Bool(true)) {
        return Err(ToolError::invalid("initial_must_be_true"));
    }
    let reference = branch(args, "reference", "reference_hex")?;
    let candidate = oid(args, "expected_candidate", format)?;
    let bytes = bundle(args)?;
    Ok(Input { reference, candidate, bytes })
}

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    if !backend.options.writes.source {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let key = common::key(args)?;
    let input = parse(args, backend.options.format)?;
    let session = common::session(backend, key)?;
    let principal = session.authenticated_session()
        .ok_or(ToolError::invalid("principal_not_bound"))?.principal_id();
    let request = fgit_cli::command_request_context(&backend.node);
    // The native engine verifies zero parents, exact advertised coordinates,
    // complete regular-file closure and expected absence. Its same-key terminal
    // recovery precedes current intake and object checks. No MCP-local ref,
    // preparation receipt, or separate latest-head read authorizes publication.
    let admitted = backend.node.runtime().block_on(
        backend.node.apply_initial_patch_bundle_durable_in(
            &request, &session, &input.reference, input.candidate, &input.bytes,
            Default::default(),
        ),
    ).map_err(|_| ToolError::uncertain("source_mutation_outcome_unknown"))?;
    let observations: Vec<_> = admitted.commands.iter().map(|c| (c.tx_id, c.terminal)).collect();
    let (tx, terminal) = atomic_terminal(
        admitted.session.atomic, &admitted.session.tx_ids, &observations, 1,
    )?;
    let mut result = common::binding(backend, principal, false);
    result.extend(common::terminal(tx, &terminal));
    result.extend([
        ("type".into(), text("source_publication")),
        ("action".into(), text("publish_initial")),
        ("initial".into(), Value::Bool(true)),
        ("atomic".into(), Value::Bool(true)),
        ("complete".into(), Value::Bool(true)),
        ("historical_outcome".into(), Value::Bool(true)),
        ("current_refs_asserted".into(), Value::Bool(false)),
        ("ref_transaction_committed".into(), Value::Bool(matches!(terminal.outcome, DecisionOutcome::Committed { .. }))),
        ("submitted_commands".into(), Value::Array(vec![object([
            ("reference_hex", text(hex(input.reference.as_bytes()))),
            ("expected_old", Value::Null),
            ("proposed_new", text(input.candidate.to_string())),
            ("force", Value::Bool(false)),
        ])])),
        // A historical retry recovers its seal, not a new pack-validation claim.
        ("bundle_validation_receipt".into(), Value::Null),
    ]);
    Ok(Value::Object(result))
}

#[cfg(test)]
mod tests;
