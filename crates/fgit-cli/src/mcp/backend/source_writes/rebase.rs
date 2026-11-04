//! Explicit publication of an independently inspected native linear series.
//! The source-tip lease and the bundle's onto prerequisite have distinct roles.
use super::*;
use fgit_types::{GitOid, RefName, MAX_REF_NAME_LEN};

pub(super) const NAME: &str = "frankengit_source_publish_rebase";
const FIELDS: &[&str] = &[
    "reference",
    "reference_hex",
    "expected_source",
    "onto",
    "expected_candidate",
    "bundle_hex_chunks",
    "idempotency_key",
];

pub(super) fn schema() -> Value {
    let mut properties = Object::new();
    properties.insert("idempotency_key".into(), common::key_schema());
    properties.insert(
        "reference".into(),
        object([
            ("type", text("string")),
            ("minLength", json::number(1)),
            ("maxLength", json::number(MAX_REF_NAME_LEN as u64)),
            ("description", text("Exact SOURCE branch to replace, under refs/heads/. Supply exactly one UTF-8 or raw-hex encoding.")),
        ]),
    );
    properties.insert(
        "reference_hex".into(),
        object([
            ("type", text("string")),
            ("minLength", json::number(2)),
            ("maxLength", json::number((MAX_REF_NAME_LEN * 2) as u64)),
            ("pattern", text("^(?:[0-9a-f]{2})+$")),
        ]),
    );
    for (name, description) in [
        ("expected_source", "Exact old SOURCE branch tip. This is the publication lease; the onto commit does not replace it."),
        ("onto", "Exact native commit used as the bundle's sole prerequisite. Not a branch lease or a current-tip lookup."),
        ("expected_candidate", "Exact independently inspected final tip of the complete linear series; may equal onto for a zero-commit series."),
    ] {
        properties.insert(
            name.into(),
            object([
                ("type", text("string")),
                ("pattern", text("^(?:[0-9a-f]{40}|[0-9a-f]{64})$")),
                ("description", text(description)),
            ]),
        );
    }
    properties.insert(
        "bundle_hex_chunks".into(),
        object([
            ("type", text("array")),
            ("minItems", json::number(1)),
            ("maxItems", json::number(MAX_CHUNKS as u64)),
            ("items", object([
                ("type", text("string")),
                ("minLength", json::number(2)),
                ("maxLength", json::number((CHUNK_BYTES * 2) as u64)),
                ("pattern", text("^(?:[0-9a-f]{2})+$")),
            ])),
            ("description", text("One complete reviewed native Git bundle in ordered chunks, at most 24 KiB total. Bytes are untrusted; native quarantine and complete-series validation precede new publication.")),
        ]),
    );
    let mut result = common::input_schema(
        properties,
        &["expected_source", "onto", "expected_candidate", "bundle_hex_chunks", "idempotency_key"],
    );
    if let Value::Object(fields) = &mut result {
        fields.insert(
            "oneOf".into(),
            Value::Array(vec![
                object([("required", Value::Array(vec![text("reference")]))]),
                object([("required", Value::Array(vec![text("reference_hex")]))]),
            ]),
        );
    }
    result
}

#[derive(Debug)]
struct Input {
    reference: RefName,
    expected_source: GitOid,
    onto: GitOid,
    expected_candidate: GitOid,
    bytes: Vec<u8>,
}

fn parse(args: &Object, format: GitHashAlgorithm) -> Result<Input, ToolError> {
    require_fields(args, FIELDS)?;
    Ok(Input {
        reference: branch(args, "reference", "reference_hex")?,
        expected_source: oid(args, "expected_source", format)?,
        onto: oid(args, "onto", format)?,
        expected_candidate: oid(args, "expected_candidate", format)?,
        bytes: bundle(args)?,
    })
}

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    // A sponsored run needs its own checked broker adapter. An operator entry
    // point must never turn an agent session into an OperatorAssertion.
    if !backend.options.writes.source || backend.options.agent_token_file.is_some() {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let key = common::key(args)?;
    let input = parse(args, backend.options.format)?;
    let session = common::session(backend, key)?;
    let principal = session
        .authenticated_session()
        .ok_or(ToolError::invalid("principal_not_bound"))?
        .principal_id();
    let request = fgit_cli::command_request_context(&backend.node);
    // No preliminary current-head or source read: native terminal recovery
    // must remain possible after the successful rebase or a later branch move.
    // This dedicated owner verifies a bounded single-parent series to onto;
    // the existing one-commit workspace publisher remains its own profile.
    let admitted = backend
        .node
        .runtime()
        .block_on(backend.node.apply_rebase_bundle_durable_in(
            &request,
            principal,
            common::required(args, "idempotency_key")?.as_bytes(),
            &input.reference,
            input.expected_source,
            input.onto,
            input.expected_candidate,
            &input.bytes,
        ))
        .map_err(|_| ToolError::uncertain("source_mutation_outcome_unknown"))?;
    let mut result = publication_receipt(
        backend,
        principal,
        "publish_rebase",
        &[RefCommand {
            name: input.reference,
            expected_old: ExpectedOld::Exactly(input.expected_source),
            proposed_new: ProposedNew::Update(input.expected_candidate),
            force: false,
        }],
        &admitted,
    )?;
    result.insert("publication_profile".into(), text("linear-rebase-v1"));
    // Onto and pack encoding are not part of the ref transaction's seal.
    // Name this as a submitted input, never a recovered validation assertion.
    result.insert("submitted_onto".into(), text(input.onto.to_string()));
    result.insert("replay_equivalence_verified".into(), Value::Bool(false));
    Ok(Value::Object(result))
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod integration_tests;
