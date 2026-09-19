//! Source mutations are ordinary native receive admission, not MCP-local refs.
//! The launch sponsor grants writes explicitly; source bytes grant no authority.
use fgit_authority::{ExpectedOld, ProposedNew, RefCommand, TerminalOutcome};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, TxId};
use super::{NodeTools, hex, require_fields, unhex};
use super::{mutations as common, pull_writes::{branch, oid}};
use super::super::json::{self, Object, Value, object, text};
use super::super::protocol::{Tool, ToolError};

pub(super) const CREATE: &str = "frankengit_branch_create";
pub(super) const UPDATE: &str = "frankengit_branch_update";
pub(super) const DELETE: &str = "frankengit_branch_delete";
pub(super) const RENAME: &str = "frankengit_branch_rename";
pub(super) const PUBLISH: &str = "frankengit_source_publish";
const MAX_CHUNKS: usize = 3;
const CHUNK_BYTES: usize = 8 * 1024;
const MAX_BUNDLE_BYTES: usize = MAX_CHUNKS * CHUNK_BYTES;

pub(super) fn is_tool(name: &str) -> bool { matches!(name, CREATE | UPDATE | DELETE | RENAME | PUBLISH) }
pub(super) fn tools() -> Vec<Tool> {
    [
        (CREATE, "Create an absent branch at an explicit already-visible commit. Canonical mutation; cannot overwrite an existing branch or import an arbitrary object."),
        (UPDATE, "Move a branch from an exact expected tip to an already-visible commit through non-forced native admission. No implicit latest tip or protection bypass."),
        (DELETE, "Delete a branch at its exact expected tip. The native default-branch and current protection checks remain mandatory. Does not rewrite PR metadata."),
        (RENAME, "Atomically delete an exact-tip branch and create an absent destination at that SAME tip. No partial rename, overwrite, default-branch rename or PR retargeting."),
        (PUBLISH, "Publish a reviewed single-parent native Git bundle with an explicit branch, base and candidate commit. At most 24 KiB in three hex chunks. Native quarantine verifies objects before ordinary admission; no merge approval."),
    ].into_iter().map(|(name, description)| Tool { name, description, schema: schema(name) }).collect()
}
fn schema(name: &str) -> Value {
    let mut properties = Object::new();
    properties.insert("idempotency_key".into(), common::key_schema());
    let mut required = vec!["idempotency_key"];
    let mut pairs = vec![("reference", "reference_hex")];
    if name == RENAME { pairs.push(("destination", "destination_hex")); }
    for (plain, encoded) in &pairs {
        properties.insert((*plain).into(), object([("type", text("string")), ("maxLength", json::number(4096)),
            ("description", text("Full branch name, such as refs/heads/topic. Exactly one UTF-8 or _hex encoding is required."))]));
        properties.insert((*encoded).into(), object([("type", text("string")), ("maxLength", json::number(8192)),
            ("pattern", text("^(?:[0-9a-f]{2})+$"))]));
    }
    let pins: &[&str] = match name {
        CREATE => &["target"], UPDATE => &["expected_old", "target"],
        DELETE | RENAME => &["expected_old"], PUBLISH => &["expected_base", "expected_candidate"], _ => &[],
    };
    for pin in pins {
        required.push(*pin);
        properties.insert((*pin).into(), object([("type", text("string")), ("pattern", text("^(?:[0-9a-f]{40}|[0-9a-f]{64})$")),
            ("description", text("Exact nonzero native commit OID in the repository hash domain; not a latest-tip selector."))]));
    }
    if name == PUBLISH {
        required.push("bundle_hex_chunks");
        properties.insert("bundle_hex_chunks".into(), object([("type", text("array")),
            ("minItems", json::number(1)), ("maxItems", json::number(MAX_CHUNKS as u64)),
            ("items", object([("type", text("string")), ("minLength", json::number(2)),
                ("maxLength", json::number((CHUNK_BYTES * 2) as u64)), ("pattern", text("^(?:[0-9a-f]{2})+$"))])),
            ("description", text("Ordered chunks of ONE complete Git bundle, concatenated byte-for-byte. Each chunk is at most 8192 decoded bytes. No host file paths, URLs, partial uploads or ambient reads."))]));
    }
    let mut result = common::input_schema(properties, &required);
    if let Value::Object(fields) = &mut result {
        fields.insert("allOf".into(), Value::Array(pairs.into_iter().map(|(plain, encoded)| object([
            ("oneOf", Value::Array(vec![object([("required", Value::Array(vec![text(plain)]))]),
                object([("required", Value::Array(vec![text(encoded)]))])])),
        ])).collect()));
    }
    result
}
#[derive(Debug)]
struct Input { commands: Vec<RefCommand>, bundle: Option<Vec<u8>> }
fn bundle(args: &Object) -> Result<Vec<u8>, ToolError> {
    let Some(Value::Array(chunks)) = args.get("bundle_hex_chunks") else {
        return Err(ToolError::invalid("bundle_chunks_required"));
    };
    if chunks.is_empty() || chunks.len() > MAX_CHUNKS { return Err(ToolError::invalid("bundle_chunk_limit")); }
    // Validate every fragment and aggregate BEFORE reserving the complete body.
    let mut length = 0_usize;
    for chunk in chunks {
        let value = chunk.text().ok_or(ToolError::invalid("bundle_chunk_must_be_hex"))?;
        if value.is_empty() || value.len() % 2 != 0 || value.len() > CHUNK_BYTES * 2
            || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(ToolError::invalid("invalid_bundle_chunk"));
        }
        length = length.checked_add(value.len() / 2).filter(|n| *n <= MAX_BUNDLE_BYTES)
            .ok_or(ToolError::invalid("bundle_byte_limit"))?;
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|_| ToolError::failed("allocation_refused"))?;
    for chunk in chunks {
        let value = chunk.text().ok_or(ToolError::invalid("bundle_chunk_must_be_hex"))?;
        bytes.extend_from_slice(&unhex(value, CHUNK_BYTES)?);
    }
    Ok(bytes)
}
fn parse(name: &str, args: &Object, format: GitHashAlgorithm) -> Result<Input, ToolError> {
    let allowed: &[&str] = match name {
        CREATE => &["reference", "reference_hex", "target", "idempotency_key"],
        UPDATE => &["reference", "reference_hex", "expected_old", "target", "idempotency_key"],
        DELETE => &["reference", "reference_hex", "expected_old", "idempotency_key"],
        RENAME => &["reference", "reference_hex", "destination", "destination_hex", "expected_old", "idempotency_key"],
        PUBLISH => &["reference", "reference_hex", "expected_base", "expected_candidate", "bundle_hex_chunks", "idempotency_key"],
        _ => return Err(ToolError::invalid("tool_not_granted")),
    };
    require_fields(args, allowed)?;
    let reference = branch(args, "reference", "reference_hex")?;
    let (old, new) = match name {
        CREATE => (ExpectedOld::Absent, ProposedNew::Update(oid(args, "target", format)?)),
        UPDATE | PUBLISH => {
            let (a, b) = if name == PUBLISH { ("expected_base", "expected_candidate") } else { ("expected_old", "target") };
            let old = oid(args, a, format)?; let new = oid(args, b, format)?;
            if old == new { return Err(ToolError::invalid("source_transition_must_change_tip")); }
            (ExpectedOld::Exactly(old), ProposedNew::Update(new))
        }
        DELETE | RENAME => (ExpectedOld::Exactly(oid(args, "expected_old", format)?), ProposedNew::Delete),
        _ => return Err(ToolError::invalid("tool_not_granted")),
    };
    let mut commands = vec![RefCommand { name: reference.clone(), expected_old: old, proposed_new: new, force: false }];
    if name == RENAME {
        let destination = branch(args, "destination", "destination_hex")?;
        if destination == reference { return Err(ToolError::invalid("rename_requires_distinct_branches")); }
        let ExpectedOld::Exactly(tip) = old else { return Err(ToolError::invalid("exact_tip_required")); };
        commands.push(RefCommand { name: destination, expected_old: ExpectedOld::Absent,
            proposed_new: ProposedNew::Update(tip), force: false });
    }
    let bundle = if name == PUBLISH { Some(bundle(args)?) } else { None };
    Ok(Input { commands, bundle })
}
pub(super) fn call(backend: &NodeTools, name: &str, args: &Object) -> Result<Value, ToolError> {
    if !backend.options.writes.source || !is_tool(name) { return Err(ToolError::invalid("tool_not_granted")); }
    let key = common::key(args)?;
    let input = parse(name, args, backend.options.format)?;
    let session = common::session(backend, key)?;
    let principal = session.authenticated_session().ok_or(ToolError::invalid("principal_not_bound"))?.principal_id();
    let request = backend.node.request_context();
    let admitted = if let Some(bytes) = &input.bundle {
        let command = &input.commands[0];
        let (ExpectedOld::Exactly(base), ProposedNew::Update(candidate)) = (command.expected_old, command.proposed_new)
            else { return Err(ToolError::invalid("invalid_publication_shape")); };
        backend.node.runtime().block_on(backend.node.apply_workspace_bundle_durable_in(
            &request, principal, common::required(args, "idempotency_key")?.as_bytes(),
            &command.name, base, candidate, bytes,
        ))
    } else {
        backend.node.runtime().block_on(backend.node.admit_branch_updates_durable_in(
            &request, &session, &input.commands, Default::default(),
        ))
    }.map_err(|_| ToolError::uncertain("source_mutation_outcome_unknown"))?;
    // An atomic result must have ONE verified decision for every submitted ref.
    // Do not accept a per-command partial result as a successful rename.
    let observations: Vec<_> = admitted.commands.iter().map(|c| (c.tx_id, c.terminal)).collect();
    let (tx, terminal) = atomic_terminal(admitted.session.atomic, &admitted.session.tx_ids,
        &observations, input.commands.len())?;
    let mut result = common::binding(backend, principal, false);
    result.extend(common::terminal(tx, &terminal));
    result.insert("type".into(), text("source_publication"));
    result.insert("action".into(), text(match name { CREATE => "create", UPDATE => "update", DELETE => "delete", RENAME => "rename", _ => "publish" }));
    result.insert("atomic".into(), Value::Bool(true));
    result.insert("complete".into(), Value::Bool(true));
    result.insert("historical_outcome".into(), Value::Bool(true));
    result.insert("current_refs_asserted".into(), Value::Bool(false));
    result.insert("ref_transaction_committed".into(), Value::Bool(matches!(terminal.outcome, DecisionOutcome::Committed { .. })));
    result.insert("submitted_commands".into(), Value::Array(input.commands.iter().map(|c| object([
        ("reference_hex", text(hex(c.name.as_bytes()))),
        ("expected_old", match c.expected_old { ExpectedOld::Exactly(id) => text(id.to_string()), _ => Value::Null }),
        ("proposed_new", match c.proposed_new { ProposedNew::Update(id) => text(id.to_string()), ProposedNew::Delete => Value::Null }),
        ("force", Value::Bool(false)),
    ])).collect()));
    // A recovered decision does not attest a newly supplied pack encoding.
    result.insert("bundle_validation_receipt".into(), Value::Null);
    Ok(Value::Object(result))
}
fn atomic_terminal(atomic: bool, ids: &[TxId], observations: &[(TxId, TerminalOutcome)], expected: usize)
    -> Result<(TxId, TerminalOutcome), ToolError> {
    let invalid = || ToolError::uncertain("inconsistent_atomic_outcome");
    let first = observations.first().copied().ok_or_else(invalid)?;
    if !atomic || !(1..=2).contains(&expected) || observations.len() != expected
        || ids != [first.0] || observations.iter().any(|entry| *entry != first) {
        return Err(invalid());
    }
    Ok(first)
}
#[cfg(test)]
mod tests;
#[cfg(test)]
mod integration_tests;
