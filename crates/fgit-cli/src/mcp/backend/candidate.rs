//! Non-publishing source-candidate work for the explicitly sponsored local MCP
//! profile. Repository bytes and commit metadata never select a principal.
mod prepare;
mod inspect;

use super::super::json::{self, Object, Value, object, text};
use super::super::protocol::{MAX_TOOL_RESULT, Tool, ToolError};
use super::pull_writes::{branch, oid};
use super::{NodeTools, hex, require_fields, string, unhex};
use fgit_types::{GitHashAlgorithm, GitOid, RefName};

pub(super) const NAME: &str = "frankengit_source_candidate";
// Match the existing source publisher's closed transport envelope. Tests send
// these exact chunks through that publisher; there is no implicit upload store.
const CHUNK_BYTES: usize = 8 * 1024;
const MAX_CHUNKS: usize = 3;
const MAX_BUNDLE_BYTES: usize = CHUNK_BYTES * MAX_CHUNKS;

pub(super) fn tool() -> Tool {
    Tool {
        name: NAME,
        description: "Prepare an exact patch into a bounded native Git bundle, or inspect an uploaded single-parent candidate at an exact visible branch/base. Inspection returns the actual full-tree diff and commit metadata, optionally snapshot-pinned. Read-only: no object import, checkout, shell, approval or publication. Publication requires the independent source-write tool and an original retry key.",
        schema: object([
            ("type", text("object")),
            ("oneOf", Value::Array(vec![prepare::schema(), inspect::schema()])),
        ]),
    }
}

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    // Also protect direct handler callers, before parsing or touching the node.
    if !backend.options.source {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let result = match required(args, "operation")? {
        "prepare_patch" => prepare::call(backend, args)?,
        "inspect" => inspect::call(backend, args)?,
        _ => return Err(ToolError::invalid("unsupported_candidate_operation")),
    };
    result
        .encode(MAX_TOOL_RESULT)
        .map_err(|_| ToolError::failed("candidate_response_limit"))?;
    Ok(result)
}

fn required<'a>(args: &'a Object, name: &str) -> Result<&'a str, ToolError> {
    string(args, name)?.ok_or(ToolError::invalid("required_argument_missing"))
}
fn raw_oid(id: GitOid) -> String {
    hex(id.as_bytes())
}
fn text_schema(maximum: usize) -> Value {
    object([
        ("type", text("string")),
        ("maxLength", json::number(maximum as u64)),
    ])
}
fn hex_schema(maximum: usize) -> Value {
    object([
        ("type", text("string")),
        ("minLength", json::number(2)),
        ("maxLength", json::number((maximum * 2) as u64)),
        ("pattern", text("^(?:[0-9a-f]{2})+$")),
    ])
}
fn chunk_schema() -> Value {
    object([
        ("type", text("array")),
        ("minItems", json::number(1)),
        ("maxItems", json::number(MAX_CHUNKS as u64)),
        ("items", hex_schema(CHUNK_BYTES)),
    ])
}
fn common_properties(operation: &str) -> Object {
    let mut properties = Object::new();
    properties.insert("operation".into(), object([("const", text(operation))]));
    properties.insert("reference".into(), text_schema(4096));
    properties.insert("reference_hex".into(), hex_schema(4096));
    properties.insert("expected_base".into(), oid_schema());
    properties
}
fn oid_schema() -> Value {
    object([
        ("type", text("string")),
        ("pattern", text("^(?:[0-9a-f]{40}|[0-9a-f]{64})$")),
        ("description", text("Exact nonzero native commit ID in the repository hash format.")),
    ])
}
fn exactly_one(a: &str, b: &str) -> Value {
    object([("oneOf", Value::Array(vec![
        object([("required", Value::Array(vec![text(a)]))]),
        object([("required", Value::Array(vec![text(b)]))]),
    ]))])
}
fn input_schema(properties: Object, required: &[&str], mut constraints: Vec<Value>) -> Value {
    constraints.push(exactly_one("reference", "reference_hex"));
    object([
        ("type", text("object")),
        ("properties", Value::Object(properties)),
        ("required", Value::Array(required.iter().map(|name| text(*name)).collect())),
        ("allOf", Value::Array(constraints)),
        ("additionalProperties", Value::Bool(false)),
    ])
}

/// Validate all fragments and aggregate size before allocating the byte buffer.
fn chunks(args: &Object, name: &str) -> Result<Vec<u8>, ToolError> {
    let Some(Value::Array(parts)) = args.get(name) else {
        return Err(ToolError::invalid("candidate_chunks_required"));
    };
    if parts.is_empty() || parts.len() > MAX_CHUNKS {
        return Err(ToolError::invalid("candidate_chunk_limit"));
    }
    let mut size = 0_usize;
    for part in parts {
        let value = part.text().ok_or(ToolError::invalid("invalid_candidate_chunk"))?;
        if value.is_empty() || value.len() > CHUNK_BYTES * 2
            || !value.len().is_multiple_of(2)
            || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ToolError::invalid("invalid_candidate_chunk"));
        }
        size = size.checked_add(value.len() / 2)
            .filter(|size| *size <= MAX_BUNDLE_BYTES)
            .ok_or(ToolError::invalid("candidate_byte_limit"))?;
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size).map_err(|_| ToolError::failed("allocation_refused"))?;
    for part in parts {
        bytes.extend(unhex(part.text().ok_or(ToolError::invalid("invalid_candidate_chunk"))?, CHUNK_BYTES)?);
    }
    Ok(bytes)
}
fn encoded_chunks(bytes: &[u8]) -> Result<Value, ToolError> {
    if bytes.is_empty() || bytes.len() > MAX_BUNDLE_BYTES {
        return Err(ToolError::failed("candidate_bundle_limit"));
    }
    Ok(Value::Array(bytes.chunks(CHUNK_BYTES).map(|part| text(hex(part))).collect()))
}
fn publication_arguments(reference: &RefName, base: GitOid, candidate: GitOid, bytes: &[u8]) -> Result<Value, ToolError> {
    Ok(object([
        ("reference_hex", text(hex(reference.as_bytes()))),
        ("expected_base", text(raw_oid(base))),
        ("expected_candidate", text(raw_oid(candidate))),
        ("bundle_hex_chunks", encoded_chunks(bytes)?),
    ]))
}
fn binding(backend: &NodeTools) -> Object {
    let Value::Object(fields) = object([
        ("tenant_id", text(backend.options.tenant.to_string())),
        ("repository_id", text(backend.options.repository.to_string())),
        ("repository_incarnation", text(backend.node.repository_incarnation_id().to_string())),
        ("object_format", text(backend.options.format.as_str())),
        ("read_only", Value::Bool(true)),
        ("repository_changed", Value::Bool(false)),
        ("published", Value::Bool(false)),
        ("approval_granted", Value::Bool(false)),
    ]) else { unreachable!() };
    fields
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod integration_tests;
