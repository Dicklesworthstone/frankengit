//! Closed raw-byte selectors and finite complete-result budgets.
use super::*;

pub(super) fn schema() -> Value {
    object([
        ("type", text("object")),
        (
            "properties",
            object([
                (
                    "reference",
                    object([
                        ("type", text("string")),
                        ("minLength", json::number(6)),
                        ("maxLength", json::number(MAX_REF_BYTES as u64)),
                        ("pattern", text("^refs/")),
                        (
                            "description",
                            text(
                                "Exact full visible refs/* name, at most 1024 UTF-8 bytes. Supply exactly one of reference/reference_hex.",
                            ),
                        ),
                    ]),
                ),
                (
                    "reference_hex",
                    object([
                        ("type", text("string")),
                        ("minLength", json::number(12)),
                        ("maxLength", json::number((MAX_REF_BYTES * 2) as u64)),
                        ("pattern", text("^(?:[0-9a-f]{2})+$")),
                        (
                            "description",
                            text(
                                "Exact full raw refs/* name as lowercase hex; at most 1024 decoded bytes. Mutually exclusive with reference.",
                            ),
                        ),
                    ]),
                ),
                (
                    "path_hex",
                    object([
                        ("type", text("string")),
                        ("minLength", json::number(2)),
                        ("maxLength", json::number((MAX_PATH_BYTES * 2) as u64)),
                        ("pattern", text("^(?:[0-9a-f]{2})+$")),
                        (
                            "description",
                            text(
                                "Exact repository byte path as lowercase hex, at most 4096 decoded bytes, 64 components and 255 bytes per component. Native validation rejects leading/trailing slashes and dot/empty components. Bytes are never normalized or interpreted as a host path.",
                            ),
                        ),
                    ]),
                ),
                (
                    "expected_head",
                    object([
                        ("type", text("string")),
                        ("maxLength", json::number(140)),
                        (
                            "description",
                            text(
                                "Required independently trusted algorithm-qualified authority head token. The response cannot supply its own trust pin; a moved current head refuses.",
                            ),
                        ),
                    ]),
                ),
                (
                    "max_blob_bytes",
                    object([
                        ("type", text("integer")),
                        ("minimum", json::number(1)),
                        ("maximum", json::number(MAX_BLOB_BYTES as u64)),
                        ("default", json::number(DEFAULT_BLOB_BYTES as u64)),
                        (
                            "description",
                            text(
                                "Complete blob allowance. A larger blob refuses with no bytes or partial proof; empty blobs remain valid.",
                            ),
                        ),
                    ]),
                ),
            ]),
        ),
        (
            "required",
            Value::Array(vec![text("path_hex"), text("expected_head")]),
        ),
        (
            "oneOf",
            Value::Array(vec![
                object([("required", Value::Array(vec![text("reference")]))]),
                object([("required", Value::Array(vec![text("reference_hex")]))]),
            ]),
        ),
        ("additionalProperties", Value::Bool(false)),
    ])
}

pub(super) fn parse(args: &Object) -> Result<Query, ToolError> {
    require_fields(
        args,
        &[
            "reference",
            "reference_hex",
            "path_hex",
            "expected_head",
            "max_blob_bytes",
        ],
    )?;
    let reference = match (string(args, "reference")?, string(args, "reference_hex")?) {
        (Some(name), None) if name.len() <= MAX_REF_BYTES => name.as_bytes().to_vec(),
        (None, Some(name)) => unhex(name, MAX_REF_BYTES)?,
        (Some(_), None) => return Err(ToolError::invalid("invalid_reference")),
        _ => {
            return Err(ToolError::invalid(
                "exactly_one_reference_encoding_required",
            ));
        }
    };
    if !reference.starts_with(b"refs/") {
        return Err(ToolError::invalid("full_reference_required"));
    }
    let reference =
        RefName::try_new(&reference).map_err(|_| ToolError::invalid("invalid_reference"))?;
    let path = unhex(
        string(args, "path_hex")?.ok_or(ToolError::invalid("path_required"))?,
        MAX_PATH_BYTES,
    )?;
    validate_blob_path(&path).map_err(|_| ToolError::invalid("invalid_blob_path"))?;
    let expected = string(args, "expected_head")?.ok_or(ToolError::invalid("snapshot_required"))?;
    if expected.len() > 140 {
        return Err(ToolError::invalid("invalid_snapshot_token"));
    }
    let expected_head = head(args, 0)?.ok_or(ToolError::invalid("snapshot_required"))?;
    let maximum = args
        .get("max_blob_bytes")
        .map(|value| {
            value
                .unsigned()
                .ok_or(ToolError::invalid("invalid_blob_limit"))
        })
        .transpose()?
        .unwrap_or(DEFAULT_BLOB_BYTES as u64);
    if !(1..=MAX_BLOB_BYTES as u64).contains(&maximum) {
        return Err(ToolError::invalid("invalid_blob_limit"));
    }
    Ok(Query {
        reference,
        path,
        expected_head,
        max_blob_bytes: maximum as usize,
    })
}
