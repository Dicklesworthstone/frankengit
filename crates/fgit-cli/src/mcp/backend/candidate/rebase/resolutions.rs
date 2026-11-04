//! Share replay's exact conflict-choice grammar; bind each set to an original
//! native commit and charge bytes and paths across the complete rebase series.
use super::*;

fn charge(
    total: &mut usize,
    amount: usize,
    maximum: usize,
    code: &'static str,
) -> Result<(), ToolError> {
    *total = total
        .checked_add(amount)
        .filter(|value| *value <= maximum)
        .ok_or(ToolError::invalid(code))?;
    Ok(())
}
fn encoded_length(value: &Value, maximum: usize) -> Result<usize, ToolError> {
    let value = value
        .text()
        .ok_or(ToolError::invalid("resolution_hex_required"))?;
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || value.len() > maximum * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ToolError::invalid("invalid_resolution_hex"));
    }
    Ok(value.len() / 2)
}
pub(super) fn parse(
    args: &Object,
    format: GitHashAlgorithm,
) -> Result<Vec<RebaseCommitResolution>, ToolError> {
    let Some(Value::Array(rows)) = args.get("resolutions") else {
        return Err(ToolError::invalid("resolutions_required"));
    };
    if rows.is_empty() || rows.len() > MAX_RESOLUTIONS {
        return Err(ToolError::invalid("resolution_count_limit"));
    }
    // Validate the entire envelope before cloning or decoding any replacement.
    let (mut count, mut bytes) = (0_usize, 0_usize);
    for row in rows {
        let row = row
            .object()
            .ok_or(ToolError::invalid("invalid_rebase_resolution"))?;
        require_fields(row, &["original", "paths"])?;
        oid(row, "original", format)?;
        let Some(Value::Array(paths)) = row.get("paths") else {
            return Err(ToolError::invalid("resolution_paths_required"));
        };
        if paths.is_empty() {
            return Err(ToolError::invalid("resolution_paths_required"));
        }
        charge(
            &mut count,
            paths.len(),
            MAX_RESOLUTIONS,
            "resolution_count_limit",
        )?;
        for path in paths {
            let path = path
                .object()
                .ok_or(ToolError::invalid("invalid_resolution"))?;
            charge(
                &mut bytes,
                encoded_length(
                    path.get("path_hex")
                        .ok_or(ToolError::invalid("resolution_path_required"))?,
                    4096,
                )?,
                MAX_BUNDLE_BYTES,
                "resolution_byte_limit",
            )?;
            if let Some(Value::Array(parts)) = path.get("bytes_hex_chunks") {
                if parts.len() > MAX_CHUNKS {
                    return Err(ToolError::invalid("candidate_chunk_limit"));
                }
                for part in parts {
                    charge(
                        &mut bytes,
                        encoded_length(part, CHUNK_BYTES)?,
                        MAX_BUNDLE_BYTES,
                        "resolution_byte_limit",
                    )?;
                }
            }
        }
    }
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        let row = row
            .object()
            .ok_or(ToolError::invalid("invalid_rebase_resolution"))?;
        let mut wrapped = Object::new();
        wrapped.insert(
            "resolutions".into(),
            row.get("paths")
                .ok_or(ToolError::invalid("resolution_paths_required"))?
                .clone(),
        );
        result.push(RebaseCommitResolution {
            original: oid(row, "original", format)?,
            paths: super::super::replay::input::resolutions(&wrapped)?,
        });
    }
    result.sort_by_key(|row| row.original);
    Ok(result)
}
pub(super) fn schema() -> Value {
    object([
        ("type", text("array")),
        ("minItems", json::number(1)),
        ("maxItems", json::number(MAX_RESOLUTIONS as u64)),
        (
            "items",
            object([
                ("type", text("object")),
                ("additionalProperties", Value::Bool(false)),
                (
                    "required",
                    Value::Array(vec![text("original"), text("paths")]),
                ),
                (
                    "properties",
                    object([
                        ("original", oid_schema()),
                        ("paths", super::super::replay::input::resolution_schema()),
                    ]),
                ),
            ]),
        ),
        (
            "description",
            text(
                "Decisions bind original commit IDs, not rewritten IDs or ordinals. At most 64 total paths and 24 KiB decoded paths plus replacement bytes across the whole series. Only supplied actual conflicts may resolve; future recipes may remain unused only when preparation stops without a candidate.",
            ),
        ),
    ])
}
