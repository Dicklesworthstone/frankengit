//! Closed resolution shape, all aggregate byte bounds checked before decoding.
use super::*;
use fgit_forge::preparation::{MergeMetadata, PreparationLimits};
use fgit_forge::preparation::resolution::validate_resolutions;

const MAX_RESOLUTIONS: usize = 64;
const LIMITS: &[(&str, usize, usize, usize)] = &[
    ("max_commits", 4096, 1, 4096),
    ("max_tree_entries", 100_000, 1, 100_000),
    ("max_preparation_bytes", 256 * 1024, 1, 1024 * 1024),
    ("max_review_bytes", 64 * 1024, 1, 128 * 1024),
    ("max_changes", 64, 1, 64),
    ("context_lines", 3, 0, 20),
    ("max_diff_work", 1_000_000, 1, 1_000_000),
];

pub(super) struct Input {
    pub selection: Selection,
    pub base: GitOid,
    pub resolutions: Vec<ConflictResolution>,
    pub metadata: MergeMetadata,
    pub limits: PreparationLimits,
    review: Object,
}
impl Input {
    pub fn inspection_limits(&self, args: &mut Object) { args.extend(self.review.clone()); }
}
fn bound(args: &Object, name: &str) -> Result<usize, ToolError> {
    let &(_, default, min, max) = LIMITS.iter().find(|value| value.0 == name)
        .ok_or(ToolError::invalid("invalid_resolution_limit"))?;
    let value = args.get(name).map(|value| value.unsigned()
        .ok_or(ToolError::invalid("invalid_resolution_limit"))).transpose()?.unwrap_or(default as u64);
    let value = usize::try_from(value).map_err(|_| ToolError::invalid("invalid_resolution_limit"))?;
    if !(min..=max).contains(&value) { return Err(ToolError::invalid("invalid_resolution_limit")); }
    Ok(value)
}
fn length(value: &Value, maximum: usize) -> Result<usize, ToolError> {
    let value = value.text().ok_or(ToolError::invalid("resolution_hex_required"))?;
    if value.is_empty() || !value.len().is_multiple_of(2) || value.len() > maximum * 2
        || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    { return Err(ToolError::invalid("invalid_resolution_hex")); }
    Ok(value.len() / 2)
}
fn charge(total: &mut usize, bytes: usize) -> Result<(), ToolError> {
    *total = total.checked_add(bytes).filter(|value| *value <= MAX_BUNDLE_BYTES)
        .ok_or(ToolError::invalid("resolution_byte_limit"))?;
    Ok(())
}
fn resolutions(args: &Object) -> Result<Vec<ConflictResolution>, ToolError> {
    let Some(Value::Array(rows)) = args.get("resolutions") else {
        return Err(ToolError::invalid("resolutions_required"));
    };
    if rows.is_empty() || rows.len() > MAX_RESOLUTIONS {
        return Err(ToolError::invalid("resolution_count_limit"));
    }
    let mut total = 0_usize;
    for row in rows {
        let row = row.object().ok_or(ToolError::invalid("invalid_resolution"))?;
        let choice = required(row, "choice")?;
        require_fields(row, if choice == "file" {
            &["path_hex", "choice", "mode", "bytes_hex_chunks"]
        } else { &["path_hex", "choice"] })?;
        charge(&mut total, length(row.get("path_hex").ok_or(ToolError::invalid("resolution_path_required"))?, 4096)?)?;
        match choice {
            "base" | "ours" | "theirs" | "delete" => {}
            "file" => {
                if !matches!(required(row, "mode")?, "100644" | "100755") {
                    return Err(ToolError::invalid("regular_file_mode_required"));
                }
                let Some(Value::Array(parts)) = row.get("bytes_hex_chunks") else {
                    return Err(ToolError::invalid("resolution_bytes_required"));
                };
                if parts.len() > MAX_CHUNKS { return Err(ToolError::invalid("candidate_chunk_limit")); }
                // [] is an explicitly empty file, never an absent/deleted side.
                for part in parts { charge(&mut total, length(part, CHUNK_BYTES)?)?; }
            }
            _ => return Err(ToolError::invalid("invalid_resolution_choice")),
        }
    }
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        let row = row.object().ok_or(ToolError::invalid("invalid_resolution"))?;
        let choice = match required(row, "choice")? {
            "base" => ResolutionChoice::Base, "ours" => ResolutionChoice::Ours,
            "theirs" => ResolutionChoice::Theirs, "delete" => ResolutionChoice::Delete,
            "file" => {
                let empty = matches!(row.get("bytes_hex_chunks"), Some(Value::Array(parts)) if parts.is_empty());
                ResolutionChoice::File {
                    mode: match required(row, "mode")? {
                        "100644" => 0o100644, "100755" => 0o100755,
                        _ => return Err(ToolError::invalid("regular_file_mode_required")),
                    },
                    bytes: if empty { Vec::new() } else { chunks(row, "bytes_hex_chunks")? },
                }
            }
            _ => return Err(ToolError::invalid("invalid_resolution_choice")),
        };
        result.push(ConflictResolution { path: unhex(required(row, "path_hex")?, 4096)?, choice });
    }
    result.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(result)
}

pub(super) fn parse(args: &Object, format: GitHashAlgorithm) -> Result<Input, ToolError> {
    let mut allowed = SUBJECT_FIELDS.to_vec();
    allowed.extend(["merge_base", "resolutions", "author", "committer", "timestamp", "message_hex"]);
    allowed.extend(LIMITS.iter().map(|limit| limit.0));
    require_fields(args, &allowed)?;
    if required(args, "operation")? != RESOLVE { return Err(ToolError::invalid("unsupported_candidate_operation")); }
    let limits = PreparationLimits {
        max_commits: bound(args, "max_commits")?,
        max_tree_entries: bound(args, "max_tree_entries")?,
        max_output_bytes: bound(args, "max_preparation_bytes")?,
        max_conflicts: MAX_RESOLUTIONS, max_objects: 1024,
        ..PreparationLimits::default()
    };
    let resolutions = resolutions(args)?;
    validate_resolutions(&resolutions, limits).map_err(|_| ToolError::invalid("invalid_resolution_set"))?;
    let mut review = Object::new();
    for (external, internal) in [
        ("max_review_bytes", "max_output_bytes"), ("max_changes", "max_changes"),
        ("context_lines", "context_lines"), ("max_diff_work", "max_diff_work"),
    ] {
        review.insert(internal.into(), json::number(bound(args, external)? as u64));
    }
    Ok(Input {
        selection: selection(args, format)?, base: oid(args, "merge_base", format)?, resolutions,
        metadata: super::super::super::prepare::metadata(args)?, limits, review,
    })
}

pub(super) fn schema() -> Value {
    let mut properties = subject_properties(RESOLVE);
    properties.insert("merge_base".into(), oid_schema());
    for name in ["author", "committer"] { properties.insert(name.into(), text_schema(1024)); }
    properties.insert("timestamp".into(), super::super::super::super::decimal_schema());
    properties.insert("message_hex".into(), hex_schema(4096));
    let simple = object([
        ("type", text("object")), ("additionalProperties", Value::Bool(false)),
        ("required", Value::Array(vec![text("path_hex"), text("choice")])),
        ("properties", object([
            ("path_hex", hex_schema(4096)),
            ("choice", object([("type", text("string")),
                ("enum", Value::Array(vec![text("base"), text("ours"), text("theirs"), text("delete")]))])),
        ])),
    ]);
    let file = object([
        ("type", text("object")), ("additionalProperties", Value::Bool(false)),
        ("required", Value::Array(vec![text("path_hex"), text("choice"), text("mode"), text("bytes_hex_chunks")])),
        ("properties", object([
            ("path_hex", hex_schema(4096)), ("choice", object([("const", text("file"))])),
            ("mode", object([("type", text("string")), ("enum", Value::Array(vec![text("100644"), text("100755")]))])),
            ("bytes_hex_chunks", object([("type", text("array")), ("minItems", json::number(0)),
                ("maxItems", json::number(MAX_CHUNKS as u64)), ("items", hex_schema(CHUNK_BYTES))])),
        ])),
    ]);
    properties.insert("resolutions".into(), object([
        ("type", text("array")), ("minItems", json::number(1)), ("maxItems", json::number(MAX_RESOLUTIONS as u64)),
        ("items", object([("oneOf", Value::Array(vec![simple, file]))])),
        ("description", text("Every and only actual PathMergeV1 conflict. At most 24 KiB decoded paths plus file bytes in total. Explicit file [] means empty; a missing side is never deletion.")),
    ]));
    for &(name, default, minimum, maximum) in LIMITS {
        properties.insert(name.into(), object([
            ("type", text("integer")), ("minimum", json::number(minimum as u64)),
            ("maximum", json::number(maximum as u64)), ("default", json::number(default as u64)),
        ]));
    }
    reviews::candidate_schema(properties, &[
        "operation", "number", "expected_version", "expected_source", "expected_target", "policy_epoch",
        "merge_base", "resolutions", "author", "committer", "timestamp", "message_hex",
    ])
}
