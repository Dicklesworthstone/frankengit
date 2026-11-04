//! Closed replay inputs. Exact refs and commit IDs are independent selectors;
//! metadata and supplied resolution bytes are never capabilities.
use super::*;
use fgit_forge::preparation::resolution::validate_resolutions;

const LIMITS: &[(&str, usize, usize)] = &[
    ("max_commits", 4096, 4096),
    ("max_edges", 16_384, 16_384),
    ("max_tree_entries", 100_000, 100_000),
    ("max_preparation_bytes", 256 * 1024, 1024 * 1024),
];
pub(super) const COMMON_FIELDS: &[&str] = &[
    "operation", "profile", "direction", "reference", "reference_hex",
    "source_reference", "source_reference_hex", "expected_base", "expected_source",
    "selected_commit", "mainline", "expected_head", "author", "committer",
    "timestamp", "message_hex", "max_commits", "max_edges", "max_tree_entries",
    "max_preparation_bytes",
];

pub(super) struct Input {
    pub reference: RefName,
    pub source: RefName,
    pub request: ReplayRequest,
    pub expected_head: Option<RepositoryAuthorityHeadId>,
    pub metadata: MergeMetadata,
    pub limits: PreparationLimits,
    pub resolutions: Option<Vec<ConflictResolution>>,
}
impl Input {
    pub fn operation(&self) -> &'static str {
        if self.resolutions.is_some() { RESOLVE } else { PREPARE }
    }
}
fn bound(args: &Object, name: &str) -> Result<usize, ToolError> {
    let &(_, default, maximum) = LIMITS
        .iter()
        .find(|value| value.0 == name)
        .ok_or(ToolError::invalid("invalid_replay_limit"))?;
    let value = args.get(name).map(|value| {
        value.unsigned().ok_or(ToolError::invalid("invalid_replay_limit"))
    }).transpose()?.unwrap_or(default as u64);
    let value = usize::try_from(value)
        .map_err(|_| ToolError::invalid("invalid_replay_limit"))?;
    if value == 0 || value > maximum {
        return Err(ToolError::invalid("invalid_replay_limit"));
    }
    Ok(value)
}

pub(super) fn parse(args: &Object, format: GitHashAlgorithm) -> Result<Input, ToolError> {
    let resolving = match required(args, "operation")? {
        PREPARE => false,
        RESOLVE => true,
        _ => return Err(ToolError::invalid("unsupported_candidate_operation")),
    };
    let mut allowed = COMMON_FIELDS.to_vec();
    if resolving {
        allowed.push("resolutions");
    }
    require_fields(args, &allowed)?;
    if required(args, "profile")? != "path-v1" {
        return Err(ToolError::invalid("unsupported_replay_profile"));
    }
    let direction = match required(args, "direction")? {
        "cherry-pick" => ReplayDirection::CherryPick,
        "revert" => ReplayDirection::Revert,
        _ => return Err(ToolError::invalid("invalid_replay_direction")),
    };
    let mainline = args.get("mainline").map(|value| {
        value.unsigned()
            .and_then(|value| u16::try_from(value).ok())
            .filter(|value| *value > 0)
            .ok_or(ToolError::invalid("invalid_mainline"))
    }).transpose()?;
    let expected_head = head(args, 0)?;
    if resolving && expected_head.is_none() {
        return Err(ToolError::invalid("resolution_snapshot_required"));
    }
    let limits = PreparationLimits {
        max_commits: bound(args, "max_commits")?,
        max_edges: bound(args, "max_edges")?,
        max_tree_entries: bound(args, "max_tree_entries")?,
        max_output_bytes: bound(args, "max_preparation_bytes")?,
        max_conflicts: MAX_RESOLUTIONS,
        max_objects: 1024,
        ..PreparationLimits::default()
    };
    limits.validate().map_err(|_| ToolError::invalid("invalid_replay_limit"))?;
    let resolutions = if resolving {
        let choices = resolutions(args)?;
        validate_resolutions(&choices, limits)
            .map_err(|_| ToolError::invalid("invalid_resolution_set"))?;
        Some(choices)
    } else {
        None
    };
    Ok(Input {
        reference: branch(args, "reference", "reference_hex")?,
        source: branch(args, "source_reference", "source_reference_hex")?,
        request: ReplayRequest {
            direction,
            target: oid(args, "expected_base", format)?,
            source_tip: oid(args, "expected_source", format)?,
            selected_commit: oid(args, "selected_commit", format)?,
            mainline,
        },
        expected_head,
        metadata: super::super::prepare::metadata(args)?,
        limits,
        resolutions,
    })
}

fn length(value: &Value, maximum: usize) -> Result<usize, ToolError> {
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
fn charge(total: &mut usize, bytes: usize) -> Result<(), ToolError> {
    *total = total
        .checked_add(bytes)
        .filter(|value| *value <= MAX_BUNDLE_BYTES)
        .ok_or(ToolError::invalid("resolution_byte_limit"))?;
    Ok(())
}
pub(in super::super) fn resolutions(args: &Object) -> Result<Vec<ConflictResolution>, ToolError> {
    let Some(Value::Array(rows)) = args.get("resolutions") else {
        return Err(ToolError::invalid("resolutions_required"));
    };
    if rows.is_empty() || rows.len() > MAX_RESOLUTIONS {
        return Err(ToolError::invalid("resolution_count_limit"));
    }
    let mut total = 0_usize;
    for row in rows {
        let row = row
            .object()
            .ok_or(ToolError::invalid("invalid_resolution"))?;
        let choice = required(row, "choice")?;
        require_fields(
            row,
            if choice == "file" {
                &["path_hex", "choice", "mode", "bytes_hex_chunks"]
            } else {
                &["path_hex", "choice"]
            },
        )?;
        charge(
            &mut total,
            length(
                row.get("path_hex")
                    .ok_or(ToolError::invalid("resolution_path_required"))?,
                4096,
            )?,
        )?;
        match choice {
            "base" | "ours" | "theirs" | "delete" => {}
            "file" => {
                if !matches!(required(row, "mode")?, "100644" | "100755") {
                    return Err(ToolError::invalid("regular_file_mode_required"));
                }
                let Some(Value::Array(parts)) = row.get("bytes_hex_chunks") else {
                    return Err(ToolError::invalid("resolution_bytes_required"));
                };
                if parts.len() > MAX_CHUNKS {
                    return Err(ToolError::invalid("candidate_chunk_limit"));
                }
                // [] is an explicitly empty file, never an absent/deleted side.
                for part in parts {
                    charge(&mut total, length(part, CHUNK_BYTES)?)?;
                }
            }
            _ => return Err(ToolError::invalid("invalid_resolution_choice")),
        }
    }
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        let row = row
            .object()
            .ok_or(ToolError::invalid("invalid_resolution"))?;
        let choice = match required(row, "choice")? {
            "base" => ResolutionChoice::Base,
            "ours" => ResolutionChoice::Ours,
            "theirs" => ResolutionChoice::Theirs,
            "delete" => ResolutionChoice::Delete,
            "file" => {
                let empty = matches!(row.get("bytes_hex_chunks"), Some(Value::Array(parts)) if parts.is_empty());
                ResolutionChoice::File {
                    mode: match required(row, "mode")? {
                        "100644" => 0o100644,
                        "100755" => 0o100755,
                        _ => return Err(ToolError::invalid("regular_file_mode_required")),
                    },
                    bytes: if empty {
                        Vec::new()
                    } else {
                        chunks(row, "bytes_hex_chunks")?
                    },
                }
            }
            _ => return Err(ToolError::invalid("invalid_resolution_choice")),
        };
        result.push(ConflictResolution {
            path: unhex(required(row, "path_hex")?, 4096)?,
            choice,
        });
    }
    result.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(result)
}


pub(super) fn schema(resolving: bool) -> Value {
    let operation = if resolving { RESOLVE } else { PREPARE };
    let mut properties = common_properties(operation);
    properties.insert("profile".into(), object([("const", text("path-v1"))]));
    properties.insert("direction".into(), object([
        ("type", text("string")),
        ("enum", Value::Array(vec![text("cherry-pick"), text("revert")])),
    ]));
    properties.insert("source_reference".into(), text_schema(4096));
    properties.insert("source_reference_hex".into(), hex_schema(4096));
    for name in ["expected_source", "selected_commit"] {
        properties.insert(name.into(), oid_schema());
    }
    properties.insert("mainline".into(), object([
        ("type", text("integer")),
        ("minimum", json::number(1)),
        ("maximum", json::number(u16::MAX as u64)),
        ("description", text("One-based stored parent position. Required for a merge commit; omitted for a root; an ordinary commit defaults to one.")),
    ]));
    properties.insert("expected_head".into(), text_schema(140));
    for name in ["author", "committer"] {
        properties.insert(name.into(), text_schema(1024));
    }
    properties.insert("timestamp".into(), super::super::super::decimal_schema());
    properties.insert("message_hex".into(), hex_schema(4096));
    for &(name, default, maximum) in LIMITS {
        properties.insert(name.into(), object([
            ("type", text("integer")),
            ("minimum", json::number(1)),
            ("maximum", json::number(maximum as u64)),
            ("default", json::number(default as u64)),
        ]));
    }
    let mut required = vec![
        "operation", "profile", "direction", "expected_base", "expected_source",
        "selected_commit", "author", "committer", "timestamp", "message_hex",
    ];
    if resolving {
        properties.insert("resolutions".into(), resolution_schema());
        required.extend(["expected_head", "resolutions"]);
    }
    input_schema(
        properties,
        &required,
        vec![exactly_one("source_reference", "source_reference_hex")],
    )
}

pub(in super::super) fn resolution_schema() -> Value {
    let simple = object([
        ("type", text("object")),
        ("additionalProperties", Value::Bool(false)),
        (
            "required",
            Value::Array(vec![text("path_hex"), text("choice")]),
        ),
        (
            "properties",
            object([
                ("path_hex", hex_schema(4096)),
                (
                    "choice",
                    object([
                        ("type", text("string")),
                        (
                            "enum",
                            Value::Array(vec![
                                text("base"),
                                text("ours"),
                                text("theirs"),
                                text("delete"),
                            ]),
                        ),
                    ]),
                ),
            ]),
        ),
    ]);
    let file = object([
        ("type", text("object")),
        ("additionalProperties", Value::Bool(false)),
        (
            "required",
            Value::Array(vec![
                text("path_hex"),
                text("choice"),
                text("mode"),
                text("bytes_hex_chunks"),
            ]),
        ),
        (
            "properties",
            object([
                ("path_hex", hex_schema(4096)),
                ("choice", object([("const", text("file"))])),
                (
                    "mode",
                    object([
                        ("type", text("string")),
                        ("enum", Value::Array(vec![text("100644"), text("100755")])),
                    ]),
                ),
                (
                    "bytes_hex_chunks",
                    object([
                        ("type", text("array")),
                        ("minItems", json::number(0)),
                        ("maxItems", json::number(MAX_CHUNKS as u64)),
                        ("items", hex_schema(CHUNK_BYTES)),
                    ]),
                ),
            ]),
        ),
    ]);
    object([
        ("type", text("array")), ("minItems", json::number(1)), ("maxItems", json::number(MAX_RESOLUTIONS as u64)),
        ("items", object([("oneOf", Value::Array(vec![simple, file]))])),
        ("description", text("Every and only actual PathMergeV1 conflict. At most 24 KiB decoded paths plus file bytes in total. Explicit file [] means empty; a missing side is never deletion.")),
    ])
}
