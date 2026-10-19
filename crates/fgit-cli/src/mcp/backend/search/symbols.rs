//! Rust declaration-head search over one verified snapshot: the same native
//! reader as `fg search --symbols`. Not compiler name resolution; no index is
//! read, built or refreshed, and no source is executed.
use super::*;
use fgit_forge::source_symbols::{
    MAX_SYMBOL_WORK, PROFILE, SymbolKind, SymbolMatch, SymbolMatchMode, SymbolQuery,
    SymbolReadError, SymbolSearchReport,
};

pub(in super::super) const NAME: &str = "frankengit_source_symbols";
const MAX_KINDS: usize = 8;
const MAX_NAME_BYTES: usize = 256;

pub(super) fn tool() -> Tool {
    Tool {
        name: NAME,
        description: "Find Rust declaration heads (function, struct, enum, trait, type, module, union, macro) by exact or prefix ASCII name in .rs files of a visible ref, from one authority snapshot. Paths and spans are exact bytes. Not compiler name resolution: attributes and macro bodies are opaque and all cfg branches are searched. Malformed Rust refuses the read; a match ceiling returns an explicitly incomplete prefix.",
        schema: input_schema(),
    }
}

fn kind(value: &str) -> Option<SymbolKind> {
    Some(match value {
        "function" => SymbolKind::Function,
        "struct" => SymbolKind::Struct,
        "enum" => SymbolKind::Enum,
        "trait" => SymbolKind::Trait,
        "type" => SymbolKind::Type,
        "module" => SymbolKind::Module,
        "union" => SymbolKind::Union,
        "macro" => SymbolKind::Macro,
        _ => return None,
    })
}

fn parse(args: &Object, format: GitHashAlgorithm) -> Result<(Selection, SymbolQuery), ToolError> {
    require_fields(
        args,
        &[
            "reference",
            "name",
            "match",
            "kinds",
            "path_prefixes_hex",
            "expected_head",
            "expected_commit",
            "max_matches",
            "max_files",
            "max_file_bytes",
            "max_total_bytes",
            "max_work",
        ],
    )?;
    let selected = selection(args, format)?;
    let name = string(args, "name")?.ok_or(ToolError::invalid("name_required"))?;
    if name.len() > MAX_NAME_BYTES {
        return Err(ToolError::invalid("invalid_symbol_query"));
    }
    let mode = match string(args, "match")? {
        None | Some("exact") => SymbolMatchMode::Exact,
        Some("prefix") => SymbolMatchMode::Prefix,
        Some(_) => return Err(ToolError::invalid("invalid_match_mode")),
    };
    let mut kinds = Vec::new();
    if let Some(value) = args.get("kinds") {
        let Value::Array(values) = value else {
            return Err(ToolError::invalid("invalid_symbol_kinds"));
        };
        if values.len() > MAX_KINDS {
            return Err(ToolError::invalid("invalid_symbol_kinds"));
        }
        for value in values {
            kinds.push(
                value
                    .text()
                    .and_then(kind)
                    .ok_or(ToolError::invalid("invalid_symbol_kinds"))?,
            );
        }
    }
    // No ignore_ascii_case is admitted above, so only the path prefixes apply.
    let (_, prefixes) = scope(args)?;
    let work = args
        .get("max_work")
        .map(|value| value.unsigned().ok_or(ToolError::invalid("invalid_limit")))
        .transpose()?
        .unwrap_or(MAX_SYMBOL_WORK);
    if work == 0 || work > MAX_SYMBOL_WORK {
        return Err(ToolError::invalid("invalid_limit"));
    }
    let query = SymbolQuery::new(name.as_bytes(), mode, &kinds, &prefixes, work)
        .map_err(|_| ToolError::invalid("invalid_symbol_query"))?;
    Ok((selected, query))
}

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    if !backend.options.source {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let (selected, query) = parse(args, backend.options.format)?;
    let request = fgit_cli::command_request_context(&backend.node);
    let (head, report) = backend
        .node
        .runtime()
        .block_on(backend.node.search_source_symbols_snapshot_local_in(
            &request,
            &selected.reference,
            selected.expected_head,
            selected.expected_commit,
            &query,
            selected.limits,
        ))
        .map_err(|error| match error {
            SymbolReadError::Source(error) => read_error(error),
            // The CLI names the path and offset; a tool code stays static.
            SymbolReadError::Syntax { .. } => ToolError::failed("unsupported_rust_source"),
        })?;
    let mut result = backend.header(head);
    result.extend(render(
        backend.options.repository,
        backend.options.format,
        head,
        &selected,
        &query,
        &report,
    )?);
    bounded_result(result)
}

fn accepted(query: &SymbolQuery, hit: &SymbolMatch) -> bool {
    (query.kinds().is_empty() || query.kinds().contains(&hit.kind))
        && match query.mode() {
            SymbolMatchMode::Exact => hit.name == query.name(),
            SymbolMatchMode::Prefix => hit.name.starts_with(query.name()),
        }
}

fn render(
    repository: RepositoryId,
    format: GitHashAlgorithm,
    head: RepositoryAuthorityHeadId,
    selected: &Selection,
    query: &SymbolQuery,
    report: &SymbolSearchReport,
) -> Result<Object, ToolError> {
    if report.repository != repository {
        return Err(ToolError::failed("repository_binding_mismatch"));
    }
    validate_coordinates(
        format,
        head,
        selected,
        report.source_commit,
        report.source_tree,
    )?;
    validate_work(
        selected.limits,
        report.files_selected,
        report.files_read,
        report.bytes_read,
        report.bytes_searched,
    )?;
    let scope = query.source_scope();
    if report.matches.len() > selected.limits.max_matches
        || report.work_units > query.maximum_work()
        || (report.completion == SearchCompletion::MatchLimit
            && report.matches.len() != selected.limits.max_matches)
        // Every selected file is either read (.rs) or counted as unsupported.
        || (report.completion == SearchCompletion::Complete
            && report.files_read.checked_add(report.unsupported_language_files)
                != Some(report.files_selected))
        || report.matches.windows(2).any(|pair| {
            (&pair[0].location.path, pair[0].location.byte_offset)
                >= (&pair[1].location.path, pair[1].location.byte_offset)
        })
    {
        return Err(invalid_report());
    }
    let mut retained = 0usize;
    let mut matches = Vec::with_capacity(report.matches.len());
    for hit in &report.matches {
        let found = &hit.location;
        let start = found
            .byte_offset
            .checked_sub(found.excerpt_offset)
            .ok_or_else(invalid_report)?;
        let end = start
            .checked_add(found.match_length)
            .ok_or_else(invalid_report)?;
        if !accepted(query, hit)
            || found.match_length != hit.name.len()
            || found.excerpt.get(start..end) != Some(hit.name.as_slice())
            || found.path.is_empty()
            || found.path.len() > 4096
            || found.path.contains(&0)
            || found
                .path
                .split(|b| *b == b'/')
                .any(|part| part.is_empty() || part == b"." || part == b"..")
            || !found.path.ends_with(b".rs")
            || found.blob.is_zero()
            || found.blob.algorithm() != format
            || found.line == 0
            || found.byte_column == 0
            || found.byte_column - 1 > found.byte_offset
            || (!scope.prefixes().is_empty()
                && !scope.prefixes().iter().any(|prefix| {
                    let prefix = prefix.as_bytes();
                    found.path.as_slice() == prefix
                        || found
                            .path
                            .strip_prefix(prefix)
                            .is_some_and(|tail| tail.starts_with(b"/"))
                }))
        {
            return Err(invalid_report());
        }
        retained = retained
            .checked_add(found.path.len() + found.excerpt.len())
            .filter(|n| *n <= MAX_RETAINED_BYTES)
            .ok_or(ToolError::failed("resource_limit"))?;
        matches.push(object([
            ("name_hex", text(hex(&hit.name))),
            (
                "name",
                std::str::from_utf8(&hit.name).map_or(Value::Null, text),
            ),
            ("kind", text(hit.kind.as_str())),
            ("raw_identifier", Value::Bool(hit.raw_identifier)),
            ("path_hex", text(hex(&found.path))),
            ("blob", text(found.blob.to_string())),
            ("byte_offset", text(found.byte_offset.to_string())),
            ("line", text(found.line.to_string())),
            ("byte_column", text(found.byte_column.to_string())),
            ("match_length", text(found.match_length.to_string())),
            ("excerpt_offset", text(found.excerpt_offset.to_string())),
            ("excerpt_hex", text(hex(&found.excerpt))),
            (
                "excerpt_utf8",
                std::str::from_utf8(&found.excerpt)
                    .ok()
                    .map_or(Value::Null, text),
            ),
        ]));
    }
    let mut result = search_header(selected, scope, report.source_commit, report.source_tree);
    result.extend([
        ("type".into(), text("source_symbol_search")),
        ("profile".into(), text(PROFILE)),
        ("source_rcr".into(), text(report.source_rcr.to_string())),
        ("name_hex".into(), text(hex(query.name()))),
        (
            "match_mode".into(),
            text(match query.mode() {
                SymbolMatchMode::Exact => "exact",
                SymbolMatchMode::Prefix => "prefix",
            }),
        ),
        (
            "kinds".into(),
            Value::Array(
                query
                    .kinds()
                    .iter()
                    .map(|kind| text(kind.as_str()))
                    .collect(),
            ),
        ),
        ("matches".into(), Value::Array(matches)),
        ("match_count".into(), text(report.matches.len().to_string())),
        (
            "declarations_examined".into(),
            text(report.declarations_examined.to_string()),
        ),
        (
            "unsupported_language_files".into(),
            text(report.unsupported_language_files.to_string()),
        ),
        (
            "macro_bodies_skipped".into(),
            text(report.macro_bodies_skipped.to_string()),
        ),
        (
            "attributes_skipped".into(),
            text(report.attributes_skipped.to_string()),
        ),
        ("work_units".into(), text(report.work_units.to_string())),
        ("max_work".into(), text(query.maximum_work().to_string())),
        ("repository_changed".into(), Value::Bool(false)),
        ("index_changed".into(), Value::Bool(false)),
    ]);
    // The literal header's case is meaningless for declaration names.
    result.remove("case");
    completion_fields(&mut result, report.completion);
    work_fields(
        &mut result,
        report.files_selected,
        report.files_read,
        report.bytes_read,
        report.bytes_searched,
        report.non_regular_entries,
    );
    Ok(result)
}

fn input_schema() -> Value {
    let base = super::input_schema();
    let mut properties = base.object().expect("literal object schema")["properties"]
        .object()
        .expect("literal properties")
        .clone();
    properties.remove("needle_hex");
    properties.remove("ignore_ascii_case");
    properties.insert(
        "name".into(),
        object([
            ("type", text("string")),
            ("minLength", json::number(1)),
            ("maxLength", json::number(MAX_NAME_BYTES as u64)),
            ("pattern", text("^[A-Za-z_][A-Za-z0-9_]*$")),
            (
                "description",
                text("Case-sensitive ASCII identifier, without an r# prefix."),
            ),
        ]),
    );
    properties.insert(
        "match".into(),
        object([
            ("type", text("string")),
            ("enum", Value::Array(vec![text("exact"), text("prefix")])),
            ("default", text("exact")),
        ]),
    );
    properties.insert(
        "kinds".into(),
        object([
            ("type", text("array")),
            ("maxItems", json::number(MAX_KINDS as u64)),
            (
                "items",
                object([(
                    "enum",
                    Value::Array(
                        [
                            "function", "struct", "enum", "trait", "type", "module", "union",
                            "macro",
                        ]
                        .into_iter()
                        .map(text)
                        .collect(),
                    ),
                )]),
            ),
        ]),
    );
    properties.insert(
        "max_work".into(),
        object([
            ("type", text("integer")),
            ("minimum", json::number(1)),
            ("maximum", json::number(MAX_SYMBOL_WORK)),
            ("default", json::number(MAX_SYMBOL_WORK)),
        ]),
    );
    object([
        ("type", text("object")),
        ("properties", Value::Object(properties)),
        (
            "required",
            Value::Array(vec![text("reference"), text("name")]),
        ),
        ("additionalProperties", Value::Bool(false)),
    ])
}

#[cfg(test)]
mod tests;
