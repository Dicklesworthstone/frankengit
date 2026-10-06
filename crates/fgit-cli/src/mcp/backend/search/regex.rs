//! Explicit native byte-regex reads. No index access, maintenance or fallback.
use super::*;
use fgit_forge::source_search::regex::{MAX_REGEX_STEPS, RegexQuery, RegexSearchReport};

const MAX_PATTERN_BYTES: usize = 256;

fn parse(args: &Object, format: GitHashAlgorithm) -> Result<(Selection, RegexQuery), ToolError> {
    require_fields(args, &[
        "operation", "reference", "pattern", "pattern_hex", "path_prefixes_hex",
        "ignore_ascii_case", "expected_head", "expected_commit", "max_matches",
        "max_files", "max_file_bytes", "max_total_bytes", "max_regex_steps",
    ])?;
    if string(args, "operation")? != Some("regex") {
        return Err(ToolError::invalid("unsupported_search_operation"));
    }
    let pattern = match (string(args, "pattern")?, string(args, "pattern_hex")?) {
        (Some(value), None) if !value.is_empty() && value.len() <= MAX_PATTERN_BYTES => value.as_bytes().to_vec(),
        (None, Some(value)) => unhex(value, MAX_PATTERN_BYTES)?,
        _ => return Err(ToolError::invalid("exactly_one_regex_pattern_required")),
    };
    let selected = selection(args, format)?;
    let (case, prefixes) = scope(args)?;
    let steps = bounded_number(args, "max_regex_steps", MAX_REGEX_STEPS as usize, MAX_REGEX_STEPS as usize)?;
    let query = RegexQuery::new(&pattern, case, &prefixes, steps as u64)
        .map_err(|_| ToolError::invalid("invalid_regex_query"))?;
    Ok((selected, query))
}

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    if !backend.options.source {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let (selected, query) = parse(args, backend.options.format)?;
    let request = fgit_cli::command_request_context(&backend.node);
    let (head, report) = backend.node.runtime().block_on(
        backend.node.search_source_regex_snapshot_local_in(
            &request, &selected.reference, selected.expected_head, selected.expected_commit,
            &query, selected.limits,
        ),
    ).map_err(read_error)?;
    let mut result = backend.header(head);
    result.extend(render(backend.options.repository, backend.options.format, head, &selected, &query, &report)?);
    bounded_result(result)
}

// Do not feed regex spans to the literal renderer: zero-width and long matches
// are legal, and a bounded excerpt need not contain the entire regex match.
fn render(repository: RepositoryId, format: GitHashAlgorithm, head: RepositoryAuthorityHeadId,
    selected: &Selection, query: &RegexQuery, report: &RegexSearchReport) -> Result<Object, ToolError>
{
    let source = &report.source;
    let invalid = || ToolError::failed("invalid_regex_report");
    validate_coordinates(format, head, selected, source.source_commit, source.source_tree)?;
    validate_work(selected.limits, source.files_selected, source.files_read, source.bytes_read, source.bytes_searched)?;
    if source.repository != repository || report.program_states != query.state_count()
        || report.steps > query.maximum_steps() || report.lines_searched > source.bytes_searched
        || source.matches.len() > selected.limits.max_matches
        || source.matches.len() > report.lines_searched
        || (source.completion == SearchCompletion::Complete
            && (source.files_selected != source.files_read || source.bytes_read != source.bytes_searched))
        || (source.completion == SearchCompletion::MatchLimit
            && (source.matches.len() != selected.limits.max_matches || report.lines_searched <= source.matches.len()))
        || source.matches.windows(2).any(|p| (&p[0].path, p[0].byte_offset) >= (&p[1].path, p[1].byte_offset)
            || (p[0].path == p[1].path && (p[0].line >= p[1].line || p[0].blob != p[1].blob)))
    { return Err(invalid()); }
    let mut retained = 0usize;
    let mut matches = Vec::with_capacity(source.matches.len());
    for found in &source.matches {
        let column = found.byte_column.checked_sub(1).ok_or_else(invalid)?;
        let line_start = found.byte_offset.checked_sub(column).ok_or_else(invalid)?;
        let end = found.byte_offset.checked_add(found.match_length).ok_or_else(invalid)?;
        let excerpt_end = found.excerpt_offset.checked_add(found.excerpt.len()).ok_or_else(invalid)?;
        if found.line == 0 || found.path.is_empty() || found.path.len() > 4096 || found.path.contains(&0)
            || found.path.split(|b| *b == b'/').any(|p| p.is_empty() || p == b"." || p == b"..")
            || found.blob.is_zero() || found.blob.algorithm() != format
            || found.excerpt.len() > 416 || found.excerpt.contains(&b'\n')
            || end > selected.limits.max_file_bytes || excerpt_end > selected.limits.max_file_bytes
            || found.byte_offset > excerpt_end
            || found.excerpt_offset != line_start + column.saturating_sub(80)
            || (!query.prefixes().is_empty() && !query.prefixes().iter().any(|p| {
                found.path == p.as_bytes() || found.path.strip_prefix(p.as_bytes()).is_some_and(|tail| tail.starts_with(b"/"))
            }))
        { return Err(invalid()); }
        retained = retained.checked_add(found.path.len() + found.excerpt.len())
            .filter(|n| *n <= MAX_RETAINED_BYTES).ok_or(ToolError::failed("resource_limit"))?;
        let full = end <= excerpt_end;
        let bytes = if full {
            let start = found.byte_offset.checked_sub(found.excerpt_offset).ok_or_else(invalid)?;
            let end = start.checked_add(found.match_length).ok_or_else(invalid)?;
            text(hex(found.excerpt.get(start..end).ok_or_else(invalid)?))
        } else { Value::Null };
        matches.push(object([
            ("path_hex", text(hex(&found.path))), ("blob", text(found.blob.to_string())),
            ("byte_offset", text(found.byte_offset.to_string())), ("match_length", text(found.match_length.to_string())),
            ("line", text(found.line.to_string())), ("byte_column", text(found.byte_column.to_string())),
            ("excerpt_offset", text(found.excerpt_offset.to_string())), ("excerpt_hex", text(hex(&found.excerpt))),
            ("excerpt_utf8", std::str::from_utf8(&found.excerpt).ok().map_or(Value::Null, text)),
            ("match_fully_in_excerpt", Value::Bool(full)), ("match_bytes_hex", bytes),
        ]));
    }
    let mut result = search_header(selected, query.source_scope(), source.source_commit, source.source_tree);
    result.extend([
        ("type".into(), text("source_regex_search")), ("operation".into(), text("regex")),
        ("profile".into(), text("line-byte-regex-v1")),
        ("match_semantics".into(), text("one_leftmost_longest_span_per_matching_lf_line")),
        ("pattern_hex".into(), text(hex(query.pattern()))),
        ("source_rcr".into(), text(source.source_rcr.to_string())),
        ("program_states".into(), text(report.program_states.to_string())),
        ("regex_steps".into(), text(report.steps.to_string())),
        ("max_regex_steps".into(), text(query.maximum_steps().to_string())),
        ("lines_searched".into(), text(report.lines_searched.to_string())),
        ("match_count".into(), text(source.matches.len().to_string())),
        ("matches".into(), Value::Array(matches)), ("repository_changed".into(), Value::Bool(false)),
    ]);
    completion_fields(&mut result, source.completion);
    work_fields(&mut result, source.files_selected, source.files_read, source.bytes_read, source.bytes_searched, source.non_regular_entries);
    Ok(result)
}

pub(super) fn schema(literal: Value) -> Value {
    let mut expression = literal.object().expect("literal object schema").clone();
    let mut properties = expression["properties"].object().expect("literal properties").clone();
    properties.remove("needle_hex");
    properties.insert("operation".into(), object([("const", text("regex"))]));
    properties.insert("pattern".into(), object([
        ("type", text("string")), ("minLength", json::number(1)),
        ("maxLength", json::number(MAX_PATTERN_BYTES as u64)),
        ("description", text("Native byte regex, at most 256 encoded bytes. No captures, backreferences or lookaround.")),
    ]));
    properties.insert("pattern_hex".into(), hex_schema(MAX_PATTERN_BYTES));
    properties.insert("max_regex_steps".into(), object([
        ("type", text("integer")), ("minimum", json::number(1)),
        ("maximum", json::number(MAX_REGEX_STEPS)), ("default", json::number(MAX_REGEX_STEPS)),
    ]));
    expression.insert("properties".into(), Value::Object(properties.clone()));
    expression.insert("required".into(), Value::Array(vec![text("operation"), text("reference")]));
    expression.insert("oneOf".into(), Value::Array(vec![
        object([("required", Value::Array(vec![text("pattern")]))]),
        object([("required", Value::Array(vec![text("pattern_hex")]))]),
    ]));
    properties.insert("needle_hex".into(), hex_schema(256));
    object([
        ("type", text("object")), ("properties", Value::Object(properties)),
        ("additionalProperties", Value::Bool(false)),
        ("oneOf", Value::Array(vec![literal, Value::Object(expression)])),
    ])
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod integration_tests;
