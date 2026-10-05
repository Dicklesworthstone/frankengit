//! One native batch scan, not repeated single-query calls with drifting roots.
use super::*;
use fgit_forge::source_search::batch::{
    MAX_BATCH_QUERIES, SourceQueryBatch, SourceSearchBatchReport,
};

const DEFAULT_MATCHES_PER_QUERY: usize = 5;
const MAX_BATCH_MATCHES: usize = 200;

pub(super) fn tool() -> Tool {
    Tool {
        name: BATCH_NAME,
        description: "Search up to 32 literal byte needles in one verified source scan. All results share an authority snapshot and file-read budget. Duplicate needles retain separate ordered slots; each slot reports its own completeness. Requires the source read grant; no index publication or host access.",
        schema: input_schema(),
    }
}

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    if !backend.options.source {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let (selection, queries) = parse(args, backend.options.format)?;
    let request = fgit_cli::command_request_context(&backend.node);
    let (source_head, report) = backend
        .node
        .runtime()
        .block_on(backend.node.search_source_batch_snapshot_local_in(
            &request,
            &selection.reference,
            selection.expected_head,
            selection.expected_commit,
            &queries,
            selection.limits,
        ))
        .map_err(read_error)?;
    let mut result = backend.header(source_head);
    result.extend(render(
        backend.options.repository,
        backend.options.format,
        source_head,
        &selection,
        &queries,
        &report,
    )?);
    bounded_result(result)
}

fn parse(
    args: &Object,
    format: GitHashAlgorithm,
) -> Result<(Selection, SourceQueryBatch), ToolError> {
    require_fields(args, &[
        "reference", "needles_hex", "path_prefixes_hex", "ignore_ascii_case",
        "expected_head", "expected_commit", "max_matches", "max_files",
        "max_file_bytes", "max_total_bytes",
    ])?;
    let mut selection = selection(args, format)?;
    if !args.contains_key("max_matches") {
        selection.limits.max_matches = DEFAULT_MATCHES_PER_QUERY;
    }
    let Some(Value::Array(values)) = args.get("needles_hex") else {
        return Err(ToolError::invalid("needles_required"));
    };
    if values.is_empty() || values.len() > MAX_BATCH_QUERIES {
        return Err(ToolError::invalid("invalid_search_query"));
    }
    if values.len().checked_mul(selection.limits.max_matches)
        .is_none_or(|count| count > MAX_BATCH_MATCHES)
    {
        return Err(ToolError::invalid("batch_match_limit"));
    }
    let (case, prefixes) = scope(args)?;
    let needles = values.iter().map(|value| {
        unhex(value.text().ok_or(ToolError::invalid("expected_string"))?, 256)
    }).collect::<Result<Vec<_>, _>>()?;
    let queries = SourceQueryBatch::new(&needles, case, &prefixes)
        .map_err(|_| ToolError::invalid("invalid_search_query"))?;
    Ok((selection, queries))
}

fn render(
    repository: RepositoryId,
    format: GitHashAlgorithm,
    source_head: RepositoryAuthorityHeadId,
    selection: &Selection,
    queries: &SourceQueryBatch,
    report: &SourceSearchBatchReport,
) -> Result<Object, ToolError> {
    if report.repository != repository {
        return Err(ToolError::failed("repository_binding_mismatch"));
    }
    validate_coordinates(format, source_head, selection, report.source_commit, report.source_tree)?;
    validate_work(selection.limits, report.files_selected, report.files_read, report.bytes_read, report.bytes_searched)?;
    if report.results.len() != queries.queries().len() {
        return Err(invalid_report());
    }
    let mut complete = true;
    let mut retained = 0;
    let mut total_matches = 0usize;
    let mut results = Vec::with_capacity(report.results.len());
    for (index, (query, observed)) in queries.queries().iter().zip(&report.results).enumerate() {
        if observed.needle.as_slice() != query.needle() {
            return Err(invalid_report());
        }
        let matches = render_matches(
            query, selection.limits, format, &observed.matches,
            observed.completion, &mut retained,
        )?;
        total_matches = total_matches.checked_add(matches.len())
            .filter(|count| *count <= MAX_BATCH_MATCHES)
            .ok_or_else(invalid_report)?;
        complete &= observed.completion == SearchCompletion::Complete;
        let Value::Object(mut slot) = object([
            ("query_index", text(index.to_string())),
            ("needle_hex", text(hex(query.needle()))),
            ("match_count", text(matches.len().to_string())),
            ("matches", Value::Array(matches)),
        ]) else { unreachable!() };
        completion_fields(&mut slot, observed.completion);
        results.push(Value::Object(slot));
    }
    // Even a single complete slot means the native collector searched every
    // selected file. No complete slot can be fabricated from an early stop.
    if report.results.iter().any(|slot| slot.completion == SearchCompletion::Complete)
        && report.files_read != report.files_selected
    {
        return Err(invalid_report());
    }
    let mut result = search_header(selection, queries.scope(), report.source_commit, report.source_tree);
    result.insert("profile".into(), text("literal-bytes-batch-v1"));
    result.insert("source_rcr".into(), text(report.source_rcr.to_string()));
    result.insert("query_count".into(), text(results.len().to_string()));
    result.insert("match_count".into(), text(total_matches.to_string()));
    result.insert("results".into(), Value::Array(results));
    completion_fields(&mut result, if complete {
        SearchCompletion::Complete
    } else {
        SearchCompletion::MatchLimit
    });
    // Native counters are shared batch totals, never summed once per needle.
    work_fields(&mut result, report.files_selected, report.files_read, report.bytes_read, report.bytes_searched, report.non_regular_entries);
    Ok(result)
}

fn input_schema() -> Value {
    let Value::Object(mut schema) = super::input_schema() else { unreachable!() };
    let Some(Value::Object(properties)) = schema.get_mut("properties") else { unreachable!() };
    properties.remove("needle_hex");
    properties.insert("needles_hex".into(), object([
        ("type", text("array")),
        ("minItems", json::number(1)),
        ("maxItems", json::number(MAX_BATCH_QUERIES as u64)),
        ("items", hex_schema(256)),
        ("description", text("Ordered literal byte needles. Duplicates keep separate result slots. No LF, regex, or implicit text decoding.")),
    ]));
    properties.insert("max_matches".into(), object([
        ("type", text("integer")),
        ("minimum", json::number(1)),
        ("maximum", json::number(MAX_MATCHES as u64)),
        ("default", json::number(DEFAULT_MATCHES_PER_QUERY as u64)),
        ("description", text("Per-query match ceiling. The number of needles multiplied by this ceiling must not exceed 200; resource exhaustion refuses the whole batch.")),
    ]));
    schema.insert("required".into(), Value::Array(vec![text("reference"), text("needles_hex")]));
    Value::Object(schema)
}

#[cfg(test)]
mod tests;
