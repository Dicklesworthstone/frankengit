//! Operator-granted source retrieval over the node's single-snapshot reader.
//! Query paths narrow the launch grant; they never mint authority or host access.
mod batch;

use super::*;
use fgit_forge::source_browse::SourceBrowseError;
use fgit_forge::source_search::{
    SearchCase, SearchCompletion, SearchError, SearchLimits, SourceMatch, SourceQuery,
    SourceSearchReport,
};
use fgit_node::NodeWorkspaceRefusal;
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RepositoryId};

pub(super) const NAME: &str = "frankengit_source_search";
pub(super) const BATCH_NAME: &str = "frankengit_source_search_batch";
const MAX_RESULT_BYTES: usize = 1024 * 1024;
const MAX_RETAINED_BYTES: usize = 256 * 1024;
const MAX_MATCHES: usize = 100;

pub(super) fn tools() -> Vec<Tool> {
    vec![Tool {
        name: NAME,
        description: "Search exact literal bytes in regular files of a visible ref. One authority snapshot; optional ASCII case folding and slash-bounded path prefixes. No regex, checkout, host paths, symlink following, or implicit binary exclusion. A match ceiling returns an explicitly incomplete prefix, not an exhaustive answer.",
        schema: input_schema(),
    }, batch::tool()]
}

pub(super) fn call_batch(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    batch::call(backend, args)
}

struct Selection {
    reference: RefName,
    expected_head: Option<RepositoryAuthorityHeadId>,
    expected_commit: Option<GitOid>,
    limits: SearchLimits,
}

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    // This defense remains in the adapter as well as the immutable registry.
    if !backend.options.source {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let (selection, query) = parse(args, backend.options.format)?;
    let request = fgit_cli::command_request_context(&backend.node);
    let (source_head, report) = backend
        .node
        .runtime()
        .block_on(backend.node.search_source_snapshot_local_in(
            &request,
            &selection.reference,
            selection.expected_head,
            selection.expected_commit,
            &query,
            selection.limits,
        ))
        .map_err(read_error)?;
    let mut result = backend.header(source_head);
    result.extend(render(
        backend.options.repository,
        backend.options.format,
        source_head,
        &selection,
        &query,
        &report,
    )?);
    bounded_result(result)
}

fn parse(args: &Object, format: GitHashAlgorithm) -> Result<(Selection, SourceQuery), ToolError> {
    require_fields(args, &[
        "reference", "needle_hex", "path_prefixes_hex", "ignore_ascii_case",
        "expected_head", "expected_commit", "max_matches", "max_files",
        "max_file_bytes", "max_total_bytes",
    ])?;
    let selection = selection(args, format)?;
    let (case, prefixes) = scope(args)?;
    let needle = string(args, "needle_hex")?.ok_or(ToolError::invalid("needle_required"))?;
    let query = SourceQuery::new(&unhex(needle, 256)?, case, &prefixes)
        .map_err(|_| ToolError::invalid("invalid_search_query"))?;
    Ok((selection, query))
}

fn selection(args: &Object, format: GitHashAlgorithm) -> Result<Selection, ToolError> {
    let reference = string(args, "reference")?.ok_or(ToolError::invalid("reference_required"))?;
    if reference.len() > 4096 || !reference.starts_with("refs/") {
        return Err(ToolError::invalid("invalid_reference"));
    }
    let reference = RefName::try_new(reference.as_bytes())
        .map_err(|_| ToolError::invalid("invalid_reference"))?;
    let expected_head = head(args, 0)?;
    let expected_commit = string(args, "expected_commit")?
        .map(|value| {
            if !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
                return Err(ToolError::invalid("invalid_expected_commit"));
            }
            let id = GitOid::from_hex(format, value)
                .map_err(|_| ToolError::invalid("invalid_expected_commit"))?;
            if id.is_zero() {
                return Err(ToolError::invalid("invalid_expected_commit"));
            }
            Ok(id)
        })
        .transpose()?;
    let limits = SearchLimits {
        max_matches: bounded_number(args, "max_matches", 20, MAX_MATCHES)?,
        max_files: bounded_number(args, "max_files", 2000, 20_000)?,
        max_file_bytes: bounded_number(args, "max_file_bytes", 1024 * 1024, 8 * 1024 * 1024)?,
        max_total_bytes: bounded_number(args, "max_total_bytes", 8 * 1024 * 1024, 64 * 1024 * 1024)?,
        ..SearchLimits::default()
    };
    limits.validate().map_err(|_| ToolError::invalid("invalid_limit"))?;
    Ok(Selection { reference, expected_head, expected_commit, limits })
}

fn bounded_number(args: &Object, name: &str, default: usize, maximum: usize) -> Result<usize, ToolError> {
    let value = args.get(name)
        .map(|v| v.unsigned().ok_or(ToolError::invalid("invalid_limit")))
        .transpose()?
        .unwrap_or(default as u64);
    if value == 0 || value > maximum as u64 {
        return Err(ToolError::invalid("invalid_limit"));
    }
    usize::try_from(value).map_err(|_| ToolError::invalid("invalid_limit"))
}

fn scope(args: &Object) -> Result<(SearchCase, Vec<Vec<u8>>), ToolError> {
    let case = match args.get("ignore_ascii_case") {
        None | Some(Value::Bool(false)) => SearchCase::Exact,
        Some(Value::Bool(true)) => SearchCase::AsciiInsensitive,
        Some(_) => return Err(ToolError::invalid("expected_boolean")),
    };
    let mut prefixes = Vec::new();
    if let Some(value) = args.get("path_prefixes_hex") {
        let Value::Array(values) = value else {
            return Err(ToolError::invalid("invalid_path_prefixes"));
        };
        if values.len() > 32 {
            return Err(ToolError::invalid("invalid_path_prefixes"));
        }
        let mut total = 0usize;
        for value in values {
            let raw = value.text().ok_or(ToolError::invalid("expected_string"))?;
            let bytes = unhex(raw, 4096)?;
            total += bytes.len();
            if total > 16 * 1024 {
                return Err(ToolError::invalid("invalid_path_prefixes"));
            }
            prefixes.push(bytes);
        }
    }
    Ok((case, prefixes))
}

fn invalid_report() -> ToolError {
    ToolError::failed("invalid_search_report")
}

fn validate_coordinates(
    format: GitHashAlgorithm,
    source_head: RepositoryAuthorityHeadId,
    selection: &Selection,
    commit: GitOid,
    tree: GitOid,
) -> Result<(), ToolError> {
    if selection.expected_head.is_some_and(|head| head != source_head)
        || selection.expected_commit.is_some_and(|id| id != commit)
        || [commit, tree].iter().any(|id| id.is_zero() || id.algorithm() != format)
    {
        return Err(invalid_report());
    }
    Ok(())
}

fn validate_work(
    limits: SearchLimits,
    selected: usize,
    read: usize,
    bytes: usize,
    searched: usize,
) -> Result<(), ToolError> {
    if read > selected || selected > limits.max_files || bytes > limits.max_total_bytes || searched > bytes {
        return Err(invalid_report());
    }
    Ok(())
}

fn render(
    repository: RepositoryId,
    format: GitHashAlgorithm,
    source_head: RepositoryAuthorityHeadId,
    selection: &Selection,
    query: &SourceQuery,
    report: &SourceSearchReport,
) -> Result<Object, ToolError> {
    if report.repository != repository {
        return Err(ToolError::failed("repository_binding_mismatch"));
    }
    validate_coordinates(format, source_head, selection, report.source_commit, report.source_tree)?;
    validate_work(selection.limits, report.files_selected, report.files_read, report.bytes_read, report.bytes_searched)?;
    if report.completion == SearchCompletion::Complete && report.files_read != report.files_selected {
        return Err(invalid_report());
    }
    let mut retained = 0;
    let matches = render_matches(query, selection.limits, format, &report.matches, report.completion, &mut retained)?;
    let mut result = search_header(selection, query, report.source_commit, report.source_tree);
    result.insert("source_rcr".into(), text(report.source_rcr.to_string()));
    result.insert("needle_hex".into(), text(hex(query.needle())));
    result.insert("matches".into(), Value::Array(matches));
    result.insert("match_count".into(), text(report.matches.len().to_string()));
    completion_fields(&mut result, report.completion);
    work_fields(&mut result, report.files_selected, report.files_read, report.bytes_read, report.bytes_searched, report.non_regular_entries);
    Ok(result)
}

fn search_header(selection: &Selection, query: &SourceQuery, commit: GitOid, tree: GitOid) -> Object {
    let Value::Object(result) = object([
        ("profile", text("literal-bytes-v1")),
        ("scope", text("selected_regular_files")),
        ("reference_hex", text(hex(selection.reference.as_bytes()))),
        ("source_commit", text(commit.to_string())),
        ("source_tree", text(tree.to_string())),
        ("case", text(match query.case() {
            SearchCase::Exact => "exact",
            SearchCase::AsciiInsensitive => "ascii_insensitive",
        })),
        ("path_prefixes_hex", Value::Array(query.prefixes().iter().map(|p| text(hex(p.as_bytes()))).collect())),
        ("max_matches", json::number(selection.limits.max_matches as u64)),
    ]) else { unreachable!() };
    result
}

fn completion_fields(result: &mut Object, completion: SearchCompletion) {
    result.insert("complete".into(), Value::Bool(completion == SearchCompletion::Complete));
    result.insert("truncated_reason".into(), match completion {
        SearchCompletion::Complete => Value::Null,
        SearchCompletion::MatchLimit => text("match_limit"),
    });
}

fn work_fields(result: &mut Object, selected: usize, read: usize, bytes: usize, searched: usize, excluded: usize) {
    for (name, count) in [
        ("files_selected", selected), ("files_read", read),
        ("bytes_read", bytes), ("bytes_searched", searched),
        ("non_regular_entries", excluded),
    ] {
        result.insert(name.into(), text(count.to_string()));
    }
}

fn render_matches(
    query: &SourceQuery,
    limits: SearchLimits,
    format: GitHashAlgorithm,
    matches: &[SourceMatch],
    completion: SearchCompletion,
    retained: &mut usize,
) -> Result<Vec<Value>, ToolError> {
    if matches.len() > limits.max_matches
        || (completion == SearchCompletion::MatchLimit && matches.len() != limits.max_matches)
        || matches.windows(2).any(|pair| {
            (&pair[0].path, pair[0].byte_offset) >= (&pair[1].path, pair[1].byte_offset)
        })
    {
        return Err(invalid_report());
    }
    let mut values = Vec::with_capacity(matches.len());
    for found in matches {
        // Validate coordinates before exposing a possibly corrupt read report.
        let start = found.byte_offset.checked_sub(found.excerpt_offset).ok_or_else(invalid_report)?;
        let end = start.checked_add(found.match_length).ok_or_else(invalid_report)?;
        let matched = found.excerpt.get(start..end).ok_or_else(invalid_report)?;
        if found.path.is_empty() || found.path.len() > 4096
            || found.path.split(|b| *b == b'/').any(|part| part.is_empty() || part == b"." || part == b"..")
            || found.path.contains(&0)
            || found.blob.is_zero() || found.blob.algorithm() != format
            || found.line == 0 || found.byte_column == 0 || found.byte_column - 1 > found.byte_offset
            || found.match_length != query.needle().len() || found.excerpt.len() > 416
            || found.byte_offset.checked_add(found.match_length).is_none_or(|n| n > limits.max_file_bytes)
            || !query.prefixes().is_empty() && !query.prefixes().iter().any(|p| {
                let prefix = p.as_bytes();
                found.path.as_slice() == prefix || found.path.strip_prefix(prefix).is_some_and(|tail| tail.starts_with(b"/"))
            })
            || !matched.iter().zip(query.needle()).all(|(a, b)| match query.case() {
                SearchCase::Exact => a == b,
                SearchCase::AsciiInsensitive => a.eq_ignore_ascii_case(b),
            })
        {
            return Err(invalid_report());
        }
        *retained = (*retained).checked_add(found.path.len() + found.excerpt.len())
            .filter(|n| *n <= MAX_RETAINED_BYTES)
            .ok_or(ToolError::failed("resource_limit"))?;
        values.push(object([
            ("path_hex", text(hex(&found.path))),
            ("blob", text(found.blob.to_string())),
            ("byte_offset", text(found.byte_offset.to_string())),
            ("line", text(found.line.to_string())),
            ("byte_column", text(found.byte_column.to_string())),
            ("match_length", text(found.match_length.to_string())),
            ("excerpt_offset", text(found.excerpt_offset.to_string())),
            ("excerpt_hex", text(hex(&found.excerpt))),
            ("excerpt_utf8", std::str::from_utf8(&found.excerpt).ok().map_or(Value::Null, text)),
        ]));
    }
    Ok(values)
}

fn bounded_result(result: Object) -> Result<Value, ToolError> {
    let value = Value::Object(result);
    value.encode(MAX_RESULT_BYTES).map_err(|_| ToolError::failed("resource_limit"))?;
    Ok(value)
}

fn read_error(error: NodeWorkspaceRefusal) -> ToolError {
    match error {
        NodeWorkspaceRefusal::RefUnavailable => ToolError::failed("reference_unavailable"),
        NodeWorkspaceRefusal::CommitRequired => ToolError::failed("commit_required"),
        NodeWorkspaceRefusal::Cancelled { exhaustion: None } => ToolError::failed("read_cancelled"),
        NodeWorkspaceRefusal::Cancelled { exhaustion: Some(_) } => ToolError::failed("resource_limit"),
        NodeWorkspaceRefusal::SourceSearch(error) => match *error {
            SearchError::InvalidQuery => ToolError::invalid("invalid_search_query"),
            SearchError::InvalidLimits => ToolError::invalid("invalid_limit"),
            SearchError::InvalidObjectFormat => ToolError::invalid("invalid_expected_commit"),
            SearchError::Cancelled => ToolError::failed("read_cancelled"),
            SearchError::Budget(_) => ToolError::failed("resource_limit"),
            _ => ToolError::failed("source_search_failed"),
        },
        NodeWorkspaceRefusal::SourceBrowse(error) => match *error {
            SourceBrowseError::SnapshotMoved => ToolError::failed("snapshot_moved"),
            SourceBrowseError::CommitMoved => ToolError::failed("source_commit_moved"),
            _ => ToolError::failed("source_search_failed"),
        },
        _ => ToolError::failed("source_search_failed"),
    }
}

fn hex_schema(maximum: usize) -> Value {
    object([
        ("type", text("string")),
        ("pattern", text("^(?:[0-9a-f]{2})+$")),
        ("maxLength", json::number((maximum * 2) as u64)),
    ])
}

fn input_schema() -> Value {
    let mut properties = Object::new();
    properties.insert("reference".into(), object([
        ("type", text("string")), ("maxLength", json::number(4096)),
        ("description", text("Full currently visible ref such as refs/heads/main; not an object ID or host path.")),
    ]));
    properties.insert("needle_hex".into(), hex_schema(256));
    properties.insert("path_prefixes_hex".into(), object([
        ("type", text("array")), ("maxItems", json::number(32)),
        ("items", hex_schema(4096)),
        ("description", text("Exact relative path prefixes, slash-bounded, at most 16384 decoded bytes in total. Omit to search all operator-granted regular files.")),
    ]));
    properties.insert("ignore_ascii_case".into(), object([
        ("type", text("boolean")), ("default", Value::Bool(false)),
    ]));
    for (name, length) in [("expected_head", 140), ("expected_commit", 64)] {
        properties.insert(name.into(), object([
            ("type", text("string")), ("maxLength", json::number(length)),
        ]));
    }
    for (name, default, maximum) in [
        ("max_matches", 20, MAX_MATCHES as u64),
        ("max_files", 2000, 20_000),
        ("max_file_bytes", 1024 * 1024, 8 * 1024 * 1024),
        ("max_total_bytes", 8 * 1024 * 1024, 64 * 1024 * 1024),
    ] {
        properties.insert(name.into(), object([
            ("type", text("integer")), ("minimum", json::number(1)),
            ("maximum", json::number(maximum)), ("default", json::number(default)),
        ]));
    }
    object([
        ("type", text("object")), ("properties", Value::Object(properties)),
        ("required", Value::Array(vec![text("reference"), text("needle_hex")])),
        ("additionalProperties", Value::Bool(false)),
    ])
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod integration_tests;
