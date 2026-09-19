//! Native diff tools over one authenticated repository snapshot. A comparison
//! is untrusted review data, never an approval, mutation, or host-file request.
mod output;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod integration_tests;

use super::*;
use fgit_forge::review::{ComparisonMode, ReviewOptions, ReviewSelection, SourceReview};
use fgit_forge::{AggregateVersion, PullRequestNumber};
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RepositoryId};

pub(super) const COMPARE: &str = "frankengit_source_compare";
pub(super) const PULL_DIFF: &str = "frankengit_pull_diff";
const MAX_PATHS: usize = 32;
const MAX_PATH_BYTES: usize = 16 * 1024;
const MAX_CHANGES: usize = 128;
const MAX_OUTPUT_BYTES: usize = 256 * 1024;
const MAX_HUNKS: usize = 256;
const MAX_RESULT_BYTES: usize = 2 * 1024 * 1024;

// Both registry and dispatch use this conjunction. PR metadata permission alone
// does not disclose code, and source permission alone does not disclose a PR.
pub(super) fn permitted(source: bool, pulls: bool, name: &str) -> bool {
    source && (name == COMPARE || (pulls && name == PULL_DIFF))
}
pub(super) fn tools(source: bool, pulls: bool) -> Vec<Tool> {
    let mut tools = Vec::new();
    if permitted(source, pulls, COMPARE) {
        tools.push(Tool { name: COMPARE,
            description: "Compare two currently visible refs at one authenticated head. Exact byte/line hunks; optional unique merge-base mode. Paths narrow the read, not permissions. No approval or publication.",
            schema: input_schema(false) });
    }
    if permitted(source, pulls, PULL_DIFF) {
        tools.push(Tool { name: PULL_DIFF,
            description: "Review the exact code tips recorded by a PR at its required version. Requires source AND PR read grants. Moving branches never refresh the compared PR tips. No approval or publication.",
            schema: input_schema(true) });
    }
    tools
}

struct Query {
    selection: ReviewSelection,
    expected_head: Option<RepositoryAuthorityHeadId>,
    expected_before: Option<GitOid>,
    expected_after: Option<GitOid>,
    options: ReviewOptions,
}

pub(super) fn call(backend: &NodeTools, name: &str, args: &Object) -> Result<Value, ToolError> {
    // Defense in depth for direct handler callers, before even parsing input.
    if !permitted(backend.options.source, backend.options.pulls, name) {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let query = parse(args, name == PULL_DIFF, backend.options.format)?;
    let request = backend.node.request_context();
    // The native API selects PR metadata, refs, visibility, and objects from
    // ONE head. Do not precede it with an independently selected PR/ref read.
    let report = backend.node.runtime().block_on(backend.node.review_source_in(
        &request, &query.selection, &Default::default(), query.expected_head, &query.options,
    )).map_err(|_| ToolError::failed("source_review_failed"))?;
    let mut result = backend.header(report.source_head);
    result.extend(output::render(backend.options.repository, backend.options.format, &query, &report)?);
    let result = Value::Object(result);
    result.encode(MAX_RESULT_BYTES).map_err(|_| ToolError::failed("review_response_limit"))?;
    Ok(result)
}

fn bounded(args: &Object, name: &str, default: usize, minimum: usize, maximum: usize) -> Result<usize, ToolError> {
    let value = args.get(name).map(|value| value.unsigned().ok_or(ToolError::invalid("invalid_review_limit")))
        .transpose()?.unwrap_or(default as u64);
    let value = usize::try_from(value).map_err(|_| ToolError::invalid("invalid_review_limit"))?;
    if value < minimum || value > maximum { return Err(ToolError::invalid("invalid_review_limit")); }
    Ok(value)
}
fn reference(args: &Object, utf8: &str, raw: &str) -> Result<RefName, ToolError> {
    let bytes = match (string(args, utf8)?, string(args, raw)?) {
        (Some(value), None) if value.len() <= 4096 => value.as_bytes().to_vec(),
        (None, Some(value)) => unhex(value, 4096)?,
        _ => return Err(ToolError::invalid("exactly_one_reference_required")),
    };
    if !bytes.starts_with(b"refs/") { return Err(ToolError::invalid("invalid_reference")); }
    RefName::try_new(&bytes).map_err(|_| ToolError::invalid("invalid_reference"))
}
fn native(args: &Object, name: &str, format: GitHashAlgorithm) -> Result<Option<GitOid>, ToolError> {
    string(args, name)?.map(|value| {
        if value.len() != format.digest_len() * 2 { return Err(ToolError::invalid("invalid_commit_pin")); }
        unhex(value, format.digest_len())?;
        let oid = GitOid::from_hex(format, value).map_err(|_| ToolError::invalid("invalid_commit_pin"))?;
        if oid.is_zero() { return Err(ToolError::invalid("invalid_commit_pin")); }
        Ok(oid)
    }).transpose()
}
fn parse(args: &Object, pr: bool, format: GitHashAlgorithm) -> Result<Query, ToolError> {
    let mut allowed = vec!["comparison", "paths_hex", "context_lines", "max_changes",
        "max_blob_bytes", "max_output_bytes", "max_diff_work", "expected_head", "expected_before", "expected_after"];
    allowed.extend(if pr { vec!["number", "expected_version"] }
        else { vec!["before_ref", "after_ref", "before_ref_hex", "after_ref_hex"] });
    require_fields(args, &allowed)?;
    let selection = if pr {
        ReviewSelection::PullRequest {
            number: PullRequestNumber::try_new(decimal(args, "number", 0)?)
                .ok_or(ToolError::invalid("positive_pr_number_required"))?,
            expected_version: Some(AggregateVersion::try_new(decimal(args, "expected_version", 0)?)
                .ok_or(ToolError::invalid("positive_pr_version_required"))?),
        }
    } else {
        ReviewSelection::References {
            before: reference(args, "before_ref", "before_ref_hex")?,
            after: reference(args, "after_ref", "after_ref_hex")?,
        }
    };
    let mode = match string(args, "comparison")?.unwrap_or(if pr { "merge-base" } else { "direct" }) {
        "direct" => ComparisonMode::Direct,
        "merge-base" => ComparisonMode::MergeBase,
        _ => return Err(ToolError::invalid("invalid_comparison_mode")),
    };
    let mut options = ReviewOptions { mode, ..ReviewOptions::default() };
    if let Some(value) = args.get("paths_hex") {
        let Value::Array(paths) = value else { return Err(ToolError::invalid("paths_must_be_array")); };
        if paths.len() > MAX_PATHS { return Err(ToolError::invalid("too_many_paths")); }
        let mut bytes = 0_usize;
        for path in paths {
            let path = unhex(path.text().ok_or(ToolError::invalid("path_must_be_hex_string"))?, 4096)?;
            bytes = bytes.checked_add(path.len()).filter(|value| *value <= MAX_PATH_BYTES)
                .ok_or(ToolError::invalid("path_bytes_limit"))?;
            options.paths.push(path);
        }
        options.paths.sort();
        if options.paths.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ToolError::invalid("duplicate_path_prefix"));
        }
    }
    options.context_lines = bounded(args, "context_lines", 3, 0, 20)?;
    options.limits.max_changes = bounded(args, "max_changes", 64, 1, MAX_CHANGES)?;
    options.limits.max_blob_bytes = bounded(args, "max_blob_bytes", 1024 * 1024, 1, 1024 * 1024)?;
    options.limits.max_output_bytes = bounded(args, "max_output_bytes", 64 * 1024, 1, MAX_OUTPUT_BYTES)?;
    options.limits.max_diff_work = bounded(args, "max_diff_work", 1_000_000, 1, 1_000_000)?;
    options.limits.max_hunks = MAX_HUNKS;
    options.limits.max_text_files = 32;
    options.validate().map_err(|_| ToolError::invalid("invalid_review_options"))?;
    Ok(Query { selection, expected_head: head(args, 0)?,
        expected_before: native(args, "expected_before", format)?,
        expected_after: native(args, "expected_after", format)?, options })
}

fn integer_schema(default: u64, minimum: u64, maximum: u64) -> Value {
    object([("type", text("integer")), ("default", json::number(default)),
        ("minimum", json::number(minimum)), ("maximum", json::number(maximum))])
}
fn input_schema(pr: bool) -> Value {
    let mut properties = Object::new();
    properties.insert("comparison".into(), object([("type", text("string")),
        ("enum", Value::Array(vec![text("direct"), text("merge-base")])),
        ("default", text(if pr { "merge-base" } else { "direct" }))]));
    let bytes = object([("type", text("string")), ("pattern", text("^(?:[0-9a-f]{2})+$")),
        ("maxLength", json::number(8192))]);
    properties.insert("paths_hex".into(), object([("type", text("array")),
        ("maxItems", json::number(MAX_PATHS as u64)), ("uniqueItems", Value::Bool(true)),
        ("items", bytes.clone()), ("description", text("Raw path-component prefixes; at most 16 KiB decoded in total. These narrow output, not authorization."))]));
    for (name, default, min, max) in [
        ("context_lines", 3, 0, 20), ("max_changes", 64, 1, MAX_CHANGES as u64),
        ("max_blob_bytes", 1_048_576, 1, 1_048_576),
        ("max_output_bytes", 65_536, 1, MAX_OUTPUT_BYTES as u64),
        ("max_diff_work", 1_000_000, 1, 1_000_000),
    ] { properties.insert(name.into(), integer_schema(default, min, max)); }
    properties.insert("expected_head".into(), object([("type", text("string")),
        ("maxLength", json::number(140)), ("description", text("Strict current authority head pin. A moved head refuses; no retained-snapshot substitution."))]));
    for name in ["expected_before", "expected_after"] {
        properties.insert(name.into(), object([("type", text("string")),
            ("pattern", text("^(?:[0-9a-f]{40}|[0-9a-f]{64})$")),
            ("description", text("Optional nonzero native commit comparison pin. Does not select objects or grant access."))]));
    }
    if pr {
        for name in ["number", "expected_version"] {
            properties.insert(name.into(), object([("type", text("string")),
                ("pattern", text("^[1-9][0-9]{0,19}$")),
                ("description", text("Positive exact unsigned decimal string; bounded by u64, never a JSON number."))]));
        }
    } else {
        for name in ["before_ref", "after_ref"] {
            properties.insert(name.into(), object([("type", text("string")),
                ("maxLength", json::number(4096)), ("pattern", text("^refs/"))]));
        }
        for name in ["before_ref_hex", "after_ref_hex"] { properties.insert(name.into(), bytes.clone()); }
    }
    let Value::Object(mut schema) = object([("type", text("object")), ("properties", Value::Object(properties)),
        ("additionalProperties", Value::Bool(false)),
        ("required", Value::Array(if pr { vec![text("number"), text("expected_version")] } else { Vec::new() }))])
        else { unreachable!() };
    if !pr {
        // oneOf also rejects supplying both UTF-8 and raw encodings of a ref.
        schema.insert("allOf".into(), Value::Array([("before_ref", "before_ref_hex"), ("after_ref", "after_ref_hex")]
            .into_iter().map(|(a, b)| object([("oneOf", Value::Array(vec![
                object([("required", Value::Array(vec![text(a)]))]),
                object([("required", Value::Array(vec![text(b)]))]),
            ]))])).collect()));
    }
    Value::Object(schema)
}
