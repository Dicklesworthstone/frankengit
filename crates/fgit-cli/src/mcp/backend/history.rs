//! Read-only native commit-DAG pages and exact line ancestry. Native author
//! and signature fields remain untrusted metadata, never authenticated identity.
mod output;
#[cfg(test)]
mod tests;

use super::*;
use fgit_forge::history::{BlameOptions, HistoryError, HistoryLimits, LogOptions};
use fgit_types::{GitHashAlgorithm, GitOid, RefName};

pub(super) const LOG: &str = "frankengit_source_log";
pub(super) const BLAME: &str = "frankengit_source_blame";
const MAX_LOG_PAGE: usize = 20;
const MAX_BLAME_LINES: usize = 200;
const MAX_CONTENT_BYTES: usize = 64 * 1024;
const MAX_METADATA_BYTES: usize = 128 * 1024;
const MAX_RESULT_BYTES: usize = 2 * 1024 * 1024;

pub(super) fn tools() -> Vec<Tool> {
    vec![
        Tool {
            name: LOG,
            description: "Page the complete bounded commit DAG of a visible ref in child-before-parent order. Exact commit bytes and parent order; continuation requires the same snapshot. Author headers are not authentication.",
            schema: input_schema(false),
        },
        Tool {
            name: BLAME,
            description: "Read a bounded line range with exact same-path ancestry across all merge parents. Byte-exact content and native origin IDs; no rename/whitespace guesses or human-authorship claims. Continuation requires the same snapshot.",
            schema: input_schema(true),
        },
    ]
}
struct Query {
    reference: RefName,
    expected_head: Option<RepositoryAuthorityHeadId>,
    expected_commit: Option<GitOid>,
    limits: HistoryLimits,
    after: usize,
    limit: usize,
    path: Option<Vec<u8>>,
}
fn bound(args: &Object, field: &str, default: usize, max: usize) -> Result<usize, ToolError> {
    let value = args
        .get(field)
        .map(|value| {
            value
                .unsigned()
                .ok_or(ToolError::invalid("invalid_history_limit"))
        })
        .transpose()?
        .unwrap_or(default as u64);
    let value = usize::try_from(value).map_err(|_| ToolError::invalid("invalid_history_limit"))?;
    if value == 0 || value > max {
        return Err(ToolError::invalid("invalid_history_limit"));
    }
    Ok(value)
}
fn parse(args: &Object, blame: bool, format: GitHashAlgorithm) -> Result<Query, ToolError> {
    require_fields(
        args,
        if blame {
            &[
                "reference",
                "reference_hex",
                "path_hex",
                "first_line",
                "limit",
                "expected_head",
                "expected_commit",
                "max_commits",
                "max_blob_bytes",
                "max_diff_work",
            ]
        } else {
            &[
                "reference",
                "reference_hex",
                "after",
                "limit",
                "expected_head",
                "expected_commit",
                "max_commits",
            ]
        },
    )?;
    let reference = match (string(args, "reference")?, string(args, "reference_hex")?) {
        (Some(value), None) if value.len() <= 4096 => value.as_bytes().to_vec(),
        (None, Some(value)) => unhex(value, 4096)?,
        _ => return Err(ToolError::invalid("exactly_one_reference_required")),
    };
    if !reference.starts_with(b"refs/") {
        return Err(ToolError::invalid("invalid_reference"));
    }
    let reference =
        RefName::try_new(&reference).map_err(|_| ToolError::invalid("invalid_reference"))?;
    let after = decimal(args, if blame { "first_line" } else { "after" }, 0)?;
    let expected_head = head(args, after)?;
    let after = usize::try_from(after).map_err(|_| ToolError::invalid("invalid_history_offset"))?;
    let expected_commit = string(args, "expected_commit")?
        .map(|value| {
            if value.len() != format.digest_len() * 2 {
                return Err(ToolError::invalid("invalid_commit_pin"));
            }
            unhex(value, format.digest_len())?;
            let id = GitOid::from_hex(format, value)
                .map_err(|_| ToolError::invalid("invalid_commit_pin"))?;
            if id.is_zero() {
                return Err(ToolError::invalid("invalid_commit_pin"));
            }
            Ok(id)
        })
        .transpose()?;
    let mut limits = HistoryLimits {
        max_metadata_bytes: MAX_METADATA_BYTES,
        ..HistoryLimits::default()
    };
    limits.max_commits = bound(args, "max_commits", limits.max_commits, limits.max_commits)?;
    let (path, limit) = if blame {
        limits.max_blob_bytes = bound(
            args,
            "max_blob_bytes",
            limits.max_blob_bytes,
            limits.max_blob_bytes,
        )?;
        limits.max_diff_work = bound(
            args,
            "max_diff_work",
            limits.max_diff_work,
            limits.max_diff_work,
        )?;
        let path = unhex(
            string(args, "path_hex")?.ok_or(ToolError::invalid("path_required"))?,
            4096,
        )?;
        // Validate the starting position and path without assuming file length.
        BlameOptions {
            path: path.clone(),
            first_line: after,
            end_line: Some(after),
            limits,
        }
        .validate()
        .map_err(|_| ToolError::invalid("invalid_blame_options"))?;
        (Some(path), bound(args, "limit", 100, MAX_BLAME_LINES)?)
    } else {
        let limit = bound(args, "limit", 5, MAX_LOG_PAGE)?;
        LogOptions {
            after,
            limit,
            limits,
        }
        .validate()
        .map_err(|_| ToolError::invalid("invalid_log_options"))?;
        (None, limit)
    };
    limits
        .validate()
        .map_err(|_| ToolError::invalid("invalid_history_limits"))?;
    Ok(Query {
        reference,
        expected_head,
        expected_commit,
        limits,
        after,
        limit,
        path,
    })
}

pub(super) fn call(backend: &NodeTools, name: &str, args: &Object) -> Result<Value, ToolError> {
    if !backend.options.source || !matches!(name, LOG | BLAME) {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let query = parse(args, name == BLAME, backend.options.format)?;
    let request = backend.node.request_context();
    let (head, fields) = if let Some(path) = &query.path {
        // An empty native range obtains the exact total without disclosing an
        // unbounded file or assuming that `first + limit` exists. The actual
        // page reuses its authenticated head; an intervening write fails closed.
        let discovery = BlameOptions {
            path: path.clone(),
            first_line: 0,
            end_line: Some(0),
            limits: query.limits,
        };
        let (head, size) = backend
            .node
            .runtime()
            .block_on(backend.node.blame_source_in(
                &request,
                &query.reference,
                &Default::default(),
                query.expected_head,
                &discovery,
            ))
            .map_err(|error| {
                if error.is_snapshot_moved() {
                    ToolError::failed("snapshot_moved")
                } else if error.is_unavailable() {
                    ToolError::failed("reference_unavailable")
                } else {
                    failure(error.history_error())
                }
            })?;
        check_pin(&query, backend.options.format, head, size.tip)?;
        if size.path != *path
            || size.first_line != 0
            || size.end_line != 0
            || !size.lines.is_empty()
            || !size.content.is_empty()
            || !size.origins.is_empty()
            || size.total_lines > query.limits.max_lines
        {
            return Err(ToolError::failed("invalid_blame_report"));
        }
        if query.after > size.total_lines {
            return Err(ToolError::invalid("line_range_outside_file"));
        }
        let end = query
            .after
            .checked_add(query.limit)
            .ok_or(ToolError::invalid("invalid_history_offset"))?
            .min(size.total_lines);
        let options = BlameOptions {
            path: path.clone(),
            first_line: query.after,
            end_line: Some(end),
            limits: query.limits,
        };
        let (actual_head, report) = backend
            .node
            .runtime()
            .block_on(backend.node.blame_source_in(
                &request,
                &query.reference,
                &Default::default(),
                Some(head),
                &options,
            ))
            .map_err(|error| {
                if error.is_snapshot_moved() {
                    ToolError::failed("snapshot_moved")
                } else if error.is_unavailable() {
                    ToolError::failed("reference_unavailable")
                } else {
                    failure(error.history_error())
                }
            })?;
        if actual_head != head
            || report.tip != size.tip
            || report.blob != size.blob
            || report.tree != size.tree
            || report.total_lines != size.total_lines
        {
            return Err(ToolError::failed("invalid_blame_report"));
        }
        (
            actual_head,
            output::blame(backend.options.format, &query, &report)?,
        )
    } else {
        let options = LogOptions {
            after: query.after,
            limit: query.limit,
            limits: query.limits,
        };
        let (head, report) = backend
            .node
            .runtime()
            .block_on(backend.node.read_commit_history_in(
                &request,
                &query.reference,
                &Default::default(),
                query.expected_head,
                options,
            ))
            .map_err(|error| {
                if error.is_snapshot_moved() {
                    ToolError::failed("snapshot_moved")
                } else if error.is_unavailable() {
                    ToolError::failed("reference_unavailable")
                } else {
                    failure(error.history_error())
                }
            })?;
        check_pin(&query, backend.options.format, head, report.tip)?;
        (head, output::log(backend.options.format, &query, &report)?)
    };
    let mut result = backend.header(head);
    result.extend(fields);
    let result = Value::Object(result);
    result
        .encode(MAX_RESULT_BYTES)
        .map_err(|_| ToolError::failed("history_response_limit"))?;
    Ok(result)
}
fn check_pin(
    query: &Query,
    format: GitHashAlgorithm,
    head: RepositoryAuthorityHeadId,
    tip: GitOid,
) -> Result<(), ToolError> {
    if query.expected_head.is_some_and(|pin| pin != head) {
        return Err(ToolError::failed("snapshot_moved"));
    }
    if tip.is_zero() || tip.algorithm() != format {
        return Err(ToolError::failed("invalid_history_report"));
    }
    if query.expected_commit.is_some_and(|pin| pin != tip) {
        return Err(ToolError::failed("source_commit_moved"));
    }
    Ok(())
}
const fn failure(error: Option<&HistoryError>) -> ToolError {
    match error {
        Some(HistoryError::InvalidOptions) => ToolError::invalid("invalid_history_options"),
        Some(HistoryError::LineRange) => ToolError::invalid("range_outside_history"),
        Some(HistoryError::BinaryContent) => ToolError::failed("binary_blame_unsupported"),
        Some(HistoryError::PathUnavailable) => ToolError::failed("path_unavailable"),
        Some(HistoryError::Budget(_)) => ToolError::failed("resource_limit"),
        Some(HistoryError::Source(fgit_forge::preparation::MergeSourceError::Cancelled)) => {
            ToolError::failed("read_cancelled")
        }
        _ => ToolError::failed("history_read_failed"),
    }
}
fn input_schema(blame: bool) -> Value {
    let mut properties = Object::new();
    properties.insert(
        "reference".into(),
        object([
            ("type", text("string")),
            ("maxLength", json::number(4096)),
            ("pattern", text("^refs/")),
        ]),
    );
    let bytes = object([
        ("type", text("string")),
        ("pattern", text("^(?:[0-9a-f]{2})+$")),
        ("maxLength", json::number(8192)),
    ]);
    properties.insert("reference_hex".into(), bytes.clone());
    properties.insert(
        "expected_head".into(),
        object([("type", text("string")), ("maxLength", json::number(140))]),
    );
    properties.insert(
        "expected_commit".into(),
        object([
            ("type", text("string")),
            ("pattern", text("^(?:[0-9a-f]{40}|[0-9a-f]{64})$")),
        ]),
    );
    properties.insert(
        if blame { "first_line" } else { "after" }.into(),
        decimal_schema(),
    );
    properties.insert(
        "limit".into(),
        integer_schema(if blame { 100 } else { 5 }, if blame { 200 } else { 20 }),
    );
    properties.insert("max_commits".into(), integer_schema(4096, 4096));
    if blame {
        properties.insert("path_hex".into(), bytes);
        properties.insert(
            "max_blob_bytes".into(),
            integer_schema(1_048_576, 1_048_576),
        );
        properties.insert("max_diff_work".into(), integer_schema(1_000_000, 1_000_000));
    }
    object([
        ("type", text("object")),
        ("properties", Value::Object(properties)),
        (
            "required",
            Value::Array(if blame {
                vec![text("path_hex")]
            } else {
                Vec::new()
            }),
        ),
        ("additionalProperties", Value::Bool(false)),
        (
            "oneOf",
            Value::Array(vec![
                object([("required", Value::Array(vec![text("reference")]))]),
                object([("required", Value::Array(vec![text("reference_hex")]))]),
            ]),
        ),
    ])
}
fn integer_schema(default: u64, maximum: u64) -> Value {
    object([
        ("type", text("integer")),
        ("minimum", json::number(1)),
        ("maximum", json::number(maximum)),
        ("default", json::number(default)),
    ])
}
