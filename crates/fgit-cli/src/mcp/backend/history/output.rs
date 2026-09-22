//! Bounded, byte-preserving metadata and provenance output. Native commit
//! headers identify objects; their author/signature strings authenticate nobody.
use super::*;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::history::{BlameResult, HistoryCommit, HistoryPage};
use std::collections::{BTreeMap, BTreeSet};

fn invalid() -> ToolError {
    ToolError::failed("invalid_history_report")
}
fn oid(format: GitHashAlgorithm, value: GitOid) -> Result<(), ToolError> {
    if value.is_zero() || value.algorithm() != format {
        return Err(invalid());
    }
    Ok(())
}
fn record(value: &HistoryCommit) -> Value {
    object([
        ("id", text(value.id.to_string())),
        ("tree", text(value.tree.to_string())),
        (
            "parents",
            Value::Array(
                value
                    .parents
                    .iter()
                    .map(|id| text(id.to_string()))
                    .collect(),
            ),
        ),
        ("body_hex", text(hex(&value.body))),
        ("body_bytes", text(value.body.len().to_string())),
        ("author_authenticated", Value::Bool(false)),
    ])
}
fn records(
    format: GitHashAlgorithm,
    limits: HistoryLimits,
    values: &[HistoryCommit],
) -> Result<(), ToolError> {
    let (mut bytes, mut edges) = (0_usize, 0_usize);
    let mut ids = BTreeSet::new();
    if values.len() > limits.max_commits {
        return Err(invalid());
    }
    for value in values {
        oid(format, value.id)?;
        oid(format, value.tree)?;
        if !ids.insert(value.id) || value.body.len() > 64 * 1024 {
            return Err(invalid());
        }
        bytes = bytes
            .checked_add(value.body.len())
            .filter(|n| *n <= limits.max_metadata_bytes)
            .ok_or_else(invalid)?;
        edges = edges
            .checked_add(value.parents.len())
            .filter(|n| *n <= limits.max_edges)
            .ok_or_else(invalid)?;
        for parent in &value.parents {
            oid(format, *parent)?;
        }
        if git_object_id(format, GitObjectKind::Commit, &value.body) != value.id {
            return Err(invalid());
        }
    }
    Ok(())
}
fn common(kind: &str, reference: &RefName, tip: GitOid) -> Object {
    object([
        ("type", text(kind)),
        ("schema_version", json::number(1)),
        ("reference_hex", text(hex(reference.as_bytes()))),
        ("source_commit", text(tip.to_string())),
        ("repository_changed", Value::Bool(false)),
        ("merge_permission", Value::Null),
    ])
    .object()
    .unwrap()
    .clone()
}

pub(super) fn log(
    format: GitHashAlgorithm,
    query: &Query,
    report: &HistoryPage,
) -> Result<Object, ToolError> {
    oid(format, report.tip)?;
    if query.path.is_some()
        || report.after != query.after
        || report.total_commits == 0
        || report.total_commits > query.limits.max_commits
        || report.after > report.total_commits
    {
        return Err(invalid());
    }
    let end = query
        .after
        .checked_add(query.limit)
        .ok_or_else(invalid)?
        .min(report.total_commits);
    if report.commits.len() != end - query.after
        || report.next_after != (end < report.total_commits).then_some(end)
        || (query.after == 0 && report.commits.first().map(|row| row.id) != Some(report.tip))
    {
        return Err(invalid());
    }
    records(format, query.limits, &report.commits)?;
    let positions: BTreeMap<_, _> = report
        .commits
        .iter()
        .enumerate()
        .map(|(n, row)| (row.id, n))
        .collect();
    for (index, commit) in report.commits.iter().enumerate() {
        if commit
            .parents
            .iter()
            .any(|parent| positions.get(parent).is_some_and(|n| *n <= index))
        {
            return Err(invalid());
        }
    }
    let mut result = common("source_history_page", &query.reference, report.tip);
    result.insert("order".into(), text("child-before-parent-native-id-ties"));
    result.insert("after".into(), text(report.after.to_string()));
    result.insert("limit".into(), text(query.limit.to_string()));
    result.insert(
        "total_commits".into(),
        text(report.total_commits.to_string()),
    );
    result.insert(
        "commits".into(),
        Value::Array(report.commits.iter().map(record).collect()),
    );
    result.insert(
        "next_after".into(),
        report
            .next_after
            .map_or(Value::Null, |n| text(n.to_string())),
    );
    result.insert("complete".into(), Value::Bool(report.next_after.is_none()));
    Ok(result)
}

pub(super) fn blame(
    format: GitHashAlgorithm,
    query: &Query,
    report: &BlameResult,
) -> Result<Object, ToolError> {
    if report.content.len() > MAX_CONTENT_BYTES {
        return Err(ToolError::failed("blame_page_byte_limit"));
    }
    for id in [report.tip, report.tree, report.blob] {
        oid(format, id)?;
    }
    let end = query
        .after
        .checked_add(query.limit)
        .ok_or_else(invalid)?
        .min(report.total_lines);
    if query.path.as_ref() != Some(&report.path)
        || report.total_lines > query.limits.max_lines
        || query.after > report.total_lines
        || report.first_line != query.after
        || report.end_line != end
        || report.lines.len() != end - query.after
        || report.lines.len() > MAX_BLAME_LINES
        || report.content.contains(&0)
        || report.graph_commits == 0
        || report.graph_commits > query.limits.max_commits
        || report.comparisons > query.limits.max_comparisons
        || report.algorithms.len() > query.limits.max_comparisons
        || report
            .content_byte_start
            .checked_add(report.content.len())
            .is_none_or(|n| n > query.limits.max_blob_bytes)
    {
        return Err(invalid());
    }
    records(format, query.limits, &report.origins)?;
    if report
        .origins
        .windows(2)
        .any(|pair| pair[0].id >= pair[1].id)
    {
        return Err(invalid());
    }
    let mut used = BTreeSet::new();
    let mut cursor = report.content_byte_start;
    for (index, line) in report.lines.iter().enumerate() {
        oid(format, line.origin_commit)?;
        oid(format, line.origin_blob)?;
        if line.line != query.after + index
            || line.byte_start != cursor
            || line.byte_end <= cursor
            || line.origin_byte_end <= line.origin_byte_start
            || line.origin_byte_end > query.limits.max_blob_bytes
            || line.origin_line >= query.limits.max_lines
            || line.byte_end - line.byte_start != line.origin_byte_end - line.origin_byte_start
        {
            return Err(invalid());
        }
        let relative_start = line
            .byte_start
            .checked_sub(report.content_byte_start)
            .ok_or_else(invalid)?;
        let relative_end = line
            .byte_end
            .checked_sub(report.content_byte_start)
            .ok_or_else(invalid)?;
        let content = report
            .content
            .get(relative_start..relative_end)
            .ok_or_else(invalid)?;
        // Exactly one LF-inclusive line, except the last physical line may
        // omit LF. Byte offsets, not Unicode columns, partition the payload.
        if content[..content.len() - 1].contains(&b'\n')
            || (content.last() != Some(&b'\n') && line.line + 1 != report.total_lines)
        {
            return Err(invalid());
        }
        used.insert(line.origin_commit);
        cursor = line.byte_end;
    }
    if cursor.checked_sub(report.content_byte_start) != Some(report.content.len())
        || used
            != report
                .origins
                .iter()
                .map(|row| row.id)
                .collect::<BTreeSet<_>>()
    {
        return Err(invalid());
    }
    let lines = report
        .lines
        .iter()
        .map(|line| {
            object([
                ("line", text(line.line.to_string())),
                ("byte_start", text(line.byte_start.to_string())),
                ("byte_end", text(line.byte_end.to_string())),
                ("origin_commit", text(line.origin_commit.to_string())),
                ("origin_blob", text(line.origin_blob.to_string())),
                ("origin_line", text(line.origin_line.to_string())),
                (
                    "origin_byte_start",
                    text(line.origin_byte_start.to_string()),
                ),
                ("origin_byte_end", text(line.origin_byte_end.to_string())),
            ])
        })
        .collect();
    let mut result = common("source_blame_page", &query.reference, report.tip);
    result.insert(
        "profile".into(),
        text("exact-same-path-all-parents-stored-order"),
    );
    result.insert("human_authorship_proven".into(), Value::Bool(false));
    result.insert("tree".into(), text(report.tree.to_string()));
    result.insert("blob".into(), text(report.blob.to_string()));
    result.insert("path_hex".into(), text(hex(&report.path)));
    result.insert("total_lines".into(), text(report.total_lines.to_string()));
    result.insert("first_line".into(), text(report.first_line.to_string()));
    result.insert("end_line".into(), text(report.end_line.to_string()));
    result.insert(
        "content_byte_start".into(),
        text(report.content_byte_start.to_string()),
    );
    result.insert("bytes_hex".into(), text(hex(&report.content)));
    result.insert("lines".into(), Value::Array(lines));
    result.insert(
        "origins".into(),
        Value::Array(report.origins.iter().map(record).collect()),
    );
    result.insert(
        "graph_commits".into(),
        text(report.graph_commits.to_string()),
    );
    result.insert("comparisons".into(), text(report.comparisons.to_string()));
    result.insert(
        "algorithms".into(),
        Value::Array(
            report
                .algorithms
                .iter()
                .map(|algorithm| text(format!("{algorithm:?}")))
                .collect(),
        ),
    );
    result.insert(
        "next_first_line".into(),
        if end < report.total_lines {
            text(end.to_string())
        } else {
            Value::Null
        },
    );
    result.insert("complete".into(), Value::Bool(end == report.total_lines));
    result.insert("attribution_complete".into(), Value::Bool(true));
    Ok(result)
}
