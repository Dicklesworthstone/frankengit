//! Validate the complete native result before encoding any source bytes.
use super::*;
use fgit_forge::review::{ChangeKind, EntryIdentity, ReviewContent, ReviewHunk, ReviewSpan};

fn invalid() -> ToolError {
    ToolError::failed("invalid_review_report")
}
fn under(path: &[u8], prefix: &[u8]) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|tail| tail.starts_with(b"/"))
}
fn valid_path(path: &[u8]) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && !path.contains(&0)
        && path
            .split(|byte| *byte == b'/')
            .all(|part| !part.is_empty() && part != b"." && part != b"..")
}
fn is_blob(entry: Option<EntryIdentity>) -> bool {
    entry.is_some_and(|entry| matches!(entry.mode, 0o100644 | 0o100755 | 0o120000))
}
fn identity(value: Option<EntryIdentity>) -> Value {
    value.map_or(Value::Null, |entry| {
        object([
            ("oid", text(entry.oid.to_string())),
            ("mode", text(format!("{:06o}", entry.mode))),
        ])
    })
}
fn span(value: ReviewSpan) -> Value {
    object([
        ("byte_start", text(value.byte_start.to_string())),
        ("byte_end", text(value.byte_end.to_string())),
        ("line_start", text(value.line_start.to_string())),
        ("line_count", text(value.line_count.to_string())),
    ])
}
fn hunk(value: &ReviewHunk) -> Value {
    object([
        ("old", span(value.old)),
        ("new", span(value.new)),
        ("before_hex", text(hex(&value.before))),
        ("after_hex", text(hex(&value.after))),
    ])
}
fn mode_name(mode: ComparisonMode) -> &'static str {
    match mode {
        ComparisonMode::Direct => "direct",
        ComparisonMode::MergeBase => "merge-base",
    }
}
fn kind_name(kind: ChangeKind) -> &'static str {
    match kind {
        ChangeKind::Added => "added",
        ChangeKind::Deleted => "deleted",
        ChangeKind::Modified => "modified",
        ChangeKind::ModeChanged => "mode_changed",
        ChangeKind::TypeChanged => "type_changed",
    }
}
fn content(value: &ReviewContent) -> Value {
    match value {
        ReviewContent::Identical => object([("kind", text("identical"))]),
        ReviewContent::ObjectOnly => object([("kind", text("object_only"))]),
        ReviewContent::Binary {
            before_bytes,
            after_bytes,
        } => object([
            ("kind", text("binary")),
            ("before_bytes", text(before_bytes.to_string())),
            ("after_bytes", text(after_bytes.to_string())),
        ]),
        ReviewContent::Text {
            algorithm,
            additions,
            deletions,
            before_bytes,
            after_bytes,
            hunks,
        } => object([
            ("kind", text("text")),
            ("algorithm", text(format!("{algorithm:?}"))),
            ("additions", text(additions.to_string())),
            ("deletions", text(deletions.to_string())),
            ("before_bytes", text(before_bytes.to_string())),
            ("after_bytes", text(after_bytes.to_string())),
            ("hunks", Value::Array(hunks.iter().map(hunk).collect())),
        ]),
    }
}
fn check_span(span: ReviewSpan, bytes: &[u8], total: usize) -> Result<(), ToolError> {
    let length = span
        .byte_end
        .checked_sub(span.byte_start)
        .ok_or_else(invalid)?;
    let lines = bytes.iter().filter(|byte| **byte == b'\n').count()
        + usize::from(!bytes.is_empty() && bytes.last() != Some(&b'\n'));
    if span.byte_end > total
        || length != bytes.len()
        || span.line_count != lines
        || span.line_start > span.byte_start
        || span.line_start.checked_add(span.line_count).is_none()
    {
        return Err(invalid());
    }
    Ok(())
}
fn charge(total: &mut usize, amount: usize, maximum: usize) -> Result<(), ToolError> {
    *total = total
        .checked_add(amount)
        .filter(|n| *n <= maximum)
        .ok_or_else(invalid)?;
    Ok(())
}

fn validate(
    repository: RepositoryId,
    format: GitHashAlgorithm,
    query: &Query,
    report: &SourceReview,
) -> Result<(), ToolError> {
    let comparison = &report.comparison;
    if report.repository_id != repository
        || query
            .expected_head
            .is_some_and(|head| head != report.source_head)
        || comparison.mode != query.options.mode
        || query
            .expected_before
            .is_some_and(|pin| pin != comparison.requested_before)
        || query
            .expected_after
            .is_some_and(|pin| pin != comparison.requested_after)
        || (comparison.mode == ComparisonMode::Direct
            && comparison.compared_before != comparison.requested_before)
        || [
            comparison.requested_before,
            comparison.requested_after,
            comparison.compared_before,
            comparison.before_tree,
            comparison.after_tree,
        ]
        .iter()
        .any(|id| id.is_zero() || id.algorithm() != format)
    {
        return Err(invalid());
    }
    match &query.selection {
        ReviewSelection::References { before, after } => {
            if report.pull_request.is_some()
                || &report.before_reference != before
                || &report.after_reference != after
            {
                return Err(invalid());
            }
        }
        ReviewSelection::PullRequest {
            number,
            expected_version,
        } => {
            let Some((actual, version)) = report.pull_request else {
                return Err(invalid());
            };
            if actual != *number
                || expected_version != &Some(version)
                || !report
                    .before_reference
                    .as_bytes()
                    .starts_with(b"refs/heads/")
                || !report
                    .after_reference
                    .as_bytes()
                    .starts_with(b"refs/heads/")
            {
                return Err(invalid());
            }
        }
    }
    let limits = query.options.limits;
    if comparison.entries.len() > limits.max_changes
        || comparison
            .entries
            .windows(2)
            .any(|pair| pair[0].path >= pair[1].path)
    {
        return Err(invalid());
    }
    let (mut bytes, mut hunks, mut texts) = (0_usize, 0_usize, 0_usize);
    for entry in &comparison.entries {
        if !valid_path(&entry.path)
            || (!query.options.paths.is_empty()
                && !query
                    .options
                    .paths
                    .iter()
                    .any(|prefix| under(&entry.path, prefix)))
        {
            return Err(invalid());
        }
        charge(&mut bytes, entry.path.len(), limits.max_output_bytes)?;
        for identity in [entry.before, entry.after].into_iter().flatten() {
            if identity.oid.is_zero()
                || identity.oid.algorithm() != format
                || !matches!(
                    identity.mode,
                    0o040000 | 0o100644 | 0o100755 | 0o120000 | 0o160000
                )
            {
                return Err(invalid());
            }
        }
        let expected_kind = match (entry.before, entry.after) {
            (None, Some(_)) => ChangeKind::Added,
            (Some(_), None) => ChangeKind::Deleted,
            (Some(a), Some(b)) if a.mode & 0o170000 != b.mode & 0o170000 => ChangeKind::TypeChanged,
            (Some(a), Some(b)) if a.mode != b.mode => ChangeKind::ModeChanged,
            (Some(_), Some(_)) => ChangeKind::Modified,
            _ => return Err(invalid()),
        };
        if entry.kind != expected_kind || entry.before == entry.after {
            return Err(invalid());
        }
        let lengths = match &entry.content {
            ReviewContent::Identical => {
                if !is_blob(entry.before)
                    || !is_blob(entry.after)
                    || !entry
                        .before
                        .zip(entry.after)
                        .is_some_and(|(a, b)| a.oid == b.oid)
                {
                    return Err(invalid());
                }
                None
            }
            ReviewContent::ObjectOnly => {
                if is_blob(entry.before) || is_blob(entry.after) {
                    return Err(invalid());
                }
                None
            }
            ReviewContent::Binary {
                before_bytes,
                after_bytes,
            } => Some((*before_bytes, *after_bytes)),
            ReviewContent::Text {
                additions,
                deletions,
                before_bytes,
                after_bytes,
                hunks: spans,
                ..
            } => {
                charge(&mut texts, 1, limits.max_text_files)?;
                charge(&mut hunks, spans.len(), limits.max_hunks)?;
                if *additions > *after_bytes
                    || *deletions > *before_bytes
                    || ((*additions == 0 && *deletions == 0) != spans.is_empty())
                {
                    return Err(invalid());
                }
                for span in spans {
                    check_span(span.old, &span.before, *before_bytes)?;
                    check_span(span.new, &span.after, *after_bytes)?;
                    charge(&mut bytes, span.before.len(), limits.max_output_bytes)?;
                    charge(&mut bytes, span.after.len(), limits.max_output_bytes)?;
                }
                if spans.windows(2).any(|pair| {
                    pair[0].old.byte_start > pair[1].old.byte_start
                        || pair[0].new.byte_start > pair[1].new.byte_start
                }) {
                    return Err(invalid());
                }
                Some((*before_bytes, *after_bytes))
            }
        };
        if let Some((old, new)) = lengths {
            if old > limits.max_blob_bytes
                || new > limits.max_blob_bytes
                || (!is_blob(entry.before) && old != 0)
                || (!is_blob(entry.after) && new != 0)
                || (!is_blob(entry.before) && !is_blob(entry.after))
            {
                return Err(invalid());
            }
        }
    }
    Ok(())
}

pub(super) fn render(
    repository: RepositoryId,
    format: GitHashAlgorithm,
    query: &Query,
    report: &SourceReview,
) -> Result<Object, ToolError> {
    validate(repository, format, query, report)?;
    let comparison = &report.comparison;
    let entries = comparison
        .entries
        .iter()
        .map(|entry| {
            object([
                ("path_hex", text(hex(&entry.path))),
                ("before", identity(entry.before)),
                ("after", identity(entry.after)),
                ("change", text(kind_name(entry.kind))),
                ("content", content(&entry.content)),
            ])
        })
        .collect();
    let Value::Object(fields) = object([
        ("type", text("source_review")),
        ("schema_version", json::number(1)),
        ("comparison", text(mode_name(comparison.mode))),
        (
            "before_ref_hex",
            text(hex(report.before_reference.as_bytes())),
        ),
        (
            "after_ref_hex",
            text(hex(report.after_reference.as_bytes())),
        ),
        (
            "pull_request",
            report
                .pull_request
                .map_or(Value::Null, |(number, version)| {
                    object([
                        ("number", text(number.get().to_string())),
                        ("version", text(version.get().to_string())),
                    ])
                }),
        ),
        (
            "requested_before",
            text(comparison.requested_before.to_string()),
        ),
        (
            "requested_after",
            text(comparison.requested_after.to_string()),
        ),
        (
            "compared_before",
            text(comparison.compared_before.to_string()),
        ),
        ("before_tree", text(comparison.before_tree.to_string())),
        ("after_tree", text(comparison.after_tree.to_string())),
        (
            "paths_hex",
            Value::Array(
                query
                    .options
                    .paths
                    .iter()
                    .map(|path| text(hex(path)))
                    .collect(),
            ),
        ),
        (
            "context_lines",
            text(query.options.context_lines.to_string()),
        ),
        ("entries", Value::Array(entries)),
        ("entry_count", text(comparison.entries.len().to_string())),
        ("complete", Value::Bool(true)),
        ("completion_scope", text("selected_path_prefixes")),
        ("repository_changed", Value::Bool(false)),
        ("merge_permission", Value::Null),
    ]) else {
        unreachable!()
    };
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_spans_preserve_crlf_and_missing_final_newline() {
        for bytes in [b"a\r\nb".as_slice(), b"\r\n", b"", b"\xff\n"] {
            let count = bytes.iter().filter(|b| **b == b'\n').count()
                + usize::from(!bytes.is_empty() && bytes.last() != Some(&b'\n'));
            let span = ReviewSpan {
                byte_start: 8,
                byte_end: 8 + bytes.len(),
                line_start: 2,
                line_count: count,
            };
            check_span(span, bytes, 8 + bytes.len()).unwrap();
            assert!(
                check_span(
                    ReviewSpan {
                        byte_end: span.byte_end + 1,
                        ..span
                    },
                    bytes,
                    usize::MAX
                )
                .is_err()
            );
            assert!(
                check_span(
                    ReviewSpan {
                        line_count: count + 1,
                        ..span
                    },
                    bytes,
                    usize::MAX
                )
                .is_err()
            );
        }
        assert!(
            check_span(
                ReviewSpan {
                    byte_start: 2,
                    byte_end: 1,
                    line_start: 0,
                    line_count: 0
                },
                b"",
                2
            )
            .is_err()
        );
        assert!(
            check_span(
                ReviewSpan {
                    byte_start: 0,
                    byte_end: 1,
                    line_start: usize::MAX,
                    line_count: 1
                },
                b"x",
                1
            )
            .is_err()
        );
    }
}
