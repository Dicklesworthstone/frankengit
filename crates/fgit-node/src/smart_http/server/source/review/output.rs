//! Bounded JSON view of the native review report. Source bytes are never
//! interpreted as HTML, Unicode replacements, patch instructions or approval.

use fgit_forge::review::{ChangeKind, ComparisonMode, EntryIdentity, ReviewContent,
    ReviewOptions, ReviewSelection, ReviewSpan, ReviewedEntry, SourceReview};
use fgit_types::{GitHashAlgorithm, GitOid};
use crate::OneNode;
use super::Command;
use super::super::super::{Status, issues::{ApiError, quote}};

const MAX_REPLY_BYTES: usize = 8 * 1024 * 1024;
fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), ApiError> {
    if live() { Ok(()) } else { Err(ApiError::from_status(Status::Timeout, false)) }
}
struct Output { body: String, maximum: usize }
impl Output {
    fn new(maximum: usize) -> Self { Self { body: String::new(), maximum: maximum.min(MAX_REPLY_BYTES) } }
    fn reserve(&mut self, amount: usize) -> Result<(), ApiError> {
        if self.body.len().checked_add(amount).is_none_or(|n| n > self.maximum) { return Err(ApiError::too_large()); }
        self.body.try_reserve(amount).map_err(|_| ApiError::unavailable())
    }
    fn append(&mut self, text: &str) -> Result<(), ApiError> {
        self.reserve(text.len())?; self.body.push_str(text); Ok(())
    }
    fn hex(&mut self, bytes: &[u8], live: &mut impl FnMut() -> bool) -> Result<(), ApiError> {
        checkpoint(live)?;
        let expanded = bytes.len().checked_mul(2).and_then(|n| n.checked_add(2)).ok_or_else(ApiError::too_large)?;
        self.reserve(expanded)?;
        self.body.push('"');
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for chunk in bytes.chunks(4096) {
            checkpoint(live)?;
            for byte in chunk {
                self.body.push(char::from(HEX[usize::from(*byte >> 4)]));
                self.body.push(char::from(HEX[usize::from(*byte & 15)]));
            }
        }
        self.body.push('"');
        Ok(())
    }
}
fn valid_oid(id: GitOid, format: GitHashAlgorithm) -> bool { !id.is_zero() && id.algorithm() == format }
fn blob(entry: Option<EntryIdentity>) -> bool { entry.is_some_and(|e| matches!(e.mode, 0o100644 | 0o100755 | 0o120000)) }
fn under(path: &[u8], prefix: &[u8]) -> bool {
    path == prefix || path.strip_prefix(prefix).is_some_and(|rest| rest.starts_with(b"/"))
}
fn count(total: &mut usize, amount: usize, maximum: usize) -> Result<(), ApiError> {
    *total = total.checked_add(amount).filter(|n| *n <= maximum).ok_or_else(ApiError::too_large)?;
    Ok(())
}
fn validate_span(span: ReviewSpan, bytes: &[u8], total: usize) -> Result<(), ApiError> {
    let lines = bytes.iter().filter(|byte| **byte == b'\n').count()
        + usize::from(!bytes.is_empty() && bytes.last() != Some(&b'\n'));
    if span.byte_start > span.byte_end || span.byte_end > total
        || span.byte_end.checked_sub(span.byte_start) != Some(bytes.len())
        || span.line_count != lines || span.line_start.checked_add(span.line_count).is_none()
        || (span.byte_start == 0 && span.line_start != 0)
        || (!bytes.is_empty() && span.byte_end < total && bytes.last() != Some(&b'\n'))
    { return Err(ApiError::unavailable()); }
    Ok(())
}
fn validate_entries(entries: &[ReviewedEntry], options: &ReviewOptions, format: GitHashAlgorithm,
    live: &mut impl FnMut() -> bool,
) -> Result<(), ApiError> {
    if entries.len() > options.limits.max_changes || entries.windows(2).any(|pair| pair[0].path >= pair[1].path) {
        return Err(ApiError::unavailable());
    }
    let (mut payload, mut total_hunks, mut text_files) = (0, 0, 0);
    for entry in entries {
        checkpoint(live)?;
        if entry.path.is_empty() || entry.path.len() > 4096 || entry.path.contains(&0)
            || entry.path.split(|b| *b == b'/').any(|part| part.is_empty() || part == b"." || part == b"..")
            || (!options.paths.is_empty() && !options.paths.iter().any(|prefix| under(&entry.path, prefix)))
        { return Err(ApiError::unavailable()); }
        count(&mut payload, entry.path.len(), options.limits.max_output_bytes)?;
        for side in [entry.before, entry.after].into_iter().flatten() {
            if !valid_oid(side.oid, format) || !matches!(side.mode, 0o040000 | 0o100644 | 0o100755 | 0o120000 | 0o160000) {
                return Err(ApiError::unavailable());
            }
        }
        let kind = match (entry.before, entry.after) {
            (None, Some(_)) => ChangeKind::Added,
            (Some(_), None) => ChangeKind::Deleted,
            (Some(a), Some(b)) if a.mode & 0o170000 != b.mode & 0o170000 => ChangeKind::TypeChanged,
            (Some(a), Some(b)) if a.mode != b.mode => ChangeKind::ModeChanged,
            (Some(a), Some(b)) if a.oid != b.oid => ChangeKind::Modified,
            _ => return Err(ApiError::unavailable()),
        };
        if entry.kind != kind { return Err(ApiError::unavailable()); }
        match &entry.content {
            ReviewContent::Identical => {
                if !blob(entry.before) || !blob(entry.after)
                    || entry.before.zip(entry.after).is_none_or(|(a, b)| a.oid != b.oid)
                { return Err(ApiError::unavailable()); }
            }
            ReviewContent::ObjectOnly => {
                if blob(entry.before) || blob(entry.after) { return Err(ApiError::unavailable()); }
            }
            ReviewContent::Binary { before_bytes, after_bytes }
            | ReviewContent::Text { before_bytes, after_bytes, .. } => {
                if (!blob(entry.before) && *before_bytes != 0) || (!blob(entry.after) && *after_bytes != 0)
                    || (!blob(entry.before) && !blob(entry.after))
                    || *before_bytes > options.limits.max_blob_bytes || *after_bytes > options.limits.max_blob_bytes
                { return Err(ApiError::unavailable()); }
                if let ReviewContent::Text { additions, deletions, hunks, .. } = &entry.content {
                    if *additions > *after_bytes || *deletions > *before_bytes { return Err(ApiError::unavailable()); }
                    count(&mut text_files, 1, options.limits.max_text_files)?;
                    count(&mut total_hunks, hunks.len(), options.limits.max_hunks)?;
                    for hunk in hunks {
                        checkpoint(live)?;
                        validate_span(hunk.old, &hunk.before, *before_bytes)?;
                        validate_span(hunk.new, &hunk.after, *after_bytes)?;
                        count(&mut payload, hunk.before.len(), options.limits.max_output_bytes)?;
                        count(&mut payload, hunk.after.len(), options.limits.max_output_bytes)?;
                    }
                }
            }
        }
    }
    checkpoint(live)
}
fn entry_identity(out: &mut Output, value: Option<EntryIdentity>) -> Result<(), ApiError> {
    match value {
        None => out.append("null"),
        Some(value) => out.append(&format!("{{\"object_id\":{},\"mode\":{}}}", quote(&value.oid.to_string()), quote(&format!("{:06o}", value.mode)))),
    }
}
fn span(out: &mut Output, value: ReviewSpan) -> Result<(), ApiError> {
    out.append(&format!("{{\"byte_start\":{},\"byte_end\":{},\"line_start\":{},\"line_count\":{}}}",
        value.byte_start, value.byte_end, value.line_start, value.line_count))
}
fn render_entry(out: &mut Output, entry: &ReviewedEntry, live: &mut impl FnMut() -> bool) -> Result<(), ApiError> {
    checkpoint(live)?;
    let kind = match entry.kind { ChangeKind::Added => "added", ChangeKind::Deleted => "deleted",
        ChangeKind::Modified => "modified", ChangeKind::ModeChanged => "mode_changed", ChangeKind::TypeChanged => "type_changed" };
    out.append("{\"path_hex\":")?; out.hex(&entry.path, live)?;
    out.append(&format!(",\"kind\":{},\"before\":", quote(kind)))?; entry_identity(out, entry.before)?;
    out.append(",\"after\":")?; entry_identity(out, entry.after)?;
    out.append(",\"content\":{")?;
    match &entry.content {
        ReviewContent::Identical => out.append("\"kind\":\"identical\"")?,
        ReviewContent::ObjectOnly => out.append("\"kind\":\"object_only\"")?,
        ReviewContent::Binary { before_bytes, after_bytes } => out.append(&format!(
            "\"kind\":\"binary\",\"before_bytes\":{before_bytes},\"after_bytes\":{after_bytes}"))?,
        ReviewContent::Text { algorithm, additions, deletions, before_bytes, after_bytes, hunks } => {
            out.append(&format!(concat!("\"kind\":\"text\",\"algorithm\":{},\"additions\":{},\"deletions\":{},",
                "\"before_bytes\":{},\"after_bytes\":{},\"hunks\":["),
                quote(&format!("{algorithm:?}")), additions, deletions, before_bytes, after_bytes))?;
            for (index, hunk) in hunks.iter().enumerate() {
                checkpoint(live)?;
                if index != 0 { out.append(",")?; }
                out.append("{\"old\":")?; span(out, hunk.old)?;
                out.append(",\"new\":")?; span(out, hunk.new)?;
                out.append(",\"before_hex\":")?; out.hex(&hunk.before, live)?;
                out.append(",\"after_hex\":")?; out.hex(&hunk.after, live)?;
                out.append("}")?;
            }
            out.append("]")?;
        }
    }
    out.append("}}")
}
pub(super) fn render(node: &OneNode, command: &Command, report: &SourceReview,
    maximum: usize, live: &mut impl FnMut() -> bool,
) -> Result<String, ApiError> {
    checkpoint(live)?;
    if report.repository_id != node.repository_id { return Err(ApiError::unavailable()); }
    if command.expected_head.is_some_and(|expected| expected != report.source_head) {
        return Err(ApiError::new(Status::Conflict, "source_snapshot_moved"));
    }
    let comparison = &report.comparison;
    if command.expected_before.is_some_and(|id| id != comparison.requested_before)
        || command.expected_after.is_some_and(|id| id != comparison.requested_after)
    { return Err(ApiError::new(Status::Conflict, "source_commit_moved")); }
    match &command.selection {
        ReviewSelection::References { before, after } => {
            if &report.before_reference != before || &report.after_reference != after || report.pull_request.is_some() {
                return Err(ApiError::unavailable());
            }
        }
        ReviewSelection::PullRequest { number, expected_version } => {
            if report.pull_request.is_none_or(|(actual, version)| actual != *number
                || expected_version.is_some_and(|expected| expected != version))
            { return Err(ApiError::unavailable()); }
        }
    }
    if comparison.mode != command.options.mode
        || (comparison.mode == ComparisonMode::Direct && comparison.compared_before != comparison.requested_before)
        || [comparison.requested_before, comparison.requested_after, comparison.compared_before,
            comparison.before_tree, comparison.after_tree].iter().any(|id| !valid_oid(*id, node.object_format))
    { return Err(ApiError::unavailable()); }
    validate_entries(&comparison.entries, &command.options, node.object_format, live)?;
    let mut out = Output::new(maximum);
    let id = report.source_head.as_internal_object_id();
    let digest = id.digest().as_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>();
    let token = format!("alg:{}:{digest}", id.algorithm().code_point());
    let mode = match comparison.mode { ComparisonMode::Direct => "direct", ComparisonMode::MergeBase => "merge-base" };
    let pr = report.pull_request.map_or_else(|| "null".into(), |(number, version)|
        format!("{{\"number\":{},\"version\":{}}}", number.get(), version.get()));
    out.append(&format!(concat!("{{\"type\":\"source_diff\",\"schema_version\":1,\"profile\":\"native-tree-review-v1\",",
        "\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},\"object_format\":{},",
        "\"source_head\":{},\"snapshot_token\":{},\"mode\":{},\"pull_request\":{},",
        "\"read_only\":true,\"transaction_created\":false,\"published\":false,\"approval_created\":false,",
        "\"complete\":true,\"line_origin\":0,\"context_lines\":{},\"before_ref_hex\":"),
        quote(&node.tenant_id.to_string()), quote(&node.repository_id.to_string()),
        quote(&node.repository_incarnation_id().to_string()), quote(node.object_format.as_str()),
        quote(&report.source_head.to_string()), quote(&token), quote(mode), pr, command.options.context_lines))?;
    out.hex(report.before_reference.as_bytes(), live)?;
    out.append(",\"after_ref_hex\":")?; out.hex(report.after_reference.as_bytes(), live)?;
    out.append(&format!(concat!(",\"requested_before\":{},\"requested_after\":{},\"compared_before\":{},",
        "\"before_tree\":{},\"after_tree\":{},\"entry_count\":{},\"path_prefixes_hex\":["),
        quote(&comparison.requested_before.to_string()), quote(&comparison.requested_after.to_string()),
        quote(&comparison.compared_before.to_string()), quote(&comparison.before_tree.to_string()),
        quote(&comparison.after_tree.to_string()), comparison.entries.len()))?;
    for (index, path) in command.options.paths.iter().enumerate() {
        if index != 0 { out.append(",")?; } out.hex(path, live)?;
    }
    out.append("],\"entries\":[")?;
    for (index, entry) in comparison.entries.iter().enumerate() {
        if index != 0 { out.append(",")?; } render_entry(&mut out, entry, live)?;
    }
    out.append("]}")?;
    checkpoint(live)?;
    Ok(out.body)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn byte_payloads_are_lossless_and_expansion_is_bounded_before_allocation() {
        let mut out = Output::new(12);
        out.hex(b"\0\xff\r\n\x1b", &mut || true).unwrap();
        assert_eq!(out.body, "\"00ff0d0a1b\"");
        let prior = out.body.clone();
        assert!(out.hex(b"x", &mut || true).is_err()); assert_eq!(out.body, prior);
        assert!(Output::new(8).hex(b"payload", &mut || true).is_err());
        assert!(Output::new(100).hex(b"bytes", &mut || false).is_err());
    }
    #[test]
    fn exact_spans_preserve_crlf_non_utf8_and_missing_final_newlines() {
        let bytes = b"a\r\n\xff";
        let span = ReviewSpan { byte_start: 0, byte_end: 4, line_start: 0, line_count: 2 };
        validate_span(span, bytes, 4).unwrap();
        assert!(validate_span(span, bytes, 5).is_err());
        assert!(validate_span(ReviewSpan { line_count: 1, ..span }, bytes, 4).is_err());
        assert!(validate_span(ReviewSpan { byte_end: 3, ..span }, bytes, 4).is_err());
        validate_span(ReviewSpan { byte_start: 4, byte_end: 4, line_start: 2, line_count: 0 }, b"", 4).unwrap();
    }
    #[test]
    fn directory_records_and_prefixes_do_not_become_file_payloads() {
        let format = GitHashAlgorithm::Sha1;
        let id = GitOid::from_hex(format, &"a".repeat(40)).unwrap();
        let mut entry = ReviewedEntry { path: b"dir".to_vec(), before: None,
            after: Some(EntryIdentity { mode: 0o040000, oid: id }), kind: ChangeKind::Added,
            content: ReviewContent::ObjectOnly };
        let mut options = ReviewOptions::default();
        validate_entries(&[entry.clone()], &options, format, &mut || true).unwrap();
        entry.content = ReviewContent::Binary { before_bytes: 0, after_bytes: 4 };
        assert!(validate_entries(&[entry.clone()], &options, format, &mut || true).is_err());
        entry.content = ReviewContent::ObjectOnly;
        options.paths = vec![b"di".to_vec()];
        assert!(validate_entries(&[entry.clone()], &options, format, &mut || true).is_err());
        options.paths = vec![b"dir".to_vec()];
        assert!(validate_entries(&[entry.clone(), entry.clone()], &options, format, &mut || true).is_err());
        assert!(validate_entries(&[entry], &options, format, &mut || false).is_err());
    }
}
