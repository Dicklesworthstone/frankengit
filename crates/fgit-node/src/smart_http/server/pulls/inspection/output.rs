//! A complete bounded inspection report, built before HTTP success. Paths,
//! native commit metadata and hunk bytes are hex, never lossy UTF-8 or HTML.
//! Binary/object-only entries are explicit rather than invisible empty diffs.

use fgit_forge::review::{ChangeKind, ComparisonMode, EntryIdentity, ReviewContent, ReviewSpan, ReviewedEntry};
use fgit_types::GitOid;
use crate::OneNode;
use crate::treefs_workspace::candidate_inspection::PullRequestInspection;
use super::super::super::issues::{ApiError, quote};
use super::super::super::Status;

pub(super) const MAX_REPLY_BYTES: usize = 32 * 1024 * 1024;

struct Json<'a, C> {
    text: String,
    maximum: usize,
    live: &'a mut C,
}
impl<C: FnMut() -> bool> Json<'_, C> {
    fn checkpoint(&mut self) -> Result<(), ApiError> {
        if (self.live)() { Ok(()) } else { Err(ApiError::from_status(Status::Timeout, false)) }
    }
    fn reserve(&mut self, bytes: usize) -> Result<(), ApiError> {
        self.checkpoint()?;
        let end = self.text.len().checked_add(bytes).filter(|n| *n <= self.maximum)
            .ok_or_else(ApiError::too_large)?;
        if end > self.text.capacity() {
            let capacity = end.max(self.text.capacity().saturating_mul(2)).min(self.maximum);
            self.text.try_reserve_exact(capacity - self.text.len()).map_err(|_| ApiError::unavailable())?;
        }
        Ok(())
    }
    fn put(&mut self, value: &str) -> Result<(), ApiError> {
        self.reserve(value.len())?;
        self.text.push_str(value);
        Ok(())
    }
    fn hex(&mut self, bytes: &[u8]) -> Result<(), ApiError> {
        let count = bytes.len().checked_mul(2).and_then(|n| n.checked_add(2)).ok_or_else(ApiError::too_large)?;
        self.reserve(count)?;
        self.text.push('"');
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for chunk in bytes.chunks(16 * 1024) {
            self.checkpoint()?;
            for byte in chunk {
                self.text.push(char::from(HEX[usize::from(byte >> 4)]));
                self.text.push(char::from(HEX[usize::from(byte & 15)]));
            }
        }
        self.text.push('"');
        Ok(())
    }
}
fn id(value: Option<EntryIdentity>) -> String {
    value.map_or_else(|| "null".to_owned(), |value| format!("{{\"mode\":{},\"oid\":{}}}", value.mode, quote(&value.oid.to_string())))
}
fn oids(values: &[GitOid]) -> String {
    format!("[{}]", values.iter().map(|oid| quote(&oid.to_string())).collect::<Vec<_>>().join(","))
}
fn span(value: ReviewSpan, bytes: &[u8], total: usize) -> Result<String, ApiError> {
    if value.byte_end > total || value.byte_end.checked_sub(value.byte_start) != Some(bytes.len())
        || value.line_start.checked_add(value.line_count).is_none()
        || value.line_count != bytes.iter().filter(|&&b| b == b'\n').count()
            + usize::from(!bytes.is_empty() && !bytes.ends_with(b"\n"))
    { return Err(ApiError::unavailable()); }
    Ok(format!("{{\"byte_start\":{},\"byte_end\":{},\"line_start\":{},\"line_count\":{}}}",
        value.byte_start, value.byte_end, value.line_start, value.line_count))
}
fn entry<C: FnMut() -> bool>(out: &mut Json<'_, C>, value: &ReviewedEntry) -> Result<(), ApiError> {
    if value.path.is_empty() || value.path.len() > 4096 { return Err(ApiError::unavailable()); }
    out.put("{\"path_hex\":")?;
    out.hex(&value.path)?;
    let kind = match value.kind { ChangeKind::Added => "added", ChangeKind::Deleted => "deleted",
        ChangeKind::Modified => "modified", ChangeKind::ModeChanged => "mode_changed", ChangeKind::TypeChanged => "type_changed" };
    out.put(&format!(",\"kind\":{},\"before\":{},\"after\":{},\"content\":", quote(kind), id(value.before), id(value.after)))?;
    match &value.content {
        ReviewContent::Identical => out.put("{\"type\":\"identical\",\"content_read\":false}")?,
        ReviewContent::ObjectOnly => out.put("{\"type\":\"object_only\",\"content_read\":false}")?,
        ReviewContent::Binary { before_bytes, after_bytes } => out.put(&format!(
            "{{\"type\":\"binary\",\"before_bytes\":{before_bytes},\"after_bytes\":{after_bytes},\"body_included\":false}}"))?,
        ReviewContent::Text { algorithm, additions, deletions, before_bytes, after_bytes, hunks } => {
            if hunks.len() > 4096 { return Err(ApiError::unavailable()); }
            out.put(&format!(concat!("{{\"type\":\"text\",\"algorithm\":{},\"additions\":{},\"deletions\":{},",
                "\"before_bytes\":{},\"after_bytes\":{},\"hunks\":["),
                quote(&format!("{algorithm:?}")), additions, deletions, before_bytes, after_bytes))?;
            let mut ends = (0, 0);
            for (index, hunk) in hunks.iter().enumerate() {
                if hunk.old.byte_start < ends.0 || hunk.new.byte_start < ends.1 { return Err(ApiError::unavailable()); }
                let old = span(hunk.old, &hunk.before, *before_bytes)?;
                let new = span(hunk.new, &hunk.after, *after_bytes)?;
                ends = (hunk.old.byte_end, hunk.new.byte_end);
                if index != 0 { out.put(",")?; }
                out.put(&format!("{{\"old\":{old},\"new\":{new},\"before_hex\":"))?;
                out.hex(&hunk.before)?;
                out.put(",\"after_hex\":")?;
                out.hex(&hunk.after)?;
                out.put("}")?;
            }
            out.put("]}")?;
        }
    }
    out.put("}")
}

pub(super) fn build(node: &OneNode, value: &PullRequestInspection, maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<String, ApiError> {
    let review = &value.review;
    let subject = &value.subject;
    let comparison = &review.comparison;
    if review.repository_id != node.repository_id
        || review.pull_request != Some((subject.pull_request, subject.pull_request_version))
        || comparison.mode != ComparisonMode::Direct || comparison.requested_before != subject.target_tip
        || comparison.compared_before != subject.target_tip || comparison.requested_after != value.candidate.commit
        || value.parents != [subject.target_tip, subject.source_tip]
        || value.prerequisites.len() > 64 || value.candidate_commit_body.len() > 2 * 1024 * 1024
        || comparison.entries.len() > 512
        || comparison.entries.windows(2).any(|rows| rows[0].path >= rows[1].path)
    { return Err(ApiError::unavailable()); }
    value.candidate.validate(subject).map_err(|_| ApiError::unavailable())?;
    let mut out = Json { text: String::new(), maximum: maximum.min(MAX_REPLY_BYTES), live };
    let head = review.source_head.as_internal_object_id();
    let digest: String = head.digest().as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    let token = format!("alg:{}:{digest}", head.algorithm().code_point());
    out.put(&format!(concat!("{{\"type\":\"candidate_inspection\",\"schema_version\":1,\"tenant_id\":{},",
        "\"repository_id\":{},\"repository_incarnation\":{},\"object_format\":{},\"source_head\":{},\"snapshot_token\":{},",
        "\"read_only\":true,\"objects_staged\":false,\"transaction_created\":false,\"published\":false,",
        "\"merge_authorized\":false,\"all_changed_paths\":true,\"binary_bodies_included\":false,",
        "\"comparison_profile\":\"full-tree-direct-path-myers-v1\",\"context_lines\":3,",
        "\"subject\":{{\"pull_request\":{},\"pull_request_version\":{},\"policy_epoch\":{},",
        "\"source_ref\":{},\"target_ref\":{},\"source_tip\":{},\"target_tip\":{}}},",
        "\"merge_base\":{},\"candidate_commit\":{},\"parents\":{},\"prerequisites\":{},",
        "\"candidate_commit_body_hex\":"),
        quote(&node.tenant_id.to_string()), quote(&node.repository_id.to_string()),
        quote(&node.repository_incarnation_id().to_string()), quote(node.object_format.as_str()),
        quote(&review.source_head.to_string()), quote(&token), subject.pull_request.get(),
        subject.pull_request_version.get(), subject.policy_epoch.get(), quote(subject.source_ref.as_str()),
        quote(subject.target_ref.as_str()), quote(&subject.source_tip.to_string()), quote(&subject.target_tip.to_string()),
        quote(&value.candidate.merge_base.to_string()), quote(&value.candidate.commit.to_string()),
        oids(&value.parents), oids(&value.prerequisites)))?;
    out.hex(&value.candidate_commit_body)?;
    out.put(&format!(concat!(",\"bundle\":{{\"bytes\":{},\"pack_bytes\":{},\"pack_objects\":{},\"expanded_bytes\":{},",
        "\"closure_objects\":{},\"transport_only_objects\":{},\"sha256\":"),
        value.bundle.bytes, value.bundle.pack_bytes, value.bundle.pack_objects, value.bundle.expanded_bytes,
        value.bundle.closure_objects, value.bundle.transport_only_objects))?;
    out.hex(&value.bundle.sha256)?;
    out.put(&format!(concat!("}},\"comparison\":{{\"mode\":\"direct\",\"before\":{},\"after\":{},",
        "\"before_tree\":{},\"after_tree\":{},\"entry_count\":{},\"entries\":["),
        quote(&comparison.requested_before.to_string()), quote(&comparison.requested_after.to_string()),
        quote(&comparison.before_tree.to_string()), quote(&comparison.after_tree.to_string()), comparison.entries.len()))?;
    for (index, row) in comparison.entries.iter().enumerate() {
        if index != 0 { out.put(",")?; }
        entry(&mut out, row)?;
    }
    out.put("]}}")?;
    out.checkpoint()?;
    Ok(out.text)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn byte_fields_preserve_non_utf8_nul_crlf_and_missing_final_newline() {
        let mut live = || true;
        let mut out = Json { text: String::new(), maximum: 64, live: &mut live };
        out.hex(b"\0\xff\r\n<script>").unwrap();
        assert_eq!(out.text, "\"00ff0d0a3c7363726970743e\"");
        assert!(span(ReviewSpan { byte_start: 0, byte_end: 2, line_start: 0, line_count: 1 }, b"\xffx", 2).is_ok());
        assert!(span(ReviewSpan { byte_start: 1, byte_end: 4, line_start: 0, line_count: 1 }, b"x\r\n", 3).is_err());
    }
    #[test]
    fn hex_growth_refuses_before_allocation_and_cancellation_stops_large_fields() {
        let mut live = || true;
        let mut out = Json { text: "abc".into(), maximum: 6, live: &mut live };
        assert!(out.hex(b"xx").is_err());
        assert_eq!(out.text, "abc");
        let mut calls = 0;
        let mut live = || { calls += 1; calls < 3 };
        let mut out = Json { text: String::new(), maximum: 100_000, live: &mut live };
        assert!(out.hex(&vec![0xff; 32_000]).is_err());
    }
    #[test]
    fn binary_and_object_only_entries_cannot_look_like_empty_text_changes() {
        let mut live = || true;
        for content in [ReviewContent::Binary { before_bytes: 10, after_bytes: 11 }, ReviewContent::ObjectOnly, ReviewContent::Identical] {
            let mut out = Json { text: String::new(), maximum: 1024, live: &mut live };
            entry(&mut out, &ReviewedEntry { path: b"x\xff".to_vec(), before: None, after: None,
                kind: ChangeKind::Modified, content }).unwrap();
            assert!(out.text.contains("\"path_hex\":\"78ff\""));
            assert!(!out.text.contains("\"hunks\":[]"));
        }
    }
}
