//! Fully bounded source-change artifacts and receipts. Preparation owns its
//! native bundle until delivery; no extra bundle-sized response copy is made.

use super::super::super::{
    Status,
    issues::{ApiError, Reply as JsonReply, quote, ref_fields},
};
use crate::{OneNode, treefs_workspace::WorkspacePatchCandidate};
use fgit_admission::AdmissionResult;
use fgit_crypto::sha256_digest;
use fgit_forge::review::{
    ChangeKind, ComparisonMode, EntryIdentity, ReviewContent, ReviewSpan, SourceReview,
};
use fgit_types::{DecisionOutcome, GitOid, PrincipalId, RefName};
use fgit_wire::smart_http::HttpVersion;
use std::io::{self, Write};

const MAX_BUNDLE: usize = 64 * 1024 * 1024;
const MAX_METADATA: usize = 1024 * 1024;
pub(super) const MAX_INSPECTION: usize = 32 * 1024 * 1024;

fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), ApiError> {
    if live() {
        Ok(())
    } else {
        Err(ApiError::from_status(Status::Timeout, false))
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn optional_oid(id: Option<GitOid>) -> String {
    id.map_or_else(|| "null".into(), |id| quote(&id.to_string()))
}
fn scope(node: &OneNode) -> String {
    format!(
        "\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},\"object_format\":{}",
        quote(&node.tenant_id.to_string()),
        quote(&node.repository_id.to_string()),
        quote(&node.repository_incarnation_id().to_string()),
        quote(node.object_format.as_str())
    )
}
fn append(out: &mut String, text: &str, maximum: usize) -> Result<(), ApiError> {
    if out
        .len()
        .checked_add(text.len())
        .is_none_or(|n| n > maximum)
    {
        return Err(ApiError::too_large());
    }
    out.try_reserve(text.len())
        .map_err(|_| ApiError::unavailable())?;
    out.push_str(text);
    Ok(())
}
fn append_hex(
    out: &mut String,
    bytes: &[u8],
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<(), ApiError> {
    let count = bytes
        .len()
        .checked_mul(2)
        .and_then(|n| n.checked_add(2))
        .ok_or_else(ApiError::too_large)?;
    if out.len().checked_add(count).is_none_or(|n| n > maximum) {
        return Err(ApiError::too_large());
    }
    out.try_reserve(count)
        .map_err(|_| ApiError::unavailable())?;
    out.push('"');
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for chunk in bytes.chunks(16 * 1024) {
        checkpoint(live)?;
        for byte in chunk {
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    out.push('"');
    Ok(())
}

pub(in crate::smart_http::server::source) struct PatchReply {
    candidate: WorkspacePatchCandidate,
    content_type: String,
    prefix: String,
    suffix: String,
    length: usize,
}
impl PatchReply {
    pub fn send(&self, writer: &mut impl Write, version: HttpVersion) -> io::Result<()> {
        let version = match version {
            HttpVersion::Http10 => "HTTP/1.0",
            HttpVersion::Http11 => "HTTP/1.1",
        };
        write!(
            writer,
            "{version} 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nVary: Authorization\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
            self.content_type, self.length
        )?;
        writer.write_all(self.prefix.as_bytes())?;
        writer.write_all(self.candidate.bundle_bytes())?;
        writer.write_all(self.suffix.as_bytes())?;
        writer.flush()
    }
}
fn contains(
    bytes: &[u8],
    pattern: &[u8],
    live: &mut impl FnMut() -> bool,
) -> Result<bool, ApiError> {
    let mut offset = 0_usize;
    while offset < bytes.len() {
        checkpoint(live)?;
        let end = offset
            .saturating_add(64 * 1024 + pattern.len() - 1)
            .min(bytes.len());
        if bytes[offset..end]
            .windows(pattern.len())
            .any(|window| window == pattern)
        {
            return Ok(true);
        }
        offset += 64 * 1024;
    }
    Ok(false)
}
pub(super) fn prepared(
    node: &OneNode,
    reference: &RefName,
    base: GitOid,
    candidate: WorkspacePatchCandidate,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<PatchReply, ApiError> {
    checkpoint(live)?;
    if candidate.object_format != node.object_format
        || candidate.source_commit != base
        || candidate.candidate_commit.is_zero()
        || candidate.paths.is_empty()
        || candidate.paths.len() > 1024
    {
        return Err(ApiError::unavailable());
    }
    let bytes = candidate.bundle_bytes();
    if bytes.is_empty() || bytes.len() > MAX_BUNDLE {
        return Err(ApiError::too_large());
    }
    let digest = hex(&sha256_digest(bytes));
    let mut metadata = format!(
        concat!(
            "{{\"type\":\"source_preparation\",{},{},\"source_commit\":{},",
            "\"source_rcr\":{},\"candidate_commit\":{},\"root_tree\":{},\"patch_sha256\":{},\"object_count\":{},",
            "\"read_only\":true,\"objects_staged\":false,\"transaction_created\":false,\"published\":false,",
            "\"publication_authorized\":false,\"bundle\":{{\"bytes\":{},\"sha256\":{}}},\"paths\":["
        ),
        scope(node),
        ref_fields("ref", reference),
        quote(&base.to_string()),
        quote(&candidate.source_rcr.to_string()),
        quote(&candidate.candidate_commit.to_string()),
        quote(&candidate.root_tree.to_string()),
        quote(&hex(&candidate.patch_sha256)),
        candidate.object_count,
        bytes.len(),
        quote(&digest)
    );
    for (index, path) in candidate.paths.iter().enumerate() {
        checkpoint(live)?;
        if path.path.is_empty() || path.path.len() > 4096 {
            return Err(ApiError::unavailable());
        }
        append(
            &mut metadata,
            &format!(
                "{}{{\"path_hex\":{},\"old_blob\":{},\"new_blob\":{},\"new_mode\":{},\"hunks\":{}}}",
                if index == 0 { "" } else { "," },
                quote(&hex(&path.path)),
                optional_oid(path.old_blob),
                optional_oid(path.new_blob),
                path.new_mode
                    .map_or_else(|| "null".into(), |mode| mode.to_string()),
                path.hunks
            ),
            MAX_METADATA,
        )?;
    }
    append(&mut metadata, "]}", MAX_METADATA)?;
    let mut boundary = None;
    for attempt in 0..16 {
        let value = format!("fg-source-{}-{attempt:x}", &digest[..48]);
        let marker = format!("--{value}");
        if !contains(metadata.as_bytes(), marker.as_bytes(), live)?
            && !contains(bytes, marker.as_bytes(), live)?
        {
            boundary = Some(value);
            break;
        }
    }
    let boundary = boundary.ok_or_else(ApiError::too_large)?;
    let prefix = format!(
        "--{boundary}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Disposition: inline; name=\"metadata\"\r\n\r\n{metadata}\r\n--{boundary}\r\nContent-Type: application/x-git-bundle\r\nContent-Disposition: attachment; name=\"bundle\"; filename=\"candidate.bundle\"\r\n\r\n"
    );
    let suffix = format!("\r\n--{boundary}--\r\n");
    let length = prefix
        .len()
        .checked_add(bytes.len())
        .and_then(|n| n.checked_add(suffix.len()))
        .filter(|n| *n <= maximum)
        .ok_or_else(ApiError::too_large)?;
    checkpoint(live)?;
    Ok(PatchReply {
        candidate,
        content_type: format!("multipart/mixed; boundary={boundary}"),
        prefix,
        suffix,
        length,
    })
}

fn entry(id: Option<EntryIdentity>) -> String {
    id.map_or_else(
        || "null".into(),
        |id| {
            format!(
                "{{\"mode\":{},\"oid\":{}}}",
                id.mode,
                quote(&id.oid.to_string())
            )
        },
    )
}
fn span(value: ReviewSpan, bytes: &[u8], total: usize) -> Result<String, ApiError> {
    if value.byte_end > total
        || value.byte_end.checked_sub(value.byte_start) != Some(bytes.len())
        || value.line_start.checked_add(value.line_count).is_none()
        || value.line_count
            != bytes.iter().filter(|&&b| b == b'\n').count()
                + usize::from(!bytes.is_empty() && !bytes.ends_with(b"\n"))
    {
        return Err(ApiError::unavailable());
    }
    Ok(format!(
        "{{\"byte_start\":{},\"byte_end\":{},\"line_start\":{},\"line_count\":{}}}",
        value.byte_start, value.byte_end, value.line_start, value.line_count
    ))
}
pub(super) fn inspection(
    node: &OneNode,
    reference: &RefName,
    base: GitOid,
    candidate: GitOid,
    review: &SourceReview,
    parents: &[GitOid],
    commit: &[u8],
    bundle_digest: &[u8; 32],
    bundle_bytes: usize,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<String, ApiError> {
    checkpoint(live)?;
    let maximum = maximum.min(MAX_INSPECTION);
    let comparison = &review.comparison;
    if review.repository_id != node.repository_id
        || review.before_reference != *reference
        || review.after_reference != *reference
        || review.pull_request.is_some()
        || comparison.mode != ComparisonMode::Direct
        || comparison.requested_before != base
        || comparison.compared_before != base
        || comparison.requested_after != candidate
        || parents != [base]
        || commit.len() > 2 * 1024 * 1024
        || comparison.entries.len() > 512
        || comparison
            .entries
            .windows(2)
            .any(|rows| rows[0].path >= rows[1].path)
    {
        return Err(ApiError::unavailable());
    }
    let head = review.source_head.as_internal_object_id();
    let token = format!(
        "alg:{}:{}",
        head.algorithm().code_point(),
        hex(head.digest().as_bytes())
    );
    let mut out = String::new();
    append(
        &mut out,
        &format!(
            concat!(
                "{{\"type\":\"source_inspection\",{},{},\"source_head\":{},\"snapshot_token\":{},",
                "\"expected_commit\":{},\"candidate_commit\":{},\"parents\":[{}],\"bundle_bytes\":{},\"bundle_sha256\":{},",
                "\"read_only\":true,\"objects_staged\":false,\"transaction_created\":false,\"published\":false,",
                "\"publication_authorized\":false,\"all_changed_paths\":true,\"binary_bodies_included\":false,",
                "\"candidate_commit_body_hex\":"
            ),
            scope(node),
            ref_fields("ref", reference),
            quote(&review.source_head.to_string()),
            quote(&token),
            quote(&base.to_string()),
            quote(&candidate.to_string()),
            quote(&base.to_string()),
            bundle_bytes,
            quote(&hex(bundle_digest))
        ),
        maximum,
    )?;
    append_hex(&mut out, commit, maximum, live)?;
    append(
        &mut out,
        &format!(
            ",\"comparison\":{{\"mode\":\"direct\",\"before_tree\":{},\"after_tree\":{},\"entry_count\":{},\"entries\":[",
            quote(&comparison.before_tree.to_string()),
            quote(&comparison.after_tree.to_string()),
            comparison.entries.len()
        ),
        maximum,
    )?;
    for (index, row) in comparison.entries.iter().enumerate() {
        checkpoint(live)?;
        if row.path.is_empty() || row.path.len() > 4096 {
            return Err(ApiError::unavailable());
        }
        let kind = match row.kind {
            ChangeKind::Added => "added",
            ChangeKind::Deleted => "deleted",
            ChangeKind::Modified => "modified",
            ChangeKind::ModeChanged => "mode_changed",
            ChangeKind::TypeChanged => "type_changed",
        };
        append(
            &mut out,
            &format!(
                "{}{{\"path_hex\":{},\"kind\":{},\"before\":{},\"after\":{},\"content\":",
                if index == 0 { "" } else { "," },
                quote(&hex(&row.path)),
                quote(kind),
                entry(row.before),
                entry(row.after)
            ),
            maximum,
        )?;
        match &row.content {
            ReviewContent::Identical => append(
                &mut out,
                "{\"type\":\"identical\",\"content_read\":false}",
                maximum,
            )?,
            ReviewContent::ObjectOnly => append(
                &mut out,
                "{\"type\":\"object_only\",\"content_read\":false}",
                maximum,
            )?,
            ReviewContent::Binary {
                before_bytes,
                after_bytes,
            } => append(
                &mut out,
                &format!(
                    "{{\"type\":\"binary\",\"before_bytes\":{before_bytes},\"after_bytes\":{after_bytes},\"body_included\":false}}"
                ),
                maximum,
            )?,
            ReviewContent::Text {
                algorithm,
                additions,
                deletions,
                before_bytes,
                after_bytes,
                hunks,
            } => {
                if hunks.len() > 4096 {
                    return Err(ApiError::unavailable());
                }
                append(
                    &mut out,
                    &format!(
                        "{{\"type\":\"text\",\"algorithm\":{},\"additions\":{additions},\"deletions\":{deletions},\"before_bytes\":{before_bytes},\"after_bytes\":{after_bytes},\"hunks\":[",
                        quote(&format!("{algorithm:?}"))
                    ),
                    maximum,
                )?;
                let mut ends = (0, 0);
                for (index, hunk) in hunks.iter().enumerate() {
                    if hunk.old.byte_start < ends.0 || hunk.new.byte_start < ends.1 {
                        return Err(ApiError::unavailable());
                    }
                    let old = span(hunk.old, &hunk.before, *before_bytes)?;
                    let new = span(hunk.new, &hunk.after, *after_bytes)?;
                    ends = (hunk.old.byte_end, hunk.new.byte_end);
                    append(
                        &mut out,
                        &format!(
                            "{}{{\"old\":{old},\"new\":{new},\"before_hex\":",
                            if index == 0 { "" } else { "," }
                        ),
                        maximum,
                    )?;
                    append_hex(&mut out, &hunk.before, maximum, live)?;
                    append(&mut out, ",\"after_hex\":", maximum)?;
                    append_hex(&mut out, &hunk.after, maximum, live)?;
                    append(&mut out, "}", maximum)?;
                }
                append(&mut out, "]}", maximum)?;
            }
        }
        append(&mut out, "}", maximum)?;
    }
    append(&mut out, "]}}", maximum)?;
    checkpoint(live)?;
    Ok(out)
}

pub(super) fn publication(
    node: &OneNode,
    principal: PrincipalId,
    reference: &RefName,
    base: GitOid,
    candidate: GitOid,
    result: AdmissionResult,
    maximum: usize,
) -> Result<JsonReply, ApiError> {
    let [command] = result.commands.as_slice() else {
        return Err(ApiError::unknown());
    };
    if !result.session.atomic || result.session.tx_ids.as_slice() != [command.tx_id] {
        return Err(ApiError::unknown());
    }
    let (status, outcome, record, code) = match command.terminal.outcome {
        DecisionOutcome::Committed {
            repository_commit_id,
        } => (
            Status::Success,
            "committed",
            quote(&repository_commit_id.to_string()),
            "null".to_owned(),
        ),
        DecisionOutcome::Refused {
            code,
            refusal_record_id,
        } => (
            Status::Conflict,
            "refused",
            quote(&refusal_record_id.to_string()),
            quote(&format!("{code:?}")),
        ),
    };
    let body = format!(
        concat!(
            "{{\"type\":\"source_publication\",{},\"principal_id\":{},{},\"expected_commit\":{},",
            "\"candidate_commit\":{},\"tx_id\":{},\"outcome\":{},\"decision_sequence\":{},\"decision_record\":{},",
            "\"refusal_code\":{},\"delivery_acknowledged\":null}}"
        ),
        scope(node),
        quote(&principal.to_string()),
        ref_fields("ref", reference),
        quote(&base.to_string()),
        quote(&candidate.to_string()),
        quote(&command.tx_id.to_string()),
        quote(outcome),
        command.terminal.decision_sequence.get(),
        record,
        code
    );
    if body.len() > maximum {
        eprintln!(
            "Source reply limit after canonical transaction {}; recover the original key",
            command.tx_id
        );
        return Err(ApiError::unknown());
    }
    Ok(JsonReply {
        status,
        body,
        terminal: Some((command.tx_id, command.terminal)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn byte_growth_is_checked_before_encoding_and_cancellation_is_not_success() {
        let mut out = "abc".to_owned();
        assert!(append_hex(&mut out, b"xx", 6, &mut || true).is_err());
        assert_eq!(out, "abc");
        let mut out = String::new();
        append_hex(&mut out, b"\0\xff\r\n", 10, &mut || true).unwrap();
        assert_eq!(out, "\"00ff0d0a\"");
        assert!(append_hex(&mut String::new(), b"x", 4, &mut || false).is_err());
    }
    #[test]
    fn boundary_scans_cover_chunk_edges_and_spans_reject_inconsistent_lengths() {
        let mut bytes = vec![b'x'; 65535];
        bytes.extend_from_slice(b"--boundary");
        assert!(contains(&bytes, b"--boundary", &mut || true).unwrap());
        assert!(contains(&bytes, b"--boundary", &mut || false).is_err());
        assert!(
            span(
                ReviewSpan {
                    byte_start: 0,
                    byte_end: 3,
                    line_start: 0,
                    line_count: 1
                },
                b"x\r\n",
                3
            )
            .is_ok()
        );
        assert!(
            span(
                ReviewSpan {
                    byte_start: 0,
                    byte_end: 4,
                    line_start: 0,
                    line_count: 1
                },
                b"x\r\n",
                3
            )
            .is_err()
        );
    }
}
