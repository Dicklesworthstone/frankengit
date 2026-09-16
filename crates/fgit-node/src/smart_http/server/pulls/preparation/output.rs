//! Bounded read-only artifacts. A clean result has JSON metadata and a binary
//! Git bundle in one multipart/mixed response; no second bundle-sized copy is
//! made. Boundary collisions, limits and cancellation are checked before HTTP
//! success. Conflict paths are exact hex bytes, not lossy or executable text.

use std::io::{self, Write};
use fgit_crypto::sha256_digest;
use fgit_forge::event::review::ReviewSubject;
use fgit_forge::preparation::{ConflictKind, MergeEntry, MergePreparation};
use fgit_types::RepositoryAuthorityHeadId;
use fgit_wire::smart_http::HttpVersion;
use crate::OneNode;
use super::super::super::{Status, issues::{ApiError, quote}};

const MAX_METADATA_BYTES: usize = 2 * 1024 * 1024;
const MAX_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
pub(super) const MAX_REPLY_BYTES: usize = MAX_METADATA_BYTES + MAX_BUNDLE_BYTES + 16 * 1024;

pub(super) enum Reply {
    Json { status: Status, body: String },
    Bundle { content_type: String, prefix: String, bundle: Vec<u8>, suffix: String, length: usize },
}
impl Reply {
    pub(super) fn send(&self, writer: &mut impl Write, version: HttpVersion) -> io::Result<()> {
        let (status, content_type, length) = match self {
            Self::Json { status, body } => (*status, "application/json; charset=utf-8", body.len()),
            Self::Bundle { content_type, length, .. } => (Status::Success, content_type.as_str(), *length),
        };
        let version = match version { HttpVersion::Http10 => "HTTP/1.0", HttpVersion::Http11 => "HTTP/1.1" };
        write!(writer, "{version} {}\r\nContent-Type: {content_type}\r\nContent-Length: {length}\r\nCache-Control: no-store\r\nVary: Authorization\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n", status.line())?;
        match self {
            Self::Json { body, .. } => writer.write_all(body.as_bytes())?,
            Self::Bundle { prefix, bundle, suffix, .. } => {
                writer.write_all(prefix.as_bytes())?;
                writer.write_all(bundle)?;
                writer.write_all(suffix.as_bytes())?;
            }
        }
        writer.flush()
    }
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), ApiError> {
    if live() { Ok(()) } else { Err(ApiError::from_status(Status::Timeout, false)) }
}
fn append(out: &mut String, part: &str) -> Result<(), ApiError> {
    if out.len().checked_add(part.len()).is_none_or(|n| n > MAX_METADATA_BYTES) {
        return Err(ApiError::too_large());
    }
    out.try_reserve(part.len()).map_err(|_| ApiError::unavailable())?;
    out.push_str(part);
    Ok(())
}
fn entry(value: Option<&MergeEntry>) -> String {
    value.map_or_else(|| "null".to_owned(), |value| format!("{{\"mode\":{},\"oid\":{}}}",
        value.mode, quote(&value.oid.to_string())))
}
fn kind(value: ConflictKind) -> &'static str {
    match value {
        ConflictKind::Content => "content", ConflictKind::Binary => "binary",
        ConflictKind::ModifyDelete => "modify_delete", ConflictKind::TypeChange => "type_change",
        ConflictKind::Mode => "mode", ConflictKind::Opaque => "opaque",
        ConflictKind::AttributesRequireDriver => "attributes_require_driver",
    }
}

pub(super) fn build(node: &OneNode, head: RepositoryAuthorityHeadId, subject: &ReviewSubject,
    outcome: &MergePreparation, bundle: Option<Vec<u8>>, maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<Reply, ApiError> {
    checkpoint(live)?;
    if bundle.as_ref().is_some_and(|bytes| bytes.len() > MAX_BUNDLE_BYTES) { return Err(ApiError::too_large()); }
    let bundle_digest = bundle.as_ref().map(|bytes| hex(&sha256_digest(bytes)));
    checkpoint(live)?;
    let id = head.as_internal_object_id();
    let token = format!("alg:{}:{}", id.algorithm().code_point(), hex(id.digest().as_bytes()));
    let mut metadata = format!(concat!(
        "{{\"type\":\"merge_preparation\",\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},",
        "\"repository_incarnation\":{},\"object_format\":{},\"source_head\":{},\"snapshot_token\":{},",
        "\"profile\":\"path-merge-v1\",\"read_only\":true,\"objects_staged\":false,",
        "\"transaction_created\":false,\"published\":false,\"merge_authorized\":false,",
        "\"subject\":{{\"pull_request\":{},\"pull_request_version\":{},\"policy_epoch\":{},",
        "\"source_ref\":{},\"target_ref\":{},\"source_tip\":{},\"target_tip\":{}}},"),
        quote(&node.tenant_id.to_string()), quote(&node.repository_id.to_string()),
        quote(&node.repository_incarnation_id().to_string()), quote(node.object_format.as_str()),
        quote(&head.to_string()), quote(&token), subject.pull_request.get(), subject.pull_request_version.get(),
        subject.policy_epoch.get(), quote(subject.source_ref.as_str()), quote(subject.target_ref.as_str()),
        quote(&subject.source_tip.to_string()), quote(&subject.target_tip.to_string()));
    let status = match outcome {
        MergePreparation::Clean(plan) => {
            let bytes = bundle.as_ref().filter(|bytes| !bytes.is_empty()).ok_or_else(ApiError::unavailable)?;
            if plan.source != subject.source_tip || plan.target != subject.target_tip {
                return Err(ApiError::unavailable());
            }
            append(&mut metadata, &format!(concat!(
                "\"state\":\"clean\",\"candidate\":{{\"merge_base\":{},\"commit\":{},\"tree\":{},\"new_object_count\":{}}},",
                "\"bundle\":{{\"bytes\":{},\"sha256\":{}}},\"conflicts\":[]}}"),
                quote(&plan.base.to_string()), quote(&plan.commit.to_string()), quote(&plan.tree.to_string()),
                plan.objects.len(), bytes.len(), quote(bundle_digest.as_deref().ok_or_else(ApiError::unavailable)?)))?;
            Status::Success
        }
        MergePreparation::Conflicted { base, conflicts } => {
            if bundle.is_some() || conflicts.is_empty() || conflicts.len() > 128 { return Err(ApiError::unavailable()); }
            append(&mut metadata, &format!("\"state\":\"conflicted\",\"merge_base\":{},\"candidate\":null,\"bundle\":null,\"conflicts\":[", quote(&base.to_string())))?;
            for (index, conflict) in conflicts.iter().enumerate() {
                checkpoint(live)?;
                if conflict.path.len() > 4096 { return Err(ApiError::too_large()); }
                append(&mut metadata, &format!("{}{{\"path_hex\":{},\"kind\":{},\"base\":{},\"ours\":{},\"theirs\":{}}}",
                    if index == 0 { "" } else { "," }, quote(&hex(&conflict.path)), quote(kind(conflict.kind)),
                    entry(conflict.base.as_ref()), entry(conflict.ours.as_ref()), entry(conflict.theirs.as_ref())))?;
            }
            append(&mut metadata, "]}")?;
            Status::Conflict
        }
        MergePreparation::AlreadyUpToDate { target } => {
            if bundle.is_some() || *target != subject.target_tip { return Err(ApiError::unavailable()); }
            append(&mut metadata, "\"state\":\"already_up_to_date\",\"candidate\":null,\"bundle\":null,\"conflicts\":[]}")?;
            Status::Success
        }
    };
    checkpoint(live)?;
    let maximum = maximum.min(MAX_REPLY_BYTES);
    match bundle {
        None => {
            if metadata.len() > maximum { return Err(ApiError::too_large()); }
            Ok(Reply::Json { status, body: metadata })
        }
        Some(bundle) => mixed(metadata, bundle, bundle_digest.as_deref().ok_or_else(ApiError::unavailable)?, maximum, live),
    }
}

fn contains(bytes: &[u8], pattern: &[u8], live: &mut impl FnMut() -> bool) -> Result<bool, ApiError> {
    // Overlap preserves matches that straddle a cancellation checkpoint.
    let mut offset = 0;
    while offset < bytes.len() {
        checkpoint(live)?;
        let end = offset.saturating_add(64 * 1024 + pattern.len() - 1).min(bytes.len());
        if bytes[offset..end].windows(pattern.len()).any(|window| window == pattern) { return Ok(true); }
        offset = offset.saturating_add(64 * 1024);
    }
    Ok(false)
}
fn mixed(metadata: String, bundle: Vec<u8>, digest: &str, maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<Reply, ApiError> {
    let mut selected = None;
    // The hash is a deterministic transport checksum, NOT publication evidence.
    // Correctness does not assume collision resistance: both parts are scanned.
    for attempt in 0..16 {
        let boundary = format!("fg-prepare-{digest}-{attempt:x}");
        let marker = format!("--{boundary}");
        if !contains(metadata.as_bytes(), marker.as_bytes(), live)?
            && !contains(&bundle, marker.as_bytes(), live)?
        { selected = Some(boundary); break; }
    }
    let boundary = selected.ok_or_else(ApiError::too_large)?;
    let prefix = format!(concat!(
        "--{}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Disposition: inline; name=\"metadata\"\r\n\r\n{}",
        "\r\n--{}\r\nContent-Type: application/x-git-bundle\r\nContent-Disposition: attachment; name=\"bundle\"; filename=\"candidate.bundle\"\r\n\r\n"),
        boundary, metadata, boundary);
    let suffix = format!("\r\n--{boundary}--\r\n");
    let length = prefix.len().checked_add(bundle.len()).and_then(|n| n.checked_add(suffix.len()))
        .filter(|n| *n <= maximum).ok_or_else(ApiError::too_large)?;
    checkpoint(live)?;
    Ok(Reply::Bundle { content_type: format!("multipart/mixed; boundary={boundary}"), prefix, bundle, suffix, length })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binary_transport_is_exact_self_delimited_and_not_base64_or_utf8_converted() {
        let bundle = b"# v2 git bundle\n\nPACK\0\xff\r\n".to_vec();
        let digest = hex(&sha256_digest(&bundle));
        let reply = mixed("{\"read_only\":true}".into(), bundle.clone(), &digest, 4096, &mut || true).unwrap();
        let mut out = Vec::new(); reply.send(&mut out, HttpVersion::Http11).unwrap();
        let split = out.windows(4).position(|x| x == b"\r\n\r\n").unwrap() + 4;
        let header = std::str::from_utf8(&out[..split]).unwrap();
        assert!(header.contains(&format!("Content-Length: {}\r\n", out.len() - split)));
        assert!(out.windows(bundle.len()).any(|x| x == bundle));
        assert!(header.contains("Cache-Control: no-store"));
        assert!(mixed("{}".into(), bundle, &digest, 1, &mut || true).is_err());
    }
    #[test]
    fn boundary_collision_scanning_covers_chunk_edges_and_cancellation() {
        let pattern = b"--edge-marker";
        let mut bytes = vec![b'x'; 64 * 1024 - 3]; bytes.extend_from_slice(pattern);
        assert!(contains(&bytes, pattern, &mut || true).unwrap());
        assert!(contains(&bytes, pattern, &mut || false).is_err());
        let digest = "a".repeat(64);
        let bundle = format!("--fg-prepare-{digest}-0").into_bytes();
        let reply = mixed("{}".into(), bundle, &digest, 4096, &mut || true).unwrap();
        let Reply::Bundle { content_type, .. } = reply else { panic!("binary") };
        assert!(content_type.ends_with("-1"));
    }
}
