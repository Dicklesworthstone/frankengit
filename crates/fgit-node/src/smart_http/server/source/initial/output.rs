//! A prepared root commit is an artifact, never a publication receipt. Build
//! all bounded metadata and framing before success; borrow the owned bundle
//! during writes rather than allocating another bundle-sized response.

use std::io::{self, Write};
use fgit_admission::AdmissionResult;
use fgit_crypto::{GitObjectKind, sha256_digest};
use fgit_forge::initial_commit::InitialCommitPlan;
use fgit_pack::full_bundle::FullBundle;
use fgit_types::{DecisionOutcome, GitOid, PrincipalId, RefName, RepositoryAuthorityHeadId};
use fgit_wire::smart_http::HttpVersion;
use crate::OneNode;
use super::super::super::{Status, issues::{ApiError, Reply, quote, ref_fields}};

const MAX_METADATA: usize = 1024 * 1024;
const MAX_BUNDLE: usize = 64 * 1024 * 1024;

fn check(live: &mut impl FnMut() -> bool) -> Result<(), ApiError> {
    if live() { Ok(()) } else { Err(ApiError::from_status(Status::Timeout, false)) }
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }
fn append(out: &mut String, value: &str, maximum: usize) -> Result<(), ApiError> {
    if out.len().checked_add(value.len()).is_none_or(|n| n > maximum) { return Err(ApiError::too_large()); }
    out.try_reserve(value.len()).map_err(|_| ApiError::unavailable())?;
    out.push_str(value);
    Ok(())
}
fn hex_field(out: &mut String, bytes: &[u8], live: &mut impl FnMut() -> bool) -> Result<(), ApiError> {
    let count = bytes.len().checked_mul(2).and_then(|n| n.checked_add(2)).ok_or_else(ApiError::too_large)?;
    if out.len().checked_add(count).is_none_or(|n| n > MAX_METADATA) { return Err(ApiError::too_large()); }
    out.try_reserve(count).map_err(|_| ApiError::unavailable())?;
    out.push('"');
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for chunk in bytes.chunks(16 * 1024) {
        check(live)?;
        for byte in chunk {
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    out.push('"');
    Ok(())
}
fn scope(node: &OneNode) -> String {
    format!("\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},\"object_format\":{}",
        quote(&node.tenant_id.to_string()), quote(&node.repository_id.to_string()),
        quote(&node.repository_incarnation_id().to_string()), quote(node.object_format.as_str()))
}
fn contains(bytes: &[u8], marker: &[u8], live: &mut impl FnMut() -> bool) -> Result<bool, ApiError> {
    for start in (0..bytes.len()).step_by(64 * 1024) {
        check(live)?;
        let end = start.saturating_add(64 * 1024 + marker.len() - 1).min(bytes.len());
        if bytes[start..end].windows(marker.len()).any(|part| part == marker) { return Ok(true); }
    }
    Ok(false)
}

pub(in crate::smart_http::server::source) struct Prepared {
    bundle: FullBundle,
    boundary: String,
    prefix: String,
    suffix: String,
    length: usize,
}
impl Prepared {
    pub(in crate::smart_http::server::source) fn send(&self, writer: &mut impl Write, version: HttpVersion) -> io::Result<()> {
        let version = match version { HttpVersion::Http10 => "HTTP/1.0", HttpVersion::Http11 => "HTTP/1.1" };
        write!(writer, "{version} 200 OK\r\nContent-Type: multipart/mixed; boundary={}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nVary: Authorization\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n", self.boundary, self.length)?;
        writer.write_all(self.prefix.as_bytes())?;
        writer.write_all(self.bundle.bytes())?;
        writer.write_all(self.suffix.as_bytes())?;
        writer.flush()
    }
}

pub(super) fn prepared(node: &OneNode, reference: &RefName, head: RepositoryAuthorityHeadId,
    plan: InitialCommitPlan, bundle: FullBundle, maximum: usize, live: &mut impl FnMut() -> bool,
) -> Result<Prepared, ApiError> {
    check(live)?;
    if plan.object_format != node.object_format || plan.commit.is_zero() || plan.tree.is_zero()
        || [plan.commit, plan.tree].iter().any(|id| id.algorithm() != node.object_format)
        || plan.files.is_empty() || plan.files.len() > 1024
        || plan.files.windows(2).any(|pair| pair[0].path >= pair[1].path)
    { return Err(ApiError::unavailable()); }
    if bundle.bytes().is_empty() || bundle.bytes().len() > MAX_BUNDLE { return Err(ApiError::too_large()); }
    let commit = plan.objects.iter().find(|object| object.id == plan.commit && object.kind == GitObjectKind::Commit)
        .ok_or_else(ApiError::unavailable)?;
    let digest = hex(&sha256_digest(bundle.bytes()));
    check(live)?;
    let id = head.as_internal_object_id();
    let token = format!("alg:{}:{}", id.algorithm().code_point(), hex(id.digest().as_bytes()));
    let mut metadata = String::new();
    append(&mut metadata, &format!(concat!("{{\"type\":\"initial_source_preparation\",{},{},",
        "\"source_head\":{},\"snapshot_token\":{},\"expected_absent\":true,\"parents\":[],\"prerequisites\":[],",
        "\"candidate_commit\":{},\"root_tree\":{},\"patch_sha256\":{},\"object_count\":{},",
        "\"read_only\":true,\"objects_staged\":false,\"transaction_created\":false,\"published\":false,",
        "\"publication_authorized\":false,\"default_branch_changed\":false,",
        "\"bundle\":{{\"bytes\":{},\"sha256\":{}}},\"candidate_commit_body_hex\":"),
        scope(node), ref_fields("ref", reference), quote(&head.to_string()), quote(&token),
        quote(&plan.commit.to_string()), quote(&plan.tree.to_string()), quote(&hex(&plan.patch_sha256)),
        plan.objects.len(), bundle.bytes().len(), quote(&digest)), MAX_METADATA)?;
    hex_field(&mut metadata, &commit.body, live)?;
    append(&mut metadata, ",\"files\":[", MAX_METADATA)?;
    for (index, file) in plan.files.iter().enumerate() {
        check(live)?;
        if file.path.is_empty() || file.path.len() > 4096 || !matches!(file.mode, 0o100644 | 0o100755)
            || file.blob.is_zero() || file.blob.algorithm() != node.object_format
        { return Err(ApiError::unavailable()); }
        append(&mut metadata, if index == 0 { "{\"path_hex\":" } else { ",{\"path_hex\":" }, MAX_METADATA)?;
        hex_field(&mut metadata, &file.path, live)?;
        append(&mut metadata, &format!(",\"blob\":{},\"mode\":{},\"bytes\":{}}}",
            quote(&file.blob.to_string()), file.mode, file.bytes), MAX_METADATA)?;
    }
    append(&mut metadata, "]}", MAX_METADATA)?;
    // Candidate objects are construction scratch, not retained staging.
    drop(plan);
    let mut boundary = None;
    for attempt in 0..16 {
        let value = format!("fg-initial-{}-{attempt:x}", &digest[..48]);
        let marker = format!("--{value}");
        if !contains(metadata.as_bytes(), marker.as_bytes(), live)?
            && !contains(bundle.bytes(), marker.as_bytes(), live)?
        { boundary = Some(value); break; }
    }
    let boundary = boundary.ok_or_else(ApiError::too_large)?;
    let prefix = format!("--{boundary}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Disposition: inline; name=\"metadata\"\r\n\r\n{metadata}\r\n--{boundary}\r\nContent-Type: application/x-git-bundle\r\nContent-Disposition: attachment; name=\"bundle\"; filename=\"initial.bundle\"\r\n\r\n");
    let suffix = format!("\r\n--{boundary}--\r\n");
    let length = prefix.len().checked_add(bundle.bytes().len()).and_then(|n| n.checked_add(suffix.len()))
        .filter(|n| *n <= maximum).ok_or_else(ApiError::too_large)?;
    check(live)?;
    Ok(Prepared { bundle, boundary, prefix, suffix, length })
}

pub(super) fn publication(node: &OneNode, principal: PrincipalId, reference: &RefName,
    candidate: GitOid, result: AdmissionResult, maximum: usize,
) -> Result<Reply, ApiError> {
    // Admission already returned: an encoding/limit failure cannot imply rollback.
    let [command] = result.commands.as_slice() else { return Err(ApiError::unknown()); };
    if !result.session.atomic || result.session.tx_ids.as_slice() != [command.tx_id] {
        return Err(ApiError::unknown());
    }
    let terminal = command.terminal;
    let (status, outcome, decision) = match terminal.outcome {
        DecisionOutcome::Committed { repository_commit_id } => (Status::Success, "committed",
            format!("{{\"repository_commit_id\":{}}}", quote(&repository_commit_id.to_string()))),
        DecisionOutcome::Refused { code, refusal_record_id } => (Status::Conflict, "refused",
            format!("{{\"code\":{},\"code_point\":{},\"refusal_record_id\":{}}}",
                quote(&format!("{code:?}")), code.code_point(), quote(&refusal_record_id.to_string()))),
    };
    let body = format!(concat!("{{\"type\":\"initial_source_publication\",{},\"principal_id\":{},{},",
        "\"expected_absent\":true,\"candidate_commit\":{},\"tx_id\":{},\"decision_sequence\":{},",
        "\"outcome\":{},\"decision\":{},\"atomic\":true,\"terminal\":true,",
        "\"receipt_confirms_transport_revalidation\":false,\"default_branch_changed\":false}}"),
        scope(node), quote(&principal.to_string()), ref_fields("ref", reference), quote(&candidate.to_string()),
        quote(&command.tx_id.to_string()), terminal.decision_sequence.get(), quote(outcome), decision);
    if body.len() > maximum {
        eprintln!("Initial source receipt exceeded response limit after canonical transaction {}; recover the original key", command.tx_id);
        return Err(ApiError::unknown());
    }
    Ok(Reply { status, body, terminal: Some((command.tx_id, terminal)) })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metadata_limits_refuse_before_hex_allocation() {
        let mut out = String::from("abc");
        assert!(append(&mut out, "de", 4).is_err());
        assert_eq!(out, "abc");
        let mut out = "a".repeat(MAX_METADATA - 3);
        assert!(hex_field(&mut out, b"xx", &mut || true).is_err());
        assert_eq!(out.len(), MAX_METADATA - 3);
    }
    #[test]
    fn exact_bytes_and_split_delimiters_are_not_lost() {
        let mut out = String::new();
        hex_field(&mut out, b"\0\xff\r\n", &mut || true).unwrap();
        assert_eq!(out, "\"00ff0d0a\"");
        let mut bytes = vec![b'x'; 64 * 1024 - 3];
        bytes.extend_from_slice(b"--boundary");
        assert!(contains(&bytes, b"--boundary", &mut || true).unwrap());
        assert!(!contains(&bytes, b"--another", &mut || true).unwrap());
        assert!(contains(&bytes, b"--boundary", &mut || false).is_err());
    }
}
