//! Bounded read-only artifacts. Clean/resolved results carry JSON metadata and
//! a binary Git bundle without a second bundle-sized response copy. Conflict
//! and resolution paths are exact hex bytes, never lossy filesystem strings.

use super::super::super::{
    Status,
    issues::{ApiError, quote, ref_fields},
};
use crate::OneNode;
use fgit_crypto::sha256_digest;
use fgit_forge::event::review::ReviewSubject;
use fgit_forge::preparation::resolution::{ResolutionKind, ResolvedMerge, ResolvedPath};
use fgit_forge::preparation::{ConflictKind, MergeEntry, MergePreparation, MergeProfile};
use fgit_types::RepositoryAuthorityHeadId;
use fgit_wire::smart_http::HttpVersion;
use std::io::{self, Write};

const MAX_METADATA_BYTES: usize = 2 * 1024 * 1024;
const MAX_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
pub(super) const MAX_REPLY_BYTES: usize = MAX_METADATA_BYTES + MAX_BUNDLE_BYTES + 16 * 1024;

pub(crate) struct Reply(Body);
enum Body {
    Json {
        status: Status,
        body: String,
    },
    Bundle {
        content_type: String,
        prefix: String,
        bundle: Vec<u8>,
        suffix: String,
        length: usize,
    },
}
impl Reply {
    pub(crate) fn send(&self, writer: &mut impl Write, version: HttpVersion) -> io::Result<()> {
        let (status, content_type, length) = match &self.0 {
            Body::Json { status, body } => (*status, "application/json; charset=utf-8", body.len()),
            Body::Bundle {
                content_type,
                length,
                ..
            } => (Status::Success, content_type.as_str(), *length),
        };
        let version = match version {
            HttpVersion::Http10 => "HTTP/1.0",
            HttpVersion::Http11 => "HTTP/1.1",
        };
        write!(
            writer,
            "{version} {}\r\nContent-Type: {content_type}\r\nContent-Length: {length}\r\nCache-Control: no-store\r\nVary: Authorization\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
            status.line()
        )?;
        match &self.0 {
            Body::Json { body, .. } => writer.write_all(body.as_bytes())?,
            Body::Bundle {
                prefix,
                bundle,
                suffix,
                ..
            } => {
                writer.write_all(prefix.as_bytes())?;
                writer.write_all(bundle)?;
                writer.write_all(suffix.as_bytes())?;
            }
        }
        writer.flush()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), ApiError> {
    if live() {
        Ok(())
    } else {
        Err(ApiError::from_status(Status::Timeout, false))
    }
}
fn append(out: &mut String, part: &str) -> Result<(), ApiError> {
    if out
        .len()
        .checked_add(part.len())
        .is_none_or(|n| n > MAX_METADATA_BYTES)
    {
        return Err(ApiError::too_large());
    }
    out.try_reserve(part.len())
        .map_err(|_| ApiError::unavailable())?;
    out.push_str(part);
    Ok(())
}
fn entry(value: Option<&MergeEntry>) -> String {
    value.map_or_else(
        || "null".to_owned(),
        |value| {
            format!(
                "{{\"mode\":{},\"oid\":{}}}",
                value.mode,
                quote(&value.oid.to_string())
            )
        },
    )
}
fn kind(value: ConflictKind) -> &'static str {
    match value {
        ConflictKind::Content => "content",
        ConflictKind::Binary => "binary",
        ConflictKind::ModifyDelete => "modify_delete",
        ConflictKind::TypeChange => "type_change",
        ConflictKind::Mode => "mode",
        ConflictKind::Opaque => "opaque",
        ConflictKind::AttributesRequireDriver => "attributes_require_driver",
    }
}
fn resolution_metadata(
    out: &mut String,
    paths: &[ResolvedPath],
    live: &mut impl FnMut() -> bool,
) -> Result<(), ApiError> {
    if paths.is_empty()
        || paths.len() > 128
        || paths
            .windows(2)
            .any(|pair| pair[0].conflict.path >= pair[1].conflict.path)
    {
        return Err(ApiError::unavailable());
    }
    append(
        out,
        "\"resolution_profile\":\"exact-path-resolutions-v1\",\"resolutions\":[",
    )?;
    for (index, path) in paths.iter().enumerate() {
        checkpoint(live)?;
        let conflict = &path.conflict;
        if conflict.path.is_empty() || conflict.path.len() > 4096 {
            return Err(ApiError::too_large());
        }
        let choice = match path.choice {
            ResolutionKind::Base => "base",
            ResolutionKind::Ours => "ours",
            ResolutionKind::Theirs => "theirs",
            ResolutionKind::Delete => "delete",
            ResolutionKind::File => "file",
        };
        if (path.choice == ResolutionKind::Delete) != path.result.is_none() {
            return Err(ApiError::unavailable());
        }
        append(
            out,
            &format!(
                concat!(
                    "{}{{\"path_hex\":{},\"kind\":{},\"base\":{},\"ours\":{},",
                    "\"theirs\":{},\"choice\":{},\"result\":{}}}"
                ),
                if index == 0 { "" } else { "," },
                quote(&hex(&conflict.path)),
                quote(kind(conflict.kind)),
                entry(conflict.base.as_ref()),
                entry(conflict.ours.as_ref()),
                entry(conflict.theirs.as_ref()),
                quote(choice),
                entry(path.result.as_ref())
            ),
        )?;
    }
    append(out, "],")
}

pub(super) fn build(
    node: &OneNode,
    head: RepositoryAuthorityHeadId,
    subject: &ReviewSubject,
    outcome: &MergePreparation,
    bundle: Option<Vec<u8>>,
    profile: MergeProfile,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<Reply, ApiError> {
    build_inner(
        node, head, subject, outcome, bundle, None, profile, maximum, live,
    )
}

pub(super) fn build_resolved(
    node: &OneNode,
    head: RepositoryAuthorityHeadId,
    subject: &ReviewSubject,
    resolved: ResolvedMerge,
    bundle: Vec<u8>,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<Reply, ApiError> {
    let ResolvedMerge { plan, resolutions } = resolved;
    build_inner(
        node,
        head,
        subject,
        &MergePreparation::Clean(plan),
        Some(bundle),
        Some(&resolutions),
        MergeProfile::PathMergeV1,
        maximum,
        live,
    )
}

fn build_inner(
    node: &OneNode,
    head: RepositoryAuthorityHeadId,
    subject: &ReviewSubject,
    outcome: &MergePreparation,
    bundle: Option<Vec<u8>>,
    resolutions: Option<&[ResolvedPath]>,
    profile: MergeProfile,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<Reply, ApiError> {
    checkpoint(live)?;
    if bundle
        .as_ref()
        .is_some_and(|bytes| bytes.len() > MAX_BUNDLE_BYTES)
    {
        return Err(ApiError::too_large());
    }
    if resolutions.is_some()
        && (profile != MergeProfile::PathMergeV1 || !matches!(outcome, MergePreparation::Clean(_)))
    {
        return Err(ApiError::unavailable());
    }
    let bundle_digest = bundle.as_ref().map(|bytes| hex(&sha256_digest(bytes)));
    checkpoint(live)?;
    let id = head.as_internal_object_id();
    let token = format!(
        "alg:{}:{}",
        id.algorithm().code_point(),
        hex(id.digest().as_bytes())
    );
    let mut metadata = format!(
        concat!(
            "{{\"type\":\"merge_preparation\",\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},",
            "\"repository_incarnation\":{},\"object_format\":{},\"source_head\":{},\"snapshot_token\":{},",
            "\"profile\":{},\"read_only\":true,\"objects_staged\":false,",
            "\"transaction_created\":false,\"published\":false,\"merge_authorized\":false,",
            "\"subject\":{{\"pull_request\":{},\"pull_request_version\":{},\"policy_epoch\":{},",
            "{},{},\"source_tip\":{},\"target_tip\":{}}},"
        ),
        quote(&node.tenant_id.to_string()),
        quote(&node.repository_id.to_string()),
        quote(&node.repository_incarnation_id().to_string()),
        quote(node.object_format.as_str()),
        quote(&head.to_string()),
        quote(&token),
        quote(match profile {
            MergeProfile::PathMergeV1 => "path-merge-v1",
            MergeProfile::ExactRenamesV1 => "exact-renames-v1",
        }),
        subject.pull_request.get(),
        subject.pull_request_version.get(),
        subject.policy_epoch.get(),
        ref_fields("source_ref", &subject.source_ref),
        ref_fields("target_ref", &subject.target_ref),
        quote(&subject.source_tip.to_string()),
        quote(&subject.target_tip.to_string())
    );
    if let Some(paths) = resolutions {
        resolution_metadata(&mut metadata, paths, live)?;
    }
    let status = match outcome {
        MergePreparation::Clean(plan) => {
            let bytes = bundle
                .as_ref()
                .filter(|bytes| !bytes.is_empty())
                .ok_or_else(ApiError::unavailable)?;
            if plan.source != subject.source_tip || plan.target != subject.target_tip {
                return Err(ApiError::unavailable());
            }
            append(
                &mut metadata,
                &format!(
                    concat!(
                        "\"state\":{},\"candidate\":{{\"merge_base\":{},\"commit\":{},\"tree\":{},\"new_object_count\":{}}},",
                        "\"bundle\":{{\"bytes\":{},\"sha256\":{}}},\"conflicts\":[]}}"
                    ),
                    quote(if resolutions.is_some() {
                        "resolved"
                    } else {
                        "clean"
                    }),
                    quote(&plan.base.to_string()),
                    quote(&plan.commit.to_string()),
                    quote(&plan.tree.to_string()),
                    plan.objects.len(),
                    bytes.len(),
                    quote(bundle_digest.as_deref().ok_or_else(ApiError::unavailable)?)
                ),
            )?;
            Status::Success
        }
        MergePreparation::Conflicted { base, conflicts } => {
            if bundle.is_some() || conflicts.is_empty() || conflicts.len() > 128 {
                return Err(ApiError::unavailable());
            }
            append(
                &mut metadata,
                &format!(
                    "\"state\":\"conflicted\",\"merge_base\":{},\"candidate\":null,\"bundle\":null,\"conflicts\":[",
                    quote(&base.to_string())
                ),
            )?;
            for (index, conflict) in conflicts.iter().enumerate() {
                checkpoint(live)?;
                if conflict.path.len() > 4096 {
                    return Err(ApiError::too_large());
                }
                append(
                    &mut metadata,
                    &format!(
                        "{}{{\"path_hex\":{},\"kind\":{},\"base\":{},\"ours\":{},\"theirs\":{}}}",
                        if index == 0 { "" } else { "," },
                        quote(&hex(&conflict.path)),
                        quote(kind(conflict.kind)),
                        entry(conflict.base.as_ref()),
                        entry(conflict.ours.as_ref()),
                        entry(conflict.theirs.as_ref())
                    ),
                )?;
            }
            append(&mut metadata, "]}")?;
            Status::Conflict
        }
        MergePreparation::AlreadyUpToDate { target } => {
            if bundle.is_some() || *target != subject.target_tip {
                return Err(ApiError::unavailable());
            }
            append(
                &mut metadata,
                "\"state\":\"already_up_to_date\",\"candidate\":null,\"bundle\":null,\"conflicts\":[]}",
            )?;
            Status::Success
        }
    };
    checkpoint(live)?;
    let maximum = maximum.min(MAX_REPLY_BYTES);
    match bundle {
        None => {
            if metadata.len() > maximum {
                return Err(ApiError::too_large());
            }
            Ok(Reply(Body::Json {
                status,
                body: metadata,
            }))
        }
        Some(bundle) => mixed(
            metadata,
            bundle,
            bundle_digest.as_deref().ok_or_else(ApiError::unavailable)?,
            maximum,
            live,
        ),
    }
}

fn contains(
    bytes: &[u8],
    pattern: &[u8],
    live: &mut impl FnMut() -> bool,
) -> Result<bool, ApiError> {
    let mut offset = 0;
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
        offset = offset.saturating_add(64 * 1024);
    }
    Ok(false)
}
fn mixed(
    metadata: String,
    bundle: Vec<u8>,
    digest: &str,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<Reply, ApiError> {
    let digest = digest.get(..48).ok_or_else(ApiError::unavailable)?;
    let mut selected = None;
    for attempt in 0..16 {
        let boundary = format!("fg-prepare-{digest}-{attempt:x}");
        let marker = format!("--{boundary}");
        if !contains(metadata.as_bytes(), marker.as_bytes(), live)?
            && !contains(&bundle, marker.as_bytes(), live)?
        {
            selected = Some(boundary);
            break;
        }
    }
    let boundary = selected.ok_or_else(ApiError::too_large)?;
    let prefix = format!(
        concat!(
            "--{}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Disposition: inline; name=\"metadata\"\r\n\r\n{}",
            "\r\n--{}\r\nContent-Type: application/x-git-bundle\r\nContent-Disposition: attachment; name=\"bundle\"; filename=\"candidate.bundle\"\r\n\r\n"
        ),
        boundary, metadata, boundary
    );
    let suffix = format!("\r\n--{boundary}--\r\n");
    let length = prefix
        .len()
        .checked_add(bundle.len())
        .and_then(|n| n.checked_add(suffix.len()))
        .filter(|n| *n <= maximum)
        .ok_or_else(ApiError::too_large)?;
    checkpoint(live)?;
    Ok(Reply(Body::Bundle {
        content_type: format!("multipart/mixed; boundary={boundary}"),
        prefix,
        bundle,
        suffix,
        length,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binary_transport_is_exact_self_delimited_and_not_base64_or_utf8_converted() {
        let bundle = b"# v2 git bundle\n\nPACK\0\xff\r\n".to_vec();
        let digest = hex(&sha256_digest(&bundle));
        let reply = mixed(
            "{\"read_only\":true}".into(),
            bundle.clone(),
            &digest,
            4096,
            &mut || true,
        )
        .unwrap();
        let mut out = Vec::new();
        reply.send(&mut out, HttpVersion::Http11).unwrap();
        let split = out.windows(4).position(|x| x == b"\r\n\r\n").unwrap() + 4;
        let header = std::str::from_utf8(&out[..split]).unwrap();
        assert!(header.contains(&format!("Content-Length: {}\r\n", out.len() - split)));
        let boundary = header
            .split_once("boundary=")
            .unwrap()
            .1
            .split("\r\n")
            .next()
            .unwrap();
        assert!(boundary.len() <= 70);
        assert!(out.windows(bundle.len()).any(|x| x == bundle.as_slice()));
        assert!(header.contains("Cache-Control: no-store"));
        assert!(mixed("{}".into(), bundle, &digest, 1, &mut || true).is_err());
    }
    #[test]
    fn boundary_collision_scanning_covers_chunk_edges_and_cancellation() {
        let pattern = b"--edge-marker";
        let mut bytes = vec![b'x'; 64 * 1024 - 3];
        bytes.extend_from_slice(pattern);
        assert!(contains(&bytes, pattern, &mut || true).unwrap());
        assert!(contains(&bytes, pattern, &mut || false).is_err());
        let digest = "a".repeat(48);
        let bundle = format!("--fg-prepare-{digest}-0").into_bytes();
        let reply = mixed("{}".into(), bundle, &digest, 4096, &mut || true).unwrap();
        let Body::Bundle { content_type, .. } = reply.0 else {
            panic!("binary")
        };
        assert!(content_type.ends_with("-1"));
    }
    #[test]
    fn resolution_receipts_are_byte_exact_non_authorizing_and_complete() {
        let path = ResolvedPath {
            conflict: fgit_forge::preparation::MergeConflict {
                path: vec![255],
                kind: ConflictKind::Binary,
                base: None,
                ours: None,
                theirs: None,
            },
            choice: ResolutionKind::Delete,
            result: None,
        };
        let mut json = String::new();
        resolution_metadata(&mut json, std::slice::from_ref(&path), &mut || true).unwrap();
        assert!(json.contains("\"path_hex\":\"ff\""));
        assert!(json.contains("\"choice\":\"delete\",\"result\":null"));
        assert!(!json.contains("approved"));
        assert!(
            resolution_metadata(&mut String::new(), &[path.clone(), path], &mut || true).is_err()
        );
        assert!(resolution_metadata(&mut String::new(), &[], &mut || true).is_err());
    }
}
