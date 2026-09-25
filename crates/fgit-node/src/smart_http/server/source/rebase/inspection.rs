//! Inspect the actual uploaded rebase series, not a preparation receipt.
//! Source read authorization and its quota precede this body-bearing read.

mod output;

use super::super::super::{
    Status,
    issues::{ApiError, Reply, parse_decimal, parse_form, parse_snapshot},
    pulls::{SourceUploadKind, read_source_upload, source_upload},
};
use super::request::{oid, unhex};
use crate::smart_http::drive_request_while;
use crate::treefs_workspace::candidate_inspection::BundleInspectionRefusal;
use crate::{
    GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession, OneNode,
};
use fgit_forge::review::{ReviewError, ReviewOptions};
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RepositoryAuthorityHeadId};
use fgit_wire::smart_http::{BodyFraming, HttpLimits};
use std::collections::BTreeMap;
use std::io::Read;

#[derive(Debug)]
struct Command {
    source: RefName,
    onto_ref: RefName,
    expected_source: GitOid,
    onto: GitOid,
    candidate: GitOid,
    expected_head: Option<RepositoryAuthorityHeadId>,
    options: ReviewOptions,
}
impl Command {
    fn parse(bytes: &[u8], format: GitHashAlgorithm) -> Result<Self, ApiError> {
        let mut fields = BTreeMap::new();
        for (name, value) in parse_form(bytes, 24)? {
            if !matches!(
                name.as_str(),
                "object_format"
                    | "profile"
                    | "source_ref"
                    | "source_ref_hex"
                    | "onto_ref"
                    | "onto_ref_hex"
                    | "expected_source"
                    | "expected_onto"
                    | "candidate_commit"
                    | "expected_head"
                    | "context_lines"
                    | "max_tree_entries"
                    | "max_changes"
                    | "max_text_files"
                    | "max_blob_bytes"
                    | "max_output_bytes"
                    | "max_hunks"
                    | "max_diff_work"
            ) {
                return Err(ApiError::bad("unknown_rebase_inspection_field"));
            }
            if fields.insert(name, value).is_some() {
                return Err(ApiError::bad("duplicate_field"));
            }
        }
        if take(&mut fields, "object_format")? != format.as_str() {
            return Err(ApiError::bad("object_format_mismatch"));
        }
        if take(&mut fields, "profile")? != "linear-v1" {
            return Err(ApiError::bad("unsupported_rebase_profile"));
        }
        let source = reference(&mut fields, "source_ref", "source_ref_hex")?;
        let onto_ref = reference(&mut fields, "onto_ref", "onto_ref_hex")?;
        if source == onto_ref {
            return Err(ApiError::bad("rebase_requires_distinct_branches"));
        }
        let expected_source = oid(&take(&mut fields, "expected_source")?, format)?;
        let onto = oid(&take(&mut fields, "expected_onto")?, format)?;
        let candidate = oid(&take(&mut fields, "candidate_commit")?, format)?;
        let expected_head = fields
            .remove("expected_head")
            .map(|text| parse_snapshot(&text))
            .transpose()?;
        let mut options = ReviewOptions::default();
        for (name, field) in [
            ("context_lines", &mut options.context_lines),
            ("max_tree_entries", &mut options.limits.max_tree_entries),
            ("max_changes", &mut options.limits.max_changes),
            ("max_text_files", &mut options.limits.max_text_files),
            ("max_blob_bytes", &mut options.limits.max_blob_bytes),
            ("max_output_bytes", &mut options.limits.max_output_bytes),
            ("max_hunks", &mut options.limits.max_hunks),
            ("max_diff_work", &mut options.limits.max_diff_work),
        ] {
            if let Some(text) = fields.remove(name) {
                *field = usize::try_from(parse_decimal(&text)?)
                    .map_err(|_| ApiError::bad("invalid_inspection_limit"))?;
            }
        }
        options
            .validate()
            .map_err(|_| ApiError::bad("invalid_inspection_options"))?;
        if !fields.is_empty() {
            return Err(ApiError::bad("unknown_rebase_inspection_field"));
        }
        Ok(Self {
            source,
            onto_ref,
            expected_source,
            onto,
            candidate,
            expected_head,
            options,
        })
    }
}
fn take(fields: &mut BTreeMap<String, String>, name: &str) -> Result<String, ApiError> {
    fields
        .remove(name)
        .ok_or_else(|| ApiError::bad("missing_rebase_inspection_field"))
}
fn reference(
    fields: &mut BTreeMap<String, String>,
    text: &str,
    hex: &str,
) -> Result<RefName, ApiError> {
    let bytes = match (fields.remove(text), fields.remove(hex)) {
        (Some(text), None) => text.into_bytes(),
        (None, Some(text)) => unhex(&text, 4096)?,
        _ => return Err(ApiError::bad("exactly_one_reference_encoding_required")),
    };
    if bytes.len() > 4096 || !bytes.starts_with(b"refs/heads/") {
        return Err(ApiError::bad("rebase_requires_branch"));
    }
    RefName::try_new(&bytes).map_err(|_| ApiError::bad("invalid_ref"))
}

pub(super) fn execute(
    node: &OneNode,
    boundary: &str,
    session: &LoopbackReceiveSession,
    framing: BodyFraming,
    reader: &mut impl Read,
    http: HttpLimits,
    maximum_response: u64,
) -> Result<Reply, ApiError> {
    if session.authenticated_session().is_none() {
        return Err(ApiError::new(Status::Unauthorized, "unauthorized"));
    }
    let bytes = read_source_upload(reader, framing, http, SourceUploadKind::Bundle)?;
    let deadline = GitDaemonSessionDeadline::new(
        node.git_daemon_session_timeout,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let context = node.session_request_context(&deadline);
    let mut live = || !deadline.expired();
    let (form, bundle) = source_upload(&bytes, boundary, SourceUploadKind::Bundle, &mut live)?;
    let command = Command::parse(form, node.object_format)?;
    let inspected = drive_request_while(
        node,
        &context,
        node.inspect_rebase_bundle_in(
            &context,
            &command.source,
            &command.onto_ref,
            command.expected_source,
            command.onto,
            command.candidate,
            bundle,
            &Default::default(),
            command.expected_head,
            &command.options,
        ),
        &mut live,
    )
    .map_err(failure)?;
    // No raw upload buffer is retained while expanding commit bodies and hunks.
    drop(bytes);
    let body = output::render(
        node,
        &command,
        inspected,
        usize::try_from(maximum_response).unwrap_or(usize::MAX),
        &mut live,
    )?;
    Ok(Reply {
        status: Status::Success,
        body,
        terminal: None,
    })
}
fn failure(error: BundleInspectionRefusal) -> ApiError {
    match error {
        BundleInspectionRefusal::RefUnavailable => ApiError::not_found(),
        BundleInspectionRefusal::SnapshotMoved => {
            ApiError::new(Status::Conflict, "source_snapshot_moved")
        }
        BundleInspectionRefusal::ParentMoved => ApiError::new(Status::Conflict, "rebase_tip_moved"),
        BundleInspectionRefusal::InvalidCandidate(_) | BundleInspectionRefusal::Envelope(_) => {
            ApiError::bad("invalid_rebase_candidate")
        }
        BundleInspectionRefusal::BudgetExceeded => ApiError::too_large(),
        BundleInspectionRefusal::Source(error) => super::source_error(&error),
        BundleInspectionRefusal::Review(error) => match *error {
            ReviewError::InvalidOptions => ApiError::bad("invalid_inspection_options"),
            ReviewError::Budget(_) => ApiError::too_large(),
            ReviewError::Source(error) => super::source_error(&error),
            _ => ApiError::unavailable(),
        },
        // Corrupt/unavailable bytes are never a successful empty comparison.
        // No read failure constitutes an ambiguous publication or a decision.
        _ => ApiError::unavailable(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn form(format: GitHashAlgorithm) -> String {
        format!(
            "object_format={}&profile=linear-v1&source_ref=refs/heads/topic&onto_ref=refs/heads/main&expected_source={}&expected_onto={}&candidate_commit={}",
            format.as_str(),
            "a".repeat(format.digest_len() * 2),
            "b".repeat(format.digest_len() * 2),
            "c".repeat(format.digest_len() * 2)
        )
    }
    #[test]
    fn exact_pins_byte_refs_and_zero_commit_candidates_are_supported() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let text = form(format).replace(
                "source_ref=refs/heads/topic",
                "source_ref_hex=726566732f68656164732fff",
            ) + "&context_lines=0&max_changes=1";
            let parsed = Command::parse(text.as_bytes(), format).unwrap();
            assert_eq!(parsed.source.as_bytes(), b"refs/heads/\xff");
            assert_eq!(parsed.options.context_lines, 0);
            assert_eq!(parsed.options.limits.max_changes, 1);
            assert!(parsed.options.paths.is_empty());
            assert!(
                Command::parse(
                    form(format)
                        .replace(
                            &"c".repeat(format.digest_len() * 2),
                            &"b".repeat(format.digest_len() * 2)
                        )
                        .as_bytes(),
                    format
                )
                .is_ok()
            );
        }
    }
    #[test]
    fn missing_pins_filters_replay_instructions_and_widened_limits_refuse() {
        let good = form(GitHashAlgorithm::Sha1);
        for extra in [
            "&path_prefix_hex=61",
            "&mode=merge-base",
            "&upstream=original",
            "&empty=drop",
            "&committer=admin",
            "&force=true",
            "&principal=admin",
            "&expected_source=other",
            "&source_ref_hex=61",
            "&max_changes=0",
            "&max_changes=513",
            "&context_lines=21",
        ] {
            assert!(
                Command::parse((good.clone() + extra).as_bytes(), GitHashAlgorithm::Sha1).is_err(),
                "{extra}"
            );
        }
        for bad in [
            good.replace("expected_onto=", "unrecognized="),
            good.replace("source_ref=refs/heads/topic", "source_ref=refs/heads/main"),
            good.replace(&"c".repeat(40), &"0".repeat(40)),
        ] {
            assert!(Command::parse(bad.as_bytes(), GitHashAlgorithm::Sha1).is_err());
        }
    }
    #[test]
    fn read_errors_never_claim_a_transaction_or_disclose_internal_details() {
        for error in [
            BundleInspectionRefusal::InvalidCandidate("private internals"),
            BundleInspectionRefusal::RefUnavailable,
            BundleInspectionRefusal::SnapshotMoved,
            BundleInspectionRefusal::BudgetExceeded,
            BundleInspectionRefusal::Source(fgit_forge::preparation::MergeSourceError::Cancelled),
        ] {
            let error = failure(error);
            assert!(!error.outcome_unknown);
            let mut wire = Vec::new();
            error
                .send_named(
                    &mut wire,
                    fgit_wire::smart_http::HttpVersion::Http11,
                    "source_error",
                )
                .unwrap();
            let wire = String::from_utf8(wire).unwrap();
            assert!(!wire.contains("private internals") && !wire.contains("\"complete\":true"));
        }
    }
}
