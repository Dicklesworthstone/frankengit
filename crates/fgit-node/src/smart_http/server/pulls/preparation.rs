//! Read-only automatic and resolved candidate construction. Fetch AND PR-read
//! grants are required on one credential. No candidate is staged or approved.

mod output;
mod request;

use super::super::issues::{ApiError, read_form};
use super::super::{Profile, Status, retry_key};
use super::collaboration::{read_upload_bounded, resolution_upload};
use crate::smart_http::drive_request_while;
use crate::{
    GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession,
    NodeWorkspaceRefusal, OneNode,
};
use fgit_admission::ProjectionFailure;
use fgit_authority::IdempotencyKey;
use fgit_forge::preparation::renames::RenameRefusal;
use fgit_forge::preparation::resolution::ResolutionError;
use fgit_forge::preparation::{MergeSourceError, PreparationError, PreparationLimits};
use fgit_types::RefusalCode;
use fgit_wire::smart_http::{BodyFraming, HttpLimits, Service, head::Envelope};
use fgit_wire::visibility::RefVisibility;
pub(super) use output::Reply;
pub(super) use request::Request;
use std::io::Read;

pub(super) fn authenticate(
    request: &Request<'_>,
    envelope: &Envelope<'_>,
    raw_head: &[u8],
    profile: &Profile,
) -> Result<LoopbackReceiveSession, ApiError> {
    let grant = profile
        .credentials
        .authenticate(envelope.authorization())
        .map_err(|error| ApiError::from_status(Status::from(error), false))?;
    if request.repository_route.as_bytes() != profile.route {
        return Err(ApiError::not_found());
    }
    if !profile.allow_pulls || !grant.permits(Service::UploadPack) || !grant.permits_pulls(false) {
        return Err(ApiError::new(Status::Forbidden, "forbidden"));
    }
    if retry_key(raw_head)
        .map_err(|_| ApiError::bad("invalid_idempotency_key"))?
        .is_some()
    {
        return Err(ApiError::bad("preparation_has_no_transaction_key"));
    }
    // This transport sentinel is never passed to admission or key binding.
    Ok(LoopbackReceiveSession::authenticated(
        grant.principal,
        IdempotencyKey::new(b"read-only-candidate-preparation".to_vec())
            .map_err(|_| ApiError::unavailable())?,
    ))
}

pub(super) fn execute(
    node: &OneNode,
    request: &Request<'_>,
    session: &LoopbackReceiveSession,
    framing: BodyFraming,
    reader: &mut impl Read,
    limits: HttpLimits,
    maximum_response: u64,
) -> Result<Reply, ApiError> {
    if session.authenticated_session().is_none() {
        return Err(ApiError::new(Status::Unauthorized, "unauthorized"));
    }
    let bytes = if request.boundary.is_some() {
        read_upload_bounded(reader, framing, limits, resolution_upload::MAX_UPLOAD_BYTES)?
    } else {
        read_form(reader, framing, limits)?
    };
    let deadline = GitDaemonSessionDeadline::new(
        node.git_daemon_session_timeout,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let context = node.session_request_context(&deadline);
    let mut live = || !deadline.expired();
    let maximum = usize::try_from(maximum_response)
        .unwrap_or(usize::MAX)
        .min(output::MAX_REPLY_BYTES);
    let visibility = RefVisibility::new();
    if request.resolution {
        let command = {
            let upload = if let Some(boundary) = request.boundary {
                resolution_upload::parse(&bytes, boundary, &mut live)?
            } else {
                resolution_upload::Upload {
                    command: &bytes,
                    files: Default::default(),
                }
            };
            request.resolved_command(upload.command, upload.files, node.object_format)?
        };
        // Native choices now own their exact bytes. Release the HTTP buffer
        // before graph walks, tree reconstruction and bundle generation.
        drop(bytes);
        let resolved = drive_request_while(
            node,
            &context,
            node.prepare_resolved_pull_request_bundle_in(
                &context,
                &command.subject,
                command.base,
                &visibility,
                &command.choices,
                &command.metadata,
                PreparationLimits::default(),
            ),
            &mut live,
        )
        .map_err(|error| {
            if error.is_snapshot_unavailable() {
                ApiError::new(Status::Conflict, "preparation_subject_moved")
            } else if let Some(error) = error.source_refusal() {
                preparation_error(error)
            } else if let Some(error) = error.resolution_refusal() {
                resolution_error(error)
            } else {
                ApiError::unavailable()
            }
        })?;
        return output::build_resolved(
            node,
            resolved.source_head,
            &command.subject,
            resolved.resolved,
            resolved.bundle,
            maximum,
            &mut live,
        );
    }
    let command = request.command(&bytes, node.object_format)?;
    drop(bytes);
    let prepared = drive_request_while(
        node,
        &context,
        node.prepare_pull_request_bundle_with_profile_in(
            &context,
            &command.subject,
            &visibility,
            &command.metadata,
            PreparationLimits::default(),
            command.profile,
        ),
        &mut live,
    )
    .map_err(|error| preparation_error(&error))?;
    output::build(
        node,
        prepared.source_head,
        &prepared.subject,
        &prepared.outcome,
        prepared.bundle,
        command.profile,
        maximum,
        &mut live,
    )
}

fn resolution_error(error: &ResolutionError) -> ApiError {
    match error {
        ResolutionError::InvalidInputs
        | ResolutionError::InvalidResolution { .. }
        | ResolutionError::DuplicatePath(_)
        | ResolutionError::OverlappingPaths => ApiError::bad("invalid_resolution_set"),
        ResolutionError::NonConflictPath(_) => {
            ApiError::new(Status::Conflict, "resolution_names_clean_path")
        }
        ResolutionError::MissingSide { .. } => {
            ApiError::new(Status::Conflict, "resolution_side_missing")
        }
        ResolutionError::Unresolved(_) => ApiError::new(Status::Conflict, "unresolved_conflicts"),
        ResolutionError::BaseMismatch { .. } => {
            ApiError::new(Status::Conflict, "resolution_base_mismatch")
        }
        ResolutionError::NoConflicts => ApiError::new(Status::Conflict, "no_conflicts_to_resolve"),
        ResolutionError::Budget => ApiError::too_large(),
        ResolutionError::Preparation(error) => native_preparation_error(error),
        ResolutionError::ReconstructionMismatch => ApiError::unavailable(),
    }
}
fn preparation_error(error: &NodeWorkspaceRefusal) -> ApiError {
    match error {
        NodeWorkspaceRefusal::RefUnavailable => ApiError::not_found(),
        NodeWorkspaceRefusal::StaleWorkspaceBase => {
            ApiError::new(Status::Conflict, "preparation_subject_moved")
        }
        NodeWorkspaceRefusal::ObjectFormatMismatch
        | NodeWorkspaceRefusal::InvalidWorkspaceCandidate(_) => {
            ApiError::bad("invalid_preparation_request")
        }
        NodeWorkspaceRefusal::Cancelled { .. } => ApiError::from_status(Status::Timeout, false),
        NodeWorkspaceRefusal::MergeValidation(ProjectionFailure::Unavailable(
            RefusalCode::ResourceBudgetExceeded,
        )) => ApiError::too_large(),
        NodeWorkspaceRefusal::MergeValidation(ProjectionFailure::Unavailable(
            RefusalCode::CancellationInProgress,
        )) => ApiError::from_status(Status::Timeout, false),
        NodeWorkspaceRefusal::MergePreparation(error) => native_preparation_error(error),
        _ => ApiError::unavailable(),
    }
}
fn native_preparation_error(error: &PreparationError) -> ApiError {
    match error {
        // Rename conflicts are inspectable construction refusals, not failed
        // servers or mutation outcomes. Never reflect raw source paths/IDs.
        PreparationError::Rename(error) => ApiError::new(
            Status::Conflict,
            match error {
                RenameRefusal::AmbiguousIdentity { .. } => "rename_identity_ambiguous",
                RenameRefusal::Divergent { .. } => "rename_destinations_diverge",
                RenameRefusal::RenameDelete { .. } => "rename_delete_conflict",
                RenameRefusal::DestinationOccupied { .. } => "rename_destination_occupied",
                RenameRefusal::UnsupportedEntry { .. } => "rename_entry_unsupported",
                RenameRefusal::AttributesRequireDriver { .. } => "rename_attributes_require_driver",
            },
        ),
        PreparationError::NoCommonAncestor => ApiError::new(Status::Conflict, "no_common_ancestor"),
        PreparationError::MultipleMergeBases(_) => {
            ApiError::new(Status::Conflict, "multiple_merge_bases")
        }
        PreparationError::InvalidLimits
        | PreparationError::InvalidMetadata
        | PreparationError::ObjectFormat => ApiError::bad("invalid_preparation_request"),
        PreparationError::Budget(_)
        | PreparationError::Source(MergeSourceError::BudgetExceeded) => ApiError::too_large(),
        PreparationError::Source(MergeSourceError::Cancelled) => {
            ApiError::from_status(Status::Timeout, false)
        }
        _ => ApiError::unavailable(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preparation_failures_never_manufacture_mutation_ambiguity_or_terminal_refusals() {
        for error in [
            NodeWorkspaceRefusal::StaleWorkspaceBase,
            NodeWorkspaceRefusal::RefUnavailable,
            NodeWorkspaceRefusal::Cancelled { exhaustion: None },
            NodeWorkspaceRefusal::MergePreparation(PreparationError::NoCommonAncestor),
            NodeWorkspaceRefusal::MergePreparation(PreparationError::Budget("test")),
        ] {
            let error = preparation_error(&error);
            assert!(!error.outcome_unknown);
            let mut bytes = Vec::new();
            error
                .send_named(
                    &mut bytes,
                    fgit_wire::smart_http::HttpVersion::Http11,
                    "pull_request_error",
                )
                .unwrap();
            assert!(
                !String::from_utf8(bytes)
                    .unwrap()
                    .contains("\"outcome\":\"refused\"")
            );
        }
    }
    #[test]
    fn resolution_errors_distinguish_bad_choices_from_unavailable_evidence() {
        assert_eq!(
            resolution_error(&ResolutionError::NoConflicts).status,
            Status::Conflict
        );
        assert_eq!(
            resolution_error(&ResolutionError::Unresolved(vec![])).code,
            "unresolved_conflicts"
        );
        assert_eq!(
            resolution_error(&ResolutionError::NonConflictPath(b"not disclosed".to_vec())).code,
            "resolution_names_clean_path"
        );
        assert_eq!(
            resolution_error(&ResolutionError::ReconstructionMismatch).status,
            Status::Unavailable
        );
        for error in [
            ResolutionError::Budget,
            ResolutionError::NoConflicts,
            ResolutionError::ReconstructionMismatch,
            ResolutionError::Preparation(PreparationError::Source(MergeSourceError::Cancelled)),
        ] {
            assert!(!resolution_error(&error).outcome_unknown);
        }
    }

    #[test]
    fn rename_refusals_are_distinct_safe_conflicts_not_mutation_or_server_failures() {
        use fgit_forge::preparation::renames::RenameSide;
        use fgit_types::{GitHashAlgorithm, GitOid};
        let oid = GitOid::from_hex(GitHashAlgorithm::Sha1, &"de".repeat(20)).unwrap();
        let private = b"private-path-do-not-reflect".to_vec();
        for (refusal, code) in [
            (
                RenameRefusal::AmbiguousIdentity {
                    side: RenameSide::Source,
                    oid,
                },
                "rename_identity_ambiguous",
            ),
            (
                RenameRefusal::Divergent {
                    from: private.clone(),
                    target: private.clone(),
                    source: private.clone(),
                },
                "rename_destinations_diverge",
            ),
            (
                RenameRefusal::RenameDelete {
                    from: private.clone(),
                    to: private.clone(),
                },
                "rename_delete_conflict",
            ),
            (
                RenameRefusal::DestinationOccupied {
                    path: private.clone(),
                },
                "rename_destination_occupied",
            ),
            (
                RenameRefusal::UnsupportedEntry {
                    path: private.clone(),
                },
                "rename_entry_unsupported",
            ),
            (
                RenameRefusal::AttributesRequireDriver { path: private },
                "rename_attributes_require_driver",
            ),
        ] {
            let error = preparation_error(&NodeWorkspaceRefusal::MergePreparation(
                PreparationError::Rename(refusal),
            ));
            assert_eq!(error.status, Status::Conflict);
            assert_eq!(error.code, code);
            assert!(!error.outcome_unknown);
            let mut bytes = Vec::new();
            error
                .send_named(
                    &mut bytes,
                    fgit_wire::smart_http::HttpVersion::Http11,
                    "pull_request_error",
                )
                .unwrap();
            let text = String::from_utf8(bytes).unwrap();
            assert!(!text.contains("private-path-do-not-reflect"));
            assert!(!text.contains(&oid.to_string()));
            assert!(!text.contains("\"outcome\":\"refused\""));
        }
    }
}
