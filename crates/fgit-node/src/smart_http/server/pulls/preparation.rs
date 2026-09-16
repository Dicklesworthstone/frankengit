//! Read-only candidate construction. Fetch AND PR-read credentials are needed
//! because the result discloses both source code and PR coordinates. Neither
//! voting nor merge capability implies those reads. No attempt is sealed.

mod request;
mod output;

use std::io::Read;
use fgit_authority::IdempotencyKey;
use fgit_admission::ProjectionFailure;
use fgit_forge::preparation::{MergeSourceError, PreparationError, PreparationLimits};
use fgit_types::RefusalCode;
use fgit_wire::smart_http::{BodyFraming, HttpLimits, Service, head::Envelope};
use fgit_wire::visibility::RefVisibility;
use crate::{GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession, NodeWorkspaceRefusal, OneNode};
use crate::smart_http::drive_request_while;
use super::super::{Profile, Status, retry_key};
use super::super::issues::{ApiError, read_form};
pub(super) use request::Request;
pub(super) use output::Reply;

pub(super) fn authenticate(request: &Request<'_>, envelope: &Envelope<'_>,
    raw_head: &[u8], profile: &Profile,
) -> Result<LoopbackReceiveSession, ApiError> {
    let grant = profile.credentials.authenticate(envelope.authorization())
        .map_err(|error| ApiError::from_status(Status::from(error), false))?;
    if request.repository_route.as_bytes() != profile.route { return Err(ApiError::not_found()); }
    if !profile.allow_pulls || !grant.permits(Service::UploadPack) || !grant.permits_pulls(false) {
        return Err(ApiError::new(Status::Forbidden, "forbidden"));
    }
    if retry_key(raw_head).map_err(|_| ApiError::bad("invalid_idempotency_key"))?.is_some() {
        return Err(ApiError::bad("preparation_has_no_transaction_key"));
    }
    // Transport identity only. This sentinel is never passed to admission,
    // binding, staging, or outcome-recovery APIs.
    Ok(LoopbackReceiveSession::authenticated(grant.principal,
        IdempotencyKey::new(b"read-only-candidate-preparation".to_vec()).map_err(|_| ApiError::unavailable())?))
}

pub(super) fn execute(node: &OneNode, request: &Request<'_>, session: &LoopbackReceiveSession,
    framing: BodyFraming, reader: &mut impl Read, limits: HttpLimits, maximum_response: u64,
) -> Result<Reply, ApiError> {
    if session.authenticated_session().is_none() { return Err(ApiError::new(Status::Unauthorized, "unauthorized")); }
    let form = read_form(reader, framing, limits)?;
    let (subject, metadata) = request.command(&form, node.object_format)?;
    let context = node.request_context();
    let deadline = GitDaemonSessionDeadline::new(node.git_daemon_session_timeout, GitDaemonSessionWorkScaling::FLAT);
    let mut live = || !deadline.expired();
    let maximum = usize::try_from(maximum_response).unwrap_or(usize::MAX).min(output::MAX_REPLY_BYTES);
    let visibility = RefVisibility::new();
    let prepared = drive_request_while(node, &context,
        node.prepare_pull_request_bundle_in(&context, &subject, &visibility, &metadata, PreparationLimits::default()),
        &mut live).map_err(preparation_error)?;
    // Cancellation before delivery discards only an un-staged read artifact.
    output::build(node, prepared.source_head, &prepared.subject, &prepared.outcome,
        prepared.bundle, maximum, &mut live)
}

fn preparation_error(error: NodeWorkspaceRefusal) -> ApiError {
    match error {
        NodeWorkspaceRefusal::RefUnavailable => ApiError::not_found(),
        NodeWorkspaceRefusal::StaleWorkspaceBase => ApiError::new(Status::Conflict, "preparation_subject_moved"),
        NodeWorkspaceRefusal::ObjectFormatMismatch | NodeWorkspaceRefusal::InvalidWorkspaceCandidate(_) =>
            ApiError::bad("invalid_preparation_request"),
        NodeWorkspaceRefusal::Cancelled { .. } => ApiError::from_status(Status::Timeout, false),
        NodeWorkspaceRefusal::MergeValidation(ProjectionFailure::Unavailable(RefusalCode::ResourceBudgetExceeded)) => ApiError::too_large(),
        NodeWorkspaceRefusal::MergeValidation(ProjectionFailure::Unavailable(RefusalCode::CancellationInProgress)) => ApiError::from_status(Status::Timeout, false),
        NodeWorkspaceRefusal::MergePreparation(error) => match error {
            PreparationError::NoCommonAncestor => ApiError::new(Status::Conflict, "no_common_ancestor"),
            PreparationError::MultipleMergeBases(_) => ApiError::new(Status::Conflict, "multiple_merge_bases"),
            PreparationError::InvalidLimits | PreparationError::InvalidMetadata | PreparationError::ObjectFormat => ApiError::bad("invalid_preparation_request"),
            PreparationError::Budget(_) | PreparationError::Source(MergeSourceError::BudgetExceeded) => ApiError::too_large(),
            PreparationError::Source(MergeSourceError::Cancelled) => ApiError::from_status(Status::Timeout, false),
            _ => ApiError::unavailable(),
        },
        _ => ApiError::unavailable(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preparation_failures_never_manufacture_mutation_ambiguity_or_terminal_refusals() {
        for error in [NodeWorkspaceRefusal::StaleWorkspaceBase, NodeWorkspaceRefusal::RefUnavailable,
            NodeWorkspaceRefusal::Cancelled { exhaustion: None },
            NodeWorkspaceRefusal::MergePreparation(PreparationError::NoCommonAncestor),
            NodeWorkspaceRefusal::MergePreparation(PreparationError::Budget("test"))]
        {
            let error = preparation_error(error);
            assert!(!error.outcome_unknown);
            let mut bytes = Vec::new();
            error.send_named(&mut bytes, fgit_wire::smart_http::HttpVersion::Http11, "pull_request_error").unwrap();
            assert!(!String::from_utf8(bytes).unwrap().contains("\"outcome\":\"refused\""));
        }
    }
}
