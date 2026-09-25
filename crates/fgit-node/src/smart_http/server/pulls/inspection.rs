//! Authenticated, body-bearing candidate inspection. The same token needs
//! Git-read and PR-read permission; voting/merge grants confer neither. No
//! transaction key, native-object staging, review event or publication occurs.

mod output;
mod request;
pub(super) use request::Request;

use super::super::issues::{ApiError, Reply};
use super::super::{Profile, Status, retry_key};
use super::collaboration::{CANDIDATE_UPLOAD_BYTES, inspection_upload, read_upload_bounded};
use crate::smart_http::drive_request_while;
use crate::treefs_workspace::candidate_inspection::{
    BundleInspectionRefusal, PullRequestInspectionRefusal,
};
use crate::{
    GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession,
    NodeWorkspaceRefusal, OneNode,
};
use fgit_admission::ProjectionFailure;
use fgit_authority::IdempotencyKey;
use fgit_forge::preparation::MergeSourceError;
use fgit_forge::review::{ReviewError, ReviewOptions};
use fgit_types::RefusalCode;
use fgit_wire::smart_http::{BodyFraming, HttpLimits, Service, head::Envelope};
use fgit_wire::visibility::RefVisibility;
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
        return Err(ApiError::bad("inspection_has_no_transaction_key"));
    }
    // Transport identity only; this key never reaches any authority binding.
    Ok(LoopbackReceiveSession::authenticated(
        grant.principal,
        IdempotencyKey::new(b"read-only-candidate-inspection".to_vec())
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
    let bytes = read_upload_bounded(reader, framing, limits, CANDIDATE_UPLOAD_BYTES)?;
    let deadline = GitDaemonSessionDeadline::new(
        node.git_daemon_session_timeout,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let context = node.session_request_context(&deadline);
    let mut live = || !deadline.expired();
    let (command, bundle) = inspection_upload(&bytes, request.boundary, &mut live)?;
    let (subject, candidate) = request.command(command, node.object_format)?;
    let options = ReviewOptions::default();
    let visibility = RefVisibility::new();
    let inspected = drive_request_while(
        node,
        &context,
        node.inspect_pull_request_bundle_in(
            &context,
            &subject,
            candidate,
            bundle,
            &visibility,
            &options,
        ),
        &mut live,
    )
    .map_err(inspection_error)?;
    // No report retains references into ingress. Release the complete buffered
    // upload before allocating the JSON report; native work staged no objects.
    drop(bytes);
    let maximum = usize::try_from(maximum_response)
        .unwrap_or(usize::MAX)
        .min(output::MAX_REPLY_BYTES);
    let body = output::build(node, &inspected, maximum, &mut live)?;
    Ok(Reply {
        status: Status::Success,
        body,
        terminal: None,
    })
}

fn source_error(error: NodeWorkspaceRefusal) -> ApiError {
    match error {
        NodeWorkspaceRefusal::RefUnavailable => ApiError::not_found(),
        NodeWorkspaceRefusal::StaleWorkspaceBase => {
            ApiError::new(Status::Conflict, "inspection_subject_moved")
        }
        NodeWorkspaceRefusal::ObjectFormatMismatch
        | NodeWorkspaceRefusal::InvalidWorkspaceCandidate(_) => {
            ApiError::bad("invalid_inspection_request")
        }
        NodeWorkspaceRefusal::Cancelled {
            exhaustion: Some(_),
        } => ApiError::too_large(),
        NodeWorkspaceRefusal::Cancelled { exhaustion: None } => {
            ApiError::from_status(Status::Timeout, false)
        }
        NodeWorkspaceRefusal::MergeValidation(ProjectionFailure::Unavailable(
            RefusalCode::ResourceBudgetExceeded,
        )) => ApiError::too_large(),
        NodeWorkspaceRefusal::MergeValidation(ProjectionFailure::Unavailable(
            RefusalCode::CancellationInProgress,
        )) => ApiError::from_status(Status::Timeout, false),
        _ => ApiError::unavailable(),
    }
}
fn inspection_error(error: PullRequestInspectionRefusal) -> ApiError {
    let error = match error {
        PullRequestInspectionRefusal::Selection(error) => return source_error(*error),
        PullRequestInspectionRefusal::Candidate(error) => *error,
    };
    match error {
        BundleInspectionRefusal::SnapshotMoved | BundleInspectionRefusal::ParentMoved => {
            ApiError::new(Status::Conflict, "inspection_subject_moved")
        }
        BundleInspectionRefusal::RefUnavailable => ApiError::not_found(),
        BundleInspectionRefusal::BudgetExceeded
        | BundleInspectionRefusal::Source(MergeSourceError::BudgetExceeded)
        | BundleInspectionRefusal::Validation(ProjectionFailure::Unavailable(
            RefusalCode::ResourceBudgetExceeded,
        )) => ApiError::too_large(),
        BundleInspectionRefusal::Source(MergeSourceError::Cancelled)
        | BundleInspectionRefusal::Validation(ProjectionFailure::Unavailable(
            RefusalCode::CancellationInProgress,
        )) => ApiError::from_status(Status::Timeout, false),
        BundleInspectionRefusal::InvalidCandidate(_)
        | BundleInspectionRefusal::Pack(_)
        | BundleInspectionRefusal::Validation(ProjectionFailure::Refuse(_)) => {
            ApiError::bad("invalid_candidate")
        }
        BundleInspectionRefusal::Envelope(error) => source_error(*error),
        BundleInspectionRefusal::Review(error) => match *error {
            ReviewError::InvalidOptions => ApiError::bad("invalid_inspection_request"),
            ReviewError::Budget(_) | ReviewError::Source(MergeSourceError::BudgetExceeded) => {
                ApiError::too_large()
            }
            ReviewError::Source(MergeSourceError::Cancelled) => {
                ApiError::from_status(Status::Timeout, false)
            }
            _ => ApiError::unavailable(),
        },
        _ => ApiError::unavailable(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_candidates_and_unavailable_evidence_never_become_votes_or_empty_reports() {
        for cause in [
            BundleInspectionRefusal::BudgetExceeded,
            BundleInspectionRefusal::ParentMoved,
            BundleInspectionRefusal::InvalidCandidate("untrusted input"),
            BundleInspectionRefusal::Source(MergeSourceError::Cancelled),
        ] {
            let error = inspection_error(cause.into());
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
            assert!(!text.contains("untrusted input"));
            assert!(!text.contains("\"outcome\":\"refused\""));
            assert!(!text.contains("\"type\":\"candidate_inspection\""));
        }
    }
}
