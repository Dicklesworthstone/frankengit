//! Authenticated exact-PR-source workflow observations. A read grants neither
//! execution authority nor approval. Evidence bodies require a separate output
//! disclosure grant. Sponsored readers use their own exact-check capability;
//! ordinary operators retain the independent PR-read plus artifact-read pair.

mod output;
mod request;
pub(in crate::smart_http::server) use request::Request;

use super::super::issues::{ApiError, Reply};
use super::super::{Profile, Status, retry_key};
use crate::smart_http::drive_request_while;
use crate::{GitDaemonSessionDeadline, LoopbackReceiveSession, OneNode};
use fgit_authority::IdempotencyKey;
use fgit_wire::smart_http::head::Envelope;
use fgit_wire::visibility::RefVisibility;

pub(super) fn authenticate(
    request: &Request<'_>,
    envelope: &Envelope<'_>,
    raw_head: &[u8],
    profile: &Profile,
) -> Result<LoopbackReceiveSession, ApiError> {
    let grant = profile
        .credentials
        .authenticate(super::super::bearer_only(envelope.authorization()))
        .map_err(|error| ApiError::from_status(Status::from(error), false))?;
    if request.repository_route.as_bytes() != profile.route {
        return Err(ApiError::not_found());
    }
    let permitted = grant.permits_pulls(false)
        || if request.evidence.is_some() {
            grant.permits_pull_check_evidence_read()
        } else {
            grant.permits_pull_feedback_read()
        };
    if !profile.allow_pulls() || !permitted {
        return Err(ApiError::new(Status::Forbidden, "forbidden"));
    }
    if request.evidence.is_some()
        && !(grant.permits_artifact_read() || grant.permits_pull_check_evidence_read())
    {
        return Err(ApiError::new(
            Status::Forbidden,
            "artifact_read_not_granted",
        ));
    }
    if retry_key(raw_head)
        .map_err(|_| ApiError::bad("invalid_idempotency_key"))?
        .is_some()
    {
        return Err(ApiError::bad("checks_have_no_transaction_key"));
    }
    Ok(grant.session(
        IdempotencyKey::new(b"read-only-pull-request-checks".to_vec())
            .map_err(|_| ApiError::unavailable())?,
    ))
}

pub(super) fn execute(
    node: &OneNode,
    request: &Request<'_>,
    session: &LoopbackReceiveSession,
    maximum_response: u64,
    deadline: &GitDaemonSessionDeadline,
) -> Result<Reply, ApiError> {
    if session.authenticated_session().is_none() {
        return Err(ApiError::new(Status::Unauthorized, "unauthorized"));
    }
    let context = node.authenticated_session_request_context(deadline, session);
    let visibility = RefVisibility::new();
    if let Some(check) = request.evidence {
        let head = request
            .page
            .expected_head
            .ok_or_else(|| ApiError::bad("snapshot_required"))?;
        let result = drive_request_while(
            node,
            &context,
            node.read_pull_request_check_evidence_in(
                &context,
                &visibility,
                request.number,
                check,
                head,
            ),
            &mut || context.is_live() && !deadline.expired(),
        )
        .map_err(read_error)?
        .ok_or_else(ApiError::not_found)?;
        let maximum = usize::try_from(maximum_response)
            .unwrap_or(usize::MAX)
            .min(output::MAX_EVIDENCE_REPLY_BYTES);
        return Ok(Reply {
            status: Status::Success,
            body: output::evidence(node, request.number, check, head, &result, maximum, &|| {
                context.is_live() && !deadline.expired()
            })?,
            terminal: None,
        });
    }
    let result = drive_request_while(
        node,
        &context,
        node.read_pull_request_checks_in(
            &context,
            &visibility,
            request.number,
            request.page.after,
            request.page.limit,
            request.page.expected_head,
        ),
        &mut || !deadline.expired(),
    )
    .map_err(read_error)?;
    let maximum = usize::try_from(maximum_response)
        .unwrap_or(usize::MAX)
        .min(output::MAX_REPLY_BYTES);
    Ok(Reply {
        status: if result.is_some() {
            Status::Success
        } else {
            Status::NotFound
        },
        body: output::page(node, request.number, request.page, result.as_ref(), maximum)?,
        terminal: None,
    })
}

fn read_error(error: crate::PullRequestChecksReadRefusal) -> ApiError {
    if error.is_snapshot_unavailable() {
        ApiError::snapshot_moved()
    } else {
        ApiError::unavailable()
    }
}
