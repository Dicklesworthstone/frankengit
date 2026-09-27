//! Authenticated exact-PR-source workflow observations. A read grants neither
//! execution authority nor approval; the projection never exposes evidence bodies.

mod output;
mod request;
pub(super) use request::Request;

use super::super::issues::{ApiError, Reply};
use super::super::{Profile, Status, retry_key};
use crate::smart_http::drive_request_while;
use crate::{
    GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession, OneNode,
};
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
        .authenticate(envelope.authorization())
        .map_err(|error| ApiError::from_status(Status::from(error), false))?;
    if request.repository_route.as_bytes() != profile.route {
        return Err(ApiError::not_found());
    }
    if !profile.allow_pulls || !grant.permits_pulls(false) {
        return Err(ApiError::new(Status::Forbidden, "forbidden"));
    }
    if retry_key(raw_head)
        .map_err(|_| ApiError::bad("invalid_idempotency_key"))?
        .is_some()
    {
        return Err(ApiError::bad("checks_have_no_transaction_key"));
    }
    Ok(LoopbackReceiveSession::authenticated(
        grant.principal,
        IdempotencyKey::new(b"read-only-pull-request-checks".to_vec())
            .map_err(|_| ApiError::unavailable())?,
    ))
}

pub(super) fn execute(
    node: &OneNode,
    request: &Request<'_>,
    session: &LoopbackReceiveSession,
    maximum_response: u64,
) -> Result<Reply, ApiError> {
    if session.authenticated_session().is_none() {
        return Err(ApiError::new(Status::Unauthorized, "unauthorized"));
    }
    let deadline = GitDaemonSessionDeadline::new(
        node.git_daemon_session_timeout,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let context = node.session_request_context(&deadline);
    let visibility = RefVisibility::new();
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
    .map_err(|error| {
        if error.is_snapshot_unavailable() {
            ApiError::snapshot_moved()
        } else {
            ApiError::unavailable()
        }
    })?;
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
