//! Native PR discussion with independently granted reads and writes. Comments
//! use a separate canonical stream and never imply a review or merge approval.

mod output;
mod request;
pub(super) use request::Request;

use std::io::Read;

use fgit_authority::IdempotencyKey;
use fgit_types::DecisionOutcome;
use fgit_wire::smart_http::{BodyFraming, HttpLimits, head::Envelope};
use fgit_wire::visibility::RefVisibility;

use super::super::issues::{ApiError, Reply, admission_error, read_form};
use super::super::{Profile, Status, retry_key};
use crate::smart_http::drive_request_while;
use crate::{
    GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession, OneNode,
};

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
    if !profile.allow_pulls || !grant.permits_pulls(request.is_mutation()) {
        return Err(ApiError::new(Status::Forbidden, "forbidden"));
    }
    let key = retry_key(raw_head).map_err(|_| ApiError::bad("invalid_idempotency_key"))?;
    let key = if request.is_mutation() {
        key.ok_or_else(|| ApiError::bad("idempotency_key_required"))?
    } else {
        if key.is_some() {
            return Err(ApiError::bad("idempotency_key_not_allowed"));
        }
        b"pull-request-comments-read-no-publication".as_slice()
    };
    let key =
        IdempotencyKey::new(key.to_vec()).map_err(|_| ApiError::bad("invalid_idempotency_key"))?;
    Ok(LoopbackReceiveSession::authenticated(grant.principal, key))
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
    let principal = session
        .authenticated_session()
        .ok_or_else(|| ApiError::new(Status::Unauthorized, "unauthorized"))?
        .principal_id();
    let deadline = GitDaemonSessionDeadline::new(
        node.git_daemon_session_timeout,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let context = node.session_request_context(&deadline);
    let mut live = || !deadline.expired();
    let maximum = usize::try_from(maximum_response)
        .unwrap_or(usize::MAX)
        .min(output::MAX_REPLY_BYTES);
    if request.is_mutation() {
        // Finish framing and validate the entire supplied form before the
        // native driver can acquire any publication responsibility.
        let command = request.command(&read_form(reader, framing, limits)?)?;
        command
            .proposed_event(principal)
            .map_err(|_| ApiError::bad("invalid_comment_command"))?;
        let (tx, terminal) = drive_request_while(
            node,
            &context,
            node.admit_pull_request_comment_durable_in(
                &context,
                session,
                &command,
                Default::default(),
            ),
            &mut live,
        )
        .map_err(admission_error)?;
        // Do not read a newer discussion here: an exact historical retry must
        // retain its original terminal after later comments or PR changes.
        let body = output::publication(node, principal, &command, tx, terminal)?;
        if body.len() > maximum {
            eprintln!(
                "PR comment HTTP response limit after canonical outcome for transaction {tx}; recover the original key"
            );
            return Err(ApiError::unknown());
        }
        Ok(Reply {
            status: match terminal.outcome {
                DecisionOutcome::Committed { .. } => Status::Success,
                DecisionOutcome::Refused { .. } => Status::Conflict,
            },
            body,
            terminal: Some((tx, terminal)),
        })
    } else {
        let visibility = RefVisibility::new();
        let result = drive_request_while(
            node,
            &context,
            node.read_pull_request_comments_in(
                &context,
                &visibility,
                request.number,
                request.page.after,
                request.page.limit,
                request.page.expected_head,
            ),
            &mut live,
        )
        .map_err(|error| {
            if error.is_snapshot_unavailable() {
                ApiError::snapshot_moved()
            } else {
                ApiError::unavailable()
            }
        })?;
        Ok(Reply {
            status: if result.is_some() {
                Status::Success
            } else {
                Status::NotFound
            },
            body: output::page(node, request, result.as_ref(), maximum, &mut live)?,
            terminal: None,
        })
    }
}
