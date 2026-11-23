//! Exact replacement and additive PR labels share native PR authority and durable
//! retry recovery. Labels never move refs or advance the PR content stream.

mod output;
mod request;
pub(super) use output::fields;
pub(super) use request::Request;

use std::io::Read;

use fgit_authority::IdempotencyKey;
use fgit_types::DecisionOutcome;
use fgit_wire::smart_http::{BodyFraming, HttpLimits, head::Envelope};
use fgit_wire::visibility::RefVisibility;

use super::super::issues::{ApiError, Reply, admission_error, read_form};
use super::super::{Profile, Status, retry_key};
use crate::smart_http::drive_request_while;
use crate::{GitDaemonSessionDeadline, LoopbackReceiveSession, OneNode};

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
    if !profile.allow_pulls() || !grant.permits_pulls(request.is_mutation()) {
        return Err(ApiError::new(Status::Forbidden, "forbidden"));
    }
    let key = retry_key(raw_head).map_err(|_| ApiError::bad("invalid_idempotency_key"))?;
    let key = if request.is_mutation() {
        key.ok_or_else(|| ApiError::bad("idempotency_key_required"))?
    } else {
        if key.is_some() {
            return Err(ApiError::bad("idempotency_key_not_allowed"));
        }
        b"pull-request-labels-read-no-publication".as_slice()
    };
    let key =
        IdempotencyKey::new(key.to_vec()).map_err(|_| ApiError::bad("invalid_idempotency_key"))?;
    Ok(grant.session(key))
}

pub(super) fn execute(
    node: &OneNode,
    request: &Request<'_>,
    session: &LoopbackReceiveSession,
    framing: BodyFraming,
    reader: &mut impl Read,
    limits: HttpLimits,
    maximum_response: u64,
    deadline: &GitDaemonSessionDeadline,
) -> Result<Reply, ApiError> {
    let principal = session
        .authenticated_session()
        .ok_or_else(|| ApiError::new(Status::Unauthorized, "unauthorized"))?
        .principal_id();
    // Complete framing before the node can seal a mutation. The command is
    // immutable across CAS retries and original-key outcome recovery.
    let body = if request.is_mutation() {
        Some(read_form(reader, framing, limits)?)
    } else {
        None
    };
    let context = node.authenticated_session_request_context(deadline, session);
    let mut live = || !deadline.expired();
    let maximum = usize::try_from(maximum_response)
        .unwrap_or(usize::MAX)
        .min(output::MAX_REPLY_BYTES);
    if let Some(body) = body {
        let (tx, terminal, body) = if request.is_addition() {
            let intent = request.addition(&body)?;
            let (tx, terminal) = drive_request_while(
                node,
                &context,
                node.admit_pull_request_add_labels_durable_in(&context, session, &intent, Default::default()),
                &mut live,
            ).map_err(admission_error)?;
            let body = output::addition_publication(node, principal, &intent, tx, terminal)?;
            (tx, terminal, body)
        } else {
            let command = request.command(&body)?;
            command.proposed_event(principal)
                .map_err(|_| ApiError::bad("invalid_pull_request_labels"))?;
            let (tx, terminal) = drive_request_while(
                node,
                &context,
                node.admit_pull_request_labels_durable_in(&context, session, &command, Default::default()),
                &mut live,
            ).map_err(admission_error)?;
            let body = output::publication(node, principal, &command, tx, terminal)?;
            (tx, terminal, body)
        };
        if body.len() > maximum {
            eprintln!(
                "PR label HTTP response limit after canonical outcome for transaction {tx}; recover the original key"
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
            node.read_pull_requests_in(
                &context,
                &visibility,
                request.number.get() - 1,
                1,
                request.expected_head,
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
        let (found, body) = output::read(node, request, &result, maximum)?;
        Ok(Reply {
            status: if found {
                Status::Success
            } else {
                Status::NotFound
            },
            body,
            terminal: None,
        })
    }
}
