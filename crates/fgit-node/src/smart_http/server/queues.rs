//! Independently granted queue management through native metadata admission.
//! Queue intent neither moves Git refs nor authorizes a later merge.
mod output;
mod request;
#[cfg(test)]
mod tests;

use std::io::Read;

use fgit_authority::IdempotencyKey;
use fgit_types::DecisionOutcome;
use fgit_wire::smart_http::{BodyFraming, HttpLimits, head::Envelope};
use fgit_wire::visibility::RefVisibility;

use super::super::drive_request_while;
use super::issues::{ApiError, Reply, admission_error, read_form};
use super::{Profile, Status, retry_key};
use crate::{
    GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession, OneNode,
};
use request::Operation;
pub(super) use request::Request;

const ROUTE: &str = "/api/v1/queues";
const MAX_COMMAND_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

pub(super) fn is_route(target: &str) -> bool {
    target
        .split('?')
        .next()
        .is_some_and(|path| path.contains(ROUTE))
}

pub(super) fn authenticate(
    request: &Request<'_>,
    envelope: &Envelope<'_>,
    raw_head: &[u8],
    profile: &Profile,
) -> Result<LoopbackReceiveSession, ApiError> {
    let grant = profile
        .credentials
        .authenticate(super::bearer_only(envelope.authorization()))
        .map_err(|error| ApiError::from_status(Status::from(error), false))?;
    if request.repository_route.as_bytes() != profile.route {
        return Err(ApiError::not_found());
    }
    if !profile.config.http_queue_management_enabled()
        || !grant.permits_queues(request.is_mutation())
    {
        return Err(ApiError::new(Status::Forbidden, "forbidden"));
    }
    let key = retry_key(raw_head).map_err(|_| ApiError::bad("invalid_idempotency_key"))?;
    let key = if request.is_mutation() {
        key.ok_or_else(|| ApiError::bad("idempotency_key_required"))?
    } else {
        if key.is_some() {
            return Err(ApiError::bad("idempotency_key_not_allowed"));
        }
        b"queue-read-no-publication".as_slice()
    };
    Ok(grant.session(
        IdempotencyKey::new(key.to_vec()).map_err(|_| ApiError::bad("invalid_idempotency_key"))?,
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
        .min(MAX_RESPONSE_BYTES);
    let read_error = |error: crate::treefs_workspace::QueueReadRefusal| {
        if error.is_snapshot_unavailable() {
            ApiError::snapshot_moved()
        } else {
            ApiError::unavailable()
        }
    };
    match &request.operation {
        Operation::List(page) => {
            let selected = drive_request_while(
                node,
                &context,
                node.read_queues_in(
                    &context,
                    &RefVisibility::default(),
                    page.after,
                    page.limit,
                    page.expected_head,
                ),
                &mut live,
            )
            .map_err(read_error)?;
            Ok(Reply {
                status: Status::Success,
                body: output::list(node, *page, &selected, maximum)?,
                terminal: None,
            })
        }
        Operation::Show {
            number,
            expected_head,
        } => {
            let selected = drive_request_while(
                node,
                &context,
                node.read_queue_in(&context, &RefVisibility::default(), *number, *expected_head),
                &mut live,
            )
            .map_err(read_error)?;
            Ok(Reply {
                status: if selected.queue.is_some() {
                    Status::Success
                } else {
                    Status::NotFound
                },
                body: output::show(node, *number, *expected_head, &selected, maximum)?,
                terminal: None,
            })
        }
        Operation::Mutate { .. } => {
            let limits = HttpLimits {
                max_body_bytes: limits.max_body_bytes.min(MAX_COMMAND_BYTES as u64),
                max_body_wire_bytes: limits
                    .max_body_wire_bytes
                    .min((MAX_COMMAND_BYTES + 64 * 1024) as u64),
                max_chunks: limits.max_chunks.min(4096),
                ..limits
            };
            let bytes = read_form(reader, framing, limits)?;
            let command =
                request.command(&bytes, node.object_format, node.repository_incarnation_id())?;
            command
                .proposed_event(principal, node.object_format)
                .map_err(|_| ApiError::bad("invalid_queue_command"))?;
            let (tx, terminal) = drive_request_while(
                node,
                &context,
                node.admit_queue_durable_in(&context, session, &command, Default::default()),
                &mut live,
            )
            .map_err(admission_error)?;
            // Return the original terminal, without a latest-state read that
            // could change an identical retry's result or its disclosure.
            let body = output::mutation(node, principal, &command, tx, terminal);
            if body.len() > maximum {
                eprintln!(
                    "Queue HTTP response limit after canonical outcome for transaction {tx}; recover the original key"
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
        }
    }
}
