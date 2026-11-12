//! Independently authenticated discussion reads, strict writes and append intents.
mod output;
mod request;
#[cfg(test)]
mod tests;

use fgit_authority::IdempotencyKey;
use fgit_types::DecisionOutcome;
use fgit_wire::smart_http::{BodyFraming, HttpLimits, head::Envelope};
use std::io::Read;

use super::super::drive_request_while;
use super::issues::{ApiError, Reply, admission_error, read_form};
use super::{Profile, Status, retry_key};
use crate::{
    GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession, OneNode,
};
pub(super) use request::Request;
use request::{Command, Operation};

const ROUTE: &str = "/api/v1/discussions";
const MAX_RESPONSE_BYTES: usize = 48 * 1024 * 1024;

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
    if !profile.config.http_discussions_enabled()
        || !grant.permits_discussions(request.is_mutation())
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
        b"discussion-read-no-publication".as_slice()
    };
    Ok(grant.session(
        IdempotencyKey::new(key.to_vec()).map_err(|_| ApiError::bad("invalid_idempotency_key"))?,
    ))
}

fn read_error(error: crate::DiscussionReadRefusal) -> ApiError {
    match error {
        crate::DiscussionReadRefusal::SnapshotMoved => ApiError::snapshot_moved(),
        crate::DiscussionReadRefusal::SnapshotRequired => ApiError::bad("snapshot_required"),
        crate::DiscussionReadRefusal::InvalidLimit => ApiError::bad("invalid_page_limit"),
        _ => ApiError::unavailable(),
    }
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
    // Framing and content validation finish before any seal or canonical effect.
    let command = if request.is_mutation() {
        Some(request.command(&read_form(reader, framing, limits)?)?)
    } else {
        None
    };
    let deadline = GitDaemonSessionDeadline::new(
        node.git_daemon_session_timeout,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let context = node.authenticated_session_request_context(&deadline, session);
    let mut live = || !deadline.expired();
    let maximum = usize::try_from(maximum_response)
        .unwrap_or(usize::MAX)
        .min(MAX_RESPONSE_BYTES);
    match &request.operation {
        Operation::List(page) => {
            let result = drive_request_while(
                node,
                &context,
                node.read_discussions_in(&context, page.after, page.limit, page.expected_head),
                &mut live,
            )
            .map_err(read_error)?;
            Ok(Reply {
                status: Status::Success,
                body: output::list(node, *page, &result, maximum)?,
                terminal: None,
            })
        }
        Operation::Show { number, page } => {
            let result = drive_request_while(
                node,
                &context,
                node.read_discussion_history_in(
                    &context,
                    *number,
                    page.after,
                    page.limit,
                    page.expected_head,
                ),
                &mut live,
            )
            .map_err(read_error)?;
            Ok(Reply {
                status: if result.discussion.is_some() {
                    Status::Success
                } else {
                    Status::NotFound
                },
                body: output::history(node, *number, *page, &result, maximum)?,
                terminal: None,
            })
        }
        Operation::Mutate { .. } => {
            let command = command.ok_or_else(|| ApiError::bad("missing_command"))?;
            match &command {
                Command::Versioned(command) => command.proposed_event(principal),
                Command::AppendComment(intent) => intent.commitment_event(principal),
            }
            .map_err(|_| ApiError::bad("invalid_discussion_command"))?;
            let (tx, terminal) = match &command {
                Command::Versioned(command) => drive_request_while(
                    node,
                    &context,
                    node.admit_discussion_durable_in(
                        &context,
                        session,
                        command,
                        Default::default(),
                    ),
                    &mut live,
                ),
                Command::AppendComment(intent) => drive_request_while(
                    node,
                    &context,
                    node.admit_discussion_comment_durable_in(
                        &context,
                        session,
                        intent,
                        Default::default(),
                    ),
                    &mut live,
                ),
            }
            .map_err(admission_error)?;
            let body = output::mutation(node, principal, &command, tx, terminal);
            if body.len() > maximum {
                eprintln!(
                    "Discussion HTTP response limit after canonical outcome for transaction {tx}"
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
