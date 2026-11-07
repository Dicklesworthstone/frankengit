//! Explicit queue-head target refresh through one ordinary metadata decision.
//! Both queue management and PR-write grants are required by the gateway.

mod request;
pub(super) use request::parse;
pub(super) const MAX_COMMAND_BYTES: usize = super::super::issues::MAX_FORM_BYTES;

use std::io::Read;
use fgit_forge::QueueNumber;
use fgit_types::DecisionOutcome;
use fgit_wire::smart_http::{BodyFraming, HttpLimits};

use super::super::issues::{ApiError, Reply, admission_error, read_form};
use super::super::Status;
use super::output;
use crate::smart_http::drive_request_while;
use crate::{
    GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession, OneNode,
};

pub(super) fn execute(
    node: &OneNode,
    number: QueueNumber,
    session: &LoopbackReceiveSession,
    framing: BodyFraming,
    reader: &mut impl Read,
    limits: HttpLimits,
    maximum_response: u64,
) -> Result<Reply, ApiError> {
    let authenticated = session.authenticated_session()
        .ok_or_else(|| ApiError::new(Status::Unauthorized, "unauthorized"))?;
    let principal = authenticated.principal_id();
    let deadline = GitDaemonSessionDeadline::new(
        node.git_daemon_session_timeout,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let context = node.session_request_context(&deadline);
    let mut live = || !deadline.expired();
    let bytes = read_form(reader, framing, limits)?;
    let command = parse(
        number, &bytes, node.object_format, node.repository_incarnation_id(),
    )?;
    drop(bytes);
    command.proposed_event(principal, node.object_format)
        .map_err(|_| ApiError::bad("invalid_queue_refresh"))?;
    // Metadata refresh neither moves a ref nor inherits the separate code
    // landing permission. Native admission owns current visibility and policy.
    let (tx, terminal) = drive_request_while(
        node, &context,
        node.refresh_queue_head_durable_in(
            &context, session, &command, Default::default(),
        ),
        &mut live,
    ).map_err(admission_error)?;
    let body = output::refresh(node, principal, &command, tx, terminal);
    let maximum = usize::try_from(maximum_response)
        .unwrap_or(usize::MAX).min(super::MAX_RESPONSE_BYTES);
    if body.len() > maximum {
        eprintln!(
            "Queue refresh HTTP response limit after canonical outcome for transaction {tx}; recover the original key"
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
