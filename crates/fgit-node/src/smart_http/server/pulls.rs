//! Authenticated native PR lifecycle. This adapter supplies no PR database,
//! object proof, merge permission, or alternate publication path. It binds a
//! credential principal to explicit commands and calls the existing node APIs.

mod output;
mod request;

use std::io::Read;

use fgit_authority::IdempotencyKey;
use fgit_types::DecisionOutcome;
use fgit_wire::smart_http::{BodyFraming, HttpLimits, head::Envelope};
use fgit_wire::visibility::RefVisibility;

use crate::{GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession, OneNode};
use super::{Profile, Status, retry_key};
use super::issues::{ApiError, Reply, admission_error, read_form};
use super::super::drive_request_while;
use request::Operation;
pub(super) use request::Request;

pub(super) fn authenticate(
    request: &Request<'_>, envelope: &Envelope<'_>, raw_head: &[u8], profile: &Profile,
) -> Result<LoopbackReceiveSession, ApiError> {
    let grant = profile.credentials.authenticate(envelope.authorization())
        .map_err(|error| ApiError::from_status(Status::from(error), false))?;
    if request.repository_route.as_bytes() != profile.route { return Err(ApiError::not_found()); }
    if !profile.allow_pulls || !grant.permits_pulls(request.is_mutation()) {
        return Err(ApiError::new(Status::Forbidden, "forbidden"));
    }
    let key = retry_key(raw_head).map_err(|_| ApiError::bad("invalid_idempotency_key"))?;
    let key = if request.is_mutation() {
        key.ok_or_else(|| ApiError::bad("idempotency_key_required"))?
    } else {
        b"pull-request-read-no-publication".as_slice()
    };
    let key = IdempotencyKey::new(key.to_vec()).map_err(|_| ApiError::bad("invalid_idempotency_key"))?;
    Ok(LoopbackReceiveSession::authenticated(grant.principal, key))
}

/// The listener authenticates scopes and applies intake quota before this call.
/// Full HTTP framing precedes any admission. The exact submitted command enters
/// durable PR admission, so ref/closure/policy/version checks and retry identity
/// are identical to local publication. Closing never refreshes metadata first.
pub(super) fn execute(
    node: &OneNode, request: &Request<'_>, session: &LoopbackReceiveSession,
    framing: BodyFraming, reader: &mut impl Read, limits: HttpLimits, maximum_response: u64,
) -> Result<Reply, ApiError> {
    let principal = session.authenticated_session()
        .ok_or_else(|| ApiError::new(Status::Unauthorized, "unauthorized"))?.principal_id();
    let command = if request.is_mutation() {
        Some(request.command(&read_form(reader, framing, limits)?, node.object_format)?)
    } else { None };
    let context = node.request_context();
    let deadline = GitDaemonSessionDeadline::new(node.git_daemon_session_timeout, GitDaemonSessionWorkScaling::FLAT);
    let mut live = || !deadline.expired();
    let maximum = usize::try_from(maximum_response).unwrap_or(usize::MAX).min(output::MAX_REPLY_BYTES);
    // An empty caller visibility filter cannot override canonical hidden refs:
    // the node applies current repository policy to both source and target.
    let visibility = RefVisibility::new();
    match &request.operation {
        Operation::List(page) => {
            let result = drive_request_while(node, &context,
                node.read_pull_requests_in(&context, &visibility, page.after, page.limit, page.expected_head),
                &mut live).map_err(|error| {
                    if error.is_snapshot_unavailable() { ApiError::snapshot_moved() } else { ApiError::unavailable() }
                })?;
            Ok(Reply { status: Status::Success, body: output::list(node, *page, &result, maximum)?, terminal: None })
        }
        Operation::Show { number, expected_head } => {
            let result = drive_request_while(node, &context,
                node.read_pull_requests_in(&context, &visibility, number.get() - 1, 1, *expected_head),
                &mut live).map_err(|error| {
                    if error.is_snapshot_unavailable() { ApiError::snapshot_moved() } else { ApiError::unavailable() }
                })?;
            let (found, body) = output::show(node, *number, *expected_head, &result, maximum)?;
            Ok(Reply { status: if found { Status::Success } else { Status::NotFound }, body, terminal: None })
        }
        Operation::Mutate { .. } => {
            let command = command.ok_or_else(|| ApiError::bad("missing_command"))?;
            command.proposed_event(principal, node.object_format)
                .map_err(|_| ApiError::bad("invalid_pull_request_command"))?;
            let (tx, terminal) = drive_request_while(node, &context,
                node.admit_pull_request_durable_in(&context, session, &command, Default::default()), &mut live)
                .map_err(admission_error)?;
            let body = output::mutation(node, principal, &command, tx, terminal);
            if body.len() > maximum {
                eprintln!("PR HTTP response limit after canonical outcome for transaction {tx}; recover the original key");
                return Err(ApiError::unknown());
            }
            Ok(Reply { status: match terminal.outcome {
                DecisionOutcome::Committed { .. } => Status::Success,
                DecisionOutcome::Refused { .. } => Status::Conflict,
            }, body, terminal: Some((tx, terminal)) })
        }
    }
}
