//! Canonical symbolic HEAD through independently granted HTTP administration.
//! Reads use source disclosure; writes never inherit Git receive or policy-edit
//! grants. Native admission owns current administrator checks and every terminal.

mod request;
#[cfg(test)]
mod tests;

use std::io::Read;
use std::time::Duration;

use fgit_admission::default_branch::DefaultBranchCommand;
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_types::{DecisionOutcome, GitOid, PrincipalId, RefName, RepositoryAuthorityHeadId, TxId};
use fgit_wire::smart_http::{BodyFraming, HttpLimits, head::Envelope};
use fgit_wire::visibility::RefVisibility;

use super::issues::{ApiError, Reply, admission_error, quote, read_form};
use super::{Profile, Status, retry_key};
use crate::smart_http::drive_request_while;
use crate::{GitDaemonSessionDeadline, LoopbackReceiveSession, NodeWorkspaceRefusal, OneNode};

pub(super) use request::Request;
pub(super) const ROUTE: &str = "/api/v1/default-branch";
const MAX_COMMAND_BYTES: usize = 24 * 1024;
const MAX_REPLY_BYTES: usize = 32 * 1024;

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
    let permitted = if request.is_mutation() {
        profile.config.http_default_branch_admin_enabled() && grant.permits_default_branch_write()
    } else {
        profile.allow_source() && grant.permits_source_read()
    };
    if !permitted {
        return Err(ApiError::new(Status::Forbidden, "forbidden"));
    }
    let key = retry_key(raw_head).map_err(|_| ApiError::bad("invalid_idempotency_key"))?;
    let key = if request.is_mutation() {
        key.ok_or_else(|| ApiError::bad("idempotency_key_required"))?
    } else {
        if key.is_some() {
            return Err(ApiError::bad("idempotency_key_not_allowed"));
        }
        b"default-branch-read-no-publication".as_slice()
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
    deadline: &GitDaemonSessionDeadline,
) -> Result<Reply, ApiError> {
    let principal = session
        .authenticated_session()
        .ok_or_else(|| ApiError::new(Status::Unauthorized, "unauthorized"))?
        .principal_id();
    // Finish complete bounded framing before native admission. Intake and all
    // awaited authority work share the original accepted connection's deadline.
    let command = if request.is_mutation() {
        let limits = HttpLimits {
            max_body_bytes: limits.max_body_bytes.min(MAX_COMMAND_BYTES as u64),
            max_body_wire_bytes: limits.max_body_wire_bytes.min((48 * 1024) as u64),
            max_chunks: limits.max_chunks.min(256),
            ..limits
        };
        Some(request::command(
            &read_form(reader, framing, limits)?,
            node.object_format,
        )?)
    } else {
        None
    };
    if deadline.expired() {
        return Err(ApiError::from_status(Status::Timeout, false));
    }
    let context =
        node.session_request_context_with_timeout(deadline.remaining().unwrap_or(Duration::ZERO));
    let mut live = || !deadline.expired() && context.is_live();
    let maximum = usize::try_from(maximum_response)
        .unwrap_or(usize::MAX)
        .min(MAX_REPLY_BYTES);
    if let Some(command) = command {
        let (tx, terminal) = drive_request_while(
            node,
            &context,
            node.admit_default_branch_http_admin_in(
                &context,
                session,
                &command,
                Default::default(),
            ),
            &mut live,
        )
        .map_err(admission_error)?;
        // A fresh HEAD/policy read after publication could overwrite a genuine
        // historical terminal. The receipt describes only the sealed command.
        let body = publication(node, principal, &command, tx, terminal);
        if body.len() > maximum {
            eprintln!(
                "Default-branch HTTP receipt unavailable after transaction {tx}; recover the original key"
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
        let (head, target, tip) = drive_request_while(
            node,
            &context,
            node.read_default_branch_in(&context, &RefVisibility::new()),
            &mut live,
        )
        .map_err(read_error)?;
        if request
            .expected_head
            .is_some_and(|expected| expected != head)
        {
            return Err(ApiError::new(Status::Conflict, "source_snapshot_moved"));
        }
        let body = observation(node, principal, head, target.as_ref(), tip);
        if body.len() > maximum {
            return Err(ApiError::too_large());
        }
        if !live() {
            return Err(ApiError::from_status(Status::Timeout, false));
        }
        Ok(Reply {
            status: Status::Success,
            body,
            terminal: None,
        })
    }
}

fn read_error(error: NodeWorkspaceRefusal) -> ApiError {
    match error {
        NodeWorkspaceRefusal::RefUnavailable => ApiError::not_found(),
        NodeWorkspaceRefusal::Cancelled {
            exhaustion: Some(_),
        } => ApiError::too_large(),
        NodeWorkspaceRefusal::Cancelled { exhaustion: None } => {
            ApiError::from_status(Status::Timeout, false)
        }
        _ => ApiError::unavailable(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn reference(name: Option<&RefName>) -> String {
    name.map_or_else(|| "null".into(), |name| quote(&hex(name.as_bytes())))
}
fn metadata(node: &OneNode, principal: PrincipalId) -> String {
    format!(
        concat!(
            "\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},",
            "\"repository_incarnation\":{},\"principal_id\":{},\"object_format\":{}"
        ),
        quote(&node.tenant_id.to_string()),
        quote(&node.repository_id.to_string()),
        quote(&node.repository_incarnation_id().to_string()),
        quote(&principal.to_string()),
        quote(node.object_format.as_str()),
    )
}
fn observation(
    node: &OneNode,
    principal: PrincipalId,
    head: RepositoryAuthorityHeadId,
    target: Option<&RefName>,
    tip: Option<GitOid>,
) -> String {
    let internal = head.as_internal_object_id();
    let token = format!(
        "alg:{}:{}",
        internal.algorithm().code_point(),
        hex(internal.digest().as_bytes())
    );
    format!(
        concat!(
            "{{\"type\":\"default_branch\",{},\"source_head\":{},\"snapshot_token\":{},",
            "\"default_reference_hex\":{},\"tip\":{},\"unborn\":{},",
            "\"read_only\":true,\"transaction_created\":false,\"published\":false}}"
        ),
        metadata(node, principal),
        quote(&head.to_string()),
        quote(&token),
        reference(target),
        tip.map_or_else(|| "null".into(), |tip| quote(&tip.to_string())),
        target.is_some() && tip.is_none(),
    )
}
fn publication(
    node: &OneNode,
    principal: PrincipalId,
    command: &DefaultBranchCommand,
    tx: TxId,
    terminal: TerminalOutcome,
) -> String {
    let (committed, decision) = match terminal.outcome {
        DecisionOutcome::Committed {
            repository_commit_id,
        } => (
            true,
            format!(
                "\"outcome\":\"committed\",\"repository_commit_id\":{}",
                quote(&repository_commit_id.to_string())
            ),
        ),
        DecisionOutcome::Refused {
            code,
            refusal_record_id,
        } => (
            false,
            format!(
                "\"outcome\":\"refused\",\"code\":{},\"code_point\":{},\"refusal_record_id\":{}",
                quote(&format!("{code:?}")),
                code.code_point(),
                quote(&refusal_record_id.to_string())
            ),
        ),
    };
    format!(
        concat!(
            "{{\"type\":\"default_branch_publication\",{},\"operation\":\"set-default\",",
            "\"authentication\":\"http-token\",\"terminal\":true,\"tx_id\":{},\"decision_sequence\":{},",
            "{},\"expected_default_reference_hex\":{},\"default_reference_hex\":{},\"expected_tip\":{},",
            "\"head_changed_by_transaction\":{},\"direct_refs_changed\":false}}"
        ),
        metadata(node, principal),
        quote(&tx.to_string()),
        terminal.decision_sequence.get(),
        decision,
        reference(command.expected_head.as_ref()),
        reference(Some(&command.target)),
        quote(&command.expected_target_tip.to_string()),
        committed && command.expected_head.as_ref() != Some(&command.target),
    )
}
