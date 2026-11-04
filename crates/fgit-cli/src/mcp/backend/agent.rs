//! Canonical sponsored credentials for closed MCP source and metadata tools.
//!
//! Launch flags only attenuate. The current authenticated repository frontier
//! authorizes each call independently; neither discovery nor a prior call grants
//! access. Active authority lasts for one native call; its separate completed
//! reservation remains until the response is emitted or the session closes.

use super::super::protocol::{MAX_MESSAGE_BYTES, MAX_RESPONSE};
use super::{NodeTools, Object, Options, ToolError, Value, mutations, object, text};
use fgit_authority::IdempotencyKey;
use fgit_identity::agent::{
    DISCUSSIONS_READ, DISCUSSIONS_WRITE, ISSUES_READ, ISSUES_WRITE, OUTCOMES_READ, PULLS_READ,
    PULLS_WRITE, SOURCE_READ,
};
use fgit_node::agent_credentials::AgentRequest;
use fgit_node::{LoopbackReceiveSession, NodeReceiveTransportRefusal};
use std::time::{Duration, Instant};

// Reserve the framing ceilings actually enforced by protocol::serve, including
// the output LF. These are envelope bounds, not whole-process resource accounting.
const INPUT_BYTES: u64 = MAX_MESSAGE_BYTES as u64;
const OUTPUT_BYTES: u64 = MAX_RESPONSE as u64 + 1;

pub(super) struct Profile {
    // Intentionally no Debug/Clone: the bearer must not enter diagnostics or
    // request/result values. Replacing the file cannot change a running identity.
    bearer: Vec<u8>,
    pub(super) request: Option<AgentRequest>,
    // A completed request can authorize only its response, never another
    // operation or session. The protocol clears it after emission.
    pub(super) response: Option<AgentRequest>,
}

impl Profile {
    pub(super) fn load(options: &Options) -> Result<Option<Self>, String> {
        options
            .agent_token_file
            .as_ref()
            .map(|path| {
                fgit_cli::agent_credential_token::read(path).map(|bearer| Self {
                    bearer,
                    request: None,
                    response: None,
                })
            })
            .transpose()
    }
}

/// One exhaustive list owns both discovery and dispatch. Do not derive this
/// from broad operator groups: those also grant milestones, notifications,
/// checks, reviews, history, candidates and events not covered by these grants.
pub(super) fn operation(options: &Options, name: &str) -> Option<u16> {
    match name {
        "frankengit_issue_list" | "frankengit_issue_show" if options.issues => Some(ISSUES_READ),
        "frankengit_issue_open"
        | "frankengit_issue_edit"
        | "frankengit_issue_close"
        | "frankengit_issue_reopen"
        | "frankengit_issue_lock"
        | "frankengit_issue_unlock"
        | "frankengit_issue_comment"
        | "frankengit_issue_append_comment"
        | "frankengit_issue_add_assignees"
        | "frankengit_issue_add_labels"
        | "frankengit_issue_assign"
        | "frankengit_issue_unassign"
        | "frankengit_issue_set_milestone"
        | "frankengit_issue_clear_milestone"
            if options.writes.issues =>
        {
            Some(ISSUES_WRITE)
        }
        "frankengit_pull_list" | "frankengit_pull_show" | "frankengit_pull_comments"
            if options.pulls =>
        {
            Some(PULLS_READ)
        }
        "frankengit_pull_open"
        | "frankengit_pull_update"
        | "frankengit_pull_close"
        | "frankengit_pull_comment"
        | "frankengit_pull_append_comment"
            if options.writes.pulls =>
        {
            Some(PULLS_WRITE)
        }
        "frankengit_discussion_list" | "frankengit_discussion_show" if options.discussions => {
            Some(DISCUSSIONS_READ)
        }
        "frankengit_discussion_open"
        | "frankengit_discussion_edit"
        | "frankengit_discussion_comment"
        | "frankengit_discussion_lock"
        | "frankengit_discussion_unlock"
        | "frankengit_discussion_close"
        | "frankengit_discussion_reopen"
            if options.writes.discussions =>
        {
            Some(DISCUSSIONS_WRITE)
        }
        "frankengit_transaction_outcome" if options.outcomes => Some(OUTCOMES_READ),
        "frankengit_source_tree"
        | "frankengit_source_blob"
        | "frankengit_source_search"
        | "frankengit_source_search_batch"
        | "frankengit_source_search_index"
        | "frankengit_source_symbols"
        | "frankengit_ref_list"
        | "frankengit_source_initial"
        | "frankengit_source_context"
            if options.source =>
        {
            Some(SOURCE_READ)
        }
        "frankengit_agent_context" if options.agent_context => Some(SOURCE_READ),
        _ => None,
    }
}

pub(super) fn is_write(operation: u16) -> bool {
    operation & (ISSUES_WRITE | PULLS_WRITE | DISCUSSIONS_WRITE) != 0
}

fn request_commitment(name: &str, args: &Object) -> Result<[u8; 32], ToolError> {
    let request = object([
        ("name", text(name)),
        ("arguments", Value::Object(args.clone())),
    ])
    .encode(MAX_MESSAGE_BYTES)
    .map_err(|_| ToolError::invalid("agent_request_limit"))?;
    let mut bytes = b"frankengit/agent-metadata/mcp-request/v1\0".to_vec();
    bytes.extend_from_slice(request.as_bytes());
    Ok(fgit_crypto::sha256_digest(&bytes))
}

fn auth_error(error: NodeReceiveTransportRefusal) -> ToolError {
    match error {
        NodeReceiveTransportRefusal::Unauthenticated => {
            ToolError::failed("agent_credential_unavailable")
        }
        NodeReceiveTransportRefusal::Admission(error)
            if matches!(
                *error,
                fgit_admission::AdmissionError::AsyncProjectionUnavailable(
                    fgit_types::RefusalCode::CapabilityScopeViolation
                )
            ) =>
        {
            ToolError::invalid("agent_operation_not_granted")
        }
        _ => ToolError::failed("agent_authentication_unavailable"),
    }
}

pub(super) fn call(backend: &mut NodeTools, name: &str, args: &Object) -> Result<Value, ToolError> {
    if let Some(profile) = &mut backend.agent {
        profile.request = None;
        profile.response = None;
    }
    // Closed dispatch precedes every credential/repository lookup, including
    // direct backend calls that do not pass through protocol discovery.
    let operation =
        operation(&backend.options, name).ok_or(ToolError::invalid("tool_not_granted"))?;
    let key = if is_write(operation) || operation == OUTCOMES_READ {
        mutations::key(args)?
    } else {
        IdempotencyKey::new(b"agent-metadata-read-no-publication".to_vec())
            .map_err(|_| ToolError::failed("agent_authentication_unavailable"))?
    };
    let commitment = request_commitment(name, args)?;
    let profile = backend
        .agent
        .as_mut()
        .ok_or(ToolError::failed("agent_credential_unavailable"))?;
    profile.request = None;
    let timeout = fgit_cli::command_timeout_duration().min(Duration::from_secs(
        fgit_node::agent_credentials::MAX_REQUEST_SECONDS,
    ));
    let deadline = Instant::now() + timeout;
    let timeout = fgit_node::GitDaemonSessionTimeout::try_new(timeout)
        .map_err(|_| ToolError::failed("agent_authentication_unavailable"))?;
    let context = backend.node.command_request_context(Some(timeout));
    let mut request = backend
        .node
        .runtime()
        .block_on(backend.node.authenticate_agent_request_in(
            &context,
            &profile.bearer,
            &key,
            operation,
            commitment,
            INPUT_BYTES,
            OUTPUT_BYTES,
        ))
        .map_err(auth_error)?;
    request.constrain_deadline(deadline);
    request.check(INPUT_BYTES, 0).map_err(auth_error)?;
    profile.request = Some(request);
    let result = backend.call_granted(name, args);
    let request = backend
        .agent
        .as_mut()
        .and_then(|profile| profile.request.take())
        .ok_or(ToolError::failed("agent_authentication_unavailable"))?;
    // Native reads do not consume an authenticated session themselves, so their
    // returned data cannot escape after the request expires. For mutations an
    // expired reply preserves uncertainty; it never asserts non-publication.
    request
        .check(INPUT_BYTES, OUTPUT_BYTES)
        .map_err(|_| ToolError::failed("agent_request_expired"))?;
    if result.is_ok() {
        backend
            .agent
            .as_mut()
            .ok_or(ToolError::failed("agent_authentication_unavailable"))?
            .response = Some(request);
    }
    result
}

pub(super) fn response_checkpoint(
    profile: &Profile,
    output_bytes: u64,
) -> Result<(), &'static str> {
    if let Some(request) = &profile.response {
        request
            .check(INPUT_BYTES, output_bytes)
            .map_err(|_| "agent_response_expired_or_exhausted")?;
    }
    Ok(())
}

pub(super) fn session(
    backend: &NodeTools,
    key: IdempotencyKey,
) -> Result<LoopbackReceiveSession, ToolError> {
    let request = backend
        .agent
        .as_ref()
        .and_then(|profile| profile.request.as_ref())
        .ok_or(ToolError::failed("agent_request_required"))?;
    request.check(0, 0).map_err(auth_error)?;
    let session = request.authenticated_session();
    if session
        .authenticated_session()
        .is_none_or(|session| session.client_idempotency_key() != &key)
    {
        return Err(ToolError::invalid("agent_request_key_mismatch"));
    }
    Ok(session)
}

/// Structured source results must retain the verified request's sponsorship
/// and original deadline. A configured agent without an active call never
/// acquires the trusted-local source authority of an ordinary MCP launch.
pub(super) fn source_read_context(
    backend: &NodeTools,
) -> Result<fgit_node::source_retrieval::authorization::SourceReadContext, ToolError> {
    backend
        .agent
        .as_ref()
        .and_then(|profile| profile.request.as_ref())
        .ok_or(ToolError::failed("agent_request_required"))?
        .mcp_source_read_context(&backend.node)
        .map_err(auth_error)
}

#[cfg(test)]
mod tests;
