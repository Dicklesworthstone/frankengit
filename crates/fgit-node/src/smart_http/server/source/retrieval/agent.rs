//! Agent Protocol documents through the existing authenticated source gateway.
//! Form fields select data and finite bounds; they cannot choose a principal,
//! grant, run identity, durable state or publication capability.
use super::{
    ApiError, BTreeMap, BodyFraming, GitDaemonSessionDeadline, GitDaemonSessionWorkScaling,
    GitHashAlgorithm, HttpLimits, JsonReply, OneNode, Read, SourceReadContext, Status, context,
    drive_request_while, parse_form, positive, read_form,
};
use crate::source_retrieval::agent_context::AgentContextReadError;
use crate::source_retrieval::agent_context::document::{
    AgentContextDocumentError, AgentContextRequest, MAX_LIFETIME, MAX_OUTPUT_BYTES,
    read_agent_context_in,
};
use crate::{GitDaemonSessionTimeout, NodeRequestContext};
use fgit_types::PrincipalId;
use std::time::Duration;

struct AgentCommand {
    context: context::ContextCommand,
    expires_after: Duration,
    max_output_bytes: usize,
}

fn command_fields(
    parsed: Vec<(String, String)>,
    format: GitHashAlgorithm,
    maximum: usize,
) -> Result<AgentCommand, ApiError> {
    if parsed.len() > 199 {
        return Err(ApiError::too_large());
    }
    let maximum = maximum.min(MAX_OUTPUT_BYTES);
    if maximum == 0 {
        return Err(ApiError::too_large());
    }
    let mut fields = BTreeMap::new();
    let mut context = Vec::new();
    for (name, value) in parsed {
        match name.as_str() {
            "expires_after_secs" | "max_output_bytes" => {
                if fields.insert(name, value).is_some() {
                    return Err(ApiError::bad("duplicate_field"));
                }
            }
            "expected_commit" => {
                return Err(ApiError::bad("unsupported_agent_context_precondition"));
            }
            "sponsor" | "sponsor_id" | "principal" | "principal_id" | "run_id" => {
                return Err(ApiError::bad("caller_selected_agent_identity"));
            }
            _ => context.push((name, value)),
        }
    }
    let expires_after = positive(
        &mut fields,
        "expires_after_secs",
        30,
        MAX_LIFETIME.as_secs(),
    )?;
    let max_output_bytes = positive(
        &mut fields,
        "max_output_bytes",
        maximum as u64,
        MAX_OUTPUT_BYTES as u64,
    )? as usize;
    // A caller-selected allowance is never silently enlarged or reduced.
    // The absent field selects this host's own finite response ceiling.
    if max_output_bytes > maximum {
        return Err(ApiError::too_large());
    }
    let context = context::command_fields(context, format)?;
    if context.ranked {
        return Err(ApiError::bad("unsupported_agent_context_selection"));
    }
    Ok(AgentCommand {
        context,
        expires_after: Duration::from_secs(expires_after),
        max_output_bytes,
    })
}

pub(super) fn execute(
    node: &OneNode,
    read: &SourceReadContext,
    framing: BodyFraming,
    reader: &mut impl Read,
    http: HttpLimits,
    maximum: u64,
) -> Result<JsonReply, ApiError> {
    let sponsor = read.principal().ok_or_else(|| {
        ApiError::new(Status::Forbidden, "agent_context_read_credential_required")
    })?;
    let maximum = usize::try_from(maximum)
        .unwrap_or(usize::MAX)
        .min(super::super::output::MAX_REPLY_BYTES);
    let fields = parse_form(&read_form(reader, framing, http)?, 199)?;
    let command = command_fields(fields, node.object_format, maximum)?;
    let body = run(node, read, sponsor, &command)?;
    Ok(JsonReply {
        status: Status::Success,
        body,
        terminal: None,
    })
}

/// The real HTTP `source/agent-context` grammar and implementation for a
/// separately authorized in-process host. `fields` omit `object_format`, which
/// comes from the selected node. An HTTP read context binds sponsorship to its
/// principal; trusted-local hosts must first check their explicit launch grant
/// and supply the launch-bound sponsor. Caller fields cannot choose either.
/// The result is a buffered read-only document, never a reusable credential.
pub fn source_agent_context_json(
    node: &OneNode,
    read: &SourceReadContext,
    sponsor: PrincipalId,
    mut fields: Vec<(String, String)>,
    maximum: usize,
) -> Result<String, &'static str> {
    read.check_node(node)
        .map_err(|_| "source_read_context_mismatch")?;
    if fields.iter().any(|(name, _)| name == "object_format") {
        return Err("unknown_initial_field");
    }
    fields.push(("object_format".into(), node.object_format.as_str().into()));
    command_fields(fields, node.object_format, maximum)
        .and_then(|command| run(node, read, sponsor, &command))
        .map_err(|error| error.code)
}

fn run(
    node: &OneNode,
    read: &SourceReadContext,
    sponsor: PrincipalId,
    command: &AgentCommand,
) -> Result<String, ApiError> {
    read.check_node(node)
        .map_err(|_| ApiError::new(Status::Forbidden, "source_read_context_mismatch"))?;
    if read
        .principal()
        .is_some_and(|principal| principal != sponsor)
    {
        return Err(ApiError::new(
            Status::Forbidden,
            "agent_context_sponsor_mismatch",
        ));
    }
    let expires_after = command
        .expires_after
        .min(node.git_daemon_session_timeout.duration());
    let timeout = GitDaemonSessionTimeout::try_new(expires_after)
        .map_err(|_| ApiError::bad("invalid_agent_context_lifetime"))?;
    let deadline = GitDaemonSessionDeadline::new(timeout, GitDaemonSessionWorkScaling::FLAT);
    let request = node.session_request_context(&deadline);
    let mut live = || !deadline.expired();
    let context = &command.context;
    drive_request_while(
        node,
        &request,
        read_agent_context_in(
            node,
            &request,
            AgentContextRequest {
                authorization: read,
                reference: &context.initial.selection.reference,
                query: &context.initial.query,
                checkpoints: &context.initial.checkpoints,
                retrieval_limits: context.initial.limits,
                context_limits: context.limits,
                sponsor,
                expected_head: context.initial.selection.expected_head,
                expires_after,
                max_output_bytes: command.max_output_bytes,
            },
        ),
        &mut live,
    )
    .map(|document| document.json)
    .map_err(|error| failure(error, &request))
}

fn failure(error: AgentContextDocumentError, request: &NodeRequestContext) -> ApiError {
    match error {
        AgentContextDocumentError::SponsorAuthorization => {
            ApiError::new(Status::Forbidden, "agent_context_sponsor_mismatch")
        }
        AgentContextDocumentError::InvalidInput(_) => {
            ApiError::bad("invalid_agent_context_request")
        }
        AgentContextDocumentError::AuthorityHeadChanged => {
            ApiError::new(Status::Conflict, "source_snapshot_moved")
        }
        AgentContextDocumentError::OutputLimit => ApiError::too_large(),
        AgentContextDocumentError::Interrupted => match crate::source_retrieval::live(request) {
            Err(error) => super::evidence_failure(error),
            Ok(()) => ApiError::from_status(Status::Timeout, false),
        },
        AgentContextDocumentError::Expired
        | AgentContextDocumentError::Native(AgentContextReadError::RunExpired) => {
            ApiError::from_status(Status::Timeout, false)
        }
        AgentContextDocumentError::Native(AgentContextReadError::Retrieval(error)) => {
            super::evidence_failure(error)
        }
        _ => {
            // An authority or evidence error can carry request interruption.
            // Preserve native budget exhaustion as a resource refusal rather
            // than conflating every stopped request with a wall-clock timeout.
            match crate::source_retrieval::live(request) {
                Err(error) => super::evidence_failure(error),
                Ok(()) => ApiError::new(Status::Unavailable, "agent_context_unavailable"),
            }
        }
    }
}

#[cfg(test)]
mod tests;
