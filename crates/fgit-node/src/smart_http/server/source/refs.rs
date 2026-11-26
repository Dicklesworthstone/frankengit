//! Reference discovery and branch lifecycle through existing native engines.
//! No transport-local refs, object uploads, default-branch rewrite or forge
//! transitions. The shared source gateway owns authentication and quotas.

mod cursor;
mod output;
mod request;
mod transaction;

use std::io::Read;

use fgit_authority::{ExpectedOld, ProposedNew, RefCommand};
use fgit_wire::smart_http::{BodyFraming, HttpLimits, head::Envelope};
use fgit_wire::visibility::RefVisibility;

use super::super::Status;
use super::super::issues::{ApiError, Reply, admission_error, read_form};
use crate::smart_http::drive_request_while;
use crate::{
    GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession,
    NodeWorkspaceRefusal, OneNode,
};
use request::{Command, Namespace};
use transaction::WriterScope;

/// The parent source router needs only route, mutation class, and execution;
/// the command grammar and atomic lowering stay private to this adapter.
#[derive(Debug)]
pub(super) struct Request<'a>(request::Request<'a>);
impl<'a> Request<'a> {
    pub(super) fn parse(envelope: &Envelope<'a>) -> Result<Option<Self>, ApiError> {
        request::Request::parse(envelope).map(|request| request.map(Self))
    }
    pub(super) fn is_mutation(&self) -> bool {
        self.0.is_mutation()
    }
    pub(super) const fn is_create(&self) -> bool {
        matches!(self.0.operation, request::Operation::Create)
    }
    pub(super) const fn route(&self) -> &str {
        self.0.repository_route
    }
}

pub(super) fn execute(
    node: &OneNode,
    request: &Request<'_>,
    session: &LoopbackReceiveSession,
    agent_request: Option<&crate::agent_credentials::AgentRequest>,
    framing: BodyFraming,
    reader: &mut impl Read,
    limits: HttpLimits,
    maximum_response: u64,
    admission_deadline: &GitDaemonSessionDeadline,
) -> Result<Reply, ApiError> {
    let authenticated = session
        .authenticated_session()
        .ok_or_else(|| ApiError::new(Status::Unauthorized, "unauthorized"))?;
    let creation_request = match authenticated.authentication() {
        fgit_admission::evidence::AdmissionAuthentication::AgentCredential(authentication)
            if request.is_mutation() =>
        {
            if !request.is_create() {
                return Err(ApiError::new(Status::Forbidden, "branch_creation_required"));
            }
            let agent = agent_request
                .filter(|agent| {
                    agent.authentication == authentication
                        && authentication.agent() == authenticated.principal_id()
                        && Some(agent.deadline()) == authenticated.agent_deadline
                })
                .ok_or_else(|| ApiError::new(Status::Forbidden, "source_grant_required"))?;
            let creation = agent.source_branch_creation(node).map_err(|_| {
                ApiError::new(Status::Forbidden, "branch_creation_grant_unavailable")
            })?;
            if creation.key() != authenticated.client_idempotency_key() {
                return Err(ApiError::new(
                    Status::Forbidden,
                    "branch_creation_key_mismatch",
                ));
            }
            Some(creation)
        }
        _ => None,
    };
    // Authentication, scope/deployment ceilings and quota precede intake in
    // the parent gateway. Complete HTTP framing precedes ANY authority work.
    let bytes = read_form(reader, framing, limits)?;
    if let Some(creation) = &creation_request {
        // Reserve the complete form, not only the target ref and object ID.
        // This checkpoint precedes all publication and is never ambiguous.
        creation
            .check_input(bytes.len())
            .map_err(creation_input_error)?;
    }
    let deadline = if authenticated.authentication().agent_provenance().is_some() {
        admission_deadline.clone()
    } else {
        GitDaemonSessionDeadline::new(
            node.git_daemon_session_timeout,
            GitDaemonSessionWorkScaling::FLAT,
        )
    };
    let context = node.authenticated_session_request_context(&deadline, session);
    let mut live = || {
        !deadline.expired()
            && context.is_live()
            && creation_request
                .as_ref()
                .is_none_or(|request| request.check_context(node, &context).is_ok())
    };
    if !live() {
        return Err(ApiError::from_status(Status::Timeout, false));
    }
    let command = request.0.command(&bytes, node.object_format)?;
    let maximum = usize::try_from(maximum_response)
        .unwrap_or(usize::MAX)
        .min(output::MAX_REPLY_BYTES);
    match command {
        Command::List(page) => {
            let visibility = RefVisibility::new();
            let read = async {
                match page.namespace {
                    Namespace::All => {
                        node.list_refs_in(
                            &context,
                            &visibility,
                            page.after.as_ref(),
                            page.limit,
                            page.expected_head,
                        )
                        .await
                    }
                    Namespace::Branches => {
                        node.list_branch_refs_in(
                            &context,
                            &visibility,
                            page.after.as_ref(),
                            page.limit,
                            page.expected_head,
                        )
                        .await
                    }
                    Namespace::Tags => {
                        node.list_tag_refs_in(
                            &context,
                            &visibility,
                            page.after.as_ref(),
                            page.limit,
                            page.expected_head,
                        )
                        .await
                    }
                }
            };
            let (head, rows, next) = drive_request_while(node, &context, read, &mut live).map_err(
                |error| match error {
                    NodeWorkspaceRefusal::BranchOperation("reference snapshot moved") => {
                        ApiError::new(Status::Conflict, "source_snapshot_moved")
                    }
                    error => super::read_error(error),
                },
            )?;
            let body = output::page(node, &page, head, &rows, next.as_ref(), maximum, &mut live)?;
            Ok(Reply {
                status: Status::Success,
                body,
                terminal: None,
            })
        }
        Command::Mutate {
            commands,
            expected_scope,
        } => {
            // The assertion only constrains the already-authenticated writer.
            // Check it before creating any native transaction or seal.
            if let Some(expected) = expected_scope
                && expected
                    != (WriterScope {
                        tenant: node.tenant_id(),
                        repository: node.repository_id(),
                        incarnation: node.repository_incarnation_id(),
                        principal: authenticated.principal_id(),
                    })
            {
                return Err(ApiError::new(
                    Status::Forbidden,
                    "branch_transaction_scope_mismatch",
                ));
            }
            super::super::require_ref_writes(authenticated, commands.iter().map(|c| &c.name))?;
            // The node checks current visibility and commit kind, preserves
            // the default branch, constructs real empty-pack quarantine proof,
            // then submits ONE atomic request to canonical policy/seal/CAS.
            // Do not read/refresh tips here: terminal retries must also work
            // after source deletion, branch movement, or a node restart.
            let result = if let Some(creation) = &creation_request {
                let [
                    RefCommand {
                        name,
                        expected_old: ExpectedOld::Absent,
                        proposed_new: ProposedNew::Update(target),
                        force: false,
                    },
                ] = commands.as_slice()
                else {
                    return Err(ApiError::new(Status::Forbidden, "branch_creation_required"));
                };
                // Only the native scoped entrypoint can prove the target is a
                // current visible branch tip and recheck it in each CAS basis.
                // A retained object ID or source-publish grant is insufficient.
                drive_request_while(
                    node,
                    &context,
                    node.create_agent_branch_in(
                        &context,
                        creation,
                        name,
                        *target,
                        Default::default(),
                    ),
                    &mut live,
                )
            } else {
                drive_request_while(
                    node,
                    &context,
                    async {
                        if request.0.operation == request::Operation::Transaction {
                            node.admit_branch_transaction_durable_in(
                                &context,
                                session,
                                &commands,
                                Default::default(),
                            )
                            .await
                        } else {
                            node.admit_branch_updates_durable_in(
                                &context,
                                session,
                                &commands,
                                Default::default(),
                            )
                            .await
                        }
                    },
                    &mut live,
                )
            }
            .map_err(publication_error)?;
            // No post-decision timeout/freshness read can overwrite the result.
            output::publication(
                node,
                authenticated.principal_id(),
                request.0.operation,
                &commands,
                &result,
                maximum,
            )
        }
    }
}

fn creation_input_error(error: NodeWorkspaceRefusal) -> ApiError {
    if let NodeWorkspaceRefusal::WorkspacePublication(error) = error
        && let crate::NodeReceiveTransportRefusal::Admission(error) = *error
        && matches!(
            *error,
            fgit_admission::AdmissionError::AsyncProjectionUnavailable(
                fgit_types::RefusalCode::ResourceBudgetExceeded
            )
        )
    {
        return ApiError::too_large();
    }
    ApiError::new(Status::Forbidden, "branch_creation_grant_unavailable")
}

fn publication_error(error: NodeWorkspaceRefusal) -> ApiError {
    match error {
        NodeWorkspaceRefusal::WorkspacePublication(source) => admission_error(*source),
        NodeWorkspaceRefusal::RefUnavailable => ApiError::not_found(),
        NodeWorkspaceRefusal::BranchOperation(_) => {
            ApiError::new(Status::Conflict, "branch_operation_refused")
        }
        NodeWorkspaceRefusal::CommitRequired => {
            ApiError::new(Status::Conflict, "branch_target_not_commit")
        }
        NodeWorkspaceRefusal::ObjectFormatMismatch => ApiError::bad("object_format_mismatch"),
        // A failed awaited authority call may already have published. Never
        // translate storage, timeout or cancellation into a fabricated refusal.
        _ => ApiError::unknown(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preflight_refusals_and_ambiguous_authority_work_are_not_conflated() {
        for error in [
            NodeWorkspaceRefusal::RefUnavailable,
            NodeWorkspaceRefusal::CommitRequired,
            NodeWorkspaceRefusal::BranchOperation("default branch"),
            NodeWorkspaceRefusal::ObjectFormatMismatch,
        ] {
            assert!(!publication_error(error).outcome_unknown);
        }
        assert!(
            publication_error(NodeWorkspaceRefusal::Cancelled { exhaustion: None }).outcome_unknown
        );
    }
}
