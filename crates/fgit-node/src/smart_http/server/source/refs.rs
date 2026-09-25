//! Reference discovery and branch lifecycle through existing native engines.
//! No transport-local refs, object uploads, default-branch rewrite or forge
//! transitions. The shared source gateway owns authentication and quotas.

mod output;
mod request;

use std::io::Read;

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
    pub(super) const fn route(&self) -> &str {
        self.0.repository_route
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
    let authenticated = session
        .authenticated_session()
        .ok_or_else(|| ApiError::new(Status::Unauthorized, "unauthorized"))?;
    // Authentication, scope/deployment ceilings and quota precede intake in
    // the parent gateway. Complete HTTP framing precedes ANY authority work.
    let command = request
        .0
        .command(&read_form(reader, framing, limits)?, node.object_format)?;
    let deadline = GitDaemonSessionDeadline::new(
        node.git_daemon_session_timeout,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let context = node.session_request_context(&deadline);
    let mut live = || !deadline.expired();
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
        Command::Mutate(commands) => {
            // The node checks current visibility and commit kind, preserves
            // the default branch, constructs real empty-pack quarantine proof,
            // then submits ONE atomic request to canonical policy/seal/CAS.
            // Do not read/refresh tips here: terminal retries must also work
            // after source deletion, branch movement, or a node restart.
            let result = drive_request_while(
                node,
                &context,
                node.admit_branch_updates_durable_in(
                    &context,
                    session,
                    &commands,
                    Default::default(),
                ),
                &mut live,
            )
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
