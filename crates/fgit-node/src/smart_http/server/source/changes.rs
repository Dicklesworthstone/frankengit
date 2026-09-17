//! Read -> exact patch -> unstaged bundle -> inspection -> conditional source
//! publication. These are existing native engines, not a gateway worktree or
//! a second publication path. Authentication and deployment gates precede intake.

mod request;
mod output;

use std::io::Read;
use fgit_forge::patch::{PatchError, PatchLimits};
use fgit_forge::review::ReviewOptions;
use fgit_wire::smart_http::{BodyFraming, HttpLimits};
use fgit_wire::visibility::RefVisibility;
use crate::{GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession,
    NodeWorkspaceRefusal, OneNode};
use crate::smart_http::drive_request_while;
use super::{Reply, read_error};
use super::super::{Status, issues::{ApiError, Reply as JsonReply, admission_error}};
use super::super::pulls::{read_source_upload, source_upload};
use request::{Command, Operation};
pub(super) use request::Request;
pub(super) use output::PatchReply;

pub(super) fn execute(node: &OneNode, request: &Request<'_>, session: &LoopbackReceiveSession,
    framing: BodyFraming, reader: &mut impl Read, limits: HttpLimits, maximum_response: u64,
) -> Result<Reply, ApiError> {
    let authenticated = session.authenticated_session()
        .ok_or_else(|| ApiError::new(Status::Unauthorized, "unauthorized"))?;
    // Finish HTTP framing before parsing provisional MIME parts or entering an
    // engine. Socket ingress has its own deadline; this is the server-work phase.
    let bytes = read_source_upload(reader, framing, limits, request.kind())?;
    let context = node.request_context();
    let deadline = GitDaemonSessionDeadline::new(node.git_daemon_session_timeout, GitDaemonSessionWorkScaling::FLAT);
    let mut live = || !deadline.expired();
    let (form, payload) = source_upload(&bytes, request.boundary, request.kind(), &mut live)?;
    let command = request.command(form, node.object_format)?;
    let maximum = usize::try_from(maximum_response).unwrap_or(usize::MAX);
    match command {
        Command::Prepare { reference, base, metadata } => {
            let candidate = drive_request_while(node, &context,
                node.prepare_trusted_patch_in(&context, &reference, base,
                    *authenticated.principal_id().as_bytes(), payload, &metadata, PatchLimits::default()), &mut live)
                .map_err(preparation_error)?;
            // The input lifetime ends before output framing. The native bundle
            // stays owned by its candidate, not copied into a response buffer.
            drop(bytes);
            output::prepared(node, &reference, base, candidate, maximum, &mut live).map(Reply::Patch)
        }
        Command::Candidate { reference, base, candidate } if request.operation == Operation::Inspect => {
            let inspected = drive_request_while(node, &context,
                node.inspect_workspace_bundle_in(&context, &reference, base, candidate, payload,
                    &RefVisibility::new(), None, &ReviewOptions::default()), &mut live)
                // The inspector's evidence failures never turn into an empty
                // diff or an invented approval. No transaction was attempted.
                .map_err(|_| ApiError::unavailable())?;
            drop(bytes);
            let body = output::inspection(node, &reference, base, candidate, &inspected.review,
                &inspected.parents, &inspected.candidate_commit_body, &inspected.bundle_sha256,
                inspected.bundle_bytes, maximum, &mut live)?;
            Ok(Reply::Json(JsonReply { status: Status::Success, body, terminal: None }))
        }
        Command::Candidate { reference, base, candidate } if request.operation == Operation::Apply => {
            // No preliminary freshness read can replace canonical expected-old
            // admission. In particular, identical terminal retries must recover
            // after the branch moves. The native publisher owns quarantine,
            // single-parent validation, policy, seal and exact-predecessor CAS.
            let result = drive_request_while(node, &context,
                node.apply_workspace_bundle_durable_in(&context, authenticated.principal_id(),
                    authenticated.client_idempotency_key().as_bytes(), &reference, base, candidate, payload), &mut live)
                .map_err(|error| match error {
                    NodeWorkspaceRefusal::WorkspacePublication(error) => admission_error(*error),
                    // After entry, infrastructure and cancellation never prove
                    // non-commit; the independent key lookup is the recovery path.
                    _ => ApiError::unknown(),
                })?;
            output::publication(node, authenticated.principal_id(), &reference, base, candidate, result, maximum)
                .map(Reply::Json)
        }
        _ => Err(ApiError::bad("source_operation_mismatch")),
    }
}

fn preparation_error(error: NodeWorkspaceRefusal) -> ApiError {
    match error {
        NodeWorkspaceRefusal::StaleWorkspaceBase => ApiError::new(Status::Conflict, "source_commit_moved"),
        NodeWorkspaceRefusal::InvalidWorkspaceCandidate(_) => ApiError::bad("invalid_source_patch"),
        NodeWorkspaceRefusal::UnsupportedWorkspaceEdit => ApiError::bad("unsupported_source_edit"),
        NodeWorkspaceRefusal::WorkspacePatch(error) => match error {
            PatchError::Cancelled => ApiError::from_status(Status::Timeout, false),
            PatchError::Budget(_) => ApiError::too_large(),
            PatchError::ContextMismatch { .. } => ApiError::new(Status::Conflict, "patch_context_mismatch"),
            PatchError::SourcePresence | PatchError::SourceMode | PatchError::SourceRange { .. } =>
                ApiError::new(Status::Conflict, "patch_source_mismatch"),
            _ => ApiError::bad("invalid_source_patch"),
        },
        error => read_error(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_patch_construction_is_not_a_canonical_mutation_refusal() {
        for error in [NodeWorkspaceRefusal::StaleWorkspaceBase,
            NodeWorkspaceRefusal::WorkspacePatch(PatchError::ContextMismatch { hunk: 1, source_line: 2 }),
            NodeWorkspaceRefusal::WorkspacePatch(PatchError::Budget("output")),
            NodeWorkspaceRefusal::WorkspacePatch(PatchError::Cancelled)]
        {
            let error = preparation_error(error);
            assert!(!error.outcome_unknown);
            let mut body = Vec::new();
            error.send_named(&mut body, fgit_wire::smart_http::HttpVersion::Http11, "source_error").unwrap();
            assert!(!String::from_utf8(body).unwrap().contains("\"outcome\":\"refused\""));
        }
    }
}
