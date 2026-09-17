//! Bootstrap absent branches through the existing native root-commit engine.
//! The source gateway owns credentials and quotas; the node owns validation,
//! branch-absence admission, transaction identity, and terminal retry recovery.

mod output;
mod request;

use std::io::Read;
use fgit_forge::initial_commit::InitialCommitError;
use fgit_forge::patch::{PatchError, PatchLimits};
use fgit_wire::smart_http::{BodyFraming, HttpLimits};
use crate::{GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession,
    NodeWorkspaceRefusal, OneNode};
use crate::smart_http::drive_request_while;
use super::{Reply, read_error};
use super::super::{Status, issues::{ApiError, admission_error}, pulls::{read_source_upload, source_upload}};
use request::Command;
pub(super) use request::Request;
pub(super) use output::Prepared;

pub(super) fn execute(node: &OneNode, request: &Request<'_>, session: &LoopbackReceiveSession,
    framing: BodyFraming, reader: &mut impl Read, limits: HttpLimits, maximum_response: u64,
) -> Result<Reply, ApiError> {
    let authenticated = session.authenticated_session()
        .ok_or_else(|| ApiError::new(Status::Unauthorized, "unauthorized"))?;
    // No provisional part can stage objects. Complete fixed/chunked HTTP
    // framing precedes MIME parsing, native preparation and all publication.
    let bytes = read_source_upload(reader, framing, limits, request.kind())?;
    let context = node.request_context();
    let deadline = GitDaemonSessionDeadline::new(node.git_daemon_session_timeout, GitDaemonSessionWorkScaling::FLAT);
    let mut live = || !deadline.expired();
    let (form, payload) = source_upload(&bytes, request.boundary, request.kind(), &mut live)?;
    let command = request.command(form, node.object_format)?;
    let maximum = usize::try_from(maximum_response).unwrap_or(usize::MAX);
    match command {
        Command::Prepare { reference, metadata, expected_head } => {
            let (head, plan, bundle) = drive_request_while(node, &context,
                node.prepare_trusted_initial_patch_in(&context, &reference, payload, &metadata,
                    PatchLimits::default(), expected_head), &mut live).map_err(preparation_error)?;
            drop(bytes);
            output::prepared(node, &reference, head, plan, bundle, maximum, &mut live).map(Reply::initial)
        }
        Command::Apply { reference, candidate } => {
            // A terminal retry deliberately precedes current branch-presence
            // and object checks inside the native publisher. No pre-read here
            // may reinterpret the original expected-absent command as an update.
            let result = drive_request_while(node, &context,
                node.apply_initial_patch_bundle_durable_in(&context, session, &reference,
                    candidate, payload, Default::default()), &mut live).map_err(publication_error)?;
            output::publication(node, authenticated.principal_id(), &reference, candidate, result, maximum)
                .map(Reply::json)
        }
    }
}

fn preparation_error(error: NodeWorkspaceRefusal) -> ApiError {
    match error {
        NodeWorkspaceRefusal::InvalidWorkspaceCandidate("initial commit preparation snapshot moved") =>
            ApiError::new(Status::Conflict, "source_snapshot_moved"),
        NodeWorkspaceRefusal::InvalidWorkspaceCandidate("initial commit destination branch already exists") =>
            ApiError::new(Status::Conflict, "branch_already_exists"),
        NodeWorkspaceRefusal::InvalidWorkspaceCandidate(_) => ApiError::bad("invalid_initial_candidate"),
        NodeWorkspaceRefusal::InitialCommit(error) => match error {
            InitialCommitError::Patch(PatchError::Cancelled) => ApiError::from_status(Status::Timeout, false),
            InitialCommitError::Budget(_) | InitialCommitError::Patch(PatchError::Budget(_)) => ApiError::too_large(),
            InitialCommitError::CreationRequired => ApiError::bad("creation_only_patch_required"),
            InitialCommitError::IdentityCollision | InitialCommitError::InvalidTree => ApiError::unavailable(),
            _ => ApiError::bad("invalid_initial_patch"),
        },
        error => read_error(error),
    }
}
fn publication_error(error: NodeWorkspaceRefusal) -> ApiError {
    match error {
        NodeWorkspaceRefusal::WorkspacePublication(error) => admission_error(*error),
        // These are native pre-admission shape/visibility checks, not decisions.
        NodeWorkspaceRefusal::InvalidWorkspaceCandidate(_) => ApiError::bad("invalid_initial_candidate"),
        NodeWorkspaceRefusal::ObjectFormatMismatch => ApiError::bad("object_format_mismatch"),
        NodeWorkspaceRefusal::RefUnavailable => ApiError::not_found(),
        // An awaited store failure or cancellation cannot establish rollback.
        _ => ApiError::unknown(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_construction_has_no_transaction_but_interrupted_publication_is_unknown() {
        for error in [NodeWorkspaceRefusal::InitialCommit(InitialCommitError::CreationRequired),
            NodeWorkspaceRefusal::InitialCommit(InitialCommitError::Patch(PatchError::Cancelled)),
            NodeWorkspaceRefusal::InvalidWorkspaceCandidate("initial commit preparation snapshot moved")]
        {
            assert!(!preparation_error(error).outcome_unknown);
        }
        assert!(publication_error(NodeWorkspaceRefusal::Cancelled { exhaustion: None }).outcome_unknown);
        assert!(!publication_error(NodeWorkspaceRefusal::InvalidWorkspaceCandidate("initial commit has a parent")).outcome_unknown);
    }
}
