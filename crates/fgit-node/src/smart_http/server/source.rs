//! Authenticated repository-wide source reads. The gateway grants exactly the
//! selected repository's read scope before invoking the native local-owner
//! readers. No caller-controlled path/OID creates authority or a host path.

mod request;
mod output;

use std::io::Read;
use fgit_authority::IdempotencyKey;
use fgit_forge::source_browse::SourceBrowseError;
use fgit_forge::source_search::SearchError;
use fgit_treefs::BaseError;
use fgit_wire::smart_http::{BodyFraming, HttpLimits, Service, head::Envelope};
use crate::{GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession,
    NodeWorkspaceRefusal, OneNode};
use crate::smart_http::drive_request_while;
use super::{Profile, Status, retry_key};
use super::issues::{ApiError, Reply, read_form};
use request::Command;
pub(super) use request::Request;

pub(super) fn authenticate(request: &Request<'_>, envelope: &Envelope<'_>,
    raw_head: &[u8], profile: &Profile,
) -> Result<LoopbackReceiveSession, ApiError> {
    let grant = profile.credentials.authenticate(envelope.authorization())
        .map_err(|error| ApiError::from_status(Status::from(error), false))?;
    if request.repository_route.as_bytes() != profile.route { return Err(ApiError::not_found()); }
    if !profile.allow_source || !grant.permits(Service::UploadPack) {
        return Err(ApiError::new(Status::Forbidden, "forbidden"));
    }
    if retry_key(raw_head).map_err(|_| ApiError::bad("invalid_idempotency_key"))?.is_some() {
        return Err(ApiError::bad("source_read_has_no_transaction_key"));
    }
    // This identity is transport-local and never reaches any seal/key binder.
    Ok(LoopbackReceiveSession::authenticated(grant.principal,
        IdempotencyKey::new(b"read-only-source-query".to_vec()).map_err(|_| ApiError::unavailable())?))
}

pub(super) fn execute(node: &OneNode, request: &Request<'_>, session: &LoopbackReceiveSession,
    framing: BodyFraming, reader: &mut impl Read, http: HttpLimits, maximum_response: u64,
) -> Result<Reply, ApiError> {
    if session.authenticated_session().is_none() { return Err(ApiError::new(Status::Unauthorized, "unauthorized")); }
    let command = request.command(&read_form(reader, framing, http)?, node.object_format)?;
    let context = node.request_context();
    let deadline = GitDaemonSessionDeadline::new(node.git_daemon_session_timeout, GitDaemonSessionWorkScaling::FLAT);
    let mut live = || !deadline.expired();
    let maximum = usize::try_from(maximum_response).unwrap_or(usize::MAX).min(output::MAX_REPLY_BYTES);
    // Native readers derive path grants from the SAME verified selected tree.
    // This operator-managed profile grants whole-repository reads, not a remote
    // agent's sparse capability. Current canonical hidden refs still apply.
    let body = match &command {
        Command::Browse { selection, query } => {
            let report = drive_request_while(node, &context,
                node.browse_source_local_in(&context, &selection.reference, query), &mut live)
                .map_err(read_error)?;
            output::browse(node, selection, query, &report, maximum, &mut live)?
        }
        Command::Search { selection, query, limits } => {
            let (head, report) = drive_request_while(node, &context,
                node.search_source_snapshot_local_in(&context, &selection.reference,
                    selection.expected_head, selection.expected_commit, query, *limits), &mut live)
                .map_err(read_error)?;
            output::search(node, selection, query, *limits, head, &report, maximum, &mut live)?
        }
    };
    Ok(Reply { status: Status::Success, body, terminal: None })
}

fn base_error(error: BaseError) -> ApiError {
    match error {
        BaseError::NotFound { .. } => ApiError::not_found(),
        BaseError::NotADirectory { .. } => ApiError::new(Status::Conflict, "not_a_directory"),
        BaseError::SymlinkTraversal { .. } => ApiError::new(Status::Conflict, "symlink_not_followed"),
        BaseError::Path(_) => ApiError::bad("invalid_repository_path"),
        // A missing/corrupt required object is not a nonexistent user path.
        _ => ApiError::unavailable(),
    }
}
fn read_error(error: NodeWorkspaceRefusal) -> ApiError {
    match error {
        NodeWorkspaceRefusal::RefUnavailable => ApiError::not_found(),
        NodeWorkspaceRefusal::CommitRequired => ApiError::new(Status::Conflict, "ref_does_not_select_commit"),
        NodeWorkspaceRefusal::ObjectFormatMismatch => ApiError::bad("object_format_mismatch"),
        NodeWorkspaceRefusal::Cancelled { exhaustion: Some(_) } => ApiError::too_large(),
        NodeWorkspaceRefusal::Cancelled { exhaustion: None } => ApiError::from_status(Status::Timeout, false),
        NodeWorkspaceRefusal::SourceBrowse(error) => match *error {
            SourceBrowseError::InvalidRequest(_) => ApiError::bad("invalid_browse_query"),
            SourceBrowseError::SnapshotMoved => ApiError::new(Status::Conflict, "source_snapshot_moved"),
            SourceBrowseError::CommitMoved => ApiError::new(Status::Conflict, "source_commit_moved"),
            SourceBrowseError::ExpectedFile => ApiError::new(Status::Conflict, "not_a_file"),
            SourceBrowseError::RangeOutsideFile => ApiError::bad("range_outside_file"),
            SourceBrowseError::Budget(_) => ApiError::too_large(),
            SourceBrowseError::Base(error) => base_error(*error),
            _ => ApiError::unavailable(),
        },
        NodeWorkspaceRefusal::SourceSearch(error) => match *error {
            SearchError::InvalidQuery | SearchError::InvalidLimits | SearchError::InvalidObjectFormat => ApiError::bad("invalid_search_query"),
            SearchError::Cancelled => ApiError::from_status(Status::Timeout, false),
            SearchError::Budget(_) => ApiError::too_large(),
            SearchError::Base(error) => base_error(*error),
            _ => ApiError::unavailable(),
        },
        _ => ApiError::unavailable(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn read_failures_never_imply_mutation_ambiguity_or_complete_empty_results() {
        for error in [NodeWorkspaceRefusal::RefUnavailable, NodeWorkspaceRefusal::CommitRequired,
            NodeWorkspaceRefusal::Cancelled { exhaustion: None },
            NodeWorkspaceRefusal::SourceSearch(Box::new(SearchError::Budget("files"))),
            NodeWorkspaceRefusal::SourceBrowse(Box::new(SourceBrowseError::SnapshotMoved))]
        {
            let error = read_error(error);
            assert!(!error.outcome_unknown);
            let mut reply = Vec::new();
            error.send_named(&mut reply, fgit_wire::smart_http::HttpVersion::Http11, "source_error").unwrap();
            let text = String::from_utf8(reply).unwrap();
            assert!(!text.contains("\"matches\":[]") && !text.contains("\"outcome\":\"refused\""));
        }
    }
}
