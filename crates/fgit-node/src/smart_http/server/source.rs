//! Repository source reads, ref lifecycle and exact candidate operations.
//! Read grants never imply publication. Branch/tag mutation and bundle
//! application require receive scope and the explicit Git-write switch.

mod artifact;
mod bundles;
mod changes;
mod historical;
mod history;
mod indexed;
mod initial;
mod output;
mod rebase;
mod refs;
mod regex;
mod replay;
mod request;
mod retrieval;
pub use indexed::source_index_json;
pub use retrieval::{source_agent_context_json, source_retrieval_json};
pub(super) mod review;
mod symbols;
mod tags;
mod verified_blob;

use super::issues::{ApiError, Reply as JsonReply, read_form};
use super::{Profile, Status, retry_key};
use crate::smart_http::drive_request_while;
use crate::{
    GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession,
    NodeWorkspaceRefusal, OneNode,
};
use fgit_authority::IdempotencyKey;
use fgit_forge::source_browse::SourceBrowseError;
use fgit_forge::source_search::SearchError;
use fgit_treefs::BaseError;
use fgit_wire::smart_http::{BodyFraming, HttpLimits, HttpVersion, Service, head::Envelope};
use request::Command;
use std::io::{self, Read, Write};

#[derive(Debug)]
pub(super) struct Request<'a>(RequestKind<'a>);
#[derive(Debug)]
enum RequestKind<'a> {
    Read(request::Request<'a>),
    Regex(regex::Request<'a>),
    Indexed(indexed::Request<'a>),
    Symbols(symbols::Request<'a>),
    Retrieval(retrieval::Request<'a>),
    Change(changes::Request<'a>),
    Refs(refs::Request<'a>),
    Tags(tags::Request<'a>),
    Initial(initial::Request<'a>),
    History(history::Request<'a>),
    Historical(historical::Request<'a>),
    Review(review::Request<'a>),
    Replay(replay::Request<'a>),
    Rebase(rebase::Request<'a>),
    Bundle(bundles::Request<'a>),
    VerifiedBlob(verified_blob::Request<'a>),
}
impl<'a> Request<'a> {
    pub(super) fn parse(envelope: &Envelope<'a>) -> Result<Self, ApiError> {
        if let Some(request) = verified_blob::Request::parse(envelope)? {
            return Ok(Self(RequestKind::VerifiedBlob(request)));
        }
        if let Some(request) = retrieval::Request::parse(envelope)? {
            return Ok(Self(RequestKind::Retrieval(request)));
        }
        if let Some(request) = symbols::Request::parse(envelope)? {
            return Ok(Self(RequestKind::Symbols(request)));
        }
        if let Some(request) = indexed::Request::parse(envelope)? {
            return Ok(Self(RequestKind::Indexed(request)));
        }
        if let Some(request) = regex::Request::parse(envelope)? {
            return Ok(Self(RequestKind::Regex(request)));
        }
        if let Some(request) = bundles::Request::parse(envelope)? {
            return Ok(Self(RequestKind::Bundle(request)));
        }
        if let Some(request) = historical::Request::parse(envelope)? {
            return Ok(Self(RequestKind::Historical(request)));
        }
        if let Some(request) = rebase::Request::parse(envelope)? {
            return Ok(Self(RequestKind::Rebase(request)));
        }
        if let Some(request) = replay::Request::parse(envelope)? {
            return Ok(Self(RequestKind::Replay(request)));
        }
        if let Some(request) = review::Request::parse(envelope)? {
            return Ok(Self(RequestKind::Review(request)));
        }
        if let Some(request) = history::Request::parse(envelope)? {
            return Ok(Self(RequestKind::History(request)));
        }
        if let Some(request) = initial::Request::parse(envelope)? {
            return Ok(Self(RequestKind::Initial(request)));
        }
        if let Some(request) = tags::Request::parse(envelope)? {
            return Ok(Self(RequestKind::Tags(request)));
        }
        if let Some(request) = refs::Request::parse(envelope)? {
            return Ok(Self(RequestKind::Refs(request)));
        }
        if let Some(request) = changes::Request::parse(envelope)? {
            return Ok(Self(RequestKind::Change(request)));
        }
        request::Request::parse(envelope).map(|request| Self(RequestKind::Read(request)))
    }
    pub(super) fn is_mutation(&self) -> bool {
        match &self.0 {
            RequestKind::Read(_)
            | RequestKind::History(_)
            | RequestKind::Historical(_)
            | RequestKind::Review(_)
            | RequestKind::Replay(_)
            | RequestKind::Regex(_)
            | RequestKind::Indexed(_)
            | RequestKind::Symbols(_)
            | RequestKind::Retrieval(_) => false,
            RequestKind::VerifiedBlob(_) => false,
            RequestKind::Bundle(request) => request.is_mutation(),
            RequestKind::Rebase(request) => request.is_mutation(),
            RequestKind::Change(request) => request.is_mutation(),
            RequestKind::Refs(request) => request.is_mutation(),
            RequestKind::Tags(request) => request.is_mutation(),
            RequestKind::Initial(request) => request.is_mutation(),
        }
    }
    /// Closed source-understanding profiles for sponsored credentials. Several
    /// other nonmutating routes prepare candidate objects or disclose historical
    /// bundles; classifying every read as source access would widen this grant.
    /// The current-commit reader belongs to the same ref-selected source surface
    /// as tree/blob; it cannot traverse parents or select an arbitrary object.
    pub(super) fn agent_operation(&self) -> Option<u16> {
        use fgit_identity::agent::{SOURCE_CANDIDATES, SOURCE_HISTORY_READ, SOURCE_READ};
        match &self.0 {
            RequestKind::Read(_)
            | RequestKind::Regex(_)
            | RequestKind::Indexed(_)
            | RequestKind::Symbols(_)
            | RequestKind::Retrieval(_) => Some(SOURCE_READ),
            RequestKind::Refs(request) => (!request.is_mutation()).then_some(SOURCE_READ),
            RequestKind::Tags(request) => (!request.is_mutation()).then_some(SOURCE_READ),
            RequestKind::History(_) | RequestKind::Historical(_) | RequestKind::Review(_) => {
                Some(SOURCE_HISTORY_READ)
            }
            RequestKind::Change(request) => (!request.is_mutation()).then_some(SOURCE_CANDIDATES),
            RequestKind::Initial(_)
            | RequestKind::Replay(_)
            | RequestKind::Rebase(_)
            | RequestKind::Bundle(_)
            | RequestKind::VerifiedBlob(_) => None,
        }
    }
    fn requires_history_read(&self) -> bool {
        matches!(
            &self.0,
            RequestKind::History(_) | RequestKind::Historical(_) | RequestKind::Review(_)
        )
    }
    /// Only exact-patch preparation and supplied-bundle inspection belong to
    /// the candidate scope; other nonpublishing source routes stay excluded.
    pub(super) fn candidate_upload_maximum(&self) -> Option<u64> {
        match &self.0 {
            RequestKind::Change(request) if !request.is_mutation() => {
                Some(request.kind().maximum() as u64)
            }
            _ => None,
        }
    }
    const fn route(&self) -> &str {
        match &self.0 {
            RequestKind::Read(request) => request.repository_route,
            RequestKind::Regex(request) => request.repository_route,
            RequestKind::Indexed(request) => request.repository_route,
            RequestKind::Symbols(request) => request.repository_route,
            RequestKind::Retrieval(request) => request.repository_route,
            RequestKind::Change(request) => request.repository_route,
            RequestKind::Refs(request) => request.route(),
            RequestKind::Tags(request) => request.route(),
            RequestKind::Initial(request) => request.repository_route,
            RequestKind::History(request) => request.repository_route,
            RequestKind::Historical(request) => request.repository_route,
            RequestKind::Review(request) => request.repository_route,
            RequestKind::Replay(request) => request.repository_route,
            RequestKind::Bundle(request) => request.repository_route,
            RequestKind::Rebase(request) => request.repository_route,
            RequestKind::VerifiedBlob(request) => request.repository_route,
        }
    }
}

pub(super) struct Reply(ReplyBody);
enum ReplyBody {
    Json(JsonReply),
    Patch(changes::PatchReply),
    Initial(initial::Prepared),
    Candidate(artifact::PreparedReply),
    BundleExport(bundles::Export),
    VerifiedBlob(verified_blob::Reply),
}
impl Reply {
    const fn json(reply: JsonReply) -> Self {
        Self(ReplyBody::Json(reply))
    }
    const fn patch(reply: changes::PatchReply) -> Self {
        Self(ReplyBody::Patch(reply))
    }
    const fn initial(reply: initial::Prepared) -> Self {
        Self(ReplyBody::Initial(reply))
    }
    const fn candidate(reply: artifact::PreparedReply) -> Self {
        Self(ReplyBody::Candidate(reply))
    }
    const fn bundle_export(reply: bundles::Export) -> Self {
        Self(ReplyBody::BundleExport(reply))
    }
    pub(super) fn send(&self, writer: &mut impl Write, version: HttpVersion) -> io::Result<()> {
        match &self.0 {
            ReplyBody::Json(reply) => reply.send(writer, version),
            ReplyBody::Patch(reply) => reply.send(writer, version),
            ReplyBody::Initial(reply) => reply.send(writer, version),
            ReplyBody::Candidate(reply) => reply.send(writer, version),
            ReplyBody::BundleExport(reply) => reply.send(writer, version),
            ReplyBody::VerifiedBlob(reply) => reply.send(writer, version),
        }
    }
}

// Retained separately from a principal session: only source reads that passed
// the actual route, credential and source-read grant can create this value.
pub(super) struct HttpReadGrant {
    principal: fgit_types::PrincipalId,
    agent: Option<(
        fgit_admission::evidence::AgentAuthentication,
        std::time::Instant,
    )>,
}
impl HttpReadGrant {
    fn context(&self, node: &OneNode) -> crate::source_retrieval::authorization::SourceReadContext {
        match self.agent {
            Some((authentication, deadline)) => {
                crate::source_retrieval::authorization::SourceReadContext::http_agent_credential(
                    node,
                    authentication,
                    deadline,
                )
            }
            None => crate::source_retrieval::authorization::SourceReadContext::http_credential(
                node,
                self.principal,
            ),
        }
    }
}
pub(super) fn authenticate(
    request: &Request<'_>,
    envelope: &Envelope<'_>,
    raw_head: &[u8],
    profile: &Profile,
) -> Result<(LoopbackReceiveSession, Option<HttpReadGrant>), ApiError> {
    let grant = profile
        .credentials
        .authenticate(super::bearer_only(envelope.authorization()))
        .map_err(|error| ApiError::from_status(Status::from(error), false))?;
    if request.route().as_bytes() != profile.route {
        return Err(ApiError::not_found());
    }
    let permitted = if request.is_mutation() {
        profile.allow_receive() && grant.permits(Service::ReceivePack)
    } else if request.requires_history_read() {
        grant.permits_source_history_read()
    } else if request.candidate_upload_maximum().is_some() {
        grant.permits_source_candidates()
    } else {
        grant.permits_source_read()
    };
    if !profile.allow_source() || !permitted {
        return Err(ApiError::new(Status::Forbidden, "forbidden"));
    }
    let supplied_key = retry_key(raw_head).map_err(|_| ApiError::bad("invalid_idempotency_key"))?;
    let key = if request.is_mutation() {
        supplied_key.ok_or_else(|| ApiError::bad("idempotency_key_required"))?
    } else {
        if supplied_key.is_some() {
            return Err(ApiError::bad("source_read_has_no_transaction_key"));
        }
        // Transport identity only: reads never pass it into seal/key binding.
        b"read-only-source-query".as_slice()
    };
    let session = grant.session(
        IdempotencyKey::new(key.to_vec()).map_err(|_| ApiError::bad("invalid_idempotency_key"))?,
    );
    let authenticated = session
        .authenticated_session()
        .ok_or_else(|| ApiError::new(Status::Unauthorized, "unauthorized"))?;
    let agent = match authenticated.authentication() {
        fgit_admission::evidence::AdmissionAuthentication::AgentCredential(authentication) => {
            if !matches!(
                request.agent_operation(),
                Some(
                    fgit_identity::agent::SOURCE_READ
                        | fgit_identity::agent::SOURCE_HISTORY_READ
                        | fgit_identity::agent::SOURCE_CANDIDATES
                )
            ) {
                return Err(ApiError::new(Status::Forbidden, "forbidden"));
            }
            // Both values originate in the same bounded credential request.
            // Missing deadline cannot be substituted with a fresh lifetime.
            Some((
                authentication,
                authenticated
                    .agent_deadline
                    .ok_or_else(ApiError::unavailable)?,
            ))
        }
        _ => None,
    };
    // History and candidate requests cannot mint the current-source context
    // used by retrieval adapters. Candidate work also requires the original
    // authenticated reservation at execution, not just session provenance.
    let read = (!request.is_mutation()
        && !request.requires_history_read()
        && request.candidate_upload_maximum().is_none())
    .then_some(HttpReadGrant {
        principal: grant.principal,
        agent,
    });
    Ok((session, read))
}

pub(super) fn execute(
    node: &OneNode,
    request: &Request<'_>,
    session: &LoopbackReceiveSession,
    read_grant: Option<&HttpReadGrant>,
    agent_request: Option<&crate::agent_credentials::AgentRequest>,
    framing: BodyFraming,
    reader: &mut impl Read,
    http: HttpLimits,
    maximum_response: u64,
) -> Result<Reply, ApiError> {
    let request = match &request.0 {
        RequestKind::VerifiedBlob(request) => {
            return verified_blob::execute(node, request, session, maximum_response)
                .map(|reply| Reply(ReplyBody::VerifiedBlob(reply)));
        }
        RequestKind::Retrieval(request) => {
            let read = read_grant
                .ok_or_else(|| ApiError::new(Status::Forbidden, "source_read_grant_required"))?
                .context(node);
            return retrieval::execute(
                node,
                request,
                session,
                &read,
                framing,
                reader,
                http,
                maximum_response,
            )
            .map(Reply::json);
        }
        RequestKind::Symbols(request) => {
            return symbols::execute(
                node,
                request,
                session,
                framing,
                reader,
                http,
                maximum_response,
            )
            .map(Reply::json);
        }
        RequestKind::Indexed(request) => {
            return indexed::execute(
                node,
                request,
                session,
                framing,
                reader,
                http,
                maximum_response,
            )
            .map(Reply::json);
        }
        RequestKind::Regex(request) => {
            return regex::execute(
                node,
                request,
                session,
                framing,
                reader,
                http,
                maximum_response,
            )
            .map(Reply::json);
        }
        RequestKind::Bundle(request) => {
            return bundles::execute(
                node,
                request,
                session,
                framing,
                reader,
                http,
                maximum_response,
            );
        }
        RequestKind::Historical(request) => {
            return historical::execute(
                node,
                request,
                session,
                framing,
                reader,
                http,
                maximum_response,
            )
            .map(Reply::json);
        }
        RequestKind::Rebase(request) => {
            return rebase::execute(
                node,
                request,
                session,
                framing,
                reader,
                http,
                maximum_response,
            );
        }
        RequestKind::Replay(request) => {
            return replay::execute(
                node,
                request,
                session,
                framing,
                reader,
                http,
                maximum_response,
            )
            .map(Reply::candidate);
        }
        RequestKind::Review(request) => {
            return review::execute(
                node,
                request,
                session,
                framing,
                reader,
                http,
                maximum_response,
            )
            .map(Reply::json);
        }
        RequestKind::History(request) => {
            return history::execute(
                node,
                request,
                session,
                framing,
                reader,
                http,
                maximum_response,
            )
            .map(Reply::json);
        }
        RequestKind::Initial(request) => {
            return initial::execute(
                node,
                request,
                session,
                framing,
                reader,
                http,
                maximum_response,
            );
        }
        RequestKind::Tags(request) => {
            return tags::execute(
                node,
                request,
                session,
                framing,
                reader,
                http,
                maximum_response,
            )
            .map(Reply::json);
        }
        RequestKind::Refs(request) => {
            return refs::execute(
                node,
                request,
                session,
                framing,
                reader,
                http,
                maximum_response,
            )
            .map(Reply::json);
        }
        RequestKind::Change(request) => {
            return changes::execute(
                node,
                request,
                session,
                agent_request,
                framing,
                reader,
                http,
                maximum_response,
            );
        }
        RequestKind::Read(request) => request,
    };
    if session.authenticated_session().is_none() {
        return Err(ApiError::new(Status::Unauthorized, "unauthorized"));
    }
    let command = request.command(&read_form(reader, framing, http)?, node.object_format)?;
    let deadline = GitDaemonSessionDeadline::new(
        node.git_daemon_session_timeout,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let context = node.authenticated_session_request_context(&deadline, session);
    let mut live = || !deadline.expired() && context.is_live();
    let maximum = usize::try_from(maximum_response)
        .unwrap_or(usize::MAX)
        .min(output::MAX_REPLY_BYTES);
    // Native readers derive path grants from the SAME verified selected tree.
    // Both operator reads and explicit sponsored source-read grants have the
    // repository boundary; query paths only narrow selection. Current canonical
    // hidden refs remain undisclosable.
    let body = match &command {
        Command::Commit { selection } => {
            let report = drive_request_while(
                node,
                &context,
                node.read_source_commit_local_in(
                    &context,
                    &selection.reference,
                    selection.expected_head,
                    selection.expected_commit,
                ),
                &mut live,
            )
            .map_err(read_error)?;
            output::current_commit(node, selection, &report, maximum, &mut live)?
        }
        Command::Browse { selection, query } => {
            let report = drive_request_while(
                node,
                &context,
                node.browse_source_local_in(&context, &selection.reference, query),
                &mut live,
            )
            .map_err(read_error)?;
            output::browse(node, selection, query, &report, maximum, &mut live)?
        }
        Command::SearchBatch {
            selection,
            query,
            limits,
        } => {
            let (head, report) = drive_request_while(
                node,
                &context,
                node.search_source_batch_snapshot_local_in(
                    &context,
                    &selection.reference,
                    selection.expected_head,
                    selection.expected_commit,
                    query,
                    *limits,
                ),
                &mut live,
            )
            .map_err(read_error)?;
            output::search_batch(
                node, selection, query, *limits, head, &report, maximum, &mut live,
            )?
        }
        Command::Search {
            selection,
            query,
            limits,
        } => {
            let (head, report) = drive_request_while(
                node,
                &context,
                node.search_source_snapshot_local_in(
                    &context,
                    &selection.reference,
                    selection.expected_head,
                    selection.expected_commit,
                    query,
                    *limits,
                ),
                &mut live,
            )
            .map_err(read_error)?;
            output::search(
                node, selection, query, *limits, head, &report, maximum, &mut live,
            )?
        }
    };
    Ok(Reply::json(JsonReply {
        status: Status::Success,
        body,
        terminal: None,
    }))
}

fn base_error(error: BaseError) -> ApiError {
    match error {
        BaseError::NotFound { .. } => ApiError::not_found(),
        BaseError::NotADirectory { .. } => ApiError::new(Status::Conflict, "not_a_directory"),
        BaseError::SymlinkTraversal { .. } => {
            ApiError::new(Status::Conflict, "symlink_not_followed")
        }
        BaseError::Path(_) => ApiError::bad("invalid_repository_path"),
        // A missing/corrupt required object is not a nonexistent user path.
        _ => ApiError::unavailable(),
    }
}
fn read_error(error: NodeWorkspaceRefusal) -> ApiError {
    match error {
        NodeWorkspaceRefusal::RefUnavailable => ApiError::not_found(),
        NodeWorkspaceRefusal::CommitRequired => {
            ApiError::new(Status::Conflict, "ref_does_not_select_commit")
        }
        NodeWorkspaceRefusal::ObjectFormatMismatch => ApiError::bad("object_format_mismatch"),
        NodeWorkspaceRefusal::Cancelled {
            exhaustion: Some(_),
        } => ApiError::too_large(),
        NodeWorkspaceRefusal::Cancelled { exhaustion: None } => {
            ApiError::from_status(Status::Timeout, false)
        }
        NodeWorkspaceRefusal::SourceBrowse(error) => match *error {
            SourceBrowseError::InvalidRequest(_) => ApiError::bad("invalid_browse_query"),
            SourceBrowseError::SnapshotMoved => {
                ApiError::new(Status::Conflict, "source_snapshot_moved")
            }
            SourceBrowseError::CommitMoved => {
                ApiError::new(Status::Conflict, "source_commit_moved")
            }
            SourceBrowseError::ExpectedFile => ApiError::new(Status::Conflict, "not_a_file"),
            SourceBrowseError::RangeOutsideFile => ApiError::bad("range_outside_file"),
            SourceBrowseError::Budget(_) => ApiError::too_large(),
            SourceBrowseError::Base(error) => base_error(*error),
            _ => ApiError::unavailable(),
        },
        NodeWorkspaceRefusal::SourceSearch(error) => match *error {
            SearchError::InvalidQuery
            | SearchError::InvalidLimits
            | SearchError::InvalidObjectFormat => ApiError::bad("invalid_search_query"),
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
    fn current_commit_source_grant_does_not_open_history_or_binary_authority_proofs() {
        for (raw, expected) in [
            (
                "POST /repo/api/v1/source/commit HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n\r\n",
                Some(fgit_identity::agent::SOURCE_READ),
            ),
            (
                "POST /repo/api/v1/source/log HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n\r\n",
                None,
            ),
            (
                "GET /repo/api/v1/source/verified-blob?ref_hex=726566732f68656164732f6d61696e HTTP/1.1\r\nHost: local\r\n\r\n",
                None,
            ),
        ] {
            let envelope =
                fgit_wire::smart_http::head::parse(raw.as_bytes(), HttpLimits::default())
                    .unwrap()
                    .unwrap();
            assert_eq!(
                Request::parse(&envelope).unwrap().agent_operation(),
                expected
            );
        }
    }
    #[test]
    fn read_failures_never_imply_mutation_ambiguity_or_complete_empty_results() {
        for error in [
            NodeWorkspaceRefusal::RefUnavailable,
            NodeWorkspaceRefusal::CommitRequired,
            NodeWorkspaceRefusal::Cancelled { exhaustion: None },
            NodeWorkspaceRefusal::SourceSearch(Box::new(SearchError::Budget("files"))),
            NodeWorkspaceRefusal::SourceBrowse(Box::new(SourceBrowseError::SnapshotMoved)),
        ] {
            let error = read_error(error);
            assert!(!error.outcome_unknown);
            let mut reply = Vec::new();
            error
                .send_named(
                    &mut reply,
                    fgit_wire::smart_http::HttpVersion::Http11,
                    "source_error",
                )
                .unwrap();
            let text = String::from_utf8(reply).unwrap();
            assert!(!text.contains("\"matches\":[]") && !text.contains("\"outcome\":\"refused\""));
        }
    }
    #[test]
    fn branch_tag_and_candidate_mutations_acquire_the_same_write_semantics() {
        for (action, media, mutation) in [
            ("commit", "application/x-www-form-urlencoded", false),
            ("tree", "application/x-www-form-urlencoded", false),
            ("log", "application/x-www-form-urlencoded", false),
            ("search-batch", "application/x-www-form-urlencoded", false),
            ("search-regex", "application/x-www-form-urlencoded", false),
            ("search-index", "application/x-www-form-urlencoded", false),
            ("search-symbols", "application/x-www-form-urlencoded", false),
            ("bundle/export", "application/x-www-form-urlencoded", false),
            (
                "historical-tree",
                "application/x-www-form-urlencoded",
                false,
            ),
            (
                "historical-blob",
                "application/x-www-form-urlencoded",
                false,
            ),
            ("diff", "application/x-www-form-urlencoded", false),
            (
                "cherry-pick/prepare",
                "application/x-www-form-urlencoded",
                false,
            ),
            ("revert/prepare", "application/x-www-form-urlencoded", false),
            ("rebase/prepare", "application/x-www-form-urlencoded", false),
            ("rebase/apply", "multipart/form-data; boundary=x", true),
            ("refs", "application/x-www-form-urlencoded", false),
            ("branches/create", "application/x-www-form-urlencoded", true),
            ("branches/update", "application/x-www-form-urlencoded", true),
            ("branches/delete", "application/x-www-form-urlencoded", true),
            ("branches/rename", "application/x-www-form-urlencoded", true),
            (
                "tags/lightweight",
                "application/x-www-form-urlencoded",
                true,
            ),
            ("tags/annotated", "application/x-www-form-urlencoded", true),
            ("tags/delete", "application/x-www-form-urlencoded", true),
            ("tags/inspect", "application/x-www-form-urlencoded", false),
            ("prepare", "multipart/form-data; boundary=x", false),
            ("inspect", "multipart/form-data; boundary=x", false),
            ("apply", "multipart/form-data; boundary=x", true),
            ("initial/prepare", "multipart/form-data; boundary=x", false),
            ("initial/apply", "multipart/form-data; boundary=x", true),
        ] {
            let bytes = format!(
                "POST /repo.git/api/v1/source/{action} HTTP/1.1\r\nHost: local\r\nContent-Type: {media}\r\nContent-Length: 1\r\n\r\n"
            );
            let envelope =
                fgit_wire::smart_http::head::parse(bytes.as_bytes(), HttpLimits::default())
                    .unwrap()
                    .unwrap();
            assert_eq!(Request::parse(&envelope).unwrap().is_mutation(), mutation);
        }
    }
}
