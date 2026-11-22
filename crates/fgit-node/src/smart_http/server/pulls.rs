//! Authenticated PR collaboration. Every route selects its own explicit grant
//! and calls the existing node engine; metadata, reviews and code publication
//! never gain authority from each other or from request text.

mod checks;
mod collaboration;
mod conversation;
mod diff;
mod fast_forward;
mod inspection;
mod labels;
mod output;
mod preparation;
mod request;
mod search;
mod subject;

// Queue preparation shares only the bounded artifact formatter and native
// read-error mapping. Queue selection and its independent grants remain local.
pub(super) use preparation::{
    Reply as PreparationReply, build_queue as queue_preparation_reply,
    preparation_error as candidate_preparation_error,
};

// Source editing shares the established ingress/MIME implementation, not PR
// authorization. These helpers parse bytes and confer no publication authority.
pub(super) use collaboration::source_upload::{
    SourceUploadKind, read_source_upload, source_upload, source_upload_boundary,
};

// Queue candidate publication shares only bounded byte ingress. These helpers
// confer no PR capability and retain optional bundle bytes for terminal recovery.
pub(super) const CANDIDATE_UPLOAD_BYTES: usize = collaboration::CANDIDATE_UPLOAD_BYTES;
pub(super) fn candidate_boundary(media: &str) -> Result<&str, ApiError> {
    collaboration::candidate_boundary(media)
}
pub(super) fn read_candidate_upload(
    reader: &mut impl Read,
    framing: BodyFraming,
    limits: HttpLimits,
) -> Result<Vec<u8>, ApiError> {
    collaboration::read_upload_bounded(reader, framing, limits, CANDIDATE_UPLOAD_BYTES)
}
pub(super) fn candidate_upload<'a>(
    bytes: &'a [u8],
    boundary: &str,
    live: &mut impl FnMut() -> bool,
) -> Result<(&'a [u8], Option<&'a [u8]>), ApiError> {
    collaboration::publication_upload(bytes, boundary, live)
}

// Replay resolution uses exactly the existing resolution part policy. Expose
// byte-only adapters, not a PR request, subject, credential or execution method.
pub(super) const MAX_RESOLUTION_UPLOAD_BYTES: usize =
    collaboration::resolution_upload::MAX_UPLOAD_BYTES;
pub(super) fn resolution_upload_boundary(media: &str) -> Result<&str, ApiError> {
    collaboration::resolution_upload::boundary(media)
}
pub(super) fn read_resolution_upload(
    reader: &mut impl Read,
    framing: BodyFraming,
    limits: HttpLimits,
) -> Result<Vec<u8>, ApiError> {
    collaboration::read_upload_bounded(reader, framing, limits, MAX_RESOLUTION_UPLOAD_BYTES)
}
pub(super) type ResolutionUpload<'a> = (&'a [u8], std::collections::BTreeMap<&'a str, &'a [u8]>);

pub(super) fn resolution_upload<'a>(
    bytes: &'a [u8],
    boundary: &str,
    live: &mut impl FnMut() -> bool,
) -> Result<ResolutionUpload<'a>, ApiError> {
    let upload = collaboration::resolution_upload::parse(bytes, boundary, live)?;
    Ok((upload.command, upload.files))
}

use std::io::{self, Read, Write};

use fgit_authority::IdempotencyKey;
use fgit_types::DecisionOutcome;
use fgit_wire::smart_http::{BodyFraming, HttpLimits, HttpVersion, head::Envelope};
use fgit_wire::visibility::RefVisibility;

use super::super::drive_request_while;
use super::issues::{ApiError, Reply as JsonReply, admission_error, read_form};
use super::{Profile, Status, retry_key};
use crate::{GitDaemonSessionDeadline, LoopbackReceiveSession, OneNode};
use request::Operation;

#[derive(Debug)]
pub(super) enum Request<'a> {
    Metadata(request::Request<'a>),
    Collaboration(collaboration::Request<'a>),
    Conversation(conversation::Request<'a>),
    Labels(labels::Request<'a>),
    Preparation(preparation::Request<'a>),
    Inspection(inspection::Request<'a>),
    Diff(diff::Request<'a>),
    Checks(checks::Request<'a>),
    FastForward(fast_forward::Request<'a>),
}
impl<'a> Request<'a> {
    pub(super) fn uses_read_quota(&self) -> bool {
        matches!(self, Self::Labels(request) if !request.is_mutation())
            || matches!(self, Self::Metadata(request::Request {
                operation: Operation::List { labels, .. }, ..
            }) if !labels.is_empty())
            || matches!(
                self,
                Self::Metadata(request::Request {
                    operation: Operation::Search(_),
                    ..
                })
            )
    }

    pub(super) const fn preserves_deadline(&self) -> bool {
        matches!(
            self,
            Self::Labels(_) | Self::Metadata(_) | Self::Diff(_) | Self::Checks(_)
        ) || matches!(self, Self::Collaboration(request) if !request.is_mutation())
    }

    pub(super) fn agent_operation(&self) -> Option<u32> {
        use fgit_identity::agent::{PULLS_DIFF_READ, PULLS_FEEDBACK_READ, PULLS_READ, PULLS_WRITE};
        match self {
            Self::Diff(_) => Some(PULLS_DIFF_READ),
            Self::Checks(request) if request.evidence.is_none() => Some(PULLS_FEEDBACK_READ),
            Self::Collaboration(request) if !request.is_mutation() => Some(PULLS_FEEDBACK_READ),
            Self::Metadata(_) | Self::Conversation(_) | Self::Labels(_) => {
                Some(if self.is_mutation() {
                    PULLS_WRITE
                } else {
                    PULLS_READ
                })
            }
            _ => None,
        }
    }
    pub(super) fn parse(envelope: &Envelope<'a>) -> Result<Option<Self>, ApiError> {
        if let Some(request) = labels::Request::parse(envelope)? {
            return Ok(Some(Self::Labels(request)));
        }
        if let Some(request) = conversation::Request::parse(envelope)? {
            return Ok(Some(Self::Conversation(request)));
        }
        if let Some(request) = fast_forward::Request::parse(envelope)? {
            return Ok(Some(Self::FastForward(request)));
        }
        if let Some(request) = checks::Request::parse(envelope)? {
            return Ok(Some(Self::Checks(request)));
        }
        if let Some(request) = diff::Request::parse(envelope)? {
            return Ok(Some(Self::Diff(request)));
        }
        if let Some(request) = inspection::Request::parse(envelope)? {
            return Ok(Some(Self::Inspection(request)));
        }
        if let Some(request) = preparation::Request::parse(envelope)? {
            return Ok(Some(Self::Preparation(request)));
        }
        if let Some(request) = collaboration::Request::parse(envelope)? {
            return Ok(Some(Self::Collaboration(request)));
        }
        request::Request::parse(envelope).map(|request| request.map(Self::Metadata))
    }
    pub(super) const fn is_mutation(&self) -> bool {
        match self {
            Self::FastForward(_) => true,
            Self::Metadata(request) => request.is_mutation(),
            Self::Collaboration(request) => request.is_mutation(),
            Self::Conversation(request) => request.is_mutation(),
            Self::Labels(request) => request.is_mutation(),
            Self::Preparation(_) | Self::Inspection(_) | Self::Diff(_) | Self::Checks(_) => false,
        }
    }
    /// Preparation, inspection and diff spend bounded work on a POST body,
    /// but acquire neither transaction responsibility nor a retry-key binding.
    pub(super) const fn accepts_body(&self) -> bool {
        self.is_mutation()
            || matches!(
                self,
                Self::Preparation(_) | Self::Inspection(_) | Self::Diff(_)
            )
    }
}

pub(super) enum Reply {
    Json(JsonReply),
    Preparation(preparation::Reply),
}
impl Reply {
    pub(super) fn send(&self, writer: &mut impl Write, version: HttpVersion) -> io::Result<()> {
        match self {
            Self::Json(reply) => reply.send(writer, version),
            Self::Preparation(reply) => reply.send(writer, version),
        }
    }
}

pub(super) fn authenticate(
    request: &Request<'_>,
    envelope: &Envelope<'_>,
    raw_head: &[u8],
    profile: &Profile,
) -> Result<LoopbackReceiveSession, ApiError> {
    let request = match request {
        Request::Labels(request) => {
            return labels::authenticate(request, envelope, raw_head, profile);
        }
        Request::Conversation(request) => {
            return conversation::authenticate(request, envelope, raw_head, profile);
        }
        Request::Checks(request) => {
            return checks::authenticate(request, envelope, raw_head, profile);
        }
        Request::Diff(request) => return diff::authenticate(request, envelope, raw_head, profile),
        Request::Inspection(request) => {
            return inspection::authenticate(request, envelope, raw_head, profile);
        }
        Request::Preparation(request) => {
            return preparation::authenticate(request, envelope, raw_head, profile);
        }
        Request::Collaboration(request) => {
            return collaboration::authenticate(request, envelope, raw_head, profile);
        }
        Request::FastForward(request) => {
            return fast_forward::authenticate(request, envelope, raw_head, profile);
        }
        Request::Metadata(request) => request,
    };
    let grant = profile
        .credentials
        .authenticate(super::bearer_only(envelope.authorization()))
        .map_err(|error| ApiError::from_status(Status::from(error), false))?;
    if request.repository_route.as_bytes() != profile.route {
        return Err(ApiError::not_found());
    }
    if !profile.allow_pulls() || !grant.permits_pulls(request.is_mutation()) {
        return Err(ApiError::new(Status::Forbidden, "forbidden"));
    }
    let key = retry_key(raw_head).map_err(|_| ApiError::bad("invalid_idempotency_key"))?;
    let key = if request.is_mutation() {
        key.ok_or_else(|| ApiError::bad("idempotency_key_required"))?
    } else {
        b"pull-request-read-no-publication".as_slice()
    };
    let key =
        IdempotencyKey::new(key.to_vec()).map_err(|_| ApiError::bad("invalid_idempotency_key"))?;
    Ok(grant.session(key))
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
    match request {
        Request::Labels(request) => labels::execute(
            node,
            request,
            session,
            framing,
            reader,
            limits,
            maximum_response,
            deadline,
        )
        .map(Reply::Json),
        Request::Conversation(request) => conversation::execute(
            node,
            request,
            session,
            framing,
            reader,
            limits,
            maximum_response,
        )
        .map(Reply::Json),
        Request::Checks(request) => {
            checks::execute(node, request, session, maximum_response, deadline).map(Reply::Json)
        }
        Request::Diff(request) => diff::execute(
            node,
            request,
            session,
            framing,
            reader,
            limits,
            maximum_response,
            deadline,
        )
        .map(Reply::Json),
        Request::Inspection(request) => inspection::execute(
            node,
            request,
            session,
            framing,
            reader,
            limits,
            maximum_response,
        )
        .map(Reply::Json),
        Request::Preparation(request) => preparation::execute(
            node,
            request,
            session,
            framing,
            reader,
            limits,
            maximum_response,
        )
        .map(Reply::Preparation),
        Request::Collaboration(request) => collaboration::execute(
            node,
            request,
            session,
            framing,
            reader,
            limits,
            maximum_response,
            deadline,
        )
        .map(Reply::Json),
        Request::FastForward(request) => fast_forward::execute(
            node,
            request,
            session,
            framing,
            reader,
            limits,
            maximum_response,
        )
        .map(Reply::Json),
        Request::Metadata(request) => execute_metadata(
            node,
            request,
            session,
            framing,
            reader,
            limits,
            maximum_response,
            deadline,
        )
        .map(Reply::Json),
    }
}

/// Full HTTP framing precedes metadata admission. The exact submitted command
/// enters the existing durable engine; closing never refreshes metadata first.
fn execute_metadata(
    node: &OneNode,
    request: &request::Request<'_>,
    session: &LoopbackReceiveSession,
    framing: BodyFraming,
    reader: &mut impl Read,
    limits: HttpLimits,
    maximum_response: u64,
    deadline: &GitDaemonSessionDeadline,
) -> Result<JsonReply, ApiError> {
    let principal = session
        .authenticated_session()
        .ok_or_else(|| ApiError::new(Status::Unauthorized, "unauthorized"))?
        .principal_id();
    let command = if request.is_mutation() {
        Some(request.command(&read_form(reader, framing, limits)?, node.object_format)?)
    } else {
        None
    };
    let context = node.authenticated_session_request_context(deadline, session);
    let mut live = || !deadline.expired();
    let maximum = usize::try_from(maximum_response)
        .unwrap_or(usize::MAX)
        .min(output::MAX_REPLY_BYTES);
    let visibility = RefVisibility::new();
    match &request.operation {
        Operation::Search(search) => {
            let result = drive_request_while(
                node,
                &context,
                node.search_pull_requests_in(&context, &visibility, &search.query, search.request),
                &mut live,
            )
            .map_err(search::error)?;
            Ok(JsonReply {
                status: Status::Success,
                body: output::search(node, search, &result, maximum)?,
                terminal: None,
            })
        }
        Operation::List { page, labels } => {
            let result = drive_request_while(
                node,
                &context,
                node.read_pull_requests_filtered_in(
                    &context,
                    &visibility,
                    page.after,
                    page.limit,
                    page.expected_head,
                    labels,
                ),
                &mut live,
            )
            .map_err(|error| {
                if error.is_snapshot_unavailable() {
                    ApiError::snapshot_moved()
                } else {
                    ApiError::unavailable()
                }
            })?;
            Ok(JsonReply {
                status: Status::Success,
                body: output::list(node, *page, labels, &result, maximum)?,
                terminal: None,
            })
        }
        Operation::Show {
            number,
            expected_head,
            render,
        } => {
            let result = drive_request_while(
                node,
                &context,
                node.read_pull_requests_in(
                    &context,
                    &visibility,
                    number.get() - 1,
                    1,
                    *expected_head,
                ),
                &mut live,
            )
            .map_err(|error| {
                if error.is_snapshot_unavailable() {
                    ApiError::snapshot_moved()
                } else {
                    ApiError::unavailable()
                }
            })?;
            let (found, body) =
                output::show(node, *number, *expected_head, *render, &result, maximum)?;
            Ok(JsonReply {
                status: if found {
                    Status::Success
                } else {
                    Status::NotFound
                },
                body,
                terminal: None,
            })
        }
        Operation::Mutate { .. } => {
            let command = command.ok_or_else(|| ApiError::bad("missing_command"))?;
            command
                .proposed_event(principal, node.object_format)
                .map_err(|_| ApiError::bad("invalid_pull_request_command"))?;
            let (tx, terminal) = drive_request_while(
                node,
                &context,
                node.admit_pull_request_durable_in(&context, session, &command, Default::default()),
                &mut live,
            )
            .map_err(admission_error)?;
            let body = output::mutation(node, principal, &command, tx, terminal);
            if body.len() > maximum {
                eprintln!(
                    "PR HTTP response limit after canonical outcome for transaction {tx}; recover the original key"
                );
                return Err(ApiError::unknown());
            }
            Ok(JsonReply {
                status: match terminal.outcome {
                    DecisionOutcome::Committed { .. } => Status::Success,
                    DecisionOutcome::Refused { .. } => Status::Conflict,
                },
                body,
                terminal: Some((tx, terminal)),
            })
        }
    }
}

#[cfg(test)]
mod routing_tests {
    use super::*;
    use fgit_wire::smart_http::head;
    #[test]
    fn labels_have_explicit_read_and_write_grants_without_collaboration_escalation() {
        for (method, mutation, operation) in [
            ("GET", false, fgit_identity::agent::PULLS_READ),
            ("POST", true, fgit_identity::agent::PULLS_WRITE),
        ] {
            let headers = if mutation {
                "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n"
            } else {
                ""
            };
            let raw = format!(
                "{method} /repo.git/api/v1/pulls/1/labels HTTP/1.1\r\nHost: local\r\n{headers}\r\n"
            );
            let envelope = head::parse(raw.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            let request = Request::parse(&envelope).unwrap().unwrap();
            assert!(matches!(request, Request::Labels(_)));
            assert_eq!(request.is_mutation(), mutation);
            assert_eq!(request.accepts_body(), mutation);
            assert_eq!(request.agent_operation(), Some(operation));
        }
    }
    #[test]
    fn metadata_reviews_and_merges_have_distinct_typed_routes() {
        for (method, path, collaboration, mutation) in [
            ("GET", "/api/v1/pulls/1", false, false),
            ("GET", "/api/v1/pulls/1/reviews", true, false),
            ("POST", "/api/v1/pulls/1/reviews/approve", true, true),
            ("POST", "/api/v1/pulls/1/merge", true, true),
        ] {
            let headers = if mutation {
                "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n"
            } else {
                ""
            };
            let bytes =
                format!("{method} /repo.git{path} HTTP/1.1\r\nHost: local\r\n{headers}\r\n");
            let envelope = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            let request = Request::parse(&envelope).unwrap().unwrap();
            assert_eq!(matches!(request, Request::Collaboration(_)), collaboration);
            assert_eq!(request.is_mutation(), mutation);
            assert_eq!(request.accepts_body(), mutation);
        }
    }
    #[test]
    fn body_bearing_preparation_and_inspection_never_acquire_publication_semantics() {
        for (action, media) in [
            ("prepare", "application/x-www-form-urlencoded"),
            ("inspect", "multipart/form-data; boundary=x"),
            ("diff", "application/x-www-form-urlencoded"),
        ] {
            let bytes = format!(
                "POST /repo.git/api/v1/pulls/1/{action} HTTP/1.1\r\nHost: local\r\nContent-Type: {media}\r\nContent-Length: 1\r\n\r\n"
            );
            let envelope = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            let request = Request::parse(&envelope).unwrap().unwrap();
            assert!(matches!(
                request,
                Request::Preparation(_) | Request::Inspection(_) | Request::Diff(_)
            ));
            assert!(request.accepts_body());
            assert!(!request.is_mutation());
        }
    }
}
