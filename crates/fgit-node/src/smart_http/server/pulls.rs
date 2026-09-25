//! Authenticated PR collaboration. Every route selects its own explicit grant
//! and calls the existing node engine; metadata, reviews and code publication
//! never gain authority from each other or from request text.

mod collaboration;
mod diff;
mod inspection;
mod output;
mod preparation;
mod request;

// Source editing shares the established ingress/MIME implementation, not PR
// authorization. These helpers parse bytes and confer no publication authority.
pub(super) use collaboration::source_upload::{
    SourceUploadKind, read_source_upload, source_upload, source_upload_boundary,
};

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
pub(super) fn resolution_upload<'a>(
    bytes: &'a [u8],
    boundary: &str,
    live: &mut impl FnMut() -> bool,
) -> Result<(&'a [u8], std::collections::BTreeMap<&'a str, &'a [u8]>), ApiError> {
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
use crate::{
    GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession, OneNode,
};
use request::Operation;

#[derive(Debug)]
pub(super) enum Request<'a> {
    Metadata(request::Request<'a>),
    Collaboration(collaboration::Request<'a>),
    Preparation(preparation::Request<'a>),
    Inspection(inspection::Request<'a>),
    Diff(diff::Request<'a>),
}
impl<'a> Request<'a> {
    pub(super) fn parse(envelope: &Envelope<'a>) -> Result<Option<Self>, ApiError> {
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
    pub(super) fn is_mutation(&self) -> bool {
        match self {
            Self::Metadata(request) => request.is_mutation(),
            Self::Collaboration(request) => request.is_mutation(),
            Self::Preparation(_) | Self::Inspection(_) | Self::Diff(_) => false,
        }
    }
    /// Preparation, inspection and diff spend bounded work on a POST body,
    /// but acquire neither transaction responsibility nor a retry-key binding.
    pub(super) fn accepts_body(&self) -> bool {
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
        Request::Metadata(request) => request,
    };
    let grant = profile
        .credentials
        .authenticate(envelope.authorization())
        .map_err(|error| ApiError::from_status(Status::from(error), false))?;
    if request.repository_route.as_bytes() != profile.route {
        return Err(ApiError::not_found());
    }
    if !profile.allow_pulls || !grant.permits_pulls(request.is_mutation()) {
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
    Ok(LoopbackReceiveSession::authenticated(grant.principal, key))
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
    match request {
        Request::Diff(request) => diff::execute(
            node,
            request,
            session,
            framing,
            reader,
            limits,
            maximum_response,
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
    let deadline = GitDaemonSessionDeadline::new(
        node.git_daemon_session_timeout,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let context = node.session_request_context(&deadline);
    let mut live = || !deadline.expired();
    let maximum = usize::try_from(maximum_response)
        .unwrap_or(usize::MAX)
        .min(output::MAX_REPLY_BYTES);
    let visibility = RefVisibility::new();
    match &request.operation {
        Operation::List(page) => {
            let result = drive_request_while(
                node,
                &context,
                node.read_pull_requests_in(
                    &context,
                    &visibility,
                    page.after,
                    page.limit,
                    page.expected_head,
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
                body: output::list(node, *page, &result, maximum)?,
                terminal: None,
            })
        }
        Operation::Show {
            number,
            expected_head,
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
            let (found, body) = output::show(node, *number, *expected_head, &result, maximum)?;
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
