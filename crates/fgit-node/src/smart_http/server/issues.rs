//! Authenticated repository issue API. The gateway owns credential grants;
//! the existing issue admission driver owns seals, policy, RCR/outbox state,
//! exact-version decisions and retry recovery. No HTTP-local issue state exists.

mod output;
mod request;
mod search;

use std::io::{self, Read, Write};

use fgit_admission::AdmissionError;
use fgit_authority::{IdempotencyKey, SealFailure, TerminalOutcome};
use fgit_types::{DecisionOutcome, TxId};
use fgit_wire::smart_http::{BodyDecoder, BodyFraming, HttpError, HttpLimits, HttpVersion, head::Envelope};
use fgit_wire::smart_http::rpc::{RpcError, RpcProgress};
use fgit_wire::WireError;

use crate::{GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, IssueReadRefusal,
    LoopbackReceiveSession, NodeReceiveTransportRefusal, OneNode};
use super::{Profile, Status, retry_key};
use super::super::{drive_request_while, ingress::BodyInput};
use request::Operation;
pub(super) use request::{Page, Request};

// Sibling forge adapters reuse the same hostile-input and JSON primitives.
// These helpers confer no identity, visibility, or publication permission.
pub(super) const MAX_FORM_BYTES: usize = request::MAX_FORM_BYTES;
pub(super) fn parse_form(bytes: &[u8], maximum_fields: usize) -> Result<Vec<(String, String)>, ApiError> {
    request::form(bytes, maximum_fields)
}
pub(super) fn parse_decimal(text: &str) -> Result<u64, ApiError> { request::decimal(text) }
pub(super) fn parse_page(query: Option<&str>, cursor: &str) -> Result<Page, ApiError> { request::page(query, cursor) }
pub(super) fn parse_snapshot(text: &str) -> Result<fgit_types::RepositoryAuthorityHeadId, ApiError> {
    request::parse_head_token(text)
}
pub(super) fn quote(text: &str) -> String { output::quote(text) }
pub(super) fn ref_fields(name: &'static str, reference: &fgit_types::RefName) -> String {
    output::ref_fields(name, reference)
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ApiError {
    pub(super) status: Status,
    pub(super) code: &'static str,
    pub(super) outcome_unknown: bool,
}
impl ApiError {
    pub(super) fn new(status: Status, code: &'static str) -> Self { Self { status, code, outcome_unknown: false } }
    pub(super) fn bad(code: &'static str) -> Self { Self::new(Status::BadRequest, code) }
    pub(super) fn not_found() -> Self { Self::new(Status::NotFound, "not_found") }
    pub(super) fn too_large() -> Self { Self::new(Status::TooLarge, "resource_limit") }
    pub(super) fn media() -> Self { Self::new(Status::MediaType, "unsupported_media_type") }
    pub(super) fn method() -> Self { Self::new(Status::Method, "method_not_allowed") }
    pub(super) fn unavailable() -> Self { Self::new(Status::Unavailable, "repository_unavailable") }
    pub(super) fn snapshot_moved() -> Self { Self::new(Status::Conflict, "snapshot_moved") }
    pub(super) fn unknown() -> Self { Self { status: Status::Unavailable, code: "outcome_unknown", outcome_unknown: true } }

    pub(super) fn from_status(status: Status, mutation: bool) -> Self {
        let code = match status {
            Status::Unauthorized => "unauthorized",
            Status::Forbidden => "forbidden",
            Status::NotFound => "not_found",
            Status::TooLarge | Status::HeaderTooLarge => "resource_limit",
            Status::Timeout => "request_timeout",
            Status::RateLimited => "rate_limited",
            Status::Unavailable => if mutation { "outcome_unknown" } else { "repository_unavailable" },
            _ => "invalid_request",
        };
        Self { status, code, outcome_unknown: mutation && status == Status::Unavailable }
    }
    pub(super) fn send(self, writer: &mut impl Write, version: HttpVersion) -> io::Result<()> {
        self.send_named(writer, version, "issue_error")
    }
    pub(super) fn send_named(self, writer: &mut impl Write, version: HttpVersion, family: &'static str) -> io::Result<()> {
        let body = format!("{{\"type\":{},\"schema_version\":1,\"code\":{},\"outcome_unknown\":{}}}",
            output::quote(family), output::quote(self.code), self.outcome_unknown);
        write_json(writer, version, self.status, &body)
    }
}
impl From<IssueReadRefusal> for ApiError {
    fn from(error: IssueReadRefusal) -> Self {
        match error {
            IssueReadRefusal::SnapshotMoved => Self::snapshot_moved(),
            IssueReadRefusal::SnapshotRequired => Self::bad("snapshot_required"),
            IssueReadRefusal::InvalidLimit => Self::bad("invalid_page_limit"),
            _ => Self::unavailable(),
        }
    }
}

pub(super) struct Reply {
    pub(super) status: Status,
    pub(super) body: String,
    pub(super) terminal: Option<(TxId, TerminalOutcome)>,
}
impl Reply {
    pub(super) fn send(&self, writer: &mut impl Write, version: HttpVersion) -> io::Result<()> {
        let delivered = write_json(writer, version, self.status, &self.body);
        if delivered.is_err() {
            if let Some((tx, _)) = self.terminal {
                eprintln!("Forge HTTP reply lost after canonical outcome for transaction {tx}; retry the identical command and Idempotency-Key");
            }
        }
        delivered
    }
}
fn write_json(writer: &mut impl Write, version: HttpVersion, status: Status, body: &str) -> io::Result<()> {
    let version = match version { HttpVersion::Http10 => "HTTP/1.0", HttpVersion::Http11 => "HTTP/1.1" };
    let extra = match status {
        Status::Unauthorized => "WWW-Authenticate: Bearer realm=\"frankengit\"\r\n",
        Status::RateLimited => "Retry-After: 60\r\n",
        Status::Method => "Allow: GET, POST\r\n",
        _ => "",
    };
    write!(writer, "{version} {}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nVary: Authorization\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n{extra}\r\n{body}", status.line(), body.len())?;
    writer.flush()
}

pub(super) fn authenticate(request: &Request<'_>, envelope: &Envelope<'_>,
    raw_head: &[u8], profile: &Profile,
) -> Result<LoopbackReceiveSession, ApiError> {
    let grant = profile.credentials.authenticate(envelope.authorization())
        .map_err(|error| ApiError::from_status(Status::from(error), false))?;
    if request.repository_route.as_bytes() != profile.route { return Err(ApiError::not_found()); }
    if !profile.allow_issues || !grant.permits_issues(request.is_mutation()) {
        return Err(ApiError::new(Status::Forbidden, "forbidden"));
    }
    let key = retry_key(raw_head).map_err(|_| ApiError::bad("invalid_idempotency_key"))?;
    if matches!(&request.operation, Operation::Search) && key.is_some() {
        return Err(ApiError::bad("idempotency_key_not_allowed"));
    }
    let key = if request.is_mutation() { key.ok_or_else(|| ApiError::bad("idempotency_key_required"))? }
        else { b"issue-read-no-publication".as_slice() };
    let key = IdempotencyKey::new(key.to_vec()).map_err(|_| ApiError::bad("invalid_idempotency_key"))?;
    Ok(LoopbackReceiveSession::authenticated(grant.principal, key))
}

pub(super) fn admission_error(error: NodeReceiveTransportRefusal) -> ApiError {
    // Reusing a key is a request rejection, not a new terminal refusal.
    // Infrastructure failures remain ambiguous even after earlier work.
    if let NodeReceiveTransportRefusal::Admission(error) = &error {
        if matches!(error.as_ref(), AdmissionError::Seal(source)
            if matches!(source.as_ref(), SealFailure::Rejected(_)))
        { return ApiError::new(Status::Conflict, "idempotency_key_reuse"); }
    }
    ApiError::unknown()
}

/// Body framing is finished before admission. Once admission starts, its exact
/// terminal result wins over local timeout or connection status.
pub(super) fn execute(node: &OneNode, request: &Request<'_>, session: &LoopbackReceiveSession,
    framing: BodyFraming, reader: &mut impl Read, limits: HttpLimits, maximum_response: u64,
) -> Result<Reply, ApiError> {
    let principal = session.authenticated_session().ok_or_else(|| ApiError::new(Status::Unauthorized, "unauthorized"))?
        .principal_id();
    let command = if request.is_mutation() { Some(request.command(&read_form(reader, framing, limits)?)?) } else { None };
    let context = node.request_context();
    let deadline = GitDaemonSessionDeadline::new(node.git_daemon_session_timeout, GitDaemonSessionWorkScaling::FLAT);
    let mut live = || !deadline.expired();
    let maximum = usize::try_from(maximum_response).unwrap_or(usize::MAX).min(output::MAX_REPLY_BYTES);
    match &request.operation {
        Operation::List(page) => {
            let result = drive_request_while(node, &context,
                node.read_issues_in(&context, page.after, page.limit, page.expected_head), &mut live)?;
            Ok(Reply { status: Status::Success, body: output::list(node, *page, &result, maximum)?, terminal: None })
        }
        Operation::Show { number, page } => {
            let result = drive_request_while(node, &context,
                node.read_issue_history_in(&context, *number, page.after, page.limit, page.expected_head), &mut live)?;
            Ok(Reply { status: if result.issue.is_some() { Status::Success } else { Status::NotFound },
                body: output::history(node, *number, *page, &result, maximum)?, terminal: None })
        }
        Operation::Search => {
            let (query, parameters) = search::parse(&read_form(reader, framing, limits)?)?;
            let result = fgit_forge::issue_search::search(&query, parameters, |after, limit, expected_head| {
                let page = drive_request_while(node, &context,
                    node.read_issues_in(&context, after, limit, expected_head), &mut live)
                    .map_err(ApiError::from)?;
                Ok::<_, ApiError>(fgit_forge::issue_search::SourcePage {
                    source_head: page.source_head, issues: page.issues, next_after: page.next_after,
                })
            }).map_err(search::error)?;
            Ok(Reply { status: Status::Success,
                body: output::search(node, parameters, &query, &result, maximum, &mut live)?, terminal: None })
        }
        Operation::Mutate { .. } => {
            let command = command.ok_or_else(|| ApiError::bad("missing_command"))?;
            command.proposed_event(principal).map_err(|_| ApiError::bad("invalid_issue_command"))?;
            let (tx, terminal) = drive_request_while(node, &context,
                node.admit_issue_durable_in(&context, session, &command, Default::default()), &mut live)
                .map_err(admission_error)?;
            let body = output::mutation(node, principal, &command, tx, terminal);
            if body.len() > maximum {
                eprintln!("Issue HTTP response limit after canonical outcome for transaction {tx}");
                return Err(ApiError::unknown());
            }
            Ok(Reply { status: match terminal.outcome {
                DecisionOutcome::Committed { .. } => Status::Success,
                DecisionOutcome::Refused { .. } => Status::Conflict,
            }, body, terminal: Some((tx, terminal)) })
        }
    }
}

pub(super) fn read_form(reader: &mut impl Read, framing: BodyFraming, limits: HttpLimits) -> Result<Vec<u8>, ApiError> {
    let limits = HttpLimits {
        max_body_bytes: limits.max_body_bytes.min(request::MAX_FORM_BYTES as u64),
        max_body_wire_bytes: limits.max_body_wire_bytes.min((request::MAX_FORM_BYTES + 64 * 1024) as u64),
        max_chunks: limits.max_chunks.min(16_384),
        ..limits
    };
    let mut decoder = BodyDecoder::new(framing, limits)
        .map_err(|error| ApiError::from_status(Status::from(error), false))?;
    let mut form = Vec::new();
    BodyInput::Reader(reader).consume(&mut || true, |bytes, _| {
        let mut cursor = 0;
        while cursor < bytes.len() && !decoder.is_complete() {
            let step = decoder.push(&bytes[cursor..])?;
            if step.consumed == 0 { return Err(RpcError::IncompleteRequest); }
            let length = form.len().checked_add(step.data.len()).ok_or(HttpError::BodyTooLarge)?;
            if length > request::MAX_FORM_BYTES { return Err(HttpError::BodyTooLarge.into()); }
            form.try_reserve_exact(step.data.len()).map_err(|_| WireError::AllocationFailure)?;
            form.extend_from_slice(step.data);
            cursor += step.consumed;
        }
        Ok(RpcProgress { consumed: cursor, body_complete: decoder.is_complete(), decoded_body_bytes: decoder.decoded_bytes() })
    }).map_err(|error| ApiError::from_status(Status::from(error), false))?;
    decoder.finish().map_err(|error| ApiError::from_status(Status::from(error), false))?;
    Ok(form)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    #[test]
    fn form_intake_requires_the_complete_http_boundary_and_no_buffered_suffix() {
        for body in [b"3\r\na=b\r\n0\r\n\r\nNEXT".as_slice(), b"3\r\na=b\r\n0\r\n", b"3\r\na=b\r\n0\r\nX: y\r\n\r\n"] {
            assert!(read_form(&mut Cursor::new(body), BodyFraming::Chunked, HttpLimits::default()).is_err());
        }
        assert_eq!(read_form(&mut Cursor::new(b"3\r\na=b\r\n0\r\n\r\n"), BodyFraming::Chunked, HttpLimits::default()).unwrap(), b"a=b");
    }
    #[test]
    fn error_replies_are_json_self_delimited_and_do_not_invent_terminal_outcomes() {
        let mut out = Vec::new();
        ApiError::unknown().send(&mut out, HttpVersion::Http11).unwrap();
        let text = String::from_utf8(out).unwrap();
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("HTTP/1.1 503"));
        assert!(head.contains(&format!("Content-Length: {}", body.len())));
        assert!(body.contains("\"outcome_unknown\":true"));
        assert!(!body.contains("\"outcome\":\"refused\""));
    }
}
