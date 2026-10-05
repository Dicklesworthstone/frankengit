//! Authenticated, cursor-paged canonical metadata reads. The shared node reader
//! owns event selection, same-basis hidden-ref filtering and cursor advancement.

use std::collections::BTreeMap;
use std::io::{self, Write};

use fgit_types::{PrincipalId, RepositoryAuthorityHeadId};
use fgit_wire::smart_http::{BodyFraming, HttpVersion, head::Envelope};

use super::super::drive_request_while;
use super::issues::{self, ApiError};
use super::{Profile, Status};
use crate::{GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, OneNode};

const ROUTE: &str = "/api/v1/events";
const MAX_QUERY_BYTES: usize = 2048;

pub(super) fn is_route(target: &str) -> bool {
    target.split('?').next().is_some_and(|path| path.contains(ROUTE))
}

#[derive(Debug)]
struct Request<'a> {
    repository_route: &'a str,
    after: Option<(u64, u32)>,
    limit: u16,
    expected_head: Option<RepositoryAuthorityHeadId>,
}
impl<'a> Request<'a> {
    fn parse(envelope: &Envelope<'a>) -> Result<Self, ApiError> {
        let (path, query) = envelope.target.split_once('?').unwrap_or((envelope.target, ""));
        let repository_route = path.strip_suffix(ROUTE).ok_or_else(ApiError::not_found)?;
        if repository_route.is_empty() || query.len() > MAX_QUERY_BYTES {
            return Err(ApiError::bad("invalid_event_request"));
        }
        if envelope.method != "GET" {
            return Err(ApiError::method());
        }
        if !matches!(envelope.body, BodyFraming::Empty | BodyFraming::ContentLength(0))
            || envelope.expect_continue
        {
            return Err(ApiError::bad("body_not_allowed"));
        }
        if envelope.git_protocol.is_some() {
            return Err(ApiError::bad("git_protocol_not_applicable"));
        }
        let mut fields = BTreeMap::new();
        if !query.is_empty() {
            for (name, value) in issues::parse_form(query.as_bytes(), 3)? {
                if !matches!(name.as_str(), "after" | "limit" | "expected_head")
                    || fields.insert(name, value).is_some()
                {
                    return Err(ApiError::bad("invalid_event_query"));
                }
            }
        }
        let after = OneNode::parse_forge_event_feed_cursor(
            fields.get("after").map_or("0", String::as_str),
        ).map_err(|_| ApiError::bad("invalid_event_cursor"))?;
        let limit = fields.get("limit")
            .map(|value| issues::parse_decimal(value))
            .transpose()?.unwrap_or(20);
        if !(1..=100).contains(&limit) {
            return Err(ApiError::bad("invalid_event_limit"));
        }
        let expected_head = fields.get("expected_head")
            .map(|value| {
                if value.len() > 140 { return Err(ApiError::bad("invalid_snapshot_token")); }
                issues::parse_snapshot(value)
            }).transpose()?;
        Ok(Self { repository_route, after, limit: limit as u16, expected_head })
    }
}

#[derive(Clone, Copy, Debug)]
struct ReadGrant {
    principal: PrincipalId,
    issues: bool,
    pulls: bool,
}
fn authenticate(
    profile: &Profile,
    envelope: &Envelope<'_>,
    request: &Request<'_>,
) -> Result<ReadGrant, ApiError> {
    let grant = profile.credentials.authenticate(super::bearer_only(envelope.authorization()))
        .map_err(|error| ApiError::from_status(Status::from(error), false))?;
    if request.repository_route.as_bytes() != profile.route {
        return Err(ApiError::not_found());
    }
    let issues = profile.allow_issues && grant.permits_issues(false);
    let pulls = profile.allow_pulls && grant.permits_pulls(false);
    if !issues && !pulls {
        return Err(ApiError::new(Status::Forbidden, "events_not_granted"));
    }
    Ok(ReadGrant { principal: grant.principal, issues, pulls })
}

fn read_error(code: &'static str) -> ApiError {
    let status = match code {
        "invalid_event_limit" | "invalid_event_cursor" => Status::BadRequest,
        "snapshot_moved" => Status::Conflict,
        "events_not_granted" => Status::Forbidden,
        "event_response_limit" => Status::TooLarge,
        "event_read_cancelled" => Status::Timeout,
        _ => return ApiError::new(Status::Unavailable, "event_read_unavailable"),
    };
    ApiError::new(status, code)
}

/// No node is opened/leased before credentials, independent endpoint ceilings,
/// request shape and the principal's bounded read quota have passed. This uses
/// the expensive-read quota, never mutation or outcome-recovery quota.
fn prepare(
    profile: &Profile,
    envelope: &Envelope<'_>,
    read_ahead: &[u8],
) -> Result<(OneNode, String), ApiError> {
    let request = Request::parse(envelope)?;
    let grant = authenticate(profile, envelope, &request)?;
    if !read_ahead.is_empty() { return Err(ApiError::bad("body_not_allowed")); }
    profile.source_quota.evaluate(&grant.principal)
        .map_err(|_| ApiError::new(Status::RateLimited, "rate_limited"))?;
    let node = profile.nodes.lease().ok_or_else(ApiError::unavailable)?;
    let result = execute(&node, &request, grant, profile.maximum_response_bytes);
    match result {
        Ok(body) => Ok((node, body)),
        Err(error) => {
            if let Err(cleanup) = node.shutdown() {
                super::log_cleanup(&cleanup);
                return Err(ApiError::unavailable());
            }
            Err(error)
        }
    }
}
fn execute(
    node: &OneNode,
    query: &Request<'_>,
    grant: ReadGrant,
    maximum_response: u64,
) -> Result<String, ApiError> {
    let deadline = GitDaemonSessionDeadline::new(
        node.git_daemon_session_timeout, GitDaemonSessionWorkScaling::FLAT,
    );
    let request = node.session_request_context(&deadline);
    let page = drive_request_while(
        node, &request,
        node.read_scoped_forge_events_in(&request, query.after, query.limit, query.expected_head,
            grant.issues, grant.pulls),
        &mut || !deadline.expired(),
    ).map_err(|error| read_error(error.public_code()))?;
    let body = page.to_json().map_err(|error| read_error(error.public_code()))?;
    if body.len() as u64 > maximum_response {
        return Err(ApiError::too_large());
    }
    Ok(body)
}

/// The outer connection already tracks whether a final response has started.
/// A refusal is serialized here before returning Err; a failed success write or
/// post-response cleanup never emits a contradictory second HTTP response.
pub(super) fn serve(
    profile: &Profile,
    envelope: &Envelope<'_>,
    read_ahead: &[u8],
    writer: &mut impl Write,
) -> Result<(), Status> {
    let (node, body) = match prepare(profile, envelope, read_ahead) {
        Ok(prepared) => prepared,
        Err(error) => {
            let body = format!(
                "{{\"type\":\"event_error\",\"schema_version\":1,\"code\":{},\"read_only\":true,\"outcome_unknown\":false}}",
                issues::quote(error.code),
            );
            let _ = send(writer, envelope.version, error.status, &body);
            return Err(error.status);
        }
    };
    let sent = send(writer, envelope.version, Status::Success, &body);
    let cleanup = if sent.is_ok() { profile.nodes.restore(node) } else { node.shutdown() };
    if let Err(error) = cleanup {
        super::log_cleanup(&error);
        return Err(Status::Unavailable);
    }
    sent.map_err(|_| Status::Unavailable)
}
fn send(
    writer: &mut impl Write,
    version: HttpVersion,
    status: Status,
    body: &str,
) -> io::Result<()> {
    let version = match version { HttpVersion::Http10 => "HTTP/1.0", HttpVersion::Http11 => "HTTP/1.1" };
    let extra = match status {
        Status::Unauthorized => "WWW-Authenticate: Bearer realm=\"frankengit\"\r\n",
        Status::Method => "Allow: GET\r\n",
        Status::RateLimited => "Retry-After: 60\r\n",
        _ => "",
    };
    write!(writer,
        "{version} {}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nVary: Authorization\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n{extra}\r\n{body}",
        status.line(), body.len(),
    )?;
    writer.flush()
}

#[cfg(test)]
mod tests;
