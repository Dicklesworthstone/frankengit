//! Explicit repository-wide workflow artifact custody reads. This independent
//! grant includes the complete configured namespace, including hidden-ref outputs.
//! Stored provenance and guessed IDs never supply permission or check authority.

use std::io::{self, Write};

use fgit_types::{Digest, PrincipalId};
use fgit_wire::smart_http::{BodyFraming, HttpVersion, head::Envelope};

use super::super::drive_request_while;
use super::issues::{self, ApiError};
use super::{Profile, Status};
use crate::workflow_artifacts::{WorkflowArtifactReadRefusal, parse_artifact_id};
use crate::{GitDaemonSessionDeadline, GitDaemonSessionTimeout, OneNode};

const ROUTE: &str = "/api/v1/artifacts";

pub(super) fn is_route(target: &str) -> bool {
    target
        .split('?')
        .next()
        .is_some_and(|path| path.contains(ROUTE))
}

#[derive(Debug)]
struct Request<'a> {
    repository_route: &'a str,
    id: Digest,
    id_hex: &'a str,
    content: bool,
}
impl<'a> Request<'a> {
    fn parse(
        envelope: &Envelope<'a>,
        raw_head: &[u8],
        read_ahead: &[u8],
    ) -> Result<Self, ApiError> {
        if envelope.method != "GET" {
            return Err(ApiError::method());
        }
        if envelope.target.contains('?') || envelope.git_protocol.is_some() {
            return Err(ApiError::bad("invalid_artifact_request"));
        }
        if !matches!(
            envelope.body,
            BodyFraming::Empty | BodyFraming::ContentLength(0)
        ) || envelope.expect_continue
            || !read_ahead.is_empty()
        {
            return Err(ApiError::bad("body_not_allowed"));
        }
        if super::retry_key(raw_head)
            .map_err(|_| ApiError::bad("invalid_idempotency_key"))?
            .is_some()
        {
            return Err(ApiError::bad("idempotency_key_not_allowed"));
        }
        let (repository_route, suffix) = envelope
            .target
            .rsplit_once("/api/v1/artifacts/")
            .ok_or_else(ApiError::not_found)?;
        if repository_route.is_empty() {
            return Err(ApiError::not_found());
        }
        let (id_hex, content) = suffix
            .strip_suffix("/content")
            .map_or((suffix, false), |id| (id, true));
        let id = parse_artifact_id(id_hex).map_err(read_error)?;
        Ok(Self {
            repository_route,
            id,
            id_hex,
            content,
        })
    }
}

fn authenticate(
    profile: &Profile,
    envelope: &Envelope<'_>,
    request: &Request<'_>,
) -> Result<PrincipalId, ApiError> {
    let grant = profile
        .credentials
        .authenticate(super::bearer_only(envelope.authorization()))
        .map_err(|error| ApiError::from_status(Status::from(error), false))?;
    if request.repository_route.as_bytes() != profile.route {
        return Err(ApiError::not_found());
    }
    if profile.config.workflow_artifact_root().is_none() || !grant.permits_artifact_read() {
        return Err(ApiError::new(
            Status::Forbidden,
            "artifact_read_not_granted",
        ));
    }
    Ok(grant.principal)
}

fn read_error(error: WorkflowArtifactReadRefusal) -> ApiError {
    let code = error.code();
    let status = match code {
        "artifact_storage_disabled" => Status::Forbidden,
        "invalid_artifact_id" => Status::BadRequest,
        "artifact_not_found" => Status::NotFound,
        "artifact_payload_limit" => Status::TooLarge,
        "artifact_request_expired" => Status::Timeout,
        _ => Status::Unavailable,
    };
    ApiError::new(status, code)
}

enum Reply {
    Metadata(String),
    Content { id_hex: String, bytes: Vec<u8> },
}

fn prepare(
    profile: &Profile,
    envelope: &Envelope<'_>,
    raw_head: &[u8],
    read_ahead: &[u8],
    deadline: &GitDaemonSessionDeadline,
) -> Result<(OneNode, Reply), ApiError> {
    let query = Request::parse(envelope, raw_head, read_ahead)?;
    let principal = authenticate(profile, envelope, &query)?;
    profile
        .source_quota
        .evaluate(&principal)
        .map_err(|_| ApiError::new(Status::RateLimited, "rate_limited"))?;
    let node = profile.nodes.lease().ok_or_else(ApiError::unavailable)?;
    let result = execute(&node, &query, deadline, profile.maximum_response_bytes);
    match result {
        Ok(reply) => Ok((node, reply)),
        Err(error) => {
            if let Err(cleanup) = node.shutdown() {
                super::log_cleanup(&cleanup);
                return Err(ApiError::new(
                    Status::Unavailable,
                    "artifact_storage_unavailable",
                ));
            }
            Err(error)
        }
    }
}

fn execute(
    node: &OneNode,
    query: &Request<'_>,
    deadline: &GitDaemonSessionDeadline,
    maximum: u64,
) -> Result<Reply, ApiError> {
    // Chunk verification is synchronous within the read future. Its native
    // context must inherit only the connection's remaining time, so chunk
    // checkpoints enforce ingress expiry even between async polls.
    let remaining = deadline
        .remaining()
        .map_err(|_| ApiError::new(Status::Timeout, "artifact_request_expired"))?;
    let timeout = GitDaemonSessionTimeout::try_new(remaining)
        .map_err(|_| ApiError::new(Status::Timeout, "artifact_request_expired"))?;
    let request = node.command_request_context(Some(timeout));
    let mut live = || !deadline.expired();
    if query.content {
        let payload = drive_request_while(
            node,
            &request,
            node.read_workflow_artifact_in(&request, &query.id),
            &mut live,
        )
        .map_err(read_error)?;
        if payload.bytes().len() as u64 > maximum {
            return Err(ApiError::too_large());
        }
        let (_, bytes) = payload.into_parts();
        Ok(Reply::Content {
            id_hex: query.id_hex.to_owned(),
            bytes,
        })
    } else {
        let metadata = drive_request_while(
            node,
            &request,
            node.inspect_workflow_artifact_in(&request, &query.id),
            &mut live,
        )
        .map_err(read_error)?;
        let json = metadata.to_json().map_err(read_error)?;
        if json.len() as u64 > maximum {
            return Err(ApiError::too_large());
        }
        Ok(Reply::Metadata(json))
    }
}

/// Verification and node reads finish before a successful HTTP byte escapes.
/// A response failure closes the read lane and never emits a second response.
pub(super) fn serve(
    profile: &Profile,
    envelope: &Envelope<'_>,
    raw_head: &[u8],
    read_ahead: &[u8],
    writer: &mut impl Write,
    deadline: &GitDaemonSessionDeadline,
) -> Result<(), Status> {
    let (node, reply) = match prepare(profile, envelope, raw_head, read_ahead, deadline) {
        Ok(value) => value,
        Err(error) => {
            let body = format!(
                "{{\"type\":\"artifact_error\",\"schema_version\":1,\"code\":{},\"read_only\":true,\"outcome_unknown\":false}}",
                issues::quote(error.code),
            );
            let _ = send(
                writer,
                envelope.version,
                error.status,
                body.as_bytes(),
                None,
            );
            return Err(error.status);
        }
    };
    let sent = match reply {
        Reply::Metadata(body) => send(
            writer,
            envelope.version,
            Status::Success,
            body.as_bytes(),
            None,
        ),
        Reply::Content { id_hex, bytes } => send(
            writer,
            envelope.version,
            Status::Success,
            &bytes,
            Some(&id_hex),
        ),
    };
    let cleanup = if sent.is_ok() {
        profile.nodes.restore(node)
    } else {
        node.shutdown()
    };
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
    body: &[u8],
    content_id: Option<&str>,
) -> io::Result<()> {
    let version = match version {
        HttpVersion::Http10 => "HTTP/1.0",
        HttpVersion::Http11 => "HTTP/1.1",
    };
    let media = if content_id.is_some() {
        "application/octet-stream"
    } else {
        "application/json; charset=utf-8"
    };
    let disposition = content_id.map_or_else(String::new, |id| {
        format!("Content-Disposition: attachment; filename=\"artifact-{id}\"\r\n")
    });
    let extra = match status {
        Status::Unauthorized => "WWW-Authenticate: Bearer realm=\"frankengit\"\r\n",
        Status::Method => "Allow: GET\r\n",
        Status::RateLimited => "Retry-After: 60\r\n",
        _ => "",
    };
    write!(
        writer,
        "{version} {}\r\nContent-Type: {media}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nVary: Authorization\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n{disposition}{extra}\r\n",
        status.line(),
        body.len()
    )?;
    writer.write_all(body)?;
    writer.flush()
}

#[cfg(test)]
mod tests;
