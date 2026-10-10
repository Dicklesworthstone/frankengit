//! Binary blob proofs under the existing authenticated source-read gate.
//! The required head is a comparison, never a server-issued client trust pin.

use std::collections::BTreeMap;
use std::io::{self, Write};

use fgit_types::{RefName, RepositoryAuthorityHeadId};
use fgit_verified_read::blob::{MAX_VERIFIED_BLOB_FRAME_BYTES, encode_verified_blob_envelope};
use fgit_wire::smart_http::{BodyFraming, HttpVersion, head::Envelope};
use fgit_wire::visibility::RefVisibility;

use super::super::issues::{ApiError, parse_form, parse_snapshot};
use super::{
    GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession, OneNode, Status,
    drive_request_while,
};
use crate::VerifiedBlobReadRefusal;

const MEDIA_TYPE: &str = "application/vnd.frankengit.verified-blob";

#[derive(Debug)]
pub(super) struct Request<'a> {
    pub(super) repository_route: &'a str,
    query: &'a str,
}

impl<'a> Request<'a> {
    pub(super) fn parse(head: &Envelope<'a>) -> Result<Option<Self>, ApiError> {
        let (path, query) = head
            .target
            .split_once('?')
            .map_or((head.target, None), |(path, query)| (path, Some(query)));
        let Some((repository_route, action)) = path.split_once("/api/v1/source/") else {
            return Ok(None);
        };
        if action != "verified-blob" {
            return Ok(None);
        }
        if repository_route.len() < 2
            || !repository_route.starts_with('/')
            || repository_route[1..].split('/').any(|part| {
                part.is_empty()
                    || matches!(part, "." | "..")
                    || !part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte))
            })
        {
            return Err(ApiError::not_found());
        }
        if head.method != "GET" {
            return Err(ApiError::method());
        }
        if !matches!(
            head.body,
            BodyFraming::Empty | BodyFraming::ContentLength(0)
        ) || head.content_type.is_some()
            || head.git_protocol.is_some()
        {
            return Err(ApiError::bad("invalid_verified_blob_envelope"));
        }
        let query = query
            .filter(|query| !query.is_empty() && query.len() <= 12 * 1024)
            .ok_or_else(|| ApiError::bad("verified_blob_selection_required"))?;
        Ok(Some(Self {
            repository_route,
            query,
        }))
    }

    fn selection(&self) -> Result<Selection, ApiError> {
        let mut fields = BTreeMap::new();
        for (name, value) in parse_form(self.query.as_bytes(), 3)? {
            if !matches!(name.as_str(), "ref_hex" | "path_hex" | "expected_head")
                || fields.insert(name, value).is_some()
            {
                return Err(ApiError::bad("unknown_or_duplicate_verified_blob_field"));
            }
        }
        let mut take = |name| {
            fields
                .remove(name)
                .ok_or_else(|| ApiError::bad("verified_blob_selection_required"))
        };
        let reference = RefName::try_new(&unhex(&take("ref_hex")?, 1024)?)
            .map_err(|_| ApiError::bad("invalid_ref"))?;
        let path = unhex(&take("path_hex")?, 4096)?;
        if path.split(|byte| *byte == b'/').any(|part| {
            part.is_empty()
                || part.len() > 255
                || part == b"."
                || part == b".."
                || part.contains(&0)
        }) || path.split(|byte| *byte == b'/').count() > 64
        {
            return Err(ApiError::bad("invalid_verified_blob_path"));
        }
        let expected_head = parse_snapshot(&take("expected_head")?)?;
        Ok(Selection {
            reference,
            path,
            expected_head,
        })
    }
}

struct Selection {
    reference: RefName,
    path: Vec<u8>,
    expected_head: RepositoryAuthorityHeadId,
}

fn unhex(text: &str, maximum: usize) -> Result<Vec<u8>, ApiError> {
    if text.is_empty()
        || !text.len().is_multiple_of(2)
        || text.len() > maximum * 2
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApiError::bad("invalid_hex_bytes"));
    }
    let digit = |byte| {
        if byte <= b'9' {
            byte - b'0'
        } else {
            byte - b'a' + 10
        }
    };
    Ok(text
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| digit(pair[0]) << 4 | digit(pair[1]))
        .collect())
}

pub(super) fn execute(
    node: &OneNode,
    request: &Request<'_>,
    session: &LoopbackReceiveSession,
    maximum_response: u64,
) -> Result<Reply, ApiError> {
    if session.authenticated_session().is_none() {
        return Err(ApiError::new(Status::Unauthorized, "unauthorized"));
    }
    let selected = request.selection()?;
    let deadline = GitDaemonSessionDeadline::new(
        node.git_daemon_session_timeout,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let context = node.session_request_context(&deadline);
    let envelope = drive_request_while(
        node,
        &context,
        node.verified_blob_in(
            &context,
            &RefVisibility::new(),
            &selected.reference,
            &selected.path,
            selected.expected_head,
        ),
        &mut || !deadline.expired(),
    )
    .map_err(read_error)?;
    if deadline.expired() {
        return Err(ApiError::from_status(Status::Timeout, false));
    }
    let body = encode_verified_blob_envelope(&envelope).map_err(|_| ApiError::unavailable())?;
    if body.len() > MAX_VERIFIED_BLOB_FRAME_BYTES || body.len() as u64 > maximum_response {
        return Err(ApiError::too_large());
    }
    if deadline.expired() {
        return Err(ApiError::from_status(Status::Timeout, false));
    }
    Ok(Reply { body })
}

fn read_error(error: VerifiedBlobReadRefusal) -> ApiError {
    match error {
        VerifiedBlobReadRefusal::InvalidRequest(_) => ApiError::bad("invalid_verified_blob_query"),
        VerifiedBlobReadRefusal::Cancelled => ApiError::from_status(Status::Timeout, false),
        VerifiedBlobReadRefusal::RefUnavailable | VerifiedBlobReadRefusal::PathUnavailable => {
            ApiError::not_found()
        }
        VerifiedBlobReadRefusal::SnapshotMoved => ApiError::snapshot_moved(),
        VerifiedBlobReadRefusal::UnsupportedLayout => {
            ApiError::new(Status::Conflict, "verified_blob_layout_unavailable")
        }
        _ => ApiError::unavailable(),
    }
}

/// Proof and native bytes are complete before any successful header is sent.
pub(super) struct Reply {
    body: Vec<u8>,
}
impl Reply {
    pub(super) fn send(&self, writer: &mut impl Write, version: HttpVersion) -> io::Result<()> {
        let version = match version {
            HttpVersion::Http10 => "HTTP/1.0",
            HttpVersion::Http11 => "HTTP/1.1",
        };
        write!(
            writer,
            "{version} 200 OK\r\nContent-Type: {MEDIA_TYPE}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nPragma: no-cache\r\nVary: Authorization\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
            self.body.len()
        )?;
        for chunk in self.body.chunks(64 * 1024) {
            writer.write_all(chunk)?;
        }
        writer.flush()
    }
}

#[cfg(test)]
mod tests;
