//! Remote review and merge composition over the existing native engines.
//! Votes validate the actual uploaded candidate without importing it. Merges
//! quarantine that candidate, then publish refs, PR state and outbox together.
//! No read-model approval or caller-computed closure authorizes publication.

mod multipart;
mod output;
mod request;
pub(super) mod resolution_upload;

use std::io::Read;
use fgit_authority::IdempotencyKey;
use fgit_forge::ExpectedVersion;
use fgit_types::DecisionOutcome;
use fgit_wire::smart_http::{BodyDecoder, BodyFraming, HttpError, HttpLimits, head::Envelope};
use fgit_wire::smart_http::rpc::{RpcError, RpcProgress};
use fgit_wire::visibility::RefVisibility;
use fgit_wire::WireError;
use crate::{GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession, NodeWorkspaceRefusal, OneNode};
use crate::smart_http::{drive_request_while, ingress::BodyInput};
use super::super::{Profile, Status, retry_key};
use super::super::issues::{ApiError, Reply, admission_error, read_form};
use request::{Command, Encoding, Operation};
pub(super) use request::Request;

pub(super) const CANDIDATE_UPLOAD_BYTES: usize = multipart::MAX_UPLOAD_BYTES;
pub(super) fn candidate_boundary(content_type: &str) -> Result<&str, ApiError> {
    multipart::boundary(content_type).map_err(|_| ApiError::media())
}
/// Inspection requires actual bytes even when a similar review is terminal.
/// The shared MIME parser still owns part order, byte bounds and delimiters.
pub(super) fn inspection_upload<'a>(bytes: &'a [u8], boundary: &str,
    live: &mut impl FnMut() -> bool,
) -> Result<(&'a [u8], &'a [u8]), ApiError> {
    let upload = multipart::parse(bytes, boundary, live).map_err(|error| match error {
        multipart::Error::Limit => ApiError::too_large(),
        multipart::Error::Framing => ApiError::bad("invalid_candidate_upload"),
        multipart::Error::Cancelled => ApiError::from_status(Status::Timeout, false),
    })?;
    let bundle = upload.bundle.filter(|bytes| !bytes.is_empty())
        .ok_or_else(|| ApiError::bad("candidate_bundle_required"))?;
    Ok((upload.command, bundle))
}

pub(super) fn authenticate(request: &Request<'_>, envelope: &Envelope<'_>,
    raw_head: &[u8], profile: &Profile,
) -> Result<LoopbackReceiveSession, ApiError> {
    let grant = profile.credentials.authenticate(envelope.authorization())
        .map_err(|error| ApiError::from_status(Status::from(error), false))?;
    if request.repository_route.as_bytes() != profile.route { return Err(ApiError::not_found()); }
    let permitted = match request.operation {
        Operation::List(_) => grant.permits_reviews(false),
        Operation::Review(_) => grant.permits_reviews(true),
        Operation::Merge => grant.permits_reviewed_merge(),
    };
    if !profile.allow_pulls || !permitted { return Err(ApiError::new(Status::Forbidden, "forbidden")); }
    let key = retry_key(raw_head).map_err(|_| ApiError::bad("invalid_idempotency_key"))?;
    let key = if request.is_mutation() { key.ok_or_else(|| ApiError::bad("idempotency_key_required"))? }
        else { b"review-read-no-publication".as_slice() };
    Ok(LoopbackReceiveSession::authenticated(grant.principal,
        IdempotencyKey::new(key.to_vec()).map_err(|_| ApiError::bad("invalid_idempotency_key"))?))
}

pub(super) fn execute(node: &OneNode, request: &Request<'_>, session: &LoopbackReceiveSession,
    framing: BodyFraming, reader: &mut impl Read, limits: HttpLimits, maximum_response: u64,
) -> Result<Reply, ApiError> {
    let authenticated = session.authenticated_session()
        .ok_or_else(|| ApiError::new(Status::Unauthorized, "unauthorized"))?;
    let bytes = if request.is_mutation() {
        match request.encoding {
            Encoding::Form => read_form(reader, framing, limits)?,
            Encoding::Multipart(_) => read_upload(reader, framing, limits)?,
        }
    } else { Vec::new() };
    let context = node.request_context();
    let deadline = GitDaemonSessionDeadline::new(node.git_daemon_session_timeout, GitDaemonSessionWorkScaling::FLAT);
    let mut live = || !deadline.expired();
    let maximum = usize::try_from(maximum_response).unwrap_or(usize::MAX).min(output::MAX_REPLY_BYTES);
    if let Operation::List(page) = request.operation {
        let visibility = RefVisibility::new();
        let result = drive_request_while(node, &context,
            node.read_reviews_in(&context, &visibility, request.number, page.after, page.limit, page.expected_head), &mut live)
            .map_err(|error| if error.is_snapshot_unavailable() { ApiError::snapshot_moved() } else { ApiError::unavailable() })?;
        return Ok(Reply { status: if result.is_some() { Status::Success } else { Status::NotFound },
            body: output::page(node, request.number, page, result.as_ref(), maximum)?, terminal: None });
    }
    let upload = match request.encoding {
        Encoding::Form => multipart::Upload { command: &bytes, bundle: None },
        Encoding::Multipart(boundary) => multipart::parse(&bytes, boundary, &mut live).map_err(|error| match error {
            multipart::Error::Limit => ApiError::too_large(),
            multipart::Error::Framing => ApiError::bad("invalid_candidate_upload"),
            multipart::Error::Cancelled => ApiError::from_status(Status::Timeout, false),
        })?,
    };
    if !live() { return Err(ApiError::from_status(Status::Timeout, false)); }
    let command = request.command(upload.command, node.object_format, authenticated.principal_id())?;
    let (tx, terminal) = match &command {
        Command::Review(command) => drive_request_while(node, &context,
            node.admit_candidate_review_durable_in(&context, session, command, upload.bundle, Default::default()), &mut live)
            .map_err(admission_error)?,
        Command::Merge { subject, candidate, required } => drive_request_while(node, &context,
            node.apply_reviewed_merge_bundle_durable_in(&context, authenticated.principal_id(),
                authenticated.client_idempotency_key().as_bytes(), request.number,
                ExpectedVersion::Exactly(subject.pull_request_version), &candidate.merge(subject),
                upload.bundle.unwrap_or(&[]), required.policy_epoch(), required.reviewers()), &mut live)
            .map_err(|error| match error {
                NodeWorkspaceRefusal::WorkspacePublication(source) => admission_error(*source),
                _ => ApiError::unknown(),
            })?,
    };
    // An authenticated terminal result wins over post-admission cancellation.
    let body = output::mutation(node, authenticated.principal_id(), &command, tx, terminal);
    if body.len() > maximum {
        eprintln!("Review/merge HTTP reply exceeds limit after canonical outcome for transaction {tx}; recover the original key");
        return Err(ApiError::unknown());
    }
    Ok(Reply { status: match terminal.outcome {
        DecisionOutcome::Committed { .. } => Status::Success,
        DecisionOutcome::Refused { .. } => Status::Conflict,
    }, body, terminal: Some((tx, terminal)) })
}

fn read_upload(reader: &mut impl Read, framing: BodyFraming, limits: HttpLimits) -> Result<Vec<u8>, ApiError> {
    read_upload_bounded(reader, framing, limits, multipart::MAX_UPLOAD_BYTES)
}

/// A consumer can narrow the existing candidate ingress envelope, never widen
/// it. Complete HTTP framing precedes any part parsing, staging or construction.
pub(super) fn read_upload_bounded(reader: &mut impl Read, framing: BodyFraming,
    limits: HttpLimits, maximum_bytes: usize,
) -> Result<Vec<u8>, ApiError> {
    if maximum_bytes > multipart::MAX_UPLOAD_BYTES { return Err(ApiError::too_large()); }
    let maximum = limits.max_body_bytes.min(maximum_bytes as u64);
    let limits = HttpLimits { max_body_bytes: maximum,
        max_body_wire_bytes: limits.max_body_wire_bytes.min(maximum + 1024 * 1024),
        max_chunks: limits.max_chunks.min(16_384), ..limits };
    let mut decoder = BodyDecoder::new(framing, limits)
        .map_err(|error| ApiError::from_status(Status::from(error), false))?;
    let mut body = Vec::new();
    BodyInput::Reader(reader).consume(&mut || true, |bytes, _| {
        let mut cursor = 0;
        while cursor < bytes.len() && !decoder.is_complete() {
            let step = decoder.push(&bytes[cursor..])?;
            if step.consumed == 0 { return Err(RpcError::IncompleteRequest); }
            let length = body.len().checked_add(step.data.len()).ok_or(HttpError::BodyTooLarge)?;
            if length as u64 > maximum { return Err(HttpError::BodyTooLarge.into()); }
            if length > body.capacity() {
                let capacity = length.max(body.capacity().saturating_mul(2)).min(maximum as usize);
                body.try_reserve_exact(capacity - body.len()).map_err(|_| WireError::AllocationFailure)?;
            }
            body.extend_from_slice(step.data);
            cursor += step.consumed;
        }
        Ok(RpcProgress { consumed: cursor, body_complete: decoder.is_complete(), decoded_body_bytes: decoder.decoded_bytes() })
    }).map_err(|error| ApiError::from_status(Status::from(error), false))?;
    decoder.finish().map_err(|error| ApiError::from_status(Status::from(error), false))?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    #[test]
    fn candidate_intake_finishes_at_http_framing_and_refuses_suffix_or_truncation() {
        for wire in [b"3\r\nabc\r\n0\r\n".as_slice(), b"3\r\nabc\r\n0\r\n\r\nNEXT"] {
            assert!(read_upload(&mut Cursor::new(wire), BodyFraming::Chunked, HttpLimits::default()).is_err());
        }
        assert_eq!(read_upload(&mut Cursor::new(b"3\r\nabc\r\n0\r\n\r\n"), BodyFraming::Chunked, HttpLimits::default()).unwrap(), b"abc");
        let limits = HttpLimits { max_body_bytes: 2, ..HttpLimits::default() };
        assert!(read_upload(&mut Cursor::new(b"abc"), BodyFraming::ContentLength(3), limits).is_err());
        assert!(read_upload_bounded(&mut Cursor::new(b"abc"), BodyFraming::ContentLength(3), HttpLimits::default(), 2).is_err());
    }
    #[test]
    fn inspection_cannot_use_the_terminal_review_retry_without_a_bundle() {
        let command = b"--x\r\nContent-Disposition: form-data; name=\"command\"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na=b\r\n--x--\r\n";
        assert!(multipart::parse(command, "x", &mut || true).is_ok());
        assert_eq!(inspection_upload(command, "x", &mut || true).unwrap_err().code, "candidate_bundle_required");
    }
}
