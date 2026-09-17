//! Authenticated one-commit cherry-pick and revert preparation. The source
//! gateway owns read authorization before intake. Publishing is a separate
//! ordinary source/apply request, never an implicit consequence of preparation.

mod request;
mod output;
mod resolution;

use std::io::Read;
use fgit_forge::preparation::{MergeSourceError, PreparationError};
use fgit_forge::preparation::replay::{ReplayDirection, ReplayError};
use fgit_wire::smart_http::{BodyFraming, HttpLimits, head::Envelope};
use crate::{GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession, OneNode};
use crate::smart_http::drive_request_while;
use super::artifact::PreparedReply;
use super::super::{Status, issues::{ApiError, MAX_FORM_BYTES, read_form},
    pulls::{MAX_RESOLUTION_UPLOAD_BYTES, read_resolution_upload, resolution_upload_boundary}};
use request::Command;

#[derive(Debug)]
pub(super) struct Request<'a> {
    pub(super) repository_route: &'a str,
    direction: ReplayDirection,
    resolving: bool,
    boundary: Option<&'a str>,
}
impl<'a> Request<'a> {
    pub(super) fn parse(head: &Envelope<'a>) -> Result<Option<Self>, ApiError> {
        let (path, query) = head.target.split_once('?').map_or((head.target, None), |(p, q)| (p, Some(q)));
        let Some((repository_route, action)) = path.split_once("/api/v1/source/") else { return Ok(None); };
        let (direction, resolving) = match action {
            "cherry-pick/prepare" => (ReplayDirection::CherryPick, false),
            "revert/prepare" => (ReplayDirection::Revert, false),
            "cherry-pick/resolve" => (ReplayDirection::CherryPick, true),
            "revert/resolve" => (ReplayDirection::Revert, true),
            _ => return Ok(None),
        };
        if repository_route.len() < 2 || !repository_route.starts_with('/')
            || repository_route[1..].split('/').any(|part| part.is_empty() || matches!(part, "." | "..")
                || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b)))
        { return Err(ApiError::not_found()); }
        if head.method != "POST" { return Err(ApiError::method()); }
        if query.is_some() || head.body == BodyFraming::Empty || head.git_protocol.is_some() {
            return Err(ApiError::bad("invalid_replay_envelope"));
        }
        let media = head.content_type.ok_or_else(ApiError::media)?;
        let boundary = if media.eq_ignore_ascii_case("application/x-www-form-urlencoded")
            || media.eq_ignore_ascii_case("application/x-www-form-urlencoded; charset=utf-8") {
            None
        } else if resolving { Some(resolution_upload_boundary(media)?) }
        else { return Err(ApiError::media()); };
        let maximum = if boundary.is_some() { MAX_RESOLUTION_UPLOAD_BYTES } else { MAX_FORM_BYTES };
        if matches!(head.body, BodyFraming::ContentLength(n) if n > maximum as u64) {
            return Err(ApiError::too_large());
        }
        Ok(Some(Self { repository_route, direction, resolving, boundary }))
    }
}

pub(super) fn execute(node: &OneNode, request: &Request<'_>, session: &LoopbackReceiveSession,
    framing: BodyFraming, reader: &mut impl Read, limits: HttpLimits, maximum_response: u64,
) -> Result<PreparedReply, ApiError> {
    if session.authenticated_session().is_none() { return Err(ApiError::new(Status::Unauthorized, "unauthorized")); }
    let bytes = if request.boundary.is_some() { read_resolution_upload(reader, framing, limits)? }
        else { read_form(reader, framing, limits)? };
    let context = node.request_context();
    let deadline = GitDaemonSessionDeadline::new(node.git_daemon_session_timeout, GitDaemonSessionWorkScaling::FLAT);
    let mut live = || !deadline.expired();
    let (command, choices) = if request.resolving {
        let (command, choices) = resolution::parse(&bytes, request.boundary, node.object_format, request.direction, &mut live)?;
        (command, Some(choices))
    } else { (Command::parse(&bytes, node.object_format, request.direction)?, None) };
    // Exact choices now own their bytes. Do not retain a second upload-sized
    // buffer during native conflict discovery, reconstruction and packaging.
    drop(bytes);
    let prepared = if let Some(choices) = choices.as_deref() {
        drive_request_while(node, &context,
            node.prepare_resolved_replay_bundle_in(&context, &command.target, &command.source,
                command.inputs, &Default::default(), command.expected_head, choices, &command.metadata, command.limits),
            &mut live).map(|resolved| (resolved.artifact, resolved.resolutions))
    } else {
        drive_request_while(node, &context,
            node.prepare_replay_bundle_in(&context, &command.target, &command.source,
                command.inputs, &Default::default(), command.expected_head, &command.metadata, command.limits),
            &mut live).map(|artifact| (artifact, Vec::new()))
    };
    let (artifact, receipts) = prepared.map_err(|error| {
        if error.is_snapshot_moved() { ApiError::new(Status::Conflict, "source_snapshot_moved") }
        else if error.is_tip_moved() { ApiError::new(Status::Conflict, "replay_tip_moved") }
        else if error.is_unavailable() { ApiError::not_found() }
        else if error.is_invalid_input() { ApiError::bad("invalid_replay_inputs") }
        else if error.is_resource_refusal() { ApiError::too_large() }
        else if error.is_cancelled() { ApiError::from_status(Status::Timeout, false) }
        else if let Some(cause) = error.preparation_refusal() { replay_error(cause) }
        else if let Some(cause) = error.source_refusal() { source_error(cause) }
        else { ApiError::unavailable() }
    })?;
    let resolutions = choices.as_deref().map(|choices| (choices, receipts.as_slice()));
    output::build(node, &command, artifact.source_head, &artifact.outcome, artifact.bundle,
        (artifact.pack_objects, artifact.borrowed_objects), resolutions,
        usize::try_from(maximum_response).unwrap_or(usize::MAX), &mut live)
}
fn source_error(error: &MergeSourceError) -> ApiError {
    match error {
        MergeSourceError::Cancelled => ApiError::from_status(Status::Timeout, false),
        MergeSourceError::BudgetExceeded => ApiError::too_large(),
        _ => ApiError::unavailable(),
    }
}
fn preparation_error(error: &PreparationError) -> ApiError {
    match error {
        PreparationError::InvalidLimits | PreparationError::InvalidMetadata | PreparationError::ObjectFormat => ApiError::bad("invalid_replay_inputs"),
        PreparationError::Budget(_) => ApiError::too_large(),
        PreparationError::Source(error) => source_error(error),
        _ => ApiError::unavailable(),
    }
}
fn replay_error(error: &ReplayError) -> ApiError {
    match error {
        ReplayError::MainlineRequired { .. } => ApiError::new(Status::Conflict, "mainline_required"),
        ReplayError::InvalidMainline { .. } => ApiError::bad("invalid_mainline"),
        ReplayError::CommitOutsideSourceHistory => ApiError::not_found(),
        ReplayError::Preparation(error) => preparation_error(error),
        ReplayError::Resolution(error) => resolution::failure(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_wire::smart_http::head;
    #[test]
    fn exact_routes_select_direction_without_granting_mutation() {
        for (action, direction) in [("cherry-pick/prepare", ReplayDirection::CherryPick), ("revert/prepare", ReplayDirection::Revert)] {
            let bytes = format!("POST /repo.git/api/v1/source/{action} HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n\r\n");
            let envelope = head::parse(bytes.as_bytes(), HttpLimits::default()).unwrap().unwrap();
            assert_eq!(Request::parse(&envelope).unwrap().unwrap().direction, direction);
        }
        for (method, action, extra) in [("GET", "revert/prepare", ""),
            ("POST", "cherry-pick/prepare?commit=secret", ""),
            ("POST", "revert/prepare", "Git-Protocol: version=2\r\n")]
        {
            let bytes = format!("{method} /repo.git/api/v1/source/{action} HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n{extra}\r\n");
            let envelope = head::parse(bytes.as_bytes(), HttpLimits::default()).unwrap().unwrap();
            assert!(Request::parse(&envelope).is_err());
        }
    }
    #[test]
    fn history_authorization_refusal_never_discloses_ids_or_invents_no_change() {
        let failures = [ReplayError::CommitOutsideSourceHistory,
            ReplayError::MainlineRequired { parents: 2 }, ReplayError::InvalidMainline { requested: 3, parents: 2 },
            ReplayError::Preparation(PreparationError::Source(MergeSourceError::Cancelled)),
            ReplayError::Preparation(PreparationError::Budget("not disclosed"))];
        for failure in failures {
            let error = replay_error(&failure); assert!(!error.outcome_unknown);
            let mut wire = Vec::new();
            error.send_named(&mut wire, fgit_wire::smart_http::HttpVersion::Http11, "source_error").unwrap();
            let wire = String::from_utf8(wire).unwrap();
            assert!(!wire.contains("no_change") && !wire.contains("not disclosed"));
        }
    }
    #[test]
    fn file_uploads_are_only_accepted_for_explicit_resolution_reads() {
        for action in ["cherry-pick", "revert"] {
            for media in ["application/x-www-form-urlencoded", "multipart/form-data; boundary=replay"] {
                let bytes = format!("POST /repo.git/api/v1/source/{action}/resolve HTTP/1.1\r\nHost: local\r\nContent-Type: {media}\r\nContent-Length: 1\r\n\r\n");
                let envelope = head::parse(bytes.as_bytes(), HttpLimits::default()).unwrap().unwrap();
                let parsed = Request::parse(&envelope).unwrap().unwrap();
                assert!(parsed.resolving);
                assert_eq!(parsed.boundary.is_some(), media.starts_with("multipart/"));
                assert!(!super::super::Request::parse(&envelope).unwrap().is_mutation());
                if media.starts_with("multipart/") {
                    let automatic = bytes.replace("/resolve HTTP", "/prepare HTTP");
                    let envelope = head::parse(automatic.as_bytes(), HttpLimits::default()).unwrap().unwrap();
                    assert!(Request::parse(&envelope).is_err());
                }
            }
        }
    }
}
