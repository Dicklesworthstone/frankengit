//! Native linear rebase over the existing source gateway. Preparation,
//! resolution and inspection are reads; publication is an exact-old transaction.

mod inspection;
mod output;
mod request;
mod resolution;

use super::super::{
    Status,
    issues::{ApiError, MAX_FORM_BYTES, admission_error, read_form},
    pulls::{
        MAX_RESOLUTION_UPLOAD_BYTES, SourceUploadKind, read_resolution_upload, read_source_upload,
        resolution_upload_boundary, source_upload, source_upload_boundary,
    },
};
use super::Reply;
use crate::smart_http::drive_request_while;
use crate::{
    GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession,
    NodeWorkspaceRefusal, OneNode,
};
use fgit_forge::preparation::rebase::RebaseError;
use fgit_forge::preparation::resolution::ResolutionError;
use fgit_forge::preparation::{MergeSourceError, PreparationError};
use fgit_wire::smart_http::{BodyFraming, HttpLimits, head::Envelope};
use std::io::Read;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation {
    Prepare,
    Resolve,
    Inspect,
    Apply,
}
#[derive(Debug)]
pub(super) struct Request<'a> {
    pub(super) repository_route: &'a str,
    operation: Operation,
    boundary: Option<&'a str>,
}
impl<'a> Request<'a> {
    pub(super) fn parse(head: &Envelope<'a>) -> Result<Option<Self>, ApiError> {
        let (path, query) = head
            .target
            .split_once('?')
            .map_or((head.target, None), |(p, q)| (p, Some(q)));
        let Some((repository_route, action)) = path.split_once("/api/v1/source/") else {
            return Ok(None);
        };
        let operation = match action {
            "rebase/prepare" => Operation::Prepare,
            "rebase/resolve" => Operation::Resolve,
            "rebase/inspect" => Operation::Inspect,
            "rebase/apply" => Operation::Apply,
            _ => return Ok(None),
        };
        if repository_route.len() < 2
            || !repository_route.starts_with('/')
            || repository_route[1..].split('/').any(|part| {
                part.is_empty()
                    || matches!(part, "." | "..")
                    || !part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
            })
        {
            return Err(ApiError::not_found());
        }
        if head.method != "POST" {
            return Err(ApiError::method());
        }
        if query.is_some() || head.body == BodyFraming::Empty || head.git_protocol.is_some() {
            return Err(ApiError::bad("invalid_rebase_envelope"));
        }
        let media = head.content_type.ok_or_else(ApiError::media)?;
        let boundary = match operation {
            Operation::Prepare | Operation::Resolve
                if media.eq_ignore_ascii_case("application/x-www-form-urlencoded")
                    || media.eq_ignore_ascii_case(
                        "application/x-www-form-urlencoded; charset=utf-8",
                    ) =>
            {
                None
            }
            Operation::Resolve => Some(resolution_upload_boundary(media)?),
            Operation::Inspect | Operation::Apply => Some(source_upload_boundary(media)?),
            _ => return Err(ApiError::media()),
        };
        let maximum = match operation {
            Operation::Inspect | Operation::Apply => SourceUploadKind::Bundle.maximum(),
            Operation::Resolve if boundary.is_some() => MAX_RESOLUTION_UPLOAD_BYTES,
            _ => MAX_FORM_BYTES,
        };
        if matches!(head.body, BodyFraming::ContentLength(n) if n > maximum as u64) {
            return Err(ApiError::too_large());
        }
        Ok(Some(Self {
            repository_route,
            operation,
            boundary,
        }))
    }
    pub(super) fn is_mutation(&self) -> bool {
        self.operation == Operation::Apply
    }
}

pub(super) fn execute(
    node: &OneNode,
    request: &Request<'_>,
    session: &LoopbackReceiveSession,
    framing: BodyFraming,
    reader: &mut impl Read,
    http: HttpLimits,
    maximum_response: u64,
) -> Result<Reply, ApiError> {
    if request.operation == Operation::Inspect {
        return inspection::execute(
            node,
            request.boundary.ok_or_else(ApiError::media)?,
            session,
            framing,
            reader,
            http,
            maximum_response,
        )
        .map(Reply::json);
    }
    let authenticated = session
        .authenticated_session()
        .ok_or_else(|| ApiError::new(Status::Unauthorized, "unauthorized"))?;
    let bytes = if request.is_mutation() {
        read_source_upload(reader, framing, http, SourceUploadKind::Bundle)?
    } else if request.boundary.is_some() {
        read_resolution_upload(reader, framing, http)?
    } else {
        read_form(reader, framing, http)?
    };
    let context = node.request_context();
    let deadline = GitDaemonSessionDeadline::new(
        node.git_daemon_session_timeout,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let mut live = || !deadline.expired();
    let maximum = usize::try_from(maximum_response).unwrap_or(usize::MAX);
    if request.is_mutation() {
        let boundary = request.boundary.ok_or_else(ApiError::media)?;
        let (form, bundle) = source_upload(&bytes, boundary, SourceUploadKind::Bundle, &mut live)?;
        let command = request::Apply::parse(form, node.object_format)?;
        // The native publisher recovers a terminal transaction BEFORE mutable
        // source/onto or object checks. Never insert a fresh pre-read here.
        let result = drive_request_while(
            node,
            &context,
            node.apply_rebase_bundle_durable_in(
                &context,
                authenticated.principal_id(),
                authenticated.client_idempotency_key().as_bytes(),
                &command.reference,
                command.expected_source,
                command.onto,
                command.candidate,
                bundle,
            ),
            &mut live,
        )
        .map_err(publication_error)?;
        return output::publication(
            node,
            authenticated.principal_id(),
            &command,
            result,
            maximum,
        )
        .map(Reply::json);
    }
    let (command, recipes) = if request.operation == Operation::Resolve {
        let (command, recipes) =
            resolution::parse(&bytes, request.boundary, node.object_format, &mut live)?;
        (command, Some(recipes))
    } else {
        (request::Prepare::parse(&bytes, node.object_format)?, None)
    };
    // Recipes own only their exact bounded file bytes, not a second MIME copy.
    drop(bytes);
    let prepared = if let Some(recipes) = recipes.as_deref() {
        drive_request_while(
            node,
            &context,
            node.prepare_resolved_rebase_bundle_in(
                &context,
                &command.source,
                &command.onto_ref,
                command.inputs,
                &Default::default(),
                command.expected_head,
                &command.committer,
                command.limits,
                recipes,
            ),
            &mut live,
        )
    } else {
        drive_request_while(
            node,
            &context,
            node.prepare_rebase_bundle_in(
                &context,
                &command.source,
                &command.onto_ref,
                command.inputs,
                &Default::default(),
                command.expected_head,
                &command.committer,
                command.limits,
            ),
            &mut live,
        )
        .map(|artifact| (artifact, Vec::new()))
    };
    let (artifact, receipts) = prepared.map_err(|error| {
        if error.is_snapshot_moved() {
            ApiError::new(Status::Conflict, "source_snapshot_moved")
        } else if error.is_tip_moved() {
            ApiError::new(Status::Conflict, "rebase_tip_moved")
        } else if error.is_unavailable() {
            ApiError::not_found()
        } else if error.is_invalid_input() {
            ApiError::bad("invalid_rebase_inputs")
        } else if error.is_resource_refusal() {
            ApiError::too_large()
        } else if error.is_cancelled() {
            ApiError::from_status(Status::Timeout, false)
        } else if let Some(cause) = error.preparation_refusal() {
            rebase_error(cause)
        } else if let Some(cause) = error.source_refusal() {
            source_error(cause)
        } else {
            ApiError::unavailable()
        }
    })?;
    let resolution = recipes
        .as_deref()
        .map(|recipes| (recipes, receipts.as_slice()));
    output::build(
        node,
        &command,
        artifact.source_head,
        &artifact.outcome,
        artifact.bundle,
        (artifact.pack_objects, artifact.borrowed_objects),
        resolution,
        maximum,
        &mut live,
    )
    .map(Reply::candidate)
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
        PreparationError::InvalidLimits
        | PreparationError::InvalidMetadata
        | PreparationError::ObjectFormat => ApiError::bad("invalid_rebase_inputs"),
        PreparationError::Budget(_) => ApiError::too_large(),
        PreparationError::Source(error) => source_error(error),
        _ => ApiError::unavailable(),
    }
}
fn rebase_error(error: &RebaseError) -> ApiError {
    match error {
        RebaseError::UpstreamOutsideLinearHistory => {
            ApiError::new(Status::Conflict, "upstream_outside_linear_history")
        }
        RebaseError::MergeCommit { .. } => {
            ApiError::new(Status::Conflict, "merge_commits_not_supported")
        }
        RebaseError::Preparation(error) => preparation_error(error),
        RebaseError::DuplicateResolutionCommit(_) | RebaseError::ResolutionOutsideSuffix(_) => {
            ApiError::bad("invalid_rebase_resolution_subject")
        }
        RebaseError::Resolution { error, .. } => resolution_error(error),
        _ => ApiError::unavailable(),
    }
}
fn resolution_error(error: &ResolutionError) -> ApiError {
    match error {
        ResolutionError::Budget => ApiError::too_large(),
        ResolutionError::Preparation(error) => preparation_error(error),
        ResolutionError::Unresolved(_) => ApiError::new(Status::Conflict, "unresolved_conflicts"),
        ResolutionError::NoConflicts | ResolutionError::NonConflictPath(_) => {
            ApiError::new(Status::Conflict, "resolution_names_clean_step_or_path")
        }
        ResolutionError::MissingSide { .. } => {
            ApiError::new(Status::Conflict, "resolution_side_missing")
        }
        ResolutionError::ReconstructionMismatch => ApiError::unavailable(),
        _ => ApiError::bad("invalid_resolution_set"),
    }
}
fn publication_error(error: NodeWorkspaceRefusal) -> ApiError {
    match error {
        NodeWorkspaceRefusal::WorkspacePublication(error) => admission_error(*error),
        NodeWorkspaceRefusal::InvalidWorkspaceCandidate(_) => {
            ApiError::bad("invalid_rebase_candidate")
        }
        NodeWorkspaceRefusal::ObjectFormatMismatch => ApiError::bad("object_format_mismatch"),
        NodeWorkspaceRefusal::RefUnavailable => ApiError::not_found(),
        // Cancellation/store failure after admission began cannot prove rollback.
        _ => ApiError::unknown(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_wire::smart_http::head;
    #[test]
    fn prepare_and_apply_keep_distinct_media_and_mutation_semantics() {
        for (action, media, mutation) in [
            ("prepare", "application/x-www-form-urlencoded", false),
            ("resolve", "application/x-www-form-urlencoded", false),
            ("resolve", "multipart/form-data; boundary=x", false),
            ("inspect", "multipart/form-data; boundary=x", false),
            ("apply", "multipart/form-data; boundary=x", true),
        ] {
            let bytes = format!(
                "POST /r.git/api/v1/source/rebase/{action} HTTP/1.1\r\nHost: local\r\nContent-Type: {media}\r\nContent-Length: 1\r\n\r\n"
            );
            let parsed = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert_eq!(
                Request::parse(&parsed).unwrap().unwrap().is_mutation(),
                mutation
            );
            assert_eq!(
                super::super::Request::parse(&parsed).unwrap().is_mutation(),
                mutation
            );
            for invalid in [
                bytes.replace("POST ", "GET "),
                bytes.replace(" HTTP/1.1", "?force=true HTTP/1.1"),
                bytes.replace("Host: local", "Git-Protocol: version=2\r\nHost: local"),
            ] {
                let parsed = head::parse(invalid.as_bytes(), HttpLimits::default())
                    .unwrap()
                    .unwrap();
                assert!(Request::parse(&parsed).is_err());
            }
        }
        let bytes = b"POST /r.git/api/v1/source/rebase/inspect HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n\r\n";
        let parsed = head::parse(bytes, HttpLimits::default()).unwrap().unwrap();
        assert!(
            Request::parse(&parsed).is_err(),
            "an inspection cannot omit its actual bundle"
        );
    }
    #[test]
    fn preparation_errors_are_not_terminal_transactions_or_partial_successes() {
        let errors = [
            RebaseError::UpstreamOutsideLinearHistory,
            RebaseError::Preparation(PreparationError::Budget("private backend detail")),
            RebaseError::Preparation(PreparationError::Source(MergeSourceError::Cancelled)),
        ];
        for error in errors {
            let error = rebase_error(&error);
            assert!(!error.outcome_unknown);
            let mut response = Vec::new();
            error
                .send_named(
                    &mut response,
                    fgit_wire::smart_http::HttpVersion::Http11,
                    "source_error",
                )
                .unwrap();
            let text = String::from_utf8(response).unwrap();
            assert!(
                !text.contains("private backend detail") && !text.contains("\"state\":\"clean\"")
            );
        }
        assert!(
            publication_error(NodeWorkspaceRefusal::Cancelled { exhaustion: None }).outcome_unknown
        );
    }
}
