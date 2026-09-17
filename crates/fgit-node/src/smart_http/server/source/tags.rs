//! Native tag lifecycle without HTTP-local tag state or trusted metadata.
//! The source gateway authenticates repository-scoped grants before intake;
//! the existing node owns quarantine, ref protection, sealing and publication.

mod request;
mod output;

use std::io::Read;
use fgit_forge::tags::TagRefusal;
use fgit_wire::smart_http::{BodyFraming, HttpLimits, head::Envelope};
use fgit_wire::visibility::RefVisibility;
use crate::{GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession,
    NodeWorkspaceRefusal, OneNode};
use crate::smart_http::drive_request_while;
use super::super::issues::{ApiError, Reply, admission_error, read_form};
use super::super::Status;
use request::Command;

#[derive(Debug)]
pub(super) struct Request<'a>(request::Request<'a>);
impl<'a> Request<'a> {
    pub(super) fn parse(envelope: &Envelope<'a>) -> Result<Option<Self>, ApiError> {
        request::Request::parse(envelope).map(|request| request.map(Self))
    }
    pub(super) fn is_mutation(&self) -> bool { self.0.is_mutation() }
    pub(super) fn route(&self) -> &str { self.0.repository_route }
}

pub(super) fn execute(node: &OneNode, request: &Request<'_>, session: &LoopbackReceiveSession,
    framing: BodyFraming, reader: &mut impl Read, limits: HttpLimits, maximum_response: u64,
) -> Result<Reply, ApiError> {
    let authenticated = session.authenticated_session()
        .ok_or_else(|| ApiError::new(Status::Unauthorized, "unauthorized"))?;
    // Complete HTTP framing precedes command parsing and all canonical work.
    // An annotation carries bounded metadata, never caller-computed proof.
    let command = request.0.command(&read_form(reader, framing, limits)?, node.object_format)?;
    let context = node.request_context();
    let deadline = GitDaemonSessionDeadline::new(node.git_daemon_session_timeout, GitDaemonSessionWorkScaling::FLAT);
    let mut live = || !deadline.expired();
    let maximum = usize::try_from(maximum_response).unwrap_or(usize::MAX).min(output::MAX_REPLY_BYTES);
    match command {
        Command::Inspect(query) => {
            let visibility = RefVisibility::new();
            let report = drive_request_while(node, &context,
                node.read_tag_in(&context, &query.reference, &visibility, query.expected_head, query.limits),
                &mut live).map_err(read_error)?;
            // This compares the selected ref value, never authorizes an OID
            // lookup. The native report's head and complete peel chain agree.
            if query.expected_object.is_some_and(|expected| expected != report.tip) {
                return Err(ApiError::new(Status::Conflict, "tag_object_moved"));
            }
            let body = output::inspection(node, &query, &report, maximum, &mut live)?;
            Ok(Reply { status: Status::Success, body, terminal: None })
        }
        Command::Mutate(command) => {
            let prepared = command.prepare(node.object_format).map_err(|_| ApiError::bad("invalid_tag_command"))?;
            // Do not pre-read/refetch a newer tip. Native terminal retry recovery
            // must still work after deletion or movement. Annotation metadata is
            // bound by its native tag OID within the ordinary sealed ref request.
            let result = drive_request_while(node, &context,
                node.admit_tag_durable_in(&context, session, &command, Default::default()),
                &mut live).map_err(publication_error)?;
            // A returned canonical decision wins over subsequent cancellation.
            output::publication(node, authenticated.principal_id(), request.0.operation,
                &prepared.command, &result, maximum)
        }
    }
}
fn read_error(error: NodeWorkspaceRefusal) -> ApiError {
    match error {
        NodeWorkspaceRefusal::Tag(TagRefusal::SnapshotMoved) => ApiError::new(Status::Conflict, "source_snapshot_moved"),
        NodeWorkspaceRefusal::Tag(TagRefusal::Budget(_)) => ApiError::too_large(),
        NodeWorkspaceRefusal::Tag(TagRefusal::InvalidName | TagRefusal::InvalidLimits | TagRefusal::ObjectFormat) =>
            ApiError::bad("invalid_tag_query"),
        NodeWorkspaceRefusal::Tag(_) => ApiError::unavailable(),
        error => super::read_error(error),
    }
}
fn publication_error(error: NodeWorkspaceRefusal) -> ApiError {
    match error {
        NodeWorkspaceRefusal::WorkspacePublication(source) => admission_error(*source),
        NodeWorkspaceRefusal::RefUnavailable => ApiError::not_found(),
        NodeWorkspaceRefusal::Tag(TagRefusal::InvalidName | TagRefusal::InvalidMetadata | TagRefusal::ObjectFormat) =>
            ApiError::bad("invalid_tag_command"),
        // Awaited infrastructure and cancellation failures never establish
        // non-commit. The original key remains the outcome-recovery selector.
        _ => ApiError::unknown(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tag_read_failures_never_invent_absence_or_mutation_outcomes() {
        assert_eq!(read_error(NodeWorkspaceRefusal::Tag(TagRefusal::SnapshotMoved)).status, Status::Conflict);
        for reason in [TagRefusal::InvalidObject, TagRefusal::TargetKindMismatch, TagRefusal::Cycle] {
            let error = read_error(NodeWorkspaceRefusal::Tag(reason));
            assert_eq!(error.status, Status::Unavailable); assert!(!error.outcome_unknown);
        }
        assert_eq!(read_error(NodeWorkspaceRefusal::RefUnavailable).status, Status::NotFound);
    }
    #[test]
    fn publication_cancellation_preserves_ambiguity_but_syntax_does_not() {
        assert!(publication_error(NodeWorkspaceRefusal::Cancelled { exhaustion: None }).outcome_unknown);
        assert!(!publication_error(NodeWorkspaceRefusal::Tag(TagRefusal::InvalidName)).outcome_unknown);
        assert!(!read_error(NodeWorkspaceRefusal::Cancelled { exhaustion: None }).outcome_unknown);
    }
}
