//! Read-only preparation of an exact canonical queue prefix. The queue gateway
//! owns authentication and body admission; the native engine owns one-basis
//! selection, projected merges and the complete unpublished bundle.

mod output;
mod request;

use std::io::Read;

use fgit_forge::QueueNumber;
use fgit_forge::preparation::PreparationLimits;
use fgit_wire::smart_http::{BodyFraming, HttpLimits};
use fgit_wire::visibility::RefVisibility;

use super::super::Status;
use super::super::issues::{ApiError, read_form};
use super::super::pulls::{PreparationReply, candidate_preparation_error};
use crate::smart_http::drive_request_while;
use crate::{
    GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession, OneNode,
};

pub(super) fn execute(
    node: &OneNode,
    number: QueueNumber,
    session: &LoopbackReceiveSession,
    framing: BodyFraming,
    reader: &mut impl Read,
    limits: HttpLimits,
    maximum_response: u64,
) -> Result<PreparationReply, ApiError> {
    if session.authenticated_session().is_none() {
        return Err(ApiError::new(Status::Unauthorized, "unauthorized"));
    }
    let bytes = read_form(reader, framing, limits)?;
    let command = request::parse(&bytes, node.object_format, node.repository_incarnation_id())?;
    drop(bytes);
    let deadline = GitDaemonSessionDeadline::new(
        node.git_daemon_session_timeout,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let context = node.session_request_context(&deadline);
    let mut live = || !deadline.expired();
    let visibility = RefVisibility::new();
    let prepared = drive_request_while(
        node,
        &context,
        node.prepare_queue_prefix_bundle_in(
            &context,
            number,
            command.expected_version,
            &command.entries,
            &visibility,
            PreparationLimits::default(),
            command.profile,
        ),
        &mut live,
    )
    .map_err(|error| candidate_preparation_error(&error))?;
    drop(command);
    output::build(
        node,
        prepared,
        usize::try_from(maximum_response).unwrap_or(usize::MAX),
        &mut live,
    )
}
