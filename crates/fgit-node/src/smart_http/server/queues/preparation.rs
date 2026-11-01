//! Body-bearing, read-only construction of one exact canonical queue head.
//! The queue gateway has already required fetch, PR-read and queue-read on a
//! single credential. Native preparation owns selection, visibility and bytes.

mod request;

use std::io::Read;

use fgit_forge::QueueNumber;
use fgit_forge::preparation::PreparationLimits;
use fgit_wire::smart_http::{BodyFraming, HttpLimits};
use fgit_wire::visibility::RefVisibility;

use super::super::Status;
use super::super::issues::{ApiError, MAX_FORM_BYTES, read_form};
use super::super::pulls::{PreparationReply, candidate_preparation_error, queue_preparation_reply};
use crate::smart_http::drive_request_while;
use crate::{
    GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession, OneNode,
};

// Shared form decoding enforces this bound before growth for both fixed and
// chunked requests. It also permits the native 64 KiB message as exact hex.
pub(super) const MAX_COMMAND_BYTES: usize = MAX_FORM_BYTES;

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
    // Only typed, bounded metadata remains while the native graph and pack
    // engine runs; do not retain a second HTTP input allocation.
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
        node.prepare_queue_head_bundle_with_profile_in(
            &context,
            number,
            command.expected_version,
            &command.subject,
            &visibility,
            &command.metadata,
            PreparationLimits::default(),
            command.profile,
        ),
        &mut live,
    )
    .map_err(|error| candidate_preparation_error(&error))?;
    queue_preparation_reply(
        node,
        prepared,
        command.profile,
        usize::try_from(maximum_response).unwrap_or(usize::MAX),
        &mut live,
    )
}
