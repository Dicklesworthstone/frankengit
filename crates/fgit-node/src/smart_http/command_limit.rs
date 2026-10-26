//! Known pre-admission command-count refusals, shared by the Git carriers.
//! Other interruptions retain their existing unknown-outcome treatment.

use std::io::Write;

use fgit_admission::AdmissionError;
use fgit_wire::receive::ReceiveError;
use fgit_wire::smart_http::rpc::RpcError;
use fgit_wire::smart_http::{RequestHead, success_head};
use fgit_wire::{Packet, WireError, WireLimits, encode_packets};

use super::{NodeSmartHttpRefusal, write_response_part};

pub(super) fn before_admission(error: &NodeSmartHttpRefusal) -> Option<usize> {
    match error {
        NodeSmartHttpRefusal::Receive(error) => match error.as_ref() {
            ReceiveError::TooManyCommands { limit } => Some(*limit),
            _ => None,
        },
        NodeSmartHttpRefusal::Rpc(error) => match error.as_ref() {
            RpcError::Receive(ReceiveError::TooManyCommands { limit }) => Some(*limit),
            _ => None,
        },
        // Planning precedes session binding, sealing and publication. Never
        // infer non-commit from an interruption with a mapped session/prefix.
        NodeSmartHttpRefusal::ReceiveInterrupted(error)
            if error.session().is_none() && error.completed_commands().is_empty() =>
        {
            match error.admission_error() {
                AdmissionError::CommandLimitExceeded { limit } => Some(*limit),
                _ => None,
            }
        }
        _ => None,
    }
}

pub(super) fn message(limit: usize) -> Vec<u8> {
    format!(
        "ERR receive command count exceeded: observed at least {}; maximum {limit}; \
         split the push into batches of at most {limit} commands; \
         no ref decision was attempted\n",
        limit.saturating_add(1),
    )
    .into_bytes()
}

/// Emit a Git service result while retaining the typed refusal for the caller.
/// A parser refusal may precede completion of HTTP ingress; the connection
/// owner still applies its existing bounded close/drain policy, never admission.
pub(super) fn report_http(
    request: &RequestHead<'_>,
    error: &NodeSmartHttpRefusal,
    limits: &WireLimits,
    writer: &mut impl Write,
) -> Result<(), NodeSmartHttpRefusal> {
    let Some(limit) = before_admission(error) else {
        return Ok(());
    };
    let body = encode_packets(&[Packet::Data(message(limit)), Packet::Flush], limits)?;
    let length = u64::try_from(body.len()).map_err(|_| WireError::AllocationFailure)?;
    let head = success_head(request, Some(length));
    write_response_part(
        writer,
        head.as_bytes(),
        "write smart HTTP command-limit head",
    )?;
    write_response_part(writer, &body, "write smart HTTP command-limit refusal")?;
    writer.flush().map_err(|source| NodeSmartHttpRefusal::Io {
        operation: "flush smart HTTP command-limit refusal",
        source,
    })
}
