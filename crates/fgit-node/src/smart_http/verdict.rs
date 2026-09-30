//! One classification of authoritative receive refusals into per-command
//! verdicts, shared by the git-daemon and Smart HTTP receive paths.

use fgit_types::RefusalCode;
use fgit_wire::Packet;
use fgit_wire::receive::{
    ReceiveCommandStatus, ReceiveError, ReceiveLimits, ReceiveRequest, UnpackStatus, report_status,
};

/// The reason text for an authoritative handoff refusal that is a verdict on
/// the commands of a fully received pack, or `None` when it is not one.
///
/// Such a verdict means the pack framed and unpacked, the commands were judged,
/// and none was admitted, so upstream-compatible clients get report-status:
/// `unpack ok` and one `ng <ref> <reason>` per command, as git-receive-pack
/// reports a connectivity failure (frankengit-root-doctrine-x2mv.4.49).
/// Framing, resource, authority and cancellation codes are not verdicts; they
/// keep each transport's fatal path and never fabricate a per-ref rejection.
pub(super) fn command_verdict_phrase(code: RefusalCode) -> Option<&'static str> {
    Some(match code {
        RefusalCode::ObjectClosureIncomplete => "missing necessary objects",
        RefusalCode::EvidenceInvalid | RefusalCode::EvidenceMissing => {
            "object graph failed validation"
        }
        RefusalCode::NonFastForwardRefused => "non-fast-forward",
        RefusalCode::RefNameInvalid => "invalid ref name",
        RefusalCode::HashAlgorithmDomainMismatch => "object format mismatch",
        _ => return None,
    })
}

/// Report-status packets rejecting every command of `request` for `code`.
pub(super) fn command_verdict_report(
    request: &ReceiveRequest,
    code: RefusalCode,
    limits: &ReceiveLimits,
) -> Option<Result<Vec<Packet>, ReceiveError>> {
    let phrase = command_verdict_phrase(code)?;
    let message = format!("{phrase} ({code:?})").into_bytes();
    let statuses = vec![ReceiveCommandStatus::Rejected { message }; request.commands.len()];
    Some(report_status(request, UnpackStatus::Ok, &statuses, limits))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only verdicts on received commands become per-ref rejections; framing,
    /// resource, authority and cancellation codes keep the fatal path
    /// (frankengit-root-doctrine-x2mv.4.49).
    #[test]
    fn only_command_verdicts_become_per_ref_rejections() {
        for code in [
            RefusalCode::ObjectClosureIncomplete,
            RefusalCode::EvidenceInvalid,
            RefusalCode::EvidenceMissing,
            RefusalCode::NonFastForwardRefused,
            RefusalCode::RefNameInvalid,
            RefusalCode::HashAlgorithmDomainMismatch,
        ] {
            assert!(command_verdict_phrase(code).is_some(), "{code:?}");
        }
        for code in [
            RefusalCode::PackFramingInvalid,
            RefusalCode::ObjectHeaderInvalid,
            RefusalCode::ResourceBudgetExceeded,
            RefusalCode::DecompressionBudgetExceeded,
            RefusalCode::DeltaBudgetExceeded,
            RefusalCode::CancellationInProgress,
            RefusalCode::AuthorityReceiptStale,
            RefusalCode::AuthorityReceiptInvalid,
            RefusalCode::ThinPackBaseMissing,
            RefusalCode::NativeObjectIdMismatch,
        ] {
            assert!(command_verdict_phrase(code).is_none(), "{code:?}");
        }
    }
}
