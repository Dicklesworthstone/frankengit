//! Recognize typed cancellation ONLY on read-only source selection, before the
//! watcher reserves event custody. Never apply these predicates to execution or
//! publication: their ambiguous outcomes retain original reconciliation duties.

use crate::treefs_workspace::events::ForgeEventReadRefusal;
use crate::treefs_workspace::pull_request::PullRequestReadRefusal;
use crate::{AdmissionMaterializationRefusal, NodeRefusal};
use fgit_admission::AdmissionError;
use fgit_authority::{AmbiguityReason, AuthorityFailure, OutcomeFailure, SealFailure};
use fgit_types::RefusalCode;

const fn authority(error: &AuthorityFailure) -> bool {
    matches!(
        error,
        AuthorityFailure::Ambiguous(AmbiguityReason::Cancelled | AmbiguityReason::Timeout)
    )
}

fn outcome(error: &OutcomeFailure) -> bool {
    matches!(error, OutcomeFailure::Seal(error) if matches!(error.as_ref(), SealFailure::Store(error) if authority(error)))
}

pub(super) fn admission(error: &AdmissionError) -> bool {
    match error {
        AdmissionError::AsyncProjectionUnavailable(RefusalCode::CancellationInProgress) => true,
        AdmissionError::Authority(error) => authority(error),
        AdmissionError::Outcome(error) => outcome(error),
        _ => false,
    }
}

pub(super) fn materialization(error: &AdmissionMaterializationRefusal) -> bool {
    match error {
        AdmissionMaterializationRefusal::Cancelled => true,
        AdmissionMaterializationRefusal::Authority(error) => authority(error),
        AdmissionMaterializationRefusal::DecisionHistory(error) => outcome(error),
        AdmissionMaterializationRefusal::Delivery(error) => admission(error),
        _ => false,
    }
}

pub(super) fn node_read(error: &NodeRefusal) -> bool {
    match error {
        NodeRefusal::Authority(error) => outcome(error),
        NodeRefusal::AdmissionMaterialization(error) => materialization(error),
        _ => false,
    }
}

fn forge_read(error: &ForgeEventReadRefusal) -> bool {
    match error {
        ForgeEventReadRefusal::Cancelled => true,
        ForgeEventReadRefusal::Authority(error) => materialization(error),
        ForgeEventReadRefusal::Boundary(error) => outcome(error),
        ForgeEventReadRefusal::Admission(error) => admission(error),
        _ => false,
    }
}

pub(super) fn pull_request_read(error: &PullRequestReadRefusal) -> bool {
    match error {
        PullRequestReadRefusal::Selection(error) => forge_read(error),
        PullRequestReadRefusal::Authority(error) => materialization(error),
        PullRequestReadRefusal::Admission(error) => admission(error),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_authority::AuthorityRefusal;

    #[test]
    fn nested_read_cancellation_keeps_its_typed_stop_across_source_boundaries() {
        for reason in [AmbiguityReason::Cancelled, AmbiguityReason::Timeout] {
            let cancelled = AuthorityFailure::Ambiguous(reason);
            assert!(materialization(
                &AdmissionMaterializationRefusal::Authority(cancelled)
            ));
            assert!(materialization(
                &AdmissionMaterializationRefusal::DecisionHistory(Box::new(cancelled.into()))
            ));
            assert!(node_read(&NodeRefusal::Authority(Box::new(
                cancelled.into()
            ))));
            assert!(pull_request_read(&PullRequestReadRefusal::Selection(
                Box::new(ForgeEventReadRefusal::Boundary(Box::new(cancelled.into())),)
            )));
        }
        assert!(materialization(&AdmissionMaterializationRefusal::Cancelled));
        assert!(pull_request_read(&PullRequestReadRefusal::Admission(
            Box::new(AdmissionError::AsyncProjectionUnavailable(
                RefusalCode::CancellationInProgress
            ),)
        )));
    }

    #[test]
    fn corruption_unavailability_and_unrelated_ambiguity_never_become_idle_stop() {
        for error in [
            AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse),
            AuthorityFailure::Refused(AuthorityRefusal::Unavailable),
            AuthorityFailure::Refused(AuthorityRefusal::UnknownVersionToken),
        ] {
            assert!(!node_read(&NodeRefusal::Authority(Box::new(error.into()))));
        }
        assert!(!materialization(
            &AdmissionMaterializationRefusal::ExactBasisMismatch
        ));
        assert!(!materialization(
            &AdmissionMaterializationRefusal::DecisionHistory(Box::new(
                OutcomeFailure::StreamBodyMissing {
                    link: "cancelled is only text here"
                },
            ))
        ));
        assert!(!pull_request_read(&PullRequestReadRefusal::Admission(
            Box::new(AdmissionError::AsyncProjectionUnavailable(
                RefusalCode::EvidenceInvalid
            ),)
        )));
        assert!(!pull_request_read(&PullRequestReadRefusal::SnapshotMoved));
    }
}
