use super::*;

fn wrapped(failure: AuthorityFailure) -> [AdmissionError; 3] {
    [
        AdmissionError::Authority(failure),
        AdmissionError::Seal(Box::new(SealFailure::Store(failure))),
        AdmissionError::Outcome(Box::new(OutcomeFailure::from(failure))),
    ]
}

#[test]
fn cancelled_or_expired_reads_never_become_corrupt_or_missing_evidence() {
    for fallback in [
        RefusalCode::AuthorityReceiptInvalid,
        RefusalCode::EvidenceInvalid,
        RefusalCode::EvidenceMissing,
    ] {
        for reason in [AmbiguityReason::Cancelled, AmbiguityReason::Timeout] {
            for error in wrapped(AuthorityFailure::Ambiguous(reason)) {
                assert_eq!(
                    error.into_projection_unavailable(fallback),
                    ProjectionFailure::Unavailable(RefusalCode::CancellationInProgress),
                    "x2mv.4.51 acceptance 1: interruption survives each authority wrapper"
                );
            }
        }
    }
}

#[test]
fn real_receipt_failures_and_explicit_evidence_refusals_keep_their_class() {
    for fallback in [
        RefusalCode::AuthorityReceiptInvalid,
        RefusalCode::EvidenceInvalid,
        RefusalCode::EvidenceMissing,
    ] {
        for refusal in [
            AuthorityRefusal::UnknownVersionToken,
            AuthorityRefusal::TokenBodyMismatch,
            AuthorityRefusal::TokenKeyMismatch,
            AuthorityRefusal::TokenGenerationMismatch,
        ] {
            for error in wrapped(AuthorityFailure::Refused(refusal)) {
                assert_eq!(
                    error.into_projection_unavailable(fallback),
                    ProjectionFailure::Unavailable(fallback),
                    "x2mv.4.51 acceptance 2: actual integrity failures retain boundary semantics"
                );
            }
        }
        for code in [
            RefusalCode::EvidenceMissing,
            RefusalCode::EvidenceInvalid,
            RefusalCode::AuthorityReceiptInvalid,
            RefusalCode::ResourceBudgetExceeded,
            RefusalCode::CancellationInProgress,
        ] {
            assert_eq!(
                AdmissionError::AsyncProjectionUnavailable(code)
                    .into_projection_unavailable(fallback),
                ProjectionFailure::Unavailable(code),
            );
        }
        assert_eq!(
            AdmissionError::Outcome(Box::new(OutcomeFailure::StreamBodyMissing {
                link: "test canonical evidence",
            }))
            .into_projection_unavailable(fallback),
            ProjectionFailure::Unavailable(fallback),
        );
    }
}

#[test]
fn history_replay_bound_is_a_resource_limit_not_missing_or_invalid_evidence() {
    for fallback in [
        RefusalCode::AuthorityReceiptInvalid,
        RefusalCode::EvidenceInvalid,
        RefusalCode::EvidenceMissing,
    ] {
        assert_eq!(
            AdmissionError::Outcome(Box::new(OutcomeFailure::ReplayBoundExceeded { limit: 1 }))
                .into_projection_unavailable(fallback),
            ProjectionFailure::Unavailable(RefusalCode::ResourceBudgetExceeded),
        );
    }
}

#[test]
fn unresolved_io_and_resource_limits_are_not_integrity_claims() {
    for (failure, expected) in [
        (
            AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse),
            RefusalCode::ExternalEffectIndeterminate,
        ),
        (
            AuthorityFailure::Refused(AuthorityRefusal::Throttled),
            RefusalCode::ResourceBudgetExceeded,
        ),
        (
            AuthorityFailure::Refused(AuthorityRefusal::CapacityExhausted {
                occupancy: 2,
                limit: 2,
            }),
            RefusalCode::ResourceBudgetExceeded,
        ),
        (
            AuthorityFailure::Refused(AuthorityRefusal::BodyTooLarge { len: 2, limit: 1 }),
            RefusalCode::ResourceBudgetExceeded,
        ),
        (
            AuthorityFailure::Refused(AuthorityRefusal::Unavailable),
            RefusalCode::DurabilityProfileUnavailable,
        ),
        (
            AuthorityFailure::Refused(AuthorityRefusal::OperationUnsupported),
            RefusalCode::DurabilityProfileUnavailable,
        ),
    ] {
        for error in wrapped(failure) {
            assert_eq!(
                error.into_projection_unavailable(RefusalCode::EvidenceInvalid),
                ProjectionFailure::Unavailable(expected),
            );
        }
    }
}
