#![forbid(unsafe_code)]
//! The five admission outcomes (plan section 36.2) decided against one
//! scope's effective ceiling and the shared obligation ledger.
//!
//! Decision order is fixed and deterministic:
//! 1. a request (or its degraded profile) exceeding the chain's effective
//!    ceiling is refused before the pool is touched (`HardRefusal`);
//! 2. the full request is attempted against the ledger
//!    (`AdmittedWithReservation`);
//! 3. otherwise the declared degraded profile, if any, is attempted
//!    (`DegradedOptionalProfile`);
//! 4. otherwise, when the caller permits queuing, the request parks with a
//!    deadline (`QueuedWithDeadline`);
//! 5. otherwise it bounces with a retry hint (`RetryableRefusalWithHint`).
//!
//! Nothing here observes wall-clock time: deadlines and retry hints are
//! durations the caller anchors.

pub use crate::algebra::BudgetGrant;
use crate::algebra::{Grade, ResourceError, ResourceVector};
use crate::quota::hierarchy::{ScopeCeilings, ScopeChain};
use fgit_types::{Hint, HintSource};
use std::time::Duration;

/// Why an admission was hard-refused before any pool interaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HardRefusalReason {
    /// The ask exceeded its chain's effective ceiling in this grade.
    CeilingExceeded { grade: Grade },
    /// The ledger reported an arithmetic-range failure; retrying cannot help.
    LedgerOverflow { grade: Grade },
}

/// One admission decision. Exactly one variant per outcome class of 36.2.
#[derive(Debug)]
pub enum AdmissionOutcome {
    /// Budget reserved from the pool; the caller owes commit-or-release.
    AdmittedWithReservation { grant: BudgetGrant },
    /// Parked until `deadline` elapses; re-attempt then.
    QueuedWithDeadline { deadline: Duration },
    /// Reserved at the reduced profile; the original ask is recorded so the
    /// degradation stays visible downstream.
    DegradedOptionalProfile {
        grant: BudgetGrant,
        original_request: ResourceVector,
    },
    /// Refused now; the hint names what would make a retry succeed.
    RetryableRefusalWithHint {
        hint: Hint<&'static str>,
        retry_after: Duration,
    },
    /// Refused categorically; retrying cannot help while ceilings hold.
    HardRefusal { reason: HardRefusalReason },
}

/// Everything [`admit`] needs besides the ledger.
#[derive(Clone)]
pub struct AdmissionRequest {
    /// The full resource ask.
    pub requested: ResourceVector,
    /// An optional smaller profile that may be served under contention.
    pub degraded_profile: Option<ResourceVector>,
    /// How long a queued request may wait before it must bounce. Zero
    /// disables queueing for this request.
    pub queue_deadline: Duration,
    /// How long a retryable refusal advises the caller to wait.
    pub retry_after: Duration,
}

impl AdmissionRequest {
    /// A plain request: no degradation, no queueing, immediate retry hint.
    #[must_use]
    pub const fn exact(requested: ResourceVector) -> Self {
        Self {
            requested,
            degraded_profile: None,
            queue_deadline: Duration::ZERO,
            retry_after: Duration::from_secs(1),
        }
    }
}

fn exceeds_ceiling(ask: &ResourceVector, ceiling: &ResourceVector) -> Option<Grade> {
    for (grade, amount) in ask.pairs() {
        let cap = ceiling.get(grade);
        // A zero ceiling on an undeclared dimension means "nothing reserved
        // through this economy yet", not "refuse everything"; callers that
        // want deny-by-default declare every dimension.
        if cap > 0 && amount > cap {
            return Some(grade);
        }
    }
    None
}

const CAPACITY_HINT: &str = "capacity-contention";

/// Decides one admission against `chain`'s effective ceiling and `ledger`.
#[must_use]
pub fn admit(
    ledger: &crate::custody::ObligationLedger,
    chain: &ScopeChain,
    ceilings: &ScopeCeilings,
    request: &AdmissionRequest,
) -> AdmissionOutcome {
    let ceiling = chain.effective_ceiling(ceilings);

    if let Some(grade) = exceeds_ceiling(&request.requested, &ceiling) {
        return AdmissionOutcome::HardRefusal {
            reason: HardRefusalReason::CeilingExceeded { grade },
        };
    }

    match ledger.grant(request.requested) {
        Ok(grant) => return AdmissionOutcome::AdmittedWithReservation { grant },
        Err(ResourceError::Conservation { .. }) => {}
        Err(ResourceError::Overflow { grade, .. }) => {
            return AdmissionOutcome::HardRefusal {
                reason: HardRefusalReason::LedgerOverflow { grade },
            };
        }
    }

    if let Some(degraded) = &request.degraded_profile
        && exceeds_ceiling(degraded, &ceiling).is_none()
    {
        match ledger.grant(*degraded) {
            Ok(grant) => {
                return AdmissionOutcome::DegradedOptionalProfile {
                    grant,
                    original_request: request.requested,
                };
            }
            Err(ResourceError::Conservation { .. }) => {}
            Err(ResourceError::Overflow { grade, .. }) => {
                return AdmissionOutcome::HardRefusal {
                    reason: HardRefusalReason::LedgerOverflow { grade },
                };
            }
        }
    }

    if request.queue_deadline > Duration::ZERO {
        return AdmissionOutcome::QueuedWithDeadline {
            deadline: request.queue_deadline,
        };
    }

    AdmissionOutcome::RetryableRefusalWithHint {
        hint: Hint::new(CAPACITY_HINT, HintSource::LocalProjection),
        retry_after: request.retry_after,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algebra::Grade;
    use crate::custody::{LeakDisposition, ObligationLedger};
    use crate::ids::RegionId;
    use crate::quota::hierarchy::ScopeSegment;
    use fgit_types::TenantId;
    use std::time::Duration;

    fn ledger_with(bytes_capacity: u64) -> ObligationLedger {
        ObligationLedger::root(
            RegionId::new(1),
            LeakDisposition::RecordAndContinue,
            bytes(bytes_capacity),
        )
    }

    fn tenant_chain() -> ScopeChain {
        ScopeChain::new(vec![ScopeSegment::Tenant(TenantId::from_bytes([1; 16]))]).expect("chain")
    }

    fn bytes(n: u64) -> ResourceVector {
        ResourceVector::single(Grade::Bytes, n)
    }

    fn open_ceiling() -> ScopeCeilings {
        let mut ceilings = ScopeCeilings::new();
        ceilings
            .declare(
                vec![ScopeSegment::Tenant(TenantId::from_bytes([1; 16]))],
                bytes(u64::MAX / 2),
            )
            .expect("declare");
        ceilings
    }

    #[test]
    fn over_ceiling_is_hard_refused_without_pool_touch() {
        let mut ceilings = ScopeCeilings::new();
        ceilings
            .declare(
                vec![ScopeSegment::Tenant(TenantId::from_bytes([1; 16]))],
                bytes(10),
            )
            .expect("declare");
        let outcome = admit(
            &ledger_with(1_000),
            &tenant_chain(),
            &ceilings,
            &AdmissionRequest::exact(bytes(11)),
        );
        assert!(matches!(
            outcome,
            AdmissionOutcome::HardRefusal {
                reason: HardRefusalReason::CeilingExceeded {
                    grade: Grade::Bytes
                }
            }
        ));
    }

    #[test]
    fn under_ceiling_admits_with_reservation() {
        let outcome = admit(
            &ledger_with(1_000),
            &tenant_chain(),
            &open_ceiling(),
            &AdmissionRequest::exact(bytes(50)),
        );
        assert!(matches!(
            outcome,
            AdmissionOutcome::AdmittedWithReservation { .. }
        ));
    }

    #[test]
    fn contention_falls_through_to_degraded_profile() {
        let ledger = ledger_with(100);
        // Consume all but 30 bytes.
        let _held = admit(
            &ledger,
            &tenant_chain(),
            &open_ceiling(),
            &AdmissionRequest::exact(bytes(70)),
        );
        let request = AdmissionRequest {
            requested: bytes(50),
            degraded_profile: Some(bytes(20)),
            queue_deadline: Duration::ZERO,
            retry_after: Duration::from_secs(1),
        };
        let outcome = admit(&ledger, &tenant_chain(), &open_ceiling(), &request);
        match outcome {
            AdmissionOutcome::DegradedOptionalProfile {
                grant,
                original_request,
            } => {
                assert_eq!(grant.amount().get(Grade::Bytes), 20);
                assert_eq!(original_request.get(Grade::Bytes), 50);
            }
            other => panic!("expected degraded admission, got {other:?}"),
        }
    }

    #[test]
    fn exhausted_pool_queues_when_permitted_then_bounces_without() {
        let ledger = ledger_with(100);
        let _held = admit(
            &ledger,
            &tenant_chain(),
            &open_ceiling(),
            &AdmissionRequest::exact(bytes(100)),
        );

        let queued = AdmissionRequest {
            requested: bytes(10),
            degraded_profile: None,
            queue_deadline: Duration::from_secs(5),
            retry_after: Duration::from_secs(1),
        };
        assert!(matches!(
            admit(&ledger, &tenant_chain(), &open_ceiling(), &queued),
            AdmissionOutcome::QueuedWithDeadline { .. }
        ));

        let bouncing = AdmissionRequest::exact(bytes(10));
        match admit(&ledger, &tenant_chain(), &open_ceiling(), &bouncing) {
            AdmissionOutcome::RetryableRefusalWithHint { hint, retry_after } => {
                assert_eq!(*hint.peek(), CAPACITY_HINT);
                assert_eq!(retry_after, Duration::from_secs(1));
            }
            other => panic!("expected retryable refusal, got {other:?}"),
        }
    }
}
