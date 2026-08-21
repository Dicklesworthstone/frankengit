//! Obligation-leak policy.
//!
//! The integration profile is unusually specific here, and for a reason: an
//! obligation leak is a resource whose responsibility nobody accepted. The
//! profile states that leak policy is *configured rather than inherited
//! accidentally*, that verification and release profiles use fail-fast
//! `Panic`, and that an availability-oriented service may use `Recover` only
//! with a durable leak record, bounded cleanup, health degradation, and an
//! escalation threshold. `Silent` is forbidden outright, and `Log` alone
//! cannot satisfy region closure.
//!
//! So this module makes those the only constructible states. There is no way
//! to build a [`LeakPolicy`] that maps to `Silent`, and no way to build a
//! recovering policy without all four controls.

use asupersync::Budget;
use asupersync::runtime::config::{LeakEscalation, ObligationLeakResponse};

use crate::meter::is_unbounded;
use crate::refuse::RuntimeRefusal;

/// The controls that make an availability-oriented `Recover` policy
/// admissible.
///
/// Every field is mandatory. A recovering node that cannot record the leak
/// durably, cannot bound its cleanup, cannot degrade its health signal, or
/// never escalates is indistinguishable from a node that quietly drops
/// responsibility, which is exactly what the profile forbids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeakControls {
    cleanup_budget: Budget,
    escalation_threshold: u64,
}

impl LeakControls {
    /// Assemble the controls.
    ///
    /// The durable-record and health-degradation obligations are represented
    /// by construction rather than by a boolean the caller could set to
    /// `true` without doing the work: a caller obtains `LeakControls` only by
    /// supplying a bounded cleanup budget and a non-zero escalation
    /// threshold, and [`LeakPolicy::recovering`] additionally requires the
    /// durable sink and health sink to be named.
    ///
    /// # Errors
    ///
    /// - [`RuntimeRefusal::LeakRecoveryUncontrolled`] when the cleanup budget
    ///   is unbounded, or when the escalation threshold is zero.
    pub fn new(cleanup_budget: Budget, escalation_threshold: u64) -> Result<Self, RuntimeRefusal> {
        if is_unbounded(cleanup_budget) {
            return Err(RuntimeRefusal::LeakRecoveryUncontrolled {
                missing: "bounded_cleanup",
            });
        }
        if escalation_threshold == 0 {
            return Err(RuntimeRefusal::LeakRecoveryUncontrolled {
                missing: "escalation_threshold",
            });
        }
        Ok(Self {
            cleanup_budget,
            escalation_threshold,
        })
    }

    /// The bounded cleanup budget.
    #[must_use]
    pub const fn cleanup_budget(&self) -> Budget {
        self.cleanup_budget
    }

    /// The leak count at which the policy escalates to fail-fast.
    #[must_use]
    pub const fn escalation_threshold(&self) -> u64 {
        self.escalation_threshold
    }
}

/// Where a recovering node durably records a leak, and how it degrades.
///
/// These are names, not handles: this crate does not own the evidence sink or
/// the health endpoint. Requiring them to be named is what stops `Recover`
/// from being selected as a way to make leaks disappear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverySinks {
    durable_record: String,
    health_signal: String,
}

impl RecoverySinks {
    /// Name the durable leak record and the health-degradation signal.
    ///
    /// # Errors
    ///
    /// [`RuntimeRefusal::LeakRecoveryUncontrolled`] when either name is blank.
    pub fn new(
        durable_record: impl Into<String>,
        health_signal: impl Into<String>,
    ) -> Result<Self, RuntimeRefusal> {
        let durable_record = durable_record.into();
        let health_signal = health_signal.into();
        if durable_record.trim().is_empty() {
            return Err(RuntimeRefusal::LeakRecoveryUncontrolled {
                missing: "durable_leak_record",
            });
        }
        if health_signal.trim().is_empty() {
            return Err(RuntimeRefusal::LeakRecoveryUncontrolled {
                missing: "health_degradation",
            });
        }
        Ok(Self {
            durable_record,
            health_signal,
        })
    }

    /// The durable leak record's name.
    #[must_use]
    pub fn durable_record(&self) -> &str {
        &self.durable_record
    }

    /// The health-degradation signal's name.
    #[must_use]
    pub fn health_signal(&self) -> &str {
        &self.health_signal
    }
}

/// An admissible obligation-leak policy.
///
/// Only two states exist, because only two are admissible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeakPolicy {
    /// Fail fast: a leak panics with diagnostics. Required for verification
    /// and release profiles.
    FailFast,
    /// Recover with the full control set, escalating to fail-fast at the
    /// configured threshold.
    Recovering {
        /// Bounded cleanup and escalation threshold.
        controls: LeakControls,
        /// Durable record and health-degradation sinks.
        sinks: RecoverySinks,
    },
}

impl LeakPolicy {
    /// The fail-fast policy.
    #[must_use]
    pub const fn fail_fast() -> Self {
        Self::FailFast
    }

    /// Build the recovering policy, requiring every control.
    ///
    /// # Errors
    ///
    /// [`RuntimeRefusal::LeakRecoveryUncontrolled`] naming the first missing
    /// control.
    pub fn recovering(controls: LeakControls, sinks: RecoverySinks) -> Result<Self, RuntimeRefusal> {
        Ok(Self::Recovering { controls, sinks })
    }

    /// Translate an Asupersync leak response into an admissible policy.
    ///
    /// This is the gate that rejects the two inadmissible responses. It is
    /// the only path from the runtime's four-valued enum into this crate, so
    /// a configuration that names `Silent` or `Log` cannot reach a node.
    ///
    /// # Errors
    ///
    /// [`RuntimeRefusal::LeakPolicyInsufficient`] for `Silent` and `Log`.
    pub fn from_response(
        response: ObligationLeakResponse,
        recovery: Option<(LeakControls, RecoverySinks)>,
    ) -> Result<Self, RuntimeRefusal> {
        match response {
            ObligationLeakResponse::Panic => Ok(Self::FailFast),
            ObligationLeakResponse::Silent => {
                Err(RuntimeRefusal::LeakPolicyInsufficient { policy: "Silent" })
            }
            ObligationLeakResponse::Log => {
                Err(RuntimeRefusal::LeakPolicyInsufficient { policy: "Log" })
            }
            ObligationLeakResponse::Recover => match recovery {
                Some((controls, sinks)) => Self::recovering(controls, sinks),
                None => Err(RuntimeRefusal::LeakRecoveryUncontrolled {
                    missing: "durable_leak_record",
                }),
            },
        }
    }

    /// The runtime response this policy configures.
    #[must_use]
    pub const fn response(&self) -> ObligationLeakResponse {
        match self {
            Self::FailFast => ObligationLeakResponse::Panic,
            Self::Recovering { .. } => ObligationLeakResponse::Recover,
        }
    }

    /// The runtime escalation this policy configures.
    ///
    /// A recovering policy always escalates to `Panic`: recovery is a bounded
    /// concession to availability, not a permanent operating mode.
    #[must_use]
    pub fn escalation(&self) -> Option<LeakEscalation> {
        match self {
            Self::FailFast => None,
            Self::Recovering { controls, .. } => Some(LeakEscalation::new(
                controls.escalation_threshold(),
                ObligationLeakResponse::Panic,
            )),
        }
    }

    /// Whether this policy is admissible for a profile that must fail fast.
    #[must_use]
    pub const fn is_fail_fast(&self) -> bool {
        matches!(self, Self::FailFast)
    }

    /// Stable machine name.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::FailFast => "fail_fast",
            Self::Recovering { .. } => "recovering",
        }
    }
}

#[cfg(test)]
mod tests {
    use asupersync::types::id::Time;

    use super::*;

    fn controls() -> LeakControls {
        LeakControls::new(
            Budget::new()
                .with_deadline(Time::from_secs(5))
                .with_poll_quota(1_000)
                .with_cost_quota(1_000),
            8,
        )
        .expect("bounded cleanup and a non-zero threshold")
    }

    fn sinks() -> RecoverySinks {
        RecoverySinks::new("fgit.evidence.obligation_leak", "fgit.health.degraded")
            .expect("both sinks named")
    }

    #[test]
    fn silent_leak_policy_is_rejected() {
        let refusal = LeakPolicy::from_response(ObligationLeakResponse::Silent, None)
            .expect_err("Silent is forbidden");
        assert_eq!(
            refusal,
            RuntimeRefusal::LeakPolicyInsufficient { policy: "Silent" }
        );
        assert!(!refusal.is_retryable());
    }

    #[test]
    fn log_only_leak_policy_is_rejected() {
        let refusal = LeakPolicy::from_response(ObligationLeakResponse::Log, None)
            .expect_err("Log alone cannot satisfy closure");
        assert_eq!(
            refusal,
            RuntimeRefusal::LeakPolicyInsufficient { policy: "Log" }
        );
    }

    #[test]
    fn panic_leak_policy_is_accepted() {
        // Paired permitted case for the two rejections above.
        let policy = LeakPolicy::from_response(ObligationLeakResponse::Panic, None)
            .expect("Panic is the fail-fast policy");
        assert!(policy.is_fail_fast());
        assert_eq!(policy.response(), ObligationLeakResponse::Panic);
        assert_eq!(policy.escalation(), None);
    }

    #[test]
    fn recover_without_controls_is_rejected() {
        let refusal = LeakPolicy::from_response(ObligationLeakResponse::Recover, None)
            .expect_err("Recover requires controls");
        assert_eq!(
            refusal,
            RuntimeRefusal::LeakRecoveryUncontrolled {
                missing: "durable_leak_record"
            }
        );
    }

    #[test]
    fn recover_with_full_controls_is_accepted_and_escalates() {
        // The near-identical permitted twin: same response, controls supplied.
        let policy = LeakPolicy::from_response(
            ObligationLeakResponse::Recover,
            Some((controls(), sinks())),
        )
        .expect("Recover with the full control set is admissible");

        assert!(!policy.is_fail_fast());
        assert_eq!(policy.response(), ObligationLeakResponse::Recover);

        let escalation = policy.escalation().expect("recovery always escalates");
        assert_eq!(escalation.threshold, 8);
        assert_eq!(escalation.escalate_to, ObligationLeakResponse::Panic);
    }

    #[test]
    fn unbounded_cleanup_budget_is_rejected() {
        let refusal = LeakControls::new(Budget::INFINITE, 8)
            .expect_err("cleanup must be bounded");
        assert_eq!(
            refusal,
            RuntimeRefusal::LeakRecoveryUncontrolled {
                missing: "bounded_cleanup"
            }
        );

        // Paired permitted case: a bounded cleanup budget of the same shape.
        LeakControls::new(
            Budget::INFINITE
                .with_deadline(Time::from_secs(5))
                .with_poll_quota(10)
                .with_cost_quota(10),
            8,
        )
        .expect("a bounded cleanup budget is admissible");
    }

    #[test]
    fn zero_escalation_threshold_is_rejected() {
        let refusal = LeakControls::new(
            Budget::new()
                .with_deadline(Time::from_secs(5))
                .with_poll_quota(10)
                .with_cost_quota(10),
            0,
        )
        .expect_err("a policy that never escalates is uncontrolled");
        assert_eq!(
            refusal,
            RuntimeRefusal::LeakRecoveryUncontrolled {
                missing: "escalation_threshold"
            }
        );
    }

    #[test]
    fn unnamed_recovery_sinks_are_rejected() {
        assert_eq!(
            RecoverySinks::new("  ", "fgit.health.degraded").expect_err("blank record"),
            RuntimeRefusal::LeakRecoveryUncontrolled {
                missing: "durable_leak_record"
            }
        );
        assert_eq!(
            RecoverySinks::new("fgit.evidence.obligation_leak", "").expect_err("blank health"),
            RuntimeRefusal::LeakRecoveryUncontrolled {
                missing: "health_degradation"
            }
        );

        // Paired permitted case.
        let ok = RecoverySinks::new("a", "b").expect("named sinks are admissible");
        assert_eq!(ok.durable_record(), "a");
        assert_eq!(ok.health_signal(), "b");
    }

    #[test]
    fn no_constructible_policy_maps_to_an_inadmissible_response() {
        // Exhaustive over the two constructible states: neither can produce
        // `Silent` or `Log`, so an inadmissible response cannot reach a node.
        let policies = [
            LeakPolicy::fail_fast(),
            LeakPolicy::recovering(controls(), sinks()).expect("controlled recovery"),
        ];
        for policy in &policies {
            assert!(matches!(
                policy.response(),
                ObligationLeakResponse::Panic | ObligationLeakResponse::Recover
            ));
        }
    }
}
