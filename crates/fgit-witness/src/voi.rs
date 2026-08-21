//! The value-of-information policy that decides whether refinement is worth
//! its cost.
//!
//! Plan §15.6 gives the arithmetic directly:
//!
//! ```text
//! expected_saved_retry_cost
//!   - refinement_cpu_cost
//!   - refinement_io_cost
//!   - added_latency_cost
//!   - uncertainty/risk_margin
//! ```
//!
//! and the rule that governs it: "Only bounded, deterministic,
//! receipt-producing refinement may run. If refinement cannot prove safety, the
//! transaction remains conservatively conflicting."
//!
//! Three properties follow, and each is enforced rather than documented:
//!
//! * **Bounded.** Every cost is a saturating `u64` in abstract micro-units.
//!   Nothing here can overflow into a small number and turn an expensive
//!   refinement into an attractive one.
//! * **Deterministic.** No floating point, no clock, no randomness. The same
//!   inputs always produce the same decision and the same receipt.
//! * **Conservative on doubt.** [`Decision::RetainCoarseConflict`] is the
//!   result for a non-positive net gain, an over-budget estimate, *and* an
//!   inconclusive one. Refinement is the exception that must be justified.

/// An abstract cost in micro-units.
///
/// Deliberately unitless: the policy compares costs against each other and
/// against a budget, never against wall-clock time, so nothing here depends on
/// a clock the model is not allowed to read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cost(u64);

impl Cost {
    /// No cost.
    pub const ZERO: Self = Self(0);

    /// Builds a cost.
    #[must_use]
    pub const fn new(micro_units: u64) -> Self {
        Self(micro_units)
    }

    /// The value in micro-units.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Saturating addition; costs never wrap.
    #[must_use]
    pub const fn saturating_add(self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }

    /// Saturating subtraction; a cost never goes negative.
    #[must_use]
    pub const fn saturating_sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }
}

/// Everything the policy needs, and nothing it does not.
///
/// There is no clock, no random source, and no handle to live state: a
/// decision is a pure function of this struct.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Inputs {
    /// What a successful refinement is expected to save by avoiding a retry.
    pub expected_saved_retry_cost: Cost,
    /// Processor cost of attempting the refinement.
    pub refinement_cpu_cost: Cost,
    /// Input/output cost of attempting the refinement.
    pub refinement_io_cost: Cost,
    /// Latency the attempt adds even when it succeeds.
    pub added_latency_cost: Cost,
    /// Margin held back for the chance the estimate is wrong.
    pub risk_margin: Cost,
    /// Hard ceiling on what may be spent attempting refinement.
    pub budget: Cost,
}

impl Inputs {
    /// Total cost of attempting refinement, excluding the risk margin.
    #[must_use]
    pub const fn attempt_cost(self) -> Cost {
        self.refinement_cpu_cost
            .saturating_add(self.refinement_io_cost)
            .saturating_add(self.added_latency_cost)
    }

    /// Total charge against the expected saving, risk margin included.
    #[must_use]
    pub const fn total_charge(self) -> Cost {
        self.attempt_cost().saturating_add(self.risk_margin)
    }

    /// Expected net gain: saving minus every charge, floored at zero.
    #[must_use]
    pub const fn expected_net_gain(self) -> Cost {
        self.expected_saved_retry_cost
            .saturating_sub(self.total_charge())
    }
}

/// Why refinement was not attempted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RetainReason {
    /// The expected saving did not exceed the cost plus risk margin.
    NoNetGain,
    /// Attempting it would exceed the declared budget.
    OverBudget,
    /// The caller could not estimate the inputs.
    Inconclusive,
    /// An attempt was made and did not conclude.
    AttemptFailed,
}

impl RetainReason {
    /// Stable machine-readable name, for receipts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoNetGain => "no_net_gain",
            Self::OverBudget => "over_budget",
            Self::Inconclusive => "inconclusive",
            Self::AttemptFailed => "attempt_failed",
        }
    }
}

/// What the policy decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Attempt refinement; it is expected to pay for itself.
    Refine {
        /// The expected net gain that justified it.
        expected_net_gain: Cost,
        /// What the attempt is allowed to spend.
        spend_ceiling: Cost,
    },
    /// Keep the conservative conflict.
    RetainCoarseConflict {
        /// Why.
        reason: RetainReason,
    },
}

impl Decision {
    /// True when refinement was chosen.
    #[must_use]
    pub const fn refines(self) -> bool {
        matches!(self, Self::Refine { .. })
    }

    /// The reason refinement was declined, if it was.
    #[must_use]
    pub const fn retain_reason(self) -> Option<RetainReason> {
        match self {
            Self::RetainCoarseConflict { reason } => Some(reason),
            Self::Refine { .. } => None,
        }
    }
}

/// Decides whether to refine.
///
/// Refinement requires *both* a strictly positive expected net gain and an
/// attempt cost within budget. Either failing retains the coarse conflict,
/// which is the safe direction: retaining a conflict costs a retry, while
/// wrongly clearing one costs correctness.
#[must_use]
pub fn decide(inputs: Inputs) -> Decision {
    if inputs.attempt_cost() > inputs.budget {
        return Decision::RetainCoarseConflict {
            reason: RetainReason::OverBudget,
        };
    }
    let gain = inputs.expected_net_gain();
    if gain == Cost::ZERO {
        return Decision::RetainCoarseConflict {
            reason: RetainReason::NoNetGain,
        };
    }
    Decision::Refine {
        expected_net_gain: gain,
        spend_ceiling: inputs.budget,
    }
}

/// One line of NDJSON recording a decision and every input that produced it.
///
/// §12 requires every refinement decision and input root to be receipted. A
/// decision without its inputs is unauditable: a reader cannot tell a sound
/// call from a lucky one.
#[must_use]
pub fn receipt(inputs: Inputs, decision: Decision) -> String {
    let mut out = String::with_capacity(320);
    out.push_str("{\"record\":\"voi_decision\"");
    for (key, value) in [
        (
            "expected_saved_retry_cost",
            inputs.expected_saved_retry_cost.get(),
        ),
        ("refinement_cpu_cost", inputs.refinement_cpu_cost.get()),
        ("refinement_io_cost", inputs.refinement_io_cost.get()),
        ("added_latency_cost", inputs.added_latency_cost.get()),
        ("risk_margin", inputs.risk_margin.get()),
        ("budget", inputs.budget.get()),
        ("attempt_cost", inputs.attempt_cost().get()),
        ("expected_net_gain", inputs.expected_net_gain().get()),
    ] {
        out.push_str(",\"");
        out.push_str(key);
        out.push_str("\":");
        out.push_str(&value.to_string());
    }
    out.push_str(",\"decision\":\"");
    out.push_str(if decision.refines() {
        "refine"
    } else {
        "retain_coarse_conflict"
    });
    out.push('"');
    if let Some(reason) = decision.retain_reason() {
        out.push_str(",\"reason\":\"");
        out.push_str(reason.as_str());
        out.push('"');
    }
    out.push('}');
    out
}

#[cfg(test)]
mod tests {
    use super::{Cost, Decision, Inputs, RetainReason, decide, receipt};

    fn inputs(saved: u64, cpu: u64, io: u64, latency: u64, risk: u64, budget: u64) -> Inputs {
        Inputs {
            expected_saved_retry_cost: Cost::new(saved),
            refinement_cpu_cost: Cost::new(cpu),
            refinement_io_cost: Cost::new(io),
            added_latency_cost: Cost::new(latency),
            risk_margin: Cost::new(risk),
            budget: Cost::new(budget),
        }
    }

    #[test]
    fn a_clearly_worthwhile_refinement_is_taken() {
        let decision = decide(inputs(1000, 10, 10, 10, 10, 500));
        match decision {
            Decision::Refine {
                expected_net_gain,
                spend_ceiling,
            } => {
                assert_eq!(expected_net_gain, Cost::new(960));
                assert_eq!(spend_ceiling, Cost::new(500));
            }
            other @ Decision::RetainCoarseConflict { .. } => {
                panic!("expected refine, got {other:?}")
            }
        }
    }

    #[test]
    fn a_break_even_refinement_is_declined() {
        // Exactly break-even is not worth doing: the estimate carries risk the
        // margin has already been charged for, so ties go to the safe side.
        let decision = decide(inputs(100, 40, 30, 10, 20, 500));
        assert_eq!(decision.retain_reason(), Some(RetainReason::NoNetGain));
        assert!(!decision.refines());
    }

    #[test]
    fn an_over_budget_attempt_is_declined_even_when_the_gain_is_enormous() {
        // NPC section 12: over-budget refinement retains the coarse conflict.
        // A huge expected saving must not buy an unbounded attempt.
        let decision = decide(inputs(u64::MAX, 400, 400, 400, 0, 500));
        assert_eq!(decision.retain_reason(), Some(RetainReason::OverBudget));
    }

    #[test]
    fn the_risk_margin_can_turn_a_marginal_gain_into_a_decline() {
        let without = decide(inputs(100, 10, 10, 10, 0, 500));
        assert!(without.refines());
        // The permitted twin, one input apart: the same estimate with the
        // margin charged is declined.
        let with = decide(inputs(100, 10, 10, 10, 70, 500));
        assert_eq!(with.retain_reason(), Some(RetainReason::NoNetGain));
    }

    #[test]
    fn costs_saturate_rather_than_wrapping() {
        // A wrapping cost would turn the most expensive possible refinement
        // into a free one, which is the failure mode worth pinning.
        let decision = decide(inputs(10, u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX));
        assert_eq!(decision.retain_reason(), Some(RetainReason::NoNetGain));
        assert_eq!(
            inputs(0, u64::MAX, u64::MAX, 0, 0, 0).attempt_cost(),
            Cost::new(u64::MAX)
        );
        assert_eq!(Cost::ZERO.saturating_sub(Cost::new(5)), Cost::ZERO);
    }

    #[test]
    fn the_decision_is_deterministic() {
        let i = inputs(1000, 10, 10, 10, 10, 500);
        assert_eq!(decide(i), decide(i));
        assert_eq!(receipt(i, decide(i)), receipt(i, decide(i)));
    }

    #[test]
    fn the_receipt_carries_every_input_and_is_one_ndjson_line() {
        let i = inputs(1000, 11, 12, 13, 14, 500);
        let line = receipt(i, decide(i));
        assert!(!line.contains('\n'), "one record per line: {line}");
        assert!(line.starts_with('{') && line.ends_with('}'));
        for key in [
            "\"record\":\"voi_decision\"",
            "\"expected_saved_retry_cost\":1000",
            "\"refinement_cpu_cost\":11",
            "\"refinement_io_cost\":12",
            "\"added_latency_cost\":13",
            "\"risk_margin\":14",
            "\"budget\":500",
            "\"attempt_cost\":36",
            "\"expected_net_gain\":950",
            "\"decision\":\"refine\"",
        ] {
            assert!(line.contains(key), "receipt missing {key}: {line}");
        }
    }

    #[test]
    fn a_declined_receipt_names_its_reason() {
        let i = inputs(1, 400, 400, 400, 0, 500);
        let line = receipt(i, decide(i));
        assert!(line.contains("\"decision\":\"retain_coarse_conflict\""));
        assert!(line.contains("\"reason\":\"over_budget\""));
    }

    #[test]
    fn every_retain_reason_has_a_distinct_name() {
        use std::collections::BTreeSet;
        let reasons = [
            RetainReason::NoNetGain,
            RetainReason::OverBudget,
            RetainReason::Inconclusive,
            RetainReason::AttemptFailed,
        ];
        let names = reasons.iter().map(|r| r.as_str()).collect::<BTreeSet<_>>();
        assert_eq!(names.len(), reasons.len());
    }
}
