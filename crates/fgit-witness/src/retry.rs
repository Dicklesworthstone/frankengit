//! Retry policy: identity-bound expected-loss backoff, regime reset, and the
//! deterministic starvation escalator.
//!
//! Plan §16.5: "Retries carry attempt age, conflict history, resource spend,
//! and priority class. Expected-loss policy may change backoff, refinement, or
//! batch preference within hard bounds. Deterministic starvation escalation
//! eventually routes an old transaction through a conservative serialized
//! component evaluation. **Statistical estimates cannot deny liveness
//! indefinitely.**"
//!
//! That last sentence is the design constraint that shapes this module. The
//! Beta-Bernoulli posterior is allowed to *tune* backoff inside declared
//! bounds. It is not allowed to decide whether a transaction ever runs. The
//! stateful [`RetryController`] feeds each retry observation through
//! `fgit-statistics`, publishes its policy epochs, and checks the deterministic
//! escalator after recording the observation. A test asserts that no posterior
//! value whatsoever can prevent escalation.
//!
//! ## Integers, not floats
//!
//! The posterior is a pair of counts and its mean is computed in parts per
//! million with integer arithmetic. A float posterior would make backoff
//! decisions differ across targets, and §26 requires an adaptive artifact to
//! bind a reproducible numeric fingerprint.

use fgit_statistics::{
    AdvisoryDecision, BindingRefusal, ControllerConfig, ControllerRefusal, IncrementalPosterior,
    PolicyGate, PolicySelection, RetryBackoffController, StatisticalEvidenceBody,
};
use fgit_types::{AsciiSlug, Digest, PolicyEpoch};

/// Attempts after which a transaction is escalated regardless of its
/// posterior.
///
/// A hard constant rather than a tunable: a knob here would be a knob on
/// liveness, and §16.5 forbids the statistical layer from holding one.
pub const STARVATION_ATTEMPTS: u32 = 8;

/// Attempt age, in retry ticks, after which the same escalation applies.
pub const STARVATION_AGE_TICKS: u32 = 512;

/// Largest backoff the policy may ever ask for.
pub const MAX_BACKOFF_TICKS: u32 = 64;

/// Parts per million represented by one retry tick in the shared controller.
///
/// The statistical controller operates on integer micro-units, whereas this
/// public policy exposes bounded logical ticks.  The scale is fixed so a loss
/// estimate of one million parts per million maps exactly to the hard maximum
/// of 64 ticks.  It is not learned or caller-selectable.
const LOSS_PPM_PER_TICK: u64 = 15_625;

/// Configures the shared controller for the retry policy.
///
/// The observation is the posterior *loss* in parts per million.  The profile
/// therefore keeps a candidate at zero loss, permits ordinary variation up to
/// the declared support bound, and pins the fallback at the maximum bounded
/// backoff.  The detector profile and retention bound are part of the policy
/// identity; callers cannot quietly replace them with a second retry policy.
#[must_use]
pub const fn controller_config() -> ControllerConfig {
    ControllerConfig {
        cusum: fgit_statistics::CusumConfig {
            target: 0,
            slack: 25_000,
            threshold: 900_000,
            max_deviation: 1_000_000,
            max_observations: 10_000,
        },
        base_backoff_micros: 0,
        pinned_fallback_micros: 1_000_000,
        max_retained_observations: 10_000,
    }
}

/// How urgent a transaction is relative to its peers.
///
/// Priority may reorder work; it may never starve anything, because the
/// escalator does not consult it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PriorityClass {
    /// Background or speculative work.
    Background,
    /// Ordinary interactive work.
    Interactive,
    /// Work a human is waiting on directly.
    Foreground,
}

impl PriorityClass {
    /// Backoff divisor: higher priority waits proportionally less.
    const fn backoff_divisor(self) -> u32 {
        match self {
            Self::Background => 1,
            Self::Interactive => 2,
            Self::Foreground => 4,
        }
    }

    /// Stable machine-readable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Background => "background",
            Self::Interactive => "interactive",
            Self::Foreground => "foreground",
        }
    }
}

/// Everything the retry policy reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attempt {
    /// How many attempts this sealed transaction has already made.
    pub attempts: u32,
    /// How long it has been retrying, in ticks.
    pub age_ticks: u32,
    /// Its priority class.
    pub priority: PriorityClass,
    /// What its history says about committing next time.
    pub posterior: IncrementalPosterior,
}

/// What the policy decided to do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Retry immediately; contention looks low.
    RetryNow,
    /// Wait this many ticks before retrying.
    BackoffFor {
        /// Ticks to wait, never above [`MAX_BACKOFF_TICKS`].
        ticks: u32,
    },
    /// Route through conservative serialized evaluation.
    ///
    /// The terminal rung of §16.5: it always makes progress, and no
    /// statistical input can prevent reaching it.
    EscalateToSerialized {
        /// Which hard threshold triggered it.
        trigger: EscalationTrigger,
    },
}

/// Which deterministic threshold forced escalation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EscalationTrigger {
    /// Too many attempts.
    AttemptCount,
    /// Retrying for too long.
    Age,
}

impl EscalationTrigger {
    /// Stable machine-readable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AttemptCount => "attempt_count",
            Self::Age => "age",
        }
    }
}

/// One sequenced retry decision, including the shared policy state that chose it.
///
/// The action alone is not enough evidence for adaptive behaviour: a later
/// reader also needs the policy epoch and whether the candidate or one pinned
/// fallback was selected.  The trigger remains carried by
/// [`PolicySelection`] rather than being reclassified into a retry-local
/// vocabulary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetryDecision {
    /// The liveness-preserving action to take.
    pub action: Action,
    /// Epoch of the shared statistical policy that produced this decision.
    pub epoch: PolicyEpoch,
    /// Candidate or the shared fail-closed fallback selection.
    pub selection: PolicySelection,
    /// Whether this observation changed the selected policy and published an epoch.
    pub published_epoch: bool,
    /// All section-26 bindings for this exact sequenced decision.
    pub evidence: StatisticalEvidenceBody,
}

/// Immutable identity bindings for one retry evidence stream.
///
/// This has no default and is required to construct a [`RetryController`]. A
/// caller therefore cannot obtain an adaptive retry action first and invent the
/// population, selection rule, or numeric fingerprint only when asked for a
/// receipt later.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetryEvidenceIdentity {
    population: AsciiSlug,
    selection: AsciiSlug,
    fingerprint: Digest,
}

impl RetryEvidenceIdentity {
    /// Binds the externally owned identity fields of one retry stream.
    #[must_use]
    pub const fn new(population: AsciiSlug, selection: AsciiSlug, fingerprint: Digest) -> Self {
        Self {
            population,
            selection,
            fingerprint,
        }
    }

    /// Population whose retry observations enter the stream.
    #[must_use]
    pub const fn population(&self) -> &AsciiSlug {
        &self.population
    }

    /// Selection rule that admitted retry observations into the stream.
    #[must_use]
    pub const fn selection(&self) -> &AsciiSlug {
        &self.selection
    }

    /// Numeric implementation/toolchain fingerprint for the stream.
    #[must_use]
    pub const fn fingerprint(&self) -> Digest {
        self.fingerprint
    }
}

/// Stateful retry controller backed by `fgit-statistics`.
///
/// A retry is an evidence stream, not a collection of unrelated posterior
/// reads.  The controller therefore owns sequence continuity, regime detection,
/// a retained-window bound, a pinned fallback, and policy epochs.  The only
/// adaptation left in this crate is the deterministic mapping from the shared
/// bounded backoff to this module's bounded tick representation.
#[derive(Clone, Debug)]
pub struct RetryController {
    controller: RetryBackoffController,
    identity: RetryEvidenceIdentity,
}

/// Why a retry evidence receipt cannot be built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetryEvidenceRefusal {
    /// No retry observation has entered this controller's current window.
    NoObservations,
    /// The shared controller could not bind one of its evidence fields.
    Binding(BindingRefusal),
}

/// Why a sequenced retry decision could not be produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetryRefusal {
    /// The shared controller could not advance its evidence or policy epoch.
    Controller(ControllerRefusal),
    /// The shared controller returned an advisory shape other than retry backoff.
    ///
    /// This is a typed refusal rather than an implicit conversion: treating a
    /// batch size or probe rate as retry ticks would silently invent a policy.
    UnexpectedAdvisoryDecision(AdvisoryDecision),
    /// The shared state could not produce the required bound evidence record.
    Evidence(RetryEvidenceRefusal),
}

impl RetryController {
    /// Starts the retry stream at the first policy epoch.
    ///
    /// # Errors
    ///
    /// Returns the shared controller refusal if the pinned profile is invalid.
    pub fn new(identity: RetryEvidenceIdentity) -> Result<Self, ControllerRefusal> {
        match RetryBackoffController::new(controller_config()) {
            Ok(controller) => Ok(Self {
                controller,
                identity,
            }),
            Err(refusal) => Err(refusal),
        }
    }

    /// Resumes a retry stream after its last published policy epoch.
    ///
    /// # Errors
    ///
    /// Returns the shared controller refusal if the pinned profile is invalid.
    pub fn new_at_epoch(
        identity: RetryEvidenceIdentity,
        epoch: PolicyEpoch,
    ) -> Result<Self, ControllerRefusal> {
        match RetryBackoffController::new_at_epoch(controller_config(), epoch) {
            Ok(controller) => Ok(Self {
                controller,
                identity,
            }),
            Err(refusal) => Err(refusal),
        }
    }

    /// Decides what a losing transaction should do next.
    ///
    /// The stream is observed even when the hard liveness escalator wins.  Skipping
    /// those rows would manufacture an evidence gap after the transaction resumed.
    /// The escalator then overrides the advisory action, so no statistical estimate
    /// can deny liveness indefinitely.
    ///
    /// # Errors
    ///
    /// Returns the shared controller's refusal when it cannot advance the policy
    /// stream, for example when its epoch counter is exhausted.
    pub fn decide(
        &mut self,
        sequence: u64,
        attempt: Attempt,
    ) -> Result<RetryDecision, RetryRefusal> {
        let success = attempt.posterior.success_probability().parts_per_million();
        let loss_ppm = i64::from(1_000_000_u32.saturating_sub(success));
        let step = self
            .controller
            .observe(sequence, loss_ppm)
            .map_err(RetryRefusal::Controller)?;
        let action = match (attempt.attempts, attempt.age_ticks) {
            (attempts, _) if attempts >= STARVATION_ATTEMPTS => Action::EscalateToSerialized {
                trigger: EscalationTrigger::AttemptCount,
            },
            (_, age_ticks) if age_ticks >= STARVATION_AGE_TICKS => Action::EscalateToSerialized {
                trigger: EscalationTrigger::Age,
            },
            _ => action_from_step(step, attempt.priority)?,
        };
        let evidence = self.evidence().map_err(RetryRefusal::Evidence)?;
        Ok(RetryDecision {
            action,
            epoch: step.epoch,
            selection: step.selection,
            published_epoch: step.published_epoch,
            evidence,
        })
    }

    /// Starts a fresh evidence window and publishes its new policy epoch.
    ///
    /// # Errors
    ///
    /// Returns the shared controller refusal if a new epoch cannot be issued.
    pub fn reset_window(&mut self) -> Result<PolicyEpoch, ControllerRefusal> {
        self.controller.reset_window()
    }

    /// The epoch currently in force.
    #[must_use]
    pub const fn epoch(&self) -> PolicyEpoch {
        self.controller.epoch()
    }

    /// The selected candidate or fallback currently in force.
    #[must_use]
    pub const fn selection(&self) -> PolicySelection {
        self.controller.selection()
    }

    /// The complete shared fallback gate for the current retry window.
    #[must_use]
    pub const fn gate(&self) -> PolicyGate {
        self.controller.gate()
    }

    /// Binds this retry stream into the section-26 statistical evidence body.
    ///
    /// The identity fields were supplied by the owning scheduler at construction
    /// because this library cannot truthfully invent a repository or runtime
    /// identity on its behalf. Every other field is read from the shared
    /// controller, which prevents a receipt from naming a different window,
    /// regime, or selection from the one that drove the action.
    ///
    /// # Errors
    ///
    /// Returns [`RetryEvidenceRefusal::NoObservations`] before the first retry,
    /// or the shared binding refusal when a controller field is invalid.
    pub fn evidence(&self) -> Result<StatisticalEvidenceBody, RetryEvidenceRefusal> {
        let window = self
            .controller
            .window()
            .ok_or(RetryEvidenceRefusal::NoObservations)?
            .map_err(RetryEvidenceRefusal::Binding)?;
        let assumptions =
            RetryBackoffController::assumptions().map_err(RetryEvidenceRefusal::Binding)?;
        Ok(StatisticalEvidenceBody {
            population: self.identity.population.clone(),
            selection: self.identity.selection.clone(),
            window,
            regime: self.controller.regime_binding(),
            policy: self.controller.selection(),
            assumptions,
            fingerprint: self.identity.fingerprint,
        })
    }
}

fn action_from_step(
    step: fgit_statistics::ControllerStep,
    priority: PriorityClass,
) -> Result<Action, RetryRefusal> {
    let micros = match step.decision {
        AdvisoryDecision::RetryBackoff { micros } => micros,
        decision => return Err(RetryRefusal::UnexpectedAdvisoryDecision(decision)),
    };
    let ticks = u32::try_from(micros / LOSS_PPM_PER_TICK)
        .unwrap_or(MAX_BACKOFF_TICKS)
        .min(MAX_BACKOFF_TICKS);
    // Priority may only improve the candidate's scheduling latency.  A pinned
    // fallback must remain exactly pinned, so it deliberately ignores priority.
    let ticks = match step.selection {
        PolicySelection::Candidate => ticks / priority.backoff_divisor(),
        PolicySelection::Fallback(_) => ticks,
    };
    if ticks == 0 {
        Ok(Action::RetryNow)
    } else {
        Ok(Action::BackoffFor { ticks })
    }
}

/// One NDJSON line recording a retry decision and the inputs behind it.
#[must_use]
pub fn receipt(attempt: Attempt, decision: &RetryDecision) -> String {
    // A receipt names the belief that informed this decision, including the
    // declared prior. `IncrementalPosterior::counts` is deliberately the
    // distinct real-observation evidence count, so use the canonical
    // posterior here rather than silently changing this receipt's meaning.
    let posterior = attempt.posterior.posterior();
    let successes = posterior.alpha();
    let failures = posterior.beta();
    let mut out = String::with_capacity(256);
    out.push_str("{\"record\":\"retry_decision\"");
    for (key, value) in [
        ("attempts", u64::from(attempt.attempts)),
        ("age_ticks", u64::from(attempt.age_ticks)),
        ("policy_epoch", decision.epoch.get()),
        ("posterior_successes", successes),
        ("posterior_failures", failures),
        (
            "success_probability_ppm",
            u64::from(attempt.posterior.success_probability().parts_per_million()),
        ),
        ("starvation_attempts", u64::from(STARVATION_ATTEMPTS)),
        ("starvation_age_ticks", u64::from(STARVATION_AGE_TICKS)),
    ] {
        out.push_str(",\"");
        out.push_str(key);
        out.push_str("\":");
        out.push_str(&value.to_string());
    }
    out.push_str(",\"priority\":\"");
    out.push_str(attempt.priority.as_str());
    out.push_str("\",\"selection\":\"");
    match decision.selection {
        PolicySelection::Candidate => out.push_str("candidate\""),
        PolicySelection::Fallback(trigger) => {
            out.push_str("fallback\",\"fallback_trigger_index\":");
            out.push_str(&trigger.index().to_string());
        }
    }
    out.push_str(",\"action\":\"");
    match decision.action {
        Action::RetryNow => out.push_str("retry_now\""),
        Action::BackoffFor { ticks } => {
            out.push_str("backoff\",\"ticks\":");
            out.push_str(&ticks.to_string());
        }
        Action::EscalateToSerialized { trigger } => {
            out.push_str("escalate_to_serialized\",\"trigger\":\"");
            out.push_str(trigger.as_str());
            out.push('"');
        }
    }
    out.push('}');
    out
}

#[cfg(test)]
mod tests {
    use super::{
        Action, Attempt, EscalationTrigger, MAX_BACKOFF_TICKS, PriorityClass, RetryController,
        RetryEvidenceIdentity, STARVATION_AGE_TICKS, STARVATION_ATTEMPTS, receipt,
    };
    use fgit_statistics::{BetaPrior, FallbackTrigger, IncrementalPosterior, PolicySelection};
    use fgit_types::{AsciiSlug, Digest, DigestAlgorithmId, DigestBytes};

    fn attempt(attempts: u32, age: u32, posterior: IncrementalPosterior) -> Attempt {
        Attempt {
            attempts,
            age_ticks: age,
            priority: PriorityClass::Interactive,
            posterior,
        }
    }

    fn hopeless() -> IncrementalPosterior {
        let mut p = IncrementalPosterior::new(BetaPrior::uniform());
        for _ in 0..10_000 {
            p.observe(false);
        }
        p
    }

    fn optimistic() -> IncrementalPosterior {
        let mut p = IncrementalPosterior::new(BetaPrior::uniform());
        for _ in 0..100 {
            p.observe(true);
        }
        p
    }

    fn identity() -> RetryEvidenceIdentity {
        RetryEvidenceIdentity::new(
            AsciiSlug::from_static("witness-retry"),
            AsciiSlug::from_static("sealed-transaction-retries"),
            Digest::new(
                DigestAlgorithmId::try_new(0x5_4).expect("fixture algorithm slot"),
                DigestBytes::try_new(&[5; 32]).expect("fixture digest bytes"),
            ),
        )
    }

    fn controller() -> RetryController {
        RetryController::new(identity()).expect("the pinned profile is valid")
    }

    fn decide(attempt: Attempt) -> super::RetryDecision {
        let mut controller = controller();
        controller
            .decide(1, attempt)
            .expect("the first observation cannot exhaust an epoch")
    }

    #[test]
    fn no_posterior_whatsoever_can_prevent_escalation() {
        // The central guarantee of plan section 16.5: statistical estimates
        // cannot deny liveness indefinitely. A maximally pessimistic posterior
        // must still escalate once the hard threshold is crossed.
        let hopeless = hopeless();
        assert!(
            hopeless.success_probability().parts_per_million() < 100_000,
            "the pessimistic control must remain near the reachable lower extreme"
        );
        let action = decide(attempt(STARVATION_ATTEMPTS, 0, hopeless)).action;
        assert_eq!(
            action,
            Action::EscalateToSerialized {
                trigger: EscalationTrigger::AttemptCount
            }
        );
        // And an optimistic one escalates identically: the escalator does not
        // consult the posterior at all.
        let mut optimistic = IncrementalPosterior::new(BetaPrior::uniform());
        for _ in 0..10_000 {
            optimistic.observe(true);
        }
        assert!(
            optimistic.success_probability().parts_per_million() > 900_000,
            "the optimistic control must remain near the reachable upper extreme"
        );
        assert_eq!(
            decide(attempt(STARVATION_ATTEMPTS, 0, optimistic)).action,
            Action::EscalateToSerialized {
                trigger: EscalationTrigger::AttemptCount
            }
        );
    }

    #[test]
    fn age_escalates_independently_of_attempt_count() {
        let action = decide(attempt(0, STARVATION_AGE_TICKS, hopeless())).action;
        assert_eq!(
            action,
            Action::EscalateToSerialized {
                trigger: EscalationTrigger::Age
            }
        );
    }

    #[test]
    fn priority_cannot_starve_anything() {
        // Priority damps backoff but is never read by the escalator, so the
        // lowest-priority class still escalates at exactly the same threshold.
        for priority in [
            PriorityClass::Background,
            PriorityClass::Interactive,
            PriorityClass::Foreground,
        ] {
            let action = decide(Attempt {
                attempts: STARVATION_ATTEMPTS,
                age_ticks: 0,
                priority,
                posterior: hopeless(),
            })
            .action;
            assert!(
                matches!(action, Action::EscalateToSerialized { .. }),
                "{priority:?} must still escalate"
            );
        }
    }

    #[test]
    fn a_regime_shift_publishes_the_shared_fallback_and_bindable_evidence() {
        let mut controller = controller();
        let start = controller.epoch();
        for sequence in 1..=3 {
            let decision = controller
                .decide(sequence, attempt(0, 0, optimistic()))
                .expect("in-regime retry observation");
            assert_eq!(decision.selection, PolicySelection::Candidate);
            assert!(!decision.published_epoch);
        }

        let fallback = controller
            .decide(4, attempt(0, 0, hopeless()))
            .expect("shift observation");
        assert_eq!(
            fallback.selection,
            PolicySelection::Fallback(FallbackTrigger::RegimeAlarm),
            "the injected loss regime must select the shared fallback"
        );
        assert!(fallback.published_epoch);
        assert_eq!(fallback.epoch.get(), start.get() + 1);
        assert_eq!(
            fallback.action,
            Action::BackoffFor {
                ticks: MAX_BACKOFF_TICKS
            },
            "the fallback must be the pinned maximum, not a priority-adjusted candidate"
        );

        let evidence = controller
            .evidence()
            .expect("the observed retry window must bind as evidence");
        assert_eq!(evidence.window.first(), 1);
        assert_eq!(evidence.window.last(), 4);
        assert_eq!(evidence.policy, fallback.selection);
        assert_eq!(evidence.regime.epoch, fallback.epoch.get());
        assert!(!evidence.assumptions.is_empty());
    }

    #[test]
    fn a_confident_transaction_retries_immediately() {
        let mut optimistic = IncrementalPosterior::new(BetaPrior::uniform());
        for _ in 0..100 {
            optimistic.observe(true);
        }
        assert_eq!(decide(attempt(1, 1, optimistic)).action, Action::RetryNow);
    }

    #[test]
    fn backoff_grows_as_the_posterior_worsens_and_stays_bounded() {
        let mut previous = 0_u32;
        for failures in [1_u32, 4, 16, 64] {
            let mut p = IncrementalPosterior::new(BetaPrior::uniform());
            for _ in 0..failures {
                p.observe(false);
            }
            let ticks = match decide(attempt(1, 1, p)).action {
                Action::BackoffFor { ticks } => ticks,
                Action::RetryNow => 0,
                other @ Action::EscalateToSerialized { .. } => panic!("unexpected {other:?}"),
            };
            assert!(ticks <= MAX_BACKOFF_TICKS, "backoff must stay bounded");
            assert!(
                ticks >= previous,
                "more failures must not reduce backoff: {ticks} < {previous}"
            );
            previous = ticks;
        }
    }

    #[test]
    fn higher_priority_waits_no_longer_than_lower_priority() {
        let p = hopeless();
        let ticks_for = |priority| match decide(Attempt {
            attempts: 1,
            age_ticks: 1,
            priority,
            posterior: p,
        })
        .action
        {
            Action::BackoffFor { ticks } => ticks,
            Action::RetryNow => 0,
            other @ Action::EscalateToSerialized { .. } => panic!("unexpected {other:?}"),
        };
        let background = ticks_for(PriorityClass::Background);
        let interactive = ticks_for(PriorityClass::Interactive);
        let foreground = ticks_for(PriorityClass::Foreground);
        assert!(interactive <= background);
        assert!(foreground <= interactive);
    }

    #[test]
    fn a_regime_reset_discards_history() {
        let mut p = hopeless();
        assert!(p.success_probability().parts_per_million() < 100_000);
        p.reset_for_regime();
        assert_eq!(p.counts(), (0, 0));
        assert_eq!((p.posterior().alpha(), p.posterior().beta()), (1, 1));
        assert_eq!(p.success_probability().parts_per_million(), 500_000);
    }

    #[test]
    fn posterior_counts_saturate_rather_than_wrapping() {
        let mut p = IncrementalPosterior::new(BetaPrior::uniform());
        for _ in 0..3 {
            p.observe(true);
        }
        let (successes, failures) = p.counts();
        assert_eq!((successes, failures), (3, 0));
        assert_eq!((p.posterior().alpha(), p.posterior().beta()), (4, 1));
        // A wrapped count would invert the posterior; pin that it cannot.
        let mut extreme = IncrementalPosterior::new(BetaPrior::uniform());
        for _ in 0..64 {
            extreme.observe(false);
        }
        assert!(extreme.success_probability().parts_per_million() < 500_000);
    }

    #[test]
    fn the_decision_is_deterministic() {
        let a = attempt(3, 7, hopeless());
        assert_eq!(decide(a), decide(a));
        assert_eq!(receipt(a, &decide(a)), receipt(a, &decide(a)));
    }

    #[test]
    fn the_receipt_names_the_hard_thresholds_so_a_reader_can_check_the_escalator() {
        let a = attempt(STARVATION_ATTEMPTS, 0, hopeless());
        let line = receipt(a, &decide(a));
        assert!(!line.contains('\n'), "one record per line: {line}");
        for key in [
            "\"record\":\"retry_decision\"",
            "\"attempts\":8",
            "\"starvation_attempts\":8",
            "\"starvation_age_ticks\":512",
            "\"action\":\"escalate_to_serialized\"",
            "\"trigger\":\"attempt_count\"",
        ] {
            assert!(line.contains(key), "receipt missing {key}: {line}");
        }
    }

    #[test]
    fn a_backoff_receipt_carries_its_tick_count() {
        let a = attempt(1, 1, hopeless());
        let decision = decide(a);
        let line = receipt(a, &decision);
        if let Action::BackoffFor { ticks } = decision.action {
            assert!(line.contains(&format!("\"ticks\":{ticks}")), "{line}");
        } else {
            panic!(
                "expected a backoff for a hopeless posterior, got {:?}",
                decision.action
            );
        }
    }
}
