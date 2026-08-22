//! A retry-backoff controller: evidence in, policy epochs out, fallback on drift.
//!
//! This is the bead's demo controller, and its job is to prove the other four
//! modules compose into something that runs rather than four types that merely
//! coexist. Observations go in with their sequence numbers; a [`PolicyEpoch`]
//! comes out whenever the selection changes; and an injected regime shift drives
//! the controller onto its pinned deterministic fallback.
//!
//! # Every fallback trigger is reachable from here
//!
//! [`crate::fallback`] defines five disqualifying conditions. A gate whose
//! conditions no caller can actually set is decoration, so this controller wires
//! all five to something it can observe:
//!
//! | condition | what sets it |
//! |---|---|
//! | evidence gap | a sequence number that is not its predecessor's successor |
//! | support failure | an observation outside the declared `max_deviation` |
//! | regime alarm | the CUSUM detector alarming |
//! | numeric-bound violation | the detector's accumulator saturating |
//! | stale window | more observations retained than the declared bound |
//!
//! # Why the conditions latch
//!
//! Once any of them fires, it stays set until [`RetryBackoffController::reset_window`]
//! is called. A condition that cleared itself on the next good observation would
//! let a controller drift back onto its adaptive candidate while the window it
//! is reasoning over still contains the gap, the out-of-support value, or the
//! regime change. The window is the unit the evidence is bound to, so the window
//! is what has to be replaced — explicitly, and with a fresh epoch, rather than
//! by the next observation happening to look fine.

use fgit_types::{AsciiSlug, PolicyEpoch, TypeRefusal};

use crate::authority::AdvisoryDecision;
use crate::evidence::{AssumptionSet, BindingRefusal, RegimeBinding, SequenceWindow};
use crate::fallback::{FallbackTrigger, PolicyGate, PolicySelection};
use crate::regime::{AssumptionFailure, Cusum, CusumConfig, Scaled};

/// How the controller is configured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControllerConfig {
    /// The regime detector's configuration.
    pub cusum: CusumConfig,
    /// The backoff used when the stream sits exactly at target.
    pub base_backoff_micros: u64,
    /// The pinned deterministic backoff used whenever a trigger fires.
    ///
    /// Fixed at construction and never adapted — that is what makes it a
    /// fallback rather than a second candidate.
    pub pinned_fallback_micros: u64,
    /// The largest number of observations one window may retain.
    pub max_retained_observations: u32,
}

/// Why a controller could not be built or could not take a step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControllerRefusal {
    /// The detector's assumptions do not hold.
    Detector(AssumptionFailure),
    /// `max_retained_observations` is zero, so no window could ever be valid.
    RetentionBoundZero,
    /// The policy epoch counter is exhausted.
    ///
    /// Refused rather than wrapped: a wrapped epoch would make a later policy
    /// look older than an earlier one, and epochs are how adaptive choices are
    /// ordered.
    EpochExhausted,
}

/// What one observation produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControllerStep {
    /// The epoch in force after this observation.
    pub epoch: PolicyEpoch,
    /// Whether this observation published a new epoch.
    pub published_epoch: bool,
    /// Whether the candidate ran, or which trigger selected the fallback.
    pub selection: PolicySelection,
    /// The backoff to use.
    pub decision: AdvisoryDecision,
}

/// A retry-backoff controller over one evidence stream.
#[derive(Clone, Copy, Debug)]
pub struct RetryBackoffController {
    config: ControllerConfig,
    detector: Cusum,
    epoch: PolicyEpoch,
    selection: PolicySelection,
    gate: PolicyGate,
    first_sequence: Option<u64>,
    last_sequence: Option<u64>,
    retained: u32,
}

impl RetryBackoffController {
    /// Builds a controller, checking the detector's assumptions first.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerRefusal::Detector`] when the detector's assumptions
    /// fail, or [`ControllerRefusal::RetentionBoundZero`] for a zero retention
    /// bound.
    pub const fn new(config: ControllerConfig) -> Result<Self, ControllerRefusal> {
        Self::new_at_epoch(config, PolicyEpoch::FIRST)
    }

    /// Builds a controller resuming from an already-published epoch.
    ///
    /// Epochs are stream-sequenced, so a controller restarted after a crash must
    /// not reissue an epoch a reader has already seen. This is the entry point
    /// for that: the caller supplies the last epoch it published, and the next
    /// selection change advances past it.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerRefusal::Detector`] when the detector's assumptions
    /// fail, or [`ControllerRefusal::RetentionBoundZero`] for a zero retention
    /// bound.
    pub const fn new_at_epoch(
        config: ControllerConfig,
        epoch: PolicyEpoch,
    ) -> Result<Self, ControllerRefusal> {
        if config.max_retained_observations == 0 {
            return Err(ControllerRefusal::RetentionBoundZero);
        }
        let detector = match Cusum::new(config.cusum) {
            Err(failure) => return Err(ControllerRefusal::Detector(failure)),
            Ok(detector) => detector,
        };
        Ok(Self {
            config,
            detector,
            epoch,
            // The controller starts on its candidate, and the first observation
            // that disqualifies it publishes a new epoch.
            selection: PolicySelection::Candidate,
            gate: PolicyGate::all_clear(),
            first_sequence: None,
            last_sequence: None,
            retained: 0,
        })
    }

    /// Feeds one observation and returns the policy in force afterwards.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerRefusal::EpochExhausted`] when a selection change
    /// would need an epoch beyond the counter's range.
    pub fn observe(
        &mut self,
        sequence: u64,
        value: Scaled,
    ) -> Result<ControllerStep, ControllerRefusal> {
        if let Some(last) = self.last_sequence {
            // A sequence number that is not the immediate successor means the
            // stream is missing observations it declared it would have.
            if sequence != last.saturating_add(1) {
                self.gate.set(FallbackTrigger::EvidenceGap);
            }
        } else {
            self.first_sequence = Some(sequence);
        }
        self.last_sequence = Some(sequence);

        // Support: an observation further from target than the caller declared
        // possible is outside the range the detector's assumptions were checked
        // against, so its statistic is not one this mechanism can stand behind.
        let deviation = value.saturating_sub(self.config.cusum.target);
        if deviation.saturating_abs() > self.config.cusum.max_deviation {
            self.gate.set(FallbackTrigger::SupportFailure);
        }

        if self.detector.observe(value).is_some() {
            self.gate.set(FallbackTrigger::RegimeAlarm);
        }
        if self.detector.saturated() {
            self.gate.set(FallbackTrigger::NumericBoundViolation);
        }

        self.retained = self.retained.saturating_add(1);
        if self.retained > self.config.max_retained_observations {
            self.gate.set(FallbackTrigger::StaleWindow);
        }

        let selection = self.gate.select();
        let published_epoch = selection != self.selection;
        if published_epoch {
            self.epoch = self
                .epoch
                .next()
                .map_err(|_: TypeRefusal| ControllerRefusal::EpochExhausted)?;
            self.selection = selection;
        }

        Ok(ControllerStep {
            epoch: self.epoch,
            published_epoch,
            selection,
            decision: self.backoff_for(selection, value),
        })
    }

    /// The backoff this selection implies.
    ///
    /// The candidate adds the observed excess over target to the base delay:
    /// integer, division-free, and monotone in the observation. The fallback
    /// ignores the observation entirely, which is the whole point of a pinned
    /// deterministic policy.
    fn backoff_for(&self, selection: PolicySelection, value: Scaled) -> AdvisoryDecision {
        let micros = match selection {
            PolicySelection::Fallback(_) => self.config.pinned_fallback_micros,
            PolicySelection::Candidate => {
                let excess = value.saturating_sub(self.config.cusum.target);
                let excess = if excess > 0 { excess } else { 0 };
                // Deliberately not `as u64`. `excess` is provably non-negative
                // one line above, so the conversion cannot fail and the `0` is
                // unreachable -- but a signed-to-unsigned `as` would silently
                // turn a negative into an enormous delay if that proof ever
                // stopped holding, and an enormous retry delay is indisputable
                // from the outside. This costs `const` on a private helper the
                // only caller of which is not `const` anyway.
                let excess = u64::try_from(excess).unwrap_or(0);
                self.config.base_backoff_micros.saturating_add(excess)
            }
        };
        AdvisoryDecision::RetryBackoff { micros }
    }

    /// Starts a fresh window, clearing every latched condition.
    ///
    /// Publishes a new epoch unconditionally: the policy after a window reset is
    /// not the policy before it, even when the selection happens to match, and a
    /// reader comparing two decisions needs to see that the basis changed.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerRefusal::EpochExhausted`] when the counter is spent.
    pub fn reset_window(&mut self) -> Result<PolicyEpoch, ControllerRefusal> {
        let detector = Cusum::new(self.config.cusum).map_err(ControllerRefusal::Detector)?;
        self.detector = detector;
        self.gate = PolicyGate::all_clear();
        self.first_sequence = None;
        self.last_sequence = None;
        self.retained = 0;
        self.selection = PolicySelection::Candidate;
        self.epoch = self
            .epoch
            .next()
            .map_err(|_: TypeRefusal| ControllerRefusal::EpochExhausted)?;
        Ok(self.epoch)
    }

    /// The epoch currently in force.
    #[must_use]
    pub const fn epoch(self) -> PolicyEpoch {
        self.epoch
    }

    /// The selection currently in force.
    #[must_use]
    pub const fn selection(self) -> PolicySelection {
        self.selection
    }

    /// Every disqualifying condition observed in this window.
    ///
    /// Exposed because [`PolicySelection`] reports only the *first* condition in
    /// [`crate::fallback::FallbackTrigger::ALL`] order, which is what makes the
    /// decision path replayable — but a window can have several conditions set
    /// at once, and section 33.1 binds the conditions rather than only the
    /// outcome. A reader that saw just the reported trigger would conclude the
    /// others were clear.
    #[must_use]
    pub const fn gate(self) -> PolicyGate {
        self.gate
    }

    /// The window observed so far, if any observation has arrived.
    ///
    /// # Errors
    ///
    /// Returns [`BindingRefusal::WindowInverted`] when the observed sequence
    /// numbers ran backwards, which the controller records rather than repairs.
    #[must_use]
    pub const fn window(&self) -> Option<Result<SequenceWindow, BindingRefusal>> {
        match (self.first_sequence, self.last_sequence) {
            (Some(first), Some(last)) => Some(SequenceWindow::try_new(first, last)),
            _ => None,
        }
    }

    /// The regime binding for the current window.
    #[must_use]
    pub const fn regime_binding(&self) -> RegimeBinding {
        RegimeBinding::from_detector(self.epoch.get(), &self.detector)
    }

    /// The assumptions this controller checked to produce its decisions.
    ///
    /// # Errors
    ///
    /// Returns a [`BindingRefusal`] only if the label set is malformed, which
    /// the fixed labels below make unreachable.
    pub fn assumptions() -> Result<AssumptionSet, BindingRefusal> {
        AssumptionSet::try_new(vec![
            AsciiSlug::from_static("cusum-slack-positive"),
            AsciiSlug::from_static("cusum-threshold-positive"),
            AsciiSlug::from_static("cusum-cannot-saturate"),
            AsciiSlug::from_static("observations-consecutive"),
            AsciiSlug::from_static("observations-within-declared-support"),
        ])
    }
}
