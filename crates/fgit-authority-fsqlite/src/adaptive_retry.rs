#![forbid(unsafe_code)]
//! Identity-bound adaptive authority-CAS contention retry controller
//! (`frankengit-root-doctrine-x2mv.4.37`).
//!
//! This module is the first production consumer of [`fgit_statistics`] inside
//! the embedded `FrankenSQLite` authority store:
//!
//! * Each whole-transaction store operation produces one sequenced contention
//!   observation (`contended: bool`, `retry_attempts: u32`).
//! * A betting [`EProcess`] monitors the Bernoulli contention rate for regime
//!   shifts (`wealth >= 1 / alpha`) in exact integer parts-per-million
//!   arithmetic, paired with an integer [`Cusum`] excursion detector on retry
//!   depth.
//! * While sample support is below `min_support_observations`, or whenever any
//!   [`FallbackTrigger`] (`EvidenceGap`, `SupportFailure`, `RegimeAlarm`,
//!   `NumericBoundViolation`, `StaleWindow`) fires, [`PolicyGate`] selects the
//!   pinned deterministic fallback (`2 ms ..= 512 ms`).
//! * Every decision epoch binds all seven of `AGENTS.md` §8's obligations in a
//!   canonical [`StatisticalEvidenceBody`] (`population`, `selection`,
//!   `window`, `regime`, `policy`, `assumptions`, `fingerprint`) plus the
//!   metric, candidate policy, fallback policy, and canonical body digest.
//! * Authority boundary (§33.4): the controller emits only
//!   [`AdvisoryDecision::RetryBackoff`] validated through [`resolve`], and
//!   never decides commit, ref atomicity, authorization, or error
//!   classification (`decide_after_failure` and the caller's deadline remain
//!   hard invariants).

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_codec::encode_body;
use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_statistics::authority::{
    AdvisoryDecision, DecisionRefusal, ForbiddenTarget, ProposedTarget, resolve,
};
use fgit_statistics::{
    AssumptionFailure, AssumptionSet, BindingRefusal, Cusum, CusumConfig, EProcess,
    EProcessAssumptionFailure, EProcessConfig, EProcessRefusal, FallbackTrigger, PolicyGate,
    PolicySelection, RegimeBinding, Scaled, SequenceWindow, StatisticalEvidenceBody,
};
use fgit_types::{AsciiSlug, Digest, PolicyEpoch, TypeRefusal};

use crate::retry::BackoffPlan;

/// Canonical metric identifier for authority-CAS contention backoff.
pub const METRIC_SLUG: &str = "authority-cas-contention-backoff-ms";
/// Canonical candidate policy identifier.
pub const CANDIDATE_POLICY_SLUG: &str = "eprocess-adaptive-cas-backoff-v1";
/// Canonical pinned deterministic fallback policy identifier.
pub const FALLBACK_POLICY_SLUG: &str = "pinned-exponential-jitter-2ms-512ms-v1";
/// Canonical population slug (binding 1).
pub const POPULATION_SLUG: &str = "authority-store-whole-txn-attempts";
/// Canonical selection slug (binding 2).
pub const SELECTION_SLUG: &str = "all-admitted-store-operations";
/// Toolchain and integer-arithmetic profile preimage (binding 7).
pub const TOOLCHAIN_FINGERPRINT_PREIMAGE: &[u8] =
    b"frankengit/authority-cas-retry-toolchain/v1:rustc-1.100.0-nightly-2026-08-30:integer-ppm-v1";

/// Maximum number of decision-epoch evidence records retained in memory.
pub const MAX_EPOCH_HISTORY: usize = 64;

/// Default minimum observations required before leaving the warmup fallback.
pub const DEFAULT_MIN_SUPPORT_OBSERVATIONS: u32 = 8;
/// Default maximum observations retained in one window before requiring reset.
pub const DEFAULT_MAX_RETAINED_OBSERVATIONS: u32 = 4_096;
/// Default adaptive candidate base backoff in milliseconds.
pub const CANDIDATE_BACKOFF_BASE_MS: u64 = 1;
/// Default adaptive candidate ceiling backoff in milliseconds.
pub const CANDIDATE_BACKOFF_CEILING_MS: u64 = 256;
/// Pinned deterministic fallback base backoff in milliseconds.
pub const FALLBACK_BACKOFF_BASE_MS: u64 = 2;
/// Pinned deterministic fallback ceiling backoff in milliseconds.
pub const FALLBACK_BACKOFF_CEILING_MS: u64 = 512;

/// Configuration for [`AdaptiveRetryController`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdaptiveRetryConfig {
    /// Anytime-valid Bernoulli e-process detector configuration.
    pub e_process: EProcessConfig,
    /// Integer CUSUM retry-depth excursion detector configuration.
    pub cusum: CusumConfig,
    /// Minimum observations required before trusting the candidate policy.
    pub min_support_observations: u32,
    /// Maximum observations retained in one window before `StaleWindow` fires.
    pub max_retained_observations: u32,
    /// Base backoff (ms) when `PolicySelection::Candidate` is active.
    pub candidate_base_ticks: u64,
    /// Ceiling backoff (ms) when `PolicySelection::Candidate` is active.
    pub candidate_ceiling_ticks: u64,
    /// Pinned fallback base backoff (ms) when any `FallbackTrigger` is active.
    pub fallback_base_ticks: u64,
    /// Pinned fallback ceiling backoff (ms) when any `FallbackTrigger` is active.
    pub fallback_ceiling_ticks: u64,
}

impl Default for AdaptiveRetryConfig {
    fn default() -> Self {
        Self {
            e_process: EProcessConfig {
                // Null hypothesis: <= 15% of store operations encounter transient contention.
                null_rate_parts_per_million: 150_000,
                // Bet fraction lambda = 0.50 (loss multiplier 1 - 0.075 = 0.925 > 0).
                bet_parts_per_million: 500_000,
                // Type-I alarm threshold alpha = 0.05 (wealth threshold = 20x).
                alarm_alpha_parts_per_million: 50_000,
            },
            cusum: CusumConfig {
                target: 0,
                slack: 1,
                threshold: 16,
                max_deviation: 64,
            },
            min_support_observations: DEFAULT_MIN_SUPPORT_OBSERVATIONS,
            max_retained_observations: DEFAULT_MAX_RETAINED_OBSERVATIONS,
            candidate_base_ticks: CANDIDATE_BACKOFF_BASE_MS,
            candidate_ceiling_ticks: CANDIDATE_BACKOFF_CEILING_MS,
            fallback_base_ticks: FALLBACK_BACKOFF_BASE_MS,
            fallback_ceiling_ticks: FALLBACK_BACKOFF_CEILING_MS,
        }
    }
}

/// Typed refusal from constructing or stepping [`AdaptiveRetryController`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdaptiveRetryRefusal {
    /// E-process detector assumptions failed.
    EProcess(EProcessAssumptionFailure),
    /// CUSUM detector assumptions failed.
    Cusum(AssumptionFailure),
    /// `min_support_observations` was zero or exceeded `max_retained_observations`.
    InvalidSupportBounds {
        /// Requested minimum support observations.
        min_support: u32,
        /// Requested maximum retained observations.
        max_retained: u32,
    },
    /// Backoff bounds were zero or inverted (`base > ceiling`).
    InvalidBackoffBounds {
        /// Base ticks offered.
        base_ticks: u64,
        /// Ceiling ticks offered.
        ceiling_ticks: u64,
    },
    /// Evidence binding construction failed.
    Binding(BindingRefusal),
    /// Authority boundary refused a non-admissible target.
    Decision(DecisionRefusal),
    /// Policy epoch counter exhausted.
    EpochExhausted,
}

/// Immutable record of one statistical policy epoch and its canonical evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdaptiveRetryEpochLog {
    /// Stream-sequenced policy epoch.
    pub epoch: PolicyEpoch,
    /// Metric identifier (`authority-cas-contention-backoff-ms`).
    pub metric: AsciiSlug,
    /// Candidate policy identifier (`eprocess-adaptive-cas-backoff-v1`).
    pub candidate_policy: AsciiSlug,
    /// Pinned fallback policy identifier (`pinned-exponential-jitter-2ms-512ms-v1`).
    pub fallback_policy: AsciiSlug,
    /// E-process wealth at epoch publication, in parts per million (`1_000_000` = 1.0).
    pub e_process_wealth_ppm: u128,
    /// Whether the e-process alarm has fired.
    pub e_process_alarmed: bool,
    /// Validated advisory backoff decision (`RetryBackoff { micros }`).
    pub decision: AdvisoryDecision,
    /// Canonical `AGENTS.md` §8 statistical evidence body (all 7 bindings).
    pub evidence: StatisticalEvidenceBody,
    /// SHA-256 commitment over the canonical wire encoding of `evidence`.
    pub evidence_canonical_sha256: Digest,
}

impl AdaptiveRetryEpochLog {
    /// Formats a deterministic single-line JSON log entry carrying the full
    /// `AGENTS.md` §8 / README §9 evidence identity for this decision epoch.
    #[must_use]
    pub fn to_json_line(&self) -> String {
        let policy_str = match self.evidence.policy {
            PolicySelection::Candidate => "candidate".to_owned(),
            PolicySelection::Fallback(trigger) => {
                format!("fallback:{}", fallback_trigger_slug(trigger))
            }
        };
        let selected_policy_id = if self.evidence.policy.admits_candidate() {
            self.candidate_policy.as_str()
        } else {
            self.fallback_policy.as_str()
        };
        let backoff_micros = match self.decision {
            AdvisoryDecision::RetryBackoff { micros } => micros,
            _ => 0,
        };
        let assumptions_json = self
            .evidence
            .assumptions
            .as_slice()
            .iter()
            .map(|slug| format!("\"{}\"", slug.as_str()))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            concat!(
                "{{\"type\":\"statistical_policy_epoch\",",
                "\"epoch\":{},",
                "\"metric\":\"{}\",",
                "\"population\":\"{}\",",
                "\"selection\":\"{}\",",
                "\"window_first\":{},",
                "\"window_last\":{},",
                "\"regime_epoch\":{},",
                "\"detector_high\":{},",
                "\"detector_low\":{},",
                "\"detector_observations\":{},",
                "\"detector_saturated\":{},",
                "\"e_process_wealth_ppm\":{},",
                "\"e_process_alarmed\":{},",
                "\"policy_selection\":\"{}\",",
                "\"selected_policy_id\":\"{}\",",
                "\"candidate_policy_id\":\"{}\",",
                "\"fallback_policy_id\":\"{}\",",
                "\"advisory_backoff_micros\":{},",
                "\"assumptions\":[{}],",
                "\"toolchain_fingerprint\":\"{}\",",
                "\"evidence_canonical_sha256\":\"{}\"}}"
            ),
            self.epoch.get(),
            self.metric.as_str(),
            self.evidence.population.as_str(),
            self.evidence.selection.as_str(),
            self.evidence.window.first(),
            self.evidence.window.last(),
            self.evidence.regime.epoch,
            self.evidence.regime.detector_high,
            self.evidence.regime.detector_low,
            self.evidence.regime.observations,
            self.evidence.regime.saturated,
            self.e_process_wealth_ppm,
            self.e_process_alarmed,
            policy_str,
            selected_policy_id,
            self.candidate_policy.as_str(),
            self.fallback_policy.as_str(),
            backoff_micros,
            assumptions_json,
            self.evidence.fingerprint,
            self.evidence_canonical_sha256,
        )
    }
}

/// Result of feeding one contention observation into [`AdaptiveRetryController`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdaptiveRetryStep {
    /// Policy epoch in force after this observation.
    pub epoch: PolicyEpoch,
    /// Whether this observation transitioned the controller to a new epoch.
    pub published_epoch: bool,
    /// Active policy selection (`Candidate` or `Fallback(FallbackTrigger)`).
    pub selection: PolicySelection,
    /// Base backoff ticks (ms) in force.
    pub base_ticks: u64,
    /// Ceiling backoff ticks (ms) in force.
    pub ceiling_ticks: u64,
    /// Current e-process wealth in parts per million.
    pub e_process_wealth_ppm: u128,
    /// Updated evidence record for the active epoch.
    pub epoch_log: AdaptiveRetryEpochLog,
}

/// Read-only point-in-time snapshot of the store's adaptive retry controller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdaptiveRetrySnapshot {
    /// Current policy epoch.
    pub current_epoch: PolicyEpoch,
    /// Current policy selection (`Candidate` or `Fallback(FallbackTrigger)`).
    pub active_selection: PolicySelection,
    /// Active base backoff in milliseconds.
    pub active_base_ticks: u64,
    /// Active ceiling backoff in milliseconds.
    pub active_ceiling_ticks: u64,
    /// Total observations processed across the store's lifetime.
    pub total_observations: u64,
    /// Observations retained in the current window.
    pub retained_observations: u32,
    /// Total observations that experienced transient contention.
    pub contended_observations: u64,
    /// Current e-process wealth in parts per million.
    pub e_process_wealth_ppm: u128,
    /// Whether the e-process regime alarm is currently latched.
    pub e_process_alarmed: bool,
    /// Evidence record for the current epoch (once at least one observation exists).
    pub current_evidence: Option<AdaptiveRetryEpochLog>,
    /// Bounded history of published decision epochs in chronological order.
    pub epoch_history: Vec<AdaptiveRetryEpochLog>,
}

/// Adaptive authority-CAS retry controller combining an anytime-valid
/// [`EProcess`] contention-rate detector with an integer [`Cusum`] retry-depth
/// detector and fail-closed [`PolicyGate`] fallback selection.
#[derive(Clone, Debug)]
pub struct AdaptiveRetryController {
    config: AdaptiveRetryConfig,
    e_process: EProcess,
    cusum: Cusum,
    gate: PolicyGate,
    epoch: PolicyEpoch,
    active_selection: PolicySelection,
    first_sequence: Option<u64>,
    last_sequence: Option<u64>,
    retained: u32,
    total_observations: u64,
    contended_observations: u64,
    current_evidence: Option<AdaptiveRetryEpochLog>,
    epoch_history: VecDeque<AdaptiveRetryEpochLog>,
}

impl AdaptiveRetryController {
    /// Constructs a controller after validating detector and support assumptions.
    ///
    /// Starts in `PolicySelection::Fallback(FallbackTrigger::SupportFailure)`
    /// until `min_support_observations` have been observed in the window.
    ///
    /// # Errors
    ///
    /// Returns [`AdaptiveRetryRefusal`] if any detector assumption or bound is invalid.
    pub fn new(config: AdaptiveRetryConfig) -> Result<Self, AdaptiveRetryRefusal> {
        if config.min_support_observations == 0
            || config.max_retained_observations == 0
            || config.min_support_observations > config.max_retained_observations
        {
            return Err(AdaptiveRetryRefusal::InvalidSupportBounds {
                min_support: config.min_support_observations,
                max_retained: config.max_retained_observations,
            });
        }
        if config.candidate_base_ticks == 0
            || config.candidate_base_ticks > config.candidate_ceiling_ticks
        {
            return Err(AdaptiveRetryRefusal::InvalidBackoffBounds {
                base_ticks: config.candidate_base_ticks,
                ceiling_ticks: config.candidate_ceiling_ticks,
            });
        }
        if config.fallback_base_ticks == 0
            || config.fallback_base_ticks > config.fallback_ceiling_ticks
        {
            return Err(AdaptiveRetryRefusal::InvalidBackoffBounds {
                base_ticks: config.fallback_base_ticks,
                ceiling_ticks: config.fallback_ceiling_ticks,
            });
        }
        let e_process = EProcess::new(config.e_process).map_err(AdaptiveRetryRefusal::EProcess)?;
        let cusum = Cusum::new(config.cusum).map_err(AdaptiveRetryRefusal::Cusum)?;
        Ok(Self {
            config,
            e_process,
            cusum,
            gate: PolicyGate::all_clear(),
            epoch: PolicyEpoch::FIRST,
            // Fail closed before sufficient sample support is accumulated.
            active_selection: PolicySelection::Fallback(FallbackTrigger::SupportFailure),
            first_sequence: None,
            last_sequence: None,
            retained: 0,
            total_observations: 0,
            contended_observations: 0,
            current_evidence: None,
            epoch_history: VecDeque::with_capacity(MAX_EPOCH_HISTORY),
        })
    }

    /// Builds the default production controller.
    #[must_use]
    pub fn default_production() -> Self {
        Self::new(AdaptiveRetryConfig::default())
            .expect("default production AdaptiveRetryConfig satisfies all detector assumptions")
    }

    /// Returns the active `(base_ticks, ceiling_ticks)` pair in milliseconds.
    #[must_use]
    pub const fn active_bounds_ticks(&self) -> (u64, u64) {
        match self.active_selection {
            PolicySelection::Candidate => (
                self.config.candidate_base_ticks,
                self.config.candidate_ceiling_ticks,
            ),
            PolicySelection::Fallback(_) => (
                self.config.fallback_base_ticks,
                self.config.fallback_ceiling_ticks,
            ),
        }
    }

    /// Returns the [`BackoffPlan`] for a store operation with jitter `seed`.
    #[must_use]
    pub const fn active_backoff_plan(&self, seed: u64) -> BackoffPlan {
        let (base_ticks, ceiling_ticks) = self.active_bounds_ticks();
        BackoffPlan::new(base_ticks, ceiling_ticks, seed)
    }

    /// Verifies that a proposed target is permitted by `fgit-statistics` §33.4.
    ///
    /// Any attempt to use statistical state for [`ForbiddenTarget`] (`Identity`,
    /// `Authorization`, `Retention`, `Deletion`, `Ordering`) is refused.
    ///
    /// # Errors
    ///
    /// Returns [`AdaptiveRetryRefusal::Decision`] when `target` is forbidden or
    /// mismatched with [`AdvisoryDecision::RetryBackoff`].
    pub fn authorize_target(
        &self,
        target: ProposedTarget,
    ) -> Result<AdvisoryDecision, AdaptiveRetryRefusal> {
        let (base_ticks, _) = self.active_bounds_ticks();
        let candidate = AdvisoryDecision::RetryBackoff {
            micros: base_ticks.saturating_mul(1_000),
        };
        resolve(target, candidate).map_err(AdaptiveRetryRefusal::Decision)
    }

    /// Feeds one whole-transaction operation outcome into the controller.
    ///
    /// * `sequence` — strictly increasing observation sequence number (`1, 2, ...`).
    /// * `contended` — `true` if the operation encountered at least one retryable
    ///   transient engine contention failure (`TransientClass::is_retryable()`).
    /// * `retry_attempts` — number of transient retries performed (`0` when
    ///   uncontended on the first attempt).
    ///
    /// # Errors
    ///
    /// Returns [`AdaptiveRetryRefusal`] if evidence binding fails or the epoch
    /// counter is exhausted.
    pub fn observe(
        &mut self,
        sequence: u64,
        contended: bool,
        retry_attempts: u32,
    ) -> Result<AdaptiveRetryStep, AdaptiveRetryRefusal> {
        if let Some(last) = self.last_sequence {
            if sequence != last.saturating_add(1) {
                self.gate.set(FallbackTrigger::EvidenceGap);
            }
        } else {
            self.first_sequence = Some(sequence);
        }
        let first_seq = self.first_sequence.unwrap_or(sequence);
        let last_seq = sequence.max(first_seq);
        self.last_sequence = Some(sequence);

        match self.e_process.observe(contended) {
            Ok(step) => {
                if step.alarmed() {
                    self.gate.set(FallbackTrigger::RegimeAlarm);
                }
            }
            Err(EProcessRefusal::WealthOverflow) => {
                self.gate.set(FallbackTrigger::NumericBoundViolation);
            }
        }

        let excursion = Scaled::from(retry_attempts);
        let deviation = excursion.saturating_sub(self.config.cusum.target);
        if deviation.saturating_abs() > self.config.cusum.max_deviation {
            self.gate.set(FallbackTrigger::SupportFailure);
        }
        if self.cusum.observe(excursion).is_some() {
            self.gate.set(FallbackTrigger::RegimeAlarm);
        }
        if self.cusum.saturated() {
            self.gate.set(FallbackTrigger::NumericBoundViolation);
        }

        self.retained = self.retained.saturating_add(1);
        self.total_observations = self.total_observations.saturating_add(1);
        if contended {
            self.contended_observations = self.contended_observations.saturating_add(1);
        }
        if self.retained > self.config.max_retained_observations {
            self.gate.set(FallbackTrigger::StaleWindow);
        }

        // Determine effective selection: latched disqualifiers take priority in
        // canonical `FallbackTrigger::ALL` order; otherwise insufficient sample
        // support (`retained < min_support_observations`) selects `SupportFailure`
        // without latching once the warmup window is satisfied.
        let gated = self.gate.select();
        let effective_selection = match gated {
            PolicySelection::Fallback(trigger) => PolicySelection::Fallback(trigger),
            PolicySelection::Candidate => {
                if self.retained < self.config.min_support_observations {
                    PolicySelection::Fallback(FallbackTrigger::SupportFailure)
                } else {
                    PolicySelection::Candidate
                }
            }
        };

        let is_first_observation = self.retained == 1;
        let selection_changed = effective_selection != self.active_selection;
        let published_epoch = is_first_observation || selection_changed;
        if selection_changed && !is_first_observation {
            self.epoch = self
                .epoch
                .next()
                .map_err(|_: TypeRefusal| AdaptiveRetryRefusal::EpochExhausted)?;
        }
        self.active_selection = effective_selection;

        let (base_ticks, ceiling_ticks) = self.active_bounds_ticks();
        let decision = resolve(
            ProposedTarget::RetryBackoff,
            AdvisoryDecision::RetryBackoff {
                micros: base_ticks.saturating_mul(1_000),
            },
        )
        .map_err(AdaptiveRetryRefusal::Decision)?;

        let epoch_log = self.build_epoch_log(first_seq, last_seq, effective_selection, decision)?;
        self.current_evidence = Some(epoch_log.clone());
        if published_epoch {
            if self.epoch_history.len() >= MAX_EPOCH_HISTORY {
                self.epoch_history.pop_front();
            }
            self.epoch_history.push_back(epoch_log.clone());
        } else if let Some(back) = self.epoch_history.back_mut() {
            *back = epoch_log.clone();
        }

        Ok(AdaptiveRetryStep {
            epoch: self.epoch,
            published_epoch,
            selection: effective_selection,
            base_ticks,
            ceiling_ticks,
            e_process_wealth_ppm: self.e_process.wealth_parts_per_million(),
            epoch_log,
        })
    }

    /// Resets the current observation window and detectors, advancing to a new
    /// [`PolicyEpoch`] and returning to the warmup support gate.
    ///
    /// # Errors
    ///
    /// Returns [`AdaptiveRetryRefusal`] if detector re-initialization fails or
    /// the epoch counter is exhausted.
    pub fn reset_window(&mut self) -> Result<PolicyEpoch, AdaptiveRetryRefusal> {
        let e_process =
            EProcess::new(self.config.e_process).map_err(AdaptiveRetryRefusal::EProcess)?;
        let cusum = Cusum::new(self.config.cusum).map_err(AdaptiveRetryRefusal::Cusum)?;
        self.epoch = self
            .epoch
            .next()
            .map_err(|_: TypeRefusal| AdaptiveRetryRefusal::EpochExhausted)?;
        self.e_process = e_process;
        self.cusum = cusum;
        self.gate = PolicyGate::all_clear();
        self.active_selection = PolicySelection::Fallback(FallbackTrigger::SupportFailure);
        self.first_sequence = None;
        self.last_sequence = None;
        self.retained = 0;
        Ok(self.epoch)
    }

    /// Captures a point-in-time snapshot of the controller and its epoch logs.
    #[must_use]
    pub fn snapshot(&self) -> AdaptiveRetrySnapshot {
        let (active_base_ticks, active_ceiling_ticks) = self.active_bounds_ticks();
        AdaptiveRetrySnapshot {
            current_epoch: self.epoch,
            active_selection: self.active_selection,
            active_base_ticks,
            active_ceiling_ticks,
            total_observations: self.total_observations,
            retained_observations: self.retained,
            contended_observations: self.contended_observations,
            e_process_wealth_ppm: self.e_process.wealth_parts_per_million(),
            e_process_alarmed: self.e_process.alarmed(),
            current_evidence: self.current_evidence.clone(),
            epoch_history: self.epoch_history.iter().cloned().collect(),
        }
    }

    fn build_epoch_log(
        &self,
        first_seq: u64,
        last_seq: u64,
        selection: PolicySelection,
        decision: AdvisoryDecision,
    ) -> Result<AdaptiveRetryEpochLog, AdaptiveRetryRefusal> {
        let metric = slug(METRIC_SLUG);
        let candidate_policy = slug(CANDIDATE_POLICY_SLUG);
        let fallback_policy = slug(FALLBACK_POLICY_SLUG);
        let population = slug(POPULATION_SLUG);
        let selection_slug = slug(SELECTION_SLUG);
        let window =
            SequenceWindow::try_new(first_seq, last_seq).map_err(AdaptiveRetryRefusal::Binding)?;
        let regime = RegimeBinding::from_detector(self.epoch.get(), &self.cusum);
        let assumptions = AssumptionSet::try_new(vec![
            slug("bernoulli-eprocess-submartingale"),
            slug("bounded-attempt-excursion"),
            slug("monotone-sequence-window"),
        ])
        .map_err(AdaptiveRetryRefusal::Binding)?;
        let fingerprint = sha256_digest(TOOLCHAIN_FINGERPRINT_PREIMAGE);
        let evidence = StatisticalEvidenceBody {
            population,
            selection: selection_slug,
            window,
            regime,
            policy: selection,
            assumptions,
            fingerprint,
        };
        let encoded = encode_body(&evidence)
            .expect("StatisticalEvidenceBody with bounded slugs encodes within canonical limits");
        let evidence_canonical_sha256 = sha256_digest(&encoded);
        Ok(AdaptiveRetryEpochLog {
            epoch: self.epoch,
            metric,
            candidate_policy,
            fallback_policy,
            e_process_wealth_ppm: self.e_process.wealth_parts_per_million(),
            e_process_alarmed: self.e_process.alarmed(),
            decision,
            evidence,
            evidence_canonical_sha256,
        })
    }
}

/// Thread-safe contention retry controller attached to an [`FsqliteAuthorityStore`].
#[derive(Debug)]
pub struct SharedAdaptiveRetryController {
    sequence: AtomicU64,
    inner: Mutex<AdaptiveRetryController>,
}

impl Default for SharedAdaptiveRetryController {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedAdaptiveRetryController {
    /// Creates a new shared controller with the default production configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sequence: AtomicU64::new(0),
            inner: Mutex::new(AdaptiveRetryController::default_production()),
        }
    }

    /// Returns the active [`BackoffPlan`] for a new whole-transaction operation.
    #[must_use]
    pub fn backoff_plan(&self, seed: u64) -> BackoffPlan {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.active_backoff_plan(seed)
    }

    /// Records the completion of one whole-transaction store operation.
    pub fn record_operation(
        &self,
        contended: bool,
        retry_attempts: u32,
    ) -> Option<AdaptiveRetryStep> {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        guard.observe(seq, contended, retry_attempts).ok()
    }

    /// Captures a point-in-time snapshot of the store's adaptive retry state.
    #[must_use]
    pub fn snapshot(&self) -> AdaptiveRetrySnapshot {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.snapshot()
    }
}

fn slug(literal: &'static str) -> AsciiSlug {
    AsciiSlug::try_new("statistical_slug", literal.as_bytes())
        .expect("static statistical slug literal is canonical lowercase ASCII")
}

fn sha256_digest(bytes: &[u8]) -> Digest {
    let mut hasher = Sha256Hasher::new();
    hasher.update(bytes);
    Digest::from_bytes(hasher.finish())
}

const fn fallback_trigger_slug(trigger: FallbackTrigger) -> &'static str {
    match trigger {
        FallbackTrigger::EvidenceGap => "evidence-gap",
        FallbackTrigger::SupportFailure => "support-failure",
        FallbackTrigger::RegimeAlarm => "regime-alarm",
        FallbackTrigger::NumericBoundViolation => "numeric-bound-violation",
        FallbackTrigger::StaleWindow => "stale-window",
    }
}

/// Explicitly exercises `ForbiddenTarget::ALL` so reviewers and tests can prove
/// the controller refuses every canonical-state-affecting target.
#[must_use]
pub const fn forbidden_targets() -> [ForbiddenTarget; 5] {
    ForbiddenTarget::ALL
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_codec::decode_body;

    #[test]
    fn planted_stream_with_too_little_data_selects_fixed_fallback() {
        // Acceptance 3 (insufficient support): fewer than `min_support_observations`
        // observations must stay on the pinned deterministic fallback (2..=512 ms).
        let mut controller = AdaptiveRetryController::default_production();
        for seq in 1..u64::from(DEFAULT_MIN_SUPPORT_OBSERVATIONS) {
            let step = controller.observe(seq, false, 0).unwrap();
            assert_eq!(
                step.selection,
                PolicySelection::Fallback(FallbackTrigger::SupportFailure),
                "observation {seq} below support floor must select deterministic fallback"
            );
            assert_eq!(step.base_ticks, FALLBACK_BACKOFF_BASE_MS);
            assert_eq!(step.ceiling_ticks, FALLBACK_BACKOFF_CEILING_MS);
        }

        // Permitted twin: reaching `DEFAULT_MIN_SUPPORT_OBSERVATIONS` under a
        // calm stream transitions to `PolicySelection::Candidate` and advances
        // the policy epoch.
        let step = controller
            .observe(u64::from(DEFAULT_MIN_SUPPORT_OBSERVATIONS), false, 0)
            .unwrap();
        assert_eq!(step.selection, PolicySelection::Candidate);
        assert!(step.published_epoch);
        assert_eq!(step.epoch.get(), 2);
        assert_eq!(step.base_ticks, CANDIDATE_BACKOFF_BASE_MS);
        assert_eq!(step.ceiling_ticks, CANDIDATE_BACKOFF_CEILING_MS);
    }

    #[test]
    fn planted_regime_shift_triggers_e_process_alarm_and_selects_fixed_fallback() {
        // Acceptance 3 (regime shift): after warming up into `Candidate`, a
        // burst of contended operations drives the betting e-process past
        // `1 / alpha` and latches `FallbackTrigger::RegimeAlarm`.
        let mut controller = AdaptiveRetryController::default_production();
        for seq in 1..=u64::from(DEFAULT_MIN_SUPPORT_OBSERVATIONS) {
            controller.observe(seq, false, 0).unwrap();
        }
        assert_eq!(
            controller.snapshot().active_selection,
            PolicySelection::Candidate
        );

        let mut seq = u64::from(DEFAULT_MIN_SUPPORT_OBSERVATIONS) + 1;
        let mut alarmed_step = None;
        for _ in 0..32 {
            let step = controller.observe(seq, true, 3).unwrap();
            seq += 1;
            if step.selection == PolicySelection::Fallback(FallbackTrigger::RegimeAlarm) {
                alarmed_step = Some(step);
                break;
            }
        }
        let step = alarmed_step.expect("sustained contention burst must trigger e-process/CUSUM regime alarm");
        assert!(step.published_epoch);
        assert_eq!(step.epoch.get(), 3);
        assert_eq!(step.base_ticks, FALLBACK_BACKOFF_BASE_MS);
        assert_eq!(step.ceiling_ticks, FALLBACK_BACKOFF_CEILING_MS);
    }

    #[test]
    fn epoch_logs_carry_complete_seven_binding_evidence_identity_and_roundtrip_wire_codec() {
        // Acceptance 4: every decision epoch records metric, population,
        // selection, sequence window, regime binding, candidate/fallback policy,
        // assumptions, and toolchain fingerprint.
        let mut controller = AdaptiveRetryController::default_production();
        for seq in 1..=u64::from(DEFAULT_MIN_SUPPORT_OBSERVATIONS) {
            controller.observe(seq, false, 0).unwrap();
        }
        let snapshot = controller.snapshot();
        assert_eq!(snapshot.epoch_history.len(), 2);
        for record in &snapshot.epoch_history {
            assert_eq!(record.metric.as_str(), METRIC_SLUG);
            assert_eq!(record.candidate_policy.as_str(), CANDIDATE_POLICY_SLUG);
            assert_eq!(record.fallback_policy.as_str(), FALLBACK_POLICY_SLUG);
            assert_eq!(record.evidence.population.as_str(), POPULATION_SLUG);
            assert_eq!(record.evidence.selection.as_str(), SELECTION_SLUG);
            assert_eq!(record.evidence.assumptions.len(), 3);
            let encoded = encode_body(&record.evidence).unwrap();
            let decoded: StatisticalEvidenceBody = decode_body(&encoded).unwrap();
            assert_eq!(decoded, record.evidence);
            let json = record.to_json_line();
            assert!(json.contains("\"type\":\"statistical_policy_epoch\""));
            assert!(json.contains("\"metric\":\"authority-cas-contention-backoff-ms\""));
            assert!(json.contains("\"candidate_policy_id\":\"eprocess-adaptive-cas-backoff-v1\""));
            assert!(json.contains(
                "\"fallback_policy_id\":\"pinned-exponential-jitter-2ms-512ms-v1\""
            ));
        }
    }

    #[test]
    fn forbidden_canonical_state_targets_are_refused_while_retry_backoff_is_admitted() {
        let controller = AdaptiveRetryController::default_production();
        for target in forbidden_targets() {
            let err = controller
                .authorize_target(ProposedTarget::Forbidden(target))
                .unwrap_err();
            assert_eq!(
                err,
                AdaptiveRetryRefusal::Decision(DecisionRefusal::TargetForbidden { target })
            );
        }
        let ok = controller
            .authorize_target(ProposedTarget::RetryBackoff)
            .unwrap();
        assert_eq!(
            ok,
            AdvisoryDecision::RetryBackoff {
                micros: FALLBACK_BACKOFF_BASE_MS * 1_000
            }
        );
    }

    #[test]
    fn baseline_versus_adaptive_versus_aa_contention_campaign_preserves_outcomes_and_bounds_tails()
    {
        // Acceptance 1 & 2: compare baseline (fixed 2..=512 ms) vs adaptive
        // (1..=256 ms under calm/moderate contention, 2..=512 ms on regime shift)
        // vs A-A control across a deterministic 64-operation workload with
        // injected transient contention bursts, verifying identical terminal
        // outcomes and recording raw latency/attempt distributions.
        use crate::retry::{RetryBudget, RetryOutcome, TransientClass, retry_whole_transaction};

        // Schedule of transient failures before completion for 64 operations:
        // - ops 0..16: calm warmup (0 or 1 transient Busy before success)
        // - ops 16..48: moderate contention (1..=3 Busy/WriteConflict before success)
        // - ops 48..64: heavy contention + 1 permanent refusal + 1 indeterminate
        let failure_counts: [u32; 64] = [
            0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, // 0..16
            2, 0, 1, 0, 0, 2, 0, 0, 1, 0, 0, 3, 0, 0, 1, 0, // 16..32
            0, 2, 0, 0, 1, 0, 0, 2, 0, 0, 1, 0, 0, 2, 0, 1, // 32..48
            0, 3, 0, 2, 0, 1, 0, 2, 0, 1, 0, 2, 0, 1, 999, 888, // 48..64 (62=Permanent, 63=Indeterminate)
        ];

        let run_campaign = |adaptive: bool| {
            let mut controller = AdaptiveRetryController::default_production();
            let mut outcomes = Vec::with_capacity(failure_counts.len());
            let mut loser_delays_ms = Vec::new();
            let mut total_attempts = 0_u32;

            for (idx, &failures_before_ok) in failure_counts.iter().enumerate() {
                let seed = 0xCAFE_0000_u64 ^ (idx as u64);
                let backoff = if adaptive {
                    controller.active_backoff_plan(seed)
                } else {
                    BackoffPlan::new(FALLBACK_BACKOFF_BASE_MS, FALLBACK_BACKOFF_CEILING_MS, seed)
                };
                let budget = RetryBudget::new(15_000, 128);
                let mut tries = 0_u32;
                let mut op_delay_ms = 0_u64;
                let outcome = retry_whole_transaction(
                    budget,
                    backoff,
                    |attempt| {
                        tries = attempt;
                        if failures_before_ok == 999 {
                            Err(TransientClass::Permanent)
                        } else if failures_before_ok == 888 {
                            Err(TransientClass::OutcomeIndeterminate)
                        } else if attempt <= failures_before_ok {
                            Err(TransientClass::WriteConflict)
                        } else {
                            Ok(idx)
                        }
                    },
                    |ticks| {
                        op_delay_ms += ticks;
                    },
                );
                total_attempts += tries;
                if failures_before_ok > 0 && failures_before_ok < 800 {
                    loser_delays_ms.push(op_delay_ms);
                }
                let retries_used = tries.saturating_sub(1);
                let contended = retries_used > 0;
                controller
                    .observe((idx as u64) + 1, contended, retries_used)
                    .unwrap();
                outcomes.push(outcome);
            }
            loser_delays_ms.sort_unstable();
            (outcomes, loser_delays_ms, total_attempts, controller.snapshot())
        };

        let (baseline_outcomes, baseline_delays, baseline_attempts, _) = run_campaign(false);
        let (aa_outcomes, aa_delays, aa_attempts, _) = run_campaign(false);
        let (adaptive_outcomes, adaptive_delays, adaptive_attempts, adaptive_snap) =
            run_campaign(true);

        // 1. Exact A-A determinism and outcome equivalence across all 64 operations.
        assert_eq!(baseline_outcomes, aa_outcomes);
        assert_eq!(baseline_delays, aa_delays);
        assert_eq!(baseline_attempts, aa_attempts);
        assert_eq!(
             adaptive_outcomes, baseline_outcomes,
            "adaptive retry must produce identical terminal RetryOutcome classes to fixed policy"
        );
        assert_eq!(
            adaptive_outcomes[62],
            RetryOutcome::Permanent { attempts: 1 }
        );
        assert_eq!(
            adaptive_outcomes[63],
            RetryOutcome::OutcomeIndeterminate { attempts: 1 }
        );

        // 2. Measured tail latencies (p50, p95, max) and total attempts:
        // Under the calm/moderate regime where `Candidate` (1..=256 ms) is active,
        // adaptive backoff reduces loser wait time without changing attempt count.
        let p50_idx = baseline_delays.len() / 2;
        let p95_idx = (baseline_delays.len() * 95) / 100;
        let baseline_sum: u64 = baseline_delays.iter().sum();
        let adaptive_sum: u64 = adaptive_delays.iter().sum();
        assert_eq!(adaptive_attempts, baseline_attempts);
        assert!(
            adaptive_sum < baseline_sum,
            "adaptive total loser wait ({adaptive_sum} ms) must be strictly lower than fixed baseline ({baseline_sum} ms)"
        );
        assert!(adaptive_delays[p50_idx] <= baseline_delays[p50_idx]);
        assert!(adaptive_delays[p95_idx] <= baseline_delays[p95_idx]);
        assert!(adaptive_snap.current_evidence.is_some());
    }
}
