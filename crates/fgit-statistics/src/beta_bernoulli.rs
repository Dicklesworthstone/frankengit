//! Beta-Bernoulli posteriors and a minimum-evidence arm comparison.
//!
//! # What this module provides, and what it deliberately does not
//!
//! Section 33 names "Beta-Bernoulli expected loss" in its mechanism library.
//! **The expected-loss integral is not implemented here, and this module does
//! not claim it.**
//!
//! An earlier version of this comment said it *could not* be, "because the
//! difference of two Beta variables has no exact form in integer arithmetic".
//! That was wrong, and the correction matters more than the original claim:
//! for **integer** parameters — which is all this module ever has, since a
//! proper prior plus observed counts is always integral — `P(theta_b > theta_a)`
//! has an exact closed form, a finite sum of `a_b` rational terms whose
//! successive ratio is
//!
//! ```text
//! T(i+1)/T(i) = (a_a+i)/(a_a+i+b_a+b_b) * (1+i+b_b)/(1+i) * (b_b+i)/(b_b+i+1)
//! ```
//!
//! so no factorial is ever formed. Verified against numerical integration and
//! against exact rational evaluation of the closed form.
//!
//! The real obstacle is narrower and is an engineering choice rather than a
//! mathematical one: exact evaluation needs arbitrary-precision rationals,
//! whose denominators grow across the sum, and the closed dependency universe
//! admits no bignum crate. Doing it in bounded fixed-point instead means
//! rounding that compounds over up to `a_b` terms, which owes a proven error
//! bound — and an unproven bound on a number that ranks two policies is exactly
//! the kind of claim section 10 refuses.
//!
//! So it remains unimplemented, for a reason that is now stated accurately.
//!
//! What is provided is exact and useful on its own:
//!
//! * the conjugate posterior, which is a pair of integer counts;
//! * its mean in parts per million, one division from its own two inputs; and
//! * a comparison between two arms behind a **minimum-evidence gate** and a
//!   declared **indifference margin**.
//!
//! # Why the evidence gate is the important part
//!
//! A posterior mean is defined after zero observations — it is just the prior's
//! mean — and it keeps being defined after one. Comparing two arms on their
//! means alone therefore always produces an answer, and after two trials that
//! answer is the prior with noise on it. The mechanism has no way to signal
//! this: the number looks exactly like the number it returns after ten thousand
//! trials.
//!
//! So [`ArmComparison`] refuses below a declared trial count rather than
//! returning a verdict nobody should act on. That refusal is the honest content
//! of a Bayesian comparison done in integers, and it is the part that a
//! floating-point implementation would still need.
//!
//! # The indifference margin
//!
//! Two arms whose posterior means differ by less than the margin are reported
//! [`ArmVerdict::Indistinguishable`] rather than ranked. Without it, a
//! difference of one part per million would order the arms, and a controller
//! would switch policies on noise — which is churn, not adaptation.

use fgit_types::Probability;

/// Parts per million.
const PARTS_PER_MILLION: u64 = 1_000_000;

/// A Beta prior, as two positive pseudo-counts.
///
/// The fields are private because propriety is a property this type enforces
/// rather than one the caller promises: an improper prior cannot be
/// constructed, so no downstream code needs to re-check it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BetaPrior {
    alpha: u32,
    beta: u32,
}

/// Observed Bernoulli outcomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Outcomes {
    /// How many trials succeeded.
    pub successes: u32,
    /// How many trials were run.
    pub trials: u32,
}

/// Why a prior cannot be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BetaAssumptionFailure {
    /// `alpha = 0` is an improper prior: with zero successes observed the
    /// posterior mean is exactly zero and no evidence can ever move it up from
    /// a single failure, which is not a belief anyone holds.
    AlphaZero,
    /// `beta = 0`, the mirror case.
    BetaZero,
}

/// Why a posterior or comparison was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BetaRefusal {
    /// More successes than trials were reported.
    ///
    /// Refused rather than clamped: the caller's counting is wrong, and a
    /// clamped posterior would carry that error forward silently.
    MoreSuccessesThanTrials {
        /// Successes reported.
        successes: u32,
        /// Trials reported.
        trials: u32,
    },
    /// An arm has fewer trials than the comparison requires.
    InsufficientEvidence {
        /// Trials observed on the thinner arm.
        observed: u32,
        /// Trials the comparison requires.
        required: u32,
    },
}

/// A conjugate posterior: the prior plus the observed counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Posterior {
    alpha: u64,
    beta: u64,
    trials: u32,
}

impl Posterior {
    /// The posterior mean, in parts per million.
    ///
    /// One truncating division from this posterior's own two counts. Nothing
    /// downstream feeds back into it, so the truncation quantises rather than
    /// compounds.
    /// The posterior mean as a typed probability.
    ///
    /// Uses the saturating constructor deliberately. `Probability`'s contract
    /// reserves the checked `try_new` for untrusted or policy-relevant input
    /// and permits the saturating path for a bounded calculation; this mean is
    /// `alpha / (alpha + beta)` with `alpha < alpha + beta`, so it cannot leave
    /// `0..=1_000_000` and there is no out-of-range case for a refusal to
    /// report.
    #[must_use]
    pub fn mean(self) -> Probability {
        Probability::saturating_from_parts_per_million(self.mean_parts_per_million())
    }

    #[must_use]
    pub fn mean_parts_per_million(self) -> u32 {
        let total = self.alpha + self.beta;
        // `alpha >= 1` and `beta >= 1` are enforced at construction, so `total`
        // is at least two and the division is safe. The quotient is at most
        // `PARTS_PER_MILLION` because `alpha < total`, so the conversion cannot
        // fail; `try_from` rather than `as` so that a future change to the
        // invariant is a visible saturation rather than a silent wrap.
        u32::try_from(self.alpha * PARTS_PER_MILLION / total)
            .unwrap_or(u32::MAX)
            .min(1_000_000)
    }

    /// The posterior's success pseudo-count.
    #[must_use]
    pub const fn alpha(self) -> u64 {
        self.alpha
    }

    /// The posterior's failure pseudo-count.
    #[must_use]
    pub const fn beta(self) -> u64 {
        self.beta
    }

    /// How many real trials contributed, excluding the prior's pseudo-counts.
    ///
    /// Separate from [`Self::alpha`] and [`Self::beta`] on purpose: the
    /// evidence gate must count *observations*, and a strong prior would
    /// otherwise let an arm with no data claim a large sample.
    #[must_use]
    pub const fn trials(self) -> u32 {
        self.trials
    }
}

impl BetaPrior {
    /// Builds a proper prior.
    ///
    /// # Errors
    ///
    /// Returns the failed assumption. Both counts must be positive.
    pub const fn try_new(alpha: u32, beta: u32) -> Result<Self, BetaAssumptionFailure> {
        if alpha == 0 {
            return Err(BetaAssumptionFailure::AlphaZero);
        }
        if beta == 0 {
            return Err(BetaAssumptionFailure::BetaZero);
        }
        Ok(Self { alpha, beta })
    }

    /// The uniform prior, `Beta(1, 1)`.
    #[must_use]
    pub const fn uniform() -> Self {
        Self { alpha: 1, beta: 1 }
    }

    /// The success pseudo-count.
    #[must_use]
    pub const fn alpha(self) -> u32 {
        self.alpha
    }

    /// The failure pseudo-count.
    #[must_use]
    pub const fn beta(self) -> u32 {
        self.beta
    }

    /// Updates the prior with observed outcomes.
    ///
    /// # Errors
    ///
    /// Returns [`BetaRefusal::MoreSuccessesThanTrials`] when the counts are
    /// impossible. The prior itself needs no check here, because
    /// [`Self::try_new`] is the only way to build one.
    pub const fn update(self, outcomes: Outcomes) -> Result<Posterior, BetaRefusal> {
        if outcomes.successes > outcomes.trials {
            return Err(BetaRefusal::MoreSuccessesThanTrials {
                successes: outcomes.successes,
                trials: outcomes.trials,
            });
        }
        let failures = outcomes.trials - outcomes.successes;
        Ok(Posterior {
            alpha: self.alpha as u64 + outcomes.successes as u64,
            beta: self.beta as u64 + failures as u64,
            trials: outcomes.trials,
        })
    }
}

/// How two arms compared.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ArmVerdict {
    /// The candidate's posterior mean exceeds the fallback's by at least the
    /// indifference margin.
    CandidatePreferred {
        /// How far ahead, in parts per million.
        margin: u32,
    },
    /// The fallback's posterior mean exceeds the candidate's by at least the
    /// margin.
    FallbackPreferred {
        /// How far ahead, in parts per million.
        margin: u32,
    },
    /// The means differ by less than the margin.
    ///
    /// Reported rather than ranked, because ordering arms on a difference
    /// smaller than the declared indifference is churn rather than adaptation.
    Indistinguishable {
        /// The observed absolute difference.
        difference: u32,
    },
}

impl ArmVerdict {
    /// Whether this verdict admits the adaptive candidate.
    ///
    /// [`Self::Indistinguishable`] does **not**: with no demonstrated advantage,
    /// the pinned deterministic policy is the one to keep. Switching on a tie
    /// would mean adaptation with nothing behind it.
    #[must_use]
    pub const fn admits_candidate(self) -> bool {
        matches!(self, Self::CandidatePreferred { .. })
    }
}

/// A two-arm comparison behind an evidence gate and an indifference margin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ArmComparison {
    /// Trials each arm must have before a verdict is given.
    pub min_trials_per_arm: u32,
    /// The difference below which the arms are treated as equal, in parts per
    /// million.
    pub indifference_margin: u32,
}

impl ArmComparison {
    /// Compares two posteriors.
    ///
    /// # Errors
    ///
    /// Returns [`BetaRefusal::InsufficientEvidence`] when either arm has fewer
    /// than [`Self::min_trials_per_arm`] observations. The thinner arm is named,
    /// since that is the one needing more data.
    pub fn compare(
        self,
        candidate: Posterior,
        fallback: Posterior,
    ) -> Result<ArmVerdict, BetaRefusal> {
        let thinner = if candidate.trials() < fallback.trials() {
            candidate.trials()
        } else {
            fallback.trials()
        };
        if thinner < self.min_trials_per_arm {
            return Err(BetaRefusal::InsufficientEvidence {
                observed: thinner,
                required: self.min_trials_per_arm,
            });
        }

        let candidate_mean = candidate.mean_parts_per_million();
        let fallback_mean = fallback.mean_parts_per_million();
        if candidate_mean >= fallback_mean {
            let margin = candidate_mean - fallback_mean;
            if margin >= self.indifference_margin {
                return Ok(ArmVerdict::CandidatePreferred { margin });
            }
            return Ok(ArmVerdict::Indistinguishable { difference: margin });
        }
        let margin = fallback_mean - candidate_mean;
        if margin >= self.indifference_margin {
            return Ok(ArmVerdict::FallbackPreferred { margin });
        }
        Ok(ArmVerdict::Indistinguishable { difference: margin })
    }
}

/// A posterior updated one observation at a time.
///
/// [`BetaPrior::update`] is batch-shaped: it takes a whole [`Outcomes`] and
/// yields a [`Posterior`]. A retry controller does not have a batch — it learns
/// one commit or conflict at a time and must be able to discard its history
/// when the regime moves. This is that shape, and it exists so a caller does
/// not keep its own counts beside a `Posterior` and drift from it.
///
/// # Why the prior is kept apart from the observations
///
/// The counts here are **real observations only**. The prior contributes belief
/// and is added when a [`Posterior`] is produced, never mixed into the tally.
/// That separation is what lets [`Self::trials`] answer "how much evidence is
/// there", which is the question [`ArmComparison`]'s minimum-evidence gate asks
/// — a representation that folded the prior into the counts could not answer it,
/// and would report a confident mean after zero observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IncrementalPosterior {
    prior: BetaPrior,
    successes: u32,
    failures: u32,
}

impl IncrementalPosterior {
    /// Starts from a proper prior with no observations.
    #[must_use]
    pub const fn new(prior: BetaPrior) -> Self {
        Self {
            prior,
            successes: 0,
            failures: 0,
        }
    }

    /// Records one observed outcome.
    ///
    /// Saturating, so a long-lived caller cannot wrap its own history into a
    /// smaller count and silently look less experienced than it is.
    pub const fn observe(&mut self, success: bool) {
        if success {
            self.successes = self.successes.saturating_add(1);
        } else {
            self.failures = self.failures.saturating_add(1);
        }
    }

    /// Discards accumulated observations, keeping the prior.
    ///
    /// A regime change invalidates the observations without invalidating the
    /// belief the caller started from, so the prior survives and the evidence
    /// does not. [`Self::trials`] returns to zero, which is the point: after a
    /// regime change the evidence gate should refuse again until real
    /// observations accumulate under the new regime.
    pub const fn reset_for_regime(&mut self) {
        self.successes = 0;
        self.failures = 0;
    }

    /// Real observations recorded, excluding the prior's pseudo-counts.
    #[must_use]
    pub const fn trials(self) -> u32 {
        self.successes.saturating_add(self.failures)
    }

    /// The observed counts, for a receipt.
    #[must_use]
    pub const fn counts(self) -> (u32, u32) {
        (self.successes, self.failures)
    }

    /// The posterior implied by the prior and the observations so far.
    ///
    /// # Errors
    ///
    /// Returns [`BetaRefusal::MoreSuccessesThanTrials`] only if the internal
    /// counts were somehow inconsistent, which [`Self::observe`] cannot produce.
    pub const fn posterior(self) -> Result<Posterior, BetaRefusal> {
        self.prior.update(Outcomes {
            successes: self.successes,
            trials: self.trials(),
        })
    }

    /// The posterior mean as a typed probability.
    ///
    /// # Errors
    ///
    /// Propagates [`Self::posterior`].
    pub fn success_probability(self) -> Result<Probability, BetaRefusal> {
        Ok(self.posterior()?.mean())
    }
}
