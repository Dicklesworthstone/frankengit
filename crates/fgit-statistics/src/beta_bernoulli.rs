//! Beta-Bernoulli posteriors and a minimum-evidence arm comparison.
//!
//! # What this module provides, and what it deliberately does not
//!
//! Section 33 names "Beta-Bernoulli expected loss" in its mechanism library.
//! **The expected-loss integral is not implemented here, and this module does
//! not claim it.** Expected loss under either the 0-1 or the linear loss needs
//! the distribution of the *difference* of two Beta variables, which has no
//! exact form in integer arithmetic; approximating it would mean either a float
//! path, which the workspace forbids, or a quadrature whose error bound is
//! itself a claim needing evidence.
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
    #[must_use]
    pub const fn mean_parts_per_million(self) -> u32 {
        let total = self.alpha + self.beta;
        // `alpha >= 1` and `beta >= 1` are enforced at construction, so `total`
        // is at least two and the division is safe.
        (self.alpha * PARTS_PER_MILLION / total) as u32
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
    pub const fn compare(
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
