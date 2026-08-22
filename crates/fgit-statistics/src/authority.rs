//! Section 33.4's forbidden decisions, enforced by what the API cannot say.
//!
//! `AGENTS.md` section 8 draws the line: *"Models/graphs may recommend or
//! prioritize; they may not grant access, move refs, delete data, or impose
//! irreversible sanctions."* Section 33.4 names the same boundary as five
//! forbidden targets — identity, authorization, retention, deletion, ordering.
//!
//! # Why this is a type and not a check
//!
//! A runtime check answers "was this decision allowed?" *after* a caller has
//! built it, which means the dangerous decision is representable and the
//! enforcement is one forgotten call site away from absent. Worse, the check is
//! the kind of thing that gets relaxed under deadline pressure, because it reads
//! as a policy rather than as a load-bearing invariant.
//!
//! So the primary enforcement here is [`AdvisoryDecision`] having **no variant**
//! for any of the five. A controller cannot decide a deletion because there is
//! nothing to construct — not because something refuses it. That is the "compile
//! error" half of this bead's acceptance line, and it is the half that cannot
//! rot.
//!
//! # Why there is a refusal path anyway
//!
//! Structural absence only protects callers who go through [`AdvisoryDecision`].
//! A caller holding a target chosen at runtime — read from configuration, or
//! from a plan another component produced — needs somewhere to bring it, and
//! that somewhere must say no in a way the caller can handle. [`resolve`] is
//! that path, and it returns a typed refusal rather than an `Option`, so the
//! reason survives into the caller's own evidence.
//!
//! The two halves are deliberately not the same mechanism. If [`resolve`] were
//! the only enforcement, deleting it would silently permit everything; if the
//! closed enum were the only enforcement, runtime-chosen targets would have
//! nowhere to be refused.

/// A decision a statistical mechanism is permitted to make.
///
/// **Closed by design.** Every variant is answer-preserving or affects only
/// execution; none can change canonical state, authorization, or what the
/// repository says. Adding a variant is a constitutional question, not a
/// convenience: the absence of `GrantAccess`, `MoveRef`, `DeleteObject` and
/// `ReorderCommits` is this module's primary enforcement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AdvisoryDecision {
    /// How long to wait before retrying, in microseconds.
    RetryBackoff {
        /// The delay.
        micros: u64,
    },
    /// How many items to admit into one batch.
    BatchSize {
        /// The batch size.
        items: u32,
    },
    /// How often to sample a probe, in parts per million of opportunities.
    ProbeRate {
        /// The rate.
        parts_per_million: u32,
    },
    /// Which of several *equivalent* execution plans to prefer.
    ///
    /// Equivalent is the operative word: preferring a plan may change how long
    /// the work takes and must not change what it answers.
    PlanPreference {
        /// The plan's stable identifier.
        plan: u16,
    },
}

/// How an effect relates to the answer the system gives.
///
/// Section 33 names three classes and forbids the third for adaptive control.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EffectClass {
    /// Changes physical work only; the answer is identical either way.
    AnswerPreservingPhysical,
    /// Changes how execution proceeds — timing, batching, sampling — where the
    /// answer is unchanged but the path to it is not.
    AnswerAffectingExecution,
    /// Changes canonical state.
    ///
    /// Representable so that an effect can be *classified* as forbidden and
    /// refused by name. No [`AdvisoryDecision`] maps to it, and the
    /// `no_advisory_decision_affects_canonical_state` test walks every variant
    /// to pin that.
    CanonicalStateAffecting,
}

impl AdvisoryDecision {
    /// One decision of each shape, for exhaustive tests.
    ///
    /// A test that walks this array fails to compile the moment a variant is
    /// added without being considered, which is the point.
    pub const ALL: [Self; 4] = [
        Self::RetryBackoff { micros: 1_000 },
        Self::BatchSize { items: 32 },
        Self::ProbeRate {
            parts_per_million: 10_000,
        },
        Self::PlanPreference { plan: 1 },
    ];

    /// The effect class of this decision.
    ///
    /// Total, and never [`EffectClass::CanonicalStateAffecting`] — there is no
    /// variant that could produce it.
    #[must_use]
    pub const fn effect_class(self) -> EffectClass {
        match self {
            // Preferring an equivalent plan changes work, not the answer.
            Self::PlanPreference { .. } => EffectClass::AnswerPreservingPhysical,
            // These three change timing, grouping, or sampling density.
            Self::RetryBackoff { .. } | Self::BatchSize { .. } | Self::ProbeRate { .. } => {
                EffectClass::AnswerAffectingExecution
            }
        }
    }
}

/// A decision a statistical mechanism must never make.
///
/// These exist as a vocabulary for *refusing*, not for doing. Nothing in this
/// crate consumes a [`ForbiddenTarget`] except to reject it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ForbiddenTarget {
    /// What something *is* — an identity, digest, or name binding.
    Identity,
    /// Who may do something.
    Authorization,
    /// How long data is kept.
    Retention,
    /// Whether data is destroyed.
    Deletion,
    /// The order in which effects become visible.
    Ordering,
}

impl ForbiddenTarget {
    /// Every forbidden target, in a fixed order.
    pub const ALL: [Self; 5] = [
        Self::Identity,
        Self::Authorization,
        Self::Retention,
        Self::Deletion,
        Self::Ordering,
    ];

    /// Why this target is forbidden, for the refusal's own evidence.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Identity => {
                "a statistical estimate cannot decide what something is; identity is derived from \
                 canonical bytes, not inferred"
            }
            Self::Authorization => {
                "a score cannot grant access; authorization filters precede disclosure and are not \
                 subject to adaptation"
            }
            Self::Retention => {
                "retention is decided by the authenticated registry and current basis, never by a \
                 model's confidence"
            }
            Self::Deletion => {
                "deletion is irreversible, so a mechanism that is right on average is the wrong \
                 kind of authority for it"
            }
            Self::Ordering => {
                "observable order is a closed tie-break policy; adapting it would make two runs \
                 disagree about what happened"
            }
        }
    }
}

/// What a caller may ask a controller to decide, including the things it may not.
///
/// A runtime-chosen target arrives here rather than at [`AdvisoryDecision`],
/// because a value read from configuration cannot be constrained by an enum's
/// shape. Every forbidden variant is present precisely so [`resolve`] can name
/// it in the refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProposedTarget {
    /// Permitted: retry timing.
    RetryBackoff,
    /// Permitted: batch sizing.
    BatchSize,
    /// Permitted: probe sampling rate.
    ProbeRate,
    /// Permitted: preference among equivalent plans.
    PlanPreference,
    /// Forbidden, per section 33.4.
    Forbidden(ForbiddenTarget),
}

impl ProposedTarget {
    /// Every permitted target.
    pub const PERMITTED: [Self; 4] = [
        Self::RetryBackoff,
        Self::BatchSize,
        Self::ProbeRate,
        Self::PlanPreference,
    ];
}

/// Why a proposed target was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DecisionRefusal {
    /// The target is one of section 33.4's five.
    ForbiddenTarget {
        /// Which one.
        target: ForbiddenTarget,
    },
}

impl DecisionRefusal {
    /// The refusal's explanation, for the caller's evidence record.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::ForbiddenTarget { target } => target.reason(),
        }
    }
}

/// The shape of decision a permitted target admits.
///
/// Deliberately *not* a constructed [`AdvisoryDecision`]: resolving a target
/// says a controller may decide this kind of thing, not what it decided. The
/// value still has to come from a mechanism.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AdmissibleShape {
    /// A [`AdvisoryDecision::RetryBackoff`] may be produced.
    RetryBackoff,
    /// A [`AdvisoryDecision::BatchSize`] may be produced.
    BatchSize,
    /// A [`AdvisoryDecision::ProbeRate`] may be produced.
    ProbeRate,
    /// A [`AdvisoryDecision::PlanPreference`] may be produced.
    PlanPreference,
}

/// Resolves a runtime-chosen target, refusing section 33.4's five by name.
///
/// # Errors
///
/// Returns [`DecisionRefusal::ForbiddenTarget`] for any forbidden target,
/// carrying which one so the caller's evidence records the reason rather than
/// only the outcome.
pub const fn resolve(target: ProposedTarget) -> Result<AdmissibleShape, DecisionRefusal> {
    match target {
        ProposedTarget::RetryBackoff => Ok(AdmissibleShape::RetryBackoff),
        ProposedTarget::BatchSize => Ok(AdmissibleShape::BatchSize),
        ProposedTarget::ProbeRate => Ok(AdmissibleShape::ProbeRate),
        ProposedTarget::PlanPreference => Ok(AdmissibleShape::PlanPreference),
        ProposedTarget::Forbidden(target) => Err(DecisionRefusal::ForbiddenTarget { target }),
    }
}
