//! Deterministic fault scripting for reference authority backends.
//!
//! A fault plan is a list of directives indexed by operation position.  Given
//! the same plan and the same sequence of operations, a backend injects exactly
//! the same faults in exactly the same order, so a campaign failure is a
//! replayable artifact rather than an anecdote.  Every injected fault is
//! recorded with its position, its kind, and whether control had already
//! reached the effect.
//!
//! # Ground truth versus caller knowledge
//!
//! [`FaultKind::LoseRequest`] and [`FaultKind::LoseResponse`] produce the same
//! caller-visible response.  That is the whole point: a caller cannot learn
//! non-commit from a lost response.  The difference survives only in the
//! [`FaultLog`], which is out-of-band evidence for the campaign, never a value
//! the caller under test can read.

use crate::vocabulary::AuthorityOpKind;

/// Position of one operation in a store's lifetime.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OpIndex(u64);

impl OpIndex {
    /// The first operation a store executes.
    pub const ZERO: Self = Self(0);

    /// Name a position.
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// The raw position.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Where in an operation a positional fault fires.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FaultPosition {
    /// Before the store applies any effect.
    BeforeEffect,
    /// After the store has applied its effect but before the caller is answered.
    AfterEffect,
}

/// Which copy of a duplicated request the caller is answered with.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DuplicateDelivery {
    /// The caller sees the first application's outcome.
    First,
    /// The caller sees the second application's outcome.
    ///
    /// This is the hostile shape: after a duplicated conditional replacement the
    /// caller can observe a predecessor mismatch even though its own effect
    /// linearized.
    Second,
}

/// One injectable fault.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FaultKind {
    /// The request never reaches the effect; the caller sees ambiguity.
    LoseRequest,
    /// The effect is applied and the response is lost; the caller sees the same ambiguity.
    LoseResponse,
    /// The effect is applied twice before the caller is answered.
    DuplicateRequest {
        /// Which application's outcome the caller observes.
        deliver: DuplicateDelivery,
    },
    /// Logical time is consumed at the given position.
    Delay {
        /// Where the delay is taken.
        position: FaultPosition,
        /// How many logical ticks the delay costs.
        ticks: u64,
    },
    /// The endpoint dies at the given position and refuses later requests.
    Crash {
        /// Where the endpoint dies.
        position: FaultPosition,
    },
    /// The request is shed before any effect and may be retried.
    Throttle,
}

impl FaultKind {
    /// Whether this fault can fire before the effect is applied.
    #[must_use]
    pub const fn fires_before_effect(self) -> bool {
        match self {
            Self::LoseRequest | Self::Throttle => true,
            Self::Delay { position, .. } | Self::Crash { position } => {
                matches!(position, FaultPosition::BeforeEffect)
            }
            Self::LoseResponse | Self::DuplicateRequest { .. } => false,
        }
    }
}

/// One scripted fault at one operation position.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FaultDirective {
    /// The operation position at which the directive fires.
    pub at: OpIndex,
    /// The fault to inject.
    pub kind: FaultKind,
    /// Restrict the directive to one operation kind, or `None` for any kind.
    pub applies_to: Option<AuthorityOpKind>,
}

impl FaultDirective {
    /// A directive that fires at `at` regardless of operation kind.
    #[must_use]
    pub const fn new(at: OpIndex, kind: FaultKind) -> Self {
        Self {
            at,
            kind,
            applies_to: None,
        }
    }

    /// Restrict this directive to one operation kind.
    #[must_use]
    pub const fn only_for(mut self, kind: AuthorityOpKind) -> Self {
        self.applies_to = Some(kind);
        self
    }

    /// Whether this directive fires for the given position and operation kind.
    #[must_use]
    pub fn matches(&self, at: OpIndex, kind: AuthorityOpKind) -> bool {
        self.at == at && self.applies_to.is_none_or(|only| only == kind)
    }
}

/// A deterministic, replayable fault script.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FaultPlan {
    seed: Option<u64>,
    directives: Vec<FaultDirective>,
}

impl FaultPlan {
    /// A plan that injects nothing.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            seed: None,
            directives: Vec::new(),
        }
    }

    /// A plan written out by hand.
    ///
    /// Directives are stored in ascending position order so the plan reads the
    /// same way it executes.
    #[must_use]
    pub fn explicit(mut directives: Vec<FaultDirective>) -> Self {
        directives.sort_by_key(|directive| directive.at);
        Self {
            seed: None,
            directives,
        }
    }

    /// A plan materialised from a seed.
    ///
    /// `span` is the number of operation positions the plan may target and
    /// `count` is how many directives to place.  The same `(seed, span, count)`
    /// always produces the identical directive list, which is what makes a
    /// campaign failure replayable from three integers.
    ///
    /// [`FaultKind::Crash`] is never generated: a crash terminates the endpoint
    /// and would make most of a random plan unreachable, so crash points are
    /// always placed deliberately.
    #[must_use]
    pub fn seeded(seed: u64, span: u64, count: usize) -> Self {
        let mut rng = SplitMix64::new(seed);
        let mut directives = Vec::with_capacity(count);
        for _ in 0..count {
            let at = OpIndex::from_raw(if span == 0 { 0 } else { rng.next_u64() % span });
            let kind = match rng.next_u64() % 6 {
                0 => FaultKind::LoseRequest,
                1 => FaultKind::LoseResponse,
                2 => FaultKind::DuplicateRequest {
                    deliver: DuplicateDelivery::First,
                },
                3 => FaultKind::DuplicateRequest {
                    deliver: DuplicateDelivery::Second,
                },
                4 => FaultKind::Delay {
                    position: FaultPosition::BeforeEffect,
                    ticks: 1 + rng.next_u64() % 8,
                },
                _ => FaultKind::Delay {
                    position: FaultPosition::AfterEffect,
                    ticks: 1 + rng.next_u64() % 8,
                },
            };
            directives.push(FaultDirective::new(at, kind));
        }
        directives.sort_by_key(|directive| directive.at);
        Self {
            seed: Some(seed),
            directives,
        }
    }

    /// The seed this plan was materialised from, when it was generated.
    #[must_use]
    pub const fn seed(&self) -> Option<u64> {
        self.seed
    }

    /// Every directive in the plan, in ascending position order.
    #[must_use]
    pub fn directives(&self) -> &[FaultDirective] {
        &self.directives
    }

    /// Whether the plan injects nothing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.directives.is_empty()
    }

    /// Directives that fire at one position for one operation kind.
    #[must_use]
    pub fn matching(&self, at: OpIndex, kind: AuthorityOpKind) -> Vec<FaultDirective> {
        self.directives
            .iter()
            .filter(|directive| directive.matches(at, kind))
            .copied()
            .collect()
    }
}

/// One injected fault, with enough context to replay and to audit.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FaultRecord {
    /// Ordinal of this injection within the store's lifetime.
    pub sequence: u64,
    /// The operation position the fault fired at.
    pub at: OpIndex,
    /// The operation the fault fired against.
    pub op_kind: AuthorityOpKind,
    /// What was injected.
    pub kind: FaultKind,
    /// Whether control had already reached the effect when the fault fired.
    ///
    /// This is the ground truth an ambiguous caller cannot observe.
    pub effect_reached: bool,
    /// Logical time at injection.
    pub logical_time: u64,
}

/// The ordered record of every injected fault.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FaultLog {
    records: Vec<FaultRecord>,
}

impl FaultLog {
    /// Build a log from records.
    #[must_use]
    pub const fn from_records(records: Vec<FaultRecord>) -> Self {
        Self { records }
    }

    /// Every record, in injection order.
    #[must_use]
    pub fn records(&self) -> &[FaultRecord] {
        &self.records
    }

    /// How many faults were injected.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether no fault was injected.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// One reached effect, whether or not the caller ever learned of it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EffectRecord {
    /// Ordinal of this effect within the store's lifetime.
    pub sequence: u64,
    /// The operation position that produced it.
    pub at: OpIndex,
    /// The operation kind.
    pub op_kind: AuthorityOpKind,
    /// Whether observable store state actually changed.
    pub mutated: bool,
    /// Logical time at application.
    pub logical_time: u64,
}

/// The ordered record of every reached effect.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EffectLog {
    records: Vec<EffectRecord>,
}

impl EffectLog {
    /// Build a log from records.
    #[must_use]
    pub const fn from_records(records: Vec<EffectRecord>) -> Self {
        Self { records }
    }

    /// Every record, in application order.
    #[must_use]
    pub fn records(&self) -> &[EffectRecord] {
        &self.records
    }

    /// How many effects were reached.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether no effect was reached.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// How many reached effects actually changed observable state.
    #[must_use]
    pub fn mutation_count(&self) -> usize {
        self.records.iter().filter(|record| record.mutated).count()
    }
}

/// A deterministic bit mixer used to materialise seeded schedules.
///
/// # Non-claim
///
/// This is not a cryptographic generator and must never be used where
/// unpredictability is a security property.  Its only job is to turn one seed
/// into one reproducible schedule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Start the generator at `seed`.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// The next value in the stream.
    pub const fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// The next value reduced into `0..bound`, or zero when `bound` is zero.
    pub const fn next_below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            0
        } else {
            self.next_u64() % bound
        }
    }
}
