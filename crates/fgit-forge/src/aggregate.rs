//! Aggregate identity, version tracking, and expected-version admission.
//!
//! A forge aggregate is an event stream with a gap-free version. Writing to it
//! requires naming the version you believe it is at, and a mismatch is a typed
//! refusal. There is deliberately no "just take the latest write" path: two
//! callers who both believed they were extending version 7 have produced
//! different histories, and silently keeping the second one destroys the first
//! without telling anybody.

use core::fmt;

use crate::ForgeRefusal;

/// Declares a gap-free counter newtype over `u64`.
///
/// `fgit-types` has the same construction behind a private macro, which is not
/// exported, so the semantics are reproduced here rather than approximated:
/// zero is reserved for "no value yet", the successor is always exactly one
/// greater, and exhaustion is a refusal rather than a wrap.
macro_rules! forge_counter {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        ///
        /// Zero is not a value: it is reserved to mean "none yet" in optional
        /// positions, so it can never name a live one.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(u64);

        impl $name {
            /// The first value this counter ever takes.
            pub const FIRST: Self = Self(1);

            /// Builds a counter from its wire value, refusing zero.
            ///
            /// Returns `None` rather than a typed error so each caller can
            /// name the refusal appropriate to its own surface: a decoder
            /// reports a codec refusal, an API reports a forge refusal.
            #[must_use]
            pub const fn try_new(value: u64) -> Option<Self> {
                if value == 0 { None } else { Some(Self(value)) }
            }

            /// The wire value.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0
            }

            /// True when `later` is exactly this value's successor.
            #[must_use]
            pub const fn is_immediate_predecessor_of(self, later: Self) -> bool {
                self.0 < later.0 && later.0 - self.0 == 1
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}", self.0)
            }
        }
    };
}

forge_counter!(
    AggregateVersion,
    "Position of one event within a single forge aggregate's stream."
);
forge_counter!(
    PullRequestNumber,
    "Repository-scoped number identifying one pull request aggregate."
);
forge_counter!(
    OrganisationNumber,
    "Tenant-scoped number identifying one organisation aggregate."
);
forge_counter!(
    TeamNumber,
    "Organisation-scoped number identifying one team aggregate."
);

impl AggregateVersion {
    /// The immediate successor, refusing exhaustion instead of wrapping.
    ///
    /// # Errors
    ///
    /// [`ForgeRefusal::VersionExhausted`] when the counter is saturated.
    pub const fn next(self) -> Result<Self, ForgeRefusal> {
        match self.0.checked_add(1) {
            Some(next) => Ok(Self(next)),
            None => Err(ForgeRefusal::VersionExhausted { observed: self }),
        }
    }
}

/// The version a writer believes an aggregate is at.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpectedVersion {
    /// The aggregate has no events at all yet.
    ///
    /// Distinct from `Exactly(FIRST)`: this asserts the stream does not exist,
    /// which is what creating a pull request requires. Collapsing the two would
    /// let a create silently append to a stream that already had events.
    NewStream,
    /// The aggregate is at exactly this version.
    Exactly(AggregateVersion),
}

impl fmt::Display for ExpectedVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NewStream => formatter.write_str("a new stream"),
            Self::Exactly(version) => write!(formatter, "version {version}"),
        }
    }
}

/// Which aggregate an event or head belongs to.
///
/// # Why zero is the discriminant
///
/// The aggregate slot is the leading `u64` of an event payload, and every
/// counter here refuses zero, so `counter` already rejects a zero in that slot
/// as `ValueUnrepresentable { observed: 0, limit: 1 }`. No valid encoding has
/// ever contained one. That makes zero a free escape: a nonzero slot is a pull
/// request and is written exactly as it always was, and a zero slot introduces
/// a kind tag followed by the kind's own id.
///
/// The consequence is the point of the design. Every pull-request event keeps
/// its exact canonical bytes and therefore its exact `ForgeEventId`, so adding
/// aggregates does not rewrite the identity of events already committed.
/// Widening the slot to carry a tag unconditionally would have changed every
/// one of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AggregateId {
    /// One pull request. Encoded bare, with no tag.
    PullRequest(PullRequestNumber),
    /// One organisation.
    Organisation(OrganisationNumber),
    /// One team.
    Team(TeamNumber),
}

/// Wire tag for [`AggregateId::Organisation`], written only after a zero slot.
pub(crate) const AGGREGATE_KIND_ORGANISATION: u32 = 1;
/// Wire tag for [`AggregateId::Team`], written only after a zero slot.
pub(crate) const AGGREGATE_KIND_TEAM: u32 = 2;

impl From<PullRequestNumber> for AggregateId {
    fn from(value: PullRequestNumber) -> Self {
        Self::PullRequest(value)
    }
}

impl From<OrganisationNumber> for AggregateId {
    fn from(value: OrganisationNumber) -> Self {
        Self::Organisation(value)
    }
}

impl From<TeamNumber> for AggregateId {
    fn from(value: TeamNumber) -> Self {
        Self::Team(value)
    }
}

impl fmt::Display for AggregateId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PullRequest(number) => write!(formatter, "pull-request/{number}"),
            Self::Organisation(number) => write!(formatter, "organisation/{number}"),
            Self::Team(number) => write!(formatter, "team/{number}"),
        }
    }
}

/// Where one aggregate's stream currently ends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateHead {
    /// Which aggregate this stream belongs to.
    pub aggregate: AggregateId,
    /// The last version written, absent when the stream has no events.
    pub version: Option<AggregateVersion>,
}

impl AggregateHead {
    /// A stream with no events yet.
    #[must_use]
    pub fn empty(aggregate: impl Into<AggregateId>) -> Self {
        Self {
            aggregate: aggregate.into(),
            version: None,
        }
    }

    /// A stream whose last written event is at `version`.
    #[must_use]
    pub fn at(aggregate: impl Into<AggregateId>, version: AggregateVersion) -> Self {
        Self {
            aggregate: aggregate.into(),
            version: Some(version),
        }
    }

    /// Admits a write against an expected version, returning the version the
    /// new event will carry.
    ///
    /// This is conditional replacement, not a hint: the returned version is
    /// only valid while the aggregate is still where this call observed it.
    /// The caller carries that version into the event body, so a write that
    /// loses a race cannot be re-labelled and retried without re-admitting.
    ///
    /// # Errors
    ///
    /// [`ForgeRefusal::VersionConflict`] when the aggregate is not where the
    /// caller believed, and [`ForgeRefusal::VersionExhausted`] when the counter
    /// cannot advance.
    pub const fn admit(&self, expected: ExpectedVersion) -> Result<AggregateVersion, ForgeRefusal> {
        match (expected, self.version) {
            (ExpectedVersion::NewStream, None) => Ok(AggregateVersion::FIRST),
            (ExpectedVersion::Exactly(required), Some(current))
                if required.get() == current.get() =>
            {
                current.next()
            }
            (expected, observed) => Err(ForgeRefusal::VersionConflict { expected, observed }),
        }
    }
}
