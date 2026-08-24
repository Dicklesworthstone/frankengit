//! Values that may guide work but may never decide it.
//!
//! `frankengit-fg036a`. Routing preferences and gossiped head tokens or object
//! locations are hints: they make a cell faster at finding the right answer and
//! they are never evidence that the answer is right. §5.1 states the rule —
//! routing, gossip, local rows, materializations, indexes and caches are hints
//! and projections, and only a conditional replacement of the exact predecessor
//! head publishes state.
//!
//! # Why this is a type and not a naming convention
//!
//! The rule is easy to state and easy to lose. A gossiped head token arrives as
//! the same `HeadGeneration` an authenticated read produces; an object location
//! from gossip is the same identifier the fabric returns. Once such a value is
//! an ordinary `T`, nothing at the use site distinguishes "I verified this" from
//! "someone told me this", and the two are one refactor apart.
//!
//! [`Hint<T>`] makes them different types. The inner value can be looked at
//! freely — that is what a hint is for — but obtaining an owned `T` requires
//! passing a check, so an authority-sensitive path cannot consume one by
//! accident. The compiler does not know what "authority-sensitive" means; what
//! it enforces is that somebody wrote a verification step.
//!
//! # What this deliberately does not do
//!
//! It does not verify anything itself, and it cannot: verification needs the
//! authority, which is many layers above this one. It also does not stop a
//! caller from writing a check that always succeeds. That would be a lie a type
//! cannot prevent, and pretending otherwise would be worse than the honest
//! bound — the guarantee here is that the check exists and is visible at the
//! call site, which is exactly what a reviewer can audit.

use core::fmt;

/// A value offered as guidance, not as evidence.
///
/// See the module documentation for why this exists. The short version: a hint
/// and a verified fact have the same Rust type once you unwrap them, so the
/// unwrap is the place to require a check.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hint<T> {
    value: T,
    source: HintSource,
}

impl<T> Hint<T> {
    /// Wrap a value that arrived from an unverified source.
    #[must_use]
    pub const fn new(value: T, source: HintSource) -> Self {
        Self { value, source }
    }

    /// Where this hint came from.
    #[must_use]
    pub const fn source(&self) -> HintSource {
        self.source
    }

    /// Look at the hint without taking it.
    ///
    /// This is the operation routing and prefetch want: choosing which cell to
    /// ask, or which location to try first, is a decision whose worst outcome
    /// is a slower correct answer. Nothing read through here may be published,
    /// compared against an authority record, or returned to a client as fact.
    #[must_use]
    pub const fn peek(&self) -> &T {
        &self.value
    }

    /// Take the value, but only by passing a check.
    ///
    /// # Errors
    ///
    /// Whatever `check` returns. The error type is the caller's because the
    /// verification that matters differs by hint: a head token is checked
    /// against the authority, an object location against the fabric.
    pub fn verified_by<E, F>(self, check: F) -> Result<T, E>
    where
        F: FnOnce(&T) -> Result<(), E>,
    {
        check(&self.value)?;
        Ok(self.value)
    }

    /// Discard the hint and keep nothing.
    ///
    /// The honest counterpart to [`Self::verified_by`] for a path that decides
    /// not to trust a hint at all. Named so that "we ignored this" appears in
    /// the code rather than being expressed by an unused variable.
    pub fn discard(self) {}

    /// Map the carried value, keeping it a hint.
    #[must_use]
    pub fn map<U, F>(self, transform: F) -> Hint<U>
    where
        F: FnOnce(T) -> U,
    {
        Hint {
            value: transform(self.value),
            source: self.source,
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for Hint<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Rendered as a hint rather than as the bare value, so a debug line in
        // an incident log cannot be mistaken for a verified reading.
        formatter
            .debug_struct("Hint")
            .field("source", &self.source)
            .field("unverified", &self.value)
            .finish()
    }
}

/// Where an unverified value came from.
///
/// Carried because the mitigations differ. A stale local projection is a
/// correctness-neutral latency problem; a gossiped value from a peer is
/// attacker-influenced input, and a path that treats the two the same has
/// misjudged one of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HintSource {
    /// Chosen by a local deterministic function, such as routing preference.
    LocalRouting,
    /// Received from a peer cell.
    Gossip,
    /// Read from a local projection, index, or cache.
    LocalProjection,
}

impl HintSource {
    /// Every source, in declaration order.
    pub const ALL: [Self; 3] = [Self::LocalRouting, Self::Gossip, Self::LocalProjection];

    /// Whether a peer could have chosen this value.
    ///
    /// True for [`Self::Gossip`] only. Local routing and local projections can
    /// be wrong or stale, but they are not adversarially selected, so a bound
    /// that exists to resist a hostile peer belongs on this one.
    #[must_use]
    pub const fn is_peer_influenced(self) -> bool {
        matches!(self, Self::Gossip)
    }
}
