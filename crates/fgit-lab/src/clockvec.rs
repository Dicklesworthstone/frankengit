//! Vector clocks, and the happens-before relation they induce.
//!
//! A scalar tick tells you *when* an event was recorded; it cannot tell you
//! whether two events were ordered or merely happened to be written down in
//! some order. That distinction is the whole basis of partial-order reduction:
//! two concurrent events can be swapped without changing the run, and two
//! ordered ones cannot.
//!
//! So every explored event carries a [`VectorClock`]. Participants tick their
//! own entry when they act and merge the clock of whatever they observed, which
//! makes [`VectorClock::happens_before`] exact for this model rather than
//! approximate: `a → b` iff every entry of `a` is `<=` the corresponding entry
//! of `b` and at least one is strictly less.
//!
//! Clocks are keyed by [`StepId`] in a `BTreeMap`, so iteration, rendering, and
//! comparison are all order-stable — a clock rendered twice produces identical
//! bytes, which is what lets it appear in a replayable trace.

use std::collections::BTreeMap;

use crate::plan::StepId;

/// How two vector clocks relate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClockOrdering {
    /// The two clocks are identical.
    Equal,
    /// The left clock happens strictly before the right.
    Before,
    /// The right clock happens strictly before the left.
    After,
    /// Neither precedes the other: the events are concurrent.
    Concurrent,
}

impl ClockOrdering {
    /// Stable machine code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Equal => "equal",
            Self::Before => "before",
            Self::After => "after",
            Self::Concurrent => "concurrent",
        }
    }

    /// Whether the two events may be swapped without changing the run.
    ///
    /// Only concurrent events may. Equality is not swappability — an event is
    /// not independent of itself.
    #[must_use]
    pub const fn is_swappable(self) -> bool {
        matches!(self, Self::Concurrent)
    }
}

/// A vector clock over participants.
///
/// Absent entries are zero, so a clock that has never seen a participant
/// compares correctly against one that has.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VectorClock {
    entries: BTreeMap<StepId, u64>,
}

impl VectorClock {
    /// The clock at the start of a run: every entry zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Advance `who`'s own entry by one.
    pub fn tick(&mut self, who: &StepId) {
        let entry = self.entries.entry(who.clone()).or_insert(0);
        *entry = entry.saturating_add(1);
    }

    /// Take the pointwise maximum with `other`.
    ///
    /// This is what a participant does when it observes something another
    /// participant produced: everything the observed event knew, this
    /// participant now knows too.
    pub fn merge(&mut self, other: &Self) {
        for (who, value) in &other.entries {
            let entry = self.entries.entry(who.clone()).or_insert(0);
            *entry = (*entry).max(*value);
        }
    }

    /// A participant's entry, zero if never ticked.
    #[must_use]
    pub fn get(&self, who: &StepId) -> u64 {
        self.entries.get(who).copied().unwrap_or(0)
    }

    /// Every participant this clock has an entry for, in name order.
    #[must_use]
    pub fn participants(&self) -> Vec<StepId> {
        self.entries.keys().cloned().collect()
    }

    /// Whether this clock has no entries at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether `self` is pointwise `<=` `other`.
    fn dominated_by(&self, other: &Self) -> bool {
        self.entries
            .iter()
            .all(|(who, value)| *value <= other.get(who))
    }

    /// How this clock relates to `other`.
    #[must_use]
    pub fn compare(&self, other: &Self) -> ClockOrdering {
        let forward = self.dominated_by(other);
        let backward = other.dominated_by(self);
        match (forward, backward) {
            (true, true) => ClockOrdering::Equal,
            (true, false) => ClockOrdering::Before,
            (false, true) => ClockOrdering::After,
            (false, false) => ClockOrdering::Concurrent,
        }
    }

    /// Whether this clock strictly precedes `other`.
    #[must_use]
    pub fn happens_before(&self, other: &Self) -> bool {
        self.compare(other) == ClockOrdering::Before
    }

    /// Whether neither clock precedes the other.
    #[must_use]
    pub fn concurrent_with(&self, other: &Self) -> bool {
        self.compare(other) == ClockOrdering::Concurrent
    }

    /// A canonical, stable rendering for the trace.
    ///
    /// Zero entries are omitted so a clock's rendering depends on what has
    /// actually happened rather than on how many participants the run
    /// declared. Two runs that reached the same causal state therefore render
    /// identically even if one declared extra idle participants.
    #[must_use]
    pub fn canonical(&self) -> String {
        let parts: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, value)| **value > 0)
            .map(|(who, value)| format!("{who}:{value}"))
            .collect();
        if parts.is_empty() {
            "-".to_owned()
        } else {
            parts.join(",")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn who(name: &str) -> StepId {
        StepId::new(name)
    }

    #[test]
    fn a_new_clock_is_empty_and_reads_zero_everywhere() {
        let clock = VectorClock::new();
        assert!(clock.is_empty());
        assert_eq!(clock.get(&who("anyone")), 0);
        assert_eq!(clock.canonical(), "-");
    }

    #[test]
    fn ticking_advances_only_the_ticking_participant() {
        let mut clock = VectorClock::new();
        clock.tick(&who("a"));
        clock.tick(&who("a"));
        assert_eq!(clock.get(&who("a")), 2);
        assert_eq!(clock.get(&who("b")), 0);
    }

    #[test]
    fn a_clock_strictly_precedes_its_own_future() {
        let mut before = VectorClock::new();
        before.tick(&who("a"));
        let mut after = before.clone();
        after.tick(&who("a"));

        assert_eq!(before.compare(&after), ClockOrdering::Before);
        assert_eq!(after.compare(&before), ClockOrdering::After);
        assert!(before.happens_before(&after));
        assert!(!after.happens_before(&before));
        assert!(!before.concurrent_with(&after));
    }

    #[test]
    fn independent_participants_are_concurrent() {
        // The case partial-order reduction exists to exploit: neither event
        // saw the other, so swapping them cannot change the run.
        let mut left = VectorClock::new();
        left.tick(&who("a"));
        let mut right = VectorClock::new();
        right.tick(&who("b"));

        assert_eq!(left.compare(&right), ClockOrdering::Concurrent);
        assert_eq!(right.compare(&left), ClockOrdering::Concurrent);
        assert!(left.concurrent_with(&right));
        assert!(left.compare(&right).is_swappable());
    }

    #[test]
    fn merging_establishes_causality() {
        // `b` observes something `a` produced, so everything `a` knew,
        // `b` now knows — and `a`'s event now precedes `b`'s next one.
        let mut a = VectorClock::new();
        a.tick(&who("a"));

        let mut b = VectorClock::new();
        b.tick(&who("b"));
        assert!(a.concurrent_with(&b));

        b.merge(&a);
        b.tick(&who("b"));
        assert!(a.happens_before(&b));
        assert!(!a.concurrent_with(&b));
    }

    #[test]
    fn equality_is_not_swappability() {
        // An event is not independent of itself; only genuine concurrency
        // licenses a swap.
        let mut clock = VectorClock::new();
        clock.tick(&who("a"));
        let same = clock.clone();
        assert_eq!(clock.compare(&same), ClockOrdering::Equal);
        assert!(!clock.compare(&same).is_swappable());
    }

    #[test]
    fn happens_before_is_transitive() {
        let mut first = VectorClock::new();
        first.tick(&who("a"));

        let mut second = first.clone();
        second.tick(&who("b"));

        let mut third = second.clone();
        third.tick(&who("c"));

        assert!(first.happens_before(&second));
        assert!(second.happens_before(&third));
        assert!(first.happens_before(&third));
    }

    #[test]
    fn merge_is_the_pointwise_maximum_and_is_idempotent() {
        let mut left = VectorClock::new();
        left.tick(&who("a"));
        left.tick(&who("a"));
        left.tick(&who("b"));

        let mut right = VectorClock::new();
        right.tick(&who("a"));
        right.tick(&who("c"));

        let mut merged = left.clone();
        merged.merge(&right);
        assert_eq!(merged.get(&who("a")), 2);
        assert_eq!(merged.get(&who("b")), 1);
        assert_eq!(merged.get(&who("c")), 1);

        // Merging again changes nothing.
        let once = merged.clone();
        merged.merge(&right);
        assert_eq!(merged, once);
    }

    #[test]
    fn absent_entries_compare_as_zero() {
        // A clock that has never heard of a participant must still compare
        // correctly against one that has.
        let mut seen = VectorClock::new();
        seen.tick(&who("a"));
        let unseen = VectorClock::new();

        assert_eq!(unseen.compare(&seen), ClockOrdering::Before);
        assert_eq!(seen.compare(&unseen), ClockOrdering::After);
    }

    #[test]
    fn the_canonical_rendering_is_stable_and_omits_zero_entries() {
        let mut clock = VectorClock::new();
        clock.tick(&who("writer"));
        clock.tick(&who("writer"));
        clock.tick(&who("reader"));

        // Name order, not insertion order, so the rendering is diffable.
        assert_eq!(clock.canonical(), "reader:1,writer:2");
        assert_eq!(clock.canonical(), clock.canonical());

        // An idle participant contributes nothing, so two runs that reached
        // the same causal state render identically.
        let mut with_idle = clock.clone();
        with_idle.entries.insert(who("idle"), 0);
        assert_eq!(with_idle.canonical(), clock.canonical());
    }

    #[test]
    fn concurrency_survives_unrelated_progress() {
        // `a` and `b` stay concurrent no matter how far each runs on its own.
        let mut a = VectorClock::new();
        let mut b = VectorClock::new();
        for _ in 0..16 {
            a.tick(&who("a"));
            b.tick(&who("b"));
        }
        assert!(a.concurrent_with(&b));
    }
}
