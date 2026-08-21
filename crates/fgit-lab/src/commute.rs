//! The conflict relation over `FrankenGit` protocol events.
//!
//! Partial-order reduction is only as sound as this relation. Two events are
//! *independent* when swapping adjacent occurrences of them cannot change any
//! later observation; the explorer then visits one representative per
//! equivalence class instead of every interleaving. Declare too much
//! independence and exploration silently skips the interleaving that contains
//! the bug — a false green that looks exactly like a real one. Declare too
//! little and exploration is merely slower.
//!
//! So the relation here is deliberately conservative, stated explicitly rather
//! than inferred, and every rule below is a test.
//!
//! # The relation
//!
//! Two events conflict when any of these hold:
//!
//! - **Same head key, at least one head mutation.** Two `CompareExchangeHead`
//!   on one key obviously order; a `CompareExchangeHead` and a `ReadHead` on
//!   one key also order, because the read observes one side of the CAS.
//! - **Same immutable key, at least one write.** Two `SealPut`/`BodyWrite` to
//!   one key order even when the bodies are identical: put-if-absent makes the
//!   *first* writer the creator and the second an identical-retry, and which
//!   is which is observable.
//! - **Cancellation against the same participant's own events.** A `Cancel`
//!   decides whether that participant's later events happen at all, so it
//!   orders against everything it owns — and against nothing anyone else owns.
//!
//! Everything else commutes: different keys never conflict, two reads never
//! conflict, and one participant's cancel is independent of another's work.

use crate::plan::StepId;

/// A protocol event the explorer can reorder.
///
/// Keys are carried as owned strings rather than `fgit-authority` key types so
/// the relation can be stated and tested without a store; the campaign layer
/// maps real operations onto these.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProtocolEvent {
    /// Conditional replacement of a repository head.
    CompareExchangeHead {
        /// The head key.
        key: String,
    },
    /// A read of a repository head.
    ReadHead {
        /// The head key.
        key: String,
    },
    /// Publication of a sealed transaction body.
    SealPut {
        /// The immutable key.
        key: String,
    },
    /// A write of an immutable object body.
    BodyWrite {
        /// The immutable key.
        key: String,
    },
    /// A read of an immutable object body.
    ReadBody {
        /// The immutable key.
        key: String,
    },
    /// Cancellation of a participant's own work.
    Cancel {
        /// The participant being cancelled.
        participant: StepId,
    },
}

impl ProtocolEvent {
    /// Stable machine code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::CompareExchangeHead { .. } => "cas",
            Self::ReadHead { .. } => "read_head",
            Self::SealPut { .. } => "seal_put",
            Self::BodyWrite { .. } => "body_write",
            Self::ReadBody { .. } => "read_body",
            Self::Cancel { .. } => "cancel",
        }
    }

    /// The key this event touches, if it touches one.
    #[must_use]
    pub fn key(&self) -> Option<&str> {
        match self {
            Self::CompareExchangeHead { key }
            | Self::ReadHead { key }
            | Self::SealPut { key }
            | Self::BodyWrite { key }
            | Self::ReadBody { key } => Some(key),
            Self::Cancel { .. } => None,
        }
    }

    /// Whether this event mutates the state it touches.
    #[must_use]
    pub const fn is_mutation(&self) -> bool {
        matches!(
            self,
            Self::CompareExchangeHead { .. } | Self::SealPut { .. } | Self::BodyWrite { .. }
        )
    }

    /// Whether this event acts on the repository head rather than an
    /// immutable slot.
    #[must_use]
    pub const fn is_head(&self) -> bool {
        matches!(
            self,
            Self::CompareExchangeHead { .. } | Self::ReadHead { .. }
        )
    }

    /// A canonical rendering for the trace.
    #[must_use]
    pub fn canonical(&self) -> String {
        match self {
            Self::Cancel { participant } => format!("cancel:{participant}"),
            other => other.key().map_or_else(
                || other.code().to_owned(),
                |key| format!("{}:{key}", other.code()),
            ),
        }
    }
}

/// One participant's event, as the explorer sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedEvent {
    /// Who performs it.
    pub actor: StepId,
    /// What it is.
    pub event: ProtocolEvent,
}

impl OwnedEvent {
    /// Pair an actor with an event.
    #[must_use]
    pub const fn new(actor: StepId, event: ProtocolEvent) -> Self {
        Self { actor, event }
    }

    /// A canonical rendering.
    #[must_use]
    pub fn canonical(&self) -> String {
        format!("{}@{}", self.event.canonical(), self.actor)
    }
}

/// The declared conflict relation.
///
/// A unit type rather than a free function so the relation has one named home
/// that tests and documentation both point at, and so a future profile-specific
/// relation can be introduced without changing call sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConflictRelation;

impl ConflictRelation {
    /// Whether two owned events must keep their relative order.
    ///
    /// Reflexive on a single event: an event always conflicts with itself, so
    /// the explorer never treats one occurrence as independent of another
    /// occurrence of the same thing by the same actor.
    #[must_use]
    pub fn conflicts(self, left: &OwnedEvent, right: &OwnedEvent) -> bool {
        // A participant's own events are totally ordered by its program: it
        // cannot run its second step before its first.
        if left.actor == right.actor {
            return true;
        }

        match (&left.event, &right.event) {
            // Two cancels order when they name the same target: the second
            // observes whether the first already stopped it. This arm must come
            // first — matching `(Cancel, _)` before it would compare the target
            // against the *canceller's* actor id rather than against the other
            // cancel's target, and call two same-target cancels independent.
            (
                ProtocolEvent::Cancel {
                    participant: left_target,
                },
                ProtocolEvent::Cancel {
                    participant: right_target,
                },
            ) => left_target == right_target,
            // Otherwise a cancel orders against the cancelled participant's own
            // work and nothing else. The actors differ here, so only a cancel
            // naming the *other* actor conflicts.
            (ProtocolEvent::Cancel { participant }, _) => *participant == right.actor,
            (_, ProtocolEvent::Cancel { participant }) => *participant == left.actor,
            (first, second) => Self::state_conflict(first, second),
        }
    }

    /// Whether two non-cancel events touch the same state incompatibly.
    fn state_conflict(left: &ProtocolEvent, right: &ProtocolEvent) -> bool {
        // Different keys never interact. Head keys and immutable keys live in
        // separate namespaces, so an equal string on different sides is still
        // not the same slot.
        if left.is_head() != right.is_head() {
            return false;
        }
        match (left.key(), right.key()) {
            (Some(a), Some(b)) if a == b => left.is_mutation() || right.is_mutation(),
            _ => false,
        }
    }

    /// Whether two owned events may be swapped when adjacent.
    #[must_use]
    pub fn independent(self, left: &OwnedEvent, right: &OwnedEvent) -> bool {
        !self.conflicts(left, right)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actor(name: &str) -> StepId {
        StepId::new(name)
    }

    fn cas(who: &str, key: &str) -> OwnedEvent {
        OwnedEvent::new(
            actor(who),
            ProtocolEvent::CompareExchangeHead {
                key: key.to_owned(),
            },
        )
    }

    fn read_head(who: &str, key: &str) -> OwnedEvent {
        OwnedEvent::new(
            actor(who),
            ProtocolEvent::ReadHead {
                key: key.to_owned(),
            },
        )
    }

    fn seal(who: &str, key: &str) -> OwnedEvent {
        OwnedEvent::new(
            actor(who),
            ProtocolEvent::SealPut {
                key: key.to_owned(),
            },
        )
    }

    fn body(who: &str, key: &str) -> OwnedEvent {
        OwnedEvent::new(
            actor(who),
            ProtocolEvent::BodyWrite {
                key: key.to_owned(),
            },
        )
    }

    fn read_body(who: &str, key: &str) -> OwnedEvent {
        OwnedEvent::new(
            actor(who),
            ProtocolEvent::ReadBody {
                key: key.to_owned(),
            },
        )
    }

    fn cancel(who: &str, target: &str) -> OwnedEvent {
        OwnedEvent::new(
            actor(who),
            ProtocolEvent::Cancel {
                participant: actor(target),
            },
        )
    }

    const R: ConflictRelation = ConflictRelation;

    #[test]
    fn a_participants_own_events_never_commute() {
        // Program order is absolute: a participant cannot run its second step
        // before its first, whatever the two steps touch.
        assert!(R.conflicts(&cas("a", "main"), &read_head("a", "other")));
        assert!(R.conflicts(&seal("a", "x"), &body("a", "y")));
        assert!(R.conflicts(&read_body("a", "x"), &read_body("a", "y")));
    }

    #[test]
    fn two_head_mutations_on_one_key_conflict() {
        assert!(R.conflicts(&cas("a", "main"), &cas("b", "main")));
        // ...and on different keys they do not.
        assert!(R.independent(&cas("a", "main"), &cas("b", "release")));
    }

    #[test]
    fn a_head_read_conflicts_with_a_head_mutation_on_the_same_key() {
        // The read observes one side of the CAS, so the order is visible.
        assert!(R.conflicts(&read_head("a", "main"), &cas("b", "main")));
        assert!(R.conflicts(&cas("a", "main"), &read_head("b", "main")));
    }

    #[test]
    fn two_head_reads_always_commute() {
        assert!(R.independent(&read_head("a", "main"), &read_head("b", "main")));
        assert!(R.independent(&read_head("a", "main"), &read_head("b", "release")));
    }

    #[test]
    fn two_writes_to_one_immutable_key_conflict_even_with_equal_bodies() {
        // Put-if-absent makes the first writer the creator and the second an
        // identical-retry. Which is which is observable, so they order.
        assert!(R.conflicts(&seal("a", "blob/1"), &seal("b", "blob/1")));
        assert!(R.conflicts(&body("a", "blob/1"), &seal("b", "blob/1")));
        // Different keys are independent.
        assert!(R.independent(&seal("a", "blob/1"), &seal("b", "blob/2")));
    }

    #[test]
    fn an_immutable_read_conflicts_only_with_a_write_to_that_key() {
        assert!(R.conflicts(&read_body("a", "blob/1"), &body("b", "blob/1")));
        assert!(R.independent(&read_body("a", "blob/1"), &read_body("b", "blob/1")));
        assert!(R.independent(&read_body("a", "blob/1"), &body("b", "blob/2")));
    }

    #[test]
    fn head_and_immutable_namespaces_do_not_alias() {
        // An equal key string on a head event and an immutable event is not
        // the same slot, so they must not be treated as conflicting.
        assert!(R.independent(&cas("a", "same"), &seal("b", "same")));
        assert!(R.independent(&read_head("a", "same"), &read_body("b", "same")));
    }

    #[test]
    fn a_cancel_orders_against_its_target_and_nobody_else() {
        // It decides whether the target's later events happen at all.
        assert!(R.conflicts(&cancel("supervisor", "worker"), &cas("worker", "main")));
        assert!(R.conflicts(&cas("worker", "main"), &cancel("supervisor", "worker")));

        // Paired permitted case: a cancel aimed elsewhere is independent.
        assert!(R.independent(&cancel("supervisor", "worker"), &cas("other", "main")));
        assert!(R.independent(&cancel("supervisor", "worker"), &seal("other", "blob/1")));
    }

    #[test]
    fn two_cancels_of_different_participants_commute() {
        assert!(R.independent(&cancel("s1", "worker-a"), &cancel("s2", "worker-b")));
        // But cancelling the same target twice orders, because the second
        // observes whether the first already stopped it.
        assert!(R.conflicts(&cancel("s1", "worker-a"), &cancel("s2", "worker-a")));
    }

    #[test]
    fn the_relation_is_symmetric() {
        // Asymmetry here would make exploration order-dependent, which would
        // silently change which interleavings get visited.
        let events = [
            cas("a", "main"),
            read_head("b", "main"),
            seal("a", "blob/1"),
            body("b", "blob/1"),
            read_body("a", "blob/2"),
            cancel("c", "a"),
            cancel("c", "b"),
        ];
        for left in &events {
            for right in &events {
                assert_eq!(
                    R.conflicts(left, right),
                    R.conflicts(right, left),
                    "asymmetric on {} vs {}",
                    left.canonical(),
                    right.canonical()
                );
            }
        }
    }

    #[test]
    fn the_relation_is_reflexive() {
        // An event is never independent of itself.
        for event in [
            cas("a", "main"),
            read_head("a", "main"),
            seal("a", "blob/1"),
            read_body("a", "blob/1"),
            cancel("a", "b"),
        ] {
            assert!(R.conflicts(&event, &event), "{}", event.canonical());
        }
    }

    #[test]
    fn canonical_renderings_are_distinct_and_stable() {
        let rendered = [
            cas("a", "main").canonical(),
            read_head("a", "main").canonical(),
            seal("a", "main").canonical(),
            body("a", "main").canonical(),
            read_body("a", "main").canonical(),
            cancel("a", "b").canonical(),
        ];
        let mut sorted = rendered.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), rendered.len());
        assert_eq!(cas("a", "main").canonical(), "cas:main@a");
        assert_eq!(cancel("a", "b").canonical(), "cancel:b@a");
    }
}
