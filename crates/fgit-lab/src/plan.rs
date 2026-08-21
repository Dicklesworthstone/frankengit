//! Controlled scheduling.
//!
//! A lab schedule is *data*: an explicit, ordered list of which participant
//! steps next. That is the whole point — a failing interleaving can be quoted,
//! checked in, and replayed, instead of being a story about a flaky run.
//!
//! Schedules can be built round-robin, from a seed, or written out explicitly.
//! A seeded schedule is materialised eagerly into the same explicit step list,
//! so once built there is no difference between "seeded" and "explicit" at
//! execution time and nothing consults the generator mid-run.

use std::collections::BTreeSet;

use crate::refuse::LabRefusal;
use crate::rng::SeededEntropy;

/// A participant in a schedule: a client, service, or logical actor.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StepId(String);

impl StepId {
    /// Name a participant.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for StepId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A fully materialised interleaving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabSchedule {
    participants: Vec<StepId>,
    order: Vec<StepId>,
    seed: Option<u64>,
}

impl LabSchedule {
    /// Each participant steps once per round, in declaration order.
    ///
    /// # Errors
    ///
    /// [`LabRefusal::UnknownParticipant`] if a name repeats — a duplicate
    /// participant makes "whose turn is it" ambiguous.
    pub fn round_robin(participants: Vec<StepId>, rounds: usize) -> Result<Self, LabRefusal> {
        Self::validate_participants(&participants)?;
        let mut order = Vec::with_capacity(participants.len().saturating_mul(rounds));
        for _ in 0..rounds {
            order.extend(participants.iter().cloned());
        }
        Ok(Self {
            participants,
            order,
            seed: None,
        })
    }

    /// A seeded interleaving of `steps` total steps.
    ///
    /// The generator runs to completion here, not during execution, so the
    /// resulting schedule is ordinary data that can be printed and replayed.
    ///
    /// # Errors
    ///
    /// [`LabRefusal::UnknownParticipant`] if a name repeats.
    pub fn seeded(participants: Vec<StepId>, steps: usize, seed: u64) -> Result<Self, LabRefusal> {
        Self::validate_participants(&participants)?;
        let mut entropy = SeededEntropy::from_seed(seed);
        let mut order = Vec::with_capacity(steps);
        for _ in 0..steps {
            match entropy.choose_index(participants.len()) {
                Some(index) => order.push(participants[index].clone()),
                None => break,
            }
        }
        Ok(Self {
            participants,
            order,
            seed: Some(seed),
        })
    }

    /// An explicitly written interleaving.
    ///
    /// This is the shape a reduced counterexample takes: once a campaign finds
    /// a failing seeded schedule it minimises it and checks in the explicit
    /// step list.
    ///
    /// # Errors
    ///
    /// [`LabRefusal::UnknownParticipant`] if a step names a participant that
    /// was not declared, or if a participant name repeats.
    pub fn explicit(participants: Vec<StepId>, order: Vec<StepId>) -> Result<Self, LabRefusal> {
        Self::validate_participants(&participants)?;
        for step in &order {
            if !participants.contains(step) {
                return Err(LabRefusal::UnknownParticipant {
                    name: step.0.clone(),
                });
            }
        }
        Ok(Self {
            participants,
            order,
            seed: None,
        })
    }

    fn validate_participants(participants: &[StepId]) -> Result<(), LabRefusal> {
        let mut seen = BTreeSet::new();
        for participant in participants {
            if !seen.insert(participant) {
                return Err(LabRefusal::UnknownParticipant {
                    name: participant.0.clone(),
                });
            }
        }
        Ok(())
    }

    /// The declared participants, in declaration order.
    #[must_use]
    pub fn participants(&self) -> &[StepId] {
        &self.participants
    }

    /// The full step order.
    #[must_use]
    pub fn order(&self) -> &[StepId] {
        &self.order
    }

    /// How many steps the schedule declares.
    #[must_use]
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Whether the schedule has no steps.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// The seed, when this schedule was generated from one.
    #[must_use]
    pub const fn seed(&self) -> Option<u64> {
        self.seed
    }

    /// A cursor for executing this schedule.
    #[must_use]
    pub const fn cursor(&self) -> StepCursor<'_> {
        StepCursor {
            schedule: self,
            position: 0,
        }
    }

    /// A canonical, stable, single-line rendering.
    ///
    /// This is what a campaign quotes to make a failing interleaving
    /// reproducible by someone else.
    #[must_use]
    pub fn canonical_line(&self) -> String {
        let mut out = String::from("fgit-lab-schedule-v1");
        out.push_str(&format!(
            "|seed={}",
            self.seed
                .map_or_else(|| "none".to_owned(), |seed| seed.to_string())
        ));
        out.push_str(&format!(
            "|participants={}",
            self.participants
                .iter()
                .map(StepId::as_str)
                .collect::<Vec<_>>()
                .join(",")
        ));
        out.push_str(&format!("|steps={}", self.order.len()));
        out.push_str(&format!(
            "|order={}",
            self.order
                .iter()
                .map(StepId::as_str)
                .collect::<Vec<_>>()
                .join(",")
        ));
        out
    }
}

/// A position within a schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepCursor<'a> {
    schedule: &'a LabSchedule,
    position: usize,
}

impl StepCursor<'_> {
    /// How many steps have been taken.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.position
    }

    /// How many steps remain.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.schedule.order.len().saturating_sub(self.position)
    }

    /// Whether the schedule is exhausted.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.remaining() == 0
    }

    /// Peek at the next participant without consuming it.
    #[must_use]
    pub fn peek(&self) -> Option<&StepId> {
        self.schedule.order.get(self.position)
    }

    /// Take the next step.
    ///
    /// # Errors
    ///
    /// [`LabRefusal::ScheduleExhausted`] when the schedule is finished.
    /// Running past the end silently would let a campaign's real step count
    /// drift from the schedule it claims to have run.
    pub fn next_step(&mut self) -> Result<&StepId, LabRefusal> {
        let step = self.schedule.order.get(self.position).ok_or({
            LabRefusal::ScheduleExhausted {
                declared: self.schedule.order.len(),
            }
        })?;
        self.position += 1;
        Ok(step)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn participants() -> Vec<StepId> {
        vec![
            StepId::new("writer-a"),
            StepId::new("writer-b"),
            StepId::new("reader"),
        ]
    }

    #[test]
    fn round_robin_visits_every_participant_each_round() {
        let schedule = LabSchedule::round_robin(participants(), 3).expect("valid");
        assert_eq!(schedule.len(), 9);
        assert_eq!(
            schedule
                .order()
                .iter()
                .map(StepId::as_str)
                .collect::<Vec<_>>(),
            vec![
                "writer-a", "writer-b", "reader", "writer-a", "writer-b", "reader", "writer-a",
                "writer-b", "reader",
            ]
        );
        assert_eq!(schedule.seed(), None);
    }

    #[test]
    fn a_seeded_schedule_is_reproducible_and_seed_sensitive() {
        let first = LabSchedule::seeded(participants(), 40, 0xABCD).expect("valid");
        let second = LabSchedule::seeded(participants(), 40, 0xABCD).expect("valid");
        assert_eq!(first, second);
        assert_eq!(first.seed(), Some(0xABCD));

        let other = LabSchedule::seeded(participants(), 40, 0xABCE).expect("valid");
        assert_ne!(first.order(), other.order());
    }

    #[test]
    fn a_seeded_schedule_only_names_declared_participants() {
        let schedule = LabSchedule::seeded(participants(), 200, 5).expect("valid");
        assert_eq!(schedule.len(), 200);
        for step in schedule.order() {
            assert!(
                schedule.participants().contains(step),
                "schedule named `{step}`, which was never declared"
            );
        }
    }

    #[test]
    fn an_explicit_schedule_rejects_an_undeclared_participant() {
        let refusal = LabSchedule::explicit(
            participants(),
            vec![StepId::new("writer-a"), StepId::new("ghost")],
        )
        .expect_err("a step must name a declared participant");
        assert_eq!(
            refusal,
            LabRefusal::UnknownParticipant {
                name: "ghost".to_owned()
            }
        );

        // Paired permitted case: the same shape with only declared names.
        let schedule = LabSchedule::explicit(
            participants(),
            vec![StepId::new("writer-a"), StepId::new("reader")],
        )
        .expect("declared names are permitted");
        assert_eq!(schedule.len(), 2);
    }

    #[test]
    fn duplicate_participants_are_refused() {
        let refusal =
            LabSchedule::round_robin(vec![StepId::new("writer-a"), StepId::new("writer-a")], 1)
                .expect_err("a duplicate participant makes turn order ambiguous");
        assert_eq!(
            refusal,
            LabRefusal::UnknownParticipant {
                name: "writer-a".to_owned()
            }
        );
    }

    #[test]
    fn the_cursor_walks_the_schedule_and_then_refuses() {
        let schedule = LabSchedule::round_robin(participants(), 1).expect("valid");
        let mut cursor = schedule.cursor();

        assert_eq!(cursor.remaining(), 3);
        assert_eq!(cursor.peek(), Some(&StepId::new("writer-a")));

        for expected in ["writer-a", "writer-b", "reader"] {
            assert_eq!(cursor.next_step().expect("in range").as_str(), expected);
        }
        assert!(cursor.is_exhausted());
        assert_eq!(cursor.position(), 3);

        let refusal = cursor
            .next_step()
            .expect_err("running past the end must be refused");
        assert_eq!(refusal, LabRefusal::ScheduleExhausted { declared: 3 });
        assert!(!refusal.indicts_subject());
    }

    #[test]
    fn an_empty_schedule_is_immediately_exhausted() {
        let schedule = LabSchedule::round_robin(participants(), 0).expect("valid");
        assert!(schedule.is_empty());
        let cursor = schedule.cursor();
        assert!(cursor.is_exhausted());
        assert_eq!(cursor.peek(), None);
    }

    #[test]
    fn the_canonical_line_makes_an_interleaving_quotable() {
        let schedule = LabSchedule::explicit(
            participants(),
            vec![
                StepId::new("writer-a"),
                StepId::new("writer-b"),
                StepId::new("writer-a"),
            ],
        )
        .expect("valid");

        let line = schedule.canonical_line();
        assert_eq!(
            line,
            "fgit-lab-schedule-v1|seed=none|participants=writer-a,writer-b,reader|steps=3|order=writer-a,writer-b,writer-a"
        );
        // Stable across renderings, so a report can be diffed.
        assert_eq!(line, schedule.canonical_line());

        // A seeded schedule records its seed, which is its reproduction key.
        let seeded = LabSchedule::seeded(participants(), 4, 77).expect("valid");
        assert!(seeded.canonical_line().contains("|seed=77|"));
    }

    #[test]
    fn a_quoted_explicit_schedule_replays_the_seeded_one_exactly() {
        // The reduction workflow: find it with a seed, check it in explicitly.
        let seeded = LabSchedule::seeded(participants(), 12, 31).expect("valid");
        let quoted = LabSchedule::explicit(participants(), seeded.order().to_vec()).expect("valid");
        assert_eq!(seeded.order(), quoted.order());
    }
}
