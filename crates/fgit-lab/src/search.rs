//! Schedule exploration by sleep-set dynamic partial-order reduction.
//!
//! # Which algorithm, and why
//!
//! This is **sleep-set DPOR over full enabled sets**, not source-DPOR.
//!
//! The two reduce different things. Source-DPOR prunes *state visits* by
//! computing a source set at each state and adding backtracking points when a
//! race is found; its guarantee is that no reachable state is missed. Sleep
//! sets prune *complete executions*: two executions that differ only by
//! swapping adjacent independent transitions are Mazurkiewicz-equivalent, and
//! a sleep set makes the explorer refuse to walk the second one.
//!
//! Sleep sets were chosen because the property this bead has to demonstrate is
//! a **hand-countable class count** — "on a known toy protocol, exploration
//! visits exactly the expected number of equivalence classes". With full
//! enabled sets, sleep-set DPOR yields exactly one complete execution per
//! Mazurkiewicz class, which is that property stated directly and checkable
//! against a golden number. Source-DPOR would visit fewer intermediate states
//! but its guarantee is about state coverage rather than class count, so the
//! golden would have to be stated about something less direct.
//!
//! The cost is honest and worth naming: sleep sets do not reduce the number of
//! *states* traversed the way source sets do, so this explores more internal
//! nodes than a source-DPOR implementation would. For the schedule sizes a
//! protocol campaign uses that is the right trade; if exploration ever becomes
//! the bottleneck, source sets are the next step and this module's conflict
//! relation is already the input they need.
//!
//! # Soundness rests entirely on the conflict relation
//!
//! Every pruning decision here is a call to
//! [`ConflictRelation`](crate::commute::ConflictRelation). If that relation
//! ever claims two dependent events are independent, exploration will skip the
//! interleaving containing the bug and report a clean sweep. That is why the
//! relation is declared explicitly and tested exhaustively in
//! [`crate::commute`] rather than inferred here.
//!
//! # Bounds are typed, never silent
//!
//! Exploration takes an explicit [`ExplorationBudget`]. When a bound is hit the
//! result is [`ExplorationOutcome::Incomplete`], which names the bound and what
//! was covered so far. [`ExplorationOutcome::Exhaustive`] is returned **only**
//! when the whole class space was walked, so "all schedules explored" is never
//! reported unless it is true.

use std::collections::{BTreeMap, BTreeSet};

use crate::clockvec::VectorClock;
use crate::commute::{ConflictRelation, OwnedEvent, ProtocolEvent};
use crate::plan::{LabSchedule, StepId};
use crate::refuse::LabRefusal;

/// A finite program per participant.
///
/// Each participant executes its events in order; the explorer decides only
/// *whose turn* it is, never what that participant does next. That keeps the
/// state space a pure function of the programs plus the interleaving, which is
/// what makes a counterexample schedule enough to reproduce a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    participants: Vec<StepId>,
    events: BTreeMap<StepId, Vec<ProtocolEvent>>,
}

impl Program {
    /// Build a program from per-participant event sequences.
    ///
    /// Participant order is the declared order and fixes the deterministic
    /// exploration order.
    ///
    /// # Errors
    ///
    /// [`LabRefusal::UnknownParticipant`] if a participant is declared twice.
    pub fn new(sequences: Vec<(StepId, Vec<ProtocolEvent>)>) -> Result<Self, LabRefusal> {
        let mut participants = Vec::with_capacity(sequences.len());
        let mut events = BTreeMap::new();
        for (who, sequence) in sequences {
            if events.contains_key(&who) {
                return Err(LabRefusal::UnknownParticipant {
                    name: who.as_str().to_owned(),
                });
            }
            participants.push(who.clone());
            events.insert(who, sequence);
        }
        Ok(Self {
            participants,
            events,
        })
    }

    /// The declared participants, in declaration order.
    #[must_use]
    pub fn participants(&self) -> &[StepId] {
        &self.participants
    }

    /// Total events across all participants.
    #[must_use]
    pub fn total_events(&self) -> usize {
        self.events.values().map(Vec::len).sum()
    }

    /// The event a participant would run at program counter `index`.
    fn event_at(&self, who: &StepId, index: usize) -> Option<&ProtocolEvent> {
        self.events.get(who).and_then(|seq| seq.get(index))
    }
}

/// Explicit limits on how much exploration may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExplorationBudget {
    max_executions: usize,
    max_transitions: u64,
}

impl ExplorationBudget {
    /// A budget with both bounds.
    #[must_use]
    pub const fn new(max_executions: usize, max_transitions: u64) -> Self {
        Self {
            max_executions,
            max_transitions,
        }
    }

    /// Complete executions allowed.
    #[must_use]
    pub const fn max_executions(self) -> usize {
        self.max_executions
    }

    /// Transitions allowed across the whole search.
    #[must_use]
    pub const fn max_transitions(self) -> u64 {
        self.max_transitions
    }

    /// A canonical rendering, for the receipt.
    #[must_use]
    pub fn canonical(self) -> String {
        format!(
            "max_executions={},max_transitions={}",
            self.max_executions, self.max_transitions
        )
    }
}

/// Which bound stopped exploration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BoundHit {
    /// The complete-execution limit was reached.
    Executions,
    /// The transition limit was reached.
    Transitions,
}

impl BoundHit {
    /// Stable machine code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Executions => "max_executions",
            Self::Transitions => "max_transitions",
        }
    }
}

/// A schedule that reproduces a failing property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counterexample {
    property: String,
    detail: String,
    sequence: Vec<OwnedEvent>,
    clocks: Vec<VectorClock>,
    schedule: LabSchedule,
}

impl Counterexample {
    /// The property that failed.
    #[must_use]
    pub fn property(&self) -> &str {
        &self.property
    }

    /// What the check reported.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// The exact event sequence that produced the failure.
    #[must_use]
    pub fn sequence(&self) -> &[OwnedEvent] {
        &self.sequence
    }

    /// The vector clock at each event of the failing execution.
    ///
    /// Parallel to [`sequence`](Self::sequence). These show *why* the
    /// interleaving matters: two events with concurrent clocks could have been
    /// swapped, so a violation that depends on their order is telling you
    /// about a genuine race rather than about one arbitrary serialisation.
    #[must_use]
    pub fn clocks(&self) -> &[VectorClock] {
        &self.clocks
    }

    /// The schedule that replays it.
    ///
    /// This is an ordinary [`LabSchedule`] built with
    /// [`LabSchedule::explicit`], so it feeds the replay path unchanged — the
    /// point of exporting a counterexample is that someone else can run it,
    /// not that it can be admired in a report.
    #[must_use]
    pub const fn schedule(&self) -> &LabSchedule {
        &self.schedule
    }

    /// A canonical, quotable rendering.
    #[must_use]
    pub fn canonical(&self) -> String {
        let steps: Vec<String> = self
            .sequence
            .iter()
            .map(crate::commute::OwnedEvent::canonical)
            .collect();
        format!(
            "fgit-lab-counterexample-v1|property={}|detail={}|steps={}",
            self.property,
            self.detail,
            steps.join(",")
        )
    }
}

/// What exploration found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplorationOutcome {
    /// The whole class space was walked and every execution satisfied the
    /// property.
    ///
    /// Returned **only** when exploration genuinely finished.
    Exhaustive {
        /// Complete executions visited — one per Mazurkiewicz class.
        classes: usize,
        /// Transitions taken across the search.
        transitions: u64,
    },
    /// A property failed. Exploration stops at the first failure so the
    /// counterexample is the shortest-found rather than the last.
    Violation {
        /// The failing schedule and its sequence.
        counterexample: Box<Counterexample>,
        /// Complete executions visited before the failure.
        classes: usize,
        /// Transitions taken before the failure.
        transitions: u64,
    },
    /// A bound was hit before the space was covered.
    ///
    /// This is the honest answer to "did you explore everything": no, and here
    /// is exactly how far it got and which bound stopped it.
    Incomplete {
        /// Which bound stopped it.
        bound: BoundHit,
        /// Complete executions visited.
        classes: usize,
        /// Transitions taken.
        transitions: u64,
    },
}

impl ExplorationOutcome {
    /// Whether the class space was genuinely covered.
    #[must_use]
    pub const fn is_exhaustive(&self) -> bool {
        matches!(self, Self::Exhaustive { .. })
    }

    /// Complete executions visited, whatever the outcome.
    #[must_use]
    pub const fn classes(&self) -> usize {
        match self {
            Self::Exhaustive { classes, .. }
            | Self::Violation { classes, .. }
            | Self::Incomplete { classes, .. } => *classes,
        }
    }

    /// Transitions taken, whatever the outcome.
    #[must_use]
    pub const fn transitions(&self) -> u64 {
        match self {
            Self::Exhaustive { transitions, .. }
            | Self::Violation { transitions, .. }
            | Self::Incomplete { transitions, .. } => *transitions,
        }
    }

    /// The counterexample, if a property failed.
    #[must_use]
    pub fn counterexample(&self) -> Option<&Counterexample> {
        match self {
            Self::Violation { counterexample, .. } => Some(counterexample),
            _ => None,
        }
    }

    /// A canonical receipt line recording what was and was not covered.
    #[must_use]
    pub fn canonical_receipt(&self, budget: ExplorationBudget) -> String {
        let verdict = match self {
            Self::Exhaustive { .. } => "exhaustive".to_owned(),
            Self::Violation { counterexample, .. } => {
                format!("violation:{}", counterexample.property())
            }
            Self::Incomplete { bound, .. } => format!("incomplete:{}", bound.code()),
        };
        format!(
            "fgit-lab-exploration-v1|verdict={}|classes={}|transitions={}|{}",
            verdict,
            self.classes(),
            self.transitions(),
            budget.canonical()
        )
    }
}

/// Compute the vector clock at each event of a complete execution.
///
/// Causality is derived from the conflict relation: an event learns everything
/// known to every earlier event it conflicts with, and nothing from events it
/// commutes with. That makes concurrency in these clocks mean exactly what the
/// explorer means by it — two events with concurrent clocks are two the
/// explorer would have been free to swap.
///
/// Computed from the finished sequence rather than maintained incrementally
/// during the search, because the search backtracks: incremental state would
/// have to be rolled back exactly, and a subtle rollback bug would produce
/// clocks that look plausible and are wrong.
#[must_use]
pub fn causal_clocks(sequence: &[OwnedEvent], relation: ConflictRelation) -> Vec<VectorClock> {
    let mut clocks: Vec<VectorClock> = Vec::with_capacity(sequence.len());
    for (index, event) in sequence.iter().enumerate() {
        let mut clock = VectorClock::new();
        for (earlier_index, earlier) in sequence.iter().enumerate().take(index) {
            if relation.conflicts(event, earlier) {
                clock.merge(&clocks[earlier_index]);
            }
        }
        clock.tick(&event.actor);
        clocks.push(clock);
    }
    clocks
}

/// The sleep-set DPOR explorer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Dpor {
    relation: ConflictRelation,
}

impl Dpor {
    /// An explorer using the declared conflict relation.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            relation: ConflictRelation,
        }
    }

    /// Explore every Mazurkiewicz class of `program`, checking `property` on
    /// each complete execution.
    ///
    /// `property` receives the full executed sequence and returns `Err` with a
    /// description when it does not hold.
    pub fn explore<P>(
        self,
        program: &Program,
        budget: ExplorationBudget,
        property_name: &str,
        mut property: P,
    ) -> ExplorationOutcome
    where
        P: FnMut(&[OwnedEvent]) -> Result<(), String>,
    {
        let mut state = Search {
            program,
            relation: self.relation,
            budget,
            classes: 0,
            transitions: 0,
            counters: program.participants.iter().map(|_| 0_usize).collect(),
            sequence: Vec::new(),
            violation: None,
            bound_hit: None,
            property_name: property_name.to_owned(),
        };
        state.walk(&mut property, &BTreeSet::new());

        if let Some(counterexample) = state.violation {
            return ExplorationOutcome::Violation {
                counterexample: Box::new(counterexample),
                classes: state.classes,
                transitions: state.transitions,
            };
        }
        if let Some(bound) = state.bound_hit {
            return ExplorationOutcome::Incomplete {
                bound,
                classes: state.classes,
                transitions: state.transitions,
            };
        }
        ExplorationOutcome::Exhaustive {
            classes: state.classes,
            transitions: state.transitions,
        }
    }
}

/// Mutable search state, kept out of the public surface.
struct Search<'a> {
    program: &'a Program,
    relation: ConflictRelation,
    budget: ExplorationBudget,
    classes: usize,
    transitions: u64,
    counters: Vec<usize>,
    sequence: Vec<OwnedEvent>,
    violation: Option<Counterexample>,
    bound_hit: Option<BoundHit>,
    property_name: String,
}

impl Search<'_> {
    /// Whether the search must stop.
    fn stopped(&self) -> bool {
        self.violation.is_some() || self.bound_hit.is_some()
    }

    /// The participants whose next event is available, in declared order.
    fn enabled(&self) -> Vec<usize> {
        self.program
            .participants
            .iter()
            .enumerate()
            .filter(|(index, who)| self.program.event_at(who, self.counters[*index]).is_some())
            .map(|(index, _)| index)
            .collect()
    }

    /// The owned event participant `index` would run next.
    fn next_event(&self, index: usize) -> Option<OwnedEvent> {
        let who = &self.program.participants[index];
        self.program
            .event_at(who, self.counters[index])
            .map(|event| OwnedEvent::new(who.clone(), event.clone()))
    }

    /// Walk the state space, pruning Mazurkiewicz-equivalent executions.
    ///
    /// `sleep` holds participants whose next transition has already been
    /// explored from an equivalent state; running one would replay a class
    /// already covered.
    fn walk<P>(&mut self, property: &mut P, sleep: &BTreeSet<usize>)
    where
        P: FnMut(&[OwnedEvent]) -> Result<(), String>,
    {
        if self.stopped() {
            return;
        }

        let enabled = self.enabled();
        let runnable: Vec<usize> = enabled
            .iter()
            .copied()
            .filter(|index| !sleep.contains(index))
            .collect();

        if runnable.is_empty() {
            // A maximal execution under this sleep set. Only count it as a
            // class when nothing is left at all; a run blocked purely by the
            // sleep set is a pruned duplicate, not a distinct class.
            if enabled.is_empty() {
                self.record_execution(property);
            }
            return;
        }

        let mut done: BTreeSet<usize> = BTreeSet::new();
        for index in runnable {
            if self.stopped() {
                return;
            }
            if self.transitions >= self.budget.max_transitions() {
                self.bound_hit = Some(BoundHit::Transitions);
                return;
            }

            let Some(event) = self.next_event(index) else {
                continue;
            };

            // The child's sleep set keeps everything already slept on or
            // already done here that is independent of the transition being
            // taken: those remain redundant after it runs. Anything dependent
            // wakes, because running it after this transition is a genuinely
            // different execution.
            let child_sleep: BTreeSet<usize> = sleep
                .iter()
                .chain(done.iter())
                .copied()
                .filter(|other| {
                    self.next_event(*other)
                        .is_none_or(|other_event| self.relation.independent(&event, &other_event))
                })
                .collect();

            self.apply(index, &event);
            self.walk(property, &child_sleep);
            self.undo(index);

            done.insert(index);
        }
    }

    /// Execute a transition.
    fn apply(&mut self, index: usize, event: &OwnedEvent) {
        self.counters[index] += 1;
        self.sequence.push(event.clone());
        self.transitions = self.transitions.saturating_add(1);
    }

    /// Undo the most recent transition.
    fn undo(&mut self, index: usize) {
        self.counters[index] -= 1;
        self.sequence.pop();
    }

    /// Record a complete execution and check the property.
    fn record_execution<P>(&mut self, property: &mut P)
    where
        P: FnMut(&[OwnedEvent]) -> Result<(), String>,
    {
        if self.classes >= self.budget.max_executions() {
            self.bound_hit = Some(BoundHit::Executions);
            return;
        }
        self.classes += 1;

        if let Err(detail) = property(&self.sequence) {
            let order: Vec<StepId> = self
                .sequence
                .iter()
                .map(|owned| owned.actor.clone())
                .collect();
            let clocks = causal_clocks(&self.sequence, self.relation);
            // The exported schedule is an ordinary explicit LabSchedule, so
            // the replay path consumes it with no special case.
            if let Ok(schedule) = LabSchedule::explicit(self.program.participants.to_vec(), order) {
                self.violation = Some(Counterexample {
                    property: self.property_name.clone(),
                    detail,
                    sequence: self.sequence.clone(),
                    clocks,
                    schedule,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn who(name: &str) -> StepId {
        StepId::new(name)
    }

    fn cas(key: &str) -> ProtocolEvent {
        ProtocolEvent::CompareExchangeHead {
            key: key.to_owned(),
        }
    }

    fn read_head(key: &str) -> ProtocolEvent {
        ProtocolEvent::ReadHead {
            key: key.to_owned(),
        }
    }

    fn body(key: &str) -> ProtocolEvent {
        ProtocolEvent::BodyWrite {
            key: key.to_owned(),
        }
    }

    fn always_holds(_: &[OwnedEvent]) -> Result<(), String> {
        Ok(())
    }

    const GENEROUS: ExplorationBudget = ExplorationBudget::new(10_000, 1_000_000);

    #[test]
    fn fully_independent_participants_collapse_to_one_class() {
        // Two participants, one event each, on different keys. Every
        // interleaving is Mazurkiewicz-equivalent, so exactly one class.
        // Hand-countable golden: 1.
        let program = Program::new(vec![
            (who("a"), vec![body("blob/1")]),
            (who("b"), vec![body("blob/2")]),
        ])
        .expect("valid program");

        let outcome = Dpor::new().explore(&program, GENEROUS, "trivial", always_holds);
        assert!(outcome.is_exhaustive());
        assert_eq!(outcome.classes(), 1);
    }

    #[test]
    fn fully_dependent_participants_give_one_class_per_ordering() {
        // Two participants, one CAS each on the SAME key: they conflict, so
        // the two orderings are distinct classes. Golden: 2.
        let program = Program::new(vec![
            (who("a"), vec![cas("main")]),
            (who("b"), vec![cas("main")]),
        ])
        .expect("valid program");

        let outcome = Dpor::new().explore(&program, GENEROUS, "trivial", always_holds);
        assert!(outcome.is_exhaustive());
        assert_eq!(outcome.classes(), 2);
    }

    #[test]
    fn three_dependent_singletons_give_six_classes() {
        // Three mutually conflicting events: 3! = 6 orderings, all distinct.
        let program = Program::new(vec![
            (who("a"), vec![cas("main")]),
            (who("b"), vec![cas("main")]),
            (who("c"), vec![cas("main")]),
        ])
        .expect("valid program");

        let outcome = Dpor::new().explore(&program, GENEROUS, "trivial", always_holds);
        assert!(outcome.is_exhaustive());
        assert_eq!(outcome.classes(), 6);
    }

    #[test]
    fn independence_reduces_the_space_it_would_otherwise_explore() {
        // Three participants on three DIFFERENT keys: 3! = 6 interleavings but
        // all equivalent, so 1 class. This is the reduction actually working —
        // without it the count would be 6.
        let program = Program::new(vec![
            (who("a"), vec![body("blob/1")]),
            (who("b"), vec![body("blob/2")]),
            (who("c"), vec![body("blob/3")]),
        ])
        .expect("valid program");

        let outcome = Dpor::new().explore(&program, GENEROUS, "trivial", always_holds);
        assert!(outcome.is_exhaustive());
        assert_eq!(outcome.classes(), 1);
    }

    #[test]
    fn a_read_write_pair_on_one_key_is_two_classes() {
        // The read observes one side of the write, so both orders matter.
        let program = Program::new(vec![
            (who("reader"), vec![read_head("main")]),
            (who("writer"), vec![cas("main")]),
        ])
        .expect("valid program");

        let outcome = Dpor::new().explore(&program, GENEROUS, "trivial", always_holds);
        assert_eq!(outcome.classes(), 2);

        // Paired independent case: two reads commute, so one class.
        let readers = Program::new(vec![
            (who("r1"), vec![read_head("main")]),
            (who("r2"), vec![read_head("main")]),
        ])
        .expect("valid program");
        assert_eq!(
            Dpor::new()
                .explore(&readers, GENEROUS, "trivial", always_holds)
                .classes(),
            1
        );
    }

    #[test]
    fn program_order_within_a_participant_is_never_reordered() {
        // One participant with two events: exactly one execution, and it must
        // be in program order.
        let program = Program::new(vec![(who("a"), vec![body("blob/1"), cas("main")])])
            .expect("valid program");

        let mut seen: Vec<String> = Vec::new();
        let outcome = Dpor::new().explore(&program, GENEROUS, "order", |sequence| {
            seen = sequence
                .iter()
                .map(crate::commute::OwnedEvent::canonical)
                .collect();
            Ok(())
        });
        assert_eq!(outcome.classes(), 1);
        assert_eq!(seen, vec!["body_write:blob/1@a", "cas:main@a"]);
    }

    #[test]
    fn exploration_order_is_deterministic() {
        let program = Program::new(vec![
            (who("a"), vec![cas("main")]),
            (who("b"), vec![cas("main")]),
            (who("c"), vec![read_head("main")]),
        ])
        .expect("valid program");

        let collect = || {
            let mut orders: Vec<String> = Vec::new();
            Dpor::new().explore(&program, GENEROUS, "order", |sequence| {
                orders.push(
                    sequence
                        .iter()
                        .map(crate::commute::OwnedEvent::canonical)
                        .collect::<Vec<_>>()
                        .join(","),
                );
                Ok(())
            });
            orders
        };

        let first = collect();
        for _ in 0..8 {
            assert_eq!(collect(), first, "exploration order must be deterministic");
        }
        // Every visited execution is distinct — no class visited twice.
        let mut sorted = first.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), first.len(), "a class was explored twice");
    }

    #[test]
    fn a_seeded_race_is_found_and_its_schedule_replays() {
        // The planted bug: two writers each read the head then CAS it. The
        // violating class is the one where both reads precede both CASes —
        // lost update. It is reachable only in specific interleavings, which
        // is exactly what exploration is for.
        let program = Program::new(vec![
            (who("w1"), vec![read_head("main"), cas("main")]),
            (who("w2"), vec![read_head("main"), cas("main")]),
        ])
        .expect("valid program");

        let outcome = Dpor::new().explore(&program, GENEROUS, "no_lost_update", |sequence| {
            // Reconstruct: did a writer read before the other's CAS and then
            // CAS itself? That is a lost update.
            let mut read_before_any_cas = 0;
            let mut seen_cas = false;
            for owned in sequence {
                match owned.event {
                    ProtocolEvent::ReadHead { .. } if !seen_cas => read_before_any_cas += 1,
                    ProtocolEvent::CompareExchangeHead { .. } => seen_cas = true,
                    _ => {}
                }
            }
            if read_before_any_cas >= 2 {
                return Err("both writers read the head before either committed".to_owned());
            }
            Ok(())
        });

        let counterexample = outcome
            .counterexample()
            .expect("the lost-update interleaving must be found");
        assert_eq!(counterexample.property(), "no_lost_update");
        assert!(counterexample.detail().contains("before either committed"));

        // The exported schedule is an ordinary explicit LabSchedule, so the
        // replay path takes it unchanged.
        let schedule = counterexample.schedule();
        assert_eq!(schedule.len(), 4);
        assert_eq!(schedule.participants().len(), 2);
        for step in schedule.order() {
            assert!(schedule.participants().contains(step));
        }
        // And it is quotable, which is what makes it reproducible elsewhere.
        assert!(schedule.canonical_line().contains("fgit-lab-schedule-v1"));
        assert!(counterexample.canonical().contains("no_lost_update"));
    }

    #[test]
    fn a_property_that_holds_everywhere_yields_exhaustive() {
        let program = Program::new(vec![
            (who("a"), vec![cas("main")]),
            (who("b"), vec![cas("main")]),
        ])
        .expect("valid program");

        let outcome = Dpor::new().explore(&program, GENEROUS, "always", always_holds);
        assert!(outcome.is_exhaustive());
        assert!(outcome.counterexample().is_none());
        assert!(
            outcome
                .canonical_receipt(GENEROUS)
                .contains("verdict=exhaustive")
        );
    }

    #[test]
    fn hitting_the_execution_bound_reports_incomplete_not_exhaustive() {
        // The acceptance line: never claim "all schedules explored" unless it
        // is true. Six classes exist; allow two.
        let program = Program::new(vec![
            (who("a"), vec![cas("main")]),
            (who("b"), vec![cas("main")]),
            (who("c"), vec![cas("main")]),
        ])
        .expect("valid program");

        let budget = ExplorationBudget::new(2, 1_000_000);
        let outcome = Dpor::new().explore(&program, budget, "trivial", always_holds);

        assert!(!outcome.is_exhaustive());
        match outcome {
            ExplorationOutcome::Incomplete { bound, classes, .. } => {
                assert_eq!(bound, BoundHit::Executions);
                assert_eq!(classes, 2);
            }
            other => panic!("expected Incomplete, got {other:?}"),
        }

        // Paired permitted case: a budget that covers the space is exhaustive.
        let generous = Dpor::new().explore(&program, GENEROUS, "trivial", always_holds);
        assert!(generous.is_exhaustive());
        assert_eq!(generous.classes(), 6);
    }

    #[test]
    fn hitting_the_transition_bound_reports_incomplete() {
        let program = Program::new(vec![
            (who("a"), vec![cas("main"), cas("main")]),
            (who("b"), vec![cas("main"), cas("main")]),
        ])
        .expect("valid program");

        let budget = ExplorationBudget::new(10_000, 3);
        let outcome = Dpor::new().explore(&program, budget, "trivial", always_holds);

        match outcome {
            ExplorationOutcome::Incomplete { bound, .. } => {
                assert_eq!(bound, BoundHit::Transitions);
            }
            other => panic!("expected Incomplete, got {other:?}"),
        }
        assert!(
            outcome
                .canonical_receipt(budget)
                .contains("verdict=incomplete:max_transitions")
        );
    }

    #[test]
    fn the_receipt_records_the_bounds_that_were_in_force() {
        // Bounds recorded in the receipt is an acceptance requirement: a
        // coverage number means nothing without the budget it ran under.
        let program = Program::new(vec![(who("a"), vec![cas("main")])]).expect("valid");
        let budget = ExplorationBudget::new(5, 50);
        let receipt = Dpor::new()
            .explore(&program, budget, "trivial", always_holds)
            .canonical_receipt(budget);

        assert!(receipt.starts_with("fgit-lab-exploration-v1"));
        assert!(receipt.contains("classes=1"));
        assert!(receipt.contains("max_executions=5"));
        assert!(receipt.contains("max_transitions=50"));
    }

    #[test]
    fn a_duplicate_participant_is_refused() {
        let refusal = Program::new(vec![
            (who("a"), vec![cas("main")]),
            (who("a"), vec![cas("other")]),
        ])
        .expect_err("a participant may be declared once");
        assert_eq!(
            refusal,
            LabRefusal::UnknownParticipant {
                name: "a".to_owned()
            }
        );

        // Paired permitted case: distinct names.
        Program::new(vec![
            (who("a"), vec![cas("main")]),
            (who("b"), vec![cas("other")]),
        ])
        .expect("distinct participants are permitted");
    }

    #[test]
    fn an_empty_program_has_exactly_one_empty_execution() {
        let program = Program::new(vec![]).expect("an empty program is valid");
        assert_eq!(program.total_events(), 0);
        let outcome = Dpor::new().explore(&program, GENEROUS, "trivial", always_holds);
        assert!(outcome.is_exhaustive());
        assert_eq!(outcome.classes(), 1);
        assert_eq!(outcome.transitions(), 0);
    }

    #[test]
    fn causal_clocks_mark_conflicting_events_as_ordered() {
        // Two CASes on one key conflict, so the second must learn the first:
        // its clock strictly follows.
        let sequence = vec![
            OwnedEvent::new(who("a"), cas("main")),
            OwnedEvent::new(who("b"), cas("main")),
        ];
        let clocks = causal_clocks(&sequence, ConflictRelation);
        assert_eq!(clocks.len(), 2);
        assert!(clocks[0].happens_before(&clocks[1]));
        assert!(!clocks[0].concurrent_with(&clocks[1]));
    }

    #[test]
    fn causal_clocks_mark_independent_events_as_concurrent() {
        // Different keys commute, so neither event learns the other and the
        // explorer was free to swap them. That freedom is exactly what the
        // clocks have to show.
        let sequence = vec![
            OwnedEvent::new(who("a"), body("blob/1")),
            OwnedEvent::new(who("b"), body("blob/2")),
        ];
        let clocks = causal_clocks(&sequence, ConflictRelation);
        assert!(clocks[0].concurrent_with(&clocks[1]));
        assert!(!clocks[0].happens_before(&clocks[1]));
    }

    #[test]
    fn causality_is_transitive_through_a_conflicting_middle_event() {
        // a and c touch different keys, so they never conflict directly — but
        // b conflicts with both, so a must still precede c.
        let sequence = vec![
            OwnedEvent::new(who("a"), body("blob/1")),
            OwnedEvent::new(who("b"), body("blob/1")),
            OwnedEvent::new(who("b"), body("blob/2")),
            OwnedEvent::new(who("c"), body("blob/2")),
        ];
        let clocks = causal_clocks(&sequence, ConflictRelation);
        assert!(clocks[0].happens_before(&clocks[1]));
        assert!(clocks[1].happens_before(&clocks[3]));
        assert!(
            clocks[0].happens_before(&clocks[3]),
            "causality must carry through the shared middle event"
        );
    }

    #[test]
    fn a_participants_own_events_are_always_ordered_by_its_clock() {
        let sequence = vec![
            OwnedEvent::new(who("a"), body("blob/1")),
            OwnedEvent::new(who("a"), body("blob/2")),
        ];
        let clocks = causal_clocks(&sequence, ConflictRelation);
        // Program order is absolute even across unrelated keys.
        assert!(clocks[0].happens_before(&clocks[1]));
        assert_eq!(clocks[1].get(&who("a")), 2);
    }

    #[test]
    fn causal_clocks_are_deterministic_and_stable() {
        let sequence = vec![
            OwnedEvent::new(who("a"), read_head("main")),
            OwnedEvent::new(who("b"), read_head("main")),
            OwnedEvent::new(who("a"), cas("main")),
        ];
        let first: Vec<String> = causal_clocks(&sequence, ConflictRelation)
            .iter()
            .map(VectorClock::canonical)
            .collect();
        for _ in 0..8 {
            let again: Vec<String> = causal_clocks(&sequence, ConflictRelation)
                .iter()
                .map(VectorClock::canonical)
                .collect();
            assert_eq!(again, first);
        }
        // The two reads commute; the CAS conflicts with both.
        let clocks = causal_clocks(&sequence, ConflictRelation);
        assert!(clocks[0].concurrent_with(&clocks[1]));
        assert!(clocks[1].happens_before(&clocks[2]));
    }

    #[test]
    fn an_empty_execution_has_no_clocks() {
        assert!(causal_clocks(&[], ConflictRelation).is_empty());
    }

    #[test]
    fn a_counterexample_carries_a_clock_per_event() {
        let program = Program::new(vec![
            (who("a"), vec![cas("main")]),
            (who("b"), vec![cas("main")]),
        ])
        .expect("valid program");

        let outcome = Dpor::new().explore(&program, GENEROUS, "never", |_| {
            Err("always fails".to_owned())
        });
        let counterexample = outcome.counterexample().expect("a violation");
        assert_eq!(
            counterexample.clocks().len(),
            counterexample.sequence().len(),
            "every event in a counterexample carries its clock"
        );
    }

    #[test]
    fn exploration_stops_at_the_first_violation() {
        // Stopping early keeps the counterexample the first one found rather
        // than the last, which makes it the most reproducible.
        let program = Program::new(vec![
            (who("a"), vec![cas("main")]),
            (who("b"), vec![cas("main")]),
            (who("c"), vec![cas("main")]),
        ])
        .expect("valid program");

        let outcome = Dpor::new().explore(&program, GENEROUS, "never", |_| {
            Err("this property never holds".to_owned())
        });
        assert_eq!(outcome.classes(), 1, "must stop at the first failure");
        assert!(outcome.counterexample().is_some());
        assert!(!outcome.is_exhaustive());
    }
}
