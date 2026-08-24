//! Contending cells under lab schedules, with one of them partitioned.
//!
//! `frankengit-fg036b`. This is the intersection two existing suites leave open,
//! and only the intersection — neither is re-derived here:
//!
//! * `dpor_authority.rs` explores interleavings of two contending writers, but
//!   with `HazardScript::none()`. No faults.
//! * `composed_campaign.rs` composes every fault class with a schedule, but
//!   asserts fault composition, replay determinism and trace shape — not a
//!   client-visible invariant.
//!
//! What is missing is a *cell* invariant under interleaving *and* fault: two
//! cells racing to publish while one of them cannot reach the authority. That is
//! the partition case fg036b names, and the schedule is what makes it more than
//! one lucky ordering.
//!
//! # The invariant, and why it is the right one
//!
//! `claimed == advanced`: the number of publications a cell believes it made
//! must equal how far the head actually moved. It is the same invariant
//! `dpor_authority` uses, deliberately, because it is the one that catches both
//! directions of the interesting failure — a cell that claims a commit it did
//! not make (a lost update presented as success) and a head that moved without
//! any cell claiming it (an acknowledged write nobody owns).
//!
//! A partition must not be able to break it. Losing reachability may cost a cell
//! its turn; it must never cost the system a write or manufacture one.
//!
//! # What an isolated cell does here
//!
//! Nothing, and that is the point. Its `ReadHead` returns `Ambiguous`, so it
//! holds no token, so it issues no compare-exchange and claims nothing. A cell
//! that cannot authenticate the head does not get to publish against it — §5.1
//! is that only a conditional replacement of the exact predecessor publishes,
//! and a cell with no predecessor token has nothing to condition on.

use std::cell::RefCell;
use std::rc::Rc;

use fgit_authority::HeadReadReceipt;
use fgit_authority::history::{
    ClientId as HistoryClientId, HistoryEvent, LogicalTime, OperationId,
};
use fgit_authority::lincheck::{
    AuthorityHistory, AuthorityReferenceSpec, CheckLimits, CheckReport, CheckVerdict,
    LinearizabilityChecker,
};
use fgit_authority::{
    AuthorityClient, AuthorityOp, AuthorityResponse, AuthorityStore, AuthorityVersionToken,
    CasOutcome, FaultDirective, FaultKind, FaultPlan, FaultableAuthorityStore, HeadGeneration,
    HeadInit, HeadKey, HeadRead, MemoryAuthorityStore, OpIndex, StoreInstanceId,
};
use fgit_lab::journal::TraceEvent;
use fgit_lab::{AuthorityCampaign, HazardScript, LabSchedule, LabTime, StepId, VirtualClock};

use std::collections::BTreeMap;

const HEAD: &str = "repo/multicell";

fn head_key() -> HeadKey {
    HeadKey::new(HEAD.as_bytes().to_vec()).expect("key is within bounds")
}

fn generation(value: u64) -> HeadGeneration {
    HeadGeneration::try_new(value).expect("a positive generation is valid")
}

/// The client-visible history of one campaign, in the form the checker wants.
///
/// The campaign's `CampaignOutcome` reports FINAL state -- its own docs say so --
/// which is why the invariant here was `claimed == advanced` and nothing more.
/// A linearizability check needs the per-operation record instead, and the two
/// `AuthorityClient` hooks are exactly where it can be taken: `drive` calls
/// `next_op`, executes, then `observe`, strictly paired.
#[derive(Default)]
struct CampaignHistory {
    events: Vec<HistoryEvent<AuthorityOp, AuthorityResponse>>,
    next_operation_id: u64,
    next_time_by_client: BTreeMap<u64, u64>,
}

impl CampaignHistory {
    fn next_time(&mut self, client: u64) -> LogicalTime {
        let time = self.next_time_by_client.entry(client).or_insert(0);
        *time = time.saturating_add(1);
        LogicalTime(*time)
    }

    fn invoke(&mut self, client: u64, operation: AuthorityOp) -> OperationId {
        self.next_operation_id = self.next_operation_id.saturating_add(1);
        let operation_id = OperationId(self.next_operation_id);
        let logical_time = self.next_time(client);
        self.events.push(HistoryEvent::invocation(
            HistoryClientId(client),
            logical_time,
            operation_id,
            operation,
        ));
        operation_id
    }

    /// Records a response -- UNLESS it is ambiguous.
    ///
    /// An ambiguous result is not a response, and recording it as one would ask
    /// the sequential model to produce `Ambiguous`, which no sequential model
    /// can: the check would fail for a reason that is not a violation. Leaving
    /// the invocation unanswered is the correct encoding, and it is the one the
    /// checker is built for -- a pending operation is explored as both
    /// effectful and absent. That is also §5.2 stated in the history: a lost
    /// response proves neither commit nor non-commit.
    fn respond(&mut self, client: u64, operation_id: OperationId, response: AuthorityResponse) {
        if matches!(response, AuthorityResponse::Ambiguous(_)) {
            return;
        }
        let logical_time = self.next_time(client);
        self.events.push(HistoryEvent::response(
            HistoryClientId(client),
            logical_time,
            operation_id,
            response,
        ));
    }

    fn history(&self) -> AuthorityHistory {
        AuthorityHistory::new(self.events.clone()).expect("the campaign records a valid history")
    }
}

/// A cell that reads the head, then publishes against exactly what it read.
///
/// It claims a publication only on `Committed`. `PredecessorMismatch` means it
/// lost and claims nothing; `Ambiguous` means it does not know and claims
/// nothing, which is the honest reading — §5.2 says a disconnect never proves
/// non-commit, and it equally never proves commit.
struct CellClient {
    body: Vec<u8>,
    step: usize,
    token: Option<AuthorityVersionToken>,
    claimed: Rc<RefCell<usize>>,
    client_id: u64,
    history: Rc<RefCell<CampaignHistory>>,
    pending: Option<OperationId>,
}

impl CellClient {
    fn new(
        body: &str,
        claimed: Rc<RefCell<usize>>,
        client_id: u64,
        history: Rc<RefCell<CampaignHistory>>,
    ) -> Self {
        Self {
            body: body.as_bytes().to_vec(),
            step: 0,
            token: None,
            claimed,
            client_id,
            history,
            pending: None,
        }
    }
}

impl AuthorityClient for CellClient {
    fn next_op(&mut self) -> Option<AuthorityOp> {
        let op = match self.step {
            0 => Some(AuthorityOp::ReadHead { key: head_key() }),
            1 => self
                .token
                .as_ref()
                .map(|token| AuthorityOp::CompareExchangeHead {
                    key: head_key(),
                    expected: *token,
                    new_generation: generation(2),
                    new_body: self.body.clone(),
                }),
            _ => None,
        };
        self.step = self.step.saturating_add(1);
        if let Some(operation) = op.clone() {
            self.pending = Some(self.history.borrow_mut().invoke(self.client_id, operation));
        }
        op
    }

    fn observe(&mut self, response: &AuthorityResponse) {
        if let Some(operation_id) = self.pending.take() {
            self.history
                .borrow_mut()
                .respond(self.client_id, operation_id, response.clone());
        }
        match response {
            AuthorityResponse::ReadHead(HeadRead::Present(receipt)) => {
                self.token = Some(receipt.token());
            }
            AuthorityResponse::CompareExchangeHead(CasOutcome::Committed(_)) => {
                *self.claimed.borrow_mut() += 1;
            }
            // Ambiguous and PredecessorMismatch both fall here and both claim
            // nothing: a lost response does not prove commit any more than it
            // proves non-commit, and a lost read leaves no token to publish
            // against at all.
            _ => {}
        }
    }
}

/// Isolate ONE cell: drop a single `ReadHead`, so one cell never gets a token
/// and the other proceeds normally.
///
/// `FaultDirective::new(at, kind)` targets ONE position, not a class over time.
/// I first wrote this expecting it to drop every read and asserted the head could
/// not move; the head advanced by one, because the second cell's read arrived
/// fine. The API was right and the assumption was mine. Use `nth_of_kind` per
/// occurrence for a sustained outage -- see `partition_every_read`.
fn isolate_one_cell() -> HazardScript {
    let plan = FaultPlan::explicit(vec![
        FaultDirective::new(OpIndex::ZERO, FaultKind::LoseRequest)
            .only_for(fgit_authority::AuthorityOpKind::ReadHead),
    ]);
    HazardScript::explicit(plan, Vec::new())
}

/// Isolate BOTH cells: one directive per `ReadHead` occurrence, so no cell ever
/// holds a predecessor token.
fn partition_every_read() -> HazardScript {
    let plan = FaultPlan::explicit(vec![
        FaultDirective::nth_of_kind(
            0,
            fgit_authority::AuthorityOpKind::ReadHead,
            FaultKind::LoseRequest,
        ),
        FaultDirective::nth_of_kind(
            1,
            fgit_authority::AuthorityOpKind::ReadHead,
            FaultKind::LoseRequest,
        ),
    ]);
    HazardScript::explicit(plan, Vec::new())
}

/// Every schedule this test runs the two cells through.
///
/// Named rather than seeded so a failure says which ordering broke, and so the
/// serialised and both-read-first shapes are guaranteed present instead of hoped
/// for — those are the two orderings that behave differently, and a purely
/// seeded schedule set might contain only one of them.
fn schedules() -> Vec<(&'static str, LabSchedule)> {
    let cells = vec![StepId::new("cell-a"), StepId::new("cell-b")];
    let a = StepId::new("cell-a");
    let b = StepId::new("cell-b");
    vec![
        (
            "round-robin",
            LabSchedule::round_robin(cells.clone(), 2).expect("valid"),
        ),
        (
            "serialised-a-then-b",
            LabSchedule::explicit(
                cells.clone(),
                vec![a.clone(), a.clone(), b.clone(), b.clone()],
            )
            .expect("valid"),
        ),
        (
            "both-read-first",
            LabSchedule::explicit(cells.clone(), vec![a.clone(), b.clone(), a, b]).expect("valid"),
        ),
        (
            "seeded",
            LabSchedule::seeded(cells, 4, 0xF036_B006).expect("valid"),
        ),
    ]
}

/// Run both cells under one schedule and hazard script, returning
/// `(claimed, advanced, injected_faults)`.
///
/// The fault count comes from the campaign outcome rather than being discarded.
/// It is what proves the hazard script was ACTIVE in this particular schedule --
/// without it, a fault arm that silently injected nothing would satisfy every
/// invariant below by simply being the no-fault arm again.
fn run(
    schedule: &LabSchedule,
    hazards: &HazardScript,
    instance: u64,
) -> (usize, u64, usize, CheckReport) {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(instance));
    let base = match store
        .initialize_head(&head_key(), HeadGeneration::FIRST, b"root")
        .expect("seeding the head succeeds")
    {
        HeadInit::Created(receipt) | HeadInit::IdenticalRetry(receipt) => {
            receipt.generation().get()
        }
        HeadInit::Conflict => panic!("the head already existed"),
    };

    let claimed = Rc::new(RefCell::new(0_usize));
    let history = Rc::new(RefCell::new(CampaignHistory::default()));
    let mut cells: Vec<Box<dyn AuthorityClient>> = vec![
        Box::new(CellClient::new(
            "published-by-a",
            Rc::clone(&claimed),
            0,
            Rc::clone(&history),
        )),
        Box::new(CellClient::new(
            "published-by-b",
            Rc::clone(&claimed),
            1,
            Rc::clone(&history),
        )),
    ];

    let outcome = AuthorityCampaign::new(StoreInstanceId::from_raw(instance))
        .run_on(&store, &mut cells, schedule, hazards);

    let final_generation = match store.read_head(&head_key()).expect("final read succeeds") {
        HeadRead::Present(receipt) => receipt.generation().get(),
        HeadRead::Absent => panic!("the head vanished"),
    };
    let model = AuthorityReferenceSpec::with_initial_head(
        StoreInstanceId::from_raw(instance),
        head_key(),
        HeadGeneration::FIRST,
        b"root".to_vec(),
    );
    let report = LinearizabilityChecker::new(CheckLimits {
        max_completed_operations: 16,
        max_search_nodes: 100_000,
    })
    .expect("the cell checker limits are valid")
    .check_authority(&model, &history.borrow().history());

    (
        *claimed.borrow(),
        final_generation.saturating_sub(base),
        outcome.injected_faults(),
        report,
    )
}

/// Assert the campaign's recorded history linearizes, and that the check was
/// not vacuous.
///
/// The completed-operation count is the load-bearing second half. An empty
/// history linearizes trivially, so without it a recorder that silently stopped
/// recording would read as a clean pass in every arm.
fn expect_linearizable(name: &str, report: &CheckReport) {
    assert!(
        matches!(&report.verdict, CheckVerdict::Linearizable { .. }),
        "{name}: the cell campaign did not linearize: {report:?}"
    );
}

/// The verdict PLUS the evidence that the check had something to chew on.
///
/// An empty history linearizes trivially, so a recorder that silently stopped
/// recording would read as a clean pass in every arm. Kept separate from
/// [`expect_linearizable`] because under a total partition there are genuinely
/// no completed operations -- see the partition arm, which asserts the
/// complementary fact instead.
fn expect_linearizable_over_real_work(name: &str, report: &CheckReport) {
    expect_linearizable(name, report);
    assert!(
        report.completed_operations != 0,
        "{name}: the checker saw no completed operations, so it proved nothing"
    );
}

#[test]
fn contending_cells_hold_the_publication_invariant_under_every_schedule() {
    // The no-fault arm. Two cells race; whatever the ordering, the number of
    // publications claimed must equal how far the head moved.
    for (name, schedule) in schedules() {
        let (claimed, advanced, injected, report) =
            run(&schedule, &HazardScript::none(), 0xF036_B010);
        assert_eq!(
            injected, 0,
            "{name}: the no-fault arm must inject nothing, or it is not a control"
        );
        expect_linearizable_over_real_work(name, &report);
        assert_eq!(
            u64::try_from(claimed).unwrap_or(u64::MAX),
            advanced,
            "{name}: cells claimed {claimed} publications while the head advanced {advanced}"
        );
        assert!(
            advanced <= 1,
            "{name}: both cells target generation 2, so at most one can win; head advanced {advanced}"
        );
    }
}

#[test]
fn one_isolated_cell_does_not_stop_the_other_from_publishing() {
    // The asymmetric case, and the realistic one: a single cell loses
    // reachability while the survivor carries on.
    //
    // WHAT IS UNIVERSAL AND WHAT IS NOT. The invariant holds under every
    // schedule. "The survivor publishes" does NOT: a schedule that never gives
    // the surviving cell its second turn produces no publication, and the seeded
    // order is one such. I first asserted `advanced == 1` for every schedule and
    // it failed there -- correctly. Asserting a schedule-dependent outcome as
    // universal is how a test starts demanding a particular interleaving instead
    // of a property.
    let mut published_somewhere = 0_u64;
    for (name, schedule) in schedules() {
        let (claimed, advanced, injected, report) =
            run(&schedule, &isolate_one_cell(), 0xF036_B011);
        assert!(
            injected >= 1,
            "{name}: the isolation must actually fire in this schedule, injected {injected}"
        );
        expect_linearizable_over_real_work(name, &report);
        assert_eq!(
            u64::try_from(claimed).unwrap_or(u64::MAX),
            advanced,
            "{name}: isolating one cell must not break the publication invariant \
             (claimed {claimed}, advanced {advanced})"
        );
        assert!(
            advanced <= 1,
            "{name}: only one cell can win generation 2 -- advanced {advanced}"
        );
        published_somewhere = published_somewhere.saturating_add(advanced);
    }

    // The aggregate that carries the actual claim: isolating one cell costs the
    // system a candidate, not a write. If no schedule published, isolation would
    // be indistinguishable from a total outage.
    assert!(
        published_somewhere > 0,
        "some schedule must let the reachable cell publish, or one cell's isolation \
         has silently stopped the whole system"
    );
}

#[test]
fn a_total_partition_costs_a_turn_and_never_a_write() {
    // Every cell isolated. With no predecessor token anywhere, §5.1 leaves
    // nothing to condition a replacement on, so the head must not move at all --
    // and crucially no cell may claim it did.
    for (name, schedule) in schedules() {
        let (claimed, advanced, injected, report) =
            run(&schedule, &partition_every_read(), 0xF036_B014);
        assert!(
            injected >= 1,
            "{name}: the total partition must actually fire, injected {injected}"
        );
        expect_linearizable(name, &report);
        // The complement of the completed-operations check the other two arms
        // make. Under a TOTAL partition every read is dropped, so nothing
        // completes and the history is entirely pending -- which linearizes
        // trivially. Demanding completed work here would be demanding the
        // partition not happen. What must be true instead is that the
        // operations were issued and left unanswered: that is what a partition
        // IS, and an empty history (a recorder that stopped recording) fails it.
        assert!(
            !report.pending_operations.is_empty(),
            "{name}: a total partition must leave operations unanswered, not leave no trace"
        );
        assert_eq!(
            report.completed_operations, 0,
            "{name}: with every read dropped nothing may complete, yet {} did",
            report.completed_operations
        );
        assert_eq!(
            u64::try_from(claimed).unwrap_or(u64::MAX),
            advanced,
            "{name}: a total partition must not break the publication invariant \
             (claimed {claimed}, advanced {advanced})"
        );
        assert_eq!(
            advanced, 0,
            "{name}: with every read dropped no cell holds a token, so nothing may publish \
             -- head advanced {advanced}"
        );
        assert_eq!(
            claimed, 0,
            "{name}: and no cell may claim a publication it could not have made"
        );
    }
}

#[test]
fn the_partition_is_what_changes_the_outcome_not_the_schedule() {
    // The differential, and the guard against both tests above passing for the
    // wrong reason. If the no-fault arm also published nothing, "advanced == 0"
    // under partition would be measuring the fixture rather than the partition.
    let mut healthy_published = 0_u64;
    for (_, schedule) in schedules() {
        let (_, advanced, _, _) = run(&schedule, &HazardScript::none(), 0xF036_B012);
        healthy_published = healthy_published.saturating_add(advanced);
    }
    assert!(
        healthy_published > 0,
        "the unpartitioned arm must publish something, or the partitioned arm's zero \
         proves nothing about partitions"
    );

    // And the invariant is not merely 0 == 0 in the fault arm: the cells did run
    // and did observe their isolation. A campaign that skipped both cells
    // entirely would also report claimed == advanced == 0.
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0xF036_B013));
    store
        .initialize_head(&head_key(), HeadGeneration::FIRST, b"root")
        .expect("seeding succeeds");
    store.install_fault_plan(FaultPlan::explicit(vec![
        FaultDirective::new(OpIndex::ZERO, FaultKind::LoseRequest)
            .only_for(fgit_authority::AuthorityOpKind::ReadHead),
    ]));
    let dropped = store.execute(&AuthorityOp::ReadHead { key: head_key() });
    assert!(
        matches!(dropped, AuthorityResponse::Ambiguous(_)),
        "the partition plan must actually drop a read, got {dropped:?}"
    );
    assert!(
        !store.fault_log().is_empty(),
        "and it must be recorded in the fault log"
    );
}

/// Run one schedule at a chosen virtual-clock rate, returning the instants the
/// run passed through and the head it ended on.
///
/// `with_ticks_per_op` is the injection point: logical time in the lab advances
/// because a step advanced it, never because a wall clock moved, so changing
/// the rate genuinely changes every instant in the run without changing the
/// operations.
fn run_at_tick_rate(
    schedule: &LabSchedule,
    ticks_per_op: u64,
    instance: u64,
) -> (Vec<LabTime>, Option<HeadReadReceipt>) {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(instance));
    store
        .initialize_head(&head_key(), HeadGeneration::FIRST, b"root")
        .expect("seeding the head succeeds");

    let claimed = Rc::new(RefCell::new(0_usize));
    let history = Rc::new(RefCell::new(CampaignHistory::default()));
    let mut cells: Vec<Box<dyn AuthorityClient>> = vec![
        Box::new(CellClient::new(
            "published-by-a",
            Rc::clone(&claimed),
            0,
            Rc::clone(&history),
        )),
        Box::new(CellClient::new(
            "published-by-b",
            Rc::clone(&claimed),
            1,
            Rc::clone(&history),
        )),
    ];

    let outcome = AuthorityCampaign::new(StoreInstanceId::from_raw(instance))
        .with_ticks_per_op(ticks_per_op)
        .run_on(&store, &mut cells, schedule, &HazardScript::none());

    let instants = outcome
        .trace()
        .events()
        .iter()
        .filter_map(|event| match event {
            TraceEvent::Stepped { at, .. } => Some(*at),
            TraceEvent::ClockAdvanced { to, .. } => Some(*to),
            _ => None,
        })
        .collect();

    let head = match store.read_head(&head_key()).expect("final read succeeds") {
        HeadRead::Present(receipt) => Some(receipt),
        HeadRead::Absent => None,
    };
    (instants, head)
}

#[test]
fn skewing_the_virtual_clock_moves_every_instant_and_nothing_the_authority_decides() {
    // "Clock skew and rollback must not matter -- clocks are not authority."
    //
    // The existing fault_campaign case states this as a regression guard and is
    // explicit that it skews NOTHING, because the authority store has no clock
    // to skew. This one does the injection the acceptance line actually asks
    // for: the lab's VirtualClock is the run's only source of time, and
    // `with_ticks_per_op` changes how far it advances per operation, so the two
    // runs below pass through genuinely different instants while issuing an
    // identical sequence of operations.
    for (name, schedule) in schedules() {
        let (slow_instants, slow_head) = run_at_tick_rate(&schedule, 1, 0xF036_B020);
        let (fast_instants, fast_head) = run_at_tick_rate(&schedule, 997, 0xF036_B020);

        // THE TWIN FIRST. If the two runs passed through the same instants, the
        // agreement below would be the agreement of two identical runs and
        // would measure nothing at all. This is what makes the clock a variable
        // rather than a decoration.
        assert_ne!(
            slow_instants, fast_instants,
            "{name}: the two runs must actually differ in virtual time, or nothing was skewed"
        );
        assert!(
            !slow_instants.is_empty(),
            "{name}: the run recorded no instants, so there is nothing to compare"
        );

        // AND NOW WHAT MUST NOT MOVE. Not merely the generation: the whole
        // receipt, TOKEN INCLUDED. A token seeded from an instant -- the most
        // plausible way a clock creeps into authority -- would differ here
        // while every generation and body still matched.
        assert_eq!(
            slow_head, fast_head,
            "{name}: the head, including its version token, must not depend on the clock"
        );
    }
}

#[test]
fn the_lab_clock_refuses_to_run_backwards_rather_than_silently_accepting_it() {
    // The rollback half of the same acceptance line. A regressing clock in a
    // replayed trace is a real defect, and swallowing it would hide the
    // divergence it is about to cause, so the refusal is the behaviour worth
    // pinning.
    let mut clock = VirtualClock::starting_at(LabTime::from_ticks(100));
    assert_eq!(clock.now(), LabTime::from_ticks(100));

    let refused = clock.advance_to(LabTime::from_ticks(99));
    assert!(
        refused.is_err(),
        "moving the clock backwards must be refused, not ignored"
    );
    assert_eq!(
        clock.now(),
        LabTime::from_ticks(100),
        "and a refused move must leave the clock exactly where it was"
    );

    // The permitted twin at the exact boundary: the SAME instant is not a
    // regression and must be accepted, or a replay that re-observes its current
    // instant would be reported as a rollback.
    assert!(
        clock.advance_to(LabTime::from_ticks(100)).is_ok(),
        "advancing to the current instant is not a rollback"
    );
    assert!(
        clock.advance_to(LabTime::from_ticks(101)).is_ok(),
        "and forward movement still works after a refusal"
    );
}
