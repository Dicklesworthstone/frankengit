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

use fgit_authority::{
    AuthorityClient, AuthorityOp, AuthorityResponse, AuthorityStore, AuthorityVersionToken,
    CasOutcome, FaultDirective, FaultKind, FaultPlan, FaultableAuthorityStore, HeadGeneration,
    HeadInit, HeadKey, HeadRead, MemoryAuthorityStore, OpIndex, StoreInstanceId,
};
use fgit_lab::{AuthorityCampaign, HazardScript, LabSchedule, StepId};

const HEAD: &str = "repo/multicell";

fn head_key() -> HeadKey {
    HeadKey::new(HEAD.as_bytes().to_vec()).expect("key is within bounds")
}

fn generation(value: u64) -> HeadGeneration {
    HeadGeneration::try_new(value).expect("a positive generation is valid")
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
}

impl CellClient {
    fn new(body: &str, claimed: Rc<RefCell<usize>>) -> Self {
        Self {
            body: body.as_bytes().to_vec(),
            step: 0,
            token: None,
            claimed,
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
        op
    }

    fn observe(&mut self, response: &AuthorityResponse) {
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
fn run(schedule: &LabSchedule, hazards: &HazardScript, instance: u64) -> (usize, u64, usize) {
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
    let mut cells: Vec<Box<dyn AuthorityClient>> = vec![
        Box::new(CellClient::new("published-by-a", Rc::clone(&claimed))),
        Box::new(CellClient::new("published-by-b", Rc::clone(&claimed))),
    ];

    let outcome = AuthorityCampaign::new(StoreInstanceId::from_raw(instance))
        .run_on(&store, &mut cells, schedule, hazards);

    let final_generation = match store.read_head(&head_key()).expect("final read succeeds") {
        HeadRead::Present(receipt) => receipt.generation().get(),
        HeadRead::Absent => panic!("the head vanished"),
    };
    (
        *claimed.borrow(),
        final_generation.saturating_sub(base),
        outcome.injected_faults(),
    )
}

#[test]
fn contending_cells_hold_the_publication_invariant_under_every_schedule() {
    // The no-fault arm. Two cells race; whatever the ordering, the number of
    // publications claimed must equal how far the head moved.
    for (name, schedule) in schedules() {
        let (claimed, advanced, injected) = run(&schedule, &HazardScript::none(), 0xF036_B010);
        assert_eq!(
            injected, 0,
            "{name}: the no-fault arm must inject nothing, or it is not a control"
        );
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
        let (claimed, advanced, injected) = run(&schedule, &isolate_one_cell(), 0xF036_B011);
        assert!(
            injected >= 1,
            "{name}: the isolation must actually fire in this schedule, injected {injected}"
        );
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
        let (claimed, advanced, injected) = run(&schedule, &partition_every_read(), 0xF036_B014);
        assert!(
            injected >= 1,
            "{name}: the total partition must actually fire, injected {injected}"
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
        let (_, advanced, _) = run(&schedule, &HazardScript::none(), 0xF036_B012);
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
