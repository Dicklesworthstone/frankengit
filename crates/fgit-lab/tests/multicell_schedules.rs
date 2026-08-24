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

use fgit_authority::history::{
    ClientId as HistoryClientId, HistoryEvent, LogicalTime, OperationId,
};
use fgit_authority::lincheck::{
    AuthorityHistory, CheckLimits, CheckReport, CheckVerdict, LinearizabilityChecker,
    SequentialSpec,
};
use fgit_authority::{
    AuthorityClient, AuthorityOp, AuthorityResponse, AuthorityStore, AuthorityVersionToken,
    CasOutcome, FaultDirective, FaultKind, FaultPlan, FaultableAuthorityStore, HeadGeneration,
    HeadInit, HeadKey, HeadRead, MemoryAuthorityStore, OpIndex, StoreInstanceId,
};
use fgit_authority::{AuthorityRefusal, HeadReadReceipt, PutOutcome};
use fgit_lab::{AuthorityCampaign, HazardScript, LabSchedule, StepId};

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

/// The sequential specification the cell campaign is checked against.
///
/// Scoped to the two operations the cells actually issue. It is a SECOND model
/// alongside the one in `fgit-authority`'s own `fault_campaign` tests, which is
/// a duplication worth naming rather than hiding: two models of one vocabulary
/// are free to drift, which is the shape `frankengit-0kqi` was filed for.
/// Promoting a single reference spec into the library -- next to
/// `suite.rs`, which exists for exactly this reason -- is the right fix, and is
/// filed separately rather than smuggled into this bead.
struct CellModel {
    initial_generation: HeadGeneration,
    initial_body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CellModelState {
    /// The head as a whole receipt, not as separate fields.
    ///
    /// A version token names a head VERSION, not a read of one: the store hands
    /// back the SAME token for repeated reads of an unchanged head and mints a
    /// new one only when the head moves. Minting per read made two concurrent
    /// reads of one head disagree with the store and reported a violation that
    /// was purely an artefact of the model.
    head: HeadReadReceipt,
    /// Every token ever issued, and the key it was issued for.
    ///
    /// Needed because "this token is not one I minted" and "this token is stale"
    /// are DIFFERENT answers from the store, and a model holding only the
    /// current head cannot tell them apart.
    issued: BTreeMap<AuthorityVersionToken, HeadKey>,
    next_issuance: u64,
}

fn mint_token(next_issuance: &mut u64) -> AuthorityVersionToken {
    let mut bytes = [0_u8; 16];
    // MUST match `normalize_token`'s representative layout in fgit-authority's
    // history module: the checker rewrites observed tokens to `b"fgithist"`
    // plus a big-endian counter from 0, and compares the model's tokens against
    // those rewritten ones. A different prefix makes every receipt unequal and
    // the very first read reports NotLinearizable -- which is what it did.
    bytes[..8].copy_from_slice(b"fgithist");
    bytes[8..].copy_from_slice(&next_issuance.to_be_bytes());
    *next_issuance = next_issuance.saturating_add(1);
    AuthorityVersionToken::from_opaque_bytes(bytes)
}

impl SequentialSpec for CellModel {
    type State = CellModelState;
    type Operation = AuthorityOp;
    type Response = AuthorityResponse;

    fn initial_state(&self) -> Self::State {
        // The head is seeded BEFORE the campaign, so the model does not start
        // empty. Starting it empty would make every read disagree with the
        // store and report a violation that is an artefact of the setup.
        let mut next_issuance = 0_u64;
        let token = mint_token(&mut next_issuance);
        CellModelState {
            head: HeadReadReceipt::new(
                head_key(),
                token,
                self.initial_generation,
                self.initial_body.clone(),
            ),
            issued: BTreeMap::from([(token, head_key())]),
            next_issuance,
        }
    }

    fn apply(
        &self,
        state: &Self::State,
        operation: &Self::Operation,
    ) -> (Self::State, Self::Response) {
        let mut next = state.clone();
        let response = match operation {
            AuthorityOp::ReadHead { .. } => {
                AuthorityResponse::ReadHead(HeadRead::Present(next.head.clone()))
            }
            AuthorityOp::CompareExchangeHead {
                key,
                expected,
                new_generation,
                new_body,
            } => {
                // 5.1: only a conditional replacement of the EXACT predecessor
                // publishes, and that is decided against the CURRENT head's
                // token. A token naming a superseded head must not win.
                // The store's guards, IN ITS ORDER. Order is part of the
                // contract: an unknown token is refused before the predecessor
                // is compared, and monotonicity only AFTER the predecessor
                // matches. A model that collapses them answers differently for
                // any input that trips more than one.
                match next.issued.get(expected) {
                    None => AuthorityResponse::Refused(AuthorityRefusal::UnknownVersionToken),
                    Some(issued_key) if issued_key != key => {
                        AuthorityResponse::Refused(AuthorityRefusal::TokenKeyMismatch)
                    }
                    Some(_) if next.head.token() != *expected => {
                        AuthorityResponse::CompareExchangeHead(CasOutcome::PredecessorMismatch)
                    }
                    Some(_) if *new_generation <= next.head.generation() => {
                        // The serialised schedule reaches this and nothing else
                        // does: cell B reads the head A just published and
                        // re-proposes generation 2 against it. Its token IS
                        // current, so this is not a predecessor mismatch -- it
                        // is a non-advancing publish, which the store names
                        // separately and refuses.
                        AuthorityResponse::Refused(AuthorityRefusal::NonMonotoneGeneration {
                            current: next.head.generation(),
                            proposed: *new_generation,
                        })
                    }
                    Some(_) => {
                        let token = mint_token(&mut next.next_issuance);
                        next.issued.insert(token, key.clone());
                        next.head = HeadReadReceipt::new(
                            key.clone(),
                            token,
                            *new_generation,
                            new_body.clone(),
                        );
                        AuthorityResponse::CompareExchangeHead(CasOutcome::Committed(
                            next.head.clone(),
                        ))
                    }
                }
            }
            AuthorityOp::PutIfAbsent { .. } => AuthorityResponse::PutIfAbsent(PutOutcome::Conflict),
            AuthorityOp::ReadImmutable { .. }
            | AuthorityOp::InitializeHead { .. }
            | AuthorityOp::AuthenticateHeadReceipt { .. } => {
                unreachable!("the cell campaign issues only ReadHead and CompareExchangeHead")
            }
        };
        (next, response)
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
    let model = CellModel {
        initial_generation: HeadGeneration::FIRST,
        initial_body: b"root".to_vec(),
    };
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
