//! FG-005b: the AF-01..AF-08 injected-fault cells, driven against the real
//! `FrankenSQLite` backend.
//!
//! # The reason this cell carried, and why it was wrong
//!
//! `FG-005B-E2E-020` was recorded unsupported as:
//!
//! > `run_fault_conformance` is bound `S: FaultableAuthorityStore` and
//! > `MemoryAuthorityStore` is the only impl in the workspace, so ambiguity,
//! > duplication and lost-request-vs-lost-response are **unprovable for this
//! > backend by anyone**.
//!
//! Both halves of the first clause are true. The conclusion does not follow.
//! `FaultableAuthorityStore` is a trait, and nothing requires its implementor
//! to be the backend: a wrapper that counts operations, consults the plan, and
//! delegates to a real store satisfies it exactly. `crash_equivalence.rs`
//! already carries the hard half -- `impl AuthorityStore for Crashable` bridges
//! the async engine behind the sync trait -- so the missing piece was the fault
//! engine, not access to the backend.
//!
//! "Unprovable by anyone" was the load-bearing phrase and it was never
//! measured. It is the sixth such reason on this bead to fall, and the family
//! resemblance is now the finding: **every one asserted the impossibility of a
//! test from a reading of one layer.** Three said a checkpoint could not be
//! observed, one said cancellation could not be driven, this one said fault
//! injection could not reach this backend. None survived being tried.
//!
//! # What is proved here, stated precisely
//!
//! The faults are injected at the **store boundary**, not inside SQLite. So
//! what this establishes is that the caller-visible contract holds against a
//! real `FrankenSQLite` database when responses are lost, requests are lost,
//! requests are duplicated, and the endpoint dies: the effects really are
//! applied to real SQLite, the ambiguity really is resolved by an exact-key
//! read against real SQLite, and the answers agree with the reference.
//!
//! What it does **not** establish is that SQLite itself produces those faults,
//! or that its internal failure modes are exhausted by this vocabulary. A
//! genuine engine-level lost response is still unexercised. That is a real
//! remaining gap and it is narrower than the one this file closes.
//!
//! # Why the semantics are transcribed rather than invented
//!
//! The fault engine below mirrors `MemoryAuthorityStore::run` deliberately and
//! closely: before-effect faults in plan order, then the effect, then the
//! duplicate, then after-effect faults, with `effect_reached` recording the
//! ground truth an ambiguous caller cannot see. A wrapper that improvised its
//! own ordering would produce a backend that fails AF cells for reasons that
//! belong to the wrapper, and the campaign would report a defect in the engine
//! that is really a defect in the harness.
//!
//! Nothing here edits `fgit-authority-fsqlite/src`; the verifier independence
//! the bead rests on is unchanged.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use asupersync::cx::Cx as NativeCx;
use fgit_authority::{
    AmbiguityReason, AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityOpKind,
    AuthorityRefusal, AuthorityStore, AuthorityVersionToken, CasOutcome, EffectLog, EffectRecord,
    FaultKind, FaultLog, FaultPlan, FaultPosition, FaultRecord, FaultableAuthorityStore,
    HeadGeneration, HeadInit, HeadKey, HeadRead, HeadReadReceipt, ImmutableKey, ImmutableRead,
    OpIndex, PutOutcome, StoreInstanceId, run_fault_conformance,
};
use fgit_authority_fsqlite::{EngineError, FsqliteAuthorityStore};
use fgit_runtime::boot::{NodeRuntime, RuntimeProfile};
use fgit_runtime::meter::BudgetClass;
use fsqlite_types::cx::Cx as FsqliteCx;

// ------------------------------------------------------------- the fault state

#[derive(Default)]
struct FaultState {
    plan: FaultPlan,
    op_index: u64,
    kind_counts: BTreeMap<AuthorityOpKind, u64>,
    crashed: bool,
    logical_time: u64,
    fault_sequence: u64,
    effect_sequence: u64,
    faults: Vec<FaultRecord>,
    effects: Vec<EffectRecord>,
}

/// A real `FrankenSQLite` store behind a deterministic fault script.
///
/// The database is genuine: every effect that is not suppressed reaches real
/// SQL, and every resolution reads it back. Only the *delivery* of requests and
/// responses is scripted.
struct FaultingStore<'a> {
    node: &'a NodeRuntime,
    cx: FsqliteCx,
    store: FsqliteAuthorityStore,
    _native: NativeCx,
    state: Mutex<FaultState>,
}

impl<'a> FaultingStore<'a> {
    fn open(node: &'a NodeRuntime, instance: StoreInstanceId) -> Self {
        let native = node.request_cx(BudgetClass::Request);
        let cx = FsqliteCx::new();
        cx.set_native_cx(native.clone());
        let store = node
            .block_on(FsqliteAuthorityStore::open(
                &cx,
                ":memory:".to_owned(),
                instance,
                AuthorityLimits::default(),
            ))
            .expect("an in-memory store opens");
        Self {
            node,
            cx,
            store,
            _native: native,
            state: Mutex::new(FaultState::default()),
        }
    }

    fn locked(&self) -> MutexGuard<'_, FaultState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn record_fault(
        &self,
        at: OpIndex,
        op_kind: AuthorityOpKind,
        kind: FaultKind,
        effect_reached: bool,
    ) {
        let mut state = self.locked();
        let sequence = state.fault_sequence;
        state.fault_sequence = sequence.saturating_add(1);
        let logical_time = state.logical_time;
        state.faults.push(FaultRecord {
            sequence,
            at,
            op_kind,
            kind,
            effect_reached,
            logical_time,
        });
    }

    fn record_effect(&self, at: OpIndex, op_kind: AuthorityOpKind, mutated: bool) {
        let mut state = self.locked();
        let sequence = state.effect_sequence;
        state.effect_sequence = sequence.saturating_add(1);
        let logical_time = state.logical_time;
        state.effects.push(EffectRecord {
            sequence,
            at,
            op_kind,
            mutated,
            logical_time,
        });
    }

    /// Run one operation through the fault engine.
    ///
    /// `effect` is a callable rather than an inline expression for the same
    /// reason it is in the reference: a duplicated request applies it twice.
    fn run<T>(
        &self,
        op_kind: AuthorityOpKind,
        effect: &dyn Fn() -> Result<T, AuthorityFailure>,
        mutated: &dyn Fn(&Result<T, AuthorityFailure>) -> bool,
    ) -> Result<T, AuthorityFailure> {
        // The guard is dropped explicitly before the effect runs. Holding it
        // across `block_on` would serialise every operation behind the fault
        // bookkeeping, which is both unnecessary and the wrong shape: the
        // engine's own concurrency is what the campaign is meant to exercise.
        let (at, directives) = {
            let mut state = self.locked();
            if state.crashed {
                return Err(AuthorityFailure::Refused(AuthorityRefusal::Unavailable));
            }
            let at = OpIndex::from_raw(state.op_index);
            state.op_index = state.op_index.saturating_add(1);
            let seen = state.kind_counts.entry(op_kind).or_insert(0);
            let within_kind = OpIndex::from_raw(*seen);
            *seen = seen.saturating_add(1);
            let directives = state.plan.selecting(at, within_kind, op_kind);
            drop(state);
            (at, directives)
        };

        for directive in &directives {
            match directive.kind {
                FaultKind::Throttle => {
                    self.record_fault(at, op_kind, directive.kind, false);
                    return Err(AuthorityFailure::Refused(AuthorityRefusal::Throttled));
                }
                FaultKind::LoseRequest => {
                    self.record_fault(at, op_kind, directive.kind, false);
                    return Err(AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse));
                }
                FaultKind::Crash {
                    position: FaultPosition::BeforeEffect,
                } => {
                    self.locked().crashed = true;
                    self.record_fault(at, op_kind, directive.kind, false);
                    return Err(AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse));
                }
                FaultKind::Delay {
                    position: FaultPosition::BeforeEffect,
                    ticks,
                } => {
                    {
                        let mut state = self.locked();
                        state.logical_time = state.logical_time.saturating_add(ticks);
                    }
                    self.record_fault(at, op_kind, directive.kind, false);
                }
                FaultKind::Crash { .. }
                | FaultKind::Delay { .. }
                | FaultKind::LoseResponse
                | FaultKind::DuplicateRequest { .. } => {}
            }
        }

        let mut outcome = effect();
        self.record_effect(at, op_kind, mutated(&outcome));

        if let Some(directive) = directives
            .iter()
            .find(|directive| matches!(directive.kind, FaultKind::DuplicateRequest { .. }))
        {
            let second = effect();
            self.record_effect(at, op_kind, mutated(&second));
            self.record_fault(at, op_kind, directive.kind, true);
            if matches!(
                directive.kind,
                FaultKind::DuplicateRequest {
                    deliver: fgit_authority::DuplicateDelivery::Second
                }
            ) {
                outcome = second;
            }
        }

        for directive in &directives {
            match directive.kind {
                FaultKind::Delay {
                    position: FaultPosition::AfterEffect,
                    ticks,
                } => {
                    {
                        let mut state = self.locked();
                        state.logical_time = state.logical_time.saturating_add(ticks);
                    }
                    self.record_fault(at, op_kind, directive.kind, true);
                }
                FaultKind::LoseResponse => {
                    self.record_fault(at, op_kind, directive.kind, true);
                    return Err(AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse));
                }
                FaultKind::Crash {
                    position: FaultPosition::AfterEffect,
                } => {
                    self.locked().crashed = true;
                    self.record_fault(at, op_kind, directive.kind, true);
                    return Err(AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse));
                }
                FaultKind::Crash { .. }
                | FaultKind::Delay { .. }
                | FaultKind::LoseRequest
                | FaultKind::Throttle
                | FaultKind::DuplicateRequest { .. } => {}
            }
        }

        outcome
    }
}

// ---------------------------------------------------------- the sync bridge

impl AuthorityStore for FaultingStore<'_> {
    fn instance_id(&self) -> StoreInstanceId {
        self.store.instance_id()
    }

    fn limits(&self) -> AuthorityLimits {
        self.store.limits()
    }

    fn put_if_absent(
        &self,
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        self.run(
            AuthorityOpKind::PutIfAbsent,
            &|| {
                self.node
                    .block_on(self.store.put_if_absent(&self.cx, key, body))
                    .map_err(EngineError::into_failure)
            },
            &|outcome| matches!(outcome, Ok(PutOutcome::Created)),
        )
    }

    fn read_immutable(&self, key: &ImmutableKey) -> Result<ImmutableRead, AuthorityFailure> {
        self.run(
            AuthorityOpKind::ReadImmutable,
            &|| {
                self.node
                    .block_on(self.store.read_immutable(&self.cx, key))
                    .map_err(EngineError::into_failure)
            },
            &|_| false,
        )
    }

    fn initialize_head(
        &self,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, AuthorityFailure> {
        self.run(
            AuthorityOpKind::InitializeHead,
            &|| {
                self.node
                    .block_on(self.store.initialize_head(&self.cx, key, generation, body))
                    .map_err(EngineError::into_failure)
            },
            &|outcome| matches!(outcome, Ok(HeadInit::Created(_))),
        )
    }

    fn read_head(&self, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        self.run(
            AuthorityOpKind::ReadHead,
            &|| {
                self.node
                    .block_on(self.store.read_head(&self.cx, key))
                    .map_err(EngineError::into_failure)
            },
            &|_| false,
        )
    }

    fn compare_exchange_head(
        &self,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        self.run(
            AuthorityOpKind::CompareExchangeHead,
            &|| {
                self.node
                    .block_on(self.store.compare_exchange_head(
                        &self.cx,
                        key,
                        expected,
                        new_generation,
                        new_body,
                    ))
                    .map_err(EngineError::into_failure)
            },
            &|outcome| matches!(outcome, Ok(CasOutcome::Committed(_))),
        )
    }

    fn authenticate_head_receipt(
        &self,
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure> {
        self.run(
            AuthorityOpKind::AuthenticateHeadReceipt,
            &|| {
                self.node
                    .block_on(self.store.authenticate_head_receipt(&self.cx, receipt))
                    .map_err(EngineError::into_failure)
            },
            &|_| false,
        )
    }
}

impl FaultableAuthorityStore for FaultingStore<'_> {
    fn install_fault_plan(&self, plan: FaultPlan) {
        // Per the trait's contract: counters, clock and both logs reset; stored
        // bodies and heads persist, because a new script is a new experiment
        // against the same accumulated state.
        let mut state = self.locked();
        state.plan = plan;
        state.op_index = 0;
        state.kind_counts.clear();
        state.crashed = false;
        state.logical_time = 0;
        state.fault_sequence = 0;
        state.effect_sequence = 0;
        state.faults.clear();
        state.effects.clear();
    }

    fn fault_log(&self) -> FaultLog {
        FaultLog::from_records(self.locked().faults.clone())
    }

    fn effect_log(&self) -> EffectLog {
        EffectLog::from_records(self.locked().effects.clone())
    }

    fn is_crashed(&self) -> bool {
        self.locked().crashed
    }

    fn restart(&self) {
        self.locked().crashed = false;
    }
}

// ------------------------------------------------------------------- the cells

fn node() -> NodeRuntime {
    RuntimeProfile::deterministic()
        .build()
        .expect("the deterministic profile builds")
}

/// The cells `run_fault_conformance` declares, named so a silent drop is loud.
const AF_CELLS: [&str; 8] = [
    "AF-01", "AF-02", "AF-03", "AF-04", "AF-05", "AF-06", "AF-07", "AF-08",
];

#[test]
fn the_injected_fault_cells_pass_against_the_real_backend() {
    // AF-01..AF-08, driven by the same campaign the reference runs, over a real
    // `FrankenSQLite` database.
    let node = node();
    let report = run_fault_conformance(|instance| FaultingStore::open(&node, instance));

    assert!(
        report.is_pass(),
        "the injected-fault cells must pass against the real backend; failed: {:?}",
        report.failed_ids()
    );
    // A pass over zero checks is also a pass, so the count is checked against
    // the declared set rather than against a number I chose. Naming the cells
    // beats asserting `len() >= 8`: a campaign that dropped AF-04 and gained
    // some other check would satisfy the count and quietly stop testing the
    // cell this bead is about.
    for id in AF_CELLS {
        assert!(
            report.check(id).is_some(),
            "{id} was never recorded; the campaign did not run the cell rather than the backend \
             satisfying it"
        );
    }
}

#[test]
fn the_harness_can_actually_suppress_an_effect() {
    // The control for the whole file. `run_fault_conformance` passing proves
    // the backend lawful only if the harness really injects; a wrapper whose
    // plan never fired would deliver an unfaulted store, and every AF cell that
    // asserts "resolves to applied" would pass for the wrong reason.
    //
    // So: lose the request, and check the ground truth the caller cannot see --
    // no effect was reached, and the body is genuinely absent from SQLite.
    let node = node();
    let store = FaultingStore::open(&node, StoreInstanceId::from_raw(1));
    let key = ImmutableKey::new(b"blob/suppressed".to_vec()).expect("admissible");

    store.install_fault_plan(FaultPlan::explicit(vec![
        fgit_authority::FaultDirective::new(OpIndex::from_raw(0), FaultKind::LoseRequest),
    ]));

    let answer = store.put_if_absent(&key, b"payload");
    assert!(
        matches!(answer, Err(AuthorityFailure::Ambiguous(_))),
        "a lost request must present as ambiguity, not as a clean failure; got {answer:?}"
    );
    assert!(
        store.effect_log().is_empty(),
        "a lost request must not reach the effect; the effect log holds {:?}",
        store.effect_log().records()
    );
    assert_eq!(
        store.fault_log().len(),
        1,
        "the injection must be recorded, or the campaign cannot audit what it exercised"
    );

    // Read through the same wrapper with no plan installed, so the answer comes
    // from real SQL rather than from the fault engine.
    store.install_fault_plan(FaultPlan::none());
    let after = store.read_immutable(&key).expect("a read with no plan");
    assert!(
        matches!(after, ImmutableRead::Absent),
        "the suppressed write must be absent from the real database; found {after:?}"
    );
}

#[test]
fn a_lost_response_really_did_apply_the_effect() {
    // The other side of the pair, and the one that distinguishes a lost
    // response from a lost request -- the distinction the old unsupported
    // reason said was unprovable for this backend.
    let node = node();
    let store = FaultingStore::open(&node, StoreInstanceId::from_raw(1));
    let key = ImmutableKey::new(b"blob/applied".to_vec()).expect("admissible");

    store.install_fault_plan(FaultPlan::explicit(vec![
        fgit_authority::FaultDirective::new(OpIndex::from_raw(0), FaultKind::LoseResponse),
    ]));

    let answer = store.put_if_absent(&key, b"payload");
    assert!(
        matches!(answer, Err(AuthorityFailure::Ambiguous(_))),
        "a lost response is ambiguous to the caller, exactly like a lost request; got {answer:?}"
    );
    assert_eq!(
        store.effect_log().mutation_count(),
        1,
        "a lost response must have applied the effect; that is what makes it different from a \
         lost request, and the caller cannot tell them apart"
    );

    store.install_fault_plan(FaultPlan::none());
    let after = store.read_immutable(&key).expect("a read with no plan");
    assert!(
        matches!(after, ImmutableRead::Present(_)),
        "the body must really be in SQLite after a lost response; found {after:?}"
    );
}
