//! Fault scripts are deterministic, replayable, and fully logged.

use fgit_authority::{
    AuthorityOpKind, AuthorityStore, DuplicateDelivery, FaultDirective, FaultKind, FaultLog,
    FaultPlan, FaultPosition, FaultableAuthorityStore, HeadGeneration, HeadInit, HeadKey,
    ImmutableKey, MemoryAuthorityStore, OpIndex, PutOutcome, SplitMix64, StoreInstanceId,
};

fn store() -> MemoryAuthorityStore {
    MemoryAuthorityStore::new(StoreInstanceId::from_raw(1))
}

fn immutable_key(name: &str) -> ImmutableKey {
    ImmutableKey::new(name.as_bytes().to_vec()).expect("admissible immutable key")
}

fn head_key(name: &str) -> HeadKey {
    HeadKey::new(name.as_bytes().to_vec()).expect("admissible head key")
}

fn run_twelve_puts(store: &MemoryAuthorityStore) -> FaultLog {
    let key = immutable_key("seal/tx");
    for index in 0_u8..12 {
        let body = [b'b', index];
        let _ignored = store.put_if_absent(&key, &body);
    }
    store.fault_log()
}

#[test]
fn a_seed_materialises_one_plan() {
    let left = FaultPlan::seeded(0x5EED_0001, 12, 6);
    let right = FaultPlan::seeded(0x5EED_0001, 12, 6);
    assert_eq!(left, right, "the same seed must produce the same plan");
    assert_eq!(left.seed(), Some(0x5EED_0001));
    assert_eq!(left.directives().len(), 6);
    assert_ne!(
        left,
        FaultPlan::seeded(0x5EED_0002, 12, 6),
        "a different seed must produce a different plan"
    );
}

#[test]
fn a_seeded_plan_is_sorted_by_position_so_it_reads_as_it_runs() {
    let plan = FaultPlan::seeded(0x5EED_0003, 32, 10);
    let positions: Vec<u64> = plan
        .directives()
        .iter()
        .map(|directive| directive.at.raw())
        .collect();
    let mut sorted = positions.clone();
    sorted.sort_unstable();
    assert_eq!(positions, sorted);
}

#[test]
fn a_seeded_plan_replays_to_an_identical_fault_log() {
    let first = store();
    first.install_fault_plan(FaultPlan::seeded(0x5EED_0001, 12, 6));
    let left = run_twelve_puts(&first);

    let second = store();
    second.install_fault_plan(FaultPlan::seeded(0x5EED_0001, 12, 6));
    let right = run_twelve_puts(&second);

    assert_eq!(
        left, right,
        "the same seed against the same operation sequence must inject the same faults"
    );
    assert!(
        !left.is_empty(),
        "a six-directive plan over twelve operations must inject something"
    );
}

#[test]
fn every_injected_fault_is_logged_with_its_position_and_kind() {
    let store = store();
    store.install_fault_plan(FaultPlan::explicit(vec![
        FaultDirective::new(OpIndex::from_raw(0), FaultKind::Throttle),
        FaultDirective::new(
            OpIndex::from_raw(1),
            FaultKind::Delay {
                position: FaultPosition::BeforeEffect,
                ticks: 3,
            },
        ),
        FaultDirective::new(OpIndex::from_raw(2), FaultKind::LoseResponse),
    ]));

    let key = immutable_key("seal/tx");
    let _throttled = store.put_if_absent(&key, b"a");
    let _delayed = store.put_if_absent(&key, b"a");
    let _lost = store.put_if_absent(&key, b"a");

    let log = store.fault_log();
    assert_eq!(log.len(), 3);
    let records = log.records();

    assert_eq!(records[0].at, OpIndex::from_raw(0));
    assert_eq!(records[0].kind, FaultKind::Throttle);
    assert_eq!(records[0].op_kind, AuthorityOpKind::PutIfAbsent);
    assert!(!records[0].effect_reached);
    assert_eq!(records[0].sequence, 0);

    assert_eq!(records[1].at, OpIndex::from_raw(1));
    assert!(matches!(records[1].kind, FaultKind::Delay { ticks: 3, .. }));
    assert!(!records[1].effect_reached);

    assert_eq!(records[2].at, OpIndex::from_raw(2));
    assert_eq!(records[2].kind, FaultKind::LoseResponse);
    assert!(records[2].effect_reached);
    assert_eq!(records[2].sequence, 2);
}

#[test]
fn a_delay_advances_the_logical_clock_at_the_scripted_position() {
    let store = store();
    store.install_fault_plan(FaultPlan::explicit(vec![
        FaultDirective::new(
            OpIndex::from_raw(0),
            FaultKind::Delay {
                position: FaultPosition::BeforeEffect,
                ticks: 5,
            },
        ),
        FaultDirective::new(
            OpIndex::from_raw(1),
            FaultKind::Delay {
                position: FaultPosition::AfterEffect,
                ticks: 2,
            },
        ),
    ]));
    assert_eq!(store.logical_time(), 0);

    let key = immutable_key("seal/tx");
    store.put_if_absent(&key, b"a").expect("delayed put");
    assert_eq!(store.logical_time(), 5);
    store.put_if_absent(&key, b"a").expect("delayed retry");
    assert_eq!(store.logical_time(), 7);

    let records = store.fault_log();
    assert_eq!(records.records()[0].logical_time, 5);
    assert_eq!(records.records()[1].logical_time, 7);
}

#[test]
fn a_directive_can_be_restricted_to_one_operation_kind() {
    let store = store();
    store.install_fault_plan(FaultPlan::explicit(vec![
        FaultDirective::new(OpIndex::from_raw(0), FaultKind::Throttle)
            .only_for(AuthorityOpKind::ReadHead),
    ]));

    let key = immutable_key("seal/tx");
    assert_eq!(
        store.put_if_absent(&key, b"a").expect("an unrelated kind is untouched"),
        PutOutcome::Created,
        "a directive restricted to another operation kind must not fire"
    );
    assert!(store.fault_log().is_empty());
}

#[test]
fn the_effect_log_is_ground_truth_the_caller_cannot_see() {
    let store = store();
    store.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::new(
        OpIndex::ZERO,
        FaultKind::DuplicateRequest {
            deliver: DuplicateDelivery::Second,
        },
    )]));

    let key = head_key("repo/head");
    let outcome = store
        .initialize_head(&key, HeadGeneration::FIRST, b"head-1")
        .expect("head creation");
    assert!(
        matches!(outcome, HeadInit::IdenticalRetry(_)),
        "the second delivery of a duplicated creation observes the first, observed {outcome:?}"
    );

    let effects = store.effect_log();
    assert_eq!(
        effects.len(),
        2,
        "a duplicated request reaches the effect twice"
    );
    assert_eq!(
        effects.mutation_count(),
        1,
        "but only one application changes state"
    );
    assert_eq!(effects.records()[0].op_kind, AuthorityOpKind::InitializeHead);
    assert_eq!(effects.records()[0].at, OpIndex::ZERO);
    assert_eq!(effects.records()[1].at, OpIndex::ZERO);
}

#[test]
fn installing_a_plan_starts_a_fresh_script_run_but_keeps_stored_state() {
    let store = store();
    let key = immutable_key("seal/tx");
    store.put_if_absent(&key, b"body").expect("first put");
    assert_eq!(store.operations_started(), 1);

    store.install_fault_plan(FaultPlan::none());
    assert_eq!(
        store.operations_started(),
        0,
        "the operation counter the plan indexes restarts"
    );
    assert!(store.fault_log().is_empty());
    assert!(store.effect_log().is_empty());
    assert_eq!(
        store.put_if_absent(&key, b"body").expect("second put"),
        PutOutcome::IdenticalRetry,
        "stored bodies survive a new script run"
    );
}

#[test]
fn the_schedule_generator_is_deterministic_and_bounded() {
    let mut left = SplitMix64::new(42);
    let mut right = SplitMix64::new(42);
    let mut other = SplitMix64::new(43);
    let left_stream: Vec<u64> = (0..64).map(|_| left.next_u64()).collect();
    let right_stream: Vec<u64> = (0..64).map(|_| right.next_u64()).collect();
    let other_stream: Vec<u64> = (0..64).map(|_| other.next_u64()).collect();

    assert_eq!(left_stream, right_stream, "one seed, one stream");
    assert_ne!(left_stream, other_stream, "different seeds, different streams");

    let mut bounded = SplitMix64::new(7);
    for _ in 0..64 {
        assert!(bounded.next_below(5) < 5, "next_below must respect its bound");
    }
    assert_eq!(
        SplitMix64::new(1).next_below(0),
        0,
        "a zero bound yields zero rather than dividing by zero"
    );
}
