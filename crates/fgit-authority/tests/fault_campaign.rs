//! Deterministic fault and adversarial campaigns over the reference authority store.
//!
//! The campaign transcript separates the raw caller result from the checker
//! history.  A caller-visible `Ambiguous` result represents an invocation for
//! which no authority response was observed, so it is deliberately retained as
//! a pending invocation in the linearizability history.  The raw result remains
//! in the evidence record; it is never rewritten to a fabricated negative.

use std::collections::BTreeMap;
use std::sync::{Arc, Barrier, Mutex, PoisonError, mpsc};

use core::time::Duration;

use fgit_authority::HeadBodyRefusal;
use fgit_authority::history::{
    ClientId as HistoryClientId, HistoryEvent, LogicalTime, OperationId,
};
use fgit_authority::lincheck::{
    AuthorityHistory, AuthorityReferenceSpec, CheckLimits, CheckReport, CheckVerdict,
    LinearizabilityChecker,
};
use fgit_authority::{
    AmbiguityReason, AuthenticatedHead, AuthorityFailure, AuthorityOp, AuthorityRefusal,
    AuthorityResponse, AuthorityStore, AuthorityVersionToken, CasOutcome, FaultDirective,
    FaultKind, FaultPlan, FaultPosition, FaultableAuthorityStore, HeadGeneration, HeadInit,
    HeadKey, HeadRead, HeadReadReceipt, ImmutableKey, ImmutableRead, MemoryAuthorityStore, OpIndex,
    PutOutcome, StoreInstanceId, resolve_ambiguous_cas,
};
use fgit_codec::wire::{CanonicalBody, encode_body};
use fgit_codec::{CodecRefusal, Decoder, Encoder, RepositoryAuthorityHeadBody};
use fgit_types::cell::{
    CellRefusal, CellState, ReadLabel, ReadMode, StalenessBound, StalenessObservation, admits_read,
};
use fgit_types::label::{DomainTag, SchemaFamily};

const DEFAULT_SEED: u64 = 0xF004_C001_5EED_0001;

#[derive(Clone, Debug, Default)]
struct HistoryRecorder {
    events: Vec<HistoryEvent<AuthorityOp, AuthorityResponse>>,
    next_operation_id: u64,
    next_time_by_client: BTreeMap<u64, u64>,
    raw_responses: Vec<AuthorityResponse>,
}

impl HistoryRecorder {
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

    fn respond(&mut self, client: u64, operation_id: OperationId, response: AuthorityResponse) {
        self.raw_responses.push(response.clone());
        if !matches!(response, AuthorityResponse::Ambiguous(_)) {
            let logical_time = self.next_time(client);
            self.events.push(HistoryEvent::response(
                HistoryClientId(client),
                logical_time,
                operation_id,
                response,
            ));
        }
    }

    fn execute<S>(&mut self, store: &S, client: u64, operation: AuthorityOp) -> AuthorityResponse
    where
        S: AuthorityStore + ?Sized,
    {
        let operation_id = self.invoke(client, operation.clone());
        let response = store.execute(&operation);
        self.respond(client, operation_id, response.clone());
        response
    }

    fn history(&self) -> AuthorityHistory {
        AuthorityHistory::new(self.events.clone()).expect("campaign recorder emits valid history")
    }
}

fn checker() -> LinearizabilityChecker {
    LinearizabilityChecker::new(CheckLimits {
        max_completed_operations: 16,
        max_search_nodes: 100_000,
    })
    .expect("campaign checker limits are valid")
}

fn head_key(label: &str) -> HeadKey {
    HeadKey::new(format!("fault/{label}").into_bytes()).expect("campaign head key is valid")
}

fn immutable_key(label: &str) -> ImmutableKey {
    ImmutableKey::new(format!("fault/{label}").into_bytes())
        .expect("campaign immutable key is valid")
}

fn generation(value: u64) -> HeadGeneration {
    HeadGeneration::try_new(value).expect("campaign generation is nonzero")
}

fn created_receipt(response: &AuthorityResponse) -> HeadReadReceipt {
    match response {
        AuthorityResponse::InitializeHead(HeadInit::Created(receipt)) => receipt.clone(),
        unexpected => panic!("expected an initial head receipt, got {unexpected:?}"),
    }
}

fn committed_receipt(response: &AuthorityResponse) -> HeadReadReceipt {
    match response {
        AuthorityResponse::CompareExchangeHead(CasOutcome::Committed(receipt)) => receipt.clone(),
        unexpected => panic!("expected a committed CAS receipt, got {unexpected:?}"),
    }
}

fn read_receipt(response: &AuthorityResponse) -> HeadReadReceipt {
    match response {
        AuthorityResponse::ReadHead(HeadRead::Present(receipt)) => receipt.clone(),
        unexpected => panic!("expected a present head read, got {unexpected:?}"),
    }
}

fn expect_linearizable(report: &CheckReport) {
    assert!(
        matches!(&report.verdict, CheckVerdict::Linearizable { .. }),
        "reference campaign unexpectedly failed lincheck: {report:?}"
    );
}

fn json_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn fault_script_json(plan: &FaultPlan) -> String {
    let entries = plan
        .directives()
        .iter()
        .map(|directive| {
            format!(
                "{{\"at\":{},\"kind\":{},\"applies_to\":{}}}",
                directive.at.raw(),
                json_string(&format!("{:?}", directive.kind)),
                json_string(&format!("{:?}", directive.applies_to)),
            )
        })
        .collect::<Vec<_>>();
    format!("[{}]", entries.join(","))
}

fn history_json(history: &AuthorityHistory) -> String {
    let events = history
        .events()
        .iter()
        .map(|event| {
            format!(
                "{{\"client\":{},\"logical_time\":{},\"operation_id\":{},\"event\":{}}}",
                event.client.0,
                event.logical_time.0,
                event.operation_id.0,
                json_string(&format!("{:?}", event.kind)),
            )
        })
        .collect::<Vec<_>>();
    format!("[{}]", events.join(","))
}

fn evidence_ndjson(
    seed: u64,
    plan: &FaultPlan,
    recorder: &HistoryRecorder,
    history: &AuthorityHistory,
    report: &CheckReport,
    note: &str,
) -> String {
    let raw_responses = recorder
        .raw_responses
        .iter()
        .map(|response| json_string(&format!("{response:?}")))
        .collect::<Vec<_>>();
    format!(
        "{{\"schema\":\"fgit.authority.fault-campaign.v1\",\"seed\":{seed},\"fault_script\":{},\"history\":{},\"raw_responses\":[{}],\"checker\":{},\"note\":{}}}",
        fault_script_json(plan),
        history_json(history),
        raw_responses.join(","),
        report.to_ndjson().trim_end(),
        json_string(note),
    )
}

fn configured_seed(default_seed: u64) -> u64 {
    let Ok(seed) = std::env::var("FG_AUTHORITY_FAULT_SEED") else {
        return default_seed;
    };
    let digits = seed.trim().trim_start_matches("0x");
    u64::from_str_radix(digits, 16)
        .unwrap_or_else(|error| panic!("FG_AUTHORITY_FAULT_SEED must be hexadecimal: {error}"))
}

fn check_and_emit(
    seed: u64,
    plan: &FaultPlan,
    recorder: &HistoryRecorder,
    model: AuthorityReferenceSpec,
    note: &str,
) -> CheckReport {
    let history = recorder.history();
    let report = checker().check_authority(&model, &history);
    println!(
        "{}",
        evidence_ndjson(seed, plan, recorder, &history, &report, note)
    );
    report
}

fn initialize(
    recorder: &mut HistoryRecorder,
    store: &MemoryAuthorityStore,
    key: &HeadKey,
) -> HeadReadReceipt {
    created_receipt(&recorder.execute(
        store,
        0,
        AuthorityOp::InitializeHead {
            key: key.clone(),
            generation: HeadGeneration::FIRST,
            body: b"root".to_vec(),
        },
    ))
}

#[test]
fn seeded_fault_matrix_records_replayable_linearizable_histories() {
    let base_seed = configured_seed(DEFAULT_SEED);
    for seed in [
        base_seed,
        base_seed.wrapping_add(1),
        base_seed ^ 0x5EED_CAFE,
    ] {
        let instance = StoreInstanceId::from_raw(0xF004_C001);
        let store = MemoryAuthorityStore::new(instance);
        let key = head_key("seeded-read-matrix");
        let mut recorder = HistoryRecorder::default();
        let _receipt = initialize(&mut recorder, &store, &key);
        let plan = FaultPlan::seeded(seed, 8, 6);
        store.install_fault_plan(plan.clone());

        for client in 1_u64..=8 {
            let _response =
                recorder.execute(&store, client, AuthorityOp::ReadHead { key: key.clone() });
        }

        assert_eq!(plan.seed(), Some(seed));
        assert!(
            !store.fault_log().is_empty(),
            "the seeded plan must inject at least one fault"
        );
        let report = check_and_emit(
            seed,
            &plan,
            &recorder,
            AuthorityReferenceSpec::new(instance),
            "seeded plans target reads so duplicate delivery and ambiguity preserve a checkable client history",
        );
        expect_linearizable(&report);
    }
}

#[test]
fn lost_acknowledgement_after_cas_and_crash_point_preserve_pending_histories() {
    let instance = StoreInstanceId::from_raw(0xF004_C002);
    let key = head_key("lost-ack");
    let store = MemoryAuthorityStore::new(instance);
    let mut recorder = HistoryRecorder::default();
    let predecessor = initialize(&mut recorder, &store, &key);
    let plan = FaultPlan::explicit(vec![
        FaultDirective::new(OpIndex::ZERO, FaultKind::LoseResponse)
            .only_for(fgit_authority::AuthorityOpKind::CompareExchangeHead),
    ]);
    store.install_fault_plan(plan.clone());

    let response = recorder.execute(
        &store,
        1,
        AuthorityOp::CompareExchangeHead {
            key: key.clone(),
            expected: predecessor.token(),
            new_generation: generation(2),
            new_body: b"after-loss".to_vec(),
        },
    );
    assert_eq!(
        response,
        AuthorityResponse::Ambiguous(AmbiguityReason::NoResponse)
    );
    let resolution =
        read_receipt(&recorder.execute(&store, 2, AuthorityOp::ReadHead { key: key.clone() }));
    assert_eq!(resolution.generation(), generation(2));
    assert_eq!(resolution.body(), b"after-loss");
    assert!(matches!(
        resolve_ambiguous_cas(&store, &key, generation(2), b"after-loss"),
        Ok(fgit_authority::CasResolution::Applied(_))
    ));
    let report = check_and_emit(
        0xF004_C002,
        &plan,
        &recorder,
        AuthorityReferenceSpec::new(instance),
        "lost CAS acknowledgement remains pending; the recorded exact-key resolution proves its effect",
    );
    expect_linearizable(&report);

    let crash_instance = StoreInstanceId::from_raw(0xF004_C003);
    let crash_store = MemoryAuthorityStore::new(crash_instance);
    let crash_key = head_key("crash-read");
    let mut crash_recorder = HistoryRecorder::default();
    let _receipt = initialize(&mut crash_recorder, &crash_store, &crash_key);
    let crash_plan = FaultPlan::explicit(vec![
        FaultDirective::new(
            OpIndex::ZERO,
            FaultKind::Crash {
                position: FaultPosition::AfterEffect,
            },
        )
        .only_for(fgit_authority::AuthorityOpKind::ReadHead),
    ]);
    crash_store.install_fault_plan(crash_plan.clone());
    let crash_response = crash_recorder.execute(
        &crash_store,
        1,
        AuthorityOp::ReadHead {
            key: crash_key.clone(),
        },
    );
    assert_eq!(
        crash_response,
        AuthorityResponse::Ambiguous(AmbiguityReason::NoResponse)
    );
    assert!(crash_store.is_crashed());
    crash_store.restart();
    assert!(!crash_store.is_crashed());
    let crash_report = check_and_emit(
        0xF004_C003,
        &crash_plan,
        &crash_recorder,
        AuthorityReferenceSpec::new(crash_instance),
        "post-effect crash on a read is a pending response, then restart restores availability",
    );
    expect_linearizable(&crash_report);
}

#[test]
fn stale_token_and_malicious_receipt_attempts_are_linearized_or_refused() {
    let instance = StoreInstanceId::from_raw(0xF004_C004);
    let store = MemoryAuthorityStore::new(instance);
    let key = head_key("adversarial-receipt");
    let mut recorder = HistoryRecorder::default();
    let original = initialize(&mut recorder, &store, &key);
    let updated = committed_receipt(&recorder.execute(
        &store,
        1,
        AuthorityOp::CompareExchangeHead {
            key: key.clone(),
            expected: original.token(),
            new_generation: generation(2),
            new_body: b"updated".to_vec(),
        },
    ));
    let stale = recorder.execute(
        &store,
        2,
        AuthorityOp::CompareExchangeHead {
            key: key.clone(),
            expected: original.token(),
            new_generation: generation(3),
            new_body: b"stale-attempt".to_vec(),
        },
    );
    assert_eq!(
        stale,
        AuthorityResponse::CompareExchangeHead(CasOutcome::PredecessorMismatch)
    );
    let forged = HeadReadReceipt::new(
        key.clone(),
        AuthorityVersionToken::from_opaque_bytes([0xA5; 16]),
        generation(99),
        b"forged".to_vec(),
    );
    let forged_response = recorder.execute(
        &store,
        3,
        AuthorityOp::AuthenticateHeadReceipt { receipt: forged },
    );
    assert_eq!(
        forged_response,
        AuthorityResponse::Refused(AuthorityRefusal::UnknownVersionToken)
    );
    let tampered = HeadReadReceipt::new(
        key.clone(),
        original.token(),
        original.generation(),
        b"tampered".to_vec(),
    );
    let tampered_response = recorder.execute(
        &store,
        4,
        AuthorityOp::AuthenticateHeadReceipt { receipt: tampered },
    );
    assert_eq!(
        tampered_response,
        AuthorityResponse::Refused(AuthorityRefusal::TokenBodyMismatch)
    );
    assert_eq!(updated.generation(), generation(2));

    let plan = FaultPlan::none();
    let report = check_and_emit(
        0xF004_C004,
        &plan,
        &recorder,
        AuthorityReferenceSpec::new(instance),
        "issued-but-stale tokens lose by predecessor mismatch; forged and tampered receipts are typed refusals",
    );
    expect_linearizable(&report);
}

#[test]
fn overlapping_multi_client_cas_race_has_exactly_one_winner() {
    let instance = StoreInstanceId::from_raw(0xF004_C005);
    let store = Arc::new(MemoryAuthorityStore::new(instance));
    let key = head_key("concurrent-cas");
    let mut recorder = HistoryRecorder::default();
    let predecessor = initialize(&mut recorder, store.as_ref(), &key);
    let left = AuthorityOp::CompareExchangeHead {
        key: key.clone(),
        expected: predecessor.token(),
        new_generation: generation(2),
        new_body: b"left".to_vec(),
    };
    let right = AuthorityOp::CompareExchangeHead {
        key,
        expected: predecessor.token(),
        new_generation: generation(2),
        new_body: b"right".to_vec(),
    };
    let left_id = recorder.invoke(1, left.clone());
    let right_id = recorder.invoke(2, right.clone());
    let barrier = Arc::new(Barrier::new(3));
    let (sender, receiver) = mpsc::channel();

    std::thread::scope(|scope| {
        for (client, operation_id, operation) in [(1, left_id, left), (2, right_id, right)] {
            let barrier = Arc::clone(&barrier);
            let sender = sender.clone();
            let store = Arc::clone(&store);
            scope.spawn(move || {
                barrier.wait();
                let response = store.execute(&operation);
                sender
                    .send((client, operation_id, response))
                    .expect("race observer remains alive");
            });
        }
        barrier.wait();
        drop(sender);

        for (client, operation_id, response) in receiver {
            recorder.respond(client, operation_id, response);
        }
    });

    let winners = recorder
        .raw_responses
        .iter()
        .filter(|response| {
            matches!(
                response,
                AuthorityResponse::CompareExchangeHead(CasOutcome::Committed(_))
            )
        })
        .count();
    assert_eq!(winners, 1, "exactly one overlapping CAS may commit");
    let plan = FaultPlan::none();
    let report = check_and_emit(
        0xF004_C005,
        &plan,
        &recorder,
        AuthorityReferenceSpec::new(instance),
        "two OS threads pass a barrier before racing their exact-predecessor CAS attempts",
    );
    expect_linearizable(&report);
}

#[cfg(test)]
#[derive(Debug)]
struct SeededDoubleSuccessStore {
    inner: MemoryAuthorityStore,
    first_commit: Mutex<Option<HeadReadReceipt>>,
}

#[cfg(test)]
impl SeededDoubleSuccessStore {
    fn new(instance: StoreInstanceId) -> Self {
        Self {
            inner: MemoryAuthorityStore::new(instance),
            first_commit: Mutex::new(None),
        }
    }

    fn first_commit(&self) -> std::sync::MutexGuard<'_, Option<HeadReadReceipt>> {
        self.first_commit
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
impl AuthorityStore for SeededDoubleSuccessStore {
    fn instance_id(&self) -> StoreInstanceId {
        self.inner.instance_id()
    }

    fn limits(&self) -> fgit_authority::AuthorityLimits {
        self.inner.limits()
    }

    fn put_if_absent(
        &self,
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        self.inner.put_if_absent(key, body)
    }

    fn read_immutable(&self, key: &ImmutableKey) -> Result<ImmutableRead, AuthorityFailure> {
        self.inner.read_immutable(key)
    }

    fn initialize_head(
        &self,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, AuthorityFailure> {
        self.inner.initialize_head(key, generation, body)
    }

    fn read_head(&self, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        self.inner.read_head(key)
    }

    fn compare_exchange_head(
        &self,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        match self
            .inner
            .compare_exchange_head(key, expected, new_generation, new_body)
        {
            Ok(CasOutcome::Committed(receipt)) => {
                *self.first_commit() = Some(receipt.clone());
                Ok(CasOutcome::Committed(receipt))
            }
            Ok(CasOutcome::PredecessorMismatch) => {
                self.first_commit()
                    .take()
                    .map_or(Ok(CasOutcome::PredecessorMismatch), |_| {
                        let receipt = HeadReadReceipt::new(
                            key.clone(),
                            AuthorityVersionToken::from_opaque_bytes([0xD0; 16]),
                            new_generation,
                            new_body.to_vec(),
                        );
                        Ok(CasOutcome::Committed(receipt))
                    })
            }
            Err(error) => Err(error),
        }
    }

    fn authenticate_head_receipt(
        &self,
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure> {
        self.inner.authenticate_head_receipt(receipt)
    }
}

#[test]
fn seeded_double_success_bug_is_caught_by_the_same_checker() {
    let seed = configured_seed(DEFAULT_SEED ^ 0xD0B1_E000);
    let instance = StoreInstanceId::from_raw(0xF004_C006);
    let store = SeededDoubleSuccessStore::new(instance);
    let key = head_key("planted-double-success");
    let mut recorder = HistoryRecorder::default();
    let predecessor = created_receipt(&recorder.execute(
        &store,
        0,
        AuthorityOp::InitializeHead {
            key: key.clone(),
            generation: HeadGeneration::FIRST,
            body: b"root".to_vec(),
        },
    ));
    let left = AuthorityOp::CompareExchangeHead {
        key: key.clone(),
        expected: predecessor.token(),
        new_generation: generation(2),
        new_body: seed.to_be_bytes().to_vec(),
    };
    let right = AuthorityOp::CompareExchangeHead {
        key,
        expected: predecessor.token(),
        new_generation: generation(2),
        new_body: seed.rotate_left(7).to_be_bytes().to_vec(),
    };
    let left_id = recorder.invoke(1, left.clone());
    let right_id = recorder.invoke(2, right.clone());
    let left_response = store.execute(&left);
    assert!(matches!(
        &left_response,
        AuthorityResponse::CompareExchangeHead(CasOutcome::Committed(_))
    ));
    recorder.respond(1, left_id, left_response);
    let right_response = store.execute(&right);
    assert!(matches!(
        &right_response,
        AuthorityResponse::CompareExchangeHead(CasOutcome::Committed(_))
    ));
    recorder.respond(2, right_id, right_response);

    let plan = FaultPlan::none();
    let history = recorder.history();
    let report = checker().check_authority(&AuthorityReferenceSpec::new(instance), &history);
    println!(
        "{}",
        evidence_ndjson(
            seed,
            &plan,
            &recorder,
            &history,
            &report,
            "test-only seeded backend fabricates a second CAS success from the first receipt",
        )
    );
    assert!(
        matches!(&report.verdict, CheckVerdict::NotLinearizable { .. }),
        "the planted double-success backend must be rejected: {report:?}"
    );
}

#[test]
fn lost_acknowledgement_resolution_exposes_the_seeded_double_success_bug() {
    let seed = configured_seed(DEFAULT_SEED ^ 0xD0B1_E001);
    let instance = StoreInstanceId::from_raw(0xF004_C008);
    let store = SeededDoubleSuccessStore::new(instance);
    let key = head_key("lost-ack-double-success");
    let mut recorder = HistoryRecorder::default();
    let predecessor = created_receipt(&recorder.execute(
        &store,
        0,
        AuthorityOp::InitializeHead {
            key: key.clone(),
            generation: HeadGeneration::FIRST,
            body: b"root".to_vec(),
        },
    ));
    let left = AuthorityOp::CompareExchangeHead {
        key: key.clone(),
        expected: predecessor.token(),
        new_generation: generation(2),
        new_body: b"left-after-lost-ack".to_vec(),
    };
    let right = AuthorityOp::CompareExchangeHead {
        key: key.clone(),
        expected: predecessor.token(),
        new_generation: generation(2),
        new_body: b"counterfeit-second-success".to_vec(),
    };
    let left_id = recorder.invoke(1, left.clone());
    let right_id = recorder.invoke(2, right.clone());

    let left_response = store.execute(&left);
    assert!(matches!(
        left_response,
        AuthorityResponse::CompareExchangeHead(CasOutcome::Committed(_))
    ));
    recorder.respond(
        1,
        left_id,
        AuthorityResponse::Ambiguous(AmbiguityReason::NoResponse),
    );

    let resolution = read_receipt(&recorder.execute(&store, 3, AuthorityOp::ReadHead { key }));
    assert_eq!(resolution.body(), b"left-after-lost-ack");

    let right_response = store.execute(&right);
    assert!(matches!(
        &right_response,
        AuthorityResponse::CompareExchangeHead(CasOutcome::Committed(receipt))
            if receipt.body() == b"counterfeit-second-success"
    ));
    recorder.respond(2, right_id, right_response);

    let plan = FaultPlan::none();
    let history = recorder.history();
    let report = checker().check_authority(&AuthorityReferenceSpec::new(instance), &history);
    println!(
        "{}",
        evidence_ndjson(
            seed,
            &plan,
            &recorder,
            &history,
            &report,
            "lost acknowledgement leaves the first CAS pending; recorded resolution forces its effect before a counterfeit second old-token success",
        )
    );
    assert!(
        matches!(&report.verdict, CheckVerdict::NotLinearizable { .. }),
        "the resolution-constrained lost-ack double-success history must be rejected: {report:?}"
    );
}

#[test]
fn immutable_fault_schedule_remains_linearizable_after_reordered_retries() {
    let instance = StoreInstanceId::from_raw(0xF004_C007);
    let store = MemoryAuthorityStore::new(instance);
    let key = immutable_key("reordered-retry");
    let mut recorder = HistoryRecorder::default();
    let plan = FaultPlan::explicit(vec![
        FaultDirective::new(
            OpIndex::ZERO,
            FaultKind::Delay {
                position: FaultPosition::BeforeEffect,
                ticks: 3,
            },
        )
        .only_for(fgit_authority::AuthorityOpKind::PutIfAbsent),
        FaultDirective::new(
            OpIndex::from_raw(1),
            FaultKind::DuplicateRequest {
                deliver: fgit_authority::DuplicateDelivery::First,
            },
        )
        .only_for(fgit_authority::AuthorityOpKind::ReadImmutable),
    ]);
    store.install_fault_plan(plan.clone());
    let put = recorder.execute(
        &store,
        2,
        AuthorityOp::PutIfAbsent {
            key: key.clone(),
            body: b"sealed-body".to_vec(),
        },
    );
    assert_eq!(put, AuthorityResponse::PutIfAbsent(PutOutcome::Created));
    let retry = recorder.execute(&store, 1, AuthorityOp::ReadImmutable { key });
    assert_eq!(
        retry,
        AuthorityResponse::ReadImmutable(ImmutableRead::Present(b"sealed-body".to_vec()))
    );
    let report = check_and_emit(
        0xF004_C007,
        &plan,
        &recorder,
        AuthorityReferenceSpec::new(instance),
        "reordered clients observe an immutable write once; duplicated reads cannot mutate it",
    );
    expect_linearizable(&report);
}

// ---------------------------------------------------------------------------
// Distributed / cell-level faults (frankengit-fg036b)
// ---------------------------------------------------------------------------
//
// The scenarios above are authority-shaped: one store, N clients, faults on the
// operation stream. These are cell-shaped, and they exist because fg036a landed
// typed read modes and readiness on the serving path, which gives a partition
// somewhere to be observed.
//
// Deliberately NOT re-covered here, because the file already proves them and a
// second copy would drift:
//   * an asymmetric partition that loses only the response ->
//     `lost_acknowledgement_after_cas_and_crash_point_preserve_pending_histories`
//   * crash after effect, then restart -> the same test
//   * an old token replayed, a fabricated receipt ->
//     `stale_token_and_malicious_receipt_attempts_are_linearized_or_refused`
//     and lincheck_authority_patterns' ABA and split-brain cases.

/// A cell that cannot reach the authority holds whatever it last authenticated.
///
/// Returns the generation gap between what the isolated cell still believes and
/// what the authority actually holds, which is the quantity a bounded-stale
/// label has to carry honestly.
const fn generation_lag(stale: &HeadReadReceipt, current: &HeadReadReceipt) -> u64 {
    current
        .generation()
        .get()
        .saturating_sub(stale.generation().get())
}

#[test]
fn an_isolated_cell_cannot_label_a_drifted_answer_as_current() {
    // The scenario fg036a made observable. A cell is partitioned from the
    // authority (its requests are lost, which is what isolation IS at this
    // layer) while a reachable cell keeps publishing. The isolated cell still
    // holds a receipt it authenticated legitimately -- it is not corrupt, it is
    // OLD -- and the question is what it is allowed to say about it.
    let instance = StoreInstanceId::from_raw(0xF036_B001);
    let store = MemoryAuthorityStore::new(instance);
    let key = head_key("isolated-cell");
    let mut recorder = HistoryRecorder::default();
    let root = initialize(&mut recorder, &store, &key);

    // The isolated cell authenticates once, while it still can.
    let held =
        read_receipt(&recorder.execute(&store, 1, AuthorityOp::ReadHead { key: key.clone() }));
    assert_eq!(held.generation(), HeadGeneration::FIRST);

    // A reachable cell advances the head three times.
    let mut predecessor = root;
    for step in 2..=4_u64 {
        predecessor = committed_receipt(&recorder.execute(
            &store,
            2,
            AuthorityOp::CompareExchangeHead {
                key: key.clone(),
                expected: predecessor.token(),
                new_generation: generation(step),
                new_body: format!("published-{step}").into_bytes(),
            },
        ));
    }
    let current = predecessor;
    assert_eq!(current.generation(), generation(4));

    // Now the partition: every request from the isolated cell is lost. This is
    // the symmetric case -- nothing reaches the authority, so the cell cannot
    // refresh at all. It is distinct from the lost-RESPONSE case above, where
    // the effect happens and only the acknowledgement is missing.
    let plan = FaultPlan::explicit(vec![
        FaultDirective::new(OpIndex::ZERO, FaultKind::LoseRequest)
            .only_for(fgit_authority::AuthorityOpKind::ReadHead),
    ]);
    store.install_fault_plan(plan.clone());
    let isolated = recorder.execute(&store, 1, AuthorityOp::ReadHead { key: key.clone() });
    assert_eq!(
        isolated,
        AuthorityResponse::Ambiguous(AmbiguityReason::NoResponse),
        "an isolated cell must not receive a head it did not reach the authority for"
    );

    // What the cell may now SAY. It is four generations behind, which no honest
    // label can describe as current.
    let lag = generation_lag(&held, &current);
    assert_eq!(lag, 3, "the isolated cell is three generations behind");

    // Inside its declared bound, bounded-stale is admissible and carries the
    // measurement, so a client can see exactly how far behind the answer is.
    let generous = StalenessBound::new(Duration::from_secs(600), 5);
    let labelled = ReadLabel::bounded_stale(
        generous,
        StalenessObservation::new(Duration::from_secs(30), lag),
    )
    .expect("three generations is inside a bound of five");
    assert!(
        !labelled.mode().claims_currentness(),
        "the whole point: a drifted answer must not claim to be current"
    );
    assert_eq!(
        labelled.observed().expect("measured").generation_lag(),
        lag,
        "and the client must be told the real distance, not the bound"
    );

    // Past the bound it cannot even be labelled. A cell that has drifted
    // further than it promised does not get to relabel the answer as something
    // weaker and serve it anyway -- it has to refuse.
    let tight = StalenessBound::new(Duration::from_secs(600), 2);
    assert!(
        matches!(
            ReadLabel::bounded_stale(
                tight,
                StalenessObservation::new(Duration::from_secs(30), lag)
            ),
            Err(CellRefusal::StalenessExceedsBound { .. })
        ),
        "drifting past the promised bound must refuse, not downgrade silently"
    );

    // And a cell in the state a partition puts it in cannot serve a current
    // read at all, independently of any bound.
    assert!(
        admits_read(CellState::DegradedRead, ReadMode::Current).is_err(),
        "a degraded cell must not serve a current read"
    );
    assert!(
        admits_read(CellState::DegradedRead, ReadMode::BoundedStale(generous)).is_ok(),
        "but it must still serve within an explicit bound, or the mode is pointless"
    );

    let report = check_and_emit(
        0xF036_B001,
        &plan,
        &recorder,
        AuthorityReferenceSpec::new(instance),
        "an isolated cell's read is pending, never a stale head presented as current",
    );
    expect_linearizable(&report);
}

#[test]
fn an_isolated_cell_that_reconnects_observes_no_lost_write() {
    // REACHABILITY loss and return -- deliberately not called region loss.
    //
    // What this exercises is a cell cut off from the authority while survivors
    // keep publishing, and what it observes on return. That is real, and it is
    // NOT the acceptance line's "region loss with visible-before-archive
    // durability states": that one is about DURABILITY STATE (impaired
    // placement, visible-but-not-archived), not about reachability, and an
    // in-memory store cannot stand in for it. I previously described this test
    // as region-loss evidence in a batch report, which inflated it; the
    // durability-state scenarios are tracked separately on the bead and this
    // comment exists so no future reader inherits the confusion.
    //
    // Zero acknowledged-write loss is the property here, and a reconnecting
    // reader is where a loss would show first.
    let instance = StoreInstanceId::from_raw(0xF036_B002);
    let store = MemoryAuthorityStore::new(instance);
    let key = head_key("region-loss");
    let mut recorder = HistoryRecorder::default();
    let root = initialize(&mut recorder, &store, &key);

    // Cut client 1 off. Only its reads are lost; the survivor's CAS traffic is
    // untouched, which is what an asymmetric region loss looks like from here.
    let partition = FaultPlan::explicit(vec![
        FaultDirective::new(OpIndex::ZERO, FaultKind::LoseRequest)
            .only_for(fgit_authority::AuthorityOpKind::ReadHead),
    ]);
    store.install_fault_plan(partition.clone());
    assert_eq!(
        recorder.execute(&store, 1, AuthorityOp::ReadHead { key: key.clone() }),
        AuthorityResponse::Ambiguous(AmbiguityReason::NoResponse),
        "the cell must actually be isolated, or the rest of this test proves nothing"
    );

    let mut predecessor = root;
    let mut acknowledged = Vec::new();
    for step in 2..=6_u64 {
        let body = format!("survivor-{step}").into_bytes();
        predecessor = committed_receipt(&recorder.execute(
            &store,
            2,
            AuthorityOp::CompareExchangeHead {
                key: key.clone(),
                expected: predecessor.token(),
                new_generation: generation(step),
                new_body: body.clone(),
            },
        ));
        acknowledged.push((generation(step), body));
    }
    assert!(
        !store.fault_log().is_empty(),
        "the partition must have injected at least one fault"
    );

    // Heal, and only now can the cell read again.
    store.install_fault_plan(FaultPlan::none());
    let rejoined = read_receipt(&recorder.execute(&store, 1, AuthorityOp::ReadHead { key }));

    let (last_generation, last_body) = acknowledged.last().expect("writes were acknowledged");
    assert_eq!(
        rejoined.generation(),
        *last_generation,
        "a returning cell must observe the newest acknowledged write, never an older head"
    );
    assert_eq!(rejoined.body(), last_body.as_slice());
    assert_eq!(
        rejoined.generation().get(),
        6,
        "every write acknowledged during the outage must survive it"
    );

    let report = check_and_emit(
        0xF036_B002,
        &partition,
        &recorder,
        AuthorityReferenceSpec::new(instance),
        "a cell rejoining after a real partition observes every acknowledged write and no rollback",
    );
    expect_linearizable(&report);
}

/// A body written by a build that knows a format this test's "old cell" does not.
const NEWER_FORMAT_BODY: &[u8] = b"\x00\x02newer-format-payload-the-old-cell-cannot-parse";

/// What a cell running the previous build would try to write.
const OLDER_FORMAT_BODY: &[u8] = b"\x00\x01older-format-payload";

#[test]
fn an_older_cell_holding_a_superseded_token_cannot_replace_the_head() {
    // The scenario a rolling upgrade produces: two cells running different
    // builds against one authority, with the newer one publishing first.
    //
    // NAMED FOR ITS MECHANISM, which is token supersession. The bodies below
    // are opaque blobs that nothing decodes -- their \x00\x02 / \x00\x01
    // prefixes only LOOK like version stamps -- so what stops the rollback here
    // is the CAS predecessor check, and this test would read identically if both
    // bodies were the same bytes. That is worth having, but it is not a
    // statement about formats, and the name used to say it was.
    // `a_head_from_a_newer_build_is_refused_by_version_and_the_cell_does_not_fall_back`
    // is the one that decodes genuinely versioned bytes through the production
    // reader.
    //
    // The guarantee is NOT that the old cell understands the new bytes -- it
    // cannot, and it is not asked to. It is that not understanding them gives it
    // no route to replace them. Rollback during a rolling upgrade is how a
    // deployment loses a write that was already acknowledged to a client.
    let instance = StoreInstanceId::from_raw(0xF036_B003);
    let store = MemoryAuthorityStore::new(instance);
    let key = head_key("mixed-version");
    let mut recorder = HistoryRecorder::default();
    let root = initialize(&mut recorder, &store, &key);

    // The OLD cell authenticates the head first, so it holds a legitimately
    // obtained token. This matters: the refusal below must not depend on the old
    // cell being malicious or confused. It is behaving correctly on stale
    // information, which is the realistic case.
    let old_cells_view =
        read_receipt(&recorder.execute(&store, 1, AuthorityOp::ReadHead { key: key.clone() }));
    assert_eq!(old_cells_view.generation(), HeadGeneration::FIRST);

    // The NEW cell publishes a body in a format the old build does not know.
    let published = committed_receipt(&recorder.execute(
        &store,
        2,
        AuthorityOp::CompareExchangeHead {
            key: key.clone(),
            expected: root.token(),
            new_generation: generation(2),
            new_body: NEWER_FORMAT_BODY.to_vec(),
        },
    ));
    assert_eq!(published.body(), NEWER_FORMAT_BODY);

    // The old cell now tries to publish, using the token it holds. It is not
    // attacking; it simply has not seen generation 2.
    let attempted_rollback = recorder.execute(
        &store,
        1,
        AuthorityOp::CompareExchangeHead {
            key: key.clone(),
            expected: old_cells_view.token(),
            new_generation: generation(2),
            new_body: OLDER_FORMAT_BODY.to_vec(),
        },
    );
    assert_eq!(
        attempted_rollback,
        AuthorityResponse::CompareExchangeHead(CasOutcome::PredecessorMismatch),
        "an old cell holding a superseded token must not be able to replace the head"
    );

    // NO ROLLBACK: the newer body is still there, byte for byte.
    let after =
        read_receipt(&recorder.execute(&store, 3, AuthorityOp::ReadHead { key: key.clone() }));
    assert_eq!(
        after.body(),
        NEWER_FORMAT_BODY,
        "the newer format must survive the older cell's attempt untouched"
    );
    assert_eq!(after.generation(), generation(2));

    // NO TORN SCHEMA: the stored bytes are exactly what the newer cell wrote,
    // with none of the older body mixed in. A partial overwrite would leave a
    // body that parses as neither format, which is worse than either.
    assert!(
        !after
            .body()
            .windows(OLDER_FORMAT_BODY.len())
            .any(|w| w == OLDER_FORMAT_BODY),
        "no fragment of the older write may appear in the published body"
    );
    assert_eq!(after.body().len(), NEWER_FORMAT_BODY.len());

    // THE PERMITTED TWIN. A refusal test alone is satisfied by an authority that
    // refuses everything, which would be a worse system, not a safer one. Having
    // lost, the old cell rereads and its next attempt succeeds -- §5.2's rule
    // that a CAS loser revalidates and retries rather than being locked out.
    // It is still an old cell writing an old-format body; being outdated is not
    // what disqualified it, holding a superseded token was.
    let revalidated =
        read_receipt(&recorder.execute(&store, 1, AuthorityOp::ReadHead { key: key.clone() }));
    let retried = committed_receipt(&recorder.execute(
        &store,
        1,
        AuthorityOp::CompareExchangeHead {
            key: key.clone(),
            expected: revalidated.token(),
            new_generation: generation(3),
            new_body: OLDER_FORMAT_BODY.to_vec(),
        },
    ));
    assert_eq!(retried.generation(), generation(3));
    assert_eq!(retried.body(), OLDER_FORMAT_BODY);

    let report = check_and_emit(
        0xF036_B003,
        &FaultPlan::none(),
        &recorder,
        AuthorityReferenceSpec::new(instance),
        "a rolling upgrade cannot roll back or tear a newer head; the loser revalidates and proceeds",
    );
    expect_linearizable(&report);
}

#[test]
fn a_crash_during_a_head_transition_never_leaves_a_half_published_head() {
    // "A read never observes a half-published head", which the existing crash
    // coverage does not reach: put_if_absent.rs and fault_determinism.rs crash
    // IMMUTABLE puts, and the campaign's own crash case above crashes a ReadHead.
    // Nothing crashed a head COMPARE-EXCHANGE, which is the transition that has
    // two fields to tear -- generation and body -- and is the only place a torn
    // head could come from.
    //
    // The property is not "the write survives" or "the write is lost". It is that
    // exactly one of those happened: generation and body must move TOGETHER. A
    // head carrying generation 2 with generation 1's body would verify against
    // nothing and be undiagnosable from the outside.
    let root_body = b"root".to_vec();
    let next_body = b"transition-target".to_vec();

    for position in [FaultPosition::BeforeEffect, FaultPosition::AfterEffect] {
        let instance = StoreInstanceId::from_raw(0xF036_B004);
        let store = MemoryAuthorityStore::new(instance);
        let key = head_key("torn-head");
        let mut recorder = HistoryRecorder::default();
        let root = initialize(&mut recorder, &store, &key);
        assert_eq!(root.body(), root_body.as_slice());

        let plan = FaultPlan::explicit(vec![
            FaultDirective::new(OpIndex::ZERO, FaultKind::Crash { position })
                .only_for(fgit_authority::AuthorityOpKind::CompareExchangeHead),
        ]);
        store.install_fault_plan(plan.clone());

        let interrupted = recorder.execute(
            &store,
            1,
            AuthorityOp::CompareExchangeHead {
                key: key.clone(),
                expected: root.token(),
                new_generation: generation(2),
                new_body: next_body.clone(),
            },
        );
        assert_eq!(
            interrupted,
            AuthorityResponse::Ambiguous(AmbiguityReason::NoResponse),
            "{position:?}: a crashed transition tells the caller nothing, which is why \
             the head's own consistency has to carry the guarantee"
        );
        assert!(store.is_crashed());
        store.restart();

        // The head after recovery must be one of exactly two whole values.
        let recovered =
            read_receipt(&recorder.execute(&store, 2, AuthorityOp::ReadHead { key: key.clone() }));
        let observed = (recovered.generation(), recovered.body().to_vec());
        let old_whole = (HeadGeneration::FIRST, root_body.clone());
        let new_whole = (generation(2), next_body.clone());
        assert!(
            observed == old_whole || observed == new_whole,
            "{position:?}: the head must be wholly old or wholly new, got generation {:?} \
             with body {:?}",
            recovered.generation(),
            String::from_utf8_lossy(recovered.body())
        );

        // And the pairing is the point, so state the two torn shapes explicitly
        // rather than relying on the disjunction above to have excluded them.
        assert_ne!(
            observed,
            (generation(2), root_body.clone()),
            "{position:?}: a new generation carrying the old body is a torn head"
        );
        assert_ne!(
            observed,
            (HeadGeneration::FIRST, next_body.clone()),
            "{position:?}: the old generation carrying the new body is a torn head"
        );

        // The crash position decides WHICH whole value survived, and the caller
        // can find out -- 5.2's rule that a disconnect never proves non-commit,
        // so the ambiguity is resolved by asking rather than by assuming.
        let resolution = resolve_ambiguous_cas(&store, &key, generation(2), &next_body);
        match position {
            FaultPosition::BeforeEffect => {
                assert_eq!(
                    observed, old_whole,
                    "a crash before the effect must leave the predecessor intact"
                );
                assert!(
                    matches!(resolution, Ok(fgit_authority::CasResolution::NotApplied(_))),
                    "and resolution must report the transition did not take effect, got {resolution:?}"
                );
            }
            FaultPosition::AfterEffect => {
                assert_eq!(
                    observed, new_whole,
                    "a crash after the effect must leave the transition applied"
                );
                assert!(
                    matches!(resolution, Ok(fgit_authority::CasResolution::Applied(_))),
                    "and resolution must report it did, got {resolution:?}"
                );
            }
        }

        let report = check_and_emit(
            0xF036_B004,
            &plan,
            &recorder,
            AuthorityReferenceSpec::new(instance),
            "a crash mid-transition leaves a whole head; the pending caller resolves it by asking",
        );
        expect_linearizable(&report);
    }
}

/// Run one fixed transition sequence on a fresh store and return what a reader
/// would see, so two runs separated in wall-clock time can be compared.
fn replay_fixed_sequence(instance_raw: u64, bodies: &[&[u8]]) -> Vec<(HeadGeneration, Vec<u8>)> {
    let instance = StoreInstanceId::from_raw(instance_raw);
    let store = MemoryAuthorityStore::new(instance);
    let key = head_key("clock-independence");
    let mut recorder = HistoryRecorder::default();
    let mut predecessor = initialize(&mut recorder, &store, &key);
    let mut observed = vec![(predecessor.generation(), predecessor.body().to_vec())];
    for (step, body) in bodies.iter().enumerate() {
        let next = u64::try_from(step).unwrap_or_default().saturating_add(2);
        predecessor = committed_receipt(&recorder.execute(
            &store,
            1,
            AuthorityOp::CompareExchangeHead {
                key: key.clone(),
                expected: predecessor.token(),
                new_generation: generation(next),
                new_body: (*body).to_vec(),
            },
        ));
        observed.push((predecessor.generation(), predecessor.body().to_vec()));
    }

    // Every history this file produces goes through the checker, including this
    // one. It previously did not -- it compared two head histories directly and
    // ran no linearizability check at all, which left one scenario outside the
    // fg004b oracle for no reason other than that it did not need faults.
    let report = check_and_emit(
        instance_raw,
        &FaultPlan::none(),
        &recorder,
        AuthorityReferenceSpec::new(instance),
        "a fixed operation sequence, checked like every other history in this campaign",
    );
    expect_linearizable(&report);

    observed
}

#[test]
fn the_head_history_is_a_pure_function_of_its_operations_not_of_the_clock() {
    // "Clock skew and rollback must not matter -- clocks are not authority."
    //
    // WHAT THIS CAN AND CANNOT DETECT, stated because the distinction decides
    // whether the test is worth having. HeadReadReceipt is {key, token,
    // generation, body}: there is no time field, so under the reference store
    // this assertion cannot fail today, and I am not claiming it proves the
    // system ignores clocks -- nothing here skews a clock, because there is no
    // clock to skew.
    //
    // What it IS: a regression guard with a specific, plausible target. If a
    // later implementation seeds a version token from a timestamp, stamps a
    // publication time into a head body, or orders transitions by arrival time
    // rather than by predecessor token, two identical sequences separated in wall
    // time stop agreeing and this fails. That is the change worth catching, and
    // it is the kind that arrives looking harmless.
    let bodies: [&[u8]; 3] = [b"one", b"two", b"three"];

    let first = replay_fixed_sequence(0xF036_B005, &bodies);
    // Separated in real wall-clock time, without sleeping: the two runs are at
    // different instants because they are sequential, which is all a clock
    // dependence would need to show itself.
    let second = replay_fixed_sequence(0xF036_B006, &bodies);

    assert_eq!(
        first, second,
        "the same operation sequence must produce the same head history regardless of when it ran"
    );
    assert_eq!(first.len(), 4, "one initial head plus three transitions");

    // The twin, so the equality above is not the equality of two empty or
    // constant things: a DIFFERENT sequence must produce a different history.
    let divergent: [&[u8]; 3] = [b"one", b"two", b"different"];
    let third = replay_fixed_sequence(0xF036_B007, &divergent);
    assert_ne!(
        first, third,
        "a different operation sequence must produce a different history, or the \
         comparison above is measuring nothing"
    );
    // And the divergence must be exactly where the inputs diverged, not earlier.
    assert_eq!(
        first[..3],
        third[..3],
        "the histories must agree up to the point the inputs differ"
    );
}

#[test]
fn the_cell_level_flow_is_linearizable_under_seeded_plans_and_replays_identically() {
    // Addresses two items from source review 3944 that my explicit-plan scenarios
    // did not cover: SEEDED REPLAY, and per-history checking of a seeded
    // cell-level flow rather than of the pre-existing read matrix.
    //
    // Why seeded matters when I already had explicit plans: an explicit directive
    // is a scenario I chose, so it can only find faults I thought of. A seeded
    // plan places faults across a span I did not pick, at positions I did not
    // enumerate, and the acceptance asks for replayability of exactly that.
    let base_seed = configured_seed(DEFAULT_SEED);
    let mut transcripts = Vec::new();

    for seed in [
        base_seed,
        base_seed.wrapping_add(7),
        base_seed ^ 0x0F03_6B00,
    ] {
        // Two runs per seed against fresh stores, to establish replay rather than
        // merely a pass. Same seed must reproduce the same fault log.
        let mut per_seed = Vec::new();
        for attempt in 0..2 {
            let instance = StoreInstanceId::from_raw(0xF036_B020 + attempt);
            let store = MemoryAuthorityStore::new(instance);
            let key = head_key("seeded-cell-flow");
            let mut recorder = HistoryRecorder::default();
            let root = initialize(&mut recorder, &store, &key);

            // The publisher runs BEFORE the seeded plan is installed, and that
            // ordering is the whole design of this scenario rather than a
            // convenience.
            //
            // A seeded plan places faults across positions I did not choose, and
            // one of those faults is DuplicateRequest. Duplicate delivery of a
            // MUTATION means one invocation with two effects: the first delivery
            // commits and the second returns PredecessorMismatch, so with
            // `deliver: Second` the caller is told its CAS lost while the head
            // actually advanced. No sequential specification can linearize that,
            // because the spec models one effect per invocation -- so the checker
            // correctly reports NotLinearizable and the finding is about the
            // FAULT MODEL, not about the store.
            //
            // I hit exactly that on the first version of this test and nearly
            // read it as a violation. The pre-existing seeded_fault_matrix case
            // already records the same constraint in its own note ("seeded plans
            // target reads so duplicate delivery and ambiguity preserve a
            // checkable client history"); this scenario honours it by faulting
            // only the read path. Mutation-side duplicate and lost delivery are
            // covered with EXPLICIT plans elsewhere in this file, where the
            // outcome is asserted directly instead of through the spec.
            let mut predecessor = root;
            for step in 0..3_u64 {
                let next = predecessor.generation().get().saturating_add(1);
                predecessor = committed_receipt(&recorder.execute(
                    &store,
                    2,
                    AuthorityOp::CompareExchangeHead {
                        key: key.clone(),
                        expected: predecessor.token(),
                        new_generation: generation(next),
                        new_body: format!("seeded-{step}").into_bytes(),
                    },
                ));
            }
            let published = (predecessor.generation(), predecessor.body().to_vec());

            let plan = FaultPlan::seeded(seed, 10, 5);
            store.install_fault_plan(plan.clone());

            // Now the cell-level READ path under faults the seed placed: a cell
            // that was isolated, and cells returning afterwards.
            for client in 3..=6_u64 {
                let _observed =
                    recorder.execute(&store, client, AuthorityOp::ReadHead { key: key.clone() });
            }

            // Whatever the seed did to the reads, the published state stands.
            //
            // RETRIED, because the settled read is itself inside the fault
            // plan's blast radius. This assumed a definite answer and got one
            // under the default seed; under the e2e suite's seed the settled
            // read was itself faulted and came back Ambiguous(NoResponse),
            // which is a genuine outcome and not a failure. §5.2 is explicit
            // that an ambiguous result proves nothing either way, so the only
            // correct client response -- and the only sound thing for an
            // assertion to do -- is revalidate rather than treat it as an
            // answer. The plan places finitely many faults, so a bounded retry
            // terminates.
            let mut settled = None;
            for attempt in 7..7 + 32_u64 {
                if let AuthorityResponse::ReadHead(HeadRead::Present(receipt)) =
                    recorder.execute(&store, attempt, AuthorityOp::ReadHead { key: key.clone() })
                {
                    settled = Some(receipt);
                    break;
                }
            }
            let settled =
                settled.expect("a bounded retry must eventually get a definite read back");
            assert_eq!(
                (settled.generation(), settled.body().to_vec()),
                published,
                "seeded read-path faults must not alter what was published"
            );
            assert!(
                !store.fault_log().is_empty(),
                "the seeded plan must have injected at least one fault"
            );

            assert_eq!(plan.seed(), Some(seed));
            let report = check_and_emit(
                seed,
                &plan,
                &recorder,
                AuthorityReferenceSpec::new(instance),
                "seeded cell-level flow: isolated reader, publisher, returning reader",
            );
            expect_linearizable(&report);

            // EXECUTED evidence, not the plan. Comparing fault_script_json(&plan)
            // would compare what the generator INTENDED and prove only that
            // FaultPlan::seeded is deterministic -- a property of the generator,
            // not of the run. store.fault_log() is the record of faults that
            // actually fired, in order, with the operation index and kind each
            // one hit. That is what "replays identically" has to mean.
            // MEASURED, not assumed: for these three seeds the plan declares 5
            // directives and only 1, 2 and 3 of them respectively ever fire. A
            // directive is a CONDITIONAL ("the nth occurrence of kind K"), so a
            // plan is a set of standing offers and the log is the subset that
            // was taken. Two thirds of this plan never executes.
            //
            // That is why comparing fault_script_json(&plan) across two runs of
            // one seed was the wrong evidence, and close to tautological: the
            // same generator on the same seed emits the same directives BY
            // CONSTRUCTION, without the executor being involved at all. Such a
            // comparison cannot fail on executor nondeterminism, which is the
            // only thing "replays identically" is about. The log can: it carries
            // the firing order and the op_kind each fault actually struck, both
            // resolved during the run and absent from the plan.
            per_seed.push(
                store
                    .fault_log()
                    .records()
                    .iter()
                    .map(|record| {
                        format!(
                            "{}:{:?}:{:?}:{:?}",
                            record.sequence, record.at, record.op_kind, record.kind
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("|"),
            );
        }

        // REPLAY: the same seed must have FIRED the same faults both times, in
        // the same order, against the same operations.
        assert_eq!(
            per_seed[0], per_seed[1],
            "seed {seed:#x} executed two different fault sequences, so the run is not replayable"
        );
        assert!(
            !per_seed[0].is_empty(),
            "seed {seed:#x} fired no faults at all, so comparing two empty logs proves nothing"
        );
        transcripts.push(per_seed.remove(0));
    }

    // And the seed must MATTER, or "replayable" is the replayability of a
    // constant. Distinct seeds must not all yield the same script.
    let mut distinct = transcripts.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert!(
        distinct.len() > 1,
        "every seed executed an identical fault sequence, so seeding is doing nothing"
    );
}

#[test]
fn a_process_pause_around_a_cas_changes_no_outcome() {
    // GC-pause simulation, the acceptance item I previously said was "expressible
    // with FaultKind::Delay and I did not do it". Doing it.
    //
    // A pause is not a fault in the sense the other cases are: nothing is lost,
    // corrupted or reordered. The operation simply takes longer, which is exactly
    // what a stop-the-world collection looks like from outside. So the property is
    // the strongest available one -- the outcome must be IDENTICAL to the
    // unpaused run, not merely still linearizable.
    let baseline = {
        let instance = StoreInstanceId::from_raw(0xF036_B030);
        let store = MemoryAuthorityStore::new(instance);
        let key = head_key("gc-pause");
        let mut recorder = HistoryRecorder::default();
        let root = initialize(&mut recorder, &store, &key);
        let committed = committed_receipt(&recorder.execute(
            &store,
            1,
            AuthorityOp::CompareExchangeHead {
                key: key.clone(),
                expected: root.token(),
                new_generation: generation(2),
                new_body: b"after-pause".to_vec(),
            },
        ));
        let report = check_and_emit(
            0xF036_B030,
            &FaultPlan::none(),
            &recorder,
            AuthorityReferenceSpec::new(instance),
            "unpaused control for the GC-pause comparison",
        );
        expect_linearizable(&report);
        (committed.generation(), committed.body().to_vec())
    };

    for position in [FaultPosition::BeforeEffect, FaultPosition::AfterEffect] {
        let instance = StoreInstanceId::from_raw(0xF036_B031);
        let store = MemoryAuthorityStore::new(instance);
        let key = head_key("gc-pause");
        let mut recorder = HistoryRecorder::default();
        let root = initialize(&mut recorder, &store, &key);

        let plan = FaultPlan::explicit(vec![
            FaultDirective::new(OpIndex::ZERO, FaultKind::Delay { position, ticks: 9 })
                .only_for(fgit_authority::AuthorityOpKind::CompareExchangeHead),
        ]);
        store.install_fault_plan(plan.clone());

        let paused = committed_receipt(&recorder.execute(
            &store,
            1,
            AuthorityOp::CompareExchangeHead {
                key: key.clone(),
                expected: root.token(),
                new_generation: generation(2),
                new_body: b"after-pause".to_vec(),
            },
        ));

        assert_eq!(
            (paused.generation(), paused.body().to_vec()),
            baseline,
            "{position:?}: a pause around the CAS changed the committed outcome"
        );
        assert!(
            !store.fault_log().is_empty(),
            "{position:?}: the pause must actually have been injected, or this run is the \
             control again"
        );

        let report = check_and_emit(
            0xF036_B031,
            &plan,
            &recorder,
            AuthorityReferenceSpec::new(instance),
            "a stop-the-world pause around a CAS: same outcome, still linearizable",
        );
        expect_linearizable(&report);
    }
}

/// The head body a NEWER build publishes: every field this build knows, plus
/// one it does not, stamped at the next schema minor.
///
/// This exists because the version skew in
/// `an_older_cell_cannot_roll_back_a_head_written_in_a_newer_format` was
/// decorative. That test's `NEWER_FORMAT_BODY` is a hand-written ASCII blob
/// whose `\x00\x02` prefix merely LOOKS like a version stamp; nothing decodes
/// it, so the refusal it observes is a CAS token mismatch and would be
/// identical if both bodies were the same bytes. It is a sound CAS test wearing
/// version-skew clothing, and its name promised a guarantee its mechanism never
/// exercised.
struct NewerMinorHead(RepositoryAuthorityHeadBody);

impl CanonicalBody for NewerMinorHead {
    const DOMAIN: DomainTag = RepositoryAuthorityHeadBody::DOMAIN;
    const SCHEMA_FAMILY: SchemaFamily = RepositoryAuthorityHeadBody::SCHEMA_FAMILY;
    const SCHEMA_MAJOR: u16 = RepositoryAuthorityHeadBody::SCHEMA_MAJOR;
    // The ONLY difference from a body this build writes. Everything else --
    // domain, family, major, and every known field below -- is held identical,
    // so a refusal can be attributed to the minor and to nothing else.
    const SCHEMA_MINOR: u16 = RepositoryAuthorityHeadBody::SCHEMA_MINOR + 1;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.0.write_payload(out)?;
        // The field the older build has no name for.
        out.write_scalar(0xFFFF_u16);
        Ok(())
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let inner = RepositoryAuthorityHeadBody::read_payload(input)?;
        let _unknown: u16 = input.read_scalar("unknown_future_field")?;
        Ok(Self(inner))
    }
}

/// A head body at the generation given, in the schema minor this build writes.
fn current_minor_head_bytes(at: HeadGeneration) -> Vec<u8> {
    let mut body = fgit_codec::harness::genesis_head();
    body.generation = at;
    encode_body(&body).expect("a current-minor head body encodes")
}

/// The same head, at the same generation, one schema minor ahead.
fn newer_minor_head_bytes(at: HeadGeneration) -> Vec<u8> {
    let mut body = fgit_codec::harness::genesis_head();
    body.generation = at;
    encode_body(&NewerMinorHead(body)).expect("a newer-minor head body encodes")
}

#[test]
fn a_head_from_a_newer_build_is_refused_by_version_and_the_cell_does_not_fall_back() {
    // The mixed-version half of `frankengit-fg036b`, exercised through the real
    // production reader rather than narrated with opaque blobs.
    //
    // Two cells run different builds against one authority during a rolling
    // upgrade. The newer one publishes first. The older one must (a) fail to
    // read the body, (b) fail SPECIFICALLY on the version rather than
    // misreading it as some other fault, and (c) not use that failure as a
    // reason to reinstate the head it can read. (c) is the §5.5 requirement --
    // "never silently roll back to an older valid root" -- and it is the half a
    // refusal-only test skips.
    let instance = StoreInstanceId::from_raw(0xF036_B009);
    let store = MemoryAuthorityStore::new(instance);
    let key = head_key("mixed-version-decoded");
    let mut recorder = HistoryRecorder::default();
    let root = initialize(&mut recorder, &store, &key);

    // The older cell authenticates while the head is still one it can read, so
    // it holds a legitimately obtained token. Nothing here depends on it being
    // malicious or confused; it is correct code on stale information.
    let old_cells_view =
        read_receipt(&recorder.execute(&store, 1, AuthorityOp::ReadHead { key: key.clone() }));

    // The newer cell publishes a genuinely encoded body one schema minor ahead.
    let newer = newer_minor_head_bytes(generation(2));
    let published = committed_receipt(&recorder.execute(
        &store,
        2,
        AuthorityOp::CompareExchangeHead {
            key: key.clone(),
            expected: root.token(),
            new_generation: generation(2),
            new_body: newer.clone(),
        },
    ));

    // (a) and (b). The old cell authenticates the receipt -- authentication is
    // about provenance and still succeeds -- and then decodes, which is where
    // the skew lands.
    let authenticated = AuthenticatedHead::new(published, instance);
    let refusal = authenticated
        .body()
        .expect_err("a head one schema minor ahead must not decode");
    let HeadBodyRefusal::Codec(CodecRefusal::SchemaMinorUnsupported {
        observed,
        supported,
        ..
    }) = refusal
    else {
        panic!("expected a schema-minor refusal, got {refusal:?}");
    };
    assert_eq!(
        (observed, supported),
        (
            RepositoryAuthorityHeadBody::SCHEMA_MINOR + 1,
            RepositoryAuthorityHeadBody::SCHEMA_MINOR
        ),
        "the refusal must name the minor it saw and the one this build implements"
    );

    // THE PERMITTED TWIN, at the exact boundary. The same head, same
    // generation, same fields, differing ONLY in the schema minor, decodes and
    // agrees with the receipt. Without this the test above is satisfied by a
    // reader that refuses every head.
    let twin_store = MemoryAuthorityStore::new(instance);
    let twin_key = head_key("mixed-version-twin");
    let mut twin_recorder = HistoryRecorder::default();
    let twin_root = initialize(&mut twin_recorder, &twin_store, &twin_key);
    let twin = committed_receipt(&twin_recorder.execute(
        &twin_store,
        2,
        AuthorityOp::CompareExchangeHead {
            key: twin_key.clone(),
            expected: twin_root.token(),
            new_generation: generation(2),
            new_body: current_minor_head_bytes(generation(2)),
        },
    ));
    let readable = AuthenticatedHead::new(twin, instance)
        .body()
        .expect("the same head at this build's minor decodes");
    assert_eq!(
        readable.generation,
        generation(2),
        "and it agrees with the generation the receipt authenticated"
    );

    // (c) NO FALL-BACK. Not understanding the head gives the old cell no route
    // to replace it: its token was superseded by the newer cell's publish.
    let attempted = recorder.execute(
        &store,
        1,
        AuthorityOp::CompareExchangeHead {
            key: key.clone(),
            expected: old_cells_view.token(),
            new_generation: generation(2),
            new_body: current_minor_head_bytes(generation(2)),
        },
    );
    assert_eq!(
        attempted,
        AuthorityResponse::CompareExchangeHead(CasOutcome::PredecessorMismatch),
        "a cell that cannot read the head must not be able to replace it either"
    );

    // The unreadable-but-authoritative body is still there, byte for byte. An
    // implementation that treated an undecodable head as absent, or that
    // reinstated the last body it understood, fails exactly here.
    let after =
        read_receipt(&recorder.execute(&store, 3, AuthorityOp::ReadHead { key: key.clone() }));
    assert_eq!(
        after.body(),
        newer.as_slice(),
        "the newer-format head must survive an older cell that cannot read it"
    );
    assert_eq!(after.generation(), generation(2));

    // LINEARIZABILITY, because the acceptance line says every scenario and this
    // one was recording a history without ever checking it. A version refusal
    // is not exempt from the head history having a sequential explanation: the
    // interesting risk here is precisely that a refusal path leaves the head in
    // a state no ordering of these operations could produce.
    let report =
        checker().check_authority(&AuthorityReferenceSpec::new(instance), &recorder.history());
    expect_linearizable(&report);
    assert!(
        report.completed_operations != 0,
        "an empty history linearizes trivially, so the check above must have seen work"
    );
}
