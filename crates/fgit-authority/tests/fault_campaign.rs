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

use fgit_authority::history::{
    ClientId as HistoryClientId, HistoryEvent, LogicalTime, OperationId,
};
use fgit_authority::lincheck::{
    AuthorityHistory, CheckLimits, CheckReport, CheckVerdict, LinearizabilityChecker,
    SequentialSpec,
};
use fgit_authority::{
    AmbiguityReason, AuthenticatedHead, AuthorityFailure, AuthorityOp, AuthorityRefusal,
    AuthorityResponse, AuthorityStore, AuthorityVersionToken, CasOutcome, FaultDirective,
    FaultKind, FaultPlan, FaultPosition, FaultableAuthorityStore, HeadGeneration, HeadInit,
    HeadKey, HeadRead, HeadReadReceipt, ImmutableKey, ImmutableRead, MemoryAuthorityStore, OpIndex,
    PutOutcome, StoreInstanceId, resolve_ambiguous_cas,
};
use fgit_types::cell::{
    CellRefusal, CellState, ReadLabel, ReadMode, StalenessBound, StalenessObservation, admits_read,
};

const DEFAULT_SEED: u64 = 0xF004_C001_5EED_0001;

#[derive(Clone, Debug, Eq, PartialEq)]
struct IssuedVersion {
    key: HeadKey,
    generation: HeadGeneration,
    body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthorityModelState {
    immutable: BTreeMap<ImmutableKey, Vec<u8>>,
    heads: BTreeMap<HeadKey, HeadReadReceipt>,
    issued: BTreeMap<AuthorityVersionToken, IssuedVersion>,
    next_issuance: u64,
}

impl AuthorityModelState {
    fn mint_receipt(
        &mut self,
        key: HeadKey,
        generation: HeadGeneration,
        body: Vec<u8>,
    ) -> HeadReadReceipt {
        let mut bytes = [0_u8; 16];
        bytes[..8].copy_from_slice(b"fgithist");
        bytes[8..].copy_from_slice(&self.next_issuance.to_be_bytes());
        self.next_issuance = self.next_issuance.saturating_add(1);
        let token = AuthorityVersionToken::from_opaque_bytes(bytes);
        self.issued.insert(
            token,
            IssuedVersion {
                key: key.clone(),
                generation,
                body: body.clone(),
            },
        );
        HeadReadReceipt::new(key, token, generation, body)
    }
}

#[derive(Clone, Copy, Debug)]
struct AuthorityModel {
    instance: StoreInstanceId,
}

impl AuthorityModel {
    const fn new(instance: StoreInstanceId) -> Self {
        Self { instance }
    }
}

impl SequentialSpec for AuthorityModel {
    type State = AuthorityModelState;
    type Operation = AuthorityOp;
    type Response = AuthorityResponse;

    fn initial_state(&self) -> Self::State {
        AuthorityModelState {
            immutable: BTreeMap::new(),
            heads: BTreeMap::new(),
            issued: BTreeMap::new(),
            next_issuance: 0,
        }
    }

    fn apply(
        &self,
        state: &Self::State,
        operation: &Self::Operation,
    ) -> (Self::State, Self::Response) {
        let mut next = state.clone();
        match operation {
            AuthorityOp::PutIfAbsent { key, body } => {
                let response = match next.immutable.get(key) {
                    Some(existing) if existing == body => {
                        AuthorityResponse::PutIfAbsent(PutOutcome::IdenticalRetry)
                    }
                    Some(_) => AuthorityResponse::PutIfAbsent(PutOutcome::Conflict),
                    None => {
                        next.immutable.insert(key.clone(), body.clone());
                        AuthorityResponse::PutIfAbsent(PutOutcome::Created)
                    }
                };
                (next, response)
            }
            AuthorityOp::ReadImmutable { key } => {
                let response = next.immutable.get(key).map_or_else(
                    || AuthorityResponse::ReadImmutable(ImmutableRead::Absent),
                    |body| AuthorityResponse::ReadImmutable(ImmutableRead::Present(body.clone())),
                );
                (next, response)
            }
            AuthorityOp::InitializeHead {
                key,
                generation,
                body,
            } => {
                let response = match next.heads.get(key) {
                    Some(existing)
                        if existing.generation() == *generation && existing.body() == body =>
                    {
                        AuthorityResponse::InitializeHead(HeadInit::IdenticalRetry(
                            existing.clone(),
                        ))
                    }
                    Some(_) => AuthorityResponse::InitializeHead(HeadInit::Conflict),
                    None => {
                        let receipt = next.mint_receipt(key.clone(), *generation, body.clone());
                        next.heads.insert(key.clone(), receipt.clone());
                        AuthorityResponse::InitializeHead(HeadInit::Created(receipt))
                    }
                };
                (next, response)
            }
            AuthorityOp::ReadHead { key } => {
                let response = next.heads.get(key).map_or_else(
                    || AuthorityResponse::ReadHead(HeadRead::Absent),
                    |receipt| AuthorityResponse::ReadHead(HeadRead::Present(receipt.clone())),
                );
                (next, response)
            }
            AuthorityOp::CompareExchangeHead {
                key,
                expected,
                new_generation,
                new_body,
            } => {
                let response = match next.issued.get(expected) {
                    None => AuthorityResponse::Refused(AuthorityRefusal::UnknownVersionToken),
                    Some(issued) if issued.key != *key => {
                        AuthorityResponse::Refused(AuthorityRefusal::TokenKeyMismatch)
                    }
                    Some(_) => match next.heads.get(key).cloned() {
                        None => AuthorityResponse::Refused(AuthorityRefusal::HeadAbsent),
                        Some(current) if current.token() != *expected => {
                            AuthorityResponse::CompareExchangeHead(CasOutcome::PredecessorMismatch)
                        }
                        Some(current) if *new_generation <= current.generation() => {
                            AuthorityResponse::Refused(AuthorityRefusal::NonMonotoneGeneration {
                                current: current.generation(),
                                proposed: *new_generation,
                            })
                        }
                        Some(_) => {
                            let receipt =
                                next.mint_receipt(key.clone(), *new_generation, new_body.clone());
                            next.heads.insert(key.clone(), receipt.clone());
                            AuthorityResponse::CompareExchangeHead(CasOutcome::Committed(receipt))
                        }
                    },
                };
                (next, response)
            }
            AuthorityOp::AuthenticateHeadReceipt { receipt } => {
                let response = match next.issued.get(&receipt.token()) {
                    None => AuthorityResponse::Refused(AuthorityRefusal::UnknownVersionToken),
                    Some(issued) if issued.key != *receipt.key() => {
                        AuthorityResponse::Refused(AuthorityRefusal::TokenKeyMismatch)
                    }
                    Some(issued) if issued.generation != receipt.generation() => {
                        AuthorityResponse::Refused(AuthorityRefusal::TokenGenerationMismatch)
                    }
                    Some(issued) if issued.body.as_slice() != receipt.body() => {
                        AuthorityResponse::Refused(AuthorityRefusal::TokenBodyMismatch)
                    }
                    Some(_) => AuthorityResponse::AuthenticateHeadReceipt(AuthenticatedHead::new(
                        receipt.clone(),
                        self.instance,
                    )),
                };
                (next, response)
            }
        }
    }
}

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
    model: AuthorityModel,
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
            AuthorityModel::new(instance),
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
        AuthorityModel::new(instance),
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
        AuthorityModel::new(crash_instance),
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
        AuthorityModel::new(instance),
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
        AuthorityModel::new(instance),
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
    let report = checker().check_authority(&AuthorityModel::new(instance), &history);
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
    let report = checker().check_authority(&AuthorityModel::new(instance), &history);
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
        AuthorityModel::new(instance),
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
fn generation_lag(stale: &HeadReadReceipt, current: &HeadReadReceipt) -> u64 {
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
        AuthorityModel::new(instance),
        "an isolated cell's read is pending, never a stale head presented as current",
    );
    expect_linearizable(&report);
}

#[test]
fn an_isolated_cell_that_reconnects_observes_no_lost_write() {
    // Region loss and return. While a cell is genuinely cut off, the survivors
    // keep publishing; when the partition heals it must observe EVERY committed
    // write, never a rolled-back or torn view. Zero acknowledged-write loss is
    // the acceptance line, and a reconnecting reader is where a loss shows first.
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
        AuthorityModel::new(instance),
        "a cell rejoining after a real partition observes every acknowledged write and no rollback",
    );
    expect_linearizable(&report);
}
