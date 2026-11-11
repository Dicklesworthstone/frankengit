//! Reference-store qualification of canonical frontier proofs. These fixtures
//! authenticate their heads and publish real checkpoint edges through head CAS;
//! their check payloads are synthetic, not native runner execution evidence.
use super::super::{
    MAX_HISTORY_STEPS, MAX_SCAN_BATCHES, MAX_SCAN_BYTES, MAX_SCAN_EVENTS, verify_at,
};
use super::*;
use crate::merge::native::protection::candidate_checks::observation_matcher;
use crate::merge::native::storage::checkpoint_test_support::stage_checkpoint;
use fgit_authority::{
    AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityStore, AuthorityVersionToken,
    CasOutcome, HeadInit, HeadKey, HeadRead, HeadReadReceipt, ImmutableKey, ImmutableRead,
    MemoryAuthorityStore, PublicationOutcome, PutOutcome, StoreInstanceId,
    collect_cumulative_outcomes, outcome_index_root, publish_decisions,
};
use fgit_chronicle::{PublicationPlan, ResultingRoots};
use fgit_codec::{CanonicalOutboxState, CryptoBodyIdentity, encode_body, harness::genesis_head};
use fgit_forge::event::protection::{RequiredCandidateWorkflowCheck, RequiredWorkflowCheck};
use fgit_forge::event::review::{CandidateBinding, ReviewSubject};
use fgit_forge::event::workflow_check::candidate::CandidateWorkflowCheckRecord;
use fgit_forge::event::workflow_check::{
    NativeWorkflowCheck, WorkflowCheckConclusion, WorkflowCheckRecord,
};
use fgit_forge::{ForgeEvent, ForgeEventBatch, PullRequestNumber};
use fgit_types::{
    GitHashAlgorithm, GitOid, PolicyEpoch, PrincipalId, RefName, RepositoryId, TenantId,
};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

fn run<F: Future>(future: F) -> F::Output {
    match Box::pin(future)
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("reference store operations do not suspend"),
    }
}

struct Store {
    memory: MemoryAuthorityStore,
    missing: Mutex<Option<ImmutableKey>>,
    corrupt: Mutex<Option<ImmutableKey>>,
    reads: AtomicUsize,
    read_keys: Mutex<Vec<ImmutableKey>>,
}
impl AsyncAuthorityStore for Store {
    type Context = ();
    fn instance_id(&self) -> StoreInstanceId {
        self.memory.instance_id()
    }
    fn limits(&self) -> AuthorityLimits {
        self.memory.limits()
    }
    fn put_if_absent(
        &self,
        (): &(),
        key: &ImmutableKey,
        body: &[u8],
    ) -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> + Send {
        std::future::ready(self.memory.put_if_absent(key, body))
    }
    fn read_immutable(
        &self,
        (): &(),
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.read_keys.lock().unwrap().push(key.clone());
        if self.missing.lock().unwrap().as_ref() == Some(key) {
            return std::future::ready(Ok(ImmutableRead::Absent));
        }
        if self.corrupt.lock().unwrap().as_ref() == Some(key) {
            return std::future::ready(Ok(ImmutableRead::Present(vec![1, 2, 3])));
        }
        std::future::ready(self.memory.read_immutable(key))
    }
    fn initialize_head(
        &self,
        (): &(),
        key: &HeadKey,
        generation: fgit_types::HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        std::future::ready(self.memory.initialize_head(key, generation, body))
    }
    fn read_head(
        &self,
        (): &(),
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send {
        std::future::ready(self.memory.read_head(key))
    }
    fn compare_exchange_head(
        &self,
        (): &(),
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: fgit_types::HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        std::future::ready(
            self.memory
                .compare_exchange_head(key, expected, generation, body),
        )
    }
    fn authenticate_head_receipt(
        &self,
        (): &(),
        receipt: &HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send {
        std::future::ready(self.memory.authenticate_head_receipt(receipt))
    }
}

fn check(
    format: GitHashAlgorithm,
    attempt: u8,
    job: &str,
    conclusion: WorkflowCheckConclusion,
) -> NativeWorkflowCheck {
    NativeWorkflowCheck {
        actor: PrincipalId::from_bytes([7; 16]),
        record: WorkflowCheckRecord {
            source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
            source_commit: GitOid::from_hex(format, &"11".repeat(format.digest_len())).unwrap(),
            run_id: [4; 32],
            attempt_id: [attempt; 32],
            graph_root: [6; 32],
            job: job.into(),
            conclusion,
            evidence: b"reference check; not an execution attestation".to_vec(),
        },
    }
}

fn event(check: &NativeWorkflowCheck) -> ForgeEvent {
    check
        .record
        .proposed_event(check.actor, check.record.source_commit.algorithm())
        .unwrap()
}

fn requirement(check: &NativeWorkflowCheck) -> RequiredWorkflowCheck {
    RequiredWorkflowCheck {
        source_ref: check.record.source_ref.clone(),
        publisher: check.actor,
        graph_root: check.record.graph_root,
        job: check.record.job.clone(),
    }
}

fn matcher(
    template: &NativeWorkflowCheck,
    jobs: &[&str],
) -> impl FnMut(&ForgeEventPayload) -> Result<bool, ProjectionFailure> + Clone + Send {
    let template = template.clone();
    let mut jobs: Vec<String> = jobs.iter().map(|job| (*job).to_owned()).collect();
    move |payload| {
        let ForgeEventPayload::WorkflowCheckObservedNative(observed) = payload else {
            return Ok(false);
        };
        if observed.actor != template.actor
            || observed.record.source_ref != template.record.source_ref
            || observed.record.source_commit != template.record.source_commit
            || observed.record.graph_root != template.record.graph_root
        {
            return Ok(false);
        }
        if let Some(index) = jobs.iter().position(|job| *job == observed.record.job) {
            if observed.record.conclusion != WorkflowCheckConclusion::Success {
                return Err(ProjectionFailure::Refuse(
                    RefusalCode::ProtectedRefTransitionDenied,
                ));
            }
            jobs.remove(index);
        }
        Ok(jobs.is_empty())
    }
}

struct Fixture {
    store: Store,
    key: HeadKey,
    basis: PublicationBasis,
    position_key: ImmutableKey,
    event_keys: Vec<ImmutableKey>,
    frame_bytes: usize,
    event_count: usize,
    last_capsule_key: Option<ImmutableKey>,
}
impl Fixture {
    fn new(events: Vec<ForgeEvent>, grouped: bool) -> Self {
        Self::with_positions(events, grouped, |_| {})
    }

    fn with_positions(
        events: Vec<ForgeEvent>,
        grouped: bool,
        alter: impl FnOnce(&mut Vec<ForgePositionStateEntry>),
    ) -> Self {
        Self::assemble(events, grouped, false, alter)
    }

    fn published(events: Vec<ForgeEvent>) -> Self {
        Self::assemble(events, true, true, |_| {})
    }

    fn assemble(
        events: Vec<ForgeEvent>,
        grouped: bool,
        publish: bool,
        alter: impl FnOnce(&mut Vec<ForgePositionStateEntry>),
    ) -> Self {
        let store = Store {
            memory: MemoryAuthorityStore::new(StoreInstanceId::from_raw(0xc4ed)),
            missing: Mutex::new(None),
            corrupt: Mutex::new(None),
            reads: AtomicUsize::new(0),
            read_keys: Mutex::new(Vec::new()),
        };
        let repository = RepositoryId::from_bytes([0x34; 16]);
        let event_count = events.len();
        let batches = if grouped {
            vec![ForgeEventBatch { events }]
        } else {
            events.into_iter().map(ForgeEventBatch::of_one).collect()
        };
        let mut entries = BTreeMap::new();
        let mut event_keys = Vec::new();
        let mut event_roots = Vec::new();
        let mut frame_bytes = 0;
        for batch in batches {
            let root = run(storage::stage_body(
                &store,
                &(),
                repository,
                storage::EVENT_NAMESPACE,
                &batch,
            ))
            .unwrap();
            event_roots.push(root);
            frame_bytes += encode_body(&batch).unwrap().len();
            event_keys.push(storage::body_key(storage::EVENT_NAMESPACE, repository, root).unwrap());
            for event in &batch.events {
                let stream = storage::aggregate_label(event.aggregate).unwrap();
                entries.insert(
                    stream,
                    ForgePositionStateEntry::try_new(stream, 0, 1, root).unwrap(),
                );
            }
        }
        let mut entries: Vec<_> = entries.into_values().collect();
        alter(&mut entries);
        let positions = CanonicalForgePositionState::try_new(repository, entries).unwrap();
        frame_bytes += encode_body(&positions).unwrap().len();
        let mut head = genesis_head();
        head.repository_id = repository;
        head.forge_position_root = run(storage::stage_body(
            &store,
            &(),
            repository,
            storage::POSITION_NAMESPACE,
            &positions,
        ))
        .unwrap();
        let position_key = storage::body_key(
            storage::POSITION_NAMESPACE,
            repository,
            head.forge_position_root,
        )
        .unwrap();
        let selected_root = head.forge_position_root;
        if publish {
            head.forge_position_root = run(storage::stage_body(
                &store,
                &(),
                repository,
                storage::POSITION_NAMESPACE,
                &CanonicalForgePositionState::try_new(repository, Vec::new()).unwrap(),
            ))
            .unwrap();
        }
        head.outcome_index_root = outcome_index_root(&[]).unwrap();
        // This read does not acquire delivery authority or consume outbox data.
        head.outbox_root =
            storage::root(&CanonicalOutboxState::try_new(repository, Vec::new()).unwrap()).unwrap();
        let key = HeadKey::new(b"check-frontier/head".to_vec()).unwrap();
        fgit_authority::initialize_repository(&store.memory, &key, &head).unwrap();
        let mut basis = run(crate::read_basis_async(&store, &(), &key)).unwrap().0;
        if publish {
            assert_eq!(event_roots.len(), 1, "one canonical decision payload");
            let HeadRead::Present(before) = store.memory.read_head(&key).unwrap() else {
                panic!("initialized head");
            };
            let mut record = fgit_codec::harness::commit_record();
            record.repository_id = repository;
            record.resulting_ref_root = basis.body().ref_root;
            record.forge_event_batch_root = event_roots[0];
            record.resulting_forge_position_root = selected_root;
            record.policy_epoch = basis.body().policy_epoch;
            let mut plan = PublicationPlan::open(basis.clone()).unwrap();
            plan.commit(record);
            let outcomes = collect_cumulative_outcomes(&store.memory, &key).unwrap();
            let publication = plan
                .seal(
                    &CryptoBodyIdentity,
                    ResultingRoots {
                        forge_position_root: selected_root,
                        ..ResultingRoots::carried_forward(&basis)
                    },
                    &outcomes,
                    before.token(),
                )
                .unwrap();
            assert!(matches!(
                publish_decisions(
                    &store.memory,
                    &key,
                    before.token(),
                    publication.batch(),
                    publication.head(),
                    TenantId::from_bytes([0x35; 16]),
                )
                .unwrap(),
                PublicationOutcome::Published(_),
            ));
            basis = run(crate::read_basis_async(&store, &(), &key)).unwrap().0;
            assert_eq!(basis.body().forge_position_root, selected_root);
            assert_eq!(basis.body().latest_decision_sequence.unwrap().get(), 1);
        }
        store.reads.store(0, Ordering::Relaxed);
        store.read_keys.lock().unwrap().clear();
        Self {
            store,
            key,
            basis,
            position_key,
            event_keys,
            frame_bytes,
            event_count,
            last_capsule_key: None,
        }
    }

    fn checkpoints(&mut self, count: usize) {
        for _ in 0..count {
            let HeadRead::Present(before) = self.store.memory.read_head(&self.key).unwrap() else {
                panic!("initialized head");
            };
            let (next, capsule_key) = stage_checkpoint(&self.store.memory, &self.basis);
            assert!(matches!(
                self.store
                    .memory
                    .compare_exchange_head(
                        &self.key,
                        before.token(),
                        next.body().generation,
                        &encode_body(next.body()).unwrap(),
                    )
                    .unwrap(),
                CasOutcome::Committed(_),
            ));
            self.basis = run(crate::read_basis_async(&self.store, &(), &self.key))
                .unwrap()
                .0;
            assert_eq!(self.basis.id(), next.id());
            self.last_capsule_key = Some(capsule_key);
        }
        self.store.reads.store(0, Ordering::Relaxed);
        self.store.read_keys.lock().unwrap().clear();
    }

    fn ordered(&self, check: &NativeWorkflowCheck) -> Result<(), ProjectionFailure> {
        run(verify_at(
            &self.store,
            &(),
            &self.basis,
            &BTreeMap::from([(check.record.source_ref.clone(), check.record.source_commit)]),
            check.record.source_commit,
            &[requirement(check)],
            &|| false,
        ))
    }

    fn unordered(&self, check: &NativeWorkflowCheck) -> Result<bool, ProjectionFailure> {
        run(verify_unanimous_at(
            &self.store,
            &(),
            &self.basis,
            matcher(check, &[&check.record.job]),
            &mut ScanBudget::default(),
            &|| false,
        ))
    }
}

fn unavailable<T: std::fmt::Debug>(result: Result<T, ProjectionFailure>, expected: RefusalCode) {
    assert!(
        matches!(&result, Err(ProjectionFailure::Unavailable(code)) if *code == expected),
        "expected unavailable {expected:?}, got {result:?}",
    );
}

#[test]
fn old_success_survives_the_actual_history_bound_with_verified_checkpoint_edges() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let success = check(format, 1, "build", WorkflowCheckConclusion::Success);
        let mut fixture = Fixture::published(vec![event(&success)]);
        fixture.ordered(&success).unwrap();
        assert!(
            !fixture
                .store
                .read_keys
                .lock()
                .unwrap()
                .contains(&fixture.position_key),
            "a recent matching check uses only the ordered path",
        );
        fixture.checkpoints(MAX_HISTORY_STEPS + 1);
        for _ in 0..2 {
            fixture.ordered(&success).unwrap();
        }
        assert!(
            fixture.store.reads.load(Ordering::Relaxed) >= 4 * MAX_HISTORY_STEPS,
            "the production history bound was exercised, not lowered for this test",
        );

        // A damaged observed edge must not trigger the success-only shortcut.
        *fixture.store.missing.lock().unwrap() = fixture.last_capsule_key.clone();
        fixture.store.read_keys.lock().unwrap().clear();
        unavailable(fixture.ordered(&success), RefusalCode::EvidenceMissing);
        assert!(
            !fixture
                .store
                .read_keys
                .lock()
                .unwrap()
                .contains(&fixture.position_key),
            "frontier fallback is only for the predecessor bound",
        );
    }
}

#[test]
fn mixed_old_results_keep_the_original_bound_refusal_in_both_native_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let success = check(format, 1, "build", WorkflowCheckConclusion::Success);
        let failed = check(format, 2, "build", WorkflowCheckConclusion::Failure);
        let mut fixture = Fixture::published(vec![event(&failed), event(&success)]);
        // The later event is success while order remains available.
        fixture.ordered(&success).unwrap();
        fixture.checkpoints(MAX_HISTORY_STEPS + 1);
        unavailable(
            fixture.ordered(&success),
            RefusalCode::ResourceBudgetExceeded,
        );
    }
}

#[test]
fn shared_batches_are_read_once_and_complete_success_is_order_independent() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let build = check(format, 1, "build", WorkflowCheckConclusion::Success);
        let lint = check(format, 2, "lint", WorkflowCheckConclusion::Success);
        let unrelated = check(format, 3, "other", WorkflowCheckConclusion::Failure);
        for grouped in [false, true] {
            for events in [
                vec![event(&build), event(&lint), event(&unrelated)],
                vec![event(&unrelated), event(&lint), event(&build)],
            ] {
                let fixture = Fixture::new(events, grouped);
                let mut scan = ScanBudget::default();
                assert!(
                    run(verify_unanimous_at(
                        &fixture.store,
                        &(),
                        &fixture.basis,
                        matcher(&build, &["build", "lint"]),
                        &mut scan,
                        &|| false,
                    ))
                    .unwrap(),
                );
                assert_eq!(scan.events, 3);
                assert_eq!(scan.batches, if grouped { 1 } else { 3 });
                assert_eq!(
                    fixture.store.reads.load(Ordering::Relaxed),
                    if grouped { 2 } else { 4 },
                );
                assert_eq!(scan.bytes, fixture.frame_bytes);
            }
        }
    }
}

#[test]
fn no_non_success_can_hide_behind_a_success_visited_earlier() {
    let format = GitHashAlgorithm::Sha1;
    let success = check(format, 1, "build", WorkflowCheckConclusion::Success);
    for conclusion in [
        WorkflowCheckConclusion::ActionRequired,
        WorkflowCheckConclusion::Failure,
        WorkflowCheckConclusion::Cancelled,
        WorkflowCheckConclusion::TimedOut,
    ] {
        let other = check(format, 2, "build", conclusion);
        for events in [
            vec![event(&success), event(&other)],
            vec![event(&other), event(&success)],
        ] {
            // The bulk frame preserves event order and forces both visit orders.
            assert!(!Fixture::new(events, true).unordered(&success).unwrap());
        }
    }
    assert!(
        Fixture::new(vec![event(&success)], true)
            .unordered(&success)
            .unwrap(),
    );
}

#[test]
fn unmatched_or_incomplete_selected_checks_do_not_prove_success() {
    let success = check(
        GitHashAlgorithm::Sha256,
        1,
        "build",
        WorkflowCheckConclusion::Success,
    );
    let fixture = Fixture::new(vec![event(&success)], true);
    for field in 0..5 {
        let mut requested = success.clone();
        match field {
            0 => requested.actor = PrincipalId::from_bytes([9; 16]),
            1 => requested.record.source_ref = RefName::try_new(b"refs/heads/other").unwrap(),
            2 => {
                requested.record.source_commit =
                    GitOid::from_hex(GitHashAlgorithm::Sha256, &"22".repeat(32)).unwrap();
            }
            3 => requested.record.graph_root = [9; 32],
            _ => requested.record.job = "missing".into(),
        }
        assert!(
            !fixture.unordered(&requested).unwrap(),
            "selector field {field}",
        );
    }
    assert!(
        !run(verify_unanimous_at(
            &fixture.store,
            &(),
            &fixture.basis,
            matcher(&success, &["build", "missing"]),
            &mut ScanBudget::default(),
            &|| false,
        ))
        .unwrap()
    );
}

#[test]
fn resolved_newer_suffix_results_are_not_overridden_by_old_failures() {
    let format = GitHashAlgorithm::Sha1;
    let latest_build = check(format, 3, "build", WorkflowCheckConclusion::Success);
    let old_build = check(format, 1, "build", WorkflowCheckConclusion::Failure);
    let old_lint = check(format, 2, "lint", WorkflowCheckConclusion::Success);
    let fixture = Fixture::new(vec![event(&old_build), event(&old_lint)], true);
    let mut pending = matcher(&latest_build, &["build", "lint"]);
    assert!(!pending(&event(&latest_build).payload).unwrap());
    assert!(
        run(verify_unanimous_at(
            &fixture.store,
            &(),
            &fixture.basis,
            pending,
            &mut ScanBudget::default(),
            &|| false,
        ))
        .unwrap()
    );
    assert!(
        !run(verify_unanimous_at(
            &fixture.store,
            &(),
            &fixture.basis,
            matcher(&latest_build, &["build", "lint"]),
            &mut ScanBudget::default(),
            &|| false,
        ))
        .unwrap()
    );
}

#[test]
fn missing_and_corrupt_selected_bodies_refuse_beside_the_permitted_twin() {
    let success = check(
        GitHashAlgorithm::Sha1,
        1,
        "build",
        WorkflowCheckConclusion::Success,
    );
    let fixture = Fixture::new(vec![event(&success)], true);
    for key in [&fixture.position_key, &fixture.event_keys[0]] {
        *fixture.store.missing.lock().unwrap() = Some(key.clone());
        unavailable(fixture.unordered(&success), RefusalCode::EvidenceMissing);
        *fixture.store.missing.lock().unwrap() = None;
        *fixture.store.corrupt.lock().unwrap() = Some(key.clone());
        unavailable(fixture.unordered(&success), RefusalCode::EvidenceInvalid);
        *fixture.store.corrupt.lock().unwrap() = None;
        assert!(fixture.unordered(&success).unwrap());
    }
}

#[test]
fn selected_ranges_labels_and_duplicate_events_are_validated() {
    let success = check(
        GitHashAlgorithm::Sha1,
        1,
        "build",
        WorkflowCheckConclusion::Success,
    );
    for kind in 0..4 {
        let fixture = Fixture::with_positions(vec![event(&success)], true, |entries| {
            let old = entries[0];
            let (stream, predecessor, count) = match kind {
                0 => (old.stream(), 1, 1),
                1 => (old.stream(), 0, 2),
                2 => (
                    AsciiSlug::try_new("stream", b"check/not-a-canonical-id").unwrap(),
                    0,
                    1,
                ),
                _ => (
                    storage::aggregate_label(AggregateId::WorkflowCheck(
                        WorkflowCheckId::from_bytes([99; 32]),
                    ))
                    .unwrap(),
                    0,
                    1,
                ),
            };
            entries[0] = ForgePositionStateEntry::try_new(
                stream,
                predecessor,
                count,
                old.event_batch_root(),
            )
            .unwrap();
        });
        unavailable(fixture.unordered(&success), RefusalCode::EvidenceInvalid);
    }
    let duplicate = Fixture::new(vec![event(&success), event(&success)], true);
    unavailable(duplicate.unordered(&success), RefusalCode::EvidenceInvalid);
    assert!(
        Fixture::new(vec![event(&success)], true)
            .unordered(&success)
            .unwrap(),
    );
}

#[test]
fn interrupted_partial_frontier_never_becomes_a_success() {
    let success = check(
        GitHashAlgorithm::Sha1,
        1,
        "build",
        WorkflowCheckConclusion::Success,
    );
    let other = check(
        GitHashAlgorithm::Sha1,
        2,
        "other",
        WorkflowCheckConclusion::Success,
    );
    let fixture = Fixture::new(vec![event(&success), event(&other)], false);
    for stop_after in 0..=2 {
        fixture.store.reads.store(0, Ordering::Relaxed);
        unavailable(
            run(verify_unanimous_at(
                &fixture.store,
                &(),
                &fixture.basis,
                matcher(&success, &["build"]),
                &mut ScanBudget::default(),
                &|| fixture.store.reads.load(Ordering::Relaxed) >= stop_after,
            )),
            RefusalCode::CancellationInProgress,
        );
    }
    assert!(fixture.unordered(&success).unwrap());
}

#[test]
fn fallback_shares_prior_work_budgets_and_exact_limits_remain_permitted() {
    let success = check(
        GitHashAlgorithm::Sha1,
        1,
        "build",
        WorkflowCheckConclusion::Success,
    );
    let fixture = Fixture::new(vec![event(&success)], true);
    for kind in 0..3 {
        let mut scan = ScanBudget::default();
        match kind {
            0 => scan.batches = MAX_SCAN_BATCHES,
            1 => scan.events = MAX_SCAN_EVENTS,
            _ => scan.bytes = MAX_SCAN_BYTES,
        }
        unavailable(
            run(verify_unanimous_at(
                &fixture.store,
                &(),
                &fixture.basis,
                matcher(&success, &["build"]),
                &mut scan,
                &|| false,
            )),
            RefusalCode::ResourceBudgetExceeded,
        );
    }
    let mut exact = ScanBudget {
        batches: MAX_SCAN_BATCHES - fixture.event_keys.len(),
        events: MAX_SCAN_EVENTS - fixture.event_count,
        bytes: MAX_SCAN_BYTES - fixture.frame_bytes,
    };
    assert!(
        run(verify_unanimous_at(
            &fixture.store,
            &(),
            &fixture.basis,
            matcher(&success, &["build"]),
            &mut exact,
            &|| false,
        ))
        .unwrap()
    );
    assert_eq!(exact.batches, MAX_SCAN_BATCHES);
    assert_eq!(exact.events, MAX_SCAN_EVENTS);
    assert_eq!(exact.bytes, MAX_SCAN_BYTES);
}

#[test]
fn moved_source_is_denied_before_history_or_frontier_reads() {
    let success = check(
        GitHashAlgorithm::Sha1,
        1,
        "build",
        WorkflowCheckConclusion::Success,
    );
    let fixture = Fixture::new(vec![event(&success)], true);
    let moved = GitOid::from_hex(GitHashAlgorithm::Sha1, &"22".repeat(20)).unwrap();
    let result = run(verify_at(
        &fixture.store,
        &(),
        &fixture.basis,
        &BTreeMap::from([(success.record.source_ref.clone(), moved)]),
        success.record.source_commit,
        &[requirement(&success)],
        &|| false,
    ));
    assert!(matches!(
        result,
        Err(ProjectionFailure::Refuse(
            RefusalCode::ProtectedRefTransitionDenied
        )),
    ));
    assert_eq!(fixture.store.reads.load(Ordering::Relaxed), 0);
}

#[test]
fn staged_only_observations_cannot_grant_or_revoke_selected_success() {
    let format = GitHashAlgorithm::Sha1;
    let success = check(format, 1, "build", WorkflowCheckConclusion::Success);
    let unrelated = check(format, 2, "lint", WorkflowCheckConclusion::Success);
    let failed = check(format, 3, "build", WorkflowCheckConclusion::Failure);
    for (selected, staged, expected) in [(&success, &failed, true), (&unrelated, &success, false)] {
        let fixture = Fixture::new(vec![event(selected)], true);
        let root = run(storage::stage_body(
            &fixture.store,
            &(),
            fixture.basis.body().repository_id,
            storage::EVENT_NAMESPACE,
            &ForgeEventBatch::of_one(event(staged)),
        ))
        .unwrap();
        let staged_key = storage::body_key(
            storage::EVENT_NAMESPACE,
            fixture.basis.body().repository_id,
            root,
        )
        .unwrap();
        assert_eq!(fixture.unordered(&success).unwrap(), expected);
        assert!(
            !fixture
                .store
                .read_keys
                .lock()
                .unwrap()
                .contains(&staged_key),
            "immutable placement does not select an observation",
        );
    }
}

#[test]
fn actual_candidate_and_branch_frames_are_both_mandatory_in_the_shared_proof() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let oid = |byte: &str| GitOid::from_hex(format, &byte.repeat(format.digest_len())).unwrap();
        let subject = ReviewSubject {
            pull_request: PullRequestNumber::FIRST,
            pull_request_version: AggregateVersion::FIRST,
            source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
            target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
            source_tip: oid("11"),
            target_tip: oid("22"),
            policy_epoch: PolicyEpoch::FIRST,
        };
        let candidate = CandidateBinding {
            merge_base: oid("33"),
            commit: oid("44"),
        };
        let mut ordinary = check(format, 1, "build", WorkflowCheckConclusion::Success);
        ordinary.record.source_ref = RefName::try_new(b"refs/heads/ci").unwrap();
        ordinary.record.source_commit = candidate.commit;
        let ordinary_required = [requirement(&ordinary)];
        let candidate_required = [RequiredCandidateWorkflowCheck {
            publisher: ordinary.actor,
            graph_root: ordinary.record.graph_root,
            job: ordinary.record.job.clone(),
        }];
        for case in 0..5 {
            let mut branch = ordinary.clone();
            if case == 1 {
                branch.record.conclusion = WorkflowCheckConclusion::Failure;
            }
            let mut record = ordinary.record.clone();
            record.source_ref = subject.target_ref.clone();
            record.attempt_id = [2; 32];
            if case == 2 {
                record.conclusion = WorkflowCheckConclusion::Failure;
            }
            let exact = CandidateWorkflowCheckRecord {
                subject: subject.clone(),
                candidate,
                bundle_sha256: [9; 32],
                check: record,
            }
            .proposed_event(ordinary.actor, format)
            .unwrap();
            let events = match case {
                3 => vec![event(&branch)],
                4 => vec![exact],
                _ => vec![event(&branch), exact],
            };
            let fixture = Fixture::new(events, true);
            assert_eq!(
                run(verify_unanimous_at(
                    &fixture.store,
                    &(),
                    &fixture.basis,
                    observation_matcher(
                        subject.clone(),
                        candidate,
                        &ordinary_required,
                        &candidate_required,
                    ),
                    &mut ScanBudget::default(),
                    &|| false,
                ))
                .unwrap(),
                case == 0,
                "candidate/ordinary case {case} in {format:?}",
            );
        }
    }
}

#[test]
fn cancellation_after_a_matching_success_still_refuses_the_partial_proof() {
    let success = check(
        GitHashAlgorithm::Sha1,
        1,
        "build",
        WorkflowCheckConclusion::Success,
    );
    let other = check(
        GitHashAlgorithm::Sha1,
        2,
        "other",
        WorkflowCheckConclusion::Success,
    );
    let fixture = Fixture::new(vec![event(&success), event(&other)], true);
    let stopped = AtomicBool::new(false);
    let stop = &stopped;
    let mut matching = matcher(&success, &["build"]);
    let observe = move |payload: &ForgeEventPayload| {
        let result = matching(payload);
        if matches!(&result, Ok(true)) {
            stop.store(true, Ordering::Relaxed);
        }
        result
    };
    unavailable(
        run(verify_unanimous_at(
            &fixture.store,
            &(),
            &fixture.basis,
            observe,
            &mut ScanBudget::default(),
            &|| stopped.load(Ordering::Relaxed),
        )),
        RefusalCode::CancellationInProgress,
    );
    assert!(stopped.load(Ordering::Relaxed));
}
