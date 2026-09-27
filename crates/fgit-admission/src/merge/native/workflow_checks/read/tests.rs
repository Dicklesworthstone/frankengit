//! Production readers over authenticated genesis-selected canonical frontiers.
//! The reference authority is non-durable. Synthetic observations exercise read
//! semantics; they do not authenticate a runner or prove workflow execution.

use super::*;
use fgit_authority::{
    AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityStore, AuthorityVersionToken,
    CasOutcome, HeadInit, HeadKey, HeadRead, HeadReadReceipt, ImmutableKey, ImmutableRead,
    MemoryAuthorityStore, PutOutcome, StoreInstanceId,
};
use fgit_codec::harness::genesis_head;
use fgit_codec::{CanonicalBody, CanonicalForgePositionState, CanonicalOutboxState, encode_body};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::event::workflow_check::WorkflowCheckRecord;
use fgit_forge::{ExpectedVersion, ForgeEvent};
use fgit_types::{Digest, GitHashAlgorithm, RepositoryId, RootLayoutVersion};
use std::future::Future;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
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
    fault: Mutex<Option<(ImmutableKey, ImmutableRead)>>,
    fault_reads: AtomicUsize,
}
impl AsyncAuthorityStore for Store {
    type Context = ();
    fn instance_id(&self) -> StoreInstanceId {
        self.memory.instance_id()
    }
    fn limits(&self) -> AuthorityLimits {
        self.memory.limits()
    }
    async fn put_if_absent(
        &self,
        _: &(),
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        self.memory.put_if_absent(key, body)
    }
    async fn read_immutable(
        &self,
        _: &(),
        key: &ImmutableKey,
    ) -> Result<ImmutableRead, AuthorityFailure> {
        if let Some((selected, response)) = self.fault.lock().unwrap().as_ref() {
            if selected == key {
                self.fault_reads.fetch_add(1, Ordering::Relaxed);
                return Ok(response.clone());
            }
        }
        self.memory.read_immutable(key)
    }
    async fn initialize_head(
        &self,
        _: &(),
        key: &HeadKey,
        generation: fgit_types::HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, AuthorityFailure> {
        self.memory.initialize_head(key, generation, body)
    }
    async fn read_head(&self, _: &(), key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        self.memory.read_head(key)
    }
    async fn compare_exchange_head(
        &self,
        _: &(),
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: fgit_types::HeadGeneration,
        body: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        self.memory
            .compare_exchange_head(key, expected, generation, body)
    }
    async fn authenticate_head_receipt(
        &self,
        _: &(),
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure> {
        self.memory.authenticate_head_receipt(receipt)
    }
}

struct Fixture {
    store: Store,
    basis: PublicationBasis,
    forge: CanonicalForgePositionState,
    refs: BTreeMap<RefName, GitOid>,
    selection: usize,
}
impl Fixture {
    fn new(format: GitHashAlgorithm, batches: Vec<ForgeEventBatch>) -> Self {
        let store = Store {
            memory: MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x1c4ec)),
            fault: Mutex::new(None),
            fault_reads: AtomicUsize::new(0),
        };
        let repository = RepositoryId::from_bytes([0x34; 16]);
        let mut forge = CanonicalForgePositionState::try_new(repository, Vec::new()).unwrap();
        for batch in batches {
            let root = stage(&store, repository, storage::EVENT_NAMESPACE, &batch);
            forge = storage::advance_positions(&forge, &batch, root).unwrap();
        }
        let refs = BTreeMap::from([
            (branch("topic"), oid(format, '1')),
            (branch("main"), oid(format, '2')),
        ]);
        let mut head = genesis_head();
        head.repository_id = repository;
        head.ref_root = crate::ref_state_root(
            RootLayoutVersion::LegacyWholeBody,
            &crate::CanonicalRefState::new(refs.clone()),
        )
        .unwrap();
        head.forge_position_root = stage(&store, repository, storage::POSITION_NAMESPACE, &forge);
        let outbox = CanonicalOutboxState::try_new(repository, Vec::new()).unwrap();
        head.outbox_root = stage(&store, repository, delivery::OUTBOX_NAMESPACE, &outbox);
        let key = HeadKey::new(b"checks-reference/head".to_vec()).unwrap();
        fgit_authority::initialize_repository(&store.memory, &key, &head).unwrap();
        let basis = run(crate::read_basis_async(&store, &(), &key)).unwrap().0;
        Self {
            store,
            basis,
            forge,
            refs,
            selection: 0,
        }
    }
    fn checks(format: GitHashAlgorithm, checks: &[NativeWorkflowCheck]) -> Self {
        let mut events = vec![pr(format)];
        events.extend(
            checks
                .iter()
                .map(|check| check.record.proposed_event(check.actor, format).unwrap()),
        );
        Self::new(
            format,
            events.into_iter().map(ForgeEventBatch::of_one).collect(),
        )
    }
    fn page(&self, after: Option<WorkflowCheckId>, limit: u16) -> PullRequestChecksPage {
        self.read(after, limit, &|_, _| true, &|| false)
            .unwrap()
            .unwrap()
    }
    fn read<V, C>(
        &self,
        after: Option<WorkflowCheckId>,
        limit: u16,
        visible: &V,
        cancelled: &C,
    ) -> Result<Option<PullRequestChecksPage>, AdmissionError>
    where
        V: Fn(&RefName, &RefName) -> bool + Sync,
        C: Fn() -> bool + Sync,
    {
        run(read_pull_request_page_at(
            &self.store,
            &(),
            &self.basis,
            number(1),
            &self.refs,
            after,
            limit,
            visible,
            cancelled,
        ))
    }
    fn fault(&self, root: Digest, response: ImmutableRead) {
        let key = storage::body_key(
            storage::EVENT_NAMESPACE,
            self.basis.body().repository_id,
            root,
        )
        .unwrap();
        *self.store.fault.lock().unwrap() = Some((key, response));
        self.store.fault_reads.store(0, Ordering::Relaxed);
    }
    fn clear_fault(&self) {
        *self.store.fault.lock().unwrap() = None;
        self.store.fault_reads.store(0, Ordering::Relaxed);
    }
    fn position(&self, aggregate: AggregateId) -> ForgePositionStateEntry {
        *self
            .forge
            .entry(storage::aggregate_label(aggregate).unwrap())
            .unwrap()
    }
    /// Authenticate another explicit genesis fixture. This is not a publication
    /// or a durability/recovery simulation.
    fn reselect(&mut self) {
        let mut head = self.basis.body().clone();
        head.ref_root = crate::ref_state_root(
            RootLayoutVersion::LegacyWholeBody,
            &crate::CanonicalRefState::new(self.refs.clone()),
        )
        .unwrap();
        head.forge_position_root = stage(
            &self.store,
            head.repository_id,
            storage::POSITION_NAMESPACE,
            &self.forge,
        );
        self.selection += 1;
        let key =
            HeadKey::new(format!("checks-reference/selection/{}", self.selection).into_bytes())
                .unwrap();
        fgit_authority::initialize_repository(&self.store.memory, &key, &head).unwrap();
        self.basis = run(crate::read_basis_async(&self.store, &(), &key))
            .unwrap()
            .0;
    }
}

fn stage<B: CanonicalBody + Sync>(
    store: &Store,
    repository: RepositoryId,
    namespace: &[u8],
    body: &B,
) -> Digest {
    run(storage::stage_body(store, &(), repository, namespace, body)).unwrap()
}
fn number(value: u64) -> PullRequestNumber {
    PullRequestNumber::try_new(value).unwrap()
}
fn branch(name: &str) -> RefName {
    RefName::try_new(format!("refs/heads/{name}").as_bytes()).unwrap()
}
fn oid(format: GitHashAlgorithm, digit: char) -> GitOid {
    GitOid::from_hex(format, &digit.to_string().repeat(format.digest_len() * 2)).unwrap()
}
fn pr(format: GitHashAlgorithm) -> ForgeEvent {
    PullRequestCommand {
        number: number(1),
        expected_version: ExpectedVersion::NewStream,
        action: PullRequestAction::Open,
        data: PullRequestData {
            source_ref: branch("topic"),
            target_ref: branch("main"),
            source_tip: oid(format, '1'),
            target_tip: oid(format, '2'),
            title: "Read exact checks".into(),
            body: String::new(),
        },
    }
    .proposed_event(PrincipalId::from_bytes([3; 16]), format)
    .unwrap()
}
fn check(format: GitHashAlgorithm, publisher: u8) -> NativeWorkflowCheck {
    NativeWorkflowCheck {
        actor: PrincipalId::from_bytes([publisher; 16]),
        record: WorkflowCheckRecord {
            source_ref: branch("topic"),
            source_commit: oid(format, '1'),
            run_id: [4; 32],
            attempt_id: [5; 32],
            graph_root: [6; 32],
            job: "build".into(),
            conclusion: WorkflowCheckConclusion::ActionRequired,
            evidence: b"reference observation, not execution attestation".to_vec(),
        },
    }
}
fn summary(check: &NativeWorkflowCheck) -> WorkflowCheckSummary {
    WorkflowCheckSummary {
        id: check.id(),
        publisher: check.actor,
        run_id: check.record.run_id,
        attempt_id: check.record.attempt_id,
        graph_root: check.record.graph_root,
        job: check.record.job.clone(),
        conclusion: check.record.conclusion,
        evidence_sha256: fgit_crypto::sha256_digest(&check.record.evidence),
        evidence_bytes: check.record.evidence.len() as u64,
    }
}
fn refuses<T: std::fmt::Debug>(result: Result<T, AdmissionError>, code: RefusalCode) {
    assert!(
        matches!(&result, Err(AdmissionError::AsyncProjectionUnavailable(found)) if *found == code),
        "expected {code:?}, got {result:?}"
    );
}

#[test]
fn both_native_domains_filter_exact_coordinates_and_page_full_publisher_identities() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let first = check(format, 7);
        let mut second = check(format, 8);
        second.record.conclusion = WorkflowCheckConclusion::Failure;
        let mut third = check(format, 9);
        third.record.conclusion = WorkflowCheckConclusion::TimedOut;
        third.record.job = "test".into();
        let mut wrong_branch = check(format, 10);
        wrong_branch.record.source_ref = branch("other");
        let mut wrong_tip = check(format, 11);
        wrong_tip.record.source_commit = oid(format, '3');
        let checks = vec![
            third.clone(),
            wrong_tip,
            first.clone(),
            wrong_branch,
            second.clone(),
        ];
        let fixture = Fixture::checks(format, &checks);
        let mut expected: Vec<_> = [&first, &second, &third].into_iter().map(summary).collect();
        expected.sort_by_key(|check| check.id);
        let page = fixture.page(None, 100);
        assert_eq!(page.checks, expected);
        assert_eq!(page.source_head, fixture.basis.id());
        assert_eq!(page.source_tip, oid(format, '1'));
        assert_eq!(page.target_tip, oid(format, '2'));
        assert!(page.source_current);
        assert_eq!(page.next_after, None);
        let mut after = None;
        for (index, expected_check) in expected.iter().enumerate() {
            let page = fixture.page(after, 1);
            assert_eq!(page.checks, vec![expected_check.clone()]);
            assert_eq!(
                page.next_after,
                (index + 1 < expected.len()).then_some(expected_check.id)
            );
            assert_eq!(
                page.validate_window(number(1), after, 1, Some(fixture.basis.id())),
                Ok(())
            );
            after = Some(expected_check.id);
        }
        assert!(fixture.page(after, 1).checks.is_empty());
        let reversed: Vec<_> = checks.into_iter().rev().collect();
        assert_eq!(Fixture::checks(format, &reversed).page(None, 100), page);
    }
}

#[test]
fn unselected_staged_observation_never_appears_in_the_authenticated_page() {
    let format = GitHashAlgorithm::Sha256;
    let fixture = Fixture::checks(format, &[check(format, 7)]);
    let before = fixture.page(None, 10);
    let unselected = check(format, 8);
    let batch = ForgeEventBatch::of_one(
        unselected
            .record
            .proposed_event(unselected.actor, format)
            .unwrap(),
    );
    stage(
        &fixture.store,
        fixture.basis.body().repository_id,
        storage::EVENT_NAMESPACE,
        &batch,
    );
    assert_eq!(fixture.page(None, 10), before);
    assert_eq!(before.checks.len(), 1);
}

#[test]
fn hidden_source_or_target_is_not_disclosed_and_does_not_read_check_frames() {
    let format = GitHashAlgorithm::Sha1;
    let observation = check(format, 7);
    let fixture = Fixture::checks(format, &[observation.clone()]);
    let allowed = fixture.page(None, 10);
    fixture.fault(
        fixture
            .position(AggregateId::WorkflowCheck(observation.id()))
            .event_batch_root(),
        ImmutableRead::Absent,
    );
    for hidden in [branch("topic"), branch("main")] {
        assert!(
            fixture
                .read(
                    None,
                    10,
                    &|source, target| source != &hidden && target != &hidden,
                    &|| false
                )
                .unwrap()
                .is_none()
        );
        assert_eq!(fixture.store.fault_reads.load(Ordering::Relaxed), 0);
    }
    refuses(
        fixture.read(None, 10, &|_, _| true, &|| false),
        RefusalCode::EvidenceMissing,
    );
    fixture.clear_fault();
    assert_eq!(fixture.page(None, 10), allowed);
}

#[test]
fn moved_or_deleted_source_suppresses_checks_while_the_retained_basis_is_stable() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for deleted in [false, true] {
            let observation = check(format, 7);
            let mut fixture = Fixture::checks(format, &[observation.clone()]);
            let retained_basis = fixture.basis.clone();
            let retained_refs = fixture.refs.clone();
            let retained_page = fixture.page(None, 1);
            if deleted {
                fixture.refs.remove(&branch("topic"));
            } else {
                fixture.refs.insert(branch("topic"), oid(format, '3'));
            }
            fixture.reselect();
            fixture.fault(
                fixture
                    .position(AggregateId::WorkflowCheck(observation.id()))
                    .event_batch_root(),
                ImmutableRead::Absent,
            );
            let stale = fixture.page(None, 1);
            assert!(!stale.source_current);
            assert!(stale.checks.is_empty());
            assert_eq!(stale.next_after, None);
            assert_eq!(fixture.store.fault_reads.load(Ordering::Relaxed), 0);
            fixture.clear_fault();
            let retained = run(read_pull_request_page_at(
                &fixture.store,
                &(),
                &retained_basis,
                number(1),
                &retained_refs,
                None,
                1,
                &|_, _| true,
                &|| false,
            ))
            .unwrap()
            .unwrap();
            assert_eq!(retained, retained_page);
            assert_ne!(stale.source_head, retained.source_head);
        }
    }
}

#[test]
fn absent_and_legacy_prs_are_absent_but_native_merge_only_prs_keep_source_coordinates() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let empty = Fixture::new(format, Vec::new());
        assert!(
            empty
                .read(None, 1, &|_, _| true, &|| false)
                .unwrap()
                .is_none()
        );
        let legacy = ForgeEvent {
            aggregate: AggregateId::PullRequest(number(1)),
            version: AggregateVersion::FIRST,
            payload: ForgeEventPayload::PullRequestOpened {
                source_ref: branch("topic").as_bytes().to_vec(),
                target_ref: branch("main").as_bytes().to_vec(),
                source_tip: empty.basis.body().ref_root,
                target_tip: empty.basis.body().ref_root,
            },
        };
        assert!(
            Fixture::new(format, vec![ForgeEventBatch::of_one(legacy)])
                .read(None, 1, &|_, _| true, &|| false)
                .unwrap()
                .is_none()
        );
        let observation = check(format, 7);
        let merge = ForgeEvent {
            aggregate: AggregateId::PullRequest(number(1)),
            version: AggregateVersion::FIRST,
            payload: ForgeEventPayload::MergeCommittedNative(fgit_forge::event::NativeMerge {
                source_ref: branch("topic"),
                source_tip: oid(format, '1'),
                base_tip: oid(format, '3'),
                target_ref: branch("main"),
                target_tip_before: oid(format, '2'),
                merge_commit: oid(format, '4'),
            }),
        };
        let fixture = Fixture::new(
            format,
            vec![
                ForgeEventBatch::of_one(merge),
                ForgeEventBatch::of_one(
                    observation
                        .record
                        .proposed_event(observation.actor, format)
                        .unwrap(),
                ),
            ],
        );
        let page = fixture.page(None, 1);
        assert_eq!(page.checks, vec![summary(&observation)]);
        assert_eq!(page.source_ref, branch("topic"));
        assert_eq!(page.target_ref, branch("main"));
        assert_eq!(page.target_tip, oid(format, '2'));
    }
}

#[test]
fn selected_missing_corrupt_or_substituted_frames_return_typed_refusals() {
    let format = GitHashAlgorithm::Sha1;
    let observation = check(format, 7);
    let fixture = Fixture::checks(format, &[observation.clone()]);
    let allowed = fixture.page(None, 10);
    let substitute = check(format, 8);
    let substitute_frame = encode_body(&ForgeEventBatch::of_one(
        substitute
            .record
            .proposed_event(substitute.actor, format)
            .unwrap(),
    ))
    .unwrap();
    for aggregate in [
        AggregateId::PullRequest(number(1)),
        AggregateId::WorkflowCheck(observation.id()),
    ] {
        let root = fixture.position(aggregate).event_batch_root();
        for (response, code) in [
            (ImmutableRead::Absent, RefusalCode::EvidenceMissing),
            (
                ImmutableRead::Present(vec![0xff, 0x00, 0x01]),
                RefusalCode::EvidenceInvalid,
            ),
            (
                ImmutableRead::Present(substitute_frame.clone()),
                RefusalCode::EvidenceInvalid,
            ),
        ] {
            fixture.fault(root, response);
            refuses(fixture.read(None, 10, &|_, _| true, &|| false), code);
            fixture.clear_fault();
            assert_eq!(fixture.page(None, 10), allowed);
        }
    }
}

#[test]
fn authenticated_noncanonical_position_ranges_refuse_instead_of_selecting_the_last_event() {
    let format = GitHashAlgorithm::Sha1;
    for (predecessor, count) in [(1, 1), (0, 2)] {
        let mut fixture = Fixture::checks(format, &[check(format, 7)]);
        assert_eq!(fixture.page(None, 1).checks.len(), 1);
        let original = fixture.forge.clone();
        let selected = fixture.position(AggregateId::PullRequest(number(1)));
        let replacement = ForgePositionStateEntry::try_new(
            selected.stream(),
            predecessor,
            count,
            selected.event_batch_root(),
        )
        .unwrap();
        fixture.forge = CanonicalForgePositionState::try_new(
            original.repository_id(),
            original
                .entries()
                .iter()
                .map(|entry| {
                    if entry.stream() == selected.stream() {
                        replacement
                    } else {
                        *entry
                    }
                })
                .collect(),
        )
        .unwrap();
        fixture.reselect();
        refuses(
            fixture.read(None, 1, &|_, _| true, &|| false),
            RefusalCode::EvidenceInvalid,
        );
        fixture.forge = original;
        fixture.reselect();
        assert_eq!(fixture.page(None, 1).checks.len(), 1);
    }
}

#[test]
fn cancellation_before_and_after_a_selected_read_never_returns_a_partial_page() {
    let format = GitHashAlgorithm::Sha256;
    let observation = check(format, 7);
    let fixture = Fixture::checks(format, &[observation.clone(), check(format, 8)]);
    let allowed = fixture.page(None, 10);
    for limit in [0, 101] {
        refuses(
            fixture.read(None, limit, &|_, _| true, &|| false),
            RefusalCode::ResourceBudgetExceeded,
        );
    }
    refuses(
        fixture.read(None, 10, &|_, _| true, &|| true),
        RefusalCode::CancellationInProgress,
    );
    let batch = ForgeEventBatch::of_one(
        observation
            .record
            .proposed_event(observation.actor, format)
            .unwrap(),
    );
    fixture.fault(
        storage::root(&batch).unwrap(),
        ImmutableRead::Present(encode_body(&batch).unwrap()),
    );
    refuses(
        fixture.read(None, 10, &|_, _| true, &|| {
            fixture.store.fault_reads.load(Ordering::Relaxed) != 0
        }),
        RefusalCode::CancellationInProgress,
    );
    fixture.clear_fault();
    assert_eq!(fixture.page(None, 10), allowed);
}

#[test]
fn real_batch_reads_charge_all_events_and_frame_bytes_at_exact_scan_boundaries() {
    let format = GitHashAlgorithm::Sha1;
    let observation = check(format, 7);
    let batch = ForgeEventBatch {
        events: vec![
            pr(format),
            observation
                .record
                .proposed_event(observation.actor, format)
                .unwrap(),
        ],
    };
    let fixture = Fixture::new(format, vec![batch.clone()]);
    let position = fixture.position(AggregateId::PullRequest(number(1)));
    let bytes = encode_body(&batch).unwrap().len();
    let events = batch.events.len();
    let mut exact = ScanBudget {
        bytes: MAX_SCAN_BYTES - bytes,
        events: MAX_SCAN_EVENTS - events,
    };
    assert_eq!(
        run(read_batch(
            &fixture.store,
            &(),
            &fixture.basis,
            &position,
            &mut exact,
            &|| false
        ))
        .unwrap(),
        batch
    );
    assert_eq!(exact.bytes, MAX_SCAN_BYTES);
    assert_eq!(exact.events, MAX_SCAN_EVENTS);
    for mut exhausted in [
        ScanBudget {
            bytes: MAX_SCAN_BYTES - bytes + 1,
            events: 0,
        },
        ScanBudget {
            bytes: 0,
            events: MAX_SCAN_EVENTS - events + 1,
        },
        ScanBudget {
            bytes: usize::MAX,
            events: 0,
        },
        ScanBudget {
            bytes: 0,
            events: usize::MAX,
        },
    ] {
        refuses(
            run(read_batch(
                &fixture.store,
                &(),
                &fixture.basis,
                &position,
                &mut exhausted,
                &|| false,
            )),
            RefusalCode::ResourceBudgetExceeded,
        );
        assert_eq!(
            run(read_batch(
                &fixture.store,
                &(),
                &fixture.basis,
                &position,
                &mut ScanBudget::default(),
                &|| false
            ))
            .unwrap(),
            batch
        );
    }
}

#[test]
fn response_window_validation_rejects_wrong_heads_cursors_coordinates_and_summaries() {
    let format = GitHashAlgorithm::Sha1;
    let fixture = Fixture::checks(format, &[check(format, 7), check(format, 8)]);
    let valid = fixture.page(None, 2);
    let head = Some(fixture.basis.id());
    assert_eq!(valid.validate_window(number(1), None, 2, head), Ok(()));
    for limit in [0, 1, 101] {
        assert_eq!(
            valid.validate_window(number(1), None, limit, head),
            Err(RefusalCode::ResourceBudgetExceeded)
        );
    }
    assert_eq!(
        valid.validate_window(number(2), None, 2, head),
        Err(RefusalCode::EvidenceInvalid)
    );
    assert_eq!(
        valid.validate_window(number(1), Some(valid.checks[0].id), 2, None),
        Err(RefusalCode::EvidenceInvalid)
    );
    assert_eq!(
        valid.validate_window(number(1), Some(valid.checks[0].id), 2, head),
        Err(RefusalCode::EvidenceInvalid)
    );
    let other_head = Fixture::checks(format, &[]).basis.id();
    assert_eq!(
        valid.validate_window(number(1), None, 2, Some(other_head)),
        Err(RefusalCode::EvidenceInvalid)
    );
    for case in 0..12 {
        let mut invalid = valid.clone();
        match case {
            0 => invalid.checks.swap(0, 1),
            1 => invalid.checks[1].id = invalid.checks[0].id,
            2 => invalid.source_ref = invalid.target_ref.clone(),
            3 => invalid.source_ref = RefName::try_new(b"refs/tags/v1").unwrap(),
            4 => invalid.source_tip = oid(format, '0'),
            5 => invalid.target_tip = oid(GitHashAlgorithm::Sha256, '2'),
            6 => invalid.source_current = false,
            7 => invalid.checks[0].job.clear(),
            8 => invalid.checks[0].job.push('\n'),
            9 => invalid.checks[0].job = "x".repeat(MAX_CHECK_JOB_BYTES + 1),
            10 => invalid.checks[0].evidence_bytes = 0,
            _ => invalid.checks[0].evidence_bytes = MAX_CHECK_EVIDENCE_BYTES as u64 + 1,
        }
        assert_eq!(
            invalid.validate_window(number(1), None, 2, head),
            Err(RefusalCode::EvidenceInvalid),
            "case {case}"
        );
    }
    let mut invalid = valid.clone();
    invalid.next_after = Some(valid.checks[0].id);
    assert_eq!(
        invalid.validate_window(number(1), None, 2, head),
        Err(RefusalCode::EvidenceInvalid)
    );
    invalid.next_after = Some(valid.checks[1].id);
    assert_eq!(
        invalid.validate_window(number(1), None, 3, head),
        Err(RefusalCode::EvidenceInvalid)
    );
    assert_eq!(invalid.validate_window(number(1), None, 2, head), Ok(()));
    let mut empty = valid;
    empty.checks.clear();
    empty.source_current = false;
    assert_eq!(empty.validate_window(number(1), None, 2, head), Ok(()));
    empty.next_after = invalid.next_after;
    assert_eq!(
        empty.validate_window(number(1), None, 2, head),
        Err(RefusalCode::EvidenceInvalid)
    );
}
