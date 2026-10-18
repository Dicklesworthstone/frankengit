//! Metadata projection isolation through the production readers and validators.
//!
//! These fixtures authenticate genesis-seeded maps with MemoryAuthorityStore.
//! They exercise the real asynchronous storage boundary but are reference model
//! tests, not evidence of durable publication, process recovery or filesystem I/O.

use std::future::Future;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityStore,
    AuthorityVersionToken, CasOutcome, HeadInit, HeadKey, HeadRead, HeadReadReceipt, ImmutableKey,
    ImmutableRead, MemoryAuthorityStore, PutOutcome, StoreInstanceId,
};
use fgit_chronicle::PublicationBasis;
use fgit_codec::harness::{genesis_head, tx_id};
use fgit_codec::{
    CanonicalForgePositionState, CanonicalOutboxEffectState, CanonicalOutboxState,
    CanonicalOutboxStateEntry, ForgePositionStateEntry, OutboxDeliveryIdentityInput,
    derive_outbox_delivery_key, encode_body,
};
use fgit_forge::event::issue::{IssueAction, IssueCommand};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::{
    AggregateId, AggregateVersion, ExpectedVersion, ForgeEvent, ForgeEventBatch, IssueNumber,
    PullRequestNumber,
};
use fgit_types::{
    AsciiSlug, Digest, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RefName,
};

use super::{delivery, issues, pull_request, storage};
use crate::{AdmissionError, RefusalCode};

fn run<F: Future>(future: F) -> F::Output {
    match Box::pin(future)
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("reference authority operations do not suspend"),
    }
}

#[derive(Clone)]
enum Fault {
    Missing,
    Replaced(Vec<u8>),
}

struct Store {
    backend: MemoryAuthorityStore,
    fault: Mutex<Option<(ImmutableKey, Fault)>>,
    reads: Mutex<Vec<ImmutableKey>>,
    writes: AtomicUsize,
}

impl Store {
    fn new() -> Self {
        Self {
            backend: MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x4_0007)),
            fault: Mutex::new(None),
            reads: Mutex::new(Vec::new()),
            writes: AtomicUsize::new(0),
        }
    }

    fn read_count(&self) -> usize {
        self.reads.lock().unwrap().len()
    }

    fn clear_reads(&self) {
        self.reads.lock().unwrap().clear();
    }
}

impl AsyncAuthorityStore for Store {
    type Context = ();

    fn instance_id(&self) -> StoreInstanceId {
        self.backend.instance_id()
    }

    fn limits(&self) -> AuthorityLimits {
        self.backend.limits()
    }

    fn put_if_absent(
        &self,
        (): &(),
        key: &ImmutableKey,
        body: &[u8],
    ) -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> + Send {
        self.writes.fetch_add(1, Ordering::Relaxed);
        std::future::ready(self.backend.put_if_absent(key, body))
    }

    fn read_immutable(
        &self,
        (): &(),
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        self.reads.lock().unwrap().push(key.clone());
        let fault = self.fault.lock().unwrap().clone();
        let result = match fault {
            Some((selected, fault)) if selected == *key => Ok(match fault {
                Fault::Missing => ImmutableRead::Absent,
                Fault::Replaced(bytes) => ImmutableRead::Present(bytes),
            }),
            _ => self.backend.read_immutable(key),
        };
        std::future::ready(result)
    }

    fn initialize_head(
        &self,
        (): &(),
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        self.writes.fetch_add(1, Ordering::Relaxed);
        std::future::ready(self.backend.initialize_head(key, generation, body))
    }

    fn read_head(
        &self,
        (): &(),
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send {
        std::future::ready(self.backend.read_head(key))
    }

    fn compare_exchange_head(
        &self,
        (): &(),
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        self.writes.fetch_add(1, Ordering::Relaxed);
        std::future::ready(
            self.backend
                .compare_exchange_head(key, expected, generation, body),
        )
    }

    fn authenticate_head_receipt(
        &self,
        (): &(),
        receipt: &HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send {
        std::future::ready(self.backend.authenticate_head_receipt(receipt))
    }
}

struct Fixture {
    store: Store,
    key: HeadKey,
    basis: PublicationBasis,
    state: delivery::DeliveryState,
    effects: Vec<CanonicalOutboxEffectState>,
    payloads: Vec<Digest>,
}

impl Fixture {
    fn new(batches: Vec<ForgeEventBatch>, stage_effects: bool) -> Self {
        Self::with_range_fault(batches, stage_effects, None)
    }

    fn with_range_fault(
        batches: Vec<ForgeEventBatch>,
        stage_effects: bool,
        malformed: Option<AggregateId>,
    ) -> Self {
        let store = Store::new();
        let mut head = genesis_head();
        let repository = head.repository_id;
        let mut forge = CanonicalForgePositionState::try_new(repository, Vec::new()).unwrap();
        let mut entries = Vec::new();
        let mut effects = Vec::new();
        let mut payloads = Vec::new();
        for batch in batches {
            let payload = run(storage::stage_body(
                &store,
                &(),
                repository,
                storage::EVENT_NAMESPACE,
                &batch,
            ))
            .unwrap();
            payloads.push(payload);
            forge = storage::advance_positions(&forge, &batch, payload).unwrap();
            let class = AsciiSlug::from_static("forge-event");
            let destination = AsciiSlug::from_static("forge-projection");
            let key = derive_outbox_delivery_key(OutboxDeliveryIdentityInput::new(
                repository,
                class,
                destination,
                payload,
                tx_id(),
                None,
            ))
            .unwrap();
            let effect = CanonicalOutboxEffectState::committed(repository, key, tx_id(), payload);
            entries.push(CanonicalOutboxStateEntry::new(
                key,
                class,
                destination,
                payload,
                tx_id(),
                None,
                storage::root(&effect).unwrap(),
                None,
            ));
            effects.push(effect);
        }
        if let Some(aggregate) = malformed {
            let stream = storage::aggregate_label(aggregate).unwrap();
            let positions = forge
                .entries()
                .iter()
                .map(|entry| {
                    if entry.stream() != stream {
                        return *entry;
                    }
                    // Keep the exact last version and payload. Only the claimed
                    // range is false: its first event is absent from this batch.
                    ForgePositionStateEntry::try_new(
                        stream,
                        entry.predecessor_position().checked_sub(1).unwrap(),
                        entry.event_count().checked_add(1).unwrap(),
                        entry.event_batch_root(),
                    )
                    .unwrap()
                })
                .collect();
            forge = CanonicalForgePositionState::try_new(repository, positions).unwrap();
        }
        let outbox = CanonicalOutboxState::try_new(repository, entries).unwrap();
        head.forge_position_root = run(storage::stage_body(
            &store,
            &(),
            repository,
            storage::POSITION_NAMESPACE,
            &forge,
        ))
        .unwrap();
        head.outbox_root = run(storage::stage_body(
            &store,
            &(),
            repository,
            delivery::OUTBOX_NAMESPACE,
            &outbox,
        ))
        .unwrap();
        let key = HeadKey::new(b"metadata-read-isolation/head".to_vec()).unwrap();
        fgit_authority::initialize_repository(&store.backend, &key, &head).unwrap();
        let basis = run(crate::read_basis_async(&store, &(), &key)).unwrap().0;
        let fixture = Self {
            store,
            key,
            basis,
            state: delivery::DeliveryState { forge, outbox },
            effects,
            payloads,
        };
        if stage_effects {
            fixture.stage_effects();
        }
        fixture.store.clear_reads();
        fixture
    }

    fn stage_effects(&self) {
        for effect in &self.effects {
            run(storage::stage_body(
                &self.store,
                &(),
                self.basis.body().repository_id,
                delivery::EFFECT_NAMESPACE,
                effect,
            ))
            .unwrap();
        }
    }

    fn key_for(&self, namespace: &[u8], root: Digest) -> ImmutableKey {
        storage::body_key(namespace, self.basis.body().repository_id, root).unwrap()
    }

    fn head(&self) -> HeadRead {
        self.store.backend.read_head(&self.key).unwrap()
    }
}

fn expected(version: u64) -> ExpectedVersion {
    if version == 1 {
        ExpectedVersion::NewStream
    } else {
        ExpectedVersion::Exactly(AggregateVersion::try_new(version - 1).unwrap())
    }
}

fn pr_number(number: u64) -> PullRequestNumber {
    PullRequestNumber::try_new(number).unwrap()
}

fn issue_number(number: u64) -> IssueNumber {
    IssueNumber::try_new(number).unwrap()
}

fn pr_event(number: u64, version: u64, format: GitHashAlgorithm) -> ForgeEvent {
    PullRequestCommand {
        number: pr_number(number),
        expected_version: expected(version),
        action: if version == 1 {
            PullRequestAction::Open
        } else {
            PullRequestAction::Update
        },
        data: PullRequestData {
            source_ref: RefName::try_new(format!("refs/heads/topic-{number}").as_bytes()).unwrap(),
            target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
            source_tip: GitOid::from_hex(format, &"11".repeat(format.digest_len())).unwrap(),
            target_tip: GitOid::from_hex(format, &"22".repeat(format.digest_len())).unwrap(),
            title: format!("PR {number} version {version}"),
            body: "Retained native metadata".into(),
        },
    }
    .proposed_event(PrincipalId::from_bytes([7; 16]), format)
    .unwrap()
}

fn issue_event(number: u64, version: u64) -> ForgeEvent {
    IssueCommand {
        number: issue_number(number),
        expected_version: expected(version),
        action: if version == 1 {
            IssueAction::Open {
                title: format!("Issue {number}"),
                body: "Initial issue text".into(),
                labels: Vec::new(),
            }
        } else {
            IssueAction::Comment {
                body: format!("Comment {version}"),
            }
        },
    }
    .proposed_event(PrincipalId::from_bytes([8; 16]))
    .unwrap()
}

fn history(numbers: &[u64], versions: u64, format: GitHashAlgorithm) -> Vec<ForgeEventBatch> {
    (1..=versions)
        .map(|version| ForgeEventBatch {
            events: numbers
                .iter()
                .flat_map(|number| {
                    [
                        pr_event(*number, version, format),
                        issue_event(*number, version),
                    ]
                })
                .collect(),
        })
        .collect()
}

#[derive(Clone, Copy, Debug)]
enum ReadKind {
    PullRequests,
    Issues,
    IssueHistory,
}

const READ_KINDS: [ReadKind; 3] = [
    ReadKind::PullRequests,
    ReadKind::Issues,
    ReadKind::IssueHistory,
];

#[derive(Debug, Eq, PartialEq)]
enum Page {
    PullRequests(pull_request::PullRequestPage),
    Issues(issues::IssuePage),
    IssueHistory(issues::IssueHistoryPage),
}

impl ReadKind {
    fn read<C: Fn() -> bool + Sync>(
        self,
        fixture: &Fixture,
        after: u64,
        limit: u16,
        cancelled: &C,
    ) -> Result<Page, AdmissionError> {
        match self {
            Self::PullRequests => run(pull_request::read_page_at(
                &fixture.store,
                &(),
                &fixture.basis,
                after,
                limit,
                &|_, _| true,
                cancelled,
            ))
            .map(Page::PullRequests),
            Self::Issues => run(issues::read_page_at(
                &fixture.store,
                &(),
                &fixture.basis,
                after,
                limit,
                cancelled,
            ))
            .map(Page::Issues),
            Self::IssueHistory => run(issues::read_history_at(
                &fixture.store,
                &(),
                &fixture.basis,
                issue_number(1),
                after,
                limit,
                cancelled,
            ))
            .map(Page::IssueHistory),
        }
    }
}

#[test]
fn metadata_reads_survive_missing_effects_while_delivery_preflight_still_refuses() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(history(&[1, 2], 2, format), false);
        let head = fixture.head();
        let writes = fixture.store.writes.load(Ordering::Relaxed);
        let pages: Vec<_> = READ_KINDS
            .iter()
            .map(|kind| kind.read(&fixture, 0, 100, &|| false).unwrap())
            .collect();
        assert!(fixture.store.reads.lock().unwrap().iter().all(|key| {
            !key.as_bytes().starts_with(delivery::EFFECT_NAMESPACE)
                && !key.as_bytes().starts_with(delivery::RECEIPT_NAMESPACE)
        }));
        assert_eq!(fixture.store.writes.load(Ordering::Relaxed), writes);
        assert!(matches!(
            run(delivery::read_in(
                &fixture.store,
                &(),
                &fixture.basis,
                &|| false
            )),
            Err(AdmissionError::AsyncProjectionUnavailable(
                RefusalCode::EvidenceMissing
            ))
        ));
        fixture.stage_effects();
        let complete = run(delivery::read_in(
            &fixture.store,
            &(),
            &fixture.basis,
            &|| false,
        ))
        .unwrap();
        assert_eq!(complete, fixture.state);
        for (kind, expected) in READ_KINDS.iter().zip(pages) {
            assert_eq!(kind.read(&fixture, 0, 100, &|| false).unwrap(), expected);
        }
        assert_eq!(
            fixture.head(),
            head,
            "projection and delivery reads must not publish"
        );
    }
}

#[test]
fn selected_map_and_event_evidence_never_becomes_a_successful_empty_page() {
    let fixture = Fixture::new(history(&[1], 2, GitHashAlgorithm::Sha256), true);
    let repository = fixture.basis.body().repository_id;
    let alternate_events = encode_body(&ForgeEventBatch {
        events: vec![pr_event(1, 3, GitHashAlgorithm::Sha256), issue_event(1, 3)],
    })
    .unwrap();
    let targets = [
        (
            fixture.key_for(
                storage::POSITION_NAMESPACE,
                fixture.basis.body().forge_position_root,
            ),
            encode_body(&CanonicalForgePositionState::try_new(repository, Vec::new()).unwrap())
                .unwrap(),
        ),
        (
            fixture.key_for(delivery::OUTBOX_NAMESPACE, fixture.basis.body().outbox_root),
            encode_body(&CanonicalOutboxState::try_new(repository, Vec::new()).unwrap()).unwrap(),
        ),
        (
            fixture.key_for(storage::EVENT_NAMESPACE, fixture.payloads[0]),
            alternate_events.clone(),
        ),
        (
            fixture.key_for(storage::EVENT_NAMESPACE, fixture.payloads[1]),
            alternate_events,
        ),
    ];
    let head = fixture.head();
    let writes = fixture.store.writes.load(Ordering::Relaxed);
    for kind in READ_KINDS {
        let expected = kind.read(&fixture, 0, 100, &|| false).unwrap();
        for (key, alternate) in &targets {
            for fault in [
                Fault::Missing,
                Fault::Replaced(vec![0]),
                Fault::Replaced(alternate.clone()),
            ] {
                *fixture.store.fault.lock().unwrap() = Some((key.clone(), fault));
                assert!(
                    matches!(
                        kind.read(&fixture, 0, 100, &|| false),
                        Err(AdmissionError::AsyncProjectionUnavailable(
                            RefusalCode::EvidenceMissing | RefusalCode::EvidenceInvalid
                        ))
                    ),
                    "{kind:?} must reject selected missing, corrupt or replayed evidence"
                );
                *fixture.store.fault.lock().unwrap() = None;
                assert_eq!(kind.read(&fixture, 0, 100, &|| false).unwrap(), expected);
            }
        }
    }
    assert_eq!(fixture.store.writes.load(Ordering::Relaxed), writes);
    assert_eq!(fixture.head(), head);
}

#[test]
fn selected_frontiers_validate_the_complete_range_not_only_the_last_version() {
    for aggregate in [
        AggregateId::PullRequest(pr_number(1)),
        AggregateId::Issue(issue_number(1)),
    ] {
        let fixture = Fixture::with_range_fault(
            history(&[1], 2, GitHashAlgorithm::Sha1),
            true,
            Some(aggregate),
        );
        let position = fixture
            .state
            .forge
            .entry(storage::aggregate_label(aggregate).unwrap())
            .unwrap();
        assert_eq!(position.successor_position(), 2);
        assert_eq!(position.event_count(), 2);
        // All map identities and the final event version are still valid.
        // Reading the named range must discover the missing first event.
        assert!(
            run(delivery::read_roots_in(
                &fixture.store,
                &(),
                &fixture.basis,
                &|| false
            ))
            .is_ok()
        );
        assert!(matches!(
            run(delivery::read_in(
                &fixture.store,
                &(),
                &fixture.basis,
                &|| false
            )),
            Err(AdmissionError::AsyncProjectionUnavailable(
                RefusalCode::EvidenceInvalid
            ))
        ));
        let selected = match aggregate {
            AggregateId::PullRequest(_) => ReadKind::PullRequests,
            AggregateId::Issue(_) => ReadKind::Issues,
            _ => unreachable!("fixture selects only PRs and issues"),
        };
        assert!(matches!(
            selected.read(&fixture, 0, 1, &|| false),
            Err(AdmissionError::AsyncProjectionUnavailable(
                RefusalCode::EvidenceInvalid
            ))
        ));
        if matches!(aggregate, AggregateId::Issue(_)) {
            assert!(matches!(
                ReadKind::IssueHistory.read(&fixture, 0, 1, &|| false),
                Err(AdmissionError::AsyncProjectionUnavailable(
                    RefusalCode::EvidenceInvalid
                ))
            ));
        }
        let repaired = Fixture::new(history(&[1], 2, GitHashAlgorithm::Sha1), true);
        assert!(selected.read(&repaired, 0, 1, &|| false).is_ok());
    }
}

#[test]
fn unselected_frontier_ranges_do_not_disable_a_healthy_metadata_page() {
    for aggregate in [
        AggregateId::PullRequest(pr_number(10)),
        AggregateId::Issue(issue_number(10)),
    ] {
        let fixture = Fixture::with_range_fault(
            history(&[10, 2, 1], 2, GitHashAlgorithm::Sha256),
            true,
            Some(aggregate),
        );
        assert!(
            run(delivery::read_in(
                &fixture.store,
                &(),
                &fixture.basis,
                &|| false
            ))
            .is_err()
        );
        let Page::PullRequests(prs) = ReadKind::PullRequests
            .read(&fixture, 0, 1, &|| false)
            .unwrap()
        else {
            panic!("PR page");
        };
        assert_eq!(prs.pull_requests.len(), 1);
        assert_eq!(prs.pull_requests[0].number, pr_number(1));
        assert_eq!(prs.pull_requests[0].event.version.get(), 2);
        assert_eq!(prs.next_after, Some(1));
        let Page::Issues(issues) = ReadKind::Issues.read(&fixture, 0, 1, &|| false).unwrap() else {
            panic!("issue page");
        };
        assert_eq!(issues.issues.len(), 1);
        assert_eq!(issues.issues[0].number, issue_number(1));
        assert_eq!(issues.issues[0].version.get(), 2);
        assert_eq!(issues.issues[0].comments, 1);
        assert_eq!(issues.next_after, Some(1));
        assert!(
            ReadKind::IssueHistory
                .read(&fixture, 0, 100, &|| false)
                .is_ok()
        );
    }
}

#[test]
fn cancellation_at_each_storage_read_returns_no_partial_page_and_retry_is_identical() {
    let fixture = Fixture::new(history(&[1, 2], 2, GitHashAlgorithm::Sha1), false);
    let head = fixture.head();
    let writes = fixture.store.writes.load(Ordering::Relaxed);
    for kind in READ_KINDS {
        fixture.store.clear_reads();
        let expected = kind.read(&fixture, 0, 100, &|| false).unwrap();
        let reads = fixture.store.read_count();
        assert!(reads >= 4, "both maps and selected events are actual reads");
        for stop_after in 0..=reads {
            fixture.store.clear_reads();
            let result = kind.read(&fixture, 0, 100, &|| {
                fixture.store.read_count() >= stop_after
            });
            assert!(
                matches!(
                    result,
                    Err(AdmissionError::AsyncProjectionUnavailable(
                        RefusalCode::CancellationInProgress
                    ))
                ),
                "{kind:?}, stop after {stop_after} storage reads"
            );
            assert_eq!(fixture.store.read_count(), stop_after);
            assert_eq!(kind.read(&fixture, 0, 100, &|| false).unwrap(), expected);
        }
    }
    assert_eq!(fixture.store.writes.load(Ordering::Relaxed), writes);
    assert_eq!(fixture.head(), head);
}

#[test]
fn projection_only_reads_preserve_numeric_pagination_history_and_visibility() {
    let fixture = Fixture::new(history(&[10, 1, 2], 3, GitHashAlgorithm::Sha256), false);
    let head = fixture.head();
    let writes = fixture.store.writes.load(Ordering::Relaxed);
    for kind in [ReadKind::PullRequests, ReadKind::Issues] {
        for (after, number, next) in [(0, 1, Some(1)), (1, 2, Some(2)), (2, 10, None)] {
            let page = kind.read(&fixture, after, 1, &|| false).unwrap();
            match &page {
                Page::PullRequests(page) => {
                    assert_eq!(page.source_head, fixture.basis.id());
                    assert_eq!(page.pull_requests.len(), 1);
                    assert_eq!(page.pull_requests[0].number.get(), number);
                    assert_eq!(page.pull_requests[0].event.version.get(), 3);
                    assert_eq!(
                        page.pull_requests[0].opened_by,
                        Some(PrincipalId::from_bytes([7; 16]))
                    );
                    assert_eq!(page.next_after, next);
                }
                Page::Issues(page) => {
                    assert_eq!(page.source_head, fixture.basis.id());
                    assert_eq!(page.issues.len(), 1);
                    assert_eq!(page.issues[0].number.get(), number);
                    assert_eq!(page.issues[0].version.get(), 3);
                    assert_eq!(page.issues[0].comments, 2);
                    assert_eq!(page.next_after, next);
                }
                Page::IssueHistory(_) => panic!("list query"),
            }
            assert_eq!(kind.read(&fixture, after, 1, &|| false).unwrap(), page);
        }
    }
    for (after, version, next) in [(0, 1, Some(1)), (1, 2, Some(2)), (2, 3, None)] {
        let Page::IssueHistory(page) = ReadKind::IssueHistory
            .read(&fixture, after, 1, &|| false)
            .unwrap()
        else {
            panic!("issue history");
        };
        assert_eq!(page.source_head, fixture.basis.id());
        assert_eq!(page.issue.as_ref().unwrap().version.get(), 3);
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].version.get(), version);
        assert_eq!(page.next_after, next);
    }
    let visible = run(pull_request::read_page_at(
        &fixture.store,
        &(),
        &fixture.basis,
        0,
        1,
        &|source, _| source.as_bytes() != b"refs/heads/topic-1",
        &|| false,
    ))
    .unwrap();
    assert_eq!(visible.pull_requests[0].number, pr_number(2));
    assert_eq!(visible.next_after, Some(2));
    let hidden = run(pull_request::read_page_at(
        &fixture.store,
        &(),
        &fixture.basis,
        0,
        1,
        &|_, _| false,
        &|| false,
    ))
    .unwrap();
    assert!(hidden.pull_requests.is_empty());
    assert_eq!(hidden.next_after, None);
    assert_eq!(fixture.store.writes.load(Ordering::Relaxed), writes);
    assert_eq!(fixture.head(), head);
}
