//! The production review readers over authenticated reference-store heads.
//! These fixtures seed canonical bodies; they are not durable-node or crash
//! evidence, and synthetic votes do not attest to an executed review.

use super::*;
use fgit_authority::{
    AuthorityFailure, AuthorityLimits, AuthorityStore, AuthorityVersionToken, CasOutcome, HeadInit,
    HeadKey, HeadRead, HeadReadReceipt, ImmutableKey, ImmutableRead, MemoryAuthorityStore,
    PutOutcome, StoreInstanceId,
};
use fgit_codec::harness::{genesis_head, tx_id};
use fgit_codec::{
    CanonicalBody, CanonicalOutboxEffectState, CanonicalOutboxState, CanonicalOutboxStateEntry,
    ForgePositionStateEntry,
};
use fgit_forge::event::issue::{IssueAction, IssueCommand};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::event::review::ReviewSubject;
use fgit_forge::{ExpectedVersion, IssueNumber};
use fgit_types::{Digest, GitHashAlgorithm, GitOid, RepositoryId};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
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

#[derive(Clone, Copy)]
enum ReadFault {
    Missing,
    Tampered,
}

struct Store {
    memory: MemoryAuthorityStore,
    reads: Mutex<BTreeMap<ImmutableKey, usize>>,
    fault: Mutex<Option<(ImmutableKey, ReadFault)>>,
    cancel_on: Mutex<Option<(ImmutableKey, usize)>>,
    cancelled: AtomicBool,
}
impl Store {
    fn reset_reads(&self) {
        self.reads.lock().unwrap().clear();
        self.cancelled.store(false, Ordering::Relaxed);
        *self.cancel_on.lock().unwrap() = None;
    }
    fn reads_of(&self, key: &ImmutableKey) -> usize {
        self.reads.lock().unwrap().get(key).copied().unwrap_or(0)
    }
    fn reads_in(&self, namespace: &[u8]) -> usize {
        self.reads
            .lock()
            .unwrap()
            .iter()
            .filter(|(key, _)| key.as_bytes().starts_with(namespace))
            .map(|(_, count)| *count)
            .sum()
    }
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
        let count = {
            let mut reads = self.reads.lock().unwrap();
            let count = reads.entry(key.clone()).or_default();
            *count += 1;
            *count
        };
        if self.cancel_on.lock().unwrap().as_ref() == Some(&(key.clone(), count)) {
            self.cancelled.store(true, Ordering::Relaxed);
        }
        let fault = self
            .fault
            .lock()
            .unwrap()
            .as_ref()
            .filter(|(fault_key, _)| fault_key == key)
            .map(|(_, fault)| *fault);
        let result = match fault {
            Some(ReadFault::Missing) => Ok(ImmutableRead::Absent),
            Some(ReadFault::Tampered) => self.memory.read_immutable(key).map(|value| {
                let ImmutableRead::Present(mut frame) = value else {
                    panic!("tamper target must exist");
                };
                let byte = frame.last_mut().expect("canonical frame is nonempty");
                *byte ^= 1;
                ImmutableRead::Present(frame)
            }),
            None => self.memory.read_immutable(key),
        };
        std::future::ready(result)
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

struct Fixture {
    store: Store,
    basis: PublicationBasis,
    positions: CanonicalForgePositionState,
    refs: BTreeMap<RefName, GitOid>,
    subject: ReviewSubject,
    candidate: CandidateBinding,
}
impl Fixture {
    fn new(format: GitHashAlgorithm, unrelated: u64, reviews: Vec<ForgeEvent>) -> Self {
        let store = Store {
            memory: MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x4e71)),
            reads: Mutex::new(BTreeMap::new()),
            fault: Mutex::new(None),
            cancel_on: Mutex::new(None),
            cancelled: AtomicBool::new(false),
        };
        let repository = RepositoryId::from_bytes([0x42; 16]);
        let subject = subject(format);
        let pr = PullRequestCommand {
            number: PullRequestNumber::FIRST,
            expected_version: ExpectedVersion::NewStream,
            action: PullRequestAction::Open,
            data: PullRequestData {
                source_ref: subject.source_ref.clone(),
                target_ref: subject.target_ref.clone(),
                source_tip: subject.source_tip,
                target_tip: subject.target_tip,
                title: "Exact candidate".into(),
                body: "PR opener belongs to this canonical event".into(),
            },
        }
        .proposed_event(principal(7), format)
        .unwrap();
        let mut batches = vec![ForgeEventBatch::of_one(pr)];
        batches.extend(reviews.into_iter().map(ForgeEventBatch::of_one));
        let issues: Vec<_> = (1..=unrelated)
            .map(|number| {
                IssueCommand {
                    number: IssueNumber::try_new(number).unwrap(),
                    expected_version: ExpectedVersion::NewStream,
                    action: IssueAction::Open {
                        title: format!("Unrelated {number}"),
                        body: String::new(),
                        labels: Vec::new(),
                    },
                }
                .proposed_event(principal(8))
                .unwrap()
            })
            .collect();
        // Each source frame and the outbox map fit the reference store's
        // ordinary 1 MiB body bound. The forge map still has every aggregate.
        batches.extend(issues.chunks(64).map(|events| ForgeEventBatch {
            events: events.to_vec(),
        }));
        let mut positions = CanonicalForgePositionState::try_new(repository, Vec::new()).unwrap();
        let mut obligations = Vec::new();
        for batch in batches {
            let payload = stage(&store, repository, storage::EVENT_NAMESPACE, &batch);
            positions = storage::advance_positions(&positions, &batch, payload).unwrap();
            let class = AsciiSlug::from_static("forge-event");
            let destination = AsciiSlug::from_static("forge-projection");
            let key = fgit_codec::derive_outbox_delivery_key(
                fgit_codec::OutboxDeliveryIdentityInput::new(
                    repository,
                    class,
                    destination,
                    payload,
                    tx_id(),
                    None,
                ),
            )
            .unwrap();
            let effect = CanonicalOutboxEffectState::committed(repository, key, tx_id(), payload);
            let effect_root = stage(&store, repository, delivery::EFFECT_NAMESPACE, &effect);
            obligations.push(CanonicalOutboxStateEntry::new(
                key,
                class,
                destination,
                payload,
                tx_id(),
                None,
                effect_root,
                None,
            ));
        }
        let outbox = CanonicalOutboxState::try_new(repository, obligations).unwrap();
        let mut head = genesis_head();
        head.repository_id = repository;
        head.forge_position_root =
            stage(&store, repository, storage::POSITION_NAMESPACE, &positions);
        head.outbox_root = stage(&store, repository, delivery::OUTBOX_NAMESPACE, &outbox);
        let key = HeadKey::new(b"review-read/head".to_vec()).unwrap();
        fgit_authority::initialize_repository(&store.memory, &key, &head).unwrap();
        let basis = run(crate::read_basis_async(&store, &(), &key)).unwrap().0;
        store.reset_reads();
        Self {
            store,
            basis,
            positions,
            refs: BTreeMap::from([
                (subject.source_ref.clone(), subject.source_tip),
                (subject.target_ref.clone(), subject.target_tip),
            ]),
            subject,
            candidate: candidate(format),
        }
    }
    fn key(&self, reviewer: u8) -> ImmutableKey {
        let label = storage::aggregate_label(AggregateId::PullRequestReview {
            pull_request: PullRequestNumber::FIRST,
            reviewer: principal(reviewer),
        })
        .unwrap();
        storage::body_key(
            storage::EVENT_NAMESPACE,
            self.basis.body().repository_id,
            self.positions.entry(label).unwrap().event_batch_root(),
        )
        .unwrap()
    }
    fn pr_page(&self) {
        run(super::super::read_page_at(
            &self.store,
            &(),
            &self.basis,
            0,
            1,
            &|_, _| true,
            &|| false,
        ))
        .unwrap();
    }
    fn page(
        &self,
        after: Option<PrincipalId>,
        limit: u16,
    ) -> Result<Option<ReviewPage>, AdmissionError> {
        run(read_page_at(
            &self.store,
            &(),
            &self.basis,
            PullRequestNumber::FIRST,
            &self.refs,
            after,
            limit,
            &|_, _| true,
            &|| self.store.cancelled.load(Ordering::Relaxed),
        ))
    }
    fn gate(&self, reviewers: Vec<PrincipalId>) -> Result<(), ProjectionFailure> {
        let intent = super::super::super::NativeMergeIntent::new(
            PullRequestNumber::FIRST,
            ExpectedVersion::Exactly(AggregateVersion::FIRST),
            self.candidate.merge(&self.subject),
        )
        .unwrap();
        let requirements = gate::ReviewRequirements::new(PolicyEpoch::FIRST, reviewers).unwrap();
        run(gate::verify_at(
            &self.store,
            &(),
            &self.basis,
            &intent,
            principal(3),
            &requirements,
            &|| self.store.cancelled.load(Ordering::Relaxed),
        ))
    }
}

fn principal(byte: u8) -> PrincipalId {
    PrincipalId::from_bytes([byte; 16])
}
fn oid(format: GitHashAlgorithm, byte: &str) -> GitOid {
    GitOid::from_hex(format, &byte.repeat(format.digest_len())).unwrap()
}
fn subject(format: GitHashAlgorithm) -> ReviewSubject {
    ReviewSubject {
        pull_request: PullRequestNumber::FIRST,
        pull_request_version: AggregateVersion::FIRST,
        source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
        target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
        source_tip: oid(format, "11"),
        target_tip: oid(format, "22"),
        policy_epoch: PolicyEpoch::FIRST,
    }
}
fn candidate(format: GitHashAlgorithm) -> CandidateBinding {
    CandidateBinding {
        merge_base: oid(format, "33"),
        commit: oid(format, "44"),
    }
}
fn vote(format: GitHashAlgorithm, reviewer: u8) -> ForgeEvent {
    CandidateReviewCommand {
        review: ReviewCommand {
            expected_version: ExpectedVersion::NewStream,
            subject: subject(format),
            decision: ReviewDecision::Approve,
            reason: "Exact synthetic review".into(),
        },
        candidate: candidate(format),
    }
    .proposed_event(principal(reviewer), format)
    .unwrap()
}
fn stage<B: CanonicalBody + Sync>(
    store: &Store,
    repository: RepositoryId,
    namespace: &[u8],
    body: &B,
) -> Digest {
    run(storage::stage_body(store, &(), repository, namespace, body)).unwrap()
}
fn assert_refusal<T: std::fmt::Debug>(result: Result<T, AdmissionError>, expected: RefusalCode) {
    assert!(
        matches!(&result, Err(AdmissionError::AsyncProjectionUnavailable(code)) if *code == expected),
        "expected {expected:?}, got {result:?}"
    );
}

#[test]
fn review_pages_cross_4096_unrelated_streams_without_delivery_replay() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format, 4097, vec![vote(format, 12), vote(format, 9)]);
        assert_eq!(fixture.positions.entries().len(), 4100);
        fixture.pr_page();
        let parent_events = fixture.store.reads_in(storage::EVENT_NAMESPACE);
        fixture.store.reset_reads();
        let page = fixture.page(None, 1).unwrap().unwrap();
        assert_eq!(page.reviews.len(), 1);
        assert_eq!(page.reviews[0].event.reviewer, principal(9));
        assert_eq!(page.reviews[0].freshness, ReviewFreshness::Current);
        assert_eq!(page.reviews[0].reviewer_is_opener, Some(false));
        assert_eq!(page.next_after, Some(principal(9)));
        assert_eq!(page.source_head, fixture.basis.id());
        assert_eq!(fixture.store.reads_in(delivery::EFFECT_NAMESPACE), 0);
        assert_eq!(
            fixture.store.reads_in(storage::EVENT_NAMESPACE),
            parent_events + 2
        );
        let last = fixture.page(page.next_after, 1).unwrap().unwrap();
        assert_eq!(last.reviews[0].event.reviewer, principal(12));
        assert_eq!(last.next_after, None);
    }
}

#[test]
fn named_review_gate_reads_only_named_frontiers_after_the_pr() {
    let format = GitHashAlgorithm::Sha256;
    let fixture = Fixture::new(format, 32, vec![vote(format, 9), vote(format, 12)]);
    fixture.pr_page();
    let selected_reads = fixture.store.reads_of(&fixture.key(9));
    let unlisted_reads = fixture.store.reads_of(&fixture.key(12));
    fixture.store.reset_reads();
    fixture.gate(vec![principal(9)]).unwrap();
    assert_eq!(fixture.store.reads_of(&fixture.key(9)), selected_reads + 1);
    assert_eq!(fixture.store.reads_of(&fixture.key(12)), unlisted_reads);
    assert_eq!(fixture.store.reads_in(delivery::EFFECT_NAMESPACE), 0);
    assert!(matches!(
        fixture.gate(vec![principal(13)]),
        Err(ProjectionFailure::Refuse(RefusalCode::EvidenceMissing))
    ));
}

#[test]
fn selected_review_range_is_checked_even_when_the_last_version_matches() {
    let format = GitHashAlgorithm::Sha1;
    let fixture = Fixture::new(format, 0, vec![vote(format, 9)]);
    let first = vote(format, 9);
    let mut second = first.clone();
    second.version = AggregateVersion::try_new(2).unwrap();
    let aggregate = first.aggregate;
    for (events, permitted) in [(vec![first, second.clone()], true), (vec![second], false)] {
        let batch = ForgeEventBatch { events };
        let root = stage(
            &fixture.store,
            fixture.basis.body().repository_id,
            storage::EVENT_NAMESPACE,
            &batch,
        );
        let positions = CanonicalForgePositionState::try_new(
            fixture.basis.body().repository_id,
            vec![
                ForgePositionStateEntry::try_new(
                    storage::aggregate_label(aggregate).unwrap(),
                    0,
                    2,
                    root,
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let result = run(review_frontier(&fixture.store, &(), &positions, aggregate));
        if permitted {
            assert_eq!(result.unwrap().unwrap().version.get(), 2);
        } else {
            assert_refusal(result, RefusalCode::EvidenceInvalid);
        }
    }
}

#[test]
fn selected_missing_and_tampered_reviews_refuse_with_an_intact_twin() {
    let format = GitHashAlgorithm::Sha256;
    let fixture = Fixture::new(format, 0, vec![vote(format, 9)]);
    let aggregate = AggregateId::PullRequestReview {
        pull_request: PullRequestNumber::FIRST,
        reviewer: principal(9),
    };
    let read = || {
        run(review_frontier(
            &fixture.store,
            &(),
            &fixture.positions,
            aggregate,
        ))
    };
    assert!(read().unwrap().is_some());
    for (fault, code) in [
        (ReadFault::Missing, RefusalCode::EvidenceMissing),
        (ReadFault::Tampered, RefusalCode::EvidenceInvalid),
    ] {
        *fixture.store.fault.lock().unwrap() = Some((fixture.key(9), fault));
        assert_refusal(read(), code);
        *fixture.store.fault.lock().unwrap() = None;
        assert!(read().unwrap().is_some());
    }
}

#[test]
fn review_visibility_freshness_and_bounded_pagination_are_preserved() {
    let format = GitHashAlgorithm::Sha1;
    let mut fixture = Fixture::new(
        format,
        0,
        vec![vote(format, 13), vote(format, 7), vote(format, 11)],
    );
    let first = fixture.page(None, 2).unwrap().unwrap();
    assert_eq!(
        first
            .reviews
            .iter()
            .map(|row| row.event.reviewer)
            .collect::<Vec<_>>(),
        vec![principal(7), principal(11)]
    );
    assert_eq!(first.reviews[0].reviewer_is_opener, Some(true));
    assert_eq!(first.next_after, Some(principal(11)));
    assert_eq!(fixture.page(None, 2).unwrap().unwrap(), first);
    assert_eq!(
        fixture.page(first.next_after, 2).unwrap().unwrap().reviews[0]
            .event
            .reviewer,
        principal(13)
    );
    assert_refusal(fixture.page(None, 0), RefusalCode::ResourceBudgetExceeded);
    assert_refusal(fixture.page(None, 101), RefusalCode::ResourceBudgetExceeded);
    let hidden = run(read_page_at(
        &fixture.store,
        &(),
        &fixture.basis,
        PullRequestNumber::FIRST,
        &fixture.refs,
        None,
        2,
        &|_, _| false,
        &|| false,
    ))
    .unwrap();
    assert_eq!(hidden, None);
    fixture
        .refs
        .insert(fixture.subject.source_ref.clone(), oid(format, "55"));
    assert!(
        fixture
            .page(None, 3)
            .unwrap()
            .unwrap()
            .reviews
            .iter()
            .all(|row| row.freshness == ReviewFreshness::SourceMoved)
    );
}

#[test]
fn cancellation_during_the_last_selected_review_never_returns_a_page_or_approval() {
    let format = GitHashAlgorithm::Sha1;
    let fixture = Fixture::new(format, 0, vec![vote(format, 9)]);
    fixture.pr_page();
    let parent_reads = fixture.store.reads_of(&fixture.key(9));
    for gate_read in [false, true] {
        fixture.store.reset_reads();
        *fixture.store.cancel_on.lock().unwrap() = Some((fixture.key(9), parent_reads + 1));
        if gate_read {
            assert!(matches!(
                fixture.gate(vec![principal(9)]),
                Err(ProjectionFailure::Unavailable(
                    RefusalCode::CancellationInProgress
                ))
            ));
        } else {
            assert_refusal(fixture.page(None, 1), RefusalCode::CancellationInProgress);
        }
        fixture.store.reset_reads();
        assert_eq!(fixture.page(None, 1).unwrap().unwrap().reviews.len(), 1);
        fixture.gate(vec![principal(9)]).unwrap();
    }
}
