//! Stored canonical-body differential and I/O regressions for delivery preflight.
//! The reference authority is not filesystem durability or native-node evidence.

use std::future::{Future, ready};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use fgit_authority::{
    AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityStore, AuthorityVersionToken,
    CasOutcome, HeadInit, HeadKey, HeadRead, HeadReadReceipt, ImmutableKey, ImmutableRead,
    MemoryAuthorityStore, PutOutcome, StoreInstanceId,
};
use fgit_codec::harness::{genesis_head, tx_id};
use fgit_codec::{ForgePositionStateEntry, encode_body};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::{AggregateVersion, ExpectedVersion, ForgeEvent, PullRequestNumber};
use fgit_resource::LifecycleEvent;
use fgit_types::{AsciiSlug, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RefName};

use super::*;

#[derive(Clone)]
enum Fault {
    Missing,
    Replaced(Vec<u8>),
}

struct Store {
    backend: MemoryAuthorityStore,
    reads: Mutex<Vec<ImmutableKey>>,
    fault: Mutex<Option<(ImmutableKey, Fault)>>,
    writes: AtomicUsize,
}

impl Store {
    fn new(limits: AuthorityLimits) -> Self {
        Self {
            backend: MemoryAuthorityStore::with_config(fgit_authority::MemoryStoreConfig {
                instance: StoreInstanceId::from_raw(0x0040_0701),
                limits,
                ..fgit_authority::MemoryStoreConfig::default()
            }),
            reads: Mutex::new(Vec::new()),
            fault: Mutex::new(None),
            writes: AtomicUsize::new(0),
        }
    }

    fn clear_reads(&self) {
        self.reads.lock().unwrap().clear();
    }

    fn read_count(&self) -> usize {
        self.reads.lock().unwrap().len()
    }

    fn event_reads(&self) -> usize {
        self.reads
            .lock()
            .unwrap()
            .iter()
            .filter(|key| key.as_bytes().starts_with(storage::EVENT_NAMESPACE))
            .count()
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
        ready(self.backend.put_if_absent(key, body))
    }

    fn read_immutable(
        &self,
        (): &(),
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        self.reads.lock().unwrap().push(key.clone());
        let fault = self.fault.lock().unwrap().clone();
        ready(match fault {
            Some((selected, fault)) if selected == *key => Ok(match fault {
                Fault::Missing => ImmutableRead::Absent,
                Fault::Replaced(bytes) => ImmutableRead::Present(bytes),
            }),
            _ => self.backend.read_immutable(key),
        })
    }

    fn initialize_head(
        &self,
        (): &(),
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        self.writes.fetch_add(1, Ordering::Relaxed);
        ready(self.backend.initialize_head(key, generation, body))
    }

    fn read_head(
        &self,
        (): &(),
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send {
        ready(self.backend.read_head(key))
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
        ready(
            self.backend
                .compare_exchange_head(key, expected, generation, body),
        )
    }

    fn authenticate_head_receipt(
        &self,
        (): &(),
        receipt: &HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send {
        ready(self.backend.authenticate_head_receipt(receipt))
    }
}

fn run<F: Future>(future: F) -> F::Output {
    match Box::pin(future)
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("reference authority operations do not suspend"),
    }
}

fn event(number: u64, version: u64, format: GitHashAlgorithm) -> ForgeEvent {
    PullRequestCommand {
        number: PullRequestNumber::try_new(number).unwrap(),
        expected_version: if version == 1 {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(AggregateVersion::try_new(version - 1).unwrap())
        },
        action: if version == 1 {
            PullRequestAction::Open
        } else {
            PullRequestAction::Update
        },
        data: PullRequestData {
            source_ref: RefName::try_new(format!("refs/heads/topic-{number}").as_bytes()).unwrap(),
            target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
            source_tip: GitOid::from_hex(format, &"a".repeat(format.digest_len() * 2)).unwrap(),
            target_tip: GitOid::from_hex(format, &"b".repeat(format.digest_len() * 2)).unwrap(),
            title: format!("PR {number}, version {version}"),
            body: format!("exact source text {number}/{version}: <script>é</script>"),
        },
    }
    .proposed_event(PrincipalId::from_bytes([7; 16]), format)
    .unwrap()
}

struct Fixture {
    store: Store,
    state: DeliveryState,
    basis: PublicationBasis,
    payloads: Vec<Digest>,
}

impl Fixture {
    fn new(batches: Vec<ForgeEventBatch>, destinations: usize, settled: bool) -> Self {
        Self::with_limits(batches, destinations, settled, AuthorityLimits::default())
    }

    fn with_limits(
        batches: Vec<ForgeEventBatch>,
        destinations: usize,
        settled: bool,
        limits: AuthorityLimits,
    ) -> Self {
        let store = Store::new(limits);
        let mut head = genesis_head();
        let repository = head.repository_id;
        let mut forge = CanonicalForgePositionState::try_new(repository, Vec::new()).unwrap();
        let mut entries = Vec::new();
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
            for destination in 0..destinations {
                let destination = AsciiSlug::try_new(
                    "destination",
                    format!("projection-{destination}").as_bytes(),
                )
                .unwrap();
                let class = AsciiSlug::from_static("forge-event");
                let key = derive_outbox_delivery_key(OutboxDeliveryIdentityInput::new(
                    repository,
                    class,
                    destination,
                    payload,
                    tx_id(),
                    None,
                ))
                .unwrap();
                let mut effect =
                    CanonicalOutboxEffectState::committed(repository, key, tx_id(), payload);
                run(storage::stage_body(
                    &store,
                    &(),
                    repository,
                    EFFECT_NAMESPACE,
                    &effect,
                ))
                .unwrap();
                if settled {
                    let receipt = CanonicalOutboxDeliveryReceipt::try_new(
                        repository,
                        key,
                        destination,
                        payload,
                        effect.root().unwrap(),
                        OutboxDeliveryDisposition::Acknowledged,
                        b"receiver accepted stable key".to_vec(),
                    )
                    .unwrap();
                    let receipt_root = run(storage::stage_body(
                        &store,
                        &(),
                        repository,
                        RECEIPT_NAMESPACE,
                        &receipt,
                    ))
                    .unwrap();
                    effect = effect
                        .transition(LifecycleEvent::Acknowledge, Some(receipt_root))
                        .unwrap();
                    run(storage::stage_body(
                        &store,
                        &(),
                        repository,
                        EFFECT_NAMESPACE,
                        &effect,
                    ))
                    .unwrap();
                }
                entries.push(CanonicalOutboxStateEntry::new(
                    key,
                    class,
                    destination,
                    payload,
                    tx_id(),
                    None,
                    effect.root().unwrap(),
                    effect.predecessor_root(),
                ));
            }
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
            OUTBOX_NAMESPACE,
            &outbox,
        ))
        .unwrap();
        let basis = PublicationBasis::new(
            fgit_authority::authority_head_identity(&head).unwrap(),
            head,
        );
        Self {
            store,
            state: DeliveryState { forge, outbox },
            basis,
            payloads,
        }
    }

    fn select_forge(&mut self, entries: Vec<ForgePositionStateEntry>) {
        self.state.forge =
            CanonicalForgePositionState::try_new(self.basis.body().repository_id, entries).unwrap();
        let mut head = self.basis.body().clone();
        head.forge_position_root = run(storage::stage_body(
            &self.store,
            &(),
            head.repository_id,
            storage::POSITION_NAMESPACE,
            &self.state.forge,
        ))
        .unwrap();
        self.basis = PublicationBasis::new(
            fgit_authority::authority_head_identity(&head).unwrap(),
            head,
        );
    }

    fn read(&self) -> Result<DeliveryState, AdmissionError> {
        run(read_in(&self.store, &(), &self.basis, &|| false))
    }
}

/// Unoptimized preflight retained as a differential oracle: one full batch
/// decode for every frontier and every delivery entry, in canonical map order.
fn reference(fixture: &Fixture) -> Result<DeliveryState, AdmissionError> {
    run(async {
        let state = read_roots_in(&fixture.store, &(), &fixture.basis, &|| false).await?;
        let repository = fixture.basis.body().repository_id;
        for position in state.forge.entries() {
            let events =
                storage::read_events(&fixture.store, &(), repository, position.event_batch_root())
                    .await?;
            validate_position_batch(position, &events)?;
        }
        for entry in state.outbox.entries() {
            read_effect_in(&fixture.store, &(), repository, entry, &|| false).await?;
            let payload =
                storage::read_events(&fixture.store, &(), repository, entry.payload_root()).await?;
            validate_payload_positions(&state.forge, &payload)?;
        }
        Ok(state)
    })
}

#[test]
fn bulk_frontiers_and_delivery_fanout_read_each_stored_payload_once() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(
            (1..=3)
                .map(|version| ForgeEventBatch {
                    events: (1..=128)
                        .rev()
                        .map(|number| event(number, version, format))
                        .collect(),
                })
                .collect(),
            32,
            true,
        );
        fixture.store.clear_reads();
        let expected = reference(&fixture).unwrap();
        assert_eq!(fixture.store.event_reads(), 128 + 3 * 32);
        let reference_reads = fixture.store.read_count();
        fixture.store.clear_reads();
        let writes = fixture.store.writes.load(Ordering::Relaxed);
        let actual = fixture.read().unwrap();
        assert_eq!(actual, expected);
        assert_eq!(actual, fixture.state);
        assert_eq!(
            encode_body(&actual.forge).unwrap(),
            encode_body(&expected.forge).unwrap()
        );
        assert_eq!(
            encode_body(&actual.outbox).unwrap(),
            encode_body(&expected.outbox).unwrap()
        );
        assert_eq!(fixture.store.event_reads(), 3);
        assert_eq!(reference_reads - fixture.store.read_count(), 221);
        assert_eq!(fixture.store.writes.load(Ordering::Relaxed), writes);
        fixture.store.clear_reads();
        assert_eq!(fixture.read().unwrap(), actual);
        assert_eq!(
            fixture.store.event_reads(),
            3,
            "no persistent payload cache masks a read"
        );
    }
}

#[test]
fn incremental_mixed_stream_histories_match_the_full_preflight_oracle() {
    for seed in 1_u64..=24 {
        let format = if seed % 2 == 0 {
            GitHashAlgorithm::Sha1
        } else {
            GitHashAlgorithm::Sha256
        };
        let mut random = seed;
        let mut versions = [0_u64; 8];
        let mut batches = Vec::new();
        for _ in 0..6 {
            let mut events = Vec::new();
            for _ in 0..12 {
                random = random
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                let index = (random >> 32) as usize % versions.len();
                versions[index] += 1;
                events.push(event(index as u64 + 1, versions[index], format));
            }
            batches.push(ForgeEventBatch { events });
        }
        let fixture = Fixture::new(batches, (seed % 4) as usize, seed % 3 == 0);
        assert_eq!(
            fixture.read().unwrap(),
            reference(&fixture).unwrap(),
            "seed {seed}"
        );
        assert_eq!(fixture.read().unwrap(), fixture.state, "seed {seed}");
    }
}

#[test]
fn grouped_ranges_require_every_selected_streams_complete_contiguous_range() {
    let mut fixture = Fixture::new(
        vec![ForgeEventBatch {
            events: vec![
                event(1, 1, GitHashAlgorithm::Sha1),
                event(2, 1, GitHashAlgorithm::Sha1),
                event(1, 2, GitHashAlgorithm::Sha1),
                event(2, 2, GitHashAlgorithm::Sha1),
            ],
        }],
        2,
        false,
    );
    let original = fixture.state.forge.entries().to_vec();
    for index in 0..original.len() {
        let entry = original[index];
        for (before, count) in [(0, 1), (0, 3), (1, 1), (1, 2)] {
            let mut bad = original.clone();
            bad[index] = ForgePositionStateEntry::try_new(
                entry.stream(),
                before,
                count,
                entry.event_batch_root(),
            )
            .unwrap();
            fixture.select_forge(bad);
            assert!(matches!(
                fixture.read(),
                Err(AdmissionError::AsyncProjectionUnavailable(
                    RefusalCode::EvidenceInvalid
                ))
            ));
            assert!(matches!(
                reference(&fixture),
                Err(AdmissionError::AsyncProjectionUnavailable(
                    RefusalCode::EvidenceInvalid
                ))
            ));
            fixture.select_forge(original.clone());
            assert_eq!(fixture.read().unwrap(), reference(&fixture).unwrap());
        }
    }
}

#[test]
fn deduplication_does_not_skip_payloads_effects_receipts_or_root_commitments() {
    let fixture = Fixture::new(
        (1..=2)
            .map(|version| ForgeEventBatch {
                events: vec![
                    event(1, version, GitHashAlgorithm::Sha256),
                    event(2, version, GitHashAlgorithm::Sha256),
                ],
            })
            .collect(),
        3,
        true,
    );
    fixture.read().unwrap();
    let keys = fixture.store.reads.lock().unwrap().clone();
    assert!(
        keys.iter()
            .any(|key| key.as_bytes().starts_with(RECEIPT_NAMESPACE))
    );
    assert!(
        keys.iter()
            .any(|key| key.as_bytes().starts_with(EFFECT_NAMESPACE))
    );
    let different = encode_body(&ForgeEventBatch {
        events: vec![event(3, 1, GitHashAlgorithm::Sha256)],
    })
    .unwrap();
    for key in keys {
        for fault in [
            Fault::Missing,
            Fault::Replaced(b"corrupt canonical body".to_vec()),
            Fault::Replaced(different.clone()),
        ] {
            *fixture.store.fault.lock().unwrap() = Some((key.clone(), fault));
            let expected = reference(&fixture).unwrap_err();
            let actual = fixture.read().unwrap_err();
            assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
            *fixture.store.fault.lock().unwrap() = None;
            assert_eq!(fixture.read().unwrap(), fixture.state);
        }
    }
}

#[test]
fn every_read_interruption_returns_no_partial_state_and_retry_revalidates_bodies() {
    let fixture = Fixture::new(
        vec![ForgeEventBatch {
            events: (1..=9)
                .map(|number| event(number, 1, GitHashAlgorithm::Sha1))
                .collect(),
        }],
        4,
        true,
    );
    fixture.store.clear_reads();
    let expected = fixture.read().unwrap();
    let reads = fixture.store.read_count();
    for boundary in 0..=reads {
        fixture.store.clear_reads();
        assert!(
            matches!(
                run(read_in(&fixture.store, &(), &fixture.basis, &|| fixture
                    .store
                    .read_count()
                    >= boundary)),
                Err(AdmissionError::AsyncProjectionUnavailable(
                    RefusalCode::CancellationInProgress
                )),
            ),
            "read boundary {boundary}"
        );
        assert_eq!(fixture.store.read_count(), boundary);
        fixture.store.clear_reads();
        assert_eq!(fixture.read().unwrap(), expected);
        assert_eq!(fixture.store.event_reads(), fixture.payloads.len());
    }
}

#[test]
fn the_existing_full_frontier_envelope_uses_one_payload_read() {
    let count = fgit_codec::MAX_FORGE_POSITION_STATE_ENTRIES;
    let fixture = Fixture::with_limits(
        vec![ForgeEventBatch {
            events: (1..=count as u64)
                .map(|number| event(number, 1, GitHashAlgorithm::Sha256))
                .collect(),
        }],
        0,
        false,
        AuthorityLimits {
            // This full-envelope fixture uses the reader's complete-frame allowance.
            body_bytes: usize::try_from(DecodeLimits::DEFAULT.frame_bytes).unwrap(),
            ..AuthorityLimits::default()
        },
    );
    fixture.store.clear_reads();
    assert_eq!(fixture.read().unwrap(), fixture.state);
    assert_eq!(fixture.state.forge.entries().len(), count);
    assert_eq!(fixture.store.event_reads(), 1);
    assert_eq!(
        fixture.store.read_count(),
        3,
        "two maps plus one shared payload"
    );
}

#[test]
fn frontier_only_batches_keep_the_existing_unselected_stream_semantics() {
    for destinations in [0, 2] {
        let mut fixture = Fixture::new(
            vec![ForgeEventBatch {
                events: vec![
                    event(1, 1, GitHashAlgorithm::Sha1),
                    event(2, 1, GitHashAlgorithm::Sha1),
                ],
            }],
            destinations,
            false,
        );
        let original = fixture.state.forge.entries().to_vec();
        fixture.select_forge(vec![original[0]]);
        if destinations == 0 {
            assert_eq!(fixture.read().unwrap(), reference(&fixture).unwrap());
        } else {
            assert!(matches!(
                fixture.read(),
                Err(AdmissionError::AsyncProjectionUnavailable(
                    RefusalCode::EvidenceInvalid
                ))
            ));
            assert!(matches!(
                reference(&fixture),
                Err(AdmissionError::AsyncProjectionUnavailable(
                    RefusalCode::EvidenceInvalid
                ))
            ));
        }
        fixture.select_forge(original);
        assert_eq!(fixture.read().unwrap(), reference(&fixture).unwrap());
    }
}

#[test]
fn cancellation_during_a_shared_batch_does_not_wait_for_the_next_storage_read() {
    let fixture = Fixture::new(
        vec![ForgeEventBatch {
            events: (1..=32)
                .map(|number| event(number, 1, GitHashAlgorithm::Sha1))
                .collect(),
        }],
        1,
        false,
    );
    for event_boundary in 1..=32 {
        fixture.store.clear_reads();
        let checkpoints_after_payload_read = AtomicUsize::new(0);
        let cancelled = || {
            fixture.store.event_reads() != 0
                && checkpoints_after_payload_read.fetch_add(1, Ordering::Relaxed) >= event_boundary
        };
        assert!(matches!(
            run(read_in(&fixture.store, &(), &fixture.basis, &cancelled)),
            Err(AdmissionError::AsyncProjectionUnavailable(
                RefusalCode::CancellationInProgress
            )),
        ));
        assert_eq!(
            fixture.store.read_count(),
            3,
            "cancellation stays inside the shared batch"
        );
        fixture.store.clear_reads();
        assert_eq!(fixture.read().unwrap(), fixture.state);
    }
}

#[test]
fn grouped_frontier_errors_keep_precedence_against_an_intervening_missing_body() {
    let format = GitHashAlgorithm::Sha1;
    let mut fixture = Fixture::new(
        vec![
            ForgeEventBatch {
                events: vec![event(1, 1, format), event(3, 1, format)],
            },
            ForgeEventBatch {
                events: vec![event(2, 1, format)],
            },
        ],
        0,
        false,
    );
    let original = fixture.state.forge.entries().to_vec();
    let missing = storage::body_key(
        storage::EVENT_NAMESPACE,
        fixture.basis.body().repository_id,
        fixture.payloads[1],
    )
    .unwrap();
    for number in [1, 3] {
        let stream = storage::aggregate_label(event(number, 1, format).aggregate).unwrap();
        let mut entries = original.clone();
        let position = entries
            .iter_mut()
            .find(|entry| entry.stream() == stream)
            .unwrap();
        *position =
            ForgePositionStateEntry::try_new(stream, 0, 2, position.event_batch_root()).unwrap();
        fixture.select_forge(entries);
        *fixture.store.fault.lock().unwrap() = Some((missing.clone(), Fault::Missing));
        let expected = if number == 1 {
            RefusalCode::EvidenceInvalid
        } else {
            RefusalCode::EvidenceMissing
        };
        for result in [reference(&fixture), fixture.read()] {
            assert!(
                matches!(result, Err(AdmissionError::AsyncProjectionUnavailable(code)) if code == expected)
            );
        }
        *fixture.store.fault.lock().unwrap() = None;
        for result in [reference(&fixture), fixture.read()] {
            assert!(matches!(
                result,
                Err(AdmissionError::AsyncProjectionUnavailable(
                    RefusalCode::EvidenceInvalid
                ))
            ));
        }
        fixture.select_forge(original.clone());
        assert_eq!(fixture.read().unwrap(), reference(&fixture).unwrap());
    }
}

#[test]
fn prevalidated_payload_errors_keep_precedence_against_missing_delivery_effects() {
    let mut fixture = Fixture::new(
        vec![ForgeEventBatch {
            events: vec![
                event(1, 1, GitHashAlgorithm::Sha256),
                event(2, 1, GitHashAlgorithm::Sha256),
            ],
        }],
        2,
        false,
    );
    let original = fixture.state.forge.entries().to_vec();
    for missing_index in 0..2 {
        // The selected frontier is complete for its own stream, but the outbox
        // payload also names a stream absent from the selected forge map.
        fixture.select_forge(vec![original[0]]);
        let entry = fixture.state.outbox.entries()[missing_index];
        let key = storage::body_key(
            EFFECT_NAMESPACE,
            fixture.basis.body().repository_id,
            entry.effect_state_root(),
        )
        .unwrap();
        *fixture.store.fault.lock().unwrap() = Some((key, Fault::Missing));
        let expected = if missing_index == 0 {
            RefusalCode::EvidenceMissing
        } else {
            RefusalCode::EvidenceInvalid
        };
        for result in [reference(&fixture), fixture.read()] {
            assert!(
                matches!(result, Err(AdmissionError::AsyncProjectionUnavailable(code)) if code == expected)
            );
        }
        *fixture.store.fault.lock().unwrap() = None;
        for result in [reference(&fixture), fixture.read()] {
            assert!(matches!(
                result,
                Err(AdmissionError::AsyncProjectionUnavailable(
                    RefusalCode::EvidenceInvalid
                ))
            ));
        }
        fixture.select_forge(original.clone());
        assert_eq!(fixture.read().unwrap(), reference(&fixture).unwrap());
    }
}
