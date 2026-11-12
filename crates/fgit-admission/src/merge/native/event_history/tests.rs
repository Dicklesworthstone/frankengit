//! Reference-store tests of authenticated seeded history and bounded selection.
//! Durable publication, retirement and reopen are covered by native node tests.

use super::*;
use crate::merge::native::metadata_read_tests::{Store, run};
use fgit_authority::{HeadKey, initialize_repository_async};
use fgit_codec::harness::{genesis_head, tx_id};
use fgit_codec::{
    CanonicalOutboxEffectState, CanonicalOutboxStateEntry, OutboxDeliveryIdentityInput,
    derive_outbox_delivery_key,
};
use fgit_forge::event::issue::{IssueAction, IssueCommand};
use fgit_forge::{ExpectedVersion, IssueNumber};
use fgit_types::{AsciiSlug, PrincipalId};
use std::sync::atomic::{AtomicBool, Ordering};

struct Fixture {
    store: Store,
    basis: PublicationBasis,
    forge: CanonicalForgePositionState,
    outbox: CanonicalOutboxState,
}

impl Fixture {
    /// All history bodies exist, but only frontier and active roots are retained
    /// by this genesis. This distinction catches accidental object enumeration.
    fn new(history: &[ForgeEventBatch], active: &[ForgeEventBatch]) -> Self {
        let store = Store::new();
        let mut head = genesis_head();
        let repository = head.repository_id;
        let mut forge = CanonicalForgePositionState::try_new(repository, Vec::new()).unwrap();
        for batch in history {
            let root = run(storage::stage_body(
                &store,
                &(),
                repository,
                storage::EVENT_NAMESPACE,
                batch,
            ))
            .unwrap();
            forge = storage::advance_positions(&forge, batch, root).unwrap();
        }
        let entries = active
            .iter()
            .map(|batch| {
                let root = run(storage::stage_body(
                    &store,
                    &(),
                    repository,
                    storage::EVENT_NAMESPACE,
                    batch,
                ))
                .unwrap();
                let effect = AsciiSlug::from_static("forge-event");
                let destination = AsciiSlug::from_static("forge-projection");
                let delivery_key = derive_outbox_delivery_key(OutboxDeliveryIdentityInput::new(
                    repository,
                    effect,
                    destination,
                    root,
                    tx_id(),
                    None,
                ))
                .unwrap();
                let state =
                    CanonicalOutboxEffectState::committed(repository, delivery_key, tx_id(), root);
                let state_root = run(storage::stage_body(
                    &store,
                    &(),
                    repository,
                    delivery::EFFECT_NAMESPACE,
                    &state,
                ))
                .unwrap();
                CanonicalOutboxStateEntry::new(
                    delivery_key,
                    effect,
                    destination,
                    root,
                    tx_id(),
                    None,
                    state_root,
                    None,
                )
            })
            .collect();
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
        let key = HeadKey::new(b"selected-event-history/head".to_vec()).unwrap();
        run(initialize_repository_async(&store, &(), &key, &head)).unwrap();
        let basis = run(crate::read_basis_async(&store, &(), &key)).unwrap().0;
        let state = run(delivery::read_roots_in(&store, &(), &basis, &|| false)).unwrap();
        assert_eq!(state.forge, forge);
        assert_eq!(state.outbox, outbox);
        Self {
            store,
            basis,
            forge,
            outbox,
        }
    }

    fn selected(&self, numbers: &[u64]) -> BTreeMap<AggregateId, ForgePositionStateEntry> {
        numbers
            .iter()
            .map(|number| {
                let aggregate = AggregateId::Issue(IssueNumber::try_new(*number).unwrap());
                (
                    aggregate,
                    *self
                        .forge
                        .entry(storage::aggregate_label(aggregate).unwrap())
                        .unwrap(),
                )
            })
            .collect()
    }

    fn visit(
        &self,
        selected: &BTreeMap<AggregateId, ForgePositionStateEntry>,
        limits: HistoryReadLimits,
        visitor: &mut (impl FnMut(&ForgeEvent, usize) -> Result<(), AdmissionError> + Send),
        cancelled: &(impl Fn() -> bool + Sync),
    ) -> Result<HistoryReadSummary, AdmissionError> {
        run(visit_selected_at(
            &self.store,
            &(),
            &self.basis,
            &self.forge,
            &self.outbox,
            selected,
            limits,
            visitor,
            cancelled,
        ))
    }
}

fn event(number: u64, version: u64) -> ForgeEvent {
    IssueCommand {
        number: IssueNumber::try_new(number).unwrap(),
        expected_version: if version == 1 {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(AggregateVersion::try_new(version - 1).unwrap())
        },
        action: if version == 1 {
            IssueAction::Open {
                title: format!("Issue {number}"),
                body: "original body".into(),
                labels: Vec::new(),
            }
        } else {
            IssueAction::Comment {
                body: format!("Comment {version}"),
            }
        },
    }
    .proposed_event(PrincipalId::from_bytes([3; 16]))
    .unwrap()
}

#[test]
fn shared_frontiers_and_outbox_are_read_once_without_retaining_unselected_payloads() {
    let batch = ForgeEventBatch {
        events: vec![event(1, 1), event(2, 1), event(1, 2)],
    };
    let fixture = Fixture::new(std::slice::from_ref(&batch), std::slice::from_ref(&batch));
    for selected in [fixture.selected(&[1]), fixture.selected(&[1, 2])] {
        let mut visited = BTreeMap::new();
        let summary = fixture
            .visit(
                &selected,
                HistoryReadLimits::DEFAULT,
                &mut |event, bytes| {
                    assert_eq!(bytes, fgit_codec::encode_body(event).unwrap().len());
                    assert!(
                        visited
                            .insert((event.aggregate, event.version), bytes)
                            .is_none()
                    );
                    Ok(())
                },
                &|| false,
            )
            .unwrap();
        assert_eq!(summary.scanned_events, 3);
        assert_eq!(
            summary.scanned_bytes,
            fgit_codec::encode_body(&batch).unwrap().len()
        );
        assert_eq!(visited.len(), if selected.len() == 1 { 2 } else { 3 });
    }
}

#[test]
fn unreferenced_object_presence_cannot_fill_a_gap_in_genesis_history() {
    let first = ForgeEventBatch {
        events: vec![event(1, 1)],
    };
    let second = ForgeEventBatch {
        events: vec![event(1, 2)],
    };
    let history = [first.clone(), second];
    let incomplete = Fixture::new(&history, &[]);
    assert!(matches!(
        incomplete.visit(
            &incomplete.selected(&[1]),
            HistoryReadLimits::DEFAULT,
            &mut |_, _| Ok(()),
            &|| false,
        ),
        Err(AdmissionError::AsyncProjectionUnavailable(
            RefusalCode::EvidenceMissing
        )),
    ));
    let complete = Fixture::new(&history, &[first]);
    let mut versions = BTreeSet::new();
    complete
        .visit(
            &complete.selected(&[1]),
            HistoryReadLimits::DEFAULT,
            &mut |event, _| {
                versions.insert(event.version.get());
                Ok(())
            },
            &|| false,
        )
        .unwrap();
    assert_eq!(versions, BTreeSet::from([1, 2]));
}

#[test]
fn a_conflicting_duplicate_in_another_authenticated_payload_is_not_ignored() {
    let original = event(1, 1);
    let mut changed = original.clone();
    let fgit_forge::ForgeEventPayload::IssueChangedNative(change) = &mut changed.payload else {
        unreachable!()
    };
    let IssueAction::Open { body, .. } = &mut change.action else {
        unreachable!()
    };
    *body = "conflicting original body".into();
    let history = [ForgeEventBatch {
        events: vec![original.clone()],
    }];
    let fixture = Fixture::new(
        &history,
        &[ForgeEventBatch {
            events: vec![changed],
        }],
    );
    assert!(matches!(
        fixture.visit(
            &fixture.selected(&[1]),
            HistoryReadLimits::DEFAULT,
            &mut |_, _| Ok(()),
            &|| false,
        ),
        Err(AdmissionError::AsyncProjectionUnavailable(
            RefusalCode::EvidenceInvalid
        )),
    ));
    let consistent = Fixture::new(&history, &history);
    let mut visited = 0;
    consistent
        .visit(
            &consistent.selected(&[1]),
            HistoryReadLimits::DEFAULT,
            &mut |_, _| {
                visited += 1;
                Ok(())
            },
            &|| false,
        )
        .unwrap();
    assert_eq!(visited, 1);
}

#[test]
fn all_scanned_events_and_bytes_are_charged_before_visiting_a_batch() {
    let batch = ForgeEventBatch {
        events: vec![event(1, 1), event(2, 1)],
    };
    let bytes = fgit_codec::encode_body(&batch).unwrap().len();
    let fixture = Fixture::new(&[batch], &[]);
    let selected = fixture.selected(&[1]);
    for limits in [
        HistoryReadLimits {
            events: 1,
            scan_bytes: bytes,
        },
        HistoryReadLimits {
            events: 2,
            scan_bytes: bytes - 1,
        },
        HistoryReadLimits {
            events: 0,
            scan_bytes: bytes,
        },
        HistoryReadLimits {
            events: HistoryReadLimits::DEFAULT.events + 1,
            scan_bytes: bytes,
        },
        HistoryReadLimits {
            events: 2,
            scan_bytes: 0,
        },
        HistoryReadLimits {
            events: 2,
            scan_bytes: HistoryReadLimits::DEFAULT.scan_bytes + 1,
        },
    ] {
        let mut visited = false;
        assert!(matches!(
            fixture.visit(
                &selected,
                limits,
                &mut |_, _| {
                    visited = true;
                    Ok(())
                },
                &|| false,
            ),
            Err(AdmissionError::AsyncProjectionUnavailable(
                RefusalCode::ResourceBudgetExceeded
            )),
        ));
        assert!(!visited);
    }
    assert_eq!(
        fixture
            .visit(
                &selected,
                HistoryReadLimits {
                    events: 2,
                    scan_bytes: bytes
                },
                &mut |_, _| Ok(()),
                &|| false,
            )
            .unwrap(),
        HistoryReadSummary {
            scanned_events: 2,
            scanned_bytes: bytes
        },
    );
}

#[test]
fn cancellation_and_visitor_refusal_never_become_a_partial_success() {
    let batch = ForgeEventBatch {
        events: vec![event(1, 1), event(1, 2)],
    };
    let fixture = Fixture::new(&[batch], &[]);
    let selected = fixture.selected(&[1]);
    let cancelled = AtomicBool::new(false);
    assert!(matches!(
        fixture.visit(
            &selected,
            HistoryReadLimits::DEFAULT,
            &mut |_, _| {
                cancelled.store(true, Ordering::Relaxed);
                Ok(())
            },
            &|| cancelled.load(Ordering::Relaxed),
        ),
        Err(AdmissionError::AsyncProjectionUnavailable(
            RefusalCode::CancellationInProgress
        )),
    ));
    assert!(matches!(
        fixture.visit(
            &selected,
            HistoryReadLimits::DEFAULT,
            &mut |_, _| Err(unavailable(RefusalCode::ResourceBudgetExceeded)),
            &|| false,
        ),
        Err(AdmissionError::AsyncProjectionUnavailable(
            RefusalCode::ResourceBudgetExceeded
        )),
    ));
    assert_eq!(
        fixture
            .visit(
                &selected,
                HistoryReadLimits::DEFAULT,
                &mut |_, _| Ok(()),
                &|| false
            )
            .unwrap()
            .scanned_events,
        2,
    );
}

#[test]
fn selected_entries_and_even_an_empty_selection_must_bind_the_asserted_head() {
    let fixture = Fixture::new(
        &[ForgeEventBatch {
            events: vec![event(1, 1)],
        }],
        &[],
    );
    let mut selected = fixture.selected(&[1]);
    let position = selected.values_mut().next().unwrap();
    *position = ForgePositionStateEntry::try_new(
        position.stream(),
        0,
        1,
        storage::root(&ForgeEventBatch { events: Vec::new() }).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        fixture.visit(
            &selected,
            HistoryReadLimits::DEFAULT,
            &mut |_, _| Ok(()),
            &|| false
        ),
        Err(AdmissionError::AsyncProjectionUnavailable(
            RefusalCode::EvidenceInvalid
        )),
    ));
    let empty = BTreeMap::new();
    assert_eq!(
        fixture
            .visit(
                &empty,
                HistoryReadLimits::DEFAULT,
                &mut |_, _| Ok(()),
                &|| false
            )
            .unwrap(),
        HistoryReadSummary {
            scanned_events: 0,
            scanned_bytes: 0
        },
    );
    let mut body = fixture.basis.body().clone();
    body.policy_epoch = fgit_types::PolicyEpoch::try_new(2).unwrap();
    let mismatched = PublicationBasis::new(fixture.basis.id(), body);
    assert!(matches!(
        run(visit_selected_at(
            &fixture.store,
            &(),
            &mismatched,
            &fixture.forge,
            &fixture.outbox,
            &empty,
            HistoryReadLimits::DEFAULT,
            &mut |_, _| Ok(()),
            &|| false,
        )),
        Err(AdmissionError::AsyncProjectionUnavailable(
            RefusalCode::EvidenceInvalid
        )),
    ));
}
