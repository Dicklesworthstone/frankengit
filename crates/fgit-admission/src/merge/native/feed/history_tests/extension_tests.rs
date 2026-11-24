//! A new head may reuse a prefix only after its complete canonical edge verifies.
use super::*;
use fgit_authority::{StoreInstanceId, authority_head_identity, body_key_for_id};
use fgit_chronicle::PublicationBasis;
use fgit_types::{HeadGeneration, RepositoryId, RepositorySequence};
use std::sync::atomic::{AtomicUsize, Ordering};

const INDEX_BYTES: usize = 32 * 1024 * 1024;

fn build(f: &Fixture) -> VerifiedEventIndex {
    ready(VerifiedEventIndex::build_at(
        &f.store,
        &(),
        &f.basis,
        INDEX_BYTES,
        &|| false,
    ))
    .unwrap()
}

fn extend(f: &Fixture, prefix: &VerifiedEventIndex) -> VerifiedEventIndex {
    ready(prefix.extend_at(&f.store, &(), &f.basis, INDEX_BYTES, &|| false))
        .unwrap()
        .expect("the published head directly succeeds the verified prefix")
}

fn page(
    f: &Fixture,
    index: &VerifiedEventIndex,
    after: Option<ForgeEventCursor>,
    limit: u16,
) -> ForgeEventPage {
    ready(index.read_page_at(&f.store, &(), &f.basis, after, limit, &|| false)).unwrap()
}

fn refuses(result: Result<Option<VerifiedEventIndex>, AdmissionError>, code: RefusalCode) {
    assert!(
        matches!(&result, Err(AdmissionError::AsyncProjectionUnavailable(actual)) if *actual == code),
        "expected {code:?}, observed {result:?}",
    );
}

#[test]
fn every_page_of_a_direct_extension_matches_canonical_replay() {
    let mut f = Fixture::new();
    f.append(&[2, 0]);
    f.checkpoint();
    let prefix = build(&f);
    f.append(&[0, 3, 1]);
    f.store.reset();
    let index = extend(&f, &prefix);
    assert_eq!(f.store.count(), 3, "one verified edge and one empty body");
    assert_eq!(index.source_head(), f.basis.id());
    let full = f.page(None, 100).unwrap();
    for after in std::iter::once(None).chain(full.events.iter().map(|row| Some(row.cursor))) {
        for limit in 1..=8 {
            assert_eq!(
                page(&f, &index, after, limit),
                f.page(after, limit).unwrap(),
                "after={after:?}, limit={limit}",
            );
        }
    }
}

#[test]
fn extension_reads_one_edge_independently_of_retained_history_length() {
    for length in [4, 64] {
        let mut f = Fixture::new();
        for _ in 0..length {
            f.append(&[1]);
        }
        let prefix = build(&f);
        f.append(&[1]);
        f.store.reset();
        let index = extend(&f, &prefix);
        assert_eq!(f.store.count(), 2, "prefix length {length}");
        assert_eq!(page(&f, &index, None, 100), f.page(None, 100).unwrap());
        // Previously verified metadata does not need to be fetched again.
        // The exact predecessor body of the new edge remains mandatory below.
        f.store.fault(Some(batch_key(&f.heads[0])), true);
        f.store.reset();
        let same = extend(&f, &prefix);
        assert_eq!(f.store.count(), 2);
        assert_eq!(page(&f, &same, None, 1).events.len(), 1);
        f.store.fault(None, false);
    }
}

#[test]
fn native_empty_reference_empty_refusal_and_checkpoint_successors_reuse_prefix() {
    let mut f = Fixture::new();
    f.append(&[2]);
    let mut index = build(&f);
    let original_events = f.page(None, 100).unwrap().events;
    for (kind, expected_reads) in [(0, 3), (1, 3), (2, 2), (3, 2)] {
        match kind {
            0 => f.append(&[0; 24]),
            1 => f.append_reference_empty(24),
            2 => f.append(&[]),
            3 => {
                f.checkpoint();
            }
            _ => unreachable!(),
        }
        f.store.reset();
        index = extend(&f, &index);
        assert_eq!(f.store.count(), expected_reads, "successor kind {kind}");
        let observed = page(&f, &index, None, 100);
        assert_eq!(observed.events, original_events);
        assert_eq!(observed, f.page(None, 100).unwrap());
    }
}

#[test]
fn same_and_skipped_heads_are_zero_io_misses_without_relabelling_the_prefix() {
    let mut f = Fixture::new();
    f.append(&[1]);
    let original = f.basis.clone();
    let prefix = build(&f);
    f.store.reset();
    assert!(
        ready(prefix.extend_at(&f.store, &(), &f.basis, INDEX_BYTES, &|| false))
            .unwrap()
            .is_none()
    );
    assert_eq!(f.store.count(), 0);
    f.append(&[1]);
    f.append(&[1]);
    f.store.reset();
    assert!(
        ready(prefix.extend_at(&f.store, &(), &f.basis, INDEX_BYTES, &|| false))
            .unwrap()
            .is_none()
    );
    assert_eq!(f.store.count(), 0);
    assert_eq!(prefix.source_head(), original.id());
    assert_eq!(
        ready(prefix.read_page_at(&f.store, &(), &original, None, 100, &|| false))
            .unwrap()
            .events
            .len(),
        1,
    );
}

#[test]
fn extension_checks_body_repository_and_store_even_before_an_unrelated_fast_miss() {
    let mut f = Fixture::new();
    f.append(&[1]);
    let original = f.basis.clone();
    let prefix = build(&f);
    f.append(&[1]);
    let direct = f.basis.clone();
    f.append(&[1]);
    f.store.reset();
    let forged = PublicationBasis::new(original.id(), f.basis.body().clone());
    refuses(
        ready(prefix.extend_at(&f.store, &(), &forged, INDEX_BYTES, &|| false)),
        RefusalCode::EvidenceInvalid,
    );
    let mut foreign_body = f.basis.body().clone();
    foreign_body.repository_id = RepositoryId::from_bytes([0x31; 16]);
    let foreign_basis = PublicationBasis::new(
        authority_head_identity(&foreign_body).unwrap(),
        foreign_body,
    );
    refuses(
        ready(prefix.extend_at(&f.store, &(), &foreign_basis, INDEX_BYTES, &|| false)),
        RefusalCode::EvidenceInvalid,
    );
    let foreign = Fixture::with_instance(StoreInstanceId::from_raw(0x701));
    refuses(
        ready(prefix.extend_at(&foreign.store, &(), &f.basis, INDEX_BYTES, &|| false)),
        RefusalCode::EvidenceInvalid,
    );
    assert_eq!(f.store.count(), 0);
    assert_eq!(foreign.store.count(), 0);
    assert!(
        ready(prefix.extend_at(&f.store, &(), &direct, INDEX_BYTES, &|| false))
            .unwrap()
            .is_some()
    );
}

#[test]
fn missing_or_corrupt_new_batch_or_predecessor_refuses_and_preserves_original_index() {
    let mut f = Fixture::new();
    f.append(&[1]);
    let original = f.basis.clone();
    let prefix = build(&f);
    f.append(&[1]);
    let predecessor_key = body_key_for_id(original.id().as_internal_object_id()).unwrap();
    for key in [predecessor_key, batch_key(f.heads.last().unwrap())] {
        for corrupt in [false, true] {
            f.store.fault(Some(key.clone()), corrupt);
            assert!(
                ready(prefix.extend_at(&f.store, &(), &f.basis, INDEX_BYTES, &|| false)).is_err()
            );
            assert_eq!(
                ready(prefix.read_page_at(&f.store, &(), &original, None, 1, &|| false))
                    .unwrap()
                    .events
                    .len(),
                1,
            );
            f.store.fault(None, false);
            assert_eq!(page(&f, &extend(&f, &prefix), None, 100).events.len(), 2);
        }
    }
}

#[test]
fn checkpoint_capsule_and_both_new_empty_schemas_must_verify() {
    for kind in 0..3 {
        let mut f = Fixture::new();
        f.append(&[1]);
        let prefix = build(&f);
        let key = if kind == 0 {
            f.checkpoint()
        } else {
            if kind == 1 {
                f.append(&[0]);
            } else {
                f.append_reference_empty(1);
            }
            let records = f.records(None, history::Limits::DEFAULT).unwrap();
            storage::body_key(
                storage::EVENT_NAMESPACE,
                f.basis.body().repository_id,
                records.last().unwrap().event_root,
            )
            .unwrap()
        };
        for corrupt in [false, true] {
            f.store.fault(Some(key.clone()), corrupt);
            assert!(
                ready(prefix.extend_at(&f.store, &(), &f.basis, INDEX_BYTES, &|| false)).is_err(),
                "successor kind {kind}, corrupt={corrupt}",
            );
            f.store.fault(None, false);
            assert_eq!(page(&f, &extend(&f, &prefix), None, 100).events.len(), 1);
        }
    }
}

#[test]
fn extended_pages_still_read_prefix_and_new_payloads_even_for_eof_cursors() {
    let mut f = Fixture::new();
    f.append(&[1]);
    let prefix = build(&f);
    f.append(&[1]);
    let index = extend(&f, &prefix);
    for record in f.records(None, history::Limits::DEFAULT).unwrap() {
        let key = storage::body_key(
            storage::EVENT_NAMESPACE,
            f.basis.body().repository_id,
            record.event_root,
        )
        .unwrap();
        for corrupt in [false, true] {
            f.store.fault(Some(key.clone()), corrupt);
            for after in [None, Some(cursor(record.sequence, 0))] {
                assert!(
                    ready(index.read_page_at(&f.store, &(), &f.basis, after, 100, &|| false))
                        .is_err()
                );
            }
            f.store.fault(None, false);
            assert_eq!(page(&f, &index, None, 100), f.page(None, 100).unwrap());
        }
    }
}

#[test]
fn cancellation_before_io_during_edge_and_during_prefix_copy_never_publishes_partial_index() {
    let mut f = Fixture::new();
    f.append(&[1; 64]);
    let original = f.basis.clone();
    let prefix = build(&f);
    f.append(&[1]);
    f.store.reset();
    refuses(
        ready(prefix.extend_at(&f.store, &(), &f.basis, INDEX_BYTES, &|| true)),
        RefusalCode::CancellationInProgress,
    );
    assert_eq!(f.store.count(), 0);
    refuses(
        ready(prefix.extend_at(&f.store, &(), &f.basis, INDEX_BYTES, &|| {
            f.store.count() >= 1
        })),
        RefusalCode::CancellationInProgress,
    );
    assert_eq!(f.store.count(), 1);

    f.store.reset();
    let polls_after_io = AtomicUsize::new(0);
    let complete = ready(prefix.extend_at(&f.store, &(), &f.basis, INDEX_BYTES, &|| {
        if f.store.count() == 2 {
            polls_after_io.fetch_add(1, Ordering::Relaxed);
        }
        false
    }))
    .unwrap()
    .unwrap();
    let polls = polls_after_io.load(Ordering::Relaxed);
    assert!(
        polls > 64,
        "copying every retained row must poll cancellation"
    );
    f.store.reset();
    polls_after_io.store(0, Ordering::Relaxed);
    refuses(
        ready(prefix.extend_at(&f.store, &(), &f.basis, INDEX_BYTES, &|| {
            f.store.count() == 2 && polls_after_io.fetch_add(1, Ordering::Relaxed) >= polls - 5
        })),
        RefusalCode::CancellationInProgress,
    );
    assert_eq!(f.store.count(), 2);
    assert_eq!(prefix.source_head(), original.id());
    assert_eq!(
        ready(prefix.read_page_at(&f.store, &(), &original, None, 100, &|| false))
            .unwrap()
            .events
            .len(),
        64,
    );
    assert_eq!(
        page(&f, &extend(&f, &prefix), None, 100),
        page(&f, &complete, None, 100)
    );
}

#[test]
fn extension_accounts_for_the_complete_retained_allocation_and_exact_cap() {
    let mut f = Fixture::new();
    f.append(&[1, 1, 1]);
    let original = f.basis.clone();
    let prefix = build(&f);
    f.append(&[2]);
    let full = build(&f);
    let bytes = full.retained_bytes();
    f.store.reset();
    refuses(
        ready(prefix.extend_at(&f.store, &(), &f.basis, 0, &|| false)),
        RefusalCode::ResourceBudgetExceeded,
    );
    assert_eq!(f.store.count(), 0);
    refuses(
        ready(prefix.extend_at(&f.store, &(), &f.basis, bytes - 1, &|| false)),
        RefusalCode::ResourceBudgetExceeded,
    );
    let exact = ready(prefix.extend_at(&f.store, &(), &f.basis, bytes, &|| false))
        .unwrap()
        .unwrap();
    assert_eq!(exact.retained_bytes(), bytes);
    assert_eq!(page(&f, &exact, None, 100), page(&f, &full, None, 100));
    assert_eq!(
        ready(prefix.read_page_at(&f.store, &(), &original, None, 100, &|| false))
            .unwrap()
            .events
            .len(),
        3,
    );
}

#[test]
fn extension_preserves_total_record_and_predecessor_edge_profile_limits_before_io() {
    let mut f = Fixture::new();
    f.append(&[1]);
    let prefix = build(&f);
    f.append(&[1]);
    for records in [true, false] {
        let mut body = f.basis.body().clone();
        if records {
            body.latest_repository_sequence = Some(
                RepositorySequence::try_new(history::Limits::DEFAULT.records as u64 + 1).unwrap(),
            );
        } else {
            body.generation =
                HeadGeneration::try_new(history::Limits::DEFAULT.batches as u64 + 2).unwrap();
        }
        let oversized = PublicationBasis::new(authority_head_identity(&body).unwrap(), body);
        f.store.reset();
        refuses(
            ready(prefix.extend_at(&f.store, &(), &oversized, INDEX_BYTES, &|| false)),
            RefusalCode::ResourceBudgetExceeded,
        );
        assert_eq!(f.store.count(), 0);
    }
    assert_eq!(page(&f, &extend(&f, &prefix), None, 100).events.len(), 2);
}

#[test]
fn a_genesis_index_extends_into_the_first_committed_publication() {
    let mut f = Fixture::new();
    let prefix = build(&f);
    assert!(page(&f, &prefix, None, 10).events.is_empty());
    f.append(&[2]);
    f.store.reset();
    let index = extend(&f, &prefix);
    assert_eq!(f.store.count(), 2);
    assert_eq!(page(&f, &index, None, 10), f.page(None, 10).unwrap());
}

#[test]
fn a_matching_predecessor_and_valid_body_digest_do_not_replace_transition_verification() {
    for checkpoint in [false, true] {
        let mut f = Fixture::new();
        f.append(&[1]);
        let prefix = build(&f);
        if checkpoint {
            f.checkpoint();
        } else {
            f.append(&[1]);
        }
        let mut body = f.basis.body().clone();
        body.ref_root = body.forge_position_root;
        let forged = PublicationBasis::new(authority_head_identity(&body).unwrap(), body);
        f.store.reset();
        refuses(
            ready(prefix.extend_at(&f.store, &(), &forged, INDEX_BYTES, &|| false)),
            RefusalCode::EvidenceInvalid,
        );
        assert_eq!(f.store.count(), 2, "complete transition was checked");
        assert_eq!(
            page(&f, &extend(&f, &prefix), None, 100),
            f.page(None, 100).unwrap()
        );
    }
}
