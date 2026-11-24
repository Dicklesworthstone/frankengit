//! Indexed pages compared with the unchanged canonical-history oracle.
use super::*;
use fgit_authority::{StoreInstanceId, authority_head_identity};
use fgit_chronicle::PublicationBasis;
use fgit_types::RepositoryId;

const INDEX_BYTES: usize = 32 * 1024 * 1024;

#[test]
fn retention_preflight_avoids_history_io_for_clearly_undersized_caches() {
    let mut f = Fixture::new();
    f.append(&[1, 1, 1]);
    let index = build(&f);
    f.store.reset();
    assert!(VerifiedEventIndex::fits_retention_budget(
        &f.basis,
        index.retained_bytes(),
    ));
    assert!(!VerifiedEventIndex::fits_retention_budget(&f.basis, 0));
    assert!(!VerifiedEventIndex::fits_retention_budget(
        &f.basis,
        index.retained_bytes() - 1,
    ));
    assert_eq!(f.store.count(), 0);
    assert_eq!(f.page(None, 100).unwrap().events.len(), 3);
}

fn build(fixture: &Fixture) -> VerifiedEventIndex {
    ready(VerifiedEventIndex::build_at(
        &fixture.store,
        &(),
        &fixture.basis,
        INDEX_BYTES,
        &|| false,
    ))
    .unwrap()
}

fn page(
    fixture: &Fixture,
    index: &VerifiedEventIndex,
    after: Option<ForgeEventCursor>,
    limit: u16,
) -> Result<ForgeEventPage, AdmissionError> {
    ready(index.read_page_at(&fixture.store, &(), &fixture.basis, after, limit, &|| false))
}

fn refuses(result: Result<ForgeEventPage, AdmissionError>, code: RefusalCode) {
    assert!(
        matches!(&result, Err(AdmissionError::AsyncProjectionUnavailable(actual)) if *actual == code),
        "expected {code:?}, observed {result:?}",
    );
}

#[test]
fn every_indexed_page_matches_canonical_replay_across_empty_commits_and_checkpoints() {
    let mut f = Fixture::new();
    f.append(&[2, 0]);
    f.append(&[]);
    f.checkpoint();
    f.append_reference_empty(3);
    f.append(&[3, 0, 1, 2]);
    let index = build(&f);
    assert_eq!(index.source_head(), f.basis.id());
    assert!(index.retained_bytes() <= INDEX_BYTES);
    let full = f.page(None, 100).unwrap();
    for after in std::iter::once(None).chain(full.events.iter().map(|row| Some(row.cursor))) {
        for limit in 1..=10 {
            let expected = f.page(after, limit).unwrap();
            let observed = page(&f, &index, after, limit).unwrap();
            assert_eq!(observed, expected, "after={after:?}, limit={limit}");
        }
    }
}

#[test]
fn warm_old_cursor_and_first_page_reads_do_not_grow_with_history_length() {
    for length in [4, 64] {
        let mut f = Fixture::new();
        for _ in 0..length {
            f.append(&[1]);
        }
        let index = build(&f);
        for (after, limit, reads) in [(None, 2, 3), (Some(cursor(1, 0)), 2, 4)] {
            let expected = f.page(after, limit).unwrap();
            f.store.reset();
            assert_eq!(page(&f, &index, after, limit).unwrap(), expected);
            assert_eq!(f.store.count(), reads, "history length {length}");
        }
        f.store.reset();
        assert!(
            page(&f, &index, Some(cursor(length, 0)), 1)
                .unwrap()
                .events
                .is_empty()
        );
        assert_eq!(f.store.count(), 1, "EOF still verifies the cursor payload");
    }
}

#[test]
fn both_empty_event_schemas_are_verified_once_and_never_scanned_by_warm_pages() {
    let mut f = Fixture::new();
    f.append(&[1]);
    f.append(&[0; 48]);
    f.append_reference_empty(48);
    f.append(&[2]);
    f.store.reset();
    let index = build(&f);
    assert_eq!(
        f.store.count(),
        10,
        "four verified batch/predecessor pairs and two exact empty bodies",
    );
    let expected = f.page(Some(cursor(1, 0)), 1).unwrap();
    f.store.reset();
    assert_eq!(page(&f, &index, Some(cursor(1, 0)), 1).unwrap(), expected);
    assert_eq!(f.store.count(), 2, "cursor and next nonempty batch only");
    for sequence in [2, 49, 50, 97] {
        f.store.reset();
        refuses(
            page(&f, &index, Some(cursor(sequence, 0)), 1),
            RefusalCode::EvidenceStale,
        );
        assert_eq!(f.store.count(), 0, "an empty RCR is not an event cursor");
    }
}

#[test]
fn cached_coordinates_do_not_hide_missing_or_corrupt_selected_payload_even_at_eof() {
    let mut f = Fixture::new();
    f.append(&[1, 2]);
    let index = build(&f);
    let records = f.records(None, history::Limits::DEFAULT).unwrap();
    let key = storage::body_key(
        storage::EVENT_NAMESPACE,
        f.basis.body().repository_id,
        records[1].event_root,
    )
    .unwrap();
    for corrupt in [false, true] {
        f.store.fault(Some(key.clone()), corrupt);
        for after in [Some(cursor(1, 0)), Some(cursor(2, 1))] {
            refuses(
                page(&f, &index, after, 10),
                if corrupt {
                    RefusalCode::EvidenceInvalid
                } else {
                    RefusalCode::EvidenceMissing
                },
            );
        }
        f.store.fault(None, false);
        assert_eq!(
            page(&f, &index, Some(cursor(1, 0)), 10)
                .unwrap()
                .events
                .len(),
            2,
        );
        assert!(
            page(&f, &index, Some(cursor(2, 1)), 10)
                .unwrap()
                .events
                .is_empty()
        );
    }
}

#[test]
fn missing_or_corrupt_empty_body_cannot_be_certified_as_empty_history() {
    let mut f = Fixture::new();
    f.append(&[0]);
    f.append_reference_empty(1);
    let roots = f.records(None, history::Limits::DEFAULT).unwrap();
    for record in roots {
        let key = storage::body_key(
            storage::EVENT_NAMESPACE,
            f.basis.body().repository_id,
            record.event_root,
        )
        .unwrap();
        for corrupt in [false, true] {
            f.store.fault(Some(key.clone()), corrupt);
            let result = ready(VerifiedEventIndex::build_at(
                &f.store,
                &(),
                &f.basis,
                INDEX_BYTES,
                &|| false,
            ));
            assert!(result.is_err());
            f.store.fault(None, false);
            assert!(page(&f, &build(&f), None, 1).unwrap().events.is_empty());
        }
    }
}

#[test]
fn index_refuses_changed_head_body_repository_and_store_before_payload_io() {
    let mut f = Fixture::new();
    f.append(&[1]);
    let original = f.basis.clone();
    let index = build(&f);
    f.append(&[1]);
    f.store.reset();
    refuses(page(&f, &index, None, 1), RefusalCode::EvidenceStale);
    assert_eq!(f.store.count(), 0);
    let forged = PublicationBasis::new(original.id(), f.basis.body().clone());
    refuses(
        ready(index.read_page_at(&f.store, &(), &forged, None, 1, &|| false)),
        RefusalCode::EvidenceInvalid,
    );
    let mut other_repository = original.body().clone();
    other_repository.repository_id = RepositoryId::from_bytes([0x41; 16]);
    let other_repository = PublicationBasis::new(
        authority_head_identity(&other_repository).unwrap(),
        other_repository,
    );
    refuses(
        ready(index.read_page_at(&f.store, &(), &other_repository, None, 1, &|| false)),
        RefusalCode::EvidenceInvalid,
    );
    let foreign = Fixture::with_instance(StoreInstanceId::from_raw(0xdead));
    refuses(
        ready(index.read_page_at(&foreign.store, &(), &original, None, 1, &|| false)),
        RefusalCode::EvidenceInvalid,
    );
    assert_eq!(f.store.count(), 0);
    assert_eq!(foreign.store.count(), 0);
    // The original immutable basis remains valid; a newer index is built
    // independently rather than relabelling the old descriptors.
    assert_eq!(
        ready(index.read_page_at(&f.store, &(), &original, None, 1, &|| false))
            .unwrap()
            .events
            .len(),
        1,
    );
    assert_eq!(page(&f, &build(&f), None, 10).unwrap().events.len(), 2);
}

#[test]
fn indexed_cursor_limits_refuse_beside_valid_twins() {
    let mut f = Fixture::new();
    f.append(&[0, 2]);
    let index = build(&f);
    for bad in [
        cursor(1, 0),
        cursor(2, 2),
        cursor(2, u32::MAX),
        cursor(3, 0),
    ] {
        refuses(page(&f, &index, Some(bad), 1), RefusalCode::EvidenceStale);
    }
    refuses(
        page(
            &f,
            &index,
            Some(ForgeEventCursor {
                repository_sequence: 0,
                event_index: 0,
            }),
            1,
        ),
        RefusalCode::EvidenceInvalid,
    );
    for limit in [0, 101] {
        refuses(
            page(&f, &index, None, limit),
            RefusalCode::ResourceBudgetExceeded,
        );
    }
    assert_eq!(
        page(&f, &index, Some(cursor(2, 0)), 1)
            .unwrap()
            .events
            .len(),
        1,
    );
}

#[test]
fn cancelled_build_and_page_do_not_return_partial_results_and_retries_match() {
    let mut f = Fixture::new();
    f.append(&[1, 1, 1]);
    f.store.reset();
    assert!(matches!(
        ready(VerifiedEventIndex::build_at(
            &f.store,
            &(),
            &f.basis,
            INDEX_BYTES,
            &|| f.store.count() >= 1,
        )),
        Err(AdmissionError::AsyncProjectionUnavailable(
            RefusalCode::CancellationInProgress
        )),
    ));
    assert_eq!(f.store.count(), 1);
    let index = build(&f);
    f.store.reset();
    refuses(
        ready(index.read_page_at(&f.store, &(), &f.basis, None, 10, &|| f.store.count() >= 2)),
        RefusalCode::CancellationInProgress,
    );
    assert_eq!(f.store.count(), 2);
    assert_eq!(
        page(&f, &index, None, 10).unwrap(),
        f.page(None, 10).unwrap()
    );
}

#[test]
fn retained_byte_limit_is_exact_and_rejection_does_not_invalidate_existing_index() {
    let mut f = Fixture::new();
    f.append(&[1, 1, 1]);
    let index = build(&f);
    let bytes = index.retained_bytes();
    for bound in [0, bytes - 1] {
        assert!(matches!(
            ready(VerifiedEventIndex::build_at(
                &f.store,
                &(),
                &f.basis,
                bound,
                &|| false,
            )),
            Err(AdmissionError::AsyncProjectionUnavailable(
                RefusalCode::ResourceBudgetExceeded
            )),
        ));
    }
    let exact = ready(VerifiedEventIndex::build_at(
        &f.store,
        &(),
        &f.basis,
        bytes,
        &|| false,
    ))
    .unwrap();
    assert_eq!(exact.retained_bytes(), bytes);
    assert_eq!(
        page(&f, &exact, None, 10).unwrap(),
        page(&f, &index, None, 10).unwrap(),
    );
}

#[test]
fn index_construction_never_certifies_missing_or_corrupt_history() {
    let mut f = Fixture::new();
    f.append(&[1]);
    f.append(&[1]);
    f.append(&[1]);
    for index in [0, 1, 2] {
        for corrupt in [false, true] {
            f.store.fault(Some(batch_key(&f.heads[index])), corrupt);
            assert!(
                ready(VerifiedEventIndex::build_at(
                    &f.store,
                    &(),
                    &f.basis,
                    INDEX_BYTES,
                    &|| false,
                ))
                .is_err()
            );
            f.store.fault(None, false);
            assert_eq!(page(&f, &build(&f), None, 10).unwrap().events.len(), 3);
        }
    }
}
