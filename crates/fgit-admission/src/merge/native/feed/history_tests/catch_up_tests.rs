//! Catch-up work is bounded by the missed suffix; only exact verified ancestry
//! permits reusing retained descriptors. These are reference-store I/O tests.
use super::*;
use fgit_authority::{StoreInstanceId, authority_head_identity, body_key_for_id};
use fgit_chronicle::PublicationBasis;
use fgit_types::{HeadGeneration, RepositoryId};
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

fn catch_up(f: &Fixture, prefix: &VerifiedEventIndex) -> VerifiedEventIndex {
    ready(prefix.catch_up_at(&f.store, &(), &f.basis, INDEX_BYTES, &|| false))
        .unwrap()
        .expect("the selected head descends from the verified prefix within the catch-up bound")
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
fn mixed_multi_edge_catch_up_preserves_microbatch_order_and_every_page() {
    let mut f = Fixture::new();
    f.append(&[2, 0]);
    f.checkpoint();
    let prefix = build(&f);
    f.append(&[3, 0, 1]);
    f.append(&[]);
    f.checkpoint();
    f.append(&[0, 0]);
    f.append_reference_empty(2);
    f.append(&[1, 2, 1]);

    f.store.reset();
    let index = catch_up(&f, &prefix);
    assert_eq!(f.store.count(), 14, "six edges and both empty schemas");
    assert_eq!(index.source_head(), f.basis.id());
    assert_eq!(index.source_generation(), f.basis.body().generation);
    let full = f.page(None, 100).unwrap();
    assert_eq!(full.events.len(), 10);
    for after in std::iter::once(None).chain(full.events.iter().map(|row| Some(row.cursor))) {
        for limit in 1..=5 {
            assert_eq!(
                page(&f, &index, after, limit),
                f.page(after, limit).unwrap(),
                "after={after:?}, limit={limit}",
            );
        }
    }
}

#[test]
fn catch_up_reads_the_same_suffix_independently_of_verified_prefix_length() {
    for length in [4, 64] {
        let mut f = Fixture::new();
        for _ in 0..length {
            f.append(&[1]);
        }
        let prefix = build(&f);
        f.append(&[1, 2]);
        f.checkpoint();
        f.append(&[]);
        f.append(&[2]);
        f.append(&[]);
        f.store.reset();
        let index = catch_up(&f, &prefix);
        assert_eq!(f.store.count(), 10, "prefix length {length}");
        assert_eq!(page(&f, &index, None, 100), f.page(None, 100).unwrap());

        // An unrelated, already verified decision is not fetched again.
        // The exact source head and every new edge remain mandatory.
        f.store.fault(Some(batch_key(&f.heads[0])), true);
        f.store.reset();
        let reused = catch_up(&f, &prefix);
        assert_eq!(f.store.count(), 10, "prefix length {length}");
        assert_eq!(page(&f, &reused, None, 1).events.len(), 1);
        f.store.fault(None, false);
    }
}

#[test]
fn sixty_four_refusal_or_checkpoint_edges_fit_but_sixty_five_decline_without_io() {
    for checkpoint in [false, true] {
        let mut f = Fixture::new();
        f.append(&[2]);
        let original = f.basis.clone();
        let prefix = build(&f);
        for _ in 0..64 {
            if checkpoint {
                f.checkpoint();
            } else {
                f.append(&[]);
            }
        }
        assert!(prefix.can_catch_up_at(&f.basis));
        f.store.reset();
        let index = catch_up(&f, &prefix);
        assert_eq!(f.store.count(), 128, "checkpoint={checkpoint}");
        assert_eq!(index.retained_bytes(), prefix.retained_bytes());
        assert_eq!(page(&f, &index, None, 100), f.page(None, 100).unwrap());

        if checkpoint {
            f.checkpoint();
        } else {
            f.append(&[]);
        }
        assert!(!prefix.can_catch_up_at(&f.basis));
        f.store.reset();
        assert!(
            ready(prefix.catch_up_at(&f.store, &(), &f.basis, INDEX_BYTES, &|| false))
                .unwrap()
                .is_none()
        );
        assert_eq!(f.store.count(), 0, "checkpoint={checkpoint}");
        assert_eq!(prefix.source_head(), original.id());
        assert_eq!(
            ready(prefix.read_page_at(&f.store, &(), &original, None, 100, &|| false))
                .unwrap()
                .events
                .len(),
            2,
        );
    }
}

#[test]
fn same_and_older_heads_are_zero_io_misses_without_relabelling_the_prefix() {
    let mut f = Fixture::new();
    let genesis = f.basis.clone();
    f.append(&[1]);
    let older = f.basis.clone();
    f.append(&[1]);
    let original = f.basis.clone();
    let prefix = build(&f);
    for basis in [&genesis, &older, &original] {
        assert!(!prefix.can_catch_up_at(basis));
        f.store.reset();
        assert!(
            ready(prefix.catch_up_at(&f.store, &(), basis, INDEX_BYTES, &|| false))
                .unwrap()
                .is_none()
        );
        assert_eq!(f.store.count(), 0);
        assert_eq!(prefix.source_head(), original.id());
        assert_eq!(prefix.source_generation(), original.body().generation);
    }
}

#[test]
fn equal_generation_and_sequence_on_a_valid_fork_do_not_prove_ancestry() {
    let mut left = Fixture::new();
    left.append(&[1, 2]);
    let prefix = build(&left);
    let mut right = Fixture::new();
    right.append(&[2, 1]);
    assert_eq!(left.basis.body().generation, right.basis.body().generation);
    assert_eq!(
        left.basis.body().latest_repository_sequence,
        right.basis.body().latest_repository_sequence,
    );
    assert_ne!(left.basis.id(), right.basis.id());
    right.append(&[1]);
    right.checkpoint();
    right.append(&[]);
    assert!(prefix.can_catch_up_at(&right.basis));
    right.store.reset();
    assert!(
        ready(prefix.catch_up_at(&right.store, &(), &right.basis, INDEX_BYTES, &|| false))
            .unwrap()
            .is_none()
    );
    assert_eq!(right.store.count(), 6, "the valid fork was fully checked");
    assert_eq!(
        page(&left, &prefix, None, 100),
        left.page(None, 100).unwrap()
    );
    assert_eq!(
        page(&right, &build(&right), None, 100),
        right.page(None, 100).unwrap()
    );
}

#[test]
fn missing_or_corrupt_middle_evidence_refuses_without_replacing_the_prefix() {
    let mut f = Fixture::new();
    f.append(&[1]);
    let original = f.basis.clone();
    let prefix = build(&f);
    f.append(&[1]);
    let middle_head = body_key_for_id(f.basis.id().as_internal_object_id()).unwrap();
    let middle_decision = batch_key(f.heads.last().unwrap());
    let capsule = f.checkpoint();
    f.append(&[2]);
    f.append(&[]);
    let source_head = body_key_for_id(original.id().as_internal_object_id()).unwrap();

    for key in [middle_head, middle_decision, capsule, source_head] {
        for corrupt in [false, true] {
            f.store.fault(Some(key.clone()), corrupt);
            assert!(
                ready(prefix.catch_up_at(&f.store, &(), &f.basis, INDEX_BYTES, &|| false)).is_err(),
                "key={key:?}, corrupt={corrupt}",
            );
            assert_eq!(
                ready(prefix.read_page_at(&f.store, &(), &original, None, 1, &|| false))
                    .unwrap()
                    .events
                    .len(),
                1,
            );
            f.store.fault(None, false);
            assert_eq!(
                page(&f, &catch_up(&f, &prefix), None, 100),
                f.page(None, 100).unwrap(),
            );
        }
    }
}

#[test]
fn cancellation_at_each_suffix_read_and_during_copy_keeps_original_index_usable() {
    let mut f = Fixture::new();
    f.append(&[1; 64]);
    let original = f.basis.clone();
    let prefix = build(&f);
    f.append(&[1]);
    f.checkpoint();
    f.append(&[1, 1]);
    for read_limit in 0..=6 {
        f.store.reset();
        refuses(
            ready(
                prefix.catch_up_at(&f.store, &(), &f.basis, INDEX_BYTES, &|| {
                    f.store.count() >= read_limit
                }),
            ),
            RefusalCode::CancellationInProgress,
        );
        assert_eq!(f.store.count(), read_limit);
    }

    f.store.reset();
    let polls_after_io = AtomicUsize::new(0);
    let complete = ready(
        prefix.catch_up_at(&f.store, &(), &f.basis, INDEX_BYTES, &|| {
            if f.store.count() == 6 {
                polls_after_io.fetch_add(1, Ordering::Relaxed);
            }
            false
        }),
    )
    .unwrap()
    .unwrap();
    let polls = polls_after_io.load(Ordering::Relaxed);
    assert!(polls > 64, "every retained row must poll cancellation");
    f.store.reset();
    polls_after_io.store(0, Ordering::Relaxed);
    refuses(
        ready(
            prefix.catch_up_at(&f.store, &(), &f.basis, INDEX_BYTES, &|| {
                f.store.count() == 6 && polls_after_io.fetch_add(1, Ordering::Relaxed) >= polls - 5
            }),
        ),
        RefusalCode::CancellationInProgress,
    );
    assert_eq!(f.store.count(), 6);
    assert_eq!(prefix.source_head(), original.id());
    assert_eq!(
        ready(prefix.read_page_at(&f.store, &(), &original, None, 100, &|| false))
            .unwrap()
            .events
            .len(),
        64,
    );
    assert_eq!(
        page(&f, &catch_up(&f, &prefix), None, 100),
        page(&f, &complete, None, 100),
    );
}

#[test]
fn catch_up_accounts_for_the_complete_retained_allocation_and_exact_cap() {
    let mut f = Fixture::new();
    f.append(&[1, 1, 1]);
    let original = f.basis.clone();
    let prefix = build(&f);
    f.append(&[2]);
    f.append(&[0, 1]);
    let full = build(&f);
    let bytes = full.retained_bytes();
    f.store.reset();
    refuses(
        ready(prefix.catch_up_at(&f.store, &(), &f.basis, 0, &|| false)),
        RefusalCode::ResourceBudgetExceeded,
    );
    assert_eq!(f.store.count(), 0);
    refuses(
        ready(prefix.catch_up_at(&f.store, &(), &f.basis, bytes - 1, &|| false)),
        RefusalCode::ResourceBudgetExceeded,
    );
    let exact = ready(prefix.catch_up_at(&f.store, &(), &f.basis, bytes, &|| false))
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
fn catch_up_checks_body_repository_and_store_binding_before_a_fast_miss() {
    let mut f = Fixture::new();
    f.append(&[1]);
    let original = f.basis.clone();
    let prefix = build(&f);
    f.append(&[1]);
    let mismatched = PublicationBasis::new(original.id(), f.basis.body().clone());
    let mut foreign_body = original.body().clone();
    foreign_body.repository_id = RepositoryId::from_bytes([0x31; 16]);
    let foreign_basis = PublicationBasis::new(
        authority_head_identity(&foreign_body).unwrap(),
        foreign_body,
    );
    let foreign = Fixture::with_instance(StoreInstanceId::from_raw(0x701));
    f.store.reset();
    refuses(
        ready(prefix.catch_up_at(&f.store, &(), &mismatched, INDEX_BYTES, &|| false)),
        RefusalCode::EvidenceInvalid,
    );
    refuses(
        ready(prefix.catch_up_at(&f.store, &(), &foreign_basis, INDEX_BYTES, &|| false)),
        RefusalCode::EvidenceInvalid,
    );
    refuses(
        ready(prefix.catch_up_at(&foreign.store, &(), &original, INDEX_BYTES, &|| false)),
        RefusalCode::EvidenceInvalid,
    );
    assert_eq!(f.store.count(), 0);
    assert_eq!(foreign.store.count(), 0);
    assert_eq!(
        page(&f, &catch_up(&f, &prefix), None, 100),
        f.page(None, 100).unwrap()
    );
}

#[test]
fn a_matching_direct_predecessor_cannot_hide_an_invalid_generation_as_a_cache_miss() {
    let mut f = Fixture::new();
    f.append(&[1]);
    let prefix = build(&f);
    f.append(&[1]);
    for generation in [HeadGeneration::FIRST, prefix.source_generation()] {
        let mut body = f.basis.body().clone();
        body.generation = generation;
        let forged = PublicationBasis::new(authority_head_identity(&body).unwrap(), body);
        f.store.reset();
        refuses(
            ready(prefix.extend_at(&f.store, &(), &forged, INDEX_BYTES, &|| false)),
            RefusalCode::EvidenceInvalid,
        );
        assert_eq!(f.store.count(), 0);
    }
    assert_eq!(
        page(&f, &catch_up(&f, &prefix), None, 100),
        f.page(None, 100).unwrap()
    );
}
