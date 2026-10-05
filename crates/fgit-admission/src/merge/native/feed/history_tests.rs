//! Count actual authority reads and compare cursor pages with a complete replay.
//! Reference-store tests only; not a native-runtime or filesystem benchmark.
mod support;
use super::*;
use support::{Fixture, batch_key, cursor, ready};

#[test]
fn recent_cursor_reads_only_its_verified_suffix_under_a_tight_budget() {
    let mut f = Fixture::new();
    for _ in 0..8 { f.append(&[1]); }
    let limits = history::Limits { batches: 1, records: 1 };
    let records = f.records(Some(cursor(8, 0)), limits).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].sequence, 8);
    assert_eq!(f.store.count(), 2, "one predecessor and one decision batch");
    assert!(f.records(None, limits).is_err(), "a full replay cannot pretend to fit");
    f.store.reset();
    assert!(f.page(Some(cursor(8, 0)), 1).unwrap().events.is_empty());
    assert_eq!(f.store.count(), 3, "EOF still verifies the cursor's event bytes");
}

#[test]
fn cursor_in_a_microbatch_keeps_later_records_and_charges_every_examined_record() {
    let mut f = Fixture::new();
    f.append(&[1, 2, 1]);
    let limits = history::Limits { batches: 1, records: 3 };
    let records = f.records(Some(cursor(2, 0)), limits).unwrap();
    assert_eq!(records.iter().map(|r| r.sequence).collect::<Vec<_>>(), vec![2, 3]);
    assert!(f.records(Some(cursor(3, 0)), history::Limits { records: 2, ..limits }).is_err());
    assert_eq!(f.records(Some(cursor(3, 0)), limits).unwrap().len(), 1);
}

#[test]
fn refusal_only_heads_are_verified_but_never_invent_repository_positions() {
    let mut f = Fixture::new();
    f.append(&[1]); f.append(&[]); f.append(&[]);
    let limits = history::Limits { batches: 3, records: 1 };
    assert!(f.records(Some(cursor(1, 0)), history::Limits { batches: 2, ..limits }).is_err());
    f.store.reset();
    assert_eq!(f.records(Some(cursor(1, 0)), limits).unwrap().len(), 1);
    assert_eq!(f.store.count(), 6);
    f.store.reset();
    assert!(f.page(Some(cursor(2, 0)), 1).is_err());
    assert_eq!(f.store.count(), 0, "future committed position refuses before I/O");
}

#[test]
fn every_real_cursor_matches_the_complete_replay_including_page_boundaries() {
    let mut f = Fixture::new();
    f.append(&[2, 0]); f.append(&[]); f.append(&[3]); f.append(&[0, 1, 2]);
    let full = f.page(None, 100).unwrap();
    assert!(full.next_after.is_none());
    assert_eq!(full.events.len(), 8);
    for (position, event) in full.events.iter().enumerate() {
        for limit in 1..=4 {
            let page = f.page(Some(event.cursor), limit).unwrap();
            let remaining = &full.events[position + 1..];
            let expected = remaining.iter().take(usize::from(limit)).cloned().collect::<Vec<_>>();
            assert_eq!(page.events, expected);
            assert_eq!(page.source_head, full.source_head);
            let next = if remaining.len() > usize::from(limit) {
                expected.last().map(|row| row.cursor)
            } else { None };
            assert_eq!(page.next_after, next);
        }
    }
}

#[test]
fn an_existing_rcr_does_not_validate_an_absent_event_or_out_of_range_index() {
    let mut f = Fixture::new();
    f.append(&[0, 2]);
    for bad in [cursor(1, 0), cursor(2, 2), cursor(2, u32::MAX), cursor(3, 0)] {
        assert!(f.page(Some(bad), 1).is_err());
    }
    assert_eq!(f.page(Some(cursor(2, 0)), 1).unwrap().events.len(), 1);
    assert!(f.page(Some(cursor(2, 1)), 1).unwrap().events.is_empty());
}

#[test]
fn unrelated_old_batch_loss_does_not_break_a_verified_recent_suffix() {
    let mut f = Fixture::new();
    for _ in 0..5 { f.append(&[1]); }
    for corrupt in [false, true] {
        f.store.fault(Some(batch_key(&f.heads[0])), corrupt);
        assert_eq!(f.page(Some(cursor(4, 0)), 5).unwrap().events.len(), 1);
        assert!(f.page(None, 5).is_err(), "initial read must verify its complete prefix");
        f.store.fault(None, false);
        assert_eq!(f.page(None, 5).unwrap().events.len(), 5);
    }
}

#[test]
fn missing_or_corrupt_boundary_and_suffix_batches_never_yield_partial_success() {
    let mut f = Fixture::new();
    for _ in 0..4 { f.append(&[1]); }
    for index in [2, 3] {
        for corrupt in [false, true] {
            f.store.fault(Some(batch_key(&f.heads[index])), corrupt);
            assert!(f.page(Some(cursor(3, 0)), 5).is_err());
            f.store.fault(None, false);
            assert_eq!(f.page(Some(cursor(3, 0)), 5).unwrap().events.len(), 1);
        }
    }
}

#[test]
fn cursor_payload_commitment_remains_mandatory_even_at_eof() {
    let mut f = Fixture::new();
    f.append(&[2]);
    let records = f.records(None, history::Limits::DEFAULT).unwrap();
    let key = storage::body_key(storage::EVENT_NAMESPACE, f.basis.body().repository_id, records[0].event_root).unwrap();
    for corrupt in [false, true] {
        f.store.fault(Some(key.clone()), corrupt);
        assert!(f.page(Some(cursor(1, 1)), 5).is_err());
        f.store.fault(None, false);
        assert!(f.page(Some(cursor(1, 1)), 5).unwrap().events.is_empty());
    }
}

#[test]
fn cancellation_after_a_history_read_is_not_an_empty_page_and_retry_is_safe() {
    let mut f = Fixture::new();
    f.append(&[2]);
    assert!(ready(read_page_at(&f.store, &(), &f.basis, Some(cursor(1, 0)), 1,
        &|| f.store.count() >= 1)).is_err());
    assert_eq!(f.store.count(), 1);
    assert_eq!(f.page(Some(cursor(1, 0)), 1).unwrap().events.len(), 1);
}

#[test]
fn zero_and_oversized_history_budgets_refuse_before_reading() {
    let mut f = Fixture::new(); f.append(&[1]);
    for limits in [
        history::Limits { batches: 0, records: 1 },
        history::Limits { batches: 1, records: 0 },
        history::Limits { batches: 4097, records: 1 },
        history::Limits { batches: 1, records: 65_537 },
    ] { assert!(f.records(None, limits).is_err()); }
    assert_eq!(f.store.count(), 0);
    assert_eq!(f.records(None, history::Limits { batches: 1, records: 1 }).unwrap().len(), 1);
}

#[test]
fn an_asserted_head_id_cannot_label_another_head_body() {
    let mut f = Fixture::new(); f.append(&[1]);
    let mut body = f.basis.body().clone();
    body.latest_repository_sequence = None;
    let forged = PublicationBasis::new(f.basis.id(), body);
    assert!(ready(read_page_at(&f.store, &(), &forged, None, 1, &|| false)).is_err());
    assert_eq!(f.store.count(), 0);
    assert_eq!(f.page(None, 1).unwrap().events.len(), 1);
}

#[test]
fn genesis_is_empty_but_no_cursor_can_name_an_event_there() {
    let f = Fixture::new();
    assert!(f.page(None, 1).unwrap().events.is_empty());
    assert!(f.page(Some(cursor(1, 0)), 1).is_err());
    assert!(f.page(Some(ForgeEventCursor { repository_sequence: 0, event_index: 0 }), 1).is_err());
    assert_eq!(f.store.count(), 0);
}
