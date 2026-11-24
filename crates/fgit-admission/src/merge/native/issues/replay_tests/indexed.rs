//! List and timeline projections share coordinates without sharing output rows.
use super::*;

const INDEX_BYTES: usize = 1024 * 1024;

#[test]
fn indexed_issue_pages_and_timeline_windows_match_canonical_replay() {
    let fixture = Fixture::new(vec![history(1, 12), history(2, 4), history(10, 2)]);
    let (cold, index) = run(read_page_indexed_at(
        &fixture.store, &(), &fixture.basis, 0, 100, None, INDEX_BYTES, &|| false,
    ))
    .unwrap();
    assert_eq!(cold, fixture.page(0, 100));
    let index = index.expect("the complete list replay supplies bounded coordinates");
    for after in [0, 1, 2, 10] {
        for limit in [1, 2, 3] {
            let (actual, _) = run(read_page_indexed_at(
                &fixture.store, &(), &fixture.basis, after, limit,
                Some(&index), INDEX_BYTES, &|| false,
            ))
            .unwrap();
            assert_eq!(actual, fixture.page(after, limit));
        }
    }
    for issue in [1, 2, 10, 99] {
        for after in [0, 1, 11, 12] {
            let expected = run(read_history_at(
                &fixture.store, &(), &fixture.basis, number(issue), after, 2, &|| false,
            ))
            .unwrap();
            let (actual, _) = run(read_history_indexed_at(
                &fixture.store, &(), &fixture.basis, number(issue), after, 2,
                Some(&index), INDEX_BYTES, &|| false,
            ))
            .unwrap();
            assert_eq!(actual, expected, "issue={issue}, after={after}");
        }
    }
}

#[test]
fn indexed_issue_selection_misses_and_retention_limits_keep_canonical_results() {
    let fixture = Fixture::new(vec![history(1, 5), history(2, 3)]);
    let (_, selected) = run(read_history_indexed_at(
        &fixture.store, &(), &fixture.basis, number(1), 0, 1, None, INDEX_BYTES, &|| false,
    ))
    .unwrap();
    let selected = selected.unwrap();
    // The prior proof covers issue1, so the broader page must replay and prove
    // issue2 as well instead of treating missing coordinates as absent data.
    let (page, broader) = run(read_page_indexed_at(
        &fixture.store, &(), &fixture.basis, 0, 100, Some(&selected), INDEX_BYTES, &|| false,
    ))
    .unwrap();
    assert_eq!(page, fixture.page(0, 100));
    assert!(broader.is_some());
    for budget in [0, 1] {
        let (page, index) = run(read_page_indexed_at(
            &fixture.store, &(), &fixture.basis, 0, 100, None, budget, &|| false,
        ))
        .unwrap();
        assert_eq!(page, fixture.page(0, 100));
        assert!(index.is_none());
    }
    assert!(matches!(
        run(read_history_indexed_at(
            &fixture.store, &(), &fixture.basis, number(1), 0, 1,
            Some(&selected), INDEX_BYTES, &|| true,
        )),
        Err(AdmissionError::AsyncProjectionUnavailable(RefusalCode::CancellationInProgress))
    ));
}

#[test]
fn indexed_issue_reads_do_not_use_old_coordinates_to_fill_an_incomplete_new_basis() {
    let mut fixture = Fixture::new(vec![
        ForgeEventBatch::of_one(opened(1)),
        ForgeEventBatch::of_one(event(1, 2, IssueAction::Close)),
    ]);
    let (_, index) = run(read_page_indexed_at(
        &fixture.store, &(), &fixture.basis, 0, 1, None, INDEX_BYTES, &|| false,
    ))
    .unwrap();
    let index = index.unwrap();
    let frontier_root = fixture.forge.entries()[0].event_batch_root();
    let entries = fixture.outbox.entries().iter()
        .filter(|entry| entry.payload_root() == frontier_root).copied().collect();
    fixture.select_outbox(entries);
    assert!(run(read_page_indexed_at(
        &fixture.store, &(), &fixture.basis, 0, 1, Some(&index), INDEX_BYTES, &|| false,
    )).is_err());
    assert!(run(read_page_indexed_at(
        &fixture.store, &(), &fixture.basis, 0, 1, None, INDEX_BYTES, &|| false,
    )).is_err());
}
