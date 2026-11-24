//! Indexed production pages must preserve the ordinary canonical reader.
use super::*;

const INDEX_BYTES: usize = 1024 * 1024;

#[test]
fn indexed_pr_pages_preserve_rows_filters_and_pagination_in_both_hash_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut batches = history(1, 5, format, 12);
        batches.extend(history(2, 3, format, 24));
        batches.extend(history(10, 2, format, 0));
        for pr in [1, 10] {
            let labels = fgit_forge::event::pull_request_labels::PullRequestLabelsCommand {
                number: number(pr),
                expected_version: ExpectedVersion::NewStream,
                labels: vec!["ready".into()],
            }
            .proposed_event(PrincipalId::from_bytes([9; 16]))
            .unwrap();
            batches.push(ForgeEventBatch::of_one(labels));
        }
        let fixture = Fixture::new(batches);
        let (cold, index) = run(read_page_filtered_indexed_at(
            &fixture.store,
            &(),
            &fixture.basis,
            0,
            100,
            &[],
            &|_, _| true,
            None,
            INDEX_BYTES,
            &|| false,
        ))
        .unwrap();
        assert_eq!(cold, fixture.page(0, 100));
        let index = index.expect("a completed selected replay supplies bounded metadata");
        for after in [0, 1, 2, 10] {
            for limit in [1, 2, 3] {
                for required in [vec![], vec!["ready".to_string()]] {
                    for hidden in [false, true] {
                        let visible = |source: &RefName, _: &RefName| {
                            !hidden || source.as_bytes() != b"refs/heads/topic-1"
                        };
                        let expected = run(read_page_filtered_at(
                            &fixture.store, &(), &fixture.basis, after, limit, &required,
                            &visible, &|| false,
                        ))
                        .unwrap();
                        let (actual, _) = run(read_page_filtered_indexed_at(
                            &fixture.store, &(), &fixture.basis, after, limit, &required,
                            &visible, Some(&index), INDEX_BYTES, &|| false,
                        ))
                        .unwrap();
                        assert_eq!(actual, expected, "after={after}, limit={limit}, hidden={hidden}");
                    }
                }
            }
        }
    }
}

#[test]
fn indexed_pr_reads_preserve_merge_metadata_and_optional_retention_failure() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let metadata = data(1, 2, format, 12);
        let merge = ForgeEvent {
            aggregate: AggregateId::PullRequest(number(1)),
            version: AggregateVersion::try_new(3).unwrap(),
            payload: ForgeEventPayload::MergeCommittedNative(fgit_forge::event::NativeMerge {
                source_ref: metadata.source_ref.clone(),
                source_tip: metadata.source_tip,
                base_tip: oid(format, '3'),
                target_ref: metadata.target_ref.clone(),
                target_tip_before: metadata.target_tip,
                merge_commit: oid(format, '4'),
            }),
        };
        let mut batches = history(1, 2, format, 12);
        batches.push(ForgeEventBatch::of_one(merge));
        let fixture = Fixture::new(batches);
        let expected = fixture.page(0, 1);
        for budget in [0, 1, INDEX_BYTES] {
            let (page, index) = run(read_page_filtered_indexed_at(
                &fixture.store, &(), &fixture.basis, 0, 1, &[], &|_, _| true,
                None, budget, &|| false,
            ))
            .unwrap();
            assert_eq!(page, expected);
            if budget < INDEX_BYTES {
                assert!(index.is_none());
            } else {
                let index = index.unwrap();
                let (warm, replacement) = run(read_page_filtered_indexed_at(
                    &fixture.store, &(), &fixture.basis, 0, 1, &[], &|_, _| true,
                    Some(&index), budget, &|| false,
                ))
                .unwrap();
                assert_eq!(warm, expected);
                assert!(replacement.is_none(), "successful reuse retains the original index");
                assert!(matches!(
                    run(read_page_filtered_indexed_at(
                        &fixture.store, &(), &fixture.basis, 0, 1, &[], &|_, _| true,
                        Some(&index), budget, &|| true,
                    )),
                    Err(AdmissionError::AsyncProjectionUnavailable(RefusalCode::CancellationInProgress))
                ));
            }
        }
    }
}

#[test]
fn indexed_pr_cold_read_still_refuses_conflicting_active_history() {
    let mut fixture = Fixture::new(history(1, 2, GitHashAlgorithm::Sha1, 0));
    let fork = ForgeEventBatch::of_one(event(1, 2, GitHashAlgorithm::Sha1, 10));
    let root = stage(
        &fixture.store, fixture.basis.body().repository_id, storage::EVENT_NAMESPACE, &fork,
    );
    let mut entries = fixture.outbox.entries().to_vec();
    entries.push(fixture.entry(root, AsciiSlug::from_static("conflicting-projection")));
    fixture.select_outbox(entries);
    assert!(matches!(
        run(read_page_filtered_indexed_at(
            &fixture.store, &(), &fixture.basis, 0, 1, &[], &|_, _| true,
            None, INDEX_BYTES, &|| false,
        )),
        Err(AdmissionError::AsyncProjectionUnavailable(RefusalCode::EvidenceInvalid))
    ));
}
