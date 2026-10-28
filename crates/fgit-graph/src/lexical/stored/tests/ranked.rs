use super::*;
fn query() -> LexicalQuery {
    LexicalQuery::new(
        LexicalChannel::Content,
        &[
            b"ALPHA".to_vec(),
            b"beta".to_vec(),
            b"missing".to_vec(),
            b"alpha".to_vec(),
        ],
        &[],
    )
    .unwrap()
}
#[test]
fn any_term_ranking_uses_global_coverage_then_rarity_before_truncation() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let store = Store::new(920);
        let idx = index(&store, format);
        let p = prepared(
            format,
            1,
            &[b"alpha alpha", b"alpha", b"beta", b"alpha beta"],
        );
        idx.publish(&p, None, &mut || true).unwrap();
        let selected = idx
            .select(None, None, Default::default(), &mut || true)
            .unwrap();
        let ranked = idx
            .search_ranked(
                &selected,
                &query(),
                Default::default(),
                Default::default(),
                &mut || true,
            )
            .unwrap();
        assert_eq!(ranked.scoped_documents, 4);
        assert_eq!(ranked.matched_documents, 4);
        assert_eq!(ranked.term_document_frequencies, [3, 2, 0]);
        assert_eq!(
            ranked
                .index
                .results
                .hits
                .iter()
                .map(|hit| hit.document_id)
                .collect::<Vec<_>>(),
            [4, 3, 1, 2]
        );
        assert_eq!(
            ranked
                .scores
                .iter()
                .map(|score| (score.matched_terms, score.rarity_q16))
                .collect::<Vec<_>>(),
            [(2, 191146), (1, 109226), (1, 81920), (1, 81920)]
        );
        assert_eq!(
            ranked.index.results.hits[0]
                .spans
                .iter()
                .map(|span| span.query_index)
                .collect::<Vec<_>>(),
            [0, 1]
        );
        assert!(ranked.index.results.complete);
        assert_eq!(ranked.index.results.next_after, None);
        assert!(
            idx.search(
                &selected,
                &query(),
                None,
                Default::default(),
                Default::default(),
                &mut || true
            )
            .unwrap()
            .results
            .hits
            .is_empty()
        );
        for maximum in 1..=4 {
            let short = idx
                .search_ranked(
                    &selected,
                    &query(),
                    Default::default(),
                    LexicalQueryLimits {
                        max_results: maximum,
                        ..Default::default()
                    },
                    &mut || true,
                )
                .unwrap();
            assert_eq!(
                short.index.results.hits,
                ranked.index.results.hits[..maximum]
            );
            assert_eq!(short.scores, ranked.scores[..maximum]);
            assert_eq!(short.index.results.complete, maximum == 4);
            assert_eq!(short.index.results.next_after, None);
            assert_eq!(short.index.segments_read, 4);
            assert_eq!(
                short.term_document_frequencies,
                ranked.term_document_frequencies
            );
        }
    }
}
#[test]
fn scope_changes_the_actual_corpus_and_path_queries_keep_original_spans() {
    let store = Store::new(921);
    let idx = index(&store, GitHashAlgorithm::Sha1);
    idx.publish(
        &prepared(GitHashAlgorithm::Sha1, 1, &[b"alpha", b"beta", b"beta"]),
        None,
        &mut || true,
    )
    .unwrap();
    let selected = idx
        .select(None, None, Default::default(), &mut || true)
        .unwrap();
    let scoped = LexicalQuery::new(
        LexicalChannel::Content,
        &[b"alpha".to_vec(), b"beta".to_vec()],
        &[b"src/001.rs".to_vec()],
    )
    .unwrap();
    let report = idx
        .search_ranked(
            &selected,
            &scoped,
            Default::default(),
            Default::default(),
            &mut || true,
        )
        .unwrap();
    assert_eq!(report.scoped_documents, 1);
    assert_eq!(report.term_document_frequencies, [0, 1]);
    assert_eq!(report.index.results.hits[0].document_id, 2);
    assert_eq!(report.scores[0].rarity_q16, 65536);
    let paths = LexicalQuery::new(
        LexicalChannel::Path,
        &[b"rs".to_vec(), b"002".to_vec()],
        &[],
    )
    .unwrap();
    let report = idx
        .search_ranked(
            &selected,
            &paths,
            Default::default(),
            Default::default(),
            &mut || true,
        )
        .unwrap();
    assert_eq!(report.index.results.hits[0].path, b"src/002.rs");
    assert_eq!(report.scores[0].matched_terms, 2);
    assert_eq!(report.index.results.hits[0].spans[0].byte_offset, 4);
    assert_eq!(report.index.results.hits[0].spans[1].byte_offset, 8);
    let outside = LexicalQuery::new(
        LexicalChannel::Content,
        &[b"beta".to_vec()],
        &[b"src/001".to_vec()],
    )
    .unwrap();
    let report = idx
        .search_ranked(
            &selected,
            &outside,
            Default::default(),
            Default::default(),
            &mut || true,
        )
        .unwrap();
    assert_eq!(report.scoped_documents, 0);
    assert!(report.index.results.hits.is_empty());
}
#[test]
fn late_corruption_missing_payload_and_budget_failure_never_return_top_one() {
    let store = Store::new(922);
    let idx = index(&store, GitHashAlgorithm::Sha1);
    let p = prepared(
        GitHashAlgorithm::Sha1,
        1,
        &[b"alpha beta", b"alpha", b"unmatched"],
    );
    idx.publish(&p, None, &mut || true).unwrap();
    let selected = idx
        .select(None, None, Default::default(), &mut || true)
        .unwrap();
    let limits = LexicalQueryLimits {
        max_results: 1,
        ..Default::default()
    };
    let report = idx
        .search_ranked(&selected, &query(), Default::default(), limits, &mut || {
            true
        })
        .unwrap();
    assert_eq!(report.index.results.hits[0].document_id, 1);
    let payload = p.segments.last().unwrap();
    let key = payload_key(p.source().namespace, payload.kind, payload.root).unwrap();
    *store.missing.lock().unwrap() = Some(key.clone());
    assert!(matches!(
        idx.search_ranked(&selected, &query(), Default::default(), limits, &mut || {
            true
        }),
        Err(IndexError::MissingPayload(_))
    ));
    *store.missing.lock().unwrap() = None;
    let mut corrupted = payload.bytes.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    *store.changed.lock().unwrap() = Some((key, corrupted));
    assert!(
        idx.search_ranked(&selected, &query(), Default::default(), limits, &mut || {
            true
        })
        .is_err()
    );
    *store.changed.lock().unwrap() = None;
    let exact = LexicalQueryLimits {
        max_work: report.index.results.work_units,
        ..limits
    };
    assert!(
        idx.search_ranked(&selected, &query(), Default::default(), exact, &mut || true)
            .is_ok()
    );
    assert!(matches!(
        idx.search_ranked(
            &selected,
            &query(),
            Default::default(),
            LexicalQueryLimits {
                max_work: exact.max_work - 1,
                ..exact
            },
            &mut || true
        ),
        Err(IndexError::Lexical(LexicalError::Limit("query work")))
    ));
    let exact_bytes = LexicalReadLimits {
        max_payload_bytes: report.index.payload_bytes_read,
        ..Default::default()
    };
    assert!(
        idx.search_ranked(&selected, &query(), exact_bytes, limits, &mut || true)
            .is_ok()
    );
    assert!(
        idx.search_ranked(
            &selected,
            &query(),
            LexicalReadLimits {
                max_payload_bytes: exact_bytes.max_payload_bytes - 1,
                ..exact_bytes
            },
            limits,
            &mut || true
        )
        .is_err()
    );
}
#[test]
fn cancellation_and_async_reads_share_the_complete_generation_contract() {
    let store = Store::new(923);
    let idx = index(&store, GitHashAlgorithm::Sha256);
    let first = idx
        .publish(
            &prepared(GitHashAlgorithm::Sha256, 1, &[b"alpha", b"alpha beta"]),
            None,
            &mut || true,
        )
        .unwrap();
    let selected = idx
        .select(None, None, Default::default(), &mut || true)
        .unwrap();
    let mut calls = 0;
    let report = idx
        .search_ranked(
            &selected,
            &query(),
            Default::default(),
            Default::default(),
            &mut || {
                calls += 1;
                true
            },
        )
        .unwrap();
    for stop_at in [0, calls / 2, calls - 1] {
        let mut observed = 0;
        assert!(matches!(
            idx.search_ranked(
                &selected,
                &query(),
                Default::default(),
                Default::default(),
                &mut || {
                    let keep = observed < stop_at;
                    observed += 1;
                    keep
                }
            ),
            Err(IndexError::Lexical(LexicalError::Cancelled))
        ));
    }
    idx.publish(
        &prepared(GitHashAlgorithm::Sha256, 2, &[b"beta"]),
        Some(first.generation_id),
        &mut || true,
    )
    .unwrap();
    store.suspend.store(true, Ordering::SeqCst);
    let asynchronous = drive(idx.search_ranked_async(
        &71,
        &selected,
        &query(),
        Default::default(),
        Default::default(),
        &mut || true,
    ))
    .unwrap();
    assert_eq!(asynchronous.index.generation, first);
    assert_eq!(asynchronous.index.results, report.index.results);
    assert_eq!(asynchronous.scores, report.scores);
    assert_eq!(
        asynchronous.term_document_frequencies,
        report.term_document_frequencies
    );
    assert!(store.contexts.lock().unwrap().iter().all(|cx| *cx == 71));
}
#[test]
fn segment_compaction_cannot_change_ranking_or_frequencies() {
    let format = GitHashAlgorithm::Sha1;
    let p = prepared(format, 1, &[b"alpha", b"beta", b"alpha beta", b"unmatched"]);
    let segments = p
        .segments
        .iter()
        .map(|payload| {
            LexicalSegment::decode(
                &payload.bytes,
                payload.root,
                p.source().namespace,
                &mut || true,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let compact = LexicalSegment::concatenate(&segments, &mut || true).unwrap();
    let compact =
        PreparedLexicalIndex::new(p.source().clone(), vec![compact], 2, &mut || true).unwrap();
    let stores = [Store::new(924), Store::new(925)];
    let mut results = Vec::new();
    for (store, input) in stores.iter().zip([&p, &compact]) {
        let idx = index(store, format);
        idx.publish(input, None, &mut || true).unwrap();
        let selected = idx
            .select(None, None, Default::default(), &mut || true)
            .unwrap();
        results.push(
            idx.search_ranked(
                &selected,
                &query(),
                Default::default(),
                Default::default(),
                &mut || true,
            )
            .unwrap(),
        );
    }
    assert_eq!(results[0].index.results.hits, results[1].index.results.hits);
    assert_eq!(results[0].scores, results[1].scores);
    assert_eq!(
        results[0].term_document_frequencies,
        results[1].term_document_frequencies
    );
}
#[test]
fn long_common_path_ties_spend_the_comparison_byte_budget() {
    let format = GitHashAlgorithm::Sha1;
    let store = Store::new(926);
    let idx = index(&store, format);
    let paths: Vec<_> = (0..4)
        .map(|i| format!("{}/{i}.rs", "p".repeat(1000)).into_bytes())
        .collect();
    let content = b"alpha";
    let segment = LexicalSegment::build(
        source(format, 1).namespace,
        1,
        paths.iter().map(|path| SourceDocument {
            path,
            content,
            blob: git_object_id(format, GitObjectKind::Blob, content),
        }),
        &mut || true,
    )
    .unwrap();
    let prepared =
        PreparedLexicalIndex::new(source(format, 1), vec![segment], 0, &mut || true).unwrap();
    idx.publish(&prepared, None, &mut || true).unwrap();
    let selected = idx
        .select(None, None, Default::default(), &mut || true)
        .unwrap();
    let limits = LexicalQueryLimits {
        max_results: 1,
        ..Default::default()
    };
    let full = idx
        .search_ranked(
            &selected,
            &q(b"alpha"),
            Default::default(),
            limits,
            &mut || true,
        )
        .unwrap();
    assert_eq!(full.index.results.hits[0].path, paths[0]);
    // This allowance covers copies and scalar postings but not repeated path comparisons.
    let copies_only = (paths.iter().map(Vec::len).sum::<usize>() * 3) as u64;
    assert!(full.index.results.work_units > copies_only);
    assert!(matches!(
        idx.search_ranked(
            &selected,
            &q(b"alpha"),
            Default::default(),
            LexicalQueryLimits {
                max_work: copies_only,
                ..limits
            },
            &mut || true
        ),
        Err(IndexError::Lexical(LexicalError::Limit("query work")))
    ));
}
