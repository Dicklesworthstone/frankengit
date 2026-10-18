//! Native verified bytes, persisted generations, and source coverage receipts.
use super::*;
use fgit_graph::lexical::LexicalOmissionReason;

fn corpus_bytes() -> usize {
    TEXT.len() + BINARY.len() + b"needle in nested\n".len() + b"#!/bin/sh\nneedle\n".len()
}
fn narrow() -> SearchLimits {
    SearchLimits {
        max_file_bytes: TEXT.len() - 1,
        max_total_bytes: corpus_bytes(),
        ..Default::default()
    }
}
fn assert_partial(report: &IndexedLexicalReport, format: GitHashAlgorithm) {
    assert!(report.results.complete);
    assert!(!report.coverage_complete);
    assert_eq!(report.indexed_documents, 4);
    assert_eq!(report.indexed_source_bytes, corpus_bytes() - TEXT.len());
    assert_eq!(report.non_regular_entries, 2);
    assert_eq!(report.results.hits.len(), 3);
    assert_eq!(report.omissions.len(), 1);
    let row = &report.omissions[0];
    assert_eq!(row.path, b"alpha.txt");
    assert_eq!(
        row.blob,
        fgit_crypto::git_object_id(format, fgit_crypto::GitObjectKind::Blob, TEXT)
    );
    assert_eq!(row.source_bytes, TEXT.len());
    assert_eq!(row.reason, LexicalOmissionReason::FileBytes);
    assert_eq!(row.limit, narrow().max_file_bytes);
    assert_eq!(report.validate_coverage().unwrap(), TEXT.len());
    // Existing byte-oriented binary indexing remains available.
    assert!(
        report
            .results
            .hits
            .iter()
            .any(|hit| hit.path == BINARY_PATH)
    );
    assert!(report.results.hits.iter().all(|hit| hit.path != row.path));
}

#[test]
fn verified_omissions_survive_real_reopen_and_restored_limits_rebuild_the_file() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, commit) = fixture(&root, format);
        let before = generation(&node);
        let (source, first) = node
            .runtime()
            .block_on(node.build_source_index_local_in(
                &node.outbox_delivery_context(),
                &reference(),
                None,
                Some(commit),
                None,
                narrow(),
            ))
            .unwrap();
        let q = query(LexicalChannel::Content, &[b"needle"], &[]);
        let report = search(&node, &q).unwrap();
        assert_eq!(report.source, source);
        assert_partial(&report, format);
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
        let node = reopen(&config);
        let reopened = search(&node, &q).unwrap();
        assert_eq!(reopened.generation, first);
        assert_eq!(reopened.omissions, report.omissions);
        assert_eq!(reopened.results, report.results);
        let (_, second, stats) = node
            .runtime()
            .block_on(node.refresh_source_index_local_in(
                &node.outbox_delivery_context(),
                &reference(),
                None,
                Some(commit),
                first.generation_id,
                SearchLimits {
                    max_file_bytes: TEXT.len(),
                    ..narrow()
                },
                Default::default(),
            ))
            .unwrap();
        assert_eq!(stats.reused_documents, 4);
        assert_eq!(stats.rebuilt_documents, 1);
        assert_eq!(stats.rebuilt_source_bytes, TEXT.len());
        let restored = search(&node, &q).unwrap();
        assert_eq!(restored.generation, second);
        assert!(restored.coverage_complete);
        assert!(restored.omissions.is_empty());
        assert_eq!(restored.indexed_documents, 5);
        assert_eq!(restored.results.hits.len(), 4);
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}

#[test]
fn narrowing_a_live_index_rechecks_oversized_rows_and_cannot_spend_past_the_corpus_limit() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, _) = fixture(&root, format);
        let first = build(&node, None);
        let before = generation(&node);
        let q = query(LexicalChannel::Content, &[b"needle"], &[]);
        let mut published = false;
        let refused = node
            .runtime()
            .block_on(node.refresh_source_index_guarded_local_in(
                &node.outbox_delivery_context(),
                &reference(),
                None,
                None,
                first.generation_id,
                SearchLimits {
                    max_total_bytes: corpus_bytes() - 1,
                    ..narrow()
                },
                Default::default(),
                &mut |_| {
                    published = true;
                    Ok(())
                },
            ));
        assert!(refused.is_err());
        assert!(!published);
        assert_eq!(search(&node, &q).unwrap().generation, first);
        let (_, second, stats) = node
            .runtime()
            .block_on(node.refresh_source_index_local_in(
                &node.outbox_delivery_context(),
                &reference(),
                None,
                None,
                first.generation_id,
                narrow(),
                Default::default(),
            ))
            .unwrap();
        assert_eq!(stats.reused_documents, 4);
        assert_eq!(stats.rebuilt_documents, 0);
        assert_eq!(stats.prior_documents_not_reused, 1);
        assert_eq!(stats.reused_source_bytes, corpus_bytes() - TEXT.len());
        assert_partial(&search(&node, &q).unwrap(), format);
        // Unchanged omitted blobs are not prior posting evidence. A repeated
        // refresh must retain their authenticated source size and diagnostics.
        let (_, third, _) = node
            .runtime()
            .block_on(node.refresh_source_index_local_in(
                &node.outbox_delivery_context(),
                &reference(),
                None,
                None,
                second.generation_id,
                narrow(),
                Default::default(),
            ))
            .unwrap();
        let again = search(&node, &q).unwrap();
        assert_eq!(again.generation, third);
        assert_partial(&again, format);
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}

#[test]
fn a_file_above_eight_mib_is_omitted_at_default_limits_but_host_limits_still_refuse() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let maximum = SearchLimits::default().max_file_bytes;
        let text = vec![b'x'; maximum + 1];
        let (node, _) = fixture_with_text(&root, format, config.clone(), &text);
        let before = generation(&node);
        let first = build(&node, None);
        let q = query(LexicalChannel::Content, &[b"needle"], &[]);
        let partial = search(&node, &q).unwrap();
        assert_eq!(partial.indexed_documents, 4);
        assert_eq!(partial.results.hits.len(), 3);
        assert!(!partial.coverage_complete);
        assert_eq!(partial.omissions.len(), 1);
        assert_eq!(partial.omissions[0].source_bytes, maximum + 1);
        assert_eq!(partial.omissions[0].limit, maximum);
        assert_eq!(partial.validate_coverage().unwrap(), maximum + 1);
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();

        let node = reopen(&config.with_max_object_bytes(maximum as u64));
        let mut called = false;
        let refused = node
            .runtime()
            .block_on(node.build_source_index_guarded_local_in(
                &node.outbox_delivery_context(),
                &reference(),
                None,
                None,
                Some(first.generation_id),
                Default::default(),
                &mut |_| {
                    called = true;
                    Ok(())
                },
            ));
        assert!(refused.is_err());
        assert!(!called);
        assert_eq!(search(&node, &q).unwrap().generation, first);
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}
