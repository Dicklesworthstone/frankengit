//! The actual native reader must reach the authenticated omission path.
use super::*;

#[test]
fn full_build_omits_over_limit_blobs_and_preserves_coverage_after_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, commit) = symbols(&root, format);
        let canonical = generation(&node);
        let limits = SearchLimits {
            max_file_bytes: A.len() - 1,
            max_total_bytes: A.len() + B.len() + RAW.len(),
            ..Default::default()
        };
        let (_, first) = node
            .runtime()
            .block_on(node.build_source_symbol_index_local_in(
                &node.outbox_delivery_context(),
                &reference(),
                None,
                Some(commit),
                None,
                limits,
            ))
            .unwrap();
        let partial = search(
            &node,
            &ordinary(),
            Default::default(),
            data::MAX_INDEX_BYTES,
        )
        .unwrap();
        assert!(partial.complete);
        assert!(!partial.coverage_complete);
        assert_eq!(partial.indexed_files, 2);
        assert_eq!(partial.omissions.len(), 1);
        let omitted = &partial.omissions[0];
        assert_eq!(omitted.path, b"src/a.rs");
        assert_eq!(omitted.source_bytes, A.len());
        assert_eq!(omitted.limit, Some(limits.max_file_bytes));
        assert_eq!(omitted.reason, data::OmissionReason::FileBytes);
        assert_eq!(
            omitted.blob,
            fgit_crypto::git_object_id(format, fgit_crypto::GitObjectKind::Blob, A)
        );
        assert!(
            partial
                .matches
                .iter()
                .all(|row| row.location.path != b"src/a.rs")
        );
        assert_eq!(generation(&node), canonical);
        node.shutdown().unwrap();

        let node = reopen(&config);
        let retained = search(
            &node,
            &ordinary(),
            Default::default(),
            data::MAX_INDEX_BYTES,
        )
        .unwrap();
        assert_eq!(retained.omissions, partial.omissions);
        assert_eq!(retained.matches, partial.matches);
        // The exact same blob is indexable at its boundary. It must be read
        // again: a previous omission is never reusable declaration evidence.
        let (_, _, stats) = node
            .runtime()
            .block_on(node.refresh_source_symbol_index_local_in(
                &node.outbox_delivery_context(),
                &reference(),
                None,
                Some(commit),
                first.generation_id,
                SearchLimits {
                    max_file_bytes: A.len(),
                    ..limits
                },
            ))
            .unwrap();
        assert_eq!(stats.reused_files, 2);
        assert_eq!(stats.source_blobs_read, 1);
        assert_eq!(stats.source_bytes_read, A.len());
        let full = search(
            &node,
            &ordinary(),
            Default::default(),
            data::MAX_INDEX_BYTES,
        )
        .unwrap();
        assert!(full.coverage_complete);
        assert!(full.omissions.is_empty());
        assert_eq!(full.indexed_files, 3);
        assert_eq!(generation(&node), canonical);
        node.shutdown().unwrap();
    }
}

#[test]
fn omitted_blobs_still_consume_the_shared_budget_and_cannot_publish_on_exhaustion() {
    let root = Scratch::new();
    let (node, commit) = symbols(&root, GitHashAlgorithm::Sha256);
    let limits = SearchLimits {
        max_file_bytes: A.len() - 1,
        max_total_bytes: A.len() + B.len() + RAW.len() - 1,
        ..Default::default()
    };
    let canonical = generation(&node);
    let mut called = false;
    let result = node
        .runtime()
        .block_on(node.build_source_symbol_index_guarded_local_in(
            &node.outbox_delivery_context(),
            &reference(),
            None,
            Some(commit),
            None,
            limits,
            &mut |_| {
                called = true;
                Ok(())
            },
        ));
    assert!(result.is_err());
    assert!(!called);
    assert!(matches!(
        search(
            &node,
            &ordinary(),
            Default::default(),
            data::MAX_INDEX_BYTES
        ),
        Err(AccessError::Uninitialized)
    ));
    assert_eq!(generation(&node), canonical);
    let (_, _) = node
        .runtime()
        .block_on(node.build_source_symbol_index_local_in(
            &node.outbox_delivery_context(),
            &reference(),
            None,
            Some(commit),
            None,
            SearchLimits {
                max_total_bytes: limits.max_total_bytes + 1,
                ..limits
            },
        ))
        .unwrap();
    assert!(
        !search(
            &node,
            &ordinary(),
            Default::default(),
            data::MAX_INDEX_BYTES
        )
        .unwrap()
        .coverage_complete
    );
    node.shutdown().unwrap();
}

#[test]
fn cancelled_symbol_intake_never_reaches_the_publication_barrier() {
    let root = Scratch::new();
    let (node, commit) = symbols(&root, GitHashAlgorithm::Sha1);
    let request = node.outbox_delivery_context();
    request.cancel();
    let mut called = false;
    let result = node
        .runtime()
        .block_on(node.build_source_symbol_index_guarded_local_in(
            &request,
            &reference(),
            None,
            Some(commit),
            None,
            SearchLimits {
                max_file_bytes: A.len() - 1,
                ..Default::default()
            },
            &mut |_| {
                called = true;
                Ok(())
            },
        ));
    assert!(matches!(
        result,
        Err(AccessError::Index(data::Error::Cancelled))
    ));
    assert!(!called);
    assert!(matches!(
        search(
            &node,
            &ordinary(),
            Default::default(),
            data::MAX_INDEX_BYTES
        ),
        Err(AccessError::Uninitialized)
    ));
    node.shutdown().unwrap();
}
