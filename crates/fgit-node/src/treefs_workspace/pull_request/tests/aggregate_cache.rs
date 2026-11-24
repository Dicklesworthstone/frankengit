//! Real native PR pages retain only verified history coordinates.
use super::*;
use crate::aggregate_history::HistoryKind;
use std::sync::Arc;

fn reopened(config: NodeConfig) -> OneNode {
    let mut node = OneNode::open_existing(config).unwrap();
    let generation = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap()
        .receipt()
        .generation();
    node.bring_into_service(generation).unwrap();
    node
}

#[test]
fn missing_pr_selections_rebuild_once_and_subsets_reuse_the_complete_selection() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        let fixture = fixture(&node, &scratch, format);
        for number in [1, 2, 3] {
            accepted(apply(
                &node,
                &command(&fixture, number),
                &format!("cache-open-{number}"),
            ));
        }
        let cache = node.aggregate_history_index_cache();
        assert_eq!(cache.test_builds(), 0);
        let first = page(&node, 0, 1, None).unwrap();
        assert_eq!(first.pull_requests.len(), 1);
        assert_eq!(first.next_after, Some(1));
        assert_eq!(cache.test_builds(), 1);
        assert_eq!(page(&node, 0, 1, None).unwrap(), first);
        assert_eq!(cache.test_builds(), 1);

        let all = page(&node, 0, 100, Some(first.source_head)).unwrap();
        assert_eq!(
            all.pull_requests
                .iter()
                .map(|row| row.number.get())
                .collect::<Vec<_>>(),
            [1, 2, 3]
        );
        assert_eq!(
            cache.test_builds(),
            2,
            "the first index did not cover PRs 2 and 3"
        );
        let retained = cache
            .lookup(&node, HistoryKind::PullRequests, all.source_head)
            .unwrap();
        let middle = page(&node, 1, 1, Some(all.source_head)).unwrap();
        assert_eq!(middle.pull_requests, all.pull_requests[1..2]);
        assert_eq!(middle.next_after, Some(2));
        assert_eq!(page(&node, 0, 100, None).unwrap(), all);
        assert_eq!(cache.test_builds(), 2);
        assert!(Arc::ptr_eq(
            &retained,
            &cache
                .lookup(&node, HistoryKind::PullRequests, all.source_head)
                .unwrap()
        ));

        let scalar_config = node
            .service_config
            .clone()
            .with_aggregate_history_index_cache_bytes(0);
        node.shutdown().unwrap();
        let scalar = reopened(scalar_config);
        assert_eq!(page(&scalar, 0, 100, None).unwrap(), all);
        assert_eq!(page(&scalar, 1, 1, Some(all.source_head)).unwrap(), middle);
        assert_eq!(scalar.aggregate_history_index_cache().test_builds(), 0);
        scalar.shutdown().unwrap();
    }
}

#[test]
fn warm_pr_coordinates_do_not_override_fresh_visibility_or_cancelled_requests() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        let fixture = fixture(&node, &scratch, format);
        accepted(apply(&node, &command(&fixture, 1), "cache-visible-open"));
        let visible = page(&node, 0, 100, None).unwrap();
        assert_eq!(visible.pull_requests.len(), 1);
        let cache = node.aggregate_history_index_cache();
        let retained = cache
            .lookup(&node, HistoryKind::PullRequests, visible.source_head)
            .unwrap();
        for hidden in [source_ref(), target()] {
            let mut visibility = RefVisibility::new();
            visibility
                .push_rule(hidden.as_bytes(), &Default::default())
                .unwrap();
            let request = node.request_context();
            let hidden = node
                .runtime()
                .block_on(node.read_pull_requests_in(
                    &request,
                    &visibility,
                    0,
                    100,
                    Some(visible.source_head),
                ))
                .unwrap();
            assert!(hidden.pull_requests.is_empty());
            assert_eq!(hidden.next_after, None);
            assert_eq!(hidden.source_head, visible.source_head);
        }
        let cancelled = node.request_context();
        cancelled.authority().cancel();
        assert!(
            node.runtime()
                .block_on(node.read_pull_requests_in(
                    &cancelled,
                    &RefVisibility::new(),
                    0,
                    100,
                    Some(visible.source_head),
                ))
                .is_err()
        );
        assert!(matches!(
            page(&node, 0, 0, None),
            Err(PullRequestReadRefusal::InvalidLimit)
        ));
        assert_eq!(cache.test_builds(), 1);
        assert!(Arc::ptr_eq(
            &retained,
            &cache
                .lookup(&node, HistoryKind::PullRequests, visible.source_head)
                .unwrap()
        ));
        assert_eq!(page(&node, 0, 100, None).unwrap(), visible);
        assert_eq!(cache.test_builds(), 1);
        node.shutdown().unwrap();
    }
}

fn copy_storage(from: &Path, to: &Path) {
    fs::create_dir(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let destination = to.join(entry.file_name());
        let kind = entry.file_type().unwrap();
        if kind.is_dir() {
            copy_storage(&entry.path(), &destination);
        } else {
            assert!(kind.is_file());
            fs::copy(entry.path(), destination).unwrap();
        }
    }
}

#[test]
fn pr_coordinates_survive_service_reopen_but_cannot_cross_identical_storage_roots() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let source = Scratch::new();
        let destination = Scratch::new();
        let node = node(&source, format);
        let fixture = fixture(&node, &source, format);
        accepted(apply(&node, &command(&fixture, 1), "cache-reopen-open"));
        let expected = page(&node, 0, 100, None).unwrap();
        let config = node.service_config.clone();
        assert_eq!(node.aggregate_history_index_cache().test_builds(), 1);
        node.shutdown().unwrap();

        let child = reopened(config.clone());
        assert!(
            child
                .aggregate_history_index_cache()
                .lookup(&child, HistoryKind::PullRequests, expected.source_head)
                .is_some()
        );
        assert_eq!(page(&child, 0, 100, None).unwrap(), expected);
        assert_eq!(child.aggregate_history_index_cache().test_builds(), 1);
        child.shutdown().unwrap();

        let mut copied_config = config.clone();
        copied_config.storage_root = destination.0.join("copied-node");
        copy_storage(&config.storage_root, &copied_config.storage_root);
        let copied = reopened(copied_config);
        assert!(
            copied
                .aggregate_history_index_cache()
                .lookup(&copied, HistoryKind::PullRequests, expected.source_head)
                .is_none()
        );
        assert_eq!(page(&copied, 0, 100, None).unwrap(), expected);
        assert_eq!(
            copied.aggregate_history_index_cache().test_builds(),
            2,
            "identical canonical history still requires verification in the other storage scope"
        );
        assert_eq!(page(&copied, 0, 100, None).unwrap(), expected);
        assert_eq!(copied.aggregate_history_index_cache().test_builds(), 2);
        copied.shutdown().unwrap();
    }
}
