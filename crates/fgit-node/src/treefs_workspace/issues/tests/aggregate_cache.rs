//! Listing and history windows share verified coordinates, never read authority.
use super::*;
use crate::aggregate_history::HistoryKind;
use std::sync::Arc;

fn list(node: &OneNode, pin: Option<RepositoryAuthorityHeadId>) -> issues::IssuePage {
    let request = node.request_context();
    node.runtime()
        .block_on(node.read_issues_in(&request, 0, 100, pin))
        .unwrap()
}

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
fn issue_list_and_history_windows_share_one_index_with_uncached_page_parity() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        accepted(apply(&node, &open(1), "cache-issue-one"));
        accepted(apply(&node, &open(2), "cache-issue-two"));
        for version in 1..=2 {
            accepted(apply(
                &node,
                &change(
                    1,
                    version,
                    IssueAction::Comment {
                        body: format!("Comment {version}"),
                    },
                ),
                &format!("cache-comment-{version}"),
            ));
        }
        let all = list(&node, None);
        assert_eq!(
            all.issues
                .iter()
                .map(|row| row.number.get())
                .collect::<Vec<_>>(),
            [1, 2]
        );
        let cache = node.aggregate_history_index_cache();
        let retained = cache
            .lookup(&node, HistoryKind::Issues, all.source_head)
            .unwrap();
        let first = history(&node, 1, 0, Some(all.source_head)).unwrap();
        let last = history(&node, 1, 2, Some(all.source_head)).unwrap();
        let other = history(&node, 2, 0, Some(all.source_head)).unwrap();
        assert_eq!(first.events.len(), 2);
        assert_eq!(first.next_after, Some(2));
        assert_eq!(first.issue.as_ref().unwrap().comments, 2);
        assert_eq!(last.events.len(), 1);
        assert_eq!(last.events[0].version.get(), 3);
        assert_eq!(last.next_after, None);
        assert_eq!(other.events.len(), 1);
        assert_eq!(list(&node, None), all);
        assert_eq!(
            cache.test_builds(),
            1,
            "timeline windows reuse the listing's complete selected histories"
        );
        assert!(Arc::ptr_eq(
            &retained,
            &cache
                .lookup(&node, HistoryKind::Issues, all.source_head)
                .unwrap()
        ));
        let config = node.service_config.clone();
        node.shutdown().unwrap();

        for budget in [0, 1] {
            let scalar = reopened(
                config
                    .clone()
                    .with_aggregate_history_index_cache_bytes(budget),
            );
            assert_eq!(list(&scalar, None), all);
            assert_eq!(
                history(&scalar, 1, 0, Some(all.source_head)).unwrap(),
                first
            );
            assert_eq!(history(&scalar, 1, 2, Some(all.source_head)).unwrap(), last);
            assert_eq!(
                history(&scalar, 2, 0, Some(all.source_head)).unwrap(),
                other
            );
            assert_eq!(scalar.aggregate_history_index_cache().test_builds(), 0);
            assert!(
                scalar
                    .aggregate_history_index_cache()
                    .lookup(&scalar, HistoryKind::Issues, all.source_head)
                    .is_none()
            );
            scalar.shutdown().unwrap();
        }
    }
}

#[test]
fn failed_and_late_historical_issue_reads_preserve_the_newest_verified_coordinates() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        accepted(apply(&node, &open(1), "cache-old-issue"));
        let old = list(&node, None);
        let old_history = history(&node, 1, 0, Some(old.source_head)).unwrap();
        let cache = node.aggregate_history_index_cache();
        let old_index = cache
            .lookup(&node, HistoryKind::Issues, old.source_head)
            .unwrap();
        accepted(apply(
            &node,
            &change(
                1,
                1,
                IssueAction::Edit(IssueEdit {
                    title: Some("New title".into()),
                    ..Default::default()
                }),
            ),
            "cache-new-title",
        ));
        accepted(apply(&node, &open(2), "cache-new-issue"));

        let cancelled = node.request_context();
        cancelled.authority().cancel();
        assert!(
            node.runtime()
                .block_on(node.read_issues_in(&cancelled, 0, 100, None))
                .is_err()
        );
        let request = node.request_context();
        assert!(matches!(
            node.runtime()
                .block_on(node.read_issues_in(&request, 0, 0, None)),
            Err(IssueReadRefusal::InvalidLimit)
        ));
        assert_eq!(cache.test_builds(), 1);
        assert!(Arc::ptr_eq(
            &old_index,
            &cache
                .lookup(&node, HistoryKind::Issues, old.source_head)
                .unwrap()
        ));

        let current = list(&node, None);
        assert_ne!(current.source_head, old.source_head);
        assert_eq!(current.issues.len(), 2);
        assert_eq!(current.issues[0].title, "New title");
        let current_index = cache
            .lookup(&node, HistoryKind::Issues, current.source_head)
            .unwrap();
        assert!(current_index.source_generation() > old_index.source_generation());
        assert_eq!(cache.test_builds(), 2);

        // A valid retained snapshot can complete after the current read. Its
        // response stays historical, but it must not displace the newer index.
        assert_eq!(list(&node, Some(old.source_head)), old);
        assert_eq!(
            history(&node, 1, 0, Some(old.source_head)).unwrap(),
            old_history
        );
        assert!(Arc::ptr_eq(
            &current_index,
            &cache
                .lookup(&node, HistoryKind::Issues, current.source_head)
                .unwrap()
        ));
        assert!(
            cache
                .lookup(&node, HistoryKind::Issues, old.source_head)
                .is_none()
        );
        assert_eq!(cache.test_builds(), 2);
        assert_eq!(list(&node, None), current);
        assert_eq!(cache.test_builds(), 2);
        node.shutdown().unwrap();
    }
}
