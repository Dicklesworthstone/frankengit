//! The branch write consumer uses only native-verified, currently selected
//! parent adjacency. A cache hit changes physical reads, never publication.

use super::*;
use crate::ancestry_metadata::AncestryMetadataAccess;

fn reopen(node: OneNode, cache_bytes: Option<usize>) -> OneNode {
    let mut config = node.service_config.clone();
    if let Some(bytes) = cache_bytes {
        config = config.with_ancestry_metadata_cache_bytes(bytes);
    }
    node.shutdown().unwrap();
    let mut reopened = OneNode::open_existing(config).unwrap();
    let generation = reopened
        .runtime()
        .block_on(reopened.authenticate_authority_head())
        .unwrap()
        .receipt()
        .generation();
    reopened.bring_into_service(generation).unwrap();
    reopened
}

fn advance(node: &OneNode, name: &str, base: GitOid, tip: GitOid, key: &str) -> AdmissionResult {
    accepted(apply(
        node,
        &[RefCommand {
            name: reference(name),
            expected_old: ExpectedOld::Exactly(base),
            proposed_new: ProposedNew::Update(tip),
            force: false,
        }],
        key,
    ))
}

fn query(
    node: &OneNode,
    cached: bool,
    ancestor: GitOid,
    tip: GitOid,
    closure: &BTreeSet<GitOid>,
    limits: &ParseLimits,
    maximum_object_bytes: usize,
    live: impl FnMut() -> bool,
) -> Result<bool, NodeWorkspaceRefusal> {
    let request = node.request_context();
    let exhaustion = Cell::new(None);
    let source = VerifiedFabricPackSource {
        fabric: &node.fabric,
        object_format: node.object_format,
        maximum_object_bytes,
        database_context: request.authority(),
        database_exhaustion: &exhaustion,
        session_is_live: None,
    };
    let ancestry = AncestryMetadataAccess::for_node(node);
    is_fast_forward(
        &source,
        node.object_format,
        ancestor,
        tip,
        closure,
        limits,
        cached.then_some(&ancestry),
        live,
    )
}

#[test]
fn branch_publication_reuses_verified_ancestry_across_requests_and_service_children() {
    const COMMITS: usize = 192;
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, chain) = linear_fixture(&scratch, format, COMMITS);
        let node = reopen(node, Some(4 * 1024 * 1024));
        let (base, tip) = (chain[0], chain[COMMITS - 1]);
        let original = snapshot(&node);
        for name in ["refs/heads/cold", "refs/heads/warm", "refs/heads/reopened"] {
            accepted(apply(&node, &[create(name, base)], name));
        }
        assert_eq!(node.ancestry_metadata_cache().test_counts(), (0, 0));

        advance(&node, "refs/heads/cold", base, tip, "advance-cold");
        let cold = node.ancestry_metadata_cache().test_counts();
        assert_eq!(cold.0, COMMITS - 1);
        let terminal = advance(&node, "refs/heads/warm", base, tip, "advance-warm");
        let warm = node.ancestry_metadata_cache().test_counts();
        assert_eq!(
            warm.0, cold.0,
            "warm ancestry performs no native body reads"
        );
        assert_eq!(warm.1 - cold.1, COMMITS - 1);
        let settled = snapshot(&node);
        assert_eq!(settled.snapshot().refs[&reference("refs/heads/cold")], tip);
        assert_eq!(settled.snapshot().refs[&reference("refs/heads/warm")], tip);
        assert_eq!(
            settled.selected_closure().closure(),
            original.selected_closure().closure()
        );
        assert_eq!(
            advance(&node, "refs/heads/warm", base, tip, "advance-warm"),
            terminal
        );
        assert_eq!(snapshot(&node).basis(), settled.basis());
        assert_eq!(node.ancestry_metadata_cache().test_counts(), warm);

        // Service children reopen the same store with the same bounded cache.
        let node = reopen(node, None);
        advance(&node, "refs/heads/reopened", base, tip, "advance-reopened");
        let reopened = node.ancestry_metadata_cache().test_counts();
        assert_eq!(reopened.0, cold.0);
        assert_eq!(reopened.1 - warm.1, COMMITS - 1);

        // Discarding all derived state restores the original object walk.
        let node = reopen(node, Some(0));
        for (index, name) in ["refs/heads/disabled-a", "refs/heads/disabled-b"]
            .into_iter()
            .enumerate()
        {
            accepted(apply(&node, &[create(name, base)], name));
            advance(&node, name, base, tip, &format!("advance-disabled-{index}"));
            assert_eq!(
                node.ancestry_metadata_cache().test_counts(),
                ((index + 1) * (COMMITS - 1), 0)
            );
            assert_eq!(snapshot(&node).snapshot().refs[&reference(name)], tip);
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn cached_branch_ancestry_preserves_selection_limits_negative_answers_and_cancellation() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, chain) = linear_fixture(&scratch, format, 8);
        let limits = ParseLimits {
            tree_reference_bytes: format.digest_len(),
            ..ParseLimits::default()
        };
        let before = snapshot(&node);
        let closure = before.selected_closure().closure().objects();
        let (base, tip) = (chain[0], chain[7]);
        assert!(
            query(&node, true, base, tip, closure, &limits, usize::MAX, || {
                true
            })
            .unwrap()
        );
        let warmed = node.ancestry_metadata_cache().test_counts();
        assert!(
            query(&node, true, base, tip, closure, &limits, usize::MAX, || {
                true
            })
            .unwrap()
        );
        assert_eq!(node.ancestry_metadata_cache().test_counts().0, warmed.0);

        for cached in [false, true] {
            assert!(
                !query(
                    &node,
                    cached,
                    tip,
                    base,
                    closure,
                    &limits,
                    usize::MAX,
                    || true
                )
                .unwrap()
            );
            for omitted in [tip, chain[4]] {
                let mut incomplete = closure.clone();
                incomplete.remove(&omitted);
                assert!(matches!(
                    query(
                        &node,
                        cached,
                        base,
                        tip,
                        &incomplete,
                        &limits,
                        usize::MAX,
                        || true
                    ),
                    Err(NodeWorkspaceRefusal::BranchOperation(
                        "commit ancestry leaves the authority-selected closure during fast-forward check"
                    ))
                ));
            }
            assert!(
                query(
                    &node,
                    cached,
                    base,
                    tip,
                    closure,
                    &limits,
                    usize::MAX,
                    || true
                )
                .unwrap()
            );
        }

        // A hit cannot widen either the native read envelope or the parser.
        // Refusal text remains the cold path's typed branch refusal.
        for (narrowed, maximum) in [
            (limits.clone(), 1),
            (
                ParseLimits {
                    max_object_bytes: 1,
                    ..limits.clone()
                },
                usize::MAX,
            ),
            (
                ParseLimits {
                    max_header_lines: 1,
                    ..limits.clone()
                },
                usize::MAX,
            ),
            (
                ParseLimits {
                    max_header_line_bytes: 1,
                    ..limits.clone()
                },
                usize::MAX,
            ),
        ] {
            let cold = query(&node, false, base, tip, closure, &narrowed, maximum, || {
                true
            })
            .unwrap_err();
            let warm =
                query(&node, true, base, tip, closure, &narrowed, maximum, || true).unwrap_err();
            assert_eq!(format!("{cold:?}"), format!("{warm:?}"));
        }

        let checkpoints = Cell::new(0);
        assert!(
            query(&node, true, base, tip, closure, &limits, usize::MAX, || {
                checkpoints.set(checkpoints.get() + 1);
                true
            })
            .unwrap()
        );
        for stop in 1..=checkpoints.get() {
            for cached in [false, true] {
                let calls = Cell::new(0);
                assert!(matches!(
                    query(
                        &node,
                        cached,
                        base,
                        tip,
                        closure,
                        &limits,
                        usize::MAX,
                        || {
                            calls.set(calls.get() + 1);
                            calls.get() < stop
                        }
                    ),
                    Err(NodeWorkspaceRefusal::Cancelled { .. })
                ));
                assert_eq!(calls.get(), stop);
            }
        }
        assert_eq!(snapshot(&node).basis(), before.basis());
        node.shutdown().unwrap();
    }
}

#[test]
fn branch_ancestry_eviction_restores_cold_reads_without_changing_answers() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, chain) = linear_fixture(&scratch, format, 8);
        // Too small for this entire chain, large enough for eligible metadata.
        let node = reopen(node, Some(8 * 1024));
        let limits = ParseLimits {
            tree_reference_bytes: format.digest_len(),
            ..ParseLimits::default()
        };
        let selected = snapshot(&node);
        let closure = selected.selected_closure().closure().objects();
        let (base, tip) = (chain[0], chain[7]);
        for _ in 0..3 {
            let before = node.ancestry_metadata_cache().test_counts();
            assert!(
                query(&node, true, base, tip, closure, &limits, usize::MAX, || {
                    true
                })
                .unwrap()
            );
            let after = node.ancestry_metadata_cache().test_counts();
            assert!(after.0 > before.0, "evicted entries use native reads");
            assert!(
                query(
                    &node,
                    false,
                    base,
                    tip,
                    closure,
                    &limits,
                    usize::MAX,
                    || true
                )
                .unwrap()
            );
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn historical_branch_commits_outside_the_cache_profile_keep_the_original_parser() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, base, child, _) = fixture(&scratch, format);
        let tree = node
            .put_git_object(ObjectType::Tree, Vec::new())
            .unwrap()
            .identity();
        // GitCompatibleImport accepts the old byte-preserving headers. The
        // reusable metadata constructor deliberately refuses ambiguous trees.
        // This direct source fixture checks that optional retention does not
        // narrow the original branch walker; it does not publish these bytes.
        let body = format!("tree {tree}\ntree {tree}\nparent {child}\n\nhistorical\n");
        let historical = node
            .put_git_object(ObjectType::Commit, body.into_bytes())
            .unwrap()
            .identity();
        let selected = snapshot(&node);
        let mut closure = selected.selected_closure().closure().objects().clone();
        closure.extend([tree, historical]);
        let limits = ParseLimits {
            tree_reference_bytes: format.digest_len(),
            ..ParseLimits::default()
        };
        assert!(
            query(
                &node,
                false,
                base,
                historical,
                &closure,
                &limits,
                usize::MAX,
                || true
            )
            .unwrap()
        );
        assert!(
            query(
                &node,
                true,
                base,
                historical,
                &closure,
                &limits,
                usize::MAX,
                || true
            )
            .unwrap()
        );
        let first = node.ancestry_metadata_cache().test_counts();
        assert!(
            query(
                &node,
                true,
                base,
                historical,
                &closure,
                &limits,
                usize::MAX,
                || true
            )
            .unwrap()
        );
        let second = node.ancestry_metadata_cache().test_counts();
        assert_eq!(
            second.0,
            first.0 + 1,
            "historical metadata stays on the native path"
        );
        assert_eq!(
            second.1,
            first.1 + 1,
            "its ordinary parent can still be reused"
        );
        assert_eq!(snapshot(&node).basis(), selected.basis());
        node.shutdown().unwrap();
    }
}
