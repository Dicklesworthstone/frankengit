//! Persisted-node coverage for disposable verified history metadata. The
//! admission tests count actual history reads; these tests exercise the native
//! consumer, service-child ownership and authorization boundaries.

use super::super::scoped::ScopedForgeEventPage;
use super::*;

const CACHE_BYTES: usize = 2 * 1024 * 1024;

fn populated(
    scratch: &Scratch,
    format: GitHashAlgorithm,
    event_count: u64,
    cache_bytes: usize,
) -> OneNode {
    let (mut node, _) = OneNode::init(
        scratch
            .config(format)
            .with_event_history_index_cache_bytes(cache_bytes),
    )
    .unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    if event_count != 0 {
        publish(&node, &open(), "index-open");
        for version in 1..event_count {
            publish(
                &node,
                &change(
                    version,
                    IssueAction::Comment {
                        body: format!("history event {version}"),
                    },
                ),
                &format!("index-comment-{version}"),
            );
        }
    }
    node
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

fn scoped(
    node: &OneNode,
    request: &NodeRequestContext,
    issues: bool,
    pulls: bool,
) -> Result<ScopedForgeEventPage, ForgeEventReadRefusal> {
    node.runtime()
        .block_on(node.read_scoped_forge_events_in(request, None, 2, None, issues, pulls))
}

#[test]
fn indexed_pages_match_uncached_history_and_survive_service_child_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = populated(&scratch, format, 12, CACHE_BYTES);
        let retained_config = node.service_config.clone();
        assert_eq!(node.event_history_index_cache().test_counts(), (0, 0));

        let first = page(&node, None, 3, None).unwrap();
        assert_eq!(first.events.len(), 3);
        assert_eq!(node.event_history_index_cache().test_counts(), (1, 0));
        let all = page(&node, None, 100, Some(first.source_head)).unwrap();
        assert_eq!(all.events.len(), 12);
        let requests = [
            (None, 1),
            (None, 100),
            (Some(coordinates(all.events[0].cursor)), 1),
            (Some(coordinates(all.events[2].cursor)), 4),
            (Some(coordinates(all.events[11].cursor)), 100),
        ];
        let indexed: Vec<_> = requests
            .iter()
            .map(|&(after, limit)| page(&node, after, limit, Some(first.source_head)).unwrap())
            .collect();
        let warmed = node.event_history_index_cache().test_counts();
        assert_eq!(warmed.0, 1, "old cursors reuse one verified history index");
        assert!(warmed.1 >= requests.len());
        node.shutdown().unwrap();

        // A disabled cache independently reconstructs the same persisted
        // history. Compare complete envelopes, not just event counts.
        let scalar = reopened(
            retained_config
                .clone()
                .with_event_history_index_cache_bytes(0),
        );
        for (&(after, limit), expected) in requests.iter().zip(&indexed) {
            assert_eq!(
                &page(&scalar, after, limit, Some(first.source_head)).unwrap(),
                expected
            );
        }
        assert_eq!(scalar.event_history_index_cache().test_counts(), (0, 0));
        scalar.shutdown().unwrap();

        // The service's cloned configuration owns the metadata across child
        // shutdown/reopen. It owns no authority selection or read grants.
        let child = reopened(retained_config.clone());
        assert_eq!(page(&child, None, 3, None).unwrap(), first);
        let reused = child.event_history_index_cache().test_counts();
        assert_eq!(reused.0, warmed.0);
        assert!(reused.1 > warmed.1);
        child.shutdown().unwrap();

        // Existing storage retains its recorded authority-store instance; a
        // different proposed creation instance cannot relabel that binding.
        // Reopening therefore preserves eligibility for this exact cache hit.
        let rebound = reopened(
            retained_config.with_store_instance(fgit_authority::StoreInstanceId::from_raw(2)),
        );
        assert_eq!(page(&rebound, None, 3, None).unwrap(), first);
        let rebound_counts = rebound.event_history_index_cache().test_counts();
        assert_eq!(rebound_counts.0, reused.0);
        assert!(rebound_counts.1 > reused.1);
        rebound.shutdown().unwrap();

        // A fresh service has no retained metadata. Discarding it changes
        // reconstruction work only, not canonical output or cursor validity.
        let fresh = reopened(scratch.config(format));
        assert_eq!(fresh.event_history_index_cache().test_counts(), (0, 0));
        assert_eq!(page(&fresh, None, 3, None).unwrap(), first);
        assert_eq!(fresh.event_history_index_cache().test_counts().0, 1);
        fresh.shutdown().unwrap();
    }
}

#[test]
fn advancing_authority_extends_the_index_and_stale_pins_never_use_it() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = populated(&scratch, format, 3, CACHE_BYTES);
        let original = page(&node, None, 100, None).unwrap();
        let cursor = coordinates(original.events[0].cursor);
        let before = node.event_history_index_cache().test_counts();
        assert_eq!(before.0, 1);
        assert_eq!(node.event_history_index_cache().test_extension_count(), 0);

        let appended = publish(
            &node,
            &change(
                3,
                IssueAction::Comment {
                    body: "appended after the cached head".into(),
                },
            ),
            "index-append-after-warm",
        );
        assert!(matches!(
            page(&node, Some(cursor), 100, Some(original.source_head)),
            Err(ForgeEventReadRefusal::SnapshotMoved)
        ));
        assert_eq!(node.event_history_index_cache().test_counts(), before);
        assert_eq!(node.event_history_index_cache().test_extension_count(), 0);

        // A verified edge alone is insufficient: an invented event offset
        // must refuse without retaining a partially useful successor index.
        assert!(matches!(
            page(&node, Some((cursor.0, u32::MAX)), 100, None),
            Err(ForgeEventReadRefusal::Admission(_))
        ));
        assert_eq!(node.event_history_index_cache().test_counts(), before);
        assert_eq!(node.event_history_index_cache().test_extension_count(), 0);

        let advanced = page(&node, Some(cursor), 100, None).unwrap();
        assert_ne!(advanced.source_head, original.source_head);
        assert_eq!(advanced.events.len(), 3);
        assert_eq!(&advanced.events[..2], &original.events[1..]);
        assert_eq!(advanced.events[2].tx_id, appended.0);
        assert!(
            advanced
                .events
                .windows(2)
                .all(|pair| pair[0].cursor < pair[1].cursor)
        );
        assert!(advanced.next_after.is_none());
        // A direct successor verifies one edge and reuses the old prefix,
        // including when the first read at that head resumes an old cursor.
        assert_eq!(node.event_history_index_cache().test_counts(), before);
        assert_eq!(node.event_history_index_cache().test_extension_count(), 1);
        let full_advanced = page(&node, None, 100, None).unwrap();
        assert_eq!(&full_advanced.events[1..], advanced.events.as_slice());
        let refreshed = node.event_history_index_cache().test_counts();
        assert_eq!(refreshed.0, before.0);
        assert!(refreshed.1 > before.1);
        assert_eq!(page(&node, Some(cursor), 100, None).unwrap(), advanced);
        assert!(node.event_history_index_cache().test_counts().1 > refreshed.1);

        // Cache membership of an RCR does not validate an invented event
        // offset within that record. The permitted cursor remains usable.
        assert!(matches!(
            page(&node, Some((cursor.0, u32::MAX)), 100, None),
            Err(ForgeEventReadRefusal::Admission(_))
        ));
        assert_eq!(page(&node, Some(cursor), 100, None).unwrap(), advanced);
        node.shutdown().unwrap();
    }
}

#[test]
fn warm_history_rechecks_grants_and_cancellation_for_every_request() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = populated(&scratch, format, 4, CACHE_BYTES);
        let raw = page(&node, None, 2, None).unwrap();
        let request = node.request_context();
        let permitted = scoped(&node, &request, true, false).unwrap();
        assert_eq!(permitted.events().len(), 2);
        assert_eq!(permitted.source_head(), raw.source_head);

        // Pull-read permission cannot disclose issue events even when another
        // reader has already warmed this exact history and source head.
        let request = node.request_context();
        let omitted = scoped(&node, &request, false, true).unwrap();
        assert!(omitted.events().is_empty());
        assert_eq!(omitted.source_head(), permitted.source_head());
        assert_eq!(omitted.resume_after(), permitted.resume_after());
        assert_eq!(omitted.next_after(), permitted.next_after());
        let warmed = node.event_history_index_cache().test_counts();
        assert_eq!(warmed.0, 1);
        assert!(warmed.1 >= 2);

        let request = node.request_context();
        assert!(matches!(
            scoped(&node, &request, false, false),
            Err(ForgeEventReadRefusal::NoReadScope)
        ));
        assert_eq!(node.event_history_index_cache().test_counts(), warmed);

        let cancelled = node.request_context();
        cancelled.cancel();
        assert!(matches!(
            scoped(&node, &cancelled, true, false),
            Err(ForgeEventReadRefusal::Cancelled)
        ));
        assert!(matches!(
            node.runtime()
                .block_on(node.read_forge_events_in(&cancelled, None, 2, None)),
            Err(ForgeEventReadRefusal::Cancelled)
        ));
        assert_eq!(node.event_history_index_cache().test_counts(), warmed);

        let request = node.request_context();
        let permitted_again = scoped(&node, &request, true, false).unwrap();
        assert_eq!(
            permitted_again.to_json().unwrap(),
            permitted.to_json().unwrap()
        );
        assert_eq!(page(&node, None, 2, None).unwrap(), raw);
        assert_eq!(node.event_history_index_cache().test_counts().0, 1);
        node.shutdown().unwrap();
    }
}

#[test]
fn empty_history_and_an_undersized_cache_keep_the_scalar_results() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = populated(&scratch, format, 0, CACHE_BYTES);
        let empty = page(&node, None, 1, None).unwrap();
        assert!(empty.events.is_empty());
        assert!(empty.next_after.is_none());
        assert_eq!(page(&node, None, 1, None).unwrap(), empty);
        assert_eq!(node.event_history_index_cache().test_counts(), (1, 1));
        assert!(matches!(
            page(&node, Some((1, 0)), 1, None),
            Err(ForgeEventReadRefusal::Admission(_))
        ));

        publish(&node, &open(), "index-first-event");
        let first = page(&node, None, 1, None).unwrap();
        assert_eq!(first.events.len(), 1);
        assert_ne!(first.source_head, empty.source_head);
        assert_eq!(node.event_history_index_cache().test_counts().0, 1);
        assert_eq!(node.event_history_index_cache().test_extension_count(), 1);
        let tiny_config = node
            .service_config
            .clone()
            .with_event_history_index_cache_bytes(1);
        node.shutdown().unwrap();

        // A retained-byte ceiling too small for one index is an acceleration
        // miss. It must not turn an otherwise valid event page into a refusal.
        let tiny = reopened(tiny_config);
        assert_eq!(page(&tiny, None, 1, None).unwrap(), first);
        assert_eq!(page(&tiny, None, 1, None).unwrap(), first);
        assert_eq!(tiny.event_history_index_cache().test_counts(), (0, 0));
        tiny.shutdown().unwrap();
    }
}

#[test]
fn refusal_and_checkpoint_edges_preserve_events_and_extend_the_exact_basis() {
    use crate::outcome_checkpoint::OutcomeCheckpointLimits;

    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = populated(&scratch, format, 3, CACHE_BYTES);
        let original = page(&node, None, 100, None).unwrap();
        let cursor = coordinates(original.events[0].cursor);

        let request = node.request_context();
        let refused = node
            .runtime()
            .block_on(node.admit_issue_durable_in(
                &request,
                &session("index-refusal-only"),
                &change(1, IssueAction::Close),
                AdmissionLimits::default(),
            ))
            .unwrap();
        assert!(matches!(refused.1.outcome, DecisionOutcome::Refused { .. }));
        let after_refusal = page(&node, Some(cursor), 100, None).unwrap();
        assert_ne!(after_refusal.source_head, original.source_head);
        assert_eq!(after_refusal.events, original.events[1..]);
        assert_eq!(node.event_history_index_cache().test_counts().0, 1);
        assert_eq!(node.event_history_index_cache().test_extension_count(), 1);

        let request = node.request_context();
        let checkpoint = node
            .runtime()
            .block_on(node.checkpoint_outcomes_in(
                &request,
                OutcomeCheckpointLimits {
                    expected_head: Some(after_refusal.source_head),
                    ..OutcomeCheckpointLimits::default()
                },
            ))
            .unwrap();
        assert!(checkpoint.published);
        assert_eq!(checkpoint.source_head, after_refusal.source_head);
        let after_checkpoint = page(&node, Some(cursor), 100, None).unwrap();
        assert_eq!(after_checkpoint.source_head, checkpoint.published_head);
        assert_eq!(after_checkpoint.events, after_refusal.events);
        assert_eq!(after_checkpoint.next_after, after_refusal.next_after);
        assert_eq!(node.event_history_index_cache().test_counts().0, 1);
        assert_eq!(node.event_history_index_cache().test_extension_count(), 2);
        node.shutdown().unwrap();
    }
}

#[test]
fn skipped_publications_catch_up_once_for_resumed_and_initial_reads() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = populated(&scratch, format, 3, CACHE_BYTES);
        let original = page(&node, None, 100, None).unwrap();
        let before = node.event_history_index_cache().test_counts();
        for version in 3..5 {
            publish(
                &node,
                &change(
                    version,
                    IssueAction::Comment {
                        body: format!("unobserved successor {version}"),
                    },
                ),
                &format!("index-skip-{version}"),
            );
        }

        let resumed = page(
            &node,
            Some(coordinates(original.events[2].cursor)),
            100,
            None,
        )
        .unwrap();
        assert_eq!(resumed.events.len(), 2);
        assert_ne!(resumed.source_head, original.source_head);
        assert_eq!(node.event_history_index_cache().test_counts(), before);
        assert_eq!(node.event_history_index_cache().test_extension_count(), 1);
        let full = page(&node, None, 100, None).unwrap();
        assert_eq!(full.events[3..], resumed.events);
        assert_eq!(node.event_history_index_cache().test_counts().0, before.0);
        assert_eq!(node.event_history_index_cache().test_extension_count(), 1);

        // A reader starting from the beginning also reuses its verified
        // prefix after more than one publication, without a new full build.
        for version in 5..8 {
            publish(
                &node,
                &change(
                    version,
                    IssueAction::Comment {
                        body: format!("initial-page successor {version}"),
                    },
                ),
                &format!("index-initial-skip-{version}"),
            );
        }
        let advanced = page(&node, None, 100, None).unwrap();
        assert_eq!(advanced.events.len(), 8);
        assert_eq!(advanced.events[..5], full.events);
        assert_eq!(node.event_history_index_cache().test_counts().0, before.0);
        assert_eq!(node.event_history_index_cache().test_extension_count(), 2);
        let scalar_config = node
            .service_config
            .clone()
            .with_event_history_index_cache_bytes(0);
        node.shutdown().unwrap();
        let scalar = reopened(scalar_config);
        assert_eq!(page(&scalar, None, 100, None).unwrap(), advanced);
        assert_eq!(
            page(
                &scalar,
                Some(coordinates(original.events[2].cursor)),
                2,
                None,
            )
            .unwrap()
            .events,
            resumed.events
        );
        scalar.shutdown().unwrap();
    }
}

#[test]
fn skipped_refusals_and_checkpoints_preserve_cursors_grants_and_cancellation() {
    use crate::outcome_checkpoint::OutcomeCheckpointLimits;

    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = populated(&scratch, format, 3, CACHE_BYTES);
        let original = page(&node, None, 100, None).unwrap();
        let before = node.event_history_index_cache().test_counts();
        let cursor = coordinates(original.events.last().unwrap().cursor);

        let request = node.request_context();
        let refused = node
            .runtime()
            .block_on(node.admit_issue_durable_in(
                &request,
                &session("index-skipped-refusal"),
                &change(1, IssueAction::Close),
                AdmissionLimits::default(),
            ))
            .unwrap();
        assert!(matches!(refused.1.outcome, DecisionOutcome::Refused { .. }));
        let request = node.request_context();
        let checkpoint = node
            .runtime()
            .block_on(node.checkpoint_outcomes_in(&request, OutcomeCheckpointLimits::default()))
            .unwrap();
        assert!(checkpoint.published);
        let mut appended = Vec::new();
        for version in 3..5 {
            appended.push(
                publish(
                    &node,
                    &change(
                        version,
                        IssueAction::Comment {
                            body: format!("after unobserved checkpoint {version}"),
                        },
                    ),
                    &format!("index-checkpoint-skip-{version}"),
                )
                .0,
            );
        }

        assert!(matches!(
            page(&node, Some(cursor), 100, Some(original.source_head)),
            Err(ForgeEventReadRefusal::SnapshotMoved)
        ));
        assert!(matches!(
            page(&node, Some((cursor.0, u32::MAX)), 100, None),
            Err(ForgeEventReadRefusal::Admission(_))
        ));
        let denied = node.request_context();
        assert!(matches!(
            scoped(&node, &denied, false, false),
            Err(ForgeEventReadRefusal::NoReadScope)
        ));
        let cancelled = node.request_context();
        cancelled.cancel();
        assert!(matches!(
            node.runtime()
                .block_on(node.read_forge_events_in(&cancelled, Some(cursor), 100, None,)),
            Err(ForgeEventReadRefusal::Cancelled)
        ));
        assert_eq!(node.event_history_index_cache().test_counts(), before);
        assert_eq!(node.event_history_index_cache().test_extension_count(), 0);

        let resumed = page(&node, Some(cursor), 100, None).unwrap();
        assert_eq!(
            resumed
                .events
                .iter()
                .map(|event| event.tx_id)
                .collect::<Vec<_>>(),
            appended
        );
        assert_eq!(node.event_history_index_cache().test_counts(), before);
        assert_eq!(node.event_history_index_cache().test_extension_count(), 1);
        let request = node.request_context();
        let omitted = scoped(&node, &request, false, true).unwrap();
        assert!(omitted.events().is_empty());
        assert_eq!(omitted.source_head(), resumed.source_head);
        let request = node.request_context();
        assert_eq!(
            scoped(&node, &request, true, false).unwrap().events().len(),
            2
        );
        let full = page(&node, None, 100, None).unwrap();
        assert_eq!(full.events[..3], original.events);
        assert_eq!(full.events[3..], resumed.events);
        assert_eq!(
            full.events.len(),
            5,
            "refusals and checkpoints add no events"
        );
        assert_eq!(node.event_history_index_cache().test_counts().0, before.0);
        node.shutdown().unwrap();
    }
}

#[test]
fn late_older_read_cannot_replace_newer_metadata_in_the_same_scope() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = populated(&scratch, format, 3, CACHE_BYTES);
        let original = page(&node, None, 100, None).unwrap();
        let older = node
            .event_history_index_cache()
            .lookup(&node, original.source_head)
            .unwrap();
        for version in 3..5 {
            publish(
                &node,
                &change(
                    version,
                    IssueAction::Comment {
                        body: format!("newer cache owner {version}"),
                    },
                ),
                &format!("index-newer-owner-{version}"),
            );
        }
        let current = page(&node, None, 100, None).unwrap();
        let counts = node.event_history_index_cache().test_counts();
        let extensions = node.event_history_index_cache().test_extension_count();
        let newer = node
            .event_history_index_cache()
            .lookup(&node, current.source_head)
            .unwrap();
        assert!(newer.source_generation() > older.source_generation());

        // Deterministically finish both possible older in-flight reader paths
        // after the newer read: a cold build and an incremental extension.
        node.event_history_index_cache()
            .insert(&node, Arc::clone(&older));
        node.event_history_index_cache()
            .insert_extended(&node, older);
        node.event_history_index_cache()
            .insert(&node, Arc::clone(&newer));
        assert_eq!(node.event_history_index_cache().test_counts(), counts);
        assert_eq!(
            node.event_history_index_cache().test_extension_count(),
            extensions
        );
        let retained = node
            .event_history_index_cache()
            .lookup(&node, current.source_head)
            .unwrap();
        assert!(Arc::ptr_eq(&retained, &newer));
        assert!(
            node.event_history_index_cache()
                .lookup(&node, original.source_head)
                .is_none()
        );
        assert_eq!(page(&node, None, 100, None).unwrap(), current);
        assert_eq!(node.event_history_index_cache().test_counts().0, counts.0);
        assert_eq!(
            node.event_history_index_cache().test_extension_count(),
            extensions
        );
        node.shutdown().unwrap();
    }
}

fn copy_storage(from: &std::path::Path, to: &std::path::Path) {
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
fn an_identical_history_in_another_root_cannot_reuse_an_older_index() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let source = Scratch::new();
        let destination = Scratch::new();
        let node = populated(&source, format, 3, CACHE_BYTES);
        let original = page(&node, None, 100, None).unwrap();
        let before = node.event_history_index_cache().test_counts();
        let mut copied_config = node.service_config.clone();
        let source_root = copied_config.storage_root.clone();
        copied_config.storage_root = destination.0.join("copied-node");
        node.shutdown().unwrap();
        // Copy a closed native store so every identity and canonical head is
        // identical, while deliberately retaining the source service's cache.
        copy_storage(&source_root, &copied_config.storage_root);
        let copied = reopened(copied_config);
        let request = copied.request_context();
        let basis = copied
            .runtime()
            .block_on(copied.event_read_basis_in(&request, None))
            .unwrap();
        assert_eq!(basis.basis.id(), original.source_head);
        for version in 3..5 {
            publish(
                &copied,
                &change(
                    version,
                    IssueAction::Comment {
                        body: format!("only in the copied root {version}"),
                    },
                ),
                &format!("index-copied-root-{version}"),
            );
        }
        let resumed = page(
            &copied,
            Some(coordinates(original.events[2].cursor)),
            100,
            None,
        )
        .unwrap();
        assert_eq!(resumed.events.len(), 2);
        assert_eq!(copied.event_history_index_cache().test_counts(), before);
        assert_eq!(copied.event_history_index_cache().test_extension_count(), 0);
        let full = page(&copied, None, 100, None).unwrap();
        assert_eq!(full.events[3..], resumed.events);
        assert_eq!(
            copied.event_history_index_cache().test_counts().0,
            before.0 + 1
        );
        copied.shutdown().unwrap();
    }
}

#[test]
fn exhausted_catch_up_retention_uses_the_scalar_suffix_without_a_second_build() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = populated(&scratch, format, 1, 5120);
        let first = page(&node, None, 1, None).unwrap();
        assert_eq!(node.event_history_index_cache().test_counts().0, 1);
        let mut events = first.events;
        let mut budget_miss = false;
        // This small real cache fills after a few committed descriptors. Skip
        // two publications between reads, then fall back to that same suffix
        // without attempting a redundant full-history index build.
        for version in (1..24).step_by(2) {
            let prior_extensions = node.event_history_index_cache().test_extension_count();
            let mut appended = Vec::new();
            for version in version..version + 2 {
                appended.push(
                    publish(
                        &node,
                        &change(
                            version,
                            IssueAction::Comment {
                                body: format!("bounded retention event {version}"),
                            },
                        ),
                        &format!("index-budget-{version}"),
                    )
                    .0,
                );
            }
            let next = page(
                &node,
                Some(coordinates(events.last().unwrap().cursor)),
                2,
                None,
            )
            .unwrap();
            assert_eq!(next.events.len(), 2);
            assert_eq!(
                next.events
                    .iter()
                    .map(|event| event.tx_id)
                    .collect::<Vec<_>>(),
                appended
            );
            assert!(next.next_after.is_none());
            events.extend(next.events);
            assert_eq!(node.event_history_index_cache().test_counts().0, 1);
            if node.event_history_index_cache().test_extension_count() == prior_extensions {
                budget_miss = true;
                break;
            }
        }
        assert!(budget_miss, "the small retained-byte allowance must fill");
        let counts = node.event_history_index_cache().test_counts();
        let extensions = node.event_history_index_cache().test_extension_count();
        assert!(extensions > 0);
        let full = page(&node, None, 100, None).unwrap();
        assert_eq!(full.events, events);
        assert_eq!(node.event_history_index_cache().test_counts(), counts);
        assert_eq!(
            node.event_history_index_cache().test_extension_count(),
            extensions
        );
        node.shutdown().unwrap();
    }
}
