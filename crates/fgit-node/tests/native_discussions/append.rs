//! Real durable discussion intents, independent request overlap and cold recovery.
use super::*;
use fgit_forge::ForgeEventPayload;
use fgit_forge::event::discussion::DiscussionCommentIntent;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::task::Poll;

fn intent(number: u64, body: &str) -> DiscussionCommentIntent {
    DiscussionCommentIntent {
        number: DiscussionNumber::try_new(number).unwrap(),
        body: body.into(),
    }
}

fn append(node: &OneNode, intent: &DiscussionCommentIntent, key: &str) -> Outcome {
    node.runtime()
        .block_on(node.admit_discussion_comment_durable_in(
            &node.request_context(),
            &session(key),
            intent,
            AdmissionLimits::default(),
        ))
}

#[test]
fn append_preserves_metadata_and_lock_rules_with_exact_recovery_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = scratch.node(format);
        committed(apply(&node, &opening(7), "open"));
        let submitted = intent(7, "Exact é\r\ncomment without newline");
        committed(apply(
            &node,
            &command(
                7,
                1,
                DiscussionAction::Edit(DiscussionEdit {
                    title: Some("Concurrent title".into()),
                    body: None,
                }),
            ),
            "edit",
        ));
        let before = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        let original = committed(append(&node, &submitted, "append"));
        let first = history(&node, 7, None);
        let discussion = first.discussion.as_ref().unwrap();
        assert_eq!((discussion.version.get(), discussion.comments), (3, 1));
        assert_eq!(discussion.title, "Concurrent title");
        assert_eq!(
            discussion.body,
            "Native discussion é\n<script>untrusted</script>"
        );
        assert!(matches!(
            &first.events[2].payload,
            ForgeEventPayload::DiscussionChangedNative(change)
                if change.actor == PrincipalId::from_bytes([0xc3; 16])
                    && change.action == (DiscussionAction::Comment { body: submitted.body.clone() })
        ));

        let strict = command(
            7,
            1,
            DiscussionAction::Comment {
                body: submitted.body.clone(),
            },
        );
        refused(
            apply(&node, &strict, "strict-stale"),
            RefusalCode::EvidenceStale,
        );
        assert!(apply(&node, &strict, "append").is_err());
        assert!(append(&node, &intent(7, "changed bytes"), "append").is_err());
        committed(apply(
            &node,
            &command(7, 3, DiscussionAction::Close),
            "close",
        ));
        committed(append(
            &node,
            &intent(7, "Closed discussion comment"),
            "closed",
        ));
        committed(apply(&node, &command(7, 5, DiscussionAction::Lock), "lock"));
        assert_eq!(append(&node, &submitted, "append").unwrap(), original);
        let blocked = intent(7, "Locked comment");
        let refusal = refused(
            append(&node, &blocked, "blocked"),
            RefusalCode::ProtectedRefTransitionDenied,
        );
        committed(apply(
            &node,
            &command(7, 6, DiscussionAction::Unlock),
            "unlock",
        ));
        assert_eq!(append(&node, &blocked, "blocked").unwrap(), refusal);
        committed(append(&node, &blocked, "after-unlock"));
        committed(apply(
            &node,
            &command(7, 8, DiscussionAction::Lock),
            "lock-again",
        ));
        let settled = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        let current = history(&node, 7, None);
        let discussion = current.discussion.as_ref().unwrap();
        assert_eq!(
            (
                discussion.version.get(),
                discussion.comments,
                discussion.locked
            ),
            (9, 3, true)
        );
        assert_eq!(discussion.state, DiscussionState::Closed);
        assert_eq!(discussion.title, "Concurrent title");
        assert_eq!(settled.snapshot().refs, before.snapshot().refs);
        assert_eq!(
            settled.basis().body().ref_root,
            before.basis().body().ref_root
        );
        assert_eq!(
            settled.basis().body().policy_epoch,
            before.basis().body().policy_epoch
        );
        assert_eq!(
            settled.basis().body().retention_root,
            before.basis().body().retention_root
        );
        assert_eq!(
            settled.selected_closure().closure(),
            before.selected_closure().closure()
        );
        assert_eq!(history(&node, 7, Some(first.source_head)), first);
        node.shutdown().unwrap();

        // No warmed projections or serving state can substitute for the durable
        // terminal: the original commit/refusal is recovered before new intake.
        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        assert_eq!(append(&reopened, &submitted, "append").unwrap(), original);
        assert_eq!(append(&reopened, &blocked, "blocked").unwrap(), refusal);
        assert!(append(&reopened, &submitted, "stopped-intake").is_err());
        assert!(append(&reopened, &intent(7, "changed bytes"), "append").is_err());
        let generation = reopened
            .runtime()
            .block_on(reopened.authenticate_authority_head())
            .unwrap()
            .receipt()
            .generation();
        reopened.bring_into_service(generation).unwrap();
        assert_eq!(history(&reopened, 7, None), current);
        assert_eq!(
            reopened
                .runtime()
                .block_on(reopened.materialize_admission())
                .unwrap()
                .basis(),
            settled.basis()
        );
        reopened.shutdown().unwrap();
    }
}

#[test]
fn eight_overlapping_discussion_comments_all_commit_once() {
    const COUNT: usize = 8;
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = scratch.node(format);
        committed(apply(&node, &opening(1), "open"));
        let before = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        // Equal text under different keys is two comments, not body deduplication.
        let intents: Vec<_> = (0..COUNT)
            .map(|i| intent(1, &format!("comment {}", i / 2)))
            .collect();
        let requests: Vec<_> = (0..COUNT).map(|_| node.request_context()).collect();
        let keys: Vec<_> = (0..COUNT).map(|i| format!("append-{i}")).collect();
        let sessions: Vec<_> = keys.iter().map(|key| session(key)).collect();
        let mut pending: Vec<_> = (0..COUNT)
            .map(|i| {
                Box::pin(node.admit_discussion_comment_durable_in(
                    &requests[i],
                    &sessions[i],
                    &intents[i],
                    AdmissionLimits::default(),
                ))
            })
            .collect();
        let mut results: Vec<_> = (0..COUNT).map(|_| None).collect();
        let mut overlap = false;
        node.runtime().block_on(std::future::poll_fn(|cx| {
            let mut waiting = 0;
            for i in 0..COUNT {
                if results[i].is_none() {
                    match pending[i].as_mut().poll(cx) {
                        Poll::Ready(result) => results[i] = Some(result),
                        Poll::Pending => waiting += 1,
                    }
                }
            }
            overlap |= waiting > 1;
            if results.iter().all(Option::is_some) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }));
        drop(pending);
        assert!(
            overlap,
            "independent requests must have pending authority operations together"
        );
        let results: Vec<_> = results
            .into_iter()
            .map(|result| committed(result.unwrap()))
            .collect();
        assert_eq!(
            results
                .iter()
                .map(|result| result.0)
                .collect::<BTreeSet<_>>()
                .len(),
            COUNT
        );
        let page = history(&node, 1, None);
        let discussion = page.discussion.as_ref().unwrap();
        assert_eq!(
            (discussion.version.get(), discussion.comments),
            (COUNT as u64 + 1, COUNT as u64)
        );
        let mut bodies = BTreeMap::new();
        for event in page.events.iter().skip(1) {
            let ForgeEventPayload::DiscussionChangedNative(change) = &event.payload else {
                panic!("discussion event");
            };
            let DiscussionAction::Comment { body } = &change.action else {
                panic!("comment event");
            };
            *bodies.entry(body.clone()).or_insert(0usize) += 1;
        }
        assert_eq!(
            bodies,
            (0..COUNT / 2)
                .map(|i| (format!("comment {i}"), 2))
                .collect()
        );
        let settled = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(
            settled.snapshot().outbox.len(),
            before.snapshot().outbox.len() + COUNT
        );
        assert_eq!(settled.snapshot().refs, before.snapshot().refs);
        assert_eq!(
            settled.selected_closure().closure(),
            before.selected_closure().closure()
        );
        for i in (0..COUNT).rev() {
            assert_eq!(append(&node, &intents[i], &keys[i]).unwrap(), results[i]);
        }
        assert_eq!(
            node.runtime()
                .block_on(node.materialize_admission())
                .unwrap()
                .basis(),
            settled.basis()
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn missing_cancelled_and_unauthenticated_appends_preserve_their_boundaries() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = scratch.node(format);
        let comment = intent(1, "One comment");
        let missing = refused(
            append(&node, &comment, "missing"),
            RefusalCode::EvidenceStale,
        );
        committed(apply(&node, &opening(1), "open"));
        assert_eq!(append(&node, &comment, "missing").unwrap(), missing);
        let before = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert!(matches!(
            node.runtime()
                .block_on(node.admit_discussion_comment_durable_in(
                    &node.request_context(),
                    &LoopbackReceiveSession::anonymous(),
                    &comment,
                    AdmissionLimits::default(),
                )),
            Err(NodeReceiveTransportRefusal::Unauthenticated)
        ));
        let cancelled = node.request_context();
        cancelled.cancel();
        assert!(
            node.runtime()
                .block_on(node.admit_discussion_comment_durable_in(
                    &cancelled,
                    &session("cancelled"),
                    &comment,
                    AdmissionLimits::default(),
                ))
                .is_err()
        );
        assert_eq!(
            node.runtime()
                .block_on(node.materialize_admission())
                .unwrap()
                .basis(),
            before.basis()
        );
        let terminal = committed(append(&node, &comment, "cancelled"));
        assert_eq!(append(&node, &comment, "cancelled").unwrap(), terminal);
        assert_eq!(history(&node, 1, None).discussion.unwrap().comments, 1);
        node.shutdown().unwrap();
    }
}
