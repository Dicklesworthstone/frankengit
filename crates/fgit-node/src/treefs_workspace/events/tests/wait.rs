//! Native tail waits exercise the production timer and canonical store. The
//! writer waits for the reader's initial page before publishing, so these
//! cases cannot pass by finding an event that predates the wait.

use super::super::scoped::ScopedForgeEventPage;
use super::*;
use std::{
    future::{Future, poll_fn},
    pin::pin,
    task::Poll,
    time::Duration,
};

fn grants(issues: bool) -> ForgeEventReadGrants {
    ForgeEventReadGrants {
        issues,
        pulls: !issues,
        ..ForgeEventReadGrants::default()
    }
}

fn populated(scratch: &Scratch, format: GitHashAlgorithm) -> OneNode {
    let (mut node, _) = OneNode::init(
        scratch
            .config(format)
            .with_event_history_index_cache_bytes(2 * 1024 * 1024),
    )
    .unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    publish(&node, &open(), "wait-open");
    node
}

fn read(
    node: &OneNode,
    request: &NodeRequestContext,
    after: Option<(u64, u32)>,
    grants: ForgeEventReadGrants,
    wait_ms: u32,
) -> Result<ScopedForgeEventPage, ForgeEventReadRefusal> {
    node.runtime()
        .block_on(node.read_profiled_forge_events_wait_in(
            request,
            after,
            1,
            None,
            ForgeEventDisclosureProfile::IssuesPullsV1,
            grants,
            wait_ms,
        ))
}

// Poll both owned futures through completion. In particular, a finished read
// never abandons an in-flight canonical publication or its terminal result.
async fn complete_both<A: Future, B: Future>(first: A, second: B) -> (A::Output, B::Output) {
    let mut first = pin!(first);
    let mut second = pin!(second);
    let mut first_result = None;
    let mut second_result = None;
    poll_fn(|cx| {
        if first_result.is_none()
            && let Poll::Ready(result) = first.as_mut().poll(cx)
        {
            first_result = Some(result);
        }
        if second_result.is_none()
            && let Poll::Ready(result) = second.as_mut().poll(cx)
        {
            second_result = Some(result);
        }
        if first_result.is_some() && second_result.is_some() {
            Poll::Ready((first_result.take().unwrap(), second_result.take().unwrap()))
        } else {
            Poll::Pending
        }
    })
    .await
}

async fn after_initial_tail_read(node: &OneNode, previous_hits: usize) {
    let deadline = node.runtime().now() + Duration::from_secs(2);
    while node.event_history_index_cache().test_counts().1 == previous_hits {
        assert!(
            node.runtime().now() < deadline,
            "initial tail read did not complete"
        );
        asupersync::time::sleep(node.runtime().now(), Duration::from_millis(5)).await;
    }
    // The observed cache hit is recorded only after reading the empty page.
    // Allow at least one idle polling interval before the concurrent change.
    asupersync::time::sleep(node.runtime().now(), Duration::from_millis(75)).await;
}

#[test]
fn zero_wait_and_existing_visible_or_hidden_progress_preserve_one_page() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = populated(&scratch, format);
        publish(&node, &change(1, IssueAction::Close), "wait-close");
        for profile in [
            ForgeEventDisclosureProfile::IssuesPullsV1,
            ForgeEventDisclosureProfile::CollaborationV2,
        ] {
            for issues in [false, true] {
                let request = node.request_context();
                let expected = node
                    .runtime()
                    .block_on(node.read_profiled_forge_events_in(
                        &request,
                        None,
                        1,
                        None,
                        profile,
                        grants(issues),
                    ))
                    .unwrap();
                assert_eq!(expected.events().len(), usize::from(issues));
                assert!(expected.resume_after().is_some());
                assert!(expected.next_after().is_some());
                for wait_ms in [0, OneNode::MAX_FORGE_EVENT_WAIT_MS] {
                    // Waiting instead of returning cursor progress exhausts
                    // this original request and must fail the assertion.
                    let request = node.session_request_context_with_timeout(Duration::from_secs(1));
                    let actual = node
                        .runtime()
                        .block_on(node.read_profiled_forge_events_wait_in(
                            &request,
                            None,
                            1,
                            None,
                            profile,
                            grants(issues),
                            wait_ms,
                        ))
                        .unwrap();
                    assert_eq!(actual.to_json().unwrap(), expected.to_json().unwrap());
                }
            }
        }
        let request = node.request_context();
        let error = read(
            &node,
            &request,
            None,
            grants(true),
            OneNode::MAX_FORGE_EVENT_WAIT_MS + 1,
        )
        .unwrap_err();
        assert!(matches!(error, ForgeEventReadRefusal::InvalidWait));
        assert_eq!(error.public_code(), "invalid_event_wait");
        for wait_ms in [0, 1] {
            assert!(matches!(
                read(
                    &node,
                    &request,
                    None,
                    ForgeEventReadGrants::default(),
                    wait_ms
                ),
                Err(ForgeEventReadRefusal::NoReadScope)
            ));
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn timeout_retains_tail_without_replaying_unchanged_history_and_survives_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = populated(&scratch, format);
        let first = read(&node, &node.request_context(), None, grants(true), 0).unwrap();
        let before = node.event_history_index_cache().test_counts();
        let request = node.request_context();
        let started = node.runtime().now();
        let waited = read(&node, &request, first.resume_after(), grants(true), 150).unwrap();
        assert!(node.runtime().now().duration_since(started) >= 150_000_000);
        assert_eq!(waited.source_head(), first.source_head());
        assert_eq!(waited.resume_after(), first.resume_after());
        assert!(waited.events().is_empty());
        assert!(waited.next_after().is_none());
        assert_eq!(
            node.event_history_index_cache().test_counts(),
            (before.0, before.1 + 1),
            "idle polls authenticate the head but do not reread the event page"
        );
        node.shutdown().unwrap();

        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        let generation = reopened
            .runtime()
            .block_on(reopened.authenticate_authority_head())
            .unwrap()
            .receipt()
            .generation();
        reopened.bring_into_service(generation).unwrap();
        let resumed = read(
            &reopened,
            &reopened.request_context(),
            waited.resume_after(),
            grants(true),
            0,
        )
        .unwrap();
        assert_eq!(resumed.to_json().unwrap(), waited.to_json().unwrap());
        reopened.shutdown().unwrap();
    }
}

#[test]
fn waiting_tail_returns_delayed_visible_and_hidden_canonical_progress() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for issues in [false, true] {
            let scratch = Scratch::new();
            let node = populated(&scratch, format);
            let first = read(&node, &node.request_context(), None, grants(true), 0).unwrap();
            let previous_hits = node.event_history_index_cache().test_counts().1;
            let request = node.request_context();
            let (waited, published) = node.runtime().block_on(complete_both(
                node.read_profiled_forge_events_wait_in(
                    &request,
                    first.resume_after(),
                    1,
                    None,
                    ForgeEventDisclosureProfile::IssuesPullsV1,
                    grants(issues),
                    2_000,
                ),
                async {
                    after_initial_tail_read(&node, previous_hits).await;
                    node.admit_issue_durable_in(
                        &node.request_context(),
                        &session("delayed-wait-close"),
                        &change(1, IssueAction::Close),
                        AdmissionLimits::default(),
                    )
                    .await
                },
            ));
            let published = published.unwrap();
            assert!(matches!(
                published.1.outcome,
                DecisionOutcome::Committed { .. }
            ));
            let waited = waited.unwrap();
            assert_ne!(waited.source_head(), first.source_head());
            assert_ne!(waited.resume_after(), first.resume_after());
            assert_eq!(waited.events().len(), usize::from(issues));
            if issues {
                assert_eq!(waited.events()[0].tx_id(), published.0);
            }
            let immediate = read(
                &node,
                &node.request_context(),
                first.resume_after(),
                grants(issues),
                0,
            )
            .unwrap();
            assert_eq!(waited.to_json().unwrap(), immediate.to_json().unwrap());
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn waiting_exact_head_remains_pinned_when_a_later_publication_arrives() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = populated(&scratch, format);
        let first = read(&node, &node.request_context(), None, grants(true), 0).unwrap();
        let previous_hits = node.event_history_index_cache().test_counts().1;
        let request = node.request_context();
        let (waited, published) = node.runtime().block_on(complete_both(
            node.read_profiled_forge_events_wait_in(
                &request,
                first.resume_after(),
                1,
                Some(first.source_head()),
                ForgeEventDisclosureProfile::IssuesPullsV1,
                grants(true),
                2_000,
            ),
            async {
                after_initial_tail_read(&node, previous_hits).await;
                node.admit_issue_durable_in(
                    &node.request_context(),
                    &session("pinned-wait-close"),
                    &change(1, IssueAction::Close),
                    AdmissionLimits::default(),
                )
                .await
            },
        ));
        assert!(matches!(
            published.unwrap().1.outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert!(matches!(waited, Err(ForgeEventReadRefusal::SnapshotMoved)));
        node.shutdown().unwrap();
    }
}

#[test]
fn idle_wait_honors_original_deadline_and_cancellation_without_new_contexts() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = populated(&scratch, format);
        let first = read(&node, &node.request_context(), None, grants(true), 0).unwrap();
        let request = node.session_request_context_with_timeout(Duration::from_millis(200));
        let native = request.authority().attached_native_cx().unwrap();
        let original = native.budget();
        assert!(matches!(
            read(&node, &request, first.resume_after(), grants(true), 2_000),
            Err(ForgeEventReadRefusal::Cancelled)
        ));
        assert_eq!(native.budget().deadline, original.deadline);
        assert!(native.budget().poll_quota <= original.poll_quota);

        let previous_hits = node.event_history_index_cache().test_counts().1;
        let request = node.request_context();
        let (waited, ()) = node.runtime().block_on(complete_both(
            node.read_profiled_forge_events_wait_in(
                &request,
                first.resume_after(),
                1,
                None,
                ForgeEventDisclosureProfile::IssuesPullsV1,
                grants(true),
                2_000,
            ),
            async {
                after_initial_tail_read(&node, previous_hits).await;
                request.cancel();
            },
        ));
        assert!(matches!(waited, Err(ForgeEventReadRefusal::Cancelled)));
        let current = read(
            &node,
            &node.request_context(),
            first.resume_after(),
            grants(true),
            0,
        )
        .unwrap();
        assert_eq!(current.source_head(), first.source_head());
        assert_eq!(current.resume_after(), first.resume_after());
        node.shutdown().unwrap();
    }
}
