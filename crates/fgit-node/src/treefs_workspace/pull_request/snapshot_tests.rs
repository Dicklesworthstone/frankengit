//! Retained views use the existing production import and PR fixtures.
use super::*;

#[test]
fn retained_pr_walk_excludes_later_insertions_and_edits_even_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        let fixture = fixture(&node, &scratch, format);
        for number in [9, 3, 1] {
            accepted(apply(
                &node,
                &command(&fixture, number),
                &format!("open-{number}"),
            ));
        }
        let reference = page(&node, 0, 100, None).unwrap();
        let first = page(&node, 0, 1, Some(reference.source_head)).unwrap();
        let mut updated = command(&fixture, 3);
        updated.action = PullRequestAction::Update;
        updated.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
        updated.data.title = "Only the new view sees this edit".into();
        accepted(apply(&node, &updated, "edit-after-pin"));
        accepted(apply(&node, &command(&fixture, 2), "insert-after-pin"));
        let mut closed = command(&fixture, 9);
        closed.action = PullRequestAction::Close;
        closed.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
        accepted(apply(&node, &closed, "close-after-pin"));
        let current = snapshot(&node);
        let fresh = page(&node, 0, 100, None).unwrap();
        assert_eq!(
            fresh
                .pull_requests
                .iter()
                .map(|row| row.number.get())
                .collect::<Vec<_>>(),
            [1, 2, 3, 9]
        );
        assert_eq!(
            fresh.pull_requests[2].data.as_ref().unwrap().title,
            updated.data.title
        );
        assert_ne!(fresh.source_head, reference.source_head);
        let second = page(&node, first.next_after.unwrap(), 1, Some(first.source_head)).unwrap();
        let last = page(
            &node,
            second.next_after.unwrap(),
            1,
            Some(first.source_head),
        )
        .unwrap();
        assert_eq!(second.source_head, first.source_head);
        assert_eq!(last.source_head, first.source_head);
        assert_eq!(last.next_after, None);
        let mut walked = first.pull_requests;
        walked.extend(second.pull_requests);
        walked.extend(last.pull_requests);
        assert_eq!(
            walked, reference.pull_requests,
            "no duplicate, omission, newer title or newer lifecycle state"
        );
        assert_eq!(snapshot(&node).basis(), current.basis());
        node.shutdown().unwrap();

        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        let head = reopened
            .runtime()
            .block_on(reopened.authenticate_authority_head())
            .unwrap();
        reopened
            .bring_into_service(head.receipt().generation())
            .unwrap();
        assert_eq!(
            page(&reopened, 0, 100, Some(reference.source_head)).unwrap(),
            reference
        );
        assert_eq!(snapshot(&reopened).basis(), current.basis());
        reopened.shutdown().unwrap();
    }
}

#[test]
fn a_retained_pr_token_never_overrides_the_callers_current_ref_visibility() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        let fixture = fixture(&node, &scratch, format);
        accepted(apply(&node, &command(&fixture, 1), "open-first"));
        let pinned = page(&node, 0, 10, None).unwrap();
        accepted(apply(&node, &command(&fixture, 2), "open-after-pin"));
        for hidden in [source_ref(), target()] {
            let mut visibility = RefVisibility::new();
            visibility
                .push_rule(hidden.as_bytes(), &Default::default())
                .unwrap();
            let request = node.request_context();
            let redacted = node
                .runtime()
                .block_on(node.read_pull_requests_in(
                    &request,
                    &visibility,
                    0,
                    10,
                    Some(pinned.source_head),
                ))
                .unwrap();
            assert!(redacted.pull_requests.is_empty());
            assert_eq!(redacted.next_after, None);
            assert_eq!(redacted.source_head, pinned.source_head);
        }
        assert_eq!(
            page(&node, 0, 10, Some(pinned.source_head)).unwrap(),
            pinned
        );
        let cancelled = node.request_context();
        cancelled.authority().cancel();
        assert!(
            node.runtime()
                .block_on(node.read_pull_requests_in(
                    &cancelled,
                    &RefVisibility::new(),
                    0,
                    10,
                    Some(pinned.source_head)
                ))
                .is_err()
        );
        node.shutdown().unwrap();
    }
}
