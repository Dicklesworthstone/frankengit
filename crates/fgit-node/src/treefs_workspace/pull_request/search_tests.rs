//! Real file-backed PR publications, exact retained-head reads, and disclosure
//! through the same native source reader used by ordinary list/show adapters.

use super::*;
use fgit_forge::event::pull_request_labels::PullRequestLabelsCommand;
use fgit_forge::pull_request_search::{
    PullRequestQuery, PullRequestState, SearchError, SearchRequest, SearchStop,
};

fn request(limit: u16, max_scan: u16) -> SearchRequest {
    SearchRequest {
        after: 0,
        limit,
        max_scan,
        expected_head: None,
    }
}
fn search(
    node: &OneNode,
    query: &PullRequestQuery,
    search_request: SearchRequest,
) -> Result<PullRequestSearchPage, PullRequestSearchRefusal> {
    let context = node.request_context();
    let compiled = query.clone().compile().unwrap();
    node.runtime().block_on(node.search_pull_requests_in(
        &context,
        &RefVisibility::new(),
        &compiled,
        search_request,
    ))
}

fn labels(node: &OneNode, number: u64, previous: Option<AggregateVersion>, label: &str) {
    let command = PullRequestLabelsCommand {
        number: PullRequestNumber::try_new(number).unwrap(),
        expected_version: previous.map_or(ExpectedVersion::NewStream, ExpectedVersion::Exactly),
        labels: vec![label.into()],
    };
    let context = node.request_context();
    accepted(
        node.runtime()
            .block_on(node.admit_pull_request_labels_durable_in(
                &context,
                &session(&format!("search-label-{number}-{label}")),
                &command,
                AdmissionLimits::default(),
            )),
    );
}

#[test]
fn native_search_resumes_after_misses_and_keeps_original_metadata_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        let fixture = fixture(&node, &scratch, format);
        for (number, title) in [(9, "Needle later"), (3, "Needle first"), (1, "Unrelated")] {
            let mut open = command(&fixture, number);
            open.data.title = title.into();
            accepted(apply(&node, &open, &format!("search-open-{number}")));
        }
        labels(&node, 9, None, "before");
        let query = PullRequestQuery {
            state: Some(PullRequestState::Open),
            opened_by: Some(principal()),
            source_ref: Some(source_ref()),
            target_ref: Some(target()),
            text: Some("needle".into()),
            case_sensitive: false,
        };
        let first = search(&node, &query, request(1, 1)).unwrap();
        assert!(first.pull_requests.is_empty());
        assert_eq!(first.scanned, 1);
        assert_eq!(first.next_after, Some(1));
        assert_eq!(first.stop, SearchStop::ScanLimit);
        let second = search(
            &node,
            &query,
            SearchRequest {
                after: first.next_after.unwrap(),
                expected_head: Some(first.source_head),
                ..request(1, 100)
            },
        )
        .unwrap();
        assert_eq!(second.pull_requests[0].number.get(), 3);
        assert_eq!(second.scanned, 1);
        assert_eq!(second.next_after, Some(3));
        assert_eq!(second.stop, SearchStop::ResultLimit);

        // An insertion, metadata edit, and lifecycle change happen after the
        // search was pinned. Each would change a fresh matching result.
        let mut inserted = command(&fixture, 2);
        inserted.data.title = "Needle inserted later".into();
        accepted(apply(&node, &inserted, "search-insert-after-pin"));
        let mut edited = command(&fixture, 3);
        edited.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
        edited.action = PullRequestAction::Update;
        edited.data.title = "Title no longer matches".into();
        accepted(apply(&node, &edited, "search-edit-after-pin"));
        let mut closed = command(&fixture, 9);
        closed.data.title = "Needle later".into();
        closed.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
        closed.action = PullRequestAction::Close;
        accepted(apply(&node, &closed, "search-close-after-pin"));
        labels(&node, 9, Some(AggregateVersion::FIRST), "after");
        let before_read = snapshot(&node);
        let continuation = SearchRequest {
            after: second.next_after.unwrap(),
            expected_head: Some(first.source_head),
            ..request(100, 1000)
        };
        let retained = search(&node, &query, continuation).unwrap();
        assert_eq!(retained.source_head, first.source_head);
        assert_eq!(retained.pull_requests.len(), 1);
        assert_eq!(retained.pull_requests[0].number.get(), 9);
        assert_eq!(retained.pull_requests[0].labels, ["before"]);
        assert_eq!(
            retained.pull_requests[0].labels_version,
            Some(AggregateVersion::FIRST)
        );
        assert_eq!(retained.pull_requests[0].labels_actor, Some(principal()));
        assert_eq!(
            retained.pull_requests[0].data.as_ref().unwrap().title,
            "Needle later"
        );
        assert!(retained.is_complete());
        assert_eq!(retained.next_after, None);
        let fresh = search(&node, &query, request(100, 1000)).unwrap();
        assert_eq!(
            fresh
                .pull_requests
                .iter()
                .map(|row| row.number.get())
                .collect::<Vec<_>>(),
            [2]
        );
        assert_ne!(fresh.source_head, first.source_head);
        let current_closed = search(
            &node,
            &PullRequestQuery {
                state: Some(PullRequestState::Closed),
                ..query.clone()
            },
            request(100, 1000),
        )
        .unwrap();
        assert_eq!(current_closed.source_head, fresh.source_head);
        assert_eq!(current_closed.pull_requests.len(), 1);
        assert_eq!(current_closed.pull_requests[0].labels, ["after"]);
        assert_eq!(
            current_closed.pull_requests[0].labels_version,
            AggregateVersion::try_new(2)
        );
        assert_eq!(snapshot(&node).basis(), before_read.basis());
        node.shutdown().unwrap();

        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        let head = reopened
            .runtime()
            .block_on(reopened.authenticate_authority_head())
            .unwrap();
        reopened
            .bring_into_service(head.receipt().generation())
            .unwrap();
        assert_eq!(search(&reopened, &query, continuation).unwrap(), retained);
        assert_eq!(
            search(&reopened, &query, request(100, 1000)).unwrap(),
            fresh
        );
        assert_eq!(snapshot(&reopened).basis(), before_read.basis());
        reopened.shutdown().unwrap();
    }
}

#[test]
fn search_never_discloses_hidden_candidates_and_preserves_typed_cancellation() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        let fixture = fixture(&node, &scratch, format);
        accepted(apply(&node, &command(&fixture, 1), "search-visible-pr"));
        let query = PullRequestQuery::default();
        let visible = search(&node, &query, request(10, 10)).unwrap();
        assert_eq!(visible.pull_requests.len(), 1);
        accepted(apply(&node, &command(&fixture, 2), "search-newer-pr"));
        let compiled = query.compile().unwrap();
        for hidden in [source_ref(), target()] {
            let mut visibility = RefVisibility::new();
            visibility
                .push_rule(hidden.as_bytes(), &Default::default())
                .unwrap();
            for pin in [None, Some(visible.source_head)] {
                let context = node.request_context();
                let redacted = node
                    .runtime()
                    .block_on(node.search_pull_requests_in(
                        &context,
                        &visibility,
                        &compiled,
                        SearchRequest {
                            expected_head: pin,
                            ..request(10, 10)
                        },
                    ))
                    .unwrap();
                assert!(redacted.pull_requests.is_empty());
                assert_eq!(redacted.scanned, 0);
                assert_eq!(redacted.next_after, None);
                assert!(redacted.is_complete());
                if let Some(pin) = pin {
                    assert_eq!(redacted.source_head, pin);
                }
            }
        }
        let cancelled = node.request_context();
        cancelled.authority().cancel();
        let error = node
            .runtime()
            .block_on(node.search_pull_requests_in(
                &cancelled,
                &RefVisibility::new(),
                &compiled,
                request(10, 10),
            ))
            .unwrap_err();
        assert!(matches!(error, SearchError::Source(error) if !error.is_snapshot_unavailable()));
        // Invalid search shapes refuse before the cancelled authority context
        // is consulted; they must not become storage or token-expiry errors.
        assert!(matches!(
            node.runtime().block_on(node.search_pull_requests_in(
                &cancelled,
                &RefVisibility::new(),
                &compiled,
                request(0, 10),
            )),
            Err(SearchError::InvalidLimits)
        ));
        assert!(matches!(
            node.runtime().block_on(node.search_pull_requests_in(
                &cancelled,
                &RefVisibility::new(),
                &compiled,
                SearchRequest {
                    after: 1,
                    ..request(10, 10)
                },
            )),
            Err(SearchError::SnapshotRequired)
        ));
        node.shutdown().unwrap();
    }
}

#[test]
fn real_merged_search_keeps_metadata_and_does_not_invent_merge_only_title_or_opener() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for metadata in [false, true] {
            let scratch = Scratch::new();
            let node = node(&scratch, format);
            let fixture = fixture(&node, &scratch, format);
            if metadata {
                accepted(apply(&node, &command(&fixture, 1), "search-open-merged"));
            }
            let candidate = node
                .put_git_object(
                    GitObjectKind::Commit,
                    commit(
                        fixture.tree,
                        &[fixture.data.target_tip, fixture.data.source_tip],
                        "search merge",
                    ),
                )
                .unwrap()
                .identity();
            let intent = NativeMergeIntent::new(
                PullRequestNumber::FIRST,
                if metadata {
                    ExpectedVersion::Exactly(AggregateVersion::FIRST)
                } else {
                    ExpectedVersion::NewStream
                },
                NativeMerge {
                    source_ref: source_ref(),
                    source_tip: fixture.data.source_tip,
                    base_tip: fixture.base,
                    target_ref: target(),
                    target_tip_before: fixture.data.target_tip,
                    merge_commit: candidate,
                },
            )
            .unwrap();
            let context = node.request_context();
            let terminal = node
                .runtime()
                .block_on(node.admit_native_merge_durable_in(
                    &context,
                    &session("search-merge"),
                    &intent,
                    AdmissionLimits::default(),
                    MergeObjectLimits::default(),
                ))
                .unwrap();
            assert!(matches!(
                terminal.outcome,
                DecisionOutcome::Committed { .. }
            ));
            let query = PullRequestQuery {
                state: Some(PullRequestState::Merged),
                source_ref: Some(source_ref()),
                target_ref: Some(target()),
                ..Default::default()
            };
            let page = search(&node, &query, request(10, 10)).unwrap();
            assert_eq!(page.pull_requests.len(), 1);
            assert_eq!(page.pull_requests[0].data.is_some(), metadata);
            assert_eq!(
                page.pull_requests[0].opened_by,
                metadata.then_some(principal())
            );
            for filter in [
                PullRequestQuery {
                    text: Some("native pull".into()),
                    ..query.clone()
                },
                PullRequestQuery {
                    opened_by: Some(principal()),
                    ..query.clone()
                },
            ] {
                let filtered = search(&node, &filter, request(10, 10)).unwrap();
                assert_eq!(filtered.pull_requests.len(), usize::from(metadata));
                assert_eq!(filtered.scanned, 1);
                assert!(filtered.is_complete());
            }
            assert!(
                search(
                    &node,
                    &PullRequestQuery {
                        state: Some(PullRequestState::Open),
                        ..Default::default()
                    },
                    request(10, 10)
                )
                .unwrap()
                .pull_requests
                .is_empty()
            );
            node.shutdown().unwrap();
        }
    }
}
