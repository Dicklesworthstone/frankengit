use super::*;
use crate::aggregate::AggregateVersion;
use crate::event::NativeMerge;
use crate::event::pull_request::NativePullRequestEvent;
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::{CANONICAL_CODEC_VERSION, GitHashAlgorithm, GitOid};
use std::future::ready;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

#[derive(Clone, Debug, Eq, PartialEq)]
struct Row {
    number: PullRequestNumber,
    event: ForgeEvent,
    data: Option<PullRequestData>,
    opened_by: Option<PrincipalId>,
    last_metadata_actor: Option<PrincipalId>,
}
fn describe(row: &Row) -> SearchDocument<'_> {
    SearchDocument {
        number: row.number,
        event: &row.event,
        data: row.data.as_ref(),
        opened_by: row.opened_by,
        last_metadata_actor: row.last_metadata_actor,
    }
}
fn actor(byte: u8) -> PrincipalId {
    PrincipalId::from_bytes([byte; 16])
}
fn head(byte: u8) -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(1).unwrap(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[byte; 32]).unwrap(),
    )
}
fn oid(format: GitHashAlgorithm, digit: &str) -> GitOid {
    GitOid::from_hex(format, &digit.repeat(format.digest_len() * 2)).unwrap()
}
fn row(number: u64, action: PullRequestAction, format: GitHashAlgorithm) -> Row {
    let number = PullRequestNumber::try_new(number).unwrap();
    let data = PullRequestData {
        source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
        target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
        source_tip: oid(format, "a"),
        target_tip: oid(format, "b"),
        title: "Fix HTTP".into(),
        body: "café\nbody needle".into(),
    };
    Row {
        number,
        event: ForgeEvent {
            aggregate: AggregateId::PullRequest(number),
            version: if action == PullRequestAction::Open {
                AggregateVersion::FIRST
            } else {
                AggregateVersion::try_new(2).unwrap()
            },
            payload: ForgeEventPayload::PullRequestChangedNative(NativePullRequestEvent {
                action,
                actor: actor(1),
                data: data.clone(),
            }),
        },
        data: Some(data),
        opened_by: Some(actor(1)),
        last_metadata_actor: Some(actor(1)),
    }
}
fn set_title(row: &mut Row, title: &str) {
    row.data.as_mut().unwrap().title = title.into();
    if let ForgeEventPayload::PullRequestChangedNative(change) = &mut row.event.payload {
        change.data.title = title.into();
    }
}
fn merged(format: GitHashAlgorithm, metadata: bool) -> Row {
    let mut row = row(7, PullRequestAction::Open, format);
    let data = row.data.as_ref().unwrap();
    row.event.payload = ForgeEventPayload::MergeCommittedNative(NativeMerge {
        source_ref: data.source_ref.clone(),
        source_tip: data.source_tip,
        base_tip: oid(format, "c"),
        target_ref: data.target_ref.clone(),
        target_tip_before: data.target_tip,
        merge_commit: oid(format, "d"),
    });
    row.event.version = AggregateVersion::try_new(2).unwrap();
    if !metadata {
        row.data = None;
        row.opened_by = None;
        row.last_metadata_actor = None;
    }
    row
}
fn matches(query: PullRequestQuery, row: &Row) -> bool {
    query.compile().unwrap().matches(describe(row)).unwrap()
}

// These engine fixtures return only Ready futures. One safe poll verifies the
// entire bounded engine without importing a foreign runtime into forge.
fn complete<F: Future>(future: F) -> F::Output {
    struct Noop;
    impl Wake for Noop {
        fn wake(self: Arc<Self>) {}
    }
    let waker = Waker::from(Arc::new(Noop));
    let mut context = Context::from_waker(&waker);
    match std::pin::pin!(future).as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("in-memory source unexpectedly suspended"),
    }
}
fn request(limit: u16, max_scan: u16) -> SearchRequest {
    SearchRequest {
        after: 0,
        limit,
        max_scan,
        expected_head: None,
    }
}
fn read(rows: &[Row], after: u64, limit: u16) -> SourcePage<Row> {
    let mut remaining = rows.iter().filter(|row| row.number.get() > after);
    let pull_requests: Vec<_> = remaining
        .by_ref()
        .take(usize::from(limit))
        .cloned()
        .collect();
    let next_after = if remaining.next().is_some() {
        pull_requests.last().map(|row| row.number.get())
    } else {
        None
    };
    SourcePage {
        source_head: head(1),
        pull_requests,
        next_after,
    }
}
fn run(rows: &[Row], request: SearchRequest) -> SearchPage<Row> {
    let query = PullRequestQuery {
        text: Some("hit".into()),
        ..Default::default()
    }
    .compile()
    .unwrap();
    complete(search(
        &query,
        request,
        |after, limit, pin| {
            if after != 0 {
                assert_eq!(pin, Some(head(1)));
            }
            ready(Ok::<_, &'static str>(read(rows, after, limit)))
        },
        describe,
    ))
    .unwrap()
}

#[test]
fn conjunction_uses_exact_branches_original_opener_and_native_lifecycle() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for action in [
            PullRequestAction::Open,
            PullRequestAction::Update,
            PullRequestAction::Reopen,
        ] {
            let row = row(1, action, format);
            let query = PullRequestQuery {
                state: Some(PullRequestState::Open),
                opened_by: Some(actor(1)),
                source_ref: Some(RefName::try_new(b"refs/heads/topic").unwrap()),
                target_ref: Some(RefName::try_new(b"refs/heads/main").unwrap()),
                text: Some("HTTP".into()),
                case_sensitive: true,
            };
            assert!(matches(query.clone(), &row));
            for changed in [
                PullRequestQuery {
                    state: Some(PullRequestState::Closed),
                    ..query.clone()
                },
                PullRequestQuery {
                    opened_by: Some(actor(2)),
                    ..query.clone()
                },
                PullRequestQuery {
                    source_ref: Some(RefName::try_new(b"refs/heads/topic-two").unwrap()),
                    ..query.clone()
                },
                PullRequestQuery {
                    target_ref: Some(RefName::try_new(b"refs/heads/main-two").unwrap()),
                    ..query.clone()
                },
            ] {
                assert!(!matches(changed, &row));
            }
        }
        let closed = row(2, PullRequestAction::Close, format);
        assert!(matches(
            PullRequestQuery {
                state: Some(PullRequestState::Closed),
                ..Default::default()
            },
            &closed
        ));
        assert!(!matches(
            PullRequestQuery {
                state: Some(PullRequestState::Open),
                ..Default::default()
            },
            &closed
        ));
        let mut edited = row(3, PullRequestAction::Update, format);
        if let ForgeEventPayload::PullRequestChangedNative(change) = &mut edited.event.payload {
            change.actor = actor(2);
        }
        edited.last_metadata_actor = Some(actor(2));
        assert!(matches(
            PullRequestQuery {
                opened_by: Some(actor(1)),
                ..Default::default()
            },
            &edited
        ));
        assert!(!matches(
            PullRequestQuery {
                opened_by: Some(actor(2)),
                ..Default::default()
            },
            &edited
        ));
    }
}

#[test]
fn literals_fold_ascii_only_and_never_join_title_to_body() {
    let row = row(1, PullRequestAction::Open, GitHashAlgorithm::Sha1);
    for (text, sensitive, expected) in [
        ("http", false, true),
        ("http", true, false),
        ("café", false, true),
        ("CAFÉ", false, false),
        ("body needle", true, true),
        ("HTTPcafé", false, false),
        ("Fix HTTPcafé", false, false),
    ] {
        assert_eq!(
            matches(
                PullRequestQuery {
                    text: Some(text.into()),
                    case_sensitive: sensitive,
                    ..Default::default()
                },
                &row
            ),
            expected
        );
    }
    let mut adversarial = row.clone();
    let body = format!("{}b", "a".repeat(65_535));
    adversarial.data.as_mut().unwrap().body.clone_from(&body);
    if let ForgeEventPayload::PullRequestChangedNative(change) = &mut adversarial.event.payload {
        change.data.body = body;
    }
    assert!(matches(
        PullRequestQuery {
            text: Some(format!("{}b", "a".repeat(255))),
            ..Default::default()
        },
        &adversarial
    ));
    assert!(!matches(
        PullRequestQuery {
            text: Some(format!("{}c", "a".repeat(255))),
            ..Default::default()
        },
        &adversarial
    ));
}

#[test]
fn merged_metadata_remains_searchable_and_merge_only_never_invents_it() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let with_metadata = merged(format, true);
        let merge_only = merged(format, false);
        let query = PullRequestQuery {
            state: Some(PullRequestState::Merged),
            source_ref: Some(RefName::try_new(b"refs/heads/topic").unwrap()),
            target_ref: Some(RefName::try_new(b"refs/heads/main").unwrap()),
            ..Default::default()
        };
        assert!(matches(query.clone(), &with_metadata));
        assert!(matches(query.clone(), &merge_only));
        for query in [
            PullRequestQuery {
                text: Some("http".into()),
                ..query.clone()
            },
            PullRequestQuery {
                opened_by: Some(actor(1)),
                ..query
            },
        ] {
            assert!(matches(query.clone(), &with_metadata));
            assert!(!matches(query, &merge_only));
        }
    }
}

#[test]
fn malformed_snapshots_refuse_even_when_inexpensive_filters_do_not_match() {
    let query = PullRequestQuery {
        state: Some(PullRequestState::Closed),
        ..Default::default()
    }
    .compile()
    .unwrap();
    let original = row(1, PullRequestAction::Open, GitHashAlgorithm::Sha1);
    let mut mismatched = original.clone();
    mismatched.data.as_mut().unwrap().title = "substituted title".into();
    let mut no_opener = original.clone();
    no_opener.opened_by = None;
    let mut wrong_aggregate = original.clone();
    wrong_aggregate.number = PullRequestNumber::try_new(2).unwrap();
    let mut invalid_text = original.clone();
    set_title(&mut invalid_text, "bad\ntext");
    let mut invented_opener = merged(GitHashAlgorithm::Sha1, false);
    invented_opener.opened_by = Some(actor(1));
    let mut different_merge = merged(GitHashAlgorithm::Sha1, true);
    different_merge.data.as_mut().unwrap().source_tip = oid(GitHashAlgorithm::Sha1, "f");
    for bad in [
        mismatched,
        no_opener,
        wrong_aggregate,
        invalid_text,
        invented_opener,
        different_merge,
    ] {
        assert!(query.matches(describe(&bad)).is_err(), "{bad:?}");
    }
}

#[test]
fn invalid_predicates_are_bounded_by_utf8_bytes_and_branch_namespace() {
    assert!(
        PullRequestQuery {
            case_sensitive: true,
            ..Default::default()
        }
        .compile()
        .is_err()
    );
    for text in [
        String::new(),
        "a\0b".into(),
        "a".repeat(257),
        "é".repeat(129),
    ] {
        assert!(
            PullRequestQuery {
                text: Some(text),
                ..Default::default()
            }
            .compile()
            .is_err()
        );
    }
    assert!(
        PullRequestQuery {
            text: Some("é".repeat(128)),
            ..Default::default()
        }
        .compile()
        .is_ok()
    );
    for reference in [b"refs/tags/main".as_slice(), b"refs/remotes/origin/main"] {
        let reference = Some(RefName::try_new(reference).unwrap());
        assert!(
            PullRequestQuery {
                source_ref: reference.clone(),
                ..Default::default()
            }
            .compile()
            .is_err()
        );
        assert!(
            PullRequestQuery {
                target_ref: reference,
                ..Default::default()
            }
            .compile()
            .is_err()
        );
    }
}

#[test]
fn resume_cursor_advances_after_examined_candidates_without_skipping_matches() {
    let rows: Vec<_> = [
        (2, "miss"),
        (7, "hit"),
        (10, "hit"),
        (99, "miss"),
        (101, "hit"),
    ]
    .into_iter()
    .map(|(number, title)| {
        let mut row = row(number, PullRequestAction::Open, GitHashAlgorithm::Sha1);
        set_title(&mut row, title);
        row
    })
    .collect();
    let first = run(&rows, request(1, 100));
    assert_eq!(first.pull_requests[0].number.get(), 7);
    assert_eq!(first.scanned, 2);
    assert_eq!(first.next_after, Some(7));
    assert_eq!(first.stop, SearchStop::ResultLimit);
    assert!(!first.is_complete());
    let second = run(
        &rows,
        SearchRequest {
            after: 7,
            expected_head: Some(first.source_head),
            ..request(3, 100)
        },
    );
    assert_eq!(
        second
            .pull_requests
            .iter()
            .map(|row| row.number.get())
            .collect::<Vec<_>>(),
        [10, 101]
    );
    assert_eq!(second.next_after, None);
    assert!(second.is_complete());
    let limited = run(&rows, request(10, 1));
    assert!(limited.pull_requests.is_empty());
    assert_eq!(limited.scanned, 1);
    assert_eq!(limited.next_after, Some(2));
    assert_eq!(limited.stop, SearchStop::ScanLimit);
}

#[test]
fn one_snapshot_is_reused_and_later_source_failures_discard_matches() {
    let rows: Vec<_> = (1..=205)
        .map(|number| {
            let mut row = row(number, PullRequestAction::Open, GitHashAlgorithm::Sha1);
            set_title(&mut row, if number == 205 { "hit" } else { "miss" });
            row
        })
        .collect();
    let query = PullRequestQuery {
        text: Some("hit".into()),
        ..Default::default()
    }
    .compile()
    .unwrap();
    let mut calls = 0;
    let page = complete(search(
        &query,
        request(2, 250),
        |after, limit, pin| {
            assert_eq!(pin, if calls == 0 { None } else { Some(head(1)) });
            calls += 1;
            ready(Ok::<_, &'static str>(read(&rows, after, limit)))
        },
        describe,
    ))
    .unwrap();
    assert_eq!(calls, 3);
    assert_eq!(page.scanned, 205);
    assert_eq!(page.pull_requests[0].number.get(), 205);
    for moved in [false, true] {
        let error = complete(search(
            &query,
            request(2, 250),
            |after, limit, _| {
                let mut page = read(&rows, after, limit);
                if after == 0 {
                    set_title(&mut page.pull_requests[0], "hit");
                }
                if after != 0 {
                    if !moved {
                        return ready(Err("source cancelled"));
                    }
                    page.source_head = head(2);
                }
                ready(Ok(page))
            },
            describe,
        ))
        .unwrap_err();
        if moved {
            assert!(matches!(error, SearchError::SnapshotMoved));
        } else {
            assert!(matches!(error, SearchError::Source("source cancelled")));
        }
    }
}

#[test]
fn malformed_pages_and_unpinned_continuations_refuse_without_extra_reads() {
    let query = PullRequestQuery::default().compile().unwrap();
    for bad in [
        request(0, 1),
        request(101, 1),
        request(1, 0),
        request(1, 1001),
        SearchRequest {
            after: 1,
            ..request(1, 1)
        },
    ] {
        assert!(
            complete(search(
                &query,
                bad,
                |_, _, _| -> std::future::Ready<Result<SourcePage<Row>, &'static str>> {
                    panic!("must refuse before reading")
                },
                describe
            ))
            .is_err()
        );
    }
    let first = row(1, PullRequestAction::Open, GitHashAlgorithm::Sha1);
    let second = row(2, PullRequestAction::Open, GitHashAlgorithm::Sha1);
    for (rows, continuation) in [
        (vec![], Some(1)),
        (vec![first.clone()], Some(1)),
        (vec![second.clone(), first.clone()], None),
        (vec![first.clone(), first.clone()], None),
        (vec![first.clone(), second.clone()], Some(1)),
        (vec![first.clone(), second.clone()], Some(u64::MAX)),
        (vec![first.clone(), second.clone(), second.clone()], None),
    ] {
        let error = complete(search(
            &query,
            request(2, 2),
            |_, _, _| {
                ready(Ok::<_, &'static str>(SourcePage {
                    source_head: head(1),
                    pull_requests: rows.clone(),
                    next_after: continuation,
                }))
            },
            describe,
        ))
        .unwrap_err();
        assert!(matches!(error, SearchError::InvalidSourcePage));
    }
    let error = complete(search(
        &query,
        SearchRequest {
            after: 1,
            expected_head: Some(head(1)),
            ..request(2, 2)
        },
        |_, _, _| {
            ready(Ok::<_, &'static str>(SourcePage {
                source_head: head(1),
                pull_requests: vec![first.clone()],
                next_after: None,
            }))
        },
        describe,
    ))
    .unwrap_err();
    assert!(matches!(error, SearchError::InvalidSourcePage));
    let empty = run(&[], request(1, 1));
    assert_eq!(empty.scanned, 0);
    assert!(empty.is_complete());
    assert_eq!(empty.next_after, None);
}

#[test]
fn maximum_scan_uses_ten_bounded_pages_and_keeps_empty_result_resumable() {
    let rows: Vec<_> = (1..=1001)
        .map(|number| row(number, PullRequestAction::Open, GitHashAlgorithm::Sha1))
        .collect();
    let query = PullRequestQuery {
        text: Some("absent".into()),
        ..Default::default()
    }
    .compile()
    .unwrap();
    let mut calls = 0;
    let page = complete(search(
        &query,
        request(MAX_RESULTS, MAX_SCAN),
        |after, limit, _| {
            assert_eq!(limit, MAX_RESULTS);
            calls += 1;
            ready(Ok::<_, &'static str>(read(&rows, after, limit)))
        },
        describe,
    ))
    .unwrap();
    assert_eq!(calls, 10);
    assert!(page.pull_requests.is_empty());
    assert_eq!(page.scanned, MAX_SCAN);
    assert_eq!(page.next_after, Some(1000));
    assert_eq!(page.stop, SearchStop::ScanLimit);
}
