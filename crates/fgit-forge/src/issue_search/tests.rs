use super::*;
use crate::aggregate::{AggregateVersion, IssueNumber};
use crate::event::issue::{IssueQuery, IssueState};
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::{CANONICAL_CODEC_VERSION, PrincipalId};

fn head(byte: u8) -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(1).unwrap(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[byte; 32]).unwrap(),
    )
}
fn issue(number: u64, matching: bool) -> IssueSnapshot {
    IssueSnapshot {
        number: IssueNumber::try_new(number).unwrap(),
        version: AggregateVersion::FIRST,
        title: if matching { "hit" } else { "miss" }.into(),
        body: String::new(),
        labels: Vec::new(),
        state: IssueState::Open,
        opened_by: PrincipalId::from_bytes([1; 16]),
        last_actor: PrincipalId::from_bytes([1; 16]),
        comments: 0,
    }
}
fn query() -> CompiledIssueQuery {
    IssueQuery {
        text: Some("hit".into()),
        ..Default::default()
    }
    .compile()
    .unwrap()
}
fn request(limit: u16, max_scan: u16) -> SearchRequest {
    SearchRequest {
        after: 0,
        limit,
        max_scan,
        expected_head: None,
    }
}
fn read(rows: &[IssueSnapshot], after: u64, limit: u16) -> SourcePage {
    let remaining: Vec<_> = rows.iter().filter(|row| row.number.get() > after).collect();
    let issues: Vec<_> = remaining
        .iter()
        .take(usize::from(limit))
        .map(|row| (**row).clone())
        .collect();
    let next_after = if remaining.len() > issues.len() {
        issues.last().map(|row| row.number.get())
    } else {
        None
    };
    SourcePage {
        source_head: head(1),
        issues,
        next_after,
    }
}
fn run(rows: &[IssueSnapshot], request: SearchRequest) -> SearchPage {
    search(&query(), request, |after, limit, pin| {
        if after != 0 {
            assert_eq!(pin, Some(head(1)));
        }
        Ok::<_, &'static str>(read(rows, after, limit))
    })
    .unwrap()
}

#[test]
fn resume_after_last_scanned_never_skips_an_unexamined_match() {
    let rows = vec![
        issue(2, false),
        issue(7, true),
        issue(10, true),
        issue(99, false),
        issue(101, true),
    ];
    let first = run(&rows, request(1, 100));
    assert_eq!(first.issues[0].number.get(), 7);
    assert_eq!(first.scanned, 2);
    assert_eq!(first.next_after, Some(7));
    assert_eq!(first.stop, SearchStop::ResultLimit);
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
            .issues
            .iter()
            .map(|row| row.number.get())
            .collect::<Vec<_>>(),
        [10, 101]
    );
    assert_eq!(second.stop, SearchStop::Exhausted);
    assert_eq!(second.next_after, None);
}

#[test]
fn zero_matches_at_scan_limit_are_not_a_complete_no_match_result() {
    let rows = vec![issue(3, false), issue(8, false), issue(10, true)];
    let first = run(&rows, request(10, 2));
    assert!(first.issues.is_empty());
    assert_eq!(first.scanned, 2);
    assert_eq!(first.next_after, Some(8));
    assert_eq!(first.stop, SearchStop::ScanLimit);
    let last = run(
        &rows,
        SearchRequest {
            after: 8,
            expected_head: Some(head(1)),
            ..request(1, 1)
        },
    );
    assert_eq!(last.issues.len(), 1);
    assert_eq!(last.stop, SearchStop::Exhausted);
    assert_eq!(last.next_after, None);
}

#[test]
fn selected_head_is_reused_across_pages_and_source_errors_are_preserved() {
    let rows: Vec<_> = (1..=205).map(|n| issue(n, n == 205)).collect();
    let mut calls = 0;
    let page = search(&query(), request(2, 250), |after, limit, pin| {
        assert_eq!(pin, if calls == 0 { None } else { Some(head(1)) });
        calls += 1;
        Ok::<_, &'static str>(read(&rows, after, limit))
    })
    .unwrap();
    assert_eq!(calls, 3);
    assert_eq!(page.scanned, 205);
    assert_eq!(page.issues[0].number.get(), 205);
    for moved in [false, true] {
        let error = search(&query(), request(2, 250), |after, limit, _| {
            let mut page = read(&rows, after, limit);
            if after != 0 {
                if !moved {
                    return Err("source cancelled");
                }
                page.source_head = head(2);
            }
            Ok(page)
        })
        .unwrap_err();
        if moved {
            assert!(matches!(error, SearchError::SnapshotMoved));
        } else {
            assert!(matches!(error, SearchError::Source("source cancelled")));
        }
    }
}

#[test]
fn invalid_requests_refuse_before_read_and_malformed_pages_never_loop() {
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
            search(&query(), bad, |_, _, _| -> Result<SourcePage, &str> {
                panic!("must not read")
            })
            .is_err()
        );
    }
    for issues in [
        vec![issue(1, true), issue(1, true)],
        vec![issue(2, true), issue(1, true)],
        vec![issue(1, true), issue(2, true), issue(3, true)],
    ] {
        assert!(matches!(
            search(&query(), request(1, 2), |_, _, _| Ok::<_, &str>(
                SourcePage {
                    source_head: head(1),
                    issues: issues.clone(),
                    next_after: None,
                }
            )),
            Err(SearchError::InvalidSourcePage)
        ));
    }
    for (issues, next_after) in [
        (vec![], Some(1)),
        (vec![issue(1, true)], Some(1)),
        (vec![issue(1, true), issue(2, true)], Some(3)),
        (vec![issue(1, true), issue(u64::MAX, true)], Some(u64::MAX)),
    ] {
        assert!(matches!(
            search(&query(), request(1, 2), |_, _, _| Ok::<_, &str>(
                SourcePage {
                    source_head: head(1),
                    issues: issues.clone(),
                    next_after,
                }
            )),
            Err(SearchError::InvalidSourcePage)
        ));
    }
    let mut invalid = issue(1, false);
    invalid.comments = 1;
    assert!(matches!(
        search(&query(), request(1, 1), |_, _, _| Ok::<_, &str>(
            SourcePage {
                source_head: head(1),
                issues: vec![invalid.clone()],
                next_after: None,
            }
        )),
        Err(SearchError::InvalidSnapshot(_))
    ));
}

#[test]
fn empty_tail_and_exact_limits_are_exhausted_not_falsely_partial() {
    for rows in [Vec::new(), vec![issue(1, true)], vec![issue(1, false)]] {
        let page = run(&rows, request(1, 1));
        assert_eq!(page.stop, SearchStop::Exhausted);
        assert_eq!(page.next_after, None);
    }
    let page = run(
        &[issue(u64::MAX, true)],
        SearchRequest {
            after: u64::MAX,
            expected_head: Some(head(1)),
            ..request(1, 1)
        },
    );
    assert!(page.issues.is_empty());
    assert_eq!(page.scanned, 0);
}

#[test]
fn every_small_match_pattern_paginates_like_the_scalar_filter() {
    for mask in 0_u32..256 {
        let rows: Vec<_> = (0..8)
            .map(|n| issue(3 * n + 1, mask & (1 << n) != 0))
            .collect();
        let expected: Vec<_> = rows
            .iter()
            .filter(|row| row.title == "hit")
            .map(|row| row.number)
            .collect();
        for limit in 1..=4 {
            for max_scan in 1..=5 {
                let mut request = request(limit, max_scan);
                let mut actual = Vec::new();
                let mut calls = 0;
                loop {
                    let page = run(&rows, request);
                    calls += 1;
                    assert!(calls <= 8, "continuation must make progress");
                    actual.extend(page.issues.iter().map(|row| row.number));
                    let Some(after) = page.next_after else {
                        break;
                    };
                    assert!(after > request.after);
                    request.after = after;
                    request.expected_head = Some(page.source_head);
                }
                assert_eq!(
                    actual, expected,
                    "mask={mask}, limit={limit}, max_scan={max_scan}"
                );
            }
        }
    }
}
