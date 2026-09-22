use super::*;
use fgit_forge::aggregate::{AggregateVersion, IssueNumber};
use fgit_forge::event::issue::IssueSnapshot;
use fgit_forge::issue_search::{SearchPage, SearchStop};

fn args(extra: &[&str]) -> Vec<String> {
    let mut args: Vec<_> = [
        "unused-storage",
        "01010101010101010101010101010101",
        "02020202020202020202020202020202",
        "--trusted-local",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    args.extend(extra.iter().map(|s| (*s).to_owned()));
    args
}

#[test]
fn parses_filters_and_reuses_exact_read_identity_contract() {
    let options = parse(&args(&[
        "--state",
        "closed",
        "--query",
        "HTTP",
        "--case-sensitive",
        "--label",
        "z",
        "--label",
        "a",
        "--opened-by",
        "03030303030303030303030303030303",
        "--limit",
        "7",
        "--max-scan",
        "2",
        "--object-format",
        "sha256",
    ]))
    .unwrap();
    assert_eq!(options.max_scan, 2);
    assert_eq!(options.query.query().labels, ["a", "z"]);
    assert_eq!(options.query.query().state, Some(IssueState::Closed));
    assert!(options.query.query().case_sensitive);
    assert_eq!(
        options.query.query().opened_by,
        Some(PrincipalId::from_bytes([3; 16]))
    );
    assert_eq!(options.base.format.as_str(), "sha256");
    let Operation::Read(read) = &options.base.operation else {
        panic!("read");
    };
    assert_eq!(read.limit, 7);
    assert_eq!(read.number, None);
    assert!(
        options
            .query
            .matches(&IssueSnapshot {
                number: IssueNumber::FIRST,
                version: AggregateVersion::FIRST,
                title: "HTTP bug".into(),
                body: String::new(),
                labels: vec!["a".into(), "z".into()],
                state: IssueState::Closed,
                opened_by: PrincipalId::from_bytes([3; 16]),
                last_actor: PrincipalId::from_bytes([4; 16]),
                comments: 0,
            })
            .unwrap()
    );
}

#[test]
fn rejects_inapplicable_duplicate_and_unbounded_inputs_before_node_open() {
    for flags in [
        vec!["--state", "unknown"],
        vec!["--query", ""],
        vec!["--query", "a\0b"],
        vec!["--label", "bug", "--label", "bug"],
        vec!["--max-scan", "0"],
        vec!["--max-scan", "1001"],
        vec!["--max-scan", "01"],
        vec!["--limit", "0"],
        vec!["--limit", "101"],
        vec!["--case-sensitive"],
        vec!["--case-sensitive", "--case-sensitive"],
        vec!["--query", "a", "--query", "b"],
        vec!["--state", "all", "--state", "all"],
        vec!["--opened-by", "bad"],
        vec!["--trusted-local"],
        vec!["--after", "1"],
        vec!["--principal", "03030303030303030303030303030303"],
        vec!["--idempotency-key", "read-has-no-key"],
        vec!["--after-version", "1"],
        vec!["--query"],
    ] {
        assert!(parse(&args(&flags)).is_err(), "{flags:?}");
    }
    assert!(parse(&args(&["--query", &"a".repeat(257)])).is_err());
    let mut untrusted = args(&[]);
    untrusted.pop();
    assert!(parse(&untrusted).is_err());
    let defaults = parse(&args(&[])).unwrap();
    assert_eq!(defaults.max_scan, 1000);
    assert_eq!(defaults.query.query(), &IssueQuery::default());
}

#[test]
fn continuation_and_partial_empty_receipt_are_explicit() {
    let token = format!("alg:1:{}", "ab".repeat(32));
    let options = parse(&args(&[
        "--after",
        "7",
        "--expected-head",
        &token,
        "--query",
        "<script>\"",
        "--max-scan",
        "2",
    ]))
    .unwrap();
    let Operation::Read(read) = &options.base.operation else {
        panic!("read");
    };
    let mut page = SearchPage {
        source_head: read.expected_head.unwrap(),
        issues: Vec::new(),
        scanned: 2,
        next_after: Some(9),
        stop: SearchStop::ScanLimit,
    };
    let report =
        super::super::output::search(&options.base, read, &options.query, options.max_scan, &page)
            .unwrap();
    assert!(report.contains("\"type\":\"issue_search_page\""));
    assert!(report.contains("\"complete\":false"));
    assert!(report.contains("\"has_more_candidates\":true"));
    assert!(report.contains("\"stop_reason\":\"scan_limit\""));
    assert!(report.contains("\"next_after\":9"));
    assert!(report.contains("\"count\":0"));
    assert!(report.contains(&format!(
        "\"text\":{}",
        crate::publication_support::quote("<script>\"")
    )));
    assert!(report.contains(&format!("\"snapshot_token\":\"{token}\"")));
    page.stop = SearchStop::Exhausted;
    assert!(
        super::super::output::search(&options.base, read, &options.query, options.max_scan, &page)
            .is_err()
    );
    page.next_after = None;
    assert!(
        super::super::output::search(&options.base, read, &options.query, options.max_scan, &page)
            .unwrap()
            .contains("\"complete\":true")
    );
}
