use super::*;

fn args(extra: &[&str]) -> Vec<String> {
    let mut args = vec![
        "unopened-node".into(),
        "11".repeat(16),
        "22".repeat(16),
        "--trusted-local".into(),
    ];
    args.extend(extra.iter().map(|s| (*s).to_owned()));
    args
}

#[test]
fn search_preserves_literal_text_and_exact_byte_refs_in_both_hash_domains() {
    for format in ["sha1", "sha256"] {
        let bytes = b"refs/heads/topic-\xff";
        let raw = options::hex(bytes);
        let options = parse(&args(&[
            "--query",
            "[A].*é",
            "--case-sensitive",
            "--state",
            "merged",
            "--source-ref-hex",
            &raw,
            "--target-ref",
            "refs/heads/main",
            "--object-format",
            format,
            "--opened-by",
            &"33".repeat(16),
            "--limit",
            "2",
            "--max-scan",
            "3",
        ]))
        .unwrap();
        let query = options.query.query();
        assert_eq!(query.text.as_deref(), Some("[A].*é"));
        assert!(query.case_sensitive);
        assert_eq!(query.state, Some(PullRequestState::Merged));
        assert_eq!(query.source_ref.as_ref().unwrap().as_bytes(), bytes);
        assert_eq!(options.base.format.as_str(), format);
        assert_eq!((options.request.limit, options.request.max_scan), (2, 3));
    }
}

#[test]
fn search_rejects_authority_flags_ambiguous_refs_invalid_filters_and_unpinned_cursors() {
    let cases: &[&[&str]] = &[
        &["--principal", "admin"],
        &["--idempotency-key", "mutate"],
        &["--body-file", "/tmp/source"],
        &["--state", "all", "--state", "open"],
        &["--state", "pending"],
        &["--case-sensitive"],
        &["--query", ""],
        &["--query", "a\0b"],
        &["--after", "1"],
        &["--after", "01"],
        &["--max-scan", "0"],
        &["--max-scan", "1001"],
        &["--limit", "101"],
        &["--source-ref", "refs/tags/release"],
        &[
            "--source-ref",
            "refs/heads/topic",
            "--source-ref-hex",
            "726566732f68656164732f746f706963",
        ],
        &["--target-ref-hex", "FF"],
        &["--trusted-local"],
    ];
    for extra in cases {
        assert!(parse(&args(extra)).is_err(), "{extra:?}");
    }
    assert!(parse(&args(&["--query", &"é".repeat(129)])).is_err());
    let mut untrusted = args(&[]);
    untrusted.pop();
    assert!(parse(&untrusted).is_err());
}

#[test]
fn empty_partial_search_receipt_keeps_scanned_cursor_and_snapshot() {
    let options = parse(&args(&["--query", "unmatched", "--max-scan", "2"])).unwrap();
    let head = options::parse_head(&format!("alg:1:{}", "ab".repeat(32))).unwrap();
    let page = PullRequestSearchPage {
        source_head: head,
        pull_requests: vec![],
        scanned: 2,
        next_after: Some(9),
        stop: fgit_forge::pull_request_search::SearchStop::ScanLimit,
    };
    let report = receipt(&options, &page).unwrap();
    assert!(report.contains("\"scanned\":2,\"count\":0,\"complete\":false"));
    assert!(report.contains("\"stop_reason\":\"scan_limit\",\"next_after\":9"));
    assert!(report.contains(&options::head_token(head)));
    let continued = parse(&args(&[
        "--query",
        "unmatched",
        "--after",
        "9",
        "--expected-head",
        &options::head_token(head),
    ]))
    .unwrap();
    assert_eq!(continued.request.expected_head, Some(head));
}
