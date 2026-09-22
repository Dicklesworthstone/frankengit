use super::super::{
    Status,
    request::{Operation, Request},
};
use super::*;
use fgit_forge::issue_search::SearchStop;
use fgit_wire::smart_http::{HttpLimits, head};

#[test]
fn search_post_is_read_only_and_rejects_get_query_and_wrong_media() {
    let wire = b"POST /repo.git/api/v1/issues/search HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\n\r\n";
    let head = head::parse(wire, HttpLimits::default()).unwrap().unwrap();
    let request = Request::parse(&head).unwrap().unwrap();
    assert!(matches!(request.operation, Operation::Search));
    assert!(!request.is_mutation());
    assert_eq!(request.repository_route, "/repo.git");
    assert!(
        request
            .command(b"expected_version=0&title=forged&body=x")
            .is_err()
    );
    for request in [
        "GET /repo.git/api/v1/issues/search HTTP/1.1\r\nHost: local\r\n\r\n",
        "POST /repo.git/api/v1/issues/search?query=x HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\n\r\n",
        "POST /repo.git/api/v1/issues/search HTTP/1.1\r\nHost: local\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n",
    ] {
        let head = head::parse(request.as_bytes(), HttpLimits::default())
            .unwrap()
            .unwrap();
        assert!(Request::parse(&head).is_err());
    }
}

#[test]
fn form_search_preserves_literal_bytes_and_conjoins_filters() {
    let token = format!("alg:1:{}", "ab".repeat(32));
    let body = format!(
        "query=HTTP%2B%25%0A%C3%A9&state=closed&label=z&label=a&case_sensitive=true&opened_by={}&after=7&expected_head={token}&limit=2&max_scan=1",
        "03".repeat(16)
    );
    let (query, request) = parse(body.as_bytes()).unwrap();
    assert_eq!(query.query().text.as_deref(), Some("HTTP+%\né"));
    assert_eq!(query.query().labels, ["a", "z"]);
    assert_eq!(query.query().state, Some(IssueState::Closed));
    assert!(query.query().case_sensitive);
    assert_eq!(
        query.query().opened_by,
        Some(PrincipalId::from_bytes([3; 16]))
    );
    assert_eq!(request.after, 7);
    assert_eq!(request.limit, 2);
    assert_eq!(request.max_scan, 1);
    assert_eq!(
        request.expected_head,
        Some(request::parse_head_token(&token).unwrap())
    );
    let (query, request) = parse(b"").unwrap();
    assert_eq!(query.query(), &IssueQuery::default());
    assert_eq!(request.limit, 50);
    assert_eq!(request.max_scan, 1000);
}

#[test]
fn invalid_or_authority_widening_fields_refuse_before_search() {
    for body in [
        "query=",
        "query=%00",
        "query=%FF",
        "query=%",
        "query=a&query=b",
        "label=a&label=a",
        "state=all&state=all",
        "case_sensitive=1",
        "case_sensitive=true",
        "opened_by=bad",
        "after=1",
        "limit=0",
        "limit=101",
        "max_scan=0",
        "max_scan=1001",
        "max_scan=01",
        "max_scan=18446744073709551616",
        "principal=admin",
        "storage_root=/tmp",
        "tenant=other",
        "repository=other",
        "expected_version=0",
        "idempotency_key=forged",
        "clear_labels=true",
        "after_version=1",
    ] {
        assert!(parse(body.as_bytes()).is_err(), "{body}");
    }
    assert!(parse(format!("query={}", "x".repeat(257)).as_bytes()).is_err());
    let labels = (0..33)
        .map(|n| format!("label={n:02}"))
        .collect::<Vec<_>>()
        .join("&");
    assert!(parse(labels.as_bytes()).is_err());
}

#[test]
fn search_errors_do_not_invent_mutation_ambiguity_or_terminal_outcomes() {
    for (error, status) in [
        (SearchError::InvalidLimits, Status::BadRequest),
        (SearchError::SnapshotRequired, Status::BadRequest),
        (SearchError::SnapshotMoved, Status::Conflict),
        (SearchError::InvalidSourcePage, Status::Unavailable),
        (SearchError::Allocation, Status::Unavailable),
        (
            SearchError::Source(ApiError::snapshot_moved()),
            Status::Conflict,
        ),
    ] {
        let error = super::error(error);
        assert_eq!(error.status, status);
        assert!(!error.outcome_unknown);
    }
    assert_eq!(SearchStop::Exhausted.as_str(), "exhausted");
    assert_eq!(SearchStop::ScanLimit.as_str(), "scan_limit");
}
