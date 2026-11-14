use super::*;
use fgit_wire::smart_http::{HttpLimits, head};

#[test]
fn literal_filters_and_raw_branch_aliases_are_preserved() {
    let raw = b"refs/heads/topic-\xff"
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let parsed = parse(format!("query=%5Ba%5D.%2A%C3%A9&state=merged&case_sensitive=true&source_ref_hex={raw}&target_ref=refs%2Fheads%2Fmain&limit=2&max_scan=3").as_bytes()).unwrap();
    assert_eq!(parsed.query.query().text.as_deref(), Some("[a].*é"));
    assert_eq!(
        parsed.query.query().source_ref.as_ref().unwrap().as_bytes(),
        b"refs/heads/topic-\xff"
    );
    assert_eq!(parsed.query.query().state, Some(PullRequestState::Merged));
    assert_eq!((parsed.request.limit, parsed.request.max_scan), (2, 3));
}

#[test]
fn search_refuses_unknown_authority_fields_duplicates_bad_encodings_and_unpinned_continuation() {
    for query in [
        "principal=admin",
        "idempotency_key=write",
        "query=x&query=y",
        "state=approved",
        "case_sensitive=true",
        "case_sensitive=1",
        "query=",
        "query=a%00b",
        "query=%ff",
        "after=1",
        "after=01",
        "limit=0",
        "limit=101",
        "max_scan=1001",
        "source_ref=refs/tags/release",
        "source_ref=refs/heads/x&source_ref_hex=aa",
        "target_ref_hex=FF",
        "render=executable",
    ] {
        assert!(parse(query.as_bytes()).is_err(), "{query}");
    }
    assert!(parse(format!("query={}", "é".repeat(129)).as_bytes()).is_err());
}

#[test]
fn search_has_only_read_semantics_and_rejects_body_or_git_protocol() {
    let bytes = b"GET /repo.git/api/v1/pulls/search?state=open HTTP/1.1\r\nHost: local\r\n\r\n";
    let envelope = head::parse(bytes, HttpLimits::default()).unwrap().unwrap();
    let request = super::super::Request::parse(&envelope).unwrap().unwrap();
    assert!(!request.is_mutation());
    assert!(!request.accepts_body());
    assert!(request.uses_read_quota());
    assert!(request.preserves_deadline());
    assert_eq!(
        request.agent_operation(),
        Some(fgit_identity::agent::PULLS_READ)
    );
    for headers in [
        "Content-Length: 1\r\n",
        "Expect: 100-continue\r\n",
        "Git-Protocol: version=2\r\n",
    ] {
        let bytes =
            format!("GET /repo.git/api/v1/pulls/search HTTP/1.1\r\nHost: local\r\n{headers}\r\n");
        match head::parse(bytes.as_bytes(), HttpLimits::default()) {
            Ok(Some(envelope)) => assert!(super::super::Request::parse(&envelope).is_err()),
            Err(_) => {}
            Ok(None) => panic!("complete head unexpectedly incomplete"),
        }
    }
}

#[test]
fn search_and_existing_label_reads_share_only_the_read_quota() {
    for (method, suffix, headers, expected) in [
        ("GET", "/search?query=needle", "", true),
        ("GET", "?label=triage", "", true),
        ("GET", "/1/labels", "", true),
        ("GET", "", "", false),
        ("GET", "/1", "", false),
        (
            "POST",
            "/1/labels",
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n",
            false,
        ),
        (
            "POST",
            "/1/open",
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n",
            false,
        ),
    ] {
        let bytes = format!(
            "{method} /repo.git/api/v1/pulls{suffix} HTTP/1.1\r\nHost: local\r\n{headers}\r\n"
        );
        let envelope = head::parse(bytes.as_bytes(), HttpLimits::default())
            .unwrap()
            .unwrap();
        let request = super::super::Request::parse(&envelope).unwrap().unwrap();
        assert_eq!(request.uses_read_quota(), expected, "{method} {suffix}");
    }
}
