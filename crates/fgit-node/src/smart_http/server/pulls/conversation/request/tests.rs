use super::*;
use fgit_wire::smart_http::{HttpLimits, head};

fn command(body: &str) -> Result<PullRequestCommentCommand, ApiError> {
    let bytes = format!(
        "POST /repo.git/api/v1/pulls/7/comments HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let envelope = head::parse(bytes.as_bytes(), HttpLimits::default())
        .unwrap()
        .unwrap();
    Request::parse(&envelope)?.unwrap().command(body.as_bytes())
}

#[test]
fn comment_form_keeps_exact_text_and_its_independent_discussion_version() {
    let body = "expected_version=0&body=Review+%F0%9F%A6%80%0A%3Cscript%3E%252f%22";
    let first = command(body).unwrap();
    assert_eq!(first.number.get(), 7);
    assert_eq!(first.expected_version, ExpectedVersion::NewStream);
    assert_eq!(first.body, "Review 🦀\n<script>%2f\"");
    let second = command(&body.replace("expected_version=0", "expected_version=1")).unwrap();
    assert_eq!(
        second.expected_version,
        ExpectedVersion::Exactly(AggregateVersion::FIRST)
    );
    assert_eq!(second.body, first.body);
    let reordered = body.split('&').rev().collect::<Vec<_>>().join("&");
    assert_eq!(command(&reordered).unwrap(), first);
}

#[test]
fn callers_cannot_inject_identity_review_permissions_or_pr_versions() {
    let good = "expected_version=0&body=comment";
    for body in [
        good.to_owned() + "&actor=admin",
        good.to_owned() + "&principal_id=admin",
        good.to_owned() + "&approved=true",
        good.to_owned() + "&pull_request_version=1",
        good.to_owned() + "&source_tip=deadbeef",
        good.to_owned() + "&body=replaced",
        good.to_owned() + "&expected_version=1",
        "body=comment".to_owned(),
        "expected_version=0".to_owned(),
        "expected_version=00&body=comment".to_owned(),
        "expected_version=-1&body=comment".to_owned(),
        "expected_version=18446744073709551615&body=comment".to_owned(),
    ] {
        assert!(command(&body).is_err(), "{body}");
    }
}

#[test]
fn nonblank_utf8_comments_have_the_exact_native_byte_boundary() {
    for body in ["", "+%09%0A", "%00", "%FF", "%", "%u1234"] {
        assert!(command(&format!("expected_version=0&body={body}")).is_err());
    }
    let exact = "a".repeat(MAX_COMMENT_BYTES);
    assert_eq!(
        command(&format!("expected_version=0&body={exact}"))
            .unwrap()
            .body
            .len(),
        MAX_COMMENT_BYTES
    );
    assert_eq!(
        command(&format!("expected_version=0&body={exact}a"))
            .unwrap_err()
            .status,
        super::super::super::super::Status::TooLarge
    );
    let multibyte = "é".repeat(MAX_COMMENT_BYTES / 2);
    assert_eq!(
        command(&format!("expected_version=0&body={multibyte}"))
            .unwrap()
            .body
            .len(),
        MAX_COMMENT_BYTES
    );
}

#[test]
fn read_continuations_need_a_pinned_head_and_preserve_the_rendering_request() {
    let token = format!("alg:1:{}", "ab".repeat(32));
    for (query, accepted) in [
        ("".to_owned(), true),
        ("limit=1".to_owned(), true),
        (
            format!("after=1&limit=2&expected_head={token}&render=html_safe"),
            true,
        ),
        ("after=1".to_owned(), false),
        ("limit=0".to_owned(), false),
        ("limit=101".to_owned(), false),
        ("limit=1&limit=2".to_owned(), false),
        ("principal_id=admin".to_owned(), false),
        ("render=raw".to_owned(), false),
    ] {
        let bytes = format!(
            "GET /repo.git/api/v1/pulls/7/comments?{query} HTTP/1.1\r\nHost: local\r\n\r\n"
        );
        let envelope = head::parse(bytes.as_bytes(), HttpLimits::default())
            .unwrap()
            .unwrap();
        let parsed = Request::parse(&envelope);
        assert_eq!(parsed.is_ok(), accepted, "{query}");
        if let Ok(Some(request)) = parsed {
            assert!(!request.is_mutation());
            assert_eq!(request.number.get(), 7);
            if query.contains("render=") {
                assert!(request.page.render.is_some());
                assert!(request.page.expected_head.is_some());
            }
        }
    }
}

#[test]
fn exact_comments_routes_obey_the_native_http_envelope_and_writer_semantics() {
    let form = "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n";
    for (method, number, query, extra, accepted) in [
        ("GET", "7", "", "", true),
        ("POST", "7", "", form, true),
        ("GET", "0", "", "", false),
        ("GET", "07", "", "", false),
        ("GET", "1/2", "", "", false),
        ("PUT", "7", "", form, false),
        ("POST", "7", "?limit=1", form, false),
        (
            "POST",
            "7",
            "",
            "Content-Type: application/json\r\nContent-Length: 1\r\n",
            false,
        ),
        ("GET", "7", "", "Content-Length: 1\r\n", false),
        ("GET", "7", "", "Expect: 100-continue\r\n", false),
        ("GET", "7", "", "Git-Protocol: version=2\r\n", false),
    ] {
        let bytes = format!(
            "{method} /repo.git/api/v1/pulls/{number}/comments{query} HTTP/1.1\r\nHost: local\r\n{extra}\r\n"
        );
        let envelope = head::parse(bytes.as_bytes(), HttpLimits::default())
            .unwrap()
            .unwrap();
        let result = super::super::super::Request::parse(&envelope);
        assert_eq!(result.is_ok(), accepted, "{method} {number} {extra}");
        if let Ok(Some(request)) = result {
            assert!(matches!(
                request,
                super::super::super::Request::Conversation(_)
            ));
            assert_eq!(request.is_mutation(), method == "POST");
            assert_eq!(request.accepts_body(), method == "POST");
        }
    }
}
