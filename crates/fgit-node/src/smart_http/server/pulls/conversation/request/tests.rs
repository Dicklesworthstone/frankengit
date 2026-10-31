use super::*;
use fgit_wire::smart_http::{HttpLimits, head};

fn command(body: &str) -> Result<PullRequestCommentCommand, ApiError> {
    command_with_format(body, GitHashAlgorithm::Sha1)
}

fn command_with_format(
    body: &str,
    format: GitHashAlgorithm,
) -> Result<PullRequestCommentCommand, ApiError> {
    let bytes = format!(
        "POST /repo.git/api/v1/pulls/7/comments HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let envelope = head::parse(bytes.as_bytes(), HttpLimits::default())
        .unwrap()
        .unwrap();
    Request::parse(&envelope)?
        .unwrap()
        .command(body.as_bytes(), format)
}

#[test]
fn comment_form_keeps_exact_text_and_its_independent_discussion_version() {
    let body = "expected_version=0&body=Review+%F0%9F%A6%80%0A%3Cscript%3E%252f%22";
    let first = command(body).unwrap();
    assert_eq!(first.number.get(), 7);
    assert_eq!(first.expected_version, ExpectedVersion::NewStream);
    assert!(first.anchor.is_none());
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

fn append_command(
    body: &str,
    format: GitHashAlgorithm,
) -> Result<PullRequestAppendCommentCommand, ApiError> {
    let bytes = format!(
        "POST /repo.git/api/v1/pulls/7/comments/append HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let envelope = head::parse(bytes.as_bytes(), HttpLimits::default())
        .unwrap()
        .unwrap();
    let request = Request::parse(&envelope)?.unwrap();
    assert!(request.is_mutation());
    assert!(request.is_append());
    assert!(request.command(body.as_bytes(), format).is_err());
    request.append_command(body.as_bytes(), format)
}

#[test]
fn append_form_has_no_conversation_predecessor_and_keeps_literal_text() {
    let parsed =
        append_command("body=Review+%F0%9F%A6%80%0A%252f", GitHashAlgorithm::Sha1).unwrap();
    assert_eq!(parsed.number.get(), 7);
    assert_eq!(parsed.body, "Review 🦀\n%2f");
    assert!(parsed.anchor.is_none());
    for body in [
        "",
        "body=",
        "body=+%09%0A",
        "body=%00",
        "body=%FF",
        "body=%",
        "body=comment&expected_version=0",
        "body=comment&expected_version=1",
        "body=comment&body=changed",
        "body=comment&actor=admin",
        "body=comment&principal_id=admin",
        "body=comment&approved=true",
        "body=comment&pull_request_version=1",
        "body=comment&anchor_status=exact",
    ] {
        assert!(
            append_command(body, GitHashAlgorithm::Sha1).is_err(),
            "{body}"
        );
    }
    let exact = "é".repeat(MAX_COMMENT_BYTES / 2);
    assert_eq!(
        append_command(&format!("body={exact}"), GitHashAlgorithm::Sha1)
            .unwrap()
            .body
            .len(),
        MAX_COMMENT_BYTES
    );
    assert_eq!(
        append_command(&format!("body={exact}a"), GitHashAlgorithm::Sha1)
            .unwrap_err()
            .status,
        super::super::super::super::Status::TooLarge
    );
    assert!(
        command("body=comment").is_err(),
        "strict comment still requires an exact predecessor"
    );
}

#[test]
fn append_form_retains_every_source_anchor_precondition() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fields = anchor_fields(format);
        let strict = anchored_form(&fields);
        let append = strict.strip_prefix("expected_version=0&").unwrap();
        let parsed = append_command(append, format).unwrap();
        assert_eq!(
            parsed.anchor,
            command_with_format(&strict, format).unwrap().anchor
        );
        for field in ANCHOR_FIELDS {
            let mut missing = fields.clone();
            missing.remove(field);
            let form = anchored_form(&missing);
            assert!(
                append_command(form.strip_prefix("expected_version=0&").unwrap(), format).is_err(),
                "missing {field}"
            );
            assert!(
                append_command(&format!("{append}&{field}={}", fields[field]), format).is_err(),
                "duplicate {field}"
            );
        }
        let other = if format == GitHashAlgorithm::Sha1 {
            GitHashAlgorithm::Sha256
        } else {
            GitHashAlgorithm::Sha1
        };
        assert!(append_command(append, other).is_err());
    }
}

#[test]
fn append_route_cannot_be_read_or_used_with_a_query() {
    for (method, suffix, length) in [
        ("GET", "", 0),
        ("PUT", "", 6),
        ("POST", "?expected_version=0", 6),
    ] {
        let raw = format!(
            "{method} /repo.git/api/v1/pulls/7/comments/append{suffix} HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {length}\r\n\r\n"
        );
        let envelope = head::parse(raw.as_bytes(), HttpLimits::default())
            .unwrap()
            .unwrap();
        assert!(Request::parse(&envelope).is_err());
    }
}

fn anchor_fields(format: GitHashAlgorithm) -> BTreeMap<String, String> {
    let bytes = match format {
        GitHashAlgorithm::Sha1 => 20,
        GitHashAlgorithm::Sha256 => 32,
    };
    [
        ("anchor_pull_request_version", "1".into()),
        (
            "anchor_source_ref_hex",
            fgit_crypto::lowercase_hex(b"refs/heads/topic"),
        ),
        (
            "anchor_target_ref_hex",
            fgit_crypto::lowercase_hex(b"refs/heads/main"),
        ),
        ("anchor_source_tip", "11".repeat(bytes)),
        ("anchor_target_tip", "22".repeat(bytes)),
        ("anchor_compared_base", "22".repeat(bytes)),
        ("anchor_comparison", "direct".into()),
        (
            "anchor_path_hex",
            fgit_crypto::lowercase_hex(b"src/\xff.rs"),
        ),
        ("anchor_side", "after".into()),
        ("anchor_blob", "33".repeat(bytes)),
        ("anchor_mode", "100755".into()),
        ("anchor_byte_start", "0".into()),
        ("anchor_byte_end", "6".into()),
        ("anchor_line_start", "0".into()),
        ("anchor_line_count", "1".into()),
    ]
    .into_iter()
    .map(|(field, value)| (field.into(), value))
    .collect()
}

fn anchored_form(fields: &BTreeMap<String, String>) -> String {
    format!(
        "expected_version=0&body=Review+%F0%9F%A6%80&{}",
        fields
            .iter()
            .map(|(field, value)| format!("{field}={value}"))
            .collect::<Vec<_>>()
            .join("&")
    )
}

#[test]
fn source_anchor_form_binds_every_exact_field_and_the_repository_hash_format() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fields = anchor_fields(format);
        let form = anchored_form(&fields);
        let parsed = command_with_format(&form, format).unwrap();
        let anchor = parsed.anchor.as_ref().unwrap();
        assert_eq!(parsed.body, "Review 🦀");
        assert_eq!(anchor.path, b"src/\xff.rs");
        assert_eq!(anchor.source_tip.algorithm(), format);
        assert_eq!(
            (
                anchor.byte_start,
                anchor.byte_end,
                anchor.line_start,
                anchor.line_count
            ),
            (0, 6, 0, 1)
        );
        let reordered = form.split('&').rev().collect::<Vec<_>>().join("&");
        assert_eq!(command_with_format(&reordered, format).unwrap(), parsed);
        for field in ANCHOR_FIELDS {
            let mut missing = fields.clone();
            missing.remove(field);
            assert!(
                command_with_format(&anchored_form(&missing), format).is_err(),
                "missing {field}"
            );
            let duplicate = format!("{form}&{field}={}", fields[field]);
            assert!(
                command_with_format(&duplicate, format).is_err(),
                "duplicate {field}"
            );
        }
        for (field, value) in [
            ("anchor_pull_request_version", "0"),
            ("anchor_line_count", "0"),
            ("anchor_line_count", "129"),
            ("anchor_line_start", "01"),
            ("anchor_byte_end", "0"),
            ("anchor_byte_end", "65537"),
            ("anchor_mode", "160000"),
            ("anchor_mode", "0100644"),
            ("anchor_path_hex", "FF"),
            ("anchor_path_hex", "2e2e2f66696c65"),
            ("anchor_side", "guess"),
            ("anchor_comparison", "remapped"),
        ] {
            let mut invalid = fields.clone();
            invalid.insert(field.into(), value.into());
            assert!(
                command_with_format(&anchored_form(&invalid), format).is_err(),
                "{field}={value}"
            );
        }
        for extra in [
            "anchor_profile=untrusted",
            "anchor_status=exact",
            "actor=admin",
            "approved=true",
        ] {
            assert!(command_with_format(&format!("{form}&{extra}"), format).is_err());
        }
        let other = if format == GitHashAlgorithm::Sha1 {
            GitHashAlgorithm::Sha256
        } else {
            GitHashAlgorithm::Sha1
        };
        assert!(command_with_format(&form, other).is_err());
    }
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
        (String::new(), true),
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
