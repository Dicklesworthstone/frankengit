#![forbid(unsafe_code)]
//! Regression coverage for webhook URLs copied into an HTTP request line.

use fgit_forge::webhook::{SsrfPolicy, WebhookRefusal};

fn assert_invalid(raw: &str) {
    assert!(
        matches!(
            SsrfPolicy::STRICT.validate_url(raw),
            Err(WebhookRefusal::InvalidUrl(_))
        ),
        "URL should have been refused: {raw:?}"
    );
}

#[test]
fn rejects_every_ascii_control_in_request_targets() {
    for byte in (0u8..=31).chain(std::iter::once(127)) {
        let control = char::from(byte);
        assert_invalid(&format!("http://example.com/hook{control}injected"));
        assert_invalid(&format!("http://example.com/?key={control}"));
    }
}

#[test]
fn controls_are_not_laundered_by_trimming() {
    for raw in [
        "\r\nhttp://example.com/hook",
        "http://example.com/hook\r\n",
        "\thttp://example.com/hook",
        "http://example.com/hook\0",
    ] {
        assert_invalid(raw);
    }
}

#[test]
fn refuses_http_request_line_and_header_injection() {
    for raw in [
        "http://example.com/hook HTTP/1.1\r\nX-Injected: yes\r\n\r\n",
        "http://example.com/a b",
        "http://example.com/?value=a b",
        "http://example.com/caf\u{e9}",
        "http://example.com/hook#fragment",
        "http://example.com/hook\\other",
    ] {
        assert_invalid(raw);
    }
}

#[test]
fn query_only_urls_get_an_origin_form_request_target() {
    for (raw, host, port, target) in [
        ("http://example.com?topic=push", "example.com", 80, "/?topic=push"),
        (
            "https://example.com:8443?recipient=a@b",
            "example.com",
            8443,
            "/?recipient=a@b",
        ),
        ("https://example.com?", "example.com", 443, "/?"),
    ] {
        let url = SsrfPolicy::STRICT.validate_url(raw).expect("valid query URL");
        assert_eq!(url.host(), host);
        assert_eq!(url.port(), port);
        assert_eq!(url.path_and_query(), target);
        assert!(url.path_and_query().starts_with('/'));
    }
}

#[test]
fn query_only_ipv6_urls_preserve_the_authority() {
    let url = SsrfPolicy::PERMISSIVE_FOR_TESTS
        .validate_url("http://[::1]:9000?topic=push")
        .expect("explicitly permitted loopback IPv6");
    assert_eq!(url.host(), "::1");
    assert_eq!(url.port(), 9000);
    assert_eq!(url.path_and_query(), "/?topic=push");
    assert!(SsrfPolicy::STRICT
        .validate_url("http://[::1]:9000?topic=push")
        .is_err());
}

#[test]
fn credentials_remain_forbidden_but_at_signs_in_targets_are_data() {
    for raw in [
        "http://user:pass@example.com/hook",
        "http://user@example.com?recipient=a@b",
        "http://user@example.com",
    ] {
        assert_invalid(raw);
    }
    for raw in [
        "http://example.com/hook@v1",
        "http://example.com?recipient=a@b",
        "http://example.com/hook?recipient=a@b",
    ] {
        assert!(SsrfPolicy::STRICT.validate_url(raw).is_ok(), "{raw}");
    }
}

#[test]
fn encoded_target_bytes_are_preserved_without_decoding() {
    let raw = "https://example.com/hook%20name?value=%0D%0A%23%5C&utf8=caf%C3%A9";
    let url = SsrfPolicy::STRICT.validate_url(raw).expect("encoded URI");
    assert_eq!(
        url.path_and_query(),
        "/hook%20name?value=%0D%0A%23%5C&utf8=caf%C3%A9"
    );
}

#[test]
fn ordinary_urls_keep_their_existing_request_targets() {
    for (raw, target) in [
        ("http://example.com", "/"),
        ("https://example.com/", "/"),
        ("https://example.com/hook?topic=push", "/hook?topic=push"),
    ] {
        let url = SsrfPolicy::STRICT.validate_url(raw).expect("ordinary URI");
        assert_eq!(url.path_and_query(), target);
    }
}
