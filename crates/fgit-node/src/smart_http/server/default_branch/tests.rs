use super::*;
use fgit_types::GitHashAlgorithm;
use fgit_wire::smart_http::head;

fn form(format: GitHashAlgorithm) -> String {
    format!(
        "expected_default_hex={}&reference_hex={}&expected_tip={}",
        hex(b"refs/heads/main"),
        hex(b"refs/heads/release\xff"),
        "a".repeat(format.digest_len() * 2)
    )
}

#[test]
fn exact_old_target_and_byte_names_survive_both_native_oid_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let parsed = request::command(form(format).as_bytes(), format).unwrap();
        assert_eq!(parsed.expected_head.unwrap().as_bytes(), b"refs/heads/main");
        assert_eq!(parsed.target.as_bytes(), b"refs/heads/release\xff");
        assert_eq!(parsed.expected_target_tip.algorithm(), format);
        let absent = form(format).replace(
            &format!("expected_default_hex={}", hex(b"refs/heads/main")),
            "expect_no_default=true",
        );
        assert!(
            request::command(absent.as_bytes(), format)
                .unwrap()
                .expected_head
                .is_none()
        );
    }
}

#[test]
fn stale_expectations_cannot_be_omitted_or_widened_and_identity_is_not_payload() {
    let valid = form(GitHashAlgorithm::Sha1);
    for bad in [
        valid.replace(&format!("expected_default_hex={}&", hex(b"refs/heads/main")), ""),
        valid.replace("expected_default_hex", "expected_default"),
        valid.replace(&hex(b"refs/heads/main"), ""),
        valid.replace(&hex(b"refs/heads/release\xff"), &hex(b"refs/tags/release")),
        valid.replace(&"a".repeat(40), &"0".repeat(40)),
        valid.replace(&"a".repeat(40), &"a".repeat(64)),
        valid.replace("reference_hex=", "reference_hex=FF"),
        valid.clone() + "&expect_no_default=true",
        valid.clone() + "&principal_id=admin",
        valid.clone() + "&force=true",
        valid.clone() + "&reference_hex=726566732f68656164732f61",
        "expect_no_default=false&reference_hex=726566732f68656164732f61&expected_tip=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
    ] {
        assert!(request::command(bad.as_bytes(), GitHashAlgorithm::Sha1).is_err(), "{bad}");
    }
}

#[test]
fn route_parser_refuses_suffixes_queries_unbounded_bodies_and_foreign_protocols() {
    for (method, target, headers) in [
        ("GET", "/repo.git/api/v1/default-branch/", ""),
        ("GET", "/repo.git/api/v1/default-branch?principal=admin", ""),
        (
            "GET",
            "/repo.git/api/v1/default-branch",
            "Content-Length: 1\r\n",
        ),
        (
            "GET",
            "/repo.git/api/v1/default-branch",
            "Expect: 100-continue\r\n",
        ),
        (
            "GET",
            "/repo.git/api/v1/default-branch",
            "Git-Protocol: version=2\r\n",
        ),
        ("DELETE", "/repo.git/api/v1/default-branch", ""),
        (
            "POST",
            "/repo.git/api/v1/default-branch",
            "Content-Length: 0\r\nContent-Type: application/x-www-form-urlencoded\r\n",
        ),
        (
            "POST",
            "/repo.git/api/v1/default-branch",
            "Content-Length: 25000\r\nContent-Type: application/x-www-form-urlencoded\r\n",
        ),
        (
            "POST",
            "/repo.git/api/v1/default-branch?expected_head=any",
            "Content-Length: 1\r\nContent-Type: application/x-www-form-urlencoded\r\n",
        ),
        (
            "POST",
            "/repo.git/api/v1/default-branch",
            "Content-Length: 1\r\nContent-Type: application/json\r\n",
        ),
    ] {
        let raw = format!("{method} {target} HTTP/1.1\r\nHost: local\r\n{headers}\r\n");
        let envelope = head::parse(raw.as_bytes(), HttpLimits::default())
            .unwrap()
            .unwrap();
        assert!(Request::parse(&envelope).is_err(), "{raw}");
    }
    for (method, headers) in [
        ("GET", ""),
        (
            "POST",
            "Transfer-Encoding: chunked\r\nContent-Type: application/x-www-form-urlencoded\r\n",
        ),
    ] {
        let raw = format!(
            "{method} /tenant/repo.git/api/v1/default-branch HTTP/1.1\r\nHost: local\r\n{headers}\r\n"
        );
        let envelope = head::parse(raw.as_bytes(), HttpLimits::default())
            .unwrap()
            .unwrap();
        let parsed = Request::parse(&envelope).unwrap();
        assert_eq!(parsed.is_mutation(), method == "POST");
        assert_eq!(parsed.repository_route, "/tenant/repo.git");
    }
}
