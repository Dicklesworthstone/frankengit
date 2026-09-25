use super::*;
use crate::{GitDaemonSessionTimeout, NodeConfig, PushQuota};
use fgit_crypto::sha256_digest;
use fgit_types::{PrincipalId, RepositoryId, TenantId};
use fgit_wire::smart_http::BodyFraming;
use std::sync::Arc;

fn profile() -> Profile {
    Profile {
        config: NodeConfig::new(
            "unused".into(),
            TenantId::from_bytes([1; 16]),
            RepositoryId::from_bytes([2; 16]),
        ),
        route: b"/repo.git".to_vec(),
        credentials: super::super::CredentialSource::Static {
            digest: sha256_digest(&[b'a'; 64]),
            principal: PrincipalId::from_bytes([3; 16]),
        },
        allow_receive: true,
        allow_issues: false,
        allow_outcomes: false,
        allow_pulls: false,
        allow_source: false,
        http: HttpLimits::default(),
        maximum_response_bytes: 1024,
        timeout: GitDaemonSessionTimeout::DEFAULT,
        quota: Arc::new(PushQuota::default()),
        outcome_quota: Arc::new(PushQuota::default()),
        source_quota: Arc::new(PushQuota::default()),
    }
}

fn request(method: &str, target: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "{method} {target} HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer {}\r\n{headers}\r\n",
        "a".repeat(64)
    )
    .into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn run(bytes: Vec<u8>, profile: &Profile, nonce: u8) -> Result<(Option<Vec<u8>>, Vec<u8>), Status> {
    let mut output = Vec::new();
    let result = adapt_with_nonce(
        bytes,
        profile,
        &mut HttpVersion::Http11,
        &mut output,
        || [nonce; 32],
    )?;
    Ok((result, output))
}

fn location(output: &[u8]) -> &str {
    std::str::from_utf8(output)
        .unwrap()
        .split("\r\n")
        .find_map(|line| line.strip_prefix("Location: "))
        .unwrap()
}

fn scoped(identifier: &str, suffix: &str) -> String {
    format!("/repo.git{MARKER}{identifier}{suffix}")
}

const RPC_HEADERS: &str =
    "Content-Type: application/x-git-receive-pack-request\r\nContent-Length: 4\r\n";

#[test]
fn ordinary_push_discovery_redirects_without_a_custom_header() {
    let profile = profile();
    let input = request("GET", &format!("/repo.git{DISCOVERY}"), "", b"");
    let (forwarded, output) = run(input, &profile, 0x42).unwrap();
    assert!(forwarded.is_none());
    assert_eq!(location(&output), scoped(&"42".repeat(32), DISCOVERY));
    let response = std::str::from_utf8(&output).unwrap();
    assert!(response.starts_with("HTTP/1.1 307 Temporary Redirect\r\n"));
    assert!(response.contains("Cache-Control: no-store\r\n"));
    assert!(response.contains("Content-Length: 0\r\n"));
    assert!(response.contains(&format!(
        "Idempotency-Key: {KEY_PREFIX}{}\r\n",
        "42".repeat(32)
    )));
    assert!(response.ends_with("\r\n\r\n"));
    assert!(!response.contains(&"a".repeat(64)));
}

#[test]
fn discovery_and_rpc_reuse_one_key_without_any_process_local_session_state() {
    let first_profile = profile();
    let identifier = "42".repeat(32);
    let key = format!("{KEY_PREFIX}{identifier}");
    let discovery = request("GET", &scoped(&identifier, DISCOVERY), "", b"");
    let (discovery, output) = run(discovery, &first_profile, 7).unwrap();
    assert!(output.is_empty());
    let discovery = discovery.unwrap();
    assert_eq!(retry_key(&discovery).unwrap(), Some(key.as_bytes()));
    let parsed = parse_head(&discovery, first_profile.http).unwrap().unwrap();
    assert_eq!(parsed.repository_route, "/repo.git");
    assert_eq!(parsed.operation, Operation::Discover(Service::ReceivePack));
    assert!(authenticated_session(&parsed, &discovery, &first_profile).is_ok());

    // A reconstructed Profile has no memory of discovery. Identity survives it.
    let reopened = profile();
    let rpc = request(
        "POST",
        &scoped(&identifier, RPC),
        RPC_HEADERS,
        b"\xff\x00\xfe\x01",
    );
    let (normalized, output) = run(rpc.clone(), &reopened, 8).unwrap();
    assert!(output.is_empty());
    let normalized = normalized.unwrap();
    let parsed = parse_head(&normalized, reopened.http).unwrap().unwrap();
    assert_eq!(parsed.operation, Operation::Rpc(Service::ReceivePack));
    assert_eq!(parsed.repository_route, "/repo.git");
    assert_eq!(parsed.body, BodyFraming::ContentLength(4));
    assert_eq!(&normalized[parsed.consumed..], b"\xff\x00\xfe\x01");
    assert_eq!(
        retry_key(&normalized[..parsed.consumed]).unwrap(),
        Some(key.as_bytes())
    );
    let selected =
        authenticated_session(&parsed, &normalized[..parsed.consumed], &reopened).unwrap();
    assert_eq!(
        selected.authenticated_session().unwrap().principal_id(),
        PrincipalId::from_bytes([3; 16])
    );
    assert_eq!(run(rpc, &profile(), 99).unwrap().0, Some(normalized));
}

#[test]
fn separate_discoveries_of_identical_work_get_distinct_attempts() {
    let profile = profile();
    let request = request("GET", &format!("/repo.git{DISCOVERY}"), "", b"");
    let mut paths = std::collections::BTreeSet::new();
    for nonce in [1, 2, 3] {
        let (_, response) = run(request.clone(), &profile, nonce).unwrap();
        paths.insert(location(&response).to_owned());
    }
    assert_eq!(paths.len(), 3);
}

#[test]
fn no_redirect_or_entropy_before_authentication_and_receive_permission() {
    let profile = profile();
    let valid = request("GET", &format!("/repo.git{DISCOVERY}"), "", b"");
    for (input, expected) in [
        (
            String::from_utf8(valid.clone())
                .unwrap()
                .replace(&format!("Authorization: Bearer {}\r\n", "a".repeat(64)), "")
                .into_bytes(),
            Status::Unauthorized,
        ),
        (
            String::from_utf8(valid.clone())
                .unwrap()
                .replace(&"a".repeat(64), &"b".repeat(64))
                .into_bytes(),
            Status::Unauthorized,
        ),
    ] {
        let mut output = Vec::new();
        assert_eq!(
            adapt_with_nonce(
                input,
                &profile,
                &mut HttpVersion::Http11,
                &mut output,
                || panic!("no entropy before authentication")
            ),
            Err(expected)
        );
        assert!(output.is_empty());
    }
    let mut readonly = profile;
    readonly.allow_receive = false;
    let mut output = Vec::new();
    assert_eq!(
        adapt_with_nonce(
            valid,
            &readonly,
            &mut HttpVersion::Http11,
            &mut output,
            || panic!("no entropy before permission")
        ),
        Err(Status::Forbidden)
    );
    assert!(output.is_empty());
}

#[test]
fn scoped_url_never_authenticates_a_post_or_overrides_revocation() {
    let mut profile = profile();
    let input = request("POST", &scoped(&"42".repeat(32), RPC), RPC_HEADERS, b"0000");
    let normalized = run(input, &profile, 1).unwrap().0.unwrap();
    let envelope = head::parse(&normalized, profile.http).unwrap().unwrap();
    let parsed = parse_head(&normalized, profile.http).unwrap().unwrap();
    assert!(authenticated_session(&parsed, &normalized[..envelope.consumed], &profile).is_ok());
    profile.allow_receive = false;
    assert_eq!(
        authenticated_session(&parsed, &normalized[..envelope.consumed], &profile),
        Err(Status::Forbidden)
    );
    profile.allow_receive = true;
    profile.credentials = super::super::CredentialSource::Static {
        digest: sha256_digest(&[b'b'; 64]),
        principal: PrincipalId::from_bytes([3; 16]),
    };
    assert_eq!(
        authenticated_session(&parsed, &normalized[..envelope.consumed], &profile),
        Err(Status::Unauthorized)
    );
}

#[test]
fn explicit_keys_and_unrelated_services_are_byte_for_byte_unchanged() {
    let profile = profile();
    for input in [
        request(
            "GET",
            &format!("/repo.git{DISCOVERY}"),
            "Idempotency-Key: explicit\r\n",
            b"",
        ),
        request(
            "POST",
            "/repo.git/git-receive-pack",
            &format!("{RPC_HEADERS}Idempotency-Key: explicit\r\n"),
            b"0000",
        ),
        request(
            "GET",
            "/repo.git/info/refs?service=git-upload-pack",
            "",
            b"",
        ),
        request("GET", "/repo.git/api/v1/issues", "", b""),
        request(
            "GET",
            "/repo.git-other/info/refs?service=git-receive-pack",
            "",
            b"",
        ),
    ] {
        let mut output = Vec::new();
        let expected = input.clone();
        assert_eq!(
            adapt_with_nonce(
                input,
                &profile,
                &mut HttpVersion::Http11,
                &mut output,
                || panic!("explicit or unrelated path must not allocate an attempt")
            )
            .unwrap(),
            Some(expected)
        );
        assert!(output.is_empty());
    }
}

#[test]
fn conflicting_duplicate_and_hop_by_hop_keys_are_refused() {
    let profile = profile();
    let identifier = "42".repeat(32);
    let key = format!("{KEY_PREFIX}{identifier}");
    let target = scoped(&identifier, RPC);
    for extra in [
        "Idempotency-Key: other\r\n".to_owned(),
        format!("Idempotency-Key: {key}\r\nidempotency-key: {key}\r\n"),
        "Connection: Idempotency-Key\r\n".to_owned(),
    ] {
        assert!(
            run(
                request("POST", &target, &format!("{RPC_HEADERS}{extra}"), b"0000"),
                &profile,
                1
            )
            .is_err()
        );
    }
    let input = request(
        "POST",
        &target,
        &format!("{RPC_HEADERS}Idempotency-Key: {key}\r\n"),
        b"0000",
    );
    let normalized = run(input, &profile, 1).unwrap().0.unwrap();
    let parsed = parse_head(&normalized, profile.http).unwrap().unwrap();
    assert_eq!(
        retry_key(&normalized[..parsed.consumed]).unwrap(),
        Some(key.as_bytes())
    );
}

#[test]
fn alias_syntax_cannot_select_foreign_endpoints_or_ambiguous_nonces() {
    let profile = profile();
    for identifier in [
        "".to_owned(),
        "a".repeat(63),
        "a".repeat(65),
        "A".repeat(64),
        "g".repeat(64),
        "%61".repeat(32),
    ] {
        assert!(
            run(
                request("GET", &scoped(&identifier, DISCOVERY), "", b""),
                &profile,
                1
            )
            .is_err()
        );
    }
    for suffix in [
        "/info/refs?service=git-upload-pack",
        "/git-upload-pack",
        "/git-receive-pack?x=1",
        "/api/v1/source",
        "/api/v1/outcomes",
        "/../info/refs?service=git-receive-pack",
    ] {
        assert!(
            run(
                request("GET", &scoped(&"42".repeat(32), suffix), "", b""),
                &profile,
                1
            )
            .is_err()
        );
    }
    assert!(
        run(
            request("GET", &scoped(&"42".repeat(32), RPC), "", b""),
            &profile,
            1
        )
        .is_err()
    );
}

#[test]
fn discovery_body_expectation_and_pipelined_bytes_do_not_redirect() {
    let profile = profile();
    let target = format!("/repo.git{DISCOVERY}");
    for (headers, body) in [
        ("Content-Length: 1\r\n", b"x".as_slice()),
        ("Expect: 100-continue\r\n", b"".as_slice()),
        ("", b"GET /other HTTP/1.1\r\n\r\n".as_slice()),
    ] {
        let mut output = Vec::new();
        assert!(
            adapt_with_nonce(
                request("GET", &target, headers, body),
                &profile,
                &mut HttpVersion::Http11,
                &mut output,
                || panic!("invalid discovery must not allocate")
            )
            .is_err()
        );
        assert!(output.is_empty());
    }
    assert!(
        run(
            request("GET", &target, "Content-Length: 0\r\n", b""),
            &profile,
            1
        )
        .unwrap()
        .0
        .is_none()
    );
}

#[test]
fn normalization_preserves_chunked_stream_and_protocol_headers() {
    let profile = profile();
    let headers = "Content-Type: application/x-git-receive-pack-request\r\nTransfer-Encoding: chunked\r\nGit-Protocol: version=1\r\n";
    let body = b"2\r\n\xff\x00\r\n2\r\n\xfe\x01\r\n0\r\n\r\n";
    let normalized = run(
        request("POST", &scoped(&"42".repeat(32), RPC), headers, body),
        &profile,
        1,
    )
    .unwrap()
    .0
    .unwrap();
    let parsed = parse_head(&normalized, profile.http).unwrap().unwrap();
    assert_eq!(parsed.body, BodyFraming::Chunked);
    assert_eq!(
        parsed.requested_version,
        fgit_wire::smart_http::ProtocolVersion::V1
    );
    assert_eq!(&normalized[parsed.consumed..], body);
}

#[test]
fn synthetic_header_is_charged_to_header_count_and_byte_limits() {
    let profile = profile();
    let input = request("POST", &scoped(&"42".repeat(32), RPC), RPC_HEADERS, b"0000");
    let normalized = run(input.clone(), &profile, 1).unwrap().0.unwrap();
    let original_head = head::parse(&input, profile.http).unwrap().unwrap().consumed;
    let normalized_head = head::parse(&normalized, profile.http)
        .unwrap()
        .unwrap()
        .consumed;
    assert!(normalized_head > original_head);
    let mut limited = profile.clone();
    limited.http.max_head_bytes = normalized_head;
    limited.http.max_target_bytes = 128;
    assert!(run(input.clone(), &limited, 1).is_ok());
    limited.http.max_head_bytes -= 1;
    assert_eq!(run(input.clone(), &limited, 1), Err(Status::HeaderTooLarge));
    let mut count_limited = profile;
    count_limited.http.max_headers = 4;
    assert_eq!(
        run(input.clone(), &count_limited, 1),
        Err(Status::HeaderTooLarge)
    );
    count_limited.http.max_headers = 5;
    assert!(run(input, &count_limited, 1).is_ok());
}

#[test]
fn redirect_respects_http_version_and_target_limit() {
    let mut profile = profile();
    let input = String::from_utf8(request("GET", &format!("/repo.git{DISCOVERY}"), "", b""))
        .unwrap()
        .replace("HTTP/1.1", "HTTP/1.0")
        .into_bytes();
    let (_, output) = run(input.clone(), &profile, 1).unwrap();
    assert!(output.starts_with(b"HTTP/1.0 307 Temporary Redirect\r\n"));
    profile.http.max_target_bytes = location(&output).len();
    assert!(run(input.clone(), &profile, 1).is_ok());
    profile.http.max_target_bytes -= 1;
    assert_eq!(run(input, &profile, 1), Err(Status::HeaderTooLarge));
}
