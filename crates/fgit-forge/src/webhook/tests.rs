use super::*;

#[test]
fn ssrf_strict_blocks_loopback_private_and_metadata_addresses() {
    let policy = SsrfPolicy::STRICT;

    // Forbidden IPv4 addresses
    let forbidden_urls = [
        "http://127.0.0.1:8080/hook",
        "http://127.0.0.2/hook",
        "http://127.255.255.254/hook",
        "http://localhost:8080/hook",
        "http://LOCALHOST/hook",
        "http://10.0.0.1/hook",
        "http://10.254.1.1:9000/hook",
        "http://172.16.0.1/hook",
        "http://172.25.1.1/hook",
        "http://172.31.255.254/hook",
        "http://192.168.0.1/hook",
        "http://192.168.100.50/hook",
        "http://169.254.169.254/latest/meta-data", // AWS/GCP instance metadata
        "http://169.254.1.1/hook",
        "http://100.64.0.1/hook", // Carrier-grade NAT
        "http://100.127.255.254/hook",
        "http://0.0.0.0/hook",
        "http://255.255.255.255/hook",
        "http://224.0.0.1/hook",    // Multicast
        "http://240.0.0.1/hook",    // Reserved
        "http://192.0.2.1/hook",    // TEST-NET-1
        "http://198.51.100.1/hook", // TEST-NET-2
        "http://203.0.113.1/hook",  // TEST-NET-3
    ];

    for url in forbidden_urls {
        let res = policy.validate_url(url);
        assert!(
            matches!(res, Err(WebhookRefusal::SsrfBlocked { .. })),
            "expected {url} to be blocked by SSRF policy, got {res:?}"
        );
    }
}

#[test]
fn ssrf_strict_blocks_ipv6_private_loopback_and_mapped_addresses() {
    let policy = SsrfPolicy::STRICT;

    let forbidden_ipv6 = [
        "http://[::1]:8080/hook",
        "http://[::]/hook",
        "http://[fc00::1]/hook",
        "http://[fd00::1234]/hook",
        "http://[fe80::1]/hook",                // link-local
        "http://[ff02::1]/hook",                // multicast
        "http://[2001:db8::1]/hook",            // documentation
        "http://[::ffff:127.0.0.1]/hook",       // IPv4-mapped loopback
        "http://[::ffff:169.254.169.254]/hook", // IPv4-mapped metadata
        "http://[::ffff:10.0.0.1]/hook",        // IPv4-mapped private
        "http://[::ffff:192.168.1.1]/hook",     // IPv4-mapped private
    ];

    for url in forbidden_ipv6 {
        let res = policy.validate_url(url);
        assert!(
            matches!(res, Err(WebhookRefusal::SsrfBlocked { .. })),
            "expected IPv6 {url} to be blocked, got {res:?}"
        );
    }
}

#[test]
fn ssrf_blocks_obfuscated_ip_notations_and_embedded_credentials() {
    let policy = SsrfPolicy::STRICT;

    let obfuscated = [
        "http://2130706433/hook",            // Decimal integer for 127.0.0.1
        "http://0x7f000001/hook",            // Hex integer
        "http://0177.0.0.1/hook",            // Octal notation
        "http://user:pass@example.com/hook", // Embedded credentials
        "ftp://example.com/hook",            // Unsupported scheme
        "file:///etc/passwd",                // Unsupported scheme
        "gopher://example.com/hook",         // Unsupported scheme
    ];

    for url in obfuscated {
        let res = policy.validate_url(url);
        assert!(res.is_err(), "expected {url} to be rejected, got {res:?}");
    }
}

#[test]
fn ssrf_accepts_valid_public_hosts_and_ips() {
    let policy = SsrfPolicy::STRICT;

    let valid_urls = [
        "https://api.github.com/webhook",
        "http://example.com:8080/events",
        "https://subdomain.example.org/path?param=1",
        "https://93.184.216.34/hook",    // example.com public IP
        "https://8.8.8.8:443/dns-query", // public DNS IP
    ];

    for url in valid_urls {
        let res = policy.validate_url(url);
        assert!(res.is_ok(), "expected {url} to be accepted, got {res:?}");
        let validated = res.unwrap();
        assert!(!validated.host().is_empty());
        assert!(validated.port() > 0);
    }
}

#[test]
fn ssrf_permissive_for_tests_allows_loopback_but_still_blocks_metadata_and_private() {
    let test_policy = SsrfPolicy::PERMISSIVE_FOR_TESTS;

    // Loopback allowed in test policy:
    assert!(
        test_policy
            .validate_url("http://127.0.0.1:8080/hook")
            .is_ok()
    );
    assert!(
        test_policy
            .validate_url("http://localhost:3000/webhook")
            .is_ok()
    );
    assert!(test_policy.validate_url("http://[::1]:9999/hook").is_ok());

    // BUT metadata and private are STILL strictly blocked!
    assert!(matches!(
        test_policy.validate_url("http://169.254.169.254/metadata"),
        Err(WebhookRefusal::SsrfBlocked { .. })
    ));
    assert!(matches!(
        test_policy.validate_url("http://10.1.2.3/hook"),
        Err(WebhookRefusal::SsrfBlocked { .. })
    ));
    assert!(matches!(
        test_policy.validate_url("http://192.168.1.1/hook"),
        Err(WebhookRefusal::SsrfBlocked { .. })
    ));
}

#[test]
fn ssrf_redirect_validation_blocks_redirect_to_internal_ip() {
    let policy = SsrfPolicy::STRICT;
    let initial = policy
        .validate_url("https://example.com/api/v1/hook")
        .unwrap();

    // Redirect to internal IP must be blocked:
    assert!(matches!(
        policy.validate_redirect(&initial, "http://127.0.0.1/admin"),
        Err(WebhookRefusal::SsrfBlocked { .. })
    ));
    assert!(matches!(
        policy.validate_redirect(&initial, "http://169.254.169.254/latest"),
        Err(WebhookRefusal::SsrfBlocked { .. })
    ));
    assert!(matches!(
        policy.validate_redirect(&initial, "http://10.0.0.1/internal"),
        Err(WebhookRefusal::SsrfBlocked { .. })
    ));

    // Relative redirect on same host is safe:
    let rel = policy.validate_redirect(&initial, "/api/v2/hook").unwrap();
    assert_eq!(rel.host(), "example.com");
    assert_eq!(rel.path_and_query(), "/api/v2/hook");

    // Public external redirect is safe:
    let ext = policy
        .validate_redirect(&initial, "https://hooks.slack.com/services/123")
        .unwrap();
    assert_eq!(ext.host(), "hooks.slack.com");
}

#[test]
fn webhook_secret_signing_and_verification() {
    let secret = WebhookSecret::new(b"0123456789abcdef0123456789abcdef").unwrap();
    let payload = b"{\"event\":\"pull_request\",\"action\":\"opened\",\"number\":42}";

    let sig = secret.sign(payload);
    assert!(secret.verify(payload, &sig));

    // Tampered payload fails verification:
    let tampered = b"{\"event\":\"pull_request\",\"action\":\"opened\",\"number\":43}";
    assert!(!secret.verify(tampered, &sig));

    // Wrong secret fails verification:
    let other_secret = WebhookSecret::new(b"different_secret_key_1234567890").unwrap();
    assert!(!other_secret.verify(payload, &sig));

    // Hex signature generation and verification:
    let hex_sig = secret.sign_hex(payload);
    assert!(hex_sig.starts_with("sha256="));
    let rotation = WebhookSecretRotation::new(secret);
    assert!(rotation.verify_hex(payload, &hex_sig, 1000));
}

#[test]
fn webhook_secret_rotation_window() {
    let old_secret = WebhookSecret::new(b"old_secret_bytes_12345678901234").unwrap();
    let new_secret = WebhookSecret::new(b"new_secret_bytes_12345678901234").unwrap();

    let mut rotation = WebhookSecretRotation::new(old_secret.clone());
    let payload = b"hello webhook";

    let old_sig = old_secret.sign(payload);
    let new_sig = new_secret.sign(payload);

    let t0 = 1_000_000u64;
    let window_secs = 300u64; // 5 minute rotation window

    // Rotate to new secret at t0:
    rotation.rotate(new_secret, window_secs, t0);

    // During window (e.g. t0 + 100s): BOTH old and new signatures verify!
    assert!(rotation.verify(payload, &old_sig, t0 + 100));
    assert!(rotation.verify(payload, &new_sig, t0 + 100));

    // Exactly at window boundary (t0 + 300s): both still verify:
    assert!(rotation.verify(payload, &old_sig, t0 + 300));
    assert!(rotation.verify(payload, &new_sig, t0 + 300));

    // After window expires (t0 + 301s): old signature FAILS, new signature SUCCEEDS:
    assert!(!rotation.verify(payload, &old_sig, t0 + 301));
    assert!(rotation.verify(payload, &new_sig, t0 + 301));
}

#[test]
fn webhook_retry_schedule_exponential_backoff_and_jitter() {
    let schedule =
        WebhookRetrySchedule::new(5, Duration::from_secs(1), Duration::from_secs(30)).unwrap();

    // Attempt 1 delay is 0:
    assert_eq!(schedule.delay_for_attempt(1, 42), Duration::ZERO);

    // Attempt 2 base is 1s, with jitter [-20%, +20%] -> [800ms, 1200ms]
    let d2 = schedule.delay_for_attempt(2, 42);
    assert!(
        d2 >= Duration::from_millis(800) && d2 <= Duration::from_millis(1200),
        "d2 was {d2:?}"
    );

    // Attempt 3 base is 2s -> [1600ms, 2400ms]
    let d3 = schedule.delay_for_attempt(3, 42);
    assert!(
        d3 >= Duration::from_millis(1600) && d3 <= Duration::from_millis(2400),
        "d3 was {d3:?}"
    );

    // Attempt 4 base is 4s -> [3200ms, 4800ms]
    let d4 = schedule.delay_for_attempt(4, 42);
    assert!(
        d4 >= Duration::from_millis(3200) && d4 <= Duration::from_millis(4800),
        "d4 was {d4:?}"
    );

    // Attempt 5 base is 8s -> [6400ms, 9600ms]
    let d5 = schedule.delay_for_attempt(5, 42);
    assert!(
        d5 >= Duration::from_millis(6400) && d5 <= Duration::from_millis(9600),
        "d5 was {d5:?}"
    );

    // Deterministic with same seed and attempt:
    assert_eq!(
        schedule.delay_for_attempt(3, 42),
        schedule.delay_for_attempt(3, 42)
    );
}

#[test]
fn webhook_event_filter() {
    let wildcard = WebhookEventFilter::Wildcard;
    assert!(wildcard.matches("pull_request"));
    assert!(wildcard.matches("push"));
    assert!(wildcard.matches("issue"));

    let selected = WebhookEventFilter::Selected(vec!["pull_request".into(), "push".into()]);
    assert!(selected.matches("pull_request"));
    assert!(selected.matches("PULL_REQUEST")); // case-insensitive
    assert!(selected.matches("push"));
    assert!(!selected.matches("issue"));
    assert!(!selected.matches("release"));
}
