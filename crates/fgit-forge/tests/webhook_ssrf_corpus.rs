//! Comprehensive adversarial SSRF corpus, secret rotation, and retry schedule test suite (FG-046b).

use fgit_forge::webhook::{SsrfPolicy, WebhookRetrySchedule, WebhookSecret, WebhookSecretRotation};
use std::time::Duration;

#[test]
fn ssrf_corpus_blocks_all_metadata_targets() {
    let policy = SsrfPolicy::STRICT;
    let metadata_probes = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254:80/latest/user-data",
        "https://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://[::ffff:169.254.169.254]/latest/meta-data/",
        "http://[::ffff:a9fe:a9fe]/latest/meta-data/",
        "http://2852039166/latest/meta-data/", // decimal 169.254.169.254
        "http://0xa9fea9fe/latest/meta-data/", // hex 169.254.169.254
        "http://0251.0376.0251.0376/latest/meta-data/", // octal 169.254.169.254
    ];

    for probe in metadata_probes {
        let result = policy.validate_url(probe);
        assert!(
            result.is_err(),
            "probe {probe} must be blocked under strict policy"
        );
    }
}

#[test]
fn ssrf_corpus_blocks_all_private_and_loopback_ipv4() {
    let policy = SsrfPolicy::STRICT;
    let private_probes = [
        // 127.0.0.0/8 loopback
        "http://127.0.0.1/hook",
        "http://127.0.0.2:8080/",
        "http://127.255.255.255/",
        "http://2130706433/", // decimal 127.0.0.1
        "http://0x7f000001/", // hex 127.0.0.1
        "http://0177.0.0.1/", // octal
        // 10.0.0.0/8 private
        "http://10.0.0.1/",
        "http://10.255.255.254:3000/",
        "http://167772161/",  // decimal 10.0.0.1
        "http://0x0a000001/", // hex 10.0.0.1
        // 172.16.0.0/12 private
        "http://172.16.0.1/",
        "http://172.31.255.254:9000/",
        // 192.168.0.0/16 private
        "http://192.168.0.1/",
        "http://192.168.1.254:8443/",
        // 0.0.0.0/8 current network
        "http://0.0.0.0:8000/",
        // 100.64.0.0/10 Carrier Grade NAT (RFC 6598)
        "http://100.64.0.1/",
        "http://100.127.255.254/",
        // 192.0.2.0/24 TEST-NET-1 (RFC 5737)
        "http://192.0.2.1/",
        // 198.51.100.0/24 TEST-NET-2
        "http://198.51.100.1/",
        // 203.0.113.0/24 TEST-NET-3
        "http://203.0.113.1/",
        // 224.0.0.0/4 Multicast
        "http://224.0.0.1/",
        // 240.0.0.0/4 Reserved
        "http://240.0.0.1/",
    ];

    for probe in private_probes {
        let result = policy.validate_url(probe);
        assert!(
            result.is_err(),
            "private probe {probe} must be blocked under strict policy"
        );
    }
}

#[test]
fn ssrf_corpus_blocks_all_forbidden_ipv6_addresses() {
    let policy = SsrfPolicy::STRICT;
    let ipv6_probes = [
        "http://[::1]/",                    // Loopback
        "http://[::]/",                     // Unspecified
        "http://[fc00::1]/",                // Unique local address (ULA)
        "http://[fd12:3456:789a:1::1]/",    // ULA
        "http://[fe80::1]/",                // Link-local
        "http://[ff02::1]/",                // Multicast
        "http://[2001:db8::1]/",            // Documentation
        "http://[::ffff:127.0.0.1]/",       // IPv4-mapped loopback
        "http://[::ffff:10.0.0.1]/",        // IPv4-mapped private
        "http://[::ffff:172.16.0.1]/",      // IPv4-mapped private
        "http://[::ffff:192.168.1.1]/",     // IPv4-mapped private
        "http://[::ffff:169.254.169.254]/", // IPv4-mapped metadata
        "http://[64:ff9b::127.0.0.1]/",     // NAT64 prefix
        "http://[2002:7f00:1::1]/",         // 6to4 prefix embedding 127.0.0.1
        "http://[2002:0a00:0001::]/",       // 6to4 prefix embedding 10.0.0.1
        "http://[100::1]/",                 // Discard-only prefix (RFC 6666)
    ];

    for probe in ipv6_probes {
        let result = policy.validate_url(probe);
        assert!(
            result.is_err(),
            "ipv6 probe {probe} must be blocked under strict policy"
        );
    }
}

#[test]
fn ssrf_corpus_blocks_embedded_credentials_and_unsupported_schemes() {
    let policy = SsrfPolicy::STRICT;

    // Embedded credentials
    assert!(
        policy
            .validate_url("http://user:pass@example.com/webhook")
            .is_err()
    );
    assert!(policy.validate_url("https://token@example.com/").is_err());
    assert!(
        policy
            .validate_url("http://admin:secret@127.0.0.1/")
            .is_err()
    );

    // Unsupported schemes
    assert!(policy.validate_url("file:///etc/passwd").is_err());
    assert!(policy.validate_url("gopher://127.0.0.1:70/").is_err());
    assert!(policy.validate_url("ftp://example.com/").is_err());
    assert!(policy.validate_url("ssh://example.com/").is_err());
    assert!(policy.validate_url("javascript:alert(1)").is_err());

    // Invalid ports
    assert!(policy.validate_url("http://example.com:0/").is_err());
    assert!(policy.validate_url("http://example.com:65536/").is_err());

    // Empty and oversized URLs
    assert!(policy.validate_url("").is_err());
    let oversized = format!("http://example.com/{}", "a".repeat(5000));
    assert!(policy.validate_url(&oversized).is_err());
}

#[test]
fn ssrf_corpus_accepts_valid_public_targets() {
    let policy = SsrfPolicy::STRICT;
    let valid_targets = [
        "https://api.github.com/webhook",
        "http://webhook.site/test",
        "https://events.example.org:8443/listener",
        "http://93.184.216.34/hook", // example.com IPv4
        "https://[2606:2800:220:1:248:1893:25c8:1946]/hook", // example.com IPv6
    ];

    for target in valid_targets {
        let result = policy.validate_url(target);
        assert!(
            result.is_ok(),
            "valid public target {target} should be accepted"
        );
    }
}

#[test]
fn ssrf_corpus_redirect_validation() {
    let policy = SsrfPolicy::STRICT;
    let current = policy.validate_url("https://api.example.com/hook").unwrap();

    // Redirect to metadata -> BLOCKED
    let r1 = policy.validate_redirect(&current, "http://169.254.169.254/latest/meta-data");
    assert!(r1.is_err());

    // Redirect to loopback -> BLOCKED
    let r2 = policy.validate_redirect(&current, "http://127.0.0.1:8080/hook");
    assert!(r2.is_err());

    // Redirect to private RFC 1918 -> BLOCKED
    let r3 = policy.validate_redirect(&current, "http://10.0.0.5/");
    assert!(r3.is_err());

    // Valid public redirect -> ACCEPTED
    let r4 = policy.validate_redirect(&current, "https://api2.example.com/hook_v2");
    assert!(r4.is_ok());

    // Valid relative redirect on the same host -> ACCEPTED
    let r5 = policy.validate_redirect(&current, "/hook_new_path");
    assert!(r5.is_ok());
    assert_eq!(r5.unwrap().path_and_query(), "/hook_new_path");
}

#[test]
fn dual_secret_rotation_window_full_lifecycle() {
    let secret_v1 = WebhookSecret::new(b"0123456789abcdef0123456789abcdef").unwrap();
    let secret_v2 = WebhookSecret::new(b"fedcba9876543210fedcba9876543210").unwrap();

    let mut rotation = WebhookSecretRotation::new(secret_v1.clone());
    let payload = b"{\"event\":\"merge_committed\",\"id\":42}";

    // 1. Initial state: v1 validates, v2 fails
    let sig_v1 = secret_v1.sign_hex(payload);
    let sig_v2 = secret_v2.sign_hex(payload);
    assert!(rotation.verify_hex(payload, &sig_v1, 1000));
    assert!(!rotation.verify_hex(payload, &sig_v2, 1000));

    // 2. Rotate to v2 with a 3600-second window (expires at timestamp 4600)
    rotation.rotate(secret_v2, 3600, 1000);

    // 3. During rotation window (ts = 2000): BOTH v1 and v2 validate!
    assert!(rotation.verify_hex(payload, &sig_v1, 2000));
    assert!(rotation.verify_hex(payload, &sig_v2, 2000));

    // At exact boundary (ts = 4600): BOTH still validate
    assert!(rotation.verify_hex(payload, &sig_v1, 4600));
    assert!(rotation.verify_hex(payload, &sig_v2, 4600));

    // 4. After rotation window expires (ts = 4601): old secret v1 FAILS, active v2 SUCCEEDS
    assert!(!rotation.verify_hex(payload, &sig_v1, 4601));
    assert!(rotation.verify_hex(payload, &sig_v2, 4601));
}

#[test]
fn retry_schedule_exponential_backoff_bounds_and_jitter() {
    let schedule = WebhookRetrySchedule {
        max_attempts: 5,
        initial_delay: Duration::from_millis(500),
        max_delay: Duration::from_secs(30),
    };

    // Attempt 1: zero delay
    assert_eq!(schedule.delay_for_attempt(1, 12345), Duration::ZERO);

    // Attempt 2 base is 500ms; with [-20%, +20%] jitter it must be in [400ms, 600ms]
    let d2 = schedule.delay_for_attempt(2, 12345);
    assert!(d2.as_millis() >= 400 && d2.as_millis() <= 600);

    // Attempt 3 base is 1000ms; in [800ms, 1200ms]
    let d3 = schedule.delay_for_attempt(3, 12345);
    assert!(d3.as_millis() >= 800 && d3.as_millis() <= 1200);

    // Attempt 4 base is 2000ms; in [1600ms, 2400ms]
    let d4 = schedule.delay_for_attempt(4, 12345);
    assert!(d4.as_millis() >= 1600 && d4.as_millis() <= 2400);

    // Delay is strictly bounded by max_delay (30s) even for high attempt count
    let d10 = schedule.delay_for_attempt(10, 12345);
    assert!(d10 <= Duration::from_secs(36)); // 30s + 20% max jitter
}
