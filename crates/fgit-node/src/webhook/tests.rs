use super::*;
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::thread;

use fgit_forge::ForgeEventBatch;
use fgit_forge::webhook::{
    WebhookEventFilter, WebhookId, WebhookRetrySchedule, WebhookSecret, WebhookSecretRotation,
};
use fgit_types::{Digest, DigestAlgorithmId, DigestBytes};

fn dummy_digest() -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(1).unwrap(),
        DigestBytes::try_new(&[0xaa; 32]).unwrap(),
    )
}

fn test_secret() -> WebhookSecret {
    WebhookSecret::new(b"0123456789abcdef0123456789abcdef").unwrap()
}

fn test_registration(url_str: &str, ssrf_policy: SsrfPolicy) -> WebhookRegistration {
    let url = ssrf_policy.validate_url(url_str).unwrap();
    let secret = test_secret();
    WebhookRegistration {
        id: WebhookId(1),
        url,
        secrets: WebhookSecretRotation::new(secret),
        filter: WebhookEventFilter::Wildcard,
        active: true,
        retry_schedule: WebhookRetrySchedule::default(),
    }
}

#[test]
fn webhook_delivery_successful_acknowledgement_and_signature_verification() {
    // 1. Start a local loopback server to act as the webhook receiver
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_addr = listener.local_addr().unwrap();

    let secret = test_secret();
    let secret_clone = secret.clone();

    let server_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(&mut stream);
        let mut headers = Vec::new();
        let mut content_length = 0usize;
        let mut signature_header = String::new();
        let mut delivery_header = String::new();

        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let trimmed = line.trim();
            if trimmed.is_empty() {
                break;
            }
            if let Some(val) = trimmed.strip_prefix("Content-Length:") {
                content_length = val.trim().parse().unwrap();
            }
            if let Some(val) = trimmed.strip_prefix("X-FrankenGit-Signature-256:") {
                signature_header = val.trim().to_string();
            }
            if let Some(val) = trimmed.strip_prefix("X-FrankenGit-Delivery:") {
                delivery_header = val.trim().to_string();
            }
            headers.push(trimmed.to_string());
        }

        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body).unwrap();

        // Verify the received HMAC signature against the secret
        let hex_tag = signature_header.strip_prefix("sha256=").unwrap();
        let sig_bytes = hex::decode(hex_tag).unwrap();
        let mut sig_arr = [0u8; 32];
        sig_arr.copy_from_slice(&sig_bytes);
        assert!(secret_clone.verify(&body, &sig_arr));
        assert_eq!(delivery_header, "delivery-123");

        // Respond with HTTP 200 OK
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"status\":\"ok\"}";
        stream.write_all(response.as_bytes()).unwrap();
        stream.flush().unwrap();
    });

    // 2. Dispatch webhook delivery
    let url_str = format!("http://127.0.0.1:{}/hook", server_addr.port());
    let reg = test_registration(&url_str, SsrfPolicy::PERMISSIVE_FOR_TESTS);
    let dead_letters = DeadLetterQueue::new();
    let dest = WebhookDeliveryDestination::new(
        AsciiSlug::from_static("test-webhook"),
        reg,
        SsrfPolicy::PERMISSIVE_FOR_TESTS,
        dead_letters.clone(),
    );

    let empty_events = ForgeEventBatch { events: Vec::new() };
    let request = DeliveryRequest {
        key: AsciiSlug::from_static("delivery-123"),
        destination: AsciiSlug::from_static("test-webhook"),
        payload_root: dummy_digest(),
        events: &empty_events,
    };

    let result = dest.dispatch_http(&request, 1).unwrap();
    assert_eq!(result.0, DeliveryVerdict::Accepted);
    assert_eq!(dead_letters.list().len(), 0);

    server_handle.join().unwrap();
}

#[test]
fn webhook_duplicate_delivery_reports_duplicate_suppressed() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(&mut stream);
        let mut line = String::new();
        while reader.read_line(&mut line).is_ok() {
            if line.trim().is_empty() {
                break;
            }
            line.clear();
        }
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
        stream.write_all(response.as_bytes()).unwrap();
        stream.flush().unwrap();
    });

    let url_str = format!("http://127.0.0.1:{}/hook", server_addr.port());
    let reg = test_registration(&url_str, SsrfPolicy::PERMISSIVE_FOR_TESTS);
    let dead_letters = DeadLetterQueue::new();
    let dest = WebhookDeliveryDestination::new(
        AsciiSlug::from_static("test-webhook"),
        reg,
        SsrfPolicy::PERMISSIVE_FOR_TESTS,
        dead_letters,
    );

    let empty_events = ForgeEventBatch { events: Vec::new() };
    let request = DeliveryRequest {
        key: AsciiSlug::from_static("delivery-retry-1"),
        destination: AsciiSlug::from_static("test-webhook"),
        payload_root: dummy_digest(),
        events: &empty_events,
    };

    // Attempt 2 (retry) with 200 OK gives DuplicateSuppressed
    let result = dest.dispatch_http(&request, 2).unwrap();
    assert_eq!(result.0, DeliveryVerdict::DuplicateSuppressed);

    server_handle.join().unwrap();
}

#[test]
fn webhook_receiver_down_drill_retries_and_exhausts_to_dead_letter() {
    // Pick an unused port where nothing is listening
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener); // closed, connection will fail

    let url_str = format!("http://127.0.0.1:{port}/hook");
    let reg = test_registration(&url_str, SsrfPolicy::PERMISSIVE_FOR_TESTS);
    let dead_letters = DeadLetterQueue::new();
    let dest = WebhookDeliveryDestination::new(
        AsciiSlug::from_static("test-webhook"),
        reg,
        SsrfPolicy::PERMISSIVE_FOR_TESTS,
        dead_letters.clone(),
    );

    let empty_events = ForgeEventBatch { events: Vec::new() };
    let request = DeliveryRequest {
        key: AsciiSlug::from_static("delivery-down-1"),
        destination: AsciiSlug::from_static("test-webhook"),
        payload_root: dummy_digest(),
        events: &empty_events,
    };

    // Attempts 1 through 4 report TransientFailure (retriable)
    for attempt in 1..=4 {
        let result = dest.dispatch_http(&request, attempt).unwrap();
        assert_eq!(result.0, DeliveryVerdict::TransientFailure);
        assert_eq!(dead_letters.list().len(), 0);
    }

    // Attempt 5 (max_attempts = 5) reports PermanentRejection and lands in DeadLetterQueue!
    let terminal_result = dest.dispatch_http(&request, 5).unwrap();
    assert_eq!(terminal_result.0, DeliveryVerdict::PermanentRejection);

    let dl = dead_letters.list();
    assert_eq!(dl.len(), 1);
    assert_eq!(dl[0].delivery_id, AsciiSlug::from_static("delivery-down-1"));
    assert_eq!(dl[0].attempts, 5);
}

#[test]
fn webhook_ssrf_blocked_target_immediately_rejects_and_dead_letters() {
    // Attempting to deliver to metadata service under strict policy
    let url = ValidatedWebhookUrl::new_unchecked_for_testing(
        "http://169.254.169.254/latest/meta-data",
        "http",
        "169.254.169.254",
        80,
        "/latest/meta-data",
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(169, 254, 169, 254))),
    );
    let reg = WebhookRegistration {
        id: WebhookId(99),
        url,
        secrets: WebhookSecretRotation::new(test_secret()),
        filter: WebhookEventFilter::Wildcard,
        active: true,
        retry_schedule: WebhookRetrySchedule::default(),
    };
    let dead_letters = DeadLetterQueue::new();
    let dest = WebhookDeliveryDestination::new(
        AsciiSlug::from_static("test-webhook"),
        reg,
        SsrfPolicy::STRICT,
        dead_letters.clone(),
    );

    let empty_events = ForgeEventBatch { events: Vec::new() };
    let request = DeliveryRequest {
        key: AsciiSlug::from_static("delivery-ssrf-1"),
        destination: AsciiSlug::from_static("test-webhook"),
        payload_root: dummy_digest(),
        events: &empty_events,
    };

    let result = dest.dispatch_http(&request, 1).unwrap();
    assert_eq!(result.0, DeliveryVerdict::PermanentRejection);

    let dl = dead_letters.list();
    assert_eq!(dl.len(), 1);
    assert_eq!(dl[0].delivery_id, AsciiSlug::from_static("delivery-ssrf-1"));
    assert!(dl[0].terminal_reason.contains("private or local range"));
}

#[test]
fn webhook_store_persists_registrations_and_dead_letters() {
    let store_dir = std::env::temp_dir().join(format!(
        "fg-webhook-store-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&store_dir);

    let store = WebhookStore::open(store_dir.clone()).unwrap();
    let reg = test_registration("http://example.com/webhook", SsrfPolicy::STRICT);
    store.register(reg.clone()).unwrap();

    let dl = DeadLetterEntry {
        delivery_id: AsciiSlug::from_static("test-dl-1"),
        webhook_id: reg.id,
        target_url: "http://example.com/webhook".into(),
        payload_root: dummy_digest(),
        event_name: "forge_event".into(),
        attempts: 5,
        terminal_reason: "connection timeout".into(),
        failed_at_unix_secs: 1000,
    };
    store.dead_letters().push(dl);

    // Reopen store from same directory and verify persistence
    let reopened = WebhookStore::open(store_dir.clone()).unwrap();
    let regs = reopened.list();
    assert_eq!(regs.len(), 1);
    assert_eq!(regs[0].id, reg.id);
    assert_eq!(regs[0].url.raw(), "http://example.com/webhook");

    let dead = reopened.list_dead_letters();
    assert_eq!(dead.len(), 1);
    assert_eq!(dead[0].delivery_id, AsciiSlug::from_static("test-dl-1"));
    assert_eq!(dead[0].attempts, 5);

    // Replay dead letter
    let replayed = reopened.replay_dead_letter(AsciiSlug::from_static("test-dl-1"));
    assert!(replayed.is_some());
    assert_eq!(reopened.list_dead_letters().len(), 0);

    let _ = std::fs::remove_dir_all(&store_dir);
}

mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if s.len() % 2 != 0 {
            return Err(());
        }
        let mut bytes = Vec::with_capacity(s.len() / 2);
        for i in (0..s.len()).step_by(2) {
            let byte = u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ())?;
            bytes.push(byte);
        }
        Ok(bytes)
    }
}
