use super::*;
use crate::webhook::{DeadLetterQueue, WebhookDeliveryDestination};
use fgit_forge::ForgeEventBatch;
use fgit_forge::webhook::{
    SsrfPolicy, WebhookEventFilter, WebhookRetrySchedule, WebhookSecret, WebhookSecretRotation,
};
use fgit_resource::settlement::{DeliveryVerdict, ProbeVerdict};
use fgit_types::{DigestAlgorithmId, DigestBytes, RefusalCode};

fn root(byte: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(1).unwrap(),
        DigestBytes::try_new(&[byte; 32]).unwrap(),
    )
}

fn registration(url: &str) -> WebhookRegistration {
    WebhookRegistration {
        id: WebhookId(1),
        url: SsrfPolicy::PERMISSIVE_FOR_TESTS.validate_url(url).unwrap(),
        secrets: WebhookSecretRotation::new(
            WebhookSecret::new(b"0123456789abcdef0123456789abcdef").unwrap(),
        ),
        filter: WebhookEventFilter::Wildcard,
        active: true,
        retry_schedule: WebhookRetrySchedule::default(),
    }
}

fn request<'a>(key: &'static str, events: &'a ForgeEventBatch) -> DeliveryRequest<'a> {
    DeliveryRequest {
        key: AsciiSlug::from_static(key),
        destination: AsciiSlug::from_static("test-webhook"),
        payload_root: root(1),
        events,
    }
}

fn destination(url: &str) -> WebhookDeliveryDestination {
    WebhookDeliveryDestination::new(
        AsciiSlug::from_static("test-webhook"),
        registration(url),
        SsrfPolicy::PERMISSIVE_FOR_TESTS,
        DeadLetterQueue::new(),
    )
}

#[test]
fn acknowledgement_binds_key_payload_destination_registration_and_url() {
    let events = ForgeEventBatch { events: Vec::new() };
    let mut request = request("binding", &events);
    let mut registration = registration("http://example.com/hook");
    let mut receipts = Acknowledgements::<2>::default();
    assert!(!receipts.contains(&request, &registration));
    assert!(receipts.remember(&request, &registration));
    assert!(receipts.contains(&request, &registration));

    request.key = AsciiSlug::from_static("other-key");
    assert!(!receipts.contains(&request, &registration));
    request.key = AsciiSlug::from_static("binding");
    request.payload_root = root(2);
    assert!(!receipts.contains(&request, &registration));
    request.payload_root = root(1);
    request.destination = AsciiSlug::from_static("other-webhook");
    assert!(!receipts.contains(&request, &registration));
    request.destination = AsciiSlug::from_static("test-webhook");
    registration.id = WebhookId(2);
    assert!(!receipts.contains(&request, &registration));
    registration.id = WebhookId(1);
    registration.url = SsrfPolicy::PERMISSIVE_FOR_TESTS
        .validate_url("http://example.com/reconfigured")
        .unwrap();
    assert!(!receipts.contains(&request, &registration));
    registration.url = SsrfPolicy::PERMISSIVE_FOR_TESTS
        .validate_url("http://example.com/hook")
        .unwrap();
    assert!(receipts.contains(&request, &registration));
}

#[test]
fn acknowledgement_cache_evicts_oldest_and_repeated_ack_refreshes_without_growth() {
    let events = ForgeEventBatch { events: Vec::new() };
    let registration = registration("http://example.com/hook");
    let a = request("ack-a", &events);
    let b = request("ack-b", &events);
    let c = request("ack-c", &events);
    let mut receipts = Acknowledgements::<2>::default();
    assert!(receipts.remember(&a, &registration));
    assert!(receipts.remember(&b, &registration));
    for _ in 0..100 {
        assert!(receipts.remember(&a, &registration));
        assert_eq!(receipts.entries.len(), 2);
    }
    assert!(receipts.remember(&c, &registration));
    assert_eq!(receipts.entries.len(), 2);
    assert!(receipts.contains(&a, &registration));
    assert!(!receipts.contains(&b, &registration));
    assert!(receipts.contains(&c, &registration));
}

#[test]
fn acknowledgement_cache_zero_capacity_retains_no_evidence() {
    let events = ForgeEventBatch { events: Vec::new() };
    let registration = registration("http://example.com/hook");
    let request = request("uncached", &events);
    let mut receipts = Acknowledgements::<0>::default();
    assert!(!receipts.remember(&request, &registration));
    assert!(!receipts.contains(&request, &registration));
    assert!(receipts.entries.is_empty());
}

#[test]
fn same_key_different_payload_never_hits_the_old_receipt() {
    let events = ForgeEventBatch { events: Vec::new() };
    let dest = destination("http://example.com/hook");
    let mut request = request("same-key", &events);
    dest.remember_acknowledgement(&request, 1);
    assert_eq!(
        dest.probe_acknowledgement(&request),
        Ok(ProbeVerdict::Delivered)
    );
    request.payload_root = root(2);
    assert_eq!(
        dest.probe_acknowledgement(&request),
        Ok(ProbeVerdict::Unknown)
    );
}

#[test]
fn public_diagnostic_injection_cannot_authorize_a_probe() {
    let events = ForgeEventBatch { events: Vec::new() };
    let dest = destination("http://example.com/hook");
    let request = request("not-actually-acknowledged", &events);
    dest.acknowledged.lock().unwrap().push((request.key, 1));
    assert_eq!(
        dest.probe_acknowledgement(&request),
        Ok(ProbeVerdict::Unknown)
    );
}

#[test]
fn probe_refuses_a_different_destination_even_when_diagnostics_contain_the_key() {
    let events = ForgeEventBatch { events: Vec::new() };
    let dest = destination("http://example.com/hook");
    let mut request = request("wrong-destination", &events);
    dest.remember_acknowledgement(&request, 1);
    request.destination = AsciiSlug::from_static("other-webhook");
    assert_eq!(
        dest.probe_acknowledgement(&request),
        Err(RefusalCode::PublicationPolicyRefused)
    );
}

#[test]
fn reconfiguration_and_restart_do_not_inherit_receipts_for_a_different_receiver() {
    let events = ForgeEventBatch { events: Vec::new() };
    let mut dest = destination("http://example.com/hook");
    let request = request("reconfigured", &events);
    dest.remember_acknowledgement(&request, 1);
    dest.registration = registration("http://example.com/new-hook");
    assert_eq!(
        dest.probe_acknowledgement(&request),
        Ok(ProbeVerdict::Unknown)
    );
    dest.registration = registration("http://example.com/hook");
    assert_eq!(
        dest.probe_acknowledgement(&request),
        Ok(ProbeVerdict::Delivered)
    );
    let restarted = destination("http://example.com/hook");
    assert_eq!(
        restarted.probe_acknowledgement(&request),
        Ok(ProbeVerdict::Unknown)
    );
}

#[test]
fn diagnostic_history_is_bounded_and_retries_replace_the_same_entry() {
    let events = ForgeEventBatch { events: Vec::new() };
    let dest = destination("http://example.com/hook");
    let request = request("latest", &events);
    // The legacy public diagnostics may have been filled by an old caller.
    dest.acknowledged.lock().unwrap().resize(
        MAX_ACKNOWLEDGEMENTS + 10,
        (AsciiSlug::from_static("old"), 1),
    );
    dest.remember_acknowledgement(&request, 1);
    assert_eq!(
        dest.acknowledged.lock().unwrap().len(),
        MAX_ACKNOWLEDGEMENTS
    );
    for attempt in 2..10 {
        dest.remember_acknowledgement(&request, attempt);
    }
    let diagnostics = dest.acknowledged.lock().unwrap();
    assert_eq!(diagnostics.len(), MAX_ACKNOWLEDGEMENTS);
    assert_eq!(diagnostics.last(), Some(&(request.key, 9)));
    assert_eq!(
        diagnostics
            .iter()
            .filter(|(key, _)| *key == request.key)
            .count(),
        1
    );
}

#[test]
fn poisoned_receipt_cache_is_unknown_without_panicking_or_claiming_rejection() {
    let events = ForgeEventBatch { events: Vec::new() };
    let dest = destination("http://example.com/hook");
    let request = request("poisoned-cache", &events);
    dest.remember_acknowledgement(&request, 1);
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = dest.receipts.lock().unwrap();
        panic!("simulate a failed cache owner");
    }));
    assert!(poisoned.is_err());
    assert_eq!(
        dest.probe_acknowledgement(&request),
        Ok(ProbeVerdict::Unknown)
    );
    dest.remember_acknowledgement(&request, 2);
    assert_eq!(
        dest.probe_acknowledgement(&request),
        Ok(ProbeVerdict::Unknown)
    );
}

#[test]
fn actual_http_ack_stays_accepted_with_poisoned_diagnostics_and_binds_the_payload() {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "http://127.0.0.1:{}/hook",
        listener.local_addr().unwrap().port()
    );
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut reader = BufReader::new(&mut stream);
        let mut length = None;
        loop {
            let mut line = String::new();
            assert_ne!(reader.read_line(&mut line).unwrap(), 0);
            if line == "\r\n" {
                break;
            }
            if let Some(value) = line.strip_prefix("Content-Length:") {
                length = Some(value.trim().parse::<usize>().unwrap());
            }
        }
        let mut body = vec![0; length.unwrap()];
        reader.read_exact(&mut body).unwrap();
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
            .unwrap();
    });
    let dest = destination(&url);
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = dest.acknowledged.lock().unwrap();
        panic!("simulate a diagnostic consumer panic");
    }));
    assert!(poisoned.is_err());
    let events = ForgeEventBatch { events: Vec::new() };
    let mut request = request("actual-ack", &events);
    request.payload_root = fgit_admission::evidence::evidence_root(&events).unwrap();
    let result = dest.dispatch_http(&request, 1);
    server.join().unwrap();
    assert_eq!(result.unwrap().0, DeliveryVerdict::Accepted);
    assert_eq!(
        dest.probe_acknowledgement(&request),
        Ok(ProbeVerdict::Delivered)
    );
    request.payload_root = root(99);
    assert_eq!(
        dest.probe_acknowledgement(&request),
        Ok(ProbeVerdict::Unknown)
    );
    assert!(dest.dead_letters.list().is_empty());
}

#[test]
fn production_capacity_remains_bounded_during_distinct_receipt_churn() {
    let events = ForgeEventBatch { events: Vec::new() };
    let registration = registration("http://example.com/hook");
    let mut request = request("churn", &events);
    let mut receipts = Acknowledgements::<MAX_ACKNOWLEDGEMENTS>::default();
    for sequence in 0..(MAX_ACKNOWLEDGEMENTS * 2) {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&(sequence as u64).to_le_bytes());
        request.payload_root = Digest::new(
            DigestAlgorithmId::try_new(1).unwrap(),
            DigestBytes::try_new(&bytes).unwrap(),
        );
        assert!(receipts.remember(&request, &registration));
        assert!(receipts.entries.len() <= MAX_ACKNOWLEDGEMENTS);
        assert!(receipts.contains(&request, &registration));
    }
    assert_eq!(receipts.entries.len(), MAX_ACKNOWLEDGEMENTS);
    request.payload_root = root(0);
    assert!(!receipts.contains(&request, &registration));
}

#[test]
fn oversized_url_is_not_cached_and_does_not_evict_existing_evidence() {
    let events = ForgeEventBatch { events: Vec::new() };
    let request = request("bounded-url", &events);
    let mut registration = registration("http://example.com/hook");
    let mut receipts = Acknowledgements::<1>::default();
    assert!(receipts.remember(&request, &registration));
    let raw = format!("http://example.com/{}", "x".repeat(MAX_ACK_URL_BYTES));
    registration.url = fgit_forge::webhook::ValidatedWebhookUrl::new_unchecked_for_testing(
        &raw,
        "http",
        "example.com",
        80,
        "/hook",
        None,
    );
    assert!(!receipts.remember(&request, &registration));
    assert!(!receipts.contains(&request, &registration));
    assert_eq!(receipts.entries.len(), 1);
    registration.url = SsrfPolicy::PERMISSIVE_FOR_TESTS
        .validate_url("http://example.com/hook")
        .unwrap();
    assert!(receipts.contains(&request, &registration));
}
