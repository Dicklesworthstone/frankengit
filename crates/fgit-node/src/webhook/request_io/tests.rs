use super::*;
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use fgit_admission::merge::native::settlement::DeliveryRequest;
use fgit_forge::webhook::{
    SsrfPolicy, WebhookEventFilter, WebhookId, WebhookRegistration,
    WebhookRetrySchedule, WebhookSecret, WebhookSecretRotation,
};
use fgit_forge::ForgeEventBatch;
use fgit_types::{AsciiSlug, Digest, DigestAlgorithmId, DigestBytes};

use crate::webhook::{DeadLetterQueue, WebhookDeliveryDestination};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const HEADER: &[u8] = b"POST /hook HTTP/1.1\r\nContent-Length: 4\r\n\r\n";
const BODY: &[u8] = b"test";

fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect_timeout(&listener.local_addr().unwrap(), TEST_TIMEOUT).unwrap();
    let (server, _) = listener.accept().unwrap();
    server.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    server.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();
    (client, server)
}

fn read_exact_request(server: &mut TcpStream, header: &[u8], payload: &[u8]) {
    let mut observed = vec![0; header.len() + payload.len()];
    server.read_exact(&mut observed).unwrap();
    assert_eq!(&observed[..header.len()], header);
    assert_eq!(&observed[header.len()..], payload);
}

fn destination(listener: &TcpListener) -> WebhookDeliveryDestination {
    WebhookDeliveryDestination::new(
        AsciiSlug::from_static("deadline-test"),
        WebhookRegistration {
            id: WebhookId(1),
            url: SsrfPolicy::PERMISSIVE_FOR_TESTS
                .validate_url(&format!("http://{}/hook", listener.local_addr().unwrap()))
                .unwrap(),
            secrets: WebhookSecretRotation::new(WebhookSecret::new(vec![7; 32]).unwrap()),
            filter: WebhookEventFilter::Wildcard,
            active: true,
            retry_schedule: WebhookRetrySchedule::default(),
        },
        SsrfPolicy::PERMISSIVE_FOR_TESTS,
        DeadLetterQueue::new(),
    )
}

fn request(events: &ForgeEventBatch) -> DeliveryRequest<'_> {
    DeliveryRequest {
        key: AsciiSlug::from_static("deadline-delivery"),
        destination: AsciiSlug::from_static("deadline-test"),
        payload_root: Digest::new(
            DigestAlgorithmId::try_new(2).unwrap(),
            DigestBytes::try_new(&[7; 32]).unwrap(),
        ),
        events,
    }
}

#[test]
fn repeated_progress_cannot_renew_the_absolute_deadline() {
    let checkpoint = || Ok(());
    let attempt = Attempt::new(Duration::from_secs(10), &checkpoint).unwrap();
    let original_deadline = attempt.deadline;
    for seconds in (1..=10).rev() {
        let remaining = Duration::from_secs(seconds);
        assert_eq!(
            attempt.remaining_at(original_deadline - remaining),
            Ok(remaining)
        );
        assert_eq!(attempt.deadline, original_deadline);
    }
    assert_eq!(
        attempt.remaining_at(original_deadline),
        Err(RefusalCode::ResourceBudgetExceeded)
    );
    assert_eq!(
        attempt.remaining_at(original_deadline + Duration::from_millis(1)),
        Err(RefusalCode::ResourceBudgetExceeded)
    );
}

#[test]
fn invalid_or_cancelled_budgets_refuse_at_construction() {
    let live = || Ok(());
    assert!(matches!(
        Attempt::new(Duration::ZERO, &live),
        Err(RefusalCode::ResourceBudgetExceeded)
    ));
    assert!(matches!(
        Attempt::new(Duration::MAX, &live),
        Err(RefusalCode::ResourceBudgetExceeded)
    ));
    assert!(matches!(
        Attempt::new(TEST_TIMEOUT, &|| Err(RefusalCode::CancellationInProgress)),
        Err(RefusalCode::CancellationInProgress)
    ));
}

#[test]
fn an_expired_attempt_writes_nothing_to_an_already_connected_socket() {
    let (mut client, mut server) = pair();
    let checkpoint = || Ok(());
    let mut attempt = Attempt::new(TEST_TIMEOUT, &checkpoint).unwrap();
    attempt.deadline = Instant::now();
    assert!(matches!(
        attempt.exchange(&mut client, HEADER, BODY),
        Err(Failure::Refused(RefusalCode::ResourceBudgetExceeded))
    ));
    drop(client);
    assert_eq!(server.read(&mut [0; 1]).unwrap(), 0);
}

#[test]
fn cancellation_is_checked_between_header_and_body_without_false_rejection() {
    let (mut client, mut server) = pair();
    let calls = std::cell::Cell::new(0);
    let checkpoint = || {
        let next = calls.get() + 1;
        calls.set(next);
        // Construction, timeout setup, header write, then body write.
        if next >= 4 {
            Err(RefusalCode::CancellationInProgress)
        } else {
            Ok(())
        }
    };
    let attempt = Attempt::new(TEST_TIMEOUT, &checkpoint).unwrap();
    let result = attempt.exchange(&mut client, HEADER, BODY);
    assert!(matches!(
        result,
        Err(Failure::Ambiguous(ref reason)) if reason.contains("CancellationInProgress")
    ));
    drop(client);
    let mut observed = Vec::new();
    server.read_to_end(&mut observed).unwrap();
    assert_eq!(observed.as_slice(), HEADER);
}

#[test]
fn public_precancelled_delivery_has_no_connection_or_diagnostic_side_effect() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let destination = destination(&listener);
    let events = ForgeEventBatch { events: Vec::new() };
    let failure = destination
        .deliver_request_with_checkpoint(&request(&events), 1, &|| {
            Err(RefusalCode::CancellationInProgress)
        })
        .unwrap_err();
    assert!(failure.contains("CancellationInProgress"));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(destination.dead_letters.list().is_empty());
    assert!(destination.acknowledged.lock().unwrap().is_empty());
}

#[test]
fn chunked_body_is_byte_identical_and_ack_does_not_wait_for_peer_eof() {
    let (mut client, mut server) = pair();
    let body = vec![0x81; WRITE_CHUNK_BYTES * 8 + 1];
    let expected = body.clone();
    let header = format!("POST /hook HTTP/1.1\r\nContent-Length: {}\r\n\r\n", body.len());
    let expected_header = header.clone();
    let peer = thread::spawn(move || {
        read_exact_request(&mut server, expected_header.as_bytes(), &expected);
        server.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap();
        // The peer will not send EOF first. The client must finish on the ACK
        // and close its socket rather than waiting for a response body.
        assert_eq!(server.read(&mut [0; 1]).unwrap(), 0);
    });
    let checkpoint = || Ok(());
    let response = Attempt::new(TEST_TIMEOUT, &checkpoint)
        .unwrap()
        .exchange(&mut client, header.as_bytes(), &body);
    drop(client);
    peer.join().unwrap();
    assert_eq!(super::super::parse_http_status(&response.unwrap()), Some(204));
}

#[test]
fn cancellation_after_body_transmission_keeps_public_outcome_ambiguous() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let destination = destination(&listener);
    let stopped = Arc::new(AtomicBool::new(false));
    let peer_stopped = stopped.clone();
    let peer = thread::spawn(move || {
        use std::io::{BufRead, BufReader};
        listener.set_nonblocking(true).unwrap();
        let accept_deadline = Instant::now() + TEST_TIMEOUT;
        let mut server = loop {
            match listener.accept() {
                Ok((server, _)) => break server,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < accept_deadline, "client never connected");
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("loopback accept failed: {error}"),
            }
        };
        server.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        let mut reader = BufReader::new(&mut server);
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
        drop(reader);
        peer_stopped.store(true, Ordering::SeqCst);
        // Cancellation must close the socket without requiring peer EOF.
        assert_eq!(server.read(&mut [0; 1]).unwrap(), 0);
    });
    let events = ForgeEventBatch { events: Vec::new() };
    let result = destination.deliver_request_with_checkpoint(&request(&events), 1, &|| {
        if stopped.load(Ordering::SeqCst) {
            Err(RefusalCode::CancellationInProgress)
        } else {
            Ok(())
        }
    });
    peer.join().unwrap();
    let (verdict, reason) = result.unwrap();
    assert_eq!(verdict, "AmbiguousTimeout");
    assert!(
        String::from_utf8(reason)
            .unwrap()
            .contains("CancellationInProgress")
    );
    assert!(destination.dead_letters.list().is_empty());
    assert!(destination.acknowledged.lock().unwrap().is_empty());
}

#[test]
fn trickling_headers_do_not_extend_the_attempt_deadline() {
    let (mut client, mut server) = pair();
    let peer = thread::spawn(move || {
        read_exact_request(&mut server, HEADER, BODY);
        // Each read makes progress within the idle timeout, but the attempt
        // still expires. The peer is independently finite if the client fails.
        for _ in 0..20 {
            if server.write_all(b"x").is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
    });
    let checkpoint = || Ok(());
    let result = Attempt::new(Duration::from_millis(150), &checkpoint)
        .unwrap()
        .exchange(&mut client, HEADER, BODY);
    drop(client);
    peer.join().unwrap();
    assert!(matches!(
        result,
        Err(Failure::Ambiguous(ref reason)) if reason.contains("ResourceBudgetExceeded")
    ));
}

#[test]
fn response_header_limit_is_enforced_before_growing_the_buffer() {
    let (mut client, mut server) = pair();
    let peer = thread::spawn(move || {
        read_exact_request(&mut server, HEADER, BODY);
        // No end-of-headers marker; the client must stop at the fixed bound.
        let _ = server.write_all(&vec![b'x'; MAX_RESPONSE_BYTES + 4096]);
    });
    let checkpoint = || Ok(());
    let result = Attempt::new(TEST_TIMEOUT, &checkpoint)
        .unwrap()
        .exchange(&mut client, HEADER, BODY);
    drop(client);
    peer.join().unwrap();
    assert!(matches!(
        result,
        Err(Failure::Ambiguous(ref reason)) if reason.contains("64 KiB")
    ));
}

#[test]
fn informational_response_and_binary_body_do_not_hide_a_final_ack() {
    let (mut client, mut server) = pair();
    let peer = thread::spawn(move || {
        read_exact_request(&mut server, HEADER, BODY);
        server.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").unwrap();
        server.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n\xff\x80").unwrap();
    });
    let checkpoint = || Ok(());
    let response = Attempt::new(TEST_TIMEOUT, &checkpoint)
        .unwrap()
        .exchange(&mut client, HEADER, BODY);
    drop(client);
    peer.join().unwrap();
    assert_eq!(super::super::parse_http_status(&response.unwrap()), Some(200));
}

#[test]
fn stopping_before_and_after_a_write_have_distinct_outcomes() {
    for code in [
        RefusalCode::CancellationInProgress,
        RefusalCode::ResourceBudgetExceeded,
    ] {
        assert!(matches!(
            Failure::stopped(code, false), Failure::Refused(observed) if observed == code
        ));
        assert!(matches!(Failure::stopped(code, true), Failure::Ambiguous(_)));
    }
    assert!(matches!(
        Failure::io(io::Error::new(io::ErrorKind::TimedOut, "setup"), false),
        Failure::Unsent(_)
    ));
    assert!(matches!(
        Failure::io(io::Error::new(io::ErrorKind::TimedOut, "write"), true),
        Failure::Ambiguous(_)
    ));
}
