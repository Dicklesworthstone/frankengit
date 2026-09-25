//! Exercise retry classifications through the real socket adapter, not a
//! duplicate model of the match statement.

use super::*;
use fgit_forge::ForgeEventBatch;
use fgit_forge::webhook::{
    WebhookEventFilter, WebhookId, WebhookRetrySchedule, WebhookSecret, WebhookSecretRotation,
};
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::time::Instant;

fn destination(url: &str, max_attempts: u32) -> WebhookDeliveryDestination {
    let mut schedule = WebhookRetrySchedule::default();
    schedule.max_attempts = max_attempts;
    WebhookDeliveryDestination::new(
        AsciiSlug::from_static("test-webhook"),
        WebhookRegistration {
            id: WebhookId(1),
            url: SsrfPolicy::PERMISSIVE_FOR_TESTS.validate_url(url).unwrap(),
            secrets: WebhookSecretRotation::new(
                WebhookSecret::new(b"0123456789abcdef0123456789abcdef").unwrap(),
            ),
            filter: WebhookEventFilter::Wildcard,
            active: true,
            retry_schedule: schedule,
        },
        SsrfPolicy::PERMISSIVE_FOR_TESTS,
        DeadLetterQueue::new(),
    )
}

fn request(events: &ForgeEventBatch) -> DeliveryRequest<'_> {
    DeliveryRequest {
        key: AsciiSlug::from_static("retry-policy"),
        destination: AsciiSlug::from_static("test-webhook"),
        payload_root: fgit_admission::evidence::evidence_root(events).unwrap(),
        events,
    }
}

fn deliver_status(
    status: u16,
    extra_headers: &str,
    attempt: u32,
    max_attempts: u32,
) -> (WebhookDeliveryDestination, DeliveryVerdict) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://127.0.0.1:{}/hook", listener.local_addr().unwrap().port());
    let response = format!(
        "HTTP/1.1 {status} Test\r\n{extra_headers}Content-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let server = std::thread::spawn(move || {
        // A regression that refuses before connect must fail instead of leaving
        // a test thread blocked forever in accept().
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "webhook never connected");
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
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
        stream.write_all(response.as_bytes()).unwrap();
    });
    let dest = destination(&url, max_attempts);
    let events = ForgeEventBatch { events: Vec::new() };
    let result = dest.dispatch_http(&request(&events), attempt);
    server.join().unwrap();
    (dest, result.unwrap().0)
}

#[test]
fn explicit_request_timeout_is_retryable_without_becoming_an_ambiguous_local_timeout() {
    let (dest, verdict) = deliver_status(408, "", 1, 3);
    assert_eq!(verdict, DeliveryVerdict::TransientFailure);
    assert!(dest.dead_letters.list().is_empty());
    assert!(dest.acknowledged.lock().unwrap().is_empty());
}

#[test]
fn retryable_http_statuses_exhaust_to_a_truthful_dead_letter_at_the_limit() {
    for status in [408, 429, 500, 502, 503, 504, 599] {
        let (before, verdict) = deliver_status(status, "", 2, 3);
        assert_eq!(verdict, DeliveryVerdict::TransientFailure, "HTTP {status}");
        assert!(before.dead_letters.list().is_empty());
        let (at_limit, verdict) = deliver_status(status, "", 3, 3);
        assert_eq!(verdict, DeliveryVerdict::PermanentRejection, "HTTP {status}");
        let dead = at_limit.dead_letters.list();
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].attempts, 3);
        assert!(dead[0].terminal_reason.contains(&status.to_string()));
    }
}

#[test]
fn policy_approved_redirects_cannot_retry_past_the_attempt_limit() {
    for status in [301, 302, 307, 308] {
        let headers = "Location: http://example.com/next\r\n";
        let (before, verdict) = deliver_status(status, headers, 1, 2);
        assert_eq!(verdict, DeliveryVerdict::TransientFailure, "HTTP {status}");
        assert!(before.dead_letters.list().is_empty());
        let (at_limit, verdict) = deliver_status(status, headers, 2, 2);
        assert_eq!(verdict, DeliveryVerdict::PermanentRejection, "HTTP {status}");
        let dead = at_limit.dead_letters.list();
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].attempts, 2);
        assert!(dead[0].terminal_reason.contains("redirect retry budget exhausted"));
    }
}

#[test]
fn missing_or_duplicate_redirect_locations_are_dead_lettered_not_silently_dropped() {
    for headers in [
        "",
        "Location: http://example.com/one\r\nLocation: http://example.com/two\r\n",
    ] {
        let (dest, verdict) = deliver_status(302, headers, 1, 3);
        assert_eq!(verdict, DeliveryVerdict::PermanentRejection);
        let dead = dest.dead_letters.list();
        assert_eq!(dead.len(), 1);
        assert!(dead[0].terminal_reason.contains("Location"));
    }
}

#[test]
fn unsupported_redirect_statuses_do_not_enter_the_server_error_retry_path() {
    for status in [300, 303, 304, 305, 306] {
        let (dest, verdict) = deliver_status(status, "", 1, 3);
        assert_eq!(verdict, DeliveryVerdict::PermanentRejection, "HTTP {status}");
        let dead = dest.dead_letters.list();
        assert_eq!(dead.len(), 1);
        assert!(dead[0].terminal_reason.contains("unsupported webhook redirect"));
    }
}

#[test]
fn non_retryable_client_errors_still_fail_immediately() {
    for status in [400, 401, 403, 404, 409, 410, 422] {
        let (dest, verdict) = deliver_status(status, "", 1, 3);
        assert_eq!(verdict, DeliveryVerdict::PermanentRejection, "HTTP {status}");
        assert_eq!(dest.dead_letters.list().len(), 1);
    }
}

#[test]
fn attempts_outside_the_schedule_are_refused_before_any_socket_is_opened() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://127.0.0.1:{}/hook", listener.local_addr().unwrap().port());
    let events = ForgeEventBatch { events: Vec::new() };
    for (attempt, max_attempts) in [(0, 3), (4, 3), (1, 0)] {
        let dest = destination(&url, max_attempts);
        assert_eq!(
            dest.dispatch_http(&request(&events), attempt),
            Err(RefusalCode::ResourceBudgetExceeded)
        );
        assert!(dest.dead_letters.list().is_empty());
    }
    assert_eq!(listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
}
