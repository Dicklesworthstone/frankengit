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

fn serve_status(
    status: u16,
    extra_headers: &str,
) -> (SocketAddr, std::thread::JoinHandle<(String, Vec<u8>)>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
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
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut reader = BufReader::new(&mut stream);
        let mut length = None;
        let mut headers = String::new();
        loop {
            let mut line = String::new();
            assert_ne!(reader.read_line(&mut line).unwrap(), 0);
            headers.push_str(&line);
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
        (headers, body)
    });
    (addr, server)
}

fn deliver_status(
    status: u16,
    extra_headers: &str,
    attempt: u32,
    max_attempts: u32,
) -> (WebhookDeliveryDestination, DeliveryVerdict) {
    let (addr, server) = serve_status(status, extra_headers);
    let url = format!("http://{addr}/hook");
    let dest = destination(&url, max_attempts);
    let events = ForgeEventBatch { events: Vec::new() };
    let result = dest.dispatch_http(&request(&events), attempt);
    server.join().unwrap();
    (dest, result.unwrap().0)
}

#[test]
fn dns_lookup_failures_are_typed_separately_from_policy_and_answer_bounds() {
    let mut dest = destination("http://example.com/hook", 3);
    dest.ssrf_policy = SsrfPolicy::STRICT;
    for answer in [
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "resolver temporarily unavailable",
        )),
        Ok(Vec::<SocketAddr>::new()),
    ] {
        assert!(matches!(
            dest.resolve_safe_socket_addrs(&dest.registration.url, |host, port| {
                assert_eq!((host, port), ("example.com", 80));
                answer
            }),
            Err(ResolutionFailure::Transient(_))
        ));
    }
    let safe: SocketAddr = "93.184.216.34:80".parse().unwrap();
    let unsafe_addr: SocketAddr = "127.0.0.1:80".parse().unwrap();
    for (answer, expected) in [
        (vec![safe, unsafe_addr], "rejected by SSRF policy"),
        (vec![safe; 17], "16-address webhook bound"),
    ] {
        assert!(matches!(
            dest.resolve_safe_socket_addrs(&dest.registration.url, |_, _| Ok(answer)),
            Err(ResolutionFailure::Refused(reason)) if reason.contains(expected)
        ));
    }
}

#[test]
fn dns_outages_and_empty_answers_use_the_bounded_retry_schedule() {
    let events = ForgeEventBatch { events: Vec::new() };
    let request = request(&events);
    for empty in [false, true] {
        for attempt in [1, 2, 3] {
            let dest = destination("http://example.com/hook", 3);
            let (verdict, detail) = dest
                .dispatch_http_with_lookup(&request, attempt, &|| Ok(()), |_, _| {
                    if empty {
                        Ok(Vec::<SocketAddr>::new())
                    } else {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "resolver temporarily unavailable",
                        ))
                    }
                })
                .unwrap();
            let reason = String::from_utf8(detail).unwrap();
            assert!(reason.contains(if empty {
                "DNS resolution returned no addresses"
            } else {
                "DNS resolution error for example.com"
            }));
            assert!(dest.acknowledged.lock().unwrap().is_empty());
            let dead = dest.dead_letters.list();
            if attempt < 3 {
                assert_eq!(verdict, DeliveryVerdict::TransientFailure);
                assert!(dead.is_empty());
            } else {
                assert_eq!(verdict, DeliveryVerdict::PermanentRejection);
                assert_eq!(dead.len(), 1);
                assert_eq!(dead[0].delivery_id, request.key);
                assert_eq!(dead[0].webhook_id, dest.registration.id);
                assert_eq!(dead[0].payload_root, request.payload_root);
                assert_eq!(dead[0].attempts, attempt);
                assert_eq!(dead[0].terminal_reason, reason);
            }
        }
    }
}

#[test]
fn dns_recovery_delivers_the_original_request_without_a_dead_letter() {
    for empty in [false, true] {
        let (addr, server) = serve_status(200, "");
        let dest = destination(&format!("http://example.com:{}/hook", addr.port()), 3);
        let events = ForgeEventBatch { events: Vec::new() };
        let request = request(&events);
        let first = dest.dispatch_http_with_lookup(&request, 1, &|| Ok(()), |_, _| {
            if empty {
                Ok(Vec::<SocketAddr>::new())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "resolver temporarily unavailable",
                ))
            }
        });
        let second = dest.dispatch_http_with_lookup(&request, 2, &|| Ok(()), |host, port| {
            assert_eq!((host, port), ("example.com", addr.port()));
            Ok([addr])
        });
        let (headers, body) = server.join().unwrap();
        assert_eq!(first.unwrap().0, DeliveryVerdict::TransientFailure);
        assert_eq!(second.unwrap().0, DeliveryVerdict::Accepted);
        assert_eq!(body, payload::encode(&request).unwrap().as_bytes());
        assert!(headers.contains("X-FrankenGit-Delivery: retry-policy\r\n"));
        assert!(headers.contains("X-FrankenGit-Attempt: 2\r\n"));
        let signature = hex_encode(dest.registration.secrets.sign_active(&body));
        assert!(headers.contains(&format!(
            "X-FrankenGit-Signature-256: sha256={signature}\r\n"
        )));
        assert!(dest.dead_letters.list().is_empty());
        assert_eq!(
            dest.probe_acknowledgement(&request),
            Ok(ProbeVerdict::Delivered)
        );
    }
}

#[test]
fn unsafe_or_overbound_dns_answers_refuse_before_connect_on_every_attempt() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let local = listener.local_addr().unwrap();
    let safe = SocketAddr::new("93.184.216.34".parse().unwrap(), local.port());
    let events = ForgeEventBatch { events: Vec::new() };
    for (policy, answers, expected) in [
        (
            SsrfPolicy::STRICT,
            vec![safe, local],
            "rejected by SSRF policy",
        ),
        (
            SsrfPolicy::PERMISSIVE_FOR_TESTS,
            vec![local; 17],
            "16-address webhook bound",
        ),
    ] {
        for attempt in [1, 3] {
            let mut dest = destination(&format!("http://example.com:{}/hook", local.port()), 3);
            dest.ssrf_policy = policy;
            let (verdict, _) = dest
                .dispatch_http_with_lookup(&request(&events), attempt, &|| Ok(()), |_, _| {
                    Ok(answers.clone())
                })
                .unwrap();
            assert_eq!(verdict, DeliveryVerdict::PermanentRejection);
            let dead = dest.dead_letters.list();
            assert_eq!(dead.len(), 1);
            assert_eq!(dead[0].attempts, attempt);
            assert!(dead[0].terminal_reason.contains(expected));
            assert!(dest.acknowledged.lock().unwrap().is_empty());
        }
    }
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn stopping_during_dns_does_not_retry_or_dead_letter_a_cancelled_attempt() {
    let events = ForgeEventBatch { events: Vec::new() };
    for stopped in [
        RefusalCode::CancellationInProgress,
        RefusalCode::ResourceBudgetExceeded,
    ] {
        for attempt in [1, 3] {
            let dest = destination("http://example.com/hook", 3);
            let lookup_finished = std::cell::Cell::new(false);
            let checkpoint = || {
                if lookup_finished.get() {
                    Err(stopped)
                } else {
                    Ok(())
                }
            };
            let result =
                dest.dispatch_http_with_lookup(&request(&events), attempt, &checkpoint, |_, _| {
                    lookup_finished.set(true);
                    Err::<Vec<SocketAddr>, _>(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "resolver temporarily unavailable",
                    ))
                });
            assert_eq!(result, Err(stopped));
            assert!(dest.dead_letters.list().is_empty());
            assert!(dest.acknowledged.lock().unwrap().is_empty());
        }
    }
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
        assert_eq!(
            verdict,
            DeliveryVerdict::PermanentRejection,
            "HTTP {status}"
        );
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
        assert_eq!(
            verdict,
            DeliveryVerdict::PermanentRejection,
            "HTTP {status}"
        );
        let dead = at_limit.dead_letters.list();
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].attempts, 2);
        assert!(
            dead[0]
                .terminal_reason
                .contains("redirect retry budget exhausted")
        );
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
        assert_eq!(
            verdict,
            DeliveryVerdict::PermanentRejection,
            "HTTP {status}"
        );
        let dead = dest.dead_letters.list();
        assert_eq!(dead.len(), 1);
        assert!(
            dead[0]
                .terminal_reason
                .contains("unsupported webhook redirect")
        );
    }
}

#[test]
fn non_retryable_client_errors_still_fail_immediately() {
    for status in [400, 401, 403, 404, 409, 410, 422] {
        let (dest, verdict) = deliver_status(status, "", 1, 3);
        assert_eq!(
            verdict,
            DeliveryVerdict::PermanentRejection,
            "HTTP {status}"
        );
        assert_eq!(dest.dead_letters.list().len(), 1);
    }
}

#[test]
fn attempts_outside_the_schedule_are_refused_before_any_socket_is_opened() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!(
        "http://127.0.0.1:{}/hook",
        listener.local_addr().unwrap().port()
    );
    let events = ForgeEventBatch { events: Vec::new() };
    for (attempt, max_attempts) in [(0, 3), (4, 3), (1, 0)] {
        let dest = destination(&url, max_attempts);
        assert_eq!(
            dest.dispatch_http(&request(&events), attempt),
            Err(RefusalCode::ResourceBudgetExceeded)
        );
        assert!(dest.dead_letters.list().is_empty());
    }
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
