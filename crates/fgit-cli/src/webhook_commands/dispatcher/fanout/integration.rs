//! Exercise the actual persisted authority, route journals and loopback HTTP.
use super::*;
use fgit_authority::IdempotencyKey;
use fgit_forge::event::issue::{IssueAction, IssueCommand};
use fgit_forge::webhook::{WebhookEventFilter, WebhookSecret, WebhookSecretRotation};
use fgit_forge::{ExpectedVersion, IssueNumber};
use fgit_node::LoopbackReceiveSession;
use fgit_types::{DecisionOutcome, PrincipalId};
use std::fs;
use std::io::{self, BufRead, BufReader, Read};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Instant;

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    storage: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    format: GitHashAlgorithm,
    destination: AsciiSlug,
    clock: AtomicU64,
}

fn secret() -> WebhookSecret {
    WebhookSecret::new(vec![0x42; 32]).unwrap()
}

impl Fixture {
    fn new(format: GitHashAlgorithm) -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-fanout-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let tenant = TenantId::from_bytes([0xa1; 16]);
        let repository = RepositoryId::from_bytes([0xa2; 16]);
        let storage = root.join("node");
        let config = NodeConfig::new(storage.clone(), tenant, repository)
            .with_object_format(format)
            .with_worker_threads(2);
        let (mut node, _) = OneNode::init(config).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let request = fgit_cli::command_request_context(&node);
        let session = LoopbackReceiveSession::authenticated(
            PrincipalId::from_bytes([0xa3; 16]),
            IdempotencyKey::new(b"fanout-fixture".to_vec()).unwrap(),
        );
        let command = IssueCommand {
            number: IssueNumber::try_new(1).unwrap(),
            expected_version: ExpectedVersion::NewStream,
            action: IssueAction::Open {
                title: "Fan-out issue".into(),
                body: "Actual committed payload, not a synthetic delivery".into(),
                labels: vec![],
            },
        };
        let (_, terminal) = node
            .runtime()
            .block_on(node.admit_issue_durable_in(&request, &session, &command, Default::default()))
            .unwrap();
        assert!(matches!(
            terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let page = node
            .runtime()
            .block_on(node.read_forge_outbox_snapshot_in(&request, 100, None))
            .unwrap();
        assert_eq!(page.entries.len(), 1);
        let destination = page.entries[0].destination();
        node.shutdown().unwrap();
        Self {
            root,
            storage,
            tenant,
            repository,
            format,
            destination,
            clock: AtomicU64::new(10_000),
        }
    }

    fn route(&self, id: u64) -> Options {
        Options {
            storage: self.storage.clone(),
            tenant: self.tenant,
            repository: self.repository,
            format: self.format,
            id: WebhookId(id),
            destination: self.destination,
            max_deliveries: 16,
            max_scan: 100,
            timeout: Duration::from_secs(2),
            continuous: false,
            stop_file: None,
            poll: Duration::from_millis(100),
            permissive: true,
        }
    }

    fn options(&self, limit: usize) -> FanoutOptions {
        FanoutOptions {
            routes: vec![self.route(7), self.route(8)],
            max_total_deliveries: limit,
        }
    }

    fn register(&self, id: u64, url: &str) -> WebhookRegistration {
        let registration = WebhookRegistration {
            id: WebhookId(id),
            url: SsrfPolicy::PERMISSIVE_FOR_TESTS.validate_url(url).unwrap(),
            secrets: WebhookSecretRotation::new(secret()),
            filter: WebhookEventFilter::Wildcard,
            active: true,
            retry_schedule: WebhookRetrySchedule {
                max_attempts: 3,
                initial_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(1),
            },
        };
        WebhookStore::open(self.storage.join("webhooks"))
            .unwrap()
            .register(registration.clone())
            .unwrap();
        registration
    }

    fn run(&self, limit: usize) -> (u8, String) {
        let mut output = Vec::new();
        let now = self.clock.fetch_add(10, Ordering::Relaxed);
        let code = execute(self.options(limit), &|| Ok(false), &|| Ok(now), &mut output).unwrap();
        (code, String::from_utf8(output).unwrap())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[derive(Debug)]
struct Captured {
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

struct Receiver {
    url: String,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<io::Result<Vec<Captured>>>>,
}

impl Receiver {
    fn new(statuses: Vec<Option<u16>>) -> Self {
        Self::from_listener(TcpListener::bind("127.0.0.1:0").unwrap(), statuses)
    }

    fn from_listener(listener: TcpListener, statuses: Vec<Option<u16>>) -> Self {
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/hook", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut observations = Vec::new();
            for status in statuses {
                let mut stream = loop {
                    if stopping.load(Ordering::Acquire) || Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "fanout request absent",
                        ));
                    }
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => return Err(error),
                    }
                };
                stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                observations.push(capture(&mut stream)?);
                if let Some(status) = status {
                    write!(
                        stream,
                        "HTTP/1.1 {status} Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )?;
                    stream.flush()?;
                }
            }
            Ok(observations)
        });
        Self {
            url,
            stop,
            worker: Some(worker),
        }
    }

    fn finish(mut self) -> Vec<Captured> {
        self.worker.take().unwrap().join().unwrap().unwrap()
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn capture(stream: &mut TcpStream) -> io::Result<Captured> {
    let mut reader = BufReader::new(stream.take(64 * 1024));
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line != "POST /hook HTTP/1.1\r\n" {
        return Err(io::Error::other("wrong fanout route"));
    }
    let mut headers = BTreeMap::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Err(io::Error::other("truncated request headers"));
        }
        if line == "\r\n" {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| io::Error::other("invalid header"))?;
        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
    }
    let length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|length| *length <= 32 * 1024)
        .ok_or_else(|| io::Error::other("invalid length"))?;
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    Ok(Captured { headers, body })
}

fn unused_listener() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/hook", listener.local_addr().unwrap());
    (listener, url)
}

fn assert_no_connection(listener: &TcpListener) {
    assert!(
        listener
            .accept()
            .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock)
    );
}

#[test]
fn fanout_sends_signed_canonical_bytes_and_reuses_single_worker_restart_state() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let first = Receiver::new(vec![Some(204)]);
        let second = Receiver::new(vec![Some(204)]);
        fixture.register(7, &first.url);
        fixture.register(8, &second.url);
        let before = snapshot(&fixture.route(7)).unwrap();
        let (code, output) = fixture.run(2);
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("\"routes\":2"));
        let first = first.finish();
        let second = second.finish();
        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert_eq!(first[0].body, second[0].body);
        for capture in [&first[0], &second[0]] {
            assert_eq!(
                capture.headers["x-frankengit-signature-256"],
                secret().sign_hex(&capture.body)
            );
            assert_eq!(
                capture.headers["x-frankengit-delivery"],
                before.entries[0].delivery_key().as_str()
            );
            assert_eq!(capture.headers["x-frankengit-attempt"], "1");
        }
        // Both endpoints are now closed: acceptance must suppress all egress.
        for id in [7, 8] {
            let mut output = Vec::new();
            assert_eq!(
                super::super::execute(
                    &fixture.route(id),
                    &|| Ok(false),
                    &|| Ok(10_000),
                    &mut output
                )
                .unwrap(),
                0
            );
            assert!(
                String::from_utf8(output)
                    .unwrap()
                    .contains("\"attempts\":0")
            );
        }
        let (code, output) = fixture.run(2);
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("\"attempts\":0"));
        let after = snapshot(&fixture.route(7)).unwrap();
        assert_eq!(before.head, after.head);
        assert_eq!(before.entries, after.entries);
    }
}

#[test]
fn failed_and_ambiguous_routes_do_not_block_healthy_delivery() {
    for status in [Some(404), None] {
        let fixture = Fixture::new(GitHashAlgorithm::Sha1);
        let first = Receiver::new(if status.is_none() {
            vec![None, Some(204)]
        } else {
            vec![status]
        });
        let second = Receiver::new(vec![Some(204)]);
        fixture.register(7, &first.url);
        fixture.register(8, &second.url);
        let (code, output) = fixture.run(2);
        assert_eq!(code, if status.is_none() { 3 } else { 2 }, "{output}");
        assert_eq!(second.finish().len(), 1);
        if status.is_none() {
            let (code, output) = fixture.run(2);
            assert_eq!(code, 0, "{output}");
            let captured = first.finish();
            assert_eq!(captured.len(), 2);
            assert_eq!(captured[0].body, captured[1].body);
            assert_eq!(captured[1].headers["x-frankengit-attempt"], "2");
        } else {
            assert_eq!(first.finish().len(), 1);
        }
    }
}

#[test]
fn shared_attempt_bound_resumes_the_unsent_route_without_resetting_ordinals() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256);
    let first = Receiver::new(vec![Some(204)]);
    let (listener, url) = unused_listener();
    fixture.register(7, &first.url);
    fixture.register(8, &url);
    let (code, output) = fixture.run(1);
    assert_eq!(code, 1, "{output}");
    assert_eq!(first.finish().len(), 1);
    assert_no_connection(&listener);
    let second = Receiver::from_listener(listener, vec![Some(204)]);
    let (code, output) = fixture.run(1);
    assert_eq!(code, 0, "{output}");
    let captured = second.finish();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].headers["x-frankengit-attempt"], "1");
}

#[test]
fn all_routes_are_validated_and_fenced_before_any_send() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1);
    let (listener, url) = unused_listener();
    fixture.register(7, &url);
    fixture.register(8, "https://example.com/hook");
    assert!(
        execute(
            fixture.options(2),
            &|| Ok(false),
            &|| Ok(10_000),
            &mut Vec::new()
        )
        .is_err()
    );
    assert_no_connection(&listener);
    let registration = fixture.register(8, &url);
    let options = fixture.route(8);
    let page = snapshot(&options).unwrap();
    let _fence = Journal::open(
        &journal_path(&options),
        scope(&options, page.incarnation, &registration),
        3,
    )
    .unwrap();
    assert!(
        execute(
            fixture.options(2),
            &|| Ok(false),
            &|| Ok(10_000),
            &mut Vec::new()
        )
        .is_err()
    );
    assert_no_connection(&listener);
    assert!(
        !fs::read_to_string(journal_path(&fixture.route(7)))
            .unwrap()
            .contains("in-flight")
    );
}

#[test]
fn cancellation_after_reservation_stops_every_route_and_retains_unknown() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1);
    let (first, first_url) = unused_listener();
    let (second, second_url) = unused_listener();
    fixture.register(7, &first_url);
    fixture.register(8, &second_url);
    let reservation = journal_path(&fixture.route(7));
    let fired = Cell::new(false);
    // Deliberately return true only once: the controller must latch the stop.
    let stopped = || {
        Ok(!fired.get()
            && fs::read_to_string(&reservation).is_ok_and(|text| {
                if text.contains("in-flight") {
                    fired.set(true);
                    true
                } else {
                    false
                }
            }))
    };
    let mut output = Vec::new();
    assert_eq!(
        execute(fixture.options(2), &stopped, &|| Ok(10_000), &mut output).unwrap(),
        3
    );
    assert_no_connection(&first);
    assert_no_connection(&second);
    assert!(
        fs::read_to_string(&reservation)
            .unwrap()
            .contains("unknown")
    );
    assert!(
        !fs::read_to_string(journal_path(&fixture.route(8)))
            .unwrap()
            .contains("in-flight")
    );
    assert!(
        String::from_utf8(output)
            .unwrap()
            .contains("\"stopped\":true")
    );
}

#[test]
fn output_failure_after_acceptance_stops_fanout_and_restart_does_not_resend() {
    struct FailedObservation;
    impl Write for FailedObservation {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes
                .windows(b"webhook_dispatch_observation".len())
                .any(|part| part == b"webhook_dispatch_observation")
            {
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "closed observation reader",
                ))
            } else {
                Ok(bytes.len())
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let fixture = Fixture::new(GitHashAlgorithm::Sha1);
    let first = Receiver::new(vec![Some(204)]);
    let (listener, url) = unused_listener();
    fixture.register(7, &first.url);
    fixture.register(8, &url);
    assert!(
        execute(
            fixture.options(2),
            &|| Ok(false),
            &|| Ok(10_000),
            &mut FailedObservation
        )
        .is_err()
    );
    assert_eq!(first.finish().len(), 1);
    assert_no_connection(&listener);
    let second = Receiver::from_listener(listener, vec![Some(204)]);
    let (code, output) = fixture.run(2);
    assert_eq!(code, 0, "{output}");
    assert_eq!(second.finish().len(), 1);
}

#[test]
fn continuous_global_budget_rotates_before_retrying_the_first_route() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1);
    let first = Receiver::new(vec![Some(503)]);
    let second = Receiver::new(vec![Some(204)]);
    fixture.register(7, &first.url);
    fixture.register(8, &second.url);
    let first_journal = journal_path(&fixture.route(7));
    let second_journal = journal_path(&fixture.route(8));
    // Both progress conditions need a delivery attempt to reach a journal. If
    // none does, the continuous controller never stops: under host load this
    // test once ran for over two hours and held its whole binary
    // (frankengit-e0eg). The wall-clock bound turns that into a failure.
    let started = std::time::Instant::now();
    let bound = std::time::Duration::from_secs(120);
    let stopped = || {
        let first = fs::read_to_string(&first_journal).unwrap_or_default();
        let second = fs::read_to_string(&second_journal).unwrap_or_default();
        // The second condition also bounds the failure case: a scheduling
        // regression cannot keep this test's continuous controller running.
        Ok(second.contains("accepted")
            || first.matches("in-flight").count() > 1
            || started.elapsed() > bound)
    };
    let mut options = fixture.options(1);
    for route in &mut options.routes {
        route.continuous = true;
    }
    let mut output = Vec::new();
    let delivered = execute(options, &stopped, &|| Ok(10_000), &mut output).unwrap();
    assert!(
        started.elapsed() <= bound,
        "the continuous dispatcher made no delivery progress within {bound:?}"
    );
    assert_eq!(delivered, 1);
    assert_eq!(
        fs::read_to_string(&first_journal)
            .unwrap()
            .matches("in-flight")
            .count(),
        1
    );
    assert!(
        fs::read_to_string(&second_journal)
            .unwrap()
            .contains("accepted")
    );
    assert_eq!(first.finish().len(), 1);
    assert_eq!(second.finish().len(), 1);
}
