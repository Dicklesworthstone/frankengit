//! Real persisted authority and real loopback HTTP; no fake accepted outbox.
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
use std::sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}};
use std::thread::{self, JoinHandle};
use std::time::Instant;

static NEXT: AtomicU64 = AtomicU64::new(0);
fn secret() -> WebhookSecret { WebhookSecret::new(vec![0x42; 32]).unwrap() }
struct Fixture { root: PathBuf, options: Options }
impl Fixture {
    fn new(format: GitHashAlgorithm) -> Self {
        let root = std::env::temp_dir().join(format!("fg-dispatch-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&root).unwrap();
        let tenant = TenantId::from_bytes([0xa1; 16]);
        let repository = RepositoryId::from_bytes([0xa2; 16]);
        let storage = root.join("node");
        let config = NodeConfig::new(storage.clone(), tenant, repository).with_object_format(format).with_worker_threads(2);
        let (mut node, _) = OneNode::init(config).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        publish(&node, 1);
        let request = fgit_cli::command_request_context(&node);
        let page = node.runtime().block_on(node.read_forge_outbox_snapshot_in(&request, 100, None)).unwrap();
        assert_eq!(page.entries.len(), 1);
        let destination = page.entries[0].destination();
        node.shutdown().unwrap();
        Self { root, options: Options { storage, tenant, repository, format, id: WebhookId(7), destination,
            max_deliveries: 16, max_scan: 100, timeout: Duration::from_secs(2), continuous: false,
            stop_file: None, poll: Duration::from_millis(100), permissive: true } }
    }
    fn register(&self, url: &str, filter: WebhookEventFilter) -> WebhookRegistration {
        let registration = WebhookRegistration { id: self.options.id,
            url: SsrfPolicy::PERMISSIVE_FOR_TESTS.validate_url(url).unwrap(),
            secrets: WebhookSecretRotation::new(secret()), filter, active: true,
            retry_schedule: WebhookRetrySchedule { max_attempts: 3, initial_delay: Duration::ZERO, max_delay: Duration::ZERO } };
        self.store().register(registration.clone()).unwrap();
        registration
    }
    fn store(&self) -> WebhookStore { WebhookStore::open(self.options.storage.join("webhooks")).unwrap() }
    fn run(&self) -> (u8, String) {
        let mut output = Vec::new();
        let code = execute(&self.options, &|| Ok(false), &|| Ok(10_000), &mut output).unwrap();
        (code, String::from_utf8(output).unwrap())
    }
    fn add(&self, number: u64) {
        with_node(&self.options, |node| { publish(node, number); Ok(()) }).unwrap();
    }
}
impl Drop for Fixture { fn drop(&mut self) { fs::remove_dir_all(&self.root).unwrap(); } }
fn publish(node: &OneNode, number: u64) {
    let request = fgit_cli::command_request_context(node);
    let session = LoopbackReceiveSession::authenticated(PrincipalId::from_bytes([0xa3; 16]),
        IdempotencyKey::new(format!("dispatch-fixture-{number}").into_bytes()).unwrap());
    let command = IssueCommand { number: IssueNumber::try_new(number).unwrap(), expected_version: ExpectedVersion::NewStream,
        action: IssueAction::Open { title: format!("Dispatch issue {number}"), body: "An actual canonical payload".into(), labels: vec![] } };
    let (_, terminal) = node.runtime().block_on(node.admit_issue_durable_in(&request, &session, &command, Default::default())).unwrap();
    assert!(matches!(terminal.outcome, DecisionOutcome::Committed { .. }));
}

#[derive(Debug)]
struct Captured { headers: BTreeMap<String, String>, body: Vec<u8> }
struct Receiver { url: String, stop: Arc<AtomicBool>, worker: Option<JoinHandle<io::Result<Vec<Captured>>>> }
impl Receiver {
    fn new(statuses: Vec<Option<u16>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
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
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "dispatch request absent"));
                    }
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(5)),
                        Err(e) => return Err(e),
                    }
                };
                stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                observations.push(capture(&mut stream)?);
                if let Some(code) = status {
                    let reason = if code == 204 { "No Content" } else { "Service Unavailable" };
                    write!(stream, "HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
                    stream.flush()?;
                }
                // None deliberately loses the response AFTER reading the body.
            }
            Ok(observations)
        });
        Self { url, stop, worker: Some(worker) }
    }
    fn finish(mut self) -> Vec<Captured> { self.worker.take().unwrap().join().unwrap().unwrap() }
}
impl Drop for Receiver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
    }
}
fn capture(stream: &mut TcpStream) -> io::Result<Captured> {
    let mut reader = BufReader::new(stream.take(64 * 1024));
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line != "POST /hook HTTP/1.1\r\n" { return Err(io::Error::other("wrong dispatch route")); }
    let mut headers = BTreeMap::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 { return Err(io::Error::other("truncated dispatch headers")); }
        if line == "\r\n" { break; }
        let (name, value) = line.split_once(':').ok_or_else(|| io::Error::other("invalid header"))?;
        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
    }
    let length = headers.get("content-length").and_then(|v| v.parse::<usize>().ok()).filter(|n| *n <= 32 * 1024)
        .ok_or_else(|| io::Error::other("invalid dispatch length"))?;
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    Ok(Captured { headers, body })
}

#[test]
fn signed_canonical_delivery_survives_restart_without_resending_or_settling_authority() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let receiver = Receiver::new(vec![Some(204)]);
        fixture.register(&receiver.url, WebhookEventFilter::Wildcard);
        let before = snapshot(&fixture.options).unwrap();
        let original = with_node(&fixture.options, |node| {
            let request = fgit_cli::command_request_context(node);
            let selected = node.runtime().block_on(node.select_forge_delivery_in(&request, before.entries[0].delivery_key(), fixture.options.destination, Some(before.head)))
                .map_err(|e| e.to_string())?;
            assert!(selected.is_unclaimed());
            Ok(fgit_codec::encode_body(&selected.as_request().events.events[0]).unwrap())
        }).unwrap();
        let (code, output) = fixture.run();
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("\"journal_synced\":true"));
        assert!(output.contains("\"canonical_settled\":false"));
        let captured = receiver.finish();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].headers["x-frankengit-signature-256"], secret().sign_hex(&captured[0].body));
        assert_eq!(captured[0].headers["x-frankengit-delivery"], before.entries[0].delivery_key().as_str());
        assert!(std::str::from_utf8(&captured[0].body).unwrap().contains(&format!("\"canonical_frame_hex\":\"{}\"", hex(&original))));
        let (code, output) = fixture.run();
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("\"attempts\":0"));
        let after = snapshot(&fixture.options).unwrap();
        assert_eq!(before.head, after.head);
        assert_eq!(before.entries, after.entries);
    }
}

#[test]
fn transient_response_and_lost_ack_resume_exact_payload_without_resetting_attempts() {
    for first in [Some(503), None] {
        let fixture = Fixture::new(GitHashAlgorithm::Sha1);
        let receiver = Receiver::new(vec![first, Some(204)]);
        fixture.register(&receiver.url, WebhookEventFilter::Wildcard);
        let (code, output) = fixture.run();
        assert_eq!(code, if first.is_none() { 3 } else { 1 }, "{output}");
        let (code, output) = fixture.run();
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("\"attempt\":2"));
        assert!(output.contains("\"retry_may_duplicate\":true"));
        let captured = receiver.finish();
        assert_eq!(captured[0].body, captured[1].body);
        assert_eq!(captured[0].headers["x-frankengit-signature-256"], captured[1].headers["x-frankengit-signature-256"]);
        let (code, output) = fixture.run();
        assert_eq!(code, 0);
        assert!(output.contains("\"attempts\":0"));
    }
}

#[test]
fn lost_stdout_after_accepted_observation_does_not_cause_resend() {
    struct FailedOutput;
    impl Write for FailedOutput {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> { Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed reader")) }
        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }
    let fixture = Fixture::new(GitHashAlgorithm::Sha1);
    let receiver = Receiver::new(vec![Some(204)]);
    fixture.register(&receiver.url, WebhookEventFilter::Wildcard);
    assert!(execute(&fixture.options, &|| Ok(false), &|| Ok(10_000), &mut FailedOutput).is_err());
    assert_eq!(receiver.finish().len(), 1);
    let (code, output) = fixture.run();
    assert_eq!(code, 0);
    assert!(output.contains("\"attempts\":0"));
}

#[test]
fn scan_ceiling_refuses_before_reservation_and_bounded_sweeps_find_new_keys() {
    let mut fixture = Fixture::new(GitHashAlgorithm::Sha256);
    fixture.add(2);
    let receiver = Receiver::new(vec![Some(204), Some(204), Some(204)]);
    fixture.register(&receiver.url, WebhookEventFilter::Wildcard);
    fixture.options.max_scan = 1;
    assert!(execute(&fixture.options, &|| Ok(false), &|| Ok(10_000), &mut Vec::new()).is_err());
    assert!(!journal_path(&fixture.options).exists());
    fixture.options.max_scan = 100;
    fixture.options.max_deliveries = 1;
    assert_eq!(fixture.run().0, 1);
    assert_eq!(fixture.run().0, 0);
    fixture.add(3);
    // No saved cursor exists, so this works regardless of the new key's order.
    assert_eq!(fixture.run().0, 0);
    let captured = receiver.finish();
    assert_eq!(captured.len(), 3);
    let keys: std::collections::BTreeSet<_> = captured.iter().map(|c| &c.headers["x-frankengit-delivery"]).collect();
    assert_eq!(keys.len(), 3);
}

#[test]
fn cancellation_after_write_ahead_preserves_unknown_and_never_connects() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    fixture.register(&format!("http://{}/hook", listener.local_addr().unwrap()), WebhookEventFilter::Wildcard);
    let cancelled = Cell::new(false);
    let stop = || {
        if fs::read_to_string(journal_path(&fixture.options)).is_ok_and(|s| s.contains("in-flight")) { cancelled.set(true); }
        Ok(cancelled.get())
    };
    let mut output = Vec::new();
    assert_eq!(execute(&fixture.options, &stop, &|| Ok(10_000), &mut output).unwrap(), 3);
    assert!(listener.accept().is_err_and(|e| e.kind() == io::ErrorKind::WouldBlock));
    assert!(fs::read_to_string(journal_path(&fixture.options)).unwrap().contains("unknown"));
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("\"journal_synced\":true"));
    assert!(output.contains("\"stopped\":true"));
    assert!(output.contains("\"observation_source\":\"adapter-refusal\""));
    assert!(!output.contains("response_sha256"));
}

#[test]
fn endpoint_policy_and_subscription_checks_precede_egress() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/hook", listener.local_addr().unwrap());
    let mut registration = fixture.register(&url, WebhookEventFilter::Selected(vec!["pull_request".into()]));
    let (code, output) = fixture.run();
    assert_eq!(code, 0);
    assert!(output.contains("\"filtered\":1"));
    assert!(!fs::read_to_string(journal_path(&fixture.options)).unwrap().contains("in-flight"));
    registration.active = false;
    fixture.store().register(registration.clone()).unwrap();
    assert!(execute(&fixture.options, &|| Ok(false), &|| Ok(10_000), &mut Vec::new()).is_err());
    registration.active = true;
    registration.url = SsrfPolicy::PERMISSIVE_FOR_TESTS.validate_url(&format!("{url}-changed")).unwrap();
    fixture.store().register(registration).unwrap();
    assert!(execute(&fixture.options, &|| Ok(false), &|| Ok(10_000), &mut Vec::new()).is_err());
    assert!(listener.accept().is_err_and(|e| e.kind() == io::ErrorKind::WouldBlock));
}

#[test]
fn source_snapshot_limit_and_pin_are_exact_read_only_contracts() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256);
    let before = snapshot(&fixture.options).unwrap();
    fixture.add(2);
    with_node(&fixture.options, |node| {
        for maximum in [0, 1, 16_385] {
            let request = fgit_cli::command_request_context(node);
            assert!(node.runtime().block_on(node.read_forge_outbox_snapshot_in(&request, maximum, None)).is_err());
        }
        let request = fgit_cli::command_request_context(node);
        assert!(node.runtime().block_on(node.read_forge_outbox_snapshot_in(&request, 100, Some(before.head))).is_err());
        let request = fgit_cli::command_request_context(node);
        let selected = node.runtime().block_on(node.read_forge_outbox_snapshot_in(&request, 2, None)).unwrap();
        assert_eq!(selected.entries.len(), 2);
        assert!(selected.next_after.is_none());
        Ok(())
    }).unwrap();
}

#[test]
fn command_parser_requires_exact_consent_and_bounded_applicable_options() {
    let args = |extra: &[&str]| {
        let mut values = vec!["/tmp/data".to_owned(), "a1".repeat(16), "a2".repeat(16), "--trusted-local".into()];
        values.extend(extra.iter().map(|s| (*s).to_owned())); values
    };
    let base = ["--id", "7", "--destination", "events", "--at-least-once"];
    assert!(parse(&args(&base)).is_ok());
    assert!(parse(&args(&base[..4])).is_err());
    for extra in [vec!["--id", "8"], vec!["--at-least-once"], vec!["--attempt", "1"],
        vec!["--max-deliveries", "0"], vec!["--max-deliveries", "1001"], vec!["--max-scan-entries", "16385"],
        vec!["--attempt-timeout-secs", "61"], vec!["--object-format", "sha512"], vec!["--continuous"],
        vec!["--stop-file", "/tmp/stop"], vec!["--poll-millis", "1000"], vec!["--max-deliveries", "01"]]
    {
        let mut values = base.to_vec(); values.extend(extra);
        assert!(parse(&args(&values)).is_err(), "{values:?}");
    }
    let mut values = base.to_vec(); values.extend(["--continuous", "--stop-file", "/tmp/stop", "--poll-millis", "100"]);
    assert!(parse(&args(&values)).is_ok());
}

#[test]
fn preexisting_stop_file_never_opens_repository_or_creates_a_journal() {
    let root = std::env::temp_dir().join(format!("fg-dispatch-stop-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
    fs::create_dir(&root).unwrap();
    let stop = root.join("stop");
    assert!(!stop_file(Some(&stop)).unwrap());
    fs::write(&stop, b"stop").unwrap();
    let options = Options { storage: root.join("absent-node"), tenant: TenantId::from_bytes([1; 16]),
        repository: RepositoryId::from_bytes([2; 16]), format: GitHashAlgorithm::Sha1, id: WebhookId(1),
        destination: AsciiSlug::from_static("events"), max_deliveries: 1, max_scan: 100, timeout: Duration::from_secs(1),
        continuous: true, stop_file: Some(stop.clone()), poll: Duration::from_millis(100), permissive: true };
    assert_eq!(execute(&options, &|| stop_file(Some(&stop)), &|| Ok(10_000), &mut Vec::new()).unwrap(), 1);
    assert!(!options.storage.exists());
    fs::remove_file(&stop).unwrap();
    std::os::unix::fs::symlink(root.join("missing"), &stop).unwrap();
    assert!(stop_file(Some(&stop)).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn secret_rotation_uses_new_signer_without_resetting_durable_attempt_or_payload() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256);
    let receiver = Receiver::new(vec![None, Some(204)]);
    fixture.register(&receiver.url, WebhookEventFilter::Wildcard);
    assert_eq!(fixture.run().0, 3);
    let rotated = WebhookSecret::new(vec![0x73; 32]).unwrap();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    fixture.store().rotate_secret(fixture.options.id, rotated.clone(), 60, now).unwrap();
    let (code, output) = fixture.run();
    assert_eq!(code, 0, "{output}");
    assert!(output.contains("\"attempt\":2"));
    let captured = receiver.finish();
    assert_eq!(captured[0].body, captured[1].body);
    assert_eq!(captured[0].headers["x-frankengit-signature-256"], secret().sign_hex(&captured[0].body));
    assert_eq!(captured[1].headers["x-frankengit-signature-256"], rotated.sign_hex(&captured[1].body));
    assert_ne!(captured[0].headers["x-frankengit-signature-256"], captured[1].headers["x-frankengit-signature-256"]);
}

#[test]
fn continuous_owner_drains_and_emits_a_stop_receipt_after_the_last_send() {
    let mut fixture = Fixture::new(GitHashAlgorithm::Sha1);
    let receiver = Receiver::new(vec![Some(204)]);
    fixture.register(&receiver.url, WebhookEventFilter::Wildcard);
    fixture.options.continuous = true;
    let stop = || Ok(fs::read_to_string(journal_path(&fixture.options)).is_ok_and(|s| s.contains("accepted")));
    let mut output = Vec::new();
    assert_eq!(execute(&fixture.options, &stop, &|| Ok(10_000), &mut output).unwrap(), 1);
    assert_eq!(receiver.finish().len(), 1);
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("\"state\":\"accepted\""));
    assert!(output.lines().last().unwrap().contains("\"stopped\":true"));
    // The invocation released its owner lock after all I/O and journal syncs.
    fixture.options.continuous = false;
    assert_eq!(fixture.run().0, 0);
}

#[test]
fn subscription_narrowing_cannot_clear_a_previous_unknown_delivery_outcome() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1);
    let receiver = Receiver::new(vec![None]);
    let mut registration = fixture.register(&receiver.url, WebhookEventFilter::Wildcard);
    assert_eq!(fixture.run().0, 3);
    assert_eq!(receiver.finish().len(), 1);
    let before = fs::read(journal_path(&fixture.options)).unwrap();
    registration.filter = WebhookEventFilter::Selected(vec!["pull_request".into()]);
    fixture.store().register(registration).unwrap();
    let (code, output) = fixture.run();
    assert_eq!(code, 3, "a filtered old unknown is still unknown: {output}");
    assert!(output.contains("\"attempts\":0"));
    assert!(output.contains("\"filtered\":1"));
    assert!(output.contains("\"unknown\":1"));
    assert_eq!(fs::read(journal_path(&fixture.options)).unwrap(), before);
}

#[test]
fn a_one_poll_stop_pulse_cannot_resume_a_continuous_dispatcher_after_drain() {
    let mut fixture = Fixture::new(GitHashAlgorithm::Sha1);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    fixture.register(&format!("http://{}/hook", listener.local_addr().unwrap()), WebhookEventFilter::Wildcard);
    fixture.options.continuous = true;
    let pulsed = Cell::new(false);
    let polls = Cell::new(0);
    let stop = || {
        polls.set(polls.get() + 1);
        assert!(polls.get() < 64, "dispatcher resumed after a stop pulse instead of draining");
        if !pulsed.get() && fs::read_to_string(journal_path(&fixture.options)).is_ok_and(|s| s.contains("in-flight")) {
            pulsed.set(true);
            Ok(true)
        } else { Ok(false) }
    };
    let mut output = Vec::new();
    assert_eq!(execute(&fixture.options, &stop, &|| Ok(10_000), &mut output).unwrap(), 3);
    assert!(pulsed.get());
    assert!(listener.accept().is_err_and(|e| e.kind() == io::ErrorKind::WouldBlock));
    let output = String::from_utf8(output).unwrap();
    assert!(output.lines().last().unwrap().contains("\"stopped\":true"));
    assert!(output.contains("\"attempts\":1"));
}

fn status_args(fixture: &Fixture) -> Vec<String> {
    vec![fixture.options.storage.to_string_lossy().into_owned(), fixture.options.tenant.to_string(),
        fixture.options.repository.to_string(), "--trusted-local".into(), "--id".into(), fixture.options.id.0.to_string(),
        "--destination".into(), fixture.options.destination.as_str().to_owned(), "--object-format".into(),
        fixture.options.format.as_str().to_owned()]
}

#[test]
fn live_status_reads_persisted_native_nodes_without_sending_or_changing_authority_or_journal() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let registration = fixture.register(&format!("http://{}/hook", listener.local_addr().unwrap()), WebhookEventFilter::Wildcard);
        let before = snapshot(&fixture.options).unwrap();
        let key = before.entries[0].delivery_key();
        let path = journal_path(&fixture.options);
        let mut journal = Journal::open(&path, scope(&fixture.options, before.incarnation, &registration), 3).unwrap();
        journal.reserve(key, payload_hash(before.entries[0].payload_root()), 10_000, 10_000).unwrap();
        journal.observe(key, State::Unknown, 10_000, 10_000, b"lost receiver acknowledgement").unwrap();
        let bytes = fs::read(&path).unwrap();
        let mut output = Vec::new();
        assert_eq!(status::execute(&status_args(&fixture), &|| Ok(9_999), &mut output).unwrap(), 0);
        let output = String::from_utf8(output).unwrap();
        for expected in ["\"journal_present\":true", "\"scope_matches_current\":true", "\"unknown\":1",
            "\"clock_behind_floor\":true", "\"transport_attempted\":false", "\"journal_modified\":false",
            "\"durability_verified\":false", "\"canonical_settled\":false", "\"node_closed\":true"]
        { assert!(output.contains(expected), "{expected}: {output}"); }
        assert!(!output.contains("lost receiver acknowledgement"), "only the evidence digest is disclosed");
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(listener.accept().unwrap_err().kind(), io::ErrorKind::WouldBlock);
        let after = snapshot(&fixture.options).unwrap();
        assert_eq!(after.head, before.head);
        assert_eq!(after.entries, before.entries);
    }
}

#[test]
fn status_keeps_old_unknowns_visible_when_configuration_is_disabled_changed_or_unavailable() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut registration = fixture.register(&format!("http://{}/hook", listener.local_addr().unwrap()), WebhookEventFilter::Wildcard);
    let page = snapshot(&fixture.options).unwrap();
    let key = page.entries[0].delivery_key();
    let path = journal_path(&fixture.options);
    let mut journal = Journal::open(&path, scope(&fixture.options, page.incarnation, &registration), 3).unwrap();
    journal.reserve(key, payload_hash(page.entries[0].payload_root()), 10_000, 10_000).unwrap();
    journal.observe(key, State::Unknown, 10_000, 10_000, b"unknown").unwrap();
    let original = fs::read(&path).unwrap();
    let args = status_args(&fixture);
    registration.active = false;
    fixture.store().register(registration.clone()).unwrap();
    let mut output = Vec::new();
    status::execute(&args, &|| Ok(10_000), &mut output).unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("\"registration_active\":false"));
    assert!(output.contains("\"scope_matches_current\":true"));
    assert!(output.contains("\"unresolved\":1"));
    registration.url = SsrfPolicy::PERMISSIVE_FOR_TESTS.validate_url("http://127.0.0.1:9/changed").unwrap();
    fixture.store().register(registration).unwrap();
    let mut output = Vec::new();
    status::execute(&args, &|| Ok(10_000), &mut output).unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("\"scope_matches_current\":false"));
    assert!(output.contains("\"unresolved\":1"));
    fs::write(fixture.options.storage.join("webhooks/registrations.json"), "corrupt configuration\n").unwrap();
    let mut output = Vec::new();
    status::execute(&args, &|| Err("clock unavailable".into()), &mut output).unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("\"configuration_available\":false"));
    assert!(output.contains("\"scope_matches_current\":null"));
    assert!(output.contains("\"wall_clock_millis\":null"));
    assert!(output.contains("\"unresolved\":1"));
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_eq!(listener.accept().unwrap_err().kind(), io::ErrorKind::WouldBlock);
}

#[test]
fn status_output_failure_does_not_reserve_or_rewrite_a_delivery() {
    struct FailedStatusOutput;
    impl Write for FailedStatusOutput {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> { Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed status reader")) }
        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }
    let fixture = Fixture::new(GitHashAlgorithm::Sha1);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    fixture.register(&format!("http://{}/hook", listener.local_addr().unwrap()), WebhookEventFilter::Wildcard);
    let before = snapshot(&fixture.options).unwrap();
    assert!(status::execute(&status_args(&fixture), &|| Ok(10_000), &mut FailedStatusOutput).is_err());
    assert!(!journal_path(&fixture.options).exists());
    assert_eq!(snapshot(&fixture.options).unwrap().head, before.head);
    assert_eq!(listener.accept().unwrap_err().kind(), io::ErrorKind::WouldBlock);
}
