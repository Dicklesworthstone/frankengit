#![forbid(unsafe_code)]
//! Actual fg processes, real persisted authority and signed TCP HTTP. Kill tests
//! terminate only an owned child after the receiver has read its complete body.
#![cfg(unix)]
use fgit_authority::IdempotencyKey;
use fgit_forge::event::issue::{IssueAction, IssueCommand};
use fgit_forge::webhook::{
    SsrfPolicy, WebhookEventFilter, WebhookId, WebhookRegistration, WebhookRetrySchedule,
    WebhookSecret, WebhookSecretRotation,
};
use fgit_forge::{ExpectedVersion, IssueNumber};
use fgit_node::webhook::WebhookStore;
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{
    AsciiSlug, DecisionOutcome, GitHashAlgorithm, HeadGeneration, PrincipalId, RepositoryId,
    TenantId,
};
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
const TENANT: &str = "11111111111111111111111111111111";
const REPOSITORY: &str = "22222222222222222222222222222222";
const PRINCIPAL: &str = "33333333333333333333333333333333";
static NEXT: AtomicU64 = AtomicU64::new(0);
fn secret() -> WebhookSecret {
    WebhookSecret::new(vec![0x42; 32]).unwrap()
}
struct Fixture {
    root: PathBuf,
    format: GitHashAlgorithm,
    key: AsciiSlug,
    destination: AsciiSlug,
}
impl Fixture {
    fn new(format: GitHashAlgorithm, url: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-canonical-http-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let config = NodeConfig::new(
            root.join("node"),
            TenantId::from_hex(TENANT).unwrap(),
            RepositoryId::from_hex(REPOSITORY).unwrap(),
        )
        .with_object_format(format)
        .with_worker_threads(2);
        let (mut node, _) = OneNode::init(config).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let request = node.request_context();
        let session = LoopbackReceiveSession::authenticated(
            PrincipalId::from_hex(PRINCIPAL).unwrap(),
            IdempotencyKey::new(b"real-http-source".to_vec()).unwrap(),
        );
        let command = IssueCommand {
            number: IssueNumber::try_new(1).unwrap(),
            expected_version: ExpectedVersion::NewStream,
            action: IssueAction::Open {
                title: "A real signed event".into(),
                body: "Exact payload for dispatch and replay".into(),
                labels: vec![],
            },
        };
        let (_, outcome) = node
            .runtime()
            .block_on(node.admit_issue_durable_in(&request, &session, &command, Default::default()))
            .unwrap();
        assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }));
        let page = node
            .runtime()
            .block_on(node.read_forge_outbox_snapshot_in(&request, 100, None))
            .unwrap();
        let entry = page.entries[0];
        let registration = WebhookRegistration {
            id: WebhookId(7),
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
        node.webhook_store()
            .unwrap()
            .register(registration)
            .unwrap();
        node.shutdown().unwrap();
        Self {
            root,
            format,
            key: entry.delivery_key(),
            destination: entry.destination(),
        }
    }
    fn command(&self, replay: bool) -> Command {
        self.command_with_policy(replay, true)
    }
    fn command_with_policy(&self, replay: bool, permissive: bool) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_fg"));
        c.arg("webhook");
        if replay {
            c.args(["dead-letter", "replay"]);
        } else {
            c.arg("dispatch");
        }
        c.arg(self.root.join("node")).args([
            TENANT,
            REPOSITORY,
            "--trusted-local",
            "--object-format",
            self.format.as_str(),
            "--id",
            "7",
            "--destination",
            self.destination.as_str(),
            "--at-least-once",
            "--canonical-principal",
            PRINCIPAL,
        ]);
        if permissive {
            c.arg("--permissive-for-tests");
        }
        if replay {
            c.args([
                "--delivery-id",
                self.key.as_str(),
                "--replay-key",
                "one-explicit-replay",
            ]);
        } else {
            c.args(["--max-deliveries", "1", "--attempt-timeout-secs", "5"]);
        }
        c
    }
    fn run(&self, replay: bool, expected: i32) -> String {
        let result = self.command(replay).output().unwrap();
        assert_eq!(
            result.status.code(),
            Some(expected),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        String::from_utf8(result.stdout).unwrap()
    }
    fn read<T>(&self, read: impl FnOnce(&OneNode) -> T) -> T {
        let config = NodeConfig::new(
            self.root.join("node"),
            TenantId::from_hex(TENANT).unwrap(),
            RepositoryId::from_hex(REPOSITORY).unwrap(),
        )
        .with_object_format(self.format)
        .with_worker_threads(2);
        let mut node = OneNode::open_existing(config).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let r = read(&node);
        node.shutdown().unwrap();
        r
    }
    fn head(&self) -> fgit_types::RepositoryAuthorityHeadId {
        self.read(|node| {
            let request = node.request_context();
            node.runtime()
                .block_on(node.read_forge_outbox_snapshot_in(&request, 100, None))
                .unwrap()
                .source_head
        })
    }
    fn receipt(&self, key: AsciiSlug) -> Vec<u8> {
        self.read(|node| {
            let request = node.request_context();
            let receipt = node
                .runtime()
                .block_on(node.read_retired_forge_receipt_in(&request, key, self.destination, None))
                .unwrap();
            fgit_codec::encode_body(receipt.receipt()).unwrap()
        })
    }
    fn spawn(&self, replay: bool) -> OwnedChild {
        let stdout = fs::File::create(self.root.join("child.stdout")).unwrap();
        let stderr = fs::File::create(self.root.join("child.stderr")).unwrap();
        OwnedChild(
            self.command(replay)
                .stdin(Stdio::null())
                .stdout(stdout)
                .stderr(stderr)
                .spawn()
                .unwrap(),
        )
    }
}
// A failed assertion still reaps our subprocess before fixture removal.
struct OwnedChild(Child);
impl std::ops::Deref for OwnedChild {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}
impl std::ops::DerefMut for OwnedChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
#[derive(Clone, Debug)]
struct Captured {
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}
struct Receiver {
    url: String,
    stop: Arc<AtomicBool>,
    captured: Arc<Mutex<Vec<Captured>>>,
    worker: Option<JoinHandle<Result<(), String>>>,
}
impl Receiver {
    fn new(statuses: Vec<Option<u16>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/hook", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let captured = Arc::new(Mutex::new(vec![]));
        let observations = Arc::clone(&captured);
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(90);
            for status in statuses {
                let mut stream = loop {
                    if stopping.load(Ordering::Acquire) {
                        return Ok(());
                    }
                    if Instant::now() >= deadline {
                        return Err("expected HTTP request absent".into());
                    }
                    match listener.accept() {
                        Ok((s, _)) => break s,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5))
                        }
                        Err(e) => return Err(e.to_string()),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .map_err(|e| e.to_string())?;
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .map_err(|e| e.to_string())?;
                let request = capture(&mut stream)?;
                observations.lock().unwrap().push(request);
                if let Some(code) = status {
                    write!(
                        stream,
                        "HTTP/1.1 {code} Result\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .map_err(|e| e.to_string())?;
                    stream.flush().map_err(|e| e.to_string())?;
                } else {
                    stream
                        .set_read_timeout(Some(Duration::from_millis(100)))
                        .map_err(|e| e.to_string())?;
                    let mut extra = [0];
                    loop {
                        if stopping.load(Ordering::Acquire) || Instant::now() >= deadline {
                            break;
                        }
                        match stream.read(&mut extra) {
                            Ok(0) => break,
                            Ok(_) => return Err("unexpected bytes after complete HTTP body".into()),
                            Err(e)
                                if matches!(
                                    e.kind(),
                                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                                ) => {}
                            Err(_) => break,
                        }
                    }
                }
            }
            // Remain an independent absence oracle after the killed stream's
            // EOF. Any recovery request is read, counted and answered.
            while !stopping.load(Ordering::Acquire) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(5)))
                            .map_err(|e| e.to_string())?;
                        observations.lock().unwrap().push(capture(&mut stream)?);
                        write!(stream,"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").map_err(|e|e.to_string())?;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => return Err(e.to_string()),
                }
            }
            Ok(())
        });
        Self {
            url,
            stop,
            captured,
            worker: Some(worker),
        }
    }
    fn wait_for(&self, count: usize, child: &mut Child) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while self.captured.lock().unwrap().len() < count {
            assert!(
                child.try_wait().unwrap().is_none(),
                "fg exited before complete request body"
            );
            assert!(Instant::now() < deadline, "HTTP child made no progress");
            thread::sleep(Duration::from_millis(5));
        }
    }
    fn finish(mut self) -> Vec<Captured> {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap().unwrap();
        self.captured.lock().unwrap().clone()
    }
}
impl Drop for Receiver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}
fn capture(stream: &mut TcpStream) -> Result<Captured, String> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    if !line.starts_with("POST /hook HTTP/1.1") {
        return Err(format!("unexpected request {line}"));
    }
    let mut headers = BTreeMap::new();
    loop {
        line.clear();
        reader.read_line(&mut line).map_err(|e| e.to_string())?;
        if line == "\r\n" {
            break;
        }
        if line.len() > 8192 || headers.len() > 64 {
            return Err("request header bound".into());
        }
        let (name, value) = line.split_once(':').ok_or("invalid header")?;
        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
    }
    let length = headers
        .get("content-length")
        .and_then(|n| n.parse::<usize>().ok())
        .filter(|n| *n <= 32768)
        .ok_or("invalid length")?;
    let mut body = vec![0; length];
    reader.read_exact(&mut body).map_err(|e| e.to_string())?;
    Ok(Captured { headers, body })
}
fn string_field(output: &str, key: &str) -> String {
    let needle = format!("\"{key}\":\"");
    output
        .split_once(&needle)
        .unwrap()
        .1
        .split('"')
        .next()
        .unwrap()
        .to_owned()
}
fn assert_signed(request: &Captured) {
    assert_eq!(
        request.headers["x-frankengit-signature-256"],
        secret().sign_hex(&request.body)
    );
}

#[test]
fn actual_fg_strict_ssrf_publishes_terminal_refusal_without_reaching_loopback() {
    let receiver = Receiver::new(vec![]);
    let fixture = Fixture::new(GitHashAlgorithm::Sha256, &receiver.url);
    let initial = fixture.head();
    let result = fixture.command_with_policy(false, false).output().unwrap();
    assert_eq!(
        result.status.code(),
        Some(2),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let output = String::from_utf8(result.stdout).unwrap();
    assert!(output.contains("\"active_retired\":true"), "{output}");
    assert_ne!(initial, fixture.head());
    assert!(!fixture.receipt(fixture.key).is_empty());
    assert!(
        WebhookStore::open(fixture.root.join("node/webhooks"))
            .unwrap()
            .get_dead_letter_for(WebhookId(7), fixture.key)
            .is_some()
    );
    assert!(receiver.finish().is_empty());
}

#[test]
fn actual_fg_dispatch_and_new_sealed_replay_preserve_original_outcome_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let receiver = Receiver::new(vec![Some(503), Some(503), Some(503), Some(204)]);
        let fixture = Fixture::new(format, &receiver.url);
        let initial = fixture.head();
        fixture.run(false, 1);
        fixture.run(false, 1);
        let failure = fixture.run(false, 2);
        assert!(failure.contains("\"active_retired\":true"));
        assert_ne!(initial, fixture.head());
        let original = fixture.receipt(fixture.key);
        let before_replay = fixture.head();
        let replay = fixture.run(true, 0);
        let new_key = AsciiSlug::try_new(
            "new replay",
            string_field(&replay, "delivery_id").as_bytes(),
        )
        .unwrap();
        assert_ne!(fixture.key, new_key);
        assert!(replay.contains("\"attempts\":1"));
        assert!(replay.contains("\"active_retired\":true"));
        let terminal = fixture.head();
        assert_ne!(before_replay, terminal);
        assert_eq!(fixture.receipt(fixture.key), original);
        let new_receipt = fixture.receipt(new_key);
        assert_ne!(new_receipt, original);
        let repeated = fixture.run(true, 0);
        assert_eq!(string_field(&repeated, "delivery_id"), new_key.as_str());
        assert!(repeated.contains("\"attempts\":0"));
        assert_eq!(terminal, fixture.head());
        assert_eq!(fixture.receipt(new_key), new_receipt);
        assert!(
            WebhookStore::open(fixture.root.join("node/webhooks"))
                .unwrap()
                .get_dead_letter_for(WebhookId(7), fixture.key)
                .is_some()
        );
        let requests = receiver.finish();
        assert_eq!(requests.len(), 4);
        for request in &requests {
            assert_signed(request);
        }
        let original_body = std::str::from_utf8(&requests[0].body).unwrap();
        let replay_body = std::str::from_utf8(&requests[3].body).unwrap();
        assert_eq!(
            string_field(original_body, "payload_root"),
            string_field(replay_body, "payload_root")
        );
        assert_eq!(
            original_body.split_once("\"events\":").unwrap().1,
            replay_body.split_once("\"events\":").unwrap().1
        );
        assert_eq!(
            requests[3].headers["x-frankengit-delivery"],
            new_key.as_str()
        );
    }
}
#[test]
fn actual_fg_failed_manual_replay_has_one_send_and_preserves_original_receipt() {
    let receiver = Receiver::new(vec![Some(503), Some(503), Some(503), Some(503)]);
    let fixture = Fixture::new(GitHashAlgorithm::Sha1, &receiver.url);
    fixture.run(false, 1);
    fixture.run(false, 1);
    fixture.run(false, 2);
    let original = fixture.receipt(fixture.key);
    let replay = fixture.run(true, 2);
    let new_key = AsciiSlug::try_new(
        "new replay",
        string_field(&replay, "delivery_id").as_bytes(),
    )
    .unwrap();
    assert_ne!(new_key, fixture.key);
    assert!(replay.contains("\"attempts\":1"), "{replay}");
    assert!(replay.contains("\"active_retired\":true"), "{replay}");
    let head = fixture.head();
    let failed_receipt = fixture.receipt(new_key);
    assert_eq!(fixture.receipt(fixture.key), original);
    let repeated = fixture.run(true, 2);
    assert!(repeated.contains("\"attempts\":0"), "{repeated}");
    assert_eq!(fixture.head(), head);
    assert_eq!(fixture.receipt(new_key), failed_receipt);
    assert!(
        WebhookStore::open(fixture.root.join("node/webhooks"))
            .unwrap()
            .get_dead_letter_for(WebhookId(7), new_key)
            .is_some()
    );
    let requests = receiver.finish();
    assert_eq!(requests.len(), 4);
    for request in requests {
        assert_signed(&request);
    }
}
#[test]
fn killed_dispatch_and_manual_replay_recover_the_marker_without_another_http_send() {
    for (replay, format) in [
        (false, GitHashAlgorithm::Sha1),
        (true, GitHashAlgorithm::Sha256),
    ] {
        let mut statuses = if replay {
            vec![Some(503), Some(503), Some(503)]
        } else {
            vec![]
        };
        statuses.push(None);
        let receiver = Receiver::new(statuses);
        let fixture = Fixture::new(format, &receiver.url);
        if replay {
            fixture.run(false, 1);
            fixture.run(false, 1);
            fixture.run(false, 2);
        }
        let count = if replay { 4 } else { 1 };
        let mut child = fixture.spawn(replay);
        receiver.wait_for(count, &mut child);
        // Owned subprocess termination occurs after complete network write,
        // before a reply. Kernel-released file locks cannot prove non-delivery.
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        let selected = fixture.read(|node| {
            let request = node.request_context();
            let page = node
                .runtime()
                .block_on(node.read_forge_outbox_snapshot_in(&request, 100, None))
                .unwrap();
            assert_eq!(page.entries.len(), 1);
            let key = page.entries[0].delivery_key();
            let p = node
                .runtime()
                .block_on(node.read_forge_dispatch_in(&request, key, None))
                .unwrap()
                .unwrap();
            assert!(p.routes()[0].in_flight);
            key
        });
        let result = fixture.run(replay, 3);
        assert!(result.contains("\"attempts\":0"));
        assert!(result.contains("\"active_retired\":false"));
        fixture.read(|node| {
            let request = node.request_context();
            let p = node
                .runtime()
                .block_on(node.read_forge_dispatch_in(&request, selected, None))
                .unwrap()
                .unwrap();
            assert!(p.finished_effect_root().is_some());
            assert!(matches!(
                p.routes()[0].state,
                fgit_resource::ReconcileState::Indeterminate { .. }
            ));
        });
        let requests = receiver.finish();
        assert_eq!(requests.len(), count);
        for request in &requests {
            assert_signed(request);
        }
    }
}

#[test]
fn canonical_unknown_source_can_be_explicitly_replayed_without_a_local_diagnostic() {
    let receiver = Receiver::new(vec![None, Some(204)]);
    let fixture = Fixture::new(GitHashAlgorithm::Sha1, &receiver.url);
    fixture.run(false, 3);
    assert!(
        WebhookStore::open(fixture.root.join("node/webhooks"))
            .unwrap()
            .get_dead_letter_for(WebhookId(7), fixture.key)
            .is_none()
    );
    let original = fixture.read(|node| {
        let request = node.request_context();
        let (_, effect, _) = node
            .runtime()
            .block_on(node.read_forge_replay_source_in(
                &request,
                fixture.key,
                fixture.destination,
                None,
            ))
            .unwrap();
        assert_eq!(effect.state(), fgit_resource::ObligationState::Escalated);
        effect.root().unwrap()
    });
    let result = fixture.run(true, 0);
    assert!(result.contains("\"original_diagnostic_retained\":false"));
    let key = AsciiSlug::try_new(
        "replayed unknown",
        string_field(&result, "delivery_id").as_bytes(),
    )
    .unwrap();
    assert_ne!(key, fixture.key);
    fixture.read(|node| {
        let request = node.request_context();
        let (_, effect, _) = node
            .runtime()
            .block_on(node.read_forge_replay_source_in(
                &request,
                fixture.key,
                fixture.destination,
                None,
            ))
            .unwrap();
        assert_eq!(effect.root().unwrap(), original);
    });
    fixture.receipt(key);
    let head = fixture.head();
    assert!(fixture.run(true, 0).contains("\"attempts\":0"));
    assert_eq!(head, fixture.head());
    let requests = receiver.finish();
    assert_eq!(requests.len(), 2);
    for request in &requests {
        assert_signed(request);
    }
}
