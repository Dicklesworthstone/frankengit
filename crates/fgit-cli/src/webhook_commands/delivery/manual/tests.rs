use super::*;
use fgit_authority::IdempotencyKey;
use fgit_forge::event::issue::{IssueAction, IssueCommand};
use fgit_forge::webhook::{WebhookRetrySchedule, WebhookSecret, WebhookSecretRotation};
use fgit_forge::{AggregateId, AggregateVersion, ExpectedVersion, IssueNumber, PullRequestNumber};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, HeadGeneration, PrincipalId, RepositoryId, TenantId};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn secret() -> WebhookSecret {
    WebhookSecret::new(b"0123456789abcdef0123456789abcdef".to_vec()).unwrap()
}

struct Fixture {
    scratch: PathBuf,
    options: Options,
    root: Digest,
    frame: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let scratch = std::env::temp_dir().join(format!(
            "fg-webhook-manual-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&scratch).unwrap();
        let storage = scratch.join("node");
        let tenant = TenantId::from_bytes([0xc1; 16]);
        let repository = RepositoryId::from_bytes([0xc2; 16]);
        let config = NodeConfig::new(storage.clone(), tenant, repository).with_worker_threads(2);
        let (mut node, _) = OneNode::init(config).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let request = node.request_context();
        let session = LoopbackReceiveSession::authenticated(
            PrincipalId::from_bytes([0xc3; 16]),
            IdempotencyKey::new(b"manual-webhook-fixture".to_vec()).unwrap(),
        );
        let command = IssueCommand {
            number: IssueNumber::try_new(1).unwrap(),
            expected_version: ExpectedVersion::NewStream,
            action: IssueAction::Open {
                title: "Deliver this committed issue".into(),
                body: "Not a placeholder payload".into(),
                labels: vec![],
            },
        };
        let outcome = node.runtime().block_on(node.admit_issue_durable_in(
            &request, &session, &command, Default::default(),
        )).unwrap();
        assert!(matches!(outcome.1.outcome, DecisionOutcome::Committed { .. }));
        let request = node.request_context();
        let page = node.runtime().block_on(node.read_forge_outbox_in(&request, None, 10, None)).unwrap();
        let entry = &page.entries[0];
        let request = node.request_context();
        let selected = node.runtime().block_on(node.select_forge_delivery_in(
            &request, entry.delivery_key(), entry.destination(), Some(page.source_head),
        )).unwrap();
        let frame = fgit_codec::encode_body(&selected.as_request().events.events[0]).unwrap();
        let options = Options {
            storage, tenant, repository, format: GitHashAlgorithm::Sha1,
            expected_head: Some(head_token(page.source_head)),
            after: None, limit: 10,
            key: Some(entry.delivery_key()), destination: Some(entry.destination()),
            webhook_id: Some(7), attempt: None, at_least_once: true, permissive: true,
        };
        let root = entry.payload_root();
        node.shutdown().unwrap();
        Self { scratch, options, root, frame }
    }

    fn register(&self, url: &str, filter: WebhookEventFilter) -> WebhookRegistration {
        let registration = WebhookRegistration {
            id: WebhookId(7),
            url: SsrfPolicy::PERMISSIVE_FOR_TESTS.validate_url(url).unwrap(),
            secrets: WebhookSecretRotation::new(secret()),
            filter,
            active: true,
            retry_schedule: WebhookRetrySchedule::default(),
        };
        self.store().register(registration.clone()).unwrap();
        registration
    }

    fn store(&self) -> WebhookStore {
        WebhookStore::open(self.options.storage.join("webhooks")).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.scratch); }
}

struct Captured {
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

struct Receiver {
    url: String,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<io::Result<Captured>>>,
}

impl Receiver {
    fn new(acknowledge: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/hook", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            while !stopping.load(Ordering::Acquire) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                        let captured = capture(&mut stream)?;
                        if acknowledge {
                            stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
                        }
                        return Ok(captured);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(io::Error::new(io::ErrorKind::TimedOut, "no webhook request received"))
        });
        Self { url, stop, worker: Some(worker) }
    }

    fn finish(mut self) -> Captured {
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
        return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected request target"));
    }
    let mut headers = BTreeMap::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete headers"));
        }
        if line == "\r\n" { break; }
        let (name, value) = line.split_once(':').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid request header")
        })?;
        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
    }
    let length = headers.get("content-length").and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value <= 32 * 1024)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid content length"))?;
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    Ok(Captured { headers, body })
}

fn assert_exact_signed_event(fixture: &Fixture, captured: &Captured) {
    assert_eq!(captured.headers["x-frankengit-signature-256"], secret().sign_hex(&captured.body));
    assert_eq!(captured.headers["x-frankengit-delivery"], fixture.options.key.unwrap().as_str());
    let text = std::str::from_utf8(&captured.body).unwrap();
    let expected: String = fixture.frame.iter().map(|byte| format!("{byte:02x}")).collect();
    assert!(text.contains(&format!("\"canonical_frame_hex\":\"{expected}\"")));
    assert!(text.contains(&format!("\"payload_root\":\"{}\"", fixture.root)));
    assert!(text.contains("\"events_count\":1"));
    assert!(!text.contains("\"attempt\""));
    let encoded = text.split("\"canonical_frame_hex\":\"").nth(1).unwrap().split('"').next().unwrap();
    let bytes: Vec<u8> = (0..encoded.len()).step_by(2)
        .map(|offset| u8::from_str_radix(&encoded[offset..offset + 2], 16).unwrap()).collect();
    let actual: ForgeEvent = fgit_codec::decode_body(&bytes, fgit_codec::DecodeLimits::DEFAULT).unwrap();
    let expected: ForgeEvent = fgit_codec::decode_body(&fixture.frame, fgit_codec::DecodeLimits::DEFAULT).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn manual_cli_sends_the_real_committed_event_with_its_original_root_and_signature() {
    let fixture = Fixture::new();
    let receiver = Receiver::new(true);
    fixture.register(&receiver.url, WebhookEventFilter::Selected(vec!["issue".into()]));
    let result = execute(&fixture.options, false);
    if result.is_err() { drop(receiver); panic!("manual delivery failed: {result:?}"); }
    let captured = receiver.finish();
    assert_exact_signed_event(&fixture, &captured);
    let (code, output) = result.unwrap();
    assert_eq!(code, 0);
    assert!(output.contains("\"verdict\":\"Accepted\""));
    assert!(output.contains("\"canonical_settled\":false"));
    assert!(output.contains("\"node_closed\":true"));
}

#[test]
fn dead_letter_replay_contacts_receiver_and_preserves_the_diagnostic() {
    let fixture = Fixture::new();
    let receiver = Receiver::new(true);
    let registration = fixture.register(&receiver.url, WebhookEventFilter::Wildcard);
    let record = DeadLetterEntry {
        delivery_id: fixture.options.key.unwrap(), webhook_id: registration.id,
        target_url: registration.url.raw().into(), payload_root: fixture.root,
        event_name: "issue".into(), attempts: 5,
        terminal_reason: "receiver was down".into(), failed_at_unix_secs: 1,
    };
    fixture.store().dead_letters().try_push(record.clone()).unwrap();
    let result = execute(&fixture.options, true);
    if result.is_err() { drop(receiver); panic!("manual replay failed: {result:?}"); }
    let captured = receiver.finish();
    assert_exact_signed_event(&fixture, &captured);
    assert_eq!(captured.headers["x-frankengit-attempt"], "6");
    let (code, output) = result.unwrap();
    assert_eq!(code, 0);
    assert!(output.contains("\"replay\":true"));
    assert!(output.contains("\"diagnostic_retained\":true"));
    assert_eq!(fixture.store().get_dead_letter(record.delivery_id), Some(record));
}

#[test]
fn lost_receiver_acknowledgement_is_not_success_and_does_not_trigger_a_retry() {
    let fixture = Fixture::new();
    let receiver = Receiver::new(false);
    fixture.register(&receiver.url, WebhookEventFilter::Wildcard);
    let result = execute(&fixture.options, false);
    if result.is_err() { drop(receiver); panic!("unexpected pre-send refusal: {result:?}"); }
    let captured = receiver.finish();
    assert_exact_signed_event(&fixture, &captured);
    let (code, output) = result.unwrap();
    assert_eq!(code, 3);
    assert!(output.contains("\"outcome_unknown\":true"));
    assert!(output.contains("\"automatic_retry\":false"));
}

#[test]
fn persisted_subscription_mismatch_refuses_before_connecting() {
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    fixture.register(&format!("http://{}/hook", listener.local_addr().unwrap()),
        WebhookEventFilter::Selected(vec!["pull_request".into()]));
    assert!(execute(&fixture.options, false).is_err());
    assert_eq!(listener.accept().unwrap_err().kind(), io::ErrorKind::WouldBlock);
}

#[test]
fn stale_or_retargeted_dead_letters_do_not_authorize_replay() {
    let fixture = Fixture::new();
    let registration = fixture.register("http://example.com/hook", WebhookEventFilter::Wildcard);
    let key = fixture.options.key.unwrap();
    let record = DeadLetterEntry {
        delivery_id: key, webhook_id: registration.id,
        target_url: registration.url.raw().into(), payload_root: fixture.root,
        event_name: "issue".into(), attempts: 5,
        terminal_reason: "failure".into(), failed_at_unix_secs: 1,
    };
    assert!(require_replay_binding(&record, &registration, key, fixture.root).is_ok());
    let mut changed = record.clone();
    changed.target_url = "http://example.com/different".into();
    assert!(require_replay_binding(&changed, &registration, key, fixture.root).is_err());
    changed = record.clone();
    changed.webhook_id = WebhookId(8);
    assert!(require_replay_binding(&changed, &registration, key, fixture.root).is_err());
    changed = record.clone();
    changed.payload_root = Digest::new(
        fgit_types::DigestAlgorithmId::try_new(1).unwrap(),
        fgit_types::DigestBytes::try_new(&[0xff; 32]).unwrap(),
    );
    assert!(require_replay_binding(&changed, &registration, key, fixture.root).is_err());
    assert!(require_replay_binding(&record, &registration, AsciiSlug::from_static("different"), fixture.root).is_err());
}

#[test]
fn event_filter_preserves_whole_batches_and_unknown_outcomes_are_never_success() {
    let event = ForgeEvent {
        aggregate: AggregateId::PullRequest(PullRequestNumber::try_new(1).unwrap()),
        version: AggregateVersion::FIRST,
        payload: ForgeEventPayload::PullRequestClosed { withdrawn: true },
    };
    assert!(require_subscription(&WebhookEventFilter::Wildcard, &[]).is_err());
    assert!(require_subscription(&WebhookEventFilter::Selected(vec!["kind:4".into()]), &[event.clone()]).is_ok());
    assert!(require_subscription(&WebhookEventFilter::Selected(vec!["PULL_REQUEST".into()]), &[event.clone()]).is_ok());
    assert!(require_subscription(&WebhookEventFilter::Selected(vec!["issue".into()]), &[event.clone()]).is_err());
    let mut advanced = event.clone();
    advanced.payload = ForgeEventPayload::PullRequestHeadAdvanced {
        source_tip: Digest::new(
            fgit_types::DigestAlgorithmId::try_new(1).unwrap(),
            fgit_types::DigestBytes::try_new(&[1; 32]).unwrap(),
        ),
    };
    assert!(require_subscription(&WebhookEventFilter::Selected(vec!["kind:4".into()]), &[event, advanced]).is_err());
    assert_eq!(exit_code("Accepted"), 0);
    assert_eq!(exit_code("TransientFailure"), 1);
    assert_eq!(exit_code("PermanentRejection"), 2);
    assert_eq!(exit_code("AmbiguousTimeout"), 3);
    assert_eq!(exit_code("unknown-future-verdict"), 2);
}
