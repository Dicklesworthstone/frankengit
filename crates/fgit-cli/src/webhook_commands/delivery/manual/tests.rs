use super::*;
use fgit_authority::IdempotencyKey;
use fgit_forge::event::issue::{IssueAction, IssueCommand};
use fgit_forge::webhook::{WebhookRetrySchedule, WebhookSecret, WebhookSecretRotation};
use fgit_forge::{AggregateId, AggregateVersion, ExpectedVersion, IssueNumber, PullRequestNumber};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, HeadGeneration, PrincipalId, RepositoryId, TenantId,
};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

mod guarded_replay;

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
        Self::with_format(GitHashAlgorithm::Sha1)
    }

    fn with_format(format: GitHashAlgorithm) -> Self {
        let scratch = std::env::temp_dir().join(format!(
            "fg-webhook-manual-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&scratch).unwrap();
        let storage = scratch.join("node");
        let tenant = TenantId::from_bytes([0xc1; 16]);
        let repository = RepositoryId::from_bytes([0xc2; 16]);
        let config = NodeConfig::new(storage.clone(), tenant, repository)
            .with_object_format(format)
            .with_worker_threads(2);
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
        let outcome = node
            .runtime()
            .block_on(node.admit_issue_durable_in(&request, &session, &command, Default::default()))
            .unwrap();
        assert!(matches!(
            outcome.1.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let request = node.request_context();
        let page = node
            .runtime()
            .block_on(node.read_forge_outbox_in(&request, None, 10, None))
            .unwrap();
        let entry = &page.entries[0];
        let request = node.request_context();
        let selected = node
            .runtime()
            .block_on(node.select_forge_delivery_in(
                &request,
                entry.delivery_key(),
                entry.destination(),
                Some(page.source_head),
            ))
            .unwrap();
        let frame = fgit_codec::encode_body(&selected.as_request().events.events[0]).unwrap();
        let options = Options {
            storage,
            tenant,
            repository,
            format,
            expected_head: Some(head_token(page.source_head)),
            after: None,
            limit: 10,
            key: Some(entry.delivery_key()),
            destination: Some(entry.destination()),
            webhook_id: Some(7),
            attempt: None,
            at_least_once: true,
            permissive: true,
            canonical_principal: None,
            replay_key: None,
        };
        let root = entry.payload_root();
        node.shutdown().unwrap();
        Self {
            scratch,
            options,
            root,
            frame,
        }
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
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.scratch);
    }
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
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "no webhook request received",
            ))
        });
        Self {
            url,
            stop,
            worker: Some(worker),
        }
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
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected request target",
        ));
    }
    let mut headers = BTreeMap::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete headers",
            ));
        }
        if line == "\r\n" {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid request header"))?;
        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
    }
    let length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value <= 32 * 1024)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid content length"))?;
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    Ok(Captured { headers, body })
}

fn assert_exact_signed_event(fixture: &Fixture, captured: &Captured) {
    assert_exact_signed_event_for(fixture, captured, fixture.options.key.unwrap());
}

fn assert_exact_signed_event_for(fixture: &Fixture, captured: &Captured, key: AsciiSlug) {
    assert_eq!(
        captured.headers["x-frankengit-signature-256"],
        secret().sign_hex(&captured.body)
    );
    assert_eq!(captured.headers["x-frankengit-delivery"], key.as_str());
    let text = std::str:…2481 tokens truncated…
                        write!(
                            stream,
                            "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => return Err(error),
                }
            }
            if !stopping.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "canonical replay did not drain before the receiver deadline",
                ));
            }
            Ok(requests)
        });
        Self {
            url,
            stop,
            worker: Some(worker),
        }
    }

    fn finish(mut self) -> Vec<Captured> {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap().unwrap()
    }
}

impl Drop for ReplayReceiver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn current_head(options: &Options) -> fgit_types::RepositoryAuthorityHeadId {
    with_node(options, |node| {
        let request = node.request_context();
        node.runtime()
            .block_on(node.read_forge_outbox_snapshot_in(&request, 16384, None))
            .map(|page| page.source_head)
            .map_err(|error| error.to_string())
    })
    .unwrap()
}

fn delivery_key(output: &str) -> AsciiSlug {
    let key = output
        .split("\"delivery_id\":\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    AsciiSlug::try_new("replay delivery", key.as_bytes()).unwrap()
}

#[test]
fn canonical_replay_recovers_after_its_pinned_head_advances() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut fixture = Fixture::with_format(format);
        let receiver = ReplayReceiver::new();
        fixture.register(&receiver.url, WebhookEventFilter::Wildcard);
        let principal = PrincipalId::from_bytes([0xc3; 16]);
        let route = dispatcher::Options {
            storage: fixture.options.storage.clone(),
            tenant: fixture.options.tenant,
            repository: fixture.options.repository,
            format,
            id: WebhookId(7),
            destination: fixture.options.destination.unwrap(),
            max_deliveries: 1,
            max_scan: 16384,
            timeout: Duration::from_secs(5),
            continuous: false,
            stop_file: None,
            poll: Duration::from_secs(1),
            permissive: true,
            canonical_principal: Some(principal),
        };
        let mut dispatch_output = Vec::new();
        let code = dispatcher::execute(&route, &|| Ok(false), &|| Ok(10_000), &mut dispatch_output)
            .unwrap();
        assert_eq!(code, 2, "{}", String::from_utf8_lossy(&dispatch_output));
        let original = fixture.options.key.unwrap();
        let diagnostic = fixture
            .store()
            .get_dead_letter_for(route.id, original)
            .unwrap();
        let source_head = current_head(&fixture.options);

        fixture.options.canonical_principal = Some(principal);
        fixture.options.replay_key = Some("guarded-replay".into());
        // The fixture's old pin precedes the original delivery's terminal CAS.
        // It must not publish a new responsibility or contact the receiver.
        let error = execute(&fixture.options, true).unwrap_err();
        assert!(error.contains("EvidenceStale"), "{error}");
        assert_eq!(current_head(&fixture.options), source_head);

        fixture.options.expected_head = Some(head_token(source_head));
        let (code, output) = execute(&fixture.options, true).unwrap();
        assert_eq!(code, 0, "{output}");
        let replay = delivery_key(&output);
        assert_ne!(replay, original);
        assert!(output.contains("\"attempts\":1"), "{output}");
        assert!(output.contains("\"canonical_settled\":true"), "{output}");
        assert!(output.contains("\"active_retired\":true"), "{output}");
        let settled_head = current_head(&fixture.options);
        assert_ne!(source_head, settled_head);

        // Simulate losing the successful response: retain the exact original
        // arguments, including its now-old expected head and idempotency key.
        let (code, recovered) = execute(&fixture.options, true).unwrap();
        assert_eq!(code, 0, "{recovered}");
        assert_eq!(delivery_key(&recovered), replay);
        assert!(recovered.contains("\"attempts\":0"), "{recovered}");
        assert!(recovered.contains("\"active_retired\":true"), "{recovered}");
        assert_eq!(current_head(&fixture.options), settled_head);

        // An old pin still refuses genuinely new work after exact recovery.
        fixture.options.replay_key = Some("another-guarded-replay".into());
        let error = execute(&fixture.options, true).unwrap_err();
        assert!(error.contains("EvidenceStale"), "{error}");
        assert_eq!(current_head(&fixture.options), settled_head);
        assert_eq!(
            fixture.store().get_dead_letter_for(route.id, original),
            Some(diagnostic)
        );

        let requests = receiver.finish();
        assert_eq!(requests.len(), 2, "original rejection plus one replay only");
        assert_exact_signed_event_for(&fixture, &requests[0], original);
        assert_exact_signed_event_for(&fixture, &requests[1], replay);
        assert_eq!(requests[0].headers["x-frankengit-attempt"], "1");
        assert_eq!(requests[1].headers["x-frankengit-attempt"], "1");
    }
}
