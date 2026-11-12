//! Real storage and HTTP regression for the operator's pinned replay retry.
use super::*;
use crate::webhook_commands::dispatcher;

/// Reject the original delivery, then acknowledge explicit replay. Continue
/// observing until the caller has drained every command so an accidental
/// second replay send cannot disappear behind a closed test listener.
struct ReplayReceiver {
    url: String,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<io::Result<Vec<Captured>>>>,
}

impl ReplayReceiver {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/hook", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(60);
            let mut requests = Vec::new();
            while !stopping.load(Ordering::Acquire) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                        let request = capture(&mut stream)?;
                        if requests.len() >= 4 {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "replay exceeded the bounded test receiver",
                            ));
                        }
                        let status = if requests.is_empty() {
                            "400 Bad Request"
                        } else {
                            "204 No Content"
                        };
                        requests.push(request);
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
    thread::Builder::new()
        .name("guarded-replay-canonical".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(run_canonical_replay_recovers_after_its_pinned_head_advances)
        .unwrap()
        .join()
        .unwrap();
}

fn run_canonical_replay_recovers_after_its_pinned_head_advances() {
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
