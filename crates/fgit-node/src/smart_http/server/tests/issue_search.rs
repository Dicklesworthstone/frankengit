#![forbid(unsafe_code)]
//! Real buffered/split TCP requests through native routing and embedded authority.
use super::{profile, *};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(1);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-issue-search-http-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "retaining failed issue search fixture: {}",
                self.0.display()
            );
            return;
        }
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn exchange(
    profile: &Profile,
    method: &str,
    suffix: &str,
    body: &str,
    extra: &str,
    split: bool,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    peer.set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let head = format!(
        "{method} {}{suffix} HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer {}\r\nUser-Agent: frankengit-agent (+https://github.com/Dicklesworthstone/frankengit)\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n{extra}{}\r\n",
        String::from_utf8_lossy(&profile.route),
        "a".repeat(64),
        body.len(),
        if split {
            "Expect: 100-continue\r\n"
        } else {
            ""
        },
    );
    // Queue the complete request before accept/serve so header intake sees the
    // buffered body. The split twin waits for the real interim response.
    let mut bytes = head.into_bytes();
    if !split {
        bytes.extend_from_slice(body.as_bytes());
    }
    peer.write_all(&bytes).unwrap();
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let (stream, _) = listener.accept().unwrap();
            let deadline = GitDaemonSessionDeadline::new(
                GitDaemonSessionTimeout::try_new(Duration::from_secs(3)).unwrap(),
                GitDaemonSessionWorkScaling::FLAT,
            );
            serve_connection(stream, deadline, profile)
        });
        if split {
            let interim = b"HTTP/1.1 100 Continue\r\n\r\n";
            let mut observed = vec![0; interim.len()];
            peer.read_exact(&mut observed).unwrap();
            assert_eq!(observed, interim);
            peer.write_all(body.as_bytes()).unwrap();
        }
        let mut response = String::new();
        peer.take(64 * 1024).read_to_string(&mut response).unwrap();
        worker.join().unwrap();
        response
    })
}

fn successful_search(response: &str) {
    assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
    for field in [
        "\"type\":\"issue_search_page\"",
        "\"scanned\":0",
        "\"complete\":true",
        "\"refs_changed\":false",
        "\"transaction_created\":false",
        "\"issues\":[]",
    ] {
        assert!(response.contains(field), "missing {field}: {response}");
    }
}

fn exhaust(quota: &PushQuota, principal: PrincipalId) {
    for _ in 0..quota.limit.max_events {
        quota.evaluate(&principal).unwrap();
    }
    assert!(quota.evaluate(&principal).is_err());
}

#[test]
fn search_accepts_buffered_and_split_bodies_without_mutation_quota_or_writer_ownership() {
    for format in [
        fgit_types::GitHashAlgorithm::Sha1,
        fgit_types::GitHashAlgorithm::Sha256,
    ] {
        let scratch = Scratch::new();
        let config = NodeConfig::new(
            scratch.0.join("node"),
            TenantId::from_bytes([1; 16]),
            RepositoryId::from_bytes([2; 16]),
        )
        .with_object_format(format);
        let (mut node, _) = OneNode::init(config.clone()).unwrap();
        node.bring_into_service(fgit_types::HeadGeneration::FIRST)
            .unwrap();
        let path = scratch.0.join("credentials");
        let table = format!(
            "frankengit-http-credentials-v1 {} {} {}\n{} {} issues-read\n",
            TenantId::from_bytes([1; 16]),
            RepositoryId::from_bytes([2; 16]),
            node.repository_incarnation_id(),
            sha256_digest(&[b'a'; 64])
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            PrincipalId::from_bytes([3; 16]),
        );
        fs::write(&path, table).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut selected = profile();
        selected.route = node.git_daemon_repository_path().as_bytes().to_vec();
        selected.config = config.clone();
        selected.services = RepositoryHttpServices::NONE.with(RepositoryHttpService::Issues, true);
        selected.credentials = CredentialSource::File {
            path,
            binding: Binding {
                tenant: TenantId::from_bytes([1; 16]),
                repository: RepositoryId::from_bytes([2; 16]),
                incarnation: node.repository_incarnation_id(),
            },
        };
        selected.nodes = Arc::new(NodeLanes::new(config.clone(), 1, "issue search test"));
        node.shutdown().unwrap();
        let body = "query=needle&state=all&after=0&limit=1&max_scan=1";
        successful_search(&exchange(
            &selected,
            "POST",
            "/api/v1/issues/search",
            body,
            "",
            false,
        ));
        successful_search(&exchange(
            &selected,
            "POST",
            "/api/v1/issues/search",
            body,
            "",
            true,
        ));

        // Reads remain available when a different request owns the sole writer.
        selected.writers = Arc::new(WriterGate::new(1));
        let deadline = GitDaemonSessionDeadline::new(
            GitDaemonSessionTimeout::DEFAULT,
            GitDaemonSessionWorkScaling::FLAT,
        );
        let writer = selected.writers.acquire(&deadline).unwrap();
        successful_search(&exchange(
            &selected,
            "POST",
            "/api/v1/issues/search",
            body,
            "",
            false,
        ));
        drop(writer);

        // Mutation containment never grants or denies this read-only capability.
        let principal = PrincipalId::from_bytes([3; 16]);
        exhaust(&selected.quota, principal);
        successful_search(&exchange(
            &selected,
            "POST",
            "/api/v1/issues/search",
            body,
            "",
            false,
        ));
        let key = exchange(
            &selected,
            "POST",
            "/api/v1/issues/search",
            body,
            "Idempotency-Key: forbidden\r\n",
            false,
        );
        assert!(
            key.starts_with("HTTP/1.1 400 ") && key.contains("idempotency_key_not_allowed"),
            "{key}"
        );
        let forbidden_body = exchange(&selected, "GET", "/api/v1/issues", "x", "", false);
        assert!(
            forbidden_body.starts_with("HTTP/1.1 400 "),
            "{forbidden_body}"
        );

        // Search still consumes the bounded read quota, with no publication.
        selected.source_quota = Arc::new(PushQuota::default());
        exhaust(&selected.source_quota, principal);
        let limited = exchange(&selected, "POST", "/api/v1/issues/search", body, "", false);
        assert!(
            limited.starts_with("HTTP/1.1 429 ") && limited.contains("\"outcome_unknown\":false"),
            "{limited}"
        );
        selected.nodes.close().unwrap();
        let node = OneNode::open_existing(config).unwrap();
        let head = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        assert_eq!(
            head.receipt().generation(),
            fgit_types::HeadGeneration::FIRST
        );
        node.shutdown().unwrap();
    }
}
