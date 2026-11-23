//! Real authenticated TCP search over canonical native PR publications.
use super::{profile, *};
use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::event::pull_request_labels::PullRequestLabelsCommand;
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_schema::json::{self, Value};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, RefName};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "fg-pull-search-http-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("retaining failed PR search fixture: {}", self.0.display());
        } else {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
}
fn principal() -> PrincipalId {
    PrincipalId::from_bytes([3; 16])
}
fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let label = match kind {
        GitObjectKind::Tree => "tree",
        GitObjectKind::Commit => "commit",
        _ => panic!("fixture needs only an empty tree and a root commit"),
    };
    let id = git_object_id(format, kind, body);
    let raw = [format!("{label} {}\0", body.len()).as_bytes(), body].concat();
    let size = u16::try_from(raw.len()).unwrap();
    let mut encoded = vec![0x78, 0x01, 0x01];
    encoded.extend(size.to_le_bytes());
    encoded.extend((!size).to_le_bytes());
    encoded.extend_from_slice(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521;
        (a, (b + a) % 65_521)
    });
    encoded.extend(((b << 16) | a).to_be_bytes());
    let hex = id.to_string();
    fs::create_dir_all(root.join("objects").join(&hex[..2])).unwrap();
    fs::write(
        root.join("objects").join(&hex[..2]).join(&hex[2..]),
        encoded,
    )
    .unwrap();
    id
}
fn fixture(node: &OneNode, root: &Scratch, format: GitHashAlgorithm) -> PullRequestData {
    let source = root.0.join("source");
    fs::create_dir_all(source.join("refs/heads")).unwrap();
    fs::write(source.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    fs::write(source.join("config"), match format {
        GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
        GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
    }).unwrap();
    let tree = loose(&source, format, GitObjectKind::Tree, b"");
    let body = format!(
        "tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nsearch fixture\n"
    );
    let tip = loose(&source, format, GitObjectKind::Commit, body.as_bytes());
    for name in ["main", "topic"] {
        fs::write(source.join("refs/heads").join(name), format!("{tip}\n")).unwrap();
    }
    let imported = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &node.request_context(),
            &source,
            principal(),
            b"pull-search-http-import",
        ))
        .unwrap();
    assert!(
        imported
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    PullRequestData {
        source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
        target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
        source_tip: tip,
        target_tip: tip,
        title: "placeholder".into(),
        body: "untrusted <script> text".into(),
    }
}
fn publish(node: &OneNode, data: &PullRequestData, number: u64, title: &str, update: bool) {
    let mut data = data.clone();
    data.title = title.into();
    let command = PullRequestCommand {
        number: PullRequestNumber::try_new(number).unwrap(),
        expected_version: if update {
            ExpectedVersion::Exactly(AggregateVersion::FIRST)
        } else {
            ExpectedVersion::NewStream
        },
        action: if update {
            PullRequestAction::Update
        } else {
            PullRequestAction::Open
        },
        data,
    };
    let session = crate::LoopbackReceiveSession::authenticated(
        principal(),
        IdempotencyKey::new(format!("http-search-{number}-{update}").into_bytes()).unwrap(),
    );
    let (_, terminal) = node
        .runtime()
        .block_on(node.admit_pull_request_durable_in(
            &node.request_context(),
            &session,
            &command,
            Default::default(),
        ))
        .unwrap();
    assert!(
        matches!(terminal.outcome, DecisionOutcome::Committed { .. }),
        "{terminal:?}"
    );
}
fn reopen(config: &NodeConfig) -> OneNode {
    let mut node = OneNode::open_existing(config.clone()).unwrap();
    let generation = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap()
        .receipt()
        .generation();
    node.bring_into_service(generation).unwrap();
    node
}
fn labels(node: &OneNode, previous: Option<AggregateVersion>, label: &str) {
    let command = PullRequestLabelsCommand {
        number: PullRequestNumber::try_new(2).unwrap(),
        expected_version: previous.map_or(ExpectedVersion::NewStream, ExpectedVersion::Exactly),
        labels: vec![label.into()],
    };
    let session = crate::LoopbackReceiveSession::authenticated(
        principal(),
        IdempotencyKey::new(format!("http-search-label-{label}").into_bytes()).unwrap(),
    );
    let (_, terminal) = node
        .runtime()
        .block_on(node.admit_pull_request_labels_durable_in(
            &node.request_context(),
            &session,
            &command,
            Default::default(),
        ))
        .unwrap();
    assert!(
        matches!(terminal.outcome, DecisionOutcome::Committed { .. }),
        "{terminal:?}"
    );
}
fn exchange(
    profile: &Profile,
    query: &str,
    token: Option<char>,
    body: &str,
    extra: &str,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    peer.set_write_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    let authorization = token.map_or_else(String::new, |token| {
        format!("Authorization: Bearer {}\r\n", token.to_string().repeat(64))
    });
    let request = format!(
        "GET {}/api/v1/pulls/search?{query} HTTP/1.1\r\nHost: local\r\n{authorization}Content-Length: {}\r\n{extra}\r\n{body}",
        String::from_utf8_lossy(&profile.route),
        body.len(),
    );
    peer.write_all(request.as_bytes()).unwrap();
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let (stream, _) = listener.accept().unwrap();
            let deadline = GitDaemonSessionDeadline::new(
                GitDaemonSessionTimeout::try_new(Duration::from_secs(60)).unwrap(),
                GitDaemonSessionWorkScaling::FLAT,
            );
            serve_connection(stream, deadline, profile)
        });
        let mut response = String::new();
        peer.take(128 * 1024).read_to_string(&mut response).unwrap();
        worker.join().unwrap();
        response
    })
}
fn status(response: &str, status: u16) {
    assert!(
        response.starts_with(&format!("HTTP/1.1 {status} ")),
        "{response}"
    );
}
fn response(response: &str, expected: u16) -> Value {
    status(response, expected);
    json::parse(response.split_once("\r\n\r\n").unwrap().1.as_bytes()).unwrap()
}
fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    &value.object().unwrap()[name]
}
fn numbers(value: &Value) -> Vec<u64> {
    let Value::Array(rows) = field(value, "pull_requests") else {
        panic!("search rows required")
    };
    rows.iter()
        .map(|row| field(row, "number").unsigned().unwrap())
        .collect()
}
fn first_row(value: &Value) -> &Value {
    let Value::Array(rows) = field(value, "pull_requests") else {
        panic!("search rows required")
    };
    rows.first().unwrap()
}

#[test]
fn pulls_read_search_filters_and_retained_continuations_cross_the_real_http_boundary() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = NodeConfig::new(
            root.0.join("node"),
            TenantId::from_bytes([1; 16]),
            RepositoryId::from_bytes([2; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(2);
        let (mut node, _) = OneNode::init(config.clone()).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let config = config.with_expected_repository_incarnation(node.repository_incarnation_id());
        let data = fixture(&node, &root, format);
        for (number, title) in [(1, "Unrelated"), (2, "Needle first"), (4, "Needle last")] {
            publish(&node, &data, number, title, false);
        }
        labels(&node, None, "before");
        let path = root.0.join("credentials");
        let binding = Binding {
            tenant: TenantId::from_bytes([1; 16]),
            repository: RepositoryId::from_bytes([2; 16]),
            incarnation: node.repository_incarnation_id(),
        };
        let mut table = format!(
            "frankengit-http-credentials-v2 {} {} {}\n",
            binding.tenant, binding.repository, binding.incarnation
        );
        for (token, scope) in [
            ('a', "pulls-read"),
            ('b', "issues-read"),
            ('c', "pulls-write"),
        ] {
            let digest: String = sha256_digest(token.to_string().repeat(64).as_bytes())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            table.push_str(&format!("{digest} {} {scope} none\n", principal()));
        }
        fs::write(&path, table).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut selected = profile();
        selected.route = node.git_daemon_repository_path().as_bytes().to_vec();
        selected.config = config.clone();
        selected.credentials = CredentialSource::File { path, binding };
        selected.services = RepositoryHttpServices::NONE.with(RepositoryHttpService::Pulls, true);
        selected.maximum_response_bytes = 128 * 1024;
        selected.nodes = Arc::new(NodeLanes::new(config.clone(), 1, "PR search HTTP test"));
        node.shutdown().unwrap();
        let filters = format!(
            "query=needle&state=open&opened_by={}&source_ref=refs/heads/topic&target_ref=refs/heads/main",
            principal()
        );
        for token in [None, Some('f')] {
            status(&exchange(&selected, &filters, token, "", ""), 401);
        }
        for token in ['b', 'c'] {
            let denied = exchange(&selected, &filters, Some(token), "", "");
            status(&denied, 403);
            assert!(!denied.contains("Needle"), "{denied}");
        }
        let mut disabled = selected.clone();
        disabled.services = RepositoryHttpServices::NONE;
        status(&exchange(&disabled, &filters, Some('a'), "", ""), 403);
        status(&exchange(&selected, &filters, Some('a'), "x", ""), 400);
        status(
            &exchange(
                &selected,
                &filters,
                Some('a'),
                "",
                "Expect: 100-continue\r\n",
            ),
            400,
        );
        status(&exchange(&selected, "after=1", Some('a'), "", ""), 400);

        let first = response(
            &exchange(
                &selected,
                &format!("{filters}&limit=1&max_scan=1"),
                Some('a'),
                "",
                "",
            ),
            200,
        );
        assert_eq!(field(&first, "type").text(), Some("pull_request_search"));
        assert!(numbers(&first).is_empty());
        assert_eq!(field(&first, "scanned").unsigned(), Some(1));
        assert_eq!(field(&first, "next_after").unsigned(), Some(1));
        assert_eq!(field(&first, "complete"), &Value::Bool(false));
        assert_eq!(field(&first, "stop_reason").text(), Some("scan_limit"));
        let token = field(&first, "snapshot_token").text().unwrap();

        selected.nodes.close().unwrap();
        let node = reopen(&config);
        publish(&node, &data, 2, "Changed after snapshot", true);
        publish(&node, &data, 3, "Needle inserted after snapshot", false);
        labels(&node, Some(AggregateVersion::FIRST), "after");
        let published = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap()
            .receipt()
            .generation();
        node.shutdown().unwrap();
        let next = response(
            &exchange(
                &selected,
                &format!("{filters}&after=1&expected_head={token}&limit=1&max_scan=100"),
                Some('a'),
                "",
                "",
            ),
            200,
        );
        assert_eq!(numbers(&next), [2]);
        assert_eq!(
            field(first_row(&next), "labels"),
            &Value::Array(vec![json::text("before")])
        );
        assert_eq!(
            field(first_row(&next), "labels_version").unsigned(),
            Some(1)
        );
        assert_eq!(
            field(first_row(&next), "labels_actor").text(),
            Some(principal().to_string().as_str())
        );
        assert_eq!(field(&next, "source_head"), field(&first, "source_head"));
        assert_eq!(field(&next, "next_after").unsigned(), Some(2));
        assert_eq!(field(&next, "stop_reason").text(), Some("result_limit"));
        let last = response(
            &exchange(
                &selected,
                &format!("{filters}&after=2&expected_head={token}&limit=10&max_scan=100"),
                Some('a'),
                "",
                "",
            ),
            200,
        );
        assert_eq!(numbers(&last), [4]);
        assert_eq!(field(&last, "complete"), &Value::Bool(true));
        assert_eq!(field(&last, "next_after"), &Value::Null);
        let fresh = response(
            &exchange(
                &selected,
                &format!("{filters}&limit=10&max_scan=100"),
                Some('a'),
                "",
                "",
            ),
            200,
        );
        assert_eq!(numbers(&fresh), [3, 4]);
        assert_ne!(field(&fresh, "source_head"), field(&first, "source_head"));
        let edited = response(
            &exchange(
                &selected,
                "query=Changed&state=open&limit=10&max_scan=100",
                Some('a'),
                "",
                "",
            ),
            200,
        );
        assert_eq!(numbers(&edited), [2]);
        assert_eq!(
            field(first_row(&edited), "labels"),
            &Value::Array(vec![json::text("after")])
        );
        assert_eq!(
            field(first_row(&edited), "labels_version").unsigned(),
            Some(2)
        );
        // Search consumes the shared read allowance, independently of push
        // containment. One admitted read exhausts this deliberately small
        // profile; its refusal must not contain any partial search results.
        let mut mutation_quota = PushQuota::default();
        mutation_quota.limit.max_events = 0;
        selected.quota = Arc::new(mutation_quota);
        assert!(selected.quota.evaluate(&principal()).is_err());
        let read_quota = || {
            let mut quota = PushQuota::default();
            quota.limit.max_events = 1;
            quota.limit.window = Duration::from_secs(3600);
            Arc::new(quota)
        };
        selected.source_quota = read_quota();
        let quota_query = "query=Changed&state=open&limit=10&max_scan=100";
        let permitted = response(&exchange(&selected, quota_query, Some('a'), "", ""), 200);
        assert_eq!(permitted, edited);
        let refused = exchange(&selected, quota_query, Some('a'), "", "");
        status(&refused, 429);
        assert!(refused.contains("\"outcome_unknown\":false"), "{refused}");
        assert!(!refused.contains("\"pull_requests\""), "{refused}");
        assert!(!refused.contains("Changed after snapshot"), "{refused}");
        selected.source_quota = read_quota();
        assert_eq!(
            response(&exchange(&selected, quota_query, Some('a'), "", ""), 200),
            edited
        );
        selected.nodes.close().unwrap();
        let node = reopen(&config);
        assert_eq!(
            node.runtime()
                .block_on(node.authenticate_authority_head())
                .unwrap()
                .receipt()
                .generation(),
            published
        );
        node.shutdown().unwrap();
    }
}
