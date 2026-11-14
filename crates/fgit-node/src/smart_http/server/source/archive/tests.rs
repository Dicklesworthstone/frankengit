use super::*;
use super::super::request::{Command, Operation, Request as WireRequest};
use crate::{
    DeadlineTcpStream, GitDaemonSessionDeadline, GitDaemonSessionTimeout,
    GitDaemonSessionWorkScaling, LoopbackReceiveSession, NodeConfig,
};
use fgit_authority::IdempotencyKey;
use fgit_forge::source_archive::collect;
use fgit_forge::source_browse::{
    SourceBrowseAction, SourceBrowseContent, SourceBrowseError, SourceBrowseReport,
};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, GitHashAlgorithm, GitOid,
    PrincipalId, RefName, RepositoryAuthorityHeadId, RepositoryCommitId, RepositoryId,
    TenantId,
};
use fgit_wire::smart_http::{BodyFraming, HttpLimits, head};
use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

fn envelope(raw: &[u8]) -> head::Envelope<'_> {
    head::parse(raw, HttpLimits::default()).unwrap().unwrap()
}
fn request() -> WireRequest<'static> {
    WireRequest {
        repository_route: "/repo.git",
        operation: Operation::Archive,
    }
}
fn query() -> SourceBrowseQuery {
    SourceBrowseQuery {
        path: None,
        expected_head: None,
        expected_commit: None,
        action: SourceBrowseAction::List { after: None, limit: 1000 },
    }
}
const FORM_HEADERS: &str = "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n";

#[test]
fn archive_route_is_a_source_read_without_publication_or_history_permission() {
    let raw = format!("POST /repo.git/api/v1/source/archive HTTP/1.1\r\nHost: local\r\n{FORM_HEADERS}\r\n");
    let parsed = envelope(raw.as_bytes());
    let selected = WireRequest::parse(&parsed).unwrap();
    assert_eq!(selected.operation, Operation::Archive);
    assert_eq!(selected.repository_route, "/repo.git");
    let outer = super::super::Request::parse(&parsed).unwrap();
    assert!(outer.is_archive());
    assert!(!outer.is_mutation());
    assert!(!outer.requires_history_read());
    assert_eq!(outer.agent_operation(), Some(fgit_identity::agent::SOURCE_READ));
    assert_eq!(outer.candidate_upload_maximum(), None);
    let Command::Archive { selection, query } = selected
        .command(
            b"ref=refs/heads/main&object_format=sha256&path_hex=737263ff",
            GitHashAlgorithm::Sha256,
        )
        .unwrap()
    else {
        panic!("archive command");
    };
    assert_eq!(selection.reference.as_bytes(), b"refs/heads/main");
    assert_eq!(query.path.as_deref(), Some(b"src\xff".as_slice()));
    assert_eq!(query.action, SourceBrowseAction::List { after: None, limit: 1000 });
    for action in ["tree", "blob", "commit"] {
        let raw = format!("POST /repo.git/api/v1/source/{action} HTTP/1.1\r\nHost: local\r\n{FORM_HEADERS}\r\n");
        assert!(!super::super::Request::parse(&envelope(raw.as_bytes())).unwrap().is_archive());
    }
}

#[test]
fn archive_form_cannot_omit_prefixes_override_authority_or_raise_limits() {
    let base = "ref=refs/heads/main&object_format=sha1";
    assert!(request().command(base.as_bytes(), GitHashAlgorithm::Sha1).is_ok());
    for extra in [
        "&after_hex=61", "&offset=0", "&limit=1", "&max_bytes=100",
        "&object_id=aa", "&principal=admin", "&force=true",
        "&ref=refs/heads/other", "&path_hex=", "&path_hex=2e2e",
        "&path_hex=612f2f62", "&path_hex=FF", "&expected_head=invalid",
    ] {
        assert!(
            request().command(format!("{base}{extra}").as_bytes(), GitHashAlgorithm::Sha1).is_err(),
            "{extra}"
        );
    }
    for body in [
        format!("{base}&expected_commit={}", "0".repeat(40)),
        "ref=refs/heads/main&object_format=sha256".to_owned(),
        "object_format=sha1".to_owned(),
        "ref=refs/heads/main".to_owned(),
    ] {
        assert!(request().command(body.as_bytes(), GitHashAlgorithm::Sha1).is_err());
    }
}

#[test]
fn archive_rejects_methods_query_parameters_and_protocol_or_media_confusion() {
    for (method, path, headers) in [
        ("GET", "/repo.git/api/v1/source/archive", FORM_HEADERS),
        ("HEAD", "/repo.git/api/v1/source/archive", FORM_HEADERS),
        ("POST", "/repo.git/api/v1/source/archive?ref=secret", FORM_HEADERS),
        ("POST", "/../repo/api/v1/source/archive", FORM_HEADERS),
        ("POST", "/repo.git/api/v1/source/archive", "Content-Type: application/x-www-form-urlencoded\r\n"),
        ("POST", "/repo.git/api/v1/source/archive", "Content-Type: application/json\r\nContent-Length: 1\r\n"),
        ("POST", "/repo.git/api/v1/source/archive", "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\nGit-Protocol: version=2\r\n"),
        ("POST", "/repo.git/api/v1/source/archive", "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 262145\r\n"),
    ] {
        let raw = format!("{method} {path} HTTP/1.1\r\nHost: local\r\n{headers}\r\n");
        assert!(WireRequest::parse(&envelope(raw.as_bytes())).is_err(), "{raw}");
    }
    let raw = b"POST /repo.git/api/v1/source/archive HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded; charset=utf-8\r\nTransfer-Encoding: chunked\r\n\r\n";
    assert!(WireRequest::parse(&envelope(raw)).is_ok());
}

#[test]
fn archive_error_mapping_preserves_resource_snapshot_and_hidden_source_boundaries() {
    let missing = archive_error(SourceArchiveError::Read(NodeWorkspaceRefusal::RefUnavailable));
    assert_eq!(missing.status, Status::NotFound);
    assert_eq!(missing.code, "not_found");
    let moved = archive_error(SourceArchiveError::Read(NodeWorkspaceRefusal::SourceBrowse(
        Box::new(SourceBrowseError::SnapshotMoved),
    )));
    assert_eq!(moved.status, Status::Conflict);
    assert_eq!(moved.code, "source_snapshot_moved");
    let budget = archive_error(SourceArchiveError::Budget("private size detail"));
    assert_eq!(budget.status, Status::TooLarge);
    let invalid = archive_error(SourceArchiveError::Invalid("private/path/and/link-target"));
    assert_eq!(invalid.status, Status::Conflict);
    assert_eq!(invalid.code, "source_archive_profile_refused");
    assert!(!invalid.outcome_unknown);
    let mut response = Vec::new();
    invalid.send_named(&mut response, HttpVersion::Http11, "source_error").unwrap();
    assert!(!String::from_utf8(response).unwrap().contains("private"));
}

fn empty_archive() -> SourceArchive {
    let algorithm = DigestAlgorithmId::try_new(2).unwrap();
    let source_head = RepositoryAuthorityHeadId::from_digest(
        algorithm, CANONICAL_CODEC_VERSION, DigestBytes::try_new(&[3; 32]).unwrap(),
    );
    let source_rcr = RepositoryCommitId::from_digest(
        algorithm, CANONICAL_CODEC_VERSION, DigestBytes::try_new(&[4; 32]).unwrap(),
    );
    let source_commit = GitOid::from_hex(GitHashAlgorithm::Sha1, &"ab".repeat(20)).unwrap();
    let tree = GitOid::from_hex(GitHashAlgorithm::Sha1, &"cd".repeat(20)).unwrap();
    let report = SourceBrowseReport {
        repository_id: RepositoryId::from_bytes([2; 16]),
        source_head,
        source_rcr,
        source_commit,
        root_tree: tree,
        object_id: tree,
        path: None,
        content: SourceBrowseContent::Directory { entries: vec![], next_after: None },
    };
    collect(
        report.repository_id,
        GitHashAlgorithm::Sha1,
        &query(),
        |_| Ok::<_, NodeWorkspaceRefusal>(report.clone()),
    ).unwrap()
}

#[test]
fn archive_response_carries_complete_native_selection_and_propagates_output_failure() {
    let reply = Reply { archive: empty_archive() };
    assert_eq!(reply.archive.bytes.len(), 1536);
    for (version, prefix) in [(HttpVersion::Http10, "HTTP/1.0"), (HttpVersion::Http11, "HTTP/1.1")] {
        let mut wire = Vec::new();
        reply.send(&mut wire, version).unwrap();
        let split = wire.windows(4).position(|part| part == b"\r\n\r\n").unwrap();
        let headers = std::str::from_utf8(&wire[..split]).unwrap();
        assert!(headers.starts_with(&format!("{prefix} 200 OK\r\n")));
        for expected in [
            "Content-Type: application/x-tar",
            "Content-Disposition: attachment; filename=\"source.tar\"",
            "Content-Length: 1536",
            "Cache-Control: no-store",
            "Vary: Authorization",
            "X-Content-Type-Options: nosniff",
            "X-FrankenGit-Archive-Profile: ustar-source-v1",
            "X-FrankenGit-Archive-Entries: 1",
            "X-FrankenGit-Archive-Gitlinks: 0",
            "X-FrankenGit-Archive-Reads: 1",
        ] {
            assert!(headers.contains(expected), "{headers}");
        }
        assert!(headers.contains(&format!(
            "X-FrankenGit-Source-Commit: {}", reply.archive.pin.commit,
        )));
        assert_eq!(&wire[split + 4..], reply.archive.bytes);
    }
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }
    assert_eq!(
        reply.send(&mut Broken, HttpVersion::Http11).unwrap_err().kind(),
        io::ErrorKind::BrokenPipe,
    );
}

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-source-archive-unit-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}
fn node(root: &Scratch) -> OneNode {
    let (mut node, _) = OneNode::init(NodeConfig::new(
        root.0.join("node"),
        TenantId::from_bytes([1; 16]),
        RepositoryId::from_bytes([2; 16]),
    ).with_worker_threads(2)).unwrap();
    let head = node.runtime().block_on(node.authenticate_authority_head()).unwrap();
    node.bring_into_service(head.receipt().generation()).unwrap();
    node
}
fn expired_deadline() -> GitDaemonSessionDeadline {
    let mut deadline = GitDaemonSessionDeadline::new(
        GitDaemonSessionTimeout::try_new(Duration::from_secs(1)).unwrap(),
        GitDaemonSessionWorkScaling::FLAT,
    );
    deadline.started = Instant::now() - Duration::from_secs(2);
    deadline
}

#[test]
fn cancellation_and_too_small_response_budget_refuse_before_source_io() {
    let root = Scratch::new();
    let node = node(&root);
    let before = node.runtime().block_on(node.authenticate_authority_head()).unwrap();
    let context = node.request_context();
    let selection = Selection {
        reference: RefName::try_new(b"refs/heads/missing").unwrap(),
        expected_head: None,
        expected_commit: None,
    };
    let mut checks = 0;
    let result = produce(&node, &context, &selection, &query(), (MIN_ARCHIVE_BYTES - 1) as u64, &mut || {
        checks += 1;
        true
    });
    assert_eq!(result.err().unwrap().status, Status::TooLarge);
    assert_eq!(checks, 0);
    assert_eq!(
        produce(&node, &context, &selection, &query(), MAX_ARCHIVE_BYTES as u64, &mut || false)
            .err().unwrap().status,
        Status::Timeout,
    );
    let after = node.runtime().block_on(node.authenticate_authority_head()).unwrap();
    assert_eq!(before.receipt().generation(), after.receipt().generation());
    node.shutdown().unwrap();
}

#[test]
fn archive_collection_inherits_an_already_spent_admission_deadline() {
    let root = Scratch::new();
    let node = node(&root);
    let form = b"object_format=sha1&ref=refs/heads/missing";
    let raw = format!(
        "POST /repo.git/api/v1/source/archive HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n",
        form.len(),
    );
    let envelope = envelope(raw.as_bytes());
    let selected = super::super::Request::parse(&envelope).unwrap();
    let session = LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([3; 16]),
        IdempotencyKey::new(b"read-only-source-query".to_vec()).unwrap(),
    );
    let deadline = expired_deadline();
    let context = super::super::archive_request_context(&node, &deadline, &session);
    assert!(!context.is_live());
    // A new phase clock would disclose the absent ref instead of reporting
    // timeout. No sleeping or race with the real scheduler is needed.
    let refused = super::super::execute(
        &node,
        &selected,
        &session,
        None,
        None,
        BodyFraming::ContentLength(form.len() as u64),
        &mut form.as_slice(),
        HttpLimits::default(),
        MAX_ARCHIVE_BYTES as u64,
        &deadline,
    ).err().unwrap();
    assert_eq!(refused.status, Status::Timeout);
    node.shutdown().unwrap();
}

#[test]
fn archive_delivery_never_renews_an_expired_request_clock() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut socket, _) = listener.accept().unwrap();
    let mut writer = super::super::super::ResponseWriter {
        inner: DeadlineTcpStream::new(&mut socket, expired_deadline()),
        timeout: GitDaemonSessionTimeout::try_new(Duration::from_secs(30)).unwrap(),
        started: false,
        preserve_request_deadline: true,
        agent: None,
        agent_bytes: 0,
    };
    let reply = Reply { archive: empty_archive() };
    assert_eq!(
        reply.send(&mut writer, HttpVersion::Http11).unwrap_err().kind(),
        io::ErrorKind::TimedOut,
    );
}
