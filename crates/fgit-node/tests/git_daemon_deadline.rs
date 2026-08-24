#![forbid(unsafe_code)]

use std::convert::Infallible;
use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use fgit_node::{
    GitDaemonServeError, GitDaemonSessionOutcome, GitDaemonSessionTimeout,
    GitDaemonSessionTimeoutRefusal, GitDaemonTransportRefusal, serve_git_daemon_tcp_once,
};
use fgit_node::{NodeConfig, NodeGitDaemonServeRefusal, NodePackMaterializationRefusal, OneNode};
use fgit_runtime::{BudgetClass, BudgetPolicy, ClassLimits, Exhaustion};
use fgit_types::GitHashAlgorithm;
use fgit_types::{PrincipalId, RepositoryId, TenantId};
use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, PackPayloadSource, Packet,
    UploadPackRepository, WireError, WireLimits, encode_packets,
};

const DATABASE_CLASS_TIMEOUT: Duration = Duration::from_secs(5);
const EXPIRED_CLASS_WAIT: Duration = Duration::from_secs(6);
const ONE_NODE_SESSION_TIMEOUT: Duration = Duration::from_secs(15);

static NEXT_SCRATCH_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct ScratchDirectory {
    root: PathBuf,
}

impl ScratchDirectory {
    fn new() -> Self {
        let sequence = NEXT_SCRATCH_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "frankengit-git-daemon-budget-{}-{sequence}",
            std::process::id()
        ));
        Self { root }
    }

    fn path(&self) -> &Path {
        &self.root
    }
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Debug)]
struct EmptyRepository;

impl UploadPackRepository for EmptyRepository {
    fn object_format(&self) -> GitObjectFormat {
        GitHashAlgorithm::Sha1
    }

    fn advertised_refs(&self) -> &[fgit_wire::AdvertisedRef] {
        &[]
    }

    fn contains_want(&self, _oid: fgit_wire::AnyGitOid) -> bool {
        false
    }

    fn is_common(&self, _oid: fgit_wire::AnyGitOid) -> bool {
        false
    }
}

struct EmptyPayload;

impl PackPayloadSource for EmptyPayload {
    fn next_chunk(&mut self, _maximum_bytes: usize) -> Result<Option<Vec<u8>>, WireError> {
        Ok(None)
    }
}

struct MarkerPayload {
    bytes: Option<Vec<u8>>,
}

impl PackPayloadSource for MarkerPayload {
    fn next_chunk(&mut self, maximum_bytes: usize) -> Result<Option<Vec<u8>>, WireError> {
        let Some(bytes) = self.bytes.take() else {
            return Ok(None);
        };
        if bytes.len() > maximum_bytes {
            return Err(WireError::PackChunkTooLarge {
                observed: bytes.len(),
                limit: maximum_bytes,
            });
        }
        Ok(Some(bytes))
    }
}

struct NonEmptyRepository {
    reference: AdvertisedRef,
}

impl NonEmptyRepository {
    fn new() -> Self {
        let limits = WireLimits::default();
        let oid = AnyGitOid::from_hex(
            GitObjectFormat::Sha1,
            "1111111111111111111111111111111111111111",
        )
        .expect("fixed SHA-1 reference is valid");
        let reference = AdvertisedRef::new(oid, b"refs/heads/main", &limits)
            .expect("fixed advertised reference is valid");
        Self { reference }
    }
}

impl UploadPackRepository for NonEmptyRepository {
    fn object_format(&self) -> GitObjectFormat {
        GitObjectFormat::Sha1
    }

    fn advertised_refs(&self) -> &[AdvertisedRef] {
        std::slice::from_ref(&self.reference)
    }

    fn contains_want(&self, oid: AnyGitOid) -> bool {
        oid == self.reference.oid
    }

    fn is_common(&self, _oid: AnyGitOid) -> bool {
        false
    }
}

fn timeout(milliseconds: u64) -> GitDaemonSessionTimeout {
    GitDaemonSessionTimeout::try_new(Duration::from_millis(milliseconds))
        .expect("a non-zero test session deadline is admitted")
}

fn daemon_greeting() -> Vec<u8> {
    let payload = b"git-upload-pack /demo.git\0host=loopback\0";
    let mut frame = format!("{:04x}", payload.len() + 4).into_bytes();
    frame.extend_from_slice(payload);
    frame
}

fn complete_upload_pack_request(repository: &NonEmptyRepository) -> Vec<u8> {
    let mut request = daemon_greeting();
    request.extend(
        encode_packets(
            &[
                Packet::Data(format!("want {}\n", repository.reference.oid).into_bytes()),
                Packet::Flush,
                Packet::Data(b"done\n".to_vec()),
            ],
            &WireLimits::default(),
        )
        .expect("fixed upload-pack negotiation encodes"),
    );
    request
}

fn decode_hex(text: &str) -> Vec<u8> {
    fn digit(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("fixed fixture contains hexadecimal digits"),
        }
    }

    let compact = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    let (pairs, remainder) = compact.as_chunks::<2>();
    assert!(remainder.is_empty(), "fixed fixture has whole hex bytes");
    pairs
        .iter()
        .map(|pair| (digit(pair[0]) * 16) + digit(pair[1]))
        .collect()
}

fn write_loose_blob_repository(root: &Path) -> AnyGitOid {
    fs::create_dir_all(root).expect("fixture source directory creates");
    fs::write(root.join("HEAD"), "ref: refs/heads/main\n").expect("fixture symbolic HEAD writes");
    let oid = AnyGitOid::from_hex(
        GitObjectFormat::Sha1,
        "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0",
    )
    .expect("fixed blob identity parses");
    let object_path = root.join("objects/b6/fc4c620b67d95f953a5c1c1230aaab5db5a1b0");
    fs::create_dir_all(object_path.parent().expect("object parent exists"))
        .expect("object directory creates");
    fs::write(
        object_path,
        decode_hex(include_str!(
            "../../fgit-git-object/tests/corpus/blob-hello.zlib.hex"
        )),
    )
    .expect("fixture loose object writes");
    let ref_path = root.join("refs/heads/main");
    fs::create_dir_all(ref_path.parent().expect("ref parent exists"))
        .expect("ref directory creates");
    fs::write(ref_path, format!("{oid}\n")).expect("fixture ref writes");
    oid
}

fn one_node_budget_policy() -> BudgetPolicy {
    BudgetPolicy::finite_defaults()
        .with_class_limits(
            BudgetClass::Database,
            ClassLimits::finite(DATABASE_CLASS_TIMEOUT, 1_000_000, 50_000_000),
        )
        .expect("the database class remains finite in every dimension")
}

fn one_node_daemon_greeting(repository_path: &[u8]) -> Vec<u8> {
    let payload = [
        b"git-upload-pack ".as_slice(),
        repository_path,
        b"\0host=loopback\0".as_slice(),
    ]
    .concat();
    let mut frame = format!("{:04x}", payload.len() + 4).into_bytes();
    frame.extend_from_slice(&payload);
    frame
}

fn read_advertisement_through_flush(stream: &mut TcpStream) -> Vec<u8> {
    let mut advertisement = Vec::new();
    loop {
        let mut header = [0_u8; 4];
        stream
            .read_exact(&mut header)
            .expect("one-node advertisement pkt-line header reads");
        advertisement.extend_from_slice(&header);
        if &header == b"0000" {
            return advertisement;
        }
        let header = std::str::from_utf8(&header).expect("pkt-line header is ASCII hex");
        let length = usize::from_str_radix(header, 16).expect("pkt-line header parses as hex");
        assert!(length >= 4, "advertisement uses data packets or a flush");
        let mut payload = vec![0_u8; length - 4];
        stream
            .read_exact(&mut payload)
            .expect("one-node advertisement pkt-line payload reads");
        advertisement.extend_from_slice(&payload);
    }
}

fn run_one_node_after_advertisement_delay(
    delay: Duration,
) -> (
    Result<GitDaemonSessionOutcome, NodeGitDaemonServeRefusal>,
    Vec<u8>,
    Duration,
) {
    let scratch = ScratchDirectory::new();
    let node_root = scratch.path().join("node");
    let source_root = scratch.path().join("source");
    let wanted = write_loose_blob_repository(&source_root);
    let session_timeout = GitDaemonSessionTimeout::try_new(ONE_NODE_SESSION_TIMEOUT)
        .expect("the one-node test session deadline is finite and non-zero");
    let (node, _) = OneNode::init(
        NodeConfig::new(
            node_root,
            TenantId::from_bytes([0x51; 16]),
            RepositoryId::from_bytes([0x52; 16]),
        )
        .with_runtime_budgets(one_node_budget_policy())
        .with_git_daemon_session_timeout(session_timeout),
    )
    .expect("the bounded one-node daemon initializes");
    let import_request = node.request_context();
    node.runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &import_request,
            &source_root,
            PrincipalId::from_bytes([0x53; 16]),
            b"kxmb-daemon-budget-import",
        ))
        .expect("the real loose object and ref publish before daemon serving");

    let repository_path = node.git_daemon_repository_path().as_bytes().to_vec();
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener binds");
    let address = listener
        .local_addr()
        .expect("listener reports its loopback address");
    let server = thread::spawn(move || {
        let served = node.serve_git_daemon_once_with_limits(&listener, WireLimits::default());
        let shutdown = node.shutdown();
        (served, shutdown)
    });

    let started = Instant::now();
    let mut client = TcpStream::connect(address).expect("one-node client connects");
    client
        .set_read_timeout(Some(ONE_NODE_SESSION_TIMEOUT + Duration::from_secs(5)))
        .expect("client read timeout configures");
    client
        .write_all(&one_node_daemon_greeting(&repository_path))
        .expect("one-node greeting writes");
    let advertisement = read_advertisement_through_flush(&mut client);
    let wanted_hex = wanted.to_string();
    assert!(
        advertisement
            .windows(wanted_hex.len())
            .any(|window| window == wanted_hex.as_bytes()),
        "the phase barrier must be the advertisement for the imported ref"
    );

    thread::sleep(delay);
    let negotiation = encode_packets(
        &[
            Packet::Data(format!("want {wanted}\n").into_bytes()),
            Packet::Flush,
            Packet::Data(b"done\n".to_vec()),
        ],
        &WireLimits::default(),
    )
    .expect("fixed one-node upload-pack negotiation encodes");
    client
        .write_all(&negotiation)
        .expect("one-node negotiation writes");
    client
        .shutdown(Shutdown::Write)
        .expect("one-node client finishes its request");
    let mut response_after_advertisement = Vec::new();
    client
        .read_to_end(&mut response_after_advertisement)
        .expect("one-node response reaches EOF");
    let total_elapsed = started.elapsed();

    let (served, shutdown) = server.join().expect("one-node daemon thread joins");
    shutdown.expect("one-node daemon drains and shuts down after its session");
    (served, response_after_advertisement, total_elapsed)
}

#[test]
fn silent_peer_hits_the_typed_absolute_session_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener binds");
    let address = listener
        .local_addr()
        .expect("listener reports its loopback address");
    let worker = thread::spawn(move || {
        serve_git_daemon_tcp_once(
            &listener,
            &EmptyRepository,
            Capabilities::default(),
            WireLimits::default(),
            timeout(40),
            |_request, _pack_request| -> Result<EmptyPayload, Infallible> { Ok(EmptyPayload) },
        )
    });

    let client = TcpStream::connect(address).expect("silent loopback peer connects");
    let result = worker.join().expect("daemon worker does not panic");
    drop(client);

    assert!(matches!(
        result,
        Err(GitDaemonServeError::Transport(
            GitDaemonTransportRefusal::SessionDeadlineExceeded {
                operation: "read git-daemon greeting header"
            }
        ))
    ));
}

#[test]
fn partial_greeting_does_not_restart_the_absolute_session_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener binds");
    let address = listener
        .local_addr()
        .expect("listener reports its loopback address");
    let worker = thread::spawn(move || {
        serve_git_daemon_tcp_once(
            &listener,
            &EmptyRepository,
            Capabilities::default(),
            WireLimits::default(),
            timeout(250),
            |_request, _pack_request| -> Result<EmptyPayload, Infallible> { Ok(EmptyPayload) },
        )
    });

    let mut client = TcpStream::connect(address).expect("slow loopback peer connects");
    client
        .write_all(b"0")
        .expect("first greeting byte writes before the deadline");
    thread::sleep(Duration::from_millis(100));
    client
        .write_all(b"0")
        .expect("second greeting byte writes before the same deadline");

    let result = worker.join().expect("daemon worker does not panic");
    drop(client);
    assert!(matches!(
        result,
        Err(GitDaemonServeError::Transport(
            GitDaemonTransportRefusal::SessionDeadlineExceeded {
                operation: "read git-daemon greeting header"
            }
        ))
    ));
}

#[test]
fn peer_that_finishes_an_empty_repository_request_before_deadline_is_admitted() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener binds");
    let address = listener
        .local_addr()
        .expect("listener reports its loopback address");
    let worker = thread::spawn(move || {
        serve_git_daemon_tcp_once(
            &listener,
            &EmptyRepository,
            Capabilities::default(),
            WireLimits::default(),
            timeout(250),
            |_request, _pack_request| -> Result<EmptyPayload, Infallible> { Ok(EmptyPayload) },
        )
    });

    let mut client = TcpStream::connect(address).expect("loopback peer connects");
    client
        .write_all(&daemon_greeting())
        .expect("complete greeting writes before the deadline");
    client
        .shutdown(Shutdown::Write)
        .expect("peer sends EOF after its complete request");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .expect("empty-repository response reaches EOF");

    let result = worker.join().expect("daemon worker does not panic");
    assert!(matches!(
        result,
        Ok(GitDaemonSessionOutcome::EmptyRepository(_))
    ));
    assert_eq!(response, b"0000");
}

#[test]
fn completed_negotiation_refuses_a_slow_pack_before_raw_pack_output() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener binds");
    let address = listener
        .local_addr()
        .expect("listener reports its loopback address");
    let repository = NonEmptyRepository::new();
    let request = complete_upload_pack_request(&repository);
    let builder_started = Arc::new(AtomicBool::new(false));
    let worker_started = Arc::clone(&builder_started);
    let worker = thread::spawn(move || {
        serve_git_daemon_tcp_once(
            &listener,
            &repository,
            Capabilities::default(),
            WireLimits::default(),
            timeout(25),
            move |_request, _pack_request| -> Result<MarkerPayload, Infallible> {
                worker_started.store(true, Ordering::Relaxed);
                thread::sleep(Duration::from_millis(100));
                Ok(MarkerPayload {
                    bytes: Some(b"PACK\0late".to_vec()),
                })
            },
        )
    });

    let mut client = TcpStream::connect(address).expect("loopback client connects");
    client
        .write_all(&request)
        .expect("complete request writes before the deadline");
    client
        .shutdown(Shutdown::Write)
        .expect("client finishes the upload-pack request");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .expect("refused session closes its write half");

    let result = worker.join().expect("daemon worker does not panic");
    assert!(builder_started.load(Ordering::Relaxed));
    assert!(matches!(
        result,
        Err(GitDaemonServeError::Transport(
            GitDaemonTransportRefusal::SessionDeadlineExceeded {
                operation: "build selected git pack"
            }
        ))
    ));
    assert!(
        !response
            .windows(b"PACK".len())
            .any(|window| window == b"PACK"),
        "a deadline that elapsed while construction ran cannot publish raw pack bytes"
    );
}

#[test]
fn completed_negotiation_under_the_same_deadline_profile_emits_its_pack() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener binds");
    let address = listener
        .local_addr()
        .expect("listener reports its loopback address");
    let repository = NonEmptyRepository::new();
    let request = complete_upload_pack_request(&repository);
    let worker = thread::spawn(move || {
        serve_git_daemon_tcp_once(
            &listener,
            &repository,
            Capabilities::default(),
            WireLimits::default(),
            timeout(250),
            |_request, _pack_request| -> Result<MarkerPayload, Infallible> {
                thread::sleep(Duration::from_millis(1));
                Ok(MarkerPayload {
                    bytes: Some(b"PACK\0timely".to_vec()),
                })
            },
        )
    });

    let mut client = TcpStream::connect(address).expect("loopback client connects");
    client
        .write_all(&request)
        .expect("complete request writes before the deadline");
    client
        .shutdown(Shutdown::Write)
        .expect("client finishes the upload-pack request");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .expect("complete session reaches write-half EOF");

    let outcome = worker
        .join()
        .expect("daemon worker does not panic")
        .expect("under-budget pack construction is admitted");
    assert!(matches!(outcome, GitDaemonSessionOutcome::Pack(_)));
    assert!(response.ends_with(b"PACK\0timely"));
}

#[test]
fn one_node_reports_database_budget_expiry_while_the_session_is_live() {
    let (served, response, total_elapsed) =
        run_one_node_after_advertisement_delay(EXPIRED_CLASS_WAIT);

    assert!(
        total_elapsed < ONE_NODE_SESSION_TIMEOUT,
        "the daemon must return its class refusal while the independent session deadline is still live"
    );
    let refusal = match served {
        Err(NodeGitDaemonServeRefusal::Pack(refusal)) => refusal,
        other => panic!("class exhaustion must be a node-owned pack refusal: {other:?}"),
    };
    assert!(matches!(
        *refusal,
        NodePackMaterializationRefusal::BudgetClassExhausted {
            class: BudgetClass::Database,
            dimension: Exhaustion::Deadline,
            operation: "materialize selected git pack",
        }
    ));
    assert_eq!(response, b"0008NAK\n");
}

#[test]
fn one_node_under_the_same_class_budget_emits_the_selected_pack() {
    let (served, response, _) = run_one_node_after_advertisement_delay(Duration::ZERO);

    assert!(matches!(served, Ok(GitDaemonSessionOutcome::Pack(_))));
    assert!(response.starts_with(b"0008NAK\nPACK"));
}

#[test]
fn zero_session_deadline_is_a_typed_configuration_refusal() {
    assert_eq!(
        GitDaemonSessionTimeout::try_new(Duration::ZERO),
        Err(GitDaemonSessionTimeoutRefusal::Zero)
    );
}
