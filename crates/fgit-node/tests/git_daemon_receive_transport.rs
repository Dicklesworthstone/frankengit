#![forbid(unsafe_code)]
//! End-to-end tests for the git-daemon `git-receive-pack` service lane.
//!
//! These sessions run over a real loopback `TcpStream` against the node's own
//! bounded daemon, with hand-built wire bytes shaped exactly like a Git
//! client's push: greeting, command pkt-lines, a real pack, then report-status
//! read back. Publication is asserted only by reopening the repository through
//! the production path and materializing the authenticated head — never from
//! a 2xx-shaped response.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest};
use fgit_node::{NodeConfig, OneNode};
use fgit_types::cell::{CellState, CellTransitionCause};
use fgit_types::numeric::HeadGeneration;
use fgit_types::{GitHashAlgorithm, PrincipalId, RepositoryId, TenantId};
use fgit_wire::WireLimits;

const ZERO_OID: &str = "0000000000000000000000000000000000000000";
const PUSHED_BLOB: &[u8] = b"git-daemon receive transport: the pushed blob body\n";
const PUSHED_REF: &str = "refs/heads/main";

static NEXT_SCRATCH_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct ScratchDirectory(PathBuf);

impl ScratchDirectory {
    fn new() -> Self {
        let sequence = NEXT_SCRATCH_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "frankengit-daemon-receive-{}-{sequence}",
            std::process::id()
        )))
    }
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn config(root: PathBuf) -> NodeConfig {
    NodeConfig::new(
        root,
        TenantId::from_bytes([0x5D; 16]),
        RepositoryId::from_bytes([0x5E; 16]),
    )
}

const fn receive_principal() -> PrincipalId {
    PrincipalId::from_bytes([0x77; 16])
}

/// Initializes the repository when asked, then reopens it with the receive
/// lane configured (or not) and brings it into service.
fn serving_node(scratch: &ScratchDirectory, receive: bool, initialize: bool) -> OneNode {
    let base = config(scratch.0.clone());
    if initialize {
        let (created, _) = OneNode::init(base.clone()).expect("the genesis configuration persists");
        created.shutdown().expect("the initialized node quiesces");
    }
    let opened = if receive {
        base.with_git_daemon_receive_principal(receive_principal())
    } else {
        base
    };
    let mut node = OneNode::open_existing(opened).expect("the published head opens");
    node.bring_into_service(HeadGeneration::FIRST)
        .expect("the reopened node enters service");
    node
}

fn greeting(repository_path: &[u8]) -> Vec<u8> {
    let payload = [
        b"git-receive-pack ".as_slice(),
        repository_path,
        b"\0host=loopback\0".as_slice(),
    ]
    .concat();
    let mut frame = format!("{:04x}", payload.len() + 4).into_bytes();
    frame.extend_from_slice(&payload);
    frame
}

fn read_through_flush(stream: &mut TcpStream) -> Vec<u8> {
    let mut collected = Vec::new();
    loop {
        let mut header = [0_u8; 4];
        stream
            .read_exact(&mut header)
            .expect("pkt-line header reads");
        collected.extend_from_slice(&header);
        if &header == b"0000" {
            return collected;
        }
        let text = std::str::from_utf8(&header).expect("pkt-line header is ASCII hex");
        let length = usize::from_str_radix(text, 16).expect("pkt-line header parses as hex");
        assert!(length >= 4, "response uses data packets or a flush");
        let mut payload = vec![0_u8; length - 4];
        stream
            .read_exact(&mut payload)
            .expect("pkt-line payload reads");
        collected.extend_from_slice(&payload);
    }
}

fn pkt_line(payload: &[u8]) -> Vec<u8> {
    let mut frame = format!("{:04x}", payload.len() + 4).into_bytes();
    frame.extend_from_slice(payload);
    frame
}

fn object_header(kind: u8, declared_size: usize) -> Vec<u8> {
    let mut remaining = declared_size;
    let mut first = (kind << 4) | u8::try_from(remaining & 0x0f).expect("masked size");
    remaining >>= 4;
    if remaining == 0 {
        return vec![first];
    }
    first |= 0x80;
    let mut header = vec![first];
    while remaining != 0 {
        let mut next = u8::try_from(remaining & 0x7f).expect("masked size");
        remaining >>= 7;
        if remaining != 0 {
            next |= 0x80;
        }
        header.push(next);
    }
    header
}

fn zlib_stored(bytes: &[u8]) -> Vec<u8> {
    let length = u16::try_from(bytes.len()).expect("stored fixture fits one RFC 1951 block");
    let mut member = vec![0x78, 0x01, 0x01];
    member.extend_from_slice(&length.to_le_bytes());
    member.extend_from_slice(&(!length).to_le_bytes());
    member.extend_from_slice(bytes);
    member.extend_from_slice(&adler32(bytes).to_be_bytes());
    member
}

fn adler32(bytes: &[u8]) -> u32 {
    let mut a = 1_u32;
    let mut b = 0_u32;
    for &byte in bytes {
        a = (a + u32::from(byte)) % 65_521;
        b = (b + a) % 65_521;
    }
    (b << 16) | a
}

fn blob_pack(bodies: &[&[u8]]) -> Vec<u8> {
    let count = u32::try_from(bodies.len()).expect("small bounded fixture");
    let mut pack = b"PACK\0\0\0\x02".to_vec();
    pack.extend_from_slice(&count.to_be_bytes());
    for body in bodies {
        pack.extend_from_slice(&object_header(3, body.len()));
        pack.extend_from_slice(&zlib_stored(body));
    }
    let trailer = sha1_digest(&pack);
    pack.extend_from_slice(&trailer);
    pack
}

const SECOND_BLOB: &[u8] = b"git-daemon receive transport: the second pushed blob\n";

/// A push body updating [`PUSHED_REF`] from the first blob to the second.
fn update_request() -> Vec<u8> {
    let old = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, PUSHED_BLOB);
    let new = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, SECOND_BLOB);
    let command = format!("{old} {new} {PUSHED_REF}\0report-status");
    let mut body = pkt_line(command.as_bytes());
    body.extend_from_slice(b"0000");
    body.extend_from_slice(&blob_pack(&[SECOND_BLOB]));
    body
}

/// The exact push body a Git client would send for one ref creation.
fn push_request() -> Vec<u8> {
    let oid = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, PUSHED_BLOB);
    let command = format!("{ZERO_OID} {oid} {PUSHED_REF}\0report-status");
    let mut body = pkt_line(command.as_bytes());
    body.extend_from_slice(b"0000");
    body.extend_from_slice(&blob_pack(&[PUSHED_BLOB]));
    body
}

fn run_push_session(scratch: ScratchDirectory, initialize: bool, extra_bytes: &[u8]) -> ServedPush {
    run_session(scratch, initialize, push_request(), extra_bytes)
}

struct ServedPush {
    scratch: ScratchDirectory,
    report: Vec<u8>,
    server: Result<(), String>,
}

fn run_session(
    scratch: ScratchDirectory,
    initialize: bool,
    body_bytes: Vec<u8>,
    extra_bytes: &[u8],
) -> ServedPush {
    let node = serving_node(&scratch, true, initialize);
    let repository_path = node.git_daemon_repository_path().as_bytes().to_vec();
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener binds");
    let address = listener.local_addr().expect("listener reports its address");
    let server_thread = thread::spawn(move || {
        let served = node
            .serve_git_daemon_once_with_limits(&listener, WireLimits::default())
            .map(|_| ())
            .map_err(|error| error.to_string());
        node.shutdown().expect("the served node quiesces");
        served
    });

    let mut client = TcpStream::connect(address).expect("push client connects");
    client
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("client read timeout configures");
    client
        .write_all(&greeting(&repository_path))
        .expect("push greeting writes");
    let advertisement = read_through_flush(&mut client);
    if initialize {
        assert!(
            advertisement
                .windows(b"capabilities^{}".len())
                .any(|window| window == b"capabilities^{}"),
            "an empty repository advertises the capabilities pseudo-ref, got {advertisement:?}"
        );
    } else {
        assert!(
            advertisement
                .windows(PUSHED_REF.len())
                .any(|window| window == PUSHED_REF.as_bytes()),
            "a repository with the pushed ref advertises it, got {advertisement:?}"
        );
    }
    assert!(
        advertisement
            .windows(b"report-status".len())
            .any(|window| window == b"report-status"),
        "the receive lane advertises report-status"
    );

    let mut body = body_bytes;
    body.extend_from_slice(extra_bytes);
    client.write_all(&body).expect("push body writes");

    let report = if extra_bytes.is_empty() {
        read_through_flush(&mut client)
    } else {
        // A protocol violation ends the session without a status; drain
        // whatever the server wrote before it closed.
        let mut drained = Vec::new();
        let _ = client.read_to_end(&mut drained);
        drained
    };
    let server = server_thread.join().expect("server thread joins");
    ServedPush {
        scratch,
        report,
        server,
    }
}

/// Reopens the pushed repository through the production path and returns the
/// materialized visible ref names.
fn materialized_refs(scratch: &ScratchDirectory) -> Vec<Vec<u8>> {
    let mut node = OneNode::open_existing(config(scratch.0.clone()))
        .expect("the pushed repository reopens through the production path");
    node.bring_into_service(HeadGeneration::FIRST)
        .expect("the reopened node enters service");
    let materialized = node
        .runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .expect("the authenticated head materializes");
    let refs = materialized
        .snapshot()
        .refs
        .keys()
        .map(|name| name.as_bytes().to_vec())
        .collect();
    drop(materialized);
    node.shutdown().expect("the verifying node quiesces");
    refs
}

#[test]
fn a_configured_node_serves_a_real_push_end_to_end() {
    let outcome = run_push_session(ScratchDirectory::new(), true, &[]);

    outcome
        .server
        .as_ref()
        .expect("the server completes the receive session");
    let report = String::from_utf8_lossy(&outcome.report);
    assert!(
        report.contains("unpack ok"),
        "report-status confirms quarantine validation, got {report:?}"
    );
    assert!(
        report.contains(&format!("ok {PUSHED_REF}")),
        "report-status confirms the authenticated ref decision, got {report:?}"
    );

    let refs = materialized_refs(&outcome.scratch);
    assert_eq!(
        refs,
        vec![PUSHED_REF.as_bytes().to_vec()],
        "the push is canonical only through the reopened authenticated head"
    );
}

#[test]
fn an_identical_retry_resolves_to_the_same_sealed_transaction() {
    let first = run_push_session(ScratchDirectory::new(), true, &[]);
    first.server.as_ref().expect("the first push serves");

    // The same bytes again, against the SAME repository state on disk.
    let second = run_push_session(first.scratch, false, &[]);
    second.server.as_ref().expect("the retried push serves");
    let report = String::from_utf8_lossy(&second.report);
    assert!(
        report.contains(&format!("ok {PUSHED_REF}")),
        "an identical retry reports the same authenticated success, got {report:?}"
    );

    let refs = materialized_refs(&second.scratch);
    assert_eq!(
        refs,
        vec![PUSHED_REF.as_bytes().to_vec()],
        "the retry does not fabricate a second ref or a second head transition"
    );
}

#[test]
fn bytes_after_the_pack_trailer_refuse_the_session_without_publication() {
    let outcome = run_push_session(
        ScratchDirectory::new(),
        true,
        b"BYTES-A-CLIENT-MUST-NOT-SEND",
    );

    let refusal = outcome
        .server
        .as_ref()
        .expect_err("trailing bytes are a protocol violation");
    assert!(
        refusal.contains("after its pack trailer"),
        "the refusal names the violation, got {refusal:?}"
    );

    let refs = materialized_refs(&outcome.scratch);
    assert!(
        refs.is_empty(),
        "a refused session publishes nothing, got {refs:?}"
    );
}

#[test]
fn a_node_without_a_receive_principal_still_refuses_the_service() {
    let scratch = ScratchDirectory::new();
    let node = serving_node(&scratch, false, true);
    let repository_path = node.git_daemon_repository_path().as_bytes().to_vec();
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener binds");
    let address = listener.local_addr().expect("listener reports its address");
    let server_thread = thread::spawn(move || {
        let served = node
            .serve_git_daemon_once_with_limits(&listener, WireLimits::default())
            .map(|_| ())
            .map_err(|error| error.to_string());
        node.shutdown().expect("the refusing node quiesces");
        served
    });

    let mut client = TcpStream::connect(address).expect("client connects");
    client
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("client read timeout configures");
    client
        .write_all(&greeting(&repository_path))
        .expect("greeting writes");
    let mut response = Vec::new();
    let _ = client.read_to_end(&mut response);
    assert!(
        response.is_empty(),
        "an unconfigured node discloses nothing on the receive lane, got {response:?}"
    );

    let refusal = server_thread
        .join()
        .expect("server thread joins")
        .expect_err("the unconfigured lane refuses");
    assert!(
        refusal.contains("unsupported service"),
        "the refusal is the same one the parser used to emit, got {refusal:?}"
    );
}

/// One decision's closure names only what that decision admitted; serving
/// must union closures along the verified history or a second push makes the
/// first push's objects unservable (frankengit-hh37 found this live: a clone
/// after an incremental push received only the newest decision's objects).
#[test]
fn a_second_push_keeps_the_first_pushes_objects_servable() {
    let first = run_push_session(ScratchDirectory::new(), true, &[]);
    first.server.as_ref().expect("the first push serves");

    let second = run_session(first.scratch, false, update_request(), &[]);
    second.server.as_ref().expect("the update push serves");
    let report = String::from_utf8_lossy(&second.report);
    assert!(
        report.contains(&format!("ok {PUSHED_REF}")),
        "the ref update reports ok, got {report:?}"
    );

    let mut node = OneNode::open_existing(config(second.scratch.0.clone()))
        .expect("the twice-pushed repository reopens");
    node.bring_into_service(HeadGeneration::FIRST)
        .expect("the reopened node enters service");
    let materialized = node
        .runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .expect("the authenticated head materializes");
    let closure = materialized.selected_closure().closure().objects().clone();
    drop(materialized);
    node.shutdown().expect("the verifying node quiesces");

    let first_blob = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, PUSHED_BLOB);
    let second_blob = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, SECOND_BLOB);
    assert!(
        closure.contains(&second_blob),
        "the newest decision's object is in the serving closure"
    );
    assert!(
        closure.contains(&first_blob),
        "the earlier decision's object stays servable after a later push"
    );
}

/// A push whose pack validates but whose publication is refused must be told to
/// the client through report-status, not by closing the socket.
///
/// A `StagingOnly` cell is the deterministic small-corpus way to reach that
/// refusal: it accepts and validates the pushed pack, then refuses to publish
/// it. Before frankengit-xefn the session returned an error and the daemon
/// closed the connection, leaving `git push` to print only "the remote end
/// hung up unexpectedly"; now the client receives an `unpack`/`ng`
/// report-status naming the reason, and nothing is published.
#[test]
fn a_publication_refusal_is_reported_not_hung_up() {
    let scratch = ScratchDirectory::new();
    let base = config(scratch.0.clone());
    let (created, _) = OneNode::init(base.clone()).expect("the genesis configuration persists");
    created.shutdown().expect("the initialized node quiesces");
    let mut node =
        OneNode::open_existing(base.with_git_daemon_receive_principal(receive_principal()))
            .expect("the published head opens");
    node.bring_into_service(HeadGeneration::FIRST)
        .expect("the reopened node enters service");
    node.transition_cell_state(
        CellState::StagingOnly,
        CellTransitionCause::Operator,
        HeadGeneration::FIRST,
    )
    .expect("serving -> staging-only is a legal operator transition");

    let repository_path = node.git_daemon_repository_path().as_bytes().to_vec();
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener binds");
    let address = listener.local_addr().expect("listener reports its address");
    let server_thread = thread::spawn(move || {
        let served = node
            .serve_git_daemon_once_with_limits(&listener, WireLimits::default())
            .map(|_| ())
            .map_err(|error| error.to_string());
        node.shutdown().expect("the staging node quiesces");
        served
    });

    let mut client = TcpStream::connect(address).expect("push client connects");
    client
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("client read timeout configures");
    client
        .write_all(&greeting(&repository_path))
        .expect("push greeting writes");
    let _advertisement = read_through_flush(&mut client);
    client.write_all(&push_request()).expect("push body writes");
    // The pack is validated in full before publication is refused, so the
    // client is reading the response: a report-status must arrive.
    let report = read_through_flush(&mut client);
    let server = server_thread.join().expect("server thread joins");

    server
        .as_ref()
        .expect("the session completes by reporting the rejection, not erroring");
    let text = String::from_utf8_lossy(&report);
    assert!(
        text.contains("unpack "),
        "an unpack status line is reported to the client, got {text:?}"
    );
    assert!(
        text.contains("ng "),
        "the ref is reported rejected with an ng line, got {text:?}"
    );

    let refs = materialized_refs(&scratch);
    assert!(
        refs.is_empty(),
        "a refused publication publishes nothing, got {refs:?}"
    );
}
