#![forbid(unsafe_code)]
//! Reopening a repository takes its object format from authenticated canonical
//! state, never from a process-local default.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use fgit_node::{NodeConfig, NodeRefusal, OneNode};
use fgit_types::{GitHashAlgorithm, RepositoryId, TenantId};

static NEXT_SCRATCH_DIRECTORY: AtomicU64 = AtomicU64::new(1);

const ABRUPT_INITIALIZER_ROOT_ENV: &str = "FGIT_ABRUPT_INITIALIZER_ROOT";

struct ScratchDirectory(PathBuf);

impl ScratchDirectory {
    fn new() -> Self {
        let sequence = NEXT_SCRATCH_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "frankengit-repository-object-format-{}-{sequence}",
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
        TenantId::from_bytes([0x41; 16]),
        RepositoryId::from_bytes([0x72; 16]),
    )
}

fn daemon_greeting(payload: &[u8]) -> Vec<u8> {
    let mut greeting = format!("{:04x}", payload.len() + 4).into_bytes();
    greeting.extend_from_slice(payload);
    greeting
}

fn advertise_once(node: OneNode) -> Vec<u8> {
    let repository_path = node.git_daemon_repository_path().as_bytes().to_vec();
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener binds");
    let address = listener
        .local_addr()
        .expect("listener reports the bound address");
    let worker = thread::spawn(move || {
        let served = node.serve_git_daemon_once(&listener);
        let shutdown = node.shutdown();
        (served, shutdown)
    });

    let mut client = TcpStream::connect(address).expect("client connects to loopback daemon");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client read timeout configures");
    let greeting = daemon_greeting(
        [
            b"git-upload-pack ".as_slice(),
            repository_path.as_slice(),
            b"\0host=loopback\0".as_slice(),
        ]
        .concat()
        .as_slice(),
    );
    client
        .write_all(&greeting)
        .expect("client sends the daemon greeting");
    client
        .shutdown(Shutdown::Write)
        .expect("client closes its greeting half");
    let mut advertisement = Vec::new();
    client
        .read_to_end(&mut advertisement)
        .expect("daemon completes the advertisement");

    let (served, shutdown) = worker.join().expect("daemon worker joins");
    served.expect("authenticated empty repository serves one upload-pack request");
    shutdown.expect("daemon node reaches quiescence");
    advertisement
}

#[test]
fn sha256_repository_reopens_with_default_config_and_advertises_sha256() {
    let scratch = ScratchDirectory::new();
    let (node, _) =
        OneNode::init(config(scratch.0.clone()).with_object_format(GitHashAlgorithm::Sha256))
            .expect("SHA-256 genesis persists its canonical repository configuration");
    node.shutdown()
        .expect("initializer node quiesces before reopen");

    let reopened = OneNode::open_existing(config(scratch.0.clone()))
        .expect("default caller configuration defers to authenticated SHA-256 state");
    let advertisement = advertise_once(reopened);

    assert!(
        advertisement
            .windows(b"object-format=sha256".len())
            .any(|window| window == b"object-format=sha256"),
        "the reopened SHA-256 repository advertises its persisted object domain"
    );
    assert!(
        advertisement
            .windows(64)
            .any(|window| window
                == b"0000000000000000000000000000000000000000000000000000000000000000"),
        "the empty SHA-256 pseudo-ref remains a 64-hex object identity after reopen"
    );
}

/// Permitted twin: an explicit SHA-1 genesis retains its own persisted format
/// when opened through an unspecified/default caller configuration.
#[test]
fn sha1_repository_reopens_with_default_config_and_advertises_sha1() {
    let scratch = ScratchDirectory::new();
    let (node, _) =
        OneNode::init(config(scratch.0.clone()).with_object_format(GitHashAlgorithm::Sha1))
            .expect("SHA-1 genesis persists its canonical repository configuration");
    node.shutdown()
        .expect("initializer node quiesces before reopen");

    let reopened = OneNode::open_existing(config(scratch.0.clone()))
        .expect("default caller configuration defers to authenticated SHA-1 state");
    let advertisement = advertise_once(reopened);

    assert!(
        advertisement
            .windows(b"object-format=sha1".len())
            .any(|window| window == b"object-format=sha1"),
        "the reopened SHA-1 repository advertises its persisted object domain"
    );
    assert!(
        advertisement
            .windows(40)
            .any(|window| window == b"0000000000000000000000000000000000000000"),
        "the empty SHA-1 pseudo-ref remains a 40-hex object identity after reopen"
    );
}

#[test]
fn explicit_caller_object_format_mismatch_is_refused() {
    let scratch = ScratchDirectory::new();
    let (node, _) =
        OneNode::init(config(scratch.0.clone()).with_object_format(GitHashAlgorithm::Sha256))
            .expect("SHA-256 genesis persists its canonical repository configuration");
    node.shutdown()
        .expect("initializer node quiesces before mismatch check");

    assert!(matches!(
        OneNode::open_existing(
            config(scratch.0.clone()).with_object_format(GitHashAlgorithm::Sha1)
        ),
        Err(NodeRefusal::ObjectFormatMismatch {
            stored: GitHashAlgorithm::Sha256,
            supplied: GitHashAlgorithm::Sha1,
        })
    ));
}

/// This is invoked as a child test by
/// [`sha256_repository_reopens_after_abrupt_initializer_process_exit`]. The
/// process exit deliberately bypasses [`OneNode::shutdown`], so the parent
/// proves that reopening consumes the configuration staged before an orderly
/// node teardown could make the result look durable.
#[test]
fn abrupt_initializer_process_exits_without_node_shutdown() {
    let Ok(root) = std::env::var(ABRUPT_INITIALIZER_ROOT_ENV) else {
        return;
    };

    let _node =
        OneNode::init(config(PathBuf::from(root)).with_object_format(GitHashAlgorithm::Sha256))
            .expect("the child persists the SHA-256 canonical configuration before it exits");
    std::process::exit(0);
}

#[test]
fn sha256_repository_reopens_after_abrupt_initializer_process_exit() {
    let scratch = ScratchDirectory::new();
    let status = Command::new(std::env::current_exe().expect("test binary path resolves"))
        .args([
            "--exact",
            "abrupt_initializer_process_exits_without_node_shutdown",
            "--nocapture",
        ])
        .env(ABRUPT_INITIALIZER_ROOT_ENV, &scratch.0)
        .status()
        .expect("the abrupt initializer child starts");
    assert!(
        status.success(),
        "the child initializes successfully before intentionally exiting without shutdown"
    );

    let reopened = OneNode::open_existing(config(scratch.0.clone()))
        .expect("a fresh process default must resolve persisted SHA-256 state");
    let advertisement = advertise_once(reopened);
    assert!(
        advertisement
            .windows(b"object-format=sha256".len())
            .any(|window| window == b"object-format=sha256"),
        "the abrupt-process reopen retains the persisted SHA-256 object domain"
    );
}
