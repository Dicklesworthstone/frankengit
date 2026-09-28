//! Service-level tests for owned-listener retirement and SSH time bounds.

use super::*;
use crate::NodeConfig;
use fgit_types::{RepositoryId, TenantId};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Instant;

static NEXT_SCRATCH: AtomicUsize = AtomicUsize::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fgit-ssh-continuous-{}-{}",
            std::process::id(),
            NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn node(timeout: Duration, serving: bool) -> (OneNode, Scratch) {
    let scratch = Scratch::new();
    let config = NodeConfig::new(
        scratch.0.clone(),
        TenantId::from_bytes([0x71; 16]),
        RepositoryId::from_bytes([0x72; 16]),
    )
    .with_worker_threads(2)
    .with_git_daemon_session_timeout(GitDaemonSessionTimeout::try_new(timeout).unwrap())
    .with_git_daemon_session_work_scaling(GitDaemonSessionWorkScaling::FLAT);
    let (mut node, _) = OneNode::init(config).unwrap();
    if serving {
        let generation = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap()
            .receipt()
            .generation();
        node.bring_into_service(generation).unwrap();
    }
    (node, scratch)
}

fn host_key() -> SigningKey {
    SigningKey::from_bytes(&[0x42; 32])
}

/// A connected socket that has actually been accepted and sent identification.
fn client(addr: SocketAddr) -> TcpStream {
    let mut client = TcpStream::connect(addr).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut identification = Vec::new();
    while !identification.ends_with(b"\r\n") {
        let mut byte = [0u8; 1];
        client.read_exact(&mut byte).unwrap();
        identification.push(byte[0]);
        assert!(identification.len() <= 255);
    }
    assert!(identification.starts_with(b"SSH-2.0-"));
    client
}

fn wait_until(mut condition: impl FnMut() -> bool) {
    let started = Instant::now();
    while !condition() {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "condition did not settle"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn serving_entry_revalidates_forged_limits_and_requires_a_serving_cell() {
    let (node, _scratch) = node(Duration::from_secs(5), false);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    for (max_sessions, max_in_flight) in [(0, 1), (1, 0), (1_000_001, 1), (1, 17)] {
        let error = node
            .serve_ssh_bounded(
                &listener,
                SshServerLimits {
                    max_sessions,
                    max_in_flight,
                },
                host_key(),
                Vec::new(),
                false,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            NodeSshRefusal::ZeroSessionLimit
                | NodeSshRefusal::ZeroInFlightLimit
                | NodeSshRefusal::LimitsExceeded
        ));
    }
    assert!(matches!(
        node.serve_ssh_bounded(
            &listener,
            SshServerLimits::try_new(1, 1).unwrap(),
            host_key(),
            Vec::new(),
            false,
        ),
        Err(NodeSshRefusal::NotServing)
    ));
    node.shutdown().unwrap();
}

#[test]
fn stop_error_and_stop_panic_close_the_listener_while_a_full_pool_drains() {
    for mode in 0..3 {
        let (node, _scratch) = node(Duration::from_secs(30), true);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let observed = Arc::new(AtomicBool::new(false));
        let child_stop = Arc::clone(&stop);
        let child_observed = Arc::clone(&observed);
        let worker = std::thread::spawn(move || {
            let result =
                node.serve_ssh_until_stopped(listener, 1, host_key(), Vec::new(), false, &|| {
                    if !child_stop.load(Ordering::Acquire) {
                        return Ok(false);
                    }
                    child_observed.store(true, Ordering::Release);
                    match mode {
                        0 => Ok(true),
                        1 => Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "stop failed",
                        )),
                        _ => panic!("stop callback panic"),
                    }
                });
            node.shutdown().unwrap();
            result
        });
        let held = client(addr);
        stop.store(true, Ordering::Release);
        wait_until(|| observed.load(Ordering::Acquire));
        wait_until(|| match TcpStream::connect(addr) {
            Err(error) => error.kind() == io::ErrorKind::ConnectionRefused,
            Ok(probe) => {
                drop(probe);
                false
            }
        });
        assert!(
            !worker.is_finished(),
            "listener closed only after child exit"
        );
        drop(held);
        let result = worker.join().unwrap();
        if mode == 0 {
            let receipt = result.unwrap();
            assert_eq!(receipt.accepted_sessions, 1);
            assert_eq!(receipt.completed_sessions, 0);
            assert_eq!(receipt.refused_sessions, 1);
        } else {
            assert!(matches!(result, Err(NodeSshRefusal::StopControl(_))));
        }
    }
}

#[test]
fn no_stop_twin_keeps_serving_after_refused_sessions_then_drains_cleanly() {
    let (node, _scratch) = node(Duration::from_secs(5), true);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let child_stop = Arc::clone(&stop);
    let worker = std::thread::spawn(move || {
        let result =
            node.serve_ssh_until_stopped(listener, 1, host_key(), Vec::new(), false, &|| {
                Ok(child_stop.load(Ordering::Acquire))
            });
        node.shutdown().unwrap();
        result
    });
    for _ in 0..4 {
        drop(client(addr));
        assert!(!worker.is_finished());
    }
    stop.store(true, Ordering::Release);
    let receipt = worker.join().unwrap().unwrap();
    assert_eq!(receipt.accepted_sessions, 4);
    assert_eq!(receipt.completed_sessions, 0);
    assert_eq!(receipt.refused_sessions, 4);
}

#[test]
fn partial_identification_trickle_cannot_hold_a_handshake_past_its_accepted_budget() {
    let (node, _scratch) = node(Duration::from_millis(200), true);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let worker = std::thread::spawn(move || {
        let result = node.serve_ssh_bounded(
            &listener,
            SshServerLimits::try_new(1, 1).unwrap(),
            host_key(),
            Vec::new(),
            false,
        );
        node.shutdown().unwrap();
        result
    });
    let mut client = client(addr);
    client.write_all(b"SSH-2.0-").unwrap();
    let started = Instant::now();
    while !worker.is_finished() && started.elapsed() < Duration::from_secs(3) {
        let _ = client.write_all(b"x");
        std::thread::sleep(Duration::from_millis(10));
    }
    let completed_without_client_close = worker.is_finished();
    drop(client);
    let receipt = worker.join().unwrap().unwrap();
    assert!(
        completed_without_client_close,
        "trickle extended the accepted deadline"
    );
    assert_eq!(receipt.accepted_sessions, 1);
    assert_eq!(receipt.refused_sessions, 1);
}

#[test]
fn buffered_git_reads_and_window_waits_keep_the_budget_but_native_response_restart_is_usable() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let (stream, _) = listener.accept().unwrap();
    let mut session = SshServerSession::new(
        host_key(),
        Vec::new(),
        Arc::new(asupersync::util::OsEntropy),
    );
    session.start();
    let mut expired = GitDaemonSessionDeadline::new(
        GitDaemonSessionTimeout::try_new(Duration::from_millis(1)).unwrap(),
        GitDaemonSessionWorkScaling::FLAT,
    );
    expired.started = Instant::now() - Duration::from_secs(1);
    let state = RefCell::new(SshConnectionState {
        session,
        stream,
        deadline: expired,
        read_buf: b"git".to_vec(),
        read_pos: 0,
    });
    let mut reader = SshReader(&state);
    let mut writer = SshWriter(&state);
    let mut bytes = [0u8; 3];
    assert_eq!(
        reader.read(&mut bytes).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        writer.write(b"x").unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(writer.flush().unwrap_err().kind(), io::ErrorKind::TimedOut);

    let response = GitDaemonSessionDeadline::new(
        GitDaemonSessionTimeout::try_new(Duration::from_secs(5)).unwrap(),
        GitDaemonSessionWorkScaling::FLAT,
    );
    let response_started = response.started;
    writer.restart_deadline(response);
    writer.flush().unwrap();
    let mut identification = [0u8; 4];
    client.read_exact(&mut identification).unwrap();
    assert_eq!(&identification, b"SSH-");
    assert_eq!(reader.read(&mut bytes).unwrap(), 3);
    assert_eq!(&bytes, b"git");
    let state = state.borrow();
    assert_eq!(state.deadline.started, response_started);
    assert_eq!(
        state.deadline.shared.admitted_bytes.load(Ordering::Relaxed),
        3
    );
}
