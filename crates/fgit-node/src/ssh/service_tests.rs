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
    expired.started = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .expect("test clock supports a past deadline");
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

#[test]
fn terminal_write_allowance_flushes_without_restarting_buffered_git_reads() {
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
    let mut work = GitDaemonSessionDeadline::new(
        GitDaemonSessionTimeout::try_new(Duration::from_secs(5)).unwrap(),
        GitDaemonSessionWorkScaling::FLAT,
    );
    work.started = Instant::now()
        .checked_sub(Duration::from_secs(10))
        .expect("test clock supports a past deadline");
    let state = RefCell::new(SshConnectionState {
        session,
        stream,
        deadline: work.clone(),
        read_buf: b"git".to_vec(),
        read_pos: 0,
    });
    let mut reader = SshReader(&state);
    let mut writer = SshWriter(&state);
    assert_eq!(writer.flush().unwrap_err().kind(), io::ErrorKind::TimedOut);

    // The native upload engine arms the shared terminal clock. SSH can now
    // drain already queued output without replacing its original work clock.
    work.begin_terminal_response();
    writer.flush().unwrap();
    let mut identification = [0u8; 4];
    client.read_exact(&mut identification).unwrap();
    assert_eq!(&identification, b"SSH-");
    assert_eq!(
        reader.read(&mut [0u8; 3]).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    let state = state.borrow();
    assert_eq!(
        state.read_pos, 0,
        "terminal output did not admit more Git input"
    );
    assert_eq!(state.deadline.started, work.started);
    assert!(work.expired());
    assert_eq!(work.shared.admitted_bytes.load(Ordering::Relaxed), 0);
}

#[test]
fn ssh_receive_command_limit_reports_counts_and_accepts_the_boundary_twin() {
    use fgit_types::{DecisionOutcome, GitHashAlgorithm};
    use fgit_wire::receive::{ReceiveError, ReceiveLimits};
    use fgit_wire::{Packet, PktLineDecoder, encode_packets};

    #[derive(Default)]
    struct Reply(Vec<u8>);
    impl Write for Reply {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl ReceiveResponseWriter for Reply {
        fn restart_deadline(&mut self, _: GitDaemonSessionDeadline) {}
    }

    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let config = NodeConfig::new(
            scratch.0.clone(),
            TenantId::from_bytes([0x71; 16]),
            RepositoryId::from_bytes([0x72; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(2)
        .with_git_daemon_receive_limits(ReceiveLimits {
            max_commands: 2,
            ..ReceiveLimits::default()
        });
        let (mut node, _) = OneNode::init(config).unwrap();
        let generation = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap()
            .receipt()
            .generation();
        node.bring_into_service(generation).unwrap();
        let writers = crate::WriterGate::new(1);
        let quota = PushQuota::default();
        for count in [3, 2] {
            let zero = "0".repeat(format.digest_len() * 2);
            let mut packets: Vec<_> = (0..count)
                .map(|index| {
                    let capabilities = if index == 0 {
                        format!("\0report-status object-format={}", format.as_str())
                    } else {
                        String::new()
                    };
                    Packet::Data(
                        format!("{zero} {zero} refs/tags/absent-{index}{capabilities}")
                            .into_bytes(),
                    )
                })
                .collect();
            packets.push(Packet::Flush);
            let wire = encode_packets(&packets, &WireLimits::default()).unwrap();
            let mut input = io::Cursor::new(wire);
            let mut output = Reply::default();
            let ingress = GitDaemonSessionDeadline::new(
                GitDaemonSessionTimeout::try_new(Duration::from_secs(30)).unwrap(),
                GitDaemonSessionWorkScaling::FLAT,
            );
            let result = node.serve_ssh_receive_pack(
                &mut input,
                &mut output,
                Some(SshCommandGrant::unrestricted(PrincipalId::from_bytes(
                    [0x73; 16],
                ))),
                b"",
                &writers,
                &quota,
                &ingress,
            );
            let mut decoder = PktLineDecoder::new(WireLimits::default()).unwrap();
            let response = decoder.push(&output.0).unwrap();
            decoder.finish().unwrap();
            if count == 3 {
                assert!(
                    matches!(result, Err(crate::NodeSmartHttpRefusal::Receive(error)) if matches!(*error, ReceiveError::TooManyCommands { limit: 2 }))
                );
                let Some(Packet::Data(message)) = response.last() else {
                    panic!("SSH must deliver a Git ERR packet");
                };
                let message = std::str::from_utf8(message).unwrap();
                assert!(message.starts_with(
                    "ERR receive command count exceeded: observed at least 3; maximum 2;"
                ));
                assert!(message.contains("split the push into batches of at most 2 commands"));
                assert!(message.ends_with("this invocation stopped before admission\n"));
                assert_eq!(input.position() as usize, input.get_ref().len() - 4);
                assert_eq!(
                    node.runtime()
                        .block_on(node.authenticate_authority_head())
                        .unwrap()
                        .receipt()
                        .generation(),
                    generation
                );
            } else {
                let result = result.unwrap().unwrap();
                assert_eq!(result.commands.len(), 2);
                assert!(result.commands.iter().all(|command| matches!(
                    command.terminal.outcome,
                    DecisionOutcome::Committed { .. }
                )));
                for index in 0..2 {
                    let expected = format!("ok refs/tags/absent-{index}\n").into_bytes();
                    assert!(
                        response.iter().any(
                            |packet| matches!(packet, Packet::Data(bytes) if *bytes == expected)
                        )
                    );
                }
            }
        }
        node.shutdown().unwrap();
    }
}
