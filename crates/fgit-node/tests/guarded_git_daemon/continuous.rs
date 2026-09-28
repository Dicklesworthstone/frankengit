//! Real accepted TCP sessions establish the drain boundary. The held pack is
//! released only after a new peer has observed the owned listener close.

use super::*;
use std::io;
use std::sync::{Arc, atomic::AtomicBool};
use std::time::Instant;

fn eventually_refuses_connections(address: SocketAddr) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        match TcpStream::connect_timeout(&address, Duration::from_millis(100)) {
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => return true,
            Ok(socket) => drop(socket),
            Err(_) => {}
        }
        thread::sleep(Duration::from_millis(5));
    }
    false
}

fn empty_session(address: SocketAddr, path: &str) {
    let mut socket = connect(address, path);
    assert!(!records(&mut socket)[0].starts_with(b"ERR "));
    socket.write_all(b"0000").unwrap();
    let mut response = Vec::new();
    socket.read_to_end(&mut response).unwrap();
    assert!(response.is_empty());
}

#[test]
fn continuous_stop_closes_before_draining_an_atomic_push_and_live_twin_keeps_accepting() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for stop_during_push in [true, false] {
            let root = Scratch::new();
            let config = root.config(format, true);
            let node = start(config.clone(), false);
            let path = route(&node);
            let before = state(&node).0;
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let stopped = Arc::new(AtomicBool::new(false));
            let child_stop = Arc::clone(&stopped);
            let server = thread::spawn(move || {
                let result = node.serve_guarded_git_daemon_until_stopped(listener, 1, &|| {
                    Ok(child_stop.load(Ordering::Acquire))
                });
                node.shutdown().unwrap();
                result.unwrap()
            });

            // The default bounded run would already have exited. Repeated
            // native handshakes also force completed children out of the pool.
            for _ in 0..3 {
                empty_session(address, &path);
            }
            let (oid, zero, pack) = pack(format);
            let mut socket = connect(address, &path);
            assert!(!records(&mut socket)[0].starts_with(b"ERR "));
            socket.write_all(&prefix(format, &[
                (zero, oid, "refs/tags/atomic-a"),
                (zero, oid, "refs/tags/atomic-b"),
            ], true)).unwrap();
            socket.write_all(&pack[..12]).unwrap();

            let closed_while_held = if stop_during_push {
                stopped.store(true, Ordering::Release);
                eventually_refuses_connections(address)
            } else {
                false
            };
            let accepted_child_still_draining = !server.is_finished();
            // Always release the fixture before checking the listener oracle,
            // so a failed assertion does not strand the server's worker.
            socket.write_all(&pack[12..]).unwrap();
            let response = records(&mut socket);
            socket.shutdown(Shutdown::Write).unwrap();
            if !stop_during_push {
                empty_session(address, &path);
                stopped.store(true, Ordering::Release);
            }
            let receipt = server.join().unwrap();
            assert!(accepted_child_still_draining);
            assert_eq!(closed_while_held, stop_during_push);
            assert_eq!(response, [
                b"unpack ok\n".to_vec(),
                b"ok refs/tags/atomic-a\n".to_vec(),
                b"ok refs/tags/atomic-b\n".to_vec(),
            ]);
            assert_eq!(receipt.accepted_sessions(), if stop_during_push { 4 } else { 5 });
            assert_eq!(receipt.completed_sessions(), receipt.accepted_sessions());
            assert_eq!(receipt.refused_sessions(), 0);
            let node = start(config, true);
            let (generation, refs) = state(&node);
            assert_eq!(generation, before + 1, "one atomic authority publication");
            assert_eq!(refs.len(), 2);
            for name in [b"refs/tags/atomic-a", b"refs/tags/atomic-b"] {
                assert_eq!(refs.get(&RefName::try_new(name).unwrap()), Some(&oid));
            }
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn stop_control_failure_and_panic_close_acceptance_then_settle_the_active_child() {
    for panic_control in [false, true] {
        let root = Scratch::new();
        let config = root.config(GitHashAlgorithm::Sha1, true);
        let node = start(config.clone(), false);
        let path = route(&node);
        let before = state(&node);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let fail = Arc::new(AtomicBool::new(false));
        let child_fail = Arc::clone(&fail);
        let server = thread::spawn(move || {
            let result = node.serve_guarded_git_daemon_until_stopped(listener, 1, &|| {
                if child_fail.load(Ordering::Acquire) {
                    if panic_control { panic!("planted stop callback failure"); }
                    return Err(io::Error::new(io::ErrorKind::PermissionDenied, "control lost"));
                }
                Ok(false)
            });
            node.shutdown().unwrap();
            result
        });
        let mut socket = connect(address, &path);
        assert!(!records(&mut socket)[0].starts_with(b"ERR "));
        fail.store(true, Ordering::Release);
        let closed = eventually_refuses_connections(address);
        let draining = !server.is_finished();
        socket.write_all(b"0000").unwrap();
        let mut response = Vec::new();
        socket.read_to_end(&mut response).unwrap();
        let result = server.join().unwrap();
        assert!(closed && draining);
        assert!(response.is_empty());
        assert!(result.is_err());
        let node = start(config, true);
        assert_eq!(state(&node), before);
        node.shutdown().unwrap();
    }
}

#[test]
fn invalid_continuous_limits_close_the_unpublished_owned_listener() {
    let root = Scratch::new();
    let node = start(root.config(GitHashAlgorithm::Sha1, false), false);
    for limit in [0, 17, usize::MAX] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        assert!(node.serve_guarded_git_daemon_until_stopped(listener, limit, &|| Ok(false)).is_err());
        assert!(eventually_refuses_connections(address));
    }
    node.shutdown().unwrap();
}
