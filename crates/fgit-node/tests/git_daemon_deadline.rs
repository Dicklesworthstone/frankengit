#![forbid(unsafe_code)]

use std::convert::Infallible;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use fgit_node::{
    GitDaemonServeError, GitDaemonSessionOutcome, GitDaemonSessionTimeout,
    GitDaemonSessionTimeoutRefusal, GitDaemonTransportRefusal, serve_git_daemon_tcp_once,
};
use fgit_types::GitHashAlgorithm;
use fgit_wire::{
    Capabilities, GitObjectFormat, PackPayloadSource, UploadPackRepository, WireError, WireLimits,
};

#[derive(Debug)]
struct EmptyRepository;

impl UploadPackRepository for EmptyRepository {
    fn object_format(&self) -> GitObjectFormat {
        GitObjectFormat::from(GitHashAlgorithm::Sha1)
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
fn zero_session_deadline_is_a_typed_configuration_refusal() {
    assert_eq!(
        GitDaemonSessionTimeout::try_new(Duration::ZERO),
        Err(GitDaemonSessionTimeoutRefusal::Zero)
    );
}
