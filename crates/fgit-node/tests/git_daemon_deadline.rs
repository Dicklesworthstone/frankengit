#![forbid(unsafe_code)]

use std::convert::Infallible;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use fgit_node::{
    GitDaemonServeError, GitDaemonSessionOutcome, GitDaemonSessionTimeout,
    GitDaemonSessionTimeoutRefusal, GitDaemonTransportRefusal, serve_git_daemon_tcp_once,
};
use fgit_types::GitHashAlgorithm;
use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, PackPayloadSource, Packet,
    UploadPackRepository, WireError, WireLimits, encode_packets,
};

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
fn zero_session_deadline_is_a_typed_configuration_refusal() {
    assert_eq!(
        GitDaemonSessionTimeout::try_new(Duration::ZERO),
        Err(GitDaemonSessionTimeoutRefusal::Zero)
    );
}
