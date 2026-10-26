//! The live source cannot activate a command after its owning session expires.

use super::*;
use std::net::Shutdown;
use std::sync::Mutex;
use std::time::Instant;

struct Source<F>(F);

impl<F> SshCommandAuthorizer for Source<F>
where
    F: Fn(&[u8; 32], RepositoryId, SshGitService) -> Result<PrincipalId, AuthRefusal> + Send + Sync,
{
    fn authorize_command(
        &self,
        key: &[u8; 32],
        repository: RepositoryId,
        service: SshGitService,
    ) -> Result<PrincipalId, AuthRefusal> {
        (self.0)(key, repository, service)
    }
}

fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}

fn deadline(timeout: Duration) -> GitDaemonSessionDeadline {
    GitDaemonSessionDeadline::new(
        GitDaemonSessionTimeout::try_new(timeout).unwrap(),
        GitDaemonSessionWorkScaling::FLAT,
    )
}

fn repository() -> RepositoryId {
    RepositoryId::from_bytes([0x61; 16])
}

fn principal() -> PrincipalId {
    PrincipalId::from_bytes([0x62; 16])
}

#[test]
fn a_live_session_forwards_the_exact_key_repository_service_and_principal() {
    let (client, peer) = pair();
    let source = SessionCommandAuthorizer {
        source: Arc::new(Source(|key: &[u8; 32], repo, service| {
            assert_eq!(key, &[7; 32]);
            assert_eq!(repo, repository());
            assert_eq!(service, SshGitService::ReceivePack);
            Ok(principal())
        })),
        deadline: deadline(Duration::from_secs(5)),
        peer,
    };
    assert_eq!(
        source.authorize_command(&[7; 32], repository(), SshGitService::ReceivePack),
        Ok(principal()),
    );
    drop(client);
}

#[test]
fn expired_and_disconnected_sessions_never_invoke_the_authorization_source() {
    for expired in [true, false] {
        let (client, peer) = pair();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let mut limit = deadline(Duration::from_secs(5));
        if expired {
            limit.started = Instant::now() - Duration::from_secs(10);
        } else {
            client.shutdown(Shutdown::Both).unwrap();
        }
        let source = SessionCommandAuthorizer {
            source: Arc::new(Source(move |_: &[u8; 32], _, _| {
                observed.fetch_add(1, Ordering::Relaxed);
                Ok(principal())
            })),
            deadline: limit,
            peer,
        };
        assert_eq!(
            source.authorize_command(&[7; 32], repository(), SshGitService::UploadPack),
            Err(AuthRefusal::AuthorizationSourceUnavailable),
        );
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        drop(client);
    }
}

#[test]
fn deadline_or_disconnect_during_source_io_discards_an_otherwise_valid_grant() {
    let (client, peer) = pair();
    // Keep an already-old start live with shared work allowance, then
    // withdraw that allowance inside the source. This test-only control makes
    // the two budget observations deterministic without a sleep or clock seam.
    let mut limit = GitDaemonSessionDeadline::new(
        GitDaemonSessionTimeout::try_new(Duration::from_secs(1)).unwrap(),
        GitDaemonSessionWorkScaling::DEFAULT,
    );
    limit.started = Instant::now() - Duration::from_secs(10);
    limit.note_admitted(1 << 30);
    assert!(!limit.expired());
    let source_limit = limit.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let source = SessionCommandAuthorizer {
        source: Arc::new(Source(move |_: &[u8; 32], _, _| {
            observed.fetch_add(1, Ordering::Relaxed);
            source_limit
                .shared
                .admitted_bytes
                .store(0, Ordering::Relaxed);
            assert!(source_limit.expired());
            Ok(principal())
        })),
        deadline: limit,
        peer,
    };
    assert_eq!(
        source.authorize_command(&[7; 32], repository(), SshGitService::UploadPack),
        Err(AuthRefusal::AuthorizationSourceUnavailable),
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    drop(client);

    let (client, peer) = pair();
    let check = peer.try_clone().unwrap();
    let client = Mutex::new(Some(client));
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let source = SessionCommandAuthorizer {
        source: Arc::new(Source(move |_: &[u8; 32], _, _| {
            observed.fetch_add(1, Ordering::Relaxed);
            let client = client.lock().unwrap().take().unwrap();
            client.shutdown(Shutdown::Both).unwrap();
            drop(client);
            let started = Instant::now();
            while crate::tcp_peer_connected(&check) {
                assert!(started.elapsed() < Duration::from_secs(3));
                std::thread::sleep(Duration::from_millis(1));
            }
            Ok(principal())
        })),
        deadline: deadline(Duration::from_secs(5)),
        peer,
    };
    assert_eq!(
        source.authorize_command(&[7; 32], repository(), SshGitService::ReceivePack),
        Err(AuthRefusal::AuthorizationSourceUnavailable),
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}
