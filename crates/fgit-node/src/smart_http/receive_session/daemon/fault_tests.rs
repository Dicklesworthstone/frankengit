//! A real prefix publication followed by real projection unavailability.
//! The socket, quarantine, descriptor, seals and canonical outcomes are not faked.
use super::*;
use crate::{DurableAsyncAdmissionProjection, FsqliteAuthorityStore, FsqliteCx, NodeConfig};
use fgit_admission::policy_bridge::receive_session::{self, recovery::SessionRecovery};
use fgit_admission::{
    AdmissionContext, AdmissionError, AdmissionSnapshot, AsyncAdmissionProjection,
    CommitMaterialization, ProjectionFailure, RefusalMaterialization, ValidatedClosure,
};
use fgit_authority::key_recovery::RequestRecovery;
use fgit_authority::{AuthenticatedHead, OutcomeLookup};
use fgit_chronicle::PublicationBasis;
use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest, sha256_digest};
use fgit_reference::intent::TransactionRequest;
use fgit_txn::TransactionFoldReport;
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm as Format, PrincipalId, RefName, RefusalCode, RepositoryId,
    TenantId, TxId,
};
use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

struct FailSecond<'a> {
    inner: DurableAsyncAdmissionProjection<'a>,
    snapshots: AtomicUsize,
}
impl AsyncAdmissionProjection<FsqliteAuthorityStore> for FailSecond<'_> {
    async fn snapshot_async<'a>(
        &'a self,
        authority: &'a FsqliteAuthorityStore,
        cx: &'a FsqliteCx,
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
    ) -> Result<AdmissionSnapshot, ProjectionFailure> {
        if self.snapshots.fetch_add(1, Ordering::SeqCst) == 1 {
            return Err(ProjectionFailure::Unavailable(
                RefusalCode::DurabilityProfileUnavailable,
            ));
        }
        self.inner
            .snapshot_async(authority, cx, basis, authenticated)
            .await
    }
    fn materialize_commit_async<'a>(
        &'a self,
        authority: &'a FsqliteAuthorityStore,
        cx: &'a FsqliteCx,
        basis: &'a PublicationBasis,
        request: &'a TransactionRequest,
        fold: &'a TransactionFoldReport,
        closure: &'a ValidatedClosure,
    ) -> impl Future<Output = Result<CommitMaterialization, ProjectionFailure>> + Send + 'a {
        self.inner
            .materialize_commit_async(authority, cx, basis, request, fold, closure)
    }
    fn materialize_refusal_async<'a>(
        &'a self,
        authority: &'a FsqliteAuthorityStore,
        cx: &'a FsqliteCx,
        basis: &'a PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
    ) -> impl Future<Output = Result<RefusalMaterialization, ProjectionFailure>> + Send + 'a {
        self.inner
            .materialize_refusal_async(authority, cx, basis, tx_id, code)
    }
}
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn packet(socket: &mut TcpStream) -> Option<Vec<u8>> {
    let mut length = [0; 4];
    socket.read_exact(&mut length).unwrap();
    let length = usize::from_str_radix(std::str::from_utf8(&length).unwrap(), 16).unwrap();
    if length == 0 {
        return None;
    }
    assert!((4..=65_520).contains(&length));
    let mut bytes = vec![0; length - 4];
    socket.read_exact(&mut bytes).unwrap();
    Some(bytes)
}

#[test]
fn interrupted_raw_push_reports_unknown_and_recovers_its_committed_prefix_after_restart() {
    for format in [Format::Sha1, Format::Sha256] {
        let root = Scratch(std::env::temp_dir().join(format!(
            "fg-raw-prefix-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        let principal = PrincipalId::from_bytes([0xa3; 16]);
        let config = NodeConfig::new(
            root.0.clone(),
            TenantId::from_bytes([0xa1; 16]),
            RepositoryId::from_bytes([0xa2; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(2)
        .with_git_daemon_receive_principal(principal);
        let (mut node, _) = OneNode::init(config.clone()).unwrap();
        let selected = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        let before = selected.receipt().generation();
        node.bring_into_service(before).unwrap();
        let path = std::str::from_utf8(node.git_daemon_repository_path().as_bytes())
            .unwrap()
            .to_owned();
        let oid = git_object_id(format, GitObjectKind::Blob, b"x");
        let zero = "0".repeat(format.digest_len() * 2);
        let prefix = encode_packets(
            &[
                Packet::Data(
                    format!(
                        "{zero} {oid} refs/tags/first\0report-status object-format={}",
                        format.as_str()
                    )
                    .into_bytes(),
                ),
                Packet::Data(format!("{zero} {oid} refs/tags/second").into_bytes()),
                Packet::Flush,
            ],
            &WireLimits::default(),
        )
        .unwrap();
        let mut pack = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
        pack.extend_from_slice(&[
            0x31, 0x78, 0x01, 0x01, 1, 0, 0xfe, 0xff, b'x', 0, 121, 0, 121,
        ]);
        let checksum = match format {
            Format::Sha1 => sha1_digest(&pack).to_vec(),
            Format::Sha256 => sha256_digest(&pack).to_vec(),
        };
        pack.extend_from_slice(&checksum);
        let session = LoopbackReceiveSession::authenticated(
            principal,
            retry_key(path.as_bytes(), &prefix).unwrap(),
        );
        let body = [prefix, pack].concat();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let deadline = GitDaemonSessionDeadline::new(
                node.git_daemon_session_timeout,
                node.git_daemon_session_work_scaling,
            );
            let result = node.serve_guarded_git_daemon_stream_with_admission(
                stream,
                deadline,
                None,
                None,
                |request, session, validated, staging, live| {
                    node.receive_publication_admitted()?;
                    let identity = session.authenticated_session().unwrap();
                    let context = AdmissionContext {
                        head_key: node.head_key.clone(),
                        tenant_id: node.tenant_id,
                        repository_id: node.repository_id,
                        object_format: node.object_format,
                        principal_id: identity.principal_id(),
                        idempotency_key: identity.client_idempotency_key().clone(),
                    };
                    let probe = FailSecond {
                        inner: node
                            .durable_admission_projection_publishing(&context, staging)
                            .unwrap(),
                        snapshots: AtomicUsize::new(0),
                    };
                    let mut checkpoint = || live();
                    let result = drive_request_while(
                        &node,
                        request,
                        receive_session::admit(
                            &node.authority,
                            request.authority(),
                            &context,
                            validated,
                            AdmissionLimits::default(),
                            &probe,
                        ),
                        &mut checkpoint,
                    )
                    .map_err(|error| NodeSmartHttpRefusal::ReceiveInterrupted(Box::new(error)));
                    assert_eq!(
                        probe.snapshots.load(Ordering::SeqCst),
                        2,
                        "the fault must actually be reached"
                    );
                    result
                },
            );
            (node, result)
        });
        let mut socket = TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        socket
            .write_all(
                &encode_packets(
                    &[Packet::Data(
                        format!("git-receive-pack {path}\0host=localhost\0").into_bytes(),
                    )],
                    &WireLimits::default(),
                )
                .unwrap(),
            )
            .unwrap();
        while let Some(row) = packet(&mut socket) {
            assert!(!row.starts_with(b"ERR "));
        }
        socket.write_all(&body).unwrap();
        let error_line = packet(&mut socket).unwrap();
        assert!(error_line.starts_with(b"ERR receive outcome unknown"));
        assert!(!error_line.windows(3).any(|bytes| bytes == b"ng "));
        socket.shutdown(Shutdown::Write).unwrap();
        let (node, result) = worker.join().unwrap();
        let NodeSmartHttpRefusal::ReceiveInterrupted(error) = result.unwrap_err() else {
            panic!("retain admission error")
        };
        assert_eq!(error.completed_commands().len(), 1);
        assert!(matches!(
            error.completed_commands()[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert!(matches!(
            error.admission_error(),
            AdmissionError::AsyncProjectionUnavailable(RefusalCode::DurabilityProfileUnavailable)
        ));
        node.shutdown().unwrap();
        let mut node = OneNode::open_existing(config).unwrap();
        let selected = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        node.bring_into_service(selected.receipt().generation())
            .unwrap();
        let snapshot = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(snapshot.basis().generation().get(), before.get() + 1);
        assert_eq!(snapshot.snapshot().refs.len(), 1);
        assert!(
            snapshot
                .snapshot()
                .refs
                .contains_key(&RefName::try_new(b"refs/tags/first").unwrap())
        );
        let SessionRecovery::Recovered(partial) = node
            .runtime()
            .block_on(node.recover_receive_session_in(&node.request_context(), &session))
            .unwrap()
        else {
            panic!("persisted session")
        };
        assert!(!partial.all_terminal());
        assert_eq!(partial.commands().len(), 2);
        assert_eq!(
            partial.commands()[0].recovery().terminal(),
            Some(error.completed_commands()[0].terminal)
        );
        assert!(
            matches!(partial.commands()[1].recovery(), RequestRecovery::Recovered(known)
            if known.outcome() == OutcomeLookup::Undecided)
        );
        // Retry via the unmodified HTTP adapter with the SAME binary session
        // key. This is the typed API, not an ASCII-only HTTP header encoding.
        let headers = format!(
            "POST {path}/git-receive-pack HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-git-receive-pack-request\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let head = fgit_wire::smart_http::parse_head(headers.as_bytes(), Default::default())
            .unwrap()
            .unwrap();
        let retry = node
            .smart_http_receive_rpc_in(
                &head,
                &session,
                &body,
                Default::default(),
                AdmissionLimits::default(),
                &mut || true,
                &mut Vec::new(),
            )
            .unwrap();
        assert_eq!(retry.commands[0], error.completed_commands()[0]);
        assert!(matches!(
            retry.commands[1].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let SessionRecovery::Recovered(complete) = node
            .runtime()
            .block_on(node.recover_receive_session_in(&node.request_context(), &session))
            .unwrap()
        else {
            panic!("same persisted session")
        };
        assert_eq!(complete.identity(), partial.identity());
        assert!(complete.all_terminal());
        assert_eq!(
            node.runtime()
                .block_on(node.materialize_admission())
                .unwrap()
                .basis()
                .generation()
                .get(),
            before.get() + 2
        );
        node.shutdown().unwrap();
    }
}

// The only injected operation is a bounded server-work stall AFTER real
// quarantine. Both twins still run the real admission/CAS and wire response.
fn timed_push(
    node: OneNode,
    path: String,
    body: Vec<u8>,
    delay: Option<Duration>,
) -> (
    OneNode,
    Result<Option<fgit_admission::AdmissionResult>, NodeSmartHttpRefusal>,
    Vec<u8>,
) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let worker = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let ingress = GitDaemonSessionDeadline::new(
            node.git_daemon_session_timeout,
            node.git_daemon_session_work_scaling,
        );
        let mut reached = false;
        let result = node.serve_guarded_git_daemon_stream_with_admission(
            stream,
            ingress,
            None,
            None,
            |request, session, validated, staging, live| {
                reached = true;
                if let Some(delay) = delay {
                    let start = Instant::now();
                    std::thread::sleep(delay);
                    assert!(start.elapsed() > node.git_daemon_session_timeout.duration());
                }
                node.admit_guarded_receive(request, session, validated, staging, live)
            },
        );
        assert!(
            reached,
            "the real post-quarantine admission must be reached"
        );
        (node, result)
    });
    let mut socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    socket
        .write_all(
            &encode_packets(
                &[Packet::Data(
                    format!("git-receive-pack {path}\0host=localhost\0").into_bytes(),
                )],
                &WireLimits::default(),
            )
            .unwrap(),
        )
        .unwrap();
    while let Some(row) = packet(&mut socket) {
        assert!(!row.starts_with(b"ERR "));
    }
    socket.write_all(&body).unwrap();
    let mut report = Vec::new();
    while let Some(row) = packet(&mut socket) {
        let fatal = row.starts_with(b"ERR ");
        report.extend_from_slice(&row);
        if fatal {
            break;
        }
    }
    socket.shutdown(Shutdown::Write).unwrap();
    let (node, result) = worker.join().unwrap();
    (node, result, report)
}

#[test]
fn receive_processing_can_outlast_ingress_and_expiry_recovers_with_the_same_key() {
    for format in [Format::Sha1, Format::Sha256] {
        for allowed in [true, false] {
            let root = Scratch(std::env::temp_dir().join(format!(
                "fg-independent-receive-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            )));
            let principal = PrincipalId::from_bytes([0xa3; 16]);
            let config = NodeConfig::new(
                root.0.clone(),
                TenantId::from_bytes([0xa1; 16]),
                RepositoryId::from_bytes([0xa2; 16]),
            )
            .with_object_format(format)
            .with_worker_threads(2)
            .with_git_daemon_receive_principal(principal)
            .with_git_daemon_session_timeout(
                crate::GitDaemonSessionTimeout::try_new(Duration::from_secs(5)).unwrap(),
            )
            .with_git_daemon_session_work_scaling(GitDaemonSessionWorkScaling::FLAT)
            .with_git_daemon_receive_processing_timeout(
                crate::GitDaemonReceiveProcessingTimeout::try_new(Duration::from_secs(
                    if allowed { 30 } else { 1 },
                ))
                .unwrap(),
            );
            let (mut node, _) = OneNode::init(config.clone()).unwrap();
            let selected = node
                .runtime()
                .block_on(node.authenticate_authority_head())
                .unwrap();
            let before = selected.receipt().generation();
            node.bring_into_service(before).unwrap();
            let path = std::str::from_utf8(node.git_daemon_repository_path().as_bytes())
                .unwrap()
                .to_owned();
            let oid = git_object_id(format, GitObjectKind::Blob, b"x");
            let name = RefName::try_new(b"refs/tags/independent-budget").unwrap();
            let prefix = encode_packets(
                &[
                    Packet::Data(
                        format!(
                            "{} {oid} refs/tags/independent-budget\0report-status object-format={}",
                            "0".repeat(format.digest_len() * 2),
                            format.as_str()
                        )
                        .into_bytes(),
                    ),
                    Packet::Flush,
                ],
                &WireLimits::default(),
            )
            .unwrap();
            let session = LoopbackReceiveSession::authenticated(
                principal,
                retry_key(path.as_bytes(), &prefix).unwrap(),
            );
            let mut pack = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
            pack.extend_from_slice(&[
                0x31, 0x78, 0x01, 0x01, 1, 0, 0xfe, 0xff, b'x', 0, 121, 0, 121,
            ]);
            let checksum = match format {
                Format::Sha1 => sha1_digest(&pack).to_vec(),
                Format::Sha256 => sha256_digest(&pack).to_vec(),
            };
            pack.extend_from_slice(&checksum);
            let body = [prefix, pack].concat();
            let (node, first, report) = timed_push(
                node,
                path.clone(),
                body.clone(),
                Some(Duration::from_secs(6)),
            );
            let original = if allowed {
                let outcome = first.unwrap().unwrap();
                assert_eq!(outcome.commands.len(), 1);
                assert!(matches!(
                    outcome.commands[0].terminal.outcome,
                    DecisionOutcome::Committed { .. }
                ));
                assert!(report.starts_with(b"unpack ok"), "{report:?}");
                assert!(
                    report
                        .windows(b"ok refs/tags/independent-budget".len())
                        .any(|w| w == b"ok refs/tags/independent-budget")
                );
                Some(outcome.commands[0])
            } else {
                assert!(matches!(
                    first,
                    Err(NodeSmartHttpRefusal::ReceiveInterrupted(_))
                ));
                assert!(
                    report.starts_with(b"ERR receive outcome unknown"),
                    "{report:?}"
                );
                // The expired processing clock is named for the operator.
                let flag = b"fg serve --processing-timeout-secs";
                assert!(report.windows(flag.len()).any(|w| w == flag));
                // No per-ref `ng` report line. Match line starts: the words
                // "processing" and "during" contain those bytes.
                assert!(
                    !report
                        .split(|byte| *byte == b'\n')
                        .any(|line| line.starts_with(b"ng "))
                );
                None
            };
            node.shutdown().unwrap();
            // Inspect authenticated canonical state after a real cold reopen;
            // the negative is known pre-CAS here, not a general timeout claim.
            let retry_config = config.with_git_daemon_receive_processing_timeout(
                crate::GitDaemonReceiveProcessingTimeout::try_new(Duration::from_secs(30)).unwrap(),
            );
            let mut node = OneNode::open_existing(retry_config.clone()).unwrap();
            let selected = node
                .runtime()
                .block_on(node.authenticate_authority_head())
                .unwrap();
            node.bring_into_service(selected.receipt().generation())
                .unwrap();
            let snapshot = node
                .runtime()
                .block_on(node.materialize_admission())
                .unwrap();
            assert_eq!(
                snapshot.basis().generation().get(),
                before.get() + u64::from(allowed)
            );
            assert_eq!(
                snapshot.snapshot().refs.get(&name).copied(),
                allowed.then_some(oid)
            );
            let (node, retry, report) = timed_push(node, path, body, None);
            let retry = retry.unwrap().unwrap();
            assert!(report.starts_with(b"unpack ok"));
            assert_eq!(retry.commands.len(), 1);
            assert!(matches!(
                retry.commands[0].terminal.outcome,
                DecisionOutcome::Committed { .. }
            ));
            if let Some(original) = original {
                assert_eq!(
                    retry.commands[0], original,
                    "identical retry retains its original transaction"
                );
            }
            let SessionRecovery::Recovered(recovered) = node
                .runtime()
                .block_on(node.recover_receive_session_in(&node.request_context(), &session))
                .unwrap()
            else {
                panic!("same persisted session key")
            };
            assert!(recovered.all_terminal());
            assert_eq!(
                recovered.commands()[0].recovery().terminal(),
                Some(retry.commands[0].terminal)
            );
            node.shutdown().unwrap();
            let node = OneNode::open_existing(retry_config).unwrap();
            let snapshot = node
                .runtime()
                .block_on(node.materialize_admission())
                .unwrap();
            assert_eq!(
                snapshot.basis().generation().get(),
                before.get() + 1,
                "one canonical publication across restart and identical retry"
            );
            assert_eq!(snapshot.snapshot().refs.get(&name), Some(&oid));
            node.shutdown().unwrap();
        }
    }
}
