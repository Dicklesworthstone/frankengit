//! The sole writer slot protects admission, never client response delivery.
//! These tests execute native quarantine and durable publication. A response
//! writer tries to acquire the same gate before accepting any response bytes;
//! retaining the old permit makes that finite acquisition fail deterministically.

mod structural_quarantine;

use std::io::{self, Cursor, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fgit_admission::policy_bridge::receive_session::recovery::SessionRecovery;
use fgit_admission::{AdmissionLimits, AdmissionResult};
use fgit_authority::IdempotencyKey;
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, PrincipalId, RefusalCode, RepositoryId, TenantId,
};
use fgit_wire::smart_http::{HttpLimits, parse_head};
use fgit_wire::{Packet, WireLimits, encode_packets};

use crate::{
    GitDaemonSessionDeadline, GitDaemonSessionTimeout, GitDaemonSessionWorkScaling,
    LoopbackReceiveSession, NodeConfig, NodeSmartHttpRefusal, OneNode, ReceiveResponseWriter,
    WriterGate,
};

const PRINCIPAL: PrincipalId = PrincipalId::from_bytes([0xc3; 16]);
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "fg-receive-response-permit-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn node(format: GitHashAlgorithm) -> (OneNode, Scratch) {
    let scratch = Scratch::new();
    let (mut node, _) = OneNode::init(
        NodeConfig::new(
            scratch.0.clone(),
            TenantId::from_bytes([0xc1; 16]),
            RepositoryId::from_bytes([0xc2; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(1),
    )
    .unwrap();
    let head = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap();
    node.bring_into_service(head.receipt().generation())
        .unwrap();
    (node, scratch)
}

fn deadline(duration: Duration) -> GitDaemonSessionDeadline {
    GitDaemonSessionDeadline::new(
        GitDaemonSessionTimeout::try_new(duration).unwrap(),
        GitDaemonSessionWorkScaling::FLAT,
    )
}

fn generation(node: &OneNode) -> u64 {
    node.runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap()
        .receipt()
        .generation()
        .get()
}

struct ResponseProbe<'a> {
    gate: &'a WriterGate,
    response: bool,
    fail_delivery: bool,
    checked: bool,
    bytes: Vec<u8>,
}
impl<'a> ResponseProbe<'a> {
    fn new(gate: &'a WriterGate, response: bool, fail_delivery: bool) -> Self {
        Self {
            gate,
            response,
            fail_delivery,
            checked: false,
            bytes: Vec::new(),
        }
    }
}
impl Write for ResponseProbe<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.response {
            if !self.checked {
                // No other test thread holds this gate. The short deadline is
                // only a bounded failure path if the receive kept its permit;
                // successful acquisition requires no scheduling or sleeps.
                let permit = self
                    .gate
                    .acquire(&deadline(Duration::from_millis(5)))
                    .expect("another writer must be admitted before response I/O");
                self.checked = true;
                drop(permit);
            }
            if self.fail_delivery {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl ReceiveResponseWriter for ResponseProbe<'_> {
    fn restart_deadline(&mut self, _: GitDaemonSessionDeadline) {
        // Raw TCP and SSH advertise before ingress, then explicitly enter
        // their response phase after validation/admission has finished.
        self.response = true;
    }
}

fn commands(format: GitHashAlgorithm, suffix: &str) -> Vec<u8> {
    let zero = "0".repeat(format.digest_len() * 2);
    let stale = "1".repeat(format.digest_len() * 2);
    encode_packets(
        &[
            Packet::Data(
                format!(
                    "{stale} {zero} refs/tags/stale-{suffix}\0report-status delete-refs object-format={}",
                    format.as_str()
                )
                .into_bytes(),
            ),
            Packet::Data(format!("{zero} {zero} refs/tags/absent-{suffix}").into_bytes()),
            Packet::Flush,
        ],
        &WireLimits::default(),
    )
    .unwrap()
}

fn terminal(
    result: Result<AdmissionResult, NodeSmartHttpRefusal>,
    failed_delivery: bool,
) -> AdmissionResult {
    let result = if failed_delivery {
        let Err(NodeSmartHttpRefusal::ReceiveResponse { outcome, source }) = result else {
            panic!("failed delivery must retain the complete canonical outcome");
        };
        assert!(matches!(*source, NodeSmartHttpRefusal::Io { .. }));
        *outcome
    } else {
        result.unwrap()
    };
    assert_eq!(result.commands.len(), 2);
    assert_ne!(result.commands[0].tx_id, result.commands[1].tx_id);
    assert!(matches!(
        result.commands[0].terminal.outcome,
        DecisionOutcome::Refused {
            code: RefusalCode::ExpectedOldRefMismatch,
            ..
        }
    ));
    assert!(matches!(
        result.commands[1].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    result
}

fn recover(node: &OneNode, session: &LoopbackReceiveSession, expected: &AdmissionResult) {
    let before = generation(node);
    let recovery = node
        .runtime()
        .block_on(node.recover_receive_session_in(&node.request_context(), session))
        .unwrap();
    let SessionRecovery::Recovered(known) = recovery else {
        panic!("the complete decided session must remain recoverable");
    };
    assert!(known.all_terminal());
    assert_eq!(known.commands().len(), expected.commands.len());
    for (index, (command, expected)) in known.commands().iter().zip(&expected.commands).enumerate()
    {
        assert_eq!(command.index(), index);
        assert_eq!(command.recovery().terminal(), Some(expected.terminal));
    }
    assert_eq!(
        generation(node),
        before,
        "read-only recovery cannot republish"
    );
    assert!(
        node.runtime()
            .block_on(node.materialize_admission())
            .unwrap()
            .snapshot()
            .refs
            .is_empty()
    );
}

#[test]
fn raw_and_ssh_shared_receive_releases_the_writer_before_success_or_lost_response() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (node, _scratch) = node(format);
        let writers = WriterGate::new(1);
        let route = node.git_daemon_repository_path().as_bytes().to_vec();
        for fail_delivery in [false, true] {
            let wire = commands(format, &format!("raw-{fail_delivery}"));
            let mut input = Cursor::new(wire);
            let mut output = ResponseProbe::new(&writers, false, fail_delivery);
            let before = generation(&node);
            let mut session = None;
            // Both raw TCP and SSH invoke this production coordinator with
            // this same guarded admission callback. Capture its actual retry
            // key instead of recreating the transport identity derivation.
            let result = node.serve_guarded_receive_session(
                &mut input,
                &mut output,
                Some(PRINCIPAL),
                &deadline(Duration::from_secs(30)),
                None,
                Some(&writers),
                &WireLimits::default(),
                |_| Ok(route.clone()),
                |request, selected_session, validated, live| {
                    session = Some(selected_session.clone());
                    node.admit_guarded_receive(request, selected_session, validated, live)
                },
            );
            let expected = terminal(
                result.map(|result| result.expect("a nonempty receive has an outcome")),
                fail_delivery,
            );
            assert!(output.checked);
            assert_eq!(generation(&node), before + 1);
            recover(&node, &session.unwrap(), &expected);
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn http_receive_releases_the_writer_before_success_or_lost_response() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (node, _scratch) = node(format);
        let writers = WriterGate::new(1);
        let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
        for fail_delivery in [false, true] {
            let body = commands(format, &format!("http-{fail_delivery}"));
            let head = format!(
                "POST {route}/git-receive-pack HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-git-receive-pack-request\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            let request = parse_head(head.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            let session = LoopbackReceiveSession::authenticated(
                PRINCIPAL,
                IdempotencyKey::new(format!("http-permit-{fail_delivery}").into_bytes()).unwrap(),
            );
            let mut output = ResponseProbe::new(&writers, true, fail_delivery);
            let before = generation(&node);
            let result = node.smart_http_receive_stream_gated_in(
                &request,
                &session,
                &mut Cursor::new(body),
                HttpLimits::default(),
                AdmissionLimits::default(),
                Some(&writers),
                &mut || true,
                &mut output,
            );
            let expected = terminal(result, fail_delivery);
            assert!(output.checked);
            assert_eq!(generation(&node), before + 1);
            recover(&node, &session, &expected);
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn http_planning_refusal_releases_the_writer_before_its_protocol_error() {
    let (node, _scratch) = node(GitHashAlgorithm::Sha1);
    let writers = WriterGate::new(1);
    let body = commands(GitHashAlgorithm::Sha1, "over-limit");
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let head = format!(
        "POST {route}/git-receive-pack HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-git-receive-pack-request\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let request = parse_head(head.as_bytes(), HttpLimits::default())
        .unwrap()
        .unwrap();
    let session = LoopbackReceiveSession::authenticated(
        PRINCIPAL,
        IdempotencyKey::new(b"http-permit-planning-refusal".to_vec()).unwrap(),
    );
    let mut output = ResponseProbe::new(&writers, true, false);
    let before = generation(&node);
    let result = node.smart_http_receive_stream_gated_in(
        &request,
        &session,
        &mut Cursor::new(body),
        HttpLimits::default(),
        AdmissionLimits {
            max_commands: 1,
            ..AdmissionLimits::default()
        },
        Some(&writers),
        &mut || true,
        &mut output,
    );
    let Err(NodeSmartHttpRefusal::ReceiveInterrupted(interrupted)) = result else {
        panic!("the narrower planning bound must refuse before publication");
    };
    assert!(matches!(
        interrupted.admission_error(),
        fgit_admission::AdmissionError::CommandLimitExceeded { limit: 1 }
    ));
    assert!(interrupted.session().is_none());
    assert!(interrupted.completed_commands().is_empty());
    assert!(output.checked);
    assert!(output.bytes.windows(4).any(|bytes| bytes == b"ERR "));
    assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
}

#[test]
fn quarantine_verdicts_release_the_writer_before_raw_and_http_delivery() {
    for http in [false, true] {
        let (node, _scratch) = node(GitHashAlgorithm::Sha1);
        let writers = WriterGate::new(1);
        let zero = "0".repeat(40);
        let missing = "1".repeat(40);
        let mut body = encode_packets(
            &[
                Packet::Data(
                    format!("{zero} {missing} refs/tags/missing\0report-status object-format=sha1")
                        .into_bytes(),
                ),
                Packet::Flush,
            ],
            &WireLimits::default(),
        )
        .unwrap();
        // A valid native pack with no objects cannot supply this new target.
        // This reaches the real quarantine verdict, after taking the permit.
        let mut pack = b"PACK\0\0\0\x02\0\0\0\0".to_vec();
        let trailer = fgit_crypto::sha1_digest(&pack);
        pack.extend_from_slice(&trailer);
        body.extend_from_slice(&pack);
        let route = node.git_daemon_repository_path().as_bytes().to_vec();
        let mut output = ResponseProbe::new(&writers, http, false);
        let before = generation(&node);
        let result = if http {
            let route = std::str::from_utf8(&route).unwrap();
            let head = format!(
                "POST {route}/git-receive-pack HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-git-receive-pack-request\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            let request = parse_head(head.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            let session = LoopbackReceiveSession::authenticated(
                PRINCIPAL,
                IdempotencyKey::new(b"http-permit-quarantine-refusal".to_vec()).unwrap(),
            );
            node.smart_http_receive_stream_gated_in(
                &request,
                &session,
                &mut Cursor::new(body),
                HttpLimits::default(),
                AdmissionLimits::default(),
                Some(&writers),
                &mut || true,
                &mut output,
            )
        } else {
            node.serve_guarded_receive_session(
                &mut Cursor::new(body),
                &mut output,
                Some(PRINCIPAL),
                &deadline(Duration::from_secs(30)),
                None,
                Some(&writers),
                &WireLimits::default(),
                |_| Ok(route),
                |_, _, _, _| panic!("a quarantine refusal must not reach admission"),
            )
            .map(|result| result.expect("a nonempty receive has an outcome"))
        };
        let code = match result {
            Err(NodeSmartHttpRefusal::Receive(error)) => match *error {
                fgit_wire::receive::ReceiveError::AuthoritativeRefusal(code) => code,
                other => panic!("expected a quarantine verdict: {other:?}"),
            },
            Err(NodeSmartHttpRefusal::Rpc(error)) => match *error {
                fgit_wire::smart_http::rpc::RpcError::Receive(
                    fgit_wire::receive::ReceiveError::AuthoritativeRefusal(code),
                ) => code,
                other => panic!("expected a quarantine verdict: {other:?}"),
            },
            other => panic!("expected a quarantine verdict: {other:?}"),
        };
        assert_eq!(code, RefusalCode::ObjectClosureIncomplete);
        assert!(output.checked);
        assert!(
            String::from_utf8_lossy(&output.bytes).contains(
                "ng refs/tags/missing missing necessary objects (ObjectClosureIncomplete)"
            )
        );
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}
