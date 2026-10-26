//! Native transport regressions for structural work outside writer admission.

use std::io::Read;
use std::sync::mpsc;

use fgit_git_object::ObjectType;
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, ObjectId, PackError, PackLimits, PackPlanner,
    PackWriteError, PackWriteProfile, PackWriter,
};
use fgit_wire::receive::ReceiveError;
use fgit_wire::smart_http::rpc::RpcError;

use super::*;
use crate::{GitDaemonReceiveProcessingTimeout, NodeReceiveTransportRefusal};

#[derive(Default)]
struct Output(Vec<u8>);

impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl ReceiveResponseWriter for Output {
    fn restart_deadline(&mut self, _: GitDaemonSessionDeadline) {}
}

fn set_timeouts(node: &mut OneNode, timeout: Duration) {
    node.git_daemon_session_timeout = GitDaemonSessionTimeout::try_new(timeout).unwrap();
    node.git_daemon_receive_processing_timeout =
        GitDaemonReceiveProcessingTimeout::try_new(timeout).unwrap();
}

fn http_receive(
    node: &OneNode,
    bytes: &[u8],
    session: &LoopbackReceiveSession,
    gate: Option<&WriterGate>,
) -> Result<AdmissionResult, NodeSmartHttpRefusal> {
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let header = format!(
        "POST {route}/git-receive-pack HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-git-receive-pack-request\r\nContent-Length: {}\r\n\r\n",
        bytes.len()
    );
    let request = parse_head(header.as_bytes(), HttpLimits::default())
        .unwrap()
        .unwrap();
    node.smart_http_receive_stream_gated_in(
        &request,
        session,
        &mut Cursor::new(bytes),
        HttpLimits::default(),
        AdmissionLimits::default(),
        gate,
        &mut || true,
        &mut Output::default(),
    )
}

fn session(key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(PRINCIPAL, IdempotencyKey::new(key.to_vec()).unwrap())
}

fn command(old: &str, new: &str, format: GitHashAlgorithm, name: &str) -> Vec<u8> {
    encode_packets(
        &[
            Packet::Data(
                format!(
                    "{old} {new} {name}\0report-status delete-refs object-format={}",
                    format.as_str()
                )
                .into_bytes(),
            ),
            Packet::Flush,
        ],
        &WireLimits::default(),
    )
    .unwrap()
}

fn empty_pack(format: GitHashAlgorithm) -> Vec<u8> {
    let mut pack = b"PACK\0\0\0\x02\0\0\0\0".to_vec();
    let trailer = match format {
        GitHashAlgorithm::Sha1 => fgit_crypto::sha1_digest(&pack).to_vec(),
        GitHashAlgorithm::Sha256 => fgit_crypto::sha256_digest(&pack).to_vec(),
    };
    pack.extend_from_slice(&trailer);
    pack
}

#[test]
fn corrupt_packs_are_refused_while_another_writer_holds_the_only_permit() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut node, _scratch) = node(format);
        // An implementation that waits for the occupied gate returns a
        // capacity refusal instead of the pack's own checksum error. Keep
        // that planted regression finite without a timing-based assertion.
        set_timeouts(&mut node, Duration::from_millis(500));
        let gate = WriterGate::new(1);
        let held = gate.acquire(&deadline(Duration::from_secs(30))).unwrap();
        let zero = "00".repeat(format.digest_len());
        let target = "11".repeat(format.digest_len());
        let mut pack = empty_pack(format);
        *pack.last_mut().unwrap() ^= 1;
        let mut body = command(&zero, &target, format, "refs/tags/corrupt");
        body.extend_from_slice(&pack);
        let before = generation(&node);
        let selected_session = session(b"corrupt-before-writer");
        let result = http_receive(&node, &body, &selected_session, Some(&gate));
        assert!(matches!(
            result,
            Err(NodeSmartHttpRefusal::Rpc(error))
                if matches!(*error, RpcError::Receive(ReceiveError::Pack(PackError::TrailerChecksumMismatch)))
        ));
        let route = node.git_daemon_repository_path().as_bytes().to_vec();
        let result = node.serve_guarded_receive_session(
            &mut Cursor::new(&body),
            &mut Output::default(),
            Some(PRINCIPAL),
            &deadline(Duration::from_secs(30)),
            None,
            Some(&gate),
            &WireLimits::default(),
            |_| Ok(route),
            |_, _, _, _| panic!("structural corruption cannot reach admission"),
        );
        assert!(matches!(
            result,
            Err(NodeSmartHttpRefusal::Receive(error))
                if matches!(*error, ReceiveError::Pack(PackError::TrailerChecksumMismatch))
        ));
        assert_eq!(generation(&node), before);
        assert!(matches!(
            node.runtime()
                .block_on(
                    node.recover_receive_session_in(&node.request_context(), &selected_session)
                )
                .unwrap(),
            SessionRecovery::NotObserved
        ));
        drop(held);
        set_timeouts(&mut node, Duration::from_secs(30));
        let zero_body = command(&zero, &zero, format, "refs/tags/permitted");
        let accepted = http_receive(
            &node,
            &zero_body,
            &session(b"valid-after-corrupt"),
            Some(&gate),
        )
        .unwrap();
        assert!(matches!(
            accepted.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert_eq!(generation(&node), before + 1);
        node.shutdown().unwrap();
    }
}

#[test]
fn valid_quarantine_waits_for_capacity_and_an_identical_retry_still_publishes_once() {
    let (mut node, _scratch) = node(GitHashAlgorithm::Sha1);
    set_timeouts(&mut node, Duration::from_millis(500));
    let gate = WriterGate::new(1);
    let held = gate.acquire(&deadline(Duration::from_secs(30))).unwrap();
    let selected_session = session(b"prepared-writer-capacity");
    let bytes = commands(GitHashAlgorithm::Sha1, "prepared-wait");
    let before = generation(&node);
    assert!(matches!(
        http_receive(&node, &bytes, &selected_session, Some(&gate)),
        Err(NodeSmartHttpRefusal::ReceiveTransport(error))
            if matches!(*error, NodeReceiveTransportRefusal::QuotaContained { code: "writer_capacity", .. })
    ));
    assert_eq!(generation(&node), before);
    assert!(matches!(
        node.runtime()
            .block_on(node.recover_receive_session_in(&node.request_context(), &selected_session))
            .unwrap(),
        SessionRecovery::NotObserved
    ));
    drop(held);
    set_timeouts(&mut node, Duration::from_secs(30));
    let expected = terminal(
        http_receive(&node, &bytes, &selected_session, Some(&gate)),
        false,
    );
    assert_eq!(generation(&node), before + 1);
    let retry = terminal(
        http_receive(&node, &bytes, &selected_session, Some(&gate)),
        false,
    );
    assert_eq!(retry.commands, expected.commands);
    assert_eq!(generation(&node), before + 1);
    recover(&node, &selected_session, &expected);
    node.shutdown().unwrap();
}

struct Blob(CanonicalPackObject);

impl CanonicalObjectSource for Blob {
    fn load(&self, id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
        assert_eq!(*id, self.0.id());
        Ok(self.0.clone())
    }
}

fn blob_push(format: GitHashAlgorithm, name: &str) -> (ObjectId, Vec<u8>) {
    let body = b"the predecessor changes while another request waits for a writer".to_vec();
    let id = fgit_crypto::git_object_id(format, fgit_crypto::GitObjectKind::Blob, &body);
    let source = Blob(CanonicalPackObject::new(
        id,
        ObjectType::Blob,
        body,
        Vec::new(),
        0,
        0,
    ));
    let plan = PackPlanner::new(format, PackWriteProfile::STORED_V1, PackLimits::default())
        .plan(&source, &[id], &mut || true)
        .unwrap();
    let (pack, _) = PackWriter::new(PackLimits::default())
        .write(&plan, &mut || true)
        .unwrap();
    let mut bytes = command(
        &"00".repeat(format.digest_len()),
        &id.to_string(),
        format,
        name,
    );
    bytes.extend_from_slice(&pack);
    (id, bytes)
}

struct IngressSignal {
    bytes: Cursor<Vec<u8>>,
    finished: Option<mpsc::SyncSender<()>>,
}

impl Read for IngressSignal {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.bytes.read(buffer)?;
        if self.bytes.position() == self.bytes.get_ref().len() as u64
            && let Some(finished) = self.finished.take()
        {
            finished.send(()).unwrap();
        }
        Ok(count)
    }
}

#[test]
fn authority_is_selected_after_waiting_for_a_writer_and_observes_a_new_ref() {
    let format = GitHashAlgorithm::Sha1;
    let (node, _scratch) = node(format);
    let (mut child, _) = OneNode::init(node.service_config.clone()).unwrap();
    let authenticated = child
        .runtime()
        .block_on(child.authenticate_authority_head())
        .unwrap();
    child
        .bring_into_service(authenticated.receipt().generation())
        .unwrap();
    let name = "refs/tags/arrives-during-wait";
    let (id, publish) = blob_push(format, name);
    let deleting = command(
        &id.to_string(),
        &"00".repeat(format.digest_len()),
        format,
        name,
    );
    let gate = WriterGate::new(1);
    let held = gate.acquire(&deadline(Duration::from_secs(30))).unwrap();
    let (tx, rx) = mpsc::sync_channel(1);
    let before = generation(&node);
    let (result, response) = std::thread::scope(|scope| {
        let gate = &gate;
        let worker = scope.spawn(move || {
            let route = std::str::from_utf8(child.git_daemon_repository_path().as_bytes()).unwrap();
            let header = format!(
                "POST {route}/git-receive-pack HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-git-receive-pack-request\r\nContent-Length: {}\r\n\r\n",
                deleting.len()
            );
            let request = parse_head(header.as_bytes(), HttpLimits::default()).unwrap().unwrap();
            let mut reader = IngressSignal { bytes: Cursor::new(deleting), finished: Some(tx) };
            let mut response = Output::default();
            let result = child.smart_http_receive_stream_gated_in(
                &request,
                &session(b"delete-after-writer-wait"),
                &mut reader,
                HttpLimits::default(),
                AdmissionLimits::default(),
                Some(gate),
                &mut || true,
                &mut response,
            );
            child.shutdown().unwrap();
            (result, response.0)
        });
        rx.recv_timeout(Duration::from_secs(30)).unwrap();
        // This caller owns the sole writer permit. The waiting request's
        // expected-old value does not exist until this real publication.
        let created =
            http_receive(&node, &publish, &session(b"writer-before-delete"), None).unwrap();
        assert!(matches!(
            created.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        drop(held);
        worker.join().unwrap()
    });
    let result = result.unwrap();
    assert!(matches!(
        result.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    assert!(String::from_utf8_lossy(&response).contains("ok refs/tags/arrives-during-wait"));
    assert_eq!(generation(&node), before + 2);
    assert!(
        node.runtime()
            .block_on(node.materialize_admission())
            .unwrap()
            .snapshot()
            .refs
            .is_empty()
    );
    node.shutdown().unwrap();
}
