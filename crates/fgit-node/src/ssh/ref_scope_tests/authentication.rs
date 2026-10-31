//! Policy evidence through real raw Git TCP and the native SSH command binding.
//! SSH signature/key-exchange verification remains the owning SSH suite's gate.

use super::*;
use fgit_forge::ExpectedVersion;
use fgit_forge::event::protection::{ProtectionCommand, ReviewProtection, compile_ref_policy};
use fgit_types::RefusalCode;

fn install_authentication_policy(node: &OneNode, minimum: &str, key: &[u8]) {
    let request = node.request_context();
    let selected = node
        .runtime()
        .block_on(node.read_review_protection_in(&request))
        .unwrap();
    let policy = compile_ref_policy(&format!(
        "policy authentication {{ rule required {{ when actor.authentication >= {minimum} then allow }} default deny \"stronger authentication required\" }}"
    )).unwrap();
    let command = ProtectionCommand {
        expected_version: selected
            .version()
            .map_or(ExpectedVersion::NewStream, ExpectedVersion::Exactly),
        expected_epoch: selected.policy_epoch,
        protection: ReviewProtection {
            administrators: vec![PRINCIPAL],
            branches: Vec::new(),
            ref_policy: Some(policy),
        },
    };
    let result = node
        .runtime()
        .block_on(node.admit_review_protection_durable_in(
            &request,
            &LoopbackReceiveSession::authenticated(
                PRINCIPAL,
                IdempotencyKey::new(key.to_vec()).unwrap(),
            ),
            &command,
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        result.1.outcome,
        DecisionOutcome::Committed { .. }
    ));
}

fn command_prefix(format: GitHashAlgorithm, label: &str) -> Vec<u8> {
    let zero = "0".repeat(format.digest_len() * 2);
    let oid = git_object_id(format, GitObjectKind::Blob, b"x");
    encode_packets(
        &[
            Packet::Data(
                format!(
                    "{zero} {oid} refs/tags/{label}/one\0report-status object-format={}",
                    format.as_str()
                )
                .into_bytes(),
            ),
            Packet::Data(format!("{zero} {oid} refs/tags/{label}/two").into_bytes()),
            Packet::Flush,
        ],
        &WireLimits::default(),
    )
    .unwrap()
}

fn raw_receive(node: &OneNode, body: &[u8]) -> fgit_admission::AdmissionResult {
    use std::io::Read;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let mut greeting = b"git-receive-pack ".to_vec();
    greeting.extend_from_slice(node.git_daemon_repository_path().as_bytes());
    greeting.extend_from_slice(b"\0host=localhost\0");
    std::thread::scope(|scope| {
        let client = scope.spawn(move || {
            let mut socket = TcpStream::connect(address).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(30)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(30)))
                .unwrap();
            socket
                .write_all(
                    &encode_packets(&[Packet::Data(greeting)], &WireLimits::default()).unwrap(),
                )
                .unwrap();
            socket.write_all(body).unwrap();
            let mut response = Vec::new();
            socket.read_to_end(&mut response).unwrap();
            assert!(!response.is_empty());
        });
        let (stream, _) = listener.accept().unwrap();
        let result = node
            .serve_guarded_git_daemon_stream(stream)
            .unwrap()
            .unwrap();
        client.join().unwrap();
        result
    })
}

fn outcomes(result: &fgit_admission::AdmissionResult, committed: bool) {
    assert_eq!(result.commands.len(), 2);
    for command in &result.commands {
        if committed {
            assert!(matches!(
                command.terminal.outcome,
                DecisionOutcome::Committed { .. }
            ));
        } else {
            assert!(matches!(
                command.terminal.outcome,
                DecisionOutcome::Refused {
                    code: RefusalCode::ProtectedRefTransitionDenied,
                    ..
                }
            ));
        }
    }
}

fn persisted_ssh_evidence(
    node: &OneNode,
    result: &fgit_admission::AdmissionResult,
) -> Vec<fgit_codec::RepositoryCommitRecord> {
    use fgit_admission::evidence::{
        AdmissionAuthentication, PolicyDecisionRecord, PrincipalSnapshotRecord,
    };

    let request = node.request_context();
    let history = node
        .runtime()
        .block_on(node.snapshot_history_in(&request))
        .unwrap();
    let records = history
        .iter()
        .flat_map(|batch| &batch.batch.committed_rcrs)
        .filter(|record| {
            result
                .commands
                .iter()
                .any(|command| command.tx_id == record.tx_id)
        })
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(records.len(), result.commands.len());
    for record in &records {
        let identity = record.principal_snapshot_id.as_internal_object_id();
        let principal = node
            .runtime()
            .block_on(crate::read_principal_snapshot_in(
                &node.authority,
                request.authority(),
                node.repository_id,
                fgit_types::Digest::new(identity.algorithm(), *identity.digest()),
                &|| false,
            ))
            .unwrap();
        assert!(matches!(
            principal,
            PrincipalSnapshotRecord::Authenticated(_)
        ));
        assert_eq!(
            principal.authentication(),
            Some(AdmissionAuthentication::SshDeployKey)
        );
        let policy = node
            .runtime()
            .block_on(crate::read_policy_decision_in(
                &node.authority,
                request.authority(),
                node.repository_id,
                record.policy_decision_root,
                &|| false,
            ))
            .unwrap();
        assert!(matches!(
            policy,
            PolicyDecisionRecord::AuthenticationActivated(_)
        ));
        assert_eq!(
            policy.authentication(),
            Some(AdmissionAuthentication::SshDeployKey)
        );
    }
    records
}

#[test]
fn ssh_authentication_and_raw_operator_provenance_remain_distinct_across_durable_retries() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let config = NodeConfig::new(
            scratch.0.clone(),
            TenantId::from_bytes([0xb1; 16]),
            RepositoryId::from_bytes([0xb2; 16]),
        )
        .with_worker_threads(1)
        .with_object_format(format)
        .with_git_daemon_receive_principal(PRINCIPAL);
        let (mut node, _) = OneNode::init(config.clone()).unwrap();
        let head = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        node.bring_into_service(head.receipt().generation())
            .unwrap();
        install_authentication_policy(&node, "single_factor", b"require-transport-authentication");

        // Raw Git's configured writer is an operator assertion, even when its
        // principal ID equals the principal authorized by an SSH deploy key.
        let raw_prefix = command_prefix(format, "raw-refused");
        let raw_body = [raw_prefix, pack(format)].concat();
        let denied = raw_receive(&node, &raw_body);
        outcomes(&denied, false);
        let retry = serve(
            &node,
            &mut Cursor::new(raw_body),
            &mut Reply::default(),
            Some(grant("all")),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            retry, denied,
            "stronger transport evidence does not replace a sealed refusal"
        );

        let ssh_prefix = command_prefix(format, "ssh-permitted");
        let ssh_body = [ssh_prefix.clone(), pack(format)].concat();
        let accepted = serve(
            &node,
            &mut Cursor::new(ssh_body.clone()),
            &mut Reply::default(),
            Some(grant("all")),
        )
        .unwrap()
        .unwrap();
        outcomes(&accepted, true);
        let session = identity(&node, &ssh_prefix);
        node.shutdown().unwrap();

        let mut reopened = OneNode::open_existing(config).unwrap();
        let head = reopened
            .runtime()
            .block_on(reopened.authenticate_authority_head())
            .unwrap();
        reopened
            .bring_into_service(head.receipt().generation())
            .unwrap();
        let original_records = persisted_ssh_evidence(&reopened, &accepted);
        let snapshot = reopened
            .runtime()
            .block_on(reopened.materialize_admission())
            .unwrap();
        assert!(
            snapshot
                .snapshot()
                .refs
                .contains_key(&RefName::try_new(b"refs/tags/ssh-permitted/one").unwrap())
        );
        assert!(
            !snapshot
                .snapshot()
                .refs
                .contains_key(&RefName::try_new(b"refs/tags/raw-refused/one").unwrap())
        );
        drop(snapshot);
        let recovered = reopened
            .runtime()
            .block_on(reopened.recover_receive_session_in(&reopened.request_context(), &session))
            .unwrap();
        assert!(matches!(recovered, SessionRecovery::Recovered(session) if session.all_terminal()));

        install_authentication_policy(&reopened, "multi_factor", b"ssh-key-is-not-mfa");
        assert_eq!(
            raw_receive(&reopened, &ssh_body),
            accepted,
            "terminal recovery cannot be blocked by a changed transport or policy"
        );
        assert_eq!(
            persisted_ssh_evidence(&reopened, &accepted),
            original_records
        );
        let fresh = [command_prefix(format, "ssh-mfa-refused"), pack(format)].concat();
        let denied = serve(
            &reopened,
            &mut Cursor::new(fresh),
            &mut Reply::default(),
            Some(grant("all")),
        )
        .unwrap()
        .unwrap();
        outcomes(&denied, false);
        reopened.shutdown().unwrap();
    }
}
