//! Real embedded authority, native imports and PR decisions. The fixture does
//! not invoke Git or substitute a process-local map for canonical state.
use super::*;
use crate::NodeConfig;
use fgit_admission::AdmissionLimits;
use fgit_authority::{
    IdempotencyKey, OutcomeLookup, SealAttempt, SemanticRequest, admit_seal_async,
    bind_idempotency_key_async, idempotency_binding_key,
};
use fgit_codec::encode_body;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::{ExpectedVersion, PullRequestNumber};
use fgit_types::{
    AsciiSlug, DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RefName,
    RepositoryId, TenantId,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[path = "../../tests/authority_read_fault.rs"]
mod read_fault;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-key-recovery-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(
            self.0.join("node"),
            TenantId::from_bytes([0xd1; 16]),
            RepositoryId::from_bytes([0xd2; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(2)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn principal() -> PrincipalId {
    PrincipalId::from_bytes([0xd3; 16])
}
fn session(key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(principal(), IdempotencyKey::new(key.to_vec()).unwrap())
}
fn recover(node: &OneNode, key: &[u8]) -> Result<RequestRecovery, RecoveryFailure> {
    let request = node.request_context();
    node.runtime()
        .block_on(node.recover_transaction_in(&request, &session(key)))
}
fn head(node: &OneNode) -> fgit_authority::HeadRead {
    let request = node.request_context();
    node.runtime()
        .block_on(
            node.authority
                .read_head(request.authority(), &node.head_key),
        )
        .unwrap()
}
fn loose(
    root: &Path,
    format: GitHashAlgorithm,
    kind: GitObjectKind,
    label: &str,
    bytes: &[u8],
) -> GitOid {
    let id = git_object_id(format, kind, bytes);
    let raw = [format!("{label} {}\0", bytes.len()).as_bytes(), bytes].concat();
    let length = u16::try_from(raw.len()).unwrap();
    let mut framed = vec![0x78, 0x01, 0x01];
    framed.extend(length.to_le_bytes());
    framed.extend((!length).to_le_bytes());
    framed.extend(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521;
        (a, (b + a) % 65_521)
    });
    framed.extend(((b << 16) | a).to_be_bytes());
    let text = id.to_string();
    let directory = root.join("objects").join(&text[..2]);
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join(&text[2..]), framed).unwrap();
    id
}
fn commit(tree: GitOid, parent: Option<GitOid>, message: &str) -> Vec<u8> {
    format!("tree {tree}\n{}author Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\n{message}\n",
        parent.map_or_else(String::new, |id| format!("parent {id}\n"))).into_bytes()
}
fn imported(node: &OneNode, scratch: &Scratch, format: GitHashAlgorithm) -> PullRequestCommand {
    let root = scratch.0.join("source");
    fs::create_dir_all(root.join("refs/heads")).unwrap();
    fs::write(root.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(root.join("config"), match format {
        GitHashAlgorithm::Sha1 => "[core]\nbare = true\nrepositoryformatversion = 0\n",
        GitHashAlgorithm::Sha256 => "[core]\nbare = true\nrepositoryformatversion = 1\n[extensions]\nobjectformat = sha256\n",
    }).unwrap();
    let blob = loose(
        &root,
        format,
        GitObjectKind::Blob,
        "blob",
        b"source artifact can disappear\n",
    );
    let tree = loose(
        &root,
        format,
        GitObjectKind::Tree,
        "tree",
        &[b"100644 file\0".as_slice(), blob.as_bytes()].concat(),
    );
    let base = loose(
        &root,
        format,
        GitObjectKind::Commit,
        "commit",
        &commit(tree, None, "base"),
    );
    let target = loose(
        &root,
        format,
        GitObjectKind::Commit,
        "commit",
        &commit(tree, Some(base), "target"),
    );
    let source = loose(
        &root,
        format,
        GitObjectKind::Commit,
        "commit",
        &commit(tree, Some(base), "source"),
    );
    fs::write(root.join("refs/heads/main"), format!("{target}\n")).unwrap();
    fs::write(root.join("refs/heads/topic"), format!("{source}\n")).unwrap();
    let request = node.request_context();
    let result = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &request,
            &root,
            principal(),
            b"recovery-import",
        ))
        .unwrap();
    assert!(
        result
            .commands
            .iter()
            .all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    PullRequestCommand {
        number: PullRequestNumber::FIRST,
        expected_version: ExpectedVersion::NewStream,
        action: PullRequestAction::Open,
        data: PullRequestData {
            source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
            target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
            source_tip: source,
            target_tip: target,
            title: "Lost response".into(),
            body: "This body is not needed for lookup".into(),
        },
    }
}

#[test]
fn committed_and_refused_outcomes_recover_after_reopen_without_inputs_or_serving() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (mut node, _) = OneNode::init(scratch.config(format)).unwrap();
        assert_eq!(
            recover(&node, b"not-seen").unwrap(),
            RequestRecovery::KeyNotObserved
        );
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let command = imported(&node, &scratch, format);
        let request = node.request_context();
        let committed = node
            .runtime()
            .block_on(node.admit_pull_request_durable_in(
                &request,
                &session(b"open"),
                &command,
                AdmissionLimits::default(),
            ))
            .unwrap();
        assert!(matches!(
            committed.1.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let refused = node
            .runtime()
            .block_on(node.admit_pull_request_durable_in(
                &request,
                &session(b"stale-open"),
                &command,
                AdmissionLimits::default(),
            ))
            .unwrap();
        assert!(matches!(refused.1.outcome, DecisionOutcome::Refused { .. }));
        let before = head(&node);
        let mut original_principals = Vec::new();
        for (key, expected) in [
            (b"open".as_slice(), committed),
            (b"stale-open".as_slice(), refused),
        ] {
            let result = recover(&node, key).unwrap();
            assert_eq!(result.terminal(), Some(expected.1));
            let original = node
                .runtime()
                .block_on(node.recover_transaction_principal_in(&request, &session(key), &result))
                .unwrap()
                .unwrap();
            assert_eq!(original.principal_id(), principal());
            assert_eq!(
                original.authentication(),
                Some(fgit_admission::evidence::AdmissionAuthentication::OperatorAssertion)
            );
            for method in [
                fgit_admission::evidence::AdmissionAuthentication::HttpToken,
                fgit_admission::evidence::AdmissionAuthentication::SshDeployKey,
            ] {
                let changed_transport = LoopbackReceiveSession::Authenticated(
                    crate::AuthenticatedReceiveSession::new(
                        principal(),
                        IdempotencyKey::new(key.to_vec()).unwrap(),
                    )
                    .with_authentication(method),
                );
                assert_eq!(
                    node.runtime()
                        .block_on(node.recover_transaction_principal_in(
                            &request,
                            &changed_transport,
                            &result,
                        ))
                        .unwrap(),
                    Some(original.clone())
                );
            }
            let other_principal = LoopbackReceiveSession::authenticated(
                PrincipalId::from_bytes([0xd4; 16]),
                IdempotencyKey::new(key.to_vec()).unwrap(),
            );
            for wrong in [other_principal, session(b"different-original-key")] {
                assert!(
                    node.runtime()
                        .block_on(node.recover_transaction_principal_in(&request, &wrong, &result,))
                        .is_err()
                );
                assert_eq!(result.terminal(), Some(expected.1));
            }
            original_principals.push((key.to_vec(), original));
            let RequestRecovery::Recovered(request) = result else {
                panic!("verified result");
            };
            assert_eq!(request.tx_id(), expected.0);
        }
        assert_eq!(head(&node), before);
        drop(command);
        fs::remove_dir_all(scratch.0.join("source")).unwrap();
        node.shutdown().unwrap();
        let reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        // No bring_into_service: new-publication gates must not erase history.
        assert_eq!(
            recover(&reopened, b"open").unwrap().terminal(),
            Some(committed.1)
        );
        assert_eq!(
            recover(&reopened, b"stale-open").unwrap().terminal(),
            Some(refused.1)
        );
        for (key, original) in original_principals {
            let report = recover(&reopened, &key).unwrap();
            let request = reopened.request_context();
            assert_eq!(
                reopened
                    .runtime()
                    .block_on(reopened.recover_transaction_principal_in(
                        &request,
                        &session(&key),
                        &report,
                    ))
                    .unwrap(),
                Some(original)
            );
        }
        assert_eq!(head(&reopened), before);
        reopened.shutdown().unwrap();
    }
}

#[test]
fn principal_history_faults_preserve_their_class_and_the_known_terminal_outcome() {
    use read_fault::{Fault, ReadFault};

    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (mut node, _) = OneNode::init(scratch.config(format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let command = imported(&node, &scratch, format);
        let original_session = session(b"history-read-faults");
        let terminal = node
            .runtime()
            .block_on(node.admit_pull_request_durable_in(
                &node.request_context(),
                &original_session,
                &command,
                AdmissionLimits::default(),
            ))
            .unwrap()
            .1;
        assert!(matches!(
            terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let report = recover(&node, b"history-read-faults").unwrap();
        assert_eq!(report.terminal(), Some(terminal));
        let original = node
            .runtime()
            .block_on(node.recover_transaction_principal_in(
                &node.request_context(),
                &original_session,
                &report,
            ))
            .unwrap()
            .unwrap();
        let before = head(&node);
        let fgit_authority::HeadRead::Present(receipt) = &before else {
            panic!("a real committed decision has an authority head");
        };
        let successor: fgit_codec::RepositoryAuthorityHeadBody =
            fgit_codec::decode_body(receipt.body(), fgit_codec::DecodeLimits::DEFAULT).unwrap();

        // Fail both the predecessor and decision-body read after reaching an
        // already authenticated head. These are real history readers, native
        // contexts and frames; only the exact selected read is intercepted.
        for identity in [
            *successor
                .predecessor_head_id
                .unwrap()
                .as_internal_object_id(),
            *successor.decision_tail_id.unwrap().as_internal_object_id(),
        ] {
            let key = fgit_authority::body_key_for_id(&identity).unwrap();
            for (fault, expected) in [
                (Fault::Cancel, Some(RefusalCode::CancellationInProgress)),
                (Fault::Deadline, Some(RefusalCode::CancellationInProgress)),
                (Fault::Capacity, Some(RefusalCode::ResourceBudgetExceeded)),
                (
                    Fault::Unavailable,
                    Some(RefusalCode::DurabilityProfileUnavailable),
                ),
                (
                    Fault::NoResponse,
                    Some(RefusalCode::ExternalEffectIndeterminate),
                ),
                (Fault::Absent, None),
                (Fault::Corrupt, None),
            ] {
                let store = ReadFault::new(&node, key.clone(), fault);
                let request = node.request_context();
                let error = node
                    .runtime()
                    .block_on(super::principal::history_step_in(
                        &store,
                        request.authority(),
                        &successor,
                        &mut 0,
                        &|| Ok(()),
                    ))
                    .unwrap_err();
                assert!(
                    store.fired(),
                    "selected history read must be reached: {fault:?}"
                );
                match expected {
                    Some(expected) => assert!(
                        matches!(&error, RecoveryFailure::Interrupted(code) if *code == expected),
                        "x2mv.4.51: {fault:?} must retain {expected:?}, got {error:?}"
                    ),
                    None => assert!(
                        matches!(error, RecoveryFailure::Integrity { .. }),
                        "x2mv.4.51 integrity twin: {fault:?} must remain an integrity failure: {error:?}"
                    ),
                }
                assert_eq!(report.terminal(), Some(terminal));
                assert_eq!(head(&node), before, "a provenance read never publishes");
                assert_eq!(
                    node.runtime()
                        .block_on(node.recover_transaction_principal_in(
                            &node.request_context(),
                            &original_session,
                            &report,
                        ))
                        .unwrap(),
                    Some(original.clone()),
                    "permitted twin: retry recovers the original principal without another decision"
                );
            }
        }

        // The history reader only receives a cancellation predicate. Retain
        // the actual caller checkpoint reason when a resource budget ends it.
        let checks = std::sync::atomic::AtomicUsize::new(0);
        let mut walked = 0;
        let request = node.request_context();
        let error = node
            .runtime()
            .block_on(super::principal::history_step_in(
                &node.authority,
                request.authority(),
                &successor,
                &mut walked,
                &|| {
                    if checks.fetch_add(1, Ordering::SeqCst) == 0 {
                        Ok(())
                    } else {
                        Err(RefusalCode::ResourceBudgetExceeded)
                    }
                },
            ))
            .unwrap_err();
        assert_eq!(walked, 1, "the budget expires inside the history step");
        assert!(matches!(
            error,
            RecoveryFailure::Interrupted(RefusalCode::ResourceBudgetExceeded)
        ));

        let mut walked = fgit_authority::MAX_REPLAY_BATCHES;
        let error = node
            .runtime()
            .block_on(super::principal::history_step_in(
                &node.authority,
                request.authority(),
                &successor,
                &mut walked,
                &|| Ok(()),
            ))
            .unwrap_err();
        assert!(matches!(
            error,
            RecoveryFailure::BoundExceeded {
                field: "principal history",
                limit: fgit_authority::MAX_REPLAY_BATCHES,
                observed,
            } if observed == fgit_authority::MAX_REPLAY_BATCHES + 1
        ));
        assert_eq!(report.terminal(), Some(terminal));
        assert_eq!(recover(&node, b"history-read-faults").unwrap(), report);
        node.shutdown().unwrap();
    }
}

#[test]
fn pending_seals_use_real_async_authority_and_wrong_principals_cannot_resolve_them() {
    let scratch = Scratch::new();
    let (node, _) = OneNode::init(scratch.config(GitHashAlgorithm::Sha1)).unwrap();
    let key = IdempotencyKey::new(b"opaque\0\xff\n".to_vec()).unwrap();
    let attempt = SealAttempt {
        tenant_id: node.tenant_id,
        repository_id: node.repository_id,
        authenticated_principal_id: principal(),
        idempotency_key: key.clone(),
        request: SemanticRequest::build(
            fgit_authority::RECEIVE_ADMISSION_SCHEMA,
            GitHashAlgorithm::Sha1,
            true,
            Vec::new(),
            Vec::new(),
            vec![
                fgit_authority::ScopedEntry::new(
                    AsciiSlug::from_static("test"),
                    AsciiSlug::from_static("pending"),
                    b"fixed",
                )
                .unwrap(),
            ],
        )
        .unwrap(),
    };
    let (tx, seal) = attempt.derive().unwrap();
    let request = node.request_context();
    let before = head(&node);
    node.runtime()
        .block_on(bind_idempotency_key_async(
            &node.authority,
            request.authority(),
            &attempt,
            tx,
        ))
        .unwrap();
    assert_eq!(
        recover(&node, key.as_bytes()).unwrap(),
        RequestRecovery::SealNotObserved
    );
    node.runtime()
        .block_on(admit_seal_async(
            &node.authority,
            request.authority(),
            &seal,
        ))
        .unwrap();
    let RequestRecovery::Recovered(found) = recover(&node, key.as_bytes()).unwrap() else {
        panic!("seal");
    };
    assert_eq!(found.tx_id(), tx);
    assert_eq!(found.outcome(), OutcomeLookup::Undecided);
    let wrong = LoopbackReceiveSession::authenticated(PrincipalId::from_bytes([0xd4; 16]), key);
    assert_eq!(
        node.runtime()
            .block_on(node.recover_transaction_in(&request, &wrong))
            .unwrap(),
        RequestRecovery::KeyNotObserved
    );
    assert_eq!(head(&node), before);
    node.shutdown().unwrap();
}

#[test]
fn file_backed_corrupt_binding_and_scope_substitution_are_not_pending_results() {
    for corrupt_binding in [true, false] {
        let scratch = Scratch::new();
        let (node, _) = OneNode::init(scratch.config(GitHashAlgorithm::Sha1)).unwrap();
        let key = IdempotencyKey::new(b"bad-slot".to_vec()).unwrap();
        let attempt = SealAttempt {
            tenant_id: node.tenant_id,
            repository_id: node.repository_id,
            authenticated_principal_id: principal(),
            idempotency_key: key.clone(),
            request: SemanticRequest::build(
                fgit_authority::RECEIVE_ADMISSION_SCHEMA,
                GitHashAlgorithm::Sha1,
                true,
                Vec::new(),
                Vec::new(),
                vec![
                    fgit_authority::ScopedEntry::new(
                        AsciiSlug::from_static("test"),
                        AsciiSlug::from_static("invalid"),
                        b"fixed",
                    )
                    .unwrap(),
                ],
            )
            .unwrap(),
        };
        let (tx, mut seal) = attempt.derive().unwrap();
        let request = node.request_context();
        let before = head(&node);
        if corrupt_binding {
            let slot =
                idempotency_binding_key(node.tenant_id, node.repository_id, principal(), &key)
                    .unwrap();
            node.runtime()
                .block_on(node.authority.put_if_absent(
                    request.authority(),
                    &slot,
                    b"invalid pointer",
                ))
                .unwrap();
        } else {
            node.runtime()
                .block_on(bind_idempotency_key_async(
                    &node.authority,
                    request.authority(),
                    &attempt,
                    tx,
                ))
                .unwrap();
            seal.authenticated_principal_id = PrincipalId::from_bytes([0xd4; 16]);
            let slot = fgit_authority::seal_key(node.tenant_id, node.repository_id, tx).unwrap();
            node.runtime()
                .block_on(node.authority.put_if_absent(
                    request.authority(),
                    &slot,
                    &encode_body(&seal).unwrap(),
                ))
                .unwrap();
        }
        assert!(recover(&node, key.as_bytes()).is_err());
        assert_eq!(head(&node), before);
        node.shutdown().unwrap();
    }
}
