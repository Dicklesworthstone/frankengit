//! Deterministic interleavings against the real embedded authority/projection.
//! Only the injected unavailability and unrelated delete-only test request are
//! synthetic. The main session goes through native production quarantine.

use std::collections::BTreeSet;
use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use fgit_admission::policy_bridge::receive_session;
use fgit_admission::{
    AdmissionContext, AdmissionError, AdmissionLimits, AdmissionSnapshot, AsyncAdmissionProjection,
    BasisBoundValidatedReceive, CommitMaterialization, PermittedObjectClosure, ProjectionFailure,
    QuarantineValidator, RefusalMaterialization, ValidatedClosure, permitted_object_closure_root,
    validate_receive_at_basis,
};
use fgit_authority::{AuthenticatedHead, IdempotencyKey};
use fgit_chronicle::PublicationBasis;
use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest, sha256_digest};
use fgit_git_object::ParseLimits;
use fgit_pack::{PackLimits, QuarantinedPack};
use fgit_reference::intent::TransactionRequest;
use fgit_txn::TransactionFoldReport;
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, PrincipalId, RefName, RefusalCode, RepositoryId,
    TenantId, TxId,
};
use fgit_wire::receive::{QuarantineReceipt, ReceiveCommand, ReceivePack, ReceiveRequest};
use fgit_wire::{Packet, WireLimits, encode_packets};

use crate::{
    DurableAdmissionMaterializer, DurableAsyncAdmissionProjection, FsqliteAuthorityStore,
    FsqliteCx, NodeConfig, OneNode, ProductionReceiveQuarantineHandoff,
};

static NEXT: AtomicU64 = AtomicU64::new(1);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "fg-receive-session-fault-{}-{}",
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
fn node(root: &Scratch, format: GitHashAlgorithm) -> OneNode {
    let (mut node, _) = OneNode::init(
        NodeConfig::new(
            root.0.clone(),
            TenantId::from_bytes([0xe1; 16]),
            RepositoryId::from_bytes([0xe2; 16]),
        )
        .with_object_format(format),
    )
    .unwrap();
    node.bring_into_service(fgit_types::HeadGeneration::FIRST)
        .unwrap();
    node
}
fn context(node: &OneNode) -> AdmissionContext {
    AdmissionContext {
        head_key: node.head_key.clone(),
        tenant_id: node.tenant_id,
        repository_id: node.repository_id,
        object_format: node.object_format,
        principal_id: PrincipalId::from_bytes([0xe3; 16]),
        idempotency_key: IdempotencyKey::new(b"two-ref-session".to_vec()).unwrap(),
    }
}
fn native_receive(node: &OneNode) -> BasisBoundValidatedReceive {
    let format = node.object_format;
    let blob = b"x";
    let oid = git_object_id(format, GitObjectKind::Blob, blob);
    let zero = "0".repeat(oid.as_bytes().len() * 2);
    let mut pack = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
    // One one-byte blob, in a final stored DEFLATE block.
    pack.extend_from_slice(&[
        0x31, 0x78, 0x01, 0x01, 1, 0, 0xfe, 0xff, b'x', 0, 121, 0, 121,
    ]);
    let trailer = match format {
        GitHashAlgorithm::Sha1 => sha1_digest(&pack).to_vec(),
        GitHashAlgorithm::Sha256 => sha256_digest(&pack).to_vec(),
    };
    pack.extend_from_slice(&trailer);
    let mut body = encode_packets(
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
    body.extend_from_slice(&pack);
    let selected = node.runtime.block_on(node.materialize_admission()).unwrap();
    let validator = node
        .production_quarantine_validator(&selected, PackLimits::default(), ParseLimits::default())
        .unwrap();
    let mut handoff = ProductionReceiveQuarantineHandoff::new(validator, selected.basis().clone());
    let mut receive = ReceivePack::new(
        node.smart_http_receive_context(WireLimits::default())
            .unwrap(),
    )
    .unwrap();
    receive.push_bytes(&body).unwrap();
    receive
        .finish_with_handoff(&mut handoff, &mut || true)
        .unwrap();
    handoff.into_validated_receive().unwrap()
}

// A delete-only request needs no incoming or external object closure. This
// validator is only for the deliberately unrelated test writer, not the main
// receive whose native pack is validated above.
struct DeleteOnly;
impl QuarantineValidator for DeleteOnly {
    fn validate(
        &self,
        request: &ReceiveRequest,
        pack: Option<&QuarantinedPack>,
        receipt: &QuarantineReceipt,
        _: &mut impl fgit_pack::Deadline,
    ) -> Result<ValidatedClosure, RefusalCode> {
        assert!(request.deletes_only() && receipt.delete_only && pack.is_none());
        Ok(ValidatedClosure {
            object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::default())
                .unwrap(),
            objects: BTreeSet::new(),
        })
    }
}
async fn publish_unrelated_refusal(
    authority: &FsqliteAuthorityStore,
    cx: &FsqliteCx,
    materializer: &DurableAdmissionMaterializer,
    context: &AdmissionContext,
    basis: &PublicationBasis,
) {
    let mut foreign = context.clone();
    foreign.idempotency_key = IdempotencyKey::new(b"unrelated-writer".to_vec()).unwrap();
    let format = context.object_format;
    let width = format.digest_len() * 2;
    let request = ReceiveRequest {
        commands: vec![ReceiveCommand {
            old: GitOid::from_hex(format, &"1".repeat(width)).unwrap(),
            new: GitOid::from_hex(format, &"0".repeat(width)).unwrap(),
            ref_name: b"refs/tags/unrelated-missing".to_vec(),
        }],
        capabilities: Vec::new(),
        push_options: Vec::new(),
        certificate: None,
    };
    let receipt = QuarantineReceipt {
        object_format: format,
        object_count: 0,
        pack_bytes: 0,
        delete_only: true,
    };
    let validated =
        validate_receive_at_basis(&request, None, &receipt, basis, &DeleteOnly, &mut || true)
            .unwrap();
    let projection = DurableAsyncAdmissionProjection::new(materializer, foreign.clone());
    let result = receive_session::admit(
        authority,
        cx,
        &foreign,
        &validated,
        AdmissionLimits::default(),
        &projection,
    )
    .await
    .unwrap();
    assert!(matches!(
        result.commands[0].terminal.outcome,
        DecisionOutcome::Refused {
            code: RefusalCode::ExpectedOldRefMismatch,
            ..
        }
    ));
}

#[derive(Clone, Copy)]
enum Mode {
    InterruptSecondSnapshot,
    RaceSecondCommit,
}
struct Probe<'a> {
    inner: DurableAsyncAdmissionProjection<'a>,
    materializer: &'a DurableAdmissionMaterializer,
    context: AdmissionContext,
    snapshots: AtomicUsize,
    commits: AtomicUsize,
    mode: Mode,
}
impl<'a> Probe<'a> {
    fn new(node: &'a OneNode, context: &AdmissionContext, mode: Mode) -> Self {
        Self {
            inner: node.durable_admission_projection(context).unwrap(),
            materializer: &node.admission_materializer,
            context: context.clone(),
            snapshots: AtomicUsize::new(0),
            commits: AtomicUsize::new(0),
            mode,
        }
    }
}
impl AsyncAdmissionProjection<FsqliteAuthorityStore> for Probe<'_> {
    fn snapshot_async<'a>(
        &'a self,
        authority: &'a FsqliteAuthorityStore,
        cx: &'a FsqliteCx,
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
    ) -> impl Future<Output = Result<AdmissionSnapshot, ProjectionFailure>> + Send + 'a {
        async move {
            let index = self.snapshots.fetch_add(1, Ordering::SeqCst);
            if matches!(self.mode, Mode::InterruptSecondSnapshot) && index == 1 {
                return Err(ProjectionFailure::Unavailable(
                    RefusalCode::DurabilityProfileUnavailable,
                ));
            }
            self.inner
                .snapshot_async(authority, cx, basis, authenticated)
                .await
        }
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
        async move {
            let prepared = self
                .inner
                .materialize_commit_async(authority, cx, basis, request, fold, closure)
                .await?;
            let index = self.commits.fetch_add(1, Ordering::SeqCst);
            if matches!(self.mode, Mode::RaceSecondCommit) && index == 1 {
                // The second candidate is staged but has not attempted CAS.
                // Advance the real head now, forcing its next CAS to lose.
                publish_unrelated_refusal(authority, cx, self.materializer, &self.context, basis)
                    .await;
            }
            Ok(prepared)
        }
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
fn assert_only_first(node: &OneNode) {
    let selected = node.runtime.block_on(node.materialize_admission()).unwrap();
    assert_eq!(selected.snapshot().refs.len(), 1);
    assert!(
        selected
            .snapshot()
            .refs
            .contains_key(&RefName::try_new(b"refs/tags/first").unwrap())
    );
    assert!(
        !selected
            .snapshot()
            .refs
            .contains_key(&RefName::try_new(b"refs/tags/second").unwrap())
    );
}

#[test]
fn interrupted_second_command_preserves_first_outcome_and_stable_retry_mapping() {
    use fgit_admission::policy_bridge::receive_session::recovery::SessionRecovery;
    use fgit_authority::OutcomeLookup;
    use fgit_authority::key_recovery::RequestRecovery;

    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        let context = context(&node);
        let validated = native_receive(&node);
        let request = node.request_context();
        let projection = Probe::new(&node, &context, Mode::InterruptSecondSnapshot);
        let error = node
            .runtime
            .block_on(receive_session::admit(
                &node.authority,
                request.authority(),
                &context,
                &validated,
                AdmissionLimits::default(),
                &projection,
            ))
            .unwrap_err();
        assert_eq!(error.completed_commands().len(), 1);
        assert!(matches!(
            error.completed_commands()[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert_eq!(error.session().unwrap().tx_ids.len(), 2);
        assert!(matches!(
            error.admission_error(),
            AdmissionError::AsyncProjectionUnavailable(RefusalCode::DurabilityProfileUnavailable)
        ));
        assert_only_first(&node);
        let before_retry = node
            .runtime
            .block_on(node.materialize_admission())
            .unwrap()
            .basis()
            .generation();
        drop(projection);

        // Query only the original key: neither the command list nor the pack
        // is supplied to recovery. The real first commit must not conceal the
        // real sealed-but-undecided second command, or make the session complete.
        let session = crate::LoopbackReceiveSession::authenticated(
            context.principal_id,
            context.idempotency_key.clone(),
        );
        let observed = node
            .runtime
            .block_on(node.recover_receive_session_in(&node.request_context(), &session))
            .unwrap();
        let SessionRecovery::Recovered(partial) = observed else {
            panic!("intake persisted the complete shape")
        };
        assert_eq!(partial.commands().len(), 2);
        assert!(!partial.all_terminal());
        assert_eq!(
            partial.commands()[0].recovery().terminal(),
            Some(error.completed_commands()[0].terminal)
        );
        assert!(
            matches!(partial.commands()[1].recovery(), RequestRecovery::Recovered(known)
            if known.outcome() == OutcomeLookup::Undecided)
        );
        assert_eq!(
            node.runtime
                .block_on(node.materialize_admission())
                .unwrap()
                .basis()
                .generation(),
            before_retry
        );

        let projection = node.durable_admission_projection(&context).unwrap();
        let retried = node
            .runtime
            .block_on(receive_session::admit(
                &node.authority,
                node.request_context().authority(),
                &context,
                &validated,
                AdmissionLimits::default(),
                &projection,
            ))
            .unwrap();
        assert_eq!(&retried.session, error.session().unwrap());
        assert_eq!(retried.commands[0], error.completed_commands()[0]);
        assert!(matches!(
            retried.commands[1].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let after = node.runtime.block_on(node.materialize_admission()).unwrap();
        assert_eq!(after.basis().generation().get(), before_retry.get() + 1);
        assert_eq!(after.snapshot().refs.len(), 2);
        let SessionRecovery::Recovered(complete) = node
            .runtime
            .block_on(node.recover_receive_session_in(&node.request_context(), &session))
            .unwrap()
        else {
            panic!("same persisted shape must recover after retry")
        };
        assert!(complete.all_terminal());
        assert_eq!(complete.identity(), partial.identity());
        for (observed, admitted) in complete.commands().iter().zip(&retried.commands) {
            assert_eq!(observed.recovery().terminal(), Some(admitted.terminal));
        }
        assert_eq!(
            node.runtime
                .block_on(node.materialize_admission())
                .unwrap()
                .basis()
                .generation(),
            after.basis().generation()
        );
        drop(projection);
        node.shutdown().unwrap();
    }
}

#[test]
fn a_lost_second_cas_cannot_publish_under_an_unrelated_successor() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        let context = context(&node);
        let validated = native_receive(&node);
        let projection = Probe::new(&node, &context, Mode::RaceSecondCommit);
        let request = node.request_context();
        let result = node
            .runtime
            .block_on(receive_session::admit(
                &node.authority,
                request.authority(),
                &context,
                &validated,
                AdmissionLimits::default(),
                &projection,
            ))
            .unwrap();
        assert_eq!(projection.commits.load(Ordering::SeqCst), 2);
        assert!(matches!(
            result.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert!(matches!(
            result.commands[1].terminal.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::AuthorityReceiptStale,
                ..
            }
        ));
        assert_only_first(&node);
        drop(projection);
        node.shutdown().unwrap();
    }
}

#[test]
fn recovering_an_old_commit_does_not_unlock_an_unrelated_head_for_later_refs() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for refresh_validation in [false, true] {
            let scratch = Scratch::new();
            let node = node(&scratch, format);
            let context = context(&node);
            let original = native_receive(&node);
            let projection = Probe::new(&node, &context, Mode::InterruptSecondSnapshot);
            let request = node.request_context();
            let interrupted = node
                .runtime
                .block_on(receive_session::admit(
                    &node.authority,
                    request.authority(),
                    &context,
                    &original,
                    AdmissionLimits::default(),
                    &projection,
                ))
                .unwrap_err();
            drop(projection);
            // Exercise both proof positions. With fresh validation, the foreign
            // head below is an IMMEDIATE successor of the permitted head. Only
            // checking predecessor/generation would mistakenly authorize it;
            // the prior command's exact terminal decision must also match.
            let validated = if refresh_validation {
                native_receive(&node)
            } else {
                original
            };
            let own_head = node.runtime.block_on(node.materialize_admission()).unwrap();
            node.runtime.block_on(publish_unrelated_refusal(
                &node.authority,
                request.authority(),
                &node.admission_materializer,
                &context,
                own_head.basis(),
            ));
            let projection = node.durable_admission_projection(&context).unwrap();
            let result = node
                .runtime
                .block_on(receive_session::admit(
                    &node.authority,
                    request.authority(),
                    &context,
                    &validated,
                    AdmissionLimits::default(),
                    &projection,
                ))
                .unwrap();
            assert_eq!(result.commands[0], interrupted.completed_commands()[0]);
            if refresh_validation {
                // Validated at the head the first command produced. The
                // foreign decision since then changed nothing a receive
                // validator derives from a basis (permitted closure, visible
                // roots, configuration, retention, epochs, checkpoint), so
                // the witness's authority commitment equals the new head's:
                // the command revalidates and commits instead of being
                // refused as stale (section 5.2, x2mv.4.27).
                assert!(matches!(
                    result.commands[1].terminal.outcome,
                    DecisionOutcome::Committed { .. }
                ));
                let selected = node.runtime.block_on(node.materialize_admission()).unwrap();
                assert_eq!(selected.snapshot().refs.len(), 2);
            } else {
                // Validated before the first command moved a ref: the new
                // head's visible roots differ from the witness's, so its
                // commitment differs and the old evidence stays refused.
                assert!(matches!(
                    result.commands[1].terminal.outcome,
                    DecisionOutcome::Refused {
                        code: RefusalCode::AuthorityReceiptStale,
                        ..
                    }
                ));
                assert_only_first(&node);
            }
            drop(projection);
            node.shutdown().unwrap();
        }
    }
}
