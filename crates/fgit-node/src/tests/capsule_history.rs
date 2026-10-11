//! Native checkpoint ancestry: real authority, admission, object fabric and
//! source recovery. Capsules here declare only decision-history coverage;
//! these tests do not claim complete capsule-artifact restoration.

use super::*;

use fgit_authority::{
    AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityVersionToken, CasOutcome,
    HeadKey, HeadReadReceipt, ImmutableKey, MAX_REPLAY_BATCHES, PutOutcome, StoreInstanceId,
    body_key, body_key_for_id,
};
use fgit_chronicle::{
    ActivatedCapsule, BackupProfile, CapsuleClosure, CapsulePointer, CheckpointTransitionRefusal,
    HistoryStep, HistoryStepRefusal, RepositoryCapsuleBody, activate_frozen_capsule_async,
    capsule_identity, freeze_capsule_async, read_history_step_async,
};
use fgit_crypto::{DigestHasher, IdentityDomain, Sha256Hasher};
use fgit_forge::HistoricalBatch;
use fgit_types::HeadGeneration;

fn add_branch(node: &OneNode, name: &str) -> GitOid {
    let blob = put_object(
        node,
        ObjectType::Blob,
        format!("checkpoint fixture {name}\n").into_bytes(),
    );
    let tree = put_tree(node, &[(b"100644", b"file.txt", blob)]);
    let commit = put_commit(node, tree, &[]);
    let objects = BTreeSet::from([blob, tree, commit]);
    let closure = ValidatedClosure {
        object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
            objects.clone(),
        ))
        .unwrap(),
        objects,
    };
    let updates = [SourceRefUpdate {
        old: AnyGitOid::from_hex(
            GitObjectFormat::Sha1,
            "0000000000000000000000000000000000000000",
        )
        .unwrap(),
        new: commit,
        ref_name: format!("refs/heads/{name}").into_bytes(),
    }];
    let receipt = SourceImportReceipt {
        object_format: GitObjectFormat::Sha1,
        object_count: 3,
        delete_only: false,
        origin: SourceImportOrigin::LocalGitDirectory,
    };
    let validated = validate_source_import(&updates, &receipt, closure).unwrap();
    let (mut context, _, _) = evidence_request(node);
    context.idempotency_key =
        fgit_authority::IdempotencyKey::new(format!("checkpoint-{name}").into_bytes()).unwrap();
    let request = node.request_context();
    let result = node
        .runtime()
        .block_on(node.admit_validated_source_import_durable_in(
            &request,
            &context,
            &validated,
            AdmissionLimits::default(),
        ))
        .unwrap();
    assert_eq!(result.commands.len(), 1);
    assert!(matches!(
        result.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    commit
}

fn activate(node: &OneNode, pointer: Option<&CapsulePointer>) -> ActivatedCapsule {
    let request = node.request_context();
    let selected = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    let frozen = node
        .runtime()
        .block_on(freeze_capsule_async(
            &node.authority,
            request.authority(),
            &CryptoBodyIdentity,
            selected.authenticated().receipt(),
            pointer,
            CapsuleClosure {
                object_closure_root: permitted_object_closure_root(
                    selected.selected_closure().closure(),
                )
                .unwrap(),
                // A fixed external segment commitment is part of this reduced
                // decision-history capsule, not a claim that a segment was restored.
                segment_manifest_root: digest_of(0xc4),
                backup_profile: BackupProfile::DecisionHistoryOnly,
            },
        ))
        .unwrap();
    node.runtime()
        .block_on(activate_frozen_capsule_async(
            &node.authority,
            request.authority(),
            selected.authenticated().receipt(),
            &frozen,
        ))
        .unwrap()
}

fn history(node: &OneNode) -> Vec<HistoricalBatch> {
    let request = node.request_context();
    node.runtime()
        .block_on(node.snapshot_history_in(&request))
        .unwrap()
}

#[test]
fn checkpointed_native_genesis_serves_and_accepts_its_first_real_decision() {
    let scratch = ScratchDirectory::new();
    let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
    let checkpoint = activate(&node, None);
    let request = node.request_context();
    let selected = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    assert_eq!(selected.authenticated().receipt(), checkpoint.head());
    assert!(selected.snapshot().refs.is_empty());
    assert!(selected.selected_closure().closure().objects().is_empty());
    assert!(
        history(&node).is_empty(),
        "checkpoint activation invents no decision batch"
    );

    let commit = add_branch(&node, "first-after-empty-checkpoint");
    let batches = history(&node);
    assert_eq!(batches.len(), 1);
    assert_eq!(
        batches[0].batch.predecessor_head_id,
        authority_head_id(
            &decode_body::<RepositoryAuthorityHeadBody>(
                checkpoint.head().body(),
                fgit_codec::DecodeLimits::DEFAULT,
            )
            .unwrap()
        )
        .unwrap()
    );
    let selected = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    assert!(
        selected
            .selected_closure()
            .closure()
            .objects()
            .contains(&commit)
    );
    node.shutdown().unwrap();
}

#[test]
fn native_checkpoint_history_survives_later_admission_reopen_and_source_restore() {
    let scratch = ScratchDirectory::new();
    let transport = ScratchDirectory::new();
    let destination = ScratchDirectory::new();
    fs::create_dir_all(transport.path()).unwrap();
    let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
    let first = add_branch(&node, "before");
    let original = history(&node);
    let checkpoint = activate(&node, None);
    let second_checkpoint = activate(&node, Some(&checkpoint.pointer()));
    assert_eq!(
        history(&node),
        original,
        "both checkpoints preserve every original batch and resulting head identity"
    );
    let second = add_branch(&node, "after");
    let expected_history = history(&node);
    assert_eq!(expected_history.len(), 2);
    assert_eq!(expected_history[0], original[0]);
    let checkpoint_body: RepositoryAuthorityHeadBody = decode_body(
        second_checkpoint.head().body(),
        fgit_codec::DecodeLimits::DEFAULT,
    )
    .unwrap();
    assert_eq!(
        expected_history[1].batch.predecessor_head_id,
        authority_head_id(&checkpoint_body).unwrap()
    );
    let request = node.request_context();
    let selected = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    let expected_head = selected.authenticated().receipt().body().to_vec();
    let expected_refs = selected.snapshot().refs.clone();
    assert!(
        selected
            .selected_closure()
            .closure()
            .objects()
            .contains(&first)
    );
    assert!(
        selected
            .selected_closure()
            .closure()
            .objects()
            .contains(&second)
    );
    let tenant = node.tenant_id().to_string();
    let repository = node.repository_id().to_string();
    node.shutdown().unwrap();

    let reopened = OneNode::open_existing(test_config(scratch.path().to_path_buf())).unwrap();
    assert_eq!(history(&reopened), expected_history);
    reopened.shutdown().unwrap();

    let archive = transport.path().join("checkpoint-source.fgbackup");
    let mut receipt = Vec::new();
    crate::source_retrieval::backup::run(
        &[
            "export".into(),
            scratch.path().display().to_string(),
            archive.display().to_string(),
            tenant,
            repository,
            "--trusted-local".into(),
        ],
        &mut receipt,
    )
    .unwrap();
    let mut hash = Sha256Hasher::new();
    hash.update(&fs::read(&archive).unwrap());
    let checksum = hash
        .finish()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    crate::source_retrieval::backup::run(
        &[
            "restore".into(),
            archive.display().to_string(),
            destination.path().display().to_string(),
            "--trusted-local".into(),
            "--expected-sha256".into(),
            checksum,
            "--destination-instance".into(),
            "6401".into(),
        ],
        &mut receipt,
    )
    .unwrap();
    let restored = OneNode::open_existing(test_config(destination.path().to_path_buf())).unwrap();
    assert_eq!(history(&restored), expected_history);
    let request = restored.request_context();
    let selected = restored
        .runtime()
        .block_on(restored.materialize_admission_in(&request))
        .unwrap();
    assert_eq!(selected.authenticated().receipt().body(), expected_head);
    assert_eq!(selected.snapshot().refs, expected_refs);
    assert!(restored.read_git_object(first).is_ok());
    assert!(restored.read_git_object(second).is_ok());
    restored.shutdown().unwrap();
}

fn publish_raw_head(node: &OneNode, body: &RepositoryAuthorityHeadBody) -> HeadReadReceipt {
    let request = node.request_context();
    let basis = node
        .runtime()
        .block_on(node.authenticate_authority_head_in(&request))
        .unwrap();
    let bytes = fgit_codec::encode_body(body).unwrap();
    let key = body_key(IdentityDomain::RepositoryAuthorityHead, body).unwrap();
    node.runtime()
        .block_on(AsyncAuthorityStore::put_if_absent(
            &node.authority,
            request.authority(),
            &key,
            &bytes,
        ))
        .unwrap();
    let CasOutcome::Committed(receipt) = node
        .runtime()
        .block_on(AsyncAuthorityStore::compare_exchange_head(
            &node.authority,
            request.authority(),
            &node.head_key,
            basis.receipt().token(),
            body.generation,
            &bytes,
        ))
        .unwrap()
    else {
        panic!("test malformed head is published through the real authority slot");
    };
    receipt
}

#[test]
fn native_current_heads_refuse_changed_outcome_state_and_missing_capsule_evidence() {
    for missing_capsule in [false, true] {
        let scratch = ScratchDirectory::new();
        let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
        let checkpoint = activate(&node, None);
        let mut changed: RepositoryAuthorityHeadBody =
            decode_body(checkpoint.head().body(), fgit_codec::DecodeLimits::DEFAULT).unwrap();
        // Construct a new purported checkpoint over the genuine first one.
        let basis_id = authority_head_id(&changed).unwrap();
        let capsule = RepositoryCapsuleBody::at_head(
            basis_id,
            &changed,
            changed.last_checkpoint_id,
            digest_of(0xa1),
            digest_of(0xa2),
            BackupProfile::DecisionHistoryOnly,
        );
        let capsule_id = capsule_identity(&CryptoBodyIdentity, &capsule).unwrap();
        if !missing_capsule {
            let request = node.request_context();
            node.runtime()
                .block_on(AsyncAuthorityStore::put_if_absent(
                    &node.authority,
                    request.authority(),
                    &body_key_for_id(capsule_id.as_internal_object_id()).unwrap(),
                    &fgit_codec::encode_body(&capsule).unwrap(),
                ))
                .unwrap();
        }
        changed.predecessor_head_id = Some(basis_id);
        changed.generation = changed.generation.next().unwrap();
        changed.last_checkpoint_id = Some(capsule_id);
        if !missing_capsule {
            changed.outcome_index_root = digest_of(0xfe);
        }
        publish_raw_head(&node, &changed);
        let request = node.request_context();
        let refused = node
            .runtime()
            .block_on(node.materialize_admission_in(&request));
        if missing_capsule {
            assert!(matches!(
                refused,
                Err(AdmissionMaterializationRefusal::ImmutableAbsent(_))
            ));
        } else {
            assert!(
                matches!(refused, Err(AdmissionMaterializationRefusal::CheckpointTransition(error))
                if matches!(*error, CheckpointTransitionRefusal::HeadMismatch))
            );
        }
        assert!(
            node.runtime()
                .block_on(node.snapshot_history_in(&request))
                .is_err()
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn native_reader_keeps_the_full_decision_pair_verifier_after_checkpoint_support() {
    let scratch = ScratchDirectory::new();
    let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
    add_branch(&node, "ordinary-decision");
    assert_eq!(history(&node).len(), 1);
    let request = node.request_context();
    let selected = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    let mut malformed = selected.basis().body().clone();
    // Its retained predecessor has a different tail, so this must still take
    // the decision verifier, which rejects the forged successor generation.
    malformed.generation = malformed.generation.next().unwrap();
    publish_raw_head(&node, &malformed);
    assert!(matches!(
        node.runtime().block_on(node.snapshot_history_in(&request)),
        Err(AdmissionMaterializationRefusal::DecisionHistoryVerification(_))
    ));
    node.shutdown().unwrap();
}

#[test]
fn checkpoint_edges_consume_the_same_bounded_native_history_budget() {
    let scratch = ScratchDirectory::new();
    let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
    let first = activate(&node, None);
    let second = activate(&node, Some(&first.pointer()));
    let head: RepositoryAuthorityHeadBody =
        decode_body(second.head().body(), fgit_codec::DecodeLimits::DEFAULT).unwrap();
    let request = node.request_context();
    let live = || false;
    let mut walked = 0;
    let HistoryStep::Checkpoint { predecessor } = node
        .runtime()
        .block_on(read_history_step_async(
            &node.authority,
            request.authority(),
            &head,
            &mut walked,
            1,
            &live,
        ))
        .unwrap()
    else {
        panic!("the first edge is a real checkpoint");
    };
    assert_eq!(walked, 1);
    assert!(matches!(
        node.runtime().block_on(read_history_step_async(
            &node.authority,
            request.authority(),
            predecessor.body(),
            &mut walked,
            1,
            &live,
        )),
        Err(HistoryStepRefusal::BoundExceeded { limit: 1 })
    ));
    let mut ceiling = MAX_REPLAY_BATCHES;
    assert!(matches!(
        node.runtime().block_on(read_history_step_async(
            &node.authority,
            request.authority(),
            &head,
            &mut ceiling,
            usize::MAX,
            &live,
        )),
        Err(HistoryStepRefusal::BoundExceeded {
            limit: MAX_REPLAY_BATCHES
        })
    ));
    node.shutdown().unwrap();
}

/// Inject cancellation only AFTER one actual native immutable read completes.
/// All storage and receipt authentication still use the real node authority.
struct CancelAfterRead<'a> {
    node: &'a OneNode,
    target: ImmutableKey,
}

impl AsyncAuthorityStore for CancelAfterRead<'_> {
    type Context = FsqliteCx;
    fn instance_id(&self) -> StoreInstanceId {
        AsyncAuthorityStore::instance_id(&self.node.authority)
    }
    fn limits(&self) -> AuthorityLimits {
        AsyncAuthorityStore::limits(&self.node.authority)
    }
    async fn put_if_absent(
        &self,
        cx: &FsqliteCx,
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        AsyncAuthorityStore::put_if_absent(&self.node.authority, cx, key, body).await
    }
    async fn read_immutable(
        &self,
        cx: &FsqliteCx,
        key: &ImmutableKey,
    ) -> Result<ImmutableRead, AuthorityFailure> {
        let read = AsyncAuthorityStore::read_immutable(&self.node.authority, cx, key).await;
        if *key == self.target {
            cx.cancel();
        }
        read
    }
    async fn initialize_head(
        &self,
        cx: &FsqliteCx,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, AuthorityFailure> {
        AsyncAuthorityStore::initialize_head(&self.node.authority, cx, key, generation, body).await
    }
    async fn read_head(&self, cx: &FsqliteCx, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        AsyncAuthorityStore::read_head(&self.node.authority, cx, key).await
    }
    async fn compare_exchange_head(
        &self,
        cx: &FsqliteCx,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        AsyncAuthorityStore::compare_exchange_head(
            &self.node.authority,
            cx,
            key,
            expected,
            generation,
            body,
        )
        .await
    }
    async fn authenticate_head_receipt(
        &self,
        cx: &FsqliteCx,
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure> {
        AsyncAuthorityStore::authenticate_head_receipt(&self.node.authority, cx, receipt).await
    }
}

#[test]
fn cancellation_after_present_or_absent_capsule_reads_is_not_recast_as_bad_evidence() {
    for absent in [false, true] {
        let scratch = ScratchDirectory::new();
        let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
        let checkpoint = activate(&node, None);
        let mut head: RepositoryAuthorityHeadBody =
            decode_body(checkpoint.head().body(), fgit_codec::DecodeLimits::DEFAULT).unwrap();
        if absent {
            head.last_checkpoint_id = Some(fgit_codec::harness::capsule_id());
            head.generation = head.generation.next().unwrap();
            publish_raw_head(&node, &head);
        }
        let target =
            body_key_for_id(head.last_checkpoint_id.unwrap().as_internal_object_id()).unwrap();
        let fault = CancelAfterRead {
            node: &node,
            target,
        };
        let request = node.request_context();
        let cancelled = || request.authority().checkpoint().is_err();
        let mut walked = 0;
        assert!(matches!(
            node.runtime().block_on(read_history_step_async(
                &fault,
                request.authority(),
                &head,
                &mut walked,
                2,
                &cancelled,
            )),
            Err(HistoryStepRefusal::Cancelled)
        ));
        assert_eq!(walked, 1);
        node.shutdown().unwrap();
    }
}
