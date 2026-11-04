//! Durable membership prefixes use an explicit capsule declaration. Read
//! accounting isolates closure selection from independent forge/outcome walks.

use super::*;
use crate::outcome_checkpoint::{OutcomeCheckpointLimits, OutcomeCheckpointReceipt};
use fgit_chronicle::{ActivatedCapsule, CapsulePointer, RepositoryCapsuleBody, capsule_identity};
use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_types::RepositoryCapsuleId;

fn checkpoint(node: &OneNode) -> OutcomeCheckpointReceipt {
    let request = node.request_context();
    node.runtime()
        .block_on(node.checkpoint_outcomes_in(&request, OutcomeCheckpointLimits::default()))
        .unwrap()
}

fn capsule(node: &OneNode, id: RepositoryCapsuleId) -> RepositoryCapsuleBody {
    let request = node.request_context();
    let key = body_key_for_id(id.as_internal_object_id()).unwrap();
    let ImmutableRead::Present(bytes) = node
        .runtime()
        .block_on(AsyncAuthorityStore::read_immutable(
            &node.authority,
            request.authority(),
            &key,
        ))
        .unwrap()
    else {
        panic!("selected capsule was staged");
    };
    let body = decode_body(&bytes, fgit_codec::DecodeLimits::DEFAULT).unwrap();
    assert_eq!(capsule_identity(&CryptoBodyIdentity, &body).unwrap(), id);
    body
}

fn stage(node: &OneNode, objects: BTreeSet<GitOid>) -> Digest {
    let request = node.request_context();
    node.runtime()
        .block_on(
            node.admission_materializer
                .stage_permitted_object_closure_in(
                    &node.authority,
                    request.authority(),
                    node.repository_id(),
                    PermittedObjectClosure::new(objects),
                ),
        )
        .unwrap()
}

/// A generic caller still owns the declared profile's publication contract.
/// Legacy cases deliberately supply roots that cannot represent the union;
/// readers must not reinterpret those profiles as the new declaration.
fn activate(node: &OneNode, profile: BackupProfile, root: Digest) -> ActivatedCapsule {
    let current = selected(&cache(), node, &node.authority).unwrap();
    let pointer = current
        .basis()
        .body()
        .last_checkpoint_id
        .map(|id| CapsulePointer::restored_root(id, &capsule(node, id)));
    let request = node.request_context();
    let frozen = node
        .runtime()
        .block_on(freeze_capsule_async(
            &node.authority,
            request.authority(),
            &CryptoBodyIdentity,
            current.authenticated().receipt(),
            pointer.as_ref(),
            CapsuleClosure {
                object_closure_root: root,
                segment_manifest_root: digest_of(0xc4),
                backup_profile: profile,
            },
        ))
        .unwrap();
    node.runtime()
        .block_on(activate_frozen_capsule_async(
            &node.authority,
            request.authority(),
            current.authenticated().receipt(),
            &frozen,
        ))
        .unwrap()
}

fn assert_same_membership(actual: &AuthoritySelectedClosure, expected: &AuthoritySelectedClosure) {
    assert_eq!(actual.root(), expected.root());
    assert_eq!(actual.closure(), expected.closure());
}

#[test]
fn cold_and_reopened_checkpoint_selection_reads_only_the_tail_and_preserves_deleted_objects() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new();
        let (node, _) =
            OneNode::init(test_config(scratch.path().to_path_buf()).with_object_format(format))
                .unwrap();
        let first = add(&node, 0);
        let initial = selected(&cache(), &node, &node.authority).unwrap();
        let old_batch = body_key_for_id(
            initial
                .basis()
                .body()
                .decision_tail_id
                .unwrap()
                .as_internal_object_id(),
        )
        .unwrap();
        let mut objects = BTreeSet::from([first]);
        for index in 1..8 {
            objects.insert(add(&node, index));
        }
        assert!(matches!(
            update(
                &node,
                "delete-prefix",
                "refs/tags/closure-0",
                first,
                zero(&node)
            ),
            DecisionOutcome::Committed { .. }
        ));
        let receipt = checkpoint(&node);
        assert_eq!(
            capsule(&node, receipt.capsule_id).backup_profile,
            BackupProfile::DecisionHistoryWithAdmissionClosureV1
        );
        let warm = cache();
        let at_checkpoint = selected(&warm, &node, &node.authority).unwrap();
        let cold_reads = Observe {
            target: Some(old_batch.clone()),
            fault: Fault::Corrupt,
            ..Observe::new(&node)
        };
        let cold = project(&cache(), &node, &at_checkpoint, &cold_reads);
        assert_same_membership(&cold, &original_walk(&node, &at_checkpoint));
        assert_eq!(cold.closure().objects(), &objects);
        assert_eq!(cold_reads.history_reads(), 0);
        assert_eq!(cold_reads.closure_reads(), 1);
        assert!(!cold_reads.reads.lock().unwrap().contains(&old_batch));
        assert!(matches!(
            cold.source(),
            ClosureSelectionSource::CapsuleCheckpoint {
                capsule,
                latest: Some(_),
                united_roots: 1,
            } if capsule == receipt.capsule_id
        ));

        let removed = add(&node, 8);
        objects.insert(removed);
        objects.insert(add(&node, 9));
        assert!(matches!(
            update(
                &node,
                "delete-tail",
                "refs/tags/closure-8",
                removed,
                zero(&node)
            ),
            DecisionOutcome::Committed { .. }
        ));
        assert!(matches!(
            update(
                &node,
                "reuse-prefix",
                "refs/tags/restored",
                zero(&node),
                first
            ),
            DecisionOutcome::Committed { .. }
        ));
        let uncommitted = put_object(
            &node,
            fgit_git_object::ObjectType::Blob,
            b"uncommitted checkpoint tail".to_vec(),
        );
        assert!(matches!(
            update(
                &node,
                "refused-tail",
                "refs/tags/restored",
                zero(&node),
                uncommitted
            ),
            DecisionOutcome::Refused { .. }
        ));
        let current = selected(&cache(), &node, &node.authority).unwrap();
        let reads = Observe::new(&node);
        let projected = project(&cache(), &node, &current, &reads);
        assert_same_membership(&projected, &original_walk(&node, &current));
        assert_eq!(projected.closure().objects(), &objects);
        assert!(!projected.closure().objects().contains(&uncommitted));
        assert_eq!(
            reads.history_reads(),
            5,
            "refusals also verify their tail edge"
        );
        assert_eq!(
            reads.closure_reads(),
            5,
            "checkpoint plus four distinct tail roots"
        );
        let warm_reads = Observe::new(&node);
        assert_eq!(project(&warm, &node, &current, &warm_reads), projected);
        assert_eq!(warm_reads.history_reads(), 5);
        assert_eq!(warm_reads.closure_reads(), 4);
        node.shutdown().unwrap();

        // Construct fresh configuration/cache ownership as well as reopening
        // durable storage. No warmed service sibling supplies this prefix.
        let reopened = OneNode::open_existing(
            test_config(scratch.path().to_path_buf()).with_object_format(format),
        )
        .unwrap();
        let current = selected(&cache(), &reopened, &reopened.authority).unwrap();
        let reads = Observe::new(&reopened);
        assert_eq!(project(&cache(), &reopened, &current, &reads), projected);
        assert_eq!(reads.history_reads(), 5);
        assert_eq!(reads.closure_reads(), 5);
        reopened.shutdown().unwrap();
    }
}

#[test]
fn legacy_capsule_profiles_never_replace_the_cumulative_history_with_an_opaque_root() {
    let scratch = ScratchDirectory::new();
    let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
    let first = add(&node, 0);
    let second = add(&node, 1);
    let subset = stage(&node, BTreeSet::from([second]));
    let empty = stage(&node, BTreeSet::new());
    let unstaged = digest_of(0xc5);
    for profile in [
        BackupProfile::DecisionHistoryOnly,
        BackupProfile::FullClosure,
        BackupProfile::FullClosureWithRepair,
    ] {
        for root in [subset, empty, unstaged] {
            activate(&node, profile, root);
            let current = selected(&cache(), &node, &node.authority).unwrap();
            let reads = Observe::new(&node);
            let projected = project(&cache(), &node, &current, &reads);
            assert_eq!(projected, original_walk(&node, &current));
            assert_eq!(
                projected.closure().objects(),
                &BTreeSet::from([first, second])
            );
            assert_eq!(reads.history_reads(), 2);
            assert_eq!(reads.closure_reads(), 2);
            if root != subset {
                let key = admission_immutable_key(
                    ADMISSION_CLOSURE_KEY_PREFIX,
                    node.repository_id(),
                    root,
                )
                .unwrap();
                assert!(!reads.reads.lock().unwrap().contains(&key));
            }
        }
    }
    node.shutdown().unwrap();
}

#[test]
fn legacy_capsule_after_a_membership_checkpoint_preserves_its_verified_prefix() {
    let scratch = ScratchDirectory::new();
    let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
    add(&node, 0);
    let retained = checkpoint(&node);
    add(&node, 1);
    let legacy = activate(&node, BackupProfile::DecisionHistoryOnly, digest_of(0xc5));
    let current = selected(&cache(), &node, &node.authority).unwrap();
    let reads = Observe::new(&node);
    let projected = project(&cache(), &node, &current, &reads);
    assert_same_membership(&projected, &original_walk(&node, &current));
    assert_eq!(reads.history_reads(), 1);
    assert_eq!(reads.closure_reads(), 2);
    assert_eq!(reads.count_domain(b"frankengit/repository-capsule/v1"), 2);
    assert!(matches!(
        projected.source(),
        ClosureSelectionSource::CapsuleCheckpoint { capsule, .. }
            if capsule == retained.capsule_id
    ));
    let newest_key =
        body_key_for_id(legacy.pointer().capsule_id().as_internal_object_id()).unwrap();
    for fault in [Fault::Missing, Fault::Corrupt, Fault::Cancel] {
        let reads = Observe {
            target: Some(newest_key.clone()),
            fault,
            ..Observe::new(&node)
        };
        let fresh = cache();
        assert!(selected(&fresh, &node, &reads).is_err());
        assert!(reads.reads.lock().unwrap().contains(&newest_key));
        assert!(fresh.materialized.read().unwrap().is_none());
    }
    node.shutdown().unwrap();
}

#[test]
fn missing_corrupt_wrong_root_or_cancelled_checkpoint_membership_never_uses_an_older_prefix() {
    let scratch = ScratchDirectory::new();
    let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
    add(&node, 0);
    checkpoint(&node);
    let shared = Arc::new(crate::closure_selection::AdmissionClosureCache::default());
    let materializer = DurableAdmissionMaterializer::with_closure_cache(
        admission_cache_scope().unwrap(),
        Arc::clone(&shared),
    );
    let before = selected(&materializer, &node, &node.authority).unwrap();
    add(&node, 1);
    let latest = checkpoint(&node);
    let root = capsule(&node, latest.capsule_id).object_closure_root;
    let target =
        admission_immutable_key(ADMISSION_CLOSURE_KEY_PREFIX, node.repository_id(), root).unwrap();
    for fault in [
        Fault::Missing,
        Fault::Corrupt,
        Fault::WrongClosure,
        Fault::Cancel,
    ] {
        let reads = Observe {
            target: Some(target.clone()),
            fault,
            ..Observe::new(&node)
        };
        let error = selected(&materializer, &node, &reads).unwrap_err();
        assert!(reads.reads.lock().unwrap().contains(&target));
        match fault {
            Fault::Missing => assert!(
                matches!(error, AdmissionMaterializationRefusal::ImmutableAbsent(missing) if missing == root)
            ),
            Fault::Corrupt => assert!(matches!(
                error,
                AdmissionMaterializationRefusal::CanonicalFrame(_)
            )),
            Fault::WrongClosure => assert!(matches!(
                error,
                AdmissionMaterializationRefusal::CanonicalRoot(_)
            )),
            Fault::Cancel => assert!(matches!(error, AdmissionMaterializationRefusal::Cancelled)),
            Fault::None => unreachable!(),
        }
        assert_eq!(
            materializer
                .materialized
                .read()
                .unwrap()
                .as_ref()
                .unwrap()
                .basis,
            *before.basis()
        );
        assert_eq!(shared.read().unwrap().unwrap().basis, *before.basis());
    }
    let recovered = selected(&materializer, &node, &node.authority).unwrap();
    assert_same_membership(
        recovered.selected_closure(),
        &original_walk(&node, &recovered),
    );
    node.shutdown().unwrap();
}

#[test]
fn genesis_and_refusal_only_checkpoints_do_not_invent_a_commit_or_admit_rejected_objects() {
    for refusal in [false, true] {
        let scratch = ScratchDirectory::new();
        let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
        if refusal {
            let unselected = put_object(
                &node,
                fgit_git_object::ObjectType::Blob,
                b"never selected".to_vec(),
            );
            let absent_old = put_object(
                &node,
                fgit_git_object::ObjectType::Blob,
                b"missing expected old".to_vec(),
            );
            assert!(matches!(
                update(
                    &node,
                    "unmatched-old",
                    "refs/tags/missing",
                    absent_old,
                    unselected
                ),
                DecisionOutcome::Refused { .. }
            ));
        }
        let retained = checkpoint(&node);
        let current = selected(&cache(), &node, &node.authority).unwrap();
        let reads = Observe::new(&node);
        let projected = project(&cache(), &node, &current, &reads);
        assert_same_membership(&projected, &original_walk(&node, &current));
        assert!(projected.closure().objects().is_empty());
        assert_eq!(reads.history_reads(), 0);
        assert_eq!(reads.closure_reads(), 1);
        assert!(matches!(
            projected.source(),
            ClosureSelectionSource::CapsuleCheckpoint { capsule, latest: None, united_roots: 1 }
                if capsule == retained.capsule_id
        ));
        let object = add(&node, 0);
        let after = selected(&cache(), &node, &node.authority).unwrap();
        assert_eq!(
            after.selected_closure().closure().objects(),
            &BTreeSet::from([object])
        );
        assert!(matches!(
            after.selected_closure().source(),
            ClosureSelectionSource::CapsuleCheckpoint {
                latest: Some(_),
                ..
            }
        ));
        node.shutdown().unwrap();
    }
}

#[test]
fn a_checkpoint_without_committed_history_cannot_declare_nonempty_admission_membership() {
    let scratch = ScratchDirectory::new();
    let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
    let unselected = put_object(
        &node,
        fgit_git_object::ObjectType::Blob,
        b"unpublished".to_vec(),
    );
    let root = stage(&node, BTreeSet::from([unselected]));
    activate(
        &node,
        BackupProfile::DecisionHistoryWithAdmissionClosureV1,
        root,
    );
    assert!(matches!(
        selected(&cache(), &node, &node.authority),
        Err(
            AdmissionMaterializationRefusal::SelectedCommitStateMismatch {
                field: "checkpoint_object_closure_root"
            }
        )
    ));
    node.shutdown().unwrap();
}

#[test]
fn a_reidentified_membership_capsule_for_another_repository_cannot_terminate_history() {
    let scratch = ScratchDirectory::new();
    let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
    add(&node, 0);
    let retained = checkpoint(&node);
    let materializer = cache();
    let before = selected(&materializer, &node, &node.authority).unwrap();
    let mut body = RepositoryCapsuleBody::at_head(
        before.basis().id(),
        before.basis().body(),
        Some(retained.capsule_id),
        before.selected_closure().root(),
        digest_of(0xc4),
        BackupProfile::DecisionHistoryWithAdmissionClosureV1,
    );
    body.repository_id = fgit_types::RepositoryId::from_bytes([0xf4; 16]);
    let id = capsule_identity(&CryptoBodyIdentity, &body).unwrap();
    let request = node.request_context();
    node.runtime().block_on(async {
        let bytes = fgit_codec::encode_body(&body).unwrap();
        let key = body_key_for_id(id.as_internal_object_id()).unwrap();
        AsyncAuthorityStore::put_if_absent(&node.authority, request.authority(), &key, &bytes)
            .await
            .unwrap();
        let mut head = before.basis().body().clone();
        head.predecessor_head_id = Some(before.basis().id());
        head.generation = head.generation.next().unwrap();
        head.last_checkpoint_id = Some(id);
        let bytes = fgit_codec::encode_body(&head).unwrap();
        let key = body_key(IdentityDomain::RepositoryAuthorityHead, &head).unwrap();
        AsyncAuthorityStore::put_if_absent(&node.authority, request.authority(), &key, &bytes)
            .await
            .unwrap();
        assert!(matches!(
            AsyncAuthorityStore::compare_exchange_head(
                &node.authority,
                request.authority(),
                &node.head_key,
                before.authenticated().receipt().token(),
                head.generation,
                &bytes,
            )
            .await
            .unwrap(),
            CasOutcome::Committed(_)
        ));
    });
    assert!(matches!(
        selected(&materializer, &node, &node.authority),
        Err(AdmissionMaterializationRefusal::CheckpointTransition(_))
    ));
    assert_eq!(
        materializer
            .materialized
            .read()
            .unwrap()
            .as_ref()
            .unwrap()
            .basis,
        *before.basis()
    );
    node.shutdown().unwrap();
}

#[test]
fn source_backup_restores_the_same_checkpoint_union_and_accepts_a_new_tail() {
    let source = ScratchDirectory::new();
    let transport = ScratchDirectory::new();
    let destination = ScratchDirectory::new();
    let (node, _) = OneNode::init(test_config(source.path().to_path_buf())).unwrap();
    let deleted = add(&node, 0);
    add(&node, 1);
    assert!(matches!(
        update(
            &node,
            "backup-delete",
            "refs/tags/closure-0",
            deleted,
            zero(&node)
        ),
        DecisionOutcome::Committed { .. }
    ));
    let retained = checkpoint(&node);
    add(&node, 2);
    let current = selected(&cache(), &node, &node.authority).unwrap();
    let expected = original_walk(&node, &current);
    assert_same_membership(current.selected_closure(), &expected);
    let expected_refs = current.snapshot().refs.clone();
    let tenant = node.tenant_id().to_string();
    let repository = node.repository_id().to_string();
    node.shutdown().unwrap();
    fs::create_dir_all(transport.path()).unwrap();
    let archive = transport.path().join("admission-checkpoint.fgbackup");
    let mut output = Vec::new();
    crate::source_retrieval::backup::run(
        &[
            "export".into(),
            source.path().display().to_string(),
            archive.display().to_string(),
            tenant,
            repository,
            "--trusted-local".into(),
        ],
        &mut output,
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
            "6421".into(),
        ],
        &mut output,
    )
    .unwrap();
    let restored = OneNode::open_existing(test_config(destination.path().to_path_buf())).unwrap();
    let current = selected(&cache(), &restored, &restored.authority).unwrap();
    assert_eq!(current.snapshot().refs, expected_refs);
    assert_same_membership(current.selected_closure(), &expected);
    assert_same_membership(
        current.selected_closure(),
        &original_walk(&restored, &current),
    );
    assert!(restored.read_git_object(deleted).is_ok());
    let reads = Observe::new(&restored);
    let projected = project(&cache(), &restored, &current, &reads);
    assert_eq!(reads.history_reads(), 1);
    assert!(matches!(
        projected.source(),
        ClosureSelectionSource::CapsuleCheckpoint { capsule, .. } if capsule == retained.capsule_id
    ));
    let added = add(&restored, 3);
    let after = selected(&cache(), &restored, &restored.authority).unwrap();
    assert!(
        after
            .selected_closure()
            .closure()
            .objects()
            .contains(&added)
    );
    assert_same_membership(after.selected_closure(), &original_walk(&restored, &after));
    restored.shutdown().unwrap();
}
