//! Public maintenance API against native authority, object fabric and forge
//! operations. Checkpoints must preserve terminal facts and publish root last.

use super::*;

use crate::outcome_checkpoint::{
    OutcomeCheckpointLimits, OutcomeCheckpointReceipt, OutcomeCheckpointRefusal,
};
use crate::{LoopbackReceiveSession, MaterializedAdmission};
use fgit_admission::CommandOutcome;
use fgit_authority::{CumulativeOutcomes, IdempotencyKey, TerminalOutcome, body_key_for_id};
use fgit_chronicle::{
    BackupProfile, CapsuleClosure, CapsulePointer, OutcomeIndexCheckpointBody,
    RepositoryCapsuleBody, activate_frozen_capsule_async, capsule_identity, freeze_capsule_async,
    load_verified_outcome_index_checkpoint_async, outcome_index_leaf_archive_namespace,
};
use fgit_codec::RepositoryDecision;
use fgit_forge::aggregate::{ExpectedVersion, PullRequestNumber};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_resource::{Grade, LeakDisposition, ObligationLedger, RegionId, ResourceVector};
use fgit_types::{HeadGeneration, RepositoryCapsuleId};
use fgit_wire::visibility::RefVisibility;

fn zero(node: &OneNode) -> GitOid {
    GitOid::from_hex(
        node.object_format(),
        &"00".repeat(match node.object_format() {
            GitHashAlgorithm::Sha1 => 20,
            GitHashAlgorithm::Sha256 => 32,
        }),
    )
    .unwrap()
}

fn import_ref(
    node: &OneNode,
    key: &str,
    name: &str,
    old: GitOid,
    new: GitOid,
    objects: &BTreeSet<GitOid>,
) -> CommandOutcome {
    let closure = PermittedObjectClosure::new(objects.clone());
    let validated = validate_source_import(
        &[SourceRefUpdate {
            old,
            new,
            ref_name: name.as_bytes().to_vec(),
        }],
        &SourceImportReceipt {
            object_format: node.object_format(),
            object_count: u32::try_from(objects.len()).unwrap(),
            delete_only: new.is_zero(),
            origin: SourceImportOrigin::LocalGitDirectory,
        },
        ValidatedClosure {
            objects: objects.clone(),
            object_closure_root: permitted_object_closure_root(&closure).unwrap(),
        },
    )
    .unwrap();
    let (mut context, _, _) = evidence_request(node);
    context.idempotency_key = IdempotencyKey::new(key.as_bytes().to_vec()).unwrap();
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
    result.commands[0]
}

fn branch_objects(node: &OneNode, label: &str) -> (GitOid, BTreeSet<GitOid>) {
    let blob = put_object(node, ObjectType::Blob, format!("{label}\n").into_bytes());
    let tree = put_tree(node, &[(b"100644", b"file.txt", blob)]);
    let commit = put_commit(node, tree, &[]);
    (commit, BTreeSet::from([blob, tree, commit]))
}

fn add_tag(node: &OneNode, index: usize) -> CommandOutcome {
    let object = put_object(
        node,
        ObjectType::Blob,
        format!("maintenance outcome {index}\n").into_bytes(),
    );
    let result = import_ref(
        node,
        &format!("maintenance-{index}"),
        &format!("refs/tags/maintenance-{index}"),
        zero(node),
        object,
        &BTreeSet::from([object]),
    );
    assert!(matches!(
        result.terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    result
}

fn apply_pull_request(
    node: &OneNode,
    command: &PullRequestCommand,
    key: &str,
) -> (TxId, TerminalOutcome) {
    let request = node.request_context();
    let session = LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0x44; 16]),
        IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
    );
    node.runtime()
        .block_on(node.admit_pull_request_durable_in(
            &request,
            &session,
            command,
            AdmissionLimits::default(),
        ))
        .unwrap()
}

fn selected(node: &OneNode) -> MaterializedAdmission {
    let request = node.request_context();
    node.runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap()
}

fn maintain(
    node: &OneNode,
    limits: OutcomeCheckpointLimits,
) -> Result<OutcomeCheckpointReceipt, OutcomeCheckpointRefusal> {
    let request = node.request_context();
    node.runtime()
        .block_on(node.checkpoint_outcomes_in(&request, limits))
}

fn checkpoint(node: &OneNode) -> OutcomeCheckpointReceipt {
    maintain(node, OutcomeCheckpointLimits::default()).unwrap()
}

fn full_decisions(node: &OneNode) -> Vec<RepositoryDecision> {
    let request = node.request_context();
    let outcomes = node
        .runtime()
        .block_on(collect_cumulative_outcomes_async(
            &node.authority,
            request.authority(),
            &node.head_key,
        ))
        .unwrap();
    outcomes
        .checkpoint_decisions_against(outcomes.observed())
        .unwrap()
}

fn collected(node: &OneNode) -> CumulativeOutcomes {
    let selected = selected(node);
    let (context, _, _) = evidence_request(node);
    let projection = node.durable_admission_projection(&context).unwrap();
    let request = node.request_context();
    let outcomes = node
        .runtime()
        .block_on(projection.collect_cumulative_outcomes_async(
            &node.authority,
            request.authority(),
            &node.head_key,
            selected.authenticated(),
        ))
        .unwrap();
    assert_eq!(
        outcomes.observed(),
        selected.authenticated().receipt().token()
    );
    outcomes
}

fn assert_decisions(node: &OneNode, expected: &[RepositoryDecision]) {
    let outcomes = collected(node);
    assert_eq!(
        outcomes
            .checkpoint_decisions_against(outcomes.observed())
            .unwrap(),
        expected
    );
    assert_eq!(full_decisions(node), expected);
}

fn retained(node: &OneNode, root: Digest) -> (OutcomeIndexCheckpointBody, Vec<RepositoryDecision>) {
    let request = node.request_context();
    node.runtime()
        .block_on(load_verified_outcome_index_checkpoint_async(
            &node.authority,
            request.authority(),
            &CryptoBodyIdentity,
            &node.outcome_checkpoint_fabric,
            root,
        ))
        .unwrap()
}

fn capsule(node: &OneNode, id: RepositoryCapsuleId) -> RepositoryCapsuleBody {
    let request = node.request_context();
    let key = body_key_for_id(id.as_internal_object_id()).unwrap();
    let ImmutableRead::Present(bytes) = node
        .runtime()
        .block_on(node.authority.read_immutable(request.authority(), &key))
        .unwrap()
    else {
        panic!("published capsule must be retained");
    };
    let body = decode_body(&bytes, fgit_codec::DecodeLimits::DEFAULT).unwrap();
    assert_eq!(capsule_identity(&CryptoBodyIdentity, &body).unwrap(), id);
    body
}

fn history(node: &OneNode) -> Vec<fgit_forge::HistoricalBatch> {
    let request = node.request_context();
    node.runtime()
        .block_on(node.snapshot_history_in(&request))
        .unwrap()
}

fn assert_only_checkpoint_changed(
    before: &MaterializedAdmission,
    after: &MaterializedAdmission,
    receipt: &OutcomeCheckpointReceipt,
) {
    assert!(receipt.published);
    assert_eq!(receipt.source_head, before.basis().id());
    assert_eq!(receipt.published_head, after.basis().id());
    assert_eq!(receipt.generation, after.basis().generation());
    assert_eq!(
        after.basis().generation().get(),
        before.basis().generation().get() + 1
    );
    let mut expected = before.basis().body().clone();
    expected.generation = after.basis().generation();
    expected.predecessor_head_id = Some(before.basis().id());
    expected.last_checkpoint_id = Some(receipt.capsule_id);
    assert_eq!(after.basis().body(), &expected);
    assert_eq!(after.snapshot(), before.snapshot());
    assert_eq!(
        after.selected_closure().closure(),
        before.selected_closure().closure()
    );
}

#[test]
fn native_source_forge_refusals_and_retries_survive_checkpoint_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf())
            .with_object_format(format)
            .with_worker_threads(2);
        let (mut node, _) = OneNode::init(config).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let (target, target_objects) = branch_objects(&node, "target");
        let (source, source_objects) = branch_objects(&node, "source");
        let target_outcome = import_ref(
            &node,
            "target",
            "refs/heads/main",
            zero(&node),
            target,
            &target_objects,
        );
        let source_outcome = import_ref(
            &node,
            "source",
            "refs/heads/topic",
            zero(&node),
            source,
            &source_objects,
        );
        for outcome in [target_outcome, source_outcome] {
            assert!(matches!(
                outcome.terminal.outcome,
                DecisionOutcome::Committed { .. }
            ));
        }
        let command = PullRequestCommand {
            number: PullRequestNumber::try_new(7).unwrap(),
            expected_version: ExpectedVersion::NewStream,
            action: PullRequestAction::Open,
            data: PullRequestData {
                source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
                target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
                source_tip: source,
                target_tip: target,
                title: "Retain native forge history".into(),
                body: "Checkpointing preserves the original PR event.".into(),
            },
        };
        let opening = apply_pull_request(&node, &command, "open-pr");
        assert!(matches!(
            opening.1.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let refused = import_ref(
            &node,
            "stale-ref",
            "refs/heads/main",
            zero(&node),
            source,
            &source_objects,
        );
        assert!(matches!(
            refused.terminal.outcome,
            DecisionOutcome::Refused { .. }
        ));
        let before = selected(&node);
        let expected_history = history(&node);
        let expected_decisions = full_decisions(&node);
        assert_eq!(expected_decisions.len(), 4);
        let request = node.request_context();
        let before_page = node
            .runtime()
            .block_on(node.read_pull_requests_in(&request, &RefVisibility::new(), 0, 10, None))
            .unwrap();
        assert_eq!(before_page.pull_requests.len(), 1);

        let receipt = maintain(
            &node,
            OutcomeCheckpointLimits {
                expected_head: Some(before.basis().id()),
                ..OutcomeCheckpointLimits::default()
            },
        )
        .unwrap();
        let after = selected(&node);
        assert_only_checkpoint_changed(&before, &after, &receipt);
        assert_eq!(receipt.decisions, 4);
        assert!(receipt.leaf_objects > 0);
        assert!(receipt.leaf_bytes > 0);
        assert_eq!(history(&node), expected_history);
        assert_decisions(&node, &expected_decisions);
        let after_page = node
            .runtime()
            .block_on(node.read_pull_requests_in(&request, &RefVisibility::new(), 0, 10, None))
            .unwrap();
        assert_eq!(after_page.pull_requests, before_page.pull_requests);

        let body = capsule(&node, receipt.capsule_id);
        assert_eq!(body.head_id, before.basis().id());
        assert_eq!(body.backup_profile, BackupProfile::DecisionHistoryOnly);
        assert_eq!(
            body.outcome_index_checkpoint_root,
            Some(receipt.checkpoint_root)
        );
        let (checkpoint, leaves) = retained(&node, receipt.checkpoint_root);
        assert_eq!(leaves, expected_decisions);
        assert_eq!(
            checkpoint.decision_tail_id,
            before.basis().body().decision_tail_id
        );
        assert_eq!(
            checkpoint.latest_decision_sequence,
            before.basis().body().latest_decision_sequence
        );
        let genesis_root = checkpoint
            .predecessor_checkpoint_root
            .expect("a nonempty checkpoint must retain an explicit genesis predecessor");
        let (genesis, genesis_leaves) = retained(&node, genesis_root);
        assert_eq!(genesis.repository_id, node.repository_id());
        assert_eq!(genesis.decision_tail_id, None);
        assert_eq!(genesis.latest_decision_sequence, None);
        assert_eq!(genesis.predecessor_checkpoint_root, None);
        assert!(genesis_leaves.is_empty());
        let manifest = node
            .outcome_checkpoint_fabric
            .read_manifest(checkpoint.leaf_archive_manifest)
            .unwrap();
        assert_eq!(
            manifest.namespace(),
            outcome_index_leaf_archive_namespace(node.repository_id())
        );
        assert_eq!(manifest.entries().len(), receipt.leaf_objects);
        assert_eq!(
            manifest
                .entries()
                .iter()
                .map(|entry| entry.payload_length())
                .sum::<u64>(),
            receipt.leaf_bytes
        );
        assert!(
            manifest
                .entries()
                .iter()
                .all(|entry| entry.object_identity().algorithm() == format)
        );
        let manifest_id = checkpoint.leaf_archive_manifest.as_internal_object_id();
        assert_eq!(
            body.segment_manifest_root,
            Digest::new(manifest_id.algorithm(), *manifest_id.digest())
        );

        let again = maintain(
            &node,
            OutcomeCheckpointLimits {
                expected_head: Some(receipt.published_head),
                max_decisions: receipt.decisions,
                max_archive_bytes: receipt.leaf_bytes,
            },
        )
        .unwrap();
        assert!(!again.published);
        assert_eq!(again.source_head, receipt.published_head);
        assert_eq!(again.published_head, receipt.published_head);
        assert_eq!(again.generation, receipt.generation);
        assert_eq!(again.checkpoint_root, receipt.checkpoint_root);
        assert_eq!(again.capsule_id, receipt.capsule_id);
        assert_eq!(again.decisions, receipt.decisions);
        assert_eq!(again.leaf_objects, receipt.leaf_objects);
        assert_eq!(again.leaf_bytes, receipt.leaf_bytes);
        assert_eq!(
            import_ref(
                &node,
                "target",
                "refs/heads/main",
                zero(&node),
                target,
                &target_objects
            ),
            target_outcome
        );
        assert_eq!(apply_pull_request(&node, &command, "open-pr"), opening);
        assert_eq!(
            import_ref(
                &node,
                "stale-ref",
                "refs/heads/main",
                zero(&node),
                source,
                &source_objects
            ),
            refused
        );
        assert_eq!(
            selected(&node).authenticated().receipt(),
            after.authenticated().receipt()
        );
        assert_decisions(&node, &expected_decisions);
        node.shutdown().unwrap();
    }
}

#[test]
fn empty_checkpoint_is_genesis_and_first_decision_extends_it() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new();
        let (node, _) = OneNode::init(
            test_config(scratch.path().to_path_buf())
                .with_object_format(format)
                .with_worker_threads(2),
        )
        .unwrap();
        let before = selected(&node);
        let first = checkpoint(&node);
        assert_only_checkpoint_changed(&before, &selected(&node), &first);
        assert_eq!(first.decisions, 0);
        let (body, leaves) = retained(&node, first.checkpoint_root);
        assert_eq!(body.decision_tail_id, None);
        assert_eq!(body.latest_decision_sequence, None);
        assert_eq!(body.predecessor_checkpoint_root, None);
        assert!(leaves.is_empty());
        assert!(history(&node).is_empty());
        assert!(!checkpoint(&node).published);

        let committed = add_tag(&node, 0);
        let before = selected(&node);
        let next = checkpoint(&node);
        assert_only_checkpoint_changed(&before, &selected(&node), &next);
        let (body, leaves) = retained(&node, next.checkpoint_root);
        assert_eq!(
            body.predecessor_checkpoint_root,
            Some(first.checkpoint_root)
        );
        assert_eq!(
            body.latest_decision_sequence,
            Some(committed.terminal.decision_sequence)
        );
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0].tx_id, committed.tx_id);
        assert_decisions(&node, &leaves);
        node.shutdown().unwrap();
    }
}

#[test]
fn reopen_uses_retained_outcomes_and_new_decisions_extend_the_same_chain() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf())
            .with_object_format(format)
            .with_worker_threads(2);
        let (node, _) = OneNode::init(config.clone()).unwrap();
        let first_outcome = add_tag(&node, 0);
        let first = checkpoint(&node);
        let expected = full_decisions(&node);
        node.shutdown().unwrap();

        let node = OneNode::open_existing(config).unwrap();
        assert_decisions(&node, &expected);
        let repeated = checkpoint(&node);
        assert!(!repeated.published);
        assert_eq!(repeated.published_head, first.published_head);
        assert_eq!(repeated.checkpoint_root, first.checkpoint_root);
        let second_outcome = add_tag(&node, 1);
        let expected = full_decisions(&node);
        let before = selected(&node);
        let second = checkpoint(&node);
        assert_only_checkpoint_changed(&before, &selected(&node), &second);
        assert_ne!(second.checkpoint_root, first.checkpoint_root);
        let (newer, leaves) = retained(&node, second.checkpoint_root);
        let (older, old_leaves) = retained(&node, first.checkpoint_root);
        assert_eq!(
            newer.predecessor_checkpoint_root,
            Some(first.checkpoint_root)
        );
        assert!(newer.latest_decision_sequence > older.latest_decision_sequence);
        assert_ne!(newer.decision_tail_id, older.decision_tail_id);
        assert_eq!(leaves, expected);
        assert_eq!(old_leaves.len(), 1);
        assert_eq!(second.decisions, 2);
        let outcomes = collected(&node);
        assert_eq!(
            outcomes.decision_for(first_outcome.tx_id),
            Some(first_outcome.terminal)
        );
        assert_eq!(
            outcomes.decision_for(second_outcome.tx_id),
            Some(second_outcome.terminal)
        );
        assert_eq!(
            capsule(&node, second.capsule_id).predecessor_capsule_id,
            Some(first.capsule_id)
        );
        assert_decisions(&node, &expected);
        node.shutdown().unwrap();
    }
}

#[test]
fn generic_intervening_capsule_rebinds_the_same_verified_checkpoint() {
    let scratch = ScratchDirectory::new();
    let (node, _) =
        OneNode::init(test_config(scratch.path().to_path_buf()).with_worker_threads(2)).unwrap();
    add_tag(&node, 0);
    let first = checkpoint(&node);
    let original_checkpoint = retained(&node, first.checkpoint_root);
    let first_body = capsule(&node, first.capsule_id);
    let pointer = CapsulePointer::restored_root(first.capsule_id, &first_body);
    let before_generic = selected(&node);
    let request = node.request_context();
    let frozen = node
        .runtime()
        .block_on(freeze_capsule_async(
            &node.authority,
            request.authority(),
            &CryptoBodyIdentity,
            before_generic.authenticated().receipt(),
            Some(&pointer),
            CapsuleClosure {
                object_closure_root: permitted_object_closure_root(
                    before_generic.selected_closure().closure(),
                )
                .unwrap(),
                segment_manifest_root: digest_of(0xc4),
                backup_profile: BackupProfile::DecisionHistoryOnly,
            },
        ))
        .unwrap();
    assert_eq!(frozen.capsule().outcome_index_checkpoint_root, None);
    let generic = node
        .runtime()
        .block_on(activate_frozen_capsule_async(
            &node.authority,
            request.authority(),
            before_generic.authenticated().receipt(),
            &frozen,
        ))
        .unwrap();
    let before = selected(&node);
    let expected = full_decisions(&node);
    let rebound = checkpoint(&node);
    assert_only_checkpoint_changed(&before, &selected(&node), &rebound);
    assert_eq!(rebound.checkpoint_root, first.checkpoint_root);
    assert_ne!(rebound.capsule_id, first.capsule_id);
    assert_eq!(
        capsule(&node, rebound.capsule_id).predecessor_capsule_id,
        Some(generic.pointer().capsule_id())
    );
    assert_eq!(
        retained(&node, rebound.checkpoint_root),
        original_checkpoint
    );
    let repeated = checkpoint(&node);
    assert!(!repeated.published);
    assert_eq!(repeated.published_head, rebound.published_head);
    assert_decisions(&node, &expected);
    node.shutdown().unwrap();
}

#[test]
fn stale_head_resource_bounds_and_cancellation_never_publish() {
    let scratch = ScratchDirectory::new();
    let (node, _) =
        OneNode::init(test_config(scratch.path().to_path_buf()).with_worker_threads(2)).unwrap();
    let stale = selected(&node).basis().id();
    add_tag(&node, 0);
    add_tag(&node, 1);
    let before = selected(&node);
    let expected = full_decisions(&node);
    assert!(matches!(
        maintain(
            &node,
            OutcomeCheckpointLimits {
                expected_head: Some(stale),
                ..OutcomeCheckpointLimits::default()
            }
        ),
        Err(OutcomeCheckpointRefusal::HeadMoved)
    ));
    for limits in [
        OutcomeCheckpointLimits {
            max_decisions: 0,
            ..OutcomeCheckpointLimits::default()
        },
        OutcomeCheckpointLimits {
            max_decisions: 65_537,
            ..OutcomeCheckpointLimits::default()
        },
        OutcomeCheckpointLimits {
            max_archive_bytes: 0,
            ..OutcomeCheckpointLimits::default()
        },
        OutcomeCheckpointLimits {
            max_archive_bytes: 16 * 1024 * 1024 + 1,
            ..OutcomeCheckpointLimits::default()
        },
    ] {
        assert!(matches!(
            maintain(&node, limits),
            Err(OutcomeCheckpointRefusal::InvalidLimits)
        ));
        assert_eq!(
            selected(&node).authenticated().receipt(),
            before.authenticated().receipt()
        );
    }
    for limits in [
        OutcomeCheckpointLimits {
            max_decisions: 1,
            ..OutcomeCheckpointLimits::default()
        },
        OutcomeCheckpointLimits {
            max_archive_bytes: 1,
            ..OutcomeCheckpointLimits::default()
        },
    ] {
        assert!(matches!(
            maintain(&node, limits),
            Err(OutcomeCheckpointRefusal::LimitExceeded(_))
        ));
        assert_eq!(
            selected(&node).authenticated().receipt(),
            before.authenticated().receipt()
        );
    }
    let request = node.request_context();
    request.cancel();
    let reads = node.authority.body_cache_stats();
    assert!(matches!(
        node.runtime()
            .block_on(node.checkpoint_outcomes_in(&request, OutcomeCheckpointLimits::default())),
        Err(OutcomeCheckpointRefusal::Stopped)
    ));
    let after_reads = node.authority.body_cache_stats();
    assert_eq!(
        after_reads.hits + after_reads.misses,
        reads.hits + reads.misses
    );
    assert_eq!(
        selected(&node).authenticated().receipt(),
        before.authenticated().receipt()
    );
    assert_decisions(&node, &expected);

    let published = checkpoint(&node);
    assert_only_checkpoint_changed(&before, &selected(&node), &published);
    // A valid existing checkpoint cannot let a no-op bypass the caller's bound.
    assert!(matches!(
        maintain(
            &node,
            OutcomeCheckpointLimits {
                max_decisions: 1,
                ..OutcomeCheckpointLimits::default()
            }
        ),
        Err(OutcomeCheckpointRefusal::LimitExceeded(_))
    ));
    assert_eq!(selected(&node).basis().id(), published.published_head);
    node.shutdown().unwrap();
}

#[test]
fn damaged_newest_retained_leaf_refuses_maintenance_but_admission_can_fall_back() {
    for missing in [false, true] {
        let scratch = ScratchDirectory::new();
        let (node, _) =
            OneNode::init(test_config(scratch.path().to_path_buf()).with_worker_threads(2))
                .unwrap();
        add_tag(&node, 0);
        let older = checkpoint(&node);
        add_tag(&node, 1);
        let newest = checkpoint(&node);
        let before = selected(&node);
        let expected = full_decisions(&node);
        let (body, _) = retained(&node, newest.checkpoint_root);
        let manifest = node
            .outcome_checkpoint_fabric
            .read_manifest(body.leaf_archive_manifest)
            .unwrap();
        assert!(!manifest.entries().is_empty());
        let identity = manifest.entries()[0].object_identity();
        let hex = fgit_crypto::lowercase_hex;
        let path = node
            .storage_root
            .join("objects")
            .join(hex(manifest.namespace()))
            .join(hex(&identity.algorithm().code_point().to_be_bytes()))
            .join(hex(identity.as_bytes()));
        if missing {
            fs::remove_file(path).unwrap();
        } else {
            fs::write(path, b"corrupt newest retained outcome leaf").unwrap();
        }
        assert_eq!(retained(&node, older.checkpoint_root).1.len(), 1);
        assert_decisions(&node, &expected);
        assert!(matches!(
            maintain(&node, OutcomeCheckpointLimits::default()),
            Err(OutcomeCheckpointRefusal::Checkpoint(_))
        ));
        assert_eq!(
            selected(&node).authenticated().receipt(),
            before.authenticated().receipt()
        );
        assert_eq!(
            selected(&node).basis().body().last_checkpoint_id,
            Some(newest.capsule_id)
        );

        let admitted = add_tag(&node, 2);
        assert_eq!(
            collected(&node).decision_for(admitted.tx_id),
            Some(admitted.terminal)
        );
        assert_eq!(collected(&node).len(), 3);
        let after_admission = selected(&node);
        assert!(matches!(
            maintain(&node, OutcomeCheckpointLimits::default()),
            Err(OutcomeCheckpointRefusal::Checkpoint(_))
        ));
        assert_eq!(
            selected(&node).authenticated().receipt(),
            after_admission.authenticated().receipt()
        );
        assert_eq!(
            after_admission.basis().body().last_checkpoint_id,
            Some(newest.capsule_id)
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn valid_but_incomplete_retained_set_cannot_justify_a_checkpoint_no_op() {
    let scratch = ScratchDirectory::new();
    let (node, _) =
        OneNode::init(test_config(scratch.path().to_path_buf()).with_worker_threads(2)).unwrap();
    add_tag(&node, 0);
    let valid = checkpoint(&node);
    let (valid_body, _) = retained(&node, valid.checkpoint_root);
    let genesis_root = valid_body.predecessor_checkpoint_root.unwrap();
    let (genesis, _) = retained(&node, genesis_root);
    let before = selected(&node);
    let expected = full_decisions(&node);
    assert_eq!(expected.len(), 1);

    // Model acknowledged but semantically wrong checkpoint evidence. Every
    // identity, manifest, blob and predecessor is valid; the retained set
    // simply omits the terminal decision at the claimed nonempty position.
    // The normal freeze API must not construct such evidence, so this fault
    // fixture stages it explicitly through the real immutable store and CAS.
    let wrong = OutcomeIndexCheckpointBody::new(
        node.repository_id(),
        before.basis().body().decision_tail_id,
        before.basis().body().latest_decision_sequence,
        Some(genesis_root),
        genesis.leaf_archive_manifest,
    )
    .unwrap();
    let request = node.request_context();
    let wrong_root = node
        .runtime()
        .block_on(fgit_chronicle::stage_outcome_index_checkpoint_async(
            &node.authority,
            request.authority(),
            &CryptoBodyIdentity,
            &wrong,
        ))
        .unwrap();
    let manifest_id = wrong.leaf_archive_manifest.as_internal_object_id();
    let mut body = RepositoryCapsuleBody::at_head(
        before.basis().id(),
        before.basis().body(),
        Some(valid.capsule_id),
        permitted_object_closure_root(before.selected_closure().closure()).unwrap(),
        Digest::new(manifest_id.algorithm(), *manifest_id.digest()),
        BackupProfile::DecisionHistoryOnly,
    );
    body.outcome_index_checkpoint_root = Some(wrong_root);
    let id = capsule_identity(&CryptoBodyIdentity, &body).unwrap();
    node.runtime()
        .block_on(AsyncAuthorityStore::put_if_absent(
            &node.authority,
            request.authority(),
            &body_key_for_id(id.as_internal_object_id()).unwrap(),
            &fgit_codec::encode_body(&body).unwrap(),
        ))
        .unwrap();
    let mut changed = before.basis().body().clone();
    changed.predecessor_head_id = Some(before.basis().id());
    changed.generation = changed.generation.next().unwrap();
    changed.last_checkpoint_id = Some(id);
    let changed_bytes = fgit_codec::encode_body(&changed).unwrap();
    node.runtime()
        .block_on(AsyncAuthorityStore::put_if_absent(
            &node.authority,
            request.authority(),
            &fgit_authority::body_key(
                fgit_crypto::IdentityDomain::RepositoryAuthorityHead,
                &changed,
            )
            .unwrap(),
            &changed_bytes,
        ))
        .unwrap();
    assert!(matches!(
        node.runtime()
            .block_on(AsyncAuthorityStore::compare_exchange_head(
                &node.authority,
                request.authority(),
                &node.head_key,
                before.authenticated().receipt().token(),
                changed.generation,
                &changed_bytes,
            ))
            .unwrap(),
        fgit_authority::CasOutcome::Committed(_)
    ));

    let acknowledged = selected(&node);
    let (loaded, leaves) = retained(&node, wrong_root);
    assert_eq!(loaded, wrong);
    assert!(leaves.is_empty());
    assert_decisions(&node, &expected);
    assert!(matches!(
        maintain(&node, OutcomeCheckpointLimits::default()),
        Err(OutcomeCheckpointRefusal::Outcomes(_))
    ));
    assert_eq!(
        selected(&node).authenticated().receipt(),
        acknowledged.authenticated().receipt()
    );
    assert_eq!(selected(&node).basis().body().last_checkpoint_id, Some(id));
    node.shutdown().unwrap();
}

#[test]
fn reused_checkpoint_receipts_and_byte_limits_follow_the_actual_archive_chunks() {
    use fgit_object_fabric::fabric::{
        ManifestLimits, PlacementAdmission, PutIfAbsent, SegmentManifest, VerifiedObject,
    };
    use fgit_object_fabric::{
        CryptoDigest, DigestAlgorithm, MicrosegmentBuilder, MicrosegmentReader, ObjectEnvelope,
        ObjectKind, SegmentLimits, SegmentRecordInput,
    };

    let scratch = ScratchDirectory::new();
    let (node, _) =
        OneNode::init(test_config(scratch.path().to_path_buf()).with_worker_threads(2)).unwrap();
    add_tag(&node, 0);
    let first = checkpoint(&node);
    add_tag(&node, 1);
    let before = selected(&node);
    let decisions = full_decisions(&node);
    assert_eq!(decisions.len(), 2);

    let packed = fgit_chronicle::OutcomeIndexLeafArchive::prepare(
        node.repository_id(),
        node.object_format(),
        &decisions,
    )
    .unwrap();
    assert_eq!(packed.objects().len(), 1);
    let packed_bytes = packed.objects()[0].payload().len() as u64;

    // The wire profile allows smaller consecutive chunks. Construct two
    // ordinary verified native blobs, preserving authority-canonical order,
    // instead of relying on the current writer's maximal chunk packing.
    let digest = CryptoDigest;
    let segment_limits = SegmentLimits::default();
    let mut objects = Vec::new();
    for (index, decision) in decisions.iter().enumerate() {
        let mut encoder = fgit_codec::Encoder::new();
        encoder.write_scalar(u32::try_from(index).unwrap());
        encoder
            .write_sequence(
                "outcome_index_leaf_chunk_decisions",
                std::slice::from_ref(decision),
                RepositoryDecision::write_canonical,
            )
            .unwrap();
        let payload = encoder.into_bytes();
        let commitment = digest
            .payload_commitment(ObjectKind::Blob, &payload)
            .unwrap();
        let identity = fgit_crypto::git_object_id(
            node.object_format(),
            fgit_crypto::GitObjectKind::Blob,
            &payload,
        );
        let envelope = ObjectEnvelope::new(
            outcome_index_leaf_archive_namespace(node.repository_id()),
            identity,
            ObjectKind::Blob,
            u64::try_from(payload.len()).unwrap(),
            commitment,
            b"frankengit/outcome-index-checkpoint-leaf-chunk/v1".to_vec(),
            commitment,
            None,
            &segment_limits,
        )
        .unwrap();
        objects.push(VerifiedObject::new(envelope, payload).unwrap());
    }
    objects.sort_unstable_by_key(VerifiedObject::identity);
    let actual_bytes: u64 = objects
        .iter()
        .map(|object| u64::try_from(object.payload().len()).unwrap())
        .sum();
    assert!(actual_bytes > packed_bytes);

    let ledger = ObligationLedger::root(
        RegionId::new(0x772),
        LeakDisposition::FailFast,
        ResourceVector::single(Grade::Bytes, actual_bytes).with(Grade::Objects, 2),
    );
    let mut placements = BTreeSet::new();
    let mut builder = MicrosegmentBuilder::new(&digest, segment_limits.clone());
    for object in objects {
        builder
            .push(SegmentRecordInput {
                envelope: object.envelope().clone(),
                payload: object.payload().to_vec(),
            })
            .unwrap();
        let grant = ledger
            .grant(
                ResourceVector::single(Grade::Bytes, object.payload().len() as u64)
                    .with(Grade::Objects, 1),
            )
            .unwrap();
        let (PutIfAbsent::Created { placement, .. }
        | PutIfAbsent::AlreadyPresent { placement, .. }) = node
            .outcome_checkpoint_fabric
            .put_if_absent(object, PlacementAdmission::new(&ledger, grant))
            .unwrap();
        placements.insert(placement);
    }
    assert!(ledger.close().is_quiescent());
    let segment = builder.build().unwrap();
    let reader = MicrosegmentReader::open(segment.as_bytes(), &digest, &segment_limits).unwrap();
    let manifest = SegmentManifest::from_verified_segment(
        &reader,
        placements.into_iter().collect(),
        &ManifestLimits::default(),
    )
    .unwrap();
    let manifest_id = node
        .outcome_checkpoint_fabric
        .write_manifest(&manifest)
        .unwrap();
    let manifest_identity = manifest_id.as_internal_object_id();
    let segment_manifest_root =
        Digest::new(manifest_identity.algorithm(), *manifest_identity.digest());
    let body = OutcomeIndexCheckpointBody::new(
        node.repository_id(),
        before.basis().body().decision_tail_id,
        before.basis().body().latest_decision_sequence,
        Some(first.checkpoint_root),
        manifest_id,
    )
    .unwrap();
    let request = node.request_context();
    let object_closure_root = node
        .runtime()
        .block_on(
            node.admission_materializer
                .stage_permitted_object_closure_in(
                    &node.authority,
                    request.authority(),
                    node.repository_id(),
                    before.selected_closure().closure().clone(),
                ),
        )
        .unwrap();
    let pointer =
        CapsulePointer::restored_root(first.capsule_id, &capsule(&node, first.capsule_id));
    let frozen = node
        .runtime()
        .block_on(
            fgit_chronicle::freeze_capsule_with_outcome_index_checkpoint_async(
                &node.authority,
                request.authority(),
                &node.outcome_checkpoint_fabric,
                &CryptoBodyIdentity,
                before.authenticated().receipt(),
                Some(&pointer),
                CapsuleClosure {
                    object_closure_root,
                    segment_manifest_root,
                    backup_profile: BackupProfile::DecisionHistoryOnly,
                },
                &body,
            ),
        )
        .unwrap();
    let root = frozen.capsule().outcome_index_checkpoint_root.unwrap();
    let activated = node
        .runtime()
        .block_on(activate_frozen_capsule_async(
            &node.authority,
            request.authority(),
            before.authenticated().receipt(),
            &frozen,
        ))
        .unwrap();
    assert_eq!(retained(&node, root), (body.clone(), decisions.clone()));

    let current = selected(&node);
    let exact_limit = OutcomeCheckpointLimits {
        expected_head: Some(current.basis().id()),
        max_decisions: 2,
        max_archive_bytes: actual_bytes,
    };
    assert!(matches!(
        maintain(
            &node,
            OutcomeCheckpointLimits {
                max_archive_bytes: actual_bytes - 1,
                ..exact_limit
            }
        ),
        Err(OutcomeCheckpointRefusal::LimitExceeded(
            "retained leaf bytes"
        ))
    ));
    assert_eq!(
        selected(&node).authenticated().receipt(),
        current.authenticated().receipt()
    );
    let unchanged = maintain(&node, exact_limit).unwrap();
    assert!(!unchanged.published);
    assert_eq!(unchanged.published_head, current.basis().id());
    assert_eq!(unchanged.checkpoint_root, root);
    assert_eq!(unchanged.leaf_objects, 2);
    assert_eq!(unchanged.leaf_bytes, actual_bytes);

    let generic = node
        .runtime()
        .block_on(freeze_capsule_async(
            &node.authority,
            request.authority(),
            &CryptoBodyIdentity,
            current.authenticated().receipt(),
            Some(&activated.pointer()),
            CapsuleClosure {
                object_closure_root,
                segment_manifest_root,
                backup_profile: BackupProfile::DecisionHistoryOnly,
            },
        ))
        .unwrap();
    assert_eq!(generic.capsule().outcome_index_checkpoint_root, None);
    let generic = node
        .runtime()
        .block_on(activate_frozen_capsule_async(
            &node.authority,
            request.authority(),
            current.authenticated().receipt(),
            &generic,
        ))
        .unwrap();
    let before_rebind = selected(&node);
    let exact_limit = OutcomeCheckpointLimits {
        expected_head: Some(before_rebind.basis().id()),
        ..exact_limit
    };
    assert!(matches!(
        maintain(
            &node,
            OutcomeCheckpointLimits {
                max_archive_bytes: actual_bytes - 1,
                ..exact_limit
            }
        ),
        Err(OutcomeCheckpointRefusal::LimitExceeded(
            "retained leaf bytes"
        ))
    ));
    assert_eq!(
        selected(&node).authenticated().receipt(),
        before_rebind.authenticated().receipt()
    );
    let rebound = maintain(&node, exact_limit).unwrap();
    assert_only_checkpoint_changed(&before_rebind, &selected(&node), &rebound);
    assert_eq!(rebound.checkpoint_root, root);
    assert_eq!(rebound.leaf_objects, 2);
    assert_eq!(rebound.leaf_bytes, actual_bytes);
    assert_eq!(
        capsule(&node, rebound.capsule_id).predecessor_capsule_id,
        Some(generic.pointer().capsule_id())
    );
    assert_eq!(retained(&node, root), (body, decisions.clone()));
    assert_decisions(&node, &decisions);
    node.shutdown().unwrap();
}
