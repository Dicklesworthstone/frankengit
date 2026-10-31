//! Native outcome-checkpoint consumption, fallback and exact-token evidence.

use super::*;

use fgit_authority::{
    AuthenticatedHead, CumulativeOutcomes, OutcomeFailure, collect_cumulative_outcomes_async,
};
use fgit_chronicle::{
    BackupProfile, CapsuleClosure, OutcomeIndexCheckpointBody, OutcomeIndexLeafArchive,
    activate_frozen_capsule_async, freeze_capsule_with_outcome_index_checkpoint_async,
    outcome_index_leaf_archive_namespace, stage_outcome_index_checkpoint_async,
};
use fgit_codec::RepositoryDecision;
use fgit_object_fabric::fabric::{ImmutableObjectFabric, PlacementAdmission, PutIfAbsent};
use fgit_resource::{Grade, LeakDisposition, ObligationLedger, RegionId, ResourceVector};
use fgit_types::{DecisionSequence, Digest, RepositoryDecisionBatchId};

fn add_outcome(node: &OneNode, index: usize) {
    let object = put_object(
        node,
        ObjectType::Blob,
        format!("outcome-checkpoint-{index}\n").into_bytes(),
    );
    let objects = BTreeSet::from([object]);
    let closure = PermittedObjectClosure::new(objects.clone());
    let validated = validate_source_import(
        &[SourceRefUpdate {
            old: GitOid::from_hex(node.object_format(), &"00".repeat(20)).unwrap(),
            new: object,
            ref_name: format!("refs/tags/outcome-{index}").into_bytes(),
        }],
        &SourceImportReceipt {
            object_format: node.object_format(),
            object_count: 1,
            delete_only: false,
            origin: SourceImportOrigin::LocalGitDirectory,
        },
        ValidatedClosure {
            objects,
            object_closure_root: permitted_object_closure_root(&closure).unwrap(),
        },
    )
    .unwrap();
    let (mut context, _, _) = evidence_request(node);
    context.idempotency_key =
        fgit_authority::IdempotencyKey::new(format!("outcome-{index}").into_bytes()).unwrap();
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
    assert!(matches!(
        result.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
}

fn stage_checkpoint(
    node: &OneNode,
    decisions: &[RepositoryDecision],
    tail: Option<RepositoryDecisionBatchId>,
    sequence: Option<DecisionSequence>,
    predecessor: Option<Digest>,
) -> (OutcomeIndexCheckpointBody, Digest, Vec<PathBuf>) {
    let archive =
        OutcomeIndexLeafArchive::prepare(node.repository_id(), node.object_format(), decisions)
            .unwrap();
    let bytes = archive
        .objects()
        .iter()
        .map(|object| u64::try_from(object.payload().len()).unwrap())
        .sum();
    let ledger = ObligationLedger::root(
        RegionId::new(0x771),
        LeakDisposition::FailFast,
        ResourceVector::single(Grade::Bytes, bytes).with(
            Grade::Objects,
            u64::try_from(archive.objects().len()).unwrap(),
        ),
    );
    let mut placements = Vec::new();
    let mut object_paths = Vec::new();
    for object in archive.objects() {
        let grant = ledger
            .grant(
                ResourceVector::single(
                    Grade::Bytes,
                    u64::try_from(object.payload().len()).unwrap(),
                )
                .with(Grade::Objects, 1),
            )
            .unwrap();
        let placement = match node
            .outcome_checkpoint_fabric
            .put_if_absent(object.clone(), PlacementAdmission::new(&ledger, grant))
            .unwrap()
        {
            PutIfAbsent::Created { placement, .. }
            | PutIfAbsent::AlreadyPresent { placement, .. } => placement,
        };
        if !placements.contains(&placement) {
            placements.push(placement);
        }
        let hex = fgit_crypto::lowercase_hex;
        object_paths.push(
            node.storage_root
                .join("objects")
                .join(hex(&outcome_index_leaf_archive_namespace(
                    node.repository_id(),
                )))
                .join(hex(&object
                    .identity()
                    .algorithm()
                    .code_point()
                    .to_be_bytes()))
                .join(hex(object.identity().as_bytes())),
        );
    }
    let manifest = archive.manifest(placements).unwrap();
    let manifest_id = node
        .outcome_checkpoint_fabric
        .write_manifest(&manifest)
        .unwrap();
    assert!(ledger.close().is_quiescent());
    let checkpoint = OutcomeIndexCheckpointBody::new(
        node.repository_id(),
        tail,
        sequence,
        predecessor,
        manifest_id,
    )
    .unwrap();
    let request = node.request_context();
    let root = node
        .runtime()
        .block_on(stage_outcome_index_checkpoint_async(
            &node.authority,
            request.authority(),
            &CryptoBodyIdentity,
            &checkpoint,
        ))
        .unwrap();
    (checkpoint, root, object_paths)
}

fn checkpoint(node: &OneNode) -> Vec<PathBuf> {
    let request = node.request_context();
    let selected = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    let baseline = node
        .runtime()
        .block_on(collect_cumulative_outcomes_async(
            &node.authority,
            request.authority(),
            &node.head_key,
        ))
        .unwrap();
    let decisions = baseline
        .checkpoint_decisions_against(selected.authenticated().receipt().token())
        .unwrap();
    let (_, genesis_root, _) = stage_checkpoint(node, &[], None, None, None);
    let head = selected.basis().body();
    let (checkpoint, _, paths) = stage_checkpoint(
        node,
        &decisions,
        head.decision_tail_id,
        head.latest_decision_sequence,
        Some(genesis_root),
    );
    let object_closure_root = node
        .runtime()
        .block_on(
            node.admission_materializer
                .stage_permitted_object_closure_in(
                    &node.authority,
                    request.authority(),
                    node.repository_id(),
                    selected.selected_closure().closure().clone(),
                ),
        )
        .unwrap();
    let manifest_id = checkpoint.leaf_archive_manifest.as_internal_object_id();
    let segment_manifest_root = Digest::new(manifest_id.algorithm(), *manifest_id.digest());
    let frozen = node
        .runtime()
        .block_on(freeze_capsule_with_outcome_index_checkpoint_async(
            &node.authority,
            request.authority(),
            &node.outcome_checkpoint_fabric,
            &CryptoBodyIdentity,
            selected.authenticated().receipt(),
            None,
            CapsuleClosure {
                object_closure_root,
                // This reduced profile qualifies retained outcomes, not a
                // whole-object backup or an independent restore.
                segment_manifest_root,
                backup_profile: BackupProfile::DecisionHistoryOnly,
            },
            &checkpoint,
        ))
        .unwrap();
    node.runtime()
        .block_on(activate_frozen_capsule_async(
            &node.authority,
            request.authority(),
            selected.authenticated().receipt(),
            &frozen,
        ))
        .unwrap();
    paths
}

fn authenticated(node: &OneNode) -> AuthenticatedHead {
    node.runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap()
}

fn collected(
    node: &OneNode,
    head: &AuthenticatedHead,
) -> Result<CumulativeOutcomes, OutcomeFailure> {
    let (context, _, _) = evidence_request(node);
    let projection = node.durable_admission_projection(&context).unwrap();
    let request = node.request_context();
    node.runtime()
        .block_on(projection.collect_cumulative_outcomes_async(
            &node.authority,
            request.authority(),
            &node.head_key,
            head,
        ))
}

fn reads(node: &OneNode) -> u64 {
    let stats = node.authority.body_cache_stats();
    stats.hits + stats.misses
}

fn baseline(node: &OneNode) -> CumulativeOutcomes {
    let request = node.request_context();
    node.runtime()
        .block_on(collect_cumulative_outcomes_async(
            &node.authority,
            request.authority(),
            &node.head_key,
        ))
        .unwrap()
}

fn assert_same_outcomes(actual: &CumulativeOutcomes, expected: &CumulativeOutcomes) {
    assert_eq!(actual.observed(), expected.observed());
    assert_eq!(
        actual
            .checkpoint_decisions_against(actual.observed())
            .unwrap(),
        expected
            .checkpoint_decisions_against(expected.observed())
            .unwrap(),
        "retained leaves and full replay must produce the same authority-canonical decisions"
    );
}

#[test]
fn durable_projection_uses_retained_leaves_across_restart_and_new_publication() {
    let scratch = ScratchDirectory::new();
    let config = test_config(scratch.path().to_path_buf());
    let (node, _) = OneNode::init(config.clone()).unwrap();
    for index in 0..8 {
        add_outcome(&node, index);
    }
    checkpoint(&node);
    node.shutdown().unwrap();
    let node = OneNode::open_existing(config).unwrap();

    let head = authenticated(&node);
    let before = reads(&node);
    let expected = baseline(&node);
    let baseline_reads = reads(&node) - before;
    let before = reads(&node);
    let actual = collected(&node, &head).unwrap();
    let checkpoint_reads = reads(&node) - before;
    assert_same_outcomes(&actual, &expected);
    assert!(
        checkpoint_reads < baseline_reads,
        "native collector must skip retained decision history: {checkpoint_reads} versus {baseline_reads} reads"
    );
    assert_eq!(actual.len(), 8);

    add_outcome(&node, 8);
    let current = authenticated(&node);
    let expected = baseline(&node);
    let actual = collected(&node, &current).unwrap();
    assert_same_outcomes(&actual, &expected);
    assert_eq!(actual.len(), 9);
    assert_ne!(current.receipt().token(), head.receipt().token());
    assert!(matches!(
        actual.fold_against(head.receipt().token(), &[]),
        Err(OutcomeFailure::CumulativeIndexStale { .. })
    ));
    node.shutdown().unwrap();
}

#[test]
fn corrupt_or_missing_checkpoint_chunks_fall_back_without_changing_authority() {
    for missing in [false, true] {
        let scratch = ScratchDirectory::new();
        let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
        for index in 0..4 {
            add_outcome(&node, index);
        }
        let paths = checkpoint(&node);
        let head = authenticated(&node);
        let expected = baseline(&node);
        assert_same_outcomes(&collected(&node, &head).unwrap(), &expected);
        for path in paths {
            if missing {
                fs::remove_file(path).unwrap();
            } else {
                fs::write(path, b"corrupt retained leaf archive").unwrap();
            }
        }
        assert_same_outcomes(&collected(&node, &head).unwrap(), &expected);
        assert_eq!(authenticated(&node).receipt(), head.receipt());
        add_outcome(&node, 4);
        assert_eq!(collected(&node, &authenticated(&node)).unwrap().len(), 5);
        node.shutdown().unwrap();
    }
}

#[test]
fn cancelled_outcome_collection_never_returns_a_checkpoint_or_fallback_witness() {
    let scratch = ScratchDirectory::new();
    let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
    add_outcome(&node, 0);
    checkpoint(&node);
    let head = authenticated(&node);
    let (context, _, _) = evidence_request(&node);
    let projection = node.durable_admission_projection(&context).unwrap();
    let request = node.request_context();
    request.cancel();
    let before = reads(&node);
    assert!(
        node.runtime()
            .block_on(projection.collect_cumulative_outcomes_async(
                &node.authority,
                request.authority(),
                &node.head_key,
                &head,
            ))
            .is_err()
    );
    assert_eq!(reads(&node), before);
    assert_eq!(authenticated(&node).receipt(), head.receipt());
    node.shutdown().unwrap();
}
