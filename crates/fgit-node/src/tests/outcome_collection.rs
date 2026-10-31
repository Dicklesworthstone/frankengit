//! Native outcome-checkpoint consumption, fallback and exact-token evidence.

use super::*;

use crate::outcome_checkpoint::{OutcomeCheckpointLimits, OutcomeCheckpointReceipt};
use fgit_admission::CommandOutcome;
use fgit_authority::{
    AmbiguityReason, AuthenticatedHead, AuthorityFailure, CumulativeOutcomes, OutcomeFailure,
    collect_cumulative_outcomes_async,
};
use fgit_chronicle::{
    BackupProfile, CapsuleClosure, OutcomeIndexCheckpointBody, OutcomeIndexLeafArchive,
    activate_frozen_capsule_async, freeze_capsule_with_outcome_index_checkpoint_async,
    load_verified_outcome_index_checkpoint_async, outcome_index_leaf_archive_namespace,
    stage_outcome_index_checkpoint_async,
};
use fgit_codec::RepositoryDecision;
use fgit_object_fabric::fabric::{ImmutableObjectFabric, PlacementAdmission, PutIfAbsent};
use fgit_resource::{Grade, LeakDisposition, ObligationLedger, RegionId, ResourceVector};
use fgit_types::{DecisionSequence, Digest, RepositoryDecisionBatchId};

fn add_outcome(node: &OneNode, index: usize) -> CommandOutcome {
    let outcome = import_outcome(node, index, &format!("outcome-{index}"));
    assert!(matches!(
        outcome.terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    outcome
}

fn import_outcome(node: &OneNode, index: usize, key: &str) -> CommandOutcome {
    let object = put_object(
        node,
        ObjectType::Blob,
        format!("outcome-checkpoint-{index}\n").into_bytes(),
    );
    let objects = BTreeSet::from([object]);
    let closure = PermittedObjectClosure::new(objects.clone());
    let validated = validate_source_import(
        &[SourceRefUpdate {
            old: GitOid::from_hex(
                node.object_format(),
                &"00".repeat(match node.object_format() {
                    GitHashAlgorithm::Sha1 => 20,
                    GitHashAlgorithm::Sha256 => 32,
                }),
            )
            .unwrap(),
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
    context.idempotency_key = fgit_authority::IdempotencyKey::new(key.as_bytes().to_vec()).unwrap();
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

fn maintain_checkpoint(node: &OneNode) -> OutcomeCheckpointReceipt {
    let request = node.request_context();
    node.runtime()
        .block_on(node.checkpoint_outcomes_in(&request, OutcomeCheckpointLimits::default()))
        .unwrap()
}

fn maintained_leaf_paths(node: &OneNode, root: Digest) -> Vec<PathBuf> {
    let request = node.request_context();
    let (checkpoint, _) = node
        .runtime()
        .block_on(load_verified_outcome_index_checkpoint_async(
            &node.authority,
            request.authority(),
            &CryptoBodyIdentity,
            &node.outcome_checkpoint_fabric,
            root,
        ))
        .unwrap();
    let manifest = node
        .outcome_checkpoint_fabric
        .read_manifest(checkpoint.leaf_archive_manifest)
        .unwrap();
    assert!(!manifest.entries().is_empty());
    let hex = fgit_crypto::lowercase_hex;
    manifest
        .entries()
        .iter()
        .map(|entry| {
            let identity = entry.object_identity();
            node.storage_root
                .join("objects")
                .join(hex(manifest.namespace()))
                .join(hex(&identity.algorithm().code_point().to_be_bytes()))
                .join(hex(identity.as_bytes()))
        })
        .collect()
}

fn public_lookup(node: &OneNode, tx: TxId) -> OutcomeLookup {
    let request = node.request_context();
    node.runtime()
        .block_on(node.resolve_outcome_in(&request, tx))
        .unwrap()
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

#[test]
fn public_terminal_lookup_uses_retained_history_after_restart_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf())
            .with_object_format(format)
            .with_worker_threads(2);
        let (node, _) = OneNode::init(config.clone()).unwrap();
        let committed = add_outcome(&node, 0);
        let refused = import_outcome(&node, 0, "outcome-0-stale-create");
        assert!(matches!(
            refused.terminal.outcome,
            DecisionOutcome::Refused { .. }
        ));
        for index in 1..16 {
            add_outcome(&node, index);
        }
        assert!(maintain_checkpoint(&node).published);
        node.shutdown().unwrap();
        let node = OneNode::open_existing(config).unwrap();
        let head = authenticated(&node);
        let cases = [
            (committed.tx_id, OutcomeLookup::Decided(committed.terminal)),
            (refused.tx_id, OutcomeLookup::Decided(refused.terminal)),
            (distinct_tx_id(), OutcomeLookup::Undecided),
        ];

        // The independent full-replay oracle also exercises an absent hint.
        // Count body accesses, including cache hits, so warm caches cannot hide
        // a regression back to walking the complete decision stream.
        let before = reads(&node);
        for (tx, expected) in cases {
            let request = node.request_context();
            assert_eq!(
                node.runtime()
                    .block_on(fgit_authority::resolve_outcome_async(
                        &node.authority,
                        request.authority(),
                        &node.head_key,
                        node.tenant_id(),
                        node.repository_id(),
                        tx,
                    ))
                    .unwrap(),
                expected
            );
        }
        let replay_reads = reads(&node) - before;
        let before = reads(&node);
        for (tx, expected) in cases {
            assert_eq!(public_lookup(&node, tx), expected);
        }
        let checkpoint_reads = reads(&node) - before;
        assert!(
            checkpoint_reads < replay_reads,
            "public terminal lookup must use retained history: {checkpoint_reads} versus {replay_reads} body reads"
        );
        assert_eq!(authenticated(&node).receipt(), head.receipt());

        // The retained prefix and subsequent live suffix must agree, including
        // a refusal whose key remains terminal after a newer publication.
        let newest = add_outcome(&node, 16);
        for (tx, expected) in cases {
            assert_eq!(public_lookup(&node, tx), expected);
        }
        assert_eq!(
            public_lookup(&node, newest.tx_id),
            OutcomeLookup::Decided(newest.terminal)
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn public_terminal_lookup_replays_when_retained_chunks_are_missing_or_corrupt() {
    for missing in [false, true] {
        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf()).with_worker_threads(2);
        let (node, _) = OneNode::init(config.clone()).unwrap();
        let committed = add_outcome(&node, 0);
        let refused = import_outcome(&node, 0, "outcome-0-stale-create");
        assert!(matches!(
            refused.terminal.outcome,
            DecisionOutcome::Refused { .. }
        ));
        for index in 1..4 {
            add_outcome(&node, index);
        }
        let checkpoint = maintain_checkpoint(&node);
        for path in maintained_leaf_paths(&node, checkpoint.checkpoint_root) {
            if missing {
                fs::remove_file(path).unwrap();
            } else {
                fs::write(path, b"corrupt retained terminal history").unwrap();
            }
        }
        node.shutdown().unwrap();
        let node = OneNode::open_existing(config).unwrap();
        let head = authenticated(&node);
        assert_eq!(
            public_lookup(&node, committed.tx_id),
            OutcomeLookup::Decided(committed.terminal)
        );
        assert_eq!(
            public_lookup(&node, refused.tx_id),
            OutcomeLookup::Decided(refused.terminal)
        );
        assert_eq!(
            public_lookup(&node, distinct_tx_id()),
            OutcomeLookup::Undecided
        );
        assert_eq!(authenticated(&node).receipt(), head.receipt());
        node.shutdown().unwrap();
    }
}

#[test]
fn cancelled_public_terminal_lookup_cannot_return_checkpoint_or_replay_answers() {
    let scratch = ScratchDirectory::new();
    let (node, _) =
        OneNode::init(test_config(scratch.path().to_path_buf()).with_worker_threads(2)).unwrap();
    let committed = add_outcome(&node, 0);
    maintain_checkpoint(&node);
    let head = authenticated(&node);
    let request = node.request_context();
    request.cancel();
    let before = reads(&node);
    for tx in [committed.tx_id, distinct_tx_id()] {
        assert!(matches!(
            node.runtime().block_on(node.resolve_outcome_in(&request, tx)),
            Err(NodeRefusal::Authority(error))
                if *error == OutcomeFailure::from(AuthorityFailure::Ambiguous(
                    AmbiguityReason::Cancelled
                ))
        ));
    }
    assert_eq!(reads(&node), before);
    assert_eq!(authenticated(&node).receipt(), head.receipt());
    node.shutdown().unwrap();
}

#[test]
fn public_terminal_lookup_recovers_recent_decisions_when_older_history_is_missing() {
    for refused in [false, true] {
        let scratch = ScratchDirectory::new();
        let (node, _) =
            OneNode::init(test_config(scratch.path().to_path_buf()).with_worker_threads(2))
                .unwrap();
        add_outcome(&node, 0);
        let recent = if refused {
            let outcome = import_outcome(&node, 0, "recent-stale-create");
            assert!(matches!(
                outcome.terminal.outcome,
                DecisionOutcome::Refused { .. }
            ));
            outcome
        } else {
            add_outcome(&node, 1)
        };
        let request = node.request_context();
        let before = authenticated(&node);
        let mut head = before.body().unwrap();
        let mut batch = node
            .runtime()
            .block_on(read_decision_batch_body_async(
                &node.authority,
                request.authority(),
                head.decision_tail_id.unwrap(),
            ))
            .unwrap();

        // Fault injection models acknowledged history whose older link has
        // become unavailable. Keep the newest terminal and its accelerator
        // intact, but select a correctly identified batch pointing at a
        // missing predecessor. Ordinary publication cannot construct this.
        let missing = fgit_codec::harness::head_id();
        assert_eq!(
            node.runtime()
                .block_on(AsyncAuthorityStore::read_immutable(
                    &node.authority,
                    request.authority(),
                    &fgit_authority::body_key_for_id(missing.as_internal_object_id()).unwrap(),
                ))
                .unwrap(),
            ImmutableRead::Absent
        );
        batch.predecessor_head_id = missing;
        let batch_id = fgit_authority::decision_batch_identity(&batch).unwrap();
        node.runtime()
            .block_on(AsyncAuthorityStore::put_if_absent(
                &node.authority,
                request.authority(),
                &fgit_authority::body_key_for_id(batch_id.as_internal_object_id()).unwrap(),
                &fgit_codec::encode_body(&batch).unwrap(),
            ))
            .unwrap();
        head.predecessor_head_id = Some(fgit_authority::authority_head_identity(&head).unwrap());
        head.generation = head.generation.next().unwrap();
        head.decision_tail_id = Some(batch_id);
        let head_bytes = fgit_codec::encode_body(&head).unwrap();
        let head_id = fgit_authority::authority_head_identity(&head).unwrap();
        node.runtime()
            .block_on(AsyncAuthorityStore::put_if_absent(
                &node.authority,
                request.authority(),
                &fgit_authority::body_key_for_id(head_id.as_internal_object_id()).unwrap(),
                &head_bytes,
            ))
            .unwrap();
        assert!(matches!(
            node.runtime()
                .block_on(AsyncAuthorityStore::compare_exchange_head(
                    &node.authority,
                    request.authority(),
                    &node.head_key,
                    before.receipt().token(),
                    head.generation,
                    &head_bytes,
                ))
                .unwrap(),
            fgit_authority::CasOutcome::Committed(_)
        ));

        let selected = authenticated(&node);
        assert!(matches!(
            collected(&node, &selected),
            Err(OutcomeFailure::StreamBodyMissing { link: "head body" })
        ));
        assert_eq!(
            public_lookup(&node, recent.tx_id),
            OutcomeLookup::Decided(recent.terminal)
        );
        assert!(matches!(
            node.runtime()
                .block_on(node.resolve_outcome_in(&request, distinct_tx_id())),
            Err(NodeRefusal::Authority(error))
                if *error == OutcomeFailure::StreamBodyMissing { link: "head body" }
        ));
        assert_eq!(authenticated(&node).receipt(), selected.receipt());
        node.shutdown().unwrap();
    }
}
