//! Retained-leaf outcome-index checkpoints remain authority-verified evidence.

use fgit_authority::{
    AuthorityStore, HeadKey, HeadRead, MemoryAuthorityStore, MemoryStoreConfig, OutcomeFailure,
    StoreInstanceId, TerminalOutcome, authority_head_identity, canonical_outcome_index_decisions,
    collect_cumulative_outcomes, collect_cumulative_outcomes_from_checkpoint,
    decision_batch_identity, initialize_repository, outcome_index_root, publish_decisions,
};
use fgit_chronicle::{
    BackupProfile, CapsuleClosure, LiveCapsuleRefusal, MAX_CHECKPOINT_PREDECESSORS,
    OutcomeIndexCheckpointBody, OutcomeIndexLeafArchive, PublicationBasis, PublicationPlan,
    ResultingRoots, activate_frozen_capsule,
    collect_cumulative_outcomes_from_authenticated_capsule_checkpoint_with_fabric,
    freeze_capsule_with_outcome_index_checkpoint,
};
use fgit_codec::{
    CanonicalBody, CryptoBodyIdentity, DecodeLimits, RepositoryAuthorityHeadBody,
    RepositoryDecision, RepositoryDecisionBatchBody, decode_body, encode_body,
};
use fgit_crypto::IdentityDomain;
use fgit_object_fabric::fabric::{
    ImmutableObjectFabric, ManifestLimits, PlacementAdmission, PutIfAbsent,
};
use fgit_object_fabric::reference::{ReferenceMemoryConfig, ReferenceMemoryFabric};
use fgit_resource::algebra::{Grade, ResourceVector};
use fgit_resource::custody::{LeakDisposition, ObligationLedger};
use fgit_resource::{OpaqueHandle, RegionId};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DecisionOutcome, DecisionSequence, Digest, DigestAlgorithmId,
    DigestBytes, GitHashAlgorithm, HeadGeneration, OPAQUE_ID_LEN, PolicyEpoch, RefusalCode,
    RefusalRecordId, RegistryEpoch, RepositoryDecisionBatchId, RepositoryId, SegmentManifestId,
    TenantId, TxId,
};

const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;

fn digest(tag: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("fixture algorithm is reserved"),
        DigestBytes::try_new(&[tag; 32]).expect("fixture digest is 32 bytes"),
    )
}

macro_rules! derived {
    ($ty:ty, $tag:expr) => {
        <$ty>::from_digest(
            DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
                .expect("fixture algorithm is reserved"),
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[$tag; 32]).expect("fixture digest is 32 bytes"),
        )
    };
}

const fn repository() -> RepositoryId {
    RepositoryId::from_bytes([0x61; OPAQUE_ID_LEN])
}

const fn tenant() -> TenantId {
    TenantId::from_bytes([0x62; OPAQUE_ID_LEN])
}

fn head_key() -> HeadKey {
    HeadKey::new(b"chronicle/outcome-index-checkpoint".to_vec())
        .expect("fixture head key is admissible")
}

fn genesis() -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: repository(),
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: digest(1),
        forge_position_root: digest(2),
        outcome_index_root: outcome_index_root(&[]).expect("empty outcome index is defined"),
        retention_root: digest(3),
        outbox_root: digest(4),
        configuration_root: digest(5),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

const fn roots(basis: &PublicationBasis) -> ResultingRoots {
    ResultingRoots::carried_forward(basis)
}

fn publish_first_refusal(
    store: &MemoryAuthorityStore,
    key: &HeadKey,
) -> (
    fgit_chronicle::VerifiedPublication,
    fgit_authority::HeadReadReceipt,
) {
    let initial = genesis();
    initialize_repository(store, key, &initial).expect("genesis initializes");
    let receipt = match store.read_head(key).expect("genesis reads") {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("initialized genesis is present"),
    };
    let basis = PublicationBasis::new(
        authority_head_identity(&initial).expect("genesis identity"),
        initial,
    );
    let outcomes = collect_cumulative_outcomes(store, key).expect("genesis collects");
    let mut plan = PublicationPlan::open(basis.clone()).expect("genesis opens");
    plan.refuse(
        derived!(TxId, 0x11),
        RefusalCode::QuotaExceeded,
        derived!(RefusalRecordId, 0x12),
    );
    let publication = plan
        .seal(
            &CryptoBodyIdentity,
            roots(&basis),
            &outcomes,
            receipt.token(),
        )
        .expect("a correctly stamped refusal seals");
    publish_decisions(
        store,
        key,
        receipt.token(),
        publication.batch(),
        publication.head(),
        tenant(),
    )
    .expect("first terminal decision publishes");
    let first_receipt = match store.read_head(key).expect("first head reads") {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("published first head is present"),
    };
    (publication, first_receipt)
}

fn closure() -> CapsuleClosure {
    CapsuleClosure {
        object_closure_root: digest(0x31),
        segment_manifest_root: digest(0x32),
        backup_profile: BackupProfile::FullClosure,
    }
}

fn root_of(decisions: &[fgit_codec::RepositoryDecision]) -> Digest {
    outcome_index_root(
        &decisions
            .iter()
            .map(|decision| {
                (
                    decision.tx_id,
                    TerminalOutcome {
                        decision_sequence: decision.decision_sequence,
                        outcome: decision.outcome,
                    },
                )
            })
            .collect::<Vec<_>>(),
    )
    .expect("terminal decisions form an outcome-index root")
}

fn seeded_digest(seed: u64) -> DigestBytes {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_be_bytes());
    bytes[31] = 0x71;
    DigestBytes::try_new(&bytes).expect("fixture digest is 32 bytes")
}

fn leaf_fixture_decisions(count: usize) -> Vec<RepositoryDecision> {
    (0..count)
        .map(|index| {
            let seed = u64::try_from(index).expect("fixture index fits u64") + 1;
            RepositoryDecision {
                tx_id: TxId::from_digest(
                    DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
                        .expect("fixture algorithm is reserved"),
                    CANONICAL_CODEC_VERSION,
                    seeded_digest(seed),
                ),
                decision_sequence: DecisionSequence::try_new(seed)
                    .expect("fixture decision sequence is nonzero"),
                outcome: DecisionOutcome::Refused {
                    code: RefusalCode::QuotaExceeded,
                    refusal_record_id: RefusalRecordId::from_digest(
                        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
                            .expect("fixture algorithm is reserved"),
                        CANONICAL_CODEC_VERSION,
                        seeded_digest(seed ^ 0x4f),
                    ),
                },
            }
        })
        .collect()
}

fn stage_leaf_archive(
    decisions: &[fgit_codec::RepositoryDecision],
) -> (ReferenceMemoryFabric, SegmentManifestId) {
    let archive = OutcomeIndexLeafArchive::prepare(repository(), GitHashAlgorithm::Sha1, decisions)
        .expect("authority-canonical decisions form bounded fabric chunks");
    let fabric = ReferenceMemoryFabric::open(
        ReferenceMemoryConfig::new(
            archive.namespace().to_vec(),
            OpaqueHandle::new(b"outcome-checkpoint-fail-domain")
                .expect("fixture failure domain handle is valid"),
            OpaqueHandle::new(b"outcome-checkpoint-encryption")
                .expect("fixture encryption handle is valid"),
            1 << 20,
            ManifestLimits::default(),
        )
        .expect("reference fabric configuration is valid"),
    )
    .expect("reference fabric opens");
    let ledger = ObligationLedger::root(
        RegionId::new(0x611),
        LeakDisposition::FailFast,
        ResourceVector::single(Grade::Bytes, 1 << 20).with(Grade::Objects, 2_048),
    );
    let mut placement = None;
    for object in archive.objects() {
        let bytes = u64::try_from(object.payload().len()).expect("fixture payload length fits");
        let grant = ledger
            .grant(ResourceVector::single(Grade::Bytes, bytes).with(Grade::Objects, 1))
            .expect("fixture ledger grants object placement");
        let observed = match fabric
            .put_if_absent(object.clone(), PlacementAdmission::new(&ledger, grant))
            .expect("reference fabric stages a verified native blob")
        {
            PutIfAbsent::Created { placement, .. }
            | PutIfAbsent::AlreadyPresent { placement, .. } => placement,
        };
        if let Some(existing) = &placement {
            assert_eq!(
                existing, &observed,
                "one archive uses one reference placement"
            );
        } else {
            placement = Some(observed);
        }
    }
    let manifest = archive
        .manifest(vec![
            placement.expect("the archive contains an explicit empty or leaf chunk"),
        ])
        .expect("staged chunks produce the existing segment manifest");
    let manifest_id = fabric
        .write_manifest(&manifest)
        .expect("reference fabric stages the manifest after its chunks");
    let close = ledger.close();
    assert!(
        close.is_quiescent(),
        "all object-placement obligations settle: {close:?}"
    );
    (fabric, manifest_id)
}

fn stage_immutable_body<B: CanonicalBody>(
    store: &MemoryAuthorityStore,
    domain: IdentityDomain,
    body: &B,
) {
    let key = fgit_authority::body_key(domain, body)
        .expect("fixture immutable body has a deterministic authority key");
    let bytes = encode_body(body).expect("fixture immutable body encodes canonically");
    store
        .put_if_absent(&key, &bytes)
        .expect("fixture immutable body stages exactly once");
}

fn high_capacity_store(instance: StoreInstanceId) -> MemoryAuthorityStore {
    let mut config = MemoryStoreConfig {
        instance,
        ..MemoryStoreConfig::default()
    };
    config.limits.immutable_slots = 1 << 18;
    MemoryAuthorityStore::with_config(config)
}

#[test]
fn manifest_leaf_archive_chunks_canonically_and_reloads_each_verified_blob() {
    let offered = leaf_fixture_decisions(1_025);
    let expected = canonical_outcome_index_decisions(&offered)
        .expect("fixture decisions have unique terminal transaction identities");
    let archive = OutcomeIndexLeafArchive::prepare(repository(), GitHashAlgorithm::Sha1, &offered)
        .expect("canonical fixture decisions form a bounded leaf archive");
    assert_eq!(
        archive.objects().len(),
        2,
        "1,025 retained leaves cross the fixed 1,024-decision chunk boundary"
    );
    let (fabric, leaf_archive_manifest) = stage_leaf_archive(&offered);
    let checkpoint =
        OutcomeIndexCheckpointBody::new(repository(), None, None, None, leaf_archive_manifest)
            .expect("a genesis-position manifest checkpoint is structurally valid");
    assert_eq!(
        fgit_chronicle::load_outcome_index_checkpoint_leaves(&fabric, &checkpoint)
            .expect("the fabric rereads and reconstructs the manifest closure"),
        expected,
        "manifest closure bytes reproduce the authority-owned leaf order"
    );
}

#[test]
fn capsule_bound_checkpoint_replays_only_the_tail_and_preserves_the_root() {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x6161));
    let key = head_key();
    let (publication, first_receipt) = publish_first_refusal(&store, &key);
    let carried = collect_cumulative_outcomes(&store, &key).expect("first decision collects");
    let decisions = carried
        .checkpoint_decisions_against(first_receipt.token())
        .expect("carried decisions remain bound to the first head");
    let (fabric, leaf_archive_manifest) = stage_leaf_archive(&decisions);
    let checkpoint = OutcomeIndexCheckpointBody::new(
        repository(),
        publication.head().decision_tail_id,
        publication.head().latest_decision_sequence,
        None,
        leaf_archive_manifest,
    )
    .expect("authority order forms a checkpoint");

    let frozen = freeze_capsule_with_outcome_index_checkpoint(
        &store,
        &fabric,
        &CryptoBodyIdentity,
        &first_receipt,
        None,
        closure(),
        &checkpoint,
    )
    .expect("checkpoint stages before a capsule binds its digest");
    assert!(
        frozen.capsule().outcome_index_checkpoint_root.is_some(),
        "the capsule binds retained leaves by their checkpoint digest, never by outcome_index_root"
    );
    let activated = activate_frozen_capsule(&store, &first_receipt, &frozen)
        .expect("the capsule pointer advances only after staging");

    let authenticated = store
        .authenticate_head_receipt(activated.head())
        .expect("activated head receipt authenticates");
    let checkpointed =
        collect_cumulative_outcomes_from_authenticated_capsule_checkpoint_with_fabric(
            &store,
            &fabric,
            &CryptoBodyIdentity,
            &key,
            &authenticated,
        )
        .expect("a capsule-bound checkpoint is usable evidence");
    assert_eq!(
        checkpointed
            .checkpoint_decisions_against(activated.head().token())
            .expect("checkpointed leaves stay token-bound"),
        decisions,
        "no tail means the checkpoint leaves exactly reproduce the cumulative index"
    );
    assert_eq!(
        root_of(&publication.batch().decisions),
        publication.head().outcome_index_root,
        "the retained leaf set preserves the existing outcome-index commitment"
    );

    let activated_head: RepositoryAuthorityHeadBody =
        decode_body(activated.head().body(), DecodeLimits::DEFAULT)
            .expect("activated receipt carries a canonical head");
    let activated_basis = PublicationBasis::new(
        authority_head_identity(&activated_head).expect("activated head identity"),
        activated_head,
    );
    let mut tail_plan =
        PublicationPlan::open(activated_basis.clone()).expect("activated head opens");
    tail_plan.refuse(
        derived!(TxId, 0x21),
        RefusalCode::ProtectedRefTransitionDenied,
        derived!(RefusalRecordId, 0x22),
    );
    let tail_publication = tail_plan
        .seal(
            &CryptoBodyIdentity,
            roots(&activated_basis),
            &checkpointed,
            activated.head().token(),
        )
        .expect("a post-checkpoint terminal decision seals");
    publish_decisions(
        &store,
        &key,
        activated.head().token(),
        tail_publication.batch(),
        tail_publication.head(),
        tenant(),
    )
    .expect("the post-checkpoint tail publishes");
    let tail_receipt = match store.read_head(&key).expect("tail head reads") {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("published tail head is present"),
    };
    let authenticated_tail = store
        .authenticate_head_receipt(&tail_receipt)
        .expect("tail head receipt authenticates");
    let folded_tail =
        collect_cumulative_outcomes_from_authenticated_capsule_checkpoint_with_fabric(
            &store,
            &fabric,
            &CryptoBodyIdentity,
            &key,
            &authenticated_tail,
        )
        .expect("checkpoint leaves plus the new tail collect");
    let folded_decisions = folded_tail
        .checkpoint_decisions_against(tail_receipt.token())
        .expect("folded checkpoint-plus-tail decisions remain token-bound");
    assert_eq!(
        folded_decisions.len(),
        2,
        "exactly the retained leaf and tail remain"
    );
    assert_eq!(
        root_of(&folded_decisions),
        tail_publication.head().outcome_index_root,
        "checkpoint leaves plus a tail produce the same committed outcome-index root"
    );
}

#[test]
fn capsule_terminated_fold_crosses_the_replay_bound_and_matches_the_direct_leaf_oracle() {
    let store = high_capacity_store(StoreInstanceId::from_raw(0x6261));
    let key = head_key();
    let (checkpoint_publication, first_receipt) = publish_first_refusal(&store, &key);
    let checkpoint_outcomes =
        collect_cumulative_outcomes(&store, &key).expect("first decision collects from genesis");
    let checkpoint_decisions = checkpoint_outcomes
        .checkpoint_decisions_against(first_receipt.token())
        .expect("the checkpoint source is tied to its exact head");
    let (fabric, leaf_archive_manifest) = stage_leaf_archive(&checkpoint_decisions);
    let checkpoint = OutcomeIndexCheckpointBody::new(
        repository(),
        checkpoint_publication.head().decision_tail_id,
        checkpoint_publication.head().latest_decision_sequence,
        None,
        leaf_archive_manifest,
    )
    .expect("checkpoint position and fabric manifest pair");
    let frozen = freeze_capsule_with_outcome_index_checkpoint(
        &store,
        &fabric,
        &CryptoBodyIdentity,
        &first_receipt,
        None,
        closure(),
        &checkpoint,
    )
    .expect("checkpoint archive stages before its capsule");
    let activated = activate_frozen_capsule(&store, &first_receipt, &frozen)
        .expect("the capsule becomes visible through an exact-head CAS");
    let mut prior: RepositoryAuthorityHeadBody =
        decode_body(activated.head().body(), DecodeLimits::DEFAULT)
            .expect("activation receipt carries a canonical authority head");
    let mut prior_id = authority_head_identity(&prior).expect("activation head has an identity");

    let mut tail = leaf_fixture_decisions(fgit_authority::MAX_REPLAY_BATCHES);
    for (index, decision) in tail.iter_mut().enumerate() {
        decision.decision_sequence =
            DecisionSequence::try_new(u64::try_from(index).expect("fixture index fits") + 2)
                .expect("tail decision sequence is nonzero");
    }
    let mut direct = checkpoint_decisions.clone();
    direct.extend(tail.clone());
    let expected_root = root_of(&direct);

    for (index, decision) in tail.into_iter().enumerate() {
        let is_final_tail_batch = index + 1 == fgit_authority::MAX_REPLAY_BATCHES;
        let resulting_outcome_index_root = if is_final_tail_batch {
            expected_root
        } else {
            prior.outcome_index_root
        };
        let mut batch = RepositoryDecisionBatchBody {
            repository_id: repository(),
            predecessor_head_id: prior_id,
            predecessor_head_generation: prior.generation,
            first_decision_sequence: decision.decision_sequence,
            decisions: vec![decision],
            committed_rcrs: Vec::new(),
            resulting_ref_root: prior.ref_root,
            resulting_forge_position_root: prior.forge_position_root,
            resulting_outcome_index_root,
            resulting_retention_root: prior.retention_root,
            resulting_outbox_root: prior.outbox_root,
            resulting_policy_epoch: prior.policy_epoch,
            batch_evidence_root: digest(0xa1),
            compaction_generation_link: None,
        };
        batch.batch_evidence_root =
            fgit_chronicle::batch_evidence_root(&batch).expect("one refusal has batch evidence");
        let batch_id = decision_batch_identity(&batch).expect("tail batch has an identity");
        stage_immutable_body(&store, IdentityDomain::RepositoryDecisionBatch, &batch);
        let next = RepositoryAuthorityHeadBody {
            repository_id: repository(),
            generation: prior
                .generation
                .next()
                .expect("fixture generation stays within the type bound"),
            predecessor_head_id: Some(prior_id),
            decision_tail_id: Some(batch_id),
            latest_decision_sequence: Some(batch.first_decision_sequence),
            latest_committed_rcr_id: prior.latest_committed_rcr_id,
            latest_repository_sequence: prior.latest_repository_sequence,
            ref_root: prior.ref_root,
            forge_position_root: prior.forge_position_root,
            outcome_index_root: resulting_outcome_index_root,
            retention_root: prior.retention_root,
            outbox_root: prior.outbox_root,
            configuration_root: prior.configuration_root,
            policy_epoch: prior.policy_epoch,
            format_registry_epoch: prior.format_registry_epoch,
            last_checkpoint_id: Some(frozen.capsule_id()),
        };
        stage_immutable_body(&store, IdentityDomain::RepositoryAuthorityHead, &next);
        prior_id = authority_head_identity(&next).expect("tail head has an identity");
        prior = next;
    }

    let final_bytes = encode_body(&prior).expect("final tail head encodes canonically");
    assert!(matches!(
        store
            .compare_exchange_head(
                &key,
                activated.head().token(),
                prior.generation,
                &final_bytes,
            )
            .expect("final fixture head CAS is available"),
        fgit_authority::CasOutcome::Committed(_)
    ));
    let final_receipt = match store.read_head(&key).expect("final head reads") {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("final fixture head is present"),
    };
    let authenticated = store
        .authenticate_head_receipt(&final_receipt)
        .expect("final head receipt authenticates");
    let folded = collect_cumulative_outcomes_from_authenticated_capsule_checkpoint_with_fabric(
        &store,
        &fabric,
        &CryptoBodyIdentity,
        &key,
        &authenticated,
    )
    .expect("capsule checkpoint limits replay to exactly MAX_REPLAY_BATCHES tail batches");
    let folded_decisions = folded
        .checkpoint_decisions_against(final_receipt.token())
        .expect("fold result remains bound to the final authority head");
    assert_eq!(
        folded_decisions.len(),
        fgit_authority::MAX_REPLAY_BATCHES + 1,
        "the history is longer than the from-genesis replay bound"
    );
    assert_eq!(
        root_of(&folded_decisions),
        expected_root,
        "checkpoint leaves plus the bounded tail match the direct complete-leaf oracle"
    );
}

#[test]
fn checkpoint_with_wrong_leaves_cannot_be_capsule_bound_at_a_real_position() {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x6262));
    let key = head_key();
    let (publication, first_receipt) = publish_first_refusal(&store, &key);
    let (fabric, leaf_archive_manifest) = stage_leaf_archive(&[]);
    let wrong = OutcomeIndexCheckpointBody::new(
        repository(),
        publication.head().decision_tail_id,
        publication.head().latest_decision_sequence,
        None,
        leaf_archive_manifest,
    )
    .expect("an empty retained set is structurally canonical");

    assert!(matches!(
        freeze_capsule_with_outcome_index_checkpoint(
            &store,
            &fabric,
            &CryptoBodyIdentity,
            &first_receipt,
            None,
            closure(),
            &wrong,
        ),
        Err(LiveCapsuleRefusal::OutcomeIndexCheckpointPosition(error))
            if matches!(*error, OutcomeFailure::CheckpointRootMismatch)
    ));
}

#[test]
fn checkpoint_collector_refuses_same_tail_with_a_different_sequence() {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x6363));
    let key = head_key();
    let (publication, first_receipt) = publish_first_refusal(&store, &key);
    let carried = collect_cumulative_outcomes(&store, &key).expect("first decision collects");
    let decisions = carried
        .checkpoint_decisions_against(first_receipt.token())
        .expect("first decisions remain token-bound");

    assert!(matches!(
        collect_cumulative_outcomes_from_checkpoint(
            &store,
            &key,
            &decisions,
            publication.head().decision_tail_id,
            None,
        ),
        Err(OutcomeFailure::CheckpointPositionMismatch)
    ));
}

#[test]
fn checkpoint_collector_refuses_when_no_batch_precedes_the_checkpoint() {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x6464));
    let key = head_key();
    initialize_repository(&store, &key, &genesis()).expect("genesis initializes");
    let unreachable_tail = derived!(RepositoryDecisionBatchId, 0x65);

    assert!(matches!(
        collect_cumulative_outcomes_from_checkpoint(
            &store,
            &key,
            &[],
            Some(unreachable_tail),
            None,
        ),
        Err(OutcomeFailure::CheckpointPositionMismatch)
    ));
}

#[test]
fn checkpoint_collector_refuses_a_tail_outside_the_head_ancestry() {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x6565));
    let key = head_key();
    let (publication, first_receipt) = publish_first_refusal(&store, &key);
    let carried = collect_cumulative_outcomes(&store, &key).expect("first decision collects");
    let decisions = carried
        .checkpoint_decisions_against(first_receipt.token())
        .expect("first decisions remain token-bound");
    let unreachable_tail = derived!(RepositoryDecisionBatchId, 0x66);

    assert!(matches!(
        collect_cumulative_outcomes_from_checkpoint(
            &store,
            &key,
            &decisions,
            Some(unreachable_tail),
            publication.head().latest_decision_sequence,
        ),
        Err(OutcomeFailure::CheckpointPositionMismatch)
    ));
}

#[test]
fn checkpoint_collector_refuses_position_matched_wrong_leaves() {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x6666));
    let key = head_key();
    let (publication, _) = publish_first_refusal(&store, &key);

    assert!(matches!(
        collect_cumulative_outcomes_from_checkpoint(
            &store,
            &key,
            &[],
            publication.head().decision_tail_id,
            publication.head().latest_decision_sequence,
        ),
        Err(OutcomeFailure::CheckpointRootMismatch)
    ));
}

#[test]
fn production_checkpoint_predecessor_bound_is_spec_pinned() {
    assert_eq!(MAX_CHECKPOINT_PREDECESSORS, 65_536);
}
