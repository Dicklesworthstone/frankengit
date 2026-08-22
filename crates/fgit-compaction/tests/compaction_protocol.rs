//! Acceptance coverage for FG-079's decision-log and segment-compaction slice.

use fgit_authority::{
    AuthorityStore, HeadKey, HeadRead, MemoryAuthorityStore, StoreInstanceId,
    authority_head_identity, initialize_repository,
};
use fgit_chronicle::{PublicationBasis, PublicationPlan, ResultingRoots};
use fgit_codec::schema::{RepositoryAuthorityHeadBody, RepositoryCommitRecord};
use fgit_codec::{CryptoBodyIdentity, DecodeLimits, decode_body, encode_body};
use fgit_compaction::{
    CompactionAlgorithm, CompactionExecution, CompactionOutputs, CompactionProfile,
    CompactionPublicationRefusal, CompactionRecord, DecisionRange, DurabilityReceipt,
    DurabilityRefusal, LogicalEquivalenceProof, OutputDisposition, OutputStageReceipt, SourceEntry,
    SourceOutputTotalityMap, StagedCompaction, TotalityEntry,
};
use fgit_object_fabric::fabric::{
    AuthenticatedRetentionRegistry, PublicationState, RetentionRootProposal, StoreRefusal,
};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DecisionSequence, Digest, DigestAlgorithmId, DigestBytes, GitOid,
    GitOidSha1, HeadGeneration, OPAQUE_ID_LEN, PolicyEpoch, PrincipalSnapshotId, RegistryEpoch,
    RepositoryAuthorityHeadId, RepositoryId, RepositorySequence, SegmentManifestId, TenantId, TxId,
};

macro_rules! derived {
    ($ty:ty, $tag:expr) => {
        <$ty>::from_digest(
            DigestAlgorithmId::try_new(1).expect("algorithm code point one is present"),
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[$tag; 32]).expect("fixture digest width is valid"),
        )
    };
}

fn digest(tag: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(1).expect("algorithm code point one is present"),
        DigestBytes::try_new(&[tag; 32]).expect("fixture digest width is valid"),
    )
}

const fn repository() -> RepositoryId {
    RepositoryId::from_bytes([0x71; OPAQUE_ID_LEN])
}

const fn tenant() -> TenantId {
    TenantId::from_bytes([0x72; OPAQUE_ID_LEN])
}

const fn object() -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([0x73; GitOidSha1::LEN]))
}

fn genesis_head() -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: repository(),
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: digest(0x10),
        forge_position_root: digest(0x11),
        outcome_index_root: digest(0x12),
        retention_root: digest(0x13),
        outbox_root: digest(0x14),
        configuration_root: digest(0x15),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

fn basis() -> PublicationBasis {
    let head = genesis_head();
    let identity = authority_head_identity(&head).expect("genesis head identifies");
    PublicationBasis::new(identity, head)
}

fn record(input: &PublicationBasis) -> CompactionRecord {
    let manifest = derived!(SegmentManifestId, 0x51);
    CompactionRecord {
        input_head: input.id(),
        input_head_generation: input.generation(),
        decision_range: DecisionRange::new(DecisionSequence::FIRST, DecisionSequence::FIRST)
            .expect("one decision is an increasing range"),
        input_segment_root: digest(0x20),
        input_decision_root: digest(0x21),
        algorithm: CompactionAlgorithm::DeterministicReencodeV1,
        profile: CompactionProfile::ConservativeInterimV1,
        toolchain_fingerprint: digest(0x22),
        outputs: CompactionOutputs {
            pack_roots: vec![digest(0x30)],
            segment_manifests: vec![manifest],
            index_roots: vec![digest(0x31)],
        },
        equivalence_proof: LogicalEquivalenceProof::construct(
            digest(0x40),
            digest(0x40),
            digest(0x41),
        )
        .expect("equal reconstructed logical roots prove equivalence"),
        totality: SourceOutputTotalityMap::new(vec![
            TotalityEntry {
                source: SourceEntry::Object(object()),
                disposition: OutputDisposition::Stored {
                    pack_root: digest(0x30),
                    segment_manifest: manifest,
                },
            },
            TotalityEntry {
                source: SourceEntry::Decision(DecisionSequence::FIRST),
                disposition: OutputDisposition::DocumentedDrop {
                    evidence_root: digest(0x42),
                },
            },
        ])
        .expect("each source is accounted for once"),
        resource_receipt_root: digest(0x43),
        rejected_layout_evidence_root: digest(0x44),
    }
}

fn stage(input: &PublicationBasis) -> StagedCompaction {
    StagedCompaction::stage(
        record(input),
        OutputStageReceipt::new(vec![PublicationState::new(true, false, false); 3])
            .expect("all physical outputs are staged"),
    )
    .expect("well-formed staged compaction")
}

fn roots(evidence: Digest) -> ResultingRoots {
    ResultingRoots {
        ref_root: digest(0x10),
        forge_position_root: digest(0x11),
        outcome_index_root: digest(0x12),
        retention_root: digest(0x13),
        outbox_root: digest(0x14),
        policy_epoch: PolicyEpoch::FIRST,
        batch_evidence_root: evidence,
    }
}

fn commit_record(evidence: Digest) -> RepositoryCommitRecord {
    RepositoryCommitRecord {
        repository_id: repository(),
        repository_sequence: RepositorySequence::FIRST,
        parent_rcr_id: None,
        tx_id: derived!(TxId, 0x61),
        principal_snapshot_id: derived!(PrincipalSnapshotId, 0x62),
        canonical_request_digest: digest(0x63),
        ref_delta_root: digest(0x64),
        resulting_ref_root: digest(0x10),
        object_closure_root: digest(0x65),
        forge_event_batch_root: digest(0x66),
        resulting_forge_position_root: digest(0x11),
        policy_epoch: PolicyEpoch::FIRST,
        policy_decision_root: digest(0x67),
        invariant_evidence_root: evidence,
        outbox_effect_root: digest(0x68),
        retention_delta_root: digest(0x69),
    }
}

fn publication(
    input: PublicationBasis,
    staged: &StagedCompaction,
) -> fgit_chronicle::VerifiedPublication {
    let mut plan = PublicationPlan::open(input).expect("authenticated basis opens a plan");
    plan.commit(commit_record(staged.evidence_root()));
    plan.seal(&CryptoBodyIdentity, roots(staged.evidence_root()))
        .expect("ordinary compaction decision is well formed")
}

fn current_token(
    store: &MemoryAuthorityStore,
    head_key: &HeadKey,
) -> fgit_authority::AuthorityVersionToken {
    match store
        .read_head(head_key)
        .expect("reference head read succeeds")
    {
        HeadRead::Present(receipt) => receipt.token(),
        HeadRead::Absent => panic!("genesis head was initialized"),
    }
}

#[derive(Clone, Copy)]
struct RetentionRegistry {
    head: RepositoryAuthorityHeadId,
    permits: bool,
}

impl AuthenticatedRetentionRegistry for RetentionRegistry {
    fn revalidate_root(&self, proposal: &RetentionRootProposal) -> Result<(), StoreRefusal> {
        if proposal.authority_head() == self.head {
            Ok(())
        } else {
            Err(StoreRefusal::RetentionRevalidationFailed)
        }
    }

    fn permits_placement_deletion(&self, _object: GitOid) -> Result<(), StoreRefusal> {
        if self.permits {
            Ok(())
        } else {
            Err(StoreRefusal::DeletionRetained)
        }
    }
}

#[test]
fn record_codec_binds_every_input_output_and_evidence_field() {
    let input = basis();
    let expected = record(&input);
    let bytes = encode_body(&expected).expect("record encodes canonically");
    let actual: CompactionRecord =
        decode_body(&bytes, DecodeLimits::DEFAULT).expect("record decodes canonically");

    assert_eq!(actual, expected);
    assert_eq!(
        actual
            .generation_id(&CryptoBodyIdentity)
            .expect("registered generation domain identifies"),
        expected
            .generation_id(&CryptoBodyIdentity)
            .expect("same canonical record has the same generation"),
        "every compaction input, proof, output, and receipt participates in the generation identity"
    );
}

#[test]
fn interrupted_output_or_unpublished_staging_leaves_the_old_authority_head_complete() {
    let input = basis();
    let head_key = HeadKey::new(b"fg079/crash-head".to_vec()).expect("bounded head key");
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x79));
    initialize_repository(&store, &head_key, input.body()).expect("genesis initializes");
    let before = store
        .read_head(&head_key)
        .expect("head read before staging");

    let interrupted = StagedCompaction::stage(
        record(&input),
        OutputStageReceipt::new(vec![PublicationState::new(true, false, false); 2])
            .expect("partial output reports only what was staged"),
    );
    assert!(matches!(
        interrupted,
        Err(CompactionPublicationRefusal::OutputReceiptCardinality)
    ));
    assert_eq!(
        store.read_head(&head_key).expect("head remains readable"),
        before,
        "a crash while producing outputs cannot create a partial authority state"
    );

    let _staged_but_unpublished = stage(&input);
    assert_eq!(
        store.read_head(&head_key).expect("head remains readable"),
        before,
        "outputs staged before the CAS remain noncanonical after a crash"
    );
}

#[test]
fn ordinary_decision_makes_complete_generation_visible_then_durable_retention_controls_deletion() {
    let input = basis();
    let staged = stage(&input);
    let publication = publication(input.clone(), &staged);
    let head_key = HeadKey::new(b"fg079/visible-head".to_vec()).expect("bounded head key");
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x7a));
    initialize_repository(&store, &head_key, input.body()).expect("genesis initializes");

    let visible = match staged.publish(
        &store,
        &head_key,
        current_token(&store, &head_key),
        &publication,
        tenant(),
    ) {
        CompactionExecution::Visible(visible) => visible,
        other => panic!("ordinary decision must publish the staged generation: {other:?}"),
    };
    let current = match store.read_head(&head_key).expect("head read after publish") {
        HeadRead::Present(receipt) => {
            decode_body::<RepositoryAuthorityHeadBody>(receipt.body(), DecodeLimits::DEFAULT)
                .expect("published head remains a complete canonical body")
        }
        HeadRead::Absent => panic!("successful CAS cannot remove a head"),
    };
    assert_eq!(current.ref_root, input.body().ref_root);
    assert_eq!(
        current.forge_position_root,
        input.body().forge_position_root
    );
    assert_eq!(current.retention_root, input.body().retention_root);
    assert_eq!(
        publication.batch().batch_evidence_root,
        visible.evidence_root(),
        "the ordinary batch carries the compaction generation as evidence"
    );

    let not_durable = visible.confirm_durability(DurabilityReceipt::new(
        visible.generation(),
        CompactionProfile::ConservativeInterimV1,
        vec![PublicationState::new(true, true, false); 3],
        digest(0x81),
    ));
    assert_eq!(not_durable, Err(DurabilityRefusal::OutputNotDurable));

    let durable = visible
        .confirm_durability(DurabilityReceipt::new(
            visible.generation(),
            CompactionProfile::ConservativeInterimV1,
            vec![PublicationState::new(true, true, true); 3],
            digest(0x82),
        ))
        .expect("only all durable outputs unlock retention evaluation");
    let proposal = RetentionRootProposal::new(
        visible.successor_head(),
        current.retention_root,
        vec![derived!(SegmentManifestId, 0x51)],
    );
    let proposal = match proposal {
        Ok(proposal) => proposal,
        Err(error) => panic!("one manifest is canonical: {error}"),
    };
    let permit = durable
        .authorize_source_deletion(
            &RetentionRegistry {
                head: visible.successor_head(),
                permits: true,
            },
            &proposal,
            object(),
        )
        .expect("only authenticated retention may permit deletion");
    assert_eq!(permit.source(), object());
}

#[test]
fn publication_without_rcr_evidence_link_stays_staged_even_when_batch_evidence_matches() {
    let input = basis();
    let staged = stage(&input);
    let mut plan = PublicationPlan::open(input.clone()).expect("basis opens a plan");
    plan.commit(commit_record(digest(0x91)));
    let publication = plan
        .seal(&CryptoBodyIdentity, roots(staged.evidence_root()))
        .expect("the generic batch itself is valid");
    let head_key = HeadKey::new(b"fg079/no-rcr-link".to_vec()).expect("bounded head key");
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x7b));
    initialize_repository(&store, &head_key, input.body()).expect("genesis initializes");
    let before = store
        .read_head(&head_key)
        .expect("head before rejected publish");

    match staged.publish(
        &store,
        &head_key,
        current_token(&store, &head_key),
        &publication,
        tenant(),
    ) {
        CompactionExecution::Unpublished(unpublished) => assert_eq!(
            unpublished.reason(),
            &CompactionPublicationRefusal::RcrEvidenceLinkMissing
        ),
        other => panic!("unlinked record must never become visible: {other:?}"),
    }
    assert_eq!(
        store
            .read_head(&head_key)
            .expect("head after rejected publish"),
        before,
        "rejecting an unlinked generation happens before the authority CAS"
    );
}
