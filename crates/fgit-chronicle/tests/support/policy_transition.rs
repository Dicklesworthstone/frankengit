//! Real reference authority and canonical bodies for policy-transition tests.

use fgit_authority::{
    AuthenticatedHead, AuthorityStore, CapabilityRevocationEpochTransition,
    CapabilityRevocationGenerationBody, CumulativeOutcomes, HeadKey, HeadRead,
    MemoryAuthorityStore, StoreInstanceId, authority_head_identity, collect_cumulative_outcomes,
    initialize_repository, outcome_index_root, prepare_capability_revocation_epoch_transition,
    stage_capability_revocation_generation,
    stage_revocation_aware_repository_incarnation_configuration,
};
use fgit_chronicle::{PublicationBasis, PublicationPlan, ResultingRoots};
use fgit_codec::{
    RepositoryAuthorityHeadBody, RepositoryCommitRecord, RepositoryIncarnationConfigurationBodyV2_2,
};
use fgit_crypto::IdentityDomain;
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestBytes, GitHashAlgorithm, HeadGeneration, PolicyEpoch,
    PrincipalSnapshotId, RegistryEpoch, RepositoryId, RepositoryIncarnationId, RepositorySequence,
    RootLayoutVersion, TenantId, TxId,
};

pub const TENANT: TenantId = TenantId::from_bytes([0x91; 16]);
pub const REPOSITORY: RepositoryId = RepositoryId::from_bytes([0x92; 16]);

pub fn digest(marker: u8) -> Digest {
    Digest::new(
        IdentityDomain::Generation.algorithm().id(),
        DigestBytes::try_new(&[marker; 32]).expect("fixed-width digest"),
    )
}

pub fn tx(marker: u8) -> TxId {
    TxId::from_digest(
        digest(marker).algorithm(),
        CANONICAL_CODEC_VERSION,
        *digest(marker).bytes(),
    )
}

pub struct Current {
    pub authenticated: AuthenticatedHead,
    pub basis: PublicationBasis,
    pub cumulative: CumulativeOutcomes,
}

pub struct Fixture {
    pub store: MemoryAuthorityStore,
    pub key: HeadKey,
}

impl Fixture {
    pub fn new(revocation_enabled: bool) -> Self {
        let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x902));
        let incarnation = RepositoryIncarnationId::from_bytes([0x93; 16]);
        let generation = CapabilityRevocationGenerationBody::try_new(
            TENANT,
            REPOSITORY,
            incarnation,
            PolicyEpoch::FIRST,
            None,
            vec![[1; 16], [9; 16], [0xfe; 16]],
            digest(0x94),
        )
        .expect("bounded full generation");
        let revocation_root = revocation_enabled.then(|| {
            stage_capability_revocation_generation(&store, &generation)
                .expect("stage generation")
                .generation_root()
        });
        let configuration = RepositoryIncarnationConfigurationBodyV2_2 {
            root_layout: RootLayoutVersion::RefStateAndObjectClosureMerkleV1,
            object_format: GitHashAlgorithm::Sha256,
            repository_incarnation_id: incarnation,
            policy_root: Some(digest(0x95)),
            capability_revocation_root: revocation_root,
        };
        let configuration_root =
            stage_revocation_aware_repository_incarnation_configuration(&store, &configuration)
                .expect("stage configuration");
        let head = RepositoryAuthorityHeadBody {
            repository_id: REPOSITORY,
            generation: HeadGeneration::FIRST,
            predecessor_head_id: None,
            decision_tail_id: None,
            latest_decision_sequence: None,
            latest_committed_rcr_id: None,
            latest_repository_sequence: None,
            ref_root: digest(0x10),
            forge_position_root: digest(0x11),
            outcome_index_root: outcome_index_root(&[]).expect("empty outcomes"),
            retention_root: digest(0x13),
            outbox_root: digest(0x14),
            configuration_root,
            policy_epoch: PolicyEpoch::FIRST,
            format_registry_epoch: RegistryEpoch::FIRST,
            last_checkpoint_id: None,
        };
        let key = HeadKey::new(b"chronicle/policy-transition".to_vec()).expect("head key");
        initialize_repository(&store, &key, &head).expect("initialize authority");
        Self { store, key }
    }

    pub fn current(&self) -> Current {
        let HeadRead::Present(receipt) = self.store.read_head(&self.key).expect("current head")
        else {
            panic!("initialized head exists");
        };
        let authenticated = self
            .store
            .authenticate_head_receipt(&receipt)
            .expect("authenticate current");
        let body = authenticated.body().expect("canonical head");
        let basis = PublicationBasis::new(authority_head_identity(&body).expect("head ID"), body);
        let cumulative =
            collect_cumulative_outcomes(&self.store, &self.key).expect("actual outcome witness");
        Current {
            authenticated,
            basis,
            cumulative,
        }
    }

    pub fn transition(
        &self,
        current: &Current,
        event: Digest,
    ) -> CapabilityRevocationEpochTransition {
        prepare_capability_revocation_epoch_transition(
            &self.store,
            TENANT,
            &current.authenticated,
            current
                .basis
                .body()
                .policy_epoch
                .next()
                .expect("next epoch"),
            event,
        )
        .expect("exact carry-forward")
        .expect("explicit generation")
    }
}

pub fn roots(current: &Current, marker: u8) -> ResultingRoots {
    ResultingRoots {
        forge_position_root: digest(marker),
        outbox_root: digest(marker.wrapping_add(1)),
        policy_epoch: current
            .basis
            .body()
            .policy_epoch
            .next()
            .expect("next epoch"),
        ..ResultingRoots::carried_forward(&current.basis)
    }
}

pub fn record(current: &Current, marker: u8, event: Digest) -> RepositoryCommitRecord {
    let resulting = roots(current, marker);
    RepositoryCommitRecord {
        repository_id: REPOSITORY,
        repository_sequence: RepositorySequence::FIRST,
        parent_rcr_id: None,
        tx_id: tx(marker),
        principal_snapshot_id: PrincipalSnapshotId::from_digest(
            digest(marker).algorithm(),
            CANONICAL_CODEC_VERSION,
            *digest(marker).bytes(),
        ),
        canonical_request_digest: digest(marker),
        ref_delta_root: digest(marker),
        resulting_ref_root: resulting.ref_root,
        object_closure_root: digest(marker),
        forge_event_batch_root: event,
        resulting_forge_position_root: resulting.forge_position_root,
        policy_epoch: current.basis.body().policy_epoch,
        policy_decision_root: digest(marker),
        invariant_evidence_root: digest(marker),
        outbox_effect_root: digest(marker),
        retention_delta_root: digest(marker),
    }
}

pub fn plan(current: &Current, marker: u8, event: Digest) -> PublicationPlan {
    let mut plan = PublicationPlan::open(current.basis.clone()).expect("open exact basis");
    plan.commit(record(current, marker, event));
    plan
}
