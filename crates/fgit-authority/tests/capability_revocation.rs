#![forbid(unsafe_code)]
//! Public-path tests for canonical, authority-selected capability revocation.

use fgit_authority::{
    AuthorityFailure, AuthorityRefusal, AuthorityStore, CapabilityRevocationAuthorityFailure,
    CapabilityRevocationBodyRefusal, CapabilityRevocationGenerationBody, HeadInit, HeadKey,
    MemoryAuthorityStore, StoreInstanceId, body_key_for_id, initialize_repository,
    outcome_index_root, read_capability_revocation_generation_by_id,
    read_head_selected_capability_revocation_generation, stage_capability_revocation_generation,
    stage_latest_repository_incarnation_configuration,
    stage_revocation_aware_repository_incarnation_configuration,
};
use fgit_codec::{
    RepositoryAuthorityHeadBody, RepositoryIncarnationConfigurationBodyV2_1,
    RepositoryIncarnationConfigurationBodyV2_2, encode_body,
};
use fgit_types::{
    Digest, DigestBytes, HeadGeneration, PolicyEpoch, RegistryEpoch, RepositoryId,
    RepositoryIncarnationId, RootLayoutVersion, TenantId,
};

const fn tenant(byte: u8) -> TenantId {
    TenantId::from_bytes([byte; 16])
}

const fn repository(byte: u8) -> RepositoryId {
    RepositoryId::from_bytes([byte; 16])
}

const fn incarnation(byte: u8) -> RepositoryIncarnationId {
    RepositoryIncarnationId::from_bytes([byte; 16])
}

fn digest(byte: u8) -> Digest {
    let root = outcome_index_root(&[]).expect("empty outcome-index root is canonical");
    Digest::new(
        root.algorithm(),
        DigestBytes::try_new(&[byte; 32]).expect("fixed-width digest"),
    )
}

fn revocations(
    tenant_id: TenantId,
    repository_id: RepositoryId,
    repository_incarnation_id: RepositoryIncarnationId,
    policy_epoch: PolicyEpoch,
    ids: Vec<[u8; 16]>,
) -> CapabilityRevocationGenerationBody {
    CapabilityRevocationGenerationBody::try_new(
        tenant_id,
        repository_id,
        repository_incarnation_id,
        policy_epoch,
        None,
        ids,
        digest(0x91),
    )
    .expect("bounded unique revocation body")
}

fn head(
    repository_id: RepositoryId,
    policy_epoch: PolicyEpoch,
    configuration_root: Digest,
) -> RepositoryAuthorityHeadBody {
    let root = outcome_index_root(&[]).expect("empty outcome-index root is canonical");
    RepositoryAuthorityHeadBody {
        repository_id,
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: root,
        forge_position_root: root,
        outcome_index_root: root,
        retention_root: root,
        outbox_root: root,
        configuration_root,
        policy_epoch,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

fn authenticated_head(
    store: &MemoryAuthorityStore,
    store_id: u64,
    body: &RepositoryAuthorityHeadBody,
) -> fgit_authority::AuthenticatedHead {
    let key = HeadKey::new(format!("capability-revocation-head-{store_id}").into_bytes())
        .expect("bounded head key");
    let receipt =
        match initialize_repository(store, &key, body).expect("repository head initializes") {
            HeadInit::Created(receipt) => receipt,
            HeadInit::IdenticalRetry(_) | HeadInit::Conflict => {
                panic!("fresh store must create the head")
            }
        };
    store
        .authenticate_head_receipt(&receipt)
        .expect("the issuing store authenticates its head")
}

fn selected_fixture(
    store_id: u64,
    body: &CapabilityRevocationGenerationBody,
    configuration_incarnation: RepositoryIncarnationId,
    head_repository: RepositoryId,
    head_policy_epoch: PolicyEpoch,
) -> (MemoryAuthorityStore, fgit_authority::AuthenticatedHead) {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(store_id));
    let stage =
        stage_capability_revocation_generation(&store, body).expect("revocation generation stages");
    let configuration = RepositoryIncarnationConfigurationBodyV2_2 {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: fgit_types::GitHashAlgorithm::Sha256,
        repository_incarnation_id: configuration_incarnation,
        policy_root: None,
        capability_revocation_root: Some(stage.generation_root()),
    };
    let configuration_root =
        stage_revocation_aware_repository_incarnation_configuration(&store, &configuration)
            .expect("revocation-aware configuration stages");
    let authenticated = authenticated_head(
        &store,
        store_id,
        &head(head_repository, head_policy_epoch, configuration_root),
    );
    (store, authenticated)
}

#[test]
fn generation_identity_is_order_independent_and_round_trips() {
    let first = revocations(
        tenant(0x11),
        repository(0x22),
        incarnation(0x33),
        PolicyEpoch::FIRST,
        vec![[0x02; 16], [0x01; 16]],
    );
    let second = revocations(
        tenant(0x11),
        repository(0x22),
        incarnation(0x33),
        PolicyEpoch::FIRST,
        vec![[0x01; 16], [0x02; 16]],
    );
    assert_eq!(first, second);
    assert_eq!(
        first.generation_id().expect("first identity"),
        second.generation_id().expect("second identity")
    );

    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(201));
    let stage = stage_capability_revocation_generation(&store, &first)
        .expect("canonical generation stages");
    let retry = stage_capability_revocation_generation(&store, &second)
        .expect("byte-identical retry is accepted");
    assert_eq!(stage.generation_id(), retry.generation_id());
    assert_eq!(retry.outcome(), fgit_authority::PutOutcome::IdenticalRetry);

    let read = read_capability_revocation_generation_by_id(&store, stage.generation_id())
        .expect("generation re-identifies");
    assert_eq!(read.body(), &first);
    assert_eq!(read.generation_root(), stage.generation_root());
}

#[test]
fn duplicate_and_over_bound_snapshots_are_refused() {
    assert_eq!(
        CapabilityRevocationGenerationBody::try_new(
            tenant(0x11),
            repository(0x22),
            incarnation(0x33),
            PolicyEpoch::FIRST,
            None,
            vec![[0x01; 16], [0x01; 16]],
            digest(0x91),
        )
        .expect_err("duplicates are not silently collapsed"),
        CapabilityRevocationBodyRefusal::DuplicateCapabilityId {
            capability_id: [0x01; 16],
        }
    );

    let excessive = (0..=fgit_authority::MAX_CAPABILITY_REVOCATION_ENTRIES)
        .map(|index| {
            u128::try_from(index)
                .expect("entry index fits u128")
                .to_be_bytes()
        })
        .collect();
    assert_eq!(
        CapabilityRevocationGenerationBody::try_new(
            tenant(0x11),
            repository(0x22),
            incarnation(0x33),
            PolicyEpoch::FIRST,
            None,
            excessive,
            digest(0x91),
        )
        .expect_err("the system ceiling is load-bearing"),
        CapabilityRevocationBodyRefusal::TooManyRevocations {
            observed: fgit_authority::MAX_CAPABILITY_REVOCATION_ENTRIES + 1,
            limit: fgit_authority::MAX_CAPABILITY_REVOCATION_ENTRIES,
        }
    );
}

#[test]
fn explicit_empty_generation_is_authority_selected() {
    let body = revocations(
        tenant(0x11),
        repository(0x22),
        incarnation(0x33),
        PolicyEpoch::FIRST,
        Vec::new(),
    );
    let (store, authenticated) = selected_fixture(
        202,
        &body,
        incarnation(0x33),
        repository(0x22),
        PolicyEpoch::FIRST,
    );

    let selected =
        read_head_selected_capability_revocation_generation(&store, tenant(0x11), &authenticated)
            .expect("an explicit empty generation is a real canonical decision");
    assert!(selected.body().revoked_capability_ids().is_empty());
    assert_eq!(selected.body(), &body);
}

#[test]
fn configuration_without_revocation_root_fails_closed() {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(203));
    let legacy = RepositoryIncarnationConfigurationBodyV2_1 {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: fgit_types::GitHashAlgorithm::Sha256,
        repository_incarnation_id: incarnation(0x33),
        policy_root: None,
    };
    let configuration_root = stage_latest_repository_incarnation_configuration(&store, &legacy)
        .expect("historical v2.1 configuration stages");
    let authenticated = authenticated_head(
        &store,
        203,
        &head(repository(0x22), PolicyEpoch::FIRST, configuration_root),
    );

    assert_eq!(
        read_head_selected_capability_revocation_generation(&store, tenant(0x11), &authenticated,)
            .expect_err("absence is not an empty allow-all set"),
        CapabilityRevocationAuthorityFailure::ConfigurationHasNoRevocationRoot
    );
}

#[test]
fn missing_or_misfiled_generation_is_refused() {
    let expected = revocations(
        tenant(0x11),
        repository(0x22),
        incarnation(0x33),
        PolicyEpoch::FIRST,
        vec![[0x01; 16]],
    );
    let expected_id = expected.generation_id().expect("expected identity");

    let missing_store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(204));
    let missing_configuration = RepositoryIncarnationConfigurationBodyV2_2 {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: fgit_types::GitHashAlgorithm::Sha256,
        repository_incarnation_id: incarnation(0x33),
        policy_root: None,
        capability_revocation_root: Some(expected.generation_root().expect("expected root")),
    };
    let missing_configuration_root = stage_revocation_aware_repository_incarnation_configuration(
        &missing_store,
        &missing_configuration,
    )
    .expect("configuration stages without fabricating its target");
    let missing_head = authenticated_head(
        &missing_store,
        204,
        &head(
            repository(0x22),
            PolicyEpoch::FIRST,
            missing_configuration_root,
        ),
    );
    assert_eq!(
        read_head_selected_capability_revocation_generation(
            &missing_store,
            tenant(0x11),
            &missing_head,
        )
        .expect_err("a selected but absent body cannot default"),
        CapabilityRevocationAuthorityFailure::GenerationMissing {
            generation_id: Box::new(expected_id),
        }
    );

    let misfiled_store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(205));
    let found = revocations(
        tenant(0x11),
        repository(0x22),
        incarnation(0x33),
        PolicyEpoch::FIRST,
        vec![[0x02; 16]],
    );
    let found_id = found.generation_id().expect("found identity");
    let expected_key = body_key_for_id(expected_id.as_internal_object_id())
        .expect("expected content-addressed key");
    assert_eq!(
        misfiled_store
            .put_if_absent(
                &expected_key,
                &encode_body(&found).expect("found body encodes"),
            )
            .expect("adversarial bytes are planted under the wrong key"),
        fgit_authority::PutOutcome::Created,
    );
    let misfiled_configuration_root = stage_revocation_aware_repository_incarnation_configuration(
        &misfiled_store,
        &missing_configuration,
    )
    .expect("configuration stages");
    let misfiled_head = authenticated_head(
        &misfiled_store,
        205,
        &head(
            repository(0x22),
            PolicyEpoch::FIRST,
            misfiled_configuration_root,
        ),
    );
    assert_eq!(
        read_head_selected_capability_revocation_generation(
            &misfiled_store,
            tenant(0x11),
            &misfiled_head,
        )
        .expect_err("misfiled bytes must re-identify"),
        CapabilityRevocationAuthorityFailure::GenerationIdentityMismatch {
            expected: Box::new(expected_id),
            observed: Box::new(found_id),
        }
    );
}

#[test]
fn tenant_repository_incarnation_and_policy_substitution_are_distinct_refusals() {
    let expected_tenant = tenant(0x11);
    let expected_repository = repository(0x22);
    let expected_incarnation = incarnation(0x33);
    let expected_epoch = PolicyEpoch::FIRST;

    let tenant_body = revocations(
        tenant(0x12),
        expected_repository,
        expected_incarnation,
        expected_epoch,
        Vec::new(),
    );
    let (tenant_store, tenant_head) = selected_fixture(
        206,
        &tenant_body,
        expected_incarnation,
        expected_repository,
        expected_epoch,
    );
    assert_eq!(
        read_head_selected_capability_revocation_generation(
            &tenant_store,
            expected_tenant,
            &tenant_head,
        )
        .expect_err("tenant is part of capability identity"),
        CapabilityRevocationAuthorityFailure::TenantMismatch {
            expected: expected_tenant,
            observed: tenant(0x12),
        }
    );

    let repository_body = revocations(
        expected_tenant,
        repository(0x23),
        expected_incarnation,
        expected_epoch,
        Vec::new(),
    );
    let (repository_store, repository_head) = selected_fixture(
        207,
        &repository_body,
        expected_incarnation,
        expected_repository,
        expected_epoch,
    );
    assert_eq!(
        read_head_selected_capability_revocation_generation(
            &repository_store,
            expected_tenant,
            &repository_head,
        )
        .expect_err("repository substitution is refused"),
        CapabilityRevocationAuthorityFailure::RepositoryMismatch {
            expected: expected_repository,
            observed: repository(0x23),
        }
    );

    let incarnation_body = revocations(
        expected_tenant,
        expected_repository,
        incarnation(0x34),
        expected_epoch,
        Vec::new(),
    );
    let (incarnation_store, incarnation_head) = selected_fixture(
        208,
        &incarnation_body,
        expected_incarnation,
        expected_repository,
        expected_epoch,
    );
    assert_eq!(
        read_head_selected_capability_revocation_generation(
            &incarnation_store,
            expected_tenant,
            &incarnation_head,
        )
        .expect_err("delete/recreate cannot reuse stale revocations"),
        CapabilityRevocationAuthorityFailure::IncarnationMismatch {
            expected: expected_incarnation,
            observed: incarnation(0x34),
        }
    );

    let next_epoch = PolicyEpoch::try_new(2).expect("positive epoch");
    let policy_body = revocations(
        expected_tenant,
        expected_repository,
        expected_incarnation,
        next_epoch,
        Vec::new(),
    );
    let (policy_store, policy_head) = selected_fixture(
        209,
        &policy_body,
        expected_incarnation,
        expected_repository,
        expected_epoch,
    );
    assert_eq!(
        read_head_selected_capability_revocation_generation(
            &policy_store,
            expected_tenant,
            &policy_head,
        )
        .expect_err("policy epoch substitution is refused"),
        CapabilityRevocationAuthorityFailure::PolicyEpochMismatch {
            expected: expected_epoch,
            observed: next_epoch,
        }
    );
}

#[test]
fn authenticated_head_must_be_reauthenticated_by_the_reader_store() {
    let body = revocations(
        tenant(0x11),
        repository(0x22),
        incarnation(0x33),
        PolicyEpoch::FIRST,
        Vec::new(),
    );
    let (_issuing_store, authenticated) = selected_fixture(
        210,
        &body,
        incarnation(0x33),
        repository(0x22),
        PolicyEpoch::FIRST,
    );
    let foreign_store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(211));

    assert!(matches!(
        read_head_selected_capability_revocation_generation(
            &foreign_store,
            tenant(0x11),
            &authenticated,
        ),
        Err(CapabilityRevocationAuthorityFailure::Authority(
            AuthorityFailure::Refused(AuthorityRefusal::UnknownVersionToken)
        ))
    ));
}
