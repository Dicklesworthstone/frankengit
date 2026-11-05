#![forbid(unsafe_code)]
//! Exact-basis policy-epoch carry-forward, through both authority surfaces.

use core::future::Future;
use std::task::{Context, Poll, Waker};

use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityOpKind,
    AuthorityStore, AuthorityVersionToken, CapabilityRevocationAuthorityFailure,
    CapabilityRevocationEpochTransition, CapabilityRevocationGenerationBody,
    CapabilityRevocationTransitionRefusal, CasOutcome, FaultDirective, FaultKind, FaultPlan,
    FaultableAuthorityStore, HeadInit, HeadKey, HeadRead, ImmutableKey, ImmutableRead,
    MemoryAuthorityStore, OutcomeFailure, PutOutcome, StoreInstanceId, authority_head_identity,
    body_key, body_key_for_id, initialize_repository, outcome_index_root,
    prepare_capability_revocation_epoch_transition,
    prepare_capability_revocation_epoch_transition_async,
    read_head_selected_capability_revocation_generation, read_repository_incarnation_configuration,
    stage_capability_revocation_generation, stage_latest_repository_incarnation_configuration,
    stage_repository_configuration, stage_repository_incarnation_configuration,
    stage_revocation_aware_repository_incarnation_configuration,
    verify_capability_revocation_epoch_transition,
    verify_capability_revocation_epoch_transition_async,
};
use fgit_codec::{
    CanonicalBody, CodecRefusal, CryptoBodyIdentity, Decoder, Encoder, RepositoryAuthorityHeadBody,
    RepositoryConfigurationBody, RepositoryIncarnationConfigurationBody,
    RepositoryIncarnationConfigurationBodyV2_1, RepositoryIncarnationConfigurationBodyV2_2,
    body_id, encode_body,
};
use fgit_crypto::IdentityDomain;
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestBytes, GitHashAlgorithm, HeadGeneration,
    InternalObjectId, PolicyEpoch, RegistryEpoch, RepositoryId, RepositoryIncarnationId,
    RootLayoutVersion, TenantId,
};

const TENANT: TenantId = TenantId::from_bytes([0x71; 16]);
const REPOSITORY: RepositoryId = RepositoryId::from_bytes([0x72; 16]);
const INCARNATION: RepositoryIncarnationId = RepositoryIncarnationId::from_bytes([0x73; 16]);

fn digest(marker: u8) -> Digest {
    Digest::new(
        IdentityDomain::Generation.algorithm().id(),
        DigestBytes::try_new(&[marker; 32]).expect("fixed-width digest"),
    )
}

fn key() -> HeadKey {
    HeadKey::new(b"revocation-transition/head".to_vec()).expect("bounded head key")
}

fn genesis(configuration_root: Digest, epoch: PolicyEpoch) -> RepositoryAuthorityHeadBody {
    let root = outcome_index_root(&[]).expect("empty root");
    RepositoryAuthorityHeadBody {
        repository_id: REPOSITORY,
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
        policy_epoch: epoch,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

fn initialize(
    store: &MemoryAuthorityStore,
    configuration_root: Digest,
    epoch: PolicyEpoch,
) -> AuthenticatedHead {
    let HeadInit::Created(receipt) =
        initialize_repository(store, &key(), &genesis(configuration_root, epoch))
            .expect("initialize reference authority")
    else {
        panic!("fresh fixture head");
    };
    store
        .authenticate_head_receipt(&receipt)
        .expect("authentic receipt")
}

fn generation(epoch: PolicyEpoch, ids: Vec<[u8; 16]>) -> CapabilityRevocationGenerationBody {
    CapabilityRevocationGenerationBody::try_new(
        TENANT,
        REPOSITORY,
        INCARNATION,
        epoch,
        None,
        ids,
        digest(0x80),
    )
    .expect("bounded unique generation")
}

fn configuration(root: Option<Digest>) -> RepositoryIncarnationConfigurationBodyV2_2 {
    RepositoryIncarnationConfigurationBodyV2_2 {
        root_layout: RootLayoutVersion::RefStateAndObjectClosureMerkleV1,
        object_format: GitHashAlgorithm::Sha256,
        repository_incarnation_id: INCARNATION,
        policy_root: Some(digest(0x81)),
        capability_revocation_root: root,
    }
}

fn fixture(
    generation_epoch: PolicyEpoch,
    head_epoch: PolicyEpoch,
    ids: Vec<[u8; 16]>,
) -> (
    MemoryAuthorityStore,
    AuthenticatedHead,
    CapabilityRevocationGenerationBody,
) {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x701));
    let original = generation(generation_epoch, ids);
    let staged = stage_capability_revocation_generation(&store, &original).expect("stage original");
    let root = stage_revocation_aware_repository_incarnation_configuration(
        &store,
        &configuration(Some(staged.generation_root())),
    )
    .expect("stage selected configuration");
    let authenticated = initialize(&store, root, head_epoch);
    (store, authenticated, original)
}

fn prepare(
    store: &MemoryAuthorityStore,
    head: &AuthenticatedHead,
) -> CapabilityRevocationEpochTransition {
    prepare_capability_revocation_epoch_transition(
        store,
        TENANT,
        head,
        head.body()
            .expect("head")
            .policy_epoch
            .next()
            .expect("next epoch"),
        digest(0x82),
    )
    .expect("exact selected state prepares")
    .expect("explicit generation has a transition")
}

fn authority_failure(
    refusal: CapabilityRevocationTransitionRefusal,
) -> CapabilityRevocationAuthorityFailure {
    let CapabilityRevocationTransitionRefusal::Authority(failure) = refusal else {
        panic!("expected authority refusal: {refusal:?}");
    };
    *failure
}

#[test]
fn complete_snapshot_and_permanent_configuration_survive_the_epoch_advance() {
    for ids in [Vec::new(), vec![[0x41; 16], [0x12; 16], [0xf3; 16]]] {
        let (store, original_head, original) = fixture(PolicyEpoch::FIRST, PolicyEpoch::FIRST, ids);
        let transition = prepare(&store, &original_head);
        let before = original_head.body().expect("original head");
        assert_eq!(transition.predecessor_body(), &before);
        assert_eq!(
            transition.predecessor_id(),
            authority_head_identity(&before).expect("head ID")
        );
        assert_eq!(
            transition.expected_head_token(),
            original_head.receipt().token()
        );
        assert_eq!(
            transition.generation().revoked_capability_ids(),
            original.revoked_capability_ids()
        );
        assert_eq!(
            transition.generation().predecessor_generation_id(),
            Some(original.generation_id().expect("generation ID"))
        );
        assert_eq!(
            transition.successor_epoch(),
            PolicyEpoch::FIRST.next().expect("next epoch")
        );
        assert_eq!(transition.evidence_root(), digest(0x82));
        let expected_configuration = configuration(Some(
            transition.generation().generation_root().expect("new root"),
        ));
        assert_eq!(transition.configuration(), &expected_configuration);
        assert_ne!(transition.configuration_root(), before.configuration_root);
        assert!(matches!(
            store
                .read_immutable(
                    &body_key(IdentityDomain::Generation, transition.generation()).expect("key")
                )
                .expect("read"),
            ImmutableRead::Absent
        ));

        transition.stage(&store).expect("stage both dependencies");
        transition
            .stage(&store)
            .expect("idempotent exact-body staging");
        assert_eq!(
            read_head_selected_capability_revocation_generation(&store, TENANT, &original_head)
                .expect("old selection")
                .body(),
            &original
        );
        assert_eq!(
            read_repository_incarnation_configuration(&store, &transition.configuration_root())
                .expect("new config")
                .policy_root,
            Some(digest(0x81))
        );

        // This primitive-only authority test activates exactly the staged body.
        // Chronicle tests separately bind the committed protection decision.
        let mut successor = before;
        successor.generation = successor.generation.next().expect("next generation");
        successor.predecessor_head_id = Some(transition.predecessor_id());
        successor.policy_epoch = transition.successor_epoch();
        successor.configuration_root = transition.configuration_root();
        verify_capability_revocation_epoch_transition(
            &store,
            transition.predecessor_body(),
            &successor,
            transition.evidence_root(),
        )
        .expect("read-only history verification resolves both exact dependencies");
        ready(verify_capability_revocation_epoch_transition_async(
            &AsyncMirror(&store),
            &(),
            transition.predecessor_body(),
            &successor,
            transition.evidence_root(),
        ))
        .expect("async replay agrees");
        let CasOutcome::Committed(receipt) = store
            .compare_exchange_head(
                &key(),
                original_head.receipt().token(),
                successor.generation,
                &encode_body(&successor).expect("successor frame"),
            )
            .expect("CAS")
        else {
            panic!("exact predecessor wins");
        };
        let authenticated = store
            .authenticate_head_receipt(&receipt)
            .expect("successor authenticates");
        assert_eq!(
            read_head_selected_capability_revocation_generation(&store, TENANT, &authenticated)
                .expect("successor is usable")
                .body(),
            transition.generation()
        );
        let fresh = prepare(&store, &authenticated);
        assert_eq!(
            fresh.generation().predecessor_generation_id(),
            Some(
                transition
                    .generation()
                    .generation_id()
                    .expect("intermediate ID")
            )
        );
        assert_eq!(
            fresh.generation().revoked_capability_ids(),
            original.revoked_capability_ids()
        );
    }
}

#[test]
fn immediate_epoch_and_selected_generation_scope_are_mandatory() {
    let (store, head, _) = fixture(PolicyEpoch::FIRST, PolicyEpoch::FIRST, vec![[0x12; 16]]);
    for proposed in [
        PolicyEpoch::FIRST,
        PolicyEpoch::try_new(3).expect("third epoch"),
    ] {
        assert!(matches!(
            prepare_capability_revocation_epoch_transition(
                &store,
                TENANT,
                &head,
                proposed,
                digest(0x82)
            ),
            Err(CapabilityRevocationTransitionRefusal::EpochNotImmediateSuccessor { .. })
        ));
    }
    let wrong_tenant = TenantId::from_bytes([0xff; 16]);
    assert!(matches!(
        authority_failure(
            prepare_capability_revocation_epoch_transition(
                &store,
                wrong_tenant,
                &head,
                PolicyEpoch::FIRST.next().expect("next"),
                digest(0x82)
            )
            .expect_err("tenant mismatch")
        ),
        CapabilityRevocationAuthorityFailure::TenantMismatch { .. }
    ));

    let second = PolicyEpoch::FIRST.next().expect("second");
    let (stale_store, stale_head, _) = fixture(PolicyEpoch::FIRST, second, vec![[0x12; 16]]);
    assert!(matches!(
        authority_failure(
            prepare_capability_revocation_epoch_transition(
                &stale_store,
                TENANT,
                &stale_head,
                second.next().expect("third"),
                digest(0x82)
            )
            .expect_err("old epoch cannot be repaired implicitly")
        ),
        CapabilityRevocationAuthorityFailure::PolicyEpochMismatch { .. }
    ));
    let maximum = PolicyEpoch::try_new(u64::MAX).expect("maximum epoch");
    let (exhausted_store, exhausted_head, _) = fixture(maximum, maximum, Vec::new());
    assert_eq!(
        prepare_capability_revocation_epoch_transition(
            &exhausted_store,
            TENANT,
            &exhausted_head,
            PolicyEpoch::FIRST,
            digest(0x82)
        )
        .expect_err("checked overflow"),
        CapabilityRevocationTransitionRefusal::EpochExhausted {
            predecessor: maximum
        }
    );
}

#[test]
fn supported_configurations_without_revocation_remain_unchanged() {
    for version in 0..4 {
        let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x710 + version));
        let root = match version {
            0 => stage_repository_configuration(
                &store,
                &RepositoryConfigurationBody {
                    root_layout: RootLayoutVersion::LegacyWholeBody,
                    object_format: GitHashAlgorithm::Sha1,
                    hidden_ref_rules: vec![b"refs/private/".to_vec()],
                },
            ),
            1 => stage_repository_incarnation_configuration(
                &store,
                &RepositoryIncarnationConfigurationBody {
                    root_layout: RootLayoutVersion::RefStateMerkleV1,
                    object_format: GitHashAlgorithm::Sha256,
                    repository_incarnation_id: INCARNATION,
                },
            ),
            2 => stage_latest_repository_incarnation_configuration(
                &store,
                &RepositoryIncarnationConfigurationBodyV2_1 {
                    root_layout: RootLayoutVersion::RefStateMerkleV1,
                    object_format: GitHashAlgorithm::Sha1,
                    repository_incarnation_id: INCARNATION,
                    policy_root: Some(digest(0x81)),
                },
            ),
            _ => stage_revocation_aware_repository_incarnation_configuration(
                &store,
                &configuration(None),
            ),
        }
        .expect("known exact configuration stages");
        let head = initialize(&store, root, PolicyEpoch::FIRST);
        let before = store.read_head(&key()).expect("before");
        assert_eq!(
            prepare_capability_revocation_epoch_transition(
                &store,
                TENANT,
                &head,
                PolicyEpoch::FIRST.next().expect("next"),
                digest(0x82)
            )
            .expect("supported absence"),
            None
        );
        assert_eq!(store.read_head(&key()).expect("after"), before);
        let predecessor = head.body().expect("predecessor");
        let mut successor = predecessor.clone();
        successor.policy_epoch = predecessor.policy_epoch.next().expect("next");
        verify_capability_revocation_epoch_transition(
            &store,
            &predecessor,
            &successor,
            digest(0x82),
        )
        .expect("known no-root configuration can stay unchanged");
        ready(verify_capability_revocation_epoch_transition_async(
            &AsyncMirror(&store),
            &(),
            &predecessor,
            &successor,
            digest(0x82),
        ))
        .expect("asynchronous no-root replay");
        successor.configuration_root = digest(0xee);
        assert!(
            verify_capability_revocation_epoch_transition(
                &store,
                &predecessor,
                &successor,
                digest(0x82)
            )
            .is_err(),
            "a no-root predecessor cannot authorize an unrelated new configuration"
        );
    }
}

struct FutureConfiguration;

impl CanonicalBody for FutureConfiguration {
    const DOMAIN: fgit_types::DomainTag = RepositoryIncarnationConfigurationBodyV2_2::DOMAIN;
    const SCHEMA_FAMILY: fgit_types::SchemaFamily =
        RepositoryIncarnationConfigurationBodyV2_2::SCHEMA_FAMILY;
    const SCHEMA_MAJOR: u16 = 2;
    const SCHEMA_MINOR: u16 = 3;
    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        configuration(None).write_payload(out)
    }
    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let _ = RepositoryIncarnationConfigurationBodyV2_2::read_payload(input)?;
        Ok(Self)
    }
}

fn selected_key(root: Digest) -> ImmutableKey {
    body_key_for_id(&InternalObjectId::new(
        root.algorithm(),
        IdentityDomain::RepositoryConfiguration.domain_tag(),
        CANONICAL_CODEC_VERSION,
        *root.bytes(),
    ))
    .expect("configuration key")
}

#[test]
fn absent_corrupt_future_and_wrongly_addressed_configurations_never_mean_no_revocations() {
    for case in 0..5 {
        let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x720 + case));
        let mut root = digest(0x90);
        let bytes = match case {
            0 => None,
            1 => Some(b"corrupt configuration".to_vec()),
            2 => {
                let identity =
                    body_id(&CryptoBodyIdentity, &FutureConfiguration).expect("future body ID");
                root = Digest::new(identity.algorithm(), *identity.digest());
                Some(encode_body(&FutureConfiguration).expect("future frame"))
            }
            3 => Some(encode_body(&configuration(None)).expect("valid body under wrong root")),
            _ => Some(
                encode_body(&RepositoryConfigurationBody {
                    root_layout: RootLayoutVersion::LegacyWholeBody,
                    object_format: GitHashAlgorithm::Sha1,
                    hidden_ref_rules: Vec::new(),
                })
                .expect("legacy body under wrong root"),
            ),
        };
        if let Some(bytes) = bytes {
            store
                .put_if_absent(&selected_key(root), &bytes)
                .expect("adversarial slot");
        }
        let head = initialize(&store, root, PolicyEpoch::FIRST);
        let failure = authority_failure(
            prepare_capability_revocation_epoch_transition(
                &store,
                TENANT,
                &head,
                PolicyEpoch::FIRST.next().expect("next"),
                digest(0x82),
            )
            .expect_err("must fail closed"),
        );
        assert!(
            matches!(
                failure,
                CapabilityRevocationAuthorityFailure::Configuration(_)
            ),
            "case {case}: {failure:?}"
        );
        let predecessor = head.body().expect("predecessor");
        let mut successor = predecessor.clone();
        successor.policy_epoch = predecessor.policy_epoch.next().expect("next");
        assert!(
            verify_capability_revocation_epoch_transition(
                &store,
                &predecessor,
                &successor,
                digest(0x82)
            )
            .is_err(),
            "unchanged root is no bypass for case {case}"
        );
        assert!(
            ready(verify_capability_revocation_epoch_transition_async(
                &AsyncMirror(&store),
                &(),
                &predecessor,
                &successor,
                digest(0x82)
            ))
            .is_err()
        );
    }
}

#[test]
fn missing_or_replaced_revocation_body_fails_closed_even_with_same_count() {
    for replace in [false, true] {
        let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x730));
        let original = generation(PolicyEpoch::FIRST, vec![[1; 16], [2; 16]]);
        if replace {
            let altered = generation(PolicyEpoch::FIRST, vec![[1; 16], [3; 16]]);
            store
                .put_if_absent(
                    &body_key(IdentityDomain::Generation, &original).expect("original key"),
                    &encode_body(&altered).expect("same-count different set"),
                )
                .expect("adversarial slot");
        }
        let root = stage_revocation_aware_repository_incarnation_configuration(
            &store,
            &configuration(Some(original.generation_root().expect("original root"))),
        )
        .expect("config");
        let head = initialize(&store, root, PolicyEpoch::FIRST);
        let failure = authority_failure(
            prepare_capability_revocation_epoch_transition(
                &store,
                TENANT,
                &head,
                PolicyEpoch::FIRST.next().expect("next"),
                digest(0x82),
            )
            .expect_err("missing/misidentified generation"),
        );
        assert!(matches!(
            (replace, failure),
            (
                false,
                CapabilityRevocationAuthorityFailure::GenerationMissing { .. }
            ) | (
                true,
                CapabilityRevocationAuthorityFailure::GenerationIdentityMismatch { .. }
            )
        ));
    }
}

#[test]
fn staging_reauthenticates_and_detects_content_conflicts() {
    let (store, head, _) = fixture(PolicyEpoch::FIRST, PolicyEpoch::FIRST, vec![[1; 16]]);
    let transition = prepare(&store, &head);
    let unrelated = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x999));
    assert!(matches!(
        authority_failure(
            transition
                .stage(&unrelated)
                .expect_err("receipt is not portable authority")
        ),
        CapabilityRevocationAuthorityFailure::Authority(_)
    ));
    let generation_key =
        body_key(IdentityDomain::Generation, transition.generation()).expect("new generation key");
    assert_eq!(
        unrelated
            .read_immutable(&generation_key)
            .expect("no writes"),
        ImmutableRead::Absent
    );
    store
        .put_if_absent(&generation_key, b"conflict")
        .expect("poison selected immutable slot");
    assert!(matches!(
        authority_failure(transition.stage(&store).expect_err("generation conflict")),
        CapabilityRevocationAuthorityFailure::ContentAddressedConflict { .. }
    ));
    assert_eq!(
        store
            .read_immutable(&selected_key(transition.configuration_root()))
            .expect("config not staged"),
        ImmutableRead::Absent
    );

    let (store, head, _) = fixture(PolicyEpoch::FIRST, PolicyEpoch::FIRST, vec![[1; 16]]);
    let transition = prepare(&store, &head);
    store
        .put_if_absent(
            &selected_key(transition.configuration_root()),
            b"configuration conflict",
        )
        .expect("conflict fixture");
    assert!(
        matches!(authority_failure(transition.stage(&store).expect_err("configuration conflict")), CapabilityRevocationAuthorityFailure::Configuration(failure) if matches!(*failure, OutcomeFailure::Seal(_)))
    );
    assert_eq!(
        store.read_head(&key()).expect("head untouched"),
        HeadRead::Present(head.receipt().clone())
    );
}

#[test]
fn interrupted_staging_retries_exact_dependencies_without_publishing() {
    for ordinal in [0, 1] {
        for kind in [FaultKind::LoseRequest, FaultKind::LoseResponse] {
            let (store, head, _) = fixture(
                PolicyEpoch::FIRST,
                PolicyEpoch::FIRST,
                vec![[1; 16], [2; 16]],
            );
            let transition = prepare(&store, &head);
            store.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::nth_of_kind(
                ordinal,
                AuthorityOpKind::PutIfAbsent,
                kind,
            )]));
            assert!(matches!(
                authority_failure(
                    transition
                        .stage(&store)
                        .expect_err("interrupted dependency write")
                ),
                CapabilityRevocationAuthorityFailure::Authority(AuthorityFailure::Ambiguous(_))
                    | CapabilityRevocationAuthorityFailure::Configuration(_)
            ));
            assert_eq!(
                store.read_head(&key()).expect("head remains original"),
                HeadRead::Present(head.receipt().clone())
            );
            store.install_fault_plan(FaultPlan::none());
            transition
                .stage(&store)
                .expect("retry completes identical dependencies");
            assert_eq!(
                store
                    .read_immutable(&selected_key(transition.configuration_root()))
                    .expect("exact config present"),
                ImmutableRead::Present(
                    encode_body(transition.configuration()).expect("expected bytes")
                )
            );
        }
    }
}

#[test]
fn historical_replay_rejects_stale_unchanged_roots_and_every_carried_fact_drift() {
    let (store, head, _) = fixture(
        PolicyEpoch::FIRST,
        PolicyEpoch::FIRST,
        vec![[1; 16], [2; 16]],
    );
    let transition = prepare(&store, &head);
    transition.stage(&store).expect("valid dependencies");
    let predecessor = head.body().expect("predecessor");
    let mut successor = predecessor.clone();
    successor.policy_epoch = transition.successor_epoch();
    assert!(
        matches!(
            verify_capability_revocation_epoch_transition(
                &store,
                &predecessor,
                &successor,
                transition.evidence_root()
            ),
            Err(CapabilityRevocationTransitionRefusal::CarryForwardMismatch { .. })
        ),
        "the original bug: unchanged enabled config must refuse at the new epoch"
    );
    successor.configuration_root = transition.configuration_root();
    verify_capability_revocation_epoch_transition(
        &store,
        &predecessor,
        &successor,
        transition.evidence_root(),
    )
    .expect("permitted twin");

    for case in 0..14 {
        let expected = transition.generation();
        let mut ids = expected.revoked_capability_ids().to_vec();
        if case == 0 {
            ids[1] = [3; 16];
        }
        let altered = CapabilityRevocationGenerationBody::try_new(
            if case == 1 {
                TenantId::from_bytes([0xff; 16])
            } else {
                expected.tenant_id()
            },
            if case == 2 {
                RepositoryId::from_bytes([0xff; 16])
            } else {
                expected.repository_id()
            },
            if case == 3 {
                RepositoryIncarnationId::from_bytes([0xff; 16])
            } else {
                expected.repository_incarnation_id()
            },
            if case == 4 {
                PolicyEpoch::FIRST
            } else {
                expected.policy_epoch()
            },
            if case == 5 {
                None
            } else {
                expected.predecessor_generation_id()
            },
            ids,
            if case == 6 {
                digest(0xff)
            } else {
                expected.evidence_root()
            },
        )
        .expect("well-encoded alternative generation");
        let staged =
            stage_capability_revocation_generation(&store, &altered).expect("stage alternative");
        let mut altered_configuration = *transition.configuration();
        altered_configuration.capability_revocation_root = Some(staged.generation_root());
        match case {
            7 => altered_configuration.root_layout = RootLayoutVersion::LegacyWholeBody,
            8 => altered_configuration.object_format = GitHashAlgorithm::Sha1,
            9 => altered_configuration.policy_root = None,
            10 => {
                altered_configuration.repository_incarnation_id =
                    RepositoryIncarnationId::from_bytes([0xff; 16])
            }
            11 => altered_configuration.capability_revocation_root = None,
            _ => {}
        }
        let mut altered_head = successor.clone();
        altered_head.configuration_root =
            stage_revocation_aware_repository_incarnation_configuration(
                &store,
                &altered_configuration,
            )
            .expect("stage alternative config");
        if case == 12 {
            altered_head.repository_id = RepositoryId::from_bytes([0xff; 16]);
        }
        if case == 13 {
            altered_head.policy_epoch = altered_head.policy_epoch.next().expect("skipped epoch");
        }
        let synchronous = verify_capability_revocation_epoch_transition(
            &store,
            &predecessor,
            &altered_head,
            transition.evidence_root(),
        );
        assert!(
            synchronous.is_err(),
            "case {case} must refuse exact carried fact drift"
        );
        assert_eq!(
            ready(verify_capability_revocation_epoch_transition_async(
                &AsyncMirror(&store),
                &(),
                &predecessor,
                &altered_head,
                transition.evidence_root()
            )),
            synchronous,
            "async refusal agrees for case {case}"
        );
    }
    assert!(
        verify_capability_revocation_epoch_transition(
            &store,
            &predecessor,
            &successor,
            digest(0xfd)
        )
        .is_err(),
        "a different committed policy event cannot explain the same carry-forward"
    );
    assert_eq!(
        store.read_head(&key()).expect("replay is read-only"),
        HeadRead::Present(head.receipt().clone())
    );
}

#[test]
fn historical_replay_requires_both_exact_successor_dependencies_to_exist() {
    for case in 0..5 {
        let (store, head, _) = fixture(
            PolicyEpoch::FIRST,
            PolicyEpoch::FIRST,
            vec![[1; 16], [2; 16]],
        );
        let transition = prepare(&store, &head);
        match case {
            0 => {}
            1 => {
                stage_capability_revocation_generation(&store, transition.generation())
                    .expect("only generation");
            }
            2 => {
                stage_revocation_aware_repository_incarnation_configuration(
                    &store,
                    transition.configuration(),
                )
                .expect("only configuration");
            }
            3 => {
                stage_capability_revocation_generation(&store, transition.generation())
                    .expect("correct generation");
                store
                    .put_if_absent(
                        &selected_key(transition.configuration_root()),
                        &encode_body(&configuration(None)).expect("different valid configuration"),
                    )
                    .expect("misaddressed configuration");
            }
            _ => {
                stage_revocation_aware_repository_incarnation_configuration(
                    &store,
                    transition.configuration(),
                )
                .expect("correct configuration");
                store
                    .put_if_absent(
                        &body_key(IdentityDomain::Generation, transition.generation())
                            .expect("new generation slot"),
                        &encode_body(&generation(PolicyEpoch::FIRST, vec![[1; 16], [3; 16]]))
                            .expect("different same-size generation"),
                    )
                    .expect("misaddressed generation");
            }
        }
        let predecessor = head.body().expect("predecessor");
        let mut successor = predecessor.clone();
        successor.policy_epoch = transition.successor_epoch();
        successor.configuration_root = transition.configuration_root();
        let synchronous = verify_capability_revocation_epoch_transition(
            &store,
            &predecessor,
            &successor,
            transition.evidence_root(),
        );
        assert!(
            synchronous.is_err(),
            "case {case} cannot be inferred from the expected root alone"
        );
        assert_eq!(
            ready(verify_capability_revocation_epoch_transition_async(
                &AsyncMirror(&store),
                &(),
                &predecessor,
                &successor,
                transition.evidence_root()
            )),
            synchronous
        );
        assert_eq!(
            store.read_head(&key()).expect("read-only failure"),
            HeadRead::Present(head.receipt().clone())
        );
    }
}

struct AsyncMirror<'a>(&'a MemoryAuthorityStore);

impl AsyncAuthorityStore for AsyncMirror<'_> {
    type Context = ();
    fn instance_id(&self) -> StoreInstanceId {
        self.0.instance_id()
    }
    fn limits(&self) -> AuthorityLimits {
        self.0.limits()
    }
    fn put_if_absent(
        &self,
        _: &(),
        key: &ImmutableKey,
        body: &[u8],
    ) -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> + Send {
        core::future::ready(self.0.put_if_absent(key, body))
    }
    fn read_immutable(
        &self,
        _: &(),
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        core::future::ready(self.0.read_immutable(key))
    }
    fn initialize_head(
        &self,
        _: &(),
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        core::future::ready(self.0.initialize_head(key, generation, body))
    }
    fn read_head(
        &self,
        _: &(),
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send {
        core::future::ready(self.0.read_head(key))
    }
    fn compare_exchange_head(
        &self,
        _: &(),
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        core::future::ready(
            self.0
                .compare_exchange_head(key, expected, generation, body),
        )
    }
    fn authenticate_head_receipt(
        &self,
        _: &(),
        receipt: &fgit_authority::HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send {
        core::future::ready(self.0.authenticate_head_receipt(receipt))
    }
}

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    let Poll::Ready(output) = future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    else {
        panic!("reference operations are immediately ready");
    };
    output
}

#[test]
fn asynchronous_preparation_and_staging_match_the_reference_surface() {
    let ids = (0_u128..4096).map(u128::to_be_bytes).collect();
    let (store, head, _) = fixture(PolicyEpoch::FIRST, PolicyEpoch::FIRST, ids);
    let reference = prepare(&store, &head);
    let asynchronous = ready(prepare_capability_revocation_epoch_transition_async(
        &AsyncMirror(&store),
        &(),
        TENANT,
        &head,
        PolicyEpoch::FIRST.next().expect("next"),
        digest(0x82),
    ))
    .expect("async preparation")
    .expect("explicit root");
    assert_eq!(asynchronous, reference);
    ready(asynchronous.stage_async(&AsyncMirror(&store), &())).expect("async staging");
    reference
        .stage(&store)
        .expect("reference retries exact bytes");
    assert_eq!(
        store.read_head(&key()).expect("staging is not publication"),
        HeadRead::Present(head.receipt().clone())
    );
}
