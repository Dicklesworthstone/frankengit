#![forbid(unsafe_code)]
//! Strict authority resolution for incarnation-aware repository configuration.

use fgit_authority::{
    MemoryAuthorityStore, OutcomeFailure, RepositoryIncarnationConfiguration, StoreInstanceId,
    read_hidden_ref_policy, read_repository_incarnation_configuration, stage_hidden_ref_policy,
    stage_latest_repository_incarnation_configuration, stage_repository_configuration,
    stage_repository_incarnation_configuration,
};
use fgit_codec::{
    HiddenRefPolicyBody, RepositoryConfigurationBody, RepositoryIncarnationConfigurationBody,
    RepositoryIncarnationConfigurationBodyV2_1,
};
use fgit_crypto::IdentityDomain;
use fgit_types::hash::{Digest, DigestBytes};
use fgit_types::identity::RepositoryIncarnationId;
use fgit_types::layout::RootLayoutVersion;
use fgit_types::native::GitHashAlgorithm;

fn store() -> MemoryAuthorityStore {
    MemoryAuthorityStore::new(StoreInstanceId::from_raw(59))
}

const fn incarnation(value: u8) -> RepositoryIncarnationId {
    RepositoryIncarnationId::from_bytes([value; 16])
}

const fn v2_configuration(value: u8) -> RepositoryIncarnationConfigurationBodyV2_1 {
    RepositoryIncarnationConfigurationBodyV2_1 {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: GitHashAlgorithm::Sha256,
        repository_incarnation_id: incarnation(value),
        policy_root: None,
    }
}

#[test]
fn exact_v2_configuration_resolves_with_its_minted_incarnation() {
    let backing = store();
    let expected = v2_configuration(0x59);
    let root = stage_latest_repository_incarnation_configuration(&backing, &expected)
        .expect("the newest v2.1 configuration stages in the head-selected slot");

    assert_eq!(
        read_repository_incarnation_configuration(&backing, &root)
            .expect("the exact v2 configuration resolves"),
        RepositoryIncarnationConfiguration {
            root_layout: expected.root_layout,
            object_format: expected.object_format,
            repository_incarnation_id: expected.repository_incarnation_id,
            policy_root: None,
        },
        "a permitted current incarnation must preserve all permanent facts"
    );
}

#[test]
fn legacy_v2_zero_normalizes_to_an_absent_policy_root() {
    let backing = store();
    let legacy = RepositoryIncarnationConfigurationBody {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: GitHashAlgorithm::Sha256,
        repository_incarnation_id: incarnation(0x5A),
    };
    let root = stage_repository_incarnation_configuration(&backing, &legacy)
        .expect("the byte-stable v2.0 configuration stages for historical replay");

    assert_eq!(
        read_repository_incarnation_configuration(&backing, &root)
            .expect("the union reader recognizes exact v2.0"),
        RepositoryIncarnationConfiguration {
            root_layout: legacy.root_layout,
            object_format: legacy.object_format,
            repository_incarnation_id: legacy.repository_incarnation_id,
            policy_root: None,
        },
        "v2.0 has no policy field and must never be retroactively reinterpreted"
    );
}

#[test]
fn current_v2_one_preserves_the_shared_policy_root() {
    let backing = store();
    let policy = HiddenRefPolicyBody {
        rules: vec![
            b"refs/internal/*".to_vec(),
            b"!refs/internal/public".to_vec(),
        ],
    };
    let policy_root = stage_hidden_ref_policy(&backing, &policy)
        .expect("the shared policy stages in its dedicated identity domain");
    let current = RepositoryIncarnationConfigurationBodyV2_1 {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: GitHashAlgorithm::Sha256,
        repository_incarnation_id: incarnation(0x5B),
        policy_root: Some(policy_root),
    };
    let root = stage_latest_repository_incarnation_configuration(&backing, &current)
        .expect("the newest carrier stages the policy pointer");

    assert_eq!(
        read_repository_incarnation_configuration(&backing, &root)
            .expect("the union reader resolves exact v2.1"),
        RepositoryIncarnationConfiguration {
            root_layout: current.root_layout,
            object_format: current.object_format,
            repository_incarnation_id: current.repository_incarnation_id,
            policy_root: Some(policy_root),
        }
    );
    assert_eq!(
        read_hidden_ref_policy(&backing, &policy_root)
            .expect("the selected policy root resolves in the shared vocabulary"),
        policy,
        "the carrier cannot point at a different policy body"
    );
}

#[test]
fn v1_configuration_is_not_a_legacy_fallback_for_incarnation_resolution() {
    let backing = store();
    let v1_root = stage_repository_configuration(
        &backing,
        &RepositoryConfigurationBody {
            root_layout: RootLayoutVersion::RefStateMerkleV1,
            object_format: GitHashAlgorithm::Sha256,
            hidden_ref_rules: Vec::new(),
        },
    )
    .expect("the predecessor configuration stages");

    assert!(
        matches!(
            read_repository_incarnation_configuration(&backing, &v1_root),
            Err(OutcomeFailure::Codec(_))
        ),
        "a v1 body has no incarnation and must be refused, never defaulted"
    );
}

#[test]
fn absent_configuration_is_a_typed_refusal() {
    let backing = store();
    let missing = Digest::new(
        IdentityDomain::RepositoryConfiguration.algorithm().id(),
        DigestBytes::try_new(&[0xD3; 32]).expect("fixed digest length"),
    );

    assert!(
        matches!(
            read_repository_incarnation_configuration(&backing, &missing),
            Err(OutcomeFailure::ConfigurationUnresolvable)
        ),
        "an absent selection must not be interpreted as a legacy incarnation"
    );
}
