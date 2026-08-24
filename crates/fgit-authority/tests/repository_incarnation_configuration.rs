#![forbid(unsafe_code)]
//! Strict authority resolution for incarnation-aware repository configuration.

use fgit_authority::{
    MemoryAuthorityStore, OutcomeFailure, StoreInstanceId,
    read_repository_incarnation_configuration, stage_repository_configuration,
    stage_repository_incarnation_configuration,
};
use fgit_codec::{RepositoryConfigurationBody, RepositoryIncarnationConfigurationBody};
use fgit_crypto::IdentityDomain;
use fgit_types::hash::{Digest, DigestBytes};
use fgit_types::identity::RepositoryIncarnationId;
use fgit_types::layout::RootLayoutVersion;
use fgit_types::native::GitHashAlgorithm;

fn store() -> MemoryAuthorityStore {
    MemoryAuthorityStore::new(StoreInstanceId::from_raw(59))
}

fn incarnation(value: u8) -> RepositoryIncarnationId {
    RepositoryIncarnationId::from_bytes([value; 16])
}

fn v2_configuration(value: u8) -> RepositoryIncarnationConfigurationBody {
    RepositoryIncarnationConfigurationBody {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: GitHashAlgorithm::Sha256,
        repository_incarnation_id: incarnation(value),
    }
}

#[test]
fn exact_v2_configuration_resolves_with_its_minted_incarnation() {
    let backing = store();
    let expected = v2_configuration(0x59);
    let root = stage_repository_incarnation_configuration(&backing, &expected)
        .expect("the v2 configuration stages in the head-selected slot");

    assert_eq!(
        read_repository_incarnation_configuration(&backing, &root)
            .expect("the exact v2 configuration resolves"),
        expected,
        "a permitted current incarnation must preserve all permanent facts"
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
