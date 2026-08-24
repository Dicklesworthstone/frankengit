//! A head selects its root layout through `configuration_root`.
//!
//! This is acceptance line 1 of `frankengit-ls44` made executable: not "a
//! layout version type exists", but *a head can select v1, and a verifier
//! reaches the right answer by asking that head*.
//!
//! # The carrier, and why it is not a head field
//!
//! `RepositoryAuthorityHeadBody`'s encoding is positional and strict —
//! `write_option(None)` still emits a byte — so any added field shifts every
//! head's canonical bytes and makes existing heads undecodable. That would
//! break the very requirement the layout version serves: heads published
//! before it must verify unchanged. So the version rides in a canonical
//! configuration body that the *existing* `configuration_root` names, and
//! migration is an ordinary head transition. The orchestrator ruled this on the bead.
//!
//! # The asymmetry these tests exist to pin
//!
//! A head whose `configuration_root` resolves to nothing is **v0 for
//! verification** and a **typed refusal for proof generation**. Those are
//! different answers to different questions and collapsing them is a real
//! defect in either direction:
//!
//! * defaulting proof generation to v0 would emit a path through a tree that
//!   does not exist, and the caller would verify it vacuously;
//! * refusing verification would break every head that predates this
//!   vocabulary, which are not wrong — they are just older.

use fgit_authority::{
    AuthorityStore, MemoryAuthorityStore, OutcomeFailure, StoreInstanceId, root_layout_for_proof,
    root_layout_for_verification, stage_repository_configuration,
};
use fgit_codec::wire::{CanonicalBody, encode_body};
use fgit_codec::{
    CodecRefusal, Decoder, Encoder, RepositoryAuthorityHeadBody, RepositoryConfigurationBody,
};
use fgit_crypto::{
    MerkleRefusal, ref_state_membership_proof, ref_state_merkle_root,
    verify_ref_state_membership_under,
};
use fgit_types::hash::{Digest, DigestBytes};
use fgit_types::identity::RepositoryId;
use fgit_types::label::{DomainTag, SchemaFamily};
use fgit_types::layout::RootLayoutVersion;
use fgit_types::native::{GitOid, GitOidSha1};
use fgit_types::numeric::{HeadGeneration, PolicyEpoch, RegistryEpoch};
use fgit_types::refs::RefName;

fn store() -> MemoryAuthorityStore {
    MemoryAuthorityStore::new(StoreInstanceId::from_raw(1))
}

fn digest(byte: u8) -> Digest {
    Digest::new(
        fgit_crypto::IdentityDomain::RefTransaction.algorithm().id(),
        DigestBytes::try_new(&[byte; 32]).expect("a bounded digest"),
    )
}

fn name(text: &str) -> RefName {
    RefName::try_new(text.as_bytes()).expect("an admissible ref name")
}

const fn oid(seed: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([seed; GitOidSha1::LEN]))
}

/// A head that selects `configuration_root`.
fn head_selecting(configuration_root: Digest) -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: RepositoryId::from_bytes([0x22; 16]),
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: digest(1),
        forge_position_root: digest(0),
        outcome_index_root: digest(0),
        retention_root: digest(0),
        outbox_root: digest(0),
        configuration_root,
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

/// The ref state these tests prove membership in.
fn entries() -> Vec<(RefName, GitOid)> {
    vec![
        (name("refs/heads/main"), oid(0x11)),
        (name("refs/heads/next"), oid(0x22)),
        (name("refs/tags/v1"), oid(0x33)),
    ]
}

// ---------------------------------------------------------------------------
// The acceptance line
// ---------------------------------------------------------------------------

#[test]
fn a_head_selecting_v1_verifies_ref_state_membership() {
    let backing = store();
    let configuration_root = stage_repository_configuration(
        &backing,
        &RepositoryConfigurationBody {
            root_layout: RootLayoutVersion::RefStateMerkleV1,
        },
    )
    .expect("the configuration body stages");
    let head = head_selecting(configuration_root);

    // The whole point: the version comes FROM THE HEAD, not from the caller's
    // assumption about what it should be.
    let selected = root_layout_for_verification(&backing, &head.configuration_root)
        .expect("the head's configuration resolves");
    assert_eq!(selected, RootLayoutVersion::RefStateMerkleV1);

    let set = entries();
    let ref_root = ref_state_merkle_root(&set).expect("a root");
    let (bound, proof) =
        ref_state_membership_proof(&set, &name("refs/heads/main")).expect("a proof");

    assert_eq!(
        verify_ref_state_membership_under(
            selected,
            &ref_root,
            &name("refs/heads/main"),
            &bound,
            &proof,
        ),
        Ok(true),
        "a head that selects v1 must let a verifier confirm membership"
    );
}

#[test]
fn a_head_selecting_v0_refuses_proof_generation() {
    let backing = store();
    let configuration_root = stage_repository_configuration(
        &backing,
        &RepositoryConfigurationBody {
            root_layout: RootLayoutVersion::LegacyWholeBody,
        },
    )
    .expect("the configuration body stages");
    let head = head_selecting(configuration_root);

    // v0 is a real, resolvable answer here — the head says so explicitly.
    assert_eq!(
        root_layout_for_proof(&backing, &head.configuration_root)
            .expect("an explicit v0 configuration resolves"),
        RootLayoutVersion::LegacyWholeBody
    );

    let set = entries();
    let ref_root = ref_state_merkle_root(&set).expect("a root");
    let (bound, proof) =
        ref_state_membership_proof(&set, &name("refs/heads/main")).expect("a proof");

    assert_eq!(
        verify_ref_state_membership_under(
            RootLayoutVersion::LegacyWholeBody,
            &ref_root,
            &name("refs/heads/main"),
            &bound,
            &proof,
        ),
        Err(MerkleRefusal::LayoutAdmitsNoProof {
            version: RootLayoutVersion::LegacyWholeBody,
        }),
        "a v0 head admits no ref-state membership proof, and must say so rather than fail one"
    );
}

#[test]
fn an_unresolvable_configuration_root_is_v0_for_verification_and_refused_for_proofs() {
    // THE ASYMMETRY. This is the case every head published before this
    // vocabulary is in: its configuration_root names nothing this store holds.
    let backing = store();
    let head = head_selecting(digest(0xEE));

    assert_eq!(
        root_layout_for_verification(&backing, &head.configuration_root)
            .expect("verification resolves"),
        RootLayoutVersion::LegacyWholeBody,
        "an older head is carrying the legacy layout and must still verify, not be refused"
    );

    assert!(
        matches!(
            root_layout_for_proof(&backing, &head.configuration_root),
            Err(OutcomeFailure::ConfigurationUnresolvable)
        ),
        "proof generation must refuse rather than assume v0: a proof under a layout with no tree \
         is a path through nothing, and the caller would verify it vacuously"
    );
}

// ---------------------------------------------------------------------------
// Migration is an ordinary head transition
// ---------------------------------------------------------------------------

#[test]
fn advancing_the_layout_changes_only_the_configuration_root() {
    // The claim that justified choosing this carrier over a head field: nothing
    // already published moves. The two heads below differ in exactly one field,
    // and a v0 head's bytes are untouched by v1 existing.
    let backing = store();
    let legacy_root = stage_repository_configuration(
        &backing,
        &RepositoryConfigurationBody {
            root_layout: RootLayoutVersion::LegacyWholeBody,
        },
    )
    .expect("stages");
    let merkle_root = stage_repository_configuration(
        &backing,
        &RepositoryConfigurationBody {
            root_layout: RootLayoutVersion::RefStateMerkleV1,
        },
    )
    .expect("stages");
    assert_ne!(
        legacy_root, merkle_root,
        "the two configurations must be distinct bodies, or the head cannot select between them"
    );

    let before = head_selecting(legacy_root);
    let after = head_selecting(merkle_root);

    let mut before_with_new_root = before.clone();
    before_with_new_root.configuration_root = after.configuration_root;
    assert_eq!(
        before_with_new_root, after,
        "the migration must change configuration_root and nothing else"
    );

    // And the encoded head is the same length either way: selecting a layout
    // costs no bytes in the head body at all, which is the property a head
    // FIELD would have destroyed.
    assert_eq!(
        encode_body(&before).expect("encodes").len(),
        encode_body(&after).expect("encodes").len(),
        "advancing the layout must not change the size of a head body"
    );
}

// ---------------------------------------------------------------------------
// A head newer than this build
// ---------------------------------------------------------------------------

/// A configuration body that writes a layout code point this build does not
/// know, to stand in for a head published by a newer peer.
///
/// It borrows the real body's domain and schema so the frame is genuine — the
/// only thing wrong with it, from this build's point of view, is the version it
/// names. That is exactly the situation a rolling upgrade produces, and it
/// cannot be reached through `RepositoryConfigurationBody` because that type
/// can only hold versions this build knows.
struct FutureConfiguration;

impl CanonicalBody for FutureConfiguration {
    const DOMAIN: DomainTag = RepositoryConfigurationBody::DOMAIN;
    const SCHEMA_FAMILY: SchemaFamily = RepositoryConfigurationBody::SCHEMA_FAMILY;
    const SCHEMA_MAJOR: u16 = RepositoryConfigurationBody::SCHEMA_MAJOR;
    const SCHEMA_MINOR: u16 = RepositoryConfigurationBody::SCHEMA_MINOR;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_scalar(9999_u16);
        Ok(())
    }

    fn read_payload(_input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        Ok(Self)
    }
}

#[test]
fn a_layout_version_this_build_does_not_know_is_refused_even_when_verifying() {
    // The distinction that makes the v0 default safe rather than sloppy.
    //
    // Bytes that are NOT a configuration body mean "this head predates the
    // vocabulary" — legacy, verify it. Bytes that ARE one and name a version we
    // cannot read mean "this head is newer than us" — and reading that as
    // legacy would be a confident wrong answer about how its roots are laid
    // out. Only the first falls back.
    let backing = store();
    let future = FutureConfiguration;
    let key = fgit_authority::body_key(
        fgit_crypto::IdentityDomain::RepositoryConfiguration,
        &future,
    )
    .expect("a derivable key");
    backing
        .put_if_absent(&key, &encode_body(&future).expect("encodes"))
        .expect("the store accepts the write");

    let identity = fgit_authority::canonical_body_id(
        fgit_crypto::IdentityDomain::RepositoryConfiguration,
        fgit_types::CANONICAL_CODEC_VERSION,
        &future,
    )
    .expect("a derivable identity");
    let configuration_root = Digest::new(identity.algorithm(), *identity.digest());

    let failure = root_layout_for_verification(&backing, &configuration_root)
        .expect_err("an unknown layout version must not be read as legacy");
    assert!(
        matches!(failure, OutcomeFailure::Codec(_)),
        "a newer layout must refuse as a codec refusal, not silently become v0; got {failure:?}"
    );

    // The permitted twin: a body this build DOES understand, at the same key
    // shape, resolves normally. Without it the refusal above is satisfied by a
    // resolver that refuses every configuration body.
    let known = stage_repository_configuration(
        &backing,
        &RepositoryConfigurationBody {
            root_layout: RootLayoutVersion::RefStateMerkleV1,
        },
    )
    .expect("stages");
    assert_eq!(
        root_layout_for_verification(&backing, &known).expect("resolves"),
        RootLayoutVersion::RefStateMerkleV1
    );
}

#[test]
fn a_configuration_body_round_trips_through_its_canonical_encoding() {
    for version in RootLayoutVersion::ALL {
        let body = RepositoryConfigurationBody {
            root_layout: *version,
        };
        let bytes = encode_body(&body).expect("encodes");
        let decoded: RepositoryConfigurationBody =
            fgit_codec::decode_body(&bytes, fgit_codec::DecodeLimits::DEFAULT).expect("decodes");
        assert_eq!(decoded, body, "{version:?} must survive its canonical form");
    }
}
