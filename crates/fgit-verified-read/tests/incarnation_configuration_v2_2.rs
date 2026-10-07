#![forbid(unsafe_code)]
//! Real canonical codecs and Merkle proofs; no store, network, or signature oracle.
use fgit_codec::{
    CanonicalBody, CryptoBodyIdentity, DecodeLimits, RepositoryAuthorityHeadBody,
    RepositoryIncarnationConfigurationBodyV2_1, RepositoryIncarnationConfigurationBodyV2_2,
    body_id, harness::genesis_head,
};
use fgit_crypto::{
    ref_state_membership_proof, ref_state_merkle_root, ref_state_non_membership_proof,
};
use fgit_types::{Digest, GitHashAlgorithm, GitOid, RefName, RepositoryIncarnationId, RootLayoutVersion};
use fgit_verified_read::{
    PinnedAuthorityHead, RefDisclosurePolicy, VerifiedMembership, VerifiedReadAnswer,
    VerifiedReadConfiguration, VerifiedReadEnvelope, VerifiedReadRefusal, authorize_ref_absence,
    decode_verified_read_envelope, encode_verified_read_envelope, verify_envelope,
};

fn root<T: CanonicalBody>(body: &T) -> Digest {
    let id = body_id(&CryptoBodyIdentity, body).unwrap();
    Digest::new(id.algorithm(), *id.digest())
}
fn configuration(format: GitHashAlgorithm) -> RepositoryIncarnationConfigurationBodyV2_2 {
    RepositoryIncarnationConfigurationBodyV2_2 {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: format,
        repository_incarnation_id: RepositoryIncarnationId::from_bytes([0x73; 16]),
        policy_root: None,
        capability_revocation_root: None,
    }
}
fn fixture(c: RepositoryIncarnationConfigurationBodyV2_2) -> (PinnedAuthorityHead, VerifiedReadEnvelope) {
    let name = RefName::try_new(b"refs/heads/main").unwrap();
    let oid = GitOid::from_hex(c.object_format, &"ab".repeat(c.object_format.digest_len())).unwrap();
    let entries = [(name.clone(), oid)];
    let (_, proof) = ref_state_membership_proof(&entries, &name).unwrap();
    let mut head = genesis_head();
    head.configuration_root = root(&c);
    head.ref_root = ref_state_merkle_root(&entries).unwrap();
    (
        PinnedAuthorityHead::new(head.clone()),
        VerifiedReadEnvelope::new_with_exact_configuration(
            head,
            Some(VerifiedReadConfiguration::RepositoryIncarnationV2_2(c)),
            VerifiedReadAnswer::RefMembership { name, oid, proof: Box::new(proof) },
        ),
    )
}
fn replace(envelope: &VerifiedReadEnvelope, c: VerifiedReadConfiguration) -> VerifiedReadEnvelope {
    VerifiedReadEnvelope::new_with_exact_configuration(envelope.head().clone(), Some(c), envelope.answer().clone())
}

#[test]
fn exact_revocation_aware_bodies_roundtrip_in_both_native_hash_domains() {
    // Nonempty pointers are opaque committed identities here, not evidence that
    // the client loaded or authorized a revocation policy. No such claim is made.
    let pointer = genesis_head().configuration_root;
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for policy in [None, Some(pointer)] {
            for revocations in [None, Some(pointer)] {
                let c = RepositoryIncarnationConfigurationBodyV2_2 {
                    policy_root: policy, capability_revocation_root: revocations, ..configuration(format)
                };
                let (pin, envelope) = fixture(c);
                let bytes = encode_verified_read_envelope(&envelope).unwrap();
                let decoded = decode_verified_read_envelope(&bytes, DecodeLimits::DEFAULT).unwrap();
                assert_eq!(decoded, envelope);
                assert_eq!(decoded.configuration(), None, "the legacy getter must not normalize 2.2");
                assert_eq!(decoded.exact_configuration(), Some(&VerifiedReadConfiguration::RepositoryIncarnationV2_2(c)));
                assert_eq!(encode_verified_read_envelope(&decoded).unwrap(), bytes);
                assert_eq!(verify_envelope(&pin, &decoded), Ok(VerifiedMembership::Ref));
            }
        }
    }
}

#[test]
fn empty_revocation_selection_is_not_a_schema_2_1_alias() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let c = configuration(format);
        let old = RepositoryIncarnationConfigurationBodyV2_1 {
            root_layout: c.root_layout, object_format: c.object_format,
            repository_incarnation_id: c.repository_incarnation_id, policy_root: c.policy_root,
        };
        assert_ne!(root(&c), root(&old));
        let (pin, envelope) = fixture(c);
        let alias = replace(&envelope, VerifiedReadConfiguration::RepositoryIncarnationV2_1(old));
        assert_eq!(verify_envelope(&pin, &alias), Err(VerifiedReadRefusal::ConfigurationRootMismatch));
        // Nor may a 2.2 spelling impersonate a pinned, genuine 2.1 configuration.
        let mut old_head = envelope.head().clone();
        old_head.configuration_root = root(&old);
        let old_pin = PinnedAuthorityHead::new(old_head.clone());
        let exact_old = VerifiedReadEnvelope::new_with_exact_configuration(
            old_head.clone(), Some(VerifiedReadConfiguration::RepositoryIncarnationV2_1(old)), envelope.answer().clone(),
        );
        assert_eq!(verify_envelope(&old_pin, &exact_old), Ok(VerifiedMembership::Ref));
        let upgrade_alias = VerifiedReadEnvelope::new_with_exact_configuration(
            old_head, Some(VerifiedReadConfiguration::RepositoryIncarnationV2_2(c)), envelope.answer().clone(),
        );
        assert_eq!(verify_envelope(&old_pin, &upgrade_alias), Err(VerifiedReadRefusal::ConfigurationRootMismatch));
    }
}

#[test]
fn every_configuration_field_is_bound_to_the_independently_pinned_head() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let c = configuration(format);
        let (pin, envelope) = fixture(c);
        for changed in [
            RepositoryIncarnationConfigurationBodyV2_2 { policy_root: Some(genesis_head().configuration_root), ..c },
            RepositoryIncarnationConfigurationBodyV2_2 { capability_revocation_root: Some(genesis_head().configuration_root), ..c },
            RepositoryIncarnationConfigurationBodyV2_2 { repository_incarnation_id: RepositoryIncarnationId::from_bytes([0x74; 16]), ..c },
            RepositoryIncarnationConfigurationBodyV2_2 { root_layout: RootLayoutVersion::LegacyWholeBody, ..c },
            RepositoryIncarnationConfigurationBodyV2_2 { object_format: if format == GitHashAlgorithm::Sha1 { GitHashAlgorithm::Sha256 } else { GitHashAlgorithm::Sha1 }, ..c },
        ] {
            let tampered = replace(&envelope, VerifiedReadConfiguration::RepositoryIncarnationV2_2(changed));
            let bytes = encode_verified_read_envelope(&tampered).unwrap();
            let decoded = decode_verified_read_envelope(&bytes, DecodeLimits::DEFAULT).unwrap();
            assert_eq!(verify_envelope(&pin, &decoded), Err(VerifiedReadRefusal::ConfigurationRootMismatch));
        }
        let mut changed_head: RepositoryAuthorityHeadBody = envelope.head().clone();
        changed_head.configuration_root = genesis_head().configuration_root;
        let moved = VerifiedReadEnvelope::new_with_exact_configuration(
            changed_head, envelope.exact_configuration().cloned(), envelope.answer().clone(),
        );
        assert_eq!(verify_envelope(&pin, &moved), Err(VerifiedReadRefusal::PinnedHeadMismatch));
    }
}

struct Disclose;
impl RefDisclosurePolicy for Disclose {
    fn permits_ref_disclosure(&self, _: &RefName) -> bool { true }
}
#[test]
fn schema_2_2_supports_real_absence_proofs_without_a_missing_proof_fallback() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let c = configuration(format);
        let name = RefName::try_new(b"refs/heads/missing").unwrap();
        let mut head = genesis_head();
        head.configuration_root = root(&c);
        head.ref_root = ref_state_merkle_root(&[]).unwrap();
        let pin = PinnedAuthorityHead::new(head.clone());
        let answer = VerifiedReadAnswer::AuthorizedRefAbsence {
            absence: authorize_ref_absence(&Disclose, name.clone(), |_| false).unwrap(),
            proof: Box::new(ref_state_non_membership_proof(&[], &name).unwrap()),
        };
        let envelope = VerifiedReadEnvelope::new_with_exact_configuration(head, Some(VerifiedReadConfiguration::RepositoryIncarnationV2_2(c)), answer);
        let bytes = encode_verified_read_envelope(&envelope).unwrap();
        let decoded = decode_verified_read_envelope(&bytes, DecodeLimits::DEFAULT).unwrap();
        assert_eq!(verify_envelope(&pin, &decoded), Ok(VerifiedMembership::RefAbsence));
        for end in 0..bytes.len() {
            assert!(decode_verified_read_envelope(&bytes[..end], DecodeLimits::DEFAULT).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_verified_read_envelope(&trailing, DecodeLimits::DEFAULT).is_err());
    }
}
