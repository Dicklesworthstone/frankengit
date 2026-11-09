#![forbid(unsafe_code)]

//! The V2 ref root authenticates symbolic HEAD without reinterpreting V1.

use fgit_codec::{
    CryptoBodyIdentity, DecodeLimits, RepositoryConfigurationBody, body_id, harness::genesis_head,
    split_frame,
};
use fgit_crypto::{
    RefStateNonMembershipProof, object_closure_membership_proof, object_closure_merkle_root,
    ref_state_membership_proof, ref_state_membership_proof_v2, ref_state_merkle_root,
    ref_state_merkle_root_v2, ref_state_non_membership_proof, ref_state_non_membership_proof_v2,
};
use fgit_types::{
    Digest, GitHashAlgorithm, GitOid, GitOidSha1, GitOidSha256, RefName, RootLayoutVersion,
};
use fgit_verified_read::{
    PinnedAuthorityHead, RefDisclosurePolicy, VerifiedMembership, VerifiedReadAnswer,
    VerifiedReadEnvelope, VerifiedReadRefusal, authorize_ref_absence,
    authorize_ref_absence_witness, decode_ref_state_non_membership_proof,
    decode_verified_read_envelope, encode_ref_state_non_membership_proof,
    encode_verified_read_envelope, verify_envelope,
};

struct Disclosure {
    denied: Vec<RefName>,
}

impl RefDisclosurePolicy for Disclosure {
    fn permits_ref_disclosure(&self, name: &RefName) -> bool {
        !self.denied.contains(name)
    }
}

fn name(bytes: &[u8]) -> RefName {
    RefName::try_new(bytes).unwrap()
}

fn oid(format: GitHashAlgorithm, byte: u8) -> GitOid {
    match format {
        GitHashAlgorithm::Sha1 => GitOid::Sha1(GitOidSha1::from_bytes([byte; 20])),
        GitHashAlgorithm::Sha256 => GitOid::Sha256(GitOidSha256::from_bytes([byte; 32])),
    }
}

fn envelope(
    layout: RootLayoutVersion,
    format: GitHashAlgorithm,
    ref_root: Digest,
    answer: VerifiedReadAnswer,
) -> (PinnedAuthorityHead, VerifiedReadEnvelope) {
    let configuration = RepositoryConfigurationBody {
        root_layout: layout,
        object_format: format,
        hidden_ref_rules: Vec::new(),
    };
    let identity = body_id(&CryptoBodyIdentity, &configuration).unwrap();
    let mut head = genesis_head();
    head.configuration_root = Digest::new(identity.algorithm(), *identity.digest());
    head.ref_root = ref_root;
    (
        PinnedAuthorityHead::new(head.clone()),
        VerifiedReadEnvelope::new(head, Some(configuration), answer),
    )
}

fn absence_answer(query: RefName, proof: RefStateNonMembershipProof) -> VerifiedReadAnswer {
    let disclosure = Disclosure { denied: Vec::new() };
    let absence = authorize_ref_absence(&disclosure, query, |_| false).unwrap();
    authorize_ref_absence_witness(&disclosure, &proof).unwrap();
    VerifiedReadAnswer::AuthorizedRefAbsence {
        absence,
        proof: Box::new(proof),
    }
}

fn relay(envelope: &VerifiedReadEnvelope) -> VerifiedReadEnvelope {
    let wire = encode_verified_read_envelope(envelope).unwrap();
    let decoded = decode_verified_read_envelope(&wire, DecodeLimits::DEFAULT).unwrap();
    assert_eq!(encode_verified_read_envelope(&decoded).unwrap(), wire);
    decoded
}

#[test]
fn v2_ref_membership_survives_relay_but_not_a_changed_head_target() {
    for layout in [
        RootLayoutVersion::RefStateMerkleV2,
        RootLayoutVersion::RefStateAndObjectClosureMerkleV2,
    ] {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let main = name(b"refs/heads/main");
            let other = name(b"refs/heads/other");
            let entries = vec![
                (main.clone(), oid(format, 1)),
                (other.clone(), oid(format, 2)),
            ];
            let (bound_oid, proof) =
                ref_state_membership_proof_v2(&entries, Some(&main), &main).unwrap();
            assert_eq!(proof.index(), 1, "HEAD occupies the first leaf");
            let answer = VerifiedReadAnswer::RefMembership {
                name: main.clone(),
                oid: bound_oid,
                proof: Box::new(proof),
            };
            let (pin, original) = envelope(
                layout,
                format,
                ref_state_merkle_root_v2(&entries, Some(&main)).unwrap(),
                answer.clone(),
            );
            assert_eq!(
                verify_envelope(&pin, &relay(&original)),
                Ok(VerifiedMembership::Ref)
            );

            for changed in [None, Some(&other)] {
                let (pin, rebound) = envelope(
                    layout,
                    format,
                    ref_state_merkle_root_v2(&entries, changed).unwrap(),
                    answer.clone(),
                );
                assert_eq!(
                    verify_envelope(&pin, &relay(&rebound)),
                    Err(VerifiedReadRefusal::ProofRejected)
                );
            }
        }
    }
}

#[test]
fn v2_absence_relay_covers_empty_and_all_ordered_intervals() {
    for layout in [
        RootLayoutVersion::RefStateMerkleV2,
        RootLayoutVersion::RefStateAndObjectClosureMerkleV2,
    ] {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let target = name(b"refs/heads/unborn-\xff");
            let entries = vec![
                (name(b"refs/heads/main"), oid(format, 1)),
                (name(b"refs/tags/v1"), oid(format, 2)),
            ];
            for head_target in [None, Some(&target)] {
                for (state, query) in [
                    (Vec::new(), name(b"refs/heads/missing")),
                    (entries.clone(), name(b"refs/heads/aaa")),
                    (entries.clone(), name(b"refs/heads/middle")),
                    (entries.clone(), name(b"refs/zzzz")),
                ] {
                    let proof =
                        ref_state_non_membership_proof_v2(&state, head_target, &query).unwrap();
                    let wire = encode_ref_state_non_membership_proof(&proof).unwrap();
                    assert_eq!(
                        decode_ref_state_non_membership_proof(&wire, DecodeLimits::DEFAULT)
                            .unwrap(),
                        proof
                    );
                    let (pin, value) = envelope(
                        layout,
                        format,
                        ref_state_merkle_root_v2(&state, head_target).unwrap(),
                        absence_answer(query, proof),
                    );
                    assert_eq!(
                        verify_envelope(&pin, &relay(&value)),
                        Ok(VerifiedMembership::RefAbsence)
                    );
                }
            }
        }
    }
}

#[test]
fn empty_state_witnesses_cannot_be_reinterpreted_across_layout_versions() {
    let query = name(b"refs/heads/missing");
    let target = name(b"refs/heads/unborn");
    let v1 = RefStateNonMembershipProof::EmptyState;
    let v2 = RefStateNonMembershipProof::HeadOnly {
        head_target: Some(target.clone()),
    };
    for (layout, root, honest, foreign) in [
        (
            RootLayoutVersion::RefStateMerkleV1,
            ref_state_merkle_root(&[]).unwrap(),
            v1.clone(),
            v2.clone(),
        ),
        (
            RootLayoutVersion::RefStateMerkleV2,
            ref_state_merkle_root_v2(&[], Some(&target)).unwrap(),
            v2,
            v1,
        ),
    ] {
        let (pin, accepted) = envelope(
            layout,
            GitHashAlgorithm::Sha1,
            root,
            absence_answer(query.clone(), honest),
        );
        assert_eq!(
            verify_envelope(&pin, &relay(&accepted)),
            Ok(VerifiedMembership::RefAbsence)
        );
        let (_, refused) = envelope(
            layout,
            GitHashAlgorithm::Sha1,
            root,
            absence_answer(query.clone(), foreign),
        );
        assert_eq!(
            verify_envelope(&pin, &relay(&refused)),
            Err(VerifiedReadRefusal::ProofRejected)
        );
    }
    for changed in [None, Some(name(b"refs/heads/different"))] {
        let (pin, tampered) = envelope(
            RootLayoutVersion::RefStateMerkleV2,
            GitHashAlgorithm::Sha1,
            ref_state_merkle_root_v2(&[], Some(&target)).unwrap(),
            absence_answer(
                query.clone(),
                RefStateNonMembershipProof::HeadOnly {
                    head_target: changed,
                },
            ),
        );
        assert_eq!(
            verify_envelope(&pin, &relay(&tampered)),
            Err(VerifiedReadRefusal::ProofRejected)
        );
    }
}

#[test]
fn v1_membership_keeps_its_historical_root_and_cannot_claim_v2() {
    let main = name(b"refs/heads/main");
    let entries = vec![(main.clone(), oid(GitHashAlgorithm::Sha1, 1))];
    let (oid, proof) = ref_state_membership_proof(&entries, &main).unwrap();
    let answer = VerifiedReadAnswer::RefMembership {
        name: main.clone(),
        oid,
        proof: Box::new(proof),
    };
    let (pin, old) = envelope(
        RootLayoutVersion::RefStateMerkleV1,
        GitHashAlgorithm::Sha1,
        ref_state_merkle_root(&entries).unwrap(),
        answer.clone(),
    );
    assert_eq!(
        verify_envelope(&pin, &relay(&old)),
        Ok(VerifiedMembership::Ref)
    );
    let (pin, wrong_layout) = envelope(
        RootLayoutVersion::RefStateMerkleV2,
        GitHashAlgorithm::Sha1,
        ref_state_merkle_root_v2(&entries, Some(&main)).unwrap(),
        answer,
    );
    assert_eq!(
        verify_envelope(&pin, &relay(&wrong_layout)),
        Err(VerifiedReadRefusal::ProofRejected)
    );
}

#[test]
fn head_only_wire_tag_preserves_exact_optional_raw_ref_bytes() {
    for target in [None, Some(name(b"refs/heads/\xff-unborn"))] {
        let proof = RefStateNonMembershipProof::HeadOnly {
            head_target: target.clone(),
        };
        let encoded = encode_ref_state_non_membership_proof(&proof).unwrap();
        let (_, payload) = split_frame(&encoded, DecodeLimits::DEFAULT).unwrap();
        let mut expected = vec![4, u8::from(target.is_some())];
        if let Some(target) = &target {
            expected.extend_from_slice(&u32::try_from(target.len()).unwrap().to_be_bytes());
            expected.extend_from_slice(target.as_bytes());
        }
        assert_eq!(
            payload, expected,
            "tag 4 is distinct from every V1 absence variant"
        );
        assert_eq!(
            decode_ref_state_non_membership_proof(&encoded, DecodeLimits::DEFAULT).unwrap(),
            proof
        );

        let option_at = encoded.len() - payload.len() + 1;
        let mut invalid_option = encoded.clone();
        invalid_option[option_at] = 2;
        assert!(matches!(
            decode_ref_state_non_membership_proof(&invalid_option, DecodeLimits::DEFAULT),
            Err(VerifiedReadRefusal::WireDecode(_))
        ));
        assert!(matches!(
            decode_ref_state_non_membership_proof(
                &encoded[..encoded.len() - 1],
                DecodeLimits::DEFAULT
            ),
            Err(VerifiedReadRefusal::WireDecode(_))
        ));
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            decode_ref_state_non_membership_proof(&trailing, DecodeLimits::DEFAULT),
            Err(VerifiedReadRefusal::WireDecode(_))
        ));
    }
}

#[test]
fn absence_witness_disclosure_checks_head_and_unborn_target_independently() {
    let query = name(b"refs/heads/visible-missing");
    let target = name(b"refs/heads/private-unborn");
    let head = RefName::try_new_one_level(b"HEAD").unwrap();
    let proof = RefStateNonMembershipProof::HeadOnly {
        head_target: Some(target.clone()),
    };
    for denied in [head.clone(), target] {
        let policy = Disclosure {
            denied: vec![denied],
        };
        assert!(authorize_ref_absence(&policy, query.clone(), |_| false).is_ok());
        assert_eq!(
            authorize_ref_absence_witness(&policy, &proof),
            Err(VerifiedReadRefusal::RefNotFoundOrUnauthorized)
        );
    }
    assert_eq!(
        authorize_ref_absence_witness(&Disclosure { denied: Vec::new() }, &proof),
        Ok(())
    );
    let no_target = RefStateNonMembershipProof::HeadOnly { head_target: None };
    assert_eq!(
        authorize_ref_absence_witness(&Disclosure { denied: vec![head] }, &no_target),
        Err(VerifiedReadRefusal::RefNotFoundOrUnauthorized)
    );
    assert_eq!(
        authorize_ref_absence_witness(&Disclosure { denied: Vec::new() }, &no_target),
        Ok(())
    );
}

#[test]
fn ordered_absence_neighbours_must_be_disclosed_in_both_layouts() {
    let first = name(b"refs/heads/first");
    let last = name(b"refs/heads/last");
    let entries = vec![
        (first.clone(), oid(GitHashAlgorithm::Sha1, 1)),
        (last.clone(), oid(GitHashAlgorithm::Sha1, 2)),
    ];
    for query in [
        name(b"refs/heads/aaa"),
        name(b"refs/heads/gap"),
        name(b"refs/heads/zzz"),
    ] {
        for proof in [
            ref_state_non_membership_proof(&entries, &query).unwrap(),
            ref_state_non_membership_proof_v2(&entries, Some(&first), &query).unwrap(),
        ] {
            let names = match &proof {
                RefStateNonMembershipProof::BeforeFirst { first } => vec![first.name().clone()],
                RefStateNonMembershipProof::Between {
                    predecessor,
                    successor,
                } => vec![predecessor.name().clone(), successor.name().clone()],
                RefStateNonMembershipProof::AfterLast { last } => vec![last.name().clone()],
                _ => panic!("populated map must disclose a neighbour"),
            };
            for denied in names {
                let policy = Disclosure {
                    denied: vec![denied],
                };
                assert!(authorize_ref_absence(&policy, query.clone(), |_| false).is_ok());
                assert_eq!(
                    authorize_ref_absence_witness(&policy, &proof),
                    Err(VerifiedReadRefusal::RefNotFoundOrUnauthorized)
                );
            }
            assert_eq!(
                authorize_ref_absence_witness(&Disclosure { denied: Vec::new() }, &proof),
                Ok(())
            );
            // The optional HEAD target is hidden behind sibling hashes in a
            // populated map. Do not deny a proof that discloses no HEAD name.
            assert_eq!(
                authorize_ref_absence_witness(
                    &Disclosure {
                        denied: vec![RefName::try_new_one_level(b"HEAD").unwrap()]
                    },
                    &proof
                ),
                Ok(())
            );
        }
    }
}

#[test]
fn combined_v2_keeps_object_proofs_while_ref_only_v2_refuses_them() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let objects = vec![oid(format, 1), oid(format, 2)];
        let object_root = object_closure_merkle_root(&objects).unwrap();
        let proof = object_closure_membership_proof(&objects, &objects[0]).unwrap();
        for layout in [
            RootLayoutVersion::RefStateAndObjectClosureMerkleV2,
            RootLayoutVersion::RefStateMerkleV2,
        ] {
            let (pin, value) = envelope(
                layout,
                format,
                ref_state_merkle_root_v2(&[], None).unwrap(),
                VerifiedReadAnswer::ObjectMembership {
                    oid: objects[0],
                    proof: Box::new(proof.clone()),
                },
            );
            let pin = PinnedAuthorityHead::new_with_object_closure(pin.body().clone(), object_root);
            let result = verify_envelope(&pin, &relay(&value));
            if layout.admits_object_closure_membership_proof() {
                assert_eq!(result, Ok(VerifiedMembership::Object));
            } else {
                assert!(matches!(result, Err(VerifiedReadRefusal::ObjectLayout(_))));
            }
        }
    }
}
