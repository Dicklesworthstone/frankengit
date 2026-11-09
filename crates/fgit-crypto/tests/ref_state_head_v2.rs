//! Authenticated symbolic HEAD, historical-layout isolation, and ordered proofs.

use fgit_crypto::{
    IdentityDomain, MerkleProof, MerkleRefusal, RefStateNeighbour, RefStateNonMembershipProof,
    internal_digest_over_parts, lowercase_hex, merkle_leaf, merkle_root, merkle_root_from_proof,
    ref_state_head_leaf_v2, ref_state_head_membership_proof_v2, ref_state_leaf, ref_state_leaf_v2,
    ref_state_membership_proof, ref_state_membership_proof_v2, ref_state_merkle_root,
    ref_state_merkle_root_v2, ref_state_non_membership_proof, ref_state_non_membership_proof_v2,
    ref_state_schema_v2, verify_ref_state_head_membership_under, verify_ref_state_membership_under,
    verify_ref_state_non_membership_under,
};
use fgit_types::label::{SchemaFamily, SchemaId};
use fgit_types::layout::RootLayoutVersion;
use fgit_types::native::{GitOid, GitOidSha1, GitOidSha256};
use fgit_types::refs::RefName;

const V2_LAYOUTS: [RootLayoutVersion; 2] = [
    RootLayoutVersion::RefStateMerkleV2,
    RootLayoutVersion::RefStateAndObjectClosureMerkleV2,
];
const V1_LAYOUTS: [RootLayoutVersion; 2] = [
    RootLayoutVersion::RefStateMerkleV1,
    RootLayoutVersion::RefStateAndObjectClosureMerkleV1,
];

fn name(text: &str) -> RefName {
    RefName::try_new(text.as_bytes()).expect("valid ref name")
}

const fn oid(seed: u8, sha256: bool) -> GitOid {
    if sha256 {
        GitOid::Sha256(GitOidSha256::from_bytes([seed; GitOidSha256::LEN]))
    } else {
        GitOid::Sha1(GitOidSha1::from_bytes([seed; GitOidSha1::LEN]))
    }
}

#[test]
fn independently_derived_sha256_roots_pin_the_v2_wire_commitment() {
    // Derived with Python hashlib.sha256 and goldens/derive.py::internal_preimage,
    // not these Rust builders. Bodies are [0, option, u32be len, target] or
    // [1, u32be len, ref, u16be Git hash, oid], under schema ref-state-merkle 2.0.
    // Each root wraps its raw apex in MerkleNode body [2, u64be leaf_count, apex].
    let main = name("refs/heads/main");
    assert_eq!(
        lowercase_hex(ref_state_head_leaf_v2(None).unwrap().as_bytes()),
        "aa7193da3b5031c9e2fe4fce540409afff34bbc5acbd0d5e9f50a5b39074abe5"
    );
    assert_eq!(
        lowercase_hex(ref_state_head_leaf_v2(Some(&main)).unwrap().as_bytes()),
        "f0866445fe230799026f4b3be38ddcff42cffd6f4c6a3bbf4faa7f6f1f4d628f"
    );
    for (head, expected) in [
        (
            None,
            "c9a0767669de9bcf2d0b49afc507cd4f1ffaff1ea52d9faefaeb111604692bd0",
        ),
        (
            Some(&main),
            "f38ed7fcc9758f0aec5dbacb7ea8c39f830700e36c271953b500271aa1df3b1f",
        ),
    ] {
        assert_eq!(
            lowercase_hex(
                ref_state_merkle_root_v2(&[], head)
                    .unwrap()
                    .bytes()
                    .as_bytes()
            ),
            expected
        );
    }
    for (sha256, none_root, main_root) in [
        (
            false,
            "45606b67d1ee11c3b08caa85992f10d958242a726576ad2bd7a787f4e7f50d6e",
            "c0b0977345d487a04da35ab9975b91d267f4f07404da0593a262a21e34c5c0f9",
        ),
        (
            true,
            "5f045edda370ea7ddd1488c1e5942bcecd6adeefc4001a7b91c60f8baa43d7ea",
            "f367497e27da3e110c977adc301211f11d83eb6100b3ad2c3c0fec83e5127827",
        ),
    ] {
        let entries = [(main.clone(), oid(0x41, sha256))];
        for (head, expected) in [(None, none_root), (Some(&main), main_root)] {
            let root = ref_state_merkle_root_v2(&entries, head).unwrap();
            assert_eq!(lowercase_hex(root.bytes().as_bytes()), expected);
        }
    }
}

#[test]
fn v2_preimages_pin_schema_type_option_lengths_and_native_hash() {
    let schema = SchemaId::new(SchemaFamily::from_static("ref-state-merkle"), 2, 0);
    assert_eq!(ref_state_schema_v2(), schema);
    let main = name("refs/heads/main");
    let none_leaf = merkle_leaf(schema, &[&[0, 0]]);
    let main_leaf = merkle_leaf(schema, &[b"\0\x01\0\0\0\x0frefs/heads/main"]);
    assert_eq!(ref_state_head_leaf_v2(None), Ok(none_leaf));
    assert_eq!(ref_state_head_leaf_v2(Some(&main)), Ok(main_leaf));

    for sha256 in [false, true] {
        let native_oid = oid(0x41, sha256);
        let hash_code = native_oid.algorithm().code_point().to_be_bytes();
        let expected_ref = merkle_leaf(
            schema,
            &[
                b"\x01\0\0\0\x0frefs/heads/main",
                &hash_code,
                native_oid.as_bytes(),
            ],
        );
        assert_eq!(ref_state_leaf_v2(&main, &native_oid), expected_ref);
        let entries = [(main.clone(), native_oid)];
        let apex = merkle_root(schema, &[main_leaf, expected_ref]);
        let expected_root = internal_digest_over_parts(
            IdentityDomain::MerkleNode,
            schema,
            &[&[2], &2_u64.to_be_bytes(), apex.as_bytes()],
        );
        assert_eq!(
            ref_state_merkle_root_v2(&entries, Some(&main))
                .unwrap()
                .bytes(),
            &expected_root
        );
        assert_ne!(expected_ref, ref_state_leaf(&main, &native_oid));
    }
}

#[test]
fn changing_only_head_always_changes_root_including_empty_and_unborn_states() {
    let main = name("refs/heads/main");
    let other = name("refs/heads/other");
    let unborn = name("refs/heads/unborn");
    for sha256 in [false, true] {
        for entries in [
            vec![],
            vec![
                (main.clone(), oid(1, sha256)),
                (other.clone(), oid(2, sha256)),
            ],
        ] {
            let roots = [None, Some(&main), Some(&other), Some(&unborn)]
                .map(|head| ref_state_merkle_root_v2(&entries, head).expect("v2 root"));
            for (index, root) in roots.iter().enumerate() {
                for other_root in &roots[index + 1..] {
                    assert_ne!(root, other_root, "HEAD alone is authoritative");
                }
                assert_ne!(*root, ref_state_merkle_root(&entries).unwrap());
            }
        }
    }
}

#[test]
fn every_direct_ref_and_head_verify_at_odd_and_even_tree_sizes() {
    let head = name("refs/heads/unborn");
    for sha256 in [false, true] {
        for count in 0_u8..=9 {
            let entries: Vec<_> = (0..count)
                .map(|index| (name(&format!("refs/heads/r{index:02}")), oid(index, sha256)))
                .collect();
            for head_target in [None, Some(&head)] {
                let root = ref_state_merkle_root_v2(&entries, head_target).unwrap();
                let head_proof = ref_state_head_membership_proof_v2(&entries, head_target).unwrap();
                assert_eq!(head_proof.index(), 0);
                assert_eq!(head_proof.leaf_count(), usize::from(count) + 1);
                for version in V2_LAYOUTS {
                    assert_eq!(
                        verify_ref_state_head_membership_under(
                            version,
                            &root,
                            head_target,
                            &head_proof
                        ),
                        Ok(true)
                    );
                    for (index, (ref_name, expected_oid)) in entries.iter().enumerate() {
                        let (proven_oid, proof) =
                            ref_state_membership_proof_v2(&entries, head_target, ref_name).unwrap();
                        assert_eq!(proven_oid, *expected_oid);
                        assert_eq!(proof.index(), index + 1);
                        assert_eq!(proof.leaf_count(), usize::from(count) + 1);
                        assert_eq!(
                            verify_ref_state_membership_under(
                                version,
                                &root,
                                ref_name,
                                &proven_oid,
                                &proof
                            ),
                            Ok(true)
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn leaf_count_binding_stops_promoted_subtree_from_hiding_the_first_direct_ref() {
    let first = name("refs/heads/a");
    let last = name("refs/heads/b");
    let after = name("refs/heads/z");
    for sha256 in [false, true] {
        let entries = [
            (first.clone(), oid(1, sha256)),
            (last.clone(), oid(2, sha256)),
        ];
        let root = ref_state_merkle_root_v2(&entries, Some(&first)).unwrap();
        let (_, honest) = ref_state_membership_proof_v2(&entries, Some(&first), &last).unwrap();
        assert_eq!((honest.index(), honest.leaf_count()), (2, 3));

        // Raw odd-promotion trees alone cannot distinguish these claims:
        // node(node(HEAD,A),B) also folds B at index 1 of a claimed two-leaf tree.
        let relabelled = MerkleProof::new(1, 2, honest.siblings().to_vec());
        let leaf = ref_state_leaf_v2(&last, &entries[1].1);
        assert_eq!(
            merkle_root_from_proof(ref_state_schema_v2(), &leaf, &honest),
            merkle_root_from_proof(ref_state_schema_v2(), &leaf, &relabelled)
        );
        let false_first = RefStateNonMembershipProof::BeforeFirst {
            first: Box::new(RefStateNeighbour::new(
                last.clone(),
                entries[1].1,
                relabelled.clone(),
            )),
        };
        let false_count_last = RefStateNonMembershipProof::AfterLast {
            last: Box::new(RefStateNeighbour::new(
                last.clone(),
                entries[1].1,
                relabelled.clone(),
            )),
        };
        let honest_last =
            ref_state_non_membership_proof_v2(&entries, Some(&first), &after).unwrap();
        for version in V2_LAYOUTS {
            assert_eq!(
                verify_ref_state_membership_under(version, &root, &last, &entries[1].1, &honest),
                Ok(true)
            );
            assert_eq!(
                verify_ref_state_non_membership_under(version, &root, &after, &honest_last),
                Ok(true)
            );
            assert_eq!(
                verify_ref_state_membership_under(
                    version,
                    &root,
                    &last,
                    &entries[1].1,
                    &relabelled
                ),
                Ok(false)
            );
            assert_eq!(
                verify_ref_state_non_membership_under(version, &root, &first, &false_first),
                Ok(false)
            );
            assert_eq!(
                verify_ref_state_non_membership_under(version, &root, &after, &false_count_last),
                Ok(false)
            );
        }

        // The count also cannot be inflated while retaining a path that has
        // identical folds. This covers HEAD and ordinary direct membership.
        let head = ref_state_head_membership_proof_v2(&entries, Some(&first)).unwrap();
        let (_, member) = ref_state_membership_proof_v2(&entries, Some(&first), &first).unwrap();
        for (honest, leaf) in [
            (&head, ref_state_head_leaf_v2(Some(&first)).unwrap()),
            (&member, ref_state_leaf_v2(&first, &entries[0].1)),
        ] {
            let inflated = MerkleProof::new(honest.index(), 4, honest.siblings().to_vec());
            assert_eq!(
                merkle_root_from_proof(ref_state_schema_v2(), &leaf, honest),
                merkle_root_from_proof(ref_state_schema_v2(), &leaf, &inflated)
            );
            for version in V2_LAYOUTS {
                assert_eq!(
                    verify_ref_state_head_membership_under(version, &root, Some(&first), &inflated),
                    Ok(false)
                );
                assert_eq!(
                    verify_ref_state_membership_under(
                        version,
                        &root,
                        &first,
                        &entries[0].1,
                        &inflated
                    ),
                    Ok(false)
                );
            }
        }
    }
}

#[test]
fn head_substitution_removal_and_retargeted_proofs_fail() {
    let main = name("refs/heads/main");
    let other = name("refs/heads/other");
    for sha256 in [false, true] {
        let entries = [
            (main.clone(), oid(1, sha256)),
            (other.clone(), oid(2, sha256)),
        ];
        let root = ref_state_merkle_root_v2(&entries, Some(&main)).unwrap();
        let (_, proof) = ref_state_membership_proof_v2(&entries, Some(&main), &main).unwrap();
        let head_proof = ref_state_head_membership_proof_v2(&entries, Some(&main)).unwrap();
        for version in V2_LAYOUTS {
            assert_eq!(
                verify_ref_state_membership_under(version, &root, &main, &entries[0].1, &proof),
                Ok(true)
            );
            assert_eq!(
                verify_ref_state_head_membership_under(version, &root, Some(&main), &head_proof),
                Ok(true)
            );
            for substituted in [None, Some(&other)] {
                assert_eq!(
                    verify_ref_state_head_membership_under(
                        version,
                        &root,
                        substituted,
                        &head_proof
                    ),
                    Ok(false)
                );
                let substituted_root = ref_state_merkle_root_v2(&entries, substituted).unwrap();
                assert_eq!(
                    verify_ref_state_membership_under(
                        version,
                        &substituted_root,
                        &main,
                        &entries[0].1,
                        &proof
                    ),
                    Ok(false)
                );
            }
            assert_eq!(
                verify_ref_state_membership_under(version, &root, &main, &oid(3, sha256), &proof),
                Ok(false)
            );
            assert_eq!(
                verify_ref_state_membership_under(version, &root, &other, &entries[0].1, &proof),
                Ok(false)
            );
            assert_eq!(
                verify_ref_state_head_membership_under(version, &root, Some(&main), &proof),
                Ok(false)
            );
            assert_eq!(
                verify_ref_state_membership_under(
                    version,
                    &root,
                    &main,
                    &entries[0].1,
                    &head_proof
                ),
                Ok(false)
            );
            let wrong_index = MerkleProof::new(0, proof.leaf_count(), proof.siblings().to_vec());
            assert_eq!(
                verify_ref_state_membership_under(
                    version,
                    &root,
                    &main,
                    &entries[0].1,
                    &wrong_index
                ),
                Ok(false)
            );
        }
    }
}

#[test]
fn v1_proofs_keep_their_meaning_and_cannot_be_reinterpreted_as_v2() {
    let main = name("refs/heads/main");
    let missing = name("refs/heads/absent");
    let entries = [(main.clone(), oid(1, false))];
    let v1_root = ref_state_merkle_root(&entries).unwrap();
    let (_, v1_proof) = ref_state_membership_proof(&entries, &main).unwrap();
    let v1_absent = ref_state_non_membership_proof(&entries, &missing).unwrap();
    let v2_root = ref_state_merkle_root_v2(&entries, Some(&main)).unwrap();
    let (_, v2_proof) = ref_state_membership_proof_v2(&entries, Some(&main), &main).unwrap();
    let v2_absent = ref_state_non_membership_proof_v2(&entries, Some(&main), &missing).unwrap();
    for version in V1_LAYOUTS {
        assert_eq!(
            verify_ref_state_membership_under(version, &v1_root, &main, &entries[0].1, &v1_proof),
            Ok(true)
        );
        assert_eq!(
            verify_ref_state_non_membership_under(version, &v1_root, &missing, &v1_absent),
            Ok(true)
        );
        assert_eq!(
            verify_ref_state_membership_under(version, &v2_root, &main, &entries[0].1, &v2_proof),
            Ok(false)
        );
        assert_eq!(
            verify_ref_state_non_membership_under(version, &v2_root, &missing, &v2_absent),
            Ok(false)
        );
    }
    for version in V2_LAYOUTS {
        assert_eq!(
            verify_ref_state_membership_under(version, &v1_root, &main, &entries[0].1, &v1_proof),
            Ok(false)
        );
        assert_eq!(
            verify_ref_state_non_membership_under(version, &v1_root, &missing, &v1_absent),
            Ok(false)
        );
    }
    for version in [
        RootLayoutVersion::LegacyWholeBody,
        V1_LAYOUTS[0],
        V1_LAYOUTS[1],
    ] {
        assert_eq!(
            verify_ref_state_head_membership_under(version, &v2_root, Some(&main), &v2_proof),
            Err(MerkleRefusal::LayoutAdmitsNoProof { version })
        );
    }
}

#[test]
fn empty_direct_map_requires_head_only_witness_with_exact_optional_target() {
    let main = name("refs/heads/main");
    let other = name("refs/heads/other");
    for head in [None, Some(&main)] {
        let root = ref_state_merkle_root_v2(&[], head).unwrap();
        let proof = ref_state_non_membership_proof_v2(&[], head, &main).unwrap();
        assert_eq!(
            proof,
            RefStateNonMembershipProof::HeadOnly {
                head_target: head.cloned()
            }
        );
        for version in V2_LAYOUTS {
            assert_eq!(
                verify_ref_state_non_membership_under(version, &root, &main, &proof),
                Ok(true)
            );
            assert_eq!(
                verify_ref_state_non_membership_under(version, &root, &other, &proof),
                Ok(true)
            );
            assert_eq!(
                verify_ref_state_non_membership_under(
                    version,
                    &root,
                    &main,
                    &RefStateNonMembershipProof::EmptyState
                ),
                Ok(false)
            );
            for wrong in [None, Some(&main), Some(&other)]
                .into_iter()
                .filter(|target| *target != head)
            {
                let wrong_proof = RefStateNonMembershipProof::HeadOnly {
                    head_target: wrong.cloned(),
                };
                assert_eq!(
                    verify_ref_state_non_membership_under(version, &root, &main, &wrong_proof),
                    Ok(false)
                );
            }
            let populated =
                ref_state_merkle_root_v2(&[(main.clone(), oid(1, false))], head).unwrap();
            assert_eq!(
                verify_ref_state_non_membership_under(version, &populated, &main, &proof),
                Ok(false)
            );
        }
        for version in V1_LAYOUTS {
            assert_eq!(
                verify_ref_state_non_membership_under(version, &root, &main, &proof),
                Ok(false)
            );
            assert_eq!(
                verify_ref_state_non_membership_under(
                    version,
                    &ref_state_merkle_root(&[]).unwrap(),
                    &main,
                    &proof
                ),
                Ok(false)
            );
        }
    }
}

#[test]
fn every_ordered_gap_verifies_and_existing_refs_have_no_absence_proof() {
    let head = name("refs/heads/b");
    for sha256 in [false, true] {
        let entries = [
            (name("refs/heads/b"), oid(1, sha256)),
            (name("refs/heads/d"), oid(2, sha256)),
            (name("refs/heads/f"), oid(3, sha256)),
            (name("refs/heads/h"), oid(4, sha256)),
        ];
        let root = ref_state_merkle_root_v2(&entries, Some(&head)).unwrap();
        for query in [
            "refs/heads/a",
            "refs/heads/c",
            "refs/heads/e",
            "refs/heads/g",
            "refs/heads/i",
        ] {
            let query = name(query);
            let proof = ref_state_non_membership_proof_v2(&entries, Some(&head), &query).unwrap();
            if let RefStateNonMembershipProof::BeforeFirst { first } = &proof {
                assert_eq!(first.proof().index(), 1);
            }
            for version in V2_LAYOUTS {
                assert_eq!(
                    verify_ref_state_non_membership_under(version, &root, &query, &proof),
                    Ok(true)
                );
                for (existing, _) in &entries {
                    assert_eq!(
                        verify_ref_state_non_membership_under(version, &root, existing, &proof),
                        Ok(false)
                    );
                }
            }
        }
        for (existing, _) in &entries {
            assert_eq!(
                ref_state_non_membership_proof_v2(&entries, Some(&head), existing),
                Err(MerkleRefusal::RefIsPresent)
            );
        }
        assert_eq!(
            ref_state_membership_proof_v2(&entries, Some(&head), &name("refs/heads/missing")),
            Err(MerkleRefusal::RefNotPresent)
        );
    }
}

#[test]
fn nonadjacent_or_nonboundary_neighbours_cannot_hide_an_existing_ref() {
    let a = name("refs/heads/a");
    let b = name("refs/heads/b");
    let c = name("refs/heads/c");
    let entries = [
        (a.clone(), oid(1, false)),
        (b.clone(), oid(2, false)),
        (c.clone(), oid(3, false)),
    ];
    let root = ref_state_merkle_root_v2(&entries, Some(&a)).unwrap();
    let neighbour = |ref_name: &RefName| {
        let (native_oid, proof) =
            ref_state_membership_proof_v2(&entries, Some(&a), ref_name).unwrap();
        Box::new(RefStateNeighbour::new(ref_name.clone(), native_oid, proof))
    };
    let false_gap = RefStateNonMembershipProof::Between {
        predecessor: neighbour(&a),
        successor: neighbour(&c),
    };
    let false_before = RefStateNonMembershipProof::BeforeFirst {
        first: neighbour(&c),
    };
    let false_after = RefStateNonMembershipProof::AfterLast {
        last: neighbour(&a),
    };
    for version in V2_LAYOUTS {
        for proof in [&false_gap, &false_before, &false_after] {
            assert_eq!(
                verify_ref_state_non_membership_under(version, &root, &b, proof),
                Ok(false)
            );
        }
    }
}

#[test]
fn saturated_untrusted_neighbour_indices_are_refused_without_overflow() {
    let main = name("refs/heads/main");
    let entries = [(main.clone(), oid(1, false))];
    let root = ref_state_merkle_root_v2(&entries, Some(&main)).unwrap();
    let forged = Box::new(RefStateNeighbour::new(
        main.clone(),
        entries[0].1,
        MerkleProof::new(usize::MAX, usize::MAX, Vec::new()),
    ));
    let after = RefStateNonMembershipProof::AfterLast {
        last: forged.clone(),
    };
    let between = RefStateNonMembershipProof::Between {
        predecessor: forged.clone(),
        successor: forged,
    };
    let query = name("refs/heads/z");
    for version in V2_LAYOUTS {
        for proof in [&after, &between] {
            assert_eq!(
                verify_ref_state_non_membership_under(version, &root, &query, proof),
                Ok(false)
            );
        }
    }
}

#[test]
fn exact_non_utf8_branch_names_are_committed_without_normalization() {
    let raw = RefName::try_new(b"refs/heads/\xff").expect("Git refs need not be UTF-8");
    let replacement = name("refs/heads/\u{fffd}");
    let entries = [(raw.clone(), oid(1, false))];
    let root = ref_state_merkle_root_v2(&entries, Some(&raw)).unwrap();
    assert_ne!(
        root,
        ref_state_merkle_root_v2(&entries, Some(&replacement)).unwrap()
    );
    let proof = ref_state_head_membership_proof_v2(&entries, Some(&raw)).unwrap();
    assert_eq!(
        verify_ref_state_head_membership_under(V2_LAYOUTS[0], &root, Some(&raw), &proof),
        Ok(true)
    );
    assert_eq!(
        verify_ref_state_head_membership_under(V2_LAYOUTS[0], &root, Some(&replacement), &proof),
        Ok(false)
    );
}

#[test]
fn map_order_is_canonical_and_duplicates_and_nonbranch_head_are_refused() {
    let main = name("refs/heads/main");
    let other = name("refs/heads/other");
    let entries = [(main.clone(), oid(1, false)), (other, oid(2, true))];
    let mut reversed = entries.clone();
    reversed.reverse();
    assert_eq!(
        ref_state_merkle_root_v2(&entries, Some(&main)),
        ref_state_merkle_root_v2(&reversed, Some(&main))
    );
    assert_eq!(
        ref_state_membership_proof_v2(&entries, Some(&main), &main),
        ref_state_membership_proof_v2(&reversed, Some(&main), &main)
    );
    let duplicates = [(main.clone(), oid(1, false)), (main.clone(), oid(2, true))];
    assert_eq!(
        ref_state_merkle_root_v2(&duplicates, Some(&main)),
        Err(MerkleRefusal::DuplicateRefName)
    );
    assert_eq!(
        ref_state_membership_proof_v2(&duplicates, Some(&main), &main),
        Err(MerkleRefusal::DuplicateRefName)
    );
    assert_eq!(
        ref_state_non_membership_proof_v2(&duplicates, Some(&main), &main),
        Err(MerkleRefusal::DuplicateRefName)
    );
    assert_eq!(
        ref_state_head_membership_proof_v2(&duplicates, Some(&main)),
        Err(MerkleRefusal::DuplicateRefName)
    );
    for invalid in [name("refs/tags/main"), name("refs/other/main")] {
        assert_eq!(
            ref_state_head_leaf_v2(Some(&invalid)),
            Err(MerkleRefusal::InvalidHeadTarget)
        );
        assert_eq!(
            ref_state_merkle_root_v2(&entries, Some(&invalid)),
            Err(MerkleRefusal::InvalidHeadTarget)
        );
        assert_eq!(
            ref_state_non_membership_proof_v2(&[], Some(&invalid), &main),
            Err(MerkleRefusal::InvalidHeadTarget)
        );
        let invalid_proof = RefStateNonMembershipProof::HeadOnly {
            head_target: Some(invalid),
        };
        let empty_root = ref_state_merkle_root_v2(&[], Some(&main)).unwrap();
        assert_eq!(
            verify_ref_state_non_membership_under(
                V2_LAYOUTS[0],
                &empty_root,
                &main,
                &invalid_proof
            ),
            Ok(false)
        );
    }
}
