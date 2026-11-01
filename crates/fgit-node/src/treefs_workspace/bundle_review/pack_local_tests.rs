//! Pack-local REF bases must not trigger original-object disclosure work.

use super::*;
use crate::NodeConfig;

#[path = "../../../tests/candidate_thin_frontier/support.rs"]
mod thin_fixture;

fn decode(
    node: &OneNode,
    root: GitOid,
    input: &[u8],
    object_limits: MergeObjectLimits,
    pack_limits: PackLimits,
) -> (Result<pack::Unpacked, BundleInspectionRefusal>, usize) {
    let request = node.request_context();
    let selected = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    let exhaustion = Cell::new(None);
    let budget = ReadBudget {
        bytes: Cell::new(0),
        exhausted: Cell::new(false),
    };
    let original = OriginalSource::with_parents(
        VerifiedFabricPackSource {
            fabric: &node.fabric,
            object_format: root.algorithm(),
            maximum_object_bytes: object_limits.max_object_bytes,
            database_context: request.authority(),
            database_exhaustion: &exhaustion,
            session_is_live: None,
        },
        selected.selected_closure().closure().objects(),
        &budget,
        &[root],
        object_limits,
    )
    .unwrap();
    let result = pack::unpack(input, root.algorithm(), &pack_limits, &original);
    (result, budget.bytes.get())
}

#[test]
fn forward_and_backward_local_ref_bases_never_read_selected_hidden_originals() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, f) = fixture(format);
        let base = b"unrelated secret\n";
        let result_body = [base.as_slice(), b"!"].concat();
        let result_id = git_object_id(format, ObjectType::Blob, &result_body);
        let object_limits = MergeObjectLimits {
            max_objects: 1,
            max_total_bytes: 1,
            ..MergeObjectLimits::default()
        };
        for forward in [false, true] {
            let mut entries = vec![
                Entry::Direct(3, base.to_vec()),
                Entry::Ref(f.secret, copy_then_exclaim(base)),
            ];
            if forward {
                entries.reverse();
            }
            let (result, original_bytes) = decode(
                &node,
                f.target,
                &pack(format, &entries),
                object_limits,
                PackLimits::default(),
            );
            let result = result.unwrap();
            assert_eq!(
                original_bytes, 0,
                "all required bytes were supplied in the pack"
            );
            assert_eq!(result.objects.len(), 2);
            assert_eq!(result.objects[&result_id].body, result_body);
            assert_eq!(result.objects[&f.secret].body, base);
            assert_eq!(
                result.check_coverage(&BTreeSet::from([result_id])).unwrap(),
                1
            );
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn mixed_local_and_external_refs_only_prove_the_missing_visible_base() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, f) = fixture(format);
        let local = b"unrelated secret\n";
        let external = b"original\n";
        let local_result = [local.as_slice(), b"!"].concat();
        let external_result = [external.as_slice(), b"!"].concat();
        let local_id = git_object_id(format, ObjectType::Blob, &local_result);
        let external_id = git_object_id(format, ObjectType::Blob, &external_result);
        let entries = [
            Entry::Ref(f.secret, copy_then_exclaim(local)),
            Entry::Ref(f.original, copy_then_exclaim(external)),
            Entry::Direct(3, local.to_vec()),
        ];
        // The current commit and tree prove the visible external blob. Trying
        // to disprove reachability of the hidden local base would also traverse
        // ancestor commits and exceed this two-object allowance.
        let limits = MergeObjectLimits {
            max_objects: 2,
            ..MergeObjectLimits::default()
        };
        let (result, original_bytes) = decode(
            &node,
            f.target,
            &pack(format, &entries),
            limits,
            PackLimits::default(),
        );
        let result = result.unwrap();
        assert!(original_bytes > 0);
        assert_eq!(result.objects.len(), 3);
        assert_eq!(result.objects[&local_id].body, local_result);
        assert_eq!(result.objects[&external_id].body, external_result);
        assert!(!result.objects.contains_key(&f.original));
        assert_eq!(
            result
                .check_coverage(&BTreeSet::from([local_id, external_id]))
                .unwrap(),
            1
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn thin_ref_lookup_still_requires_visible_parent_reachability() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, f) = fixture(format);
        let visible_body = b"original\n";
        let visible_result = [visible_body.as_slice(), b"!"].concat();
        let visible_id = git_object_id(format, ObjectType::Blob, &visible_result);
        let (permitted, bytes) = decode(
            &node,
            f.target,
            &pack(
                format,
                &[Entry::Ref(f.original, copy_then_exclaim(visible_body))],
            ),
            MergeObjectLimits::default(),
            PackLimits::default(),
        );
        let permitted = permitted.unwrap();
        assert!(bytes > 0);
        assert_eq!(permitted.objects.len(), 1);
        assert_eq!(permitted.objects[&visible_id].body, visible_result);
        let (refused, _) = decode(
            &node,
            f.target,
            &pack(
                format,
                &[Entry::Ref(
                    f.secret,
                    copy_then_exclaim(b"unrelated secret\n"),
                )],
            ),
            MergeObjectLimits::default(),
            PackLimits::default(),
        );
        assert!(
            matches!(refused, Err(BundleInspectionRefusal::Pack(error)) if *error == PackError::MissingDeltaBase)
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn local_ref_chain_keeps_the_existing_depth_and_pass_ceiling() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, f) = fixture(format);
        let base = b"unrelated secret\n";
        let middle = [base.as_slice(), b"!"].concat();
        let middle_id = git_object_id(format, ObjectType::Blob, &middle);
        let final_body = [middle.as_slice(), b"!"].concat();
        let final_id = git_object_id(format, ObjectType::Blob, &final_body);
        let entries = [
            Entry::Ref(middle_id, copy_then_exclaim(&middle)),
            Entry::Ref(f.secret, copy_then_exclaim(base)),
            Entry::Direct(3, base.to_vec()),
        ];
        let bytes = pack(format, &entries);
        let object_limits = MergeObjectLimits {
            max_total_bytes: 1,
            ..MergeObjectLimits::default()
        };
        let (bounded, reads) = decode(
            &node,
            f.target,
            &bytes,
            object_limits,
            PackLimits {
                max_delta_depth: 1,
                ..PackLimits::default()
            },
        );
        assert!(bounded.is_err());
        assert_eq!(reads, 0);
        let (permitted, reads) = decode(
            &node,
            f.target,
            &bytes,
            object_limits,
            PackLimits {
                max_delta_depth: 2,
                ..PackLimits::default()
            },
        );
        let permitted = permitted.unwrap();
        assert_eq!(reads, 0);
        assert_eq!(permitted.objects[&final_id].body, final_body);
        assert_eq!(
            permitted
                .check_coverage(&BTreeSet::from([final_id]))
                .unwrap(),
            2
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn independent_external_tree_and_blob_stages_fit_depth_one_and_exact_graph_budget() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = thin_fixture::Scratch::new();
        let (node, history) = thin_fixture::fixture(&root, format);
        thin_fixture::corrupt_object(&root.0, history.sibling);
        let limits = MergeObjectLimits {
            max_objects: 8,
            ..MergeObjectLimits::default()
        };
        let mut entries = history.thin_entries(history.leaf);
        for reversed in [false, true] {
            if reversed {
                entries.reverse();
            }
            let bytes = thin_fixture::pack(format, &entries);
            let (result, read_bytes) = decode(
                &node,
                history.parent,
                &bytes,
                limits,
                PackLimits {
                    max_delta_depth: 1,
                    ..PackLimits::default()
                },
            );
            let result = result.unwrap();
            assert_eq!(result.objects.len(), 5);
            assert_eq!(
                result.objects[&history.changed].body,
                history.uploaded[&history.changed].1
            );
            assert_eq!(
                result.objects[&history.candidate].body,
                history.uploaded[&history.candidate].1
            );
            assert!(read_bytes >= history.external_bytes());
            assert_eq!(
                result
                    .check_coverage(&history.uploaded.keys().copied().collect())
                    .unwrap(),
                0
            );
            let (refused, _) = decode(
                &node,
                history.parent,
                &bytes,
                MergeObjectLimits {
                    max_objects: 7,
                    ..limits
                },
                PackLimits::default(),
            );
            assert!(matches!(
                refused,
                Err(BundleInspectionRefusal::Source(
                    MergeSourceError::BudgetExceeded
                ))
            ));
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn staged_external_bases_share_one_cache_and_resolution_work_allowance() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = thin_fixture::Scratch::new();
        let (node, history) = thin_fixture::fixture(&root, format);
        let bytes = thin_fixture::pack(format, &history.thin_entries(history.leaf));
        let external_bytes = history.external_bytes();
        assert!(external_bytes > history.uploaded.values().map(|(_, body)| body.len()).sum());
        let (permitted, _) = decode(
            &node,
            history.parent,
            &bytes,
            MergeObjectLimits::default(),
            PackLimits {
                max_cached_bytes: external_bytes,
                max_delta_depth: 1,
                ..PackLimits::default()
            },
        );
        assert!(permitted.is_ok());
        let (refused, _) = decode(
            &node,
            history.parent,
            &bytes,
            MergeObjectLimits::default(),
            PackLimits {
                max_cached_bytes: external_bytes - 1,
                max_delta_depth: 1,
                ..PackLimits::default()
            },
        );
        assert!(
            matches!(refused, Err(BundleInspectionRefusal::BudgetExceeded)),
            "separate external phases must not replenish cached-base bytes"
        );
        // The instruction outputs alone fit this allowance; graph lookups,
        // earlier unresolved attempts and the later stages must share it too.
        let instruction_bytes = [history.new_dir, history.new_deep, history.changed]
            .iter()
            .map(|id| history.uploaded[id].1.len())
            .sum();
        let (refused, _) = decode(
            &node,
            history.parent,
            &bytes,
            MergeObjectLimits::default(),
            PackLimits {
                max_delta_work: instruction_bytes,
                ..PackLimits::default()
            },
        );
        assert!(
            matches!(refused, Err(BundleInspectionRefusal::Pack(error)) if matches!(*error, PackError::DeltaWorkLimit { .. }))
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn backward_cached_ofs_and_ref_chains_cannot_hide_their_actual_delta_depth() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, f) = fixture(format);
        let base = b"unrelated secret\n";
        let middle = [base.as_slice(), b"!"].concat();
        let middle_id = git_object_id(format, ObjectType::Blob, &middle);
        let final_body = [middle.as_slice(), b"!"].concat();
        let final_id = git_object_id(format, ObjectType::Blob, &final_body);
        for ofs in [false, true] {
            let entries = if ofs {
                vec![
                    Entry::Direct(3, base.to_vec()),
                    Entry::Ofs(0, copy_then_exclaim(base)),
                    Entry::Ofs(1, copy_then_exclaim(&middle)),
                ]
            } else {
                vec![
                    Entry::Direct(3, base.to_vec()),
                    Entry::Ref(f.secret, copy_then_exclaim(base)),
                    Entry::Ref(middle_id, copy_then_exclaim(&middle)),
                ]
            };
            let bytes = pack(format, &entries);
            let original_limits = MergeObjectLimits {
                max_total_bytes: 1,
                ..MergeObjectLimits::default()
            };
            let (refused, read_bytes) = decode(
                &node,
                f.target,
                &bytes,
                original_limits,
                PackLimits {
                    max_delta_depth: 1,
                    ..PackLimits::default()
                },
            );
            if ofs {
                assert!(
                    matches!(refused, Err(BundleInspectionRefusal::Pack(error)) if matches!(*error, PackError::DeltaDepthLimit { depth: 2, limit: 1 }))
                );
            } else {
                assert!(
                    matches!(refused, Err(BundleInspectionRefusal::Pack(error)) if matches!(*error, PackError::MissingDeltaBase | PackError::DeltaDepthLimit { .. }))
                );
            }
            assert_eq!(read_bytes, 0);
            let (permitted, read_bytes) = decode(
                &node,
                f.target,
                &bytes,
                original_limits,
                PackLimits {
                    max_delta_depth: 2,
                    ..PackLimits::default()
                },
            );
            let permitted = permitted.unwrap();
            assert_eq!(permitted.objects[&final_id].body, final_body);
            assert_eq!(
                permitted
                    .check_coverage(&BTreeSet::from([final_id]))
                    .unwrap(),
                2
            );
            assert_eq!(read_bytes, 0);
        }
        node.shutdown().unwrap();
    }
}
