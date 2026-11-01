#![forbid(unsafe_code)]
//! Genuine durable-node, native-pack integration target for incremental thin
//! candidate guidance. Run independently of the node's large unit-test binary.
#[path = "candidate_thin_frontier/support.rs"]
mod support;
use fgit_forge::review::ReviewOptions;
use fgit_node::{BundleInspectionRefusal, NodeConfig, OneNode};
use fgit_pack::PackError;
use fgit_types::{GitHashAlgorithm, RefName};
use fgit_wire::visibility::RefVisibility;
use support::{Entry, Scratch, bundle, corrupt_object, fixture};

macro_rules! inspect {
    ($node:expr, $history:expr, $bytes:expr, $visibility:expr, $head:expr) => {
        $node.runtime().block_on($node.inspect_workspace_bundle_in(
            &$node.request_context(),
            &RefName::try_new(b"refs/heads/main").unwrap(),
            $history.parent,
            $history.candidate,
            $bytes,
            $visibility,
            $head,
            &ReviewOptions::default(),
        ))
    };
}

#[test]
fn deep_thin_candidate_matches_thick_review_without_opening_an_unchanged_sibling() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, history) = fixture(&root, format);
        let before = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap()
            .basis()
            .id();
        let visibility = RefVisibility::new();
        let thick = bundle(&history, &history.thick_entries());
        let baseline = inspect!(&node, &history, &thick, &visibility, Some(before)).unwrap();
        assert_eq!(baseline.review.comparison.entries.len(), 1);
        assert_eq!(baseline.review.comparison.entries[0].path, b"z/deep/file");
        assert_eq!(baseline.parents, [history.parent]);
        assert_eq!(
            baseline.candidate_commit_body,
            history.uploaded[&history.candidate].1
        );

        // All objects were durably admitted before this fault. Neither the
        // candidate's changed path nor its delta bases need this sibling.
        corrupt_object(&root.0, history.sibling);
        assert!(node.read_git_object(history.sibling).is_err());
        let mut entries = history.thin_entries(history.leaf);
        let thin = bundle(&history, &entries);
        assert!(thin.len() < history.external_bytes());
        for reversed in [false, true] {
            if reversed {
                entries.reverse();
            }
            let bytes = bundle(&history, &entries);
            let actual = inspect!(&node, &history, &bytes, &visibility, Some(before)).unwrap();
            assert_eq!(actual.review.comparison, baseline.review.comparison);
            assert_eq!(actual.closure_objects, baseline.closure_objects);
            assert_eq!(actual.candidate_commit_body, baseline.candidate_commit_body);
            assert_eq!(actual.pack_objects, 5);
            assert_eq!(actual.transport_only_objects, 0);
        }
        assert_eq!(
            node.runtime()
                .block_on(node.materialize_admission())
                .unwrap()
                .basis()
                .id(),
            before
        );
        for id in history.uploaded.keys() {
            assert!(node.read_git_object(*id).is_err());
        }
        node.shutdown().unwrap();

        let mut node = OneNode::open_existing(root.config(format)).unwrap();
        let selected = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        node.bring_into_service(selected.receipt().generation())
            .unwrap();
        let reopened = inspect!(&node, &history, &thin, &visibility, Some(before)).unwrap();
        assert_eq!(reopened.review.comparison, baseline.review.comparison);
        assert_eq!(reopened.closure_objects, baseline.closure_objects);
        assert_eq!(
            node.runtime()
                .block_on(node.materialize_admission())
                .unwrap()
                .basis()
                .id(),
            before
        );
        for id in history.uploaded.keys() {
            assert!(node.read_git_object(*id).is_err());
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn selected_unrelated_and_hidden_bases_stay_forbidden_but_supplied_bytes_are_transport() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, history) = fixture(&root, format);
        let selected = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        let before = selected.basis().id();
        assert!(
            selected
                .selected_closure()
                .closure()
                .objects()
                .contains(&history.secret)
        );
        assert!(
            node.read_git_object(history.secret).is_ok(),
            "the forbidden original genuinely exists"
        );
        let mut visibility = RefVisibility::new();
        let valid = inspect!(
            &node,
            &history,
            &bundle(&history, &history.thin_entries(history.leaf)),
            &visibility,
            Some(before)
        )
        .unwrap();
        for hidden in [false, true] {
            if hidden {
                visibility
                    .push_rule(b"refs/heads/private", &Default::default())
                    .unwrap();
            }
            let forbidden = bundle(&history, &history.thin_entries(history.secret));
            assert!(matches!(
                inspect!(&node, &history, &forbidden, &visibility, Some(before)),
                Err(BundleInspectionRefusal::Pack(error)) if *error == PackError::MissingDeltaBase
            ));
            // Supplying a base proves transport bytes, never disclosure. Test
            // both forward and backward REF order against the same candidate.
            for forward in [false, true] {
                let base = Entry::Direct(3, history.originals[&history.secret].1.clone());
                let mut entries = history.thin_entries(history.secret);
                if forward {
                    entries.push(base);
                } else {
                    entries.insert(0, base);
                }
                let result = inspect!(
                    &node,
                    &history,
                    &bundle(&history, &entries),
                    &visibility,
                    Some(before)
                )
                .unwrap();
                assert_eq!(result.review.comparison, valid.review.comparison);
                assert_eq!(result.closure_objects, valid.closure_objects);
                assert_eq!(result.pack_objects, 6);
                assert_eq!(result.transport_only_objects, 1);
            }
        }
        assert_eq!(
            node.runtime()
                .block_on(node.materialize_admission())
                .unwrap()
                .basis()
                .id(),
            before
        );
        for id in history.uploaded.keys() {
            assert!(node.read_git_object(*id).is_err());
        }
        node.shutdown().unwrap();
    }
}
