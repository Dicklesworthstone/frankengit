//! The independently configured admitted-blob policy applies to every candidate
//! consumer without widening body reads or staging unpublished source objects.
use super::support::{
    Entry, History, Scratch, assert_deep_file_change, commit, fixture_with_reused_blob, pack,
};
use super::{BundleInspectionRefusal, GitHashAlgorithm, OneNode, RefName};
use fgit_crypto::{GitHashAlgorithm as Hash, NativeObjectIdentity, git_object_id, sha256_digest};
use fgit_forge::event::NativeMerge;
use fgit_forge::preparation::{MergeCommitStyle, MergeSourceError};
use fgit_forge::review::ReviewOptions;
use fgit_git_object::ObjectType;
use fgit_treefs::{SparseLimits, TreeCapability, TreePath, WorkspaceId};
use fgit_types::{GitOid, RepositoryAuthorityHeadId};
use fgit_wire::visibility::RefVisibility;

const METADATA_BYTES: u64 = 64 * 1024;

struct Candidate {
    id: GitOid,
    parents: Vec<GitOid>,
    merge: Option<(NativeMerge, MergeCommitStyle)>,
    bundle: Vec<u8>,
}

fn reference(name: &[u8]) -> RefName {
    RefName::try_new(name).unwrap()
}

fn candidate_bundle(
    history: &History,
    name: &str,
    prerequisites: &[GitOid],
    candidate: GitOid,
    body: Vec<u8>,
) -> Vec<u8> {
    let format = history.parent.algorithm();
    let mut bytes = format!("# v3 git bundle\n@object-format={}\n", format.as_str()).into_bytes();
    for prerequisite in prerequisites {
        bytes.extend_from_slice(format!("-{prerequisite} parent\n").as_bytes());
    }
    bytes.extend_from_slice(format!("{candidate} {name}\n\n").as_bytes());
    let mut entries = history.thin_entries(history.leaf);
    *entries.last_mut().unwrap() = Entry::Direct(1, body);
    bytes.extend(pack(format, &entries));
    bytes
}

fn candidates(history: &History) -> [Candidate; 3] {
    let make = |style: Option<MergeCommitStyle>| {
        let mut parents = vec![history.parent];
        if style == Some(MergeCommitStyle::TwoParent) {
            parents.push(history.source);
        }
        let body = commit(history.new_root, &parents, "actual thin candidate");
        let id = git_object_id(history.parent.algorithm(), ObjectType::Commit, &body);
        let mut prerequisites = vec![history.parent];
        let merge = style.map(|style| {
            prerequisites.push(history.source);
            (
                NativeMerge {
                    source_ref: reference(b"refs/heads/topic"),
                    source_tip: history.source,
                    base_tip: history.source,
                    target_ref: reference(b"refs/heads/main"),
                    target_tip_before: history.parent,
                    merge_commit: id,
                },
                style,
            )
        });
        Candidate {
            id,
            parents,
            merge,
            bundle: candidate_bundle(history, "refs/heads/main", &prerequisites, id, body),
        }
    };
    [
        make(None),
        make(Some(MergeCommitStyle::TwoParent)),
        make(Some(MergeCommitStyle::Squash)),
    ]
}

fn sparse_inputs<A: Hash>(
    node: &OneNode,
    history: &History,
    candidate: &Candidate,
    head: RepositoryAuthorityHeadId,
) -> Result<(), BundleInspectionRefusal> {
    let mut capability = TreeCapability::new(
        WorkspaceId::from_bytes([0x94; 16]),
        node.repository_id(),
        vec![TreePath::parse_default(b"z/deep/file").unwrap()],
        Vec::new(),
    );
    let limits = SparseLimits {
        max_entries: 3,
        max_entry_bytes: 4096,
        max_payload_bytes: 4096,
    };
    let request = node.request_context();
    let (selected, manifest, digest) = if let Some((merge, style)) = &candidate.merge {
        node.runtime()
            .block_on(node.sparse_merge_candidate_manifest_with_style_in::<A>(
                &request,
                merge,
                &candidate.bundle,
                &RefVisibility::new(),
                Some(head),
                &mut capability,
                0,
                limits,
                *style,
            ))?
    } else {
        node.runtime()
            .block_on(node.sparse_candidate_manifest_in::<A>(
                &request,
                &reference(b"refs/heads/main"),
                history.parent,
                candidate.id,
                &candidate.bundle,
                &RefVisibility::new(),
                Some(head),
                &mut capability,
                0,
                limits,
            ))?
    };
    assert_eq!(selected, head);
    assert_eq!(digest, sha256_digest(&candidate.bundle));
    assert_eq!(
        manifest.base_commit_oid().digest_bytes(),
        history.parent.as_bytes()
    );
    assert_eq!(
        manifest.candidate_commit_oid().digest_bytes(),
        candidate.id.as_bytes()
    );
    assert_eq!(
        manifest.candidate_tree_oid().digest_bytes(),
        history.new_root.as_bytes()
    );
    assert_eq!(manifest.parents().len(), candidate.parents.len());
    for (actual, expected) in manifest.parents().iter().zip(&candidate.parents) {
        assert_eq!(actual.digest_bytes(), expected.as_bytes());
    }
    assert_eq!(
        manifest
            .entries()
            .iter()
            .map(|entry| entry.path().as_bytes())
            .collect::<Vec<_>>(),
        [b"z".as_slice(), b"z/deep", b"z/deep/file"]
    );
    assert!(manifest.entries()[0].kind().body().is_none());
    assert!(manifest.entries()[1].kind().body().is_none());
    assert_eq!(manifest.entries()[2].kind().body().unwrap(), b"changed\n");
    assert_eq!(manifest.payload_bytes(), b"changed\n".len());
    Ok(())
}

fn reopen(node: OneNode, root: &Scratch, format: GitHashAlgorithm, maximum: usize) -> OneNode {
    node.shutdown().unwrap();
    let mut node = OneNode::open_existing(
        root.config(format)
            .with_max_object_bytes(METADATA_BYTES)
            .with_selected_pack_blob_limit(maximum),
    )
    .unwrap();
    let head = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap();
    node.bring_into_service(head.receipt().generation())
        .unwrap();
    node
}

fn exercise_reused_blob_policy(format: GitHashAlgorithm, blob_bytes: usize) {
    let root = Scratch::new();
    let (mut node, mut history) = fixture_with_reused_blob(&root, format, blob_bytes);
    let inherited = history.reused_blob.unwrap();
    // The candidate transport needs only the small original delta bases. Drop
    // the fixture's large in-memory copy before exercising metadata-only reads.
    history.originals.remove(&inherited).unwrap();
    let candidates = candidates(&history);
    let rebase_bundle = candidate_bundle(
        &history,
        "refs/heads/topic",
        &[history.parent],
        history.candidate,
        history.uploaded[&history.candidate].1.clone(),
    );
    let before = node
        .runtime()
        .block_on(node.materialize_admission())
        .unwrap();
    let assert_read_only = |node: &OneNode| {
        let after = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(after.basis(), before.basis());
        assert_eq!(after.snapshot().refs, before.snapshot().refs);
        assert_eq!(
            std::fs::read_dir(root.0.join("staging")).unwrap().count(),
            0,
            "inspection and sparse discovery never acquire staging custody"
        );
        for id in history
            .uploaded
            .keys()
            .copied()
            .chain(candidates.iter().map(|c| c.id))
        {
            assert!(
                node.read_git_object(id).is_err(),
                "candidate object was stored: {id}"
            );
        }
    };
    for maximum in [blob_bytes, blob_bytes - 1] {
        node = reopen(node, &root, format, maximum);
        let permitted = maximum == blob_bytes;
        assert!(
            node.read_git_object(inherited).is_err(),
            "the unchanged blob must exceed the independent body-read ceiling"
        );
        // Ordinary inspection already honors this policy. Candidate execution
        // and rebase must agree at both the permitted and refused boundary.
        let review = node.runtime().block_on(node.inspect_workspace_bundle_in(
            &node.request_context(),
            &reference(b"refs/heads/main"),
            history.parent,
            candidates[0].id,
            &candidates[0].bundle,
            &RefVisibility::new(),
            Some(before.basis().id()),
            &ReviewOptions::default(),
        ));
        if permitted {
            let review = review.unwrap();
            assert_deep_file_change(&review.review.comparison, &history);
        } else {
            assert!(matches!(
                review,
                Err(BundleInspectionRefusal::Source(
                    MergeSourceError::BudgetExceeded
                ))
            ));
        }
        for candidate in &candidates {
            let result = match format {
                GitHashAlgorithm::Sha1 => sparse_inputs::<fgit_crypto::Sha1>(
                    &node,
                    &history,
                    candidate,
                    before.basis().id(),
                ),
                GitHashAlgorithm::Sha256 => sparse_inputs::<fgit_crypto::Sha256>(
                    &node,
                    &history,
                    candidate,
                    before.basis().id(),
                ),
            };
            if permitted {
                result.unwrap();
            } else {
                assert!(matches!(
                    result,
                    Err(BundleInspectionRefusal::Source(
                        MergeSourceError::BudgetExceeded
                    ))
                ));
            }
            assert_read_only(&node);
        }
        let rebase = node.runtime().block_on(node.inspect_rebase_bundle_in(
            &node.request_context(),
            &reference(b"refs/heads/topic"),
            &reference(b"refs/heads/main"),
            history.source,
            history.parent,
            history.candidate,
            &rebase_bundle,
            &RefVisibility::new(),
            Some(before.basis().id()),
            &ReviewOptions::default(),
        ));
        if permitted {
            let rebase = rebase.unwrap();
            assert_eq!(rebase.source_head, before.basis().id());
            assert_eq!(rebase.candidate, history.candidate);
            assert_eq!(rebase.bundle.sha256, sha256_digest(&rebase_bundle));
            assert_eq!(rebase.commits.len(), 1);
            assert_eq!(rebase.commits[0].parent, history.parent);
            assert_eq!(rebase.commits[0].id, history.candidate);
            assert_eq!(rebase.comparisons.len(), 2);
            for comparison in rebase.comparisons {
                assert_deep_file_change(&comparison, &history);
            }
        } else {
            assert!(matches!(
                rebase,
                Err(BundleInspectionRefusal::Source(
                    MergeSourceError::BudgetExceeded
                ))
            ));
        }
        assert_read_only(&node);
    }
    node.shutdown().unwrap();
}

#[test]
fn candidate_inputs_and_rebase_honor_reused_blob_limits_below_the_default() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        exercise_reused_blob_policy(format, 256 * 1024 + 17);
    }
}

#[test]
fn candidate_inputs_and_rebase_honor_reused_blob_limits_above_thirty_two_mib() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        exercise_reused_blob_policy(format, 32 * 1024 * 1024 + 17);
    }
}
