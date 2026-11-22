#![forbid(unsafe_code)]
//! Complete native gitlink patches produce reviewable bundles and ordinary CAS.

#[allow(dead_code)]
#[path = "workspace_metadata_edits/fixture.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "workspace_gitlink_edits/support.rs"]
mod support;

use fgit_crypto::{GitHashAlgorithm as HashAlgorithm, GitObjectKind, Sha1, Sha256, git_object_id};
use fgit_forge::{patch::PatchLimits, preparation::MergeMetadata};
use fgit_node::{NodeConfig, NodeWorkspaceRefusal, OneNode, WorkspacePatchCandidate};
use fgit_treefs::{CapabilityRefusal, SparseRefusal, TreeCapability};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration};
use fgit_wire::visibility::RefVisibility;
use fixture::*;
use support::*;

fn metadata() -> MergeMetadata {
    MergeMetadata {
        author: "Author <author@example.invalid>".into(),
        committer: "Committer <committer@example.invalid>".into(),
        timestamp: 2,
        message: b"exact opaque gitlink edits\n".to_vec(),
    }
}

fn patch(
    format: GitHashAlgorithm,
    target: &str,
    old: Option<GitOid>,
    new: Option<GitOid>,
) -> Vec<u8> {
    let zero = "0".repeat(format.digest_len() * 2);
    let old_hex = old.map_or_else(|| zero.clone(), |id| id.to_string());
    let new_hex = new.map_or_else(|| zero.clone(), |id| id.to_string());
    let mut bytes = format!("diff --git a/{target} b/{target}\n");
    match (old, new) {
        (None, Some(_)) => bytes.push_str(&format!(
            "new file mode 160000\nindex {old_hex}..{new_hex}\n--- /dev/null\n+++ b/{target}\n@@ -0,0 +1 @@\n+Subproject commit {new_hex}\n"
        )),
        (Some(_), None) => bytes.push_str(&format!(
            "deleted file mode 160000\nindex {old_hex}..{new_hex}\n--- a/{target}\n+++ /dev/null\n@@ -1 +0,0 @@\n-Subproject commit {old_hex}\n"
        )),
        (Some(_), Some(_)) => bytes.push_str(&format!(
            "index {old_hex}..{new_hex} 160000\n--- a/{target}\n+++ b/{target}\n@@ -1 +1 @@\n-Subproject commit {old_hex}\n+Subproject commit {new_hex}\n"
        )),
        (None, None) => panic!("fixture edit must have a present side"),
    }
    bytes.into_bytes()
}

fn prepare(
    fixture: &Fixture,
    patch: &[u8],
    limits: PatchLimits,
) -> Result<WorkspacePatchCandidate, NodeWorkspaceRefusal> {
    let node = fixture.node();
    node.runtime()
        .block_on(node.prepare_trusted_gitlink_patch_in(
            &node.request_context(),
            &reference(),
            fixture.commit,
            [0xe6; 16],
            patch,
            &metadata(),
            limits,
        ))
}

fn scoped_as<A: HashAlgorithm>(
    fixture: &Fixture,
    patch: &[u8],
    cap: &mut TreeCapability,
) -> Result<WorkspacePatchCandidate, NodeWorkspaceRefusal> {
    let node = fixture.node();
    node.runtime()
        .block_on(node.prepare_workspace_gitlink_patch_in::<A>(
            &node.request_context(),
            &reference(),
            fixture.commit,
            &RefVisibility::new(),
            cap,
            patch,
            0,
            &metadata(),
            PatchLimits::default(),
        ))
}

fn scoped(
    fixture: &Fixture,
    patch: &[u8],
    cap: &mut TreeCapability,
) -> Result<WorkspacePatchCandidate, NodeWorkspaceRefusal> {
    match fixture.format {
        GitHashAlgorithm::Sha1 => scoped_as::<Sha1>(fixture, patch, cap),
        GitHashAlgorithm::Sha256 => scoped_as::<Sha256>(fixture, patch, cap),
    }
}

fn publish_and_recover(fixture: &Fixture, candidate: &WorkspacePatchCandidate) {
    let node = fixture.node();
    assert!(node.read_git_object(candidate.candidate_commit).is_err());
    let admitted = node
        .runtime()
        .block_on(node.apply_workspace_bundle_durable_in(
            &node.request_context(),
            PRINCIPAL,
            b"opaque-gitlink-publication",
            &reference(),
            fixture.commit,
            candidate.candidate_commit,
            candidate.bundle_bytes(),
        ))
        .unwrap();
    assert!(matches!(
        admitted.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    let selected = node
        .runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .unwrap();
    assert_eq!(
        selected.snapshot().refs[&reference()],
        candidate.candidate_commit
    );

    // A fresh node handle must resolve the identical sealed request even
    // though its expected-old ref is no longer the current branch tip.
    let mut reopened = OneNode::open_existing(
        NodeConfig::new(
            node.storage_root().to_path_buf(),
            node.tenant_id(),
            node.repository_id(),
        )
        .with_object_format(fixture.format)
        .with_worker_threads(2),
    )
    .unwrap();
    reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
    let retry = reopened
        .runtime()
        .block_on(reopened.apply_workspace_bundle_durable_in(
            &reopened.request_context(),
            PRINCIPAL,
            b"opaque-gitlink-publication",
            &reference(),
            fixture.commit,
            candidate.candidate_commit,
            candidate.bundle_bytes(),
        ))
        .unwrap();
    assert_eq!(retry.commands, admitted.commands);
    reopened.shutdown().unwrap();
}

#[test]
fn gitlink_and_gitmodules_changes_share_one_native_candidate_and_publication() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let before = fixture.head();
        let next = pointer(format, b"foreign updated dependency");
        let added = pointer(format, b"foreign added dependency");
        let modules = b"[submodule \"dependency\"]\n\tpath = new/dependency\n\turl = ssh://private.invalid/other-tenant/repo\n";
        let file_patch = b"diff --git a/.gitmodules b/.gitmodules\nnew file mode 100644\n--- /dev/null\n+++ b/.gitmodules\n@@ -0,0 +1,3 @@\n+[submodule \"dependency\"]\n+\tpath = new/dependency\n+\turl = ssh://private.invalid/other-tenant/repo\n";
        let input = [
            patch(
                format,
                "module",
                Some(original_pointer(&fixture)),
                Some(next),
            ),
            patch(format, "new/dependency", None, Some(added)),
            file_patch.to_vec(),
        ]
        .concat();
        let candidate = prepare(&fixture, &input, PatchLimits::default()).unwrap();
        let modules_oid = git_object_id(format, GitObjectKind::Blob, modules);
        assert_eq!(
            candidate.root_tree,
            expected_tree(
                &fixture,
                &[
                    (".gitmodules", Some(("100644", modules_oid))),
                    ("module", Some(("160000", next))),
                    ("new/dependency", Some(("160000", added))),
                ]
            )
        );
        assert_eq!(candidate.paths.len(), 3);
        let edited = candidate
            .paths
            .iter()
            .find(|path| path.path == b"module")
            .unwrap();
        assert_eq!(
            (edited.old_blob, edited.new_blob, edited.new_mode),
            (Some(original_pointer(&fixture)), Some(next), Some(0o160000))
        );
        let created = candidate
            .paths
            .iter()
            .find(|path| path.path == b"new/dependency")
            .unwrap();
        assert_eq!(
            (created.old_blob, created.new_blob, created.new_mode),
            (None, Some(added), Some(0o160000))
        );
        assert_eq!(fixture.head(), before);
        assert_eq!(
            prepare(&fixture, &input, PatchLimits::default())
                .unwrap()
                .bundle_bytes(),
            candidate.bundle_bytes()
        );
        publish_and_recover(&fixture, &candidate);
        assert_eq!(
            fixture
                .node()
                .read_git_object(modules_oid)
                .unwrap()
                .payload(),
            modules
        );
        for foreign in [original_pointer(&fixture), next, added] {
            assert!(fixture.node().read_git_object(foreign).is_err());
        }
    }
}

#[test]
fn gitlink_deletion_publishes_without_materializing_the_old_commit() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let old = original_pointer(&fixture);
        let input = patch(format, "module", Some(old), None);
        let candidate = prepare(&fixture, &input, PatchLimits::default()).unwrap();
        assert_eq!(
            candidate.root_tree,
            expected_tree(&fixture, &[("module", None)])
        );
        assert_eq!(
            (
                candidate.paths[0].old_blob,
                candidate.paths[0].new_blob,
                candidate.paths[0].new_mode
            ),
            (Some(old), None, None)
        );
        assert_eq!(
            candidate.object_count, 2,
            "only the rebuilt root tree and commit"
        );
        publish_and_recover(&fixture, &candidate);
        assert!(fixture.node().read_git_object(old).is_err());
    }
}

#[test]
fn selected_pointer_kind_and_hash_domain_are_verified_before_any_candidate_exists() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let before = fixture.head();
        let old = original_pointer(&fixture);
        let next = pointer(format, b"foreign updated dependency");
        let other = if format == GitHashAlgorithm::Sha1 {
            GitHashAlgorithm::Sha256
        } else {
            GitHashAlgorithm::Sha1
        };
        let other_patch = patch(
            other,
            "module",
            Some(pointer(other, b"external repository")),
            Some(pointer(other, b"foreign update")),
        );
        let mut cap = complete_capability();
        assert!(scoped(&fixture, &other_patch, &mut cap).is_err());
        assert_eq!(
            cap.fetched_bytes(),
            0,
            "cross-domain records refuse before source reads"
        );
        for input in [
            patch(
                format,
                "module",
                Some(pointer(format, b"wrong old pointer")),
                Some(next),
            ),
            patch(format, "module", None, Some(next)),
            patch(format, "new/absent", Some(old), Some(next)),
            patch(format, "src/tool.sh", Some(fixture.file), Some(next)),
            patch(format, "src/tool.sh", None, Some(next)),
            patch(format, "link", None, Some(next)),
            patch(format, "src", None, Some(next)),
            patch(format, "module/child", None, Some(next)),
        ] {
            assert!(prepare(&fixture, &input, PatchLimits::default()).is_err());
        }
        let valid = patch(format, "module", Some(old), Some(next));
        let dirty = String::from_utf8(valid.clone()).unwrap().replace(
            &format!("+Subproject commit {next}\n"),
            &format!("+Subproject commit {next}-dirty\n"),
        );
        assert!(prepare(&fixture, dirty.as_bytes(), PatchLimits::default()).is_err());
        assert!(prepare(&fixture, &valid, PatchLimits::default()).is_ok());
        assert_eq!(fixture.head(), before);
    }
}

#[test]
fn old_profiles_remain_closed_and_regular_text_keeps_its_identical_candidate() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let node = fixture.node();
        let old = original_pointer(&fixture);
        let next = pointer(format, b"foreign update");
        let input = patch(format, "module", Some(old), Some(next));
        // Without the explicit index/mode declaration the synthetic text is
        // an ordinary text patch. It must never confer pointer-edit authority.
        let unmarked = String::from_utf8(input.clone())
            .unwrap()
            .replace(&format!("index {old}..{next} 160000\n"), "");
        for bytes in [input.as_slice(), unmarked.as_bytes()] {
            for result in [
                node.runtime().block_on(node.prepare_trusted_patch_in(
                    &node.request_context(),
                    &reference(),
                    fixture.commit,
                    [0xe6; 16],
                    bytes,
                    &metadata(),
                    PatchLimits::default(),
                )),
                node.runtime()
                    .block_on(node.prepare_trusted_binary_refactor_in(
                        &node.request_context(),
                        &reference(),
                        fixture.commit,
                        [0xe6; 16],
                        bytes,
                        &metadata(),
                        PatchLimits::default(),
                    )),
                node.runtime()
                    .block_on(node.prepare_trusted_symlink_patch_in(
                        &node.request_context(),
                        &reference(),
                        fixture.commit,
                        [0xe6; 16],
                        bytes,
                        &metadata(),
                        PatchLimits::default(),
                    )),
            ] {
                assert!(result.is_err());
            }
        }
        assert!(prepare(&fixture, unmarked.as_bytes(), PatchLimits::default()).is_err());
        assert!(prepare(&fixture, &input, PatchLimits::default()).is_ok());
        let ordinary = b"diff --git a/untouched.txt b/untouched.txt\n--- a/untouched.txt\n+++ b/untouched.txt\n@@ -1 +1 @@\n-root sibling\n+updated sibling\n";
        let old_profile = node
            .runtime()
            .block_on(node.prepare_trusted_patch_in(
                &node.request_context(),
                &reference(),
                fixture.commit,
                [0xe6; 16],
                ordinary,
                &metadata(),
                PatchLimits::default(),
            ))
            .unwrap();
        let new_profile = prepare(&fixture, ordinary, PatchLimits::default()).unwrap();
        assert_eq!(new_profile.bundle_bytes(), old_profile.bundle_bytes());
        assert_eq!(new_profile.paths, old_profile.paths);
    }
}

#[test]
fn gitlink_patches_keep_scope_cancellation_stale_base_and_shared_budget_checks() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let node = fixture.node();
        let before = fixture.head();
        let next = pointer(format, b"foreign update");
        let input = patch(
            format,
            "module",
            Some(original_pointer(&fixture)),
            Some(next),
        );
        let mut cap = capability(&["module"], &[]);
        assert!(matches!(
            scoped(&fixture, &input, &mut cap),
            Err(NodeWorkspaceRefusal::Manifest(SparseRefusal::Capability(
                CapabilityRefusal::WriteOutsideScope { .. }
            )))
        ));
        assert_eq!(cap.fetched_bytes(), 0);
        assert!(matches!(
            scoped(&fixture, &input, &mut capability(&["module"], &["module"])),
            Err(NodeWorkspaceRefusal::IncompleteWorkspaceExportScope)
        ));
        assert!(scoped(&fixture, &input, &mut complete_capability()).is_ok());
        assert!(matches!(
            node.runtime()
                .block_on(node.prepare_trusted_gitlink_patch_in(
                    &node.request_context(),
                    &reference(),
                    fixture.untouched,
                    [0xe6; 16],
                    &input,
                    &metadata(),
                    PatchLimits::default(),
                )),
            Err(NodeWorkspaceRefusal::StaleWorkspaceBase)
        ));
        let cancelled = node.request_context();
        cancelled.cancel();
        assert!(
            node.runtime()
                .block_on(node.prepare_trusted_gitlink_patch_in(
                    &cancelled,
                    &reference(),
                    fixture.commit,
                    [0xe6; 16],
                    &input,
                    &metadata(),
                    PatchLimits::default(),
                ))
                .is_err()
        );

        let first = patch(format, "new/first", None, Some(next));
        let second = patch(format, "new/second", None, Some(next));
        let image_bytes = format!("Subproject commit {next}\n").len();
        let limits = PatchLimits {
            max_file_bytes: image_bytes,
            max_output_bytes: image_bytes * 2 - 1,
            ..PatchLimits::default()
        };
        assert!(prepare(&fixture, &first, limits).is_ok());
        assert!(prepare(&fixture, &[first, second].concat(), limits).is_err());
        assert_eq!(fixture.head(), before);
    }
}
