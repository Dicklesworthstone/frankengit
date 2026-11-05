#![forbid(unsafe_code)]
//! Explicit symlink patches reach the existing candidate and admission path.

#[allow(dead_code)]
#[path = "workspace_metadata_edits/fixture.rs"]
mod fixture;

use fgit_crypto::{GitHashAlgorithm as HashAlgorithm, GitObjectKind, Sha1, Sha256, git_object_id};
use fgit_forge::{patch::PatchLimits, preparation::MergeMetadata};
use fgit_git_object::{AcceptanceProfile, ParseLimits, parse_tree};
use fgit_node::{NodeWorkspaceRefusal, WorkspacePatchCandidate};
use fgit_treefs::{CapabilityRefusal, SparseRefusal, SymlinkPolicy, TreeCapability};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid};
use fgit_wire::visibility::RefVisibility;
use fixture::*;

const FORMATS: [GitHashAlgorithm; 2] = [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256];
const CREATE: &[u8] = b"diff --git a/new/link b/new/link\nnew file mode 120000\n--- /dev/null\n+++ b/new/link\n@@ -0,0 +1 @@\n+../../outside\n\\ No newline at end of file\n";
const MOVE: &[u8] = b"diff --git a/link b/new/moved\nsimilarity index 100%\nrename from link\nrename to new/moved\n";

fn metadata() -> MergeMetadata {
    MergeMetadata {
        author: "Author <author@example.invalid>".into(),
        committer: "Committer <committer@example.invalid>".into(),
        timestamp: 2,
        message: b"exact symlink patch\n".to_vec(),
    }
}

fn prepare(
    fixture: &Fixture,
    patch: &[u8],
    limits: PatchLimits,
) -> Result<WorkspacePatchCandidate, NodeWorkspaceRefusal> {
    let node = fixture.node();
    node.runtime()
        .block_on(node.prepare_trusted_symlink_patch_in(
            &node.request_context(),
            &reference(),
            fixture.commit,
            [0xe1; 16],
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
        .block_on(node.prepare_workspace_symlink_patch_in::<A>(
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

fn publish(fixture: &Fixture, candidate: &WorkspacePatchCandidate) {
    let node = fixture.node();
    assert!(
        node.read_git_object(candidate.candidate_commit).is_err(),
        "preparation must not stage a commit"
    );
    let result = node
        .runtime()
        .block_on(node.apply_workspace_bundle_durable_in(
            &node.request_context(),
            PRINCIPAL,
            b"symlink-patch-publication",
            &reference(),
            fixture.commit,
            candidate.candidate_commit,
            candidate.bundle_bytes(),
        ))
        .unwrap();
    assert!(matches!(
        result.commands[0].terminal.outcome,
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
}

fn entry(fixture: &Fixture, mut tree: GitOid, target: &str) -> Option<(Vec<u8>, GitOid)> {
    let components: Vec<_> = target.as_bytes().split(|byte| *byte == b'/').collect();
    for (index, name) in components.iter().enumerate() {
        let object = fixture.node().read_git_object(tree).unwrap();
        let entries = parse_tree(
            object.payload(),
            AcceptanceProfile::GitCompatibleImport,
            &ParseLimits {
                tree_reference_bytes: fixture.format.digest_len(),
                ..ParseLimits::default()
            },
        )
        .unwrap();
        let found = entries.iter().find(|entry| entry.name == *name)?;
        let hex: String = found
            .object_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let oid = GitOid::from_hex(fixture.format, &hex).unwrap();
        if index + 1 == components.len() {
            return Some((found.mode.clone(), oid));
        }
        assert_eq!(found.mode, b"40000", "tests never follow symlink targets");
        tree = oid;
    }
    None
}

#[test]
fn explicit_symlink_creation_and_original_coordinate_move_publish_exact_modes_in_both_formats() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let before = fixture.head();
        let patch = [CREATE, MOVE].concat();
        let candidate = prepare(&fixture, &patch, PatchLimits::default()).unwrap();
        assert_eq!(fixture.head(), before);
        assert_eq!(candidate.paths.len(), 3);
        let new_blob = git_object_id(format, GitObjectKind::Blob, b"../../outside");
        let old_blob = git_object_id(format, GitObjectKind::Blob, b"src/tool.sh");
        let created = candidate
            .paths
            .iter()
            .find(|entry| entry.path == b"new/link")
            .unwrap();
        assert_eq!(
            (created.old_blob, created.new_blob, created.new_mode),
            (None, Some(new_blob), Some(0o120000))
        );
        let moved = candidate
            .paths
            .iter()
            .find(|entry| entry.path == b"new/moved")
            .unwrap();
        assert_eq!(
            (moved.new_blob, moved.new_mode),
            (Some(old_blob), Some(0o120000))
        );
        publish(&fixture, &candidate);
        assert_eq!(entry(&fixture, candidate.root_tree, "link"), None);
        assert_eq!(
            entry(&fixture, candidate.root_tree, "new/link"),
            Some((b"120000".to_vec(), new_blob))
        );
        assert_eq!(
            entry(&fixture, candidate.root_tree, "new/moved"),
            Some((b"120000".to_vec(), old_blob))
        );
        assert_eq!(
            entry(&fixture, candidate.root_tree, "src/tool.sh"),
            Some((b"100644".to_vec(), fixture.file))
        );
        assert_eq!(
            entry(&fixture, candidate.root_tree, "untouched.txt"),
            Some((b"100644".to_vec(), fixture.untouched))
        );
        assert_eq!(
            fixture.node().read_git_object(new_blob).unwrap().payload(),
            b"../../outside"
        );
    }
}

#[test]
fn symlink_edit_delete_and_explicit_type_headers_bind_actual_blob_identities() {
    for format in FORMATS {
        for (metadata, body, mode) in [
            (
                "",
                Some(b"/absolute/target".as_slice()),
                Some(b"120000".as_slice()),
            ),
            (
                "old mode 120000\nnew mode 100755\n",
                Some(b"src/tool.sh".as_slice()),
                Some(b"100755".as_slice()),
            ),
            ("deleted file mode 120000\n", None, None),
        ] {
            let fixture = Fixture::new(format);
            let old = git_object_id(format, GitObjectKind::Blob, b"src/tool.sh");
            let new = body.map(|bytes| git_object_id(format, GitObjectKind::Blob, bytes));
            let new_hex = new.map_or("0".repeat(format.digest_len() * 2), |id| id.to_string());
            let mut patch = format!("diff --git a/link b/link\n{metadata}index {old}..{new_hex}\n");
            if metadata.starts_with("old mode") {
                // Mode-only conversion preserves the source bytes and identity.
            } else if body.is_some() {
                patch.push_str("--- a/link\n+++ b/link\n@@ -1 +1 @@\n-src/tool.sh\n\\ No newline at end of file\n+/absolute/target\n\\ No newline at end of file\n");
            } else {
                patch.push_str("--- a/link\n+++ /dev/null\n@@ -1 +0,0 @@\n-src/tool.sh\n\\ No newline at end of file\n");
            }
            let candidate = prepare(&fixture, patch.as_bytes(), PatchLimits::default()).unwrap();
            let receipt = &candidate.paths[0];
            assert_eq!((receipt.old_blob, receipt.new_blob), (Some(old), new));
            let forged = patch.replacen(
                &format!("index {old}"),
                &format!("index {}", "ab".repeat(format.digest_len())),
                1,
            );
            assert!(prepare(&fixture, forged.as_bytes(), PatchLimits::default()).is_err());
            publish(&fixture, &candidate);
            assert_eq!(
                entry(&fixture, candidate.root_tree, "link"),
                mode.zip(new).map(|(mode, oid)| (mode.to_vec(), oid))
            );
            if let (Some(body), Some(oid)) = (body, new) {
                assert_eq!(fixture.node().read_git_object(oid).unwrap().payload(), body);
            }
        }
    }
}

#[test]
fn legacy_profiles_keep_declared_and_implicit_symlink_refusals() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let node = fixture.node();
        for patch in [CREATE, MOVE] {
            assert!(
                node.runtime()
                    .block_on(node.prepare_trusted_patch_in(
                        &node.request_context(),
                        &reference(),
                        fixture.commit,
                        [0xe2; 16],
                        patch,
                        &metadata(),
                        PatchLimits::default(),
                    ))
                    .is_err()
            );
            assert!(
                node.runtime()
                    .block_on(node.prepare_trusted_binary_refactor_in(
                        &node.request_context(),
                        &reference(),
                        fixture.commit,
                        [0xe2; 16],
                        patch,
                        &metadata(),
                        PatchLimits::default(),
                    ))
                    .is_err()
            );
            assert!(prepare(&fixture, patch, PatchLimits::default()).is_ok());
        }
    }
}

#[test]
fn symlink_patches_retain_scope_policy_byte_and_stale_base_guards() {
    for format in FORMATS {
        let fixture = Fixture::new(format);
        let before = fixture.head();
        let reads = ["dst", "link", "module", "new", "src", "untouched.txt"];
        for (writes, denied) in [(["new"], "link"), (["link"], "new/moved")] {
            let mut cap = capability(&reads, &writes);
            assert!(
                matches!(scoped(&fixture, MOVE, &mut cap), Err(NodeWorkspaceRefusal::Manifest(SparseRefusal::Capability(
                CapabilityRefusal::WriteOutsideScope { path: refused }
            ))) if refused == path(denied))
            );
            assert_eq!(cap.fetched_bytes(), 0);
        }
        assert!(
            scoped(
                &fixture,
                CREATE,
                &mut complete_capability().with_symlink_policy(SymlinkPolicy::Refuse)
            )
            .is_err()
        );
        assert!(scoped(&fixture, CREATE, &mut complete_capability()).is_ok());
        let limits = PatchLimits {
            max_file_bytes: 4,
            max_output_bytes: 4,
            ..PatchLimits::default()
        };
        assert!(prepare(&fixture, CREATE, limits).is_err());
        let node = fixture.node();
        assert!(matches!(
            node.runtime()
                .block_on(node.prepare_trusted_symlink_patch_in(
                    &node.request_context(),
                    &reference(),
                    fixture.untouched,
                    [0xe3; 16],
                    CREATE,
                    &metadata(),
                    PatchLimits::default(),
                )),
            Err(NodeWorkspaceRefusal::StaleWorkspaceBase)
        ));
        let cancelled = node.request_context();
        cancelled.cancel();
        assert!(matches!(
            node.runtime()
                .block_on(node.prepare_trusted_symlink_patch_in(
                    &cancelled,
                    &reference(),
                    fixture.commit,
                    [0xe3; 16],
                    CREATE,
                    &metadata(),
                    PatchLimits::default(),
                )),
            Err(NodeWorkspaceRefusal::WorkspacePatch(
                fgit_forge::patch::PatchError::Cancelled
            )) | Err(NodeWorkspaceRefusal::Cancelled { .. })
        ));
        assert_eq!(fixture.head(), before);
    }
}
