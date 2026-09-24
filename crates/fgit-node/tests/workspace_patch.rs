#![forbid(unsafe_code)]
//! Real file-backed authority -> exact patch -> TreeFS -> bundle -> receive CAS.

use fgit_crypto::{GitObjectKind, Sha1, git_object_id, sha256_digest};
use fgit_forge::patch::{PatchError, PatchLimits};
use fgit_forge::preparation::MergeMetadata;
use fgit_node::{NodeConfig, NodeWorkspaceRefusal, OneNode, WorkspacePatchCandidate};
use fgit_treefs::{TreeCapability, TreePath, WorkspaceId};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RefName, RepositoryId,
    TenantId,
};
use fgit_wire::visibility::RefVisibility;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const REPOSITORY: RepositoryId = RepositoryId::from_bytes([0xd2; 16]);
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
    node: Option<OneNode>,
    base: GitOid,
    kept: GitOid,
    old: GitOid,
    format: GitHashAlgorithm,
}
impl Fixture {
    fn new(format: GitHashAlgorithm) -> Self {
        let root = std::env::temp_dir().join(format!(
            "fgit-patch-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let source = root.join("source");
        fs::create_dir_all(source.join("refs/heads")).unwrap();
        fs::write(source.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::write(source.join("config"), match format {
            GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
            GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
        }).unwrap();
        let old = loose(&source, format, GitObjectKind::Blob, b"before\n");
        let kept = loose(&source, format, GitObjectKind::Blob, b"preserve\0me\n");
        let removed = loose(&source, format, GitObjectKind::Blob, b"remove\n");
        let tree = loose(
            &source,
            format,
            GitObjectKind::Tree,
            &[
                b"100644 edit.txt\0".as_slice(),
                old.as_bytes(),
                b"100644 keep.txt\0",
                kept.as_bytes(),
                b"100644 remove.txt\0",
                removed.as_bytes(),
            ]
            .concat(),
        );
        let base = loose(&source, format, GitObjectKind::Commit,
            format!("tree {tree}\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\nbase\n").as_bytes());
        fs::write(source.join("refs/heads/main"), format!("{base}\n")).unwrap();
        let (mut node, _) = OneNode::init(config(&root, format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let request = node.request_context();
        let result = node
            .runtime()
            .block_on(node.import_loose_git_directory_durable_in(
                &request,
                &source,
                principal(),
                b"patch-fixture",
            ))
            .unwrap();
        assert!(matches!(
            result.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        Self {
            root,
            node: Some(node),
            base,
            kept,
            old,
            format,
        }
    }
    const fn node(&self) -> &OneNode {
        self.node.as_ref().unwrap()
    }
    fn prepare(
        &self,
        patch: &[u8],
        limits: PatchLimits,
    ) -> Result<WorkspacePatchCandidate, NodeWorkspaceRefusal> {
        let node = self.node();
        let request = node.request_context();
        node.runtime().block_on(node.prepare_trusted_patch_in(
            &request,
            &reference(),
            self.base,
            [0xd4; 16],
            patch,
            &metadata(),
            limits,
        ))
    }
    fn observed(&self) -> (GitOid, String) {
        let node = self.node();
        let request = node.request_context();
        let state = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        (
            state.snapshot().refs[&reference()],
            format!("{:?}", state.basis()),
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(node) = self.node.take() {
            node.shutdown().unwrap();
        }
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn config(root: &Path, format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(
        root.join("node"),
        TenantId::from_bytes([0xd1; 16]),
        REPOSITORY,
    )
    .with_object_format(format)
    .with_worker_threads(2)
}
fn reference() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}
const fn principal() -> PrincipalId {
    PrincipalId::from_bytes([0xd3; 16])
}
fn metadata() -> MergeMetadata {
    MergeMetadata {
        author: "Test <test@example.invalid>".into(),
        committer: "Reviewer <reviewer@example.invalid>".into(),
        timestamp: 2,
        message: b"exact patch\n".to_vec(),
    }
}
fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, body);
    let raw = [
        format!("{} {}\0", kind.label(), body.len()).as_bytes(),
        body,
    ]
    .concat();
    let n = u16::try_from(raw.len()).unwrap();
    let mut z = vec![0x78, 0x01, 0x01];
    z.extend(n.to_le_bytes());
    z.extend((!n).to_le_bytes());
    z.extend(&raw);
    let (a, b) = raw.iter().fold((1u32, 0u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65521;
        (a, (b + a) % 65521)
    });
    z.extend(((b << 16) | a).to_be_bytes());
    let hex = id.to_string();
    let dir = root.join("objects").join(&hex[..2]);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(&hex[2..]), z).unwrap();
    id
}
const fn simple_patch() -> &'static [u8] {
    b"diff --git a/edit.txt b/edit.txt\n--- a/edit.txt\n+++ b/edit.txt\n@@ -1 +1 @@\n-before\n+after\n"
}
fn apply(
    f: &Fixture,
    candidate: &WorkspacePatchCandidate,
    key: &[u8],
) -> fgit_admission::AdmissionResult {
    let node = f.node();
    let request = node.request_context();
    node.runtime()
        .block_on(node.apply_workspace_bundle_durable_in(
            &request,
            principal(),
            key,
            &reference(),
            f.base,
            candidate.candidate_commit,
            candidate.bundle_bytes(),
        ))
        .unwrap()
}

#[test]
fn multi_file_patch_builds_exact_native_tree_then_publishes_once_and_reopens() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format);
        let before = f.observed();
        let after_blob = git_object_id(format, GitObjectKind::Blob, b"after\n");
        let patch = format!(
            "diff --git a/edit.txt b/edit.txt\nold mode 100644\nnew mode 100755\nindex {}..{after_blob}\n--- a/edit.txt\n+++ b/edit.txt\n@@ -1 +1 @@\n-before\n+after\ndiff --git a/new.txt b/new.txt\nnew file mode 100644\n--- /dev/null\n+++ b/new.txt\n@@ -0,0 +1 @@\n+created\n\\ No newline at end of file\ndiff --git a/remove.txt b/remove.txt\ndeleted file mode 100644\n--- a/remove.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-remove\n",
            f.old
        );
        let candidate = f.prepare(patch.as_bytes(), PatchLimits::default()).unwrap();
        assert_eq!(
            f.observed(),
            before,
            "preparation must not publish or stage a decision"
        );
        let again = f.prepare(patch.as_bytes(), PatchLimits::default()).unwrap();
        assert_eq!(candidate.bundle_bytes(), again.bundle_bytes());
        assert_eq!(candidate.patch_sha256, sha256_digest(patch.as_bytes()));
        assert_eq!(
            candidate
                .paths
                .iter()
                .map(|p| p.path.as_slice())
                .collect::<Vec<_>>(),
            vec![b"edit.txt".as_slice(), b"new.txt", b"remove.txt"]
        );
        assert_eq!(candidate.paths[0].old_blob, Some(f.old));
        assert_eq!(candidate.paths[0].new_blob, Some(after_blob));
        assert_eq!(candidate.paths[2].new_blob, None);
        let new_blob = git_object_id(format, GitObjectKind::Blob, b"created");
        let tree_bytes = [
            b"100755 edit.txt\0".as_slice(),
            after_blob.as_bytes(),
            b"100644 keep.txt\0",
            f.kept.as_bytes(),
            b"100644 new.txt\0",
            new_blob.as_bytes(),
        ]
        .concat();
        let tree = git_object_id(format, GitObjectKind::Tree, &tree_bytes);
        assert_eq!(candidate.root_tree, tree);
        let commit_bytes = format!(
            "tree {tree}\nparent {}\nauthor Test <test@example.invalid> 2 +0000\ncommitter Reviewer <reviewer@example.invalid> 2 +0000\n\nexact patch\n",
            f.base
        );
        assert_eq!(
            candidate.candidate_commit,
            git_object_id(format, GitObjectKind::Commit, commit_bytes.as_bytes())
        );
        let terminal = apply(&f, &candidate, b"patch-publication");
        assert!(matches!(
            terminal.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert_eq!(
            f.node().read_git_object(tree).unwrap().payload(),
            tree_bytes
        );
        assert_eq!(
            f.node().read_git_object(f.kept).unwrap().payload(),
            b"preserve\0me\n"
        );
        let published = f.observed();
        assert_eq!(published.0, candidate.candidate_commit);
        f.node.take().unwrap().shutdown().unwrap();
        let mut node = OneNode::open_existing(config(&f.root, f.format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        f.node = Some(node);
        assert_eq!(f.observed(), published);
        assert_eq!(apply(&f, &candidate, b"patch-publication"), terminal);
        assert_eq!(f.observed(), published);
    }
}

#[test]
fn failed_later_file_wrong_indexes_and_aggregate_budget_never_make_partial_candidates() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format);
        let before = f.observed();
        let late_failure = [simple_patch(), b"diff --git a/remove.txt b/remove.txt\n--- a/remove.txt\n+++ b/remove.txt\n@@ -1 +1 @@\n-not the base\n+wrong\n"].concat();
        assert!(matches!(
            f.prepare(&late_failure, PatchLimits::default()),
            Err(NodeWorkspaceRefusal::WorkspacePatch(
                PatchError::ContextMismatch { .. }
            ))
        ));
        let expected_new = git_object_id(format, GitObjectKind::Blob, b"after\n");
        for (old, new) in [(f.kept, expected_new), (f.old, f.kept)] {
            let index_patch = format!(
                "diff --git a/edit.txt b/edit.txt\nindex {old}..{new} 100644\n--- a/edit.txt\n+++ b/edit.txt\n@@ -1 +1 @@\n-before\n+after\n"
            );
            assert!(
                f.prepare(index_patch.as_bytes(), PatchLimits::default())
                    .is_err()
            );
        }
        let two = [simple_patch(), b"diff --git a/new.txt b/new.txt\nnew file mode 100644\n--- /dev/null\n+++ b/new.txt\n@@ -0,0 +1 @@\n+two\n"].concat();
        assert!(
            f.prepare(
                &two,
                PatchLimits {
                    max_output_bytes: 10,
                    ..PatchLimits::default()
                }
            )
            .is_ok()
        );
        assert!(matches!(
            f.prepare(
                &two,
                PatchLimits {
                    max_output_bytes: 9,
                    ..PatchLimits::default()
                }
            ),
            Err(NodeWorkspaceRefusal::WorkspacePatch(PatchError::Budget(
                "aggregate result bytes"
            )))
        ));
        assert_eq!(f.observed(), before);
        assert!(f.prepare(simple_patch(), PatchLimits::default()).is_ok());
    }
}

#[test]
fn capability_hidden_source_stale_base_and_cancellation_fail_closed_with_success_twins() {
    let f = Fixture::new(GitHashAlgorithm::Sha1);
    let node = f.node();
    let before = f.observed();
    let path = |p: &[u8]| TreePath::parse_default(p).unwrap();
    let capability = |complete: bool| {
        TreeCapability::new(
            WorkspaceId::from_bytes([0xd4; 16]),
            REPOSITORY,
            if complete {
                vec![path(b"edit.txt"), path(b"keep.txt"), path(b"remove.txt")]
            } else {
                vec![path(b"edit.txt")]
            },
            vec![path(b"edit.txt")],
        )
    };
    let request = node.request_context();
    let result = node
        .runtime()
        .block_on(node.prepare_workspace_patch_in::<Sha1>(
            &request,
            &reference(),
            f.base,
            &RefVisibility::new(),
            &mut capability(false),
            simple_patch(),
            0,
            &metadata(),
            PatchLimits::default(),
        ));
    assert!(matches!(
        result,
        Err(NodeWorkspaceRefusal::IncompleteWorkspaceExportScope)
    ));
    assert!(
        node.runtime()
            .block_on(node.prepare_workspace_patch_in::<Sha1>(
                &request,
                &reference(),
                f.base,
                &RefVisibility::new(),
                &mut capability(true),
                simple_patch(),
                0,
                &metadata(),
                PatchLimits::default()
            ))
            .is_ok()
    );
    let mut hidden = RefVisibility::new();
    hidden
        .push_rule(b"refs/heads/main", &Default::default())
        .unwrap();
    assert!(matches!(
        node.runtime()
            .block_on(node.prepare_workspace_patch_in::<Sha1>(
                &request,
                &reference(),
                f.base,
                &hidden,
                &mut capability(true),
                simple_patch(),
                0,
                &metadata(),
                PatchLimits::default()
            )),
        Err(NodeWorkspaceRefusal::RefUnavailable)
    ));
    assert!(matches!(
        node.runtime().block_on(node.prepare_trusted_patch_in(
            &request,
            &reference(),
            f.old,
            [0xd4; 16],
            simple_patch(),
            &metadata(),
            PatchLimits::default()
        )),
        Err(NodeWorkspaceRefusal::StaleWorkspaceBase)
    ));
    let unrelated = node.request_context();
    request.cancel();
    assert!(
        node.runtime()
            .block_on(node.read_authority_head_in(&request))
            .is_err()
    );
    assert!(
        node.runtime()
            .block_on(node.read_authority_head_in(&unrelated))
            .is_ok()
    );
    assert!(
        node.runtime()
            .block_on(node.prepare_trusted_patch_in(
                &request,
                &reference(),
                f.base,
                [0xd4; 16],
                simple_patch(),
                &metadata(),
                PatchLimits::default()
            ))
            .is_err()
    );
    assert_eq!(f.observed(), before);
}

#[test]
fn nested_creation_empty_creation_and_mode_only_changes_preserve_exact_content() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format);
        let patch = b"diff --git a/dir/new b/dir/new\nnew file mode 100644\n--- /dev/null\n+++ b/dir/new\n@@ -0,0 +1 @@\n+new\ndiff --git a/empty b/empty\nnew file mode 100644\ndiff --git a/keep.txt b/keep.txt\nold mode 100644\nnew mode 100755\n";
        let candidate = f.prepare(patch, PatchLimits::default()).unwrap();
        assert_eq!(candidate.paths[2].old_blob, candidate.paths[2].new_blob);
        assert_eq!(candidate.paths[2].new_mode, Some(0o100755));
        assert_eq!(
            candidate.paths[1].new_blob,
            Some(git_object_id(format, GitObjectKind::Blob, b""))
        );
        assert!(matches!(
            apply(&f, &candidate, b"nested").commands[0]
                .terminal
                .outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert_eq!(
            f.node().read_git_object(f.kept).unwrap().payload(),
            b"preserve\0me\n"
        );
    }
}

#[path = "workspace_patch/renames.rs"]
mod renames;
