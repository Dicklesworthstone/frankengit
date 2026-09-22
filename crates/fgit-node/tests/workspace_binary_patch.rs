#![forbid(unsafe_code)]
//! Actual node/TreeFS/native decoder composition, with independent byte inputs.
//! No Git subprocess is used by these Rust tests or by the production path.
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

const REPO: RepositoryId = RepositoryId::from_bytes([0x72; 16]);
static NEXT: AtomicU64 = AtomicU64::new(0);
fn reference() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}
fn principal() -> PrincipalId {
    PrincipalId::from_bytes([0x73; 16])
}
fn metadata() -> MergeMetadata {
    MergeMetadata {
        author: "A <a@example.invalid>".into(),
        committer: "C <c@example.invalid>".into(),
        timestamp: 2,
        message: b"binary patch\n".to_vec(),
    }
}
fn config(root: &Path, format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(root.join("node"), TenantId::from_bytes([0x71; 16]), REPO)
        .with_object_format(format)
        .with_worker_threads(2)
}
fn zlib(bytes: &[u8]) -> Vec<u8> {
    let size = u16::try_from(bytes.len()).unwrap();
    let mut out = vec![0x78, 1, 1];
    out.extend(size.to_le_bytes());
    out.extend((!size).to_le_bytes());
    out.extend(bytes);
    let (a, b) = bytes.iter().fold((1u32, 0u32), |(a, b), v| {
        let a = (a + u32::from(*v)) % 65521;
        (a, (b + a) % 65521)
    });
    out.extend(((b << 16) | a).to_be_bytes());
    out
}
fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, bytes: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, bytes);
    let name = id.to_string();
    let raw = [
        format!("{} {}\0", kind.label(), bytes.len()).as_bytes(),
        bytes,
    ]
    .concat();
    let dir = root.join("objects").join(&name[..2]);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(&name[2..]), zlib(&raw)).unwrap();
    id
}
struct Fixture {
    root: PathBuf,
    node: Option<OneNode>,
    base: GitOid,
    format: GitHashAlgorithm,
    kept: GitOid,
}
impl Fixture {
    fn new(format: GitHashAlgorithm, asset: Option<&[u8]>) -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-binary-patch-{}-{}",
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
        let kept = loose(
            &source,
            format,
            GitObjectKind::Blob,
            b"unchanged\0sibling\n",
        );
        let mut tree = Vec::new();
        if let Some(bytes) = asset {
            let id = loose(&source, format, GitObjectKind::Blob, bytes);
            tree.extend(b"100644 asset.bin\0");
            tree.extend(id.as_bytes());
        }
        tree.extend(b"100644 keep.bin\0");
        tree.extend(kept.as_bytes());
        let tree = loose(&source, format, GitObjectKind::Tree, &tree);
        let base = loose(&source, format, GitObjectKind::Commit,
            format!("tree {tree}\nauthor A <a@example.invalid> 1 +0000\ncommitter C <c@example.invalid> 1 +0000\n\nbase\n").as_bytes());
        fs::write(source.join("refs/heads/main"), format!("{base}\n")).unwrap();
        let (mut node, _) = OneNode::init(config(&root, format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let cx = node.request_context();
        let imported = node
            .runtime()
            .block_on(node.import_loose_git_directory_durable_in(
                &cx,
                &source,
                principal(),
                b"binary-fixture",
            ))
            .unwrap();
        assert!(matches!(
            imported.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        Self {
            root,
            node: Some(node),
            base,
            format,
            kept,
        }
    }
    fn node(&self) -> &OneNode {
        self.node.as_ref().unwrap()
    }
    fn prepare(
        &self,
        bytes: &[u8],
        limits: PatchLimits,
    ) -> Result<WorkspacePatchCandidate, NodeWorkspaceRefusal> {
        let n = self.node();
        let cx = n.request_context();
        n.runtime().block_on(n.prepare_trusted_patch_in(
            &cx,
            &reference(),
            self.base,
            [0x74; 16],
            bytes,
            &metadata(),
            limits,
        ))
    }
    fn observed(&self) -> (GitOid, String) {
        let n = self.node();
        let cx = n.request_context();
        let state = n
            .runtime()
            .block_on(n.materialize_admission_in(&cx))
            .unwrap();
        (
            state.snapshot().refs[&reference()],
            format!("{:?}", state.basis()),
        )
    }
    fn apply(
        &self,
        candidate: &WorkspacePatchCandidate,
        key: &[u8],
    ) -> fgit_admission::AdmissionResult {
        let n = self.node();
        let cx = n.request_context();
        n.runtime()
            .block_on(n.apply_workspace_bundle_durable_in(
                &cx,
                principal(),
                key,
                &reference(),
                self.base,
                candidate.candidate_commit,
                candidate.bundle_bytes(),
            ))
            .unwrap()
    }
    fn reopen(&mut self) {
        self.node.take().unwrap().shutdown().unwrap();
        let mut node = OneNode::open_existing(config(&self.root, self.format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        self.node = Some(node);
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
fn member(bytes: &[u8]) -> Vec<u8> {
    const DIGITS: &[u8] =
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
    let mut out = format!("literal {}\n", bytes.len()).into_bytes();
    for row in zlib(bytes).chunks(52) {
        let n = row.len() as u8;
        out.push(if n <= 26 { b'A' + n - 1 } else { b'a' + n - 27 });
        for part in row.chunks(4) {
            let mut word = [0u8; 4];
            word[..part.len()].copy_from_slice(part);
            let mut n = u32::from_be_bytes(word);
            let mut encoded = [0u8; 5];
            for digit in encoded.iter_mut().rev() {
                *digit = DIGITS[(n % 85) as usize];
                n /= 85;
            }
            out.extend(encoded);
        }
        out.push(b'\n');
    }
    out.push(b'\n');
    out
}
fn patch(format: GitHashAlgorithm, name: &str, old: Option<&[u8]>, new: Option<&[u8]>) -> Vec<u8> {
    let id = |bytes: Option<&[u8]>| {
        bytes.map_or_else(
            || "0".repeat(format.digest_len() * 2),
            |bytes| git_object_id(format, GitObjectKind::Blob, bytes).to_string(),
        )
    };
    let mode = if old.is_none() {
        "new file mode 100644\n"
    } else if new.is_none() {
        "deleted file mode 100644\n"
    } else {
        ""
    };
    let mut out = format!(
        "diff --git a/{name} b/{name}\n{mode}index {}..{}{}\nGIT binary patch\n",
        id(old),
        id(new),
        if old.is_some() && new.is_some() {
            " 100644"
        } else {
            ""
        }
    )
    .into_bytes();
    out.extend(member(new.unwrap_or_default()));
    out.extend(member(old.unwrap_or_default()));
    out
}

#[test]
fn git_literals_creations_deletions_and_deltas_reach_native_candidates_in_both_formats() {
    for (format, goldens) in [
        (
            GitHashAlgorithm::Sha1,
            [
                include_bytes!("../../fgit-pack/src/binary_patch/fixtures/literal-sha1.patch")
                    .as_slice(),
                include_bytes!("../../fgit-pack/src/binary_patch/fixtures/create-sha1.patch")
                    .as_slice(),
                include_bytes!("../../fgit-pack/src/binary_patch/fixtures/delete-sha1.patch")
                    .as_slice(),
                include_bytes!("../../fgit-pack/src/binary_patch/fixtures/delta-sha1.patch")
                    .as_slice(),
            ],
        ),
        (
            GitHashAlgorithm::Sha256,
            [
                include_bytes!("../../fgit-pack/src/binary_patch/fixtures/literal-sha256.patch")
                    .as_slice(),
                include_bytes!("../../fgit-pack/src/binary_patch/fixtures/create-sha256.patch")
                    .as_slice(),
                include_bytes!("../../fgit-pack/src/binary_patch/fixtures/delete-sha256.patch")
                    .as_slice(),
                include_bytes!("../../fgit-pack/src/binary_patch/fixtures/delta-sha256.patch")
                    .as_slice(),
            ],
        ),
    ] {
        let delta: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
        let next_delta = [&delta[..333], b"changed\0\xff", &delta[341..]].concat();
        for (bytes, old, new) in [
            (
                goldens[0],
                Some(b"\0old\xff\n".as_slice()),
                Some(b"\0new\xfe\r\n".as_slice()),
            ),
            (goldens[1], None, Some(b"\0new\xfe\r\n".as_slice())),
            (goldens[2], Some(b"\0old\xff\n".as_slice()), None),
            (
                goldens[3],
                Some(delta.as_slice()),
                Some(next_delta.as_slice()),
            ),
        ] {
            let f = Fixture::new(format, old);
            let before = f.observed();
            let candidate = f.prepare(bytes, Default::default()).unwrap();
            assert_eq!(f.observed(), before);
            assert!(
                f.node()
                    .read_git_object(candidate.candidate_commit)
                    .is_err()
            );
            assert_eq!(
                candidate.bundle_bytes(),
                f.prepare(bytes, Default::default()).unwrap().bundle_bytes()
            );
            assert_eq!(candidate.patch_sha256, sha256_digest(bytes));
            assert_eq!(candidate.paths.len(), 1);
            let path = &candidate.paths[0];
            assert_eq!(path.path, b"asset.bin");
            assert_eq!(
                path.old_blob,
                old.map(|b| git_object_id(format, GitObjectKind::Blob, b))
            );
            assert_eq!(
                path.new_blob,
                new.map(|b| git_object_id(format, GitObjectKind::Blob, b))
            );
            assert_eq!(path.hunks, 2);
            let mut tree = Vec::new();
            if let Some(blob) = path.new_blob {
                tree.extend(b"100644 asset.bin\0");
                tree.extend(blob.as_bytes());
            }
            tree.extend(b"100644 keep.bin\0");
            tree.extend(f.kept.as_bytes());
            assert_eq!(
                candidate.root_tree,
                git_object_id(format, GitObjectKind::Tree, &tree)
            );
            assert!(matches!(
                f.apply(&candidate, b"binary-apply").commands[0]
                    .terminal
                    .outcome,
                DecisionOutcome::Committed { .. }
            ));
            assert_eq!(
                f.node()
                    .read_git_object(candidate.root_tree)
                    .unwrap()
                    .payload(),
                tree
            );
            if let Some(body) = new {
                assert_eq!(
                    f.node()
                        .read_git_object(path.new_blob.unwrap())
                        .unwrap()
                        .payload(),
                    body
                );
            }
            assert_eq!(
                f.node().read_git_object(f.kept).unwrap().payload(),
                b"unchanged\0sibling\n"
            );
        }
    }
}

#[test]
fn reopened_exact_retry_recovers_without_replaying_a_moved_source() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, Some(b"\0old"));
        let bytes = patch(format, "asset.bin", Some(b"\0old"), Some(b"\0new"));
        let candidate = f.prepare(&bytes, Default::default()).unwrap();
        let terminal = f.apply(&candidate, b"lost-response");
        let after = f.observed();
        f.reopen();
        assert_eq!(f.observed(), after);
        assert_eq!(f.apply(&candidate, b"lost-response"), terminal);
        assert_eq!(f.observed(), after);
        assert!(
            f.prepare(&bytes, Default::default()).is_err(),
            "new preparation cannot refresh the old expected tip"
        );
    }
}

#[test]
fn mixed_binary_literal_and_rename_effects_share_one_candidate() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format, Some(b"old\0"));
        let before = f.observed();
        let mut bytes = patch(format, "asset.bin", Some(b"old\0"), Some(b"new\0"));
        bytes.extend(b"diff --git a/keep.bin b/moved.bin\nsimilarity index 100%\nrename from keep.bin\nrename to moved.bin\n");
        bytes.extend(b"diff --git a/note.txt b/note.txt\nnew file mode 100755\n--- /dev/null\n+++ b/note.txt\n@@ -0,0 +1 @@\n+note\n");
        let candidate = f.prepare(&bytes, Default::default()).unwrap();
        assert_eq!(f.observed(), before);
        assert_eq!(
            candidate
                .paths
                .iter()
                .map(|p| p.path.as_slice())
                .collect::<Vec<_>>(),
            vec![
                b"asset.bin".as_slice(),
                b"keep.bin",
                b"moved.bin",
                b"note.txt"
            ]
        );
        assert_eq!(candidate.paths[1].new_blob, None);
        assert_eq!(candidate.paths[2].new_blob, Some(f.kept));
        assert_eq!(candidate.paths[3].new_mode, Some(0o100755));
        assert!(matches!(
            f.apply(&candidate, b"mixed").commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
    }
}

#[test]
fn corrupt_reverse_wrong_identity_and_late_failure_never_stage_partial_candidates() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format, Some(b"old\0"));
        let before = f.observed();
        let correct = patch(format, "asset.bin", Some(b"old\0"), Some(b"new\0"));
        let reverse = member(b"bad\0");
        let mut corrupt = correct.clone();
        let original = member(b"old\0");
        assert!(corrupt.ends_with(&original));
        corrupt.truncate(corrupt.len() - original.len());
        corrupt.extend(reverse);
        let mut later = correct.clone();
        later.extend(
            b"diff --git a/zzz b/zzz\n--- a/zzz\n+++ b/zzz\n@@ -1 +1 @@\n-not a file\n+bad\n",
        );
        for bytes in [
            corrupt,
            later,
            patch(format, "asset.bin", Some(b"wrong\0"), Some(b"new\0")),
            patch(
                if format == GitHashAlgorithm::Sha1 {
                    GitHashAlgorithm::Sha256
                } else {
                    GitHashAlgorithm::Sha1
                },
                "asset.bin",
                Some(b"old\0"),
                Some(b"new\0"),
            ),
        ] {
            assert!(f.prepare(&bytes, Default::default()).is_err());
            assert_eq!(f.observed(), before);
        }
        assert!(f.prepare(&correct, Default::default()).is_ok());
    }
}

#[test]
fn compressed_sources_and_reverse_images_share_the_whole_patch_expansion_limit() {
    let f = Fixture::new(GitHashAlgorithm::Sha1, Some(b"old\0"));
    let before = f.observed();
    let mut bytes = patch(f.format, "asset.bin", Some(b"old\0"), Some(b"new\0"));
    bytes.extend(patch(f.format, "next.bin", None, Some(b"file\0")));
    // First: 4 source + 4 forward + 4 reverse; second: 5 forward.
    assert!(
        f.prepare(
            &bytes,
            PatchLimits {
                max_output_bytes: 17,
                ..Default::default()
            }
        )
        .is_ok()
    );
    assert!(matches!(
        f.prepare(
            &bytes,
            PatchLimits {
                max_output_bytes: 16,
                ..Default::default()
            }
        ),
        Err(NodeWorkspaceRefusal::WorkspacePatch(PatchError::Budget(_)))
    ));
    assert_eq!(f.observed(), before);
}

#[test]
fn empty_file_replacement_is_not_deletion_and_modes_are_retained() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format, Some(b"old\0"));
        let bytes = patch(format, "asset.bin", Some(b"old\0"), Some(b""));
        let candidate = f.prepare(&bytes, Default::default()).unwrap();
        assert_eq!(
            candidate.paths[0].new_blob,
            Some(git_object_id(format, GitObjectKind::Blob, b""))
        );
        assert_eq!(candidate.paths[0].new_mode, Some(0o100644));
        let text =
            String::from_utf8(patch(format, "asset.bin", Some(b"old\0"), Some(b"new\0"))).unwrap();
        let bytes = text
            .replace("index ", "old mode 100644\nnew mode 100755\nindex ")
            .replace(" 100644\nGIT", "\nGIT");
        assert_eq!(
            f.prepare(bytes.as_bytes(), Default::default())
                .unwrap()
                .paths[0]
                .new_mode,
            Some(0o100755)
        );
    }
}

#[test]
fn capabilities_hidden_refs_and_request_cancellation_still_precede_binary_disclosure() {
    let f = Fixture::new(GitHashAlgorithm::Sha1, Some(b"old\0"));
    let before = f.observed();
    let bytes = patch(f.format, "asset.bin", Some(b"old\0"), Some(b"new\0"));
    let path = |bytes: &[u8]| TreePath::parse_default(bytes).unwrap();
    let capability = |writable| {
        TreeCapability::new(
            WorkspaceId::from_bytes([0x74; 16]),
            REPO,
            vec![path(b"asset.bin"), path(b"keep.bin")],
            if writable {
                vec![path(b"asset.bin")]
            } else {
                vec![]
            },
        )
    };
    let n = f.node();
    let cx = n.request_context();
    assert!(
        n.runtime()
            .block_on(n.prepare_workspace_patch_in::<Sha1>(
                &cx,
                &reference(),
                f.base,
                &RefVisibility::new(),
                &mut capability(false),
                &bytes,
                0,
                &metadata(),
                Default::default()
            ))
            .is_err()
    );
    assert!(
        n.runtime()
            .block_on(n.prepare_workspace_patch_in::<Sha1>(
                &cx,
                &reference(),
                f.base,
                &RefVisibility::new(),
                &mut capability(true),
                &bytes,
                0,
                &metadata(),
                Default::default()
            ))
            .is_ok()
    );
    let mut hidden = RefVisibility::new();
    hidden
        .push_rule(b"refs/heads/main", &Default::default())
        .unwrap();
    assert!(
        n.runtime()
            .block_on(n.prepare_workspace_patch_in::<Sha1>(
                &cx,
                &reference(),
                f.base,
                &hidden,
                &mut capability(true),
                &bytes,
                0,
                &metadata(),
                Default::default()
            ))
            .is_err()
    );
    cx.cancel();
    assert!(
        n.runtime()
            .block_on(n.prepare_trusted_patch_in(
                &cx,
                &reference(),
                f.base,
                [0x74; 16],
                &bytes,
                &metadata(),
                Default::default()
            ))
            .is_err()
    );
    assert_eq!(f.observed(), before);
}
