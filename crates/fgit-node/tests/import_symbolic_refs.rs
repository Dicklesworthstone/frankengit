#![forbid(unsafe_code)]
//! Source symbolic refs resolve through the real durable importer. Fixtures use
//! ordinary Git directory layouts and independently framed loose objects; no
//! external Git process or in-memory admission substitute runs these tests.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_admission::{AdmissionLimits, AdmissionResult};
use fgit_authority::{IdempotencyKey, key_recovery::RequestRecovery};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_node::{
    LoopbackReceiveSession, LooseGitImportRefusal, MaterializedAdmission, NodeConfig,
    NodeSourceImportRefusal, OneNode,
};
use fgit_pack::full_bundle::FullBundleInput;
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RefName, RepositoryId,
    TenantId,
};
use fgit_wire::visibility::RefVisibility;

const PRINCIPAL: PrincipalId = PrincipalId::from_bytes([0x73; 16]);
const KEY: &[u8] = b"native-symbolic-ref-import";
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-symbolic-ref-import-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }

    fn config(&self, format: GitHashAlgorithm, directory: &str, repository: u8) -> NodeConfig {
        NodeConfig::new(
            self.0.join(directory),
            TenantId::from_bytes([0x71; 16]),
            RepositoryId::from_bytes([repository; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(2)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write(root: &Path, relative: &str, body: impl AsRef<[u8]>) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, body).unwrap();
}

fn name(value: &str) -> RefName {
    RefName::try_new(value.as_bytes()).unwrap()
}

fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let oid = git_object_id(format, kind, body);
    let raw = [
        format!("{} {}\0", kind.label(), body.len()).as_bytes(),
        body,
    ]
    .concat();
    // One stored DEFLATE block and independently calculated Adler-32 keep the
    // source representation separate from the production compressor.
    let length = u16::try_from(raw.len()).unwrap();
    let mut encoded = vec![0x78, 0x01, 0x01];
    encoded.extend(length.to_le_bytes());
    encoded.extend((!length).to_le_bytes());
    encoded.extend_from_slice(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let next = (a + u32::from(*byte)) % 65_521;
        (next, (b + next) % 65_521)
    });
    encoded.extend(((b << 16) | a).to_be_bytes());
    let hex = oid.to_string();
    write(
        root,
        &format!("objects/{}/{}", &hex[..2], &hex[2..]),
        encoded,
    );
    oid
}

struct Source {
    root: PathBuf,
    commit: GitOid,
    tree: GitOid,
    blob: GitOid,
    tag: GitOid,
    stale: GitOid,
    objects: BTreeMap<GitOid, Vec<u8>>,
}

impl Source {
    fn new(root: PathBuf, format: GitHashAlgorithm) -> Self {
        write(&root, "HEAD", b"ref: refs/heads/main\n");
        write(
            &root,
            "config",
            match format {
                GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\n",
                GitHashAlgorithm::Sha256 => {
                    "[core]\nrepositoryformatversion = 1\n[extensions]\nobjectformat = sha256\n"
                }
            },
        );
        let mut objects = BTreeMap::new();
        let mut put = |kind, body: Vec<u8>| {
            let id = loose(&root, format, kind, &body);
            objects.insert(id, body);
            id
        };
        let blob = put(
            GitObjectKind::Blob,
            b"native import survives source removal\n".to_vec(),
        );
        let tree = put(
            GitObjectKind::Tree,
            [b"100644 README\0".as_slice(), blob.as_bytes()].concat(),
        );
        let commit_body = |message: &str| {
            format!(
                "tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\n{message}\n"
            ).into_bytes()
        };
        let commit = put(GitObjectKind::Commit, commit_body("selected source"));
        let stale = put(GitObjectKind::Commit, commit_body("shadowed packed source"));
        let tag = put(
            GitObjectKind::Tag,
            format!(
                "object {commit}\ntype commit\ntag v1\ntagger Fixture <fixture@example.invalid> 1 +0000\n\nselected release\n"
            ).into_bytes(),
        );
        write(&root, "refs/heads/main", format!("{commit}\n"));
        write(&root, "packed-refs", format!("{tag} refs/tags/v1\n"));
        Self {
            root,
            commit,
            tree,
            blob,
            tag,
            stale,
            objects,
        }
    }

    fn refs(&self) -> BTreeMap<RefName, GitOid> {
        BTreeMap::from([
            (name("refs/heads/main"), self.commit),
            (name("refs/tags/v1"), self.tag),
        ])
    }

    fn assert_objects(&self, node: &OneNode) {
        let expected = self
            .objects
            .keys()
            .copied()
            .filter(|id| *id != self.stale)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            snapshot(node).selected_closure().closure().objects(),
            &expected
        );
        for (id, body) in &self.objects {
            if *id == self.stale {
                assert!(
                    node.read_git_object(*id).is_err(),
                    "shadowed roots do not enter the fabric"
                );
            } else {
                assert_eq!(node.read_git_object(*id).unwrap().payload(), body);
            }
        }
    }
}

fn node(config: NodeConfig) -> OneNode {
    let (mut node, _) = OneNode::init(config).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    node
}

fn snapshot(node: &OneNode) -> MaterializedAdmission {
    node.runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .unwrap()
}

fn session() -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(PRINCIPAL, IdempotencyKey::new(KEY.to_vec()).unwrap())
}

fn import(node: &OneNode, source: &Path) -> Result<AdmissionResult, NodeSourceImportRefusal> {
    node.runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &node.import_request_context(None),
            source,
            PRINCIPAL,
            KEY,
        ))
}

fn staging(error: NodeSourceImportRefusal) -> LooseGitImportRefusal {
    match error {
        NodeSourceImportRefusal::Staging(error) => *error,
        error => panic!("expected pre-admission source refusal, observed {error:?}"),
    }
}

fn assert_committed(result: &AdmissionResult, count: usize) {
    assert!(result.session.atomic);
    assert_eq!(result.session.tx_ids.len(), 1);
    assert_eq!(result.commands.len(), count);
    assert!(
        result
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. })),
        "{result:?}"
    );
}

fn assert_unpublished(node: &OneNode, before: &MaterializedAdmission, source: &Source) {
    let after = snapshot(node);
    assert_eq!(after.basis(), before.basis());
    assert!(after.snapshot().refs.is_empty());
    assert!(after.selected_closure().closure().objects().is_empty());
    for id in source.objects.keys() {
        assert!(node.read_git_object(*id).is_err(), "refusal placed {id}");
    }
    assert!(matches!(
        node.runtime()
            .block_on(node.recover_transaction_in(&node.request_context(), &session()))
            .unwrap(),
        RequestRecovery::KeyNotObserved
    ));
}

#[test]
fn packed_byte_names_remain_distinct_and_symbolic_targets_resolve_in_both_hash_domains() {
    let packed_name = b"refs/heads/topic-\xff";
    // A lossy conversion would collapse these two distinct branches.
    let utf8_name = "refs/heads/topic-\u{fffd}";
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let source = Source::new(scratch.0.join("source.git"), format);
        let mut lines = format!("{} refs/tags/v1\r\n{} ", source.tag, source.commit).into_bytes();
        lines.extend_from_slice(packed_name);
        lines.extend_from_slice(format!("\r\n{} {utf8_name}\n", source.stale).as_bytes());
        write(
            &source.root,
            "HEAD",
            [b"ref: ".as_slice(), packed_name, b"\n"].concat(),
        );
        write(
            &source.root,
            "refs/remotes/origin/HEAD",
            [b"ref: ".as_slice(), packed_name, b"\n"].concat(),
        );

        let mut expected = source.refs();
        expected.insert(RefName::try_new(packed_name).unwrap(), source.commit);
        expected.insert(name(utf8_name), source.stale);
        expected.insert(name("refs/remotes/origin/HEAD"), source.commit);
        let config = scratch.config(format, "node", 0x72);
        let imported = node(config.clone());
        let before = snapshot(&imported);
        for malformed in [
            b"# \xff\n".as_slice(),
            b"^\xff\n",
            b"\xff refs/heads/invalid\n",
        ] {
            write(
                &source.root,
                "packed-refs",
                [lines.as_slice(), malformed].concat(),
            );
            assert!(matches!(
                staging(import(&imported, &source.root).unwrap_err()),
                LooseGitImportRefusal::PackedRefContents(_)
            ));
            assert_unpublished(&imported, &before, &source);
        }
        write(&source.root, "packed-refs", lines);
        let first = import(&imported, &source.root).unwrap();
        assert_committed(&first, expected.len());
        assert_eq!(snapshot(&imported).snapshot().refs, expected);

        // Move the exact same ref into a loose filesystem entry. Its identity
        // and the sealed import must survive the storage-layout change.
        #[cfg(unix)]
        {
            use std::ffi::OsStr;
            use std::os::unix::ffi::OsStrExt;
            fs::write(
                source.root.join(OsStr::from_bytes(packed_name)),
                format!("{}\n", source.commit),
            )
            .unwrap();
            write(
                &source.root,
                "packed-refs",
                format!(
                    "{} refs/tags/v1\n{} {utf8_name}\n",
                    source.tag, source.stale
                ),
            );
            assert_eq!(import(&imported, &source.root).unwrap(), first);
        }
        imported.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(config).unwrap();
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(snapshot(&reopened).snapshot().refs, expected);
        reopened.shutdown().unwrap();
    }
}

#[test]
fn clone_style_aliases_import_replay_and_export_without_the_source_in_both_hash_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let checkout = scratch.0.join("ordinary clone");
        let source = Source::new(checkout.join(".git"), format);
        write(
            &source.root,
            "packed-refs",
            format!(
                "# pack-refs with: sorted\n{} refs/heads/main\n{} refs/remotes/origin/HEAD\n{} refs/remotes/origin/main\n{} refs/tags/v1\n",
                source.stale, source.stale, source.stale, source.tag,
            ),
        );
        write(
            &source.root,
            "refs/remotes/origin/HEAD",
            b"ref: refs/remotes/origin/default\n",
        );
        write(
            &source.root,
            "refs/remotes/origin/default",
            b"ref: refs/remotes/origin/main\n",
        );
        write(
            &source.root,
            "refs/remotes/origin/main",
            format!("{}\n", source.commit),
        );
        write(&source.root, "refs/tags/latest", b"ref: refs/tags/v1\n");
        let mut expected = source.refs();
        for reference in [
            "refs/remotes/origin/HEAD",
            "refs/remotes/origin/default",
            "refs/remotes/origin/main",
        ] {
            expected.insert(name(reference), source.commit);
        }
        expected.insert(name("refs/tags/latest"), source.tag);
        let config = scratch.config(format, "node", 0x72);
        let imported = node(config.clone());
        let before = snapshot(&imported);
        let first = import(&imported, &checkout).unwrap();
        assert_committed(&first, expected.len());
        let selected = snapshot(&imported);
        assert_eq!(
            selected.basis().generation().get(),
            before.basis().generation().get() + 1
        );
        assert_eq!(selected.snapshot().refs, expected);
        assert_eq!(
            selected.snapshot().head_target,
            Some(name("refs/heads/main"))
        );
        source.assert_objects(&imported);

        // The native destination owns direct snapshot refs. A source rewrite
        // from aliases to the same direct OIDs is the exact original request,
        // not a second update or an idempotency-key conflict.
        for reference in ["refs/remotes/origin/HEAD", "refs/remotes/origin/default"] {
            write(&source.root, reference, format!("{}\n", source.commit));
        }
        write(
            &source.root,
            "refs/tags/latest",
            format!("{}\n", source.tag),
        );
        assert_eq!(import(&imported, &checkout).unwrap(), first);
        assert_eq!(snapshot(&imported).basis(), selected.basis());
        let (_, original_bundle) = imported
            .runtime()
            .block_on(imported.export_full_git_bundle_in(
                &imported.request_context(),
                &RefVisibility::new(),
                Some(selected.basis().id()),
            ))
            .unwrap();
        imported.shutdown().unwrap();
        fs::remove_dir_all(checkout).unwrap();

        let mut reopened = OneNode::open_existing(config).unwrap();
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(snapshot(&reopened).basis(), selected.basis());
        assert_eq!(snapshot(&reopened).snapshot().refs, expected);
        source.assert_objects(&reopened);
        let recovery = reopened
            .runtime()
            .block_on(reopened.recover_transaction_in(&reopened.request_context(), &session()))
            .unwrap();
        assert_eq!(recovery.terminal(), Some(first.commands[0].terminal));
        let (head, bundle) = reopened
            .runtime()
            .block_on(reopened.export_full_git_bundle_in(
                &reopened.request_context(),
                &RefVisibility::new(),
                Some(selected.basis().id()),
            ))
            .unwrap();
        assert_eq!(head, selected.basis().id());
        assert_eq!(bundle.bytes(), original_bundle.bytes());
        let parsed =
            FullBundleInput::parse(bundle.bytes(), Default::default(), &mut || true).unwrap();
        assert_eq!(parsed.format(), format);
        assert_eq!(parsed.head(), Some(source.commit));
        assert!(parsed.prerequisites().is_empty());
        assert_eq!(
            parsed
                .references()
                .iter()
                .map(|reference| { (reference.name().clone(), *reference.target()) })
                .collect::<BTreeMap<_, _>>(),
            expected
        );
        parsed
            .verify_pack_framing(&Default::default(), &mut || true)
            .unwrap();

        // Consume the source-free native export through ordinary admission in
        // a second, empty repository and compare every object body and ref.
        let clone = node(scratch.config(format, "clone", 0x74));
        let result = clone
            .runtime()
            .block_on(clone.import_full_git_bundle_durable_in(
                &clone.request_context(),
                &session(),
                bundle.bytes(),
                AdmissionLimits::default(),
            ))
            .unwrap();
        assert_committed(&result, expected.len());
        assert_eq!(snapshot(&clone).snapshot().refs, expected);
        source.assert_objects(&clone);
        clone.shutdown().unwrap();
        reopened.shutdown().unwrap();
    }
}

#[test]
fn broken_alias_graphs_and_cancelled_import_publish_nothing_and_leave_the_key_reusable() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let source = Source::new(scratch.0.join("source.git"), format);
        let destination = node(scratch.config(format, "node", 0x72));
        let before = snapshot(&destination);
        let alias = "refs/remotes/origin/HEAD";
        let cycle = "refs/remotes/origin/cycle";
        for (case, bytes) in [
            b"ref: refs/remotes/origin/missing\n".as_slice(),
            b"ref: refs/remotes/origin/HEAD\n",
            b"ref: refs/remotes/origin/cycle\n",
            b"ref: HEAD\n",
            b"ref: ../outside\n",
            b"ref: refs/heads/../main\n",
            b"ref: refs/heads/main\nref: refs/heads/main\n",
            b"ref: refs/heads/main",
        ]
        .into_iter()
        .enumerate()
        {
            write(&source.root, alias, bytes);
            if case == 2 {
                write(&source.root, cycle, b"ref: refs/remotes/origin/HEAD\n");
            }
            let error = staging(import(&destination, &source.root).unwrap_err());
            assert!(
                match case {
                    0 => matches!(
                        error,
                        LooseGitImportRefusal::SymbolicRefTargetMissing { .. }
                    ),
                    1 | 2 => matches!(error, LooseGitImportRefusal::SymbolicRefCycle(_)),
                    3 | 4 => matches!(error, LooseGitImportRefusal::SymbolicRefUnsupported(_)),
                    5 | 6 => matches!(error, LooseGitImportRefusal::RefName { .. }),
                    7 => matches!(error, LooseGitImportRefusal::RefContents(_)),
                    _ => unreachable!(),
                },
                "case {case}: {error:?}"
            );
            assert_unpublished(&destination, &before, &source);
            if case == 2 {
                fs::remove_file(source.root.join(cycle)).unwrap();
            }
        }
        write(&source.root, alias, b"ref: refs/heads/main\n");
        let cancelled = destination.import_request_context(None);
        cancelled.cancel();
        let error = destination
            .runtime()
            .block_on(destination.import_loose_git_directory_durable_in(
                &cancelled,
                &source.root,
                PRINCIPAL,
                KEY,
            ))
            .unwrap_err();
        assert!(matches!(
            staging(error),
            LooseGitImportRefusal::Interrupted { .. }
        ));
        assert_unpublished(&destination, &before, &source);
        let repaired = import(&destination, &source.root).unwrap();
        assert_committed(&repaired, 3);
        let mut expected = source.refs();
        expected.insert(name(alias), source.commit);
        assert_eq!(snapshot(&destination).snapshot().refs, expected);
        source.assert_objects(&destination);
        destination.shutdown().unwrap();
    }
}

#[test]
fn a_branch_alias_still_requires_a_commit_even_when_its_target_is_a_valid_nonbranch_ref() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let source = Source::new(scratch.0.join("source.git"), format);
        let destination = node(scratch.config(format, "node", 0x72));
        let before = snapshot(&destination);
        write(&source.root, "refs/heads/alias", b"ref: refs/tags/target\n");
        for wrong_kind in [source.blob, source.tree, source.tag] {
            write(&source.root, "refs/tags/target", format!("{wrong_kind}\n"));
            let error = staging(import(&destination, &source.root).unwrap_err());
            assert!(
                matches!(error, LooseGitImportRefusal::ObjectGraph { identity, .. } if identity == wrong_kind),
                "{error:?}"
            );
            assert_unpublished(&destination, &before, &source);
        }
        write(
            &source.root,
            "refs/tags/target",
            format!("{}\n", source.commit),
        );
        assert_committed(&import(&destination, &source.root).unwrap(), 4);
        let mut expected = source.refs();
        expected.insert(name("refs/heads/alias"), source.commit);
        expected.insert(name("refs/tags/target"), source.commit);
        assert_eq!(snapshot(&destination).snapshot().refs, expected);
        source.assert_objects(&destination);
        destination.shutdown().unwrap();
    }
}

#[test]
fn linked_worktree_aliases_use_only_the_selected_private_namespace() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let common = scratch.0.join("main checkout/.git");
        let source = Source::new(common.clone(), format);
        let private = common.join("worktrees/selected");
        let checkout = scratch.0.join("linked checkout");
        write(
            &checkout,
            ".git",
            b"gitdir: ../main checkout/.git/worktrees/selected\n",
        );
        write(&private, "commondir", b"../..\n");
        write(&private, "HEAD", b"ref: refs/heads/topic\n");
        write(&common, "refs/heads/topic", format!("{}\n", source.commit));
        write(
            &common,
            "packed-refs",
            format!(
                "{} refs/tags/v1\n{} refs/worktree/pin\n",
                source.tag, source.stale,
            ),
        );
        write(&common, "refs/worktree/pin", format!("{}\n", source.stale));
        write(
            &common,
            "refs/worktree/main-only",
            format!("{}\n", source.stale),
        );
        write(&common, "refs/worktree/poison", b"ref: refs/missing/main\n");
        write(
            &common,
            "worktrees/other/refs/worktree/poison",
            b"ref: refs/missing/other\n",
        );
        write(&private, "refs/heads/main", format!("{}\n", source.stale));
        write(
            &private,
            "packed-refs",
            format!("{} refs/heads/other-private\n", source.stale),
        );
        write(
            &private,
            "refs/worktree/pin",
            format!("{}\n", source.commit),
        );
        write(&private, "refs/worktree/alias", b"ref: refs/heads/main\n");
        write(&private, "refs/bisect/good", b"ref: refs/worktree/pin\n");
        write(
            &private,
            "refs/rewritten/marker",
            b"ref: refs/worktree/alias\n",
        );
        write(
            &common,
            "refs/remotes/origin/HEAD",
            b"ref: refs/worktree/main-only\n",
        );
        let destination = node(scratch.config(format, "node", 0x72));
        let before = snapshot(&destination);
        assert!(
            matches!(staging(import(&destination, &checkout).unwrap_err()),
                LooseGitImportRefusal::SymbolicRefTargetMissing { target, .. }
                    if target == name("refs/worktree/main-only")
            ),
            "an alias must not reopen an excluded common worktree ref"
        );
        assert_unpublished(&destination, &before, &source);
        write(
            &common,
            "refs/remotes/origin/HEAD",
            b"ref: refs/worktree/pin\n",
        );
        let mut expected = source.refs();
        for reference in [
            "refs/heads/topic",
            "refs/remotes/origin/HEAD",
            "refs/worktree/pin",
            "refs/worktree/alias",
            "refs/bisect/good",
            "refs/rewritten/marker",
        ] {
            expected.insert(name(reference), source.commit);
        }
        let first = import(&destination, &checkout).unwrap();
        assert_committed(&first, expected.len());
        assert_eq!(snapshot(&destination).snapshot().refs, expected);
        assert_eq!(
            snapshot(&destination).snapshot().head_target,
            Some(name("refs/heads/main")),
            "source HEAD selects the import snapshot but never rewrites destination HEAD"
        );
        source.assert_objects(&destination);
        let head = snapshot(&destination).basis().id();
        assert_eq!(import(&destination, &private).unwrap(), first);
        assert_eq!(snapshot(&destination).basis().id(), head);
        destination.shutdown().unwrap();
    }
}

#[cfg(unix)]
#[test]
fn symbolic_git_ref_support_does_not_follow_a_host_filesystem_symlink() {
    use std::os::unix::fs::symlink;

    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let source = Source::new(scratch.0.join("source.git"), format);
        let external = scratch.0.join("outside-ref");
        fs::write(&external, b"ref: refs/heads/main\n").unwrap();
        let alias = source.root.join("refs/remotes/origin/HEAD");
        fs::create_dir_all(alias.parent().unwrap()).unwrap();
        symlink(&external, &alias).unwrap();
        let destination = node(scratch.config(format, "node", 0x72));
        let before = snapshot(&destination);
        assert!(matches!(
            staging(import(&destination, &source.root).unwrap_err()),
            LooseGitImportRefusal::SymbolicLink(_)
        ));
        assert_unpublished(&destination, &before, &source);
        fs::remove_file(alias).unwrap();
        write(
            &source.root,
            "refs/remotes/origin/HEAD",
            b"ref: refs/heads/main\n",
        );
        assert_committed(&import(&destination, &source.root).unwrap(), 3);
        source.assert_objects(&destination);
        destination.shutdown().unwrap();
    }
}
