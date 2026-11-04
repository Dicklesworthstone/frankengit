use super::*;
use crate::{LoopbackReceiveSession, NodeConfig};
use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::history::{HistoryError, LogOptions};
use fgit_types::{DecisionOutcome, HeadGeneration, PrincipalId, RepositoryId, TenantId};
use fgit_wire::visibility::RefVisibility;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

mod visibility;

const ACTOR: PrincipalId = PrincipalId::from_bytes([0x3d; 16]);

struct Fixture {
    root: PathBuf,
    config: NodeConfig,
    node: Option<OneNode>,
    reference: RefName,
    commit: GitOid,
    tree: GitOid,
    parents: Vec<GitOid>,
    body: Vec<u8>,
}

fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, body);
    let raw = [
        format!("{} {}\0", kind.label(), body.len()).as_bytes(),
        body,
    ]
    .concat();
    let mut encoded = vec![0x78, 0x01];
    let blocks = raw.chunks(usize::from(u16::MAX));
    let count = blocks.len();
    for (index, block) in blocks.enumerate() {
        let length = u16::try_from(block.len()).unwrap();
        encoded.push(u8::from(index + 1 == count));
        encoded.extend(length.to_le_bytes());
        encoded.extend((!length).to_le_bytes());
        encoded.extend_from_slice(block);
    }
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521;
        (a, (b + a) % 65_521)
    });
    encoded.extend(((b << 16) | a).to_be_bytes());
    let text = id.to_string();
    let directory = root.join("objects").join(&text[..2]);
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join(&text[2..]), encoded).unwrap();
    id
}

impl Fixture {
    fn new(format: GitHashAlgorithm, commits: usize, body_bytes: Option<usize>) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "fg-current-commit-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let git = root.join("source");
        fs::create_dir_all(git.join("refs/heads")).unwrap();
        fs::create_dir_all(git.join("refs/tags")).unwrap();
        fs::write(git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(git.join("config"), match format {
            GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
            GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
        }).unwrap();
        let tree = loose(&git, format, GitObjectKind::Tree, b"");
        let mut commit = None;
        let mut parents = Vec::new();
        let mut body = Vec::new();
        for index in 0..commits {
            parents = commit.into_iter().collect();
            let parent = commit.map_or_else(String::new, |id| format!("parent {id}\n"));
            body = format!(
                "tree {tree}\n{parent}author Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\ngpgsig opaque\n continued\n\ncommit {index}\n"
            ).into_bytes();
            body.extend_from_slice(b"untrusted \0\xff\r\n");
            if let Some(bytes) = body_bytes {
                assert!(body.len() <= bytes);
                body.resize(bytes, b'x');
            }
            commit = Some(loose(&git, format, GitObjectKind::Commit, &body));
        }
        let commit = commit.unwrap();
        fs::write(git.join("refs/heads/main"), format!("{commit}\n")).unwrap();
        fs::write(git.join("refs/tags/tree"), format!("{tree}\n")).unwrap();
        let config = NodeConfig::new(
            root.join("node"),
            TenantId::from_bytes([0x3b; 16]),
            RepositoryId::from_bytes([0x3c; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(2);
        let (mut node, _) = OneNode::init(config.clone()).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let imported = node
            .runtime()
            .block_on(node.import_loose_git_directory_durable_in(
                &node.outbox_delivery_context(),
                &git,
                ACTOR,
                b"current-commit-fixture",
            ))
            .unwrap();
        assert!(
            imported.commands.iter().all(|command| matches!(
                command.terminal.outcome,
                DecisionOutcome::Committed { .. }
            ))
        );
        Self {
            root,
            config,
            node: Some(node),
            reference: RefName::try_new(b"refs/heads/main").unwrap(),
            commit,
            tree,
            parents,
            body,
        }
    }

    fn node(&self) -> &OneNode {
        self.node.as_ref().unwrap()
    }

    fn head(&self) -> RepositoryAuthorityHeadId {
        let node = self.node();
        node.runtime()
            .block_on(node.materialize_admission_in(&node.request_context()))
            .unwrap()
            .basis()
            .id()
    }

    fn read(&self) -> Result<SourceCommitReport, NodeWorkspaceRefusal> {
        let node = self.node();
        node.runtime().block_on(node.read_source_commit_local_in(
            &node.request_context(),
            &self.reference,
            None,
            Some(self.commit),
        ))
    }

    fn reopen(&mut self) {
        self.node.take().unwrap().shutdown().unwrap();
        let mut node = OneNode::open_existing(self.config.clone()).unwrap();
        let generation = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap()
            .receipt()
            .generation();
        node.bring_into_service(generation).unwrap();
        self.node = Some(node);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(node) = self.node.take() {
            node.shutdown().unwrap();
        }
        if !std::thread::panicking() {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }
}

#[test]
fn current_commit_preserves_exact_native_bytes_pins_and_parent_order_after_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut fixture = Fixture::new(format, 2, None);
        let head = fixture.head();
        let report = fixture.read().unwrap();
        assert_eq!(report.repository_id, fixture.node().repository_id());
        assert_eq!(report.source_head, head);
        assert_eq!(report.source_commit, fixture.commit);
        assert_eq!(report.root_tree, fixture.tree);
        assert_eq!(report.parents, fixture.parents);
        assert_eq!(report.body, fixture.body);
        assert_eq!(
            git_object_id(format, GitObjectKind::Commit, &report.body),
            fixture.commit
        );
        assert_eq!(fixture.head(), head);
        fixture.reopen();
        assert_eq!(fixture.read().unwrap(), report);
    }
}

#[test]
fn current_tip_read_does_not_require_a_bounded_history_walk() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256, 4097, None);
    let node = fixture.node();
    let head = fixture.head();
    let history = node.runtime().block_on(node.read_commit_history_in(
        &node.outbox_delivery_context(),
        &fixture.reference,
        &RefVisibility::new(),
        Some(head),
        LogOptions {
            limit: 1,
            ..LogOptions::default()
        },
    ));
    assert!(matches!(
        history
            .as_ref()
            .err()
            .and_then(|cause| cause.history_error()),
        Some(HistoryError::Budget(_))
    ));
    let report = fixture.read().unwrap();
    assert_eq!(report.source_head, head);
    assert_eq!(report.body, fixture.body);
    assert_eq!(report.parents, fixture.parents);
    assert_eq!(fixture.head(), head);
}

#[test]
fn selected_commit_rejects_other_objects_missing_refs_cancellation_and_stale_head() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format, 2, None);
        let node = fixture.node();
        let head = fixture.head();
        let read = |reference: &RefName, expected| {
            node.runtime().block_on(node.read_source_commit_local_in(
                &node.request_context(),
                reference,
                None,
                expected,
            ))
        };
        for expected in [fixture.tree, fixture.parents[0]] {
            assert!(matches!(read(&fixture.reference, Some(expected)),
                Err(NodeWorkspaceRefusal::SourceBrowse(cause))
                if matches!(*cause, SourceBrowseError::CommitMoved)));
        }
        assert!(matches!(
            read(&RefName::try_new(b"refs/heads/missing").unwrap(), None),
            Err(NodeWorkspaceRefusal::RefUnavailable)
        ));
        assert!(matches!(
            read(&RefName::try_new(b"refs/tags/tree").unwrap(), None),
            Err(NodeWorkspaceRefusal::CommitRequired)
        ));
        let wrong_format = match format {
            GitHashAlgorithm::Sha1 => GitHashAlgorithm::Sha256,
            GitHashAlgorithm::Sha256 => GitHashAlgorithm::Sha1,
        };
        let wrong = git_object_id(wrong_format, GitObjectKind::Commit, &fixture.body);
        assert!(matches!(read(&fixture.reference, Some(wrong)),
            Err(NodeWorkspaceRefusal::SourceBrowse(cause))
            if matches!(*cause, SourceBrowseError::InvalidRequest(_))));
        let cancelled = node.request_context();
        cancelled.cancel();
        for request in [
            cancelled,
            node.session_request_context_with_timeout(Duration::ZERO),
        ] {
            assert!(matches!(
                node.runtime().block_on(node.read_source_commit_local_in(
                    &request,
                    &fixture.reference,
                    None,
                    None,
                )),
                Err(NodeWorkspaceRefusal::Cancelled { .. })
            ));
        }
        assert_eq!(fixture.head(), head);
        let command = RefCommand {
            name: RefName::try_new(b"refs/heads/metadata-only-move").unwrap(),
            expected_old: ExpectedOld::Absent,
            proposed_new: ProposedNew::Update(fixture.commit),
            force: false,
        };
        let session = LoopbackReceiveSession::authenticated(
            ACTOR,
            IdempotencyKey::new(b"commit-test-head-move".to_vec()).unwrap(),
        );
        let update = node
            .runtime()
            .block_on(node.admit_branch_updates_durable_in(
                &node.request_context(),
                &session,
                &[command],
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            update.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert!(
            matches!(node.runtime().block_on(node.read_source_commit_local_in(
            &node.request_context(), &fixture.reference, Some(head), Some(fixture.commit),
        )), Err(NodeWorkspaceRefusal::SourceBrowse(cause))
            if matches!(*cause, SourceBrowseError::SnapshotMoved))
        );
        assert_eq!(fixture.read().unwrap().source_commit, fixture.commit);
    }
}

#[test]
fn complete_commit_body_ceiling_is_exact_in_both_native_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for bytes in [MAX_SOURCE_COMMIT_BYTES, MAX_SOURCE_COMMIT_BYTES + 1] {
            let fixture = Fixture::new(format, 1, Some(bytes));
            let head = fixture.head();
            if bytes == MAX_SOURCE_COMMIT_BYTES {
                assert_eq!(fixture.read().unwrap().body, fixture.body);
            } else {
                assert!(
                    matches!(fixture.read(), Err(NodeWorkspaceRefusal::SourceBrowse(cause))
                    if matches!(*cause, SourceBrowseError::Budget("current commit bytes")))
                );
            }
            assert_eq!(fixture.head(), head);
        }
    }
}

#[test]
fn imported_commit_metadata_requires_unambiguous_native_edges() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let tree = git_object_id(format, GitObjectKind::Tree, b"");
        let first = git_object_id(format, GitObjectKind::Commit, b"first");
        let second = git_object_id(format, GitObjectKind::Commit, b"second");
        let body = format!("tree {tree}\nparent {second}\nparent {first}\n\nmessage\n");
        assert_eq!(
            commit_metadata(format, body.as_bytes()).unwrap(),
            (tree, vec![second, first])
        );
        for body in [
            format!("tree {tree}\ntree {tree}\n\nambiguous\n"),
            format!("tree {tree}\n continued\n\nambiguous\n"),
            format!("tree {tree}\nparent {first}\n continued\n\nambiguous\n"),
            format!(
                "tree {tree}\nparent {}\n\nzero\n",
                "0".repeat(format.digest_len() * 2)
            ),
            format!("tree {tree}\nparent not-an-object\n\ninvalid\n"),
        ] {
            assert!(matches!(
                commit_metadata(format, body.as_bytes()),
                Err(NodeWorkspaceRefusal::CommitRequired)
            ));
        }
    }
}
