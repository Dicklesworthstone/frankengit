//! Real embedded authority/source fixtures; read faults change one exact
//! immutable read and never manufacture an accepted publication.

use super::super::{LatestRefChange, latest_change_at};
use crate::{FsqliteCx, LoopbackReceiveSession, MaterializedAdmission, NodeConfig, OneNode};
use fgit_admission::AdmissionLimits;
use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityLimits,
    AuthorityVersionToken, CasOutcome, ExpectedOld, HeadInit, HeadKey, HeadRead,
    HeadReadReceipt, IdempotencyKey, ImmutableKey, ImmutableRead, ProposedNew, PutOutcome,
    RefCommand, StoreInstanceId,
};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RefName,
    RepositoryId, TenantId,
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

pub(super) struct Scratch(PathBuf);

impl Scratch {
    pub(super) fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-workflow-ref-selection-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    pub(super) fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(
            self.0.join("node"),
            TenantId::from_bytes([0xc1; 16]),
            RepositoryId::from_bytes([0xc2; 16]),
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

pub(super) fn reference(text: &str) -> RefName {
    RefName::try_new(text.as_bytes()).unwrap()
}

fn principal() -> PrincipalId {
    PrincipalId::from_bytes([0xc3; 16])
}

fn loose(
    root: &Path,
    format: GitHashAlgorithm,
    kind: GitObjectKind,
    label: &str,
    body: &[u8],
) -> GitOid {
    let id = git_object_id(format, kind, body);
    let raw = [format!("{label} {}\0", body.len()).as_bytes(), body].concat();
    let length = u16::try_from(raw.len()).unwrap();
    let mut encoded = vec![0x78, 0x01, 0x01];
    encoded.extend(length.to_le_bytes());
    encoded.extend((!length).to_le_bytes());
    encoded.extend(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), value| {
        let a = (a + u32::from(*value)) % 65521;
        (a, (b + a) % 65521)
    });
    encoded.extend(((b << 16) | a).to_be_bytes());
    let text = id.to_string();
    let directory = root.join("objects").join(&text[..2]);
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join(&text[2..]), encoded).unwrap();
    id
}

pub(super) fn fixture(scratch: &Scratch, format: GitHashAlgorithm) -> (OneNode, GitOid, GitOid) {
    let (mut node, _) = OneNode::init(scratch.config(format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let root = scratch.0.join("source");
    fs::create_dir_all(root.join("refs/heads")).unwrap();
    fs::write(root.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    let config = match format {
        GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
        GitHashAlgorithm::Sha256 => {
            "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n"
        }
    };
    fs::write(root.join("config"), config).unwrap();
    let blob = loose(
        &root,
        format,
        GitObjectKind::Blob,
        "blob",
        b"selection fixture\n",
    );
    let tree = loose(
        &root,
        format,
        GitObjectKind::Tree,
        "tree",
        &[b"100644 file\0".as_slice(), blob.as_bytes()].concat(),
    );
    let base = loose(
        &root,
        format,
        GitObjectKind::Commit,
        "commit",
        format!(
            "tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nbase\n"
        )
        .as_bytes(),
    );
    let child = loose(
        &root,
        format,
        GitObjectKind::Commit,
        "commit",
        format!(
            "tree {tree}\nparent {base}\nauthor Fixture <fixture@example.invalid> 2 +0000\ncommitter Fixture <fixture@example.invalid> 2 +0000\n\nchild\n"
        )
        .as_bytes(),
    );
    fs::write(root.join("refs/heads/main"), format!("{child}\n")).unwrap();
    let request = node.request_context();
    let imported = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &request,
            &root,
            principal(),
            b"workflow-ref-selection-fixture",
        ))
        .unwrap();
    assert!(
        imported
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    (node, base, child)
}

pub(super) fn apply(
    node: &OneNode,
    key: &str,
    name: &str,
    old: Option<GitOid>,
    new: Option<GitOid>,
) {
    let session = LoopbackReceiveSession::authenticated(
        principal(),
        IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
    );
    let command = RefCommand {
        name: reference(name),
        expected_old: old.map_or(ExpectedOld::Absent, ExpectedOld::Exactly),
        proposed_new: new.map_or(ProposedNew::Delete, ProposedNew::Update),
        force: false,
    };
    let request = node.request_context();
    let result = node
        .runtime()
        .block_on(node.admit_branch_updates_durable_in(
            &request,
            &session,
            &[command],
            AdmissionLimits::default(),
        ))
        .unwrap();
    assert!(result.session.atomic);
    assert_eq!(result.commands.len(), 1);
    assert!(matches!(
        result.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
}

pub(super) fn selected(node: &OneNode) -> MaterializedAdmission {
    let request = node.request_context();
    node.runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap()
}

pub(super) fn select(node: &OneNode, name: &str, tip: GitOid) -> LatestRefChange {
    let request = node.request_context();
    let state = selected(node);
    node.runtime()
        .block_on(latest_change_at(
            &node.authority,
            request.authority(),
            state.basis(),
            &reference(name),
            tip,
            fgit_authority::MAX_REPLAY_BATCHES,
            &|| false,
        ))
        .unwrap()
}

/// This independent oracle is the previous full-history watch selection.
pub(super) fn oracle(node: &OneNode, name: &str) -> LatestRefChange {
    let request = node.request_context();
    let history = node
        .runtime()
        .block_on(node.snapshot_history_in(&request))
        .unwrap();
    let name = reference(name);
    let mut changes = history.iter().rev().filter_map(|batch| {
        batch
            .ref_updates
            .iter()
            .find(|(reference, _)| reference == name.as_bytes())
            .map(|(_, tip)| (batch, *tip))
    });
    let (event, tip) = changes.next().unwrap();
    assert!(tip.is_some(), "the current watch tip must exist");
    LatestRefChange {
        previous_tip: changes.next().and_then(|(_, tip)| tip),
        batch_id: event.batch_id,
        resulting_head_id: event.resulting_head_id,
    }
}

#[derive(Clone, Copy)]
pub(super) enum Fault {
    Absent,
    Corrupt,
}

pub(super) struct ReadProbe<'a> {
    node: &'a OneNode,
    target: Option<(ImmutableKey, Fault)>,
    pub(super) reads: AtomicUsize,
    pub(super) fired: AtomicBool,
}

impl<'a> ReadProbe<'a> {
    pub(super) fn new(node: &'a OneNode, target: Option<(ImmutableKey, Fault)>) -> Self {
        Self {
            node,
            target,
            reads: AtomicUsize::new(0),
            fired: AtomicBool::new(false),
        }
    }
}

impl AsyncAuthorityStore for ReadProbe<'_> {
    type Context = FsqliteCx;

    fn instance_id(&self) -> StoreInstanceId {
        AsyncAuthorityStore::instance_id(&self.node.authority)
    }

    fn limits(&self) -> AuthorityLimits {
        AsyncAuthorityStore::limits(&self.node.authority)
    }

    async fn read_immutable(
        &self,
        cx: &FsqliteCx,
        key: &ImmutableKey,
    ) -> Result<ImmutableRead, AuthorityFailure> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if let Some((target, fault)) = &self.target
            && key == target
        {
            self.fired.store(true, Ordering::SeqCst);
            return Ok(match fault {
                Fault::Absent => ImmutableRead::Absent,
                Fault::Corrupt => ImmutableRead::Present(b"corrupt canonical ref history".to_vec()),
            });
        }
        AsyncAuthorityStore::read_immutable(&self.node.authority, cx, key).await
    }

    async fn put_if_absent(
        &self,
        _: &FsqliteCx,
        _: &ImmutableKey,
        _: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        panic!("ref selection must not write immutable objects")
    }

    async fn initialize_head(
        &self,
        _: &FsqliteCx,
        _: &HeadKey,
        _: HeadGeneration,
        _: &[u8],
    ) -> Result<HeadInit, AuthorityFailure> {
        panic!("ref selection must not initialize authority")
    }

    async fn read_head(&self, cx: &FsqliteCx, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        AsyncAuthorityStore::read_head(&self.node.authority, cx, key).await
    }

    async fn compare_exchange_head(
        &self,
        _: &FsqliteCx,
        _: &HeadKey,
        _: AuthorityVersionToken,
        _: HeadGeneration,
        _: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        panic!("ref selection must not publish authority")
    }

    async fn authenticate_head_receipt(
        &self,
        cx: &FsqliteCx,
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure> {
        AsyncAuthorityStore::authenticate_head_receipt(&self.node.authority, cx, receipt).await
    }
}
