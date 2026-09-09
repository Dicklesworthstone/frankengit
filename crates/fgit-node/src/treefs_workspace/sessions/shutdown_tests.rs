//! Real node shutdown with private workspace fixtures, testing lease custody.
//! These fixtures do not represent canonical workspace publication.

use std::fs;
use std::path::PathBuf;

use fgit_crypto::GitOid as TypedGitOid;
use fgit_git_object::ParseLimits;
use fgit_treefs::{BaseView, PathPolicy, TreePath};
use fgit_types::{CodecVersion, DigestAlgorithmId, DigestBytes, TenantId};

use super::*;
use crate::{NodeConfig, NodeRefusal};

static NEXT_SCRATCH: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fgit-workspace-shutdown-{}-{}",
            std::process::id(),
            NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("create shutdown fixture directory");
        Self(path)
    }

    fn node(&self) -> OneNode {
        OneNode::init(
            NodeConfig::new(
                self.0.join("node"),
                TenantId::from_bytes([0xa0; 16]),
                fgit_types::RepositoryId::from_bytes([0xa1; 16]),
            )
            .with_worker_threads(2),
        )
        .expect("initialize real authority and runtime")
        .0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove closed shutdown fixture");
    }
}

fn insert_owner(node: &OneNode, byte: u8) -> (WorkspaceId, Arc<AsyncMutex<SessionState<Sha1>>>) {
    let id = WorkspaceId::from_bytes([byte; 16]);
    let tree = TypedGitOid::<Sha1>::of_object(GitObjectKind::Tree, b"");
    let tree_hex: String = tree
        .digest_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let commit = format!(
        "tree {tree_hex}\nauthor Owner <owner@example.test> 1 +0000\ncommitter Owner <owner@example.test> 1 +0000\n\nbase\n"
    );
    // The owner has a real reservation and no pending publication. Its base is
    // fixture data: shutdown must not turn it into authority evidence.
    let base = BaseView::new(
        node.repository_id(),
        RepositoryCommitId::from_digest(
            DigestAlgorithmId::try_new(1).expect("digest algorithm"),
            CodecVersion::new(1, 0),
            DigestBytes::try_new(&[byte; 32]).expect("fixture base digest"),
        ),
        TypedGitOid::of_object(GitObjectKind::Commit, commit.as_bytes()),
        tree,
        ParseLimits::default(),
        PathPolicy::default(),
    );
    let path = TreePath::parse_default(b"file").expect("workspace path");
    let capability = TreeCapability::new(id, node.repository_id(), vec![path.clone()], vec![path]);
    let owner = Arc::new(AsyncMutex::new(
        SessionState::new(base, capability, ExportLimits::default())
            .expect("reserve actual workspace lease"),
    ));
    let entry = Entry {
        token: Arc::new(()),
        principal: PrincipalId::from_bytes([0xa2; 16]),
        reference: RefName::try_new(b"refs/heads/main").expect("reference"),
        visibility: RefVisibility::new(),
        clock_floor: Arc::new(AtomicU64::new(0)),
        session: Session::Sha1(Arc::clone(&owner)),
    };
    assert!(
        node.workspaces
            .slots
            .lock()
            .expect("workspace slots")
            .live
            .insert(id, entry)
            .is_none()
    );
    (id, owner)
}

#[test]
fn cancelled_workspace_shutdown_returns_live_owner_for_fresh_retry() {
    let scratch = Scratch::new();
    let node = scratch.node();
    let (id, owner) = insert_owner(&node, 1);
    let cancelled = node.request_context();
    cancelled.authority().cancel();

    let NodeRefusal::WorkspaceShutdownBlocked(blocked) = node
        .shutdown_with_workspace_context(cancelled)
        .expect_err("cancelled drain must retain node ownership")
    else {
        panic!("workspace cleanup failure must return the node");
    };
    assert!(matches!(
        blocked.cause(),
        NodeWorkspaceRefusal::Cancelled { exhaustion: None }
    ));
    let (node, cause) = (*blocked).into_parts();
    assert!(matches!(
        cause,
        NodeWorkspaceRefusal::Cancelled { exhaustion: None }
    ));
    assert!(
        node.workspaces
            .slots
            .lock()
            .expect("retained slots")
            .live
            .contains_key(&id)
    );
    assert!(!owner.try_lock_owned().expect("retained owner").is_closed());

    node.shutdown().expect("fresh context closes retained node");
    assert!(owner.try_lock_owned().expect("closed owner").is_closed());
}

#[test]
fn shutdown_removes_closed_entry_before_busy_owner_and_retry() {
    let scratch = Scratch::new();
    let node = scratch.node();
    let (first_id, first) = insert_owner(&node, 1);
    let (second_id, second) = insert_owner(&node, 2);
    assert!(
        first_id < second_id,
        "shutdown visits first owner before second"
    );
    let held_second = second.try_lock_owned().expect("hold later owner");

    let NodeRefusal::WorkspaceShutdownBlocked(blocked) = node
        .shutdown()
        .expect_err("locked later owner must retain node ownership")
    else {
        panic!("busy workspace must return the node");
    };
    assert!(matches!(
        blocked.cause(),
        NodeWorkspaceRefusal::WorkspaceBusy
    ));
    let (node, cause) = (*blocked).into_parts();
    assert!(matches!(cause, NodeWorkspaceRefusal::WorkspaceBusy));
    assert_eq!(
        node.workspaces
            .slots
            .lock()
            .expect("remaining workspace slots")
            .live
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        vec![second_id],
        "successful close removes only the earlier entry"
    );
    assert!(first.try_lock_owned().expect("earlier owner").is_closed());
    assert!(!held_second.is_closed(), "busy owner keeps its reservation");
    drop(held_second);

    node.shutdown()
        .expect("released owner permits shutdown retry");
    assert!(second.try_lock_owned().expect("later owner").is_closed());
}
