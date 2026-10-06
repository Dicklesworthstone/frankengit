//! Real persisted-node inspection and publication; not an in-memory authority.
use super::*;
use crate::{LoopbackReceiveSession, NodeConfig};
use fgit_authority::IdempotencyKey;
use fgit_types::{DecisionOutcome, HeadGeneration, PrincipalId, RepositoryId, TenantId};
use std::{fs, path::PathBuf, sync::atomic::{AtomicU64, Ordering}};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture { root: PathBuf, format: GitHashAlgorithm, node: Option<OneNode> }
impl Fixture {
    fn new(format: GitHashAlgorithm) -> Self {
        let root = std::env::temp_dir().join(format!("fg-initial-inspection-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&root).unwrap();
        let mut fixture = Self { root, format, node: None };
        let (mut node, _) = OneNode::init(fixture.config()).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        fixture.node = Some(node);
        fixture
    }
    fn config(&self) -> NodeConfig {
        NodeConfig::new(self.root.join("node"), TenantId::from_bytes([0xc1; 16]), RepositoryId::from_bytes([0xc2; 16]))
            .with_object_format(self.format).with_worker_threads(2)
    }
    fn node(&self) -> &OneNode { self.node.as_ref().unwrap() }
    fn head(&self) -> (RepositoryAuthorityHeadId, Vec<u8>) {
        let read = self.node().runtime().block_on(self.node().authenticate_authority_head()).unwrap();
        (fgit_authority::authority_head_identity(&read.body().unwrap()).unwrap(), read.receipt().body().to_vec())
    }
    fn inspect(&self, id: GitOid, bytes: &[u8], pin: Option<RepositoryAuthorityHeadId>)
        -> Result<(RepositoryAuthorityHeadId, InitialCommitInspection), NodeWorkspaceRefusal>
    {
        let node = self.node();
        let request = node.request_context();
        node.runtime().block_on(node.inspect_initial_patch_bundle_in(
            &request, &reference(), id, bytes, &RefVisibility::new(), pin, Default::default(),
        ))
    }
    fn apply(&self, id: GitOid, bytes: &[u8], key: &[u8])
        -> Result<fgit_admission::AdmissionResult, NodeWorkspaceRefusal>
    {
        let node = self.node();
        let request = node.request_context();
        node.runtime().block_on(node.apply_initial_patch_bundle_durable_in(
            &request, &session(key), &reference(), id, bytes, Default::default(),
        ))
    }
    fn reopen(&mut self) {
        self.node.take().unwrap().shutdown().unwrap();
        let mut node = OneNode::open_existing(self.config()).unwrap();
        let head = node.runtime().block_on(node.authenticate_authority_head()).unwrap();
        node.bring_into_service(head.receipt().generation()).unwrap();
        self.node = Some(node);
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(node) = self.node.take() { node.shutdown().unwrap(); }
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn actor(byte: u8) -> PrincipalId { PrincipalId::from_bytes([byte; 16]) }
fn session(key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(actor(1), IdempotencyKey::new(key.to_vec()).unwrap())
}

#[test]
fn actual_uploaded_root_inspection_is_unstaged_and_publication_recovers_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format);
        let (id, _, objects) = fixture(format);
        let bytes = bundle(format, id, &objects);
        let before = f.head();
        let (head, report) = f.inspect(id, &bytes, Some(before.0)).unwrap();
        assert_eq!(head, before.0);
        assert_eq!(report, inspect(format, id, &bytes, Default::default()).unwrap());
        assert_eq!(f.head(), before);
        for (kind, body) in &objects {
            assert!(f.node().read_git_object(git_object_id(format, *kind, body)).is_err());
        }
        f.reopen();
        assert_eq!(f.inspect(id, &bytes, Some(before.0)).unwrap().1, report);
        let published = f.apply(id, &bytes, b"reviewed-root").unwrap();
        assert!(matches!(published.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        let after = f.head();
        assert_ne!(after, before);
        assert!(f.inspect(id, &bytes, None).is_err(), "inspection still requires current branch absence");
        f.reopen();
        assert_eq!(f.apply(id, &bytes, b"reviewed-root").unwrap(), published);
        assert_eq!(f.head(), after);
        for (kind, body) in &objects {
            assert_eq!(f.node().read_git_object(git_object_id(format, *kind, body)).unwrap().payload(), body.as_slice());
        }
    }
}

#[test]
fn rejected_inspection_and_failed_new_publication_neither_stage_nor_move_authority() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format);
        let (id, _, objects) = fixture(format);
        let bytes = bundle(format, id, &objects);
        let before = f.head();
        let mut broken = objects.clone();
        broken[0] = (GitObjectKind::Blob, b"same count, different blob".to_vec());
        let malformed = bundle(format, id, &broken);
        assert!(f.inspect(id, &malformed, None).is_err());
        assert!(f.apply(id, &malformed, b"malformed").is_err());
        for (kind, body) in &broken {
            assert!(f.node().read_git_object(git_object_id(format, *kind, body)).is_err());
        }
        let node = f.node();
        let request = node.request_context();
        let mut hidden = RefVisibility::new();
        hidden.push_rule(b"refs/heads/main", &fgit_wire::WireLimits::default()).unwrap();
        assert!(matches!(node.runtime().block_on(node.inspect_initial_patch_bundle_in(
            &request, &reference(), id, &bytes, &hidden, None, Default::default(),
        )), Err(NodeWorkspaceRefusal::RefUnavailable)));
        request.authority().cancel();
        assert!(node.runtime().block_on(node.inspect_initial_patch_bundle_in(
            &request, &reference(), id, &bytes, &RefVisibility::new(), None, Default::default(),
        )).is_err());
        assert_eq!(f.head(), before);
        assert!(f.inspect(id, &bytes, Some(before.0)).is_ok());
    }
}

#[test]
fn successful_inspection_grants_no_branch_protection_exception_and_pins_remain_strict() {
    use fgit_forge::aggregate::ExpectedVersion;
    use fgit_forge::event::protection::{ProtectedBranch, ProtectionCommand, ReviewProtection};
    use fgit_types::PolicyEpoch;
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format);
        let (id, _, objects) = fixture(format);
        let bytes = bundle(format, id, &objects);
        let before = f.head();
        let node = f.node();
        let request = node.request_context();
        let policy = node.runtime().block_on(node.admit_review_protection_durable_in(
            &request, &session(b"protect"),
            &ProtectionCommand {
                expected_version: ExpectedVersion::NewStream, expected_epoch: PolicyEpoch::FIRST,
                protection: ReviewProtection {
                    administrators: vec![actor(1)],
                    branches: vec![ProtectedBranch { name: reference(), reviewers: vec![actor(3)] }],
                },
            }, Default::default(),
        )).unwrap();
        assert!(matches!(policy.1.outcome, DecisionOutcome::Committed { .. }));
        assert!(f.inspect(id, &bytes, Some(before.0)).is_err());
        let pinned = f.head();
        assert_eq!(f.inspect(id, &bytes, Some(pinned.0)).unwrap().0, pinned.0);
        assert_eq!(f.head(), pinned);
        let refused = f.apply(id, &bytes, b"protected-root").unwrap();
        assert!(matches!(refused.commands[0].terminal.outcome, DecisionOutcome::Refused { .. }));
        assert!(f.inspect(id, &bytes, None).is_ok(), "a refusal is not a branch creation");
        assert_eq!(f.apply(id, &bytes, b"protected-root").unwrap(), refused);
    }
}
