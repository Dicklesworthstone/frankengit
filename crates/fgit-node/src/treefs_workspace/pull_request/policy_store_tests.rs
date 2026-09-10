//! Real file-backed authority integration. These tests exercise policy staging
//! and reopening, not policy activation or repository-wide ref enforcement.
use fgit_admission::policy_bridge::persisted::{
    PolicyFrame, PolicyStageDisposition, PolicyStoreError, PolicyStoreLimits,
    read_policy_async, stage_policy_async,
};
use fgit_authority::{AsyncAuthorityStore, body_key_for_id};
use fgit_types::{GitHashAlgorithm, HeadGeneration, RepositoryId, TenantId};
use crate::{NodeConfig, OneNode};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fgit-policy-store-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(self.0.join("node"), TenantId::from_bytes([0xd1; 16]),
            RepositoryId::from_bytes([0xd2; 16])).with_object_format(format).with_worker_threads(2)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) { std::fs::remove_dir_all(&self.0).unwrap(); }
}
fn live() -> Result<(), fgit_types::RefusalCode> { Ok(()) }
fn frame(allow: bool) -> PolicyFrame {
    PolicyFrame::compile(if allow { "policy durable { default allow }" }
        else { "policy durable { default deny \"review required\" }" }, PolicyStoreLimits::default(), &live).unwrap()
}

#[test]
fn compiled_policies_survive_node_reopen_without_publishing_repository_state() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (mut node, _) = OneNode::init(scratch.config(format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let frame = frame(false);
        let before = {
            let request = node.request_context();
            let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
            let first = node.runtime().block_on(stage_policy_async(&node.authority, request.authority(), &frame, &live)).unwrap();
            assert_eq!(first.id, frame.id());
            assert_eq!(first.disposition, PolicyStageDisposition::Created);
            let repeat = node.runtime().block_on(stage_policy_async(&node.authority, request.authority(), &frame, &live)).unwrap();
            assert_eq!(repeat.disposition, PolicyStageDisposition::IdenticalRetry);
            let loaded = node.runtime().block_on(read_policy_async(&node.authority, request.authority(),
                frame.id(), PolicyStoreLimits::default(), &live)).unwrap();
            assert_eq!(loaded.encode().unwrap(), frame.bytes());
            let after = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
            assert_eq!(after.basis(), before.basis(), "storing a policy is not policy activation");
            before.basis().id()
        };
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        {
            let request = reopened.request_context();
            let loaded = reopened.runtime().block_on(read_policy_async(&reopened.authority, request.authority(),
                frame.id(), PolicyStoreLimits::default(), &live)).unwrap();
            assert_eq!(loaded.id(), frame.id());
            assert_eq!(loaded.encode().unwrap(), frame.bytes());
            let snapshot = reopened.runtime().block_on(reopened.materialize_admission_in(&request)).unwrap();
            assert_eq!(snapshot.basis().id(), before);
        }
        reopened.shutdown().unwrap();
    }
}

#[test]
fn file_backed_wrong_slots_and_cancelled_reads_cannot_return_a_policy() {
    let scratch = Scratch::new();
    let (mut node, _) = OneNode::init(scratch.config(GitHashAlgorithm::Sha256)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    {
        let request = node.request_context();
        let deny = frame(false); let allow = frame(true);
        let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        let key = body_key_for_id(deny.id().as_internal_object_id()).unwrap();
        node.runtime().block_on(node.authority.put_if_absent(request.authority(), &key, allow.bytes())).unwrap();
        assert!(matches!(node.runtime().block_on(read_policy_async(&node.authority, request.authority(),
            deny.id(), PolicyStoreLimits::default(), &live)), Err(PolicyStoreError::IdentityMismatch { .. })));
        assert!(matches!(node.runtime().block_on(stage_policy_async(&node.authority, request.authority(), &deny, &live)),
            Err(PolicyStoreError::ConflictingSlot { .. })));
        node.runtime().block_on(stage_policy_async(&node.authority, request.authority(), &allow, &live)).unwrap();
        let count = AtomicUsize::new(0);
        let stop_after_read = || if count.fetch_add(1, Ordering::Relaxed) == 0 { Ok(()) }
            else { Err(fgit_types::RefusalCode::CancellationInProgress) };
        assert!(matches!(node.runtime().block_on(read_policy_async(&node.authority, request.authority(),
            allow.id(), PolicyStoreLimits::default(), &stop_after_read)),
            Err(PolicyStoreError::Stopped(fgit_types::RefusalCode::CancellationInProgress))));
        assert_eq!(count.load(Ordering::Relaxed), 2);
        let after = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        assert_eq!(after.basis(), before.basis());
    }
    node.shutdown().unwrap();
}
