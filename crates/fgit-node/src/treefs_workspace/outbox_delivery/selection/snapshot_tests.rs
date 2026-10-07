//! Complete snapshot and claim observations use persisted canonical authority.
use super::*;
use crate::{LoopbackReceiveSession, NodeConfig};
use fgit_authority::IdempotencyKey;
use fgit_forge::event::issue::{IssueAction, IssueCommand};
use fgit_forge::{ExpectedVersion, IssueNumber};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, HeadGeneration, PrincipalId, RepositoryId, TenantId};
use std::{fs, path::PathBuf, sync::atomic::{AtomicU64, Ordering}};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-outbox-snapshot-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(self.0.join("node"), TenantId::from_bytes([0xe1; 16]), RepositoryId::from_bytes([0xe2; 16]))
            .with_object_format(format).with_worker_threads(2)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}
fn publish(node: &OneNode, number: u64) {
    let request = node.outbox_delivery_context();
    let session = LoopbackReceiveSession::authenticated(PrincipalId::from_bytes([0xe3; 16]),
        IdempotencyKey::new(format!("snapshot-issue-{number}").into_bytes()).unwrap());
    let command = IssueCommand {
        number: IssueNumber::try_new(number).unwrap(), expected_version: ExpectedVersion::NewStream,
        action: IssueAction::Open { title: format!("Issue {number}"), body: "Canonical event".into(), labels: vec![] },
    };
    let (_, terminal) = node.runtime().block_on(node.admit_issue_durable_in(
        &request, &session, &command, Default::default(),
    )).unwrap();
    assert!(matches!(terminal.outcome, DecisionOutcome::Committed { .. }));
}
fn snapshot(node: &OneNode, maximum: usize, head: Option<RepositoryAuthorityHeadId>)
    -> Result<ForgeOutboxPage, ForgeDeliveryReadRefusal>
{
    let request = node.outbox_delivery_context();
    node.runtime().block_on(node.read_forge_outbox_snapshot_in(&request, maximum, head))
}

#[test]
fn complete_snapshot_refuses_small_limits_and_stale_pins_in_both_hash_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (mut node, _) = OneNode::init(scratch.config(format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let empty = snapshot(&node, 1, None).unwrap();
        assert!(empty.entries.is_empty() && empty.next_after.is_none());
        for maximum in [0, fgit_codec::MAX_OUTBOX_STATE_ENTRIES + 1] {
            assert!(matches!(snapshot(&node, maximum, None), Err(ForgeDeliveryReadRefusal::InvalidLimit)));
        }
        publish(&node, 1);
        publish(&node, 2);
        assert!(matches!(snapshot(&node, 1, None), Err(ForgeDeliveryReadRefusal::BudgetExceeded)));
        assert!(matches!(snapshot(&node, 2, Some(empty.source_head)), Err(ForgeDeliveryReadRefusal::SnapshotMoved)));
        let complete = snapshot(&node, 2, None).unwrap();
        assert_eq!(complete.entries.len(), 2);
        assert!(complete.next_after.is_none());
        assert_ne!(complete.entries[0].delivery_key(), complete.entries[1].delivery_key());
        let again = snapshot(&node, 2, Some(complete.source_head)).unwrap();
        assert_eq!(again.source_head, complete.source_head);
        assert_eq!(again.entries, complete.entries);
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        let restored = snapshot(&reopened, 2, Some(complete.source_head)).unwrap();
        assert_eq!(restored.entries, complete.entries);
        reopened.shutdown().unwrap();
    }
}

#[test]
fn ownership_observation_neither_claims_delivery_nor_changes_original_payload() {
    let scratch = Scratch::new();
    let (mut node, _) = OneNode::init(scratch.config(GitHashAlgorithm::Sha256)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    publish(&node, 1);
    let before = snapshot(&node, 1, None).unwrap();
    let entry = &before.entries[0];
    let request = node.outbox_delivery_context();
    let selected = node.runtime().block_on(node.select_forge_delivery_in(
        &request, entry.delivery_key(), entry.destination(), Some(before.source_head),
    )).unwrap();
    assert!(selected.is_unclaimed());
    assert_eq!(selected.entry(), entry);
    assert_eq!(selected.source_head(), before.source_head);
    assert_eq!(fgit_admission::evidence::evidence_root(selected.as_request().events).unwrap(), entry.payload_root());
    let after = snapshot(&node, 1, Some(before.source_head)).unwrap();
    assert_eq!(after.entries, before.entries);
    node.shutdown().unwrap();
}
