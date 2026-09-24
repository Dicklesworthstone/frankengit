use super::*;
use crate::{LoopbackReceiveSession, NodeConfig};
use fgit_admission::AdmissionLimits;
use fgit_authority::IdempotencyKey;
use fgit_forge::event::issue::{IssueAction, IssueCommand};
use fgit_forge::{ExpectedVersion, IssueNumber};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, HeadGeneration, PrincipalId, RepositoryId, TenantId,
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-outbox-selection-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(
            self.0.join("node"),
            TenantId::from_bytes([0xb1; 16]),
            RepositoryId::from_bytes([0xb2; 16]),
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

fn publish(node: &OneNode, number: u64) {
    let command = IssueCommand {
        number: IssueNumber::try_new(number).unwrap(),
        expected_version: ExpectedVersion::NewStream,
        action: IssueAction::Open {
            title: format!("Canonical issue {number}"),
            body: "a real committed event".into(),
            labels: vec![],
        },
    };
    let session = LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0xb3; 16]),
        IdempotencyKey::new(format!("open-{number}").into_bytes()).unwrap(),
    );
    let request = node.request_context();
    let result = node
        .runtime()
        .block_on(node.admit_issue_durable_in(
            &request,
            &session,
            &command,
            AdmissionLimits::default(),
        ))
        .unwrap();
    assert!(matches!(result.1.outcome, DecisionOutcome::Committed { .. }), "{result:?}");
}

fn page(
    node: &OneNode,
    after: Option<AsciiSlug>,
    limit: u16,
    head: Option<RepositoryAuthorityHeadId>,
) -> Result<ForgeOutboxPage, ForgeDeliveryReadRefusal> {
    let request = node.request_context();
    node.runtime()
        .block_on(node.read_forge_outbox_in(&request, after, limit, head))
}

fn select(
    node: &OneNode,
    key: AsciiSlug,
    destination: AsciiSlug,
    head: Option<RepositoryAuthorityHeadId>,
) -> Result<SelectedForgeDelivery, ForgeDeliveryReadRefusal> {
    let request = node.request_context();
    node.runtime()
        .block_on(node.select_forge_delivery_in(&request, key, destination, head))
}

#[test]
fn selected_payload_is_committed_exact_and_survives_node_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (mut node, _) = OneNode::init(scratch.config(format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        publish(&node, 1);
        let before = page(&node, None, 10, None).unwrap();
        assert_eq!(before.entries.len(), 1);
        let entry = &before.entries[0];
        let selected = select(
            &node,
            entry.delivery_key(),
            entry.destination(),
            Some(before.source_head),
        )
        .unwrap();
        let request = selected.as_request();
        assert_eq!(request.key, entry.delivery_key());
        assert_eq!(request.destination, entry.destination());
        assert_eq!(request.payload_root, entry.payload_root());
        assert_eq!(
            fgit_admission::evidence::evidence_root(request.events).unwrap(),
            entry.payload_root(),
        );
        assert_eq!(request.events.events.len(), 1);
        let bytes = fgit_codec::encode_body(request.events).unwrap();
        assert_eq!(page(&node, None, 10, None).unwrap().source_head, before.source_head);
        node.shutdown().unwrap();

        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        let restored = select(
            &reopened,
            entry.delivery_key(),
            entry.destination(),
            Some(before.source_head),
        )
        .unwrap();
        assert_eq!(restored.source_head(), before.source_head);
        assert_eq!(fgit_codec::encode_body(restored.as_request().events).unwrap(), bytes);
        reopened.shutdown().unwrap();
    }
}

#[test]
fn outbox_pages_are_disjoint_and_stale_pins_refuse_without_empty_success() {
    let scratch = Scratch::new();
    let (mut node, _) = OneNode::init(scratch.config(GitHashAlgorithm::Sha1)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    assert!(page(&node, None, 10, None).unwrap().entries.is_empty());
    publish(&node, 1);
    publish(&node, 2);
    let first = page(&node, None, 1, None).unwrap();
    let after = first.next_after.expect("second entry exists");
    let second = page(&node, Some(after), 1, Some(first.source_head)).unwrap();
    assert_eq!(first.entries.len(), 1);
    assert_eq!(second.entries.len(), 1);
    assert!(first.entries[0].delivery_key() < second.entries[0].delivery_key());
    assert!(second.next_after.is_none());
    publish(&node, 3);
    assert!(matches!(
        page(&node, Some(after), 1, Some(first.source_head)),
        Err(ForgeDeliveryReadRefusal::SnapshotMoved),
    ));
    assert!(matches!(
        select(&node, first.entries[0].delivery_key(), first.entries[0].destination(), Some(first.source_head)),
        Err(ForgeDeliveryReadRefusal::SnapshotMoved),
    ));
    for limit in [0, 101] {
        assert!(matches!(
            page(&node, None, limit, None),
            Err(ForgeDeliveryReadRefusal::InvalidLimit),
        ));
    }
    node.shutdown().unwrap();
}

#[test]
fn missing_or_wrongly_addressed_delivery_cannot_select_event_bytes() {
    let scratch = Scratch::new();
    let (mut node, _) = OneNode::init(scratch.config(GitHashAlgorithm::Sha1)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    publish(&node, 1);
    let before = page(&node, None, 10, None).unwrap();
    let entry = &before.entries[0];
    assert!(matches!(
        select(&node, AsciiSlug::from_static("absent-delivery"), entry.destination(), None),
        Err(ForgeDeliveryReadRefusal::MissingDelivery),
    ));
    assert!(matches!(
        select(&node, entry.delivery_key(), AsciiSlug::from_static("other-destination"), None),
        Err(ForgeDeliveryReadRefusal::DestinationMismatch),
    ));
    assert_eq!(page(&node, None, 10, None).unwrap().source_head, before.source_head);
    node.shutdown().unwrap();
}

#[test]
fn staging_new_event_bytes_does_not_replace_a_canonical_delivery() {
    let scratch = Scratch::new();
    let (mut node, _) = OneNode::init(scratch.config(GitHashAlgorithm::Sha1)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    publish(&node, 1);
    let before = page(&node, None, 10, None).unwrap();
    let entry = &before.entries[0];
    let original = select(&node, entry.delivery_key(), entry.destination(), None).unwrap();
    let original_frame = fgit_codec::encode_body(original.as_request().events).unwrap();
    let mut staged = original.as_request().events.clone();
    staged.events[0].version = fgit_forge::AggregateVersion::try_new(2).unwrap();
    if let fgit_forge::ForgeEventPayload::IssueChangedNative(change) = &mut staged.events[0].payload {
        change.action = IssueAction::Comment { body: "staged but never published".into() };
    } else {
        panic!("fixture must be a native issue event");
    }
    let request = node.request_context();
    node.runtime()
        .block_on(crate::stage_evidence_body_in(
            &node.authority,
            request.authority(),
            node.repository_id,
            ADMISSION_FORGE_EVENT_BATCH_KEY_PREFIX,
            &staged,
            &|| false,
        ))
        .unwrap();
    let selected = select(&node, entry.delivery_key(), entry.destination(), None).unwrap();
    assert_eq!(selected.source_head(), before.source_head);
    assert_eq!(fgit_codec::encode_body(selected.as_request().events).unwrap(), original_frame);
    assert_eq!(selected.entry().payload_root(), entry.payload_root());
    node.shutdown().unwrap();
}
