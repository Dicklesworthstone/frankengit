#![forbid(unsafe_code)]
//! Real embedded-node native merge publication; no fake authority or Git engine.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_admission::merge::native::settlement::{DeliveryRequest, OutboxDestination};
use fgit_admission::merge::native::{
    NativeMergeIntent,
    objects::{MergeObjectLimits, validate_merge_objects},
};
use fgit_admission::{AdmissionError, AdmissionLimits};
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_codec::{
    CanonicalForgePositionState, ForgePositionStateEntry, CanonicalOutboxEffectState,
    CanonicalOutboxState, CanonicalOutboxStateEntry, OutboxDeliveryIdentityInput,
    derive_outbox_delivery_key,
};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::aggregate::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_forge::event::{ForgeEventBatch, ForgeEventPayload, NativeMerge};
use fgit_git_object::ObjectType;
use fgit_node::{LoopbackReceiveSession, NodeConfig, NodeReceiveTransportRefusal, OneNode};
use fgit_object_fabric::ObjectKind;
use fgit_pack::{CanonicalObjectSource, CanonicalPackObject, PackWriteError};
use fgit_resource::settlement::{DeliveryVerdict, ProbeVerdict};
use fgit_resource::{DownstreamIdempotency, ObligationState, ReconcilePolicy};
use fgit_types::{
    AsciiSlug, DecisionOutcome, Digest, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId,
    RefName, RefusalCode, RepositoryCommitId, RepositoryId, TenantId, TxId,
};
use fsqlite_types::cx::Cx;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("fgit-native-merge-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
}
impl Drop for Scratch { fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); } }
fn repository() -> RepositoryId { RepositoryId::from_bytes([0x81; 16]) }
fn config(root: &Path, format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(root.join("node"), TenantId::from_bytes([0x80; 16]), repository()).with_object_format(format)
}
fn session(key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(PrincipalId::from_bytes([0x82; 16]), IdempotencyKey::new(key.to_vec()).unwrap())
}
fn main_ref() -> RefName { RefName::try_new(b"refs/heads/main").unwrap() }
fn topic_ref() -> RefName { RefName::try_new(b"refs/heads/topic").unwrap() }

fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, label: &str, body: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, body);
    let raw = [format!("{label} {}\0", body.len()).as_bytes(), body].concat();
    let length = u16::try_from(raw.len()).unwrap();
    let mut zlib = vec![0x78, 0x01, 0x01];
    zlib.extend(length.to_le_bytes()); zlib.extend((!length).to_le_bytes()); zlib.extend(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521; (a, (b + a) % 65_521)
    });
    zlib.extend(((b << 16) | a).to_be_bytes());
    let hex = id.to_string();
    let parent = root.join("objects").join(&hex[..2]); fs::create_dir_all(&parent).unwrap();
    fs::write(parent.join(&hex[2..]), zlib).unwrap();
    id
}
fn tree(entries: &[(&str, GitOid)]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (name, oid) in entries {
        bytes.extend(format!("100644 {name}\0").as_bytes()); bytes.extend(oid.as_bytes());
    }
    bytes
}
fn commit(tree: GitOid, parents: &[GitOid], message: &str) -> Vec<u8> {
    let mut body = format!("tree {tree}\n");
    for parent in parents { body.push_str(&format!("parent {parent}\n")); }
    body.push_str("author Merge Test <merge@example.invalid> 1 +0000\ncommitter Merge Test <merge@example.invalid> 1 +0000\n\n");
    body.push_str(message);
    body.into_bytes()
}
struct Fixture {
    base: GitOid, target: GitOid, source: GitOid, merged_tree: GitOid,
    candidate: GitOid, candidate_body: Vec<u8>,
}

/// Fixture self-checks read the same real fabric objects as native admission.
struct NodeObjects<'a>(&'a OneNode);
impl CanonicalObjectSource for NodeObjects<'_> {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        let object = self.0.read_git_object(*id)
            .map_err(|_| PackWriteError::MissingCanonicalObject(*id))?;
        let kind = match object.envelope().object_kind() {
            ObjectKind::Commit => ObjectType::Commit,
            ObjectKind::Tree => ObjectType::Tree,
            ObjectKind::Blob => ObjectType::Blob,
            ObjectKind::Tag => ObjectType::Tag,
            ObjectKind::Internal => return Err(PackWriteError::MissingCanonicalObject(*id)),
        };
        Ok(CanonicalPackObject::new(object.identity(), kind, object.payload().to_vec(), Vec::new(), 0, 0))
    }
}

fn fixture(node: &OneNode, root: &Path, format: GitHashAlgorithm, stage_commit: bool) -> Fixture {
    let source = root.join("source"); fs::create_dir_all(source.join("refs/heads")).unwrap();
    fs::write(source.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    let configuration = match format {
        GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
        GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
    };
    fs::write(source.join("config"), configuration).unwrap();
    let common = loose(&source, format, GitObjectKind::Blob, "blob", b"common\n");
    let ours = loose(&source, format, GitObjectKind::Blob, "blob", b"ours\n");
    let theirs = loose(&source, format, GitObjectKind::Blob, "blob", b"theirs\n");
    let base_tree = loose(&source, format, GitObjectKind::Tree, "tree", &tree(&[("file.txt", common)]));
    let target_tree = loose(&source, format, GitObjectKind::Tree, "tree", &tree(&[("file.txt", common), ("ours.txt", ours)]));
    let source_tree = loose(&source, format, GitObjectKind::Tree, "tree", &tree(&[("file.txt", common), ("theirs.txt", theirs)]));
    let base = loose(&source, format, GitObjectKind::Commit, "commit", &commit(base_tree, &[], "base\n"));
    let target = loose(&source, format, GitObjectKind::Commit, "commit", &commit(target_tree, &[base], "target\n"));
    let topic = loose(&source, format, GitObjectKind::Commit, "commit", &commit(source_tree, &[base], "topic\n"));
    fs::write(source.join("refs/heads/main"), format!("{target}\n")).unwrap();
    fs::write(source.join("refs/heads/topic"), format!("{topic}\n")).unwrap();
    let request = node.request_context();
    let imported = node.runtime().block_on(node.import_loose_git_directory_durable_in(
        &request, &source, PrincipalId::from_bytes([0x82; 16]), b"native-merge-fixture",
    )).unwrap();
    assert!(imported.commands.iter().all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. })));
    let merged_tree = node.put_git_object(GitObjectKind::Tree, tree(&[("file.txt", common), ("ours.txt", ours), ("theirs.txt", theirs)])).unwrap().identity();
    let candidate_body = commit(merged_tree, &[target, topic], "reviewed merge\n");
    let candidate = git_object_id(format, GitObjectKind::Commit, &candidate_body);
    if stage_commit {
        assert_eq!(node.put_git_object(GitObjectKind::Commit, candidate_body.clone()).unwrap().identity(), candidate);
    }
    let fixture = Fixture { base, target, source: topic, merged_tree, candidate, candidate_body };
    if stage_commit {
        let offered = intent(&fixture, 1, ExpectedVersion::NewStream);
        let closure = validate_merge_objects(
            &NodeObjects(node), offered.merge().unwrap(), MergeObjectLimits::default(), &mut || true,
        ).expect("positive publication fixture must pass native validation before admission");
        assert_eq!(closure.objects, BTreeSet::from([
            common, ours, theirs, base_tree, target_tree, source_tree,
            merged_tree, base, target, topic, candidate,
        ]));
    }
    fixture
}
fn intent(f: &Fixture, number: u64, version: ExpectedVersion) -> NativeMergeIntent {
    NativeMergeIntent::new(PullRequestNumber::try_new(number).unwrap(), version, NativeMerge {
        source_ref: topic_ref(), source_tip: f.source, base_tip: f.base,
        target_ref: main_ref(), target_tip_before: f.target, merge_commit: f.candidate,
    }).unwrap()
}
fn apply(node: &OneNode, offered: &NativeMergeIntent, key: &[u8]) -> Result<TerminalOutcome, NodeReceiveTransportRefusal> {
    let request = node.request_context();
    node.runtime().block_on(node.admit_native_merge_durable_in(
        &request, &session(key), offered, AdmissionLimits::default(), MergeObjectLimits::default(),
    ))
}
fn refs(node: &OneNode) -> BTreeMap<RefName, GitOid> {
    let request = node.request_context();
    node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().snapshot().refs.clone()
}
fn delivery_entry(tx_id: TxId, predecessor: Option<RepositoryCommitId>, payload: Digest) -> CanonicalOutboxStateEntry {
    let class = AsciiSlug::from_static("forge-event");
    let destination = AsciiSlug::from_static("forge-projection");
    let key = derive_outbox_delivery_key(OutboxDeliveryIdentityInput::new(repository(), class,
        destination, payload, tx_id, predecessor)).unwrap();
    let effect = CanonicalOutboxEffectState::committed(repository(), key, tx_id, payload);
    CanonicalOutboxStateEntry::new(key, class, destination, payload, tx_id, predecessor, effect.root().unwrap(), None)
}

#[test]
fn native_merge_publishes_ref_event_frontier_and_outbox_together_and_recovers_after_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (mut node, _) = OneNode::init(config(&scratch.0, format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let f = fixture(&node, &scratch.0, format, true);
        let offered = intent(&f, 1, ExpectedVersion::NewStream);
        let request = node.request_context();
        let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        let old = before.basis().body().clone();
        let terminal = apply(&node, &offered, b"native-merge-1").unwrap();
        let DecisionOutcome::Committed { repository_commit_id } = terminal.outcome else { panic!("permitted merge must commit: {terminal:?}"); };
        let request = node.request_context();
        let after = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        assert_eq!(after.snapshot().refs[&main_ref()], f.candidate);
        assert_eq!(after.snapshot().refs[&topic_ref()], f.source);
        assert_eq!(after.snapshot().head_target, before.snapshot().head_target);
        assert_ne!(after.basis().body().ref_root, old.ref_root);
        assert_ne!(after.basis().body().forge_position_root, old.forge_position_root);
        assert_ne!(after.basis().body().outbox_root, old.outbox_root);
        assert_eq!(after.snapshot().outbox.len(), 1);
        assert_eq!(after.basis().body().retention_root, old.retention_root);
        let history = node.runtime().block_on(node.snapshot_history_in(&request)).unwrap();
        let last = history.last().unwrap();
        assert_eq!(last.forge_events, vec![offered.event().clone()]);
        assert_eq!(last.batch.committed_rcrs.len(), 1);
        let record = &last.batch.committed_rcrs[0];
        assert_eq!(record.resulting_ref_root, after.basis().body().ref_root);
        assert_eq!(record.resulting_forge_position_root, after.basis().body().forge_position_root);
        assert_eq!(after.basis().body().latest_committed_rcr_id, Some(repository_commit_id));
        let event_root = fgit_admission::evidence::evidence_root(&ForgeEventBatch::of_one(offered.event().clone())).unwrap();
        assert_eq!(record.forge_event_batch_root, event_root);
        let first_delivery = delivery_entry(record.tx_id, old.latest_committed_rcr_id, event_root);
        let expected_outbox = CanonicalOutboxState::try_new(repository(), vec![first_delivery]).unwrap();
        assert_eq!(expected_outbox.root().unwrap(), after.basis().body().outbox_root);
        assert_eq!(after.snapshot().outbox.values().next(), Some(&event_root));
        let frontier = CanonicalForgePositionState::try_new(repository(), vec![
            ForgePositionStateEntry::try_new(AsciiSlug::from_static("pull-request/1"), 0, 1, event_root).unwrap(),
        ]).unwrap();
        assert_eq!(frontier.root().unwrap(), record.resulting_forge_position_root);
        node.shutdown().unwrap();

        let mut reopened = OneNode::open_existing(config(&scratch.0, format)).unwrap();
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(apply(&reopened, &offered, b"native-merge-1").unwrap(), terminal);
        assert_eq!(refs(&reopened)[&main_ref()], f.candidate);
        let request = reopened.request_context();
        let retried = reopened.runtime().block_on(reopened.materialize_admission_in(&request)).unwrap();
        assert_eq!(retried.snapshot().outbox.len(), 1, "same retry cannot enqueue twice");
        assert_eq!(retried.basis().body().outbox_root, expected_outbox.root().unwrap());
        let next_body = commit(f.merged_tree, &[f.candidate, f.source], "next reviewed merge\n");
        let next_id = reopened.put_git_object(GitObjectKind::Commit, next_body).unwrap().identity();
        let next_fixture = Fixture { target: f.candidate, candidate: next_id, ..f };
        let next = intent(&next_fixture, 2, ExpectedVersion::NewStream);
        assert!(matches!(apply(&reopened, &next, b"native-merge-2").unwrap().outcome, DecisionOutcome::Committed { .. }));
        let next_request = reopened.request_context();
        let current = reopened.runtime().block_on(reopened.materialize_admission_in(&next_request)).unwrap();
        let root2 = fgit_admission::evidence::evidence_root(&ForgeEventBatch::of_one(next.event().clone())).unwrap();
        let frontier = CanonicalForgePositionState::try_new(repository(), vec![
            ForgePositionStateEntry::try_new(AsciiSlug::from_static("pull-request/1"), 0, 1, event_root).unwrap(),
            ForgePositionStateEntry::try_new(AsciiSlug::from_static("pull-request/2"), 0, 1, root2).unwrap(),
        ]).unwrap();
        assert_eq!(frontier.root().unwrap(), current.basis().body().forge_position_root);
        let history = reopened.runtime().block_on(reopened.snapshot_history_in(&next_request)).unwrap();
        let second_record = &history.last().unwrap().batch.committed_rcrs[0];
        let expected_outbox2 = CanonicalOutboxState::try_new(repository(), vec![first_delivery,
            delivery_entry(second_record.tx_id, Some(repository_commit_id), root2)]).unwrap();
        assert_eq!(expected_outbox2.root().unwrap(), current.basis().body().outbox_root);
        assert_eq!(current.snapshot().outbox.len(), 2);
        assert_eq!(apply(&reopened, &offered, b"native-merge-1").unwrap(), terminal);
        assert_eq!(refs(&reopened)[&main_ref()], next_id, "retry cannot roll back a later merge");
        reopened.shutdown().unwrap();
    }
}

#[test]
fn a_competing_merge_refuses_canonically_without_advancing_forge_or_outbox_state() {
    let scratch = Scratch::new();
    let (mut node, _) = OneNode::init(config(&scratch.0, GitHashAlgorithm::Sha1)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let f = fixture(&node, &scratch.0, GitHashAlgorithm::Sha1, true);
    let offered = intent(&f, 1, ExpectedVersion::NewStream);
    let winner = apply(&node, &offered, b"winner").unwrap();
    assert!(matches!(winner.outcome, DecisionOutcome::Committed { .. }));
    let request = node.request_context();
    let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
    let stale = intent(&f, 2, ExpectedVersion::NewStream);
    let refused = apply(&node, &stale, b"loser").unwrap();
    assert!(matches!(refused.outcome, DecisionOutcome::Refused { code: RefusalCode::TargetRefMoved, .. }));
    assert_eq!(apply(&node, &stale, b"loser").unwrap(), refused);
    let request = node.request_context();
    let after = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
    assert_eq!(before.basis().body().ref_root, after.basis().body().ref_root);
    assert_eq!(before.basis().body().forge_position_root, after.basis().body().forge_position_root);
    assert_eq!(before.basis().body().outbox_root, after.basis().body().outbox_root);
    assert_eq!(after.snapshot().outbox.len(), 1);
    let history = node.runtime().block_on(node.snapshot_history_in(&request)).unwrap();
    assert!(history.last().unwrap().forge_events.is_empty());
    node.shutdown().unwrap();
}

#[test]
fn missing_candidate_is_retryable_and_anonymous_intake_is_refused() {
    let scratch = Scratch::new();
    let (mut node, _) = OneNode::init(config(&scratch.0, GitHashAlgorithm::Sha256)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let f = fixture(&node, &scratch.0, GitHashAlgorithm::Sha256, false);
    let offered = intent(&f, 1, ExpectedVersion::NewStream);
    let original = refs(&node);
    let request = node.request_context();
    assert!(matches!(node.runtime().block_on(node.admit_native_merge_durable_in(
        &request, &LoopbackReceiveSession::anonymous(), &offered, AdmissionLimits::default(), MergeObjectLimits::default(),
    )), Err(NodeReceiveTransportRefusal::Unauthenticated)));
    assert!(matches!(apply(&node, &offered, b"missing-retry"),
        Err(NodeReceiveTransportRefusal::Admission(error)) if matches!(*error,
            AdmissionError::AsyncProjectionUnavailable(RefusalCode::EvidenceMissing))));
    assert_eq!(refs(&node), original);
    let request = node.request_context();
    assert!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().snapshot().outbox.is_empty());
    node.put_git_object(GitObjectKind::Commit, f.candidate_body.clone()).unwrap();
    assert!(matches!(apply(&node, &offered, b"missing-retry").unwrap().outcome, DecisionOutcome::Committed { .. }));
    assert_eq!(refs(&node)[&main_ref()], f.candidate);
    node.shutdown().unwrap();
}

#[test]
fn epoch_zero_candidate_preserves_strict_profile_refusal_beside_permitted_merge() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (mut node, _) = OneNode::init(config(&scratch.0, format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let mut f = fixture(&node, &scratch.0, format, true);
        let valid = f.candidate;
        let request = node.request_context();
        let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        let original = before.basis().body().clone();

        // This is the existing epoch-zero StrictCreate divergence pinned by
        // fgit-git-object's adversarial corpus. Only the signature timestamps
        // differ from the permitted candidate; parents, tree and message match.
        let permitted = std::str::from_utf8(&f.candidate_body).unwrap();
        assert_eq!(permitted.matches(" 1 +0000\n").count(), 2);
        let epoch_zero = permitted.replace(" 1 +0000\n", " 0 +0000\n");
        assert_eq!(epoch_zero.replace(" 0 +0000\n", " 1 +0000\n"), permitted);
        f.candidate = node.put_git_object(GitObjectKind::Commit, epoch_zero.into_bytes()).unwrap().identity();
        assert_ne!(f.candidate, valid);
        let offered = intent(&f, 1, ExpectedVersion::NewStream);
        let refused = apply(&node, &offered, b"epoch-zero").unwrap();
        assert!(matches!(refused.outcome, DecisionOutcome::Refused {
            code: RefusalCode::EvidenceInvalid, ..
        }), "the current StrictCreate profile refuses epoch zero: {refused:?}");
        assert_eq!(apply(&node, &offered, b"epoch-zero").unwrap(), refused);
        let request = node.request_context();
        let after = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        assert_eq!(after.snapshot().refs, before.snapshot().refs);
        assert_eq!(after.snapshot().head_target, before.snapshot().head_target);
        assert_eq!(after.basis().body().ref_root, original.ref_root);
        assert_eq!(after.basis().body().forge_position_root, original.forge_position_root);
        assert_eq!(after.basis().body().outbox_root, original.outbox_root);
        assert_eq!(after.basis().body().retention_root, original.retention_root);
        assert_eq!(after.basis().body().latest_committed_rcr_id, original.latest_committed_rcr_id);
        let history = node.runtime().block_on(node.snapshot_history_in(&request)).unwrap();
        assert!(history.last().unwrap().batch.committed_rcrs.is_empty());
        assert!(history.last().unwrap().forge_events.is_empty());

        f.candidate = valid;
        let allowed = apply(&node, &intent(&f, 1, ExpectedVersion::NewStream), b"epoch-one").unwrap();
        assert!(matches!(allowed.outcome, DecisionOutcome::Committed { .. }), "{allowed:?}");
        assert_eq!(refs(&node)[&main_ref()], valid);
        let request = node.request_context();
        let committed = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        assert_eq!(committed.snapshot().outbox.len(), 1);
        assert_eq!(committed.snapshot().forge_positions.len(), 1);
        assert_eq!(apply(&node, &offered, b"epoch-zero").unwrap(), refused);
        let request = node.request_context();
        let retried = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        assert_eq!(retried.basis().body(), committed.basis().body());
        node.shutdown().unwrap();
    }
}

#[test]
fn invalid_parent_shape_and_reused_terminal_aggregate_do_not_move_refs() {
    let scratch = Scratch::new();
    let (mut node, _) = OneNode::init(config(&scratch.0, GitHashAlgorithm::Sha1)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let mut f = fixture(&node, &scratch.0, GitHashAlgorithm::Sha1, true);
    let original = refs(&node);
    let valid = f.candidate;
    f.candidate = node.put_git_object(GitObjectKind::Commit, commit(f.merged_tree, &[f.target], "not a merge\n")).unwrap().identity();
    assert!(matches!(apply(&node, &intent(&f, 1, ExpectedVersion::NewStream), b"bad-parents").unwrap().outcome,
        DecisionOutcome::Refused { code: RefusalCode::EvidenceInvalid, .. }));
    assert_eq!(refs(&node), original);
    f.candidate = valid;
    let offered = intent(&f, 1, ExpectedVersion::NewStream);
    assert!(matches!(apply(&node, &offered, b"valid-parents").unwrap().outcome, DecisionOutcome::Committed { .. }));
    f.target = valid;
    f.candidate = node.put_git_object(GitObjectKind::Commit, commit(f.merged_tree, &[f.target, f.source], "repeat closed PR\n")).unwrap().identity();
    let closed = intent(&f, 1, ExpectedVersion::Exactly(AggregateVersion::FIRST));
    assert!(matches!(apply(&node, &closed, b"closed-pr").unwrap().outcome,
        DecisionOutcome::Refused { code: RefusalCode::ProtectedRefTransitionDenied, .. }));
    assert_eq!(refs(&node)[&main_ref()], valid);
    let request = node.request_context();
    let history = node.runtime().block_on(node.snapshot_history_in(&request)).unwrap();
    assert_eq!(history.iter().flat_map(|batch| &batch.forge_events)
        .filter(|event| matches!(event.payload, ForgeEventPayload::MergeCommittedNative(_))).count(), 1);
    assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().snapshot().outbox.len(), 1);
    node.shutdown().unwrap();
}

/// A real filesystem destination fixture. Its create-if-absent receipt is
/// synced before replying, and is the durable idempotency boundary under test.
struct DiskDestination {
    root: PathBuf,
    kill_after_delivery: bool,
    strong: bool,
    probes: usize,
    sends: usize,
}

impl OutboxDestination<Cx> for DiskDestination {
    fn destination(&self) -> AsciiSlug { AsciiSlug::from_static("forge-projection") }
    fn idempotency(&self) -> DownstreamIdempotency {
        if self.strong { DownstreamIdempotency::Strong } else { DownstreamIdempotency::Weak }
    }
    async fn probe<'a>(&'a mut self, _cx: &'a Cx, request: &'a DeliveryRequest<'_>)
        -> Result<(ProbeVerdict, Vec<u8>), RefusalCode> {
        self.probes += 1;
        match fs::read(self.root.join(request.key.to_string())) {
            Ok(bytes) => {
                assert_eq!(bytes, fgit_codec::encode_body(request.events).unwrap());
                Ok((ProbeVerdict::Delivered, b"filesystem destination: committed receipt".to_vec()))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok((ProbeVerdict::NotDelivered, Vec::new())),
            Err(_) => Err(RefusalCode::EvidenceMissing),
        }
    }
    async fn deliver<'a>(&'a mut self, _cx: &'a Cx, request: &'a DeliveryRequest<'_>, _attempt: u32)
        -> Result<(DeliveryVerdict, Vec<u8>), RefusalCode> {
        use std::io::Write;
        self.sends += 1;
        fs::create_dir_all(&self.root).unwrap();
        let path = self.root.join(request.key.to_string());
        let verdict = match fs::OpenOptions::new().create_new(true).write(true).open(&path) {
            Ok(mut file) => {
                file.write_all(&fgit_codec::encode_body(request.events).unwrap()).unwrap();
                file.sync_all().unwrap();
                fs::File::open(&self.root).unwrap().sync_all().unwrap();
                DeliveryVerdict::Accepted
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => DeliveryVerdict::DuplicateSuppressed,
            Err(_) => return Err(RefusalCode::EvidenceMissing),
        };
        if self.kill_after_delivery {
            std::process::exit(81);
        }
        Ok((verdict, b"filesystem destination: committed receipt".to_vec()))
    }
}

fn destination(root: &Path) -> DiskDestination {
    DiskDestination { root: root.join("destination"), kill_after_delivery: false, strong: true, probes: 0, sends: 0 }
}

fn delivery_key(node: &OneNode) -> AsciiSlug {
    let request = node.request_context();
    let materialized = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
    assert_eq!(materialized.snapshot().outbox.len(), 1);
    materialized.snapshot().outbox.keys().next().unwrap().label()
}

fn deliver(node: &OneNode, key: AsciiSlug, destination: &mut DiskDestination)
    -> Result<fgit_codec::CanonicalOutboxEffectState, NodeReceiveTransportRefusal> {
    let request = node.request_context();
    node.runtime().block_on(node.deliver_forge_outbox_in(&request, &session(b"delivery-worker"), key,
        destination, ReconcilePolicy::new(std::num::NonZeroU32::new(4).unwrap()), AdmissionLimits::default()))
}

#[test]
fn canonical_outbox_delivers_once_and_refuses_weak_capability_before_any_call() {
    let scratch = Scratch::new();
    let (mut node, _) = OneNode::init(config(&scratch.0, GitHashAlgorithm::Sha1)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let f = fixture(&node, &scratch.0, GitHashAlgorithm::Sha1, true);
    apply(&node, &intent(&f, 1, ExpectedVersion::NewStream), b"outbox-merge").unwrap();
    let key = delivery_key(&node);
    let mut consumer = destination(&scratch.0);
    consumer.strong = false;
    assert!(matches!(deliver(&node, key, &mut consumer), Err(NodeReceiveTransportRefusal::Admission(error))
        if matches!(*error, AdmissionError::AsyncProjectionUnavailable(RefusalCode::PublicationPolicyRefused))));
    assert_eq!((consumer.probes, consumer.sends), (0, 0));
    consumer.strong = true;
    let acknowledged = deliver(&node, key, &mut consumer).unwrap();
    assert_eq!(acknowledged.state(), ObligationState::Acknowledged);
    assert_eq!((consumer.probes, consumer.sends), (1, 1));
    assert_eq!(deliver(&node, key, &mut consumer).unwrap(), acknowledged);
    assert_eq!((consumer.probes, consumer.sends), (1, 1));
    assert_eq!(refs(&node)[&main_ref()], f.candidate);
    let request = node.request_context();
    let history = node.runtime().block_on(node.snapshot_history_in(&request)).unwrap();
    assert_eq!(history.iter().flat_map(|batch| &batch.forge_events).count(), 1);
    node.shutdown().unwrap();
}

#[test]
fn canonical_outbox_recovers_after_process_death_after_delivery() {
    const CHILD_ROOT: &str = "FGIT_ASA3_DELIVERY_CRASH_ROOT";
    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        let root = PathBuf::from(root);
        let (mut node, _) = OneNode::init(config(&root, GitHashAlgorithm::Sha256)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let f = fixture(&node, &root, GitHashAlgorithm::Sha256, true);
        apply(&node, &intent(&f, 1, ExpectedVersion::NewStream), b"crash-merge").unwrap();
        let key = delivery_key(&node);
        let mut consumer = destination(&root);
        consumer.kill_after_delivery = true;
        let result = deliver(&node, key, &mut consumer);
        panic!("child must exit at the delivery boundary: {result:?}");
    }
    let scratch = Scratch::new();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact").arg("canonical_outbox_recovers_after_process_death_after_delivery")
        .arg("--nocapture").env(CHILD_ROOT, &scratch.0).status().unwrap();
    assert_eq!(status.code(), Some(81), "child reached the exact persisted-delivery boundary");
    let mut node = OneNode::open_existing(config(&scratch.0, GitHashAlgorithm::Sha256)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let request = node.request_context();
    let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
    let history = node.runtime().block_on(node.snapshot_history_in(&request)).unwrap();
    assert!(history.last().unwrap().ref_updates.is_empty(), "the last pre-crash decision only transferred delivery responsibility");
    let key = delivery_key(&node);
    let mut consumer = destination(&scratch.0);
    let acknowledged = deliver(&node, key, &mut consumer).unwrap();
    assert_eq!(acknowledged.state(), ObligationState::Acknowledged);
    assert_eq!((consumer.probes, consumer.sends), (1, 0), "restart probes the durable receipt and does not resend");
    let request = node.request_context();
    let after = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
    assert_eq!(before.basis().body().ref_root, after.basis().body().ref_root);
    assert_eq!(before.basis().body().forge_position_root, after.basis().body().forge_position_root);
    assert_ne!(before.basis().body().outbox_root, after.basis().body().outbox_root);
    assert_eq!(fs::read_dir(&consumer.root).unwrap().count(), 1);
    node.shutdown().unwrap();
}
