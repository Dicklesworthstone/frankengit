//! Regression coverage through the ORIGINAL public node entrypoint. The
//! fixture uses real immutable objects, the embedded authority and normal
//! imports. It neither substitutes a map for authority nor invokes Git.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_admission::evidence::{DecisionEvidenceBodies, OutboxEffectBatch, evidence_root, principal_snapshot_id};
use fgit_admission::merge::{SealedMerge, prepare_native_merge, seal_attempt_for};
use fgit_admission::merge::native::delivery::{self, EFFECT_NAMESPACE, OUTBOX_NAMESPACE};
use fgit_admission::{CanonicalRefState, CommitEvidence, PermittedObjectClosure, permitted_object_closure_root};
use fgit_authority::{AsyncAuthorityStore, IdempotencyKey, OutcomeLookup, PutOutcome};
use fgit_codec::{
    CanonicalBody, CanonicalOutboxEffectState, CanonicalOutboxState,
    CanonicalOutboxStateEntry, OutboxDeliveryIdentityInput, derive_outbox_delivery_key,
};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::aggregate::{ExpectedVersion, PullRequestNumber};
use fgit_forge::event::{ForgeEventBatch, NativeMerge};
use fgit_forge::merge::{MergeAttempt, MergeEffectPackage, RefIntent as ForgeRefIntent};
use fgit_resource::ObligationState;
use fgit_reference::effect::{FoldBasis, FoldOutcome};
use fgit_reference::intent::{
    DurabilityProfile, ForgeEntityId, ForgeEventKind, ForgeIntent, ForgeStreamId,
    ForgeStreamPosition, IdempotencyKey as ModelKey, Intent, OutboxDeliveryKey,
    OutboxIntent, RefIntent, Statement,
};
use fgit_reference::refs::ExpectedRefState;
use fgit_treefs::WorkspaceEpoch;
use fgit_txn::IntentEvaluator;
use fgit_types::{
    AsciiSlug, DecisionOutcome, Digest, GitHashAlgorithm, GitOid, HeadGeneration,
    PrincipalId, PrincipalSnapshotId, RefName, RepositoryId, TenantId,
};

use super::*;
use crate::{MaterializedAdmission, NodeConfig, admission_immutable_key, read_evidence_body_in};

static NEXT: AtomicU64 = AtomicU64::new(0);
const CLASS: AsciiSlug = AsciiSlug::from_static("forge-event");
const DESTINATION: AsciiSlug = AsciiSlug::from_static("forge-projection");
const FORGE_POSITION_NAMESPACE: &[u8] = b"frankengit/admission/forge-position-state/v1/";
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fgit-sealed-native-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).expect("unique test directory");
        Self(path)
    }

    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(
            self.0.join("node"), TenantId::from_bytes([0xa1; 16]),
            RepositoryId::from_bytes([0xa2; 16]),
        ).with_object_format(format)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove owned test directory after explicit node close");
    }
}

fn target_ref() -> RefName { RefName::try_new(b"refs/heads/main").unwrap() }
fn source_ref() -> RefName { RefName::try_new(b"refs/heads/topic").unwrap() }
fn principal() -> PrincipalId { PrincipalId::from_bytes([0xa3; 16]) }

fn session(key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(principal(), IdempotencyKey::new(key.to_vec()).unwrap())
}

fn context(node: &OneNode, key: &[u8]) -> AdmissionContext {
    AdmissionContext {
        head_key: node.head_key.clone(), tenant_id: node.tenant_id,
        repository_id: node.repository_id, principal_id: principal(),
        idempotency_key: IdempotencyKey::new(key.to_vec()).unwrap(), object_format: node.object_format,
    }
}

fn snapshot(node: &OneNode) -> MaterializedAdmission {
    let request = node.request_context();
    node.runtime().block_on(node.materialize_admission_in(&request)).unwrap()
}

fn committed(outcome: TerminalOutcome) -> TerminalOutcome {
    assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }), "{outcome:?}");
    outcome
}

fn read_body<B: CanonicalBody>(node: &OneNode, namespace: &[u8], root: Digest) -> B {
    let request = node.request_context();
    node.runtime().block_on(read_evidence_body_in(
        &node.authority, request.authority(), node.repository_id, namespace, root, &|| false,
    )).unwrap()
}

fn selected_outbox(node: &OneNode, selected: &MaterializedAdmission) -> CanonicalOutboxState {
    let request = node.request_context();
    node.runtime().block_on(delivery::read_in(
        &node.authority, request.authority(), selected.basis(), &|| false,
    )).unwrap().outbox
}

fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, label: &str, body: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, body);
    let raw = [format!("{label} {}\0", body.len()).as_bytes(), body].concat();
    let length = u16::try_from(raw.len()).unwrap();
    let mut zlib = vec![0x78, 0x01, 0x01];
    zlib.extend(length.to_le_bytes());
    zlib.extend((!length).to_le_bytes());
    zlib.extend(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let next = (a + u32::from(*byte)) % 65_521;
        (next, (b + next) % 65_521)
    });
    zlib.extend(((b << 16) | a).to_be_bytes());
    let hex = id.to_string();
    let parent = root.join("objects").join(&hex[..2]);
    fs::create_dir_all(&parent).unwrap();
    fs::write(parent.join(&hex[2..]), zlib).unwrap();
    id
}

fn commit_body(tree: GitOid, parents: &[GitOid], message: &str) -> Vec<u8> {
    let mut body = format!("tree {tree}\n");
    for parent in parents { body.push_str(&format!("parent {parent}\n")); }
    body.push_str("author Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\n");
    body.push_str(message);
    body.into_bytes()
}

struct Fixture {
    base: GitOid,
    target: GitOid,
    source: GitOid,
    tree: GitOid,
    candidate: GitOid,
    body: Vec<u8>,
}

fn fixture(node: &OneNode, scratch: &Scratch, stage_candidate: bool) -> Fixture {
    let root = scratch.0.join("source");
    fs::create_dir_all(root.join("refs/heads")).unwrap();
    fs::write(root.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    let format = node.object_format;
    let configuration = match format {
        GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
        GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
    };
    fs::write(root.join("config"), configuration).unwrap();
    let blob = loose(&root, format, GitObjectKind::Blob, "blob", b"preserved content\n");
    let tree_body = [b"100644 keep.txt\0".as_slice(), blob.as_bytes()].concat();
    let tree = loose(&root, format, GitObjectKind::Tree, "tree", &tree_body);
    let base = loose(&root, format, GitObjectKind::Commit, "commit", &commit_body(tree, &[], "base\n"));
    let target = loose(&root, format, GitObjectKind::Commit, "commit", &commit_body(tree, &[base], "target\n"));
    let source = loose(&root, format, GitObjectKind::Commit, "commit", &commit_body(tree, &[base], "source\n"));
    fs::write(root.join("refs/heads/main"), format!("{target}\n")).unwrap();
    fs::write(root.join("refs/heads/topic"), format!("{source}\n")).unwrap();
    let request = node.request_context();
    let imported = node.runtime().block_on(node.import_loose_git_directory_durable_in(
        &request, &root, principal(), b"merge-outbox-fixture",
    )).unwrap();
    assert!(imported.commands.iter().all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. })));
    let body = commit_body(tree, &[target, source], "reviewed merge\n");
    let candidate = git_object_id(format, GitObjectKind::Commit, &body);
    if stage_candidate {
        assert_eq!(node.put_git_object(GitObjectKind::Commit, body.clone()).unwrap().identity(), candidate);
    }
    let fixture = Fixture { base, target, source, tree, candidate, body };
    if stage_candidate {
        let exhaustion = Cell::new(None);
        let limits = MergeObjectLimits::default();
        let source = VerifiedFabricPackSource {
            fabric: &node.fabric,
            object_format: format,
            maximum_object_bytes: limits.max_object_bytes,
            database_context: request.authority(),
            database_exhaustion: &exhaustion,
            session_is_live: None,
        };
        let offered = intent(&fixture, 1, target, candidate);
        let verified = validate_merge_objects(&source, offered.merge().unwrap(), limits, &mut || true)
            .expect("positive fixture passes real native validation before admission");
        assert_eq!(verified.objects, BTreeSet::from([blob, tree, base, target, fixture.source, candidate]));
    }
    fixture
}

fn intent(f: &Fixture, number: u64, target: GitOid, candidate: GitOid) -> NativeMergeIntent {
    NativeMergeIntent::new(PullRequestNumber::try_new(number).unwrap(), ExpectedVersion::NewStream, NativeMerge {
        source_ref: source_ref(), source_tip: f.source, base_tip: f.base,
        target_ref: target_ref(), target_tip_before: target, merge_commit: candidate,
    }).unwrap()
}

fn new_node(scratch: &Scratch, format: GitHashAlgorithm) -> OneNode {
    // Source import does not set canonical HEAD. Establish a real authenticated
    // unborn HEAD at genesis so preservation is tested, not assumed from a
    // source-directory file or injected into the materializer's cache.
    let mut node = OneNode::open_components(scratch.config(format)).unwrap();
    let request = node.request_context();
    let configuration = fgit_codec::schema::RepositoryIncarnationConfigurationBodyV2_1 {
        root_layout: node.service_config.root_layout,
        object_format: format,
        repository_incarnation_id: node.repository_incarnation_id,
        policy_root: None,
    };
    let configuration_root = node.runtime().block_on(
        fgit_authority::stage_latest_repository_incarnation_configuration_async(
            &node.authority, request.authority(), &configuration,
        ),
    ).unwrap();
    let refs = CanonicalRefState::new_with_head_target(Default::default(), target_ref()).unwrap();
    let ref_root = node.runtime().block_on(node.admission_materializer.stage_ref_state_for_layout_in(
        &node.authority, request.authority(), node.repository_id, configuration.root_layout, refs,
    )).unwrap();
    node.runtime().block_on(node.admission_materializer.stage_permitted_object_closure_in(
        &node.authority, request.authority(), node.repository_id, PermittedObjectClosure::default(),
    )).unwrap();
    let genesis = crate::genesis_head(node.repository_id, ref_root, configuration_root).unwrap();
    assert!(matches!(crate::initialize_embedded_repository(
        node.runtime(), &node.authority, request.authority(), &node.head_key, &genesis,
    ).unwrap(), fgit_authority::HeadInit::Created(_)));
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    node
}


/// A structurally valid placeholder used only while deriving the real evidence.
/// It never reaches a positive admission and is useful for negative tests.
fn unrelated_evidence() -> CommitEvidence {
    let digest = fgit_codec::harness::digest_of(0xe1);
    CommitEvidence {
        principal_snapshot_id: PrincipalSnapshotId::from_internal_object_id(
            fgit_types::InternalObjectId::new(
                digest.algorithm(), PrincipalSnapshotId::DOMAIN_TAG,
                fgit_types::CANONICAL_CODEC_VERSION, *digest.bytes(),
            ),
        ).unwrap(),
        forge_event_batch_root: digest,
        policy_decision_root: digest,
        invariant_evidence_root: digest,
        outbox_effect_root: digest,
        retention_delta_root: digest,
    }
}

#[derive(Clone)]
struct OfferedPackage {
    package: MergeEffectPackage,
    attempt: MergeAttempt,
    closure: ValidatedClosure,
    evidence: CommitEvidence,
}

impl OfferedPackage {
    fn sealed(&self, observed_epoch: WorkspaceEpoch) -> SealedMerge<'_> {
        SealedMerge {
            package: &self.package,
            attempt: &self.attempt,
            closure: &self.closure,
            evidence: self.evidence,
            workspace_epoch_now: observed_epoch,
        }
    }
}

fn offered(node: &OneNode, f: &Fixture, number: u64, epoch: u64, key: &[u8]) -> OfferedPackage {
    let mut objects = snapshot(node).selected_closure().closure().objects().clone();
    objects.insert(f.candidate);
    let event = intent(f, number, f.target, f.candidate).event().clone();
    let mut offer = OfferedPackage {
        evidence: unrelated_evidence(),
        package: MergeEffectPackage {
            objects: vec![f.candidate],
            ref_intent: ForgeRefIntent {
                name: target_ref().as_bytes().to_vec(), expected_tip: f.target,
                new_tip: f.candidate,
            },
            event,
        },
        attempt: MergeAttempt {
            pull_request: PullRequestNumber::try_new(number).unwrap(),
            source_ref: source_ref().as_bytes().to_vec(),
            target_ref: target_ref().as_bytes().to_vec(),
            source_tip: f.source, target_tip: f.target, base_tip: f.base,
            workspace_epoch: WorkspaceEpoch::from_u64(epoch),
        },
        closure: ValidatedClosure {
            object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(objects.clone())).unwrap(),
            objects,
        },
    };
    let before = snapshot(node);
    let (entry, _) = expected_entry(node, &before, &offer, key);
    let evidence = complete_evidence(node, &before, &offer, key, entry);
    offer.evidence = CommitEvidence {
        principal_snapshot_id: principal_snapshot_id(evidence.principal_snapshot()).unwrap(),
        forge_event_batch_root: entry.payload_root(),
        policy_decision_root: evidence_root(evidence.policy_decision()).unwrap(),
        invariant_evidence_root: evidence_root(evidence.invariant_evidence()).unwrap(),
        outbox_effect_root: evidence_root(evidence.outbox_effect_batch()).unwrap(),
        retention_delta_root: evidence_root(evidence.retention_delta()).unwrap(),
    };
    offer
}

fn apply(node: &OneNode, offer: &OfferedPackage, key: &[u8], observed: u64)
    -> Result<TerminalOutcome, AdmissionError>
{
    let request = node.request_context();
    let context = context(node, key);
    let sealed = offer.sealed(WorkspaceEpoch::from_u64(observed));
    node.runtime().block_on(node.admit_merge_durable_in(
        &request, &context, &sealed, AdmissionLimits::default(),
    ))
}

fn expected_entry(
    node: &OneNode, before: &MaterializedAdmission, offer: &OfferedPackage, key: &[u8],
) -> (CanonicalOutboxStateEntry, CanonicalOutboxEffectState) {
    let sealed = offer.sealed(offer.attempt.workspace_epoch);
    let tx_id = seal_attempt_for(&context(node, key), &sealed).unwrap().derive().unwrap().0;
    let payload = evidence_root(&ForgeEventBatch::of_one(offer.package.event.clone())).unwrap();
    let predecessor = before.basis().body().latest_committed_rcr_id;
    let key = derive_outbox_delivery_key(OutboxDeliveryIdentityInput::new(
        node.repository_id, CLASS, DESTINATION, payload, tx_id, predecessor,
    )).unwrap();
    let effect = CanonicalOutboxEffectState::committed(node.repository_id, key, tx_id, payload);
    let entry = CanonicalOutboxStateEntry::new(key, CLASS, DESTINATION, payload, tx_id,
        predecessor, effect.root().unwrap(), None);
    (entry, effect)
}

/// Assemble the expected FULL request explicitly. Comparing actual roots to
/// these bytes catches a ref-only evidence record with substituted forge roots.
fn complete_evidence(
    node: &OneNode, before: &MaterializedAdmission, offer: &OfferedPackage,
    key: &[u8], entry: CanonicalOutboxStateEntry,
) -> DecisionEvidenceBodies {
    let context = context(node, key);
    let sealed = offer.sealed(offer.attempt.workspace_epoch);
    let attempt = seal_attempt_for(&context, &sealed).unwrap();
    let label = AsciiSlug::try_new("test_stream", offer.package.event.aggregate.to_string().as_bytes()).unwrap();
    let request = TransactionRequest {
        tx_id: entry.tx_id(), tenant: context.tenant_id, repository: context.repository_id,
        principal: context.principal_id, schema: attempt.request.request_schema(),
        idempotency_key: ModelKey::new(AsciiSlug::from_static("receive")),
        canonical_request_digest: fgit_authority::canonical_request_digest(&attempt.request).unwrap(),
        statements: vec![Statement {
            mismatch_policy: fgit_types::MismatchPolicy::TxnAbort,
            intents: vec![
                Intent::Ref(RefIntent::Update {
                    name: target_ref(), expected: ExpectedRefState::Exact(offer.attempt.target_tip),
                    new: offer.package.ref_intent.new_tip, force: false,
                }),
                Intent::Forge(ForgeIntent {
                    stream: ForgeStreamId::new(label),
                    expected_position: ForgeStreamPosition::new(offer.package.event.version.get() - 1),
                    event: ForgeEventKind::PullRequestMerged {
                        pull_request: ForgeEntityId::new(label), target: target_ref(),
                    },
                }),
                Intent::Outbox(OutboxIntent {
                    delivery_key: OutboxDeliveryKey::new(entry.delivery_key()), parameters: entry.payload_root(),
                }),
            ],
        }],
        promised_closure: offer.closure.objects.clone(), atomic: true,
        durability: DurabilityProfile::CanonicalSource,
    };
    let fold = IntentEvaluator::new().evaluate(FoldBasis {
        refs: &before.snapshot().refs,
        forge_positions: &before.snapshot().forge_positions,
        retention: &before.snapshot().retention,
        outbox: &before.snapshot().outbox,
    }, &request);
    assert!(matches!(fold.outcome, FoldOutcome::Folded(_)));
    DecisionEvidenceBodies::derive(&context, before.basis(), &request, &fold).unwrap()
}

#[test]
fn original_node_api_publishes_the_full_transaction_under_its_original_seal() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = new_node(&scratch, format);
        let f = fixture(&node, &scratch, true);
        let offer = offered(&node, &f, 1, 7, b"original-seal");
        let before = snapshot(&node);
        let (entry, expected_effect) = expected_entry(&node, &before, &offer, b"original-seal");
        let expected = complete_evidence(&node, &before, &offer, b"original-seal", entry);
        let new_style_tx = intent(&f, 1, f.target, f.candidate)
            .seal_attempt(&context(&node, b"original-seal")).unwrap().derive().unwrap().0;
        assert_ne!(entry.tx_id(), new_style_tx, "adapting an event must not reseal an older request");
        let terminal = committed(apply(&node, &offer, b"original-seal", 7).unwrap());
        let after = snapshot(&node);
        assert_eq!(after.snapshot().refs[&target_ref()], f.candidate);
        assert_eq!(after.snapshot().refs[&source_ref()], f.source);
        assert_eq!(after.snapshot().head_target, before.snapshot().head_target);
        assert_eq!(after.snapshot().head_target, Some(target_ref()));
        assert_eq!(after.basis().generation().get(), before.basis().generation().get() + 1);
        assert_ne!(after.basis().body().ref_root, before.basis().body().ref_root);
        assert_ne!(after.basis().body().forge_position_root, before.basis().body().forge_position_root);
        assert_ne!(after.basis().body().outbox_root, before.basis().body().outbox_root);
        assert_eq!(after.basis().body().retention_root, before.basis().body().retention_root);
        let outbox = selected_outbox(&node, &after);
        assert_eq!(outbox.entries(), &[entry]);
        assert_eq!(outbox.root().unwrap(), after.basis().body().outbox_root);
        let effect: CanonicalOutboxEffectState = read_body(
            &node, EFFECT_NAMESPACE, entry.effect_state_root(),
        );
        assert_eq!(effect, expected_effect);
        assert_eq!(effect.state(), ObligationState::Committed);
        assert!(effect.evidence_root().is_none(), "enqueue is not acknowledgement");
        let request = node.request_context();
        let history = node.runtime().block_on(node.snapshot_history_in(&request)).unwrap();
        let last = history.last().unwrap();
        assert_eq!(last.forge_events, vec![offer.package.event.clone()]);
        assert_eq!(last.batch.committed_rcrs.len(), 1);
        let record = &last.batch.committed_rcrs[0];
        assert_eq!(record.tx_id, entry.tx_id());
        assert_eq!(record.invariant_evidence_root, evidence_root(expected.invariant_evidence()).unwrap());
        assert_eq!(record.outbox_effect_root, evidence_root(expected.outbox_effect_batch()).unwrap());
        assert_eq!(record.forge_event_batch_root, entry.payload_root());
        assert_eq!(record.policy_decision_root, offer.evidence.policy_decision_root);
        assert_ne!(record.policy_decision_root, unrelated_evidence().policy_decision_root);
        let actual: OutboxEffectBatch = read_body(&node,
            crate::ADMISSION_OUTBOX_EFFECT_BATCH_KEY_PREFIX, record.outbox_effect_root);
        assert_eq!(&actual, expected.outbox_effect_batch());
        assert_eq!(apply(&node, &offer, b"original-seal", 7).unwrap(), terminal);
        assert_eq!(snapshot(&node).basis(), after.basis());
        node.shutdown().unwrap();
    }
}

#[test]
fn reopened_original_retry_survives_workspace_movement_and_later_native_publication() {
    let scratch = Scratch::new();
    let format = GitHashAlgorithm::Sha256;
    let node = new_node(&scratch, format);
    let f = fixture(&node, &scratch, true);
    let offer = offered(&node, &f, 1, 7, b"recovery");
    let terminal = committed(apply(&node, &offer, b"recovery", 7).unwrap());
    let first_entry = selected_outbox(&node, &snapshot(&node)).entries()[0];
    node.shutdown().unwrap();

    let mut node = OneNode::open_existing(scratch.config(format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let before_retry = snapshot(&node);
    assert_eq!(apply(&node, &offer, b"recovery", 99).unwrap(), terminal);
    assert_eq!(snapshot(&node).basis(), before_retry.basis());
    let next = node.put_git_object(GitObjectKind::Commit,
        commit_body(f.tree, &[f.candidate, f.source], "subsequent native merge\n")).unwrap().identity();
    let next_intent = intent(&f, 2, f.candidate, next);
    let request = node.request_context();
    committed(node.runtime().block_on(node.admit_native_merge_durable_in(
        &request, &session(b"next-native"), &next_intent,
        AdmissionLimits::default(), MergeObjectLimits::default(),
    )).unwrap());
    let after = snapshot(&node);
    let outbox = selected_outbox(&node, &after);
    assert_eq!(outbox.entries().len(), 2);
    assert_eq!(outbox.entry(first_entry.delivery_key()), Some(&first_entry));
    assert_eq!(apply(&node, &offer, b"recovery", 100).unwrap(), terminal);
    assert_eq!(snapshot(&node).basis(), after.basis());
    assert_eq!(snapshot(&node).snapshot().refs[&target_ref()], next);
    node.shutdown().unwrap();
}

#[test]
fn workspace_staleness_is_a_terminal_refusal_but_not_an_identity_change() {
    let scratch = Scratch::new();
    let node = new_node(&scratch, GitHashAlgorithm::Sha1);
    let f = fixture(&node, &scratch, true);
    let offer = offered(&node, &f, 1, 7, b"stale-workspace");
    let before = snapshot(&node);
    let refused = apply(&node, &offer, b"stale-workspace", 8).unwrap();
    assert!(matches!(refused.outcome, DecisionOutcome::Refused { code: RefusalCode::EvidenceStale, .. }));
    let after = snapshot(&node);
    assert_eq!(after.basis().body().ref_root, before.basis().body().ref_root);
    assert_eq!(after.basis().body().forge_position_root, before.basis().body().forge_position_root);
    assert_eq!(after.basis().body().outbox_root, before.basis().body().outbox_root);
    assert_eq!(apply(&node, &offer, b"stale-workspace", 7).unwrap(), refused);
    assert_eq!(snapshot(&node).basis(), after.basis());
    let reviewed = offered(&node, &f, 1, 7, b"new-reviewed-attempt");
    committed(apply(&node, &reviewed, b"new-reviewed-attempt", 7).unwrap());
    node.shutdown().unwrap();
}

#[test]
fn original_epoch_stays_in_the_seal_and_changed_semantics_cannot_reuse_its_key() {
    let scratch = Scratch::new();
    let node = new_node(&scratch, GitHashAlgorithm::Sha1);
    let f = fixture(&node, &scratch, true);
    let offer = offered(&node, &f, 1, 7, b"epoch-binding");
    committed(apply(&node, &offer, b"epoch-binding", 7).unwrap());
    let before = snapshot(&node);
    let mut changed = offer.clone();
    changed.attempt.workspace_epoch = WorkspaceEpoch::from_u64(8);
    let context = context(&node, b"epoch-binding");
    let first = seal_attempt_for(&context, &offer.sealed(WorkspaceEpoch::from_u64(7))).unwrap();
    let second = seal_attempt_for(&context, &changed.sealed(WorkspaceEpoch::from_u64(8))).unwrap();
    assert_ne!(first.derive().unwrap().0, second.derive().unwrap().0);
    assert!(apply(&node, &changed, b"epoch-binding", 8).is_err());
    assert_eq!(snapshot(&node).basis(), before.basis());
    node.shutdown().unwrap();
}

#[test]
fn missing_native_object_remains_retryable_and_is_not_laundered_by_package_evidence() {
    let scratch = Scratch::new();
    let node = new_node(&scratch, GitHashAlgorithm::Sha256);
    let f = fixture(&node, &scratch, false);
    let offer = offered(&node, &f, 1, 7, b"missing-object");
    let before = snapshot(&node);
    assert!(matches!(apply(&node, &offer, b"missing-object", 7),
        Err(AdmissionError::AsyncProjectionUnavailable(RefusalCode::EvidenceMissing))));
    assert_eq!(snapshot(&node).basis(), before.basis());
    assert_eq!(node.put_git_object(GitObjectKind::Commit, f.body).unwrap().identity(), f.candidate);
    committed(apply(&node, &offer, b"missing-object", 7).unwrap());
    assert_eq!(selected_outbox(&node, &snapshot(&node)).entries().len(), 1);
    node.shutdown().unwrap();
}

#[test]
fn invalid_native_parents_refuse_even_with_self_consistent_claimed_closure() {
    let scratch = Scratch::new();
    let node = new_node(&scratch, GitHashAlgorithm::Sha1);
    let mut f = fixture(&node, &scratch, true);
    f.candidate = node.put_git_object(GitObjectKind::Commit,
        commit_body(f.tree, &[f.source, f.target], "reversed parents\n")).unwrap().identity();
    let offer = offered(&node, &f, 1, 7, b"wrong-parent-order");
    let before = snapshot(&node);
    let refused = apply(&node, &offer, b"wrong-parent-order", 7).unwrap();
    assert!(matches!(refused.outcome, DecisionOutcome::Refused { code: RefusalCode::EvidenceInvalid, .. }));
    let after = snapshot(&node);
    assert_eq!(after.basis().body().ref_root, before.basis().body().ref_root);
    assert_eq!(after.basis().body().forge_position_root, before.basis().body().forge_position_root);
    assert_eq!(after.basis().body().outbox_root, before.basis().body().outbox_root);
    node.shutdown().unwrap();
}

#[test]
fn stale_competitor_never_adds_a_forge_event_or_delivery() {
    let scratch = Scratch::new();
    let node = new_node(&scratch, GitHashAlgorithm::Sha1);
    let f = fixture(&node, &scratch, true);
    let winner = offered(&node, &f, 1, 7, b"winner");
    let loser = offered(&node, &f, 2, 7, b"loser");
    committed(apply(&node, &winner, b"winner", 7).unwrap());
    let before = snapshot(&node);
    // Ref movement precedes workspace staleness in the established contract.
    let refused = apply(&node, &loser, b"loser", 8).unwrap();
    assert!(matches!(refused.outcome, DecisionOutcome::Refused { code: RefusalCode::TargetRefMoved, .. }));
    let after = snapshot(&node);
    assert_eq!(after.basis().body().ref_root, before.basis().body().ref_root);
    assert_eq!(after.basis().body().forge_position_root, before.basis().body().forge_position_root);
    assert_eq!(after.basis().body().outbox_root, before.basis().body().outbox_root);
    assert_eq!(apply(&node, &loser, b"loser", 7).unwrap(), refused);
    let request = node.request_context();
    let history = node.runtime().block_on(node.snapshot_history_in(&request)).unwrap();
    assert!(history.last().unwrap().forge_events.is_empty());
    node.shutdown().unwrap();
}

#[test]
fn immutable_staging_failure_never_publishes_a_partial_original_api_merge() {
    for phase in 0..5 {
        let scratch = Scratch::new();
        let node = new_node(&scratch, GitHashAlgorithm::Sha256);
        let f = fixture(&node, &scratch, true);
        let offer = offered(&node, &f, 1, 7, b"failed-stage");
        let before = snapshot(&node);
        let request = node.request_context();
        let delivery = node.runtime().block_on(delivery::read_in(
            &node.authority, request.authority(), before.basis(), &|| false,
        )).unwrap();
        let refs = match before.snapshot().head_target.as_ref() {
            Some(head) => CanonicalRefState::new_with_head_target(before.snapshot().refs.clone(), head.clone()).unwrap(),
            None => CanonicalRefState::new(before.snapshot().refs.clone()),
        };
        let context = context(&node, b"failed-stage");
        let sealed = offer.sealed(WorkspaceEpoch::from_u64(7));
        let attempt = seal_attempt_for(&context, &sealed).unwrap();
        let tx_id = attempt.derive().unwrap().0;
        let prepared = prepare_native_merge(&context, &sealed, tx_id, &attempt, before.basis(),
            &NativeMergeBasis { refs, root_layout: before.root_layout(), forge: delivery.forge, outbox: delivery.outbox }).unwrap();
        let (namespace, root) = match phase {
            0 => (EFFECT_NAMESPACE, prepared.effect.root().unwrap()),
            1 => (FORGE_POSITION_NAMESPACE, prepared.forge.root().unwrap()),
            2 => (OUTBOX_NAMESPACE, prepared.outbox.root().unwrap()),
            3 => (crate::ADMISSION_INVARIANT_EVIDENCE_KEY_PREFIX, prepared.materialization.record.invariant_evidence_root),
            _ => (crate::ADMISSION_OUTBOX_EFFECT_BATCH_KEY_PREFIX, prepared.materialization.record.outbox_effect_root),
        };
        let slot = admission_immutable_key(namespace, node.repository_id, root).unwrap();
        assert!(matches!(node.runtime().block_on(node.authority.put_if_absent(
            request.authority(), &slot, b"deliberately conflicting immutable fixture",
        )).unwrap(), PutOutcome::Created));
        assert!(matches!(apply(&node, &offer, b"failed-stage", 7),
            Err(AdmissionError::AsyncProjectionUnavailable(RefusalCode::EvidenceInvalid))));
        assert_eq!(snapshot(&node).basis(), before.basis());
        let lookup = node.runtime().block_on(fgit_authority::resolve_outcome_async(
            &node.authority, request.authority(), &node.head_key,
            node.tenant_id, node.repository_id, tx_id,
        )).unwrap();
        assert_eq!(lookup, OutcomeLookup::Undecided);
        node.shutdown().unwrap();
    }
}

#[test]
fn package_objects_must_belong_to_the_independently_validated_commit_closure() {
    let scratch = Scratch::new();
    let node = new_node(&scratch, GitHashAlgorithm::Sha1);
    let f = fixture(&node, &scratch, true);
    let mut offer = offered(&node, &f, 1, 7, b"invented-object");
    let invented = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, b"unrelated missing object");
    offer.package.objects.push(invented);
    offer.closure.objects.insert(invented);
    offer.closure.object_closure_root = permitted_object_closure_root(
        &PermittedObjectClosure::new(offer.closure.objects.clone()),
    ).unwrap();
    // The legacy structural checks alone admit these internally consistent
    // claims. The new path must check them against actual verified reachability.
    assert!(seal_attempt_for(&context(&node, b"invented-object"),
        &offer.sealed(WorkspaceEpoch::from_u64(7))).is_ok());
    let before = snapshot(&node);
    let refused = apply(&node, &offer, b"invented-object", 7).unwrap();
    assert!(matches!(refused.outcome, DecisionOutcome::Refused {
        code: RefusalCode::ObjectClosureIncomplete, ..
    }));
    let after = snapshot(&node);
    assert_eq!(after.basis().body().ref_root, before.basis().body().ref_root);
    assert_eq!(after.basis().body().forge_position_root, before.basis().body().forge_position_root);
    assert_eq!(after.basis().body().outbox_root, before.basis().body().outbox_root);
    node.shutdown().unwrap();
}

#[test]
fn every_supplied_evidence_identity_is_checked_before_coupled_publication() {
    for field in 0..6 {
        let scratch = Scratch::new();
        let node = new_node(&scratch, GitHashAlgorithm::Sha1);
        let f = fixture(&node, &scratch, true);
        let valid = offered(&node, &f, 1, 7, b"checked-evidence");
        let mut forged = valid.clone();
        let unrelated = unrelated_evidence();
        match field {
            0 => forged.evidence.principal_snapshot_id = unrelated.principal_snapshot_id,
            1 => forged.evidence.forge_event_batch_root = unrelated.forge_event_batch_root,
            2 => forged.evidence.policy_decision_root = unrelated.policy_decision_root,
            3 => forged.evidence.invariant_evidence_root = unrelated.invariant_evidence_root,
            4 => forged.evidence.outbox_effect_root = unrelated.outbox_effect_root,
            _ => forged.evidence.retention_delta_root = unrelated.retention_delta_root,
        }
        assert_ne!(forged.evidence, valid.evidence);
        let before = snapshot(&node);
        let refused = apply(&node, &forged, b"checked-evidence", 7).unwrap();
        assert!(matches!(refused.outcome, DecisionOutcome::Refused {
            code: RefusalCode::EvidenceInvalid, ..
        }), "evidence field {field}: {refused:?}");
        let after = snapshot(&node);
        assert_eq!(after.basis().body().ref_root, before.basis().body().ref_root);
        assert_eq!(after.basis().body().forge_position_root, before.basis().body().forge_position_root);
        assert_eq!(after.basis().body().outbox_root, before.basis().body().outbox_root);
        assert_eq!(after.basis().body().retention_root, before.basis().body().retention_root);
        assert_eq!(apply(&node, &valid, b"checked-evidence", 7).unwrap(), refused);
        assert_eq!(snapshot(&node).basis(), after.basis());
        node.shutdown().unwrap();
    }
}
