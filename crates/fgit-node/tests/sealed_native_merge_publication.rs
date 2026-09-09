#![forbid(unsafe_code)]
//! Original sealed-package API against real embedded authority and native objects.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_admission::evidence::{DecisionEvidenceBodies, evidence_root, principal_snapshot_id};
use fgit_admission::merge::native::{
    NativeMergeIntent,
    objects::{MergeObjectLimits, validate_merge_objects},
};
use fgit_admission::merge::{SealedMerge, seal_attempt_for};
use fgit_admission::{
    AdmissionContext, AdmissionError, AdmissionLimits, CommitEvidence, PermittedObjectClosure,
    ValidatedClosure, permitted_object_closure_root,
};
use fgit_authority::{HeadKey, IdempotencyKey, TerminalOutcome};
use fgit_codec::{OutboxDeliveryIdentityInput, derive_outbox_delivery_key};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::aggregate::{ExpectedVersion, PullRequestNumber};
use fgit_forge::event::{ForgeEventBatch, NativeMerge};
use fgit_forge::{MergeAttempt, MergeEffectPackage, RefIntent as ForgeRefIntent, WorkspaceEpoch};
use fgit_git_object::ObjectType;
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_object_fabric::ObjectKind;
use fgit_pack::{CanonicalObjectSource, CanonicalPackObject, PackWriteError};
use fgit_reference::intent::{
    DurabilityProfile, ForgeEntityId, ForgeEventKind, ForgeIntent, ForgeStreamId,
    ForgeStreamPosition, IdempotencyKey as ModelKey, Intent, OutboxDeliveryKey, OutboxIntent,
    RefIntent, Statement, TransactionRequest,
};
use fgit_reference::refs::ExpectedRefState;
use fgit_txn::IntentEvaluator;
use fgit_types::{
    AsciiSlug, DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, MismatchPolicy,
    PrincipalId, RefName, RefusalCode, RepositoryId, TenantId,
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fgit-sealed-native-merge-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn repository() -> RepositoryId {
    RepositoryId::from_bytes([0x81; 16])
}
fn config(root: &Path, format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(
        root.join("node"),
        TenantId::from_bytes([0x80; 16]),
        repository(),
    )
    .with_object_format(format)
    .with_worker_threads(2)
}
fn session(key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0x82; 16]),
        IdempotencyKey::new(key.to_vec()).unwrap(),
    )
}
fn main_ref() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}
fn topic_ref() -> RefName {
    RefName::try_new(b"refs/heads/topic").unwrap()
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
    let mut zlib = vec![0x78, 0x01, 0x01];
    zlib.extend(length.to_le_bytes());
    zlib.extend((!length).to_le_bytes());
    zlib.extend(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521;
        (a, (b + a) % 65_521)
    });
    zlib.extend(((b << 16) | a).to_be_bytes());
    let hex = id.to_string();
    let parent = root.join("objects").join(&hex[..2]);
    fs::create_dir_all(&parent).unwrap();
    fs::write(parent.join(&hex[2..]), zlib).unwrap();
    id
}
fn tree(entries: &[(&str, GitOid)]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (name, oid) in entries {
        bytes.extend(format!("100644 {name}\0").as_bytes());
        bytes.extend(oid.as_bytes());
    }
    bytes
}
fn commit(tree: GitOid, parents: &[GitOid], message: &str) -> Vec<u8> {
    let mut body = format!("tree {tree}\n");
    for parent in parents {
        body.push_str(&format!("parent {parent}\n"));
    }
    body.push_str("author Merge Test <merge@example.invalid> 1 +0000\ncommitter Merge Test <merge@example.invalid> 1 +0000\n\n");
    body.push_str(message);
    body.into_bytes()
}
#[derive(Clone)]
struct Fixture {
    base: GitOid,
    target: GitOid,
    source: GitOid,
    merged_tree: GitOid,
    candidate: GitOid,
    candidate_body: Vec<u8>,
}

/// Fixture self-checks read the same real fabric objects as native admission.
struct NodeObjects<'a>(&'a OneNode);
impl CanonicalObjectSource for NodeObjects<'_> {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        let object = self
            .0
            .read_git_object(*id)
            .map_err(|_| PackWriteError::MissingCanonicalObject(*id))?;
        let kind = match object.envelope().object_kind() {
            ObjectKind::Commit => ObjectType::Commit,
            ObjectKind::Tree => ObjectType::Tree,
            ObjectKind::Blob => ObjectType::Blob,
            ObjectKind::Tag => ObjectType::Tag,
            ObjectKind::Internal => return Err(PackWriteError::MissingCanonicalObject(*id)),
        };
        Ok(CanonicalPackObject::new(
            object.identity(),
            kind,
            object.payload().to_vec(),
            Vec::new(),
            0,
            0,
        ))
    }
}

fn fixture(node: &OneNode, root: &Path, format: GitHashAlgorithm, stage_commit: bool) -> Fixture {
    let source = root.join("source");
    fs::create_dir_all(source.join("refs/heads")).unwrap();
    fs::write(source.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    let configuration = match format {
        GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
        GitHashAlgorithm::Sha256 => {
            "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n"
        }
    };
    fs::write(source.join("config"), configuration).unwrap();
    let common = loose(&source, format, GitObjectKind::Blob, "blob", b"common\n");
    let ours = loose(&source, format, GitObjectKind::Blob, "blob", b"ours\n");
    let theirs = loose(&source, format, GitObjectKind::Blob, "blob", b"theirs\n");
    let base_tree = loose(
        &source,
        format,
        GitObjectKind::Tree,
        "tree",
        &tree(&[("file.txt", common)]),
    );
    let target_tree = loose(
        &source,
        format,
        GitObjectKind::Tree,
        "tree",
        &tree(&[("file.txt", common), ("ours.txt", ours)]),
    );
    let source_tree = loose(
        &source,
        format,
        GitObjectKind::Tree,
        "tree",
        &tree(&[("file.txt", common), ("theirs.txt", theirs)]),
    );
    let base = loose(
        &source,
        format,
        GitObjectKind::Commit,
        "commit",
        &commit(base_tree, &[], "base\n"),
    );
    let target = loose(
        &source,
        format,
        GitObjectKind::Commit,
        "commit",
        &commit(target_tree, &[base], "target\n"),
    );
    let topic = loose(
        &source,
        format,
        GitObjectKind::Commit,
        "commit",
        &commit(source_tree, &[base], "topic\n"),
    );
    fs::write(source.join("refs/heads/main"), format!("{target}\n")).unwrap();
    fs::write(source.join("refs/heads/topic"), format!("{topic}\n")).unwrap();
    let request = node.request_context();
    let imported = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &request,
            &source,
            PrincipalId::from_bytes([0x82; 16]),
            b"native-merge-fixture",
        ))
        .unwrap();
    assert!(
        imported
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    let merged_tree = node
        .put_git_object(
            GitObjectKind::Tree,
            tree(&[
                ("file.txt", common),
                ("ours.txt", ours),
                ("theirs.txt", theirs),
            ]),
        )
        .unwrap()
        .identity();
    let candidate_body = commit(merged_tree, &[target, topic], "reviewed merge\n");
    let candidate = git_object_id(format, GitObjectKind::Commit, &candidate_body);
    if stage_commit {
        assert_eq!(
            node.put_git_object(GitObjectKind::Commit, candidate_body.clone())
                .unwrap()
                .identity(),
            candidate
        );
    }
    let fixture = Fixture {
        base,
        target,
        source: topic,
        merged_tree,
        candidate,
        candidate_body,
    };
    if stage_commit {
        let offered = intent(&fixture, 1, ExpectedVersion::NewStream);
        let closure = validate_merge_objects(
            &NodeObjects(node),
            offered.merge().unwrap(),
            MergeObjectLimits::default(),
            &mut || true,
        )
        .expect("positive publication fixture must pass native validation before admission");
        assert_eq!(
            closure.objects,
            BTreeSet::from([
                common,
                ours,
                theirs,
                base_tree,
                target_tree,
                source_tree,
                merged_tree,
                base,
                target,
                topic,
                candidate,
            ])
        );
    }
    fixture
}
fn intent(f: &Fixture, number: u64, version: ExpectedVersion) -> NativeMergeIntent {
    NativeMergeIntent::new(
        PullRequestNumber::try_new(number).unwrap(),
        version,
        NativeMerge {
            source_ref: topic_ref(),
            source_tip: f.source,
            base_tip: f.base,
            target_ref: main_ref(),
            target_tip_before: f.target,
            merge_commit: f.candidate,
        },
    )
    .unwrap()
}

fn context(format: GitHashAlgorithm, key: &[u8]) -> AdmissionContext {
    AdmissionContext {
        head_key: HeadKey::new(
            [b"frankengit/node/head/".as_slice(), repository().as_bytes()].concat(),
        )
        .unwrap(),
        tenant_id: TenantId::from_bytes([0x80; 16]),
        repository_id: repository(),
        principal_id: PrincipalId::from_bytes([0x82; 16]),
        idempotency_key: IdempotencyKey::new(key.to_vec()).unwrap(),
        object_format: format,
    }
}

#[derive(Clone)]
struct Package {
    effect: MergeEffectPackage,
    attempt: MergeAttempt,
    closure: ValidatedClosure,
    evidence: CommitEvidence,
    workspace_epoch_now: WorkspaceEpoch,
}
impl Package {
    fn sealed(&self) -> SealedMerge<'_> {
        SealedMerge {
            package: &self.effect,
            attempt: &self.attempt,
            closure: &self.closure,
            evidence: self.evidence,
            workspace_epoch_now: self.workspace_epoch_now,
        }
    }
}

fn closure(objects: BTreeSet<GitOid>) -> ValidatedClosure {
    ValidatedClosure {
        object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
            objects.clone(),
        ))
        .unwrap(),
        objects,
    }
}

/// Prepare caller evidence from the public evaluator at a real authenticated
/// basis. This helper does not publish, stage evidence, or call admission's
/// private preparer; the node must independently reproduce the same evidence.
fn package(
    node: &OneNode,
    f: &Fixture,
    context: &AdmissionContext,
    supplied: ValidatedClosure,
) -> Package {
    let request_context = node.request_context();
    let before = node
        .runtime()
        .block_on(node.materialize_admission_in(&request_context))
        .unwrap();
    let history = node
        .runtime()
        .block_on(node.snapshot_history_in(&request_context))
        .unwrap();
    let prior = history
        .iter()
        .rev()
        .find_map(|entry| entry.batch.committed_rcrs.last())
        .unwrap();
    let mut package = Package {
        effect: MergeEffectPackage {
            objects: vec![f.candidate, f.merged_tree],
            ref_intent: ForgeRefIntent {
                name: main_ref().as_bytes().to_vec(),
                expected_tip: f.target,
                new_tip: f.candidate,
            },
            event: intent(f, 1, ExpectedVersion::NewStream).event().clone(),
        },
        attempt: MergeAttempt {
            pull_request: PullRequestNumber::try_new(1).unwrap(),
            source_ref: topic_ref().as_bytes().to_vec(),
            target_ref: main_ref().as_bytes().to_vec(),
            source_tip: f.source,
            target_tip: f.target,
            base_tip: f.base,
            workspace_epoch: WorkspaceEpoch::from_u64(1),
        },
        closure: supplied,
        // Evidence is outside request identity. Start with real prior evidence
        // solely to construct the original seal, then derive this exact fold.
        evidence: CommitEvidence {
            principal_snapshot_id: prior.principal_snapshot_id,
            forge_event_batch_root: prior.forge_event_batch_root,
            policy_decision_root: prior.policy_decision_root,
            invariant_evidence_root: prior.invariant_evidence_root,
            outbox_effect_root: prior.outbox_effect_root,
            retention_delta_root: prior.retention_delta_root,
        },
        workspace_epoch_now: WorkspaceEpoch::from_u64(1),
    };
    let attempt = seal_attempt_for(context, &package.sealed()).unwrap();
    let tx_id = attempt.derive().unwrap().0;
    let event_root = evidence_root(&ForgeEventBatch::of_one(package.effect.event.clone())).unwrap();
    let label = AsciiSlug::from_static("pull-request/1");
    let delivery_key = derive_outbox_delivery_key(OutboxDeliveryIdentityInput::new(
        repository(),
        AsciiSlug::from_static("forge-event"),
        AsciiSlug::from_static("forge-projection"),
        event_root,
        tx_id,
        before.basis().body().latest_committed_rcr_id,
    ))
    .unwrap();
    let request = TransactionRequest {
        tx_id,
        tenant: context.tenant_id,
        repository: repository(),
        principal: context.principal_id,
        schema: attempt.request.request_schema(),
        idempotency_key: ModelKey::new(AsciiSlug::from_static("receive")),
        canonical_request_digest: fgit_authority::canonical_request_digest(&attempt.request)
            .unwrap(),
        statements: vec![Statement {
            intents: vec![
                Intent::Ref(RefIntent::Update {
                    name: main_ref(),
                    expected: ExpectedRefState::Exact(f.target),
                    new: f.candidate,
                    force: false,
                }),
                Intent::Forge(ForgeIntent {
                    stream: ForgeStreamId::new(label),
                    expected_position: ForgeStreamPosition::GENESIS,
                    event: ForgeEventKind::PullRequestMerged {
                        pull_request: ForgeEntityId::new(label),
                        target: main_ref(),
                    },
                }),
                Intent::Outbox(OutboxIntent {
                    delivery_key: OutboxDeliveryKey::new(delivery_key),
                    parameters: event_root,
                }),
            ],
            mismatch_policy: MismatchPolicy::TxnAbort,
        }],
        promised_closure: package.closure.objects.clone(),
        atomic: true,
        durability: DurabilityProfile::CanonicalSource,
    };
    let snapshot = before.snapshot();
    let fold = IntentEvaluator::new().evaluate(
        fgit_reference::effect::FoldBasis {
            refs: &snapshot.refs,
            forge_positions: &snapshot.forge_positions,
            retention: &snapshot.retention,
            outbox: &snapshot.outbox,
        },
        &request,
    );
    let bodies = DecisionEvidenceBodies::derive(context, before.basis(), &request, &fold).unwrap();
    package.evidence = CommitEvidence {
        principal_snapshot_id: principal_snapshot_id(bodies.principal_snapshot()).unwrap(),
        forge_event_batch_root: event_root,
        policy_decision_root: evidence_root(bodies.policy_decision()).unwrap(),
        invariant_evidence_root: evidence_root(bodies.invariant_evidence()).unwrap(),
        outbox_effect_root: evidence_root(bodies.outbox_effect_batch()).unwrap(),
        retention_delta_root: evidence_root(bodies.retention_delta()).unwrap(),
    };
    package
}

fn exact_package(node: &OneNode, f: &Fixture, context: &AdmissionContext) -> Package {
    let offered = intent(f, 1, ExpectedVersion::NewStream);
    let exact = validate_merge_objects(
        &NodeObjects(node),
        offered.merge().unwrap(),
        MergeObjectLimits::default(),
        &mut || true,
    )
    .unwrap();
    package(node, f, context, exact)
}

fn apply(
    node: &OneNode,
    context: &AdmissionContext,
    package: &Package,
) -> Result<TerminalOutcome, AdmissionError> {
    let request = node.request_context();
    node.runtime().block_on(node.admit_merge_durable_in(
        &request,
        context,
        &package.sealed(),
        AdmissionLimits::default(),
    ))
}

fn snapshot(node: &OneNode) -> fgit_node::MaterializedAdmission {
    let request = node.request_context();
    node.runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap()
}

fn assert_unchanged_effects(
    before: &fgit_node::MaterializedAdmission,
    after: &fgit_node::MaterializedAdmission,
) {
    assert_eq!(before.snapshot().refs, after.snapshot().refs);
    assert_eq!(before.snapshot().head_target, after.snapshot().head_target);
    assert_eq!(
        before.basis().body().ref_root,
        after.basis().body().ref_root
    );
    assert_eq!(
        before.basis().body().forge_position_root,
        after.basis().body().forge_position_root
    );
    assert_eq!(
        before.basis().body().outbox_root,
        after.basis().body().outbox_root
    );
    assert_eq!(
        before.basis().body().retention_root,
        after.basis().body().retention_root
    );
}

#[test]
fn original_sealed_identity_publishes_coupled_effects_and_recovers_after_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (mut node, _) = OneNode::init(config(&scratch.0, format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let f = fixture(&node, &scratch.0, format, true);
        let context = context(format, b"sealed-native-permitted");
        let mut package = exact_package(&node, &f, &context);
        let original = seal_attempt_for(&context, &package.sealed()).unwrap();
        let native = intent(&f, 1, ExpectedVersion::NewStream)
            .seal_attempt(&context)
            .unwrap();
        assert_ne!(
            original, native,
            "the original ref-intent and epoch entries must survive"
        );
        let before = snapshot(&node);
        let terminal = apply(&node, &context, &package).unwrap();
        let DecisionOutcome::Committed {
            repository_commit_id,
        } = terminal.outcome
        else {
            panic!("permitted sealed native merge must commit: {terminal:?}");
        };
        let after = snapshot(&node);
        assert_eq!(after.snapshot().refs[&main_ref()], f.candidate);
        assert_eq!(after.snapshot().refs[&topic_ref()], f.source);
        assert_eq!(after.snapshot().head_target, before.snapshot().head_target);
        assert_eq!(after.snapshot().forge_positions.len(), 1);
        assert_eq!(after.snapshot().outbox.len(), 1);
        assert_ne!(
            before.basis().body().ref_root,
            after.basis().body().ref_root
        );
        assert_ne!(
            before.basis().body().forge_position_root,
            after.basis().body().forge_position_root
        );
        assert_ne!(
            before.basis().body().outbox_root,
            after.basis().body().outbox_root
        );
        let request = node.request_context();
        let history = node
            .runtime()
            .block_on(node.snapshot_history_in(&request))
            .unwrap();
        let last = history.last().unwrap();
        assert_eq!(last.forge_events, vec![package.effect.event.clone()]);
        assert_eq!(last.batch.committed_rcrs.len(), 1);
        let record = &last.batch.committed_rcrs[0];
        assert_eq!(record.tx_id, original.derive().unwrap().0);
        assert_eq!(
            record.canonical_request_digest,
            fgit_authority::canonical_request_digest(&original.request).unwrap()
        );
        assert_eq!(
            record.principal_snapshot_id,
            package.evidence.principal_snapshot_id
        );
        assert_eq!(
            record.forge_event_batch_root,
            package.evidence.forge_event_batch_root
        );
        assert_eq!(
            record.invariant_evidence_root,
            package.evidence.invariant_evidence_root
        );
        assert_eq!(
            record.outbox_effect_root,
            package.evidence.outbox_effect_root
        );
        assert_eq!(
            after.basis().body().latest_committed_rcr_id,
            Some(repository_commit_id)
        );
        // Terminal recovery must precede both changed refs and a now-stale
        // caller epoch. Neither field changes the original sealed attempt.
        package.workspace_epoch_now = WorkspaceEpoch::from_u64(2);
        assert_eq!(
            seal_attempt_for(&context, &package.sealed()).unwrap(),
            original
        );
        assert_eq!(apply(&node, &context, &package).unwrap(), terminal);
        let next_id = node
            .put_git_object(
                GitObjectKind::Commit,
                commit(
                    f.merged_tree,
                    &[f.candidate, f.source],
                    "later reviewed merge\n",
                ),
            )
            .unwrap()
            .identity();
        let next_fixture = Fixture {
            target: f.candidate,
            candidate: next_id,
            ..f.clone()
        };
        let next = intent(&next_fixture, 2, ExpectedVersion::NewStream);
        let request = node.request_context();
        let later = node
            .runtime()
            .block_on(node.admit_native_merge_durable_in(
                &request,
                &session(b"later-native-merge"),
                &next,
                AdmissionLimits::default(),
                MergeObjectLimits::default(),
            ))
            .unwrap();
        assert!(matches!(later.outcome, DecisionOutcome::Committed { .. }));
        assert_eq!(apply(&node, &context, &package).unwrap(), terminal);
        let advanced = snapshot(&node);
        assert_eq!(advanced.snapshot().refs[&main_ref()], next_id);
        assert_eq!(advanced.snapshot().outbox.len(), 2);
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(config(&scratch.0, format)).unwrap();
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(apply(&reopened, &context, &package).unwrap(), terminal);
        assert_eq!(snapshot(&reopened).basis(), advanced.basis());
        reopened.shutdown().unwrap();
    }
}

#[test]
fn unvalidated_extra_closure_refuses_and_exact_closure_permits() {
    let scratch = Scratch::new();
    let (mut node, _) = OneNode::init(config(&scratch.0, GitHashAlgorithm::Sha1)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let f = fixture(&node, &scratch.0, GitHashAlgorithm::Sha1, true);
    let rejected_context = context(GitHashAlgorithm::Sha1, b"extra-closure");
    let exact = exact_package(&node, &f, &rejected_context);
    let mut extra = exact.closure.objects.clone();
    extra.insert(git_object_id(
        GitHashAlgorithm::Sha1,
        GitObjectKind::Blob,
        b"never staged or referenced",
    ));
    let rejected = package(&node, &f, &rejected_context, closure(extra));
    let before = snapshot(&node);
    let refused = apply(&node, &rejected_context, &rejected).unwrap();
    assert!(matches!(
        refused.outcome,
        DecisionOutcome::Refused {
            code: RefusalCode::ObjectClosureIncomplete,
            ..
        }
    ));
    assert_unchanged_effects(&before, &snapshot(&node));
    // Closure is derived evidence, excluded from request identity: repairing
    // it after a terminal refusal cannot silently revive the same transaction.
    assert_eq!(apply(&node, &rejected_context, &exact).unwrap(), refused);
    let permitted_context = context(GitHashAlgorithm::Sha1, b"exact-closure");
    let permitted = exact_package(&node, &f, &permitted_context);
    assert!(matches!(
        apply(&node, &permitted_context, &permitted)
            .unwrap()
            .outcome,
        DecisionOutcome::Committed { .. }
    ));
    node.shutdown().unwrap();
}

#[test]
fn forged_closure_root_and_incoherent_native_attempt_fail_before_publication() {
    let scratch = Scratch::new();
    let (mut node, _) = OneNode::init(config(&scratch.0, GitHashAlgorithm::Sha1)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let f = fixture(&node, &scratch.0, GitHashAlgorithm::Sha1, true);
    let context = context(GitHashAlgorithm::Sha1, b"coherent-seal");
    let permitted = exact_package(&node, &f, &context);
    let before = snapshot(&node);
    let mut forged = permitted.clone();
    forged.closure.object_closure_root = before.basis().body().ref_root;
    assert!(matches!(
        apply(&node, &context, &forged),
        Err(AdmissionError::MergeIncoherent {
            field: "object closure root"
        })
    ));
    let mut incoherent = permitted.clone();
    incoherent.attempt.source_tip = f.base;
    assert!(matches!(
        apply(&node, &context, &incoherent),
        Err(AdmissionError::MergeIncoherent {
            field: "native event and sealed attempt"
        })
    ));
    assert_eq!(snapshot(&node).basis(), before.basis());
    assert!(matches!(
        apply(&node, &context, &permitted).unwrap().outcome,
        DecisionOutcome::Committed { .. }
    ));
    node.shutdown().unwrap();
}

#[test]
fn supplied_evidence_cannot_replace_the_current_fold() {
    let scratch = Scratch::new();
    let (mut node, _) = OneNode::init(config(&scratch.0, GitHashAlgorithm::Sha1)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let f = fixture(&node, &scratch.0, GitHashAlgorithm::Sha1, true);
    let context = context(GitHashAlgorithm::Sha1, b"forged-evidence");
    let exact = exact_package(&node, &f, &context);
    let mut forged = exact.clone();
    forged.evidence.policy_decision_root = forged.evidence.invariant_evidence_root;
    let before = snapshot(&node);
    let refused = apply(&node, &context, &forged).unwrap();
    assert!(matches!(
        refused.outcome,
        DecisionOutcome::Refused {
            code: RefusalCode::EvidenceInvalid,
            ..
        }
    ));
    assert_unchanged_effects(&before, &snapshot(&node));
    assert_eq!(apply(&node, &context, &exact).unwrap(), refused);
    node.shutdown().unwrap();
}

#[test]
fn real_candidate_bytes_must_have_the_exact_ordered_parents() {
    for parents_reversed in [false, true] {
        let scratch = Scratch::new();
        let (mut node, _) = OneNode::init(config(&scratch.0, GitHashAlgorithm::Sha1)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let f = fixture(&node, &scratch.0, GitHashAlgorithm::Sha1, true);
        let context = context(GitHashAlgorithm::Sha1, b"wrong-parents");
        let exact = exact_package(&node, &f, &context);
        let parents = if parents_reversed {
            vec![f.source, f.target]
        } else {
            vec![f.target]
        };
        let bad = node
            .put_git_object(
                GitObjectKind::Commit,
                commit(f.merged_tree, &parents, "wrong parents\n"),
            )
            .unwrap()
            .identity();
        let mut objects = exact.closure.objects.clone();
        objects.remove(&f.candidate);
        objects.insert(bad);
        let candidate = Fixture {
            candidate: bad,
            ..f.clone()
        };
        let rejected = package(&node, &candidate, &context, closure(objects));
        let before = snapshot(&node);
        let refused = apply(&node, &context, &rejected).unwrap();
        assert!(matches!(
            refused.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::EvidenceInvalid,
                ..
            }
        ));
        assert_unchanged_effects(&before, &snapshot(&node));
        node.shutdown().unwrap();
    }
}

#[test]
fn missing_native_candidate_stays_retryable_until_real_bytes_arrive() {
    let scratch = Scratch::new();
    let (mut node, _) = OneNode::init(config(&scratch.0, GitHashAlgorithm::Sha256)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let f = fixture(&node, &scratch.0, GitHashAlgorithm::Sha256, false);
    let context = context(GitHashAlgorithm::Sha256, b"missing-native-body");
    let before = snapshot(&node);
    let mut objects = before.selected_closure().closure().objects().clone();
    objects.extend([f.merged_tree, f.candidate]);
    let offered = package(&node, &f, &context, closure(objects));
    let original = seal_attempt_for(&context, &offered.sealed()).unwrap();
    assert!(matches!(
        apply(&node, &context, &offered),
        Err(AdmissionError::AsyncProjectionUnavailable(
            RefusalCode::EvidenceMissing
        ))
    ));
    assert_eq!(snapshot(&node).basis(), before.basis());
    assert_eq!(
        node.put_git_object(GitObjectKind::Commit, f.candidate_body.clone())
            .unwrap()
            .identity(),
        f.candidate
    );
    let exact = exact_package(&node, &f, &context);
    assert_eq!(exact.closure, offered.closure);
    assert_eq!(
        seal_attempt_for(&context, &exact.sealed()).unwrap(),
        original
    );
    let terminal = apply(&node, &context, &exact).unwrap();
    assert!(matches!(
        terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    let request = node.request_context();
    let history = node
        .runtime()
        .block_on(node.snapshot_history_in(&request))
        .unwrap();
    assert_eq!(
        history.last().unwrap().batch.committed_rcrs[0].tx_id,
        original.derive().unwrap().0
    );
    node.shutdown().unwrap();
}

#[test]
fn stale_source_target_and_workspace_keep_their_existing_refusal_priority() {
    for moved in ["source", "target", "workspace"] {
        let scratch = Scratch::new();
        let (mut node, _) = OneNode::init(config(&scratch.0, GitHashAlgorithm::Sha1)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let f = fixture(&node, &scratch.0, GitHashAlgorithm::Sha1, true);
        let context = context(GitHashAlgorithm::Sha1, b"stale-sealed-attempt");
        let mut stale = exact_package(&node, &f, &context);
        // If a ref also moved, ref staleness still wins over the epoch mismatch.
        stale.workspace_epoch_now = WorkspaceEpoch::from_u64(2);
        if moved != "workspace" {
            let winner = if moved == "source" {
                let candidate = node
                    .put_git_object(
                        GitObjectKind::Commit,
                        commit(f.merged_tree, &[f.source, f.target], "source advanced\n"),
                    )
                    .unwrap()
                    .identity();
                NativeMergeIntent::new(
                    PullRequestNumber::try_new(99).unwrap(),
                    ExpectedVersion::NewStream,
                    NativeMerge {
                        source_ref: main_ref(),
                        source_tip: f.target,
                        base_tip: f.base,
                        target_ref: topic_ref(),
                        target_tip_before: f.source,
                        merge_commit: candidate,
                    },
                )
                .unwrap()
            } else {
                intent(&f, 99, ExpectedVersion::NewStream)
            };
            let request = node.request_context();
            let terminal = node
                .runtime()
                .block_on(node.admit_native_merge_durable_in(
                    &request,
                    &session(b"fresh-winner"),
                    &winner,
                    AdmissionLimits::default(),
                    MergeObjectLimits::default(),
                ))
                .unwrap();
            assert!(matches!(
                terminal.outcome,
                DecisionOutcome::Committed { .. }
            ));
        }
        let before = snapshot(&node);
        let refused = apply(&node, &context, &stale).unwrap();
        let expected = if moved == "workspace" {
            RefusalCode::EvidenceStale
        } else {
            RefusalCode::TargetRefMoved
        };
        assert!(
            matches!(refused.outcome, DecisionOutcome::Refused { code, .. } if code == expected),
            "{moved}: {refused:?}"
        );
        assert_unchanged_effects(&before, &snapshot(&node));
        assert_eq!(apply(&node, &context, &stale).unwrap(), refused);
        node.shutdown().unwrap();
    }
}
