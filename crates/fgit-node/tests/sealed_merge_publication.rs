#![forbid(unsafe_code)]
//! Exercises the original public sealed-package API against actual embedded
//! authority storage. No test publication engine or fake staging success.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_admission::evidence::{DecisionEvidenceBodies, evidence_root, principal_snapshot_id};
use fgit_admission::merge::native::objects::{MergeObjectLimits, validate_merge_objects};
use fgit_admission::merge::{SealedMerge, seal_attempt_for};
use fgit_admission::{
    AdmissionContext, AdmissionLimits, CommitEvidence, PermittedObjectClosure, ValidatedClosure,
    permitted_object_closure_root,
};
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_codec::{OutboxDeliveryIdentityInput, derive_outbox_delivery_key};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::event::NativeMerge;
use fgit_forge::{
    AggregateId, AggregateVersion, ForgeEvent, ForgeEventPayload, MergeAttempt, MergeEffectPackage,
    PullRequestNumber, RefIntent, WorkspaceEpoch,
};
use fgit_node::{NodeConfig, OneNode};
use fgit_object_fabric::ObjectKind;
use fgit_pack::{CanonicalObjectSource, CanonicalPackObject, PackWriteError};
use fgit_reference::effect::{FoldBasis, FoldOutcome};
use fgit_reference::intent::{
    DurabilityProfile, ForgeEntityId, ForgeEventKind, ForgeIntent, ForgeStreamId,
    ForgeStreamPosition, IdempotencyKey as ModelKey, Intent, OutboxDeliveryKey, OutboxIntent,
    RefIntent as ModelRefIntent, Statement, TransactionRequest,
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
        let path = std::env::temp_dir().join(format!(
            "fgit-sealed-native-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(
            self.0.join("node"),
            TenantId::from_bytes([0x51; 16]),
            RepositoryId::from_bytes([0x52; 16]),
        )
        .with_object_format(format)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn principal() -> PrincipalId {
    PrincipalId::from_bytes([0x53; 16])
}
fn main_ref() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}
fn topic_ref() -> RefName {
    RefName::try_new(b"refs/heads/topic").unwrap()
}
fn commit(tree: GitOid, parents: &[GitOid], message: &str) -> Vec<u8> {
    let mut body = format!("tree {tree}\n");
    for parent in parents {
        body.push_str(&format!("parent {parent}\n"));
    }
    body.push_str("author Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\n");
    body.push_str(message);
    body.into_bytes()
}
fn loose(
    directory: &Path,
    format: GitHashAlgorithm,
    kind: GitObjectKind,
    label: &str,
    body: &[u8],
) -> GitOid {
    let oid = git_object_id(format, kind, body);
    let raw = [format!("{label} {}\0", body.len()).as_bytes(), body].concat();
    let n = u16::try_from(raw.len()).unwrap();
    let mut bytes = vec![0x78, 0x01, 0x01];
    bytes.extend(n.to_le_bytes());
    bytes.extend((!n).to_le_bytes());
    bytes.extend(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521;
        (a, (b + a) % 65_521)
    });
    bytes.extend(((b << 16) | a).to_be_bytes());
    let hex = oid.to_string();
    let parent = directory.join("objects").join(&hex[..2]);
    fs::create_dir_all(&parent).unwrap();
    fs::write(parent.join(&hex[2..]), bytes).unwrap();
    oid
}
struct Offer {
    package: MergeEffectPackage,
    attempt: MergeAttempt,
    closure: ValidatedClosure,
    evidence: CommitEvidence,
    predecessor_evidence: CommitEvidence,
}
impl Offer {
    fn sealed(&self, now: WorkspaceEpoch) -> SealedMerge<'_> {
        SealedMerge {
            package: &self.package,
            attempt: &self.attempt,
            closure: &self.closure,
            evidence: self.evidence,
            workspace_epoch_now: now,
        }
    }
}

struct NodeObjects<'a>(&'a OneNode);
impl CanonicalObjectSource for NodeObjects<'_> {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        let object = self
            .0
            .read_git_object(*id)
            .map_err(|_| PackWriteError::MissingCanonicalObject(*id))?;
        let kind = match object.envelope().object_kind() {
            ObjectKind::Commit => GitObjectKind::Commit,
            ObjectKind::Tree => GitObjectKind::Tree,
            ObjectKind::Blob => GitObjectKind::Blob,
            ObjectKind::Tag => GitObjectKind::Tag,
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

fn setup(node: &OneNode, scratch: &Scratch, format: GitHashAlgorithm) -> Offer {
    let directory = scratch.0.join("source");
    fs::create_dir_all(directory.join("refs/heads")).unwrap();
    fs::write(directory.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(directory.join("config"), match format {
        GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
        GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
    }).unwrap();
    let blob = loose(
        &directory,
        format,
        GitObjectKind::Blob,
        "blob",
        b"source bytes\n",
    );
    let tree_body = [b"100644 file.txt\0".as_slice(), blob.as_bytes()].concat();
    let tree = loose(&directory, format, GitObjectKind::Tree, "tree", &tree_body);
    let base = loose(
        &directory,
        format,
        GitObjectKind::Commit,
        "commit",
        &commit(tree, &[], "base\n"),
    );
    let target = loose(
        &directory,
        format,
        GitObjectKind::Commit,
        "commit",
        &commit(tree, &[base], "target\n"),
    );
    let source = loose(
        &directory,
        format,
        GitObjectKind::Commit,
        "commit",
        &commit(tree, &[base], "source\n"),
    );
    fs::write(directory.join("refs/heads/main"), format!("{target}\n")).unwrap();
    fs::write(directory.join("refs/heads/topic"), format!("{source}\n")).unwrap();
    let request = node.request_context();
    let imported = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &request,
            &directory,
            principal(),
            b"sealed-native-source",
        ))
        .unwrap();
    assert!(
        imported
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    let candidate = node
        .put_git_object(
            GitObjectKind::Commit,
            commit(tree, &[target, source], "reviewed native merge\n"),
        )
        .unwrap()
        .identity();
    let request = node.request_context();
    let selected = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    let mut objects = selected.selected_closure().closure().objects().clone();
    objects.insert(candidate);
    let closure = ValidatedClosure {
        object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
            objects.clone(),
        ))
        .unwrap(),
        objects,
    };
    let request = node.request_context();
    let history = node
        .runtime()
        .block_on(node.snapshot_history_in(&request))
        .unwrap();
    let prior = &history.last().unwrap().batch.committed_rcrs[0];
    // Keep the predecessor's evidence as a distinct comparison baseline.
    // A permitted offer replaces these bootstrap values with its exact fold.
    let evidence = CommitEvidence {
        principal_snapshot_id: prior.principal_snapshot_id,
        forge_event_batch_root: prior.forge_event_batch_root,
        policy_decision_root: prior.policy_decision_root,
        invariant_evidence_root: prior.invariant_evidence_root,
        outbox_effect_root: prior.outbox_effect_root,
        retention_delta_root: prior.retention_delta_root,
    };
    let number = PullRequestNumber::FIRST;
    let offer = Offer {
        package: MergeEffectPackage {
            objects: vec![candidate],
            ref_intent: RefIntent {
                name: main_ref().as_bytes().to_vec(),
                expected_tip: target,
                new_tip: candidate,
            },
            event: ForgeEvent {
                aggregate: AggregateId::PullRequest(number),
                version: AggregateVersion::FIRST,
                payload: ForgeEventPayload::MergeCommittedNative(NativeMerge {
                    source_ref: topic_ref(),
                    source_tip: source,
                    base_tip: base,
                    target_ref: main_ref(),
                    target_tip_before: target,
                    merge_commit: candidate,
                }),
            },
        },
        attempt: MergeAttempt {
            pull_request: number,
            source_ref: topic_ref().as_bytes().to_vec(),
            target_ref: main_ref().as_bytes().to_vec(),
            source_tip: source,
            target_tip: target,
            base_tip: base,
            workspace_epoch: WorkspaceEpoch::from_u64(9),
        },
        closure,
        evidence,
        predecessor_evidence: evidence,
    };
    let ForgeEventPayload::MergeCommittedNative(merge) = &offer.package.event.payload else {
        panic!("fixture must contain a native merge");
    };
    let verified = validate_merge_objects(
        &NodeObjects(node),
        merge,
        MergeObjectLimits::default(),
        &mut || true,
    )
    .expect("epoch-one candidate and actual source objects pass the production native validator");
    assert_eq!(
        offer.closure, verified,
        "supplied closure must match the independently traversed objects"
    );
    offer
}
fn context(node: &OneNode, format: GitHashAlgorithm, key: &[u8]) -> AdmissionContext {
    let request = node.request_context();
    let head = node
        .runtime()
        .block_on(node.authenticate_authority_head_in(&request))
        .unwrap();
    AdmissionContext {
        head_key: head.receipt().key().clone(),
        tenant_id: TenantId::from_bytes([0x51; 16]),
        repository_id: RepositoryId::from_bytes([0x52; 16]),
        principal_id: principal(),
        idempotency_key: IdempotencyKey::new(key.to_vec()).unwrap(),
        object_format: format,
    }
}
fn apply(
    node: &OneNode,
    context: &AdmissionContext,
    offer: &Offer,
    now: WorkspaceEpoch,
) -> TerminalOutcome {
    let request = node.request_context();
    node.runtime()
        .block_on(node.admit_merge_durable_in(
            &request,
            context,
            &offer.sealed(now),
            AdmissionLimits::default(),
        ))
        .unwrap()
}

/// Derive supplied evidence from the public evaluator at this exact key/basis.
/// Admission independently reproduces the same complete ref/forge/outbox fold.
fn prepare_evidence(node: &OneNode, context: &AdmissionContext, offer: &mut Offer) {
    let request_context = node.request_context();
    let selected = node
        .runtime()
        .block_on(node.materialize_admission_in(&request_context))
        .unwrap();
    let attempt = seal_attempt_for(context, &offer.sealed(offer.attempt.workspace_epoch)).unwrap();
    let tx_id = attempt.derive().unwrap().0;
    let event_root = evidence_root(&fgit_forge::event::ForgeEventBatch::of_one(
        offer.package.event.clone(),
    ))
    .unwrap();
    let label = AsciiSlug::try_new(
        "forge_stream",
        offer.package.event.aggregate.to_string().as_bytes(),
    )
    .unwrap();
    let target = RefName::try_new(&offer.package.ref_intent.name).unwrap();
    let delivery_key = derive_outbox_delivery_key(OutboxDeliveryIdentityInput::new(
        context.repository_id,
        AsciiSlug::from_static("forge-event"),
        AsciiSlug::from_static("forge-projection"),
        event_root,
        tx_id,
        selected.basis().body().latest_committed_rcr_id,
    ))
    .unwrap();
    let request = TransactionRequest {
        tx_id,
        tenant: context.tenant_id,
        repository: context.repository_id,
        principal: context.principal_id,
        schema: attempt.request.request_schema(),
        idempotency_key: ModelKey::new(AsciiSlug::from_static("receive")),
        canonical_request_digest: fgit_authority::canonical_request_digest(&attempt.request)
            .unwrap(),
        statements: vec![Statement {
            intents: vec![
                Intent::Ref(ModelRefIntent::Update {
                    name: target.clone(),
                    expected: ExpectedRefState::Exact(offer.package.ref_intent.expected_tip),
                    new: offer.package.ref_intent.new_tip,
                    force: false,
                }),
                Intent::Forge(ForgeIntent {
                    stream: ForgeStreamId::new(label),
                    expected_position: ForgeStreamPosition::new(
                        offer.package.event.version.get() - 1,
                    ),
                    event: ForgeEventKind::PullRequestMerged {
                        pull_request: ForgeEntityId::new(label),
                        target,
                    },
                }),
                Intent::Outbox(OutboxIntent {
                    delivery_key: OutboxDeliveryKey::new(delivery_key),
                    parameters: event_root,
                }),
            ],
            mismatch_policy: MismatchPolicy::TxnAbort,
        }],
        promised_closure: offer.closure.objects.clone(),
        atomic: true,
        durability: DurabilityProfile::CanonicalSource,
    };
    let snapshot = selected.snapshot();
    let fold = IntentEvaluator::new().evaluate(
        FoldBasis {
            refs: &snapshot.refs,
            forge_positions: &snapshot.forge_positions,
            retention: &snapshot.retention,
            outbox: &snapshot.outbox,
        },
        &request,
    );
    assert!(
        matches!(fold.outcome, FoldOutcome::Folded(_)),
        "permitted fixture has a complete non-aborting fold"
    );
    let bodies =
        DecisionEvidenceBodies::derive(context, selected.basis(), &request, &fold).unwrap();
    offer.evidence = CommitEvidence {
        principal_snapshot_id: principal_snapshot_id(bodies.principal_snapshot()).unwrap(),
        forge_event_batch_root: event_root,
        policy_decision_root: evidence_root(bodies.policy_decision()).unwrap(),
        invariant_evidence_root: evidence_root(bodies.invariant_evidence()).unwrap(),
        outbox_effect_root: evidence_root(bodies.outbox_effect_batch()).unwrap(),
        retention_delta_root: evidence_root(bodies.retention_delta()).unwrap(),
    };
}

#[test]
fn sealed_native_api_publishes_all_roots_and_preserves_the_original_seal_across_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (mut node, _) = OneNode::init(scratch.config(format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let mut offer = setup(&node, &scratch, format);
        let context = context(&node, format, b"sealed-native-merge");
        prepare_evidence(&node, &context, &mut offer);
        let request = node.request_context();
        let before = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        let tx = seal_attempt_for(&context, &offer.sealed(offer.attempt.workspace_epoch))
            .unwrap()
            .derive()
            .unwrap()
            .0;
        let terminal = apply(&node, &context, &offer, offer.attempt.workspace_epoch);
        assert!(
            matches!(terminal.outcome, DecisionOutcome::Committed { .. }),
            "permitted native merge: {terminal:?}"
        );
        let request = node.request_context();
        let selected = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        assert_eq!(
            selected.snapshot().refs[&main_ref()],
            offer.package.ref_intent.new_tip
        );
        assert_eq!(
            selected.snapshot().head_target,
            before.snapshot().head_target,
            "a source-directory HEAD cannot replace authenticated canonical HEAD"
        );
        assert_eq!(selected.snapshot().outbox.len(), 1);
        assert_eq!(selected.snapshot().forge_positions.len(), 1);
        let history = node
            .runtime()
            .block_on(node.snapshot_history_in(&request))
            .unwrap();
        let last = history.last().unwrap();
        let record = &last.batch.committed_rcrs[0];
        assert_eq!(
            record.tx_id, tx,
            "compatibility API must not derive a different NativeMergeIntent seal"
        );
        assert_eq!(last.forge_events, vec![offer.package.event.clone()]);
        assert_eq!(record.resulting_ref_root, selected.basis().body().ref_root);
        assert_eq!(
            record.resulting_forge_position_root,
            selected.basis().body().forge_position_root
        );
        assert_ne!(
            record.invariant_evidence_root,
            offer.predecessor_evidence.invariant_evidence_root
        );
        assert_ne!(
            record.outbox_effect_root,
            offer.predecessor_evidence.outbox_effect_root
        );
        assert_eq!(
            CommitEvidence {
                principal_snapshot_id: record.principal_snapshot_id,
                forge_event_batch_root: record.forge_event_batch_root,
                policy_decision_root: record.policy_decision_root,
                invariant_evidence_root: record.invariant_evidence_root,
                outbox_effect_root: record.outbox_effect_root,
                retention_delta_root: record.retention_delta_root,
            },
            offer.evidence
        );
        let head = selected.basis().id();
        let outbox_root = selected.basis().body().outbox_root;
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(
            apply(&reopened, &context, &offer, offer.attempt.workspace_epoch),
            terminal
        );
        let request = reopened.request_context();
        let selected = reopened
            .runtime()
            .block_on(reopened.materialize_admission_in(&request))
            .unwrap();
        assert_eq!(selected.basis().id(), head);
        assert_eq!(selected.basis().body().outbox_root, outbox_root);
        assert_eq!(selected.snapshot().outbox.len(), 1);
        assert_eq!(
            selected.snapshot().head_target,
            before.snapshot().head_target
        );
        reopened.shutdown().unwrap();
    }
}

#[test]
fn stale_workspace_refusal_is_terminal_and_a_fresh_key_can_publish_the_permitted_twin() {
    let format = GitHashAlgorithm::Sha1;
    let scratch = Scratch::new();
    let (mut node, _) = OneNode::init(scratch.config(format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let mut offer = setup(&node, &scratch, format);
    let stale_context = context(&node, format, b"sealed-native-stale");
    prepare_evidence(&node, &stale_context, &mut offer);
    let refused = apply(
        &node,
        &stale_context,
        &offer,
        offer.attempt.workspace_epoch.next(),
    );
    assert!(matches!(
        refused.outcome,
        DecisionOutcome::Refused {
            code: RefusalCode::EvidenceStale,
            ..
        }
    ));
    assert_eq!(
        apply(&node, &stale_context, &offer, offer.attempt.workspace_epoch),
        refused
    );
    let request = node.request_context();
    let selected = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    assert_eq!(
        selected.snapshot().refs[&main_ref()],
        offer.attempt.target_tip
    );
    assert!(selected.snapshot().outbox.is_empty());
    assert!(selected.snapshot().forge_positions.is_empty());
    let fresh_context = context(&node, format, b"sealed-native-fresh");
    prepare_evidence(&node, &fresh_context, &mut offer);
    assert!(matches!(
        apply(&node, &fresh_context, &offer, offer.attempt.workspace_epoch).outcome,
        DecisionOutcome::Committed { .. }
    ));
    assert_eq!(
        apply(&node, &stale_context, &offer, offer.attempt.workspace_epoch),
        refused
    );
    let request = node.request_context();
    assert_eq!(
        node.runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap()
            .snapshot()
            .outbox
            .len(),
        1
    );
    node.shutdown().unwrap();
}

#[test]
fn predecessor_evidence_is_refused_and_correct_full_fold_evidence_permits_a_fresh_key() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (mut node, _) = OneNode::init(scratch.config(format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let mut offer = setup(&node, &scratch, format);
        let invalid_context = context(&node, format, b"sealed-native-invalid-evidence");
        prepare_evidence(&node, &invalid_context, &mut offer);
        let correct_evidence = offer.evidence;
        assert_ne!(correct_evidence, offer.predecessor_evidence);
        offer.evidence = offer.predecessor_evidence;
        let request = node.request_context();
        let before = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        let refused = apply(
            &node,
            &invalid_context,
            &offer,
            offer.attempt.workspace_epoch,
        );
        assert!(matches!(
            refused.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::EvidenceInvalid,
                ..
            }
        ));
        let request = node.request_context();
        let after = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        assert_eq!(after.snapshot().refs, before.snapshot().refs);
        assert_eq!(after.snapshot().head_target, before.snapshot().head_target);
        assert_eq!(
            after.basis().body().ref_root,
            before.basis().body().ref_root
        );
        assert_eq!(
            after.basis().body().forge_position_root,
            before.basis().body().forge_position_root
        );
        assert_eq!(
            after.basis().body().outbox_root,
            before.basis().body().outbox_root
        );
        assert_eq!(
            after.basis().body().retention_root,
            before.basis().body().retention_root
        );
        assert!(after.snapshot().forge_positions.is_empty());
        assert!(after.snapshot().outbox.is_empty());
        offer.evidence = correct_evidence;
        assert_eq!(
            apply(
                &node,
                &invalid_context,
                &offer,
                offer.attempt.workspace_epoch
            ),
            refused
        );

        let permitted_context = context(&node, format, b"sealed-native-valid-evidence");
        prepare_evidence(&node, &permitted_context, &mut offer);
        let committed = apply(
            &node,
            &permitted_context,
            &offer,
            offer.attempt.workspace_epoch,
        );
        assert!(matches!(
            committed.outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert_eq!(
            apply(
                &node,
                &permitted_context,
                &offer,
                offer.attempt.workspace_epoch
            ),
            committed
        );
        assert_eq!(
            apply(
                &node,
                &invalid_context,
                &offer,
                offer.attempt.workspace_epoch
            ),
            refused
        );
        let request = node.request_context();
        let selected = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        assert_eq!(
            selected.snapshot().refs[&main_ref()],
            offer.package.ref_intent.new_tip
        );
        assert_eq!(selected.snapshot().forge_positions.len(), 1);
        assert_eq!(selected.snapshot().outbox.len(), 1);
        node.shutdown().unwrap();
    }
}
