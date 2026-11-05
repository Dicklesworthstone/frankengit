#![forbid(unsafe_code)]
//! Real embedded authority, native initial/source publication, production
//! quarantine and durable host journals. ECC assertions are explicit fixture
//! inputs; the tests execute the native publication consumer separately.

#[path = "evidence_tests.rs"]
mod evidence;

use super::*;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::NodeConfig;
use fgit_agent::{
    AgentInstanceId, AuthorityReadReceipt, Capability, CapabilityId, ClassSet, ContextControl,
    ContextPacket, ContextSource, IntentRun, RetrievalChannel, RunId, WorkspaceBinding,
};
use fgit_authority::HeadReadReceipt;
use fgit_crypto::{GitObjectKind, GitOid, NativeObjectIdentity, Sha1, Sha256, sha1_digest};
use fgit_forge::initial_commit::InitialCommitPlan;
use fgit_forge::preparation::MergeMetadata;
use fgit_git_object::ParseLimits;
use fgit_resource::{RegionId, kinds::NoCandidateReason};
use fgit_treefs::{
    BaseView, ContentRef, EntryClass, EpochSet, ExpectedRef, ExportLimits, ExportPlanner, FileMode,
    ObjectSource, ObjectSourceError, Overlay, OverlayEntry, OverlayRoot, PathPolicy,
    PositionReceipt, ProposedRefIntent, ProposedTransaction, ReadGrant, TreeCapability, TreePath,
    WorkspaceId, WorkspaceSnapshotBody,
};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm as Format, HeadGeneration, RefName, RepositoryId, TenantId,
};

const OWNER: PrincipalId = PrincipalId::from_bytes([0x83; 16]);
const ISSUER: &[u8] = b"native-agent-publication-fixture";
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-native-agent-publication-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn config(&self, format: Format) -> NodeConfig {
        NodeConfig::new(
            self.0.join("node"),
            TenantId::from_bytes([0x81; 16]),
            RepositoryId::from_bytes([0x82; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(2)
    }
    fn journal(&self, label: &str) -> PathBuf {
        let directory = self.0.join(label);
        fs::create_dir(&directory).unwrap();
        directory
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn reference() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}
fn budget() -> ResourceVector {
    Grade::ALL
        .into_iter()
        .fold(ResourceVector::ZERO, |value, grade| {
            value.with(grade, 1 << 30)
        })
}

fn source(node: &OneNode) -> InitialCommitPlan {
    let metadata = MergeMetadata {
        author: "Agent Fixture <fixture@example.invalid>".into(),
        committer: "Agent Fixture <fixture@example.invalid>".into(),
        timestamp: 17,
        message: b"initial checked-agent source\n".to_vec(),
    };
    let request = node.command_request_context(None);
    let (_, plan, bundle) = node.runtime().block_on(node.prepare_trusted_initial_patch_in(
        &request, &reference(),
        b"diff --git a/lib.rs b/lib.rs\nnew file mode 100644\n--- /dev/null\n+++ b/lib.rs\n@@ -0,0 +1 @@\n+fn original() {}\n",
        &metadata, Default::default(), None,
    )).unwrap();
    let session = LoopbackReceiveSession::authenticated(
        OWNER,
        IdempotencyKey::new(b"native-agent-source".to_vec()).unwrap(),
    );
    let admitted = node
        .runtime()
        .block_on(node.apply_initial_patch_bundle_durable_in(
            &request,
            &session,
            &reference(),
            plan.commit,
            bundle.bytes(),
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        admitted.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    plan
}

fn node(scratch: &Scratch, format: Format, revocation_aware: bool) -> (OneNode, InitialCommitPlan) {
    let (mut node, _) = if revocation_aware {
        OneNode::init_with_agent_revocations(scratch.config(format)).unwrap()
    } else {
        OneNode::init(scratch.config(format)).unwrap()
    };
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let source = source(&node);
    (node, source)
}

struct Bodies(BTreeMap<Vec<u8>, Vec<u8>>);
impl<A: GitHashAlgorithm> ObjectSource<A> for Bodies {
    fn read_object(
        &self,
        oid: &GitOid<A>,
        _kind: GitObjectKind,
        _grant: &ReadGrant,
    ) -> Result<Vec<u8>, ObjectSourceError> {
        self.0
            .get(oid.digest_bytes())
            .cloned()
            .ok_or_else(|| ObjectSourceError::NotFound {
                oid_hex: String::new(),
            })
    }
}

struct Prepared<A: GitHashAlgorithm> {
    transaction: AgentRefTransaction<A>,
    export: ExportPlan<A>,
    bundle: Vec<u8>,
    body: Vec<u8>,
    original_read: HeadReadReceipt,
}

fn prepared<A: GitHashAlgorithm>(
    node: &OneNode,
    source: &InitialCommitPlan,
    branch: &[u8],
    candidate_has_wrong_tree: bool,
) -> Prepared<A> {
    let selected = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap();
    let receipt =
        AuthorityReadReceipt::from_authenticated_head(&selected, LogicalTime::new(10), [51; 32])
            .unwrap();
    let base_tree = A::parse_hex(&source.tree.to_string()).unwrap();
    let base_commit = A::parse_hex(&source.commit.to_string()).unwrap();
    let limits = ParseLimits {
        tree_reference_bytes: A::DIGEST_LEN,
        ..Default::default()
    };
    let workspace_id = WorkspaceId::from_bytes([0x41; 16]);
    let base = BaseView::new(
        receipt.repository_id(),
        receipt.latest_repository_commit_id().unwrap(),
        base_tree,
        base_tree,
        limits.clone(),
        PathPolicy::default(),
    );
    let bodies = Bodies(
        source
            .objects
            .iter()
            .map(|object| (object.id.as_bytes().to_vec(), object.body.clone()))
            .collect(),
    );
    let path = TreePath::parse_default(b"lib.rs").unwrap();
    let mut capability = TreeCapability::new(
        workspace_id,
        receipt.repository_id(),
        vec![path.clone()],
        vec![path.clone()],
    );
    let mut overlay = Overlay::new();
    let content = overlay.intern(b"fn checked_change() {}\n".to_vec());
    overlay.put(
        path,
        OverlayEntry::File {
            content: ContentRef::Overlay(content),
            mode: FileMode::Regular,
            class: EntryClass::Content,
        },
    );
    let export = ExportPlanner::new(ExportLimits::default(), limits)
        .plan(&base, &bodies, &mut capability, &overlay, 0, &|| false)
        .unwrap();
    let snapshot = WorkspaceSnapshotBody::new(
        workspace_id,
        receipt.repository_id(),
        receipt.latest_repository_commit_id().unwrap(),
        base_tree,
        base_tree,
        OverlayRoot::of(&overlay),
        EpochSet::new().stage().publish().unwrap(),
    );
    let run = IntentRun::new_authenticated(
        RunId::new(305),
        receipt.clone(),
        ClassSet::from_classes(&[
            OperationClass::TreeFsWorkspace,
            OperationClass::PreparePublication,
            OperationClass::PublishRefTransaction,
            OperationClass::ReadCanonicalObject,
        ]),
        budget(),
        LogicalTime::new(10_000),
    )
    .unwrap();
    let workspace = WorkspaceBinding::bind(run, snapshot).unwrap();
    let candidate_tree = if candidate_has_wrong_tree {
        base_tree
    } else {
        *export.root_tree()
    };
    let body = format!(
        "tree {}\nparent {}\nauthor Fixture <fixture@example.invalid> 18 +0000\ncommitter Fixture <fixture@example.invalid> 18 +0000\n\nchecked native publication\n",
        candidate_tree.erase(), base_commit.erase(),
    ).into_bytes();
    let candidate = GitOid::<A>::of_object(GitObjectKind::Commit, &body);
    let proposal = ProposedTransaction::seal(
        workspace_id,
        &export,
        PositionReceipt {
            repository_id: receipt.repository_id(),
            base_rcr_id: receipt.latest_repository_commit_id().unwrap(),
            base_tree_oid: base_tree,
            proposed_tree_oid: *export.root_tree(),
            touched_paths: overlay.touched_paths(),
        },
        vec![ProposedRefIntent {
            name: branch.to_vec(),
            expected: ExpectedRef::Exactly { oid: base_commit },
            new: candidate,
        }],
    )
    .unwrap();
    let context = ContextPacket::build(
        receipt,
        ContextControl::new(
            [1; 32],
            ClassSet::from_classes(&[OperationClass::ReadCanonicalObject]),
            [2; 32],
            vec![],
            vec![],
        ),
        vec![
            ContextSource::new(
                [3; 32],
                RetrievalChannel::Exact,
                b"untrusted source context; not approval".to_vec(),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let evidence =
        evidence::Evidence::new(&workspace, &proposal, &[context.clone()], &overlay, &export);
    let transaction = workspace
        .prepare_ref_transaction(proposal, &[context], evidence.input(&overlay, &export))
        .unwrap();
    let mut objects = if candidate_has_wrong_tree {
        // This is otherwise a valid child commit over the existing canonical
        // tree. No dangling export object can make quarantine fail first.
        Vec::new()
    } else {
        export
            .objects()
            .map(|object| (object.kind(), object.body().to_vec()))
            .collect::<Vec<_>>()
    };
    objects.push((GitObjectKind::Commit, body.clone()));
    let mut bundle = format!(
        "# v3 git bundle\n@object-format={}\n-{} source\n{} ",
        A::OBJECT_FORMAT.as_str(),
        base_commit.erase(),
        candidate.erase(),
    )
    .into_bytes();
    bundle.extend_from_slice(branch);
    bundle.extend_from_slice(b"\n\n");
    bundle.extend(pack(A::OBJECT_FORMAT, &objects));
    Prepared {
        transaction,
        export,
        bundle,
        body,
        original_read: selected.receipt().clone(),
    }
}

fn zlib(body: &[u8]) -> Vec<u8> {
    let length = u16::try_from(body.len()).unwrap();
    let mut bytes = vec![0x78, 0x01, 0x01];
    bytes.extend(length.to_le_bytes());
    bytes.extend((!length).to_le_bytes());
    bytes.extend(body);
    let (a, b) = body.iter().fold((1u32, 0u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521;
        (a, (b + a) % 65_521)
    });
    bytes.extend(((b << 16) | a).to_be_bytes());
    bytes
}
fn pack(format: Format, objects: &[(GitObjectKind, Vec<u8>)]) -> Vec<u8> {
    let mut bytes = b"PACK\0\0\0\x02".to_vec();
    bytes.extend(u32::try_from(objects.len()).unwrap().to_be_bytes());
    for (kind, body) in objects {
        let mut size = body.len();
        let mut first = (kind.type_code() << 4) | u8::try_from(size & 15).unwrap();
        size >>= 4;
        if size != 0 {
            first |= 128;
        }
        bytes.push(first);
        while size != 0 {
            let mut next = u8::try_from(size & 127).unwrap();
            size >>= 7;
            if size != 0 {
                next |= 128;
            }
            bytes.push(next);
        }
        bytes.extend(zlib(body));
    }
    bytes.extend(match format {
        Format::Sha1 => sha1_digest(&bytes).to_vec(),
        Format::Sha256 => sha256_digest(&bytes).to_vec(),
    });
    bytes
}

fn approval<A: GitHashAlgorithm>(
    change: &Prepared<A>,
    key: &[u8],
) -> TrustedLocalAgentPublicationApproval {
    TrustedLocalAgentPublicationApproval::new(
        OWNER,
        IdempotencyKey::new(key.to_vec()).unwrap(),
        *change.transaction.publication_evidence().binding_id(),
        sha256_digest(&change.body),
    )
}
fn chain(expiry: u64, publication: bool) -> VerifiedCapabilityChain {
    let operation = if publication {
        OperationClass::PublishRefTransaction
    } else {
        OperationClass::PreparePublication
    };
    let capability = Capability::issue(
        CapabilityId::new(1),
        ClassSet::from_classes(&[operation]),
        budget(),
        LogicalTime::new(10),
        LogicalTime::new(expiry),
    )
    .unwrap();
    VerifiedCapabilityChain::verify(&[capability.seal(ISSUER, None).unwrap()], ISSUER).unwrap()
}
fn broker<A: GitHashAlgorithm>(
    node: &OneNode,
    change: &Prepared<A>,
    directory: &std::path::Path,
) -> CurrentAuthorityRevocationCheckedEffectBroker {
    let request = node.request_context();
    node.runtime()
        .block_on(node.create_restorable_agent_broker_in(
            &request,
            directory,
            change.transaction.run().clone(),
            &change.original_read,
            RegionId::new(41),
            AgentInstanceId::new(42),
        ))
        .unwrap()
}
fn input<'a, A: GitHashAlgorithm>(
    change: &'a Prepared<A>,
    approval: &'a TrustedLocalAgentPublicationApproval,
    chain: &'a VerifiedCapabilityChain,
) -> TrustedLocalAgentPublicationInput<'a, A> {
    TrustedLocalAgentPublicationInput {
        transaction: &change.transaction,
        export: &change.export,
        bundle: &change.bundle,
        approval,
        chain,
    }
}

fn native_success_retry_and_restart<A: GitHashAlgorithm>() {
    let scratch = Scratch::new();
    let (node, source) = node(&scratch, A::OBJECT_FORMAT, true);
    let change = prepared::<A>(&node, &source, reference().as_bytes(), false);
    let approved = approval(&change, b"checked-agent-submit");
    let chain = chain(10_000, true);
    let directory = scratch.journal("journal");
    let mut broker = broker(&node, &change, &directory);
    let clock = node
        .trusted_local_agent_publication_clock(LogicalTime::new(20), Duration::from_secs(1))
        .unwrap();
    let request = node.command_request_context(Some(
        crate::GitDaemonSessionTimeout::try_new(Duration::from_secs(30)).unwrap(),
    ));
    let result = node
        .runtime()
        .block_on(node.publish_agent_ref_transaction_trusted_local_in(
            &request,
            &mut broker,
            &clock,
            input(&change, &approved, &chain),
        ))
        .unwrap();
    let NativeAgentPublicationResult::Submitted(submitted) = result else {
        panic!("new submission");
    };
    let admission = submitted.admission.unwrap();
    let RefTransactionResolution::Decided(settled) = submitted.responsibility.unwrap() else {
        panic!("terminal authority");
    };
    assert!(matches!(
        admission.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    assert_eq!(
        settled.observation().terminal(),
        &admission.commands[0].terminal
    );
    let expected = change
        .transaction
        .seal_attempt(node.tenant_id(), OWNER, approved.key.clone())
        .derive()
        .unwrap()
        .0;
    assert_eq!(admission.session.tx_ids, [expected]);
    assert_eq!(settled.observation().binding().tx_id(), expected);
    assert!(
        settled
            .observation()
            .binding()
            .custody_commitment()
            .is_some()
    );
    let effect = settled.observation().binding().effect_id();
    let terminal = *settled.observation().terminal();
    let selected = node
        .runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .unwrap();
    let ProposedNew::Update(candidate) =
        change.transaction.semantic_request().ref_commands()[0].proposed_new
    else {
        panic!("update");
    };
    assert_eq!(selected.snapshot().refs[&reference()], candidate);
    assert_eq!(broker.dispatch_authorizations().len(), 1);
    assert_eq!(broker.generic_dispatch_authorizations().len(), 1);

    // Caller loses its reply, the run subsequently expires, and transport bytes
    // are no longer available: exact retained responsibility permits observation
    // only, with no fresh authorization or second CAS.
    let expired = node
        .trusted_local_agent_publication_clock(LogicalTime::new(10_001), Duration::from_secs(1))
        .unwrap();
    let mut retry = input(&change, &approved, &chain);
    retry.bundle = b"unavailable retry transport";
    let recovered = node
        .runtime()
        .block_on(node.publish_agent_ref_transaction_trusted_local_in(
            &node.request_context(),
            &mut broker,
            &expired,
            retry,
        ))
        .unwrap();
    let NativeAgentPublicationResult::Recovered(observed) = recovered else {
        panic!("read-only retry");
    };
    assert_eq!(observed.binding().tx_id(), expected);
    assert_eq!(observed.terminal(), &terminal);
    assert_eq!(broker.dispatch_authorizations().len(), 1);
    let tail = broker.durable_position().unwrap().unwrap();
    let run_id = change.transaction.run_id();
    let run_commitment = *change.transaction.run().commitment().unwrap().as_bytes();
    assert!(broker.close().is_quiescent());
    drop(clock);
    drop(expired);
    drop(change);
    node.shutdown().unwrap();

    let mut reopened = OneNode::open_existing(scratch.config(A::OBJECT_FORMAT)).unwrap();
    let generation = reopened
        .runtime()
        .block_on(reopened.authenticate_authority_head())
        .unwrap()
        .receipt()
        .generation();
    reopened.bring_into_service(generation).unwrap();
    let request = reopened.request_context();
    let journal = reopened
        .runtime()
        .block_on(reopened.recover_agent_journal_in(
            &request,
            &directory,
            run_id,
            &run_commitment,
            tail,
        ))
        .unwrap();
    let observed = reopened
        .runtime()
        .block_on(reopened.observe_recovered_agent_ref_transaction_in(&request, &journal, effect))
        .unwrap()
        .unwrap();
    assert_eq!(observed.binding().tx_id(), expected);
    assert_eq!(observed.terminal(), &terminal);
    assert_eq!(journal.journal().position(), tail);
    assert!(
        !journal
            .reconciliation_report(LogicalTime::new(10_001))
            .unwrap()
            .has_unsettled_effects()
    );
    reopened.shutdown().unwrap();
}

#[test]
fn checked_publication_commits_and_recovers_original_tx_after_restart_in_both_formats() {
    native_success_retry_and_restart::<Sha1>();
    native_success_retry_and_restart::<Sha256>();
}

#[test]
fn ordinary_canonical_refusal_settles_submission_without_claiming_ref_success() {
    let scratch = Scratch::new();
    let (node, source) = node(&scratch, Format::Sha1, true);
    let change = prepared::<Sha1>(&node, &source, b"refs/heads/absent", false);
    let approved = approval(&change, b"checked-agent-expected-old-refusal");
    let chain = chain(10_000, true);
    let mut broker = broker(&node, &change, &scratch.journal("journal"));
    let clock = node
        .trusted_local_agent_publication_clock(LogicalTime::new(20), Duration::from_secs(1))
        .unwrap();
    let result = node
        .runtime()
        .block_on(node.publish_agent_ref_transaction_trusted_local_in(
            &node.request_context(),
            &mut broker,
            &clock,
            input(&change, &approved, &chain),
        ))
        .unwrap();
    let NativeAgentPublicationResult::Submitted(result) = result else {
        panic!("new submission");
    };
    let admission = result.admission.unwrap();
    assert!(matches!(
        admission.commands[0].terminal.outcome,
        DecisionOutcome::Refused { .. }
    ));
    let RefTransactionResolution::Decided(settled) = result.responsibility.unwrap() else {
        panic!("refusal is terminal");
    };
    assert_eq!(
        settled.observation().terminal(),
        &admission.commands[0].terminal
    );
    let selected = node
        .runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .unwrap();
    assert_eq!(selected.snapshot().refs[&reference()], source.commit);
    assert!(
        !selected
            .snapshot()
            .refs
            .contains_key(&RefName::try_new(b"refs/heads/absent").unwrap())
    );
    assert!(broker.close().is_quiescent());
    drop(clock);
    node.shutdown().unwrap();
}

#[test]
fn actual_commit_tree_must_match_checked_export_before_irreversible_start() {
    let scratch = Scratch::new();
    let (node, source) = node(&scratch, Format::Sha1, true);
    let change = prepared::<Sha1>(&node, &source, reference().as_bytes(), true);
    let approved = approval(&change, b"wrong-checked-tree");
    let chain = chain(10_000, true);
    let mut broker = broker(&node, &change, &scratch.journal("journal"));
    let clock = node
        .trusted_local_agent_publication_clock(LogicalTime::new(20), Duration::from_secs(1))
        .unwrap();
    let error = node
        .runtime()
        .block_on(node.publish_agent_ref_transaction_trusted_local_in(
            &node.request_context(),
            &mut broker,
            &clock,
            input(&change, &approved, &chain),
        ))
        .unwrap_err();
    let NativeAgentPublicationError::Reserved {
        reservation,
        reason,
    } = error
    else {
        panic!("retain unstarted custody");
    };
    assert!(matches!(
        reason,
        NativeAgentPublicationRefusal::Workspace(_)
    ));
    assert!(format!("{reason}").contains("candidate commit does not name the checked export tree"));
    assert!(broker.dispatch_authorizations().is_empty());
    let _settled = reservation
        .abort(NoCandidateReason::WitnessInvalid)
        .unwrap();
    assert!(broker.close().is_quiescent());
    let selected = node
        .runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .unwrap();
    assert_eq!(selected.snapshot().refs[&reference()], source.commit);
    for object in change.export.objects() {
        assert!(
            node.read_git_object(object.oid().erase()).is_err(),
            "refused private objects were not published"
        );
    }
    drop(clock);
    node.shutdown().unwrap();
}

#[test]
fn independent_approval_scope_durability_deadline_and_cancellation_are_separate_gates() {
    let scratch = Scratch::new();
    let (node, source) = node(&scratch, Format::Sha1, true);
    let change = prepared::<Sha1>(&node, &source, reference().as_bytes(), false);
    let approved = approval(&change, b"native-gates");
    let chain = chain(10_000, true);
    let clock = node
        .trusted_local_agent_publication_clock(LogicalTime::new(20), Duration::from_secs(1))
        .unwrap();
    let mut memory = CurrentAuthorityRevocationCheckedEffectBroker::open(
        change.transaction.run().clone(),
        RegionId::new(91),
        AgentInstanceId::new(92),
    )
    .unwrap();
    let error = node
        .runtime()
        .block_on(node.publish_agent_ref_transaction_trusted_local_in(
            &node.request_context(),
            &mut memory,
            &clock,
            input(&change, &approved, &chain),
        ))
        .unwrap_err();
    assert!(
        matches!(error, NativeAgentPublicationError::Preflight(NativeAgentPublicationRefusal::Effect(ref reason))
        if matches!(reason.as_ref(), RefTransactionEffectRefusal::DurableJournalRequired))
    );
    assert!(memory.records().is_empty());
    assert!(memory.close().is_quiescent());

    let mut broker = broker(&node, &change, &scratch.journal("journal"));
    let mut wrong_approval = approved.clone();
    wrong_approval.publication_binding[0] ^= 1;
    let error = node
        .runtime()
        .block_on(node.publish_agent_ref_transaction_trusted_local_in(
            &node.request_context(),
            &mut broker,
            &clock,
            input(&change, &wrong_approval, &chain),
        ))
        .unwrap_err();
    assert!(matches!(
        error,
        NativeAgentPublicationError::Preflight(NativeAgentPublicationRefusal::Binding(_))
    ));
    assert!(broker.records().is_empty());
    let prepare_only = self::chain(10_000, false);
    assert!(
        node.runtime()
            .block_on(node.publish_agent_ref_transaction_trusted_local_in(
                &node.request_context(),
                &mut broker,
                &clock,
                input(&change, &approved, &prepare_only),
            ))
            .is_err()
    );
    assert!(broker.records().is_empty());

    let short = self::chain(21, true);
    let error = node
        .runtime()
        .block_on(node.publish_agent_ref_transaction_trusted_local_in(
            &node.request_context(),
            &mut broker,
            &clock,
            input(&change, &approved, &short),
        ))
        .unwrap_err();
    let NativeAgentPublicationError::Reserved {
        reservation,
        reason,
    } = error
    else {
        panic!("short lifetime stays abortable");
    };
    assert!(matches!(
        reason,
        NativeAgentPublicationRefusal::AuthorizationDeadlineUnbound
    ));
    let _settled = reservation
        .abort(NoCandidateReason::BudgetExhausted)
        .unwrap();
    assert!(broker.dispatch_authorizations().is_empty());
    assert!(broker.close().is_quiescent());

    let mut cancelled_broker = broker_for_cancel(&node, &change, &scratch);
    let cancelled = node.request_context();
    cancelled.cancel();
    assert!(matches!(
        node.runtime()
            .block_on(node.publish_agent_ref_transaction_trusted_local_in(
                &cancelled,
                &mut cancelled_broker,
                &clock,
                input(&change, &approved, &chain),
            ))
            .unwrap_err(),
        NativeAgentPublicationError::Preflight(NativeAgentPublicationRefusal::CancelledOrExpired)
    ));
    assert!(cancelled_broker.records().is_empty());
    assert!(cancelled_broker.close().is_quiescent());
    assert!(
        node.trusted_local_agent_publication_clock(LogicalTime::new(20), Duration::ZERO)
            .is_err()
    );
    let overflow = node
        .trusted_local_agent_publication_clock(LogicalTime::new(0), Duration::from_nanos(u64::MAX))
        .unwrap();
    assert!(matches!(
        overflow.require_request_before(&node, &node.request_context(), LogicalTime::new(2)),
        Err(NativeAgentPublicationRefusal::Clock)
    ));
    drop(overflow);
    drop(clock);
    node.shutdown().unwrap();
}

fn broker_for_cancel<A: GitHashAlgorithm>(
    node: &OneNode,
    change: &Prepared<A>,
    scratch: &Scratch,
) -> CurrentAuthorityRevocationCheckedEffectBroker {
    broker(node, change, &scratch.journal("cancel-journal"))
}

#[test]
fn unconfigured_authority_and_moved_exact_basis_refuse_fresh_publication() {
    let scratch = Scratch::new();
    let (node, source) = node(&scratch, Format::Sha1, false);
    let change = prepared::<Sha1>(&node, &source, reference().as_bytes(), false);
    let approved = approval(&change, b"requires-revocation-generation");
    let chain = chain(10_000, true);
    let mut broker = broker(&node, &change, &scratch.journal("journal"));
    let clock = node
        .trusted_local_agent_publication_clock(LogicalTime::new(20), Duration::from_secs(1))
        .unwrap();
    let error = node
        .runtime()
        .block_on(node.publish_agent_ref_transaction_trusted_local_in(
            &node.request_context(),
            &mut broker,
            &clock,
            input(&change, &approved, &chain),
        ))
        .unwrap_err();
    assert!(matches!(
        error,
        NativeAgentPublicationError::Preflight(NativeAgentPublicationRefusal::Revocations(_))
    ));
    assert!(broker.records().is_empty());
    assert!(broker.close().is_quiescent());
    drop(clock);
    node.shutdown().unwrap();

    let scratch = Scratch::new();
    let (node, source) = self::node(&scratch, Format::Sha1, true);
    let change = prepared::<Sha1>(&node, &source, reference().as_bytes(), false);
    let approved = approval(&change, b"checked-stale-head");
    let mut broker = self::broker(&node, &change, &scratch.journal("journal"));
    // A real ordinary publication after preparation changes canonical authority.
    let published = node
        .runtime()
        .block_on(node.apply_workspace_bundle_durable_in(
            &node.request_context(),
            OWNER,
            b"rival-source-publication",
            &reference(),
            source.commit,
            fgit_crypto::git_object_id(Format::Sha1, GitObjectKind::Commit, &change.body),
            &change.bundle,
        ))
        .unwrap();
    assert!(matches!(
        published.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    let clock = node
        .trusted_local_agent_publication_clock(LogicalTime::new(20), Duration::from_secs(1))
        .unwrap();
    let error = node
        .runtime()
        .block_on(node.publish_agent_ref_transaction_trusted_local_in(
            &node.request_context(),
            &mut broker,
            &clock,
            input(&change, &approved, &chain),
        ))
        .unwrap_err();
    assert!(matches!(
        error,
        NativeAgentPublicationError::Preflight(NativeAgentPublicationRefusal::Binding(
            "prepared authority basis moved"
        ))
    ));
    assert!(broker.records().is_empty());
    assert!(broker.close().is_quiescent());
    drop(clock);
    node.shutdown().unwrap();
}
