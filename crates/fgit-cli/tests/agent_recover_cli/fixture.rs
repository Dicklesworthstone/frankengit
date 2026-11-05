//! Synthetic approval/ECC inputs scope a genuine native agent transaction.
//! Run capture, broker journal, canonical admission and recovery are production.

#[path = "../../../fgit-node/src/agent_publication/evidence_tests.rs"]
mod evidence;

use fgit_agent::effect_journal::EffectJournalPosition;
use fgit_agent::*;
use fgit_authority::IdempotencyKey;
use fgit_crypto::{
    GitHashAlgorithm, GitObjectKind, GitOid, NativeObjectIdentity, sha1_digest, sha256_digest,
};
use fgit_forge::initial_commit::InitialCommitPlan;
use fgit_forge::preparation::MergeMetadata;
use fgit_git_object::ParseLimits;
use fgit_node::agent_publication::*;
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_resource::{Grade, RegionId, ResourceVector};
use fgit_treefs::*;
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm as Format, HeadGeneration, PrincipalId, RefName,
    RepositoryId, TenantId, TxId,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

pub const OWNER: PrincipalId = PrincipalId::from_bytes([0x83; 16]);
pub const KEY: &[u8] = b"agent-cli-original-publication";
const ISSUER: &[u8] = b"agent-recovery-cli-fixture";
static NEXT: AtomicU64 = AtomicU64::new(0);

pub struct Scratch(pub PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-agent-recover-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Copy)]
pub enum Mode {
    Committed,
    Refused,
    Reserved,
}

pub struct Fixture {
    pub scratch: Scratch,
    pub format: Format,
    pub run: RunId,
    pub run_commitment: [u8; 32],
    pub effect: EffectId,
    pub tail: EffectJournalPosition,
    pub tx: TxId,
    pub source: fgit_types::GitOid,
    pub candidate: fgit_types::GitOid,
    pub bundle: Vec<u8>,
    pub decision: Option<fgit_authority::TerminalOutcome>,
}

impl Fixture {
    pub fn config(&self) -> NodeConfig {
        config(&self.scratch, self.format)
    }
    pub fn directory(&self) -> PathBuf {
        self.scratch.0.join("journal")
    }
    pub fn files(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        fs::read_dir(self.directory())
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let bytes = fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect()
    }
    pub fn arguments(&self) -> Vec<String> {
        vec![
            "agent".into(),
            "recover".into(),
            self.scratch.0.join("node").to_str().unwrap().into(),
            "81".repeat(16),
            "82".repeat(16),
            self.directory().to_str().unwrap().into(),
            "--trusted-local".into(),
            "--principal".into(),
            OWNER.to_string(),
            "--run-id".into(),
            format!("{:032x}", self.run.value()),
            "--effect-id".into(),
            format!("{:032x}", self.effect.value()),
            "--expected-run".into(),
            hex(&self.run_commitment),
            "--expected-tail-entries".into(),
            self.tail.entries.to_string(),
            "--expected-tail-bytes".into(),
            self.tail.bytes.to_string(),
            "--expected-tail-digest".into(),
            hex(&self.tail.digest),
            "--object-format".into(),
            self.format.as_str().into(),
        ]
    }
    pub fn head_bytes(&self) -> Vec<u8> {
        let node = OneNode::open_existing(self.config()).unwrap();
        let bytes = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap()
            .receipt()
            .body()
            .to_vec();
        node.shutdown().unwrap();
        bytes
    }
    pub fn publish_original_as_operator(&self) -> fgit_authority::TerminalOutcome {
        let mut node = OneNode::open_existing(self.config()).unwrap();
        let generation = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap()
            .receipt()
            .generation();
        node.bring_into_service(generation).unwrap();
        let result = node
            .runtime()
            .block_on(node.apply_workspace_bundle_durable_in(
                &node.command_request_context(None),
                OWNER,
                KEY,
                &reference(),
                self.source,
                self.candidate,
                &self.bundle,
            ))
            .unwrap();
        assert_eq!(result.session.tx_ids, [self.tx]);
        let terminal = result.commands[0].terminal;
        assert!(matches!(
            terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        node.shutdown().unwrap();
        terminal
    }
}

fn config(scratch: &Scratch, format: Format) -> NodeConfig {
    NodeConfig::new(
        scratch.0.join("node"),
        TenantId::from_bytes([0x81; 16]),
        RepositoryId::from_bytes([0x82; 16]),
    )
    .with_object_format(format)
    .with_worker_threads(2)
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
    let request = node.command_request_context(None);
    let metadata = MergeMetadata {
        author: "Fixture <fixture@example.invalid>".into(),
        committer: "Fixture <fixture@example.invalid>".into(),
        timestamp: 17,
        message: b"original source\n".to_vec(),
    };
    let (_, plan, bundle) = node.runtime().block_on(node.prepare_trusted_initial_patch_in(
        &request, &reference(), b"diff --git a/lib.rs b/lib.rs\nnew file mode 100644\n--- /dev/null\n+++ b/lib.rs\n@@ -0,0 +1 @@\n+fn original() {}\n", &metadata, Default::default(), None,
    )).unwrap();
    let result = node
        .runtime()
        .block_on(node.apply_initial_patch_bundle_durable_in(
            &request,
            &LoopbackReceiveSession::authenticated(
                OWNER,
                IdempotencyKey::new(b"original-source".to_vec()).unwrap(),
            ),
            &reference(),
            plan.commit,
            bundle.bytes(),
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        result.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    plan
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

pub fn fixture<A: GitHashAlgorithm>(mode: Mode) -> Fixture {
    let scratch = Scratch::new();
    let (mut node, _) =
        OneNode::init_with_agent_revocations(config(&scratch, A::OBJECT_FORMAT)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let source = source(&node);
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
    let body = format!("tree {}\nparent {}\nauthor Fixture <fixture@example.invalid> 18 +0000\ncommitter Fixture <fixture@example.invalid> 18 +0000\n\nchecked CLI recovery\n", export.root_tree().erase(), base_commit.erase()).into_bytes();
    let candidate = GitOid::<A>::of_object(GitObjectKind::Commit, &body);
    let branch: &[u8] = if matches!(mode, Mode::Refused) {
        b"refs/heads/absent"
    } else {
        b"refs/heads/main"
    };
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
                b"fixture source context, not approval".to_vec(),
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
    let mut objects = export
        .objects()
        .map(|object| (object.kind(), object.body().to_vec()))
        .collect::<Vec<_>>();
    objects.push((GitObjectKind::Commit, body.clone()));
    let mut bundle = format!(
        "# v3 git bundle\n@object-format={}\n-{} source\n{} ",
        A::OBJECT_FORMAT.as_str(),
        base_commit.erase(),
        candidate.erase()
    )
    .into_bytes();
    bundle.extend_from_slice(branch);
    bundle.extend_from_slice(b"\n\n");
    bundle.extend(pack(A::OBJECT_FORMAT, &objects));
    let approved = TrustedLocalAgentPublicationApproval::new(
        OWNER,
        IdempotencyKey::new(KEY.to_vec()).unwrap(),
        *transaction.publication_evidence().binding_id(),
        sha256_digest(&body),
    );
    let capability = Capability::issue(
        CapabilityId::new(1),
        ClassSet::from_classes(&[OperationClass::PublishRefTransaction]),
        budget(),
        LogicalTime::new(10),
        LogicalTime::new(10_000),
    )
    .unwrap();
    let chain =
        VerifiedCapabilityChain::verify(&[capability.seal(ISSUER, None).unwrap()], ISSUER).unwrap();
    let directory = scratch.0.join("journal");
    fs::create_dir(&directory).unwrap();
    let mut broker = node
        .runtime()
        .block_on(node.create_restorable_agent_broker_in(
            &node.request_context(),
            &directory,
            transaction.run().clone(),
            selected.receipt(),
            RegionId::new(41),
            AgentInstanceId::new(42),
        ))
        .unwrap();
    let clock = node
        .trusted_local_agent_publication_clock(LogicalTime::new(20), Duration::from_secs(1))
        .unwrap();
    let request = node.command_request_context(Some(
        fgit_node::GitDaemonSessionTimeout::try_new(Duration::from_secs(
            if matches!(mode, Mode::Reserved) {
                20_000
            } else {
                30
            },
        ))
        .unwrap(),
    ));
    let result = node
        .runtime()
        .block_on(node.publish_agent_ref_transaction_trusted_local_in(
            &request,
            &mut broker,
            &clock,
            TrustedLocalAgentPublicationInput {
                transaction: &transaction,
                export: &export,
                bundle: &bundle,
                approval: &approved,
                chain: &chain,
            },
        ));
    let (binding, decision) = if matches!(mode, Mode::Reserved) {
        let NativeAgentPublicationError::Reserved {
            reservation,
            reason,
        } = result.unwrap_err()
        else {
            panic!("real pre-start reservation");
        };
        assert!(matches!(
            reason,
            NativeAgentPublicationRefusal::AuthorizationDeadlineUnbound
        ));
        let binding = reservation.binding().clone();
        drop(reservation); // Simulate lost local ownership; never synthesize a journal transition.
        (binding, None)
    } else {
        let NativeAgentPublicationResult::Submitted(result) = result.unwrap() else {
            panic!("native initial submission");
        };
        let admission = result.admission.unwrap();
        let fgit_agent::ref_publication::RefTransactionResolution::Decided(settled) =
            result.responsibility.unwrap()
        else {
            panic!("real canonical terminal");
        };
        assert_eq!(
            settled.observation().terminal(),
            &admission.commands[0].terminal
        );
        (
            settled.observation().binding().clone(),
            Some(admission.commands[0].terminal),
        )
    };
    let run = transaction.run_id();
    let run_commitment = *transaction.run().commitment().unwrap().as_bytes();
    let tail = broker.durable_position().unwrap().unwrap();
    assert_eq!(
        broker.close().is_quiescent(),
        !matches!(mode, Mode::Reserved)
    );
    drop(clock);
    node.shutdown().unwrap();
    Fixture {
        scratch,
        format: A::OBJECT_FORMAT,
        run,
        run_commitment,
        effect: binding.effect_id(),
        tail,
        tx: binding.tx_id(),
        source: source.commit,
        candidate: candidate.erase(),
        bundle,
        decision,
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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
        let length = u16::try_from(body.len()).unwrap();
        bytes.extend([0x78, 0x01, 0x01]);
        bytes.extend(length.to_le_bytes());
        bytes.extend((!length).to_le_bytes());
        bytes.extend(body);
        let (a, b) = body.iter().fold((1u32, 0u32), |(a, b), byte| {
            let a = (a + u32::from(*byte)) % 65_521;
            (a, (b + a) % 65_521)
        });
        bytes.extend(((b << 16) | a).to_be_bytes());
    }
    bytes.extend(match format {
        Format::Sha1 => sha1_digest(&bytes).to_vec(),
        Format::Sha256 => sha256_digest(&bytes).to_vec(),
    });
    bytes
}
