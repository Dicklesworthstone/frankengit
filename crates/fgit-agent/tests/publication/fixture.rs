//! Actual TreeFS export and public control-plane builders for publication tests.
//! The authority engine is the reference provider; this is not native admission.

#[path = "evidence.rs"]
mod evidence;
pub use evidence::{Evidence, digest};

use std::collections::BTreeMap;

use fgit_agent::*;
use fgit_authority::{
    AuthorityStore, HeadInit, HeadKey, MemoryAuthorityStore, StoreInstanceId,
    initialize_repository, outcome_index_root,
};
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_crypto::{GitHashAlgorithm, GitObjectKind, GitOid, IdentityDomain, NativeObjectIdentity};
use fgit_git_object::{AcceptanceProfile, ParseLimits, TreeEntry, emit_tree};
use fgit_resource::{Grade, ResourceVector};
use fgit_treefs::{
    BaseView, ContentRef, EntryClass, EpochSet, ExpectedRef, ExportLimits, ExportPlan,
    ExportPlanner, FileMode, ObjectSource, ObjectSourceError, Overlay, OverlayEntry, OverlayRoot,
    PathPolicy, PositionReceipt, ProposedRefIntent, ProposedTransaction, ReadGrant, TreeCapability,
    TreePath, WorkspaceId, WorkspaceSnapshotBody,
};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DigestBytes, HeadGeneration, PolicyEpoch, RegistryEpoch,
    RepositoryCommitId, RepositoryId, RepositorySequence,
};

pub fn authority() -> (MemoryAuthorityStore, AuthorityReadReceipt) {
    let root = outcome_index_root(&[]).unwrap();
    let rcr = RepositoryCommitId::from_digest(
        IdentityDomain::RepositoryCommitRecord.algorithm().id(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[7; 32]).unwrap(),
    );
    let head = RepositoryAuthorityHeadBody {
        repository_id: RepositoryId::from_bytes([0x27; 16]),
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: Some(rcr),
        latest_repository_sequence: Some(RepositorySequence::FIRST),
        ref_root: root,
        forge_position_root: root,
        outcome_index_root: root,
        retention_root: root,
        outbox_root: root,
        configuration_root: root,
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    };
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(531));
    let key = HeadKey::new(b"publication-evidence-head".to_vec()).unwrap();
    let HeadInit::Created(read) = initialize_repository(&store, &key, &head).unwrap() else {
        panic!("fresh store");
    };
    let authenticated = store.authenticate_head_receipt(&read).unwrap();
    let receipt = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(10),
        [51; 32],
    )
    .unwrap();
    (store, receipt)
}

pub fn path(bytes: &[u8]) -> TreePath {
    TreePath::parse_default(bytes).unwrap()
}

fn parse_limits<A: GitHashAlgorithm>() -> ParseLimits {
    ParseLimits {
        tree_reference_bytes: A::DIGEST_LEN,
        ..ParseLimits::default()
    }
}

pub struct MemorySource {
    pub objects: BTreeMap<Vec<u8>, Vec<u8>>,
}
impl MemorySource {
    pub fn insert<A: GitHashAlgorithm>(&mut self, kind: GitObjectKind, body: Vec<u8>) -> GitOid<A> {
        let oid = GitOid::<A>::of_object(kind, &body);
        self.objects.insert(oid.digest_bytes().to_vec(), body);
        oid
    }
    fn tree<A: GitHashAlgorithm>(&mut self, entries: &[TreeEntry]) -> GitOid<A> {
        let body = emit_tree(
            entries,
            AcceptanceProfile::GitCompatibleImport,
            &parse_limits::<A>(),
        )
        .unwrap();
        self.insert::<A>(GitObjectKind::Tree, body)
    }
}
impl<A: GitHashAlgorithm> ObjectSource<A> for MemorySource {
    fn read_object(
        &self,
        oid: &GitOid<A>,
        _kind: GitObjectKind,
        _grant: &ReadGrant,
    ) -> Result<Vec<u8>, ObjectSourceError> {
        self.objects
            .get(oid.digest_bytes())
            .cloned()
            .ok_or_else(|| ObjectSourceError::NotFound {
                oid_hex: String::new(),
            })
    }
}

#[derive(Clone)]
pub struct Change<A: GitHashAlgorithm> {
    pub workspace: WorkspaceBinding<A>,
    pub overlay: Overlay,
    pub export: ExportPlan<A>,
    pub proposal: ProposedTransaction<A>,
    pub contexts: Vec<ContextPacket>,
}

pub fn change<A: GitHashAlgorithm>(receipt: &AuthorityReadReceipt, body: &[u8]) -> Change<A> {
    let mut source = MemorySource {
        objects: BTreeMap::new(),
    };
    let blob = source.insert::<A>(GitObjectKind::Blob, b"fn original() {}\n".to_vec());
    let root = source.tree::<A>(&[TreeEntry {
        mode: b"100644".to_vec(),
        name: b"lib.rs".to_vec(),
        object_id: blob.digest_bytes().to_vec(),
    }]);
    let workspace_id = WorkspaceId::from_bytes([0x41; 16]);
    let base = BaseView::new(
        receipt.repository_id(),
        receipt.latest_repository_commit_id().unwrap(),
        root,
        root,
        parse_limits::<A>(),
        PathPolicy::default(),
    );
    let mut capability = TreeCapability::new(
        workspace_id,
        receipt.repository_id(),
        vec![path(b"lib.rs")],
        vec![path(b"lib.rs")],
    );
    let mut overlay = Overlay::new();
    let content = overlay.intern(body.to_vec());
    overlay.put(
        path(b"lib.rs"),
        OverlayEntry::File {
            content: ContentRef::Overlay(content),
            mode: FileMode::Regular,
            class: EntryClass::Content,
        },
    );
    let export = ExportPlanner::new(ExportLimits::default(), parse_limits::<A>())
        .plan(&base, &source, &mut capability, &overlay, 0, &|| false)
        .unwrap();
    let snapshot = WorkspaceSnapshotBody::new(
        workspace_id,
        receipt.repository_id(),
        receipt.latest_repository_commit_id().unwrap(),
        root,
        root,
        OverlayRoot::of(&overlay),
        EpochSet::new().stage().publish().unwrap(),
    );
    let run = IntentRun::new_authenticated(
        RunId::new(305),
        receipt.clone(),
        ClassSet::from_classes(&[
            OperationClass::TreeFsWorkspace,
            OperationClass::PreparePublication,
            OperationClass::ReadCanonicalObject,
        ]),
        ResourceVector::single(Grade::Bytes, 16_384),
        LogicalTime::new(100),
    )
    .unwrap();
    let workspace = WorkspaceBinding::bind(run, snapshot).unwrap();
    let proposal = ProposedTransaction::seal(
        workspace_id,
        &export,
        PositionReceipt {
            repository_id: receipt.repository_id(),
            base_rcr_id: receipt.latest_repository_commit_id().unwrap(),
            base_tree_oid: root,
            proposed_tree_oid: *export.root_tree(),
            touched_paths: overlay.touched_paths(),
        },
        vec![ProposedRefIntent {
            name: b"refs/heads/main".to_vec(),
            expected: ExpectedRef::Exactly { oid: root },
            new: *export.root_tree(),
        }],
    )
    .unwrap();
    let packet = ContextPacket::build(
        receipt.clone(),
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
                b"untrusted source, not approval".to_vec(),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    Change {
        workspace,
        overlay,
        export,
        proposal,
        contexts: vec![packet],
    }
}
