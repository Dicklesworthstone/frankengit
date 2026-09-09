#![forbid(unsafe_code)]
//! Process-death boundaries through native admission and the real file-backed
//! authority. This is process-crash recovery, not power-loss/fsync fault proof.
//! The decorator forwards storage operations; it contains no publication model.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::{fs, process};

use fgit_admission::merge::NativeMergeBasis;
use fgit_admission::merge::native::objects::{MergeObjectLimits, validate_merge_objects};
use fgit_admission::merge::native::{
    NativeMergeIntent, NativeMergeProjection, admit_native_merge_async, delivery,
};
use fgit_admission::{
    AdmissionContext, AdmissionLimits, AdmissionSnapshot, AsyncAdmissionProjection,
    CanonicalRefState, CommitMaterialization, ProjectionFailure, RefusalMaterialization,
    ValidatedClosure,
};
use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityLimits,
    AuthorityVersionToken, CasOutcome, DuplicateAbsenceWitness, HeadInit, HeadKey, HeadRead,
    HeadReadReceipt, IdempotencyKey, ImmutableKey, ImmutableRead, PutOutcome, StoreInstanceId,
    TerminalOutcome,
};
use fgit_chronicle::PublicationBasis;
use fgit_codec::{
    CanonicalForgePositionState, CanonicalOutboxEffectState, CanonicalOutboxState, DecodeLimits,
    RepositoryAuthorityHeadBody, decode_body,
};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::aggregate::{ExpectedVersion, PullRequestNumber};
use fgit_forge::event::{ForgeEventBatch, NativeMerge};
use fgit_git_object::ObjectType;
use fgit_node::{
    DurableAdmissionMaterializer, DurableAsyncAdmissionProjection, LoopbackReceiveSession,
    NodeConfig, OneNode,
};
use fgit_object_fabric::ObjectKind;
use fgit_pack::{CanonicalObjectSource, CanonicalPackObject, PackWriteError};
use fgit_reference::intent::TransactionRequest;
use fgit_resource::{CacheScope, OpaqueHandle};
use fgit_runtime::meter::BudgetClass;
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RefName, RefusalCode,
    RepositoryId, TenantId, TxId,
};
use fsqlite_types::cx::Cx;

use fgit_authority_fsqlite::FsqliteAuthorityStore;

const CHILD_ROOT: &str = "FGIT_ASA3_NATIVE_CAS_CRASH_ROOT";
const CHILD_POINT: &str = "FGIT_ASA3_NATIVE_CRASH_POINT";
const CHILD_FORMAT: &str = "FGIT_ASA3_NATIVE_CRASH_FORMAT";
const MERGE_KEY: &[u8] = b"native-durable-crash-merge";
const STORE_INSTANCE: StoreInstanceId = StoreInstanceId::from_raw(203);
// These two production namespaces are private to native::storage.
const EVENT_NAMESPACE: &[u8] = b"frankengit/admission/forge-event-batch/v1/";
const POSITION_NAMESPACE: &[u8] = b"frankengit/admission/forge-position-state/v1/";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CrashPoint {
    BeforeAdmissionStaging,
    AfterEvent,
    AfterPosition,
    AfterOutboxEffect,
    AfterOutboxState,
    BeforeCas,
    AfterCas,
}
impl CrashPoint {
    const STAGING: [Self; 5] = [
        Self::BeforeAdmissionStaging,
        Self::AfterEvent,
        Self::AfterPosition,
        Self::AfterOutboxEffect,
        Self::AfterOutboxState,
    ];

    const fn exit_code(self) -> i32 {
        match self {
            Self::BeforeCas => 82,
            Self::AfterCas => 83,
            Self::BeforeAdmissionStaging => 84,
            Self::AfterEvent => 85,
            Self::AfterPosition => 86,
            Self::AfterOutboxEffect => 87,
            Self::AfterOutboxState => 88,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::BeforeAdmissionStaging => "before-admission-staging",
            Self::AfterEvent => "after-event",
            Self::AfterPosition => "after-position",
            Self::AfterOutboxEffect => "after-outbox-effect",
            Self::AfterOutboxState => "after-outbox-state",
            Self::BeforeCas => "before-cas",
            Self::AfterCas => "after-cas",
        }
    }

    fn matches_staged_body(self, key: &ImmutableKey, body: &[u8]) -> bool {
        match self {
            Self::AfterEvent => {
                key.as_bytes().starts_with(EVENT_NAMESPACE)
                    && decode_body::<ForgeEventBatch>(body, DecodeLimits::DEFAULT).is_ok()
            }
            Self::AfterPosition => key.as_bytes().starts_with(POSITION_NAMESPACE),
            Self::AfterOutboxEffect => key.as_bytes().starts_with(delivery::EFFECT_NAMESPACE),
            Self::AfterOutboxState => key.as_bytes().starts_with(delivery::OUTBOX_NAMESPACE),
            Self::BeforeAdmissionStaging | Self::BeforeCas | Self::AfterCas => false,
        }
    }
}

/// Abruptly exits before the first admission write, after selected successful
/// immutable writes, or around the actual atomic publication operation.
struct CrashAuthority {
    inner: FsqliteAuthorityStore,
    point: CrashPoint,
    observation_root: PathBuf,
}

impl CrashAuthority {
    fn exit_at_write(&self, key: &ImmutableKey, body: &[u8]) -> ! {
        // The parent consumes these exact intercepted arguments to check the
        // reopened database. They are test observations, never publication input.
        fs::write(
            self.observation_root.join("interrupted-key"),
            key.as_bytes(),
        )
        .unwrap();
        fs::write(self.observation_root.join("interrupted-body"), body).unwrap();
        process::exit(self.point.exit_code());
    }
}

impl AsyncAuthorityStore for CrashAuthority {
    type Context = Cx;
    fn instance_id(&self) -> StoreInstanceId {
        AsyncAuthorityStore::instance_id(&self.inner)
    }
    fn limits(&self) -> AuthorityLimits {
        AsyncAuthorityStore::limits(&self.inner)
    }
    async fn put_if_absent(
        &self,
        cx: &Cx,
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        if self.point == CrashPoint::BeforeAdmissionStaging {
            // Candidate Git objects were imported by the parent. This is the
            // FIRST authority write of this admission, before binding or sealing.
            assert!(
                key.as_bytes()
                    .starts_with(fgit_authority::IDEMPOTENCY_BINDING_KEY_PREFIX)
            );
            self.exit_at_write(key, body);
        }
        let result = AsyncAuthorityStore::put_if_absent(&self.inner, cx, key, body).await;
        if self.point.matches_staged_body(key, body)
            && matches!(
                &result,
                Ok(PutOutcome::Created | PutOutcome::IdenticalRetry)
            )
        {
            self.exit_at_write(key, body);
        }
        result
    }
    async fn read_immutable(
        &self,
        cx: &Cx,
        key: &ImmutableKey,
    ) -> Result<ImmutableRead, AuthorityFailure> {
        AsyncAuthorityStore::read_immutable(&self.inner, cx, key).await
    }
    async fn initialize_head(
        &self,
        cx: &Cx,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, AuthorityFailure> {
        AsyncAuthorityStore::initialize_head(&self.inner, cx, key, generation, body).await
    }
    async fn read_head(&self, cx: &Cx, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        AsyncAuthorityStore::read_head(&self.inner, cx, key).await
    }
    async fn compare_exchange_head(
        &self,
        cx: &Cx,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        AsyncAuthorityStore::compare_exchange_head(&self.inner, cx, key, expected, generation, body)
            .await
    }
    async fn publish_head_with_outcomes(
        &self,
        cx: &Cx,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
        outcomes: &[(ImmutableKey, Vec<u8>)],
        witness: &DuplicateAbsenceWitness,
    ) -> Result<CasOutcome, AuthorityFailure> {
        if self.point == CrashPoint::BeforeCas {
            process::exit(self.point.exit_code());
        }
        let result = AsyncAuthorityStore::publish_head_with_outcomes(
            &self.inner,
            cx,
            key,
            expected,
            generation,
            body,
            outcomes,
            witness,
        )
        .await;
        if self.point == CrashPoint::AfterCas && matches!(&result, Ok(CasOutcome::Committed(_))) {
            process::exit(self.point.exit_code());
        }
        result
    }
    async fn authenticate_head_receipt(
        &self,
        cx: &Cx,
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure> {
        AsyncAuthorityStore::authenticate_head_receipt(&self.inner, cx, receipt).await
    }
}

/// Native object bytes come from the real node fabric, including after reopening.
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

/// The public durable projection owns ref/evidence materialization unchanged.
/// This adapter resolves the same authenticated ref/configuration and delivery
/// bodies, validates native objects, and forwards the wrapped backend unchanged.
struct Projection<'a> {
    inner: DurableAsyncAdmissionProjection<'a>,
    materializer: &'a DurableAdmissionMaterializer,
    node: &'a OneNode,
}
impl AsyncAdmissionProjection<CrashAuthority> for Projection<'_> {
    fn snapshot_async<'a>(
        &'a self,
        authority: &'a CrashAuthority,
        cx: &'a Cx,
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
    ) -> impl Future<Output = Result<AdmissionSnapshot, ProjectionFailure>> + Send + 'a {
        self.inner
            .snapshot_async(&authority.inner, cx, basis, authenticated)
    }
    fn materialize_commit_async<'a>(
        &'a self,
        authority: &'a CrashAuthority,
        cx: &'a Cx,
        basis: &'a PublicationBasis,
        request: &'a TransactionRequest,
        fold: &'a fgit_txn::TransactionFoldReport,
        closure: &'a ValidatedClosure,
    ) -> impl Future<Output = Result<CommitMaterialization, ProjectionFailure>> + Send + 'a {
        self.inner
            .materialize_commit_async(&authority.inner, cx, basis, request, fold, closure)
    }
    fn materialize_refusal_async<'a>(
        &'a self,
        authority: &'a CrashAuthority,
        cx: &'a Cx,
        basis: &'a PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
    ) -> impl Future<Output = Result<RefusalMaterialization, ProjectionFailure>> + Send + 'a {
        self.inner
            .materialize_refusal_async(&authority.inner, cx, basis, tx_id, code)
    }
}
impl NativeMergeProjection<CrashAuthority> for Projection<'_> {
    fn merge_checkpoint(&self, cx: &Cx) -> Result<(), RefusalCode> {
        cx.checkpoint()
            .map_err(|_| RefusalCode::CancellationInProgress)
    }
    async fn resolve_merge_basis_async<'a>(
        &'a self,
        authority: &'a CrashAuthority,
        cx: &'a Cx,
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
    ) -> Result<NativeMergeBasis, ProjectionFailure> {
        self.merge_checkpoint(cx)
            .map_err(ProjectionFailure::Unavailable)?;
        let selected = self
            .materializer
            .materialize_exact_in(authority, cx, repository(), basis, authenticated, &|| {
                cx.checkpoint().is_err()
            })
            .await;
        self.merge_checkpoint(cx)
            .map_err(ProjectionFailure::Unavailable)?;
        let selected =
            selected.map_err(|_| ProjectionFailure::Unavailable(RefusalCode::EvidenceMissing))?;
        let delivery = delivery::read_in(authority, cx, basis, &|| cx.checkpoint().is_err()).await;
        self.merge_checkpoint(cx)
            .map_err(ProjectionFailure::Unavailable)?;
        let delivery =
            delivery.map_err(|_| ProjectionFailure::Unavailable(RefusalCode::EvidenceMissing))?;
        let snapshot = selected.snapshot();
        let refs = match snapshot.head_target.clone() {
            Some(target) => CanonicalRefState::new_with_head_target(snapshot.refs.clone(), target)
                .map_err(ProjectionFailure::Unavailable)?,
            None => CanonicalRefState::new(snapshot.refs.clone()),
        };
        Ok(NativeMergeBasis {
            refs,
            root_layout: selected.root_layout(),
            forge: delivery.forge,
            outbox: delivery.outbox,
        })
    }
    async fn validate_merge_async<'a>(
        &'a self,
        authority: &'a CrashAuthority,
        cx: &'a Cx,
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
        intent: &'a NativeMergeIntent,
    ) -> Result<ValidatedClosure, ProjectionFailure> {
        let selected = self
            .materializer
            .materialize_exact_in(
                &authority.inner,
                cx,
                repository(),
                basis,
                authenticated,
                &|| cx.checkpoint().is_err(),
            )
            .await
            .map_err(|_| ProjectionFailure::Unavailable(RefusalCode::EvidenceMissing))?;
        let merge = intent
            .merge()
            .map_err(|_| ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))?;
        if [merge.source_tip, merge.target_tip_before, merge.base_tip]
            .iter()
            .any(|id| !selected.selected_closure().closure().objects().contains(id))
        {
            return Err(ProjectionFailure::Refuse(
                RefusalCode::ObjectClosureIncomplete,
            ));
        }
        validate_merge_objects(
            &NodeObjects(self.node),
            merge,
            MergeObjectLimits::default(),
            &mut || cx.checkpoint().is_ok(),
        )
    }
}

fn repository() -> RepositoryId {
    RepositoryId::from_bytes([0xc4; 16])
}
fn principal() -> PrincipalId {
    PrincipalId::from_bytes([0xc5; 16])
}
fn config(root: &Path, format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(
        root.join("node"),
        TenantId::from_bytes([0xc3; 16]),
        repository(),
    )
    .with_object_format(format)
    .with_store_instance(STORE_INSTANCE)
    .with_worker_threads(2)
}
fn main_ref() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}
fn topic_ref() -> RefName {
    RefName::try_new(b"refs/heads/topic").unwrap()
}
fn context(format: GitHashAlgorithm) -> AdmissionContext {
    AdmissionContext {
        head_key: HeadKey::new(
            [b"frankengit/node/head/".as_slice(), repository().as_bytes()].concat(),
        )
        .unwrap(),
        tenant_id: TenantId::from_bytes([0xc3; 16]),
        repository_id: repository(),
        principal_id: principal(),
        idempotency_key: IdempotencyKey::new(MERGE_KEY.to_vec()).unwrap(),
        object_format: format,
    }
}

struct Objects {
    format: GitHashAlgorithm,
    base: GitOid,
    target: GitOid,
    source: GitOid,
    merged: GitOid,
    bodies: Vec<(GitObjectKind, Vec<u8>)>,
}
impl Objects {
    fn new(format: GitHashAlgorithm) -> Self {
        let tree = git_object_id(format, GitObjectKind::Tree, b"");
        let commit = |parents: &[GitOid], message: &str| {
            let parents: String = parents.iter().map(|id| format!("parent {id}\n")).collect();
            format!("tree {tree}\n{parents}author Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\n{message}\n").into_bytes()
        };
        let base_body = commit(&[], "base");
        let base = git_object_id(format, GitObjectKind::Commit, &base_body);
        let target_body = commit(&[base], "target");
        let target = git_object_id(format, GitObjectKind::Commit, &target_body);
        let source_body = commit(&[base], "source");
        let source = git_object_id(format, GitObjectKind::Commit, &source_body);
        let merged_body = commit(&[target, source], "reviewed merge");
        let merged = git_object_id(format, GitObjectKind::Commit, &merged_body);
        Self {
            format,
            base,
            target,
            source,
            merged,
            bodies: vec![
                (GitObjectKind::Tree, Vec::new()),
                (GitObjectKind::Commit, base_body),
                (GitObjectKind::Commit, target_body),
                (GitObjectKind::Commit, source_body),
                (GitObjectKind::Commit, merged_body),
            ],
        }
    }
    fn intent(&self) -> NativeMergeIntent {
        NativeMergeIntent::new(
            PullRequestNumber::try_new(1).unwrap(),
            ExpectedVersion::NewStream,
            NativeMerge {
                source_ref: topic_ref(),
                source_tip: self.source,
                base_tip: self.base,
                target_ref: main_ref(),
                target_tip_before: self.target,
                merge_commit: self.merged,
            },
        )
        .unwrap()
    }
}

fn write_loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, body: &[u8]) {
    let raw = [
        format!("{} {}\0", kind.label(), body.len()).as_bytes(),
        body,
    ]
    .concat();
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
    let hex = git_object_id(format, kind, body).to_string();
    let directory = root.join("objects").join(&hex[..2]);
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join(&hex[2..]), zlib).unwrap();
}

fn prepare(root: &Path, objects: &Objects) -> RepositoryAuthorityHeadBody {
    let (mut node, _) = OneNode::init(config(root, objects.format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let source = root.join("source");
    fs::create_dir_all(source.join("refs/heads")).unwrap();
    fs::write(source.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    for (kind, body) in &objects.bodies[..4] {
        write_loose(&source, objects.format, *kind, body);
    }
    fs::write(
        source.join("refs/heads/main"),
        format!("{}\n", objects.target),
    )
    .unwrap();
    fs::write(
        source.join("refs/heads/topic"),
        format!("{}\n", objects.source),
    )
    .unwrap();
    let request = node.request_context();
    let imported = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &request,
            &source,
            principal(),
            b"native-crash-fixture",
        ))
        .unwrap();
    assert!(
        imported
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    assert_eq!(
        node.put_git_object(GitObjectKind::Commit, objects.bodies[4].1.clone())
            .unwrap()
            .identity(),
        objects.merged
    );
    let intent = objects.intent();
    let closure = validate_merge_objects(
        &NodeObjects(&node),
        intent.merge().unwrap(),
        MergeObjectLimits::default(),
        &mut || true,
    )
    .expect("positive crash fixture must pass native validation before starting the child");
    assert_eq!(
        closure.objects,
        objects
            .bodies
            .iter()
            .map(|(kind, body)| git_object_id(objects.format, *kind, body))
            .collect::<std::collections::BTreeSet<_>>()
    );
    let request = node.request_context();
    let selected = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    let head = selected.basis().body().clone();
    assert_eq!(selected.snapshot().refs[&main_ref()], objects.target);
    assert!(selected.snapshot().outbox.is_empty());
    node.shutdown().unwrap();
    head
}

fn database_context(node: &OneNode) -> Cx {
    let cx = Cx::new();
    cx.set_native_cx(node.runtime().request_cx(BudgetClass::Database));
    cx
}

fn open_authority(node: &OneNode, root: &Path) -> (FsqliteAuthorityStore, Cx) {
    let cx = database_context(node);
    let inner = node
        .runtime()
        .block_on(FsqliteAuthorityStore::open(
            &cx,
            root.join("node/authority.fsqlite").to_str().unwrap(),
            STORE_INSTANCE,
            AuthorityLimits::default(),
        ))
        .unwrap();
    (inner, cx)
}

fn child(root: &Path, format: GitHashAlgorithm, point: CrashPoint) -> ! {
    let mut node = OneNode::open_existing(config(root, format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let (inner, cx) = open_authority(&node, root);
    let authority = CrashAuthority {
        inner,
        point,
        observation_root: root.to_path_buf(),
    };
    let materializer = DurableAdmissionMaterializer::new(CacheScope::new(
        OpaqueHandle::new(b"native-durable-crash").unwrap(),
    ));
    let context = context(format);
    let projection = Projection {
        inner: DurableAsyncAdmissionProjection::new(&materializer, context.clone()),
        materializer: &materializer,
        node: &node,
    };
    let intent = Objects::new(format).intent();
    let result = node.runtime().block_on(admit_native_merge_async(
        &authority,
        &cx,
        &context,
        &intent,
        AdmissionLimits::default(),
        &projection,
    ));
    panic!("native admission did not reach requested process-crash boundary {point:?}: {result:?}");
}

fn run_selected_child() {
    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        let label = std::env::var(CHILD_POINT).unwrap();
        let point = CrashPoint::STAGING
            .into_iter()
            .chain([CrashPoint::BeforeCas, CrashPoint::AfterCas])
            .find(|point| point.label() == label)
            .expect("parent selects one known crash boundary");
        let format = match std::env::var(CHILD_FORMAT).unwrap().as_str() {
            "sha1" => GitHashAlgorithm::Sha1,
            "sha256" => GitHashAlgorithm::Sha256,
            _ => panic!("parent selects one supported object format"),
        };
        child(&PathBuf::from(root), format, point);
    }
}

fn apply(node: &OneNode, intent: &NativeMergeIntent) -> TerminalOutcome {
    let request = node.request_context();
    let session = LoopbackReceiveSession::authenticated(
        principal(),
        IdempotencyKey::new(MERGE_KEY.to_vec()).unwrap(),
    );
    node.runtime()
        .block_on(node.admit_native_merge_durable_in(
            &request,
            &session,
            intent,
            AdmissionLimits::default(),
            MergeObjectLimits::default(),
        ))
        .unwrap()
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "fgit-native-cas-crash-{}-{}",
            process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn run_case(test: &str, point: CrashPoint, format: GitHashAlgorithm) {
    assert!(
        std::env::var_os(CHILD_ROOT).is_none(),
        "child must not enter the parent matrix"
    );
    let scratch = Scratch::new();
    let objects = Objects::new(format);
    let intent = objects.intent();
    let before = prepare(&scratch.0, &objects);
    let status = process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg(test)
        .arg("--nocapture")
        .env(CHILD_ROOT, &scratch.0)
        .env(CHILD_POINT, point.label())
        .env(
            CHILD_FORMAT,
            match format {
                GitHashAlgorithm::Sha1 => "sha1",
                GitHashAlgorithm::Sha256 => "sha256",
            },
        )
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(point.exit_code()),
        "the child must reach the exact real authority boundary: {point:?} {format:?}"
    );
    let mut node = OneNode::open_existing(config(&scratch.0, format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let request = node.request_context();
    let recovered = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    let (mut inspection_store, inspection_cx) = open_authority(&node, &scratch.0);
    let interrupted_write = if CrashPoint::STAGING.contains(&point) {
        let key = ImmutableKey::new(fs::read(scratch.0.join("interrupted-key")).unwrap()).unwrap();
        let body = fs::read(scratch.0.join("interrupted-body")).unwrap();
        let stored = node
            .runtime()
            .block_on(inspection_store.read_immutable(&inspection_cx, &key))
            .unwrap();
        if point == CrashPoint::BeforeAdmissionStaging {
            assert_eq!(
                stored,
                ImmutableRead::Absent,
                "first admission write did not run"
            );
        } else {
            assert!(point.matches_staged_body(&key, &body));
            assert_eq!(
                stored,
                ImmutableRead::Present(body.clone()),
                "the awaited body survives process death unchanged"
            );
        }
        Some((key, body))
    } else {
        None
    };
    match point {
        CrashPoint::BeforeAdmissionStaging
        | CrashPoint::AfterEvent
        | CrashPoint::AfterPosition
        | CrashPoint::AfterOutboxEffect
        | CrashPoint::AfterOutboxState
        | CrashPoint::BeforeCas => {
            assert_eq!(
                recovered.basis().body(),
                &before,
                "all candidate roots remain invisible"
            );
            assert_eq!(recovered.snapshot().refs[&main_ref()], objects.target);
            assert!(recovered.snapshot().outbox.is_empty());
            assert!(recovered.snapshot().forge_positions.is_empty());
        }
        CrashPoint::AfterCas => {
            assert_eq!(
                recovered.basis().body().generation,
                before.generation.next().unwrap()
            );
            assert_eq!(recovered.snapshot().refs[&main_ref()], objects.merged);
            assert_eq!(recovered.snapshot().outbox.len(), 1);
            assert_eq!(recovered.snapshot().forge_positions.len(), 1);
        }
    }
    let committed = apply(&node, &intent);
    let DecisionOutcome::Committed {
        repository_commit_id,
    } = committed.outcome
    else {
        panic!("permitted recovery must commit: {committed:?}");
    };
    let request = node.request_context();
    let selected = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    let after = selected.basis().body().clone();
    if point == CrashPoint::AfterCas {
        assert_eq!(
            &after,
            recovered.basis().body(),
            "retry must recover the exact already-published head"
        );
    }
    assert_eq!(
        after.generation,
        before.generation.next().unwrap(),
        "recovery publishes at most one merge"
    );
    assert_ne!(after.ref_root, before.ref_root);
    assert_ne!(after.forge_position_root, before.forge_position_root);
    assert_ne!(after.outbox_root, before.outbox_root);
    assert_eq!(after.retention_root, before.retention_root);
    assert_eq!(
        selected.snapshot().head_target,
        recovered.snapshot().head_target
    );
    assert_eq!(selected.snapshot().refs[&main_ref()], objects.merged);
    assert_eq!(selected.snapshot().refs[&topic_ref()], objects.source);
    assert_eq!(selected.snapshot().outbox.len(), 1);
    assert_eq!(selected.snapshot().forge_positions.len(), 1);
    assert_eq!(after.latest_committed_rcr_id, Some(repository_commit_id));
    let history = node
        .runtime()
        .block_on(node.snapshot_history_in(&request))
        .unwrap();
    let events: Vec<_> = history
        .iter()
        .flat_map(|batch| &batch.forge_events)
        .collect();
    assert_eq!(events, vec![intent.event()]);
    let last = history.last().unwrap();
    assert_eq!(last.batch.committed_rcrs.len(), 1);
    let record = &last.batch.committed_rcrs[0];
    assert_eq!(record.resulting_ref_root, after.ref_root);
    assert_eq!(
        record.resulting_forge_position_root,
        after.forge_position_root
    );
    assert_eq!(last.batch.resulting_outbox_root, after.outbox_root);
    let event_root =
        fgit_admission::evidence::evidence_root(&ForgeEventBatch::of_one(intent.event().clone()))
            .unwrap();
    assert_eq!(record.forge_event_batch_root, event_root);
    assert_eq!(
        selected
            .snapshot()
            .outbox
            .values()
            .copied()
            .collect::<Vec<_>>(),
        vec![event_root]
    );
    if let Some((key, body)) = interrupted_write {
        let inspection_cx = database_context(&node);
        assert_eq!(
            node.runtime()
                .block_on(inspection_store.read_immutable(&inspection_cx, &key))
                .unwrap(),
            ImmutableRead::Present(body.clone()),
            "retry reuses the exact interrupted write's key and bytes"
        );
        let delivery = node
            .runtime()
            .block_on(delivery::read_in(
                &inspection_store,
                &inspection_cx,
                selected.basis(),
                &|| false,
            ))
            .unwrap();
        assert_eq!(delivery.outbox.entries().len(), 1);
        let entry = &delivery.outbox.entries()[0];
        assert_eq!(entry.tx_id(), last.batch.decisions[0].tx_id);
        assert_eq!(entry.payload_root(), event_root);
        match point {
            CrashPoint::BeforeAdmissionStaging => {
                assert!(
                    key.as_bytes()
                        .starts_with(fgit_authority::IDEMPOTENCY_BINDING_KEY_PREFIX)
                );
            }
            CrashPoint::AfterEvent => {
                let staged: ForgeEventBatch = decode_body(&body, DecodeLimits::DEFAULT).unwrap();
                assert_eq!(staged.events, vec![intent.event().clone()]);
                assert_eq!(
                    fgit_admission::evidence::evidence_root(&staged).unwrap(),
                    event_root
                );
            }
            CrashPoint::AfterPosition => {
                let staged: CanonicalForgePositionState =
                    decode_body(&body, DecodeLimits::DEFAULT).unwrap();
                assert_eq!(staged, delivery.forge);
                assert_eq!(staged.root().unwrap(), after.forge_position_root);
            }
            CrashPoint::AfterOutboxEffect => {
                let staged: CanonicalOutboxEffectState =
                    decode_body(&body, DecodeLimits::DEFAULT).unwrap();
                assert_eq!(staged.repository_id(), repository());
                assert_eq!(staged.tx_id(), entry.tx_id());
                assert_eq!(staged.payload_root(), event_root);
                assert_eq!(staged.delivery_key(), entry.delivery_key());
                assert_eq!(staged.root().unwrap(), entry.effect_state_root());
            }
            CrashPoint::AfterOutboxState => {
                let staged: CanonicalOutboxState =
                    decode_body(&body, DecodeLimits::DEFAULT).unwrap();
                assert_eq!(staged, delivery.outbox);
                assert_eq!(staged.root().unwrap(), after.outbox_root);
            }
            CrashPoint::BeforeCas | CrashPoint::AfterCas => {
                unreachable!("only staging points record writes")
            }
        }
    }
    assert_eq!(apply(&node, &intent), committed);
    let request = node.request_context();
    assert_eq!(
        node.runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap()
            .basis()
            .body(),
        &after
    );
    let close_cx = database_context(&node);
    node.runtime()
        .block_on(inspection_store.close(&close_cx))
        .unwrap();
    node.shutdown().unwrap();
}

#[test]
fn native_merge_file_backed_prepare_crash_retries_without_half_publication() {
    run_selected_child();
    run_case(
        "native_merge_file_backed_prepare_crash_retries_without_half_publication",
        CrashPoint::BeforeCas,
        GitHashAlgorithm::Sha1,
    );
}

#[test]
fn native_merge_file_backed_post_cas_crash_recovers_exact_outcome() {
    run_selected_child();
    run_case(
        "native_merge_file_backed_post_cas_crash_recovers_exact_outcome",
        CrashPoint::AfterCas,
        GitHashAlgorithm::Sha256,
    );
}

#[test]
fn native_merge_file_backed_staging_crashes_reuse_exact_bodies_and_publish_once() {
    // Dispatch once BEFORE entering the parent matrix: every subprocess runs
    // exactly its selected point and format, never another subprocess or matrix.
    run_selected_child();
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for point in CrashPoint::STAGING {
            run_case(
                "native_merge_file_backed_staging_crashes_reuse_exact_bodies_and_publish_once",
                point,
                format,
            );
        }
    }
}
