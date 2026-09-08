#![forbid(unsafe_code)]
//! Process-death boundaries through native admission and the real file-backed
//! authority. This is process-crash recovery, not power-loss/fsync fault proof.
//! The decorator forwards storage operations; it contains no publication model.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::{fs, process};

use fgit_admission::merge::native::objects::{MergeObjectLimits, validate_merge_objects};
use fgit_admission::merge::native::{
    NativeMergeIntent, NativeMergeProjection, admit_native_merge_async,
};
use fgit_admission::{
    AdmissionContext, AdmissionLimits, AdmissionSnapshot, AsyncAdmissionProjection,
    CommitMaterialization, ProjectionFailure, RefusalMaterialization, ValidatedClosure,
};
use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityLimits,
    AuthorityVersionToken, CasOutcome, DuplicateAbsenceWitness, HeadInit, HeadKey, HeadRead,
    HeadReadReceipt, IdempotencyKey, ImmutableKey, ImmutableRead, PutOutcome, StoreInstanceId,
    TerminalOutcome,
};
use fgit_chronicle::PublicationBasis;
use fgit_codec::RepositoryAuthorityHeadBody;
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
const MERGE_KEY: &[u8] = b"native-durable-crash-merge";
const STORE_INSTANCE: StoreInstanceId = StoreInstanceId::from_raw(203);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CrashPoint {
    BeforeCas,
    AfterCas,
}
impl CrashPoint {
    const fn exit_code(self) -> i32 {
        match self {
            Self::BeforeCas => 82,
            Self::AfterCas => 83,
        }
    }
}

/// Abruptly exits at the actual async authority boundary, after every candidate
/// body has been awaited by the production native driver. AfterCas exits only
/// when the real backend returned its successful atomic publication receipt.
struct CrashAuthority {
    inner: FsqliteAuthorityStore,
    point: CrashPoint,
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
        AsyncAuthorityStore::put_if_absent(&self.inner, cx, key, body).await
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
        if matches!(&result, Ok(CasOutcome::Committed(_))) {
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
/// This adapter supplies only the additional native object-validation capability
/// and forwards the wrapped backend to that projection's actual store contract.
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

fn child(root: &Path, format: GitHashAlgorithm, point: CrashPoint) -> ! {
    let mut node = OneNode::open_existing(config(root, format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let cx = Cx::new();
    cx.set_native_cx(node.runtime().request_cx(BudgetClass::Database));
    let inner = node
        .runtime()
        .block_on(FsqliteAuthorityStore::open(
            &cx,
            root.join("node/authority.fsqlite").to_str().unwrap(),
            STORE_INSTANCE,
            AuthorityLimits::default(),
        ))
        .unwrap();
    let authority = CrashAuthority { inner, point };
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
    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        child(&PathBuf::from(root), format, point);
    }
    let scratch = Scratch::new();
    let objects = Objects::new(format);
    let intent = objects.intent();
    let before = prepare(&scratch.0, &objects);
    let status = process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg(test)
        .arg("--nocapture")
        .env(CHILD_ROOT, &scratch.0)
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(point.exit_code()),
        "the child must reach the exact real CAS boundary"
    );
    let mut node = OneNode::open_existing(config(&scratch.0, format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let request = node.request_context();
    let recovered = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    match point {
        CrashPoint::BeforeCas => {
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
    node.shutdown().unwrap();
}

#[test]
fn native_merge_file_backed_prepare_crash_retries_without_half_publication() {
    run_case(
        "native_merge_file_backed_prepare_crash_retries_without_half_publication",
        CrashPoint::BeforeCas,
        GitHashAlgorithm::Sha1,
    );
}

#[test]
fn native_merge_file_backed_post_cas_crash_recovers_exact_outcome() {
    run_case(
        "native_merge_file_backed_post_cas_crash_recovers_exact_outcome",
        CrashPoint::AfterCas,
        GitHashAlgorithm::Sha256,
    );
}
