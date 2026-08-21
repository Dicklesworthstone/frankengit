#![forbid(unsafe_code)]

//! One-process FrankenGit node assembly.
//!
//! This crate composes published subsystem boundaries only.  It opens the
//! admitted embedded `FrankenSQLite` authority profile on the node-owned
//! Asupersync runtime and places Git object bodies through the local immutable
//! object-fabric backend. Neither backend is represented by a node-owned map.
//!
//! Database opening and clean shutdown run through the owned runtime during
//! node lifecycle transitions. Authority operations themselves remain async:
//! no synchronous request-path adapter is introduced around the async engine.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::{Path, PathBuf};
use std::time::Duration;

use fgit_authority::{
    AuthenticatedHead, AuthorityLimits, HeadInit, HeadKey, HeadRead, StoreInstanceId, body_key,
};
use fgit_authority_fsqlite::{EngineError, FsqliteAuthorityStore};
use fgit_codec::{schema::RepositoryAuthorityHeadBody, wire::encode_body};
use fgit_crypto::{GitObjectKind, IdentityDomain, git_object_id, git_payload_commitment};
use fgit_git_object::ObjectType;
use fgit_object_fabric::fabric::{
    ImmutableObjectFabric, PlacementAdmission, PutIfAbsent, StoreRefusal, VerifiedObject,
};
use fgit_object_fabric::local::{LocalFilesystemConfig, LocalFilesystemFabric};
use fgit_object_fabric::{ObjectEnvelope, ObjectKind, SegmentLimits};
use fgit_resource::{
    Grade, LeakDisposition, ObligationLedger, RegionCloseOutcome, RegionId, ResourceError,
    ResourceVector,
};
use fgit_runtime::{BudgetClass, NodeRuntime, RuntimeProfile, RuntimeRefusal};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, GitHashAlgorithm, GitOid, HeadGeneration, PolicyEpoch,
    RegistryEpoch, RepositoryId, TenantId,
};
use fsqlite_types::cx::Cx as FsqliteCx;

const OBJECT_CODEC_NAMESPACE: &[u8] = b"git-object-body/v1";
const HEAD_KEY_PREFIX: &[u8] = b"frankengit/node/head/";
const FABRIC_NAMESPACE_PREFIX: &[u8] = b"frankengit/node/object/";
const DEFAULT_MAX_OBJECT_BYTES: u64 = 32 * 1024 * 1024;
const AUTHORITY_DATABASE_FILE: &str = "authority.fsqlite";
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Typed refusal from the node assembly boundary.
#[derive(Debug)]
pub enum NodeRefusal {
    /// An empty filesystem root would make the storage target ambiguous.
    EmptyStorageRoot,
    /// A caller-selected worker count was outside this slice's finite profile.
    InvalidWorkerCount,
    /// The runtime could not establish its finite production profile.
    Runtime(RuntimeRefusal),
    /// Authority-head staging or initialization refused or was ambiguous.
    Authority(fgit_authority::OutcomeFailure),
    /// A non-initializing open found no canonical authority head.
    AuthorityHeadAbsent,
    /// The operator-selected storage root cannot name the embedded database.
    StoragePathEncoding,
    /// The derived authority-head key was outside the bounded key vocabulary.
    HeadKey(fgit_authority::KeyError),
    /// A newly constructed durable authority unexpectedly held another head.
    HeadInitializationConflict,
    /// Authority initialization failed and its explicit worker cleanup failed too.
    AuthorityInitializationCleanup {
        /// The initialization failure observed before cleanup.
        initialization: Box<NodeRefusal>,
        /// The failure while awaiting the authority worker's close.
        cleanup: Box<NodeRefusal>,
    },
    /// A non-initializing open failed and then could not prove clean teardown.
    ExistingOpenCleanup {
        /// The refusal observed while opening or authenticating the head.
        opening: Box<NodeRefusal>,
        /// The refusal while draining the partially opened node.
        cleanup: Box<NodeRefusal>,
    },
    /// The local immutable object fabric refused the requested operation.
    Fabric(StoreRefusal),
    /// Object bytes exceeded this node's configured storage bound.
    ObjectTooLarge { offered: u64, maximum: u64 },
    /// A platform-sized object length could not be represented canonically.
    ObjectLengthOverflow,
    /// Resource custody could not issue the bounded placement grant.
    Resource(ResourceError),
    /// A storage effect failed to settle its obligation region.
    ResourceContainment,
    /// The node root did not quiesce within its bounded shutdown interval.
    RuntimeContainment,
    /// A fixed node identity handle failed its bounded representation.
    Identity(fgit_resource::IdentityError),
}

impl Display for NodeRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyStorageRoot => formatter.write_str("node storage root is empty"),
            Self::InvalidWorkerCount => formatter.write_str("node worker count must be non-zero"),
            Self::Runtime(error) => Display::fmt(error, formatter),
            Self::Authority(error) => Display::fmt(error, formatter),
            Self::AuthorityHeadAbsent => {
                formatter.write_str("node authority head is absent; run fg init before doctor")
            }
            Self::StoragePathEncoding => formatter.write_str(
                "node storage root cannot be represented as a UTF-8 embedded authority path",
            ),
            Self::HeadKey(error) => Display::fmt(error, formatter),
            Self::HeadInitializationConflict => {
                formatter.write_str("durable authority head conflicts during initialization")
            }
            Self::AuthorityInitializationCleanup {
                initialization,
                cleanup,
            } => write!(
                formatter,
                "authority initialization failed ({initialization}) and explicit cleanup failed ({cleanup})"
            ),
            Self::ExistingOpenCleanup { opening, cleanup } => write!(
                formatter,
                "non-initializing node open failed ({opening}) and explicit cleanup failed ({cleanup})"
            ),
            Self::Fabric(error) => Display::fmt(error, formatter),
            Self::ObjectTooLarge { offered, maximum } => {
                write!(
                    formatter,
                    "object is {offered} bytes but node limit is {maximum}"
                )
            }
            Self::ObjectLengthOverflow => {
                formatter.write_str("object length exceeds canonical range")
            }
            Self::Resource(error) => Display::fmt(error, formatter),
            Self::ResourceContainment => {
                formatter.write_str("object placement region did not reach quiescence")
            }
            Self::RuntimeContainment => {
                formatter.write_str("node runtime did not reach quiescence during shutdown")
            }
            Self::Identity(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for NodeRefusal {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
            Self::Authority(error) => Some(error),
            Self::HeadKey(error) => Some(error),
            Self::AuthorityInitializationCleanup { initialization, .. } => Some(initialization),
            Self::ExistingOpenCleanup { opening, .. } => Some(opening),
            Self::Fabric(error) => Some(error),
            Self::Resource(error) => Some(error),
            Self::Identity(error) => Some(error),
            Self::EmptyStorageRoot
            | Self::InvalidWorkerCount
            | Self::AuthorityHeadAbsent
            | Self::HeadInitializationConflict
            | Self::StoragePathEncoding
            | Self::ObjectTooLarge { .. }
            | Self::ObjectLengthOverflow
            | Self::ResourceContainment
            | Self::RuntimeContainment => None,
        }
    }
}

/// Explicit inputs for initializing one embedded node.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    storage_root: PathBuf,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    store_instance: StoreInstanceId,
    worker_threads: usize,
    object_format: GitHashAlgorithm,
    max_object_bytes: u64,
    segment_limits: SegmentLimits,
}

impl NodeConfig {
    /// Creates the bounded SHA-1 Git compatibility profile used in this slice.
    #[must_use]
    pub fn new(storage_root: PathBuf, tenant_id: TenantId, repository_id: RepositoryId) -> Self {
        Self {
            storage_root,
            tenant_id,
            repository_id,
            store_instance: StoreInstanceId::from_raw(1),
            worker_threads: 1,
            object_format: GitHashAlgorithm::Sha1,
            max_object_bytes: DEFAULT_MAX_OBJECT_BYTES,
            segment_limits: SegmentLimits::default(),
        }
    }

    /// Selects the explicit one-process authority instance identity.
    #[must_use]
    pub const fn with_store_instance(mut self, store_instance: StoreInstanceId) -> Self {
        self.store_instance = store_instance;
        self
    }

    /// Selects a finite production runtime worker count.
    #[must_use]
    pub const fn with_worker_threads(mut self, worker_threads: usize) -> Self {
        self.worker_threads = worker_threads;
        self
    }

    /// Selects the native Git object identity domain.
    #[must_use]
    pub const fn with_object_format(mut self, object_format: GitHashAlgorithm) -> Self {
        self.object_format = object_format;
        self
    }

    /// Selects the pre-allocation object byte ceiling.
    #[must_use]
    pub const fn with_max_object_bytes(mut self, max_object_bytes: u64) -> Self {
        self.max_object_bytes = max_object_bytes;
        self
    }
}

/// The idempotent result of creating the initial authority head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeInitialization {
    /// The head slot was absent and this call created it.
    Created,
    /// The requested genesis head was already installed byte-for-byte.
    IdenticalRetry,
}

/// Bounded, authenticated observations made by [`OneNode::doctor`].
///
/// This is deliberately narrower than a replay proof. It authenticates the
/// current authority receipt and, when the caller names one native object,
/// re-verifies that object's immutable envelope, native identity, and payload
/// commitment. It neither enumerates physical storage nor reconstructs an RCR
/// chain; those capabilities remain owned by the future materializer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorReport {
    authority_head: AuthenticatedHead,
    sampled_object: Option<GitOid>,
}

impl DoctorReport {
    /// The current authority receipt authenticated by the embedded store.
    #[must_use]
    pub const fn authority_head(&self) -> &AuthenticatedHead {
        &self.authority_head
    }

    /// The exact object independently re-verified by this invocation, if any.
    #[must_use]
    pub const fn sampled_object(&self) -> Option<GitOid> {
        self.sampled_object
    }
}

/// In-process authority/fabric bootstrap for the future one-node server assembly.
///
/// This type deliberately does not claim a transport service: the currently
/// published wire crate is SANS-I/O and the canonical ref projection required
/// for receive admission has not yet been published as a production surface.
#[derive(Debug)]
pub struct OneNode {
    authority: FsqliteAuthorityStore,
    authority_cx: FsqliteCx,
    head_key: HeadKey,
    fabric: LocalFilesystemFabric,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    namespace: Vec<u8>,
    object_format: GitHashAlgorithm,
    max_object_bytes: u64,
    segment_limits: SegmentLimits,
    // Kept last so an unexpected drop releases the authority context before
    // the runtime that owns its attached native context.
    runtime: NodeRuntime,
}

impl OneNode {
    /// Opens the durable authority store and initializes its first head when absent.
    ///
    /// Runtime blocking here is only node lifecycle work. Request operations
    /// such as [`Self::read_authority_head`] remain async over the runtime-owned
    /// database context.
    pub fn init(config: NodeConfig) -> Result<(Self, NodeInitialization), NodeRefusal> {
        let genesis = genesis_head(config.repository_id);
        let node = Self::open_components(config)?;
        let initialization = match initialize_embedded_repository(
            &node.runtime,
            &node.authority,
            &node.authority_cx,
            &node.head_key,
            &genesis,
        ) {
            Ok(HeadInit::Created(_)) => Ok(NodeInitialization::Created),
            Ok(HeadInit::IdenticalRetry(_)) => Ok(NodeInitialization::IdenticalRetry),
            Ok(HeadInit::Conflict) => Err(NodeRefusal::HeadInitializationConflict),
            Err(error) => Err(error),
        };
        match initialization {
            Ok(initialization) => Ok((node, initialization)),
            Err(initialization) => {
                let cleanup = node.shutdown();
                match cleanup {
                    Ok(()) => Err(initialization),
                    Err(cleanup) => Err(NodeRefusal::AuthorityInitializationCleanup {
                        initialization: Box::new(initialization),
                        cleanup: Box::new(cleanup),
                    }),
                }
            }
        }
    }

    /// Opens an already initialized node without synthesizing a canonical head.
    ///
    /// The embedded engine must establish its fixed local schema before it can
    /// read, but this method never calls `initialize_head`: an absent head is a
    /// typed refusal. A successful return has authenticated the current head
    /// receipt against the store's issuance record.
    pub fn open_existing(config: NodeConfig) -> Result<Self, NodeRefusal> {
        let node = Self::open_components(config)?;
        let opened = node.runtime().block_on(node.authenticate_authority_head());
        match opened {
            Ok(_) => Ok(node),
            Err(opening) => Err(close_after_existing_open_failure(node, opening)),
        }
    }

    fn open_components(config: NodeConfig) -> Result<Self, NodeRefusal> {
        if config.storage_root.as_os_str().is_empty() {
            return Err(NodeRefusal::EmptyStorageRoot);
        }
        if config.worker_threads == 0 {
            return Err(NodeRefusal::InvalidWorkerCount);
        }

        let runtime = RuntimeProfile::production(config.worker_threads)
            .build()
            .map_err(NodeRefusal::Runtime)?;
        let authority_path = authority_database_path(&config.storage_root)?;
        let namespace = object_namespace(config.repository_id);
        let failure_domain = fgit_resource::OpaqueHandle::new(b"node-local-filesystem")
            .map_err(NodeRefusal::Identity)?;
        let encryption_dependency =
            fgit_resource::OpaqueHandle::new(b"node-local-key").map_err(NodeRefusal::Identity)?;
        let fabric = LocalFilesystemFabric::open(LocalFilesystemConfig::new(
            config.storage_root,
            namespace.clone(),
            failure_domain,
            encryption_dependency,
            config.max_object_bytes,
            config.segment_limits.clone(),
        ))
        .map_err(NodeRefusal::Fabric)?;

        let head_key = head_key(config.repository_id)?;
        let authority_native_cx = runtime.request_cx(BudgetClass::Database);
        let authority_cx = FsqliteCx::new();
        // The database context retains this clone, making the binding to the
        // node-owned runtime explicit rather than relying on task-local state.
        authority_cx.set_native_cx(authority_native_cx);
        let authority = runtime
            .block_on(FsqliteAuthorityStore::open(
                &authority_cx,
                authority_path,
                config.store_instance,
                AuthorityLimits::default(),
            ))
            .map_err(authority_engine_refusal)?;
        Ok(Self {
            runtime,
            authority,
            authority_cx,
            head_key,
            fabric,
            tenant_id: config.tenant_id,
            repository_id: config.repository_id,
            namespace,
            object_format: config.object_format,
            max_object_bytes: config.max_object_bytes,
            segment_limits: config.segment_limits,
        })
    }

    /// Returns the runtime responsible for request contexts and lifecycle.
    #[must_use]
    pub const fn runtime(&self) -> &NodeRuntime {
        &self.runtime
    }

    /// Returns the repository tenant identity.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Returns the repository identity governed by this node's authority head.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Reads the current authority-selected head; the object fabric is not authority.
    pub async fn read_authority_head(&self) -> Result<HeadRead, NodeRefusal> {
        self.authority
            .read_head(&self.authority_cx, &self.head_key)
            .await
            .map_err(authority_engine_refusal)
    }

    /// Re-reads and authenticates the current authority-head receipt.
    ///
    /// Authentication proves the store issued the exact key, token,
    /// generation, and body presented in the read receipt. It does not prove
    /// that this receipt is current after the read, so callers still need CAS
    /// for publication.
    pub async fn authenticate_authority_head(&self) -> Result<AuthenticatedHead, NodeRefusal> {
        let HeadRead::Present(receipt) = self.read_authority_head().await? else {
            return Err(NodeRefusal::AuthorityHeadAbsent);
        };
        self.authority
            .authenticate_head_receipt(&self.authority_cx, &receipt)
            .await
            .map_err(authority_engine_refusal)
    }

    /// Performs the currently published bounded doctor checks.
    ///
    /// `sampled_object` is caller-selected rather than discovered from a
    /// directory listing. It is accepted only in this node's declared native
    /// Git identity domain, then read through fabric's verified-whole-read
    /// boundary. No sample means authority-head authentication only.
    pub async fn doctor(
        &self,
        sampled_object: Option<GitOid>,
    ) -> Result<DoctorReport, NodeRefusal> {
        let authority_head = self.authenticate_authority_head().await?;
        if let Some(identity) = sampled_object {
            let _ = self.read_git_object(identity)?;
        }
        Ok(DoctorReport {
            authority_head,
            sampled_object,
        })
    }

    /// Awaits authority-worker closure and then joins the owning runtime.
    ///
    /// Callers that obtain a node must use this before dropping it so a clean
    /// stop has an observed quiescence result instead of relying on the
    /// database driver's drop-time backstop.
    pub fn shutdown(mut self) -> Result<(), NodeRefusal> {
        self.runtime
            .block_on(self.authority.close(&self.authority_cx))
            .map_err(authority_engine_refusal)?;
        if self.runtime.join_root(SHUTDOWN_TIMEOUT) {
            Ok(())
        } else {
            Err(NodeRefusal::RuntimeContainment)
        }
    }

    /// Validates and immutably places one native Git object through object fabric.
    pub fn put_git_object(
        &self,
        object_type: ObjectType,
        body: Vec<u8>,
    ) -> Result<StoredObject, NodeRefusal> {
        let offered = u64::try_from(body.len()).map_err(|_| NodeRefusal::ObjectLengthOverflow)?;
        if offered > self.max_object_bytes {
            return Err(NodeRefusal::ObjectTooLarge {
                offered,
                maximum: self.max_object_bytes,
            });
        }
        let object_kind = fabric_object_kind(object_type);
        let crypto_kind = crypto_object_kind(object_type);
        let identity = git_object_id(self.object_format, crypto_kind, &body);
        let commitment = git_payload_commitment(crypto_kind, &body, CANONICAL_CODEC_VERSION);
        let mut commitment_bytes = [0_u8; 32];
        commitment_bytes.copy_from_slice(commitment.digest().as_bytes());
        let envelope = ObjectEnvelope::new(
            self.namespace.clone(),
            identity,
            object_kind,
            offered,
            commitment_bytes,
            OBJECT_CODEC_NAMESPACE.to_vec(),
            commitment_bytes,
            None,
            &self.segment_limits,
        )
        .map_err(|error| NodeRefusal::Fabric(StoreRefusal::Fabric(error)))?;
        let verified = VerifiedObject::new(envelope, body).map_err(NodeRefusal::Fabric)?;
        let ledger = ObligationLedger::root(
            RegionId::new(1),
            LeakDisposition::RecordAndContinue,
            placement_resources(offered),
        );
        let grant = ledger
            .grant(placement_resources(offered))
            .map_err(NodeRefusal::Resource)?;
        let outcome = self
            .fabric
            .put_if_absent(verified, PlacementAdmission::new(&ledger, grant));
        let closed = ledger.close();
        if !matches!(closed, RegionCloseOutcome::Quiescent(_)) {
            return Err(NodeRefusal::ResourceContainment);
        }
        match outcome.map_err(NodeRefusal::Fabric)? {
            PutIfAbsent::Created { .. } => Ok(StoredObject::Created(identity)),
            PutIfAbsent::AlreadyPresent { .. } => Ok(StoredObject::AlreadyPresent(identity)),
        }
    }

    /// Reads one exact immutable Git object from the local fabric.
    pub fn read_git_object(&self, identity: GitOid) -> Result<VerifiedObject, NodeRefusal> {
        if identity.algorithm() != self.object_format {
            return Err(NodeRefusal::Fabric(
                StoreRefusal::NativeObjectIdentityMismatch,
            ));
        }
        self.fabric
            .read_whole(identity)
            .map(|read| read.object)
            .map_err(NodeRefusal::Fabric)
    }
}

fn close_after_existing_open_failure(node: OneNode, opening: NodeRefusal) -> NodeRefusal {
    match node.shutdown() {
        Ok(()) => opening,
        Err(cleanup) => NodeRefusal::ExistingOpenCleanup {
            opening: Box::new(opening),
            cleanup: Box::new(cleanup),
        },
    }
}

/// Observable immutable-placement outcome; neither case is an authority publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredObject {
    /// The exact immutable object was newly placed.
    Created(GitOid),
    /// An identical immutable object was already present.
    AlreadyPresent(GitOid),
}

impl StoredObject {
    /// The native object identity named by either placement outcome.
    #[must_use]
    pub const fn identity(self) -> GitOid {
        match self {
            Self::Created(identity) | Self::AlreadyPresent(identity) => identity,
        }
    }
}

fn head_key(repository_id: RepositoryId) -> Result<HeadKey, NodeRefusal> {
    let mut bytes = Vec::with_capacity(HEAD_KEY_PREFIX.len() + repository_id.as_bytes().len());
    bytes.extend_from_slice(HEAD_KEY_PREFIX);
    bytes.extend_from_slice(repository_id.as_bytes());
    HeadKey::new(bytes).map_err(NodeRefusal::HeadKey)
}

fn authority_database_path(storage_root: &Path) -> Result<String, NodeRefusal> {
    storage_root
        .join(AUTHORITY_DATABASE_FILE)
        .into_os_string()
        .into_string()
        .map_err(|_| NodeRefusal::StoragePathEncoding)
}

fn authority_engine_refusal(error: EngineError) -> NodeRefusal {
    NodeRefusal::Authority(error.into_failure().into())
}

fn initialize_embedded_repository(
    runtime: &NodeRuntime,
    authority: &FsqliteAuthorityStore,
    authority_cx: &FsqliteCx,
    head_key: &HeadKey,
    genesis: &RepositoryAuthorityHeadBody,
) -> Result<HeadInit, NodeRefusal> {
    let immutable_key = body_key(IdentityDomain::RepositoryAuthorityHead, genesis)
        .map_err(|error| NodeRefusal::Authority(error.into()))?;
    let body = encode_body(genesis).map_err(|error| NodeRefusal::Authority(error.into()))?;
    runtime
        .block_on(authority.put_if_absent(authority_cx, &immutable_key, &body))
        .map_err(authority_engine_refusal)?;
    let generation = HeadGeneration::try_new(genesis.generation.get()).map_err(|error| {
        NodeRefusal::Authority(fgit_authority::OutcomeFailure::Codec(error.into()))
    })?;
    runtime
        .block_on(authority.initialize_head(authority_cx, head_key, generation, &body))
        .map_err(authority_engine_refusal)
}

fn object_namespace(repository_id: RepositoryId) -> Vec<u8> {
    let mut namespace =
        Vec::with_capacity(FABRIC_NAMESPACE_PREFIX.len() + repository_id.as_bytes().len());
    namespace.extend_from_slice(FABRIC_NAMESPACE_PREFIX);
    namespace.extend_from_slice(repository_id.as_bytes());
    namespace
}

fn genesis_head(repository_id: RepositoryId) -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id,
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: genesis_root(repository_id, b"refs"),
        forge_position_root: genesis_root(repository_id, b"forge-position"),
        outcome_index_root: genesis_root(repository_id, b"outcome-index"),
        retention_root: genesis_root(repository_id, b"retention"),
        outbox_root: genesis_root(repository_id, b"outbox"),
        configuration_root: genesis_root(repository_id, b"configuration"),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

fn genesis_root(repository_id: RepositoryId, label: &[u8]) -> Digest {
    let mut bytes = Vec::with_capacity(label.len() + repository_id.as_bytes().len());
    bytes.extend_from_slice(label);
    bytes.extend_from_slice(repository_id.as_bytes());
    let commitment = git_payload_commitment(GitObjectKind::Blob, &bytes, CANONICAL_CODEC_VERSION);
    Digest::new(
        IdentityDomain::GitPayloadCommitment.algorithm().id(),
        *commitment.digest(),
    )
}

const fn fabric_object_kind(object_type: ObjectType) -> ObjectKind {
    match object_type {
        ObjectType::Commit => ObjectKind::Commit,
        ObjectType::Tree => ObjectKind::Tree,
        ObjectType::Blob => ObjectKind::Blob,
        ObjectType::Tag => ObjectKind::Tag,
    }
}

const fn crypto_object_kind(object_type: ObjectType) -> GitObjectKind {
    match object_type {
        ObjectType::Commit => GitObjectKind::Commit,
        ObjectType::Tree => GitObjectKind::Tree,
        ObjectType::Blob => GitObjectKind::Blob,
        ObjectType::Tag => GitObjectKind::Tag,
    }
}

fn placement_resources(object_bytes: u64) -> ResourceVector {
    ResourceVector::from_grades(&[(Grade::Bytes, object_bytes.max(1)), (Grade::Objects, 1)])
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use fgit_authority::HeadRead;
    use fgit_types::{RepositoryId, TenantId};

    use super::{NodeConfig, NodeInitialization, NodeRefusal, OneNode};

    static NEXT_SCRATCH_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct ScratchDirectory {
        root: PathBuf,
    }

    impl ScratchDirectory {
        fn new() -> Self {
            let sequence = NEXT_SCRATCH_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "frankengit-node-authority-{}-{sequence}",
                std::process::id()
            ));
            Self { root }
        }

        fn path(&self) -> &Path {
            &self.root
        }
    }

    impl Drop for ScratchDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn test_config(root: PathBuf) -> NodeConfig {
        NodeConfig::new(
            root,
            TenantId::from_bytes([0x11; 16]),
            RepositoryId::from_bytes([0x22; 16]),
        )
    }

    #[test]
    fn clean_restart_uses_the_same_durable_authority_head() {
        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf());

        let (first, first_init) = OneNode::init(config.clone()).expect("first node opens");
        assert_eq!(first_init, NodeInitialization::Created);
        let first_head = first
            .runtime()
            .block_on(first.read_authority_head())
            .expect("first head reads");
        assert!(matches!(&first_head, HeadRead::Present(_)));
        first.shutdown().expect("first node closes cleanly");

        let (second, second_init) = OneNode::init(config).expect("reopened node opens");
        assert_eq!(second_init, NodeInitialization::IdenticalRetry);
        let second_head = second
            .runtime()
            .block_on(second.read_authority_head())
            .expect("reopened head reads");
        assert_eq!(second_head, first_head);
        second.shutdown().expect("reopened node closes cleanly");
    }

    #[test]
    fn doctor_authenticates_the_head_and_rechecks_a_named_object() {
        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf());
        let (node, _) = OneNode::init(config.clone()).expect("node opens");
        let stored = node
            .put_git_object(fgit_git_object::ObjectType::Blob, b"doctor sample".to_vec())
            .expect("sample stores");
        let report = node
            .runtime()
            .block_on(node.doctor(Some(stored.identity())))
            .expect("doctor authenticates and verifies the named sample");
        assert_eq!(report.sampled_object(), Some(stored.identity()));
        assert_eq!(
            report.authority_head().receipt().generation(),
            fgit_types::HeadGeneration::FIRST
        );
        node.shutdown().expect("node closes cleanly");

        let reopened = OneNode::open_existing(config).expect("existing head opens");
        let reopened_report = reopened
            .runtime()
            .block_on(reopened.doctor(None))
            .expect("doctor authenticates reopened head");
        assert_eq!(
            reopened_report.authority_head().receipt().generation(),
            fgit_types::HeadGeneration::FIRST
        );
        reopened.shutdown().expect("reopened node closes cleanly");
    }

    #[test]
    fn open_existing_refuses_an_absent_authority_head() {
        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf());

        assert!(matches!(
            OneNode::open_existing(config),
            Err(NodeRefusal::AuthorityHeadAbsent)
        ));
    }
}
