#![forbid(unsafe_code)]

//! One-process FrankenGit node assembly.
//!
//! This crate composes published subsystem boundaries only.  The authority
//! backend used by this first slice is the faultable in-memory reference
//! profile, so it is deliberately not presented as durable deployment
//! authority.  Git object bodies, by contrast, are placed through the local
//! immutable object-fabric backend and are never represented by a node-owned
//! map.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::PathBuf;

use fgit_authority::{
    AuthorityStore, HeadInit, HeadKey, HeadRead, MemoryAuthorityStore, StoreInstanceId,
    initialize_repository,
};
use fgit_codec::schema::RepositoryAuthorityHeadBody;
use fgit_crypto::{
    GitHashAlgorithm, GitObjectKind, IdentityDomain, git_object_id, git_payload_commitment,
};
use fgit_git_object::ObjectType;
use fgit_object_fabric::{
    ImmutableObjectFabric, LocalFilesystemConfig, LocalFilesystemFabric, ObjectEnvelope,
    ObjectKind, PlacementAdmission, PutIfAbsent, SegmentLimits, StoreRefusal, VerifiedObject,
};
use fgit_resource::{
    Grade, LeakDisposition, ObligationLedger, RegionCloseOutcome, RegionId, ResourceError,
    ResourceVector,
};
use fgit_runtime::{NodeRuntime, RuntimeProfile, RuntimeRefusal};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, GitOid, HeadGeneration, PolicyEpoch, RegistryEpoch,
    RepositoryId, TenantId,
};

const OBJECT_CODEC_NAMESPACE: &[u8] = b"git-object-body/v1";
const HEAD_KEY_PREFIX: &[u8] = b"frankengit/node/head/";
const FABRIC_NAMESPACE_PREFIX: &[u8] = b"frankengit/node/object/";
const DEFAULT_MAX_OBJECT_BYTES: u64 = 32 * 1024 * 1024;

/// Typed refusal from the node assembly boundary.
#[derive(Debug)]
pub enum NodeRefusal {
    /// An empty filesystem root would make the storage target ambiguous.
    EmptyStorageRoot,
    /// A caller-selected worker count was outside this slice's finite profile.
    InvalidWorkerCount,
    /// The runtime could not establish its finite production profile.
    Runtime(RuntimeRefusal),
    /// Authority-head staging or initialization refused.
    Authority(fgit_authority::OutcomeFailure),
    /// The derived authority-head key was outside the bounded key vocabulary.
    HeadKey(fgit_authority::KeyError),
    /// A newly constructed reference authority unexpectedly held another head.
    HeadInitializationConflict,
    /// The authority backend refused a head read.
    AuthorityRead(fgit_authority::AuthorityFailure),
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
            Self::HeadKey(error) => Display::fmt(error, formatter),
            Self::HeadInitializationConflict => {
                formatter.write_str("reference authority head conflicts during initialization")
            }
            Self::AuthorityRead(error) => Display::fmt(error, formatter),
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
            Self::AuthorityRead(error) => Some(error),
            Self::Fabric(error) => Some(error),
            Self::Resource(error) => Some(error),
            Self::Identity(error) => Some(error),
            Self::EmptyStorageRoot
            | Self::InvalidWorkerCount
            | Self::HeadInitializationConflict
            | Self::ObjectTooLarge { .. }
            | Self::ObjectLengthOverflow
            | Self::ResourceContainment => None,
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

/// A real one-process server assembly with an authority head and object fabric.
#[derive(Debug)]
pub struct OneNode {
    runtime: NodeRuntime,
    authority: MemoryAuthorityStore,
    head_key: HeadKey,
    fabric: LocalFilesystemFabric,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    namespace: Vec<u8>,
    object_format: GitHashAlgorithm,
    max_object_bytes: u64,
    segment_limits: SegmentLimits,
}

impl OneNode {
    /// Initializes the authority head and opens the bounded object-fabric namespace.
    ///
    /// The memory authority store is intentionally a reference/fault profile:
    /// it proves one-process protocol composition but does not claim persistence
    /// across node restart.
    pub fn init(config: NodeConfig) -> Result<(Self, NodeInitialization), NodeRefusal> {
        if config.storage_root.as_os_str().is_empty() {
            return Err(NodeRefusal::EmptyStorageRoot);
        }
        if config.worker_threads == 0 {
            return Err(NodeRefusal::InvalidWorkerCount);
        }

        let runtime = RuntimeProfile::production(config.worker_threads)
            .build()
            .map_err(NodeRefusal::Runtime)?;
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

        let authority = MemoryAuthorityStore::new(config.store_instance);
        let head_key = head_key(config.repository_id)?;
        let genesis = genesis_head(config.repository_id);
        let initialization = match initialize_repository(&authority, &head_key, &genesis)
            .map_err(NodeRefusal::Authority)?
        {
            HeadInit::Created(_) => NodeInitialization::Created,
            HeadInit::IdenticalRetry(_) => NodeInitialization::IdenticalRetry,
            HeadInit::Conflict => return Err(NodeRefusal::HeadInitializationConflict),
        };

        Ok((
            Self {
                runtime,
                authority,
                head_key,
                fabric,
                tenant_id: config.tenant_id,
                repository_id: config.repository_id,
                namespace,
                object_format: config.object_format,
                max_object_bytes: config.max_object_bytes,
                segment_limits: config.segment_limits,
            },
            initialization,
        ))
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
    pub fn read_authority_head(&self) -> Result<HeadRead, NodeRefusal> {
        self.authority
            .read_head(&self.head_key)
            .map_err(NodeRefusal::AuthorityRead)
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
        self.fabric
            .read_whole(identity)
            .map(|read| read.object)
            .map_err(NodeRefusal::Fabric)
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
