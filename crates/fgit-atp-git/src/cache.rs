//! Trust-scoped, non-authoritative ATP transfer caching.
//!
//! The cache is deliberately a bounded local view, never canonical state.
//! Its key commits to the caller-authorized trust scope, an encryption-key
//! domain label, and the content identity, so a hit in one scope cannot answer
//! a lookup in another.  Cache policy is separate from the resource crate's
//! [`fgit_resource::CacheGrant`]: that grant funds a materialization attempt,
//! while [`TransferCacheGrant`] states who may read an ATP payload once the
//! caller has already authorized the cache scope.
//!
//! An Intent Run identity is owned by the agent protocol, not by this crate.
//! [`IntentRunCacheScope`] therefore wraps the resource crate's opaque,
//! caller-authorized cache scope instead of inventing a second `IntentRunId`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fgit_crypto::{
    IdentityDomain, SchemaFamily, SchemaId, internal_id_preimage_header, sha256_digest,
};
use fgit_object_fabric::Commitment;
use fgit_resource::CacheScope as ResourceCacheScope;
use fgit_types::{PrincipalId, RepositoryId, TenantId};

use crate::{PeerIdentity, PeerPenaltyLedger, PeerPenaltyPolicy, TransferPayload};

/// Canonical body schema for [`IdentityDomain::AtpTrustCacheKey`].
///
/// The identity-domain registry owns the domain tag; this crate owns the
/// cache-key body format that commits the exact partition, encryption-key
/// domain label, and content identity.
const CACHE_KEY_SCHEMA: SchemaId = SchemaId::new(
    SchemaFamily::from_static("frankengit.atp-trust-cache-key"),
    1,
    0,
);

/// One monotonically increasing policy time supplied by the cache owner.
///
/// This is deliberately logical time: a cache cannot make wall-clock time a
/// hidden part of its access policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CacheEpoch(u64);

impl CacheEpoch {
    /// Builds one owner-supplied logical cache epoch.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the logical epoch value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// An opaque encryption-key domain label, never key material.
///
/// The value separates keys even when scope and payload identity match.  It
/// lets a caller rotate or partition encryption domains without exposing a
/// key or treating content identity as cache authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CacheKeyDomain([u8; 32]);

impl CacheKeyDomain {
    /// Builds one exact key-domain label from caller-authorized bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the non-secret domain label.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// A typed wrapper around the agent-owned Intent-Run cache scope.
///
/// `fgit-resource` intentionally carries this identity verbatim because the
/// agent protocol owns its disclosure rules.  ATP may compare it for exact
/// cache partitioning but does not derive, reinterpret, or publish it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IntentRunCacheScope(ResourceCacheScope);

impl IntentRunCacheScope {
    /// Wraps one caller-authorized resource cache scope for an Intent Run.
    #[must_use]
    pub const fn from_authorized_scope(scope: ResourceCacheScope) -> Self {
        Self(scope)
    }

    /// Returns the resource-layer scope without changing its meaning.
    #[must_use]
    pub const fn authorized_scope(self) -> ResourceCacheScope {
        self.0
    }
}

/// Cache scopes that can be governed by a shareable cache grant.
///
/// Secret-bearing entries are intentionally absent.  They use
/// [`SecretCacheScope`] and [`SecretCacheLease`], which cannot become a
/// [`TransferCacheGrant`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ShareableCacheScope {
    /// A policy-approved public payload cache.
    PublicGlobal,
    /// A tenant-wide cache, separated from every other tenant.
    TenantShared {
        /// Tenant that owns this partition.
        tenant: TenantId,
    },
    /// A cache private to one repository within one tenant.
    RepositoryPrivate {
        /// Tenant that owns the repository.
        tenant: TenantId,
        /// Repository whose entries may be reused.
        repository: RepositoryId,
    },
    /// A cache private to one exact agent Intent Run.
    IntentRunPrivate {
        /// Tenant that owns the run.
        tenant: TenantId,
        /// Repository the run was authorized against.
        repository: RepositoryId,
        /// Agent-protocol-owned Intent-Run cache binding.
        intent_run: IntentRunCacheScope,
    },
}

impl ShareableCacheScope {
    fn permits(self, context: CacheAccessContext) -> bool {
        match self {
            Self::PublicGlobal => true,
            Self::TenantShared { tenant } => context.tenant == tenant,
            Self::RepositoryPrivate { tenant, repository } => {
                context.tenant == tenant && context.repository == repository
            }
            Self::IntentRunPrivate {
                tenant,
                repository,
                intent_run,
            } => {
                context.tenant == tenant
                    && context.repository == repository
                    && context.intent_run == Some(intent_run)
            }
        }
    }

    fn encode_into(self, out: &mut Vec<u8>) {
        match self {
            Self::PublicGlobal => out.push(1),
            Self::TenantShared { tenant } => {
                out.push(2);
                out.extend_from_slice(tenant.as_bytes());
            }
            Self::RepositoryPrivate { tenant, repository } => {
                out.push(3);
                out.extend_from_slice(tenant.as_bytes());
                out.extend_from_slice(repository.as_bytes());
            }
            Self::IntentRunPrivate {
                tenant,
                repository,
                intent_run,
            } => {
                out.push(4);
                out.extend_from_slice(tenant.as_bytes());
                out.extend_from_slice(repository.as_bytes());
                let handle = intent_run.0.handle();
                out.push(u8::try_from(handle.len()).expect("resource scope fits in one byte"));
                out.extend_from_slice(handle.as_bytes());
            }
        }
    }
}

/// Scope for an entry that carries secret-bearing material.
///
/// This is a distinct type, not a [`ShareableCacheScope`] variant.  There is
/// consequently no API that turns it into a reader grant or an audience list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretCacheScope {
    tenant: TenantId,
    repository: RepositoryId,
    intent_run: IntentRunCacheScope,
}

impl SecretCacheScope {
    /// Builds one secret-bearing scope bound to an exact authorized Intent Run.
    #[must_use]
    pub const fn new(
        tenant: TenantId,
        repository: RepositoryId,
        intent_run: IntentRunCacheScope,
    ) -> Self {
        Self {
            tenant,
            repository,
            intent_run,
        }
    }

    fn encode_into(self, out: &mut Vec<u8>) {
        out.push(5);
        out.extend_from_slice(self.tenant.as_bytes());
        out.extend_from_slice(self.repository.as_bytes());
        let handle = self.intent_run.0.handle();
        out.push(u8::try_from(handle.len()).expect("resource scope fits in one byte"));
        out.extend_from_slice(handle.as_bytes());
    }
}

/// A reader-facing context checked before any shareable-cache lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheAccessContext {
    principal: PrincipalId,
    tenant: TenantId,
    repository: RepositoryId,
    intent_run: Option<IntentRunCacheScope>,
    now: CacheEpoch,
}

impl CacheAccessContext {
    /// Builds one access attempt under its exact tenant/repository/run scope.
    #[must_use]
    pub const fn new(
        principal: PrincipalId,
        tenant: TenantId,
        repository: RepositoryId,
        intent_run: Option<IntentRunCacheScope>,
        now: CacheEpoch,
    ) -> Self {
        Self {
            principal,
            tenant,
            repository,
            intent_run,
            now,
        }
    }
}

/// Which principals a shareable cache grant may serve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CacheReaders {
    /// Any authenticated caller may read a public-global grant.
    AnyAuthenticated,
    /// One owner plus an explicit, canonical reader set.
    Explicit {
        /// Principal that owns a plaintext-restricted grant.
        owner: PrincipalId,
        /// Readers admitted by the cache grant, in stable identity order.
        readers: BTreeSet<PrincipalId>,
    },
}

impl CacheReaders {
    /// Builds an explicit reader set and always includes its owner.
    #[must_use]
    pub fn explicit(owner: PrincipalId, readers: impl IntoIterator<Item = PrincipalId>) -> Self {
        let mut readers = readers.into_iter().collect::<BTreeSet<_>>();
        readers.insert(owner);
        Self::Explicit { owner, readers }
    }

    fn permits(&self, principal: PrincipalId) -> bool {
        match self {
            Self::AnyAuthenticated => true,
            Self::Explicit { readers, .. } => readers.contains(&principal),
        }
    }

    fn owner(&self) -> Option<PrincipalId> {
        match self {
            Self::AnyAuthenticated => None,
            Self::Explicit { owner, .. } => Some(*owner),
        }
    }
}

/// Whether raw payload bytes may be served to every listed reader.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlaintextShareability {
    /// Every reader on the grant may receive the verified payload bytes.
    Shareable,
    /// Only the grant owner may receive verified payload bytes.
    OwnerOnly,
}

/// Whether each cache hit/write must produce an audit receipt for its caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheAuditRequirement {
    /// The cache policy requires an audit receipt.
    Required,
    /// The cache policy does not require an audit receipt.
    NotRequired,
}

/// A security policy grant for one shareable transfer-cache partition.
///
/// This grants only local reuse.  It cannot publish an object, move a ref, or
/// establish repository truth.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferCacheGrant {
    scope: ShareableCacheScope,
    readers: CacheReaders,
    plaintext: PlaintextShareability,
    key_domain: CacheKeyDomain,
    expires_at: CacheEpoch,
    audit: CacheAuditRequirement,
}

impl TransferCacheGrant {
    /// Creates one fully specified shareable-cache grant.
    ///
    /// Public-global scope is deliberately constrained to an authenticated,
    /// plaintext-shareable audience.  Private scopes require an explicit
    /// audience, so a caller cannot accidentally construct a tenant,
    /// repository, or Intent-Run cache that every principal can query.
    pub fn new(
        scope: ShareableCacheScope,
        readers: CacheReaders,
        plaintext: PlaintextShareability,
        key_domain: CacheKeyDomain,
        expires_at: CacheEpoch,
        audit: CacheAuditRequirement,
    ) -> Result<Self, CacheRefusal> {
        let public_shape = matches!(scope, ShareableCacheScope::PublicGlobal);
        let public_audience = matches!(&readers, CacheReaders::AnyAuthenticated);
        let plaintext_shared = matches!(plaintext, PlaintextShareability::Shareable);
        if (public_shape && (!public_audience || !plaintext_shared))
            || (!public_shape && public_audience)
            || (matches!(plaintext, PlaintextShareability::OwnerOnly) && readers.owner().is_none())
        {
            return Err(CacheRefusal::InvalidGrantShape);
        }
        Ok(Self {
            scope,
            readers,
            plaintext,
            key_domain,
            expires_at,
            audit,
        })
    }

    /// Returns the exact trust scope this grant governs.
    #[must_use]
    pub const fn scope(&self) -> ShareableCacheScope {
        self.scope
    }

    /// Returns the non-secret encryption-key domain label.
    #[must_use]
    pub const fn key_domain(&self) -> CacheKeyDomain {
        self.key_domain
    }

    /// Returns the cache policy's audit requirement.
    #[must_use]
    pub const fn audit_requirement(&self) -> CacheAuditRequirement {
        self.audit
    }

    fn authorize(&self, context: CacheAccessContext) -> Result<(), CacheRefusal> {
        if !self.scope.permits(context) {
            return Err(CacheRefusal::ScopeDenied);
        }
        if context.now > self.expires_at {
            return Err(CacheRefusal::GrantExpired);
        }
        if !self.readers.permits(context.principal) {
            return Err(CacheRefusal::ReaderDenied);
        }
        if matches!(self.plaintext, PlaintextShareability::OwnerOnly)
            && self.readers.owner() != Some(context.principal)
        {
            return Err(CacheRefusal::PlaintextShareDenied);
        }
        Ok(())
    }
}

/// Exclusive, non-cloneable access to one secret-bearing cache partition.
///
/// There are no reader or plaintext-sharing fields and no conversion to
/// [`TransferCacheGrant`].  A secret-bearing entry therefore cannot acquire a
/// second reader through this API.
pub struct SecretCacheLease {
    scope: SecretCacheScope,
    key_domain: CacheKeyDomain,
    expires_at: CacheEpoch,
    audit: CacheAuditRequirement,
}

impl SecretCacheLease {
    /// Creates an exclusive lease for one secret-bearing cache scope.
    #[must_use]
    pub const fn new(
        scope: SecretCacheScope,
        key_domain: CacheKeyDomain,
        expires_at: CacheEpoch,
        audit: CacheAuditRequirement,
    ) -> Self {
        Self {
            scope,
            key_domain,
            expires_at,
            audit,
        }
    }

    fn require_active(&self, now: CacheEpoch) -> Result<(), CacheRefusal> {
        if now > self.expires_at {
            return Err(CacheRefusal::GrantExpired);
        }
        Ok(())
    }
}

/// An untrusted cache candidate supplied by one peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachePieceCandidate {
    claimed_content_identity: Commitment,
    bytes: Vec<u8>,
}

impl CachePieceCandidate {
    /// Records an untrusted content claim and its candidate bytes.
    #[must_use]
    pub fn new(claimed_content_identity: Commitment, bytes: Vec<u8>) -> Self {
        Self {
            claimed_content_identity,
            bytes,
        }
    }
}

/// Bounded cache capacities, partitioned by exact scope class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferCacheLimits {
    public_entries: usize,
    tenant_entries: usize,
    repository_entries: usize,
    intent_run_entries: usize,
    secret_entries: usize,
    max_piece_bytes: usize,
    max_quarantined_pieces: usize,
}

impl TransferCacheLimits {
    /// Validates every cache and quarantine bound before state is allocated.
    pub const fn new(
        public_entries: usize,
        tenant_entries: usize,
        repository_entries: usize,
        intent_run_entries: usize,
        secret_entries: usize,
        max_piece_bytes: usize,
        max_quarantined_pieces: usize,
    ) -> Result<Self, CacheRefusal> {
        if public_entries == 0
            || tenant_entries == 0
            || repository_entries == 0
            || intent_run_entries == 0
            || secret_entries == 0
            || max_piece_bytes == 0
            || max_quarantined_pieces == 0
        {
            return Err(CacheRefusal::InvalidCacheLimits);
        }
        Ok(Self {
            public_entries,
            tenant_entries,
            repository_entries,
            intent_run_entries,
            secret_entries,
            max_piece_bytes,
            max_quarantined_pieces,
        })
    }

    fn capacity_for(self, partition: CachePartition) -> usize {
        match partition {
            CachePartition::Shareable(ShareableCacheScope::PublicGlobal) => self.public_entries,
            CachePartition::Shareable(ShareableCacheScope::TenantShared { .. }) => {
                self.tenant_entries
            }
            CachePartition::Shareable(ShareableCacheScope::RepositoryPrivate { .. }) => {
                self.repository_entries
            }
            CachePartition::Shareable(ShareableCacheScope::IntentRunPrivate { .. }) => {
                self.intent_run_entries
            }
            CachePartition::Secret(_) => self.secret_entries,
        }
    }
}

/// A typed cache refusal that never discloses another scope's presence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheRefusal {
    /// A grant combined a scope, audience, and plaintext rule incoherently.
    InvalidGrantShape,
    /// A cache capacity bound was zero.
    InvalidCacheLimits,
    /// The caller's tenant/repository/Intent-Run context did not match the grant.
    ScopeDenied,
    /// The caller presented a grant after its logical expiry.
    GrantExpired,
    /// The grant did not list the caller as a reader.
    ReaderDenied,
    /// The caller is a reader but may not receive raw plaintext bytes.
    PlaintextShareDenied,
    /// The peer has reached its bad-piece exclusion threshold.
    PeerExcluded {
        /// Excluded peer identity.
        peer: PeerIdentity,
    },
    /// A candidate exceeded the byte bound before the cache copied it.
    CandidateTooLarge {
        /// Offered candidate byte length.
        offered: usize,
        /// Configured maximum candidate byte length.
        maximum: usize,
    },
    /// The bounded quarantine has no free slot for a new suspect candidate.
    QuarantineFull {
        /// Configured quarantine entry maximum.
        maximum: usize,
    },
    /// The candidate could not be reconstructed as a transfer payload.
    CandidateVerificationRefused,
    /// Cache trust evidence was supplied at an earlier logical epoch.
    TrustEpochRegressed {
        /// Previous ledger epoch.
        previous: u64,
        /// Newly supplied epoch.
        observed: u64,
    },
}

impl fmt::Display for CacheRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGrantShape => {
                formatter.write_str("invalid ATP transfer-cache grant shape")
            }
            Self::InvalidCacheLimits => {
                formatter.write_str("ATP transfer-cache limits must be positive")
            }
            Self::ScopeDenied => formatter.write_str("ATP transfer-cache scope denied"),
            Self::GrantExpired => formatter.write_str("ATP transfer-cache grant expired"),
            Self::ReaderDenied => formatter.write_str("ATP transfer-cache reader denied"),
            Self::PlaintextShareDenied => {
                formatter.write_str("ATP transfer-cache plaintext sharing denied")
            }
            Self::PeerExcluded { peer } => {
                write!(formatter, "ATP transfer-cache peer is excluded: {peer:?}")
            }
            Self::CandidateTooLarge { offered, maximum } => write!(
                formatter,
                "ATP transfer-cache candidate {offered} bytes exceeds bound {maximum}"
            ),
            Self::QuarantineFull { maximum } => {
                write!(
                    formatter,
                    "ATP transfer-cache quarantine reached bound {maximum}"
                )
            }
            Self::CandidateVerificationRefused => {
                formatter.write_str("ATP transfer-cache candidate verification refused")
            }
            Self::TrustEpochRegressed { previous, observed } => write!(
                formatter,
                "ATP transfer-cache trust epoch regressed from {previous} to {observed}"
            ),
        }
    }
}

impl std::error::Error for CacheRefusal {}

/// Result of a read after the grant and scope have been authorized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CacheLookup {
    /// No entry exists in this exact authorized scope/key-domain partition.
    Miss,
    /// A verified payload is available, together with its audit requirement.
    Hit {
        /// Verified cached payload.
        payload: TransferPayload,
        /// Audit policy attached to the grant used for this read.
        audit: CacheAuditRequirement,
    },
}

/// Result of a cache write or poison quarantine action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheWriteReceipt {
    /// A verified payload was stored; the flag records deterministic eviction.
    Stored {
        /// Whether the oldest entry in this exact partition was evicted.
        evicted: bool,
        /// Audit policy attached to the write grant.
        audit: CacheAuditRequirement,
    },
    /// A mismatched candidate was quarantined and its peer was penalized.
    Quarantined {
        /// Peer penalty after recording this bad piece.
        penalty: u32,
        /// Audit policy attached to the attempted write.
        audit: CacheAuditRequirement,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum CachePartition {
    Shareable(ShareableCacheScope),
    Secret(SecretCacheScope),
}

impl CachePartition {
    fn encode_into(self, out: &mut Vec<u8>) {
        match self {
            Self::Shareable(scope) => scope.encode_into(out),
            Self::Secret(scope) => scope.encode_into(out),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CacheEntryKey([u8; 32]);

impl CacheEntryKey {
    fn derive(
        partition: CachePartition,
        key_domain: CacheKeyDomain,
        content_identity: Commitment,
    ) -> Self {
        let mut body = Vec::with_capacity(1 + 16 + 16 + 1 + 32 + 32 + 32);
        partition.encode_into(&mut body);
        body.extend_from_slice(&key_domain.0);
        body.extend_from_slice(&content_identity);
        let body_len = u64::try_from(body.len()).expect("bounded cache key body fits in u64");
        let mut preimage = internal_id_preimage_header(
            IdentityDomain::AtpTrustCacheKey,
            CACHE_KEY_SCHEMA,
            body_len,
        );
        preimage.extend_from_slice(&body);
        Self(sha256_digest(&preimage))
    }
}

#[derive(Clone, Debug)]
struct CachedEntry {
    partition: CachePartition,
    written_at: CacheEpoch,
    payload: TransferPayload,
}

#[derive(Clone, Debug)]
struct QuarantinedCachePiece {
    peer: PeerIdentity,
    claimed_content_identity: Commitment,
    observed_content_identity: Commitment,
    bytes: Vec<u8>,
    quarantined_at: CacheEpoch,
}

/// Metadata for a suspect piece retained outside the serving cache.
///
/// This deliberately excludes the candidate bytes.  An authorized cache owner
/// can audit why a piece was quarantined without turning quarantine into a
/// second, unverified transfer source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuarantinedPieceStatus {
    /// Peer that supplied the mismatched candidate.
    pub peer: PeerIdentity,
    /// Identity the peer claimed for the candidate.
    pub claimed_content_identity: Commitment,
    /// Identity independently reconstructed from the retained bytes.
    pub observed_content_identity: Commitment,
    /// Bounded retained-byte length.
    pub byte_len: usize,
    /// Logical epoch at which the cache quarantined the candidate.
    pub quarantined_at: CacheEpoch,
}

impl From<&QuarantinedCachePiece> for QuarantinedPieceStatus {
    fn from(piece: &QuarantinedCachePiece) -> Self {
        Self {
            peer: piece.peer,
            claimed_content_identity: piece.claimed_content_identity,
            observed_content_identity: piece.observed_content_identity,
            byte_len: piece.bytes.len(),
            quarantined_at: piece.quarantined_at,
        }
    }
}

/// A bounded local cache plus its cache/peer trust ledger.
///
/// This is intentionally in-memory and non-durable.  It is a deterministic
/// cache policy/state machine for one process-local transfer actor; canonical
/// objects remain in the object fabric and authority remains elsewhere.
#[derive(Clone, Debug)]
pub struct TrustScopedTransferCache {
    limits: TransferCacheLimits,
    trust: PeerPenaltyLedger,
    entries: BTreeMap<CacheEntryKey, CachedEntry>,
    quarantine: BTreeMap<CacheEntryKey, QuarantinedCachePiece>,
}

impl TrustScopedTransferCache {
    /// Opens an empty bounded cache under one declared peer-penalty policy.
    #[must_use]
    pub const fn new(limits: TransferCacheLimits, penalty_policy: PeerPenaltyPolicy) -> Self {
        Self {
            limits,
            trust: PeerPenaltyLedger::new(penalty_policy),
            entries: BTreeMap::new(),
            quarantine: BTreeMap::new(),
        }
    }

    /// Stores a candidate under a fully authorized shareable grant.
    pub fn store_shareable(
        &mut self,
        grant: &TransferCacheGrant,
        context: CacheAccessContext,
        peer: PeerIdentity,
        candidate: CachePieceCandidate,
    ) -> Result<CacheWriteReceipt, CacheRefusal> {
        grant.authorize(context)?;
        self.store(
            CachePartition::Shareable(grant.scope),
            grant.key_domain,
            peer,
            candidate,
            context.now,
            grant.audit,
        )
    }

    /// Reads one verified shareable-cache payload after grant enforcement.
    pub fn read_shareable(
        &self,
        grant: &TransferCacheGrant,
        context: CacheAccessContext,
        content_identity: Commitment,
    ) -> Result<CacheLookup, CacheRefusal> {
        grant.authorize(context)?;
        Ok(self.lookup(
            CachePartition::Shareable(grant.scope),
            grant.key_domain,
            content_identity,
            grant.audit,
        ))
    }

    /// Returns metadata for a suspect piece after the same grant enforcement
    /// as a shareable cache lookup.
    ///
    /// The cache never serves the retained bytes.  This only exposes the
    /// bounded evidence needed for an independently authorized
    /// re-verification decision in the caller's own scope.
    pub fn quarantined_shareable_status(
        &self,
        grant: &TransferCacheGrant,
        context: CacheAccessContext,
        claimed_content_identity: Commitment,
    ) -> Result<Option<QuarantinedPieceStatus>, CacheRefusal> {
        grant.authorize(context)?;
        Ok(self.quarantine_status(
            CachePartition::Shareable(grant.scope),
            grant.key_domain,
            claimed_content_identity,
        ))
    }

    /// Stores a candidate under an exclusive secret-bearing lease.
    pub fn store_secret(
        &mut self,
        lease: &SecretCacheLease,
        peer: PeerIdentity,
        candidate: CachePieceCandidate,
        now: CacheEpoch,
    ) -> Result<CacheWriteReceipt, CacheRefusal> {
        lease.require_active(now)?;
        self.store(
            CachePartition::Secret(lease.scope),
            lease.key_domain,
            peer,
            candidate,
            now,
            lease.audit,
        )
    }

    /// Reads one verified secret-bearing payload only through its exact lease.
    pub fn read_secret(
        &self,
        lease: &SecretCacheLease,
        content_identity: Commitment,
        now: CacheEpoch,
    ) -> Result<CacheLookup, CacheRefusal> {
        lease.require_active(now)?;
        Ok(self.lookup(
            CachePartition::Secret(lease.scope),
            lease.key_domain,
            content_identity,
            lease.audit,
        ))
    }

    /// Returns metadata for a suspect secret-bearing piece through its exact
    /// exclusive lease, never through a reader grant.
    pub fn quarantined_secret_status(
        &self,
        lease: &SecretCacheLease,
        claimed_content_identity: Commitment,
        now: CacheEpoch,
    ) -> Result<Option<QuarantinedPieceStatus>, CacheRefusal> {
        lease.require_active(now)?;
        Ok(self.quarantine_status(
            CachePartition::Secret(lease.scope),
            lease.key_domain,
            claimed_content_identity,
        ))
    }

    /// Number of suspect payloads retained pending an independent re-verification decision.
    #[must_use]
    pub fn quarantined_count(&self) -> usize {
        self.quarantine.len()
    }

    /// Returns the replayable peer penalty at one logical epoch.
    pub fn peer_penalty_at(
        &self,
        peer: PeerIdentity,
        now: CacheEpoch,
    ) -> Result<u32, CacheRefusal> {
        Self::trust_result(self.trust.penalty_at(peer, now.get()))
    }

    fn store(
        &mut self,
        partition: CachePartition,
        key_domain: CacheKeyDomain,
        peer: PeerIdentity,
        candidate: CachePieceCandidate,
        now: CacheEpoch,
        audit: CacheAuditRequirement,
    ) -> Result<CacheWriteReceipt, CacheRefusal> {
        if !Self::trust_result(self.trust.is_eligible(peer, now.get()))? {
            return Err(CacheRefusal::PeerExcluded { peer });
        }
        if candidate.bytes.len() > self.limits.max_piece_bytes {
            return Err(CacheRefusal::CandidateTooLarge {
                offered: candidate.bytes.len(),
                maximum: self.limits.max_piece_bytes,
            });
        }

        let CachePieceCandidate {
            claimed_content_identity,
            bytes,
        } = candidate;
        // The candidate is already bounded above.  Keep its raw bytes only for
        // the quarantine path; the served path retains the independently
        // constructed `TransferPayload` instead.
        let payload = TransferPayload::new(bytes.clone())
            .map_err(|_| CacheRefusal::CandidateVerificationRefused)?;
        let key = CacheEntryKey::derive(partition, key_domain, claimed_content_identity);
        if payload.identity() != claimed_content_identity {
            let is_new = !self.quarantine.contains_key(&key);
            if is_new && self.quarantine.len() >= self.limits.max_quarantined_pieces {
                return Err(CacheRefusal::QuarantineFull {
                    maximum: self.limits.max_quarantined_pieces,
                });
            }
            let penalty = Self::trust_result(self.trust.record_bad_piece(peer, now.get()))?;
            self.quarantine.insert(
                key,
                QuarantinedCachePiece {
                    peer,
                    claimed_content_identity,
                    observed_content_identity: payload.identity(),
                    bytes,
                    quarantined_at: now,
                },
            );
            return Ok(CacheWriteReceipt::Quarantined { penalty, audit });
        }

        Self::trust_result(self.trust.record_verified_piece(peer, now.get()))?;
        let replacing = self.entries.contains_key(&key);
        let mut evicted = false;
        if !replacing {
            let capacity = self.limits.capacity_for(partition);
            let count = self
                .entries
                .values()
                .filter(|entry| entry.partition == partition)
                .count();
            if count >= capacity {
                let victim = self
                    .entries
                    .iter()
                    .filter(|(_, entry)| entry.partition == partition)
                    .map(|(entry_key, entry)| (entry.written_at, *entry_key))
                    .min()
                    .map(|(_, entry_key)| entry_key)
                    .expect("a full cache partition has an eviction victim");
                let _removed = self.entries.remove(&victim);
                evicted = true;
            }
        }
        self.entries.insert(
            key,
            CachedEntry {
                partition,
                written_at: now,
                payload,
            },
        );
        Ok(CacheWriteReceipt::Stored { evicted, audit })
    }

    fn lookup(
        &self,
        partition: CachePartition,
        key_domain: CacheKeyDomain,
        content_identity: Commitment,
        audit: CacheAuditRequirement,
    ) -> CacheLookup {
        let key = CacheEntryKey::derive(partition, key_domain, content_identity);
        match self.entries.get(&key) {
            Some(entry) => CacheLookup::Hit {
                payload: entry.payload.clone(),
                audit,
            },
            None => CacheLookup::Miss,
        }
    }

    fn quarantine_status(
        &self,
        partition: CachePartition,
        key_domain: CacheKeyDomain,
        claimed_content_identity: Commitment,
    ) -> Option<QuarantinedPieceStatus> {
        let key = CacheEntryKey::derive(partition, key_domain, claimed_content_identity);
        self.quarantine.get(&key).map(QuarantinedPieceStatus::from)
    }

    fn trust_result<T>(result: Result<T, crate::AtpRefusal>) -> Result<T, CacheRefusal> {
        result.map_err(|refusal| match refusal {
            crate::AtpRefusal::NonMonotonicRegimeEpoch { previous, observed } => {
                CacheRefusal::TrustEpochRegressed { previous, observed }
            }
            _ => CacheRefusal::CandidateVerificationRefused,
        })
    }
}
