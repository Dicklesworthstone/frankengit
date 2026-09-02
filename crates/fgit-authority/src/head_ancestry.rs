//! Bounded proof that the current authority head descends from an exact head.
//!
//! An authenticated historical receipt proves what one store returned at one
//! earlier read.  It does not prove that another authenticated head is later in
//! the same repository history, and generation comparison alone cannot rule out
//! a fork or a head read from another slot.  This module performs the missing
//! exact walk:
//!
//! ```text
//! current HeadKey read + store authentication
//!     -> current canonical head identity
//!     -> predecessor_head_id walk
//!     -> exact ancestor identity and generation
//! ```
//!
//! Every predecessor body is read by its content identity and re-identified by
//! the ordinary authority reader.  Repository identity must remain constant and
//! generation must decrease by exactly one at each edge.  The walk is bounded
//! before I/O by the generation distance and an explicit caller limit; it never
//! truncates a path into a positive result.

use core::fmt;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_types::{HeadGeneration, RepositoryAuthorityHeadId, RepositoryId};

use crate::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityStore,
    AuthorityVersionToken, HeadBodyRefusal, HeadKey, HeadRead, OutcomeFailure,
    authority_head_identity, read_authority_head_body, read_authority_head_body_async,
};

/// Hard ceiling for one predecessor walk.
pub const MAX_AUTHORITY_HEAD_ANCESTRY_HOPS: usize = 65_536;

const PATH_DOMAIN: &[u8] = b"frankengit.authority.head-ancestry-path/v1\0";
const RECEIPT_DOMAIN: &[u8] = b"frankengit.authority.head-ancestry-receipt/v1\0";

/// Stable identity of one exact current-head ancestry receipt.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthorityHeadAncestryReceiptId([u8; 32]);

impl AuthorityHeadAncestryReceiptId {
    /// Raw receipt commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for AuthorityHeadAncestryReceiptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("authority-head-ancestry:")?;
        write_hex(formatter, &self.0)
    }
}

/// Immutable proof summary for one exact ancestor-to-current-head walk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityHeadAncestryReceipt {
    receipt_id: AuthorityHeadAncestryReceiptId,
    repository_id: RepositoryId,
    ancestor_head_id: RepositoryAuthorityHeadId,
    ancestor_generation: HeadGeneration,
    descendant_head_id: RepositoryAuthorityHeadId,
    descendant_generation: HeadGeneration,
    descendant_version_token: AuthorityVersionToken,
    hops: u32,
    path_root: [u8; 32],
}

impl AuthorityHeadAncestryReceipt {
    /// Stable receipt identity.
    #[must_use]
    pub const fn receipt_id(self) -> AuthorityHeadAncestryReceiptId {
        self.receipt_id
    }

    /// Repository whose exact head chain was walked.
    #[must_use]
    pub const fn repository_id(self) -> RepositoryId {
        self.repository_id
    }

    /// Historical head required by the caller.
    #[must_use]
    pub const fn ancestor_head_id(self) -> RepositoryAuthorityHeadId {
        self.ancestor_head_id
    }

    /// Historical head generation required by the caller.
    #[must_use]
    pub const fn ancestor_generation(self) -> HeadGeneration {
        self.ancestor_generation
    }

    /// Current head observed in the requested slot.
    #[must_use]
    pub const fn descendant_head_id(self) -> RepositoryAuthorityHeadId {
        self.descendant_head_id
    }

    /// Current head generation observed in the requested slot.
    #[must_use]
    pub const fn descendant_generation(self) -> HeadGeneration {
        self.descendant_generation
    }

    /// Exact current slot version authenticated by the store.
    #[must_use]
    pub const fn descendant_version_token(self) -> AuthorityVersionToken {
        self.descendant_version_token
    }

    /// Number of predecessor edges between descendant and ancestor.
    #[must_use]
    pub const fn hops(self) -> u32 {
        self.hops
    }

    /// Commitment to the complete descendant-first identity path.
    #[must_use]
    pub const fn path_root(self) -> [u8; 32] {
        self.path_root
    }
}

/// Current authenticated head plus the exact proof that it descends from the
/// caller's historical basis.
#[derive(Clone, Debug)]
pub struct CurrentAuthorityHead {
    authenticated: AuthenticatedHead,
    head_id: RepositoryAuthorityHeadId,
    body: fgit_codec::RepositoryAuthorityHeadBody,
    ancestry: AuthorityHeadAncestryReceipt,
}

impl CurrentAuthorityHead {
    /// Store-authenticated current head read.
    #[must_use]
    pub const fn authenticated(&self) -> &AuthenticatedHead {
        &self.authenticated
    }

    /// Canonical identity re-derived from the authenticated body.
    #[must_use]
    pub const fn head_id(&self) -> RepositoryAuthorityHeadId {
        self.head_id
    }

    /// Exact current head body.
    #[must_use]
    pub const fn body(&self) -> &fgit_codec::RepositoryAuthorityHeadBody {
        &self.body
    }

    /// Exact ancestor-to-current proof summary.
    #[must_use]
    pub const fn ancestry(&self) -> AuthorityHeadAncestryReceipt {
        self.ancestry
    }
}

/// Why the current head could not be proved a descendant of the requested
/// historical basis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityHeadAncestryRefusal {
    /// Caller requested an unbounded or excessive walk.
    InvalidHopLimit {
        /// Limit supplied.
        observed: usize,
        /// System hard ceiling.
        hard_limit: usize,
    },
    /// The requested head slot does not exist.
    HeadAbsent,
    /// Store read or receipt authentication failed.
    Authority(AuthorityFailure),
    /// Current authenticated bytes were malformed or generation-skewed.
    HeadBody(HeadBodyRefusal),
    /// A predecessor body was absent, malformed, or misfiled.
    History(Box<OutcomeFailure>),
    /// Current body canonicalization failed.
    Identity(Box<OutcomeFailure>),
    /// Receipt/path canonical framing failed.
    Codec(CodecRefusal),
    /// The current slot contains another repository.
    RepositoryMismatch {
        /// Repository expected by the caller.
        expected: RepositoryId,
        /// Repository in the current or predecessor body.
        observed: RepositoryId,
    },
    /// Current generation is older than the requested ancestor generation.
    DescendantOlderThanAncestor {
        /// Requested historical generation.
        ancestor: HeadGeneration,
        /// Current observed generation.
        descendant: HeadGeneration,
    },
    /// Generation distance exceeds the explicit walk limit.
    HopLimitExceeded {
        /// Hops required by generation distance.
        required: u64,
        /// Hops admitted by the caller.
        limit: usize,
    },
    /// A non-genesis head omitted its predecessor identity.
    MissingPredecessor {
        /// Body whose predecessor was required.
        head_id: Box<RepositoryAuthorityHeadId>,
        /// Generation carried by that body.
        generation: HeadGeneration,
    },
    /// One predecessor edge skipped, repeated, or increased generation.
    GenerationDiscontinuity {
        /// Newer generation naming the predecessor.
        descendant: HeadGeneration,
        /// Generation carried by the predecessor body.
        predecessor: HeadGeneration,
    },
    /// The exact identity at the requested generation is not the requested
    /// ancestor.
    NotDescendant {
        /// Requested ancestor identity.
        expected: Box<RepositoryAuthorityHeadId>,
        /// Identity reached at the requested generation.
        observed: Box<RepositoryAuthorityHeadId>,
    },
    /// Hop count did not fit the stable receipt profile.
    HopCountUnrepresentable {
        /// Hops observed.
        observed: usize,
    },
}

impl fmt::Display for AuthorityHeadAncestryRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHopLimit {
                observed,
                hard_limit,
            } => write!(
                formatter,
                "authority-head ancestry limit {observed} exceeds hard limit {hard_limit}"
            ),
            Self::HeadAbsent => formatter.write_str("the requested authority head slot is absent"),
            Self::Authority(refusal) => write!(formatter, "authority-head read failed: {refusal}"),
            Self::HeadBody(refusal) => write!(formatter, "current head body refused: {refusal}"),
            Self::History(refusal) => write!(formatter, "head ancestry history refused: {refusal}"),
            Self::Identity(refusal) => {
                write!(formatter, "current head identity refused: {refusal}")
            }
            Self::Codec(refusal) => write!(formatter, "head ancestry framing refused: {refusal}"),
            Self::RepositoryMismatch { expected, observed } => write!(
                formatter,
                "authority-head path moved from repository {expected} to {observed}"
            ),
            Self::DescendantOlderThanAncestor {
                ancestor,
                descendant,
            } => write!(
                formatter,
                "current head generation {} is older than requested ancestor generation {}",
                descendant.get(),
                ancestor.get()
            ),
            Self::HopLimitExceeded { required, limit } => write!(
                formatter,
                "authority-head ancestry requires {required} hops, limit {limit}"
            ),
            Self::MissingPredecessor {
                head_id,
                generation,
            } => write!(
                formatter,
                "head {head_id} at generation {} has no required predecessor",
                generation.get()
            ),
            Self::GenerationDiscontinuity {
                descendant,
                predecessor,
            } => write!(
                formatter,
                "head generation {} names predecessor generation {}; expected exactly one less",
                descendant.get(),
                predecessor.get()
            ),
            Self::NotDescendant { expected, observed } => write!(
                formatter,
                "authority-head path reached {observed} instead of ancestor {expected}"
            ),
            Self::HopCountUnrepresentable { observed } => write!(
                formatter,
                "authority-head ancestry hop count {observed} is not representable"
            ),
        }
    }
}

impl core::error::Error for AuthorityHeadAncestryRefusal {}

impl From<AuthorityFailure> for AuthorityHeadAncestryRefusal {
    fn from(value: AuthorityFailure) -> Self {
        Self::Authority(value)
    }
}

impl From<HeadBodyRefusal> for AuthorityHeadAncestryRefusal {
    fn from(value: HeadBodyRefusal) -> Self {
        Self::HeadBody(value)
    }
}

impl From<CodecRefusal> for AuthorityHeadAncestryRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

/// Reads the current head slot and proves it descends from the exact historical
/// head supplied by the caller.
pub fn read_current_authority_head_descendant<S>(
    store: &S,
    head_key: &HeadKey,
    repository_id: RepositoryId,
    ancestor_head_id: RepositoryAuthorityHeadId,
    ancestor_generation: HeadGeneration,
    max_hops: usize,
) -> Result<CurrentAuthorityHead, AuthorityHeadAncestryRefusal>
where
    S: AuthorityStore + ?Sized,
{
    validate_hop_limit(max_hops)?;
    let HeadRead::Present(receipt) = store.read_head(head_key)? else {
        return Err(AuthorityHeadAncestryRefusal::HeadAbsent);
    };
    let authenticated = store.authenticate_head_receipt(&receipt)?;
    let body = authenticated.body()?;
    let head_id = authority_head_identity(&body)
        .map_err(|failure| AuthorityHeadAncestryRefusal::Identity(Box::new(failure)))?;
    let query = AncestryQuery {
        repository_id,
        ancestor_head_id,
        ancestor_generation,
    };
    let endpoint = DescendantEndpoint {
        head_id,
        body: &body,
        version_token: receipt.token(),
    };
    let ancestry = walk_sync(store, &query, &endpoint, max_hops)?;
    Ok(CurrentAuthorityHead {
        authenticated,
        head_id,
        body,
        ancestry,
    })
}

/// Production asynchronous twin of
/// [`read_current_authority_head_descendant`].
pub async fn read_current_authority_head_descendant_async<S>(
    store: &S,
    cx: &S::Context,
    head_key: &HeadKey,
    repository_id: RepositoryId,
    ancestor_head_id: RepositoryAuthorityHeadId,
    ancestor_generation: HeadGeneration,
    max_hops: usize,
) -> Result<CurrentAuthorityHead, AuthorityHeadAncestryRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
{
    validate_hop_limit(max_hops)?;
    let HeadRead::Present(receipt) = store.read_head(cx, head_key).await? else {
        return Err(AuthorityHeadAncestryRefusal::HeadAbsent);
    };
    let authenticated = store.authenticate_head_receipt(cx, &receipt).await?;
    let body = authenticated.body()?;
    let head_id = authority_head_identity(&body)
        .map_err(|failure| AuthorityHeadAncestryRefusal::Identity(Box::new(failure)))?;
    let query = AncestryQuery {
        repository_id,
        ancestor_head_id,
        ancestor_generation,
    };
    let endpoint = DescendantEndpoint {
        head_id,
        body: &body,
        version_token: receipt.token(),
    };
    let ancestry = walk_async(store, cx, &query, &endpoint, max_hops).await?;
    Ok(CurrentAuthorityHead {
        authenticated,
        head_id,
        body,
        ancestry,
    })
}

/// The exact ancestry question one walk answers: does the current head of
/// `repository_id` descend from this ancestor identity at this generation?
#[derive(Clone, Copy)]
struct AncestryQuery {
    repository_id: RepositoryId,
    ancestor_head_id: RepositoryAuthorityHeadId,
    ancestor_generation: HeadGeneration,
}

/// The authenticated current-slot endpoint one walk starts from.
struct DescendantEndpoint<'a> {
    head_id: RepositoryAuthorityHeadId,
    body: &'a fgit_codec::RepositoryAuthorityHeadBody,
    version_token: AuthorityVersionToken,
}

const fn validate_hop_limit(max_hops: usize) -> Result<(), AuthorityHeadAncestryRefusal> {
    if max_hops > MAX_AUTHORITY_HEAD_ANCESTRY_HOPS {
        return Err(AuthorityHeadAncestryRefusal::InvalidHopLimit {
            observed: max_hops,
            hard_limit: MAX_AUTHORITY_HEAD_ANCESTRY_HOPS,
        });
    }
    Ok(())
}

fn walk_sync<S>(
    store: &S,
    query: &AncestryQuery,
    endpoint: &DescendantEndpoint<'_>,
    max_hops: usize,
) -> Result<AuthorityHeadAncestryReceipt, AuthorityHeadAncestryRefusal>
where
    S: AuthorityStore + ?Sized,
{
    validate_start(
        query.repository_id,
        query.ancestor_generation,
        endpoint.body,
        max_hops,
    )?;
    let required = endpoint.body.generation.get() - query.ancestor_generation.get();
    let mut path = Vec::with_capacity(usize::try_from(required).unwrap_or(max_hops) + 1);
    path.push(endpoint.head_id);
    let mut cursor_id = endpoint.head_id;
    let mut cursor = endpoint.body.clone();
    for _ in 0..required {
        let predecessor_id =
            cursor
                .predecessor_head_id
                .ok_or(AuthorityHeadAncestryRefusal::MissingPredecessor {
                    head_id: Box::new(cursor_id),
                    generation: cursor.generation,
                })?;
        let predecessor = read_authority_head_body(store, predecessor_id)
            .map_err(|failure| AuthorityHeadAncestryRefusal::History(Box::new(failure)))?;
        validate_edge(query.repository_id, &cursor, &predecessor)?;
        path.push(predecessor_id);
        cursor_id = predecessor_id;
        cursor = predecessor;
    }
    finish_receipt(
        query,
        endpoint.body.generation,
        endpoint.version_token,
        cursor_id,
        &path,
    )
}

async fn walk_async<S>(
    store: &S,
    cx: &S::Context,
    query: &AncestryQuery,
    endpoint: &DescendantEndpoint<'_>,
    max_hops: usize,
) -> Result<AuthorityHeadAncestryReceipt, AuthorityHeadAncestryRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
{
    validate_start(
        query.repository_id,
        query.ancestor_generation,
        endpoint.body,
        max_hops,
    )?;
    let required = endpoint.body.generation.get() - query.ancestor_generation.get();
    let mut path = Vec::with_capacity(usize::try_from(required).unwrap_or(max_hops) + 1);
    path.push(endpoint.head_id);
    let mut cursor_id = endpoint.head_id;
    let mut cursor = endpoint.body.clone();
    for _ in 0..required {
        let predecessor_id =
            cursor
                .predecessor_head_id
                .ok_or(AuthorityHeadAncestryRefusal::MissingPredecessor {
                    head_id: Box::new(cursor_id),
                    generation: cursor.generation,
                })?;
        let predecessor = read_authority_head_body_async(store, cx, predecessor_id)
            .await
            .map_err(|failure| AuthorityHeadAncestryRefusal::History(Box::new(failure)))?;
        validate_edge(query.repository_id, &cursor, &predecessor)?;
        path.push(predecessor_id);
        cursor_id = predecessor_id;
        cursor = predecessor;
    }
    finish_receipt(
        query,
        endpoint.body.generation,
        endpoint.version_token,
        cursor_id,
        &path,
    )
}

fn validate_start(
    repository_id: RepositoryId,
    ancestor_generation: HeadGeneration,
    descendant: &fgit_codec::RepositoryAuthorityHeadBody,
    max_hops: usize,
) -> Result<(), AuthorityHeadAncestryRefusal> {
    if descendant.repository_id != repository_id {
        return Err(AuthorityHeadAncestryRefusal::RepositoryMismatch {
            expected: repository_id,
            observed: descendant.repository_id,
        });
    }
    if descendant.generation < ancestor_generation {
        return Err(AuthorityHeadAncestryRefusal::DescendantOlderThanAncestor {
            ancestor: ancestor_generation,
            descendant: descendant.generation,
        });
    }
    let required = descendant.generation.get() - ancestor_generation.get();
    if required > u64::try_from(max_hops).unwrap_or(u64::MAX) {
        return Err(AuthorityHeadAncestryRefusal::HopLimitExceeded {
            required,
            limit: max_hops,
        });
    }
    Ok(())
}

fn validate_edge(
    repository_id: RepositoryId,
    descendant: &fgit_codec::RepositoryAuthorityHeadBody,
    predecessor: &fgit_codec::RepositoryAuthorityHeadBody,
) -> Result<(), AuthorityHeadAncestryRefusal> {
    if predecessor.repository_id != repository_id {
        return Err(AuthorityHeadAncestryRefusal::RepositoryMismatch {
            expected: repository_id,
            observed: predecessor.repository_id,
        });
    }
    if predecessor.generation.get().checked_add(1) != Some(descendant.generation.get()) {
        return Err(AuthorityHeadAncestryRefusal::GenerationDiscontinuity {
            descendant: descendant.generation,
            predecessor: predecessor.generation,
        });
    }
    Ok(())
}

fn finish_receipt(
    query: &AncestryQuery,
    descendant_generation: HeadGeneration,
    descendant_version_token: AuthorityVersionToken,
    reached_ancestor_id: RepositoryAuthorityHeadId,
    path: &[RepositoryAuthorityHeadId],
) -> Result<AuthorityHeadAncestryReceipt, AuthorityHeadAncestryRefusal> {
    if reached_ancestor_id != query.ancestor_head_id {
        return Err(AuthorityHeadAncestryRefusal::NotDescendant {
            expected: Box::new(query.ancestor_head_id),
            observed: Box::new(reached_ancestor_id),
        });
    }
    let hop_count = path.len().saturating_sub(1);
    let hops = u32::try_from(hop_count).map_err(|_| {
        AuthorityHeadAncestryRefusal::HopCountUnrepresentable {
            observed: hop_count,
        }
    })?;
    let path_root = path_commitment(query.repository_id, path)?;
    let descendant_head_id = *path.first().unwrap_or(&reached_ancestor_id);
    let mut receipt = AuthorityHeadAncestryReceipt {
        receipt_id: AuthorityHeadAncestryReceiptId([0; 32]),
        repository_id: query.repository_id,
        ancestor_head_id: query.ancestor_head_id,
        ancestor_generation: query.ancestor_generation,
        descendant_head_id,
        descendant_generation,
        descendant_version_token,
        hops,
        path_root,
    };
    receipt.receipt_id = AuthorityHeadAncestryReceiptId(receipt_commitment(&receipt)?);
    Ok(receipt)
}

fn path_commitment(
    repository_id: RepositoryId,
    path: &[RepositoryAuthorityHeadId],
) -> Result<[u8; 32], CodecRefusal> {
    let mut encoder = Encoder::with_capacity(96 + path.len() * 96);
    encoder.write_bytes("authority_head_ancestry_path_domain", PATH_DOMAIN)?;
    encoder.write_opaque_id(repository_id.as_bytes());
    let count = u32::try_from(path.len()).map_err(|_| CodecRefusal::ValueUnrepresentable {
        field: "authority_head_ancestry.path",
        observed: u64::try_from(path.len()).unwrap_or(u64::MAX),
        limit: u64::from(u32::MAX),
    })?;
    encoder.write_scalar(count);
    for head_id in path {
        encoder.write_internal_object_id(head_id.as_internal_object_id())?;
    }
    Ok(hash(&encoder.into_bytes()))
}

fn receipt_commitment(receipt: &AuthorityHeadAncestryReceipt) -> Result<[u8; 32], CodecRefusal> {
    let mut encoder = Encoder::with_capacity(384);
    encoder.write_bytes("authority_head_ancestry_receipt_domain", RECEIPT_DOMAIN)?;
    encoder.write_opaque_id(receipt.repository_id.as_bytes());
    encoder.write_internal_object_id(receipt.ancestor_head_id.as_internal_object_id())?;
    encoder.write_scalar(receipt.ancestor_generation.get());
    encoder.write_internal_object_id(receipt.descendant_head_id.as_internal_object_id())?;
    encoder.write_scalar(receipt.descendant_generation.get());
    encoder.write_raw(&receipt.descendant_version_token.to_opaque_bytes());
    encoder.write_scalar(receipt.hops);
    encoder.write_raw(&receipt.path_root);
    Ok(hash(&encoder.into_bytes()))
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(bytes);
    hasher.finish()
}

fn write_hex(formatter: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

const _: () = {
    assert!(size_of::<AuthorityHeadAncestryRefusal>() <= crate::request::MAX_ERROR_BYTES);
};
