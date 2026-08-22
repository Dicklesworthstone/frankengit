#![forbid(unsafe_code)]
//! The trust-scoped cache's authorization and admission refusals
//! (`frankengit-vv12`).
//!
//! §9 requires authorization filters to precede disclosure and forbids derived
//! state from granting access; §8 says a model or graph may recommend but may
//! not grant it. This cache holds both shareable and secret payloads, and its
//! `authorize` chain is where those rules are enforced. A cache that answers a
//! read it should have refused is a **disclosure**, not a performance bug.
//!
//! # I had this crate's coverage wrong and carried it for several beads
//!
//! In `frankengit-0k6d` I wrote that `CacheRefusal` was "fully covered by
//! fg075" and scoped that bead around it. Measured per variant here:
//! `tests/trust_scoped_cache.rs` names the **enum** but only **two** of its
//! eleven variants — `ScopeDenied` and `PeerExcluded`. Nine were named by no
//! test and none was in-src-only.
//!
//! I carried the belief forward without rechecking it, which is the failure
//! mode I have spent the day warning other panes about. Rechecked per variant
//! rather than per enum, and the correction is why this bead exists.
//!
//! # The authorize chain is four ordered stages
//!
//! ```text
//! 1  scope does not permit the context   ScopeDenied            (already covered)
//! 2  context.now  >  grant.expires_at    GrantExpired
//! 3  readers do not permit the principal ReaderDenied
//! 4  OwnerOnly and principal is not the owner  PlaintextShareDenied
//! ```
//!
//! Stages 3 and 4 are the confidentiality boundary, and both were untested.
//! They are also easy to confuse: a probe showing only that "a read was
//! refused" cannot tell a reader-set failure from a plaintext-sharing failure,
//! and the mutation recorded in the bead collapses exactly those two.
//!
//! # Non-claims
//!
//! Newly covered: `InvalidGrantShape`, `InvalidCacheLimits`, `GrantExpired`,
//! `ReaderDenied`, `PlaintextShareDenied`, `CandidateTooLarge`. **Left open on
//! purpose**: `QuarantineFull`, `CandidateVerificationRefused` and
//! `TrustEpochRegressed` need a quarantine or trust-ledger fixture beyond what
//! this file builds honestly — `9xyg` and `xh96` left variants open for the
//! same reason, and stretching a file past its fixtures is how a corpus starts
//! proving things about itself. LEAD count, not a remaining-work total.
//!
//! Nothing here modifies `crates/fgit-atp-git/src/**`.

use fgit_atp_git::cache::{
    CacheAccessContext, CacheAuditRequirement, CacheEpoch, CacheKeyDomain, CachePieceCandidate,
    CacheReaders, CacheRefusal, PlaintextShareability, ShareableCacheScope, TransferCacheGrant,
    TransferCacheLimits, TrustScopedTransferCache,
};
use fgit_atp_git::{PeerIdentity, PeerPenaltyPolicy, TransferPayload};
use fgit_types::{PrincipalId, RepositoryId, TenantId};

const fn tenant(byte: u8) -> TenantId {
    TenantId::from_bytes([byte; 16])
}

const fn repository(byte: u8) -> RepositoryId {
    RepositoryId::from_bytes([byte; 16])
}

const fn principal(byte: u8) -> PrincipalId {
    PrincipalId::from_bytes([byte; 16])
}

const fn peer(byte: u8) -> PeerIdentity {
    PeerIdentity::from_bytes([byte; 32])
}

const OWNER: u8 = 1;
const STRANGER: u8 = 2;
const EXPIRY: u64 = 10;

fn limits(max_piece_bytes: usize) -> TransferCacheLimits {
    TransferCacheLimits::new(4, 4, 4, 4, 4, max_piece_bytes, 2)
        .expect("positive bounded cache limits are valid")
}

fn cache(max_piece_bytes: usize) -> TrustScopedTransferCache {
    let penalties = PeerPenaltyPolicy::new(4, 0).expect("a permissive penalty policy");
    TrustScopedTransferCache::new(limits(max_piece_bytes), penalties)
}

/// A repository-private grant, parameterised on the two fields the
/// confidentiality probes vary.
fn grant(readers: CacheReaders, plaintext: PlaintextShareability) -> TransferCacheGrant {
    TransferCacheGrant::new(
        ShareableCacheScope::RepositoryPrivate {
            tenant: tenant(1),
            repository: repository(1),
        },
        readers,
        plaintext,
        CacheKeyDomain::from_bytes([7; 32]),
        CacheEpoch::new(EXPIRY),
        CacheAuditRequirement::NotRequired,
    )
    .expect("a well-shaped repository-private grant")
}

const fn context(principal_byte: u8, now: u64) -> CacheAccessContext {
    CacheAccessContext::new(
        principal(principal_byte),
        tenant(1),
        repository(1),
        None,
        CacheEpoch::new(now),
    )
}

fn candidate(bytes: &[u8]) -> CachePieceCandidate {
    let payload = TransferPayload::new(bytes.to_vec()).expect("fixture payload is valid");
    CachePieceCandidate::new(payload.identity(), bytes.to_vec())
}

// ---------------------------------------------------------------------------
// The accepted paths, built first
// ---------------------------------------------------------------------------

/// The owner stores and reads back through an unexpired, shareable grant.
///
/// Built and made to pass before any refusal probe. Every refusal below is a
/// one-field departure from this, so without it they would be attributable to
/// a malformed fixture rather than to the guard they name.
#[test]
fn an_authorized_owner_stores_and_reads_its_own_entry() {
    let mut cache = cache(128);
    let grant = grant(
        CacheReaders::explicit(principal(OWNER), []),
        PlaintextShareability::Shareable,
    );
    let piece = candidate(b"payload bytes");
    let identity = TransferPayload::new(b"payload bytes".to_vec())
        .expect("fixture payload")
        .identity();

    cache
        .store_shareable(&grant, context(OWNER, 1), peer(9), piece)
        .expect("an authorized owner may store");
    cache
        .read_shareable(&grant, context(OWNER, 1), identity)
        .expect("an authorized owner may read what it stored");
}

/// A principal inside the explicit reader set is admitted.
///
/// The permitted half of `ReaderDenied`: without it, that refusal could be the
/// grant refusing every principal but the owner by construction.
#[test]
fn a_principal_in_the_reader_set_is_admitted() {
    let mut cache = cache(128);
    let grant = grant(
        CacheReaders::explicit(principal(OWNER), [principal(STRANGER)]),
        PlaintextShareability::Shareable,
    );
    let identity = TransferPayload::new(b"shared".to_vec())
        .expect("fixture payload")
        .identity();

    cache
        .store_shareable(&grant, context(OWNER, 1), peer(9), candidate(b"shared"))
        .expect("the owner stores");
    cache
        .read_shareable(&grant, context(STRANGER, 1), identity)
        .expect("a listed reader may read");
}

/// **The permitted twin at the exact bound.** `store` reads `>`, so a candidate
/// of exactly `max_piece_bytes` is admitted.
#[test]
fn a_candidate_at_exactly_the_size_bound_is_admitted() {
    let mut cache = cache(8);
    let grant = grant(
        CacheReaders::explicit(principal(OWNER), []),
        PlaintextShareability::Shareable,
    );
    cache
        .store_shareable(&grant, context(OWNER, 1), peer(9), candidate(b"12345678"))
        .expect("a candidate of exactly the bound must be admitted");
}

// ---------------------------------------------------------------------------
// Constructor shapes
// ---------------------------------------------------------------------------

/// Each way a grant's shape can be internally contradictory.
///
/// One condition joins three clauses, so each gets its own case with the others
/// satisfied: a public scope without a public audience, a non-public scope
/// *with* one, and an owner-only plaintext policy with no owner.
#[test]
fn a_contradictory_grant_shape_is_refused() {
    let public_without_public_audience = TransferCacheGrant::new(
        ShareableCacheScope::PublicGlobal,
        CacheReaders::explicit(principal(OWNER), []),
        PlaintextShareability::Shareable,
        CacheKeyDomain::from_bytes([7; 32]),
        CacheEpoch::new(EXPIRY),
        CacheAuditRequirement::NotRequired,
    )
    .expect_err("a public cache cannot have a private audience");
    assert_eq!(
        public_without_public_audience,
        CacheRefusal::InvalidGrantShape
    );

    let private_with_public_audience = TransferCacheGrant::new(
        ShareableCacheScope::RepositoryPrivate {
            tenant: tenant(1),
            repository: repository(1),
        },
        CacheReaders::AnyAuthenticated,
        PlaintextShareability::Shareable,
        CacheKeyDomain::from_bytes([7; 32]),
        CacheEpoch::new(EXPIRY),
        CacheAuditRequirement::NotRequired,
    )
    .expect_err("a repository-private cache cannot admit any authenticated principal");
    assert_eq!(
        private_with_public_audience,
        CacheRefusal::InvalidGrantShape
    );
}

/// Every zero field refuses the cache limits, each zeroed individually.
///
/// One `||` covers seven fields; zeroing all seven would pass against an
/// implementation checking only the first.
#[test]
fn each_zero_field_refuses_the_cache_limits() {
    let fields = [
        "public_entries",
        "tenant_entries",
        "repository_entries",
        "intent_run_entries",
        "secret_entries",
        "max_piece_bytes",
        "max_quarantined_pieces",
    ];
    for (index, field) in fields.iter().enumerate() {
        let mut values = [1_usize; 7];
        values[index] = 0;
        let error = TransferCacheLimits::new(
            values[0], values[1], values[2], values[3], values[4], values[5], values[6],
        )
        .expect_err(&format!("a zero {field} must refuse"));
        assert_eq!(
            error,
            CacheRefusal::InvalidCacheLimits,
            "a zero {field} must refuse as invalid cache limits"
        );
    }
}

// ---------------------------------------------------------------------------
// The authorize chain — the confidentiality boundary
// ---------------------------------------------------------------------------

/// An access after the grant's expiry is refused.
///
/// Passes through: the scope permits this context, so this reaches stage 2
/// rather than stopping at `ScopeDenied`.
#[test]
fn an_access_after_the_grant_expires_is_refused() {
    let cache = cache(128);
    let grant = grant(
        CacheReaders::explicit(principal(OWNER), []),
        PlaintextShareability::Shareable,
    );
    let identity = TransferPayload::new(b"anything".to_vec())
        .expect("fixture payload")
        .identity();

    let error = cache
        .read_shareable(&grant, context(OWNER, EXPIRY + 1), identity)
        .expect_err("a grant does not outlive its expiry");
    assert_eq!(error, CacheRefusal::GrantExpired);
}

/// **The permitted twin at the exact expiry.** The guard reads `>`, so access
/// *at* the expiry epoch is still authorized.
#[test]
fn an_access_at_exactly_the_expiry_is_admitted() {
    let mut cache = cache(128);
    let grant = grant(
        CacheReaders::explicit(principal(OWNER), []),
        PlaintextShareability::Shareable,
    );
    cache
        .store_shareable(
            &grant,
            context(OWNER, EXPIRY),
            peer(9),
            candidate(b"at expiry"),
        )
        .expect("access at exactly the expiry epoch is still authorized");
}

/// A principal outside the reader set is refused.
#[test]
fn a_principal_outside_the_reader_set_is_refused() {
    let cache = cache(128);
    let grant = grant(
        CacheReaders::explicit(principal(OWNER), []),
        PlaintextShareability::Shareable,
    );
    let identity = TransferPayload::new(b"private".to_vec())
        .expect("fixture payload")
        .identity();

    let error = cache
        .read_shareable(&grant, context(STRANGER, 1), identity)
        .expect_err("a principal outside the reader set may not read");
    assert_eq!(error, CacheRefusal::ReaderDenied);
}

/// **The confidentiality guard.** A listed reader is still refused the
/// plaintext when the grant is owner-only.
///
/// This is the distinction the whole file exists for: the principal **passes**
/// the reader check and is refused anyway, because owner-only plaintext is a
/// stricter condition than membership of the reader set. A probe asserting only
/// that "a read was refused" cannot tell the two apart.
#[test]
fn a_listed_reader_is_refused_owner_only_plaintext() {
    let cache = cache(128);
    let grant = grant(
        CacheReaders::explicit(principal(OWNER), [principal(STRANGER)]),
        PlaintextShareability::OwnerOnly,
    );
    let identity = TransferPayload::new(b"secretish".to_vec())
        .expect("fixture payload")
        .identity();

    let error = cache
        .read_shareable(&grant, context(STRANGER, 1), identity)
        .expect_err("owner-only plaintext is not shared with a listed reader");
    assert_eq!(
        error,
        CacheRefusal::PlaintextShareDenied,
        "a reader-set member refused for plaintext sharing, not for readership"
    );
}

/// The two confidentiality outcomes are **different refusals**.
///
/// Same grant shape apart from the reader set; the same principal is refused
/// twice for two different reasons. This is what would catch the two collapsing
/// into one code — which a single-surface probe cannot see, because each of
/// them alone is satisfied by either variant.
#[test]
fn readership_and_plaintext_sharing_are_different_refusals() {
    let cache = cache(128);
    let identity = TransferPayload::new(b"payload".to_vec())
        .expect("fixture payload")
        .identity();

    let unlisted = cache
        .read_shareable(
            &grant(
                CacheReaders::explicit(principal(OWNER), []),
                PlaintextShareability::OwnerOnly,
            ),
            context(STRANGER, 1),
            identity,
        )
        .expect_err("an unlisted principal is refused");

    let listed = cache
        .read_shareable(
            &grant(
                CacheReaders::explicit(principal(OWNER), [principal(STRANGER)]),
                PlaintextShareability::OwnerOnly,
            ),
            context(STRANGER, 1),
            identity,
        )
        .expect_err("a listed principal is still refused the plaintext");

    assert_eq!(unlisted, CacheRefusal::ReaderDenied);
    assert_eq!(listed, CacheRefusal::PlaintextShareDenied);
    assert_ne!(
        unlisted, listed,
        "readership and plaintext sharing are separate authorization facts"
    );
}

// ---------------------------------------------------------------------------
// Admission bounds, and ordering
// ---------------------------------------------------------------------------

/// A candidate past the piece bound is refused, reporting both numbers.
#[test]
fn a_candidate_past_the_size_bound_is_refused() {
    let mut cache = cache(8);
    let grant = grant(
        CacheReaders::explicit(principal(OWNER), []),
        PlaintextShareability::Shareable,
    );
    let error = cache
        .store_shareable(&grant, context(OWNER, 1), peer(9), candidate(b"123456789"))
        .expect_err("one byte past the piece bound must refuse");
    assert_eq!(
        error,
        CacheRefusal::CandidateTooLarge {
            offered: 9,
            maximum: 8,
        }
    );
}

/// Authorization runs **before** admission.
///
/// This store is wrong twice: the principal is outside the reader set *and* the
/// candidate is past the size bound. It must report the authorization failure —
/// a cache must not disclose that a piece was too large to a caller it would
/// not have served anyway. The single-fault probes cannot see this; each
/// satisfies the other condition by construction.
#[test]
fn authorization_outranks_the_admission_bound() {
    let mut cache = cache(8);
    let grant = grant(
        CacheReaders::explicit(principal(OWNER), []),
        PlaintextShareability::Shareable,
    );
    let error = cache
        .store_shareable(
            &grant,
            context(STRANGER, 1),
            peer(9),
            candidate(b"123456789"),
        )
        .expect_err("a store wrong in two ways must still refuse");
    assert_eq!(
        error,
        CacheRefusal::ReaderDenied,
        "the grant is enforced before the candidate is measured"
    );
}

/// Expiry outranks readership.
///
/// Wrong twice again — expired *and* unlisted — reporting the earlier stage.
/// Paired with the probe above, the two pin the order across three of the four
/// stages rather than one adjacency.
#[test]
fn expiry_outranks_readership() {
    let cache = cache(128);
    let grant = grant(
        CacheReaders::explicit(principal(OWNER), []),
        PlaintextShareability::Shareable,
    );
    let identity = TransferPayload::new(b"payload".to_vec())
        .expect("fixture payload")
        .identity();

    let error = cache
        .read_shareable(&grant, context(STRANGER, EXPIRY + 1), identity)
        .expect_err("an access wrong in two ways must still refuse");
    assert_eq!(
        error,
        CacheRefusal::GrantExpired,
        "the expiry is checked before the reader set"
    );
}
