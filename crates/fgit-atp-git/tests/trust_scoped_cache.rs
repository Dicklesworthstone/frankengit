//! FG-075 trust-scoped ATP cache acceptance tests.
//!
//! These tests exercise the cache through its public grant/lease API.  They do
//! not inspect its opaque cache keys: a caller learns only the outcome in its
//! own authorized scope, which is the property that prevents a cache-presence
//! probe from crossing tenant, repository, Intent-Run, or key-domain bounds.

use fgit_atp_git::cache::{
    CacheAccessContext, CacheAuditRequirement, CacheEpoch, CacheKeyDomain, CacheLookup,
    CachePieceCandidate, CacheReaders, CacheRefusal, CacheWriteReceipt, IntentRunCacheScope,
    PlaintextShareability, SecretCacheLease, SecretCacheScope, ShareableCacheScope,
    TransferCacheGrant, TransferCacheLimits, TrustScopedTransferCache,
};
use fgit_atp_git::{PeerIdentity, PeerPenaltyPolicy, TransferPayload};
use fgit_resource::{CacheScope, OpaqueHandle};
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

fn intent_run(byte: u8) -> IntentRunCacheScope {
    let handle = OpaqueHandle::new(&[byte; 16]).expect("a short opaque run handle is valid");
    IntentRunCacheScope::from_authorized_scope(CacheScope::new(handle))
}

fn cache() -> TrustScopedTransferCache {
    let limits = TransferCacheLimits::new(1, 1, 1, 1, 1, 128, 2)
        .expect("positive bounded cache limits are valid");
    let penalties = PeerPenaltyPolicy::new(1, 0).expect("one bad piece excludes a peer");
    TrustScopedTransferCache::new(limits, penalties)
}

fn candidate(bytes: &[u8]) -> CachePieceCandidate {
    let payload = TransferPayload::new(bytes.to_vec()).expect("fixture payload is valid");
    CachePieceCandidate::new(payload.identity(), bytes.to_vec())
}

fn identity(bytes: &[u8]) -> [u8; 32] {
    TransferPayload::new(bytes.to_vec())
        .expect("fixture payload is valid")
        .identity()
}

fn repository_grant(
    tenant_id: TenantId,
    repository_id: RepositoryId,
    owner: PrincipalId,
    key_domain: CacheKeyDomain,
) -> TransferCacheGrant {
    TransferCacheGrant::new(
        ShareableCacheScope::RepositoryPrivate {
            tenant: tenant_id,
            repository: repository_id,
        },
        CacheReaders::explicit(owner, []),
        PlaintextShareability::Shareable,
        key_domain,
        CacheEpoch::new(9),
        CacheAuditRequirement::Required,
    )
    .expect("a repository-private grant has an explicit owner")
}

fn context(
    principal_id: PrincipalId,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    run: Option<IntentRunCacheScope>,
    now: u64,
) -> CacheAccessContext {
    CacheAccessContext::new(
        principal_id,
        tenant_id,
        repository_id,
        run,
        CacheEpoch::new(now),
    )
}

#[test]
fn repository_private_grants_refuse_cross_tenant_reads_and_hide_other_domains() {
    let mut cache = cache();
    let tenant_a = tenant(1);
    let repository_a = repository(2);
    let alice = principal(3);
    let tenant_b = tenant(4);
    let repository_b = repository(5);
    let bob = principal(6);
    let content = b"same bytes in every requested scope";
    let content_identity = identity(content);
    let domain_a = CacheKeyDomain::from_bytes([7; 32]);
    let grant_a = repository_grant(tenant_a, repository_a, alice, domain_a);
    let alice_context = context(alice, tenant_a, repository_a, None, 1);

    assert_eq!(
        cache
            .store_shareable(&grant_a, alice_context, peer(8), candidate(content))
            .expect("the owner may store a verified private payload"),
        CacheWriteReceipt::Stored {
            evicted: false,
            audit: CacheAuditRequirement::Required,
        }
    );

    let foreign_context = context(bob, tenant_b, repository_b, None, 1);
    assert_eq!(
        cache.read_shareable(&grant_a, foreign_context, content_identity),
        Err(CacheRefusal::ScopeDenied),
        "a tenant-B caller must be refused before the cache can answer whether tenant A stored it"
    );

    let grant_b = repository_grant(tenant_b, repository_b, bob, domain_a);
    assert_eq!(
        cache
            .read_shareable(&grant_b, foreign_context, content_identity)
            .expect("Bob may query only Bob's own private partition"),
        CacheLookup::Miss,
        "the same content under tenant A is not observable as a tenant-B cache hit"
    );

    let rotated_domain = repository_grant(
        tenant_a,
        repository_a,
        alice,
        CacheKeyDomain::from_bytes([9; 32]),
    );
    assert_eq!(
        cache
            .read_shareable(&rotated_domain, alice_context, content_identity)
            .expect("the same owner may query a new key domain"),
        CacheLookup::Miss,
        "key-domain rotation must not reuse the old domain's cache key"
    );
}

#[test]
fn public_tenant_repository_and_intent_run_scopes_are_distinct_cache_partitions() {
    let mut cache = cache();
    let tenant_id = tenant(1);
    let repository_id = repository(2);
    let alice = principal(3);
    let shared_domain = CacheKeyDomain::from_bytes([4; 32]);
    let content = b"one payload, four distinct shareable trust scopes";
    let content_identity = identity(content);
    let tenant_context = context(alice, tenant_id, repository_id, None, 1);
    let run_one = intent_run(5);
    let run_two = intent_run(6);
    let run_one_context = context(alice, tenant_id, repository_id, Some(run_one), 1);
    let run_two_context = context(alice, tenant_id, repository_id, Some(run_two), 1);

    let public = TransferCacheGrant::new(
        ShareableCacheScope::PublicGlobal,
        CacheReaders::AnyAuthenticated,
        PlaintextShareability::Shareable,
        shared_domain,
        CacheEpoch::new(9),
        CacheAuditRequirement::NotRequired,
    )
    .expect("public-global cache grants use the authenticated shareable shape");
    let tenant_shared = TransferCacheGrant::new(
        ShareableCacheScope::TenantShared { tenant: tenant_id },
        CacheReaders::explicit(alice, []),
        PlaintextShareability::Shareable,
        shared_domain,
        CacheEpoch::new(9),
        CacheAuditRequirement::NotRequired,
    )
    .expect("tenant-shared cache grants have an explicit reader set");
    let repository_private = repository_grant(tenant_id, repository_id, alice, shared_domain);
    let run_private = TransferCacheGrant::new(
        ShareableCacheScope::IntentRunPrivate {
            tenant: tenant_id,
            repository: repository_id,
            intent_run: run_one,
        },
        CacheReaders::explicit(alice, []),
        PlaintextShareability::Shareable,
        shared_domain,
        CacheEpoch::new(9),
        CacheAuditRequirement::NotRequired,
    )
    .expect("Intent-Run-private cache grants have an explicit reader set");

    assert_eq!(
        cache
            .store_shareable(&public, tenant_context, peer(7), candidate(content))
            .expect("an authenticated caller may populate the public partition"),
        CacheWriteReceipt::Stored {
            evicted: false,
            audit: CacheAuditRequirement::NotRequired,
        }
    );
    assert_eq!(
        cache
            .read_shareable(&tenant_shared, tenant_context, content_identity)
            .expect("the tenant grant is authorized to query its own partition"),
        CacheLookup::Miss,
        "the public partition cannot answer a tenant-shared presence query"
    );
    cache
        .store_shareable(&tenant_shared, tenant_context, peer(7), candidate(content))
        .expect("the tenant's explicit reader may populate the tenant partition");
    assert_eq!(
        cache
            .read_shareable(&repository_private, tenant_context, content_identity)
            .expect("the repository grant is authorized to query its own partition"),
        CacheLookup::Miss,
        "the tenant-shared and repository-private key spaces are distinct"
    );

    cache
        .store_shareable(&run_private, run_one_context, peer(8), candidate(content))
        .expect("the exact Intent Run may populate its private partition");
    assert_eq!(
        cache.read_shareable(&run_private, run_two_context, content_identity),
        Err(CacheRefusal::ScopeDenied),
        "a different Intent Run is refused before its private cache can answer"
    );
    assert_eq!(
        cache
            .read_shareable(&repository_private, tenant_context, content_identity)
            .expect("the repository grant remains authorized in its own scope"),
        CacheLookup::Miss,
        "an Intent-Run-private payload is not promoted to repository-private reuse"
    );
}

#[test]
fn poisoned_candidate_is_quarantined_and_excludes_its_peer_before_a_cache_hit() {
    let mut cache = cache();
    let grant = repository_grant(
        tenant(1),
        repository(2),
        principal(3),
        CacheKeyDomain::from_bytes([4; 32]),
    );
    let access = context(principal(3), tenant(1), repository(2), None, 1);
    let claimed = identity(b"claimed object");
    let poisoner = peer(5);
    let poisoned = CachePieceCandidate::new(claimed, b"different payload".to_vec());

    assert_eq!(
        cache
            .store_shareable(&grant, access, poisoner, poisoned)
            .expect("a bounded suspect candidate must be quarantined, not served"),
        CacheWriteReceipt::Quarantined {
            penalty: 1,
            audit: CacheAuditRequirement::Required,
        }
    );
    assert_eq!(cache.quarantined_count(), 1);
    assert_eq!(cache.peer_penalty_at(poisoner, CacheEpoch::new(1)), Ok(1));
    let status = cache
        .quarantined_shareable_status(&grant, access, claimed)
        .expect("the grant owner may audit a suspect piece in its own partition")
        .expect("the mismatched candidate is retained pending independent re-verification");
    assert_eq!(status.peer, poisoner);
    assert_eq!(status.claimed_content_identity, claimed);
    assert_eq!(
        status.observed_content_identity,
        identity(b"different payload")
    );
    assert_eq!(status.byte_len, b"different payload".len());
    assert_eq!(status.quarantined_at, CacheEpoch::new(1));
    assert_eq!(
        cache
            .read_shareable(&grant, access, claimed)
            .expect("a cache owner may observe only that its serving cache has no verified entry"),
        CacheLookup::Miss,
        "quarantine is never a serving cache"
    );
    assert_eq!(
        cache.store_shareable(&grant, access, poisoner, candidate(b"claimed object")),
        Err(CacheRefusal::PeerExcluded { peer: poisoner }),
        "a peer at the declared bad-piece threshold cannot replace its quarantined candidate"
    );
}

#[test]
fn secret_leases_do_not_share_and_each_scope_evicts_its_own_oldest_entry() {
    let mut cache = cache();
    let run = intent_run(7);
    let secret = SecretCacheLease::new(
        SecretCacheScope::new(tenant(1), repository(2), run),
        CacheKeyDomain::from_bytes([8; 32]),
        CacheEpoch::new(9),
        CacheAuditRequirement::Required,
    );

    // `SecretCacheScope` is not a `ShareableCacheScope`, and `SecretCacheLease`
    // is deliberately neither Clone nor convertible to `TransferCacheGrant`.
    // The only serving operation available here requires this exact lease.
    assert_eq!(
        cache
            .store_secret(
                &secret,
                peer(9),
                candidate(b"secret one"),
                CacheEpoch::new(1)
            )
            .expect("the lease may store its own verified secret payload"),
        CacheWriteReceipt::Stored {
            evicted: false,
            audit: CacheAuditRequirement::Required,
        }
    );
    assert!(matches!(
        cache
            .read_secret(&secret, identity(b"secret one"), CacheEpoch::new(1))
            .expect("the same lease may read its own entry"),
        CacheLookup::Hit { .. }
    ));

    assert_eq!(
        cache
            .store_secret(
                &secret,
                peer(10),
                candidate(b"secret two"),
                CacheEpoch::new(2)
            )
            .expect("a full secret partition deterministically evicts its oldest entry"),
        CacheWriteReceipt::Stored {
            evicted: true,
            audit: CacheAuditRequirement::Required,
        }
    );
    assert_eq!(
        cache
            .read_secret(&secret, identity(b"secret one"), CacheEpoch::new(2))
            .expect("the same lease may observe its current partition"),
        CacheLookup::Miss
    );
    assert!(matches!(
        cache
            .read_secret(&secret, identity(b"secret two"), CacheEpoch::new(2))
            .expect("the newest entry survives deterministic eviction"),
        CacheLookup::Hit { .. }
    ));
}
