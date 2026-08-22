//! CALM-015 cache-grant evidence.
//!
//! A warmed admission view is a bounded, derived cache. The usable witness
//! exists only after exact authenticated-basis matching; it is never authority.

use fgit_resource::{
    CacheBinding, CacheGrant, CacheGrantRefusal, CachePermit, CacheScope, Grade, LeakDisposition,
    ObligationLedger, OpaqueHandle, RegionId, ResourceVector,
};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, HeadGeneration, OPAQUE_ID_LEN,
    RepositoryAuthorityHeadId, RepositoryId,
};

const fn repository(tag: u8) -> RepositoryId {
    RepositoryId::from_bytes([tag; OPAQUE_ID_LEN])
}

fn head(tag: u8) -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(1).expect("one is a registered digest algorithm"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 32]).expect("thirty-two bytes form a digest body"),
    )
}

fn generation(tag: u8) -> HeadGeneration {
    HeadGeneration::try_new(u64::from(tag)).expect("non-zero fixture generation")
}

fn binding(repository_tag: u8, head_tag: u8, generation_tag: u8, scope_tag: u8) -> CacheBinding {
    CacheBinding::new(
        repository(repository_tag),
        head(head_tag),
        generation(generation_tag),
        CacheScope::new(
            OpaqueHandle::new(&[scope_tag; 16]).expect("sixteen bytes form an opaque scope"),
        ),
    )
}

fn cache_budget() -> ResourceVector {
    ResourceVector::from_grades(&[
        (Grade::Bytes, 1_024),
        (Grade::Objects, 1),
        (Grade::CpuMicros, 10_000),
        (Grade::MemoryBytes, 4_096),
    ])
}

#[test]
fn cache_grant_refuses_unfunded_materialization_before_any_cache_permit_exists() {
    let underfunded = ResourceVector::from_grades(&[
        (Grade::Bytes, 1_024),
        (Grade::Objects, 1),
        (Grade::CpuMicros, 10_000),
    ]);
    let ledger = ObligationLedger::root(
        RegionId::new(801),
        LeakDisposition::RecordAndContinue,
        underfunded,
    );
    let budget = ledger
        .grant(underfunded)
        .expect("a ledger grants the bounded amount before cache reserve validates it");

    let refusal = CacheGrant::reserve(binding(1, 2, 3, 4), budget)
        .expect_err("missing memory must refuse before materialization work obtains a witness");
    assert_eq!(
        refusal,
        CacheGrantRefusal::MissingRequiredGrade(Grade::MemoryBytes),
        "CALM-015 requires a bounded resident view, not only decode inputs"
    );
    assert_eq!(
        ledger.snapshot().available(),
        underfunded,
        "a pre-work refusal returns the unspent budget"
    );
    assert!(
        ledger.close().is_quiescent(),
        "a refused reservation leaves no live cache capability"
    );
}

#[test]
fn unmaterialized_cache_refuses_but_its_exact_materialized_twin_proceeds() {
    let budget = cache_budget();
    let ledger = ObligationLedger::root(
        RegionId::new(802),
        LeakDisposition::RecordAndContinue,
        budget,
    );
    let exact = binding(5, 6, 7, 8);
    let grant = CacheGrant::reserve(
        exact,
        ledger
            .grant(budget)
            .expect("the complete cache budget is available before work"),
    )
    .expect("the permitted twin reserves every required cache grade");
    let permit = grant
        .accept(exact)
        .expect("a matching authenticated basis permits the materialized view");

    assert_eq!(
        CachePermit::require_matching(None, exact),
        Err(CacheGrantRefusal::Unmaterialized),
        "an absent materialization is distinct from a stale materialization"
    );
    assert_eq!(
        CachePermit::require_matching(Some(&permit), exact),
        Ok(()),
        "the exact-basis materialized twin is permitted"
    );
    assert_eq!(permit.binding(), exact);
    assert!(ledger.close().is_quiescent());
}

#[test]
fn any_repository_head_generation_or_scope_mismatch_refuses_the_cache_view() {
    let budget = cache_budget();
    let ledger = ObligationLedger::root(
        RegionId::new(803),
        LeakDisposition::RecordAndContinue,
        budget,
    );
    let exact = binding(9, 10, 11, 12);
    let permit = CacheGrant::reserve(
        exact,
        ledger
            .grant(budget)
            .expect("the complete cache budget is available before work"),
    )
    .expect("the grant is otherwise valid")
    .accept(exact)
    .expect("the matching basis creates the permitted twin");

    for mismatched in [
        binding(9, 13, 11, 12),
        binding(14, 10, 11, 12),
        binding(9, 10, 15, 12),
        binding(9, 10, 11, 16),
    ] {
        assert_eq!(
            CachePermit::require_matching(Some(&permit), mismatched),
            Err(CacheGrantRefusal::BasisMismatch),
            "every exact binding field is load-bearing"
        );
    }
    assert_eq!(
        CachePermit::require_matching(Some(&permit), exact),
        Ok(()),
        "the exact binding remains the near-identical permitted twin"
    );
    assert!(ledger.close().is_quiescent());
}

#[test]
fn cancelled_materialization_discards_its_grant_without_recording_a_budget_leak() {
    let budget = cache_budget();
    let ledger = ObligationLedger::root(
        RegionId::new(804),
        LeakDisposition::RecordAndContinue,
        budget,
    );
    let grant = CacheGrant::reserve(
        binding(17, 18, 19, 20),
        ledger
            .grant(budget)
            .expect("the complete cache budget is available before work"),
    )
    .expect("the grant is otherwise valid");

    drop(grant);
    assert_eq!(
        ledger.snapshot().available(),
        budget,
        "cancellation discards the derived cache attempt and returns its budget"
    );
    assert!(
        ledger.close().is_quiescent(),
        "discarding a cache hint is not an outstanding authority effect or budget leak"
    );
}
