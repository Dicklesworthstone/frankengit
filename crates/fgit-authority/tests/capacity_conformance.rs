//! `frankengit-jyhk`: the opt-in capacity conformance campaign, and the proof
//! that it has teeth.
//!
//! `run_authority_conformance` covers exactly one of the four ceilings
//! `AuthorityLimits` declares. That is how `frankengit-nv0a` hid: the embedded
//! backend published four ceilings through `limits()` and enforced one, and
//! every lane stayed green because `ac_16_bounded_typed_errors` exercises
//! `body_bytes`, the one ceiling both backends happened to enforce.
//!
//! A shared suite covering one member of a family reads, at a glance, as
//! covering the family.
//!
//! # Why the second half of this file exists
//!
//! Adding checks to a suite proves nothing until something demonstrates they
//! can fail. This crate already holds that discipline —
//! `planted_backends.rs` plants deliberately wrong implementations so the
//! suite's teeth are measured rather than assumed — and a capacity campaign
//! whose own failure mode was never exercised would be the same defect it was
//! written to catch, one level up.
//!
//! So `PublishesMoreThanItEnforces` reproduces nv0a exactly: it reports the
//! cramped limits it was handed and delegates every operation to a store built
//! with the *defaults*. The campaign must fail it, and must fail it on the
//! slot ceilings specifically.

use fgit_authority::{
    AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityStore, AuthorityVersionToken,
    CasOutcome, HeadGeneration, HeadInit, HeadKey, HeadRead, HeadReadReceipt, ImmutableKey,
    ImmutableRead, MemoryAuthorityStore, MemoryStoreConfig, PutOutcome, StoreInstanceId,
    run_capacity_conformance,
};

fn reference(instance: StoreInstanceId, limits: AuthorityLimits) -> MemoryAuthorityStore {
    MemoryAuthorityStore::with_config(MemoryStoreConfig {
        instance,
        limits,
        ..MemoryStoreConfig::default()
    })
}

#[test]
fn the_reference_passes_the_capacity_campaign() {
    let report = run_capacity_conformance(reference);
    assert!(
        report.is_pass(),
        "the reference enforces all four declared ceilings, so it must pass every capacity \
         check; failures: {:?}",
        report.failed_ids()
    );
}

#[test]
fn the_campaign_records_every_check_it_claims() {
    // Guards against a campaign that silently stops running checks: a report
    // with fewer entries than expected passes `is_pass()` just as happily.
    let report = run_capacity_conformance(reference);
    let observed: Vec<&str> = report.checks().iter().map(|check| check.id).collect();
    assert_eq!(
        observed,
        vec![
            "CAP-00", "CAP-01", "CAP-02", "CAP-03", "CAP-04", "CAP-05", "CAP-06"
        ],
        "the capacity campaign's check set drifted"
    );
}

// ------------------------------------------------------- the planted backend

/// Publishes the ceilings it was handed; enforces the defaults.
///
/// This is `frankengit-nv0a` in miniature. Every operation is delegated to a
/// store constructed with `AuthorityLimits::default()`, while `limits()`
/// returns the cramped limits the factory was given — so a caller reading
/// `limits()` is told a ceiling is in force that nothing consults.
struct PublishesMoreThanItEnforces {
    inner: MemoryAuthorityStore,
    published: AuthorityLimits,
}

impl PublishesMoreThanItEnforces {
    fn new(instance: StoreInstanceId, published: AuthorityLimits) -> Self {
        Self {
            inner: reference(instance, AuthorityLimits::default()),
            published,
        }
    }
}

impl AuthorityStore for PublishesMoreThanItEnforces {
    fn instance_id(&self) -> StoreInstanceId {
        self.inner.instance_id()
    }

    /// The defect: what it advertises is not what it enforces.
    fn limits(&self) -> AuthorityLimits {
        self.published
    }

    fn put_if_absent(
        &self,
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        self.inner.put_if_absent(key, body)
    }

    fn read_immutable(&self, key: &ImmutableKey) -> Result<ImmutableRead, AuthorityFailure> {
        self.inner.read_immutable(key)
    }

    fn initialize_head(
        &self,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, AuthorityFailure> {
        self.inner.initialize_head(key, generation, body)
    }

    fn read_head(&self, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        self.inner.read_head(key)
    }

    fn compare_exchange_head(
        &self,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        self.inner
            .compare_exchange_head(key, expected, new_generation, new_body)
    }

    fn authenticate_head_receipt(
        &self,
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure> {
        self.inner.authenticate_head_receipt(receipt)
    }
}

#[test]
fn the_campaign_fails_a_backend_that_publishes_more_than_it_enforces() {
    // The teeth. `body_bytes` is NOT among the failures on purpose: the planted
    // store's inner default ceiling is 1 MiB, so a body one past the *published*
    // 4096 is still accepted, and CAP-01 catches that too. What must fail are
    // the three slot ceilings, because those are the ones nv0a left unenforced.
    let report = run_capacity_conformance(PublishesMoreThanItEnforces::new);

    assert!(
        !report.is_pass(),
        "a backend publishing ceilings it does not enforce must not pass the capacity campaign; \
         if this ever passes, the campaign has stopped measuring anything and every green run \
         above it is worthless"
    );

    let failed = report.failed_ids();
    for required in ["CAP-02", "CAP-03", "CAP-04"] {
        assert!(
            failed.contains(&required),
            "{required} must fail against a store that ignores the ceiling it publishes; failures \
             were {failed:?}"
        );
    }

    // The exemption checks must still PASS against the planted store. It
    // over-publishes rather than over-refusing, so an idempotent retry is still
    // admitted — and if these failed here, CAP-05/06 would be firing for some
    // reason other than the one they name.
    assert!(
        !failed.contains(&"CAP-05") && !failed.contains(&"CAP-06"),
        "the exemption checks must not fire against a store that merely under-enforces; they \
         failed as {failed:?}, so they are not measuring what they claim"
    );

    // And the non-vacuity check is about the probe, not the backend.
    assert!(
        !failed.contains(&"CAP-00"),
        "CAP-00 checks the probe's own limits and cannot depend on the backend under test"
    );
}
