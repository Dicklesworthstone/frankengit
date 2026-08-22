//! FG-022b: capability-absent fallback to the ordinary pack path, with a typed
//! reason — every reason, and the ordering between them.
//!
//! The bead's campaign list includes *"capability-absent fallback to ordinary
//! pack path with typed reason"*. `FullFallbackReason` is a **closed set of
//! four**, so "typed reason" is checkable exhaustively rather than by sampling:
//! each variant is constructed here from the exact condition that produces it,
//! and a compile-time guard fails if a fifth is ever added without a case.
//!
//! # Why the ordering matters as much as the reasons
//!
//! `PlanSelector::fallback_reason` is an **ordered chain** — repository scope,
//! then mutual profile, then exact-closure verification, then summary size —
//! and it returns on the first match. That has two consequences a campaign has
//! to respect rather than discover by accident:
//!
//! - a test for a later reason must satisfy every earlier condition, or it
//!   silently measures the earlier one instead;
//! - when two conditions hold at once, exactly one reason is reported, and
//!   which one is a published behaviour rather than an implementation detail —
//!   an operator reading `RepositoryScopeMismatch` needs to know a profile
//!   mismatch may *also* be present.
//!
//! Both are pinned below.
//!
//! # The presence case, which is the point of the file
//!
//! Four tests that each assert "it fell back" would all pass against a selector
//! that falls back unconditionally. `a_fully_capable_pair_does_not_fall_back`
//! is the permitted case they are measured against, and it is the assertion
//! most likely to catch a real regression here.
//!
//! # Non-claims
//!
//! This covers **plan selection**, not transfer. It says nothing about whether
//! the fallback path then produces an end state equal to the ordinary pack
//! path — that is the bead's semantic-identity acceptance line and needs the
//! reconstruction pipeline, not the selector. Nothing here touches
//! `fgit-atp-git/src`.

use fgit_atp_git::{
    AtpGitProfile, AtpRefusal, AuthenticatedPeerCapabilities, FullFallbackReason, HaveSummary,
    PeerCapabilities, PeerCapabilityVerifier, PeerIdentity, PlanSelector, TransferLimits,
    TransferManifest, TransferObjectEntry, TransferPlanKind,
};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_object_fabric::ObjectKind;
use fgit_types::{GitHashAlgorithm, RepositoryId};

/// Every reason the selector may report.
///
/// Transcribed from the enum rather than iterated, so that adding a variant
/// breaks the exhaustive match in `every_reason_in_the_closed_set_is_actually_producible`
/// and forces whoever adds it to decide how it is produced.
const ALL_FALLBACK_REASONS: [FullFallbackReason; 4] = [
    FullFallbackReason::RepositoryScopeMismatch,
    FullFallbackReason::ConservativeProfileNotMutual,
    FullFallbackReason::ExactClosureVerificationUnavailable,
    FullFallbackReason::ProbabilisticSummaryTooLarge,
];

/// Authenticates whatever it is given.
///
/// The subject here is what the selector does with an *authenticated* record,
/// so verification itself is deliberately out of the way. A verifier that
/// rejected anything would make these tests measure the verifier instead.
struct AcceptingVerifier;

impl PeerCapabilityVerifier for AcceptingVerifier {
    fn verify(&self, _offered: &PeerCapabilities) -> Result<(), AtpRefusal> {
        Ok(())
    }
}

fn limits() -> TransferLimits {
    TransferLimits::new(64, 1 << 20, 1 << 24, 64).expect("positive bounds are admissible")
}

const fn repository() -> RepositoryId {
    RepositoryId::from_bytes([7; 16])
}

/// A capability record, with every axis the selector reads made explicit.
fn capabilities(
    byte: u8,
    repository: RepositoryId,
    profiles: &[AtpGitProfile],
    exact_closure: bool,
) -> AuthenticatedPeerCapabilities {
    let offered = PeerCapabilities::new(
        PeerIdentity::from_bytes([byte; 32]),
        repository,
        profiles.iter().copied(),
        exact_closure,
    );
    AuthenticatedPeerCapabilities::verify(offered, &AcceptingVerifier).expect("accepting verifier")
}

/// A fully capable peer: right repository, the supported profile, exact closure.
fn capable(byte: u8) -> AuthenticatedPeerCapabilities {
    capabilities(
        byte,
        repository(),
        &[AtpGitProfile::ConservativeInterimV1],
        true,
    )
}

fn entry(payload: &[u8]) -> TransferObjectEntry {
    let identity = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, payload);
    TransferObjectEntry::from_payload(identity, ObjectKind::Blob, payload, None)
        .expect("a payload identified by its own digest is a valid entry")
}

fn manifest() -> TransferManifest {
    let mut entries = vec![entry(b"alpha"), entry(b"beta")];
    entries.sort_by_key(TransferObjectEntry::identity);
    let roots = vec![entries.last().expect("two entries").identity()];
    TransferManifest::new(
        repository(),
        GitHashAlgorithm::Sha1,
        roots,
        entries,
        limits(),
    )
    .expect("canonical manifest")
}

/// An empty exact inventory: the receiver knows nothing, so nothing but the
/// fallback conditions can influence the plan class.
fn knows_nothing() -> HaveSummary {
    HaveSummary::exact_objects(Vec::new(), limits()).expect("an empty inventory is canonical")
}

fn selected_kind(
    source: &AuthenticatedPeerCapabilities,
    receiver: &AuthenticatedPeerCapabilities,
    have: &HaveSummary,
) -> TransferPlanKind {
    PlanSelector::new(limits())
        .select(&manifest(), source, receiver, have)
        .receipt()
        .plan_kind()
}

const fn fallback_of(kind: TransferPlanKind) -> Option<FullFallbackReason> {
    match kind {
        TransferPlanKind::FullClosureFallback(reason) => Some(reason),
        TransferPlanKind::AlreadyInSync
        | TransferPlanKind::ObjectDelta
        | TransferPlanKind::UniqueContentDelta => None,
    }
}

/// A summary one byte past the SELECTOR's bound.
///
/// Built under a permissive limit so `from_wire` accepts it: the refusal under
/// test belongs to the selector, and constructing it against the selector's own
/// bound would be refused here and never reach a plan.
fn oversize_summary() -> HaveSummary {
    let over = limits().max_probabilistic_summary_bytes() + 1;
    let bit_count = u32::try_from(over * 8).expect("a small bit count");
    let summary = fgit_atp_git::BloomHaveSummary::from_wire(
        bit_count,
        &vec![0_u8; over],
        TransferLimits::new(64, 1 << 20, 1 << 24, usize::MAX).expect("a permissive bound"),
    )
    .expect("the summary is only oversize against the selector's bound");
    HaveSummary::Probabilistic(summary)
}

// --------------------------------------------------------- the permitted case

#[test]
fn a_fully_capable_pair_does_not_fall_back() {
    // THE PRESENCE CASE, and the reason the four refusal tests below mean
    // anything. Each of them asserts "it fell back", and all four would pass
    // just as happily against a selector that fell back unconditionally. This
    // is the only assertion here that can catch that.
    let kind = selected_kind(&capable(1), &capable(2), &knows_nothing());

    assert_eq!(
        fallback_of(kind),
        None,
        "two peers in the right repository, sharing the conservative profile, with exact closure \
         verification and an empty exact inventory, must select a delta plan rather than falling \
         back; got {kind:?}"
    );
}

// ------------------------------------------------------- one test per reason

#[test]
fn a_repository_scope_mismatch_falls_back() {
    // The first link in the chain: capabilities authenticated for a different
    // repository must not influence this manifest's plan at all.
    let elsewhere = capabilities(
        1,
        RepositoryId::from_bytes([9; 16]),
        &[AtpGitProfile::ConservativeInterimV1],
        true,
    );

    let kind = selected_kind(&elsewhere, &capable(2), &knows_nothing());

    assert_eq!(
        fallback_of(kind),
        Some(FullFallbackReason::RepositoryScopeMismatch),
        "a source authenticated for another repository must fall back with the scope reason; \
         got {kind:?}"
    );
}

#[test]
fn a_profile_that_is_not_mutual_falls_back() {
    // Every earlier condition satisfied — same repository — so this measures
    // the profile check rather than the scope check above it.
    let no_profiles = capabilities(2, repository(), &[], true);

    let kind = selected_kind(&capable(1), &no_profiles, &knows_nothing());

    assert_eq!(
        fallback_of(kind),
        Some(FullFallbackReason::ConservativeProfileNotMutual),
        "a receiver offering no profile cannot share the conservative one; got {kind:?}"
    );
}

#[test]
fn a_receiver_without_exact_closure_verification_falls_back() {
    // Right repository and shared profile, so the two earlier links pass and
    // this one is what the selector actually reaches.
    let cannot_verify = capabilities(
        2,
        repository(),
        &[AtpGitProfile::ConservativeInterimV1],
        false,
    );

    let kind = selected_kind(&capable(1), &cannot_verify, &knows_nothing());

    assert_eq!(
        fallback_of(kind),
        Some(FullFallbackReason::ExactClosureVerificationUnavailable),
        "a receiver that cannot perform the mandatory exact final closure check must fall back; \
         got {kind:?}"
    );
}

#[test]
fn a_probabilistic_summary_over_its_bound_falls_back() {
    // The last link in the chain, and only reachable once all three earlier
    // conditions are satisfied — which is why this uses two fully capable
    // peers rather than a minimal fixture.
    let kind = selected_kind(&capable(1), &capable(2), &oversize_summary());

    assert_eq!(
        fallback_of(kind),
        Some(FullFallbackReason::ProbabilisticSummaryTooLarge),
        "a summary past the selector's bound must fall back rather than be trusted or truncated; \
         got {kind:?}"
    );
}

// ------------------------------------------------------------- the ordering

#[test]
fn the_first_failing_condition_is_the_one_reported() {
    // Two conditions at once. The chain checks repository scope before mutual
    // profile, so the scope reason is the one an operator sees — and the
    // profile mismatch is invisible in the receipt.
    //
    // This is published behaviour rather than an implementation detail: someone
    // reading `RepositoryScopeMismatch` must not conclude the profiles matched.
    // If the order ever changes, this fails rather than silently altering what
    // a receipt means.
    let wrong_repository_and_no_profile =
        capabilities(1, RepositoryId::from_bytes([9; 16]), &[], true);

    let kind = selected_kind(
        &wrong_repository_and_no_profile,
        &capable(2),
        &knows_nothing(),
    );

    assert_eq!(
        fallback_of(kind),
        Some(FullFallbackReason::RepositoryScopeMismatch),
        "with both a scope mismatch and an absent profile, the earlier check must win; got \
         {kind:?}"
    );
}

// ------------------------------------------------------------ the closed set

#[test]
fn every_reason_in_the_closed_set_is_actually_producible() {
    // The guard on this file's completeness, and it drives the selector rather
    // than asserting a name.
    //
    // The first version of this test matched exhaustively and then asserted
    // that a test-name string was non-empty -- trivially true, and decoration
    // (RH-5). The exhaustive match was doing all the work and the assertion
    // none. Now each arm supplies the CONDITION, and the reason is measured
    // coming back out of the selector, so the test fails if a variant is added
    // with no way to produce it as well as if the match stops compiling.
    for reason in ALL_FALLBACK_REASONS {
        let (source, receiver, have) = match reason {
            FullFallbackReason::RepositoryScopeMismatch => (
                capabilities(
                    1,
                    RepositoryId::from_bytes([9; 16]),
                    &[AtpGitProfile::ConservativeInterimV1],
                    true,
                ),
                capable(2),
                knows_nothing(),
            ),
            FullFallbackReason::ConservativeProfileNotMutual => (
                capable(1),
                capabilities(2, repository(), &[], true),
                knows_nothing(),
            ),
            FullFallbackReason::ExactClosureVerificationUnavailable => (
                capable(1),
                capabilities(
                    2,
                    repository(),
                    &[AtpGitProfile::ConservativeInterimV1],
                    false,
                ),
                knows_nothing(),
            ),
            FullFallbackReason::ProbabilisticSummaryTooLarge => {
                (capable(1), capable(2), oversize_summary())
            }
        };

        assert_eq!(
            fallback_of(selected_kind(&source, &receiver, &have)),
            Some(reason),
            "{reason:?} is in the published set but the condition mapped to it did not produce \
             it; a reason nothing can produce is a control that exists only on paper"
        );
    }
}
