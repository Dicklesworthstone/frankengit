//! What the sealed identity of a merge binds, and what it refuses to seal.
//!
//! # The defect these drills close
//!
//! `NORMATIVE_PROTOCOL_CONTRACTS.md` section 3.3 requires the canonical request
//! digest to bind "requested forge transitions" alongside the ref fields. The
//! merge seal was built from the `RefCommand` alone, so the forge half of a
//! merge reached authority carrying an identity that said nothing about it.
//!
//! Two consequences, and the drills below separate them because they need
//! different evidence:
//!
//! * two merges moving one ref to one tip with DIFFERENT events derived the same
//!   `TxId`, so the second resolved to the first's terminal decision and never
//!   ran -- one ref movement with two meanings under one identity, which is what
//!   section 5.2 forbids;
//! * an attempt and a package describing different merges were sealed happily,
//!   so the staleness check validated the tips named by one and the record moved
//!   the ref named by the other.
//!
//! # Why the assertions are on the request digest
//!
//! `canonical_request_digest` is the exact artifact section 3.3 governs, and
//! `TxId` is a pure function of it plus the tenant, repository, principal and
//! idempotency key. Asserting on the digest tests the binding rather than the
//! surrounding derivation, and the first drill also shows the `TxId`s move with
//! it so the consequence is not left as an inference.

use std::collections::BTreeSet;

use fgit_admission::merge::{SealedMerge, seal_attempt_for};
use fgit_admission::{AdmissionContext, AdmissionError, CommitEvidence, ValidatedClosure};
use fgit_authority::{
    HeadKey, IdempotencyKey, TxIdPreimage, canonical_request_digest, derive_tx_id,
};
use fgit_forge::event::ForgeEvent;
use fgit_forge::{
    AggregateVersion, ForgeEventPayload, MergeAttempt, MergeEffectPackage, PullRequestNumber,
    RefIntent, WorkspaceEpoch,
};
use fgit_types::native::GitHashAlgorithm;
use fgit_types::{
    Digest, DigestAlgorithmId, DigestBytes, GitOid, PrincipalId, PrincipalSnapshotId, RepositoryId,
    TenantId,
};
use fgit_wire::GitObjectFormat;

const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;
const _: () = assert!(FIXTURE_ALGORITHM_CODE_POINT >= 0xfff0);

const MAIN_REF: &[u8] = b"refs/heads/main";
const OTHER_REF: &[u8] = b"refs/heads/release";
const FEATURE_REF: &[u8] = b"refs/heads/feature";
const TARGET_OID: &str = "2222222222222222222222222222222222222222";
const SOURCE_OID: &str = "3333333333333333333333333333333333333333";
const BASE_OID: &str = "1111111111111111111111111111111111111111";
const MERGE_OID: &str = "4444444444444444444444444444444444444444";
const STRAY_OID: &str = "6666666666666666666666666666666666666666";

fn digest(seed: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("nonzero corpus fixture algorithm slot"),
        DigestBytes::try_new(&[seed; 32]).expect("32-byte corpus fixture body"),
    )
}

fn oid(hex: &str) -> GitOid {
    GitOid::from_hex(GitHashAlgorithm::Sha1, hex).expect("fixture oid")
}

fn context() -> AdmissionContext {
    AdmissionContext {
        head_key: HeadKey::new(b"fg/head/asa3-seal-binding".to_vec()).expect("valid head key"),
        tenant_id: TenantId::from_bytes([1; 16]),
        repository_id: RepositoryId::from_bytes([2; 16]),
        principal_id: PrincipalId::from_bytes([3; 16]),
        idempotency_key: IdempotencyKey::new(b"asa3-seal-binding".to_vec()).expect("bounded key"),
        object_format: GitObjectFormat::Sha1,
    }
}

fn commit_evidence() -> CommitEvidence {
    CommitEvidence {
        principal_snapshot_id: PrincipalSnapshotId::from_digest(
            DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
                .expect("nonzero corpus fixture algorithm slot"),
            fgit_types::CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[15; 32]).expect("32-byte corpus fixture body"),
        ),
        forge_event_batch_root: digest(8),
        policy_decision_root: digest(9),
        invariant_evidence_root: digest(10),
        outbox_effect_root: digest(11),
        retention_delta_root: digest(12),
    }
}

/// The pull request every fixture here merges.
///
/// One constant because the attempt and the event must now name the SAME
/// aggregate to be coherent -- see
/// `an_event_for_another_pull_request_is_refused_before_sealing`.
const PULL_REQUEST: u64 = 41;

/// A merge package whose ref movement is FIXED and whose event varies.
///
/// The ref intent is identical for every `version` value, which is what makes
/// the first drill's claim checkable: the two packages differ in the forge event
/// and in nothing the old ref-only seal could see.
///
/// # Why the event varies by version rather than by pull request
///
/// It varied by pull request until `frankengit-asa3` closed the coherence hole
/// `BlackOx` named: an attempt for pull request X carrying an event for pull
/// request Y sealed happily as one merge. Now it is refused before sealing, so
/// varying that field would make this drill fail at the gate instead of
/// demonstrating anything about the digest.
///
/// The stream position is the right axis anyway. It is a real field of a real
/// event, two merges of one pull request genuinely differ in it, and it is
/// invisible to a ref-only seal in exactly the way the pull-request number was.
fn package_with_event(version: u64) -> MergeEffectPackage {
    MergeEffectPackage {
        objects: vec![oid(MERGE_OID)],
        ref_intent: RefIntent {
            name: MAIN_REF.to_vec(),
            expected_tip: oid(TARGET_OID),
            new_tip: oid(MERGE_OID),
        },
        event: ForgeEvent {
            aggregate: PullRequestNumber::try_new(PULL_REQUEST)
                .expect("a nonzero pull request number")
                .into(),
            version: AggregateVersion::try_new(version).expect("a nonzero aggregate version"),
            payload: ForgeEventPayload::MergeCommitted {
                merge_commit: digest(0x51),
                target_ref: MAIN_REF.to_vec(),
                target_tip_before: digest(0x40),
                target_tip_after: digest(0x51),
            },
        },
    }
}

fn attempt() -> MergeAttempt {
    MergeAttempt {
        pull_request: PullRequestNumber::try_new(PULL_REQUEST)
            .expect("a nonzero pull request number"),
        source_ref: FEATURE_REF.to_vec(),
        target_ref: MAIN_REF.to_vec(),
        source_tip: oid(SOURCE_OID),
        target_tip: oid(TARGET_OID),
        base_tip: oid(BASE_OID),
        workspace_epoch: WorkspaceEpoch::from_u64(9),
    }
}

fn closure() -> ValidatedClosure {
    let mut objects = BTreeSet::new();
    objects.insert(oid(MERGE_OID));
    let permitted = fgit_admission::PermittedObjectClosure::new(objects.clone());
    ValidatedClosure {
        object_closure_root: fgit_admission::permitted_object_closure_root(&permitted)
            .expect("closure root"),
        objects,
    }
}

fn sealed<'a>(
    package: &'a MergeEffectPackage,
    attempt: &'a MergeAttempt,
    closure: &'a ValidatedClosure,
) -> SealedMerge<'a> {
    SealedMerge {
        package,
        attempt,
        closure,
        evidence: commit_evidence(),
        workspace_epoch_now: WorkspaceEpoch::from_u64(9),
    }
}

fn request_digest(context: &AdmissionContext, sealed: &SealedMerge<'_>) -> Digest {
    let attempt = seal_attempt_for(context, sealed).expect("a coherent merge seals");
    canonical_request_digest(&attempt.request).expect("the request has a canonical digest")
}

fn tx_id_of(context: &AdmissionContext, sealed: &SealedMerge<'_>) -> fgit_types::TxId {
    let attempt = seal_attempt_for(context, sealed).expect("a coherent merge seals");
    derive_tx_id(&TxIdPreimage {
        tenant_id: attempt.tenant_id,
        repository_id: attempt.repository_id,
        authenticated_principal_id: attempt.authenticated_principal_id,
        idempotency_key: attempt.idempotency_key.clone(),
        canonical_request_digest: canonical_request_digest(&attempt.request)
            .expect("the request has a canonical digest"),
    })
    .expect("tx id")
}

// ---------------------------------------------------------------------------
// The binding
// ---------------------------------------------------------------------------

/// Two merges whose ref movement is byte-identical and whose events differ.
///
/// The middle assertion is the one that makes this a regression test rather than
/// a restatement: it builds the ref-only request the seal used to build and
/// shows the two merges collide under it. So the drill demonstrates the defect
/// and the fix in the same run, without needing the old code to still exist.
#[test]
fn two_merges_differing_only_in_their_forge_event_no_longer_share_one_identity() {
    let context = context();
    let attempt = attempt();
    let closure = closure();
    let left = package_with_event(1);
    let right = package_with_event(2);

    // The ref halves really are identical; the events really do differ. Both are
    // asserted rather than assumed, because a fixture edit that accidentally
    // made the two packages equal would turn every assertion below into a
    // tautology that passes.
    assert_eq!(
        left.ref_intent, right.ref_intent,
        "the drill is only meaningful if the ref movement is the same"
    );
    assert_ne!(left.event, right.event, "the events must differ");

    // What the seal used to bind: ref commands and nothing else. Both merges
    // land on ONE digest, which is the collision this bead was reworked for.
    let ref_only = |package: &MergeEffectPackage| {
        let command = fgit_authority::RefCommand {
            name: fgit_types::RefName::try_new(&package.ref_intent.name).expect("ref name"),
            expected_old: fgit_authority::ExpectedOld::Exactly(package.ref_intent.expected_tip),
            proposed_new: fgit_authority::ProposedNew::Update(package.ref_intent.new_tip),
            force: false,
        };
        let semantic = fgit_authority::SemanticRequest::build(
            fgit_authority::RECEIVE_ADMISSION_SCHEMA,
            context.object_format,
            true,
            vec![command],
            Vec::new(),
            Vec::new(),
        )
        .expect("a ref-only request");
        canonical_request_digest(&semantic).expect("digest")
    };
    assert_eq!(
        ref_only(&left),
        ref_only(&right),
        "a ref-only seal cannot tell these two merges apart -- that was the defect"
    );

    // What it binds now.
    assert_ne!(
        request_digest(&context, &sealed(&left, &attempt, &closure)),
        request_digest(&context, &sealed(&right, &attempt, &closure)),
        "the requested forge transition must reach the canonical request digest"
    );
    assert_ne!(
        tx_id_of(&context, &sealed(&left, &attempt, &closure)),
        tx_id_of(&context, &sealed(&right, &attempt, &closure)),
        "and the transaction identity must move with it"
    );
}

/// The permitted twin, and the property the binding must NOT break.
///
/// Binding more into the digest is only correct if it stays a function of the
/// request. A retry that rebuilds an identical merge has to seal to the same
/// identity, or every retry would become a new transaction and idempotency would
/// be gone -- a strictly worse failure than the collision being fixed.
#[test]
fn an_identical_merge_rebuilt_seals_to_the_same_identity() {
    let context = context();
    let attempt = attempt();
    let closure = closure();
    let first = package_with_event(1);
    let second = package_with_event(1);

    assert_eq!(
        request_digest(&context, &sealed(&first, &attempt, &closure)),
        request_digest(&context, &sealed(&second, &attempt, &closure)),
        "an equivalent retry must seal to one identity"
    );
    assert_eq!(
        tx_id_of(&context, &sealed(&first, &attempt, &closure)),
        tx_id_of(&context, &sealed(&second, &attempt, &closure)),
        "so the retry resolves the original decision rather than minting one"
    );
}

/// The workspace epoch is a caller assertion, so varying it must vary identity.
///
/// Admission cannot verify a `TreeFS` workspace counter it has no access to. What
/// it can do is refuse to let the assertion be silently swapped underneath one
/// transaction identity, which is what binding it into the digest buys.
#[test]
fn a_merge_asserting_a_different_workspace_epoch_seals_as_a_different_request() {
    let context = context();
    let package = package_with_event(1);
    let closure = closure();
    let ninth = attempt();
    let tenth = MergeAttempt {
        workspace_epoch: WorkspaceEpoch::from_u64(10),
        ..attempt()
    };

    assert_ne!(
        request_digest(&context, &sealed(&package, &ninth, &closure)),
        request_digest(&context, &sealed(&package, &tenth, &closure)),
        "the asserted workspace epoch must reach the request digest"
    );
}

// ---------------------------------------------------------------------------
// The coherence gate
// ---------------------------------------------------------------------------

/// An attempt and a package naming different target refs.
///
/// Before this gate the staleness check re-read the tips of the ATTEMPT's ref
/// while the resulting state moved the PACKAGE's, so a merge could be validated
/// against one ref and published against another.
#[test]
fn an_attempt_and_package_naming_different_refs_are_refused_before_sealing() {
    let context = context();
    let closure = closure();
    let package = package_with_event(1);
    let elsewhere = MergeAttempt {
        target_ref: OTHER_REF.to_vec(),
        ..attempt()
    };

    let refusal = seal_attempt_for(&context, &sealed(&package, &elsewhere, &closure))
        .expect_err("an incoherent merge must not seal");
    assert!(
        matches!(
            refusal,
            AdmissionError::MergeIncoherent {
                field: "target ref"
            }
        ),
        "expected a target-ref incoherence, got {refusal:?}"
    );

    // The permitted twin: the same merge whose attempt names the package's ref.
    seal_attempt_for(&context, &sealed(&package, &attempt(), &closure))
        .expect("the agreeing merge still seals");
}

/// An attempt whose expected tip is not the one the package will conditionally
/// replace.
#[test]
fn an_attempt_and_package_expecting_different_tips_are_refused_before_sealing() {
    let context = context();
    let closure = closure();
    let package = package_with_event(1);
    let stale = MergeAttempt {
        target_tip: oid(STRAY_OID),
        ..attempt()
    };

    let refusal = seal_attempt_for(&context, &sealed(&package, &stale, &closure))
        .expect_err("an incoherent merge must not seal");
    assert!(
        matches!(
            refusal,
            AdmissionError::MergeIncoherent {
                field: "expected target tip"
            }
        ),
        "expected an expected-tip incoherence, got {refusal:?}"
    );

    seal_attempt_for(&context, &sealed(&package, &attempt(), &closure))
        .expect("the agreeing merge still seals");
}

/// A package naming an object the validated closure does not hold.
///
/// What gets staged is the closure, so a package naming an object outside it
/// would publish a ref pointing at bytes no later reader can resolve.
#[test]
fn a_package_object_outside_the_validated_closure_is_refused_and_one_inside_is_not() {
    let context = context();
    let attempt = attempt();
    let closure = closure();
    let mut stray = package_with_event(1);
    stray.objects.push(oid(STRAY_OID));

    let refusal = seal_attempt_for(&context, &sealed(&stray, &attempt, &closure))
        .expect_err("an object outside the closure must not seal");
    assert!(
        matches!(
            refusal,
            AdmissionError::MergeIncoherent {
                field: "created objects outside the validated closure"
            }
        ),
        "expected a closure-containment incoherence, got {refusal:?}"
    );

    // The permitted twin at the exact boundary: the SAME package, admitted the
    // moment the closure actually holds the object it names. Containment is the
    // rule, not equality, so a closure holding strictly more still seals.
    let mut objects = closure.objects;
    objects.insert(oid(STRAY_OID));
    let permitted = fgit_admission::PermittedObjectClosure::new(objects.clone());
    let wider = ValidatedClosure {
        object_closure_root: fgit_admission::permitted_object_closure_root(&permitted)
            .expect("closure root"),
        objects,
    };
    seal_attempt_for(&context, &sealed(&stray, &attempt, &wider))
        .expect("a closure that holds every created object seals");
}

// ---------------------------------------------------------------------------
// The event has to be an event ABOUT this merge
// ---------------------------------------------------------------------------

/// An attempt for one pull request carrying an event for another.
///
/// `BlackOx` named this on `frankengit-asa3`: binding the event into the request
/// digest stops two different merges sharing one `TxId`, but it never required
/// the event to be about the merge it travels with. An attempt for pull request
/// X plus an event for pull request Y sealed as one coherent merge, and the
/// record it produced said a merge of Y moved X's ref.
#[test]
fn an_event_for_another_pull_request_is_refused_before_sealing() {
    let context = context();
    let closure = closure();
    let attempt = attempt();
    let mut elsewhere = package_with_event(1);
    elsewhere.event.aggregate = PullRequestNumber::try_new(PULL_REQUEST + 1)
        .expect("a nonzero pull request number")
        .into();

    let refusal = seal_attempt_for(&context, &sealed(&elsewhere, &attempt, &closure))
        .expect_err("an event for another aggregate must not seal");
    assert!(
        matches!(
            refusal,
            AdmissionError::MergeIncoherent {
                field: "event aggregate"
            }
        ),
        "expected an event-aggregate incoherence, got {refusal:?}"
    );

    // The permitted twin at the exact boundary: the same package whose event
    // names the pull request the attempt is merging.
    seal_attempt_for(
        &context,
        &sealed(&package_with_event(1), &attempt, &closure),
    )
    .expect("an event for this pull request still seals");
}

/// An event naming a target ref the merge does not move.
#[test]
fn an_event_naming_another_target_ref_is_refused_before_sealing() {
    let context = context();
    let closure = closure();
    let attempt = attempt();
    let mut elsewhere = package_with_event(1);
    let ForgeEventPayload::MergeCommitted { target_ref, .. } = &mut elsewhere.event.payload else {
        panic!("the fixture event is a merge commit")
    };
    *target_ref = OTHER_REF.to_vec();

    let refusal = seal_attempt_for(&context, &sealed(&elsewhere, &attempt, &closure))
        .expect_err("an event naming another ref must not seal");
    assert!(
        matches!(
            refusal,
            AdmissionError::MergeIncoherent {
                field: "event target ref"
            }
        ),
        "expected an event-target-ref incoherence, got {refusal:?}"
    );

    seal_attempt_for(
        &context,
        &sealed(&package_with_event(1), &attempt, &closure),
    )
    .expect("an event naming the moved ref still seals");
}

/// An event whose merge commit is not the tip the target ends at.
///
/// These two fields are both `Digest`, so they are comparable to each other even
/// though neither is comparable to the ref intent's `GitOid` positions -- see the
/// non-claim on `check_parts_describe_one_merge`. Within the one domain, an
/// event whose new tip is not the merge commit it names is an event about some
/// other commit.
#[test]
fn an_event_whose_merge_commit_is_not_its_new_tip_is_refused_before_sealing() {
    let context = context();
    let closure = closure();
    let attempt = attempt();
    let mut scrambled = package_with_event(1);
    let ForgeEventPayload::MergeCommitted {
        target_tip_after, ..
    } = &mut scrambled.event.payload
    else {
        panic!("the fixture event is a merge commit")
    };
    *target_tip_after = digest(0x52);

    let refusal = seal_attempt_for(&context, &sealed(&scrambled, &attempt, &closure))
        .expect_err("an event whose new tip is not its merge commit must not seal");
    assert!(
        matches!(
            refusal,
            AdmissionError::MergeIncoherent {
                field: "event merge commit"
            }
        ),
        "expected an event-merge-commit incoherence, got {refusal:?}"
    );

    seal_attempt_for(
        &context,
        &sealed(&package_with_event(1), &attempt, &closure),
    )
    .expect("an event whose new tip is its merge commit still seals");
}

/// An event claiming the target ended where it started.
///
/// A merge that does not move its target is not a merge, and an event asserting
/// it would let a `MergeCommitted` be published against a ref nothing moved.
#[test]
fn an_event_whose_target_does_not_move_is_refused_before_sealing() {
    let context = context();
    let closure = closure();
    let attempt = attempt();
    let mut motionless = package_with_event(1);
    let ForgeEventPayload::MergeCommitted {
        merge_commit,
        target_tip_before,
        target_tip_after,
        ..
    } = &mut motionless.event.payload
    else {
        panic!("the fixture event is a merge commit")
    };
    // Moved together, so the refusal under test is the equal-tips one rather
    // than the merge-commit one that runs before it.
    *target_tip_before = digest(0x51);
    *target_tip_after = digest(0x51);
    *merge_commit = digest(0x51);

    let refusal = seal_attempt_for(&context, &sealed(&motionless, &attempt, &closure))
        .expect_err("an event whose target does not move must not seal");
    assert!(
        matches!(
            refusal,
            AdmissionError::MergeIncoherent {
                field: "event target tips"
            }
        ),
        "expected an event-target-tips incoherence, got {refusal:?}"
    );

    seal_attempt_for(
        &context,
        &sealed(&package_with_event(1), &attempt, &closure),
    )
    .expect("an event whose target actually moves still seals");
}

/// A package whose forge event is not a merge at all.
///
/// The four checks above all destructure `MergeCommitted`. Without this one, an
/// event of another kind would skip every one of them: a `MergeEffectPackage`
/// carrying `PullRequestClosed` would seal, and the record would name a forge
/// batch that never says the merge happened.
#[test]
fn a_package_whose_event_is_not_a_merge_is_refused_before_sealing() {
    let context = context();
    let closure = closure();
    let attempt = attempt();
    let mut closed = package_with_event(1);
    closed.event.payload = ForgeEventPayload::PullRequestClosed { withdrawn: true };

    let refusal = seal_attempt_for(&context, &sealed(&closed, &attempt, &closure))
        .expect_err("a package carrying a non-merge event must not seal");
    assert!(
        matches!(
            refusal,
            AdmissionError::MergeIncoherent {
                field: "forge event kind"
            }
        ),
        "expected a forge-event-kind incoherence, got {refusal:?}"
    );

    seal_attempt_for(
        &context,
        &sealed(&package_with_event(1), &attempt, &closure),
    )
    .expect("a package carrying a merge event still seals");
}

/// A closure whose root is not the root of its own objects.
///
/// Containment says the package's objects are IN the list. It says nothing about
/// whether the root travelling with that list is the root OF that list, and the
/// merge path took the caller's word for it while the common admission path
/// recomputed. A merge admitted under a mismatched root would move the ref and
/// publish an `object_closure_root` naming a closure nothing can resolve.
#[test]
fn a_closure_root_that_does_not_match_its_objects_is_refused_before_sealing() {
    let context = context();
    let attempt = attempt();
    let package = package_with_event(1);
    let honest = closure();
    let forged = ValidatedClosure {
        object_closure_root: digest(0x77),
        objects: honest.objects.clone(),
    };

    // The drill is only meaningful if the asserted root really is wrong.
    assert_ne!(
        forged.object_closure_root, honest.object_closure_root,
        "the forged root must differ from the real one"
    );

    let refusal = seal_attempt_for(&context, &sealed(&package, &attempt, &forged))
        .expect_err("a closure whose root is not its own must not seal");
    assert!(
        matches!(
            refusal,
            AdmissionError::MergeIncoherent {
                field: "object closure root"
            }
        ),
        "expected an object-closure-root incoherence, got {refusal:?}"
    );

    // The permitted twin: the same objects under the root they actually hash to.
    seal_attempt_for(&context, &sealed(&package, &attempt, &honest))
        .expect("a closure under its own root seals");
}
