//! Recovery may not quietly retreat to an older capsule.
//!
//! Section 23's rule is stated as a prohibition, so most of these tests assert
//! what recovery *cannot* produce. The one that matters most is negative in an
//! unusual way: it checks that no input at all makes `plan_recovery` name a
//! capsule other than the acknowledged one, because a silent fallback is not a
//! wrong answer this code could return — it is an answer the type cannot carry.

use fgit_chronicle::{
    AuditedRestore, BackupProfile, CapsulePointer, CapsuleVerification, ChronicleRefusal,
    HaltReason, RecoveryPlan, RepositoryCapsuleBody, capsule_identity, plan_recovery,
};
use fgit_codec::CryptoBodyIdentity;
use fgit_codec::schema::RepositoryAuthorityHeadBody;
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestAlgorithmId, DigestBytes, HeadGeneration, OPAQUE_ID_LEN,
    PolicyEpoch, PrincipalId, RegistryEpoch, RepositoryAuthorityHeadId, RepositoryCapsuleId,
    RepositoryId,
};

fn digest(tag: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("nonzero corpus fixture algorithm slot"),
        DigestBytes::try_new(&[tag; 32]).expect("32-byte corpus fixture body"),
    )
}

fn head_id(tag: u8) -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("nonzero corpus fixture algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 32]).expect("32-byte corpus fixture body"),
    )
}

const fn repository() -> RepositoryId {
    RepositoryId::from_bytes([7; OPAQUE_ID_LEN])
}

const fn operator() -> PrincipalId {
    PrincipalId::from_bytes([9; OPAQUE_ID_LEN])
}

fn generation(value: u64) -> HeadGeneration {
    HeadGeneration::try_new(value).expect("a non-zero generation")
}

fn head_at(value: u64) -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: repository(),
        generation: generation(value),
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: digest(0x10),
        forge_position_root: digest(0x11),
        outcome_index_root: digest(0x12),
        retention_root: digest(0x13),
        outbox_root: digest(0x14),
        configuration_root: digest(0x15),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

fn capsule_at(value: u64, predecessor: Option<RepositoryCapsuleId>) -> RepositoryCapsuleBody {
    RepositoryCapsuleBody::at_head(
        head_id(u8::try_from(value).unwrap_or(0xF0)),
        &head_at(value),
        predecessor,
        digest(0x20),
        digest(0x21),
        BackupProfile::FullClosure,
    )
}

fn identity_of(capsule: &RepositoryCapsuleBody) -> RepositoryCapsuleId {
    capsule_identity(&CryptoBodyIdentity, capsule).expect("a capsule has an identity")
}

/// An older capsule and the newer pointer that superseded it.
fn history() -> (RepositoryCapsuleId, RepositoryCapsuleId, CapsulePointer) {
    let older = capsule_at(3, None);
    let older_id = identity_of(&older);
    let newer = capsule_at(7, Some(older_id));
    let newer_id = identity_of(&newer);
    let pointer = CapsulePointer::genesis(older_id, &older)
        .expect("a first capsule points")
        .advance(newer_id, &newer)
        .expect("the successor advances");
    (older_id, newer_id, pointer)
}

#[test]
fn a_verified_acknowledged_root_simply_resumes() {
    let (_, newer_id, pointer) = history();
    assert_eq!(
        plan_recovery(&pointer, CapsuleVerification::Verified),
        RecoveryPlan::Resume {
            capsule_id: newer_id,
            head_generation: generation(7),
        },
        "when the acknowledged capsule verifies there is nothing to decide"
    );
}

#[test]
fn an_unverified_acknowledged_root_halts_instead_of_retreating() {
    let (older_id, newer_id, pointer) = history();

    let plan = plan_recovery(&pointer, CapsuleVerification::PresentButUnverified);
    assert_eq!(
        plan,
        RecoveryPlan::HaltForAudit {
            acknowledged: Some(newer_id),
            reason: HaltReason::AcknowledgedRootUnverified,
        },
        "a present-but-unverifiable root halts; it does not fall back"
    );

    // The whole point: the plan names the FAILED capsule, never the older one
    // that would still verify. A silent retreat would come up looking healthy
    // while discarding every decision made since.
    match plan {
        RecoveryPlan::HaltForAudit { acknowledged, .. } => {
            assert_ne!(
                acknowledged,
                Some(older_id),
                "recovery must never nominate the older capsule on its own"
            );
        }
        RecoveryPlan::Resume { .. } => panic!("an unverified root must not resume"),
    }
}

#[test]
fn an_absent_acknowledged_root_also_halts() {
    let (older_id, _, pointer) = history();
    let plan = plan_recovery(&pointer, CapsuleVerification::Absent);
    assert_eq!(
        plan,
        RecoveryPlan::HaltForAudit {
            acknowledged: None,
            reason: HaltReason::AcknowledgedRootAbsent,
        }
    );
    match plan {
        RecoveryPlan::HaltForAudit { acknowledged, .. } => assert_ne!(
            acknowledged,
            Some(older_id),
            "an absent root is still not permission to use the older capsule"
        ),
        RecoveryPlan::Resume { .. } => panic!("an absent root must not resume"),
    }
}

#[test]
fn no_verification_verdict_lets_recovery_name_an_older_capsule() {
    // Exhaustive over the verdict vocabulary: whatever the input, the plan
    // either resumes the acknowledged capsule or halts. There is no third
    // shape, so a silent fallback is unrepresentable rather than merely absent.
    let (older_id, newer_id, pointer) = history();
    for verdict in [
        CapsuleVerification::Verified,
        CapsuleVerification::PresentButUnverified,
        CapsuleVerification::Absent,
    ] {
        match plan_recovery(&pointer, verdict) {
            RecoveryPlan::Resume { capsule_id, .. } => assert_eq!(
                capsule_id, newer_id,
                "resume only ever names the acknowledged capsule"
            ),
            RecoveryPlan::HaltForAudit { acknowledged, .. } => assert_ne!(
                acknowledged,
                Some(older_id),
                "halting never nominates an older capsule"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// The sanctioned escape hatch, and its guards
// ---------------------------------------------------------------------------

#[test]
fn an_audited_restore_records_who_abandoned_what() {
    let (older_id, newer_id, pointer) = history();
    let plan = plan_recovery(&pointer, CapsuleVerification::PresentButUnverified);

    let restore = AuditedRestore::authorize(
        &pointer,
        plan,
        operator(),
        older_id,
        generation(3),
        generation(8),
    )
    .expect("a restore that advances the generation is permitted");

    assert_eq!(restore.authorized_by(), operator());
    assert_eq!(
        restore.abandoned(),
        Some(newer_id),
        "the record names the position that was given up"
    );
    assert_eq!(restore.restored_to(), older_id);
    assert_eq!(
        restore.restored_from_generation(),
        generation(3),
        "the record keeps how far back the content came from"
    );
    assert_eq!(
        restore.new_generation(),
        generation(8),
        "and where the authority sits afterwards"
    );
}

#[test]
fn a_restore_that_does_not_advance_the_generation_is_refused() {
    let (older_id, _, pointer) = history();
    let plan = plan_recovery(&pointer, CapsuleVerification::PresentButUnverified);

    // Planted negative: re-enter the abandoned generation.
    assert_eq!(
        AuditedRestore::authorize(
            &pointer,
            plan,
            operator(),
            older_id,
            generation(3),
            generation(7),
        ),
        Err(ChronicleRefusal::RestoreDoesNotAdvance {
            abandoned: generation(7),
            proposed: generation(7),
        }),
        "re-entering the abandoned generation would make the rewind invisible"
    );

    // Planted negative: move backwards outright.
    assert!(matches!(
        AuditedRestore::authorize(
            &pointer,
            plan,
            operator(),
            older_id,
            generation(3),
            generation(4),
        ),
        Err(ChronicleRefusal::RestoreDoesNotAdvance { .. })
    ));

    // Near-identical permitted case: one generation past the abandoned one.
    assert!(
        AuditedRestore::authorize(
            &pointer,
            plan,
            operator(),
            older_id,
            generation(3),
            generation(8),
        )
        .is_ok(),
        "a restore that moves the authority forward is permitted"
    );
}

#[test]
fn a_restore_cannot_override_a_recovery_that_was_fine() {
    let (older_id, _, pointer) = history();
    let healthy = plan_recovery(&pointer, CapsuleVerification::Verified);

    // Planted negative: authorize a restore when nothing had failed. Without
    // this guard an operator could discard live history while the repository
    // was perfectly healthy.
    assert_eq!(
        AuditedRestore::authorize(
            &pointer,
            healthy,
            operator(),
            older_id,
            generation(3),
            generation(9),
        ),
        Err(ChronicleRefusal::RestoreNotHalted),
        "a restore overrides a halt, not a working repository"
    );

    // Near-identical permitted case: the same restore once recovery has halted.
    let halted = plan_recovery(&pointer, CapsuleVerification::PresentButUnverified);
    assert!(
        AuditedRestore::authorize(
            &pointer,
            halted,
            operator(),
            older_id,
            generation(3),
            generation(9),
        )
        .is_ok()
    );
}

// Non-production fixture identity: this reserved tag deliberately has no registered digest width.
const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;
const _: () = assert!(FIXTURE_ALGORITHM_CODE_POINT >= 0xfff0);
