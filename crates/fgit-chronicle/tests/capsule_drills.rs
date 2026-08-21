//! Destructive capsule drills: every fixture reaches one typed classification.
//!
//! FG-010b. The fixtures here are damage, not malformed input — each one is a
//! capsule that a naive restore could plausibly accept. What is asserted is
//! that damage classifies precisely, that "recoverable-with-repair" is never
//! claimed without material behind it, and that no fixture reaches a state
//! restore invented.
//!
//! Every refusal is paired with the nearest case that must still succeed, so a
//! classifier that failed everything could not pass this suite.

use fgit_chronicle::{
    AuditedRestore, BackupProfile, CapsuleDefect, CapsulePointer, CapsuleVerification, HaltReason,
    MAX_REPORTED_DEFECTS, RecoveryPlan, RepositoryCapsuleBody, RestoreClassification,
    RestoreOutcome, capsule_identity, plan_recovery,
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
        DigestAlgorithmId::try_new(1).expect("code point one is valid"),
        DigestBytes::try_new(&[tag; 32]).expect("thirty-two bytes is a valid digest"),
    )
}

fn head_id(tag: u8) -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(1).expect("code point one is valid"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 32]).expect("thirty-two bytes is a valid digest"),
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

fn capsule_with(
    value: u64,
    predecessor: Option<RepositoryCapsuleId>,
    profile: BackupProfile,
) -> RepositoryCapsuleBody {
    RepositoryCapsuleBody::at_head(
        head_id(u8::try_from(value).unwrap_or(0xF0)),
        &head_at(value),
        predecessor,
        digest(0x20),
        digest(0x21),
        profile,
    )
}

fn identity_of(capsule: &RepositoryCapsuleBody) -> RepositoryCapsuleId {
    capsule_identity(&CryptoBodyIdentity, capsule).expect("a capsule has an identity")
}

// --- the four destructive fixtures ------------------------------------------

fn missing_body() -> CapsuleDefect {
    CapsuleDefect::ObjectBodyMissing {
        closure_root: digest(0x20),
        missing: 3,
    }
}

const fn truncated_segment() -> CapsuleDefect {
    CapsuleDefect::SegmentTruncated {
        declared_len: 4096,
        observed_len: 1200,
    }
}

fn corrupt_manifest() -> CapsuleDefect {
    CapsuleDefect::SegmentManifestCorrupt {
        declared: digest(0x21),
        observed: digest(0x2f),
    }
}

fn stale_predecessor() -> CapsuleDefect {
    CapsuleDefect::PredecessorStale {
        named: None,
        expected: Some(identity_of(&capsule_with(
            3,
            None,
            BackupProfile::FullClosure,
        ))),
    }
}

// --- acceptance line 1: typed classification plus an NDJSON receipt ---------

#[test]
fn an_undamaged_capsule_is_restorable_and_verifies() {
    // The permitted twin for every refusal below.
    let capsule = capsule_with(7, None, BackupProfile::FullClosure);
    let verdict = RestoreClassification::classify(&capsule, &[]);

    assert_eq!(verdict.outcome(), RestoreOutcome::Restorable);
    assert_eq!(verdict.defects(), &[]);
    assert_eq!(verdict.verification(), CapsuleVerification::Verified);
    assert_eq!(
        verdict.to_ndjson_line(),
        r#"{"outcome":"restorable","profile":"full_closure","defect_count":0,"truncated":false,"defects":[]}"#
    );
}

#[test]
fn every_destructive_fixture_reaches_its_expected_classification() {
    // The fixture matrix. Each row is (defect, profile, expected outcome), and
    // the pairing is the point: the SAME defect classifies differently
    // depending on whether repair material exists, and the two unrepairable
    // defects classify the same way under every profile.
    let cases: &[(CapsuleDefect, BackupProfile, RestoreOutcome)] = &[
        // Reconstructible damage, with repair material declared.
        (
            missing_body(),
            BackupProfile::FullClosureWithRepair,
            RestoreOutcome::RecoverableWithRepair,
        ),
        (
            truncated_segment(),
            BackupProfile::FullClosureWithRepair,
            RestoreOutcome::RecoverableWithRepair,
        ),
        (
            corrupt_manifest(),
            BackupProfile::FullClosureWithRepair,
            RestoreOutcome::RecoverableWithRepair,
        ),
        // The same damage with nothing to repair from.
        (
            missing_body(),
            BackupProfile::FullClosure,
            RestoreOutcome::FailClosed,
        ),
        (
            missing_body(),
            BackupProfile::DecisionHistoryOnly,
            RestoreOutcome::FailClosed,
        ),
        (
            truncated_segment(),
            BackupProfile::FullClosure,
            RestoreOutcome::FailClosed,
        ),
        (
            corrupt_manifest(),
            BackupProfile::FullClosure,
            RestoreOutcome::FailClosed,
        ),
        // Unrepairable damage: repair material must not rescue it.
        (
            stale_predecessor(),
            BackupProfile::FullClosureWithRepair,
            RestoreOutcome::FailClosed,
        ),
        (
            stale_predecessor(),
            BackupProfile::FullClosure,
            RestoreOutcome::FailClosed,
        ),
    ];

    let mut receipts = Vec::new();
    for (defect, profile, expected) in cases {
        let capsule = capsule_with(7, None, *profile);
        let verdict = RestoreClassification::classify(&capsule, &[*defect]);

        assert_eq!(
            verdict.outcome(),
            *expected,
            "{} under {}",
            defect.as_str(),
            profile.as_str()
        );
        assert_eq!(verdict.defects(), &[*defect], "the defect is reported");
        assert!(!verdict.truncated());

        // Acceptance line 1: every fixture emits a receipt.
        let line = verdict.to_ndjson_line();
        assert!(line.starts_with('{') && line.ends_with('}'));
        assert!(line.contains(defect.as_str()));
        assert!(line.contains(expected.as_str()));
        receipts.push(line);
    }

    assert_eq!(receipts.len(), cases.len(), "one receipt per fixture");
}

#[test]
fn an_identity_mismatch_is_never_repairable_under_any_profile() {
    // Separated from the matrix because it is the sharpest case: the capsule
    // is not damaged, it is lying about which checkpoint it is. Repair symbols
    // rebuild bytes; they cannot make this capsule be the one it claims.
    let authentic = capsule_with(7, None, BackupProfile::FullClosureWithRepair);
    let other = capsule_with(3, None, BackupProfile::FullClosureWithRepair);
    let defect = CapsuleDefect::IdentityMismatch {
        declared: identity_of(&other),
        recomputed: identity_of(&authentic),
    };

    assert!(!defect.is_reconstructible());
    for profile in [
        BackupProfile::DecisionHistoryOnly,
        BackupProfile::FullClosure,
        BackupProfile::FullClosureWithRepair,
    ] {
        let capsule = capsule_with(7, None, profile);
        assert_eq!(
            RestoreClassification::classify(&capsule, &[defect]).outcome(),
            RestoreOutcome::FailClosed,
            "identity mismatch must fail closed under {}",
            profile.as_str()
        );
    }
}

#[test]
fn one_unrepairable_defect_poisons_an_otherwise_reconstructible_set() {
    // The mixed case, which is where a classifier written as "any repairable?"
    // rather than "all repairable?" would silently go wrong.
    let capsule = capsule_with(7, None, BackupProfile::FullClosureWithRepair);

    let reconstructible = [missing_body(), truncated_segment()];
    assert_eq!(
        RestoreClassification::classify(&capsule, &reconstructible).outcome(),
        RestoreOutcome::RecoverableWithRepair,
        "the all-reconstructible set must still be repairable, or the case below is vacuous"
    );

    let poisoned = [missing_body(), truncated_segment(), stale_predecessor()];
    assert_eq!(
        RestoreClassification::classify(&capsule, &poisoned).outcome(),
        RestoreOutcome::FailClosed
    );
}

#[test]
fn a_truncated_defect_list_never_looks_cleaner_than_the_damage() {
    // Past the reporting bound the list is cut, but the VERDICT is still
    // judged over everything found. A report that dropped the unrepairable
    // defect and then called the capsule repairable would be the worst
    // possible failure of this module.
    let capsule = capsule_with(7, None, BackupProfile::FullClosureWithRepair);
    let mut found: Vec<CapsuleDefect> = (0..MAX_REPORTED_DEFECTS)
        .map(|index| CapsuleDefect::SegmentTruncated {
            declared_len: 4096,
            observed_len: index as u64,
        })
        .collect();
    found.push(stale_predecessor());

    let verdict = RestoreClassification::classify(&capsule, &found);

    assert!(verdict.truncated(), "the list was cut");
    assert_eq!(verdict.defects().len(), MAX_REPORTED_DEFECTS);
    assert!(
        !verdict.defects().contains(&stale_predecessor()),
        "the poisoning defect is outside the reported window, which is the trap"
    );
    assert_eq!(
        verdict.outcome(),
        RestoreOutcome::FailClosed,
        "the verdict must still reflect the defect the report could not fit"
    );
    assert!(verdict.to_ndjson_line().contains("\"truncated\":true"));
}

#[test]
fn a_receipt_is_byte_identical_across_runs() {
    // NDJSON is evidence, so two runs over one fixture must produce one line.
    let capsule = capsule_with(7, None, BackupProfile::FullClosureWithRepair);
    let found = [truncated_segment(), missing_body(), corrupt_manifest()];

    let first = RestoreClassification::classify(&capsule, &found).to_ndjson_line();
    let second = RestoreClassification::classify(&capsule, &found).to_ndjson_line();
    assert_eq!(first, second);

    // And input ordering must not change it: the defect list is sorted, so a
    // scanner that happened to find the same damage in another order emits the
    // same receipt.
    let reordered = [missing_body(), corrupt_manifest(), truncated_segment()];
    assert_eq!(
        RestoreClassification::classify(&capsule, &reordered).to_ndjson_line(),
        first
    );
}

// --- acceptance line 2: the masquerade drill --------------------------------

#[test]
fn the_masquerade_drill_fails_closed_and_preserves_both_capsules() {
    // A valid OLDER capsule sits behind a newer acknowledged one that does not
    // verify. The older will check out perfectly — it was valid when written —
    // which is exactly why an automatic retreat to it would come up looking
    // healthy having discarded every decision since.
    let older = capsule_with(3, None, BackupProfile::FullClosure);
    let older_id = identity_of(&older);
    let newer = capsule_with(7, Some(older_id), BackupProfile::FullClosureWithRepair);
    let newer_id = identity_of(&newer);
    let pointer = CapsulePointer::genesis(older_id, &older)
        .expect("a first capsule points")
        .advance(newer_id, &newer)
        .expect("the successor advances");

    // The older capsule genuinely verifies. This is the masquerade: it is not
    // damaged, it is just stale.
    assert_eq!(
        RestoreClassification::classify(&older, &[]).outcome(),
        RestoreOutcome::Restorable
    );

    // The acknowledged newer one does not, and declares repair material, so
    // this is the most tempting possible case for automation to "handle".
    let newer_verdict = RestoreClassification::classify(&newer, &[missing_body()]);
    assert_eq!(
        newer_verdict.outcome(),
        RestoreOutcome::RecoverableWithRepair
    );

    // Automation still halts, and the halt names the acknowledged capsule.
    let plan = plan_recovery(&pointer, newer_verdict.verification());
    assert_eq!(
        plan,
        RecoveryPlan::HaltForAudit {
            acknowledged: Some(newer_id),
            reason: HaltReason::AcknowledgedRootUnverified,
        },
        "recoverable-with-repair must not become an automatic path"
    );

    // Both capsules are preserved: the pointer still names the newer one, and
    // the older is still addressable and still valid. Nothing was discarded to
    // make recovery look tidy.
    assert_eq!(pointer.capsule_id(), newer_id);
    assert_eq!(pointer.head_generation(), generation(7));
    assert_ne!(older_id, newer_id);
    assert_eq!(
        RestoreClassification::classify(&older, &[]).outcome(),
        RestoreOutcome::Restorable,
        "the older capsule is untouched by the failed newer one"
    );
}

#[test]
fn retreating_to_the_older_capsule_requires_an_audited_generation_advance() {
    // The only way to the older capsule, and it is a person's decision on the
    // record. Paired: the rollback attempt is refused, the advancing restore
    // is allowed.
    let older = capsule_with(3, None, BackupProfile::FullClosure);
    let older_id = identity_of(&older);
    let newer = capsule_with(7, Some(older_id), BackupProfile::FullClosure);
    let newer_id = identity_of(&newer);
    let pointer = CapsulePointer::genesis(older_id, &older)
        .expect("a first capsule points")
        .advance(newer_id, &newer)
        .expect("the successor advances");
    let plan = plan_recovery(&pointer, CapsuleVerification::PresentButUnverified);

    // Re-entering a generation the repository already left is a rollback.
    assert!(
        AuditedRestore::authorize(
            &pointer,
            plan,
            operator(),
            older_id,
            generation(3),
            generation(7)
        )
        .is_err(),
        "a restore that does not advance the generation is a rollback"
    );

    // Moving forward to a position carrying older content is a restore.
    let restore = AuditedRestore::authorize(
        &pointer,
        plan,
        operator(),
        older_id,
        generation(3),
        generation(8),
    )
    .expect("advancing past the abandoned position is a restore");
    assert_eq!(restore.restored_to(), older_id);
}
