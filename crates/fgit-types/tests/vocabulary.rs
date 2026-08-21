// Closed vocabularies: stable code points, no collisions, no silent fallback
// for an unknown member, and the pre-seal/post-seal split.

use std::collections::BTreeSet;

use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::identity::{RefusalRecordId, RepositoryCommitId};
use fgit_types::vocabulary::{
    DecisionOutcome, MismatchPolicy, PublicationEpoch, RefusalCode, RequestRejectionCode,
};
use fgit_types::{CANONICAL_CODEC_VERSION, TypeRefusal};

#[test]
fn refusal_codes_have_unique_code_points_and_names() {
    let points: BTreeSet<u16> = RefusalCode::ALL
        .iter()
        .map(|code| code.code_point())
        .collect();
    assert_eq!(points.len(), RefusalCode::ALL.len(), "duplicate code point");
    let names: BTreeSet<&str> = RefusalCode::ALL.iter().map(|code| code.as_str()).collect();
    assert_eq!(names.len(), RefusalCode::ALL.len(), "duplicate wire name");
}

#[test]
fn every_refusal_code_round_trips_through_its_code_point() {
    for code in RefusalCode::ALL {
        let recovered =
            RefusalCode::from_code_point(code.code_point()).expect("every member round trips");
        assert_eq!(
            recovered,
            *code,
            "code point {} lost its member",
            code.code_point()
        );
    }
}

#[test]
fn an_unknown_refusal_code_point_is_refused_rather_than_defaulted() {
    // 0x0300 is outside both allocated ranges.
    let refusal = RefusalCode::from_code_point(0x0300)
        .expect_err("a newer peer's code must not be reinterpreted as an existing one");
    assert_eq!(
        refusal,
        TypeRefusal::CodePointUnknown {
            field: "RefusalCode",
            observed: 0x0300,
        }
    );
    // Permitted counterpart: the highest allocated code point still resolves.
    assert!(RefusalCode::from_code_point(0x021d).is_ok());
}

#[test]
fn the_two_ranges_split_agent_protocol_from_ref_transaction_dimensions() {
    let agent = RefusalCode::ALL
        .iter()
        .filter(|code| code.is_agent_protocol_dimension())
        .count();
    let ref_txn = RefusalCode::ALL.len() - agent;
    assert_eq!(agent, 30, "the agent-protocol taxonomy has thirty members");
    assert_eq!(
        ref_txn, 29,
        "the ref-transaction and admission dimensions have twenty-nine members"
    );
    assert!(RefusalCode::IntentExpired.is_agent_protocol_dimension());
    assert!(!RefusalCode::ExpectedOldRefMismatch.is_agent_protocol_dimension());
}

#[test]
fn a_sealed_transaction_has_exactly_two_terminal_shapes() {
    // The exhaustive match is the real assertion: adding a third terminal
    // outcome (a `Cancelled` variant, say) stops this test compiling, which is
    // the point. Cancellation before publication leaves a sealed transaction
    // undecided and retryable; it is not a decision.
    let outcomes = [
        DecisionOutcome::Committed {
            repository_commit_id: commit_id(),
        },
        DecisionOutcome::Refused {
            code: RefusalCode::PublicationPolicyRefused,
            refusal_record_id: refusal_record_id(),
        },
    ];
    let mut seen_committed = false;
    let mut seen_refused = false;
    for outcome in outcomes {
        match outcome {
            DecisionOutcome::Committed { .. } => seen_committed = true,
            DecisionOutcome::Refused { .. } => seen_refused = true,
        }
    }
    assert!(seen_committed && seen_refused);
    assert!(
        !RefusalCode::ALL
            .iter()
            .any(|code| code.as_str() == "Cancelled"),
        "there is no cancelled refusal member"
    );
}

#[test]
fn request_rejections_and_transaction_refusals_are_separate_vocabularies() {
    let rejection_points: BTreeSet<u16> = RequestRejectionCode::ALL
        .iter()
        .map(|code| code.code_point())
        .collect();
    let refusal_points: BTreeSet<u16> = RefusalCode::ALL
        .iter()
        .map(|code| code.code_point())
        .collect();
    assert!(
        rejection_points.is_disjoint(&refusal_points),
        "a pre-seal rejection code must never decode as a terminal refusal"
    );
    for code in RequestRejectionCode::ALL {
        assert_eq!(
            RequestRejectionCode::from_code_point(code.code_point()).expect("round trip"),
            *code
        );
        assert!(
            RefusalCode::from_code_point(code.code_point()).is_err(),
            "rejection code {} must not resolve in the refusal vocabulary",
            code.as_str()
        );
    }
}

#[test]
fn idempotency_key_reuse_is_a_rejection_not_a_refusal() {
    // It happens before a seal exists, so it is not repository history.
    assert!(
        RequestRejectionCode::ALL.contains(&RequestRejectionCode::IdempotencyKeyReuse),
        "the reuse rejection lives in the pre-seal vocabulary"
    );
    assert!(
        !RefusalCode::ALL
            .iter()
            .any(|code| code.as_str() == "IdempotencyKeyReuse"),
        "the reuse rejection must not also exist as a terminal refusal"
    );
}

fn commit_id() -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        DigestAlgorithmId::try_new(1).expect("valid slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[0x01; 32]).expect("valid digest"),
    )
}

fn refusal_record_id() -> RefusalRecordId {
    RefusalRecordId::from_digest(
        DigestAlgorithmId::try_new(1).expect("valid slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[0x02; 32]).expect("valid digest"),
    )
}

#[test]
fn only_a_commit_advances_repository_sequence() {
    let committed = DecisionOutcome::Committed {
        repository_commit_id: commit_id(),
    };
    let refused = DecisionOutcome::Refused {
        code: RefusalCode::ExpectedOldRefMismatch,
        refusal_record_id: refusal_record_id(),
    };
    assert!(committed.advances_repository_sequence());
    assert!(
        !refused.advances_repository_sequence(),
        "a refusal consumes decision sequence but never repository sequence"
    );
    assert_ne!(committed.discriminant(), refused.discriminant());
}

#[test]
fn mismatch_policy_and_publication_epoch_round_trip() {
    for policy in MismatchPolicy::ALL {
        assert_eq!(
            MismatchPolicy::from_code_point(policy.code_point()).expect("round trip"),
            *policy
        );
    }
    assert!(MismatchPolicy::from_code_point(0).is_err());

    for epoch in PublicationEpoch::ALL {
        assert_eq!(
            PublicationEpoch::from_code_point(epoch.code_point()).expect("round trip"),
            *epoch
        );
    }
    assert!(PublicationEpoch::from_code_point(4).is_err());
    // Staged, visible, and durable stay ordered and distinct.
    assert!(PublicationEpoch::Staged < PublicationEpoch::Visible);
    assert!(PublicationEpoch::Visible < PublicationEpoch::Durable);
}

#[test]
fn every_construction_refusal_maps_to_a_live_refusal_code() {
    let samples = [
        TypeRefusal::LengthOutOfRange {
            field: "f",
            observed: 1,
            minimum: 2,
            maximum: 3,
        },
        TypeRefusal::ByteNotPermitted {
            field: "f",
            offset: 0,
            byte: b'!',
        },
        TypeRefusal::ValueOutOfRange {
            field: "f",
            observed: 0,
            minimum: 1,
            maximum: 2,
        },
        TypeRefusal::CodePointUnknown {
            field: "f",
            observed: 7,
        },
        TypeRefusal::DomainMismatch {
            field: "f",
            expected: "frankengit/ref-txn/v2",
        },
        TypeRefusal::HashDomainMismatch {
            expected: fgit_types::native::GitHashAlgorithm::Sha1,
            observed: fgit_types::native::GitHashAlgorithm::Sha256,
        },
        TypeRefusal::DigestLengthMismatch {
            algorithm: DigestAlgorithmId::try_new(1).expect("valid slot"),
            expected: 32,
            observed: 20,
        },
    ];
    for sample in samples {
        let code = sample.refusal_code();
        assert!(
            RefusalCode::ALL.contains(&code),
            "{} mapped to a code outside the vocabulary",
            sample.kind()
        );
        assert!(!sample.to_string().is_empty(), "refusal must be printable");
        assert!(!sample.kind().is_empty());
    }
}
