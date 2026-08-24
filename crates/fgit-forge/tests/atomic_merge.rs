//! Evidence for FG-029a's three acceptance conditions.
//!
//! Every forbidden case is paired with the near-identical permitted case, so
//! the tests show where the boundary is rather than only that a wall exists.

use fgit_codec::CryptoBodyIdentity;
use fgit_codec::schema::RepositoryCommitRecord;
use fgit_codec::wire::CanonicalBody;
use fgit_codec::{CodecRefusal, DecodeLimits, decode_body, encode_body};
use fgit_diff::{TreeEntry, TreeMergeOptions};
use fgit_forge::event::ForgeEventBatch;
use fgit_forge::merge::RecordFrame;
use fgit_forge::{
    AggregateHead, AggregateVersion, ExpectedVersion, ForgeEvent, ForgeEventPayload, ForgeRefusal,
    MergeAttempt, MergeEffectPackage, MergeSide, ObservedTips, PullRequestNumber, RefIntent,
    StaleTips, merge_pull_request_tree,
};
use fgit_treefs::WorkspaceEpoch;
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestAlgorithmId, DigestBytes, OPAQUE_ID_LEN, PolicyEpoch,
    PrincipalSnapshotId, RepositoryId, RepositorySequence, TxId,
};

const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;
const _: () = assert!(FIXTURE_ALGORITHM_CODE_POINT >= 0xfff0);

fn digest(tag: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("nonzero corpus fixture algorithm slot"),
        DigestBytes::try_new(&[tag; 32]).expect("32-byte corpus fixture body"),
    )
}

macro_rules! derived {
    ($ty:ty, $tag:expr) => {
        <$ty>::from_digest(
            DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
                .expect("nonzero corpus fixture algorithm slot"),
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[$tag; 32]).expect("32-byte corpus fixture body"),
        )
    };
}

const fn pull_request() -> PullRequestNumber {
    match PullRequestNumber::try_new(41) {
        Some(number) => number,
        None => panic!("41 is nonzero"),
    }
}

fn merge_event() -> ForgeEvent {
    ForgeEvent {
        pull_request: pull_request(),
        version: AggregateVersion::try_new(4).expect("a nonzero version"),
        payload: ForgeEventPayload::MergeCommitted {
            merge_commit: digest(0x51),
            target_ref: b"refs/heads/main".to_vec(),
            target_tip_before: digest(0x40),
            target_tip_after: digest(0x51),
        },
    }
}

fn ref_intent() -> RefIntent {
    RefIntent {
        name: b"refs/heads/main".to_vec(),
        expected_tip: digest(0x40),
        new_tip: digest(0x51),
    }
}

fn package() -> MergeEffectPackage {
    MergeEffectPackage {
        objects: vec![digest(0x51), digest(0x52)],
        ref_intent: ref_intent(),
        event: merge_event(),
    }
}

/// Every root the frame supplies is distinct and distinguishable, so a record
/// field that silently took a neighbour's value would show up as equality.
fn frame() -> RecordFrame {
    RecordFrame {
        repository_id: RepositoryId::from_bytes([7; OPAQUE_ID_LEN]),
        repository_sequence: RepositorySequence::FIRST,
        parent_rcr_id: None,
        tx_id: derived!(TxId, 0x60),
        principal_snapshot_id: derived!(PrincipalSnapshotId, 0x61),
        canonical_request_digest: digest(0x62),
        resulting_ref_root: digest(0x63),
        object_closure_root: digest(0x64),
        resulting_forge_position_root: digest(0x65),
        policy_epoch: PolicyEpoch::FIRST,
        policy_decision_root: digest(0x66),
        invariant_evidence_root: digest(0x67),
        outbox_effect_root: digest(0x68),
        retention_delta_root: digest(0x69),
    }
}

fn seal(package: &MergeEffectPackage) -> RepositoryCommitRecord {
    package
        .seal_into_record(&CryptoBodyIdentity, frame())
        .expect("a well formed package seals")
}

// ------------------------------------------------- acceptance (1): one record

/// The merge RCR carries BOTH the ref delta and the `MergeCommitted` event.
///
/// Asserting only that the two fields are populated would pass on a record that
/// stamped the same digest into both, or that copied a neighbouring root. So
/// the check is that each root equals the identity of the body it is supposed
/// to commit to, that the two differ from each other, and that neither collides
/// with any other root on the record.
#[test]
fn the_merge_record_carries_the_ref_delta_and_the_event_together() {
    let package = package();
    let roots = package
        .roots(&CryptoBodyIdentity)
        .expect("both bodies have identities");
    let record = seal(&package);

    assert_eq!(record.ref_delta_root, roots.ref_delta_root);
    assert_eq!(record.forge_event_batch_root, roots.forge_event_batch_root);
    assert_ne!(
        record.ref_delta_root, record.forge_event_batch_root,
        "two different bodies must not commit to the same root"
    );

    // The two roots this crate produces are not any of the roots the frame
    // supplied, so neither field is a copy of a neighbour.
    for supplied in [
        record.resulting_ref_root,
        record.object_closure_root,
        record.resulting_forge_position_root,
        record.policy_decision_root,
        record.invariant_evidence_root,
        record.outbox_effect_root,
        record.retention_delta_root,
        record.canonical_request_digest,
    ] {
        assert_ne!(record.ref_delta_root, supplied);
        assert_ne!(record.forge_event_batch_root, supplied);
    }
}

/// The two roots are independently load-bearing.
///
/// This is the test that would fail if `seal_into_record` derived one root and
/// reused it, or if the event were left out of the batch that gets hashed.
/// Changing the event must move the event root and leave the ref root alone,
/// and changing the ref intent must do the reverse.
#[test]
fn each_root_moves_only_for_its_own_body() {
    let baseline = seal(&package());

    let mut altered_event = package();
    altered_event.event.version = AggregateVersion::try_new(5).expect("a nonzero version");
    let altered_event = seal(&altered_event);
    assert_ne!(
        baseline.forge_event_batch_root, altered_event.forge_event_batch_root,
        "a different event must produce a different event root"
    );
    assert_eq!(
        baseline.ref_delta_root, altered_event.ref_delta_root,
        "changing the event must not disturb the ref delta root"
    );

    let mut altered_ref = package();
    altered_ref.ref_intent.new_tip = digest(0x7a);
    let altered_ref = seal(&altered_ref);
    assert_ne!(
        baseline.ref_delta_root, altered_ref.ref_delta_root,
        "a different ref intent must produce a different ref delta root"
    );
    assert_eq!(
        baseline.forge_event_batch_root, altered_ref.forge_event_batch_root,
        "changing the ref intent must not disturb the event root"
    );
}

// ------------------------------- acceptance (2): typed version admission

#[test]
fn an_aggregate_write_against_the_wrong_version_is_refused_and_the_right_one_proceeds() {
    let at_seven = AggregateHead::at(
        pull_request(),
        AggregateVersion::try_new(7).expect("a nonzero version"),
    );

    // Forbidden: the caller believes the stream is at 6 when it is at 7. This
    // is the case that must never be resolved by taking the later write.
    assert_eq!(
        at_seven.admit(ExpectedVersion::Exactly(
            AggregateVersion::try_new(6).expect("a nonzero version")
        )),
        Err(ForgeRefusal::VersionConflict {
            expected: ExpectedVersion::Exactly(
                AggregateVersion::try_new(6).expect("a nonzero version")
            ),
            observed: Some(AggregateVersion::try_new(7).expect("a nonzero version")),
        })
    );

    // Permitted twin: the same call one version later.
    assert_eq!(
        at_seven.admit(ExpectedVersion::Exactly(
            AggregateVersion::try_new(7).expect("a nonzero version")
        )),
        Ok(AggregateVersion::try_new(8).expect("a nonzero version")),
        "admission returns the version the new event will carry"
    );
}

/// `NewStream` and `Exactly(FIRST)` are different assertions, and collapsing
/// them would let a create silently append to a stream that already existed.
#[test]
fn creating_an_aggregate_that_already_exists_is_refused_and_an_empty_one_is_not() {
    let existing = AggregateHead::at(pull_request(), AggregateVersion::FIRST);
    assert_eq!(
        existing.admit(ExpectedVersion::NewStream),
        Err(ForgeRefusal::VersionConflict {
            expected: ExpectedVersion::NewStream,
            observed: Some(AggregateVersion::FIRST),
        })
    );

    let fresh = AggregateHead::empty(pull_request());
    assert_eq!(
        fresh.admit(ExpectedVersion::NewStream),
        Ok(AggregateVersion::FIRST)
    );

    // And the mirror: an empty stream is not at any version, so an exact
    // expectation against it is a conflict rather than a silent create.
    assert_eq!(
        fresh.admit(ExpectedVersion::Exactly(AggregateVersion::FIRST)),
        Err(ForgeRefusal::VersionConflict {
            expected: ExpectedVersion::Exactly(AggregateVersion::FIRST),
            observed: None,
        })
    );
}

// --------------------------------------- staleness on both sides of the merge

fn attempt() -> MergeAttempt {
    MergeAttempt {
        pull_request: pull_request(),
        source_ref: b"refs/heads/feature".to_vec(),
        target_ref: b"refs/heads/main".to_vec(),
        source_tip: digest(0x30),
        target_tip: digest(0x40),
        base_tip: digest(0x20),
        workspace_epoch: WorkspaceEpoch::from_u64(9),
    }
}

#[test]
fn a_merge_whose_source_or_target_moved_is_refused_naming_the_side_that_moved() {
    let attempt = attempt();

    // Forbidden, axis one: the source moved.
    assert_eq!(
        attempt.check_fresh(&ObservedTips {
            source_tip: digest(0x31),
            target_tip: digest(0x40),
        }),
        Err(ForgeRefusal::MergeStale {
            reference: MergeSide::Source,
            tips: Box::new(StaleTips {
                computed_against: digest(0x30),
                observed: digest(0x31),
            }),
        })
    );

    // Forbidden, axis two: the target moved. A separate axis, because a merge
    // that is fine on one side and stale on the other is the common case.
    assert_eq!(
        attempt.check_fresh(&ObservedTips {
            source_tip: digest(0x30),
            target_tip: digest(0x41),
        }),
        Err(ForgeRefusal::MergeStale {
            reference: MergeSide::Target,
            tips: Box::new(StaleTips {
                computed_against: digest(0x40),
                observed: digest(0x41),
            }),
        })
    );

    // Permitted twin: neither moved.
    assert_eq!(
        attempt.check_fresh(&ObservedTips {
            source_tip: digest(0x30),
            target_tip: digest(0x40),
        }),
        Ok(())
    );
}

// -------------------------------------------------- conflicts are not merges

fn entry(path: &[u8], object: u8) -> TreeEntry<Digest> {
    TreeEntry {
        path: path.to_vec(),
        mode: fgit_diff::TreeMode(0o100_644),
        object: digest(object),
    }
}

#[test]
fn a_conflicted_merge_is_refused_and_a_clean_one_produces_a_tree() {
    // Forbidden: both sides changed the same path differently.
    let refusal = merge_pull_request_tree(
        [entry(b"a", 0x01)],
        [entry(b"a", 0x02)],
        [entry(b"a", 0x03)],
        TreeMergeOptions::default(),
    );
    assert_eq!(
        refusal,
        Err(ForgeRefusal::MergeConflicted { paths: 1 }),
        "a partially merged tree has no meaning as a commit"
    );

    // Permitted twin: only one side changed the path, so the merge is clean.
    let merged = merge_pull_request_tree(
        [entry(b"a", 0x01)],
        [entry(b"a", 0x02)],
        [entry(b"a", 0x01)],
        TreeMergeOptions::default(),
    )
    .expect("a one-sided change merges cleanly");
    assert_eq!(merged.entries, vec![entry(b"a", 0x02)]);
}

// ------------------------------------ acceptance (3): event wire behaviour

#[test]
fn every_event_kind_survives_the_roundtrip_as_itself() {
    let kinds = [
        ForgeEventPayload::PullRequestOpened {
            source_ref: b"refs/heads/feature".to_vec(),
            target_ref: b"refs/heads/main".to_vec(),
            source_tip: digest(0x30),
            target_tip: digest(0x40),
        },
        ForgeEventPayload::PullRequestHeadAdvanced {
            source_tip: digest(0x31),
        },
        ForgeEventPayload::MergeCommitted {
            merge_commit: digest(0x51),
            target_ref: b"refs/heads/main".to_vec(),
            target_tip_before: digest(0x40),
            target_tip_after: digest(0x51),
        },
        ForgeEventPayload::PullRequestClosed { withdrawn: true },
    ];
    for payload in kinds {
        let event = ForgeEvent {
            pull_request: pull_request(),
            version: AggregateVersion::FIRST,
            payload,
        };
        let bytes = encode_body(&event).expect("encodes");
        let decoded: ForgeEvent = decode_body(&bytes, DecodeLimits::DEFAULT).expect("decodes");
        assert_eq!(decoded, event);
    }
}

/// An event kind this build does not implement is refused, not skipped.
///
/// The payload length of an unknown kind is unknowable, so a decoder that
/// tolerated the tag would read every following field from the wrong offset and
/// produce a confidently wrong body that still has a valid identity.
#[test]
fn an_unknown_event_kind_on_the_wire_is_refused_and_a_known_one_is_not() {
    let event = ForgeEvent {
        pull_request: pull_request(),
        version: AggregateVersion::FIRST,
        payload: ForgeEventPayload::PullRequestClosed { withdrawn: false },
    };
    let bytes = encode_body(&event).expect("encodes");

    // The kind is a u32 scalar, so four big-endian bytes. Locate it by
    // re-encoding with a different known kind and diffing, rather than by
    // assuming an offset.
    let other = ForgeEvent {
        payload: ForgeEventPayload::PullRequestHeadAdvanced {
            source_tip: digest(0x31),
        },
        ..event
    };
    let other = encode_body(&other).expect("encodes");
    let divergence = bytes
        .iter()
        .zip(other.iter())
        .position(|(left, right)| left != right)
        .expect("the two frames differ at the kind tag");
    let kind_offset = divergence - 3;
    assert_eq!(
        &bytes[kind_offset..kind_offset + 4],
        &4_u32.to_be_bytes(),
        "the located field must be the tag that says PullRequestClosed"
    );

    for unknown in [0_u32, 5, 99, u32::from(u16::MAX)] {
        let mut corrupted = bytes.clone();
        corrupted[kind_offset..kind_offset + 4].copy_from_slice(&unknown.to_be_bytes());
        match decode_body::<ForgeEvent>(&corrupted, DecodeLimits::DEFAULT) {
            Err(CodecRefusal::VariantUnknown {
                field, observed, ..
            }) => {
                assert_eq!(field, "kind");
                assert_eq!(observed, unknown);
            }
            other => panic!("kind {unknown} must be refused, got {other:?}"),
        }
    }

    // Permitted twin: the untouched frame, differing only in those four bytes.
    let decoded: ForgeEvent = decode_body(&bytes, DecodeLimits::DEFAULT).expect("decodes");
    assert_eq!(decoded, event);
}

/// The batch is ordered, and its identity depends on that order.
#[test]
fn a_batch_commits_to_event_order_rather_than_to_a_set() {
    let first = merge_event();
    let mut second = merge_event();
    second.version = AggregateVersion::try_new(5).expect("a nonzero version");

    let forward = ForgeEventBatch {
        events: vec![first.clone(), second.clone()],
    };
    let reversed = ForgeEventBatch {
        events: vec![second, first],
    };
    assert_ne!(
        encode_body(&forward).expect("encodes"),
        encode_body(&reversed).expect("encodes"),
        "two events on one aggregate are only meaningful in stream order"
    );

    let decoded: ForgeEventBatch = decode_body(
        &encode_body(&forward).expect("encodes"),
        DecodeLimits::DEFAULT,
    )
    .expect("decodes");
    assert_eq!(decoded, forward);
}

/// The schema this build implements, pinned so a change is a deliberate act.
#[test]
fn the_event_declares_its_registered_domain_and_schema() {
    assert_eq!(
        ForgeEvent::DOMAIN.as_str(),
        "frankengit/forge-event/v1",
        "the domain must be the one the crypto registry pins for ForgeEventId"
    );
    assert_eq!(ForgeEvent::SCHEMA_MAJOR, 1);
    assert_eq!(ForgeEvent::SCHEMA_MINOR, 0);
    assert_eq!(
        ForgeEventBatch::DOMAIN.as_str(),
        "frankengit/forge-event-batch/v1"
    );
}
