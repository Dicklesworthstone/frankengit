//! The additive aggregate discriminant: existing pull-request events must keep
//! their exact canonical bytes.
//!
//! # Why these goldens are literals and not regenerated
//!
//! Every hex string below was produced by the encoder as it stood at commit
//! 8cee164, BEFORE `AggregateId` existed, by a `[workspace]`-detached probe
//! over that source. Pinning them here proves the change is byte-neutral for
//! events that already exist, and therefore that no committed `ForgeEventId`
//! moves.
//!
//! Regenerating goldens from the new encoder and observing that they agree with
//! themselves would prove nothing at all -- that is RH-3 wearing a test's
//! clothes. The whole value of this file is that its expected values could not
//! have been produced by the code under test.

use fgit_codec::{CodecRefusal, DecodeLimits, decode_body, encode_body};
use fgit_forge::event::ForgeEventBatch;
use fgit_forge::{
    AggregateId, AggregateVersion, ForgeEvent, ForgeEventPayload, OrganisationNumber,
    PullRequestNumber, TeamNumber,
};
use fgit_types::{Digest, DigestAlgorithmId, DigestBytes};

const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;
const _: () = assert!(FIXTURE_ALGORITHM_CODE_POINT >= 0xfff0);

fn digest(tag: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("nonzero corpus fixture algorithm slot"),
        DigestBytes::try_new(&[tag; 32]).expect("32-byte corpus fixture body"),
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn pull_request() -> PullRequestNumber {
    PullRequestNumber::try_new(7).expect("nonzero")
}

fn version() -> AggregateVersion {
    AggregateVersion::try_new(3).expect("nonzero")
}

fn payloads() -> [(&'static str, ForgeEventPayload); 4] {
    [
        (
            "PullRequestOpened",
            ForgeEventPayload::PullRequestOpened {
                source_ref: b"refs/heads/feature".to_vec(),
                target_ref: b"refs/heads/main".to_vec(),
                source_tip: digest(0x30),
                target_tip: digest(0x40),
            },
        ),
        (
            "PullRequestHeadAdvanced",
            ForgeEventPayload::PullRequestHeadAdvanced {
                source_tip: digest(0x31),
            },
        ),
        (
            "MergeCommitted",
            ForgeEventPayload::MergeCommitted {
                merge_commit: digest(0x51),
                target_ref: b"refs/heads/main".to_vec(),
                target_tip_before: digest(0x40),
                target_tip_after: digest(0x51),
            },
        ),
        (
            "PullRequestClosed",
            ForgeEventPayload::PullRequestClosed { withdrawn: true },
        ),
    ]
}

/// Canonical bytes of each event kind, captured at 8cee164 before the change.
const EVENT_GOLDENS: [(&str, &str); 4] = [
    (
        "PullRequestOpened",
        "4647433100010000000000196672616e6b656e6769742f666f7267652d6576656e742f76310000000b666f7267652d6576656e740001000000000089000000000000000700000000000000030000000100000012726566732f68656164732f666561747572650000000f726566732f68656164732f6d61696efff1000000203030303030303030303030303030303030303030303030303030303030303030fff1000000204040404040404040404040404040404040404040404040404040404040404040",
    ),
    (
        "PullRequestHeadAdvanced",
        "4647433100010000000000196672616e6b656e6769742f666f7267652d6576656e742f76310000000b666f7267652d6576656e74000100000000003a0000000000000007000000000000000300000002fff1000000203131313131313131313131313131313131313131313131313131313131313131",
    ),
    (
        "MergeCommitted",
        "4647433100010000000000196672616e6b656e6769742f666f7267652d6576656e742f76310000000b666f7267652d6576656e7400010000000000990000000000000007000000000000000300000003fff10000002051515151515151515151515151515151515151515151515151515151515151510000000f726566732f68656164732f6d61696efff1000000204040404040404040404040404040404040404040404040404040404040404040fff1000000205151515151515151515151515151515151515151515151515151515151515151",
    ),
    (
        "PullRequestClosed",
        "4647433100010000000000196672616e6b656e6769742f666f7267652d6576656e742f76310000000b666f7267652d6576656e740001000000000015000000000000000700000000000000030000000401",
    ),
];

/// The same events inside a one-element batch, likewise captured beforehand.
const BATCH_GOLDENS: [(&str, &str); 4] = [
    (
        "PullRequestOpened",
        "46474331000100000000001f6672616e6b656e6769742f666f7267652d6576656e742d62617463682f763100000011666f7267652d6576656e742d6261746368000100000000008d00000001000000000000000700000000000000030000000100000012726566732f68656164732f666561747572650000000f726566732f68656164732f6d61696efff1000000203030303030303030303030303030303030303030303030303030303030303030fff1000000204040404040404040404040404040404040404040404040404040404040404040",
    ),
    (
        "PullRequestHeadAdvanced",
        "46474331000100000000001f6672616e6b656e6769742f666f7267652d6576656e742d62617463682f763100000011666f7267652d6576656e742d6261746368000100000000003e000000010000000000000007000000000000000300000002fff1000000203131313131313131313131313131313131313131313131313131313131313131",
    ),
    (
        "MergeCommitted",
        "46474331000100000000001f6672616e6b656e6769742f666f7267652d6576656e742d62617463682f763100000011666f7267652d6576656e742d6261746368000100000000009d000000010000000000000007000000000000000300000003fff10000002051515151515151515151515151515151515151515151515151515151515151510000000f726566732f68656164732f6d61696efff1000000204040404040404040404040404040404040404040404040404040404040404040fff1000000205151515151515151515151515151515151515151515151515151515151515151",
    ),
    (
        "PullRequestClosed",
        "46474331000100000000001f6672616e6b656e6769742f666f7267652d6576656e742d62617463682f763100000011666f7267652d6576656e742d6261746368000100000000001900000001000000000000000700000000000000030000000401",
    ),
];

/// A pull-request event encodes to exactly the bytes it did before aggregates
/// other than pull requests existed.
#[test]
fn existing_pull_request_events_keep_their_exact_canonical_bytes() {
    for ((name, payload), (golden_name, golden)) in payloads().into_iter().zip(EVENT_GOLDENS) {
        assert_eq!(name, golden_name, "golden table is out of order");
        let event = ForgeEvent {
            aggregate: AggregateId::PullRequest(pull_request()),
            version: version(),
            payload,
        };
        let bytes = encode_body(&event).expect("encodes");
        assert_eq!(
            hex(&bytes),
            golden,
            "{name} no longer encodes to its pre-change bytes, so its ForgeEventId moved"
        );
    }
}

/// The batch framing is unchanged too, so a committed batch keeps its identity.
#[test]
fn existing_pull_request_batches_keep_their_exact_canonical_bytes() {
    for ((name, payload), (golden_name, golden)) in payloads().into_iter().zip(BATCH_GOLDENS) {
        assert_eq!(name, golden_name, "golden table is out of order");
        let batch = ForgeEventBatch::of_one(ForgeEvent {
            aggregate: AggregateId::PullRequest(pull_request()),
            version: version(),
            payload,
        });
        let bytes = encode_body(&batch).expect("encodes");
        assert_eq!(hex(&bytes), golden, "{name} batch bytes moved");
    }
}

/// The new aggregates round-trip as themselves.
#[test]
fn organisation_and_team_aggregates_survive_the_roundtrip() {
    let aggregates = [
        AggregateId::Organisation(OrganisationNumber::try_new(11).expect("nonzero")),
        AggregateId::Team(TeamNumber::try_new(12).expect("nonzero")),
        AggregateId::PullRequest(pull_request()),
    ];
    for aggregate in aggregates {
        let event = ForgeEvent {
            aggregate,
            version: version(),
            payload: ForgeEventPayload::PullRequestClosed { withdrawn: false },
        };
        let bytes = encode_body(&event).expect("encodes");
        let decoded: ForgeEvent = decode_body(&bytes, DecodeLimits::DEFAULT).expect("decodes");
        assert_eq!(decoded.aggregate, aggregate);
        assert_eq!(decoded, event);
    }
}

/// A non-pull-request aggregate is strictly longer, which is what makes the
/// pull-request encoding able to stay bare.
#[test]
fn only_the_new_aggregates_pay_for_the_discriminant() {
    let closed = ForgeEventPayload::PullRequestClosed { withdrawn: false };
    let pr = encode_body(&ForgeEvent {
        aggregate: AggregateId::PullRequest(pull_request()),
        version: version(),
        payload: closed.clone(),
    })
    .expect("encodes");
    let org = encode_body(&ForgeEvent {
        aggregate: AggregateId::Organisation(OrganisationNumber::try_new(11).expect("nonzero")),
        version: version(),
        payload: closed,
    })
    .expect("encodes");
    assert_eq!(
        org.len() - pr.len(),
        12,
        "an organisation slot costs exactly the u32 kind plus the u64 id"
    );
}

/// An unknown aggregate kind behind the zero escape is refused, and a known one
/// is not.
#[test]
fn an_unknown_aggregate_kind_is_refused_and_a_known_one_is_not() {
    let team = AggregateId::Team(TeamNumber::try_new(12).expect("nonzero"));
    let organisation = AggregateId::Organisation(OrganisationNumber::try_new(12).expect("nonzero"));
    let event = |aggregate| ForgeEvent {
        aggregate,
        version: version(),
        payload: ForgeEventPayload::PullRequestClosed { withdrawn: false },
    };
    let team_bytes = encode_body(&event(team)).expect("encodes");
    let organisation_bytes = encode_body(&event(organisation)).expect("encodes");
    assert_eq!(
        team_bytes.len(),
        organisation_bytes.len(),
        "the two frames must be the same length for the locator to be sound"
    );

    // The permitted twin decodes.
    assert!(decode_body::<ForgeEvent>(&team_bytes, DecodeLimits::DEFAULT).is_ok());

    // The kind tag is the only byte where a team and an organisation of the
    // same number differ.
    let divergence = team_bytes
        .iter()
        .zip(organisation_bytes.iter())
        .position(|(left, right)| left != right)
        .expect("the frames differ at the kind tag");
    let mut tampered = team_bytes.clone();
    tampered[divergence] = 0x5a;
    let refusal = decode_body::<ForgeEvent>(&tampered, DecodeLimits::DEFAULT)
        .expect_err("an unknown aggregate kind is refused");
    assert!(
        matches!(
            refusal,
            CodecRefusal::VariantUnknown {
                field: "aggregate.kind",
                ..
            }
        ),
        "expected an unknown-variant refusal naming the aggregate kind, got {refusal:?}"
    );
}

/// A zero id behind the escape is refused: the counters are gap-free and zero
/// is reserved on both sides of the discriminant, not merely in front of it.
#[test]
fn a_zero_aggregate_id_behind_the_escape_is_refused() {
    let organisation = AggregateId::Organisation(OrganisationNumber::try_new(1).expect("nonzero"));
    let bytes = encode_body(&ForgeEvent {
        aggregate: organisation,
        version: version(),
        payload: ForgeEventPayload::PullRequestClosed { withdrawn: false },
    })
    .expect("encodes");
    // The id is the last eight bytes of the aggregate slot, which sits at the
    // very start of the payload: zero it and the counter must refuse.
    let mut tampered = bytes.clone();
    let id_end = bytes
        .windows(8)
        .position(|w| w == 1_u64.to_be_bytes())
        .expect("the organisation id is present as a big-endian one");
    tampered[id_end..id_end + 8].copy_from_slice(&0_u64.to_be_bytes());
    assert!(
        decode_body::<ForgeEvent>(&tampered, DecodeLimits::DEFAULT).is_err(),
        "a zero organisation number must be refused, as PullRequestNumber zero always was"
    );
    assert!(decode_body::<ForgeEvent>(&bytes, DecodeLimits::DEFAULT).is_ok());
}
