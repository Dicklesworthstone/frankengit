#![forbid(unsafe_code)]

//! frankengit-fxlp: the microsegment builder's `SegmentLimits` bounds.
//!
//! A microsegment is assembled from untrusted record inputs, so its limits are
//! what stand between a caller and unbounded allocation. AGENTS.md §7 requires
//! resource bounds enforced before allocation and work. None of these bounds
//! had a test anywhere in the workspace, and each is a `>` comparison whose
//! inclusive boundary is the thing most easily got wrong.
//!
//! Every refusal here is asserted on the CALL THAT SHOULD REFUSE -- `push`
//! rather than `build` -- and that is deliberate rather than stylistic. The
//! record and byte bounds are checked during `push`, but a segment that slipped
//! past them would also be caught at `build`, reporting the same unit variant
//! with no payload to tell the two apart. Asserting the push result is what
//! makes these tests notice which guard ran.

use fgit_object_fabric::{
    CryptoDigest, DigestAlgorithm, FabricError, MicrosegmentBuilder, ObjectEnvelope, ObjectKind,
    SegmentLimits, SegmentRecordInput,
};
use fgit_types::native::{GitOid, GitOidSha1};

const MAX_NAMESPACE: usize = 4;

fn limits(max_segment_bytes: usize, max_records: u32) -> SegmentLimits {
    SegmentLimits {
        max_segment_bytes,
        max_records,
        max_namespace_bytes: MAX_NAMESPACE,
        max_object_identity_bytes: 32,
        max_envelope_bytes: 256,
        max_record_bytes: 512,
    }
}

/// Limits generous enough that nothing under test can be what refuses.
fn roomy() -> SegmentLimits {
    limits(64 * 1024, 128)
}

fn oid(identity: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([identity; GitOidSha1::LEN]))
}

fn payload(identity: u8) -> Vec<u8> {
    vec![b'p', identity]
}

/// An envelope whose `codec_namespace` length is chosen by the caller, since
/// that is the field one bound below is about.
fn envelope_with_codec_namespace(
    identity: u8,
    codec_namespace: Vec<u8>,
    limits: &SegmentLimits,
) -> Result<ObjectEnvelope, FabricError> {
    let payload = payload(identity);
    ObjectEnvelope::new(
        vec![b'n'],
        oid(identity),
        ObjectKind::Blob,
        u64::try_from(payload.len()).expect("fixture payload length fits u64"),
        CryptoDigest
            .payload_commitment(ObjectKind::Blob, &payload)
            .expect("registered payload commitment succeeds"),
        codec_namespace,
        // `Commitment` is a public alias for `[u8; 32]`; the constant naming
        // that width is crate-private, so the width is written directly.
        [4_u8; 32],
        None,
        limits,
    )
}

fn record(identity: u8, limits: &SegmentLimits) -> SegmentRecordInput {
    SegmentRecordInput {
        envelope: envelope_with_codec_namespace(identity, vec![b'c'], limits)
            .expect("fixture envelope is within limits"),
        payload: payload(identity),
    }
}

/// A codec namespace longer than the limit is refused.
#[test]
fn a_codec_namespace_over_the_limit_is_refused() {
    let limits = roomy();

    assert_eq!(
        envelope_with_codec_namespace(1, vec![b'c'; MAX_NAMESPACE + 1], &limits),
        Err(FabricError::CodecNamespaceTooLarge),
    );
}

/// The permitted twin at the exact inclusive boundary: a codec namespace of
/// exactly the limit is accepted.
///
/// The guard is `> max_namespace_bytes`. A probe showing only that one byte too
/// many is refused is equally consistent with `>=`, which would reject a
/// namespace that exactly fits its declared budget.
#[test]
fn a_codec_namespace_of_exactly_the_limit_is_accepted() {
    let limits = roomy();

    envelope_with_codec_namespace(1, vec![b'c'; MAX_NAMESPACE], &limits)
        .expect("a codec namespace of exactly the limit must be admitted");
}

/// Pushing more records than the limit allows is refused, at the push.
#[test]
fn pushing_past_the_record_limit_is_refused() {
    let limits = limits(64 * 1024, 2);
    let digest = CryptoDigest;
    let mut builder = MicrosegmentBuilder::new(&digest, limits.clone());

    for identity in 1..=2 {
        builder
            .push(record(identity, &limits))
            .expect("the first two records are within a limit of two");
    }

    assert_eq!(
        builder.push(record(3, &limits)),
        Err(FabricError::TooManyRecords),
        "the third record exceeds a limit of two, and push is where that is decided",
    );
}

/// The permitted twin at the exact inclusive boundary: exactly the record limit
/// is accepted and builds.
///
/// Asserted on the built segment's `record_count` rather than on `is_ok`, so a
/// builder that silently dropped a record would not satisfy it.
#[test]
fn pushing_exactly_the_record_limit_is_accepted() {
    let limits = limits(64 * 1024, 2);
    let digest = CryptoDigest;
    let mut builder = MicrosegmentBuilder::new(&digest, limits.clone());

    for identity in 1..=2 {
        builder
            .push(record(identity, &limits))
            .expect("exactly the record limit must be admitted");
    }

    let segment = builder
        .build()
        .expect("a segment at its record limit builds");
    assert_eq!(segment.record_count(), 2);
}

/// The segment byte budget, calibrated at runtime rather than guessed.
///
/// The framing overhead is not something a test should hard-code, so this
/// measures the exact encoded size of a one-record segment under roomy limits
/// and then drives the boundary from that measurement: exactly that many bytes
/// is accepted, one fewer is refused.
///
/// Both halves in one test because the accepted half is meaningless without the
/// measurement that produced the number.
#[test]
fn a_segment_at_exactly_its_byte_budget_is_accepted_and_one_byte_short_is_refused() {
    let measured = {
        let roomy = roomy();
        let digest = CryptoDigest;
        let mut builder = MicrosegmentBuilder::new(&digest, roomy.clone());
        builder
            .push(record(1, &roomy))
            .expect("one record fits roomy limits");
        builder
            .build()
            .expect("one record builds under roomy limits")
            .as_bytes()
            .len()
    };

    let exact = limits(measured, 128);
    let digest = CryptoDigest;
    let mut builder = MicrosegmentBuilder::new(&digest, exact.clone());
    builder
        .push(record(1, &exact))
        .expect("a budget of exactly the encoded size must admit the record");
    builder
        .build()
        .expect("a segment of exactly its byte budget must build");

    let short = limits(measured - 1, 128);
    let digest = CryptoDigest;
    let mut builder = MicrosegmentBuilder::new(&digest, short.clone());
    assert_eq!(
        builder.push(record(1, &short)),
        Err(FabricError::SegmentTooLarge),
        "one byte under the encoded size must be refused, and push is where the \
         projection is checked",
    );
}
