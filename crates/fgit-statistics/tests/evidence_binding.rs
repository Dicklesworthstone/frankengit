//! Tests for the seven bindings `AGENTS.md` section 8 requires of statistical
//! evidence.
//!
//! The centrepiece is [`every_binding_is_load_bearing_in_the_canonical_bytes`].
//! A roundtrip test alone cannot catch a binding that `write_payload` never
//! writes, because `read_payload` would not read it either and the pair would
//! agree with each other while agreeing about nothing. The consequence is
//! specific and severe: a binding absent from the bytes is absent from the
//! digest, so two evidence records about *different populations* would commit
//! to the same identity. Varying each binding on its own and requiring the
//! bytes to move is what rules that out.

use fgit_codec::wire::{CanonicalBody, canonical_body_bytes, encode_body};
use fgit_codec::{CodecRefusal, DecodeLimits, decode_body};
use fgit_statistics::evidence::{
    AssumptionSet, BindingRefusal, RegimeBinding, SequenceWindow, StatisticalEvidenceBody,
};
use fgit_statistics::{Cusum, CusumConfig, FallbackTrigger, PolicySelection};
use fgit_types::{AsciiSlug, Digest, DigestAlgorithmId, DigestBytes};

fn slug(text: &str) -> AsciiSlug {
    AsciiSlug::try_new("test", text.as_bytes()).expect("valid slug")
}

fn fingerprint(seed: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(1).expect("nonzero code point"),
        DigestBytes::try_new(&[seed; 20]).expect("20-byte SHA-1 digest fits its registered width"),
    )
}

fn assumptions(labels: &[&str]) -> AssumptionSet {
    AssumptionSet::try_new(labels.iter().copied().map(slug).collect()).expect("valid set")
}

/// A body with every binding filled in with a distinguishable value.
fn body() -> StatisticalEvidenceBody {
    StatisticalEvidenceBody {
        population: slug("merge-queue-latency"),
        selection: slug("every-admitted-transaction"),
        window: SequenceWindow::try_new(1_000, 2_048).expect("ordered window"),
        regime: RegimeBinding {
            epoch: 7,
            detector_high: 15,
            detector_low: -4,
            observations: 1_049,
            saturated: false,
        },
        policy: PolicySelection::Candidate,
        assumptions: assumptions(&["fixed-target-declared", "slack-positive"]),
        fingerprint: fingerprint(0xab),
    }
}

// ------------------------------------------------------------------ roundtrip

#[test]
fn a_body_survives_encode_and_decode_unchanged() {
    let original = body();
    let bytes = encode_body(&original).expect("encodes");
    let decoded: StatisticalEvidenceBody =
        decode_body(&bytes, DecodeLimits::DEFAULT).expect("decodes");
    assert_eq!(decoded, original);
}

#[test]
fn every_fallback_trigger_survives_the_roundtrip_as_itself() {
    // Binding 5 must replay *which* trigger fired, not merely that one did: a
    // reader deciding whether the run is comparable needs the reason.
    for trigger in FallbackTrigger::ALL {
        let mut evidence = body();
        evidence.policy = PolicySelection::Fallback(trigger);
        let bytes = encode_body(&evidence).expect("encodes");
        let decoded: StatisticalEvidenceBody =
            decode_body(&bytes, DecodeLimits::DEFAULT).expect("decodes");
        assert_eq!(decoded.policy, PolicySelection::Fallback(trigger));
    }

    // The absence half: the candidate is not merely the value that survives
    // when nothing else does.
    let bytes = encode_body(&body()).expect("encodes");
    let decoded: StatisticalEvidenceBody =
        decode_body(&bytes, DecodeLimits::DEFAULT).expect("decodes");
    assert_eq!(decoded.policy, PolicySelection::Candidate);
}

// --------------------------------------------- every binding reaches the bytes

#[test]
fn every_binding_is_load_bearing_in_the_canonical_bytes() {
    let baseline = canonical_body_bytes(&body()).expect("encodes");

    // One mutation per section 8 binding, each touching nothing else.
    let mut population = body();
    population.population = slug("merge-queue-throughput");

    let mut selection = body();
    selection.selection = slug("sampled-one-in-ten");

    let mut window = body();
    window.window = SequenceWindow::try_new(1_000, 2_049).expect("ordered window");

    let mut regime = body();
    regime.regime.epoch = 8;

    let mut policy = body();
    policy.policy = PolicySelection::Fallback(FallbackTrigger::RegimeAlarm);

    let mut assumption = body();
    assumption.assumptions =
        assumptions(&["fixed-target-declared", "slack-positive", "iid-window"]);

    let mut fingerprint_only = body();
    fingerprint_only.fingerprint = fingerprint(0xcd);

    let mutated = [
        ("population", population),
        ("selection", selection),
        ("window", window),
        ("regime", regime),
        ("policy", policy),
        ("assumptions", assumption),
        ("fingerprint", fingerprint_only),
    ];
    assert_eq!(
        mutated.len(),
        7,
        "section 8 names seven bindings; a body that grew an eighth needs a case here"
    );

    for (binding, candidate) in mutated {
        let bytes = canonical_body_bytes(&candidate).expect("encodes");
        assert_ne!(
            bytes, baseline,
            "changing `{binding}` left the canonical bytes identical, so that binding is absent \
             from the digest and two records differing only in {binding} would commit to the \
             same identity"
        );
    }
}

#[test]
fn the_regime_detector_state_is_bound_field_by_field() {
    // `regime` is a struct, so the mutation above only proves *one* of its
    // fields reaches the bytes. Each of the rest gets its own case.
    let baseline = canonical_body_bytes(&body()).expect("encodes");

    let mut high = body();
    high.regime.detector_high = 16;
    let mut low = body();
    low.regime.detector_low = -5;
    let mut observations = body();
    observations.regime.observations = 1_050;
    let mut saturated = body();
    saturated.regime.saturated = true;

    for (field, candidate) in [
        ("detector_high", high),
        ("detector_low", low),
        ("observations", observations),
        ("saturated", saturated),
    ] {
        assert_ne!(
            canonical_body_bytes(&candidate).expect("encodes"),
            baseline,
            "regime.{field} does not reach the canonical bytes"
        );
    }
}

// ------------------------------------------------------------ canonical order

#[test]
fn assumptions_collected_in_any_order_produce_identical_bytes() {
    // Canonical bytes must not depend on the order a caller happened to gather
    // the assumptions in, or the same evidence would commit to two identities.
    let forward = assumptions(&["alpha", "beta", "gamma"]);
    let reversed = assumptions(&["gamma", "beta", "alpha"]);
    let shuffled = assumptions(&["beta", "gamma", "alpha"]);

    let mut a = body();
    a.assumptions = forward;
    let mut b = body();
    b.assumptions = reversed;
    let mut c = body();
    c.assumptions = shuffled;

    let bytes_a = canonical_body_bytes(&a).expect("encodes");
    assert_eq!(bytes_a, canonical_body_bytes(&b).expect("encodes"));
    assert_eq!(bytes_a, canonical_body_bytes(&c).expect("encodes"));

    // The permitted twin: a genuinely different set still differs, so the
    // agreement above is canonicalisation and not everything colliding.
    let mut d = body();
    d.assumptions = assumptions(&["alpha", "beta", "delta"]);
    assert_ne!(bytes_a, canonical_body_bytes(&d).expect("encodes"));
}

#[test]
fn assumptions_out_of_order_on_the_wire_are_refused() {
    // The decoder re-verifies canonical order rather than trusting the producer.
    // Two labels of equal length let the encoded elements be swapped in place,
    // producing a well-formed frame whose set is out of order.
    let mut evidence = body();
    evidence.assumptions = assumptions(&["aaa", "bbb"]);
    let mut bytes = encode_body(&evidence).expect("encodes");

    let first = find(&bytes, b"aaa").expect("first label present");
    let second = find(&bytes, b"bbb").expect("second label present");
    assert!(first < second, "canonical order puts aaa before bbb");
    for offset in 0..3 {
        bytes.swap(first + offset, second + offset);
    }

    match decode_body::<StatisticalEvidenceBody>(&bytes, DecodeLimits::DEFAULT) {
        Err(CodecRefusal::CollectionUnordered { field, .. }) => {
            assert_eq!(field, "assumptions");
        }
        other => panic!("expected CollectionUnordered, got {other:?}"),
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

// ------------------------------------------------------------- fail-closed tag

#[test]
fn an_unrecognised_policy_tag_is_refused_and_never_read_as_the_candidate() {
    // The failure this prevents: a corrupted or forward-versioned tag byte
    // decoding as `Candidate` would silently *admit* adaptation, which is the
    // one direction section 33's fail-closed rule forbids. Refusal is the only
    // safe reading of a byte this build does not understand.
    let evidence = body();
    let bytes = encode_body(&evidence).expect("encodes");

    // The tag sits between the `saturated` boolean and the assumption count.
    // Locate it by re-encoding with a known distinct tag and diffing.
    let mut alternative = body();
    alternative.policy = PolicySelection::Fallback(FallbackTrigger::StaleWindow);
    let other = encode_body(&alternative).expect("encodes");
    let tag_offset = bytes
        .iter()
        .zip(other.iter())
        .position(|(left, right)| left != right)
        .expect("the two frames differ at the policy tag");
    assert_eq!(bytes[tag_offset], 0, "the candidate tag is zero");
    assert_eq!(other[tag_offset], 5, "StaleWindow is the fifth trigger");

    for unknown in [6_u8, 7, 42, 255] {
        let mut corrupted = bytes.clone();
        corrupted[tag_offset] = unknown;
        match decode_body::<StatisticalEvidenceBody>(&corrupted, DecodeLimits::DEFAULT) {
            Err(CodecRefusal::VariantUnknown {
                field, observed, ..
            }) => {
                assert_eq!(field, "policy");
                assert_eq!(observed, u32::from(unknown));
            }
            Ok(decoded) => panic!(
                "tag {unknown} decoded as {:?} instead of being refused",
                decoded.policy
            ),
            Err(other) => panic!("expected VariantUnknown for tag {unknown}, got {other:?}"),
        }
    }

    // The permitted twin: every defined tag still decodes, so the refusal above
    // is specific to unknown tags rather than a blanket rejection.
    for tag in 0..=5_u8 {
        let mut accepted = bytes.clone();
        accepted[tag_offset] = tag;
        assert!(
            decode_body::<StatisticalEvidenceBody>(&accepted, DecodeLimits::DEFAULT).is_ok(),
            "defined tag {tag} must decode"
        );
    }
}

// ------------------------------------------------- construction-time refusals

#[test]
fn an_inverted_window_is_refused_and_a_single_position_window_is_not() {
    assert_eq!(
        SequenceWindow::try_new(10, 9),
        Err(BindingRefusal::WindowInverted { first: 10, last: 9 }),
        "a window that ends before it begins covers nothing, so any claim over it is vacuous"
    );

    // The permitted twin, and the boundary: one position is the smallest real
    // window and must be admitted.
    let single = SequenceWindow::try_new(10, 10).expect("a one-position window is valid");
    assert_eq!(single.len(), 1);
    assert_eq!(single.first(), 10);
    assert_eq!(single.last(), 10);

    let wide = SequenceWindow::try_new(10, 19).expect("valid");
    assert_eq!(wide.len(), 10, "the window is inclusive on both ends");
}

#[test]
fn an_empty_assumption_set_is_refused_and_a_single_assumption_is_not() {
    assert_eq!(
        AssumptionSet::try_new(Vec::new()),
        Err(BindingRefusal::AssumptionsEmpty),
        "an empty set is indistinguishable from a field nobody filled in"
    );

    let one = AssumptionSet::try_new(vec![slug("slack-positive")]).expect("one is enough");
    assert_eq!(one.len(), 1);
    assert!(!one.is_empty());
}

#[test]
fn a_repeated_assumption_is_refused_at_construction() {
    assert_eq!(
        AssumptionSet::try_new(vec![slug("iid-window"), slug("iid-window")]),
        Err(BindingRefusal::AssumptionDuplicated {
            label: slug("iid-window")
        })
    );

    // The permitted twin: two distinct labels, one of which is a prefix of the
    // other, must not be collapsed.
    let distinct = AssumptionSet::try_new(vec![slug("iid-window"), slug("iid")])
        .expect("distinct labels are admitted");
    assert_eq!(distinct.len(), 2);
    assert_eq!(
        distinct.as_slice()[0],
        slug("iid"),
        "stored in sorted order"
    );
}

// ------------------------------------------------- integration with the detector

#[test]
fn a_regime_binding_read_from_a_detector_matches_that_detector() {
    // The binding and the detector cannot disagree, because the binding is read
    // off the detector rather than restated by the caller.
    let config = CusumConfig {
        target: 100,
        slack: 5,
        threshold: 20,
        max_deviation: 1_000,
        max_observations: 100_000,
    };
    let mut detector = Cusum::new(config).expect("assumptions hold");
    for _ in 0..3 {
        detector.observe(110);
    }

    let binding = RegimeBinding::from_detector(4, &detector);
    assert_eq!(binding.epoch, 4);
    assert_eq!(binding.detector_high, detector.high());
    assert_eq!(binding.detector_low, detector.low());
    assert_eq!(binding.observations, detector.observations());
    assert_eq!(binding.saturated, detector.saturated());

    // Hand-checked against the recurrence: deviation 10, slack 5, so the high
    // accumulator advances by 5 per observation.
    assert_eq!(binding.detector_high, 15);
    assert_eq!(binding.observations, 3);
}

// ------------------------------------------------------------- schema identity

#[test]
fn the_body_declares_its_own_domain_and_schema() {
    assert_eq!(
        StatisticalEvidenceBody::DOMAIN.as_str(),
        "frankengit/statistical-evidence/v1"
    );
    assert_eq!(
        StatisticalEvidenceBody::SCHEMA_FAMILY.as_str(),
        "statistical-evidence"
    );
    assert_eq!(StatisticalEvidenceBody::SCHEMA_MAJOR, 1);
    assert_eq!(StatisticalEvidenceBody::SCHEMA_MINOR, 0);
}
