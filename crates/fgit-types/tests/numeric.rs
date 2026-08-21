// Bounded scalars: the sealed canonical-integer set, zigzag round-tripping,
// and gap-free monotone counters.
//
// The sweeps below are deterministic. Each failure message carries the seed
// and the exact input so a failing case is reproducible from the log alone.

use fgit_types::TypeRefusal;
use fgit_types::numeric::{
    ByteCount, CanonicalScalar, CodecVersion, DecisionSequence, HeadGeneration, PolicyEpoch,
    RegistryEpoch, RepositorySequence, ScalarWidth, zigzag_decode, zigzag_encode,
};

const SEED: u64 = 0x0f00_d000_cafe_1234;

// SplitMix64: a fixed, self-contained generator so the corpus is identical on
// every machine and every run.
struct SplitMix64(u64);

impl SplitMix64 {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    const fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

#[test]
fn zigzag_round_trips_over_a_seeded_sweep_and_the_extremes() {
    let mut rng = SplitMix64::new(SEED);
    for iteration in 0..4096 {
        let value = zigzag_decode(rng.next_u64());
        let round_tripped = zigzag_decode(zigzag_encode(value));
        assert_eq!(
            round_tripped, value,
            "zigzag round trip failed: seed={SEED:#x} iteration={iteration} value={value}"
        );
    }
    for value in [i64::MIN, -1, 0, 1, i64::MAX] {
        assert_eq!(
            zigzag_decode(zigzag_encode(value)),
            value,
            "zigzag round trip failed at extreme value={value}"
        );
    }
    // Small magnitudes stay small, which is the reason for the mapping.
    assert_eq!(zigzag_encode(0), 0);
    assert_eq!(zigzag_encode(-1), 1);
    assert_eq!(zigzag_encode(1), 2);
}

#[test]
fn canonical_scalars_round_trip_through_their_bit_form() {
    let mut rng = SplitMix64::new(SEED ^ 0x5555_5555_5555_5555);
    for iteration in 0..1024 {
        let draw = rng.next_u64();

        let narrow = u8::try_from(draw & 0xff).expect("masked to one byte");
        assert_eq!(
            u8::from_canonical_bits(narrow.to_canonical_bits()).expect("in range"),
            narrow,
            "u8 round trip failed: seed={SEED:#x} iteration={iteration} draw={draw:#x}"
        );

        let wide = draw;
        assert_eq!(
            u64::from_canonical_bits(wide.to_canonical_bits()).expect("in range"),
            wide,
            "u64 round trip failed: seed={SEED:#x} iteration={iteration} draw={draw:#x}"
        );

        let signed = zigzag_decode(draw);
        assert_eq!(
            i64::from_canonical_bits(signed.to_canonical_bits()).expect("in range"),
            signed,
            "i64 round trip failed: seed={SEED:#x} iteration={iteration} draw={draw:#x}"
        );
    }
}

// Signedness is an associated constant, so these are compile-time facts
// rather than runtime assertions; stating them as `const` makes that explicit
// and keeps them checked.
const _: () = assert!(!u8::SIGNED);
const _: () = assert!(!u32::SIGNED);
const _: () = assert!(!u64::SIGNED);
const _: () = assert!(i8::SIGNED);
const _: () = assert!(i32::SIGNED);
const _: () = assert!(i64::SIGNED);

#[test]
fn canonical_scalar_widths_and_signedness_are_declared() {
    assert_eq!(u8::WIDTH, ScalarWidth::W1);
    assert_eq!(u16::WIDTH, ScalarWidth::W2);
    assert_eq!(u32::WIDTH, ScalarWidth::W4);
    assert_eq!(u64::WIDTH, ScalarWidth::W8);
    assert_eq!(i8::WIDTH, ScalarWidth::W1);
    assert_eq!(i64::WIDTH, ScalarWidth::W8);
    assert_eq!(ScalarWidth::W1.byte_len(), 1);
    assert_eq!(ScalarWidth::W8.byte_len(), 8);
}

#[test]
fn out_of_range_bits_are_refused_rather_than_truncated() {
    let refusal =
        u8::from_canonical_bits(256).expect_err("a value above the width must not be truncated");
    assert_eq!(
        refusal,
        TypeRefusal::ValueOutOfRange {
            field: "u8",
            observed: 256,
            minimum: 0,
            maximum: 255,
        }
    );
    // Permitted counterpart: the largest value that does fit.
    assert_eq!(u8::from_canonical_bits(255).expect("in range"), 255);

    assert!(i8::from_canonical_bits(zigzag_encode(127)).is_ok());
    assert!(i8::from_canonical_bits(zigzag_encode(128)).is_err());
}

#[test]
fn counters_start_at_one_and_are_gap_free() {
    assert_eq!(DecisionSequence::FIRST.get(), 1);
    let first = DecisionSequence::FIRST;
    let second = first.next().expect("successor exists");
    assert_eq!(second.get(), 2);
    assert!(first.is_immediate_predecessor_of(second));
    assert!(!first.is_immediate_predecessor_of(first));

    let skipped = DecisionSequence::try_new(3).expect("valid");
    assert!(
        !first.is_immediate_predecessor_of(skipped),
        "a gap must not look like a valid succession"
    );
    assert!(second.is_immediate_predecessor_of(skipped));
}

#[test]
fn zero_is_reserved_and_exhaustion_is_refused() {
    for refusal in [
        DecisionSequence::try_new(0).err(),
        RepositorySequence::try_new(0).err(),
        HeadGeneration::try_new(0).err(),
        PolicyEpoch::try_new(0).err(),
        RegistryEpoch::try_new(0).err(),
    ] {
        let refusal = refusal.expect("zero is reserved for the absent case");
        assert!(matches!(refusal, TypeRefusal::ValueOutOfRange { .. }));
    }
    // Permitted counterpart: one is the first live value everywhere.
    assert!(RepositorySequence::try_new(1).is_ok());

    let last = HeadGeneration::try_new(u64::MAX).expect("valid");
    assert!(
        last.next().is_err(),
        "counter exhaustion must refuse, never wrap"
    );
}

#[test]
fn counters_from_different_families_do_not_interchange() {
    // The compile-time guarantee is that these are distinct types; the runtime
    // assertion documents that equal wire values are still different facts.
    let decision = DecisionSequence::try_new(7).expect("valid");
    let repository = RepositorySequence::try_new(7).expect("valid");
    assert_eq!(decision.get(), repository.get());
    assert_eq!(decision.to_string(), "7");
}

#[test]
fn codec_versions_order_by_major_then_minor() {
    let one_zero = CodecVersion::new(1, 0);
    let one_one = CodecVersion::new(1, 1);
    let two_zero = CodecVersion::new(2, 0);
    assert!(one_zero < one_one);
    assert!(one_one < two_zero);
    assert_eq!(one_zero.major(), 1);
    assert_eq!(one_one.minor(), 1);
    assert_eq!(two_zero.to_string(), "v2.0");
    assert_eq!(fgit_types::CANONICAL_CODEC_VERSION, one_zero);
}

#[test]
fn byte_counts_are_bounded_before_use() {
    let permitted = ByteCount::try_new("body", 1024, 4096).expect("inside the bound");
    assert_eq!(permitted.get(), 1024);
    assert_eq!(ByteCount::ZERO.get(), 0);

    let refusal = ByteCount::try_new("body", 4097, 4096)
        .expect_err("a size above the bound must be refused before allocation");
    assert_eq!(
        refusal,
        TypeRefusal::ValueOutOfRange {
            field: "body",
            observed: 4097,
            minimum: 0,
            maximum: 4096,
        }
    );
    // Permitted counterpart: exactly at the bound.
    assert!(ByteCount::try_new("body", 4096, 4096).is_ok());
}
