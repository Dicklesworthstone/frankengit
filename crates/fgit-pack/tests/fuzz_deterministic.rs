#![forbid(unsafe_code)]
//! Deterministic mutation evidence for the public pack admission boundary.
//!
//! The seeded cases are deliberately kept in the crate test target: they do
//! not invoke foreign Git and can therefore exercise the same bounded Rust
//! parser used by the differential E2E lane.

use std::panic::{AssertUnwindSafe, catch_unwind};

use fgit_pack::{NativeChecksumVerifier, ObjectFormat, PackError, PackLimits, read_verified_pack};

const FUZZ_SEED: u64 = 0x8d21_15e6_7f40_b93c;
const CASE_DENOMINATOR: usize = 256;

#[derive(Clone, Copy)]
enum MutationKind {
    BitFlip,
    Truncate,
    HeaderCount,
    EntryLength,
    Trailer,
}

impl MutationKind {
    const ALL: [Self; 5] = [
        Self::BitFlip,
        Self::Truncate,
        Self::HeaderCount,
        Self::EntryLength,
        Self::Trailer,
    ];

    const fn as_str(self) -> &'static str {
        match self {
            Self::BitFlip => "bit_flip",
            Self::Truncate => "truncate",
            Self::HeaderCount => "header_count",
            Self::EntryLength => "entry_length",
            Self::Trailer => "trailer",
        }
    }
}

struct Lcg {
    state: u64,
}

impl Lcg {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    const fn next(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.state
    }

    fn index(&mut self, upper_exclusive: usize) -> usize {
        let upper = u64::try_from(upper_exclusive).expect("fuzz bounds fit u64");
        usize::try_from(self.next() % upper).expect("bounded fuzz index fits usize")
    }
}

fn valid_pack() -> Vec<u8> {
    let entries = [entry(b"fuzz-base"), entry(b"fuzz-peer")];
    let count = u32::try_from(entries.len()).expect("fixture entry count fits u32");
    let mut pack = b"PACK\0\0\0\x02".to_vec();
    pack.extend_from_slice(&count.to_be_bytes());
    for entry in entries {
        pack.extend_from_slice(&entry);
    }
    pack.extend_from_slice(&fgit_crypto::sha1_digest(&pack));
    pack
}

fn entry(payload: &[u8]) -> Vec<u8> {
    let length = u8::try_from(payload.len()).expect("small fuzz fixture");
    assert!(length < 16, "fuzz fixture uses one-byte pack entry header");
    let stored_length = u16::from(length);
    let mut entry = vec![0x30 | length, 0x78, 0x01, 0x01];
    entry.extend_from_slice(&stored_length.to_le_bytes());
    entry.extend_from_slice(&(!stored_length).to_le_bytes());
    entry.extend_from_slice(payload);
    entry.extend_from_slice(&adler32(payload).to_be_bytes());
    entry
}

fn adler32(bytes: &[u8]) -> u32 {
    let mut a = 1_u32;
    let mut b = 0_u32;
    for &byte in bytes {
        a = (a + u32::from(byte)) % 65_521;
        b = (b + a) % 65_521;
    }
    (b << 16) | a
}

fn mutate(mut pack: Vec<u8>, kind: MutationKind, random: &mut Lcg) -> Vec<u8> {
    match kind {
        MutationKind::BitFlip => {
            let index = random.index(pack.len());
            let bit = 1_u8 << random.index(8);
            pack[index] ^= bit;
        }
        MutationKind::Truncate => {
            pack.truncate(random.index(pack.len()));
        }
        MutationKind::HeaderCount => {
            let count = random.next().to_be_bytes();
            pack[8..12].copy_from_slice(&count[4..]);
        }
        MutationKind::EntryLength => {
            let first_entry = 12_usize;
            pack[first_entry] ^= 0x0f;
        }
        MutationKind::Trailer => {
            let trailer_index = pack.len() - 1 - random.index(20);
            pack[trailer_index] ^= 1_u8 << random.index(8);
        }
    }
    pack
}

fn bounded_limits() -> PackLimits {
    PackLimits {
        max_entries: 32,
        max_object_bytes: 4 * 1024,
        max_total_expanded_bytes: 8 * 1024,
        max_input_bytes: 16 * 1024,
        ..PackLimits::default()
    }
}

#[test]
fn seeded_pack_mutators_return_a_pack_or_typed_refusal_without_panicking() {
    let original = valid_pack();
    let limits = bounded_limits();
    let mut random = Lcg::new(FUZZ_SEED);
    let mut accepted = 0_usize;
    let mut refused = 0_usize;

    for case in 0..CASE_DENOMINATOR {
        let kind = MutationKind::ALL[case % MutationKind::ALL.len()];
        let input = mutate(original.clone(), kind, &mut random);
        let result = catch_unwind(AssertUnwindSafe(|| {
            read_verified_pack(
                &input,
                ObjectFormat::Sha1,
                &limits,
                &mut || true,
                &NativeChecksumVerifier,
            )
        }));
        let result = result.unwrap_or_else(|_| {
            panic!(
                "seeded pack mutator panicked: seed=0x{FUZZ_SEED:016x} case={case} kind={}",
                kind.as_str()
            )
        });
        match result {
            Ok(_) => accepted = accepted.checked_add(1).expect("bounded case count"),
            Err(error) => {
                let _: PackError = error;
                refused = refused.checked_add(1).expect("bounded case count");
            }
        }
    }

    assert_eq!(accepted + refused, CASE_DENOMINATOR);
    println!(
        "{{\"schema\":\"frankengit.pack-fuzz.v1\",\"seed\":\"0x{FUZZ_SEED:016x}\",\"corpus_denominator\":{CASE_DENOMINATOR},\"accepted\":{accepted},\"typed_refusals\":{refused},\"non_claim\":\"deterministic mutation evidence; not exhaustive fuzzing\"}}"
    );
}
