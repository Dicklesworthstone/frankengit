#![forbid(unsafe_code)]
//! Deterministic mutation evidence for the public pack admission boundary.
//!
//! The seeded cases are deliberately kept in the crate test target: they do
//! not invoke foreign Git and can therefore exercise the same bounded Rust
//! parser used by the differential E2E lane.

use std::panic::{AssertUnwindSafe, catch_unwind};

use fgit_pack::{
    NativeChecksumVerifier, ObjectFormat, PackError, PackLimits, ScalarResolver, read_verified_pack,
};

const FUZZ_SEED: u64 = 0x8d21_15e6_7f40_b93c;
const CASE_DENOMINATOR: usize = 256;
const BASE_PAYLOAD: &[u8] = b"fuzz-base";
const BASE_PAYLOAD_START: usize = 20;

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
            Self::BitFlip => "payload_bit_flip",
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

fn valid_pack() -> (Vec<u8>, u64) {
    let mut pack = b"PACK\0\0\0\x02".to_vec();
    pack.extend_from_slice(&3_u32.to_be_bytes());
    let base_offset = u64::try_from(pack.len()).expect("fixture offset fits u64");
    let base = BASE_PAYLOAD;
    pack.extend_from_slice(&base_entry(base));

    let delta_program = copy_all_delta(base.len());
    let first_delta_offset = append_ofs_delta(&mut pack, base_offset, &delta_program);
    let second_delta_offset = append_ofs_delta(&mut pack, first_delta_offset, &delta_program);
    append_sha1_trailer(&mut pack);
    (pack, second_delta_offset)
}

fn base_entry(payload: &[u8]) -> Vec<u8> {
    let length = u8::try_from(payload.len()).expect("small fuzz fixture");
    assert!(length < 16, "fuzz fixture uses one-byte pack entry header");
    let mut entry = vec![0x30 | length];
    entry.extend_from_slice(&zlib_stored(payload));
    entry
}

fn zlib_stored(payload: &[u8]) -> Vec<u8> {
    let stored_length = u16::try_from(payload.len()).expect("small stored member");
    let mut member = vec![0x78, 0x01, 0x01];
    member.extend_from_slice(&stored_length.to_le_bytes());
    member.extend_from_slice(&(!stored_length).to_le_bytes());
    member.extend_from_slice(payload);
    member.extend_from_slice(&adler32(payload).to_be_bytes());
    member
}

fn append_ofs_delta(pack: &mut Vec<u8>, base_offset: u64, program: &[u8]) -> u64 {
    let offset = u64::try_from(pack.len()).expect("fixture offset fits u64");
    let distance = offset
        .checked_sub(base_offset)
        .expect("fixture delta is emitted after its base");
    let distance = u8::try_from(distance).expect("fixture OFS distance stays one byte");
    let program_length = u8::try_from(program.len()).expect("fixture program stays compact");
    assert!(
        program_length < 16,
        "fixture uses one-byte pack entry header"
    );
    pack.push(0x60 | program_length);
    pack.push(distance);
    pack.extend_from_slice(&zlib_stored(program));
    offset
}

fn copy_all_delta(base_length: usize) -> Vec<u8> {
    let length = u8::try_from(base_length).expect("fixture base stays compact");
    vec![length, length, 0x91, 0, length]
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

fn append_sha1_trailer(pack: &mut Vec<u8>) {
    let trailer = fgit_crypto::sha1_digest(pack);
    pack.extend_from_slice(&trailer);
}

fn rewrite_sha1_trailer(pack: &mut [u8]) {
    let trailer_start = pack
        .len()
        .checked_sub(20)
        .expect("fixture always carries a SHA-1 trailer");
    let trailer = fgit_crypto::sha1_digest(&pack[..trailer_start]);
    pack[trailer_start..].copy_from_slice(&trailer);
}

fn rewrite_base_payload_adler32(pack: &mut [u8]) {
    let payload_end = BASE_PAYLOAD_START
        .checked_add(BASE_PAYLOAD.len())
        .expect("fixture payload boundary fits usize");
    let adler_end = payload_end
        .checked_add(4)
        .expect("fixture Adler-32 boundary fits usize");
    let checksum = adler32(&pack[BASE_PAYLOAD_START..payload_end]);
    pack[payload_end..adler_end].copy_from_slice(&checksum.to_be_bytes());
}

fn mutate(mut pack: Vec<u8>, kind: MutationKind, random: &mut Lcg) -> Vec<u8> {
    let body_length = pack
        .len()
        .checked_sub(20)
        .expect("fixture always carries a SHA-1 trailer");
    match kind {
        MutationKind::BitFlip => {
            let index = BASE_PAYLOAD_START + random.index(BASE_PAYLOAD.len());
            let bit = 1_u8 << random.index(8);
            pack[index] ^= bit;
            rewrite_base_payload_adler32(&mut pack);
            rewrite_sha1_trailer(&mut pack);
        }
        MutationKind::Truncate => {
            pack.truncate(random.index(body_length));
            append_sha1_trailer(&mut pack);
        }
        MutationKind::HeaderCount => {
            let count = random.next().to_be_bytes();
            pack[8..12].copy_from_slice(&count[4..]);
            rewrite_sha1_trailer(&mut pack);
        }
        MutationKind::EntryLength => {
            let first_entry = 12_usize;
            pack[first_entry] ^= 0x0f;
            rewrite_sha1_trailer(&mut pack);
        }
        MutationKind::Trailer => {
            let trailer_index = pack.len() - 1 - random.index(20);
            pack[trailer_index] ^= 1_u8 << random.index(8);
        }
    }
    pack
}

fn exercise_reader_and_delta_resolver(
    input: &[u8],
    limits: &PackLimits,
    target_offset: u64,
) -> Result<(), PackError> {
    let objects = read_verified_pack(
        input,
        ObjectFormat::Sha1,
        limits,
        &mut || true,
        &NativeChecksumVerifier,
    )?
    .into_scalar_objects(|_| None)?;
    let resolver = ScalarResolver::new(&objects, &(), limits, &mut || true)?;
    resolver
        .resolve_offset(target_offset, &mut || true)
        .map(|_| ())
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
fn seeded_pack_mutators_reach_parser_and_delta_resolution_without_panicking() {
    let (original, target_offset) = valid_pack();
    let limits = bounded_limits();
    exercise_reader_and_delta_resolver(&original, &limits, target_offset)
        .expect("the signed OFS-delta seed corpus is a permitted pack");
    let mut random = Lcg::new(FUZZ_SEED);
    let mut accepted = 0_usize;
    let mut refused = 0_usize;
    let mut re_signed_structural_cases = 0_usize;
    let mut delta_resolver_cases = 0_usize;
    let mut trailer_gate_cases = 0_usize;

    for case in 0..CASE_DENOMINATOR {
        let kind = MutationKind::ALL[case % MutationKind::ALL.len()];
        let input = mutate(original.clone(), kind, &mut random);
        let result = catch_unwind(AssertUnwindSafe(|| {
            exercise_reader_and_delta_resolver(&input, &limits, target_offset)
        }));
        let result = result.unwrap_or_else(|_| {
            panic!(
                "seeded pack mutator panicked: seed=0x{FUZZ_SEED:016x} case={case} kind={}",
                kind.as_str()
            )
        });
        match (kind, result) {
            (MutationKind::BitFlip, Ok(())) => {
                re_signed_structural_cases = re_signed_structural_cases
                    .checked_add(1)
                    .expect("bounded structural case count");
                delta_resolver_cases = delta_resolver_cases
                    .checked_add(1)
                    .expect("bounded delta-resolver case count");
                accepted = accepted.checked_add(1).expect("bounded case count");
            }
            (MutationKind::BitFlip, outcome) => {
                panic!(
                    "re-signed payload mutation did not resolve its OFS chain: seed=0x{FUZZ_SEED:016x} case={case} outcome={outcome:?}"
                );
            }
            (MutationKind::Trailer, Err(PackError::TrailerChecksumMismatch)) => {
                trailer_gate_cases = trailer_gate_cases
                    .checked_add(1)
                    .expect("bounded trailer case count");
                refused = refused.checked_add(1).expect("bounded case count");
            }
            (MutationKind::Trailer, outcome) => {
                panic!(
                    "trailer mutation did not stop at the integrity gate: seed=0x{FUZZ_SEED:016x} case={case} outcome={outcome:?}"
                );
            }
            (_, Err(PackError::TrailerChecksumMismatch)) => {
                panic!(
                    "re-signed structural mutation stopped at the trailer gate: seed=0x{FUZZ_SEED:016x} case={case} kind={}",
                    kind.as_str()
                );
            }
            (_, Ok(())) => {
                re_signed_structural_cases = re_signed_structural_cases
                    .checked_add(1)
                    .expect("bounded structural case count");
                accepted = accepted.checked_add(1).expect("bounded case count");
            }
            (_, Err(error)) => {
                let _: PackError = error;
                re_signed_structural_cases = re_signed_structural_cases
                    .checked_add(1)
                    .expect("bounded structural case count");
                refused = refused.checked_add(1).expect("bounded case count");
            }
        }
    }

    assert_eq!(accepted + refused, CASE_DENOMINATOR);
    assert_eq!(
        re_signed_structural_cases + trailer_gate_cases,
        CASE_DENOMINATOR,
        "every case is either a re-signed structural mutation or an intentional trailer refusal"
    );
    assert_eq!(
        delta_resolver_cases, 52,
        "every deterministic re-signed payload mutation must traverse the OFS resolver"
    );
    println!(
        "{{\"schema\":\"frankengit.pack-fuzz.v1\",\"seed\":\"0x{FUZZ_SEED:016x}\",\"corpus_denominator\":{CASE_DENOMINATOR},\"re_signed_structural_cases\":{re_signed_structural_cases},\"delta_resolver_cases\":{delta_resolver_cases},\"trailer_gate_cases\":{trailer_gate_cases},\"accepted\":{accepted},\"typed_refusals\":{refused},\"non_claim\":\"deterministic mutation evidence over a signed OFS-delta seed corpus; not exhaustive fuzzing\"}}"
    );
}
