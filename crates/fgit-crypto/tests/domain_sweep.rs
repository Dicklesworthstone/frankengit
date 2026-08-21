//! A deterministic sweep over the whole identity-domain registry.
//!
//! The hand-written boundary tests pick three domains and one body. That is
//! enough to show the mechanism works and nothing like enough to show it holds
//! across the registry. This sweep computes an identity for every
//! (domain, schema, body) triple in a fixed grid, asserts that no two distinct
//! triples share a digest, and asserts that every identity verifies under its
//! own triple and produces a typed refusal under every other domain.
//!
//! Randomness is a `SplitMix64` stream with a fixed seed, so a failure is
//! reproducible from the message alone. This is a bounded deterministic sweep,
//! not a shrinking property engine and not a proof: it samples a grid, it does
//! not quantify over all inputs.

use std::collections::HashMap;

use fgit_crypto::{
    CodecVersion, IdentityDomain, InternalIdentityError, SchemaFamily, SchemaId,
    internal_digest_in_domain, internal_object_id, lowercase_hex, verify_internal_object_id,
};

/// Fixed seed, quoted in every failure message so a failure reproduces.
const SEED: u64 = 0x0f00_d000_cafe_1234;

/// `SplitMix64`: a small, exactly specified generator with no dependency.
struct SplitMix64(u64);

impl SplitMix64 {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    const fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut word = self.0;
        word = (word ^ (word >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        word = (word ^ (word >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        word ^ (word >> 31)
    }

    /// A pseudorandom body of the requested length.
    fn body(&mut self, len: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(len);
        while bytes.len() < len {
            bytes.extend_from_slice(&self.next_u64().to_be_bytes());
        }
        bytes.truncate(len);
        bytes
    }
}

fn schemas() -> Vec<SchemaId> {
    let families = [
        "frankengit.canonical-body",
        "frankengit.microsegment",
        "frankengit.generation",
    ];
    let mut out = Vec::new();
    for family in families {
        let family =
            SchemaFamily::try_new(family.as_bytes()).expect("a sweep family is a canonical label");
        out.push(SchemaId::new(family, 1, 0));
        out.push(SchemaId::new(family, 2, 7));
    }
    out
}

/// Body lengths chosen to straddle the SHA-256 padding transitions, so a
/// framing bug cannot hide behind a convenient length.
const BODY_LENGTHS: [usize; 7] = [0, 1, 31, 55, 56, 64, 129];

#[test]
fn no_two_distinct_identity_inputs_share_a_digest() {
    let mut generator = SplitMix64::new(SEED);
    let schema_grid = schemas();
    let mut seen: HashMap<String, (String, String, usize)> = HashMap::new();
    let mut computed = 0_usize;

    for length in BODY_LENGTHS {
        let body = generator.body(length);
        for domain in IdentityDomain::ALL.iter().copied() {
            for schema in &schema_grid {
                let digest = lowercase_hex(&internal_digest_in_domain(domain, *schema, &body));
                let key = (
                    domain.tag().to_owned(),
                    format!("{}/{}.{}", schema.family(), schema.major(), schema.minor()),
                    length,
                );
                if let Some(previous) = seen.insert(digest.clone(), key.clone()) {
                    panic!(
                        "seed {SEED:#x}: digest {digest} collides between {previous:?} and {key:?}"
                    );
                }
                computed += 1;
            }
        }
    }

    assert_eq!(
        computed,
        BODY_LENGTHS.len() * IdentityDomain::ALL.len() * schema_grid.len(),
        "the sweep must cover the whole grid"
    );
    assert_eq!(seen.len(), computed, "every grid point is distinct");
}

#[test]
fn every_identity_verifies_under_its_own_domain_and_refuses_every_other() {
    let mut generator = SplitMix64::new(SEED);
    let schema = SchemaId::new(
        SchemaFamily::try_new(b"frankengit.canonical-body").expect("a canonical family"),
        1,
        0,
    );
    let codec = CodecVersion::new(1, 0);

    for length in BODY_LENGTHS {
        let body = generator.body(length);
        for domain in IdentityDomain::ALL.iter().copied() {
            let identity = internal_object_id(domain, schema, codec, &body);
            assert_eq!(
                verify_internal_object_id(&identity, domain, schema, codec, &body),
                Ok(()),
                "seed {SEED:#x}: {domain} must verify under its own domain at length {length}"
            );

            for other in IdentityDomain::ALL.iter().copied() {
                if other == domain {
                    continue;
                }
                // Not `expect_err(&format!(..))`: that allocates the message
                // on every passing iteration, and clippy refuses it.
                let refusal = match verify_internal_object_id(
                    &identity, other, schema, codec, &body,
                ) {
                    Ok(()) => panic!(
                        "seed {SEED:#x}: {domain} identity must not verify as {other} at length {length}"
                    ),
                    Err(refusal) => refusal,
                };
                match refusal {
                    InternalIdentityError::DomainMismatch { expected, actual } => {
                        assert_eq!(expected, other.tag());
                        assert_eq!(actual, domain.tag());
                    }
                    other_refusal => panic!(
                        "seed {SEED:#x}: expected a typed domain mismatch, got {other_refusal}"
                    ),
                }
            }
        }
    }
}

#[test]
fn a_single_flipped_body_bit_changes_every_domains_identity() {
    let mut generator = SplitMix64::new(SEED);
    let schema = SchemaId::new(
        SchemaFamily::try_new(b"frankengit.canonical-body").expect("a canonical family"),
        1,
        0,
    );
    let body = generator.body(64);

    for bit in [0_usize, 1, 7, 8, 255, 511] {
        let mut mutated = body.clone();
        let index = bit / 8;
        mutated[index] ^= 1 << (bit % 8);
        assert_ne!(mutated, body, "the mutation must change the body");

        for domain in IdentityDomain::ALL.iter().copied() {
            assert_ne!(
                internal_digest_in_domain(domain, schema, &body),
                internal_digest_in_domain(domain, schema, &mutated),
                "seed {SEED:#x}: {domain} must not ignore bit {bit}"
            );
        }
    }
}
