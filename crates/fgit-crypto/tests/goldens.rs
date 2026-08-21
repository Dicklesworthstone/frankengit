//! The checked-in golden corpus, and the assertion that `fgit-crypto`
//! reproduces it.
//!
//! Every expected digest in `goldens/*.tsv` was derived by `goldens/derive.py`
//! using Python's `hashlib`, an implementation with no relationship to the
//! Rust under test, and cross-checked against coreutils `sha1sum`/`sha256sum`.
//! Nothing here regenerates a vector from this crate's own output.

use fgit_crypto::{
    DigestHasher, GitObjectKind, GitOid, IdentityDomain, NativeObjectIdentity, SchemaFamily,
    SchemaId, Sha1, Sha1Hasher, Sha256, Sha256Hasher, export_algorithm_registry,
    export_domain_registry, internal_digest_in_domain, internal_id_preimage, lowercase_hex,
    sha1_digest, sha256_digest,
};

const DIGEST_VECTORS: &str = include_str!("../goldens/digest_vectors.tsv");
const GIT_OID_VECTORS: &str = include_str!("../goldens/git_oid_vectors.tsv");
const INTERNAL_ID_VECTORS: &str = include_str!("../goldens/internal_id_vectors.tsv");
const ALGORITHM_REGISTRY_GOLDEN: &str = include_str!("../goldens/algorithm_registry.tsv");
const DOMAIN_REGISTRY_GOLDEN: &str = include_str!("../goldens/domain_registry.tsv");

/// Data rows of a golden file: everything after the marker and header lines.
fn data_rows(text: &str) -> Vec<Vec<&str>> {
    text.lines()
        .skip(2)
        .filter(|line| !line.is_empty())
        .map(|line| line.split('\t').collect())
        .collect()
}

/// Expand a `hex:...` or `repeat:<byte>:<count>` message specification.
fn spec_bytes(spec: &str) -> Vec<u8> {
    let (kind, rest) = spec.split_once(':').expect("a spec has a kind prefix");
    match kind {
        "hex" => decode_hex(rest),
        "repeat" => {
            let (byte, count) = rest.split_once(':').expect("a repeat spec has a count");
            let unit = decode_hex(byte);
            let count: usize = count.parse().expect("a repeat count is a number");
            unit.repeat(count)
        }
        other => panic!("unknown message spec kind `{other}`"),
    }
}

fn decode_hex(text: &str) -> Vec<u8> {
    assert!(text.len() % 2 == 0, "hex input has an even length");
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = nibble(pair[0]);
            let low = nibble(pair[1]);
            (high << 4) | low
        })
        .collect()
}

fn nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        other => panic!("`{}` is not a lowercase hex digit", char::from(other)),
    }
}

#[test]
fn fips_180_4_known_answer_vectors_hold_for_both_constructions() {
    let rows = data_rows(DIGEST_VECTORS);
    assert!(
        rows.len() >= 14,
        "the digest corpus must not shrink silently"
    );
    for row in rows {
        assert_eq!(row.len(), 5, "a digest vector row has five columns");
        let (identifier, spec, sha1_expected, sha256_expected) = (row[0], row[1], row[2], row[3]);
        let message = spec_bytes(spec);
        assert_eq!(
            lowercase_hex(&sha1_digest(&message)),
            sha1_expected,
            "{identifier}: SHA-1"
        );
        assert_eq!(
            lowercase_hex(&sha256_digest(&message)),
            sha256_expected,
            "{identifier}: SHA-256"
        );
    }
}

#[test]
fn streaming_absorption_matches_one_shot_for_every_chunk_width() {
    // The chunk widths straddle the 64-byte compression block so that a
    // buffering bug cannot hide behind an aligned split.
    let widths = [1_usize, 3, 7, 31, 63, 64, 65, 127, 1000];
    for row in data_rows(DIGEST_VECTORS) {
        assert_eq!(row.len(), 5, "a digest vector row has five columns");
        let message = spec_bytes(row[1]);
        if message.len() > 4096 {
            continue;
        }
        for width in widths {
            let mut narrow = Sha1Hasher::new();
            let mut wide = Sha256Hasher::new();
            for chunk in message.chunks(width) {
                DigestHasher::update(&mut narrow, chunk);
                DigestHasher::update(&mut wide, chunk);
            }
            assert_eq!(
                lowercase_hex(&DigestHasher::finish(narrow)),
                row[2],
                "{}: SHA-1 in {width}-byte chunks",
                row[0]
            );
            assert_eq!(
                lowercase_hex(&DigestHasher::finish(wide)),
                row[3],
                "{}: SHA-256 in {width}-byte chunks",
                row[0]
            );
        }
    }
}

#[test]
fn native_git_object_identities_match_the_golden_corpus() {
    let rows = data_rows(GIT_OID_VECTORS);
    assert!(
        rows.len() >= 8,
        "the object corpus must not shrink silently"
    );
    for row in rows {
        assert_eq!(row.len(), 6, "an object vector row has six columns");
        let (identifier, label, spec, sha1_expected, sha256_expected) =
            (row[0], row[1], row[2], row[3], row[4]);
        let kind = GitObjectKind::from_label(label).expect("a corpus label is a Git object type");
        let content = spec_bytes(spec);

        let narrow = GitOid::<Sha1>::of_object(kind, &content);
        let wide = GitOid::<Sha256>::of_object(kind, &content);
        assert_eq!(
            narrow.to_string(),
            sha1_expected,
            "{identifier}: SHA-1 identity"
        );
        assert_eq!(
            wide.to_string(),
            sha256_expected,
            "{identifier}: SHA-256 identity"
        );
    }
}

#[test]
fn streaming_object_hashing_matches_the_golden_corpus() {
    for row in data_rows(GIT_OID_VECTORS) {
        assert_eq!(row.len(), 6, "an object vector row has six columns");
        let kind = GitObjectKind::from_label(row[1]).expect("a corpus label is a Git object type");
        let content = spec_bytes(row[2]);
        let declared = u64::try_from(content.len()).expect("corpus bodies fit in u64");

        let mut narrow = GitOid::<Sha1>::object_hasher(kind, declared);
        for chunk in content.chunks(7) {
            narrow
                .update(chunk)
                .expect("chunks within the declared length");
        }
        assert_eq!(
            narrow
                .finish()
                .expect("the exact declared length")
                .to_string(),
            row[3],
            "{}: streamed SHA-1 identity",
            row[0]
        );

        let mut wide = GitOid::<Sha256>::object_hasher(kind, declared);
        for chunk in content.chunks(13) {
            wide.update(chunk)
                .expect("chunks within the declared length");
        }
        assert_eq!(
            wide.finish()
                .expect("the exact declared length")
                .to_string(),
            row[4],
            "{}: streamed SHA-256 identity",
            row[0]
        );
    }
}

#[test]
fn internal_identity_preimages_and_digests_match_the_golden_corpus() {
    let rows = data_rows(INTERNAL_ID_VECTORS);
    assert!(
        rows.len() >= 11,
        "the identity corpus must not shrink silently"
    );
    for row in rows {
        assert_eq!(row.len(), 9, "an identity vector row has nine columns");
        let (identifier, tag, family, major, minor, spec, preimage_expected, digest_expected) = (
            row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7],
        );
        let domain = IdentityDomain::from_tag(tag).expect("a corpus tag is a registered domain");
        let schema = SchemaId::new(
            SchemaFamily::try_new(family.as_bytes()).expect("a corpus family is a canonical label"),
            major.parse().expect("a corpus major version is a number"),
            minor.parse().expect("a corpus minor version is a number"),
        );
        let body = spec_bytes(spec);

        let preimage = internal_id_preimage(domain, schema, &body);
        assert_eq!(
            lowercase_hex(&preimage),
            preimage_expected,
            "{identifier}: preimage framing"
        );
        assert_eq!(
            lowercase_hex(&internal_digest_in_domain(domain, schema, &body)),
            digest_expected,
            "{identifier}: identity digest"
        );
    }
}

#[test]
fn length_prefixed_framing_separates_a_shifted_field_boundary() {
    // IV-002 and IV-008 differ only in where the boundary between the schema
    // family and the body falls. Bare concatenation would give them the same
    // preimage; the length prefixes are what keep them apart.
    let rows = data_rows(INTERNAL_ID_VECTORS);
    let find = |identifier: &str| -> Vec<&str> {
        rows.iter()
            .find(|row| row.first() == Some(&identifier))
            .expect("the requested corpus row is present")
            .clone()
    };
    let shared = find("IV-002");
    let shifted = find("IV-008");
    assert_eq!(shared.len(), 9, "an identity vector row has nine columns");
    assert_eq!(shifted.len(), 9, "an identity vector row has nine columns");
    assert_ne!(shared[6], shifted[6], "the two preimages must differ");
    assert_ne!(shared[7], shifted[7], "the two digests must differ");

    let concatenated = |row: &[&str]| {
        format!(
            "{}{}{}",
            row[1],
            row[2],
            String::from_utf8(spec_bytes(row[5])).expect("the corpus bodies are text here")
        )
    };
    assert_eq!(
        concatenated(&shared),
        concatenated(&shifted),
        "the two rows are exactly the ambiguity a bare concatenation would collapse"
    );
}

#[test]
fn algorithm_registry_export_matches_the_golden_corpus() {
    assert_eq!(export_algorithm_registry(), ALGORITHM_REGISTRY_GOLDEN);
}

#[test]
fn domain_registry_export_matches_the_golden_corpus() {
    assert_eq!(export_domain_registry(), DOMAIN_REGISTRY_GOLDEN);
}
