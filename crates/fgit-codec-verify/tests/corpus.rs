// The independent verification pass over the committed golden corpus.
//
// Nothing here imports `fgit-codec`. If this agrees with that crate, two
// implementations that share no code agree; if it disagrees, one of them is
// wrong and the corpus is what says so.

use std::path::{Path, PathBuf};

use fgit_codec_verify::{
    CORPUS_ALGORITHM_CODE_POINT, corpus_digest, default_corpus_directory, derive_body_id, hex,
    identity_preimage, load_corpus, parse_frame, verify_corpus,
};

fn corpus_dir() -> PathBuf {
    let directory = default_corpus_directory();
    assert!(
        directory.is_dir(),
        "golden corpus not found at {}",
        directory.display()
    );
    directory
}

#[test]
fn every_canonical_vector_re_derives_to_its_recorded_identity() {
    let report = verify_corpus(&corpus_dir()).expect("the corpus loads");
    assert!(
        report.is_clean(),
        "independent verification disagreed with the corpus:\n  {}",
        report.failures.join("\n  ")
    );
    assert!(
        report.valid_confirmed >= 6,
        "expected a canonical vector per identity-bearing schema, confirmed {}",
        report.valid_confirmed
    );
}

#[test]
fn the_verifier_covers_one_hundred_percent_of_the_canonical_vectors() {
    // The acceptance line is "100% of goldens verified by the independent
    // verifier", so count rather than assume: every record marked valid must
    // have been confirmed, with none silently skipped.
    let records = load_corpus(&corpus_dir()).expect("the corpus loads");
    let valid = records.iter().filter(|record| record.is_valid()).count();
    let report = verify_corpus(&corpus_dir()).expect("the corpus loads");
    assert_eq!(
        report.valid_confirmed, valid,
        "{} canonical vectors in the corpus but only {} confirmed",
        valid, report.valid_confirmed
    );
    assert_eq!(
        report.invalid_rejected + report.invalid_parsed.len(),
        records.len() - valid,
        "every planted defect must be accounted for, rejected or explained"
    );
}

#[test]
fn every_canonical_vector_records_a_frame_length_and_an_identity() {
    // A vector with no recorded identity would pass verification vacuously.
    let records = load_corpus(&corpus_dir()).expect("the corpus loads");
    for record in records.iter().filter(|record| record.is_valid()) {
        assert!(
            record.body_id.is_some(),
            "{}: canonical vector records no identity, so nothing is checked",
            record.name
        );
        assert!(record.frame_len.is_some(), "{}: no frame_len", record.name);
        assert!(
            record.canonical_body_len.is_some(),
            "{}: no canonical_body_len",
            record.name
        );
    }
}

#[test]
fn every_planted_defect_that_targets_the_frame_is_also_rejected_here() {
    // Only defects a reader can judge WITHOUT knowing what was expected belong
    // here: a bad magic, a codec major this reader does not implement, a
    // truncated payload, a trailing byte.
    //
    // `schema_major_bumped` and `domain_swapped` are deliberately NOT in this
    // list, and an earlier version of this test wrongly included the first.
    // A frame reader has no expectation to compare a schema major or a domain
    // against — it learns both from the frame itself — so both produce a
    // perfectly well-formed frame that simply names something else. Refusing
    // them belongs to the typed decoder that knows what it asked for, and
    // those two are asserted separately below.
    let records = load_corpus(&corpus_dir()).expect("the corpus loads");
    let frame_level = [
        "magic_corrupted",
        "codec_major_bumped",
        "payload_truncated",
        "trailing_byte_appended",
    ];
    let mut checked = 0;
    for record in records.iter().filter(|record| !record.is_valid()) {
        let Some(mutation) = record.mutation.as_deref() else {
            continue;
        };
        if !frame_level.contains(&mutation) {
            continue;
        }
        assert!(
            parse_frame(&record.bytes).is_err(),
            "{}: planted defect {mutation} parsed cleanly here, so the corpus \
             is weaker than it claims",
            record.name
        );
        checked += 1;
    }
    assert!(
        checked >= 20,
        "expected many frame-level defects, saw {checked}"
    );
}

#[test]
fn a_bumped_schema_major_parses_but_declares_a_version_this_reader_does_not_know() {
    // The counterpart to the exclusion above. The mutation is well formed, so
    // a frame reader must accept it and report the bumped version rather than
    // guess; the refusal is the typed decoder's, because only it knows which
    // major it wanted.
    let records = load_corpus(&corpus_dir()).expect("the corpus loads");
    let mut checked = 0;
    for record in records
        .iter()
        .filter(|record| record.mutation.as_deref() == Some("schema_major_bumped"))
    {
        let frame = parse_frame(&record.bytes).unwrap_or_else(|error| {
            panic!(
                "{}: a bumped schema major is still a well-formed frame: {error}",
                record.name
            )
        });
        assert_ne!(
            frame.schema_major, 1,
            "{}: the bump should have moved the schema major off 1",
            record.name
        );
        checked += 1;
    }
    assert!(
        checked >= 5,
        "expected a bumped-schema-major case per schema, saw {checked}"
    );
}

#[test]
fn a_swapped_domain_parses_but_names_a_different_domain() {
    // This defect is deliberately NOT a framing error: the tag is well formed,
    // it is simply the wrong one. A frame reader must accept it and report the
    // wrong domain, leaving the refusal to the layer that knows what it wanted.
    let records = load_corpus(&corpus_dir()).expect("the corpus loads");
    let mut checked = 0;
    for record in records
        .iter()
        .filter(|record| record.mutation.as_deref() == Some("domain_swapped"))
    {
        let frame = parse_frame(&record.bytes).unwrap_or_else(|error| {
            panic!(
                "{}: a swapped domain is still a valid frame: {error}",
                record.name
            )
        });
        assert_ne!(
            frame.domain, frame.family,
            "{}: the swapped tag should no longer match its family",
            record.name
        );
        checked += 1;
    }
    assert!(
        checked >= 5,
        "expected a swapped-domain case per schema, saw {checked}"
    );
}

#[test]
fn identity_depends_on_the_payload_the_domain_and_the_schema() {
    // Re-derived independently, so this is not the codec crate agreeing with
    // itself: changing any input to the preimage must change the digest.
    let base = identity_preimage("frankengit/txn-seal/v1", "txn-seal", 1, 0, b"body");
    for (domain, family, major, minor, body) in [
        ("frankengit/rcr/v1", "txn-seal", 1, 0, &b"body"[..]),
        ("frankengit/txn-seal/v1", "rcr", 1, 0, b"body"),
        ("frankengit/txn-seal/v1", "txn-seal", 2, 0, b"body"),
        ("frankengit/txn-seal/v1", "txn-seal", 1, 1, b"body"),
        ("frankengit/txn-seal/v1", "txn-seal", 1, 0, b"bodz"),
    ] {
        let other = identity_preimage(domain, family, major, minor, body);
        assert_ne!(base, other, "preimage collision for {domain}/{family}");
        assert_ne!(
            corpus_digest(&base),
            corpus_digest(&other),
            "digest collision for {domain}/{family}"
        );
    }
}

#[test]
fn the_length_prefix_is_what_separates_a_label_from_its_neighbour() {
    // Without the length prefixes the preimage would be plain concatenation,
    // and these two would collide. That is the classic ambiguity the framing
    // exists to prevent, so it is worth an explicit vector.
    let left = identity_preimage("ab", "c", 1, 0, b"");
    let right = identity_preimage("a", "bc", 1, 0, b"");
    assert_ne!(left, right, "concatenation ambiguity between labels");
    assert_ne!(corpus_digest(&left), corpus_digest(&right));
}

#[test]
fn every_domain_the_corpus_uses_appears_in_the_crypto_domain_registry() {
    // Cross-checks the corpus against CloudyTiger's exported registry rows as
    // data, without depending on that crate.
    let registry = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fgit-crypto")
        .join("goldens")
        .join("domain_registry.tsv");
    let text = std::fs::read_to_string(&registry)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", registry.display()));

    let mut tags = Vec::new();
    for line in text.lines() {
        if line.starts_with('#') || line.starts_with("id\t") || line.trim().is_empty() {
            continue;
        }
        let mut columns = line.split('\t');
        let _id = columns.next();
        if let Some(tag) = columns.next() {
            tags.push(tag.to_owned());
        }
    }
    assert!(
        tags.len() >= 25,
        "registry looks truncated: {} rows",
        tags.len()
    );

    let records = load_corpus(&corpus_dir()).expect("the corpus loads");
    let mut seen = Vec::new();
    for record in records.iter().filter(|record| record.is_valid()) {
        let frame = parse_frame(&record.bytes).expect("canonical vectors parse");
        assert!(
            tags.contains(&frame.domain),
            "{}: domain {} has no row in the crypto domain registry",
            record.name,
            frame.domain
        );
        if !seen.contains(&frame.domain) {
            seen.push(frame.domain.clone());
        }
    }
    assert!(
        seen.len() >= 6,
        "expected every identity-bearing schema's domain, saw {seen:?}"
    );
}

#[test]
fn the_recorded_identities_use_the_reserved_corpus_algorithm_slot() {
    // A canonical vector recorded under a production algorithm slot would be
    // claiming cryptographic weight the corpus digest does not carry.
    let records = load_corpus(&corpus_dir()).expect("the corpus loads");
    let marker = format!("/alg:{CORPUS_ALGORITHM_CODE_POINT}/");
    for record in records.iter().filter(|record| record.is_valid()) {
        let body_id = record.body_id.as_ref().expect("valid vectors record one");
        assert!(
            body_id.contains(&marker),
            "{}: identity {body_id} does not use the reserved corpus slot",
            record.name
        );
    }
}

#[test]
fn hex_rendering_round_trips_and_is_lowercase() {
    let bytes: Vec<u8> = (0..=255_u16)
        .map(|value| u8::try_from(value).unwrap_or(0))
        .collect();
    let rendered = hex(&bytes);
    assert_eq!(rendered.len(), bytes.len() * 2);
    assert_eq!(rendered, rendered.to_lowercase());
    assert!(rendered.starts_with("000102"));
    assert!(rendered.ends_with("fdfeff"));
}

#[test]
fn a_frame_with_a_lying_length_prefix_is_rejected() {
    // Built here rather than taken from the corpus, so the verifier is shown
    // refusing input the corpus never contained.
    let records = load_corpus(&corpus_dir()).expect("the corpus loads");
    let seal = records
        .iter()
        .find(|record| record.name == "txn-seal__canonical")
        .expect("the seal golden exists");
    let frame = parse_frame(&seal.bytes).expect("it parses as committed");

    // The payload length prefix is the last four bytes before the payload.
    let prefix_at = seal.bytes.len() - frame.payload.len() - 4;
    let mut inflated = seal.bytes.clone();
    inflated[prefix_at..prefix_at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(
        parse_frame(&inflated).is_err(),
        "a payload length of u32::MAX must be refused before allocating"
    );

    let mut deflated = seal.bytes.clone();
    deflated[prefix_at..prefix_at + 4].copy_from_slice(&0_u32.to_be_bytes());
    assert!(
        parse_frame(&deflated).is_err(),
        "shrinking the payload length must leave trailing bytes and be refused"
    );

    // Permitted counterpart: the untouched frame still parses.
    assert!(parse_frame(&seal.bytes).is_ok());
}

#[test]
fn the_verifier_derives_the_same_identity_twice() {
    let records = load_corpus(&corpus_dir()).expect("the corpus loads");
    for record in records.iter().filter(|record| record.is_valid()) {
        let frame = parse_frame(&record.bytes).expect("parses");
        let first = derive_body_id(&frame, CORPUS_ALGORITHM_CODE_POINT);
        let second = derive_body_id(&frame, CORPUS_ALGORITHM_CODE_POINT);
        assert_eq!(
            first, second,
            "{}: derivation is not deterministic",
            record.name
        );
    }
}
