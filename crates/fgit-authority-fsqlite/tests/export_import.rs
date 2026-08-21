//! Export and import: a round trip, and every internal claim checked.
//!
//! Import is where untrusted bytes become authority state, so most of this file
//! is refusals. Each is paired with the admissible bundle it was derived from,
//! so the tests show what makes a bundle valid rather than only what breaks it.

use fgit_authority_fsqlite::{
    BundleRefusal, ExportBundle, ExportedBody, ExportedHead, ExportedIssuance, export_bundle,
    import_bundle,
};

fn issuance(sequence: u64, token: u8, generation: u64, body: &[u8]) -> ExportedIssuance {
    ExportedIssuance {
        token: vec![token; 16],
        sequence,
        head_key: b"repo/head".to_vec(),
        generation,
        body: body.to_vec(),
    }
}

/// A bundle that is valid in every respect; every refusal test damages a copy.
fn admissible() -> ExportBundle {
    ExportBundle {
        schema_version: 1,
        instance: 7,
        bodies: vec![
            ExportedBody {
                key: b"body/a".to_vec(),
                body: b"alpha".to_vec(),
            },
            ExportedBody {
                key: b"body/b".to_vec(),
                body: b"beta".to_vec(),
            },
        ],
        head: Some(ExportedHead {
            key: b"repo/head".to_vec(),
            token: vec![0x02; 16],
            generation: 2,
            body: b"head-2".to_vec(),
        }),
        issuance: vec![
            issuance(1, 0x01, 1, b"head-1"),
            issuance(2, 0x02, 2, b"head-2"),
        ],
    }
}

#[test]
fn an_admissible_bundle_round_trips_byte_for_byte() {
    let bundle = admissible();
    let bytes = export_bundle(&bundle).expect("the bundle is admissible");
    let restored = import_bundle(&bytes).expect("its own export must import");
    assert_eq!(restored, bundle);
    assert_eq!(
        export_bundle(&restored).expect("re-export"),
        bytes,
        "the encoding must be canonical, so a round trip is byte-stable"
    );
}

#[test]
fn an_empty_store_exports_and_imports() {
    let empty = ExportBundle {
        schema_version: 1,
        instance: 7,
        bodies: Vec::new(),
        head: None,
        issuance: Vec::new(),
    };
    let bytes = export_bundle(&empty).expect("an empty store is admissible");
    assert_eq!(import_bundle(&bytes).expect("import"), empty);
    assert_eq!(
        empty.next_issuance().expect("a first sequence").get(),
        1,
        "a restored empty store mints from the first sequence"
    );
}

#[test]
fn the_next_sequence_comes_from_the_ledger_not_from_a_field() {
    let bundle = admissible();
    assert_eq!(
        bundle.next_issuance().expect("a successor").get(),
        3,
        "a restored store must not reissue a token the bundle already records"
    );
}

#[test]
fn a_foreign_schema_generation_is_refused() {
    let mut bundle = admissible();
    bundle.schema_version = 2;
    let refusal = bundle
        .validate()
        .expect_err("a generation this build does not implement must be refused");
    assert_eq!(
        refusal,
        BundleRefusal::SchemaGenerationUnsupported {
            observed: 2,
            expected: 1
        }
    );
    admissible()
        .validate()
        .expect("generation one is admissible");
}

#[test]
fn a_head_bearing_a_token_the_ledger_never_issued_is_refused() {
    // The forged-head case: without this check a bundle could smuggle in a head
    // whose token nobody minted, which is the forged-receipt attack arriving
    // through the restore path instead of the write path.
    let mut bundle = admissible();
    bundle.head = Some(ExportedHead {
        key: b"repo/head".to_vec(),
        token: vec![0xFF; 16],
        generation: 2,
        body: b"head-2".to_vec(),
    });
    assert_eq!(
        bundle
            .validate()
            .expect_err("a forged head must be refused"),
        BundleRefusal::HeadTokenUnissued
    );
}

#[test]
fn a_head_that_contradicts_its_own_issuance_record_is_refused() {
    for (field, damage) in [
        (
            "generation",
            ExportedHead {
                key: b"repo/head".to_vec(),
                token: vec![0x02; 16],
                generation: 9,
                body: b"head-2".to_vec(),
            },
        ),
        (
            "body",
            ExportedHead {
                key: b"repo/head".to_vec(),
                token: vec![0x02; 16],
                generation: 2,
                body: b"head-forged".to_vec(),
            },
        ),
        (
            "head key",
            ExportedHead {
                key: b"repo/other".to_vec(),
                token: vec![0x02; 16],
                generation: 2,
                body: b"head-2".to_vec(),
            },
        ),
    ] {
        let mut bundle = admissible();
        bundle.head = Some(damage);
        assert_eq!(
            bundle
                .validate()
                .expect_err("the head must agree with the ledger"),
            BundleRefusal::HeadContradictsIssuance { field },
            "the {field} disagreement was not caught"
        );
    }
}

#[test]
fn a_repeated_body_key_or_token_or_sequence_is_refused() {
    let mut repeated_body = admissible();
    repeated_body.bodies[1].key = b"body/a".to_vec();
    assert_eq!(
        repeated_body.validate().expect_err("two bodies, one key"),
        BundleRefusal::Duplicated {
            collection: "bodies"
        }
    );

    let mut repeated_sequence = admissible();
    repeated_sequence.issuance[1].sequence = 1;
    assert_eq!(
        repeated_sequence
            .validate()
            .expect_err("two records, one position"),
        BundleRefusal::Duplicated {
            collection: "issuance"
        }
    );

    let mut repeated_token = admissible();
    repeated_token.issuance[1].token = vec![0x01; 16];
    assert_eq!(
        repeated_token
            .validate()
            .expect_err("one token minted twice defeats the ABA defence"),
        BundleRefusal::Duplicated {
            collection: "issuance"
        }
    );
}

#[test]
fn a_mis_ordered_collection_is_refused_rather_than_sorted() {
    // Sorting it silently would make two different byte strings mean the same
    // bundle, and a bundle that is not byte-comparable is not much of a bundle.
    let mut bodies = admissible();
    bodies.bodies.swap(0, 1);
    assert_eq!(
        bodies
            .validate()
            .expect_err("bodies must be ordered by key"),
        BundleRefusal::OutOfOrder {
            collection: "bodies"
        }
    );

    let mut issuance = admissible();
    issuance.issuance.swap(0, 1);
    assert_eq!(
        issuance
            .validate()
            .expect_err("issuance must be ordered by sequence"),
        BundleRefusal::OutOfOrder {
            collection: "issuance"
        }
    );
}

#[test]
fn the_reserved_zeroes_are_refused() {
    let mut zero_sequence = admissible();
    zero_sequence.issuance[0].sequence = 0;
    assert_eq!(
        zero_sequence
            .validate()
            .expect_err("sequence zero is reserved"),
        BundleRefusal::SequenceReserved
    );

    let mut zero_generation = admissible();
    zero_generation.issuance[0].generation = 0;
    assert_eq!(
        zero_generation
            .validate()
            .expect_err("generation zero is reserved"),
        BundleRefusal::GenerationReserved
    );
}

#[test]
fn export_refuses_an_inconsistent_bundle_rather_than_writing_it() {
    // Validating on the way out catches a corrupt store where it can still be
    // investigated, instead of at a restore months later.
    let mut bundle = admissible();
    bundle.head = Some(ExportedHead {
        key: b"repo/head".to_vec(),
        token: vec![0xFF; 16],
        generation: 2,
        body: b"head-2".to_vec(),
    });
    assert_eq!(
        export_bundle(&bundle).expect_err("a corrupt store must not export cleanly"),
        BundleRefusal::HeadTokenUnissued
    );
}

#[test]
fn truncated_or_foreign_bytes_are_refused_rather_than_guessed_at() {
    let bytes = export_bundle(&admissible()).expect("an admissible bundle");
    for cut in [0_usize, 1, bytes.len() / 2, bytes.len() - 1] {
        assert!(
            import_bundle(&bytes[..cut]).is_err(),
            "a bundle truncated at {cut} must not import"
        );
    }
    assert!(
        import_bundle(b"not a bundle at all").is_err(),
        "foreign bytes must not import"
    );
    import_bundle(&bytes).expect("the intact bundle still imports");
}

#[test]
fn a_head_without_a_ledger_cannot_exist_but_a_ledger_without_a_head_can() {
    // A store that minted tokens and then had its head removed is not a thing
    // this profile can produce, but a store mid-initialisation -- ledger rows
    // written, head not yet published -- is.
    let mut ledger_only = admissible();
    ledger_only.head = None;
    ledger_only
        .validate()
        .expect("a ledger with no published head is admissible");

    let mut head_only = admissible();
    head_only.issuance.clear();
    assert_eq!(
        head_only
            .validate()
            .expect_err("a head with no ledger has an unissued token"),
        BundleRefusal::HeadTokenUnissued
    );
}
