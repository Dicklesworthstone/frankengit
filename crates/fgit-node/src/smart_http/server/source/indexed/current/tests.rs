//! Response and input invariants. Real storage/TCP coverage lives in
//! tests/source_index_revalidated_http.rs; these are not a replacement server.
use super::*;
use crate::smart_http::server::source::indexed::{command, rows};
use fgit_crypto::{IdentityDomain, internal_object_id};
use fgit_graph::GenerationActivation;
use fgit_graph::lexical::{
    IndexedLexicalReport, LexicalHit, LexicalNamespace, LexicalReport, LexicalSpan,
};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, GitHashAlgorithm, GitOid, HeadGeneration, RefName,
    RepositoryAuthorityHeadId, RepositoryCommitId, RepositoryId, RepositoryIncarnationId,
    SchemaFamily, SchemaId, TenantId,
};

fn form() -> &'static [u8] {
    b"object_format=sha1&ref=refs/heads/main&term_hex=6e6565646c65"
}

fn source(seed: u8) -> LexicalSource {
    let id = |domain, family| {
        internal_object_id(
            domain,
            SchemaId::new(SchemaFamily::from_static(family), 1, 0),
            CANONICAL_CODEC_VERSION,
            &[seed],
        )
    };
    let head = id(IdentityDomain::RepositoryAuthorityHead, "repository-authority-head");
    LexicalSource {
        namespace: LexicalNamespace {
            tenant: TenantId::from_bytes([1; 16]),
            repository: RepositoryId::from_bytes([2; 16]),
            incarnation: RepositoryIncarnationId::from_bytes([3; 16]),
            object_format: GitHashAlgorithm::Sha1,
        },
        reference: RefName::try_new(b"refs/heads/main").unwrap(),
        source_head: RepositoryAuthorityHeadId::from_internal_object_id(head).unwrap(),
        source_rcr: RepositoryCommitId::from_internal_object_id(id(
            IdentityDomain::RepositoryCommitRecord, "repository-commit-record",
        )).unwrap(),
        forge_position_root: Digest::new(head.algorithm(), *head.digest()),
        commit: GitOid::from_hex(GitHashAlgorithm::Sha1, &"b".repeat(40)).unwrap(),
        tree: GitOid::from_hex(GitHashAlgorithm::Sha1, &"c".repeat(40)).unwrap(),
    }
}

#[test]
fn explicit_modes_preserve_default_and_reject_unknown_or_duplicate_selection() {
    let parse = |extra: &str| {
        let bytes = [form(), extra.as_bytes()].concat();
        command(&bytes, GitHashAlgorithm::Sha1)
    };
    assert_eq!(parse("").unwrap().source_mode, SourceMode::Exact);
    assert_eq!(parse("&source_mode=exact").unwrap().source_mode, SourceMode::Exact);
    assert_eq!(
        parse("&source_mode=revalidated").unwrap().source_mode,
        SourceMode::Revalidated,
    );
    for extra in [
        "&source_mode=", "&source_mode=latest", "&source_mode=Revalidated",
        "&source_mode=exact&source_mode=revalidated", "&source_mode=exact&source_mode=exact",
        "&source_mode=revalidated&build=true", "&source_mode=revalidated&principal=admin",
    ] {
        assert!(parse(extra).is_err(), "{extra}");
    }
}

#[test]
fn revalidation_does_not_turn_incomplete_continuations_into_unpinned_reads() {
    let source = source(1);
    let generation = internal_object_id(
        IdentityDomain::Generation,
        SchemaId::new(SchemaFamily::from_static("graph-generation"), 1, 0),
        CANONICAL_CODEC_VERSION, b"generation",
    );
    let prefix = format!(
        "{}&source_mode=revalidated&after=9007199254740993",
        std::str::from_utf8(form()).unwrap(),
    );
    let pins = [
        format!("&expected_head={}", token(source.source_head.as_internal_object_id())),
        format!("&expected_commit={}", source.commit),
        format!("&index_token={}&index_number=18446744073709551615", token(&generation)),
    ];
    for mask in 0_u8..8 {
        let mut form = prefix.clone();
        for (i, pin) in pins.iter().enumerate() {
            if mask & (1 << i) != 0 {
                form.push_str(pin);
            }
        }
        let parsed = command(form.as_bytes(), GitHashAlgorithm::Sha1);
        if mask == 7 {
            let parsed = parsed.unwrap();
            assert_eq!(parsed.after, Some(9_007_199_254_740_993));
            assert_eq!(parsed.generation.unwrap().authority_generation.get(), u64::MAX);
        } else {
            assert!(parsed.is_err(), "missing pins: mask={mask}");
        }
    }
}

#[test]
fn only_metadata_coordinates_can_differ_in_a_revalidated_response() {
    let indexed = source(1);
    let current = source(2);
    assert!(validate_sources(SourceMode::Exact, &indexed, &indexed).is_ok());
    assert!(validate_sources(SourceMode::Exact, &indexed, &current).is_err());
    assert!(validate_sources(SourceMode::Revalidated, &indexed, &current).is_ok());
    for variant in 0..8 {
        let mut changed = current.clone();
        match variant {
            0 => changed.namespace.tenant = TenantId::from_bytes([9; 16]),
            1 => changed.namespace.repository = RepositoryId::from_bytes([9; 16]),
            2 => changed.namespace.incarnation = RepositoryIncarnationId::from_bytes([9; 16]),
            3 => changed.namespace.object_format = GitHashAlgorithm::Sha256,
            4 => changed.reference = RefName::try_new(b"refs/heads/other").unwrap(),
            5 => changed.commit = indexed.tree,
            6 => changed.tree = indexed.commit,
            _ => changed.source_head = indexed.source_head,
        }
        assert!(validate_sources(SourceMode::Revalidated, &indexed, &changed).is_err());
    }
}

#[test]
fn dual_provenance_retains_both_roots_and_obeys_output_budget_and_cancellation() {
    let indexed = source(1);
    let current = source(2);
    let mut body = String::new();
    append_sources(&mut body, &indexed, &current, usize::MAX, &mut || true).unwrap();
    assert!(body.contains(&format!("\"current_source\":{}", source_json(&current))));
    assert!(body.contains(&format!("\"indexed_source\":{}", source_json(&indexed))));
    assert!(body.ends_with("\"distinct_provenance\":true,"));
    let mut exact = String::new();
    append_sources(&mut exact, &indexed, &current, body.len(), &mut || true).unwrap();
    assert_eq!(exact, body);
    assert!(append_sources(
        &mut String::new(), &indexed, &current, body.len() - 1, &mut || true,
    ).is_err());
    let mut cancelled = String::new();
    assert!(append_sources(
        &mut cancelled, &indexed, &current, usize::MAX, &mut || false,
    ).is_err());
    assert!(cancelled.is_empty());
    let mut same = String::new();
    append_sources(&mut same, &indexed, &indexed, usize::MAX, &mut || true).unwrap();
    assert!(same.ends_with("\"distinct_provenance\":false,"));
}

#[test]
fn new_profile_encodes_identity_counters_losslessly_without_changing_exact_mode() {
    for number in [0, 1, 9_007_199_254_740_992, 9_007_199_254_740_993, u64::MAX] {
        assert_eq!(SourceMode::Exact.counter(number), number.to_string());
        assert_eq!(SourceMode::Revalidated.counter(number), format!("\"{number}\""));
        assert_eq!(
            SourceMode::Revalidated.optional(Some(number)),
            SourceMode::Revalidated.counter(number),
        );
    }
    assert_eq!(SourceMode::Revalidated.optional(None), "null");
}

#[test]
fn revalidated_rows_share_integrity_checks_and_keep_large_document_ids_as_strings() {
    let mut command = command(form(), GitHashAlgorithm::Sha1).unwrap();
    command.source_mode = SourceMode::Revalidated;
    let id = internal_object_id(
        IdentityDomain::Generation,
        SchemaId::new(SchemaFamily::from_static("graph-generation"), 1, 0),
        CANONICAL_CODEC_VERSION, b"generation",
    );
    let generation = GenerationActivation {
        generation_id: fgit_graph::GraphGenerationId::from_internal_object_id(id).unwrap(),
        authority_generation: HeadGeneration::FIRST,
    };
    let mut report = IndexedLexicalReport {
        source: source(1),
        generation: generation.clone(),
        selected_generation_head: generation,
        query: command.query.clone(),
        results: LexicalReport {
            hits: vec![LexicalHit {
                document_id: 9_007_199_254_740_993,
                path: b"file.txt".to_vec(),
                blob: GitOid::from_hex(GitHashAlgorithm::Sha1, &"d".repeat(40)).unwrap(),
                content_bytes: 6,
                spans: vec![LexicalSpan { query_index: 0, byte_offset: 0, byte_length: 6 }],
            }],
            complete: true, next_after: None, work_units: 10,
        },
        indexed_documents: 1, indexed_source_bytes: 6, non_regular_entries: 0,
        segments_read: 1, payload_bytes_read: 100, generation_bytes_read: 100,
    };
    let body = rows(&command, &report, usize::MAX, &mut || true).unwrap();
    assert!(body.contains("\"document_id\":\"9007199254740993\""));
    command.source_mode = SourceMode::Exact;
    let exact = rows(&command, &report, usize::MAX, &mut || true).unwrap();
    assert_eq!(exact, body.replace("\"9007199254740993\"", "9007199254740993"));
    command.source_mode = SourceMode::Revalidated;
    report.results.hits[0].spans[0].byte_offset = 1;
    assert!(rows(&command, &report, usize::MAX, &mut || true).is_err());
}
