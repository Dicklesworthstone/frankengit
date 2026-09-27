use super::*;
use fgit_crypto::{
    IdentityDomain, internal_algorithm_id, internal_digest_value, internal_object_id,
};
use fgit_types::{CodecVersion, SchemaId};
fn source(format: Format) -> Source {
    let id = |domain, family| {
        internal_object_id(
            domain,
            SchemaId::new(SchemaFamily::from_static(family), 1, 0),
            CodecVersion::new(1, 0),
            b"test",
        )
    };
    Source {
        tenant: TenantId::from_bytes([1; 16]),
        repository: RepositoryId::from_bytes([2; 16]),
        incarnation: RepositoryIncarnationId::from_bytes([3; 16]),
        format,
        reference: RefName::try_new(b"refs/heads/main").unwrap(),
        head: RepositoryAuthorityHeadId::from_internal_object_id(id(
            IdentityDomain::RepositoryAuthorityHead,
            "repository-authority-head",
        ))
        .unwrap(),
        rcr: RepositoryCommitId::from_internal_object_id(id(
            IdentityDomain::RepositoryCommitRecord,
            "repository-commit-record",
        ))
        .unwrap(),
        forge: Digest::new(
            internal_algorithm_id(IdentityDomain::MerkleLeaf),
            internal_digest_value(
                IdentityDomain::MerkleLeaf,
                SchemaId::new(SchemaFamily::from_static("test"), 1, 0),
                b"forge",
            ),
        ),
        commit: git_object_id(format, GitObjectKind::Commit, b"commit"),
        tree: git_object_id(format, GitObjectKind::Tree, b"tree"),
    }
}
fn document(format: Format, path: &[u8], body: &[u8]) -> (Document, Payload) {
    let table = table::Table::build(
        body,
        &mut engine::Budget::new(engine::MAX_WORK).unwrap(),
        &|| false,
    )
    .unwrap();
    let blob = git_object_id(format, GitObjectKind::Blob, body);
    let payload = table_payload(blob, &table, &|| false).unwrap();
    (
        Document {
            path: path.to_vec(),
            blob,
            root: payload.root,
            encoded_bytes: payload.bytes.len(),
            source_bytes: body.len(),
            declarations: table.rows().len(),
            macros: table.macros,
            attributes: table.attributes,
        },
        payload,
    )
}
#[test]
fn canonical_tables_manifests_and_queries_roundtrip_in_both_native_formats() {
    for format in [Format::Sha1, Format::Sha256] {
        let (a, pa) = document(format, b"a.rs", b"fn Thing() {} struct ThingMore;\n");
        let (b, pb) = document(format, b"dir/\xff.rs", b"fn r#type() {}\n");
        let manifest = Manifest {
            source: source(format),
            documents: vec![a.clone(), b],
            unsupported: 2,
            non_regular: 1,
        };
        let payload = manifest.encode(&|| false).unwrap();
        let decoded = Manifest::decode(&payload.bytes, payload.root, &|| false).unwrap();
        assert_eq!(decoded.source(), manifest.source());
        assert_eq!(decoded.documents(), manifest.documents());
        let query = SymbolQuery::new(
            b"Thing",
            SymbolMatchMode::Prefix,
            &[],
            &[],
            engine::MAX_WORK,
        )
        .unwrap();
        let mut search = Query::new(&query, 10).unwrap();
        assert!(!search.observe(&a, &pa.bytes, &|| false).unwrap());
        assert!(
            !search
                .observe(&manifest.documents[1], &pb.bytes, &|| false)
                .unwrap()
        );
        assert_eq!(search.matches.len(), 2);
        assert!(!search.more);
        assert_eq!(search.tables, 2);
        assert_eq!(search.matches[0].location.blob, a.blob);
    }
}
#[test]
fn manifest_and_table_substitution_fail_even_with_valid_individual_codecs() {
    let (a, pa) = document(Format::Sha256, b"a.rs", b"fn A() {}\n");
    let (b, pb) = document(Format::Sha256, b"b.rs", b"fn B() {}\n");
    assert!(decode_table(&a, &pb.bytes, &|| false).is_err());
    let mut altered = a.clone();
    altered.declarations += 1;
    assert!(decode_table(&altered, &pa.bytes, &|| false).is_err());
    let manifest = Manifest {
        source: source(Format::Sha256),
        documents: vec![a],
        unsupported: 0,
        non_regular: 0,
    };
    let encoded = manifest.encode(&|| false).unwrap();
    assert!(Manifest::decode(&encoded.bytes, b.root, &|| false).is_err());
    let mut corrupted = encoded.bytes.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 1;
    assert!(Manifest::decode(&corrupted, encoded.root, &|| false).is_err());
}
#[test]
fn duplicate_out_of_order_non_rust_and_foreign_format_catalogs_refuse() {
    let (doc, _) = document(Format::Sha1, b"src/a.rs", b"fn A() {}\n");
    let manifest = Manifest {
        source: source(Format::Sha1),
        documents: vec![doc.clone()],
        unsupported: 0,
        non_regular: 0,
    };
    assert!(manifest.encode(&|| false).is_ok());
    let mut duplicate = manifest.clone();
    duplicate.documents.push(doc);
    assert!(duplicate.encode(&|| false).is_err());
    for path in [b"../x.rs".as_slice(), b"a.txt", b".git/x.rs"] {
        let mut m = manifest.clone();
        m.documents[0].path = path.to_vec();
        assert!(m.encode(&|| false).is_err());
    }
    let mut foreign = manifest;
    foreign.source.format = Format::Sha256;
    assert!(foreign.encode(&|| false).is_err());
}
#[test]
fn exact_full_page_is_complete_and_only_extra_match_proves_a_limit() {
    let (a, pa) = document(Format::Sha1, b"a.rs", b"fn A() {} fn A() {}\n");
    let (b, pb) = document(Format::Sha1, b"b.rs", b"fn A() {}\n");
    let query = SymbolQuery::new(b"A", SymbolMatchMode::Exact, &[], &[], engine::MAX_WORK).unwrap();
    let mut search = Query::new(&query, 2).unwrap();
    assert!(!search.observe(&a, &pa.bytes, &|| false).unwrap());
    assert!(!search.more);
    assert!(search.observe(&b, &pb.bytes, &|| false).unwrap());
    assert!(search.more);
    assert_eq!(search.matches.len(), 2);
}
#[test]
fn path_scopes_are_component_bounded_and_do_not_change_query_case() {
    let query = SymbolQuery::new(
        b"A",
        SymbolMatchMode::Exact,
        &[],
        &[b"src".to_vec()],
        engine::MAX_WORK,
    )
    .unwrap();
    let search = Query::new(&query, 2).unwrap();
    let (a, _) = document(Format::Sha1, b"src/a.rs", b"fn A() {}\n");
    let (b, _) = document(Format::Sha1, b"src2/a.rs", b"fn A() {}\n");
    assert!(search.includes(&a));
    assert!(!search.includes(&b));
    let (b, pb) = document(Format::Sha1, b"src/b.rs", b"fn a() {}\n");
    let mut search = search;
    assert!(!search.observe(&b, &pb.bytes, &|| false).unwrap());
    assert!(search.matches.is_empty());
}
#[test]
fn empty_manifest_is_authenticated_empty_not_missing_and_limits_remain_errors() {
    let manifest = Manifest {
        source: source(Format::Sha1),
        documents: vec![],
        unsupported: 2,
        non_regular: 1,
    };
    let payload = manifest.encode(&|| false).unwrap();
    assert!(
        Manifest::decode(&payload.bytes, payload.root, &|| false)
            .unwrap()
            .documents()
            .is_empty()
    );
    assert!(Manifest::decode(&payload.bytes, payload.root, &|| true).is_err());
    let query = SymbolQuery::new(b"A", SymbolMatchMode::Exact, &[], &[], 1).unwrap();
    let (a, pa) = document(Format::Sha1, b"a.rs", b"fn A() {}\n");
    assert!(
        Query::new(&query, 1)
            .unwrap()
            .observe(&a, &pa.bytes, &|| false)
            .is_err()
    );
    for limit in [0, 4097] {
        assert!(Query::new(&query, limit).is_err());
    }
}

#[test]
fn opaque_unicode_tables_retain_complete_blob_identity_and_source_accounting() {
    for format in [Format::Sha1, Format::Sha256] {
        let bytes = "#[custom(名)]\nfn KeepOne() {}\nmacro_rules! make { ($名:ident) => { fn Hidden() {} }; }\nm!(名 '寿命);\nfn KeepTwo() {}\n".as_bytes();
        let (a, pa) = document(format, b"a.rs", bytes);
        let (b, pb) = document(format, b"b.rs", b"struct KeepThree;\n");
        assert_eq!(a.blob, git_object_id(format, GitObjectKind::Blob, bytes));
        assert_eq!(a.source_bytes, bytes.len());
        assert_eq!(a.declarations, 3);
        assert_eq!(a.macros, 2);
        assert_eq!(a.attributes, 1);
        let manifest = Manifest {
            source: source(format),
            documents: vec![a, b],
            unsupported: 0,
            non_regular: 0,
        };
        let encoded = manifest.encode(&|| false).unwrap();
        let decoded = Manifest::decode(&encoded.bytes, encoded.root, &|| false).unwrap();
        assert_eq!(decoded.documents(), manifest.documents());
        assert_eq!(decoded.source_bytes(), bytes.len() + b"struct KeepThree;\n".len());
        assert_eq!(decoded.declarations(), 4);
        let query = SymbolQuery::new(b"Keep", SymbolMatchMode::Prefix, &[], &[], engine::MAX_WORK).unwrap();
        let mut search = Query::new(&query, 10).unwrap();
        assert!(!search.observe(&decoded.documents()[0], &pa.bytes, &|| false).unwrap());
        assert!(!search.observe(&decoded.documents()[1], &pb.bytes, &|| false).unwrap());
        assert_eq!(search.matches.iter().map(|m| m.name.as_slice()).collect::<Vec<_>>(),
            vec![b"KeepOne".as_slice(), b"KeepTwo", b"KeepThree"]);
        assert!(!search.more);
        for hit in &search.matches[..2] {
            assert_eq!(hit.location.blob, decoded.documents()[0].blob);
            assert_eq!(&bytes[hit.location.byte_offset..hit.location.byte_offset + hit.location.match_length], hit.name.as_slice());
        }
    }
}

#[test]
fn ignored_opaque_declarations_never_enter_persisted_results() {
    for format in [Format::Sha1, Format::Sha256] {
        let body = "#[custom(名, fn Hidden() {})] macro_rules! make { () => { struct Hidden; 名 }; } m!{ 名 fn Hidden() {} } fn Visible() {}".as_bytes();
        let (doc, payload) = document(format, b"a.rs", body);
        let decoded = decode_table(&doc, &payload.bytes, &|| false).unwrap();
        assert_eq!(decoded.rows().len(), 2);
        assert!(decoded.rows().iter().all(|row| row.name.as_slice() != b"Hidden"));
        for (name, count) in [(b"Hidden".as_slice(), 0), (b"Visible".as_slice(), 1), (b"make".as_slice(), 1)] {
            let query = SymbolQuery::new(name, SymbolMatchMode::Exact, &[], &[], engine::MAX_WORK).unwrap();
            let mut search = Query::new(&query, 10).unwrap();
            assert!(!search.observe(&doc, &payload.bytes, &|| false).unwrap());
            assert_eq!(search.matches.len(), count);
        }
    }
}

#[test]
fn long_opaque_tokens_allow_zero_row_documents_without_losing_source_bytes() {
    let body = format!("#[custom({})] m!(名);", "a".repeat(8192));
    for format in [Format::Sha1, Format::Sha256] {
        let (doc, payload) = document(format, b"a.rs", body.as_bytes());
        let decoded = decode_table(&doc, &payload.bytes, &|| false).unwrap();
        assert_eq!(doc.declarations, 0);
        assert_eq!(doc.source_bytes, body.len());
        assert!(decoded.rows().is_empty());
        let manifest = Manifest { source: source(format), documents: vec![doc], unsupported: 0, non_regular: 0 };
        let encoded = manifest.encode(&|| false).unwrap();
        let roundtrip = Manifest::decode(&encoded.bytes, encoded.root, &|| false).unwrap();
        assert_eq!(roundtrip.documents().len(), 1);
        assert_eq!(roundtrip.source_bytes(), body.len());
        assert_eq!(roundtrip.declarations(), 0);
    }
}

#[test]
fn raw_ascii_declarations_after_opaque_tokens_keep_persisted_exact_spans() {
    let bytes = "m!(r#名);\r\nfn r#type() {}\r\n".as_bytes();
    for format in [Format::Sha1, Format::Sha256] {
        let (doc, payload) = document(format, b"raw.rs", bytes);
        let query = SymbolQuery::new(b"type", SymbolMatchMode::Exact, &[], &[], engine::MAX_WORK).unwrap();
        let mut search = Query::new(&query, 1).unwrap();
        assert!(!search.observe(&doc, &payload.bytes, &|| false).unwrap());
        assert_eq!(search.matches.len(), 1);
        let hit = &search.matches[0];
        assert!(hit.raw_identifier);
        assert_eq!(hit.location.line, 2);
        assert_eq!(hit.location.byte_column, 6);
        assert_eq!(&bytes[hit.location.byte_offset - 2..hit.location.byte_offset], b"r#");
        assert_eq!(&bytes[hit.location.byte_offset..hit.location.byte_offset + 4], b"type");
    }
}
