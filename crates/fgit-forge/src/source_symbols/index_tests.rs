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
