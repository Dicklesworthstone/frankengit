//! Production scanner/table/manifest codecs; scalar queries are the oracle.
use super::*;
use crate::source_search::{SearchCompletion, SourceSearchReport};
use crate::source_symbols::SymbolQuery;
use crate::source_symbols::index::{
    Corpus, Document, Format, ReuseVerifier, Source, TenantId, table_payload,
};
use fgit_crypto::{
    GitObjectKind, IdentityDomain, git_object_id, internal_algorithm_id, internal_digest_value,
    internal_object_id,
};
use fgit_types::{
    CodecVersion, RefName, RepositoryAuthorityHeadId, RepositoryCommitId, RepositoryId,
    RepositoryIncarnationId, SchemaId,
};

fn source(format: Format) -> Source {
    let id = |domain, family| {
        internal_object_id(
            domain,
            SchemaId::new(SchemaFamily::from_static(family), 1, 0),
            CodecVersion::new(1, 0),
            b"directory-test",
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
fn corpus(format: Format, files: &[(&[u8], &[u8])]) -> (Manifest, Vec<Payload>, Vec<Names>) {
    let mut documents = Vec::new();
    let mut payloads = Vec::new();
    let mut summaries = Vec::new();
    for (path, bytes) in files {
        let table = table::Table::build(
            bytes,
            &mut engine::Budget::new(engine::MAX_WORK).unwrap(),
            &|| false,
        )
        .unwrap();
        let blob = git_object_id(format, GitObjectKind::Blob, bytes);
        let payload = table_payload(blob, &table, &|| false).unwrap();
        documents.push(Document {
            path: path.to_vec(),
            blob,
            root: payload.root,
            encoded_bytes: payload.bytes.len(),
            source_bytes: bytes.len(),
            declarations: table.rows().len(),
            macros: table.macros,
            attributes: table.attributes,
        });
        summaries.push(summarize(&table, &|| false).unwrap());
        payloads.push(payload);
    }
    (
        Manifest {
            source: source(format),
            documents,
            unsupported: 0,
            non_regular: 0,
        },
        payloads,
        summaries,
    )
}
fn fixture(format: Format) -> (Manifest, Vec<Payload>, Vec<Names>) {
    corpus(
        format,
        &[
            (
                b"a.rs",
                b"fn Zebra() {}\nstruct Alpha;\nfn Alpha() {}\nmod M { fn Alpha() {} }\n",
            ),
            (b"empty.rs", b""),
            (b"src/b.rs", b"fn Alpine() {}\nfn r#type() {}\n"),
            (b"src2/c.rs", b"enum Alpha {}\ntrait Beta {}\n"),
            (b"z\xff.rs", b"union Alpha { a: u8 }\n"),
        ],
    )
}
fn query(
    name: &[u8],
    mode: SymbolMatchMode,
    kinds: &[engine::Kind],
    scopes: &[Vec<u8>],
) -> SymbolQuery {
    SymbolQuery::new(name, mode, kinds, scopes, engine::MAX_WORK).unwrap()
}
#[test]
fn accelerated_exact_prefix_kind_and_path_queries_match_scalar_tables_in_both_formats() {
    for format in [Format::Sha1, Format::Sha256] {
        let (manifest, payloads, summaries) = fixture(format);
        let directory = NameDirectory::build(&manifest, &summaries, &|| false).unwrap();
        let payload = directory.encode(&manifest, &|| false).unwrap();
        for name in [
            b"A".as_slice(),
            b"Al",
            b"Alpha",
            b"Alpine",
            b"Beta",
            b"Zebra",
            b"type",
            b"Missing",
            b"_",
        ] {
            for mode in [SymbolMatchMode::Exact, SymbolMatchMode::Prefix] {
                for kinds in [vec![], vec![engine::Kind::Function], KINDS.to_vec()] {
                    for scopes in [vec![], vec![b"src".to_vec()], vec![b"a.rs".to_vec()]] {
                        let q = query(name, mode, &kinds, &scopes);
                        for maximum in [1, 3, 100] {
                            let mut scalar = Query::new(&q, maximum).unwrap();
                            for (doc, raw) in manifest.documents().iter().zip(&payloads) {
                                if scalar.includes(doc)
                                    && scalar.observe(doc, &raw.bytes, &|| false).unwrap()
                                {
                                    break;
                                }
                            }
                            let mut fast = Query::new(&q, maximum).unwrap();
                            let candidates = fast
                                .directory_candidates(
                                    &manifest,
                                    &payload.bytes,
                                    payload.root,
                                    &|| false,
                                )
                                .unwrap();
                            assert!(candidates.windows(2).all(|w| w[0] < w[1]));
                            for i in candidates {
                                if fast
                                    .observe(&manifest.documents()[i], &payloads[i].bytes, &|| {
                                        false
                                    })
                                    .unwrap()
                                {
                                    break;
                                }
                            }
                            assert_eq!(fast.matches, scalar.matches);
                            assert_eq!(fast.more, scalar.more);
                            assert!(fast.tables <= scalar.tables);
                        }
                    }
                }
            }
        }
        let q = query(b"Alpine", SymbolMatchMode::Exact, &[], &[]);
        assert_eq!(
            Query::new(&q, 10)
                .unwrap()
                .directory_candidates(&manifest, &payload.bytes, payload.root, &|| false)
                .unwrap(),
            vec![2]
        );
        assert_eq!(
            NameDirectory::decode(&payload.bytes, payload.root, &manifest, &|| false)
                .unwrap()
                .encode(&manifest, &|| false)
                .unwrap()
                .bytes,
            payload.bytes
        );
    }
}
#[test]
fn directory_commitment_manifest_binding_truncations_and_cancellation_fail_closed() {
    let (manifest, _, summaries) = fixture(Format::Sha256);
    let payload = NameDirectory::build(&manifest, &summaries, &|| false)
        .unwrap()
        .encode(&manifest, &|| false)
        .unwrap();
    for cut in 0..payload.bytes.len() {
        assert!(
            NameDirectory::decode(&payload.bytes[..cut], payload.root, &manifest, &|| false)
                .is_err()
        );
    }
    let mut corrupt = payload.bytes.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(NameDirectory::decode(&corrupt, payload.root, &manifest, &|| false).is_err());
    let mut moved = manifest.clone();
    moved.source.commit = git_object_id(Format::Sha256, GitObjectKind::Commit, b"changed");
    assert!(NameDirectory::decode(&payload.bytes, payload.root, &moved, &|| false).is_err());
    let mut renamed = manifest.clone();
    renamed.documents[0].path = b"aa.rs".to_vec();
    assert!(NameDirectory::decode(&payload.bytes, payload.root, &renamed, &|| false).is_err());
    assert!(NameDirectory::decode(&payload.bytes, payload.root, &manifest, &|| true).is_err());
    let calls = std::cell::Cell::new(0);
    assert!(
        NameDirectory::decode(&payload.bytes, payload.root, &manifest, &|| {
            let n = calls.get() + 1;
            calls.set(n);
            n > 12
        })
        .is_err()
    );
    assert!(calls.get() > 12);
}
#[test]
fn complete_document_counts_invalid_names_kinds_and_duplicate_postings_are_checked() {
    let (manifest, _, summaries) = fixture(Format::Sha1);
    let directory = NameDirectory::build(&manifest, &summaries, &|| false).unwrap();
    for alteration in 0..6 {
        let mut bad = directory.clone();
        let rows = bad.names.get_mut(b"Alpha".as_slice()).unwrap();
        match alteration {
            0 => {
                rows.pop();
            }
            1 => {
                rows[0].document = usize::MAX;
            }
            2 => {
                rows[0].kind = 8;
            }
            3 => {
                rows[0].count = 0;
            }
            4 => {
                rows.insert(0, rows[0].clone());
            }
            _ => {
                rows[0].count = usize::MAX;
            }
        }
        assert!(bad.encode(&manifest, &|| false).is_err());
    }
    let mut bad = directory;
    let rows = bad.names.remove(b"Alpha".as_slice()).unwrap();
    bad.names.insert(b"r#Alpha".to_vec(), rows);
    assert!(bad.encode(&manifest, &|| false).is_err());
    assert!(NameDirectory::build(&manifest, &summaries[..1], &|| false).is_err());
    let (empty, _, names) = corpus(Format::Sha1, &[]);
    let payload = NameDirectory::build(&empty, &names, &|| false)
        .unwrap()
        .encode(&empty, &|| false)
        .unwrap();
    assert!(
        Query::new(&query(b"A", SymbolMatchMode::Prefix, &[], &[]), 10)
            .unwrap()
            .directory_candidates(&empty, &payload.bytes, payload.root, &|| false)
            .unwrap()
            .is_empty()
    );
}
#[test]
fn predecessor_verification_reuses_the_same_names_without_rescanning_source() {
    let (manifest, payloads, summaries) = fixture(Format::Sha256);
    let mut verifier = ReuseVerifier::new(&manifest, &|| false).unwrap();
    while let Some(doc) = verifier.next_document() {
        let payload = payloads.iter().find(|p| p.root == doc.root).unwrap();
        verifier.verify_next(&payload.bytes, &|| false).unwrap();
    }
    let verified = verifier.finish(&|| false).unwrap();
    let reused: Vec<_> = manifest
        .documents()
        .iter()
        .map(|d| verified.names(&d.blob).unwrap().clone())
        .collect();
    assert_eq!(reused, summaries);
    let direct = NameDirectory::build(&manifest, &summaries, &|| false)
        .unwrap()
        .encode(&manifest, &|| false)
        .unwrap();
    assert_eq!(
        NameDirectory::build(&manifest, &reused, &|| false)
            .unwrap()
            .encode(&manifest, &|| false)
            .unwrap()
            .bytes,
        direct.bytes
    );
}
#[test]
fn directory_work_and_table_work_share_one_exact_budget() {
    let (manifest, payloads, summaries) = fixture(Format::Sha1);
    let payload = NameDirectory::build(&manifest, &summaries, &|| false)
        .unwrap()
        .encode(&manifest, &|| false)
        .unwrap();
    let run = |maximum| {
        let q = SymbolQuery::new(b"Alpine", SymbolMatchMode::Exact, &[], &[], maximum).unwrap();
        let mut search = Query::new(&q, 10)?;
        for i in search.directory_candidates(&manifest, &payload.bytes, payload.root, &|| false)? {
            search.observe(&manifest.documents()[i], &payloads[i].bytes, &|| false)?;
        }
        Ok::<_, Error>(search.work.used)
    };
    let used = run(engine::MAX_WORK).unwrap();
    assert_eq!(run(used).unwrap(), used);
    assert!(run(used - 1).is_err());
    assert!(run(1).is_err());
}
#[test]
fn directory_size_fallback_does_not_reduce_the_legacy_corpus_or_swallow_cancellation() {
    let paths: Vec<_> = (0..20)
        .map(|i| format!("file{i:02}.rs").into_bytes())
        .collect();
    let bodies: Vec<_> = (0..20)
        .map(|file| {
            (0..400)
                .map(|i| format!("fn N{file:02}_{i:03}{}() {{}}\n", "x".repeat(116)))
                .collect::<String>()
                .into_bytes()
        })
        .collect();
    let files: Vec<_> = paths
        .iter()
        .zip(&bodies)
        .map(|(p, b)| (p.as_slice(), b.as_slice()))
        .collect();
    let (manifest, tables, names) = corpus(Format::Sha256, &files);
    let report = SourceSearchReport {
        repository: manifest.source.repository,
        source_rcr: manifest.source.rcr,
        source_commit: manifest.source.commit,
        source_tree: manifest.source.tree,
        matches: vec![],
        completion: SearchCompletion::Complete,
        files_selected: files.len(),
        files_read: files.len(),
        bytes_read: bodies.iter().map(Vec::len).sum(),
        bytes_searched: 0,
        non_regular_entries: 0,
    };
    let corpus = || Corpus {
        source: report.clone(),
        documents: manifest.documents.clone(),
        tables: tables.clone(),
        unsupported: 0,
        reused: 0,
        reuse_scope: None,
        names: names.clone(),
    };
    let expected = manifest.encode(&|| false).unwrap();
    let (actual, _, directory) = corpus()
        .finish_with_directory(manifest.source.clone(), &|| false)
        .unwrap();
    assert!(directory.is_none());
    assert_eq!(actual.encode(&|| false).unwrap().bytes, expected.bytes);
    assert!(
        corpus()
            .finish_with_directory(manifest.source.clone(), &|| true)
            .is_err()
    );
}
