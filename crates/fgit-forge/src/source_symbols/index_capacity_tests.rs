//! Real verified TreeFS enumeration, canonical tables and authenticated reuse.
//! The fixture owns immutable Git object bytes, not a substitute index.
use super::*;
use fgit_crypto::{GitOid as NativeOid, NativeObjectIdentity, Sha1};
use fgit_treefs::{ObjectSourceError, ReadGrant, WorkspaceId};
use std::cell::Cell;

#[derive(Default)]
struct Objects {
    bodies: BTreeMap<Vec<u8>, (GitObjectKind, Vec<u8>)>,
    blob_reads: Cell<usize>,
}
impl Objects {
    fn put(&mut self, kind: GitObjectKind, bytes: Vec<u8>) -> NativeOid<Sha1> {
        let oid = NativeOid::<Sha1>::of_object(kind, &bytes);
        self.bodies
            .insert(oid.digest_bytes().to_vec(), (kind, bytes));
        oid
    }
}
impl ObjectSource<Sha1> for Objects {
    fn read_object(
        &self,
        oid: &NativeOid<Sha1>,
        kind: GitObjectKind,
        grant: &ReadGrant,
    ) -> Result<Vec<u8>, ObjectSourceError> {
        let (actual, bytes) =
            self.bodies
                .get(oid.digest_bytes())
                .ok_or_else(|| ObjectSourceError::NotFound {
                    oid_hex: hex(oid.digest_bytes()),
                })?;
        assert_eq!(*actual, kind);
        if kind == GitObjectKind::Blob {
            assert!(grant.path().is_some());
            self.blob_reads.set(self.blob_reads.get() + 1);
        }
        Ok(bytes.clone())
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
struct Fixture {
    objects: Objects,
    base: BaseView<Sha1>,
    source: Source,
    paths: Vec<TreePath>,
}
impl Fixture {
    fn new(files: &[(Vec<u8>, Vec<u8>)]) -> Self {
        let mut objects = Objects::default();
        let mut entries: Vec<_> = files.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let mut tree = Vec::new();
        let mut paths = Vec::new();
        for (path, bytes) in entries {
            assert!(!path.contains(&b'/'));
            paths.push(TreePath::parse_default(path).unwrap());
            let blob = objects.put(GitObjectKind::Blob, bytes.clone());
            tree.extend_from_slice(b"100644 ");
            tree.extend_from_slice(path);
            tree.push(0);
            tree.extend_from_slice(blob.digest_bytes());
        }
        let tree_id = objects.put(GitObjectKind::Tree, tree.clone());
        let commit = format!(
            "tree {}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nindexed source\n",
            hex(tree_id.digest_bytes())
        )
        .into_bytes();
        let commit_id = objects.put(GitObjectKind::Commit, commit.clone());
        let mut source = source(Format::Sha1);
        source.tree = git_object_id(Format::Sha1, GitObjectKind::Tree, &tree);
        source.commit = git_object_id(Format::Sha1, GitObjectKind::Commit, &commit);
        source.head = RepositoryAuthorityHeadId::from_internal_object_id(internal_object_id(
            IdentityDomain::RepositoryAuthorityHead,
            SchemaId::new(SchemaFamily::from_static("repository-authority-head"), 1, 0),
            CodecVersion::new(1, 0),
            &tree,
        ))
        .unwrap();
        source.rcr = RepositoryCommitId::from_internal_object_id(internal_object_id(
            IdentityDomain::RepositoryCommitRecord,
            SchemaId::new(SchemaFamily::from_static("repository-commit-record"), 1, 0),
            CodecVersion::new(1, 0),
            &tree,
        ))
        .unwrap();
        let base = BaseView::new(
            source.repository,
            source.rcr,
            commit_id,
            tree_id,
            Default::default(),
            Default::default(),
        );
        Self {
            objects,
            base,
            source,
            paths,
        }
    }
    fn prepare(&self, reuse: Option<&VerifiedReuse>) -> Result<Corpus, Error> {
        let mut capability = TreeCapability::new(
            WorkspaceId::from_bytes([7; 16]),
            self.source.repository,
            self.paths.clone(),
            Vec::new(),
        );
        prepare_with_reuse(
            &self.base,
            &self.objects,
            &mut capability,
            0,
            SearchLimits::default(),
            &|| false,
            reuse,
        )
    }
}
fn verified_reuse(manifest: &Manifest, tables: &[Payload]) -> VerifiedReuse {
    let mut verifier = ReuseVerifier::new(manifest, &|| false).unwrap();
    while let Some(doc) = verifier.next_document() {
        let table = tables.iter().find(|table| table.root == doc.root).unwrap();
        verifier.verify_next(&table.bytes, &|| false).unwrap();
    }
    verifier.finish(&|| false).unwrap()
}
fn declarations(prefix: &str, count: usize) -> Vec<u8> {
    (0..count)
        .map(|i| format!("fn {prefix}{i:04}() {{}}\n"))
        .collect::<String>()
        .into_bytes()
}

#[test]
fn fresh_large_tree_and_verified_refresh_have_identical_complete_roots_and_queries() {
    let mut files: Vec<_> = (0..24)
        .map(|i| {
            (
                format!("file{i:02}.rs").into_bytes(),
                declarations(&format!("N{i:02}_"), 1000),
            )
        })
        .collect();
    let original = Fixture::new(&files);
    let prepared = original.prepare(None).unwrap();
    assert_eq!(prepared.source().files_read, 24);
    let (manifest, tables, directory) = prepared
        .finish_with_directory(original.source.clone(), &|| false)
        .unwrap();
    assert_eq!(manifest.declarations(), 24_000);
    let encoded = manifest.encode(&|| false).unwrap();
    assert_eq!(
        Manifest::decode(&encoded.bytes, encoded.root, &|| false)
            .unwrap()
            .documents(),
        manifest.documents()
    );
    let directory = directory.unwrap();
    NameDirectory::decode(&directory.bytes, directory.root, &manifest, &|| false).unwrap();
    let query =
        SymbolQuery::new(b"N23_", SymbolMatchMode::Prefix, &[], &[], engine::MAX_WORK).unwrap();
    let mut scalar = Query::new(&query, 3).unwrap();
    for (doc, table) in manifest.documents().iter().zip(&tables) {
        if scalar.observe(doc, &table.bytes, &|| false).unwrap() {
            break;
        }
    }
    let mut fast = Query::new(&query, 3).unwrap();
    let candidates = fast
        .directory_candidates(&manifest, &directory.bytes, directory.root, &|| false)
        .unwrap();
    assert_eq!(candidates, vec![23]);
    for i in candidates {
        if fast
            .observe(&manifest.documents()[i], &tables[i].bytes, &|| false)
            .unwrap()
        {
            break;
        }
    }
    assert_eq!(fast.matches, scalar.matches);
    assert_eq!(fast.more, scalar.more);
    let report = fast.finish(
        &manifest,
        *manifest.source.head.as_internal_object_id(),
        1,
        directory.bytes.len(),
    );
    assert_eq!(report.indexed_declarations, 24_000);
    report.validate_coverage().unwrap();
    let mut invalid = report.clone();
    invalid.indexed_declarations = MAX_INDEX_DECLARATIONS + 1;
    assert!(invalid.validate_coverage().is_err());
    invalid = report;
    invalid.indexed_files = 1;
    assert!(invalid.validate_coverage().is_err());

    let reuse = verified_reuse(&manifest, &tables);
    original.objects.blob_reads.set(0);
    let unchanged = original.prepare(Some(&reuse)).unwrap();
    assert_eq!(unchanged.reused_files(), 24);
    assert_eq!(unchanged.source().files_read, 0);
    assert_eq!(original.objects.blob_reads.get(), 0);
    let (same, fresh, same_directory) = unchanged
        .finish_with_directory(original.source.clone(), &|| false)
        .unwrap();
    assert!(fresh.is_empty());
    assert_eq!(same.encode(&|| false).unwrap().bytes, encoded.bytes);
    assert_eq!(same_directory.unwrap().bytes, directory.bytes);

    // Current raw paths and source binding change. A fresh table and a whole
    // malformed-file omission must agree with a full build of that same tree.
    files[0].0 = b"renamed.rs".to_vec();
    files[23].1.extend_from_slice(b"fn Added() {}\n");
    files.push((b"z_broken.rs".to_vec(), b"fn Discarded() {}\n(".to_vec()));
    let current = Fixture::new(&files);
    let full = current.prepare(None).unwrap();
    let refreshed = current.prepare(Some(&reuse)).unwrap();
    assert_eq!(refreshed.reused_files(), 23);
    assert_eq!(refreshed.source().files_read, 2);
    let (full, _, full_directory) = full
        .finish_with_directory(current.source.clone(), &|| false)
        .unwrap();
    let (refreshed, fresh, refreshed_directory) = refreshed
        .finish_with_directory(current.source.clone(), &|| false)
        .unwrap();
    assert_eq!(refreshed.declarations(), 24_001);
    assert_eq!(refreshed.omissions().len(), 1);
    assert_eq!(refreshed.omissions()[0].path, b"z_broken.rs");
    assert_eq!(fresh.len(), 1);
    assert_ne!(full.source(), manifest.source());
    assert_eq!(
        full.encode(&|| false).unwrap().bytes,
        refreshed.encode(&|| false).unwrap().bytes
    );
    assert_eq!(
        full_directory.unwrap().bytes,
        refreshed_directory.unwrap().bytes
    );
}

#[test]
fn repository_limit_counts_verified_reuse_and_directory_size_fallback_retains_all_rows() {
    let body = declarations("N", 1024);
    let (doc, table) = document(Format::Sha1, b"file000.rs", &body);
    let mut files: Vec<_> = (0..MAX_INDEX_DECLARATIONS / 1024)
        .map(|i| (format!("file{i:03}.rs").into_bytes(), body.clone()))
        .collect();
    let fixture = Fixture::new(&files);
    let manifest = Manifest {
        source: fixture.source.clone(),
        documents: files
            .iter()
            .map(|(path, _)| Document {
                path: path.clone(),
                ..doc.clone()
            })
            .collect(),
        unsupported: 0,
        non_regular: 0,
        omissions: Vec::new(),
    };
    let encoded = manifest.encode(&|| false).unwrap();
    assert_eq!(
        Manifest::decode(&encoded.bytes, encoded.root, &|| false)
            .unwrap()
            .declarations(),
        MAX_INDEX_DECLARATIONS
    );
    let reuse = verified_reuse(&manifest, std::slice::from_ref(&table));
    let prepared = fixture.prepare(Some(&reuse)).unwrap();
    assert_eq!(prepared.reused_files(), files.len());
    assert_eq!(fixture.objects.blob_reads.get(), 0);
    let (complete, fresh, directory) = prepared
        .finish_with_directory(fixture.source.clone(), &|| false)
        .unwrap();
    assert!(fresh.is_empty());
    assert!(
        directory.is_none(),
        "131,072 complete postings exceed the unchanged 1 MiB directory payload"
    );
    assert_eq!(complete.encode(&|| false).unwrap().bytes, encoded.bytes);
    assert!(complete.omissions().is_empty());

    // The last file is syntactically invalid, but exceeding the aggregate
    // declaration budget happens first and must never become an omission.
    files.push((b"z_broken.rs".to_vec(), b"fn Beyond() {}\n(".to_vec()));
    let over = Fixture::new(&files);
    assert!(matches!(
        over.prepare(Some(&reuse)),
        Err(Error::Table(table::Error::Syntax(engine::Error {
            kind: engine::ErrorKind::DeclarationLimit,
            ..
        })))
    ));
    let mut over_manifest = manifest.clone();
    over_manifest
        .documents
        .push(document(Format::Sha1, b"z_extra.rs", b"fn X(){}\n").0);
    assert!(matches!(
        over_manifest.encode(&|| false),
        Err(Error::Limit("declarations"))
    ));

    // One fewer retained declaration admits one late syntax omission. Its
    // discarded head is refunded, allowing the next valid file to fill the
    // exact repository boundary; the verified predecessor remains unchanged.
    files.pop();
    let last = files.last_mut().unwrap();
    last.1 = declarations("N", 1023);
    let (last_doc, last_table) = document(Format::Sha1, &last.0, &last.1);
    let before = Fixture::new(&files);
    let mut below = manifest;
    below.source = before.source.clone();
    *below.documents.last_mut().unwrap() = last_doc;
    let below_reuse = verified_reuse(&below, &[table, last_table]);
    files.push((b"z_broken.rs".to_vec(), b"fn Discarded() {}\n(".to_vec()));
    files.push((b"zz_after.rs".to_vec(), b"fn Last() {}\n".to_vec()));
    let after = Fixture::new(&files);
    let prepared = after.prepare(Some(&below_reuse)).unwrap();
    assert_eq!(prepared.source().files_read, 2);
    let (complete, _) = prepared.finish(after.source.clone(), &|| false).unwrap();
    assert_eq!(complete.declarations(), MAX_INDEX_DECLARATIONS);
    assert_eq!(complete.omissions().len(), 1);
    assert_eq!(
        complete.omissions()[0].reason,
        OmissionReason::UnbalancedDelimiter
    );
}

#[test]
fn per_file_table_limit_stays_fatal_and_cannot_be_forged_in_a_larger_manifest() {
    for format in [Format::Sha1, Format::Sha256] {
        let exact = "fn f(){}\n".repeat(engine::MAX_DECLARATIONS);
        let (doc, _) = document(format, b"a.rs", exact.as_bytes());
        let mut manifest = Manifest {
            source: source(format),
            documents: vec![doc],
            unsupported: 0,
            non_regular: 0,
            omissions: Vec::new(),
        };
        manifest.encode(&|| false).unwrap();
        manifest.documents[0].declarations += 1;
        assert!(matches!(
            manifest.encode(&|| false),
            Err(Error::Invalid("document catalog"))
        ));
    }
    let body = "fn f(){}\n"
        .repeat(engine::MAX_DECLARATIONS + 1)
        .into_bytes();
    let fixture = Fixture::new(&[(b"a.rs".to_vec(), body)]);
    assert!(matches!(
        fixture.prepare(None),
        Err(Error::Table(table::Error::Syntax(engine::Error {
            kind: engine::ErrorKind::DeclarationLimit,
            ..
        })))
    ));
}
