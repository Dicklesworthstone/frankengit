//! Incremental preparation reuses only complete, commitment-checked tables.
//! The caller must select the manifest through authenticated generation state.
//! Neither a manifest nor a table grants access to a current source path.
use super::{BTreeMap, Document, Error, GitOid, Manifest, Source, check, decode_table, directory};

/// Actual refresh work, separate from canonical manifest identity. Reused
/// files still count toward all resulting-corpus size/declaration ceilings.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RefreshStats {
    pub reused_files: usize,
    pub source_blobs_read: usize,
    pub source_bytes_read: usize,
    pub predecessor_tables_read: usize,
    pub predecessor_payload_bytes: usize,
}

/// Streaming verifier for a predecessor's tables. Only one table's bytes need
/// be retained at a time; duplicate native blobs require one verification.
/// A failed verification leaves that exact table pending, never reusable.
pub struct ReuseVerifier {
    source: Source,
    pending: BTreeMap<GitOid, Document>,
    verified: BTreeMap<GitOid, Document>,
    names: BTreeMap<GitOid, directory::Names>,
}

/// Complete verified predecessor inventory, not repository authority. Its
/// private entries cannot be populated from caller-supplied document metadata.
pub struct VerifiedReuse {
    source: Source,
    documents: BTreeMap<GitOid, Document>,
    names: BTreeMap<GitOid, directory::Names>,
}

fn same_table(left: &Document, right: &Document) -> bool {
    left.blob == right.blob
        && left.root == right.root
        && left.encoded_bytes == right.encoded_bytes
        && left.source_bytes == right.source_bytes
        && left.declarations == right.declarations
        && left.macros == right.macros
        && left.attributes == right.attributes
}

impl ReuseVerifier {
    /// Validate the complete manifest before any table reads. Source selection
    /// and generation/profile authentication remain the native owner's job.
    pub fn new(manifest: &Manifest, cancelled: &dyn Fn() -> bool) -> Result<Self, Error> {
        manifest.encode(cancelled)?;
        let mut pending = BTreeMap::new();
        for doc in manifest.documents() {
            check(cancelled)?;
            if let Some(previous) = pending.get(&doc.blob) {
                if !same_table(previous, doc) {
                    return Err(Error::Invalid("conflicting tables for native blob"));
                }
            } else {
                pending.insert(doc.blob, doc.clone());
            }
        }
        Ok(Self {
            source: manifest.source().clone(),
            pending,
            verified: BTreeMap::new(),
            names: BTreeMap::new(),
        })
    }

    /// The next exact payload to read, in deterministic native-object order.
    #[must_use]
    pub fn next_document(&self) -> Option<&Document> {
        self.pending.first_key_value().map(|(_, doc)| doc)
    }

    /// Authenticate the next table's frame, native identity, directory, spans
    /// and counters. Do not remove responsibility on an error or cancellation.
    pub fn verify_next(&mut self, raw: &[u8], cancelled: &dyn Fn() -> bool) -> Result<(), Error> {
        check(cancelled)?;
        let doc = self
            .next_document()
            .ok_or(Error::Invalid("unexpected reuse table"))?;
        let table = decode_table(doc, raw, cancelled)?;
        let names = directory::summarize(&table, cancelled)?;
        check(cancelled)?;
        let doc = doc.clone();
        self.pending.remove(&doc.blob);
        self.names.insert(doc.blob, names);
        self.verified.insert(doc.blob, doc);
        Ok(())
    }

    /// Missing backing is not an empty cache or a request to rescan silently.
    pub fn finish(self, cancelled: &dyn Fn() -> bool) -> Result<VerifiedReuse, Error> {
        check(cancelled)?;
        if !self.pending.is_empty() {
            return Err(Error::Invalid("unverified reuse tables"));
        }
        Ok(VerifiedReuse {
            source: self.source,
            documents: self.verified,
            names: self.names,
        })
    }
}

impl VerifiedReuse {
    #[must_use]
    pub const fn source(&self) -> &Source {
        &self.source
    }

    pub(super) fn document(&self, blob: &GitOid) -> Option<&Document> {
        self.documents.get(blob)
    }
    pub(super) fn names(&self, blob: &GitOid) -> Result<&directory::Names, Error> {
        self.names
            .get(blob)
            .ok_or(Error::Invalid("missing verified names"))
    }
}

pub(super) fn same_namespace(left: &Source, right: &Source) -> bool {
    left.tenant == right.tenant
        && left.repository == right.repository
        && left.incarnation == right.incarnation
        && left.format == right.format
        && left.reference == right.reference
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_symbols::index::{
        Format, Payload, SchemaFamily, TenantId, engine, table, table_payload,
    };
    use fgit_crypto::{
        GitObjectKind, IdentityDomain, git_object_id, internal_algorithm_id, internal_digest_value,
        internal_object_id,
    };
    use fgit_types::{
        CodecVersion, Digest, RefName, RepositoryAuthorityHeadId, RepositoryCommitId, RepositoryId,
        RepositoryIncarnationId, SchemaId,
    };

    fn source(format: Format) -> Source {
        let id = |domain, family| {
            internal_object_id(
                domain,
                SchemaId::new(SchemaFamily::from_static(family), 1, 0),
                CodecVersion::new(1, 0),
                b"reuse-test",
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

    fn document(format: Format, path: &[u8], bytes: &[u8]) -> (Document, Payload) {
        let table = table::Table::build(
            bytes,
            &mut engine::Budget::new(engine::MAX_WORK).unwrap(),
            &|| false,
        )
        .unwrap();
        let blob = git_object_id(format, GitObjectKind::Blob, bytes);
        let payload = table_payload(blob, &table, &|| false).unwrap();
        (
            Document {
                path: path.to_vec(),
                blob,
                root: payload.root,
                encoded_bytes: payload.bytes.len(),
                source_bytes: bytes.len(),
                declarations: table.rows().len(),
                macros: table.macros,
                attributes: table.attributes,
            },
            payload,
        )
    }

    fn manifest(format: Format) -> (Manifest, Payload) {
        let (doc, payload) = document(format, b"old.rs", b"pub struct Example;\n");
        (
            Manifest {
                source: source(format),
                documents: vec![doc],
                unsupported: 0,
                non_regular: 0,
            },
            payload,
        )
    }

    #[test]
    fn incomplete_reuse_never_becomes_an_empty_success() {
        let (manifest, _) = manifest(Format::Sha1);
        let verifier = ReuseVerifier::new(&manifest, &|| false).unwrap();
        assert!(matches!(
            verifier.finish(&|| false),
            Err(Error::Invalid("unverified reuse tables"))
        ));
        let empty = Manifest {
            documents: vec![],
            ..manifest
        };
        assert!(
            ReuseVerifier::new(&empty, &|| false)
                .unwrap()
                .finish(&|| false)
                .is_ok()
        );
    }

    #[test]
    fn substitution_and_cancellation_leave_the_exact_table_pending() {
        for format in [Format::Sha1, Format::Sha256] {
            let (manifest, payload) = manifest(format);
            let (_, foreign) = document(format, b"other.rs", b"fn Other() {}\n");
            let mut verifier = ReuseVerifier::new(&manifest, &|| false).unwrap();
            assert!(verifier.verify_next(&foreign.bytes, &|| false).is_err());
            assert!(verifier.verify_next(&payload.bytes, &|| true).is_err());
            let mut corrupt = payload.bytes.clone();
            let last = corrupt.len() - 1;
            corrupt[last] ^= 1;
            assert!(verifier.verify_next(&corrupt, &|| false).is_err());
            assert_eq!(verifier.next_document(), Some(&manifest.documents[0]));
            verifier.verify_next(&payload.bytes, &|| false).unwrap();
            assert!(verifier.next_document().is_none());
            assert!(verifier.verify_next(&payload.bytes, &|| false).is_err());
            let reuse = verifier.finish(&|| false).unwrap();
            assert_eq!(
                reuse.document(&manifest.documents[0].blob),
                Some(&manifest.documents[0])
            );
        }
    }

    #[test]
    fn identical_blobs_share_one_verified_table_across_renames_and_copies() {
        for format in [Format::Sha1, Format::Sha256] {
            let (mut manifest, payload) = manifest(format);
            let mut copy = manifest.documents[0].clone();
            copy.path = b"z-copy.rs".to_vec();
            manifest.documents.push(copy);
            let mut verifier = ReuseVerifier::new(&manifest, &|| false).unwrap();
            verifier.verify_next(&payload.bytes, &|| false).unwrap();
            assert!(verifier.next_document().is_none());
            let reuse = verifier.finish(&|| false).unwrap();
            let cached = reuse.document(&manifest.documents[0].blob).unwrap();
            let (rebuilt, rebuilt_payload) =
                document(format, b"renamed.rs", b"pub struct Example;\n");
            let mut renamed = cached.clone();
            renamed.path = b"renamed.rs".to_vec();
            assert_eq!(renamed, rebuilt);
            assert_eq!(payload.bytes, rebuilt_payload.bytes);
            assert!(
                reuse
                    .document(&git_object_id(
                        format,
                        GitObjectKind::Blob,
                        b"fn Changed() {}\n"
                    ))
                    .is_none()
            );
        }
    }

    #[test]
    fn a_native_blob_cannot_select_two_table_commitments() {
        let (mut manifest, _) = manifest(Format::Sha256);
        let (other, _) = document(Format::Sha256, b"other.rs", b"fn Other() {}\n");
        let mut duplicate = manifest.documents[0].clone();
        duplicate.path = b"z.rs".to_vec();
        duplicate.root = other.root;
        manifest.documents.push(duplicate);
        assert!(matches!(
            ReuseVerifier::new(&manifest, &|| false),
            Err(Error::Invalid("conflicting tables for native blob"))
        ));
    }

    #[test]
    fn namespace_binding_allows_new_snapshots_but_not_scope_substitution() {
        let source = source(Format::Sha1);
        let mut changed = source.clone();
        changed.commit = git_object_id(Format::Sha1, GitObjectKind::Commit, b"next");
        assert!(same_namespace(&source, &changed));
        changed.tenant = TenantId::from_bytes([9; 16]);
        assert!(!same_namespace(&source, &changed));
        changed = source.clone();
        changed.reference = RefName::try_new(b"refs/heads/other").unwrap();
        assert!(!same_namespace(&source, &changed));
        changed = source.clone();
        changed.incarnation = RepositoryIncarnationId::from_bytes([9; 16]);
        assert!(!same_namespace(&source, &changed));
        changed = source.clone();
        changed.format = Format::Sha256;
        assert!(!same_namespace(&source, &changed));
    }
}
