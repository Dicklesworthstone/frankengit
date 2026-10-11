//! Real lexical codecs and the explicit in-memory reference authority. These
//! tests establish bounded protocol behavior, not disk/runtime durability.
use super::super::{
    LexicalIndexStore, LexicalSource, PreparedLexicalIndex, RefreshDocument,
    manifest::Manifest,
    scoped::{LexicalScope, PreparedScopedLexicalIndex, ScopedLexicalIndexStore},
};
use super::*;
use crate::lexical::encoding::{decode_limits, payload_root};
use crate::lexical::{
    LexicalChannel, LexicalNamespace, LexicalQuery, LexicalQueryLimits, LexicalSegment,
    SourceDocument,
};
use fgit_authority::{MemoryAuthorityStore, StoreInstanceId};
use fgit_codec::{CanonicalBody, CodecRefusal, decode_body, encode_body, read_frame_header};
use fgit_crypto::{
    GitObjectKind, IdentityDomain, git_object_id, internal_algorithm_id, internal_digest_value,
    internal_object_id,
};
use fgit_types::{
    CodecVersion, Digest, DomainTag, RefName, RepositoryAuthorityHeadId, RepositoryCommitId,
    RepositoryId, RepositoryIncarnationId, SchemaFamily, SchemaId, TenantId,
};

fn source(format: GitHashAlgorithm) -> LexicalSource {
    let id = |domain, family: &'static str| {
        internal_object_id(
            domain,
            SchemaId::new(SchemaFamily::from_static(family), 1, 0),
            CodecVersion::new(1, 0),
            b"lexical-omission-source",
        )
    };
    LexicalSource {
        namespace: LexicalNamespace {
            tenant: TenantId::from_bytes([1; 16]),
            repository: RepositoryId::from_bytes([2; 16]),
            incarnation: RepositoryIncarnationId::from_bytes([3; 16]),
            object_format: format,
        },
        reference: RefName::try_new(b"refs/heads/main").unwrap(),
        source_head: RepositoryAuthorityHeadId::from_internal_object_id(id(
            IdentityDomain::RepositoryAuthorityHead,
            "repository-authority-head",
        ))
        .unwrap(),
        source_rcr: RepositoryCommitId::from_internal_object_id(id(
            IdentityDomain::RepositoryCommitRecord,
            "repository-commit-record",
        ))
        .unwrap(),
        forge_position_root: Digest::new(
            internal_algorithm_id(IdentityDomain::MerkleLeaf),
            internal_digest_value(
                IdentityDomain::MerkleLeaf,
                SchemaId::new(SchemaFamily::from_static("omission-test"), 1, 0),
                b"source",
            ),
        ),
        commit: git_object_id(format, GitObjectKind::Commit, b"commit"),
        tree: git_object_id(format, GitObjectKind::Tree, b"tree"),
    }
}
fn omitted(format: GitHashAlgorithm, path: &[u8]) -> LexicalOmission {
    LexicalOmission {
        path: path.to_vec(),
        blob: git_object_id(format, GitObjectKind::Blob, b"oversized bytes"),
        source_bytes: b"oversized bytes".len(),
        reason: LexicalOmissionReason::FileBytes,
        limit: 2,
    }
}
fn segment(source: &LexicalSource) -> LexicalSegment {
    LexicalSegment::build(
        source.namespace,
        1,
        [b"src/a.rs".as_slice(), b"src/c.rs".as_slice()].map(|path| SourceDocument {
            path,
            blob: git_object_id(
                source.namespace.object_format,
                GitObjectKind::Blob,
                b"needle",
            ),
            content: b"needle",
        }),
        &mut || true,
    )
    .unwrap()
}
fn prepared(format: GitHashAlgorithm) -> PreparedLexicalIndex {
    let source = source(format);
    PreparedLexicalIndex::with_omissions(
        source.clone(),
        vec![segment(&source)],
        1,
        vec![omitted(format, b"src/b\xff.rs")],
        &mut || true,
    )
    .unwrap()
}
fn search(
    index: &LexicalIndexStore<'_, MemoryAuthorityStore>,
    needle: &[u8],
    limit: usize,
) -> super::super::IndexedLexicalReport {
    let selection = index
        .select(None, None, Default::default(), &mut || true)
        .unwrap();
    let query = LexicalQuery::new(LexicalChannel::Content, &[needle.to_vec()], &[]).unwrap();
    index
        .search(
            &selection,
            &query,
            None,
            Default::default(),
            LexicalQueryLimits {
                max_results: limit,
                ..Default::default()
            },
            &mut || true,
        )
        .unwrap()
}

#[test]
fn authenticated_omissions_roundtrip_in_both_formats_and_plain_generations_remain_v1() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let partial = prepared(format);
        let payload = partial
            .metadata
            .iter()
            .find(|p| p.kind == "manifest")
            .unwrap();
        assert_eq!(
            read_frame_header(&payload.bytes, decode_limits())
                .unwrap()
                .0
                .schema
                .major(),
            2
        );
        let decoded = Manifest::decode(
            &payload.bytes,
            payload.root,
            partial.source().namespace,
            &mut || true,
        )
        .unwrap();
        assert_eq!(decoded.omissions, partial.omissions());
        assert_eq!(
            decoded
                .payloads(&mut || true)
                .unwrap()
                .last()
                .unwrap()
                .bytes,
            payload.bytes
        );
        assert!(
            Manifest::decode(
                &payload.bytes[..payload.bytes.len() - 1],
                payload.root,
                partial.source().namespace,
                &mut || true
            )
            .is_err()
        );
        assert!(matches!(
            Manifest::decode(
                &payload.bytes,
                payload.root,
                partial.source().namespace,
                &mut || false
            ),
            Err(IndexError::Lexical(LexicalError::Cancelled))
        ));
        let plain = PreparedLexicalIndex::new(
            partial.source().clone(),
            vec![segment(partial.source())],
            1,
            &mut || true,
        )
        .unwrap();
        let empty = PreparedLexicalIndex::with_omissions(
            partial.source().clone(),
            vec![segment(partial.source())],
            1,
            Vec::new(),
            &mut || true,
        )
        .unwrap();
        for (legacy, empty) in plain.metadata.iter().zip(&empty.metadata) {
            assert_eq!(legacy.bytes, empty.bytes);
            assert_eq!(
                read_frame_header(&legacy.bytes, decode_limits())
                    .unwrap()
                    .0
                    .schema
                    .major(),
                1
            );
        }
        for kind in ["documents", "postings"] {
            assert_eq!(
                plain
                    .metadata
                    .iter()
                    .find(|p| p.kind == kind)
                    .unwrap()
                    .bytes,
                partial
                    .metadata
                    .iter()
                    .find(|p| p.kind == kind)
                    .unwrap()
                    .bytes
            );
        }
        let changed = PreparedLexicalIndex::with_omissions(
            partial.source().clone(),
            vec![segment(partial.source())],
            1,
            vec![LexicalOmission {
                limit: 3,
                ..partial.omissions()[0].clone()
            }],
            &mut || true,
        )
        .unwrap();
        for kind in ["manifest", "evidence"] {
            assert_ne!(
                changed
                    .metadata
                    .iter()
                    .find(|p| p.kind == kind)
                    .unwrap()
                    .root,
                partial
                    .metadata
                    .iter()
                    .find(|p| p.kind == kind)
                    .unwrap()
                    .root
            );
        }
    }
}

#[test]
fn coverage_is_incomplete_for_empty_complete_and_truncated_match_pages() {
    let prepared = prepared(GitHashAlgorithm::Sha256);
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(1001));
    let index = LexicalIndexStore::new(
        &store,
        prepared.source().namespace,
        prepared.source().reference.clone(),
    )
    .unwrap();
    let activation = index.publish(&prepared, None, &mut || true).unwrap();
    assert!(matches!(
        index.publish(&prepared, None, &mut || true),
        Err(IndexError::Generation(
            crate::GenerationAuthorityError::PredecessorMismatch { .. }
        ))
    ));
    assert!(matches!(
        index.recover(activation.generation_id, None, Default::default(), &mut || true).unwrap(),
        crate::GenerationRecovery::Active { selected } if selected.activation() == &activation
    ));
    for (needle, limit, matches, complete) in [
        (b"absent".as_slice(), 2, 0, true),
        (b"needle".as_slice(), 2, 2, true),
        (b"needle".as_slice(), 1, 1, false),
    ] {
        let report = search(&index, needle, limit);
        assert_eq!(report.results.hits.len(), matches);
        assert_eq!(report.results.complete, complete);
        assert!(!report.coverage_complete);
        assert_eq!(report.omissions, prepared.omissions());
        assert_eq!(
            report.validate_coverage().unwrap(),
            prepared.omissions()[0].source_bytes
        );
        let mut forged = report.clone();
        forged.coverage_complete = true;
        assert!(forged.validate_coverage().is_err());
        if !report.results.hits.is_empty() {
            let mut undercounted = report.clone();
            undercounted.indexed_documents = report.results.hits.len() - 1;
            assert!(undercounted.validate_coverage().is_err());
            let mut undercounted = report.clone();
            undercounted.indexed_source_bytes = report
                .results
                .hits
                .iter()
                .map(|hit| hit.content_bytes as usize)
                .sum::<usize>()
                - 1;
            assert!(undercounted.validate_coverage().is_err());
            let mut forged = report;
            forged.results.hits[0].path = forged.omissions[0].path.clone();
            assert!(forged.validate_coverage().is_err());
        }
    }
}

#[test]
fn omission_validation_preserves_native_identity_disjoint_order_and_combined_limits() {
    let format = GitHashAlgorithm::Sha1;
    let source = source(format);
    let valid = omitted(format, b"src/b.rs");
    let mut invalid = Vec::new();
    for path in [b"src/a.rs".as_slice(), b"../bad.rs", b"bad\0.rs"] {
        invalid.push(vec![LexicalOmission {
            path: path.to_vec(),
            ..valid.clone()
        }]);
    }
    invalid.push(vec![valid.clone(), valid.clone()]);
    invalid.push(vec![omitted(format, b"src/z.rs"), valid.clone()]);
    invalid.push(vec![LexicalOmission {
        blob: git_object_id(GitHashAlgorithm::Sha256, GitObjectKind::Blob, b"other"),
        ..valid.clone()
    }]);
    for limit in [0, valid.source_bytes, MAX_FILE_BYTES + 1] {
        invalid.push(vec![LexicalOmission {
            limit,
            ..valid.clone()
        }]);
    }
    invalid.push(vec![LexicalOmission {
        source_bytes: MAX_SOURCE_BYTES + 1,
        ..valid.clone()
    }]);
    for omissions in invalid {
        assert!(
            PreparedLexicalIndex::with_omissions(
                source.clone(),
                vec![segment(&source)],
                0,
                omissions,
                &mut || true
            )
            .is_err()
        );
    }
    assert!(
        validate(
            &[valid.clone()],
            format,
            MAX_INDEX_DOCUMENTS,
            0,
            &mut || true
        )
        .is_err()
    );
    assert!(
        validate(
            &[valid.clone()],
            format,
            0,
            MAX_SOURCE_BYTES - valid.source_bytes + 1,
            &mut || true
        )
        .is_err()
    );
    assert_eq!(
        validate(
            &[valid.clone()],
            format,
            MAX_INDEX_DOCUMENTS - 1,
            MAX_SOURCE_BYTES - valid.source_bytes,
            &mut || true
        )
        .unwrap(),
        valid.source_bytes
    );
    let too_large = LexicalOmission {
        source_bytes: MAX_SOURCE_BYTES - 11,
        ..valid
    };
    assert!(
        PreparedLexicalIndex::with_omissions(
            source.clone(),
            vec![segment(&source)],
            0,
            vec![too_large],
            &mut || true
        )
        .is_err()
    );
}

#[test]
fn refreshed_generation_requires_new_omissions_and_rescans_formerly_omitted_blobs() {
    let format = GitHashAlgorithm::Sha256;
    let partial = prepared(format);
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(1002));
    let index = LexicalIndexStore::new(
        &store,
        partial.source().namespace,
        partial.source().reference.clone(),
    )
    .unwrap();
    index.publish(&partial, None, &mut || true).unwrap();
    let selection = index
        .select(None, None, Default::default(), &mut || true)
        .unwrap();
    let reuse = index
        .load_refresh_base(&selection, Default::default(), &mut || true)
        .unwrap();
    let omission = &partial.omissions()[0];
    assert_eq!(reuse.document_bytes(&omission.path, omission.blob), None);
    let mut rows = vec![
        RefreshDocument {
            path: b"src/a.rs",
            blob: git_object_id(format, GitObjectKind::Blob, b"needle"),
            content: None,
        },
        RefreshDocument {
            path: b"src/c.rs",
            blob: git_object_id(format, GitObjectKind::Blob, b"needle"),
            content: None,
        },
    ];
    let (same, stats) = reuse
        .prepare_with_omissions(
            partial.source().clone(),
            &rows,
            1,
            partial.omissions().to_vec(),
            &mut || true,
        )
        .unwrap();
    assert_eq!(stats.reused_documents, 2);
    assert_eq!(
        index.candidate_id(&same, None).unwrap(),
        index.candidate_id(&partial, None).unwrap()
    );
    rows.insert(
        1,
        RefreshDocument {
            path: &omission.path,
            blob: omission.blob,
            content: None,
        },
    );
    assert!(
        reuse
            .prepare(partial.source().clone(), &rows, 1, &mut || true)
            .is_err()
    );
    rows[1].content = Some(b"oversized bytes");
    let (complete, stats) = reuse
        .prepare(partial.source().clone(), &rows, 1, &mut || true)
        .unwrap();
    assert_eq!(stats.reused_documents, 2);
    assert_eq!(stats.rebuilt_documents, 1);
    assert_eq!(complete.document_count(), 3);
    assert!(complete.omissions().is_empty());
    assert!(
        reuse
            .prepare_with_omissions(
                partial.source().clone(),
                &rows,
                1,
                partial.omissions().to_vec(),
                &mut || true
            )
            .is_err()
    );
    assert!(matches!(
        reuse.prepare_with_omissions(partial.source().clone(), &rows, 1, Vec::new(), &mut || {
            false
        }),
        Err(IndexError::Lexical(LexicalError::Cancelled))
    ));
}

#[test]
fn scoped_omissions_cannot_escape_coverage_in_initial_or_refresh_preparation() {
    let format = GitHashAlgorithm::Sha1;
    let source = source(format);
    let scope = LexicalScope::new(&[b"src".to_vec()]).unwrap();
    let make = |path: &[u8]| {
        PreparedScopedLexicalIndex::with_omissions(
            source.clone(),
            scope.clone(),
            vec![segment(&source)],
            0,
            vec![omitted(format, path)],
            &mut || true,
        )
    };
    assert!(make(b"src-other/secret").is_err());
    let partial = make(b"src/b.rs").unwrap();
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(1003));
    let index =
        ScopedLexicalIndexStore::new(&store, source.namespace, source.reference.clone(), scope)
            .unwrap();
    index.publish(&partial, None, &mut || true).unwrap();
    let selection = index
        .select(None, None, Default::default(), &mut || true)
        .unwrap();
    let reuse = index
        .load_refresh_base(&selection, Default::default(), &mut || true)
        .unwrap();
    assert!(
        reuse
            .prepare_with_omissions(
                source.clone(),
                &[],
                0,
                vec![omitted(format, b"src-other/secret")],
                &mut || true
            )
            .is_err()
    );
    let (only_omissions, _) = reuse
        .prepare_with_omissions(source, &[], 0, partial.omissions().to_vec(), &mut || true)
        .unwrap();
    index
        .publish(
            &only_omissions,
            Some(selection.activation().generation_id),
            &mut || true,
        )
        .unwrap();
    let selection = index
        .select(None, None, Default::default(), &mut || true)
        .unwrap();
    let query = LexicalQuery::new(LexicalChannel::Content, &[b"needle".to_vec()], &[]).unwrap();
    let report = index
        .search(
            &selection,
            &query,
            None,
            Default::default(),
            Default::default(),
            &mut || true,
        )
        .unwrap();
    assert!(report.index.results.hits.is_empty());
    assert!(report.index.results.complete);
    assert!(!report.index.coverage_complete);
    assert!(report.index.validate_coverage().is_ok());
}

struct OmissionManifestFrame(Vec<u8>);
impl CanonicalBody for OmissionManifestFrame {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/generation/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("source-lexical-manifest");
    const SCHEMA_MAJOR: u16 = 2;
    const SCHEMA_MINOR: u16 = 0;
    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_bytes("source-lexical-manifest", &self.0)
    }
    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        Ok(Self(input.read_bytes("source-lexical-manifest")?.to_vec()))
    }
}

#[test]
fn authenticated_unknown_omission_reason_and_forged_segment_overlap_refuse() {
    let partial = prepared(GitHashAlgorithm::Sha1);
    let payload = partial
        .metadata
        .iter()
        .find(|p| p.kind == "manifest")
        .unwrap();
    let mut frame = decode_body::<OmissionManifestFrame>(&payload.bytes, decode_limits()).unwrap();
    let reason_at = frame.0.len() - 9;
    frame.0[reason_at] = 255;
    assert!(matches!(
        Manifest::decode(
            &encode_body(&frame).unwrap(),
            payload_root(&frame).unwrap(),
            partial.source().namespace,
            &mut || true
        ),
        Err(IndexError::Lexical(LexicalError::Invalid(
            "omission reason"
        )))
    ));
    let mut forged = prepared(GitHashAlgorithm::Sha1);
    forged.manifest.omissions[0].path = b"src/a.rs".to_vec();
    forged.metadata = forged.manifest.payloads(&mut || true).unwrap();
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(1004));
    let index = LexicalIndexStore::new(
        &store,
        forged.source().namespace,
        forged.source().reference.clone(),
    )
    .unwrap();
    index.publish(&forged, None, &mut || true).unwrap();
    let selection = index
        .select(None, None, Default::default(), &mut || true)
        .unwrap();
    let query = LexicalQuery::new(LexicalChannel::Content, &[b"needle".to_vec()], &[]).unwrap();
    assert!(
        index
            .search(
                &selection,
                &query,
                None,
                Default::default(),
                Default::default(),
                &mut || true
            )
            .is_err()
    );
    assert!(
        index
            .load_refresh_base(&selection, Default::default(), &mut || true)
            .is_err()
    );
}

fn many_omissions(count: usize) -> Vec<LexicalOmission> {
    let blob = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, b"xx");
    (0..count)
        .map(|n| LexicalOmission {
            path: format!("omit/{n:05}").into_bytes(),
            blob,
            source_bytes: 2,
            reason: LexicalOmissionReason::FileBytes,
            limit: 1,
        })
        .collect()
}

#[test]
fn omissions_must_fit_results_before_preparation_and_manifest_decode() {
    let source = source(GitHashAlgorithm::Sha1);
    // The canonical catalogs fit their independent 1 MiB limit in both twins.
    // 19,784 * (10 + 96) + 48 = exactly the 2 MiB retained-result allowance.
    let mut omissions = many_omissions(19_784);
    omissions.last_mut().unwrap().path.extend([b'x'; 48]);
    assert_eq!(
        omissions
            .iter()
            .map(|row| row.path.len() + 96)
            .sum::<usize>(),
        MAX_RESULT_BYTES
    );
    let prepared = PreparedLexicalIndex::with_omissions(
        source.clone(),
        Vec::new(),
        0,
        omissions.clone(),
        &mut || true,
    )
    .unwrap();
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(1010));
    let index = LexicalIndexStore::new(&store, source.namespace, source.reference.clone()).unwrap();
    let active = index.publish(&prepared, None, &mut || true).unwrap();
    let report = search(&index, b"needle", 1);
    assert!(report.results.complete);
    assert!(!report.coverage_complete);
    assert!(report.results.hits.is_empty());
    assert_eq!(report.segments_read, 0);
    assert_eq!(report.validate_coverage().unwrap(), 19_784 * 2);
    assert_eq!(report.omissions, omissions);

    // A one-byte larger inventory and the original 20,000-short-path case
    // must fail before there is a prepared generation to stage or publish.
    omissions.last_mut().unwrap().path.push(b'x');
    for invalid in [omissions.clone(), many_omissions(20_000)] {
        assert!(matches!(
            PreparedLexicalIndex::with_omissions(
                source.clone(),
                Vec::new(),
                0,
                invalid,
                &mut || true,
            ),
            Err(IndexError::Lexical(LexicalError::Limit("result bytes")))
        ));
    }

    // Produce correctly committed, canonical hostile metadata by bypassing
    // the public constructor in this module-private codec fixture. Selection
    // must reject the same inventory instead of deferring failure to queries.
    let mut forged = prepared.manifest.clone();
    forged.omissions = omissions;
    let metadata = forged.payloads(&mut || true).unwrap();
    let payload = metadata.iter().find(|row| row.kind == "manifest").unwrap();
    assert!(payload.bytes.len() <= crate::lexical::MAX_SEGMENT_BYTES);
    assert!(matches!(
        Manifest::decode(&payload.bytes, payload.root, source.namespace, &mut || true,),
        Err(IndexError::Lexical(LexicalError::Limit("result bytes")))
    ));
    assert_eq!(
        index
            .select(None, None, Default::default(), &mut || true)
            .unwrap()
            .activation(),
        &active
    );
}

#[test]
fn hit_and_omission_bytes_use_one_exact_retained_result_allowance() {
    let source = source(GitHashAlgorithm::Sha1);
    let paths: Vec<_> = (0..100)
        .map(|n| format!("hit/{n:03}/{}", "x".repeat(992)).into_bytes())
        .collect();
    assert_eq!(paths[0].len(), 1000);
    let segment = LexicalSegment::build(
        source.namespace,
        1,
        paths.iter().map(|path| SourceDocument {
            path,
            blob: git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, b"needle"),
            content: b"needle",
        }),
        &mut || true,
    )
    .unwrap();
    let prepared = PreparedLexicalIndex::with_omissions(
        source.clone(),
        vec![segment],
        0,
        many_omissions(19_000),
        &mut || true,
    )
    .unwrap();
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(1011));
    let index = LexicalIndexStore::new(&store, source.namespace, source.reference).unwrap();
    index.publish(&prepared, None, &mut || true).unwrap();
    let selection = index
        .select(None, None, Default::default(), &mut || true)
        .unwrap();
    let query = LexicalQuery::new(LexicalChannel::Content, &[b"needle".to_vec()], &[]).unwrap();
    // 19,000 * (10 + 96) + 76 * (1000 + 24 + 64) = 2,096,688.
    // One additional hit crosses the unchanged 2,097,152-byte result ceiling.
    for limit in [76, 77] {
        let report = index.search(
            &selection,
            &query,
            None,
            Default::default(),
            LexicalQueryLimits {
                max_results: limit,
                ..Default::default()
            },
            &mut || true,
        );
        if limit == 76 {
            let report = report.unwrap();
            assert_eq!(report.results.hits.len(), 76);
            assert!(!report.results.complete);
            assert!(!report.coverage_complete);
            assert_eq!(report.validate_coverage().unwrap(), 38_000);
        } else {
            assert!(matches!(
                report,
                Err(IndexError::Lexical(LexicalError::Limit("result bytes")))
            ));
        }
    }
}
