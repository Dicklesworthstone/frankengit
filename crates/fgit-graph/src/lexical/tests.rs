use super::*;

fn scope(format: GitHashAlgorithm) -> LexicalNamespace {
    LexicalNamespace { tenant: TenantId::from_bytes([1; 16]), repository: RepositoryId::from_bytes([2; 16]),
        incarnation: RepositoryIncarnationId::from_bytes([3; 16]), object_format: format }
}
fn build(format: GitHashAlgorithm, first: u64, rows: &[(&[u8], &[u8])]) -> LexicalSegment {
    LexicalSegment::build(scope(format), first, rows.iter().map(|(path, content)| SourceDocument {
        path, content, blob: git_object_id(format, GitObjectKind::Blob, content),
    }), &mut || true).unwrap()
}
fn query(channel: LexicalChannel, terms: &[&[u8]], paths: &[&[u8]]) -> LexicalQuery {
    LexicalQuery::new(channel, &terms.iter().map(|x| x.to_vec()).collect::<Vec<_>>(),
        &paths.iter().map(|x| x.to_vec()).collect::<Vec<_>>()).unwrap()
}
fn find(segment: &LexicalSegment, terms: &[&[u8]]) -> LexicalReport {
    segment.search(&query(LexicalChannel::Content, terms, &[]), None, Default::default(), &mut || true).unwrap()
}

#[test]
fn native_id_and_complete_token_semantics_for_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let s = build(format, 71, &[(b"a.rs", b"Alpha alpha\r\nbeta"), (b"b.rs", b"alphabet beta")]);
        let answer = find(&s, &[b"BETA", b"ALPHA", b"alpha"]);
        assert!(answer.complete); assert_eq!(answer.hits.len(), 1);
        assert_eq!(answer.hits[0].document_id, 71); assert_eq!(answer.hits[0].path, b"a.rs");
        assert_eq!(answer.hits[0].spans, vec![LexicalSpan { query_index: 0, byte_offset: 0, byte_length: 5 },
            LexicalSpan { query_index: 1, byte_offset: 13, byte_length: 4 }]);
        assert!(find(&s, &[b"alph"]).hits.is_empty());
        let bytes = s.encode(&mut || true).unwrap(); let root = s.root(&mut || true).unwrap();
        assert_eq!(LexicalSegment::decode(&bytes, root, scope(format), &mut || true).unwrap(), s);
        assert_eq!(s.documents()[0].blob, git_object_id(format, GitObjectKind::Blob, b"Alpha alpha\r\nbeta"));
    }
}
#[test]
fn binary_paths_empty_files_and_non_ascii_keep_original_byte_spans() {
    let s = build(GitHashAlgorithm::Sha256, 1, &[(b"a\xff.rs", b"\0\xffALPHA\r\n\xc3\xa9_beta"), (b"empty", b"")]);
    assert_eq!(find(&s, &[b"alpha"]).hits[0].spans[0].byte_offset, 2);
    assert_eq!(find(&s, &[b"_beta"]).hits[0].spans[0].byte_offset, 11);
    assert_eq!(find(&s, &[b"alpha"]).hits[0].path, b"a\xff.rs");
    assert!(find(&s, &[b"empty"]).hits.is_empty());
    let paths = s.search(&query(LexicalChannel::Path, &[b"empty"], &[]), None, Default::default(), &mut || true).unwrap();
    assert_eq!(paths.hits[0].content_bytes, 0); assert_eq!(paths.hits[0].spans[0].byte_length, 5);
}
#[test]
fn path_filters_use_components_not_string_prefixes() {
    let s = build(GitHashAlgorithm::Sha1, 1, &[(b"src/a", b"term"), (b"src2/a", b"term")]);
    let q = query(LexicalChannel::Content, &[b"term"], &[b"src"]);
    assert_eq!(s.search(&q, None, Default::default(), &mut || true).unwrap().hits.len(), 1);
    assert_eq!(s.search(&query(LexicalChannel::Path, &[b"src2"], &[]), None, Default::default(), &mut || true).unwrap().hits[0].document_id, 2);
}
#[test]
fn compaction_is_byte_identical_to_rebuild_without_renumbering() {
    let rows: Vec<(Vec<u8>, Vec<u8>)> = (0..25).map(|i| (format!("p/{i:03}.rs").into_bytes(),
        format!("COMMON symbol_{} repeated repeated", i % 7).into_bytes())).collect();
    let borrowed: Vec<_> = rows.iter().map(|(p, b)| (p.as_slice(), b.as_slice())).collect();
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let full = build(format, 1000, &borrowed);
        for size in [1, 2, 5, 8, 25] {
            let segments: Vec<_> = borrowed.chunks(size).enumerate()
                .map(|(i, rows)| build(format, 1000 + (i * size) as u64, rows)).collect();
            let compacted = LexicalSegment::concatenate(&segments, &mut || true).unwrap();
            assert_eq!(compacted, full);
            assert_eq!(compacted.encode(&mut || true).unwrap(), full.encode(&mut || true).unwrap());
            assert_eq!(compacted.root(&mut || true).unwrap(), full.root(&mut || true).unwrap());
            assert_eq!(find(&compacted, &[b"COMMON", b"symbol_3"]).hits, find(&full, &[b"common", b"symbol_3"]).hits);
        }
    }
}
#[test]
fn compaction_rejects_overlap_reordering_duplicate_paths_and_foreign_scope() {
    let a = build(GitHashAlgorithm::Sha1, 1, &[(b"a", b"x")]);
    let b = build(GitHashAlgorithm::Sha1, 2, &[(b"b", b"x")]);
    assert!(LexicalSegment::concatenate(&[a.clone(), b.clone()], &mut || true).is_ok());
    for segments in [vec![a.clone(), a.clone()], vec![b.clone(), a.clone()],
        vec![a.clone(), build(GitHashAlgorithm::Sha1, 2, &[(b"a", b"x")])]] {
        assert!(LexicalSegment::concatenate(&segments, &mut || true).is_err());
    }
    let mut foreign = b; foreign.namespace.incarnation = RepositoryIncarnationId::from_bytes([9; 16]);
    assert!(matches!(LexicalSegment::concatenate(&[a, foreign], &mut || true), Err(LexicalError::NamespaceMismatch)));
}
#[test]
fn pagination_observes_an_extra_hit_before_reporting_a_limit() {
    let s = build(GitHashAlgorithm::Sha1, 7, &[(b"a", b"x"), (b"b", b"x"), (b"c", b"x")]);
    let q = query(LexicalChannel::Content, &[b"x"], &[]);
    let limits = LexicalQueryLimits { max_results: 2, ..Default::default() };
    let first = s.search(&q, None, limits, &mut || true).unwrap();
    assert!(!first.complete); assert_eq!(first.next_after, Some(8));
    let last = s.search(&q, first.next_after, limits, &mut || true).unwrap();
    assert!(last.complete); assert_eq!(last.next_after, None); assert_eq!(last.hits[0].document_id, 9);
    let exact = s.search(&q, Some(7), limits, &mut || true).unwrap();
    assert!(exact.complete); assert_eq!(exact.hits.len(), 2);
    assert!(s.search(&q, Some(u64::MAX), limits, &mut || true).unwrap().hits.is_empty());
}
#[test]
fn rarest_posting_intersection_agrees_with_an_independent_scalar_corpus() {
    let rows: Vec<(Vec<u8>, Vec<u8>)> = (0..64u64).map(|mask| {
        let text = (0..6).filter(|bit| mask & (1 << bit) != 0).map(|bit| format!("W{bit} w{bit} ")).collect::<String>();
        (format!("d{mask:03}").into_bytes(), text.into_bytes())
    }).collect();
    let borrowed: Vec<_> = rows.iter().map(|(p, b)| (p.as_slice(), b.as_slice())).collect();
    let s = build(GitHashAlgorithm::Sha1, 101, &borrowed);
    for wanted in 1..64u64 {
        let terms: Vec<Vec<u8>> = (0..6).filter(|bit| wanted & (1 << bit) != 0).map(|bit| format!("w{bit}").into_bytes()).collect();
        let q = LexicalQuery::new(LexicalChannel::Content, &terms, &[]).unwrap();
        let report = s.search(&q, None, Default::default(), &mut || true).unwrap();
        let expected: Vec<u64> = (0..64u64).filter(|mask| mask & wanted == wanted).map(|mask| 101 + mask).collect();
        assert_eq!(report.hits.iter().map(|h| h.document_id).collect::<Vec<_>>(), expected);
        for hit in report.hits {
            let source = &rows[(hit.document_id - 101) as usize].1;
            for span in hit.spans {
                assert_eq!(source[span.byte_offset as usize..span.byte_offset as usize + span.byte_length as usize].to_ascii_lowercase(), q.terms()[span.query_index]);
            }
        }
    }
}
#[test]
fn decoder_rejects_substitution_truncation_suffix_and_cross_namespace() {
    let s = build(GitHashAlgorithm::Sha1, 1, &[(b"a", b"abc")]);
    let bytes = s.encode(&mut || true).unwrap(); let root = s.root(&mut || true).unwrap();
    for end in 0..bytes.len() { assert!(LexicalSegment::decode(&bytes[..end], root, s.namespace(), &mut || true).is_err()); }
    let mut longer = bytes.clone(); longer.push(0);
    assert!(LexicalSegment::decode(&longer, root, s.namespace(), &mut || true).is_err());
    let other = build(GitHashAlgorithm::Sha1, 1, &[(b"a", b"abd")]);
    assert!(matches!(LexicalSegment::decode(&other.encode(&mut || true).unwrap(), root, s.namespace(), &mut || true), Err(LexicalError::CommitmentMismatch)));
    let mut foreign = s.namespace(); foreign.tenant = TenantId::from_bytes([9; 16]);
    assert!(matches!(LexicalSegment::decode(&bytes, root, foreign, &mut || true), Err(LexicalError::NamespaceMismatch)));
}
#[test]
fn decoder_validates_structure_even_when_the_payload_digest_matches() {
    let s = build(GitHashAlgorithm::Sha1, 1, &[(b"a", b"abc"), (b"b", b"abc")]);
    for variant in 0..5 {
        let mut malformed = s.clone();
        match variant {
            0 => malformed.documents[1].id = 1,
            1 => malformed.documents[1].path = b"a".to_vec(),
            2 => malformed.terms.first_entry().unwrap().get_mut().documents[0] = 99,
            3 => malformed.terms.first_entry().unwrap().get_mut().offsets[0] = 99,
            _ => malformed.terms.first_entry().unwrap().get_mut().offsets.clear(),
        }
        let bytes = malformed.encode(&mut || true).unwrap(); let root = malformed.root(&mut || true).unwrap();
        assert!(LexicalSegment::decode(&bytes, root, s.namespace(), &mut || true).is_err());
    }
}
#[test]
fn invalid_documents_never_become_index_entries() {
    let format = GitHashAlgorithm::Sha1; let body = b"x";
    let blob = git_object_id(format, GitObjectKind::Blob, body);
    for path in [b"".as_slice(), b"/a", b"a/", b"a//b", b"../a", b"a/./b", b"a\0b"] {
        assert!(LexicalSegment::build(scope(format), 1, [SourceDocument { path, blob, content: body }], &mut || true).is_err());
    }
    assert!(matches!(LexicalSegment::build(scope(format), 1,
        [SourceDocument { path: b"a", blob, content: b"different" }], &mut || true), Err(LexicalError::NativeIdentityMismatch)));
    assert!(LexicalSegment::build(scope(format), 0, [SourceDocument { path: b"a", blob, content: body }], &mut || true).is_err());
    assert!(LexicalSegment::build(scope(format), u64::MAX, [SourceDocument { path: b"a", blob, content: body },
        SourceDocument { path: b"b", blob, content: body }], &mut || true).is_err());
}
#[test]
fn token_and_query_limits_have_permitted_boundary_twins() {
    let good = vec![b'a'; MAX_TERM_BYTES]; let bad = vec![b'a'; MAX_TERM_BYTES + 1];
    assert_eq!(find(&build(GitHashAlgorithm::Sha1, 1, &[(b"a", &good)]), &[&good]).hits.len(), 1);
    assert!(LexicalSegment::build(scope(GitHashAlgorithm::Sha1), 1, [SourceDocument { path: b"a", content: &bad,
        blob: git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, &bad) }], &mut || true).is_err());
    for term in [b"".as_slice(), b"a b", b"a-b", b"\xff", &bad] {
        assert!(LexicalQuery::new(LexicalChannel::Content, &[term.to_vec()], &[]).is_err());
    }
    assert!(LexicalQuery::new(LexicalChannel::Content, &[], &[]).is_err());
    assert!(LexicalQuery::new(LexicalChannel::Content, &vec![b"a".to_vec(); 33], &[]).is_err());
}
#[test]
fn cancellation_and_work_exhaustion_are_not_complete_empty_answers() {
    let s = build(GitHashAlgorithm::Sha1, 1, &[(b"a", b"alpha beta")]);
    let q = query(LexicalChannel::Content, &[b"alpha"], &[]);
    assert!(matches!(s.search(&q, None, Default::default(), &mut || false), Err(LexicalError::Cancelled)));
    assert!(matches!(s.search(&q, None, LexicalQueryLimits { max_work: 1, ..Default::default() }, &mut || true), Err(LexicalError::Limit("query work"))));
    let good = s.search(&q, None, Default::default(), &mut || true).unwrap();
    assert_eq!(s.search(&q, None, LexicalQueryLimits { max_work: good.work_units, ..Default::default() }, &mut || true).unwrap(), good);
    assert!(s.search(&q, None, LexicalQueryLimits { max_work: good.work_units - 1, ..Default::default() }, &mut || true).is_err());
    let body = vec![b' '; 8192]; let mut checks = 0;
    assert!(matches!(LexicalSegment::build(scope(GitHashAlgorithm::Sha1), 1, [SourceDocument { path: b"a", content: &body,
        blob: git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, &body) }], &mut || { checks += 1; checks < 5 }), Err(LexicalError::Cancelled)));
    assert!(s.encode(&mut || false).is_err()); assert!(LexicalSegment::concatenate(&[s], &mut || false).is_err());
}
