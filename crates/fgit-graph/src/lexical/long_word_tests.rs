//! Whole-word source intake must remain total for bounded native blobs, without
//! making prefixes/suffixes of unqueryable words into false search results.
use super::*;

fn namespace(format: GitHashAlgorithm) -> LexicalNamespace {
    LexicalNamespace {
        tenant: TenantId::from_bytes([1; 16]),
        repository: RepositoryId::from_bytes([2; 16]),
        incarnation: RepositoryIncarnationId::from_bytes([3; 16]),
        object_format: format,
    }
}

fn build(format: GitHashAlgorithm, first: u64, path: &[u8], body: &[u8]) -> LexicalSegment {
    LexicalSegment::build(
        namespace(format),
        first,
        [SourceDocument {
            path,
            blob: git_object_id(format, GitObjectKind::Blob, body),
            content: body,
        }],
        &mut || true,
    )
    .unwrap()
}

fn search(segment: &LexicalSegment, channel: LexicalChannel, term: &[u8]) -> LexicalReport {
    let query = LexicalQuery::new(channel, &[term.to_vec()], &[]).unwrap();
    segment
        .search(&query, None, Default::default(), &mut || true)
        .unwrap()
}

fn collected(bytes: &[u8]) -> Vec<(Vec<u8>, u32)> {
    let mut output = Vec::new();
    tokens(bytes, &mut || true, |token, at| {
        output.push((token.to_vec(), at));
        Ok(())
    })
    .unwrap();
    output
}

#[test]
fn unqueryable_words_do_not_poison_other_words_or_change_native_identity() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut body = b"BEFORE ".to_vec();
        body.extend_from_slice(&vec![b'x'; MAX_TERM_BYTES + 1]);
        body.extend_from_slice(b" after BEFORE");
        let segment = build(format, 7, b"a.rs", &body);
        let before = search(&segment, LexicalChannel::Content, b"before");
        assert!(before.complete);
        assert_eq!(before.hits.len(), 1);
        assert_eq!(before.hits[0].document_id, 7);
        assert_eq!(before.hits[0].spans[0].byte_offset, 0);
        let after = search(&segment, LexicalChannel::Content, b"AFTER");
        assert_eq!(after.hits[0].spans[0].byte_offset as usize, 7 + MAX_TERM_BYTES + 2);
        assert_eq!(segment.documents()[0].content_bytes as usize, body.len());
        assert_eq!(
            segment.documents()[0].blob,
            git_object_id(format, GitObjectKind::Blob, &body)
        );
        assert!(search(&segment, LexicalChannel::Content, &vec![b'x'; MAX_TERM_BYTES]).hits.is_empty());
        assert!(search(&segment, LexicalChannel::Content, b"x").hits.is_empty());
        let encoded = segment.encode(&mut || true).unwrap();
        let root = segment.root(&mut || true).unwrap();
        let decoded = LexicalSegment::decode(&encoded, root, namespace(format), &mut || true).unwrap();
        assert_eq!(decoded, segment);
        assert_eq!(search(&decoded, LexicalChannel::Content, b"after"), after);
    }
}

#[test]
fn every_byte_delimiter_and_boundary_length_agree_with_complete_word_oracle() {
    for delimiter in 0..=u8::MAX {
        if delimiter.is_ascii_alphanumeric() || delimiter == b'_' {
            continue;
        }
        for len in [0, 1, 127, 128, 129, 255, 256, 257, 4095, 4096, 4097] {
            let mut input = vec![b'Q'; len];
            input.push(delimiter);
            input.extend_from_slice(b"tail");
            let mut expected = Vec::new();
            if (1..=MAX_TERM_BYTES).contains(&len) {
                expected.push((vec![b'Q'; len], 0));
            }
            expected.push((b"tail".to_vec(), (len + 1) as u32));
            assert_eq!(collected(&input), expected, "delimiter={delimiter}, len={len}");
            let eof = collected(&input[..len]);
            assert_eq!(eof.len(), usize::from((1..=MAX_TERM_BYTES).contains(&len)));
        }
    }
}

#[test]
fn chunks_of_one_long_word_never_become_prefix_suffix_or_repeated_matches() {
    for len in [129, 256, 257, 4096, 8193] {
        let mut body = b"prefix".to_vec();
        body.extend_from_slice(&vec![b'_'; len]);
        body.extend_from_slice(b"suffix");
        assert!(collected(&body).is_empty());
        body.extend_from_slice(b" prefix suffix");
        assert_eq!(
            collected(&body),
            vec![
                (b"prefix".to_vec(), (len + 13) as u32),
                (b"suffix".to_vec(), (len + 20) as u32),
            ]
        );
    }
}

#[test]
fn long_paths_keep_path_channel_suffixes_and_all_original_byte_offsets() {
    let mut path = vec![b'p'; MAX_TERM_BYTES + 1];
    path.extend_from_slice(b"/leaf.rs");
    let segment = build(GitHashAlgorithm::Sha256, 1, &path, b"content");
    let leaf = search(&segment, LexicalChannel::Path, b"leaf");
    assert_eq!(leaf.hits.len(), 1);
    assert_eq!(leaf.hits[0].path, path);
    assert_eq!(leaf.hits[0].spans[0].byte_offset as usize, MAX_TERM_BYTES + 2);
    assert!(search(&segment, LexicalChannel::Path, &vec![b'p'; MAX_TERM_BYTES]).hits.is_empty());
    assert!(search(&segment, LexicalChannel::Content, b"leaf").hits.is_empty());
}

#[test]
fn a_document_with_no_queryable_words_still_survives_encoding_and_compaction() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let path = vec![b'a'; MAX_TERM_BYTES + 1];
        let body = vec![b'x'; MAX_TERM_BYTES * 3];
        let first = build(format, 1, &path, &body);
        assert_eq!(first.documents().len(), 1);
        assert_eq!(first.term_count(), 0);
        assert_eq!(first.posting_count(), 0);
        let bytes = first.encode(&mut || true).unwrap();
        let decoded = LexicalSegment::decode(
            &bytes,
            first.root(&mut || true).unwrap(),
            namespace(format),
            &mut || true,
        )
        .unwrap();
        assert_eq!(decoded, first);
        let second = build(format, 2, b"b.rs", b"needle");
        let combined = LexicalSegment::concatenate(&[first, second], &mut || true).unwrap();
        assert_eq!(combined.documents().len(), 2);
        assert_eq!(combined.documents()[0].path, path);
        assert_eq!(search(&combined, LexicalChannel::Content, b"needle").hits[0].document_id, 2);
    }
}

#[test]
fn cancellation_remains_bounded_inside_an_unqueryable_word_and_at_eof() {
    let body = vec![b'x'; 8193];
    for stop_after in 0..=3 {
        let mut checks = 0;
        let mut emitted = 0;
        let result = tokens(
            &body,
            &mut || {
                checks += 1;
                checks <= stop_after
            },
            |_, _| {
                emitted += 1;
                Ok(())
            },
        );
        assert!(matches!(result, Err(LexicalError::Cancelled)));
        assert_eq!(checks, stop_after + 1);
        assert_eq!(emitted, 0);
    }
}

#[test]
fn consumer_errors_after_long_words_are_not_swallowed() {
    let mut body = vec![b'x'; 129];
    body.extend_from_slice(b" word");
    let result = tokens(&body, &mut || true, |_, _| Err(LexicalError::Limit("postings")));
    assert!(matches!(result, Err(LexicalError::Limit("postings"))));
}

#[test]
fn long_words_do_not_bypass_file_budgets_or_native_identity_checks() {
    let format = GitHashAlgorithm::Sha1;
    let original = vec![b'x'; 129];
    let blob = git_object_id(format, GitObjectKind::Blob, &original);
    let changed = vec![b'y'; 129];
    assert!(matches!(
        LexicalSegment::build(
            namespace(format),
            1,
            [SourceDocument { path: b"a", blob, content: &changed }],
            &mut || true,
        ),
        Err(LexicalError::NativeIdentityMismatch)
    ));
    let oversized = vec![b'x'; MAX_FILE_BYTES + 1];
    assert!(matches!(
        LexicalSegment::build(
            namespace(format),
            1,
            [SourceDocument { path: b"a", blob, content: &oversized }],
            &mut || true,
        ),
        Err(LexicalError::Limit("file bytes"))
    ));
}
