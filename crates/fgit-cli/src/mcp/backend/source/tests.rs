use super::*;
use fgit_forge::source_browse::{SourceDirectoryEntry, SourceEntryKind};
use fgit_types::{DigestAlgorithmId, DigestBytes, RepositoryCommitId, RepositoryId};
fn args<const N: usize>(fields: [(&str, Value); N]) -> Object {
    let Value::Object(value) = object(fields) else {
        unreachable!()
    };
    value
}
fn token() -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(1).unwrap(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[7; 32]).unwrap(),
    )
}
fn oid(byte: u8) -> GitOid {
    GitOid::from_hex(GitHashAlgorithm::Sha256, &format!("{byte:02x}").repeat(32)).unwrap()
}
fn report(content: SourceBrowseContent) -> SourceBrowseReport {
    SourceBrowseReport {
        repository_id: RepositoryId::from_bytes([2; 16]),
        source_head: token(),
        source_rcr: RepositoryCommitId::from_digest(
            DigestAlgorithmId::try_new(1).unwrap(),
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[8; 32]).unwrap(),
        ),
        source_commit: oid(1),
        root_tree: oid(2),
        object_id: oid(3),
        path: Some(b"file".to_vec()),
        content,
    }
}
#[test]
fn source_queries_reject_host_paths_mutations_and_unpinned_continuations() {
    for extra in [
        args([("storage", text("/etc"))]),
        args([("principal", text("admin"))]),
        args([("oid", text(oid(1).to_string()))]),
        args([("path_hex", text("2e2e2f736563726574"))]),
        args([("after_hex", text("61"))]),
        args([("limit", json::number(101))]),
        args([("expected_commit", text("00".repeat(32)))]),
    ] {
        let mut input = args([("reference", text("refs/heads/main"))]);
        input.extend(extra);
        assert!(parse(&input, false, GitHashAlgorithm::Sha256).is_err());
    }
    assert!(
        parse(
            &args([("reference", text("refs/heads/main"))]),
            true,
            GitHashAlgorithm::Sha256
        )
        .is_err()
    );
    assert!(
        parse(
            &args([("reference", text("/etc/passwd")), ("path_hex", text("61"))]),
            true,
            GitHashAlgorithm::Sha256
        )
        .is_err()
    );
    let valid = args([
        ("reference", text("refs/heads/main")),
        ("path_hex", text("ff")),
        ("expected_head", text(head_token(token()))),
        ("offset", text("1")),
        ("max_bytes", json::number(65536)),
    ]);
    assert!(parse(&valid, true, GitHashAlgorithm::Sha256).is_ok());
    let mut bad = valid;
    bad.insert("max_bytes".into(), json::number(65537));
    assert!(parse(&bad, true, GitHashAlgorithm::Sha256).is_err());
}
#[test]
fn file_ranges_keep_binary_bytes_exact_and_cannot_mislabel_partial_results() {
    let reference = RefName::try_new(b"refs/heads/main").unwrap();
    let query = SourceBrowseQuery {
        path: Some(b"file".to_vec()),
        expected_head: Some(token()),
        expected_commit: Some(oid(1)),
        action: SourceBrowseAction::Read {
            offset: 1,
            limit: 2,
        },
    };
    let mut observed = report(SourceBrowseContent::Blob {
        kind: SourceEntryKind::File,
        bytes: vec![0, 255],
        total_bytes: 5,
        offset: 1,
        next_offset: Some(3),
    });
    let value = render(&reference, &query, &observed).unwrap();
    assert_eq!(value["bytes_hex"].text(), Some("00ff"));
    assert_eq!(value["text_utf8"], Value::Null);
    assert_eq!(value["complete"], Value::Bool(false));
    assert_eq!(value["next_offset"].text(), Some("3"));
    if let SourceBrowseContent::Blob { next_offset, .. } = &mut observed.content {
        *next_offset = None;
    }
    assert!(render(&reference, &query, &observed).is_err());
}
#[test]
fn directory_receipts_keep_raw_order_and_exact_cursors() {
    let reference = RefName::try_new(b"refs/heads/main").unwrap();
    let query = SourceBrowseQuery {
        path: None,
        expected_head: Some(token()),
        expected_commit: None,
        action: SourceBrowseAction::List {
            after: None,
            limit: 1,
        },
    };
    let mut observed = report(SourceBrowseContent::Directory {
        entries: vec![SourceDirectoryEntry {
            name: vec![255],
            oid: oid(3),
            kind: SourceEntryKind::Symlink,
        }],
        next_after: Some(vec![255]),
    });
    observed.path = None;
    let value = render(&reference, &query, &observed).unwrap();
    assert_eq!(value["next_after_hex"].text(), Some("ff"));
    assert_eq!(value["complete"], Value::Bool(false));
    if let SourceBrowseContent::Directory { next_after, .. } = &mut observed.content {
        *next_after = Some(b"a".to_vec());
    }
    assert!(render(&reference, &query, &observed).is_err());
}
