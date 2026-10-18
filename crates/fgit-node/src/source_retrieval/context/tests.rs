use super::*;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_types::GitHashAlgorithm;

fn file(path: &[u8], bytes: &[u8]) -> PlannedFile {
    PlannedFile { path: path.to_vec(), blob: git_object_id(GitHashAlgorithm::Sha256, GitObjectKind::Blob, bytes),
        source_bytes: Some(bytes.len()), witnesses: Vec::new() }
}
fn witness(file: &mut PlannedFile, channel: ContextChannel, at: usize, expected: &[u8], raw: bool) {
    file.push(ContextAnchor { channel, byte_offset: at, byte_length: expected.len() }, expected, raw, &mut 0).unwrap();
}

#[test]
fn overlapping_windows_merge_without_changing_original_bytes_or_channel_anchors() {
    let bytes = b"//\xff\r\nfn Thing() {}\n";
    let mut file = file(b"src/Thing.rs", bytes);
    witness(&mut file, ContextChannel::Symbol, 8, b"Thing", false);
    witness(&mut file, ContextChannel::Content, 8, b"thing", false);
    witness(&mut file, ContextChannel::Path, 4, b"thing", false);
    let mut result = Assembly::default();
    result.observe(&file, bytes, ContextLimits { radius_bytes: 10, ..Default::default() }, &|| false).unwrap();
    assert_eq!(result.source_bytes, bytes.len());
    assert_eq!(result.excerpt_bytes, bytes.len());
    assert_eq!(result.files[0].anchors.len(), 3);
    assert_eq!(result.files[0].excerpts, vec![ContextExcerpt { offset: 0, bytes: bytes.to_vec() }]);
}

#[test]
fn path_only_offsets_address_the_path_and_empty_files_remain_real_context() {
    for bytes in [b"hi".as_slice(), b""] {
        let mut file = file(b"long/subdir/Thing.rs", bytes);
        witness(&mut file, ContextChannel::Path, 12, b"thing", false);
        let mut result = Assembly::default();
        result.observe(&file, bytes, ContextLimits::default(), &|| false).unwrap();
        assert_eq!(result.files[0].excerpts[0].offset(), 0);
        assert_eq!(result.files[0].excerpts[0].untrusted_bytes(), bytes);
        assert_eq!(result.files[0].anchors[0].byte_offset, 12);
    }
}

#[test]
fn invalid_spans_wrong_terms_subwords_and_false_raw_markers_are_integrity_failures() {
    for (bytes, at, expected, channel, raw) in [
        (b"Other".as_slice(), 0, b"thing".as_slice(), ContextChannel::Content, false),
        (b"ThingExtra", 0, b"thing", ContextChannel::Content, false),
        (b"aThing", 1, b"thing", ContextChannel::Content, false),
        (b"r#type", 2, b"Type", ContextChannel::Symbol, true),
        (b"  type", 2, b"type", ContextChannel::Symbol, true),
        (b"Thing", usize::MAX, b"Thing", ContextChannel::Symbol, false),
    ] {
        let mut file = file(b"file.rs", bytes);
        witness(&mut file, channel, at, expected, raw);
        let mut result = Assembly::default();
        assert!(result.observe(&file, bytes, ContextLimits::default(), &|| false).is_err());
        assert!(result.files.is_empty());
    }
    let mut file = file(b"file.rs", b"fn r#type() {}\n");
    witness(&mut file, ContextChannel::Symbol, 5, b"type", true);
    assert!(Assembly::default().observe(&file, b"fn r#type() {}\n", ContextLimits::default(), &|| false).is_ok());
}

#[test]
fn exact_output_and_source_limits_have_one_byte_under_refusal_twins() {
    let bytes = b"Thing other words Thing";
    let mut file = file(b"file.rs", bytes);
    witness(&mut file, ContextChannel::Content, 0, b"thing", false);
    witness(&mut file, ContextChannel::Symbol, bytes.len()-5, b"Thing", false);
    let limits = ContextLimits { radius_bytes: 0, max_source_bytes: bytes.len(), max_excerpt_bytes: 10, ..Default::default() };
    let mut result = Assembly::default();
    result.observe(&file, bytes, limits, &|| false).unwrap();
    assert_eq!(result.files[0].excerpts.len(), 2);
    assert_eq!(result.excerpt_bytes, 10);
    for limits in [ContextLimits { max_source_bytes: bytes.len()-1, ..limits },
        ContextLimits { max_excerpt_bytes: 9, ..limits }] {
        let mut refused = Assembly::default();
        assert!(refused.observe(&file, bytes, limits, &|| false).is_err());
        assert!(refused.files.is_empty());
    }
    assert!(Assembly::default().observe(&file, bytes, limits, &|| true).is_err());
    file.source_bytes = Some(bytes.len()+1);
    assert!(Assembly::default().observe(&file, bytes, limits, &|| false).is_err());
}

#[test]
fn source_shares_are_fixed_before_reads_and_namespace_collisions_never_merge() {
    let limits = ContextLimits { max_source_bytes: 25, ..Default::default() };
    assert_eq!(limits.file_limit(3).unwrap(), 8);
    assert!(limits.file_limit(26).is_err());
    assert!(ContextLimits { max_files: 33, ..limits }.validate().is_err());
    assert!(ContextLimits { radius_bytes: usize::MAX, ..limits }.validate().is_err());
    let one = file(b"a.rs", b"one"); let other = file(b"a.rs", b"two");
    let mut identities = BTreeMap::new();
    identity(&mut identities, &one.path, one.blob, None).unwrap();
    identity(&mut identities, &one.path, one.blob, Some(3)).unwrap();
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[b"a.rs".as_slice()].source_bytes, Some(3));
    assert!(identity(&mut identities, &one.path, other.blob, Some(3)).is_err());
    assert!(identity(&mut identities, &one.path, one.blob, Some(4)).is_err());
}

#[test]
fn too_many_disjoint_windows_never_exposes_a_truncated_success() {
    let bytes = b"Thing ".repeat(MAX_WINDOWS+1);
    let mut file = file(b"file.rs", &bytes);
    for at in (0..bytes.len()).step_by(6) {
        witness(&mut file, ContextChannel::Symbol, at, b"Thing", false);
    }
    let mut result = Assembly::default();
    assert!(matches!(result.observe(&file, &bytes, ContextLimits { radius_bytes: 0, ..Default::default() }, &|| false),
        Err(RetrievalError::Limit("context windows"))));
    assert!(result.files.is_empty());
}
