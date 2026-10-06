//! These packs contain handwritten native objects; the planner's dependency
//! hints are deliberately empty. Only the production reader proves their graph.
use super::*;
use super::super::Objects;
use fgit_pack::{CanonicalPackObject, PackPlanner, PackWriteProfile, PackWriter};

#[path = "persisted_tests.rs"]
mod persisted;

type Object = (GitObjectKind, Vec<u8>);
fn reference() -> RefName { RefName::try_new(b"refs/heads/main").unwrap() }
fn commit(format: GitHashAlgorithm, root: GitOid, parent: Option<GitOid>) -> (GitOid, Object) {
    let mut body = format!("tree {root}\n");
    if let Some(parent) = parent { body.push_str(&format!("parent {parent}\n")); }
    body.push_str("author A <a@example.invalid> 1 +0000\ncommitter C <c@example.invalid> 2 +0000\n\nroot\n");
    let object = (GitObjectKind::Commit, body.into_bytes());
    (git_object_id(format, object.0, &object.1), object)
}
fn tree(format: GitHashAlgorithm, entries: &[(&[u8], u32, GitOid)]) -> (GitOid, Object) {
    let mut body = Vec::new();
    for (name, mode, id) in entries {
        body.extend_from_slice(format!("{mode:o} ").as_bytes());
        body.extend_from_slice(name);
        body.push(0);
        body.extend_from_slice(id.as_bytes());
    }
    let object = (GitObjectKind::Tree, body);
    (git_object_id(format, object.0, &object.1), object)
}
fn packed(format: GitHashAlgorithm, objects: &[Object]) -> Vec<u8> {
    let source = Objects(objects.iter().map(|(kind, body)| {
        let id = git_object_id(format, *kind, body);
        (id, CanonicalPackObject::new(id, *kind, body.clone(), vec![], 0, 0))
    }).collect());
    let ids = source.0.keys().copied().collect::<Vec<_>>();
    let limits = PackLimits::default();
    let plan = PackPlanner::new(format, PackWriteProfile::STORED_V1, limits.clone())
        .plan_selected(&source, &ids, &mut || true).unwrap();
    PackWriter::new(limits).write(&plan, &mut || true).unwrap().0
}
fn bundle(format: GitHashAlgorithm, candidate: GitOid, objects: &[Object]) -> Vec<u8> {
    let mut bytes = match format {
        GitHashAlgorithm::Sha1 => b"# v2 git bundle\n".to_vec(),
        GitHashAlgorithm::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".to_vec(),
    };
    bytes.extend_from_slice(format!("{candidate} refs/heads/main\n\n").as_bytes());
    bytes.extend(packed(format, objects));
    bytes
}
fn fixture(format: GitHashAlgorithm) -> (GitOid, GitOid, Vec<Object>) {
    let file = (GitObjectKind::Blob, b"\0\xff\r\nno-final-newline".to_vec());
    let blob = git_object_id(format, file.0, &file.1);
    let (empty_id, empty) = tree(format, &[]);
    let (root, directory) = tree(format, &[
        (b"data", 0o100755, blob), (b"empty", 0o40000, empty_id), (b"raw-\xff", 0o100644, blob),
    ]);
    let (id, commit) = commit(format, root, None);
    (id, root, vec![file, empty, directory, commit])
}
fn verified(format: GitHashAlgorithm, candidate: GitOid, bytes: &[u8]) -> VerifiedInitial {
    let envelope = envelope(bytes, format, &reference(), candidate, &mut || true).unwrap();
    read_pack(envelope.pack_bytes(), format, candidate, &PackLimits::default(), &mut || true).unwrap()
}
fn inspect(format: GitHashAlgorithm, candidate: GitOid, bytes: &[u8], limits: InitialInspectionLimits)
    -> Result<InitialCommitInspection, NodeWorkspaceRefusal>
{
    let envelope = envelope(bytes, format, &reference(), candidate, &mut || true)?;
    let verified = read_pack(envelope.pack_bytes(), format, candidate, &PackLimits::default(), &mut || true)?;
    preview(&verified, bytes, envelope.pack_bytes().len(), limits, &mut || true)
}

#[test]
fn inspection_preserves_binary_bytes_modes_raw_paths_and_empty_directories() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (id, root, objects) = fixture(format);
        let bytes = bundle(format, id, &objects);
        let view = inspect(format, id, &bytes, InitialInspectionLimits::default()).unwrap();
        assert_eq!(view.object_format, format);
        assert_eq!(view.candidate_commit, id);
        assert_eq!(view.root_tree, root);
        assert_eq!(view.commit_body, objects[3].1);
        assert_eq!(view.files.len(), 2);
        assert_eq!(view.files[0].path, b"data");
        assert_eq!(view.files[0].mode, 0o100755);
        assert_eq!(view.files[1].path, b"raw-\xff");
        for file in &view.files {
            assert_eq!(file.content, objects[0].1);
            assert_eq!(git_object_id(format, GitObjectKind::Blob, &file.content), file.blob);
        }
        assert_eq!(view.directories.iter().map(|d| d.path.as_slice()).collect::<Vec<_>>(), [b"".as_slice(), b"empty"]);
        assert_eq!(view.object_count, objects.len());
        assert_eq!(view.expanded_bytes, objects.iter().map(|o| o.1.len()).sum::<usize>());
        assert_eq!(view.bundle_sha256, sha256_digest(&bytes));
        assert_eq!(view.bundle_bytes, bytes.len());
        assert!(view.pack_bytes < view.bundle_bytes);
    }
}

#[test]
fn missing_blob_cannot_be_compensated_by_an_unreachable_same_count_object() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (id, _, objects) = fixture(format);
        let mut replaced = objects.clone();
        replaced[0] = (GitObjectKind::Blob, b"unrelated substitute".to_vec());
        assert_eq!(objects.len(), replaced.len());
        assert!(inspect(format, id, &bundle(format, id, &replaced), Default::default()).is_err());
        assert!(inspect(format, id, &bundle(format, id, &objects), Default::default()).is_ok());
        let mut extra = objects.clone();
        extra.push(replaced[0].clone());
        assert!(inspect(format, id, &bundle(format, id, &extra), Default::default()).is_err());
    }
}

#[test]
fn every_edge_checks_its_kind_even_when_the_object_was_already_visited() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (empty_id, empty) = tree(format, &[]);
        let (root, directory) = tree(format, &[
            (b"file", 0o100644, empty_id), (b"sub", 0o40000, empty_id),
        ]);
        let (id, commit) = commit(format, root, None);
        assert!(inspect(format, id, &bundle(format, id, &[empty, directory, commit]), Default::default()).is_err());
        let (id, _, objects) = fixture(format);
        assert!(inspect(format, id, &bundle(format, id, &objects), Default::default()).is_ok());
    }
}

#[test]
fn duplicate_pack_entries_do_not_turn_set_cardinality_into_completeness() {
    let format = GitHashAlgorithm::Sha256;
    let (id, _, objects) = fixture(format);
    let mut raw = packed(format, &objects);
    let parsed = read_verified_pack(&raw, format, &PackLimits::default(), &mut || true, &NativeChecksumVerifier).unwrap();
    let first = usize::try_from(parsed.entries()[0].offset).unwrap();
    let second = usize::try_from(parsed.entries()[1].offset).unwrap();
    let repeated = raw[first..second].to_vec();
    raw.truncate(raw.len() - format.digest_len());
    raw.extend(repeated);
    raw[8..12].copy_from_slice(&(u32::try_from(objects.len()).unwrap() + 1).to_be_bytes());
    raw.extend_from_slice(&sha256_digest(&raw));
    assert!(read_verified_pack(&raw, format, &PackLimits::default(), &mut || true, &NativeChecksumVerifier).is_ok());
    assert!(read_pack(&raw, format, id, &PackLimits::default(), &mut || true).is_err());
    assert!(read_pack(&packed(format, &objects), format, id, &PackLimits::default(), &mut || true).is_ok());
}

#[test]
fn aliases_are_expanded_at_every_path_and_charged_before_copying() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let file = (GitObjectKind::Blob, b"shared content".to_vec());
        let blob = git_object_id(format, file.0, &file.1);
        let (sub_id, sub) = tree(format, &[(b"file", 0o100644, blob)]);
        let (root, directory) = tree(format, &[(b"a", 0o40000, sub_id), (b"b", 0o40000, sub_id)]);
        let (id, commit) = commit(format, root, None);
        let bytes = bundle(format, id, &[file, sub, directory, commit]);
        let view = inspect(format, id, &bytes, Default::default()).unwrap();
        assert_eq!(view.files.iter().map(|f| f.path.as_slice()).collect::<Vec<_>>(), [b"a/file".as_slice(), b"b/file".as_slice()]);
        assert_eq!(view.directories.len(), 3);
        assert_eq!(view.files[0].blob, view.files[1].blob);
        let charged = view.commit_body.len() + view.files.iter().map(|f| f.path.len() + f.content.len()).sum::<usize>()
            + view.directories.iter().map(|d| d.path.len()).sum::<usize>();
        let exact = InitialInspectionLimits { max_files: 2, max_tree_entries: 4, max_depth: 2,
            max_path_bytes: 6, max_output_bytes: charged, ..Default::default() };
        assert_eq!(inspect(format, id, &bytes, exact).unwrap(), view);
        for narrow in [
            InitialInspectionLimits { max_files: 1, ..exact },
            InitialInspectionLimits { max_tree_entries: 3, ..exact },
            InitialInspectionLimits { max_depth: 1, ..exact },
            InitialInspectionLimits { max_path_bytes: 5, ..exact },
            InitialInspectionLimits { max_output_bytes: charged - 1, ..exact },
            InitialInspectionLimits { max_file_bytes: 1, ..exact },
            InitialInspectionLimits { max_commit_bytes: 1, ..exact },
        ] {
            assert!(inspect(format, id, &bytes, narrow).is_err(), "{narrow:?}");
        }
    }
}

#[test]
fn empty_root_is_a_complete_empty_tree_not_a_missing_commit() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (root, tree) = tree(format, &[]);
        let (id, commit) = commit(format, root, None);
        let bytes = bundle(format, id, &[tree, commit]);
        let view = inspect(format, id, &bytes, Default::default()).unwrap();
        assert!(view.files.is_empty());
        assert_eq!(view.directories, [InspectedInitialDirectory { path: vec![], tree: root }]);
        assert!(read_pack(&packed(format, &[]), format, id, &PackLimits::default(), &mut || true).is_err());
    }
}

#[test]
fn parents_unsafe_names_and_nonregular_modes_refuse_in_the_same_reader() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (id, root, objects) = fixture(format);
        let (child_id, child) = commit(format, root, Some(id));
        let mut parented = objects[..3].to_vec();
        parented.push(child);
        assert!(inspect(format, child_id, &bundle(format, child_id, &parented), Default::default()).is_err());
        let blob = git_object_id(format, objects[0].0, &objects[0].1);
        for (name, mode) in [(b"unsafe".as_slice(), 0o120000), (b"link", 0o160000),
            (b"..", 0o100644), (b".git", 0o100644), (b"a/b", 0o100644)]
        {
            let (root, directory) = tree(format, &[(name, mode, blob)]);
            let (id, commit) = commit(format, root, None);
            assert!(inspect(format, id, &bundle(format, id, &[objects[0].clone(), directory, commit]), Default::default()).is_err());
        }
        assert!(inspect(format, id, &bundle(format, id, &objects), Default::default()).is_ok());
    }
}

#[test]
fn every_read_and_preview_checkpoint_refuses_cancellation_without_partial_success() {
    let format = GitHashAlgorithm::Sha256;
    let (id, _, objects) = fixture(format);
    let bytes = bundle(format, id, &objects);
    let raw = envelope(&bytes, format, &reference(), id, &mut || true).unwrap();
    let mut calls = 0usize;
    read_pack(raw.pack_bytes(), format, id, &PackLimits::default(), &mut || { calls += 1; true }).unwrap();
    for stop in 1..=calls {
        let mut count = 0usize;
        assert!(read_pack(raw.pack_bytes(), format, id, &PackLimits::default(), &mut || { count += 1; count != stop }).is_err());
    }
    let verified = verified(format, id, &bytes);
    calls = 0;
    preview(&verified, &bytes, raw.pack_bytes().len(), Default::default(), &mut || { calls += 1; true }).unwrap();
    for stop in 1..=calls {
        let mut count = 0usize;
        assert!(preview(&verified, &bytes, raw.pack_bytes().len(), Default::default(), &mut || { count += 1; count != stop }).is_err());
    }
    assert!(preview(&verified, &bytes, raw.pack_bytes().len(), Default::default(), &mut || true).is_ok());
}

#[test]
fn corrupt_transport_and_independent_coordinate_mismatches_refuse() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (id, root, objects) = fixture(format);
        let bytes = bundle(format, id, &objects);
        assert!(envelope(&bytes, format, &RefName::try_new(b"refs/heads/other").unwrap(), id, &mut || true).is_err());
        assert!(envelope(&bytes, format, &reference(), root, &mut || true).is_err());
        let mut corrupt = bytes.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(inspect(format, id, &corrupt, Default::default()).is_err());
        assert!(inspect(format, id, &bytes[..bytes.len() - 1], Default::default()).is_err());
        assert!(inspect(format, id, &bytes, Default::default()).is_ok());
    }
}
