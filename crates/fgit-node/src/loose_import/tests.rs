use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_crypto::GitObjectKind;
use fgit_types::{GitHashAlgorithm, GitOid, RepositoryId, TenantId};

use super::{LooseGitImportRefusal, OneNode, read_through_first_excess_byte};

static NEXT_SCRATCH_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct ScratchDirectory(PathBuf);

impl ScratchDirectory {
    fn new() -> Self {
        let sequence = NEXT_SCRATCH_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "frankengit-node-loose-import-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("scratch directory creates");
        Self(path)
    }
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn decode_hex(text: &str) -> Vec<u8> {
    let (pairs, remainder) = text.trim().as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty(), "fixture has an even hex length");
    pairs
        .iter()
        .map(|[high, low]| (hex_nibble(*high) * 16) + hex_nibble(*low))
        .collect()
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("fixture contains hex"),
    }
}

fn node(root: PathBuf) -> OneNode {
    OneNode::init(super::super::NodeConfig::new(
        root,
        TenantId::from_hex("11111111111111111111111111111111").expect("tenant parses"),
        RepositoryId::from_hex("22222222222222222222222222222222").expect("repository parses"),
    ))
    .expect("node initializes")
    .0
}

fn write_loose_commit_repository(root: &Path) -> GitOid {
    write_branch_head(root);
    let blob = write_loose_object(root, GitObjectKind::Blob, b"first clone fixture\n");
    let mut tree = b"100644 README\0".to_vec();
    tree.extend_from_slice(blob.require_sha1().expect("fixture is SHA-1").as_bytes());
    let tree = write_loose_object(root, GitObjectKind::Tree, &tree);
    let commit = format!(
        "tree {tree}\nauthor FrankenGit <fg@example.invalid> 0 +0000\ncommitter FrankenGit <fg@example.invalid> 0 +0000\n\nfirst clone fixture\n"
    );
    let commit = write_loose_object(root, GitObjectKind::Commit, commit.as_bytes());
    let ref_path = root.join("refs/heads/main");
    fs::create_dir_all(ref_path.parent().expect("ref parent exists"))
        .expect("ref directory creates");
    fs::write(ref_path, format!("{commit}\n")).expect("fixture ref writes");
    commit
}

fn write_loose_blob_repository(root: &Path) -> GitOid {
    write_branch_head(root);
    let oid = GitOid::from_hex(
        GitHashAlgorithm::Sha1,
        "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0",
    )
    .expect("fixed blob identity parses");
    let object_path = root.join("objects/b6/fc4c620b67d95f953a5c1c1230aaab5db5a1b0");
    fs::create_dir_all(object_path.parent().expect("object parent exists"))
        .expect("object directory creates");
    fs::write(
        object_path,
        decode_hex(include_str!(
            "../../../fgit-git-object/tests/corpus/blob-hello.zlib.hex"
        )),
    )
    .expect("fixture loose object writes");
    let ref_path = root.join("refs/heads/main");
    fs::create_dir_all(ref_path.parent().expect("ref parent exists"))
        .expect("ref directory creates");
    fs::write(ref_path, format!("{oid}\n")).expect("fixture ref writes");
    oid
}

fn write_branch_head(root: &Path) {
    fs::write(root.join("HEAD"), "ref: refs/heads/main\n").expect("symbolic branch HEAD writes");
}

fn write_loose_object(root: &Path, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let oid = fgit_crypto::git_object_id(GitHashAlgorithm::Sha1, kind, body);
    let identity = oid.to_string();
    let (directory, file) = identity.split_at(2);
    let path = root.join("objects").join(directory).join(file);
    fs::create_dir_all(path.parent().expect("object parent exists"))
        .expect("object directory creates");
    let mut framed = format!("{} {}\0", kind.label(), body.len()).into_bytes();
    framed.extend_from_slice(body);
    fs::write(path, zlib_stored_member(&framed)).expect("zlib loose object writes");
    oid
}

fn zlib_stored_member(bytes: &[u8]) -> Vec<u8> {
    let length = u16::try_from(bytes.len()).expect("small test member fits one stored block");
    let mut member = Vec::with_capacity(bytes.len() + 11);
    member.extend_from_slice(&[0x78, 0x01, 0x01]);
    member.extend_from_slice(&length.to_le_bytes());
    member.extend_from_slice(&(!length).to_le_bytes());
    member.extend_from_slice(bytes);
    member.extend_from_slice(&adler32(bytes).to_be_bytes());
    member
}

fn adler32(bytes: &[u8]) -> u32 {
    let mut a = 1_u32;
    let mut b = 0_u32;
    for byte in bytes {
        a = (a + u32::from(*byte)) % 65_521;
        b = (b + a) % 65_521;
    }
    (b << 16) | a
}

#[test]
fn bounded_file_reader_consumes_only_the_first_excess_byte() {
    let mut input = std::io::Cursor::new(b"123456789".to_vec());
    let observed = read_through_first_excess_byte(&mut input, 4)
        .expect("the bounded in-memory reader completes");

    assert_eq!(observed, b"12345");
    assert_eq!(input.position(), 5);
}

#[test]
fn loose_import_stages_a_verified_direct_ref_closure_without_publishing_it() {
    let scratch = ScratchDirectory::new();
    let source = scratch.0.join("source.git");
    fs::create_dir_all(&source).expect("source directory creates");
    let oid = write_loose_commit_repository(&source);
    let node = node(scratch.0.join("node"));

    let staged = node
        .stage_loose_git_import(&source)
        .expect("reachable loose object stages through verified fabric");
    assert_eq!(staged.object_count(), 3);
    assert_eq!(staged.total_object_bytes(), 218);
    assert_eq!(
        staged
            .refs()
            .refs()
            .get(&fgit_types::RefName::try_new(b"refs/heads/main").expect("fixed ref parses")),
        Some(&oid)
    );
    assert_eq!(staged.closure().objects().len(), 3);
    assert!(staged.closure().objects().contains(&oid));
    assert!(node.read_git_object(oid).is_ok());

    let materialized = node
        .runtime()
        .block_on(node.materialize_admission())
        .expect("genesis remains authoritative after staging");
    assert!(materialized.snapshot().refs.is_empty());
    assert!(
        materialized
            .selected_closure()
            .closure()
            .objects()
            .is_empty()
    );
    node.shutdown().expect("node drains");
}

#[test]
fn loose_import_captures_a_symbolic_branch_head_in_canonical_state() {
    let scratch = ScratchDirectory::new();
    let source = scratch.0.join("source.git");
    fs::create_dir_all(&source).expect("source directory creates");
    let _ = write_loose_commit_repository(&source);
    let node = node(scratch.0.join("node"));

    let staged = node
        .stage_loose_git_import(&source)
        .expect("a symbolic branch HEAD is admitted with the source refs");
    assert_eq!(
        staged.refs().head_target(),
        Some(&fgit_types::RefName::try_new(b"refs/heads/main").expect("fixed ref parses"))
    );
    node.shutdown().expect("node drains");
}

#[test]
fn loose_import_refuses_missing_direct_and_non_branch_heads() {
    for (name, contents, expected) in [
        ("missing", None, "missing"),
        (
            "direct",
            Some("b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0\n"),
            "direct",
        ),
        ("tag", Some("ref: refs/tags/v1\n"), "non-branch"),
    ] {
        let scratch = ScratchDirectory::new();
        let source = scratch.0.join(name);
        fs::create_dir_all(&source).expect("source directory creates");
        fs::create_dir_all(source.join("objects")).expect("object directory creates");
        if let Some(contents) = contents {
            fs::write(source.join("HEAD"), contents).expect("HEAD fixture writes");
        }
        let node = node(scratch.0.join("node"));

        let refusal = node
            .stage_loose_git_import(&source)
            .expect_err("invalid HEAD must refuse before import staging");
        assert!(
            matches!(
                (expected, refusal),
                ("missing", LooseGitImportRefusal::HeadMissing(_))
                    | ("direct", LooseGitImportRefusal::HeadNotSymbolic(_))
                    | ("non-branch", LooseGitImportRefusal::HeadTargetNotBranch(_))
            ),
            "{expected} HEAD form must retain its typed refusal"
        );
        node.shutdown().expect("node drains");
    }
}

#[test]
fn loose_import_refuses_a_ref_that_names_an_unstaged_object() {
    let scratch = ScratchDirectory::new();
    let source = scratch.0.join("source.git");
    fs::create_dir_all(&source).expect("source directory creates");
    write_branch_head(&source);
    let ref_path = source.join("refs/heads/main");
    fs::create_dir_all(ref_path.parent().expect("ref parent exists"))
        .expect("ref directory creates");
    fs::create_dir_all(source.join("objects")).expect("object directory creates");
    let oid = "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0";
    fs::write(&ref_path, format!("{oid}\n")).expect("fixture ref writes");
    let node = node(scratch.0.join("node"));

    assert!(matches!(
        node.stage_loose_git_import(&source),
        Err(LooseGitImportRefusal::ObjectMissing(identity)) if identity.to_string() == oid
    ));
    node.shutdown().expect("node drains");
}

#[test]
fn loose_import_uses_packed_refs_without_treating_them_as_an_object_source() {
    let scratch = ScratchDirectory::new();
    let source = scratch.0.join("source.git");
    fs::create_dir_all(&source).expect("source directory creates");
    let oid = write_loose_commit_repository(&source);
    fs::remove_file(source.join("refs/heads/main")).expect("direct ref is removed");
    fs::write(
        source.join("packed-refs"),
        format!("# pack-refs with: peeled fully-peeled\n{oid} refs/heads/main\n"),
    )
    .expect("packed ref writes");
    let node = node(scratch.0.join("node"));

    let staged = node
        .stage_loose_git_import(&source)
        .expect("a packed ref still names the same verified loose closure");
    assert_eq!(staged.object_count(), 3);
    assert_eq!(
        staged
            .refs()
            .refs()
            .get(&fgit_types::RefName::try_new(b"refs/heads/main").expect("fixed ref parses")),
        Some(&oid)
    );
    assert!(node.read_git_object(oid).is_ok());
    node.shutdown().expect("node drains");
}

#[test]
fn loose_import_refuses_an_alternate_even_when_its_direct_closure_is_valid() {
    let scratch = ScratchDirectory::new();
    let source = scratch.0.join("source.git");
    fs::create_dir_all(&source).expect("source directory creates");
    let _ = write_loose_commit_repository(&source);
    let alternates = source.join("objects/info/alternates");
    fs::create_dir_all(alternates.parent().expect("alternates parent exists"))
        .expect("alternates parent creates");
    fs::write(&alternates, "/outside/object-source\n").expect("alternate writes");
    let node = node(scratch.0.join("node"));

    assert!(matches!(
        node.stage_loose_git_import(&source),
        Err(LooseGitImportRefusal::ObjectAlternatesUnsupported(path)) if *path == alternates
    ));
    node.shutdown().expect("node drains");
}

#[cfg(unix)]
#[test]
fn loose_import_refuses_a_worktree_git_directory_symlink() {
    let scratch = ScratchDirectory::new();
    let source = scratch.0.join("worktree");
    let dot_git = source.join(".git");
    fs::create_dir_all(&source).expect("worktree directory creates");
    std::os::unix::fs::symlink(scratch.0.join("outside"), &dot_git)
        .expect("fixture symbolic link creates");
    let node = node(scratch.0.join("node"));

    assert!(matches!(
        node.stage_loose_git_import(&source),
        Err(LooseGitImportRefusal::SymbolicLink(path)) if *path == dot_git
    ));
    node.shutdown().expect("node drains");
}

#[test]
fn loose_import_refuses_a_worktree_git_directory_file() {
    let scratch = ScratchDirectory::new();
    let source = scratch.0.join("worktree");
    let dot_git = source.join(".git");
    fs::create_dir_all(&source).expect("worktree directory creates");
    fs::write(&dot_git, "gitdir: /outside\n").expect("indirection fixture writes");
    let node = node(scratch.0.join("node"));

    assert!(matches!(
        node.stage_loose_git_import(&source),
        Err(LooseGitImportRefusal::GitDirectoryFileUnsupported(path)) if *path == dot_git
    ));
    node.shutdown().expect("node drains");
}

#[test]
fn local_import_refuses_an_unpaired_pack_instead_of_ignoring_it() {
    let scratch = ScratchDirectory::new();
    let source = scratch.0.join("source.git");
    let pack_directory = source.join("objects/pack");
    fs::create_dir_all(&pack_directory).expect("packed-object directory creates");
    let pack_path = pack_directory.join("fixture.pack");
    fs::write(&pack_path, b"not a complete pack pair").expect("packed-object fixture writes");
    let node = node(scratch.0.join("node"));

    assert!(matches!(
        node.stage_loose_git_import(&source),
        Err(LooseGitImportRefusal::PackPairMissing(path)) if *path == pack_path
    ));
    node.shutdown().expect("node drains");
}

#[test]
fn loose_import_refuses_a_symbolic_ref_instead_of_resolving_it() {
    let scratch = ScratchDirectory::new();
    let source = scratch.0.join("source.git");
    let ref_path = source.join("refs/heads/main");
    fs::create_dir_all(ref_path.parent().expect("ref parent exists"))
        .expect("ref directory creates");
    fs::create_dir_all(source.join("objects")).expect("object directory creates");
    fs::write(&ref_path, "ref: refs/heads/other\n").expect("symbolic ref fixture writes");
    let node = node(scratch.0.join("node"));

    assert!(matches!(
        node.stage_loose_git_import(&source),
        Err(LooseGitImportRefusal::SymbolicRefUnsupported(path)) if *path == ref_path
    ));
    node.shutdown().expect("node drains");
}

#[test]
fn loose_import_refuses_a_loose_body_that_does_not_match_its_path_identity() {
    let scratch = ScratchDirectory::new();
    let source = scratch.0.join("source.git");
    fs::create_dir_all(&source).expect("source directory creates");
    let observed = write_loose_blob_repository(&source);
    let expected = "a6fc4c620b67d95f953a5c1c1230aaab5db5a1b0";
    let original_path = source.join("objects/b6/fc4c620b67d95f953a5c1c1230aaab5db5a1b0");
    let mismatched_path = source.join("objects/a6/fc4c620b67d95f953a5c1c1230aaab5db5a1b0");
    fs::create_dir_all(mismatched_path.parent().expect("mismatched parent exists"))
        .expect("mismatched object directory creates");
    fs::rename(&original_path, &mismatched_path).expect("fixture object moves");
    fs::write(source.join("refs/heads/main"), format!("{expected}\n"))
        .expect("mismatched ref writes");
    let node = node(scratch.0.join("node"));

    assert!(matches!(
        node.stage_loose_git_import(&source),
        Err(LooseGitImportRefusal::ObjectIdentityMismatch {
            expected: refused_expected,
            observed: refused_observed,
        }) if refused_expected.to_string() == expected && refused_observed == observed
    ));
    node.shutdown().expect("node drains");
}

#[test]
fn loose_import_refuses_a_source_without_a_git_objects_directory() {
    let scratch = ScratchDirectory::new();
    let source = scratch.0.join("not-a-git-directory");
    fs::create_dir_all(&source).expect("source directory creates");
    let node = node(scratch.0.join("node"));

    assert!(matches!(
        node.stage_loose_git_import(&source),
        Err(LooseGitImportRefusal::GitDirectoryMissing(path)) if *path == source
    ));
    node.shutdown().expect("node drains");
}

#[cfg(unix)]
#[test]
fn loose_import_maps_an_invalid_source_path_to_the_typed_io_refusal() {
    let scratch = ScratchDirectory::new();
    let source = scratch.0.join("invalid\0source");
    let node = node(scratch.0.join("node"));

    assert!(matches!(
        node.stage_loose_git_import(&source),
        Err(LooseGitImportRefusal::Io { operation, path, .. })
            if operation == "inspect Git source" && *path == source
    ));
    node.shutdown().expect("node drains");
}

#[test]
fn loose_import_refuses_a_file_where_the_packed_object_directory_belongs() {
    let scratch = ScratchDirectory::new();
    let source = scratch.0.join("source.git");
    let pack_directory = source.join("objects/pack");
    fs::create_dir_all(source.join("objects")).expect("object directory creates");
    fs::write(&pack_directory, b"not a directory").expect("wrong-kind fixture writes");
    let node = node(scratch.0.join("node"));

    assert!(matches!(
        node.stage_loose_git_import(&source),
        Err(LooseGitImportRefusal::PathKind { expected, path })
            if expected == "packed-object directory" && *path == pack_directory
    ));
    node.shutdown().expect("node drains");
}

#[test]
fn loose_import_refuses_a_loose_ref_path_outside_the_canonical_vocabulary() {
    let scratch = ScratchDirectory::new();
    let source = scratch.0.join("source.git");
    let ref_path = source.join("refs/heads/bad..name");
    fs::create_dir_all(ref_path.parent().expect("ref parent exists"))
        .expect("ref directory creates");
    fs::create_dir_all(source.join("objects")).expect("object directory creates");
    fs::write(&ref_path, "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0\n")
        .expect("invalid-name ref writes");
    let node = node(scratch.0.join("node"));

    assert!(matches!(
        node.stage_loose_git_import(&source),
        Err(LooseGitImportRefusal::RefName { path, .. }) if *path == ref_path
    ));
    node.shutdown().expect("node drains");
}

#[test]
fn loose_import_refuses_a_direct_ref_with_noncanonical_object_hex() {
    let scratch = ScratchDirectory::new();
    let source = scratch.0.join("source.git");
    let ref_path = source.join("refs/heads/main");
    fs::create_dir_all(ref_path.parent().expect("ref parent exists"))
        .expect("ref directory creates");
    fs::create_dir_all(source.join("objects")).expect("object directory creates");
    fs::write(&ref_path, "NOT-AN-OBJECT\n").expect("invalid-identity ref writes");
    let node = node(scratch.0.join("node"));

    assert!(matches!(
        node.stage_loose_git_import(&source),
        Err(LooseGitImportRefusal::ObjectIdentity { path, .. }) if *path == ref_path
    ));
    node.shutdown().expect("node drains");
}

#[test]
fn loose_import_refuses_a_direct_ref_with_ambiguous_contents() {
    let scratch = ScratchDirectory::new();
    let source = scratch.0.join("source.git");
    let ref_path = source.join("refs/heads/main");
    fs::create_dir_all(ref_path.parent().expect("ref parent exists"))
        .expect("ref directory creates");
    fs::create_dir_all(source.join("objects")).expect("object directory creates");
    fs::write(&ref_path, "one identity plus another\n").expect("ambiguous ref fixture writes");
    let node = node(scratch.0.join("node"));

    assert!(matches!(
        node.stage_loose_git_import(&source),
        Err(LooseGitImportRefusal::RefContents(path)) if *path == ref_path
    ));
    node.shutdown().expect("node drains");
}

#[test]
fn loose_import_refuses_malformed_packed_refs() {
    let scratch = ScratchDirectory::new();
    let source = scratch.0.join("source.git");
    let packed_refs = source.join("packed-refs");
    fs::create_dir_all(source.join("objects")).expect("object directory creates");
    fs::write(&packed_refs, "not a packed ref\n").expect("malformed packed refs write");
    let node = node(scratch.0.join("node"));

    assert!(matches!(
        node.stage_loose_git_import(&source),
        Err(LooseGitImportRefusal::PackedRefContents(path)) if *path == packed_refs
    ));
    node.shutdown().expect("node drains");
}

#[test]
fn loose_import_refuses_a_duplicate_packed_ref_name_as_contents_not_size() {
    let scratch = ScratchDirectory::new();
    let source = scratch.0.join("source.git");
    let packed_refs = source.join("packed-refs");
    fs::create_dir_all(source.join("objects")).expect("object directory creates");
    let oid = "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0";
    let duplicate = format!("{oid} refs/heads/duplicated\n{oid} refs/heads/duplicated\n");
    fs::write(&packed_refs, duplicate).expect("duplicate packed refs write");
    let node = node(scratch.0.join("node"));

    // One name carried twice is a contents-law violation even though the
    // set is far below any limit: it must not be misreported as
    // RefLimitExceeded.
    assert!(matches!(
        node.stage_loose_git_import(&source),
        Err(LooseGitImportRefusal::PackedRefContents(path)) if *path == packed_refs
    ));
    node.shutdown().expect("node drains");
}

#[test]
fn loose_import_refuses_packed_refs_over_the_direct_ref_limit() {
    let scratch = ScratchDirectory::new();
    let source = scratch.0.join("source.git");
    fs::create_dir_all(source.join("objects")).expect("object directory creates");
    let oid = "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0";
    let mut packed_refs = String::with_capacity((super::MAX_IMPORT_REFS + 1) * 64);
    for index in 0..=super::MAX_IMPORT_REFS {
        packed_refs.push_str(oid);
        packed_refs.push_str(" refs/heads/ref-");
        packed_refs.push_str(&index.to_string());
        packed_refs.push('\n');
    }
    fs::write(source.join("packed-refs"), packed_refs).expect("packed refs fixture writes");
    let node = node(scratch.0.join("node"));

    assert!(matches!(
        node.stage_loose_git_import(&source),
        Err(LooseGitImportRefusal::RefLimitExceeded { limit })
            if limit == super::MAX_IMPORT_REFS
    ));
    node.shutdown().expect("node drains");
}

#[test]
fn loose_import_refuses_a_reachable_file_that_is_not_a_zlib_loose_object() {
    let scratch = ScratchDirectory::new();
    let source = scratch.0.join("source.git");
    fs::create_dir_all(&source).expect("source directory creates");
    write_branch_head(&source);
    let oid = "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0";
    let ref_path = source.join("refs/heads/main");
    let object_path = source.join("objects/b6/fc4c620b67d95f953a5c1c1230aaab5db5a1b0");
    fs::create_dir_all(ref_path.parent().expect("ref parent exists"))
        .expect("ref directory creates");
    fs::create_dir_all(object_path.parent().expect("object parent exists"))
        .expect("object directory creates");
    fs::write(&ref_path, format!("{oid}\n")).expect("fixture ref writes");
    fs::write(&object_path, b"not a zlib stream").expect("invalid loose object writes");
    let node = node(scratch.0.join("node"));

    assert!(matches!(
        node.stage_loose_git_import(&source),
        Err(LooseGitImportRefusal::LooseObject(_))
    ));
    node.shutdown().expect("node drains");
}

#[test]
fn loose_import_refuses_a_compressed_object_before_reading_it_over_the_bound() {
    let scratch = ScratchDirectory::new();
    let source = scratch.0.join("source.git");
    fs::create_dir_all(&source).expect("source directory creates");
    write_branch_head(&source);
    let oid = "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0";
    let ref_path = source.join("refs/heads/main");
    let object_path = source.join("objects/b6/fc4c620b67d95f953a5c1c1230aaab5db5a1b0");
    fs::create_dir_all(ref_path.parent().expect("ref parent exists"))
        .expect("ref directory creates");
    fs::create_dir_all(object_path.parent().expect("object parent exists"))
        .expect("object directory creates");
    fs::write(&ref_path, format!("{oid}\n")).expect("fixture ref writes");
    let compressed_bytes = super::MAX_IMPORT_COMPRESSED_OBJECT_BYTES + 1;
    fs::File::create(&object_path)
        .expect("oversized loose object creates")
        .set_len(compressed_bytes)
        .expect("oversized loose object is sparse");
    let node = node(scratch.0.join("node"));

    assert!(matches!(
        node.stage_loose_git_import(&source),
        Err(LooseGitImportRefusal::CompressedObjectBytesExceeded { limit, observed })
            if limit == super::MAX_IMPORT_COMPRESSED_OBJECT_BYTES
                && observed == compressed_bytes
    ));
    node.shutdown().expect("node drains");
}

#[test]
fn loose_import_refuses_a_reachable_tree_with_an_incomplete_edge() {
    let scratch = ScratchDirectory::new();
    let source = scratch.0.join("source.git");
    fs::create_dir_all(&source).expect("source directory creates");
    write_branch_head(&source);
    let tree = decode_hex(include_str!(
        "../../../fgit-git-object/tests/corpus/malformed/tree-truncated-reference.hex"
    ));
    let tree_oid = write_loose_object(&source, GitObjectKind::Tree, &tree);
    let commit = format!(
        "tree {tree_oid}\nauthor FrankenGit <fg@example.invalid> 0 +0000\ncommitter FrankenGit <fg@example.invalid> 0 +0000\n\ntruncated tree fixture\n"
    );
    let commit_oid = write_loose_object(&source, GitObjectKind::Commit, commit.as_bytes());
    let ref_path = source.join("refs/heads/main");
    fs::create_dir_all(ref_path.parent().expect("ref parent exists"))
        .expect("ref directory creates");
    fs::write(&ref_path, format!("{commit_oid}\n")).expect("fixture ref writes");
    let node = node(scratch.0.join("node"));

    assert!(matches!(
        node.stage_loose_git_import(&source),
        Err(LooseGitImportRefusal::ObjectStructure(_))
    ));
    node.shutdown().expect("node drains");
}

#[test]
fn loose_import_refuses_a_reachable_commit_without_a_tree_edge() {
    let scratch = ScratchDirectory::new();
    let source = scratch.0.join("source.git");
    fs::create_dir_all(&source).expect("source directory creates");
    write_branch_head(&source);
    let oid = write_loose_object(
        &source,
        GitObjectKind::Commit,
        b"author Example <example@invalid> 1 +0000\ncommitter Example <example@invalid> 1 +0000\n",
    );
    let ref_path = source.join("refs/heads/main");
    fs::create_dir_all(ref_path.parent().expect("ref parent exists"))
        .expect("ref directory creates");
    fs::write(&ref_path, format!("{oid}\n")).expect("fixture ref writes");
    let node = node(scratch.0.join("node"));

    assert!(matches!(
        node.stage_loose_git_import(&source),
        Err(LooseGitImportRefusal::CommitTreeMissing(identity)) if identity == oid
    ));
    node.shutdown().expect("node drains");
}

#[test]
fn loose_import_refuses_a_reachable_tag_without_exactly_one_target() {
    let scratch = ScratchDirectory::new();
    let source = scratch.0.join("source.git");
    fs::create_dir_all(&source).expect("source directory creates");
    write_branch_head(&source);
    let oid = write_loose_object(
        &source,
        GitObjectKind::Tag,
        b"type commit\ntag v1.0.0\ntagger Example <example@invalid> 1 +0000\n",
    );
    let ref_path = source.join("refs/tags/v1.0.0");
    fs::create_dir_all(ref_path.parent().expect("ref parent exists"))
        .expect("ref directory creates");
    fs::write(&ref_path, format!("{oid}\n")).expect("fixture ref writes");
    let node = node(scratch.0.join("node"));

    assert!(matches!(
        node.stage_loose_git_import(&source),
        Err(LooseGitImportRefusal::TagObjectMissing(identity)) if identity == oid
    ));
    node.shutdown().expect("node drains");
}

#[test]
fn loose_import_refuses_ref_directories_deeper_than_the_profile_limit() {
    let scratch = ScratchDirectory::new();
    let source = scratch.0.join("source.git");
    let mut nested = source.join("refs");
    for index in 0..=super::MAX_IMPORT_REF_DEPTH {
        nested.push(format!("level-{index}"));
    }
    fs::create_dir_all(&nested).expect("deep ref directory creates");
    fs::create_dir_all(source.join("objects")).expect("object directory creates");
    let node = node(scratch.0.join("node"));

    assert!(matches!(
        node.stage_loose_git_import(&source),
        Err(LooseGitImportRefusal::RefDepthExceeded { limit })
            if limit == super::MAX_IMPORT_REF_DEPTH
    ));
    node.shutdown().expect("node drains");
}
