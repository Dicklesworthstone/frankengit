use super::*;
use fgit_codec::{CryptoBodyIdentity, RepositoryConfigurationBody, body_id, harness::genesis_head};
use fgit_crypto::{git_object_id, ref_state_membership_proof, ref_state_merkle_root};
use fgit_types::{Digest, RootLayoutVersion};
use std::cell::Cell;

fn reference() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}

fn tree_entry(mode: &[u8], name: &[u8], oid: GitOid) -> Vec<u8> {
    [mode, b" ", name, b"\0", oid.as_bytes()].concat()
}

fn fixture(
    format: GitHashAlgorithm,
    path: &[u8],
    mode: &[u8],
    bytes: &[u8],
) -> VerifiedBlobEnvelope {
    let components: Vec<_> = path.split(|b| *b == b'/').collect();
    let mut next = git_object_id(format, GitObjectKind::Blob, bytes);
    let mut trees = Vec::new();
    for (index, component) in components.iter().rev().enumerate() {
        let tree = tree_entry(if index == 0 { mode } else { b"40000" }, component, next);
        next = git_object_id(format, GitObjectKind::Tree, &tree);
        trees.push(tree);
    }
    trees.reverse();
    let commit = format!("tree {next}\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\nexact bytes\n").into_bytes();
    envelope_for(format, path, commit, trees, bytes.to_vec())
}

fn envelope_for(
    format: GitHashAlgorithm,
    path: &[u8],
    commit: Vec<u8>,
    trees: Vec<Vec<u8>>,
    blob: Vec<u8>,
) -> VerifiedBlobEnvelope {
    let tip = git_object_id(format, GitObjectKind::Commit, &commit);
    let configuration = RepositoryConfigurationBody {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: format,
        hidden_ref_rules: vec![],
    };
    let configuration_id = body_id(&CryptoBodyIdentity, &configuration).unwrap();
    let mut head = genesis_head();
    head.configuration_root = Digest::new(configuration_id.algorithm(), *configuration_id.digest());
    let entries = vec![
        (reference(), tip),
        (RefName::try_new(b"refs/heads/other").unwrap(), tip),
    ];
    head.ref_root = ref_state_merkle_root(&entries).unwrap();
    let (_, proof) = ref_state_membership_proof(&entries, &reference()).unwrap();
    let proof = VerifiedReadEnvelope::new(
        head,
        Some(configuration),
        VerifiedReadAnswer::RefMembership {
            name: reference(),
            oid: tip,
            proof: Box::new(proof),
        },
    );
    VerifiedBlobEnvelope::from_parts(proof, path.to_vec(), commit, trees, blob).unwrap()
}

fn pin(envelope: &VerifiedBlobEnvelope) -> RepositoryAuthorityHeadId {
    authority_head_identity(envelope.head()).unwrap()
}

fn verified(envelope: &VerifiedBlobEnvelope) -> Result<VerifiedBlob<'_>, VerifiedBlobRefusal> {
    verify_blob_against_head(pin(envelope), &reference(), envelope.path(), envelope)
}

#[test]
fn both_hash_domains_verify_complete_nested_raw_binary_executable_and_symlink_data() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for (path, mode, body, kind) in [
            (
                b"file".as_slice(),
                b"100644".as_slice(),
                b"".as_slice(),
                VerifiedBlobKind::File,
            ),
            (
                b"src/\xff.bin",
                b"100755",
                b"\0\xff\r\nwithout-final",
                VerifiedBlobKind::Executable,
            ),
            (
                b"dir/link",
                b"120000",
                b"../../private",
                VerifiedBlobKind::Symlink,
            ),
        ] {
            let envelope = fixture(format, path, mode, body);
            let frame = encode_verified_blob_envelope(&envelope).unwrap();
            let decoded = decode_verified_blob_envelope(&frame).unwrap();
            assert_eq!(envelope, decoded);
            assert_eq!(frame, encode_verified_blob_envelope(&decoded).unwrap());
            let result =
                verify_blob_against_head(pin(&envelope), &reference(), path, &decoded).unwrap();
            assert_eq!(result.kind, kind);
            assert_eq!(result.bytes, body);
            assert_eq!(
                result.object_id,
                git_object_id(format, GitObjectKind::Blob, body)
            );
            assert_eq!(
                result.source_commit,
                git_object_id(format, GitObjectKind::Commit, &envelope.commit)
            );
        }
    }
}

#[test]
fn every_original_object_and_the_exact_head_ref_and_path_are_load_bearing() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let original = fixture(format, b"one/two/file", b"100644", b"payload");
        let expected = pin(&original);
        assert!(verified(&original).is_ok());
        for target in 0..5 {
            let mut tampered = original.clone();
            match target {
                0 => tampered.commit[0] ^= 1,
                1..=3 => tampered.trees[target - 1][0] ^= 1,
                4 => tampered.blob[0] ^= 1,
                _ => unreachable!(),
            }
            assert!(matches!(
                verify_blob_against_head(expected, &reference(), original.path(), &tampered),
                Err(VerifiedBlobRefusal::ObjectHashMismatch)
            ));
        }
        let mut changed_head = original.clone();
        changed_head.ref_proof.head.ref_root = genesis_head().ref_root;
        assert!(matches!(
            verify_blob_against_head(expected, &reference(), original.path(), &changed_head),
            Err(VerifiedBlobRefusal::HeadMismatch)
        ));
        assert!(matches!(
            verify_blob_against_head(
                expected,
                &RefName::try_new(b"refs/heads/other").unwrap(),
                original.path(),
                &original
            ),
            Err(VerifiedBlobRefusal::RefMismatch)
        ));
        assert!(matches!(
            verify_blob_against_head(expected, &reference(), b"one/two/other", &original),
            Err(VerifiedBlobRefusal::PathMismatch)
        ));
        let mut forged_path = original.clone();
        forged_path.path = b"one/two/other".to_vec();
        assert!(matches!(
            verified(&forged_path),
            Err(VerifiedBlobRefusal::PathMissing)
        ));
        let mut reversed = original.clone();
        reversed.trees.reverse();
        assert!(matches!(
            verified(&reversed),
            Err(VerifiedBlobRefusal::ObjectHashMismatch)
        ));
        let mut missing = original.clone();
        missing.trees.pop();
        assert!(matches!(
            verified(&missing),
            Err(VerifiedBlobRefusal::TreeCountMismatch)
        ));
        let mut extra = original.clone();
        extra.trees.push(extra.trees[0].clone());
        assert!(matches!(
            verified(&extra),
            Err(VerifiedBlobRefusal::TreeCountMismatch)
        ));
    }
}

#[test]
fn a_ref_proof_cannot_be_substituted_with_another_configuration_domain_or_layout() {
    let original = fixture(GitHashAlgorithm::Sha1, b"file", b"100644", b"data");
    assert!(verified(&original).is_ok());
    let mut forged = original.clone();
    let Some(VerifiedReadConfiguration::RepositoryV1(configuration)) =
        &mut forged.ref_proof.configuration
    else {
        panic!()
    };
    configuration.object_format = GitHashAlgorithm::Sha256;
    assert!(matches!(
        verified(&forged),
        Err(VerifiedBlobRefusal::RefProof(_))
    ));
    let mut legacy = original.clone();
    let Some(VerifiedReadConfiguration::RepositoryV1(configuration)) =
        &mut legacy.ref_proof.configuration
    else {
        panic!()
    };
    configuration.root_layout = RootLayoutVersion::LegacyWholeBody;
    let id = body_id(&CryptoBodyIdentity, configuration).unwrap();
    legacy.ref_proof.head.configuration_root = Digest::new(id.algorithm(), *id.digest());
    assert!(matches!(
        verified(&legacy),
        Err(VerifiedBlobRefusal::RefProof(_))
    ));
    let mut wrong_width = original.clone();
    let Some(VerifiedReadConfiguration::RepositoryV1(configuration)) =
        &mut wrong_width.ref_proof.configuration
    else {
        panic!()
    };
    configuration.object_format = GitHashAlgorithm::Sha256;
    let id = body_id(&CryptoBodyIdentity, configuration).unwrap();
    wrong_width.ref_proof.head.configuration_root = Digest::new(id.algorithm(), *id.digest());
    assert!(matches!(
        verified(&wrong_width),
        Err(VerifiedBlobRefusal::ObjectFormatMismatch)
    ));
    let mut unproven = original.clone();
    unproven.ref_proof.configuration = None;
    assert!(matches!(
        verified(&unproven),
        Err(VerifiedBlobRefusal::RefProof(_))
    ));
}

#[test]
fn exact_path_rules_refuse_aliases_and_bound_depth_before_traversal() {
    for path in [
        b"".as_slice(),
        b"/file",
        b"file/",
        b"a//b",
        b"a/./b",
        b"a/../b",
        b"a\0b",
    ] {
        assert!(matches!(
            validate_blob_path(path),
            Err(VerifiedBlobRefusal::InvalidPath)
        ));
    }
    assert!(validate_blob_path(b".github/\xff name").is_ok());
    assert!(validate_blob_path(&vec![b'a'; 255]).is_ok());
    assert!(validate_blob_path(&vec![b'a'; 256]).is_err());
    let depth64 = vec![b"a".as_slice(); 64].join(&b'/');
    let depth65 = vec![b"a".as_slice(); 65].join(&b'/');
    assert_eq!(validate_blob_path(&depth64).unwrap(), 64);
    assert!(validate_blob_path(&depth65).is_err());
    let deepest = fixture(GitHashAlgorithm::Sha256, &depth64, b"100644", b"depth");
    assert_eq!(verified(&deepest).unwrap().bytes, b"depth");
}

#[test]
fn gitlinks_directories_duplicate_entries_and_non_directory_edges_never_become_blobs() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let valid = fixture(format, b"file", b"100644", b"body");
        for mode in [b"160000".as_slice(), b"40000"] {
            let invalid = fixture(format, b"file", mode, b"body");
            assert!(matches!(
                verified(&invalid),
                Err(VerifiedBlobRefusal::BlobRequired)
            ));
        }
        let duplicate = [valid.trees[0].as_slice(), valid.trees[0].as_slice()].concat();
        let tree_id = git_object_id(format, GitObjectKind::Tree, &duplicate);
        let commit = format!("tree {tree_id}\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\nmessage\n").into_bytes();
        let duplicate = envelope_for(format, b"file", commit, vec![duplicate], b"body".to_vec());
        assert!(matches!(
            verified(&duplicate),
            Err(VerifiedBlobRefusal::InvalidObject)
        ));
        let mut nested = fixture(format, b"dir/file", b"100644", b"body");
        let replacement = tree_entry(
            b"120000",
            b"dir",
            git_object_id(format, GitObjectKind::Tree, &nested.trees[1]),
        );
        let root = git_object_id(format, GitObjectKind::Tree, &replacement);
        nested.trees[0] = replacement;
        let commit = format!("tree {root}\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\nmessage\n").into_bytes();
        let nested = envelope_for(format, b"dir/file", commit, nested.trees, nested.blob);
        assert!(matches!(
            verified(&nested),
            Err(VerifiedBlobRefusal::DirectoryRequired)
        ));
        assert!(verified(&valid).is_ok());
    }
}

#[test]
fn malformed_framing_never_leaves_a_verified_prefix_or_ignores_a_suffix() {
    let original = fixture(GitHashAlgorithm::Sha256, b"dir/file", b"100644", b"body");
    let frame = encode_verified_blob_envelope(&original).unwrap();
    for length in [0, 1, 4, frame.len() / 2, frame.len() - 1] {
        assert!(decode_verified_blob_envelope(&frame[..length]).is_err());
    }
    let mut trailing = frame.clone();
    trailing.push(0);
    assert!(decode_verified_blob_envelope(&trailing).is_err());
    assert!(
        decode_verified_blob_envelope(&encode_verified_read_envelope(&original.ref_proof).unwrap())
            .is_err()
    );
    let mut wrong_magic = frame.clone();
    wrong_magic[0] ^= 1;
    assert!(decode_verified_blob_envelope(&wrong_magic).is_err());
    let mut unknown_version = original;
    unknown_version.ref_proof.version = 2;
    assert!(encode_verified_blob_envelope(&unknown_version).is_err());
    assert!(decode_verified_blob_envelope(&frame).is_ok());
}

#[test]
fn cancellation_before_and_during_hashing_never_returns_file_bytes() {
    let body = vec![b'x'; HASH_CHUNK_BYTES * 4 + 1];
    let original = fixture(GitHashAlgorithm::Sha256, b"file", b"100644", &body);
    for allowed in 0..18 {
        let calls = Cell::new(0);
        let result = verify_blob_against_head_while(
            pin(&original),
            &reference(),
            b"file",
            &original,
            &|| {
                let n = calls.get();
                calls.set(n + 1);
                n < allowed
            },
        );
        if let Ok(result) = result {
            assert_eq!(result.bytes, body);
        } else {
            assert!(matches!(result, Err(VerifiedBlobRefusal::Cancelled)));
        }
    }
    assert_eq!(verified(&original).unwrap().bytes, body);
}

#[test]
fn byte_and_entry_budgets_are_shared_across_the_complete_proof() {
    let mut blob = fixture(GitHashAlgorithm::Sha256, b"file", b"100644", b"body");
    blob.blob.resize(MAX_VERIFIED_BLOB_BYTES + 1, 0);
    assert!(matches!(
        blob.validate_shape(),
        Err(VerifiedBlobRefusal::BoundExceeded("blob bytes"))
    ));
    let mut metadata = fixture(GitHashAlgorithm::Sha256, b"dir/file", b"100644", b"body");
    metadata.trees[0].resize(MAX_VERIFIED_BLOB_METADATA_BYTES / 2, 0);
    metadata.trees[1].resize(MAX_VERIFIED_BLOB_METADATA_BYTES / 2, 0);
    assert!(matches!(
        metadata.validate_shape(),
        Err(VerifiedBlobRefusal::BoundExceeded("metadata bytes"))
    ));
    let oversized = vec![0; MAX_VERIFIED_BLOB_FRAME_BYTES + 1];
    assert!(matches!(
        decode_verified_blob_envelope(&oversized),
        Err(VerifiedBlobRefusal::BoundExceeded("frame bytes"))
    ));
    assert!(
        verified(&fixture(
            GitHashAlgorithm::Sha256,
            b"file",
            b"100644",
            b"body"
        ))
        .is_ok()
    );
}

#[test]
fn ten_thousand_entry_tree_has_a_complete_original_tree_witness_and_measured_bounds() {
    let format = GitHashAlgorithm::Sha256;
    let blob = b"verified large-tree payload";
    let oid = git_object_id(format, GitObjectKind::Blob, blob);
    let mut tree = Vec::new();
    for i in 0..10_000 {
        tree.extend(tree_entry(
            b"100644",
            format!("file-{i:05}").as_bytes(),
            oid,
        ));
    }
    let tree_id = git_object_id(format, GitObjectKind::Tree, &tree);
    let commit = format!("tree {tree_id}\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\nlarge tree\n").into_bytes();
    let envelope = envelope_for(format, b"file-09999", commit, vec![tree], blob.to_vec());
    let frame = encode_verified_blob_envelope(&envelope).unwrap();
    let started = std::time::Instant::now();
    let result = verified(&envelope).unwrap();
    let elapsed = started.elapsed();
    assert_eq!(result.bytes, blob);
    assert!(frame.len() > 480_000 && frame.len() < 510_000);
    eprintln!(
        "verified-blob entries=10000 frame_bytes={} verify_nanos={}",
        frame.len(),
        elapsed.as_nanos()
    );
}
