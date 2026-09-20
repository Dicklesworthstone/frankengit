//! Builder contract tests. The decoder callback is deliberately a test double;
//! actual native decompression is exercised by the node adapter's tests.
use super::*;
use std::cell::Cell;

const BODY: &[u8] = b"\0\x01\x02\r\n\xffA";
// Git 2.47.3 creation literal and empty reverse member, not executable content.
const HUNKS: &str = "GIT binary patch\nliteral 7\nOcmZQzWa8!e?+5?_r~z95\n\nliteral 0\nHcmV?d00001\n\n";
fn metadata() -> MergeMetadata {
    MergeMetadata { author: "A <a@example.invalid>".into(), committer: "C <c@example.invalid>".into(),
        timestamp: 1, message: b"initial\n".to_vec() }
}
fn compressed(format: GitHashAlgorithm, path: &str) -> Vec<u8> {
    let id = git_object_id(format, GitObjectKind::Blob, BODY);
    format!("diff --git a/{path} b/{path}\nnew file mode 100644\nindex {}..{id}\n{HUNKS}",
        "0".repeat(format.digest_len() * 2)).into_bytes()
}
fn literal() -> Vec<u8> {
    [b"diff --git a/asset.bin b/asset.bin\nnew file mode 100644\n--- /dev/null\n+++ b/asset.bin\n@@ -0,0 +1,2 @@\n+\0\x01\x02\r\n+\xffA\n\\ No newline at end of file\n".as_slice()].concat()
}

#[test]
fn decoder_opt_in_produces_the_same_complete_native_root_as_literal_bytes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let input = compressed(format, "asset.bin"); let mut calls = 0;
        let actual = prepare_initial_commit_with_binary_decoder(format, &input, &metadata(),
            PatchLimits::default(), &|| false, |bytes, index, base| {
                calls += 1; assert_eq!(bytes, HUNKS.as_bytes()); assert!(base.is_empty());
                assert!(index.old.iter().all(|b| *b == b'0')); Ok(BODY.to_vec())
            }).unwrap();
        let expected = prepare_initial_commit(format, &literal(), &metadata(), PatchLimits::default(), &|| false).unwrap();
        assert_eq!(calls, 1); assert_eq!(actual.commit, expected.commit);
        assert_eq!(actual.tree, expected.tree); assert_eq!(actual.files, expected.files);
        assert_eq!(actual.objects, expected.objects); assert_eq!(actual.patch_sha256, sha256_digest(&input));
        assert!(prepare_initial_commit(format, &input, &metadata(), PatchLimits::default(), &|| false).is_err());
    }
}

#[test]
fn mixed_literal_empty_and_compressed_files_only_decode_the_compressed_record() {
    let format = GitHashAlgorithm::Sha256; let mut input = compressed(format, "asset.bin");
    input.extend_from_slice(b"diff --git a/empty b/empty\nnew file mode 100755\ndiff --git a/readme b/readme\nnew file mode 100644\n--- /dev/null\n+++ b/readme\n@@ -0,0 +1 @@\n+hello\n");
    let mut calls = 0;
    let plan = prepare_initial_commit_with_binary_decoder(format, &input, &metadata(),
        PatchLimits::default(), &|| false, |_, _, _| { calls += 1; Ok(BODY.to_vec()) }).unwrap();
    assert_eq!(calls, 1); assert_eq!(plan.files.len(), 3);
    assert_eq!(plan.files[1].bytes, 0); assert_eq!(plan.files[1].mode, 0o100755);
    assert_eq!(plan.files[2].blob, git_object_id(format, GitObjectKind::Blob, b"hello\n"));
}

#[test]
fn a_late_noncreation_refuses_before_any_decode() {
    let mut input = compressed(GitHashAlgorithm::Sha1, "asset.bin");
    input.extend_from_slice(b"diff --git a/z b/z\ndeleted file mode 100644\n--- a/z\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n");
    let mut calls = 0;
    let result = prepare_initial_commit_with_binary_decoder(GitHashAlgorithm::Sha1, &input, &metadata(),
        PatchLimits::default(), &|| false, |_, _, _| { calls += 1; Ok(BODY.to_vec()) });
    assert!(matches!(result, Err(InitialCommitError::CreationRequired))); assert_eq!(calls, 0);
}

#[test]
fn binary_indexes_must_use_the_selected_full_native_hash_domain() {
    for (format, other) in [(GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256),
        (GitHashAlgorithm::Sha256, GitHashAlgorithm::Sha1)] {
        let input = compressed(other, "asset.bin"); let mut calls = 0;
        let result = prepare_initial_commit_with_binary_decoder(format, &input, &metadata(),
            PatchLimits::default(), &|| false, |_, _, _| { calls += 1; Ok(BODY.to_vec()) });
        assert!(matches!(result, Err(InitialCommitError::IndexMismatch))); assert_eq!(calls, 0);
    }
}

#[test]
fn decoder_results_still_require_exact_blob_identities_and_complete_closure_budget() {
    let input = compressed(GitHashAlgorithm::Sha1, "asset.bin");
    let wrong = prepare_initial_commit_with_binary_decoder(GitHashAlgorithm::Sha1, &input, &metadata(),
        PatchLimits::default(), &|| false, |_, _, _| Ok(b"different".to_vec()));
    assert!(matches!(wrong, Err(InitialCommitError::IndexMismatch)));
    let bounded = prepare_initial_commit_with_binary_decoder(GitHashAlgorithm::Sha1, &input, &metadata(),
        PatchLimits { max_output_bytes: BODY.len(), ..PatchLimits::default() }, &|| false, |_, _, _| Ok(BODY.to_vec()));
    assert!(matches!(bounded, Err(InitialCommitError::Budget(_))));
}

#[test]
fn cancellation_after_decoder_success_cannot_return_a_plan() {
    let stopped = Cell::new(false); let input = compressed(GitHashAlgorithm::Sha1, "asset.bin");
    let result = prepare_initial_commit_with_binary_decoder(GitHashAlgorithm::Sha1, &input, &metadata(),
        PatchLimits::default(), &|| stopped.get(), |_, _, _| { stopped.set(true); Ok(BODY.to_vec()) });
    assert!(matches!(result, Err(InitialCommitError::Patch(PatchError::Cancelled))));
}

#[test]
fn decoder_error_after_an_earlier_file_never_returns_a_partial_plan() {
    let mut input = compressed(GitHashAlgorithm::Sha256, "a");
    input.extend(compressed(GitHashAlgorithm::Sha256, "b")); let mut calls = 0;
    let result = prepare_initial_commit_with_binary_decoder(GitHashAlgorithm::Sha256, &input, &metadata(),
        PatchLimits::default(), &|| false, |_, _, _| {
            calls += 1; if calls == 1 { Ok(BODY.to_vec()) } else { Err(PatchError::Budget("test decoder")) }
        });
    assert_eq!(calls, 2); assert!(matches!(result, Err(InitialCommitError::Patch(PatchError::Budget(_)))));
}
