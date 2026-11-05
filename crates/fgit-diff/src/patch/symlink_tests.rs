//! Explicit symlink parsing and exact blob-data application. Binary members
//! here are framing fixtures; decoder doubles test the adapter contract only.
//! Native consumers separately verify compressed bytes and object identities.

use super::*;
use std::cell::Cell;

fn parse(input: &[u8]) -> Result<UnifiedPatch<'_>, PatchError> {
    UnifiedPatch::parse_with_symlinks(input, PatchLimits::default(), &|| false)
}

fn old_profiles(input: &[u8]) -> [Result<UnifiedPatch<'_>, PatchError>; 5] {
    let limits = PatchLimits::default();
    [
        UnifiedPatch::parse(input, limits, &|| false),
        UnifiedPatch::parse_with_renames(input, limits, &|| false),
        UnifiedPatch::parse_with_binary(input, limits, &|| false),
        UnifiedPatch::parse_with_binary_and_renames(input, limits, &|| false),
        UnifiedPatch::parse_with_binary_renames(input, limits, &|| false),
    ]
}

fn creation(target: &[u8]) -> Vec<u8> {
    let mut bytes = b"diff --git a/link b/link\nnew file mode 120000\n".to_vec();
    if !target.is_empty() {
        bytes.extend(b"--- /dev/null\n+++ b/link\n@@ -0,0 +1 @@\n+");
        bytes.extend(target);
        bytes.extend(b"\n\\ No newline at end of file\n");
    }
    bytes
}

const EDIT: &[u8] = b"diff --git a/link b/link\n--- a/link\n+++ b/link\n@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+../target\n\\ No newline at end of file\n";

#[test]
fn only_the_explicit_profile_creates_byte_exact_inert_symlink_data() {
    for target in [
        b"../target".as_slice(),
        b"../../outside/.git/config",
        b"/absolute/never-follow",
        b"raw\0link-text\xff",
        b"",
    ] {
        let bytes = creation(target);
        for old in old_profiles(&bytes) {
            assert!(matches!(old, Err(PatchError::Unsupported { .. })));
        }
        let patch = parse(&bytes).unwrap();
        assert_eq!(patch.files().len(), 1);
        let file = &patch.files()[0];
        assert!(file.allows_symlinks());
        assert_eq!(file.path(), b"link");
        assert_eq!(file.change(), FileChange::Create);
        assert_eq!(
            file.apply(None, patch.limits(), &|| false).unwrap(),
            Some(PatchedFile {
                mode: 0o120000,
                content: target.to_vec()
            })
        );
        assert_eq!(
            file.apply(Some((0o120000, b"existing")), patch.limits(), &|| false),
            Err(PatchError::SourcePresence)
        );
    }
}

#[test]
fn an_implicit_symlink_source_does_not_widen_any_old_profile() {
    for old in old_profiles(EDIT) {
        let patch = old.unwrap();
        let file = &patch.files()[0];
        assert!(!file.allows_symlinks());
        assert_eq!(
            file.apply(Some((0o120000, b"old")), patch.limits(), &|| false),
            Err(PatchError::SourceMode)
        );
        assert_eq!(
            file.apply(Some((0o100644, b"old")), patch.limits(), &|| false)
                .unwrap(),
            Some(PatchedFile {
                mode: 0o100644,
                content: b"../target".to_vec()
            })
        );
    }
    let patch = parse(EDIT).unwrap();
    assert_eq!(
        patch.files()[0]
            .apply(Some((0o120000, b"old")), patch.limits(), &|| false)
            .unwrap(),
        Some(PatchedFile {
            mode: 0o120000,
            content: b"../target".to_vec()
        })
    );
    assert!(matches!(
        patch.files()[0].apply(Some((0o120000, b"wrong")), patch.limits(), &|| false),
        Err(PatchError::ContextMismatch { .. })
    ));
}

#[test]
fn symlink_mode_replacements_preserve_bytes_and_bind_the_actual_old_kind() {
    for (before, after) in [
        (0o100644, 0o120000),
        (0o100755, 0o120000),
        (0o120000, 0o100644),
        (0o120000, 0o100755),
    ] {
        let bytes =
            format!("diff --git a/link b/link\nold mode {before:06o}\nnew mode {after:06o}\n");
        for old in old_profiles(bytes.as_bytes()) {
            assert!(matches!(old, Err(PatchError::Unsupported { .. })));
        }
        let patch = parse(bytes.as_bytes()).unwrap();
        let file = &patch.files()[0];
        assert_eq!(
            file.apply(
                Some((before, b"../unchanged\0bytes")),
                patch.limits(),
                &|| false
            )
            .unwrap(),
            Some(PatchedFile {
                mode: after,
                content: b"../unchanged\0bytes".to_vec()
            })
        );
        assert_eq!(
            file.apply(
                Some((after, b"../unchanged\0bytes")),
                patch.limits(),
                &|| false
            ),
            Err(PatchError::SourceMode)
        );
    }
}

#[test]
fn index_modes_and_deletions_keep_identity_and_source_presence_checks() {
    for width in [40, 64] {
        let old = "a".repeat(width);
        let new = "b".repeat(width);
        let mut bytes =
            format!("diff --git a/link b/link\nindex {old}..{new} 120000\n").into_bytes();
        bytes.extend(&EDIT["diff --git a/link b/link\n".len()..]);
        let patch = parse(&bytes).unwrap();
        let file = &patch.files()[0];
        assert_eq!(
            file.index(),
            Some(&IndexExpectation {
                old: old.into_bytes(),
                new: new.into_bytes()
            })
        );
        assert_eq!(
            file.apply(Some((0o120000, b"old")), patch.limits(), &|| false)
                .unwrap()
                .unwrap()
                .mode,
            0o120000
        );
        assert_eq!(
            file.apply(Some((0o100644, b"old")), patch.limits(), &|| false),
            Err(PatchError::SourceMode)
        );
        for legacy in old_profiles(&bytes) {
            assert!(matches!(legacy, Err(PatchError::Unsupported { .. })));
        }
    }
    let bytes = b"diff --git a/link b/link\ndeleted file mode 120000\n--- a/link\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n\\ No newline at end of file\n";
    let patch = parse(bytes).unwrap();
    assert_eq!(patch.files()[0].change(), FileChange::Delete);
    assert_eq!(
        patch.files()[0]
            .apply(Some((0o120000, b"old")), patch.limits(), &|| false)
            .unwrap(),
        None
    );
    assert_eq!(
        patch.files()[0].apply(None, patch.limits(), &|| false),
        Err(PatchError::SourcePresence)
    );
    for metadata in [
        "index ABCD..bbbb 120000\n",
        "index aaa..bbbb 120000\n",
        "index aaaa..bbbb 120000 trailing\n",
        "old mode 120000\nnew mode 100644\nindex aaaa..bbbb 120000\n",
    ] {
        let bytes = format!("diff --git a/link b/link\n{metadata}");
        assert!(parse(bytes.as_bytes()).is_err());
    }
}

fn rename(from: &str, to: &str) -> String {
    format!(
        "diff --git a/{from} b/{to}\nsimilarity index 100%\nrename from {from}\nrename to {to}\n"
    )
}

#[test]
fn pure_and_edited_symlink_renames_keep_original_coordinates_and_modes() {
    let bytes = rename("old", "new");
    let patch = parse(bytes.as_bytes()).unwrap();
    let file = &patch.files()[0];
    assert_eq!(file.source_path(), b"old");
    assert_eq!(file.path(), b"new");
    assert_eq!(file.renamed_from(), Some(b"old".as_slice()));
    for body in [b"../target".as_slice(), b"\0binary\xff\n\0", b""] {
        assert_eq!(
            file.apply(Some((0o120000, body)), patch.limits(), &|| false)
                .unwrap(),
            Some(PatchedFile {
                mode: 0o120000,
                content: body.to_vec()
            })
        );
    }
    for legacy in [
        UnifiedPatch::parse_with_renames(bytes.as_bytes(), patch.limits(), &|| false),
        UnifiedPatch::parse_with_binary_and_renames(bytes.as_bytes(), patch.limits(), &|| false),
        UnifiedPatch::parse_with_binary_renames(bytes.as_bytes(), patch.limits(), &|| false),
    ] {
        let legacy = legacy.unwrap();
        assert_eq!(
            legacy.files()[0].apply(Some((0o120000, b"../target")), legacy.limits(), &|| false),
            Err(PatchError::SourceMode)
        );
    }
    let bytes = b"diff --git a/old b/new\nrename from old\nrename to new\nindex aaaa..bbbb 120000\n--- a/old\n+++ b/new\n@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+../target\n\\ No newline at end of file\n";
    let patch = parse(bytes).unwrap();
    assert_eq!(
        patch.files()[0]
            .apply(Some((0o120000, b"old")), patch.limits(), &|| false)
            .unwrap(),
        Some(PatchedFile {
            mode: 0o120000,
            content: b"../target".to_vec()
        })
    );
}

#[test]
fn symlink_opt_in_keeps_disjoint_paths_and_rejects_directories_gitlinks_and_copies() {
    let moved = rename("old", "new");
    for name in ["old", "new", "old/child", "new/child"] {
        let input = format!("{moved}diff --git a/{name} b/{name}\nnew file mode 120000\n");
        assert!(matches!(
            parse(input.as_bytes()),
            Err(PatchError::DuplicatePath | PatchError::OverlappingPaths)
        ));
    }
    let chain = moved.clone() + &rename("new", "third");
    assert_eq!(parse(chain.as_bytes()), Err(PatchError::DuplicatePath));
    let disjoint = moved + &rename("other", "another");
    assert_eq!(parse(disjoint.as_bytes()).unwrap().files().len(), 2);
    for mode in ["040000", "40000", "160000", "120001"] {
        let input = format!("diff --git a/link b/link\nnew file mode {mode}\n");
        assert!(matches!(
            parse(input.as_bytes()),
            Err(PatchError::Unsupported { .. })
        ));
    }
    let patch = parse(EDIT).unwrap();
    for mode in [0o40000, 0o160000, 0o120001] {
        assert_eq!(
            patch.files()[0].apply(Some((mode, b"old")), patch.limits(), &|| false),
            Err(PatchError::SourceMode)
        );
    }
    assert!(parse(b"diff --git a/old b/new\ncopy from old\ncopy to new\n").is_err());
}

#[test]
fn binary_symlinks_require_full_indices_and_the_existing_native_decoder() {
    const MEMBER: &str = "literal 3\nC00000\n\n";
    for width in [40, 64] {
        let input = format!(
            "diff --git a/link b/link\nnew file mode 120000\nindex {}..{}\nGIT binary patch\n{MEMBER}",
            "0".repeat(width),
            "b".repeat(width)
        );
        let patch = parse(input.as_bytes()).unwrap();
        let file = &patch.files()[0];
        assert!(matches!(
            file.apply(None, patch.limits(), &|| false),
            Err(PatchError::Unsupported { .. })
        ));
        let calls = Cell::new(0);
        let result = file
            .apply_with_binary_decoder(None, patch.limits(), &|| false, |encoded, index, before| {
                calls.set(calls.get() + 1);
                assert!(encoded.starts_with(b"GIT binary patch\n"));
                assert_eq!(index.new, "b".repeat(width).as_bytes());
                assert!(before.is_empty());
                Ok(b"\0/\xff".to_vec())
            })
            .unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(
            result,
            Some(PatchedFile {
                mode: 0o120000,
                content: b"\0/\xff".to_vec()
            })
        );
        for legacy in old_profiles(input.as_bytes()) {
            assert!(matches!(legacy, Err(PatchError::Unsupported { .. })));
        }
        let abbreviated = input.replace(&"b".repeat(width), "bbbb");
        assert!(parse(abbreviated.as_bytes()).is_err());

        // The symlink profile extends binary-and-renames, not the separate
        // compressed-edit relocation grammar; neither kind may widen it.
        for mode in ["100644", "120000"] {
            let renamed = format!(
                "diff --git a/old b/new\nrename from old\nrename to new\nindex {}..{} {mode}\nGIT binary patch\n{MEMBER}{MEMBER}",
                "a".repeat(width),
                "b".repeat(width)
            );
            assert!(parse(renamed.as_bytes()).is_err());
            if mode == "100644" {
                assert!(
                    UnifiedPatch::parse_with_binary_renames(
                        renamed.as_bytes(),
                        PatchLimits::default(),
                        &|| false
                    )
                    .is_ok()
                );
            }
        }
    }
}

#[test]
fn symlink_bytes_obey_existing_parse_apply_and_cancellation_limits() {
    let bytes = creation(b"../target");
    let exact = PatchLimits {
        max_patch_bytes: bytes.len(),
        ..PatchLimits::default()
    };
    assert!(UnifiedPatch::parse_with_symlinks(&bytes, exact, &|| false).is_ok());
    let short = PatchLimits {
        max_patch_bytes: bytes.len() - 1,
        ..exact
    };
    assert_eq!(
        UnifiedPatch::parse_with_symlinks(&bytes, short, &|| false),
        Err(PatchError::Budget("patch bytes"))
    );
    let patch = parse(&bytes).unwrap();
    let output = PatchLimits {
        max_output_bytes: 8,
        ..PatchLimits::default()
    };
    assert_eq!(
        patch.files()[0].apply(None, output, &|| false),
        Err(PatchError::Budget("result file bytes"))
    );
    let output = PatchLimits {
        max_output_bytes: 9,
        ..output
    };
    assert_eq!(
        patch.files()[0]
            .apply(None, output, &|| false)
            .unwrap()
            .unwrap()
            .content,
        b"../target"
    );
    let edit = parse(EDIT).unwrap();
    let source = PatchLimits {
        max_file_bytes: 2,
        ..PatchLimits::default()
    };
    assert_eq!(
        edit.files()[0].apply(Some((0o120000, b"old")), source, &|| false),
        Err(PatchError::Budget("source file bytes"))
    );
    assert_eq!(
        UnifiedPatch::parse_with_symlinks(&bytes, exact, &|| true),
        Err(PatchError::Cancelled)
    );
    let calls = Cell::new(0);
    let cancelled = || {
        let n = calls.get();
        calls.set(n + 1);
        n >= 1
    };
    assert_eq!(
        edit.files()[0].apply(Some((0o120000, b"old")), edit.limits(), &cancelled),
        Err(PatchError::Cancelled)
    );
    assert!(calls.get() > 1);

    let two = [creation(b"a"), creation(b"b")].concat();
    let one_file = PatchLimits {
        max_files: 1,
        ..PatchLimits::default()
    };
    assert_eq!(
        UnifiedPatch::parse_with_symlinks(&two, one_file, &|| false),
        Err(PatchError::Budget("patch files"))
    );
}
