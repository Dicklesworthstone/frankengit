use super::*;
use std::cell::Cell;

fn relocation(from: &str, to: &str) -> String {
    format!("diff --git a/{from} b/{to}\nsimilarity index 100%\nrename from {from}\nrename to {to}\n")
}
fn parse(input: &[u8]) -> Result<UnifiedPatch<'_>, PatchError> {
    UnifiedPatch::parse_with_renames(input, PatchLimits::default(), &|| false)
}

#[test]
fn relocation_requires_explicit_opt_in_and_preserves_exact_bytes_and_modes() {
    let input = relocation("old", "new");
    assert!(matches!(UnifiedPatch::parse(input.as_bytes(), PatchLimits::default(), &|| false),
        Err(PatchError::Unsupported { .. })));
    let patch = parse(input.as_bytes()).unwrap();
    let file = &patch.files()[0];
    assert_eq!(file.path(), b"new");
    assert_eq!(file.source_path(), b"old");
    assert_eq!(file.renamed_from(), Some(b"old".as_slice()));
    assert_eq!(file.change(), FileChange::Modify);
    for bytes in [b"".as_slice(), b"one\ntwo\n", b"no final newline", b"\0binary\xff\n\0"] {
        for mode in [0o100644, 0o100755] {
            assert_eq!(file.apply(Some((mode, bytes)), patch.limits(), &|| false).unwrap(),
                Some(PatchedFile { mode, content: bytes.to_vec() }));
        }
    }
    assert_eq!(file.apply(None, patch.limits(), &|| false), Err(PatchError::SourcePresence));
    assert_eq!(file.apply(Some((0o120000, b"target")), patch.limits(), &|| false), Err(PatchError::SourceMode));
}

#[test]
fn rename_can_apply_exact_hunks_index_expectations_and_mode_changes() {
    let input = b"diff --git a/old b/new\nold mode 100644\nnew mode 100755\nsimilarity index 50%\nrename from old\nrename to new\nindex 1234567..abcdef0\n--- a/old\n+++ b/new\n@@ -1,2 +1,2 @@\n same\n-old\n+new\n";
    let patch = parse(input).unwrap();
    let file = &patch.files()[0];
    assert_eq!(file.hunk_count(), 1);
    assert_eq!(file.index().unwrap(), &IndexExpectation { old: b"1234567".to_vec(), new: b"abcdef0".to_vec() });
    assert_eq!(file.apply(Some((0o100644, b"same\nold\n")), patch.limits(), &|| false).unwrap(),
        Some(PatchedFile { mode: 0o100755, content: b"same\nnew\n".to_vec() }));
    assert!(matches!(file.apply(Some((0o100644, b"wrong\nold\n")), patch.limits(), &|| false),
        Err(PatchError::ContextMismatch { .. })));
    assert_eq!(file.apply(Some((0o100755, b"same\nold\n")), patch.limits(), &|| false), Err(PatchError::SourceMode));
}

#[test]
fn mode_only_rename_and_no_newline_edit_are_supported() {
    let input = relocation("old", "new") + "old mode 100644\nnew mode 100755\n";
    let patch = parse(input.as_bytes()).unwrap();
    assert_eq!(patch.files()[0].apply(Some((0o100644, b"contents")), patch.limits(), &|| false).unwrap(),
        Some(PatchedFile { mode: 0o100755, content: b"contents".to_vec() }));
    let input = b"diff --git a/old b/new\nrename from old\nrename to new\n--- a/old\n+++ b/new\n@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file\n";
    let patch = parse(input).unwrap();
    assert_eq!(patch.files()[0].apply(Some((0o100644, b"old")), patch.limits(), &|| false).unwrap().unwrap().content, b"new");
}

#[test]
fn names_with_spaces_and_separator_fragments_have_one_interpretation() {
    for (from, to) in [("old name ", " new name"), ("x b/y b/old", "new b/z b/file "), ("café", "résumé")] {
        let input = relocation(from, to);
        let patch = parse(input.as_bytes()).unwrap();
        assert_eq!(patch.files()[0].source_path(), from.as_bytes());
        assert_eq!(patch.files()[0].path(), to.as_bytes());
        assert_eq!(patch, parse(input.as_bytes()).unwrap());
    }
}

#[test]
fn quoted_and_mixed_headers_preserve_raw_paths() {
    for input in [
        b"diff --git \"a/old\\t\\377\" \"b/new\\n\\376\"\nrename from \"old\\t\\377\"\nrename to \"new\\n\\376\"\n".as_slice(),
        b"diff --git a/old b/name \"b/new\\t\"\nrename from old b/name\nrename to \"new\\t\"\n",
        b"diff --git \"a/old\\t\" b/new b/name\nrename from \"old\\t\"\nrename to new b/name\n",
    ] { assert!(parse(input).is_ok()); }
    let patch = parse(b"diff --git \"a/old\\t\\377\" \"b/new\\n\\376\"\nrename from \"old\\t\\377\"\nrename to \"new\\n\\376\"\n").unwrap();
    assert_eq!(patch.files()[0].source_path(), b"old\t\xff");
    assert_eq!(patch.files()[0].path(), b"new\n\xfe");
}

#[test]
fn malformed_or_inconsistent_relocation_metadata_refuses() {
    for input in [
        "diff --git a/old b/new\nrename from old\n",
        "diff --git a/old b/new\nrename to new\n",
        "diff --git a/old b/new\nsimilarity index 100%\n",
        "diff --git a/old b/new\nrename from wrong\nrename to new\n",
        "diff --git a/old b/new\nrename from old\nrename to wrong\n",
        "diff --git a/old b/old\nrename from old\nrename to old\n",
        "diff --git a/old b/new trailing\nrename from old\nrename to new\n",
        "diff --git a/old b/new\nrename from old\nrename from old\nrename to new\n",
        "diff --git a/old b/new\nrename from old\nrename to new\nrename to new\n",
        "diff --git a/old b/new\nrename from old\nrename to new\nsimilarity index 101%\n",
        "diff --git a/old b/new\nrename from old\nrename to new\nsimilarity index -1%\n",
        "diff --git a/old b/new\nrename from old\nrename to new\nsimilarity index 100\n",
        "diff --git a/old b/new\nrename from old\nrename to new\nsimilarity index 99%\n",
    ] { assert!(parse(input.as_bytes()).is_err(), "{input}"); }
    let duplicate = relocation("old", "new") + "similarity index 100%\n";
    assert!(parse(duplicate.as_bytes()).is_err());
}

#[test]
fn identical_claim_never_permits_changed_content() {
    let input = relocation("old", "new") + "--- a/old\n+++ b/new\n@@ -1 +1 @@\n-old\n+new\n";
    let patch = parse(input.as_bytes()).unwrap();
    assert!(matches!(patch.files()[0].apply(Some((0o100644, b"old\n")), patch.limits(), &|| false),
        Err(PatchError::Syntax { reason: "identical rename changed file content", .. })));
}

#[test]
fn rename_cannot_disguise_copy_creation_deletion_or_unsupported_types() {
    for suffix in ["copy from old\ncopy to new\n", "new file mode 100644\n",
        "deleted file mode 100644\n", "old mode 120000\nnew mode 100644\n",
        "index 1234567..abcdef0 160000\n", "GIT binary patch\nliteral 1\nx\n",
        "--- /dev/null\n+++ b/new\n@@ -0,0 +1 @@\n+x\n",
        "--- a/old\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n",
        "--- a/wrong\n+++ b/new\n@@ -1 +1 @@\n-x\n+y\n",
        "--- a/old\n+++ b/wrong\n@@ -1 +1 @@\n-x\n+y\n"] {
        assert!(parse((relocation("old", "new") + suffix).as_bytes()).is_err(), "{suffix}");
    }
}

#[test]
fn both_names_are_validated_without_traversal_or_metadata_paths() {
    for path in ["../outside", "/absolute", ".git/config", "dir/.GiT/config", "a//b", "a/./b", ""] {
        assert!(parse(relocation(path, "new").as_bytes()).is_err());
        assert!(parse(relocation("old", path).as_bytes()).is_err());
    }
    assert!(parse(b"diff --git a/old b/new\nrename from old\nrename to \"new\\000\"\n").is_err());
    assert!(parse(b"diff --git a/old b/new\nrename from old\nrename to \"new\"garbage\n").is_err());
}

#[test]
fn duplicate_and_overlapping_source_or_destination_paths_refuse() {
    for (first, second, expected) in [
        (relocation("a", "b"), relocation("a", "c"), PatchError::DuplicatePath),
        (relocation("a", "b"), relocation("c", "b"), PatchError::DuplicatePath),
        (relocation("a", "b"), relocation("b", "a"), PatchError::DuplicatePath),
        (relocation("a", "b"), relocation("b", "c"), PatchError::DuplicatePath),
        (relocation("a/x", "b"), relocation("a", "c"), PatchError::OverlappingPaths),
        (relocation("a", "b"), relocation("c", "b/x"), PatchError::OverlappingPaths),
    ] { assert_eq!(parse((first + &second).as_bytes()), Err(expected)); }
    assert_eq!(parse(relocation("dir", "dir/file").as_bytes()), Err(PatchError::OverlappingPaths));
    let input = relocation("old", "new") + "diff --git a/old b/old\nold mode 100644\nnew mode 100755\n";
    assert_eq!(parse(input.as_bytes()), Err(PatchError::DuplicatePath));
}

#[test]
fn independent_renames_are_order_invariant_and_ordinary_edits_still_work() {
    let first = relocation("a", "b"); let second = relocation("c", "d");
    let forward = first.clone() + &second; let reverse = second + &first;
    assert_eq!(parse(forward.as_bytes()).unwrap(), parse(reverse.as_bytes()).unwrap());
    let input = b"diff --git a/file b/file\n--- a/file\n+++ b/file\n@@ -1 +1 @@\n-a\n+b\n";
    let patch = parse(input).unwrap();
    assert_eq!(patch, UnifiedPatch::parse(input, PatchLimits::default(), &|| false).unwrap());
    assert_eq!(patch.files()[0].renamed_from(), None);
    assert_eq!(patch.files()[0].source_path(), b"file");
}

#[test]
fn source_destination_and_parser_limits_have_boundary_twins() {
    let input = relocation("longer", "new");
    let limits = PatchLimits { max_path_bytes: 6, max_files: 1, ..PatchLimits::default() };
    let patch = UnifiedPatch::parse_with_renames(input.as_bytes(), limits, &|| false).unwrap();
    assert_eq!(UnifiedPatch::parse_with_renames(input.as_bytes(), PatchLimits { max_path_bytes: 5, ..limits }, &|| false), Err(PatchError::InvalidPath));
    assert_eq!(patch.files()[0].apply(Some((0o100644, b"x")), PatchLimits { max_path_bytes: 5, ..limits }, &|| false), Err(PatchError::InvalidPath));
    let input = relocation("old", "longer");
    assert_eq!(UnifiedPatch::parse_with_renames(input.as_bytes(), PatchLimits { max_path_bytes: 5, ..limits }, &|| false), Err(PatchError::InvalidPath));
    let exact = PatchLimits { max_patch_bytes: input.len(), max_lines: 4, ..limits };
    assert!(UnifiedPatch::parse_with_renames(input.as_bytes(), exact, &|| false).is_ok());
    for limits in [PatchLimits { max_patch_bytes: input.len() - 1, ..exact }, PatchLimits { max_lines: 3, ..exact }] {
        assert!(matches!(UnifiedPatch::parse_with_renames(input.as_bytes(), limits, &|| false), Err(PatchError::Budget(_))));
    }
    let two = input + &relocation("third", "fourth");
    assert_eq!(UnifiedPatch::parse_with_renames(two.as_bytes(), limits, &|| false), Err(PatchError::Budget("patch files")));
}

#[test]
fn cancellation_during_scan_and_apply_never_returns_partial_success() {
    let input = relocation("old", "new"); let calls = Cell::new(0usize);
    parse(input.as_bytes()).unwrap();
    UnifiedPatch::parse_with_renames(input.as_bytes(), PatchLimits::default(), &|| { calls.set(calls.get() + 1); false }).unwrap();
    for cancel_at in 1..=calls.get() {
        let seen = Cell::new(0);
        assert_eq!(UnifiedPatch::parse_with_renames(input.as_bytes(), PatchLimits::default(), &|| {
            seen.set(seen.get() + 1); seen.get() >= cancel_at
        }), Err(PatchError::Cancelled));
    }
    let patch = parse(input.as_bytes()).unwrap();
    assert_eq!(patch.files()[0].apply(Some((0o100644, b"x")), patch.limits(), &|| true), Err(PatchError::Cancelled));
}
