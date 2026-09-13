use super::*;
use std::cell::Cell;

fn parse(bytes: &[u8]) -> Result<UnifiedPatch<'_>, PatchError> {
    UnifiedPatch::parse(bytes, PatchLimits::default(), &|| false)
}
fn text(hunks: &[u8]) -> Vec<u8> {
    [b"diff --git a/file b/file\n--- a/file\n+++ b/file\n".as_slice(), hunks].concat()
}
fn apply(patch: &[u8], old: &[u8]) -> Result<Vec<u8>, PatchError> {
    let parsed = parse(patch)?;
    Ok(parsed.files()[0].apply(Some((0o100644, old)), parsed.limits(), &|| false)?.unwrap().content)
}

#[test]
fn edits_apply_to_exact_old_and_new_line_coordinates() {
    let patch = text(b"@@ -1,3 +1,4 @@ heading\n a\n-b\n+B\n+extra\n c\n@@ -5 +6 @@\n-e\n+E\n");
    assert_eq!(apply(&patch, b"a\nb\nc\nd\ne\nf\n").unwrap(), b"a\nB\nextra\nc\nd\nE\nf\n");
    assert_eq!(apply(&patch, b"a\nb\nc\nd\ne\nf\n").unwrap(), apply(&patch, b"a\nb\nc\nd\ne\nf\n").unwrap());
    assert!(matches!(apply(&patch, b"a\nwrong\nc\nd\ne\nf\n"), Err(PatchError::ContextMismatch { .. })));
    assert!(matches!(apply(&patch, b"prefix\na\nb\nc\nd\ne\nf\n"), Err(PatchError::ContextMismatch { .. })));
    let wrong_new = text(b"@@ -1,3 +2,4 @@\n a\n-b\n+B\n+extra\n c\n");
    assert!(matches!(apply(&wrong_new, b"a\nb\nc\n"), Err(PatchError::ResultRange { .. })));
}

#[test]
fn zero_length_ranges_insert_at_start_middle_and_end() {
    for (hunk, expected) in [
        (b"@@ -0,0 +1 @@\n+z\n".as_slice(), b"z\na\nb\n".as_slice()),
        (b"@@ -1,0 +2 @@\n+z\n", b"a\nz\nb\n"),
        (b"@@ -2,0 +3 @@\n+z\n", b"a\nb\nz\n"),
    ] { assert_eq!(apply(&text(hunk), b"a\nb\n").unwrap(), expected); }
    assert!(parse(&text(b"@@ -0 +1 @@\n-a\n+b\n")).is_err());
    assert!(parse(&text(b"@@ -0,0 +0,0 @@\n")).is_err());
}

#[test]
fn preserves_crlf_arbitrary_utf8_and_missing_final_newlines() {
    let patch = text(b"@@ -1,2 +1,2 @@\n a\r\n-b\r\n+c\r\n");
    assert_eq!(apply(&patch, b"a\r\nb\r\n").unwrap(), b"a\r\nc\r\n");
    let patch = text(b"@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file\n");
    assert_eq!(apply(&patch, b"old").unwrap(), b"new");
    assert!(apply(&patch, b"old\n").is_err());
    let patch = text(b"@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+new\n");
    assert_eq!(apply(&patch, b"old").unwrap(), b"new\n");
    let patch = text(b"@@ -1 +1 @@\n-old\n+new\n\\ No newline at end of file\n");
    assert_eq!(apply(&patch, b"old\n").unwrap(), b"new");
    let patch = text("@@ -1 +1 @@\n-café\n+🦀\n".as_bytes());
    assert_eq!(apply(&patch, "café\n".as_bytes()).unwrap(), "🦀\n".as_bytes());
}

#[test]
fn missing_newline_cannot_be_used_to_concatenate_logical_lines() {
    let patch = text(b"@@ -0,0 +1,2 @@\n+one\n\\ No newline at end of file\n+two\n");
    assert_eq!(apply(&patch, b""), Err(PatchError::MissingNewlineNotAtEnd));
    let patch = text(b"@@ -0,0 +1 @@\n+one\n\\ No newline at end of file\n");
    assert_eq!(apply(&patch, b"tail\n"), Err(PatchError::MissingNewlineNotAtEnd));
    assert!(parse(&text(b"@@ -0,0 +1 @@\n+\n\\ No newline at end of file\n")).is_err());
    assert!(parse(&text(b"@@ -1 +1 @@\n-a\n+b\n\\ Not the marker\n")).is_err());
}

#[test]
fn creation_deletion_and_executable_modes_enforce_presence() {
    let bytes = b"diff --git a/new b/new\nnew file mode 100755\nindex 0000000..1234567\n--- /dev/null\n+++ b/new\n@@ -0,0 +1,2 @@\n+#!/bin/sh\n+exit 0\n";
    let parsed = parse(bytes).unwrap(); let file = &parsed.files()[0];
    assert_eq!(file.change(), FileChange::Create);
    assert_eq!(file.apply(None, parsed.limits(), &|| false).unwrap(), Some(PatchedFile { mode: 0o100755, content: b"#!/bin/sh\nexit 0\n".to_vec() }));
    assert_eq!(file.apply(Some((0o100644, b"")), parsed.limits(), &|| false), Err(PatchError::SourcePresence));
    let parsed = parse(b"diff --git a/file b/file\ndeleted file mode 100644\n--- a/file\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n").unwrap();
    let file = &parsed.files()[0];
    assert_eq!(file.apply(Some((0o100644, b"old\n")), parsed.limits(), &|| false).unwrap(), None);
    assert_eq!(file.apply(None, parsed.limits(), &|| false), Err(PatchError::SourcePresence));
    assert_eq!(file.apply(Some((0o100755, b"old\n")), parsed.limits(), &|| false), Err(PatchError::SourceMode));
    assert_eq!(file.apply(Some((0o100644, b"old\nuntouched\n")), parsed.limits(), &|| false), Err(PatchError::NonemptyDeletion));
    let parsed = parse(b"diff --git a/file b/file\nold mode 100644\nnew mode 100755\n").unwrap();
    assert_eq!(parsed.files()[0].apply(Some((0o100644, b"binary\0bytes")), parsed.limits(), &|| false).unwrap(), Some(PatchedFile { mode: 0o100755, content: b"binary\0bytes".to_vec() }));
}

#[test]
fn hunkless_empty_file_changes_do_not_drop_unmentioned_source_bytes() {
    let parsed = parse(b"diff --git a/file b/file\nnew file mode 100644\nindex 0000000..e69de29\n").unwrap();
    assert_eq!(parsed.files()[0].apply(None, parsed.limits(), &|| false).unwrap().unwrap().content, b"");
    let parsed = parse(b"diff --git a/file b/file\ndeleted file mode 100644\nindex e69de29..0000000\n").unwrap();
    let file = &parsed.files()[0];
    assert_eq!(file.apply(Some((0o100644, b"")), parsed.limits(), &|| false).unwrap(), None);
    assert_eq!(file.apply(Some((0o100644, b"secret\n")), parsed.limits(), &|| false), Err(PatchError::NonemptyDeletion));
}

#[test]
fn raw_paths_are_decoded_once_and_never_normalized_or_followed() {
    let parsed = parse(b"diff --git \"a/dir/caf\\303\\251\tfile\" \"b/dir/caf\\303\\251\tfile\"\nold mode 100644\nnew mode 100755\n").unwrap();
    assert_eq!(parsed.files()[0].path(), b"dir/caf\xc3\xa9\tfile");
    let parsed = parse(b"diff --git a/file with spaces b/file with spaces\nold mode 100644\nnew mode 100755\n").unwrap();
    assert_eq!(parsed.files()[0].path(), b"file with spaces");
    for path in ["../outside", "/absolute", "a//b", "a/./b", "a/../b", ".git/config", "x/.GiT/config", ""] {
        let patch = format!("diff --git a/{path} b/{path}\nold mode 100644\nnew mode 100755\n");
        assert!(parse(patch.as_bytes()).is_err(), "{path}");
    }
    assert!(parse(b"diff --git \"a/evil\\000path\" \"b/evil\\000path\"\nold mode 100644\nnew mode 100755\n").is_err());
    assert!(parse(b"diff --git \"a/file\\400\" \"b/file\\400\"\nold mode 100644\nnew mode 100755\n").is_err());
}

#[test]
fn duplicate_paths_prefix_collisions_and_renames_are_not_sequential_side_effects() {
    let section = |path| format!("diff --git a/{path} b/{path}\nold mode 100644\nnew mode 100755\n");
    assert_eq!(parse((section("x") + &section("x")).as_bytes()), Err(PatchError::DuplicatePath));
    assert_eq!(parse((section("x/y") + &section("x")).as_bytes()), Err(PatchError::OverlappingPaths));
    // 'a-' sorts between 'a' and 'a/x'; checking adjacent names is insufficient.
    assert_eq!(parse((section("a") + &section("a-") + &section("a/x")).as_bytes()), Err(PatchError::OverlappingPaths));
    assert!(matches!(parse(b"diff --git a/old b/new\nsimilarity index 100%\nrename from old\nrename to new\n"), Err(PatchError::Unsupported { .. })));
    let input = section("z") + &section("a"); let parsed = parse(input.as_bytes()).unwrap();
    assert_eq!(parsed.files().iter().map(FilePatch::path).collect::<Vec<_>>(), vec![b"a".as_slice(), b"z".as_slice()]);
}

#[test]
fn all_unsupported_extended_formats_and_inconsistent_headers_refuse() {
    for patch in [
        b"diff --git a/file b/file\nGIT binary patch\nliteral 1\nx\n".as_slice(),
        b"diff --git a/file b/file\nnew file mode 120000\n",
        b"diff --git a/file b/file\nold mode 160000\nnew mode 100644\n",
        b"diff --git a/file b/file\nindex 1234567..abcdef0 120000\n",
        b"diff --git a/file b/file\nold mode 100644\n",
        b"diff --git a/file b/file\n--- a/other\n+++ b/file\n@@ -1 +1 @@\n-a\n+b\n",
        b"diff --git a/file b/file\nnew file mode 100644\n--- a/file\n+++ b/file\n@@ -1 +1 @@\n-a\n+b\n",
        b"diff --git a/file b/file\nold mode 100644\nnew mode 100755\nindex 1234567..abcdef0 100644\n",
        b"diff --git a/file b/file\nindex 1234567..abcdef0\nindex 1234567..abcdef0\n",
        b"diff --git a/file b/file\n--- a/file\n+++ b/file\n@@@ -1 +1 @@@\n-a\n+b\n",
    ] { assert!(parse(patch).is_err(), "{}", String::from_utf8_lossy(patch)); }
}

#[test]
fn malformed_hunk_ranges_never_trigger_unbounded_allocation() {
    for hunk in [
        b"@@ -184467440737095516160,1 +1 @@\n-a\n+b\n".as_slice(),
        b"@@ -1,999999999 +1 @@\n-a\n+b\n",
        b"@@ -1,2 +1 @@\n-a\n+b\n",
        b"@@ -1 +1 @@\n-a\n+b", // truncated record, not an implicit no-newline marker
        b"@@ -1 +1 @@\n-a\n+b\n+extra\n",
        b"@@ -1 +1 @@\n?a\n+b\n",
    ] { assert!(parse(&text(hunk)).is_err()); }
    assert!(matches!(apply(&text(b"@@ -3 +3 @@\n-a\n+b\n"), b"a\n"), Err(PatchError::SourceRange { .. })));
    let backwards = text(b"@@ -2 +2 @@\n-b\n+B\n@@ -1 +1 @@\n-a\n+A\n");
    assert!(matches!(apply(&backwards, b"a\nb\n"), Err(PatchError::SourceRange { .. })));
}

#[test]
fn each_parser_resource_limit_has_a_permitted_boundary_twin() {
    let input = text(b"@@ -1 +1 @@\n-a\n+b\n"); let defaults = PatchLimits::default();
    let at = PatchLimits { max_patch_bytes: input.len(), ..defaults };
    assert!(UnifiedPatch::parse(&input, at, &|| false).is_ok());
    assert!(matches!(UnifiedPatch::parse(&input, PatchLimits { max_patch_bytes: input.len() - 1, ..defaults }, &|| false), Err(PatchError::Budget(_))));
    let lines = input.split_inclusive(|b| *b == b'\n').count();
    assert!(UnifiedPatch::parse(&input, PatchLimits { max_lines: lines, ..defaults }, &|| false).is_ok());
    assert!(matches!(UnifiedPatch::parse(&input, PatchLimits { max_lines: lines - 1, ..defaults }, &|| false), Err(PatchError::Budget(_))));
    assert!(UnifiedPatch::parse(&input, PatchLimits { max_path_bytes: 4, ..defaults }, &|| false).is_ok());
    assert!(UnifiedPatch::parse(&input, PatchLimits { max_path_bytes: 3, ..defaults }, &|| false).is_err());
    let two = [input.as_slice(), b"diff --git a/other b/other\nold mode 100644\nnew mode 100755\n"].concat();
    assert!(UnifiedPatch::parse(&two, PatchLimits { max_files: 2, ..defaults }, &|| false).is_ok());
    assert_eq!(UnifiedPatch::parse(&two, PatchLimits { max_files: 1, ..defaults }, &|| false), Err(PatchError::Budget("patch files")));
    let two = text(b"@@ -1 +1 @@\n-a\n+A\n@@ -3 +3 @@\n-c\n+C\n");
    assert!(UnifiedPatch::parse(&two, PatchLimits { max_hunks: 2, ..defaults }, &|| false).is_ok());
    assert_eq!(UnifiedPatch::parse(&two, PatchLimits { max_hunks: 1, ..defaults }, &|| false), Err(PatchError::Budget("patch hunks")));
    assert!(UnifiedPatch::parse(&input, PatchLimits { max_files: 0, ..defaults }, &|| false).is_err());
}

#[test]
fn application_bounds_source_output_and_cancellation() {
    let input = text(b"@@ -1 +1 @@\n-a\n+longer\n"); let patch = parse(&input).unwrap(); let file = &patch.files()[0];
    assert_eq!(file.apply(Some((0o100644, b"a\n")), PatchLimits { max_file_bytes: 7, ..patch.limits() }, &|| false).unwrap().unwrap().content, b"longer\n");
    assert!(matches!(file.apply(Some((0o100644, b"a\n")), PatchLimits { max_file_bytes: 6, ..patch.limits() }, &|| false), Err(PatchError::Budget(_))));
    assert!(matches!(file.apply(Some((0o100644, b"a\n")), PatchLimits { max_file_bytes: 1, ..patch.limits() }, &|| false), Err(PatchError::Budget(_))));
    assert_eq!(UnifiedPatch::parse(&input, patch.limits(), &|| true), Err(PatchError::Cancelled));
    assert_eq!(file.apply(Some((0o100644, b"a\n")), patch.limits(), &|| true), Err(PatchError::Cancelled));
    let calls = Cell::new(0usize);
    file.apply(Some((0o100644, b"a\n")), patch.limits(), &|| { calls.set(calls.get() + 1); false }).unwrap();
    for cutoff in 0..calls.get() {
        let at = Cell::new(0);
        assert_eq!(file.apply(Some((0o100644, b"a\n")), patch.limits(), &|| { let n = at.get(); at.set(n + 1); n >= cutoff }), Err(PatchError::Cancelled));
    }
}

#[test]
fn identity_expectations_bind_prefixes_and_absent_sides_without_guessing_hash_domains() {
    assert!(IndexExpectation::matches(b"0000000", None));
    assert!(!IndexExpectation::matches(b"1234567", None));
    assert!(IndexExpectation::matches(b"abcdef0", Some(b"abcdef0123456789")));
    assert!(!IndexExpectation::matches(b"abcdef0", Some(b"abcdef1123456789")));
    assert!(!IndexExpectation::matches(b"abcdef01234567890", Some(b"abcdef0123456789")));
}

#[test]
fn exhaustive_small_sequences_replay_independently_constructed_whole_file_hunks() {
    fn lines(mut n: usize, length: usize, newline: bool) -> Vec<u8> {
        let mut result = Vec::new();
        for index in 0..length {
            result.push(b'a' + (n % 3) as u8); n /= 3;
            if index + 1 < length || newline { result.push(b'\n'); }
        }
        result
    }
    fn record(out: &mut Vec<u8>, prefix: u8, bytes: &[u8]) {
        for line in bytes.split_inclusive(|b| *b == b'\n') {
            out.push(prefix); out.extend_from_slice(line);
            if !line.ends_with(b"\n") { out.extend_from_slice(b"\n\\ No newline at end of file\n"); }
        }
    }
    let mut cases = 0;
    for old_n in 0..4u32 { for new_n in 0..4u32 {
        if old_n + new_n == 0 { continue; }
        for old_id in 0..3usize.pow(old_n) { for new_id in 0..3usize.pow(new_n) {
            for old_lf in [false, true] { for new_lf in [false, true] {
                let old = lines(old_id, old_n as usize, old_lf); let new = lines(new_id, new_n as usize, new_lf);
                let mut hunk = format!("@@ -{},{} +{},{} @@\n", usize::from(old_n != 0), old_n, usize::from(new_n != 0), new_n).into_bytes();
                record(&mut hunk, b'-', &old); record(&mut hunk, b'+', &new);
                assert_eq!(apply(&text(&hunk), &old).unwrap(), new); cases += 1;
            }}
        }}
    }}
    assert_eq!(cases, 6396);
}

#[test]
fn application_cannot_reuse_a_parsed_patch_to_bypass_narrower_limits() {
    let bytes = text(b"@@ -0,0 +1,2 @@\n+first\n+second\n");
    let parsed = parse(&bytes).unwrap();
    let limits = PatchLimits { max_lines: 3, ..parsed.limits() };
    assert_eq!(parsed.files()[0].apply(Some((0o100644, b"tail\n")), limits, &|| false)
        .unwrap().unwrap().content, b"first\nsecond\ntail\n");
    assert!(matches!(parsed.files()[0].apply(Some((0o100644, b"tail\nextra\n")), limits,
        &|| false), Err(PatchError::Budget("result lines"))));
    let bytes = text(b"@@ -1 +1 @@\n-a\n+A\n@@ -3 +3 @@\n-c\n+C\n");
    let parsed = parse(&bytes).unwrap();
    assert!(matches!(parsed.files()[0].apply(Some((0o100644, b"a\nb\nc\n")),
        PatchLimits { max_hunks: 1, ..parsed.limits() }, &|| false), Err(PatchError::Budget("patch hunks"))));
}
