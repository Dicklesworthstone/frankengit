//! Literal byte hunks are not Git's compressed `GIT binary patch` format.
//! These tests pin existing native semantics consumed by binary-safe editors.
//! No Git subprocess, filesystem checkout, or external decoder runs here.
use fgit_diff::patch::{FileChange, PatchError, PatchLimits, UnifiedPatch};

/// Line count: every newline-terminated line plus an unterminated tail.
fn count(bytes: &[u8]) -> usize {
    bytes.split_inclusive(|byte| *byte == b'\n').count()
}
fn literal(before: Option<&[u8]>, after: Option<&[u8]>) -> Vec<u8> {
    let mut out = b"diff --git a/asset.bin b/asset.bin\n".to_vec();
    if before.is_none() {
        out.extend_from_slice(b"new file mode 100644\n");
    }
    if after.is_none() {
        out.extend_from_slice(b"deleted file mode 100644\n");
    }
    let old = before.unwrap_or_default();
    let new = after.unwrap_or_default();
    if old.is_empty() && new.is_empty() {
        return out;
    }
    out.extend_from_slice(if before.is_some() {
        b"--- a/asset.bin\n"
    } else {
        b"--- /dev/null\n"
    });
    out.extend_from_slice(if after.is_some() {
        b"+++ b/asset.bin\n"
    } else {
        b"+++ /dev/null\n"
    });
    let (a, b) = (count(old), count(new));
    out.extend_from_slice(
        format!(
            "@@ -{},{} +{},{} @@\n",
            usize::from(a != 0),
            a,
            usize::from(b != 0),
            b
        )
        .as_bytes(),
    );
    for (prefix, bytes) in [(b'-', old), (b'+', new)] {
        for line in bytes.split_inclusive(|byte| *byte == b'\n') {
            out.push(prefix);
            out.extend_from_slice(line);
            if line.last() != Some(&b'\n') {
                out.extend_from_slice(b"\n\\ No newline at end of file\n");
            }
        }
    }
    out
}
fn apply(before: Option<&[u8]>, after: Option<&[u8]>) {
    let input = literal(before, after);
    let limits = PatchLimits::default();
    let patch = UnifiedPatch::parse(&input, limits, &|| false).unwrap();
    assert_eq!(patch.files().len(), 1);
    let result = patch.files()[0]
        .apply(before.map(|body| (0o100644, body)), limits, &|| false)
        .unwrap();
    assert_eq!(result.as_ref().map(|file| file.content.as_slice()), after);
    if let Some(file) = result {
        assert_eq!(file.mode, 0o100644);
    }
}

#[test]
fn hand_written_nul_hunks_keep_non_utf8_crlf_and_final_newline_state() {
    let input = b"diff --git a/asset.bin b/asset.bin\n--- a/asset.bin\n+++ b/asset.bin\n@@ -1,2 +1,2 @@\n-\0old\xff\r\n-\0tail\n\\ No newline at end of file\n+\0new\xfe\r\n+\0end\n\\ No newline at end of file\n";
    let limits = PatchLimits::default();
    let patch = UnifiedPatch::parse(input, limits, &|| false).unwrap();
    let result = patch.files()[0]
        .apply(Some((0o100644, b"\0old\xff\r\n\0tail")), limits, &|| false)
        .unwrap()
        .unwrap();
    assert_eq!(result.content, b"\0new\xfe\r\n\0end");
}
#[test]
fn every_byte_value_survives_creation_replacement_deletion_and_reversal() {
    let original: Vec<u8> = (0..=255).collect();
    let changed: Vec<u8> = original.iter().rev().copied().collect();
    for (before, after) in [
        (None, Some(original.as_slice())),
        (Some(original.as_slice()), None),
        (Some(original.as_slice()), Some(changed.as_slice())),
        (Some(changed.as_slice()), Some(original.as_slice())),
    ] {
        apply(before, after);
    }
}
#[test]
fn an_empty_file_is_not_absent_and_zero_bytes_are_not_empty() {
    for bytes in [b"\0".as_slice(), b"\0\0\0", b"\0\n\0", b"\xff\0\n"] {
        apply(None, Some(bytes));
        apply(Some(bytes), None);
        apply(Some(b""), Some(bytes));
        apply(Some(bytes), Some(b""));
    }
    let bytes = literal(None, Some(b"\0"));
    let patch = UnifiedPatch::parse(&bytes, PatchLimits::default(), &|| false).unwrap();
    assert_eq!(patch.files()[0].change(), FileChange::Create);
    assert_eq!(
        patch.files()[0].apply(Some((0o100644, b"")), patch.limits(), &|| false),
        Err(PatchError::SourcePresence)
    );
}
#[test]
fn binary_context_is_compared_after_nul_without_c_string_truncation() {
    let input = literal(Some(b"same\0before\xff"), Some(b"same\0after\xfe"));
    let patch = UnifiedPatch::parse(&input, PatchLimits::default(), &|| false).unwrap();
    assert!(matches!(
        patch.files()[0].apply(
            Some((0o100644, b"same\0changed\xff")),
            patch.limits(),
            &|| false
        ),
        Err(PatchError::ContextMismatch { .. })
    ));
}
#[test]
fn mode_only_changes_preserve_all_original_binary_bytes() {
    let input = b"diff --git a/asset.bin b/asset.bin\nold mode 100644\nnew mode 100755\n";
    let patch = UnifiedPatch::parse(input, PatchLimits::default(), &|| false).unwrap();
    let bytes = b"\0\xff\r\n\0";
    let result = patch.files()[0]
        .apply(Some((0o100644, bytes)), patch.limits(), &|| false)
        .unwrap()
        .unwrap();
    assert_eq!(result.content, bytes);
    assert_eq!(result.mode, 0o100755);
    assert_eq!(
        patch.files()[0].apply(Some((0o100755, bytes)), patch.limits(), &|| false),
        Err(PatchError::SourceMode)
    );
}
#[test]
fn binary_data_does_not_escape_hunks_into_control_records() {
    let bytes = b"\0\ndiff --git a/other b/other\n@@ -1 +1 @@\n\\ No newline at end of file\n--- /dev/null\n+++ b/other\n\xff";
    apply(None, Some(bytes));
    apply(Some(bytes), None);
}
#[test]
fn binary_work_preserves_cancellation_and_byte_and_line_ceilings() {
    let input = literal(Some(b"a\0b"), Some(b"c\0d\0e"));
    let limits = PatchLimits::default();
    assert_eq!(
        UnifiedPatch::parse(&input, limits, &|| true),
        Err(PatchError::Cancelled)
    );
    let patch = UnifiedPatch::parse(&input, limits, &|| false).unwrap();
    assert_eq!(
        patch.files()[0].apply(Some((0o100644, b"a\0b")), limits, &|| true),
        Err(PatchError::Cancelled)
    );
    let small = PatchLimits {
        max_file_bytes: 4,
        ..limits
    };
    assert!(matches!(
        patch.files()[0].apply(Some((0o100644, b"a\0b")), small, &|| false),
        Err(PatchError::Budget(_))
    ));
    let input = literal(None, Some(b"\0\n\0\n\0\n"));
    assert!(matches!(
        UnifiedPatch::parse(
            &input,
            PatchLimits {
                max_lines: 2,
                ..limits
            },
            &|| false
        ),
        Err(PatchError::Budget(_))
    ));
}
#[test]
fn binary_content_does_not_widen_paths_modes_or_compressed_patch_support() {
    for input in [
        b"diff --git a/x\0y b/x\0y\nnew file mode 100644\n".as_slice(),
        b"diff --git a/x b/x\nnew file mode 120000\n",
        b"diff --git a/x b/x\nGIT binary patch\nliteral 1\nA00000\n\n",
    ] {
        assert!(UnifiedPatch::parse(input, PatchLimits::default(), &|| false).is_err());
    }
}
