//! The explicit gitlink grammar carries a commit pointer as one virtual line.
//! No blob is read, hashed, traversed, or created by this structural adapter.

use super::{FileChange, FilePatch, IndexExpectation, Line, PatchError, syntax};

fn full_index(
    index: Option<&IndexExpectation>,
    change: FileChange,
    at: usize,
) -> Result<&IndexExpectation, PatchError> {
    let index = index.ok_or_else(|| syntax(at, "gitlink requires full index identities"))?;
    if !matches!(index.old.len(), 40 | 64) || index.old.len() != index.new.len() {
        return Err(syntax(
            at,
            "gitlink index identities must share a full hash width",
        ));
    }
    let old_absent = index.old.iter().all(|byte| *byte == b'0');
    let new_absent = index.new.iter().all(|byte| *byte == b'0');
    if old_absent != (change == FileChange::Create) || new_absent != (change == FileChange::Delete)
    {
        return Err(PatchError::SourcePresence);
    }
    Ok(index)
}

fn image_matches(bytes: &[u8], id: &[u8]) -> bool {
    bytes
        .strip_prefix(b"Subproject commit ")
        .and_then(|body| body.strip_suffix(b"\n"))
        == Some(id)
}

fn line_matches(line: &Line<'_>, kind: u8, id: &[u8]) -> bool {
    line.kind == kind && !line.no_newline && image_matches(line.bytes, id)
}

/// Validate only declared gitlinks, after common path/mode/header validation.
/// Full width is structural here; the caller must bind the repository domain.
pub(super) fn check(file: &FilePatch<'_>, records: &[&[u8]], at: usize) -> Result<(), PatchError> {
    let expected_modes = match file.change {
        FileChange::Create => (None, Some(0o160000)),
        FileChange::Modify => (Some(0o160000), Some(0o160000)),
        FileChange::Delete => (Some(0o160000), None),
    };
    if (file.old_mode, file.new_mode) != expected_modes {
        return Err(PatchError::Unsupported {
            line: at + 1,
            feature: "gitlink entry type conversion",
        });
    }
    if file.renamed_from.is_some() || file.binary.is_some() {
        return Err(PatchError::Unsupported {
            line: at + 1,
            feature: "gitlink rename or binary patch",
        });
    }
    let index = full_index(file.index.as_ref(), file.change, at)?;
    // Stock Git's full-index pointer add, update and delete each have exactly
    // seven records. Requiring their complete shape rejects context trailers,
    // partial images, missing-newline markers and reordered metadata.
    if records.len() != 7 {
        return Err(syntax(
            at,
            "gitlink requires one canonical whole-image hunk",
        ));
    }
    let (hunk_at, hunk_header, metadata_matches) = match file.change {
        FileChange::Create => (
            5,
            b"@@ -0,0 +1 @@\n".as_slice(),
            records[1] == b"new file mode 160000\n" && records[2].starts_with(b"index "),
        ),
        FileChange::Modify => (
            4,
            b"@@ -1 +1 @@\n".as_slice(),
            records[1].starts_with(b"index "),
        ),
        FileChange::Delete => (
            5,
            b"@@ -1 +0,0 @@\n".as_slice(),
            records[1] == b"deleted file mode 160000\n" && records[2].starts_with(b"index "),
        ),
    };
    if !metadata_matches
        || !records[hunk_at - 2].starts_with(b"--- ")
        || !records[hunk_at - 1].starts_with(b"+++ ")
        || records[hunk_at] != hunk_header
    {
        return Err(syntax(at, "noncanonical gitlink headers"));
    }
    let [hunk] = file.hunks.as_slice() else {
        return Err(syntax(
            at,
            "gitlink requires one canonical whole-image hunk",
        ));
    };
    let images_match = match (file.change, hunk.lines.as_slice()) {
        (FileChange::Create, [new]) => line_matches(new, b'+', &index.new),
        (FileChange::Modify, [old, new]) => {
            line_matches(old, b'-', &index.old) && line_matches(new, b'+', &index.new)
        }
        (FileChange::Delete, [old]) => line_matches(old, b'-', &index.old),
        _ => false,
    };
    if !images_match {
        return Err(syntax(
            at,
            "gitlink images must exactly match full index identities",
        ));
    }
    Ok(())
}

/// A hunk must consume the entire synthetic source, not just its first line.
pub(super) fn check_source(file: &FilePatch<'_>, body: &[u8]) -> Result<(), PatchError> {
    let index = full_index(file.index.as_ref(), file.change, 0)?;
    if !image_matches(body, &index.old) {
        return Err(PatchError::ContextMismatch {
            hunk: 0,
            source_line: 0,
        });
    }
    Ok(())
}
