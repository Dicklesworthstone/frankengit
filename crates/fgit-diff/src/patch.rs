//! Exact, bounded Git unified patches. No fuzzy matching, filesystem effects,
//! external drivers, rename guessing, or publication authority.
//!
//! The supported profile is ordinary `git diff` for regular files, including
//! creation, deletion, executable-bit changes, quoted raw paths and missing
//! final newlines. Binary patches, symlinks, gitlinks, copies and renames refuse.
//! `index` names are parsed and exposed as optional identity expectations;
//! callers with an object store must check them against verified native IDs.

use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PatchLimits {
    pub max_patch_bytes: usize,
    pub max_files: usize,
    pub max_hunks: usize,
    pub max_lines: usize,
    pub max_path_bytes: usize,
    pub max_file_bytes: usize,
    pub max_output_bytes: usize,
}
impl Default for PatchLimits {
    fn default() -> Self {
        Self { max_patch_bytes: 16 * 1024 * 1024, max_files: 1024, max_hunks: 4096,
            max_lines: 262_144, max_path_bytes: 4096, max_file_bytes: 8 * 1024 * 1024,
            max_output_bytes: 32 * 1024 * 1024 }
    }
}
impl PatchLimits {
    pub fn validate(self) -> Result<(), PatchError> {
        let ceiling = Self::default();
        for (value, maximum) in [(self.max_patch_bytes, ceiling.max_patch_bytes),
            (self.max_files, ceiling.max_files), (self.max_hunks, ceiling.max_hunks),
            (self.max_lines, ceiling.max_lines), (self.max_path_bytes, ceiling.max_path_bytes),
            (self.max_file_bytes, ceiling.max_file_bytes), (self.max_output_bytes, ceiling.max_output_bytes)] {
            if value == 0 || value > maximum { return Err(PatchError::InvalidLimits); }
        }
        Ok(())
    }
}

/// Refusals do not include source bytes or undisclosed repository paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PatchError {
    InvalidLimits,
    Cancelled,
    Budget(&'static str),
    Syntax { line: usize, reason: &'static str },
    Unsupported { line: usize, feature: &'static str },
    InvalidPath,
    DuplicatePath,
    OverlappingPaths,
    SourcePresence,
    SourceMode,
    SourceRange { hunk: usize },
    ContextMismatch { hunk: usize, source_line: usize },
    ResultRange { hunk: usize },
    MissingNewlineNotAtEnd,
    NonemptyDeletion,
}
impl std::fmt::Display for PatchError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "exact unified patch refused: {self:?}")
    }
}
impl std::error::Error for PatchError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileChange { Create, Modify, Delete }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexExpectation {
    pub old: Vec<u8>,
    pub new: Vec<u8>,
}
impl IndexExpectation {
    /// The all-zero name is Git's absent-side sentinel, not an object ID.
    pub fn matches(prefix: &[u8], id: Option<&[u8]>) -> bool {
        match id {
            None => prefix.iter().all(|byte| *byte == b'0'),
            Some(id) => prefix.len() <= id.len() && id.starts_with(prefix),
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PatchedFile { pub mode: u32, pub content: Vec<u8> }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnifiedPatch<'a> { files: Vec<FilePatch<'a>>, limits: PatchLimits }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilePatch<'a> {
    path: Vec<u8>,
    change: FileChange,
    old_mode: Option<u32>,
    new_mode: Option<u32>,
    index: Option<IndexExpectation>,
    hunks: Vec<Hunk<'a>>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Hunk<'a> { old: usize, old_count: usize, new: usize, new_count: usize, lines: Vec<Line<'a>> }
#[derive(Clone, Debug, Eq, PartialEq)]
struct Line<'a> { kind: u8, bytes: &'a [u8], no_newline: bool }

fn syntax(line: usize, reason: &'static str) -> PatchError { PatchError::Syntax { line: line + 1, reason } }
fn checkpoint(cancelled: &dyn Fn() -> bool) -> Result<(), PatchError> {
    if cancelled() { Err(PatchError::Cancelled) } else { Ok(()) }
}
fn metadata(line: &[u8], at: usize) -> Result<&[u8], PatchError> {
    line.strip_suffix(b"\n").ok_or_else(|| syntax(at, "unterminated patch record"))
}
fn number(bytes: &[u8], at: usize) -> Result<usize, PatchError> {
    if bytes.is_empty() || bytes.iter().any(|byte| !byte.is_ascii_digit()) {
        return Err(syntax(at, "invalid decimal range"));
    }
    bytes.iter().try_fold(0usize, |n, byte| n.checked_mul(10)
        .and_then(|n| n.checked_add(usize::from(*byte - b'0')))
        .ok_or_else(|| syntax(at, "range overflow")))
}
fn mode(bytes: &[u8], at: usize) -> Result<u32, PatchError> {
    match bytes {
        b"100644" => Ok(0o100644), b"100755" => Ok(0o100755),
        _ => Err(PatchError::Unsupported { line: at + 1, feature: "non-regular file mode" }),
    }
}
fn set<T>(slot: &mut Option<T>, value: T, at: usize) -> Result<(), PatchError> {
    if slot.is_some() { return Err(syntax(at, "duplicate metadata")); }
    *slot = Some(value); Ok(())
}
fn range(bytes: &[u8], at: usize, limit: usize) -> Result<(usize, usize), PatchError> {
    let mut parts = bytes.split(|byte| *byte == b',');
    let start = number(parts.next().unwrap_or_default(), at)?;
    let count = parts.next().map_or(Ok(1), |part| number(part, at))?;
    if parts.next().is_some() || (count != 0 && start == 0) { return Err(syntax(at, "invalid hunk range")); }
    let offset = if count == 0 { start } else { start - 1 };
    if offset.checked_add(count).is_none_or(|end| end > limit) { return Err(PatchError::Budget("hunk range")); }
    Ok((offset, count))
}
fn unquote(bytes: &[u8], at: usize) -> Result<(Vec<u8>, usize), PatchError> {
    if bytes.first() != Some(&b'"') { return Err(syntax(at, "expected quoted path")); }
    let mut out = Vec::new(); let mut pos = 1;
    while let Some(&byte) = bytes.get(pos) {
        pos += 1;
        match byte {
            b'"' => return Ok((out, pos)),
            b'\\' => {
                let escaped = *bytes.get(pos).ok_or_else(|| syntax(at, "truncated path escape"))?;
                pos += 1;
                let value = match escaped {
                    b'"' | b'\\' => escaped,
                    b'a' => 7, b'b' => 8, b't' => 9, b'n' => 10, b'v' => 11, b'f' => 12, b'r' => 13,
                    b'0'..=b'3' => {
                        let digits = bytes.get(pos..pos + 2).ok_or_else(|| syntax(at, "truncated octal path"))?;
                        if digits.iter().any(|byte| !(b'0'..=b'7').contains(byte)) { return Err(syntax(at, "invalid octal path")); }
                        pos += 2; (escaped - b'0') * 64 + (digits[0] - b'0') * 8 + digits[1] - b'0'
                    }
                    _ => return Err(syntax(at, "unsupported path escape")),
                };
                out.push(value);
            }
            _ => out.push(byte),
        }
    }
    Err(syntax(at, "unterminated quoted path"))
}
fn check_path(bytes: &[u8], limit: usize) -> Result<(), PatchError> {
    if bytes.is_empty() || bytes.len() > limit || bytes.contains(&0)
        || bytes.split(|byte| *byte == b'/').count() > 64
        || bytes.split(|byte| *byte == b'/').any(|part| part.is_empty() || part == b"." || part == b".." || part.eq_ignore_ascii_case(b".git")) {
        return Err(PatchError::InvalidPath);
    }
    Ok(())
}
fn strip_path(bytes: &[u8], prefix: &[u8], limit: usize) -> Result<Vec<u8>, PatchError> {
    let bytes = bytes.strip_prefix(prefix).ok_or(PatchError::InvalidPath)?;
    check_path(bytes, limit)?; Ok(bytes.to_vec())
}
fn diff_paths(bytes: &[u8], at: usize, limit: usize) -> Result<Vec<u8>, PatchError> {
    if bytes.len() > limit.saturating_mul(8).saturating_add(16) { return Err(PatchError::Budget("path metadata")); }
    let (left, right) = if bytes.first() == Some(&b'"') {
        let (left, used) = unquote(bytes, at)?;
        let rest = bytes.get(used..).and_then(|rest| rest.strip_prefix(b" ")).ok_or_else(|| syntax(at, "missing second diff path"))?;
        let right = if rest.first() == Some(&b'"') {
            let (right, used) = unquote(rest, at)?;
            if used != rest.len() { return Err(syntax(at, "trailing diff path bytes")); } right
        } else { rest.to_vec() };
        (left, right)
    } else {
        // Git leaves ordinary spaces unquoted. Require a unique b/ boundary;
        // ambiguous headers refuse instead of guessing a destination.
        let boundaries = bytes.windows(3).enumerate().filter(|(_, part)| *part == b" b/").map(|(i, _)| i).collect::<Vec<_>>();
        if boundaries.len() != 1 { return Err(syntax(at, "ambiguous diff paths")); }
        let split = boundaries[0]; (bytes[..split].to_vec(), bytes[split + 1..].to_vec())
    };
    let left = strip_path(&left, b"a/", limit)?;
    let right = strip_path(&right, b"b/", limit)?;
    if left != right { return Err(PatchError::Unsupported { line: at + 1, feature: "rename or copy" }); }
    Ok(left)
}
fn file_path(bytes: &[u8], prefix: &[u8], at: usize, limit: usize) -> Result<Option<Vec<u8>>, PatchError> {
    if bytes.len() > limit.saturating_mul(4).saturating_add(16) { return Err(PatchError::Budget("path metadata")); }
    if bytes == b"/dev/null" { return Ok(None); }
    let decoded = if bytes.first() == Some(&b'"') {
        let (decoded, used) = unquote(bytes, at)?;
        if used != bytes.len() { return Err(syntax(at, "trailing file header bytes")); } decoded
    } else { bytes.to_vec() };
    strip_path(&decoded, prefix, limit).map(Some)
}
fn index(bytes: &[u8], at: usize) -> Result<(IndexExpectation, Option<u32>), PatchError> {
    let mut parts = bytes.split(|byte| *byte == b' ');
    let names = parts.next().unwrap_or_default();
    let mode = parts.next().map(|part| mode(part, at)).transpose()?;
    if parts.next().is_some() { return Err(syntax(at, "trailing index metadata")); }
    let split = names.windows(2).position(|part| part == b"..").ok_or_else(|| syntax(at, "invalid index names"))?;
    let old = &names[..split]; let new = &names[split + 2..];
    for name in [old, new] {
        if !(4..=64).contains(&name.len()) || name.iter().any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(byte)) {
            return Err(syntax(at, "invalid lowercase index prefix"));
        }
    }
    Ok((IndexExpectation { old: old.to_vec(), new: new.to_vec() }, mode))
}

impl<'a> UnifiedPatch<'a> {
    pub fn parse(input: &'a [u8], limits: PatchLimits, cancelled: &dyn Fn() -> bool) -> Result<Self, PatchError> {
        limits.validate()?; checkpoint(cancelled)?;
        if input.len() > limits.max_patch_bytes { return Err(PatchError::Budget("patch bytes")); }
        let mut records = Vec::new();
        for line in input.split_inclusive(|byte| *byte == b'\n') {
            checkpoint(cancelled)?;
            if records.len() == limits.max_lines { return Err(PatchError::Budget("patch lines")); }
            records.push(line);
        }
        if records.is_empty() { return Err(syntax(0, "empty patch")); }
        let mut files = Vec::new(); let mut pos = 0; let mut hunk_count = 0;
        while pos < records.len() {
            checkpoint(cancelled)?;
            if files.len() == limits.max_files { return Err(PatchError::Budget("patch files")); }
            let first = metadata(records[pos], pos)?;
            let paths = first.strip_prefix(b"diff --git ").ok_or_else(|| syntax(pos, "expected diff --git"))?;
            let path = diff_paths(paths, pos, limits.max_path_bytes)?;
            let mut file = FilePatch { path, change: FileChange::Modify, old_mode: None, new_mode: None, index: None, hunks: Vec::new() };
            let (mut kind, mut index_mode, mut headers) = (None, None, false);
            pos += 1;
            while pos < records.len() && !records[pos].starts_with(b"diff --git ") {
                checkpoint(cancelled)?;
                let text = metadata(records[pos], pos)?;
                if text.starts_with(b"@@ ") {
                    if !headers { return Err(syntax(pos, "hunk before file headers")); }
                    if hunk_count == limits.max_hunks { return Err(PatchError::Budget("patch hunks")); }
                    hunk_count += 1;
                    let mut parts = text.splitn(5, |byte| *byte == b' ');
                    if parts.next() != Some(b"@@".as_slice()) { return Err(syntax(pos, "invalid hunk header")); }
                    let old = parts.next().and_then(|part| part.strip_prefix(b"-")).ok_or_else(|| syntax(pos, "missing old range"))?;
                    let new = parts.next().and_then(|part| part.strip_prefix(b"+")).ok_or_else(|| syntax(pos, "missing new range"))?;
                    if parts.next() != Some(b"@@".as_slice()) { return Err(syntax(pos, "invalid hunk trailer")); }
                    let (old, old_count) = range(old, pos, limits.max_lines)?;
                    let (new, new_count) = range(new, pos, limits.max_lines)?;
                    if old_count == 0 && new_count == 0 { return Err(syntax(pos, "empty hunk")); }
                    let mut hunk = Hunk { old, old_count, new, new_count, lines: Vec::new() };
                    let (mut removed, mut added) = (0, 0); pos += 1;
                    while removed < old_count || added < new_count {
                        checkpoint(cancelled)?;
                        let line = *records.get(pos).ok_or_else(|| syntax(pos, "truncated hunk"))?;
                        let tag = *line.first().ok_or_else(|| syntax(pos, "empty hunk record"))?;
                        if !matches!(tag, b' ' | b'-' | b'+') { return Err(syntax(pos, "invalid hunk record")); }
                        metadata(line, pos)?;
                        removed += usize::from(tag != b'+'); added += usize::from(tag != b'-');
                        if removed > old_count || added > new_count { return Err(syntax(pos, "hunk counts disagree")); }
                        let mut line = Line { kind: tag, bytes: &line[1..], no_newline: false };
                        pos += 1;
                        if records.get(pos).is_some_and(|line| line.starts_with(b"\\")) {
                            if metadata(records[pos], pos)? != b"\\ No newline at end of file" { return Err(syntax(pos, "invalid missing-newline marker")); }
                            line.bytes = line.bytes.strip_suffix(b"\n").ok_or_else(|| syntax(pos, "missing line terminator"))?;
                            if line.bytes.is_empty() { return Err(syntax(pos, "zero-byte logical line")); }
                            line.no_newline = true; pos += 1;
                        }
                        hunk.lines.push(line);
                    }
                    file.hunks.push(hunk); continue;
                }
                if !file.hunks.is_empty() { return Err(syntax(pos, "metadata after hunk")); }
                if let Some(value) = text.strip_prefix(b"--- ") {
                    if headers { return Err(syntax(pos, "duplicate file headers")); }
                    let old = file_path(value, b"a/", pos, limits.max_path_bytes)?;
                    pos += 1;
                    let next = *records.get(pos).ok_or_else(|| syntax(pos, "missing new-file header"))?;
                    let value = metadata(next, pos)?.strip_prefix(b"+++ ").ok_or_else(|| syntax(pos, "missing new-file header"))?;
                    let new = file_path(value, b"b/", pos, limits.max_path_bytes)?;
                    let change = match (&old, &new) {
                        (None, Some(_)) => FileChange::Create, (Some(_), None) => FileChange::Delete,
                        (Some(_), Some(_)) => FileChange::Modify, _ => return Err(syntax(pos, "two absent file sides")),
                    };
                    if old.iter().chain(new.iter()).any(|path| path != &file.path) { return Err(syntax(pos, "file paths disagree")); }
                    if kind.is_some_and(|kind| kind != change) { return Err(syntax(pos, "file presence metadata disagrees")); }
                    kind = Some(change); headers = true;
                } else if headers {
                    return Err(syntax(pos, "expected hunk after file headers"));
                } else if let Some(value) = text.strip_prefix(b"new file mode ") {
                    set(&mut kind, FileChange::Create, pos)?; set(&mut file.new_mode, mode(value, pos)?, pos)?;
                } else if let Some(value) = text.strip_prefix(b"deleted file mode ") {
                    set(&mut kind, FileChange::Delete, pos)?; set(&mut file.old_mode, mode(value, pos)?, pos)?;
                } else if let Some(value) = text.strip_prefix(b"old mode ") {
                    set(&mut file.old_mode, mode(value, pos)?, pos)?;
                } else if let Some(value) = text.strip_prefix(b"new mode ") {
                    set(&mut file.new_mode, mode(value, pos)?, pos)?;
                } else if let Some(value) = text.strip_prefix(b"index ") {
                    let (names, mode) = index(value, pos)?; set(&mut file.index, names, pos)?; index_mode = mode;
                } else {
                    return Err(PatchError::Unsupported { line: pos + 1, feature: "extended, binary, rename or copy record" });
                }
                pos += 1;
            }
            file.change = kind.unwrap_or(FileChange::Modify);
            if let Some(mode) = index_mode {
                if file.old_mode.is_some() || file.new_mode.is_some() || file.change != FileChange::Modify {
                    return Err(syntax(pos.saturating_sub(1), "conflicting index mode"));
                }
                file.old_mode = Some(mode); file.new_mode = Some(mode);
            }
            match file.change {
                FileChange::Create if file.old_mode.is_some() || file.new_mode.is_none() => return Err(syntax(pos.saturating_sub(1), "creation needs a new regular-file mode")),
                FileChange::Delete if file.new_mode.is_some() || file.old_mode.is_none() => return Err(syntax(pos.saturating_sub(1), "deletion needs an old regular-file mode")),
                FileChange::Modify if file.old_mode.is_some() != file.new_mode.is_some() => return Err(syntax(pos.saturating_sub(1), "incomplete mode change")),
                _ => {}
            }
            if file.hunks.is_empty() && file.change == FileChange::Modify && (file.old_mode.is_none() || file.old_mode == file.new_mode) {
                return Err(syntax(pos.saturating_sub(1), "file has no hunks or mode change"));
            }
            files.push(file);
        }
        files.sort_by(|left, right| left.path.cmp(&right.path));
        let mut paths = BTreeSet::new();
        for file in &files {
            checkpoint(cancelled)?;
            if !paths.insert(file.path.as_slice()) { return Err(PatchError::DuplicatePath); }
        }
        for file in &files {
            for (i, byte) in file.path.iter().enumerate() {
                if *byte == b'/' && paths.contains(&file.path[..i]) { return Err(PatchError::OverlappingPaths); }
            }
        }
        checkpoint(cancelled)?; Ok(Self { files, limits })
    }
    pub fn files(&self) -> &[FilePatch<'a>] { &self.files }
    pub fn limits(&self) -> PatchLimits { self.limits }
}
impl FilePatch<'_> {
    pub fn path(&self) -> &[u8] { &self.path }
    pub fn change(&self) -> FileChange { self.change }
    pub fn index(&self) -> Option<&IndexExpectation> { self.index.as_ref() }
    pub fn hunk_count(&self) -> usize { self.hunks.len() }
    /// Apply at the exact declared offsets. The caller must bind the source
    /// to its independently selected immutable commit and verify index names.
    pub fn apply(&self, source: Option<(u32, &[u8])>, limits: PatchLimits,
        cancelled: &dyn Fn() -> bool) -> Result<Option<PatchedFile>, PatchError> {
        limits.validate()?; checkpoint(cancelled)?;
        check_path(&self.path, limits.max_path_bytes)?;
        if self.hunks.len() > limits.max_hunks { return Err(PatchError::Budget("patch hunks")); }
        if self.hunks.iter().map(|hunk| hunk.lines.len()).sum::<usize>() > limits.max_lines {
            return Err(PatchError::Budget("hunk lines"));
        }
        if (self.change == FileChange::Create) != source.is_none() { return Err(PatchError::SourcePresence); }
        let (old_mode, body) = source.unwrap_or((0o100644, b""));
        if !matches!(old_mode, 0o100644 | 0o100755) || self.old_mode.is_some_and(|mode| mode != old_mode) { return Err(PatchError::SourceMode); }
        if body.len() > limits.max_file_bytes { return Err(PatchError::Budget("source file bytes")); }
        let mut old_lines = Vec::new();
        for line in body.split_inclusive(|byte| *byte == b'\n') {
            checkpoint(cancelled)?;
            if old_lines.len() == limits.max_lines { return Err(PatchError::Budget("source lines")); }
            old_lines.push(line);
        }
        let mut output = Vec::new(); let mut old_cursor = 0; let mut new_cursor = 0;
        let output_limit = limits.max_file_bytes.min(limits.max_output_bytes);
        for (index, hunk) in self.hunks.iter().enumerate() {
            checkpoint(cancelled)?;
            if hunk.old < old_cursor || hunk.old > old_lines.len() { return Err(PatchError::SourceRange { hunk: index }); }
            for line in &old_lines[old_cursor..hunk.old] {
                checkpoint(cancelled)?; append_line(&mut output, line, output_limit, &mut new_cursor, limits.max_lines)?;
            }
            if new_cursor != hunk.new { return Err(PatchError::ResultRange { hunk: index }); }
            old_cursor = hunk.old;
            for line in &hunk.lines {
                checkpoint(cancelled)?;
                if line.kind != b'+' {
                    if old_lines.get(old_cursor).copied() != Some(line.bytes) { return Err(PatchError::ContextMismatch { hunk: index, source_line: old_cursor }); }
                    old_cursor += 1;
                    if line.no_newline && old_cursor != old_lines.len() { return Err(PatchError::MissingNewlineNotAtEnd); }
                }
                if line.kind != b'-' { append_line(&mut output, line.bytes, output_limit, &mut new_cursor, limits.max_lines)?; }
            }
            if old_cursor != hunk.old + hunk.old_count || new_cursor != hunk.new + hunk.new_count { return Err(PatchError::ResultRange { hunk: index }); }
        }
        for line in &old_lines[old_cursor..] { checkpoint(cancelled)?; append_line(&mut output, line, output_limit, &mut new_cursor, limits.max_lines)?; }
        if self.change == FileChange::Delete {
            if !output.is_empty() { return Err(PatchError::NonemptyDeletion); }
            checkpoint(cancelled)?; return Ok(None);
        }
        checkpoint(cancelled)?;
        Ok(Some(PatchedFile { mode: self.new_mode.unwrap_or(old_mode), content: output }))
    }
}
fn append_line(output: &mut Vec<u8>, bytes: &[u8], byte_limit: usize,
    lines: &mut usize, line_limit: usize) -> Result<(), PatchError> {
    if *lines >= line_limit { return Err(PatchError::Budget("result lines")); }
    append(output, bytes, byte_limit)?; *lines += 1; Ok(())
}
fn append(output: &mut Vec<u8>, bytes: &[u8], limit: usize) -> Result<(), PatchError> {
    if !output.is_empty() && output.last() != Some(&b'\n') { return Err(PatchError::MissingNewlineNotAtEnd); }
    if bytes.len() > limit.saturating_sub(output.len()) { return Err(PatchError::Budget("result file bytes")); }
    output.try_reserve(bytes.len()).map_err(|_| PatchError::Budget("allocation"))?;
    output.extend_from_slice(bytes); Ok(())
}

#[cfg(test)]
mod tests;
