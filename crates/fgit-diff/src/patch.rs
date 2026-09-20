//! Exact, bounded Git unified patches. No fuzzy matching, filesystem effects,
//! external drivers, rename guessing, or publication authority.
//!
//! The supported profile is ordinary `git diff` for regular files, including
//! creation, deletion, executable-bit changes, quoted raw paths and missing
//! final newlines. `parse_with_renames` additionally accepts explicit regular-file
//! renames, including exact text and mode changes. `parse` keeps refusing renames
//! for callers that do not implement atomic two-path effects. Binary patches,
//! symlinks, gitlinks and copies refuse in both profiles. `parse_with_binary`
//! separately opts into framed binary hunks requiring an explicit native decoder.
//! It does not opt into renames or introduce a compression/hash dependency.
//! `index` names are parsed and exposed as optional identity expectations;
//! callers with an object store must check them against verified native IDs.

use std::collections::BTreeSet;

mod rename;
mod binary;
pub use binary::BinaryHunks;

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
    renamed_from: Option<Vec<u8>>,
    identical_content: bool,
    change: FileChange,
    old_mode: Option<u32>,
    new_mode: Option<u32>,
    index: Option<IndexExpectation>,
    hunks: Vec<Hunk<'a>>,
    binary: Option<BinaryHunks<'a>>,
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
                        pos += 2; (escaped - b'0') * 64 + (digits[0] - b'0') * 8 + (digits[1] - b'0')
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
        // In this non-rename profile the two raw paths must be identical.
        // Their lengths therefore determine the sole possible separator, even
        // when the filename itself contains " b/". Check that exact spelling
        // before considering the ordinary single-boundary refusal path.
        let middle = bytes.len() / 2;
        if bytes.starts_with(b"a/")
            && bytes.get(middle..middle + 3) == Some(b" b/".as_slice())
            && bytes[2..middle] == bytes[middle + 3..]
        {
            return strip_path(&bytes[..middle], b"a/", limit);
        }
        let mut boundaries = bytes.windows(3).enumerate()
            .filter(|(_, part)| *part == b" b/").map(|(i, _)| i);
        let split = boundaries.next().ok_or_else(|| syntax(at, "ambiguous diff paths"))?;
        if boundaries.next().is_some() { return Err(syntax(at, "ambiguous diff paths")); }
        (bytes[..split].to_vec(), bytes[split + 1..].to_vec())
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
    } else {
        // Git terminates an unquoted ---/+++ path containing spaces with a
        // tab. Remove only that delimiter, never filename spaces. Actual tabs
        // in a pathname are quoted; timestamps and other suffixes are outside
        // this profile and must not be mistaken for part of a destination.
        let path = bytes.strip_suffix(b"\t").unwrap_or(bytes);
        if path.contains(&b'\t') { return Err(syntax(at, "unsupported file header suffix")); }
        path.to_vec()
    };
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
        Self::parse_profile(input, limits, cancelled, false, false)
    }

    /// Opt into explicit renames. Callers MUST read `source_path()` from the
    /// same immutable base, authorize both paths, refuse an occupied destination,
    /// and remove `renamed_from()` only as part of the complete atomic patch.
    /// All touched paths are disjoint: swaps, chains and directory/file overlaps
    /// refuse rather than depending on application order. Similarity is never
    /// used to infer a source or to relax exact hunk/index validation.
    pub fn parse_with_renames(input: &'a [u8], limits: PatchLimits,
        cancelled: &dyn Fn() -> bool) -> Result<Self, PatchError> {
        Self::parse_profile(input, limits, cancelled, true, false)
    }

    /// Opt into full-index compressed binary patches without enabling renames.
    /// Framing is not decompression or identity verification: `apply()` refuses
    /// binary hunks. Consumers must use `apply_with_binary_decoder()` and verify
    /// the exact native old/new hashes and every supplied reverse member.
    pub fn parse_with_binary(input: &'a [u8], limits: PatchLimits,
        cancelled: &dyn Fn() -> bool) -> Result<Self, PatchError> {
        Self::parse_profile(input, limits, cancelled, false, true)
    }

    fn parse_profile(input: &'a [u8], limits: PatchLimits, cancelled: &dyn Fn() -> bool,
        allow_renames: bool, allow_binary: bool) -> Result<Self, PatchError> {
        limits.validate()?; checkpoint(cancelled)?;
        if input.len() > limits.max_patch_bytes { return Err(PatchError::Budget("patch bytes")); }
        let mut records = Vec::new();
        let mut offsets = Vec::new(); let mut offset = 0;
        for line in input.split_inclusive(|byte| *byte == b'\n') {
            checkpoint(cancelled)?;
            if records.len() == limits.max_lines { return Err(PatchError::Budget("patch lines")); }
            if allow_binary { offsets.push(offset); offset += line.len(); }
            records.push(line);
        }
        if records.is_empty() { return Err(syntax(0, "empty patch")); }
        let mut files = Vec::new(); let mut pos = 0; let mut hunk_count = 0usize;
        let mut binary_expanded = 0usize;
        while pos < records.len() {
            checkpoint(cancelled)?;
            if files.len() == limits.max_files { return Err(PatchError::Budget("patch files")); }
            let first = metadata(records[pos], pos)?;
            let paths = first.strip_prefix(b"diff --git ").ok_or_else(|| syntax(pos, "expected diff --git"))?;
            let relocation = if allow_renames {
                rename::scan(&records, pos, paths, limits.max_path_bytes, cancelled)?
            } else { None };
            let similarity = relocation.as_ref().and_then(|rename| rename.similarity);
            let (path, renamed_from) = match relocation {
                Some(rename) => (rename.to, Some(rename.from)),
                None => (diff_paths(paths, pos, limits.max_path_bytes)?, None),
            };
            let mut file = FilePatch { path, renamed_from, identical_content: similarity == Some(100),
                change: FileChange::Modify, old_mode: None, new_mode: None, index: None, hunks: Vec::new(), binary: None };
            let (mut kind, mut index_mode, mut headers) = (None, None, false);
            pos += 1;
            while pos < records.len() && !records[pos].starts_with(b"diff --git ") {
                checkpoint(cancelled)?;
                let text = metadata(records[pos], pos)?;
                if allow_binary && text == b"GIT binary patch" {
                    if headers || !file.hunks.is_empty() || file.renamed_from.is_some() {
                        return Err(syntax(pos, "binary and text/rename payloads cannot mix"));
                    }
                    let payload = binary::scan(&input[offsets[pos]..], pos, limits, cancelled)?;
                    hunk_count = hunk_count.checked_add(payload.member_count())
                        .filter(|count| *count <= limits.max_hunks)
                        .ok_or(PatchError::Budget("patch hunks"))?;
                    binary_expanded = binary_expanded.checked_add(payload.declared_inflated_bytes())
                        .filter(|bytes| *bytes <= limits.max_output_bytes)
                        .ok_or(PatchError::Budget("binary inflated bytes"))?;
                    pos += payload.line_count();
                    file.binary = Some(payload);
                    break;
                }
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
                    if old.as_deref().is_some_and(|path| path != file.source_path())
                        || new.as_deref().is_some_and(|path| path != file.path()) {
                        return Err(syntax(pos, "file paths disagree"));
                    }
                    if kind.is_some_and(|kind| kind != change) { return Err(syntax(pos, "file presence metadata disagrees")); }
                    kind = Some(change); headers = true;
                } else if headers {
                    return Err(syntax(pos, "expected hunk after file headers"));
                } else if file.renamed_from.is_some() && rename::is_metadata(text) {
                    // The bounded pre-scan already checked these exact records,
                    // including duplicates and agreement with both diff paths.
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
            if file.renamed_from.is_some() {
                if file.change != FileChange::Modify {
                    return Err(syntax(pos.saturating_sub(1), "rename cannot create or delete a file side"));
                }
                if file.hunks.is_empty() && similarity.is_some_and(|score| score != 100) {
                    return Err(syntax(pos.saturating_sub(1), "nonidentical rename needs exact hunks"));
                }
            }
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
            if file.binary.is_some() {
                binary::check_index(file.index.as_ref(), file.change)?;
            }
            if file.binary.is_none() && file.renamed_from.is_none() && file.hunks.is_empty() && file.change == FileChange::Modify && (file.old_mode.is_none() || file.old_mode == file.new_mode) {
                return Err(syntax(pos.saturating_sub(1), "file has no hunks or mode change"));
            }
            files.push(file);
        }
        files.sort_by(|left, right| left.path.cmp(&right.path));
        let mut paths = BTreeSet::new();
        for file in &files {
            checkpoint(cancelled)?;
            if !paths.insert(file.path.as_slice()) { return Err(PatchError::DuplicatePath); }
            if let Some(source) = file.renamed_from() {
                if !paths.insert(source) { return Err(PatchError::DuplicatePath); }
            }
        }
        for path in &paths {
            checkpoint(cancelled)?;
            for (i, byte) in path.iter().enumerate() {
                if *byte == b'/' && paths.contains(&path[..i]) { return Err(PatchError::OverlappingPaths); }
            }
        }
        checkpoint(cancelled)?; Ok(Self { files, limits })
    }
    pub fn files(&self) -> &[FilePatch<'a>] { &self.files }
    pub fn limits(&self) -> PatchLimits { self.limits }
}
impl FilePatch<'_> {
    /// Destination path (the deleted path for a deletion).
    pub fn path(&self) -> &[u8] { &self.path }
    /// Source path to resolve against the original, independently selected tree.
    pub fn source_path(&self) -> &[u8] { self.renamed_from.as_deref().unwrap_or(&self.path) }
    /// Additional path to remove atomically after successful rename application.
    pub fn renamed_from(&self) -> Option<&[u8]> { self.renamed_from.as_deref() }
    /// File-content presence change. A rename is `Modify`; `renamed_from()`
    /// separately carries its required two-path tree effect.
    pub fn change(&self) -> FileChange { self.change }
    pub fn index(&self) -> Option<&IndexExpectation> { self.index.as_ref() }
    /// Includes both encoded binary members, when present.
    pub fn hunk_count(&self) -> usize { self.hunks.len() + self.binary.as_ref().map_or(0, BinaryHunks::member_count) }
    pub fn binary_hunks(&self) -> Option<&BinaryHunks<'_>> { self.binary.as_ref() }
    /// Apply at the exact declared offsets. The caller must bind the source
    /// to its independently selected immutable commit and verify index names.
    pub fn apply(&self, source: Option<(u32, &[u8])>, limits: PatchLimits,
        cancelled: &dyn Fn() -> bool) -> Result<Option<PatchedFile>, PatchError> {
        self.apply_with_binary_decoder(source, limits, cancelled, |_, _, _| {
            Err(PatchError::Unsupported { line: 1, feature: "native binary decoder required" })
        })
    }

    /// Apply literal hunks normally, or call the supplied native decoder once.
    /// Before returning success, the decoder MUST validate the exact full-index
    /// identities, bounded decompression/deltas, and any reverse image. Returning
    /// decoded bytes is not authority to stage objects or publish a ref. This
    /// adapter enforces source presence/mode and final size/deletion constraints;
    /// consumers still own aggregate work budgets and immutable source selection.
    pub fn apply_with_binary_decoder(
        &self, source: Option<(u32, &[u8])>, limits: PatchLimits,
        cancelled: &dyn Fn() -> bool,
        decoder: impl FnOnce(&[u8], &IndexExpectation, &[u8]) -> Result<Vec<u8>, PatchError>,
    ) -> Result<Option<PatchedFile>, PatchError> {
        limits.validate()?; checkpoint(cancelled)?;
        check_path(&self.path, limits.max_path_bytes)?;
        check_path(self.source_path(), limits.max_path_bytes)?;
        if self.hunks.len() > limits.max_hunks { return Err(PatchError::Budget("patch hunks")); }
        if self.hunks.iter().map(|hunk| hunk.lines.len()).sum::<usize>() > limits.max_lines {
            return Err(PatchError::Budget("hunk lines")); }
        if (self.change == FileChange::Create) != source.is_none() { return Err(PatchError::SourcePresence); }
        let (old_mode, body) = source.unwrap_or((0o100644, b""));
        if !matches!(old_mode, 0o100644 | 0o100755) || self.old_mode.is_some_and(|mode| mode != old_mode) { return Err(PatchError::SourceMode); }
        if body.len() > limits.max_file_bytes { return Err(PatchError::Budget("source file bytes")); }
        if let Some(binary) = &self.binary {
            binary.check_limits(limits)?;
            let index = binary::check_index(self.index.as_ref(), self.change)?;
            let output = decoder(binary.bytes(), index, body)?;
            checkpoint(cancelled)?;
            if output.len() > limits.max_file_bytes.min(limits.max_output_bytes) {
                return Err(PatchError::Budget("result file bytes"));
            }
            if self.change == FileChange::Delete {
                if !output.is_empty() { return Err(PatchError::NonemptyDeletion); }
                return Ok(None);
            }
            return Ok(Some(PatchedFile { mode: self.new_mode.unwrap_or(old_mode), content: output }));
        }
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
        if self.identical_content && output != body {
            return Err(syntax(0, "identical rename changed file content"));
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

#[cfg(test)]
#[path = "patch/octal_tests.rs"]
mod octal_tests;

#[cfg(test)]
mod path_header_regressions {
    use super::*;

    fn edit(path: &str) -> String {
        format!(
            "diff --git a/{path} b/{path}\n--- a/{path}\t\n+++ b/{path}\t\n@@ -1 +1 @@\n-old\n+new\n"
        )
    }

    #[test]
    fn git_space_terminated_headers_apply_to_the_exact_filename() {
        for path in [
            "ordinary space", " leading", "trailing ", "  ",
            "a b/x", "nested b/name", "x b/y b/z", "café b/file ",
        ] {
            let bytes = edit(path);
            let patch = UnifiedPatch::parse(bytes.as_bytes(), PatchLimits::default(), &|| false).unwrap();
            assert_eq!(patch.files().len(), 1);
            let file = &patch.files()[0];
            assert_eq!(file.path(), path.as_bytes());
            assert_eq!(file.change(), FileChange::Modify);
            assert_eq!(file.apply(Some((0o100644, b"old\n")), patch.limits(), &|| false).unwrap(),
                Some(PatchedFile { mode: 0o100644, content: b"new\n".to_vec() }));
            assert!(matches!(file.apply(Some((0o100644, b"wrong\n")), patch.limits(), &|| false),
                Err(PatchError::ContextMismatch { .. })));
        }
    }

    #[test]
    fn space_paths_work_for_creation_deletion_and_mode_only_changes() {
        let path = "nested b/file with spaces ";
        for (metadata, headers, hunk, source, expected, change) in [
            ("new file mode 100755\n", format!("--- /dev/null\n+++ b/{path}\t\n"),
                "@@ -0,0 +1 @@\n+new\n", None,
                Some(PatchedFile { mode: 0o100755, content: b"new\n".to_vec() }), FileChange::Create),
            ("deleted file mode 100644\n", format!("--- a/{path}\t\n+++ /dev/null\n"),
                "@@ -1 +0,0 @@\n-old\n", Some((0o100644, b"old\n".as_slice())),
                None, FileChange::Delete),
            ("old mode 100644\nnew mode 100755\n", String::new(), "",
                Some((0o100644, b"old\n".as_slice())),
                Some(PatchedFile { mode: 0o100755, content: b"old\n".to_vec() }), FileChange::Modify),
        ] {
            let bytes = format!("diff --git a/{path} b/{path}\n{metadata}{headers}{hunk}");
            let patch = UnifiedPatch::parse(bytes.as_bytes(), PatchLimits::default(), &|| false).unwrap();
            let file = &patch.files()[0];
            assert_eq!(file.path(), path.as_bytes());
            assert_eq!(file.change(), change);
            assert_eq!(file.apply(source, patch.limits(), &|| false).unwrap(), expected);
        }
    }

    #[test]
    fn quoted_trailing_tabs_remain_filename_bytes() {
        let bytes = b"diff --git \"a/name\\t\" \"b/name\\t\"\n--- \"a/name\\t\"\n+++ \"b/name\\t\"\n@@ -1 +1 @@\n-old\n+new\n";
        let patch = UnifiedPatch::parse(bytes, PatchLimits::default(), &|| false).unwrap();
        let file = &patch.files()[0];
        assert_eq!(file.path(), b"name\t");
        assert_eq!(file.apply(Some((0o100644, b"old\n")), patch.limits(), &|| false).unwrap().unwrap().content,
            b"new\n");
    }

    #[test]
    fn file_header_suffixes_are_not_silently_discarded() {
        for bytes in [
            b"a/name\t2000-01-01".as_slice(), b"a/name\t\t",
            b"a/inner\ttab\t", b"a/name\tgarbage\t", b"\"a/name\"\t",
        ] {
            assert!(matches!(file_path(bytes, b"a/", 0, 4096), Err(PatchError::Syntax { .. })));
        }
        assert_eq!(file_path(b"/dev/null", b"a/", 0, 4096).unwrap(), None);
        assert_eq!(file_path(b"/dev/null\t", b"a/", 0, 4096), Err(PatchError::InvalidPath));
        assert_eq!(file_path(b"a/name \t", b"a/", 0, 4096).unwrap(), Some(b"name ".to_vec()));
    }

    #[test]
    fn unquoted_separator_resolution_does_not_allow_renames_or_traversal() {
        assert!(matches!(diff_paths(b"a/old b/new", 0, 4096),
            Err(PatchError::Unsupported { feature: "rename or copy", .. })));
        for bytes in [b"a/old b/one b/two".as_slice(), b"a/x b/y b/x b/z", b"a/x"] {
            assert!(matches!(diff_paths(bytes, 0, 4096), Err(PatchError::Syntax { .. })));
        }
        for path in ["x b/../outside", "x b/.git/config", "x b//file", "x b/./file"] {
            let bytes = format!("a/{path} b/{path}");
            assert_eq!(diff_paths(bytes.as_bytes(), 0, 4096), Err(PatchError::InvalidPath));
        }
        assert_eq!(diff_paths(b"a/x\0 b/y b/x\0 b/y", 0, 4096), Err(PatchError::InvalidPath));
    }

    #[test]
    fn file_headers_must_still_agree_with_the_complete_diff_path() {
        for (path, old, new) in [
            ("trailing ", "trailing", "trailing "),
            ("nested b/name", "name", "nested b/name"),
            ("nested b/name", "nested b/name", "another"),
        ] {
            let bytes = format!("diff --git a/{path} b/{path}\n--- a/{old}\t\n+++ b/{new}\t\n@@ -1 +1 @@\n-old\n+new\n");
            assert!(matches!(UnifiedPatch::parse(bytes.as_bytes(), PatchLimits::default(), &|| false),
                Err(PatchError::Syntax { reason: "file paths disagree", .. })));
        }
    }

    #[test]
    fn filename_limit_excludes_the_git_header_delimiter() {
        let path = "a b/x";
        let bytes = edit(path);
        let limits = PatchLimits { max_path_bytes: path.len(), ..PatchLimits::default() };
        assert!(UnifiedPatch::parse(bytes.as_bytes(), limits, &|| false).is_ok());
        assert_eq!(UnifiedPatch::parse(bytes.as_bytes(),
            PatchLimits { max_path_bytes: path.len() - 1, ..limits }, &|| false), Err(PatchError::InvalidPath));
        let path = format!("{} b/x", "x".repeat(4092));
        assert_eq!(path.len(), 4096);
        let bytes = edit(&path);
        assert!(UnifiedPatch::parse(bytes.as_bytes(), PatchLimits::default(), &|| false).is_ok());
        let bytes = edit(&(path + "x"));
        assert_eq!(UnifiedPatch::parse(bytes.as_bytes(), PatchLimits::default(), &|| false),
            Err(PatchError::InvalidPath));
    }

    #[test]
    fn repeated_separator_fragments_have_one_exact_interpretation() {
        for count in 1..=32 {
            let path = format!("{}leaf ", "x b/".repeat(count));
            let bytes = edit(&path);
            let first = UnifiedPatch::parse(bytes.as_bytes(), PatchLimits::default(), &|| false).unwrap();
            let second = UnifiedPatch::parse(bytes.as_bytes(), PatchLimits::default(), &|| false).unwrap();
            assert_eq!(first, second);
            assert_eq!(first.files()[0].path(), path.as_bytes());
        }
    }
}

#[cfg(test)]
#[path = "patch/rename_tests.rs"]
mod rename_tests;
