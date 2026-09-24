//! Structural intake only. The native pack crate owns base85/zlib/delta and
//! Git identity verification; neither parsing nor a checksum grants authority.
use super::{FileChange, IndexExpectation, PatchError, PatchLimits, checkpoint, number, syntax};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryHunks<'a> {
    bytes: &'a [u8],
    lines: usize,
    members: usize,
    declared: [usize; 2],
}
impl BinaryHunks<'_> {
    #[must_use]
    pub const fn bytes(&self) -> &[u8] {
        self.bytes
    }
    #[must_use]
    pub const fn member_count(&self) -> usize {
        self.members
    }
    #[must_use]
    pub const fn line_count(&self) -> usize {
        self.lines
    }
    /// Literal bytes or inflated delta PROGRAM bytes, not delta result sizes.
    #[must_use]
    pub fn declared_inflated_bytes(&self) -> usize {
        self.declared.iter().sum()
    }
    pub(super) fn check_limits(&self, limits: PatchLimits) -> Result<(), PatchError> {
        if self.bytes.len() > limits.max_patch_bytes
            || self.lines > limits.max_lines
            || self.members > limits.max_hunks
            || self
                .declared
                .iter()
                .any(|size| *size > limits.max_file_bytes)
            || self.declared_inflated_bytes() > limits.max_output_bytes
        {
            return Err(PatchError::Budget("binary hunks"));
        }
        Ok(())
    }
}

pub(super) fn check_index(
    index: Option<&IndexExpectation>,
    change: FileChange,
) -> Result<&IndexExpectation, PatchError> {
    let index = index.ok_or_else(|| syntax(0, "binary patch requires full index identities"))?;
    if !matches!(index.old.len(), 40 | 64) || index.old.len() != index.new.len() {
        return Err(syntax(
            0,
            "binary index identities must share a full hash width",
        ));
    }
    let old_absent = index.old.iter().all(|b| *b == b'0');
    let new_absent = index.new.iter().all(|b| *b == b'0');
    if old_absent != (change == FileChange::Create) || new_absent != (change == FileChange::Delete)
    {
        return Err(PatchError::SourcePresence);
    }
    Ok(index)
}

struct Cursor<'a> {
    input: &'a [u8],
    at: usize,
    lines: usize,
    first_line: usize,
}
impl<'a> Cursor<'a> {
    fn line(
        &mut self,
        limits: PatchLimits,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<&'a [u8], PatchError> {
        checkpoint(cancelled)?;
        if self.lines >= limits.max_lines {
            return Err(PatchError::Budget("binary lines"));
        }
        let rest = &self.input[self.at..];
        // Count prefix plus at most 65 base85 digits. Do not scan a huge invalid
        // record while postponing cancellation. Headers fit the same bound.
        let end = rest
            .iter()
            .take(67)
            .position(|b| *b == b'\n')
            .ok_or_else(|| {
                syntax(
                    self.first_line + self.lines,
                    "truncated or oversized binary record",
                )
            })?;
        self.at += end + 1;
        self.lines += 1;
        Ok(&rest[..end])
    }
    fn file_end(&self) -> bool {
        self.at == self.input.len() || self.input[self.at..].starts_with(b"diff --git ")
    }
}

pub(super) fn scan<'a>(
    input: &'a [u8],
    first_line: usize,
    limits: PatchLimits,
    cancelled: &dyn Fn() -> bool,
) -> Result<BinaryHunks<'a>, PatchError> {
    let mut cursor = Cursor {
        input,
        at: 0,
        lines: 0,
        first_line,
    };
    if cursor.line(limits, cancelled)? != b"GIT binary patch" {
        return Err(syntax(first_line, "binary marker required"));
    }
    let mut declared = [0usize; 2];
    let mut members = 0;
    loop {
        if members == 2 {
            return Err(syntax(first_line + cursor.lines, "trailing binary records"));
        }
        let at = first_line + cursor.lines;
        let header = cursor.line(limits, cancelled)?;
        let digits = header
            .strip_prefix(b"literal ")
            .or_else(|| header.strip_prefix(b"delta "))
            .ok_or_else(|| syntax(at, "binary member header required"))?;
        if digits.len() > 1 && digits[0] == b'0' {
            return Err(syntax(at, "noncanonical binary size"));
        }
        let size = number(digits, at)?;
        if size > limits.max_file_bytes {
            return Err(PatchError::Budget("binary member bytes"));
        }
        declared[members] = size;
        members += 1;
        let mut rows = 0usize;
        loop {
            let at = first_line + cursor.lines;
            let row = cursor.line(limits, cancelled)?;
            if row.is_empty() {
                break;
            }
            let count = match row[0] {
                b'A'..=b'Z' => usize::from(row[0] - b'A') + 1,
                b'a'..=b'z' => usize::from(row[0] - b'a') + 27,
                _ => return Err(syntax(at, "binary row length prefix")),
            };
            if row.len() != 1 + count.div_ceil(4) * 5
                || row[1..]
                    .iter()
                    .any(|b| !b.is_ascii_alphanumeric() && !b"!#$%&()*+-;<=>?@^_`{|}~".contains(b))
            {
                return Err(syntax(at, "binary row framing"));
            }
            rows += 1;
        }
        if rows == 0 {
            return Err(syntax(at, "empty encoded binary member"));
        }
        if cursor.file_end() {
            break;
        }
    }
    let hunks = BinaryHunks {
        bytes: &input[..cursor.at],
        lines: cursor.lines,
        members,
        declared,
    };
    hunks.check_limits(limits)?;
    checkpoint(cancelled)?;
    Ok(hunks)
}

impl<'a> super::UnifiedPatch<'a> {
    /// Combine literal renames and non-renaming compressed file changes in one
    /// atomic workspace patch. All original two-path obligations still apply.
    /// A compressed rename itself remains unsupported; use explicit delete and
    /// create records instead. Neither existing parser profile is widened.
    pub fn parse_with_binary_and_renames(
        input: &'a [u8],
        limits: PatchLimits,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, PatchError> {
        Self::parse_profile(input, limits, cancelled, true, true)
    }
}

#[cfg(test)]
mod tests;
