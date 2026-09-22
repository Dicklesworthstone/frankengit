//! Explicit relocation metadata, never similarity-based rename inference.

use super::{PatchError, check_path, checkpoint, metadata, number, set, syntax, unquote};

pub(super) struct Rename {
    pub from: Vec<u8>,
    pub to: Vec<u8>,
    pub similarity: Option<usize>,
}

pub(super) fn is_metadata(line: &[u8]) -> bool {
    line.starts_with(b"rename from ")
        || line.starts_with(b"rename to ")
        || line.starts_with(b"similarity index ")
}

fn path(bytes: &[u8], at: usize, limit: usize) -> Result<Vec<u8>, PatchError> {
    if bytes.len() > limit.saturating_mul(4).saturating_add(2) {
        return Err(PatchError::Budget("rename path metadata"));
    }
    let decoded = if bytes.first() == Some(&b'"') {
        let (decoded, used) = unquote(bytes, at)?;
        if used != bytes.len() {
            return Err(syntax(at, "trailing rename path bytes"));
        }
        decoded
    } else {
        // Extended headers contain the whole raw path, with no a/b prefix or
        // trailing tab delimiter. Preserve spaces; controls require C quoting.
        if bytes.iter().any(|byte| byte.is_ascii_control()) {
            return Err(syntax(at, "unquoted rename path control"));
        }
        bytes.to_vec()
    };
    check_path(&decoded, limit)?;
    Ok(decoded)
}

// The explicit names determine the boundary, even when either contains " b/".
// Decode quoted headers and compare them to those names; do not guess a split.
fn consume<'a>(
    bytes: &'a [u8],
    prefix: &[u8],
    expected: &[u8],
    at: usize,
) -> Result<&'a [u8], PatchError> {
    if bytes.first() == Some(&b'"') {
        let (decoded, used) = unquote(bytes, at)?;
        if decoded.strip_prefix(prefix) != Some(expected) {
            return Err(syntax(at, "rename paths disagree"));
        }
        Ok(&bytes[used..])
    } else {
        bytes
            .strip_prefix(prefix)
            .and_then(|rest| rest.strip_prefix(expected))
            .ok_or_else(|| syntax(at, "rename paths disagree"))
    }
}

pub(super) fn scan(
    records: &[&[u8]],
    start: usize,
    header: &[u8],
    limit: usize,
    cancelled: &dyn Fn() -> bool,
) -> Result<Option<Rename>, PatchError> {
    let (mut from, mut to, mut similarity) = (None, None, None);
    for (at, record) in records.iter().enumerate().skip(start + 1) {
        checkpoint(cancelled)?;
        if record.starts_with(b"diff --git ")
            || record.starts_with(b"--- ")
            || record.starts_with(b"@@ ")
        {
            break;
        }
        let text = metadata(record, at)?;
        if let Some(value) = text.strip_prefix(b"rename from ") {
            set(&mut from, path(value, at, limit)?, at)?;
        } else if let Some(value) = text.strip_prefix(b"rename to ") {
            set(&mut to, path(value, at, limit)?, at)?;
        } else if let Some(value) = text.strip_prefix(b"similarity index ") {
            let digits = value
                .strip_suffix(b"%")
                .ok_or_else(|| syntax(at, "invalid similarity index"))?;
            let score = number(digits, at)?;
            if score > 100 {
                return Err(syntax(at, "invalid similarity index"));
            }
            set(&mut similarity, score, at)?;
        }
    }
    if from.is_none() && to.is_none() && similarity.is_none() {
        return Ok(None);
    }
    let (Some(from), Some(to)) = (from, to) else {
        return Err(syntax(start, "incomplete rename metadata"));
    };
    if from == to {
        return Err(syntax(start, "rename paths are identical"));
    }
    if header.len() > limit.saturating_mul(8).saturating_add(16) {
        return Err(PatchError::Budget("path metadata"));
    }
    let rest = consume(header, b"a/", &from, start)?;
    let rest = rest
        .strip_prefix(b" ")
        .ok_or_else(|| syntax(start, "missing second diff path"))?;
    if !consume(rest, b"b/", &to, start)?.is_empty() {
        return Err(syntax(start, "trailing diff path bytes"));
    }
    Ok(Some(Rename {
        from,
        to,
        similarity,
    }))
}
