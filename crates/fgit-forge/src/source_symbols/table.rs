#![forbid(unsafe_code)]
//! Immutable per-blob declaration tables. Native identity and the canonical
//! outer commitment belong to index.rs; this byte codec never grants access.
use super::engine::{self, Budget, Kind};
use std::collections::BTreeMap;

pub const MAX_BYTES: usize = 1024 * 1024;
const MAGIC: &[u8] = b"fgit-rust-symbol-table-v1\0";
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    pub name: Vec<u8>,
    pub kind: Kind,
    pub raw: bool,
    pub offset: usize,
    pub line: usize,
    pub column: usize,
    pub excerpt_offset: usize,
    pub excerpt: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Table {
    pub source_bytes: usize,
    pub macros: usize,
    pub attributes: usize,
    rows: Vec<Entry>,
    names: BTreeMap<Vec<u8>, Vec<usize>>,
}
#[derive(Debug)]
pub enum Error {
    Syntax(engine::Error),
    Invalid(&'static str),
    Limit(&'static str),
    Cancelled,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "symbol table refused: {self:?}")
    }
}
impl std::error::Error for Error {}
fn check(cancelled: &dyn Fn() -> bool) -> Result<(), Error> {
    if cancelled() {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}
const fn tag(kind: Kind) -> u8 {
    match kind {
        Kind::Function => 0,
        Kind::Struct => 1,
        Kind::Enum => 2,
        Kind::Trait => 3,
        Kind::Type => 4,
        Kind::Module => 5,
        Kind::Union => 6,
        Kind::Macro => 7,
    }
}
const fn kind(tag: u8) -> Result<Kind, Error> {
    Ok(match tag {
        0 => Kind::Function,
        1 => Kind::Struct,
        2 => Kind::Enum,
        3 => Kind::Trait,
        4 => Kind::Type,
        5 => Kind::Module,
        6 => Kind::Union,
        7 => Kind::Macro,
        _ => return Err(Error::Invalid("kind")),
    })
}
fn name_valid(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= engine::MAX_NAME_BYTES
        && (name[0].is_ascii_alphabetic() || name[0] == b'_')
        && name.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}
fn validate(row: &Entry, bytes: usize) -> Result<(), Error> {
    let end = row
        .offset
        .checked_add(row.name.len())
        .ok_or(Error::Invalid("span"))?;
    let excerpt_end = row
        .excerpt_offset
        .checked_add(row.excerpt.len())
        .ok_or(Error::Invalid("excerpt"))?;
    if !name_valid(&row.name)
        || row.name == b"_"
        || end > bytes
        || row.line == 0
        || row.line > row.offset + 1
        || row.column == 0
        || row.column > row.offset + 1
        || row.excerpt.len() > 288
        || row.excerpt_offset > row.offset
        || excerpt_end < end
        || excerpt_end > bytes
        || row.excerpt.contains(&b'\n')
        || row.excerpt_offset < row.offset - (row.column - 1)
    {
        return Err(Error::Invalid("source coordinates"));
    }
    let at = row.offset - row.excerpt_offset;
    if row.excerpt.get(at..at + row.name.len()) != Some(row.name.as_slice())
        || (row.raw && (at < 2 || row.excerpt.get(at - 2..at) != Some(b"r#".as_slice())))
    {
        return Err(Error::Invalid("name/excerpt agreement"));
    }
    Ok(())
}
impl Table {
    pub fn build(
        bytes: &[u8],
        budget: &mut Budget,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, Error> {
        check(cancelled)?;
        let scan = engine::extract(bytes, budget, cancelled).map_err(Error::Syntax)?;
        let mut rows = Vec::with_capacity(scan.declarations.len());
        let mut bound = MAGIC.len() + 16;
        for declaration in scan.declarations {
            check(cancelled)?;
            let start = declaration.byte_offset;
            let end = start + declaration.byte_length;
            let from = (start - (declaration.byte_column - 1)).max(start.saturating_sub(80));
            let upper = bytes.len().min(end.saturating_add(80));
            let until = bytes[end..upper]
                .iter()
                .position(|b| *b == b'\n')
                .map_or(upper, |n| end + n);
            bound += 24 + end - start + until - from;
            if bound > MAX_BYTES {
                return Err(Error::Limit("table bytes"));
            }
            rows.push(Entry {
                name: bytes[start..end].to_vec(),
                kind: declaration.kind,
                raw: declaration.raw_identifier,
                offset: start,
                line: declaration.line,
                column: declaration.byte_column,
                excerpt_offset: from,
                excerpt: bytes[from..until].to_vec(),
            });
        }
        Self::assemble(
            bytes.len(),
            scan.macro_bodies_skipped,
            scan.attributes_skipped,
            rows,
            cancelled,
        )
    }
    fn assemble(
        source_bytes: usize,
        macros: usize,
        attributes: usize,
        rows: Vec<Entry>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, Error> {
        check(cancelled)?;
        if source_bytes > engine::MAX_FILE_BYTES
            || macros > source_bytes
            || attributes > source_bytes
            || rows.len() > engine::MAX_DECLARATIONS
        {
            return Err(Error::Limit("table counters"));
        }
        let mut names: BTreeMap<Vec<u8>, Vec<usize>> = BTreeMap::new();
        let mut previous_end = 0;
        for (i, row) in rows.iter().enumerate() {
            check(cancelled)?;
            validate(row, source_bytes)?;
            if i > 0 && row.offset < previous_end {
                return Err(Error::Invalid("declaration order"));
            }
            previous_end = row.offset + row.name.len();
            names.entry(row.name.clone()).or_default().push(i);
        }
        Ok(Self {
            source_bytes,
            macros,
            attributes,
            rows,
            names,
        })
    }
    pub fn rows(&self) -> &[Entry] {
        &self.rows
    }
    /// Name dictionary lookup, not a scan of source bytes. Returned positions
    /// preserve original declaration order even for a prefix spanning names.
    pub fn lookup(
        &self,
        name: &[u8],
        prefix: bool,
        kinds: &[Kind],
        work: &mut Work,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<usize>, Error> {
        if !name_valid(name) || kinds.len() > 8 {
            return Err(Error::Invalid("query"));
        }
        work.charge(name.len() as u64 + 1, cancelled)?;
        let mut out = Vec::new();
        for (key, positions) in self.names.range(name.to_vec()..) {
            work.charge(key.len() as u64 + 1, cancelled)?;
            if !key.starts_with(name) || (!prefix && key.as_slice() != name) {
                break;
            }
            for position in positions {
                work.charge(1 + kinds.len() as u64, cancelled)?;
                if kinds.is_empty() || kinds.contains(&self.rows[*position].kind) {
                    out.push(*position);
                }
            }
            if !prefix {
                break;
            }
        }
        // Deterministic comparison sorting is separately charged conservatively.
        let comparisons = out.len() as u64 * u64::from(out.len().max(1).bit_width());
        work.charge(comparisons, cancelled)?;
        out.sort_unstable();
        check(cancelled)?;
        Ok(out)
    }
    pub fn encode(&self, cancelled: &dyn Fn() -> bool) -> Result<Vec<u8>, Error> {
        check(cancelled)?;
        let mut out = MAGIC.to_vec();
        for n in [
            self.source_bytes,
            self.macros,
            self.attributes,
            self.rows.len(),
        ] {
            put32(&mut out, n)?;
        }
        for row in &self.rows {
            check(cancelled)?;
            validate(row, self.source_bytes)?;
            out.push(tag(row.kind));
            out.push(u8::from(row.raw));
            out.extend_from_slice(&(row.name.len() as u16).to_le_bytes());
            for n in [row.offset, row.line, row.column, row.excerpt_offset] {
                put32(&mut out, n)?;
            }
            out.extend_from_slice(&(row.excerpt.len() as u16).to_le_bytes());
            out.extend_from_slice(&row.name);
            out.extend_from_slice(&row.excerpt);
            if out.len() > MAX_BYTES {
                return Err(Error::Limit("table bytes"));
            }
        }
        check(cancelled)?;
        Ok(out)
    }
    pub fn decode(bytes: &[u8], cancelled: &dyn Fn() -> bool) -> Result<Self, Error> {
        check(cancelled)?;
        if bytes.len() > MAX_BYTES {
            return Err(Error::Limit("table bytes"));
        }
        let mut input = Input { bytes, at: 0 };
        if input.take(MAGIC.len())? != MAGIC {
            return Err(Error::Invalid("table profile"));
        }
        let source_bytes = input.u32()?;
        let macros = input.u32()?;
        let attributes = input.u32()?;
        let count = input.u32()?;
        if count > engine::MAX_DECLARATIONS || count > input.remaining() / 24 {
            return Err(Error::Invalid("row count"));
        }
        let mut rows = Vec::with_capacity(count);
        for _ in 0..count {
            check(cancelled)?;
            let kind = kind(input.take(1)?[0])?;
            let raw = match input.take(1)?[0] {
                0 => false,
                1 => true,
                _ => return Err(Error::Invalid("raw identifier tag")),
            };
            let name_len = input.u16()?;
            let offset = input.u32()?;
            let line = input.u32()?;
            let column = input.u32()?;
            let excerpt_offset = input.u32()?;
            let excerpt_len = input.u16()?;
            if name_len > engine::MAX_NAME_BYTES || excerpt_len > 288 {
                return Err(Error::Invalid("row bytes"));
            }
            let name = input.take(name_len)?.to_vec();
            let excerpt = input.take(excerpt_len)?.to_vec();
            rows.push(Entry {
                name,
                kind,
                raw,
                offset,
                line,
                column,
                excerpt_offset,
                excerpt,
            });
        }
        if input.remaining() != 0 {
            return Err(Error::Invalid("trailing bytes"));
        }
        let table = Self::assemble(source_bytes, macros, attributes, rows, cancelled)?;
        if table.encode(cancelled)? != bytes {
            return Err(Error::Invalid("noncanonical table"));
        }
        Ok(table)
    }
}
fn put32(out: &mut Vec<u8>, n: usize) -> Result<(), Error> {
    out.extend_from_slice(
        &u32::try_from(n)
            .map_err(|_| Error::Limit("integer width"))?
            .to_le_bytes(),
    );
    Ok(())
}
struct Input<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Input<'a> {
    const fn remaining(&self) -> usize {
        self.bytes.len() - self.at
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self
            .at
            .checked_add(n)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(Error::Invalid("truncated table"))?;
        let bytes = &self.bytes[self.at..end];
        self.at = end;
        Ok(bytes)
    }
    fn u16(&mut self) -> Result<usize, Error> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]) as usize)
    }
    fn u32(&mut self) -> Result<usize, Error> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
    }
}
#[derive(Debug)]
pub struct Work {
    pub used: u64,
    maximum: u64,
}
impl Work {
    pub const fn new(maximum: u64) -> Result<Self, Error> {
        if maximum == 0 || maximum > engine::MAX_WORK {
            return Err(Error::Limit("query work"));
        }
        Ok(Self { used: 0, maximum })
    }
    pub fn charge(&mut self, amount: u64, cancelled: &dyn Fn() -> bool) -> Result<(), Error> {
        check(cancelled)?;
        self.used = self
            .used
            .checked_add(amount)
            .filter(|n| *n <= self.maximum)
            .ok_or(Error::Limit("query work"))?;
        Ok(())
    }
}
#[cfg(test)]
#[path = "table_tests.rs"]
mod tests;
