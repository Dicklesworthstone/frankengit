//! A commitment-bound inverted name directory, not a source of authorization.
//! Every entry is derived from complete verified tables. The directory is only
//! a candidate filter: returned rows still come from verified original tables.
use super::*;

/// Generation layout profile. Existing v1 tables and manifests keep their
/// canonical bytes; this names the additional manifest-bound lookup payload.
pub const DIRECTORY_PROFILE: &str = "rust-symbol-name-directory-v1";

// One count per (name, kind), including repeated declarations within a file.
// The ordinal mapping is this codec's closed kind registry, not enum layout.
pub(super) type Names = BTreeMap<(Vec<u8>, u8), usize>;
const KINDS: [engine::Kind; 8] = [
    engine::Kind::Function,
    engine::Kind::Struct,
    engine::Kind::Enum,
    engine::Kind::Trait,
    engine::Kind::Type,
    engine::Kind::Module,
    engine::Kind::Union,
    engine::Kind::Macro,
];
fn kind_tag(kind: engine::Kind) -> u8 {
    match kind {
        engine::Kind::Function => 0,
        engine::Kind::Struct => 1,
        engine::Kind::Enum => 2,
        engine::Kind::Trait => 3,
        engine::Kind::Type => 4,
        engine::Kind::Module => 5,
        engine::Kind::Union => 6,
        engine::Kind::Macro => 7,
    }
}
pub(super) fn summarize(
    table: &table::Table,
    cancelled: &dyn Fn() -> bool,
) -> Result<Names, Error> {
    let mut names = Names::new();
    for row in table.rows() {
        check(cancelled)?;
        *names
            .entry((row.name.clone(), kind_tag(row.kind)))
            .or_insert(0) += 1;
    }
    check(cancelled)?;
    Ok(names)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Posting {
    document: usize,
    kind: u8,
    count: usize,
}
/// The authenticated generation must supply `expected` when decoding this
/// payload. A directory is bound to one complete canonical manifest, including
/// its source observation and exact current path order.
#[derive(Clone, Debug)]
pub struct NameDirectory {
    manifest: Digest,
    names: BTreeMap<Vec<u8>, Vec<Posting>>,
}
frame!(DirectoryFrame, "source-symbol-name-directory");

impl NameDirectory {
    pub(super) fn build(
        manifest: &Manifest,
        names: &[Names],
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, Error> {
        if names.len() != manifest.documents().len() {
            return Err(Error::Invalid("directory inventory"));
        }
        let mut result = Self {
            manifest: manifest.encode(cancelled)?.root,
            names: BTreeMap::new(),
        };
        for (document, summary) in names.iter().enumerate() {
            for ((name, kind), count) in summary {
                check(cancelled)?;
                result.names.entry(name.clone()).or_default().push(Posting {
                    document,
                    kind: *kind,
                    count: *count,
                });
            }
        }
        result.validate(manifest, cancelled)?;
        Ok(result)
    }
    fn validate(&self, manifest: &Manifest, cancelled: &dyn Fn() -> bool) -> Result<(), Error> {
        check(cancelled)?;
        if self.manifest != manifest.encode(cancelled)?.root {
            return Err(Error::CommitmentMismatch);
        }
        let mut counts = vec![0usize; manifest.documents().len()];
        let mut postings = 0usize;
        for (name, rows) in &self.names {
            check(cancelled)?;
            if name.is_empty()
                || name.len() > engine::MAX_NAME_BYTES
                || name == b"_"
                || !(name[0].is_ascii_alphabetic() || name[0] == b'_')
                || !name.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
                || rows.is_empty()
            {
                return Err(Error::Invalid("directory name"));
            }
            let mut previous = None;
            for row in rows {
                check(cancelled)?;
                let key = (row.document, row.kind);
                if row.document >= counts.len()
                    || usize::from(row.kind) >= KINDS.len()
                    || row.count == 0
                    || previous.is_some_and(|p| p >= key)
                {
                    return Err(Error::Invalid("directory posting"));
                }
                add(
                    &mut counts[row.document],
                    row.count,
                    manifest.documents()[row.document].declarations,
                    "directory declaration count",
                )?;
                add(
                    &mut postings,
                    1,
                    engine::MAX_DECLARATIONS,
                    "directory postings",
                )?;
                previous = Some(key);
            }
        }
        if counts
            .iter()
            .zip(manifest.documents())
            .any(|(n, d)| *n != d.declarations)
        {
            return Err(Error::Invalid("incomplete directory"));
        }
        check(cancelled)
    }
    /// One bounded payload. Builders may explicitly retain the legacy layout
    /// on a size refusal, never on an integrity or cancellation failure.
    pub fn encode(
        &self,
        manifest: &Manifest,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Payload, Error> {
        self.validate(manifest, cancelled)?;
        let mut out = Encoder::new();
        out.write_bytes("directory profile", DIRECTORY_PROFILE.as_bytes())?;
        out.write_digest(&self.manifest)?;
        out.write_scalar(self.names.len() as u32);
        for (name, rows) in &self.names {
            check(cancelled)?;
            out.write_bytes("name", name)?;
            out.write_scalar(rows.len() as u32);
            for row in rows {
                check(cancelled)?;
                out.write_scalar(row.document as u32);
                out.write_scalar(row.kind);
                out.write_scalar(row.count as u32);
                if out.len() > MAX_PAYLOAD {
                    return Err(Error::Limit("directory bytes"));
                }
            }
        }
        let result = payload(&DirectoryFrame(out.into_bytes())).map_err(|error| match error {
            Error::Limit("payload bytes") => Error::Limit("directory bytes"),
            other => other,
        })?;
        let mut total = manifest.encode(cancelled)?.bytes.len();
        for doc in manifest.documents() {
            add(
                &mut total,
                doc.encoded_bytes,
                MAX_INDEX_BYTES,
                "index bytes",
            )?;
        }
        add(
            &mut total,
            result.bytes.len(),
            MAX_INDEX_BYTES,
            "directory bytes",
        )?;
        check(cancelled)?;
        Ok(result)
    }
    pub fn decode(
        raw: &[u8],
        expected: Digest,
        manifest: &Manifest,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, Error> {
        check(cancelled)?;
        let limits = || DecodeLimits {
            elements: 160_000,
            ..decode_limits()
        };
        let frame = decode_body::<DirectoryFrame>(raw, limits())?;
        if root(&frame)? != expected || encode_body(&frame)? != raw {
            return Err(Error::CommitmentMismatch);
        }
        let mut input = Decoder::new(&frame.0, limits());
        if input.read_bytes("directory profile")? != DIRECTORY_PROFILE.as_bytes() {
            return Err(Error::Invalid("directory profile"));
        }
        let bound = input.read_digest()?;
        let count = input.read_scalar::<u32>("names")? as usize;
        if count > engine::MAX_DECLARATIONS || count > input.remaining() / 9 {
            return Err(Error::Limit("directory names"));
        }
        let mut names = BTreeMap::new();
        let mut total = 0usize;
        for _ in 0..count {
            check(cancelled)?;
            let name = input.read_bytes("name")?.to_vec();
            if names
                .last_key_value()
                .is_some_and(|(last, _)| last >= &name)
            {
                return Err(Error::Invalid("directory name order"));
            }
            let n = input.read_scalar::<u32>("postings")? as usize;
            add(
                &mut total,
                n,
                engine::MAX_DECLARATIONS,
                "directory postings",
            )?;
            if n > input.remaining() / 9 {
                return Err(Error::Invalid("directory posting count"));
            }
            let mut rows = Vec::with_capacity(n);
            for _ in 0..n {
                check(cancelled)?;
                rows.push(Posting {
                    document: input.read_scalar::<u32>("document")? as usize,
                    kind: input.read_scalar::<u8>("kind")?,
                    count: input.read_scalar::<u32>("declarations")? as usize,
                });
            }
            names.insert(name, rows);
        }
        input.finish()?;
        let result = Self {
            manifest: bound,
            names,
        };
        if result.encode(manifest, cancelled)?.bytes != raw {
            return Err(Error::CommitmentMismatch);
        }
        Ok(result)
    }
}

impl Query {
    /// Decode and select with the SAME work budget used for table queries.
    /// Output ordinals preserve raw path order and remove duplicate candidates
    /// across names/kinds. Path scope narrows candidates before any table I/O.
    pub fn directory_candidates(
        &mut self,
        manifest: &Manifest,
        raw: &[u8],
        expected: Digest,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<usize>, Error> {
        self.work.charge(
            raw.len() as u64 + manifest.documents().len() as u64,
            cancelled,
        )?;
        let directory = NameDirectory::decode(raw, expected, manifest, cancelled)?;
        let mut selected = vec![false; manifest.documents().len()];
        let name = self.query.name();
        let prefix = self.query.mode() == SymbolMatchMode::Prefix;
        // Account conservatively for the directory seek as well as traversal.
        self.work.charge((name.len() as u64 + 1) * 32, cancelled)?;
        for (key, rows) in directory.names.range(name.to_vec()..) {
            self.work.charge(key.len() as u64 + 1, cancelled)?;
            if !key.starts_with(name) || (!prefix && key.as_slice() != name) {
                break;
            }
            for row in rows {
                self.work
                    .charge(1 + self.query.kinds().len() as u64, cancelled)?;
                if (self.query.kinds().is_empty()
                    || self.query.kinds().contains(&KINDS[usize::from(row.kind)]))
                    && self.includes(&manifest.documents()[row.document])
                {
                    selected[row.document] = true;
                }
            }
            if !prefix {
                break;
            }
        }
        check(cancelled)?;
        Ok(selected
            .into_iter()
            .enumerate()
            .filter_map(|(i, take)| take.then_some(i))
            .collect())
    }
}

#[cfg(test)]
#[path = "index_directory_tests.rs"]
mod tests;
