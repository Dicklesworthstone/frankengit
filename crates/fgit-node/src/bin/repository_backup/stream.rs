//! Bounded streaming I/O for the existing FGSRC001 transport. The wire bytes do
//! not change. A record is borrowed from one reusable object buffer; no archive
//! payload or object inventory is accumulated. Only finish authenticates a pass.
use std::io::{self, Read, Write};

use fgit_authority_fsqlite::{ExportBundle, import_bundle};
use fgit_crypto::{
    DigestHasher, GitObjectKind, Sha256Hasher, git_object_id, git_payload_commitment,
};
use fgit_types::{
    CANONICAL_CODEC_VERSION, GitHashAlgorithm, GitOid, RepositoryId, RepositoryIncarnationId,
    TenantId,
};

use super::{Identity, MAGIC, MAX_OBJECT_BYTES, MAX_OBJECTS, Record, kind, kind_byte};

const CHUNK_BYTES: usize = 64 * 1024;
// Authority portability has its own codec and row bounds. A larger source
// payload budget must not silently widen that separate allocation boundary.
const MAX_AUTHORITY_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferLimits {
    pub max_archive_bytes: u64,
}
impl Default for TransferLimits {
    fn default() -> Self {
        Self {
            max_archive_bytes: 1 << 30,
        }
    }
}
impl TransferLimits {
    pub fn validate(self) -> Result<(), String> {
        if self.max_archive_bytes == 0 || self.max_archive_bytes > (1_u64 << 40) {
            return Err("archive byte budget must be in 1..=1099511627776".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Seal {
    pub digest: [u8; 32],
    pub bytes: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct StreamHeader {
    pub identity: Identity,
    pub authority: ExportBundle,
    pub objects: usize,
}

/// Owns neither the destination path nor publication. A failed writer is
/// poisoned, so ignoring a short write/cancellation cannot yield a success seal.
pub struct StreamEncoder<W> {
    output: W,
    hash: Sha256Hasher,
    bytes: u64,
    limits: TransferLimits,
    format: GitHashAlgorithm,
    remaining: usize,
    previous: Option<GitOid>,
    failed: bool,
}
impl<W: Write> StreamEncoder<W> {
    pub fn new(
        output: W,
        identity: Identity,
        authority: &[u8],
        objects: usize,
        limits: TransferLimits,
        live: &mut impl FnMut() -> Result<(), String>,
    ) -> Result<Self, String> {
        limits.validate()?;
        live()?;
        if objects > MAX_OBJECTS {
            return Err("repository backup object-count limit".into());
        }
        if authority.is_empty() || authority.len() > MAX_AUTHORITY_BYTES {
            return Err("repository backup authority-byte limit".into());
        }
        let mut encoder = Self {
            output,
            hash: Sha256Hasher::new(),
            bytes: 0,
            limits,
            format: identity.format,
            remaining: objects,
            previous: None,
            failed: false,
        };
        encoder.push(MAGIC, live)?;
        encoder.push(identity.tenant.as_bytes(), live)?;
        encoder.push(identity.repository.as_bytes(), live)?;
        encoder.push(identity.incarnation.as_bytes(), live)?;
        encoder.push(
            &[match identity.format {
                GitHashAlgorithm::Sha1 => 1,
                GitHashAlgorithm::Sha256 => 2,
            }],
            live,
        )?;
        encoder.push(&(authority.len() as u64).to_be_bytes(), live)?;
        encoder.push(authority, live)?;
        encoder.push(&(objects as u64).to_be_bytes(), live)?;
        Ok(encoder)
    }
    /// The source fabric verifies the supplied commitment; the read-back pass
    /// independently checks it before the enclosing file can be published.
    pub fn object(
        &mut self,
        oid: GitOid,
        kind: GitObjectKind,
        payload: &[u8],
        commitment: &[u8; 32],
        live: &mut impl FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        if self.failed {
            return Err("repository backup encoder previously failed".into());
        }
        let result = self.object_inner(oid, kind, payload, commitment, live);
        self.failed = result.is_err();
        result
    }
    fn object_inner(
        &mut self,
        oid: GitOid,
        kind: GitObjectKind,
        payload: &[u8],
        commitment: &[u8; 32],
        live: &mut impl FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        live()?;
        if self.remaining == 0
            || oid.algorithm() != self.format
            || oid.is_zero()
            || self.previous.is_some_and(|last| last >= oid)
        {
            return Err("repository backup object order/domain mismatch".into());
        }
        if payload.len() > MAX_OBJECT_BYTES {
            return Err("repository backup object-byte limit".into());
        }
        let record_bytes = (self.format.digest_len() + 1 + 8 + 32) as u64 + payload.len() as u64;
        check_room(self.bytes, record_bytes, self.limits)?;
        self.push(oid.as_bytes(), live)?;
        self.push(&[kind_byte(kind)], live)?;
        self.push(&(payload.len() as u64).to_be_bytes(), live)?;
        self.push(commitment, live)?;
        self.push(payload, live)?;
        self.remaining -= 1;
        self.previous = Some(oid);
        Ok(())
    }
    fn push(
        &mut self,
        bytes: &[u8],
        live: &mut impl FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        check_room(self.bytes, bytes.len() as u64, self.limits)?;
        // Do not delegate retries of Interrupted to write_all: cancellation must
        // still be observed when a faulty device repeatedly interrupts the call.
        let mut pending = bytes;
        while !pending.is_empty() {
            live()?;
            let offered = pending.len().min(CHUNK_BYTES);
            match self.output.write(&pending[..offered]) {
                Ok(0) => return Err("repository backup write made no progress".into()),
                Ok(count) if count <= offered => {
                    self.hash.update(&pending[..count]);
                    self.bytes += count as u64;
                    pending = &pending[count..];
                }
                Ok(_) => {
                    return Err("repository backup writer returned an invalid byte count".into());
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(format!("repository backup write failed: {error}")),
            }
            live()?;
        }
        Ok(())
    }
    pub fn finish(mut self, live: &mut impl FnMut() -> Result<(), String>) -> Result<Seal, String> {
        if self.failed || self.remaining != 0 {
            return Err("incomplete repository backup object set".into());
        }
        live()?;
        self.output
            .flush()
            .map_err(|e| format!("repository backup flush failed: {e}"))?;
        live()?;
        Ok(Seal {
            digest: self.hash.finish(),
            bytes: self.bytes,
        })
    }
}

fn check_room(used: u64, amount: u64, limits: TransferLimits) -> Result<(), String> {
    used.checked_add(amount)
        .filter(|total| *total <= limits.max_archive_bytes)
        .ok_or_else(|| "repository backup archive-byte limit exceeded".to_owned())
        .map(|_| ())
}

struct Input<R> {
    reader: R,
    hash: Sha256Hasher,
    bytes: u64,
    limits: TransferLimits,
}
impl<R: Read> Input<R> {
    fn read_exact(
        &mut self,
        output: &mut [u8],
        live: &mut impl FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        check_room(self.bytes, output.len() as u64, self.limits)?;
        let mut remaining = output;
        while !remaining.is_empty() {
            live()?;
            let offered = remaining.len().min(CHUNK_BYTES);
            match self.reader.read(&mut remaining[..offered]) {
                Ok(0) => return Err("truncated repository backup".into()),
                Ok(count) if count <= offered => {
                    self.hash.update(&remaining[..count]);
                    self.bytes += count as u64;
                    remaining = &mut remaining[count..];
                }
                Ok(_) => {
                    return Err("repository backup reader returned an invalid byte count".into());
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(format!("repository backup read failed: {error}")),
            }
            live()?;
        }
        Ok(())
    }
    fn array<const N: usize>(
        &mut self,
        live: &mut impl FnMut() -> Result<(), String>,
    ) -> Result<[u8; N], String> {
        let mut output = [0; N];
        self.read_exact(&mut output, live)?;
        Ok(output)
    }
    fn length(
        &mut self,
        maximum: usize,
        live: &mut impl FnMut() -> Result<(), String>,
    ) -> Result<usize, String> {
        usize::try_from(u64::from_be_bytes(self.array(live)?))
            .ok()
            .filter(|n| *n <= maximum)
            .ok_or_else(|| "repository backup declared length/count exceeds its limit".into())
    }
    fn finish(
        mut self,
        expected: [u8; 32],
        live: &mut impl FnMut() -> Result<(), String>,
    ) -> Result<Seal, String> {
        // EOF is part of the exact-byte contract, including when bytes == limit.
        // At most one extra byte is probed, never accepted into a complete pass.
        loop {
            live()?;
            match self.reader.read(&mut [0; 1]) {
                Ok(0) => break,
                Ok(_) => return Err("trailing repository backup bytes".into()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(format!("repository backup EOF check failed: {error}")),
            }
        }
        live()?;
        let seal = Seal {
            digest: self.hash.finish(),
            bytes: self.bytes,
        };
        if seal.digest != expected {
            return Err(
                "repository backup checksum mismatch or input changed during verification".into(),
            );
        }
        Ok(seal)
    }
}

/// Header/record access is tentative until finish verifies the COMPLETE file.
/// Callers must not publish effects using these views alone. Each subsequent
/// pass on the same open input is rehashed against the independently trusted pin.
pub struct StreamDecoder<R> {
    input: Input<R>,
    header: StreamHeader,
    remaining: usize,
    previous: Option<GitOid>,
    payload: Vec<u8>,
    failed: bool,
}
impl<R: Read> StreamDecoder<R> {
    pub fn new(
        reader: R,
        limits: TransferLimits,
        live: &mut impl FnMut() -> Result<(), String>,
    ) -> Result<Self, String> {
        limits.validate()?;
        live()?;
        let mut input = Input {
            reader,
            hash: Sha256Hasher::new(),
            bytes: 0,
            limits,
        };
        if &input.array::<8>(live)? != MAGIC {
            return Err("unsupported repository backup transport".into());
        }
        let tenant = TenantId::from_bytes(input.array(live)?);
        let repository = RepositoryId::from_bytes(input.array(live)?);
        let incarnation = RepositoryIncarnationId::from_bytes(input.array(live)?);
        let format = match input.array::<1>(live)?[0] {
            1 => GitHashAlgorithm::Sha1,
            2 => GitHashAlgorithm::Sha256,
            _ => return Err("unsupported repository backup object format".into()),
        };
        let size = input.length(MAX_AUTHORITY_BYTES, live)?;
        check_room(input.bytes, size as u64, limits)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(size)
            .map_err(|_| "repository authority allocation refused")?;
        bytes.resize(size, 0);
        input.read_exact(&mut bytes, live)?;
        let authority = import_bundle(&bytes)
            .map_err(|error| format!("invalid repository authority transport: {error}"))?;
        drop(bytes);
        live()?;
        if authority.head.is_none() {
            return Err("repository backup has no authority head".into());
        }
        let objects = input.length(MAX_OBJECTS, live)?;
        let minimum = (format.digest_len() + 1 + 8 + 32) as u64;
        check_room(input.bytes, objects as u64 * minimum, limits)?;
        Ok(Self {
            input,
            header: StreamHeader {
                identity: Identity {
                    tenant,
                    repository,
                    incarnation,
                    format,
                },
                authority,
                objects,
            },
            remaining: objects,
            previous: None,
            payload: Vec::new(),
            failed: false,
        })
    }
    pub const fn header(&self) -> &StreamHeader {
        &self.header
    }
    /// At most one 32 MiB payload is retained; the borrow prevents a caller from
    /// keeping it alive while asking this decoder for another record.
    pub fn record(
        &mut self,
        live: &mut impl FnMut() -> Result<(), String>,
    ) -> Result<Option<Record<'_>>, String> {
        if self.failed {
            return Err("repository backup decoder previously failed".into());
        }
        let result = self.record_inner(live);
        // Metadata is returned separately so an error can poison the decoder
        // without competing with a borrow of the retained payload buffer.
        match result {
            Ok(Some((oid, kind))) => Ok(Some(Record {
                oid,
                kind,
                payload: &self.payload,
            })),
            Ok(None) => Ok(None),
            Err(error) => {
                self.failed = true;
                Err(error)
            }
        }
    }
    fn record_inner(
        &mut self,
        live: &mut impl FnMut() -> Result<(), String>,
    ) -> Result<Option<(GitOid, GitObjectKind)>, String> {
        live()?;
        if self.remaining == 0 {
            return Ok(None);
        }
        let format = self.header.identity.format;
        let mut raw = [0; 32];
        self.input
            .read_exact(&mut raw[..format.digest_len()], live)?;
        let text = raw[..format.digest_len()]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let oid = GitOid::from_hex(format, &text).map_err(|_| "invalid native object ID")?;
        if oid.is_zero() || self.previous.is_some_and(|last| last >= oid) {
            return Err("repository backup object order/domain mismatch".into());
        }
        let kind = kind(self.input.array::<1>(live)?[0])?;
        let length = self.input.length(MAX_OBJECT_BYTES, live)?;
        let commitment = self.input.array::<32>(live)?;
        check_room(self.input.bytes, length as u64, self.input.limits)?;
        self.payload.clear();
        self.payload
            .try_reserve_exact(length)
            .map_err(|_| "repository backup object allocation refused")?;
        self.payload.resize(length, 0);
        self.input.read_exact(&mut self.payload, live)?;
        if git_object_id(format, kind, &self.payload) != oid {
            return Err(format!(
                "repository backup native object identity mismatch: {oid}"
            ));
        }
        let computed = git_payload_commitment(kind, &self.payload, CANONICAL_CODEC_VERSION);
        if computed.digest().as_bytes() != commitment.as_slice() {
            return Err(format!(
                "repository backup payload commitment mismatch: {oid}"
            ));
        }
        live()?;
        self.remaining -= 1;
        self.previous = Some(oid);
        Ok(Some((oid, kind)))
    }
    pub fn finish(
        self,
        expected: [u8; 32],
        live: &mut impl FnMut() -> Result<(), String>,
    ) -> Result<(StreamHeader, Seal), String> {
        if self.failed || self.remaining != 0 {
            return Err("incomplete repository backup object set".into());
        }
        let seal = self.input.finish(expected, live)?;
        Ok((self.header, seal))
    }
}

#[cfg(test)]
#[path = "stream_tests.rs"]
mod tests;
