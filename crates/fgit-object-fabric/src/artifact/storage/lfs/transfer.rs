//! Bounded LFS custody companion archives, separate from Git and authority data.
//!
//! The v1 transport spells one source label followed by strictly OID-ordered
//! `(SHA-256, u64 length, raw payload)` records. All integers are big-endian.
//! Its fixed header is `FGLF\0\0\0\x01`, tenant/repository/incarnation (16 bytes
//! each), Git format (1 = SHA-1, 2 = SHA-256), head generation (u64), opaque head
//! token (16 bytes), head-body SHA-256 (32 bytes), object count (u32), and total
//! payload length (u64). There are no paths, optional fields, or trailing data.
//! The caller supplies a separately trusted SHA-256 of the **complete archive**;
//! source labels are not independent authority or permission to import objects.
//! Verification consumes the entire stream before returning any record offsets.
//! The owning service must then check its exact destination basis and pointer
//! inventory before installing custody through the existing LFS store.
//!
//! A verified archive does not freeze an external file. The local host must keep
//! the input stable, and each payload must be reverified by `LfsStore::put` when
//! reread. A later I/O failure may leave a verified subset in immutable custody;
//! retry is by the same digest and length, never by changing repository refs.

use super::{LfsObject, LfsOid, MAX_OBJECT_BYTES};
use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_types::{GitHashAlgorithm, RepositoryId, RepositoryIncarnationId, TenantId};
use std::io::{self, Read, Seek, SeekFrom, Write};

const MAGIC: &[u8; 8] = b"FGLF\0\0\0\x01";
const HEADER_BYTES: usize = 125;
const RECORD_BYTES: u64 = 40;
const CHUNK_BYTES: usize = 64 * 1024;
pub const MAX_OBJECTS: usize = 1_000_000;
pub const MAX_ARCHIVE_BYTES: u64 = 1024 * 1024 * 1024 * 1024;

/// Labels the exact authenticated source selection, not a grant or a new head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceIdentity {
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub incarnation: RepositoryIncarnationId,
    pub format: GitHashAlgorithm,
    pub head_generation: u64,
    pub head_token: [u8; 16],
    /// Raw SHA-256 of the exact authenticated authority-head body bytes.
    pub head_sha256: [u8; 32],
}

/// Independent count, per-object, aggregate-payload, and wire-byte ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferLimits {
    pub max_objects: usize,
    pub max_object_bytes: u64,
    pub max_payload_bytes: u64,
    pub max_archive_bytes: u64,
}
impl Default for TransferLimits {
    fn default() -> Self {
        Self {
            max_objects: 100_000,
            max_object_bytes: MAX_OBJECT_BYTES,
            max_payload_bytes: 1024 * 1024 * 1024,
            max_archive_bytes: 1024 * 1024 * 1024,
        }
    }
}
impl TransferLimits {
    fn validate(self) -> Result<(), TransferError> {
        if self.max_objects == 0
            || self.max_objects > MAX_OBJECTS
            || self.max_object_bytes == 0
            || self.max_object_bytes > MAX_OBJECT_BYTES
            || self.max_payload_bytes == 0
            || self.max_payload_bytes > MAX_ARCHIVE_BYTES
            || self.max_archive_bytes == 0
            || self.max_archive_bytes > MAX_ARCHIVE_BYTES
        {
            return Err(TransferError::InvalidInput("invalid LFS transfer limits"));
        }
        Ok(())
    }

    fn admit(self, count: usize, payload: u64) -> Result<u64, TransferError> {
        self.validate()?;
        if count > self.max_objects {
            return Err(TransferError::ObjectCountLimit);
        }
        if payload > self.max_payload_bytes {
            return Err(TransferError::PayloadLimit);
        }
        let bytes = (count as u64)
            .checked_mul(RECORD_BYTES)
            .and_then(|n| n.checked_add(HEADER_BYTES as u64))
            .and_then(|n| n.checked_add(payload))
            .ok_or(TransferError::ArchiveLimit)?;
        if bytes > self.max_archive_bytes {
            return Err(TransferError::ArchiveLimit);
        }
        Ok(bytes)
    }
}

/// Exact transport commitment; it does not publish or authenticate a repository.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Seal {
    pub digest: [u8; 32],
    pub bytes: u64,
    pub payload_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferError {
    InvalidInput(&'static str),
    InvalidEncoding(&'static str),
    ObjectCountLimit,
    ObjectLimit,
    PayloadLimit,
    ArchiveLimit,
    ObjectOrder,
    PayloadMismatch,
    DigestMismatch,
    Truncated,
    TrailingBytes,
    Incomplete,
    Cancelled,
    Io {
        operation: &'static str,
        kind: io::ErrorKind,
    },
}
impl std::fmt::Display for TransferError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "LFS transfer refused: {self:?}")
    }
}
impl std::error::Error for TransferError {}

fn io_error(operation: &'static str, error: io::Error) -> TransferError {
    TransferError::Io {
        operation,
        kind: error.kind(),
    }
}
fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), TransferError> {
    if live() {
        Ok(())
    } else {
        Err(TransferError::Cancelled)
    }
}

fn read_exact(
    input: &mut impl Read,
    mut bytes: &mut [u8],
    live: &mut impl FnMut() -> bool,
) -> Result<(), TransferError> {
    while !bytes.is_empty() {
        checkpoint(live)?;
        let result = input.read(bytes);
        checkpoint(live)?;
        match result {
            Ok(0) => return Err(TransferError::Truncated),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(io_error("read LFS archive", error)),
        }
    }
    Ok(())
}
fn require_eof(
    input: &mut impl Read,
    live: &mut impl FnMut() -> bool,
) -> Result<(), TransferError> {
    let mut byte = [0];
    loop {
        checkpoint(live)?;
        let result = input.read(&mut byte);
        checkpoint(live)?;
        match result {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(TransferError::TrailingBytes),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(io_error("check LFS archive end", error)),
        }
    }
}

/// Streams into a caller-owned private staging output. A failed object poisons
/// the encoder: even a later successful call can never produce a seal for it.
pub struct Encoder<W: Write> {
    output: W,
    hash: Sha256Hasher,
    limits: TransferLimits,
    expected_objects: usize,
    expected_payload: u64,
    expected_bytes: u64,
    objects: usize,
    payload: u64,
    bytes: u64,
    previous: Option<LfsOid>,
    poisoned: bool,
}
impl<W: Write> Encoder<W> {
    pub fn new(
        output: W,
        source: SourceIdentity,
        object_count: usize,
        payload_bytes: u64,
        limits: TransferLimits,
        live: &mut impl FnMut() -> bool,
    ) -> Result<Self, TransferError> {
        checkpoint(live)?;
        if source.head_generation == 0 {
            return Err(TransferError::InvalidInput("zero source head generation"));
        }
        if object_count == 0 && payload_bytes != 0 {
            return Err(TransferError::InvalidInput("payload without LFS objects"));
        }
        let expected_bytes = limits.admit(object_count, payload_bytes)?;
        let mut result = Self {
            output,
            hash: Sha256Hasher::new(),
            limits,
            expected_objects: object_count,
            expected_payload: payload_bytes,
            expected_bytes,
            objects: 0,
            payload: 0,
            bytes: 0,
            previous: None,
            poisoned: false,
        };
        let header = encode_header(source, object_count, payload_bytes);
        result.write(&header, live)?;
        Ok(result)
    }

    pub fn object(
        &mut self,
        object: LfsObject,
        input: &mut impl Read,
        live: &mut impl FnMut() -> bool,
    ) -> Result<(), TransferError> {
        if self.poisoned {
            return Err(TransferError::Incomplete);
        }
        self.poisoned = true;
        self.object_inner(object, input, live)?;
        self.poisoned = false;
        Ok(())
    }

    fn object_inner(
        &mut self,
        object: LfsObject,
        input: &mut impl Read,
        live: &mut impl FnMut() -> bool,
    ) -> Result<(), TransferError> {
        checkpoint(live)?;
        if self.objects >= self.expected_objects {
            return Err(TransferError::ObjectCountLimit);
        }
        if object.size > self.limits.max_object_bytes {
            return Err(TransferError::ObjectLimit);
        }
        if self.previous.is_some_and(|previous| previous >= object.oid) {
            return Err(TransferError::ObjectOrder);
        }
        let payload = self
            .payload
            .checked_add(object.size)
            .filter(|n| *n <= self.expected_payload)
            .ok_or(TransferError::PayloadLimit)?;
        self.write(&object.oid.0, live)?;
        self.write(&object.size.to_be_bytes(), live)?;
        let mut hash = Sha256Hasher::new();
        let mut chunk = [0_u8; CHUNK_BYTES];
        let mut remaining = object.size;
        while remaining != 0 {
            let length = remaining.min(CHUNK_BYTES as u64) as usize;
            read_exact(input, &mut chunk[..length], live)?;
            DigestHasher::update(&mut hash, &chunk[..length]);
            self.write(&chunk[..length], live)?;
            remaining -= length as u64;
        }
        require_eof(input, live)?;
        if DigestHasher::finish(hash) != object.oid.0 {
            return Err(TransferError::PayloadMismatch);
        }
        checkpoint(live)?;
        self.objects += 1;
        self.payload = payload;
        self.previous = Some(object.oid);
        Ok(())
    }

    fn write(
        &mut self,
        mut bytes: &[u8],
        live: &mut impl FnMut() -> bool,
    ) -> Result<(), TransferError> {
        if self
            .bytes
            .checked_add(bytes.len() as u64)
            .is_none_or(|n| n > self.expected_bytes || n > self.limits.max_archive_bytes)
        {
            return Err(TransferError::ArchiveLimit);
        }
        while !bytes.is_empty() {
            checkpoint(live)?;
            let result = self.output.write(bytes);
            checkpoint(live)?;
            match result {
                Ok(0) => {
                    return Err(TransferError::Io {
                        operation: "write LFS archive",
                        kind: io::ErrorKind::WriteZero,
                    });
                }
                Ok(count) => {
                    DigestHasher::update(&mut self.hash, &bytes[..count]);
                    self.bytes += count as u64;
                    bytes = &bytes[count..];
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(io_error("write LFS archive", error)),
            }
        }
        Ok(())
    }

    pub fn finish(mut self, live: &mut impl FnMut() -> bool) -> Result<Seal, TransferError> {
        checkpoint(live)?;
        if self.poisoned
            || self.objects != self.expected_objects
            || self.payload != self.expected_payload
            || self.bytes != self.expected_bytes
        {
            return Err(TransferError::Incomplete);
        }
        loop {
            checkpoint(live)?;
            let result = self.output.flush();
            checkpoint(live)?;
            match result {
                Ok(()) => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(io_error("flush LFS archive", error)),
            }
        }
        let digest = DigestHasher::finish(self.hash);
        checkpoint(live)?;
        Ok(Seal {
            digest,
            bytes: self.bytes,
            payload_bytes: self.payload,
        })
    }
}

fn encode_header(source: SourceIdentity, count: usize, payload: u64) -> [u8; HEADER_BYTES] {
    let mut bytes = [0; HEADER_BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..24].copy_from_slice(source.tenant.as_bytes());
    bytes[24..40].copy_from_slice(source.repository.as_bytes());
    bytes[40..56].copy_from_slice(source.incarnation.as_bytes());
    bytes[56] = match source.format {
        GitHashAlgorithm::Sha1 => 1,
        GitHashAlgorithm::Sha256 => 2,
    };
    bytes[57..65].copy_from_slice(&source.head_generation.to_be_bytes());
    bytes[65..81].copy_from_slice(&source.head_token);
    bytes[81..113].copy_from_slice(&source.head_sha256);
    bytes[113..117].copy_from_slice(&(count as u32).to_be_bytes());
    bytes[117..125].copy_from_slice(&payload.to_be_bytes());
    bytes
}

/// One entry whose payload was completely verified during the archive pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedRecord {
    object: LfsObject,
    payload_offset: u64,
}
impl VerifiedRecord {
    #[must_use]
    pub const fn object(&self) -> LfsObject {
        self.object
    }
    #[must_use]
    pub const fn payload_offset(&self) -> u64 {
        self.payload_offset
    }
}

/// Only complete structural, payload, and externally pinned digest verification
/// can construct this value. It grants no destination publication authority.
#[derive(Debug)]
pub struct VerifiedArchive {
    source: SourceIdentity,
    records: Vec<VerifiedRecord>,
    seal: Seal,
}
impl VerifiedArchive {
    #[must_use]
    pub const fn source(&self) -> &SourceIdentity {
        &self.source
    }
    #[must_use]
    pub fn records(&self) -> &[VerifiedRecord] {
        &self.records
    }
    #[must_use]
    pub const fn seal(&self) -> Seal {
        self.seal
    }
}

/// Validate from offset zero using constant payload memory. No offsets escape
/// until strict EOF and the caller's independently trusted total digest match.
pub fn verify(
    input: &mut (impl Read + Seek),
    expected_sha256: [u8; 32],
    limits: TransferLimits,
    live: &mut impl FnMut() -> bool,
) -> Result<VerifiedArchive, TransferError> {
    checkpoint(live)?;
    limits.validate()?;
    if limits.max_archive_bytes < HEADER_BYTES as u64 {
        return Err(TransferError::ArchiveLimit);
    }
    input
        .seek(SeekFrom::Start(0))
        .map_err(|e| io_error("rewind LFS archive", e))?;
    checkpoint(live)?;
    let mut header = [0; HEADER_BYTES];
    read_exact(input, &mut header, live)?;
    let mut fields = Fields(&header);
    if fields.array::<8>()? != *MAGIC {
        return Err(TransferError::InvalidEncoding("LFS archive version"));
    }
    let tenant = TenantId::from_bytes(fields.array()?);
    let repository = RepositoryId::from_bytes(fields.array()?);
    let incarnation = RepositoryIncarnationId::from_bytes(fields.array()?);
    let format = match fields.array::<1>()?[0] {
        1 => GitHashAlgorithm::Sha1,
        2 => GitHashAlgorithm::Sha256,
        _ => return Err(TransferError::InvalidEncoding("Git object format")),
    };
    let source = SourceIdentity {
        tenant,
        repository,
        incarnation,
        format,
        head_generation: u64::from_be_bytes(fields.array()?),
        head_token: fields.array()?,
        head_sha256: fields.array()?,
    };
    if source.head_generation == 0 {
        return Err(TransferError::InvalidEncoding(
            "zero source head generation",
        ));
    }
    let count = u32::from_be_bytes(fields.array()?) as usize;
    let declared_payload = u64::from_be_bytes(fields.array()?);
    let expected_bytes = limits.admit(count, declared_payload)?;
    if count == 0 && declared_payload != 0 {
        return Err(TransferError::InvalidEncoding(
            "payload without LFS objects",
        ));
    }
    let mut records = Vec::new();
    records
        .try_reserve_exact(count)
        .map_err(|_| TransferError::Io {
            operation: "allocate LFS record inventory",
            kind: io::ErrorKind::OutOfMemory,
        })?;
    let mut archive_hash = Sha256Hasher::new();
    DigestHasher::update(&mut archive_hash, &header);
    let mut bytes = HEADER_BYTES as u64;
    let mut payload = 0_u64;
    let mut previous = None;
    let mut chunk = [0; CHUNK_BYTES];
    for _ in 0..count {
        let mut header = [0; RECORD_BYTES as usize];
        read_exact(input, &mut header, live)?;
        DigestHasher::update(&mut archive_hash, &header);
        bytes += RECORD_BYTES;
        let mut fields = Fields(&header);
        let object = LfsObject {
            oid: LfsOid(fields.array()?),
            size: u64::from_be_bytes(fields.array()?),
        };
        if previous.is_some_and(|oid| oid >= object.oid) {
            return Err(TransferError::ObjectOrder);
        }
        if object.size > limits.max_object_bytes {
            return Err(TransferError::ObjectLimit);
        }
        payload = payload
            .checked_add(object.size)
            .filter(|n| *n <= declared_payload)
            .ok_or(TransferError::PayloadLimit)?;
        let offset = bytes;
        let mut object_hash = Sha256Hasher::new();
        let mut remaining = object.size;
        while remaining != 0 {
            let length = remaining.min(CHUNK_BYTES as u64) as usize;
            read_exact(input, &mut chunk[..length], live)?;
            DigestHasher::update(&mut archive_hash, &chunk[..length]);
            DigestHasher::update(&mut object_hash, &chunk[..length]);
            checkpoint(live)?;
            remaining -= length as u64;
            bytes += length as u64;
        }
        if DigestHasher::finish(object_hash) != object.oid.0 {
            return Err(TransferError::PayloadMismatch);
        }
        checkpoint(live)?;
        records.push(VerifiedRecord {
            object,
            payload_offset: offset,
        });
        previous = Some(object.oid);
    }
    if payload != declared_payload || bytes != expected_bytes {
        return Err(TransferError::InvalidEncoding(
            "aggregate LFS payload length",
        ));
    }
    require_eof(input, live)?;
    let digest = DigestHasher::finish(archive_hash);
    if digest != expected_sha256 {
        return Err(TransferError::DigestMismatch);
    }
    checkpoint(live)?;
    Ok(VerifiedArchive {
        source,
        records,
        seal: Seal {
            digest,
            bytes,
            payload_bytes: payload,
        },
    })
}

struct Fields<'a>(&'a [u8]);
impl Fields<'_> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N], TransferError> {
        let (field, rest) = self.0.split_at_checked(N).ok_or(TransferError::Truncated)?;
        self.0 = rest;
        field.try_into().map_err(|_| TransferError::Truncated)
    }
}
