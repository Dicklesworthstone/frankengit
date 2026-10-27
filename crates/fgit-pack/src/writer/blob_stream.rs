//! Bounded, tentative blob input for the versioned streaming pack profiles.

use super::{
    CanonicalPackObject, Deadline, DeflateReceipt, ENCODER_INPUT_CHUNK_BYTES, ObjectFormat,
    ObjectId, ObjectType, PackArtifactSink, PackEntryEncoder, PackError, PackOrderKey,
    PackWriteError, PackWriteProfile, StreamingEmitter, checkpoint, encode_entry_header, fmt,
};
use fgit_crypto::{GitObjectHasher, NativeObjectIdentity, Sha1, Sha256};

/// A synchronous bounded read into caller-owned storage. Returning zero means
/// exact EOF, including successful completion of any source-side commitment
/// checks. Bytes returned before EOF are tentative: consumers must not expose
/// them before the whole pack's verification and promotion boundary.
/// Implementations own their I/O deadline; the pack writer checkpoints before
/// and after every call but cannot interrupt a blocking operating-system read.
pub trait CanonicalBlobReader {
    fn read(&mut self, output: &mut [u8]) -> Result<usize, PackWriteError>;
}

/// One blob's declared metadata and exclusively owned tentative reader.
pub struct CanonicalBlobStream<'a> {
    key: PackOrderKey,
    length: usize,
    reader: Box<dyn CanonicalBlobReader + 'a>,
}

impl<'a> CanonicalBlobStream<'a> {
    #[must_use]
    pub fn new(key: PackOrderKey, length: usize, reader: impl CanonicalBlobReader + 'a) -> Self {
        Self {
            key,
            length,
            reader: Box::new(reader),
        }
    }

    #[must_use]
    pub const fn order_key(&self) -> PackOrderKey {
        self.key
    }

    #[must_use]
    pub const fn length(&self) -> usize {
        self.length
    }

    pub(super) fn from_buffered(object: CanonicalPackObject) -> Self {
        Self::new(
            PackOrderKey {
                id: object.id,
                object_type: object.object_type,
                recency: object.recency,
                path_hash: object.path_hash,
            },
            object.body.len(),
            BufferedBlob {
                bytes: object.body,
                position: 0,
            },
        )
    }

    pub(super) fn validate_key(&self, expected: PackOrderKey) -> Result<(), PackWriteError> {
        if self.key.id != expected.id {
            return Err(PackWriteError::SourceIdentityMismatch {
                requested: expected.id,
                returned: self.key.id,
            });
        }
        if self.key != expected || self.key.object_type != ObjectType::Blob {
            return Err(PackWriteError::SourceOrderMismatch(expected.id));
        }
        Ok(())
    }

    pub(super) fn into_buffered(
        mut self,
        deadline: &mut impl Deadline,
    ) -> Result<CanonicalPackObject, PackWriteError> {
        let mut body = Vec::new();
        body.try_reserve_exact(self.length)
            .map_err(|_| PackError::AllocationFailed {
                requested: self.length,
            })?;
        let mut verified = VerifiedBlobReader::new(self.key.id, self.length, &mut *self.reader)?;
        let mut chunk = [0; ENCODER_INPUT_CHUNK_BYTES];
        loop {
            checkpoint(deadline)?;
            let read = verified.read(&mut chunk);
            checkpoint(deadline)?;
            let count = read?;
            if count == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..count]);
        }
        verified.finish()?;
        Ok(CanonicalPackObject::new(
            self.key.id,
            ObjectType::Blob,
            body,
            Vec::new(),
            self.key.recency,
            self.key.path_hash,
        ))
    }
}

struct BufferedBlob {
    bytes: Vec<u8>,
    position: usize,
}

impl CanonicalBlobReader for BufferedBlob {
    fn read(&mut self, output: &mut [u8]) -> Result<usize, PackWriteError> {
        let count = output.len().min(self.bytes.len() - self.position);
        output[..count].copy_from_slice(&self.bytes[self.position..self.position + count]);
        self.position += count;
        Ok(count)
    }
}

impl fmt::Debug for CanonicalBlobStream<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalBlobStream")
            .field("key", &self.key)
            .field("length", &self.length)
            .finish_non_exhaustive()
    }
}

enum NativeBlobHash {
    Sha1(GitObjectHasher<Sha1>),
    Sha256(GitObjectHasher<Sha256>),
}

impl NativeBlobHash {
    fn new(id: ObjectId, length: usize) -> Result<Self, PackWriteError> {
        let length = u64::try_from(length).map_err(|_| PackError::IntegerOverflow {
            context: "streamed blob length",
        })?;
        Ok(match id.algorithm() {
            ObjectFormat::Sha1 => Self::Sha1(GitObjectHasher::new(ObjectType::Blob, length)),
            ObjectFormat::Sha256 => Self::Sha256(GitObjectHasher::new(ObjectType::Blob, length)),
        })
    }

    fn update(&mut self, bytes: &[u8]) -> Result<(), PackWriteError> {
        match self {
            Self::Sha1(hash) => hash.update(bytes),
            Self::Sha256(hash) => hash.update(bytes),
        }
        .map_err(|_| PackError::NativeObjectIdMismatch.into())
    }

    fn finish(self) -> Result<ObjectId, PackWriteError> {
        match self {
            Self::Sha1(hash) => hash.finish().map(|id| id.erase()),
            Self::Sha256(hash) => hash.finish().map(|id| id.erase()),
        }
        .map_err(|_| PackError::NativeObjectIdMismatch.into())
    }
}

/// Protects even custom encoders from accepting a short, growing, or forged
/// source. The final one-byte probe is never included in the native hash.
struct VerifiedBlobReader<'a> {
    reader: &'a mut dyn CanonicalBlobReader,
    id: ObjectId,
    declared: usize,
    consumed: usize,
    eof: bool,
    hash: NativeBlobHash,
}

impl<'a> VerifiedBlobReader<'a> {
    fn new(
        id: ObjectId,
        declared: usize,
        reader: &'a mut dyn CanonicalBlobReader,
    ) -> Result<Self, PackWriteError> {
        Ok(Self {
            reader,
            id,
            declared,
            consumed: 0,
            eof: false,
            hash: NativeBlobHash::new(id, declared)?,
        })
    }

    const fn length_error(&self, observed: usize) -> PackWriteError {
        PackWriteError::SourceLengthMismatch {
            id: self.id,
            declared: self.declared,
            observed,
        }
    }

    fn finish(self) -> Result<(), PackWriteError> {
        if !self.eof || self.consumed != self.declared {
            return Err(self.length_error(self.consumed));
        }
        if self.hash.finish()? != self.id {
            return Err(PackError::NativeObjectIdMismatch.into());
        }
        Ok(())
    }
}

impl CanonicalBlobReader for VerifiedBlobReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> Result<usize, PackWriteError> {
        if output.is_empty() || self.eof {
            return Ok(0);
        }
        let remaining = self.declared - self.consumed;
        if remaining == 0 {
            let mut probe = [0];
            let count = self.reader.read(&mut probe)?;
            if count > probe.len() {
                return Err(PackWriteError::SourceReadOverflow {
                    count,
                    capacity: probe.len(),
                });
            }
            if count != 0 {
                let observed =
                    self.declared
                        .checked_add(count)
                        .ok_or(PackError::IntegerOverflow {
                            context: "streamed blob excess length",
                        })?;
                return Err(self.length_error(observed));
            }
            self.eof = true;
            return Ok(0);
        }
        let capacity = remaining.min(output.len());
        let count = self.reader.read(&mut output[..capacity])?;
        if count > capacity {
            return Err(PackWriteError::SourceReadOverflow { count, capacity });
        }
        if count == 0 {
            return Err(self.length_error(self.consumed));
        }
        self.hash.update(&output[..count])?;
        self.consumed += count;
        Ok(count)
    }
}

pub(super) fn emit_blob<S: PackArtifactSink>(
    emitter: &mut StreamingEmitter<'_, '_, S>,
    mut blob: CanonicalBlobStream<'_>,
    offsets: &mut Vec<u64>,
    encoder: &mut impl PackEntryEncoder,
    profile: PackWriteProfile,
    deadline: &mut impl Deadline,
) -> Result<DeflateReceipt, PackWriteError> {
    checkpoint(deadline)?;
    offsets
        .try_reserve(1)
        .map_err(|_| PackError::AllocationFailed { requested: 1 })?;
    offsets.push(u64::try_from(emitter.bytes_written()).map_err(|_| {
        PackError::IntegerOverflow {
            context: "pack entry offset",
        }
    })?);
    emitter.emit_hashed(&encode_entry_header(
        ObjectType::Blob.type_code(),
        blob.length,
    )?)?;
    let start = emitter.bytes_written();
    let mut input = VerifiedBlobReader::new(blob.key.id, blob.length, &mut *blob.reader)?;
    let receipt = encoder.encode_blob_stream(&mut input, blob.length, deadline, &mut |bytes| {
        emitter.emit_hashed(bytes)
    })?;
    checkpoint(deadline)?;
    input.finish()?;
    if receipt.input_bytes != blob.length
        || receipt.output_bytes != emitter.bytes_written() - start
        || receipt.profile != profile.compression
    {
        return Err(PackWriteError::CompressionReceiptMismatch);
    }
    Ok(receipt)
}

#[cfg(test)]
mod tests;
