//! Tentative file-backed blob reads, authenticated only at exact EOF.

use super::*;
use std::io::Read;

use fgit_crypto::{
    DigestHasher, GitObjectHasher, GitObjectKind, IdentityDomain, NativeObjectIdentity, Sha1,
    Sha256, Sha256Hasher,
};

const CHUNK_BYTES: usize = 64 * 1024;

/// A bounded reader over one checked descriptor. Chunks remain tentative until
/// `read_tentative` reaches exact EOF and verifies both the stronger payload
/// commitment and native Git identity. This is deliberately not a verified
/// range-read API: callers must retain private custody of derived output until
/// `is_verified()` is true. Dropping the stream closes its sole file handle.
#[derive(Debug)]
pub struct LocalBlobStream {
    file: File,
    envelope: ObjectEnvelope,
    consumed: u64,
    native: Option<NativeHash>,
    strong: Option<Sha256Hasher>,
    verified: bool,
    refusal: Option<StoreRefusal>,
}

#[derive(Debug)]
enum NativeHash {
    Sha1(GitObjectHasher<Sha1>),
    Sha256(GitObjectHasher<Sha256>),
}

impl NativeHash {
    fn new(id: GitOid, length: u64) -> Self {
        match id.algorithm() {
            fgit_types::GitHashAlgorithm::Sha1 => {
                Self::Sha1(GitObjectHasher::new(GitObjectKind::Blob, length))
            }
            fgit_types::GitHashAlgorithm::Sha256 => {
                Self::Sha256(GitObjectHasher::new(GitObjectKind::Blob, length))
            }
        }
    }

    fn update(&mut self, bytes: &[u8]) -> Result<(), StoreRefusal> {
        match self {
            Self::Sha1(hash) => hash.update(bytes),
            Self::Sha256(hash) => hash.update(bytes),
        }
        .map_err(|_| StoreRefusal::NativeObjectIdentityMismatch)
    }

    fn finish(self) -> Result<GitOid, StoreRefusal> {
        match self {
            Self::Sha1(hash) => hash.finish().map(|id| id.erase()),
            Self::Sha256(hash) => hash.finish().map(|id| id.erase()),
        }
        .map_err(|_| StoreRefusal::NativeObjectIdentityMismatch)
    }
}

impl LocalFilesystemFabric {
    /// Opens one blob under independent stored-file, envelope, and payload
    /// limits without loading its body. Namespace, requested identity, kind,
    /// framing and exact declared/file length are checked on the same handle.
    /// The caller owns request cancellation around each bounded read and must
    /// not disclose tentative bytes before the stream verifies at exact EOF.
    pub fn open_blob_stream_bounded(
        &self,
        identity: GitOid,
        maximum_payload_bytes: u64,
    ) -> Result<LocalBlobStream, StoreRefusal> {
        let (file, bytes, stored) = bounded_read::open_envelope(
            &self.object_path(identity),
            self.max_stored_object_bytes,
            self.envelope_limits.max_envelope_bytes,
        )?;
        let envelope = ObjectEnvelope::decode(&bytes, &self.envelope_limits)?;
        if envelope.namespace() != self.namespace {
            return Err(StoreRefusal::NamespaceMismatch);
        }
        if envelope.object_identity() != identity {
            return Err(StoreRefusal::StoredObjectReconstructionMismatch {
                requested: identity,
                reconstructed: envelope.object_identity(),
            });
        }
        if envelope.object_kind() != ObjectKind::Blob {
            return Err(StoreRefusal::NativeObjectIdentityMismatch);
        }
        if envelope.declared_length() != stored {
            return Err(StoreRefusal::MalformedStoredObject);
        }
        if stored > maximum_payload_bytes {
            return Err(StoreRefusal::StreamingBudgetExceeded {
                offered: stored,
                maximum: maximum_payload_bytes,
            });
        }
        // The registered strong commitment hashes the domain header followed
        // by Git's type/length/NUL framing and the exact payload. Header space
        // is bounded independently of the blob size.
        let native_header = format!("blob {stored}\0");
        let framed_length = stored
            .checked_add(native_header.len() as u64)
            .ok_or(StoreRefusal::LengthOverflow)?;
        let mut strong = Sha256Hasher::new();
        strong.update(&fgit_crypto::internal_id_preimage_header(
            IdentityDomain::GitPayloadCommitment,
            fgit_crypto::GIT_PAYLOAD_SCHEMA,
            framed_length,
        ));
        strong.update(native_header.as_bytes());
        Ok(LocalBlobStream {
            file,
            envelope,
            consumed: 0,
            native: Some(NativeHash::new(identity, stored)),
            strong: Some(strong),
            verified: false,
            refusal: None,
        })
    }
}

impl LocalBlobStream {
    #[must_use]
    pub const fn identity(&self) -> GitOid {
        self.envelope.object_identity()
    }

    #[must_use]
    pub const fn declared_length(&self) -> u64 {
        self.envelope.declared_length()
    }

    #[must_use]
    pub const fn is_verified(&self) -> bool {
        self.verified
    }

    /// Reads at most 64 KiB into a nonempty caller buffer. Zero means exact,
    /// authenticated EOF. A failed read is latched, so a retry can never turn
    /// a partially checked stream into successful completion.
    pub fn read_tentative(&mut self, output: &mut [u8]) -> Result<usize, StoreRefusal> {
        if let Some(refusal) = &self.refusal {
            return Err(refusal.clone());
        }
        let result = self.read_next(output);
        if let Err(refusal) = &result {
            // EINTR made no progress and remains retryable by the owner, which
            // can check its request deadline before retrying the OS call.
            if !matches!(
                refusal,
                StoreRefusal::StorageIo {
                    kind: std::io::ErrorKind::Interrupted,
                    ..
                }
            ) {
                self.refusal = Some(refusal.clone());
            }
        }
        result
    }

    fn read_next(&mut self, output: &mut [u8]) -> Result<usize, StoreRefusal> {
        if output.is_empty() {
            return Err(StoreRefusal::InvalidStreamingBudget);
        }
        if self.verified {
            return Ok(0);
        }
        let remaining = self.envelope.declared_length() - self.consumed;
        if remaining == 0 {
            let mut probe = [0];
            if self.file.read(&mut probe).map_err(io_refusal)? != 0 {
                return Err(StoreRefusal::MalformedStoredObject);
            }
            let strong = self
                .strong
                .take()
                .ok_or(StoreRefusal::PayloadCommitmentMismatch)?;
            if strong.finish() != self.envelope.payload_commitment() {
                return Err(StoreRefusal::PayloadCommitmentMismatch);
            }
            let native = self
                .native
                .take()
                .ok_or(StoreRefusal::NativeObjectIdentityMismatch)?;
            if native.finish()? != self.envelope.object_identity() {
                return Err(StoreRefusal::NativeObjectIdentityMismatch);
            }
            self.verified = true;
            return Ok(0);
        }
        let capacity = output
            .len()
            .min(CHUNK_BYTES)
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let count = self
            .file
            .read(&mut output[..capacity])
            .map_err(io_refusal)?;
        if count == 0 {
            return Err(StoreRefusal::MalformedStoredObject);
        }
        self.native
            .as_mut()
            .ok_or(StoreRefusal::NativeObjectIdentityMismatch)?
            .update(&output[..count])?;
        self.strong
            .as_mut()
            .ok_or(StoreRefusal::PayloadCommitmentMismatch)?
            .update(&output[..count]);
        self.consumed += count as u64;
        Ok(count)
    }
}

fn io_refusal(error: std::io::Error) -> StoreRefusal {
    StoreRefusal::StorageIo {
        operation: StorageOperation::ReadBody,
        kind: error.kind(),
    }
}

#[cfg(test)]
#[path = "local_blob_stream/tests.rs"]
mod tests;
