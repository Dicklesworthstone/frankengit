//! Tentative blob reads and bounded native-object integrity verification.
//! Both paths authenticate the checked descriptor at exact EOF.

use super::{
    File, GitOid, LocalFilesystemFabric, ObjectEnvelope, ObjectKind, StorageOperation,
    StoreRefusal, bounded_read,
};
use std::io::Read;

use fgit_crypto::{
    DigestHasher, GitObjectHasher, GitObjectKind, IdentityDomain, NativeObjectIdentity, Sha1,
    Sha256, Sha256Hasher,
};

const CHUNK_BYTES: usize = 64 * 1024;

/// Integrity of the native bytes read from one checked descriptor at exact EOF.
/// This receipt grants neither placement nor authority, and does not certify
/// graph structure or the health of a later read. Only this module constructs it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedObjectIntegrity {
    identity: GitOid,
    kind: ObjectKind,
    payload_length: u64,
}

impl VerifiedObjectIntegrity {
    #[must_use]
    pub const fn identity(self) -> GitOid {
        self.identity
    }

    #[must_use]
    pub const fn object_kind(self) -> ObjectKind {
        self.kind
    }

    #[must_use]
    pub const fn payload_length(self) -> u64 {
        self.payload_length
    }
}

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
pub(super) enum NativeHash {
    Sha1(GitObjectHasher<Sha1>),
    Sha256(GitObjectHasher<Sha256>),
}

impl NativeHash {
    pub(super) fn new(id: GitOid, length: u64) -> Self {
        Self::for_kind(id, GitObjectKind::Blob, length)
    }

    fn for_kind(id: GitOid, kind: GitObjectKind, length: u64) -> Self {
        match id.algorithm() {
            fgit_types::GitHashAlgorithm::Sha1 => Self::Sha1(GitObjectHasher::new(kind, length)),
            fgit_types::GitHashAlgorithm::Sha256 => {
                Self::Sha256(GitObjectHasher::new(kind, length))
            }
        }
    }

    pub(super) fn update(&mut self, bytes: &[u8]) -> Result<(), StoreRefusal> {
        match self {
            Self::Sha1(hash) => hash.update(bytes),
            Self::Sha256(hash) => hash.update(bytes),
        }
        .map_err(|_| StoreRefusal::NativeObjectIdentityMismatch)
    }

    pub(super) fn finish(self) -> Result<GitOid, StoreRefusal> {
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
        self.open_native_stream_bounded(identity, maximum_payload_bytes, Some(ObjectKind::Blob))
    }

    /// Verify native identity, exact length and the original strong payload
    /// commitment without allocating the whole body. The payload ceiling is
    /// checked on the same descriptor before body reads; every read is at most
    /// 64 KiB and is bracketed by the caller's cancellation/budget checkpoint.
    ///
    /// Checkpoints also bracket opening and its refusals, so post-I/O expiry
    /// outranks a storage failure. EINTR is retried only after those checkpoints.
    /// Nothing is disclosed, placed, repaired or selected by this operation.
    pub fn verify_object_integrity_bounded(
        &self,
        identity: GitOid,
        maximum_payload_bytes: u64,
        live: &mut impl FnMut() -> bool,
    ) -> Result<VerifiedObjectIntegrity, StoreRefusal> {
        integrity_checkpoint(live)?;
        let opened = self.open_native_stream_bounded(identity, maximum_payload_bytes, None);
        integrity_checkpoint(live)?;
        let mut stream = opened?;
        let mut buffer = [0; CHUNK_BYTES];
        loop {
            integrity_checkpoint(live)?;
            let read = stream.read_tentative(&mut buffer);
            integrity_checkpoint(live)?;
            match read {
                Ok(0) => {
                    return Ok(VerifiedObjectIntegrity {
                        identity: stream.identity(),
                        kind: stream.envelope().object_kind(),
                        payload_length: stream.declared_length(),
                    });
                }
                Ok(_) => {}
                Err(StoreRefusal::StorageIo {
                    kind: std::io::ErrorKind::Interrupted,
                    ..
                }) => {}
                Err(error) => return Err(error),
            }
        }
    }

    // Keep the general stream private: the public streaming API still opens
    // blobs only, while integrity scans consume all chunks before returning.
    fn open_native_stream_bounded(
        &self,
        identity: GitOid,
        maximum_payload_bytes: u64,
        expected_kind: Option<ObjectKind>,
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
        if expected_kind.is_some_and(|kind| envelope.object_kind() != kind) {
            return Err(StoreRefusal::NativeObjectIdentityMismatch);
        }
        let kind = native_kind(envelope.object_kind())?;
        if envelope.declared_length() != stored {
            return Err(StoreRefusal::MalformedStoredObject);
        }
        if stored > maximum_payload_bytes {
            return Err(StoreRefusal::StreamingBudgetExceeded {
                offered: stored,
                maximum: maximum_payload_bytes,
            });
        }
        let strong = strong_hasher_for_kind(kind, stored)?;
        Ok(LocalBlobStream {
            file,
            envelope,
            consumed: 0,
            native: Some(NativeHash::for_kind(identity, kind, stored)),
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

    /// The envelope's claimed payload commitment, authenticated only at EOF.
    #[must_use]
    pub const fn payload_commitment(&self) -> [u8; 32] {
        self.envelope.payload_commitment()
    }

    pub(super) const fn envelope(&self) -> &ObjectEnvelope {
        &self.envelope
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

/// Registered strong commitment framing shared by bounded blob reads/writes.
pub(super) fn strong_hasher(length: u64) -> Result<Sha256Hasher, StoreRefusal> {
    strong_hasher_for_kind(GitObjectKind::Blob, length)
}

fn strong_hasher_for_kind(kind: GitObjectKind, length: u64) -> Result<Sha256Hasher, StoreRefusal> {
    let native_header = format!("{} {length}\0", kind.label());
    let framed_length = length
        .checked_add(native_header.len() as u64)
        .ok_or(StoreRefusal::LengthOverflow)?;
    let mut strong = Sha256Hasher::new();
    strong.update(&fgit_crypto::internal_id_preimage_header(
        IdentityDomain::GitPayloadCommitment,
        fgit_crypto::GIT_PAYLOAD_SCHEMA,
        framed_length,
    ));
    strong.update(native_header.as_bytes());
    Ok(strong)
}

fn native_kind(kind: ObjectKind) -> Result<GitObjectKind, StoreRefusal> {
    match kind {
        ObjectKind::Commit => Ok(GitObjectKind::Commit),
        ObjectKind::Tree => Ok(GitObjectKind::Tree),
        ObjectKind::Blob => Ok(GitObjectKind::Blob),
        ObjectKind::Tag => Ok(GitObjectKind::Tag),
        ObjectKind::Internal => Err(StoreRefusal::NativeObjectIdentityMismatch),
    }
}

fn integrity_checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), StoreRefusal> {
    if live() {
        Ok(())
    } else {
        Err(StoreRefusal::RuntimeCheckpointRejected)
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
