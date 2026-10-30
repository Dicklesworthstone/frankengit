//! Request-scoped ordering hints over an unchanged canonical object source.
//!
//! The selected closure owns these hints. They affect only the frozen pack
//! ordering policy, never object identity, disclosure, closure or authority.

use super::{
    CanonicalBlobStream, CanonicalObjectSource, CanonicalPackObject, ObjectId, ObjectType,
    PackOrderKey, PackWriteError,
};
use fgit_crypto::{DigestHasher, Sha256Hasher};

/// Frozen domain for a derived pack-order hint, not an immutable object ID.
const BASENAME_HASH_DOMAIN: &[u8] = b"frankengit/pack-basename-path-hash/v1\0";

/// Hash an exact Git tree-entry basename into a stable pack-order hint.
///
/// The frozen preimage is `b"frankengit/pack-basename-path-hash/v1\0"`
/// followed by `name`; the result is the first eight SHA-256 digest bytes,
/// interpreted as a big-endian `u64`. No Unicode conversion, case folding,
/// path parsing or platform-specific normalization occurs. Equal basename
/// bytes therefore cluster across directories, including non-UTF-8 names.
///
/// This is only a deterministic grouping hint. A collision may change delta
/// candidates but cannot establish identity or skip native verification.
#[must_use]
pub fn basename_path_hash(name: &[u8]) -> u64 {
    let mut hash = Sha256Hasher::new();
    hash.update(BASENAME_HASH_DOMAIN);
    hash.update(name);
    let digest = hash.finish();
    u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ])
}

/// Overlay prepared pack-order hints without copying object bodies or readers.
///
/// `lookup` must return stable hints for the duration of a materialization,
/// normally from its already prepared, ID-sorted selected-object keys. Missing
/// hints preserve the underlying metadata, including for external thin bases.
/// A supplied key must name the requested native ID and the source's actual
/// native type; the adapter never relabels either to make a key agree.
///
/// The adapter performs exactly the requested source load/open and changes
/// only `recency` and `path_hash` in its owned result. Native body verification,
/// deadlines, resource bounds and artifact promotion remain the pack writer's
/// responsibility.
pub struct PackOrderingSource<'a, S: ?Sized, L> {
    source: &'a S,
    lookup: L,
}

impl<'a, S: CanonicalObjectSource + ?Sized, L> PackOrderingSource<'a, S, L>
where
    L: Fn(&ObjectId) -> Option<PackOrderKey>,
{
    /// Borrow a canonical source and the prepared selection's immutable lookup.
    #[must_use]
    pub const fn new(source: &'a S, lookup: L) -> Self {
        Self { source, lookup }
    }

    fn key(&self, id: &ObjectId) -> Result<Option<PackOrderKey>, PackWriteError> {
        let key = (self.lookup)(id);
        if let Some(key) = key {
            require_identity(id, key.id)?;
        }
        Ok(key)
    }
}

impl<S: CanonicalObjectSource + ?Sized, L> CanonicalObjectSource for PackOrderingSource<'_, S, L>
where
    L: Fn(&ObjectId) -> Option<PackOrderKey>,
{
    fn load(&self, id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
        let key = self.key(id)?;
        let mut object = self.source.load(id)?;
        require_identity(id, object.id)?;
        if let Some(key) = key {
            if object.object_type != key.object_type {
                return Err(PackWriteError::SourceOrderMismatch(*id));
            }
            object.recency = key.recency;
            object.path_hash = key.path_hash;
        }
        Ok(object)
    }

    fn open_blob(&self, id: &ObjectId) -> Result<Option<CanonicalBlobStream<'_>>, PackWriteError> {
        let key = self.key(id)?;
        let Some(mut stream) = self.source.open_blob(id)? else {
            return Ok(None);
        };
        let native = stream.order_key();
        require_identity(id, native.id)?;
        if native.object_type != ObjectType::Blob
            || key.is_some_and(|key| key.object_type != native.object_type)
        {
            return Err(PackWriteError::SourceOrderMismatch(*id));
        }
        if let Some(key) = key {
            stream.set_ordering_metadata(key.recency, key.path_hash);
        }
        Ok(Some(stream))
    }
}

fn require_identity(requested: &ObjectId, returned: ObjectId) -> Result<(), PackWriteError> {
    if *requested == returned {
        Ok(())
    } else {
        Err(PackWriteError::SourceIdentityMismatch {
            requested: *requested,
            returned,
        })
    }
}

#[cfg(test)]
mod tests;
