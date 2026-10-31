//! Exact interoperable FGCHNK01 byte-range hints. The original signed archive
//! seal, never this self-checksummed catalog, authenticates reconstruction.

use fgit_crypto::{DigestHasher, Sha256Hasher};

use super::super::archive::stream::Seal;

pub(super) const CHUNK_BYTES: u64 = 4 * 1024 * 1024;
const HEADER_BYTES: usize = 56;
const DIGEST_BYTES: usize = 32;
const MAGIC: &[u8; 8] = b"FGCHNK01";
const MAX_ARCHIVE_BYTES: u64 = 1 << 40;
pub(super) const MAX_CATALOG_BYTES: usize =
    HEADER_BYTES + DIGEST_BYTES + (MAX_ARCHIVE_BYTES / CHUNK_BYTES) as usize * DIGEST_BYTES;

pub(super) struct Catalog {
    pub(super) archive: Seal,
    hashes: Vec<[u8; DIGEST_BYTES]>,
}

impl Catalog {
    pub(super) fn new(archive: Seal) -> Result<Self, String> {
        let count = chunk_count(archive.bytes)?;
        let mut hashes = Vec::new();
        hashes
            .try_reserve_exact(count)
            .map_err(|_| "backup chunk catalog allocation refused")?;
        Ok(Self { archive, hashes })
    }

    pub(super) fn push(&mut self, digest: [u8; DIGEST_BYTES]) -> Result<(), String> {
        if self.hashes.len() >= chunk_count(self.archive.bytes)? {
            return Err("backup chunk catalog has too many ranges".into());
        }
        self.hashes.push(digest);
        Ok(())
    }

    pub(super) fn count(&self) -> usize {
        self.hashes.len()
    }

    pub(super) fn hash(&self, index: usize) -> &[u8; DIGEST_BYTES] {
        &self.hashes[index]
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>, String> {
        let count = chunk_count(self.archive.bytes)?;
        if self.hashes.len() != count {
            return Err("backup chunk catalog has an incomplete range set".into());
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(encoded_len(count))
            .map_err(|_| "backup chunk catalog allocation refused")?;
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.archive.bytes.to_be_bytes());
        bytes.extend_from_slice(&self.archive.digest);
        bytes.extend_from_slice(&(CHUNK_BYTES as u32).to_be_bytes());
        bytes.extend_from_slice(&(count as u32).to_be_bytes());
        for hash in &self.hashes {
            bytes.extend_from_slice(hash);
        }
        let trailer = digest(&bytes);
        bytes.extend_from_slice(&trailer);
        Ok(bytes)
    }

    pub(super) fn parse(bytes: &[u8], original: Seal) -> Result<Self, String> {
        // The independently authenticated size bounds count/allocation before
        // any catalog field can select work or influence its expected length.
        let count = chunk_count(original.bytes)?;
        if bytes.len() != encoded_len(count)
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes[8..16] != original.bytes.to_be_bytes()
            || bytes[16..48] != original.digest
            || bytes[48..52] != (CHUNK_BYTES as u32).to_be_bytes()
            || bytes[52..56] != (count as u32).to_be_bytes()
            || digest(&bytes[..bytes.len() - DIGEST_BYTES]) != bytes[bytes.len() - DIGEST_BYTES..]
        {
            return Err("backup chunk catalog does not match its original signed archive".into());
        }
        let mut catalog = Self::new(original)?;
        for hash in bytes[HEADER_BYTES..bytes.len() - DIGEST_BYTES].chunks_exact(DIGEST_BYTES) {
            let mut value = [0; DIGEST_BYTES];
            value.copy_from_slice(hash);
            catalog.hashes.push(value);
        }
        Ok(catalog)
    }
}

fn chunk_count(bytes: u64) -> Result<usize, String> {
    if bytes == 0 || bytes > MAX_ARCHIVE_BYTES {
        return Err("backup chunk archive length must be in 1..=1099511627776".into());
    }
    usize::try_from(bytes.div_ceil(CHUNK_BYTES))
        .map_err(|_| "backup chunk count is not representable on this host".into())
}

const fn encoded_len(count: usize) -> usize {
    // count is bounded by chunk_count to at most 262144.
    HEADER_BYTES + count * DIGEST_BYTES + DIGEST_BYTES
}

pub(super) fn digest(bytes: &[u8]) -> [u8; DIGEST_BYTES] {
    let mut hash = Sha256Hasher::new();
    hash.update(bytes);
    hash.finish()
}

pub(super) fn encoded_length(archive: Seal) -> Result<usize, String> {
    chunk_count(archive.bytes).map(encoded_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_wire_profile_matches_independently_assembled_bytes() {
        let archive = Seal {
            digest: digest(b"abc"),
            bytes: 3,
        };
        let mut catalog = Catalog::new(archive).unwrap();
        catalog.push(digest(b"abc")).unwrap();
        let encoded = catalog.encode().unwrap();
        let mut expected = b"FGCHNK01".to_vec();
        expected.extend_from_slice(&3_u64.to_be_bytes());
        expected.extend_from_slice(&archive.digest);
        expected.extend_from_slice(&[0, 64, 0, 0, 0, 0, 0, 1]);
        expected.extend_from_slice(&archive.digest);
        expected.extend_from_slice(&digest(&expected));
        assert_eq!(encoded, expected);
        let parsed = Catalog::parse(&encoded, archive).unwrap();
        assert_eq!(parsed.archive, archive);
        assert_eq!(parsed.count(), 1);
        assert_eq!(parsed.hash(0), &archive.digest);
        assert_eq!(MAX_CATALOG_BYTES, 8_388_696);
        assert_eq!(chunk_count(CHUNK_BYTES).unwrap(), 1);
        assert_eq!(chunk_count(CHUNK_BYTES + 1).unwrap(), 2);
        assert_eq!(chunk_count(MAX_ARCHIVE_BYTES).unwrap(), 262_144);
    }

    #[test]
    fn malformed_counts_fields_trailer_and_lengths_never_become_authority() {
        let archive = Seal {
            digest: [0x42; 32],
            bytes: CHUNK_BYTES + 1,
        };
        let mut catalog = Catalog::new(archive).unwrap();
        assert!(catalog.encode().is_err());
        catalog.push([1; 32]).unwrap();
        catalog.push([2; 32]).unwrap();
        assert!(catalog.push([3; 32]).is_err());
        let original = catalog.encode().unwrap();
        for offset in [0, 8, 16, 48, 52] {
            let mut changed = original.clone();
            changed[offset] ^= 0xff;
            let end = changed.len() - 32;
            let trailer = digest(&changed[..end]);
            changed[end..].copy_from_slice(&trailer);
            assert!(Catalog::parse(&changed, archive).is_err());
        }
        for length in [0, 8, 55, original.len() - 1] {
            assert!(Catalog::parse(&original[..length], archive).is_err());
        }
        let mut trailing = original.clone();
        trailing.push(0);
        assert!(Catalog::parse(&trailing, archive).is_err());
        let mut wrong_hash = original.clone();
        let end = wrong_hash.len() - 1;
        wrong_hash[end] ^= 1;
        assert!(Catalog::parse(&wrong_hash, archive).is_err());
        assert!(
            Catalog::new(Seal {
                bytes: 0,
                ..archive
            })
            .is_err()
        );
        assert!(
            Catalog::new(Seal {
                bytes: MAX_ARCHIVE_BYTES + 1,
                ..archive
            })
            .is_err()
        );
        assert_eq!(Catalog::parse(&original, archive).unwrap().count(), 2);
    }
}
