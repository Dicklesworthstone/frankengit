//! Deterministic Git bundle-URI V1 mirror-list materialization.
//!
//! The supported profile is deliberately narrow: it advertises HTTP(S)
//! mirrors for one already-complete, self-contained [`BundleV2`] artifact.
//! The list is derived metadata, not an HTTP publisher, object-admission path,
//! or authority source.  Its receipt records the exact bytes it mirrors so a
//! publication controller can bind a later host effect to this materialization.

use crate::{BundleProfile, BundleSource, BundleV2, Deadline, ObjectId, PackError, checkpoint};
use core::fmt::{self, Display, Formatter};
use fgit_crypto::sha256_digest;
use std::collections::BTreeSet;

/// Bounds selected before a bundle-URI list retains entry metadata or emits
/// its config text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BundleUriLimits {
    /// Most mirror entries in one list.
    pub max_entries: usize,
    /// Most bytes in the complete UTF-8 config file.
    pub max_output_bytes: usize,
}

impl Default for BundleUriLimits {
    fn default() -> Self {
        Self {
            max_entries: 1_024,
            max_output_bytes: 1024 * 1024,
        }
    }
}

/// Frozen first bundle-URI list profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundleUriProfile {
    /// Git bundle list V1, `mode=any`, carrying only complete Full Bundle V2
    /// mirrors.  Creation-token, filter, relative-URI, and incremental-bundle
    /// semantics are deliberately not represented by this profile.
    V1AnyFullBundleV2Mirrors,
}

/// Scope represented by a generated bundle-URI list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundleUriCompleteness {
    /// Every listed URI is a mirror of the same one complete bundle artifact.
    ExactMirrorsOfOneFullBundleV2,
}

/// Verification performed before a URI list was emitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundleUriVerification {
    /// Every entry held a completed Full Bundle V2 whose source coordinate and
    /// bytes equal the selected source artifact.  This does not prove a remote
    /// endpoint has published or will retain those bytes.
    CompletedBundleByteIdentityV1,
}

/// One validated mirror name, URI, and completed bundle artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleUriEntry {
    name: String,
    uri: String,
    bundle: BundleV2,
}

impl BundleUriEntry {
    /// Creates one URI-list entry.  Names follow Git's bundle-list section
    /// grammar (ASCII alphanumeric or `-`); the URI is a conservative absolute
    /// HTTP(S) spelling safe to emit unquoted into Git config text.
    pub fn new(name: String, uri: String, bundle: BundleV2) -> Result<Self, BundleUriRefusal> {
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(BundleUriRefusal::InvalidName { name });
        }
        if !valid_absolute_http_uri(&uri) {
            return Err(BundleUriRefusal::InvalidUri { uri });
        }
        Ok(Self { name, uri, bundle })
    }

    /// Server-designated bundle-list section name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Absolute HTTP(S) URI emitted in the config list.
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Completed full Bundle V2 whose bytes this URI must mirror on publication.
    #[must_use]
    pub const fn bundle(&self) -> &BundleV2 {
        &self.bundle
    }
}

/// Immutable evidence for one generated bundle-URI list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleUriListReceipt {
    source: BundleSource,
    profile: BundleUriProfile,
    completeness: BundleUriCompleteness,
    verification: BundleUriVerification,
    entry_count: usize,
    bundle_header_sha256: [u8; 32],
    bundle_pack_checksum: ObjectId,
    bundle_output_bytes: usize,
    list_sha256: [u8; 32],
    output_bytes: usize,
}

impl BundleUriListReceipt {
    #[must_use]
    pub const fn source(&self) -> &BundleSource {
        &self.source
    }
    #[must_use]
    pub const fn profile(&self) -> BundleUriProfile {
        self.profile
    }
    #[must_use]
    pub const fn completeness(&self) -> BundleUriCompleteness {
        self.completeness
    }
    #[must_use]
    pub const fn verification(&self) -> BundleUriVerification {
        self.verification
    }
    #[must_use]
    pub const fn entry_count(&self) -> usize {
        self.entry_count
    }
    #[must_use]
    pub const fn bundle_header_sha256(&self) -> &[u8; 32] {
        &self.bundle_header_sha256
    }
    #[must_use]
    pub const fn bundle_pack_checksum(&self) -> &ObjectId {
        &self.bundle_pack_checksum
    }
    #[must_use]
    pub const fn bundle_output_bytes(&self) -> usize {
        self.bundle_output_bytes
    }
    #[must_use]
    pub const fn list_sha256(&self) -> &[u8; 32] {
        &self.list_sha256
    }
    #[must_use]
    pub const fn output_bytes(&self) -> usize {
        self.output_bytes
    }
}

/// Complete Git-config bundle URI list and its derived receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleUriListV1 {
    bytes: Vec<u8>,
    receipt: BundleUriListReceipt,
}

impl BundleUriListV1 {
    /// Emits a canonical V1 `mode=any` config list for exact mirrors of one
    /// full completed Bundle V2.  No URI fetch or host publication occurs here.
    pub fn write(
        source: BundleSource,
        entries: &[BundleUriEntry],
        limits: BundleUriLimits,
        deadline: &mut impl Deadline,
    ) -> Result<Self, BundleUriRefusal> {
        if entries.is_empty() {
            return Err(BundleUriRefusal::EmptyEntrySet);
        }
        if entries.len() > limits.max_entries {
            return Err(BundleUriRefusal::EntryLimitExceeded {
                observed: entries.len(),
                limit: limits.max_entries,
            });
        }
        let mut ordered = Vec::new();
        ordered.try_reserve_exact(entries.len()).map_err(|_| {
            BundleUriRefusal::AllocationFailed {
                requested: entries.len(),
            }
        })?;
        for entry in entries {
            checkpoint(deadline).map_err(BundleUriRefusal::Pack)?;
            ordered.push(entry);
        }
        ordered.sort_unstable_by(|left, right| left.name.cmp(&right.name));
        let exemplar = ordered[0].bundle();
        let exemplar_receipt = exemplar.receipt();
        if exemplar_receipt.profile() != BundleProfile::FullV2Sha1
            || exemplar_receipt.source() != &source
        {
            return Err(BundleUriRefusal::BundleSourceMismatch {
                name: ordered[0].name.clone(),
            });
        }
        let mut names = BTreeSet::new();
        let mut uris = BTreeSet::new();
        let mut output_bytes = b"[bundle]\nversion = 1\nmode = any\n".len();
        for entry in &ordered {
            checkpoint(deadline).map_err(BundleUriRefusal::Pack)?;
            if !names.insert(entry.name.as_str()) {
                return Err(BundleUriRefusal::DuplicateName {
                    name: entry.name.clone(),
                });
            }
            if !uris.insert(entry.uri.as_str()) {
                return Err(BundleUriRefusal::DuplicateUri {
                    uri: entry.uri.clone(),
                });
            }
            let receipt = entry.bundle.receipt();
            if receipt.profile() != BundleProfile::FullV2Sha1
                || receipt.source() != &source
                || receipt.header_sha256() != exemplar_receipt.header_sha256()
                || receipt.pack_receipt().checksum != exemplar_receipt.pack_receipt().checksum
                || entry.bundle.bytes() != exemplar.bytes()
            {
                return Err(BundleUriRefusal::BundleSourceMismatch {
                    name: entry.name.clone(),
                });
            }
            output_bytes = output_bytes
                .checked_add(b"\n[bundle \"\"]\nuri = \n".len())
                .and_then(|value| value.checked_add(entry.name.len()))
                .and_then(|value| value.checked_add(entry.uri.len()))
                .ok_or(BundleUriRefusal::SizeOverflow)?;
        }
        if output_bytes > limits.max_output_bytes {
            return Err(BundleUriRefusal::OutputBytesExceeded {
                observed: output_bytes,
                limit: limits.max_output_bytes,
            });
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(output_bytes)
            .map_err(|_| BundleUriRefusal::AllocationFailed {
                requested: output_bytes,
            })?;
        bytes.extend_from_slice(b"[bundle]\nversion = 1\nmode = any\n");
        for entry in ordered {
            checkpoint(deadline).map_err(BundleUriRefusal::Pack)?;
            bytes.extend_from_slice(b"\n[bundle \"");
            bytes.extend_from_slice(entry.name.as_bytes());
            bytes.extend_from_slice(b"\"]\nuri = ");
            bytes.extend_from_slice(entry.uri.as_bytes());
            bytes.push(b'\n');
        }
        if bytes.len() != output_bytes {
            return Err(BundleUriRefusal::OutputMismatch {
                expected: output_bytes,
                actual: bytes.len(),
            });
        }
        let list_sha256 = sha256_digest(&bytes);
        Ok(Self {
            bytes,
            receipt: BundleUriListReceipt {
                source,
                profile: BundleUriProfile::V1AnyFullBundleV2Mirrors,
                completeness: BundleUriCompleteness::ExactMirrorsOfOneFullBundleV2,
                verification: BundleUriVerification::CompletedBundleByteIdentityV1,
                entry_count: entries.len(),
                bundle_header_sha256: *exemplar_receipt.header_sha256(),
                bundle_pack_checksum: exemplar_receipt.pack_receipt().checksum,
                bundle_output_bytes: exemplar_receipt.output_bytes(),
                list_sha256,
                output_bytes,
            },
        })
    }

    /// Exact config-file bytes suitable for static bundle-list publication.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Derived receipt; it makes no remote-publication or authority claim.
    #[must_use]
    pub const fn receipt(&self) -> &BundleUriListReceipt {
        &self.receipt
    }
}

/// Why bundle-URI V1 materialization was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BundleUriRefusal {
    EmptyEntrySet,
    EntryLimitExceeded {
        observed: usize,
        limit: usize,
    },
    InvalidName {
        name: String,
    },
    InvalidUri {
        uri: String,
    },
    DuplicateName {
        name: String,
    },
    DuplicateUri {
        uri: String,
    },
    /// An entry is not byte-identical to the selected completed Bundle V2.
    BundleSourceMismatch {
        name: String,
    },
    OutputBytesExceeded {
        observed: usize,
        limit: usize,
    },
    SizeOverflow,
    AllocationFailed {
        requested: usize,
    },
    Pack(PackError),
    OutputMismatch {
        expected: usize,
        actual: usize,
    },
}

impl Display for BundleUriRefusal {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyEntrySet => f.write_str("bundle URI list needs one mirror"),
            Self::EntryLimitExceeded { observed, limit } => {
                write!(f, "{observed} bundle URI entries exceeds limit {limit}")
            }
            Self::InvalidName { name } => write!(f, "invalid bundle URI name {name:?}"),
            Self::InvalidUri { uri } => write!(f, "invalid absolute HTTP(S) bundle URI {uri:?}"),
            Self::DuplicateName { name } => write!(f, "duplicate bundle URI name {name:?}"),
            Self::DuplicateUri { uri } => write!(f, "duplicate bundle URI {uri:?}"),
            Self::BundleSourceMismatch { name } => write!(
                f,
                "bundle URI mirror {name:?} differs from selected completed bundle"
            ),
            Self::OutputBytesExceeded { observed, limit } => {
                write!(f, "bundle URI list has {observed} bytes, limit is {limit}")
            }
            Self::SizeOverflow => f.write_str("bundle URI list size overflowed"),
            Self::AllocationFailed { requested } => write!(
                f,
                "bundle URI list could not reserve {requested} elements or bytes"
            ),
            Self::Pack(error) => write!(f, "bundle URI list checkpoint refused: {error}"),
            Self::OutputMismatch { expected, actual } => write!(
                f,
                "bundle URI list emitted {actual} bytes after planning {expected}"
            ),
        }
    }
}

impl core::error::Error for BundleUriRefusal {}

fn valid_absolute_http_uri(uri: &str) -> bool {
    let scheme_end = if uri.starts_with("https://") {
        8
    } else if uri.starts_with("http://") {
        7
    } else {
        return false;
    };
    uri.len() > scheme_end
        && uri
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'"' | b'\\' | b'#' | b';'))
}
