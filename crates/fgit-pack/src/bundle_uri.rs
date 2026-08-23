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

const BUNDLE_URI_V1_ANY_HEADER: &[u8] = b"[bundle]\nversion = 1\nmode = any\n";

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
        if !valid_bundle_uri_name(&name) {
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

/// Bounds selected before an untrusted bundle-URI list is retained or parsed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BundleUriReadLimits {
    /// Most input bytes accepted from the remote list resource.
    pub max_input_bytes: usize,
    /// Most mirror entries retained from one accepted list.
    pub max_entries: usize,
}

impl Default for BundleUriReadLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 1024 * 1024,
            max_entries: 1_024,
        }
    }
}

/// One validated location selected from an untrusted bundle-URI list.
///
/// The location is not a proof that its endpoint exists, serves a bundle, or
/// is authorized for a repository.  A subsequent fetch must remain bounded,
/// verify the selected bundle, and bind it to a current authority read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantinedBundleUriEntry {
    name: String,
    uri: String,
}

impl QuarantinedBundleUriEntry {
    /// The validated Git bundle-list section name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The validated absolute HTTP(S) endpoint spelling.
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }
}

/// A bounded, strict bundle-URI V1 input retained in quarantine.
///
/// This reader accepts only the exact `mode=any` mirror-list profile emitted
/// by [`BundleUriListV1::write`].  Creation tokens, `mode=all`, relative
/// endpoints, and incremental bundle semantics are not silently generalized:
/// callers receive a typed refusal before a remote endpoint can be used.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantinedBundleUriListV1 {
    entries: Vec<QuarantinedBundleUriEntry>,
    input_sha256: [u8; 32],
    input_bytes: usize,
}

impl QuarantinedBundleUriListV1 {
    /// Parses a canonical V1 `mode=any` mirror list into a non-authoritative,
    /// fetch-unready quarantine representation.
    pub fn parse(
        input: &[u8],
        limits: BundleUriReadLimits,
        deadline: &mut impl Deadline,
    ) -> Result<Self, BundleUriRefusal> {
        if input.len() > limits.max_input_bytes {
            return Err(BundleUriRefusal::InputBytesExceeded {
                observed: input.len(),
                limit: limits.max_input_bytes,
            });
        }
        if !input.starts_with(BUNDLE_URI_V1_ANY_HEADER) {
            return Err(BundleUriRefusal::UnsupportedInputProfile);
        }
        let mut offset = BUNDLE_URI_V1_ANY_HEADER.len();
        let mut entries: Vec<QuarantinedBundleUriEntry> = Vec::new();
        let mut uris = BTreeSet::new();
        while offset < input.len() {
            checkpoint(deadline).map_err(BundleUriRefusal::Pack)?;
            let section_prefix = b"\n[bundle \"";
            if !input[offset..].starts_with(section_prefix) {
                return Err(BundleUriRefusal::UnexpectedInputSyntax { offset });
            }
            offset = offset
                .checked_add(section_prefix.len())
                .ok_or(BundleUriRefusal::SizeOverflow)?;
            let name_start = offset;
            let Some(name_length) = input[offset..]
                .windows(3)
                .position(|window| window == b"\"]\n")
            else {
                return Err(BundleUriRefusal::UnexpectedInputSyntax { offset });
            };
            offset = offset
                .checked_add(name_length)
                .ok_or(BundleUriRefusal::SizeOverflow)?;
            let name = core::str::from_utf8(&input[name_start..offset])
                .map_err(|_| BundleUriRefusal::InputNotUtf8 { offset: name_start })?
                .to_owned();
            if !valid_bundle_uri_name(&name) {
                return Err(BundleUriRefusal::InvalidName { name });
            }
            offset = offset
                .checked_add(3)
                .ok_or(BundleUriRefusal::SizeOverflow)?;
            let uri_prefix = b"uri = ";
            if !input[offset..].starts_with(uri_prefix) {
                return Err(BundleUriRefusal::UnexpectedInputSyntax { offset });
            }
            offset = offset
                .checked_add(uri_prefix.len())
                .ok_or(BundleUriRefusal::SizeOverflow)?;
            let uri_start = offset;
            let Some(uri_length) = input[offset..].iter().position(|byte| *byte == b'\n') else {
                return Err(BundleUriRefusal::UnexpectedInputSyntax { offset });
            };
            offset = offset
                .checked_add(uri_length)
                .ok_or(BundleUriRefusal::SizeOverflow)?;
            let uri = core::str::from_utf8(&input[uri_start..offset])
                .map_err(|_| BundleUriRefusal::InputNotUtf8 { offset: uri_start })?
                .to_owned();
            if !valid_absolute_http_uri(&uri) {
                return Err(BundleUriRefusal::InvalidUri { uri });
            }
            offset = offset
                .checked_add(1)
                .ok_or(BundleUriRefusal::SizeOverflow)?;
            if entries.len() >= limits.max_entries {
                return Err(BundleUriRefusal::EntryLimitExceeded {
                    observed: entries.len().saturating_add(1),
                    limit: limits.max_entries,
                });
            }
            if let Some(previous) = entries.last() {
                if name == previous.name {
                    return Err(BundleUriRefusal::DuplicateName { name });
                }
                if name < previous.name {
                    return Err(BundleUriRefusal::NonCanonicalEntryOrder {
                        previous: previous.name.clone(),
                        current: name,
                    });
                }
            }
            if !uris.insert(uri.clone()) {
                return Err(BundleUriRefusal::DuplicateUri { uri });
            }
            entries
                .try_reserve(1)
                .map_err(|_| BundleUriRefusal::AllocationFailed { requested: 1 })?;
            entries.push(QuarantinedBundleUriEntry { name, uri });
        }
        if entries.is_empty() {
            return Err(BundleUriRefusal::EmptyEntrySet);
        }
        Ok(Self {
            entries,
            input_sha256: sha256_digest(input),
            input_bytes: input.len(),
        })
    }

    /// Canonically ordered, validated endpoint candidates.  They remain
    /// non-authoritative until a bounded fetch and bundle inspection succeed.
    #[must_use]
    pub fn entries(&self) -> &[QuarantinedBundleUriEntry] {
        &self.entries
    }

    /// SHA-256 of the exact untrusted config bytes accepted by this parser.
    #[must_use]
    pub const fn input_sha256(&self) -> &[u8; 32] {
        &self.input_sha256
    }

    /// Exact input length used for the quarantine receipt.
    #[must_use]
    pub const fn input_bytes(&self) -> usize {
        self.input_bytes
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
    /// An untrusted list exceeded its configured bound before parsing.
    InputBytesExceeded {
        observed: usize,
        limit: usize,
    },
    /// The received list is outside this strict reader's supported profile.
    UnsupportedInputProfile,
    /// A named text field in the untrusted list was not valid UTF-8.
    InputNotUtf8 {
        offset: usize,
    },
    /// The received list diverged from the canonical V1 grammar at this byte.
    UnexpectedInputSyntax {
        offset: usize,
    },
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
    /// Input entries were not strictly ordered by their section name.
    NonCanonicalEntryOrder {
        previous: String,
        current: String,
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
            Self::InputBytesExceeded { observed, limit } => {
                write!(f, "bundle URI input has {observed} bytes, limit is {limit}")
            }
            Self::UnsupportedInputProfile => f.write_str(
                "bundle URI input is outside the strict V1 mode=any complete-mirror profile",
            ),
            Self::InputNotUtf8 { offset } => {
                write!(f, "bundle URI input is not UTF-8 at byte {offset}")
            }
            Self::UnexpectedInputSyntax { offset } => {
                write!(f, "bundle URI input has unexpected syntax at byte {offset}")
            }
            Self::EntryLimitExceeded { observed, limit } => {
                write!(f, "{observed} bundle URI entries exceeds limit {limit}")
            }
            Self::InvalidName { name } => write!(f, "invalid bundle URI name {name:?}"),
            Self::InvalidUri { uri } => write!(f, "invalid absolute HTTP(S) bundle URI {uri:?}"),
            Self::DuplicateName { name } => write!(f, "duplicate bundle URI name {name:?}"),
            Self::DuplicateUri { uri } => write!(f, "duplicate bundle URI {uri:?}"),
            Self::NonCanonicalEntryOrder { previous, current } => write!(
                f,
                "bundle URI entry {current:?} appears after non-greater entry {previous:?}"
            ),
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

fn valid_bundle_uri_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}
