//! Bounded, deterministic USTAR materialization from an authenticated TreeFS base.
//!
//! This is a derived-output adapter, never an authority surface.  It reads only
//! objects selected by a [`TreeCapability`], rechecks every payload identity
//! through [`BaseView`], and returns a byte stream plus the exact base it came
//! from.  Nothing here writes a host path, changes a ref, or publishes a
//! repository decision.
//!
//! The supported format is deliberately the portable USTAR subset.  Paths that
//! need a PAX extension, submodules, and symlink targets USTAR cannot encode are
//! typed refusals rather than a lossy best effort.  That keeps the first archive
//! materializer byte-stable and makes its compatibility surface explicit.

use crate::base::{BaseError, BaseView, ObjectSource, ObjectSourceError};
use crate::capability::{CapabilityRefusal, TreeCapability};
use crate::path::TreePath;
use core::fmt::{self, Display, Formatter};
use fgit_crypto::{GitHashAlgorithm, GitObjectKind, GitOid};
use fgit_types::{RepositoryCommitId, RepositoryId};
use std::collections::BTreeMap;

const TAR_BLOCK_BYTES: usize = 512;
const TAR_END_BYTES: usize = TAR_BLOCK_BYTES * 2;
const USTAR_NAME_BYTES: usize = 100;
const USTAR_LINK_BYTES: usize = 100;
const USTAR_PREFIX_BYTES: usize = 155;

/// Bounds applied before the renderer appends an archive record.
///
/// `BaseView` separately bounds each object according to its parse profile.
/// These limits bound this materializer's own retained metadata and output
/// stream, so a permissive object source cannot make archive output unbounded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TarLimits {
    /// Most headers (including directory headers) this archive may contain.
    pub max_entries: usize,
    /// Most bytes accepted for one regular-file payload.
    pub max_entry_bytes: usize,
    /// Most bytes in the complete USTAR stream, including headers and trailer.
    pub max_output_bytes: usize,
}

impl Default for TarLimits {
    fn default() -> Self {
        Self {
            max_entries: 100_000,
            max_entry_bytes: 128 * 1024 * 1024,
            max_output_bytes: 512 * 1024 * 1024,
        }
    }
}

/// The deterministic archive profile used for a materialization receipt.
///
/// `UstarV1` fixes USTAR headers, zero uid/gid/mtime, no owner names, and no
/// PAX/GNU extension records.  Those choices make the same verified tree and
/// capability-visible paths render to the same bytes on every host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveProfile {
    /// Portable USTAR with fixed metadata and explicit typed refusals for
    /// unrepresentable entries.
    UstarV1,
}

/// The format and deterministic metadata of a rendered archive.
///
/// The receipt deliberately names the immutable base RCR and tree identity
/// rather than a local output directory.  The output remains disposable: a
/// caller can discard it and render the same archive again from verified base
/// objects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveReceipt<A: GitHashAlgorithm> {
    repository_id: RepositoryId,
    source_rcr_id: RepositoryCommitId,
    source_tree_oid: GitOid<A>,
    profile: ArchiveProfile,
    entry_paths: Vec<TreePath>,
    entry_count: usize,
    regular_file_bytes: usize,
    stream_bytes: usize,
}

impl<A: GitHashAlgorithm> ArchiveReceipt<A> {
    /// The repository whose authenticated base supplied this materialization.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// The canonical RCR to which the source base is pinned.
    #[must_use]
    pub const fn source_rcr_id(&self) -> RepositoryCommitId {
        self.source_rcr_id
    }

    /// The immutable root tree from which the stream was rendered.
    #[must_use]
    pub const fn source_tree_oid(&self) -> &GitOid<A> {
        &self.source_tree_oid
    }

    /// The renderer profile that fixes the observable stream format.
    #[must_use]
    pub const fn profile(&self) -> ArchiveProfile {
        self.profile
    }

    /// The complete capability-visible member set, in canonical path order.
    ///
    /// The path set binds this receipt to one materialized subset of the base;
    /// source tree plus profile alone would not distinguish a narrow archive
    /// from a broader archive of the same repository.
    #[must_use]
    pub fn entry_paths(&self) -> &[TreePath] {
        &self.entry_paths
    }

    /// The number of rendered USTAR headers, including directories.
    #[must_use]
    pub const fn entry_count(&self) -> usize {
        self.entry_count
    }

    /// Total source bytes represented as regular-file payloads.
    #[must_use]
    pub const fn regular_file_bytes(&self) -> usize {
        self.regular_file_bytes
    }

    /// Complete stream size including USTAR headers, padding, and trailer.
    #[must_use]
    pub const fn stream_bytes(&self) -> usize {
        self.stream_bytes
    }
}

/// A complete USTAR materialization and its provenance receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UstarArchive<A: GitHashAlgorithm> {
    bytes: Vec<u8>,
    receipt: ArchiveReceipt<A>,
}

impl<A: GitHashAlgorithm> UstarArchive<A> {
    /// Renders the capability-visible portion of `base` as a USTAR stream.
    ///
    /// Directory discovery is completed before blob rendering, making output
    /// order independent of source scheduling and refusing entry-count excess
    /// before any archive record is retained.  Every blob is read through the
    /// identity-verifying `BaseView` boundary and charged to `capability`.
    pub fn render<S: ObjectSource<A>>(
        base: &BaseView<A>,
        source: &S,
        capability: &mut TreeCapability,
        now: u64,
        limits: TarLimits,
    ) -> Result<Self, ArchiveRefusal> {
        let mut entries = BTreeMap::new();
        discover_directory(base, source, capability, None, now, limits, &mut entries)?;

        let entry_paths: Vec<TreePath> = entries.keys().cloned().collect();
        let entry_count = entry_paths.len();
        let mut bytes = Vec::new();
        let mut regular_file_bytes = 0_usize;
        for (path, entry) in entries {
            match entry {
                PlannedEntry::Directory => append_record(
                    &mut bytes,
                    &path,
                    TarEntryKind::Directory,
                    0o755,
                    &[],
                    limits.max_output_bytes,
                )?,
                PlannedEntry::File { oid, mode } => {
                    let body = read_blob(base, source, capability, &path, &oid, now)?;
                    if body.len() > limits.max_entry_bytes {
                        return Err(ArchiveRefusal::EntryBytesExceeded {
                            path,
                            observed: body.len(),
                            limit: limits.max_entry_bytes,
                        });
                    }
                    regular_file_bytes = regular_file_bytes
                        .checked_add(body.len())
                        .ok_or(ArchiveRefusal::OutputSizeOverflow)?;
                    append_record(
                        &mut bytes,
                        &path,
                        TarEntryKind::File,
                        file_mode(&path, &mode)?,
                        &body,
                        limits.max_output_bytes,
                    )?;
                }
                PlannedEntry::Symlink { oid } => {
                    let target = read_blob(base, source, capability, &path, &oid, now)?;
                    if target.contains(&0) {
                        return Err(ArchiveRefusal::SymlinkTargetContainsNul { path });
                    }
                    if target.len() > USTAR_LINK_BYTES {
                        return Err(ArchiveRefusal::SymlinkTargetTooLong {
                            path,
                            observed: target.len(),
                            limit: USTAR_LINK_BYTES,
                        });
                    }
                    append_record_with_link(
                        &mut bytes,
                        &path,
                        0o777,
                        &target,
                        limits.max_output_bytes,
                    )?;
                }
            }
        }

        ensure_append_capacity(&bytes, TAR_END_BYTES, limits.max_output_bytes)?;
        bytes.resize(bytes.len() + TAR_END_BYTES, 0);

        let receipt = ArchiveReceipt {
            repository_id: base.repository_id(),
            source_rcr_id: base.base_rcr_id(),
            source_tree_oid: base.base_tree_oid().clone(),
            profile: ArchiveProfile::UstarV1,
            entry_paths,
            entry_count,
            regular_file_bytes,
            stream_bytes: bytes.len(),
        };
        Ok(Self { bytes, receipt })
    }

    /// The exact USTAR stream.  It has no host-path side effect.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The immutable source and output metadata for this stream.
    #[must_use]
    pub const fn receipt(&self) -> &ArchiveReceipt<A> {
        &self.receipt
    }
}

/// Why an archive materialization was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArchiveRefusal {
    /// Discovering the authenticated tree failed.
    Base(BaseError),
    /// Reading a verified blob failed.
    Source(ObjectSourceError),
    /// The read capability refused a payload fetch or budget charge.
    Capability(CapabilityRefusal),
    /// A tree supplied the same archive name twice.
    DuplicatePath {
        /// The duplicate archive path.
        path: TreePath,
    },
    /// The archive would exceed its header-count bound.
    EntryLimitExceeded {
        /// Headers that would have been emitted.
        observed: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// A regular file exceeds its per-entry body bound.
    EntryBytesExceeded {
        /// The file path.
        path: TreePath,
        /// Bytes returned by the verified object read.
        observed: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// A Git submodule cannot be represented as a portable USTAR member here.
    SubmoduleUnsupported {
        /// The submodule path.
        path: TreePath,
    },
    /// The path cannot fit in USTAR's name and prefix fields.
    PathTooLong {
        /// The entry path.
        path: TreePath,
        /// Bytes in the path.
        observed: usize,
        /// Largest USTAR path this renderer can encode.
        limit: usize,
    },
    /// A symlink body contains a byte USTAR uses as an in-field terminator.
    SymlinkTargetContainsNul {
        /// The symlink path.
        path: TreePath,
    },
    /// A symlink target cannot fit in USTAR's link-name field.
    SymlinkTargetTooLong {
        /// The symlink path.
        path: TreePath,
        /// Bytes in the link target.
        observed: usize,
        /// USTAR's link-name ceiling.
        limit: usize,
    },
    /// A Git file mode was not canonical octal bytes.
    InvalidFileMode {
        /// The file path.
        path: TreePath,
        /// The observed raw Git mode bytes.
        mode: Vec<u8>,
    },
    /// A numeric value cannot be represented in its fixed USTAR field.
    HeaderFieldOverflow {
        /// The entry path.
        path: TreePath,
        /// The USTAR header field.
        field: &'static str,
        /// The value that did not fit.
        value: u64,
    },
    /// A size calculation overflowed the platform's address space.
    OutputSizeOverflow,
    /// The complete output would exceed the configured byte ceiling.
    OutputBytesExceeded {
        /// Bytes that would have been retained.
        observed: usize,
        /// Configured maximum.
        limit: usize,
    },
}

impl Display for ArchiveRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Base(inner) => write!(formatter, "base traversal failed: {inner}"),
            Self::Source(inner) => write!(formatter, "verified object read failed: {inner}"),
            Self::Capability(inner) => write!(formatter, "archive capability refused: {inner}"),
            Self::DuplicatePath { path } => write!(formatter, "duplicate archive path {path}"),
            Self::EntryLimitExceeded { observed, limit } => {
                write!(
                    formatter,
                    "{observed} archive entries exceeds the limit of {limit}"
                )
            }
            Self::EntryBytesExceeded {
                path,
                observed,
                limit,
            } => write!(
                formatter,
                "archive entry {path} is {observed} bytes, limit is {limit}"
            ),
            Self::SubmoduleUnsupported { path } => {
                write!(
                    formatter,
                    "submodule {path} is unsupported in the USTAR profile"
                )
            }
            Self::PathTooLong {
                path,
                observed,
                limit,
            } => write!(
                formatter,
                "archive path {path} is {observed} bytes, USTAR limit is {limit}"
            ),
            Self::SymlinkTargetContainsNul { path } => {
                write!(formatter, "symlink {path} has a NUL-containing target")
            }
            Self::SymlinkTargetTooLong {
                path,
                observed,
                limit,
            } => write!(
                formatter,
                "symlink target at {path} is {observed} bytes, USTAR limit is {limit}"
            ),
            Self::InvalidFileMode { path, mode } => write!(
                formatter,
                "file {path} has non-octal Git mode {:?}",
                String::from_utf8_lossy(mode)
            ),
            Self::HeaderFieldOverflow { path, field, value } => write!(
                formatter,
                "USTAR {field} field for {path} cannot encode {value}"
            ),
            Self::OutputSizeOverflow => formatter.write_str("archive output size overflowed"),
            Self::OutputBytesExceeded { observed, limit } => write!(
                formatter,
                "archive would retain {observed} bytes, limit is {limit}"
            ),
        }
    }
}

impl core::error::Error for ArchiveRefusal {}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PlannedEntry<A: GitHashAlgorithm> {
    Directory,
    File { oid: GitOid<A>, mode: Vec<u8> },
    Symlink { oid: GitOid<A> },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TarEntryKind {
    File,
    Directory,
}

impl TarEntryKind {
    const fn typeflag(self) -> u8 {
        match self {
            Self::File => b'0',
            Self::Directory => b'5',
        }
    }
}

fn discover_directory<A: GitHashAlgorithm, S: ObjectSource<A>>(
    base: &BaseView<A>,
    source: &S,
    capability: &mut TreeCapability,
    directory: Option<&TreePath>,
    now: u64,
    limits: TarLimits,
    entries: &mut BTreeMap<TreePath, PlannedEntry<A>>,
) -> Result<(), ArchiveRefusal> {
    let children = base
        .list(source, capability, directory, now)
        .map_err(ArchiveRefusal::Base)?;
    for (name, entry) in children {
        let path = match directory {
            Some(parent) => parent
                .join(&name, base.path_policy())
                .map_err(|error| ArchiveRefusal::Base(BaseError::Path(error)))?,
            None => TreePath::parse(&name, base.path_policy())
                .map_err(|error| ArchiveRefusal::Base(BaseError::Path(error)))?,
        };
        if entries.len() >= limits.max_entries {
            return Err(ArchiveRefusal::EntryLimitExceeded {
                observed: entries.len().saturating_add(1),
                limit: limits.max_entries,
            });
        }

        let planned = match entry {
            crate::base::BaseEntry::Directory { .. } => PlannedEntry::Directory,
            crate::base::BaseEntry::File { oid, mode } => PlannedEntry::File { oid, mode },
            crate::base::BaseEntry::Symlink { oid } => {
                // Listing exposes a symlink as data so callers can choose a
                // policy.  This renderer is one such caller: it never follows
                // the target, but a `Refuse` capability still means no symlink
                // representation may cross this adapter boundary.
                capability
                    .check_symlink(&path)
                    .map_err(ArchiveRefusal::Capability)?;
                PlannedEntry::Symlink { oid }
            }
            crate::base::BaseEntry::Submodule { .. } => {
                return Err(ArchiveRefusal::SubmoduleUnsupported { path });
            }
        };
        if entries.insert(path.clone(), planned).is_some() {
            return Err(ArchiveRefusal::DuplicatePath { path });
        }
        if matches!(entries.get(&path), Some(PlannedEntry::Directory)) {
            discover_directory(base, source, capability, Some(&path), now, limits, entries)?;
        }
    }
    Ok(())
}

fn read_blob<A: GitHashAlgorithm, S: ObjectSource<A>>(
    base: &BaseView<A>,
    source: &S,
    capability: &mut TreeCapability,
    path: &TreePath,
    oid: &GitOid<A>,
    now: u64,
) -> Result<Vec<u8>, ArchiveRefusal> {
    let grant = capability
        .authorize_read(path, now)
        .map_err(ArchiveRefusal::Capability)?;
    let body = base
        .read_object(source, oid, GitObjectKind::Blob, &grant)
        .map_err(ArchiveRefusal::Source)?;
    capability
        .charge_fetch(u64::try_from(body.len()).map_err(|_| ArchiveRefusal::OutputSizeOverflow)?)
        .map_err(ArchiveRefusal::Capability)?;
    Ok(body)
}

fn file_mode(path: &TreePath, mode: &[u8]) -> Result<u64, ArchiveRefusal> {
    let mut value = 0_u64;
    for byte in mode {
        if !(b'0'..=b'7').contains(byte) {
            return Err(ArchiveRefusal::InvalidFileMode {
                path: path.clone(),
                mode: mode.to_vec(),
            });
        }
        value = value
            .checked_mul(8)
            .and_then(|value| value.checked_add(u64::from(byte - b'0')))
            .ok_or_else(|| ArchiveRefusal::InvalidFileMode {
                path: path.clone(),
                mode: mode.to_vec(),
            })?;
    }
    Ok(value & 0o7777)
}

fn append_record(
    bytes: &mut Vec<u8>,
    path: &TreePath,
    kind: TarEntryKind,
    mode: u64,
    body: &[u8],
    max_output_bytes: usize,
) -> Result<(), ArchiveRefusal> {
    let mut header = header_for(path, kind.typeflag(), mode, body.len())?;
    finalize_checksum(&mut header);
    append_header_and_body(bytes, header, body, max_output_bytes)
}

fn append_record_with_link(
    bytes: &mut Vec<u8>,
    path: &TreePath,
    mode: u64,
    target: &[u8],
    max_output_bytes: usize,
) -> Result<(), ArchiveRefusal> {
    let mut header = header_for(path, b'2', mode, 0)?;
    header[157..157 + target.len()].copy_from_slice(target);
    finalize_checksum(&mut header);
    append_header_and_body(bytes, header, &[], max_output_bytes)
}

fn header_for(
    path: &TreePath,
    typeflag: u8,
    mode: u64,
    body_len: usize,
) -> Result<[u8; TAR_BLOCK_BYTES], ArchiveRefusal> {
    let mut header = [0_u8; TAR_BLOCK_BYTES];
    write_ustar_path(&mut header, path)?;
    write_octal_field(&mut header[100..108], mode).ok_or(ArchiveRefusal::HeaderFieldOverflow {
        path: path.clone(),
        field: "mode",
        value: mode,
    })?;
    if write_octal_field(&mut header[108..116], 0).is_none() {
        return Err(ArchiveRefusal::HeaderFieldOverflow {
            path: path.clone(),
            field: "uid",
            value: 0,
        });
    }
    if write_octal_field(&mut header[116..124], 0).is_none() {
        return Err(ArchiveRefusal::HeaderFieldOverflow {
            path: path.clone(),
            field: "gid",
            value: 0,
        });
    }
    let body_len = u64::try_from(body_len).map_err(|_| ArchiveRefusal::OutputSizeOverflow)?;
    write_octal_field(&mut header[124..136], body_len).ok_or(
        ArchiveRefusal::HeaderFieldOverflow {
            path: path.clone(),
            field: "size",
            value: body_len,
        },
    )?;
    if write_octal_field(&mut header[136..148], 0).is_none() {
        return Err(ArchiveRefusal::HeaderFieldOverflow {
            path: path.clone(),
            field: "mtime",
            value: 0,
        });
    }
    header[148..156].fill(b' ');
    header[156] = typeflag;
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    Ok(header)
}

fn write_ustar_path(
    header: &mut [u8; TAR_BLOCK_BYTES],
    path: &TreePath,
) -> Result<(), ArchiveRefusal> {
    let bytes = path.as_bytes();
    if bytes.len() <= USTAR_NAME_BYTES {
        header[..bytes.len()].copy_from_slice(bytes);
        return Ok(());
    }

    let split = bytes.iter().enumerate().rev().find_map(|(index, byte)| {
        if *byte != b'/' {
            return None;
        }
        let prefix_len = index;
        let name_len = bytes.len().saturating_sub(index + 1);
        (prefix_len <= USTAR_PREFIX_BYTES && name_len <= USTAR_NAME_BYTES).then_some(index)
    });
    let Some(split) = split else {
        return Err(ArchiveRefusal::PathTooLong {
            path: path.clone(),
            observed: bytes.len(),
            limit: USTAR_NAME_BYTES + 1 + USTAR_PREFIX_BYTES,
        });
    };
    let prefix = &bytes[..split];
    let name = &bytes[split + 1..];
    header[..name.len()].copy_from_slice(name);
    header[345..345 + prefix.len()].copy_from_slice(prefix);
    Ok(())
}

fn append_header_and_body(
    bytes: &mut Vec<u8>,
    header: [u8; TAR_BLOCK_BYTES],
    body: &[u8],
    max_output_bytes: usize,
) -> Result<(), ArchiveRefusal> {
    let padding = (TAR_BLOCK_BYTES - (body.len() % TAR_BLOCK_BYTES)) % TAR_BLOCK_BYTES;
    let record_bytes = TAR_BLOCK_BYTES
        .checked_add(body.len())
        .and_then(|value| value.checked_add(padding))
        .ok_or(ArchiveRefusal::OutputSizeOverflow)?;
    ensure_append_capacity(bytes, record_bytes, max_output_bytes)?;
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(body);
    bytes.resize(bytes.len() + padding, 0);
    Ok(())
}

fn ensure_append_capacity(
    bytes: &[u8],
    additional: usize,
    max_output_bytes: usize,
) -> Result<(), ArchiveRefusal> {
    let observed = bytes
        .len()
        .checked_add(additional)
        .ok_or(ArchiveRefusal::OutputSizeOverflow)?;
    if observed > max_output_bytes {
        return Err(ArchiveRefusal::OutputBytesExceeded {
            observed,
            limit: max_output_bytes,
        });
    }
    Ok(())
}

fn write_octal_field(field: &mut [u8], mut value: u64) -> Option<()> {
    let digits = field.len().checked_sub(1)?;
    field.fill(0);
    for index in (0..digits).rev() {
        field[index] = b'0' + u8::try_from(value & 7).ok()?;
        value >>= 3;
    }
    (value == 0).then_some(())
}

fn finalize_checksum(header: &mut [u8; TAR_BLOCK_BYTES]) {
    let checksum = header.iter().map(|byte| u64::from(*byte)).sum::<u64>();
    let field = &mut header[148..156];
    field.fill(b' ');
    for index in (0..6).rev() {
        field[index] = b'0' + ((checksum >> ((5 - index) * 3)) & 7) as u8;
    }
    field[6] = 0;
    field[7] = b' ';
}
