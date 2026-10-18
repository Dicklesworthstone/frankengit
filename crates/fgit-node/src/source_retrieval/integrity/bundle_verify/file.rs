//! File-backed native verification. Object bodies live in caller-owned scratch;
//! the in-memory inventory and graph remain explicitly count/edge bounded.

mod resolve;
mod storage;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};

use fgit_pack::full_bundle::{FullBundleHeader, StreamBundleHeaderError};
use fgit_pack::{
    StreamPackError, StreamPackIndexEntry, build_streamed_pack_index_v2, read_streamed_pack,
};
use fgit_types::RefName;

use super::recovery::{RecoveryMetadata, prepare_metadata};
use super::{
    BundleExpectationError, BundleExpectations, BundleRecoveryError, BundleVerifyError,
    BundleVerifyLimits, ObjectGraphAudit, VerifiedGitBundle, checkpoint,
};
use resolve::Inventory;
use storage::{CHUNK_BYTES, HashingReader, Scratch, io_error, read_source_hash, seek};

/// Complete content evidence for the exact byte stream read during native pack
/// verification. No input handle, temporary workspace, or destination is owned.
/// The caller must keep the source stable and verify copied pack bytes against
/// `pack_sha256` before publishing a bare repository.
#[derive(Debug)]
pub struct FileBundleVerification {
    verified: VerifiedGitBundle,
    pack_offset: u64,
    pack_len: u64,
    pack_sha256: [u8; 32],
    index: Vec<u8>,
    scratch_bytes: u64,
}
impl FileBundleVerification {
    #[must_use]
    pub const fn verified(&self) -> &VerifiedGitBundle {
        &self.verified
    }
    #[must_use]
    pub const fn pack_offset(&self) -> u64 {
        self.pack_offset
    }
    #[must_use]
    pub const fn pack_len(&self) -> u64 {
        self.pack_len
    }
    #[must_use]
    pub const fn pack_sha256(&self) -> &[u8; 32] {
        &self.pack_sha256
    }
    #[must_use]
    pub fn index(&self) -> &[u8] {
        &self.index
    }
    #[must_use]
    pub const fn scratch_bytes(&self) -> u64 {
        self.scratch_bytes
    }
}

/// The file-backed counterpart of `GitBundleRecovery`. The original pack is a
/// source-file range, never a second in-memory copy. This plan performs no
/// filesystem publication and proves neither signatures nor current authority.
#[derive(Debug)]
pub struct FileGitBundleRecovery {
    file: FileBundleVerification,
    head_ref: RefName,
    metadata: RecoveryMetadata,
}
impl FileGitBundleRecovery {
    #[must_use]
    pub const fn verified(&self) -> &VerifiedGitBundle {
        self.file.verified()
    }
    #[must_use]
    pub const fn pack_offset(&self) -> u64 {
        self.file.pack_offset()
    }
    #[must_use]
    pub const fn pack_len(&self) -> u64 {
        self.file.pack_len()
    }
    #[must_use]
    pub const fn pack_sha256(&self) -> &[u8; 32] {
        self.file.pack_sha256()
    }
    #[must_use]
    pub fn index(&self) -> &[u8] {
        self.file.index()
    }
    #[must_use]
    pub const fn scratch_bytes(&self) -> u64 {
        self.file.scratch_bytes()
    }
    #[must_use]
    pub const fn head_ref(&self) -> &RefName {
        &self.head_ref
    }
    #[must_use]
    pub fn packed_refs(&self) -> &[u8] {
        &self.metadata.packed_refs
    }
    #[must_use]
    pub fn config(&self) -> &[u8] {
        &self.metadata.config
    }
    #[must_use]
    pub fn head(&self) -> &[u8] {
        &self.metadata.head
    }
}

/// Verify a seekable full bundle without retaining its payload or all expanded
/// objects in memory. `scratch` must be empty at position zero and must be an
/// independently owned, private, seekable quarantine. It is never authority;
/// failed attempts may leave residue which the caller alone owns and cleans.
///
/// Input and aggregate work limits remain separate from per-object memory.
/// Scratch is bounded by the admitted inflated bytes plus resolved payload
/// bytes. Native IDs, ranges, delta links and graph edges remain O(objects+edges)
/// metadata. At most one inflated entry, or one delta base/program/result tuple,
/// is retained as payload at a time; this is not an unbounded-inventory profile.
/// Both source passes, all scratch I/O, delta work, graph checks and index output
/// share sticky cooperative cancellation. Blocking `Read`/`Write` cannot be
/// preempted by this synchronous core.
pub fn verify_git_bundle_reader<R: Read + Seek, W: Read + Write + Seek>(
    input: &mut R,
    scratch: &mut W,
    limits: &BundleVerifyLimits,
    expectations: Option<&BundleExpectations>,
    allow_work: &mut impl FnMut() -> bool,
) -> Result<FileBundleVerification, BundleVerifyError> {
    let mut stopped = false;
    let mut live = || {
        if !stopped && !allow_work() {
            stopped = true;
        }
        !stopped
    };
    verify_reader_inner(input, scratch, limits, expectations, &mut live)
}

pub fn prepare_git_bundle_recovery_reader<R: Read + Seek, W: Read + Write + Seek>(
    input: &mut R,
    scratch: &mut W,
    limits: &BundleVerifyLimits,
    expectations: Option<&BundleExpectations>,
    head_ref: &RefName,
    allow_work: &mut impl FnMut() -> bool,
) -> Result<FileGitBundleRecovery, BundleRecoveryError> {
    let mut stopped = false;
    let mut live = || {
        if !stopped && !allow_work() {
            stopped = true;
        }
        !stopped
    };
    checkpoint(&mut live)?;
    if !head_ref.as_bytes().starts_with(b"refs/heads/") {
        return Err(BundleRecoveryError::HeadNotBranch);
    }
    let file = verify_reader_inner(input, scratch, limits, expectations, &mut live)?;
    let metadata = prepare_metadata(file.verified(), limits, head_ref, &mut live)?;
    checkpoint(&mut live)?;
    Ok(FileGitBundleRecovery {
        file,
        head_ref: head_ref.clone(),
        metadata,
    })
}

fn header_error(error: StreamBundleHeaderError) -> BundleVerifyError {
    match error {
        StreamBundleHeaderError::Io(error) => io_error("read bundle header", error),
        StreamBundleHeaderError::Bundle(error) => BundleVerifyError::Envelope(error),
    }
}

fn verify_reader_inner<R: Read + Seek, W: Read + Write + Seek>(
    input: &mut R,
    workspace: &mut W,
    limits: &BundleVerifyLimits,
    expectations: Option<&BundleExpectations>,
    live: &mut impl FnMut() -> bool,
) -> Result<FileBundleVerification, BundleVerifyError> {
    checkpoint(live)?;
    if let Some(expected) = expectations {
        expected
            .validate_limits(limits)
            .map_err(BundleVerifyError::Expectation)?;
    }
    let mut scratch = Scratch::new(workspace, limits, live)?;
    let length = seek(input, SeekFrom::End(0), "inspect bundle length", live)?;
    let bytes = usize::try_from(length)
        .ok()
        .filter(|size| *size <= limits.envelope.max_bundle_bytes)
        .ok_or(BundleVerifyError::Envelope(super::FullBundleError::Limit(
            "bundle bytes",
        )))?;
    seek(input, SeekFrom::Start(0), "rewind bundle", live)?;
    let first = {
        let mut reader = BufReader::with_capacity(CHUNK_BYTES, &mut *input);
        let result = FullBundleHeader::read(&mut reader, limits.envelope, live);
        checkpoint(live)?;
        result.map_err(header_error)?
    };
    if first.references().len() > limits.graph.max_references {
        return Err(BundleVerifyError::Graph(super::GraphRefusal::Limit(
            "references",
        )));
    }
    if let Some(expected) = expectations {
        expected.check_selection(first.format(), first.references(), live)?;
    }
    let pack_offset = first.header_bytes() as u64;
    let pack_length = length
        .checked_sub(pack_offset)
        .ok_or(BundleVerifyError::SourceChanged)?;
    if pack_length > limits.pack.max_input_bytes as u64 {
        return Err(BundleVerifyError::Pack(fgit_pack::PackError::InputLimit {
            actual: usize::try_from(pack_length).unwrap_or(usize::MAX),
            limit: limits.pack.max_input_bytes,
        }));
    }
    // Authenticate the selected file before inflation. The actual verification
    // pass below must yield the same complete digest, including header bytes.
    let preflight = read_source_hash(input, length, live)?;
    if expectations
        .and_then(BundleExpectations::sha256)
        .is_some_and(|expected| *expected != preflight)
    {
        return Err(BundleVerifyError::Expectation(
            BundleExpectationError::ArtifactMismatch,
        ));
    }
    seek(
        input,
        SeekFrom::Start(0),
        "rewind bundle for verification",
        live,
    )?;
    let mut hashing = HashingReader::new(&mut *input);
    let mut inventory = Inventory::new(limits);
    let receipt = {
        let mut reader = BufReader::with_capacity(CHUNK_BYTES, &mut hashing);
        let result = FullBundleHeader::read(&mut reader, limits.envelope, live);
        checkpoint(live)?;
        let selected = result.map_err(header_error)?;
        if selected.raw_bytes() != first.raw_bytes() {
            return Err(BundleVerifyError::SourceChanged);
        }
        let mut pack_limits = limits.pack.clone();
        pack_limits.max_entries = pack_limits
            .max_entries
            .min(u32::try_from(limits.graph.max_objects).unwrap_or(u32::MAX));
        // The pack reader and its sink are synchronous and never overlap; a
        // shared callback owner avoids minting a separate cancellation budget.
        let gate = RefCell::new(&mut *live);
        let mut pack_live = || (gate.borrow_mut())();
        let result = read_streamed_pack(
            &mut reader,
            first.format(),
            &pack_limits,
            &mut pack_live,
            |entry| {
                let mut sink_live = || (gate.borrow_mut())();
                inventory.accept(entry, first.format(), &mut scratch, limits, &mut sink_live)
            },
        );
        checkpoint(&mut pack_live)?;
        result.map_err(|error| match error {
            StreamPackError::Io(error) => io_error("read bundle pack", error),
            StreamPackError::Pack(error) => BundleVerifyError::Pack(error),
            StreamPackError::Sink(error) => error,
        })?
    };
    let (sha256, consumed) = hashing.finish();
    checkpoint(live)?;
    if consumed != length || sha256 != preflight || receipt.pack_bytes() != pack_length {
        return Err(BundleVerifyError::SourceChanged);
    }
    let resolution_passes = inventory.resolve(first.format(), &mut scratch, limits, live)?;
    let ids: BTreeSet<_> = inventory.by_id.keys().copied().collect();
    let result = ObjectGraphAudit::new(&ids, first.format(), limits.graph, live);
    checkpoint(live)?;
    let mut graph = result.map_err(BundleVerifyError::Graph)?;
    let references: BTreeMap<_, _> = first
        .references()
        .iter()
        .map(|row| (row.name().clone(), *row.target()))
        .collect();
    let mut rows = Vec::new();
    rows.try_reserve_exact(inventory.entries.len())
        .map_err(|_| BundleVerifyError::Allocation)?;
    for (&id, &at) in &inventory.by_id {
        checkpoint(live)?;
        let entry = &inventory.entries[at];
        let resolved = entry
            .resolved
            .as_ref()
            .ok_or(BundleVerifyError::ResolutionIncomplete)?;
        let body = scratch.read(resolved.span, limits.graph.max_object_bytes, live)?;
        let result = graph.observe(id, resolved.kind, &body, live);
        checkpoint(live)?;
        result.map_err(BundleVerifyError::Graph)?;
        rows.push(StreamPackIndexEntry {
            oid: id,
            pack_offset: entry.offset,
            end_offset: entry.end_offset,
            crc32: entry.crc32,
        });
    }
    let result = graph.finish(&references, live);
    checkpoint(live)?;
    let graph = result.map_err(BundleVerifyError::Graph)?;
    let result = build_streamed_pack_index_v2(&receipt, &rows, &limits.pack, live);
    checkpoint(live)?;
    let index = result.map_err(BundleVerifyError::Pack)?;
    scratch.finish(live)?;
    let verified = VerifiedGitBundle {
        format: first.format(),
        bytes,
        sha256,
        pack_bytes: usize::try_from(pack_length).map_err(|_| BundleVerifyError::SourceChanged)?,
        pack_checksum: receipt.trailer(),
        advertised_head: first.head(),
        references,
        graph,
        delta_objects: inventory.delta_objects,
        resolution_passes,
    };
    checkpoint(live)?;
    Ok(FileBundleVerification {
        verified,
        pack_offset,
        pack_len: pack_length,
        pack_sha256: receipt.pack_sha256(),
        index,
        scratch_bytes: scratch.bytes(),
    })
}

#[cfg(test)]
mod tests;
