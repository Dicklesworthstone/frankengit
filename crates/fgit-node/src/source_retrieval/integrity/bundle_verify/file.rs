//! File-backed native verification. Object bodies live in caller-owned scratch;
//! the in-memory inventory and graph remain explicitly count/edge bounded.

mod import;
mod incremental;
mod resolve;
mod storage;

pub use import::BundleImportObjectPlan;
pub use import::{prepare_full_bundle_fetch_reader, prepare_full_bundle_import_reader};
pub use incremental::{
    BundleOriginalObject, BundleOriginalSource, prepare_incremental_bundle_fetch_reader,
    prepare_incremental_bundle_import_reader,
};

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};

use fgit_pack::full_bundle::{FullBundleHeader, StreamBundleHeaderError};
use fgit_pack::{
    StreamPackError, StreamPackIndexEntry, StreamPackReceipt, build_streamed_pack_index_v2,
    read_streamed_pack_chunks,
};
use fgit_treefs::integrity::{BlobGraphError, GraphReport, ObjectKind};
use fgit_types::{GitHashAlgorithm, RefName};

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
/// metadata. Base blobs use bounded inflate and graph-reader chunks even when
/// their independent streamed-blob allowance exceeds the buffered object cap.
/// Blob delta bases/results above the buffered cap use the same private
/// scratch descriptor, with a fully verified base block index and authenticated
/// random reads. Metadata and delta programs retain their buffered caps. Small
/// deltas retain the scalar path and its work accounting. Inventory remains
/// bounded by objects and edges; a large base's temporary index uses 32 bytes
/// per 16 KiB block plus one cached block.
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
    verify_reader_inventory(input, workspace, limits, expectations, None, live)
        .map(|verified| verified.file)
}

/// Kept private: only complete native verification can produce a retained
/// inventory, and its span commitments never come from a caller.
struct VerifiedReaderInventory {
    file: FileBundleVerification,
    inventory: Inventory,
    receipt: StreamPackReceipt,
}

fn verify_reader_inventory<R: Read + Seek, W: Read + Write + Seek>(
    input: &mut R,
    workspace: &mut W,
    limits: &BundleVerifyLimits,
    expectations: Option<&BundleExpectations>,
    expected_format: Option<GitHashAlgorithm>,
    live: &mut impl FnMut() -> bool,
) -> Result<VerifiedReaderInventory, BundleVerifyError> {
    let verified = verify_reader_contents(
        input,
        workspace,
        limits,
        expectations,
        expected_format,
        None,
        0,
        live,
    )?;
    let references = verified
        .header
        .references()
        .iter()
        .map(|row| (row.name().clone(), *row.target()))
        .collect();
    let report = VerifiedGitBundle {
        format: verified.header.format(),
        bytes: verified.bytes,
        sha256: verified.sha256,
        pack_bytes: usize::try_from(verified.pack_length)
            .map_err(|_| BundleVerifyError::SourceChanged)?,
        pack_checksum: verified.receipt.trailer(),
        advertised_head: verified.header.head(),
        references,
        graph: verified.graph,
        delta_objects: verified.inventory.delta_objects,
        resolution_passes: verified.resolution_passes,
    };
    Ok(VerifiedReaderInventory {
        file: FileBundleVerification {
            verified: report,
            pack_offset: verified.pack_offset,
            pack_len: verified.pack_length,
            pack_sha256: verified.receipt.pack_sha256(),
            index: verified.index,
            scratch_bytes: verified.scratch_bytes,
        },
        inventory: verified.inventory,
        receipt: verified.receipt,
    })
}

/// Shared native framing, resolved inventory and union-graph facts. This is
/// deliberately distinct from public full-bundle content/recovery evidence:
/// incremental input may depend on separately authenticated original bodies.
struct VerifiedReaderContents {
    header: FullBundleHeader,
    inventory: Inventory,
    receipt: StreamPackReceipt,
    bytes: usize,
    sha256: [u8; 32],
    pack_offset: u64,
    pack_length: u64,
    index: Vec<u8>,
    scratch_bytes: u64,
    graph: GraphReport,
    resolution_passes: usize,
}

fn read_header(
    reader: &mut impl std::io::BufRead,
    limits: &BundleVerifyLimits,
    incremental: bool,
    live: &mut impl FnMut() -> bool,
) -> Result<FullBundleHeader, BundleVerifyError> {
    let result = if incremental {
        FullBundleHeader::read_incremental(reader, limits.envelope, live)
    } else {
        FullBundleHeader::read(reader, limits.envelope, live)
    };
    checkpoint(live)?;
    result.map_err(header_error)
}

fn verify_reader_contents<R: Read + Seek, W: Read + Write + Seek>(
    input: &mut R,
    workspace: &mut W,
    limits: &BundleVerifyLimits,
    expectations: Option<&BundleExpectations>,
    expected_format: Option<GitHashAlgorithm>,
    originals: Option<&mut dyn BundleOriginalSource>,
    max_original_bytes: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<VerifiedReaderContents, BundleVerifyError> {
    checkpoint(live)?;
    if let Some(expected) = expectations {
        expected
            .validate_limits(limits)
            .map_err(BundleVerifyError::Expectation)?;
    }
    let incremental = originals.is_some();
    let mut scratch = if incremental {
        Scratch::new_with_originals(workspace, limits, max_original_bytes as u64, live)?
    } else {
        Scratch::new(workspace, limits, live)?
    };
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
        read_header(&mut reader, limits, incremental, live)?
    };
    if let Some(expected) = expected_format.filter(|expected| *expected != first.format()) {
        return Err(BundleVerifyError::Pack(
            fgit_pack::PackError::ObjectFormatMismatch {
                expected,
                actual: first.format(),
            },
        ));
    }
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
        let selected = read_header(&mut reader, limits, incremental, live)?;
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
        let result = read_streamed_pack_chunks(
            &mut reader,
            first.format(),
            &pack_limits,
            limits.max_streamed_blob_bytes,
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
    if let Some(source) = originals {
        incremental::capture_originals(
            source,
            &first,
            &mut inventory,
            &mut scratch,
            max_original_bytes,
            limits,
            live,
        )?;
    }
    let mut union_limits = limits.clone();
    union_limits.graph.max_payload_bytes = union_limits
        .graph
        .max_payload_bytes
        .checked_add(inventory.original_bytes() as u64)
        .ok_or(BundleVerifyError::Graph(super::GraphRefusal::Limit(
            "payload bytes",
        )))?;
    if incremental {
        incremental::validate_original_closure(
            &first,
            &mut inventory,
            &mut scratch,
            &union_limits,
            live,
        )?;
    }
    let resolution_passes = inventory.resolve(first.format(), &mut scratch, limits, live)?;
    let mut ids = BTreeSet::new();
    for &identity in inventory.by_id.keys().chain(inventory.originals.keys()) {
        checkpoint(live)?;
        if ids.contains(&identity) {
            continue;
        }
        if ids.len() >= limits.graph.max_objects {
            return Err(BundleVerifyError::Graph(super::GraphRefusal::Limit(
                "objects",
            )));
        }
        ids.insert(identity);
    }
    let result = ObjectGraphAudit::new(&ids, first.format(), union_limits.graph, live);
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
    for &id in &ids {
        checkpoint(live)?;
        let resolved = inventory.object(id)?;
        if resolved.kind == ObjectKind::Blob {
            if resolved.span.length() > limits.max_streamed_blob_bytes {
                return Err(BundleVerifyError::Graph(super::GraphRefusal::Limit(
                    "object bytes",
                )));
            }
            let mut reader = scratch.reader(resolved.span, limits.max_streamed_blob_bytes, live)?;
            // Both the graph hasher and storage span verifier share the same
            // sticky cancellation owner. Neither callback outlives this read.
            let gate = RefCell::new(&mut *live);
            let mut graph_live = || (gate.borrow_mut())();
            let mut read = |output: &mut [u8]| reader.read(output, &mut || (gate.borrow_mut())());
            let result = graph.observe_blob_stream(
                id,
                resolved.span.length(),
                limits.max_streamed_blob_bytes,
                &mut read,
                &mut graph_live,
            );
            checkpoint(&mut graph_live)?;
            result.map_err(|error| match error {
                BlobGraphError::Graph(error) => BundleVerifyError::Graph(error),
                BlobGraphError::Reader(error) => error,
            })?;
        } else {
            let body = scratch.read(resolved.span, limits.graph.max_object_bytes, live)?;
            let result = graph.observe(id, resolved.kind, &body, live);
            checkpoint(live)?;
            result.map_err(BundleVerifyError::Graph)?;
        }
        if let Some(&at) = inventory.by_id.get(&id) {
            let entry = &inventory.entries[at];
            rows.push(StreamPackIndexEntry {
                oid: id,
                pack_offset: entry.offset,
                end_offset: entry.end_offset,
                crc32: entry.crc32,
            });
        }
    }
    let result = graph.finish(&references, live);
    checkpoint(live)?;
    let graph = result.map_err(BundleVerifyError::Graph)?;
    let result = build_streamed_pack_index_v2(&receipt, &rows, &limits.pack, live);
    checkpoint(live)?;
    let index = result.map_err(BundleVerifyError::Pack)?;
    scratch.finish(live)?;
    checkpoint(live)?;
    Ok(VerifiedReaderContents {
        header: first,
        inventory,
        receipt,
        bytes,
        sha256,
        pack_offset,
        pack_length,
        index,
        scratch_bytes: scratch.bytes(),
        graph,
        resolution_passes,
    })
}

#[cfg(test)]
mod tests;
