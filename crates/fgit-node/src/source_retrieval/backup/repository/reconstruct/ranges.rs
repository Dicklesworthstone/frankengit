//! The shared exact-range acquisition kernel. Catalogs select candidate bytes;
//! only the separately approved whole-file seal can authenticate the result.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{ErrorKind, Seek, SeekFrom};
use std::path::PathBuf;

use fgit_crypto::{DigestHasher, Sha256Hasher};

use super::super::archive::stream::Seal;
use super::catalog::{self, CHUNK_BYTES, Catalog, MAX_CATALOG_BYTES};
use super::io::{BUFFER_BYTES, Checkpoint, Control, ReadFailure, Source, SourceFailure};

#[derive(Clone, Copy)]
pub(super) enum DuplicateSources {
    Refuse,
    Skip,
}

pub(super) struct Replica {
    pub(super) path: PathBuf,
    pub(super) source: Option<Source>,
    pub(super) chunks_used: usize,
    pub(super) chunks_rejected: usize,
    pub(super) unavailable: Option<String>,
    pub(super) duplicate_of: Option<usize>,
}

pub(super) fn open_replicas(
    paths: &[PathBuf],
    original: Seal,
    control: &Control<'_>,
    duplicates: DuplicateSources,
) -> Result<Vec<Replica>, String> {
    if paths.is_empty() || paths.len() > super::MAX_REPLICAS {
        return Err("backup reconstruction requires 1..64 explicit copies".into());
    }
    let mut replicas = Vec::with_capacity(paths.len());
    let mut identities = BTreeMap::new();
    for (index, path) in paths.iter().enumerate() {
        control.check()?;
        let (source, unavailable, duplicate_of) = match Source::open(path, original.bytes) {
            Ok(source) => {
                if let Some(&previous) = identities.get(&source.identity()) {
                    match duplicates {
                        DuplicateSources::Refuse => {
                            return Err(
                                "backup replicas must name distinct underlying files".into()
                            );
                        }
                        DuplicateSources::Skip => (None, None, Some(previous)),
                    }
                } else {
                    identities.insert(source.identity(), index);
                    (Some(source), None, None)
                }
            }
            Err(SourceFailure::Unavailable(error)) => (None, Some(error), None),
            Err(SourceFailure::Fatal(error)) => return Err(error),
        };
        replicas.push(Replica {
            path: path.clone(),
            source,
            chunks_used: 0,
            chunks_rejected: 0,
            unavailable,
            duplicate_of,
        });
    }
    control.check()?;
    Ok(replicas)
}

/// Charge each attempted range against the same finite ledger, retaining enough
/// remaining allowance for all not-yet-assembled source bytes and the caller's
/// complete subsequent checksum, decoding and native archive passes.
pub(super) fn copy_ranges(
    catalog: &Catalog,
    replicas: &mut [Replica],
    output: &mut File,
    control: &Control<'_>,
    after_assembly_reads: u64,
) -> Result<(), String> {
    let original = catalog.archive;
    let mut buffer = [0; BUFFER_BYTES];
    for chunk in 0..catalog.count() {
        let start = chunk as u64 * CHUNK_BYTES;
        let end = original.bytes.min(start + CHUNK_BYTES);
        let required = (original.bytes - start)
            .checked_add(after_assembly_reads)
            .ok_or("backup range read reservation overflow")?;
        let mut accepted = false;
        for (index, replica) in replicas.iter_mut().enumerate() {
            control.check()?;
            let Some(source) = replica.source.as_mut() else {
                continue;
            };
            if source.length() < end {
                replica.chunks_rejected += 1;
                continue;
            }
            control.reserve(required)?;
            match copy_candidate(
                source,
                output,
                start,
                end,
                catalog.hash(chunk),
                control,
                &mut buffer,
            ) {
                Ok(true) => {
                    replica.chunks_used += 1;
                    control.checkpoint(Checkpoint::ChunkAccepted {
                        chunk,
                        replica: index,
                    })?;
                    accepted = true;
                    break;
                }
                Ok(false) => replica.chunks_rejected += 1,
                Err(SourceFailure::Unavailable(error)) => {
                    replica.chunks_rejected += 1;
                    replica.unavailable = Some(error);
                    // A changed/short descriptor is never reconsidered.
                    replica.source = None;
                }
                Err(SourceFailure::Fatal(error)) => return Err(error),
            }
        }
        if !accepted {
            return Err(format!(
                "no surviving approved byte range for backup chunk {chunk}"
            ));
        }
    }
    control.check()
}

pub(super) fn read_catalog(
    path: &std::path::Path,
    original: Seal,
    control: &Control<'_>,
) -> Result<Catalog, String> {
    control.check()?;
    let mut source =
        Source::open(path, MAX_CATALOG_BYTES as u64).map_err(SourceFailure::message)?;
    let expected = catalog::encoded_length(original)?;
    if source.length() != expected as u64 {
        return Err(
            "backup catalog length disagrees with original authenticated range count".into(),
        );
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected)
        .map_err(|_| "backup catalog input allocation refused")?;
    bytes.resize(expected, 0);
    let mut at = 0;
    while at < expected {
        let count = control.metadata_read(&mut source.file, &mut bytes[at..])?;
        if count == 0 {
            return Err("backup catalog was truncated while reading".into());
        }
        at += count;
    }
    if control.metadata_read(&mut source.file, &mut [0; 1])? != 0 {
        return Err("backup catalog has trailing bytes".into());
    }
    source.check().map_err(SourceFailure::message)?;
    control.check()?;
    Catalog::parse(&bytes, original)
}

fn copy_candidate(
    source: &mut Source,
    output: &mut File,
    start: u64,
    end: u64,
    expected: &[u8; 32],
    control: &Control<'_>,
    buffer: &mut [u8],
) -> Result<bool, SourceFailure> {
    control.check().map_err(SourceFailure::Fatal)?;
    source.check()?;
    source
        .file
        .seek(SeekFrom::Start(start))
        .map_err(SourceFailure::from_io)?;
    output
        .seek(SeekFrom::Start(start))
        .map_err(|error| SourceFailure::Fatal(format!("backup staging seek failed: {error}")))?;
    let mut hash = Sha256Hasher::new();
    let mut at = start;
    while at < end {
        let maximum = (end - at).min(buffer.len() as u64) as usize;
        let count = match control.read(&mut source.file, &mut buffer[..maximum]) {
            Ok(0) => {
                return Err(SourceFailure::Unavailable(
                    "source became short while reading a range".into(),
                ));
            }
            Ok(count) => count,
            Err(ReadFailure::Io(error)) if error.kind() == ErrorKind::Interrupted => continue,
            Err(ReadFailure::Io(error)) => return Err(SourceFailure::from_io(error)),
            Err(ReadFailure::Gate(error)) => return Err(SourceFailure::Fatal(error)),
        };
        hash.update(&buffer[..count]);
        control
            .write_all(output, &buffer[..count])
            .map_err(SourceFailure::Fatal)?;
        at += count as u64;
    }
    source.check()?;
    control.check().map_err(SourceFailure::Fatal)?;
    Ok(&hash.finish() == expected)
}
