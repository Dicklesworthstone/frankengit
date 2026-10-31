//! Packed-source decoding with immutable disk custody, not retained body maps.
//! Every pack is checksum/index/native-identity verified before its cache becomes
//! usable. Per-pack decoder/cache bounds and operation-wide work remain distinct.
#[cfg(test)]
use super::graph;
use super::{
    AcceptanceProfile, BTreeMap, BoundedInputClass, GitHashAlgorithm, GitOid, IdxV2, ImportControl,
    LooseGitImportRefusal, MAX_IMPORT_INDEX_FILE_BYTES, MAX_IMPORT_OBJECTS, MAX_IMPORT_PACKS,
    MAX_IMPORT_TOTAL_INDEX_BYTES, NativeChecksumVerifier, OsStr, OsString, PackError, PackLimits,
    ParseLimits, ParsedDeltaBase, Path, PathBuf, ResolutionBudget, StreamPackEntry,
    StreamPackError, apply_delta_to_charged_base_with_budget, bounded_directory_entries, fs,
    import_pack_limits, io_refusal, is_ignored_pack_accelerator, object_type_from_base_entry,
    open_regular_bounded, pack_input_limit, pack_refusal, parse_limits, parse_pack_header,
    path_metadata, profile, read_regular_bounded, read_streamed_pack, spool,
    validate_idx_pack_count, verify_native_object,
};
use std::io::{Read, Seek, SeekFrom};

use super::control::IO_CHUNK_BYTES;

pub(super) struct VerifiedPack {
    entries: BTreeMap<GitOid, spool::Entry>,
    spool: spool::Spool,
}

#[derive(Default)]
struct PackPairPaths {
    index: Option<PathBuf>,
    pack: Option<PathBuf>,
}

pub(super) struct PackedObjectSource {
    index_path: PathBuf,
    pack_path: PathBuf,
    index: IdxV2,
    pub(super) verified_objects: Option<VerifiedPack>,
}

pub(super) struct PackedObjectSources {
    pub(super) sources: Vec<PackedObjectSource>,
    limits: PackLimits,
    parse_limits: ParseLimits,
    resolution_budget: ResolutionBudget,
    loaded_pack_bytes: u64,
    loaded_inflated_bytes: u64,
    loaded_resolved_bytes: u64,
    loaded_objects: usize,
    custody_root: PathBuf,
    maximum_bytes: u64,
}

impl PackedObjectSources {
    pub(super) fn open_with_profile(
        git_directory: &Path,
        object_format: GitHashAlgorithm,
        max_object_bytes: u64,
        custody_root: &Path,
        maximum_bytes: u64,
        control: &ImportControl<'_>,
    ) -> Result<Self, LooseGitImportRefusal> {
        control.checkpoint()?;
        profile::validate_limit(maximum_bytes)?;
        let limits = import_pack_limits(max_object_bytes, maximum_bytes);
        let parse_limits = parse_limits(object_format, max_object_bytes);
        let pack_directory = git_directory.join("objects/pack");
        let Some(metadata) =
            path_metadata(&pack_directory, "inspect packed-object directory", control)?
        else {
            return Ok(Self::empty(
                limits,
                parse_limits,
                custody_root,
                maximum_bytes,
            ));
        };
        if metadata.file_type().is_symlink() {
            return Err(LooseGitImportRefusal::SymbolicLink(Box::new(
                pack_directory,
            )));
        }
        if !metadata.is_dir() {
            return Err(LooseGitImportRefusal::PathKind {
                expected: "packed-object directory",
                path: Box::new(pack_directory),
            });
        }

        let mut pairs = BTreeMap::<OsString, PackPairPaths>::new();
        for entry in bounded_directory_entries(&pack_directory, control)? {
            control.checkpoint()?;
            let path = entry.path();
            let metadata = control
                .run(|| fs::symlink_metadata(&path))?
                .map_err(|error| io_refusal("inspect pack-directory entry", path.clone(), error))?;
            if metadata.file_type().is_symlink() {
                return Err(LooseGitImportRefusal::SymbolicLink(Box::new(path)));
            }
            if !metadata.is_file() {
                return Err(LooseGitImportRefusal::PathKind {
                    expected: "regular pack-directory file",
                    path: Box::new(path),
                });
            }
            let file_name = path.file_name().unwrap_or_else(|| OsStr::new(""));
            if file_name == OsStr::new("multi-pack-index") || is_ignored_pack_accelerator(&path) {
                continue;
            }
            let Some(extension) = path.extension().and_then(OsStr::to_str) else {
                return Err(LooseGitImportRefusal::PackDirectoryEntryUnsupported(
                    Box::new(path),
                ));
            };
            if !matches!(extension, "idx" | "pack") {
                return Err(LooseGitImportRefusal::PackDirectoryEntryUnsupported(
                    Box::new(path),
                ));
            }
            let Some(stem) = path.file_stem() else {
                return Err(LooseGitImportRefusal::PackDirectoryEntryUnsupported(
                    Box::new(path),
                ));
            };
            let pair = pairs.entry(stem.to_os_string()).or_default();
            let slot = if extension == "idx" {
                &mut pair.index
            } else {
                &mut pair.pack
            };
            if slot.replace(path.clone()).is_some() {
                return Err(LooseGitImportRefusal::PackDirectoryEntryUnsupported(
                    Box::new(path),
                ));
            }
        }
        if pairs.len() > MAX_IMPORT_PACKS {
            return Err(LooseGitImportRefusal::PackFileLimitExceeded {
                limit: MAX_IMPORT_PACKS,
            });
        }

        let mut sources = Vec::new();
        let mut total_index_bytes = 0_u64;
        for (_, pair) in pairs {
            control.checkpoint()?;
            let (index_path, pack_path) = match (pair.index, pair.pack) {
                (Some(index), Some(pack)) => (index, pack),
                (Some(index), None) => {
                    return Err(LooseGitImportRefusal::PackPairMissing(Box::new(index)));
                }
                (None, Some(pack)) => {
                    return Err(LooseGitImportRefusal::PackPairMissing(Box::new(pack)));
                }
                (None, None) => unreachable!("a pack pair is created only for a pack or index"),
            };
            let index_bytes = read_regular_bounded(
                &index_path,
                "read pack index",
                "regular pack index file",
                MAX_IMPORT_INDEX_FILE_BYTES,
                BoundedInputClass::PackOrIndex,
                control,
            )?;
            total_index_bytes = total_index_bytes
                .saturating_add(u64::try_from(index_bytes.len()).unwrap_or(u64::MAX));
            if total_index_bytes > MAX_IMPORT_TOTAL_INDEX_BYTES {
                return Err(LooseGitImportRefusal::PackInputBytesExceeded {
                    path: Box::new(pack_directory),
                    limit: MAX_IMPORT_TOTAL_INDEX_BYTES,
                    observed: total_index_bytes,
                });
            }
            let index = IdxV2::parse_verified(
                &index_bytes,
                object_format,
                &limits,
                &mut control.cpu_probe(),
                &NativeChecksumVerifier,
            )
            .map_err(|source| pack_refusal(index_path.clone(), source))?;
            sources.push(PackedObjectSource {
                index_path,
                pack_path,
                index,
                verified_objects: None,
            });
        }

        Ok(Self {
            sources,
            limits,
            parse_limits,
            resolution_budget: ResolutionBudget::new(),
            loaded_pack_bytes: 0,
            loaded_inflated_bytes: 0,
            loaded_resolved_bytes: 0,
            loaded_objects: 0,
            custody_root: custody_root.to_path_buf(),
            maximum_bytes,
        })
    }

    fn empty(
        limits: PackLimits,
        parse_limits: ParseLimits,
        custody_root: &Path,
        maximum_bytes: u64,
    ) -> Self {
        Self {
            sources: Vec::new(),
            limits,
            parse_limits,
            resolution_budget: ResolutionBudget::new(),
            loaded_pack_bytes: 0,
            loaded_inflated_bytes: 0,
            loaded_resolved_bytes: 0,
            loaded_objects: 0,
            custody_root: custody_root.to_path_buf(),
            maximum_bytes,
        }
    }

    pub(super) fn read(
        &mut self,
        identity: GitOid,
        control: &ImportControl<'_>,
    ) -> Result<Option<fgit_crypto::IdentifiedGitObject>, LooseGitImportRefusal> {
        control.checkpoint()?;
        let Some(source_index) = self
            .sources
            .iter()
            .position(|source| source.index.lookup(&identity).is_some())
        else {
            return Ok(None);
        };
        self.load(source_index, control)?;
        let result = match self.sources[source_index].verified_objects.as_mut() {
            Some(pack) => match pack.entries.get(&identity).copied() {
                Some(entry) => pack
                    .spool
                    .read_identified(identity, entry, control)
                    .map(Some),
                None => Ok(None),
            },
            None => Ok(None),
        };
        let result = control.after(result, |error| error);
        if result.is_err() {
            // A failed read cannot leave a reusable cache from this attempt.
            // Work already charged to the operation is deliberately not reset.
            self.sources[source_index].verified_objects = None;
        }
        result
    }

    /// Stream one checksum-bound pack into private disk custody
    /// (frankengit-855v). The pack is never held whole: resident memory is
    /// one inflated member, or one delta base, program and result. Every
    /// member is bound to its idx row (offset, CRC and, once reconstructed,
    /// native identity) and charged to the operation before custody, and a
    /// pack installs nothing unless all of it verifies.
    fn load(
        &mut self,
        source_index: usize,
        control: &ImportControl<'_>,
    ) -> Result<(), LooseGitImportRefusal> {
        control.checkpoint()?;
        if self.sources[source_index].verified_objects.is_some() {
            return Ok(());
        }
        let source = &self.sources[source_index];
        let next_objects = self
            .loaded_objects
            .checked_add(source.index.entries().len())
            .filter(|count| *count <= MAX_IMPORT_OBJECTS)
            .ok_or(LooseGitImportRefusal::ObjectLimitExceeded {
                limit: MAX_IMPORT_OBJECTS,
            })?;
        let pack_path = source.pack_path.clone();
        let index_path = source.index_path.clone();
        let format = source.index.format();
        let input_limit = pack_input_limit(self.maximum_bytes);
        let (mut file, pack_length) = open_regular_bounded(
            &pack_path,
            "read packed object file",
            "regular packed object file",
            input_limit,
            BoundedInputClass::PackOrIndex,
            control,
        )?;
        let next_pack_bytes = self.loaded_pack_bytes.saturating_add(pack_length);
        if next_pack_bytes > input_limit {
            return Err(LooseGitImportRefusal::PackInputBytesExceeded {
                path: Box::new(pack_path),
                limit: input_limit,
                observed: next_pack_bytes,
            });
        }
        // Refuse an idx/pack count mismatch before inflating any member.
        let mut fixed = [0_u8; 12];
        control
            .run(|| file.read_exact(&mut fixed))?
            .map_err(|error| io_refusal("read pack header", pack_path.clone(), error))?;
        let header = parse_pack_header(&fixed, &self.limits)
            .map_err(|error| pack_refusal(pack_path.clone(), error))?;
        validate_idx_pack_count(&source.index, header)
            .map_err(|error| pack_refusal(index_path.clone(), error))?;
        control
            .run(|| file.seek(SeekFrom::Start(0)))?
            .map_err(|error| io_refusal("rewind packed object file", pack_path.clone(), error))?;

        let mut rows = BTreeMap::new();
        for entry in source.index.entries() {
            control.checkpoint()?;
            if rows.insert(entry.pack_offset, entry.clone()).is_some() {
                return Err(pack_refusal(
                    index_path,
                    PackError::DuplicateObjectOffset(entry.pack_offset),
                ));
            }
        }
        let pack_checksum = *source.index.pack_checksum();
        let remaining = self
            .maximum_bytes
            .checked_sub(self.loaded_resolved_bytes)
            .ok_or_else(|| {
                super::control::interrupted(fgit_types::RefusalCode::InternalInvariantBreach)
            })?;
        let mut custody = StreamedPack {
            format,
            pack_path: &pack_path,
            index_path: &index_path,
            rows: &rows,
            declared: header.object_count,
            limits: &self.limits,
            parse_limits: &self.parse_limits,
            budget: &mut self.resolution_budget,
            spool: spool::Spool::create(&self.custody_root, remaining, control)?,
            programs: None,
            custody_root: &self.custody_root,
            maximum_bytes: self.maximum_bytes,
            inflated_before: self.loaded_inflated_bytes,
            inflated: 0,
            resolved_bytes: 0,
            resolved: BTreeMap::new(),
            by_id: BTreeMap::new(),
            pending: Vec::new(),
            fanout: BTreeMap::new(),
        };
        let mut reader = std::io::BufReader::with_capacity(IO_CHUNK_BYTES, file);
        let receipt = read_streamed_pack(
            &mut reader,
            format,
            custody.limits,
            &mut control.cpu_probe(),
            |entry| custody.accept(entry, control),
        );
        let receipt = control.after(receipt, |error| match error {
            StreamPackError::Io(error) => {
                io_refusal("read packed object file", pack_path.clone(), error)
            }
            StreamPackError::Pack(error) => pack_refusal(pack_path.clone(), error),
            StreamPackError::Sink(error) => error,
        })?;
        if receipt.trailer() != pack_checksum {
            return Err(pack_refusal(
                index_path.clone(),
                PackError::TrailerChecksumMismatch,
            ));
        }
        custody.resolve_pending(control)?;
        let StreamedPack {
            spool,
            inflated,
            resolved_bytes,
            resolved,
            ..
        } = custody;
        if resolved.len() != rows.len() {
            return Err(pack_refusal(pack_path, PackError::MissingDeltaBase));
        }
        let mut verified_objects = BTreeMap::new();
        for member in resolved.into_values() {
            control.checkpoint()?;
            verified_objects.insert(member.id, member.handle);
        }
        control.checkpoint()?;
        self.loaded_pack_bytes = next_pack_bytes;
        self.loaded_inflated_bytes += inflated;
        self.loaded_resolved_bytes += resolved_bytes;
        self.loaded_objects = next_objects;
        self.sources[source_index].verified_objects = Some(VerifiedPack {
            entries: verified_objects,
            spool,
        });
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DeltaBase {
    Offset(u64),
    Identity(GitOid),
}

#[derive(Clone, Copy)]
struct Member {
    id: GitOid,
    kind: fgit_git_object::ObjectType,
    handle: spool::Entry,
    depth: usize,
}

/// One pack's custody while it streams. Base members are verified against
/// their idx identity and spooled at once; a delta whose base is already
/// reconstructed is resolved at once; any other delta program waits in a
/// separate unverified spool until the trailer is authenticated.
struct StreamedPack<'a> {
    format: GitHashAlgorithm,
    pack_path: &'a Path,
    index_path: &'a Path,
    rows: &'a BTreeMap<u64, fgit_pack::IdxEntry>,
    declared: u32,
    limits: &'a PackLimits,
    parse_limits: &'a ParseLimits,
    budget: &'a mut ResolutionBudget,
    spool: spool::Spool,
    programs: Option<spool::Spool>,
    custody_root: &'a Path,
    maximum_bytes: u64,
    inflated_before: u64,
    inflated: u64,
    resolved_bytes: u64,
    resolved: BTreeMap<u64, Member>,
    by_id: BTreeMap<GitOid, u64>,
    pending: Vec<(u64, DeltaBase, spool::Entry)>,
    fanout: BTreeMap<DeltaBase, usize>,
}

impl StreamedPack<'_> {
    fn pack_error(&self, error: PackError) -> LooseGitImportRefusal {
        pack_refusal(self.pack_path.to_path_buf(), error)
    }

    const fn invariant() -> LooseGitImportRefusal {
        super::control::interrupted(fgit_types::RefusalCode::InternalInvariantBreach)
    }

    fn accept(
        &mut self,
        streamed: StreamPackEntry,
        control: &ImportControl<'_>,
    ) -> Result<(), LooseGitImportRefusal> {
        control.checkpoint()?;
        let entry = streamed.entry;
        let Some(row) = self.rows.get(&entry.offset).cloned() else {
            return Err(pack_refusal(
                self.index_path.to_path_buf(),
                PackError::ObjectCountMismatch {
                    declared: u32::try_from(self.rows.len()).unwrap_or(u32::MAX),
                    actual: self.declared,
                },
            ));
        };
        if row.crc32 != streamed.crc32 {
            return Err(pack_refusal(
                self.index_path.to_path_buf(),
                PackError::IndexEntryCrcMismatch {
                    expected: row.crc32,
                    actual: streamed.crc32,
                },
            ));
        }
        // Every decoded member counts, reachable or not.
        self.inflated = self
            .inflated
            .checked_add(entry.inflated.len() as u64)
            .ok_or_else(Self::invariant)?;
        let observed = self.inflated_before.saturating_add(self.inflated);
        if observed > self.maximum_bytes {
            return Err(LooseGitImportRefusal::TotalObjectBytesExceeded {
                limit: self.maximum_bytes,
                observed,
            });
        }
        self.budget
            .charge_work(1, self.limits)
            .map_err(|error| self.pack_error(error))?;
        let base = match entry.delta_base {
            None => {
                let kind = object_type_from_base_entry(entry.header.kind)
                    .map_err(|error| self.pack_error(error))?;
                return self.retain(entry.offset, row.oid, kind, entry.inflated, 0, control);
            }
            Some(ParsedDeltaBase::Ofs { base_offset, .. }) => {
                // Offsets name exact earlier member starts, never bytes inside one.
                if base_offset >= entry.offset || !self.rows.contains_key(&base_offset) {
                    return Err(self.pack_error(PackError::MissingDeltaBase));
                }
                DeltaBase::Offset(base_offset)
            }
            Some(ParsedDeltaBase::Ref { base, .. }) => DeltaBase::Identity(base),
        };
        let limit = self.limits.max_delta_fanout;
        let count = self.fanout.entry(base).or_default();
        *count += 1;
        let fanout = *count;
        if fanout > limit {
            return Err(self.pack_error(PackError::DeltaFanoutLimit { fanout, limit }));
        }
        if let Some(member) = self.base_member(base) {
            return self.reconstruct(entry.offset, row.oid, member, &entry.inflated, control);
        }
        if self.programs.is_none() {
            self.programs = Some(spool::Spool::create(
                self.custody_root,
                self.maximum_bytes,
                control,
            )?);
        }
        let programs = self.programs.as_mut().ok_or_else(Self::invariant)?;
        let held = programs.retain_unverified(&entry.inflated, control)?;
        self.pending.push((entry.offset, base, held));
        Ok(())
    }

    fn base_member(&self, base: DeltaBase) -> Option<Member> {
        let offset = match base {
            DeltaBase::Offset(offset) => offset,
            // Bases are learned only from this pack's reconstructed members.
            DeltaBase::Identity(id) => *self.by_id.get(&id)?,
        };
        self.resolved.get(&offset).copied()
    }

    fn reconstruct(
        &mut self,
        offset: u64,
        id: GitOid,
        base: Member,
        program: &[u8],
        control: &ImportControl<'_>,
    ) -> Result<(), LooseGitImportRefusal> {
        let depth = base.depth + 1;
        if depth > self.limits.max_delta_depth {
            return Err(self.pack_error(PackError::DeltaDepthLimit {
                depth,
                limit: self.limits.max_delta_depth,
            }));
        }
        // The spool re-identifies the base bytes before they are used.
        let base_body = self.spool.read(base.id, base.handle, control)?.body;
        let result = apply_delta_to_charged_base_with_budget(
            &base_body,
            program,
            self.limits,
            self.budget,
            &mut control.cpu_probe(),
        );
        drop(base_body);
        let result = control.after(result, |error| self.pack_error(error))?;
        self.retain(offset, id, base.kind, result, depth, control)
    }

    fn retain(
        &mut self,
        offset: u64,
        id: GitOid,
        kind: fgit_git_object::ObjectType,
        body: Vec<u8>,
        depth: usize,
        control: &ImportControl<'_>,
    ) -> Result<(), LooseGitImportRefusal> {
        let verified = verify_native_object(
            self.format,
            kind,
            &body,
            &id,
            AcceptanceProfile::GitCompatibleImport,
            self.parse_limits,
        );
        control.after(verified, |error| self.pack_error(error))?;
        self.resolved_bytes = self
            .resolved_bytes
            .checked_add(body.len() as u64)
            .ok_or_else(Self::invariant)?;
        let handle = self.spool.retain(
            id,
            fgit_git_object::LooseObject {
                object_type: kind,
                declared_size: body.len(),
                body,
            },
            control,
        )?;
        self.resolved.insert(
            offset,
            Member {
                id,
                kind,
                handle,
                depth,
            },
        );
        self.by_id.insert(id, offset);
        Ok(())
    }

    /// Bounded passes over deltas whose base arrived later (REF_DELTA) or was
    /// itself waiting. A pass without progress refuses; nothing is fetched.
    fn resolve_pending(
        &mut self,
        control: &ImportControl<'_>,
    ) -> Result<(), LooseGitImportRefusal> {
        let passes = self.limits.max_delta_depth.min(self.pending.len());
        for _ in 0..=passes {
            control.checkpoint()?;
            if self.pending.is_empty() {
                return Ok(());
            }
            let waiting = std::mem::take(&mut self.pending);
            let before = waiting.len();
            for (offset, base, held) in waiting {
                control.checkpoint()?;
                let Some(member) = self.base_member(base) else {
                    self.pending.push((offset, base, held));
                    continue;
                };
                let row = self
                    .rows
                    .get(&offset)
                    .cloned()
                    .ok_or_else(Self::invariant)?;
                let programs = self.programs.as_mut().ok_or_else(Self::invariant)?;
                let program = programs.read_unverified(held, control)?;
                self.reconstruct(offset, row.oid, member, &program, control)?;
            }
            if self.pending.len() == before {
                break;
            }
        }
        if self.pending.is_empty() {
            Ok(())
        } else {
            Err(self.pack_error(PackError::MissingDeltaBase))
        }
    }
}

impl PackedObjectSources {
    #[cfg(test)]
    pub(super) fn open(
        git_directory: &Path,
        object_format: GitHashAlgorithm,
        max_object_bytes: u64,
        control: &ImportControl<'_>,
    ) -> Result<Self, LooseGitImportRefusal> {
        Self::open_with_profile(
            git_directory,
            object_format,
            max_object_bytes,
            git_directory,
            graph::MAX_REACHABLE_OBJECT_BYTES,
            control,
        )
    }
    pub(super) fn finish(mut self) -> Result<(), LooseGitImportRefusal> {
        for source in &mut self.sources {
            if let Some(pack) = source.verified_objects.take() {
                pack.spool.finish()?;
            }
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests;
