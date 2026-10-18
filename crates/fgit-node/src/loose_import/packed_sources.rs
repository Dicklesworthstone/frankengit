//! Packed-source decoding with immutable disk custody, not retained body maps.
//! Every pack is checksum/index/native-identity verified before its cache becomes
//! usable. Per-pack decoder/cache bounds and operation-wide work remain distinct.
use super::*;

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
        let limits = import_pack_limits(max_object_bytes);
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
                MAX_IMPORT_PACK_BYTES,
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
    ) -> Result<Option<fgit_git_object::LooseObject>, LooseGitImportRefusal> {
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
                Some(entry) => pack.spool.read(identity, entry, control).map(Some),
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
        let pack_bytes = read_regular_bounded(
            &pack_path,
            "read packed object file",
            "regular packed object file",
            MAX_IMPORT_PACK_BYTES,
            BoundedInputClass::PackOrIndex,
            control,
        )?;
        let next_pack_bytes = self
            .loaded_pack_bytes
            .saturating_add(u64::try_from(pack_bytes.len()).unwrap_or(u64::MAX));
        if next_pack_bytes > MAX_IMPORT_TOTAL_PACK_BYTES {
            return Err(LooseGitImportRefusal::PackInputBytesExceeded {
                path: Box::new(pack_path),
                limit: MAX_IMPORT_TOTAL_PACK_BYTES,
                observed: next_pack_bytes,
            });
        }
        let quarantined = read_verified_pack(
            &pack_bytes,
            source.index.format(),
            &self.limits,
            &mut control.cpu_probe(),
            &NativeChecksumVerifier,
        )
        .map_err(|error| pack_refusal(source.pack_path.clone(), error))?;
        if &quarantined.trailer != source.index.pack_checksum() {
            return Err(pack_refusal(
                source.index_path.clone(),
                PackError::TrailerChecksumMismatch,
            ));
        }
        validate_idx_pack_count(&source.index, quarantined.header)
            .map_err(|error| pack_refusal(source.index_path.clone(), error))?;

        let mut entries_by_offset = BTreeMap::new();
        for entry in source.index.entries() {
            control.checkpoint()?;
            if entries_by_offset.insert(entry.pack_offset, entry).is_some() {
                return Err(pack_refusal(
                    source.index_path.clone(),
                    PackError::DuplicateObjectOffset(entry.pack_offset),
                ));
            }
        }
        let pack_body_end = pack_bytes
            .len()
            .checked_sub(source.index.format().digest_len())
            .ok_or_else(|| {
                pack_refusal(
                    source.pack_path.clone(),
                    PackError::Truncated {
                        context: "pack checksum",
                    },
                )
            })?;
        for (position, entry) in quarantined.entries().iter().enumerate() {
            control.checkpoint()?;
            let Some(index_entry) = entries_by_offset.get(&entry.offset) else {
                return Err(pack_refusal(
                    source.index_path.clone(),
                    PackError::ObjectCountMismatch {
                        declared: u32::try_from(source.index.entries().len()).unwrap_or(u32::MAX),
                        actual: u32::try_from(quarantined.entries().len()).unwrap_or(u32::MAX),
                    },
                ));
            };
            let end = quarantined
                .entries()
                .get(position + 1)
                .and_then(|next| usize::try_from(next.offset).ok())
                .unwrap_or(pack_body_end);
            let start = usize::try_from(entry.offset).map_err(|_| {
                pack_refusal(
                    source.pack_path.clone(),
                    PackError::IntegerOverflow {
                        context: "pack entry offset",
                    },
                )
            })?;
            let raw_entry = pack_bytes.get(start..end).ok_or_else(|| {
                pack_refusal(
                    source.pack_path.clone(),
                    PackError::Truncated {
                        context: "indexed pack entry",
                    },
                )
            })?;
            validate_idx_entry_crc(
                index_entry,
                raw_entry,
                &self.limits,
                &mut control.cpu_probe(),
            )
            .map_err(|error| pack_refusal(source.index_path.clone(), error))?;
        }
        let inflated_bytes = quarantined
            .entries()
            .iter()
            .try_fold(0_u64, |total, entry| {
                total.checked_add(u64::try_from(entry.inflated.len()).ok()?)
            })
            .unwrap_or(u64::MAX);
        let next_inflated = self.loaded_inflated_bytes.saturating_add(inflated_bytes);
        if next_inflated > self.maximum_bytes {
            return Err(LooseGitImportRefusal::TotalObjectBytesExceeded {
                limit: self.maximum_bytes,
                observed: next_inflated,
            });
        }
        control.checkpoint()?;
        let objects = quarantined
            .into_scalar_objects(|offset| entries_by_offset.get(&offset).map(|entry| entry.oid))
            .map_err(|error| pack_refusal(source.pack_path.clone(), error))?;
        control.checkpoint()?;
        // The decoder and resident resolver cache keep their original 128 MiB
        // ceilings. Only total reconstruction work spans the selected profile.
        // Retain ONE ResolutionBudget across all packs; never renew delta work.
        let mut resolution_limits = self.limits.clone();
        resolution_limits.max_total_expanded_bytes =
            usize::try_from(self.maximum_bytes).map_err(|_| {
                super::control::interrupted(fgit_types::RefusalCode::ResourceBudgetExceeded)
            })?;
        let mut resolver =
            CachedResolver::new(&objects, &(), &resolution_limits, &mut control.cpu_probe())
                .map_err(|error| pack_refusal(source.pack_path.clone(), error))?;
        let remaining = self
            .maximum_bytes
            .checked_sub(self.loaded_resolved_bytes)
            .ok_or_else(|| {
                super::control::interrupted(fgit_types::RefusalCode::InternalInvariantBreach)
            })?;
        let mut spool = spool::Spool::create(&self.custody_root, remaining, control)?;
        let mut resolved_bytes = 0_u64;
        let mut verified_objects = BTreeMap::new();
        for entry in source.index.entries() {
            control.checkpoint()?;
            let (object_type, body) = resolver
                .resolve_id_typed_with_budget(
                    &entry.oid,
                    &mut self.resolution_budget,
                    &mut control.cpu_probe(),
                )
                .map_err(|error| pack_refusal(source.pack_path.clone(), error))?;
            verify_native_object(
                source.index.format(),
                object_type,
                &body,
                &entry.oid,
                AcceptanceProfile::GitCompatibleImport,
                &self.parse_limits,
            )
            .map_err(|error| pack_refusal(source.pack_path.clone(), error))?;
            control.checkpoint()?;
            resolved_bytes = resolved_bytes
                .checked_add(body.len() as u64)
                .ok_or_else(|| {
                    super::control::interrupted(fgit_types::RefusalCode::ResourceBudgetExceeded)
                })?;
            let handle = spool.retain(
                entry.oid,
                fgit_git_object::LooseObject {
                    object_type,
                    declared_size: body.len(),
                    body,
                },
                control,
            )?;
            verified_objects.insert(entry.oid, handle);
        }
        control.checkpoint()?;
        self.loaded_pack_bytes = next_pack_bytes;
        self.loaded_inflated_bytes = next_inflated;
        self.loaded_resolved_bytes += resolved_bytes;
        self.loaded_objects = next_objects;
        self.sources[source_index].verified_objects = Some(VerifiedPack {
            entries: verified_objects,
            spool,
        });
        Ok(())
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
