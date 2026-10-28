//! Bounded native source files, refs, and source-kind validation.
#[cfg(test)]
use super::Read;
use super::{
    BTreeMap, GitHashAlgorithm, GitOid, ImportControl, InflateLimits, LooseGitImportRefusal,
    MAX_IMPORT_COMPRESSED_OBJECT_BYTES, MAX_IMPORT_COMPRESSED_OBJECT_BYTES_USIZE,
    MAX_IMPORT_DIRECTORY_ENTRIES, MAX_IMPORT_OBJECTS, MAX_IMPORT_PACKED_REFS_HEADER_BYTES,
    MAX_IMPORT_REF_DEPTH, MAX_REF_NAME_LEN, MIN_IMPORT_PACK_INPUT_BYTES, OsStr, PackError,
    PackLimits, PackedObjectSources, ParseLimits, Path, PathBuf, ReadFailure, RefName, control, fs,
    io,
};

pub(super) fn resolve_git_directory(
    source: &Path,
    control: &ImportControl<'_>,
) -> Result<PathBuf, LooseGitImportRefusal> {
    control.checkpoint()?;
    require_directory(source, "Git source directory", control)?;
    let dot_git = source.join(".git");
    let git_directory = match control.run(|| fs::symlink_metadata(&dot_git))? {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(LooseGitImportRefusal::SymbolicLink(Box::new(dot_git)));
            }
            if metadata.is_dir() {
                dot_git
            } else {
                return Err(LooseGitImportRefusal::GitDirectoryFileUnsupported(
                    Box::new(dot_git),
                ));
            }
        }
        Err(source_error) if source_error.kind() == io::ErrorKind::NotFound => source.to_path_buf(),
        Err(source_error) => return Err(io_refusal("inspect .git", dot_git, source_error)),
    };
    let objects = git_directory.join("objects");
    match control.run(|| fs::symlink_metadata(&objects))? {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(LooseGitImportRefusal::SymbolicLink(Box::new(objects)))
        }
        Ok(metadata) if metadata.is_dir() => Ok(git_directory),
        Ok(_) => Err(LooseGitImportRefusal::GitDirectoryMissing(Box::new(
            git_directory,
        ))),
        Err(source_error) if source_error.kind() == io::ErrorKind::NotFound => Err(
            LooseGitImportRefusal::GitDirectoryMissing(Box::new(git_directory)),
        ),
        Err(source_error) => Err(io_refusal(
            "inspect Git objects directory",
            objects,
            source_error,
        )),
    }
}

pub(super) fn reject_object_alternates(
    git_directory: &Path,
    control: &ImportControl<'_>,
) -> Result<(), LooseGitImportRefusal> {
    control.checkpoint()?;
    let alternates = git_directory.join("objects/info/alternates");
    if path_exists(&alternates, control)? {
        return Err(LooseGitImportRefusal::ObjectAlternatesUnsupported(
            Box::new(alternates),
        ));
    }
    Ok(())
}

/// Packs are streamed into disk custody, so resident memory is one object (or
/// one delta base, program and result) whatever these bounds are. Both the
/// per-pack decoder bound and compressed input therefore follow the selected
/// profile instead of a fixed resident-cache envelope (frankengit-855v).
pub(super) fn import_pack_limits(max_object_bytes: u64, maximum_bytes: u64) -> PackLimits {
    let maximum = usize::try_from(maximum_bytes).unwrap_or(usize::MAX);
    PackLimits {
        max_input_bytes: usize::try_from(pack_input_limit(maximum_bytes)).unwrap_or(usize::MAX),
        max_object_bytes: usize::try_from(max_object_bytes).unwrap_or(usize::MAX),
        max_total_expanded_bytes: maximum,
        max_cached_bytes: maximum,
        max_delta_work: usize::try_from(delta_work_limit(maximum_bytes)).unwrap_or(usize::MAX),
        ..PackLimits::default()
    }
}

/// Reconstruction work one import may spend, across every pack
/// (frankengit-kxew). A streamed member is reconstructed exactly once:
/// it is charged one unit, and a delta is charged its base length and its
/// result bytes. Both are resolved bytes the profile already bounds, so the
/// work bound follows the same operator decision instead of the fixed
/// 256 MiB default that refused ordinary repositories.
pub(super) const fn delta_work_limit(maximum_bytes: u64) -> u64 {
    maximum_bytes
        .saturating_mul(2)
        .saturating_add(MAX_IMPORT_OBJECTS as u64)
}

/// Compressed pack bytes one import may read, per pack and in total: twice the
/// selected native-byte profile, never less than the 128 MiB floor. A pack
/// whose objects fit the profile exceeds it only through framing and DEFLATE
/// expansion of incompressible members.
pub(super) const fn pack_input_limit(maximum_bytes: u64) -> u64 {
    let doubled = maximum_bytes.saturating_mul(2);
    if doubled > MIN_IMPORT_PACK_INPUT_BYTES {
        doubled
    } else {
        MIN_IMPORT_PACK_INPUT_BYTES
    }
}

pub(super) fn is_ignored_pack_accelerator(path: &Path) -> bool {
    matches!(
        path.extension().and_then(OsStr::to_str),
        Some("bitmap" | "keep" | "mtimes" | "promisor" | "rev")
    )
}

#[derive(Clone, Copy)]
pub(super) enum BoundedInputClass {
    PackOrIndex,
    RefControl,
    CompressedLooseObject,
}

impl BoundedInputClass {
    fn limit_refusal(self, path: &Path, limit: u64, observed: u64) -> LooseGitImportRefusal {
        match self {
            Self::PackOrIndex => LooseGitImportRefusal::PackInputBytesExceeded {
                path: Box::new(path.to_path_buf()),
                limit,
                observed,
            },
            Self::RefControl => LooseGitImportRefusal::RefInputBytesExceeded {
                path: Box::new(path.to_path_buf()),
                limit,
                observed,
            },
            Self::CompressedLooseObject => {
                LooseGitImportRefusal::CompressedObjectBytesExceeded { limit, observed }
            }
        }
    }
}

pub(super) fn read_regular_bounded(
    path: &Path,
    operation: &'static str,
    expected: &'static str,
    limit: u64,
    class: BoundedInputClass,
    control: &ImportControl<'_>,
) -> Result<Vec<u8>, LooseGitImportRefusal> {
    let (file, _) = open_regular_bounded(path, operation, expected, limit, class, control)?;
    let bytes = control::read_bytes(file, limit, control).map_err(|error| match error {
        ReadFailure::Io(error) => io_refusal(operation, path.to_path_buf(), error),
        ReadFailure::Interrupted(error) => error,
    })?;
    let observed = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if observed > limit {
        return Err(class.limit_refusal(path, limit, observed));
    }
    Ok(bytes)
}

/// The checks of [`read_regular_bounded`] without the read: a regular,
/// non-symlink file within `limit`, returned open with its observed length.
/// A caller that streams it must still bound the bytes it reads, because the
/// file can grow after this check (frankengit-855v).
pub(super) fn open_regular_bounded(
    path: &Path,
    operation: &'static str,
    expected: &'static str,
    limit: u64,
    class: BoundedInputClass,
    control: &ImportControl<'_>,
) -> Result<(fs::File, u64), LooseGitImportRefusal> {
    control.checkpoint()?;
    let metadata = control
        .run(|| fs::symlink_metadata(path))?
        .map_err(|error| io_refusal(operation, path.to_path_buf(), error))?;
    if metadata.file_type().is_symlink() {
        return Err(LooseGitImportRefusal::SymbolicLink(Box::new(
            path.to_path_buf(),
        )));
    }
    if !metadata.is_file() {
        return Err(LooseGitImportRefusal::PathKind {
            expected,
            path: Box::new(path.to_path_buf()),
        });
    }
    if metadata.len() > limit {
        return Err(class.limit_refusal(path, limit, metadata.len()));
    }

    // The path can grow or be replaced after the first metadata check. Read
    // from one opened handle and stop after the first byte beyond the selected
    // envelope, so growth beyond the envelope causes a typed refusal rather
    // than an unbounded `fs::read` allocation.
    let file = control
        .run(|| fs::File::open(path))?
        .map_err(|error| io_refusal(operation, path.to_path_buf(), error))?;
    let opened_metadata = control
        .run(|| file.metadata())?
        .map_err(|error| io_refusal(operation, path.to_path_buf(), error))?;
    if !opened_metadata.is_file() {
        return Err(LooseGitImportRefusal::PathKind {
            expected,
            path: Box::new(path.to_path_buf()),
        });
    }
    if opened_metadata.len() > limit {
        return Err(class.limit_refusal(path, limit, opened_metadata.len()));
    }
    Ok((file, opened_metadata.len()))
}

#[cfg(test)]
pub(super) fn read_through_first_excess_byte(
    reader: impl Read,
    limit: u64,
) -> Result<Vec<u8>, io::Error> {
    let mut live = || true;
    let control = ImportControl::new(&mut live);
    control::read_bytes(reader, limit, &control).map_err(|error| match error {
        ReadFailure::Io(error) => error,
        ReadFailure::Interrupted(error) => io::Error::other(error.to_string()),
    })
}

pub(super) fn pack_refusal(path: PathBuf, source: PackError) -> LooseGitImportRefusal {
    LooseGitImportRefusal::PackedObject {
        path: Box::new(path),
        source: Box::new(source),
    }
}

pub(super) fn direct_ref_input_limit(object_format: GitHashAlgorithm) -> u64 {
    u64::try_from(
        object_format
            .digest_len()
            .saturating_mul(2)
            .saturating_add(1),
    )
    .unwrap_or(u64::MAX)
}

pub(super) fn head_input_limit() -> u64 {
    u64::try_from(
        b"ref: "
            .len()
            .saturating_add(MAX_REF_NAME_LEN)
            .saturating_add(1),
    )
    .unwrap_or(u64::MAX)
}

pub(super) fn packed_refs_input_limit(object_format: GitHashAlgorithm, max_refs: usize) -> u64 {
    let oid_hex_bytes = object_format.digest_len().saturating_mul(2);
    let direct_line_bytes = oid_hex_bytes
        .saturating_add(1)
        .saturating_add(MAX_REF_NAME_LEN)
        // `str::lines` admits both LF and CRLF, so the input envelope must
        // retain the larger line ending even though Git normally writes LF.
        .saturating_add(2);
    let peeled_line_bytes = oid_hex_bytes.saturating_add(3);
    let per_ref_bytes = direct_line_bytes.saturating_add(peeled_line_bytes);
    let total = max_refs
        .saturating_mul(per_ref_bytes)
        .saturating_add(MAX_IMPORT_PACKED_REFS_HEADER_BYTES);
    u64::try_from(total).unwrap_or(u64::MAX)
}

pub(super) fn read_direct_refs(
    git_directory: &Path,
    object_format: GitHashAlgorithm,
    max_refs: usize,
    control: &ImportControl<'_>,
) -> Result<BTreeMap<RefName, GitOid>, LooseGitImportRefusal> {
    control.checkpoint()?;
    let mut refs = read_packed_refs(git_directory, object_format, max_refs, control)?;
    let loose_root = git_directory.join("refs");
    let Some(metadata) = path_metadata(&loose_root, "inspect loose refs directory", control)?
    else {
        return Ok(refs);
    };
    if metadata.file_type().is_symlink() {
        return Err(LooseGitImportRefusal::SymbolicLink(Box::new(loose_root)));
    }
    if !metadata.is_dir() {
        return Err(LooseGitImportRefusal::PathKind {
            expected: "loose refs directory",
            path: Box::new(loose_root),
        });
    }
    collect_loose_refs(
        &loose_root,
        &loose_root,
        object_format,
        0,
        max_refs,
        &mut refs,
        control,
    )?;
    if refs.len() > max_refs {
        return Err(LooseGitImportRefusal::RefLimitExceeded {
            observed: refs.len(),
            limit: max_refs,
        });
    }
    Ok(refs)
}

pub(super) fn read_head_target(
    git_directory: &Path,
    control: &ImportControl<'_>,
) -> Result<RefName, LooseGitImportRefusal> {
    control.checkpoint()?;
    let head = git_directory.join("HEAD");
    let metadata = match control.run(|| fs::symlink_metadata(&head))? {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(LooseGitImportRefusal::HeadMissing(Box::new(head)));
        }
        Err(error) => return Err(io_refusal("inspect HEAD", head, error)),
    };
    if metadata.file_type().is_symlink() {
        return Err(LooseGitImportRefusal::SymbolicLink(Box::new(head)));
    }
    if !metadata.is_file() {
        return Err(LooseGitImportRefusal::PathKind {
            expected: "HEAD file",
            path: Box::new(head),
        });
    }

    let bytes = read_regular_bounded(
        &head,
        "read HEAD",
        "HEAD file",
        head_input_limit(),
        BoundedInputClass::RefControl,
        control,
    )?;
    let Some(rest) = bytes.strip_prefix(b"ref: ") else {
        return Err(LooseGitImportRefusal::HeadNotSymbolic(Box::new(head)));
    };
    let Some(target) = rest.strip_suffix(b"\n") else {
        return Err(LooseGitImportRefusal::HeadContents(Box::new(head)));
    };
    if target.is_empty() || target.contains(&b'\n') || target.contains(&b'\r') {
        return Err(LooseGitImportRefusal::HeadContents(Box::new(head)));
    }
    let target = RefName::try_new(target).map_err(|source| LooseGitImportRefusal::RefName {
        path: Box::new(head.clone()),
        source: Box::new(source),
    })?;
    if !target.as_bytes().starts_with(b"refs/heads/") {
        return Err(LooseGitImportRefusal::HeadTargetNotBranch(Box::new(head)));
    }
    Ok(target)
}

pub(super) fn read_packed_refs(
    git_directory: &Path,
    object_format: GitHashAlgorithm,
    max_refs: usize,
    control: &ImportControl<'_>,
) -> Result<BTreeMap<RefName, GitOid>, LooseGitImportRefusal> {
    control.checkpoint()?;
    let packed = git_directory.join("packed-refs");
    let Some(metadata) = path_metadata(&packed, "inspect packed refs", control)? else {
        return Ok(BTreeMap::new());
    };
    if metadata.file_type().is_symlink() {
        return Err(LooseGitImportRefusal::SymbolicLink(Box::new(packed)));
    }
    if !metadata.is_file() {
        return Err(LooseGitImportRefusal::PathKind {
            expected: "packed refs file",
            path: Box::new(packed),
        });
    }
    let bytes = read_regular_bounded(
        &packed,
        "read packed refs",
        "packed refs file",
        packed_refs_input_limit(object_format, max_refs),
        BoundedInputClass::RefControl,
        control,
    )?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| LooseGitImportRefusal::PackedRefContents(Box::new(packed.clone())))?;
    let mut refs = BTreeMap::new();
    for line in text.lines() {
        control.checkpoint()?;
        if line.is_empty() || line.starts_with('#') || line.starts_with('^') {
            continue;
        }
        let Some((identity, name)) = line.split_once(' ') else {
            return Err(LooseGitImportRefusal::PackedRefContents(Box::new(
                packed.clone(),
            )));
        };
        if identity.is_empty() || name.is_empty() || name.contains(' ') {
            return Err(LooseGitImportRefusal::PackedRefContents(Box::new(
                packed.clone(),
            )));
        }
        let name =
            RefName::try_new(name.as_bytes()).map_err(|error| LooseGitImportRefusal::RefName {
                path: Box::new(packed.clone()),
                source: Box::new(error),
            })?;
        let identity = GitOid::from_hex(object_format, identity).map_err(|error| {
            LooseGitImportRefusal::ObjectIdentity {
                path: Box::new(packed.clone()),
                source: Box::new(error),
            }
        })?;
        // A repeated name is a contents-law violation (one ref, one
        // identity), not a size problem: it gets the malformed-contents
        // refusal, and only a genuinely over-limit set names the limit.
        if refs.insert(name, identity).is_some() {
            return Err(LooseGitImportRefusal::PackedRefContents(Box::new(
                packed.clone(),
            )));
        }
        if refs.len() > max_refs {
            return Err(LooseGitImportRefusal::RefLimitExceeded {
                observed: refs.len(),
                limit: max_refs,
            });
        }
    }
    Ok(refs)
}

pub(super) fn collect_loose_refs(
    root: &Path,
    directory: &Path,
    object_format: GitHashAlgorithm,
    depth: usize,
    max_refs: usize,
    refs: &mut BTreeMap<RefName, GitOid>,
    control: &ImportControl<'_>,
) -> Result<(), LooseGitImportRefusal> {
    control.checkpoint()?;
    if depth > MAX_IMPORT_REF_DEPTH {
        return Err(LooseGitImportRefusal::RefDepthExceeded {
            limit: MAX_IMPORT_REF_DEPTH,
        });
    }
    for entry in bounded_directory_entries(directory, control)? {
        control.checkpoint()?;
        let path = entry.path();
        let metadata = control
            .run(|| fs::symlink_metadata(&path))?
            .map_err(|error| io_refusal("inspect loose ref", path.clone(), error))?;
        if metadata.file_type().is_symlink() {
            return Err(LooseGitImportRefusal::SymbolicLink(Box::new(path)));
        }
        if metadata.is_dir() {
            collect_loose_refs(
                root,
                &path,
                object_format,
                depth + 1,
                max_refs,
                refs,
                control,
            )?;
            continue;
        }
        if !metadata.is_file() {
            return Err(LooseGitImportRefusal::PathKind {
                expected: "loose ref file",
                path: Box::new(path),
            });
        }
        let name = ref_name_from_path(root, &path)?;
        let bytes = read_regular_bounded(
            &path,
            "read loose ref",
            "loose ref file",
            direct_ref_input_limit(object_format),
            BoundedInputClass::RefControl,
            control,
        )?;
        let identity = parse_direct_ref(&path, &bytes, object_format)?;
        refs.insert(name, identity);
        if refs.len() > max_refs {
            return Err(LooseGitImportRefusal::RefLimitExceeded {
                observed: refs.len(),
                limit: max_refs,
            });
        }
    }
    Ok(())
}

pub(super) fn ref_name_from_path(
    root: &Path,
    path: &Path,
) -> Result<RefName, LooseGitImportRefusal> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| LooseGitImportRefusal::RefContents(Box::new(path.to_path_buf())))?;
    let mut name = String::from("refs");
    for component in relative.components() {
        let Some(part) = component.as_os_str().to_str() else {
            return Err(LooseGitImportRefusal::RefContents(Box::new(
                path.to_path_buf(),
            )));
        };
        name.push('/');
        name.push_str(part);
    }
    RefName::try_new(name.as_bytes()).map_err(|error| LooseGitImportRefusal::RefName {
        path: Box::new(path.to_path_buf()),
        source: Box::new(error),
    })
}

pub(super) fn parse_direct_ref(
    path: &Path,
    bytes: &[u8],
    object_format: GitHashAlgorithm,
) -> Result<GitOid, LooseGitImportRefusal> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| LooseGitImportRefusal::RefContents(Box::new(path.to_path_buf())))?;
    if text.starts_with("ref: ") {
        return Err(LooseGitImportRefusal::SymbolicRefUnsupported(Box::new(
            path.to_path_buf(),
        )));
    }
    let Some(identity) = text.strip_suffix('\n') else {
        return Err(LooseGitImportRefusal::RefContents(Box::new(
            path.to_path_buf(),
        )));
    };
    if identity.is_empty() || identity.contains(['\n', '\r', ' ', '\t']) {
        return Err(LooseGitImportRefusal::RefContents(Box::new(
            path.to_path_buf(),
        )));
    }
    GitOid::from_hex(object_format, identity).map_err(|error| {
        LooseGitImportRefusal::ObjectIdentity {
            path: Box::new(path.to_path_buf()),
            source: Box::new(error),
        }
    })
}

pub(super) fn read_local_object(
    git_directory: &Path,
    identity: GitOid,
    object_format: GitHashAlgorithm,
    max_object_bytes: u64,
    packed: &mut PackedObjectSources,
    control: &ImportControl<'_>,
) -> Result<super::graph::SourceObject, LooseGitImportRefusal> {
    control.checkpoint()?;
    if let Some(object) = try_read_loose_object(
        git_directory,
        identity,
        object_format,
        max_object_bytes,
        control,
    )? {
        return Ok(super::graph::SourceObject::Unverified(object));
    }
    packed
        .read(identity, control)?
        .map(super::graph::SourceObject::Identified)
        .ok_or(LooseGitImportRefusal::ObjectMissing(identity))
}

pub(super) fn try_read_loose_object(
    git_directory: &Path,
    identity: GitOid,
    object_format: GitHashAlgorithm,
    max_object_bytes: u64,
    control: &ImportControl<'_>,
) -> Result<Option<fgit_git_object::LooseObject>, LooseGitImportRefusal> {
    control.checkpoint()?;
    let identity_text = identity.to_string();
    let (directory, file) = identity_text.split_at(2);
    let path = git_directory.join("objects").join(directory).join(file);
    let metadata = match control.run(|| fs::symlink_metadata(&path))? {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_refusal("inspect loose object", path, error)),
    };
    if metadata.file_type().is_symlink() {
        return Err(LooseGitImportRefusal::SymbolicLink(Box::new(path)));
    }
    if !metadata.is_file() {
        return Err(LooseGitImportRefusal::PathKind {
            expected: "loose object file",
            path: Box::new(path),
        });
    }
    let compressed = read_regular_bounded(
        &path,
        "read loose object",
        "loose object file",
        MAX_IMPORT_COMPRESSED_OBJECT_BYTES,
        BoundedInputClass::CompressedLooseObject,
        control,
    )?;
    let maximum = usize::try_from(max_object_bytes).unwrap_or(usize::MAX);
    let inflate_limits = InflateLimits {
        max_input_bytes: MAX_IMPORT_COMPRESSED_OBJECT_BYTES_USIZE,
        max_pending_input_bytes: MAX_IMPORT_COMPRESSED_OBJECT_BYTES_USIZE,
        max_output_bytes: maximum,
        ..InflateLimits::GIT_OBJECT
    };
    control::decode_loose(
        &compressed,
        inflate_limits,
        parse_limits(object_format, max_object_bytes),
        control,
    )
    .map(Some)
}

pub(super) fn parse_limits(object_format: GitHashAlgorithm, max_object_bytes: u64) -> ParseLimits {
    ParseLimits {
        max_object_bytes: usize::try_from(max_object_bytes).unwrap_or(usize::MAX),
        tree_reference_bytes: match object_format {
            GitHashAlgorithm::Sha1 => 20,
            GitHashAlgorithm::Sha256 => 32,
        },
        ..ParseLimits::default()
    }
}

pub(super) fn require_directory(
    path: &Path,
    expected: &'static str,
    control: &ImportControl<'_>,
) -> Result<(), LooseGitImportRefusal> {
    control.checkpoint()?;
    let metadata = control
        .run(|| fs::symlink_metadata(path))?
        .map_err(|error| io_refusal("inspect Git source", path.to_path_buf(), error))?;
    if metadata.file_type().is_symlink() {
        return Err(LooseGitImportRefusal::SymbolicLink(Box::new(
            path.to_path_buf(),
        )));
    }
    if metadata.is_dir() {
        Ok(())
    } else {
        Err(LooseGitImportRefusal::PathKind {
            expected,
            path: Box::new(path.to_path_buf()),
        })
    }
}

pub(super) fn path_exists(
    path: &Path,
    control: &ImportControl<'_>,
) -> Result<bool, LooseGitImportRefusal> {
    control.checkpoint()?;
    match control.run(|| fs::symlink_metadata(path))? {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_refusal("inspect import path", path.to_path_buf(), error)),
    }
}

pub(super) fn path_metadata(
    path: &Path,
    operation: &'static str,
    control: &ImportControl<'_>,
) -> Result<Option<fs::Metadata>, LooseGitImportRefusal> {
    control.checkpoint()?;
    match control.run(|| fs::symlink_metadata(path))? {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_refusal(operation, path.to_path_buf(), error)),
    }
}

pub(super) fn bounded_directory_entries(
    path: &Path,
    control: &ImportControl<'_>,
) -> Result<Vec<fs::DirEntry>, LooseGitImportRefusal> {
    control.checkpoint()?;
    let entries = control
        .run(|| fs::read_dir(path))?
        .map_err(|error| io_refusal("list import directory", path.to_path_buf(), error))?;
    let mut collected = Vec::new();
    for entry in entries {
        control.checkpoint()?;
        if collected.len() == MAX_IMPORT_DIRECTORY_ENTRIES {
            return Err(LooseGitImportRefusal::DirectoryEntryLimitExceeded {
                limit: MAX_IMPORT_DIRECTORY_ENTRIES,
            });
        }
        collected.push(entry.map_err(|error| {
            io_refusal("read import directory entry", path.to_path_buf(), error)
        })?);
    }
    control.run(|| collected.sort_by_key(fs::DirEntry::path))?;
    Ok(collected)
}

pub(super) fn io_refusal(
    operation: &'static str,
    path: PathBuf,
    source: io::Error,
) -> LooseGitImportRefusal {
    LooseGitImportRefusal::Io {
        operation,
        path: Box::new(path),
        source: Box::new(source),
    }
}
