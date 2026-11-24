//! Explicit private file copies for selected Git symlink inputs. Resolution
//! examines verified manifest metadata only; no host symlink is ever created
//! or followed, and the original Git link entry remains the export basis.

use super::{
    BTreeMap, BTreeSet, File, FileMode, FileType, GitHashAlgorithm, HostEpoch, HostRefusal, Mode,
    NativeObjectIdentity, OFlags, Read, SparseEntryKind, SparseLimits, TreeCapability, TreePath,
    WorkspaceManifest, checkpoint, fs, host_mode, io_error, open,
};
use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_treefs::SparseEntry;

const BINDING_DOMAIN: &[u8] = b"frankengit/sparse-host/selected-file-link-copies/v1\0";
const CHUNK: usize = 8192;

/// How a trusted sparse host represents selected Git symlink inputs.
/// This changes no TreeFS capability or direct-API traversal rule.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SymlinkInputPolicy {
    /// Preserve the original sparse-host profile: symlinks refuse before I/O.
    #[default]
    Refuse,
    /// Copy an independently selected and authorized ordinary target into a
    /// distinct read-only regular file at the link path. Original Git link
    /// text/OID are retained; host readlink and POSIX alias identity are absent.
    SelectedFileCopies,
}

impl SymlinkInputPolicy {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Refuse => "refuse",
            Self::SelectedFileCopies => "selected-file-link-copies-v1",
        }
    }
}

#[derive(Clone, Debug)]
struct ExpectedFile {
    path: TreePath,
    /// The selected regular source entry supplying bytes and executable mode.
    source_index: usize,
}

/// Both the link copies and their original targets are immutable input-only
/// paths. Their index references share manifest bytes instead of cloning bodies
/// while planning; physical copies still count against the expanded byte limit.
#[derive(Clone, Debug)]
pub(super) struct FileLinksPlan {
    policy: SymlinkInputPolicy,
    copies: BTreeMap<TreePath, usize>,
    protected: BTreeMap<Vec<u8>, ExpectedFile>,
    input_payload_bytes: usize,
    binding: Option<[u8; 32]>,
}

impl FileLinksPlan {
    pub(super) fn build<A: GitHashAlgorithm>(
        manifest: &WorkspaceManifest<A>,
        capability: &TreeCapability,
        now: u64,
        limits: SparseLimits,
        policy: SymlinkInputPolicy,
    ) -> Result<Self, HostRefusal> {
        let mut plan = Self {
            policy,
            copies: BTreeMap::new(),
            protected: BTreeMap::new(),
            input_payload_bytes: 0,
            binding: None,
        };
        let entries = manifest.entries();
        let mut hash = Sha256Hasher::new();
        hash.update(BINDING_DOMAIN);
        for entry in entries {
            match entry.kind() {
                SparseEntryKind::File { body, .. } => {
                    plan.add_payload(body.len(), limits)?;
                }
                SparseEntryKind::Symlink { target } => {
                    if policy != SymlinkInputPolicy::SelectedFileCopies {
                        return Err(HostRefusal::UnsupportedEntry(entry.path().clone()));
                    }
                    capability
                        .check_symlink(entry.path())
                        .map_err(HostRefusal::Capability)?;
                    if target.len() > limits.max_entry_bytes || target.len() > 4096 {
                        return Err(HostRefusal::ResourceLimit);
                    }
                    let source_index = resolve_target(entries, entry.path(), target)?;
                    let source = &entries[source_index];
                    capability
                        .authorize_read(source.path(), now)
                        .map_err(HostRefusal::Capability)?;
                    let (mode, body) = regular_source(manifest, source_index)?;
                    plan.add_payload(body.len(), limits)?;
                    plan.copies.insert(entry.path().clone(), source_index);
                    for path in [entry.path(), source.path()] {
                        plan.protected.insert(
                            path.as_bytes().to_vec(),
                            ExpectedFile {
                                path: path.clone(),
                                source_index,
                            },
                        );
                    }
                    frame(&mut hash, entry.path().as_bytes());
                    frame(&mut hash, entry.source_oid().digest_bytes());
                    frame(&mut hash, target);
                    frame(&mut hash, source.path().as_bytes());
                    frame(&mut hash, source.source_oid().digest_bytes());
                    hash.update(&[u8::from(mode == FileMode::Executable)]);
                }
                SparseEntryKind::Directory | SparseEntryKind::Gitlink => {}
            }
        }
        if policy == SymlinkInputPolicy::SelectedFileCopies {
            // Even an empty alias inventory names the explicitly selected
            // profile. Default plans and cache scopes append no new bytes.
            hash.update(&(plan.copies.len() as u64).to_be_bytes());
            plan.binding = Some(hash.finish());
        }
        Ok(plan)
    }

    fn add_payload(&mut self, amount: usize, limits: SparseLimits) -> Result<(), HostRefusal> {
        if amount > limits.max_entry_bytes {
            return Err(HostRefusal::ResourceLimit);
        }
        self.input_payload_bytes = self
            .input_payload_bytes
            .checked_add(amount)
            .filter(|bytes| *bytes <= limits.max_payload_bytes)
            .ok_or(HostRefusal::ResourceLimit)?;
        Ok(())
    }

    pub(super) const fn policy(&self) -> SymlinkInputPolicy {
        self.policy
    }
    pub(super) const fn binding(&self) -> Option<&[u8; 32]> {
        self.binding.as_ref()
    }
    pub(super) const fn input_payload_bytes(&self) -> usize {
        self.input_payload_bytes
    }
    pub(super) fn descriptor_count(&self) -> usize {
        self.protected.len()
    }
    pub(super) fn is_empty(&self) -> bool {
        self.protected.is_empty()
    }

    pub(super) fn authorize(
        &self,
        capability: &TreeCapability,
        now: u64,
    ) -> Result<(), HostRefusal> {
        for path in self.copies.keys() {
            capability
                .check_symlink(path)
                .map_err(HostRefusal::Capability)?;
        }
        for file in self.protected.values() {
            capability
                .authorize_read(&file.path, now)
                .map_err(HostRefusal::Capability)?;
        }
        Ok(())
    }

    pub(super) fn mode(&self, path: &TreePath, mode: FileMode) -> Mode {
        if self.protected.contains_key(path.as_bytes()) {
            readonly_mode(mode)
        } else {
            host_mode(mode)
        }
    }

    pub(super) fn copied_input<'a, A: GitHashAlgorithm>(
        &self,
        manifest: &'a WorkspaceManifest<A>,
        path: &TreePath,
    ) -> Result<(&'a [u8], Mode), HostRefusal> {
        let index = self.copies.get(path).ok_or(HostRefusal::IdentityMismatch)?;
        let (mode, body) = regular_source(manifest, *index)?;
        Ok((body, readonly_mode(mode)))
    }

    pub(super) fn refuse_overlap(&self, path: &TreePath) -> Result<(), HostRefusal> {
        let mut descendants = path.as_bytes().to_vec();
        descendants.push(b'/');
        if self.protected.contains_key(path.as_bytes())
            || self
                .protected
                .range(descendants.clone()..)
                .next()
                .is_some_and(|(name, _)| name.starts_with(&descendants))
        {
            return Err(HostRefusal::UnsupportedEntry(path.clone()));
        }
        let mut parent = path.parent();
        while let Some(ancestor) = parent {
            if self.protected.contains_key(ancestor.as_bytes()) {
                return Err(HostRefusal::UnsupportedEntry(path.clone()));
            }
            parent = ancestor.parent();
        }
        Ok(())
    }
}

fn regular_source<A: GitHashAlgorithm>(
    manifest: &WorkspaceManifest<A>,
    index: usize,
) -> Result<(FileMode, &[u8]), HostRefusal> {
    match manifest.entries().get(index).map(SparseEntry::kind) {
        Some(SparseEntryKind::File { mode, body }) => Ok((*mode, body)),
        _ => Err(HostRefusal::IdentityMismatch),
    }
}

fn frame(hash: &mut Sha256Hasher, body: &[u8]) {
    hash.update(&(body.len() as u64).to_be_bytes());
    hash.update(body);
}

fn readonly_mode(mode: FileMode) -> Mode {
    match mode {
        FileMode::Regular => Mode::RUSR,
        FileMode::Executable => Mode::RUSR | Mode::XUSR,
    }
}

/// Interpret relative link text against selected, verified metadata. Every
/// traversed non-dot component must itself be a selected directory: lexical
/// collapse must not hide a symlink, regular file, gitlink or missing component.
fn resolve_target<A: GitHashAlgorithm>(
    entries: &[SparseEntry<A>],
    link: &TreePath,
    text: &[u8],
) -> Result<usize, HostRefusal> {
    let invalid = || HostRefusal::UnsupportedEntry(link.clone());
    if text.is_empty() || text.starts_with(b"/") || text.contains(&0) {
        return Err(invalid());
    }
    let mut directory = link.parent();
    let mut components = text.split(|byte| *byte == b'/').peekable();
    while let Some(component) = components.next() {
        if component.is_empty() || component == b"." {
            continue;
        }
        if component == b".." {
            directory = directory.ok_or_else(invalid)?.parent();
            continue;
        }
        let path = match &directory {
            Some(parent) => {
                let mut bytes = parent.as_bytes().to_vec();
                bytes.push(b'/');
                bytes.extend_from_slice(component);
                TreePath::parse_default(&bytes).map_err(|_| invalid())?
            }
            None => TreePath::parse_default(component).map_err(|_| invalid())?,
        };
        let index = entries
            .binary_search_by(|entry| entry.path().cmp(&path))
            .map_err(|_| invalid())?;
        if components.peek().is_none() {
            return if matches!(entries[index].kind(), SparseEntryKind::File { .. }) {
                Ok(index)
            } else {
                Err(invalid())
            };
        }
        if !matches!(entries[index].kind(), SparseEntryKind::Directory) {
            return Err(invalid());
        }
        directory = Some(path);
    }
    Err(invalid())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug)]
struct PinnedFile {
    identity: FileIdentity,
    // Retaining the original inode makes replacement checks immune to reuse.
    _handle: File,
}

#[derive(Debug, Default)]
pub(super) struct FileLinkCopies(BTreeMap<TreePath, PinnedFile>);

impl FileLinkCopies {
    pub(super) fn capture<A: GitHashAlgorithm>(
        root: &File,
        plan: &FileLinksPlan,
        manifest: &WorkspaceManifest<A>,
        cancelled: &dyn Fn(HostEpoch) -> bool,
    ) -> Result<Self, HostRefusal> {
        let mut files = BTreeMap::new();
        let mut aliases = BTreeSet::new();
        for (ordinal, expected) in plan.protected.values().enumerate() {
            let (mode, body) = regular_source(manifest, expected.source_index)?;
            let (identity, handle) = inspect(root, &expected.path, mode, body, &|| {
                checkpoint(cancelled, HostEpoch::ValidatingLinkCopy(ordinal))
            })?;
            if !aliases.insert((identity.device, identity.inode)) {
                return Err(HostRefusal::AliasedEntry(expected.path.clone()));
            }
            files.insert(
                expected.path.clone(),
                PinnedFile {
                    identity,
                    _handle: handle,
                },
            );
        }
        Ok(Self(files))
    }

    pub(super) fn verify<A: GitHashAlgorithm>(
        &self,
        root: &File,
        plan: &FileLinksPlan,
        manifest: &WorkspaceManifest<A>,
        cancelled: &dyn Fn(HostEpoch) -> bool,
    ) -> Result<(), HostRefusal> {
        if self.0.len() != plan.protected.len() {
            return Err(HostRefusal::IdentityMismatch);
        }
        for (ordinal, expected) in plan.protected.values().enumerate() {
            let pinned = self
                .0
                .get(&expected.path)
                .ok_or(HostRefusal::IdentityMismatch)?;
            let (mode, body) = regular_source(manifest, expected.source_index)?;
            let (identity, _) = inspect(root, &expected.path, mode, body, &|| {
                checkpoint(cancelled, HostEpoch::ValidatingLinkCopy(ordinal))
            })?;
            if identity != pinned.identity {
                return Err(HostRefusal::UndeclaredChange(expected.path.clone()));
            }
        }
        Ok(())
    }
}

fn inspect(
    root: &File,
    path: &TreePath,
    mode: FileMode,
    body: &[u8],
    live: &dyn Fn() -> Result<(), HostRefusal>,
) -> Result<(FileIdentity, File), HostRefusal> {
    live()?;
    let mut file = open(root, path.as_bytes(), OFlags::RDONLY).map_err(|error| match error {
        HostRefusal::Io {
            kind: std::io::ErrorKind::NotFound,
            ..
        } => HostRefusal::UndeclaredChange(path.clone()),
        other => other,
    })?;
    let before =
        fs::fstat(&file).map_err(|error| io_error("inspect immutable link copy", error))?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_nlink != 1
        || before.st_mode & 0o7777 != readonly_mode(mode).bits()
        || u64::try_from(before.st_size).ok() != Some(body.len() as u64)
    {
        return Err(HostRefusal::UndeclaredChange(path.clone()));
    }
    let mut buffer = [0; CHUNK];
    for expected in body.chunks(CHUNK) {
        live()?;
        file.read_exact(&mut buffer[..expected.len()])
            .map_err(|error| io_error("read immutable link copy", error))?;
        if buffer[..expected.len()] != *expected {
            return Err(HostRefusal::UndeclaredChange(path.clone()));
        }
    }
    live()?;
    if file
        .read(&mut buffer[..1])
        .map_err(|error| io_error("check immutable link copy end", error))?
        != 0
    {
        return Err(HostRefusal::UndeclaredChange(path.clone()));
    }
    let after = fs::fstat(&file).map_err(|error| io_error("recheck immutable link copy", error))?;
    let named = open(root, path.as_bytes(), OFlags::RDONLY)?;
    let named =
        fs::fstat(&named).map_err(|error| io_error("recheck immutable link path", error))?;
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mode,
        before.st_nlink,
        before.st_mtime,
        before.st_mtime_nsec,
        before.st_ctime,
        before.st_ctime_nsec,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mode,
        after.st_nlink,
        after.st_mtime,
        after.st_mtime_nsec,
        after.st_ctime,
        after.st_ctime_nsec,
    ) || (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino)
    {
        return Err(HostRefusal::ChangedDuringRead(path.clone()));
    }
    live()?;
    Ok((
        FileIdentity {
            device: after.st_dev,
            inode: after.st_ino,
        },
        file,
    ))
}
