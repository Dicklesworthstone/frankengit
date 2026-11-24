//! Opaque uninitialized submodules in the existing descriptor-owned workspace.
//! A gitlink target is source metadata, never an object-read capability. Only
//! its empty host directory is inspected; no child is opened or followed.

use super::{
    BTreeMap, File, FileType, HostEpoch, HostRefusal, OFlags, TreePath, checkpoint, fs, io_error,
    open,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug)]
struct RetainedDirectory {
    identity: DirectoryIdentity,
    // Pin the inode throughout the lease so unlink/recreate cannot recycle it
    // and counterfeit the original identity. These descriptors are funded by
    // the host plan and released before cleanup settles that reservation.
    _handle: File,
}

/// Identities belong to this lease, not to repository authority. Reopen checks
/// the source-bound marker and captures new handles only after the same empty
/// representation verifies. No inode identity is treated as a Git object ID.
#[derive(Debug, Default)]
pub(super) struct GitlinkDirectories(BTreeMap<TreePath, RetainedDirectory>);

impl GitlinkDirectories {
    pub(super) fn capture(
        root: &File,
        paths: &BTreeMap<Vec<u8>, TreePath>,
        cancelled: &dyn Fn(HostEpoch) -> bool,
    ) -> Result<Self, HostRefusal> {
        let mut identities = BTreeMap::new();
        for (index, path) in paths.values().enumerate() {
            let live = || checkpoint(cancelled, HostEpoch::ValidatingGitlink(index));
            let (identity, handle) = inspect_empty(root, path, &live)?;
            identities.insert(
                path.clone(),
                RetainedDirectory {
                    identity,
                    _handle: handle,
                },
            );
        }
        Ok(Self(identities))
    }

    pub(super) fn verify(
        &self,
        root: &File,
        cancelled: &dyn Fn(HostEpoch) -> bool,
    ) -> Result<(), HostRefusal> {
        for (index, (path, expected)) in self.0.iter().enumerate() {
            let live = || checkpoint(cancelled, HostEpoch::ValidatingGitlink(index));
            if inspect_empty(root, path, &live)?.0 != expected.identity {
                return Err(HostRefusal::UndeclaredChange(path.clone()));
            }
        }
        Ok(())
    }
}

/// Outputs must neither replace a gitlink/ancestor nor create a descendant.
/// Ordered lookup and bounded parent traversal avoid a full gitlink scan for
/// every output in a large sparse manifest.
pub(super) fn refuse_overlap(
    gitlinks: &BTreeMap<Vec<u8>, TreePath>,
    path: &TreePath,
) -> Result<(), HostRefusal> {
    // The separator belongs in the lower bound: a sibling such as `a-thing`
    // sorts before `a/child` and must not hide a descendant of output `a`.
    let mut descendants = path.as_bytes().to_vec();
    descendants.push(b'/');
    if gitlinks.contains_key(path.as_bytes())
        || gitlinks
            .range(descendants..)
            .next()
            .is_some_and(|(_, gitlink)| gitlink.starts_with(path))
    {
        return Err(HostRefusal::UnsupportedEntry(path.clone()));
    }
    let mut parent = path.parent();
    while let Some(ancestor) = parent {
        if gitlinks.contains_key(ancestor.as_bytes()) {
            return Err(HostRefusal::UnsupportedEntry(path.clone()));
        }
        parent = ancestor.parent();
    }
    Ok(())
}

fn inspect_empty(
    root: &File,
    path: &TreePath,
    live: &dyn Fn() -> Result<(), HostRefusal>,
) -> Result<(DirectoryIdentity, File), HostRefusal> {
    live()?;
    let directory = open(root, path.as_bytes(), OFlags::RDONLY | OFlags::DIRECTORY).map_err(
        |error| match error {
            HostRefusal::Io {
                kind: std::io::ErrorKind::NotFound,
                ..
            } => HostRefusal::UndeclaredChange(path.clone()),
            other => other,
        },
    )?;
    let before = fs::fstat(&directory).map_err(|error| io_error("inspect gitlink", error))?;
    if FileType::from_raw_mode(before.st_mode) != FileType::Directory
        || before.st_mode & 0o7777 != 0o700
    {
        return Err(HostRefusal::UnsupportedEntry(path.clone()));
    }
    let entries = fs::Dir::read_from(&directory)
        .map_err(|error| io_error("inspect uninitialized gitlink", error))?;
    for entry in entries {
        live()?;
        let entry = entry.map_err(|error| io_error("read uninitialized gitlink", error))?;
        if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
            return Err(HostRefusal::UndeclaredChange(path.clone()));
        }
    }
    live()?;
    let after = fs::fstat(&directory).map_err(|error| io_error("recheck gitlink", error))?;
    let named = open(root, path.as_bytes(), OFlags::RDONLY | OFlags::DIRECTORY)?;
    let named = fs::fstat(&named).map_err(|error| io_error("recheck gitlink path", error))?;
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
    Ok((
        DirectoryIdentity {
            device: after.st_dev,
            inode: after.st_ino,
        },
        directory,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lexically_prior_sibling_cannot_hide_an_opaque_descendant() {
        let path = |value: &[u8]| TreePath::parse_default(value).unwrap();
        let links = [b"a-foreign".as_slice(), b"a/module"]
            .into_iter()
            .map(|bytes| (bytes.to_vec(), path(bytes)))
            .collect();
        for output in [b"a".as_slice(), b"a/module", b"a/module/child"] {
            assert!(matches!(refuse_overlap(&links, &path(output)),
                Err(HostRefusal::UnsupportedEntry(rejected)) if rejected == path(output)));
        }
        for output in [b"a-neighbor".as_slice(), b"a/modules", b"b"] {
            assert_eq!(refuse_overlap(&links, &path(output)), Ok(()));
        }
    }
}
