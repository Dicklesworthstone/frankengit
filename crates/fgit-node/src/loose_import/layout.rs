//! Bounded Git directory indirection for local source import.
//!
//! A gitfile selects one administrative directory; an optional commondir
//! selects one shared repository. Neither is a recursive search path or an
//! object alternate. Paths in these control files are literal native paths,
//! relative to the containing directory, never environment/config expansion.

use std::path::Component;

use super::source_io::{
    BoundedInputClass, io_refusal, path_metadata, read_direct_refs, read_head_target,
    read_regular_bounded, read_worktree_refs, reject_object_alternates, require_directory,
};
use super::{
    BTreeMap, GitHashAlgorithm, GitOid, ImportControl, LooseGitImportRefusal, Path, PathBuf,
    RefName, fs,
};
use fgit_admission::CanonicalRefState;

const MAX_DIRECTORY_CONTROL_BYTES: u64 = 16 * 1024;
const MAX_DIRECTORY_COMPONENTS: usize = 256;

#[derive(Debug, Eq, PartialEq)]
pub(super) struct SourceLayout {
    source: PathBuf,
    root: PathBuf,
    git_directory: PathBuf,
    common_directory: PathBuf,
    gitfile: Option<Vec<u8>>,
    commondir: Option<Vec<u8>>,
}

impl SourceLayout {
    pub(super) fn resolve(
        source: &Path,
        control: &ImportControl<'_>,
    ) -> Result<Self, LooseGitImportRefusal> {
        require_directory(source, "Git source directory", control)?;
        // Resolve the caller-selected root once. Symlinks introduced by the
        // source's indirection paths are checked component by component below.
        let root = control
            .run(|| fs::canonicalize(source))?
            .map_err(|error| io_refusal("resolve Git source", source.to_path_buf(), error))?;
        let dot_git = root.join(".git");
        let mut gitfile = None;
        let git_directory = match path_metadata(&dot_git, "inspect .git", control)? {
            None => root.clone(),
            Some(metadata) if metadata.file_type().is_symlink() => {
                return Err(LooseGitImportRefusal::SymbolicLink(Box::new(dot_git)));
            }
            Some(metadata) if metadata.is_dir() => dot_git,
            Some(_) => {
                let bytes = read_control(&dot_git, control)?;
                let target = bytes
                    .strip_prefix(b"gitdir: ")
                    .ok_or_else(|| invalid(&dot_git, "expected gitdir: followed by one path"))?;
                let path = control_path(target, &dot_git)?;
                let directory = resolve_directory(&root, &path, control)?;
                if directory == root {
                    return Err(invalid(&dot_git, "gitfile points back to its worktree"));
                }
                gitfile = Some(bytes);
                directory
            }
        };
        let common_file = git_directory.join("commondir");
        let commondir = match path_metadata(&common_file, "inspect commondir", control)? {
            None => None,
            Some(_) => Some(read_control(&common_file, control)?),
        };
        let common_directory = if let Some(bytes) = &commondir {
            let target = control_path(bytes, &common_file)?;
            let directory = resolve_directory(&git_directory, &target, control)?;
            if directory == git_directory {
                return Err(invalid(&common_file, "commondir points to itself"));
            }
            if path_metadata(
                &directory.join("commondir"),
                "inspect common repository",
                control,
            )?
            .is_some()
            {
                return Err(invalid(
                    &common_file,
                    "nested or cyclic commondir is unsupported",
                ));
            }
            directory
        } else {
            git_directory.clone()
        };
        let objects = common_directory.join("objects");
        match path_metadata(&objects, "inspect Git objects directory", control)? {
            Some(metadata) if metadata.file_type().is_symlink() => {
                return Err(LooseGitImportRefusal::SymbolicLink(Box::new(objects)));
            }
            Some(metadata) if metadata.is_dir() => {}
            _ => {
                return Err(LooseGitImportRefusal::GitDirectoryMissing(Box::new(
                    common_directory,
                )));
            }
        }
        Ok(Self {
            source: source.to_path_buf(),
            root,
            git_directory,
            common_directory,
            gitfile,
            commondir,
        })
    }

    pub(super) fn git_directory(&self) -> &Path {
        &self.git_directory
    }

    pub(super) fn common_directory(&self) -> &Path {
        &self.common_directory
    }

    pub(super) fn read_head(
        &self,
        control: &ImportControl<'_>,
    ) -> Result<RefName, LooseGitImportRefusal> {
        read_head_target(self.git_directory(), control)
    }

    pub(super) fn read_refs(
        &self,
        format: GitHashAlgorithm,
        max_refs: usize,
        control: &ImportControl<'_>,
    ) -> Result<BTreeMap<RefName, GitOid>, LooseGitImportRefusal> {
        let shared = self.git_directory != self.common_directory;
        let mut refs =
            read_direct_refs(self.common_directory(), format, max_refs, shared, control)?;
        if shared {
            read_worktree_refs(self.git_directory(), format, max_refs, &mut refs, control)?;
        }
        Ok(refs)
    }

    /// The selected layout must still identify the same source when verified
    /// bytes leave quarantine. This is change detection for trusted local
    /// input, not filesystem snapshot isolation against a malicious host.
    pub(super) fn revalidate(
        &self,
        format: GitHashAlgorithm,
        max_refs: usize,
        refs: &CanonicalRefState,
        control: &ImportControl<'_>,
    ) -> Result<(), LooseGitImportRefusal> {
        if self.gitfile.is_none() && self.commondir.is_none() {
            return control.checkpoint();
        }
        let observed = Self::resolve(&self.source, control)?;
        if observed != *self
            || Some(&observed.read_head(control)?) != refs.head_target()
            || observed.read_refs(format, max_refs, control)? != *refs.refs()
        {
            return Err(LooseGitImportRefusal::SourceLayoutChanged(Box::new(
                self.source.clone(),
            )));
        }
        reject_object_alternates(self.common_directory(), control)
    }
}

fn invalid(path: &Path, reason: &'static str) -> LooseGitImportRefusal {
    LooseGitImportRefusal::DirectoryControlInvalid {
        path: Box::new(path.to_path_buf()),
        reason,
    }
}

fn read_control(
    path: &Path,
    control: &ImportControl<'_>,
) -> Result<Vec<u8>, LooseGitImportRefusal> {
    read_regular_bounded(
        path,
        "read Git directory control",
        "regular Git directory control file",
        MAX_DIRECTORY_CONTROL_BYTES,
        BoundedInputClass::DirectoryControl,
        control,
    )
}

fn control_path(bytes: &[u8], path: &Path) -> Result<PathBuf, LooseGitImportRefusal> {
    // Native Git writes one LF. A single CRLF or missing terminal newline is
    // unambiguous; embedded newlines/NULs are not a second path or whitespace.
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let bytes = bytes.strip_suffix(b"\r").unwrap_or(bytes);
    if bytes.is_empty() || bytes.iter().any(|byte| matches!(byte, 0 | b'\r' | b'\n')) {
        return Err(invalid(path, "expected one nonempty native directory path"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(PathBuf::from(std::ffi::OsStr::from_bytes(bytes)))
    }
    #[cfg(not(unix))]
    {
        std::str::from_utf8(bytes)
            .map(PathBuf::from)
            .map_err(|_| invalid(path, "directory path is not representable on this host"))
    }
}

fn resolve_directory(
    base: &Path,
    target: &Path,
    control: &ImportControl<'_>,
) -> Result<PathBuf, LooseGitImportRefusal> {
    let mut directory = if target.is_absolute() {
        PathBuf::new()
    } else {
        base.to_path_buf()
    };
    for (index, component) in target.components().enumerate() {
        control.checkpoint()?;
        if index >= MAX_DIRECTORY_COMPONENTS {
            return Err(invalid(
                target,
                "directory path exceeds the component limit",
            ));
        }
        match component {
            Component::Prefix(_) if !target.is_absolute() => {
                return Err(invalid(
                    target,
                    "drive-relative directory paths are unsupported",
                ));
            }
            Component::Prefix(_) => {
                directory.push(component);
                continue;
            }
            Component::RootDir => directory.push(component),
            Component::CurDir => continue,
            Component::ParentDir => {
                directory.pop();
            }
            Component::Normal(name) => directory.push(name),
        }
        // Check before reducing a later '..': `symlink/../repo` must not
        // conceal a symlink traversal. No source-selected component is followed.
        require_directory(&directory, "Git administrative directory", control)?;
    }
    require_directory(&directory, "Git administrative directory", control)?;
    Ok(directory)
}
