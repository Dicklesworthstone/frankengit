//! Read-only namespace preflight for donor-assisted export. Parent paths are
//! operator controlled; descriptor identities detect substitution but are not a
//! sandbox against an adversarial process with the same user identity.

use std::fs::{self, File, Metadata};
use std::path::{Path, PathBuf};

struct Directory {
    path: PathBuf,
    file: File,
    original: Metadata,
}

impl Directory {
    fn open(path: PathBuf) -> Result<Self, String> {
        let file = File::open(&path).map_err(|error| error.to_string())?;
        let original = file.metadata().map_err(|error| error.to_string())?;
        let directory = Self {
            path,
            file,
            original,
        };
        directory.check()?;
        Ok(directory)
    }

    fn check(&self) -> Result<(), String> {
        let opened = self.file.metadata().map_err(|error| error.to_string())?;
        let named = fs::symlink_metadata(&self.path).map_err(|error| error.to_string())?;
        if !same_directory(&self.original, &opened) || !same_directory(&opened, &named) {
            return Err("donor export protected directory identity changed".into());
        }
        Ok(())
    }
}

fn same_directory(left: &Metadata, right: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.is_dir()
            && right.is_dir()
            && left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.uid() == right.uid()
            && left.mode() == right.mode()
    }
    #[cfg(not(unix))]
    {
        let _ = (left, right);
        false
    }
}

struct Location {
    requested: PathBuf,
    physical: PathBuf,
}

pub(crate) struct Separation {
    source: Location,
    others: Vec<Location>,
    directories: Vec<Directory>,
}

impl Separation {
    /// Scratch and output are new paths. The donor is an existing regular file.
    /// No source, input, output or scratch root may contain another. The output
    /// and scratch may share an existing parent outside the live source.
    pub(crate) fn capture(
        source: &Path,
        input: &Path,
        output: &Path,
        scratch: &Path,
        mut live: impl FnMut() -> Result<(), String>,
    ) -> Result<Self, String> {
        if !cfg!(unix) {
            return Err("donor export requires Unix pinned directory identities".into());
        }
        live()?;
        if !fs::symlink_metadata(source)
            .map_err(|error| error.to_string())?
            .is_dir()
        {
            return Err("donor export source must be an existing directory, not a symlink".into());
        }
        if !fs::symlink_metadata(input)
            .map_err(|error| error.to_string())?
            .is_file()
        {
            return Err("donor backup must be an existing regular file, not a symlink".into());
        }
        let physical_source = fs::canonicalize(source).map_err(|error| error.to_string())?;
        let source = Location {
            requested: source.to_path_buf(),
            physical: physical_source,
        };
        let mut directories = vec![Directory::open(source.physical.clone())?];
        let mut others: Vec<Location> = Vec::with_capacity(3);
        for path in [input, output, scratch] {
            live()?;
            let physical = location(path)?;
            if overlaps(&source.physical, &physical)
                || others
                    .iter()
                    .any(|other| overlaps(&other.physical, &physical))
            {
                return Err("donor backup, output and scratch must be physically separate from each other and the live source".into());
            }
            let parent = physical.parent().ok_or("donor export path has no parent")?;
            if !directories.iter().any(|directory| directory.path == parent) {
                directories.push(Directory::open(parent.to_path_buf())?);
            }
            others.push(Location {
                requested: path.to_path_buf(),
                physical,
            });
        }
        let separation = Self {
            source,
            others,
            directories,
        };
        separation.check(&mut live)?;
        Ok(separation)
    }

    pub(crate) fn check(&self, mut live: impl FnMut() -> Result<(), String>) -> Result<(), String> {
        for directory in &self.directories {
            live()?;
            directory.check()?;
        }
        live()?;
        if fs::canonicalize(&self.source.requested).map_err(|error| error.to_string())?
            != self.source.physical
        {
            return Err("donor export source alias changed".into());
        }
        for other in &self.others {
            live()?;
            if location(&other.requested)? != other.physical {
                return Err("donor export protected parent alias changed".into());
            }
        }
        live()
    }
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn location(path: &Path) -> Result<PathBuf, String> {
    let name = path
        .file_name()
        .ok_or("donor export requires named paths")?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = fs::canonicalize(parent).map_err(|error| error.to_string())?;
    let physical = parent.join(name);
    if physical.as_os_str().len() > 8192 {
        return Err("donor export physical path-byte limit".into());
    }
    Ok(physical)
}

#[cfg(test)]
#[path = "paths/tests.rs"]
mod tests;
