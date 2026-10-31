//! Witness independence is checked through directory identities, without
//! opening losing payloads. Missing acquisition suffixes stay ordinary names;
//! unknown I/O and dangling parent symlinks never become an empty location.

use std::collections::BTreeMap;
use std::fs::{self, File, Metadata};
use std::io::ErrorKind;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use super::super::profile::Deadline;
use super::Options;

struct Parent {
    file: File,
    identity: Metadata,
}

impl Parent {
    fn open(path: &Path) -> Result<Self, String> {
        #[cfg(unix)]
        {
            let file = rustix::fs::open(
                path,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::NONBLOCK,
                rustix::fs::Mode::empty(),
            )
            .map(File::from)
            .map_err(|error| format!("selected recovery parent open: {error}"))?;
            let identity = file.metadata().map_err(|error| error.to_string())?;
            let parent = Self { file, identity };
            parent.check(path)?;
            Ok(parent)
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err("witnessed selection requires Unix pinned directory identities".into())
        }
    }

    fn check(&self, path: &Path) -> Result<(), String> {
        let opened = self.file.metadata().map_err(|error| error.to_string())?;
        let named = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
        if !same_directory(&self.identity, &opened) || !same_directory(&opened, &named) {
            return Err("selected recovery protected parent identity changed".into());
        }
        Ok(())
    }
}

fn same_directory(left: &Metadata, right: &Metadata) -> bool {
    #[cfg(unix)]
    {
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

pub(super) struct Separation {
    locations: Vec<Location>,
    parents: BTreeMap<PathBuf, Parent>,
}

impl Separation {
    pub(super) fn capture(
        options: &Options,
        witness: &Path,
        deadline: Deadline,
    ) -> Result<Self, String> {
        let requested_witness = options
            .witness
            .as_deref()
            .ok_or("selected recovery witness path is absent")?;
        let paths =
            std::iter::once(requested_witness)
                .chain(std::iter::once(options.destination.as_path()))
                .chain(std::iter::once(options.trust.trust_key_path()))
                .chain(options.candidates.iter().flat_map(|candidate| {
                    [candidate.input.as_path(), candidate.approval.as_path()]
                }));
        let mut locations = Vec::with_capacity(3 + options.candidates.len() * 2);
        let mut parents = BTreeMap::new();
        for (index, path) in paths.enumerate() {
            let (physical, parent) = physical_location(path, deadline)?;
            if index == 0 {
                if physical != witness {
                    return Err("selected recovery witness parent alias changed".into());
                }
            } else if physical.starts_with(witness) || witness.starts_with(&physical) {
                return Err("selected recovery witness must be physically separate from every input, control and destination".into());
            }
            if !parents.contains_key(&parent) {
                parents.insert(parent.clone(), Parent::open(&parent)?);
            }
            locations.push(Location {
                requested: path.to_path_buf(),
                physical,
            });
        }
        let separation = Self { locations, parents };
        separation.check(deadline)?;
        Ok(separation)
    }

    pub(super) fn check(&self, deadline: Deadline) -> Result<(), String> {
        for (path, parent) in &self.parents {
            deadline.check()?;
            parent.check(path)?;
        }
        for location in &self.locations {
            let (current, _) = physical_location(&location.requested, deadline)?;
            if current != location.physical {
                return Err("selected recovery protected parent alias changed".into());
            }
        }
        deadline.check()
    }
}

/// Resolve parents only, preserving the final input name for its existing
/// no-symlink intake. The original bounded path limits the ancestor walk. A
/// missing lower artifact or acquisition directory does not make it selected.
fn physical_location(path: &Path, deadline: Deadline) -> Result<(PathBuf, PathBuf), String> {
    let name = path
        .file_name()
        .ok_or("selected recovery requires named protected paths")?;
    let mut parent = path
        .parent()
        .ok_or("selected recovery protected path has no parent")?
        .to_path_buf();
    let mut missing = Vec::new();
    loop {
        deadline.check()?;
        match fs::canonicalize(&parent) {
            Ok(existing) => {
                let mut physical = existing.clone();
                for part in missing.iter().rev() {
                    physical.push(part);
                }
                physical.push(name);
                if physical.to_str().is_none_or(|text| text.len() > 8192) {
                    return Err("selected recovery physical path-byte limit exceeded".into());
                }
                deadline.check()?;
                return Ok((physical, existing));
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                match fs::symlink_metadata(&parent) {
                    Err(missing) if missing.kind() == ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(format!("selected recovery parent metadata: {error}"));
                    }
                    Ok(_) => {
                        return Err(
                            "selected recovery cannot resolve a present parent alias".into()
                        );
                    }
                }
                let part = parent
                    .file_name()
                    .ok_or("selected recovery has no resolvable protected parent")?
                    .to_os_string();
                missing.push(part);
                if !parent.pop() {
                    return Err("selected recovery has no resolvable protected parent".into());
                }
            }
            Err(error) => return Err(format!("selected recovery parent resolution: {error}")),
        }
    }
}
