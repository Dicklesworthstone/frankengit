//! Witness and private reconstruction roots remain independent through pinned
//! directory identities without opening losing payloads. Missing acquisition
//! suffixes stay ordinary names;
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

pub(in super::super) struct Separation {
    locations: Vec<Location>,
    parents: BTreeMap<PathBuf, Parent>,
}

impl Separation {
    pub(super) fn capture(
        options: &Options,
        witness: Option<&Path>,
        deadline: Deadline,
    ) -> Result<Self, String> {
        Self::capture_inner(options, witness, None, deadline)
    }

    /// A replica publication directory must stay independent of every source,
    /// trust control, verification root and retained witness, without opening
    /// losing archive payloads or treating a directory listing as authority.
    pub(in super::super) fn capture_for_output(
        options: &Options,
        witness: Option<&Path>,
        output: &Path,
        deadline: Deadline,
    ) -> Result<Self, String> {
        Self::capture_inner(options, witness, Some(output), deadline)
    }

    fn capture_inner(
        options: &Options,
        witness: Option<&Path>,
        output: Option<&Path>,
        deadline: Deadline,
    ) -> Result<Self, String> {
        let mut paths = Vec::with_capacity(6 + options.candidates.len() * 2);
        paths.push(options.destination.as_path());
        paths.push(options.trust.trust_key_path());
        paths.extend(
            options
                .candidates
                .iter()
                .flat_map(|candidate| [candidate.input.as_path(), candidate.approval.as_path()]),
        );
        let witness_index = options.witness.as_deref().map(|path| {
            let index = paths.len();
            paths.push(path);
            index
        });
        if witness_index.is_some() != witness.is_some() {
            return Err("selected recovery captured witness path is absent".into());
        }
        let reconstruction_index = options.reconstruction.as_ref().map(|reconstruction| {
            paths.push(reconstruction.catalog.as_path());
            let index = paths.len();
            paths.push(reconstruction.root.as_path());
            index
        });
        let output_index = output.map(|path| {
            let index = paths.len();
            paths.push(path);
            index
        });
        let mut locations = Vec::with_capacity(paths.len());
        let mut parents = BTreeMap::new();
        for path in paths {
            let (physical, parent) = physical_location(path, deadline)?;
            if !parents.contains_key(&parent) {
                parents.insert(parent.clone(), Parent::open(&parent)?);
            }
            locations.push(Location {
                requested: path.to_path_buf(),
                physical,
            });
        }
        if let (Some(index), Some(witness)) = (witness_index, witness) {
            if locations[index].physical != witness {
                return Err("selected recovery witness parent alias changed".into());
            }
            if locations.iter().enumerate().any(|(other, location)| {
                other != index
                    && (location.physical.starts_with(witness)
                        || witness.starts_with(&location.physical))
            }) {
                return Err("selected recovery witness must be physically separate from every input, control and destination".into());
            }
        }
        for (index, label) in reconstruction_index
            .map(|index| (index, "reconstruction root"))
            .into_iter()
            .chain(output_index.map(|index| (index, "replica directory")))
        {
            let root = &locations[index].physical;
            if locations.iter().enumerate().any(|(other, location)| {
                other != index
                    && (location.physical.starts_with(root) || root.starts_with(&location.physical))
            }) {
                return Err(format!(
                    "selected {label} must be physically separate from every input, control, witness and native destination"
                ));
            }
            let destination = &locations[0].physical;
            if locations.iter().skip(1).any(|location| {
                location.physical.starts_with(destination)
                    || destination.starts_with(&location.physical)
            }) {
                return Err("selected native destination must be physically separate from every input and control".into());
            }
        }
        let separation = Self { locations, parents };
        separation.check(deadline)?;
        Ok(separation)
    }

    pub(in super::super) fn check(&self, deadline: Deadline) -> Result<(), String> {
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
