//! The staleness gate over the generated artifact.
//!
//! The contract is `fgit-schema`'s, which is the reviewed precedent in this
//! workspace: `generate` writes, `check` refuses, and the two share one
//! renderer so they cannot disagree about what "current" means.
//!
//! # `check` never writes
//!
//! A gate that repairs what it finds cannot fail, and a gate that cannot fail is
//! decoration. A missing artifact is [`BridgeRefusal::ArtifactMissing`], not a
//! silent regeneration, and a test asserts the file is still absent afterwards.

use std::fs;
use std::path::{Path, PathBuf};

/// The generated artifact's file name, relative to the directory it lives in.
pub const ARTIFACT: &str = "Vectors.lean";

/// Why the gate refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BridgeRefusal {
    /// The committed artifact is absent.
    ArtifactMissing {
        /// Where it was expected.
        path: PathBuf,
    },
    /// The committed artifact does not match what the current inputs render.
    Stale {
        /// Where it lives.
        path: PathBuf,
        /// Byte offset of the first difference.
        ///
        /// Reported because "stale" sends a reader to a diff tool while "stale
        /// at byte 5326" sends them to the line that changed.
        offset: usize,
    },
    /// The artifact could not be read.
    Unreadable {
        /// Where it lives.
        path: PathBuf,
        /// What the filesystem said.
        message: String,
    },
}

/// The first byte offset at which two renderings differ.
///
/// `None` when they are identical. A shorter prefix of a longer string differs
/// at the shorter one's length, which is the offset a reader wants: it is where
/// the truncation begins.
#[must_use]
pub fn first_difference(left: &str, right: &str) -> Option<usize> {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let shared = left.len().min(right.len());
    for offset in 0..shared {
        if left[offset] != right[offset] {
            return Some(offset);
        }
    }
    if left.len() == right.len() {
        None
    } else {
        Some(shared)
    }
}

/// Writes the artifact, returning how many bytes it holds.
///
/// # Errors
///
/// Whatever the filesystem reports.
pub fn write(directory: &Path, rendered: &str) -> std::io::Result<usize> {
    fs::create_dir_all(directory)?;
    let path = directory.join(ARTIFACT);
    fs::write(&path, rendered)?;
    Ok(rendered.len())
}

/// Refuses when the committed artifact is missing or stale.
///
/// # Errors
///
/// [`BridgeRefusal`] naming which, and for staleness the first differing byte.
pub fn check(directory: &Path, rendered: &str) -> Result<usize, BridgeRefusal> {
    let path = directory.join(ARTIFACT);
    if !path.exists() {
        return Err(BridgeRefusal::ArtifactMissing { path });
    }
    let committed = fs::read_to_string(&path).map_err(|error| BridgeRefusal::Unreadable {
        path: path.clone(),
        message: error.to_string(),
    })?;
    first_difference(&committed, rendered).map_or(Ok(committed.len()), |offset| {
        Err(BridgeRefusal::Stale { path, offset })
    })
}
