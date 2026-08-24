//! The staleness gate.
//!
//! Generated artifacts are **committed**, and this is what makes that safe.
//! AGENTS.md §13 says to keep generated artifacts out of source; the exception
//! here is deliberate and is the acceptance's own mechanism — the output is
//! committed precisely so a reviewer reads the real bytes a client will
//! consume, and [`check`] is what stops those bytes drifting from the
//! descriptors. Committed-plus-gated and uncommitted are the two safe states;
//! committed-and-ungated is the one this module exists to prevent.
//!
//! The comparison is byte-for-byte. Nothing here normalises whitespace,
//! reorders keys, or tolerates a trailing newline difference, because every one
//! of those tolerances is a place a real difference could hide.

use std::fs;
use std::path::Path;

use crate::emit::{Artifact, artifacts};
use crate::error::SchemaRefusal;

/// Byte offset of the first difference between two strings.
///
/// `None` when they are equal. When one is a strict prefix of the other the
/// offset is the shorter length, which is where the reader would first notice.
#[must_use]
pub fn first_difference(left: &str, right: &str) -> Option<usize> {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let shared = left.len().min(right.len());
    for index in 0..shared {
        if left[index] != right[index] {
            return Some(index);
        }
    }
    if left.len() == right.len() {
        None
    } else {
        Some(shared)
    }
}

/// Writes every artifact into `directory`, creating it if needed.
///
/// Returns the number of files written.
pub fn write(directory: &Path) -> std::io::Result<usize> {
    fs::create_dir_all(directory)?;
    let generated = artifacts();
    for artifact in &generated {
        fs::write(directory.join(artifact.name), artifact.contents.as_bytes())?;
    }
    Ok(generated.len())
}

/// Refuses if any committed artifact differs from what the descriptors produce.
///
/// Returns the number of artifacts checked. A missing file is
/// [`SchemaRefusal::ArtifactMissing`] rather than a silent regeneration: the
/// gate reports, it never repairs, because a gate that fixes what it finds
/// cannot fail.
pub fn check(directory: &Path) -> Result<usize, SchemaRefusal> {
    let generated = artifacts();
    for artifact in &generated {
        let path = directory.join(artifact.name);
        let committed = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(_) => {
                return Err(SchemaRefusal::ArtifactMissing {
                    artifact: artifact.name.into(),
                });
            }
        };
        if let Some(offset) = first_difference(&committed, &artifact.contents) {
            return Err(SchemaRefusal::ArtifactStale {
                artifact: artifact.name.into(),
                offset,
            });
        }
    }
    Ok(generated.len())
}

/// The artifacts the gate covers, for a caller that wants to list them.
#[must_use]
pub fn covered() -> Vec<&'static str> {
    artifacts()
        .iter()
        .map(|artifact: &Artifact| artifact.name)
        .collect()
}
