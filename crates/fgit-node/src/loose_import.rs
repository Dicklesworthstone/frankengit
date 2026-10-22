//! Bounded staging of an ordinary local Git directory.
//!
//! This module owns only the pre-publication half of import: it validates a
//! local Git directory, follows the closure named by its direct refs, resolves
//! those objects from checksum-bound loose or idx/pack storage, and places
//! verified immutable object bodies in the node's fabric.  The returned
//! [`StagedLooseGitImport`] is not a publication capability.  In particular,
//! objects staged here remain non-canonical until the caller has sealed an
//! import request, recorded its admission, and published an RCR through the
//! authority head's conditional replacement.

#[cfg(test)]
mod cancellation_tests;
mod control;
pub mod graph;
mod metadata;
mod packed_sources;
mod placement;
mod refusal;
mod source_io;
pub use refusal::LooseGitImportRefusal;
use source_io::*;
mod profile;
use packed_sources::PackedObjectSources;
mod spool;

pub use control::checkpoint_request;
use control::{ImportControl, ReadFailure};

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io;
#[cfg(test)]
use std::io::Read;
use std::path::{Path, PathBuf};

use fgit_admission::{CanonicalRefState, PermittedObjectClosure};
use fgit_git_object::{
    AcceptanceProfile, InflateLimits, LooseObjectDecodeError, ObjectError, ParseLimits,
};
use fgit_pack::{
    Deadline, IdxV2, NativeChecksumVerifier, PackError, PackLimits, ParsedDeltaBase,
    ResolutionBudget, StreamPackEntry, StreamPackError, apply_delta_to_charged_base_with_budget,
    object_type_from_base_entry, parse_pack_header, read_streamed_pack, validate_idx_pack_count,
    verify_native_object,
};
use fgit_types::{GitHashAlgorithm, GitOid, MAX_REF_NAME_LEN, RefName, TypeRefusal};

use super::{NodeRefusal, NodeRequestContext, OneNode};

const MAX_IMPORT_REFS: usize = 65_536;
const MAX_IMPORT_OBJECTS: usize = 1_000_000;
const MAX_IMPORT_COMPRESSED_OBJECT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_IMPORT_COMPRESSED_OBJECT_BYTES_USIZE: usize = 64 * 1024 * 1024;
const MAX_IMPORT_PACKS: usize = 128;
/// One `.idx` file is read whole; packs are streamed (frankengit-855v).
const MAX_IMPORT_INDEX_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// Floor of the compressed pack input every import may read, whatever its
/// profile: many tiny objects carry more framing than body.
const MIN_IMPORT_PACK_INPUT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_IMPORT_TOTAL_INDEX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_IMPORT_PACKED_REFS_HEADER_BYTES: usize = 1024;
const MAX_IMPORT_REF_DEPTH: usize = 32;
const MAX_IMPORT_DIRECTORY_ENTRIES: usize = 1_000_000;

/// Verified, non-canonical state staged from a local Git directory.
///
/// This type has no public constructor.  Its refs and closure can only be
/// produced after every object reachable from a direct source ref was parsed,
/// re-identified, and placed through the immutable fabric.  It is still only
/// a candidate: publishing it requires the separate sealed import path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedLooseGitImport {
    refs: CanonicalRefState,
    closure: PermittedObjectClosure,
    object_count: usize,
    total_object_bytes: u64,
}

impl StagedLooseGitImport {
    /// Candidate canonical refs copied from the source's direct refs.
    #[must_use]
    pub const fn refs(&self) -> &CanonicalRefState {
        &self.refs
    }

    /// Exact verified native object closure reachable from those refs.
    #[must_use]
    pub const fn closure(&self) -> &PermittedObjectClosure {
        &self.closure
    }

    /// Number of unique reachable objects staged in immutable fabric.
    #[must_use]
    pub const fn object_count(&self) -> usize {
        self.object_count
    }

    /// Sum of the uncompressed bodies staged by this candidate import.
    #[must_use]
    pub const fn total_object_bytes(&self) -> u64 {
        self.total_object_bytes
    }
}

impl OneNode {
    /// Validates and stages an ordinary local Git directory.
    ///
    /// This accepts a bare directory or a worktree directory containing a
    /// `.git` directory. Direct refs may reach loose objects or objects in
    /// checksum-bound idx-v2/pack-v2 pairs. Alternates, symbolic refs, and
    /// `.git` indirection files are explicit typed refusals rather than paths
    /// that can quietly select a different object source.
    ///
    /// Success proves that every returned closure member was native-hash
    /// verified with a complete required-kind graph before the first placement.
    /// Gitlinks remain external and are not fetched. Verified bodies are then
    /// immutably placed through this node's fabric. It does not
    /// make refs visible and does not publish an authority head.
    pub fn stage_loose_git_import(
        &self,
        source: &Path,
    ) -> Result<StagedLooseGitImport, LooseGitImportRefusal> {
        self.stage_loose_git_import_with_ref_limit(source, MAX_IMPORT_REFS)
    }

    /// Standalone compatibility entrypoint with hard resource bounds but no
    /// caller deadline. Request-handling code uses the `_in` variant below.
    pub(crate) fn stage_loose_git_import_with_ref_limit(
        &self,
        source: &Path,
        max_refs: usize,
    ) -> Result<StagedLooseGitImport, LooseGitImportRefusal> {
        self.stage_loose_git_import_with_control(source, max_refs, &mut || true)
    }

    /// Verify and stage under a caller-owned cooperative deadline. Returning an
    /// interruption may leave verified unselected placement, never a ref update.
    /// No OS read already in progress can be preempted by this synchronous API.
    pub fn stage_loose_git_import_with_deadline(
        &self,
        source: &Path,
        deadline: &mut impl Deadline,
    ) -> Result<StagedLooseGitImport, LooseGitImportRefusal> {
        self.stage_loose_git_import_with_control(source, MAX_IMPORT_REFS, deadline)
    }

    pub(crate) fn stage_loose_git_import_with_ref_limit_in(
        &self,
        request: &NodeRequestContext,
        source: &Path,
        max_refs: usize,
    ) -> Result<StagedLooseGitImport, LooseGitImportRefusal> {
        let mut stopped = None;
        let result = self.stage_loose_git_import_with_control(source, max_refs, &mut || {
            match checkpoint_request(request) {
                Ok(()) => true,
                Err(error) => {
                    stopped = Some(error);
                    false
                }
            }
        });
        match stopped {
            Some(error) => Err(error),
            None => result,
        }
    }

    fn stage_loose_git_import_with_control(
        &self,
        source: &Path,
        max_refs: usize,
        deadline: &mut impl Deadline,
    ) -> Result<StagedLooseGitImport, LooseGitImportRefusal> {
        let control = ImportControl::new(deadline);
        let result = self.stage_loose_git_import_controlled(
            source,
            max_refs,
            graph::MAX_REACHABLE_OBJECT_BYTES,
            &control,
        );
        // All effects here are noncanonical placement. Never apply this
        // post-operation cancellation rule to the result of authority CAS.
        control.after(result, |error| error)
    }

    fn stage_loose_git_import_controlled(
        &self,
        source: &Path,
        max_refs: usize,
        maximum_bytes: u64,
        control: &ImportControl<'_>,
    ) -> Result<StagedLooseGitImport, LooseGitImportRefusal> {
        control.checkpoint()?;
        if max_refs > MAX_IMPORT_REFS {
            return Err(LooseGitImportRefusal::RefLimitExceeded {
                limit: MAX_IMPORT_REFS,
            });
        }
        profile::validate_limit(maximum_bytes)?;
        let graph_limits = graph::Limits {
            bytes: maximum_bytes,
            ..graph::Limits::default()
        };
        let git_directory = resolve_git_directory(source, control)?;
        reject_object_alternates(&git_directory, control)?;
        let mut packed = PackedObjectSources::open_with_profile(
            &git_directory,
            self.object_format,
            self.max_object_bytes,
            self.storage_root(),
            maximum_bytes,
            control,
        )?;
        let refs = read_direct_refs(&git_directory, self.object_format, max_refs, control)?;
        let head_target = read_head_target(&git_directory, control)?;
        let mut spool = spool::Spool::create(self.storage_root(), maximum_bytes, control)?;
        let validated = graph::validate_typed_with_custody(
            refs.iter().map(|(name, id)| {
                (
                    *id,
                    fgit_git_object::required_ref_target_kind(name.as_bytes()),
                )
            }),
            self.object_format,
            &parse_limits(self.object_format, self.max_object_bytes),
            graph_limits,
            |identity| {
                read_local_object(
                    &git_directory,
                    identity,
                    self.object_format,
                    self.max_object_bytes,
                    &mut packed,
                    control,
                )
            },
            |identity, object| spool.retain(identity, object, control),
            control,
        )?;
        let refs = CanonicalRefState::new_with_head_target(refs, head_target)
            .map_err(|_| LooseGitImportRefusal::HeadTargetNotBranch(Box::new(git_directory)))?;
        // Release pack decoding caches before placement. The proof retains only
        // bounded spool handles; no mutable source file is reread.
        packed.finish()?;
        let mut closure = BTreeSet::new();
        for identity in validated.objects.keys() {
            control.checkpoint()?;
            closure.insert(*identity);
        }
        // The validated graph also needs a persistable, readable authority
        // closure. Refuse an oversized metadata frame before any durable object
        // placement; extra elapsed-time/expanded-payload allowance cannot fix it.
        metadata::preflight(
            self.object_format,
            closure.len(),
            &refs,
            self.authority.limits().body_bytes,
            control,
        )?;
        let total_object_bytes = validated.total_bytes;
        // All required local edges and object bodies have now verified. Only
        // placement failures or cancellation can leave verified, noncanonical objects.
        let mut placements = placement::Placements::new(self);
        for (identity, entry) in validated.objects {
            // Flush before reading an object that would exceed the chunk budget.
            placements.prepare(entry.length(), control)?;
            let object = spool.read(identity, entry, control)?;
            placements.push(identity, object, control)?;
        }
        placements.flush(control)?;

        spool.finish()?;
        control.checkpoint()?;
        Ok(StagedLooseGitImport {
            refs,
            object_count: closure.len(),
            closure: PermittedObjectClosure::new(closure),
            total_object_bytes,
        })
    }
}

#[cfg(test)]
mod tests;
