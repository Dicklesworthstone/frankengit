//! Bounded staging of an ordinary local Git directory.
//!
//! This module owns only the pre-publication half of import: it validates a
//! local Git directory, follows the closure named by its direct refs, resolves
//! those objects from checksum-bound loose or idx/pack storage, and retains
//! verified immutable object bodies in the node's fabric. Standalone staging
//! links their immutable names; durable import keeps synced private custody
//! until ordinary admission prepares a commit. The returned
//! [`StagedLooseGitImport`] is not a publication capability.  In particular,
//! objects staged here remain non-canonical until the caller has sealed an
//! import request, recorded its admission, and published an RCR through the
//! authority head's conditional replacement.

#[cfg(test)]
use source_io::read_through_first_excess_byte;
#[cfg(test)]
mod cancellation_tests;
mod control;
pub mod graph;
mod layout;
mod metadata;
mod packed_sources;
mod placement;
mod refusal;
mod source_io;
pub use refusal::LooseGitImportRefusal;
use source_io::{
    BoundedInputClass, bounded_directory_entries, import_pack_limits, io_refusal,
    is_ignored_pack_accelerator, open_regular_bounded, pack_input_limit, pack_refusal,
    parse_limits, path_metadata, read_local_object, read_regular_bounded, reject_object_alternates,
};
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
use crate::receive_staging::ReceiveStaging;

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

/// The same domain-separated digest stored by immutable placement. An optional
/// representation must match the selected body even under native-ID aliasing.
fn captured_payload_commitment(kind: fgit_git_object::ObjectType, body: &[u8]) -> Option<[u8; 32]> {
    fgit_crypto::git_payload_commitment(kind, body, fgit_types::CANONICAL_CODEC_VERSION)
        .digest()
        .as_bytes()
        .try_into()
        .ok()
}

/// The shared source-import metadata preflight, before candidate object staging.
pub fn preflight_import_metadata(
    format: GitHashAlgorithm,
    object_count: usize,
    refs: &CanonicalRefState,
    authority_bytes: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<(), LooseGitImportRefusal> {
    let control = ImportControl::new(live);
    metadata::preflight(format, object_count, refs, authority_bytes, &control)
}

/// Verified, non-canonical state staged from a local Git directory.
///
/// This type has no public constructor.  Its refs and closure can only be
/// produced after every object reachable from a direct source ref was parsed,
/// re-identified, and retained through the immutable fabric. Standalone staging
/// places immutable names; durable import holds private synced files. It is
/// still only a candidate: publishing it requires the sealed import path.
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
    /// `.git` directory or bounded `gitdir:` file. Linked worktrees select
    /// their own HEAD and private refs while sharing objects and ordinary refs
    /// through `commondir`. Direct refs may reach loose objects or objects in
    /// checksum-bound idx-v2/pack-v2 pairs. Alternates, symbolic refs, symlinks,
    /// malformed indirection and a changed source layout are typed refusals.
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
        staging: &ReceiveStaging,
    ) -> Result<StagedLooseGitImport, LooseGitImportRefusal> {
        self.stage_import_profile_in(
            request,
            source,
            max_refs,
            graph::MAX_REACHABLE_OBJECT_BYTES,
            Some(staging),
        )
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
            None,
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
        staging: Option<&ReceiveStaging>,
    ) -> Result<StagedLooseGitImport, LooseGitImportRefusal> {
        control.checkpoint()?;
        if max_refs > MAX_IMPORT_REFS {
            return Err(LooseGitImportRefusal::RefLimitInvalid {
                requested: max_refs,
                maximum: MAX_IMPORT_REFS,
            });
        }
        profile::validate_limit(maximum_bytes)?;
        let graph_limits = graph::Limits {
            bytes: maximum_bytes,
            ..graph::Limits::default()
        };
        let layout = layout::SourceLayout::resolve(source, control)?;
        let git_directory = layout.common_directory();
        reject_object_alternates(git_directory, control)?;
        let mut packed = PackedObjectSources::open_with_profile(
            git_directory,
            self.object_format,
            self.max_object_bytes,
            self.storage_root(),
            maximum_bytes,
            control,
        )?
        .with_received_pack_custody(std::sync::Arc::clone(
            &self.service_config.received_pack_cache,
        ));
        let refs = layout.read_refs(self.object_format, max_refs, control)?;
        let head_target = layout.read_head(control)?;
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
                    git_directory,
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
        let refs = CanonicalRefState::new_with_head_target(refs, head_target).map_err(|_| {
            LooseGitImportRefusal::HeadTargetNotBranch(Box::new(
                layout.git_directory().to_path_buf(),
            ))
        })?;
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
        // Release expanded decoder spools before placement. Optional raw
        // custody comes only from the original verified stream and only when
        // every entry is covered by this complete graph. Source paths are
        // never reopened to construct a reusable representation.
        let mut captured = packed.finish_with_captures(&closure, control)?;
        let total_object_bytes = validated.total_bytes;
        // Indirection is local input, never authority. Detect a changed
        // gitfile/commondir or selected worktree refs before installing any
        // objects; all subsequent bytes come from the verified private spool.
        layout.revalidate(self.object_format, max_refs, &refs, control)?;
        // All required local edges and object bodies have now verified. The
        // standalone API places immutable names; durable import retains only
        // private synced batches until admission prepares its first commit.
        let mut placements = placement::Placements::new(self).with_deferred(staging);
        let has_captures = !captured.is_empty();
        let placed = (|| {
            let mut observe = |identity, commitment| {
                for candidate in &mut captured {
                    candidate.observe(identity, commitment);
                }
            };
            for (identity, entry) in validated.objects {
                // Flush before reading an object that would exceed the chunk budget.
                placements.prepare(entry.length(), control)?;
                let object = spool.read_identified(identity, entry, control)?;
                placements.push_observing(
                    identity,
                    object,
                    control,
                    has_captures.then_some(&mut observe),
                )?;
            }
            placements.finish(control)
        })();
        // A batch still in flight is settled, never left to its drop.
        if let Err(refusal) = placed {
            return Err(placements.abandon(refusal));
        }

        spool.finish()?;
        control.checkpoint()?;
        for candidate in captured {
            control.checkpoint()?;
            let Some(pending) = candidate.complete() else {
                continue;
            };
            let pending = pending.with_persistence(self.durable_received_pack_store());
            if let Some(staging) = staging {
                staging
                    .retain_received_pack(pending)
                    .map_err(control::interrupted)?;
            } else {
                // Standalone import has completed immutable placement. A
                // deferred import activates the same custody only when its
                // ordinary admission projection publishes the staged bodies.
                let _retained = pending.commit_with_deadline(&mut control.cpu_probe());
                control.checkpoint()?;
                // Optional custody failure cannot change an import result.
                // The sticky original request stop above remains authoritative.
            }
        }
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
