#![forbid(unsafe_code)]
//! Offline full-bundle verification using the existing native pack and graph engines.
//!
//! No node is opened, no external base is consulted and nothing is published.
//! The report covers every included object's typed local dependencies, not only
//! objects reachable from current refs. Gitlinks remain external dependencies.

mod expectations;
mod file;
mod recovery;
pub use file::{
    FileBundleVerification, FileGitBundleRecovery, prepare_git_bundle_recovery_reader,
    verify_git_bundle_reader,
};
pub use recovery::{BundleRecoveryError, GitBundleRecovery, prepare_git_bundle_recovery};
pub use expectations::{
    BundleExpectationError, BundleExpectations, MAX_EXPECTED_REFS, MatchedGitBundle,
    verify_git_bundle_against,
};

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fgit_crypto::{git_object_id, sha256_digest};
use fgit_pack::full_bundle::{FullBundleError, FullBundleInput, FullBundleLimits};
use fgit_pack::{
    CachedResolver, DeltaObject, NativeChecksumVerifier, PackError, PackLimits, PackObject,
    ResolutionBudget, read_verified_pack,
};
use fgit_treefs::integrity::{
    GraphLimits, GraphRefusal, GraphReport, ObjectGraphAudit, ObjectKind,
};
use fgit_types::{GitHashAlgorithm, GitOid, RefName};

/// Payload and work limits are independent. They are not a total-process RSS limit.
#[derive(Clone, Debug)]
pub struct BundleVerifyLimits {
    pub envelope: FullBundleLimits,
    pub pack: PackLimits,
    pub graph: GraphLimits,
}
impl Default for BundleVerifyLimits {
    fn default() -> Self {
        Self {
            envelope: FullBundleLimits::default(),
            pack: PackLimits {
                max_input_bytes: 128 * 1024 * 1024,
                max_entries: 100_000,
                ..PackLimits::default()
            },
            graph: GraphLimits {
                max_references: 4096,
                max_payload_bytes: 128 * 1024 * 1024,
                ..GraphLimits::default()
            },
        }
    }
}

#[derive(Debug)]
pub enum BundleVerifyError {
    Stopped,
    Envelope(FullBundleError),
    Pack(PackError),
    Graph(GraphRefusal),
    Expectation(BundleExpectationError),
    DuplicateObject(GitOid),
    ResolutionIncomplete,
    Allocation,
    Io {
        operation: &'static str,
        kind: std::io::ErrorKind,
    },
    ScratchNotEmpty,
    ScratchChanged,
    SourceChanged,
}
impl fmt::Display for BundleVerifyError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stopped => out.write_str("bundle_verification_stopped"),
            Self::Envelope(error) => write!(out, "bundle_envelope: {error}"),
            Self::Pack(error) => write!(out, "bundle_pack: {error}"),
            Self::Graph(error) => write!(out, "bundle_graph: {error}"),
            Self::Expectation(error) => fmt::Display::fmt(error, out),
            Self::DuplicateObject(id) => write!(out, "duplicate_bundle_object: {id}"),
            Self::ResolutionIncomplete => {
                out.write_str("bundle_delta_base_missing_or_unresolvable")
            }
            Self::Allocation => out.write_str("bundle_allocation_refused"),
            Self::Io { operation, kind } => write!(out, "bundle_io: {operation}: {kind:?}"),
            Self::ScratchNotEmpty => out.write_str("bundle_scratch_must_be_empty"),
            Self::ScratchChanged => out.write_str("bundle_scratch_changed"),
            Self::SourceChanged => out.write_str("bundle_source_changed"),
        }
    }
}
impl std::error::Error for BundleVerifyError {}

/// Constructible only after the complete pack and graph checks succeed.
/// This is content evidence, not origin authentication, admission or authority.
#[derive(Clone, Debug)]
pub struct VerifiedGitBundle {
    format: GitHashAlgorithm,
    bytes: usize,
    sha256: [u8; 32],
    pack_bytes: usize,
    pack_checksum: GitOid,
    advertised_head: Option<GitOid>,
    references: BTreeMap<RefName, GitOid>,
    graph: GraphReport,
    delta_objects: usize,
    resolution_passes: usize,
}
impl VerifiedGitBundle {
    #[must_use]
    pub const fn format(&self) -> GitHashAlgorithm {
        self.format
    }
    #[must_use]
    pub const fn bytes(&self) -> usize {
        self.bytes
    }
    #[must_use]
    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
    #[must_use]
    pub const fn pack_bytes(&self) -> usize {
        self.pack_bytes
    }
    #[must_use]
    pub const fn pack_checksum(&self) -> GitOid {
        self.pack_checksum
    }
    #[must_use]
    pub const fn advertised_head(&self) -> Option<GitOid> {
        self.advertised_head
    }
    #[must_use]
    pub fn references(&self) -> &BTreeMap<RefName, GitOid> {
        &self.references
    }
    #[must_use]
    pub const fn graph(&self) -> &GraphReport {
        &self.graph
    }
    #[must_use]
    pub const fn delta_objects(&self) -> usize {
        self.delta_objects
    }
    #[must_use]
    pub const fn resolution_passes(&self) -> usize {
        self.resolution_passes
    }
}

fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), BundleVerifyError> {
    if live() {
        Ok(())
    } else {
        Err(BundleVerifyError::Stopped)
    }
}
const fn offset(object: &PackObject) -> u64 {
    match object {
        PackObject::Base { offset, .. }
        | PackObject::TypedBase { offset, .. }
        | PackObject::Delta(DeltaObject { offset, .. }) => *offset,
    }
}
const fn set_id(object: &mut PackObject, value: GitOid) {
    match object {
        PackObject::Base { id, .. } | PackObject::TypedBase { id, .. } => *id = Some(value),
        PackObject::Delta(delta) => delta.id = Some(value),
    }
}
type Resolved = BTreeMap<GitOid, (ObjectKind, Vec<u8>, u64)>;

// REF_DELTA identities are learned only from reconstructed native bytes. Rebuild
// the native resolver's immutable index between discovery passes, as receive
// quarantine does. The SAME resolution budget charges successful and deferred
// attempts across all passes. There is no ambient thin-pack fallback.
fn resolve(
    mut objects: Vec<PackObject>,
    format: GitHashAlgorithm,
    limits: &BundleVerifyLimits,
    live: &mut impl FnMut() -> bool,
) -> Result<(Resolved, usize), BundleVerifyError> {
    let mut verified = BTreeMap::new();
    let mut completed = BTreeSet::new();
    let mut budget = ResolutionBudget::new();
    let mut payload = 0_u64;
    if objects.is_empty() {
        return Ok((verified, 0));
    }
    // One pass establishes base identities; at most one additional pass per
    // dependency level is necessary. Count also bounds absurd caller depths.
    for pass in 0..=limits.pack.max_delta_depth.min(objects.len()) {
        checkpoint(live)?;
        let mut newly_resolved = Vec::new();
        {
            let result = CachedResolver::new(&objects, &(), &limits.pack, live);
            checkpoint(live)?;
            let mut resolver = result.map_err(BundleVerifyError::Pack)?;
            for (index, object) in objects.iter().enumerate() {
                checkpoint(live)?;
                if completed.contains(&index) {
                    continue;
                }
                let result =
                    resolver.resolve_offset_typed_with_budget(offset(object), &mut budget, live);
                checkpoint(live)?;
                match result {
                    Ok((kind, body)) => {
                        payload = payload
                            .checked_add(body.len() as u64)
                            .filter(|value| *value <= limits.graph.max_payload_bytes)
                            .ok_or(BundleVerifyError::Graph(GraphRefusal::Limit(
                                "payload bytes",
                            )))?;
                        newly_resolved
                            .try_reserve(1)
                            .map_err(|_| BundleVerifyError::Allocation)?;
                        newly_resolved.push((index, kind, body));
                    }
                    Err(PackError::MissingDeltaBase) => {}
                    Err(error) => return Err(BundleVerifyError::Pack(error)),
                }
            }
        }
        if newly_resolved.is_empty() {
            return Err(BundleVerifyError::ResolutionIncomplete);
        }
        for (index, kind, body) in newly_resolved {
            checkpoint(live)?;
            let id = git_object_id(format, kind, &body);
            checkpoint(live)?;
            if verified.insert(id, (kind, body, offset(&objects[index]))).is_some() {
                return Err(BundleVerifyError::DuplicateObject(id));
            }
            set_id(&mut objects[index], id);
            completed.insert(index);
        }
        if completed.len() == objects.len() {
            return Ok((verified, pass + 1));
        }
    }
    Err(BundleVerifyError::ResolutionIncomplete)
}

/// Verify one owned-by-the-caller, immutable full Git bundle. The callback is
/// shared with the existing header, inflater, resolver and graph checker. Once
/// it refuses, this invocation stays stopped even if a later poll would allow.
/// No failed/partial report, borrowed base, store write or network read exists.
pub fn verify_git_bundle(
    input: &[u8],
    limits: &BundleVerifyLimits,
    allow_work: &mut impl FnMut() -> bool,
) -> Result<VerifiedGitBundle, BundleVerifyError> {
    verify_git_bundle_inner(input, limits, None, allow_work)
}

fn verify_git_bundle_inner(
    input: &[u8],
    limits: &BundleVerifyLimits,
    expectations: Option<&BundleExpectations>,
    allow_work: &mut impl FnMut() -> bool,
) -> Result<VerifiedGitBundle, BundleVerifyError> {
    verify_git_bundle_with_locations(input, limits, expectations, None, allow_work)
}

// Recovery consumes locations from the SAME bounded framing/resolution pass.
// Ordinary verification keeps its public report and does not retain this table.
fn verify_git_bundle_with_locations(
    input: &[u8],
    limits: &BundleVerifyLimits,
    expectations: Option<&BundleExpectations>,
    mut locations: Option<&mut Vec<(GitOid, u64)>>,
    allow_work: &mut impl FnMut() -> bool,
) -> Result<VerifiedGitBundle, BundleVerifyError> {
    let mut stopped = false;
    let mut live = || {
        if !stopped && !allow_work() {
            stopped = true;
        }
        !stopped
    };
    checkpoint(&mut live)?;
    if let Some(expected) = expectations {
        expected.validate_limits(limits).map_err(BundleVerifyError::Expectation)?;
    }
    let result = FullBundleInput::parse(input, limits.envelope, &mut live);
    checkpoint(&mut live)?;
    let envelope = result.map_err(BundleVerifyError::Envelope)?;
    if envelope.references().len() > limits.graph.max_references {
        return Err(BundleVerifyError::Graph(GraphRefusal::Limit("references")));
    }
    // A match here is only preflight. Never construct a content result until
    // the ordinary native pack and graph checks below have completed.
    let expected_digest = match expectations {
        Some(expected) => expected.check(input, &envelope, &mut live)?,
        None => None,
    };
    let references = envelope
        .references()
        .iter()
        .map(|row| (row.name().clone(), *row.target()))
        .collect();
    // Apply the tighter caller-selected object count before the pack reader's
    // table reservation or inflation. The graph may deliberately be narrower.
    let mut pack_limits = limits.pack.clone();
    pack_limits.max_entries = pack_limits
        .max_entries
        .min(u32::try_from(limits.graph.max_objects).unwrap_or(u32::MAX));
    let result = read_verified_pack(
        envelope.pack_bytes(),
        envelope.format(),
        &pack_limits,
        &mut live,
        &NativeChecksumVerifier,
    );
    checkpoint(&mut live)?;
    let pack = result.map_err(BundleVerifyError::Pack)?;
    if pack.entries().len() > limits.graph.max_objects {
        return Err(BundleVerifyError::Graph(GraphRefusal::Limit("objects")));
    }
    if let Some(entries) = &mut locations {
        entries
            .try_reserve_exact(pack.entries().len())
            .map_err(|_| BundleVerifyError::Allocation)?;
    }
    let pack_checksum = pack.trailer;
    let objects = pack
        .into_scalar_objects(|_| None)
        .map_err(BundleVerifyError::Pack)?;
    let delta_objects = objects
        .iter()
        .filter(|object| matches!(object, PackObject::Delta(_)))
        .count();
    let (verified, resolution_passes) = resolve(objects, envelope.format(), limits, &mut live)?;
    let ids = verified.keys().copied().collect();
    let result = ObjectGraphAudit::new(&ids, envelope.format(), limits.graph, &mut live);
    checkpoint(&mut live)?;
    let mut graph = result.map_err(BundleVerifyError::Graph)?;
    for (id, (kind, body, position)) in verified {
        let result = graph.observe(id, kind, &body, &mut live);
        checkpoint(&mut live)?;
        result.map_err(BundleVerifyError::Graph)?;
        if let Some(entries) = &mut locations {
            entries.push((id, position));
        }
    }
    let result = graph.finish(&references, &mut live);
    checkpoint(&mut live)?;
    let graph = result.map_err(BundleVerifyError::Graph)?;
    let sha256 = expected_digest.unwrap_or_else(|| sha256_digest(input));
    checkpoint(&mut live)?;
    Ok(VerifiedGitBundle {
        format: envelope.format(),
        bytes: input.len(),
        sha256,
        pack_bytes: envelope.pack_bytes().len(),
        pack_checksum,
        advertised_head: envelope.head(),
        references,
        graph,
        delta_objects,
        resolution_passes,
    })
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod expectation_tests;
