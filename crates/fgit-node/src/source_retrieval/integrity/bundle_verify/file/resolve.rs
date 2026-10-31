//! Metadata-only discovery over scratch-backed native objects. REF_DELTA bases
//! come from native-verified pack entries or the separately captured, complete
//! declared prerequisite closure. Neither caller offsets nor an index can
//! manufacture a base. Cycles and missing bases cannot make progress.

mod stream;

use std::collections::BTreeMap;
use std::io::{Read, Seek, Write};

use fgit_crypto::{GitObjectHasher, NativeObjectIdentity, Sha1, Sha256, git_object_id};
use fgit_pack::{
    PackError, ParsedDeltaBase, ResolutionBudget, StreamPackEntryEnd, StreamPackEntryStart,
    StreamPackEvent, apply_delta_to_charged_base_with_budget, delta_declared_sizes,
    object_type_from_base_entry,
};
use fgit_types::{GitHashAlgorithm, GitOid};

use super::super::{BundleVerifyError, BundleVerifyLimits, GraphRefusal, ObjectKind, checkpoint};
use super::storage::{Append, Scratch, Span};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Base {
    Offset(u64),
    Identity(GitOid),
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Resolved {
    pub(super) id: GitOid,
    pub(super) kind: ObjectKind,
    pub(super) span: Span,
    depth: usize,
}

pub(super) struct Entry {
    pub(super) offset: u64,
    pub(super) end_offset: u64,
    pub(super) crc32: u32,
    original: Span,
    base: Option<Base>,
    pub(super) resolved: Option<Resolved>,
}

pub(super) enum NativeEntryHash {
    Sha1(GitObjectHasher<Sha1>),
    Sha256(GitObjectHasher<Sha256>),
}
impl NativeEntryHash {
    pub(super) fn new(format: GitHashAlgorithm, kind: ObjectKind, length: usize) -> Self {
        match format {
            GitHashAlgorithm::Sha1 => Self::Sha1(GitObjectHasher::new(kind, length as u64)),
            GitHashAlgorithm::Sha256 => Self::Sha256(GitObjectHasher::new(kind, length as u64)),
        }
    }
    pub(super) fn update(&mut self, bytes: &[u8]) -> Result<(), BundleVerifyError> {
        match self {
            Self::Sha1(hash) => hash.update(bytes),
            Self::Sha256(hash) => hash.update(bytes),
        }
        .map_err(|_| BundleVerifyError::Pack(PackError::NativeObjectIdMismatch))
    }
    pub(super) fn finish(self) -> Result<GitOid, BundleVerifyError> {
        match self {
            Self::Sha1(hash) => hash.finish().map(|id| id.erase()),
            Self::Sha256(hash) => hash.finish().map(|id| id.erase()),
        }
        .map_err(|_| BundleVerifyError::Pack(PackError::NativeObjectIdMismatch))
    }
}

struct Pending {
    start: StreamPackEntryStart,
    base: Option<Base>,
    append: Append,
    native: Option<(ObjectKind, NativeEntryHash)>,
}

pub(super) struct Inventory {
    pub(super) entries: Vec<Entry>,
    pub(super) by_id: BTreeMap<GitOid, usize>,
    /// External spans never acquire pack offsets, entries or index rows.
    pub(super) originals: BTreeMap<GitOid, Resolved>,
    original_expanded_bytes: usize,
    by_offset: BTreeMap<u64, usize>,
    fanout: BTreeMap<Base, usize>,
    payload_bytes: u64,
    budget: ResolutionBudget,
    pub(super) delta_objects: usize,
    pending: Option<Pending>,
}
impl Inventory {
    /// Prefer a supplied object when it also occurs in the original closure.
    /// Such overlaps must match both native identity and SHA-256 commitment.
    pub(super) fn object(&self, id: GitOid) -> Result<Resolved, BundleVerifyError> {
        self.by_id
            .get(&id)
            .and_then(|at| self.entries.get(*at))
            .and_then(|entry| entry.resolved)
            .or_else(|| self.originals.get(&id).copied())
            .ok_or(BundleVerifyError::ResolutionIncomplete)
    }

    pub(super) fn original(&self, id: GitOid) -> Result<Resolved, BundleVerifyError> {
        self.originals.get(&id).copied().ok_or_else(|| {
            BundleVerifyError::Graph(GraphRefusal::MissingTarget {
                source: None,
                target: id,
            })
        })
    }

    fn base_object(&self, base: Base) -> Option<Resolved> {
        match base {
            Base::Offset(offset) => self
                .by_offset
                .get(&offset)
                .and_then(|at| self.entries.get(*at))
                .and_then(|entry| entry.resolved),
            Base::Identity(id) => self.object(id).ok(),
        }
    }

    /// Retain real transport dependencies alongside native graph edges. An
    /// external original has no pack transport dependency of its own.
    pub(super) fn delta_base(&self, id: GitOid) -> Result<Option<GitOid>, BundleVerifyError> {
        let Some(at) = self.by_id.get(&id) else {
            return self.original(id).map(|_| None);
        };
        let entry = self
            .entries
            .get(*at)
            .ok_or(BundleVerifyError::ResolutionIncomplete)?;
        entry
            .base
            .map(|base| {
                self.base_object(base)
                    .map(|resolved| resolved.id)
                    .ok_or(BundleVerifyError::ResolutionIncomplete)
            })
            .transpose()
    }

    /// Called only after actual source EOF, exact length and native hashing.
    /// Prepay originals in the same count-once resolution ledger used by the
    /// native delta engine. The ceiling gains EXACTLY this prepaid amount:
    /// remaining uploaded expansion capacity is unchanged, even for a reused
    /// original base or an original that is never used by a delta.
    pub(super) fn retain_original(
        &mut self,
        id: GitOid,
        kind: ObjectKind,
        span: Span,
        limits: &BundleVerifyLimits,
    ) -> Result<(), BundleVerifyError> {
        if self.originals.contains_key(&id) {
            return Err(BundleVerifyError::DuplicateObject(id));
        }
        if let Some(uploaded) = self
            .by_id
            .get(&id)
            .and_then(|at| self.entries.get(*at))
            .and_then(|entry| entry.resolved)
        {
            if uploaded.kind != kind || !uploaded.span.same_content(span) {
                return Err(BundleVerifyError::DuplicateObject(id));
            }
        }
        let total = self
            .original_expanded_bytes
            .checked_add(span.length())
            .ok_or(BundleVerifyError::Graph(GraphRefusal::Limit(
                "original bytes",
            )))?;
        let mut accounting = limits.pack.clone();
        accounting.max_total_expanded_bytes = accounting
            .max_total_expanded_bytes
            .checked_add(total)
            .ok_or(BundleVerifyError::Graph(GraphRefusal::Limit(
                "expanded bytes",
            )))?;
        self.budget
            .charge_expanded(span.length(), &accounting)
            .map_err(BundleVerifyError::Pack)?;
        self.original_expanded_bytes = total;
        self.originals.insert(
            id,
            Resolved {
                id,
                kind,
                span,
                depth: 0,
            },
        );
        Ok(())
    }

    pub(super) const fn original_bytes(&self) -> usize {
        self.original_expanded_bytes
    }

    fn check_original_overlap(&self, resolved: Resolved) -> Result<(), BundleVerifyError> {
        if let Some(original) = self.originals.get(&resolved.id) {
            if original.kind != resolved.kind || !original.span.same_content(resolved.span) {
                return Err(BundleVerifyError::DuplicateObject(resolved.id));
            }
        }
        Ok(())
    }

    pub(super) fn charge_selection_work(
        &mut self,
        amount: usize,
        limits: &BundleVerifyLimits,
    ) -> Result<(), BundleVerifyError> {
        self.budget
            .charge_work(amount, &limits.pack)
            .map_err(BundleVerifyError::Pack)
    }

    pub(super) fn new(_limits: &BundleVerifyLimits) -> Self {
        Self {
            entries: Vec::new(),
            by_id: BTreeMap::new(),
            originals: BTreeMap::new(),
            original_expanded_bytes: 0,
            by_offset: BTreeMap::new(),
            fanout: BTreeMap::new(),
            payload_bytes: 0,
            budget: ResolutionBudget::new(),
            delta_objects: 0,
            pending: None,
        }
    }

    pub(super) fn accept<W: Read + Write + Seek>(
        &mut self,
        event: StreamPackEvent<'_>,
        format: GitHashAlgorithm,
        scratch: &mut Scratch<'_, W>,
        limits: &BundleVerifyLimits,
        live: &mut impl FnMut() -> bool,
    ) -> Result<(), BundleVerifyError> {
        checkpoint(live)?;
        match event {
            StreamPackEvent::Begin(start) => self.begin(start, format, scratch, limits, live),
            StreamPackEvent::Data(bytes) => {
                let pending = self
                    .pending
                    .as_mut()
                    .ok_or(BundleVerifyError::ResolutionIncomplete)?;
                scratch.append_chunk(&mut pending.append, bytes, live)?;
                if let Some((_, hash)) = &mut pending.native {
                    hash.update(bytes)?;
                }
                checkpoint(live)
            }
            StreamPackEvent::End(end) => self.end(end, scratch, live),
        }
    }

    fn begin<W: Read + Write + Seek>(
        &mut self,
        start: StreamPackEntryStart,
        format: GitHashAlgorithm,
        scratch: &mut Scratch<'_, W>,
        limits: &BundleVerifyLimits,
        live: &mut impl FnMut() -> bool,
    ) -> Result<(), BundleVerifyError> {
        if self.pending.is_some() {
            return Err(BundleVerifyError::ResolutionIncomplete);
        }
        if self.entries.len() >= limits.graph.max_objects {
            return Err(BundleVerifyError::Graph(GraphRefusal::Limit("objects")));
        }
        self.budget
            .charge_work(1, &limits.pack)
            .map_err(BundleVerifyError::Pack)?;
        if self.by_offset.contains_key(&start.offset) {
            return Err(BundleVerifyError::Pack(PackError::DuplicateObjectOffset(
                start.offset,
            )));
        }
        let base = match &start.delta_base {
            Some(ParsedDeltaBase::Ofs { base_offset, .. }) => {
                if *base_offset >= start.offset || !self.by_offset.contains_key(base_offset) {
                    return Err(BundleVerifyError::Pack(PackError::MissingDeltaBase));
                }
                Some(Base::Offset(*base_offset))
            }
            Some(ParsedDeltaBase::Ref { base, .. }) => Some(Base::Identity(*base)),
            None => None,
        };
        if let Some(base) = base {
            let count = self.fanout.entry(base).or_default();
            *count = count.checked_add(1).ok_or(BundleVerifyError::Pack(
                PackError::IntegerOverflow {
                    context: "file delta fanout",
                },
            ))?;
            if *count > limits.pack.max_delta_fanout {
                return Err(BundleVerifyError::Pack(PackError::DeltaFanoutLimit {
                    fanout: *count,
                    limit: limits.pack.max_delta_fanout,
                }));
            }
        }
        self.entries
            .try_reserve(1)
            .map_err(|_| BundleVerifyError::Allocation)?;
        let native = if base.is_none() {
            let kind =
                object_type_from_base_entry(start.header.kind).map_err(BundleVerifyError::Pack)?;
            let maximum = if kind == ObjectKind::Blob {
                limits.max_streamed_blob_bytes
            } else {
                limits.graph.max_object_bytes
            };
            if start.header.declared_size > maximum {
                return Err(BundleVerifyError::Graph(GraphRefusal::Limit(
                    "object bytes",
                )));
            }
            self.charge_payload(start.header.declared_size, limits)?;
            self.budget
                .charge_expanded(start.header.declared_size, &limits.pack)
                .map_err(BundleVerifyError::Pack)?;
            Some((
                kind,
                NativeEntryHash::new(format, kind, start.header.declared_size),
            ))
        } else {
            self.delta_objects += 1;
            None
        };
        let append = scratch.begin_append(start.header.declared_size, live)?;
        self.pending = Some(Pending {
            start,
            base,
            append,
            native,
        });
        checkpoint(live)
    }

    fn end<W: Read + Write + Seek>(
        &mut self,
        end: StreamPackEntryEnd,
        scratch: &mut Scratch<'_, W>,
        live: &mut impl FnMut() -> bool,
    ) -> Result<(), BundleVerifyError> {
        let pending = self
            .pending
            .take()
            .ok_or(BundleVerifyError::ResolutionIncomplete)?;
        let span = scratch.finish_append(pending.append, live)?;
        let at = self.entries.len();
        let resolved = if let Some((kind, hash)) = pending.native {
            let id = hash.finish()?;
            if self.by_id.contains_key(&id) {
                return Err(BundleVerifyError::DuplicateObject(id));
            }
            self.by_id.insert(id, at);
            Some(Resolved {
                id,
                kind,
                span,
                depth: 0,
            })
        } else {
            None
        };
        self.by_offset.insert(pending.start.offset, at);
        self.entries.push(Entry {
            offset: pending.start.offset,
            end_offset: end.end_offset,
            crc32: end.crc32,
            original: span,
            base: pending.base,
            resolved,
        });
        checkpoint(live)
    }

    fn charge_payload(
        &mut self,
        amount: usize,
        limits: &BundleVerifyLimits,
    ) -> Result<(), BundleVerifyError> {
        self.payload_bytes = self
            .payload_bytes
            .checked_add(amount as u64)
            .filter(|total| *total <= limits.graph.max_payload_bytes)
            .ok_or(BundleVerifyError::Graph(GraphRefusal::Limit(
                "payload bytes",
            )))?;
        Ok(())
    }

    pub(super) fn resolve<W: Read + Write + Seek>(
        &mut self,
        format: GitHashAlgorithm,
        scratch: &mut Scratch<'_, W>,
        limits: &BundleVerifyLimits,
        live: &mut impl FnMut() -> bool,
    ) -> Result<usize, BundleVerifyError> {
        checkpoint(live)?;
        if self.pending.is_some() {
            return Err(BundleVerifyError::ResolutionIncomplete);
        }
        if self.entries.is_empty() {
            return Ok(0);
        }
        if self.delta_objects == 0 {
            return Ok(1);
        }
        // Incoming framing and payload accounting keep the original limits.
        // Only the native count-once expansion ledger has this prepaid credit;
        // every original byte was already charged by `retain_original`.
        let mut resolution_limits = limits.clone();
        resolution_limits.pack.max_total_expanded_bytes = limits
            .pack
            .max_total_expanded_bytes
            .checked_add(self.original_expanded_bytes)
            .ok_or(BundleVerifyError::Graph(GraphRefusal::Limit(
                "expanded bytes",
            )))?;
        // Base discovery is the first pass. Subsequent bounded passes learn
        // forward REF_DELTA identities. Each successful entry is expanded once;
        // a scan with no progress refuses rather than retrying or fetching.
        for pass in 0..=limits.pack.max_delta_depth.min(self.entries.len()) {
            checkpoint(live)?;
            let mut progress = false;
            for at in 0..self.entries.len() {
                checkpoint(live)?;
                self.budget
                    .charge_work(1, &limits.pack)
                    .map_err(BundleVerifyError::Pack)?;
                if self.entries[at].resolved.is_some() {
                    continue;
                }
                let base = self.entries[at]
                    .base
                    .ok_or(BundleVerifyError::ResolutionIncomplete)?;
                let Some(base) = self.base_object(base) else {
                    continue;
                };
                let depth = base.depth.checked_add(1).ok_or(BundleVerifyError::Pack(
                    PackError::IntegerOverflow {
                        context: "file delta depth",
                    },
                ))?;
                if depth > limits.pack.max_delta_depth {
                    return Err(BundleVerifyError::Pack(PackError::DeltaDepthLimit {
                        depth,
                        limit: limits.pack.max_delta_depth,
                    }));
                }
                let buffered_maximum = limits
                    .pack
                    .max_object_bytes
                    .min(limits.graph.max_object_bytes);
                let program = scratch.read(
                    self.entries[at].original,
                    limits.pack.max_object_bytes,
                    live,
                )?;
                let sizes = delta_declared_sizes(&program, live);
                checkpoint(live)?;
                let (_, result_length) = sizes.map_err(BundleVerifyError::Pack)?;
                let resolved = if base.kind == ObjectKind::Blob
                    && (base.span.length() > buffered_maximum || result_length > buffered_maximum)
                {
                    // The entire graph-payload allowance is reserved before
                    // scratch output. Streamed execution separately charges
                    // unique expansion, base verification, output and random
                    // block-read work to the same operation-wide pack budget.
                    self.charge_payload(result_length, limits)?;
                    stream::resolve(
                        scratch,
                        base,
                        &program,
                        format,
                        depth,
                        &resolution_limits,
                        &mut self.budget,
                        live,
                    )?
                } else {
                    let maximum = if base.kind == ObjectKind::Blob {
                        buffered_maximum.min(limits.max_streamed_blob_bytes)
                    } else {
                        buffered_maximum
                    };
                    if base.span.length() > maximum {
                        return Err(BundleVerifyError::Pack(PackError::ObjectSizeLimit {
                            actual: base.span.length(),
                            limit: maximum,
                        }));
                    }
                    let base_body = scratch.read(base.span, maximum, live)?;
                    let actual = git_object_id(format, base.kind, &base_body);
                    checkpoint(live)?;
                    if actual != base.id {
                        return Err(BundleVerifyError::ScratchChanged);
                    }
                    let mut delta_limits = resolution_limits.pack.clone();
                    delta_limits.max_object_bytes = maximum;
                    // Retain the buffered oracle and its exact work accounting
                    // for objects that already fit the ordinary memory bound.
                    let result = apply_delta_to_charged_base_with_budget(
                        &base_body,
                        &program,
                        &delta_limits,
                        &mut self.budget,
                        live,
                    );
                    checkpoint(live)?;
                    let result = result.map_err(BundleVerifyError::Pack)?;
                    drop(base_body);
                    self.charge_payload(result.len(), limits)?;
                    let id = git_object_id(format, base.kind, &result);
                    checkpoint(live)?;
                    let span = scratch.append(&result, live)?;
                    Resolved {
                        id,
                        kind: base.kind,
                        span,
                        depth,
                    }
                };
                if self.by_id.contains_key(&resolved.id) {
                    return Err(BundleVerifyError::DuplicateObject(resolved.id));
                }
                self.check_original_overlap(resolved)?;
                self.by_id.insert(resolved.id, at);
                self.entries[at].resolved = Some(resolved);
                progress = true;
            }
            if self.by_id.len() == self.entries.len() {
                return Ok(pass + 2);
            }
            if !progress {
                return Err(BundleVerifyError::ResolutionIncomplete);
            }
        }
        Err(BundleVerifyError::ResolutionIncomplete)
    }
}
