//! Metadata-only discovery over scratch-backed native objects. REF_DELTA bases
//! are learned exclusively from locally reconstructed bytes, never an index or
//! an external object source. Cycles and missing bases cannot make progress.

use std::collections::BTreeMap;
use std::io::{Read, Seek, Write};

use fgit_crypto::git_object_id;
use fgit_pack::{
    PackError, ParsedDeltaBase, ResolutionBudget, StreamPackEntry,
    apply_delta_to_charged_base_with_budget, object_type_from_base_entry,
};
use fgit_types::{GitHashAlgorithm, GitOid};

use super::super::{BundleVerifyError, BundleVerifyLimits, GraphRefusal, ObjectKind, checkpoint};
use super::storage::{Scratch, Span};

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

pub(super) struct Inventory {
    pub(super) entries: Vec<Entry>,
    pub(super) by_id: BTreeMap<GitOid, usize>,
    by_offset: BTreeMap<u64, usize>,
    fanout: BTreeMap<Base, usize>,
    payload_bytes: u64,
    budget: ResolutionBudget,
    pub(super) delta_objects: usize,
}
impl Inventory {
    pub(super) fn new(_limits: &BundleVerifyLimits) -> Self {
        Self {
            entries: Vec::new(),
            by_id: BTreeMap::new(),
            by_offset: BTreeMap::new(),
            fanout: BTreeMap::new(),
            payload_bytes: 0,
            budget: ResolutionBudget::new(),
            delta_objects: 0,
        }
    }

    pub(super) fn accept<W: Read + Write + Seek>(
        &mut self,
        entry: StreamPackEntry,
        format: GitHashAlgorithm,
        scratch: &mut Scratch<'_, W>,
        limits: &BundleVerifyLimits,
        live: &mut impl FnMut() -> bool,
    ) -> Result<(), BundleVerifyError> {
        checkpoint(live)?;
        if self.entries.len() >= limits.graph.max_objects {
            return Err(BundleVerifyError::Graph(GraphRefusal::Limit("objects")));
        }
        self.budget
            .charge_work(1, &limits.pack)
            .map_err(BundleVerifyError::Pack)?;
        let original = &entry.entry;
        // The streaming reader has already bounded every inflated member by
        // the pack limit. A delta program is not a graph object: its result is
        // independently checked against the tighter graph limit at resolution.
        if original.delta_base.is_none() && original.inflated.len() > limits.graph.max_object_bytes
        {
            return Err(BundleVerifyError::Graph(GraphRefusal::Limit(
                "object bytes",
            )));
        }
        if self.by_offset.contains_key(&original.offset) {
            return Err(BundleVerifyError::Pack(PackError::DuplicateObjectOffset(
                original.offset,
            )));
        }
        let base = match &original.delta_base {
            Some(ParsedDeltaBase::Ofs { base_offset, .. }) => {
                // Offsets identify exact earlier entry starts; a byte inside an
                // earlier compressed member is never accepted as a base.
                if *base_offset >= original.offset || !self.by_offset.contains_key(base_offset) {
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
        let resolved = if base.is_none() {
            let kind = object_type_from_base_entry(original.header.kind)
                .map_err(BundleVerifyError::Pack)?;
            self.charge_payload(original.inflated.len(), limits)?;
            self.budget
                .charge_expanded(original.inflated.len(), &limits.pack)
                .map_err(BundleVerifyError::Pack)?;
            let id = git_object_id(format, kind, &original.inflated);
            checkpoint(live)?;
            if self.by_id.contains_key(&id) {
                return Err(BundleVerifyError::DuplicateObject(id));
            }
            Some((id, kind))
        } else {
            self.delta_objects += 1;
            None
        };
        let span = scratch.append(&original.inflated, live)?;
        let at = self.entries.len();
        self.by_offset.insert(original.offset, at);
        let resolved = resolved.map(|(id, kind)| {
            self.by_id.insert(id, at);
            Resolved {
                id,
                kind,
                span,
                depth: 0,
            }
        });
        self.entries.push(Entry {
            offset: original.offset,
            end_offset: entry.end_offset,
            crc32: entry.crc32,
            original: span,
            base,
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
        if self.entries.is_empty() {
            return Ok(0);
        }
        if self.delta_objects == 0 {
            return Ok(1);
        }
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
                let base_at = match base {
                    Base::Offset(offset) => self.by_offset.get(&offset),
                    Base::Identity(id) => self.by_id.get(&id),
                }
                .copied();
                let Some(base_at) = base_at else {
                    continue;
                };
                let Some(base) = self.entries[base_at].resolved else {
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
                let maximum = limits
                    .pack
                    .max_object_bytes
                    .min(limits.graph.max_object_bytes);
                let base_body = scratch.read(base.span, maximum, live)?;
                let actual = git_object_id(format, base.kind, &base_body);
                checkpoint(live)?;
                if actual != base.id {
                    return Err(BundleVerifyError::ScratchChanged);
                }
                let program = scratch.read(
                    self.entries[at].original,
                    limits.pack.max_object_bytes,
                    live,
                )?;
                let mut delta_limits = limits.pack.clone();
                delta_limits.max_object_bytes = maximum;
                // Every inventory base was charged once when accepted or
                // reconstructed, and its scratch bytes and native identity
                // were just checked. Reuse consumes work, not another copy of
                // the unique expanded-payload allowance.
                let result = apply_delta_to_charged_base_with_budget(
                    &base_body,
                    &program,
                    &delta_limits,
                    &mut self.budget,
                    live,
                );
                checkpoint(live)?;
                let result = result.map_err(BundleVerifyError::Pack)?;
                drop(program);
                drop(base_body);
                self.charge_payload(result.len(), limits)?;
                let id = git_object_id(format, base.kind, &result);
                checkpoint(live)?;
                if self.by_id.contains_key(&id) {
                    return Err(BundleVerifyError::DuplicateObject(id));
                }
                let span = scratch.append(&result, live)?;
                self.entries[at].resolved = Some(Resolved {
                    id,
                    kind: base.kind,
                    span,
                    depth,
                });
                self.by_id.insert(id, at);
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
