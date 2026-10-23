//! Demand-driven original-object disclosure from independently selected parents.
//! Membership in the cumulative admitted set is necessary, but never sufficient:
//! each permitted object has a chain of verified native edges from these roots.

use super::*;
use fgit_git_object::ObjectError;
use std::collections::VecDeque;

pub(super) struct ParentReachability {
    format: GitHashAlgorithm,
    required: BTreeMap<GitOid, ObjectType>,
    pending: VecDeque<GitOid>,
    expanded: BTreeSet<GitOid>,
    edges: usize,
    bytes: usize,
    limits: MergeObjectLimits,
}

impl ParentReachability {
    pub(super) fn new(
        format: GitHashAlgorithm,
        roots: &[GitOid],
        limits: MergeObjectLimits,
    ) -> Result<Self, MergeSourceError> {
        let maximum = MergeObjectLimits::default();
        if roots.is_empty()
            || roots.len() > 2
            || limits.max_objects == 0
            || limits.max_objects > maximum.max_objects
            || limits.max_edges == 0
            || limits.max_edges > maximum.max_edges
            || limits.max_object_bytes == 0
            || limits.max_object_bytes > maximum.max_object_bytes
            || limits.max_total_bytes == 0
            || limits.max_total_bytes > maximum.max_total_bytes
        {
            return Err(MergeSourceError::BudgetExceeded);
        }
        let mut result = Self {
            format,
            required: BTreeMap::new(),
            pending: VecDeque::new(),
            expanded: BTreeSet::new(),
            edges: 0,
            bytes: 0,
            limits,
        };
        for root in roots {
            result.require(*root, ObjectType::Commit)?;
        }
        Ok(result)
    }

    pub(super) fn ensure(
        &mut self,
        wanted: GitOid,
        mut load: impl FnMut(GitOid) -> Result<(ObjectType, Vec<u8>), MergeSourceError>,
        mut live: impl FnMut() -> Result<(), MergeSourceError>,
    ) -> Result<bool, MergeSourceError> {
        live()?;
        if self.required.contains_key(&wanted) {
            return Ok(true);
        }
        // Breadth first starts with the current parent trees, not every blob or
        // the oldest history. Reads observed by the caller expand their edges
        // too, so normal tree/path and ancestry reads rarely need this search.
        while let Some(id) = self.pending.pop_front() {
            live()?;
            if self.expanded.contains(&id) {
                continue;
            }
            if self.expanded.len() >= self.limits.max_objects {
                return Err(MergeSourceError::BudgetExceeded);
            }
            let (kind, bytes) = load(id)?;
            self.observe(id, kind, &bytes, &mut live)?;
            if self.required.contains_key(&wanted) {
                return Ok(true);
            }
        }
        live()?;
        Ok(false)
    }

    /// A remembered identity is a typed native edge, not an untyped allow-list.
    pub(super) fn require_kind(
        &self,
        id: GitOid,
        kind: ObjectType,
    ) -> Result<(), MergeSourceError> {
        if self.required.get(&id) == Some(&kind) {
            Ok(())
        } else {
            Err(MergeSourceError::InvalidObject(id))
        }
    }

    pub(super) fn observe(
        &mut self,
        id: GitOid,
        kind: ObjectType,
        bytes: &[u8],
        live: &mut impl FnMut() -> Result<(), MergeSourceError>,
    ) -> Result<(), MergeSourceError> {
        live()?;
        if bytes.len() > self.limits.max_object_bytes {
            return Err(MergeSourceError::BudgetExceeded);
        }
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .filter(|value| *value <= self.limits.max_total_bytes)
            .ok_or(MergeSourceError::BudgetExceeded)?;
        if self.required.get(&id) != Some(&kind)
            || id.algorithm() != self.format
            || git_object_id(self.format, kind, bytes) != id
        {
            return Err(MergeSourceError::InvalidObject(id));
        }
        // Blob identity is checked, but blobs have no outgoing native edges.
        // Never read another blob merely to establish reachability.
        if kind == ObjectType::Blob || self.expanded.contains(&id) {
            return Ok(());
        }
        if self.expanded.len() >= self.limits.max_objects {
            return Err(MergeSourceError::BudgetExceeded);
        }
        let edges = native_edges(id, kind, bytes, self.limits, live)?;
        let total = self
            .edges
            .checked_add(edges.work)
            .filter(|value| *value <= self.limits.max_edges)
            .ok_or(MergeSourceError::BudgetExceeded)?;
        for (child, required) in edges.objects {
            live()?;
            self.require(child, required)?;
        }
        self.edges = total;
        self.expanded.insert(id);
        live()
    }

    fn require(&mut self, id: GitOid, kind: ObjectType) -> Result<(), MergeSourceError> {
        if id.is_zero() || id.algorithm() != self.format {
            return Err(MergeSourceError::InvalidObject(id));
        }
        if let Some(expected) = self.required.get(&id) {
            return if *expected == kind {
                Ok(())
            } else {
                Err(MergeSourceError::InvalidObject(id))
            };
        }
        // The edge bound covers remembered frontier identities, while the
        // object bound covers graph objects actually expanded. A wide admitted
        // tree does not consume one object-read allowance for each leaf blob.
        if self.required.len() >= self.limits.max_edges + 2 {
            return Err(MergeSourceError::BudgetExceeded);
        }
        self.required.insert(id, kind);
        if kind != ObjectType::Blob {
            self.pending
                .try_reserve(1)
                .map_err(|_| MergeSourceError::BudgetExceeded)?;
            self.pending.push_back(id);
        }
        Ok(())
    }
}

pub(super) struct NativeEdges {
    pub objects: Vec<(GitOid, ObjectType)>,
    pub work: usize,
}

/// Parse native edges, including their required kinds. Gitlinks consume work
/// but are not objects in this repository. Shared by disclosure and pack-only
/// coverage, which must not trust uploader-provided edge metadata either.
pub(super) fn native_edges(
    id: GitOid,
    kind: ObjectType,
    bytes: &[u8],
    limits: MergeObjectLimits,
    live: &mut impl FnMut() -> Result<(), MergeSourceError>,
) -> Result<NativeEdges, MergeSourceError> {
    live()?;
    if bytes.len() > limits.max_object_bytes {
        return Err(MergeSourceError::BudgetExceeded);
    }
    if kind == ObjectType::Blob {
        return Ok(NativeEdges {
            objects: Vec::new(),
            work: 0,
        });
    }
    let parsed = parse_object_body(
        kind,
        bytes,
        AcceptanceProfile::GitCompatibleImport,
        &ParseLimits {
            max_object_bytes: limits.max_object_bytes,
            max_tree_entries: limits.max_edges,
            tree_reference_bytes: id.algorithm().digest_len(),
            ..ParseLimits::default()
        },
    )
    .map_err(|error| match error {
        ObjectError::ObjectTooLarge { .. }
        | ObjectError::LooseHeaderTooLarge { .. }
        | ObjectError::TooManyTreeEntries { .. }
        | ObjectError::HeaderLimitExceeded { .. }
        | ObjectError::AllocationFailure => MergeSourceError::BudgetExceeded,
        _ => MergeSourceError::InvalidObject(id),
    })?;
    let oid = |value: &[u8]| {
        let value = std::str::from_utf8(value).map_err(|_| MergeSourceError::InvalidObject(id))?;
        GitOid::from_hex(id.algorithm(), &value.to_ascii_lowercase())
            .map_err(|_| MergeSourceError::InvalidObject(id))
    };
    let mut result = NativeEdges {
        objects: Vec::new(),
        work: 0,
    };
    let mut push = |child, expected| {
        live()?;
        result.work = result
            .work
            .checked_add(1)
            .filter(|value| *value <= limits.max_edges)
            .ok_or(MergeSourceError::BudgetExceeded)?;
        if let Some(expected) = expected {
            result
                .objects
                .try_reserve(1)
                .map_err(|_| MergeSourceError::BudgetExceeded)?;
            result.objects.push((child, expected));
        }
        Ok(())
    };
    match parsed {
        ParsedObject::Commit(commit) => {
            if commit
                .headers()
                .iter()
                .filter(|h| h.name == b"tree")
                .count()
                != 1
                || commit.headers().iter().any(|h| {
                    (h.name == b"tree" || h.name == b"parent") && !h.continuations.is_empty()
                })
            {
                return Err(MergeSourceError::InvalidObject(id));
            }
            push(
                oid(commit
                    .tree_reference()
                    .ok_or(MergeSourceError::InvalidObject(id))?)?,
                Some(ObjectType::Tree),
            )?;
            for parent in commit.parent_references() {
                push(oid(parent)?, Some(ObjectType::Commit))?;
            }
        }
        ParsedObject::Tree(entries) => {
            for entry in entries {
                let mode = std::str::from_utf8(&entry.mode)
                    .ok()
                    .and_then(|mode| u32::from_str_radix(mode, 8).ok())
                    .ok_or(MergeSourceError::InvalidObject(id))?;
                let expected = match mode & 0o170_000 {
                    0o040_000 => Some(ObjectType::Tree),
                    0o100_000 | 0o120_000 => Some(ObjectType::Blob),
                    0o160_000 => None,
                    _ => return Err(MergeSourceError::InvalidObject(id)),
                };
                let hex: String = entry
                    .object_id
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                push(oid(hex.as_bytes())?, expected)?;
            }
        }
        ParsedObject::Blob(_) => {}
        ParsedObject::Tag(_) => return Err(MergeSourceError::InvalidObject(id)),
    }
    live()?;
    Ok(result)
}
