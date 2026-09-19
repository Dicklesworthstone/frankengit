//! Current-ref-authorized historical source selection. A candidate object ID
//! never causes a direct read: only parent edges from the selected tip do.
//! This is a bounded local-owner profile, not an agent capability expansion.

use std::collections::{BTreeSet, VecDeque};

use super::*;

const MAX_COMMITS: usize = 4096;
const MAX_EDGES: usize = 16_384;
const MAX_COMMIT_BYTES: usize = 64 * 1024;
const MAX_ANCESTRY_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy)]
pub(super) struct Selection {
    pub(super) expected_ref_tip: Oid,
    pub(super) commit: Oid,
}

impl Selection {
    pub(super) fn validate(
        self,
        format: Format,
        query: &SourceBrowseQuery,
    ) -> Result<(), NodeWorkspaceRefusal> {
        if [self.expected_ref_tip, self.commit]
            .iter()
            .any(|id| id.is_zero() || id.algorithm() != format)
        {
            return Err(NodeWorkspaceRefusal::ObjectFormatMismatch);
        }
        if query.expected_head.is_none() || query.expected_commit != Some(self.commit) {
            return Err(error(SourceBrowseError::InvalidRequest(
                "historical browsing requires a head and the exact selected commit",
            )));
        }
        Ok(())
    }
}

impl OneNode {
    /// Read an exact historical tree/file through one current visible ref.
    ///
    /// The caller must have repository-wide local-owner read authority, as for
    /// `browse_source_local_in`. `expected_ref_tip` is the CURRENT ref tip;
    /// `commit` is the selected historical commit. The query must bind its
    /// `expected_head` and set `expected_commit` to `commit`. No argument grants
    /// object authority. A commit admitted on a different branch is unavailable
    /// unless a bounded parent-edge traversal from this tip reaches it.
    ///
    /// Canonical hidden refs are checked at the same selected authority head
    /// as the ancestry and tree. This does not implement historical policy,
    /// retention changes, arbitrary OID reads, or agent capability widening.
    /// Ancestry reads at most 4096 commits, 16384 parent edges and 16 MiB of
    /// commit bodies, with 64 KiB per commit. Its bytes also consume the normal
    /// source-read allowance. A budget/error/cancellation is never a short read.
    pub async fn browse_source_ancestor_local_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        expected_ref_tip: Oid,
        commit: Oid,
        query: &SourceBrowseQuery,
    ) -> Result<SourceBrowseReport, NodeWorkspaceRefusal> {
        let selection = Some(Selection { expected_ref_tip, commit });
        match self.object_format {
            Format::Sha1 => self.browse_local_format::<Sha1>(request, reference, query, selection).await,
            Format::Sha256 => self.browse_local_format::<Sha256>(request, reference, query, selection).await,
        }
    }
}

pub(super) struct Receipt {
    pub(super) body: Vec<u8>,
    pub(super) bytes: u64,
}

/// Every read remains in the authenticated selected closure and inherits the
/// request-owned database context. Tighten before fabric decode/allocation.
pub(super) fn select(
    source: &NodeTreeSource<'_>,
    request: &NodeRequestContext,
    tip: Oid,
    commit: Oid,
) -> Result<Receipt, NodeWorkspaceRefusal> {
    let mut read = |id: Oid, maximum: usize| {
        live(request)?;
        if !source.selected.closure().objects().contains(&id) {
            return Err(invalid_source());
        }
        let bounded = VerifiedFabricPackSource {
            maximum_object_bytes: source.inner.maximum_object_bytes.min(maximum),
            ..source.inner
        };
        let loaded = bounded.read_object(&id);
        live(request)?;
        loaded.map_err(|_| invalid_source())
    };
    walk(source.inner.object_format, tip, commit, Limits::default(), &mut read,
        &mut || live(request))
}

#[derive(Clone, Copy)]
struct Limits { commits: usize, edges: usize, bytes: usize, object_bytes: usize }
impl Default for Limits {
    fn default() -> Self {
        Self { commits: MAX_COMMITS, edges: MAX_EDGES,
            bytes: MAX_ANCESTRY_BYTES, object_bytes: MAX_COMMIT_BYTES }
    }
}

fn invalid_source() -> NodeWorkspaceRefusal {
    NodeWorkspaceRefusal::Object(read_refused("required ancestry is unavailable or invalid"))
}
fn budget(name: &'static str) -> NodeWorkspaceRefusal {
    error(SourceBrowseError::Budget(name))
}
fn parse_oid(bytes: &[u8], format: Format) -> Result<Oid, NodeWorkspaceRefusal> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid_source())?;
    let id = Oid::from_hex(format, &text.to_ascii_lowercase()).map_err(|_| invalid_source())?;
    if id.is_zero() { return Err(invalid_source()); }
    Ok(id)
}

/// Deterministic breadth-first traversal, retaining original parent order.
/// Success requires an actual verified path, not mere repository membership.
/// Non-reachability is reported only after the bounded traversal completes.
fn walk(
    format: Format,
    tip: Oid,
    wanted: Oid,
    limits: Limits,
    read: &mut impl FnMut(Oid, usize) -> Result<(ObjectType, Vec<u8>), NodeWorkspaceRefusal>,
    checkpoint: &mut impl FnMut() -> Result<(), NodeWorkspaceRefusal>,
) -> Result<Receipt, NodeWorkspaceRefusal> {
    checkpoint()?;
    if [tip, wanted].iter().any(|id| id.is_zero() || id.algorithm() != format) {
        return Err(NodeWorkspaceRefusal::ObjectFormatMismatch);
    }
    let mut seen = BTreeSet::from([tip]);
    let mut queue = VecDeque::from([tip]);
    let mut bytes = 0_usize;
    let mut edges = 0_usize;
    while let Some(id) = queue.pop_front() {
        checkpoint()?;
        if seen.len() > limits.commits { return Err(budget("historical commit count")); }
        let remaining = limits.bytes.checked_sub(bytes)
            .ok_or_else(|| budget("historical commit bytes"))?;
        let maximum = remaining.min(limits.object_bytes);
        if maximum == 0 { return Err(budget("historical commit bytes")); }
        let (kind, body) = read(id, maximum)?;
        checkpoint()?;
        if body.len() > maximum { return Err(budget("historical commit bytes")); }
        bytes = bytes.checked_add(body.len()).ok_or_else(|| budget("historical commit bytes"))?;
        if kind != ObjectType::Commit
            || fgit_crypto::git_object_id(format, GitObjectKind::Commit, &body) != id
        {
            return Err(invalid_source());
        }
        let parse = ParseLimits {
            max_object_bytes: maximum,
            max_header_lines: MAX_EDGES,
            tree_reference_bytes: format.digest_len(),
            ..ParseLimits::default()
        };
        let ParsedObject::Commit(parsed) = parse_object_body(ObjectType::Commit, &body,
            AcceptanceProfile::GitCompatibleImport, &parse).map_err(|_| invalid_source())?
        else { return Err(invalid_source()); };
        // Native identity alone does not disambiguate imported unusual headers.
        // Never choose one tree header or drop continuation bytes on graph edges.
        if parsed.headers().iter().filter(|header| header.name == b"tree").count() != 1
            || parsed.headers().iter().any(|header| (header.name == b"tree" || header.name == b"parent")
                && !header.continuations.is_empty())
        {
            return Err(invalid_source());
        }
        parse_oid(parsed.tree_reference().ok_or_else(invalid_source)?, format)?;
        let mut parents = Vec::new();
        for parent in parsed.parent_references() {
            checkpoint()?;
            edges = edges.checked_add(1).filter(|count| *count <= limits.edges)
                .ok_or_else(|| budget("historical parent edges"))?;
            parents.push(parse_oid(parent, format)?);
        }
        checkpoint()?;
        if id == wanted {
            return Ok(Receipt { body, bytes: bytes as u64 });
        }
        for parent in parents {
            checkpoint()?;
            if !seen.contains(&parent) {
                if seen.len() >= limits.commits { return Err(budget("historical commit count")); }
                seen.insert(parent);
                queue.push_back(parent);
            }
        }
    }
    checkpoint()?;
    Err(NodeWorkspaceRefusal::RefUnavailable)
}

#[cfg(test)]
mod tests;
