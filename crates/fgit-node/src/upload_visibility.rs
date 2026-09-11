//! Exact-head disclosure for the production upload-pack transport.
//!
//! Cumulative admission proves storage provenance, not current disclosure.
//! Derive one complete visible native graph before negotiation, then use that
//! same private proof for wants, ACKs, and pack selection. Never narrow or
//! rewrite the canonical per-decision closure or the trusted local exporter.
use super::*;

const MAX_DISCLOSURE_EDGES: usize = 4_000_000;
const DISCLOSURE_OPERATION: &str = "verify visible upload-pack graph";

/// Constructible only after the entire selected graph has been checked.
/// The derived set is not an RCR root and is deliberately not persisted.
pub(super) struct VisibleUploadPack {
    basis: PublicationBasis,
    closure: PermittedObjectClosure,
    repository: AdmissionUploadPackRepository,
}

impl VisibleUploadPack {
    pub(super) fn repository(&self) -> &AdmissionUploadPackRepository {
        &self.repository
    }

    pub(super) fn closure_for(
        &self,
        materialized: &MaterializedAdmission,
    ) -> Result<&PermittedObjectClosure, NodePackMaterializationRefusal> {
        if self.basis != *materialized.basis() {
            return Err(disclosure_refusal(RefusalCode::AuthorityReceiptStale));
        }
        Ok(&self.closure)
    }
}

impl OneNode {
    pub(super) fn prepare_visible_upload_pack(
        &self,
        request: &NodeRequestContext,
        materialized: &MaterializedAdmission,
        limits: &WireLimits,
        deadline: &GitDaemonSessionDeadline,
    ) -> Result<VisibleUploadPack, NodeGitDaemonServeRefusal> {
        deadline.check(DISCLOSURE_OPERATION)?;
        let repository = AdmissionUploadPackRepository::from_snapshot(
            materialized.snapshot(),
            self.object_format,
            limits,
        )
        .map_err(NodeAdmissionViewRefusal::from)?;
        let exhaustion = Cell::new(None);
        let live = || !deadline.expired();
        let source = VerifiedFabricPackSource {
            fabric: &self.fabric,
            object_format: self.object_format,
            maximum_object_bytes: self
                .selected_pack_limits
                .max_object_bytes
                .min(usize::try_from(self.max_object_bytes).unwrap_or(usize::MAX)),
            database_context: request.authority(),
            database_exhaustion: &exhaustion,
            session_is_live: Some(&live),
        };
        let closure = project_visible_closure(
            &source,
            materialized.selected_closure().closure(),
            repository
                .advertised_refs()
                .iter()
                .map(|reference| reference.oid),
            &self.selected_pack_limits,
        );
        // Preserve the established outer-session > Database > object-refusal
        // precedence, including a deadline crossed inside an immutable read.
        deadline.check(DISCLOSURE_OPERATION)?;
        if let Some(dimension) = exhaustion.get() {
            return Err(NodePackMaterializationRefusal::BudgetClassExhausted {
                class: BudgetClass::Database,
                dimension,
                operation: DISCLOSURE_OPERATION,
            }
            .into());
        }
        let closure = closure?;
        let repository = repository.with_closure_objects(closure.objects().clone());
        Ok(VisibleUploadPack {
            basis: materialized.basis().clone(),
            closure,
            repository,
        })
    }
}

fn disclosure_refusal(code: RefusalCode) -> NodePackMaterializationRefusal {
    NodePackMaterializationRefusal::DisclosureGraph(code)
}

/// The production implementation always returns native-verified immutable
/// bodies. The narrow seam allows budget and read-set assertions in tests.
trait VisibilitySource {
    fn format(&self) -> GitHashAlgorithm;
    fn parse_limits(&self) -> ParseLimits;
    fn checkpoint(&self) -> Result<(), NodePackMaterializationRefusal>;
    fn load(&self, id: GitOid) -> Result<(ObjectType, Vec<u8>), NodePackMaterializationRefusal>;
}

impl VisibilitySource for VerifiedFabricPackSource<'_> {
    fn format(&self) -> GitHashAlgorithm {
        self.object_format
    }
    fn parse_limits(&self) -> ParseLimits {
        VerifiedFabricPackSource::parse_limits(self)
    }
    fn checkpoint(&self) -> Result<(), NodePackMaterializationRefusal> {
        self.session_checkpoint()?;
        if !self.database_read_is_live() {
            return Err(PackWriteError::from(PackError::DeadlineExceeded).into());
        }
        Ok(())
    }
    fn load(&self, id: GitOid) -> Result<(ObjectType, Vec<u8>), NodePackMaterializationRefusal> {
        self.read_object(&id)
            .map_err(NodePackMaterializationRefusal::from)
    }
}

fn project_visible_closure(
    source: &impl VisibilitySource,
    admitted: &PermittedObjectClosure,
    roots: impl IntoIterator<Item = GitOid>,
    limits: &PackLimits,
) -> Result<PermittedObjectClosure, NodePackMaterializationRefusal> {
    source.checkpoint()?;
    let maximum = usize::try_from(limits.max_entries).unwrap_or(usize::MAX);
    let mut required = BTreeMap::<GitOid, Option<ObjectType>>::new();
    let mut pending = BTreeSet::new();
    let mut known = BTreeMap::<GitOid, ObjectType>::new();
    // Validate ALL roots before a read. A visible ref outside the authenticated
    // admitted set is inconsistent state, never permission to search storage.
    for root in roots {
        source.checkpoint()?;
        enqueue(
            source.format(),
            admitted,
            root,
            None,
            maximum,
            &mut required,
            &mut pending,
        )?;
    }
    let mut bytes = 0_usize;
    let mut edges_left = limits.max_total_expanded_bytes.min(MAX_DISCLOSURE_EDGES);
    let parse_limits = source.parse_limits();
    while let Some(id) = pending.pop_first() {
        source.checkpoint()?;
        let loaded = source.load(id);
        source.checkpoint()?;
        let (kind, body) = loaded?;
        if body.len() > limits.max_object_bytes || body.len() > parse_limits.max_object_bytes {
            return Err(disclosure_refusal(RefusalCode::ResourceBudgetExceeded));
        }
        bytes = bytes
            .checked_add(body.len())
            .ok_or_else(|| disclosure_refusal(RefusalCode::ResourceBudgetExceeded))?;
        if bytes > limits.max_total_expanded_bytes {
            return Err(disclosure_refusal(RefusalCode::ResourceBudgetExceeded));
        }
        if let Some(Some(expected)) = required.get(&id) {
            require_kind(kind, *expected)?;
        }
        // Blobs have no local edges. Avoid a second full-body parsed copy.
        let edges = if kind == ObjectType::Blob {
            Vec::new()
        } else {
            let parsed = parse_object_body(
                kind,
                &body,
                AcceptanceProfile::GitCompatibleImport,
                &parse_limits,
            );
            source.checkpoint()?;
            let parsed =
                parsed.map_err(|_| disclosure_refusal(RefusalCode::ObjectHeaderInvalid))?;
            let mut stopped = None;
            let edges = crate::loose_import::graph::references(
                source.format(),
                &parsed,
                &body,
                &parse_limits,
                &mut edges_left,
                &mut || {
                    if stopped.is_some() {
                        return false;
                    }
                    match source.checkpoint() {
                        Ok(()) => true,
                        Err(error) => {
                            stopped = Some(error);
                            false
                        }
                    }
                },
            );
            // A later successful probe cannot erase an already observed stop.
            if let Some(error) = stopped {
                return Err(error);
            }
            source.checkpoint()?;
            edges.map_err(disclosure_refusal)?
        };
        known.insert(id, kind);
        for (child, expected) in edges {
            source.checkpoint()?;
            // Every edge is checked, including one into an already loaded root.
            if let Some(actual) = known.get(&child) {
                require_kind(*actual, expected)?;
            }
            enqueue(
                source.format(),
                admitted,
                child,
                Some(expected),
                maximum,
                &mut required,
                &mut pending,
            )?;
        }
    }
    source.checkpoint()?;
    Ok(PermittedObjectClosure::new(known.into_keys().collect()))
}

fn enqueue(
    format: GitHashAlgorithm,
    admitted: &PermittedObjectClosure,
    id: GitOid,
    expected: Option<ObjectType>,
    maximum: usize,
    required: &mut BTreeMap<GitOid, Option<ObjectType>>,
    pending: &mut BTreeSet<GitOid>,
) -> Result<(), NodePackMaterializationRefusal> {
    if id.is_zero() || id.algorithm() != format {
        return Err(disclosure_refusal(RefusalCode::ObjectHeaderInvalid));
    }
    if !admitted.objects().contains(&id) {
        return Err(disclosure_refusal(RefusalCode::ObjectClosureIncomplete));
    }
    if let Some(previous) = required.get_mut(&id) {
        if let (Some(first), Some(next)) = (*previous, expected) {
            require_kind(first, next)?;
        }
        if previous.is_none() {
            *previous = expected;
        }
        return Ok(());
    }
    // Count on enqueue, not dequeue: a broad frontier is bounded as well as
    // the completed set. Duplicate edges cannot repeatedly grow either set.
    if required.len() >= maximum {
        return Err(disclosure_refusal(RefusalCode::ResourceBudgetExceeded));
    }
    required.insert(id, expected);
    pending.insert(id);
    Ok(())
}

fn require_kind(
    actual: ObjectType,
    expected: ObjectType,
) -> Result<(), NodePackMaterializationRefusal> {
    if actual == expected {
        Ok(())
    } else {
        Err(disclosure_refusal(RefusalCode::EvidenceInvalid))
    }
}

#[cfg(test)]
mod tests;
