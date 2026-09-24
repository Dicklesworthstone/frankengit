//! Bounded transfer of complete local evidence and its proposal to a second
//! operator-selected journal. This is durable custody, not check publication.
use super::*;

impl FileCheckJournal {
    /// Transfer one FIFO batch and every referenced trusted job body. Before
    /// touching the destination, validate every completed fact against its exact
    /// evidence and cap the aggregate unique evidence bytes. Queued/InProgress
    /// facts need no body; command-only profiles are explicitly unsupported.
    ///
    /// The caller selects both private journals and authorizes this disclosure.
    /// No URL, destination, capability, or scope comes from repository text.
    /// After destination acceptance is durable, record the exact acknowledgement
    /// even if cancellation arrives. Failure before that point retains source
    /// custody. A partial destination evidence prefix is harmless and reusable;
    /// repeating a lost acceptance response deduplicates through the existing
    /// journal. No job is executed and no canonical check is asserted.
    pub fn transfer_next_trusted(
        &mut self,
        destination: &mut Self,
        maximum_evidence_bytes: usize,
        live: &dyn Fn() -> bool,
    ) -> Result<Option<CheckDeliveryAcknowledgement>, ObservationRefusal> {
        self.healthy()?;
        destination.healthy()?;
        if maximum_evidence_bytes == 0 || maximum_evidence_bytes > MAX_OBSERVATION_BYTES {
            return Err(ObservationRefusal::InvalidLimits);
        }
        if !live() { return Err(ObservationRefusal::Cancelled); }
        if self.scope.tenant != destination.scope.tenant
            || self.scope.repository != destination.scope.repository
            || self.scope.journal_id == destination.scope.journal_id
        {
            return Err(CheckDeliveryRefusal::ScopeMismatch.into());
        }
        // Check even the empty case: a stale in-memory index cannot declare
        // a truncated journal completely transferred.
        self.verify_checkpoint(self.pin())?;
        let Some(id) = self.pending.front().copied() else { return Ok(None); };
        let batch = self.read_retained_batch(id)?.batch;
        if !matches!(batch.execution_profile(), CoordinatorExecutionProfile::TrustedWorkflow { .. }) {
            return Err(ObservationRefusal::UnsupportedProfile);
        }
        let mut roots = BTreeSet::new();
        let mut total = 0usize;
        for fact in batch.facts() {
            if !live() { return Err(ObservationRefusal::Cancelled); }
            if fact.status != CheckRunStatus::Completed { continue; }
            let root = fact.receipt_commitment.ok_or(ObservationRefusal::EvidenceMissing)?;
            if roots.insert(root) {
                let frame = self.evidence.get(&root).ok_or(ObservationRefusal::EvidenceMissing)?;
                let length = frame.length.checked_sub(33).ok_or(CheckDeliveryRefusal::CorruptJournal)?;
                total = total.checked_add(length).ok_or(ObservationRefusal::RecordTooLarge)?;
                if total > maximum_evidence_bytes { return Err(ObservationRefusal::RecordTooLarge); }
            }
        }
        let mut bodies = BTreeMap::new();
        for root in roots {
            if !live() { return Err(ObservationRefusal::Cancelled); }
            bodies.insert(root, self.read_evidence(root)?);
        }
        for (index, fact) in batch.facts().iter().enumerate() {
            if fact.status != CheckRunStatus::Completed { continue; }
            let root = fact.receipt_commitment.ok_or(ObservationRefusal::EvidenceMissing)?;
            let bytes = bodies.get(&root).ok_or(ObservationRefusal::EvidenceMissing)?;
            // All semantic checks precede any destination write. A later bad
            // fact cannot smuggle an earlier part of an invalid batch across.
            verify_trusted_job(&batch, index, bytes, maximum_evidence_bytes, live)?;
        }
        for (root, bytes) in bodies {
            if !live() { return Err(ObservationRefusal::Cancelled); }
            destination.store_evidence(root, &bytes)?;
        }
        if !live() { return Err(ObservationRefusal::Cancelled); }
        let acknowledgement = destination.accept(&batch)?;
        // The accepting journal owns exact durable evidence now. Do not infer
        // non-acceptance from a late cancellation or drop this responsibility.
        self.record_delivery(acknowledgement)?;
        Ok(Some(acknowledgement))
    }
}
