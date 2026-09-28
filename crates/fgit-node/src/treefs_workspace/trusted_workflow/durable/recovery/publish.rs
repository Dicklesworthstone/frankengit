//! Select one completed saved job for the existing canonical publisher.
//! Reading custody does not execute a workflow or acknowledge its delivery.

use std::path::Path;

use fgit_crypto::Digest;
use fgit_forge::event::workflow_check::{MAX_CHECK_EVIDENCE_BYTES, WorkflowCheckRecord};
use fgit_types::{RefName, RepositoryId, TenantId};

use super::TrustedWorkflowFailure;
use super::inspect::{checked_pin, checked_root, checked_scope, failure};
use crate::OneNode;

impl OneNode {
    /// Recover a publication record from one exact completed job in a saved
    /// trusted-local run. `expected` is (tenant, repository, original attempt
    /// marker digest); `minimum` is an independently retained journal pin.
    /// `batch` is an accepted batch digest and `fact_index` is its zero-based
    /// fact index. Neither selects an arbitrary evidence file or journal offset.
    ///
    /// The original private marker and journal are reopened once using the
    /// existing custody boundary. Under that same exclusive journal lock, the
    /// reader checks the completed fact, its referenced evidence size before
    /// allocating that body, and its exact native source/run/attempt/job/graph
    /// binding. Selected evidence is limited to the canonical check profile's
    /// 1 MiB envelope, independently of the larger bounded journal-open profile.
    ///
    /// `source_ref` is the explicit reporting branch. A running node and its
    /// authenticated publisher must still call `admit_trusted_workflow_check_in`
    /// to verify current repository authority and publish. This loader requires
    /// no source repository or final report and neither executes code, settles
    /// delivery, removes custody nor manufactures a successful check. As with
    /// other trusted custody reads, parent paths must be stable/private; hostile
    /// replacement by the same host UID is outside this execution profile.
    pub fn trusted_workflow_check_record(
        directory: &Path,
        expected: (TenantId, RepositoryId, Digest),
        minimum: Option<(u64, Digest)>,
        batch: Digest,
        fact_index: usize,
        source_ref: RefName,
        live: &dyn Fn() -> bool,
    ) -> Result<WorkflowCheckRecord, TrustedWorkflowFailure> {
        if !live() {
            return Err(failure(directory, "workflow check selection cancelled"));
        }
        if !source_ref.as_bytes().starts_with(b"refs/heads/") {
            return Err(TrustedWorkflowFailure::InvalidInput(
                "workflow check reporting source must be a branch ref",
            ));
        }
        let expected = checked_scope(expected)?;
        let minimum = minimum.map(checked_pin).transpose()?;
        let batch = checked_root(batch)?;
        let mut journal = Self::open_trusted_workflow_journal(directory, expected, minimum, live)?;
        let snapshot = journal.pin();
        // This reader checks the indexed evidence length BEFORE allocating it.
        // It also verifies the exact completed fact and all typed execution
        // coordinates. Drop its decoded report before rereading the bytes.
        journal
            .read_trusted_job(snapshot, batch, fact_index, MAX_CHECK_EVIDENCE_BYTES, live)
            .map_err(|error| failure(directory, error))?;
        let selected = journal
            .read_retained_batch(batch)
            .map_err(|error| failure(directory, error))?;
        let evidence_id = selected
            .batch()
            .facts()
            .get(fact_index)
            .and_then(|fact| fact.receipt_commitment)
            .ok_or_else(|| failure(directory, "completed workflow fact has no evidence"))?;
        if !live() {
            return Err(failure(directory, "workflow check selection cancelled"));
        }
        // The same locked journal retains the immutable frame coordinates whose
        // size was just bounded above. Reopening or listing files here would
        // discard that selection and permit an independent oversized read.
        let evidence = journal
            .read_evidence(evidence_id)
            .map_err(|error| failure(directory, error))?;
        Self::workflow_check_record_from_batch(
            source_ref,
            selected.batch(),
            fact_index,
            &evidence,
            live,
        )
        .map_err(|error| failure(directory, error))
    }
}
