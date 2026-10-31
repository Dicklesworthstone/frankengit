//! Explicit source-import size profiles over the same native admission path.
//! Limits govern work and private custody, never transaction identity or truth.
use super::{
    ImportControl, LooseGitImportRefusal, StagedLooseGitImport, checkpoint_request, graph,
};
use crate::receive_staging::ReceiveStaging;
use crate::{NodeRequestContext, NodeSourceImportRefusal, OneNode};
use fgit_admission::{
    AdmissionContext, AdmissionLimits, AdmissionResult, SourceImportOrigin, SourceImportReceipt,
    SourceRefUpdate, ValidatedClosure, permitted_object_closure_root, validate_source_import,
};
use fgit_authority::IdempotencyKey;
use fgit_types::cell::admits_staging_intake;
use fgit_types::{GitHashAlgorithm, GitOid, GitOidSha1, GitOidSha256, PrincipalId, RefusalCode};
use std::path::Path;

pub(super) fn validate_limit(maximum: u64) -> Result<(), LooseGitImportRefusal> {
    if maximum == 0 || usize::try_from(maximum).is_err() {
        return Err(super::control::interrupted(
            RefusalCode::ResourceBudgetExceeded,
        ));
    }
    if maximum > graph::MAX_EXPLICIT_OBJECT_BYTES {
        return Err(LooseGitImportRefusal::TotalObjectBytesExceeded {
            limit: graph::MAX_EXPLICIT_OBJECT_BYTES,
            observed: maximum,
        });
    }
    Ok(())
}

impl OneNode {
    pub(super) fn stage_import_profile_in(
        &self,
        request: &NodeRequestContext,
        source: &Path,
        max_refs: usize,
        maximum_bytes: u64,
        staging: Option<&ReceiveStaging>,
    ) -> Result<StagedLooseGitImport, LooseGitImportRefusal> {
        let mut stopped = None;
        let mut live = || match checkpoint_request(request) {
            Ok(()) => true,
            Err(error) => {
                stopped = Some(error);
                false
            }
        };
        let result = {
            let control = ImportControl::new(&mut live);
            let result = self.stage_loose_git_import_controlled(
                source,
                max_refs,
                maximum_bytes,
                &control,
                staging,
            );
            control.after(result, |error| error)
        };
        if matches!(&result, Err(LooseGitImportRefusal::Node(error))
            if matches!(**error, crate::NodeRefusal::ResourceContainment))
        {
            return result;
        }
        match stopped {
            Some(error) => Err(error),
            None => result,
        }
    }

    /// Import under an explicit native-body ceiling without weakening the
    /// per-object, packed-input, graph, source-kind or canonical publication rules.
    /// The original caller context covers validation, spool custody, placement
    /// and admission. No context is replenished here. Use the matching context
    /// factory before calling; deliberately smaller or cancelled contexts remain
    /// authoritative. The size limit is local work policy, not sealed identity.
    pub async fn import_loose_git_directory_with_byte_limit_durable_in(
        &self,
        request: &NodeRequestContext,
        source: &Path,
        principal_id: PrincipalId,
        idempotency_key: &[u8],
        maximum_bytes: u64,
    ) -> Result<AdmissionResult, NodeSourceImportRefusal> {
        validate_limit(maximum_bytes)
            .map_err(|error| NodeSourceImportRefusal::Staging(Box::new(error)))?;
        // The same intake question the receive transport asks, at the one
        // production site that reaches this crate from outside: `fg import`.
        // A source import reads a local tree and PUBLISHES its refs, so a cell
        // nobody brought into service must refuse it for exactly the reason it
        // refuses a push. Raised before the source is read, so an unserving
        // cell stages nothing.
        //
        // There is no staging-only middle response here. §22.6's middle
        // response exists because a receive-pack session has already spent the
        // bytes by the time publication is decided; a local directory has not
        // been consumed and can simply be re-offered, so holding it would
        // create staged state with no client waiting on it.
        admits_staging_intake(self.cell_state()).map_err(NodeSourceImportRefusal::CellState)?;
        let idempotency_key = IdempotencyKey::new(idempotency_key.to_vec())
            .map_err(|error| NodeSourceImportRefusal::Idempotency(Box::new(error)))?;
        let limits = AdmissionLimits::default();
        let staging = ReceiveStaging::default();
        let staged = self
            .stage_import_profile_in(
                request,
                source,
                limits.command_limit(true),
                maximum_bytes,
                Some(&staging),
            )
            .map_err(|error| NodeSourceImportRefusal::Staging(Box::new(error)))?;
        let object_count = u32::try_from(staged.object_count()).map_err(|_| {
            NodeSourceImportRefusal::ObjectCountOutOfRange {
                count: staged.object_count(),
            }
        })?;
        let closure = ValidatedClosure {
            object_closure_root: permitted_object_closure_root(staged.closure())
                .map_err(NodeSourceImportRefusal::ClosureRoot)?,
            objects: staged.closure().objects().clone(),
        };
        let absent = match self.object_format {
            GitHashAlgorithm::Sha1 => GitOid::Sha1(GitOidSha1::ZERO),
            GitHashAlgorithm::Sha256 => GitOid::Sha256(GitOidSha256::ZERO),
        };
        let updates = staged
            .refs()
            .refs()
            .iter()
            .map(|(name, new)| SourceRefUpdate {
                old: absent,
                new: *new,
                ref_name: name.as_bytes().to_vec(),
            })
            .collect::<Vec<_>>();
        let receipt = SourceImportReceipt {
            object_format: self.object_format,
            object_count,
            delete_only: updates.iter().all(|update| update.new.is_zero()),
            origin: SourceImportOrigin::LocalGitDirectory,
        };
        let validated = validate_source_import(&updates, &receipt, closure)
            .map_err(NodeSourceImportRefusal::Validation)?;
        let context = AdmissionContext {
            head_key: self.head_key.clone(),
            tenant_id: self.tenant_id,
            repository_id: self.repository_id,
            principal_id,
            idempotency_key,
            object_format: self.object_format,
        };
        // The caller's deadline covers source work AND publication. Do not
        // detach admission with a fresh budget after expensive preparation.
        checkpoint_request(request)
            .map_err(|error| NodeSourceImportRefusal::Staging(Box::new(error)))?;
        self.admit_validated_source_import_publishing_in(
            request,
            &context,
            &validated,
            limits,
            Some(&staging),
        )
        .await
        .map_err(|error| NodeSourceImportRefusal::Admission(Box::new(error)))
    }
}

#[cfg(test)]
mod tests;
