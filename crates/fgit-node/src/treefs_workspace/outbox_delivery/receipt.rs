//! Read terminal evidence through the authenticated removal, without a sender.

use fgit_admission::merge::native::{delivery, history};
use fgit_codec::{CanonicalOutboxDeliveryReceipt, CanonicalOutboxEffectState};
use fgit_types::cell::{ReadMode, admits_read};
use fgit_types::{AsciiSlug, RepositoryAuthorityHeadId};

use super::selection::{ForgeDeliveryReadRefusal, checkpoint};
use crate::{NodeRequestContext, OneNode, read_evidence_body_in};

/// Original terminal outcome selected by a verified outbox-removal decision.
/// This value is evidence for inspection, never a capability to send again.
#[derive(Debug)]
pub struct RetiredForgeDeliveryReceipt {
    source_head: RepositoryAuthorityHeadId,
    effect: CanonicalOutboxEffectState,
    receipt: CanonicalOutboxDeliveryReceipt,
}

impl RetiredForgeDeliveryReceipt {
    #[must_use]
    pub const fn source_head(&self) -> RepositoryAuthorityHeadId {
        self.source_head
    }

    #[must_use]
    pub const fn effect(&self) -> &CanonicalOutboxEffectState {
        &self.effect
    }

    #[must_use]
    pub const fn receipt(&self) -> &CanonicalOutboxDeliveryReceipt {
        &self.receipt
    }
}

impl OneNode {
    /// Recover the original receipt of a retired native forge delivery, with
    /// no transport capability, probe, send, or authority write. An active or
    /// unknown key refuses; map absence alone cannot establish completion.
    /// The existing bounded authenticated-history limits apply. A pinned head
    /// must match this read's immutable basis; later publication does not mix
    /// newer state into the result. This trusted-local read grants no replay.
    pub async fn read_retired_forge_receipt_in(
        &self,
        request: &NodeRequestContext,
        key: AsciiSlug,
        destination: AsciiSlug,
        expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<RetiredForgeDeliveryReceipt, ForgeDeliveryReadRefusal> {
        checkpoint(request)?;
        admits_read(self.cell_state(), ReadMode::Current)
            .map_err(ForgeDeliveryReadRefusal::Cell)?;
        let selected = self
            .materialize_admission_in(request)
            .await
            .map_err(|error| ForgeDeliveryReadRefusal::Authority(Box::new(error)))?;
        if expected_head.is_some_and(|head| head != selected.basis().id()) {
            return Err(ForgeDeliveryReadRefusal::SnapshotMoved);
        }
        let cancelled = || checkpoint(request).is_err();
        let effect = history::retired_effect(
            &self.authority,
            request.authority(),
            selected.basis(),
            key,
            destination,
            &cancelled,
        )
        .await
        .map_err(|error| ForgeDeliveryReadRefusal::Admission(Box::new(error)))?
        .ok_or(ForgeDeliveryReadRefusal::MissingDelivery)?;
        let receipt = read_evidence_body_in(
            &self.authority,
            request.authority(),
            self.repository_id,
            delivery::RECEIPT_NAMESPACE,
            effect
                .evidence_root()
                .ok_or(ForgeDeliveryReadRefusal::MissingDelivery)?,
            &cancelled,
        )
        .await
        .map_err(|error| ForgeDeliveryReadRefusal::Authority(Box::new(error)))?;
        checkpoint(request)?;
        Ok(RetiredForgeDeliveryReceipt {
            source_head: selected.basis().id(),
            effect,
            receipt,
        })
    }
}
