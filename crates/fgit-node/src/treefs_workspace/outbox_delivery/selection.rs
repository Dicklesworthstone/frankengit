//! Read-only selection for operator-driven delivery. No send or settlement is
//! inferred from a local queue, an object listing, or a staged event body.

use fgit_admission::merge::native::{delivery, settlement::DeliveryRequest};
use fgit_codec::CanonicalOutboxStateEntry;
use fgit_forge::ForgeEventBatch;
use fgit_types::cell::{CellRefusal, ReadMode, admits_read};
use fgit_types::{AsciiSlug, RepositoryAuthorityHeadId};

use crate::{
    ADMISSION_FORGE_EVENT_BATCH_KEY_PREFIX, AdmissionMaterializationRefusal, NodeRequestContext,
    OneNode, PackContextCheckpoint, checkpoint_pack_context, read_evidence_body_in,
};

/// A selection failure never constitutes a transport or settlement observation.
#[derive(Debug)]
pub enum ForgeDeliveryReadRefusal {
    InvalidLimit,
    MissingDelivery,
    DestinationMismatch,
    UnsupportedEffectClass,
    SnapshotMoved,
    Cancelled,
    BudgetExceeded,
    Cell(CellRefusal),
    Authority(Box<AdmissionMaterializationRefusal>),
    Admission(Box<fgit_admission::AdmissionError>),
}

impl std::fmt::Display for ForgeDeliveryReadRefusal {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "forge delivery selection refused: {self:?}")
    }
}
impl std::error::Error for ForgeDeliveryReadRefusal {}

/// A page of retained obligations, including those already settled. This is
/// not a mutable pending queue. Pin `source_head` when walking several pages.
#[derive(Clone, Debug)]
pub struct ForgeOutboxPage {
    pub source_head: RepositoryAuthorityHeadId,
    pub entries: Vec<CanonicalOutboxStateEntry>,
    pub next_after: Option<AsciiSlug>,
}

/// An owned, immutable payload read through the authenticated outbox root.
/// Private fields prevent a caller from constructing a selection from a key
/// and unverified events. Reading this value grants no automatic retry rights.
pub struct SelectedForgeDelivery {
    source_head: RepositoryAuthorityHeadId,
    entry: CanonicalOutboxStateEntry,
    events: ForgeEventBatch,
}

impl SelectedForgeDelivery {
    #[must_use]
    pub const fn source_head(&self) -> RepositoryAuthorityHeadId {
        self.source_head
    }

    #[must_use]
    pub fn entry(&self) -> &CanonicalOutboxStateEntry {
        &self.entry
    }

    /// Preserve every original outbox parameter, including its destination and
    /// payload commitment. A transport must not retarget the selected request.
    #[must_use]
    pub fn as_request(&self) -> DeliveryRequest<'_> {
        DeliveryRequest {
            key: self.entry.delivery_key(),
            destination: self.entry.destination(),
            payload_root: self.entry.payload_root(),
            events: &self.events,
        }
    }
}

fn checkpoint(request: &NodeRequestContext) -> Result<(), ForgeDeliveryReadRefusal> {
    match checkpoint_pack_context(request.authority()) {
        PackContextCheckpoint::Live => Ok(()),
        PackContextCheckpoint::Stopped {
            budget_exhaustion: Some(_),
        } => Err(ForgeDeliveryReadRefusal::BudgetExceeded),
        PackContextCheckpoint::Stopped {
            budget_exhaustion: None,
        } => Err(ForgeDeliveryReadRefusal::Cancelled),
    }
}

impl OneNode {
    async fn selected_forge_outbox_in(
        &self,
        request: &NodeRequestContext,
        expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<(RepositoryAuthorityHeadId, delivery::DeliveryState), ForgeDeliveryReadRefusal>
    {
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
        let state = delivery::read_in(
            &self.authority,
            request.authority(),
            selected.basis(),
            &|| checkpoint(request).is_err(),
        )
        .await
        .map_err(|error| ForgeDeliveryReadRefusal::Admission(Box::new(error)))?;
        checkpoint(request)?;
        Ok((selected.basis().id(), state))
    }

    /// List retained canonical deliveries in their codec-defined key order.
    /// This trusted-local metadata read neither contacts a destination nor
    /// acknowledges anything. The page is bounded; the existing whole-outbox
    /// verification cost and storage limits remain in force.
    pub async fn read_forge_outbox_in(
        &self,
        request: &NodeRequestContext,
        after: Option<AsciiSlug>,
        limit: u16,
        expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<ForgeOutboxPage, ForgeDeliveryReadRefusal> {
        if !(1..=100).contains(&limit) {
            return Err(ForgeDeliveryReadRefusal::InvalidLimit);
        }
        let (source_head, state) = self
            .selected_forge_outbox_in(request, expected_head)
            .await?;
        let mut entries: Vec<_> = state
            .outbox
            .entries()
            .iter()
            .filter(|entry| after.is_none_or(|key| entry.delivery_key() > key))
            .take(usize::from(limit) + 1)
            .cloned()
            .collect();
        let more = entries.len() > usize::from(limit);
        entries.truncate(usize::from(limit));
        let next_after = if more {
            entries.last().map(CanonicalOutboxStateEntry::delivery_key)
        } else {
            None
        };
        checkpoint(request)?;
        Ok(ForgeOutboxPage {
            source_head,
            entries,
            next_after,
        })
    }

    /// Resolve a native canonical event batch for one retained delivery key.
    /// The caller explicitly binds the configured transport audience. Missing,
    /// corrupt, legacy non-native, or differently addressed payloads refuse;
    /// no replacement empty batch or payload root is invented.
    ///
    /// This is a read-only operator boundary, not an automatic worker. Generic
    /// HTTP delivery remains weakly idempotent and cannot enter the separate
    /// strong-idempotency settlement driver. An explicit manual send can be
    /// repeated and does not settle the source obligation.
    pub async fn select_forge_delivery_in(
        &self,
        request: &NodeRequestContext,
        key: AsciiSlug,
        expected_destination: AsciiSlug,
        expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<SelectedForgeDelivery, ForgeDeliveryReadRefusal> {
        let (source_head, state) = self
            .selected_forge_outbox_in(request, expected_head)
            .await?;
        let entry = state
            .outbox
            .entry(key)
            .ok_or(ForgeDeliveryReadRefusal::MissingDelivery)?;
        if entry.destination() != expected_destination {
            return Err(ForgeDeliveryReadRefusal::DestinationMismatch);
        }
        if entry.effect_class() != AsciiSlug::from_static("forge-event") {
            return Err(ForgeDeliveryReadRefusal::UnsupportedEffectClass);
        }
        let events: ForgeEventBatch = read_evidence_body_in(
            &self.authority,
            request.authority(),
            self.repository_id,
            ADMISSION_FORGE_EVENT_BATCH_KEY_PREFIX,
            entry.payload_root(),
            &|| checkpoint(request).is_err(),
        )
        .await
        .map_err(|error| ForgeDeliveryReadRefusal::Authority(Box::new(error)))?;
        checkpoint(request)?;
        Ok(SelectedForgeDelivery {
            source_head,
            entry: entry.clone(),
            events,
        })
    }
}

#[cfg(test)]
mod tests;
