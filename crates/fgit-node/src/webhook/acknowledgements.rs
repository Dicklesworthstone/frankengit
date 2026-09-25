//! Bounded, process-local evidence of an observed HTTP acknowledgement.
//!
//! This is not a receiver-side idempotency contract. A miss, eviction, poisoned
//! mutex, or restart means Unknown, never NotDelivered. Public diagnostics are
//! deliberately not an input to this cache.

use std::collections::VecDeque;

use fgit_forge::webhook::{WebhookId, WebhookRegistration};
use fgit_types::{AsciiSlug, Digest};

use super::DeliveryRequest;

pub(super) const MAX_ACKNOWLEDGEMENTS: usize = 1024;
const MAX_ACK_URL_BYTES: usize = 8 * 1024;

#[derive(Debug)]
struct Acknowledgement {
    key: AsciiSlug,
    destination: AsciiSlug,
    payload_root: Digest,
    webhook_id: WebhookId,
    target_url: String,
}

impl Acknowledgement {
    fn matches(&self, request: &DeliveryRequest<'_>, registration: &WebhookRegistration) -> bool {
        self.key == request.key
            && self.destination == request.destination
            && self.payload_root == request.payload_root
            && self.webhook_id == registration.id
            && self.target_url == registration.url.raw()
    }
}

#[derive(Debug, Default)]
pub(super) struct Acknowledgements<const N: usize = MAX_ACKNOWLEDGEMENTS> {
    entries: VecDeque<Acknowledgement>,
}

impl<const N: usize> Acknowledgements<N> {
    pub(super) fn contains(
        &self,
        request: &DeliveryRequest<'_>,
        registration: &WebhookRegistration,
    ) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.matches(request, registration))
    }

    /// Remember only an already-observed final 2xx response. Failure to cache
    /// optional evidence must not turn that definitive ACK into a failed send.
    pub(super) fn remember(
        &mut self,
        request: &DeliveryRequest<'_>,
        registration: &WebhookRegistration,
    ) -> bool {
        if N == 0 || registration.url.raw().len() > MAX_ACK_URL_BYTES {
            return false;
        }
        if let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.matches(request, registration))
        {
            // Retries refresh the same receipt without increasing storage or
            // allowing repeated keys to displace unrelated recent receipts.
            if let Some(entry) = self.entries.remove(index) {
                self.entries.push_back(entry);
                return true;
            }
            return false;
        }

        let mut target_url = String::new();
        if target_url
            .try_reserve_exact(registration.url.raw().len())
            .is_err()
        {
            return false;
        }
        target_url.push_str(registration.url.raw());
        if self.entries.len() < N {
            if self.entries.try_reserve(1).is_err() {
                return false;
            }
        } else {
            let _ = self.entries.pop_front();
        }
        self.entries.push_back(Acknowledgement {
            key: request.key,
            destination: request.destination,
            payload_root: request.payload_root,
            webhook_id: registration.id,
            target_url,
        });
        true
    }
}

#[cfg(test)]
mod tests;
