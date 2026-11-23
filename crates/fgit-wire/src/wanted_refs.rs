//! Exact visible-name selectors and receipts for Git protocol-v2 fetch.
//!
//! The advertisement is the disclosure boundary. A general-purpose resolver
//! cannot widen it, and the response retains the exact name/object pair that
//! entered the pack wants. Only pack-producing responses emit these receipts.

use std::collections::HashSet;
use std::fmt;

use crate::request_ids::RequestObjectIds;
use crate::{
    AdvertisedRef, AnyGitOid, Packet, UploadPackRepository, WireError, WireLimits,
    add_output_packet, oid_hex, parse_advertised_ref_name, parse_ref_name,
};

#[derive(Clone, Default)]
pub(crate) struct WantedRefs {
    // Preserve first-seen request order; the set is only a membership index.
    requested: Vec<AdvertisedRef>,
    names: HashSet<Vec<u8>>,
    // Bounded positional index avoids both cloning all advertised names and
    // rescanning all refs for each request. Deterministic providers need not
    // already use lexicographic order, so we sort only these private offsets.
    advertised_order: Option<Vec<usize>>,
    response_bytes: usize,
}

// The randomized membership index is never an output-order authority, even
// in diagnostics from the publicly Debug-capable upload-pack machine.
impl fmt::Debug for WantedRefs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WantedRefs")
            .field("requested", &self.requested)
            .field("advertised_order", &self.advertised_order)
            .field("response_bytes", &self.response_bytes)
            .finish()
    }
}

impl WantedRefs {
    pub(crate) const fn len(&self) -> usize {
        self.requested.len()
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.requested.is_empty()
    }

    pub(crate) fn accept(
        &mut self,
        text: &[u8],
        repository: &impl UploadPackRepository,
        limits: &WireLimits,
        explicit_wants: usize,
        wants: &mut RequestObjectIds,
    ) -> Result<(), WireError> {
        if !repository.supports_ref_in_want() {
            return Err(WireError::PackSourceRefused);
        }
        repository.ref_in_want_checkpoint()?;
        let name = parse_ref_name(text, limits)?;
        if self.names.contains(&name) {
            return Err(WireError::DuplicateWantedRef { name });
        }
        if self.requested.len() >= limits.max_wants.saturating_sub(explicit_wants) {
            return Err(WireError::TooManyObjectIds {
                field: "want-ref",
                limit: limits.max_wants,
            });
        }
        self.prepare_index(repository, limits)?;
        let oid = self
            .lookup(repository, &name)
            .filter(|oid| repository.contains_want(*oid))
            .ok_or_else(|| WireError::UnknownWantedRef { name: name.clone() })?;
        if oid.algorithm() != repository.object_format() {
            return Err(WireError::ObjectFormatMismatch {
                expected: repository.object_format(),
                observed: oid.algorithm(),
            });
        }
        // Charge the complete future receipt before retaining its name. The
        // final response also charges ACK, shallow and packfile sections.
        let row_bytes = name
            .len()
            .saturating_add(oid.algorithm().digest_len() * 2 + 6);
        if row_bytes > limits.max_packet_bytes {
            return Err(WireError::PacketTooLarge {
                declared: row_bytes,
                limit: limits.max_packet_bytes,
            });
        }
        let prior = if self.requested.is_empty() {
            b"wanted-refs\n".len() + 4 + 4
        } else {
            self.response_bytes
        };
        if row_bytes > limits.max_outbound_bytes.saturating_sub(prior) {
            return Err(WireError::OutboundBytesExceeded {
                limit: limits.max_outbound_bytes,
            });
        }
        self.requested
            .try_reserve(1)
            .map_err(|_| WireError::AllocationFailure)?;
        self.names
            .try_reserve(1)
            .map_err(|_| WireError::AllocationFailure)?;
        let mut indexed_name = Vec::new();
        indexed_name
            .try_reserve_exact(name.len())
            .map_err(|_| WireError::AllocationFailure)?;
        indexed_name.extend_from_slice(&name);
        repository.ref_in_want_checkpoint()?;
        wants.insert("want", oid, limits.max_wants)?;
        self.names.insert(indexed_name);
        self.requested.push(AdvertisedRef { oid, name });
        self.response_bytes = prior + row_bytes;
        Ok(())
    }

    fn prepare_index(
        &mut self,
        repository: &impl UploadPackRepository,
        limits: &WireLimits,
    ) -> Result<(), WireError> {
        if self.advertised_order.is_some() {
            return Ok(());
        }
        let refs = repository.advertised_refs();
        if refs.len() > limits.max_advertised_refs {
            return Err(WireError::TooManyAdvertisedRefs {
                limit: limits.max_advertised_refs,
            });
        }
        let mut order = Vec::new();
        order
            .try_reserve_exact(refs.len())
            .map_err(|_| WireError::AllocationFailure)?;
        for (index, reference) in refs.iter().enumerate() {
            repository.ref_in_want_checkpoint()?;
            parse_advertised_ref_name(&reference.name, limits)?;
            if reference.oid.algorithm() != repository.object_format() {
                return Err(WireError::ObjectFormatMismatch {
                    expected: repository.object_format(),
                    observed: reference.oid.algorithm(),
                });
            }
            order.push(index);
        }
        order.sort_unstable_by(|&left, &right| refs[left].name.cmp(&refs[right].name));
        repository.ref_in_want_checkpoint()?;
        if order
            .windows(2)
            .any(|pair| refs[pair[0]].name == refs[pair[1]].name)
        {
            return Err(WireError::UnsortedOrDuplicateAdvertisement);
        }
        self.advertised_order = Some(order);
        Ok(())
    }

    fn lookup(&self, repository: &impl UploadPackRepository, name: &[u8]) -> Option<AnyGitOid> {
        let refs = repository.advertised_refs();
        let order = self.advertised_order.as_ref()?;
        if order.len() != refs.len() {
            return None;
        }
        let offset = order
            .binary_search_by(|&index| refs[index].name.as_slice().cmp(name))
            .ok()?;
        let reference = &refs[order[offset]];
        (reference.name == name).then_some(reference.oid)
    }

    /// Revalidate all saved pairs before producing even an ACK-only response.
    /// A caller substituting a different view cannot mix names from one
    /// snapshot with pack selection from another.
    pub(crate) fn validate(&self, repository: &impl UploadPackRepository) -> Result<(), WireError> {
        if self.is_empty() {
            return Ok(());
        }
        if !repository.supports_ref_in_want() {
            return Err(WireError::PackSourceRefused);
        }
        for reference in &self.requested {
            repository.ref_in_want_checkpoint()?;
            if self.lookup(repository, &reference.name) != Some(reference.oid)
                || reference.oid.algorithm() != repository.object_format()
                || !repository.contains_want(reference.oid)
            {
                return Err(WireError::PackSourceRefused);
            }
        }
        repository.ref_in_want_checkpoint()
    }

    pub(crate) fn append_response(
        &self,
        repository: &impl UploadPackRepository,
        output: &mut Vec<Packet>,
        used_bytes: &mut usize,
        limits: &WireLimits,
    ) -> Result<(), WireError> {
        if self.is_empty() {
            return Ok(());
        }
        append(output, b"wanted-refs\n".to_vec(), used_bytes, limits)?;
        for reference in &self.requested {
            repository.ref_in_want_checkpoint()?;
            let mut line = oid_hex(reference.oid).into_bytes();
            line.try_reserve(reference.name.len().saturating_add(2))
                .map_err(|_| WireError::AllocationFailure)?;
            line.push(b' ');
            line.extend_from_slice(&reference.name);
            line.push(b'\n');
            append(output, line, used_bytes, limits)?;
        }
        repository.ref_in_want_checkpoint()?;
        add_output_packet(output, Packet::Delimiter, 4, used_bytes, limits)
    }
}

fn append(
    output: &mut Vec<Packet>,
    line: Vec<u8>,
    used_bytes: &mut usize,
    limits: &WireLimits,
) -> Result<(), WireError> {
    let bytes = line.len() + 4;
    if bytes > limits.max_packet_bytes {
        return Err(WireError::PacketTooLarge {
            declared: bytes,
            limit: limits.max_packet_bytes,
        });
    }
    add_output_packet(output, Packet::Data(line), bytes, used_bytes, limits)
}
