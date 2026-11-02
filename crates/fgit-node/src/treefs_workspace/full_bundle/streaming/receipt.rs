//! Distinct construction evidence behind the common streamed export view.

use fgit_pack::full_bundle::stream::StreamFullBundleReceipt;
use fgit_pack::full_bundle::stream::existing::ExistingPackBundleReceipt;
use fgit_types::{GitHashAlgorithm, GitOid};

use crate::ReceivedPackReceipt;

/// Whether the caller enabled optional verified representation reuse, and
/// whether an eligible representation was selected before any output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamBundleReuse {
    NotRequested,
    Miss,
    Reused,
}

/// Complete bundle output with the exact kind of construction evidence kept
/// separate. A received representation is not an encoder receipt, deterministic
/// object ordering, or a claim that omitted prerequisite bodies were emitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamBundleExportReceipt {
    evidence: Evidence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Evidence {
    Encoded(StreamFullBundleReceipt),
    Received {
        pack: ReceivedPackReceipt,
        framing: ExistingPackBundleReceipt,
    },
}

impl StreamBundleExportReceipt {
    pub(super) const fn from_encoded(receipt: StreamFullBundleReceipt) -> Self {
        Self {
            evidence: Evidence::Encoded(receipt),
        }
    }

    pub(super) const fn from_received(
        pack: ReceivedPackReceipt,
        framing: ExistingPackBundleReceipt,
    ) -> Self {
        Self {
            evidence: Evidence::Received { pack, framing },
        }
    }

    #[must_use]
    pub const fn encoded(&self) -> Option<&StreamFullBundleReceipt> {
        match &self.evidence {
            Evidence::Encoded(receipt) => Some(receipt),
            Evidence::Received { .. } => None,
        }
    }

    #[must_use]
    pub const fn received(&self) -> Option<&ReceivedPackReceipt> {
        match &self.evidence {
            Evidence::Received { pack, .. } => Some(pack),
            Evidence::Encoded(_) => None,
        }
    }

    #[must_use]
    pub const fn framing(&self) -> Option<&ExistingPackBundleReceipt> {
        match &self.evidence {
            Evidence::Received { framing, .. } => Some(framing),
            Evidence::Encoded(_) => None,
        }
    }

    #[must_use]
    pub const fn format(&self) -> GitHashAlgorithm {
        match &self.evidence {
            Evidence::Encoded(receipt) => receipt.format(),
            Evidence::Received { framing, .. } => framing.format(),
        }
    }

    #[must_use]
    pub const fn profile_id(&self) -> &'static str {
        match &self.evidence {
            Evidence::Encoded(receipt) => receipt.profile_id(),
            Evidence::Received { framing, .. } if framing.prerequisite_count() != 0 => {
                "git-bundle-incremental-received-pack-v1"
            }
            Evidence::Received { .. } => "git-bundle-received-pack-v1",
        }
    }

    #[must_use]
    pub const fn pack_checksum(&self) -> GitOid {
        match &self.evidence {
            Evidence::Encoded(receipt) => receipt.pack_checksum(),
            Evidence::Received { framing, .. } => framing.pack_checksum(),
        }
    }

    #[must_use]
    pub const fn object_count(&self) -> u32 {
        match &self.evidence {
            Evidence::Encoded(receipt) => receipt.object_count(),
            Evidence::Received { framing, .. } => framing.object_count(),
        }
    }

    #[must_use]
    pub const fn prerequisite_count(&self) -> usize {
        match &self.evidence {
            Evidence::Encoded(receipt) => receipt.prerequisite_count(),
            Evidence::Received { framing, .. } => framing.prerequisite_count(),
        }
    }

    /// Verified omitted closure, not the number of external delta bases used.
    #[must_use]
    pub const fn external_object_count(&self) -> usize {
        match &self.evidence {
            Evidence::Encoded(receipt) => receipt.external_object_count(),
            Evidence::Received { framing, .. } => framing.external_object_count(),
        }
    }

    #[must_use]
    pub const fn total_object_bytes(&self) -> usize {
        match &self.evidence {
            Evidence::Encoded(receipt) => receipt.total_object_bytes(),
            Evidence::Received { pack, .. } => pack.total_object_bytes(),
        }
    }

    #[must_use]
    pub const fn pack_bytes(&self) -> usize {
        match &self.evidence {
            Evidence::Encoded(receipt) => receipt.pack_bytes(),
            Evidence::Received { framing, .. } => framing.pack_bytes(),
        }
    }

    #[must_use]
    pub const fn header_bytes(&self) -> usize {
        match &self.evidence {
            Evidence::Encoded(receipt) => receipt.header_bytes(),
            Evidence::Received { framing, .. } => framing.header_bytes(),
        }
    }

    #[must_use]
    pub const fn bundle_bytes(&self) -> usize {
        match &self.evidence {
            Evidence::Encoded(receipt) => receipt.bundle_bytes(),
            Evidence::Received { framing, .. } => framing.bundle_bytes(),
        }
    }

    #[must_use]
    pub const fn bundle_sha256(&self) -> [u8; 32] {
        match &self.evidence {
            Evidence::Encoded(receipt) => receipt.bundle_sha256(),
            Evidence::Received { framing, .. } => framing.bundle_sha256(),
        }
    }

    /// Work performed by the compressor during this export. Reuse performs
    /// none; this does not describe selection, restoration or hashing work.
    #[must_use]
    pub const fn compression_work(&self) -> u64 {
        match &self.evidence {
            Evidence::Encoded(receipt) => receipt.compression_work(),
            Evidence::Received { .. } => 0,
        }
    }
}
