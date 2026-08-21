//! The production [`BodyIdentity`] implementation.
//!
//! `fgit-codec` produces canonical bytes and names a domain and schema;
//! `fgit-crypto` owns the preimage framing, the digest, and the identity
//! registry. Neither can implement the seam alone, and `fgit-crypto` does not
//! depend on this crate, so the bridge lives here — the one place that can see
//! both sides.
//!
//! Putting it here rather than in each consumer is deliberate. Every body
//! identity in the system flows through one implementation, so there is no
//! second place for the domain-to-registry mapping to drift.

use fgit_types::identity::InternalObjectId;
use fgit_types::numeric::CodecVersion;
use fgit_types::{DomainTag, SchemaId};

use crate::attest::BodyIdentity;
use crate::error::CodecRefusal;

/// Computes body identities through the `fgit-crypto` identity registry.
///
/// A domain the registry does not know is a typed refusal, never a computed
/// value: an identity under an unregistered domain is one nothing else could
/// verify.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CryptoBodyIdentity;

impl BodyIdentity for CryptoBodyIdentity {
    fn identify(
        &self,
        domain: DomainTag,
        schema: SchemaId,
        codec_version: CodecVersion,
        canonical_body: &[u8],
    ) -> Result<InternalObjectId, CodecRefusal> {
        fgit_crypto::internal_object_id_for_tag(domain, schema, codec_version, canonical_body)
            .map_err(|_| CodecRefusal::identity_domain_unregistered(domain))
    }
}
