//! Revocation-aware incarnation configuration.
//!
//! Repository configuration schemas 2.0 and 2.1 are already published byte
//! formats.  They remain in `schema.rs` unchanged.  This module adds schema 2.2
//! as a new exact body, preserving every 2.1 field in order and appending one
//! optional pointer to a canonical capability-revocation generation.
//!
//! The pointer is part of the body selected by
//! `RepositoryAuthorityHeadBody::configuration_root`.  Revocation selection
//! therefore changes only through the ordinary authority-head transition; it
//! cannot be filled in later through a side database or mutable cache.

use fgit_types::{
    Digest, DomainTag, GitHashAlgorithm, RepositoryIncarnationId, RootLayoutVersion, SchemaFamily,
};

use crate::{CanonicalBody, CodecRefusal, Decoder, Encoder};

/// Incarnation-aware repository configuration with an exact capability-
/// revocation generation pointer.
///
/// `policy_root` retains the schema-2.1 hidden-ref policy meaning.  The new
/// `capability_revocation_root` names a body in the registered
/// `frankengit/generation/v1` identity domain.  `None` means this configuration
/// predates or deliberately omits canonical agent-capability revocation state;
/// a high-value effect reader must fail closed rather than interpret absence as
/// an empty revoked set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepositoryIncarnationConfigurationBodyV2_2 {
    /// How this repository's authenticated roots are laid out.
    pub root_layout: RootLayoutVersion,
    /// Permanent native Git object identity domain for this repository.
    pub object_format: GitHashAlgorithm,
    /// Minted incarnation preventing delete/recreate resurrection.
    pub repository_incarnation_id: RepositoryIncarnationId,
    /// Optional immutable hidden-ref policy introduced by schema 2.1.
    pub policy_root: Option<Digest>,
    /// Optional exact capability-revocation generation selected by this body.
    pub capability_revocation_root: Option<Digest>,
}

impl CanonicalBody for RepositoryIncarnationConfigurationBodyV2_2 {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/repository-configuration/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("repository-configuration");
    const SCHEMA_MAJOR: u16 = 2;
    const SCHEMA_MINOR: u16 = 2;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_scalar(self.root_layout.code_point());
        out.write_scalar(self.object_format.code_point());
        out.write_opaque_id(self.repository_incarnation_id.as_bytes());
        out.write_option(self.policy_root.as_ref(), Encoder::write_digest)?;
        out.write_option(
            self.capability_revocation_root.as_ref(),
            Encoder::write_digest,
        )
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let root_layout =
            RootLayoutVersion::from_code_point(input.read_scalar::<u16>("root_layout")?)?;
        let object_format =
            GitHashAlgorithm::from_code_point(input.read_scalar::<u16>("object_format")?)?;
        let repository_incarnation_id =
            RepositoryIncarnationId::from_bytes(input.read_opaque_id("repository_incarnation_id")?);
        let policy_root = input.read_option("policy_root", Decoder::read_digest)?;
        let capability_revocation_root =
            input.read_option("capability_revocation_root", Decoder::read_digest)?;
        Ok(Self {
            root_layout,
            object_format,
            repository_incarnation_id,
            policy_root,
            capability_revocation_root,
        })
    }
}
