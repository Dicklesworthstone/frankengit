use fgit_chronicle::PublicationBasis;
use fgit_codec::{CanonicalBody, CodecRefusal, Decoder, Encoder};
use fgit_types::{
    Digest, DomainTag, PrincipalId, RefusalCode, RepositoryAuthorityHeadId, RepositoryId,
    RootLayoutVersion, SchemaFamily, TenantId, TxId,
};

use super::{DefaultBranchCommand, proposal};
use crate::{AdmissionContext, CanonicalRefState, ref_state_root};

/// The actual symbolic-ref delta and invariant witness for one HEAD decision.
/// Direct refs are unchanged. A same-target no-op has equal predecessor and
/// successor roots and explicitly records the identical old/new branch.
/// Decoding this body alone does not establish publication or authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalHeadChange {
    pub(super) tenant: TenantId,
    pub(super) repository: RepositoryId,
    pub(super) principal: PrincipalId,
    pub(super) tx_id: TxId,
    pub(super) request_digest: Digest,
    pub(super) basis_head: RepositoryAuthorityHeadId,
    pub(super) layout: RootLayoutVersion,
    pub(super) previous_ref_root: Digest,
    pub(super) resulting_ref_root: Digest,
    pub(super) command: DefaultBranchCommand,
    /// Canonical single-event witness for the selected protection state. The
    /// named basis separately authenticates its actual forge frontier.
    pub(super) protection_witness_root: Option<Digest>,
}

impl CanonicalHeadChange {
    #[must_use]
    pub const fn command(&self) -> &DefaultBranchCommand {
        &self.command
    }

    #[must_use]
    pub const fn basis_head(&self) -> RepositoryAuthorityHeadId {
        self.basis_head
    }

    #[must_use]
    pub const fn previous_ref_root(&self) -> Digest {
        self.previous_ref_root
    }

    #[must_use]
    pub const fn resulting_ref_root(&self) -> Digest {
        self.resulting_ref_root
    }

    #[must_use]
    pub const fn root_layout(&self) -> RootLayoutVersion {
        self.layout
    }

    /// Recompute the complete semantic transition and its original seal binding.
    /// The caller must independently authenticate the named basis, verify that
    /// `root_layout()` is selected by its `configuration_root`, and verify the
    /// selected administrator policy. This pure check cannot fetch that
    /// configuration or promote an orphaned staged body into canonical state.
    pub fn verify_transition(
        &self,
        context: &AdmissionContext,
        basis: &PublicationBasis,
        before: &CanonicalRefState,
        after: &CanonicalRefState,
        command: &DefaultBranchCommand,
        protection_witness_root: Option<Digest>,
    ) -> Result<(), RefusalCode> {
        command.validate(context.object_format)?;
        let (tx_id, seal) = proposal(context, command)
            .map_err(|_| RefusalCode::EvidenceInvalid)?
            .derive()
            .map_err(|_| RefusalCode::EvidenceInvalid)?;
        if !self.layout.commits_head_target()
            || basis.body().repository_id != context.repository_id
            || self.tenant != context.tenant_id
            || self.repository != context.repository_id
            || self.principal != context.principal_id
            || self.tx_id != tx_id
            || self.request_digest != seal.canonical_request_digest
            || self.basis_head != basis.id()
            || self.command != *command
            || self.protection_witness_root != protection_witness_root
            || before.head_target() != command.expected_head.as_ref()
            || before.refs().get(&command.target) != Some(&command.expected_target_tip)
            || after.head_target() != Some(&command.target)
            || before.refs() != after.refs()
            || self.previous_ref_root != basis.body().ref_root
            || ref_state_root(self.layout, before)? != self.previous_ref_root
            || ref_state_root(self.layout, after)? != self.resulting_ref_root
        {
            return Err(RefusalCode::EvidenceInvalid);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), CodecRefusal> {
        self.command
            .validate(self.command.expected_target_tip.algorithm())
            .map_err(|code| CodecRefusal::VariantUnknown {
                field: "head_change.command",
                observed: u32::from(code.code_point()),
                offset: 0,
            })?;
        if !self.layout.commits_head_target() {
            return Err(CodecRefusal::VariantUnknown {
                field: "head_change.layout",
                observed: u32::from(self.layout.code_point()),
                offset: 0,
            });
        }
        Ok(())
    }
}

impl CanonicalBody for CanonicalHeadChange {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/admission-head-delta/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("admission-head-delta");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.validate_shape()?;
        out.write_opaque_id(self.tenant.as_bytes());
        out.write_opaque_id(self.repository.as_bytes());
        out.write_opaque_id(self.principal.as_bytes());
        out.write_internal_object_id(self.tx_id.as_internal_object_id())?;
        out.write_digest(&self.request_digest)?;
        out.write_internal_object_id(self.basis_head.as_internal_object_id())?;
        out.write_scalar(self.layout.code_point());
        out.write_digest(&self.previous_ref_root)?;
        out.write_digest(&self.resulting_ref_root)?;
        self.command.write(out)?;
        out.write_option(self.protection_witness_root.as_ref(), Encoder::write_digest)
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let body = Self {
            tenant: TenantId::from_bytes(input.read_opaque_id("head_change.tenant")?),
            repository: RepositoryId::from_bytes(input.read_opaque_id("head_change.repository")?),
            principal: PrincipalId::from_bytes(input.read_opaque_id("head_change.principal")?),
            tx_id: TxId::from_internal_object_id(input.read_internal_object_id()?)?,
            request_digest: input.read_digest()?,
            basis_head: RepositoryAuthorityHeadId::from_internal_object_id(
                input.read_internal_object_id()?,
            )?,
            layout: RootLayoutVersion::from_code_point(input.read_scalar("head_change.layout")?)?,
            previous_ref_root: input.read_digest()?,
            resulting_ref_root: input.read_digest()?,
            command: DefaultBranchCommand::read(input)?,
            protection_witness_root: input
                .read_option("head_change.protection_witness_root", Decoder::read_digest)?,
        };
        body.validate_shape()?;
        Ok(body)
    }
}
