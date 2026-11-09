use fgit_authority::{ScopedEntry, SealAttempt, SemanticRequest};
use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_types::{
    AsciiSlug, GitHashAlgorithm, GitOid, RefName, RefusalCode, SchemaFamily, SchemaId,
};

use crate::{AdmissionContext, AdmissionError};

/// Semantic request profile for a repository-administrator symbolic HEAD change.
/// The authenticated authority basis is preparation evidence, not request identity.
pub const DEFAULT_BRANCH_ADMISSION_SCHEMA: SchemaId =
    SchemaId::new(SchemaFamily::from_static("default-branch-admission"), 1, 0);

/// Select an existing branch at one exact native tip. `None` requires an absent
/// symbolic HEAD; it never means "any current target". An exact same-target
/// request is a valid sealed no-op and still checks administrator authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DefaultBranchCommand {
    pub expected_head: Option<RefName>,
    pub target: RefName,
    pub expected_target_tip: GitOid,
}

impl DefaultBranchCommand {
    pub(super) fn validate(&self, format: GitHashAlgorithm) -> Result<(), RefusalCode> {
        if let Some(expected) = &self.expected_head {
            crate::validate_head_target(expected)?;
        }
        crate::validate_head_target(&self.target)?;
        if self.expected_target_tip.algorithm() != format {
            return Err(RefusalCode::HashAlgorithmDomainMismatch);
        }
        if self.expected_target_tip.is_zero() {
            return Err(RefusalCode::NativeObjectIdMismatch);
        }
        Ok(())
    }

    pub(super) fn write(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_option(self.expected_head.as_ref(), Encoder::write_ref_name)?;
        out.write_ref_name(&self.target)?;
        out.write_git_oid(&self.expected_target_tip);
        Ok(())
    }

    pub(super) fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        Ok(Self {
            expected_head: input
                .read_option("head_change.expected_head", Decoder::read_ref_name)?,
            target: input.read_ref_name()?,
            expected_target_tip: input.read_git_oid()?,
        })
    }
}

/// Derive the ordinary transaction-seal attempt without reading repository state.
/// All three command fields are sealed; there are no disguised direct-ref edits.
pub fn proposal(
    context: &AdmissionContext,
    command: &DefaultBranchCommand,
) -> Result<SealAttempt, AdmissionError> {
    command
        .validate(context.object_format)
        .map_err(super::unavailable)?;
    let mut payload = Encoder::new();
    command
        .write(&mut payload)
        .map_err(|_| super::unavailable(RefusalCode::CanonicalFramingInvalid))?;
    let request = SemanticRequest::build(
        DEFAULT_BRANCH_ADMISSION_SCHEMA,
        context.object_format,
        true,
        Vec::new(),
        Vec::new(),
        vec![ScopedEntry::new(
            AsciiSlug::from_static("ref-state"),
            AsciiSlug::from_static("default-branch.v1"),
            payload.as_bytes(),
        )?],
    )?;
    Ok(SealAttempt {
        tenant_id: context.tenant_id,
        repository_id: context.repository_id,
        authenticated_principal_id: context.principal_id,
        idempotency_key: context.idempotency_key.clone(),
        request,
    })
}
