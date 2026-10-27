//! Native source retrieval -> Agent Protocol ContextPacket bridge.
//!
//! This module is a product-host consumer of `fgit-agent`, not another authority
//! model. It accepts only an authenticated IntentRun, proves that the hydrated
//! source context is from that run's exact repository/head/RCR/forge position,
//! and keeps repository bytes in ContextSource's visibly-untrusted field.
use super::{InitialReport, context::InitialContext};
use fgit_agent::{
    AuthorityReadReceipt, ContextControl, ContextPacket, ContextSource, IntentRun, OperationClass,
    ProtocolRefusal, RetrievalChannel,
};
use fgit_crypto::sha256_digest;

pub mod document;
mod read;
pub use read::{AgentContextRead, AgentContextReadError, AgentSourceContext};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentContextRefusal {
    RunAuthorityReceiptRequired,
    ReadOperationOutsideRun,
    ControlScopeOutsideRun,
    NodeRepositoryMismatch,
    RepositoryMismatch,
    AuthorityHeadMismatch,
    RepositoryCommitMissing,
    RepositoryCommitMismatch,
    ForgePositionMismatch,
    Protocol(ProtocolRefusal),
}
impl core::fmt::Display for AgentContextRefusal {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(out, "agent source context refused: {self:?}")
    }
}
impl core::error::Error for AgentContextRefusal {}

fn source_commitment(
    path: &[u8],
    blob: fgit_types::GitOid,
    offset: usize,
    bytes: &[u8],
) -> [u8; 32] {
    let mut input = Vec::with_capacity(64 + path.len() + blob.as_bytes().len() + bytes.len());
    input.extend_from_slice(b"frankengit/agent-context-source/v1\0");
    input.extend_from_slice(&(path.len() as u64).to_be_bytes());
    input.extend_from_slice(path);
    input.push(match blob {
        fgit_types::GitOid::Sha1(_) => 1,
        fgit_types::GitOid::Sha256(_) => 2,
    });
    input.extend_from_slice(blob.as_bytes());
    input.extend_from_slice(&(offset as u64).to_be_bytes());
    input.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    input.extend_from_slice(bytes);
    sha256_digest(&input)
}

/// Bind one native InitialContext to an authenticated agent run.
///
/// Search ranking, generations, and repository text never supply authority.
/// The caller-provided ContextControl may only narrow the run's operation classes.
pub fn context_packet_for_run(
    run: &IntentRun,
    context: &InitialContext,
    control: ContextControl,
) -> Result<ContextPacket, AgentContextRefusal> {
    let receipt = run_receipt(run, &control)?;
    match_run_source(receipt, context.retrieval())?;

    let mut sources = Vec::new();
    for file in context.files() {
        for excerpt in file.excerpts() {
            let body = excerpt.untrusted_bytes().to_vec();
            let commitment = source_commitment(file.path(), file.blob(), excerpt.offset(), &body);
            sources.push(
                ContextSource::new(commitment, RetrievalChannel::Exact, body)
                    .map_err(AgentContextRefusal::Protocol)?,
            );
        }
    }
    ContextPacket::build(receipt.clone(), control, sources).map_err(AgentContextRefusal::Protocol)
}

// Shared preflight: the native reader checks these BEFORE source acquisition,
// while the existing pure binding entrypoint retains its original contract.
fn run_receipt<'a>(
    run: &'a IntentRun,
    control: &ContextControl,
) -> Result<&'a AuthorityReadReceipt, AgentContextRefusal> {
    let receipt = run
        .authority_read_receipt()
        .ok_or(AgentContextRefusal::RunAuthorityReceiptRequired)?;
    let allowed = run.allowed_operation_classes();
    if !allowed.contains(OperationClass::ReadCanonicalObject)
        || !allowed.contains(OperationClass::ReadDerivedGeneration)
    {
        return Err(AgentContextRefusal::ReadOperationOutsideRun);
    }
    if !control.authorization_scope().is_subset_of(allowed) {
        return Err(AgentContextRefusal::ControlScopeOutsideRun);
    }

    Ok(receipt)
}

fn match_run_source(
    receipt: &AuthorityReadReceipt,
    initial: &InitialReport,
) -> Result<(), AgentContextRefusal> {
    let source = initial.source();
    if source.namespace.repository != receipt.repository_id() {
        return Err(AgentContextRefusal::RepositoryMismatch);
    }
    if source.source_head != receipt.authority_head_id() {
        return Err(AgentContextRefusal::AuthorityHeadMismatch);
    }
    let expected_rcr = receipt
        .latest_repository_commit_id()
        .ok_or(AgentContextRefusal::RepositoryCommitMissing)?;
    if source.source_rcr != expected_rcr {
        return Err(AgentContextRefusal::RepositoryCommitMismatch);
    }
    if source.forge_position_root != receipt.forge_position_root() {
        return Err(AgentContextRefusal::ForgePositionMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excerpt_identity_binds_path_blob_offset_and_bytes() {
        use fgit_crypto::{GitObjectKind, git_object_id};
        use fgit_types::GitHashAlgorithm;
        let a = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, b"abc");
        let b = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, b"abd");
        let base = source_commitment(b"src/a", a, 7, b"abc");
        assert_eq!(base, source_commitment(b"src/a", a, 7, b"abc"));
        assert_ne!(base, source_commitment(b"src/b", a, 7, b"abc"));
        assert_ne!(base, source_commitment(b"src/a", b, 7, b"abc"));
        assert_ne!(base, source_commitment(b"src/a", a, 8, b"abc"));
        assert_ne!(base, source_commitment(b"src/a", a, 7, b"abd"));
    }
}
