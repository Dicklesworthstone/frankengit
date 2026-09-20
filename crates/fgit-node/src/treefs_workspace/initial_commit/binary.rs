//! Creation-only root history through the existing native binary batch decoder.
//! No object lookup, host checkout, or publication authority is introduced.
use fgit_forge::initial_commit::{InitialCommitError, InitialCommitPlan,
    prepare_initial_commit_with_binary_decoder};
use fgit_forge::patch::{FileChange, IndexExpectation, PatchError, PatchLimits, UnifiedPatch};
use fgit_forge::preparation::MergeMetadata;
use fgit_pack::binary_patch::{BinaryPatchBatch, BinaryPatchError, BinaryPatchLimits};
use fgit_types::{GitHashAlgorithm, GitOid};

fn invalid(reason: &'static str) -> PatchError { PatchError::Syntax { line: 1, reason } }
fn target(index: &IndexExpectation, format: GitHashAlgorithm) -> Result<GitOid, PatchError> {
    let width = format.digest_len() * 2;
    if index.old.len() != width || index.new.len() != width
        || !index.old.iter().all(|b| *b == b'0')
        || !index.new.iter().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)) {
        return Err(invalid("initial binary index requires full absent/source and native target identities"));
    }
    let value = std::str::from_utf8(&index.new).map_err(|_| invalid("invalid initial binary target"))?;
    let id = GitOid::from_hex(format, value).map_err(|_| invalid("invalid initial binary target"))?;
    if id.is_zero() { return Err(invalid("initial binary target must be present")); }
    Ok(id)
}
fn refusal(error: BinaryPatchError) -> PatchError {
    match error {
        BinaryPatchError::Cancelled => PatchError::Cancelled,
        BinaryPatchError::InvalidLimits => PatchError::InvalidLimits,
        BinaryPatchError::Limit(_) => PatchError::Budget("initial compressed patch decoding"),
        BinaryPatchError::SourceMismatch => invalid("initial binary source mismatch"),
        BinaryPatchError::TargetMismatch => invalid("initial binary target mismatch"),
        BinaryPatchError::ReverseMismatch => invalid("initial binary reverse image mismatch"),
        BinaryPatchError::Invalid(_) => invalid("invalid initial compressed patch"),
    }
}

pub(super) fn prepare_initial_commit(
    format: GitHashAlgorithm, bytes: &[u8], metadata: &MergeMetadata,
    limits: PatchLimits, cancelled: &dyn Fn() -> bool,
) -> Result<InitialCommitPlan, InitialCommitError> {
    if cancelled() { return Err(PatchError::Cancelled.into()); }
    limits.validate()?;
    metadata.validate().map_err(InitialCommitError::Metadata)?;
    // Count structurally admitted records before reserving one nonrenewable
    // budget. Drop this bounded parse before the forge's independent parse;
    // no second decoder and no renewed per-file budget is created.
    let patch = UnifiedPatch::parse_with_binary(bytes, limits, cancelled)?;
    let mut count = 0;
    for file in patch.files() {
        if cancelled() { return Err(PatchError::Cancelled.into()); }
        if file.change() != FileChange::Create || file.renamed_from().is_some() {
            return Err(InitialCommitError::CreationRequired);
        }
        fgit_treefs::TreePath::parse_default(file.path()).map_err(|_| PatchError::InvalidPath)?;
        if file.binary_hunks().is_some() {
            target(file.index().ok_or(InitialCommitError::IndexMismatch)?, format)?;
            count += 1;
        }
    }
    drop(patch);
    let mut batch = if count == 0 { None } else {
        Some(BinaryPatchBatch::new(BinaryPatchLimits {
            max_input_bytes: limits.max_patch_bytes, max_file_bytes: limits.max_file_bytes,
            max_expanded_bytes: limits.max_output_bytes, max_lines: limits.max_lines,
            ..BinaryPatchLimits::default()
        }, count).map_err(refusal)?)
    };
    let plan = prepare_initial_commit_with_binary_decoder(format, bytes, metadata, limits, cancelled,
        |hunks, index, base| {
            if !base.is_empty() { return Err(invalid("initial binary source must be absent")); }
            let id = target(index, format)?;
            let batch = batch.as_mut().ok_or_else(|| invalid("initial binary budget not reserved"))?;
            batch.apply(hunks, None, Some(id), base, &mut || !cancelled()).map_err(refusal)
        })?;
    if batch.as_ref().is_some_and(|batch| batch.usage().files != count) {
        return Err(invalid("initial binary file count mismatch").into());
    }
    if cancelled() { return Err(PatchError::Cancelled.into()); }
    Ok(plan)
}

#[cfg(test)]
mod tests;
