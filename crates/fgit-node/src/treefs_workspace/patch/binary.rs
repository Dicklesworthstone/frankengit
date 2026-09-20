//! Connect structural patch intake to the existing native identity-checked
//! decoder. No source lookup, staging, publication, or fallback lives here.
use fgit_forge::patch::{FilePatch, IndexExpectation, PatchedFile, PatchError, PatchLimits, UnifiedPatch};
use fgit_pack::binary_patch::{BinaryPatchBatch, BinaryPatchError, BinaryPatchLimits};
use fgit_types::{GitHashAlgorithm, GitOid};

fn invalid(reason: &'static str) -> PatchError { PatchError::Syntax { line: 1, reason } }
fn identity(bytes: &[u8], format: GitHashAlgorithm) -> Result<Option<GitOid>, PatchError> {
    if bytes.len() != format.digest_len() * 2 || !bytes.iter().all(|b|
        b.is_ascii_digit() || (b'a'..=b'f').contains(b)) {
        return Err(invalid("binary index must use the repository's full native hash width"));
    }
    if bytes.iter().all(|b| *b == b'0') { return Ok(None); }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("invalid binary index"))?;
    GitOid::from_hex(format, text).map(Some).map_err(|_| invalid("invalid binary index"))
}
fn identities(index: &IndexExpectation, format: GitHashAlgorithm)
    -> Result<(Option<GitOid>, Option<GitOid>), PatchError>
{
    Ok((identity(&index.old, format)?, identity(&index.new, format)?))
}
fn refusal(error: BinaryPatchError) -> PatchError {
    match error {
        BinaryPatchError::Cancelled => PatchError::Cancelled,
        BinaryPatchError::InvalidLimits => PatchError::InvalidLimits,
        BinaryPatchError::Limit(_) => PatchError::Budget("compressed patch decoding"),
        BinaryPatchError::SourceMismatch => invalid("binary source identity mismatch"),
        BinaryPatchError::TargetMismatch => invalid("binary target identity mismatch"),
        BinaryPatchError::ReverseMismatch => invalid("binary reverse image mismatch"),
        BinaryPatchError::Invalid(_) => invalid("invalid compressed binary patch"),
    }
}

pub(super) struct Decoder {
    format: GitHashAlgorithm,
    batch: Option<BinaryPatchBatch>,
}
impl Decoder {
    pub(super) fn new(patch: &UnifiedPatch<'_>, format: GitHashAlgorithm) -> Result<Self, PatchError> {
        let limits = patch.limits(); limits.validate()?;
        let mut count = 0;
        for file in patch.files() {
            if file.binary_hunks().is_some() {
                let index = file.index().ok_or_else(|| invalid("binary index required"))?;
                identities(index, format)?; // Never accept a prefix from another hash domain.
                count += 1;
            }
        }
        let batch = if count == 0 { None } else {
            Some(BinaryPatchBatch::new(BinaryPatchLimits {
                max_input_bytes: limits.max_patch_bytes,
                max_file_bytes: limits.max_file_bytes,
                max_expanded_bytes: limits.max_output_bytes,
                max_lines: limits.max_lines,
                ..BinaryPatchLimits::default()
            }, count).map_err(refusal)?)
        };
        Ok(Self { format, batch })
    }

    pub(super) fn apply(&mut self, file: &FilePatch<'_>, source: Option<(u32, &[u8])>,
        limits: PatchLimits, cancelled: &dyn Fn() -> bool,
    ) -> Result<Option<PatchedFile>, PatchError> {
        file.apply_with_binary_decoder(source, limits, cancelled, |bytes, index, original| {
            let (old, new) = identities(index, self.format)?;
            let batch = self.batch.as_mut().ok_or_else(|| invalid("binary budget was not reserved"))?;
            batch.apply(bytes, old, new, original, &mut || !cancelled()).map_err(refusal)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_width_and_absent_identity_are_not_prefix_comparisons() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let width = format.digest_len() * 2;
            assert_eq!(identity("0".repeat(width).as_bytes(), format).unwrap(), None);
            assert!(identity("a".repeat(width).as_bytes(), format).unwrap().is_some());
            for text in ["a".repeat(width - 1), "a".repeat(width + 1), "A".repeat(width),
                "0".repeat(if width == 40 { 64 } else { 40 })] {
                assert!(identity(text.as_bytes(), format).is_err());
            }
        }
    }
    #[test]
    fn native_decode_refusals_remain_read_errors_not_publication_outcomes() {
        assert_eq!(refusal(BinaryPatchError::Cancelled), PatchError::Cancelled);
        assert!(matches!(refusal(BinaryPatchError::Limit("private data")), PatchError::Budget(_)));
        for error in [BinaryPatchError::SourceMismatch, BinaryPatchError::TargetMismatch,
            BinaryPatchError::ReverseMismatch, BinaryPatchError::Invalid("private data")] {
            let error = refusal(error);
            assert!(matches!(error, PatchError::Syntax { .. }));
            assert!(!error.to_string().contains("private data"));
        }
    }
}
