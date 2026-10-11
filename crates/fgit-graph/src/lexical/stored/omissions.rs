//! Authenticated source coverage, independent of result pagination. The native
//! source owner verifies each omitted blob and supplies its actual byte count;
//! these records never prove authorization, source absence, or reusable content.

use super::{
    GitHashAlgorithm, GitOid, IndexError, IndexedDocument, LexicalError, MAX_FILE_BYTES,
    MAX_INDEX_DOCUMENTS, MAX_RESULT_BYTES, MAX_SOURCE_BYTES, bounded_add, check, path_valid,
};
use crate::lexical::encoding::oid_read;
use fgit_codec::{Decoder, Encoder};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LexicalOmissionReason {
    FileBytes,
}
impl LexicalOmissionReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FileBytes => "file_bytes",
        }
    }
}

/// One verified current native blob excluded by the selected per-file bound.
/// Raw-byte paths preserve non-UTF-8 names. A later build must enumerate and
/// verify the current blob again; this receipt is not a shortcut around reads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LexicalOmission {
    pub path: Vec<u8>,
    pub blob: GitOid,
    pub source_bytes: usize,
    pub reason: LexicalOmissionReason,
    pub limit: usize,
}
impl LexicalOmission {
    pub fn validate(&self, format: GitHashAlgorithm) -> Result<(), IndexError> {
        if !path_valid(&self.path)
            || self.blob.is_zero()
            || self.blob.algorithm() != format
            || self.source_bytes > MAX_SOURCE_BYTES
        {
            return Err(LexicalError::Invalid("omission source").into());
        }
        match self.reason {
            LexicalOmissionReason::FileBytes => {
                if !(1..=MAX_FILE_BYTES).contains(&self.limit) || self.source_bytes <= self.limit {
                    return Err(LexicalError::Invalid("omission diagnostics").into());
                }
            }
        }
        Ok(())
    }

    pub(super) fn write(&self, out: &mut Encoder) -> Result<(), IndexError> {
        out.write_bytes("omitted path", &self.path)?;
        out.write_raw(self.blob.as_bytes());
        out.write_scalar(self.source_bytes as u64);
        out.write_scalar(match self.reason {
            LexicalOmissionReason::FileBytes => 1u8,
        });
        out.write_scalar(self.limit as u64);
        Ok(())
    }

    pub(super) fn read(
        input: &mut Decoder<'_>,
        format: GitHashAlgorithm,
    ) -> Result<Self, IndexError> {
        let path = input.read_bytes("omitted path")?.to_vec();
        let blob = oid_read(input, format)?;
        let source_bytes = usize::try_from(input.read_scalar::<u64>("omitted source bytes")?)
            .map_err(|_| LexicalError::Limit("omission integer width"))?;
        let reason = match input.read_scalar::<u8>("omission reason")? {
            1 => LexicalOmissionReason::FileBytes,
            _ => return Err(LexicalError::Invalid("omission reason").into()),
        };
        let limit = usize::try_from(input.read_scalar::<u64>("omission limit")?)
            .map_err(|_| LexicalError::Limit("omission integer width"))?;
        let value = Self {
            path,
            blob,
            source_bytes,
            reason,
            limit,
        };
        value.validate(format)?;
        Ok(value)
    }
}

pub(super) fn validate(
    omissions: &[LexicalOmission],
    format: GitHashAlgorithm,
    indexed_documents: usize,
    indexed_source_bytes: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<usize, IndexError> {
    check(live)?;
    if indexed_documents
        .checked_add(omissions.len())
        .is_none_or(|n| n > MAX_INDEX_DOCUMENTS)
        || indexed_source_bytes > MAX_SOURCE_BYTES
    {
        return Err(LexicalError::Limit("index source coverage").into());
    }
    let mut bytes = indexed_source_bytes;
    let mut previous: Option<&[u8]> = None;
    for omission in omissions {
        check(live)?;
        omission.validate(format)?;
        if previous.is_some_and(|path| path >= omission.path.as_slice()) {
            return Err(LexicalError::Invalid("omission path order").into());
        }
        bounded_add(
            &mut bytes,
            omission.source_bytes,
            MAX_SOURCE_BYTES,
            "source bytes",
        )?;
        previous = Some(&omission.path);
    }
    // Every query must retain the whole inventory, even when it has no hits.
    // Refuse an unqueryable generation during preparation and manifest decode,
    // before it can replace an active index. Hits still share this allowance
    // when a particular query runs.
    charge_results(omissions, &mut 0, live)?;
    Ok(bytes - indexed_source_bytes)
}

pub(super) fn disjoint(
    omissions: &[LexicalOmission],
    documents: &[IndexedDocument],
    live: &mut impl FnMut() -> bool,
) -> Result<(), IndexError> {
    for document in documents {
        check(live)?;
        if omissions
            .binary_search_by(|row| row.path.cmp(&document.path))
            .is_ok()
        {
            return Err(LexicalError::Invalid("omission overlaps indexed document").into());
        }
    }
    Ok(())
}

/// Omission receipts and hits share one retained-result allowance. Charge the
/// receipts before scanning, including when there are no posting segments.
pub(super) fn charge_results(
    omissions: &[LexicalOmission],
    bytes: &mut usize,
    live: &mut impl FnMut() -> bool,
) -> Result<(), IndexError> {
    for omission in omissions {
        check(live)?;
        bounded_add(
            bytes,
            omission.path.len() + 96,
            MAX_RESULT_BYTES,
            "result bytes",
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
