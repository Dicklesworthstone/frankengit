//! Immutable fixed-width handoff from actual execution to later check publication.
use super::{
    File, Format, GitOid, MetadataExt, NodeRequestContext, Path, Read, TrustedWorkflowDispatch,
    TrustedWorkflowFailure, fs, hex, invalid, io, sha256_digest, write_new,
};
use std::collections::BTreeSet;
const MAGIC: &[u8; 8] = b"FGWCS001";
const MAX_BYTES: usize = 4096;
pub(super) struct Run {
    pub run: [u8; 16],
    pub journal: [u8; 32],
    pub bytes: u64,
    pub tail: [u8; 32],
}
pub(super) struct Sources {
    pub identity: [u8; 32],
    pub commit: GitOid,
    pub runs: Vec<Run>,
}
impl Sources {
    pub(super) fn capture(
        path: &Path,
        scope: [u8; 32],
        event: [u8; 32],
        commit: GitOid,
        dispatch: &TrustedWorkflowDispatch,
        request: &NodeRequestContext,
    ) -> Result<(), TrustedWorkflowFailure> {
        if dispatch.runs().len() > 32 {
            return Err(invalid("watch check-source count exceeded"));
        }
        let mut body = Vec::new();
        body.extend_from_slice(MAGIC);
        body.extend(scope);
        body.extend(event);
        body.push(match commit.algorithm() {
            Format::Sha1 => 1,
            Format::Sha256 => 2,
        });
        body.extend_from_slice(commit.as_bytes());
        body.extend_from_slice(&(dispatch.runs().len() as u32).to_be_bytes());
        for run in dispatch.runs() {
            if run.executed_commit() != commit {
                return Err(invalid("watch child source mismatch"));
            }
            let journal = run.open_check_journal(None, &|| request.checkpoint_is_live())?;
            body.extend(run.run_id);
            body.extend_from_slice(
                run.check_journal_scope()
                    .journal_id
                    .digest()
                    .bytes()
                    .as_bytes(),
            );
            body.extend(journal.pin().byte_len().to_be_bytes());
            body.extend_from_slice(journal.pin().tail().digest().bytes().as_bytes());
        }
        let checksum = sha256_digest(&body);
        body.extend(checksum);
        write_new(&path.join("check-sources"), &body)
            .and_then(|()| File::open(path)?.sync_all())
            .map_err(io)
    }
    pub(super) fn read(
        path: &Path,
        scope: &[u8; 32],
        key: &str,
    ) -> Result<Self, TrustedWorkflowFailure> {
        let bytes = read_private(&path.join("check-sources"), MAX_BYTES)?;
        Self::decode(&bytes, scope, key)
    }
    fn decode(bytes: &[u8], scope: &[u8; 32], key: &str) -> Result<Self, TrustedWorkflowFailure> {
        if bytes.len() < 129
            || &bytes[..8] != MAGIC
            || &bytes[8..40] != scope
            || hex(&bytes[40..72]) != key
        {
            return Err(invalid("invalid watch check-source binding or version"));
        }
        let end = bytes.len() - 32;
        if sha256_digest(&bytes[..end]) != bytes[end..] {
            return Err(invalid("watch check-source checksum mismatch"));
        }
        let (format, width) = match bytes[72] {
            1 => (Format::Sha1, 20),
            2 => (Format::Sha256, 32),
            _ => return Err(invalid("invalid watch native format")),
        };
        let offset = 73 + width;
        let count = u32::from_be_bytes(
            bytes
                .get(offset..offset + 4)
                .ok_or_else(|| invalid("truncated watch count"))?
                .try_into()
                .map_err(|_| invalid("watch count width"))?,
        ) as usize;
        if count > 32 || offset + 4 + count * 88 != end {
            return Err(invalid("invalid watch check-source length"));
        }
        let commit = GitOid::from_hex(format, &hex(&bytes[73..offset]))
            .map_err(|_| invalid("invalid watch source commit"))?;
        if commit.is_zero() {
            return Err(invalid("zero watch source commit"));
        }
        let mut runs = Vec::new();
        let mut seen = BTreeSet::new();
        for row in bytes[offset + 4..end].as_chunks::<88>().0 {
            let run: [u8; 16] = row[..16]
                .try_into()
                .map_err(|_| invalid("watch run width"))?;
            if run == [0; 16] || !seen.insert(run) {
                return Err(invalid("duplicate or zero watch run"));
            }
            runs.push(Run {
                run,
                journal: row[16..48]
                    .try_into()
                    .map_err(|_| invalid("watch digest width"))?,
                bytes: u64::from_be_bytes(
                    row[48..56]
                        .try_into()
                        .map_err(|_| invalid("watch pin width"))?,
                ),
                tail: row[56..88]
                    .try_into()
                    .map_err(|_| invalid("watch tail width"))?,
            });
        }
        Ok(Self {
            identity: sha256_digest(bytes),
            commit,
            runs,
        })
    }
}
pub(in super::super) fn read_private(
    path: &Path,
    maximum: usize,
) -> Result<Vec<u8>, TrustedWorkflowFailure> {
    let meta = fs::symlink_metadata(path).map_err(io)?;
    if !meta.is_file()
        || meta.mode() & 0o777 != 0o600
        || meta.nlink() != 1
        || meta.len() > maximum as u64
    {
        return Err(invalid("invalid bounded private watch record"));
    }
    let file = File::open(path).map_err(io)?;
    let actual = file.metadata().map_err(io)?;
    if (meta.dev(), meta.ino(), meta.len()) != (actual.dev(), actual.ino(), actual.len()) {
        return Err(invalid("watch record changed during open"));
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() as u64 != meta.len() || bytes.len() > maximum {
        return Err(invalid("watch record length changed"));
    }
    Ok(bytes)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_frames_refuse_all_truncations_bit_flips_and_foreign_scope() {
        for format in [Format::Sha1, Format::Sha256] {
            let mut b = MAGIC.to_vec();
            b.extend([1; 32]);
            b.extend([2; 32]);
            b.push(if format == Format::Sha1 { 1 } else { 2 });
            b.extend(vec![3; format.digest_len()]);
            b.extend(0u32.to_be_bytes());
            b.extend(sha256_digest(&b));
            let key = hex(&[2; 32]);
            assert!(Sources::decode(&b, &[1; 32], &key).is_ok());
            for n in 0..b.len() {
                assert!(Sources::decode(&b[..n], &[1; 32], &key).is_err());
            }
            for n in 0..b.len() {
                let mut bad = b.clone();
                bad[n] ^= 1;
                assert!(Sources::decode(&bad, &[1; 32], &key).is_err());
            }
            assert!(Sources::decode(&b, &[4; 32], &key).is_err());
        }
    }
}
