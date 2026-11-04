//! Immutable fixed-width handoff from actual execution to later check publication.
use super::{
    File, Format, GitOid, MetadataExt, Path, Read, TrustedWorkflowDispatch, TrustedWorkflowFailure,
    fs, hex, invalid, io, sha256_digest, write_new,
};
use std::collections::BTreeSet;
const MAGIC: &[u8; 8] = b"FGWCS001";
const TERMINAL_MAGIC: &[u8; 8] = b"FGWCS002";
const TERMINAL_BYTES: usize = 37;
const MAX_BYTES: usize = 4096;
const MAX_JOURNAL_BYTES: u64 = 32 * 1024 * 1024;

/// Explicit local producer proof of a stopped, closed native dispatch. The
/// exact original plan and selected count distinguish a genuine zero-child
/// stop from an execution whose children or completion records are missing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TerminalDispatch {
    pub selected: usize,
    pub reason: u8,
    pub plan: [u8; 32],
}

impl TerminalDispatch {
    fn from_native(
        selected: usize,
        reason: &str,
        plan: [u8; 32],
    ) -> Result<Self, TrustedWorkflowFailure> {
        let reason = match reason {
            "request_stopped" => 1,
            "output_budget_exhausted" => 2,
            "workflow_refused" => 3,
            "workflow_timed_out" => 4,
            "workflow_output_limit" => 5,
            _ => return Err(invalid("watch terminal dispatch is not proved closed")),
        };
        if selected > 32 {
            return Err(invalid("watch terminal selection bound exceeded"));
        }
        Ok(Self {
            selected,
            reason,
            plan,
        })
    }

    pub(super) const fn permits_empty_prefix(self) -> bool {
        self.reason == 1
    }
}

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
    pub terminal: Option<TerminalDispatch>,
}
impl Sources {
    /// A stopped empty prefix requires explicit producer custody bound to the
    /// exact original selected plan. Legacy framing never supplies that proof.
    pub(super) fn verify_selection(
        &self,
        selected: usize,
        plan: [u8; 32],
    ) -> Result<(), TrustedWorkflowFailure> {
        if self
            .terminal
            .is_some_and(|terminal| terminal.selected != selected || terminal.plan != plan)
        {
            return Err(invalid(
                "watch terminal dispatch differs from its exact original selected plan",
            ));
        }
        if self.runs.len() > selected
            || (self.runs.is_empty()
                && selected > 0
                && !self
                    .terminal
                    .is_some_and(|terminal| terminal.permits_empty_prefix()))
        {
            return Err(invalid(
                "watch handoff lacks its original executed child prefix",
            ));
        }
        Ok(())
    }

    pub(super) fn capture(
        path: &Path,
        scope: [u8; 32],
        event: [u8; 32],
        commit: GitOid,
        dispatch: &TrustedWorkflowDispatch,
        live: &dyn Fn() -> bool,
    ) -> Result<(), TrustedWorkflowFailure> {
        checkpoint(live)?;
        if dispatch.runs().len() > 32 {
            return Err(invalid("watch check-source count exceeded"));
        }
        let terminal = dispatch
            .stopped_custody()
            .map(|(selected, reason, plan)| TerminalDispatch::from_native(selected, reason, plan))
            .transpose()?;
        if terminal.is_some_and(|terminal| {
            dispatch.runs().len() > terminal.selected
                || (dispatch.runs().is_empty()
                    && terminal.selected > 0
                    && !terminal.permits_empty_prefix())
        }) {
            return Err(invalid(
                "watch terminal prefix differs from selected dispatch",
            ));
        }
        checkpoint(live)?;
        let mut body = Vec::new();
        body.try_reserve_exact(MAX_BYTES)
            .map_err(|_| invalid("watch handoff allocation refused"))?;
        body.extend_from_slice(if terminal.is_some() {
            TERMINAL_MAGIC
        } else {
            MAGIC
        });
        body.extend(scope);
        body.extend(event);
        body.push(match commit.algorithm() {
            Format::Sha1 => 1,
            Format::Sha256 => 2,
        });
        body.extend_from_slice(commit.as_bytes());
        body.extend_from_slice(&(dispatch.runs().len() as u32).to_be_bytes());
        let mut journal_bytes = MAX_JOURNAL_BYTES;
        for run in dispatch.runs() {
            checkpoint(live)?;
            if run.executed_commit() != commit {
                return Err(invalid("watch child source mismatch"));
            }
            // Bound the whole finalization pass before opening journals. The
            // reader verifies their private paths, framing, scope and locks;
            // its checkpoint uses this same unrenewed finalization allowance.
            let metadata = fs::symlink_metadata(run.run_directory.join("check-proposals.journal"))
                .map_err(io)?;
            if !metadata.is_file()
                || metadata.mode() & 0o777 != 0o600
                || metadata.nlink() != 1
                || metadata.len() < 72
            {
                return Err(invalid(
                    "watch terminal journal is not bounded private custody",
                ));
            }
            journal_bytes = journal_bytes
                .checked_sub(metadata.len())
                .ok_or_else(|| invalid("watch terminal aggregate journal bound exceeded"))?;
            let journal = run.open_check_journal(None, live)?;
            if journal.pin().byte_len() != metadata.len() {
                return Err(invalid(
                    "watch terminal journal changed during finalization",
                ));
            }
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
        if let Some(terminal) = terminal {
            body.extend_from_slice(&(terminal.selected as u32).to_be_bytes());
            body.push(terminal.reason);
            body.extend_from_slice(&terminal.plan);
        }
        let checksum = sha256_digest(&body);
        body.extend(checksum);
        checkpoint(live)?;
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
            || bytes.len() > MAX_BYTES
            || (&bytes[..8] != MAGIC && &bytes[..8] != TERMINAL_MAGIC)
            || &bytes[8..40] != scope
            || hex(&bytes[40..72]) != key
        {
            return Err(invalid("invalid watch check-source binding or version"));
        }
        let end = bytes.len() - 32;
        if sha256_digest(&bytes[..end]) != bytes[end..] {
            return Err(invalid("watch check-source checksum mismatch"));
        }
        let terminal = if &bytes[..8] == TERMINAL_MAGIC {
            let start = end
                .checked_sub(TERMINAL_BYTES)
                .ok_or_else(|| invalid("truncated watch terminal dispatch"))?;
            let selected = u32::from_be_bytes(
                bytes[start..start + 4]
                    .try_into()
                    .map_err(|_| invalid("watch terminal count width"))?,
            ) as usize;
            let reason = bytes[start + 4];
            if selected > 32 || !(1..=5).contains(&reason) {
                return Err(invalid("invalid watch terminal selection or reason"));
            }
            Some(TerminalDispatch {
                selected,
                reason,
                plan: bytes[start + 5..end]
                    .try_into()
                    .map_err(|_| invalid("watch terminal plan width"))?,
            })
        } else {
            None
        };
        let rows_end = end
            - if terminal.is_some() {
                TERMINAL_BYTES
            } else {
                0
            };
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
        if count > 32
            || offset + 4 + count * 88 != rows_end
            || terminal.is_some_and(|terminal| {
                count > terminal.selected
                    || (count == 0 && terminal.selected > 0 && !terminal.permits_empty_prefix())
            })
        {
            return Err(invalid("invalid watch check-source length"));
        }
        let commit = GitOid::from_hex(format, &hex(&bytes[73..offset]))
            .map_err(|_| invalid("invalid watch source commit"))?;
        if commit.is_zero() {
            return Err(invalid("zero watch source commit"));
        }
        let mut runs = Vec::new();
        let mut seen = BTreeSet::new();
        for row in bytes[offset + 4..rows_end].as_chunks::<88>().0 {
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
            terminal,
        })
    }
}
fn checkpoint(live: &dyn Fn() -> bool) -> Result<(), TrustedWorkflowFailure> {
    if live() {
        Ok(())
    } else {
        Err(invalid("watch terminal finalization deadline exceeded"))
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
    let mut file = File::open(path).map_err(io)?;
    let actual = file.metadata().map_err(io)?;
    if !actual.is_file()
        || actual.mode() & 0o777 != 0o600
        || actual.nlink() != 1
        || (meta.dev(), meta.ino(), meta.len()) != (actual.dev(), actual.ino(), actual.len())
    {
        return Err(invalid("watch record changed during open"));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(meta.len() as usize)
        .map_err(|_| invalid("watch record allocation refused"))?;
    file.by_ref()
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() as u64 != meta.len() || bytes.len() > maximum {
        return Err(invalid("watch record length changed"));
    }
    let named = fs::symlink_metadata(path).map_err(io)?;
    let held = file.metadata().map_err(io)?;
    if [named, held].iter().any(|current| {
        !current.is_file()
            || current.mode() & 0o777 != 0o600
            || current.nlink() != 1
            || (current.dev(), current.ino(), current.len()) != (meta.dev(), meta.ino(), meta.len())
    }) {
        return Err(invalid("watch record changed during read"));
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

    fn empty_frame(format: Format, terminal: Option<TerminalDispatch>) -> Vec<u8> {
        let mut bytes = if terminal.is_some() {
            TERMINAL_MAGIC
        } else {
            MAGIC
        }
        .to_vec();
        bytes.extend([1; 32]);
        bytes.extend([2; 32]);
        bytes.push(if format == Format::Sha1 { 1 } else { 2 });
        bytes.extend(vec![3; format.digest_len()]);
        bytes.extend(0u32.to_be_bytes());
        if let Some(terminal) = terminal {
            bytes.extend((terminal.selected as u32).to_be_bytes());
            bytes.push(terminal.reason);
            bytes.extend(terminal.plan);
        }
        bytes.extend(sha256_digest(&bytes));
        bytes
    }

    #[test]
    fn stopped_empty_prefix_requires_v2_exact_plan_and_explicit_terminal_reason() {
        for format in [Format::Sha1, Format::Sha256] {
            let terminal = TerminalDispatch::from_native(2, "request_stopped", [9; 32]).unwrap();
            let bytes = empty_frame(format, Some(terminal));
            let key = hex(&[2; 32]);
            let decoded = Sources::decode(&bytes, &[1; 32], &key).unwrap();
            assert_eq!(decoded.terminal, Some(terminal));
            assert!(decoded.runs.is_empty());
            assert!(decoded.verify_selection(2, [9; 32]).is_ok());
            assert!(decoded.verify_selection(1, [9; 32]).is_err());
            assert!(decoded.verify_selection(2, [8; 32]).is_err());
            let legacy = empty_frame(format, None);
            let decoded = Sources::decode(&legacy, &[1; 32], &key).unwrap();
            assert!(decoded.terminal.is_none());
            assert!(decoded.verify_selection(2, [9; 32]).is_err());
            assert!(decoded.verify_selection(0, [9; 32]).is_ok());
            for reason in [0, 2, 3, 4, 5, 6, 255] {
                let changed = empty_frame(format, Some(TerminalDispatch { reason, ..terminal }));
                assert!(
                    Sources::decode(&changed, &[1; 32], &key).is_err(),
                    "reason {reason}"
                );
            }
            for length in 0..bytes.len() {
                assert!(Sources::decode(&bytes[..length], &[1; 32], &key).is_err());
            }
            for index in 0..bytes.len() {
                let mut altered = bytes.clone();
                altered[index] ^= 1;
                assert!(Sources::decode(&altered, &[1; 32], &key).is_err());
            }
            assert_eq!(decoded.identity, sha256_digest(&legacy));
        }
    }

    #[test]
    fn unclosed_or_unknown_dispatch_reasons_cannot_mint_terminal_custody() {
        assert!(TerminalDispatch::from_native(1, "containment_unproved", [1; 32]).is_err());
        assert!(TerminalDispatch::from_native(1, "", [1; 32]).is_err());
        assert!(TerminalDispatch::from_native(33, "request_stopped", [1; 32]).is_err());
        for reason in [
            "request_stopped",
            "output_budget_exhausted",
            "workflow_refused",
            "workflow_timed_out",
            "workflow_output_limit",
        ] {
            assert!(TerminalDispatch::from_native(1, reason, [1; 32]).is_ok());
        }
        assert!(checkpoint(&|| false).is_err());
        assert!(checkpoint(&|| true).is_ok());
    }
}
