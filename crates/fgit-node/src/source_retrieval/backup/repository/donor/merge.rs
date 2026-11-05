//! One bounded merge of selected native identities and a verified donor stream.
//!
//! This module owns no archive codec, authority, path, or publication. The
//! caller supplies the current selected set, a scan that authenticates its
//! original complete donor at EOF, and the existing identity-checking encoder.
//! Donor overlap is selected before any local read: a half-written local blob
//! must never be retried as a different source inside an already started record.

use std::collections::BTreeSet;
use std::io::{self, Read};

use fgit_types::{GitHashAlgorithm, GitOid};

const CHUNK_BYTES: usize = 64 * 1024;

pub(super) trait Record: Copy {
    fn oid(self) -> GitOid;
    fn length(self) -> u64;
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Limits {
    pub format: GitHashAlgorithm,
    pub donor_objects: usize,
    pub max_objects: usize,
    pub max_donor_payload_bytes: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Counts {
    pub donor_objects: usize,
    pub donor_payload_bytes: u64,
    pub local_objects: usize,
}

pub(super) enum Source<'a, H> {
    Local(GitOid),
    Donor(H, &'a mut dyn Read),
}

/// Stream each selected identity exactly once in native-identity order. Even
/// ignored donor rows are consumed through verified EOF. A successful callback
/// must consume the complete selected donor body; swallowing a callback/read
/// error cannot turn this invocation into a successful composition.
///
/// `scan` MUST recheck its original whole-file commitment before returning Ok.
/// Output remains private until the ordinary complete archive/graph/head checks
/// and create-only publication finish. Counts are not an authority receipt.
pub(super) fn compose<H: Record>(
    selected: &BTreeSet<GitOid>,
    limits: Limits,
    scan: impl FnOnce(&mut dyn FnMut(H, &mut dyn Read) -> Result<(), String>) -> Result<(), String>,
    mut emit: impl FnMut(Source<'_, H>) -> Result<(), String>,
    mut live: impl FnMut() -> Result<(), String>,
) -> Result<Counts, String> {
    live()?;
    if limits.max_objects == 0
        || selected.len() > limits.max_objects
        || limits.donor_objects > limits.max_objects
        || limits.max_donor_payload_bytes == 0
    {
        return Err("donor composition object or payload limit".into());
    }
    for oid in selected {
        live()?;
        if oid.algorithm() != limits.format || oid.is_zero() {
            return Err("donor composition selected object domain mismatch".into());
        }
    }
    let mut remaining = selected.iter().copied().peekable();
    let mut previous = None;
    let mut visited = 0usize;
    let mut donor_bytes = 0_u64;
    let mut counts = Counts::default();
    let mut failed: Option<String> = None;
    let mut discard = Vec::new();
    discard
        .try_reserve_exact(CHUNK_BYTES)
        .map_err(|_| "donor composition discard buffer allocation refused")?;
    discard.resize(CHUNK_BYTES, 0);
    scan(&mut |header, input| {
        if let Some(error) = &failed {
            return Err(error.clone());
        }
        let result: Result<(), String> = (|| {
            live()?;
            let oid = header.oid();
            if visited >= limits.donor_objects
                || oid.algorithm() != limits.format
                || oid.is_zero()
                || previous.is_some_and(|last| last >= oid)
            {
                return Err("donor composition record order, count or domain mismatch".into());
            }
            let next_bytes = donor_bytes
                .checked_add(header.length())
                .filter(|bytes| *bytes <= limits.max_donor_payload_bytes)
                .ok_or("donor composition payload limit")?;
            while remaining.peek().is_some_and(|next| *next < oid) {
                live()?;
                let local = remaining.next().ok_or("donor composition cursor lost")?;
                emit(Source::Local(local))?;
                live()?;
                counts.local_objects += 1;
            }
            let selected_here = remaining.peek() == Some(&oid);
            let mut body = Payload::new(input, header.length(), &mut live);
            if selected_here {
                let _ = remaining.next();
                emit(Source::Donor(header, &mut body))?;
                body.finish()?;
                counts.donor_objects += 1;
                counts.donor_payload_bytes = counts
                    .donor_payload_bytes
                    .checked_add(header.length())
                    .ok_or("donor composition byte count overflow")?;
            } else {
                while body.read(&mut discard).map_err(|error| error.to_string())? != 0 {}
                body.finish()?;
            }
            live()?;
            visited += 1;
            donor_bytes = next_bytes;
            previous = Some(oid);
            Ok(())
        })();
        if let Err(error) = &result {
            failed = Some(error.clone());
        }
        result
    })?;
    if let Some(error) = failed {
        return Err(error);
    }
    live()?;
    if visited != limits.donor_objects {
        return Err("donor composition incomplete donor inventory".into());
    }
    // The local tail starts only after the scan reauthenticated the complete
    // original donor, including rows which were not selected for this output.
    for oid in remaining {
        live()?;
        emit(Source::Local(oid))?;
        live()?;
        counts.local_objects += 1;
    }
    if counts.donor_objects.checked_add(counts.local_objects) != Some(selected.len()) {
        return Err("donor composition incomplete selected inventory".into());
    }
    live()?;
    Ok(counts)
}

struct Payload<'a, L> {
    input: &'a mut dyn Read,
    remaining: u64,
    live: &'a mut L,
    eof: bool,
    failed: Option<String>,
}

impl<'a, L: FnMut() -> Result<(), String>> Payload<'a, L> {
    fn new(input: &'a mut dyn Read, length: u64, live: &'a mut L) -> Self {
        Self {
            input,
            remaining: length,
            live,
            eof: false,
            failed: None,
        }
    }

    fn finish(&mut self) -> Result<(), String> {
        if let Some(error) = &self.failed {
            return Err(error.clone());
        }
        if self.remaining != 0 {
            return Err("selected donor payload was not completely consumed".into());
        }
        // Force the underlying record's authenticated EOF even if a sink used
        // read_exact and would otherwise stop immediately after the last byte.
        self.read(&mut [0]).map_err(|error| error.to_string())?;
        (self.live)()
    }

    fn read_inner(&mut self, output: &mut [u8]) -> Result<usize, String> {
        (self.live)()?;
        if output.is_empty() || self.eof {
            return Ok(0);
        }
        let end = self.remaining == 0;
        let mut probe = [0];
        let offered = if end {
            &mut probe[..]
        } else {
            let count = output
                .len()
                .min(CHUNK_BYTES)
                .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
            &mut output[..count]
        };
        let count = loop {
            (self.live)()?;
            match self.input.read(offered) {
                Ok(count) if count <= offered.len() => break count,
                Ok(_) => return Err("donor source returned an invalid byte count".into()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(format!("donor payload read failed: {error}")),
            }
        };
        (self.live)()?;
        if end {
            if count != 0 {
                return Err("donor payload exceeds its declared length".into());
            }
            self.eof = true;
            Ok(0)
        } else if count == 0 {
            Err("donor payload is truncated".into())
        } else {
            self.remaining -= count as u64;
            Ok(count)
        }
    }
}

impl<L: FnMut() -> Result<(), String>> Read for Payload<'_, L> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if let Some(error) = &self.failed {
            return Err(io::Error::other(error.clone()));
        }
        let result = self.read_inner(output);
        if let Err(error) = &result {
            self.failed = Some(error.clone());
        }
        result.map_err(io::Error::other)
    }
}

#[cfg(test)]
#[path = "merge/tests.rs"]
mod tests;
