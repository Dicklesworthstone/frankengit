//! Bounded acquisition of one selected canonical statement. This layer owns
//! no authority work and cannot retry after a checksum-pinned archive is accepted.

use std::collections::BTreeSet;
use std::fs::File;

use super::super::super::quote;
use super::super::archive::stream::Seal;
use super::super::input::{DamageKind, PinnedArchive, ReplicaInputFailure};
use super::super::profile::Deadline;
use super::super::recovery_io::{Control, Metered, Source, SourceFailure};
use super::engine::Checkpoint;
use super::{Operation, Options};

enum Outcome {
    Unavailable(String),
    Damaged(DamageKind),
    Duplicate,
    Acquired,
}

struct Attempt {
    candidate: usize,
    outcome: Outcome,
    bytes: u64,
}

impl Attempt {
    fn json(&self) -> String {
        let (outcome, reason) = match &self.outcome {
            Outcome::Unavailable(reason) => ("unavailable", Some(reason.as_str())),
            Outcome::Damaged(kind) => ("damaged", Some(kind.code())),
            Outcome::Duplicate => ("duplicate", None),
            Outcome::Acquired => ("acquired", None),
        };
        format!(
            "{{\"candidate_index\":{},\"outcome\":{},\"bytes_read\":{}{}}}",
            self.candidate,
            quote(outcome),
            self.bytes,
            reason.map_or_else(String::new, |value| format!(",\"reason\":{}", quote(value))),
        )
    }
}

pub(in super::super) struct Report {
    acquired: usize,
    attempts: Vec<Attempt>,
    duplicates: usize,
}

impl Report {
    /// Attempt bytes describe acquisition; totals also include every subsequent
    /// native archive pass through this same ledger, captured after completion.
    pub(in super::super) fn json(&self, control: &Control<'_>, maximum: u64) -> String {
        format!(
            concat!(
                "{{\"acquired_candidate_index\":{},\"candidates_attempted\":{},",
                "\"duplicate_sources_skipped\":{},\"payload_bytes_read\":{},",
                "\"payload_read_calls\":{},\"max_read_bytes\":{},",
                "\"read_budget_scope\":\"all_archive_passes\",\"attempts\":[{}]}}"
            ),
            self.acquired,
            self.attempts.len(),
            self.duplicates,
            control.bytes_read(),
            control.read_calls(),
            maximum,
            self.attempts
                .iter()
                .map(Attempt::json)
                .collect::<Vec<_>>()
                .join(","),
        )
    }
}

pub(in super::super) struct Acquired<'control, 'scope> {
    pub(in super::super) archive: PinnedArchive<Metered<'control, 'scope, File>>,
    // The original descriptor pins the input's metadata while the archive owns
    // its cloned read descriptor. All native work retains this custody check.
    pub(in super::super) source: Source,
    pub(in super::super) report: Report,
}

pub(in super::super) fn acquire<'control, 'scope>(
    options: &Options,
    aliases: &[usize],
    expected: Seal,
    control: &'control Control<'scope>,
    deadline: Deadline,
    mut checkpoint: impl FnMut(Checkpoint) -> Result<(), String>,
) -> Result<Acquired<'control, 'scope>, String> {
    let required = expected
        .bytes
        .checked_mul(match options.operation {
            Operation::Verify => 3,
            Operation::Recover => 6,
        })
        .ok_or("selected replica native read reservation overflow")?;
    let mut identities = BTreeSet::new();
    let mut attempts = Vec::with_capacity(aliases.len());
    let mut duplicates = 0;
    for &index in aliases {
        control.check()?;
        checkpoint(Checkpoint::BeforeReplicaAttempt)?;
        control.check()?;
        let candidate = options
            .candidates
            .get(index)
            .ok_or("selected replica internal candidate mismatch")?;
        let source = match Source::open(&candidate.input, expected.bytes) {
            Ok(source) => source,
            Err(SourceFailure::Unavailable(reason)) => {
                attempts.push(Attempt {
                    candidate: index,
                    outcome: Outcome::Unavailable(reason),
                    bytes: 0,
                });
                checkpoint(Checkpoint::ReplicaUnavailable)?;
                continue;
            }
            Err(SourceFailure::Fatal(error)) => return Err(error),
        };
        control.check()?;
        if !identities.insert(source.identity()) {
            duplicates += 1;
            attempts.push(Attempt {
                candidate: index,
                outcome: Outcome::Duplicate,
                bytes: 0,
            });
            continue;
        }
        if source.length() != expected.bytes {
            attempts.push(Attempt {
                candidate: index,
                outcome: Outcome::Damaged(DamageKind::LengthMismatch),
                bytes: 0,
            });
            checkpoint(Checkpoint::ReplicaUnavailable)?;
            continue;
        }
        // A failed checksum attempt stays charged. Before reading another full
        // copy, preserve enough allowance to finish its entire native operation.
        control.reserve(required)?;
        let start = control.bytes_read();
        let file = source
            .file
            .try_clone()
            .map_err(|error| format!("selected replica descriptor clone failed: {error}"))?;
        let result = PinnedArchive::from_replica_reader(
            Metered {
                input: file,
                control,
            },
            expected,
            options.profile.transfer,
            deadline,
        );
        let bytes = control.bytes_read() - start;
        match result {
            Ok(archive) => {
                // Acceptance is final. Any custody change here or any later
                // native failure refuses this operation instead of another try.
                source.check().map_err(SourceFailure::message)?;
                control.check()?;
                attempts.push(Attempt {
                    candidate: index,
                    outcome: Outcome::Acquired,
                    bytes,
                });
                return Ok(Acquired {
                    archive,
                    source,
                    report: Report {
                        acquired: index,
                        attempts,
                        duplicates,
                    },
                });
            }
            Err(ReplicaInputFailure::Damaged(kind)) => {
                attempts.push(Attempt {
                    candidate: index,
                    outcome: Outcome::Damaged(kind),
                    bytes,
                });
                checkpoint(Checkpoint::ReplicaUnavailable)?;
            }
            Err(ReplicaInputFailure::Fatal(error)) => return Err(error),
        }
    }
    control.check()?;
    Err(format!(
        "no usable copy of the highest selected canonical statement; all {} candidate aliases refused or duplicated; payload_bytes_read={}; lower checkpoints remain ineligible",
        attempts.len(),
        control.bytes_read(),
    ))
}
