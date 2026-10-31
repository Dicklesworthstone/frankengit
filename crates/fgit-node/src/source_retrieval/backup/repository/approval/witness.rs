//! Independently retained recovery observations, never repository authority.
//! The lease spans intake and native work. Unfinished ownership and uncertain
//! persistence remain blocking; release is an explicit settled-work operation.

#[cfg(unix)]
mod filesystem;
#[cfg(unix)]
mod state;

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::super::super::emit;
#[cfg(unix)]
use super::super::super::{hex, quote};
use super::super::profile::{Profile, ProfileFlags};
use super::observation::LoadedApprovalTrust;
use super::{
    AuthenticatedApprovalObservation, Deadline, SelectionTrustFlags, SelectionTrustOptions,
};

#[cfg(unix)]
use filesystem::{Lease, StateFile};
#[cfg(unix)]
use state::State;

pub(in super::super) const USAGE: &str =
    "usage: fg backup witness init|inspect <directory> --trusted-local
         --trust-key <independently-trusted-public-PEM>
         --tenant-id <hex> --repository-id <hex> --incarnation-id <hex>
         --object-format sha1|sha256 --minimum-head-generation <positive-u64>
         [--timeout-secs <1..86400>]

init creates a NEW owner-private witness directory under an existing private
parent. inspect reauthenticates the retained original signatures and takes the
same exclusive lease as native witnessed recovery. Initialization is never
implicit; missing or corrupt state refuses instead of becoming empty state.

Retain this directory independently of repositories and recovery artifacts.
A stronger supplied generation floor is durably retained; weakening it refuses.
Authenticated higher observations remain remembered even if expired, unavailable
or outside a later operation's payload allowance. Conflicting highest statements
remain blocking until a strictly higher authenticated observation supersedes them.
The state uses the existing repository_backup_witness_v1 JSON, bounded at 64 KiB.

Only the independently supplied key and exact namespace are trusted. Changing
keys, namespaces or an entire witness directory is never an implicit migration.
These tools do not prove global freshness, completeness of a checkpoint set,
native archive validity, canonical authorization, or a complete signed Capsule.

Unix stable owner-controlled private paths are required. A create-only durable
lease excludes cooperating owners; process death or uncertain state persistence
leaves it blocking. There is no PID/age-based lock stealing or automatic reset.
Do not remove a retained lease until all associated work is independently known
to have stopped and the latest retained state has been preserved and inspected.
One original deadline covers work; final settled cleanup cannot undo completed
native publication. Exit 0: initialization/inspection and cleanup completed;
2: refusal, uncertainty, cleanup failure or receipt-output failure.";

#[derive(Debug)]
pub(in super::super) struct WitnessSnapshot {
    json: String,
}

impl WitnessSnapshot {
    pub(in super::super) fn json(&self) -> &str {
        &self.json
    }
}

pub(in super::super) fn initialize(
    directory: &Path,
    trust: &LoadedApprovalTrust,
    deadline: Deadline,
) -> Result<WitnessSnapshot, String> {
    deadline.check()?;
    trust.check_deadline()?;
    #[cfg(unix)]
    {
        let state = State::empty(trust);
        let bytes = state.encode(trust)?;
        let directory = filesystem::initialize(directory, &bytes, deadline)?;
        Ok(WitnessSnapshot {
            json: format!(
                concat!(
                    "{{\"type\":\"repository_backup_witness_initialized\",\"schema_version\":1,",
                    "\"directory\":{},\"initialized\":true,\"complete\":true,",
                    "\"policy\":{},\"trusted_key_id\":{},\"state_sha256\":{},",
                    "\"publication_state\":\"durable\",\"newest_checkpoint_verified\":false,",
                    "\"repository_changed\":false}}"
                ),
                quote(&directory.display().to_string()),
                state::policy_json(trust.policy()),
                quote(trust.trusted_key_id()),
                quote(&hex(&super::sha256(&bytes))),
            ),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
        Err(unsupported())
    }
}

/// No Drop implementation removes the lease. Dropping an unfinished guard
/// closes descriptors while retaining evidence of unfinished responsibility.
pub(in super::super) struct WitnessGuard<'a> {
    directory: PathBuf,
    trust: &'a LoadedApprovalTrust,
    deadline: Deadline,
    poisoned: bool,
    #[cfg(unix)]
    lease: Lease,
    #[cfg(unix)]
    original: StateFile,
    #[cfg(unix)]
    state: State,
    #[cfg(unix)]
    selected: Option<(u64, String)>,
}

impl fmt::Debug for WitnessGuard<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WitnessGuard")
            .field("directory", &self.directory)
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl<'a> WitnessGuard<'a> {
    pub(in super::super) fn directory(&self) -> &Path {
        &self.directory
    }

    pub(in super::super) fn open(
        directory: &Path,
        trust: &'a LoadedApprovalTrust,
        deadline: Deadline,
    ) -> Result<Self, String> {
        deadline.check()?;
        trust.check_deadline()?;
        #[cfg(unix)]
        {
            let lease = Lease::acquire(directory, deadline)?;
            let loaded = (|| {
                let original = lease.state(deadline)?;
                let state = State::decode(&original.bytes, trust)?;
                Ok((original, state))
            })();
            let (original, state) = match loaded {
                Ok(loaded) => loaded,
                Err(error) => {
                    return match lease.release() {
                        Ok(()) => Err(error),
                        Err(cleanup) => {
                            Err(format!("{error}; witness lease cleanup failed: {cleanup}"))
                        }
                    };
                }
            };
            let mut guard = Self {
                directory: lease.path().to_path_buf(),
                trust,
                deadline,
                poisoned: false,
                lease,
                original,
                state,
                selected: None,
            };
            if trust.policy().minimum_generation > guard.state.floor {
                // The external stronger floor is now an obligation. No failed
                // allocation, deadline or synchronization may forget it.
                guard.poisoned = true;
                let mut observations = Vec::with_capacity(guard.state.observations.len());
                for observed in &guard.state.observations {
                    observations.push(
                        trust
                            .inspect_bytes(observed.envelope_bytes())
                            .map_err(|error| guard.retained_error(&error))?,
                    );
                }
                let next = State {
                    floor: trust.policy().minimum_generation,
                    observations,
                };
                guard.persist(next, |_| Ok(()))?;
            }
            Ok(guard)
        }
        #[cfg(not(unix))]
        {
            let _ = directory;
            Err(unsupported())
        }
    }

    fn live(&self) -> Result<(), String> {
        if self.poisoned {
            return Err(self.retained_error("backup witness persistence is poisoned"));
        }
        self.deadline.check()?;
        self.trust.check_deadline()
    }

    fn retained_error(&self, error: &str) -> String {
        format!(
            "{error}; witness_lock_retained=true at {}; preserve and inspect the witness before retrying",
            self.directory.display()
        )
    }

    pub(in super::super) fn observe(
        &mut self,
        observation: &AuthenticatedApprovalObservation,
    ) -> Result<(), String> {
        #[cfg(unix)]
        {
            self.observe_with_checkpoints(observation, |_| Ok(()))
        }
        #[cfg(not(unix))]
        {
            let _ = observation;
            Err(unsupported())
        }
    }

    #[cfg(unix)]
    fn observe_with_checkpoints(
        &mut self,
        observation: &AuthenticatedApprovalObservation,
        checkpoint: impl FnMut(filesystem::Checkpoint) -> Result<(), String>,
    ) -> Result<(), String> {
        if self.poisoned {
            return Err(self.retained_error("backup witness persistence is poisoned"));
        }
        if !self.trust.matches_observation(observation) {
            return Err(
                "backup witness observation does not belong to the captured independent trust"
                    .into(),
            );
        }
        let highest = self
            .state
            .observations
            .first()
            .map_or(0, AuthenticatedApprovalObservation::generation);
        let higher = observation.generation() > highest;
        let conflict = observation.generation() == highest
            && self.state.observations.len() == 1
            && !observation.same_statement(&self.state.observations[0]);
        if higher || conflict {
            // The typed incoming value already authenticated this knowledge.
            // Poison before any new deadline check, allocation or persistence.
            self.poisoned = true;
            if self.selected.is_some() {
                return Err(self.retained_error(
                    "backup witness received new evidence after binding native selection",
                ));
            }
            let mut observations = Vec::with_capacity(if conflict { 2 } else { 1 });
            if conflict {
                observations.push(
                    self.trust
                        .inspect_bytes(self.state.observations[0].envelope_bytes())
                        .map_err(|error| self.retained_error(&error))?,
                );
            }
            observations.push(
                self.trust
                    .inspect_bytes(observation.envelope_bytes())
                    .map_err(|error| self.retained_error(&error))?,
            );
            self.persist(
                State {
                    floor: self.state.floor,
                    observations,
                },
                checkpoint,
            )
        } else {
            self.live()?;
            self.lease.check_state(&self.original, self.deadline)
        }
    }

    #[cfg(unix)]
    fn persist(
        &mut self,
        next: State,
        checkpoint: impl FnMut(filesystem::Checkpoint) -> Result<(), String>,
    ) -> Result<(), String> {
        self.poisoned = true;
        let bytes = next
            .encode(self.trust)
            .map_err(|error| self.retained_error(&error))?;
        let current = self
            .lease
            .replace(&self.original, &bytes, self.deadline, checkpoint)
            .map_err(|error| self.retained_error(&error))?;
        self.original = current;
        self.state = next;
        self.poisoned = false;
        Ok(())
    }

    /// Bind a typed winner only after every supplied observation has been
    /// retained. Later native publication checks require this same statement.
    pub(in super::super) fn require(
        &mut self,
        observation: &AuthenticatedApprovalObservation,
    ) -> Result<(), String> {
        self.live()?;
        #[cfg(unix)]
        {
            self.lease.check_state(&self.original, self.deadline)?;
            if !self.trust.matches_observation(observation) {
                return Err("backup witness selected approval belongs to different trust".into());
            }
            let highest = self
                .state
                .observations
                .first()
                .ok_or("backup witness has no authenticated observation for this selection")?;
            if observation.generation() < highest.generation()
                || observation.generation() < self.state.floor
            {
                return Err("selected backup is below the independently retained witness".into());
            }
            if self.state.observations.len() == 2 {
                return Err(
                    "backup witness retains conflicting highest-generation statements".into(),
                );
            }
            if !observation.same_statement(highest) {
                return Err("selected backup statement does not match retained witness".into());
            }
            self.selected = Some((
                observation.generation(),
                observation.statement_json().to_owned(),
            ));
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = observation;
            Err(unsupported())
        }
    }

    pub(in super::super) fn check_selected(&self) -> Result<(), String> {
        self.live()?;
        #[cfg(unix)]
        {
            let (generation, statement) = self
                .selected
                .as_ref()
                .ok_or("backup witness has no bound native selection")?;
            self.lease.check_state(&self.original, self.deadline)?;
            if self.state.observations.len() != 1
                || *generation < self.state.floor
                || self.state.observations[0].generation() != *generation
                || self.state.observations[0].statement_json() != statement
            {
                return Err("backup witness no longer permits the bound native selection".into());
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            Err(unsupported())
        }
    }

    pub(in super::super) fn snapshot_json(&self) -> String {
        #[cfg(unix)]
        {
            let highest = self.state.observations.first().map_or_else(
                || "null".into(),
                |value| quote(&value.generation().to_string()),
            );
            format!(
                concat!(
                    "{{\"directory\":{},\"minimum_head_generation\":{},\"highest_observed_generation\":{},",
                    "\"conflicting_statements\":{},\"state_sha256\":{},\"newest_checkpoint_verified\":false}}"
                ),
                quote(&self.directory.display().to_string()),
                quote(&self.state.floor.to_string()),
                highest,
                self.state.observations.len() == 2,
                quote(&hex(&super::sha256(&self.original.bytes))),
            )
        }
        #[cfg(not(unix))]
        {
            "{\"supported\":false}".into()
        }
    }

    /// The caller has settled native work. Release ignores a late clock/deadline
    /// failure, so cleanup never reclassifies an already completed publication.
    pub(in super::super) fn finish(self) -> Result<(), String> {
        if self.poisoned {
            return Err(self.retained_error(
                "backup witness failed to retain authenticated recovery evidence",
            ));
        }
        #[cfg(unix)]
        {
            self.lease
                .check_custody(&self.original)
                .map_err(|error| self.retained_error(&error))?;
            self.lease.release()
        }
        #[cfg(not(unix))]
        {
            Err(unsupported())
        }
    }

    /// Native containment may be unresolved. Close local descriptors while
    /// deliberately retaining the exclusive marker for independent inspection.
    pub(in super::super) fn retain(self, reason: &str) -> String {
        self.retained_error(reason)
    }
}

#[cfg(not(unix))]
fn unsupported() -> String {
    "backup witness requires the Unix stable private-file and durable create-only lease profile"
        .into()
}

#[derive(Clone, Copy)]
enum Operation {
    Initialize,
    Inspect,
}

struct Options {
    operation: Operation,
    directory: PathBuf,
    trust: SelectionTrustOptions,
    profile: Profile,
}

fn parse(args: &[String]) -> Result<Options, String> {
    if !(16..=18).contains(&args.len())
        || args[0] != "witness"
        || args
            .iter()
            .any(|value| value.is_empty() || value.len() > 8192 || value.contains('\0'))
        || args.iter().map(String::len).sum::<usize>() > 32768
    {
        return Err(USAGE.into());
    }
    let operation = match args[1].as_str() {
        "init" => Operation::Initialize,
        "inspect" => Operation::Inspect,
        _ => return Err(USAGE.into()),
    };
    let directory = PathBuf::from(&args[2]);
    if directory.file_name().is_none() {
        return Err("backup witness requires a named directory".into());
    }
    let mut trust = SelectionTrustFlags::default();
    let mut profile = ProfileFlags::default();
    let mut trusted = false;
    let mut cursor = 3;
    while let Some(flag) = args.get(cursor) {
        cursor += 1;
        if flag == "--trusted-local" && !trusted {
            trusted = true;
            continue;
        }
        let value = args
            .get(cursor)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        if flag == "--timeout-secs" {
            profile.set(flag, value)?;
        } else if SelectionTrustFlags::accepts(flag) {
            trust.set(flag, value)?;
        } else {
            return Err(format!(
                "unknown or duplicate backup witness option: {flag}"
            ));
        }
    }
    if !trusted {
        return Err("backup witness requires --trusted-local".into());
    }
    Ok(Options {
        operation,
        directory,
        trust: trust.finish()?,
        profile: profile.finish(),
    })
}

pub(in super::super) fn run(
    args: &[String],
    output: &mut impl Write,
    timeout: Option<Duration>,
) -> Result<(), String> {
    if args == ["witness", "--help"] {
        return emit(output, USAGE);
    }
    let mut options = parse(args)?;
    options.profile = options.profile.with_timeout_cap(timeout)?;
    let deadline = options.profile.start();
    let trust = options.trust.load(deadline)?;
    #[cfg(unix)]
    {
        let witness = filesystem::physical_directory(&options.directory)?;
        let key = std::fs::canonicalize(options.trust.trust_key_path())
            .map_err(|error| error.to_string())?;
        if key.starts_with(&witness) || witness.starts_with(&key) {
            return Err("backup witness must remain independent of its trusted key path".into());
        }
    }
    let receipt = match options.operation {
        Operation::Initialize => initialize(&options.directory, &trust, deadline)?
            .json()
            .to_owned(),
        Operation::Inspect => {
            let guard = WitnessGuard::open(&options.directory, &trust, deadline)?;
            let view = guard.snapshot_json();
            guard
                .finish()
                .map_err(|error| format!("backup witness inspected; cleanup failed: {error}"))?;
            format!(
                "{{\"type\":\"repository_backup_witness_inspection\",\"schema_version\":1,\"complete\":true,\"witness\":{view},\"repository_changed\":false}}"
            )
        }
    };
    emit(output, &receipt).map_err(|error| format!("backup witness operation completed; preserve retained state; receipt output failed: {error}"))
}

#[cfg(all(test, unix))]
mod tests;
