//! Bounded creation-only landing attempts and non-authoritative acknowledgements.
//! The exact original candidate supplies every command field on reconstruction.

use super::{
    File, OneNode, Path, PrincipalId, QueueCandidateLandingCommand, TerminalOutcome,
    TrustedWorkflowFailure, check_directory, commitment, fs, hex, invalid, invalid_owned, io,
    lower_hash, reporting, write_new,
};
use crate::LoopbackReceiveSession;
use fgit_admission::AdmissionContext;
use fgit_admission::merge::native::queue::candidate_landing_proposal;
use fgit_authority::IdempotencyKey;
use fgit_crypto::{DigestAlgorithm, sha256_digest};
use fgit_types::{DecisionOutcome, RepositoryAuthorityHeadId, TxId};
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::DirBuilderExt;

const MAX_ATTEMPTS: usize = 32;
const MAX_RECORD: usize = 512;
const MAGIC: &[u8; 8] = b"FGQLA001";
const ACK_MAGIC: &[u8; 8] = b"FGQLR001";
const ACK_BYTES: usize = 81;
const DIRECTORY: &str = "landing-attempts";

pub(super) struct Attempt {
    identity: [u8; 32],
    event: [u8; 32],
    basis: [u8; 32],
    key: [u8; 32],
    lander: PrincipalId,
    pub(super) tx_id: TxId,
}

impl Attempt {
    pub(super) fn new(
        node: &OneNode,
        lander: PrincipalId,
        command: &QueueCandidateLandingCommand,
        identity: [u8; 32],
        event: [u8; 32],
        basis: RepositoryAuthorityHeadId,
    ) -> Result<Self, TrustedWorkflowFailure> {
        let native = basis.as_internal_object_id();
        if native.algorithm() != DigestAlgorithm::Sha256.id() {
            return Err(invalid(
                "queue landing custody requires SHA-256 authority identities",
            ));
        }
        let basis = native
            .digest()
            .as_bytes()
            .try_into()
            .map_err(|_| invalid("invalid queue landing authority width"))?;
        Self::from_basis(node, lander, command, identity, event, basis)
    }

    fn from_basis(
        node: &OneNode,
        lander: PrincipalId,
        command: &QueueCandidateLandingCommand,
        identity: [u8; 32],
        event: [u8; 32],
        basis: [u8; 32],
    ) -> Result<Self, TrustedWorkflowFailure> {
        let key = commitment(&[
            b"frankengit/queue-watch-landing-attempt/v1",
            &identity,
            &event,
            &basis,
        ]);
        let context = AdmissionContext {
            head_key: node.head_key.clone(),
            tenant_id: node.tenant_id(),
            repository_id: node.repository_id(),
            principal_id: lander,
            idempotency_key: IdempotencyKey::new(key.to_vec())
                .map_err(|_| invalid("invalid queue landing retry key"))?,
            object_format: node.object_format(),
        };
        let (_, seal) = candidate_landing_proposal(&context, command)
            .map_err(|error| invalid_owned(error.to_string()))?;
        let tx_id = seal
            .derive()
            .map_err(|error| invalid_owned(error.to_string()))?
            .0;
        Ok(Self {
            identity,
            event,
            basis,
            key,
            lander,
            tx_id,
        })
    }

    pub(super) fn decode(
        node: &OneNode,
        lander: PrincipalId,
        command: &QueueCandidateLandingCommand,
        identity: [u8; 32],
        event: [u8; 32],
        name: &str,
        bytes: &[u8],
    ) -> Result<Self, TrustedWorkflowFailure> {
        if bytes.len() < 136 || bytes.len() > MAX_RECORD || bytes.get(..8) != Some(MAGIC.as_slice())
        {
            return Err(invalid("invalid original queue landing attempt"));
        }
        let basis = bytes[72..104]
            .try_into()
            .map_err(|_| invalid("invalid queue landing basis"))?;
        let attempt = Self::from_basis(node, lander, command, identity, event, basis)?;
        // Re-derive the key and transaction from independently reconstructed
        // repository, operator, event and command coordinates. Stored bytes
        // never choose another principal or refreshed source/target leases.
        if attempt.name() != name || attempt.bytes() != bytes {
            return Err(invalid("queue landing attempt binding or checksum differs"));
        }
        Ok(attempt)
    }

    pub(super) fn session(&self) -> LoopbackReceiveSession {
        LoopbackReceiveSession::authenticated(
            self.lander,
            IdempotencyKey::new(self.key.to_vec()).expect("32-byte retry key"),
        )
    }

    fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(MAX_RECORD);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.identity);
        bytes.extend_from_slice(&self.event);
        bytes.extend_from_slice(&self.basis);
        bytes.extend_from_slice(self.tx_id.to_string().as_bytes());
        let digest = sha256_digest(&bytes);
        bytes.extend_from_slice(&digest);
        bytes
    }

    fn name(&self) -> String {
        format!("attempt-{}", hex(&self.key))
    }
    fn outcome_name(&self) -> String {
        format!("outcome-{}", hex(&self.key))
    }
}

/// Empty means no submission was reserved in this event. An unknown, partial,
/// foreign, oversized or orphaned record blocks later selection.
pub(super) fn records(path: &Path) -> Result<Vec<(String, Vec<u8>)>, TrustedWorkflowFailure> {
    let directory = path.join(DIRECTORY);
    match fs::symlink_metadata(&directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(io(error)),
        Ok(_) => check_directory(&directory)?,
    }
    let entries = fs::read_dir(&directory)
        .map_err(io)?
        .take(MAX_ATTEMPTS * 2 + 1)
        .collect::<Result<Vec<_>, _>>()
        .map_err(io)?;
    if entries.len() > MAX_ATTEMPTS * 2 {
        return Err(invalid("queue landing attempt bound exceeded"));
    }
    let mut attempts = BTreeMap::new();
    let mut outcomes = BTreeSet::new();
    for entry in entries {
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| invalid("invalid queue landing custody entry"))?;
        if let Some(key) = name.strip_prefix("attempt-").filter(|key| lower_hash(key)) {
            attempts.insert(
                key.to_owned(),
                (
                    name.to_owned(),
                    reporting::read_private(&entry.path(), MAX_RECORD)?,
                ),
            );
        } else if let Some(key) = name.strip_prefix("outcome-").filter(|key| lower_hash(key)) {
            // Reject symlinks, hard links and unbounded files even before the
            // corresponding command has been reconstructed.
            let _ = reporting::read_private(&entry.path(), ACK_BYTES)?;
            outcomes.insert(key.to_owned());
        } else {
            return Err(invalid("unknown queue landing custody entry"));
        }
    }
    if attempts.len() > MAX_ATTEMPTS || outcomes.iter().any(|key| !attempts.contains_key(key)) {
        return Err(invalid(
            "orphaned or excessive queue landing acknowledgement",
        ));
    }
    Ok(attempts.into_values().collect())
}

pub(super) fn retain(path: &Path, attempt: &Attempt) -> Result<(), TrustedWorkflowFailure> {
    let existing = records(path)?;
    let bytes = attempt.bytes();
    if bytes.len() > MAX_RECORD {
        return Err(invalid(
            "queue landing attempt record exceeds its byte bound",
        ));
    }
    if let Some((_, old)) = existing.iter().find(|(name, _)| *name == attempt.name()) {
        if *old != bytes {
            return Err(invalid("original queue landing attempt changed"));
        }
        return sync(
            &path.join(DIRECTORY),
            &path.join(DIRECTORY).join(attempt.name()),
        );
    }
    if existing.len() >= MAX_ATTEMPTS {
        return Err(invalid("queue landing event attempt bound exceeded"));
    }
    let directory = path.join(DIRECTORY);
    match fs::DirBuilder::new().mode(0o700).create(&directory) {
        Ok(()) => File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(io)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(io(error)),
    }
    check_directory(&directory)?;
    let file = directory.join(attempt.name());
    write_new(&file, &bytes).map_err(io)?;
    sync(&directory, &file)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Acknowledgement {
    Committed,
    Refused,
}

pub(super) fn acknowledged(
    path: &Path,
    attempt: &Attempt,
) -> Result<Option<(Acknowledgement, u64)>, TrustedWorkflowFailure> {
    let file = path.join(DIRECTORY).join(attempt.outcome_name());
    match fs::symlink_metadata(&file) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io(error)),
        Ok(_) => {}
    }
    let bytes = reporting::read_private(&file, ACK_BYTES)?;
    if bytes.len() != ACK_BYTES
        || &bytes[..8] != ACK_MAGIC
        || bytes[8..40] != sha256_digest(&attempt.bytes())
        || bytes[41..49] == [0; 8]
        || bytes[49..] != sha256_digest(&bytes[..49])
    {
        return Err(invalid("invalid queue landing acknowledgement"));
    }
    let ack = match bytes[40] {
        1 => Acknowledgement::Committed,
        2 => Acknowledgement::Refused,
        _ => return Err(invalid("invalid queue landing acknowledgement outcome")),
    };
    let sequence = u64::from_be_bytes(
        bytes[41..49]
            .try_into()
            .map_err(|_| invalid("invalid queue landing acknowledgement sequence"))?,
    );
    sync(&path.join(DIRECTORY), &file)?;
    Ok(Some((ack, sequence)))
}

pub(super) fn acknowledge(
    path: &Path,
    attempt: &Attempt,
    terminal: &TerminalOutcome,
) -> Result<(), TrustedWorkflowFailure> {
    let tag = if matches!(terminal.outcome, DecisionOutcome::Committed { .. }) {
        1
    } else {
        2
    };
    let mut bytes = Vec::with_capacity(ACK_BYTES);
    bytes.extend_from_slice(ACK_MAGIC);
    bytes.extend_from_slice(&sha256_digest(&attempt.bytes()));
    bytes.push(tag);
    bytes.extend_from_slice(&terminal.decision_sequence.get().to_be_bytes());
    let digest = sha256_digest(&bytes);
    bytes.extend_from_slice(&digest);
    let directory = path.join(DIRECTORY);
    check_directory(&directory)?;
    let file = directory.join(attempt.outcome_name());
    write_new(&file, &bytes).map_err(io)?;
    sync(&directory, &file)
}

fn sync(directory: &Path, file: &Path) -> Result<(), TrustedWorkflowFailure> {
    File::open(file)
        .and_then(|file| file.sync_all())
        .and_then(|()| File::open(directory)?.sync_all())
        .map_err(io)
}

#[cfg(test)]
mod tests;
