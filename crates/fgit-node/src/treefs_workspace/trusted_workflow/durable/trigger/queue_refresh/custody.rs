//! Creation-only custody of the complete original queue-head refresh command.
//! Local acknowledgements never establish a canonical outcome or grant a caller
//! permission to publish as a principal read from disk.

use super::super::{
    File, OneNode, Path, TrustedWorkflowFailure, check_directory, commitment, fs, hex,
    invalid, invalid_owned, io, lower_hash, reporting, write_new,
};
use crate::LoopbackReceiveSession;
use fgit_admission::AdmissionContext;
use fgit_admission::merge::native::queue::{
    QueueHeadRefreshCommand, queue_head_refresh_proposal,
};
use fgit_authority::{IdempotencyKey, TerminalOutcome, canonical_request_digest};
use fgit_crypto::{DigestAlgorithm, sha256_digest};
use fgit_forge::event::pull_request::{
    MAX_BODY_BYTES, MAX_TITLE_BYTES, PullRequestAction, PullRequestCommand, PullRequestData,
};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber, QueueNumber};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, PolicyEpoch, PrincipalId,
    RepositoryAuthorityHeadId, TxId,
};
use std::collections::BTreeSet;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};

pub(super) const MAX_ATTEMPTS: usize = 1024;
const MAX_RECORD: usize = 256 * 1024;
const MAGIC: &[u8; 8] = b"FGQRA001";
const ACK_MAGIC: &[u8; 8] = b"FGQRR001";
const ACK_BYTES: usize = 81;
const DIRECTORY: &str = "queue-refresh";

pub(super) struct Attempt {
    identity: [u8; 32],
    refresher: PrincipalId,
    tenant: [u8; 16],
    repository: [u8; 16],
    incarnation: [u8; 16],
    format: GitHashAlgorithm,
    basis: [u8; 32],
    key: [u8; 32],
    pub(super) tx_id: TxId,
    /// Re-derived native request identity, independent of the selected basis.
    pub(super) semantic: String,
    pub(super) command: QueueHeadRefreshCommand,
}

impl Attempt {
    pub(super) fn new(
        node: &OneNode,
        refresher: PrincipalId,
        command: &QueueHeadRefreshCommand,
        identity: [u8; 32],
        basis: RepositoryAuthorityHeadId,
    ) -> Result<Self, TrustedWorkflowFailure> {
        let native = basis.as_internal_object_id();
        if native.algorithm() != DigestAlgorithm::Sha256.id() {
            return Err(invalid("queue refresh custody requires SHA-256 authority identities"));
        }
        let basis = native.digest().as_bytes().try_into()
            .map_err(|_| invalid("invalid queue refresh authority width"))?;
        Self::from_basis(node, refresher, command, identity, basis)
    }

    fn from_basis(
        node: &OneNode,
        refresher: PrincipalId,
        command: &QueueHeadRefreshCommand,
        identity: [u8; 32],
        basis: [u8; 32],
    ) -> Result<Self, TrustedWorkflowFailure> {
        // Derive the key from the complete native semantic request, including
        // title/body and both target observations. The provisional key is only
        // used to build that pure request; it is never submitted or retained.
        let mut context = AdmissionContext {
            head_key: node.head_key.clone(),
            tenant_id: node.tenant_id(),
            repository_id: node.repository_id(),
            principal_id: refresher,
            idempotency_key: IdempotencyKey::new(
                b"queue-refresh-custody-digest-only".to_vec(),
            ).map_err(|_| invalid("invalid queue refresh digest key"))?,
            object_format: node.object_format(),
        };
        let (_, proposed) = queue_head_refresh_proposal(&context, command)
            .map_err(|error| invalid_owned(error.to_string()))?;
        let semantic = canonical_request_digest(&proposed.request)
            .map_err(|error| invalid_owned(error.to_string()))?;
        let semantic = semantic.to_string();
        let key = commitment(&[
            b"frankengit/queue-watch-refresh-attempt/v1",
            &identity,
            node.tenant_id().as_bytes(),
            node.repository_id().as_bytes(),
            node.repository_incarnation_id().as_bytes(),
            node.object_format().as_str().as_bytes(),
            refresher.as_bytes(),
            &basis,
            semantic.as_bytes(),
        ]);
        context.idempotency_key = IdempotencyKey::new(key.to_vec())
            .map_err(|_| invalid("invalid queue refresh retry key"))?;
        let (_, seal) = queue_head_refresh_proposal(&context, command)
            .map_err(|error| invalid_owned(error.to_string()))?;
        let tx_id = seal.derive().map_err(|error| invalid_owned(error.to_string()))?.0;
        let attempt = Self {
            identity,
            refresher,
            tenant: *node.tenant_id().as_bytes(),
            repository: *node.repository_id().as_bytes(),
            incarnation: *node.repository_incarnation_id().as_bytes(),
            format: node.object_format(),
            basis,
            key,
            tx_id,
            semantic,
            command: command.clone(),
        };
        // Check the exact serialized size before creating any custody file.
        attempt.bytes()?;
        Ok(attempt)
    }

    pub(super) fn decode(
        node: &OneNode,
        refresher: PrincipalId,
        identity: [u8; 32],
        name: &str,
        bytes: &[u8],
    ) -> Result<Self, TrustedWorkflowFailure> {
        check_frame(bytes)?;
        let mut input = Input { bytes: &bytes[..bytes.len() - 32], offset: 8 };
        if input.array::<32>()? != identity
            || input.array::<16>()? != *refresher.as_bytes()
            || input.array::<16>()? != *node.tenant_id().as_bytes()
            || input.array::<16>()? != *node.repository_id().as_bytes()
            || input.array::<16>()? != *node.repository_incarnation_id().as_bytes()
            || input.array::<1>()?[0] != format_tag(node.object_format())
        {
            return Err(invalid("queue refresh attempt scope or principal differs"));
        }
        let basis = input.array::<32>()?;
        let number = QueueNumber::try_new(input.counter()?)
            .ok_or_else(|| invalid("invalid retained queue number"))?;
        let expected_queue_version = AggregateVersion::try_new(input.counter()?)
            .ok_or_else(|| invalid("invalid retained queue version"))?;
        let expected_policy_epoch = PolicyEpoch::try_new(input.counter()?)
            .map_err(|_| invalid("invalid retained queue policy epoch"))?;
        let pull_number = PullRequestNumber::try_new(input.counter()?)
            .ok_or_else(|| invalid("invalid retained pull request number"))?;
        let pull_version = AggregateVersion::try_new(input.counter()?)
            .ok_or_else(|| invalid("invalid retained pull request version"))?;
        let format = node.object_format();
        let expected_recorded_target_tip = input.oid(format)?;
        let source_tip = input.oid(format)?;
        let target_tip = input.oid(format)?;
        let source_ref = fgit_types::RefName::try_new(input.field(MAX_RECORD)?)
            .map_err(|_| invalid("invalid retained source reference"))?;
        let target_ref = fgit_types::RefName::try_new(input.field(MAX_RECORD)?)
            .map_err(|_| invalid("invalid retained target reference"))?;
        let title = input.text(MAX_TITLE_BYTES)?;
        let body = input.text(MAX_BODY_BYTES)?;
        // These fields are re-derived below, never trusted as authority.
        let _stored_key = input.array::<32>()?;
        let _stored_tx = input.field(256)?;
        if input.offset != input.bytes.len() {
            return Err(invalid("trailing queue refresh custody fields"));
        }
        let command = QueueHeadRefreshCommand {
            number,
            expected_queue_version,
            expected_policy_epoch,
            expected_recorded_target_tip,
            pull_request: PullRequestCommand {
                number: pull_number,
                expected_version: ExpectedVersion::Exactly(pull_version),
                action: PullRequestAction::Update,
                data: PullRequestData {
                    source_ref, target_ref, source_tip, target_tip, title, body,
                },
            },
        };
        let attempt = Self::from_basis(node, refresher, &command, identity, basis)?;
        // A rewritten body plus a new local checksum still changes the key,
        // filename and native TxId. It cannot borrow an earlier canonical ACK.
        if attempt.name() != name || attempt.bytes()? != bytes {
            return Err(invalid("queue refresh attempt binding or checksum differs"));
        }
        Ok(attempt)
    }

    pub(super) fn session(&self) -> LoopbackReceiveSession {
        LoopbackReceiveSession::authenticated(
            self.refresher,
            IdempotencyKey::new(self.key.to_vec()).expect("32-byte retry key"),
        )
    }

    pub(super) fn name(&self) -> String {
        format!("attempt-{}", hex(&self.key))
    }

    fn outcome_name(&self) -> String {
        format!("outcome-{}", hex(&self.key))
    }

    fn bytes(&self) -> Result<Vec<u8>, TrustedWorkflowFailure> {
        self.command.proposed_event(self.refresher, self.format)
            .map_err(|_| invalid("invalid original queue refresh command"))?;
        let pull = &self.command.pull_request;
        let ExpectedVersion::Exactly(previous) = pull.expected_version else {
            return Err(invalid("queue refresh requires an exact PR predecessor"));
        };
        let tx = self.tx_id.to_string();
        let fields = [
            pull.data.source_ref.as_bytes(),
            pull.data.target_ref.as_bytes(),
            pull.data.title.as_bytes(),
            pull.data.body.as_bytes(),
            tx.as_bytes(),
        ];
        let mut size = 8 + 32 + 16 * 4 + 1 + 32 + 8 * 5
            + self.format.digest_len() * 3 + 32 + 32;
        for field in &fields {
            if field.len() > u32::MAX as usize {
                return Err(invalid("queue refresh custody field is too large"));
            }
            size = size.checked_add(4).and_then(|size| size.checked_add(field.len()))
                .filter(|size| *size <= MAX_RECORD)
                .ok_or_else(|| invalid("queue refresh attempt record exceeds its byte bound"))?;
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size)
            .map_err(|_| invalid("queue refresh record allocation refused"))?;
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.identity);
        bytes.extend_from_slice(self.refresher.as_bytes());
        bytes.extend_from_slice(&self.tenant);
        bytes.extend_from_slice(&self.repository);
        bytes.extend_from_slice(&self.incarnation);
        bytes.push(format_tag(self.format));
        bytes.extend_from_slice(&self.basis);
        for number in [
            self.command.number.get(),
            self.command.expected_queue_version.get(),
            self.command.expected_policy_epoch.get(),
            pull.number.get(),
            previous.get(),
        ] {
            bytes.extend_from_slice(&number.to_be_bytes());
        }
        bytes.extend_from_slice(self.command.expected_recorded_target_tip.as_bytes());
        bytes.extend_from_slice(pull.data.source_tip.as_bytes());
        bytes.extend_from_slice(pull.data.target_tip.as_bytes());
        for field in &fields[..4] {
            bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
            bytes.extend_from_slice(field);
        }
        bytes.extend_from_slice(&self.key);
        bytes.extend_from_slice(&(tx.len() as u32).to_be_bytes());
        bytes.extend_from_slice(tx.as_bytes());
        let digest = sha256_digest(&bytes);
        bytes.extend_from_slice(&digest);
        Ok(bytes)
    }
}

const fn format_tag(format: GitHashAlgorithm) -> u8 {
    match format {
        GitHashAlgorithm::Sha1 => 1,
        GitHashAlgorithm::Sha256 => 2,
    }
}

fn check_frame(bytes: &[u8]) -> Result<(), TrustedWorkflowFailure> {
    if bytes.len() < 8 + 32 + 16 + 32
        || bytes.len() > MAX_RECORD
        || bytes.get(..8) != Some(MAGIC.as_slice())
        || bytes[bytes.len() - 32..] != sha256_digest(&bytes[..bytes.len() - 32])
    {
        return Err(invalid("invalid original queue refresh attempt"));
    }
    Ok(())
}

/// Untrusted observation-only principal. The caller must independently verify
/// the existing scope marker, decode the complete record and authenticate its
/// canonical outcome. This accessor never authorizes submission as that actor.
pub(super) fn record_principal(bytes: &[u8]) -> Result<PrincipalId, TrustedWorkflowFailure> {
    check_frame(bytes)?;
    Ok(PrincipalId::from_bytes(bytes[40..56].try_into()
        .map_err(|_| invalid("invalid retained refresh principal"))?))
}

struct Input<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Input<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], TrustedWorkflowFailure> {
        let end = self.offset.checked_add(length)
            .ok_or_else(|| invalid("queue refresh custody length overflow"))?;
        let bytes = self.bytes.get(self.offset..end)
            .ok_or_else(|| invalid("truncated queue refresh custody"))?;
        self.offset = end;
        Ok(bytes)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], TrustedWorkflowFailure> {
        self.take(N)?.try_into().map_err(|_| invalid("invalid queue refresh custody field"))
    }

    fn counter(&mut self) -> Result<u64, TrustedWorkflowFailure> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn field(&mut self, maximum: usize) -> Result<&'a [u8], TrustedWorkflowFailure> {
        let length = usize::try_from(u32::from_be_bytes(self.array()?))
            .map_err(|_| invalid("queue refresh custody length overflow"))?;
        if length > maximum {
            return Err(invalid("queue refresh custody field exceeds its byte bound"));
        }
        self.take(length)
    }

    fn text(&mut self, maximum: usize) -> Result<String, TrustedWorkflowFailure> {
        std::str::from_utf8(self.field(maximum)?)
            .map(str::to_owned)
            .map_err(|_| invalid("queue refresh custody text is not UTF-8"))
    }

    fn oid(&mut self, format: GitHashAlgorithm) -> Result<GitOid, TrustedWorkflowFailure> {
        GitOid::from_hex(format, &hex(self.take(format.digest_len())?))
            .map_err(|_| invalid("invalid retained native object ID"))
    }
}

/// Enumerate bounded names only, retaining at most one payload in the caller's
/// recovery loop. Missing, foreign, linked, oversized and orphaned entries
/// refuse; a local ACK does not discharge an attempt here.
pub(super) fn records(root: &Path) -> Result<Vec<String>, TrustedWorkflowFailure> {
    let directory = root.join(DIRECTORY);
    match fs::symlink_metadata(&directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(io(error)),
        Ok(_) => check_directory(&directory)?,
    }
    let mut attempts = BTreeSet::new();
    let mut outcomes = BTreeSet::new();
    for (index, entry) in fs::read_dir(&directory).map_err(io)?.enumerate() {
        if index >= MAX_ATTEMPTS * 2 {
            return Err(invalid("queue refresh attempt bound exceeded"));
        }
        let entry = entry.map_err(io)?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| invalid("invalid queue refresh custody entry"))?;
        if let Some(key) = name.strip_prefix("attempt-").filter(|key| lower_hash(key)) {
            private_metadata(&entry.path(), MAX_RECORD)?;
            attempts.insert(key.to_owned());
        } else if let Some(key) = name.strip_prefix("outcome-").filter(|key| lower_hash(key)) {
            private_metadata(&entry.path(), ACK_BYTES)?;
            outcomes.insert(key.to_owned());
        } else {
            return Err(invalid("unknown queue refresh custody entry"));
        }
    }
    if attempts.len() > MAX_ATTEMPTS || outcomes.iter().any(|key| !attempts.contains(key)) {
        return Err(invalid("orphaned or excessive queue refresh acknowledgement"));
    }
    Ok(attempts.into_iter().map(|key| format!("attempt-{key}")).collect())
}

fn private_metadata(path: &Path, maximum: usize) -> Result<(), TrustedWorkflowFailure> {
    let meta = fs::symlink_metadata(path).map_err(io)?;
    if !meta.is_file() || meta.mode() & 0o777 != 0o600 || meta.nlink() != 1
        || meta.len() > maximum as u64
    {
        return Err(invalid("invalid bounded private queue refresh record"));
    }
    Ok(())
}

pub(super) fn read_record(root: &Path, name: &str) -> Result<Vec<u8>, TrustedWorkflowFailure> {
    if name.strip_prefix("attempt-").is_none_or(|key| !lower_hash(key)) {
        return Err(invalid("invalid queue refresh attempt filename"));
    }
    let directory = root.join(DIRECTORY);
    check_directory(&directory)?;
    reporting::read_private(&directory.join(name), MAX_RECORD)
}

pub(super) fn retain(root: &Path, attempt: &Attempt) -> Result<(), TrustedWorkflowFailure> {
    let existing = records(root)?;
    let bytes = attempt.bytes()?;
    let name = attempt.name();
    if existing.contains(&name) {
        if read_record(root, &name)? != bytes {
            return Err(invalid("original queue refresh attempt changed"));
        }
        return sync(&root.join(DIRECTORY), &root.join(DIRECTORY).join(name));
    }
    if existing.len() >= MAX_ATTEMPTS {
        return Err(invalid("queue refresh scope attempt bound exceeded"));
    }
    let directory = root.join(DIRECTORY);
    match fs::DirBuilder::new().mode(0o700).create(&directory) {
        Ok(()) => File::open(root).and_then(|file| file.sync_all()).map_err(io)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(io(error)),
    }
    check_directory(&directory)?;
    let file = directory.join(name);
    write_new(&file, &bytes).map_err(io)?;
    sync(&directory, &file)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Acknowledgement {
    Committed,
    Refused,
}

pub(super) fn acknowledged(
    root: &Path,
    attempt: &Attempt,
) -> Result<Option<(Acknowledgement, u64)>, TrustedWorkflowFailure> {
    let directory = root.join(DIRECTORY);
    check_directory(&directory)?;
    let file = directory.join(attempt.outcome_name());
    match fs::symlink_metadata(&file) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io(error)),
        Ok(_) => {}
    }
    let bytes = reporting::read_private(&file, ACK_BYTES)?;
    if bytes.len() != ACK_BYTES
        || &bytes[..8] != ACK_MAGIC
        || bytes[8..40] != sha256_digest(&attempt.bytes()?)
        || bytes[41..49] == [0; 8]
        || bytes[49..] != sha256_digest(&bytes[..49])
    {
        return Err(invalid("invalid queue refresh acknowledgement"));
    }
    let acknowledgement = match bytes[40] {
        1 => Acknowledgement::Committed,
        2 => Acknowledgement::Refused,
        _ => return Err(invalid("invalid queue refresh acknowledgement outcome")),
    };
    let sequence = u64::from_be_bytes(bytes[41..49].try_into()
        .map_err(|_| invalid("invalid queue refresh acknowledgement sequence"))?);
    sync(&directory, &file)?;
    Ok(Some((acknowledgement, sequence)))
}

/// The caller must authenticate the canonical terminal before invoking this.
/// Persisting a local receipt cannot replace that check on the next load.
pub(super) fn acknowledge(
    root: &Path,
    attempt: &Attempt,
    terminal: &TerminalOutcome,
) -> Result<(), TrustedWorkflowFailure> {
    let original = attempt.bytes()?;
    if read_record(root, &attempt.name())? != original {
        return Err(invalid("queue refresh acknowledgement lost its original attempt"));
    }
    let tag = if matches!(terminal.outcome, DecisionOutcome::Committed { .. }) { 1 } else { 2 };
    let mut bytes = Vec::with_capacity(ACK_BYTES);
    bytes.extend_from_slice(ACK_MAGIC);
    bytes.extend_from_slice(&sha256_digest(&original));
    bytes.push(tag);
    bytes.extend_from_slice(&terminal.decision_sequence.get().to_be_bytes());
    let digest = sha256_digest(&bytes);
    bytes.extend_from_slice(&digest);
    let directory = root.join(DIRECTORY);
    check_directory(&directory)?;
    let file = directory.join(attempt.outcome_name());
    write_new(&file, &bytes).map_err(io)?;
    sync(&directory, &file)
}

fn sync(directory: &Path, file: &Path) -> Result<(), TrustedWorkflowFailure> {
    File::open(file).and_then(|file| file.sync_all())
        .and_then(|()| File::open(directory)?.sync_all()).map_err(io)
}

#[cfg(test)]
mod tests;
