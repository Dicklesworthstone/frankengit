//! File/codec unit tests. Acknowledgement bytes below are non-authoritative
//! format vectors; they are not fabricated repository decisions or evidence
//! that a queue landing committed.

use super::*;
use crate::NodeConfig;
use fgit_authority::{OutcomeLookup, read_seal_async};
use fgit_forge::event::NativeMerge;
use fgit_forge::{AggregateVersion, PullRequestNumber, QueueNumber};
use fgit_types::{GitHashAlgorithm, GitOid, PolicyEpoch, RefName, RepositoryId, TenantId};
use std::os::unix::fs::{DirBuilderExt, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-queue-landing-custody-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        private_directory(&path);
        Self(path)
    }

    fn event(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        private_directory(&path);
        path
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn private_directory(path: &Path) {
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}

fn fixture() -> (Scratch, OneNode, PrincipalId, QueueCandidateLandingCommand) {
    let scratch = Scratch::new();
    let (node, _) = OneNode::init(
        NodeConfig::new(
            scratch.0.join("node"),
            TenantId::from_bytes([0xb1; 16]),
            RepositoryId::from_bytes([0xb2; 16]),
        )
        .with_object_format(GitHashAlgorithm::Sha256)
        .with_worker_threads(1),
    )
    .unwrap();
    let oid = |value: u8| {
        GitOid::from_hex(GitHashAlgorithm::Sha256, &format!("{value:02x}").repeat(32)).unwrap()
    };
    let command = QueueCandidateLandingCommand {
        number: QueueNumber::FIRST,
        expected_version: AggregateVersion::FIRST,
        expected_policy_epoch: PolicyEpoch::FIRST,
        pull_request: PullRequestNumber::FIRST,
        expected_pull_request_version: AggregateVersion::FIRST,
        merge: NativeMerge {
            source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
            source_tip: oid(1),
            base_tip: oid(2),
            target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
            target_tip_before: oid(3),
            merge_commit: oid(4),
        },
    };
    (scratch, node, PrincipalId::from_bytes([0xb3; 16]), command)
}

fn assert_no_submission(node: &OneNode, attempt: &Attempt) {
    let request = node.request_context();
    assert!(
        node.runtime()
            .block_on(read_seal_async(
                &node.authority,
                request.authority(),
                node.tenant_id(),
                node.repository_id(),
                attempt.tx_id,
            ))
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        node.runtime()
            .block_on(node.resolve_outcome_checkpointed_in(&request, attempt.tx_id))
            .unwrap(),
        OutcomeLookup::Undecided
    ));
}

#[test]
fn attempt_round_trip_rederives_original_identity_and_rejects_tampering() {
    let (_scratch, node, lander, command) = fixture();
    let identity = [0xc1; 32];
    let event = [0xc2; 32];
    let attempt =
        Attempt::from_basis(&node, lander, &command, identity, event, [0xc3; 32]).unwrap();
    let bytes = attempt.bytes();
    assert_eq!(&bytes[..8], b"FGQLA001");
    assert!(bytes.len() <= MAX_RECORD);
    let decode = |bytes: &[u8]| {
        Attempt::decode(
            &node,
            lander,
            &command,
            identity,
            event,
            &attempt.name(),
            bytes,
        )
    };
    let restored = decode(&bytes).unwrap();
    assert_eq!(restored.bytes(), bytes);
    assert_eq!(restored.key, attempt.key);
    assert_eq!(restored.tx_id, attempt.tx_id);
    let session = restored.session();
    let authenticated = session.authenticated_session().unwrap();
    assert_eq!(authenticated.principal_id(), lander);
    assert_eq!(
        authenticated.client_idempotency_key(),
        &IdempotencyKey::new(attempt.key.to_vec()).unwrap()
    );
    for length in 0..bytes.len() {
        assert!(decode(&bytes[..length]).is_err(), "truncation {length}");
    }
    for offset in [0, 8, 40, 72, 104, bytes.len() - 1] {
        let mut corrupt = bytes.clone();
        corrupt[offset] ^= 1;
        assert!(decode(&corrupt).is_err(), "field byte {offset}");
    }
    assert!(decode(&vec![0; MAX_RECORD + 1]).is_err());
    let mut changed_command = command.clone();
    changed_command.expected_version = command.expected_version.next().unwrap();
    for (other_lander, other_command, other_identity, other_event) in [
        (
            PrincipalId::from_bytes([0xff; 16]),
            &command,
            identity,
            event,
        ),
        (lander, &changed_command, identity, event),
        (lander, &command, [0xff; 32], event),
        (lander, &command, identity, [0xff; 32]),
    ] {
        assert!(
            Attempt::decode(
                &node,
                other_lander,
                other_command,
                other_identity,
                other_event,
                &attempt.name(),
                &bytes,
            )
            .is_err()
        );
    }
    let next = Attempt::from_basis(&node, lander, &command, identity, event, [0xc4; 32]).unwrap();
    assert_ne!(next.key, attempt.key);
    assert_ne!(next.tx_id, attempt.tx_id);
    assert!(
        Attempt::decode(
            &node,
            lander,
            &command,
            identity,
            event,
            &next.name(),
            &bytes,
        )
        .is_err()
    );
    assert_no_submission(&node, &attempt);
    assert_no_submission(&node, &next);
    node.shutdown().unwrap();
}

#[test]
fn custody_retains_exact_attempts_and_refuses_bounds_orphans_and_unknown_files() {
    let (scratch, node, lander, command) = fixture();
    let path = scratch.event("bounded");
    assert!(records(&path).unwrap().is_empty());
    let mut retained = Vec::new();
    for index in 0..MAX_ATTEMPTS {
        let mut basis = [0; 32];
        basis[0] = u8::try_from(index).unwrap();
        let attempt =
            Attempt::from_basis(&node, lander, &command, [1; 32], [2; 32], basis).unwrap();
        retain(&path, &attempt).unwrap();
        retained.push(attempt);
    }
    let before = records(&path).unwrap();
    assert_eq!(before.len(), MAX_ATTEMPTS);
    assert!(before.windows(2).all(|pair| pair[0].0 < pair[1].0));
    // An exact retry still works at capacity; a new basis cannot grow custody.
    retain(&path, &retained[0]).unwrap();
    let extra = Attempt::from_basis(&node, lander, &command, [1; 32], [2; 32], [0xff; 32]).unwrap();
    assert!(retain(&path, &extra).is_err());
    assert_eq!(records(&path).unwrap(), before);
    let directory = path.join(DIRECTORY);
    let orphan = directory.join(extra.outcome_name());
    write_new(&orphan, &[0; ACK_BYTES]).unwrap();
    assert!(records(&path).is_err());
    fs::remove_file(orphan).unwrap();
    let unknown = directory.join("foreign-record");
    write_new(&unknown, b"foreign").unwrap();
    assert!(records(&path).is_err());
    fs::remove_file(unknown).unwrap();
    let first = directory.join(retained[0].name());
    fs::write(&first, vec![0; MAX_RECORD + 1]).unwrap();
    assert!(records(&path).is_err());
    fs::write(&first, retained[0].bytes()).unwrap();
    assert_eq!(records(&path).unwrap(), before);
    let mut corrupt = retained[0].bytes();
    corrupt[8] ^= 1;
    fs::write(&first, corrupt).unwrap();
    assert!(retain(&path, &retained[0]).is_err());
    fs::write(&first, retained[0].bytes()).unwrap();
    retain(&path, &retained[0]).unwrap();
    assert_eq!(records(&path).unwrap(), before);
    assert_no_submission(&node, &extra);
    node.shutdown().unwrap();
}

fn acknowledgement_vector(attempt: &Attempt, tag: u8, sequence: u64) -> Vec<u8> {
    let mut bytes = b"FGQLR001".to_vec();
    bytes.extend_from_slice(&sha256_digest(&attempt.bytes()));
    bytes.push(tag);
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&sha256_digest(&bytes));
    bytes
}

#[test]
fn private_receipts_reject_links_or_corruption_and_never_establish_authority() {
    let (scratch, node, lander, command) = fixture();
    let path = scratch.event("private");
    let attempt = Attempt::from_basis(&node, lander, &command, [1; 32], [2; 32], [3; 32]).unwrap();
    let elsewhere = scratch.event("elsewhere");
    symlink(&elsewhere, path.join(DIRECTORY)).unwrap();
    assert!(records(&path).is_err());
    assert!(retain(&path, &attempt).is_err());
    fs::remove_file(path.join(DIRECTORY)).unwrap();
    retain(&path, &attempt).unwrap();
    assert!(acknowledged(&path, &attempt).unwrap().is_none());
    let directory = path.join(DIRECTORY);
    let file = directory.join(attempt.name());
    let link = elsewhere.join("attempt-link");
    fs::hard_link(&file, &link).unwrap();
    assert!(records(&path).is_err());
    fs::remove_file(&link).unwrap();
    fs::rename(&file, &link).unwrap();
    symlink(&link, &file).unwrap();
    assert!(records(&path).is_err());
    fs::remove_file(&file).unwrap();
    fs::rename(&link, &file).unwrap();
    assert_eq!(records(&path).unwrap().len(), 1);

    let receipt = directory.join(attempt.outcome_name());
    let valid = acknowledgement_vector(&attempt, 1, 7);
    assert_eq!(valid.len(), ACK_BYTES);
    write_new(&receipt, &valid).unwrap();
    assert_eq!(
        acknowledged(&path, &attempt).unwrap(),
        Some((Acknowledgement::Committed, 7))
    );
    for offset in [0, 8, 40, 41, ACK_BYTES - 1] {
        let mut corrupt = valid.clone();
        corrupt[offset] ^= 1;
        fs::write(&receipt, corrupt).unwrap();
        assert!(acknowledged(&path, &attempt).is_err());
    }
    for (tag, sequence) in [(3, 7), (1, 0)] {
        fs::write(&receipt, acknowledgement_vector(&attempt, tag, sequence)).unwrap();
        assert!(acknowledged(&path, &attempt).is_err());
    }
    let other = Attempt::from_basis(&node, lander, &command, [1; 32], [2; 32], [4; 32]).unwrap();
    fs::write(&receipt, acknowledgement_vector(&other, 1, 1)).unwrap();
    assert!(acknowledged(&path, &attempt).is_err());
    fs::write(&receipt, acknowledgement_vector(&attempt, 2, 9)).unwrap();
    assert_eq!(
        acknowledged(&path, &attempt).unwrap(),
        Some((Acknowledgement::Refused, 9))
    );
    let alias = elsewhere.join("receipt-link");
    fs::hard_link(&receipt, &alias).unwrap();
    assert!(records(&path).is_err());
    assert!(acknowledged(&path, &attempt).is_err());
    fs::remove_file(&alias).unwrap();
    fs::rename(&receipt, &alias).unwrap();
    symlink(&alias, &receipt).unwrap();
    assert!(records(&path).is_err());
    assert!(acknowledged(&path, &attempt).is_err());
    fs::remove_file(&receipt).unwrap();
    fs::rename(&alias, &receipt).unwrap();
    assert_eq!(records(&path).unwrap().len(), 1);
    assert_eq!(
        acknowledged(&path, &attempt).unwrap(),
        Some((Acknowledgement::Refused, 9))
    );
    assert_no_submission(&node, &attempt);
    node.shutdown().unwrap();
}
