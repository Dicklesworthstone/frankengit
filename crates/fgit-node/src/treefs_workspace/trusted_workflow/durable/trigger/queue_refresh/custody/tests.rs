//! Codec vectors never establish authority. Synthetic ACK tests verify that no
//! native seal or outcome exists; the restart test uses a real canonical refusal.
use super::*;
use crate::NodeConfig;
use fgit_authority::{OutcomeLookup, read_seal_async};
use fgit_types::{RefName, RepositoryId, TenantId};
use std::os::unix::fs::{DirBuilderExt, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-queue-refresh-custody-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        private_directory(&path);
        Self(path)
    }

    fn child(&self, name: &str) -> PathBuf {
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

fn fixture(format: GitHashAlgorithm) -> (Scratch, OneNode, PrincipalId, QueueHeadRefreshCommand) {
    let scratch = Scratch::new();
    let (node, _) = OneNode::init(
        NodeConfig::new(
            scratch.0.join("node"),
            TenantId::from_bytes([0xb1; 16]),
            RepositoryId::from_bytes([0xb2; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(1),
    )
    .unwrap();
    let oid = |value: u8| {
        GitOid::from_hex(format, &format!("{value:02x}").repeat(format.digest_len())).unwrap()
    };
    let command = QueueHeadRefreshCommand {
        number: QueueNumber::FIRST,
        expected_queue_version: AggregateVersion::try_new(4).unwrap(),
        expected_policy_epoch: PolicyEpoch::FIRST,
        expected_recorded_target_tip: oid(1),
        pull_request: PullRequestCommand {
            number: PullRequestNumber::try_new(7).unwrap(),
            expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
            action: PullRequestAction::Update,
            data: PullRequestData {
                source_ref: RefName::try_new(b"refs/heads/topic-\xff").unwrap(),
                target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
                source_tip: oid(2),
                target_tip: oid(3),
                title: "Preserved original title é".into(),
                body: "The original body remains exact.\n".into(),
            },
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
        OutcomeLookup::Undecided,
    ));
}

fn repair_checksum(bytes: &mut [u8]) {
    let end = bytes.len() - 32;
    let checksum = sha256_digest(&bytes[..end]);
    bytes[end..].copy_from_slice(&checksum);
}

#[test]
fn original_full_body_raw_refs_and_retry_identity_round_trip_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, refresher, mut command) = fixture(format);
        command.pull_request.data.body = "é".repeat(MAX_BODY_BYTES / 2);
        let identity = [0xc1; 32];
        let attempt =
            Attempt::from_basis(&node, refresher, &command, identity, [0xc2; 32]).unwrap();
        let bytes = attempt.bytes().unwrap();
        assert_eq!(&bytes[..8], b"FGQRA001");
        assert!(bytes.len() > MAX_BODY_BYTES && bytes.len() <= MAX_RECORD);
        let decode =
            |bytes: &[u8]| Attempt::decode(&node, refresher, identity, &attempt.name(), bytes);
        let restored = decode(&bytes).unwrap();
        assert_eq!(restored.bytes().unwrap(), bytes);
        assert_eq!(restored.command, command);
        assert_eq!(
            restored.command.pull_request.data.body.len(),
            MAX_BODY_BYTES
        );
        assert_eq!(
            restored.command.pull_request.data.source_ref.as_bytes(),
            b"refs/heads/topic-\xff"
        );
        assert_eq!(restored.key, attempt.key);
        assert_eq!(restored.tx_id, attempt.tx_id);
        assert_eq!(restored.semantic, attempt.semantic);
        assert_eq!(record_principal(&bytes).unwrap(), refresher);
        let session = restored.session();
        let authenticated = session.authenticated_session().unwrap();
        assert_eq!(authenticated.principal_id(), refresher);
        assert_eq!(
            authenticated.client_idempotency_key(),
            &IdempotencyKey::new(attempt.key.to_vec()).unwrap(),
        );
        for length in [
            0,
            1,
            7,
            8,
            39,
            40,
            55,
            56,
            103,
            104,
            105,
            136,
            137,
            176,
            177,
            bytes.len() - 33,
            bytes.len() - 32,
            bytes.len() - 1,
        ] {
            assert!(decode(&bytes[..length]).is_err(), "truncation {length}");
        }
        for offset in [0, 8, 40, 56, 72, 88, 104, 105, 137, bytes.len() - 1] {
            let mut corrupt = bytes.clone();
            corrupt[offset] ^= 1;
            assert!(decode(&corrupt).is_err(), "field byte {offset}");
        }
        assert!(decode(&vec![0; MAX_RECORD + 1]).is_err());
        let mut too_large = command.clone();
        too_large.pull_request.data.body.push('x');
        assert!(Attempt::from_basis(&node, refresher, &too_large, identity, [0xc2; 32]).is_err());
        assert_no_submission(&node, &attempt);
        node.shutdown().unwrap();
    }
}

#[test]
fn full_semantics_and_bindings_cannot_be_rewritten_under_an_original_key_or_ack() {
    let (_scratch, node, refresher, command) = fixture(GitHashAlgorithm::Sha256);
    let identity = [0xc1; 32];
    let basis = [0xc2; 32];
    let original = Attempt::from_basis(&node, refresher, &command, identity, basis).unwrap();
    let bytes = original.bytes().unwrap();
    let mut variants = Vec::new();
    let mut changed = command.clone();
    changed.pull_request.data.title.push('!');
    variants.push(changed);
    let mut changed = command.clone();
    changed.pull_request.data.body.push('!');
    variants.push(changed);
    let mut changed = command.clone();
    changed.expected_queue_version = changed.expected_queue_version.next().unwrap();
    variants.push(changed);
    let mut changed = command.clone();
    changed.expected_policy_epoch = changed.expected_policy_epoch.next().unwrap();
    variants.push(changed);
    let mut changed = command.clone();
    changed.expected_recorded_target_tip =
        GitOid::from_hex(GitHashAlgorithm::Sha256, &"04".repeat(32)).unwrap();
    variants.push(changed);
    let mut changed = command.clone();
    changed.pull_request.expected_version =
        ExpectedVersion::Exactly(AggregateVersion::try_new(2).unwrap());
    variants.push(changed);
    let mut changed = command.clone();
    changed.pull_request.data.source_tip =
        GitOid::from_hex(GitHashAlgorithm::Sha256, &"05".repeat(32)).unwrap();
    variants.push(changed);
    let mut changed = command.clone();
    changed.pull_request.data.target_tip =
        GitOid::from_hex(GitHashAlgorithm::Sha256, &"06".repeat(32)).unwrap();
    variants.push(changed);
    for changed in variants {
        let next = Attempt::from_basis(&node, refresher, &changed, identity, basis).unwrap();
        assert_ne!(next.key, original.key);
        assert_ne!(next.tx_id, original.tx_id);
        assert_ne!(next.semantic, original.semantic);
        assert!(
            Attempt::decode(
                &node,
                refresher,
                identity,
                &original.name(),
                &next.bytes().unwrap(),
            )
            .is_err()
        );
    }
    for (actor, scope, observed) in [
        (PrincipalId::from_bytes([0xff; 16]), identity, basis),
        (refresher, [0xff; 32], basis),
        (refresher, identity, [0xff; 32]),
    ] {
        let next = Attempt::from_basis(&node, actor, &command, scope, observed).unwrap();
        assert_ne!(next.key, original.key);
        assert_ne!(next.tx_id, original.tx_id);
        if actor == refresher {
            assert_eq!(
                next.semantic, original.semantic,
                "basis or custody identity must not create a new native intent"
            );
        } else {
            assert_ne!(next.semantic, original.semantic);
        }
        assert!(Attempt::decode(&node, actor, scope, &next.name(), &bytes).is_err());
    }

    // Even recomputing the non-authoritative local checksum cannot keep the
    // original key/TxId when title, body or context bytes were substituted.
    let title = command.pull_request.data.title.as_bytes();
    let title_offset = bytes
        .windows(title.len())
        .position(|window| window == title)
        .unwrap();
    let body = command.pull_request.data.body.as_bytes();
    let body_offset = bytes
        .windows(body.len())
        .position(|window| window == body)
        .unwrap();
    let key_offset = bytes.len() - 32 - 4 - original.tx_id.to_string().len() - 32;
    for offset in [
        8,
        40,
        56,
        72,
        88,
        104,
        105,
        137,
        title_offset,
        body_offset,
        key_offset,
    ] {
        let mut corrupt = bytes.clone();
        corrupt[offset] ^= 1;
        repair_checksum(&mut corrupt);
        assert!(
            Attempt::decode(&node, refresher, identity, &original.name(), &corrupt).is_err(),
            "rechecksummed byte {offset}"
        );
    }
    let mut length_bomb = bytes.clone();
    let first_field = 8 + 32 + 16 * 4 + 1 + 32 + 8 * 5 + 3 * 32;
    length_bomb[first_field..first_field + 4].fill(0xff);
    repair_checksum(&mut length_bomb);
    assert!(Attempt::decode(&node, refresher, identity, &original.name(), &length_bomb,).is_err());
    let mut trailing = bytes.clone();
    trailing.insert(trailing.len() - 32, 0);
    repair_checksum(&mut trailing);
    assert!(Attempt::decode(&node, refresher, identity, &original.name(), &trailing).is_err());
    assert_no_submission(&node, &original);
    node.shutdown().unwrap();
}

fn acknowledgement_vector(attempt: &Attempt, tag: u8, sequence: u64) -> Vec<u8> {
    let mut bytes = ACK_MAGIC.to_vec();
    bytes.extend_from_slice(&sha256_digest(&attempt.bytes().unwrap()));
    bytes.push(tag);
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&sha256_digest(&bytes));
    bytes
}

#[test]
fn scope_retains_1024_attempts_without_buffering_payloads_and_refuses_orphans_or_growth() {
    let (scratch, node, refresher, command) = fixture(GitHashAlgorithm::Sha256);
    let root = scratch.child("bounded");
    assert!(records(&root).unwrap().is_empty());
    let directory = root.join(DIRECTORY);
    private_directory(&directory);
    let first = Attempt::from_basis(&node, refresher, &command, [1; 32], [0; 32]).unwrap();
    // Write codec vectors directly so the bound test does not rescan the whole
    // directory on every insertion. No command is submitted to the authority.
    for index in 0..MAX_ATTEMPTS {
        let mut basis = [0; 32];
        basis[..8].copy_from_slice(&(index as u64).to_be_bytes());
        let attempt = Attempt::from_basis(&node, refresher, &command, [1; 32], basis).unwrap();
        write_new(&directory.join(attempt.name()), &attempt.bytes().unwrap()).unwrap();
    }
    let before = records(&root).unwrap();
    assert_eq!(before.len(), MAX_ATTEMPTS);
    assert!(before.windows(2).all(|pair| pair[0] < pair[1]));
    retain(&root, &first).unwrap();
    assert_eq!(
        read_record(&root, &first.name()).unwrap(),
        first.bytes().unwrap()
    );
    let extra = Attempt::from_basis(&node, refresher, &command, [1; 32], [0xff; 32]).unwrap();
    assert!(retain(&root, &extra).is_err());
    assert_eq!(records(&root).unwrap(), before);
    // The cap counts attempts, allowing an additional matching ACK per attempt.
    write_new(
        &directory.join(first.outcome_name()),
        &acknowledgement_vector(&first, 1, 1),
    )
    .unwrap();
    assert_eq!(records(&root).unwrap(), before);
    let orphan = directory.join(extra.outcome_name());
    write_new(&orphan, &[0; ACK_BYTES]).unwrap();
    assert!(records(&root).is_err());
    fs::remove_file(orphan).unwrap();
    let unknown = directory.join("foreign-record");
    write_new(&unknown, b"foreign").unwrap();
    assert!(records(&root).is_err());
    fs::remove_file(unknown).unwrap();
    let file = directory.join(first.name());
    fs::write(&file, vec![0; MAX_RECORD + 1]).unwrap();
    assert!(records(&root).is_err());
    fs::write(&file, first.bytes().unwrap()).unwrap();
    let mut corrupt = first.bytes().unwrap();
    corrupt[8] ^= 1;
    fs::write(&file, corrupt).unwrap();
    assert!(retain(&root, &first).is_err());
    fs::write(&file, first.bytes().unwrap()).unwrap();
    retain(&root, &first).unwrap();
    assert_eq!(records(&root).unwrap(), before);
    assert!(read_record(&root, "../original").is_err());
    assert!(read_record(&root, &extra.outcome_name()).is_err());
    assert_no_submission(&node, &first);
    assert_no_submission(&node, &extra);
    node.shutdown().unwrap();
}

#[test]
fn private_records_and_local_acknowledgements_fail_closed_without_becoming_authority() {
    let (scratch, node, refresher, command) = fixture(GitHashAlgorithm::Sha1);
    let root = scratch.child("private");
    let elsewhere = scratch.child("elsewhere");
    let attempt = Attempt::from_basis(&node, refresher, &command, [1; 32], [2; 32]).unwrap();
    symlink(&elsewhere, root.join(DIRECTORY)).unwrap();
    assert!(records(&root).is_err());
    assert!(retain(&root, &attempt).is_err());
    fs::remove_file(root.join(DIRECTORY)).unwrap();
    retain(&root, &attempt).unwrap();
    assert!(acknowledged(&root, &attempt).unwrap().is_none());
    let directory = root.join(DIRECTORY);
    let file = directory.join(attempt.name());
    let link = elsewhere.join("attempt-link");
    fs::hard_link(&file, &link).unwrap();
    assert!(records(&root).is_err());
    assert!(read_record(&root, &attempt.name()).is_err());
    fs::remove_file(&link).unwrap();
    fs::rename(&file, &link).unwrap();
    symlink(&link, &file).unwrap();
    assert!(records(&root).is_err());
    assert!(read_record(&root, &attempt.name()).is_err());
    fs::remove_file(&file).unwrap();
    fs::rename(&link, &file).unwrap();

    let receipt = directory.join(attempt.outcome_name());
    let valid = acknowledgement_vector(&attempt, 1, 7);
    assert_eq!(valid.len(), ACK_BYTES);
    write_new(&receipt, &valid).unwrap();
    assert_eq!(
        acknowledged(&root, &attempt).unwrap(),
        Some((Acknowledgement::Committed, 7))
    );
    for offset in [0, 8, 40, 41, ACK_BYTES - 1] {
        let mut corrupt = valid.clone();
        corrupt[offset] ^= 1;
        fs::write(&receipt, corrupt).unwrap();
        assert!(acknowledged(&root, &attempt).is_err());
    }
    for (tag, sequence) in [(3, 7), (1, 0)] {
        fs::write(&receipt, acknowledgement_vector(&attempt, tag, sequence)).unwrap();
        assert!(acknowledged(&root, &attempt).is_err());
    }
    let other = Attempt::from_basis(&node, refresher, &command, [1; 32], [3; 32]).unwrap();
    fs::write(&receipt, acknowledgement_vector(&other, 1, 1)).unwrap();
    assert!(acknowledged(&root, &attempt).is_err());
    fs::write(&receipt, acknowledgement_vector(&attempt, 2, 9)).unwrap();
    assert_eq!(
        acknowledged(&root, &attempt).unwrap(),
        Some((Acknowledgement::Refused, 9))
    );
    let alias = elsewhere.join("receipt-link");
    fs::hard_link(&receipt, &alias).unwrap();
    assert!(records(&root).is_err());
    assert!(acknowledged(&root, &attempt).is_err());
    fs::remove_file(&alias).unwrap();
    fs::rename(&receipt, &alias).unwrap();
    symlink(&alias, &receipt).unwrap();
    assert!(records(&root).is_err());
    assert!(acknowledged(&root, &attempt).is_err());
    fs::remove_file(&receipt).unwrap();
    fs::rename(&alias, &receipt).unwrap();
    assert_eq!(records(&root).unwrap(), vec![attempt.name()]);
    assert_no_submission(&node, &attempt);
    node.shutdown().unwrap();
}

#[test]
fn retained_undecided_intent_without_principal_marker_recovers_only_under_explicit_original_grant()
{
    use super::super::super::{
        Owner, merge_queue, pull_request_merge::PullRequestMergeWatchConfig,
    };
    use super::super::{QueueRefreshMode, identity};
    use fgit_forge::preparation::{MergeCommitStyle, MergeMetadata, MergeProfile};
    use fgit_types::HeadGeneration;

    let (scratch, mut node, refresher, command) = fixture(GitHashAlgorithm::Sha256);
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let parent = scratch.child("watch-parent");
    let target = command.pull_request.data.target_ref.clone();
    let merge = PullRequestMergeWatchConfig::try_new(
        RefName::try_new(b"refs/heads/ci/refresh").unwrap(),
        PrincipalId::from_bytes([3; 16]),
        MergeMetadata {
            author: "CI <ci@example.test>".into(),
            committer: "CI <ci@example.test>".into(),
            timestamp: 1_700_000_000,
            message: b"Check target\n".to_vec(),
        },
        MergeProfile::PathMergeV1,
        MergeCommitStyle::TwoParent,
    )
    .unwrap();
    let number = command.number.get();
    let scope = merge_queue::scope(&node, &target, b"ci", number);
    let root = parent.join(format!("watch-{}", hex(&scope)));
    let expected_identity = identity(&scope, &merge, refresher);
    let before = node
        .runtime()
        .block_on(node.materialize_admission())
        .unwrap();
    let original = Attempt::new(
        &node,
        refresher,
        &command,
        expected_identity,
        before.basis().id(),
    )
    .unwrap();
    {
        let _owner = Owner::open(&root).unwrap();
        merge.bind(&root).unwrap();
        retain(&root, &original).unwrap();
    }
    let marker = root.join("refresh-principal");
    assert!(!marker.exists());
    assert_no_submission(&node, &original);

    // Deterministic crash boundary: the fsynced complete request exists, but
    // neither its principal marker nor any authority seal was ever written.
    node.shutdown().unwrap();
    let mut node = OneNode::open_existing(
        NodeConfig::new(
            scratch.0.join("node"),
            TenantId::from_bytes([0xb1; 16]),
            RepositoryId::from_bytes([0xb2; 16]),
        )
        .with_object_format(GitHashAlgorithm::Sha256)
        .with_worker_threads(1),
    )
    .unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    for unauthorized in [None, Some(PrincipalId::from_bytes([0xff; 16]))] {
        assert!(
            node.runtime()
                .block_on(node.validate_trusted_queue_head_refresh_custody_in(
                    &node.request_context(),
                    &target,
                    number,
                    b"ci",
                    &parent,
                    &merge,
                    unauthorized,
                ))
                .is_err()
        );
        assert!(
            !marker.exists(),
            "validation must not repair an absent authority marker"
        );
    }
    assert!(
        node.runtime()
            .block_on(node.validate_trusted_queue_head_refresh_custody_in(
                &node.request_context(),
                &target,
                number,
                b"ci",
                &parent,
                &merge,
                Some(refresher),
            ))
            .unwrap()
    );
    assert!(!marker.exists());
    assert!(acknowledged(&root, &original).unwrap().is_none());
    assert_eq!(
        node.runtime()
            .block_on(node.materialize_admission())
            .unwrap()
            .basis(),
        before.basis(),
    );
    assert_no_submission(&node, &original);

    let publisher = PrincipalId::from_bytes([4; 16]);
    let lander = PrincipalId::from_bytes([5; 16]);
    let mut decisions = Vec::new();
    let recovered = node
        .runtime()
        .block_on(node.refresh_trusted_queue_head_merge_workflows_in(
            &node.request_context(),
            &target,
            number,
            b"ci",
            &parent,
            &merge,
            publisher,
            lander,
            refresher,
            QueueRefreshMode::RecoverOnly,
            |text| {
                decisions.push(text.to_owned());
                Ok(())
            },
        ));
    assert!(recovered.error.is_none(), "{:?}", recovered.error);
    assert!(!recovered.request_stopped && !recovered.pending);
    assert_eq!(recovered.committed, 0);
    assert_eq!(
        recovered.refused, 1,
        "the absent queue must canonically refuse the original command"
    );
    assert_eq!(decisions.len(), 1);
    assert!(decisions[0].contains(&original.tx_id.to_string()));
    assert_eq!(
        reporting::read_private(&marker, 32).unwrap(),
        expected_identity.to_vec()
    );
    let OutcomeLookup::Decided(terminal) = node
        .runtime()
        .block_on(node.resolve_outcome_checkpointed_in(&node.request_context(), original.tx_id))
        .unwrap()
    else {
        panic!("recovery must resolve the retained original transaction");
    };
    assert!(matches!(terminal.outcome, DecisionOutcome::Refused { .. }));
    assert_eq!(
        acknowledged(&root, &original).unwrap(),
        Some((Acknowledgement::Refused, terminal.decision_sequence.get()))
    );
    let bytes = read_record(&root, &original.name()).unwrap();
    let retained = Attempt::decode(
        &node,
        refresher,
        expected_identity,
        &original.name(),
        &bytes,
    )
    .unwrap();
    assert_eq!(retained.command, command);
    assert_eq!(retained.tx_id, original.tx_id);
    let after = node
        .runtime()
        .block_on(node.materialize_admission())
        .unwrap();
    assert_eq!(after.snapshot().refs, before.snapshot().refs);
    assert_eq!(after.snapshot().outbox, before.snapshot().outbox);
    assert_eq!(
        after.basis().body().forge_position_root,
        before.basis().body().forge_position_root
    );

    // Once the ACK has been authenticated against the real terminal, a later
    // read-only fence needs no publication grant and recovery cannot resubmit.
    assert!(
        !node
            .runtime()
            .block_on(node.validate_trusted_queue_head_refresh_custody_in(
                &node.request_context(),
                &target,
                number,
                b"ci",
                &parent,
                &merge,
                None,
            ))
            .unwrap()
    );
    let repeated = node
        .runtime()
        .block_on(node.refresh_trusted_queue_head_merge_workflows_in(
            &node.request_context(),
            &target,
            number,
            b"ci",
            &parent,
            &merge,
            publisher,
            lander,
            refresher,
            QueueRefreshMode::RecoverOnly,
            |_| Err("a verified acknowledgement must suppress duplicate observation".into()),
        ));
    assert!(repeated.error.is_none(), "{:?}", repeated.error);
    assert_eq!(repeated.previously_decided, 1);
    assert_eq!(repeated.committed + repeated.refused, 0);
    assert!(!repeated.pending);
    assert_eq!(
        node.runtime()
            .block_on(node.materialize_admission())
            .unwrap()
            .basis(),
        after.basis(),
    );
    node.shutdown().unwrap();
}
