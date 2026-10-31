//! Remote divergent queue execution with actual native objects and one authority
//! publication. Transport failure never stands in for a canonical outcome.

use super::support::*;
use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::event::protection::{ProtectedBranch, ProtectionCommand, ReviewProtection};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::event::queue::QueueAction;
use fgit_forge::event::review::{CandidateBinding, ReviewSubject};
use fgit_forge::merge_queue::{QueueCommand, QueueCommandAction};
use fgit_forge::preparation::{MergeCommitStyle, MergeMetadata, MergePreparation};
use fgit_forge::{
    AggregateVersion, ExpectedVersion, ForgeEventPayload, PullRequestNumber, QueueNumber,
};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, PolicyEpoch, RefName};
use std::fs;
use std::io::Write;
use std::net::Shutdown;
use std::path::Path;

struct Fixture {
    node: OneNode,
    candidate: Candidate,
    config: NodeConfig,
    expected_tree: GitOid,
}

fn session(key: &str) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        OWNER,
        IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
    )
}

fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, bytes: &[u8]) -> GitOid {
    let oid = git_object_id(format, kind, bytes);
    let raw = [
        format!("{} {}\0", kind.label(), bytes.len()).as_bytes(),
        bytes,
    ]
    .concat();
    let length = u16::try_from(raw.len()).unwrap();
    let mut encoded = vec![0x78, 0x01, 0x01];
    encoded.extend(length.to_le_bytes());
    encoded.extend((!length).to_le_bytes());
    encoded.extend(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), value| {
        let next = (a + u32::from(*value)) % 65_521;
        (next, (b + next) % 65_521)
    });
    encoded.extend(((b << 16) | a).to_be_bytes());
    let name = oid.to_string();
    let directory = root.join("objects").join(&name[..2]);
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join(&name[2..]), encoded).unwrap();
    oid
}

fn tree(entries: &[(&str, GitOid)]) -> Vec<u8> {
    entries
        .iter()
        .flat_map(|(name, oid)| [format!("100644 {name}\0").as_bytes(), oid.as_bytes()].concat())
        .collect()
}

fn protect(
    node: &OneNode,
    data: &PullRequestData,
    version: u64,
    epoch: PolicyEpoch,
    reviewed: bool,
) {
    let command = ProtectionCommand {
        expected_version: if version == 0 {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(AggregateVersion::try_new(version).unwrap())
        },
        expected_epoch: epoch,
        protection: ReviewProtection {
            administrators: vec![OWNER],
            branches: vec![ProtectedBranch {
                name: data.target_ref.clone(),
                reviewers: if reviewed { vec![REVIEWER] } else { Vec::new() },
                required_approvals: if reviewed { 1 } else { 0 },
                required_checks: Vec::new(),
                require_merge_queue: true,
            }],
            ref_policy: None,
        },
    };
    let (_, outcome) = node
        .runtime()
        .block_on(node.admit_review_protection_durable_in(
            &node.request_context(),
            &session(&format!("candidate-http-policy-{version}")),
            &command,
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }));
}

fn enqueue(node: &OneNode, data: &PullRequestData, queue: u64, pull: u64, previous: u64) {
    let command = QueueCommand {
        number: QueueNumber::try_new(queue).unwrap(),
        target_ref: data.target_ref.clone(),
        expected_version: if previous == 0 {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(AggregateVersion::try_new(previous).unwrap())
        },
        action: QueueCommandAction::Enqueue {
            pull_request: PullRequestNumber::try_new(pull).unwrap(),
            expected_pull_request_version: AggregateVersion::FIRST,
            source_ref: data.source_ref.clone(),
            head_tip: data.source_tip,
            expected_target_tip: data.target_tip,
            priority: 0,
        },
    };
    let (_, outcome) = node
        .runtime()
        .block_on(node.admit_queue_durable_in(
            &node.request_context(),
            &session(&format!("candidate-http-enqueue-{queue}-{pull}")),
            &command,
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }));
}

fn divergent(root: &Scratch, format: GitHashAlgorithm) -> Fixture {
    let config = root
        .config(format)
        .with_http_queue_management()
        .with_http_queue_landings();
    let (mut node, _) = OneNode::init(config.clone()).unwrap();
    let head = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap();
    node.bring_into_service(head.receipt().generation())
        .unwrap();
    let source = root.0.join("divergent-source");
    fs::create_dir_all(source.join("refs/heads")).unwrap();
    fs::write(source.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(source.join("config"), match format {
        GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
        GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
    }).unwrap();
    let common = loose(&source, format, GitObjectKind::Blob, b"common\n");
    let ours = loose(&source, format, GitObjectKind::Blob, b"target addition\n");
    let theirs = loose(&source, format, GitObjectKind::Blob, b"source addition\n");
    let base_tree = loose(
        &source,
        format,
        GitObjectKind::Tree,
        &tree(&[("base.txt", common)]),
    );
    let target_tree = loose(
        &source,
        format,
        GitObjectKind::Tree,
        &tree(&[("base.txt", common), ("target.txt", ours)]),
    );
    let source_tree = loose(
        &source,
        format,
        GitObjectKind::Tree,
        &tree(&[("base.txt", common), ("source.txt", theirs)]),
    );
    let expected_tree = git_object_id(
        format,
        GitObjectKind::Tree,
        &tree(&[
            ("base.txt", common),
            ("source.txt", theirs),
            ("target.txt", ours),
        ]),
    );
    let commit = |tree: GitOid, parent: Option<GitOid>, message: &str| {
        let parent = parent.map_or_else(String::new, |oid| format!("parent {oid}\n"));
        loose(&source, format, GitObjectKind::Commit, format!(
            "tree {tree}\n{parent}author Fixture <queue@example.invalid> 1 +0000\ncommitter Fixture <queue@example.invalid> 1 +0000\n\n{message}\n"
        ).as_bytes())
    };
    let base = commit(base_tree, None, "base");
    let target = commit(target_tree, Some(base), "independent target");
    let tip = commit(source_tree, Some(base), "independent source");
    fs::write(source.join("refs/heads/main"), format!("{target}\n")).unwrap();
    fs::write(source.join("refs/heads/topic"), format!("{tip}\n")).unwrap();
    let imported = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &node.request_context(),
            &source,
            OWNER,
            b"queue-candidate-http-fixture",
        ))
        .unwrap();
    assert!(!imported.commands.is_empty());
    assert!(
        imported
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    let data = PullRequestData {
        source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
        target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
        source_tip: tip,
        target_tip: target,
        title: "Divergent remote queue candidate".into(),
        body: String::new(),
    };
    for number in [1, 2] {
        let pull = PullRequestCommand {
            number: PullRequestNumber::try_new(number).unwrap(),
            expected_version: ExpectedVersion::NewStream,
            action: PullRequestAction::Open,
            data: data.clone(),
        };
        let (_, outcome) = node
            .runtime()
            .block_on(node.admit_pull_request_durable_in(
                &node.request_context(),
                &session(&format!("candidate-http-pr-{number}")),
                &pull,
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }));
        enqueue(&node, &data, 1, number, number - 1);
    }
    protect(&node, &data, 0, PolicyEpoch::FIRST, false);
    let epoch = PolicyEpoch::FIRST.next().unwrap();
    let before = generation(&node);
    let prepared = node
        .runtime()
        .block_on(node.prepare_queue_head_bundle_in(
            &node.request_context(),
            QueueNumber::FIRST,
            AggregateVersion::try_new(2).unwrap(),
            &ReviewSubject {
                pull_request: PullRequestNumber::FIRST,
                pull_request_version: AggregateVersion::FIRST,
                source_ref: data.source_ref.clone(),
                target_ref: data.target_ref.clone(),
                source_tip: tip,
                target_tip: target,
                policy_epoch: epoch,
            },
            &Default::default(),
            &MergeMetadata {
                author: "Remote queue <queue@example.invalid>".into(),
                committer: "Remote queue <queue@example.invalid>".into(),
                timestamp: 3,
                message: b"Land exact divergent queue head\n".to_vec(),
            },
            Default::default(),
        ))
        .unwrap();
    let MergePreparation::Clean(plan) = prepared.outcome else {
        panic!("clean divergent native candidate")
    };
    assert_eq!(plan.style, MergeCommitStyle::TwoParent);
    assert_eq!(plan.base, base);
    assert_ne!(plan.commit, tip);
    assert_ne!(plan.commit, target);
    assert!(node.read_git_object(plan.commit).is_err());
    assert_eq!(generation(&node), before);
    Fixture {
        node,
        config,
        expected_tree,
        candidate: Candidate {
            data,
            binding: CandidateBinding {
                merge_base: base,
                commit: plan.commit,
            },
            epoch,
            bundle: prepared.bundle.unwrap(),
        },
    }
}

fn candidate_form(
    candidate: &Candidate,
    incarnation: fgit_types::RepositoryIncarnationId,
) -> String {
    landing_form(candidate, incarnation)
        + &format!(
            "&merge_base={}&expected_commit={}",
            candidate.binding.merge_base, candidate.binding.commit,
        )
}

fn wire(
    client: &Endpoint,
    number: u64,
    token: char,
    key: &str,
    command: &str,
    bundle: Option<&[u8]>,
    chunked: bool,
) -> Vec<u8> {
    let mut body = b"--queue-candidate\r\nContent-Disposition: form-data; name=\"command\"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n".to_vec();
    body.extend_from_slice(command.as_bytes());
    body.extend_from_slice(b"\r\n");
    if let Some(bundle) = bundle {
        body.extend_from_slice(b"--queue-candidate\r\nContent-Disposition: form-data; name=\"bundle\"; filename=\"candidate.bundle\"\r\nContent-Type: application/x-git-bundle\r\n\r\n");
        body.extend_from_slice(bundle);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"--queue-candidate--\r\n");
    let (body, framing) = if chunked {
        let mut encoded = Vec::new();
        for chunk in body.chunks(97) {
            encoded.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            encoded.extend_from_slice(chunk);
            encoded.extend_from_slice(b"\r\n");
        }
        encoded.extend_from_slice(b"0\r\n\r\n");
        (encoded, "Transfer-Encoding: chunked\r\n".to_owned())
    } else {
        let framing = format!("Content-Length: {}\r\n", body.len());
        (body, framing)
    };
    request(
        client,
        "POST",
        &format!("/api/v1/queues/{number}/land-candidate"),
        token,
        &format!(
            "Content-Type: multipart/form-data; boundary=queue-candidate\r\n{framing}Idempotency-Key: {key}\r\n"
        ),
        &body,
    )
}

fn publish(
    client: &Endpoint,
    number: u64,
    token: char,
    key: &str,
    command: &str,
    bundle: Option<&[u8]>,
    chunked: bool,
) -> Reply {
    exchange(
        client,
        &wire(client, number, token, key, command, bundle, chunked),
        true,
    )
}

fn landed_candidate(reply: &Reply, candidate: &Candidate) {
    accepted(reply);
    assert!(reply.body.contains("\"type\":\"merge_queue_publication\""));
    assert!(
        reply
            .body
            .contains("\"name\":\"land-candidate\",\"method\":\"merge-commit\"")
    );
    assert!(reply.body.contains("\"refs_changed\":true"));
    assert!(reply.body.contains(&format!(
        "\"expected_commit\":\"{}\"",
        candidate.binding.commit
    )));
    assert!(
        reply
            .body
            .contains(&format!("\"principal_id\":\"{MERGER}\""))
    );
}

#[test]
fn divergent_queue_candidate_lands_atomically_and_recovers_unknown_reply_after_restart_and_stronger_policy()
 {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let Fixture {
            node,
            candidate,
            config,
            expected_tree,
        } = divergent(&root, format);
        let before = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        let original_refs = before.snapshot().refs.clone();
        let original_objects = before.selected_closure().closure().objects().clone();
        let original_generation = generation(&node);
        let credentials = root.0.join("credentials");
        queue_credentials(
            &node,
            &credentials,
            &format!("exact:{}", hex(candidate.data.target_ref.as_bytes())),
        );
        let form = candidate_form(&candidate, node.repository_incarnation_id());
        let server = Server::start(node, &credentials, 3, false, true);
        let historical = get(&server.client, "/api/v1/queues/1", 'a'); // 1
        status(&historical, 200);
        let pin = token(&historical);
        let mut disconnected = connection(&server.client);
        disconnected
            .write_all(&wire(
                &server.client,
                1,
                'c',
                "candidate-lost-reply",
                &form,
                Some(&candidate.bundle),
                false,
            ))
            .unwrap(); // 2
        disconnected.shutdown(Shutdown::Write).unwrap();
        drop(disconnected);
        let original = publish(
            &server.client,
            1,
            'c',
            "candidate-lost-reply",
            &form,
            Some(&candidate.bundle),
            true,
        ); // 3
        landed_candidate(&original, &candidate);
        assert_eq!(server.finish().accepted_sessions(), 3);

        let node = reopen(&config);
        assert_eq!(generation(&node), original_generation + 1);
        let selected = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        let mut expected_refs = original_refs;
        expected_refs.insert(candidate.data.target_ref.clone(), candidate.binding.commit);
        assert_eq!(selected.snapshot().refs, expected_refs);
        assert!(
            selected
                .selected_closure()
                .closure()
                .objects()
                .is_superset(&original_objects)
        );
        assert!(
            selected
                .selected_closure()
                .closure()
                .objects()
                .contains(&expected_tree)
        );
        assert!(
            selected
                .selected_closure()
                .closure()
                .objects()
                .contains(&candidate.binding.commit)
        );
        let commit = node.read_git_object(candidate.binding.commit).unwrap();
        let commit = std::str::from_utf8(commit.payload()).unwrap();
        assert!(commit.starts_with(&format!(
            "tree {expected_tree}\nparent {}\nparent {}\n",
            candidate.data.target_tip, candidate.data.source_tip
        )));
        let request = node.request_context();
        let queue = node
            .runtime()
            .block_on(node.read_queue_in(&request, &Default::default(), QueueNumber::FIRST, None))
            .unwrap()
            .queue
            .unwrap();
        assert_eq!(queue.version.get(), 4);
        assert_eq!(
            queue.deterministic_order(),
            vec![PullRequestNumber::try_new(2).unwrap()]
        );
        assert!(queue.active_batch.is_none());
        let pulls = node
            .runtime()
            .block_on(node.read_pull_requests_in(&request, &Default::default(), 0, 100, None))
            .unwrap();
        assert_eq!(pulls.pull_requests[0].event.version.get(), 2);
        assert!(
            matches!(&pulls.pull_requests[0].event.payload, ForgeEventPayload::MergeCommittedNative(merge) if merge.merge_commit == candidate.binding.commit && merge.base_tip == candidate.binding.merge_base)
        );
        assert_eq!(pulls.pull_requests[1].event.version.get(), 1);
        let history = node
            .runtime()
            .block_on(node.snapshot_history_in(&request))
            .unwrap();
        let last = history.last().unwrap();
        assert_eq!(last.batch.decisions.len(), 1);
        assert_eq!(last.batch.committed_rcrs.len(), 1);
        assert_eq!(last.forge_events.len(), 3);
        assert!(
            matches!(&last.forge_events[0].payload, ForgeEventPayload::MergeQueueChangedNative(change) if matches!(&change.action, QueueAction::BatchFormed { .. }))
        );
        assert!(matches!(
            &last.forge_events[1].payload,
            ForgeEventPayload::MergeCommittedNative(_)
        ));
        assert!(
            matches!(&last.forge_events[2].payload, ForgeEventPayload::MergeQueueChangedNative(change) if matches!(&change.action, QueueAction::BatchLanded { target_tip, .. } if *target_tip == candidate.binding.commit))
        );
        protect(&node, &candidate.data, 1, candidate.epoch, true);
        node.shutdown().unwrap();

        let node = reopen(&config);
        let server = Server::start(node, &credentials, 4, false, true);
        assert_eq!(
            publish(
                &server.client,
                1,
                'c',
                "candidate-lost-reply",
                &form,
                None,
                true
            ),
            original
        ); // 1
        assert_eq!(
            get(
                &server.client,
                &format!("/api/v1/queues/1?expected_head={pin}"),
                'a'
            ),
            historical
        ); // 2
        let recovered = lookup(&server.client, 'd', "candidate-lost-reply"); // 3
        status(&recovered, 200);
        let tx = original
            .body
            .split_once("\"tx_id\":\"")
            .unwrap()
            .1
            .split('"')
            .next()
            .unwrap();
        assert!(recovered.body.contains(tx));
        assert!(recovered.body.contains("committed"));
        let reused = publish(
            &server.client,
            1,
            'c',
            "candidate-lost-reply",
            &form.replace("expected_version=2", "expected_version=4"),
            Some(&candidate.bundle),
            false,
        ); // 4
        status(&reused, 409);
        assert!(reused.body.contains("idempotency_key_reuse"));
        assert_eq!(server.finish().accepted_sessions(), 4);
        let node = reopen(&config);
        assert_eq!(generation(&node), original_generation + 2);
        assert_eq!(
            node.runtime()
                .block_on(node.materialize_admission())
                .unwrap()
                .snapshot()
                .refs,
            expected_refs
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn candidate_upload_scope_and_malformed_bytes_preserve_reusable_keys_and_exact_stale_refusals() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let Fixture {
            node,
            candidate,
            config,
            ..
        } = divergent(&root, format);
        enqueue(&node, &candidate.data, 2, 2, 0);
        let before = generation(&node);
        let credentials = root.0.join("credentials");
        let binding = queue_credentials(&node, &credentials, "none");
        let form = candidate_form(&candidate, node.repository_incarnation_id());
        let second = form
            .replace("expected_version=2", "expected_version=1")
            .replace("pull_request=1&", "pull_request=2&");
        let server = Server::start(node, &credentials, 11, false, true);
        let client = &server.client;
        status(
            &publish(
                client,
                2,
                'b',
                "candidate-repair",
                &second,
                Some(&candidate.bundle),
                false,
            ),
            403,
        ); // 1
        let denied = publish(
            client,
            2,
            'c',
            "candidate-repair",
            &second,
            Some(&candidate.bundle),
            false,
        ); // 2
        status(&denied, 403);
        assert!(denied.body.contains("ref_write_scope_denied"));
        assert!(
            lookup(client, 'd', "candidate-repair")
                .body
                .contains("key_not_observed")
        ); // 3
        write_credentials(
            &credentials,
            &binding,
            &format!("exact:{}", hex(candidate.data.source_ref.as_bytes())),
        );
        status(
            &publish(
                client,
                2,
                'c',
                "candidate-repair",
                &second,
                Some(&candidate.bundle),
                true,
            ),
            403,
        ); // 4
        write_credentials(
            &credentials,
            &binding,
            &format!("exact:{}", hex(candidate.data.target_ref.as_bytes())),
        );
        let malformed = publish(
            client,
            2,
            'c',
            "candidate-repair",
            &second,
            Some(b"not a native Git bundle"),
            false,
        ); // 5
        status(&malformed, 503);
        assert!(malformed.body.contains("outcome_unknown"));
        let unsealed = lookup(client, 'd', "candidate-repair"); // 6
        status(&unsealed, 200);
        assert!(unsealed.body.contains("key_not_observed"));
        let stale_queue_form = form.replace("expected_version=2", "expected_version=1");
        let stale = publish(
            client,
            1,
            'c',
            "candidate-stale-queue",
            &stale_queue_form,
            Some(&candidate.bundle),
            true,
        ); // 7
        refused_landing(&stale, "EvidenceStale");
        refused_landing(
            &publish(
                client,
                1,
                'c',
                "candidate-stale-policy",
                &form.replace("expected_policy_epoch=2", "expected_policy_epoch=1"),
                Some(&candidate.bundle),
                false,
            ),
            "EvidenceStale",
        ); // 8
        landed_candidate(
            &publish(
                client,
                2,
                'c',
                "candidate-repair",
                &second,
                Some(&candidate.bundle),
                true,
            ),
            &candidate,
        ); // 9
        // A different legitimate queue advanced the target while this queue
        // and its first PR retained their exact versions and selected policy.
        refused_landing(
            &publish(
                client,
                1,
                'c',
                "candidate-target-moved",
                &form,
                Some(&candidate.bundle),
                false,
            ),
            "TargetRefMoved",
        ); // 10
        assert_eq!(
            publish(
                client,
                1,
                'c',
                "candidate-stale-queue",
                &stale_queue_form,
                None,
                true
            ),
            stale
        ); // 11
        assert_eq!(server.finish().accepted_sessions(), 11);
        let node = reopen(&config);
        assert_eq!(
            generation(&node),
            before + 4,
            "only three refusals and one real landing publish decisions"
        );
        let request = node.request_context();
        let queue = node
            .runtime()
            .block_on(node.read_queue_in(&request, &Default::default(), QueueNumber::FIRST, None))
            .unwrap()
            .queue
            .unwrap();
        assert_eq!(queue.version.get(), 2);
        assert_eq!(queue.entries.len(), 2);
        let second_queue = node
            .runtime()
            .block_on(node.read_queue_in(
                &request,
                &Default::default(),
                QueueNumber::try_new(2).unwrap(),
                None,
            ))
            .unwrap()
            .queue
            .unwrap();
        assert_eq!(second_queue.version.get(), 3);
        assert!(second_queue.entries.is_empty());
        let pulls = node
            .runtime()
            .block_on(node.read_pull_requests_in(&request, &Default::default(), 0, 100, None))
            .unwrap();
        assert_eq!(pulls.pull_requests[0].event.version.get(), 1);
        assert_eq!(pulls.pull_requests[1].event.version.get(), 2);
        let selected = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(
            selected.snapshot().refs[&candidate.data.target_ref],
            candidate.binding.commit
        );
        assert_eq!(
            selected.snapshot().refs[&candidate.data.source_ref],
            candidate.data.source_tip
        );
        node.shutdown().unwrap();
    }
}
