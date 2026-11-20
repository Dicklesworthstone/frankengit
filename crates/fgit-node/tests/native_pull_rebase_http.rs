#![forbid(unsafe_code)]
//! Real TCP requests over imported native histories. In particular a protected
//! file added and then removed by the series must still require its reviewer.
#[path = "candidate_preparation_http/support.rs"]
mod support;
use support::*;

use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id, sha256_digest};
use fgit_forge::event::protection::{
    PathReviewRule, PathReviewScope, ProtectedBranch, ProtectionCommand, ReviewProtection,
};
use fgit_forge::event::pull_request::PullRequestData;
use fgit_forge::event::review::{CandidateBinding, ReviewSubject};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_node::{LoopbackReceiveSession, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, PolicyEpoch, RefName};
use fgit_wire::visibility::RefVisibility;
use std::fs;
use std::path::Path;

fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, body);
    let bytes = [
        format!("{} {}\0", kind.label(), body.len()).as_bytes(),
        body,
    ]
    .concat();
    let length = u16::try_from(bytes.len()).unwrap();
    let mut zlib = vec![0x78, 0x01, 0x01];
    zlib.extend(length.to_le_bytes());
    zlib.extend((!length).to_le_bytes());
    zlib.extend(&bytes);
    let (a, b) = bytes.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521;
        (a, (b + a) % 65_521)
    });
    zlib.extend(((b << 16) | a).to_be_bytes());
    let name = id.to_string();
    let directory = root.join("objects").join(&name[..2]);
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join(&name[2..]), zlib).unwrap();
    id
}

struct History {
    data: PullRequestData,
    base: GitOid,
    first: GitOid,
    epoch: PolicyEpoch,
}

fn history(
    root: &Scratch,
    format: GitHashAlgorithm,
    protected: bool,
    conflict: bool,
) -> (OneNode, History) {
    let source = root.0.join("rebase-source");
    fs::create_dir_all(source.join("refs/heads")).unwrap();
    fs::write(source.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(
        source.join("config"),
        match format {
            GitHashAlgorithm::Sha1 => "[core]\nbare=true\nrepositoryformatversion=0\n",
            GitHashAlgorithm::Sha256 => {
                "[core]\nbare=true\nrepositoryformatversion=1\n[extensions]\nobjectformat=sha256\n"
            }
        },
    )
    .unwrap();
    let tree = |entries: &[(&[u8], &[u8])]| {
        let mut body = Vec::new();
        for (name, bytes) in entries {
            let blob = loose(&source, format, GitObjectKind::Blob, bytes);
            body.extend(b"100644 ");
            body.extend(*name);
            body.push(0);
            body.extend(blob.as_bytes());
        }
        loose(&source, format, GitObjectKind::Tree, &body)
    };
    let commit = |tree: GitOid, parent: Option<GitOid>, message: &str| {
        loose(
            &source,
            format,
            GitObjectKind::Commit,
            format!(
                "tree {tree}\n{}author Original <original@example.invalid> 5 -0330\ncommitter Original <original@example.invalid> 6 +0000\n\n{message}\n",
                parent.map_or_else(String::new, |id| format!("parent {id}\n"))
            )
            .as_bytes(),
        )
    };
    let base = commit(tree(&[(b"keep", b"unchanged\n")]), None, "base");
    let target_tree = if conflict {
        tree(&[
            (b"final", b"conflicting target change\n"),
            (b"keep", b"unchanged\n"),
            (b"target", b"target-only\n"),
        ])
    } else {
        tree(&[(b"keep", b"unchanged\n"), (b"target", b"target-only\n")])
    };
    let target = commit(target_tree, Some(base), "target");
    let first = commit(
        tree(&[(b"keep", b"unchanged\n"), (b"zz-private", b"temporary\n")]),
        Some(base),
        "first original message",
    );
    let tip = commit(
        tree(&[(b"final", b"final-change\n"), (b"keep", b"unchanged\n")]),
        Some(first),
        "second original message",
    );
    for (name, id) in [("main", target), ("topic", tip)] {
        fs::write(source.join("refs/heads").join(name), format!("{id}\n")).unwrap();
    }
    let (mut node, _) = OneNode::init(root.config(format)).unwrap();
    let head = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap();
    node.bring_into_service(head.receipt().generation())
        .unwrap();
    let imported = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &node.request_context(),
            &source,
            OWNER,
            b"native-pr-rebase-http-history",
        ))
        .unwrap();
    assert!(
        imported
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    let mut epoch = PolicyEpoch::FIRST;
    if protected {
        let protection = ProtectionCommand {
            expected_version: ExpectedVersion::NewStream,
            expected_epoch: epoch,
            protection: ReviewProtection {
                administrators: vec![OWNER],
                ref_policy: None,
                branches: vec![ProtectedBranch {
                    name: RefName::try_new(b"refs/heads/main").unwrap(),
                    reviewers: Vec::new(),
                    required_approvals: 0,
                    required_checks: Vec::new(),
                    required_candidate_checks: Vec::new(),
                    require_merge_queue: false,
                    path_reviews: vec![PathReviewRule {
                        path: b"zz-private".to_vec(),
                        scope: PathReviewScope::Exact,
                        reviewers: vec![REVIEWER],
                        required_approvals: 1,
                    }],
                }],
            },
        };
        let (_, terminal) = node
            .runtime()
            .block_on(node.admit_review_protection_durable_in(
                &node.request_context(),
                &LoopbackReceiveSession::authenticated(
                    OWNER,
                    IdempotencyKey::new(b"protect-temporary-path".to_vec()).unwrap(),
                ),
                &protection,
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        epoch = epoch.next().unwrap();
    }
    (
        node,
        History {
            data: PullRequestData {
                source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
                target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
                source_tip: tip,
                target_tip: target,
                title: "Review a complete rebase series".into(),
                body: "The temporary protected file is absent from the final tree.".into(),
            },
            base,
            first,
            epoch,
        },
    )
}

fn credentials(node: &OneNode, path: &Path) {
    replace(
        path,
        &(header(node)
            + &row('a', OWNER, "outcomes-read,pulls-read,pulls-write")
            + &row('b', REVIEWER, "outcomes-read,reviews-read,reviews-write")
            + &row('c', MERGER, "outcomes-read,merges-write")
            + &row('d', FOREIGN, "read,pulls-read")
            + &row('e', SECOND, "reviews-write")
            + &row('f', FOREIGN, "read")),
    );
}

fn preparation(f: &History) -> String {
    format!(
        "object_format={}&pull_request_version=1&policy_epoch={}&source_ref=refs%2Fheads%2Ftopic&target_ref=refs%2Fheads%2Fmain&source_tip={}&target_tip={}&profile=path-v1&upstream={}&committer=Rebaser+%3Crebaser%40example.invalid%3E&timestamp=100&empty=stop",
        f.base.algorithm().as_str(),
        f.epoch.get(),
        f.data.source_tip,
        f.data.target_tip,
        f.base,
    )
}

fn read_request(
    endpoint: &Endpoint,
    action: &str,
    token: char,
    command: &str,
    bundle: Option<&[u8]>,
    chunked: bool,
) -> BinaryReply {
    let (body, content_type) = if let Some(bundle) = bundle {
        let mut body = b"--inspect-boundary\r\nContent-Disposition: form-data; name=\"command\"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n".to_vec();
        body.extend(command.as_bytes());
        body.extend(b"\r\n--inspect-boundary\r\nContent-Disposition: form-data; name=\"bundle\"; filename=\"candidate.bundle\"\r\nContent-Type: application/x-git-bundle\r\n\r\n");
        body.extend(bundle);
        body.extend(b"\r\n--inspect-boundary--\r\n");
        (body, "multipart/form-data; boundary=inspect-boundary")
    } else {
        (
            command.as_bytes().to_vec(),
            "application/x-www-form-urlencoded",
        )
    };
    let (wire, framing) = if chunked {
        let mut wire = Vec::new();
        for bytes in body.chunks(17) {
            wire.extend(format!("{:x}\r\n", bytes.len()).as_bytes());
            wire.extend(bytes);
            wire.extend(b"\r\n");
        }
        wire.extend(b"0\r\n\r\n");
        (wire, "Transfer-Encoding: chunked\r\n".to_owned())
    } else {
        let framing = format!("Content-Length: {}\r\n", body.len());
        (body, framing)
    };
    binary_exchange(
        endpoint,
        &request(
            endpoint,
            "POST",
            &format!("/api/v1/pulls/1/{action}"),
            token,
            &format!("Content-Type: {content_type}\r\n{framing}"),
            &wire,
        ),
        true,
    )
}

// These fixture-only readers select closed scalar fields; they never parse
// arbitrary repository strings or provide a product JSON implementation.
fn field<'a>(text: &'a str, name: &str) -> &'a str {
    text.split_once(&format!("\"{name}\":\""))
        .unwrap()
        .1
        .split('"')
        .next()
        .unwrap()
}

fn candidate(reply: &BinaryReply, f: &History) -> (Candidate, String) {
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    let boundary = reply
        .head
        .lines()
        .find_map(|line| line.strip_prefix("Content-Type: multipart/mixed; boundary="))
        .unwrap()
        .trim();
    let body = reply
        .body
        .strip_prefix(format!("--{boundary}\r\n").as_bytes())
        .unwrap();
    let start = body.windows(4).position(|b| b == b"\r\n\r\n").unwrap() + 4;
    let body = &body[start..];
    let delimiter = format!("\r\n--{boundary}\r\n");
    let split = body
        .windows(delimiter.len())
        .position(|b| b == delimiter.as_bytes())
        .unwrap();
    let metadata = String::from_utf8(body[..split].to_vec()).unwrap();
    let body = &body[split + delimiter.len()..];
    let start = body.windows(4).position(|b| b == b"\r\n\r\n").unwrap() + 4;
    let bundle = body[start..]
        .strip_suffix(format!("\r\n--{boundary}--\r\n").as_bytes())
        .unwrap()
        .to_vec();
    assert_eq!(numeric(&metadata, "bytes"), bundle.len() as u64);
    let digest: String = sha256_digest(&bundle)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(field(&metadata, "sha256"), digest);
    assert_eq!(field(&metadata, "type"), "pull_request_rebase_preparation");
    assert_eq!(field(&metadata, "method"), "rebase");
    assert_eq!(
        field(&metadata, "source_tip"),
        f.data.source_tip.to_string()
    );
    assert_eq!(
        field(&metadata, "target_tip"),
        f.data.target_tip.to_string()
    );
    for flag in [
        "\"read_only\":true",
        "\"objects_staged\":false",
        "\"transaction_created\":false",
    ] {
        assert!(metadata.contains(flag), "{metadata}");
    }
    assert_eq!(metadata.matches("\"original\":").count(), 2);
    assert!(metadata.contains(&f.first.to_string()));
    let binding = CandidateBinding {
        merge_base: GitOid::from_hex(f.base.algorithm(), field(&metadata, "merge_base")).unwrap(),
        commit: GitOid::from_hex(f.base.algorithm(), field(&metadata, "candidate_commit")).unwrap(),
    };
    assert_eq!(binding.merge_base, f.base);
    assert!(
        bundle
            .windows(format!("{} refs/heads/main\n", binding.commit).len())
            .any(|b| b == format!("{} refs/heads/main\n", binding.commit).as_bytes())
    );
    (
        Candidate {
            data: f.data.clone(),
            binding,
            epoch: f.epoch,
            bundle,
        },
        metadata,
    )
}

#[test]
fn rebase_http_reviews_every_step_and_publishes_only_the_target_and_pr_once() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, f) = history(&root, format, true, false);
        let before = generation(&node);
        let path = root.0.join("credentials");
        credentials(&node, &path);
        let server = Server::start(node, &path, 5, true, true);
        committed(&post(
            &server.client,
            1,
            "open",
            'a',
            "open-rebase",
            &form(&f.data, 0),
            false,
        ));
        let prepared = read_request(
            &server.client,
            "prepare-rebase",
            'd',
            &preparation(&f),
            None,
            false,
        );
        let (candidate, _) = candidate(&prepared, &f);
        assert_eq!(
            read_request(
                &server.client,
                "prepare-rebase",
                'd',
                &preparation(&f),
                None,
                true
            ),
            prepared
        );
        let inspection = read_request(
            &server.client,
            "inspect-rebase",
            'd',
            &common(&candidate),
            Some(&candidate.bundle),
            true,
        );
        assert_eq!(
            inspection.status,
            200,
            "{}",
            String::from_utf8_lossy(&inspection.body)
        );
        let report = String::from_utf8(inspection.body).unwrap();
        assert_eq!(field(&report, "type"), "pull_request_rebase_inspection");
        assert_eq!(field(&report, "method"), "rebase");
        assert!(report.contains("\"complete\":true"));
        assert!(
            report.contains("7a7a2d70726976617465"),
            "the transient zz-private path must be disclosed: {report}"
        );
        assert_eq!(
            read_request(
                &server.client,
                "inspect-rebase",
                'b',
                &common(&candidate),
                Some(&candidate.bundle),
                false
            )
            .status,
            403
        );
        assert_eq!(server.finish().accepted_sessions(), 5);

        let node = reopen(&config);
        assert_eq!(
            generation(&node),
            before + 1,
            "only opening the PR published"
        );
        assert!(node.read_git_object(candidate.binding.commit).is_err());
        let subject = ReviewSubject {
            pull_request: PullRequestNumber::FIRST,
            pull_request_version: AggregateVersion::FIRST,
            source_ref: f.data.source_ref.clone(),
            target_ref: f.data.target_ref.clone(),
            source_tip: f.data.source_tip,
            target_tip: f.data.target_tip,
            policy_epoch: f.epoch,
        };
        let inspected = node
            .runtime()
            .block_on(node.inspect_pull_request_rebase_bundle_in(
                &node.request_context(),
                &subject,
                f.base,
                candidate.binding.commit,
                &candidate.bundle,
                &RefVisibility::new(),
                None,
                &Default::default(),
            ))
            .unwrap();
        assert_eq!(inspected.commits.len(), 2);
        assert_eq!(inspected.comparisons.len(), 3);
        assert!(
            inspected.comparisons[0]
                .entries
                .iter()
                .all(|entry| entry.path != b"zz-private")
        );
        assert!(inspected.comparisons[1..].iter().all(|comparison| {
            comparison
                .entries
                .iter()
                .any(|entry| entry.path == b"zz-private")
        }));
        for commit in &inspected.commits {
            let body = std::str::from_utf8(&commit.body).unwrap();
            assert!(body.contains("author Original <original@example.invalid> 5 -0330\n"));
            assert!(body.contains("committer Rebaser <rebaser@example.invalid> 100 +0000\n"));
        }
        let outbox = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap()
            .snapshot()
            .outbox
            .len();
        let server = Server::start(node, &path, 7, true, true);
        let review = review_form(&candidate, 0) + "&method=rebase";
        accepted(&send(
            &server.client,
            "reviews/approve",
            'e',
            "named-review",
            &review,
            Some(&candidate.bundle),
            false,
        ));
        let merge = merge_form(&candidate, &[SECOND]) + "&method=rebase";
        refused(&send(
            &server.client,
            "merge",
            'c',
            "missing-path-review",
            &merge,
            Some(&candidate.bundle),
            false,
        ));
        accepted(&send(
            &server.client,
            "reviews/approve",
            'b',
            "path-review",
            &review,
            Some(&candidate.bundle),
            true,
        ));
        refused(&send(
            &server.client,
            "merge",
            'c',
            "wrong-method",
            &merge.replace("method=rebase", "method=squash"),
            Some(&candidate.bundle),
            false,
        ));
        let published = send(
            &server.client,
            "merge",
            'c',
            "land-series",
            &merge,
            Some(&candidate.bundle),
            true,
        );
        accepted(&published);
        assert!(published.body.contains("\"method\":\"rebase\""));
        assert_eq!(
            send(
                &server.client,
                "merge",
                'c',
                "land-series",
                &merge,
                None,
                false
            ),
            published
        );
        let reused = send(
            &server.client,
            "merge",
            'c',
            "land-series",
            &merge.replace("method=rebase", "method=squash"),
            Some(&candidate.bundle),
            false,
        );
        status(&reused, 409);
        assert!(reused.body.contains("idempotency_key_reuse"));
        assert_eq!(server.finish().accepted_sessions(), 7);

        let node = reopen(&config);
        let state = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(state.snapshot().refs[&f.data.source_ref], f.data.source_tip);
        assert_eq!(
            state.snapshot().refs[&f.data.target_ref],
            candidate.binding.commit
        );
        assert_eq!(
            state.snapshot().outbox.len(),
            outbox + 3,
            "only two reviews and one atomic merge enqueue delivery"
        );
        for commit in &inspected.commits {
            assert_eq!(
                node.read_git_object(commit.id).unwrap().payload(),
                commit.body
            );
        }
        let settled_generation = generation(&node);
        let server = Server::start(node, &path, 3, true, true);
        assert_eq!(
            send(
                &server.client,
                "merge",
                'c',
                "land-series",
                &merge,
                None,
                false
            ),
            published
        );
        let pull = get(&server.client, "/api/v1/pulls/1", 'a');
        status(&pull, 200);
        assert!(pull.body.contains("\"version\":2,\"state\":\"merged\""));
        assert!(pull.body.contains(&candidate.binding.commit.to_string()));
        status(&lookup(&server.client, 'c', "land-series"), 200);
        assert_eq!(server.finish().accepted_sessions(), 3);
        let node = reopen(&config);
        assert_eq!(
            generation(&node),
            settled_generation,
            "recovery never republishes"
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn stale_subjects_narrow_grants_and_partial_inspections_never_become_rebase_candidates() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, f) = history(&root, format, false, false);
        let path = root.0.join("credentials");
        credentials(&node, &path);
        let before = generation(&node);
        let server = Server::start(node, &path, 10, true, false);
        committed(&post(
            &server.client,
            1,
            "open",
            'a',
            "open-stale",
            &form(&f.data, 0),
            false,
        ));
        let command = preparation(&f);
        let (candidate, _) = candidate(
            &read_request(&server.client, "prepare-rebase", 'd', &command, None, false),
            &f,
        );
        assert_eq!(
            read_request(&server.client, "prepare-rebase", 'f', &command, None, false).status,
            403
        );
        assert_eq!(
            read_request(&server.client, "prepare-rebase", 'a', &command, None, false).status,
            403
        );
        let stale = command.replace("pull_request_version=1", "pull_request_version=2");
        assert_eq!(
            read_request(&server.client, "prepare-rebase", 'd', &stale, None, false).status,
            409
        );
        let moved = command.replace(
            &format!("source_tip={}", f.data.source_tip),
            &format!("source_tip={}", f.first),
        );
        assert_eq!(
            read_request(&server.client, "prepare-rebase", 'd', &moved, None, false).status,
            409
        );
        let inspect = common(&candidate);
        assert_eq!(
            read_request(
                &server.client,
                "inspect-rebase",
                'd',
                &(inspect.clone() + "&path=keep"),
                Some(&candidate.bundle),
                false
            )
            .status,
            400
        );
        assert_eq!(
            read_request(
                &server.client,
                "inspect-rebase",
                'd',
                &inspect,
                Some(&candidate.bundle[..candidate.bundle.len() - 1]),
                false
            )
            .status,
            400
        );
        assert_eq!(
            read_request(
                &server.client,
                "inspect-rebase",
                'd',
                &inspect.replace("pull_request_version=1", "pull_request_version=2"),
                Some(&candidate.bundle),
                false
            )
            .status,
            409
        );
        let retry = read_request(
            &server.client,
            "inspect-rebase",
            'd',
            &inspect,
            Some(&candidate.bundle),
            true,
        );
        assert_eq!(
            retry.status,
            200,
            "{}",
            String::from_utf8_lossy(&retry.body)
        );
        assert_eq!(server.finish().accepted_sessions(), 10);
        let node = reopen(&config);
        assert_eq!(generation(&node), before + 1);
        assert!(node.read_git_object(candidate.binding.commit).is_err());
        let state = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(state.snapshot().refs[&f.data.source_ref], f.data.source_tip);
        assert_eq!(state.snapshot().refs[&f.data.target_ref], f.data.target_tip);
        node.shutdown().unwrap();
    }
}

#[test]
fn a_conflict_after_a_clean_prefix_returns_no_partial_artifact_or_publication() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, f) = history(&root, format, false, true);
        let before = generation(&node);
        let path = root.0.join("credentials");
        credentials(&node, &path);
        let server = Server::start(node, &path, 3, true, false);
        committed(&post(
            &server.client,
            1,
            "open",
            'a',
            "open-conflicted",
            &form(&f.data, 0),
            false,
        ));
        let stopped = read_request(
            &server.client,
            "prepare-rebase",
            'd',
            &preparation(&f),
            None,
            false,
        );
        assert_eq!(
            stopped.status,
            409,
            "{}",
            String::from_utf8_lossy(&stopped.body)
        );
        assert!(stopped.head.contains("Content-Type: application/json"));
        let metadata = std::str::from_utf8(&stopped.body).unwrap();
        assert_eq!(field(metadata, "type"), "pull_request_rebase_preparation");
        assert_eq!(field(metadata, "state"), "conflicted");
        assert_eq!(
            field(metadata, "stopped_commit"),
            f.data.source_tip.to_string()
        );
        assert_eq!(numeric(metadata, "step_count"), 1);
        assert_eq!(field(metadata, "original"), f.first.to_string());
        assert!(metadata.contains("\"bundle\":null"));
        assert!(metadata.contains("\"candidate_commit\":null"));
        assert!(metadata.contains("\"objects_staged\":false"));
        assert!(metadata.contains("\"published\":false"));
        assert!(metadata.contains("\"series_complete\":false"));
        assert!(metadata.contains("\"provisional_steps\":true"));
        assert!(metadata.contains("\"path_hex\":\"66696e616c\""));
        let provisional = GitOid::from_hex(format, field(metadata, "rewritten")).unwrap();
        assert_eq!(
            read_request(
                &server.client,
                "prepare-rebase",
                'd',
                &preparation(&f),
                None,
                true,
            ),
            stopped
        );
        assert_eq!(server.finish().accepted_sessions(), 3);
        let node = reopen(&config);
        assert_eq!(generation(&node), before + 1);
        assert!(node.read_git_object(provisional).is_err());
        let state = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(state.snapshot().refs[&f.data.source_ref], f.data.source_tip);
        assert_eq!(state.snapshot().refs[&f.data.target_ref], f.data.target_tip);
        node.shutdown().unwrap();
    }
}
