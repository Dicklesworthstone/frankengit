#![forbid(unsafe_code)]
#![cfg(unix)]
//! Exact multi-PR preparation through the actual TCP HTTP server.
#[path = "candidate_preparation_http/support.rs"]
mod http;
#[path = "queue_prefix_preparation/support.rs"]
mod native;
#[path = "queue_prefix_http/support.rs"]
mod support;
use support::*;

use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::event::pull_request::PullRequestAction;
use fgit_forge::event::queue::DequeueReason;
use fgit_forge::merge_queue::QueueCommandAction;
use fgit_pack::full_bundle::{FullBundleInput, FullBundleLimits};
use fgit_pack::{EntryKind, NativeChecksumVerifier, PackLimits, read_verified_pack};
use fgit_schema::json::{self, Value};
use fgit_types::{GitHashAlgorithm, GitOid};
use std::collections::BTreeMap;

const FORMATS: [GitHashAlgorithm; 2] = [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256];

#[test]
fn http_prefix_exports_large_exact_native_artifacts_without_staging_or_landing() {
    for format in FORMATS {
        let mut f = Fixture::new(format, false, true);
        let message = large_message();
        for entry in &mut f.entries {
            entry.metadata.message = message.clone();
        }
        let profile = match format {
            GitHashAlgorithm::Sha1 => "path-merge-v1",
            GitHashAlgorithm::Sha256 => "exact-renames-v1",
        };
        let body = f.form(&f.entries, 2, profile);
        let before = native::state(f.native.node());
        let server = f.start(2, true);
        let first = send(&server.client, &body, false);
        let (document, bundle) = extract(&first);
        assert!(bundle.len() > 24 * 1024);
        assert_eq!(text(&document, "profile"), profile);
        assert_eq!(text(&document, "source_head"), before.head.to_string());
        assert_eq!(
            text(&document, "initial_target"),
            f.native.target.to_string()
        );
        assert_eq!(field(&document, "entry_count"), &json::number(2));
        let queue = field(&document, "queue");
        assert_eq!(field(queue, "number"), &json::number(1));
        assert_eq!(field(queue, "expected_version"), &json::number(2));
        let subjects = array(&document, "original_subjects");
        let steps = array(&document, "projected_steps");
        assert_eq!(subjects.len(), 2);
        assert_eq!(steps.len(), 2);

        let extra = git_object_id(format, GitObjectKind::Blob, b"second\n");
        let left = git_object_id(format, GitObjectKind::Blob, b"target\n");
        let right = git_object_id(format, GitObjectKind::Blob, b"source\n");
        let first_tree = git_object_id(
            format,
            GitObjectKind::Tree,
            &[
                b"100644 left\0".as_slice(),
                left.as_bytes(),
                b"100644 right\0",
                right.as_bytes(),
                b"100644 workflow.yml\0",
                f.native.workflow.as_bytes(),
            ]
            .concat(),
        );
        let second_tree = git_object_id(
            format,
            GitObjectKind::Tree,
            &[
                b"100644 extra\0".as_slice(),
                extra.as_bytes(),
                b"100644 left\0",
                left.as_bytes(),
                b"100644 right\0",
                right.as_bytes(),
                b"100644 workflow.yml\0",
                f.native.workflow.as_bytes(),
            ]
            .concat(),
        );
        let mut projected = f.native.target;
        let mut expected_commits = BTreeMap::new();
        for (index, entry) in f.entries.iter().enumerate() {
            let tree = [first_tree, second_tree][index];
            let mut bytes = format!(
                "tree {tree}\nparent {projected}\nparent {}\nauthor {} {} +0000\ncommitter {} {} +0000\n\n",
                entry.subject.source_tip, entry.metadata.author, entry.metadata.timestamp,
                entry.metadata.committer, entry.metadata.timestamp,
            ).into_bytes();
            bytes.extend_from_slice(&message);
            let commit = git_object_id(format, GitObjectKind::Commit, &bytes);
            assert_eq!(
                field(&subjects[index], "index"),
                &json::number(index as u64)
            );
            assert_eq!(
                field(&subjects[index], "pull_request"),
                &json::number(index as u64 + 1)
            );
            assert_eq!(
                text(&subjects[index], "target_tip"),
                f.native.target.to_string()
            );
            assert_eq!(
                text(&subjects[index], "source_tip"),
                entry.subject.source_tip.to_string()
            );
            assert_eq!(
                text(&subjects[index], "source_ref_hex"),
                hex(entry.subject.source_ref.as_bytes())
            );
            assert_eq!(
                text(&steps[index], "projected_target_tip"),
                projected.to_string()
            );
            assert_eq!(text(&steps[index], "merge_base"), f.native.base.to_string());
            assert_eq!(
                text(&steps[index], "source_tip"),
                entry.subject.source_tip.to_string()
            );
            assert_eq!(text(&steps[index], "tree"), tree.to_string());
            assert_eq!(text(&steps[index], "commit"), commit.to_string());
            expected_commits.insert(commit, bytes);
            projected = commit;
        }
        assert_eq!(
            text(field(&document, "candidate"), "commit"),
            projected.to_string()
        );
        assert_eq!(
            text(field(&document, "candidate"), "tree"),
            second_tree.to_string()
        );
        let parsed =
            FullBundleInput::parse_incremental(&bundle, FullBundleLimits::default(), &mut || true)
                .unwrap();
        assert_eq!(parsed.references().len(), 1);
        assert_eq!(parsed.references()[0].name(), &native::target_ref());
        assert_eq!(parsed.references()[0].target(), &projected);
        let mut prerequisites = vec![
            f.native.target,
            f.native.source,
            f.entries[1].subject.source_tip,
        ];
        prerequisites.sort();
        assert_eq!(parsed.prerequisites(), prerequisites);
        let packed = read_verified_pack(
            parsed.pack_bytes(),
            format,
            &PackLimits::default(),
            &mut || true,
            &NativeChecksumVerifier,
        )
        .unwrap();
        let mut actual_commits = BTreeMap::new();
        for object in packed.entries() {
            assert!(object.delta_base.is_none());
            let kind = match object.header.kind {
                EntryKind::Commit => GitObjectKind::Commit,
                EntryKind::Tree => GitObjectKind::Tree,
                other => panic!("the independent-path fixture emits only trees/commits: {other:?}"),
            };
            let id = git_object_id(format, kind, &object.inflated);
            if kind == GitObjectKind::Commit {
                assert!(actual_commits.insert(id, object.inflated.clone()).is_none());
            }
        }
        assert_eq!(actual_commits, expected_commits);
        assert_eq!(
            field(field(&document, "candidate"), "new_object_count")
                .unsigned()
                .unwrap(),
            packed.entries().len() as u64
        );
        assert_eq!(send(&server.client, &body, true), first);
        assert_eq!(server.finish().accepted_sessions(), 2);
        f.native.reopen();
        assert_eq!(native::state(f.native.node()), before);
        assert!(f.native.node().read_git_object(projected).is_err());

        let server = f.start(1, true);
        assert_eq!(send(&server.client, &body, false), first);
        server.finish();
        f.native.reopen();
        assert_eq!(native::state(f.native.node()), before);
    }
}

#[test]
fn exact_read_grants_and_body_limits_are_enforced_before_continue() {
    let mut f = Fixture::new(GitHashAlgorithm::Sha1, false, true);
    let before = native::state(f.native.node());
    let body = f.form(&f.entries, 2, "path-merge-v1");
    let server = f.start(12, true);
    for token in ['b', 'c', 'd', 'e', 'f'] {
        let denied = withheld(&server.client, token, "", 4096);
        assert_eq!(denied.status, 403, "{token}: {denied:?}");
        assert!(!denied.head.contains("100 Continue"));
    }
    assert_eq!(withheld(&server.client, 'z', "", 4096).status, 401);
    let keyed = withheld(
        &server.client,
        'a',
        "Idempotency-Key: cannot-land-prefix\r\n",
        4096,
    );
    assert_eq!(keyed.status, 400);
    assert!(!keyed.head.contains("100 Continue"));
    let oversized = withheld(&server.client, 'a', "", 256 * 1024 + 1);
    assert_eq!(oversized.status, 413);
    assert!(!oversized.head.contains("100 Continue"));
    // This credential has exactly the three read scopes and no ref/write grant.
    extract(&send(&server.client, &body, false));
    assert_eq!(
        send(&server.client, &"x".repeat(256 * 1024 + 1), true).status,
        413
    );
    assert_eq!(
        send(
            &server.client,
            &(body.clone() + "&principal=attacker"),
            false
        )
        .status,
        400
    );
    assert_eq!(
        send(&server.client, &(body + "&pull_request_00=1"), false).status,
        400
    );
    assert_eq!(server.finish().accepted_sessions(), 12);
    f.native.reopen();
    assert_eq!(native::state(f.native.node()), before);
}

#[test]
fn prefix_preparation_requires_both_queue_and_pull_deployment_switches() {
    for (queues, pulls) in [(false, true), (true, false)] {
        let mut f = Fixture::new(GitHashAlgorithm::Sha256, false, queues);
        let before = native::state(f.native.node());
        let server = f.start(1, pulls);
        let denied = withheld(&server.client, 'a', "", 4096);
        assert_eq!(denied.status, 403);
        assert!(!denied.head.contains("100 Continue"));
        server.finish();
        f.native.reopen();
        assert_eq!(native::state(f.native.node()), before);
    }
}

#[test]
fn indexed_guards_and_actual_reordering_cannot_silently_select_another_prefix() {
    for format in FORMATS {
        let mut f = Fixture::new(format, false, true);
        let original = f.form(&f.entries, 2, "path-merge-v1");
        let before = native::state(f.native.node());
        let mutations = [
            ("expected_version", "1".to_owned()),
            ("expected_pull_request_version_1", "2".to_owned()),
            ("expected_source_tip_1", f.native.source.to_string()),
            ("expected_target_tip", f.native.base.to_string()),
            ("expected_policy_epoch", "2".to_owned()),
        ];
        let server = f.start(6, true);
        for (name, value) in mutations {
            let refused = send(
                &server.client,
                &replace_field(&original, name, &value),
                false,
            );
            assert_eq!(
                refused.status,
                409,
                "{name}: {}",
                String::from_utf8_lossy(&refused.body)
            );
            assert!(!refused.head.contains("multipart/mixed"));
        }
        let accepted = send(&server.client, &original, false);
        let (old_document, _) = extract(&accepted);
        server.finish();
        f.native.reopen();
        assert_eq!(native::state(f.native.node()), before);

        native::change_queue(
            f.native.node(),
            2,
            QueueCommandAction::Reorder {
                order: vec![native::pr(2), native::pr(1)],
            },
            "prefix-http-reorder",
        );
        f.entries.swap(0, 1);
        let refreshed = f.form(&f.entries, 3, "path-merge-v1");
        let after_reorder = native::state(f.native.node());
        let server = f.start(2, true);
        let stale = send(&server.client, &original, false);
        assert_eq!(stale.status, 409);
        assert!(!stale.head.contains("multipart/mixed"));
        let (new_document, _) = extract(&send(&server.client, &refreshed, true));
        assert_ne!(
            text(&old_document, "preparation_id"),
            text(&new_document, "preparation_id")
        );
        assert_eq!(
            field(
                &array(&new_document, "original_subjects")[0],
                "pull_request"
            ),
            &json::number(2)
        );
        assert_eq!(
            text(&new_document, "source_head"),
            after_reorder.head.to_string()
        );
        server.finish();
        f.native.reopen();
        assert_eq!(native::state(f.native.node()), after_reorder);
    }
}

#[test]
fn later_conflict_or_already_integrated_pr_never_returns_a_shortened_artifact() {
    for format in FORMATS {
        for conflict in [true, false] {
            let mut f = Fixture::new(format, conflict, true);
            let queue_version = if conflict {
                2
            } else {
                // Two distinct canonical PRs may point at the same source.
                // Requeue the updated second PR through the actual commands.
                native::change_queue(
                    f.native.node(),
                    2,
                    QueueCommandAction::Dequeue {
                        pull_request: native::pr(2),
                        reason: DequeueReason::Withdrawn,
                    },
                    "prefix-http-remove-second",
                );
                f.entries[1].subject.source_ref = native::source_ref();
                f.entries[1].subject.source_tip = f.native.source;
                native::change_pull(
                    f.native.node(),
                    &f.entries[1],
                    PullRequestAction::Update,
                    false,
                    "prefix-http-alias-pr",
                );
                f.entries[1].subject.pull_request_version = native::version(2);
                native::change_queue(
                    f.native.node(),
                    3,
                    QueueCommandAction::Enqueue {
                        pull_request: native::pr(2),
                        expected_pull_request_version: native::version(2),
                        source_ref: native::source_ref(),
                        head_tip: f.native.source,
                        expected_target_tip: f.native.target,
                        priority: 0,
                    },
                    "prefix-http-requeue-alias",
                );
                4
            };
            let before = native::state(f.native.node());
            let one = f.form(&f.entries[..1], queue_version, "path-merge-v1");
            let both = f.form(&f.entries, queue_version, "path-merge-v1");
            let server = f.start(2, true);
            let (first, _) = extract(&send(&server.client, &one, false));
            let reply = send(&server.client, &both, true);
            assert_eq!(
                reply.status,
                409,
                "{}",
                String::from_utf8_lossy(&reply.body)
            );
            assert!(reply.head.contains("application/json"));
            assert!(!reply.head.contains("multipart/mixed"));
            let stopped = json::parse(&reply.body).unwrap();
            read_only(&stopped);
            assert_eq!(text(&stopped, "state"), "stopped");
            for name in ["preparation_id", "candidate", "bundle"] {
                assert_eq!(field(&stopped, name), &Value::Null);
            }
            let stop = field(&stopped, "stop");
            assert_eq!(field(stop, "index"), &json::number(1));
            assert_eq!(field(stop, "pull_request"), &json::number(2));
            assert_eq!(
                text(stop, "reason"),
                if conflict {
                    "conflicted"
                } else {
                    "already_integrated"
                }
            );
            assert_eq!(
                text(stop, "projected_target_tip"),
                text(field(&first, "candidate"), "commit")
            );
            assert_eq!(array(&stopped, "projected_steps").len(), 1);
            assert_eq!(array(&stopped, "original_subjects").len(), 2);
            assert_eq!(array(stop, "conflicts").len(), usize::from(conflict));
            let candidate = GitOid::from_hex(format, text(stop, "projected_target_tip")).unwrap();
            server.finish();
            f.native.reopen();
            assert!(f.native.node().read_git_object(candidate).is_err());
            assert_eq!(native::state(f.native.node()), before);
        }
    }
}
