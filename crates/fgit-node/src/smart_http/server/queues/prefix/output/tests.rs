use super::*;

use fgit_crypto::{DigestAlgorithm, sha256_digest};
use fgit_forge::event::review::ReviewSubject;
use fgit_forge::preparation::queue_prefix::PreparedPrefix;
use fgit_forge::preparation::{MergeConflict, MergeMetadata};
use fgit_forge::{AggregateVersion, PullRequestNumber, QueueNumber};
use fgit_schema::json::{self, Value};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DigestBytes, PolicyEpoch, RefName, RepositoryAuthorityHeadId,
    RepositoryId, RepositoryIncarnationId, TenantId,
};
use fgit_wire::smart_http::HttpVersion;

fn oid(format: GitHashAlgorithm, byte: u8) -> GitOid {
    GitOid::from_hex(format, &format!("{byte:02x}").repeat(format.digest_len())).unwrap()
}
fn fixture(format: GitHashAlgorithm) -> PreparedQueuePrefixBundle {
    let target = oid(format, 1);
    let entries = (0..2)
        .map(|index| QueuePrefixEntry {
            subject: ReviewSubject {
                pull_request: PullRequestNumber::try_new(index as u64 + 1).unwrap(),
                pull_request_version: AggregateVersion::try_new(3 + index as u64).unwrap(),
                source_ref: RefName::try_new(format!("refs/heads/topic-{index}").as_bytes())
                    .unwrap(),
                target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
                source_tip: oid(format, 2 + index),
                target_tip: target,
                policy_epoch: PolicyEpoch::try_new(7).unwrap(),
            },
            metadata: MergeMetadata {
                author: "Test <test@example.invalid>".into(),
                committer: "Test <test@example.invalid>".into(),
                timestamp: 1,
                message: b"prefix\n".to_vec(),
            },
        })
        .collect::<Vec<_>>();
    let steps = vec![
        PrefixStep {
            source: entries[0].subject.source_tip,
            base: target,
            projected_target: target,
            tree: oid(format, 4),
            commit: oid(format, 6),
        },
        PrefixStep {
            source: entries[1].subject.source_tip,
            base: target,
            projected_target: oid(format, 6),
            tree: oid(format, 5),
            commit: oid(format, 7),
        },
    ];
    PreparedQueuePrefixBundle {
        number: QueueNumber::FIRST,
        expected_version: AggregateVersion::try_new(8).unwrap(),
        source_head: RepositoryAuthorityHeadId::from_digest(
            DigestAlgorithm::Sha256.id(),
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[9; 32]).unwrap(),
        ),
        entries,
        profile: MergeProfile::PathMergeV1,
        preparation_id: Some([10; 32]),
        outcome: PrefixPreparation::Clean(PreparedPrefix {
            initial_target: target,
            final_commit: oid(format, 7),
            steps,
            objects: Vec::new(),
        }),
        bundle: Some(b"# formatter fixture\nPACK\0\xff\r\n".to_vec()),
    }
}
fn render(
    format: GitHashAlgorithm,
    prepared: PreparedQueuePrefixBundle,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<Vec<u8>, ApiError> {
    let reply = build_bound(
        Binding {
            tenant: TenantId::from_bytes([1; 16]),
            repository: RepositoryId::from_bytes([2; 16]),
            incarnation: RepositoryIncarnationId::from_bytes([3; 16]),
        },
        format,
        prepared,
        maximum,
        live,
    )?;
    let mut bytes = Vec::new();
    reply.send(&mut bytes, HttpVersion::Http11).unwrap();
    Ok(bytes)
}
fn metadata(wire: &[u8]) -> Value {
    let start = wire.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let body = &wire[start..];
    if body.starts_with(b"--") {
        let start = body.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let end = body[start..]
            .windows(4)
            .position(|w| w == b"\r\n--")
            .unwrap()
            + start;
        json::parse(&body[start..end]).unwrap()
    } else {
        json::parse(body).unwrap()
    }
}
fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.object().unwrap().get(key).unwrap()
}
fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    let Value::Array(values) = field(value, key) else {
        panic!("array {key}")
    };
    values
}

#[test]
fn clean_prefix_keeps_original_subjects_separate_from_the_projected_chain_and_exact_binary() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let prepared = fixture(format);
        let bundle = prepared.bundle.clone().unwrap();
        let wire = render(format, prepared, 64 * 1024, &mut || true).unwrap();
        assert!(wire.starts_with(b"HTTP/1.1 200 "));
        assert!(wire.windows(bundle.len()).any(|window| window == bundle));
        let document = metadata(&wire);
        assert_eq!(
            field(&document, "type").text(),
            Some("queue_prefix_preparation")
        );
        assert_eq!(field(&document, "state").text(), Some("clean"));
        assert_eq!(
            field(&document, "publication_supported"),
            &Value::Bool(false)
        );
        assert_eq!(field(&document, "objects_staged"), &Value::Bool(false));
        assert!(!document.object().unwrap().contains_key("landing"));
        let subjects = array(&document, "original_subjects");
        let steps = array(&document, "projected_steps");
        assert_eq!(subjects.len(), 2);
        assert_eq!(steps.len(), 2);
        assert_eq!(
            field(&subjects[1], "target_tip").text().unwrap(),
            oid(format, 1).to_string()
        );
        assert_eq!(
            field(&steps[1], "projected_target_tip").text().unwrap(),
            oid(format, 6).to_string()
        );
        assert_eq!(
            field(field(&document, "candidate"), "commit")
                .text()
                .unwrap(),
            oid(format, 7).to_string()
        );
        assert_eq!(
            field(field(&document, "bundle"), "sha256").text().unwrap(),
            hex(&sha256_digest(&bundle))
        );
        assert_eq!(
            field(field(&document, "bundle"), "bytes").unsigned(),
            Some(bundle.len() as u64)
        );
        assert_eq!(field(&document, "stop"), &Value::Null);
    }
}

#[test]
fn every_later_stop_is_conflict_json_without_an_artifact_or_shortened_success() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for conflict in [false, true] {
            let mut prepared = fixture(format);
            let PrefixPreparation::Clean(plan) = prepared.outcome else {
                panic!()
            };
            prepared.outcome = PrefixPreparation::Stopped {
                index: 1,
                source: prepared.entries[1].subject.source_tip,
                projected_target: plan.steps[0].commit,
                completed: vec![plan.steps[0]],
                reason: if conflict {
                    PrefixStop::Conflicted {
                        base: oid(format, 1),
                        conflicts: vec![MergeConflict {
                            path: b"src/\xff".to_vec(),
                            kind: ConflictKind::Content,
                            base: None,
                            ours: None,
                            theirs: None,
                        }],
                    }
                } else {
                    PrefixStop::AlreadyIntegrated
                },
            };
            prepared.bundle = None;
            prepared.preparation_id = None;
            let wire = render(format, prepared, 64 * 1024, &mut || true).unwrap();
            assert!(wire.starts_with(b"HTTP/1.1 409 "));
            assert!(!wire.windows(15).any(|window| window == b"multipart/mixed"));
            let document = metadata(&wire);
            assert_eq!(field(&document, "state").text(), Some("stopped"));
            for absent in ["candidate", "bundle", "preparation_id"] {
                assert_eq!(field(&document, absent), &Value::Null);
            }
            assert_eq!(array(&document, "original_subjects").len(), 2);
            assert_eq!(array(&document, "projected_steps").len(), 1);
            let stop = field(&document, "stop");
            assert_eq!(field(stop, "index").unsigned(), Some(1));
            assert_eq!(field(stop, "pull_request").unsigned(), Some(2));
            assert_eq!(
                field(stop, "reason").text(),
                Some(if conflict {
                    "conflicted"
                } else {
                    "already_integrated"
                })
            );
            if conflict {
                assert_eq!(
                    field(&array(stop, "conflicts")[0], "path_hex").text(),
                    Some("7372632fff")
                );
            } else {
                assert_eq!(field(stop, "merge_base"), &Value::Null);
                assert!(array(stop, "conflicts").is_empty());
            }
        }
    }
}

#[test]
fn malformed_artifact_shapes_bounds_and_cancellation_remain_read_only_failures() {
    let format = GitHashAlgorithm::Sha1;
    for fault in 0..5 {
        let mut prepared = fixture(format);
        match fault {
            0 => prepared.preparation_id = None,
            1 => prepared.bundle = None,
            2 => {
                let PrefixPreparation::Clean(plan) = &mut prepared.outcome else {
                    panic!()
                };
                plan.steps[1].projected_target = plan.initial_target;
            }
            3 => {
                let PrefixPreparation::Clean(plan) = &mut prepared.outcome else {
                    panic!()
                };
                plan.steps.pop();
            }
            _ => {
                prepared.outcome = PrefixPreparation::Stopped {
                    index: 0,
                    source: prepared.entries[0].subject.source_tip,
                    projected_target: prepared.entries[0].subject.target_tip,
                    completed: Vec::new(),
                    reason: PrefixStop::AlreadyIntegrated,
                }
            }
        }
        let error = render(format, prepared, 64 * 1024, &mut || true).unwrap_err();
        assert!(!error.outcome_unknown, "{fault}");
    }
    let limited = render(format, fixture(format), 1, &mut || true).unwrap_err();
    assert_eq!(limited.status, Status::TooLarge);
    assert!(!limited.outcome_unknown);
    let stopped = render(format, fixture(format), 64 * 1024, &mut || false).unwrap_err();
    assert_eq!(stopped.status, Status::Timeout);
    assert!(!stopped.outcome_unknown);
}
