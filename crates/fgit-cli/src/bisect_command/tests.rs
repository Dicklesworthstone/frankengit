use super::*;
use fgit_forge::bisection::{
    BisectionRange, MonotonicityShape, PredicateOutcome, ProbeObservation,
    search_published_positions,
};
use fgit_node::source_retrieval::bisection::{Predicate, PullState, head_token};
use fgit_types::{
    CodecVersion, DecisionSequence, DigestAlgorithmId, DigestBytes, GitHashAlgorithm, PolicyEpoch,
    RefName, RepositoryAuthorityHeadId, RepositoryId, RepositoryIncarnationId, TenantId,
};
fn args(extra: &[&str]) -> Vec<String> {
    [
        vec![
            "not-created-bisect-root".into(),
            "11".repeat(16),
            "22".repeat(16),
            "--trusted-local".into(),
        ],
        extra.iter().map(|s| s.to_string()).collect(),
    ]
    .concat()
}
fn id() -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(1).unwrap(),
        CodecVersion::new(1, 0),
        DigestBytes::try_new(&[3; 32]).unwrap(),
    )
}
#[test]
fn strict_predicates_and_full_snapshot_tokens_round_trip() {
    for selector in [
        vec!["--ref", "refs/heads/main", "--absent"],
        vec!["--policy-at-least", "1"],
        vec!["--issue", "2", "--state", "closed"],
        vec!["--pull", "3", "--state", "merged"],
    ] {
        let parsed = options::parse(&args(&selector)).unwrap();
        assert_eq!(parsed.query.start.get(), 1);
        assert!(parsed.query.end.is_none());
        assert_eq!(parsed.query.max_probes, 4096);
    }
    let mut selected = args(&[
        "--pull",
        "3",
        "--state",
        "merged",
        "--start",
        "2",
        "--end",
        "9",
        "--max-probes",
        "17",
    ]);
    selected.extend([
        "--expected-head".into(),
        head_token(id()),
        "--expected-incarnation".into(),
        "44".repeat(16),
    ]);
    let parsed = options::parse(&selected).unwrap();
    assert_eq!(parsed.query.expected_head, Some(id()));
    assert_eq!(parsed.query.end.unwrap().get(), 9);
    assert!(matches!(
        parsed.query.predicate,
        Predicate::PullRequestState {
            state: PullState::Merged,
            ..
        }
    ));
    assert!(parsed.incarnation.is_some());
}
#[test]
fn malformed_conflicting_and_untrusted_requests_never_reach_storage() {
    for selector in [
        vec![],
        vec!["--ref", "refs/heads/main"],
        vec!["--ref", "refs/heads/main", "--absent", "--equals", "bad"],
        vec!["--issue", "1", "--state", "merged"],
        vec!["--issue", "1", "--state", "open", "--policy-at-least", "1"],
        vec!["--policy-at-least", "1", "--start", "4", "--end", "3"],
        vec!["--policy-at-least", "1", "--max-probes", "4097"],
        vec!["--policy-at-least", "1", "--max-probes", "0"],
        vec![
            "--policy-at-least",
            "1",
            "--max-probes",
            "1",
            "--max-probes",
            "2",
        ],
        vec!["--policy-at-least", "1", "--actor", "any"],
        vec!["--policy-at-least", "1", "--assume-monotone"],
        vec!["--policy-at-least", "1", "--trusted-local"],
        vec!["--policy-at-least", "1", "--end", "18446744073709551616"],
    ] {
        assert!(options::parse(&args(&selector)).is_err(), "{selector:?}");
    }
    let mut missing = args(&["--policy-at-least", "1"]);
    missing.remove(3);
    assert!(options::parse(&missing).is_err());
    for text in [
        "",
        "alg:1:00",
        "head:alg:01:codec:1.0:abcd",
        "head:alg:1:codec:01.0:abcd",
        "head:alg:1:codec:1.0:ABCDEF",
        "head:alg:1:codec:1.0:abc",
    ] {
        let input = args(&["--policy-at-least", "1", "--expected-head", text]);
        assert!(options::parse(&input).is_err(), "{text}");
    }
}
#[test]
fn native_oid_domains_and_numeric_boundaries_are_explicit() {
    for width in [40, 64] {
        let oid = "a".repeat(width);
        let parsed =
            options::parse(&args(&["--ref", "refs/heads/main", "--equals", &oid])).unwrap();
        assert!(
            matches!(parsed.query.predicate,Predicate::RefEquals{target,..}if target.as_bytes().len()*2==width)
        );
    }
    for oid in [
        "0".repeat(40),
        "0".repeat(64),
        "A".repeat(40),
        "a".repeat(41),
    ] {
        assert!(options::parse(&args(&["--ref", "refs/heads/main", "--equals", &oid])).is_err());
    }
    for max in ["1", "4096"] {
        assert!(
            options::parse(&args(&[
                "--policy-at-least",
                "18446744073709551615",
                "--max-probes",
                max
            ]))
            .is_ok()
        );
    }
}
fn report() -> Report {
    let repository = RepositoryId::from_bytes([2; 16]);
    let sequence = DecisionSequence::FIRST;
    let predicate = Predicate::RefAbsent {
        name: RefName::try_new(b"refs/heads/main").unwrap(),
    };
    let search = search_published_positions(
        repository,
        BisectionRange::new(sequence, sequence).unwrap(),
        MonotonicityShape::LinearOnly { max_steps: 1 },
        &[sequence],
        |_| {
            Ok(ProbeObservation {
                outcome: Ok(PredicateOutcome::Satisfied),
                head_id: id(),
                policy_epoch: PolicyEpoch::FIRST,
                replayed_batches: 1,
            })
        },
        &mut || true,
    );
    Report {
        tenant: TenantId::from_bytes([1; 16]),
        repository,
        incarnation: RepositoryIncarnationId::from_bytes([4; 16]),
        format: GitHashAlgorithm::Sha1,
        source_head: id(),
        source_generation: 1,
        current_policy_epoch: PolicyEpoch::FIRST,
        query: Query::new(sequence, predicate),
        history_batches: 1,
        history_events: 0,
        published_positions: 1,
        positions_digest: "00".repeat(32),
        search,
    }
}
#[test]
fn output_write_or_flush_failure_is_not_a_completed_receipt() {
    struct Broken(bool);
    impl Write for Broken {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.0 {
                Ok(bytes.len())
            } else {
                Err(io::Error::other("write failed"))
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("flush failed"))
        }
    }
    let report = report();
    let mut bytes = Vec::new();
    assert_eq!(write_report(&report, &mut bytes).unwrap(), 0);
    assert!(bytes.ends_with(b"\n"));
    assert!(String::from_utf8(bytes).unwrap().contains("receipt_sha256"));
    assert!(write_report(&report, &mut Broken(false)).is_err());
    assert!(write_report(&report, &mut Broken(true)).is_err());
}
