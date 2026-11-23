use super::*;
use fgit_forge::event::pull_request::{NativePullRequestEvent, PullRequestAction, PullRequestData};
use fgit_forge::{AggregateId, ForgeEvent, ForgeEventPayload};
use fgit_types::{CANONICAL_CODEC_VERSION, DecisionSequence, DigestAlgorithmId, DigestBytes, GitOid, RefName, RefusalCode, RefusalRecordId, RepositoryCommitId};

fn args(write: bool) -> Vec<String> {
    let mut args = vec![if write { "set-labels" } else { "labels" }.into(), "node".into(), "11".repeat(16), "22".repeat(16), "7".into(), "--trusted-local".into()];
    if write { args.extend(["--principal".into(), "33".repeat(16), "--idempotency-key".into(), "original-private-key".into(), "--expected-version".into(), "0".into(), "--label".into(), "é".into(), "--label".into(), " bug ".into()]); }
    args
}
fn replace(args: &mut [String], flag: &str, value: &str) {
    let at = args.iter().position(|arg| arg == flag).unwrap();
    args[at + 1] = value.into();
}
fn addition_args() -> Vec<String> {
    let mut input = args(true);
    input[0] = "add-labels".into();
    let at = input.iter().position(|arg| arg == "--expected-version").unwrap();
    input.drain(at..at + 2);
    input
}
fn digest(seed: u8) -> DigestBytes { DigestBytes::try_new(&[seed; 32]).unwrap() }
fn algorithm() -> DigestAlgorithmId { DigestAlgorithmId::try_new(1).unwrap() }
fn head() -> RepositoryAuthorityHeadId { RepositoryAuthorityHeadId::from_digest(algorithm(), CANONICAL_CODEC_VERSION, digest(7)) }
fn view() -> PullRequestView {
    let number = PullRequestNumber::try_new(7).unwrap();
    let actor = PrincipalId::from_bytes([3; 16]);
    let data = PullRequestData {
        source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
        target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
        source_tip: GitOid::from_hex(GitHashAlgorithm::Sha1, &"11".repeat(20)).unwrap(),
        target_tip: GitOid::from_hex(GitHashAlgorithm::Sha1, &"22".repeat(20)).unwrap(),
        title: "Literal title".into(), body: "Literal body".into(),
    };
    PullRequestView {
        number,
        event: ForgeEvent { aggregate: AggregateId::PullRequest(number), version: AggregateVersion::FIRST, payload: ForgeEventPayload::PullRequestChangedNative(NativePullRequestEvent { action: PullRequestAction::Open, actor, data: data.clone() }) },
        data: Some(data), opened_by: Some(actor), last_metadata_actor: Some(actor),
        labels: Vec::new(), labels_version: None, labels_actor: None,
    }
}

#[test]
fn exact_labels_preserve_text_and_full_u64_versions_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut input = args(true);
        input.extend(["--object-format".into(), format.as_str().into()]);
        let options = parse(&input).unwrap();
        assert_eq!(options.format, format);
        let Operation::Set { command, key, .. } = options.operation else { panic!("write") };
        assert_eq!(command.labels, [" bug ", "é"]);
        assert_eq!(command.expected_version, ExpectedVersion::NewStream);
        assert_eq!(key, b"original-private-key");
        replace(&mut input, "--expected-version", "9007199254740993");
        let Operation::Set { command, .. } = parse(&input).unwrap().operation else { panic!("write") };
        assert_eq!(command.expected_version, ExpectedVersion::Exactly(AggregateVersion::try_new(9_007_199_254_740_993).unwrap()));
    }
}

#[test]
fn clearing_is_explicit_and_ambiguous_or_authority_widening_input_refuses() {
    for (flag, value) in [("--label", ""), ("--label", " \t"), ("--label", "a\0b"), ("--expected-version", "01"), ("--expected-version", "18446744073709551615"), ("--principal", "bad")] {
        let mut input = args(true); replace(&mut input, flag, value); assert!(parse(&input).is_err(), "{flag}");
    }
    for flag in ["--expected-version", "--principal", "--idempotency-key"] {
        let mut input = args(true); let at = input.iter().position(|arg| arg == flag).unwrap(); input.drain(at..at + 2); assert!(parse(&input).is_err());
    }
    for extra in [vec!["--clear-labels"], vec!["--label", "é"], vec!["--force", "true"], vec!["--expected-head", "ignored"], vec!["--trusted-local"]] {
        let mut input = args(true); input.extend(extra.into_iter().map(str::to_owned)); assert!(parse(&input).is_err());
    }
    let mut clear = args(true); clear.truncate(12);
    assert!(parse(&clear).is_err());
    clear.push("--clear-labels".into());
    let Operation::Set { command, .. } = parse(&clear).unwrap().operation else { panic!("clear") };
    assert!(command.labels.is_empty());
    let mut untrusted = args(true); untrusted.retain(|arg| arg != "--trusted-local"); assert!(parse(&untrusted).is_err());
    for (flag, value) in [("--principal", "33".repeat(16)), ("--label", "bug".into()), ("--expected-version", "0".into())] {
        let mut input = args(false); input.extend([flag.into(), value]); assert!(parse(&input).is_err());
    }
}

#[test]
fn label_bounds_are_utf8_bytes_and_set_membership_is_not_normalized() {
    let mut input = args(true); replace(&mut input, "--label", &"é".repeat(32)); assert!(parse(&input).is_ok());
    replace(&mut input, "--label", &"é".repeat(33)); assert!(parse(&input).is_err());
    let mut maximum = args(true); maximum.truncate(12);
    for n in (0..32).rev() { maximum.extend(["--label".into(), format!("label-{n:02}")]); }
    assert!(parse(&maximum).is_ok());
    maximum.extend(["--label".into(), "extra".into()]); assert!(parse(&maximum).is_err());
    let mut distinct = args(true); distinct.extend(["--label".into(), "bug".into(), "--label".into(), "BUG".into()]); assert!(parse(&distinct).is_ok());
}

#[test]
fn unset_cleared_missing_and_corrupt_label_states_are_distinct() {
    let options = parse(&args(false)).unwrap();
    let mut row = view();
    let unset = read_report(&options, "incarnation", head(), Some(&row)).unwrap();
    assert!(unset.contains("\"found\":true")); assert!(unset.contains("\"labels_version\":\"0\"")); assert!(unset.contains("\"labels_actor\":null"));
    row.labels_version = Some(AggregateVersion::FIRST); row.labels_actor = Some(PrincipalId::from_bytes([4; 16]));
    let cleared = read_report(&options, "incarnation", head(), Some(&row)).unwrap();
    assert!(cleared.contains("\"labels_version\":\"1\"")); assert!(cleared.contains("\"labels\":[]"));
    row.labels = vec!["<script>literal</script>".into(), "é".into()]; assert!(read_report(&options, "incarnation", head(), Some(&row)).is_ok());
    row.labels_actor = None; assert!(read_report(&options, "incarnation", head(), Some(&row)).is_err());
    let absent = read_report(&options, "incarnation", head(), None).unwrap();
    assert!(absent.contains("\"found\":false")); assert!(absent.contains("\"labels_version\":null")); assert!(!absent.contains("Literal title"));
}

#[test]
fn terminal_receipts_preserve_original_facts_through_cleanup_or_output_failure() {
    let options = parse(&args(true)).unwrap();
    let tx = TxId::from_digest(algorithm(), CANONICAL_CODEC_VERSION, digest(1));
    for committed in [false, true] {
        let terminal = TerminalOutcome { decision_sequence: DecisionSequence::FIRST, outcome: if committed {
            DecisionOutcome::Committed { repository_commit_id: RepositoryCommitId::from_digest(algorithm(), CANONICAL_CODEC_VERSION, digest(2)) }
        } else { DecisionOutcome::Refused { code: RefusalCode::EvidenceStale, refusal_record_id: RefusalRecordId::from_digest(algorithm(), CANONICAL_CODEC_VERSION, digest(3)) } } };
        let report = mutation_report(&options, "incarnation", tx, &terminal, Some("shutdown failed")).unwrap();
        assert!(report.contains("\"outcome_unknown\":false")); assert!(report.contains("\"node_closed\":false")); assert!(report.contains("\"pull_request_version_changed\":false"));
        assert!(!report.contains("original-private-key")); assert!(report.contains(" bug "));
        assert!(report.contains(if committed { "\"labels_version\":\"1\"" } else { "\"labels_version\":null" }));
        let error = write_terminal_receipt(&mut Broken, &report, tx, &terminal).unwrap_err();
        assert!(error.contains(&tx.to_string())); assert!(error.contains(if committed { "committed" } else { "refused" }));
    }
}
struct Broken;
impl Write for Broken {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> { Err(std::io::ErrorKind::BrokenPipe.into()) }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

#[test]
fn additions_have_an_explicit_nonempty_profile_without_replacement_controls() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut input = addition_args();
        input.extend(["--object-format".into(), format.as_str().into()]);
        let options = parse(&input).unwrap();
        assert_eq!(options.format, format);
        let Operation::Add { intent, key, .. } = options.operation else { panic!("addition") };
        assert_eq!(intent.number.get(), 7);
        assert_eq!(intent.labels, [" bug ", "é"]);
        assert_eq!(key, b"original-private-key");
    }
    for extra in [vec!["--expected-version", "0"], vec!["--expected-head", "latest"], vec!["--clear-labels"], vec!["--force"], vec!["--label", "é"]] {
        let mut input = addition_args();
        input.extend(extra.into_iter().map(str::to_owned));
        assert!(parse(&input).is_err());
    }
    let mut empty = addition_args();
    empty.truncate(10);
    assert!(parse(&empty).is_err());
    let mut boundary = empty;
    for n in (0..32).rev() { boundary.extend(["--label".into(), format!("label-{n:02}")]); }
    assert!(parse(&boundary).is_ok());
    boundary.extend(["--label".into(), "extra".into()]);
    assert!(parse(&boundary).is_err());
    for value in ["", " ", "a\nb", "a\0b"] {
        let mut input = addition_args(); replace(&mut input, "--label", value);
        assert!(parse(&input).is_err());
    }
}

#[test]
fn addition_receipts_keep_original_additions_without_inventing_a_current_version() {
    let options = parse(&addition_args()).unwrap();
    let tx = TxId::from_digest(algorithm(), CANONICAL_CODEC_VERSION, digest(1));
    for committed in [false, true] {
        let terminal = TerminalOutcome { decision_sequence: DecisionSequence::FIRST, outcome: if committed {
            DecisionOutcome::Committed { repository_commit_id: RepositoryCommitId::from_digest(algorithm(), CANONICAL_CODEC_VERSION, digest(2)) }
        } else { DecisionOutcome::Refused { code: RefusalCode::ResourceBudgetExceeded, refusal_record_id: RefusalRecordId::from_digest(algorithm(), CANONICAL_CODEC_VERSION, digest(3)) } } };
        let report = mutation_report(&options, "incarnation", tx, &terminal, None).unwrap();
        for field in ["\"action\":\"add-labels\"", "\"command_profile\":\"pull-request.add-labels.v1\"", "\"expected_version\":null", "\"labels_version\":null", "\"labels\":[\" bug \",\"é\"]", "\"historical_outcome\":true", "\"pull_request_version_changed\":false"] {
            assert!(report.contains(field), "{report}");
        }
        assert!(!report.contains("original-private-key"));
        let error = write_terminal_receipt(&mut Broken, &report, tx, &terminal).unwrap_err();
        assert!(error.contains(&tx.to_string()));
        assert!(error.contains(if committed { "committed" } else { "refused" }));
    }
}
