//! Presentation/parser regressions. Real node execution has its own tests and
//! scripts/e2e/pull_request_smoke.py; these fixtures do not simulate authority.

use super::*;
use super::options::{ReadOptions, head_token, parse, parse_head};
use super::output::{Row, read_receipt};
use fgit_forge::aggregate::{AggregateId, AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_forge::event::{ForgeEvent, ForgeEventPayload, NativeMerge};
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::{CANONICAL_CODEC_VERSION, DecisionSequence, GitHashAlgorithm,
    RepositoryAuthorityHeadId, RepositoryCommitId, RefusalCode, RefusalRecordId};
use std::sync::atomic::{AtomicU64, Ordering};

fn args(width: usize) -> Vec<String> {
    vec!["open".into(), "node".into(), "11".repeat(16), "22".repeat(16), "7".into(),
        "--trusted-local".into(), "--principal".into(), "33".repeat(16),
        "--idempotency-key".into(), "private-retry-key".into(),
        "--source-ref".into(), "refs/heads/topic".into(), "--expected-source".into(), "a".repeat(width),
        "--target-ref".into(), "refs/heads/main".into(), "--expected-target".into(), "b".repeat(width),
        "--expected-version".into(), "0".into(), "--title".into(), "A reviewed change".into(),
        "--body".into(), "Untrusted <script>\nUnicode: é\n".into()]
}
fn replace(arguments: &mut [String], flag: &str, value: &str) {
    let at = arguments.iter().position(|arg| arg == flag).unwrap();
    arguments[at + 1] = value.to_owned();
}
fn read_args(action: &str) -> Vec<String> {
    let mut args = vec![action.to_owned(), "node".into(), "11".repeat(16), "22".repeat(16)];
    if action == "show" { args.push("7".into()); }
    args.push("--trusted-local".into()); args
}
fn mutation(options: &Options) -> &Mutation {
    match &options.operation { Operation::Mutate(value) => value, _ => panic!("expected mutation") }
}
fn read_options(options: &Options) -> &ReadOptions {
    match &options.operation { Operation::Read(value) => value, _ => panic!("expected read") }
}
fn algorithm() -> DigestAlgorithmId { DigestAlgorithmId::try_new(1).unwrap() }
fn digest(seed: u8) -> DigestBytes { DigestBytes::try_new(&[seed; 32]).unwrap() }
fn head(seed: u8) -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(algorithm(), CANONICAL_CODEC_VERSION, digest(seed))
}
fn terminal(committed: bool) -> (TxId, TerminalOutcome) {
    let tx = TxId::from_digest(algorithm(), CANONICAL_CODEC_VERSION, digest(1));
    let outcome = if committed { DecisionOutcome::Committed {
        repository_commit_id: RepositoryCommitId::from_digest(algorithm(), CANONICAL_CODEC_VERSION, digest(2)),
    } } else { DecisionOutcome::Refused { code: RefusalCode::EvidenceStale,
        refusal_record_id: RefusalRecordId::from_digest(algorithm(), CANONICAL_CODEC_VERSION, digest(3)),
    } };
    (tx, TerminalOutcome { decision_sequence: DecisionSequence::FIRST, outcome })
}
fn row<'a>(event: &'a ForgeEvent, mutation: &'a Mutation) -> Row<'a> {
    let AggregateId::PullRequest(number) = event.aggregate else { panic!("PR fixture") };
    Row { number, event, data: Some(&mutation.command.data),
        opened_by: Some(mutation.principal), last_metadata_actor: Some(mutation.principal) }
}

#[test]
fn complete_mutations_preserve_bytes_versions_and_both_hash_domains() {
    for (width, format) in [(40, GitHashAlgorithm::Sha1), (64, GitHashAlgorithm::Sha256)] {
        let options = parse(&args(width)).unwrap(); let value = mutation(&options);
        assert_eq!(options.format, format);
        assert_eq!(value.command.data.source_tip.to_string(), "a".repeat(width));
        assert_eq!(value.command.data.body, "Untrusted <script>\nUnicode: é\n");
        assert_eq!(value.command.expected_version, ExpectedVersion::NewStream);
        assert_eq!(value.key, b"private-retry-key");
        for action in ["update", "close"] {
            let mut input = args(width); input[0] = action.into();
            replace(&mut input, "--expected-version", "17");
            let parsed = parse(&input).unwrap();
            assert_eq!(mutation(&parsed).command.expected_version,
                ExpectedVersion::Exactly(AggregateVersion::try_new(17).unwrap()));
        }
    }
}

#[test]
fn every_semantic_mutation_field_and_local_trust_are_required() {
    for flag in ["--principal", "--idempotency-key", "--source-ref", "--expected-source",
        "--target-ref", "--expected-target", "--expected-version", "--title", "--body"]
    {
        let mut missing = args(40);
        let at = missing.iter().position(|arg| arg == flag).unwrap(); missing.drain(at..at + 2);
        assert!(parse(&missing).is_err(), "missing {flag}");
    }
    for action in ["open", "update", "close", "list", "show"] {
        let mut missing = if matches!(action, "list" | "show") { read_args(action) } else {
            let mut value = args(40); value[0] = action.into(); value
        };
        missing.retain(|value| value != "--trusted-local"); assert!(parse(&missing).is_err());
    }
}

#[test]
fn unknown_duplicates_irrelevant_options_and_conflicting_encodings_refuse() {
    let original = args(40);
    for at in (6..original.len()).step_by(2) {
        let mut duplicate = original.clone(); duplicate.extend_from_slice(&original[at..at + 2]);
        assert!(parse(&duplicate).is_err(), "duplicate {}", original[at]);
    }
    for extra in [vec!["--trusted-local"], vec!["--force", "true"], vec!["--limit", "2"],
        vec!["--body-file", "ignored"], vec!["--source-ref-hex", "61"]]
    {
        let mut input = args(40); input.extend(extra.into_iter().map(str::to_owned)); assert!(parse(&input).is_err());
    }
    for action in ["list", "show"] {
        let mut input = read_args(action); input.extend(["--principal".into(), "33".repeat(16)]);
        assert!(parse(&input).is_err());
    }
    let mut show = read_args("show"); show.extend(["--limit", "1"].map(str::to_owned)); assert!(parse(&show).is_err());
    let mut binary = args(40);
    let at = binary.iter().position(|arg| arg == "--source-ref").unwrap();
    binary[at] = "--source-ref-hex".into(); binary[at + 1] = options::hex(b"refs/heads/topic");
    assert_eq!(mutation(&parse(&binary).unwrap()).command.data.source_ref.as_bytes(), b"refs/heads/topic");
}

#[test]
fn numeric_shape_metadata_limits_and_object_formats_fail_before_io() {
    for (flag, value) in [("--expected-version", "1"), ("--expected-version", "01"),
        ("--expected-version", "-1"), ("--expected-source", "0"),
        ("--title", " \t"), ("--title", "escape\u{1b}"), ("--body", "nul\0")]
    {
        let mut input = args(40); replace(&mut input, flag, value); assert!(parse(&input).is_err());
    }
    let mut exhausted = args(40); exhausted[0] = "update".into();
    replace(&mut exhausted, "--expected-version", &u64::MAX.to_string()); assert!(parse(&exhausted).is_err());
    let mut mixed = args(40); replace(&mut mixed, "--expected-target", &"b".repeat(64)); assert!(parse(&mixed).is_err());
    let mut mismatched = args(64); mismatched.extend(["--object-format", "sha1"].map(str::to_owned)); assert!(parse(&mismatched).is_err());
    let mut body = args(40); replace(&mut body, "--body", &"x".repeat(MAX_BODY_BYTES)); assert!(parse(&body).is_ok());
    replace(&mut body, "--body", &"x".repeat(MAX_BODY_BYTES + 1)); assert!(parse(&body).is_err());
    let mut title = args(40); replace(&mut title, "--title", &"é".repeat(129)); assert!(parse(&title).is_err());
    let mut nonexistent = args(40); let at = nonexistent.iter().position(|arg| arg == "--body").unwrap();
    nonexistent[at] = "--body-file".into(); nonexistent[at + 1] = "/does-not-exist/body".into();
    assert!(parse(&nonexistent).is_ok(), "syntax parsing must not perform file I/O");
}

#[test]
fn head_tokens_roundtrip_and_list_continuations_cannot_mix_snapshots() {
    for seed in 1..4 { assert_eq!(parse_head(&head_token(head(seed))).unwrap(), head(seed)); }
    for invalid in ["", "abcd", "alg:01:ab", "alg:1:", "alg:1:zz", "alg:1:AA", "alg:1:0"] {
        assert!(parse_head(invalid).is_err(), "{invalid}");
    }
    let mut input = read_args("list"); input.extend(["--after", "2"].map(str::to_owned));
    assert!(parse(&input).is_err());
    input.extend(["--expected-head".into(), head_token(head(1)), "--limit".into(), "2".into()]);
    let parsed = parse(&input).unwrap(); let read = read_options(&parsed);
    assert_eq!(read.after(), 2); assert_eq!(read.limit(), 2); assert_eq!(read.expected_head, Some(head(1)));
    assert!(read_receipt(&parsed, read, head(2), None, &[]).is_err());
    assert!(read_receipt(&parsed, read, head(1), None, &[]).is_ok());
}

#[test]
fn exact_show_does_not_disclose_a_different_next_number() {
    let original = parse(&args(40)).unwrap(); let value = mutation(&original);
    let mut event = value.command.proposed_event(value.principal, original.format).unwrap();
    event.aggregate = AggregateId::PullRequest(PullRequestNumber::try_new(8).unwrap());
    let options = parse(&read_args("show")).unwrap();
    let (text, exit) = read_receipt(&options, read_options(&options), head(1), Some(8), &[row(&event, value)]).unwrap();
    assert_eq!(exit, 4); assert!(text.contains("\"found\":false,\"pull_request\":null"));
    assert!(!text.contains("A reviewed change")); assert!(!text.contains("next_after"));
    event.aggregate = AggregateId::PullRequest(value.command.number);
    let (text, exit) = read_receipt(&options, read_options(&options), head(1), None, &[row(&event, value)]).unwrap();
    assert_eq!(exit, 0); assert!(text.contains("\"found\":true")); assert!(text.contains("A reviewed change"));
}

#[test]
fn page_order_cursor_and_row_binding_are_checked_before_disclosure() {
    let original = parse(&args(40)).unwrap(); let value = mutation(&original);
    let event = value.command.proposed_event(value.principal, original.format).unwrap();
    let options = parse(&read_args("list")).unwrap(); let read = read_options(&options);
    assert!(read_receipt(&options, read, head(1), None, &[row(&event, value), row(&event, value)]).is_err());
    assert!(read_receipt(&options, read, head(1), Some(999), &[row(&event, value)]).is_err());
    let mut invalid = row(&event, value); invalid.number = PullRequestNumber::FIRST;
    assert!(read_receipt(&options, read, head(1), None, &[invalid]).is_err());
    let (text, _) = read_receipt(&options, read, head(1), Some(7), &[row(&event, value)]).unwrap();
    assert!(text.contains("\"count\":1,\"has_more\":true,\"next_after\":7"));
}

#[test]
fn merge_only_receipts_do_not_invent_an_opener_or_metadata() {
    let original = parse(&args(40)).unwrap(); let value = mutation(&original); let data = &value.command.data;
    let event = ForgeEvent { aggregate: AggregateId::PullRequest(value.command.number), version: AggregateVersion::FIRST,
        payload: ForgeEventPayload::MergeCommittedNative(NativeMerge {
            source_ref: data.source_ref.clone(), source_tip: data.source_tip, base_tip: data.target_tip,
            target_ref: data.target_ref.clone(), target_tip_before: data.target_tip,
            merge_commit: crate::publication_support::parse_oid(&"c".repeat(40)).unwrap(),
        }) };
    let row = Row { number: value.command.number, event: &event, data: None, opened_by: None, last_metadata_actor: None };
    let options = parse(&read_args("list")).unwrap();
    let (text, _) = read_receipt(&options, read_options(&options), head(1), None, &[row]).unwrap();
    assert!(text.contains("\"kind\":\"merge_receipt\",\"state\":\"merged\""));
    assert!(text.contains("\"data\":null,\"opened_by\":null,\"last_metadata_actor\":null"));
    assert!(text.contains(&"c".repeat(40)));
}

#[test]
fn receipt_text_is_control_safe_and_private_key_is_not_echoed() {
    let mut input = args(40); replace(&mut input, "--body", "quote\" slash\\ \u{1b}\u{9b}\n\t é\u{2028}");
    let options = parse(&input).unwrap(); let (tx, terminal) = terminal(true);
    let text = output::mutation_receipt(&options, mutation(&options), tx, &terminal, None);
    assert!(!text.chars().any(char::is_control)); assert!(!text.contains('\u{2028}'));
    for escaped in ["\\u001b", "\\u009b", "\\u000a", "\\u0009", "\\u2028"] { assert!(text.contains(escaped)); }
    assert!(!text.contains("private-retry-key")); assert!(text.contains('é'));
    assert!(text.contains("\"command_committed\":true")); assert!(text.contains("\"refs_changed\":false"));
}

#[test]
fn write_flush_and_cleanup_failures_keep_the_known_terminal_decision() {
    struct Failing { fail_write: bool }
    impl Write for Failing {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.fail_write { Err(std::io::ErrorKind::BrokenPipe.into()) } else { Ok(bytes.len()) }
        }
        fn flush(&mut self) -> std::io::Result<()> { Err(std::io::ErrorKind::BrokenPipe.into()) }
    }
    let options = parse(&args(40)).unwrap();
    for committed in [true, false] {
        let (tx, terminal) = terminal(committed);
        for fail_write in [true, false] {
            let error = finish_mutation(&mut Failing { fail_write }, &options, mutation(&options), tx, &terminal, Some("cleanup-marker")).unwrap_err();
            assert!(error.contains(&tx.to_string())); assert!(error.contains("cleanup-marker"));
            assert!(error.contains(if committed { "is committed" } else { "canonical refusal" }));
        }
        let mut output = Vec::new();
        assert_eq!(finish_mutation(&mut output, &options, mutation(&options), tx, &terminal, None).unwrap(), if committed { 0 } else { 3 });
        assert!(String::from_utf8(output).unwrap().contains("\"node_closed\":true"));
    }
    assert!(write_read_report(&mut Failing { fail_write: false }, "{}").is_err());
}

#[test]
fn body_files_allow_empty_data_but_refuse_bad_encoding_size_and_symlinks() {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!("fg-pr-body-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
    fs::create_dir(&root).unwrap(); let file = root.join("body");
    for body in [b"".as_slice(), b"<script>\n\r\t", "é\n".as_bytes()] {
        fs::write(&file, body).unwrap(); assert_eq!(read_body_file(&file).unwrap().as_bytes(), body);
    }
    for bad in [vec![0], vec![0xff], vec![b'x'; MAX_BODY_BYTES + 1]] {
        fs::write(&file, bad).unwrap(); assert!(read_body_file(&file).is_err());
    }
    assert!(read_body_file(&root).is_err());
    #[cfg(unix)] {
        fs::write(&file, b"safe").unwrap(); let link = root.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap(); assert!(read_body_file(&link).is_err());
    }
    fs::remove_dir_all(root).unwrap();
}
