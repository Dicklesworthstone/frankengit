use super::*;
use fgit_types::{CANONICAL_CODEC_VERSION, DecisionSequence, RefusalRecordId, RepositoryCommitId};
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};

fn arguments(width: usize) -> Vec<String> {
    ["unopened".into(), "11".repeat(16), "22".repeat(16), "refs/heads/topic".into(), "candidate.bundle".into(),
        "--trusted-local".into(), "--allow-rewrite".into(), "--principal".into(), "33".repeat(16),
        "--idempotency-key".into(), "private-retry-key".into(), "--expected-source".into(), "a".repeat(width),
        "--expected-onto".into(), "b".repeat(width), "--expected-commit".into(), "c".repeat(width)].into()
}
fn terminal(refused: bool) -> (TxId, TerminalOutcome) {
    let algorithm = DigestAlgorithmId::try_new(2).unwrap();
    let digest = DigestBytes::try_new(&[0x42; 32]).unwrap();
    let tx = TxId::from_digest(algorithm, CANONICAL_CODEC_VERSION, digest);
    let outcome = if refused {
        DecisionOutcome::Refused { code: fgit_types::RefusalCode::ExpectedOldRefMismatch,
            refusal_record_id: RefusalRecordId::from_digest(algorithm, CANONICAL_CODEC_VERSION, digest) }
    } else {
        DecisionOutcome::Committed { repository_commit_id: RepositoryCommitId::from_digest(algorithm, CANONICAL_CODEC_VERSION, digest) }
    };
    (tx, TerminalOutcome { decision_sequence: DecisionSequence::try_new(2).unwrap(), outcome })
}

#[test]
fn parse_requires_review_coordinates_explicit_rewrite_and_one_key() {
    for width in [40, 64] {
        let args = arguments(width);
        assert!(options::parse(&args).is_ok());
        for switch in ["--trusted-local", "--allow-rewrite"] {
            let changed: Vec<_> = args.iter().filter(|arg| arg.as_str() != switch).cloned().collect();
            assert!(options::parse(&changed).is_err());
        }
        for name in ["--principal", "--expected-source", "--expected-onto", "--expected-commit", "--idempotency-key"] {
            let at = args.iter().position(|arg| arg == name).unwrap();
            let mut changed = args.clone(); changed.drain(at..at+2);
            assert!(options::parse(&changed).is_err(), "missing {name}");
            let mut duplicate = args.clone(); duplicate.extend([name.into(), args[at+1].clone()]);
            assert!(options::parse(&duplicate).is_err(), "duplicate {name}");
        }
        let mut zero = args.clone(); *zero.last_mut().unwrap() = "0".repeat(width);
        assert!(options::parse(&zero).is_err());
        let mut mixed = args.clone(); *mixed.last_mut().unwrap() = "c".repeat(if width == 40 {64} else {40});
        assert!(options::parse(&mixed).is_err());
        for extra in ["--force", "--key-stdin", "--allow-rewrite"] {
            let mut changed = args.clone(); changed.push(extra.into());
            assert!(options::parse(&changed).is_err());
        }
    }
}

#[test]
fn refs_preserve_bytes_and_key_intake_is_exact_and_bounded() {
    let mut args = arguments(40);
    args[3] = hex(b"refs/heads/\xff"); args.push("--source-ref-hex".into());
    assert_eq!(options::parse(&args).unwrap().reference.as_bytes(), b"refs/heads/\xff");
    args[3] = hex(b"refs/tags/not-a-branch"); assert!(options::parse(&args).is_err());
    assert_eq!(read_key(&mut &b"a\0b\n"[..]).unwrap(), b"a\0b\n");
    assert_eq!(read_key(&mut &vec![7;256][..]).unwrap().len(), 256);
    assert!(read_key(&mut &vec![7;257][..]).is_err());
    assert!(read_key(&mut &b""[..]).is_err());
    let mut args = arguments(40); drop(args.splice(9..11, ["--key-stdin".into()]));
    assert!(matches!(options::parse(&args).unwrap().key, KeyInput::Stdin));
}

#[test]
fn receipts_preserve_committed_and_refused_outcomes_after_cleanup_failure() {
    for refused in [false, true] {
        let options = options::parse(&arguments(40)).unwrap();
        let (tx, terminal) = terminal(refused);
        let mut output = Vec::new();
        assert_eq!(finish(&mut output, &options, tx, &terminal, None).unwrap(), if refused {3} else {0});
        let good = String::from_utf8(output).unwrap();
        assert!(good.contains("\"type\":\"rebase_publication\""));
        assert!(good.contains("\"atomic\":true"));
        assert!(good.contains(&format!("\"command_committed\":{}", !refused)));
        assert!(good.contains("\"delivery_acknowledged\":null"));
        assert!(!good.contains("private-retry-key"));
        assert!(good.contains(&format!("\"expected_source\":\"{}\"", "a".repeat(40))));
        let mut output = Vec::new();
        let error = finish(&mut output, &options, tx, &terminal, Some("close\nfailed")).unwrap_err();
        assert!(error.contains(&describe(tx, &terminal)));
        let partial = String::from_utf8(output).unwrap();
        assert!(partial.contains("\"node_closed\":false"));
        assert!(partial.contains("close\\u000afailed"));
        assert!(partial.contains(&format!("\"command_committed\":{}", !refused)));
    }
}

#[test]
fn write_or_flush_failure_does_not_erase_a_known_terminal_decision() {
    struct Broken(bool);
    impl Write for Broken {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.0 { Err(std::io::Error::other("write failed")) } else { Ok(bytes.len()) }
        }
        fn flush(&mut self) -> std::io::Result<()> { Err(std::io::Error::other("flush failed")) }
    }
    for refused in [false, true] {
        let options = options::parse(&arguments(64)).unwrap();
        let (tx, terminal) = terminal(refused);
        for fail_write in [false, true] {
            let error = finish(&mut Broken(fail_write), &options, tx, &terminal, None).unwrap_err();
            assert!(error.contains(&describe(tx, &terminal)));
            assert!(!error.contains("private-retry-key"));
        }
    }
}
