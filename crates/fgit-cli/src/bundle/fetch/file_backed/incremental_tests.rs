//! Profile selection must never reinterpret a retry key or mapping operand.

use super::*;
use fgit_types::GitHashAlgorithm;

const MIB: usize = 1024 * 1024;

fn args(extra: &[&str]) -> Vec<String> {
    let mut input = vec![
        "node".into(),
        "01".repeat(16),
        "02".repeat(16),
        "changes.bundle".into(),
        "--file-backed".into(),
        "--trusted-local".into(),
        "--principal".into(),
        "03".repeat(16),
        "--idempotency-key".into(),
        "exact-key".into(),
        "--map".into(),
        "refs/heads/main".into(),
        "refs/remotes/upstream/main".into(),
        "absent".into(),
    ];
    input.extend(extra.iter().map(|arg| (*arg).into()));
    input
}

#[test]
fn incremental_original_allowance_is_explicit_and_independent() {
    let full = parse(&args(&[])).unwrap();
    assert_eq!(full.profile, SourceProfile::Full);
    let default = parse(&args(&["--incremental"])).unwrap();
    assert_eq!(default.profile.original_byte_limit(), 128 * MIB);
    let enlarged = parse(&args(&["--max-original-mib", "16384", "--incremental"])).unwrap();
    assert_eq!(enlarged.profile.original_byte_limit(), 16_384 * MIB);
    assert_eq!(
        enlarged.query.limits.pack.max_total_expanded_bytes,
        full.query.limits.pack.max_total_expanded_bytes
    );
    assert_eq!(
        enlarged.query.limits.envelope.max_bundle_bytes,
        full.query.limits.envelope.max_bundle_bytes
    );
    assert_eq!(enlarged.query.limits.pack.max_object_bytes, 32 * MIB);
    assert_eq!(enlarged.query.limits.max_streamed_blob_bytes, 32 * MIB);
    assert!(parse(&args(&["--max-original-mib", "128"])).is_err());
}

#[test]
fn incremental_selection_keeps_exact_keys_and_byte_ref_mappings() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut input = args(&["--incremental", "--object-format", format.as_str()]);
        let old = "1a".repeat(format.digest_len());
        input.extend([
            "--map-hex".into(),
            super::super::hex(b"refs/heads/main"),
            super::super::hex(b"refs/remotes/upstream/\xff"),
            old.clone(),
        ]);
        let key_at = input
            .iter()
            .position(|arg| arg == "--idempotency-key")
            .unwrap();
        input[key_at + 1] = "--incremental".into();
        let parsed = parse(&input).unwrap();
        assert_eq!(parsed.common.mappings.len(), 2);
        let mapping = parsed.common.mappings.last().unwrap();
        assert_eq!(
            mapping.destination.as_bytes(),
            b"refs/remotes/upstream/\xff"
        );
        assert_eq!(mapping.expected_old.unwrap().to_string(), old);
        assert_eq!(
            super::super::key_bytes(&parsed.common.key, &mut b"unused".as_slice()).unwrap(),
            b"--incremental"
        );
        input.splice(key_at..key_at + 2, ["--key-stdin".into()]);
        let parsed = parse(&input).unwrap();
        assert_eq!(
            super::super::key_bytes(&parsed.common.key, &mut b"exact\nkey\n".as_slice()).unwrap(),
            b"exact\nkey\n"
        );
    }
}

#[test]
fn option_order_and_opaque_operands_cannot_change_the_profile() {
    let mut incremental_first = args(&["--incremental"]);
    incremental_first.remove(4);
    incremental_first.push("--file-backed".into());
    assert!(requested(&incremental_first));
    assert!(matches!(
        parse(&incremental_first).unwrap().profile,
        SourceProfile::Incremental { .. }
    ));

    for value in ["--incremental", "--file-backed", "--max-original-mib"] {
        let mut input = args(&[]);
        input[9] = value.into();
        assert_eq!(parse(&input).unwrap().profile, SourceProfile::Full);
        input.remove(4);
        assert!(!requested(&input), "opaque key selected a profile: {value}");
        assert!(super::super::parse(&input).is_ok());
    }
    for mapping_operand in 11..=13 {
        let mut input = args(&["--incremental"]);
        input[mapping_operand] = "--file-backed".into();
        input.remove(4);
        assert!(!requested(&input));
    }
    let mut value = args(&["--max-original-mib", "--file-backed", "--incremental"]);
    value.remove(4);
    assert!(!requested(&value));
}

#[test]
fn incremental_ambiguities_and_unbounded_original_reads_refuse_before_io() {
    for extra in [
        vec!["--incremental", "--incremental"],
        vec!["--incremental", "--max-original-mib", "0"],
        vec!["--incremental", "--max-original-mib", "01"],
        vec!["--incremental", "--max-original-mib", "16385"],
        vec![
            "--incremental",
            "--max-original-mib",
            "18446744073709551615",
        ],
        vec!["--incremental", "--max-original-mib"],
        vec![
            "--incremental",
            "--max-original-mib",
            "1",
            "--max-original-mib",
            "1",
        ],
        vec!["--incremental", "--force"],
        vec!["--incremental", "--prune"],
    ] {
        assert!(parse(&args(&extra)).is_err(), "accepted {extra:?}");
    }
    let mut missing_file = args(&["--incremental"]);
    missing_file.remove(4);
    assert!(parse(&missing_file).is_err());
    assert!(super::super::parse(&missing_file).is_err());
}

#[test]
fn incremental_fanout_preserves_full_mapping_and_resource_capacities() {
    let mut input = args(&[
        "--incremental",
        "--max-original-mib",
        "512",
        "--max-input-mib",
        "512",
        "--max-expanded-mib",
        "1024",
        "--max-object-mib",
        "1",
        "--max-blob-mib",
        "40",
        "--max-objects",
        "100000",
        "--max-refs",
        "1",
        "--max-edges",
        "1000000",
        "--timeout-secs",
        "600",
    ]);
    for index in 1..4096 {
        input.extend([
            "--map".into(),
            "refs/heads/main".into(),
            format!("refs/remotes/upstream/copy-{index}"),
            "absent".into(),
        ]);
    }
    let parsed = parse(&input).unwrap();
    assert_eq!(parsed.common.mappings.len(), 4096);
    assert_eq!(parsed.profile.original_byte_limit(), 512 * MIB);
    assert_eq!(parsed.query.limits.envelope.max_references, 1);
    assert_eq!(
        parsed.query.limits.pack.max_total_expanded_bytes,
        1024 * MIB
    );
    input.extend([
        "--map".into(),
        "refs/heads/main".into(),
        "refs/remotes/upstream/overflow".into(),
        "absent".into(),
    ]);
    assert!(parse(&input).is_err());
}

#[test]
fn incremental_help_is_available_before_any_credentials_or_filesystem_work() {
    for flags in [
        ["--help", "--incremental", "--file-backed"],
        ["--help", "--file-backed", "--incremental"],
        ["--incremental", "--help", "--file-backed"],
        ["--incremental", "--file-backed", "--help"],
        ["--file-backed", "--help", "--incremental"],
        ["--file-backed", "--incremental", "--help"],
    ] {
        let input = flags.map(String::from);
        assert!(help_requested(&input));
        let mut output = Vec::new();
        assert_eq!(run_with_output(&input, &mut output).unwrap(), 0);
        let help = String::from_utf8(output).unwrap();
        assert!(help.contains("--max-original-mib"));
        assert!(help.contains("git_bundle_fetch"));
    }
    for flags in [
        vec!["--help", "--incremental"],
        vec!["--file-backed", "--help", "--file-backed"],
        vec!["--file-backed", "--help", "--incremental", "--incremental"],
    ] {
        assert!(!help_requested(
            &flags.into_iter().map(String::from).collect::<Vec<_>>()
        ));
    }
}
