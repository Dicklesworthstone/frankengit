use super::*;

fn args(extra: &[&str]) -> Vec<String> {
    [
        "transaction",
        "unopened",
        "11111111111111111111111111111111",
        "22222222222222222222222222222222",
        "--trusted-local",
        "--principal",
        "33333333333333333333333333333333",
        "--idempotency-key",
        "exact-key",
    ]
    .into_iter()
    .chain(extra.iter().copied())
    .map(str::to_owned)
    .collect()
}
fn commands(options: Options) -> Vec<RefCommand> {
    match options.operation {
        Operation::Mutate { commands, .. } => commands,
        _ => panic!("mutation expected"),
    }
}

#[test]
fn mixed_transaction_preserves_exact_old_and_new_conditions_in_both_formats() {
    for (format, width) in [("sha1", 40), ("sha256", 64)] {
        let old = "1".repeat(width);
        let new = "2".repeat(width);
        let input = args(&[
            "--create",
            "refs/heads/a",
            &new,
            "--update",
            "refs/heads/b",
            &old,
            &new,
            "--delete",
            "refs/heads/c",
            &old,
            "--object-format",
            format,
        ]);
        let parsed = commands(parse(&input).unwrap());
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].expected_old, ExpectedOld::Absent);
        assert_eq!(
            parsed[1].expected_old,
            ExpectedOld::Exactly(
                GitOid::from_hex(
                    if width == 40 {
                        GitHashAlgorithm::Sha1
                    } else {
                        GitHashAlgorithm::Sha256
                    },
                    &old
                )
                .unwrap()
            )
        );
        assert_eq!(parsed[2].proposed_new, ProposedNew::Delete);
        assert!(parsed.iter().all(|command| !command.force));
    }
}

#[test]
fn non_utf8_reference_bytes_are_preserved_and_duplicate_encodings_refuse() {
    let tip = "1".repeat(40);
    let encoded = super::super::options::hex(b"refs/heads/raw-\xff");
    let parsed = commands(parse(&args(&["--create-hex", &encoded, &tip])).unwrap());
    assert_eq!(parsed[0].name.as_bytes(), b"refs/heads/raw-\xff");
    let plain = super::super::options::hex(b"refs/heads/a");
    assert!(
        parse(&args(&[
            "--create",
            "refs/heads/a",
            &tip,
            "--delete-hex",
            &plain,
            &tip
        ]))
        .is_err()
    );
    for bad in ["aa0", "GG", "", "726566732f746167732f61"] {
        assert!(parse(&args(&["--create-hex", bad, &tip])).is_err());
    }
}

#[test]
fn transaction_has_a_hard_command_bound_with_a_permitted_boundary_twin() {
    let tip = "1".repeat(40);
    let mut input = args(&[]);
    for i in 0..64 {
        input.extend(["--create".into(), format!("refs/heads/b-{i}"), tip.clone()]);
    }
    assert_eq!(commands(parse(&input).unwrap()).len(), 64);
    input.extend(["--create".into(), "refs/heads/overflow".into(), tip]);
    assert!(parse(&input).is_err());
    assert!(parse(&args(&[])).is_err());
    let huge = "x".repeat(8193);
    assert!(parse(&args(&["--create", &huge, &"1".repeat(40)])).is_err());
}

#[test]
fn unsupported_flags_missing_operands_and_noncanonical_tips_refuse() {
    let tip = "1".repeat(40);
    for extra in [
        vec!["--force"],
        vec!["--create", "refs/heads/a"],
        vec!["--update", "refs/heads/a", &tip],
        vec!["--delete"],
        vec!["--create", "refs/heads/a", "--delete"],
        vec!["--create", "refs/tags/a", &tip],
        vec!["--create", "a", &tip],
        vec!["--object-format", "sha3", "--create", "refs/heads/a", &tip],
    ] {
        assert!(parse(&args(&extra)).is_err(), "{extra:?}");
    }
    for bad in ["0".repeat(40), "AB".repeat(20), "1".repeat(64), "*".into()] {
        assert!(parse(&args(&["--create", "refs/heads/a", &bad])).is_err());
    }
}

#[test]
fn keys_and_operator_authorization_are_explicit_without_echoing_secret_values() {
    let tip = "1".repeat(40);
    let input = args(&["--create", "refs/heads/a", &tip]);
    let mut untrusted = input.clone();
    untrusted.retain(|arg| arg != "--trusted-local");
    assert!(parse(&untrusted).is_err());
    let mut duplicate = input.clone();
    duplicate.push("--trusted-local".into());
    assert!(parse(&duplicate).is_err());
    let mut both = input.clone();
    both.push("--key-stdin".into());
    assert!(parse(&both).is_err());
    let mut stdin = input.clone();
    stdin.splice(7..9, ["--key-stdin".into()]);
    assert!(matches!(
        parse(&stdin).unwrap().operation,
        Operation::Mutate {
            key: KeyInput::Stdin,
            ..
        }
    ));
    let mut oversized = input.clone();
    oversized[8] = "S".repeat(257);
    let error = parse(&oversized).err().unwrap();
    assert!(!error.contains(&oversized[8]));
    assert!(parse(&[]).is_err());
}
