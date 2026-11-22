use super::*;
use fgit_identity::agent::{
    ISSUES_READ, ISSUES_WRITE, MILESTONES_READ, MILESTONES_WRITE, PULLS_DIFF_READ,
    PULLS_FEEDBACK_READ, PULLS_READ, PULLS_WRITE, SOURCE_CANDIDATES, SOURCE_HISTORY_READ,
    SOURCE_PUBLISH, SOURCE_READ, SOURCE_VERIFIED_READ, SponsorKind,
};
use std::path::PathBuf;

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}

#[test]
fn source_publication_issuance_requires_explicit_native_ref_and_path_ceilings() {
    let mut input = issue();
    replace(&mut input, "--operations", "source-publish");
    assert!(options::parse(&input).is_err());
    input.extend(strings(&[
        "--source-ref-scope",
        "exact:726566732f68656164732f6167656e74",
    ]));
    assert!(options::parse(&input).is_err());
    input.extend(strings(&[
        "--source-path-hex",
        "737263",
        "--source-path-hex",
        "646174612fff",
    ]));
    let Options::Repository(parsed) = options::parse(&input).unwrap() else {
        panic!()
    };
    let Operation::Issue {
        grant,
        source_scope: Some(scope),
        ..
    } = parsed.operation
    else {
        panic!()
    };
    assert_eq!(grant.operations, SOURCE_PUBLISH);
    assert!(!grant.permits(SOURCE_READ | SOURCE_CANDIDATES | ISSUES_WRITE));
    assert_eq!(
        scope.path_prefixes(),
        &[b"data/\xff".to_vec(), b"src".to_vec()]
    );
    assert!(scope.permits_ref(&fgit_types::RefName::try_new(b"refs/heads/agent").unwrap()));
    assert!(!scope.permits_ref(&fgit_types::RefName::try_new(b"refs/heads/main").unwrap()));
    assert!(scope.permits_path(b"src/file.rs"));
    assert!(!scope.permits_path(b"src-other/file.rs"));
    for operation in ["source-read", "source-candidates", "issues-write"] {
        let mut changed = input.clone();
        replace(&mut changed, "--operations", operation);
        assert!(options::parse(&changed).is_err());
    }
    for field in [
        "all",
        "none",
        "exact:726566732f68656164732f61,exact:726566732f68656164732f61",
    ] {
        let mut changed = input.clone();
        replace(&mut changed, "--source-ref-scope", field);
        assert!(options::parse(&changed).is_err());
    }
    for path in [
        "0",
        "FF",
        "2e676974",
        "7372632f2e2e2f78",
        "7372632f",
        "7372632f00",
        "646174612fff",
    ] {
        let mut changed = input.clone();
        replace(&mut changed, "--source-path-hex", path);
        assert!(options::parse(&changed).is_err(), "path {path}");
    }
}

#[test]
fn whole_tree_source_ceiling_requires_an_explicit_empty_path_argument() {
    let mut input = issue();
    replace(&mut input, "--operations", "source-publish");
    input.extend(strings(&[
        "--source-ref-scope",
        "prefix:726566732f68656164732f6167656e742f",
        "--source-path-hex",
        "",
    ]));
    let Options::Repository(parsed) = options::parse(&input).unwrap() else {
        panic!()
    };
    let Operation::Issue {
        source_scope: Some(scope),
        ..
    } = parsed.operation
    else {
        panic!()
    };
    assert_eq!(scope.path_prefixes(), &[Vec::<u8>::new()]);
    assert!(scope.permits_path(b"README.md"));
    assert!(!scope.permits_path(b".git/config"));
    input.extend(strings(&["--source-path-hex", "737263"]));
    assert!(options::parse(&input).is_err());
}

#[test]
fn milestone_credential_scopes_require_explicit_nonduplicated_permissions() {
    for (scopes, expected) in [
        ("milestones-read", MILESTONES_READ),
        ("milestones-write", MILESTONES_WRITE),
        (
            "milestones-read,milestones-write",
            MILESTONES_READ | MILESTONES_WRITE,
        ),
        (
            "issues-read,milestones-write",
            ISSUES_READ | MILESTONES_WRITE,
        ),
        (
            "issues-write,milestones-read",
            ISSUES_WRITE | MILESTONES_READ,
        ),
    ] {
        let mut input = issue();
        replace(&mut input, "--operations", scopes);
        let Options::Repository(parsed) = options::parse(&input).unwrap() else {
            panic!("repository issuance expected")
        };
        let Operation::Issue { grant, .. } = parsed.operation else {
            panic!("issuance expected")
        };
        assert_eq!(grant.operations, expected);
        for scope in [ISSUES_READ, ISSUES_WRITE, MILESTONES_READ, MILESTONES_WRITE] {
            assert_eq!(grant.permits(scope), expected & scope != 0);
        }
        assert!(!grant.permits(SOURCE_READ));
        assert!(!grant.permits(PULLS_WRITE));
    }
    for scopes in [
        "milestones-read,milestones-read",
        "milestones-write,milestones-write",
        "milestones",
        "milestone-read",
        "milestones-write,receive",
        "milestones-read,",
    ] {
        let mut input = issue();
        replace(&mut input, "--operations", scopes);
        assert!(options::parse(&input).is_err(), "{scopes}");
    }
}

#[test]
fn candidate_scope_is_explicit_and_does_not_imply_source_or_publication() {
    for (scopes, expected) in [
        ("source-candidates", SOURCE_CANDIDATES),
        (
            "source-read,source-candidates",
            SOURCE_READ | SOURCE_CANDIDATES,
        ),
        (
            "source-history-read,source-candidates",
            SOURCE_HISTORY_READ | SOURCE_CANDIDATES,
        ),
    ] {
        let mut input = issue();
        replace(&mut input, "--operations", scopes);
        let Options::Repository(parsed) = options::parse(&input).unwrap() else {
            panic!()
        };
        let Operation::Issue { grant, .. } = parsed.operation else {
            panic!()
        };
        assert_eq!(grant.operations, expected);
        assert_eq!(grant.permits(SOURCE_READ), expected & SOURCE_READ != 0);
        assert_eq!(
            grant.permits(SOURCE_HISTORY_READ),
            expected & SOURCE_HISTORY_READ != 0
        );
        assert!(!grant.permits(ISSUES_WRITE | PULLS_WRITE));
    }
    for scopes in [
        "source-candidates,source-candidates",
        "source-candidates,receive",
        "source-candidates,source-write",
    ] {
        let mut input = issue();
        replace(&mut input, "--operations", scopes);
        assert!(options::parse(&input).is_err());
    }
}

#[test]
fn history_scope_issuance_preserves_explicit_independent_permissions() {
    for (scopes, expected) in [
        ("source-history-read", SOURCE_HISTORY_READ),
        (
            "source-read,source-history-read",
            SOURCE_READ | SOURCE_HISTORY_READ,
        ),
        (
            "issues-read,source-history-read",
            ISSUES_READ | SOURCE_HISTORY_READ,
        ),
    ] {
        let mut input = issue();
        replace(&mut input, "--operations", scopes);
        let Options::Repository(parsed) = options::parse(&input).unwrap() else {
            panic!("repository issuance expected")
        };
        let Operation::Issue { grant, .. } = parsed.operation else {
            panic!("issuance expected")
        };
        assert_eq!(grant.operations, expected);
        assert_eq!(grant.permits(SOURCE_READ), expected & SOURCE_READ != 0);
        assert_eq!(grant.permits(ISSUES_READ), expected & ISSUES_READ != 0);
        assert!(!grant.permits(ISSUES_WRITE | PULLS_WRITE));
    }
    for scopes in [
        "source-history-read,source-history-read",
        "source-history-read,source-write",
        "source-history-read,read",
        "source-history-read,receive",
        "source-history-read,",
    ] {
        let mut input = issue();
        replace(&mut input, "--operations", scopes);
        assert!(options::parse(&input).is_err(), "{scopes}");
    }
}

fn issue() -> Vec<String> {
    strings(&[
        "issue",
        "store",
        "11111111111111111111111111111111",
        "22222222222222222222222222222222",
        "--trusted-local",
        "--incarnation",
        "33333333333333333333333333333333",
        "--principal",
        "44444444444444444444444444444444",
        "--agent",
        "55555555555555555555555555555555",
        "--sponsor-kind",
        "human",
        "--token-file",
        "private.token",
        "--issued-at",
        "100",
        "--expires-at",
        "200",
        "--operations",
        "issues-read,issues-write,pulls-write",
        "--idempotency-key",
        "first-agent-issuance",
    ])
}

fn replace(args: &mut [String], flag: &str, value: &str) {
    let index = args.iter().position(|arg| arg == flag).unwrap();
    args[index + 1] = value.into();
}

#[test]
fn source_read_is_explicit_and_independent_of_metadata_and_git_permissions() {
    let mut input = issue();
    replace(&mut input, "--operations", "source-read");
    let Options::Repository(parsed) = options::parse(&input).unwrap() else {
        panic!("repository issuance expected")
    };
    let Operation::Issue { grant, .. } = parsed.operation else {
        panic!("issuance expected")
    };
    assert_eq!(grant.operations, SOURCE_READ);
    assert!(!grant.permits(ISSUES_READ | ISSUES_WRITE | PULLS_WRITE));
    for operations in ["source-read,source-read", "source-write", "read", "receive"] {
        replace(&mut input, "--operations", operations);
        assert!(options::parse(&input).is_err(), "{operations}");
    }
}

#[test]
fn issuance_requires_explicit_sponsor_incarnation_lifetime_and_independent_operations() {
    let input = issue();
    let Options::Repository(parsed) = options::parse(&input).unwrap() else {
        panic!()
    };
    let Operation::Issue {
        principal, grant, ..
    } = parsed.operation
    else {
        panic!()
    };
    assert_eq!(principal, grant.sponsor);
    assert_eq!(grant.sponsor_kind, SponsorKind::Human);
    assert_eq!(grant.operations, ISSUES_READ | ISSUES_WRITE | PULLS_WRITE);
    assert_eq!(grant.incarnation, parsed.incarnation);
    assert_eq!(grant.issued_at, 100);
    assert_eq!(grant.expires_at, 200);
    for (flag, value) in [
        ("--sponsor-kind", "agent"),
        ("--sponsor-kind", ""),
        ("--agent", "44444444444444444444444444444444"),
        ("--principal", "00000000000000000000000000000000"),
        ("--incarnation", "00000000000000000000000000000000"),
        ("--issued-at", "0100"),
        ("--issued-at", "0"),
        ("--expires-at", "100"),
        ("--expires-at", "999999999"),
        ("--operations", "issues-read,issues-read"),
        ("--operations", "issues-read,"),
        ("--operations", "receive"),
        ("--operations", "reviews-write"),
        ("--operations", "merges-write"),
        ("--operations", "protection-write"),
    ] {
        let mut changed = input.clone();
        replace(&mut changed, flag, value);
        assert!(options::parse(&changed).is_err(), "{flag}");
    }
    for required in [
        "--incarnation",
        "--sponsor-kind",
        "--token-file",
        "--issued-at",
        "--expires-at",
        "--operations",
        "--idempotency-key",
    ] {
        let mut changed = input.clone();
        let index = changed.iter().position(|arg| arg == required).unwrap();
        changed.drain(index..index + 2);
        assert!(options::parse(&changed).is_err(), "{required}");
    }
    let mut no_trust = input.clone();
    no_trust.retain(|arg| arg != "--trusted-local");
    assert!(options::parse(&no_trust).is_err());
    let mut duplicate = input.clone();
    duplicate.extend(strings(&["--issued-at", "101"]));
    assert!(options::parse(&duplicate).is_err());
    let mut secret_argv = input;
    secret_argv.extend(strings(&["--token", "unaccepted-secret"]));
    let error = options::parse(&secret_argv).err().unwrap();
    assert!(!error.contains("unaccepted-secret"));
}

#[test]
fn revocation_keeps_the_original_version_and_show_does_not_accept_mutation_flags() {
    let prefix = strings(&[
        "revoke",
        "store",
        "11111111111111111111111111111111",
        "22222222222222222222222222222222",
        "--trusted-local",
        "--incarnation",
        "33333333333333333333333333333333",
        "--principal",
        "44444444444444444444444444444444",
        "--idempotency-key",
        "revoke-1",
        "--credential-id",
        &"99".repeat(32),
        "--expected-version",
        "1",
    ]);
    assert!(options::parse(&prefix).is_ok());
    for value in ["0", "2", "01", "18446744073709551616"] {
        let mut changed = prefix.clone();
        replace(&mut changed, "--expected-version", value);
        assert!(options::parse(&changed).is_err());
    }
    for value in ["00".repeat(32), "AA".repeat(32), "99".repeat(31)] {
        let mut changed = prefix.clone();
        replace(&mut changed, "--credential-id", &value);
        assert!(options::parse(&changed).is_err());
    }
    let mut show = prefix;
    show[0] = "show".into();
    assert!(options::parse(&show).is_err());
    show.truncate(7);
    assert!(options::parse(&show).is_ok());
    show.extend(strings(&["--credential-id", &"99".repeat(32)]));
    assert!(options::parse(&show).is_ok());
}

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "fg-agent-credential-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn generated_token_is_private_bounded_never_printed_and_never_overwrites() {
    let directory = Directory::new();
    let path = directory.0.join("agent.token");
    let args = strings(&["generate-token", "--output", path.to_str().unwrap()]);
    let mut report = Vec::new();
    assert_eq!(run_to(&args, &mut report).unwrap(), 0);
    let bearer = token::read(&path).unwrap();
    assert_eq!(bearer.len(), 72);
    assert!(bearer.starts_with(b"fgagent_"));
    let report = String::from_utf8(report).unwrap();
    assert!(!report.contains(std::str::from_utf8(&bearer).unwrap()));
    assert!(report.contains(&agent_credential_id(&bearer).unwrap().to_string()));
    assert!(run_to(&args, &mut Vec::new()).is_err());
    assert_eq!(token::read(&path).unwrap(), bearer);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let link = directory.0.join("link");
        symlink(&path, &link).unwrap();
        assert!(token::read(&link).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(token::read(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    for bytes in [
        b"secret\n".to_vec(),
        format!("fgagent_{}\r\n", "aa".repeat(32)).into_bytes(),
        format!("fgagent_{}\n\n", "aa".repeat(32)).into_bytes(),
        format!("fgagent_{}", "AA".repeat(32)).into_bytes(),
        vec![b'a'; 4096],
    ] {
        std::fs::write(&path, bytes).unwrap();
        assert!(token::read(&path).is_err());
    }
    std::fs::write(&path, &bearer).unwrap();
    assert_eq!(token::read(&path).unwrap(), bearer);
}

#[test]
fn complete_proof_and_pull_diff_scopes_are_independent_explicit_cli_grants() {
    for (scopes, expected) in [
        ("source-verified-read", SOURCE_VERIFIED_READ),
        ("pulls-diff-read", PULLS_DIFF_READ),
        (
            "source-verified-read,pulls-diff-read",
            SOURCE_VERIFIED_READ | PULLS_DIFF_READ,
        ),
        (
            "source-read,source-verified-read",
            SOURCE_READ | SOURCE_VERIFIED_READ,
        ),
    ] {
        let mut input = issue();
        replace(&mut input, "--operations", scopes);
        let Options::Repository(parsed) = options::parse(&input).unwrap() else {
            panic!()
        };
        let Operation::Issue {
            grant,
            source_scope,
            ..
        } = parsed.operation
        else {
            panic!()
        };
        assert_eq!(grant.operations, expected);
        assert!(source_scope.is_none());
        assert!(!grant.permits(SOURCE_PUBLISH));
        for scope in [
            SOURCE_READ,
            SOURCE_HISTORY_READ,
            SOURCE_CANDIDATES,
            SOURCE_VERIFIED_READ,
            PULLS_DIFF_READ,
        ] {
            assert_eq!(grant.permits(scope), expected & scope != 0);
        }
    }
    for scopes in [
        "source-verified-read,source-verified-read",
        "pulls-diff-read,pulls-diff-read",
        "proof-read",
        "pulls-diff-read,receive",
    ] {
        let mut input = issue();
        replace(&mut input, "--operations", scopes);
        assert!(options::parse(&input).is_err());
    }
}

#[test]
fn feedback_cli_issuance_is_explicit_and_never_implies_source_or_write_scopes() {
    for (scopes, expected) in [
        ("pulls-feedback-read", PULLS_FEEDBACK_READ),
        (
            "pulls-read,pulls-feedback-read",
            PULLS_READ | PULLS_FEEDBACK_READ,
        ),
        (
            "pulls-diff-read,pulls-feedback-read",
            PULLS_DIFF_READ | PULLS_FEEDBACK_READ,
        ),
        (
            "source-read,pulls-feedback-read",
            SOURCE_READ | PULLS_FEEDBACK_READ,
        ),
    ] {
        let mut input = issue();
        replace(&mut input, "--operations", scopes);
        let Options::Repository(parsed) = options::parse(&input).unwrap() else {
            panic!()
        };
        let Operation::Issue {
            grant,
            source_scope,
            ..
        } = parsed.operation
        else {
            panic!()
        };
        assert_eq!(grant.operations, expected);
        assert!(source_scope.is_none());
        for operation in (0..16).map(|bit| 1u16 << bit) {
            assert_eq!(grant.permits(operation), expected & operation != 0);
        }
        input.extend(strings(&[
            "--source-ref-scope",
            "exact:726566732f68656164732f6167656e74",
            "--source-path-hex",
            "737263",
        ]));
        assert!(options::parse(&input).is_err());
    }
    for scopes in [
        "pulls-feedback-read,pulls-feedback-read",
        "pulls-feedback-read,",
        "feedback-read",
        "pulls-feedback-read,reviews-write",
        "pulls-feedback-read,checks-write",
        "pulls-feedback-read,artifacts-read",
    ] {
        let mut input = issue();
        replace(&mut input, "--operations", scopes);
        assert!(options::parse(&input).is_err(), "{scopes}");
    }
    let mut output = Vec::new();
    assert_eq!(run_to(&strings(&["issue", "--help"]), &mut output), Ok(0));
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("pulls-feedback-read permits bounded review pages"));
    assert!(output.contains("canonical check summaries"));
    assert!(output.contains("Check evidence bodies, logs and artifacts require separate authority."));
}
