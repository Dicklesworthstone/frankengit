use super::*;
use fgit_identity::agent::{
    ISSUES_READ, ISSUES_WRITE, PULLS_WRITE, SOURCE_HISTORY_READ, SOURCE_READ, SponsorKind,
};
use std::path::PathBuf;

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
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
