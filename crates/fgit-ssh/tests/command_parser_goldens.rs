#![forbid(unsafe_code)]

use fgit_ssh::command::{CommandParseRefusal, SshGitCommand, SshGitService};

#[test]
fn test_valid_commands() {
    let cases = [
        ("git-upload-pack 'repo.git'", SshGitService::UploadPack, "repo.git"),
        ("git-upload-pack '/repo.git'", SshGitService::UploadPack, "repo.git"),
        ("git-upload-pack '/owner/repo.git'", SshGitService::UploadPack, "owner/repo.git"),
        ("git-receive-pack 'repo.git'", SshGitService::ReceivePack, "repo.git"),
        ("git-receive-pack '/path/to/my-repo.git'", SshGitService::ReceivePack, "path/to/my-repo.git"),
        ("git upload-pack 'repo.git'", SshGitService::UploadPack, "repo.git"),
        ("git receive-pack 'repo.git'", SshGitService::ReceivePack, "repo.git"),
        ("git-upload-pack \"repo.git\"", SshGitService::UploadPack, "repo.git"),
        ("git-upload-pack repo.git", SshGitService::UploadPack, "repo.git"),
        ("git-upload-pack 'path with spaces/repo.git'", SshGitService::UploadPack, "path with spaces/repo.git"),
        ("git-upload-pack 'foo'\\''bar.git'", SshGitService::UploadPack, "foo'bar.git"),
    ];

    for (input, expected_service, expected_path) in cases {
        let cmd = SshGitCommand::parse(input)
            .unwrap_or_else(|e| panic!("failed to parse `{input}`: {e:?}"));
        assert_eq!(cmd.service(), expected_service, "service mismatch for `{input}`");
        assert_eq!(cmd.repository_path(), expected_path, "path mismatch for `{input}`");
    }
}

#[test]
fn test_empty_and_unsupported_services() {
    assert_eq!(SshGitCommand::parse(""), Err(CommandParseRefusal::EmptyCommand));
    assert_eq!(SshGitCommand::parse("   "), Err(CommandParseRefusal::EmptyCommand));

    let hostile = [
        "rm -rf /",
        "bash -c 'id'",
        "sh",
        "cat /etc/passwd",
        "git-archive 'repo.git'",
        "git",
        "echo hello",
    ];

    for input in hostile {
        let err = SshGitCommand::parse(input).unwrap_err();
        assert!(
            matches!(err, CommandParseRefusal::UnsupportedService { .. }),
            "expected UnsupportedService for `{input}`, got {err:?}"
        );
    }
}

#[test]
fn test_option_injection_attacks() {
    let options = [
        "git-upload-pack '--exec=calc.exe'",
        "git-upload-pack '-v'",
        "git-upload-pack '--upload-pack=/bin/sh'",
        "git-receive-pack '--receive-pack=/bin/sh'",
        "git-upload-pack -rf",
    ];

    for input in options {
        let err = SshGitCommand::parse(input).unwrap_err();
        assert!(
            matches!(err, CommandParseRefusal::OptionInjection { .. }),
            "expected OptionInjection for `{input}`, got {err:?}"
        );
    }
}

#[test]
fn test_shell_metacharacters_attacks() {
    let metachars = [
        ("git-upload-pack 'repo.git; rm -rf /'", ';'),
        ("git-upload-pack 'repo.git && id'", '&'),
        ("git-upload-pack 'repo.git | ls'", '|'),
        ("git-upload-pack '$(id).git'", '$'),
        ("git-upload-pack '`id`.git'", '`'),
        ("git-upload-pack 'repo.git\nid'", '\n'),
        ("git-upload-pack 'repo.git > /tmp/pwn'", '>'),
        ("git-upload-pack 'repo.git < /etc/passwd'", '<'),
        ("git-upload-pack 'repo.git!danger'", '!'),
        ("git-upload-pack '{a,b}.git'", '{'),
    ];

    for (input, expected_char) in metachars {
        let err = SshGitCommand::parse(input).unwrap_err();
        assert_eq!(
            err,
            CommandParseRefusal::ShellMetacharacterForbidden {
                character: expected_char
            },
            "mismatch for `{input}`"
        );
    }
}

#[test]
fn test_directory_traversal_attacks() {
    let traversals = [
        "git-upload-pack '../secret.git'",
        "git-upload-pack '/../secret.git'",
        "git-upload-pack 'a/../../b.git'",
        "git-upload-pack 'repo.git/..'",
        "git-upload-pack 'repo.git/../etc/passwd'",
        "git-upload-pack '..'",
    ];

    for input in traversals {
        let err = SshGitCommand::parse(input).unwrap_err();
        assert_eq!(
            err,
            CommandParseRefusal::PathTraversalForbidden,
            "mismatch for `{input}`"
        );
    }
}

#[test]
fn test_null_byte_attacks() {
    let null_cases = [
        "git-upload-pack 'repo.git\0extra'",
        "git-receive-pack '\0repo.git'",
    ];

    for input in null_cases {
        let err = SshGitCommand::parse(input).unwrap_err();
        assert_eq!(
            err,
            CommandParseRefusal::NullByteForbidden,
            "mismatch for `{input}`"
        );
    }
}

#[test]
fn test_trailing_arguments_and_malformed_quotes() {
    let trailing = [
        "git-upload-pack 'repo.git' extra_arg",
        "git-upload-pack repo.git extra_arg",
        "git-upload-pack \"repo.git\" extra",
    ];

    for input in trailing {
        let err = SshGitCommand::parse(input).unwrap_err();
        assert_eq!(
            err,
            CommandParseRefusal::TrailingArgumentsForbidden,
            "mismatch for `{input}`"
        );
    }

    let bad_quotes = [
        "git-upload-pack 'unclosed",
        "git-upload-pack \"unclosed",
        "git-upload-pack '",
        "git-upload-pack \"",
    ];

    for input in bad_quotes {
        let err = SshGitCommand::parse(input).unwrap_err();
        assert_eq!(
            err,
            CommandParseRefusal::InvalidQuoting,
            "mismatch for `{input}`"
        );
    }
}
