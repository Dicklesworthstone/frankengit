//! CLI-owned live deploy-key sources survive configuration parsing.

use super::*;
use fgit_identity::deploy_key::DeployKeyRefusal;
use fgit_ssh::{AuthRefusal, SshGitService};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
const REPOSITORY: RepositoryId = RepositoryId::from_bytes([0x22; 16]);
const PRINCIPAL: PrincipalId = PrincipalId::from_bytes([0x44; 16]);

struct Fixture {
    root: PathBuf,
    host: PathBuf,
    table: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-ssh-live-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&root).unwrap();
        let host = root.join("host-key");
        fs::write(&host, [0x11; 32]).unwrap();
        Self {
            table: root.join("deploy-keys"),
            host,
            root,
        }
    }

    fn replace(&self, contents: &str) {
        let replacement = self.root.join(format!(
            "replacement-{}",
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&replacement)
            .unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        drop(file);
        fs::rename(replacement, &self.table).unwrap();
    }

    fn arguments(&self, credential_flags: &[&str], lifetime: &[&str]) -> Vec<String> {
        [
            "serve-ssh",
            "not-opened",
            &"11".repeat(16),
            &REPOSITORY.to_string(),
            "127.0.0.1:0",
            "--host-key-file",
            self.host.to_str().unwrap(),
        ]
        .into_iter()
        .chain(credential_flags.iter().copied())
        .chain(lifetime.iter().copied())
        .map(str::to_owned)
        .collect()
    }

    fn file_arguments(&self, lifetime: &[&str]) -> Vec<String> {
        self.arguments(
            &["--deploy-keys-file", self.table.to_str().unwrap()],
            lifetime,
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn key(seed: u8) -> [u8; 32] {
    SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn row(seed: u8, principal: PrincipalId, scopes: &str) -> String {
    format!("{} {principal} {scopes}\n", hex(&key(seed)))
}

#[test]
fn file_credentials_remain_live_after_parsing_in_both_service_lifetimes() {
    for lifetime in [
        vec!["--max-sessions", "2"],
        vec!["--continuous", "--stop-file", "ssh.stop"],
    ] {
        let fixture = Fixture::new();
        fixture.replace(&row(1, PRINCIPAL, "read,write"));
        let prepared = parse(&fixture.file_arguments(&lifetime)).unwrap();
        let authorize = |seed, service| {
            prepared
                .authorizer
                .authorize_command(&key(seed), REPOSITORY, service)
        };
        assert_eq!(authorize(1, SshGitService::ReceivePack), Ok(PRINCIPAL));

        let rotated = PrincipalId::from_bytes([0x55; 16]);
        fixture.replace(&row(2, rotated, "read"));
        assert_eq!(
            authorize(1, SshGitService::UploadPack),
            Err(AuthRefusal::DeployKey(DeployKeyRefusal::NoBindingForKey))
        );
        assert_eq!(authorize(2, SshGitService::UploadPack), Ok(rotated));
        assert_eq!(
            authorize(2, SshGitService::ReceivePack),
            Err(AuthRefusal::DeployKey(DeployKeyRefusal::ScopeNotGranted {
                requested: DeployKeyScope::Write
            }))
        );

        fixture.replace(&format!("{}malformed later row\n", row(2, rotated, "read")));
        assert_eq!(
            authorize(2, SshGitService::UploadPack),
            Err(AuthRefusal::AuthorizationSourceUnavailable)
        );
        fixture.replace(&row(2, rotated, "read"));
        assert_eq!(authorize(2, SshGitService::UploadPack), Ok(rotated));
        fs::remove_file(&fixture.table).unwrap();
        assert_eq!(
            authorize(2, SshGitService::UploadPack),
            Err(AuthRefusal::AuthorizationSourceUnavailable)
        );
        fixture.replace("");
        assert_eq!(
            authorize(2, SshGitService::UploadPack),
            Err(AuthRefusal::DeployKey(DeployKeyRefusal::NoBindingForKey))
        );
    }
}

#[test]
fn invalid_file_configuration_refuses_before_starting_service() {
    let fixture = Fixture::new();
    assert!(parse(&fixture.file_arguments(&[])).is_err());
    fixture.replace("malformed\n");
    assert!(parse(&fixture.file_arguments(&[])).is_err());
    fixture.replace(&row(1, PRINCIPAL, "read"));
    assert!(parse(&fixture.file_arguments(&[])).is_ok());
    for (flag, value) in [
        ("--deploy-key", hex(&key(1))),
        ("--principal", PRINCIPAL.to_string()),
        ("--scopes", "read".to_owned()),
    ] {
        assert!(
            parse(&fixture.file_arguments(&[flag, &value])).is_err(),
            "{flag}"
        );
    }
}

#[test]
fn inline_credentials_keep_the_explicit_static_profile_and_scopes() {
    let fixture = Fixture::new();
    let args = fixture.arguments(
        &[
            "--deploy-key",
            &hex(&key(1)),
            "--principal",
            &PRINCIPAL.to_string(),
            "--scopes",
            "write,read,read",
        ],
        &[],
    );
    let prepared = parse(&args).unwrap();
    for service in [SshGitService::UploadPack, SshGitService::ReceivePack] {
        assert_eq!(
            prepared
                .authorizer
                .authorize_command(&key(1), REPOSITORY, service),
            Ok(PRINCIPAL)
        );
    }
    assert!(
        prepared
            .authorizer
            .authorize_command(&key(2), REPOSITORY, SshGitService::UploadPack)
            .is_err()
    );
    assert!(
        prepared
            .authorizer
            .authorize_command(
                &key(1),
                RepositoryId::from_bytes([0x33; 16]),
                SshGitService::UploadPack
            )
            .is_err()
    );
}

#[test]
fn non_ascii_hex_refuses_without_panicking_in_inline_or_host_key_parsing() {
    for malformed in ["€".repeat(21) + "0", "é".repeat(32)] {
        assert_eq!(malformed.len(), 64);
        assert!(parse_hex_key_32(&malformed, "test key").is_err());
        let fixture = Fixture::new();
        let args = fixture.arguments(
            &[
                "--deploy-key",
                &malformed,
                "--principal",
                &PRINCIPAL.to_string(),
                "--scopes",
                "read",
            ],
            &[],
        );
        assert!(parse(&args).is_err());
        fs::write(&fixture.host, malformed).unwrap();
        assert!(read_host_key(&fixture.host).is_err());
    }
}
