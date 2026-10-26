use super::*;

#[cfg(unix)]
mod unix {
    use super::*;
    use fgit_identity::deploy_key::{DeployKeyRefusal, DeployKeyScope};
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant, SystemTime};

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "fgit-live-ssh-keys-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn file(&self) -> PathBuf {
            self.0.join("deploy-keys")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn repository() -> RepositoryId {
        RepositoryId::from_bytes([0x61; 16])
    }

    fn route() -> RepositoryId {
        RepositoryId::from_bytes([0x62; 16])
    }

    fn principal(seed: u8) -> PrincipalId {
        PrincipalId::from_bytes([seed; 16])
    }

    fn key(seed: u8) -> [u8; 32] {
        fgit_ssh::SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
    }

    fn row(seed: u8, owner: u8, scopes: &str) -> String {
        let key: String = key(seed).iter().map(|byte| format!("{byte:02x}")).collect();
        format!("{key} {} {scopes}\n", principal(owner))
    }

    fn private_write(path: &Path, bytes: &[u8]) {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    fn replace(path: &Path, bytes: &[u8]) {
        let next = path.with_extension("next");
        private_write(&next, bytes);
        fs::rename(next, path).unwrap();
    }

    fn open_source(path: &Path) -> FileDeployKeyAuthorizer {
        FileDeployKeyAuthorizer::try_new(path.to_path_buf(), repository(), route()).unwrap()
    }

    #[test]
    fn each_exec_observes_atomic_revocation_addition_scope_and_principal_changes() {
        let scratch = Scratch::new();
        let path = scratch.file();
        private_write(&path, row(1, 11, "read").as_bytes());
        let source = open_source(&path);
        for selected_repository in [repository(), route()] {
            assert_eq!(
                source.authorize_command(&key(1), selected_repository, SshGitService::UploadPack),
                Ok(principal(11)),
            );
            assert!(matches!(
                source.authorize_command(&key(1), selected_repository, SshGitService::ReceivePack),
                Err(AuthRefusal::DeployKey(DeployKeyRefusal::ScopeNotGranted {
                    requested: DeployKeyScope::Write,
                })),
            ));
        }
        assert!(matches!(
            source.authorize_command(
                &key(1),
                RepositoryId::from_bytes([0x63; 16]),
                SshGitService::UploadPack,
            ),
            Err(AuthRefusal::DeployKey(DeployKeyRefusal::NoBindingForKey)),
        ));

        replace(&path, row(2, 22, "read,write").as_bytes());
        assert!(matches!(
            source.authorize_command(&key(1), repository(), SshGitService::UploadPack),
            Err(AuthRefusal::DeployKey(DeployKeyRefusal::NoBindingForKey)),
        ));
        for service in [SshGitService::UploadPack, SshGitService::ReceivePack] {
            assert_eq!(
                source.authorize_command(&key(2), repository(), service),
                Ok(principal(22)),
            );
        }

        replace(&path, row(2, 33, "read").as_bytes());
        assert_eq!(
            source.authorize_command(&key(2), repository(), SshGitService::UploadPack),
            Ok(principal(33)),
        );
        assert!(
            source
                .authorize_command(&key(2), repository(), SshGitService::ReceivePack)
                .is_err()
        );

        replace(
            &path,
            b"# revoke every key without restarting the listener\n",
        );
        assert!(matches!(
            source.authorize_command(&key(2), route(), SshGitService::UploadPack),
            Err(AuthRefusal::DeployKey(DeployKeyRefusal::NoBindingForKey)),
        ));
        replace(&path, row(1, 44, "read,write").as_bytes());
        assert_eq!(
            source.authorize_command(&key(1), route(), SshGitService::ReceivePack),
            Ok(principal(44)),
        );
    }

    #[test]
    fn malformed_or_unavailable_replacement_never_reuses_a_previously_valid_grant() {
        let scratch = Scratch::new();
        let path = scratch.file();
        let valid = row(1, 11, "read,write");
        private_write(&path, valid.as_bytes());
        let source = open_source(&path);
        assert!(
            source
                .authorize_command(&key(1), repository(), SshGitService::ReceivePack)
                .is_ok()
        );

        let replacements = [
            format!("{valid}malformed unrelated registration\n").into_bytes(),
            format!("{valid}{valid}").into_bytes(),
            [valid.as_bytes(), &[0xff]].concat(),
        ];
        for malformed in replacements {
            replace(&path, &malformed);
            assert_eq!(
                source.authorize_command(&key(1), repository(), SshGitService::UploadPack),
                Err(AuthRefusal::AuthorizationSourceUnavailable),
            );
            assert!(matches!(
                FileDeployKeyAuthorizer::try_new(path.clone(), repository(), route()),
                Err(FileDeployKeyRefusal::InvalidTable(_)),
            ));
            replace(&path, valid.as_bytes());
            assert_eq!(
                source.authorize_command(&key(1), repository(), SshGitService::UploadPack),
                Ok(principal(11)),
            );
        }
        fs::remove_file(&path).unwrap();
        assert_eq!(
            source.authorize_command(&key(1), repository(), SshGitService::ReceivePack),
            Err(AuthRefusal::AuthorizationSourceUnavailable),
        );
        private_write(&path, valid.as_bytes());
        assert_eq!(
            source.authorize_command(&key(1), repository(), SshGitService::ReceivePack),
            Ok(principal(11)),
        );

        // An initially empty source also observes a new key on its next exec.
        replace(&path, b"");
        let empty = open_source(&path);
        replace(&path, row(2, 22, "read").as_bytes());
        assert_eq!(
            empty.authorize_command(&key(2), repository(), SshGitService::UploadPack),
            Ok(principal(22)),
        );
    }

    #[test]
    fn exact_byte_bound_is_accepted_and_growing_or_changed_descriptors_are_refused() {
        let scratch = Scratch::new();
        let path = scratch.file();
        let valid = row(1, 11, "read");
        let mut boundary = valid.as_bytes().to_vec();
        boundary.push(b'#');
        boundary.resize(MAX_DEPLOY_KEY_TABLE_BYTES, b'x');
        private_write(&path, &boundary);
        let source = open_source(&path);
        assert_eq!(
            source.authorize_command(&key(1), repository(), SshGitService::UploadPack),
            Ok(principal(11)),
        );
        boundary.push(b'x');
        replace(&path, &boundary);
        assert!(matches!(
            source.read_bindings(),
            Err(FileDeployKeyRefusal::TooLarge {
                observed,
                limit: MAX_DEPLOY_KEY_TABLE_BYTES,
            }) if observed == (MAX_DEPLOY_KEY_TABLE_BYTES + 1) as u64,
        ));
        assert_eq!(
            source.authorize_command(&key(1), repository(), SshGitService::UploadPack),
            Err(AuthRefusal::AuthorizationSourceUnavailable),
        );

        replace(&path, valid.as_bytes());
        let file = open_regular_file(&path).unwrap();
        let opened = file.metadata().unwrap();
        let mut writer = fs::OpenOptions::new().append(true).open(&path).unwrap();
        writer
            .write_all(&vec![b'x'; MAX_DEPLOY_KEY_TABLE_BYTES])
            .unwrap();
        writer.sync_all().unwrap();
        assert!(matches!(
            read_snapshot(file, &opened),
            Err(FileDeployKeyRefusal::TooLarge {
                observed,
                limit: MAX_DEPLOY_KEY_TABLE_BYTES,
            }) if observed == (MAX_DEPLOY_KEY_TABLE_BYTES + 1) as u64,
        ));

        replace(&path, valid.as_bytes());
        let file = open_regular_file(&path).unwrap();
        let opened = file.metadata().unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
            .unwrap();
        assert_eq!(
            read_snapshot(file, &opened),
            Err(FileDeployKeyRefusal::UnsafeFile),
        );
        replace(&path, valid.as_bytes());
        assert_eq!(
            source.authorize_command(&key(1), repository(), SshGitService::UploadPack),
            Ok(principal(11)),
        );
    }

    #[test]
    fn every_reload_requires_private_regular_files_and_descriptor_open_cannot_wait_on_a_fifo() {
        let scratch = Scratch::new();
        let path = scratch.file();
        let valid = row(1, 11, "read");
        private_write(&path, valid.as_bytes());
        let source = open_source(&path);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            source.read_bindings(),
            Err(FileDeployKeyRefusal::UnsafeFile)
        );
        assert_eq!(
            source.authorize_command(&key(1), repository(), SshGitService::UploadPack),
            Err(AuthRefusal::AuthorizationSourceUnavailable),
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            source
                .authorize_command(&key(1), repository(), SshGitService::UploadPack)
                .is_ok()
        );

        let target = scratch.0.join("target");
        private_write(&target, valid.as_bytes());
        fs::remove_file(&path).unwrap();
        symlink(&target, &path).unwrap();
        assert_eq!(
            source.read_bindings(),
            Err(FileDeployKeyRefusal::UnsafeFile)
        );
        // Exercise the actual descriptor opener without its preceding lstat:
        // swapping a regular file for this symlink must still fail closed.
        assert!(open_regular_file(&path).is_err());
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert_eq!(
            source.read_bindings(),
            Err(FileDeployKeyRefusal::UnsafeFile)
        );
        fs::remove_dir(&path).unwrap();

        rustix::fs::mkfifo(&path, rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR).unwrap();
        let started = Instant::now();
        // No writer is opened. NOFOLLOW alone would not prevent this open
        // from blocking if the path changed to a FIFO after metadata checking.
        assert!(matches!(
            open_regular_file(&path),
            Err(FileDeployKeyRefusal::UnsafeFile),
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(
            source.read_bindings(),
            Err(FileDeployKeyRefusal::UnsafeFile)
        );
        fs::remove_file(&path).unwrap();
        private_write(&path, valid.as_bytes());
        assert_eq!(
            source.authorize_command(&key(1), repository(), SshGitService::UploadPack),
            Ok(principal(11)),
        );
    }
}

#[cfg(not(unix))]
#[test]
fn a_live_file_source_refuses_an_unsupported_platform_without_opening_the_path() {
    assert!(matches!(
        FileDeployKeyAuthorizer::try_new(
            PathBuf::from("does-not-exist"),
            RepositoryId::from_bytes([1; 16]),
            RepositoryId::from_bytes([2; 16]),
        ),
        Err(FileDeployKeyRefusal::UnsupportedPlatform),
    ));
}
