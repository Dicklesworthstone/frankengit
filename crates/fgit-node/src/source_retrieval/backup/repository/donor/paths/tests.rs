use super::*;

#[cfg(unix)]
mod unix {
    use super::*;
    use std::cell::Cell;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);
    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "fg-donor-paths-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            fs::create_dir(root.join("source")).unwrap();
            fs::write(root.join("donor.fg"), b"test path fixture, not an archive").unwrap();
            Self(root)
        }
        fn source(&self) -> PathBuf {
            self.0.join("source")
        }
        fn input(&self) -> PathBuf {
            self.0.join("donor.fg")
        }
        fn output(&self) -> PathBuf {
            self.0.join("output.fg")
        }
        fn scratch(&self) -> PathBuf {
            self.0.join("verify")
        }
        fn capture(&self) -> Separation {
            Separation::capture(
                &self.source(),
                &self.input(),
                &self.output(),
                &self.scratch(),
                || Ok(()),
            )
            .unwrap()
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn separate_siblings_share_an_existing_parent_without_creating_any_output() {
        let fixture = Scratch::new();
        let guard = fixture.capture();
        guard.check(|| Ok(())).unwrap();
        assert!(!fixture.output().exists());
        assert!(!fixture.scratch().exists());
        assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 2);
        assert_eq!(
            fs::read(fixture.input()).unwrap(),
            b"test path fixture, not an archive"
        );
    }

    #[test]
    fn input_output_scratch_and_source_cannot_alias_or_contain_each_other() {
        let fixture = Scratch::new();
        for (input, output, scratch) in [
            (
                fixture.input(),
                fixture.source().join("output"),
                fixture.scratch(),
            ),
            (
                fixture.input(),
                fixture.output(),
                fixture.source().join("scratch"),
            ),
            (fixture.input(), fixture.input(), fixture.scratch()),
            (fixture.input(), fixture.output(), fixture.input()),
            (fixture.input(), fixture.output(), fixture.output()),
            (fixture.input(), fixture.output(), fixture.0.clone()),
        ] {
            assert!(
                Separation::capture(&fixture.source(), &input, &output, &scratch, || Ok(()))
                    .is_err()
            );
        }
        let inside = fixture.source().join("donor");
        fs::write(&inside, b"untrusted path fixture").unwrap();
        assert!(
            Separation::capture(
                &fixture.source(),
                &inside,
                &fixture.output(),
                &fixture.scratch(),
                || Ok(())
            )
            .is_err()
        );
        fs::create_dir(fixture.0.join("new-root")).unwrap();
        assert!(
            Separation::capture(
                &fixture.source(),
                &fixture.input(),
                &fixture.0.join("new-root/out"),
                &fixture.0.join("new-root"),
                || Ok(())
            )
            .is_err()
        );
    }

    #[test]
    fn physical_parent_aliases_cannot_hide_live_source_overlap() {
        let fixture = Scratch::new();
        let alias = fixture.0.join("source-alias");
        symlink(fixture.source(), &alias).unwrap();
        assert!(
            Separation::capture(
                &fixture.source(),
                &fixture.input(),
                &alias.join("out"),
                &fixture.scratch(),
                || Ok(())
            )
            .is_err()
        );
        assert!(
            Separation::capture(
                &alias,
                &fixture.input(),
                &fixture.output(),
                &fixture.scratch(),
                || Ok(())
            )
            .is_err(),
            "source leaf symlinks refuse"
        );
        let donor_alias = fixture.0.join("donor-alias");
        symlink(fixture.input(), &donor_alias).unwrap();
        assert!(
            Separation::capture(
                &fixture.source(),
                &donor_alias,
                &fixture.output(),
                &fixture.scratch(),
                || Ok(())
            )
            .is_err(),
            "donor leaf symlinks refuse"
        );
    }

    #[test]
    fn replacing_a_protected_directory_or_changing_its_mode_invalidates_the_guard() {
        let fixture = Scratch::new();
        let guard = fixture.capture();
        fs::rename(fixture.source(), fixture.0.join("source-before")).unwrap();
        fs::create_dir(fixture.source()).unwrap();
        assert!(guard.check(|| Ok(())).is_err());

        let fixture = Scratch::new();
        let guard = fixture.capture();
        let permissions = fs::metadata(fixture.source()).unwrap().permissions();
        let changed = permissions.mode() ^ 0o010;
        fs::set_permissions(fixture.source(), fs::Permissions::from_mode(changed)).unwrap();
        assert!(guard.check(|| Ok(())).is_err());
        fs::set_permissions(fixture.source(), permissions).unwrap();
    }

    #[test]
    fn retargeting_a_parent_alias_invalidates_an_otherwise_intact_directory() {
        let fixture = Scratch::new();
        let first = fixture.0.join("first");
        let second = fixture.0.join("second");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        let alias = fixture.0.join("output-parent");
        symlink(&first, &alias).unwrap();
        let guard = Separation::capture(
            &fixture.source(),
            &fixture.input(),
            &alias.join("out.fg"),
            &fixture.scratch(),
            || Ok(()),
        )
        .unwrap();
        guard.check(|| Ok(())).unwrap();
        fs::remove_file(&alias).unwrap();
        symlink(&second, &alias).unwrap();
        assert!(guard.check(|| Ok(())).is_err());
        assert!(!first.join("out.fg").exists());
        assert!(!second.join("out.fg").exists());
    }

    #[test]
    fn cancellation_checks_cover_preflight_and_every_later_guard_pass() {
        let fixture = Scratch::new();
        assert!(
            Separation::capture(
                &fixture.source(),
                &fixture.input(),
                &fixture.output(),
                &fixture.scratch(),
                || Err("expired".into())
            )
            .is_err()
        );
        let guard = fixture.capture();
        let visits = Cell::new(0);
        assert!(
            guard
                .check(|| {
                    visits.set(visits.get() + 1);
                    if visits.get() == 2 {
                        Err("cancelled".into())
                    } else {
                        Ok(())
                    }
                })
                .is_err()
        );
        assert_eq!(visits.get(), 2);
        assert!(!fixture.output().exists());
        assert!(!fixture.scratch().exists());
    }
}

#[cfg(not(unix))]
#[test]
fn unsupported_directory_identity_profile_refuses_without_filesystem_access() {
    assert!(
        Separation::capture(
            Path::new("source"),
            Path::new("input"),
            Path::new("output"),
            Path::new("scratch"),
            || Ok(())
        )
        .err()
        .unwrap()
        .contains("requires Unix")
    );
}
