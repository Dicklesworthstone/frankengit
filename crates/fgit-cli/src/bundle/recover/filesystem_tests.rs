//! Actual production filesystem state machine, independent of the Git parser.
//! Synthetic body bytes here test publication, ownership and interruption only;
//! native-plan and ordinary Git compatibility are separate integration gates.
#![cfg(unix)]

use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::sync::atomic::{AtomicU64, Ordering};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "fg-native-materialize-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        create_private_directory(&root).unwrap();
        Self(root)
    }
    fn target(&self) -> PathBuf {
        self.0.join("source.git")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

struct Bodies {
    record: Vec<u8>,
    stem: String,
    pack: Vec<u8>,
    index: Vec<u8>,
    refs: Vec<u8>,
    config: Vec<u8>,
    head: Vec<u8>,
}
impl Bodies {
    fn new(width: usize) -> Self {
        Self {
            record: format!("frankengit-native-bare-recovery-v1\nartifact-sha256 {}\nobject-format {}\nhead-ref-hex 726566732f68656164732f6d61696e\npack-checksum {}\n", "a".repeat(64), if width == 40 { "sha1" } else { "sha256" }, "b".repeat(width)).into_bytes(),
            stem: format!("pack-{}", "b".repeat(width)),
            // Multiple I/O chunks including every byte value and a short tail.
            pack: (0..CHUNK + 517).map(|n| (n % 256) as u8).collect(),
            index: (0..333).map(|n| (n % 251) as u8).collect(),
            refs: format!("# pack-refs with: sorted\n{} refs/heads/main\n", "c".repeat(width)).into_bytes(),
            config: b"[core]\n\trepositoryformatversion = 0\n\tbare = true\n".to_vec(),
            head: b"ref: refs/heads/main\n".to_vec(),
        }
    }
    fn layout(&self) -> Layout<'_> {
        Layout {
            record: &self.record,
            pack_stem: &self.stem,
            pack: &self.pack,
            index: &self.index,
            packed_refs: &self.refs,
            config: &self.config,
            head: &self.head,
        }
    }
    fn files(&self) -> Vec<(String, &[u8])> {
        vec![
            (RECORD.into(), &self.record),
            (format!("objects/pack/{}.pack", self.stem), &self.pack),
            (format!("objects/pack/{}.idx", self.stem), &self.index),
            ("packed-refs".into(), &self.refs),
            ("config".into(), &self.config),
            ("HEAD".into(), &self.head),
        ]
    }
    fn assert_complete(&self, root: &Path) {
        for (name, expected) in self.files() {
            assert_eq!(fs::read(root.join(&name)).unwrap(), expected, "{name}");
            assert!(!root.join(format!("{name}{PART}")).exists());
            let metadata = fs::symlink_metadata(root.join(&name)).unwrap();
            assert_eq!(metadata.mode() & 0o7777, 0o600);
            assert_eq!(metadata.nlink(), 1);
        }
        for path in [
            root.to_owned(),
            root.join("refs"),
            root.join("objects"),
            root.join("objects/pack"),
        ] {
            assert_eq!(fs::metadata(path).unwrap().mode() & 0o7777, 0o700);
        }
    }
}

fn private_write(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn recover(fixture: &Fixture, bodies: &Bodies, resume: bool) -> Result<Completed, Error> {
    materialize(&fixture.target(), &bodies.layout(), resume, &mut || true)
}

#[test]
fn exact_bodies_publish_head_last_in_both_native_filename_domains() {
    for width in [40, 64] {
        let fixture = Fixture::new();
        let bodies = Bodies::new(width);
        let result = materialize(&fixture.target(), &bodies.layout(), false, &mut || {
            if fixture.target().join("HEAD").exists() {
                for (name, expected) in bodies.files() {
                    assert_eq!(fs::read(fixture.target().join(name)).unwrap(), expected);
                }
            }
            true
        })
        .unwrap();
        assert_eq!(
            result,
            Completed {
                resumed: false,
                already_published: false
            }
        );
        bodies.assert_complete(&fixture.target());
        assert_eq!(
            recover(&fixture, &bodies, true).unwrap(),
            Completed {
                resumed: true,
                already_published: true
            }
        );
        bodies.assert_complete(&fixture.target());
    }
}

#[test]
fn every_cooperative_interruption_is_latched_and_identified_work_resumes() {
    let bodies = Bodies::new(40);
    let baseline = Fixture::new();
    let mut polls = 0;
    materialize(&baseline.target(), &bodies.layout(), false, &mut || {
        polls += 1;
        true
    })
    .unwrap();
    assert!(
        polls > 100 && polls < 5000,
        "unexpected checkpoint count {polls}"
    );
    let mut observed_partial_pack = false;
    let mut observed_published_stop = false;
    let mut observed_durable_stop = false;
    for stop in 1..=polls {
        let fixture = Fixture::new();
        let mut seen = 0;
        let error = materialize(&fixture.target(), &bodies.layout(), false, &mut || {
            seen += 1;
            seen != stop // Later polls would allow; the stopped call stays stopped.
        })
        .unwrap_err();
        assert_eq!(error.code, Code::Stopped, "stop={stop}: {error}");
        assert_eq!(seen, stop);
        observed_published_stop |= error.state == State::Published;
        observed_durable_stop |= error.state == State::Durable;
        let pack_part = fixture
            .target()
            .join(format!("objects/pack/{}.pack{PART}", bodies.stem));
        if let Ok(metadata) = fs::metadata(pack_part) {
            observed_partial_pack |=
                metadata.len() > 0 && metadata.len() < bodies.pack.len() as u64;
        }
        if fixture.target().join("HEAD").exists() {
            for (name, expected) in bodies.files() {
                assert_eq!(
                    fs::read(fixture.target().join(name)).unwrap(),
                    expected,
                    "stop={stop}"
                );
            }
        }
        if fixture.target().join(RECORD).exists() {
            recover(&fixture, &bodies, true).unwrap_or_else(|error| panic!("stop={stop}: {error}"));
            bodies.assert_complete(&fixture.target());
        } else if fixture.target().exists() {
            assert_eq!(
                recover(&fixture, &bodies, true).unwrap_err().code,
                Code::MissingRecoveryRecord
            );
            assert!(!fixture.target().join("HEAD").exists());
        }
    }
    assert!(observed_partial_pack);
    assert!(observed_published_stop);
    assert!(observed_durable_stop);
}

#[test]
fn fresh_recovery_never_reuses_files_directories_or_symlinks() {
    let bodies = Bodies::new(40);
    for kind in 0..3 {
        let fixture = Fixture::new();
        match kind {
            0 => create_private_directory(&fixture.target()).unwrap(),
            1 => private_write(&fixture.target(), b"keep this"),
            _ => {
                private_write(&fixture.0.join("unrelated"), b"keep this");
                symlink(fixture.0.join("unrelated"), fixture.target()).unwrap();
            }
        }
        let error = recover(&fixture, &bodies, false).unwrap_err();
        assert_eq!(error.code, Code::ExistingDestination);
        assert_eq!(error.state, State::Unchanged);
        if kind == 0 {
            assert_eq!(fs::read_dir(fixture.target()).unwrap().count(), 0);
        } else {
            assert_eq!(fs::read(fixture.target()).unwrap(), b"keep this");
        }
    }
}

#[test]
fn malformed_layout_refuses_before_directory_creation() {
    let fixture = Fixture::new();
    let bodies = Bodies::new(40);
    for stem in [
        "pack-../escape",
        "pack-aa",
        "pack-000000000000000000000000000000000000000G",
    ] {
        let mut layout = bodies.layout();
        layout.pack_stem = stem;
        let error = materialize(&fixture.target(), &layout, false, &mut || true).unwrap_err();
        assert_eq!(error.code, Code::InvalidLayout);
        assert!(!fixture.target().exists());
    }
    recover(&fixture, &bodies, false).unwrap();
}

#[test]
fn a_recovery_record_is_exact_and_partial_markers_never_establish_ownership() {
    let bodies = Bodies::new(64);
    let fixture = Fixture::new();
    create_private_directory(&fixture.target()).unwrap();
    private_write(
        &fixture.target().join(format!("{RECORD}{PART}")),
        &bodies.record[..12],
    );
    assert_eq!(
        recover(&fixture, &bodies, true).unwrap_err().code,
        Code::MissingRecoveryRecord
    );
    assert_eq!(fs::read_dir(fixture.target()).unwrap().count(), 1);
    let valid = Fixture::new();
    recover(&valid, &bodies, false).unwrap();
    let mut other = Bodies::new(64);
    other.record[50] ^= 1;
    let error = recover(&valid, &other, true).unwrap_err();
    assert_eq!(error.code, Code::BodyMismatch);
    assert_eq!(error.state, State::PublicationUncertain);
    bodies.assert_complete(&valid.target());
    recover(&valid, &bodies, true).unwrap();
}

#[test]
fn existing_prefixes_resume_by_append_and_matching_published_links_are_reaped() {
    let bodies = Bodies::new(40);
    let fixture = Fixture::new();
    recover(&fixture, &bodies, false).unwrap();
    fs::remove_file(fixture.target().join("HEAD")).unwrap();
    for (name, expected) in bodies.files().into_iter().skip(1) {
        if name != "HEAD" {
            fs::remove_file(fixture.target().join(&name)).unwrap();
        }
        private_write(
            &fixture.target().join(format!("{name}{PART}")),
            &expected[..expected.len() / 2],
        );
    }
    let result = recover(&fixture, &bodies, true).unwrap();
    assert!(!result.already_published);
    bodies.assert_complete(&fixture.target());
    for (name, _) in bodies.files() {
        fs::hard_link(
            fixture.target().join(&name),
            fixture.target().join(format!("{name}{PART}")),
        )
        .unwrap();
    }
    assert!(recover(&fixture, &bodies, true).unwrap().already_published);
    bodies.assert_complete(&fixture.target());
}

#[test]
fn wrong_prefix_final_body_or_unknown_entry_refuses_before_resume_mutation() {
    for defect in 0..3 {
        let bodies = Bodies::new(40);
        let fixture = Fixture::new();
        recover(&fixture, &bodies, false).unwrap();
        fs::remove_file(fixture.target().join("HEAD")).unwrap();
        fs::remove_file(fixture.target().join("config")).unwrap();
        let index_name = format!("objects/pack/{}.idx", bodies.stem);
        match defect {
            0 => {
                fs::remove_file(fixture.target().join(&index_name)).unwrap();
                private_write(
                    &fixture.target().join(format!("{index_name}{PART}")),
                    b"wrong prefix",
                );
            }
            1 => {
                fs::write(fixture.target().join(index_name), b"wrong complete body").unwrap();
            }
            _ => {
                private_write(
                    &fixture.target().join("do-not-touch"),
                    b"unrelated operator file",
                );
            }
        }
        let error = recover(&fixture, &bodies, true).unwrap_err();
        assert!(matches!(
            error.code,
            Code::BodyMismatch | Code::UnexpectedEntry
        ));
        assert!(!fixture.target().join("config").exists());
        assert!(!fixture.target().join("HEAD").exists());
    }
}

#[test]
fn a_visible_head_with_missing_dependencies_is_never_repaired_in_place() {
    for missing in ["config", "refs", "packed-refs"] {
        let fixture = Fixture::new();
        let bodies = Bodies::new(64);
        recover(&fixture, &bodies, false).unwrap();
        if missing == "refs" {
            fs::remove_dir(fixture.target().join(missing)).unwrap();
        } else {
            fs::remove_file(fixture.target().join(missing)).unwrap();
        }
        let error = recover(&fixture, &bodies, true).unwrap_err();
        assert_eq!(error.code, Code::BodyMismatch);
        assert_eq!(error.state, State::PublicationUncertain);
        assert!(!fixture.target().join(missing).exists());
        assert_eq!(
            fs::read(fixture.target().join("HEAD")).unwrap(),
            bodies.head
        );
    }
}

#[test]
fn unrelated_entries_cannot_hide_a_preexisting_publication_root() {
    let fixture = Fixture::new();
    let bodies = Bodies::new(40);
    recover(&fixture, &bodies, false).unwrap();
    private_write(&fixture.target().join("operator-note"), b"preserve this");
    let error = recover(&fixture, &bodies, true).unwrap_err();
    assert_eq!(error.code, Code::UnexpectedEntry);
    assert_eq!(error.state, State::PublicationUncertain);
    assert_eq!(
        fs::read(fixture.target().join("operator-note")).unwrap(),
        b"preserve this"
    );
    bodies.assert_complete(&fixture.target());
}

#[test]
fn resume_refusals_before_target_inspection_preserve_publication_uncertainty() {
    let fixture = Fixture::new();
    let bodies = Bodies::new(40);
    recover(&fixture, &bodies, false).unwrap();
    fs::set_permissions(fixture.target(), fs::Permissions::from_mode(0o755)).unwrap();
    let error = recover(&fixture, &bodies, true).unwrap_err();
    assert_eq!(error.code, Code::InvalidDestination);
    assert_eq!(error.state, State::PublicationUncertain);
    assert_eq!(
        fs::read(fixture.target().join("HEAD")).unwrap(),
        bodies.head
    );
    assert_eq!(
        fs::metadata(fixture.target()).unwrap().mode() & 0o7777,
        0o755
    );

    fs::set_permissions(fixture.target(), fs::Permissions::from_mode(0o700)).unwrap();
    bodies.assert_complete(&fixture.target());
    let error = materialize(&fixture.target(), &bodies.layout(), true, &mut || false).unwrap_err();
    assert_eq!(error.code, Code::Stopped);
    assert_eq!(error.state, State::PublicationUncertain);
    bodies.assert_complete(&fixture.target());
    assert!(recover(&fixture, &bodies, true).unwrap().already_published);
    bodies.assert_complete(&fixture.target());
}

#[test]
fn symlink_and_external_hard_link_refusals_preserve_unrelated_content() {
    let fixture = Fixture::new();
    let bodies = Bodies::new(40);
    recover(&fixture, &bodies, false).unwrap();
    let outside = fixture.0.join("outside");
    fs::hard_link(fixture.target().join("config"), &outside).unwrap();
    assert_eq!(
        recover(&fixture, &bodies, true).unwrap_err().code,
        Code::InvalidFile
    );
    assert_eq!(fs::read(&outside).unwrap(), bodies.config);
    fs::remove_file(&outside).unwrap();
    fs::remove_file(fixture.target().join("config")).unwrap();
    private_write(&outside, b"unrelated bytes");
    symlink(&outside, fixture.target().join("config")).unwrap();
    assert_eq!(
        recover(&fixture, &bodies, true).unwrap_err().code,
        Code::InvalidFile
    );
    assert_eq!(fs::read(&outside).unwrap(), b"unrelated bytes");
}

#[test]
fn directory_substitution_after_staging_is_detected_and_preserved() {
    let fixture = Fixture::new();
    let bodies = Bodies::new(40);
    let mut replaced = false;
    let error = materialize(&fixture.target(), &bodies.layout(), false, &mut || {
        let directory = fixture.target().join("objects/pack");
        if !replaced
            && directory
                .join(format!("{}.pack{PART}", bodies.stem))
                .exists()
        {
            fs::rename(&directory, fixture.0.join("original-pack-directory")).unwrap();
            create_private_directory(&directory).unwrap();
            replaced = true;
        }
        true
    })
    .unwrap_err();
    assert!(replaced);
    assert_eq!(error.code, Code::NamespaceChanged);
    assert!(!fixture.target().join("HEAD").exists());
    assert!(fixture.0.join("original-pack-directory").exists());
}

#[test]
fn permissive_modes_and_non_normal_destinations_refuse() {
    let fixture = Fixture::new();
    let bodies = Bodies::new(40);
    recover(&fixture, &bodies, false).unwrap();
    fs::set_permissions(
        fixture.target().join("config"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert_eq!(
        recover(&fixture, &bodies, true).unwrap_err().code,
        Code::InvalidFile
    );
    fs::set_permissions(
        fixture.target().join("config"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    recover(&fixture, &bodies, true).unwrap();
    let ambiguous = fixture.0.join("new").join(".");
    assert!(materialize(&ambiguous, &bodies.layout(), false, &mut || true).is_err());
    assert!(!fixture.0.join("new").exists());
}
