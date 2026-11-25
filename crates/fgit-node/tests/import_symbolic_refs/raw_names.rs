//! Durable imports retain native reference bytes rather than a text rendering.
use super::*;

const FIRST: &[u8] = b"refs/heads/team-\xff/topic-\xfe";
const SECOND: &[u8] = b"refs/heads/team-\xfe/topic-\xff";

#[derive(Clone, Copy)]
enum RefStorage {
    Packed,
    #[cfg(unix)]
    Loose,
}

fn row(identity: GitOid, reference: &[u8], ending: &[u8]) -> Vec<u8> {
    [identity.to_string().as_bytes(), b" ", reference, ending].concat()
}

fn packed(source: &Source, raw_tip: GitOid) -> Vec<u8> {
    let mut bytes = format!(
        "# pack-refs with: peeled\n{} refs/tags/v1\n^{}\n",
        source.tag, source.commit,
    )
    .into_bytes();
    bytes.extend(row(raw_tip, FIRST, b"\r\n"));
    bytes.extend(row(raw_tip, SECOND, b""));
    bytes
}

#[cfg(unix)]
fn raw_path(root: &Path, reference: &[u8]) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    root.join(std::ffi::OsStr::from_bytes(reference))
}

#[cfg(unix)]
fn write_raw(root: &Path, reference: &[u8], bytes: &[u8]) -> PathBuf {
    let path = raw_path(root, reference);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, bytes).unwrap();
    path
}

fn round_trip(storage: RefStorage) {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let source = Source::new(scratch.0.join("admin.git"), format);
        let checkout = scratch.0.join("checkout");
        write(&checkout, ".git", b"gitdir: ../admin.git\n");
        write(
            &source.root,
            "HEAD",
            [b"ref: ".as_slice(), FIRST, b"\n"].concat(),
        );
        let raw_tip = match storage {
            RefStorage::Packed => source.commit,
            #[cfg(unix)]
            RefStorage::Loose => source.stale,
        };
        write(&source.root, "packed-refs", packed(&source, raw_tip));
        #[cfg(unix)]
        if matches!(storage, RefStorage::Loose) {
            // A stale packed name is shadowed by the exact native loose name.
            // Neither invalid UTF-8 component may be replaced or normalized.
            for reference in [FIRST, SECOND] {
                write_raw(
                    &source.root,
                    reference,
                    format!("{}\n", source.commit).as_bytes(),
                );
            }
        }
        let aliases = [
            ("refs/remotes/origin/HEAD", FIRST),
            ("refs/remotes/origin/other", SECOND),
        ];
        let mut expected = source.refs();
        for reference in [FIRST, SECOND] {
            expected.insert(RefName::try_new(reference).unwrap(), source.commit);
        }
        for (alias, target) in aliases {
            write(
                &source.root,
                alias,
                [b"ref: ".as_slice(), target, b"\n"].concat(),
            );
            expected.insert(name(alias), source.commit);
        }
        assert_eq!(String::from_utf8_lossy(FIRST), String::from_utf8_lossy(SECOND));
        let config = scratch.config(format, "node", 0x72);
        let imported = node(config.clone());
        let first = import(&imported, &checkout).unwrap();
        assert_committed(&first, expected.len());
        let selected = snapshot(&imported);
        assert_eq!(selected.snapshot().refs, expected);
        assert_eq!(
            selected.snapshot().head_target,
            Some(name("refs/heads/main")),
            "the byte-native source HEAD does not rewrite the destination HEAD",
        );
        source.assert_objects(&imported);

        // Repacking and resolving aliases do not change the sealed ref map or
        // publish a second decision under the original idempotency key.
        write(&source.root, "packed-refs", packed(&source, source.commit));
        #[cfg(unix)]
        if matches!(storage, RefStorage::Loose) {
            for reference in [FIRST, SECOND] {
                fs::remove_file(raw_path(&source.root, reference)).unwrap();
            }
        }
        for (alias, _) in aliases {
            write(&source.root, alias, format!("{}\n", source.commit));
        }
        assert_eq!(import(&imported, &checkout).unwrap(), first);
        assert_eq!(snapshot(&imported).basis(), selected.basis());
        let (_, original_bundle) = imported
            .runtime()
            .block_on(imported.export_full_git_bundle_in(
                &imported.request_context(),
                &RefVisibility::new(),
                Some(selected.basis().id()),
            ))
            .unwrap();
        let parsed =
            FullBundleInput::parse(original_bundle.bytes(), Default::default(), &mut || true)
                .unwrap();
        assert_eq!(parsed.format(), format);
        assert_eq!(
            parsed
                .references()
                .iter()
                .map(|reference| (reference.name().clone(), *reference.target()))
                .collect::<BTreeMap<_, _>>(),
            expected,
        );
        parsed
            .verify_pack_framing(&Default::default(), &mut || true)
            .unwrap();
        imported.shutdown().unwrap();
        fs::remove_dir_all(&checkout).unwrap();
        fs::remove_dir_all(&source.root).unwrap();

        let mut reopened = OneNode::open_existing(config).unwrap();
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(snapshot(&reopened).basis(), selected.basis());
        assert_eq!(snapshot(&reopened).snapshot().refs, expected);
        source.assert_objects(&reopened);
        let recovery = reopened
            .runtime()
            .block_on(reopened.recover_transaction_in(&reopened.request_context(), &session()))
            .unwrap();
        assert_eq!(recovery.terminal(), Some(first.commands[0].terminal));
        let (_, bundle) = reopened
            .runtime()
            .block_on(reopened.export_full_git_bundle_in(
                &reopened.request_context(),
                &RefVisibility::new(),
                Some(selected.basis().id()),
            ))
            .unwrap();
        assert_eq!(bundle.bytes(), original_bundle.bytes());
        reopened.shutdown().unwrap();
    }
}

#[test]
fn raw_packed_names_import_export_reopen_and_recover_in_both_hash_domains() {
    round_trip(RefStorage::Packed);
}

#[cfg(unix)]
#[test]
fn raw_loose_names_shadow_packed_refs_and_survive_repacking_in_both_hash_domains() {
    round_trip(RefStorage::Loose);
}

#[test]
fn invalid_raw_packed_refs_and_cancelled_import_leave_the_key_and_authority_unchanged() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let source = Source::new(scratch.0.join("source.git"), format);
        let destination = node(scratch.config(format, "node", 0x72));
        let before = snapshot(&destination);
        let valid = packed(&source, source.commit);
        for bad_name in [
            b"refs/heads/bad-\xff\0".as_slice(),
            b"refs/heads/bad-\xff\t",
            b"refs/heads/bad-\xff..suffix",
            b"refs/heads/bad-\xff.lock",
        ] {
            write(
                &source.root,
                "packed-refs",
                [
                    valid.as_slice(),
                    b"\n",
                    row(source.commit, bad_name, b"\n").as_slice(),
                ]
                .concat(),
            );
            assert!(matches!(
                staging(import(&destination, &source.root).unwrap_err()),
                LooseGitImportRefusal::RefName { .. }
            ));
            assert_unpublished(&destination, &before, &source);
        }
        // Repeated names are still malformed, even when their native IDs agree.
        write(
            &source.root,
            "packed-refs",
            [
                valid.as_slice(),
                b"\n",
                row(source.commit, FIRST, b"\n").as_slice(),
            ]
            .concat(),
        );
        assert!(matches!(
            staging(import(&destination, &source.root).unwrap_err()),
            LooseGitImportRefusal::PackedRefContents(_)
        ));
        assert_unpublished(&destination, &before, &source);

        // Raw name support does not permit raw bytes in native hexadecimal IDs.
        let malformed_identity = vec![0xff; format.digest_len() * 2];
        write(
            &source.root,
            "packed-refs",
            [malformed_identity.as_slice(), b" ", FIRST, b"\n"].concat(),
        );
        assert!(matches!(
            staging(import(&destination, &source.root).unwrap_err()),
            LooseGitImportRefusal::PackedRefContents(_)
        ));
        assert_unpublished(&destination, &before, &source);
        write(&source.root, "packed-refs", &valid);
        let cancelled = destination.import_request_context(None);
        cancelled.cancel();
        let error = destination
            .runtime()
            .block_on(destination.import_loose_git_directory_durable_in(
                &cancelled,
                &source.root,
                PRINCIPAL,
                KEY,
            ))
            .unwrap_err();
        assert!(matches!(
            staging(error),
            LooseGitImportRefusal::Interrupted { .. }
        ));
        assert_unpublished(&destination, &before, &source);

        let accepted = import(&destination, &source.root).unwrap();
        assert_committed(&accepted, 4);
        let mut expected = source.refs();
        expected.insert(RefName::try_new(FIRST).unwrap(), source.commit);
        expected.insert(RefName::try_new(SECOND).unwrap(), source.commit);
        assert_eq!(snapshot(&destination).snapshot().refs, expected);
        source.assert_objects(&destination);
        destination.shutdown().unwrap();
    }
}

#[cfg(unix)]
#[test]
fn raw_loose_names_keep_name_validation_and_filesystem_symlink_refusals() {
    use std::os::unix::fs::symlink;

    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let source = Source::new(scratch.0.join("source.git"), format);
        let destination = node(scratch.config(format, "node", 0x72));
        let before = snapshot(&destination);
        for bad_name in [
            b"refs/heads/bad-\xff\t".as_slice(),
            b"refs/heads/bad-\xff..suffix",
        ] {
            let path = write_raw(
                &source.root,
                bad_name,
                format!("{}\n", source.commit).as_bytes(),
            );
            assert!(matches!(
                staging(import(&destination, &source.root).unwrap_err()),
                LooseGitImportRefusal::RefName { .. }
            ));
            assert_unpublished(&destination, &before, &source);
            fs::remove_file(path).unwrap();
        }
        let path = raw_path(&source.root, FIRST);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        symlink(source.root.join("refs/heads/main"), &path).unwrap();
        assert!(matches!(
            staging(import(&destination, &source.root).unwrap_err()),
            LooseGitImportRefusal::SymbolicLink(_)
        ));
        assert_unpublished(&destination, &before, &source);
        fs::remove_file(path).unwrap();
        write_raw(
            &source.root,
            FIRST,
            format!("{}\n", source.commit).as_bytes(),
        );
        assert_committed(&import(&destination, &source.root).unwrap(), 3);
        let mut expected = source.refs();
        expected.insert(RefName::try_new(FIRST).unwrap(), source.commit);
        assert_eq!(snapshot(&destination).snapshot().refs, expected);
        source.assert_objects(&destination);
        destination.shutdown().unwrap();
    }
}
