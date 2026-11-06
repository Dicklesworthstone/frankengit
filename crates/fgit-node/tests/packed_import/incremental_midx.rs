//! Incremental MIDX files are disposable accelerators. Native import must use
//! the original pack/index pairs and never inspect the accelerator directory.

use super::*;
use std::ffi::OsStr;

fn write_incremental_midx(root: &Path) -> PathBuf {
    let directory = root.join("objects/pack/multi-pack-index.d");
    fs::create_dir_all(directory.join("irrelevant/nested")).unwrap();
    fs::write(
        directory.join("multi-pack-index-chain"),
        b"not a layer checksum\n../../not-an-object-source\n",
    )
    .unwrap();
    fs::write(
        directory.join("multi-pack-index-0000000000000000000000000000000000000000.midx"),
        b"MIDX\0truncated, unusable accelerator",
    )
    .unwrap();
    fs::write(
        directory.join("irrelevant/nested/unpaired.pack"),
        b"never parse this file",
    )
    .unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("missing-layer", directory.join("dangling-layer")).unwrap();
    directory
}

fn import(node: &OneNode, source: &Path) -> AdmissionResult {
    node.runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &node.import_request_context(None),
            source,
            PrincipalId::from_bytes([0xc3; 16]),
            b"incremental-midx-import",
        ))
        .expect("ordinary pack/index pairs import independently of MIDX")
}

#[test]
fn disposable_incremental_midx_preserves_exact_refs_objects_limits_and_retry() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new();
        let source = scratch.0.join("source.git");
        let repository = write_packed_repository_with_format(&source, BlobStorage::Loose, format);
        // Both packs are needed: the first holds the commit and tree, and this
        // second holds their blob. No loose object or MIDX lookup can supply it.
        let blob_hex = repository.blob.to_string();
        fs::remove_file(
            source
                .join("objects")
                .join(&blob_hex[..2])
                .join(&blob_hex[2..]),
        )
        .unwrap();
        let (pack, records) = encode_pack_with_format(
            &[FixtureEntry::Base {
                type_code: 3,
                oid: repository.blob,
                body: repository.blob_body.clone(),
            }],
            format,
        );
        let index =
            encode_index_with_format(&records, &pack[pack.len() - format.digest_len()..], format);
        fs::write(source.join("objects/pack/pack-blob.pack"), pack).unwrap();
        fs::write(source.join("objects/pack/pack-blob.idx"), index).unwrap();

        let baseline_root = scratch.0.join("baseline");
        let baseline = serving_node_with_format(baseline_root.clone(), format);
        let admitted = import(&baseline, &source);
        assert!(matches!(
            admitted.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let expected = imported_state(&baseline, &baseline_root, &repository);
        assert_eq!(
            expected.0,
            BTreeMap::from([(
                RefName::try_new(b"refs/heads/main").unwrap(),
                repository.commit,
            )])
        );
        assert_eq!(
            expected.1,
            BTreeSet::from([repository.commit, repository.tree, repository.blob])
        );
        assert_eq!(expected.2.len(), 3);
        assert_eq!(
            expected.3,
            vec![
                repository.commit_body.clone(),
                repository.tree_body.clone(),
                repository.blob_body.clone(),
            ]
        );
        baseline.shutdown().unwrap();

        let accelerator = write_incremental_midx(&source);
        let node_root = scratch.0.join("with-midx");
        let node = serving_node_with_format(node_root.clone(), format);
        let before = node.runtime().block_on(node.read_authority_head()).unwrap();
        let cancelled = node.import_request_context(None);
        cancelled.cancel();
        assert!(matches!(
            node.runtime().block_on(node.import_loose_git_directory_durable_in(
                &cancelled,
                &source,
                PrincipalId::from_bytes([0xc3; 16]),
                b"incremental-midx-import",
            )),
            Err(NodeSourceImportRefusal::Staging(error))
                if matches!(*error, LooseGitImportRefusal::Interrupted {
                    code: fgit_types::RefusalCode::CancellationInProgress,
                    ..
                })
        ));

        let bytes = (repository.commit_body.len()
            + repository.tree_body.len()
            + repository.blob_body.len()) as u64;
        let request = node
            .import_request_context_with_byte_limit(None, bytes - 1)
            .unwrap();
        assert!(matches!(
            node.runtime().block_on(node.import_loose_git_directory_with_byte_limit_durable_in(
                &request,
                &source,
                PrincipalId::from_bytes([0xc3; 16]),
                b"incremental-midx-import",
                bytes - 1,
            )),
            Err(NodeSourceImportRefusal::Staging(error))
                if matches!(*error, LooseGitImportRefusal::TotalObjectBytesExceeded {
                    limit, observed,
                } if limit == bytes - 1 && observed == bytes)
        ));
        assert_eq!(
            node.runtime().block_on(node.read_authority_head()).unwrap(),
            before
        );
        for oid in [repository.commit, repository.tree, repository.blob] {
            assert!(node.read_git_object(oid).is_err());
        }

        let request = node
            .import_request_context_with_byte_limit(None, bytes)
            .unwrap();
        let accepted = node
            .runtime()
            .block_on(node.import_loose_git_directory_with_byte_limit_durable_in(
                &request,
                &source,
                PrincipalId::from_bytes([0xc3; 16]),
                b"incremental-midx-import",
                bytes,
            ))
            .unwrap();
        assert_eq!(accepted.commands.len(), 1);
        assert!(matches!(
            accepted.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert_eq!(imported_state(&node, &node_root, &repository), expected);
        let head = node.runtime().block_on(node.read_authority_head()).unwrap();
        fs::remove_dir_all(accelerator).unwrap();
        assert_eq!(import(&node, &source), accepted);
        assert_eq!(
            node.runtime().block_on(node.read_authority_head()).unwrap(),
            head
        );
        assert_eq!(imported_state(&node, &node_root, &repository), expected);
        node.shutdown().unwrap();
    }
}

#[test]
fn other_pack_directories_and_accelerator_file_types_remain_refused() {
    for name in [
        "unrecognized",
        "multi-pack-index.d.backup",
        "multi-pack-index",
        "pack.bitmap",
    ] {
        assert_source_refusal(
            |repository| {
                write_incremental_midx(&repository.root);
                fs::create_dir(repository.root.join("objects/pack").join(name)).unwrap();
            },
            |refusal| {
                matches!(refusal, LooseGitImportRefusal::PathKind {
                expected: "regular pack-directory file", path,
            } if path.file_name() == Some(OsStr::new(name)))
            },
        );
    }
    for name in ["multi-pack-index.d", "multi-pack-index-layer.midx"] {
        assert_source_refusal(
            |repository| {
                fs::write(
                    repository.root.join("objects/pack").join(name),
                    b"not a directory",
                )
                .unwrap();
            },
            |refusal| {
                matches!(refusal, LooseGitImportRefusal::PackDirectoryEntryUnsupported(path)
                if path.file_name() == Some(OsStr::new(name)))
            },
        );
    }
}

#[cfg(unix)]
#[test]
fn incremental_midx_symlinks_and_fifos_refuse_without_publication() {
    for dangling in [false, true] {
        assert_source_refusal(
            |repository| {
                let outside = repository.root.join("outside-accelerator");
                if !dangling {
                    fs::create_dir(&outside).unwrap();
                }
                std::os::unix::fs::symlink(
                    outside,
                    repository.root.join("objects/pack/multi-pack-index.d"),
                )
                .unwrap();
            },
            |refusal| {
                matches!(refusal, LooseGitImportRefusal::SymbolicLink(path)
                if path.file_name() == Some(OsStr::new("multi-pack-index.d")))
            },
        );
    }
    #[cfg(target_os = "linux")]
    {
        assert_source_refusal(
            |repository| {
                rustix::fs::mkfifoat(
                    rustix::fs::CWD,
                    repository.root.join("objects/pack/multi-pack-index.d"),
                    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                )
                .unwrap();
            },
            |refusal| {
                matches!(refusal, LooseGitImportRefusal::PathKind {
                expected: "regular pack-directory file", path,
            } if path.file_name() == Some(OsStr::new("multi-pack-index.d")))
            },
        );
    }
}

#[test]
fn incremental_midx_never_substitutes_for_a_verified_pack_index_pair() {
    for damage in ["index-checksum", "pack-checksum", "missing-index"] {
        assert_source_refusal(
            |repository| {
                write_incremental_midx(&repository.root);
                if damage == "missing-index" {
                    fs::remove_file(&repository.index_path).unwrap();
                } else {
                    let path = if damage == "index-checksum" {
                        &repository.index_path
                    } else {
                        &repository.pack_path
                    };
                    let mut bytes = fs::read(path).unwrap();
                    *bytes.last_mut().unwrap() ^= 1;
                    fs::write(path, bytes).unwrap();
                }
            },
            |refusal| match (damage, refusal) {
                ("missing-index", LooseGitImportRefusal::PackPairMissing(_)) => true,
                ("index-checksum", LooseGitImportRefusal::PackedObject { source, .. }) => {
                    matches!(**source, PackError::IndexChecksumMismatch)
                }
                ("pack-checksum", LooseGitImportRefusal::PackedObject { source, .. }) => {
                    matches!(**source, PackError::TrailerChecksumMismatch)
                }
                _ => false,
            },
        );
    }
}
