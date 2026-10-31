#![forbid(unsafe_code)]
#![cfg(unix)]
//! Real commands cross the old 32 MiB per-object export/import ceiling in both
//! native hash domains. The source enters through durable native loose import;
//! the destination receives the actual exported bundle through file custody.
//! No foreign executable is available to fg.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_crypto::{GitObjectKind, git_object_id, lowercase_hex, sha256_digest};
use fgit_node::{NodeConfig, OneNode};
use fgit_pack::full_bundle::{FullBundleHeader, FullBundleLimits};
use fgit_pack::{PackLimits, object_type_from_base_entry, read_streamed_pack};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, PrincipalId, RefName, RepositoryId, TenantId,
};

const TENANT: &str = "11111111111111111111111111111111";
const REPOSITORY: &str = "22222222222222222222222222222222";
const PRINCIPAL: &str = "33333333333333333333333333333333";
const MIB: usize = 1024 * 1024;
const BLOB_BYTES: usize = 33 * MIB;
const BLOB_BYTE: u8 = b'q';

struct Fixture {
    root: PathBuf,
    format: GitHashAlgorithm,
    base: GitOid,
    tip: GitOid,
    blob: GitOid,
    full: BTreeMap<GitOid, Option<Vec<u8>>>,
    incremental: BTreeMap<GitOid, Option<Vec<u8>>>,
}

impl Fixture {
    fn new(format: GitHashAlgorithm) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "fg-stream-export-large-blob-{}-{}-{}-{}",
            format.as_str(),
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(root.join("no-executables")).unwrap();
        fs::create_dir(root.join("scratch")).unwrap();
        fs::set_permissions(root.join("scratch"), fs::Permissions::from_mode(0o700)).unwrap();
        let source = root.join("source.git");
        fs::create_dir_all(source.join("refs/heads")).unwrap();
        fs::write(source.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::write(source.join("config"), match format {
            GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
            GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
        }).unwrap();

        let empty_tree = loose(&source, format, GitObjectKind::Tree, b"");
        let base_body = commit(empty_tree, None);
        let base = loose(&source, format, GitObjectKind::Commit, &base_body);
        let blob = loose(
            &source,
            format,
            GitObjectKind::Blob,
            &vec![BLOB_BYTE; BLOB_BYTES],
        );
        let mut tree_body = b"100644 large.bin\0".to_vec();
        tree_body.extend_from_slice(blob.as_bytes());
        let tree = loose(&source, format, GitObjectKind::Tree, &tree_body);
        let tip_body = commit(tree, Some(base));
        let tip = loose(&source, format, GitObjectKind::Commit, &tip_body);
        fs::write(source.join("refs/heads/main"), format!("{tip}\n")).unwrap();

        let (mut node, _) = OneNode::init(
            NodeConfig::new(
                root.join("node"),
                TenantId::from_bytes([0x11; 16]),
                RepositoryId::from_bytes([0x22; 16]),
            )
            .with_object_format(format)
            .with_max_object_bytes((64 * MIB) as u64)
            .with_worker_threads(2),
        )
        .unwrap();
        let selected = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        node.bring_into_service(selected.receipt().generation())
            .unwrap();
        let request = node.import_request_context(None);
        let imported = node
            .runtime()
            .block_on(node.import_loose_git_directory_durable_in(
                &request,
                &source,
                PrincipalId::from_bytes([0x33; 16]),
                b"large-blob-stream-export-fixture",
            ))
            .unwrap();
        assert_eq!(imported.commands.len(), 1);
        assert!(matches!(
            imported.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        node.shutdown().unwrap();

        let incremental =
            BTreeMap::from([(blob, None), (tree, Some(tree_body)), (tip, Some(tip_body))]);
        let mut full = incremental.clone();
        full.insert(empty_tree, Some(Vec::new()));
        full.insert(base, Some(base_body));
        Self {
            root,
            format,
            base,
            tip,
            blob,
            full,
            incremental,
        }
    }

    fn run(&self, args: &[String]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_fg"))
            .args(["--timeout-secs", "600"])
            .args(args)
            .current_dir(&self.root)
            .env_clear()
            .env("PATH", self.root.join("no-executables"))
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    fn refs(&self) -> String {
        self.refs_at("node")
    }

    fn refs_at(&self, storage: &str) -> String {
        success(self.run(&args(&[
            "refs",
            storage,
            TENANT,
            REPOSITORY,
            "--trusted-local",
            "--object-format",
            self.format.as_str(),
        ])))
    }

    fn import(&self, bundle: &str, file_backed: bool, extra: &[&str]) -> Output {
        let mut values = args(&[
            "bundle",
            "import",
            "receiver",
            TENANT,
            REPOSITORY,
            bundle,
            "--trusted-local",
            "--object-format",
            self.format.as_str(),
            "--principal",
            PRINCIPAL,
            "--idempotency-key",
            "native-file-blob-transfer",
        ]);
        if file_backed {
            values.push("--file-backed".to_owned());
        }
        values.extend(args(extra));
        self.run(&values)
    }

    fn assert_receiver_staging_empty(&self) {
        assert_eq!(
            fs::read_dir(self.root.join("receiver/staging"))
                .unwrap()
                .count(),
            0,
            "file import must settle private payload and scratch custody"
        );
    }

    fn fetch(
        &self,
        bundle: &str,
        key: &str,
        file_backed: bool,
        mappings: &[&str],
        extra: &[&str],
    ) -> Output {
        let mut values = args(&[
            "bundle",
            "fetch",
            "fetcher",
            TENANT,
            REPOSITORY,
            bundle,
            "--trusted-local",
            "--object-format",
            self.format.as_str(),
            "--principal",
            PRINCIPAL,
            "--idempotency-key",
            key,
        ]);
        if file_backed {
            values.push("--file-backed".to_owned());
        }
        values.extend(args(mappings));
        values.extend(args(extra));
        self.run(&values)
    }

    fn assert_file_fetch(&self, bundle: &str) {
        success(self.run(&args(&[
            "init",
            "fetcher",
            TENANT,
            REPOSITORY,
            self.format.as_str(),
        ])));
        let empty = self.refs_at("fetcher");
        let raw = fs::read(self.root.join(bundle)).unwrap();
        let at = raw.windows(2).position(|pair| pair == b"\n\n").unwrap() + 2;
        let signature = match self.format {
            GitHashAlgorithm::Sha1 => "# v2 git bundle\n",
            GitHashAlgorithm::Sha256 => "# v3 git bundle\n@object-format=sha256\n",
        };
        let header = format!("{signature}{} refs/heads/main\n\n", self.base);
        let seed = "mapped-base.bundle";
        // Narrow the advertisement, retaining the complete valid native pack.
        // Intake must verify even its unselected large payload without placing it.
        fs::write(
            self.root.join(seed),
            [header.as_bytes(), &raw[at..]].concat(),
        )
        .unwrap();
        let policy = [
            "--max-object-mib",
            "1",
            "--max-blob-mib",
            "40",
            "--timeout-secs",
            "600",
        ];
        let initial = [
            "--map",
            "refs/heads/main",
            "refs/remotes/upstream/main",
            "absent",
        ];
        let seeded = success(self.fetch(seed, "mapped-seed", true, &initial, &policy));
        assert!(seeded.contains("\"type\":\"git_bundle_fetch\""), "{seeded}");
        assert!(seeded.contains("\"reference_count\":1"), "{seeded}");
        let before = self.refs_at("fetcher");
        assert_ne!(before, empty);
        let source_hex = lowercase_hex(b"refs/heads/main");
        let tracking_hex = lowercase_hex(b"refs/remotes/upstream/main");
        let raw_ref = RefName::try_new(b"refs/remotes/upstream/\xff").unwrap();
        let raw_hex = lowercase_hex(raw_ref.as_bytes());
        assert!(
            before.contains(&format!(
                "{{\"reference_hex\":\"{tracking_hex}\",\"tip\":\"{}\"}}",
                self.base,
            )),
            "{before}"
        );
        let node = OneNode::open_existing(
            NodeConfig::new(
                self.root.join("fetcher"),
                TenantId::from_bytes([0x11; 16]),
                RepositoryId::from_bytes([0x22; 16]),
            )
            .with_object_format(self.format)
            .with_max_object_bytes(MIB as u64)
            .with_bundle_import_blob_limit(40 * MIB)
            .with_worker_threads(2),
        )
        .unwrap();
        let request = node.import_request_context(None);
        let selected = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        assert_eq!(selected.selected_closure().closure().objects().len(), 2);
        for id in [self.tip, self.blob] {
            assert!(matches!(node.git_object_header(id),
                Err(fgit_node::NodeRefusal::Fabric(error))
                    if matches!(*error, fgit_object_fabric::fabric::StoreRefusal::ObjectAbsent)));
        }
        node.shutdown().unwrap();
        let base = self.base.to_string();
        let mappings = [
            "--map",
            "refs/heads/main",
            "refs/remotes/upstream/main",
            base.as_str(),
            "--map-hex",
            source_hex.as_str(),
            raw_hex.as_str(),
            "absent",
        ];
        refused(self.fetch(bundle, "mapped-update", true, &mappings, &[]));
        assert_eq!(self.refs_at("fetcher"), before);
        assert_eq!(
            fs::read_dir(self.root.join("fetcher/staging"))
                .unwrap()
                .count(),
            0
        );
        let updated = success(self.fetch(bundle, "mapped-update", true, &mappings, &policy));
        for required in [
            "\"type\":\"git_bundle_fetch\"",
            "\"outcome\":\"committed\"",
            "\"command_committed\":true",
            "\"atomic\":true",
            "\"reference_count\":2",
            "\"node_closed\":true",
            "\"cleanup_error\":null",
        ] {
            assert!(updated.contains(required), "{updated}");
        }
        let assert_mapped = |report: &str| {
            for name in [&tracking_hex, &raw_hex] {
                assert!(
                    report.contains(&format!(
                        "{{\"reference_hex\":\"{name}\",\"tip\":\"{}\"}}",
                        self.tip,
                    )),
                    "{report}"
                );
            }
            assert_eq!(report.matches("\"reference_hex\":").count(), 2, "{report}");
        };
        let committed = self.refs_at("fetcher");
        assert_mapped(&committed);
        self.assert_native_objects_at(
            "fetcher",
            &[
                (
                    RefName::try_new(b"refs/remotes/upstream/main").unwrap(),
                    self.tip,
                ),
                (raw_ref, self.tip),
            ],
        );
        // The one sealed mapped update survives the smaller default blob limit
        // and a retry through the buffered transport profile.
        assert_eq!(
            success(self.fetch(bundle, "mapped-update", true, &mappings, &[])),
            updated
        );
        assert_eq!(
            success(self.fetch(bundle, "mapped-update", false, &mappings, &[])),
            updated
        );
        assert_eq!(self.refs_at("fetcher"), committed);

        let stale = [
            "--map",
            "refs/heads/main",
            "refs/remotes/upstream/main",
            base.as_str(),
            "--map",
            "refs/heads/main",
            "refs/heads/partial",
            "absent",
        ];
        let output = self.fetch(bundle, "mapped-stale", true, &stale, &policy);
        assert_eq!(
            output.status.code(),
            Some(3),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let refusal = String::from_utf8(output.stdout).unwrap();
        assert!(refusal.contains("\"outcome\":\"refused\""), "{refusal}");
        assert!(
            refusal.contains("\"refusal_code\":\"ExpectedOldRefMismatch\""),
            "{refusal}"
        );
        let after_refusal = self.refs_at("fetcher");
        assert_mapped(&after_refusal);
        assert!(!after_refusal.contains(&lowercase_hex(b"refs/heads/partial")));
        let replay = self.fetch(bundle, "mapped-stale", false, &stale, &[]);
        assert_eq!(replay.status.code(), Some(3));
        assert_eq!(String::from_utf8(replay.stdout).unwrap(), refusal);
        assert_eq!(self.refs_at("fetcher"), after_refusal);

        let tip = self.tip.to_string();
        let rewind = [
            "--map",
            "refs/heads/main",
            "refs/remotes/upstream/main",
            tip.as_str(),
        ];
        refused(self.fetch(seed, "mapped-rewind", true, &rewind, &policy));
        assert_eq!(self.refs_at("fetcher"), after_refusal);
        assert_eq!(
            fs::read_dir(self.root.join("fetcher/staging"))
                .unwrap()
                .count(),
            0
        );
        self.assert_clean();
    }

    fn assert_full_import(&self, bundle: &str) {
        success(self.run(&args(&[
            "init",
            "receiver",
            TENANT,
            REPOSITORY,
            self.format.as_str(),
        ])));
        let empty = self.refs_at("receiver");
        refused(self.import(bundle, true, &[]));
        assert_eq!(self.refs_at("receiver"), empty);
        self.assert_receiver_staging_empty();
        self.assert_clean();

        let accepted = success(self.import(
            bundle,
            true,
            &[
                "--max-object-mib",
                "1",
                "--max-blob-mib",
                "40",
                "--timeout-secs",
                "600",
            ],
        ));
        for required in [
            "\"type\":\"git_bundle_import\"",
            "\"outcome\":\"committed\"",
            "\"command_committed\":true",
            "\"atomic\":true",
            "\"reference_count\":1",
            "\"node_closed\":true",
            "\"cleanup_error\":null",
        ] {
            assert!(accepted.contains(required), "{accepted}");
        }
        self.assert_receiver_staging_empty();
        self.assert_received_native_objects();
        let committed = self.refs_at("receiver");
        assert_ne!(committed, empty);
        let reference = format!(
            "{{\"reference_hex\":\"{}\",\"tip\":\"{}\"}}",
            lowercase_hex(b"refs/heads/main"),
            self.tip
        );
        assert!(committed.contains(&reference), "{committed}");
        assert_eq!(committed.matches("\"reference_hex\":").count(), 1);

        // The same exact mutation/key recovers its terminal outcome even with
        // today's smaller default blob allowance or the buffered intake profile.
        assert_eq!(success(self.import(bundle, true, &[])), accepted);
        assert_eq!(success(self.import(bundle, false, &[])), accepted);
        assert_eq!(self.refs_at("receiver"), committed);
        self.assert_receiver_staging_empty();
        self.assert_clean();
    }

    fn sync_import(
        &self,
        bundle: &str,
        key: &str,
        file_backed: bool,
        expectation: &str,
        extra: &[&str],
    ) -> Output {
        let mut values = args(&[
            "bundle",
            "sync-import",
            "syncer",
            TENANT,
            REPOSITORY,
            bundle,
            "--trusted-local",
            "--object-format",
            self.format.as_str(),
            "--principal",
            PRINCIPAL,
            "--idempotency-key",
            key,
            "--allow-ref-updates",
            "--expect",
            expectation,
        ]);
        if file_backed {
            values.push("--file-backed".into());
        }
        values.extend(args(extra));
        self.run(&values)
    }

    fn assert_sync_staging_empty(&self) {
        assert_eq!(
            fs::read_dir(self.root.join("syncer/staging"))
                .unwrap()
                .count(),
            0,
            "incremental import must settle original and uploaded custody",
        );
    }

    fn assert_incremental_import(&self, bundle: &str) {
        // Seed only the real prerequisite history through native durable import.
        // The receiving node initially has neither the large blob nor its tip.
        let source = self.root.join("sync-base.git");
        fs::create_dir_all(source.join("refs/heads")).unwrap();
        fs::write(source.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::copy(self.root.join("source.git/config"), source.join("config")).unwrap();
        let tree = loose(&source, self.format, GitObjectKind::Tree, b"");
        assert!(self.full.contains_key(&tree));
        let base = loose(
            &source,
            self.format,
            GitObjectKind::Commit,
            self.full[&self.base].as_ref().unwrap(),
        );
        assert_eq!(base, self.base);
        fs::write(source.join("refs/heads/main"), format!("{base}\n")).unwrap();
        let (mut node, _) = OneNode::init(
            NodeConfig::new(
                self.root.join("syncer"),
                TenantId::from_bytes([0x11; 16]),
                RepositoryId::from_bytes([0x22; 16]),
            )
            .with_object_format(self.format)
            .with_worker_threads(2),
        )
        .unwrap();
        let current = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        node.bring_into_service(current.receipt().generation())
            .unwrap();
        let request = node.import_request_context(None);
        let seeded = node
            .runtime()
            .block_on(node.import_loose_git_directory_durable_in(
                &request,
                &source,
                PrincipalId::from_bytes([0x33; 16]),
                b"incremental-large-original-seed",
            ))
            .unwrap();
        assert!(matches!(
            seeded.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert!(node.read_git_object(self.blob).is_err());
        node.shutdown().unwrap();

        let before = self.refs_at("syncer");
        let expected = format!("refs/heads/main={}", self.base);
        for limits in [
            vec![],
            vec![
                "--max-object-mib",
                "1",
                "--max-blob-mib",
                "40",
                "--max-expanded-mib",
                "32",
            ],
        ] {
            refused(self.sync_import(bundle, "large-incremental-upload", true, &expected, &limits));
            assert_eq!(self.refs_at("syncer"), before);
            self.assert_sync_staging_empty();
        }
        let accepted = success(self.sync_import(
            bundle,
            "large-incremental-upload",
            true,
            &expected,
            &[
                "--max-object-mib",
                "1",
                "--max-blob-mib",
                "40",
                "--max-expanded-mib",
                "40",
                "--max-original-mib",
                "1",
                "--timeout-secs",
                "600",
            ],
        ));
        for required in [
            "\"type\":\"git_bundle_import\"",
            "\"outcome\":\"committed\"",
            "\"atomic\":true",
            "\"reference_count\":1",
            "\"node_closed\":true",
            "\"cleanup_error\":null",
        ] {
            assert!(accepted.contains(required), "{accepted}");
        }
        self.assert_native_objects_at(
            "syncer",
            &[(RefName::try_new(b"refs/heads/main").unwrap(), self.tip)],
        );
        self.assert_sync_staging_empty();
        let committed = self.refs_at("syncer");
        assert_ne!(committed, before);
        // Cross-profile terminal recovery precedes fresh blob and original limits.
        assert_eq!(
            success(self.sync_import(bundle, "large-incremental-upload", true, &expected, &[])),
            accepted,
        );
        assert_eq!(
            success(self.sync_import(bundle, "large-incremental-upload", false, &expected, &[])),
            accepted,
        );

        // A zero-entry incremental pack must still authenticate all 33 MiB of
        // original blob data before a fresh operation may reuse the history.
        let zero_name = "large-original-only.bundle";
        let report = success(self.run(&args(&[
            "bundle",
            "sync-export",
            "node",
            TENANT,
            REPOSITORY,
            zero_name,
            "--streaming",
            "--trusted-local",
            "--object-format",
            self.format.as_str(),
            "--ref",
            "refs/heads/main",
            "--prerequisite",
            &self.tip.to_string(),
            "--max-object-mib",
            "1",
            "--max-blob-mib",
            "40",
            "--max-expanded-mib",
            "1",
            "--max-output-mib",
            "1",
            "--timeout-secs",
            "600",
        ])));
        assert!(report.contains("\"object_count\":0,"), "{report}");
        let mut raw = fs::read(self.root.join(zero_name)).unwrap();
        let boundary = raw.windows(2).position(|pair| pair == b"\n\n").unwrap() + 2;
        let header = std::str::from_utf8(&raw[..boundary])
            .unwrap()
            .replace(" refs/heads/main\n", " refs/heads/copied\n");
        assert!(header.contains(" refs/heads/copied\n"));
        let pack = raw.split_off(boundary);
        raw = header.into_bytes();
        raw.extend_from_slice(&pack);
        fs::write(self.root.join(zero_name), raw).unwrap();

        for limits in [
            vec![
                "--max-object-mib",
                "1",
                "--max-blob-mib",
                "40",
                "--max-original-mib",
                "32",
                "--max-expanded-mib",
                "1",
            ],
            vec![
                "--max-object-mib",
                "1",
                "--max-blob-mib",
                "32",
                "--max-original-mib",
                "40",
                "--max-expanded-mib",
                "1",
            ],
        ] {
            refused(self.sync_import(
                zero_name,
                "borrow-large-original",
                true,
                "refs/heads/copied=absent",
                &limits,
            ));
            assert_eq!(self.refs_at("syncer"), committed);
            self.assert_sync_staging_empty();
        }
        let borrowed = success(self.sync_import(
            zero_name,
            "borrow-large-original",
            true,
            "refs/heads/copied=absent",
            &[
                "--max-object-mib",
                "1",
                "--max-blob-mib",
                "40",
                "--max-original-mib",
                "40",
                "--max-expanded-mib",
                "1",
                "--timeout-secs",
                "600",
            ],
        ));
        assert!(borrowed.contains("\"outcome\":\"committed\""), "{borrowed}");
        self.assert_native_objects_at(
            "syncer",
            &[
                (RefName::try_new(b"refs/heads/main").unwrap(), self.tip),
                (RefName::try_new(b"refs/heads/copied").unwrap(), self.tip),
            ],
        );
        assert_eq!(
            success(self.sync_import(
                zero_name,
                "borrow-large-original",
                true,
                "refs/heads/copied=absent",
                &["--max-original-mib", "1", "--max-blob-mib", "1"],
            )),
            borrowed
        );
        assert_eq!(
            success(self.sync_import(
                zero_name,
                "borrow-large-original",
                false,
                "refs/heads/copied=absent",
                &[],
            )),
            borrowed
        );
        self.assert_sync_staging_empty();
        self.assert_clean();
    }

    fn assert_received_native_objects(&self) {
        self.assert_native_objects_at(
            "receiver",
            &[(RefName::try_new(b"refs/heads/main").unwrap(), self.tip)],
        );
    }

    fn assert_native_objects_at(&self, storage: &str, expected_refs: &[(RefName, GitOid)]) {
        let node = OneNode::open_existing(
            NodeConfig::new(
                self.root.join(storage),
                TenantId::from_bytes([0x11; 16]),
                RepositoryId::from_bytes([0x22; 16]),
            )
            .with_object_format(self.format)
            .with_max_object_bytes(MIB as u64)
            .with_bundle_import_blob_limit(40 * MIB)
            .with_worker_threads(2),
        )
        .unwrap();
        let request = node.import_request_context(None);
        let materialized = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        assert_eq!(
            materialized.snapshot().refs,
            expected_refs.iter().cloned().collect::<BTreeMap<_, _>>(),
        );
        assert_eq!(
            materialized.selected_closure().closure().objects(),
            &self.full.keys().copied().collect::<BTreeSet<_>>()
        );
        for (identity, expected) in &self.full {
            if let Some(body) = expected {
                let object = node.read_git_object(*identity).unwrap();
                assert_eq!(object.identity(), *identity);
                assert_eq!(object.payload(), body);
            }
        }
        assert!(node.read_git_object(self.blob).is_err());
        let mut blob = node
            .open_git_blob_stream(self.blob, BLOB_BYTES as u64)
            .unwrap();
        let mut buffer = [0_u8; 64 * 1024];
        let mut received = 0;
        loop {
            let count = blob.read_tentative(&mut buffer).unwrap();
            if count == 0 {
                break;
            }
            assert!(buffer[..count].iter().all(|byte| *byte == BLOB_BYTE));
            received += count;
        }
        assert_eq!(received, BLOB_BYTES);
        assert!(blob.is_verified());
        drop(blob);
        node.shutdown().unwrap();
    }

    fn export(&self, name: &str, incremental: bool, extra: &[&str]) -> Output {
        let mut values = args(&[
            "bundle",
            if incremental { "sync-export" } else { "export" },
            "node",
            TENANT,
            REPOSITORY,
            name,
            "--streaming",
            "--trusted-local",
            "--object-format",
            self.format.as_str(),
            "--timeout-secs",
            "600",
            "--max-compression-work",
            "4000000000",
        ]);
        if incremental {
            values.extend(args(&[
                "--ref",
                "refs/heads/main",
                "--prerequisite",
                &self.base.to_string(),
            ]));
        }
        values.extend(args(extra));
        self.run(&values)
    }

    fn assert_clean(&self) {
        assert_eq!(fs::read_dir(self.root.join("scratch")).unwrap().count(), 0);
        for entry in fs::read_dir(&self.root).unwrap() {
            let name = entry.unwrap().file_name();
            assert!(
                !name.to_string_lossy().starts_with(".fg-stream-export-"),
                "{name:?}"
            );
        }
    }

    fn assert_bundle(&self, name: &str, incremental: bool) -> GitOid {
        let mut input = BufReader::new(File::open(self.root.join(name)).unwrap());
        let header = if incremental {
            FullBundleHeader::read_incremental(&mut input, FullBundleLimits::default(), &mut || {
                true
            })
        } else {
            FullBundleHeader::read(&mut input, FullBundleLimits::default(), &mut || true)
        }
        .unwrap();
        assert_eq!(header.format(), self.format);
        assert_eq!(header.references().len(), 1);
        assert_eq!(header.references()[0].name().as_bytes(), b"refs/heads/main");
        assert_eq!(*header.references()[0].target(), self.tip);
        assert_eq!(
            header.head(),
            if incremental { None } else { Some(self.tip) }
        );
        assert_eq!(
            header.prerequisites(),
            if incremental {
                std::slice::from_ref(&self.base)
            } else {
                &[]
            }
        );
        self.assert_pack(
            &mut input,
            if incremental {
                &self.incremental
            } else {
                &self.full
            },
        )
    }

    fn assert_pack(
        &self,
        input: &mut impl BufRead,
        expected: &BTreeMap<GitOid, Option<Vec<u8>>>,
    ) -> GitOid {
        // The oracle reads one bounded object at a time, independently of the
        // exporter's blob reader and its metadata-allocation ceiling.
        let limits = PackLimits {
            max_object_bytes: 40 * MIB,
            ..PackLimits::default()
        };
        let mut seen = BTreeSet::new();
        let receipt = read_streamed_pack(
            input,
            self.format,
            &limits,
            &mut || true,
            |entry| -> Result<(), io::Error> {
                let kind = object_type_from_base_entry(entry.entry.header.kind).unwrap();
                let body = entry.entry.inflated;
                let id = git_object_id(self.format, kind, &body);
                match expected
                    .get(&id)
                    .expect("only the expected native inventory may be exported")
                {
                    Some(bytes) => assert_eq!(&body, bytes),
                    None => {
                        assert_eq!(id, self.blob);
                        assert_eq!(kind, GitObjectKind::Blob);
                        assert_eq!(body.len(), BLOB_BYTES);
                        assert!(body.iter().all(|byte| *byte == BLOB_BYTE));
                    }
                }
                assert!(seen.insert(id), "duplicate native object");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(seen, expected.keys().copied().collect());
        assert_eq!(receipt.header().object_count as usize, expected.len());
        receipt.trailer()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn success(output: Output) -> String {
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = String::from_utf8(output.stdout).unwrap();
    assert_eq!(report.lines().count(), 1, "{report}");
    report
}

fn refused(output: Output) {
    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("\"type\":\"bundle_error\""));
}

fn commit(tree: GitOid, parent: Option<GitOid>) -> Vec<u8> {
    let parent = parent.map_or_else(String::new, |id| format!("parent {id}\n"));
    format!("tree {tree}\n{parent}author Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nlarge blob export\n").into_bytes()
}

/// Native loose framing plus bounded stored DEFLATE blocks avoids relying on
/// either the exporter or a foreign compressor to create the admitted source.
fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, body);
    let text = id.to_string();
    let directory = root.join("objects").join(&text[..2]);
    fs::create_dir_all(&directory).unwrap();
    let mut output = File::create(directory.join(&text[2..])).unwrap();
    output.write_all(&[0x78, 0x01]).unwrap();
    let mut adler = (1_u32, 0_u32);
    let prefix = format!("{} {}\0", kind.label(), body.len());
    stored_block(&mut output, prefix.as_bytes(), body.is_empty(), &mut adler);
    let mut chunks = body.chunks(u16::MAX as usize).peekable();
    while let Some(chunk) = chunks.next() {
        stored_block(&mut output, chunk, chunks.peek().is_none(), &mut adler);
    }
    output
        .write_all(&((adler.1 << 16) | adler.0).to_be_bytes())
        .unwrap();
    id
}

fn stored_block(output: &mut File, bytes: &[u8], last: bool, adler: &mut (u32, u32)) {
    let length = u16::try_from(bytes.len()).unwrap();
    output.write_all(&[u8::from(last)]).unwrap();
    output.write_all(&length.to_le_bytes()).unwrap();
    output.write_all(&(!length).to_le_bytes()).unwrap();
    output.write_all(bytes).unwrap();
    for byte in bytes {
        adler.0 = (adler.0 + u32::from(*byte)) % 65_521;
        adler.1 = (adler.1 + adler.0) % 65_521;
    }
}

#[test]
fn both_domains_export_a_33_mib_blob_without_widening_metadata_and_recover_exact_bytes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let before = fixture.refs();
        for incremental in [false, true] {
            for (name, extra) in [
                ("default-refused.bundle", vec![]),
                (
                    "blob-refused.bundle",
                    vec!["--max-object-mib", "1", "--max-blob-mib", "32"],
                ),
                (
                    "total-refused.bundle",
                    vec![
                        "--max-object-mib",
                        "1",
                        "--max-blob-mib",
                        "40",
                        "--max-expanded-mib",
                        "32",
                    ],
                ),
            ] {
                refused(fixture.export(name, incremental, &extra));
                assert!(!fixture.root.join(name).exists());
                fixture.assert_clean();
                assert_eq!(fixture.refs(), before);
            }
            let name = if incremental {
                "incremental.bundle"
            } else {
                "full.bundle"
            };
            let extra = ["--max-object-mib", "1", "--max-blob-mib", "40"];
            let report = success(fixture.export(name, incremental, &extra));
            for required in [
                "\"streaming\":true",
                "\"publication_state\":\"durable\"",
                "\"node_closed\":true",
                "\"repository_changed\":false",
            ] {
                assert!(report.contains(required), "{report}");
            }
            let objects = if incremental { 3 } else { 5 };
            assert!(
                report.contains(&format!("\"object_count\":{objects},")),
                "{report}"
            );
            if incremental {
                assert!(report.contains("\"prerequisite_count\":1,"), "{report}");
                assert!(report.contains("\"external_object_count\":2}"), "{report}");
            }
            let checksum = fixture.assert_bundle(name, incremental);
            assert!(report.contains(&format!("\"pack_checksum\":\"{checksum}\"")));
            let path = fixture.root.join(name);
            assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
            let bytes = fs::read(&path).unwrap();
            let digest = lowercase_hex(&sha256_digest(&bytes));
            assert!(report.contains(&format!("\"bundle_sha256\":\"{digest}\"")));
            let repeat = format!("again-{name}");
            assert_eq!(
                success(fixture.export(&repeat, incremental, &extra)),
                report
            );
            assert_eq!(fs::read(fixture.root.join(repeat)).unwrap(), bytes);
            fixture.assert_clean();
            assert_eq!(fixture.refs(), before);

            if incremental {
                fixture.assert_incremental_import(name);
                continue;
            }
            fixture.assert_full_import(name);
            fixture.assert_file_fetch(name);
            let pins = args(&[
                "--file-backed",
                "--scratch-dir",
                "scratch",
                "--max-blob-mib",
                "40",
                "--expect-sha256",
                &digest,
                "--expect-format",
                format.as_str(),
                "--expect-ref",
                &format!("refs/heads/main={}", fixture.tip),
                "--exact-refs",
                "--timeout-secs",
                "600",
            ]);
            let mut verify = args(&["bundle", "verify", name]);
            verify.extend(pins.clone());
            let verified = success(fixture.run(&verify));
            assert!(verified.contains("\"object_graph_verified\":true"));
            assert!(verified.contains("\"caller_expectations_matched\":true"));
            fixture.assert_clean();
            let mut recover = args(&[
                "bundle",
                "recover",
                name,
                "restored.git",
                "--trusted-local",
                "--head-ref",
                "refs/heads/main",
            ]);
            recover.extend(pins);
            let recovered = success(fixture.run(&recover));
            assert!(recovered.contains("\"state\":\"durable\""));
            assert!(recovered.contains(&format!("\"pack_checksum\":\"{checksum}\"")));
            assert_eq!(
                fs::read(fixture.root.join("restored.git/HEAD")).unwrap(),
                b"ref: refs/heads/main\n"
            );
            let packed_refs =
                fs::read_to_string(fixture.root.join("restored.git/packed-refs")).unwrap();
            assert!(
                packed_refs
                    .lines()
                    .any(|line| line == format!("{} refs/heads/main", fixture.tip))
            );
            let packs: Vec<_> = fs::read_dir(fixture.root.join("restored.git/objects/pack"))
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| {
                    path.extension()
                        .is_some_and(|extension| extension == "pack")
                })
                .collect();
            assert_eq!(packs.len(), 1);
            assert_eq!(
                fixture.assert_pack(
                    &mut BufReader::new(File::open(&packs[0]).unwrap()),
                    &fixture.full
                ),
                checksum
            );
            fixture.assert_clean();
            assert_eq!(fixture.refs(), before);
        }
    }
}
