//! Actual fg processes combine mapped destinations with incremental file custody.
//! The source and native readback belong to the parent fixture; no foreign Git,
//! test peer, or synthetic success receipt stands in for either receiving node.

use super::*;

const STORAGE: &str = "incremental-fetcher";
const TRACKING: &str = "refs/remotes/upstream/main";
const COPIED: &str = "refs/remotes/archive/main";

impl Fixture {
    fn incremental_fetch(
        &self,
        bundle: &str,
        key: &str,
        mappings: &[&str],
        extra: &[&str],
    ) -> Output {
        let mut options = vec!["--incremental"];
        options.extend_from_slice(extra);
        self.fetch_at(STORAGE, bundle, key, true, mappings, &options)
    }

    fn assert_incremental_fetch_staging_empty(&self) {
        assert_eq!(
            fs::read_dir(self.root.join(STORAGE).join("staging"))
                .unwrap()
                .count(),
            0,
            "mapped incremental fetch must settle original, upload and scratch custody",
        );
    }

    fn assert_incremental_fetch_seed(&self) {
        let node = OneNode::open_existing(
            NodeConfig::new(
                self.root.join(STORAGE),
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
            BTreeMap::from([(RefName::try_new(TRACKING.as_bytes()).unwrap(), self.base,)]),
        );
        let originals = self
            .full
            .keys()
            .filter(|id| !self.incremental.contains_key(*id))
            .copied()
            .collect::<BTreeSet<_>>();
        assert_eq!(originals.len(), 2);
        assert_eq!(
            materialized.selected_closure().closure().objects(),
            &originals,
        );
        for &id in self.incremental.keys() {
            assert!(matches!(node.git_object_header(id),
                Err(fgit_node::NodeRefusal::Fabric(error))
                    if matches!(*error, fgit_object_fabric::fabric::StoreRefusal::ObjectAbsent)));
        }
        node.shutdown().unwrap();
    }

    pub(super) fn assert_incremental_fetch(
        &self,
        bundle: &str,
        full_bundle: &str,
        seed_bundle: &str,
    ) {
        success(self.run(&args(&[
            "init",
            STORAGE,
            TENANT,
            REPOSITORY,
            self.format.as_str(),
        ])));
        let initial = ["--map", "refs/heads/main", TRACKING, "absent"];
        success(self.fetch_at(
            STORAGE,
            seed_bundle,
            "incremental-mapped-seed",
            true,
            &initial,
            &[
                "--max-object-mib",
                "1",
                "--max-blob-mib",
                "40",
                "--timeout-secs",
                "600",
            ],
        ));
        self.assert_incremental_fetch_seed();
        self.assert_incremental_fetch_staging_empty();
        let before = self.refs_at(STORAGE);

        // Keep the native pack and declared prerequisites intact, but advertise
        // another valid source that must never become an implicit destination.
        let selected_bundle = "mapped-incremental.bundle";
        let input = fs::read(self.root.join(bundle)).unwrap();
        let boundary = input.windows(2).position(|pair| pair == b"\n\n").unwrap() + 2;
        let header = std::str::from_utf8(&input[..boundary]).unwrap();
        let header = format!(
            "{}{} refs/heads/unselected\n\n",
            header.strip_suffix('\n').unwrap(),
            self.base,
        );
        fs::write(
            self.root.join(selected_bundle),
            [header.as_bytes(), &input[boundary..]].concat(),
        )
        .unwrap();
        let parsed = FullBundleHeader::read_incremental(
            &mut BufReader::new(File::open(self.root.join(selected_bundle)).unwrap()),
            FullBundleLimits::default(),
            &mut || true,
        )
        .unwrap();
        assert_eq!(parsed.references().len(), 2);
        assert_eq!(parsed.prerequisites(), &[self.base]);
        let source_hex = lowercase_hex(b"refs/heads/main");
        let raw_ref = RefName::try_new(b"refs/remotes/upstream/\xff").unwrap();
        let raw_hex = lowercase_hex(raw_ref.as_bytes());
        let base = self.base.to_string();
        let mappings = [
            "--map",
            "refs/heads/main",
            TRACKING,
            base.as_str(),
            "--map-hex",
            source_hex.as_str(),
            raw_hex.as_str(),
            "absent",
        ];
        let upload_limits = [
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
        ];

        // Ordinary file fetch retains its self-contained contract. The same
        // input only borrows history when the explicit profile is selected.
        refused(self.fetch_at(
            STORAGE,
            selected_bundle,
            "incremental-mapped-update",
            true,
            &mappings,
            &["--max-object-mib", "1", "--max-blob-mib", "40"],
        ));
        assert_eq!(self.refs_at(STORAGE), before);
        self.assert_incremental_fetch_staging_empty();

        for limits in [
            [
                "--max-object-mib",
                "1",
                "--max-blob-mib",
                "32",
                "--max-expanded-mib",
                "40",
                "--max-original-mib",
                "1",
            ],
            [
                "--max-object-mib",
                "1",
                "--max-blob-mib",
                "40",
                "--max-expanded-mib",
                "32",
                "--max-original-mib",
                "1",
            ],
        ] {
            refused(self.incremental_fetch(
                selected_bundle,
                "incremental-mapped-update",
                &mappings,
                &limits,
            ));
            assert_eq!(self.refs_at(STORAGE), before);
            self.assert_incremental_fetch_staging_empty();
        }
        let accepted = success(self.incremental_fetch(
            selected_bundle,
            "incremental-mapped-update",
            &mappings,
            &upload_limits,
        ));
        for required in [
            "\"type\":\"git_bundle_fetch\"",
            "\"outcome\":\"committed\"",
            "\"command_committed\":true",
            "\"atomic\":true",
            "\"reference_count\":2",
            "\"node_closed\":true",
            "\"cleanup_error\":null",
        ] {
            assert!(accepted.contains(required), "{accepted}");
        }
        let tracking = RefName::try_new(TRACKING.as_bytes()).unwrap();
        let mut expected_refs = vec![(tracking, self.tip), (raw_ref, self.tip)];
        self.assert_native_objects_at(STORAGE, &expected_refs);
        self.assert_incremental_fetch_staging_empty();
        let committed = self.refs_at(STORAGE);
        assert_ne!(committed, before);
        for advertised in [b"refs/heads/main".as_slice(), b"refs/heads/unselected"] {
            assert!(
                !committed.contains(&lowercase_hex(advertised)),
                "{committed}"
            );
        }

        // Recovery reads the semantic header before fresh blob/original work.
        // Equivalent full input and reordered maps retain the original decision.
        let replay_limits = [
            "--max-original-mib",
            "1",
            "--max-blob-mib",
            "1",
            "--max-expanded-mib",
            "1",
        ];
        let reordered = [&mappings[4..], &mappings[..4]].concat();
        assert_eq!(
            success(self.incremental_fetch(
                selected_bundle,
                "incremental-mapped-update",
                &reordered,
                &replay_limits,
            )),
            accepted,
        );
        assert_eq!(
            success(self.fetch_at(
                STORAGE,
                full_bundle,
                "incremental-mapped-update",
                false,
                &mappings,
                &[],
            )),
            accepted,
        );
        assert_eq!(self.refs_at(STORAGE), committed);
        self.assert_incremental_fetch_staging_empty();

        let stale = [
            "--map",
            "refs/heads/main",
            TRACKING,
            base.as_str(),
            "--map",
            "refs/heads/main",
            "refs/heads/partial",
            "absent",
        ];
        let refusal = self.incremental_fetch(
            selected_bundle,
            "incremental-mapped-stale",
            &stale,
            &upload_limits,
        );
        assert_eq!(
            refusal.status.code(),
            Some(3),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&refusal.stdout),
            String::from_utf8_lossy(&refusal.stderr),
        );
        let refusal = String::from_utf8(refusal.stdout).unwrap();
        assert!(
            refusal.contains("\"refusal_code\":\"ExpectedOldRefMismatch\""),
            "{refusal}",
        );
        assert_eq!(self.refs_at(STORAGE), committed);
        self.assert_incremental_fetch_staging_empty();
        let replay = self.fetch_at(
            STORAGE,
            full_bundle,
            "incremental-mapped-stale",
            false,
            &stale,
            &[],
        );
        assert_eq!(replay.status.code(), Some(3));
        assert_eq!(String::from_utf8(replay.stdout).unwrap(), refusal);

        self.assert_incremental_original_fetch(full_bundle, &mut expected_refs);
        self.assert_incremental_fetch_staging_empty();
        self.assert_clean();
    }

    fn assert_incremental_original_fetch(
        &self,
        full_bundle: &str,
        expected_refs: &mut Vec<(RefName, GitOid)>,
    ) {
        let zero_bundle = "mapped-original-only.bundle";
        let tip = self.tip.to_string();
        let report = success(self.run(&args(&[
            "bundle",
            "sync-export",
            "node",
            TENANT,
            REPOSITORY,
            zero_bundle,
            "--streaming",
            "--trusted-local",
            "--object-format",
            self.format.as_str(),
            "--ref",
            "refs/heads/main",
            "--prerequisite",
            tip.as_str(),
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
        let mappings = ["--map", "refs/heads/main", COPIED, "absent"];
        let before = self.refs_at(STORAGE);
        for limits in [
            [
                "--max-object-mib",
                "1",
                "--max-blob-mib",
                "40",
                "--max-original-mib",
                "32",
                "--max-expanded-mib",
                "1",
            ],
            [
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
            refused(self.incremental_fetch(
                zero_bundle,
                "incremental-mapped-original",
                &mappings,
                &limits,
            ));
            assert_eq!(self.refs_at(STORAGE), before);
            self.assert_incremental_fetch_staging_empty();
        }
        let original_limits = [
            "--max-object-mib",
            "1",
            "--max-blob-mib",
            "40",
            "--max-original-mib",
            "40",
            "--max-expanded-mib",
            "1",
            "--max-refs",
            "1",
            "--timeout-secs",
            "600",
        ];
        let accepted = success(self.incremental_fetch(
            zero_bundle,
            "incremental-mapped-original",
            &mappings,
            &original_limits,
        ));
        assert!(accepted.contains("\"outcome\":\"committed\""), "{accepted}");
        assert!(accepted.contains("\"reference_count\":1"), "{accepted}");
        expected_refs.push((RefName::try_new(COPIED.as_bytes()).unwrap(), self.tip));
        self.assert_native_objects_at(STORAGE, expected_refs);
        self.assert_incremental_fetch_staging_empty();
        let committed = self.refs_at(STORAGE);
        assert_eq!(
            success(self.incremental_fetch(
                zero_bundle,
                "incremental-mapped-original",
                &mappings,
                &["--max-original-mib", "1", "--max-blob-mib", "1"],
            )),
            accepted,
        );
        assert_eq!(
            success(self.fetch_at(
                STORAGE,
                full_bundle,
                "incremental-mapped-original",
                false,
                &mappings,
                &[],
            )),
            accepted,
        );
        assert_eq!(self.refs_at(STORAGE), committed);

        // The old tip belongs to the declared original closure, but is not a
        // parent of its own ancestor. Membership must not permit a rewind.
        let bytes = fs::read(self.root.join(zero_bundle)).unwrap();
        let boundary = bytes.windows(2).position(|pair| pair == b"\n\n").unwrap() + 2;
        let header = std::str::from_utf8(&bytes[..boundary]).unwrap();
        let header = header.replace(
            &format!("{} refs/heads/main\n", self.tip),
            &format!("{} refs/heads/main\n", self.base),
        );
        let rewind = "mapped-original-rewind.bundle";
        fs::write(
            self.root.join(rewind),
            [header.as_bytes(), &bytes[boundary..]].concat(),
        )
        .unwrap();
        let refused_rewind = self.incremental_fetch(
            rewind,
            "incremental-mapped-rewind",
            &["--map", "refs/heads/main", TRACKING, tip.as_str()],
            &original_limits,
        );
        assert!(
            String::from_utf8_lossy(&refused_rewind.stderr).contains("NonFastForwardRefused"),
            "{}",
            String::from_utf8_lossy(&refused_rewind.stderr),
        );
        refused(refused_rewind);
        assert_eq!(self.refs_at(STORAGE), committed);
        self.assert_incremental_fetch_staging_empty();
    }
}
