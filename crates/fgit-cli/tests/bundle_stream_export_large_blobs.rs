#![forbid(unsafe_code)]
#![cfg(unix)]
//! Real commands cross the old 32 MiB per-object export ceiling in both native
//! hash domains. The source is admitted through the public durable loose import,
//! not a fabricated closure proof. No foreign executable is available to fg.

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
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, PrincipalId, RepositoryId, TenantId};

const TENANT: &str = "11111111111111111111111111111111";
const REPOSITORY: &str = "22222222222222222222222222222222";
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
        success(self.run(&args(&[
            "refs",
            "node",
            TENANT,
            REPOSITORY,
            "--trusted-local",
            "--object-format",
            self.format.as_str(),
        ])))
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
                continue;
            }
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
