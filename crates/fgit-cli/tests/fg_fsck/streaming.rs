//! The real process audits a persisted multi-chunk blob under independent
//! metadata, blob and whole-audit limits. No alternate verifier or Git process.
use super::*;
use std::io::{Read, Seek, SeekFrom, Write};

const BLOB_BYTES: usize = 5 * 64 * 1024 + 17;
const METADATA_BYTES: usize = 64 * 1024;

struct StreamingFixture {
    _scratch: Scratch,
    root: PathBuf,
    blob: GitOid,
    blob_path: PathBuf,
    payload_bytes: usize,
    tree_bytes: usize,
}

impl StreamingFixture {
    fn new(format: GitHashAlgorithm) -> Self {
        let scratch = Scratch::new();
        let root = scratch.0.join("node");
        let source = scratch.0.join("source.git");
        let body = (0..BLOB_BYTES)
            .map(|offset| (offset % 251) as u8)
            .collect::<Vec<_>>();
        let blob = write_loose(&source, format, GitObjectKind::Blob, &body);
        let mut tree = b"100644 streamed\0".to_vec();
        tree.extend_from_slice(blob.as_bytes());
        let tree_bytes = tree.len();
        let tree = write_loose(&source, format, GitObjectKind::Tree, &tree);
        let commit = format!(
            "tree {tree}\nauthor Audit <audit@example.invalid> 1 +0000\ncommitter Audit <audit@example.invalid> 1 +0000\n\nstreamed fsck\n"
        );
        let payload_bytes = body.len() + tree_bytes + commit.len();
        let commit = write_loose(&source, format, GitObjectKind::Commit, commit.as_bytes());
        fs::create_dir_all(source.join("refs/heads")).unwrap();
        fs::write(source.join("refs/heads/main"), format!("{commit}\n")).unwrap();
        fs::write(source.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        if format == GitHashAlgorithm::Sha256 {
            fs::write(
                source.join("config"),
                "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectFormat = sha256\n",
            )
            .unwrap();
        }
        success(fg(&[
            "init",
            text(&root),
            TENANT,
            REPOSITORY,
            format.as_str(),
        ]));
        success(fg(&[
            "import",
            text(&root),
            TENANT,
            REPOSITORY,
            ACTOR,
            "streamed-fsck-fixture",
            text(&source),
        ]));
        // Locate exactly this test's native stored object for late fault
        // injection. Production selection never enumerates physical files.
        let mut paths = Vec::new();
        find_payload(&root.join("objects"), &body, 0, &mut paths);
        assert_eq!(paths.len(), 1);
        let (blob_path, _) = paths.pop().unwrap();
        Self {
            _scratch: scratch,
            root,
            blob,
            blob_path,
            payload_bytes,
            tree_bytes,
        }
    }

    fn flags(&self, objects_only: bool) -> Vec<String> {
        let mut flags = vec![
            "--max-object-bytes".into(),
            METADATA_BYTES.to_string(),
            "--max-blob-bytes".into(),
            BLOB_BYTES.to_string(),
            "--max-bytes".into(),
            self.payload_bytes.to_string(),
        ];
        if objects_only {
            flags.push("--objects-only".into());
        }
        flags
    }

    fn audit(&self, format: GitHashAlgorithm, flags: &[String]) -> Output {
        let flags = flags.iter().map(String::as_str).collect::<Vec<_>>();
        audit(&self.root, format.as_str(), &flags)
    }
}

/// Independently encode native loose objects with several stored DEFLATE
/// blocks, avoiding both a production codec oracle and the old u16 fixture cap.
fn write_loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let oid = git_object_id(format, kind, body);
    let name = oid.to_string();
    let path = root.join("objects").join(&name[..2]).join(&name[2..]);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut framed = format!("{} {}\0", kind.label(), body.len()).into_bytes();
    framed.extend_from_slice(body);
    let mut zlib = vec![0x78, 0x01];
    let mut chunks = framed.chunks(usize::from(u16::MAX)).peekable();
    while let Some(chunk) = chunks.next() {
        zlib.push(u8::from(chunks.peek().is_none()));
        let count = u16::try_from(chunk.len()).unwrap();
        zlib.extend_from_slice(&count.to_le_bytes());
        zlib.extend_from_slice(&(!count).to_le_bytes());
        zlib.extend_from_slice(chunk);
    }
    let (mut a, mut b) = (1_u32, 0_u32);
    for byte in framed {
        a = (a + u32::from(byte)) % 65_521;
        b = (b + a) % 65_521;
    }
    zlib.extend_from_slice(&((b << 16) | a).to_be_bytes());
    fs::write(path, zlib).unwrap();
    oid
}

fn set_flag(flags: &mut [String], flag: &str, value: usize) {
    let index = flags.iter().position(|item| item == flag).unwrap();
    flags[index + 1] = value.to_string();
}

#[test]
fn both_receipt_modes_stream_blobs_without_widening_metadata_or_total_limits() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = StreamingFixture::new(format);
        for objects_only in [false, true] {
            let mode = if objects_only {
                vec!["--objects-only"]
            } else {
                Vec::new()
            };
            let original = success(audit(&fixture.root, format.as_str(), &mode));
            let flags = fixture.flags(objects_only);
            let accepted = success(fixture.audit(format, &flags));
            assert_eq!(
                accepted, original,
                "streaming preserves the existing receipt"
            );
            assert!(accepted.contains("\"references_checked\":1,"));
            assert!(accepted.contains("\"objects_verified\":3,"));
            assert!(accepted.contains(&format!(
                "\"payload_bytes_verified\":{},",
                fixture.payload_bytes
            )));
            assert!(accepted.contains("\"complete\":true"));
            assert!(accepted.contains("\"node_closed\":true"));
            if objects_only {
                assert!(accepted.contains("\"object_graph_verified\":false"));
                assert!(accepted.contains("\"graph_acyclic\":null"));
                assert!(accepted.contains("\"local_edges_verified\":null"));
            } else {
                assert!(accepted.contains("\"object_graph_verified\":true"));
                assert!(accepted.contains("\"graph_acyclic\":true"));
                assert!(accepted.contains("\"local_edges_verified\":2"));
            }

            // Omitting the separate option retains the former per-object cap.
            let mut implicit = flags.clone();
            let index = implicit
                .iter()
                .position(|flag| flag == "--max-blob-bytes")
                .unwrap();
            drop(implicit.drain(index..index + 2));
            let error = refused(fixture.audit(format, &implicit));
            // Without an explicit blob allowance the stored-file policy can
            // refuse before the header is opened. Keep that existing boundary.
            assert!(error.contains("object_read_failed"), "{error}");
            assert!(error.contains(&fixture.blob.to_string()), "{error}");

            for (flag, value) in [
                ("--max-blob-bytes", BLOB_BYTES - 1),
                ("--max-object-bytes", fixture.tree_bytes - 1),
                ("--max-bytes", fixture.payload_bytes - 1),
            ] {
                let mut bounded = flags.clone();
                set_flag(&mut bounded, flag, value);
                let error = refused(fixture.audit(format, &bounded));
                assert!(
                    error.contains(flag.trim_start_matches("--")),
                    "{flag}: {error}"
                );
            }
            assert_eq!(success(fixture.audit(format, &flags)), accepted);
        }
    }
}

#[test]
fn late_blob_corruption_and_size_refusals_never_emit_either_success_receipt() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = StreamingFixture::new(format);
        let flags = fixture.flags(false);
        let graph_before = success(fixture.audit(format, &flags));
        let bytes_before = success(fixture.audit(format, &fixture.flags(true)));
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fixture.blob_path)
            .unwrap();
        file.seek(SeekFrom::End(-1)).unwrap();
        let mut original = [0_u8; 1];
        file.read_exact(&mut original).unwrap();
        let corrupt = [original[0] ^ 1];
        file.seek(SeekFrom::End(-1)).unwrap();
        file.write_all(&corrupt).unwrap();
        file.sync_all().unwrap();

        for objects_only in [false, true] {
            let mut flags = fixture.flags(objects_only);
            set_flag(&mut flags, "--max-blob-bytes", BLOB_BYTES - 1);
            let error = refused(fixture.audit(format, &flags));
            assert!(error.contains("max-blob-bytes"), "{error}");
            assert!(!error.contains("object_read_failed"), "{error}");

            set_flag(&mut flags, "--max-blob-bytes", BLOB_BYTES);
            let error = refused(fixture.audit(format, &flags));
            assert!(error.contains("object_read_failed"), "{error}");
            assert!(error.contains(&fixture.blob.to_string()), "{error}");
            file.seek(SeekFrom::End(-1)).unwrap();
            let mut stored = [0_u8; 1];
            file.read_exact(&mut stored).unwrap();
            assert_eq!(stored, corrupt, "an audit must not repair the object");
        }

        file.seek(SeekFrom::End(-1)).unwrap();
        file.write_all(&original).unwrap();
        file.sync_all().unwrap();
        assert_eq!(success(fixture.audit(format, &flags)), graph_before);
        assert_eq!(
            success(fixture.audit(format, &fixture.flags(true))),
            bytes_before
        );
    }
}
