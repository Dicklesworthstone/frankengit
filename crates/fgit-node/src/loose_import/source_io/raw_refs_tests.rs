//! Raw ref bytes stay exact through bounded parsing and source revalidation.
use super::{ImportControl, LooseGitImportRefusal, read_packed_refs};
use super::super::{CanonicalRefState, layout::SourceLayout};
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RefusalCode};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const FIRST: &[u8] = b"refs/heads/byte-\xff";
const SECOND: &[u8] = b"refs/heads/byte-\xfe";
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-raw-ref-source-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn oid(format: GitHashAlgorithm) -> GitOid {
    GitOid::from_hex(format, &"12".repeat(format.digest_len())).unwrap()
}

fn line(identity: GitOid, name: &[u8], ending: &[u8]) -> Vec<u8> {
    [identity.to_string().as_bytes(), b" ", name, ending].concat()
}

fn read(
    root: &Scratch,
    format: GitHashAlgorithm,
    limit: usize,
) -> Result<BTreeMap<RefName, GitOid>, LooseGitImportRefusal> {
    let mut live = || true;
    read_packed_refs(&root.0, format, limit, false, &ImportControl::new(&mut live))
}

#[test]
fn packed_ref_byte_names_preserve_all_existing_line_endings() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let identity = oid(format);
        for ending in [b"\n".as_slice(), b"\r\n", b""] {
            fs::write(root.0.join("packed-refs"), line(identity, FIRST, ending)).unwrap();
            assert_eq!(
                read(&root, format, 1).unwrap(),
                BTreeMap::from([(RefName::try_new(FIRST).unwrap(), identity)]),
            );
        }

        // A CR is stripped only as part of CRLF, never from an unterminated
        // name. Interior controls and invalid Git components also stay invalid.
        for name in [
            b"refs/heads/byte-\xff\r".as_slice(),
            b"refs/heads/byte-\xff\0",
            b"refs/heads/byte-\xff\t",
            b"refs/heads/byte-\xff..bad",
            b"refs/heads/byte-\xff.lock",
        ] {
            fs::write(root.0.join("packed-refs"), line(identity, name, b"")).unwrap();
            assert!(matches!(
                read(&root, format, 1),
                Err(LooseGitImportRefusal::RefName { .. })
            ));
        }
        fs::write(root.0.join("packed-refs"), line(identity, FIRST, b"\r\n")).unwrap();
        assert_eq!(read(&root, format, 1).unwrap().len(), 1);
    }
}

#[test]
fn distinct_raw_names_share_the_original_limits_and_cancellation_boundary() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let identity = oid(format);
        let bytes = [
            line(identity, FIRST, b"\n"),
            line(identity, SECOND, b"\n"),
        ]
        .concat();
        fs::write(root.0.join("packed-refs"), &bytes).unwrap();
        assert_eq!(read(&root, format, 2).unwrap().len(), 2);
        assert!(matches!(
            read(&root, format, 1),
            Err(LooseGitImportRefusal::RefLimitExceeded {
                observed: 2,
                limit: 1,
            })
        ));

        let live = Cell::new(true);
        let mut deadline = || live.get();
        let control = ImportControl::new(&mut deadline);
        assert_eq!(
            read_packed_refs(&root.0, format, 2, false, &control)
                .unwrap()
                .len(),
            2,
        );
        live.set(false);
        assert!(matches!(
            read_packed_refs(&root.0, format, 2, false, &control),
            Err(LooseGitImportRefusal::Interrupted {
                code: RefusalCode::CancellationInProgress,
                ..
            })
        ));
        live.set(true);
        assert!(matches!(
            read_packed_refs(&root.0, format, 2, false, &control),
            Err(LooseGitImportRefusal::Interrupted { .. })
        ));
        assert_eq!(read(&root, format, 2).unwrap().len(), 2);

        fs::write(
            root.0.join("packed-refs"),
            [line(identity, FIRST, b"\n"), line(identity, FIRST, b"\n")].concat(),
        )
        .unwrap();
        assert!(matches!(
            read(&root, format, 2),
            Err(LooseGitImportRefusal::PackedRefContents(_))
        ));
    }
}

#[test]
fn source_revalidation_compares_ref_bytes_without_lossy_name_collisions() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let admin = root.0.join("admin.git");
        let checkout = root.0.join("checkout");
        fs::create_dir_all(admin.join("objects")).unwrap();
        fs::create_dir(&checkout).unwrap();
        fs::write(checkout.join(".git"), b"gitdir: ../admin.git\n").unwrap();
        fs::write(admin.join("HEAD"), [b"ref: ".as_slice(), FIRST, b"\n"].concat()).unwrap();
        fs::write(admin.join("packed-refs"), line(oid(format), FIRST, b"\n")).unwrap();
        let mut live = || true;
        let control = ImportControl::new(&mut live);
        let layout = SourceLayout::resolve(&checkout, &control).unwrap();
        let selected = CanonicalRefState::new_with_head_target(
            layout.read_refs(format, 1, &control).unwrap(),
            layout.read_head(&control).unwrap(),
        )
        .unwrap();
        layout.revalidate(format, 1, &selected, &control).unwrap();

        // Representation changes preserve the exact selected namespace.
        fs::write(admin.join("packed-refs"), line(oid(format), FIRST, b"\r\n")).unwrap();
        layout.revalidate(format, 1, &selected, &control).unwrap();

        // Both names have the same replacement-character rendering. Changing
        // only the invalid UTF-8 byte must still invalidate the source snapshot.
        assert_eq!(String::from_utf8_lossy(FIRST), String::from_utf8_lossy(SECOND));
        fs::write(admin.join("packed-refs"), line(oid(format), SECOND, b"\n")).unwrap();
        assert!(matches!(
            layout.revalidate(format, 1, &selected, &control),
            Err(LooseGitImportRefusal::SourceLayoutChanged(_))
        ));
    }
}
