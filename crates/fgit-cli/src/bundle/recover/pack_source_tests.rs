#![cfg(unix)]

use super::*;
use fgit_crypto::sha256_digest;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

struct Fixture {
    root: PathBuf,
    path: PathBuf,
    header: Vec<u8>,
    pack: Vec<u8>,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "fg-native-pack-replay-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let path = root.join("input.bundle");
        let header = b"an already natively verified envelope\n\n".to_vec();
        let pack: Vec<_> = (0..64 * 1024 + 517).map(|at| (at % 251) as u8).collect();
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(&header).unwrap();
        file.write_all(&pack).unwrap();
        Self {
            root,
            path,
            header,
            pack,
        }
    }
    fn open(&self) -> StableInput {
        StableInput::open(&self.path, 1024 * 1024, &mut || true).unwrap()
    }
    fn digest(&self) -> [u8; 32] {
        sha256_digest(&self.pack)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn collect(source: &mut FilePack<'_>, chunk: usize) -> io::Result<Vec<u8>> {
    source.rewind()?;
    let mut output = Vec::new();
    let mut buffer = vec![0; chunk];
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        output.extend_from_slice(&buffer[..count]);
    }
    Ok(output)
}

#[test]
fn every_replay_reads_only_the_selected_pack_and_authenticates_its_eof() {
    let fixture = Fixture::new();
    let mut input = fixture.open();
    let mut source = FilePack::new(
        &mut input,
        fixture.header.len() as u64,
        fixture.pack.len() as u64,
        fixture.digest(),
    )
    .unwrap();
    assert_eq!(source.len(), fixture.pack.len() as u64);
    assert!(source.read(&mut [0; 3]).is_err());
    for chunk in [1, 7, 997, 64 * 1024, 128 * 1024] {
        assert_eq!(collect(&mut source, chunk).unwrap(), fixture.pack);
        assert!(source.checked);
        assert_eq!(source.read(&mut [0; 3]).unwrap(), 0);
    }
    input.recheck(&mut || true).unwrap();
}

#[test]
fn pack_digest_failure_is_reported_before_a_successful_eof() {
    let fixture = Fixture::new();
    let mut input = fixture.open();
    let mut wrong = fixture.digest();
    wrong[0] ^= 1;
    let mut source = FilePack::new(
        &mut input,
        fixture.header.len() as u64,
        fixture.pack.len() as u64,
        wrong,
    )
    .unwrap();
    let error = collect(&mut source, 997).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("SHA-256"));
    assert!(!source.checked);

    let mut source = FilePack::new(
        &mut input,
        fixture.header.len() as u64,
        fixture.pack.len() as u64,
        fixture.digest(),
    )
    .unwrap();
    assert_eq!(collect(&mut source, 997).unwrap(), fixture.pack);
}

#[test]
fn changed_source_bytes_header_length_or_namespace_cannot_reuse_an_old_plan() {
    for defect in 0..5 {
        let fixture = Fixture::new();
        let mut input = fixture.open();
        let mut source = FilePack::new(
            &mut input,
            fixture.header.len() as u64,
            fixture.pack.len() as u64,
            fixture.digest(),
        )
        .unwrap();
        source.rewind().unwrap();
        let mut first = [0_u8; 17];
        assert_eq!(source.read(&mut first).unwrap(), first.len());
        match defect {
            0 => {
                let mut file = OpenOptions::new().write(true).open(&fixture.path).unwrap();
                file.seek(SeekFrom::End(-1)).unwrap();
                file.write_all(&[fixture.pack.last().copied().unwrap() ^ 1])
                    .unwrap();
            }
            1 => {
                let mut file = OpenOptions::new().write(true).open(&fixture.path).unwrap();
                file.write_all(b"X").unwrap();
            }
            2 => {
                OpenOptions::new()
                    .write(true)
                    .open(&fixture.path)
                    .unwrap()
                    .set_len(fixture.header.len() as u64 + 23)
                    .unwrap();
            }
            3 => {
                OpenOptions::new()
                    .append(true)
                    .open(&fixture.path)
                    .unwrap()
                    .write_all(b"extra")
                    .unwrap();
            }
            _ => {
                let original = fixture.root.join("original.bundle");
                fs::rename(&fixture.path, &original).unwrap();
                symlink(&original, &fixture.path).unwrap();
            }
        }
        let mut buffer = [0_u8; 4096];
        let error = loop {
            match source.read(&mut buffer) {
                Ok(0) => panic!("source mutation {defect} reached successful EOF"),
                Ok(_) => {}
                Err(error) => break error,
            }
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "defect={defect}");
        assert!(!source.checked);
        assert!(
            source.rewind().is_err(),
            "old plan reused after defect={defect}"
        );
    }
}

#[test]
fn pack_ranges_must_be_nonempty_and_end_at_the_verified_source_eof() {
    let fixture = Fixture::new();
    let mut input = fixture.open();
    for (offset, length) in [
        (0, 0),
        (u64::MAX, 1),
        (0, fixture.pack.len() as u64),
        (fixture.header.len() as u64, fixture.pack.len() as u64 + 1),
    ] {
        assert!(FilePack::new(&mut input, offset, length, fixture.digest()).is_err());
    }
    let mut source = FilePack::new(
        &mut input,
        fixture.header.len() as u64,
        fixture.pack.len() as u64,
        fixture.digest(),
    )
    .unwrap();
    assert_eq!(collect(&mut source, 997).unwrap(), fixture.pack);
}
