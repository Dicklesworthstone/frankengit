use super::super::publish_streamed;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(1);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-stream-publication-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn entries(&self) -> usize {
        fs::read_dir(&self.0).unwrap().count()
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn streamed_bytes_remain_private_until_build_and_readback_complete() {
    let scratch = Scratch::new();
    let destination = scratch.0.join("backup");
    let receipt = publish_streamed(&destination, |file| {
        file.write_all(b"whole verified bytes").unwrap();
        assert!(!destination.exists());
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut read = Vec::new();
        file.read_to_end(&mut read).unwrap();
        assert_eq!(read, b"whole verified bytes");
        Ok("verified")
    })
    .unwrap();
    assert_eq!(receipt, "verified");
    assert_eq!(fs::read(&destination).unwrap(), b"whole verified bytes");
    assert_eq!(scratch.entries(), 1);
}
#[test]
fn failed_verification_discards_only_its_private_file_without_publication() {
    let scratch = Scratch::new();
    let destination = scratch.0.join("backup");
    let result: Result<(), String> = publish_streamed(&destination, |file| {
        file.write_all(b"partial or unverified").unwrap();
        Err("source changed".into())
    });
    assert_eq!(result.unwrap_err(), "source changed");
    assert!(!destination.exists());
    assert_eq!(scratch.entries(), 0);
}
#[test]
fn a_racing_destination_is_never_overwritten_by_a_verified_stream() {
    let scratch = Scratch::new();
    let destination = scratch.0.join("backup");
    assert!(
        publish_streamed(&destination, |file| {
            file.write_all(b"our verified bytes").unwrap();
            fs::write(&destination, b"other owner").unwrap();
            Ok(())
        })
        .is_err()
    );
    assert_eq!(fs::read(&destination).unwrap(), b"other owner");
    assert_eq!(scratch.entries(), 1);
    assert!(
        publish_streamed(&destination, |_| -> Result<(), String> {
            panic!("preexisting target must refuse before build")
        })
        .is_err()
    );
}
