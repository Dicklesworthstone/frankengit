#![forbid(unsafe_code)]
//! Public node-configuration and pre-allocation refusal boundaries.
//!
//! These tests invoke the owning `OneNode` API rather than manufacturing
//! `NodeRefusal` values.  The object-size probe establishes the intended
//! ordering: a configured byte ceiling refuses before an envelope, object
//! fabric write, or resource grant is attempted.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_git_object::ObjectType;
use fgit_node::{NodeConfig, NodeRefusal, OneNode};
use fgit_types::{RepositoryId, TenantId};

static NEXT_SCRATCH_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct ScratchDirectory(PathBuf);

impl ScratchDirectory {
    fn new() -> Self {
        let sequence = NEXT_SCRATCH_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "frankengit-node-configuration-refusals-{}-{sequence}",
            std::process::id()
        )))
    }
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn config(root: PathBuf) -> NodeConfig {
    NodeConfig::new(
        root,
        TenantId::from_bytes([0x11; 16]),
        RepositoryId::from_bytes([0x22; 16]),
    )
}

#[test]
fn an_empty_storage_root_is_refused_before_runtime_or_storage_open() {
    assert!(matches!(
        OneNode::init(config(PathBuf::new())),
        Err(NodeRefusal::EmptyStorageRoot)
    ));
}

#[test]
fn a_zero_worker_configuration_is_refused_before_runtime_creation() {
    let scratch = ScratchDirectory::new();

    assert!(matches!(
        OneNode::init(config(scratch.0.clone()).with_worker_threads(0)),
        Err(NodeRefusal::InvalidWorkerCount)
    ));
}

#[test]
fn an_oversized_object_is_refused_before_envelope_or_fabric_work() {
    let scratch = ScratchDirectory::new();
    let (node, _) = OneNode::init(config(scratch.0.clone()).with_max_object_bytes(4))
        .expect("small object profile still opens a node");

    let refusal = node.put_git_object(ObjectType::Blob, b"five!".to_vec());
    assert!(matches!(
        refusal,
        Err(NodeRefusal::ObjectTooLarge {
            offered: 5,
            maximum: 4,
        })
    ));
    node.shutdown().expect("node drains after refusal");
}

#[cfg(unix)]
#[test]
fn a_non_utf8_storage_root_is_refused_before_authority_open() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let root = PathBuf::from(OsString::from_vec(vec![b'n', b'o', b'd', b'e', 0xff]));

    assert!(matches!(
        OneNode::init(config(root)),
        Err(NodeRefusal::StoragePathEncoding)
    ));
}
