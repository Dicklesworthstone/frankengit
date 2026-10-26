#![forbid(unsafe_code)]
//! The native streaming placement boundary retains ordinary node identity,
//! resource containment and authority semantics. No foreign Git is involved.

use std::io::{self, Cursor, Read};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_crypto::{GitObjectKind, git_object_id, git_payload_commitment};
use fgit_git_object::ObjectType;
use fgit_node::{NodeConfig, NodeRefusal, OneNode, StoredObject};
use fgit_object_fabric::{ObjectKind, StoreRefusal};
use fgit_types::{CANONICAL_CODEC_VERSION, GitHashAlgorithm, GitOid, RepositoryId, TenantId};

static NEXT: AtomicU64 = AtomicU64::new(1);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "fgit-streamed-node-placement-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        )))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn config(root: &Scratch, format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(
        root.0.clone(),
        TenantId::from_bytes([0x64; 16]),
        RepositoryId::from_bytes([0x65; 16]),
    )
    .with_object_format(format)
    .with_max_object_bytes(1024)
    .with_selected_pack_blob_limit(256 * 1024)
}

fn commitment(body: &[u8]) -> [u8; 32] {
    git_payload_commitment(GitObjectKind::Blob, body, CANONICAL_CODEC_VERSION)
        .digest()
        .as_bytes()
        .try_into()
        .unwrap()
}

fn assert_stream(node: &OneNode, identity: GitOid, expected: &[u8]) {
    let header = node.git_object_header(identity).unwrap();
    assert_eq!(header.kind, ObjectKind::Blob);
    assert_eq!(header.payload_length, expected.len() as u64);
    let mut stream = node
        .open_git_blob_stream(identity, expected.len() as u64)
        .unwrap();
    assert_eq!(stream.identity(), identity);
    assert_eq!(stream.payload_commitment(), commitment(expected));
    let mut offset = 0;
    let mut buffer = [0; 997];
    loop {
        let count = stream.read_tentative(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        assert_eq!(&buffer[..count], &expected[offset..offset + count]);
        offset += count;
    }
    assert_eq!(offset, expected.len());
    assert!(stream.is_verified());
}

#[test]
fn streamed_node_placement_reopens_and_retries_without_publishing_authority() {
    let body = (0..150_123).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = config(&root, format);
        let (node, _) = OneNode::init(config.clone()).unwrap();
        let before = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        let identity = git_object_id(format, GitObjectKind::Blob, &body);
        // The explicit blob allowance cannot widen the ordinary buffered path.
        assert!(matches!(
            node.put_git_object(ObjectType::Blob, body.clone()),
            Err(NodeRefusal::ObjectTooLarge { maximum: 1024, .. })
        ));
        assert_eq!(
            node.put_git_blob_stream(
                identity,
                body.len() as u64,
                commitment(&body),
                body.len() as u64,
                &mut Cursor::new(&body),
                &mut || true,
            )
            .unwrap(),
            StoredObject::Created(identity),
        );
        // A selected-blob storage allowance must not widen a whole-object
        // allocation, including a metadata header changing before its read.
        assert!(matches!(
            node.read_git_object(identity),
            Err(NodeRefusal::Fabric(error))
                if matches!(*error, StoreRefusal::StreamingBudgetExceeded {
                    offered, maximum: 1024,
                } if offered == body.len() as u64)
        ));
        assert_stream(&node, identity, &body);
        let after = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        assert_eq!(after.receipt(), before.receipt());
        node.shutdown().unwrap();

        let reopened = OneNode::open_existing(config).unwrap();
        assert_stream(&reopened, identity, &body);
        assert_eq!(
            reopened
                .put_git_blob_stream(
                    identity,
                    body.len() as u64,
                    commitment(&body),
                    body.len() as u64,
                    &mut Cursor::new(&body),
                    &mut || true,
                )
                .unwrap(),
            StoredObject::AlreadyPresent(identity),
        );
        let after = reopened
            .runtime()
            .block_on(reopened.authenticate_authority_head())
            .unwrap();
        assert_eq!(after.receipt(), before.receipt());
        reopened.shutdown().unwrap();
    }
}

struct Unread {
    calls: usize,
}
impl Read for Unread {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        self.calls += 1;
        Err(io::Error::other("source must not be read"))
    }
}

#[test]
fn preflight_refusals_do_not_read_source_or_leak_node_resource_obligations() {
    let root = Scratch::new();
    let (node, _) = OneNode::init(config(&root, GitHashAlgorithm::Sha256)).unwrap();
    let body = b"one admitted source";
    let identity = git_object_id(GitHashAlgorithm::Sha256, GitObjectKind::Blob, body);
    let wrong_format = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, body);
    let before = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap();
    let mut unread = Unread { calls: 0 };
    assert!(matches!(
        node.put_git_blob_stream(
            wrong_format,
            body.len() as u64,
            commitment(body),
            256 * 1024,
            &mut unread,
            &mut || true,
        ),
        Err(NodeRefusal::ObjectFormatMismatch {
            stored: GitHashAlgorithm::Sha256,
            supplied: GitHashAlgorithm::Sha1,
        })
    ));
    assert!(matches!(
        node.put_git_blob_stream(
            identity, body.len() as u64, commitment(body), body.len() as u64 - 1,
            &mut unread, &mut || true,
        ),
        Err(NodeRefusal::Fabric(error))
            if matches!(*error, StoreRefusal::StreamingBudgetExceeded { .. })
    ));
    assert!(matches!(
        node.put_git_blob_stream(
            identity, body.len() as u64, commitment(body), body.len() as u64,
            &mut unread, &mut || false,
        ),
        Err(NodeRefusal::Fabric(error))
            if matches!(*error, StoreRefusal::RuntimeCheckpointRejected)
    ));
    assert_eq!(unread.calls, 0);
    assert!(matches!(
        node.git_object_header(identity),
        Err(NodeRefusal::Fabric(error)) if matches!(*error, StoreRefusal::ObjectAbsent)
    ));
    assert_eq!(
        node.put_git_blob_stream(
            identity,
            body.len() as u64,
            commitment(body),
            body.len() as u64,
            &mut Cursor::new(body),
            &mut || true,
        )
        .unwrap(),
        StoredObject::Created(identity),
    );
    let after = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap();
    assert_eq!(after.receipt(), before.receipt());
    node.shutdown().unwrap();
}

struct LateFailure<'a> {
    remaining: &'a [u8],
}
impl Read for LateFailure<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.remaining.is_empty() && !output.is_empty() {
            return Err(io::Error::other("late source authentication failed"));
        }
        self.remaining.read(output)
    }
}

#[test]
fn late_source_authentication_failure_never_becomes_success_or_skips_an_existing_key() {
    let root = Scratch::new();
    let (node, _) = OneNode::init(config(&root, GitHashAlgorithm::Sha1)).unwrap();
    let body = b"source authenticates only after its final byte";
    let identity = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, body);
    let before = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap();
    for already_present in [false, true] {
        assert!(matches!(
            node.put_git_blob_stream(
                identity, body.len() as u64, commitment(body), body.len() as u64,
                &mut LateFailure { remaining: body }, &mut || true,
            ),
            Err(NodeRefusal::Fabric(error))
                if matches!(*error, StoreRefusal::StorageIo { .. })
        ));
        if already_present {
            assert_stream(&node, identity, body);
        } else {
            assert!(matches!(
                node.git_object_header(identity),
                Err(NodeRefusal::Fabric(error)) if matches!(*error, StoreRefusal::ObjectAbsent)
            ));
            assert_eq!(
                node.put_git_blob_stream(
                    identity,
                    body.len() as u64,
                    commitment(body),
                    body.len() as u64,
                    &mut Cursor::new(body),
                    &mut || true,
                )
                .unwrap(),
                StoredObject::Created(identity),
            );
        }
    }
    let after = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap();
    assert_eq!(after.receipt(), before.receipt());
    node.shutdown().unwrap();
}
