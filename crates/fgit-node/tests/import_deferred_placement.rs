#![forbid(unsafe_code)]
//! Real source imports retain private custody until ordinary admission commits.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_admission::{AdmissionLimits, AdmissionResult};
use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest, sha256_digest};
use fgit_forge::aggregate::ExpectedVersion;
use fgit_forge::event::protection::{ProtectionCommand, ReviewProtection, compile_ref_policy};
use fgit_node::{LoopbackReceiveSession, NodeConfig, NodeRefusal, OneNode};
use fgit_object_fabric::fabric::StoreRefusal;
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RefName, RefusalCode,
    RepositoryId, TenantId,
};

const PRINCIPAL: PrincipalId = PrincipalId::from_bytes([0x73; 16]);
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-import-deferred-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }

    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(
            self.0.join("node"),
            TenantId::from_bytes([0x71; 16]),
            RepositoryId::from_bytes([0x72; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(2)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn stored_zlib(bytes: &[u8]) -> Vec<u8> {
    let mut result = vec![0x78, 0x01];
    let chunks = bytes.chunks(65_535);
    let count = chunks.len();
    for (index, chunk) in chunks.enumerate() {
        result.push(u8::from(index + 1 == count));
        let length = u16::try_from(chunk.len()).unwrap();
        result.extend(length.to_le_bytes());
        result.extend((!length).to_le_bytes());
        result.extend(chunk);
    }
    let (a, b) = bytes.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521;
        (a, (b + a) % 65_521)
    });
    result.extend(((b << 16) | a).to_be_bytes());
    result
}

struct Source {
    root: PathBuf,
    format: GitHashAlgorithm,
    reference: String,
    tip: GitOid,
    objects: BTreeMap<GitOid, (GitObjectKind, Vec<u8>)>,
}

impl Source {
    fn new(root: PathBuf, format: GitHashAlgorithm, reference: &str, payload: Vec<u8>) -> Self {
        fs::create_dir_all(&root).unwrap();
        let mut objects = BTreeMap::new();
        let mut put = |kind, body: Vec<u8>| {
            let id = git_object_id(format, kind, &body);
            objects.insert(id, (kind, body));
            id
        };
        let blob = put(GitObjectKind::Blob, payload);
        let shared = put(GitObjectKind::Blob, b"shared canonical object\n".to_vec());
        let tree = put(
            GitObjectKind::Tree,
            [
                b"100644 file\0".as_slice(),
                blob.as_bytes(),
                b"100644 shared\0",
                shared.as_bytes(),
            ]
            .concat(),
        );
        let tip = put(
            GitObjectKind::Commit,
            format!(
                "tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nimport custody\n"
            )
            .into_bytes(),
        );
        for (id, (kind, body)) in &objects {
            let hex = id.to_string();
            let path = root.join("objects").join(&hex[..2]).join(&hex[2..]);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let bytes = [
                format!("{} {}\0", kind.label(), body.len()).as_bytes(),
                body,
            ]
            .concat();
            fs::write(path, stored_zlib(&bytes)).unwrap();
        }
        let mut source = Self {
            root,
            format,
            reference: String::new(),
            tip,
            objects,
        };
        source.set_ref(reference);
        source
    }

    fn set_ref(&mut self, reference: &str) {
        if !self.reference.is_empty() {
            fs::remove_file(self.root.join(&self.reference)).unwrap();
        }
        let path = self.root.join(reference);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, format!("{}\n", self.tip)).unwrap();
        fs::write(self.root.join("HEAD"), format!("ref: {reference}\n")).unwrap();
        self.reference = reference.to_owned();
    }

    fn bytes(&self) -> u64 {
        self.objects
            .values()
            .map(|(_, body)| body.len() as u64)
            .sum()
    }

    fn pack(&self) {
        let mut pack = b"PACK\0\0\0\x02".to_vec();
        pack.extend(u32::try_from(self.objects.len()).unwrap().to_be_bytes());
        let mut entries = Vec::new();
        for (id, (kind, body)) in &self.objects {
            let offset = pack.len();
            let kind = match kind {
                GitObjectKind::Commit => 1_u8,
                GitObjectKind::Tree => 2,
                GitObjectKind::Blob => 3,
                GitObjectKind::Tag => 4,
            };
            let mut size = body.len();
            let mut byte = kind << 4 | (size as u8 & 15);
            size >>= 4;
            while size != 0 {
                pack.push(byte | 128);
                byte = size as u8 & 127;
                size >>= 7;
            }
            pack.push(byte);
            pack.extend(stored_zlib(body));
            let mut crc = !0_u32;
            for byte in &pack[offset..] {
                crc ^= u32::from(*byte);
                for _ in 0..8 {
                    crc = (crc >> 1) ^ (0xedb8_8320_u32 & (0_u32.wrapping_sub(crc & 1)));
                }
            }
            entries.push((*id, !crc, u32::try_from(offset).unwrap()));
        }
        let digest = |bytes: &[u8]| match self.format {
            GitHashAlgorithm::Sha1 => sha1_digest(bytes).to_vec(),
            GitHashAlgorithm::Sha256 => sha256_digest(bytes).to_vec(),
        };
        let checksum = digest(&pack);
        pack.extend(&checksum);
        let mut index = b"\xfftOc\0\0\0\x02".to_vec();
        for byte in 0_u16..256 {
            index.extend(
                u32::try_from(
                    entries
                        .iter()
                        .filter(|(id, _, _)| u16::from(id.as_bytes()[0]) <= byte)
                        .count(),
                )
                .unwrap()
                .to_be_bytes(),
            );
        }
        for (id, _, _) in &entries {
            index.extend(id.as_bytes());
        }
        for (_, crc, _) in &entries {
            index.extend(crc.to_be_bytes());
        }
        for (_, _, offset) in &entries {
            index.extend(offset.to_be_bytes());
        }
        index.extend(checksum);
        let checksum = digest(&index);
        index.extend(checksum);
        let directory = self.root.join("objects/pack");
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("fixture.pack"), pack).unwrap();
        fs::write(directory.join("fixture.idx"), index).unwrap();
        for id in self.objects.keys() {
            let hex = id.to_string();
            fs::remove_file(self.root.join("objects").join(&hex[..2]).join(&hex[2..])).unwrap();
        }
    }
}

fn import(node: &OneNode, source: &Source, key: &[u8], explicit: bool) -> AdmissionResult {
    if explicit {
        let request = node
            .import_request_context_with_byte_limit(None, source.bytes())
            .unwrap();
        node.runtime()
            .block_on(node.import_loose_git_directory_with_byte_limit_durable_in(
                &request,
                &source.root,
                PRINCIPAL,
                key,
                source.bytes(),
            ))
            .unwrap()
    } else {
        let request = node.import_request_context(None);
        node.runtime()
            .block_on(node.import_loose_git_directory_durable_in(
                &request,
                &source.root,
                PRINCIPAL,
                key,
            ))
            .unwrap()
    }
}

fn refs(node: &OneNode) -> BTreeMap<RefName, GitOid> {
    node.runtime()
        .block_on(node.materialize_admission())
        .unwrap()
        .snapshot()
        .refs
        .clone()
}

fn clean(node: &OneNode) {
    assert_eq!(
        fs::read_dir(node.storage_root().join("staging"))
            .unwrap()
            .count(),
        0
    );
    assert!(!fs::read_dir(node.storage_root()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".fg-import-quarantine-")
    }));
}

fn assert_stored(node: &OneNode, source: &Source) {
    for (id, (_, body)) in &source.objects {
        assert_eq!(node.read_git_object(*id).unwrap().payload(), body);
    }
}

fn assert_unselected_absent(node: &OneNode, source: &Source, existing: &Source) {
    for id in source
        .objects
        .keys()
        .filter(|id| !existing.objects.contains_key(*id))
    {
        assert!(
            matches!(node.read_git_object(*id), Err(NodeRefusal::Fabric(error))
            if matches!(*error, StoreRefusal::ObjectAbsent)),
            "new object {id} escaped private custody"
        );
    }
    assert_stored(node, existing);
    clean(node);
}

fn install_policy(node: &OneNode) {
    let request = node.request_context();
    let before = node
        .runtime()
        .block_on(node.read_review_protection_in(&request))
        .unwrap();
    let command = ProtectionCommand {
        expected_version: before.version().map_or(ExpectedVersion::NewStream, ExpectedVersion::Exactly),
        expected_epoch: before.policy_epoch,
        protection: ReviewProtection {
            administrators: vec![PRINCIPAL],
            branches: Vec::new(),
            ref_policy: Some(compile_ref_policy(
                "policy import_guard { rule restricted { when ref.name matches \"refs/heads/restricted\" then deny \"reserved namespace\" } default allow }",
            ).unwrap()),
        },
    };
    let session = LoopbackReceiveSession::authenticated(
        PRINCIPAL,
        IdempotencyKey::new(b"import-policy".to_vec()).unwrap(),
    );
    let (_, terminal) = node
        .runtime()
        .block_on(node.admit_review_protection_durable_in(
            &request,
            &session,
            &command,
            AdmissionLimits::default(),
        ))
        .unwrap();
    assert!(matches!(
        terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
}

#[test]
fn refused_loose_and_packed_imports_abandon_new_objects_and_recover_the_original_outcome() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for explicit in [false, true] {
            for (reference, expected) in [
                ("refs/heads/main", RefusalCode::ExpectedOldRefMismatch),
                ("refs/heads/main/child", RefusalCode::RefNameConflict),
                (
                    "refs/heads/restricted",
                    RefusalCode::ProtectedRefTransitionDenied,
                ),
            ] {
                let scratch = Scratch::new();
                let config = scratch.config(format);
                let (mut node, _) = OneNode::init(config.clone()).unwrap();
                node.bring_into_service(HeadGeneration::FIRST).unwrap();
                let baseline = Source::new(
                    scratch.0.join("baseline"),
                    format,
                    "refs/heads/main",
                    b"original".to_vec(),
                );
                assert!(matches!(
                    import(&node, &baseline, b"initial", explicit).commands[0]
                        .terminal
                        .outcome,
                    DecisionOutcome::Committed { .. }
                ));
                install_policy(&node);
                let before = refs(&node);
                let mut incoming = Source::new(
                    scratch.0.join("incoming"),
                    format,
                    reference,
                    b"new unselected content".to_vec(),
                );
                if explicit {
                    incoming.pack();
                }
                let refused = import(&node, &incoming, b"refused-import", explicit);
                assert!(
                    matches!(refused.commands[0].terminal.outcome, DecisionOutcome::Refused { code, .. } if code == expected)
                );
                assert_eq!(refs(&node), before);
                assert_unselected_absent(&node, &incoming, &baseline);
                node.shutdown().unwrap();

                let mut node = OneNode::open_existing(config.clone()).unwrap();
                let head = node
                    .runtime()
                    .block_on(node.authenticate_authority_head())
                    .unwrap();
                node.bring_into_service(head.receipt().generation())
                    .unwrap();
                let retry = import(&node, &incoming, b"refused-import", explicit);
                assert_eq!(retry.commands[0].terminal, refused.commands[0].terminal);
                assert_eq!(refs(&node), before);
                assert_unselected_absent(&node, &incoming, &baseline);

                incoming.set_ref("refs/heads/allowed");
                let accepted = import(&node, &incoming, b"allowed-import", explicit);
                assert!(matches!(
                    accepted.commands[0].terminal.outcome,
                    DecisionOutcome::Committed { .. }
                ));
                assert_stored(&node, &incoming);
                assert_stored(&node, &baseline);
                clean(&node);
                node.shutdown().unwrap();

                let mut node = OneNode::open_existing(config).unwrap();
                let head = node
                    .runtime()
                    .block_on(node.authenticate_authority_head())
                    .unwrap();
                node.bring_into_service(head.receipt().generation())
                    .unwrap();
                let retry = import(&node, &incoming, b"allowed-import", explicit);
                assert_eq!(retry.commands[0].terminal, accepted.commands[0].terminal);
                assert_stored(&node, &incoming);
                clean(&node);
                node.shutdown().unwrap();
            }
        }
    }
}

#[test]
fn objects_larger_than_the_placement_chunk_stay_private_until_an_allowed_import_commits() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (mut node, _) = OneNode::init(scratch.config(format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let baseline = Source::new(
            scratch.0.join("baseline"),
            format,
            "refs/heads/main",
            b"original".to_vec(),
        );
        import(&node, &baseline, b"initial", false);
        let mut incoming = Source::new(
            scratch.0.join("large"),
            format,
            "refs/heads/main",
            vec![b'x'; 8 * 1024 * 1024 + 1],
        );
        let refused = import(&node, &incoming, b"large-refused", false);
        assert!(matches!(
            refused.commands[0].terminal.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::ExpectedOldRefMismatch,
                ..
            }
        ));
        assert_unselected_absent(&node, &incoming, &baseline);
        incoming.set_ref("refs/heads/large");
        assert!(matches!(
            import(&node, &incoming, b"large-allowed", true).commands[0]
                .terminal
                .outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert_stored(&node, &incoming);
        clean(&node);
        node.shutdown().unwrap();
    }
}
