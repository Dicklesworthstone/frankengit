//! The real authenticated listener composes LFS custody with ordinary receive.
use std::collections::BTreeMap;

use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_git_object::ObjectType;
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, PackLimits, PackPlanner, PackWriteError,
    PackWriteProfile, PackWriter,
};
use fgit_types::{GitOid, RefName};
use fgit_wire::smart_http::{BodyDecoder, BodyFraming, HttpLimits};
use fgit_wire::{Packet, WireLimits, encode_packets};

use super::*;

fn receive_server(node: OneNode, credentials: PathBuf, sessions: usize) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let route = String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec()).unwrap();
    let worker = thread::spawn(move || {
        let result = node.serve_smart_http_with_credentials_file_bounded(
            &listener,
            GitDaemonServerLimits::try_new(sessions, 1).unwrap(),
            &credentials,
            true,
            Duration::from_secs(15),
        );
        node.shutdown().unwrap();
        result.unwrap()
    });
    Server {
        address,
        route,
        worker: Some(worker),
    }
}

fn policy_credentials(path: &Path, incarnation: RepositoryIncarnationId) {
    let table = format!(
        "frankengit-http-credentials-v1 {TENANT} {REPOSITORY} {incarnation}\n{} {} read,receive,lfs-read,lfs-write\n",
        hex(&sha256_digest("a".repeat(64).as_bytes())),
        PrincipalId::from_bytes([0x61; 16]),
    );
    fs::write(path, table).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[derive(Default)]
struct Objects(BTreeMap<GitOid, CanonicalPackObject>);
impl CanonicalObjectSource for Objects {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        self.0
            .get(id)
            .cloned()
            .ok_or(PackWriteError::MissingCanonicalObject(*id))
    }
}
impl Objects {
    fn add(&mut self, format: GitHashAlgorithm, kind: ObjectType, body: Vec<u8>) -> GitOid {
        let crypto = match kind {
            ObjectType::Blob => GitObjectKind::Blob,
            ObjectType::Tree => GitObjectKind::Tree,
            ObjectType::Commit => GitObjectKind::Commit,
            ObjectType::Tag => GitObjectKind::Tag,
        };
        let id = git_object_id(format, crypto, &body);
        self.0.insert(
            id,
            CanonicalPackObject::new(id, kind, body, Vec::new(), 0, 0),
        );
        id
    }
    fn pack(&self, format: GitHashAlgorithm) -> Vec<u8> {
        let limits = PackLimits::default();
        let ids: Vec<_> = self.0.keys().copied().collect();
        let plan = PackPlanner::new(format, PackWriteProfile::STORED_V1, limits.clone())
            .plan_selected(self, &ids, &mut || true)
            .unwrap();
        PackWriter::new(limits)
            .write(&plan, &mut || true)
            .unwrap()
            .0
    }
}

fn pointer_graph(format: GitHashAlgorithm, object: LfsObject) -> (GitOid, GitOid, Vec<u8>) {
    let mut objects = Objects::default();
    let blob = objects.add(format, ObjectType::Blob, object.pointer().into_bytes());
    let mut tree = b"100644 asset.bin\0".to_vec();
    tree.extend_from_slice(blob.as_bytes());
    let tree = objects.add(format, ObjectType::Tree, tree);
    let commit = objects.add(format, ObjectType::Commit, format!(
        "tree {tree}\nauthor A <a@example.com> 1 +0000\ncommitter A <a@example.com> 1 +0000\n\nLFS receive policy\n",
    ).into_bytes());
    (commit, blob, objects.pack(format))
}

fn push(
    server: &Server,
    format: GitHashAlgorithm,
    reference: &str,
    commit: GitOid,
    pack: &[u8],
    key: &str,
) -> String {
    let zero = "0".repeat(format.digest_len() * 2);
    let mut body = encode_packets(
        &[
            Packet::Data(
                format!(
                    "{zero} {commit} {reference}\0report-status object-format={}",
                    format.as_str()
                )
                .into_bytes(),
            ),
            Packet::Flush,
        ],
        &WireLimits::default(),
    )
    .unwrap();
    body.extend_from_slice(pack);
    let mut stream = server.request("POST", "/git-receive-pack", 'a', &format!(
        "Content-Type: application/x-git-receive-pack-request\r\nContent-Length: {}\r\nIdempotency-Key: {key}\r\n", body.len(),
    ));
    stream.write_all(&body).unwrap();
    let head = head(&mut stream, 200);
    let mut wire = Vec::new();
    (&mut stream)
        .take(64 * 1024)
        .read_to_end(&mut wire)
        .unwrap();
    let body = if head.contains("Transfer-Encoding: chunked") {
        let mut decoder = BodyDecoder::new(BodyFraming::Chunked, HttpLimits::default()).unwrap();
        let mut body = Vec::new();
        let mut cursor = 0;
        while cursor < wire.len() {
            let step = decoder.push(&wire[cursor..]).unwrap();
            assert!(step.consumed > 0);
            cursor += step.consumed;
            body.extend_from_slice(step.data);
        }
        decoder.finish().unwrap();
        body
    } else {
        assert_eq!(wire.len() as u64, content_length(&head));
        wire
    };
    String::from_utf8(body).unwrap()
}

fn upload(server: &Server, object: LfsObject, payload: &[u8]) {
    let suffix = format!("/info/lfs/objects/{}/{}", object.oid, object.size);
    let mut stream = server.request(
        "PUT",
        &suffix,
        'a',
        &format!(
            "Content-Type: application/octet-stream\r\nContent-Length: {}\r\n",
            payload.len(),
        ),
    );
    stream.write_all(payload).unwrap();
    assert_eq!(small_response(&mut stream, 200), "");
}

fn reopened(config: &NodeConfig) -> OneNode {
    let mut node = OneNode::open_existing(config.clone()).unwrap();
    let generation = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap()
        .receipt()
        .generation();
    node.bring_into_service(generation).unwrap();
    node
}

fn assert_refs(node: &OneNode, expected: &[(&str, GitOid)]) -> HeadGeneration {
    let materialized = node
        .runtime()
        .block_on(node.materialize_admission())
        .unwrap();
    let wanted = expected
        .iter()
        .map(|(name, id)| (RefName::try_new(name.as_bytes()).unwrap(), *id))
        .collect();
    assert_eq!(materialized.snapshot().refs, wanted);
    materialized.basis().generation()
}

fn custody_files(path: &Path) -> Vec<PathBuf> {
    fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .flat_map(|path| {
            if path.is_dir() {
                custody_files(&path)
            } else {
                vec![path]
            }
        })
        .collect()
}

#[test]
fn authenticated_http_push_requires_lfs_payloads_and_keeps_policy_after_cold_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let config = scratch
            .config()
            .with_object_format(format)
            .with_receive_lfs_root(scratch.0.join("lfs"));
        let (mut node, _) = OneNode::init(config.clone()).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let initial = assert_refs(&node, &[]);
        let grants = scratch.0.join("credentials");
        policy_credentials(&grants, node.repository_incarnation_id());
        let payload = b"a retained LFS asset delivered through the real HTTP listener";
        let object = LfsObject {
            oid: LfsOid::of_payload(payload),
            size: payload.len() as u64,
        };
        let (commit, blob, pack) = pointer_graph(format, object);
        let main = "refs/heads/main";
        let copy = "refs/heads/copied";

        let server = receive_server(node, grants.clone(), 1);
        let refused = push(&server, format, main, commit, &pack, "original-lfs-push");
        assert!(
            refused
                .contains("ng refs/heads/main missing necessary objects (ObjectClosureIncomplete)"),
            "{refused}"
        );
        assert!(!refused.contains("\nok refs/"));
        assert_eq!(server.finish().refused_sessions(), 1);
        let node = reopened(&config);
        assert_eq!(assert_refs(&node, &[]), initial);
        assert!(
            node.read_git_object(blob).is_err(),
            "a missing LFS object refuses before Git placement"
        );

        let server = receive_server(node, grants.clone(), 2);
        upload(&server, object, payload);
        let accepted = push(&server, format, main, commit, &pack, "original-lfs-push");
        assert!(accepted.contains("ok refs/heads/main\n"), "{accepted}");
        assert_eq!(server.finish().completed_sessions(), 2);
        let node = reopened(&config);
        let published = assert_refs(&node, &[(main, commit)]);
        assert_ne!(published, initial);
        assert_eq!(
            node.read_git_object(blob).unwrap().payload(),
            object.pointer().as_bytes()
        );

        // Simulate loss of immutable payload custody with writers stopped.
        // A checksummed empty pack reuses the old Git graph; it must still
        // discover the pointer and refuse its new branch, even after reopen.
        let path = custody_files(&scratch.0.join("lfs")).pop().unwrap();
        fs::remove_file(path).unwrap();
        let empty = Objects::default().pack(format);
        let server = receive_server(node, grants.clone(), 1);
        let refused = push(&server, format, copy, commit, &empty, "copied-lfs-push");
        assert!(
            refused.contains(
                "ng refs/heads/copied missing necessary objects (ObjectClosureIncomplete)"
            ),
            "{refused}"
        );
        assert_eq!(server.finish().refused_sessions(), 1);
        let node = reopened(&config);
        assert_eq!(assert_refs(&node, &[(main, commit)]), published);

        let server = receive_server(node, grants.clone(), 2);
        upload(&server, object, payload);
        let accepted = push(&server, format, copy, commit, &empty, "copied-lfs-push");
        assert!(accepted.contains("ok refs/heads/copied\n"), "{accepted}");
        assert_eq!(server.finish().completed_sessions(), 2);
        let node = reopened(&config);
        assert_refs(&node, &[(main, commit), (copy, commit)]);
        assert_eq!(
            node.read_git_object(blob).unwrap().payload(),
            object.pointer().as_bytes()
        );
        node.shutdown().unwrap();
    }
}
