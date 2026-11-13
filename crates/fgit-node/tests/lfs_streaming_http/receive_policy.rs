//! The real authenticated listener composes LFS custody with ordinary receive.
use std::collections::BTreeMap;
use std::io::{Seek, SeekFrom};

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
    fn graph(
        &mut self,
        format: GitHashAlgorithm,
        body: Vec<u8>,
        message: &str,
    ) -> (GitOid, GitOid) {
        let blob = self.add(format, ObjectType::Blob, body);
        let mut tree = b"100644 asset.bin\0".to_vec();
        tree.extend_from_slice(blob.as_bytes());
        let tree = self.add(format, ObjectType::Tree, tree);
        let commit = self.add(format, ObjectType::Commit, format!(
            "tree {tree}\nauthor A <a@example.com> 1 +0000\ncommitter A <a@example.com> 1 +0000\n\n{message}\n",
        ).into_bytes());
        (commit, blob)
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
    push_commands(server, format, &[(reference, commit)], pack, key)
}

fn push_commands(
    server: &Server,
    format: GitHashAlgorithm,
    commands: &[(&str, GitOid)],
    pack: &[u8],
    key: &str,
) -> String {
    let mut stream = receive_request(server, format, commands, pack, key);
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

fn receive_request(
    server: &Server,
    format: GitHashAlgorithm,
    commands: &[(&str, GitOid)],
    pack: &[u8],
    key: &str,
) -> TcpStream {
    assert!(!commands.is_empty());
    let zero = "0".repeat(format.digest_len() * 2);
    let mut packets = Vec::with_capacity(commands.len() + 1);
    for (index, (reference, commit)) in commands.iter().enumerate() {
        let mut command = format!("{zero} {commit} {reference}");
        if index == 0 {
            // Deliberately omit `atomic`: quarantine validation must finish
            // before even the first otherwise-valid sibling can publish.
            command.push_str(&format!(
                "\0report-status object-format={}",
                format.as_str()
            ));
        }
        packets.push(Packet::Data(command.into_bytes()));
    }
    packets.push(Packet::Flush);
    let mut body = encode_packets(&packets, &WireLimits::default()).unwrap();
    body.extend_from_slice(pack);
    let mut stream = server.request("POST", "/git-receive-pack", 'a', &format!(
        "Content-Type: application/x-git-receive-pack-request\r\nContent-Length: {}\r\nIdempotency-Key: {key}\r\n", body.len(),
    ));
    stream.write_all(&body).unwrap();
    stream
}

fn assert_malformed_pointer_refused(
    server: &Server,
    format: GitHashAlgorithm,
    reference: &str,
    commit: GitOid,
    pack: &[u8],
    key: &str,
) {
    let mut stream = receive_request(server, format, &[(reference, commit)], pack, key);
    // ObjectHeaderInvalid follows the transport's fatal receive path, with
    // its exact HTTP 400 plain-text refusal and no per-command report-status.
    let header = head(&mut stream, 400);
    assert!(
        header
            .lines()
            .any(|line| line == "Content-Type: text/plain; charset=utf-8"),
        "{header}"
    );
    let expected = b"Smart HTTP request refused\n";
    assert_eq!(content_length(&header), expected.len() as u64);
    let mut body = vec![0; expected.len()];
    stream.read_exact(&mut body).unwrap();
    assert_eq!(body.as_slice(), expected);
    assert_eq!(
        stream.read(&mut [0; 1]).unwrap(),
        0,
        "exact fatal response EOF"
    );
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

fn assert_unpublished(
    config: &NodeConfig,
    generation: HeadGeneration,
    objects: &Objects,
) -> OneNode {
    let node = reopened(config);
    assert_eq!(assert_refs(&node, &[]), generation);
    for id in objects.0.keys() {
        assert!(
            node.read_git_object(*id).is_err(),
            "refused receive must not promote native object {id}"
        );
    }
    node
}

fn assert_refused(response: &str, references: &[&str], code: &str) {
    for reference in references {
        assert!(response.contains(&format!("ng {reference} ")), "{response}");
    }
    assert!(response.contains(&format!("({code})")), "{response}");
    assert!(!response.contains("ok refs/"), "{response}");
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

#[test]
fn corrupt_or_unsupported_lfs_refuses_the_entire_receive_before_any_promotion() {
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

        let payload = b"uploaded custody must verify its actual retained payload bytes";
        let object = LfsObject {
            oid: LfsOid::of_payload(payload),
            size: payload.len() as u64,
        };
        let server = receive_server(node, grants.clone(), 1);
        upload(&server, object, payload);
        assert_eq!(server.finish().completed_sessions(), 1);

        // The upload completed and its listener shut down. Preserve the
        // immutable file's length and header while corrupting one payload byte.
        let files = custody_files(&scratch.0.join("lfs"));
        assert_eq!(files.len(), 1, "one completed immutable LFS object");
        let mut retained = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&files[0])
            .unwrap();
        let length = retained.metadata().unwrap().len();
        assert!(length >= payload.len() as u64);
        retained.seek(SeekFrom::End(-1)).unwrap();
        let mut byte = [0_u8];
        retained.read_exact(&mut byte).unwrap();
        byte[0] ^= 0x40;
        retained.seek(SeekFrom::End(-1)).unwrap();
        retained.write_all(&byte).unwrap();
        retained.sync_all().unwrap();
        assert_eq!(retained.metadata().unwrap().len(), length);
        drop(retained);

        let mut corrupt = Objects::default();
        let (commit, _) = corrupt.graph(format, object.pointer().into_bytes(), "corrupt custody");
        let pack = corrupt.pack(format);
        let node = reopened(&config);
        assert_eq!(assert_refs(&node, &[]), initial);
        let server = receive_server(node, grants.clone(), 1);
        let rejected = push(
            &server,
            format,
            "refs/heads/corrupt",
            commit,
            &pack,
            "corrupt-lfs-custody",
        );
        assert_refused(&rejected, &["refs/heads/corrupt"], "EvidenceInvalid");
        assert_eq!(server.finish().refused_sessions(), 1);
        let mut node = assert_unpublished(&config, initial, &corrupt);

        // These are recognizable pointers, including historical and extension
        // spellings. Unsupported forms must not become ordinary Git blobs.
        let pointer = object.pointer();
        for (case, body) in [
            ("unsupported-version", pointer.replace("/v1", "/v2")),
            (
                "noncanonical-size",
                pointer.replace(
                    &format!("size {}", object.size),
                    &format!("size 0{}", object.size),
                ),
            ),
            (
                "legacy-pointer",
                pointer.replace(
                    "https://git-lfs.github.com/spec/v1",
                    "http://git-media.io/v/2",
                ),
            ),
            (
                "extension-pointer",
                format!("ext-0-transform sha256:{}\n{pointer}", object.oid),
            ),
        ] {
            let mut unsupported = Objects::default();
            let (commit, _) = unsupported.graph(format, body.into_bytes(), case);
            let pack = unsupported.pack(format);
            let server = receive_server(node, grants.clone(), 1);
            assert_malformed_pointer_refused(
                &server,
                format,
                "refs/heads/unsupported",
                commit,
                &pack,
                case,
            );
            assert_eq!(server.finish().refused_sessions(), 1);
            node = assert_unpublished(&config, initial, &unsupported);
        }

        let valid_ref = "refs/heads/valid";
        let blocked_ref = "refs/heads/blocked";
        let valid_body = b"ordinary Git sibling must wait for the complete quarantine verdict\n";
        let missing_payload = b"this distinct LFS object has never been uploaded";
        let missing = LfsObject {
            oid: LfsOid::of_payload(missing_payload),
            size: missing_payload.len() as u64,
        };
        let mut mixed = Objects::default();
        let (valid_commit, _) = mixed.graph(format, valid_body.to_vec(), "valid sibling");
        let (blocked_commit, _) =
            mixed.graph(format, missing.pointer().into_bytes(), "missing sibling");
        let pack = mixed.pack(format);
        let server = receive_server(node, grants.clone(), 1);
        let rejected = push_commands(
            &server,
            format,
            &[(valid_ref, valid_commit), (blocked_ref, blocked_commit)],
            &pack,
            "non-atomic-mixed-lfs",
        );
        assert_refused(
            &rejected,
            &[valid_ref, blocked_ref],
            "ObjectClosureIncomplete",
        );
        assert_eq!(server.finish().refused_sessions(), 1);
        let node = assert_unpublished(&config, initial, &mixed);

        // A near-identical non-atomic request succeeds when both graphs are
        // ordinary content. The first sibling is byte-identical to the one
        // above, and unrelated corrupt LFS custody cannot block normal Git.
        let mut permitted = Objects::default();
        let (same_valid_commit, _) = permitted.graph(format, valid_body.to_vec(), "valid sibling");
        assert_eq!(same_valid_commit, valid_commit);
        let (other_commit, _) = permitted.graph(
            format,
            b"ordinary replacement for the absent LFS pointer\n".to_vec(),
            "permitted sibling",
        );
        let pack = permitted.pack(format);
        let server = receive_server(node, grants, 1);
        let accepted = push_commands(
            &server,
            format,
            &[(valid_ref, valid_commit), (blocked_ref, other_commit)],
            &pack,
            "non-atomic-permitted-lfs",
        );
        for reference in [valid_ref, blocked_ref] {
            assert!(
                accepted.contains(&format!("ok {reference}\n")),
                "{accepted}"
            );
        }
        assert!(!accepted.contains("ng refs/"), "{accepted}");
        assert_eq!(server.finish().completed_sessions(), 1);
        let node = reopened(&config);
        assert_ne!(
            assert_refs(
                &node,
                &[(valid_ref, valid_commit), (blocked_ref, other_commit)]
            ),
            initial
        );
        for (id, object) in &permitted.0 {
            assert_eq!(node.read_git_object(*id).unwrap().payload(), object.body());
        }
        node.shutdown().unwrap();
    }
}
