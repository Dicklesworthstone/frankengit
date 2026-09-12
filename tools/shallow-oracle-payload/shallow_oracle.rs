//! Optional real-client campaign; no upstream Git in production.
use super::*;
use super::partial_oracle::{checked, command, inventory, live_client};
use std::process::Command;

type Revision = (GitOid, GitOid, GitOid);

fn markers(run: &str, client: &str) -> BTreeSet<GitOid> {
    let path = PathBuf::from(run).join("work").join(client).join(".git/shallow");
    match std::fs::read_to_string(&path) {
        Ok(text) => text.lines().map(|line| {
            let format = match line.len() { 40 => GitHashAlgorithm::Sha1, 64 => GitHashAlgorithm::Sha256, _ => panic!("invalid shallow file identity") };
            GitOid::from_hex(format, line).unwrap()
        }).collect(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeSet::new(),
        Err(error) => panic!("shallow file read failed: {error}"),
    }
}

fn history(run: &str, client: &str) -> BTreeSet<String> {
    String::from_utf8(checked(command(run, "history", client, &[]))).unwrap().lines().map(str::to_owned).collect()
}

fn append(node: &OneNode, parent: GitOid, foreign: GitOid, serial: usize) -> Revision {
    let body = format!("shallow native next revision {serial}\n").into_bytes();
    let blob = node.put_git_object(ObjectType::Blob, body).unwrap().identity();
    let tree = node.put_git_object(ObjectType::Tree, tree_bytes(&[(b"100644", b"public", blob), (b"160000", b"submodule", foreign)])).unwrap().identity();
    let commit = node.put_git_object(ObjectType::Commit, commit_bytes(tree, &[parent])).unwrap().identity();
    let request = node.request_context();
    let current = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
    let mut objects = current.selected_closure().closure().objects().clone();
    objects.extend([commit, tree, blob]);
    let closure = ValidatedClosure {
        object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(objects.clone())).unwrap(), objects,
    };
    let receipt = SourceImportReceipt { object_format: node.object_format, object_count: closure.objects.len().try_into().unwrap(), delete_only: false, origin: SourceImportOrigin::LocalGitDirectory };
    let updates = [SourceRefUpdate { old: parent, new: commit, ref_name: b"refs/heads/public".to_vec() }];
    let validated = validate_source_import(&updates, &receipt, closure).unwrap();
    let context = AdmissionContext {
        head_key: node.head_key.clone(), tenant_id: node.tenant_id(), repository_id: node.repository_id(),
        principal_id: PrincipalId::from_bytes([0x64;16]),
        idempotency_key: IdempotencyKey::new(format!("shallow-oracle-append-{serial}").into_bytes()).unwrap(),
        object_format: node.object_format,
    };
    let result = node.runtime().block_on(node.admit_validated_source_import_durable_in(&request, &context, &validated, AdmissionLimits::default())).unwrap();
    assert!(result.commands.iter().all(|command| matches!(command.terminal.outcome, fgit_types::DecisionOutcome::Committed { .. })));
    (commit, tree, blob)
}

#[test]
#[ignore = "requires source/binary-verified Git 2.54.0 and Bubblewrap via FGIT_ORACLE_ROOT"]
fn pinned_git_shallow_clone_deepen_incremental_fetch_and_unshallow() {
    let oracle = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/e2e/oracle/oracle.sh");
    let output = Command::new(&oracle).args(["create-run", "git-2.54.0", "shallow-node"]).output().unwrap();
    assert!(output.status.success(), "verified oracle unavailable: {}", String::from_utf8_lossy(&output.stderr));
    let run = String::from_utf8(output.stdout).unwrap().trim().to_owned();
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture { scratch, mut node, config, public, private, private_blob, ancestor, .. } = fixture(format);
        delete_private(&node, private);
        let root_blob = git_object_id(format, GitObjectKind::Blob, b"common ancestor body");
        let root_tree = git_object_id(format, GitObjectKind::Tree, &tree_bytes(&[(b"100644", b"common", root_blob)]));
        let public_blob = git_object_id(format, GitObjectKind::Blob, b"current public content");
        let public_tree = git_object_id(format, GitObjectKind::Tree, &tree_bytes(&[(b"100644", b"public", public_blob), (b"160000", b"submodule", private)]));
        let mut revisions = vec![(ancestor, root_tree, root_blob), (public, public_tree, public_blob)];
        for serial in 0..2 {
            revisions.push(append(&node, revisions.last().unwrap().0, private, serial));
        }
        node.shutdown().unwrap();
        node = OneNode::open_existing(config).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let repository = String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec()).unwrap();
        let mut serial = 2;
        for version in ["0", "1", "2"] {
            for (name, profile) in [("full", "1"), ("blobless", "1,blob:none"), ("treeless", "1,tree:0")] {
                let client = format!("shallow-{}-{version}-{name}", format.as_str());
                let tip = *revisions.last().unwrap();
                let old_parent = revisions[revisions.len()-2].0;
                let expected_file = node.read_git_object(tip.2).unwrap().payload().to_vec();
                let context = node.request_context();
                let before = node.runtime().block_on(node.materialize_admission_in(&context)).unwrap();
                let (returned, _) = live_client(node, &listener, command(&run, "shallow-clone", &client, &[&endpoint, &repository, version, profile]));
                node = returned;
                let mut expected = BTreeSet::from([tip.0.to_string()]);
                if name != "treeless" { expected.insert(tip.1.to_string()); }
                if name == "full" { expected.insert(tip.2.to_string()); }
                assert_eq!(inventory(&run, &client), expected, "initial depth-one pack contains no ancestor content and obeys its filter");
                assert_eq!(markers(&run, &client), BTreeSet::from([tip.0]));
                assert_eq!(history(&run, &client), BTreeSet::from([tip.0.to_string()]));
                checked(command(&run, "fsck", &client, &[]));
                let checkout = command(&run, "checkout", &client, &[&endpoint, &repository, version, &tip.0.to_string()]);
                if name == "full" { checked(checkout); } else {
                    let (returned, _) = live_client(node, &listener, checkout); node = returned;
                }
                assert_eq!(std::fs::read(PathBuf::from(&run).join("work").join(&client).join("public")).unwrap(), expected_file);
                assert_eq!(inventory(&run, &client), BTreeSet::from([tip.0.to_string(), tip.1.to_string(), tip.2.to_string()]), "checkout hydrates its own snapshot without crossing the shallow boundary");
                let (returned, _) = live_client(node, &listener, command(&run, "depth", &client, &[&endpoint, &repository, version, "2"]));
                node = returned;
                assert_eq!(markers(&run, &client), BTreeSet::from([old_parent]));
                assert_eq!(history(&run, &client), BTreeSet::from([tip.0.to_string(), old_parent.to_string()]), "depth change on an already-common tip must supply its missing ancestor");
                checked(command(&run, "fsck", &client, &[]));
                let context = node.request_context();
                let after_reads = node.runtime().block_on(node.materialize_admission_in(&context)).unwrap();
                assert_eq!(before.basis(), after_reads.basis(), "clone, checkout and depth fetch never publish repository state");
                let next = append(&node, tip.0, private, serial); serial += 1; revisions.push(next);
                let (returned, _) = live_client(node, &listener, command(&run, "fetch", &client, &[&endpoint, &repository, version, "-"]));
                node = returned;
                assert_eq!(markers(&run, &client), BTreeSet::from([old_parent]), "ordinary incremental fetch retains the client's original boundary");
                assert_eq!(history(&run, &client), BTreeSet::from([next.0.to_string(), tip.0.to_string(), old_parent.to_string()]));
                checked(command(&run, "fsck", &client, &[]));
                let (returned, _) = live_client(node, &listener, command(&run, "unshallow", &client, &[&endpoint, &repository, version, "-"]));
                node = returned;
                assert!(markers(&run, &client).is_empty());
                assert!(!PathBuf::from(&run).join("work").join(&client).join(".git/shallow").exists(), "unshallow removes the client's boundary file");
                assert_eq!(history(&run, &client), revisions.iter().map(|revision| revision.0.to_string()).collect(), "unshallow supplies the entire native ancestry");
                let present = inventory(&run, &client);
                assert!(!present.contains(&private.to_string()) && !present.contains(&private_blob.to_string()), "neither deleted-only history nor foreign gitlinks become public");
                if name == "full" {
                    assert_eq!(present, revisions.iter().flat_map(|revision| [revision.0.to_string(), revision.1.to_string(), revision.2.to_string()]).collect(), "full unshallow has the exact complete public object set");
                }
                checked(command(&run, "fsck", &client, &[]));
                eprintln!("PINNED_SHALLOW_CELL format={} protocol={} profile={} clone_checkout_deepen_incremental_unshallow=passed", format.as_str(), version, name);
            }
        }
        node.shutdown().unwrap(); drop(scratch);
    }
}
