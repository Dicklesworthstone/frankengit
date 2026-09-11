use super::*;
use std::process::{Command, Output};
use std::sync::Arc;

fn command(run: &str, operation: &str, client: &str, extra: &[&str]) -> Command {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/e2e/oracle/partial_clone_client.py");
    let mut command = Command::new("python3");
    command.arg(script).arg(run).arg(operation).arg(client).args(extra);
    command
}
fn checked(mut command: Command) -> Vec<u8> {
    let output = command.output().expect("run pinned client wrapper");
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    assert!(output.status.success(), "pinned client failed: {}", String::from_utf8_lossy(&output.stderr));
    output.stdout
}
fn live_client(node: OneNode, listener: &TcpListener, mut command: Command) -> (OneNode, Output) {
    let listener = listener.try_clone().unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = Arc::clone(&stop);
    let worker = std::thread::spawn(move || {
        let start = std::time::Instant::now();
        while !stopping.load(Ordering::Relaxed) && start.elapsed() < Duration::from_secs(90) {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    let result = node.serve_git_daemon_stream_with_limits(stream, WireLimits::default());
                    return (node, Some(result));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("test listener: {error}"),
            }
        }
        (node, None)
    });
    let output = command.output();
    stop.store(true, Ordering::Relaxed);
    let (node, result) = worker.join().unwrap();
    let output = output.expect("pinned client wrapper launches");
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    assert!(output.status.success(), "pinned client exit {:?}: {}", output.status.code(), String::from_utf8_lossy(&output.stderr));
    assert!(matches!(result, Some(Ok(GitDaemonSessionOutcome::Pack(_)))), "real server must emit its pack: {result:?}");
    (node, output)
}
fn inventory(run: &str, client: &str) -> BTreeSet<String> {
    String::from_utf8(checked(command(run,"inventory",client,&[]))).unwrap().lines().map(str::to_owned).collect()
}

#[test]
#[ignore = "requires source/binary-verified Git 2.54.0 and Bubblewrap via FGIT_ORACLE_ROOT"]
fn pinned_git_partial_clone_promisor_and_lazy_read_round_trip() {
    let oracle = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/e2e/oracle/oracle.sh");
    let run = Command::new(&oracle).args(["create-run","git-2.54.0","partial-clone-node"]).output().unwrap();
    assert!(run.status.success(), "pinned oracle unavailable: {}", String::from_utf8_lossy(&run.stderr));
    let run = String::from_utf8(run.stdout).unwrap().trim().to_owned();
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture { scratch, mut node, config, public, private, visible, .. } = fixture(format);
        delete_private(&node, private);
        let wanted_blob = git_object_id(format, GitObjectKind::Blob, b"current public content");
        let kinds = visible.iter().map(|id| (*id, node.read_git_object(*id).unwrap().envelope().object_kind())).collect::<BTreeMap<_,_>>();
        node.shutdown().unwrap(); node = OneNode::open_existing(config).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let repository = String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec()).unwrap();
        for version in ["0","1","2"] {
            for (name, filter) in [("blob-none","blob:none"),("tree-zero","tree:0")] {
                let client = format!("{}-{version}-{name}",format.as_str());
                let expected = kinds.iter().filter(|(_,kind)| {
                    if filter == "tree:0" { **kind == fgit_object_fabric::ObjectKind::Commit }
                    else { **kind != fgit_object_fabric::ObjectKind::Blob }
                }).map(|(id,_)| id.to_string()).collect::<BTreeSet<_>>();
                let (returned, _) = live_client(node,&listener,command(&run,"clone",&client,&[&endpoint,&repository,version,filter])); node = returned;
                assert_eq!(inventory(&run,&client),expected,"the pinned client must really retain an incomplete filtered pack");
                let pack_directory = PathBuf::from(&run).join("work").join(&client).join(".git/objects/pack");
                assert!(std::fs::read_dir(&pack_directory).unwrap().any(|entry| entry.unwrap().path().extension().is_some_and(|extension| extension == "promisor")),"Git marked the received partial pack as promised");
                checked(command(&run,"fsck",&client,&[]));
                let (returned, output) = live_client(node,&listener,command(&run,"read",&client,&[&endpoint,&repository,version,&wanted_blob.to_string()])); node = returned;
                assert_eq!(output.stdout,b"current public content");
                let mut complete = expected;
                complete.insert(wanted_blob.to_string());
                assert_eq!(inventory(&run,&client),complete,"lazy cat-file fetched exactly the one requested native blob");
                checked(command(&run,"fsck",&client,&[]));
                eprintln!("PINNED_PARTIAL_CELL format={} protocol={} filter={} tip={} passed",format.as_str(),version,filter,public);
            }
        }
        node.shutdown().unwrap(); drop(scratch);
    }
}
