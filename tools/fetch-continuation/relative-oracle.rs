use super::*;

#[test]
#[ignore = "requires source/binary-verified Git 2.54.0 and Bubblewrap via FGIT_ORACLE_ROOT"]
fn pinned_git_relative_deepening_progresses_existing_full_and_partial_clones() {
    let oracle=PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/e2e/oracle/oracle.sh");
    let output=Command::new(&oracle).args(["create-run","git-2.54.0","relative-native"]).output().unwrap();
    assert!(output.status.success(),"verified oracle unavailable: {}",String::from_utf8_lossy(&output.stderr));
    let run=String::from_utf8(output.stdout).unwrap().trim().to_owned();
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256] {
        let Fixture {scratch,mut node,config,public,private,private_blob,ancestor,..}=fixture(format);
        delete_private(&node,private);
        let middle=append(&node,public,private,2000);
        let tip=append(&node,middle.0,private,2001);
        let expected_file=node.read_git_object(tip.2).unwrap().payload().to_vec();
        node.shutdown().unwrap();node=OneNode::open_existing(config).unwrap();
        let listener=TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint=listener.local_addr().unwrap().to_string();
        let repository=String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec()).unwrap();
        for version in ["0","1","2"] {
            for (name,profile) in [("full","1"),("blobless","1,blob:none"),("treeless","1,tree:0")] {
                let client=format!("relative-{}-{version}-{name}",format.as_str());
                let context=node.request_context();
                let before=node.runtime().block_on(node.materialize_admission_in(&context)).unwrap();
                let (returned,_)=live_client(node,&listener,command(&run,"shallow-clone",&client,&[&endpoint,&repository,version,profile]));node=returned;
                assert_eq!(markers(&run,&client),BTreeSet::from([tip.0]));
                let mut expected=BTreeSet::from([tip.0.to_string()]);
                if name!="treeless" {expected.insert(tip.1.to_string());}
                if name=="full" {expected.insert(tip.2.to_string());}
                assert_eq!(inventory(&run,&client),expected);
                let mut expected_history=BTreeSet::from([tip.0.to_string()]);
                for boundary in [middle.0,public] {
                    let (returned,_)=live_client(node,&listener,command(&run,"deepen",&client,&[&endpoint,&repository,version,"1"]));node=returned;
                    expected_history.insert(boundary.to_string());
                    assert_eq!(markers(&run,&client),BTreeSet::from([boundary]));
                    assert_eq!(history(&run,&client),expected_history,"each identical relative request must add another generation");
                    checked(command(&run,"fsck",&client,&[]));
                }
                let checkout=command(&run,"checkout",&client,&[&endpoint,&repository,version,&tip.0.to_string()]);
                if name=="full" {checked(checkout);} else {let (returned,_)=live_client(node,&listener,checkout);node=returned;}
                assert_eq!(std::fs::read(PathBuf::from(&run).join("work").join(&client).join("public")).unwrap(),expected_file);
                let (returned,_)=live_client(node,&listener,command(&run,"deepen",&client,&[&endpoint,&repository,version,"10"]));node=returned;
                expected_history.insert(ancestor.to_string());
                assert!(markers(&run,&client).is_empty());assert_eq!(history(&run,&client),expected_history);
                assert!(!PathBuf::from(&run).join("work").join(&client).join(".git/shallow").exists());
                let present=inventory(&run,&client);
                assert!(!present.contains(&private.to_string()) && !present.contains(&private_blob.to_string()));
                checked(command(&run,"fsck",&client,&[]));
                let context=node.request_context();let after=node.runtime().block_on(node.materialize_admission_in(&context)).unwrap();
                assert_eq!(before.basis(),after.basis(),"relative fetch never publishes repository state");
                eprintln!("PINNED_RELATIVE_CELL format={} protocol={version} profile={name} repeated_deepen_checkout_completion=passed",format.as_str());
            }
        }
        node.shutdown().unwrap();drop(scratch);
    }
}
