//! The executable must use the same durable refresh path as native callers.
use super::*;

#[test]
fn operator_refreshes_only_new_blobs_and_keeps_original_candidate_recovery() {
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node,commit) = symbols(&root,format);
        node.shutdown().unwrap();
        let run = |tail: &[&str]| std::process::Command::new(env!("CARGO_BIN_EXE_fg-symbol-index"))
            .arg(root.0.join("node"))
            .args(["31313131313131313131313131313131","32323232323232323232323232323232",format.as_str(),"refs/heads/main"])
            .args(tail).output().unwrap();
        let success = |tail: &[&str]| {
            let output = run(tail);
            assert!(output.status.success(),"{}",String::from_utf8_lossy(&output.stderr));
            String::from_utf8(output.stdout).unwrap()
        };
        let foreign = format!("alg:2:{}","a".repeat(64));
        assert!(!run(&["refresh",&foreign]).status.success());
        let built = success(&["build","genesis"]);
        let first = text(&built,"index_token").to_owned();
        let node = reopen(&config);
        const ADDED: &[u8] = b"fn ThingAdded() {}\n";
        let next = add_files(&node,commit,&[(b"new.rs",ADDED)],b"operator-symbol-refresh-new");
        let canonical = generation(&node);
        node.shutdown().unwrap();
        // Staleness is never converted into an implicit refresh by a query.
        assert!(!run(&["query","prefix","Thing"]).status.success());
        let refreshed = success(&["refresh",&first]);
        assert_eq!(text(&refreshed,"type"),"symbol_index_refresh");
        assert_eq!(text(&refreshed,"source_commit"),next.to_string());
        assert_eq!(number(&refreshed,"reused_files"),3);
        assert_eq!(number(&refreshed,"source_blobs_read"),1);
        assert_eq!(number(&refreshed,"source_bytes_read") as usize,ADDED.len());
        assert_eq!(number(&refreshed,"predecessor_tables_read"),3);
        assert!(number(&refreshed,"predecessor_payload_bytes") > 0);
        assert!(refreshed.contains("\"repository_transaction_created\":false"));
        let second = text(&refreshed,"index_token").to_owned();
        let queried = success(&["query","prefix","Thing"]);
        assert_eq!(text(&queried,"index_token"),second);
        assert_eq!(number(&queried,"source_blobs_read"),0);
        assert!(queried.contains(&hex(b"ThingAdded")));
        assert!(queried.contains("\"read_only\":true"));
        assert_eq!(text(&success(&["recover",&first]),"state"),"superseded");
        assert_eq!(text(&success(&["recover",&second]),"state"),"active");
        assert!(!run(&["refresh",&first]).status.success());
        let unchanged = success(&["refresh",&second]);
        assert_eq!(number(&unchanged,"reused_files"),4);
        assert_eq!(number(&unchanged,"source_blobs_read"),0);
        assert_eq!(number(&unchanged,"source_bytes_read"),0);
        let node = reopen(&config);
        let report = search(&node,&ordinary(),Default::default(),data::MAX_INDEX_BYTES).unwrap();
        assert_eq!(report.source.commit,next);
        assert_eq!(report.matches.len(),6);
        assert_eq!(generation(&node),canonical);
        node.shutdown().unwrap();
    }
}
