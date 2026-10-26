//! A push refused before admission reaches the client as its typed cause, not
//! the generic "receive failed before admission" line (frankengit-yrff). The
//! guarded receiver serves fg serve --continuous and fg serve-ssh alike. The
//! command-count bound has its own operator text and tests (command_limits).

use super::push_options::serve;
use super::*;

#[test]
fn a_cell_not_in_service_names_its_state_and_its_serving_twin_publishes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format, true);
        // Initialized but never brought into service: the cell is still
        // Bootstrapping and takes no receive work in.
        let node = OneNode::init(config.clone()).unwrap().0;
        let (oid, zero, pack) = pack(format);
        let (address, route, worker) = launch(node);
        let mut socket = connect(address, &route);
        let rows = records(&mut socket);
        let _ = socket.shutdown(Shutdown::Write);
        let (node, result) = worker.join().unwrap();
        let error = result.expect_err("a cell that admits no staging refuses receive");
        assert!(
            format!("{error:?}").contains("StateAdmitsNoStaging"),
            "{error:?}"
        );
        let last = rows
            .last()
            .map(|row| String::from_utf8_lossy(row).into_owned())
            .unwrap_or_default();
        assert!(
            last.starts_with("ERR this server is not accepting pushes: ")
                && last.ends_with("; no ref decision was attempted\n"),
            "{last:?}"
        );
        node.shutdown().unwrap();

        // The same node, brought into service, takes the same push.
        let node = start(config, true);
        let body = [
            prefix(format, &[(zero, oid, "refs/tags/served")], false),
            pack,
        ]
        .concat();
        let (_, node, result, rows) = serve(node, &body);
        assert!(matches!(
            result.unwrap().unwrap().commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert_eq!(rows.last().unwrap(), b"ok refs/tags/served\n");
        node.shutdown().unwrap();
    }
}
