use super::*;
use crate::treefs_workspace::trusted_workflow::durable::tests::{Temp, workflow_node};
use fgit_types::GitHashAlgorithm;
use std::cell::Cell;

#[test]
fn stopping_during_verification_preserves_the_original_settlement_for_a_live_owner() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let temp = Temp::new();
        let (node, _, _) = workflow_node(&temp, format);
        let reference = RefName::try_new(b"refs/heads/main").unwrap();
        let poll = node
            .runtime()
            .block_on(node.poll_trusted_ref_workflows_in(
                &node.command_request_context(None),
                &reference,
                b"ci",
                &temp.0,
                &[b"ci".to_vec()],
                Default::default(),
                None,
            ))
            .unwrap();
        assert!(poll.execution_settled(), "{}", poll.to_json());
        let event = poll.dispatch().unwrap().run_directory.parent().unwrap();
        let marker = event.join("settled");
        let original = fs::read(&marker).unwrap();
        let key = std::str::from_utf8(&original).unwrap();
        let scope = super::super::scope(&node, &reference, b"ci");
        fs::remove_file(&marker).unwrap();
        let inspect =
            |live: &dyn Fn() -> bool| recover(&node, &reference, b"ci", event, &scope, key, live);
        let request = node.command_request_context(None);
        let checks = Cell::new(0);
        let stopped = inspect(&|| {
            checks.set(checks.get() + 1);
            if checks.get() == 2 {
                request.cancel();
            }
            request.checkpoint_is_live()
        });
        assert!(matches!(
            stopped,
            Err(TrustedWorkflowFailure::WatchRecoveryStopped)
        ));
        assert_eq!(checks.get(), 2);
        assert!(!marker.exists());
        assert!(!event.join("reported").exists());
        assert!(inspect(&|| true).unwrap());
        assert_eq!(fs::read(&marker).unwrap(), original);
        fs::write(&marker, b"damaged marker").unwrap();
        assert!(matches!(
            inspect(&|| true),
            Err(TrustedWorkflowFailure::InvalidInput(_))
        ));
        assert_eq!(fs::read(marker).unwrap(), b"damaged marker");
        node.shutdown().unwrap();
    }
}
