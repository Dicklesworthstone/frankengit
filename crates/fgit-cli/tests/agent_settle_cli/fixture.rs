//! Shared native recovery fixtures with genuine outstanding publication debt.
//! Approval/ECC assertions are synthetic test inputs; the authority store,
//! journal, broker lifecycle, native publication and CLI recovery are real.

#[path = "../agent_recover_cli/fixture.rs"]
mod original;

pub use original::{Fixture, Mode, OWNER, fixture, fixture_with_acknowledgement, hex};

use fgit_agent::LogicalTime;
use fgit_agent::effect_journal::EffectJournalPosition;
use fgit_agent::ref_publication::prepare_recovered_ref_transaction_acknowledgement;
use fgit_node::OneNode;
use std::path::PathBuf;

pub const OBSERVED_AT: u64 = 10_001;

impl Fixture {
    pub fn journal_path(&self) -> PathBuf {
        self.directory()
            .join(format!("{:032x}.fg-agent-journal", self.run.value()))
    }

    pub fn settlement_arguments(&self) -> Vec<String> {
        let mut args = self.arguments();
        args[1] = "settle".into();
        args.extend(["--observed-at".into(), OBSERVED_AT.to_string()]);
        args
    }

    /// Obtain the production-derived exact candidate ACK before planting a
    /// partial-write fault. Neither preparation nor recovery writes the file.
    pub fn expected_ack(&self) -> (EffectJournalPosition, Vec<u8>) {
        let node = OneNode::open_existing(self.config()).unwrap();
        let request = node.command_request_context(None);
        let recovered = node
            .runtime()
            .block_on(node.recover_agent_journal_in(
                &request,
                &self.directory(),
                self.run,
                &self.run_commitment,
                self.tail,
            ))
            .unwrap();
        assert!(
            !recovered
                .original_run()
                .is_open_at(LogicalTime::new(OBSERVED_AT)),
            "cold cleanup must not renew the expired original run"
        );
        let before = recovered
            .reconciliation_report(LogicalTime::new(OBSERVED_AT))
            .unwrap();
        assert!(before.has_unsettled_effects());
        let observation = node
            .runtime()
            .block_on(node.observe_recovered_agent_ref_transaction_in(
                &request,
                &recovered,
                self.effect,
            ))
            .unwrap()
            .unwrap();
        let prepared = prepare_recovered_ref_transaction_acknowledgement(
            recovered.original_run(),
            recovered.journal(),
            &observation,
            LogicalTime::new(OBSERVED_AT),
        )
        .unwrap();
        assert!(!prepared.already_acknowledged());
        assert_eq!(prepared.before_position(), self.tail);
        let result = (prepared.after_position(), prepared.frame().to_vec());
        node.shutdown().unwrap();
        result
    }
}
