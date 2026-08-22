//! Regressions for the second-pass reference-model honesty fixes.
//!
//! These assertions pin the caller-visible contract: identity derivation
//! failures stay classified, and a campaign that omitted any successor from
//! deduplication cannot claim a clean bounded result.

use std::collections::BTreeMap;

use fgit_reference::campaign::{Bounds, CampaignReport, Coverage, Property};
use fgit_reference::harness::{IdentityMint, label};
use fgit_reference::intent::{IdempotencyKey, TxIdDerivationInputs};
use fgit_reference::state::{IdentityLedger, InvariantBreach};

fn inputs(mint: &mut IdentityMint, key: &str) -> TxIdDerivationInputs {
    TxIdDerivationInputs {
        tenant: mint.tenant(),
        repository: mint.repository(),
        principal: mint.principal(),
        idempotency_key: IdempotencyKey::new(label(key)),
        canonical_request_digest: mint.digest(),
    }
}

fn fully_exercised_report(codec_faults: usize) -> CampaignReport {
    CampaignReport {
        bounds: Bounds::DEFAULT,
        states_explored: 1,
        transitions_explored: 1,
        refused_transitions: 0,
        truncated: false,
        codec_faults,
        property_witnesses: Property::ALL
            .iter()
            .map(|property| (*property, 1))
            .collect::<BTreeMap<_, _>>(),
        coverage: Coverage::default(),
        planted_defect: None,
        defects_planted: 0,
        defects_detected: 0,
        violations: Vec::new(),
    }
}

#[test]
fn one_tx_id_with_different_derivation_inputs_is_an_injectivity_breach() {
    let mut mint = IdentityMint::new(0x5053_5752);
    let tx_id = mint.tx();
    let bound = inputs(&mut mint, "pswr-bound");
    let mut ledger = IdentityLedger::default();

    ledger
        .bind_transaction(tx_id, bound)
        .expect("first binding must succeed");
    ledger
        .bind_transaction(tx_id, bound)
        .expect("the exact retry is permitted");

    let mut conflicting = bound;
    conflicting.idempotency_key = IdempotencyKey::new(label("pswr-conflicting"));
    let breach = ledger
        .bind_transaction(tx_id, conflicting)
        .expect_err("one transaction identity cannot name two semantic inputs");
    assert!(
        matches!(
            breach.as_ref(),
            InvariantBreach::TxIdInputsInconsistent { tx_id: observed } if *observed == tx_id
        ),
        "injectivity must not be misclassified as a deterministic-derivation breach: {breach:?}"
    );
}

#[test]
fn a_codec_fault_prevents_a_campaign_from_claiming_clean_coverage() {
    let clean = fully_exercised_report(0);
    assert!(clean.is_clean(), "the zero-fault control must remain clean");

    let incomplete = fully_exercised_report(1);
    assert!(
        !incomplete.is_clean(),
        "a successor omitted after key encoding failed makes coverage incomplete"
    );
    assert!(
        incomplete.to_ndjson().contains("\"codec_faults\":1"),
        "the receipt must expose its incomplete exploration"
    );
}
