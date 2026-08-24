//! N cells, one authority backend, hints on and off. `frankengit-fg036a`, line 1.
//!
//! # What this covers that the L0 differential does not
//!
//! `fgit-types/tests/hint_differential.rs` runs the same experiment against a
//! modelled authority. This one uses the real thing: a single
//! [`MemoryAuthorityStore`] shared by every cell, a configuration body staged
//! through [`stage_repository_configuration`] and resolved back through
//! [`root_layout_for_verification`], a real ref-state Merkle root, and real
//! membership and absence proofs that the client verifies independently.
//!
//! # What it still does not cover
//!
//! These cells are structs in one process, not `fgit-node` processes. Nothing
//! here exercises scheduling, partition, or concurrent head transitions, and I
//! am not claiming acceptance line 1 on the strength of it. What it does
//! establish is that with the real authority and real proofs in the loop,
//! routing and gossip move no answer — which is the part of the line that lives
//! in code rather than in deployment.
//!
//! # The shape of the claim
//!
//! Three arms over one workload: no hints, accurate hints, poisoned hints. The
//! poisoned arm is the load-bearing one. Accurate hints agreeing with no hints
//! is also consistent with hints being trusted and merely correct; only a lying
//! peer distinguishes "the hint was right" from "the hint did not decide".

use fgit_authority::{
    MemoryAuthorityStore, StoreInstanceId, head_selected_ref_state_absence_proof,
    root_layout_for_verification, stage_repository_configuration,
};
use fgit_codec::RepositoryConfigurationBody;
use fgit_crypto::{
    preferred_combiner, ref_state_membership_proof, ref_state_merkle_root,
    verify_ref_state_membership_under, verify_ref_state_non_membership_under,
};
use fgit_types::gossip::GossipView;
use fgit_types::hash::Digest;
use fgit_types::layout::RootLayoutVersion;
use fgit_types::native::{GitHashAlgorithm, GitOid, GitOidSha1};
use fgit_types::refs::RefName;
use fgit_types::routing::PlacementCandidate;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Cell(&'static str);

impl PlacementCandidate for Cell {
    fn placement_key(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

const CELLS: [Cell; 4] = [
    Cell("cell-north"),
    Cell("cell-south"),
    Cell("cell-east"),
    Cell("cell-west"),
];

fn name(text: &str) -> RefName {
    RefName::try_new(text.as_bytes()).expect("an admissible ref name")
}

const fn oid(seed: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([seed; GitOidSha1::LEN]))
}

fn ref_state() -> Vec<(RefName, GitOid)> {
    vec![
        (name("refs/heads/main"), oid(0x11)),
        (name("refs/heads/next"), oid(0x22)),
        (name("refs/heads/release"), oid(0x33)),
        (name("refs/tags/v1"), oid(0x44)),
    ]
}

/// Present and absent names, including both edges of the sorted range.
const WORKLOAD: [&str; 7] = [
    "refs/heads/aaa-before-everything",
    "refs/heads/main",
    "refs/heads/mainx",
    "refs/heads/next",
    "refs/heads/release",
    "refs/tags/v1",
    "refs/tags/zzz-after-everything",
];

/// What a client ends up believing, and nothing about how it got there.
///
/// This is the value that must be identical across arms. It deliberately does
/// not carry which cell answered or how many probes it took — those are exactly
/// what hints are allowed to change.
#[derive(Debug, PartialEq, Eq)]
struct ClientBelief {
    oid: Option<GitOid>,
    proof_verified: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct HintRejected;

/// How the hint layer fared, which is what hints ARE allowed to change.
///
/// Kept out of [`ClientBelief`] on purpose: beliefs must match across arms and
/// these counts must not, or the experiment cannot tell "hints were consulted
/// and made no difference" from "hints were never consulted at all".
#[derive(Debug, Default, PartialEq, Eq)]
struct HintOutcome {
    accepted: usize,
    rejected: usize,
}

/// One authority, shared by every cell.
struct Deployment {
    store: MemoryAuthorityStore,
    configuration_root: Digest,
    ref_root: Digest,
    entries: Vec<(RefName, GitOid)>,
}

fn deploy() -> Deployment {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(1));
    let configuration_root = stage_repository_configuration(
        &store,
        &RepositoryConfigurationBody {
            root_layout: RootLayoutVersion::RefStateMerkleV1,
            object_format: GitHashAlgorithm::Sha1,
        },
    )
    .expect("the authority accepts the configuration");
    let entries = ref_state();
    let ref_root = ref_state_merkle_root(&entries).expect("a ref root");
    Deployment {
        store,
        configuration_root,
        ref_root,
        entries,
    }
}

/// Serve one query from whichever cell routing prefers, verifying every hint.
///
/// Every cell reads the same authority, so which one answers cannot change the
/// answer. The gossiped oid is consulted only through `verified_by`, and the
/// value that reaches the client always comes from the ref state the authority's
/// root commits to.
fn serve(
    deployment: &Deployment,
    gossip: Option<&GossipView<&'static str, GitOid>>,
    query: &'static str,
    hints: &mut HintOutcome,
) -> ClientBelief {
    // A hint. Which cell answers is a latency decision.
    let _serving = preferred_combiner(&CELLS, query.as_bytes()).expect("a preferred cell");

    // The layout is resolved from the AUTHORITY, never from a hint: it decides
    // whether a proof is admissible at all.
    let version = root_layout_for_verification(&deployment.store, &deployment.configuration_root)
        .expect("the configuration resolves");

    let queried = name(query);

    if let Some(view) = gossip
        && let Some(claimed) = view.claim_of(&query)
    {
        // A gossiped oid may only be believed if the authority's ref state
        // actually commits to it. Rejection costs latency and nothing else.
        let verified: Result<&GitOid, HintRejected> = claimed.verified_by(|candidate| {
            match ref_state_membership_proof(&deployment.entries, &queried) {
                Ok((truth, _)) if truth == **candidate => Ok(()),
                _ => Err(HintRejected),
            }
        });
        // Recorded, never acted on for correctness. A surviving hint would let
        // a real cell skip LOCATING the ref; it can never let it skip PROVING,
        // because the client checks the proof itself either way.
        if verified.is_ok() {
            hints.accepted += 1;
        } else {
            hints.rejected += 1;
        }
    }

    match ref_state_membership_proof(&deployment.entries, &queried) {
        Ok((found, proof)) => {
            let verified = verify_ref_state_membership_under(
                version,
                &deployment.ref_root,
                &queried,
                &found,
                &proof,
            )
            .expect("v1 admits membership proofs");
            ClientBelief {
                oid: Some(found),
                proof_verified: verified,
            }
        }
        Err(_) => {
            let proof = head_selected_ref_state_absence_proof(
                &deployment.store,
                &deployment.configuration_root,
                &deployment.entries,
                &queried,
            )
            .expect("a v1 head emits an absence proof");
            let verified = verify_ref_state_non_membership_under(
                version,
                &deployment.ref_root,
                &queried,
                &proof,
            )
            .expect("v1 admits absence proofs");
            ClientBelief {
                oid: None,
                proof_verified: verified,
            }
        }
    }
}

fn run(gossip: Option<&GossipView<&'static str, GitOid>>) -> Vec<ClientBelief> {
    run_measured(gossip).0
}

fn run_measured(
    gossip: Option<&GossipView<&'static str, GitOid>>,
) -> (Vec<ClientBelief>, HintOutcome) {
    let deployment = deploy();
    let mut hints = HintOutcome::default();
    let beliefs = WORKLOAD
        .iter()
        .map(|query| serve(&deployment, gossip, query, &mut hints))
        .collect();
    (beliefs, hints)
}

fn accurate_gossip() -> GossipView<&'static str, GitOid> {
    let mut view = GossipView::with_capacity(16);
    view.observe("refs/heads/main", oid(0x11)).expect("fits");
    view.observe("refs/heads/next", oid(0x22)).expect("fits");
    view.observe("refs/heads/release", oid(0x33)).expect("fits");
    view.observe("refs/tags/v1", oid(0x44)).expect("fits");
    view
}

fn poisoned_gossip() -> GossipView<&'static str, GitOid> {
    let mut view = GossipView::with_capacity(16);
    // Wrong identities for refs that exist, and identities invented for refs
    // that do not exist at all.
    view.observe("refs/heads/main", oid(0xFF)).expect("fits");
    view.observe("refs/heads/next", oid(0xFE)).expect("fits");
    view.observe("refs/heads/mainx", oid(0xFD)).expect("fits");
    view.observe("refs/tags/zzz-after-everything", oid(0xFC))
        .expect("fits");
    view
}

#[test]
fn every_arm_reaches_the_same_beliefs() {
    let without = run(None);
    let accurate = accurate_gossip();
    let poisoned = poisoned_gossip();

    assert_eq!(
        without,
        run(Some(&accurate)),
        "accurate hints must not change a single belief"
    );
    assert_eq!(
        without,
        run(Some(&poisoned)),
        "and neither must a lying peer"
    );
}

#[test]
fn every_answer_is_backed_by_a_proof_that_verifies() {
    // Without this the differential could be satisfied by three arms that all
    // answered nothing, or all answered without proving anything.
    for arm in [None, Some(&accurate_gossip()), Some(&poisoned_gossip())] {
        for (query, belief) in WORKLOAD.iter().zip(run(arm)) {
            assert!(
                belief.proof_verified,
                "{query}: every answer must carry a proof that verifies against the \
                 authority's ref root"
            );
        }
    }
}

#[test]
fn the_hint_layer_is_actually_consulted_in_the_arms_that_have_hints() {
    // Without this the two agreement tests could pass because gossip is never
    // read at all, which would make the whole differential vacuous.
    let (_, none) = run_measured(None);
    assert_eq!(
        none,
        HintOutcome {
            accepted: 0,
            rejected: 0
        },
        "the no-hint arm must consult nothing"
    );

    let accurate = accurate_gossip();
    let (_, good) = run_measured(Some(&accurate));
    assert_eq!(
        good.accepted, 4,
        "all four truthful claims must be reached and accepted"
    );
    assert_eq!(good.rejected, 0);

    let poisoned = poisoned_gossip();
    let (_, bad) = run_measured(Some(&poisoned));
    assert_eq!(
        bad.accepted, 0,
        "not one lie may survive verification against the authority"
    );
    assert_eq!(
        bad.rejected, 4,
        "and all four must be reached and rejected, not merely absent"
    );
}

#[test]
fn the_workload_actually_exercises_both_presence_and_absence() {
    // Guards the guard: if every query were absent, the membership path would
    // never run and the arms would agree for an uninteresting reason.
    let beliefs = run(None);
    let present = beliefs.iter().filter(|b| b.oid.is_some()).count();
    let absent = beliefs.iter().filter(|b| b.oid.is_none()).count();
    assert_eq!(present, 4, "four refs exist in the state");
    assert_eq!(absent, 3, "three queries miss, including both edges");
}

#[test]
fn no_fabricated_identity_reaches_a_client() {
    // The poisoned arm claims 0xFF, 0xFE, 0xFD and 0xFC. None may appear.
    let poisoned = poisoned_gossip();
    for belief in run(Some(&poisoned)) {
        if let Some(found) = belief.oid {
            assert!(
                ![oid(0xFF), oid(0xFE), oid(0xFD), oid(0xFC)].contains(&found),
                "a peer's invented identity reached the client: {found:?}"
            );
        }
    }

    // And the two queries the poisoned view claims a location for, but the ref
    // state does not hold, must still come back ABSENT with a working absence
    // proof. A peer must not be able to conjure a ref into existence.
    let beliefs = run(Some(&poisoned));
    let mut checked = 0;
    for (query, belief) in WORKLOAD.iter().zip(&beliefs) {
        if *query == "refs/heads/mainx" || *query == "refs/tags/zzz-after-everything" {
            assert_eq!(
                belief.oid, None,
                "{query}: a gossiped identity must not create a ref the authority does not hold"
            );
            assert!(
                belief.proof_verified,
                "{query}: and its absence must still be proved, not merely asserted"
            );
            checked += 1;
        }
    }
    assert_eq!(
        checked, 2,
        "both poisoned-but-absent queries must have been examined"
    );
}

#[test]
fn routing_selects_a_cell_and_the_choice_never_moves_an_answer() {
    // Pins the premise the whole differential rests on: one authority behind
    // every cell, so the routing hint has nothing to change.
    let deployment = deploy();
    for query in WORKLOAD {
        let chosen = preferred_combiner(&CELLS, query.as_bytes()).expect("a preference");
        assert!(CELLS.contains(chosen));
        let mut hints = HintOutcome::default();
        let first = serve(&deployment, None, query, &mut hints);
        let again = serve(&deployment, None, query, &mut hints);
        assert_eq!(first, again, "{query}: serving must be deterministic");
    }
}
