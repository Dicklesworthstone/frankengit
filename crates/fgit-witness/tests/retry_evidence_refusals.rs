#![forbid(unsafe_code)]

//! frankengit-pmno: the retry controller refuses to emit evidence it has not
//! observed.
//!
//! `RetryController::evidence` builds a `StatisticalEvidenceBody` — population,
//! selection, window, regime, policy, assumptions — that a caller can attach to
//! a decision as its justification. AGENTS.md §8 requires statistical evidence
//! to bind an exact sequence window, and §10 forbids describing a bounded
//! result as more than it is. A receipt built before any retry has been observed
//! would carry a window binding nothing.
//!
//! `retry.rs:381` refuses that case with `RetryEvidenceRefusal::NoObservations`,
//! and it had no test.
//!
//! # `RetryRefusal::Evidence` is dominated, and is recorded not tested
//!
//! `decide` wraps the same call as `RetryRefusal::Evidence` (`retry.rs:329`),
//! but it calls `controller.observe(..)` FIRST and only then asks for evidence.
//! By the time that wrapper could fire, an observation exists, so the
//! `NoObservations` cause cannot reach it. It is belt-and-braces against the
//! ordering changing, not a distinct condition, and it must not be counted as
//! covered.

use fgit_statistics::{BetaPrior, IncrementalPosterior};
use fgit_types::{AsciiSlug, Digest, DigestAlgorithmId, DigestBytes};
use fgit_witness::retry::{
    Attempt, PriorityClass, RetryController, RetryEvidenceIdentity, RetryEvidenceRefusal,
};

fn identity() -> RetryEvidenceIdentity {
    RetryEvidenceIdentity::new(
        AsciiSlug::from_static("witness-retry"),
        AsciiSlug::from_static("sealed-transaction-retries"),
        Digest::new(
            DigestAlgorithmId::try_new(0x5_4).expect("fixture algorithm slot"),
            DigestBytes::try_new(&[5; 32]).expect("fixture digest bytes"),
        ),
    )
}

fn controller() -> RetryController {
    RetryController::new(identity()).expect("the pinned profile is valid")
}

/// A posterior with a little history, so the attempt below is ordinary rather
/// than degenerate.
fn posterior() -> IncrementalPosterior {
    let mut p = IncrementalPosterior::new(BetaPrior::uniform());
    for _ in 0..8 {
        p.observe(true);
    }
    p
}

fn attempt() -> Attempt {
    Attempt {
        attempts: 1,
        age_ticks: 1,
        priority: PriorityClass::Interactive,
        posterior: posterior(),
    }
}

/// Before any retry is observed, evidence is refused rather than invented.
///
/// This is the whole point of the guard: a `StatisticalEvidenceBody` emitted
/// here would name a window containing no observations, which is a claim about
/// nothing wearing the shape of a measurement.
#[test]
fn evidence_before_any_observation_is_refused() {
    assert_eq!(
        controller().evidence(),
        Err(RetryEvidenceRefusal::NoObservations),
    );
}

/// The permitted twin: after one observed retry, evidence binds and is emitted.
///
/// Load-bearing. The refusal above is `evidence` declining to produce output, so
/// a controller that refused unconditionally would satisfy it and never produce
/// evidence at all — which would make every retry decision unjustifiable.
///
/// Asserted on the bound identity fields rather than `is_ok`, so a body that
/// came back carrying someone else's population or selection would not pass.
#[test]
fn evidence_after_one_observation_binds_the_declared_identity() {
    let mut controller = controller();

    controller
        .decide(1, attempt())
        .expect("an ordinary attempt yields a decision");

    let body = controller
        .evidence()
        .expect("one observation is enough to bind a window");

    assert_eq!(body.population, *identity().population());
    assert_eq!(body.selection, *identity().selection());
}

/// The refusal is about observations, not about construction.
///
/// A freshly built controller is valid — `new` returns `Ok` — so the refusal
/// above cannot be blamed on a bad profile or a rejected identity. This
/// separates "the controller is broken" from "the controller has nothing to
/// report yet", which are different answers for a caller deciding whether to
/// retry or to escalate.
#[test]
fn a_controller_with_no_observations_is_itself_valid() {
    RetryController::new(identity())
        .expect("the pinned profile is valid even before any observation");
}
