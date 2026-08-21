//! The shared authority-backend conformance suite.
//!
//! `VERIFY_SPEC.md` §7 requires every authority profile — the in-memory
//! reference, the embedded `FrankenSQLite` profile, an object-store profile, a
//! future replicated `authorityd` — to pass the *same* suite.  That is only
//! meaningful if the suite is executable code that a backend crate can call, so
//! it lives in the library rather than in this crate's test tree.
//!
//! Consumers: FG-004c's fault and adversarial campaign, FG-005's embedded
//! profile, and this crate's own planted-wrong-implementation tests, which
//! exist to prove the suite has teeth — a backend that honours stale tokens, or
//! that derives tokens from content, or that reports a definite failure after
//! applying an effect, must fail a named check here.

use crate::contract::{
    AuthorityLimits, AuthorityStore, CasResolution, FaultableAuthorityStore, PutResolution,
    resolve_ambiguous_cas, resolve_ambiguous_put,
};
use crate::injection::{
    DuplicateDelivery, FaultDirective, FaultKind, FaultPlan, FaultPosition, OpIndex,
};
use crate::keys::{HeadKey, ImmutableKey, KeyError};
use crate::tokens::{AuthorityVersionToken, HeadGeneration, StoreInstanceId, VERSION_TOKEN_BYTES};
use crate::vocabulary::{
    AmbiguityReason, AuthorityFailure, AuthorityRefusal, CasOutcome, HeadInit, HeadRead,
    HeadReadReceipt, ImmutableRead, PutOutcome,
};

/// The verdict on one named conformance requirement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceCheck {
    /// Stable identifier, referenced by acceptance rows and campaign reports.
    pub id: &'static str,
    /// The requirement in one line.
    pub requirement: &'static str,
    /// Whether the backend satisfied it.
    pub passed: bool,
    /// Evidence: what was observed when the check failed.
    pub detail: String,
}

/// The verdicts for one backend.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConformanceReport {
    checks: Vec<ConformanceCheck>,
}

impl ConformanceReport {
    /// Every check, in execution order.
    #[must_use]
    pub fn checks(&self) -> &[ConformanceCheck] {
        &self.checks
    }

    /// Whether every check passed.
    #[must_use]
    pub fn is_pass(&self) -> bool {
        self.checks.iter().all(|check| check.passed)
    }

    /// The failing checks.
    pub fn failures(&self) -> impl Iterator<Item = &ConformanceCheck> {
        self.checks.iter().filter(|check| !check.passed)
    }

    /// The identifiers of the failing checks.
    #[must_use]
    pub fn failed_ids(&self) -> Vec<&'static str> {
        self.failures().map(|check| check.id).collect()
    }

    /// Look one check up by identifier.
    #[must_use]
    pub fn check(&self, id: &str) -> Option<&ConformanceCheck> {
        self.checks.iter().find(|check| check.id == id)
    }

    fn record(&mut self, id: &'static str, requirement: &'static str, outcome: Result<(), String>) {
        let (passed, detail) = match outcome {
            Ok(()) => (true, String::new()),
            Err(detail) => (false, detail),
        };
        self.checks.push(ConformanceCheck {
            id,
            requirement,
            passed,
            detail,
        });
    }
}

fn head_key(name: &str) -> Result<HeadKey, String> {
    HeadKey::new(name.as_bytes().to_vec()).map_err(|error| error.to_string())
}

fn immutable_key(name: &str) -> Result<ImmutableKey, String> {
    ImmutableKey::new(name.as_bytes().to_vec()).map_err(|error| error.to_string())
}

fn initialized_head<S: AuthorityStore + ?Sized>(
    store: &S,
    key: &HeadKey,
    body: &[u8],
) -> Result<HeadReadReceipt, String> {
    match store
        .initialize_head(key, HeadGeneration::FIRST, body)
        .map_err(|failure| failure.to_string())?
    {
        HeadInit::Created(receipt) | HeadInit::IdenticalRetry(receipt) => Ok(receipt),
        HeadInit::Conflict => Err("head slot already held a different body".to_owned()),
    }
}

fn committed<S: AuthorityStore + ?Sized>(
    store: &S,
    key: &HeadKey,
    expected: AuthorityVersionToken,
    generation: HeadGeneration,
    body: &[u8],
) -> Result<HeadReadReceipt, String> {
    match store
        .compare_exchange_head(key, expected, generation, body)
        .map_err(|failure| failure.to_string())?
    {
        CasOutcome::Committed(receipt) => Ok(receipt),
        CasOutcome::PredecessorMismatch => {
            Err("conditional replacement lost against the exact predecessor token".to_owned())
        }
    }
}

fn present_head<S: AuthorityStore + ?Sized>(
    store: &S,
    key: &HeadKey,
) -> Result<HeadReadReceipt, String> {
    match store
        .read_head(key)
        .map_err(|failure| failure.to_string())?
    {
        HeadRead::Present(receipt) => Ok(receipt),
        HeadRead::Absent => Err("head slot is absent".to_owned()),
    }
}

fn expect_refusal(
    failure: AuthorityFailure,
    expected: &AuthorityRefusal,
    context: &str,
) -> Result<(), String> {
    match failure {
        AuthorityFailure::Refused(refusal) if &refusal == expected => Ok(()),
        other => Err(format!("{context}: expected {expected}, observed {other}")),
    }
}

const fn forged_token(seed: u8) -> AuthorityVersionToken {
    AuthorityVersionToken::from_opaque_bytes([seed; VERSION_TOKEN_BYTES])
}

// --- backend-agnostic checks -------------------------------------------------

fn ac_01_put_creates<S: AuthorityStore + ?Sized>(store: &S) -> Result<(), String> {
    let key = immutable_key("ac01/seal")?;
    let outcome = store
        .put_if_absent(&key, b"seal-body")
        .map_err(|failure| failure.to_string())?;
    if outcome == PutOutcome::Created {
        Ok(())
    } else {
        Err(format!("expected Created, observed {outcome:?}"))
    }
}

fn ac_02_put_identical_retry<S: AuthorityStore + ?Sized>(store: &S) -> Result<(), String> {
    let key = immutable_key("ac02/seal")?;
    store
        .put_if_absent(&key, b"seal-body")
        .map_err(|failure| failure.to_string())?;
    let outcome = store
        .put_if_absent(&key, b"seal-body")
        .map_err(|failure| failure.to_string())?;
    if outcome == PutOutcome::IdenticalRetry {
        Ok(())
    } else {
        Err(format!("expected IdenticalRetry, observed {outcome:?}"))
    }
}

fn ac_03_put_conflict_preserves<S: AuthorityStore + ?Sized>(store: &S) -> Result<(), String> {
    let key = immutable_key("ac03/seal")?;
    store
        .put_if_absent(&key, b"original")
        .map_err(|failure| failure.to_string())?;
    let outcome = store
        .put_if_absent(&key, b"different")
        .map_err(|failure| failure.to_string())?;
    if outcome != PutOutcome::Conflict {
        return Err(format!("expected Conflict, observed {outcome:?}"));
    }
    match store
        .read_immutable(&key)
        .map_err(|failure| failure.to_string())?
    {
        ImmutableRead::Present(body) if body == b"original" => Ok(()),
        other => Err(format!("immutable slot was replaced: {other:?}")),
    }
}

fn ac_04_read_after_write<S: AuthorityStore + ?Sized>(store: &S) -> Result<(), String> {
    let key = immutable_key("ac04/batch")?;
    store
        .put_if_absent(&key, b"decision-batch")
        .map_err(|failure| failure.to_string())?;
    match store
        .read_immutable(&key)
        .map_err(|failure| failure.to_string())?
    {
        ImmutableRead::Present(body) if body == b"decision-batch" => Ok(()),
        other => Err(format!("expected the written body, observed {other:?}")),
    }
}

fn ac_05_head_initialize_and_read<S: AuthorityStore + ?Sized>(store: &S) -> Result<(), String> {
    let key = head_key("ac05/head")?;
    let created = initialized_head(store, &key, b"head-1")?;
    let read = present_head(store, &key)?;
    if created == read {
        Ok(())
    } else {
        Err(format!("read {read:?} disagrees with creation {created:?}"))
    }
}

fn ac_06_read_your_own_writes<S: AuthorityStore + ?Sized>(store: &S) -> Result<(), String> {
    let key = head_key("ac06/head")?;
    let first = initialized_head(store, &key, b"head-1")?;
    let second = committed(
        store,
        &key,
        first.token(),
        HeadGeneration::from_raw(2),
        b"head-2",
    )?;
    let read = present_head(store, &key)?;
    if read == second {
        Ok(())
    } else {
        Err(format!(
            "read {read:?} does not reflect the commit {second:?}"
        ))
    }
}

fn ac_07_cas_exact_predecessor<S: AuthorityStore + ?Sized>(store: &S) -> Result<(), String> {
    let key = head_key("ac07/head")?;
    let first = initialized_head(store, &key, b"head-1")?;
    let second = committed(
        store,
        &key,
        first.token(),
        HeadGeneration::from_raw(2),
        b"head-2",
    )?;
    if second.generation() == HeadGeneration::from_raw(2) && second.body() == b"head-2" {
        Ok(())
    } else {
        Err(format!("commit published unexpected state: {second:?}"))
    }
}

fn ac_08_single_winner<S: AuthorityStore + ?Sized>(store: &S) -> Result<(), String> {
    let key = head_key("ac08/head")?;
    let base = initialized_head(store, &key, b"head-1")?;
    let mut winners = 0_u32;
    let mut losers = 0_u32;
    for candidate in 0_u8..8 {
        let body = [b'c', candidate];
        let outcome = store
            .compare_exchange_head(&key, base.token(), HeadGeneration::from_raw(2), &body)
            .map_err(|failure| failure.to_string())?;
        match outcome {
            CasOutcome::Committed(_) => winners += 1,
            CasOutcome::PredecessorMismatch => losers += 1,
        }
    }
    if winners == 1 && losers == 7 {
        Ok(())
    } else {
        Err(format!(
            "{winners} winners and {losers} losers among 8 contenders"
        ))
    }
}

fn ac_09_token_unique_per_write<S: AuthorityStore + ?Sized>(store: &S) -> Result<(), String> {
    let key = head_key("ac09/head")?;
    let first = initialized_head(store, &key, b"head-1")?;
    let second = committed(
        store,
        &key,
        first.token(),
        HeadGeneration::from_raw(2),
        b"head-2",
    )?;
    let third = committed(
        store,
        &key,
        second.token(),
        HeadGeneration::from_raw(3),
        b"head-3",
    )?;
    if first.token() != second.token()
        && second.token() != third.token()
        && first.token() != third.token()
    {
        Ok(())
    } else {
        Err("two writes shared a version token".to_owned())
    }
}

fn ac_10_aba_identical_restore<S: AuthorityStore + ?Sized>(store: &S) -> Result<(), String> {
    let key = head_key("ac10/head")?;
    let first = initialized_head(store, &key, b"state-a")?;
    let second = committed(
        store,
        &key,
        first.token(),
        HeadGeneration::from_raw(2),
        b"state-b",
    )?;
    let third = committed(
        store,
        &key,
        second.token(),
        HeadGeneration::from_raw(3),
        b"state-a",
    )?;
    if third.body() != b"state-a" {
        return Err("restore did not republish the byte-identical body".to_owned());
    }
    if third.token() == first.token() {
        return Err("byte-identical restore reused the original version token".to_owned());
    }
    let outcome = store
        .compare_exchange_head(&key, first.token(), HeadGeneration::from_raw(4), b"state-c")
        .map_err(|failure| failure.to_string())?;
    if outcome == CasOutcome::PredecessorMismatch {
        Ok(())
    } else {
        Err(format!(
            "a writer holding the pre-restore token was allowed to commit: {outcome:?}"
        ))
    }
}

fn ac_11_monotone_generation<S: AuthorityStore + ?Sized>(store: &S) -> Result<(), String> {
    let key = head_key("ac11/head")?;
    let first = initialized_head(store, &key, b"head-1")?;
    let second = committed(
        store,
        &key,
        first.token(),
        HeadGeneration::from_raw(7),
        b"head-7",
    )?;
    let failure = store
        .compare_exchange_head(
            &key,
            second.token(),
            HeadGeneration::from_raw(7),
            b"head-7b",
        )
        .err()
        .ok_or_else(|| "an equal generation was accepted".to_owned())?;
    expect_refusal(
        failure,
        &AuthorityRefusal::NonMonotoneGeneration {
            current: HeadGeneration::from_raw(7),
            proposed: HeadGeneration::from_raw(7),
        },
        "equal generation",
    )?;
    let failure = store
        .compare_exchange_head(&key, second.token(), HeadGeneration::from_raw(3), b"head-3")
        .err()
        .ok_or_else(|| "a lower generation was accepted".to_owned())?;
    expect_refusal(
        failure,
        &AuthorityRefusal::NonMonotoneGeneration {
            current: HeadGeneration::from_raw(7),
            proposed: HeadGeneration::from_raw(3),
        },
        "lower generation",
    )?;
    committed(
        store,
        &key,
        second.token(),
        HeadGeneration::from_raw(8),
        b"head-8",
    )
    .map(|_| ())
}

fn ac_12_stale_token_loses<S: AuthorityStore + ?Sized>(store: &S) -> Result<(), String> {
    let key = head_key("ac12/head")?;
    let first = initialized_head(store, &key, b"head-1")?;
    committed(
        store,
        &key,
        first.token(),
        HeadGeneration::from_raw(2),
        b"head-2",
    )?;
    let outcome = store
        .compare_exchange_head(&key, first.token(), HeadGeneration::from_raw(3), b"head-3")
        .map_err(|failure| format!("a stale but issued token must lose, not error: {failure}"))?;
    if outcome == CasOutcome::PredecessorMismatch {
        Ok(())
    } else {
        Err(format!("a stale token was honoured: {outcome:?}"))
    }
}

fn ac_13_forged_token_refused<S: AuthorityStore + ?Sized>(store: &S) -> Result<(), String> {
    let key = head_key("ac13/head")?;
    initialized_head(store, &key, b"head-1")?;
    let forged = forged_token(0xAB);
    let failure = store
        .compare_exchange_head(&key, forged, HeadGeneration::from_raw(2), b"head-2")
        .err()
        .ok_or_else(|| "a forged token was accepted by the conditional write".to_owned())?;
    expect_refusal(
        failure,
        &AuthorityRefusal::UnknownVersionToken,
        "forged token on conditional write",
    )?;
    let receipt =
        HeadReadReceipt::new(key, forged, HeadGeneration::from_raw(1), b"head-1".to_vec());
    let failure = store
        .authenticate_head_receipt(&receipt)
        .err()
        .ok_or_else(|| "a forged receipt was authenticated".to_owned())?;
    expect_refusal(
        failure,
        &AuthorityRefusal::UnknownVersionToken,
        "forged receipt",
    )
}

fn ac_14_tampered_receipt_refused<S: AuthorityStore + ?Sized>(store: &S) -> Result<(), String> {
    let key = head_key("ac14/head")?;
    let genuine = initialized_head(store, &key, b"head-1")?;
    store
        .authenticate_head_receipt(&genuine)
        .map_err(|failure| format!("a genuine receipt failed to authenticate: {failure}"))?;
    let tampered = HeadReadReceipt::new(
        key.clone(),
        genuine.token(),
        genuine.generation(),
        b"head-forged".to_vec(),
    );
    let failure = store
        .authenticate_head_receipt(&tampered)
        .err()
        .ok_or_else(|| "a tampered body authenticated".to_owned())?;
    expect_refusal(
        failure,
        &AuthorityRefusal::TokenBodyMismatch,
        "tampered receipt body",
    )?;
    let regenerated = HeadReadReceipt::new(
        key,
        genuine.token(),
        HeadGeneration::from_raw(99),
        genuine.body().to_vec(),
    );
    let failure = store
        .authenticate_head_receipt(&regenerated)
        .err()
        .ok_or_else(|| "a tampered generation authenticated".to_owned())?;
    expect_refusal(
        failure,
        &AuthorityRefusal::TokenGenerationMismatch,
        "tampered receipt generation",
    )
}

fn ac_15_authenticity_is_not_currency<S: AuthorityStore + ?Sized>(store: &S) -> Result<(), String> {
    let key = head_key("ac15/head")?;
    let first = initialized_head(store, &key, b"head-1")?;
    committed(
        store,
        &key,
        first.token(),
        HeadGeneration::from_raw(2),
        b"head-2",
    )?;
    store.authenticate_head_receipt(&first).map_err(|failure| {
        format!("a genuinely issued but stale receipt must stay authentic: {failure}")
    })?;
    let outcome = store
        .compare_exchange_head(&key, first.token(), HeadGeneration::from_raw(3), b"head-3")
        .map_err(|failure| failure.to_string())?;
    if outcome == CasOutcome::PredecessorMismatch {
        Ok(())
    } else {
        Err("an authenticated stale receipt was treated as current".to_owned())
    }
}

fn ac_16_bounded_typed_errors<S: AuthorityStore + ?Sized>(store: &S) -> Result<(), String> {
    let limits: AuthorityLimits = store.limits();
    let key = immutable_key("ac16/body")?;
    let oversize = vec![0_u8; limits.body_bytes.saturating_add(1)];
    let failure = store
        .put_if_absent(&key, &oversize)
        .err()
        .ok_or_else(|| "an oversize body was accepted".to_owned())?;
    expect_refusal(
        failure,
        &AuthorityRefusal::BodyTooLarge {
            len: oversize.len(),
            limit: limits.body_bytes,
        },
        "oversize body",
    )?;
    let at_limit = vec![7_u8; limits.body_bytes];
    let outcome = store
        .put_if_absent(&key, &at_limit)
        .map_err(|failure| format!("a body at the declared bound was refused: {failure}"))?;
    if outcome == PutOutcome::Created {
        Ok(())
    } else {
        Err(format!(
            "a body at the declared bound did not create: {outcome:?}"
        ))
    }
}

fn ac_17_key_admission() -> Result<(), String> {
    let error = HeadKey::new(Vec::new())
        .err()
        .ok_or_else(|| "an empty head key was admitted".to_owned())?;
    if error != KeyError::Empty {
        return Err(format!("expected KeyError::Empty, observed {error:?}"));
    }
    let oversize = vec![b'k'; crate::MAX_KEY_BYTES.saturating_add(1)];
    let error = HeadKey::new(oversize)
        .err()
        .ok_or_else(|| "an oversize head key was admitted".to_owned())?;
    if !matches!(error, KeyError::TooLong { .. }) {
        return Err(format!("expected KeyError::TooLong, observed {error:?}"));
    }
    HeadKey::new(vec![b'k'; crate::MAX_KEY_BYTES])
        .map(|_| ())
        .map_err(|error| format!("a key at the declared bound was refused: {error}"))
}

fn ac_18_head_absent<S: AuthorityStore + ?Sized>(store: &S) -> Result<(), String> {
    let absent = head_key("ac18/missing")?;
    match store
        .read_head(&absent)
        .map_err(|failure| failure.to_string())?
    {
        HeadRead::Absent => {}
        HeadRead::Present(receipt) => {
            return Err(format!("an uncreated head slot read as {receipt:?}"));
        }
    }
    let present = head_key("ac18/present")?;
    let receipt = initialized_head(store, &present, b"head-1")?;
    let failure = store
        .compare_exchange_head(&absent, receipt.token(), HeadGeneration::from_raw(2), b"x")
        .err()
        .ok_or_else(|| "a conditional write against an absent head succeeded".to_owned())?;
    expect_refusal(
        failure,
        &AuthorityRefusal::TokenKeyMismatch,
        "token issued for another key",
    )?;
    committed(
        store,
        &present,
        receipt.token(),
        HeadGeneration::from_raw(2),
        b"head-2",
    )
    .map(|_| ())
}

fn ac_19_known_root_recovery<S: AuthorityStore + ?Sized>(store: &S) -> Result<(), String> {
    let key = head_key("ac19/head")?;
    let mut receipt = initialized_head(store, &key, b"gen-1")?;
    for generation in 2_u64..=6 {
        let body = format!("gen-{generation}").into_bytes();
        receipt = committed(
            store,
            &key,
            receipt.token(),
            HeadGeneration::from_raw(generation),
            &body,
        )?;
    }
    let recovered = present_head(store, &key)?;
    if recovered.generation() == HeadGeneration::from_raw(6) && recovered.body() == b"gen-6" {
        Ok(())
    } else {
        Err(format!("known-root read recovered {recovered:?}"))
    }
}

fn ac_20_cross_instance_token_refused<S, F>(make_store: &F) -> Result<(), String>
where
    S: AuthorityStore,
    F: Fn(StoreInstanceId) -> S,
{
    let left = make_store(StoreInstanceId::from_raw(11));
    let right = make_store(StoreInstanceId::from_raw(12));
    let key = head_key("ac20/head")?;
    let left_receipt = initialized_head(&left, &key, b"head-1")?;
    initialized_head(&right, &key, b"head-1")?;
    let failure = right
        .compare_exchange_head(
            &key,
            left_receipt.token(),
            HeadGeneration::from_raw(2),
            b"head-2",
        )
        .err()
        .ok_or_else(|| "an endpoint honoured another endpoint's token".to_owned())?;
    expect_refusal(
        failure,
        &AuthorityRefusal::UnknownVersionToken,
        "cross-instance token",
    )?;
    let failure = right
        .authenticate_head_receipt(&left_receipt)
        .err()
        .ok_or_else(|| "an endpoint authenticated another endpoint's receipt".to_owned())?;
    expect_refusal(
        failure,
        &AuthorityRefusal::UnknownVersionToken,
        "cross-instance receipt",
    )
}

/// Run the backend-agnostic conformance suite.
///
/// `make_store` is a factory rather than a store so that every check runs
/// against an independent instance and cross-endpoint checks can build two.
#[must_use]
pub fn run_authority_conformance<S, F>(make_store: F) -> ConformanceReport
where
    S: AuthorityStore,
    F: Fn(StoreInstanceId) -> S,
{
    let mut report = ConformanceReport::default();
    let instance = StoreInstanceId::from_raw(1);
    macro_rules! solo {
        ($id:expr, $requirement:expr, $check:expr) => {{
            let store = make_store(instance);
            report.record($id, $requirement, $check(&store));
        }};
    }

    solo!(
        "AC-01",
        "put-if-absent creates an empty immutable slot",
        ac_01_put_creates
    );
    solo!(
        "AC-02",
        "put-if-absent of an identical body is an idempotent retry",
        ac_02_put_identical_retry
    );
    solo!(
        "AC-03",
        "put-if-absent of a different body conflicts and preserves the original",
        ac_03_put_conflict_preserves
    );
    solo!(
        "AC-04",
        "an immutable body is readable by exact key immediately after the write",
        ac_04_read_after_write
    );
    solo!(
        "AC-05",
        "head creation and head read agree",
        ac_05_head_initialize_and_read
    );
    solo!(
        "AC-06",
        "a head read after a successful conditional write observes that write",
        ac_06_read_your_own_writes
    );
    solo!(
        "AC-07",
        "a conditional write with the exact predecessor token publishes",
        ac_07_cas_exact_predecessor
    );
    solo!(
        "AC-08",
        "exactly one of N contenders on the same predecessor token wins",
        ac_08_single_winner
    );
    solo!(
        "AC-09",
        "every write mints a version token no other write shares",
        ac_09_token_unique_per_write
    );
    solo!(
        "AC-10",
        "restoring a byte-identical body mints a third token and defeats the original holder",
        ac_10_aba_identical_restore
    );
    solo!(
        "AC-11",
        "head generation strictly increases and a stale generation is refused",
        ac_11_monotone_generation
    );
    solo!(
        "AC-12",
        "a stale but genuinely issued token loses rather than erroring",
        ac_12_stale_token_loses
    );
    solo!(
        "AC-13",
        "a token the store never issued is refused as unknown",
        ac_13_forged_token_refused
    );
    solo!(
        "AC-14",
        "a receipt whose body or generation was altered after issuance is refused",
        ac_14_tampered_receipt_refused
    );
    solo!(
        "AC-15",
        "an authentic stale receipt stays authentic and still loses the conditional write",
        ac_15_authenticity_is_not_currency
    );
    solo!(
        "AC-16",
        "bodies are bounded with a typed refusal and a body at the bound is accepted",
        ac_16_bounded_typed_errors
    );
    report.record(
        "AC-17",
        "keys are bounded and non-empty, and a key at the bound is accepted",
        ac_17_key_admission(),
    );
    solo!(
        "AC-18",
        "an absent head reads as absent and rejects a token issued for another key",
        ac_18_head_absent
    );
    solo!(
        "AC-19",
        "current state is recoverable by following one known root, without listing",
        ac_19_known_root_recovery
    );
    report.record(
        "AC-20",
        "one endpoint never honours another endpoint's version token",
        ac_20_cross_instance_token_refused(&make_store),
    );
    report
}

// --- fault-profile checks ----------------------------------------------------

fn af_01_lost_response_resolves_applied<S: FaultableAuthorityStore + ?Sized>(
    store: &S,
) -> Result<(), String> {
    let key = head_key("af01/head")?;
    let first = initialized_head(store, &key, b"head-1")?;
    store.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::new(
        OpIndex::ZERO,
        FaultKind::LoseResponse,
    )]));
    let failure = store
        .compare_exchange_head(&key, first.token(), HeadGeneration::from_raw(2), b"head-2")
        .err()
        .ok_or_else(|| "a lost response still produced an outcome".to_owned())?;
    if failure.proves_no_effect() {
        return Err("a lost response was reported as proof of non-commit".to_owned());
    }
    store.install_fault_plan(FaultPlan::none());
    match resolve_ambiguous_cas(store, &key, HeadGeneration::from_raw(2), b"head-2")
        .map_err(|failure| failure.to_string())?
    {
        CasResolution::Applied(_) => Ok(()),
        other => Err(format!("resolution after a lost response said {other:?}")),
    }
}

fn af_02_lost_request_resolves_not_applied<S: FaultableAuthorityStore + ?Sized>(
    store: &S,
) -> Result<(), String> {
    let key = head_key("af02/head")?;
    let first = initialized_head(store, &key, b"head-1")?;
    store.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::new(
        OpIndex::ZERO,
        FaultKind::LoseRequest,
    )]));
    let failure = store
        .compare_exchange_head(&key, first.token(), HeadGeneration::from_raw(2), b"head-2")
        .err()
        .ok_or_else(|| "a lost request still produced an outcome".to_owned())?;
    if failure.proves_no_effect() {
        return Err("a lost request was reported as proof of non-commit".to_owned());
    }
    store.install_fault_plan(FaultPlan::none());
    match resolve_ambiguous_cas(store, &key, HeadGeneration::from_raw(2), b"head-2")
        .map_err(|failure| failure.to_string())?
    {
        CasResolution::NotApplied(_) => Ok(()),
        other => Err(format!("resolution after a lost request said {other:?}")),
    }
}

fn af_03_ambiguity_is_indistinguishable<S, F>(make_store: &F) -> Result<(), String>
where
    S: FaultableAuthorityStore,
    F: Fn(StoreInstanceId) -> S,
{
    let instance = StoreInstanceId::from_raw(1);
    let mut observed = Vec::new();
    for kind in [FaultKind::LoseRequest, FaultKind::LoseResponse] {
        let store = make_store(instance);
        let key = head_key("af03/head")?;
        let first = initialized_head(&store, &key, b"head-1")?;
        store.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::new(
            OpIndex::ZERO,
            kind,
        )]));
        let failure = store
            .compare_exchange_head(&key, first.token(), HeadGeneration::from_raw(2), b"head-2")
            .err()
            .ok_or_else(|| "an injected loss still produced an outcome".to_owned())?;
        observed.push(failure);
    }
    let ground_truth_differs = observed.len() == 2;
    if ground_truth_differs && observed[0] == observed[1] {
        if observed[0] == AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse) {
            Ok(())
        } else {
            Err(format!(
                "expected an ambiguous response, observed {:?}",
                observed[0]
            ))
        }
    } else {
        Err("losing the request and losing the response were distinguishable".to_owned())
    }
}

fn af_04_duplicate_put_is_idempotent<S: FaultableAuthorityStore + ?Sized>(
    store: &S,
) -> Result<(), String> {
    let key = immutable_key("af04/seal")?;
    store.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::new(
        OpIndex::ZERO,
        FaultKind::DuplicateRequest {
            deliver: DuplicateDelivery::Second,
        },
    )]));
    let outcome = store
        .put_if_absent(&key, b"seal-body")
        .map_err(|failure| failure.to_string())?;
    if outcome != PutOutcome::IdenticalRetry {
        return Err(format!(
            "the second delivery of a duplicated put reported {outcome:?}"
        ));
    }
    store.install_fault_plan(FaultPlan::none());
    match resolve_ambiguous_put(store, &key, b"seal-body").map_err(|failure| failure.to_string())? {
        PutResolution::PresentIdentical => Ok(()),
        other => Err(format!("a duplicated put left the slot as {other:?}")),
    }
}

fn af_05_duplicate_cas_applies_once<S: FaultableAuthorityStore + ?Sized>(
    store: &S,
) -> Result<(), String> {
    let key = head_key("af05/head")?;
    let first = initialized_head(store, &key, b"head-1")?;
    store.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::new(
        OpIndex::ZERO,
        FaultKind::DuplicateRequest {
            deliver: DuplicateDelivery::Second,
        },
    )]));
    let outcome = store
        .compare_exchange_head(&key, first.token(), HeadGeneration::from_raw(2), b"head-2")
        .map_err(|failure| failure.to_string())?;
    if outcome != CasOutcome::PredecessorMismatch {
        return Err(format!(
            "the second delivery of a duplicated conditional write reported {outcome:?}"
        ));
    }
    store.install_fault_plan(FaultPlan::none());
    let head = present_head(store, &key)?;
    if head.generation() == HeadGeneration::from_raw(2) && head.body() == b"head-2" {
        Ok(())
    } else {
        Err(format!("a duplicated conditional write published {head:?}"))
    }
}

fn af_06_crash_then_unavailable<S: FaultableAuthorityStore + ?Sized>(
    store: &S,
) -> Result<(), String> {
    let key = immutable_key("af06/seal")?;
    store.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::new(
        OpIndex::ZERO,
        FaultKind::Crash {
            position: FaultPosition::BeforeEffect,
        },
    )]));
    let failure = store
        .put_if_absent(&key, b"seal-body")
        .err()
        .ok_or_else(|| "a crash during the request still produced an outcome".to_owned())?;
    if failure.proves_no_effect() {
        return Err("a crash during an in-flight request was reported as non-commit".to_owned());
    }
    let failure = store
        .put_if_absent(&key, b"seal-body")
        .err()
        .ok_or_else(|| "a crashed endpoint accepted a request".to_owned())?;
    expect_refusal(
        failure,
        &AuthorityRefusal::Unavailable,
        "request to a crashed endpoint",
    )?;
    store.restart();
    store.install_fault_plan(FaultPlan::none());
    let outcome = store
        .put_if_absent(&key, b"seal-body")
        .map_err(|failure| format!("a restarted endpoint refused a request: {failure}"))?;
    if outcome == PutOutcome::Created {
        Ok(())
    } else {
        Err(format!(
            "the pre-crash request left partial state: {outcome:?}"
        ))
    }
}

fn af_07_throttle_is_a_refusal<S: FaultableAuthorityStore + ?Sized>(
    store: &S,
) -> Result<(), String> {
    let key = immutable_key("af07/seal")?;
    store.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::new(
        OpIndex::ZERO,
        FaultKind::Throttle,
    )]));
    let failure = store
        .put_if_absent(&key, b"seal-body")
        .err()
        .ok_or_else(|| "a throttled request still produced an outcome".to_owned())?;
    if !failure.proves_no_effect() {
        return Err("shedding a request before any effect must prove non-commit".to_owned());
    }
    expect_refusal(failure, &AuthorityRefusal::Throttled, "throttled request")?;
    store.install_fault_plan(FaultPlan::none());
    let outcome = store
        .put_if_absent(&key, b"seal-body")
        .map_err(|failure| format!("the retry after a throttle was refused: {failure}"))?;
    if outcome == PutOutcome::Created {
        Ok(())
    } else {
        Err(format!(
            "a throttled request left state behind: {outcome:?}"
        ))
    }
}

fn af_08_seeded_plans_replay<S, F>(make_store: &F) -> Result<(), String>
where
    S: FaultableAuthorityStore,
    F: Fn(StoreInstanceId) -> S,
{
    let instance = StoreInstanceId::from_raw(1);
    let left_plan = FaultPlan::seeded(0x5EED_0001, 12, 6);
    let right_plan = FaultPlan::seeded(0x5EED_0001, 12, 6);
    if left_plan != right_plan {
        return Err("the same seed produced two different plans".to_owned());
    }
    if FaultPlan::seeded(0x5EED_0002, 12, 6) == left_plan {
        return Err("two different seeds produced the same plan".to_owned());
    }
    let mut logs = Vec::new();
    for plan in [left_plan, right_plan] {
        let store = make_store(instance);
        store.install_fault_plan(plan);
        let key = immutable_key("af08/seal")?;
        for index in 0_u8..12 {
            let body = [b'b', index];
            let _ignored = store.put_if_absent(&key, &body);
        }
        logs.push(store.fault_log());
    }
    let [left_log, right_log] = logs.as_slice() else {
        return Err("both scripted runs must produce a fault log".to_owned());
    };
    if left_log == right_log {
        Ok(())
    } else {
        Err("replaying an identical seeded plan produced a different fault log".to_owned())
    }
}

/// Run the fault-profile conformance suite.
///
/// This is the half of `VERIFY_SPEC.md` §7 that needs a backend able to inject
/// its own failures.  A production backend that cannot be scripted skips it;
/// its equivalent evidence comes from the deployed fault campaign.
#[must_use]
pub fn run_fault_conformance<S, F>(make_store: F) -> ConformanceReport
where
    S: FaultableAuthorityStore,
    F: Fn(StoreInstanceId) -> S,
{
    let mut report = ConformanceReport::default();
    let instance = StoreInstanceId::from_raw(1);
    macro_rules! solo {
        ($id:expr, $requirement:expr, $check:expr) => {{
            let store = make_store(instance);
            report.record($id, $requirement, $check(&store));
        }};
    }

    solo!(
        "AF-01",
        "a response lost after the effect resolves to applied by exact-key read",
        af_01_lost_response_resolves_applied
    );
    solo!(
        "AF-02",
        "a request lost before the effect resolves to not-applied by exact-key read",
        af_02_lost_request_resolves_not_applied
    );
    report.record(
        "AF-03",
        "losing the request and losing the response are indistinguishable to the caller",
        af_03_ambiguity_is_indistinguishable(&make_store),
    );
    solo!(
        "AF-04",
        "a duplicated put-if-absent is idempotent",
        af_04_duplicate_put_is_idempotent
    );
    solo!(
        "AF-05",
        "a duplicated conditional write applies at most once",
        af_05_duplicate_cas_applies_once
    );
    solo!(
        "AF-06",
        "a crashed endpoint refuses, restarts cleanly, and leaves no partial body",
        af_06_crash_then_unavailable
    );
    solo!(
        "AF-07",
        "a shed request is a refusal, not an ambiguity",
        af_07_throttle_is_a_refusal
    );
    report.record(
        "AF-08",
        "a seeded fault plan replays to an identical fault log",
        af_08_seeded_plans_replay(&make_store),
    );
    report
}
