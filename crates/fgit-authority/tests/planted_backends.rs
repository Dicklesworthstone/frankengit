//! Planted wrong implementations must fail the same conformance suite.
//!
//! A conformance suite that only ever runs against the implementation it was
//! written beside proves nothing: it may be asserting whatever that code
//! happens to do. Every backend below is one small, deliberate defect away
//! from a correct store, and [`Defect::None`] is the undamaged control that
//! must pass every check. A plant that fails, next to a control that passes,
//! is what makes a named check evidence rather than decoration.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use fgit_authority::{
    AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityRefusal, AuthorityStore,
    AuthorityVersionToken, CasOutcome, HeadGeneration, HeadInit, HeadKey, HeadRead,
    HeadReadReceipt, ImmutableKey, ImmutableRead, MemoryAuthorityStore, PutOutcome,
    StoreInstanceId, VERSION_TOKEN_BYTES, run_authority_conformance,
};

/// The single behaviour each plant gets wrong.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Defect {
    /// No defect: the control that must pass every check.
    None,
    /// Version tokens are a function of the stored body, so a byte-identical
    /// restore resurrects an earlier token.
    ContentDerivedToken,
    /// Any token this store ever issued for the key is treated as current.
    AcceptsStaleToken,
    /// The predecessor token is not consulted at all: last writer wins.
    IgnoresExpectedToken,
    /// The head generation may move backwards.
    AllowsGenerationRollback,
    /// Any well-formed token is honoured, issued here or not.
    AcceptsForgedToken,
}

#[derive(Clone, Debug)]
struct Slot {
    token: AuthorityVersionToken,
    generation: HeadGeneration,
    body: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Issued {
    key: HeadKey,
    generation: HeadGeneration,
    body: Vec<u8>,
}

#[derive(Debug, Default)]
struct PlantedState {
    immutable: BTreeMap<ImmutableKey, Vec<u8>>,
    heads: BTreeMap<HeadKey, Slot>,
    issuance: BTreeMap<AuthorityVersionToken, Issued>,
    next_issuance: u64,
}

/// A minimal authority backend with exactly one switchable defect.
#[derive(Debug)]
struct PlantedStore {
    instance: StoreInstanceId,
    limits: AuthorityLimits,
    defect: Defect,
    state: Mutex<PlantedState>,
}

impl PlantedStore {
    fn new(instance: StoreInstanceId, defect: Defect) -> Self {
        Self {
            instance,
            limits: AuthorityLimits::default(),
            defect,
            state: Mutex::new(PlantedState::default()),
        }
    }

    fn locked(&self) -> MutexGuard<'_, PlantedState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn check_body(&self, body: &[u8]) -> Result<(), AuthorityFailure> {
        if body.len() > self.limits.max_body_bytes {
            return Err(AuthorityFailure::Refused(AuthorityRefusal::BodyTooLarge {
                len: body.len(),
                limit: self.limits.max_body_bytes,
            }));
        }
        Ok(())
    }

    fn mint(&self, state: &mut PlantedState, body: &[u8]) -> AuthorityVersionToken {
        if self.defect == Defect::ContentDerivedToken {
            // A deliberately content-addressed token: the ABA hole.
            let mut hash = 0xcbf2_9ce4_8422_2325_u64;
            for byte in body {
                hash ^= u64::from(*byte);
                hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            }
            let mut bytes = [0_u8; VERSION_TOKEN_BYTES];
            bytes[..8].copy_from_slice(&self.instance.raw().to_be_bytes());
            bytes[8..].copy_from_slice(&hash.to_be_bytes());
            return AuthorityVersionToken::from_opaque_bytes(bytes);
        }
        let mut bytes = [0_u8; VERSION_TOKEN_BYTES];
        bytes[..8].copy_from_slice(&self.instance.raw().to_be_bytes());
        bytes[8..].copy_from_slice(&state.next_issuance.to_be_bytes());
        state.next_issuance = state.next_issuance.saturating_add(1);
        AuthorityVersionToken::from_opaque_bytes(bytes)
    }
}

fn receipt_for(key: &HeadKey, slot: &Slot) -> HeadReadReceipt {
    HeadReadReceipt::new(key.clone(), slot.token, slot.generation, slot.body.clone())
}

impl AuthorityStore for PlantedStore {
    fn instance_id(&self) -> StoreInstanceId {
        self.instance
    }

    fn limits(&self) -> AuthorityLimits {
        self.limits
    }

    fn put_if_absent(
        &self,
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        self.check_body(body)?;
        let mut state = self.locked();
        let outcome = match state.immutable.get(key) {
            Some(existing) if existing.as_slice() == body => PutOutcome::IdenticalRetry,
            Some(_) => PutOutcome::Conflict,
            None => {
                state.immutable.insert(key.clone(), body.to_vec());
                PutOutcome::Created
            }
        };
        drop(state);
        Ok(outcome)
    }

    fn read_immutable(&self, key: &ImmutableKey) -> Result<ImmutableRead, AuthorityFailure> {
        Ok(self
            .locked()
            .immutable
            .get(key)
            .map_or(ImmutableRead::Absent, |body| {
                ImmutableRead::Present(body.clone())
            }))
    }

    fn initialize_head(
        &self,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, AuthorityFailure> {
        self.check_body(body)?;
        let mut state = self.locked();
        if let Some(slot) = state.heads.get(key) {
            if slot.generation == generation && slot.body.as_slice() == body {
                return Ok(HeadInit::IdenticalRetry(receipt_for(key, slot)));
            }
            return Ok(HeadInit::Conflict);
        }
        let token = self.mint(&mut state, body);
        let slot = Slot {
            token,
            generation,
            body: body.to_vec(),
        };
        state.issuance.insert(
            token,
            Issued {
                key: key.clone(),
                generation,
                body: body.to_vec(),
            },
        );
        let receipt = receipt_for(key, &slot);
        state.heads.insert(key.clone(), slot);
        drop(state);
        Ok(HeadInit::Created(receipt))
    }

    fn read_head(&self, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        Ok(self
            .locked()
            .heads
            .get(key)
            .map_or(HeadRead::Absent, |slot| {
                HeadRead::Present(receipt_for(key, slot))
            }))
    }

    fn compare_exchange_head(
        &self,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        self.check_body(new_body)?;
        let mut state = self.locked();

        if self.defect != Defect::AcceptsForgedToken && self.defect != Defect::IgnoresExpectedToken
        {
            let Some(issued) = state.issuance.get(&expected) else {
                return Err(AuthorityFailure::Refused(
                    AuthorityRefusal::UnknownVersionToken,
                ));
            };
            if &issued.key != key {
                return Err(AuthorityFailure::Refused(
                    AuthorityRefusal::TokenKeyMismatch,
                ));
            }
        }

        let Some(slot) = state.heads.get(key) else {
            return Err(AuthorityFailure::Refused(AuthorityRefusal::HeadAbsent));
        };
        let current_generation = slot.generation;
        let stale = slot.token != expected;

        let honour = match self.defect {
            Defect::IgnoresExpectedToken | Defect::AcceptsStaleToken => true,
            Defect::AcceptsForgedToken
            | Defect::ContentDerivedToken
            | Defect::AllowsGenerationRollback
            | Defect::None => !stale,
        };
        if !honour {
            return Ok(CasOutcome::PredecessorMismatch);
        }

        if self.defect != Defect::AllowsGenerationRollback && new_generation <= current_generation {
            return Err(AuthorityFailure::Refused(
                AuthorityRefusal::NonMonotoneGeneration {
                    current: current_generation,
                    proposed: new_generation,
                },
            ));
        }

        let token = self.mint(&mut state, new_body);
        state.issuance.insert(
            token,
            Issued {
                key: key.clone(),
                generation: new_generation,
                body: new_body.to_vec(),
            },
        );
        let slot = Slot {
            token,
            generation: new_generation,
            body: new_body.to_vec(),
        };
        let receipt = receipt_for(key, &slot);
        state.heads.insert(key.clone(), slot);
        drop(state);
        Ok(CasOutcome::Committed(receipt))
    }

    fn authenticate_head_receipt(
        &self,
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure> {
        if self.defect == Defect::AcceptsForgedToken {
            return Ok(AuthenticatedHead::new(receipt.clone(), self.instance));
        }
        let state = self.locked();
        let Some(issued) = state.issuance.get(&receipt.token()) else {
            return Err(AuthorityFailure::Refused(
                AuthorityRefusal::UnknownVersionToken,
            ));
        };
        if &issued.key != receipt.key() {
            return Err(AuthorityFailure::Refused(
                AuthorityRefusal::TokenKeyMismatch,
            ));
        }
        if issued.generation != receipt.generation() {
            return Err(AuthorityFailure::Refused(
                AuthorityRefusal::TokenGenerationMismatch,
            ));
        }
        if issued.body.as_slice() != receipt.body() {
            return Err(AuthorityFailure::Refused(
                AuthorityRefusal::TokenBodyMismatch,
            ));
        }
        drop(state);
        Ok(AuthenticatedHead::new(receipt.clone(), self.instance))
    }
}

fn failures_for(defect: Defect) -> Vec<&'static str> {
    let report = run_authority_conformance(move |instance| PlantedStore::new(instance, defect));
    report.failed_ids()
}

#[test]
fn the_undamaged_control_passes_every_check() {
    let report = run_authority_conformance(|instance| PlantedStore::new(instance, Defect::None));
    assert!(
        report.is_pass(),
        "the control plant must pass, so a plant's failure is attributable to its defect: {:#?}",
        report.failures().collect::<Vec<_>>()
    );
}

#[test]
fn the_reference_profile_and_the_control_agree() {
    let reference = run_authority_conformance(MemoryAuthorityStore::new);
    let control = run_authority_conformance(|instance| PlantedStore::new(instance, Defect::None));
    assert_eq!(reference.failed_ids(), control.failed_ids());
    assert!(reference.is_pass() && control.is_pass());
}

#[test]
fn content_derived_tokens_fail_the_aba_check() {
    let failed = failures_for(Defect::ContentDerivedToken);
    assert!(
        failed.contains(&"AC-10"),
        "a byte-identical restore resurrects the original token and must be caught by AC-10, \
         failures were {failed:?}"
    );
    // AC-09 writes three distinct bodies, so a content-derived token still looks
    // unique there. That is precisely why AC-10 exists as a separate check: the
    // defect is only observable across a restore, and a suite without AC-10
    // would rate this backend conformant.
    assert!(
        !failed.contains(&"AC-09"),
        "AC-09 is not the check that catches this defect; AC-10 is"
    );
}

#[test]
fn accepting_stale_tokens_fails_the_stale_token_checks() {
    let failed = failures_for(Defect::AcceptsStaleToken);
    assert!(
        failed.contains(&"AC-12"),
        "honouring a superseded token must be caught by AC-12, failures were {failed:?}"
    );
    assert!(
        failed.contains(&"AC-10"),
        "honouring a superseded token reopens ABA, failures were {failed:?}"
    );
    assert!(
        failed.contains(&"AC-15"),
        "authenticity must not become currency, failures were {failed:?}"
    );
}

#[test]
fn ignoring_the_expected_token_fails_the_single_winner_check() {
    let failed = failures_for(Defect::IgnoresExpectedToken);
    assert!(
        failed.contains(&"AC-08"),
        "last-writer-wins must be caught by AC-08, failures were {failed:?}"
    );
}

#[test]
fn allowing_generation_rollback_fails_the_monotone_check() {
    let failed = failures_for(Defect::AllowsGenerationRollback);
    assert!(
        failed.contains(&"AC-11"),
        "a head that can move backwards must be caught by AC-11, failures were {failed:?}"
    );
}

#[test]
fn accepting_forged_tokens_fails_the_forged_token_checks() {
    let failed = failures_for(Defect::AcceptsForgedToken);
    assert!(
        failed.contains(&"AC-13"),
        "a token the store never issued must be caught by AC-13, failures were {failed:?}"
    );
    assert!(
        failed.contains(&"AC-20"),
        "endpoint confusion must be caught by AC-20, failures were {failed:?}"
    );
}

#[test]
fn every_plant_fails_at_least_one_named_check() {
    for defect in [
        Defect::ContentDerivedToken,
        Defect::AcceptsStaleToken,
        Defect::IgnoresExpectedToken,
        Defect::AllowsGenerationRollback,
        Defect::AcceptsForgedToken,
    ] {
        let failed = failures_for(defect);
        assert!(
            !failed.is_empty(),
            "{defect:?} slipped through the entire suite"
        );
    }
}
