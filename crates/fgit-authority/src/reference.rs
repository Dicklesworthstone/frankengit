//! The in-memory reference authority profile.
//!
//! # What this is
//!
//! `MemoryAuthorityStore` is the *reference* profile of [`AuthorityStore`]: the
//! executable statement of what the contract means, and the substrate the
//! linearizability checker (FG-004b), the fault campaign (FG-004c), and the lab
//! core (FG-013a) run their scripts against.  It is deterministic, it is
//! scriptable, and it keeps the ground truth every one of those consumers needs
//! in order to judge a caller-visible response.
//!
//! # What this is not
//!
//! It is not durable storage and must never be described as such.  Nothing here
//! survives the process; there is no placement, no replication, no failure
//! domain, and no repair.  An injected [`crate::FaultKind::Crash`] models the
//! endpoint dying with its state intact, which is a process-crash model, not a
//! media-loss model.  A deployment carries canonical authority only through a
//! profile that both passes this contract's conformance suite and satisfies the
//! durability obligations in `NORMATIVE_PROTOCOL_CONTRACTS.md` §9.
//!
//! # Determinism
//!
//! All state sits behind one mutex, and every operation takes a position from a
//! single counter, so a fixed sequence of calls always injects a fixed sequence
//! of faults.  Real threads may share the store, but then the *caller* owns the
//! schedule; the deterministic driver in [`crate::Interleaving`] exists so that tests
//! and campaigns never depend on thread interleaving.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::contract::{AuthorityLimits, AuthorityStore, FaultableAuthorityStore};
use crate::injection::{
    DuplicateDelivery, EffectLog, EffectRecord, FaultKind, FaultLog, FaultPlan, FaultPosition,
    FaultRecord, OpIndex,
};
use crate::keys::{HeadKey, ImmutableKey};
use fgit_types::HeadGeneration;

use crate::tokens::{AuthorityVersionToken, StoreInstanceId};
use crate::vocabulary::{
    AmbiguityReason, AuthenticatedHead, AuthorityFailure, AuthorityOpKind, AuthorityRefusal,
    CasOutcome, HeadInit, HeadRead, HeadReadReceipt, ImmutableRead, PutOutcome,
};

/// A value produced by an effect, plus whether the effect changed state.
struct Applied<T> {
    value: T,
    mutated: bool,
}

impl<T> Applied<T> {
    const fn unchanged(value: T) -> Self {
        Self {
            value,
            mutated: false,
        }
    }

    const fn changed(value: T) -> Self {
        Self {
            value,
            mutated: true,
        }
    }
}

/// The published head of one repository.
#[derive(Clone, Debug)]
struct HeadSlot {
    token: AuthorityVersionToken,
    generation: HeadGeneration,
    body: Vec<u8>,
}

/// What the store recorded when it minted one version token.
///
/// The issuance record is append-only.  It is simultaneously the ABA defence
/// (a token is never minted twice, so restoring old bytes cannot restore an old
/// token) and the authentication oracle (a token absent from this map was never
/// issued here, whoever presents it).
#[derive(Clone, Debug)]
struct IssuedVersion {
    key: HeadKey,
    generation: HeadGeneration,
    body: Vec<u8>,
}

#[derive(Debug)]
struct State {
    immutable: BTreeMap<ImmutableKey, Vec<u8>>,
    heads: BTreeMap<HeadKey, HeadSlot>,
    issuance: BTreeMap<AuthorityVersionToken, IssuedVersion>,
    next_issuance: u64,
    op_index: u64,
    logical_time: u64,
    fault_sequence: u64,
    effect_sequence: u64,
    crashed: bool,
    plan: FaultPlan,
    faults: Vec<FaultRecord>,
    effects: Vec<EffectRecord>,
}

/// Construction parameters for [`MemoryAuthorityStore`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryStoreConfig {
    /// Endpoint and credential identity of the instance.
    pub instance: StoreInstanceId,
    /// Declared resource bounds.
    pub limits: AuthorityLimits,
    /// The fault script to run.
    pub plan: FaultPlan,
}

impl Default for MemoryStoreConfig {
    fn default() -> Self {
        Self {
            instance: StoreInstanceId::from_raw(1),
            limits: AuthorityLimits::default(),
            plan: FaultPlan::none(),
        }
    }
}

/// The deterministic, scriptable reference authority backend.
#[derive(Debug)]
pub struct MemoryAuthorityStore {
    instance: StoreInstanceId,
    limits: AuthorityLimits,
    state: Mutex<State>,
}

impl MemoryAuthorityStore {
    /// A store with default bounds and no injected faults.
    #[must_use]
    pub fn new(instance: StoreInstanceId) -> Self {
        Self::with_config(MemoryStoreConfig {
            instance,
            ..MemoryStoreConfig::default()
        })
    }

    /// A store running the supplied fault script.
    #[must_use]
    pub fn with_fault_plan(instance: StoreInstanceId, plan: FaultPlan) -> Self {
        Self::with_config(MemoryStoreConfig {
            instance,
            plan,
            ..MemoryStoreConfig::default()
        })
    }

    /// A store built from a complete configuration.
    #[must_use]
    pub fn with_config(config: MemoryStoreConfig) -> Self {
        Self {
            instance: config.instance,
            limits: config.limits,
            state: Mutex::new(State {
                immutable: BTreeMap::new(),
                heads: BTreeMap::new(),
                issuance: BTreeMap::new(),
                next_issuance: 0,
                op_index: 0,
                logical_time: 0,
                fault_sequence: 0,
                effect_sequence: 0,
                crashed: false,
                plan: config.plan,
                faults: Vec::new(),
                effects: Vec::new(),
            }),
        }
    }

    /// The store's logical clock, advanced only by injected delays.
    #[must_use]
    pub fn logical_time(&self) -> u64 {
        self.locked().logical_time
    }

    /// How many operations the store has begun.
    #[must_use]
    pub fn operations_started(&self) -> u64 {
        self.locked().op_index
    }

    /// How many version tokens the store has minted.
    #[must_use]
    pub fn issued_versions(&self) -> usize {
        self.locked().issuance.len()
    }

    fn locked(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Run one operation through the fault engine.
    ///
    /// The effect is passed as a callable rather than executed inline because a
    /// duplicated request has to apply it twice against the same state.
    fn run<T>(
        &self,
        op_kind: AuthorityOpKind,
        effect: &dyn Fn(&mut State) -> Result<Applied<T>, AuthorityRefusal>,
    ) -> Result<T, AuthorityFailure> {
        let mut guard = self.locked();
        let state = &mut *guard;

        let at = OpIndex::from_raw(state.op_index);
        state.op_index = state.op_index.saturating_add(1);

        if state.crashed {
            return Err(AuthorityFailure::Refused(AuthorityRefusal::Unavailable));
        }

        let directives = state.plan.matching(at, op_kind);

        for directive in &directives {
            match directive.kind {
                FaultKind::Throttle => {
                    record_fault(state, at, op_kind, directive.kind, false);
                    return Err(AuthorityFailure::Refused(AuthorityRefusal::Throttled));
                }
                FaultKind::LoseRequest => {
                    record_fault(state, at, op_kind, directive.kind, false);
                    return Err(AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse));
                }
                FaultKind::Crash {
                    position: FaultPosition::BeforeEffect,
                } => {
                    state.crashed = true;
                    record_fault(state, at, op_kind, directive.kind, false);
                    return Err(AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse));
                }
                FaultKind::Delay {
                    position: FaultPosition::BeforeEffect,
                    ticks,
                } => {
                    state.logical_time = state.logical_time.saturating_add(ticks);
                    record_fault(state, at, op_kind, directive.kind, false);
                }
                FaultKind::Crash { .. }
                | FaultKind::Delay { .. }
                | FaultKind::LoseResponse
                | FaultKind::DuplicateRequest { .. } => {}
            }
        }

        let mut outcome = effect(state);
        record_effect(state, at, op_kind, &outcome);

        if let Some(directive) = directives
            .iter()
            .find(|directive| matches!(directive.kind, FaultKind::DuplicateRequest { .. }))
        {
            let second = effect(state);
            record_effect(state, at, op_kind, &second);
            record_fault(state, at, op_kind, directive.kind, true);
            if matches!(
                directive.kind,
                FaultKind::DuplicateRequest {
                    deliver: DuplicateDelivery::Second
                }
            ) {
                outcome = second;
            }
        }

        for directive in &directives {
            match directive.kind {
                FaultKind::Delay {
                    position: FaultPosition::AfterEffect,
                    ticks,
                } => {
                    state.logical_time = state.logical_time.saturating_add(ticks);
                    record_fault(state, at, op_kind, directive.kind, true);
                }
                FaultKind::LoseResponse => {
                    record_fault(state, at, op_kind, directive.kind, true);
                    return Err(AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse));
                }
                FaultKind::Crash {
                    position: FaultPosition::AfterEffect,
                } => {
                    state.crashed = true;
                    record_fault(state, at, op_kind, directive.kind, true);
                    return Err(AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse));
                }
                FaultKind::Crash { .. }
                | FaultKind::Delay { .. }
                | FaultKind::LoseRequest
                | FaultKind::Throttle
                | FaultKind::DuplicateRequest { .. } => {}
            }
        }

        drop(guard);
        outcome
            .map(|applied| applied.value)
            .map_err(AuthorityFailure::Refused)
    }
}

/// Bodies are bounded server-side, inside the effect, so a body-size refusal is
/// subject to exactly the same fault script as any other request.
const fn check_body(limits: AuthorityLimits, body: &[u8]) -> Result<(), AuthorityRefusal> {
    if body.len() > limits.body_bytes {
        return Err(AuthorityRefusal::BodyTooLarge {
            len: body.len(),
            limit: limits.body_bytes,
        });
    }
    Ok(())
}

fn record_fault(
    state: &mut State,
    at: OpIndex,
    op_kind: AuthorityOpKind,
    kind: FaultKind,
    effect_reached: bool,
) {
    let sequence = state.fault_sequence;
    state.fault_sequence = state.fault_sequence.saturating_add(1);
    state.faults.push(FaultRecord {
        sequence,
        at,
        op_kind,
        kind,
        effect_reached,
        logical_time: state.logical_time,
    });
}

fn record_effect<T>(
    state: &mut State,
    at: OpIndex,
    op_kind: AuthorityOpKind,
    outcome: &Result<Applied<T>, AuthorityRefusal>,
) {
    let sequence = state.effect_sequence;
    state.effect_sequence = state.effect_sequence.saturating_add(1);
    let mutated = outcome.as_ref().is_ok_and(|applied| applied.mutated);
    state.effects.push(EffectRecord {
        sequence,
        at,
        op_kind,
        mutated,
        logical_time: state.logical_time,
    });
}

fn mint(state: &mut State, instance: StoreInstanceId) -> AuthorityVersionToken {
    let token = AuthorityVersionToken::mint(instance, state.next_issuance);
    state.next_issuance = state.next_issuance.saturating_add(1);
    token
}

fn receipt_for(key: &HeadKey, slot: &HeadSlot) -> HeadReadReceipt {
    HeadReadReceipt::new(key.clone(), slot.token, slot.generation, slot.body.clone())
}

impl AuthorityStore for MemoryAuthorityStore {
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
        let limits = self.limits;
        self.run(AuthorityOpKind::PutIfAbsent, &|state: &mut State| {
            check_body(limits, body)?;
            match state.immutable.get(key) {
                Some(existing) if existing.as_slice() == body => {
                    Ok(Applied::unchanged(PutOutcome::IdenticalRetry))
                }
                Some(_) => Ok(Applied::unchanged(PutOutcome::Conflict)),
                None => {
                    if state.immutable.len() >= limits.immutable_slots {
                        return Err(AuthorityRefusal::CapacityExhausted {
                            occupancy: state.immutable.len(),
                            limit: limits.immutable_slots,
                        });
                    }
                    state.immutable.insert(key.clone(), body.to_vec());
                    Ok(Applied::changed(PutOutcome::Created))
                }
            }
        })
    }

    fn read_immutable(&self, key: &ImmutableKey) -> Result<ImmutableRead, AuthorityFailure> {
        self.run(AuthorityOpKind::ReadImmutable, &|state: &mut State| {
            Ok(Applied::unchanged(
                state
                    .immutable
                    .get(key)
                    .map_or(ImmutableRead::Absent, |body| {
                        ImmutableRead::Present(body.clone())
                    }),
            ))
        })
    }

    fn initialize_head(
        &self,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, AuthorityFailure> {
        let limits = self.limits;
        let instance = self.instance;
        self.run(AuthorityOpKind::InitializeHead, &|state: &mut State| {
            check_body(limits, body)?;
            if let Some(slot) = state.heads.get(key) {
                if slot.generation == generation && slot.body.as_slice() == body {
                    return Ok(Applied::unchanged(HeadInit::IdenticalRetry(receipt_for(
                        key, slot,
                    ))));
                }
                return Ok(Applied::unchanged(HeadInit::Conflict));
            }
            if state.heads.len() >= limits.head_slots {
                return Err(AuthorityRefusal::CapacityExhausted {
                    occupancy: state.heads.len(),
                    limit: limits.head_slots,
                });
            }
            if state.issuance.len() >= limits.version_tokens {
                return Err(AuthorityRefusal::CapacityExhausted {
                    occupancy: state.issuance.len(),
                    limit: limits.version_tokens,
                });
            }
            let token = mint(state, instance);
            let slot = HeadSlot {
                token,
                generation,
                body: body.to_vec(),
            };
            state.issuance.insert(
                token,
                IssuedVersion {
                    key: key.clone(),
                    generation,
                    body: body.to_vec(),
                },
            );
            let receipt = receipt_for(key, &slot);
            state.heads.insert(key.clone(), slot);
            Ok(Applied::changed(HeadInit::Created(receipt)))
        })
    }

    fn read_head(&self, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        self.run(AuthorityOpKind::ReadHead, &|state: &mut State| {
            Ok(Applied::unchanged(
                state.heads.get(key).map_or(HeadRead::Absent, |slot| {
                    HeadRead::Present(receipt_for(key, slot))
                }),
            ))
        })
    }

    fn compare_exchange_head(
        &self,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        let limits = self.limits;
        let instance = self.instance;
        self.run(
            AuthorityOpKind::CompareExchangeHead,
            &|state: &mut State| {
                check_body(limits, new_body)?;
                let Some(issued) = state.issuance.get(&expected) else {
                    return Err(AuthorityRefusal::UnknownVersionToken);
                };
                if &issued.key != key {
                    return Err(AuthorityRefusal::TokenKeyMismatch);
                }
                let Some(slot) = state.heads.get(key) else {
                    return Err(AuthorityRefusal::HeadAbsent);
                };
                if slot.token != expected {
                    return Ok(Applied::unchanged(CasOutcome::PredecessorMismatch));
                }
                if new_generation <= slot.generation {
                    return Err(AuthorityRefusal::NonMonotoneGeneration {
                        current: slot.generation,
                        proposed: new_generation,
                    });
                }
                if state.issuance.len() >= limits.version_tokens {
                    return Err(AuthorityRefusal::CapacityExhausted {
                        occupancy: state.issuance.len(),
                        limit: limits.version_tokens,
                    });
                }
                let token = mint(state, instance);
                state.issuance.insert(
                    token,
                    IssuedVersion {
                        key: key.clone(),
                        generation: new_generation,
                        body: new_body.to_vec(),
                    },
                );
                let slot = HeadSlot {
                    token,
                    generation: new_generation,
                    body: new_body.to_vec(),
                };
                let receipt = receipt_for(key, &slot);
                state.heads.insert(key.clone(), slot);
                Ok(Applied::changed(CasOutcome::Committed(receipt)))
            },
        )
    }

    fn authenticate_head_receipt(
        &self,
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure> {
        let instance = self.instance;
        self.run(
            AuthorityOpKind::AuthenticateHeadReceipt,
            &|state: &mut State| {
                if receipt.token().minted_by() != instance {
                    return Err(AuthorityRefusal::UnknownVersionToken);
                }
                let Some(issued) = state.issuance.get(&receipt.token()) else {
                    return Err(AuthorityRefusal::UnknownVersionToken);
                };
                if &issued.key != receipt.key() {
                    return Err(AuthorityRefusal::TokenKeyMismatch);
                }
                if issued.generation != receipt.generation() {
                    return Err(AuthorityRefusal::TokenGenerationMismatch);
                }
                if issued.body.as_slice() != receipt.body() {
                    return Err(AuthorityRefusal::TokenBodyMismatch);
                }
                Ok(Applied::unchanged(AuthenticatedHead::new(
                    receipt.clone(),
                    instance,
                )))
            },
        )
    }
}

impl FaultableAuthorityStore for MemoryAuthorityStore {
    fn install_fault_plan(&self, plan: FaultPlan) {
        let mut state = self.locked();
        state.plan = plan;
        state.op_index = 0;
        state.logical_time = 0;
        state.fault_sequence = 0;
        state.effect_sequence = 0;
        state.faults.clear();
        state.effects.clear();
    }

    fn fault_log(&self) -> FaultLog {
        FaultLog::from_records(self.locked().faults.clone())
    }

    fn effect_log(&self) -> EffectLog {
        EffectLog::from_records(self.locked().effects.clone())
    }

    fn is_crashed(&self) -> bool {
        self.locked().crashed
    }

    fn restart(&self) {
        self.locked().crashed = false;
    }
}
