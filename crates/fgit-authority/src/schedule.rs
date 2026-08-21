//! Deterministic interleaving of logical authority clients.
//!
//! A linearizable store executes each operation atomically, so the interesting
//! concurrency in this contract does not live inside one call: it lives between
//! a client's authenticated head read and the conditional replacement it later
//! attempts with the token that read returned.  Two clients that both read
//! generation `n` and then both attempt generation `n + 1` are the entire
//! contention story, and reproducing it needs an interleaving of *operations*,
//! not an interleaving of threads.
//!
//! This module therefore drives client state machines against a store in an
//! order chosen up front.  The order is data, so a campaign failure replays
//! exactly; the observer hook receives one invoke and one return per step,
//! which is the shape the linearizability history checker (FG-004b) consumes.

use crate::contract::AuthorityStore;
use crate::injection::SplitMix64;
use crate::vocabulary::{AuthorityOp, AuthorityResponse};

/// Identity of one logical client in an interleaved run.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ClientId(u32);

impl ClientId {
    /// Name a client.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// The raw client discriminator.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// The client's index into a slice of clients.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// A logical client: a state machine that emits operations and consumes responses.
pub trait AuthorityClient {
    /// The next operation to issue, or `None` when the client has finished.
    fn next_op(&mut self) -> Option<AuthorityOp>;

    /// Consume the response to the operation most recently returned by [`Self::next_op`].
    fn observe(&mut self, response: &AuthorityResponse);
}

/// A hook that sees every invocation and every return.
///
/// Invoke and return are reported separately so that an ambiguous return can be
/// recorded as an operation whose effect may or may not have linearized, which
/// is precisely the case a linearizability search must treat as free.
pub trait AuthorityObserver {
    /// One operation is about to be issued.
    fn on_invoke(&mut self, client: ClientId, step: u64, op: &AuthorityOp);

    /// One operation has returned.
    fn on_return(&mut self, client: ClientId, step: u64, response: &AuthorityResponse);
}

/// An observer that records nothing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NoObserver;

impl AuthorityObserver for NoObserver {
    fn on_invoke(&mut self, _client: ClientId, _step: u64, _op: &AuthorityOp) {}

    fn on_return(&mut self, _client: ClientId, _step: u64, _response: &AuthorityResponse) {}
}

/// The order in which logical clients take their turns.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Interleaving {
    order: Vec<ClientId>,
}

impl Interleaving {
    /// Each client takes one turn per round, in ascending client order.
    #[must_use]
    pub fn round_robin(clients: u32, rounds: u32) -> Self {
        let mut order = Vec::new();
        for _ in 0..rounds {
            for client in 0..clients {
                order.push(ClientId::from_raw(client));
            }
        }
        Self { order }
    }

    /// A reproducible pseudo-random order.
    #[must_use]
    pub fn seeded(clients: u32, steps: u32, seed: u64) -> Self {
        let mut rng = SplitMix64::new(seed);
        let mut order = Vec::new();
        for _ in 0..steps {
            let pick = u32::try_from(rng.next_below(u64::from(clients))).unwrap_or(0);
            order.push(ClientId::from_raw(pick));
        }
        Self { order }
    }

    /// An order written out by hand.
    #[must_use]
    pub const fn explicit(order: Vec<ClientId>) -> Self {
        Self { order }
    }

    /// The scheduled turns, in order.
    #[must_use]
    pub fn order(&self) -> &[ClientId] {
        &self.order
    }

    /// How many turns are scheduled.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.order.len()
    }

    /// Whether no turn is scheduled.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

/// What an interleaved run did.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DriveSummary {
    /// Operations actually issued.
    pub steps: u64,
    /// Scheduled turns skipped because the client had already finished.
    pub skipped: u64,
}

/// Run `clients` against `store` in the scheduled order, reporting every step.
///
/// A scheduled turn for a client that has finished, or for a client index that
/// does not exist, is counted as skipped rather than silently dropped, so a
/// schedule and its run stay comparable.
pub fn drive<S, O>(
    store: &S,
    clients: &mut [Box<dyn AuthorityClient>],
    interleaving: &Interleaving,
    observer: &mut O,
) -> DriveSummary
where
    S: AuthorityStore + ?Sized,
    O: AuthorityObserver + ?Sized,
{
    let mut summary = DriveSummary::default();
    for client_id in interleaving.order() {
        let Some(client) = clients.get_mut(client_id.index()) else {
            summary.skipped = summary.skipped.saturating_add(1);
            continue;
        };
        let Some(op) = client.next_op() else {
            summary.skipped = summary.skipped.saturating_add(1);
            continue;
        };
        let step = summary.steps;
        observer.on_invoke(*client_id, step, &op);
        let response = store.execute(&op);
        observer.on_return(*client_id, step, &response);
        client.observe(&response);
        summary.steps = summary.steps.saturating_add(1);
    }
    summary
}
