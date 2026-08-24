//! A bounded, deterministic store of what peers have told us.
//!
//! `frankengit-fg036a`. Cells gossip head tokens and object locations so that
//! other cells can find things faster. None of it is evidence.
//!
//! # This is a cache of claims, not storage
//!
//! §4 forbids an in-memory map described as durable storage, and this is not
//! one: nothing here survives the process, nothing here is authoritative, and
//! losing all of it costs latency and nothing else. §5.1 names caches and
//! gossip as hints and projections explicitly. The type reflects that — every
//! value comes back as a [`Hint`], so a caller cannot reach an owned value
//! without passing a check.
//!
//! # Two bounds that are behaviour, not hygiene
//!
//! *Capacity is enforced before insertion.* Gossip arrives from peers, so an
//! unbounded map is a peer-controlled allocation. §14 asks for resource bounds
//! enforced before allocation and work, and refusing at the boundary is the
//! difference between a bounded cache and a memory-pressure vector.
//!
//! *Iteration is ordered.* The backing map is a [`BTreeMap`], so peers come out
//! in key order regardless of the order they were heard from. §5.3 forbids
//! relying on map iteration order, and for a routing input the consequence is
//! sharper than usual: two cells with identical gossip must make identical
//! choices, and they cannot if one of them enumerates in hash order.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use crate::hint::{Hint, HintSource};

/// What went wrong accepting gossip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GossipRefusal {
    /// Accepting a new peer would exceed the configured bound.
    ///
    /// Refused rather than evicting something else: an eviction policy chosen
    /// here would be a policy peers could drive by talking more, and the
    /// caller is better placed to decide what to forget.
    CapacityExceeded {
        /// The bound that would have been passed.
        capacity: usize,
    },
}

impl core::fmt::Display for GossipRefusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CapacityExceeded { capacity } => write!(
                formatter,
                "the gossip view already holds its bound of {capacity} peers"
            ),
        }
    }
}

impl core::error::Error for GossipRefusal {}

/// The most recent claim from each peer, bounded and ordered.
///
/// Generic over the peer key and the claimed value so that head tokens and
/// object locations use one implementation. A second copy specialised per
/// payload would be free to drift on the two rules above, which are the only
/// interesting things this type does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GossipView<P, V> {
    capacity: usize,
    claims: BTreeMap<P, V>,
}

impl<P: Ord, V> GossipView<P, V> {
    /// A view that will hold at most `capacity` peers.
    #[must_use]
    pub const fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            claims: BTreeMap::new(),
        }
    }

    /// The bound this view was built with.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// How many peers are currently represented.
    #[must_use]
    pub fn len(&self) -> usize {
        self.claims.len()
    }

    /// Whether anything has been heard.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.claims.is_empty()
    }

    /// Record what a peer says, replacing anything it said before.
    ///
    /// Replacing an existing peer's claim is always admitted, including at
    /// capacity: it consumes no new slot, and refusing it would freeze the view
    /// at whatever it happened to hold when it filled — turning a bound meant
    /// to cap memory into one that caps freshness.
    ///
    /// # Errors
    ///
    /// [`GossipRefusal::CapacityExceeded`] when admitting a *new* peer would
    /// pass the bound. Checked before the entry is created.
    pub fn observe(&mut self, peer: P, claim: V) -> Result<(), GossipRefusal> {
        // Read the bound before taking the entry: the occupied arm needs no
        // slot, so the check has to distinguish the two cases without holding
        // a mutable borrow across it.
        let occupied_count = self.claims.len();
        let capacity = self.capacity;
        match self.claims.entry(peer) {
            Entry::Occupied(mut occupied) => {
                occupied.insert(claim);
            }
            Entry::Vacant(vacant) => {
                if occupied_count >= capacity {
                    return Err(GossipRefusal::CapacityExceeded { capacity });
                }
                vacant.insert(claim);
            }
        }
        Ok(())
    }

    /// What a peer claims, as a hint.
    ///
    /// Returned wrapped so the call site cannot treat it as a reading. See
    /// [`Hint`] for why the wrapper is a type rather than a convention.
    #[must_use]
    pub fn claim_of(&self, peer: &P) -> Option<Hint<&V>> {
        self.claims
            .get(peer)
            .map(|claim| Hint::new(claim, HintSource::Gossip))
    }

    /// Every claim, in peer order.
    ///
    /// Ordered so that two cells holding the same gossip iterate identically.
    pub fn claims(&self) -> impl Iterator<Item = (&P, Hint<&V>)> {
        self.claims
            .iter()
            .map(|(peer, claim)| (peer, Hint::new(claim, HintSource::Gossip)))
    }

    /// Every peer, in order.
    pub fn peers(&self) -> impl Iterator<Item = &P> {
        self.claims.keys()
    }

    /// Drop what a peer said, freeing its slot.
    ///
    /// Returns whether anything was held. This is the caller's eviction lever,
    /// deliberately left to them rather than applied automatically inside
    /// [`Self::observe`].
    pub fn forget(&mut self, peer: &P) -> bool {
        self.claims.remove(peer).is_some()
    }

    /// Drop everything.
    ///
    /// Cheap and always safe, because none of this was evidence. A cell that
    /// suspects its gossip is poisoned can call this and lose only speed.
    pub fn forget_all(&mut self) {
        self.claims.clear();
    }
}
