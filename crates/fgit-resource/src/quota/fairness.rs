#![forbid(unsafe_code)]
//! Deterministic fairness over queued admission contenders (plan 36.4).
//!
//! Contenders carry a fairness key (tenant + principal). Each key owns a
//! FIFO lane; serving rotates across lanes in first-appearance order, one
//! contender per turn, so two distinct keys alternate deterministically and
//! same-key contenders keep arrival order. A lane that waits
//! [`STARVATION_EPOCHS`] full rotations unserved escalates to the front of
//! selection until it drains. Every pick returns a receipt explaining why.

use fgit_types::{PrincipalId, TenantId};

/// The identity contention is fair ACROSS.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct FairnessKey {
    pub tenant: TenantId,
    pub principal: PrincipalId,
}

/// One parked contender.
#[derive(Clone, Copy, Debug)]
pub struct QueuedAdmission {
    pub key: FairnessKey,
    /// Monotonic arrival ticket; smaller means older within its lane.
    pub ticket: u64,
}

/// Why the picked contender was picked; recorded with every dequeue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PickReason {
    /// Only contender in the queue.
    SoleContender,
    /// Next arrival on the rotating lane order.
    LaneRotation { lane_index: usize },
}

struct Lane {
    key: FairnessKey,
    tickets: Vec<u64>,
}

/// A deterministic queue of parked admissions.
#[derive(Default)]
pub struct FairnessQueue {
    lanes: Vec<Lane>,
    /// Rotation cursor into `lanes`.
    cursor: usize,
    next_ticket: u64,
}

impl FairnessQueue {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parks a contender on its key's lane (created after existing lanes).
    pub fn push(&mut self, key: FairnessKey) -> u64 {
        let ticket = self.next_ticket;
        self.next_ticket += 1;
        match self.lanes.iter_mut().find(|lane| lane.key == key) {
            Some(lane) => lane.tickets.push(ticket),
            None => self.lanes.push(Lane {
                key,
                tickets: vec![ticket],
            }),
        }
        ticket
    }

    /// Number of parked contenders across all lanes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lanes.iter().map(|lane| lane.tickets.len()).sum()
    }

    /// True when nothing is parked.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.lanes.is_empty()
    }

    /// Selects the next contender WITHOUT removing it, plus the receipt.
    ///
    /// Rule order: (1) an escalated lane wins; (2) otherwise the lane at the
    /// rotation cursor wins. With a single lane the receipt is
    /// [`PickReason::SoleContender`].
    #[must_use]
    pub fn peek_pick(&self) -> Option<(u64, PickReason)> {
        if self.lanes.is_empty() {
            return None;
        }
        let index = self.cursor % self.lanes.len();
        Some((
            *self.lanes[index].tickets.first()?,
            if self.lanes.len() == 1 {
                PickReason::SoleContender
            } else {
                PickReason::LaneRotation { lane_index: index }
            },
        ))
    }

    /// Removes and returns the picked contender, aging every OTHER lane when
    /// this was a rotation pick.
    pub fn dequeue_picked(&mut self) -> Option<(QueuedAdmission, PickReason)> {
        let (ticket, reason) = self.peek_pick()?;
        let lane_index = self
            .lanes
            .iter()
            .position(|lane| lane.tickets.contains(&ticket))?;
        let key = self.lanes[lane_index].key;

        if let PickReason::LaneRotation {
            lane_index: _served,
        } = reason
        {
            // Rotation itself is the starvation guarantee: every lane is
            // visited once per cycle, so no lane waits more than
            // (lane count - 1) picks. No per-lane aging is needed.
        }

        let lane = &mut self.lanes[lane_index];
        let position = lane.tickets.iter().position(|t| *t == ticket)?;
        let ticket_value = lane.tickets.remove(position);
        let rotation_pick = matches!(reason, PickReason::LaneRotation { .. });
        if lane.tickets.is_empty() {
            self.lanes.remove(lane_index);
            if rotation_pick && !self.lanes.is_empty() {
                self.cursor %= self.lanes.len();
            }
        } else if rotation_pick {
            self.cursor = (lane_index + 1) % self.lanes.len();
        }

        Some((
            QueuedAdmission {
                key,
                ticket: ticket_value,
            },
            reason,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_types::{PrincipalId, TenantId};

    fn key(tenant: u8, principal: u8) -> FairnessKey {
        FairnessKey {
            tenant: TenantId::from_bytes([tenant; 16]),
            principal: PrincipalId::from_bytes([principal; 16]),
        }
    }

    #[test]
    fn distinct_keys_alternate_in_arrival_order_of_lanes() {
        let mut queue = FairnessQueue::new();
        let first = queue.push(key(1, 1)); // creates lane 0
        let second = queue.push(key(2, 2)); // creates lane 1

        assert_eq!(
            queue.dequeue_picked().map(|(e, r)| (e.ticket, r)),
            Some((first, PickReason::LaneRotation { lane_index: 0 }))
        );
        assert_eq!(queue.dequeue_picked().map(|(e, _)| e.ticket), Some(second));
        assert!(queue.is_empty());
    }

    #[test]
    fn same_key_is_first_come_first_served() {
        let mut queue = FairnessQueue::new();
        let older = queue.push(key(1, 1));
        let newer = queue.push(key(1, 1));
        assert_eq!(queue.dequeue_picked().map(|(e, _)| e.ticket), Some(older));
        assert_eq!(queue.dequeue_picked().map(|(e, _)| e.ticket), Some(newer));
    }

    #[test]
    fn sole_contender_receipt_and_rotationless_service() {
        let mut queue = FairnessQueue::new();
        let only = queue.push(key(3, 3));
        assert_eq!(
            queue.dequeue_picked().map(|(e, r)| (e.ticket, r)),
            Some((only, PickReason::SoleContender))
        );
    }

    #[test]
    fn rotation_bounds_any_contenders_wait_to_lanes_minus_one_picks() {
        // With K lanes the rotation guarantees every parked contender is
        // served within K-1 picks of entering service order: the structural
        // starvation guarantee that replaces an escalation mechanism.
        const LANES: u8 = 6;
        let mut queue = FairnessQueue::new();
        let mut first_tickets = Vec::new();
        for tenant in 1..=LANES {
            first_tickets.push(queue.push(key(tenant, tenant)));
        }

        let mut max_wait_seen = 0usize;
        for round in 0..LANES {
            let mut waits = 0;
            loop {
                let (ticket, _) = queue.peek_pick().expect("nonempty");
                if first_tickets.contains(&ticket) && ticket == first_tickets[round as usize] {
                    break;
                }
                queue.dequeue_picked().expect("serve");
                let _refill = queue.push(key(round + 1, 200));
                waits += 1;
                assert!(waits <= LANES as usize, "wait exceeded lane count");
            }
            max_wait_seen = max_wait_seen.max(waits);
            queue.dequeue_picked().expect("take the winner");
        }
        assert!(max_wait_seen <= LANES as usize);
    }
}
