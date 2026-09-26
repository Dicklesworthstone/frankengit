//! Opened repository nodes that one serving process reuses across connections.
//!
//! The integration profile (section 3.3) pools an `AsyncConnection` "per
//! declared service/lane, not opened without bound per request". Every smart
//! HTTP connection used to open its own node instead -- a new Asupersync
//! runtime, a FrankenSQLite connection with its schema check, two head
//! authentications and a configuration read -- and shut all of it down again
//! when the response ended (frankengit-root-doctrine-x2mv.4.8).
//!
//! A leased node belongs to exactly one connection until it is restored, so
//! one caller still owns the database connection for a whole authority
//! operation. The store carries an unfinalized transaction across operations
//! and recovers it before admitting the next one; the pool additionally takes
//! a node back only after a complete response, while it is still `Serving`,
//! and after its merge workspaces have drained. Everything else is shut down
//! exactly as a per-connection node was.

use std::sync::{Mutex, PoisonError};

use crate::{
    CellState, NodeConfig, NodeRefusal, OneNode, PushQuota,
    read_repository_incarnation_configuration_async,
};

/// At most `capacity` idle, in-service nodes for one repository.
pub(crate) struct NodeLanes {
    config: NodeConfig,
    idle: Mutex<Vec<OneNode>>,
    capacity: usize,
    #[cfg(test)]
    opened: std::sync::atomic::AtomicUsize,
}

impl NodeLanes {
    pub(crate) fn new(config: NodeConfig, capacity: usize) -> Self {
        Self {
            config,
            idle: Mutex::new(Vec::new()),
            capacity,
            #[cfg(test)]
            opened: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// A node in service for one connection.
    ///
    /// An idle node is reused only after its authority head authenticates
    /// again and the stored configuration still names the object format and
    /// incarnation it was opened for. One that fails is shut down, and a new
    /// node is opened with every `open_existing` check. Either way the node
    /// starts with a fresh node-local push quota, as a per-connection node
    /// did; the service-wide quotas are the ones that span connections.
    ///
    /// `None` when no node could be put into service; the cause is written to
    /// stderr for the operator, and the connection answers "unavailable".
    pub(crate) fn lease(&self) -> Option<OneNode> {
        while let Some(mut node) = self.take_idle() {
            match revalidate(&node) {
                Ok(()) => {
                    node.push_quota = PushQuota::default();
                    return Some(node);
                }
                Err(error) => {
                    eprintln!("Smart HTTP retired a pooled repository node: {error}");
                    close(node);
                }
            }
        }
        self.open()
    }

    /// Takes back a node whose connection completed its response.
    ///
    /// # Errors
    ///
    /// The shutdown refusal of a node that could not be pooled: it was no
    /// longer `Serving`, its workspaces did not drain, or the pool was full.
    pub(crate) fn restore(&self, node: OneNode) -> Result<(), NodeRefusal> {
        if node.cell_state() != CellState::Serving {
            return node.shutdown();
        }
        let drained = node
            .runtime()
            .block_on(node.drain_merge_workspaces_in(&node.request_context()));
        if drained.is_err() {
            return node.shutdown();
        }
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        if idle.len() >= self.capacity {
            drop(idle);
            return node.shutdown();
        }
        idle.push(node);
        Ok(())
    }

    /// Shuts down every idle node, so the service reports drained only after
    /// each database worker and runtime it kept has closed.
    ///
    /// # Errors
    ///
    /// The first shutdown refusal, after every node has been tried; later
    /// ones are written to stderr.
    pub(crate) fn close(&self) -> Result<(), NodeRefusal> {
        let nodes = std::mem::take(&mut *self.idle.lock().unwrap_or_else(PoisonError::into_inner));
        let mut first = None;
        for node in nodes {
            if let Err(error) = node.shutdown() {
                if first.is_some() {
                    eprintln!("Smart HTTP could not close a pooled repository node: {error}");
                } else {
                    first = Some(error);
                }
            }
        }
        first.map_or(Ok(()), Err)
    }

    fn take_idle(&self) -> Option<OneNode> {
        self.idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop()
    }

    fn open(&self) -> Option<OneNode> {
        let mut node = OneNode::open_existing(self.config.clone())
            .inspect_err(|error| {
                eprintln!("Smart HTTP could not open the repository node: {error}");
            })
            .ok()?;
        #[cfg(test)]
        self.opened
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let generation = match node.runtime().block_on(node.authenticate_authority_head()) {
            Ok(authenticated) => authenticated.receipt().generation(),
            Err(error) => {
                eprintln!("Smart HTTP could not authenticate the authority head: {error}");
                close(node);
                return None;
            }
        };
        if let Err(error) = node.bring_into_service(generation) {
            eprintln!("Smart HTTP could not bring the node into service: {error}");
            close(node);
            return None;
        }
        Some(node)
    }
}

/// Re-authenticates an idle node's repository before it serves again.
fn revalidate(node: &OneNode) -> Result<(), NodeRefusal> {
    let configuration_cx = node.authority_context();
    node.runtime().block_on(async {
        let authenticated = node.authenticate_authority_head().await?;
        let head = authenticated
            .body()
            .map_err(fgit_authority::OutcomeFailure::from)?;
        let configuration = read_repository_incarnation_configuration_async(
            &node.authority,
            &configuration_cx,
            &head.configuration_root,
        )
        .await?;
        if configuration.object_format != node.object_format {
            return Err(NodeRefusal::ObjectFormatMismatch {
                stored: configuration.object_format,
                supplied: node.object_format,
            });
        }
        if configuration.repository_incarnation_id != node.repository_incarnation_id {
            return Err(NodeRefusal::RepositoryIncarnationMismatch {
                expected: node.repository_incarnation_id,
                observed: configuration.repository_incarnation_id,
            });
        }
        Ok(())
    })
}

fn close(node: OneNode) {
    if let Err(cleanup) = node.shutdown() {
        eprintln!("Smart HTTP could not close the repository node: {cleanup}");
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use fgit_types::{
        CellTransitionCause, HeadGeneration, PrincipalId, RepositoryId, RepositoryIncarnationId,
        TenantId,
    };

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(1);
    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A persisted repository whose creating node is already closed.
    fn repository() -> (Scratch, NodeConfig) {
        let scratch = Scratch(std::env::temp_dir().join(format!(
            "fg-node-lanes-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        let config = NodeConfig::new(
            scratch.0.clone(),
            TenantId::from_bytes([0x71; 16]),
            RepositoryId::from_bytes([0x72; 16]),
        );
        let (node, _) = OneNode::init(config.clone()).unwrap();
        node.shutdown().unwrap();
        (scratch, config)
    }

    fn opened(lanes: &NodeLanes) -> usize {
        lanes.opened.load(Ordering::Relaxed)
    }

    fn idle(lanes: &NodeLanes) -> usize {
        lanes.idle.lock().unwrap().len()
    }

    #[test]
    fn sequential_connections_reuse_one_opened_node() {
        let (_scratch, config) = repository();
        let lanes = NodeLanes::new(config, 4);
        for _ in 0..8 {
            let node = lanes.lease().unwrap();
            assert_eq!(node.cell_state(), CellState::Serving);
            node.runtime()
                .block_on(node.authenticate_authority_head())
                .unwrap();
            lanes.restore(node).unwrap();
        }
        assert_eq!(opened(&lanes), 1);
        assert_eq!(idle(&lanes), 1);
        lanes.close().unwrap();
        assert_eq!(idle(&lanes), 0);
    }

    #[test]
    fn concurrent_connections_each_own_a_node_and_the_pool_keeps_its_capacity() {
        let (_scratch, config) = repository();
        let lanes = NodeLanes::new(config, 1);
        let first = lanes.lease().unwrap();
        let second = lanes.lease().unwrap();
        assert_eq!(opened(&lanes), 2);
        lanes.restore(first).unwrap();
        // The pool is full, so the second node closes instead of idling.
        lanes.restore(second).unwrap();
        assert_eq!(idle(&lanes), 1);
        let reused = lanes.lease().unwrap();
        assert_eq!(opened(&lanes), 2);
        lanes.restore(reused).unwrap();
        lanes.close().unwrap();
    }

    #[test]
    fn a_node_that_left_service_is_closed_not_pooled() {
        let (_scratch, config) = repository();
        let lanes = NodeLanes::new(config, 4);
        let mut draining = lanes.lease().unwrap();
        draining
            .transition_cell_state(
                CellState::Draining,
                CellTransitionCause::Operator,
                HeadGeneration::FIRST,
            )
            .unwrap();
        lanes.restore(draining).unwrap();
        assert_eq!(idle(&lanes), 0);
        // Twin: the same lease left in service is pooled and reused.
        let serving = lanes.lease().unwrap();
        lanes.restore(serving).unwrap();
        assert_eq!(idle(&lanes), 1);
        let _ = lanes.lease().unwrap();
        assert_eq!(opened(&lanes), 2);
    }

    #[test]
    fn a_pooled_node_whose_repository_changed_is_retired_before_it_serves() {
        let (_scratch, config) = repository();
        let lanes = NodeLanes::new(config, 4);
        let mut stale = lanes.lease().unwrap();
        let current = stale.repository_incarnation_id;
        // As if the repository were re-created while this node sat idle.
        stale.repository_incarnation_id = RepositoryIncarnationId::from_bytes([0x7f; 16]);
        lanes.restore(stale).unwrap();
        assert_eq!(idle(&lanes), 1);
        let fresh = lanes.lease().unwrap();
        assert_eq!(opened(&lanes), 2, "the stale node must not serve");
        assert_eq!(fresh.repository_incarnation_id, current);
        assert_eq!(idle(&lanes), 0);
        lanes.restore(fresh).unwrap();
        // Twin: an unchanged pooled node is reused without another open.
        let _ = lanes.lease().unwrap();
        assert_eq!(opened(&lanes), 2);
    }

    #[test]
    fn every_lease_starts_with_a_fresh_node_local_push_quota() {
        let (_scratch, config) = repository();
        let lanes = NodeLanes::new(config, 4);
        let principal = PrincipalId::from_bytes([0x73; 16]);
        let mut node = lanes.lease().unwrap();
        node.push_quota = PushQuota {
            limit: fgit_resource::quota::abuse::RateLimit {
                max_events: 1,
                window: Duration::from_secs(60),
            },
            windows: Mutex::new(BTreeMap::new()),
        };
        assert!(node.push_quota.evaluate(&principal).is_ok());
        assert!(node.push_quota.evaluate(&principal).is_err());
        lanes.restore(node).unwrap();
        let reused = lanes.lease().unwrap();
        assert_eq!(opened(&lanes), 1);
        assert!(reused.push_quota.evaluate(&principal).is_ok());
    }
}
