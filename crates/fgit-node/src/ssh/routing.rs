//! Immutable SSH route selection. A route chooses a canonically authenticated
//! repository configuration; it never substitutes a path or hash for authority.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

use fgit_identity::deploy_key::DeployKeyRefusal;
use fgit_ssh::{AuthRefusal, SshCommandAuthorizer, SshCommandGrant, SshGitCommand, SshGitService};
use fgit_types::{PrincipalId, RepositoryId, RepositoryIncarnationId, TenantId};

use super::NodeSshRefusal;
use crate::node_lanes::NodeLanes;
use crate::{NodeConfig, NodeRefusal, OneNode, PushQuota, WriterGate};

/// One listener's finite routing catalog. Active sessions remain subject to the
/// listener's separate global concurrency ceiling.
pub const MAX_SSH_REPOSITORY_ROUTES: usize = 64;

/// One exact SSH path bound to a currently serving repository incarnation.
///
/// The route is immutable for the listener's lifetime. Its authorization source
/// can reload grants at each exec. Dispatch reuses the same route entry that
/// authorized the parsed command; pooled nodes reauthenticate canonical state
/// and the captured incarnation before any Git service begins.
#[derive(Clone)]
pub struct SshRepositoryRoute {
    path: String,
    configuration: NodeConfig,
    identity: (TenantId, RepositoryId, RepositoryIncarnationId),
    root: PathBuf,
    authorizer: Arc<dyn SshCommandAuthorizer>,
    allow_receive: bool,
}

impl std::fmt::Debug for SshRepositoryRoute {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SshRepositoryRoute")
            .field("path", &self.path)
            .field("identity", &self.identity)
            .field("allow_receive", &self.allow_receive)
            .finish_non_exhaustive()
    }
}

impl SshRepositoryRoute {
    /// Validate the exact catalog spelling before opening repository state.
    ///
    /// This bounded profile accepts two ASCII slug components, separated by
    /// one slash. A `.git` suffix is optional and literal, as are letter case
    /// and every other admitted byte. The SSH command parser may remove one
    /// leading slash from a client command; catalog entries have none.
    pub fn validate_path(path: &str) -> Result<(), NodeSshRefusal> {
        if path.is_empty() || path.len() > 512 {
            return Err(NodeSshRefusal::InvalidRoutes("route path length"));
        }
        let mut components = path.split('/');
        for _ in 0..2 {
            let component = components.next().ok_or(NodeSshRefusal::InvalidRoutes(
                "expected tenant/repository route",
            ))?;
            if component.is_empty()
                || component == "."
                || component == ".."
                || component.starts_with('-')
                || !component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            {
                return Err(NodeSshRefusal::InvalidRoutes("invalid route component"));
            }
        }
        if components.next().is_some() {
            return Err(NodeSshRefusal::InvalidRoutes(
                "expected tenant/repository route",
            ));
        }
        Ok(())
    }

    /// Capture a canonical repository identity and its deployment configuration.
    /// The authorization source receives the actual repository ID, not a path
    /// alias, through `authorize_command_grant` at each routed command.
    pub fn try_new(
        path: String,
        node: &OneNode,
        authorizer: Arc<dyn SshCommandAuthorizer>,
        allow_receive: bool,
    ) -> Result<Self, NodeSshRefusal> {
        Self::validate_path(&path)?;
        if node.cell_state() != fgit_types::cell::CellState::Serving {
            return Err(NodeSshRefusal::NotServing);
        }
        let root = node
            .service_config
            .storage_root
            .canonicalize()
            .map_err(|_| NodeSshRefusal::InvalidRoutes("repository root unavailable"))?;
        let incarnation = node.repository_incarnation_id();
        let mut configuration = node
            .service_config
            .clone()
            .with_expected_repository_incarnation(incarnation);
        // Opening a route never follows a subsequently changed relative path
        // or a replaced symlink that named the original repository root.
        configuration.storage_root = root.clone();
        Ok(Self {
            path,
            configuration,
            identity: (node.tenant_id, node.repository_id, incarnation),
            root,
            authorizer,
            allow_receive,
        })
    }
}

pub(super) struct Service {
    pub(super) nodes: NodeLanes,
    pub(super) writers: WriterGate,
    pub(super) quota: PushQuota,
    pub(super) allow_receive: bool,
    repository: RepositoryId,
    authorizer: Arc<dyn SshCommandAuthorizer>,
}

impl Service {
    fn new(
        configuration: NodeConfig,
        capacity: usize,
        authorizer: Arc<dyn SshCommandAuthorizer>,
        allow_receive: bool,
    ) -> Self {
        let repository = configuration.repository_id;
        Self {
            nodes: NodeLanes::new(configuration, capacity, "SSH"),
            writers: WriterGate::new(crate::MAX_CONCURRENT_WRITERS),
            quota: PushQuota::default(),
            allow_receive,
            repository,
            authorizer,
        }
    }
}

/// The single-repository variant preserves its historical alias semantics.
/// Routed service selection is exact and uses this same immutable map both at
/// the authorization boundary and immediately before leasing a node.
pub(super) enum Services {
    Single(Service),
    Routed(BTreeMap<String, Service>),
}

impl Services {
    pub(super) fn single(
        node: &OneNode,
        max_in_flight: usize,
        authorizer: Arc<dyn SshCommandAuthorizer>,
        allow_receive: bool,
    ) -> Self {
        Self::Single(Service::new(
            node.service_config
                .clone()
                .with_expected_repository_incarnation(node.repository_incarnation_id()),
            max_in_flight,
            authorizer,
            allow_receive,
        ))
    }

    pub(super) fn routed(
        routes: Vec<SshRepositoryRoute>,
        max_in_flight: usize,
    ) -> Result<Self, NodeSshRefusal> {
        if routes.is_empty() || routes.len() > MAX_SSH_REPOSITORY_ROUTES {
            return Err(NodeSshRefusal::InvalidRoutes(
                "expected 1..64 repository routes",
            ));
        }
        let mut paths = BTreeSet::new();
        let mut identities = BTreeSet::new();
        let mut roots: Vec<&PathBuf> = Vec::new();
        for route in &routes {
            SshRepositoryRoute::validate_path(&route.path)?;
            if !paths.insert(&route.path) {
                return Err(NodeSshRefusal::InvalidRoutes("duplicate route path"));
            }
            if !identities.insert(route.identity) {
                return Err(NodeSshRefusal::InvalidRoutes(
                    "duplicate repository identity",
                ));
            }
            if roots
                .iter()
                .any(|root| route.root.starts_with(root) || root.starts_with(&route.root))
            {
                return Err(NodeSshRefusal::InvalidRoutes(
                    "overlapping repository roots",
                ));
            }
            roots.push(&route.root);
        }
        // The whole listener keeps at most max_in_flight idle child nodes,
        // including when many repositories are visited sequentially. More
        // routes than slots means no idle retention, not an unbounded pool.
        let idle_capacity = max_in_flight / routes.len();
        Ok(Self::Routed(
            routes
                .into_iter()
                .map(|route| {
                    (
                        route.path,
                        Service::new(
                            route.configuration,
                            idle_capacity,
                            route.authorizer,
                            route.allow_receive,
                        ),
                    )
                })
                .collect(),
        ))
    }

    pub(super) fn selected(&self, command: &SshGitCommand) -> Option<&Service> {
        match self {
            Self::Single(service) => Some(service),
            Self::Routed(routes) => routes.get(command.repository_path()),
        }
    }

    pub(super) fn close(&self) -> Result<(), NodeRefusal> {
        match self {
            Self::Single(service) => service.nodes.close(),
            Self::Routed(routes) => {
                let mut first = None;
                for service in routes.values() {
                    if let Err(error) = service.nodes.close() {
                        if first.is_none() {
                            first = Some(error);
                        } else {
                            eprintln!("SSH route lane cleanup failed: {error}");
                        }
                    }
                }
                first.map_or(Ok(()), Err)
            }
        }
    }
}

fn denied() -> AuthRefusal {
    AuthRefusal::DeployKey(DeployKeyRefusal::NoBindingForKey)
}

impl SshCommandAuthorizer for Services {
    fn authorize_command(
        &self,
        key: &[u8; 32],
        repository: RepositoryId,
        service: SshGitService,
    ) -> Result<PrincipalId, AuthRefusal> {
        self.authorize_command_grant(key, repository, service)?
            .principal_without_scope(service)
    }

    fn authorize_command_grant(
        &self,
        key: &[u8; 32],
        repository: RepositoryId,
        service: SshGitService,
    ) -> Result<SshCommandGrant, AuthRefusal> {
        match self {
            Self::Single(selected) => selected
                .authorizer
                .authorize_command_grant(key, repository, service),
            Self::Routed(_) => Err(denied()),
        }
    }

    fn authorize_repository_command(
        &self,
        key: &[u8; 32],
        command: &SshGitCommand,
    ) -> Result<SshCommandGrant, AuthRefusal> {
        match self {
            Self::Single(selected) => selected
                .authorizer
                .authorize_repository_command(key, command),
            Self::Routed(routes) => {
                let selected = routes.get(command.repository_path()).ok_or_else(denied)?;
                if command.service() == SshGitService::ReceivePack && !selected.allow_receive {
                    return Err(denied());
                }
                selected
                    .authorizer
                    .authorize_command_grant(key, selected.repository, command.service())
                    // Neither route existence nor a source's detailed policy
                    // verdict is disclosed to a caller without a route grant.
                    .map_err(|_| denied())
            }
        }
    }
}

#[cfg(test)]
mod tests;
