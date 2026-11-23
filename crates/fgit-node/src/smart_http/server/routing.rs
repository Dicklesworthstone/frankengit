//! Fixed HTTP deployment routes, independent of canonical repository authority.
//!
//! A path selects exactly one already authenticated repository incarnation and
//! its live credential source. All adapters reuse that same profile; no URL
//! component is turned into a filesystem path, principal, or publication grant.

use std::collections::{BTreeMap, BTreeSet};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use fgit_types::{RepositoryId, RepositoryIncarnationId, TenantId};
use fgit_wire::smart_http::HttpLimits;

use super::{
    Controllers, NodeSmartHttpRefusal, Profile, RepositoryHttpService, RepositoryHttpServices,
    invalid_configuration, lifetime,
};
use crate::node_lanes::NodeLanes;
use crate::{
    GitDaemonRepositoryPath, GitDaemonServerLimits, GitDaemonServerReceipt, NodeRefusal, OneNode,
};

/// A finite catalog shares the listener's separate global concurrency bound.
pub const MAX_HTTP_REPOSITORY_ROUTES: usize = 64;

/// Independent deployment ceilings, never credential grants. Git reads still
/// require a read-scoped credential even when every optional service is off.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HttpRepositoryServices {
    pub receive: bool,
    pub issues: bool,
    pub outcomes: bool,
    pub pulls: bool,
    pub source: bool,
}

impl From<HttpRepositoryServices> for RepositoryHttpServices {
    fn from(services: HttpRepositoryServices) -> Self {
        Self::NONE
            .with(RepositoryHttpService::Receive, services.receive)
            .with(RepositoryHttpService::Issues, services.issues)
            .with(RepositoryHttpService::Outcomes, services.outcomes)
            .with(RepositoryHttpService::Pulls, services.pulls)
            .with(RepositoryHttpService::Source, services.source)
    }
}

/// One exact route with its captured canonical identity and deployment bounds.
///
/// Credential files remain live and are reloaded by ordinary request
/// authentication. Changing catalog membership or an incarnation requires a
/// new catalog. Cloning a route does not grant additional repository authority.
#[derive(Clone)]
pub struct HttpRepositoryRoute {
    path: String,
    root: PathBuf,
    identity: (TenantId, RepositoryId, RepositoryIncarnationId),
    profile: Profile,
}

impl std::fmt::Debug for HttpRepositoryRoute {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("HttpRepositoryRoute")
            .field("path", &self.path)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl HttpRepositoryRoute {
    /// Require `/tenant/repository` with two literal ASCII slug components.
    /// Case and an optional `.git` suffix are significant; percent decoding,
    /// path normalization, nested routes and alias fallback are not performed.
    pub fn validate_path(path: &str) -> Result<(), NodeSmartHttpRefusal> {
        if path.len() > 512 {
            return Err(invalid_configuration(
                "HTTP repository route exceeds 512 bytes",
            ));
        }
        let Some(path) = path.strip_prefix('/') else {
            return Err(invalid_configuration(
                "HTTP repository route must start with /",
            ));
        };
        let mut components = path.split('/');
        for _ in 0..2 {
            let component = components.next().ok_or_else(|| {
                invalid_configuration("HTTP repository route requires /tenant/repository")
            })?;
            if component.is_empty()
                || component == "."
                || component == ".."
                || component.starts_with('-')
                || !component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            {
                return Err(invalid_configuration(
                    "invalid HTTP repository route component",
                ));
            }
        }
        if components.next().is_some() {
            return Err(invalid_configuration(
                "HTTP repository route requires /tenant/repository",
            ));
        }
        Ok(())
    }

    /// Capture a serving node, the exact incarnation and a validated live
    /// credential table. No node is initialized and no repository state changes.
    pub fn try_new(
        path: String,
        node: &OneNode,
        credentials_file: &Path,
        services: HttpRepositoryServices,
    ) -> Result<Self, NodeSmartHttpRefusal> {
        Self::validate_path(&path)?;
        if node.cell_state() != fgit_types::cell::CellState::Serving {
            return Err(invalid_configuration(
                "HTTP route requires a serving repository",
            ));
        }
        let root = node
            .service_config
            .storage_root
            .canonicalize()
            .map_err(|error| super::io_error("resolve HTTP repository root", error))?;
        let mut profile = node.smart_http_profile(
            node.smart_http_credentials_source(credentials_file),
            services.into(),
            0,
        )?;
        profile.config.storage_root = root.clone();
        profile.config.git_daemon_repository_path = GitDaemonRepositoryPath::parse(path.as_bytes())
            .map_err(|_| invalid_configuration("invalid HTTP repository route"))?;
        profile.route = path.as_bytes().to_vec();
        // Capturing a route never retains a node. The listener replaces this
        // empty pool with its share of the global idle retention allowance.
        profile.nodes = Arc::new(NodeLanes::new(
            profile.config.clone(),
            0,
            "routed Smart HTTP",
        ));
        Ok(Self {
            path,
            root,
            identity: (
                node.tenant_id,
                node.repository_id,
                node.repository_incarnation_id(),
            ),
            profile,
        })
    }

    /// Validate the entire startup snapshot before announcing readiness.
    /// Repositories may share an ID across tenants, but not a canonical storage
    /// tree or full identity. One listener has one ingress timeout and origin
    /// policy; neither may be selected by unauthenticated request bytes.
    pub fn validate_catalog(routes: &[Self]) -> Result<(), NodeSmartHttpRefusal> {
        let Some(first) = routes.first() else {
            return Err(invalid_configuration(
                "HTTP catalog requires 1..64 repositories",
            ));
        };
        if routes.len() > MAX_HTTP_REPOSITORY_ROUTES {
            return Err(invalid_configuration(
                "HTTP catalog requires 1..64 repositories",
            ));
        }
        let mut paths = BTreeSet::new();
        let mut identities = BTreeSet::new();
        let mut roots: Vec<&Path> = Vec::new();
        for route in routes {
            Self::validate_path(&route.path)?;
            if !paths.insert(&route.path) {
                return Err(invalid_configuration("duplicate HTTP repository route"));
            }
            if !identities.insert(route.identity) {
                return Err(invalid_configuration("duplicate HTTP repository identity"));
            }
            if roots
                .iter()
                .any(|root| route.root.starts_with(root) || root.starts_with(&route.root))
            {
                return Err(invalid_configuration("overlapping HTTP repository roots"));
            }
            roots.push(&route.root);
            if route.profile.timeout.duration() != first.profile.timeout.duration()
                || route.profile.config.http_trusted_origin()
                    != first.profile.config.http_trusted_origin()
            {
                return Err(invalid_configuration(
                    "HTTP routes must share a session timeout and trusted origin",
                ));
            }
            route
                .profile
                .credentials
                .validate()
                .map_err(super::credential_error)?;
        }
        Ok(())
    }
}

/// Single-repository callers retain their existing route and response contract.
/// Catalog callers select one exact profile from the bounded request target.
pub(super) enum Profiles {
    Single(Profile),
    Routed {
        routes: BTreeMap<String, Profile>,
        ingress: HttpLimits,
    },
}

impl Profiles {
    pub(super) const fn single(profile: Profile) -> Self {
        Self::Single(profile)
    }

    fn routed(
        routes: Vec<HttpRepositoryRoute>,
        max_in_flight: usize,
    ) -> Result<Self, NodeSmartHttpRefusal> {
        HttpRepositoryRoute::validate_catalog(&routes)?;
        let idle_capacity = max_in_flight / routes.len();
        let mut ingress = routes[0].profile.http;
        let mut selected = BTreeMap::new();
        for route in routes {
            let mut profile = route.profile;
            ingress.max_body_bytes = ingress.max_body_bytes.max(profile.http.max_body_bytes);
            ingress.max_body_wire_bytes = ingress
                .max_body_wire_bytes
                .max(profile.http.max_body_wire_bytes);
            profile.nodes = Arc::new(NodeLanes::new(
                profile.config.clone(),
                idle_capacity,
                "routed Smart HTTP",
            ));
            selected.insert(route.path, profile);
        }
        Ok(Self::Routed {
            routes: selected,
            ingress,
        })
    }

    pub(super) fn first(&self) -> &Profile {
        match self {
            Self::Single(profile) => profile,
            // Construction above rejects an empty catalog before publication.
            Self::Routed { routes, .. } => {
                routes.first_key_value().expect("validated HTTP catalog").1
            }
        }
    }

    pub(super) fn http_limits(&self) -> HttpLimits {
        match self {
            Self::Single(profile) => profile.http,
            Self::Routed { ingress, .. } => *ingress,
        }
    }

    pub(super) fn select(&self, target: &str) -> Option<&Profile> {
        match self {
            Self::Single(profile) => Some(profile),
            Self::Routed { routes, .. } => routes.get(repository_path(target)?),
        }
    }

    pub(super) fn close(&self) -> Result<(), NodeRefusal> {
        match self {
            Self::Single(profile) => profile.nodes.close(),
            Self::Routed { routes, .. } => {
                let mut first = None;
                for profile in routes.values() {
                    if let Err(error) = profile.nodes.close() {
                        if first.is_none() {
                            first = Some(error);
                        } else {
                            super::log_cleanup(&error);
                        }
                    }
                }
                first.map_or(Ok(()), Err)
            }
        }
    }
}

fn repository_path(target: &str) -> Option<&str> {
    let path = target.split('?').next()?;
    let unprefixed = path.strip_prefix('/')?;
    let tenant_end = unprefixed.find('/')? + 1;
    let repository_end = path[tenant_end + 1..]
        .find('/')
        .map_or(path.len(), |offset| tenant_end + 1 + offset);
    let route = &path[..repository_end];
    HttpRepositoryRoute::validate_path(route).ok()?;
    Some(route)
}

impl OneNode {
    /// Serve an explicit immutable catalog on one bounded loopback listener.
    /// Every route retains independent credentials, quotas, writer gates and
    /// cache domains. The global connection limit and common ingress deadline
    /// apply before route selection. All accepted work and pools drain on exit.
    pub fn serve_http_repositories_bounded(
        &self,
        listener: &TcpListener,
        limits: GitDaemonServerLimits,
        routes: Vec<HttpRepositoryRoute>,
        idle_timeout: Duration,
    ) -> Result<GitDaemonServerReceipt, NodeSmartHttpRefusal> {
        self.serve_smart_http_profiles_lifetime(
            listener,
            limits.max_in_flight(),
            Profiles::routed(routes, limits.max_in_flight())?,
            lifetime::Acceptance::Bounded {
                max_sessions: limits.max_sessions(),
                idle_timeout,
            },
            Controllers::default(),
        )
    }

    /// Serve the same catalog until a bounded owner callback requests stop.
    /// Stop retires acceptance; accepted writes still settle and may commit.
    /// No quota or credential state resets between requests or idle windows.
    pub fn serve_http_repositories_until_stopped(
        &self,
        listener: &TcpListener,
        max_in_flight: usize,
        routes: Vec<HttpRepositoryRoute>,
        should_stop: &dyn Fn() -> std::io::Result<bool>,
    ) -> Result<GitDaemonServerReceipt, NodeSmartHttpRefusal> {
        self.serve_smart_http_profiles_lifetime(
            listener,
            max_in_flight,
            Profiles::routed(routes, max_in_flight)?,
            lifetime::Acceptance::UntilStopped(should_stop),
            Controllers::default(),
        )
    }
}

#[cfg(test)]
mod tests;
