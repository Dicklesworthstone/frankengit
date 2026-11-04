//! The HTTP listener uses the same owned maintenance group as stdio services.
use super::{RepositoryHttpService, RepositoryHttpServices};
use std::io;
use std::net::TcpListener;
use std::path::Path;
use std::time::Duration;

use super::{Controllers, NodeSmartHttpRefusal, io_error, lifetime::Acceptance};
use crate::index_maintenance::{MaintenanceGroup, MaintenanceReceipt};
use crate::{GitDaemonServerLimits, GitDaemonServerReceipt, OneNode, SourceIndexService};

pub(super) use crate::source_index_service::startup_stop;

pub(super) struct Worker(SourceIndexService);
impl Worker {
    pub(super) fn start(
        node: &OneNode,
        group: MaintenanceGroup,
        should_stop: Option<&dyn Fn() -> io::Result<bool>>,
    ) -> Result<Option<Self>, NodeSmartHttpRefusal> {
        SourceIndexService::start(node, group, should_stop)
            .map(|worker| worker.map(Self))
            .map_err(|error| io_error("start HTTP source index maintenance", error))
    }
    pub(super) fn finished(&self) -> bool {
        self.0.finished()
    }
    pub(super) fn request_stop(&mut self) {
        self.0.request_stop();
    }
    pub(super) fn activate(&mut self) -> Result<(), NodeSmartHttpRefusal> {
        self.0
            .activate()
            .map_err(|error| io_error("activate HTTP source index maintenance", error))
    }
    pub(super) fn finish(self) -> Result<Vec<MaintenanceReceipt>, NodeSmartHttpRefusal> {
        self.0
            .finish()
            .map_err(|error| io_error("drain HTTP source index maintenance", error))
    }
}

impl OneNode {
    /// Serve source queries while runtime-owned controllers maintain the
    /// explicitly configured references. Existing indexes remain derived state.
    ///
    /// The readiness callback runs on the accepting thread only after exclusive
    /// progress ownership and repository authentication succeed. It must not
    /// block or panic. A controller failure retires acceptance and drains every
    /// child; ordinary bounded reconcile refusals stay in the retry loop.
    /// This enables source reads under the existing credential grant. It never
    /// grants remote index maintenance or changes repository authority.
    pub fn serve_repository_http_with_index_maintenance_bounded(
        &self,
        listener: &TcpListener,
        limits: GitDaemonServerLimits,
        credentials_file: &Path,
        allow_receive: bool,
        allow_issues: bool,
        allow_outcomes: bool,
        allow_pulls: bool,
        idle_timeout: Duration,
        maintenance: impl Into<MaintenanceGroup>,
        on_ready: &dyn Fn() -> io::Result<()>,
    ) -> Result<GitDaemonServerReceipt, NodeSmartHttpRefusal> {
        self.serve_smart_http_with_source_lifetime(
            listener,
            limits.max_in_flight(),
            self.smart_http_credentials_source(credentials_file),
            RepositoryHttpServices::NONE
                .with(RepositoryHttpService::Receive, allow_receive)
                .with(RepositoryHttpService::Issues, allow_issues)
                .with(RepositoryHttpService::Outcomes, allow_outcomes)
                .with(RepositoryHttpService::Pulls, allow_pulls)
                .with(RepositoryHttpService::Source, true),
            Acceptance::Bounded {
                max_sessions: limits.max_sessions(),
                idle_timeout,
            },
            Controllers {
                maintenance: Some(maintenance.into()),
                on_ready: Some(on_ready),
                ..Controllers::default()
            },
        )
    }

    /// Continuously serve with one or two progress owners and the same
    /// HTTP quotas for the whole lifetime. Stop requests cancel and drain the
    /// active maintenance attempt and join it alongside accepted requests
    /// before this method returns.
    pub fn serve_repository_http_with_index_maintenance_until_stopped(
        &self,
        listener: &TcpListener,
        max_in_flight: usize,
        credentials_file: &Path,
        allow_receive: bool,
        allow_issues: bool,
        allow_outcomes: bool,
        allow_pulls: bool,
        maintenance: impl Into<MaintenanceGroup>,
        should_stop: &dyn Fn() -> io::Result<bool>,
        on_ready: &dyn Fn() -> io::Result<()>,
    ) -> Result<GitDaemonServerReceipt, NodeSmartHttpRefusal> {
        self.serve_smart_http_with_source_lifetime(
            listener,
            max_in_flight,
            self.smart_http_credentials_source(credentials_file),
            RepositoryHttpServices::NONE
                .with(RepositoryHttpService::Receive, allow_receive)
                .with(RepositoryHttpService::Issues, allow_issues)
                .with(RepositoryHttpService::Outcomes, allow_outcomes)
                .with(RepositoryHttpService::Pulls, allow_pulls)
                .with(RepositoryHttpService::Source, true),
            Acceptance::UntilStopped(should_stop),
            Controllers {
                maintenance: Some(maintenance.into()),
                on_ready: Some(on_ready),
                ..Controllers::default()
            },
        )
    }
}
