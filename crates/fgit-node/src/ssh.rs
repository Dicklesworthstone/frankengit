//! SSH transport service integration for FrankenGit node assembly (FG-047/FG-047b).
//!
//! Provides pure-Rust bounded SSH service execution for Git operations:
//! - Shell-free command parsing and dispatch (`git-upload-pack`, `git-receive-pack`)
//! - RFC 8731 Curve25519 key exchange and OpenSSH ChaCha20-Poly1305 encryption
//! - Deploy-key authentication and repository-scoped authorization
//! - SANS-I/O session state machine mapped to Asupersync blocking threads

use std::cell::RefCell;
use std::fmt::{self, Display, Formatter};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use fgit_identity::deploy_key::DeployKeyBinding;
use fgit_ssh::SigningKey;
use fgit_ssh::command::SshGitService;
use fgit_ssh::session::{SessionPhase, SshServerSession, SshSessionError};
use fgit_types::PrincipalId;
use fgit_wire::{UploadPackRepository, WireLimits};

use crate::{
    GitDaemonRequest, GitDaemonServerReceipt, GitDaemonService, GitDaemonSessionOutcome,
    GitDaemonTransportRefusal, NodeGitDaemonServeRefusal, NodeRefusal, OneNode,
    ReceiveResponseWriter,
};

/// Bounded concurrency and session limits for the SSH server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SshServerLimits {
    pub max_sessions: usize,
    pub max_in_flight: usize,
}

impl SshServerLimits {
    pub const DEFAULT: Self = Self {
        max_sessions: 1000,
        max_in_flight: 16,
    };

    pub const fn try_new(
        max_sessions: usize,
        max_in_flight: usize,
    ) -> Result<Self, NodeSshRefusal> {
        if max_sessions == 0 {
            return Err(NodeSshRefusal::ZeroSessionLimit);
        }
        if max_in_flight == 0 {
            return Err(NodeSshRefusal::ZeroInFlightLimit);
        }
        if max_sessions > 1_000_000 || max_in_flight > 16 {
            return Err(NodeSshRefusal::LimitsExceeded);
        }
        Ok(Self {
            max_sessions,
            max_in_flight,
        })
    }
}

/// Outcome receipt after the SSH server has completed its bounded session budget.
pub type SshServerReceipt = GitDaemonServerReceipt;

/// Refusals occurring during SSH server execution.
#[derive(Debug)]
pub enum NodeSshRefusal {
    ZeroSessionLimit,
    ZeroInFlightLimit,
    LimitsExceeded,
    Accept(io::Error),
    Session(SshSessionError),
    Service(String),
    Node(NodeRefusal),
    Shutdown(NodeRefusal),
}

impl Display for NodeSshRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroSessionLimit => write!(formatter, "zero SSH session limit"),
            Self::ZeroInFlightLimit => write!(formatter, "zero SSH in-flight limit"),
            Self::LimitsExceeded => write!(
                formatter,
                "SSH limits exceeded (max 1000000 sessions, max 16 in-flight)"
            ),
            Self::Accept(err) => write!(formatter, "cannot accept SSH connection: {err}"),
            Self::Session(err) => write!(formatter, "SSH session protocol error: {err}"),
            Self::Service(err) => write!(formatter, "SSH service error: {err}"),
            Self::Node(err) => write!(formatter, "node error: {err}"),
            Self::Shutdown(err) => write!(formatter, "shutdown error: {err}"),
        }
    }
}

impl std::error::Error for NodeSshRefusal {}

impl From<NodeRefusal> for NodeSshRefusal {
    fn from(err: NodeRefusal) -> Self {
        Self::Node(err)
    }
}

/// Finishes a connection without discarding output the client has not
/// delivered yet.
///
/// After our CHANNEL_CLOSE the client still drains buffered channel output to
/// its local program (git fetch-pack) and then sends its own CLOSE and
/// disconnects. Closing or half-closing TCP before that makes OpenSSH report
/// "connection closed by remote host" and exit immediately, truncating a
/// completed clone; dropping a socket with unread input sends RST, which can
/// destroy output too. So keep processing the client's packets (window
/// adjustments, its CLOSE) until it disconnects, bounded in time and bytes.
fn close_gracefully(session: &mut SshServerSession, stream: &mut TcpStream) {
    let _ = stream.flush();
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let started = std::time::Instant::now();
    let mut drained = 0usize;
    let mut buf = [0u8; 16384];
    while started.elapsed() < Duration::from_secs(10) && drained < 4 * 1024 * 1024 {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                drained += n;
                if session.handle_incoming_bytes(&buf[..n]).is_err() {
                    break;
                }
                let out = session.take_outgoing_bytes();
                if !out.is_empty() && (stream.write_all(&out).is_err() || stream.flush().is_err()) {
                    break;
                }
            }
        }
    }
}

struct SshConnectionState {
    session: SshServerSession,
    stream: TcpStream,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl SshConnectionState {
    /// Whether the client's TCP connection is still open, without consuming
    /// or waiting for anything. A non-blocking peek sees an orderly close as a
    /// zero-length read and a reset as an error; pending bytes and "would
    /// block" both mean the peer is still there. OpenSSH signals EOF inside
    /// the channel, so a closed socket means the client itself is gone.
    fn peer_connected(&self) -> bool {
        crate::tcp_peer_connected(&self.stream)
    }

    fn flush_outgoing(&mut self) -> io::Result<()> {
        let out = self.session.take_outgoing_bytes();
        if !out.is_empty() {
            self.stream.write_all(&out)?;
            self.stream.flush()?;
        }
        Ok(())
    }

    /// Reads one burst from the client and feeds it to the session. A socket
    /// read timeout is idleness, not a transient condition: it ends the
    /// session instead of spinning.
    fn pump_incoming(&mut self) -> io::Result<usize> {
        // Anything queued (such as a receive-window adjustment) must reach the
        // client before we block waiting for it to send more.
        self.flush_outgoing()?;
        let mut wire_buf = [0u8; 16384];
        let n = match self.stream.read(&mut wire_buf) {
            Ok(n) => n,
            Err(source)
                if matches!(
                    source.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "ssh client idle beyond the session read timeout",
                ));
            }
            Err(source) => return Err(source),
        };
        if n > 0 {
            if let Err(err) = self.session.handle_incoming_bytes(&wire_buf[..n]) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, err.to_string()));
            }
            self.flush_outgoing()?;
        }
        Ok(n)
    }

    fn read_channel(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.read_pos < self.read_buf.len() {
            let available = &self.read_buf[self.read_pos..];
            let to_copy = available.len().min(buf.len());
            buf[..to_copy].copy_from_slice(&available[..to_copy]);
            self.read_pos += to_copy;
            return Ok(to_copy);
        }

        self.read_buf.clear();
        self.read_pos = 0;

        loop {
            // Data already decoded (for example while waiting for window
            // space in `write_channel`) is delivered before EOF is reported.
            let new_data = self.session.take_channel_input();
            if !new_data.is_empty() {
                self.read_buf = new_data;
                let to_copy = self.read_buf.len().min(buf.len());
                buf[..to_copy].copy_from_slice(&self.read_buf[..to_copy]);
                self.read_pos = to_copy;
                return Ok(to_copy);
            }
            if self.session.is_channel_eof_received() || self.session.is_channel_closed() {
                return Ok(0);
            }

            if self.pump_incoming()? == 0 {
                return Ok(0);
            }

            let new_data = self.session.take_channel_input();
            if !new_data.is_empty() {
                self.read_buf = new_data;
                let to_copy = self.read_buf.len().min(buf.len());
                buf[..to_copy].copy_from_slice(&self.read_buf[..to_copy]);
                self.read_pos = to_copy;
                return Ok(to_copy);
            }
        }
    }

    fn write_channel(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut written = 0;
        while written < buf.len() {
            let accepted = self.session.send_channel_data(&buf[written..]);
            written += accepted;
            self.flush_outgoing()?;
            if accepted == 0 {
                // The client's window is exhausted: only its
                // CHANNEL_WINDOW_ADJUST can reopen it. Channel input that
                // arrives meanwhile stays queued in the session for the reader.
                if self.session.is_channel_closed() {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "ssh channel closed while output was pending",
                    ));
                }
                if self.pump_incoming()? == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "ssh client disconnected while its channel window was exhausted",
                    ));
                }
            }
        }
        Ok(buf.len())
    }
}

struct SshReader<'a>(&'a RefCell<SshConnectionState>);

struct SshWriter<'a>(&'a RefCell<SshConnectionState>);

impl Read for SshReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.borrow_mut().read_channel(buf)
    }
}

impl Write for SshWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().write_channel(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.borrow_mut().flush_outgoing()
    }
}

impl ReceiveResponseWriter for SshWriter<'_> {
    fn restart_deadline(&mut self, _deadline: crate::GitDaemonSessionDeadline) {}
}

impl OneNode {
    /// Serves incoming Git operations over SSH on the provided listener until
    /// the session budget is exhausted.
    pub fn serve_ssh_bounded(
        &self,
        listener: &TcpListener,
        limits: SshServerLimits,
        server_signing_key: SigningKey,
        deploy_keys: Vec<DeployKeyBinding>,
        allow_receive: bool,
    ) -> Result<SshServerReceipt, NodeSshRefusal> {
        listener
            .set_nonblocking(true)
            .map_err(NodeSshRefusal::Accept)?;

        let active = Arc::new(AtomicUsize::new(0));
        let writers = Arc::new(crate::WriterGate::new(crate::MAX_CONCURRENT_WRITERS));
        // Sessions lease already-opened nodes (profile section 3.3) instead of
        // opening and closing one each.
        let nodes = Arc::new(crate::node_lanes::NodeLanes::new(
            self.service_config.clone(),
            limits.max_in_flight,
            "SSH",
        ));
        let completed = Arc::new(AtomicUsize::new(0));
        let refused = Arc::new(AtomicUsize::new(0));
        let mut child_tasks = Vec::with_capacity(limits.max_sessions);
        let mut accepted = 0_usize;
        let mut terminal_refusal = None;

        while accepted < limits.max_sessions {
            if active.load(Ordering::Acquire) >= limits.max_in_flight {
                self.runtime.wait_for(Duration::from_millis(1));
                continue;
            }

            let (stream, _) = match listener.accept() {
                Ok((stream, addr)) => {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(60)));
                    (stream, addr)
                }
                Err(source) if source.kind() == io::ErrorKind::WouldBlock => {
                    self.runtime.wait_for(Duration::from_millis(1));
                    continue;
                }
                Err(source) => {
                    terminal_refusal = Some(NodeSshRefusal::Accept(source));
                    break;
                }
            };

            accepted = accepted.saturating_add(1);
            active.fetch_add(1, Ordering::AcqRel);
            let child_nodes = Arc::clone(&nodes);
            let child_active = Arc::clone(&active);
            let child_completed = Arc::clone(&completed);
            let child_refused = Arc::clone(&refused);
            let host_key = server_signing_key.clone();
            let keys = deploy_keys.clone();
            let child_writers = Arc::clone(&writers);

            let task = match self.runtime.submit_blocking(move || {
                let success = Self::serve_one_ssh_session(
                    stream,
                    host_key,
                    keys,
                    &child_nodes,
                    allow_receive,
                    &child_writers,
                );
                if success {
                    child_completed.fetch_add(1, Ordering::AcqRel);
                } else {
                    child_refused.fetch_add(1, Ordering::AcqRel);
                }
                child_active.fetch_sub(1, Ordering::AcqRel);
            }) {
                Ok(task) => task,
                Err(error) => {
                    active.fetch_sub(1, Ordering::AcqRel);
                    refused.fetch_add(1, Ordering::AcqRel);
                    terminal_refusal =
                        Some(NodeSshRefusal::Node(NodeRefusal::Runtime(Box::new(error))));
                    break;
                }
            };
            child_tasks.push(task);
        }

        for task in &child_tasks {
            task.wait();
        }
        if let Err(error) = nodes.close()
            && terminal_refusal.is_none()
        {
            terminal_refusal = Some(NodeSshRefusal::Node(error));
        }

        let accepted_sessions = accepted;
        let completed_sessions = completed.load(Ordering::Acquire);
        let refused_sessions = refused.load(Ordering::Acquire);

        if let Some(refusal) = terminal_refusal {
            return Err(refusal);
        }

        Ok(SshServerReceipt {
            accepted_sessions,
            completed_sessions,
            refused_sessions,
        })
    }

    fn serve_one_ssh_session(
        mut stream: TcpStream,
        host_key: SigningKey,
        deploy_keys: Vec<DeployKeyBinding>,
        nodes: &crate::node_lanes::NodeLanes,
        allow_receive: bool,
        writers: &crate::WriterGate,
    ) -> bool {
        // Per-session secrets come from the runtime's OS entropy source.
        let mut session =
            SshServerSession::new(host_key, deploy_keys, Arc::new(asupersync::util::OsEntropy));
        session.start();

        let initial_bytes = session.take_outgoing_bytes();
        if stream.write_all(&initial_bytes).is_err() || stream.flush().is_err() {
            return false;
        }

        let mut wire_buf = [0u8; 16384];
        while session.phase() != &SessionPhase::ActiveChannel {
            if session.phase() == &SessionPhase::Closed {
                let out = session.take_outgoing_bytes();
                if !out.is_empty() {
                    let _ = stream.write_all(&out);
                    let _ = stream.flush();
                }
                return false;
            }

            let n = match stream.read(&mut wire_buf) {
                Ok(0) => return false,
                Ok(n) => n,
                Err(_) => return false,
            };

            if session.handle_incoming_bytes(&wire_buf[..n]).is_err() {
                let out = session.take_outgoing_bytes();
                if !out.is_empty() {
                    let _ = stream.write_all(&out);
                    let _ = stream.flush();
                }
                return false;
            }

            let out = session.take_outgoing_bytes();
            if !out.is_empty() && (stream.write_all(&out).is_err() || stream.flush().is_err()) {
                return false;
            }
        }

        let command = match session.active_command() {
            Some(cmd) => cmd.clone(),
            None => return false,
        };

        if command.service() == SshGitService::ReceivePack && !allow_receive {
            let recipient = session.client_channel_id().unwrap_or(0);
            session.send_channel_extended_data(
                recipient,
                b"ERR: Git receive-pack is disabled on this server\n",
            );
            session.send_channel_exit_and_close(1);
            let out = session.take_outgoing_bytes();
            let _ = stream.write_all(&out);
            let _ = stream.flush();
            close_gracefully(&mut session, &mut stream);
            return false;
        }

        let principal = session.authenticated_principal();

        // A leased node is already authenticated and in service; the pool
        // logs why when it cannot supply one.
        let Some(child_node) = nodes.lease() else {
            let recipient = session.client_channel_id().unwrap_or(0);
            session.send_channel_extended_data(
                recipient,
                b"ERR: Could not bring repository into service\n",
            );
            session.send_channel_exit_and_close(1);
            let out = session.take_outgoing_bytes();
            let _ = stream.write_all(&out);
            let _ = stream.flush();
            close_gracefully(&mut session, &mut stream);
            return false;
        };

        // `GIT_PROTOCOL` from the client's `env` request selects the wire
        // version under the same rule as a git-daemon greeting.
        let git_protocol = session
            .git_protocol()
            .map(<[u8]>::to_vec)
            .unwrap_or_default();
        let state_cell = RefCell::new(SshConnectionState {
            session,
            stream,
            read_buf: Vec::new(),
            read_pos: 0,
        });

        let served = match command.service() {
            SshGitService::UploadPack => {
                let mut reader = SshReader(&state_cell);
                let mut writer = SshWriter(&state_cell);
                let client = crate::ClientLiveness::new(|| {
                    state_cell
                        .try_borrow()
                        .ok()
                        .map(|state| state.peer_connected())
                });
                child_node
                    .serve_ssh_upload_pack(&mut reader, &mut writer, &git_protocol, &|| {
                        client.alive()
                    })
                    .is_ok()
            }
            SshGitService::ReceivePack => {
                let mut reader = SshReader(&state_cell);
                let mut writer = SshWriter(&state_cell);
                child_node
                    .serve_ssh_receive_pack(
                        &mut reader,
                        &mut writer,
                        principal,
                        &git_protocol,
                        writers,
                    )
                    .is_ok()
            }
        };

        let (exit_code, success) = if served { (0, true) } else { (1, false) };

        let mut final_state = state_cell.into_inner();
        final_state.session.send_channel_eof();
        final_state.session.send_channel_exit_and_close(exit_code);
        let final_out = final_state.session.take_outgoing_bytes();
        if !final_out.is_empty() {
            let _ = final_state.stream.write_all(&final_out);
            let _ = final_state.stream.flush();
        }
        close_gracefully(&mut final_state.session, &mut final_state.stream);

        // Only a node whose session succeeded goes back to the pool.
        let cleanup = if success {
            nodes.restore(child_node)
        } else {
            child_node.shutdown()
        };
        success && cleanup.is_ok()
    }

    fn serve_ssh_upload_pack<R: Read, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
        git_protocol: &[u8],
        peer_alive: &dyn Fn() -> bool,
    ) -> Result<GitDaemonSessionOutcome, NodeGitDaemonServeRefusal> {
        let service =
            ssh_git_service(true, git_protocol).map_err(NodeGitDaemonServeRefusal::from)?;
        let limits = WireLimits::default();
        let deadline = crate::GitDaemonSessionDeadline::new(
            self.git_daemon_session_timeout,
            self.git_daemon_session_work_scaling,
        );
        let request = self.request_context();
        deadline
            .check("materialize authenticated admission")
            .map_err(NodeGitDaemonServeRefusal::from)?;

        let admission_deadline_expired = std::sync::atomic::AtomicBool::new(false);
        let admission_is_live = || {
            if deadline.expired() {
                admission_deadline_expired.store(true, Ordering::Relaxed);
                return false;
            }
            true
        };
        let admission = self
            .runtime
            .block_on(self.materialize_admission_while_in(&request, &admission_is_live));
        if admission_deadline_expired.load(Ordering::Relaxed) || deadline.expired() {
            return Err(NodeGitDaemonServeRefusal::from(
                GitDaemonTransportRefusal::SessionDeadlineExceeded {
                    operation: "materialize authenticated admission",
                },
            ));
        }
        let materialized = admission.map_err(|error| {
            NodeGitDaemonServeRefusal::from(crate::NodeAdmissionViewRefusal::from(error))
        })?;

        let greeting = GitDaemonRequest {
            repository_path: self.git_daemon_repository_path.clone(),
            service,
        };

        let disclosure =
            self.prepare_visible_upload_pack(&request, &materialized, &limits, &deadline)?;
        let repository = disclosure.repository();
        let advertised_capabilities =
            crate::git_daemon_capabilities(self.object_format, repository.symref_target(b"HEAD"));
        let capabilities = fgit_wire::Capabilities::parse_v1(&advertised_capabilities, &limits)
            .map_err(GitDaemonTransportRefusal::Wire)
            .map_err(NodeGitDaemonServeRefusal::from)?;

        crate::serve_git_daemon_upload_pack_after_greeting(
            reader,
            writer,
            greeting,
            repository,
            capabilities,
            limits,
            Some(&deadline),
            |_request, pack_request| {
                let pack_context = self.session_pack_materialization_context(&deadline);
                let database_exhaustion = std::cell::Cell::new(None);
                let mut stopped = false;
                let session_deadline_expired = std::cell::Cell::new(false);
                let mut transfer_exhaustion = None;
                let pack = {
                    let session_is_live = || {
                        if deadline.expired() {
                            session_deadline_expired.set(true);
                            false
                        } else {
                            true
                        }
                    };
                    let mut is_live = || {
                        if stopped {
                            return false;
                        }
                        if !session_is_live() || !peer_alive() {
                            stopped = true;
                            return false;
                        }
                        match crate::checkpoint_pack_context(&pack_context) {
                            crate::PackContextCheckpoint::Live => true,
                            crate::PackContextCheckpoint::Stopped { budget_exhaustion } => {
                                stopped = true;
                                transfer_exhaustion = budget_exhaustion;
                                false
                            }
                        }
                    };
                    self.materialize_selected_pack_in_scope(
                        &materialized,
                        disclosure
                            .closure_for(&materialized)
                            .map_err(crate::GitDaemonServeError::Pack)?,
                        Some((&disclosure, pack_request)),
                        Some(&pack_request.wants),
                        &pack_request.haves,
                        crate::selected_write_profile(pack_request.options.ofs_delta()),
                        request.authority(),
                        &database_exhaustion,
                        Some(&session_is_live),
                        &mut is_live,
                    )
                };

                if deadline.expired() || session_deadline_expired.get() {
                    Err(crate::GitDaemonServeError::Transport(
                        GitDaemonTransportRefusal::SessionDeadlineExceeded {
                            operation: crate::SELECTED_PACK_MATERIALIZATION_OPERATION,
                        },
                    ))
                } else if let Some(dimension) = database_exhaustion.get() {
                    Err(crate::GitDaemonServeError::Pack(
                        crate::NodePackMaterializationRefusal::BudgetClassExhausted {
                            class: crate::BudgetClass::Database,
                            dimension,
                            operation: crate::SELECTED_PACK_MATERIALIZATION_OPERATION,
                        },
                    ))
                } else if let Some(dimension) = transfer_exhaustion {
                    Err(crate::GitDaemonServeError::Pack(
                        crate::NodePackMaterializationRefusal::BudgetClassExhausted {
                            class: crate::SELECTED_PACK_BUDGET_CLASS,
                            dimension,
                            operation: crate::SELECTED_PACK_MATERIALIZATION_OPERATION,
                        },
                    ))
                } else {
                    pack.map_err(crate::GitDaemonServeError::Pack)
                }
            },
        )
        .map_err(|error| match error {
            crate::GitDaemonServeError::Transport(t) => NodeGitDaemonServeRefusal::from(t),
            crate::GitDaemonServeError::Pack(p) => NodeGitDaemonServeRefusal::from(p),
        })
    }

    /// Serves `git-receive-pack` over an authorized SSH channel through the
    /// same guarded receive coordinator as raw TCP and smart HTTP: fresh-basis
    /// quarantine after ingress, the complete-session retry key, and a fatal
    /// UNKNOWN response (never invented `ng` rows) when admission may already
    /// have committed. The writer is the deploy key's principal, falling back
    /// to the operator's receive principal as before.
    fn serve_ssh_receive_pack<R: Read, W: ReceiveResponseWriter>(
        &self,
        reader: &mut R,
        writer: &mut W,
        principal: Option<PrincipalId>,
        git_protocol: &[u8],
        writers: &crate::WriterGate,
    ) -> Result<Option<fgit_admission::AdmissionResult>, crate::NodeSmartHttpRefusal> {
        ssh_git_service(false, git_protocol).map_err(NodeGitDaemonServeRefusal::from)?;
        let ingress = crate::GitDaemonSessionDeadline::new(
            self.git_daemon_session_timeout,
            self.git_daemon_session_work_scaling,
        );
        let route = self.git_daemon_repository_path.as_bytes().to_vec();
        self.serve_guarded_receive_session(
            reader,
            writer,
            principal.or(self.git_daemon_receive_principal),
            &ingress,
            None,
            Some(writers),
            &WireLimits::default(),
            |_| Ok(route),
            |request, session, validated, live| {
                self.admit_guarded_receive(request, session, validated, live)
            },
        )
    }
}

/// The Git service an SSH client's `GIT_PROTOCOL` value selects. The value is
/// `:`-separated, as Git's `GIT_PROTOCOL` environment variable is, and follows
/// exactly the git-daemon greeting rule: one `version=` entry at most,
/// versions 0 (absent), 1 and 2, and receive-pack ignoring `version=2`.
fn ssh_git_service(
    is_upload: bool,
    git_protocol: &[u8],
) -> Result<GitDaemonService, GitDaemonTransportRefusal> {
    crate::git_protocol_service(is_upload, git_protocol.split(|byte| *byte == b':'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp_peer_connected;
    use fgit_wire::UploadPackVersion;
    use std::time::Instant;

    #[test]
    fn git_protocol_selects_the_upload_pack_version_like_a_daemon_greeting() {
        for (value, version) in [
            (&b""[..], UploadPackVersion::V0),
            (b"version=1", UploadPackVersion::V1),
            (b"version=2", UploadPackVersion::V2),
            (b"object-format=sha1:version=2", UploadPackVersion::V2),
            (b"version=2:", UploadPackVersion::V2),
        ] {
            assert_eq!(
                ssh_git_service(true, value).unwrap(),
                GitDaemonService::UploadPack(version),
                "{value:?}"
            );
        }
        // receive-pack speaks v0/v1 and ignores a version=2 request.
        for value in [&b""[..], b"version=1", b"version=2"] {
            assert_eq!(
                ssh_git_service(false, value).unwrap(),
                GitDaemonService::ReceivePack
            );
        }
    }

    #[test]
    fn the_peer_probe_sees_a_closed_client_and_consumes_nothing_from_a_live_one() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        assert!(tcp_peer_connected(&server), "an idle live client");
        client.write_all(b"x").unwrap();
        // Pending bytes are a live client, and the probe leaves them unread.
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(5) {
            let mut byte = [0_u8; 1];
            server.set_nonblocking(true).unwrap();
            let pending = server.peek(&mut byte).is_ok();
            server.set_nonblocking(false).unwrap();
            if pending {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(tcp_peer_connected(&server));
        let mut byte = [0_u8; 1];
        server.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"x", "the probe consumed client data");
        // An orderly close is seen as gone, and blocking mode is restored.
        drop(client);
        let started = Instant::now();
        while tcp_peer_connected(&server) && started.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!tcp_peer_connected(&server), "a closed client");
        server
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        assert_eq!(server.read(&mut byte).unwrap(), 0, "blocking read sees EOF");
    }

    #[test]
    fn duplicate_or_unknown_protocol_versions_are_typed_refusals() {
        for is_upload in [true, false] {
            assert!(matches!(
                ssh_git_service(is_upload, b"version=2:version=2"),
                Err(GitDaemonTransportRefusal::DuplicateProtocolVersion)
            ));
            assert!(matches!(
                ssh_git_service(is_upload, b"version=3"),
                Err(GitDaemonTransportRefusal::UnsupportedProtocolVersion { version_bytes: 1 })
            ));
        }
        // The permitted twins: one known version, and an unrelated key.
        assert!(ssh_git_service(true, b"version=2:agent=git/2").is_ok());
        assert!(ssh_git_service(false, b"version=1").is_ok());
    }
}
