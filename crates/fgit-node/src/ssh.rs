//! SSH transport service integration for FrankenGit node assembly (FG-047/FG-047b).
//!
//! Provides pure-Rust bounded and continuously supervised SSH service execution:
//! - Shell-free command parsing and dispatch (`git-upload-pack`, `git-receive-pack`)
//! - RFC 8731 Curve25519 key exchange and OpenSSH ChaCha20-Poly1305 encryption
//! - Deploy-key authentication and repository-scoped authorization
//! - SANS-I/O session state machine mapped to Asupersync blocking threads

use std::borrow::Borrow;
use std::cell::RefCell;
use std::fmt::{self, Display, Formatter};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use fgit_identity::deploy_key::DeployKeyBinding;
use fgit_ssh::SigningKey;
use fgit_ssh::command::SshGitService;
use fgit_ssh::session::{SessionPhase, SshServerSession, SshSessionError};
use fgit_types::PrincipalId;
use fgit_wire::{UploadPackRepository, WireLimits};

use crate::{
    GitDaemonRequest, GitDaemonServerReceipt, GitDaemonService, GitDaemonSessionDeadline,
    GitDaemonSessionOutcome, GitDaemonSessionTimeout, GitDaemonSessionWorkScaling,
    GitDaemonTransportRefusal, NodeGitDaemonServeRefusal, NodeRefusal, OneNode, PushQuota,
    ReceiveResponseWriter,
};

mod deadline;
mod lifetime;

use lifetime::{Acceptance, Completion, Pending, reap};

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

/// Outcome receipt after SSH acceptance has stopped and every child has settled.
pub type SshServerReceipt = GitDaemonServerReceipt;

/// Refusals occurring during SSH server execution.
#[derive(Debug)]
pub enum NodeSshRefusal {
    ZeroSessionLimit,
    ZeroInFlightLimit,
    LimitsExceeded,
    NotServing,
    StopControl(io::Error),
    CounterExhausted,
    UnsettledChildren,
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
            Self::NotServing => write!(formatter, "SSH requires a serving node"),
            Self::StopControl(err) => write!(formatter, "SSH stop control failed: {err}"),
            Self::CounterExhausted => write!(formatter, "SSH session counter exhausted"),
            Self::UnsettledChildren => write!(formatter, "SSH child accounting did not settle"),
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
    let deadline = GitDaemonSessionDeadline::new(
        GitDaemonSessionTimeout::try_new(Duration::from_secs(10)).expect("nonzero close budget"),
        GitDaemonSessionWorkScaling::FLAT,
    );
    let mut drained = 0usize;
    let mut buf = [0u8; 16384];
    while !deadline.expired() && drained < 4 * 1024 * 1024 {
        match deadline::read(stream, &deadline, &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                drained += n;
                if session.handle_incoming_bytes(&buf[..n]).is_err() {
                    break;
                }
                let out = session.take_outgoing_bytes();
                if deadline::write_all(stream, &deadline, &out).is_err() {
                    break;
                }
            }
        }
    }
}

struct SshConnectionState {
    session: SshServerSession,
    stream: TcpStream,
    deadline: GitDaemonSessionDeadline,
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
        self.deadline.remaining()?;
        let out = self.session.take_outgoing_bytes();
        deadline::write_all(&mut self.stream, &self.deadline, &out)
    }

    /// Reads one burst from the client and feeds it to the session. A socket
    /// read timeout is idleness, not a transient condition: it ends the
    /// session instead of spinning.
    fn pump_incoming(&mut self) -> io::Result<usize> {
        // Anything queued (such as a receive-window adjustment) must reach the
        // client before we block waiting for it to send more.
        self.flush_outgoing()?;
        let mut wire_buf = [0u8; 16384];
        let n = match deadline::read(&mut self.stream, &self.deadline, &mut wire_buf) {
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
        if buf.is_empty() {
            return Ok(0);
        }
        self.deadline.remaining()?;
        if self.read_pos < self.read_buf.len() {
            let available = &self.read_buf[self.read_pos..];
            let to_copy = available.len().min(buf.len());
            buf[..to_copy].copy_from_slice(&available[..to_copy]);
            self.read_pos += to_copy;
            self.deadline.note_admitted(to_copy);
            return Ok(to_copy);
        }

        self.read_buf.clear();
        self.read_pos = 0;

        loop {
            self.deadline.remaining()?;
            // Data already decoded (for example while waiting for window
            // space in `write_channel`) is delivered before EOF is reported.
            let new_data = self.session.take_channel_input();
            if !new_data.is_empty() {
                self.read_buf = new_data;
                let to_copy = self.read_buf.len().min(buf.len());
                buf[..to_copy].copy_from_slice(&self.read_buf[..to_copy]);
                self.read_pos = to_copy;
                self.deadline.note_admitted(to_copy);
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
                self.deadline.note_admitted(to_copy);
                return Ok(to_copy);
            }
        }
    }

    fn write_channel(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut written = 0;
        while written < buf.len() {
            self.deadline.remaining()?;
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
    fn restart_deadline(&mut self, deadline: GitDaemonSessionDeadline) {
        // The native coordinator restarts only after a terminal result exists.
        // Its response may still require SSH window-adjust packets to arrive.
        self.0.borrow_mut().deadline = deadline;
    }
}

impl OneNode {
    /// Serves SSH until the finite acceptance budget is exhausted, then drains.
    /// The caller retains ownership of the listening socket.
    pub fn serve_ssh_bounded(
        &self,
        listener: &TcpListener,
        limits: SshServerLimits,
        server_signing_key: SigningKey,
        deploy_keys: Vec<DeployKeyBinding>,
        allow_receive: bool,
    ) -> Result<SshServerReceipt, NodeSshRefusal> {
        let limits = SshServerLimits::try_new(limits.max_sessions, limits.max_in_flight)?;
        self.serve_ssh_with_lifetime(
            listener,
            limits.max_in_flight,
            server_signing_key,
            deploy_keys,
            allow_receive,
            Acceptance::Bounded(limits.max_sessions),
        )
    }

    /// Serves SSH until the control callback requests retirement.
    ///
    /// The owned listener closes before accepted sessions are joined. Accepted
    /// work retains its finite ingress, processing, response and close budgets.
    /// Stop control is checked even when all session slots are occupied.
    pub fn serve_ssh_until_stopped(
        &self,
        listener: TcpListener,
        max_in_flight: usize,
        server_signing_key: SigningKey,
        deploy_keys: Vec<DeployKeyBinding>,
        allow_receive: bool,
        should_stop: &dyn Fn() -> io::Result<bool>,
    ) -> Result<SshServerReceipt, NodeSshRefusal> {
        SshServerLimits::try_new(1, max_in_flight)?;
        self.serve_ssh_with_lifetime(
            listener,
            max_in_flight,
            server_signing_key,
            deploy_keys,
            allow_receive,
            Acceptance::UntilStopped(should_stop),
        )
    }

    fn serve_ssh_with_lifetime<L: Borrow<TcpListener>>(
        &self,
        listener: L,
        max_in_flight: usize,
        server_signing_key: SigningKey,
        deploy_keys: Vec<DeployKeyBinding>,
        allow_receive: bool,
        acceptance: Acceptance<'_>,
    ) -> Result<SshServerReceipt, NodeSshRefusal> {
        if self.cell_state() != fgit_types::cell::CellState::Serving {
            return Err(NodeSshRefusal::NotServing);
        }
        listener
            .borrow()
            .set_nonblocking(true)
            .map_err(NodeSshRefusal::Accept)?;

        let writers = Arc::new(crate::WriterGate::new(crate::MAX_CONCURRENT_WRITERS));
        // Rate accounting belongs to the service, not a short-lived lane lease.
        let quota = Arc::new(PushQuota::default());
        let nodes = Arc::new(crate::node_lanes::NodeLanes::new(
            self.service_config
                .clone()
                .with_expected_repository_incarnation(self.repository_incarnation_id()),
            max_in_flight,
            "SSH",
        ));
        let completed = Arc::new(AtomicUsize::new(0));
        let refused = Arc::new(AtomicUsize::new(0));
        let mut pending = Vec::with_capacity(max_in_flight);
        let mut accepted = 0usize;
        let mut terminal_refusal = None;

        loop {
            reap(&mut pending);
            match acceptance.keep_accepting(accepted) {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) => {
                    terminal_refusal = Some(error);
                    break;
                }
            }
            if pending.len() >= max_in_flight {
                self.runtime.wait_for(Duration::from_millis(1));
                continue;
            }

            let stream = match listener.borrow().accept() {
                Ok((stream, _)) => stream,
                Err(source) if source.kind() == io::ErrorKind::Interrupted => continue,
                Err(source) if source.kind() == io::ErrorKind::WouldBlock => {
                    self.runtime.wait_for(Duration::from_millis(1));
                    continue;
                }
                Err(source) => {
                    terminal_refusal = Some(NodeSshRefusal::Accept(source));
                    break;
                }
            };

            let Some(next_accepted) = accepted.checked_add(1) else {
                terminal_refusal = Some(NodeSshRefusal::CounterExhausted);
                break;
            };
            accepted = next_accepted;
            // Queueing and authentication consume this same accepted budget.
            let deadline = GitDaemonSessionDeadline::new(
                self.git_daemon_session_timeout,
                self.git_daemon_session_work_scaling,
            );
            let finished = Arc::new(AtomicBool::new(false));
            let completion = Completion {
                finished: Arc::clone(&finished),
                completed: Arc::clone(&completed),
                refused: Arc::clone(&refused),
                success: false,
            };
            let child_nodes = Arc::clone(&nodes);
            let host_key = server_signing_key.clone();
            let keys = deploy_keys.clone();
            let child_writers = Arc::clone(&writers);
            let child_quota = Arc::clone(&quota);

            let task = match self.runtime.submit_blocking(move || {
                let mut completion = completion;
                completion.success = Self::serve_one_ssh_session(
                    stream,
                    host_key,
                    keys,
                    &child_nodes,
                    allow_receive,
                    &child_writers,
                    &child_quota,
                    deadline,
                );
                // Drop settles accounting even if the session unwinds. A
                // rejected submission also drops this owned completion guard.
            }) {
                Ok(task) => task,
                Err(error) => {
                    terminal_refusal =
                        Some(NodeSshRefusal::Node(NodeRefusal::Runtime(Box::new(error))));
                    break;
                }
            };
            pending.push(Pending {
                finished,
                join: Box::new(move || {
                    task.wait();
                }),
            });
        }

        if let Err(error) = listener.borrow().set_nonblocking(false) {
            if terminal_refusal.is_none() {
                terminal_refusal = Some(NodeSshRefusal::Accept(error));
            } else {
                eprintln!("SSH listener cleanup failed: {error}");
            }
        }
        // For controlled service this owns the socket: close it before waiting
        // for active sessions, so a draining server cannot admit new connects.
        drop(listener);
        for task in pending {
            (task.join)();
        }
        if let Err(error) = nodes.close() {
            if terminal_refusal.is_none() {
                terminal_refusal = Some(NodeSshRefusal::Shutdown(error));
            } else {
                eprintln!("SSH lane cleanup failed: {error}");
            }
        }

        let completed_sessions = completed.load(Ordering::Acquire);
        let refused_sessions = refused.load(Ordering::Acquire);
        if completed_sessions.checked_add(refused_sessions) != Some(accepted) {
            if terminal_refusal.is_none() {
                terminal_refusal = Some(NodeSshRefusal::UnsettledChildren);
            } else {
                eprintln!("SSH child accounting did not settle");
            }
        }
        if let Some(refusal) = terminal_refusal {
            return Err(refusal);
        }
        Ok(SshServerReceipt {
            accepted_sessions: accepted,
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
        quota: &PushQuota,
        deadline: GitDaemonSessionDeadline,
    ) -> bool {
        if stream.set_nonblocking(false).is_err() || deadline.expired() {
            return false;
        }
        // Per-session secrets come from the runtime's OS entropy source.
        let mut session =
            SshServerSession::new(host_key, deploy_keys, Arc::new(asupersync::util::OsEntropy));
        session.start();

        let initial_bytes = session.take_outgoing_bytes();
        if deadline::write_all_handshake(&mut stream, &deadline, &initial_bytes).is_err() {
            return false;
        }

        let mut wire_buf = [0u8; 16384];
        while session.phase() != &SessionPhase::ActiveChannel {
            if deadline.expired() {
                return false;
            }
            if session.phase() == &SessionPhase::Closed {
                let out = session.take_outgoing_bytes();
                let _ = deadline::write_all_handshake(&mut stream, &deadline, &out);
                return false;
            }

            let n = match deadline::read_handshake(&mut stream, &deadline, &mut wire_buf) {
                Ok(0) => return false,
                Ok(n) => n,
                Err(_) => return false,
            };

            if session.handle_incoming_bytes(&wire_buf[..n]).is_err() {
                let out = session.take_outgoing_bytes();
                let _ = deadline::write_all_handshake(&mut stream, &deadline, &out);
                return false;
            }

            let out = session.take_outgoing_bytes();
            if deadline::write_all_handshake(&mut stream, &deadline, &out).is_err() {
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
            let _ = deadline::write_all(&mut stream, &deadline, &out);
            close_gracefully(&mut session, &mut stream);
            return false;
        }

        let principal = session.authenticated_principal();
        // GIT_PROTOCOL selects the same wire version as a daemon greeting.
        let git_protocol = session
            .git_protocol()
            .map(<[u8]>::to_vec)
            .unwrap_or_default();

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
            let _ = deadline::write_all(&mut stream, &deadline, &out);
            close_gracefully(&mut session, &mut stream);
            return false;
        };
        // Authenticated Git may be quiet while the client compresses a pack.
        // Use the full remaining session budget here; the 60-second idle cap
        // applies only before a command is authorized.
        let state_cell = RefCell::new(SshConnectionState {
            session,
            stream,
            deadline: deadline.clone(),
            read_buf: Vec::new(),
            read_pos: 0,
        });

        // Keep the leased node outside both unwind guards so every refusal,
        // including a panic during SSH finalization, reaches explicit shutdown.
        let served =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match command.service() {
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
                        .serve_ssh_upload_pack(
                            &mut reader,
                            &mut writer,
                            &git_protocol,
                            &|| client.alive(),
                            &deadline,
                        )
                        .inspect_err(|error| eprintln!("ssh session failed: upload-pack: {error}"))
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
                            quota,
                            &deadline,
                        )
                        .inspect_err(|error| eprintln!("ssh session failed: receive-pack: {error}"))
                        .is_ok()
                }
            }))
            .unwrap_or_else(|_| {
                eprintln!("SSH Git operation panicked; publication outcome may be unknown");
                false
            });

        let exit_code = if served { 0 } else { 1 };
        let delivered = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut final_state = state_cell.into_inner();
            final_state.session.send_channel_eof();
            final_state.session.send_channel_exit_and_close(exit_code);
            let final_out = final_state.session.take_outgoing_bytes();
            let delivered =
                deadline::write_all(&mut final_state.stream, &final_state.deadline, &final_out)
                    .is_ok();
            close_gracefully(&mut final_state.session, &mut final_state.stream);
            delivered
        }))
        .unwrap_or_else(|_| {
            eprintln!("SSH finalization panicked; publication outcome may be unknown");
            false
        });

        // Only a node whose complete session succeeded returns to the pool.
        let cleanup = if served && delivered {
            nodes.restore(child_node)
        } else {
            child_node.shutdown()
        };
        if let Err(error) = &cleanup {
            eprintln!("ssh session cleanup failed: {error}");
        }
        served && delivered && cleanup.is_ok()
    }

    fn serve_ssh_upload_pack<R: Read, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
        git_protocol: &[u8],
        peer_alive: &dyn Fn() -> bool,
        deadline: &GitDaemonSessionDeadline,
    ) -> Result<GitDaemonSessionOutcome, NodeGitDaemonServeRefusal> {
        let service =
            ssh_git_service(true, git_protocol).map_err(NodeGitDaemonServeRefusal::from)?;
        let limits = WireLimits::default();
        // On the session's deadline, not the Database class's flat 15 s
        // (frankengit-root-doctrine-x2mv.4.53).
        let request = self.session_request_context(deadline);
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
            self.prepare_visible_upload_pack(&request, &materialized, &limits, deadline)?;
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
            Some(deadline),
            |_request, pack_request| {
                let pack_context = self.session_pack_materialization_context(deadline);
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
        quota: &PushQuota,
        ingress: &GitDaemonSessionDeadline,
    ) -> Result<Option<fgit_admission::AdmissionResult>, crate::NodeSmartHttpRefusal> {
        ssh_git_service(false, git_protocol).map_err(NodeGitDaemonServeRefusal::from)?;
        let route = self.git_daemon_repository_path.as_bytes().to_vec();
        self.serve_guarded_receive_session(
            reader,
            writer,
            principal.or(self.git_daemon_receive_principal),
            ingress,
            Some(quota),
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
mod service_tests;

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
