//! Raw Git compatibility over the guarded production receive coordinator.
//! Upload negotiation remains on its existing implementation. No HTTP envelope,
//! alternate ref database, or transport-local publication rule is introduced.

mod supervisor;

use std::io::{self, Cursor, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::{Duration, Instant};

use fgit_admission::evidence::AdmissionAuthentication;
use fgit_admission::{AdmissionLimits, AdmissionResult, BasisBoundValidatedReceive};
use fgit_authority::IdempotencyKey;
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_git_object::ParseLimits;
use fgit_pack::{PackBoundaryScanner, ScanStatus};
use fgit_types::cell::admits_staging_intake;
use fgit_wire::receive::{ReceiveError, ReceiveEvent, ReceivePack, advertise_receive_pack};
use fgit_wire::{Packet, WireLimits, encode_packets};

use super::super::verdict::command_verdict_report;
use super::super::{NodeSmartHttpRefusal, command_limit, drive_request_while};
use crate::{
    AdmissionReceivePackAdvertisement, DeadlineTcpStream, GitDaemonService,
    GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, GitDaemonTransportRefusal,
    LoopbackReceiveSession, NodeAdmissionViewRefusal, NodeGitDaemonServeRefusal,
    NodeReceiveTransportRefusal, NodeRequestContext, OneNode, ProductionReceiveQuarantineHandoff,
    read_git_daemon_request, read_receive_frame,
};

const COMMAND_BYTES: usize = 4 * 1024 * 1024;
const CHUNK: usize = 16 * 1024;

const fn io_error(operation: &'static str, source: io::Error) -> NodeSmartHttpRefusal {
    NodeSmartHttpRefusal::Io { operation, source }
}
fn invalid(operation: &'static str) -> NodeSmartHttpRefusal {
    io_error(operation, io::ErrorKind::InvalidData.into())
}
fn checkpoint(deadline: &GitDaemonSessionDeadline) -> Result<(), NodeSmartHttpRefusal> {
    deadline
        .check("guarded git-daemon ingress")
        .map_err(NodeGitDaemonServeRefusal::from)?;
    Ok(())
}

/// Exact legacy selector: native transaction identities are still derived only
/// by admission. PACK representation, connection and peer address are excluded.
fn retry_key(route: &[u8], commands: &[u8]) -> Result<IdempotencyKey, NodeSmartHttpRefusal> {
    let mut hash = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hash.update(b"frankengit.git-daemon.receive-idempotency/v1\0");
    hash.update(route);
    hash.update(&[0]);
    hash.update(commands);
    IdempotencyKey::new(hash.finish().to_vec()).map_err(|_| invalid("derive daemon retry key"))
}

// Sniff only one bounded greeting without consuming it. This lets upload-pack
// keep the existing implementation, including every shallow/filter rule.
fn is_receive(
    node: &OneNode,
    stream: &TcpStream,
    deadline: &GitDaemonSessionDeadline,
    limits: &WireLimits,
) -> Result<bool, NodeSmartHttpRefusal> {
    stream
        .set_nonblocking(true)
        .map_err(|e| io_error("configure greeting peek", e))?;
    let result = (|| {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(65_520).map_err(|_| {
            io_error(
                "allocate daemon greeting buffer",
                io::ErrorKind::OutOfMemory.into(),
            )
        })?;
        bytes.resize(65_520, 0);
        loop {
            checkpoint(deadline)?;
            let read = match stream.peek(&mut bytes) {
                Ok(0) => return Err(invalid("incomplete daemon greeting")),
                Ok(n) => n,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    0
                }
                Err(e) => return Err(io_error("peek daemon greeting", e)),
            };
            if read >= 4 {
                let text = std::str::from_utf8(&bytes[..4])
                    .map_err(|_| invalid("invalid greeting length"))?;
                let size = usize::from(
                    u16::from_str_radix(text, 16)
                        .map_err(|_| invalid("invalid greeting length"))?,
                );
                if !(4..=bytes.len()).contains(&size) {
                    return Err(invalid("invalid greeting length"));
                }
                if read >= size {
                    let greeting =
                        read_git_daemon_request(&mut Cursor::new(&bytes[..size]), limits)
                            .map_err(NodeGitDaemonServeRefusal::from)?;
                    if greeting.repository_path() != &node.git_daemon_repository_path {
                        return Err(NodeSmartHttpRefusal::RepositoryRouteMismatch);
                    }
                    return Ok(greeting.service() == GitDaemonService::ReceivePack);
                }
            }
            node.runtime.wait_for(Duration::from_millis(1));
        }
    })();
    // No clone or reader exists yet, so restoring blocking mode is singular.
    let restored = stream
        .set_nonblocking(false)
        .map_err(|e| io_error("restore greeting socket", e));
    match result {
        Err(error) => Err(error),
        Ok(value) => restored.map(|()| value),
    }
}

fn fatal(
    writer: &mut impl Write,
    admission_started: bool,
    processing_expired: bool,
    command_bound: Option<usize>,
    cause: Option<&str>,
    limits: &WireLimits,
) -> io::Result<()> {
    // Before admission starts nothing was decided, so a client-safe cause
    // (crate::receive_refusal) is named; a client or CI job can act on a quota,
    // a bound or a malformed request only if it reads which (frankengit-yrff).
    // The command-count refusal keeps its own operator text (command_limit,
    // frankengit-p9b5). After admission starts the outcome is unknown whatever
    // the cause, and the processing deadline keeps its own text.
    let named = match (admission_started, processing_expired, cause) {
        (false, false, Some(cause)) if command_bound.is_none() => {
            Some(format!("ERR {cause}; no ref decision was attempted\n").into_bytes())
        }
        _ => None,
    };
    // Name the processing deadline when it is the cause, so an operator knows
    // which budget a large push needs (frankengit-3gdw contract (b)).
    let message = match (admission_started, processing_expired) {
        (true, false) => {
            b"ERR receive outcome unknown; retry identical commands or recover the original key\n"
                .as_slice()
        }
        (true, true) => b"ERR receive outcome unknown: the processing deadline expired during \
            admission; retry identical commands or recover the original key \
            (fg serve --processing-timeout-secs)\n"
            .as_slice(),
        (false, false) => {
            b"ERR receive failed before admission; no ref decision was attempted\n".as_slice()
        }
        (false, true) => b"ERR receive failed before admission: the processing deadline \
            expired; no ref decision was attempted (fg serve --processing-timeout-secs)\n"
            .as_slice(),
    };
    let bounded = command_bound
        .filter(|_| !admission_started)
        .map(command_limit::message);
    let message = bounded.as_deref().or(named.as_deref()).unwrap_or(message);
    let bytes = encode_packets(&[Packet::Data(message.to_vec())], limits)
        .map_err(|e| io::Error::other(e.to_string()))?;
    writer.write_all(&bytes)?;
    writer.flush()
}

/// A verdict reached during quarantine has the same finite response phase as
/// a terminal admission result. The earlier upload clock may already be spent.
fn write_command_verdict(
    writer: &mut impl crate::ReceiveResponseWriter,
    ready: &fgit_wire::receive::ReceiveRequest,
    code: fgit_types::RefusalCode,
    limits: &fgit_wire::receive::ReceiveLimits,
    timeout: crate::GitDaemonSessionTimeout,
) -> Result<bool, NodeSmartHttpRefusal> {
    let Some(report) = command_verdict_report(ready, code, limits) else {
        return Ok(false);
    };
    let bytes = encode_packets(&report?, &limits.wire)?;
    writer.restart_deadline(GitDaemonSessionDeadline::new(
        timeout,
        GitDaemonSessionWorkScaling::FLAT,
    ));
    writer
        .write_all(&bytes)
        .map_err(|e| io_error("write guarded receive verdict", e))?;
    writer
        .flush()
        .map_err(|e| io_error("flush guarded receive verdict", e))?;
    Ok(true)
}

impl OneNode {
    /// Serve one accepted raw Git stream with guarded receive admission.
    ///
    /// Upload-pack delegates to the original compatibility engine without
    /// consuming its greeting. Receive requires the operator-configured
    /// principal: this protocol authenticates no remote user, so deploy it only
    /// behind a trusted local transport. Use Smart HTTP for bearer credentials.
    ///
    /// Commands and PACK framing use the native machines. Quarantine selects a
    /// fresh authenticated basis AFTER ingress, not the earlier advertisement.
    /// Non-atomic commands share HTTP's complete-session key binding, guarded
    /// continuation, recovery descriptor and retained interrupted outcomes.
    /// An interrupted admission emits a fatal UNKNOWN response, never invented
    /// `ng` records for commands that may already have committed.
    ///
    /// Successful receive returns its canonical result; upload returns None.
    /// Response loss retains the result in ReceiveResponse. This blocking socket
    /// binding must be owned by a runtime blocking task through completion.
    pub fn serve_guarded_git_daemon_stream(
        &self,
        stream: TcpStream,
    ) -> Result<Option<AdmissionResult>, NodeSmartHttpRefusal> {
        let ingress = GitDaemonSessionDeadline::new(
            self.git_daemon_session_timeout,
            self.git_daemon_session_work_scaling,
        );
        self.serve_guarded_git_daemon_stream_in(stream, ingress, None, None)
    }

    fn serve_guarded_git_daemon_stream_in(
        &self,
        stream: TcpStream,
        ingress: GitDaemonSessionDeadline,
        shared_quota: Option<&crate::PushQuota>,
        writers: Option<&crate::WriterGate>,
    ) -> Result<Option<AdmissionResult>, NodeSmartHttpRefusal> {
        self.serve_guarded_git_daemon_stream_with_admission(
            stream,
            ingress,
            shared_quota,
            writers,
            |request, session, validated, staging, live| {
                self.admit_guarded_receive(request, session, validated, staging, live)
            },
        )
    }

    // Private composition seam: production always supplies the guarded driver
    // above. Fault tests substitute only an unavailable projection operation,
    // retaining the real socket parser, quarantine, authority and final response.
    fn serve_guarded_git_daemon_stream_with_admission<F>(
        &self,
        mut stream: TcpStream,
        ingress: GitDaemonSessionDeadline,
        shared_quota: Option<&crate::PushQuota>,
        writers: Option<&crate::WriterGate>,
        admit: F,
    ) -> Result<Option<AdmissionResult>, NodeSmartHttpRefusal>
    where
        F: FnOnce(
            &NodeRequestContext,
            &LoopbackReceiveSession,
            &BasisBoundValidatedReceive,
            Option<&crate::receive_staging::ReceiveStaging>,
            &mut dyn FnMut() -> bool,
        ) -> Result<AdmissionResult, NodeSmartHttpRefusal>,
    {
        let limits = WireLimits::default();
        if !is_receive(self, &stream, &ingress, &limits)? {
            return self
                .serve_git_daemon_stream_with_limits(stream, limits)
                .map(|_| None)
                .map_err(NodeSmartHttpRefusal::from);
        }
        let mut output = stream
            .try_clone()
            .map_err(|e| io_error("clone receive socket", e))?;
        let mut reader = DeadlineTcpStream::new(&mut stream, ingress.clone());
        let mut writer = DeadlineTcpStream::new(&mut output, ingress.clone());
        let result = self.serve_guarded_receive_session(
            &mut reader,
            &mut writer,
            self.git_daemon_receive_principal,
            AdmissionAuthentication::OperatorAssertion,
            None,
            &ingress,
            shared_quota,
            writers,
            &limits,
            |reader| {
                let greeting = read_git_daemon_request(reader, &limits)
                    .map_err(NodeGitDaemonServeRefusal::from)?;
                Ok(greeting.repository_path().as_bytes().to_vec())
            },
            admit,
        );
        drop(writer);
        drop(reader);
        let _ = output.shutdown(Shutdown::Write);
        // Bound cleanup by both bytes AND elapsed time, including a peer that
        // keeps sending after the response. Closing cannot infer a rollback.
        let start = Instant::now();
        let mut remaining = 64 * 1024;
        let mut scratch = [0_u8; 1024];
        while remaining > 0 {
            let budget = Duration::from_secs(1).saturating_sub(start.elapsed());
            if budget.is_zero() || stream.set_read_timeout(Some(budget)).is_err() {
                break;
            }
            match stream.read(&mut scratch[..remaining.min(1024)]) {
                Ok(0) | Err(_) => break,
                Ok(n) => remaining -= n,
            }
        }
        result
    }

    /// The guarded receive session over any byte transport.
    ///
    /// Everything between the transport's own framing and its teardown:
    /// principal, quota and cell-state checks, the authenticated
    /// advertisement, native command and PACK framing, quarantine against a
    /// fresh basis selected after ingress, `admit`, the report, and the fatal
    /// UNKNOWN response that never invents per-ref rejections. `route`
    /// supplies the repository route bound into the retry key: the raw TCP
    /// binding reads it from the git-daemon greeting, SSH takes it from the
    /// authorized exec request. `principal` is the authorized writer;
    /// `None` is refused before any byte of the request is read. The optional
    /// immutable ref ceiling comes from that same command authorization.
    /// `authentication` retains that boundary's proof: a raw Git operator
    /// assertion cannot acquire the SSH binding's credential provenance.
    pub(crate) fn serve_guarded_receive_session<R, W, G, F>(
        &self,
        reader: &mut R,
        writer: &mut W,
        principal: Option<fgit_types::PrincipalId>,
        authentication: AdmissionAuthentication,
        ref_write_scope: Option<std::sync::Arc<fgit_types::ref_write_scope::RefWriteScope>>,
        ingress: &GitDaemonSessionDeadline,
        shared_quota: Option<&crate::PushQuota>,
        writers: Option<&crate::WriterGate>,
        limits: &WireLimits,
        route: G,
        admit: F,
    ) -> Result<Option<AdmissionResult>, NodeSmartHttpRefusal>
    where
        R: Read,
        W: crate::ReceiveResponseWriter,
        G: FnOnce(&mut R) -> Result<Vec<u8>, NodeSmartHttpRefusal>,
        F: FnOnce(
            &NodeRequestContext,
            &LoopbackReceiveSession,
            &BasisBoundValidatedReceive,
            Option<&crate::receive_staging::ReceiveStaging>,
            &mut dyn FnMut() -> bool,
        ) -> Result<AdmissionResult, NodeSmartHttpRefusal>,
    {
        let mut admission_started = false;
        let mut final_attempted = false;
        let mut verdict_reported = false;
        let processing_expired = std::cell::Cell::new(false);
        let result = (|| {
            let principal = principal.ok_or(NodeSmartHttpRefusal::UnauthenticatedReceive)?;
            shared_quota
                .unwrap_or(&self.push_quota)
                .evaluate(&principal)?;
            admits_staging_intake(self.cell_state())
                .map_err(NodeReceiveTransportRefusal::CellState)?;
            let route = route(reader)?;
            let mut context = self.smart_http_receive_context(limits.clone())?;
            context.limits.max_commands = context
                .limits
                .max_commands
                .min(AdmissionLimits::default().max_commands);
            let receive_limits = context.limits.clone();
            let advertisement_request = self.request_context();
            let mut live = || !ingress.expired();
            let selected = drive_request_while(
                self,
                &advertisement_request,
                self.materialize_admission_in(&advertisement_request),
                &mut live,
            )
            .map_err(NodeAdmissionViewRefusal::from)?;
            let snapshot = selected.snapshot();
            let refs = AdmissionReceivePackAdvertisement::from_snapshot(
                snapshot,
                &snapshot.hidden_refs,
                self.object_format,
                limits,
            )
            .map_err(NodeAdmissionViewRefusal::from)?;
            let advertised = advertise_receive_pack(refs.advertised_refs().to_vec(), &context)?;
            let bytes = encode_packets(&advertised, limits)?;
            writer
                .write_all(&bytes)
                .map_err(|e| io_error("write receive advertisement", e))?;
            writer
                .flush()
                .map_err(|e| io_error("flush receive advertisement", e))?;
            drop(selected);
            let mut machine = ReceivePack::new(context)?
                .with_pack_retention(self.received_pack_cache().capture_limit());
            let mut prefix = Vec::new();
            let ready = 'commands: loop {
                checkpoint(ingress)?;
                let (raw, packet) =
                    read_receive_frame(reader, limits).map_err(NodeGitDaemonServeRefusal::from)?;
                // A flush before any command is an empty request. git sends it
                // for an up-to-date or dry-run push, and upstream receive-pack
                // ends that session successfully, admitting and reporting
                // nothing.
                if prefix.is_empty() && matches!(packet, Packet::Flush) {
                    return Ok(None);
                }
                if raw.len() > COMMAND_BYTES.saturating_sub(prefix.len()) {
                    return Err(invalid("receive command envelope exceeded"));
                }
                prefix
                    .try_reserve(raw.len())
                    .map_err(|_| invalid("allocate receive prefix"))?;
                prefix.extend_from_slice(&raw);
                for event in machine.push_packet(packet)?.events {
                    if let ReceiveEvent::RequestReady(ready) = event {
                        break 'commands ready;
                    }
                }
            };
            let authenticated =
                crate::AuthenticatedReceiveSession::new(principal, retry_key(&route, &prefix)?)
                    .with_authentication(authentication)
                    .with_ref_write_scope(ref_write_scope);
            // Check every original command before reading PACK bytes, acquiring
            // a writer slot, binding retry keys or publishing any microbatch.
            // The native admission boundary independently repeats this check.
            if ready
                .commands
                .iter()
                .any(|command| !authenticated.permits_ref_write_bytes(&command.ref_name))
            {
                return Err(NodeSmartHttpRefusal::RefWriteScopeDenied);
            }
            let session = LoopbackReceiveSession::Authenticated(authenticated);
            let mut input_bytes = prefix.len() as u64;
            drop(prefix);
            if ready.requires_pack() {
                let mut scanner =
                    PackBoundaryScanner::new(self.object_format, receive_limits.pack.clone());
                let mut chunk = [0_u8; CHUNK];
                loop {
                    checkpoint(ingress)?;
                    let count = match reader.read(&mut chunk) {
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        result => result.map_err(|e| io_error("read receive PACK", e))?,
                    };
                    if count == 0 {
                        return Err(invalid("truncated receive PACK"));
                    }
                    let state = scanner
                        .push(&chunk[..count], &mut || !ingress.expired())
                        .map_err(|e| {
                            NodeGitDaemonServeRefusal::from(
                                GitDaemonTransportRefusal::ReceivePackFraming(e),
                            )
                        })?;
                    if matches!(&state, ScanStatus::Finished { .. })
                        && !scanner.excess_bytes().is_empty()
                    {
                        return Err(NodeSmartHttpRefusal::TrailingRequestBytes {
                            count: scanner.excess_bytes().len(),
                        });
                    }
                    machine.push_bytes(&chunk[..count])?;
                    input_bytes = input_bytes
                        .checked_add(count as u64)
                        .ok_or_else(|| invalid("receive size overflow"))?;
                    if matches!(&state, ScanStatus::Finished { .. }) {
                        break;
                    }
                }
            }
            // Client upload time cannot consume the independent server-work
            // allowance. The advertisement never supplies a validation witness.
            let processing = crate::GitDaemonReceiveProcessingDeadline::new(
                self.git_daemon_receive_processing_timeout,
            );
            let mut live = || {
                let alive = !processing.expired();
                if !alive {
                    processing_expired.set(true);
                }
                alive
            };
            // Structural pack inflate/checksum work owns only this request's
            // bounded quarantine and can run alongside other writers. Select
            // the authoritative validation basis only after writer admission.
            let quarantine = machine.into_quarantine(&mut live)?;
            // Verified objects are staged and synced, and published only when
            // admission commits; a receive that ends otherwise abandons them
            // (frankengit-tz5z). Declared first so it outlives every user.
            let staging = crate::receive_staging::ReceiveStaging::default();
            // A receive that must wait for another writer stages its verified
            // objects meanwhile; the handoff below still decides alone
            // (frankengit-root-doctrine-x2mv.4.9).
            let writer_permit =
                crate::admit_writer_prestaging(writers, processing.deadline(), || {
                    let prestage = NodeRequestContext {
                        authority: self.receive_admission_authority_context(
                            input_bytes,
                            processing.deadline(),
                        ),
                    };
                    super::super::prestage_receive(
                        self,
                        &prestage,
                        &quarantine,
                        receive_limits.pack.clone(),
                        &staging,
                        &mut live,
                    );
                })?;
            let request = NodeRequestContext {
                authority: self
                    .receive_admission_authority_context(input_bytes, processing.deadline()),
            };
            let selected = drive_request_while(
                self,
                &request,
                self.materialize_admission_in(&request),
                &mut live,
            )
            .map_err(NodeAdmissionViewRefusal::from)?;
            let validator = self
                .production_quarantine_validator(
                    &selected,
                    receive_limits.pack.clone(),
                    ParseLimits {
                        tree_reference_bytes: self.object_format.digest_len(),
                        ..ParseLimits::default()
                    },
                )
                .map_err(ReceiveError::AuthoritativeRefusal)?
                .with_receive_staging(&staging);
            let mut handoff =
                ProductionReceiveQuarantineHandoff::new(validator, selected.basis().clone());
            let completion = match quarantine.handoff(&mut handoff, &mut live) {
                Err(ReceiveError::AuthoritativeRefusal(code)) => {
                    // The verdict needs no further authority writes. Raw TCP
                    // and SSH must not reserve writer capacity during delivery.
                    drop(writer_permit);
                    // A verdict on the received commands is reported to the
                    // client per ref; the refusal itself is still returned, so
                    // the session counts as refused and nothing is admitted.
                    verdict_reported = write_command_verdict(
                        writer,
                        &ready,
                        code,
                        &receive_limits,
                        self.git_daemon_session_timeout,
                    )?;
                    return Err(ReceiveError::AuthoritativeRefusal(code).into());
                }
                completion => completion?,
            };
            let validated = handoff.into_validated_receive()?;
            admission_started = true;
            let outcome = admit(&request, &session, &validated, Some(&staging), &mut live)?;
            // Publication and outcome resolution are complete. A stalled
            // receiver may delay its own response, never another writer.
            drop(writer_permit);
            // A late deadline or socket failure cannot erase canonical knowledge.
            final_attempted = true;
            writer.restart_deadline(GitDaemonSessionDeadline::new(
                self.git_daemon_session_timeout,
                GitDaemonSessionWorkScaling::FLAT,
            ));
            let delivered: Result<(), NodeSmartHttpRefusal> = (|| {
                let packets = outcome.report_packets(&completion.request, &receive_limits)?;
                let bytes = encode_packets(&packets, &receive_limits.wire)?;
                writer
                    .write_all(&bytes)
                    .map_err(|e| io_error("write guarded receive report", e))?;
                writer
                    .flush()
                    .map_err(|e| io_error("flush guarded receive report", e))
            })();
            match delivered {
                Ok(()) => Ok(Some(outcome)),
                Err(source) => Err(NodeSmartHttpRefusal::ReceiveResponse {
                    outcome: Box::new(outcome),
                    source: Box::new(source),
                }),
            }
        })();
        if result.is_err() && !final_attempted && !verdict_reported {
            writer.restart_deadline(GitDaemonSessionDeadline::new(
                self.git_daemon_session_timeout,
                GitDaemonSessionWorkScaling::FLAT,
            ));
            // Keep the exact admission error/prefix even if this best-effort
            // diagnostic is also lost. Never replace it with a transport verdict.
            let command_bound = result
                .as_ref()
                .err()
                .and_then(command_limit::before_admission);
            let cause = result
                .as_ref()
                .err()
                .and_then(crate::receive_refusal::client_cause);
            if let Err(error) = fatal(
                writer,
                admission_started,
                processing_expired.get(),
                command_bound,
                cause.as_deref(),
                limits,
            ) {
                eprintln!("guarded receive fatal response delivery failed: {error}");
            }
        }
        result
    }

    /// The production admission step every guarded receive transport uses.
    pub(crate) fn admit_guarded_receive(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        validated: &BasisBoundValidatedReceive,
        staging: Option<&crate::receive_staging::ReceiveStaging>,
        live: &mut dyn FnMut() -> bool,
    ) -> Result<AdmissionResult, NodeSmartHttpRefusal> {
        let mut checkpoint = || live();
        drive_request_while(
            self,
            request,
            self.admit_receive_session_publishing_in(
                request,
                session,
                validated,
                AdmissionLimits::default(),
                staging,
            ),
            &mut checkpoint,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_command_parser_reports_its_limit_without_inventing_ref_outcomes() {
        use fgit_wire::receive::{ReceiveContext, ReceiveLimits, SignedPushProfile};
        use fgit_wire::{Capabilities, GitObjectFormat};
        let limit = fgit_admission::MAX_ADMISSION_COMMANDS;
        let receive_limits = ReceiveLimits {
            max_commands: limit,
            ..ReceiveLimits::default()
        };
        let capabilities =
            Capabilities::parse_v1(b"report-status delete-refs", &receive_limits.wire).unwrap();
        let context = ReceiveContext::new(
            GitObjectFormat::Sha1,
            capabilities,
            receive_limits,
            SignedPushProfile::Refuse,
        )
        .unwrap();
        let mut permitted = ReceivePack::new(context.clone()).unwrap();
        let mut exceeded = ReceivePack::new(context).unwrap();
        let zero = "0".repeat(40);
        for index in 0..limit {
            let capabilities = if index == 0 {
                "\0report-status delete-refs"
            } else {
                ""
            };
            let packet = Packet::Data(
                format!("{zero} {zero} refs/tags/ref-{index}{capabilities}").into_bytes(),
            );
            permitted.push_packet(packet.clone()).unwrap();
            exceeded.push_packet(packet).unwrap();
        }
        assert!(
            permitted
                .push_packet(Packet::Flush)
                .unwrap()
                .events
                .iter()
                .any(|event| matches!(event, ReceiveEvent::RequestReady(_)))
        );
        let error = exceeded
            .push_packet(Packet::Data(
                format!("{zero} {zero} refs/tags/one-too-many").into_bytes(),
            ))
            .unwrap_err();
        let refusal = NodeSmartHttpRefusal::from(error);
        assert_eq!(command_limit::before_admission(&refusal), Some(limit));
        let mut reply = Vec::new();
        fatal(
            &mut reply,
            false,
            false,
            command_limit::before_admission(&refusal),
            None,
            &WireLimits::default(),
        )
        .unwrap();
        let payload = std::str::from_utf8(&reply[4..]).unwrap();
        assert!(payload.starts_with("ERR receive command count exceeded:"));
        assert!(payload.contains(&format!("observed at least {}; maximum {limit}", limit + 1)));
        assert!(payload.contains("this invocation stopped before admission"));
        assert!(payload.contains(&format!(
            "split the push into batches of at most {limit} commands"
        )));
        // Even an accidentally supplied parser diagnostic cannot turn an
        // already-started admission into a non-commit claim.
        let mut unknown = Vec::new();
        fatal(
            &mut unknown,
            true,
            false,
            Some(limit),
            None,
            &WireLimits::default(),
        )
        .unwrap();
        assert!(unknown[4..].starts_with(b"ERR receive outcome unknown"));
    }

    #[test]
    fn late_quarantine_verdict_uses_a_fresh_bounded_response_clock() {
        use fgit_types::RefusalCode;
        use fgit_wire::receive::{ReceiveCommand, ReceiveLimits, ReceiveRequest};

        for format in [
            fgit_types::GitHashAlgorithm::Sha1,
            fgit_types::GitHashAlgorithm::Sha256,
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (mut server, _) = listener.accept().unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let timeout = crate::GitDaemonSessionTimeout::try_new(Duration::from_secs(5)).unwrap();
            let mut ingress =
                GitDaemonSessionDeadline::new(timeout, GitDaemonSessionWorkScaling::FLAT);
            // Model time spent processing after a completed upload without a
            // wall-clock race. Only the real socket's response phase is tested.
            ingress.started -= Duration::from_secs(10);
            let mut writer = DeadlineTcpStream::new(&mut server, ingress.clone());
            assert!(writer.write_all(b"expired").is_err());
            let limits = ReceiveLimits::default();
            let request = ReceiveRequest {
                commands: vec![ReceiveCommand {
                    old: fgit_wire::AnyGitOid::from_hex(
                        format,
                        &"0".repeat(format.digest_len() * 2),
                    )
                    .unwrap(),
                    new: fgit_crypto::git_object_id(format, fgit_crypto::GitObjectKind::Blob, b"x"),
                    ref_name: b"refs/tags/late-verdict".to_vec(),
                }],
                capabilities: vec![
                    fgit_wire::Capability::parse(b"report-status", &limits.wire).unwrap(),
                ],
                push_options: Vec::new(),
                certificate: None,
            };
            // The near-identical interruption is still UNKNOWN, never an ng
            // verdict or a response budget granted by this verdict-only path.
            assert!(
                !write_command_verdict(
                    &mut writer,
                    &request,
                    RefusalCode::CancellationInProgress,
                    &limits,
                    timeout
                )
                .unwrap()
            );
            assert!(writer.deadline.expired());
            assert!(
                write_command_verdict(
                    &mut writer,
                    &request,
                    RefusalCode::ObjectClosureIncomplete,
                    &limits,
                    timeout
                )
                .unwrap()
            );
            let mut received = Vec::new();
            // Decode pkt-lines rather than comparing a derived encoding.
            let mut payloads = Vec::new();
            loop {
                let mut header = [0; 4];
                client.read_exact(&mut header).unwrap();
                let size =
                    usize::from_str_radix(std::str::from_utf8(&header).unwrap(), 16).unwrap();
                if size == 0 {
                    break;
                }
                assert!((4..=65_520).contains(&size));
                received.resize(size - 4, 0);
                client.read_exact(&mut received).unwrap();
                payloads.push(received.clone());
            }
            assert_eq!(payloads, vec![b"unpack ok\n".to_vec(), b"ng refs/tags/late-verdict missing necessary objects (ObjectClosureIncomplete)\n".to_vec()]);
            assert!(ingress.expired(), "a response never reopens upload");
            assert!(writer.deadline.remaining().unwrap() <= Duration::from_secs(5));
            writer.deadline.note_admitted(usize::MAX / 2);
            assert_eq!(writer.deadline.budget(), Duration::from_secs(5));
            writer.deadline.started -= Duration::from_secs(10);
            assert_eq!(
                writer.write_all(b"late").unwrap_err().kind(),
                io::ErrorKind::TimedOut
            );
        }
    }
    #[test]
    fn fatal_interruption_never_fabricates_per_ref_rejection() {
        let mut bytes = Vec::new();
        fatal(&mut bytes, true, false, None, None, &WireLimits::default()).unwrap();
        assert!(
            bytes
                .windows(b"ERR receive outcome unknown".len())
                .any(|w| w == b"ERR receive outcome unknown")
        );
        assert!(!bytes.windows(3).any(|w| w == b"ng "));
        let mut before = Vec::new();
        fatal(
            &mut before,
            false,
            false,
            None,
            None,
            &WireLimits::default(),
        )
        .unwrap();
        assert_ne!(bytes, before);
        // A processing-deadline cause is named, with the same outcome class:
        // still UNKNOWN after admission started, still no decision before it.
        let mut unknown = Vec::new();
        fatal(&mut unknown, true, true, None, None, &WireLimits::default()).unwrap();
        let mut early = Vec::new();
        fatal(&mut early, false, true, None, None, &WireLimits::default()).unwrap();
        for (payload, class) in [
            (&unknown, b"ERR receive outcome unknown".as_slice()),
            (&early, b"ERR receive failed before admission".as_slice()),
        ] {
            assert!(payload.windows(class.len()).any(|w| w == class));
            let flag = b"fg serve --processing-timeout-secs";
            assert!(payload.windows(flag.len()).any(|w| w == flag));
            // One ERR packet, never a per-ref `ng` report line (the words
            // "processing" and "during" contain those bytes, so match the
            // packet start rather than a substring).
            assert!(payload[4..].starts_with(b"ERR "));
            assert!(!payload[4..].starts_with(b"ng "));
        }
    }
    #[test]
    fn command_limit_diagnostic_never_reclassifies_started_admission() {
        let mut early = Vec::new();
        fatal(
            &mut early,
            false,
            false,
            Some(2),
            None,
            &WireLimits::default(),
        )
        .unwrap();
        assert!(
            early[4..].starts_with(
                b"ERR receive command count exceeded: observed at least 3; maximum 2;"
            )
        );
        assert!(
            String::from_utf8_lossy(&early)
                .contains("split the push into batches of at most 2 commands")
        );

        let mut started = Vec::new();
        fatal(
            &mut started,
            true,
            false,
            Some(2),
            None,
            &WireLimits::default(),
        )
        .unwrap();
        assert!(started[4..].starts_with(b"ERR receive outcome unknown"));
        assert!(!String::from_utf8_lossy(&started).contains("no ref decision"));
    }
    #[test]
    fn a_client_safe_cause_is_named_only_before_admission_starts() {
        let cause = "push carries more than 256 push options";
        let write = |started: bool, expired: bool, bound: Option<usize>, cause: Option<&str>| {
            let mut bytes = Vec::new();
            fatal(
                &mut bytes,
                started,
                expired,
                bound,
                cause,
                &WireLimits::default(),
            )
            .unwrap();
            bytes
        };
        let expected = format!("ERR {cause}; no ref decision was attempted\n").into_bytes();
        assert_eq!(
            &write(false, false, None, Some(cause))[4..],
            expected.as_slice()
        );
        // Once admission started the outcome is unknown: the same cause must
        // not turn into a claim that nothing was decided.
        assert_eq!(
            write(true, false, None, Some(cause)),
            write(true, false, None, None)
        );
        // The processing deadline keeps its own named text.
        assert_eq!(
            write(false, true, None, Some(cause)),
            write(false, true, None, None)
        );
        // The command-count refusal keeps its operator text (command_limit).
        assert_eq!(
            write(false, false, Some(2), Some(cause)),
            write(false, false, Some(2), None)
        );
    }
    #[test]
    fn raw_retry_selector_preserves_legacy_bytes_and_excludes_pack_representation() {
        let route = b"/repository.git";
        let commands = b"0000";
        let mut preimage = b"frankengit.git-daemon.receive-idempotency/v1\0".to_vec();
        preimage.extend_from_slice(route);
        preimage.push(0);
        preimage.extend_from_slice(commands);
        assert_eq!(
            retry_key(route, commands).unwrap().as_bytes(),
            fgit_crypto::sha256_digest(&preimage)
        );
        assert_ne!(
            retry_key(route, commands).unwrap(),
            retry_key(b"/other.git", commands).unwrap()
        );
        assert_ne!(
            retry_key(route, commands).unwrap(),
            retry_key(route, b"0001").unwrap()
        );
    }
}

#[cfg(test)]
mod fault_tests;
