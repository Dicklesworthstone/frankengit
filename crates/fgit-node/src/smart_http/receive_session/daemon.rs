//! Raw Git compatibility over the guarded production receive coordinator.
//! Upload negotiation remains on its existing implementation. No HTTP envelope,
//! alternate ref database, or transport-local publication rule is introduced.

mod supervisor;

use std::io::{self, Cursor, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::{Duration, Instant};

use fgit_admission::{AdmissionLimits, AdmissionResult, BasisBoundValidatedReceive};
use fgit_authority::IdempotencyKey;
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_git_object::ParseLimits;
use fgit_pack::{PackBoundaryScanner, ScanStatus};
use fgit_types::cell::admits_staging_intake;
use fgit_wire::receive::{ReceiveError, ReceiveEvent, ReceivePack, advertise_receive_pack};
use fgit_wire::{Packet, WireLimits, encode_packets};

use super::super::{NodeSmartHttpRefusal, drive_request_while};
use crate::{
    AdmissionReceivePackAdvertisement, DeadlineTcpStream, GitDaemonService,
    GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, GitDaemonTransportRefusal,
    LoopbackReceiveSession, NodeAdmissionViewRefusal, NodeGitDaemonServeRefusal,
    NodeReceiveTransportRefusal, NodeRequestContext, OneNode, ProductionReceiveQuarantineHandoff,
    read_git_daemon_request, read_receive_frame,
};

const COMMAND_BYTES: usize = 4 * 1024 * 1024;
const CHUNK: usize = 16 * 1024;

fn io_error(operation: &'static str, source: io::Error) -> NodeSmartHttpRefusal {
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
        let mut bytes = [0_u8; 65_520];
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

fn fatal(writer: &mut impl Write, admission_started: bool, limits: &WireLimits) -> io::Result<()> {
    let message = if admission_started {
        b"ERR receive outcome unknown; retry identical commands or recover the original key\n"
            .as_slice()
    } else {
        b"ERR receive failed before admission; no ref decision was attempted\n".as_slice()
    };
    let bytes = encode_packets(&[Packet::Data(message.to_vec())], limits)
        .map_err(|e| io::Error::other(e.to_string()))?;
    writer.write_all(&bytes)?;
    writer.flush()
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
        self.serve_guarded_git_daemon_stream_in(stream, ingress, None)
    }

    fn serve_guarded_git_daemon_stream_in(
        &self,
        stream: TcpStream,
        ingress: GitDaemonSessionDeadline,
        shared_quota: Option<&crate::PushQuota>,
    ) -> Result<Option<AdmissionResult>, NodeSmartHttpRefusal> {
        self.serve_guarded_git_daemon_stream_with_admission(
            stream,
            ingress,
            shared_quota,
            |request, session, validated, live| {
                let mut checkpoint = || live();
                drive_request_while(
                    self,
                    request,
                    self.admit_receive_session_durable_in(
                        request,
                        session,
                        validated,
                        AdmissionLimits::default(),
                    ),
                    &mut checkpoint,
                )
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
        admit: F,
    ) -> Result<Option<AdmissionResult>, NodeSmartHttpRefusal>
    where
        F: FnOnce(
            &NodeRequestContext,
            &LoopbackReceiveSession,
            &BasisBoundValidatedReceive,
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
        let mut admission_started = false;
        let mut final_attempted = false;
        let result = (|| {
            let principal = self
                .git_daemon_receive_principal
                .ok_or(NodeSmartHttpRefusal::UnauthenticatedReceive)?;
            shared_quota
                .unwrap_or(&self.push_quota)
                .evaluate(&principal)?;
            admits_staging_intake(self.cell_state())
                .map_err(NodeReceiveTransportRefusal::CellState)?;
            let greeting = read_git_daemon_request(&mut reader, &limits)
                .map_err(NodeGitDaemonServeRefusal::from)?;
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
                &limits,
            )
            .map_err(NodeAdmissionViewRefusal::from)?;
            let advertised = advertise_receive_pack(refs.advertised_refs().to_vec(), &context)?;
            let bytes = encode_packets(&advertised, &limits)?;
            writer
                .write_all(&bytes)
                .map_err(|e| io_error("write receive advertisement", e))?;
            writer
                .flush()
                .map_err(|e| io_error("flush receive advertisement", e))?;
            drop(selected);
            let mut machine = ReceivePack::new(context)?;
            let mut prefix = Vec::new();
            let ready = 'commands: loop {
                checkpoint(&ingress)?;
                let (raw, packet) = read_receive_frame(&mut reader, &limits)
                    .map_err(NodeGitDaemonServeRefusal::from)?;
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
            let session = LoopbackReceiveSession::authenticated(
                principal,
                retry_key(greeting.repository_path().as_bytes(), &prefix)?,
            );
            let mut input_bytes = prefix.len() as u64;
            drop(prefix);
            if ready.requires_pack() {
                let mut scanner =
                    PackBoundaryScanner::new(self.object_format, receive_limits.pack.clone());
                let mut chunk = [0_u8; CHUNK];
                loop {
                    checkpoint(&ingress)?;
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
            let work = GitDaemonSessionDeadline::new(
                self.git_daemon_session_timeout,
                self.git_daemon_session_work_scaling,
            );
            let processing = crate::GitDaemonReceiveProcessingDeadline::new(
                self.git_daemon_receive_processing_timeout,
            );
            let request = NodeRequestContext {
                authority: self.receive_admission_authority_context(input_bytes, &work),
            };
            let mut live = || !work.expired() && !processing.expired();
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
                .map_err(ReceiveError::AuthoritativeRefusal)?;
            let mut handoff =
                ProductionReceiveQuarantineHandoff::new(validator, selected.basis().clone());
            let completion = machine.finish_with_handoff(&mut handoff, &mut live)?;
            let validated = handoff.into_validated_receive()?;
            drop(machine);
            admission_started = true;
            let outcome = admit(&request, &session, &validated, &mut live)?;
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
        if result.is_err() && !final_attempted {
            writer.restart_deadline(GitDaemonSessionDeadline::new(
                self.git_daemon_session_timeout,
                GitDaemonSessionWorkScaling::FLAT,
            ));
            // Keep the exact admission error/prefix even if this best-effort
            // diagnostic is also lost. Never replace it with a transport verdict.
            if let Err(error) = fatal(&mut writer, admission_started, &limits) {
                eprintln!("guarded receive fatal response delivery failed: {error}");
            }
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fatal_interruption_never_fabricates_per_ref_rejection() {
        let mut bytes = Vec::new();
        fatal(&mut bytes, true, &WireLimits::default()).unwrap();
        assert!(
            bytes
                .windows(b"ERR receive outcome unknown".len())
                .any(|w| w == b"ERR receive outcome unknown")
        );
        assert!(!bytes.windows(3).any(|w| w == b"ng "));
        let mut before = Vec::new();
        fatal(&mut before, false, &WireLimits::default()).unwrap();
        assert_ne!(bytes, before);
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
