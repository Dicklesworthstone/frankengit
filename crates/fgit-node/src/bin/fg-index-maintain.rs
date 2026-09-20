#![forbid(unsafe_code)]
//! Bounded foreground maintenance over one existing node. No subprocess,
//! second async runtime, remote index-write grant, or query-side mutation.
#[path = "index_maintenance/state.rs"]
mod state;
use state::{Pin as IndexPin, ProgressFile, State, decimal, hex, unhex};
use std::ffi::OsString;
use std::future::{Future, poll_fn};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::process::ExitCode;
use std::task::Poll;
use std::time::Duration;
use fgit_crypto::{IdentityDomain, internal_algorithm_id, internal_domain_tag};
use fgit_graph::{GenerationActivation, GenerationAuthorityError, GenerationRecovery, GraphGenerationId};
use fgit_graph::lexical::IndexError;
use fgit_node::{NodeConfig, NodeRequestContext, NodeWorkspaceRefusal, OneNode};
use fgit_types::{CANONICAL_CODEC_VERSION, DigestBytes, GitHashAlgorithm, HeadGeneration,
    InternalObjectId, RefName, RepositoryId, TenantId};

const USAGE: &str = "fg-index-maintain ROOT TENANT_HEX REPOSITORY_HEX sha1|sha256 PRIVATE_STATE_DIR init|resume PASSES INTERVAL_SECONDS FULL_REF [FULL_REF ...]\nExplicit scope: 1-32 refs, 1-3600 passes, up to 24 hours of scheduled waits.\nCreate PRIVATE_STATE_DIR with mode 0700. Create its stop file to request drain.\nResume never resets missing progress, takes over a stale lock, or forgets an unresolved attempt.";
const TICK: Duration = Duration::from_millis(250);
struct Options {
    root: PathBuf, tenant: TenantId, repository: RepositoryId, format: GitHashAlgorithm,
    directory: PathBuf, initialize: bool, passes: u64, interval: Duration, refs: Vec<RefName>,
}
fn invalid(message: impl Into<String>) -> io::Error { io::Error::new(io::ErrorKind::InvalidInput, message.into()) }
fn parse(args: &[OsString]) -> io::Result<Options> {
    if args.len() < 9 || args.len() > 8 + state::MAX_REFS || args.iter().any(|a| a.len() > 4096) { return Err(invalid(USAGE)); }
    let text = |n: usize| args[n].to_str().ok_or_else(|| invalid("Only filesystem paths may contain non-UTF-8 bytes."));
    let id = |n| -> io::Result<[u8; 16]> { unhex(text(n)?, 16)?.try_into().map_err(|_| invalid("Identity must be 16 bytes.")) };
    let tenant = TenantId::from_bytes(id(1)?); let repository = RepositoryId::from_bytes(id(2)?);
    let format = match text(3)? { "sha1" => GitHashAlgorithm::Sha1, "sha256" => GitHashAlgorithm::Sha256, _ => return Err(invalid(USAGE)) };
    let initialize = match text(5)? { "init" => true, "resume" => false, _ => return Err(invalid(USAGE)) };
    let passes = decimal(text(6)?, 3600)?; let seconds = decimal(text(7)?, 3600)?;
    if passes == 0 || (passes > 1 && seconds == 0) || passes.saturating_sub(1) * seconds > 86_400 { return Err(invalid(USAGE)); }
    let mut refs = (8..args.len()).map(|n| RefName::try_new(text(n)?.as_bytes()).map_err(|_| invalid("Invalid full ref.")))
        .collect::<io::Result<Vec<_>>>()?;
    refs.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    if refs.windows(2).any(|pair| pair[0] == pair[1]) || refs.iter().any(|r| r.as_bytes().len() > 1024 || !r.as_bytes().starts_with(b"refs/"))
        || refs.iter().map(|r| r.as_bytes().len()).sum::<usize>() > 16 * 1024 { return Err(invalid("Invalid or duplicate reference scope.")); }
    Ok(Options { root: PathBuf::from(&args[0]), tenant, repository, format,
        directory: PathBuf::from(&args[4]), initialize, passes, interval: Duration::from_secs(seconds), refs })
}
fn generation(digest: [u8; 32]) -> io::Result<GraphGenerationId> {
    GraphGenerationId::from_internal_object_id(InternalObjectId::new(internal_algorithm_id(IdentityDomain::Generation),
        internal_domain_tag(IdentityDomain::Generation), CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&digest).map_err(|e| invalid(e.to_string()))?)).map_err(|e| invalid(e.to_string()))
}
fn activation(value: &IndexPin) -> io::Result<GenerationActivation> {
    Ok(GenerationActivation { generation_id: generation(value.digest)?,
        authority_generation: HeadGeneration::try_new(value.number).map_err(|e| invalid(e.to_string()))? })
}
fn checkpoint(value: &GenerationActivation) -> io::Result<IndexPin> {
    let id = value.generation_id.as_internal_object_id();
    if id.algorithm().code_point() != 2 || id.codec_version() != CANONICAL_CODEC_VERSION { return Err(invalid("Unsupported progress identity profile.")); }
    Ok(IndexPin { digest: id.digest().as_bytes().try_into().map_err(|_| invalid("Unsupported generation width."))?,
        number: value.authority_generation.get() })
}
fn token(id: &InternalObjectId) -> String { format!("alg:{}:{}", id.algorithm().code_point(), hex(id.digest().as_bytes())) }
#[derive(Default)]
struct Stop { requested: bool, error: Option<String> }
impl Stop {
    fn observe(&mut self, directory: &Path) {
        if self.requested { return; }
        match std::fs::symlink_metadata(directory.join("stop")) {
            Ok(_) => self.requested = true, // Contents and symlink targets are never read.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {},
            Err(e) => { self.requested = true; self.error = Some(e.to_string()); }
        }
    }
}
/// Cancellation requests do not drop the native future. Keep polling it until
/// the owning node returns; a confirmed result always wins over a later stop.
fn drive<F: Future>(node: &OneNode, request: &NodeRequestContext, directory: &Path,
    future: F, stop: &mut Stop,
) -> F::Output {
    let mut future = pin!(future);
    let mut tick = pin!(asupersync::time::sleep(node.runtime().now(), TICK));
    stop.observe(directory); if stop.requested { request.cancel(); }
    node.runtime().block_on(poll_fn(|cx| {
        if let Poll::Ready(result) = future.as_mut().poll(cx) { return Poll::Ready(result); }
        if tick.as_mut().poll(cx).is_ready() {
            stop.observe(directory); if stop.requested { request.cancel(); }
            tick.set(asupersync::time::sleep(node.runtime().now(), TICK));
            let _ = tick.as_mut().poll(cx); // Register the replacement timer's wake.
        }
        Poll::Pending
    }))
}
fn wait(node: &OneNode, directory: &Path, mut remaining: Duration, stop: &mut Stop) {
    while !remaining.is_zero() && !stop.requested {
        let step = remaining.min(TICK); node.runtime().wait_for(step);
        remaining = remaining.saturating_sub(step); stop.observe(directory);
    }
}
fn emit(reference: &RefName, status: &str, fields: &str) -> io::Result<()> {
    writeln!(io::stdout().lock(), "{{\"type\":\"index_maintenance\",\"ref_hex\":\"{}\",\"state\":\"{status}\",\"repository_transaction_created\":false{fields}}}", hex(reference.as_bytes()))
}
fn pin_fields(value: &IndexPin) -> String { format!(",\"index_token\":\"alg:2:{}\",\"index_number\":{}", hex(&value.digest), value.number) }
fn definite_race(error: &IndexError) -> bool {
    matches!(error, IndexError::Generation(GenerationAuthorityError::PredecessorMismatch { .. }
        | GenerationAuthorityError::ConcurrentActivation | GenerationAuthorityError::HeadAlreadyInitialized))
}
fn run(node: &OneNode, options: &Options, progress: &mut ProgressFile) -> io::Result<bool> {
    let mut stop = Stop::default(); let mut healthy = true;
    'passes: for pass in 0..options.passes {
        for reference in &options.refs {
            stop.observe(&options.directory); if stop.requested { break 'passes; }
            let row = progress.state.rows.get(reference.as_bytes()).ok_or_else(|| invalid("Missing progress row."))?.clone();
            if row.running { return Err(invalid("An interrupted attempt has no recorded candidate. Inspect it before resuming; do not reset the checkpoint.")); }
            let floor = row.floor.as_ref().map(activation).transpose()?;
            // One finite background-controller budget per independent attempt.
            // Never replace the context of an in-flight or draining attempt.
            let request = node.outbox_delivery_context();
            if let Some(candidate) = row.pending {
                let result = drive(node, &request, &options.directory,
                    node.recover_source_index_local_in(&request, reference, generation(candidate)?, floor.as_ref(), Default::default()), &mut stop);
                match result {
                    Ok(GenerationRecovery::Active { selected }) | Ok(GenerationRecovery::Superseded { selected, .. }) => {
                        let pin = checkpoint(selected.activation())?;
                        progress.state.acknowledge(reference.as_bytes(), pin.clone(), Some(candidate))?;
                        progress.save()?; emit(reference, "recovered", &pin_fields(&pin))?;
                    }
                    Ok(GenerationRecovery::Uninitialized | GenerationRecovery::NotInSelectedHistory { .. }) => {
                        // Negative selected-history evidence is NOT cancellation
                        // of an earlier write. Keep responsibility and do no build.
                        healthy = false;
                        emit(reference, "pending", &format!(",\"candidate_token\":\"alg:2:{}\"", hex(&candidate)))?;
                    }
                    Err(error) => { healthy = false; emit(reference, "recovery_unavailable", "")?; eprintln!("Index recovery: {error}"); }
                }
                continue; // Recovery and a new build are separate invocations.
            }
            // Persist responsibility before any native maintenance effect.
            progress.state.begin(reference.as_bytes())?; progress.save()?;
            let result = drive(node, &request, &options.directory,
                node.reconcile_source_index_local_in(&request, reference, None, floor.as_ref(), Default::default(), Default::default()), &mut stop);
            match result {
                Ok((source, activation)) => {
                    let pin = checkpoint(&activation)?;
                    progress.state.acknowledge(reference.as_bytes(), pin.clone(), None)?;
                    progress.save()?; // Durably retain the floor BEFORE acknowledging it.
                    emit(reference, "observed_current", &format!("{},\"snapshot_token\":\"{}\",\"source_commit\":\"{}\"",
                        pin_fields(&pin), token(source.source_head.as_internal_object_id()), source.commit))?;
                }
                Err(NodeWorkspaceRefusal::SourceIndexPublication { candidate, error }) if !definite_race(&error) => {
                    let candidate: [u8; 32] = candidate.as_internal_object_id().digest().as_bytes().try_into()
                        .map_err(|_| invalid("Unsupported candidate width; attempt remains recorded."))?;
                    progress.state.uncertain(reference.as_bytes(), candidate)?; progress.save()?;
                    healthy = false;
                    emit(reference, "pending", &format!(",\"candidate_token\":\"alg:2:{}\"", hex(&candidate)))?;
                    eprintln!("Publication not confirmed; pending candidate retained: {error}");
                }
                Err(error) => {
                    // Non-publication errors precede root publication; the three
                    // explicitly classified races are known failed preconditions.
                    progress.state.refuse(reference.as_bytes())?; progress.save()?;
                    healthy = false; emit(reference, "refused", "")?; eprintln!("Index maintenance: {error}");
                }
            }
        }
        if pass + 1 < options.passes { wait(node, &options.directory, options.interval, &mut stop); }
    }
    if let Some(error) = stop.error { return Err(invalid(format!("Stop control failed after drain: {error}"))); }
    Ok(healthy && progress.state.rows.values().all(|row| !row.running && row.pending.is_none()))
}
fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).take(8 + state::MAX_REFS + 1).collect();
    let options = match parse(&args) { Ok(value) => value, Err(e) => { eprintln!("{e}"); return ExitCode::FAILURE; } };
    if !cfg!(unix) || internal_algorithm_id(IdentityDomain::Generation).code_point() != 2
        || CANONICAL_CODEC_VERSION != fgit_types::CodecVersion::new(1, 0)
    { eprintln!("This progress profile requires Unix and SHA-256 generation codec v1."); return ExitCode::FAILURE; }
    let config = NodeConfig::new(options.root.clone(), options.tenant, options.repository).with_object_format(options.format).with_worker_threads(2);
    let mut node = match OneNode::open_existing(config) { Ok(node) => node, Err(e) => { eprintln!("Open failed: {e}"); return ExitCode::FAILURE; } };
    let ready = node.runtime().block_on(node.authenticate_authority_head()).map_err(|e| e.to_string())
        .and_then(|head| node.bring_into_service(head.receipt().generation()).map_err(|e| e.to_string()));
    if let Err(error) = ready {
        eprintln!("Authority unavailable: {error}");
        if let Err(error) = node.shutdown() { eprintln!("Shutdown also failed: {error}"); }
        return ExitCode::FAILURE;
    }
    let binding = format!("{} {} {} {}", options.tenant, options.repository, node.repository_incarnation_id(), options.format.as_str());
    let refs = options.refs.iter().map(|r| r.as_bytes().to_vec()).collect::<Vec<_>>();
    let progress = State::new(binding, &refs).and_then(|state| ProgressFile::open(&options.directory, options.initialize, state));
    let mut progress = match progress {
        Ok(value) => value,
        Err(error) => { eprintln!("Progress unavailable: {error}"); if let Err(error) = node.shutdown() { eprintln!("Shutdown also failed: {error}"); } return ExitCode::FAILURE; }
    };
    let result = run(&node, &options, &mut progress);
    let shutdown = node.shutdown(); // Explicit after success, refusal or stop; no live future is dropped.
    if let Err(error) = shutdown { eprintln!("Shutdown failed; run.lock retained: {error}. No rollback is implied."); return ExitCode::FAILURE; }
    match result {
        Ok(healthy) => {
            if let Err(error) = progress.release() { eprintln!("Progress release failed: {error}"); return ExitCode::FAILURE; }
            if healthy { ExitCode::SUCCESS } else { ExitCode::FAILURE }
        }
        Err(error) => { eprintln!("Maintenance stopped; run.lock retained for inspection: {error}. Confirmed activations are not undone."); ExitCode::FAILURE }
    }
}

#[cfg(test)]
#[path = "index_maintenance/worker_tests.rs"]
mod tests;
