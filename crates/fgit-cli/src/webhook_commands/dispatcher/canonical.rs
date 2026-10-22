//! Explicit trusted-local route intent, published before actual Weak HTTP I/O.
//! Registration files supply capabilities; the selected immutable canonical plan
//! owns completion. Journals retain only the process fence and legacy detection.
use super::*;
use fgit_authority::IdempotencyKey;
use fgit_crypto::{DigestAlgorithm, DigestBytes};
use fgit_node::LoopbackReceiveSession;
use fgit_node::webhook::{
    CanonicalDeliveryRequest, DeliveryVerdict, DispatchRoute, DispatchTransport, ObligationState,
    ProbeVerdict, ReconcileState,
};
use fgit_types::RefusalCode;

struct Route {
    options: Options,
    binding: [u8; 32],
    journal: Journal,
}
struct Transport<'a, S> {
    destination: AsciiSlug,
    definitions: Vec<DispatchRoute>,
    routes: Vec<&'a Route>,
    incarnation: RepositoryIncarnationId,
    counts: &'a mut BTreeMap<(u64, AsciiSlug), usize>,
    stopped: &'a S,
    error: Option<String>,
}
impl<C, S> DispatchTransport<C> for Transport<'_, S>
where
    C: Sync + ?Sized,
    S: Fn() -> Result<bool, String>,
{
    fn destination(&self) -> AsciiSlug {
        self.destination
    }
    fn routes(&self) -> &[DispatchRoute] {
        &self.definitions
    }
    fn can_deliver(&self, id: u64) -> bool {
        self.routes
            .iter()
            .find(|r| r.options.id.0 == id)
            .is_some_and(|r| {
                self.counts
                    .get(&(id, self.destination))
                    .copied()
                    .unwrap_or(0)
                    < r.options.max_deliveries
            })
    }
    async fn deliver<'a>(
        &'a mut self,
        _cx: &'a C,
        id: u64,
        request: &'a CanonicalDeliveryRequest<'_>,
        attempt: u32,
        checkpoint: &'a (dyn Fn() -> Result<(), RefusalCode> + Sync),
    ) -> Result<(DeliveryVerdict, Vec<u8>), RefusalCode> {
        let operation = || -> Result<(DeliveryVerdict, Vec<u8>), String> {
            let route = self
                .routes
                .iter()
                .find(|r| r.options.id.0 == id)
                .ok_or("route missing")?;
            let (store, registration) = registration(&route.options)?;
            if scope(&route.options, self.incarnation, &registration) != route.binding {
                return Err(
                    "canonical dispatch endpoint or policy changed; original plan retained".into(),
                );
            }
            require_subscription(&registration.filter, &request.events.events)?;
            let mut transport = WebhookDeliveryDestination::new(
                self.destination,
                registration,
                route.options.policy(),
                store.dead_letters(),
            );
            transport.timeout = route.options.timeout;
            let check = || {
                checkpoint()?;
                if (self.stopped)().map_err(|_| RefusalCode::CancellationInProgress)? {
                    return Err(RefusalCode::CancellationInProgress);
                }
                Ok(())
            };
            check().map_err(|e| format!("{e:?}"))?;
            // The already-selected canonical marker is the send reservation.
            // Never append a competing retry/acceptance authority to the journal.
            let (verdict, bytes) =
                transport.deliver_request_with_checkpoint(request, attempt, &check)?;
            let verdict = match verdict {
                "Accepted" => DeliveryVerdict::Accepted,
                "DuplicateSuppressed" => DeliveryVerdict::DuplicateSuppressed,
                "TransientFailure" => DeliveryVerdict::TransientFailure,
                "PermanentRejection" => DeliveryVerdict::PermanentRejection,
                "AmbiguousTimeout" => DeliveryVerdict::AmbiguousTimeout,
                _ => return Err("unknown HTTP observation".into()),
            };
            // Bind the actual bounded response without disclosing its body in
            // canonical history. Verdict is encoded separately by the profile.
            let evidence = format!(
                "frankengit/http-observation/v1:{}:{}",
                bytes.len(),
                hex(&sha256_digest(&bytes))
            )
            .into_bytes();
            Ok((verdict, evidence))
        };
        *self.counts.entry((id, self.destination)).or_default() += 1;
        match operation() {
            Ok(result) => Ok(result),
            Err(error) => {
                self.error = Some(error);
                Err(RefusalCode::PublicationPolicyRefused)
            }
        }
    }
    async fn probe<'a>(
        &'a mut self,
        _cx: &'a C,
        _id: u64,
        _request: &'a CanonicalDeliveryRequest<'_>,
        checkpoint: &'a (dyn Fn() -> Result<(), RefusalCode> + Sync),
    ) -> Result<(ProbeVerdict, Vec<u8>), RefusalCode> {
        checkpoint()?;
        // HTTP has no durable acknowledgement query. An old local observation,
        // absence of a reply, or a recovered marker cannot prove non-delivery.
        Ok((
            ProbeVerdict::Unknown,
            b"non-probing HTTP: recovered send outcome unknown".to_vec(),
        ))
    }
}

pub(super) fn execute(
    options: &[Options],
    total_limit: usize,
    stop_signal: &impl Fn() -> Result<bool, String>,
    clock: &impl Fn() -> Result<u64, String>,
    output: &mut impl Write,
) -> Result<u8, String> {
    let first = options
        .first()
        .ok_or("canonical dispatch requires routes")?;
    let principal = first
        .canonical_principal
        .ok_or("canonical dispatch requires --canonical-principal")?;
    if options.len() > 32
        || total_limit == 0
        || total_limit > 1000
        || options.iter().any(|r| {
            r.canonical_principal != Some(principal)
                || r.storage != first.storage
                || r.tenant != first.tenant
                || r.repository != first.repository
                || r.format != first.format
        })
    {
        return Err("canonical routes must share one explicit principal and repository".into());
    }
    let latched = Cell::new(false);
    let stopped = || {
        if latched.get() {
            return Ok(true);
        }
        match stop_signal() {
            Ok(false) => Ok(false),
            result => {
                latched.set(true);
                result
            }
        }
    };
    if stopped()? {
        emit(
            output,
            "{\"type\":\"webhook_dispatch_stopped\",\"schema_version\":1,\"stopped\":true,\"drained\":true,\"canonical_settled\":false}",
        )?;
        return Ok(1);
    }
    let incarnation = snapshot(first)?.incarnation;
    let mut routes = Vec::with_capacity(options.len());
    // Hold every stable route fence through HTTP drain, authority publication,
    // output and shutdown. A competing legacy worker uses these same fences.
    let mut ordered: Vec<_> = options.iter().collect();
    ordered.sort_by_key(|r| (r.id.0, r.destination));
    for route in ordered {
        let (_, registration) = registration(route)?;
        let binding = scope(route, incarnation, &registration);
        let journal = Journal::open(
            &journal_path(route),
            binding,
            registration.retry_schedule.max_attempts,
        )?;
        routes.push(Route {
            options: route.clone(),
            binding,
            journal,
        });
    }
    loop {
        let summary = with_node(first, |node| {
            if node.repository_incarnation_id() != incarnation {
                return Err("canonical dispatch incarnation changed".into());
            }
            let request = node.outbox_delivery_context();
            let page = node
                .runtime()
                .block_on(node.read_forge_outbox_snapshot_in(&request, first.max_scan, None))
                .map_err(|e| e.to_string())?;
            let mut summary = Summary::default();
            let mut counts = BTreeMap::new();
            for entry in page.entries {
                if stopped()? {
                    summary.stopped = true;
                    break;
                }
                if entry.effect_class() != AsciiSlug::from_static("forge-event") {
                    continue;
                }
                let configured: Vec<_> = routes
                    .iter()
                    .filter(|r| r.options.destination == entry.destination())
                    .collect();
                if configured.is_empty() {
                    continue;
                }
                summary.considered += 1;
                let key = entry.delivery_key();
                let selected = node
                    .runtime()
                    .block_on(node.select_forge_delivery_in(
                        &request,
                        key,
                        entry.destination(),
                        None,
                    ))
                    .map_err(|e| e.to_string())?;
                let previous = node
                    .runtime()
                    .block_on(node.read_forge_dispatch_in(&request, key, None))
                    .map_err(|e| e.to_string())?;
                if previous.is_none() && configured.iter().any(|r| r.journal.has_entry(key)) {
                    return Err("legacy journal observation has no canonical dispatch marker; explicit reconciliation required before claim".into());
                }
                if previous.is_none() && !selected.is_unclaimed() {
                    summary.claimed += 1;
                    continue;
                }
                let mut members = Vec::new();
                let mut definitions = Vec::new();
                for route in configured {
                    let (_, registration) = registration(&route.options)?;
                    if scope(&route.options, incarnation, &registration) != route.binding {
                        return Err("canonical dispatch route binding changed".into());
                    }
                    if require_subscription(
                        &registration.filter,
                        &selected.as_request().events.events,
                    )
                    .is_err()
                    {
                        if previous.is_some() {
                            return Err(
                                "subscription narrowing cannot remove an owed canonical route"
                                    .into(),
                            );
                        }
                        summary.filtered += 1;
                        continue;
                    }
                    let schedule = registration.retry_schedule;
                    definitions.push(DispatchRoute {
                        id: route.options.id.0,
                        binding: Digest::new(
                            DigestAlgorithm::Sha256.id(),
                            DigestBytes::try_new(&route.binding).map_err(|e| e.to_string())?,
                        ),
                        max_attempts: schedule.max_attempts,
                        initial_delay_millis: schedule.initial_delay.as_nanos().div_ceil(1_000_000)
                            as u64,
                        max_delay_millis: schedule.max_delay.as_nanos().div_ceil(1_000_000) as u64,
                    });
                    members.push(route);
                }
                if members.is_empty() {
                    continue;
                }
                let session = LoopbackReceiveSession::authenticated(
                    principal,
                    IdempotencyKey::new(format!("canonical-webhook/{}", key.as_str()).into_bytes())
                        .map_err(|e| e.to_string())?,
                );
                let mut transport = Transport {
                    destination: entry.destination(),
                    definitions,
                    routes: members,
                    incarnation,
                    counts: &mut counts,
                    stopped: &stopped,
                    error: None,
                };
                let result = node.runtime().block_on(node.dispatch_forge_outbox_in(
                    &request,
                    &session,
                    key,
                    &mut transport,
                    (total_limit - summary.attempts) as u32,
                    Default::default(),
                    &|| clock().map_err(|_| RefusalCode::ResourceBudgetExceeded),
                ));
                let result = result.map_err(|e| format!("canonical dispatch stopped with retained canonical progress: {e}; transport={:?}", transport.error))?;
                summary.attempts += result.sends as usize;
                for member in result.progress.routes() {
                    match member.state {
                        ReconcileState::Delivered { .. } => summary.accepted += 1,
                        ReconcileState::Undeliverable { .. } => summary.rejected += 1,
                        ReconcileState::Indeterminate { .. } => summary.unknown += 1,
                        _ => summary.pending += 1,
                    }
                }
                let settled = result.effect.as_ref().is_some_and(|e| {
                    matches!(
                        e.state(),
                        ObligationState::Acknowledged
                            | ObligationState::TerminallyFailed
                            | ObligationState::Escalated
                    )
                });
                emit(
                    output,
                    &format!(
                        "{{\"type\":\"webhook_dispatch_canonical\",\"schema_version\":1,\"delivery_id\":{},\"progress_root\":{},\"attempts\":{},\"canonical_settled\":{},\"active_retired\":{},\"node_closed\":false}}",
                        quote(key.as_str()),
                        quote(
                            &result
                                .progress
                                .root()
                                .map_err(|e| e.to_string())?
                                .to_string()
                        ),
                        result.sends,
                        settled,
                        result.effect.as_ref().is_some_and(|e| matches!(
                            e.state(),
                            ObligationState::Acknowledged | ObligationState::TerminallyFailed
                        ))
                    ),
                )?;
            }
            Ok(summary)
        })?;
        emit(
            output,
            &format!(
                "{{\"type\":\"webhook_dispatch_canonical_sweep\",\"schema_version\":1,\"attempts\":{},\"accepted_routes\":{},\"rejected_routes\":{},\"unknown_routes\":{},\"pending_routes\":{},\"claimed_elsewhere\":{},\"stopped\":{},\"drained\":true,\"node_closed\":true}}",
                summary.attempts,
                summary.accepted,
                summary.rejected,
                summary.unknown,
                summary.pending,
                summary.claimed,
                summary.stopped
            ),
        )?;
        if !first.continuous || summary.stopped {
            return Ok(summary.exit_code());
        }
        let until = std::time::Instant::now() + first.poll;
        while std::time::Instant::now() < until {
            if stopped()? {
                return Ok(1);
            }
            std::thread::sleep(
                until
                    .saturating_duration_since(std::time::Instant::now())
                    .min(Duration::from_millis(100)),
            );
        }
    }
}
