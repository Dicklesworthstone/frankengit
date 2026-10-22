//! One explicit replay request, one fresh canonical identity and one send budget.
use super::super::super::dispatcher;
use super::*;
use fgit_authority::IdempotencyKey;
use fgit_crypto::{DigestAlgorithm, DigestBytes};
use fgit_node::webhook::{
    CanonicalDeliveryRequest, DeliveryVerdict, DispatchRoute, DispatchTransport, ObligationState,
    ProbeVerdict, ReplayIntent,
};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{HeadGeneration, RefusalCode};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct Transport<'a, S> {
    destination: AsciiSlug,
    routes: Vec<DispatchRoute>,
    http: WebhookDeliveryDestination,
    error: Option<String>,
    stopped: &'a S,
}
impl<C: Sync + ?Sized, S: Fn() -> bool> DispatchTransport<C> for Transport<'_, S> {
    fn destination(&self) -> AsciiSlug {
        self.destination
    }
    fn routes(&self) -> &[DispatchRoute] {
        &self.routes
    }
    fn can_deliver(&self, _: u64) -> bool {
        !(self.stopped)()
    }
    async fn deliver<'a>(
        &'a mut self,
        _: &'a C,
        _: u64,
        request: &'a CanonicalDeliveryRequest<'_>,
        attempt: u32,
        checkpoint: &'a (dyn Fn() -> Result<(), RefusalCode> + Sync),
    ) -> Result<(DeliveryVerdict, Vec<u8>), RefusalCode> {
        let check = || {
            checkpoint()?;
            if (self.stopped)() {
                Err(RefusalCode::CancellationInProgress)
            } else {
                Ok(())
            }
        };
        let (verdict, body) = match self
            .http
            .deliver_request_with_checkpoint(request, attempt, &check)
        {
            Ok(v) => v,
            Err(e) => {
                self.error = Some(e);
                return Err(RefusalCode::PublicationPolicyRefused);
            }
        };
        let verdict = match verdict {
            "Accepted" => DeliveryVerdict::Accepted,
            "DuplicateSuppressed" => DeliveryVerdict::DuplicateSuppressed,
            "TransientFailure" => DeliveryVerdict::TransientFailure,
            "PermanentRejection" => DeliveryVerdict::PermanentRejection,
            "AmbiguousTimeout" => DeliveryVerdict::AmbiguousTimeout,
            _ => return Err(RefusalCode::EvidenceInvalid),
        };
        let evidence = format!(
            "frankengit/http-observation/v1:{}:{}",
            body.len(),
            fgit_crypto::lowercase_hex(&fgit_crypto::sha256_digest(&body))
        )
        .into_bytes();
        Ok((verdict, evidence))
    }
    async fn probe<'a>(
        &'a mut self,
        _: &'a C,
        _: u64,
        _: &'a CanonicalDeliveryRequest<'_>,
        checkpoint: &'a (dyn Fn() -> Result<(), RefusalCode> + Sync),
    ) -> Result<(ProbeVerdict, Vec<u8>), RefusalCode> {
        checkpoint()?;
        Ok((
            ProbeVerdict::Unknown,
            b"non-probing HTTP: replay send outcome unknown".to_vec(),
        ))
    }
}

pub(super) fn execute(
    options: &Options,
    replay: bool,
    stopped: &impl Fn() -> bool,
) -> Result<(u8, String), String> {
    if !replay || !options.at_least_once || options.attempt.is_some() {
        return Err("canonical replay is a new one-send intent; --at-least-once is required and --attempt is unsupported".into());
    }
    if stopped() {
        return Err("canonical replay stopped before admission".into());
    }
    let principal = options
        .canonical_principal
        .ok_or("missing canonical principal")?;
    let replay_key = options.replay_key.as_ref().ok_or("missing --replay-key")?;
    let source_key = options.key.ok_or("missing --delivery-id")?;
    let destination = options.destination.ok_or("missing --destination")?;
    let route = dispatcher::Options {
        storage: options.storage.clone(),
        tenant: options.tenant,
        repository: options.repository,
        format: options.format,
        id: WebhookId(options.webhook_id.ok_or("missing --id")?),
        destination,
        max_deliveries: 1,
        max_scan: 16384,
        timeout: Duration::from_secs(5),
        continuous: false,
        stop_file: None,
        poll: Duration::from_secs(1),
        permissive: options.permissive,
        canonical_principal: Some(principal),
    };
    // Strict SSRF/HTTPS and schedule checks precede any canonical replay write.
    let (store, registration) = dispatcher::registration(&route)?;
    let diagnostic = store.get_dead_letter_for(route.id, source_key);
    let mut node = OneNode::open_existing(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format),
    )
    .map_err(|e| e.to_string())?;
    let mut fence = None;
    let operation: Result<(u8, String), String> = (|| {
        node.bring_into_service(HeadGeneration::FIRST)
            .map_err(|e| e.to_string())?;
        fence = Some(dispatcher::acquire_replay_fence(
            &route,
            node.repository_incarnation_id(),
            &registration,
        )?);
        let request = node.outbox_delivery_context();
        let (source_head, source, events) = node
            .runtime()
            .block_on(node.read_forge_replay_source_in(&request, source_key, destination, None))
            .map_err(|e| e.to_string())?;
        check_head(options, source_head)?;
        require_subscription(&registration.filter, &events.events)?;
        let binding = Digest::new(
            DigestAlgorithm::Sha256.id(),
            DigestBytes::try_new(&dispatcher::canonical_scope(
                &route,
                node.repository_incarnation_id(),
                &registration,
            ))
            .map_err(|e| e.to_string())?,
        );
        let original_plan = node
            .runtime()
            .block_on(node.read_forge_dispatch_plan_in(
                &request,
                source_key,
                destination,
                Some(source_head),
            ))
            .map_err(|e| e.to_string())?;
        if let Some(plan) = original_plan {
            let member = plan
                .routes()
                .iter()
                .find(|m| m.route.id == route.id.0 && m.route.binding == binding)
                .ok_or("selected webhook is not an owed member of the original canonical plan")?;
            if !matches!(
                member.state,
                fgit_node::webhook::ReconcileState::Undeliverable { .. }
                    | fgit_node::webhook::ReconcileState::Indeterminate { .. }
            ) {
                return Err(
                    "a delivered or pending canonical member cannot be replayed as a dead letter"
                        .into(),
                );
            }
        } else {
            return Err(
                "canonical replay requires the original authenticated failed or uncertain route"
                    .into(),
            );
        }
        if let Some(diagnostic) = &diagnostic {
            require_replay_binding(diagnostic, &registration, source_key, source.payload_root())?;
        }
        let intent = ReplayIntent {
            source: source_key,
            destination,
            payload: source.payload_root(),
            expected_source_effect: source.root().map_err(|e| e.to_string())?,
            route_id: route.id.0,
            route_binding: binding,
        };
        let session = LoopbackReceiveSession::authenticated(
            principal,
            IdempotencyKey::new(replay_key.as_bytes().to_vec()).map_err(|e| e.to_string())?,
        );
        if stopped() {
            return Err("canonical replay stopped before enqueue".into());
        }
        let key = node
            .runtime()
            .block_on(node.enqueue_forge_replay_in(&request, &session, &intent, Default::default()))
            .map_err(|e| e.to_string())?;
        // A new logical responsibility has budget one. The original automatic
        // schedule, cumulative diagnostic and terminal outcome are untouched.
        let mut registration = registration.clone();
        registration.retry_schedule.max_attempts = 1;
        let mut http = WebhookDeliveryDestination::new(
            destination,
            registration,
            route.policy(),
            store.dead_letters(),
        );
        http.timeout = route.timeout;
        let mut transport = Transport {
            destination,
            routes: vec![DispatchRoute {
                id: route.id.0,
                binding,
                max_attempts: 1,
                initial_delay_millis: 0,
                max_delay_millis: 0,
            }],
            http,
            error: None,
            stopped,
        };
        let result = node
            .runtime()
            .block_on(node.dispatch_forge_outbox_in(
                &request,
                &session,
                key,
                &mut transport,
                1,
                Default::default(),
                &|| {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(|_| RefusalCode::EvidenceInvalid)?;
                    u64::try_from(now.as_millis()).map_err(|_| RefusalCode::ResourceBudgetExceeded)
                },
            ))
            .map_err(|e| {
                format!(
                    "canonical replay retained its responsibility: {e}; transport={:?}",
                    transport.error
                )
            })?;
        let state = result.effect.as_ref().map(|e| e.state());
        let code = match state {
            Some(ObligationState::Acknowledged) => 0,
            Some(ObligationState::TerminallyFailed) => 2,
            Some(ObligationState::Escalated) => 3,
            _ => 1,
        };
        let after = node
            .runtime()
            .block_on(node.read_forge_outbox_snapshot_in(&request, 16384, None))
            .map_err(|e| e.to_string())?;
        let text = format!(
            "{{\"type\":\"webhook_replay_canonical\",\"schema_version\":1,\"original_delivery_id\":{},\"delivery_id\":{},\"source_effect_root\":{},\"payload_root\":{},\"progress_root\":{},\"source_head\":{},\"result_head\":{},\"attempts\":{},\"invocation_attempt_limit\":1,\"canonical_settled\":{},\"active_retired\":{},\"original_diagnostic_retained\":{},\"original_delivery_reused\":false,\"node_closed\":true}}",
            quote(source_key.as_str()),
            quote(key.as_str()),
            quote(&intent.expected_source_effect.to_string()),
            quote(&intent.payload.to_string()),
            quote(
                &result
                    .progress
                    .root()
                    .map_err(|e| e.to_string())?
                    .to_string()
            ),
            quote(&source_head.to_string()),
            quote(&after.source_head.to_string()),
            result.sends,
            state.is_some(),
            matches!(
                state,
                Some(ObligationState::Acknowledged | ObligationState::TerminallyFailed)
            ),
            store.get_dead_letter_for(route.id, source_key).is_some()
        );
        Ok((code, text))
    })();
    let shutdown = node.shutdown().map_err(|e| e.to_string());
    drop(fence);
    match (operation, shutdown) {
        (Ok(result), Ok(_)) => Ok(result),
        (result, cleanup) => Err(format!(
            "canonical replay operation/shutdown incomplete; inspect retained authority state; operation={:?}; shutdown={:?}",
            result.err(),
            cleanup.err()
        )),
    }
}
