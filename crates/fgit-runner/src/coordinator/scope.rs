//! Repository/trust-scoped concurrency and recovery for the in-memory scheduler.
//! Queue ordering is accepted-call order, never hash-map or wall-clock order.
use super::*;

impl WorkflowCoordinator {
    pub(super) fn enqueue_concurrency_group(
        &mut self,
        tenant: TenantId,
        repository: RepositoryId,
        run_id: WorkflowRunId,
        trigger: &TriggerContext,
    ) {
        let Some(group) = &trigger.concurrency_group else { return; };
        let key = (tenant, repository, group.name.clone());
        let queue = self.concurrency_groups.entry(key).or_default();
        if group.cancel_in_progress {
            for existing_id in queue.iter() {
                let Some(run) = self.active_runs.get_mut(existing_id) else { continue; };
                // A fork's arbitrary group name cannot cancel a trusted run,
                // even in the same repository. Draining predecessors continue
                // owning the group until the explicit finalization boundary.
                if run.trigger_ctx.trust_domain == trigger.trust_domain
                    && run.trigger_ctx.is_fork == trigger.is_fork
                    && matches!(run.status, RunStatus::Queued | RunStatus::Running)
                {
                    let reason = DrainReason::Cancelled(CancellationReason::ConcurrencyPreempted {
                        group: group.name.clone(), newer_run: run_id,
                    });
                    run.status = RunStatus::Draining { reason: reason.clone() };
                    for status in run.job_statuses.values_mut() {
                        if matches!(status, JobStatus::Running) {
                            *status = JobStatus::Draining { reason: reason.clone() };
                        }
                    }
                }
            }
        }
        queue.push_back(run_id);
    }

    pub(super) fn has_concurrency_turn(&self, candidate: &ActiveRun) -> bool {
        let Some(group) = &candidate.concurrency_group else { return true; };
        let key = (candidate.tenant, candidate.repository, group.clone());
        let Some(queue) = self.concurrency_groups.get(&key) else { return false; };
        queue.iter().find(|id| {
            self.active_runs.get(*id).is_some_and(|run| {
                run.trigger_ctx.trust_domain == candidate.trigger_ctx.trust_domain
                    && run.trigger_ctx.is_fork == candidate.trigger_ctx.is_fork
                    && !matches!(run.status, RunStatus::Terminal(_))
            })
        }).is_some_and(|id| *id == candidate.id)
    }

    /// Reconciles only the named repository against its own head. This acts on
    /// an in-memory projection; it is neither a disk-journal loader nor an OS
    /// process reaper. Terminal observations are never rewritten by recovery.
    pub fn recover_repository_from_crash(
        &mut self,
        tenant: TenantId,
        repository: RepositoryId,
        current_authority_head: Commitment,
    ) -> Vec<WorkflowRunId> {
        let mut recovered = Vec::new();
        for (id, run) in &mut self.active_runs {
            if run.tenant != tenant || run.repository != repository
                || matches!(run.status, RunStatus::Terminal(_))
            {
                continue;
            }
            if run.authority_head != current_authority_head {
                run.status = RunStatus::Terminal(RunOutcome::Invalidated {
                    reason: format!("Stale source after restart: expected {}, current {}", run.authority_head, current_authority_head),
                });
            } else if matches!(run.status, RunStatus::Running | RunStatus::Draining { .. }) {
                run.status = RunStatus::Terminal(RunOutcome::Cancelled { reason: CancellationReason::CrashRecovery });
            } else {
                continue;
            }
            for status in run.job_statuses.values_mut() {
                if !matches!(status, JobStatus::Terminal(_)) { *status = JobStatus::Terminal(JobOutcome::Cancelled); }
            }
            recovered.push(*id);
        }
        recovered
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_schema::workflow::{Limits, compile};
    use fgit_types::GitOidSha1;

    const SOURCE: &str = "name: scoped\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: true\n";
    fn coordinator() -> WorkflowCoordinator {
        WorkflowCoordinator::new(CoordinatorLimits::default(),
            ResourceCeilings::new(100_000, 512 * 1024 * 1024, 1024 * 1024 * 1024, 0, 16, 60_000).unwrap(), 8).unwrap()
    }
    fn oid() -> GitOid { GitOid::Sha1(GitOidSha1::from_bytes([3; 20])) }
    fn trigger(cancel: bool) -> TriggerContext {
        let mut trigger = TriggerContext::trusted_push("alice");
        trigger.concurrency_group = Some(ConcurrencyGroup::new("ci", cancel));
        trigger
    }
    fn enqueue(c: &mut WorkflowCoordinator, tenant: u8, repo: u8, sequence: u64, trigger: TriggerContext) -> WorkflowRunId {
        c.enqueue_run(TenantId::from_bytes([tenant; 16]), RepositoryId::from_bytes([repo; 16]),
            Commitment::of_bytes(&[repo]), oid(), compile(SOURCE, &Limits::default()).unwrap(),
            trigger, sequence, 100).unwrap()
    }

    #[test]
    fn identical_trigger_keys_are_independent_across_repositories_and_tenants() {
        let mut c = coordinator();
        let first = enqueue(&mut c, 1, 1, 1, trigger(false));
        let other_repo = enqueue(&mut c, 1, 2, 1, trigger(false));
        let other_tenant = enqueue(&mut c, 2, 1, 1, trigger(false));
        let key = IdempotencyKey::of("push", &oid(), "scoped", 1);
        assert!(c.lookup_by_idempotency(&key).is_none());
        for (tenant, repo, id) in [(1, 1, first), (1, 2, other_repo), (2, 1, other_tenant)] {
            assert_eq!(c.lookup_in_repository(TenantId::from_bytes([tenant; 16]), RepositoryId::from_bytes([repo; 16]), &key).unwrap().id, id);
            assert_eq!(c.eligible_jobs(id).unwrap(), vec!["build"]);
        }
        assert_ne!(first, other_repo);
        assert_ne!(first, other_tenant);
    }

    #[test]
    fn non_preempting_group_is_fifo_and_releases_only_terminal_predecessors() {
        let mut c = coordinator();
        let first = enqueue(&mut c, 1, 1, 1, trigger(false));
        let second = enqueue(&mut c, 1, 1, 2, trigger(false));
        let third = enqueue(&mut c, 1, 1, 3, trigger(false));
        assert_eq!(c.active_runs[&first].concurrency_group.as_deref(), Some("ci"));
        assert!(c.require_ready_job(first, "build").is_ok());
        assert!(c.require_ready_job(second, "build").is_err());
        c.cancel_run(second, CancellationReason::UserRequested).unwrap();
        assert!(c.eligible_jobs(third).unwrap().is_empty());
        c.record_terminal_job(first, "build", JobOutcome::Succeeded, None, 200);
        assert_eq!(c.eligible_jobs(third).unwrap(), vec!["build"]);
    }

    #[test]
    fn replacement_waits_for_every_preempted_run_to_drain() {
        let mut c = coordinator();
        let first = enqueue(&mut c, 1, 1, 1, trigger(false));
        let queued = enqueue(&mut c, 1, 1, 2, trigger(false));
        let replacement = enqueue(&mut c, 1, 1, 3, trigger(true));
        assert!(matches!(c.active_runs[&first].status, RunStatus::Draining { .. }));
        assert!(matches!(c.active_runs[&queued].status, RunStatus::Draining { .. }));
        assert!(c.eligible_jobs(replacement).unwrap().is_empty());
        c.drain_and_finalize(first).unwrap();
        assert!(c.eligible_jobs(replacement).unwrap().is_empty());
        c.drain_and_finalize(queued).unwrap();
        assert_eq!(c.eligible_jobs(replacement).unwrap(), vec!["build"]);
    }

    #[test]
    fn preemption_cannot_cross_repository_tenant_or_fork_trust() {
        let mut c = coordinator();
        let trusted = enqueue(&mut c, 1, 1, 1, trigger(false));
        enqueue(&mut c, 1, 2, 2, trigger(true));
        enqueue(&mut c, 2, 1, 2, trigger(true));
        let mut fork = TriggerContext::fork_pull_request(7, "contributor");
        fork.concurrency_group = Some(ConcurrencyGroup::new("ci", true));
        let fork_run = enqueue(&mut c, 1, 1, 2, fork);
        assert_eq!(c.active_runs[&trusted].status, RunStatus::Queued);
        assert_eq!(c.eligible_jobs(trusted).unwrap(), vec!["build"]);
        assert_eq!(c.eligible_jobs(fork_run).unwrap(), vec!["build"]);
    }

    #[test]
    fn duplicate_trigger_is_refused_before_it_can_preempt_or_emit() {
        let mut c = coordinator();
        let first = enqueue(&mut c, 1, 1, 1, trigger(false));
        let before = c.outbox_facts.clone();
        let result = c.enqueue_run(TenantId::from_bytes([1; 16]), RepositoryId::from_bytes([1; 16]),
            Commitment::of_bytes(&[1]), oid(), compile(SOURCE, &Limits::default()).unwrap(), trigger(true), 1, 200);
        assert!(matches!(result, Err(CoordinatorRefusal::DuplicateIdempotencyKey(_))));
        assert_eq!(c.active_runs[&first].status, RunStatus::Queued);
        assert_eq!(c.outbox_facts, before);
    }

    #[test]
    fn recovery_does_not_apply_one_repository_head_to_another_repository() {
        let mut c = coordinator();
        let first = enqueue(&mut c, 1, 1, 1, trigger(false));
        let second = enqueue(&mut c, 1, 2, 1, trigger(false));
        assert!(c.recover_from_crash(Commitment::of_bytes(b"changed")).is_empty());
        assert_eq!(c.active_runs[&first].status, RunStatus::Queued);
        let recovered = c.recover_repository_from_crash(TenantId::from_bytes([1; 16]), RepositoryId::from_bytes([1; 16]), Commitment::of_bytes(b"changed"));
        assert_eq!(recovered, vec![first]);
        assert!(matches!(c.active_runs[&first].status, RunStatus::Terminal(RunOutcome::Invalidated { .. })));
        assert_eq!(c.active_runs[&second].status, RunStatus::Queued);
        assert_eq!(c.eligible_jobs(second).unwrap(), vec!["build"]);
    }
}
