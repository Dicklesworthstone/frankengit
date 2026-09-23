# Journaled trusted workflow execution

FG-095b's `WorkflowCoordinator::execute_trusted_workflow_journaled` composes
trusted multi-step execution with `FileCheckJournal` on Unix. It persists the
initial queued proposals before opening the first job scope. After each job's
cleanup, it persists the exact normalized per-job evidence and proposal pair
before the next job may start. The per-job bytes and check conclusions are
unchanged; local successes remain `ActionRequired`, not protected-ref checks.

Supply the same explicit compiled prepared handle and source-scoped executor
used by `execute_trusted_workflow`, plus an already open, repository-scoped
journal. The operator owns stable private paths. All currently pending facts
must belong to this run; unrelated prefixes and foreign journal scopes are
refused without consuming them. No new threads, runtime, dependencies,
canonical repository schemas, or implicit secrets are introduced.

Initial cancellation refuses before any journal transfer or user work. Once a
job has completed, persistence is part of bounded non-cancellable drain; a
cancelled caller does not discard its terminal result. Job cleanup still runs
before persistence. An I/O, capacity, or evidence failure stops subsequent
user work, retains unsettled proposals in memory and holds the run. Earlier
accepted job results remain recoverable from the journal without the original
coordinator. Later jobs are cancelled without opening their scopes. A failed
handoff never yields a successful complete-workflow receipt.

A completed repeated call flushes any remaining matching facts and returns
its original observation without repeating execution or appending duplicate
journal records. An interrupted call with no retained full observation is not
retried by this coordinator. The old non-journaled execution API retains its
behavior through a no-op custody callback.

**This method alone does not fence execution across process loss.** The journal
retains proposals and evidence; its queued facts are not an execution lease.
A new coordinator must not infer permission to rerun a job from an incomplete
proposal stream. A durable attempt owner is required for that boundary.
Canonical check admission, current-source/policy validation, hostile isolation,
and a distributed scheduler remain separate work. Disk calls are byte-bounded,
not a guarantee of hard I/O latency; the owning runtime chooses the blocking
context and the supplied executor must bound cleanup.

The ten new regression tests exercise real private-file reopen/evidence
retrieval, per-job persistence ordering, capacity failures before and after
work, cancelled drain, exact repeat calls, scope/prefix fences, retained
containment, and persistence callback failure/unwind. Executors are explicitly
control-flow fixtures, not containment proofs. Rust compilation and tests were
not run in the editing environment because Cargo/rustc were unavailable.

For a synced start fence and completed-result lookup across restart, use the
explicit [durable attempt owner](DURABLE_WORKFLOW_ATTEMPTS.md) and
`execute_trusted_workflow_durable`. The journaled-only API remains unchanged.
