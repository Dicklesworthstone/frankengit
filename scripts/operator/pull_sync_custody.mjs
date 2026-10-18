// Private, create-only plan custody. It never supplies native authorization.
import { join } from 'node:path';
import { directory, names, readPrivate, writeNew, lock } from './workflow_watch_io.mjs';
import { validatePlan, encode, LIMITS } from './pull_sync_plan.mjs';
import { fail, parseSyncJson } from './pull_sync_transport.mjs';
export async function loadPlan(state) {
  await directory(state);
  return validatePlan(parseSyncJson(await readPrivate(join(state, 'plan.json'), LIMITS.plan), LIMITS.plan));
}
export async function savePlan(state, value) {
  const plan = validatePlan(value); await directory(state);
  const release = await lock(join(state, 'owner.lock'));
  try {
    if ((await names(state, 2)).some(name => name !== 'owner.lock')) fail('sync_plan_directory_not_empty');
    await writeNew(join(state, 'plan.json'), encode(plan));
    return plan;
  } finally { await release(); }
}
export function planSummary(plan) {
  return { type: 'pull_sync_plan', schema_version: 1, plan_sha256: plan.plan_sha256, destination: plan.discovery.destination,
    snapshot_token: plan.discovery.snapshot_token, source_head: plan.discovery.source_head, scanned: plan.discovery.scanned,
    unchanged: plan.discovery.unchanged, changes: plan.discovery.changes, mutations_sent_by_this_operation: 0, publication_status: 'not_queried', approvals_carried_forward: false };
}
