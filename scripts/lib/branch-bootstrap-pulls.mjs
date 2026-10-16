// Bind create-only branch prerequisites to an already prepared native PR plan.
// The existing loader owns complete archive/request validation. This adapter
// never regenerates PR keys or derives a branch principal from archived actors.
import { loadPullImport } from './native-pull-import.mjs';
import { prepareBootstrap } from './branch-bootstrap.mjs';
import { fields, branch, pin, fail, selection, encode, hash } from './branch-bootstrap-protocol.mjs';
import { path, lifetime } from './branch-bootstrap-store.mjs';

function options(raw, preparing) {
  const required = ['migrationDir','migrationConfirm','namespace','principal',
    ...(preparing ? ['workdir','tokenFile'] : [])];
  fields(raw,[...required,'timeoutMs','signal'],required);
  const o = { ...raw, migrationDir:path(raw.migrationDir), migrationConfirm:pin(raw.migrationConfirm) };
  if (typeof o.principal !== 'string' || !/^[0-9a-f]{32}$/.test(o.principal)) fail('independent_branch_principal');
  if (typeof o.namespace !== 'string' || !o.namespace.endsWith('/')) fail('namespace');
  branch(o.namespace.slice(0,-1));
  if (preparing) { o.workdir = path(o.workdir); o.tokenFile = path(o.tokenFile); }
  return o;
}
async function requirements(o, life) {
  // Keep the old loader's timeout interface while using this invocation's one
  // deadline and cancellation signal for its entire dependency closure.
  const loaded = await loadPullImport(o.migrationDir,o.migrationConfirm,
    { check:life.check, signal:life.signal, timeout:life.remaining() });
  const refs = new Map(); let pulls = 0;
  for (const intent of loaded.intents) {
    life.check();
    if (intent.action !== 'open') continue;
    pulls++;
    for (const side of ['source','target']) {
      const ref = intent.fields[`${side}_ref`], tip = intent.fields[`${side}_tip`];
      if (refs.has(ref) && refs.get(ref) !== tip) fail('migration_ref_tip_conflict');
      refs.set(ref,tip);
    }
  }
  // Namespace membership is checked for EVERY requirement. Nothing is skipped
  // because it might already exist, and no source/base name is silently remapped.
  const selected = selection({ endpoint:loaded.manifest.selection.endpoint,
    scope:{ ...loaded.manifest.selection.scope, principal_id:o.principal }, namespace:o.namespace,
    refs:[...refs].map(([ref,new_commit]) => ({ref,new_commit})),
    origin:{ type:'native_pull_import', plan_sha256:o.migrationConfirm } });
  life.check();
  return { type:'branch_bootstrap_requirements', schema_version:1,
    migration_plan_sha256:o.migrationConfirm, requirements_sha256:hash(encode(selected)),
    selection:selected, pull_requests:pulls, required_branches:selected.refs.length,
    requirements_complete:true, current_ref_state_verified:false,
    network_accessed:false, mutation_submitted:false, pr_requests_modified:false };
}
export async function pullBootstrapRequirements(raw) {
  const o = options(raw,false), life = lifetime(o);
  try { return await requirements(o,life); } finally { life.close(); }
}
export async function preparePullBootstrap(raw) {
  const o = options(raw,true), life = lifetime(o);
  try {
    const selected = await requirements(o,life);
    const prepared = await prepareBootstrap({ workdir:o.workdir,tokenFile:o.tokenFile,
      selection:selected.selection,timeoutMs:life.remaining(),signal:life.signal });
    return { ...prepared, migration_plan_sha256:o.migrationConfirm,
      requirements_sha256:selected.requirements_sha256, pr_requests_modified:false };
  } finally { life.close(); }
}
