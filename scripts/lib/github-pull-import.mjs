// Foreign capture custody, not a forged native archive. The existing PR codec,
// sender and reservation journal own every destination request and retry.
import { mkdir, opendir, lstat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { preparePull, pullCanonical, pullHash, pullFields, parsePullJson, pullTokenFingerprint, pullScope }
  from '../operator/pull_command.mjs';
import { savePullIntent, loadPullIntent, readPullToken, readPullPrivate, privatePullDirectory }
  from '../operator/pull_files.mjs';
import { directory, encode, digest, exact, lifetime, number, pin, readPrivate, safePath, syncDirectory, writeNew }
  from './forge-pull-archive-store.mjs';
import { importSlot } from './native-pull-import.mjs';
import { executePreparedPullImport } from './native-pull-import-execute.mjs';
import { parseGithubPullCapture, GITHUB_PULL_LIMITS, githubPullFail as fail } from './github-pull-source.mjs';
import { githubPullImportSelection, compileGithubPullImport, GITHUB_PULL_IMPORT_SCHEMA as SCHEMA }
  from './github-pull-import-plan.mjs';

const MANIFEST_LIMIT=1024*1024;
async function inventory(root,names,check){
  const expected=new Set(names);
  for await(const entry of await opendir(root)){check();if(!expected.delete(entry.name))fail('import_unexpected_file');}
  if(expected.size)fail('import_missing_file');
}
function options(raw,preparing){
  const required=preparing?['workdir','captureFile','captureConfirm','selection','tokenFile']:['workdir','confirm'];
  pullFields(raw,[...required,'timeoutMs','signal'],required);
  const o={...raw,workdir:safePath(raw.workdir)};
  if(preparing){o.captureFile=safePath(raw.captureFile);o.captureConfirm=pin(raw.captureConfirm);
    o.selection=githubPullImportSelection(raw.selection);o.tokenFile=safePath(raw.tokenFile);}
  else o.confirm=pin(raw.confirm);
  return o;
}
function manifest(v){
  exact(v,['schema','selection','capture_sha256','credential_fingerprint','step_count','steps_sha256','request_sha256','request_bytes']);
  if(v.schema!==SCHEMA)fail('import_schema');
  const s=githubPullImportSelection(v.selection);
  if(!isDeepStrictEqual(s,v.selection))fail('import_selection_changed');
  pin(v.capture_sha256);pin(v.credential_fingerprint);pin(v.steps_sha256);
  number(v.step_count,1,s.max_steps,'import_step_count');number(v.request_bytes,1,s.max_request_bytes,'import_request_bytes');
  if(!Array.isArray(v.request_sha256)||v.request_sha256.length!==v.step_count)fail('import_requests');
  v.request_sha256.forEach(pin);return v;
}
async function contents(root,m,life,sealed,synchronize){
  const identity=await directory(root);await privatePullDirectory(root);
  await inventory(root,['capture.json','requests','journal',...(sealed?['manifest.json']:[])],life.check);
  const requests=join(root,'requests'),requestsIdentity=await directory(requests);await directory(join(root,'journal'));
  const bytes=await readPrivate(join(root,'capture.json'),GITHUB_PULL_LIMITS.bytes,synchronize,life.check);
  if(digest(bytes)!==m.capture_sha256)fail('capture_pin');
  const capture=parseGithubPullCapture(bytes),compiled=compileGithubPullImport(capture,m.selection);
  if(compiled.steps.length!==m.step_count||compiled.stepsSha256!==m.steps_sha256)fail('import_plan_changed');
  await inventory(requests,compiled.steps.map((_,i)=>importSlot(i)),life.check);
  const intents=[];let total=0;
  for(const [i,step] of compiled.steps.entries()){
    life.check();await directory(root,identity);await directory(requests,requestsIdentity);
    const slot=join(requests,importSlot(i));await inventory(slot,['intent.json'],life.check);
    const intent=await loadPullIntent(slot,{sync:synchronize}),text=pullCanonical(intent);
    total+=Buffer.byteLength(text);
    if(total>m.selection.max_request_bytes||pullHash(text)!==m.request_sha256[i]||intent.endpoint!==m.selection.endpoint||
        !isDeepStrictEqual(intent.scope,m.selection.scope)||intent.number!==step.number||intent.action!==step.action||
        intent.body!==step.body||!isDeepStrictEqual(intent.fields,step.fields)||intent.credential_fingerprint!==m.credential_fingerprint)fail('import_request_changed');
    intents.push(intent);
  }
  if(total!==m.request_bytes)fail('import_request_bytes');
  life.check();await directory(root,identity);await directory(requests,requestsIdentity);
  return {root,identity,manifest:m,capture,compiled,intents};
}
export async function loadGithubPullImport(workdir,confirm,life,synchronize=false){
  const root=safePath(workdir);pin(confirm);life.check();const identity=await directory(root);
  const bytes=await readPrivate(join(root,'manifest.json'),MANIFEST_LIMIT,synchronize,life.check);
  if(digest(bytes)!==confirm)fail('import_plan_pin');
  const m=manifest(parsePullJson(bytes));if(!encode(m).equals(bytes))fail('import_manifest_encoding');
  const loaded=await contents(root,m,life,true,synchronize);await directory(root,identity);
  return {...loaded,planSha256:confirm};
}
function summary(loaded){
  return {type:'github_pull_import_prepared',schema_version:1,workdir:loaded.root,plan_sha256:loaded.planSha256,
    capture_sha256:loaded.manifest.capture_sha256,source:loaded.capture.source,destination:loaded.manifest.selection.endpoint,
    scope:loaded.manifest.selection.scope,steps:loaded.intents.length,request_bytes:loaded.manifest.request_bytes,
    mapping:loaded.compiled.mapping,required_refs:loaded.compiled.refs,network_accessed:false,
    mutation_submitted:false,canonical_restore:false,atomic_batch:false,approvals_imported:false,refs_changed:false};
}
export async function prepareGithubPullImport(raw){
  const o=options(raw,true),life=lifetime(o);let created=false,planSha256=null;
  try{
    life.check();await privatePullDirectory(dirname(o.workdir));
    try{await lstat(o.workdir);fail('import_workdir_exists');}catch(e){if(e.code!=='ENOENT')throw e;}
    const bytes=await readPullPrivate(o.captureFile,GITHUB_PULL_LIMITS.bytes);life.check();
    if(digest(bytes)!==o.captureConfirm)fail('capture_pin');
    const capture=parseGithubPullCapture(bytes),compiled=compileGithubPullImport(capture,o.selection);life.check();
    // Whole-population native limits and lifecycle consent precede ALL key
    // generation. Preparation is offline; no GitHub credential is accepted here.
    const token=await readPullToken(o.tokenFile),fingerprint=pullTokenFingerprint(token),intents=[];let total=0;
    for(const {number,action,fields} of compiled.steps){
      life.check();const intent=preparePull({endpoint:o.selection.endpoint,scope:o.selection.scope,number,action,fields},token);
      total+=Buffer.byteLength(pullCanonical(intent));if(total>o.selection.max_request_bytes)fail('import_request_limit');intents.push(intent);
    }
    const m=manifest({schema:SCHEMA,selection:compiled.selection,capture_sha256:o.captureConfirm,credential_fingerprint:fingerprint,
      step_count:intents.length,steps_sha256:compiled.stepsSha256,request_sha256:intents.map(v=>pullHash(pullCanonical(v))),request_bytes:total});
    const rootBytes=encode(m);planSha256=digest(rootBytes);if(rootBytes.length>MANIFEST_LIMIT)fail('import_manifest_limit');
    life.check();await mkdir(o.workdir,{mode:0o700});created=true;await syncDirectory(dirname(o.workdir));const identity=await directory(o.workdir);
    for(const n of ['requests','journal'])await mkdir(join(o.workdir,n),{mode:0o700});await syncDirectory(o.workdir);
    await writeNew(join(o.workdir,'capture.json'),bytes);
    for(const [i,intent] of intents.entries()){
      life.check();await directory(o.workdir,identity);await savePullIntent(join(o.workdir,'requests',importSlot(i)),intent);
    }
    const loaded=await contents(o.workdir,m,life,false,true);await inventory(join(o.workdir,'journal'),[],life.check);
    life.check();await directory(o.workdir,identity);await writeNew(join(o.workdir,'manifest.json'),rootBytes);
    return summary({...loaded,planSha256});
  }catch(cause){
    const e=cause instanceof Error?cause:new Error('github_pull_import_interrupted');
    e.import_progress={workdir:o.workdir,directory_created:created,plan_sha256:planSha256,preparation_complete:false,mutation_submitted:false};throw e;
  }finally{life.close();}
}
export async function inspectGithubPullImport(raw){
  const o=options(raw,false),life=lifetime(o);
  try{return summary(await loadGithubPullImport(o.workdir,o.confirm,life));}finally{life.close();}
}
export function executeGithubPullImport(raw){return executePreparedPullImport(raw,loadGithubPullImport,'github');}

// An independent branch principal is mandatory. This returns the existing
// generic bootstrap selection, not a new key or an implicit branch mutation.
export async function githubPullBranchRequirements(raw){
  pullFields(raw,['workdir','confirm','principal','timeoutMs','signal'],['workdir','confirm','principal']);
  const principal=raw.principal,o=options(Object.fromEntries(Object.entries(raw).filter(([k])=>k!=='principal')),false),life=lifetime(o);
  try{
    const loaded=await loadGithubPullImport(o.workdir,o.confirm,life),s=loaded.manifest.selection;
    const selection={endpoint:s.endpoint,scope:pullScope({...s.scope,principal_id:principal}),namespace:s.namespace,refs:loaded.compiled.refs};
    life.check();return {type:'github_pull_branch_requirements',plan_sha256:o.confirm,capture_sha256:loaded.manifest.capture_sha256,
      requirements_sha256:digest(encode(selection)),selection,network_accessed:false,mutation_submitted:false};
  }finally{life.close();}
}
