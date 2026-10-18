// FG-049 external operator: exact create-absent branch requests. Native Git,
// reachability, ref protection and publication remain exclusively server-owned.
import { randomBytes } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { performance } from 'node:perf_hooks';
import { outcomeScope, outcomeEndpoint, lookupOutcome, validateOutcomeReply, parseOutcomeJson }
  from '../operator/transaction_outcome.mjs';
import { recordDigest } from './forge-operator-io.mjs';

export const BOOTSTRAP_LIMITS = Object.freeze({ branches: 8192, file: 1024 * 1024,
  request: 16384, requestBytes: 64 * 1024 * 1024, reply: 16384,
  attempts: 32768, perBranch: 32, result: 65536, journalBytes: 32 * 1024 * 1024 });
export const encode = value => Buffer.from(`${JSON.stringify(value)}\n`);
export const hash = recordDigest;
export const fail = code => { const e = new Error(`branch_bootstrap_${code}`); e.code = e.message; throw e; };
export function fields(v, names, required = names) {
  if (!v || typeof v !== 'object' || Array.isArray(v) || ![Object.prototype, null].includes(Object.getPrototypeOf(v)) ||
      Object.keys(v).some(k => !names.includes(k)) || required.some(k => !Object.hasOwn(v,k)) ||
      Object.values(Object.getOwnPropertyDescriptors(v)).some(d => !Object.hasOwn(d,'value'))) fail('fields');
  return v;
}
export function bounded(v, minimum, maximum) {
  if (!Number.isSafeInteger(v) || v < minimum || v > maximum) fail('limit'); return v;
}
export function pin(v) { if (typeof v !== 'string' || !/^[0-9a-f]{64}$/.test(v)) fail('pin'); return v; }
export function branch(v) {
  if (typeof v !== 'string' || Buffer.byteLength(v) > 1024 || /[\uD800-\uDFFF]/u.test(v) ||
      !v.startsWith('refs/heads/') || v.length === 11 || /[\x00-\x20\x7f~^:?*\[\\]/u.test(v) ||
      v.includes('..') || v.includes('@{') || v.endsWith('.') ||
      v.split('/').some(p => !p || p.startsWith('.') || p.endsWith('.lock'))) fail('branch');
  return v;
}
function oid(v, format, wire = false) {
  const prefix = `${format}:`, raw = wire && typeof v === 'string' && v.startsWith(prefix) ? v.slice(prefix.length) : v;
  if (typeof raw !== 'string' || !new RegExp(`^[0-9a-f]{${format === 'sha1' ? 40 : 64}}$`).test(raw) || /^0+$/.test(raw)) fail('oid');
  return raw;
}
function scope(v) {
  fields(v,['tenant_id','repository_id','repository_incarnation','principal_id','object_format']);
  if (!['sha1','sha256'].includes(v.object_format)) fail('format');
  return { ...outcomeScope(Object.fromEntries(Object.entries(v).filter(([k]) => k !== 'object_format'))), object_format:v.object_format };
}
export const outcomeBinding = s => outcomeScope(Object.fromEntries(Object.entries(s).filter(([k]) => k !== 'object_format')));
export function selection(v) {
  fields(v,['endpoint','scope','namespace','refs','origin'],['endpoint','scope','namespace','refs']);
  const endpoint = outcomeEndpoint(v.endpoint), selected = scope(v.scope);
  if (typeof v.namespace !== 'string' || !v.namespace.endsWith('/')) fail('namespace');
  branch(v.namespace.slice(0,-1));
  if (!Array.isArray(v.refs)) fail('refs'); bounded(v.refs.length,1,BOOTSTRAP_LIMITS.branches);
  const seen = new Set(), refs = v.refs.map(r => {
    fields(r,['ref','new_commit']); const ref = branch(r.ref);
    if (!ref.startsWith(v.namespace) || seen.has(ref)) fail('duplicate_or_out_of_namespace');
    seen.add(ref); return {ref,new_commit:oid(r.new_commit,selected.object_format)};
  }).sort((a,b) => Buffer.compare(Buffer.from(a.ref),Buffer.from(b.ref)));
  let origin;
  if (v.origin !== undefined) {
    fields(v.origin,['type','plan_sha256']);
    if (v.origin.type !== 'native_pull_import') fail('origin');
    origin = {type:v.origin.type,plan_sha256:pin(v.origin.plan_sha256)};
  }
  const result = {endpoint,scope:selected,namespace:v.namespace,refs,...(origin ? {origin} : {})};
  if (encode(result).length > BOOTSTRAP_LIMITS.file) fail('selection_bytes'); return result;
}
export function createRequest(selected, ref, credential, nonce = randomBytes(16).toString('hex')) {
  if (typeof nonce !== 'string' || !/^[0-9a-f]{32}$/.test(nonce)) fail('nonce'); pin(credential);
  const basis = {schema:'frankengit-branch-bootstrap-request-v1',endpoint:selected.endpoint,scope:selected.scope,
    namespace:selected.namespace,ref:ref.ref,new_commit:ref.new_commit,credential_sha256:credential,nonce,
    body:new URLSearchParams({object_format:selected.scope.object_format,ref:ref.ref,new_commit:ref.new_commit}).toString()};
  const result = {...basis,key:`fgbb1-${nonce}-${hash(encode(basis))}`};
  if (encode(result).length > BOOTSTRAP_LIMITS.request) fail('request_bytes'); return result;
}
export function checkedRequest(v) {
  fields(v,['schema','endpoint','scope','namespace','ref','new_commit','credential_sha256','nonce','body','key']);
  const s = selection({endpoint:v.endpoint,scope:v.scope,namespace:v.namespace,refs:[{ref:v.ref,new_commit:v.new_commit}]});
  const result = createRequest(s,s.refs[0],v.credential_sha256,v.nonce);
  if (!encode(result).equals(encode(v))) fail('request_changed'); return result;
}
// Reject duplicate or escaped-equivalent keys before JSON.parse discards them.
// Canonical local files additionally require exact re-encoding. Wire u64 values
// use the existing outcome parser, preserving the complete decision sequence.
export function parse(bytes, wire = false) {
  if (!Buffer.isBuffer(bytes) || bytes.length > (wire ? BOOTSTRAP_LIMITS.reply : BOOTSTRAP_LIMITS.file)) fail('json_bytes');
  const source = new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes), stack = []; let nodes = 0;
  for (let i=0;i<source.length;i++) {
    const c=source[i];
    if (c==='{' || c==='[') { if (++nodes>131072 || stack.length>=16) fail('json_structure'); stack.push({type:c,keys:new Set()}); }
    else if (c==='}' || c===']') { if (stack.pop()?.type !== (c==='}'?'{':'[')) fail('json_structure'); }
    else if (c==='"') {
      const start=i++;
      for (;i<source.length && source[i]!=='"';i++) if (source[i]==='\\') i++;
      if (i>=source.length || ++nodes>131072) fail('json_structure');
      let next=i+1; while (/[\x20\t\r\n]/.test(source[next]??'') && next<source.length) next++;
      if (source[next]===':') {
        const top=stack.at(-1), key=JSON.parse(source.slice(start,i+1));
        if (top?.type!=='{' || top.keys.has(key)) fail('duplicate_json_key'); top.keys.add(key);
      }
    }
  }
  if (stack.length) fail('json_structure');
  return wire ? parseOutcomeJson(bytes) : JSON.parse(source,(key,value,context) => {
    if (typeof value==='number' && (!Number.isSafeInteger(value) || !/^(0|[1-9][0-9]*)$/.test(context.source))) fail('json_number');
    return value;
  });
}
export function canonical(bytes) { const v=parse(bytes); if (!encode(v).equals(bytes)) fail('encoding'); return v; }
function opaque(v) {
  if (typeof v!=='string' || !v || Buffer.byteLength(v)>256 || /[\s\x00-\x1f\x7f-\x9f\uD800-\uDFFF]/u.test(v)) fail('identity'); return v;
}
export function publication(v, request, status) {
  const r=checkedRequest(request), committed=v.outcome==='committed';
  fields(v,['type','schema_version',...Object.keys(r.scope),'operation','atomic','terminal','tx_id','decision_sequence',
    'outcome','forge_transition','updates',...(committed?['repository_commit_id']:['code','code_point','refusal_record_id'])]);
  if (v.type!=='branch_publication' || v.schema_version!==1 || Object.keys(r.scope).some(k=>v[k]!==r.scope[k]) ||
      v.operation!=='create' || v.atomic!==true || v.terminal!==true || v.forge_transition!==false ||
      !['committed','refused'].includes(v.outcome) || status!==(committed?200:409)) fail('publication_binding');
  if (!Array.isArray(v.updates) || v.updates.length!==1) fail('publication_effect');
  const u=fields(v.updates[0],['ref','ref_hex','expected_commit','new_commit','force']);
  if (u.ref!==r.ref || u.ref_hex!==Buffer.from(r.ref).toString('hex') || u.expected_commit!==null || u.force!==false ||
      oid(u.new_commit,r.scope.object_format,true)!==r.new_commit) fail('publication_effect');
  opaque(v.tx_id);
  if (typeof v.decision_sequence!=='string' || !/^[1-9][0-9]{0,19}$/.test(v.decision_sequence) || BigInt(v.decision_sequence)>18446744073709551615n) fail('sequence');
  if (committed) opaque(v.repository_commit_id);
  else { opaque(v.code); opaque(v.refusal_record_id); bounded(v.code_point,0,65535); }
  return structuredClone(v);
}
export function matchOutcome(outcome, pub) {
  if (!pub || !outcome) return;
  if (outcome.transaction && outcome.transaction.tx_id!==pub.tx_id) fail('conflicting_transaction');
  if (!outcome.terminal) return;
  const d=outcome.decision;
  if (d.kind!==pub.outcome || d.decision_sequence!==pub.decision_sequence ||
      (d.repository_commit_id??null)!==(pub.repository_commit_id??null) || (d.refusal_record_id??null)!==(pub.refusal_record_id??null) ||
      (d.code??null)!==(pub.code??null) || (d.code_point??null)!==(pub.code_point??null)) fail('conflicting_terminal');
}
function post(r, token, {signal,timeoutMs,ca}) {
  return new Promise((resolve,reject) => {
    let req,res,timer,result,error,finishing=false,closed=false,delivered=false;
    const deliver=()=>{if(delivered)return;delivered=true;error?reject(error):resolve(result);};
    const finish=(failure,value)=>{
      if(finishing)return;finishing=true;error=failure;result=value;clearTimeout(timer);
      signal?.removeEventListener('abort',abort);res?.destroy();req?.destroy();if(!req||closed)deliver();
    };
    const problem=code=>{const e=new Error(`branch_bootstrap_${code}`);e.code=e.message;return e;};
    const abort=()=>finish(problem('cancelled'));
    if(signal?.aborted){abort();return;}
    try {
      const url=new URL(`${r.endpoint}/api/v1/source/branches/create`);
      req=(url.protocol==='https:'?httpsRequest:httpRequest)(url,{method:'POST',agent:false,rejectUnauthorized:true,
        maxHeaderSize:16384,...(ca?{ca}:{}),headers:{Authorization:`Bearer ${token}`,'Idempotency-Key':r.key,
          'Content-Type':'application/x-www-form-urlencoded','Content-Length':String(Buffer.byteLength(r.body)),
          Accept:'application/json','Accept-Encoding':'identity',Connection:'close','Cache-Control':'no-store'}});
      req.once('close',()=>{closed=true;if(!finishing)finish(problem('response_incomplete'));else deliver();});
      req.on('error',()=>finish(problem('transport')));
      req.once('response',incoming=>{
        res=incoming;
        if(![200,409].includes(res.statusCode)){finish(problem('http_refused'));return;}
        const names=res.rawHeaders.filter((_,i)=>i%2===0).map(n=>n.toLowerCase()).filter(n=>['content-type','content-length','content-encoding'].includes(n));
        const length=res.headers['content-length'];
        if(new Set(names).size!==names.length || !/^application\/json(?:\s*;|$)/i.test(res.headers['content-type']??'') ||
            (res.headers['content-encoding']??'identity').toLowerCase()!=='identity'){finish(problem('response_encoding'));return;}
        if(length!==undefined && (!/^(0|[1-9][0-9]*)$/.test(length)||BigInt(length)>BigInt(BOOTSTRAP_LIMITS.reply))){finish(problem('response_bytes'));return;}
        let size=0;const chunks=[];
        res.on('error',()=>finish(problem('response_incomplete')));
        res.on('data',chunk=>{if(finishing)return;size+=chunk.length;if(size>BOOTSTRAP_LIMITS.reply)finish(problem('response_bytes'));else chunks.push(chunk);});
        res.once('end',()=>{
          if(finishing)return;
          if(!res.complete || length!==undefined && BigInt(length)!==BigInt(size)){finish(problem('response_incomplete'));return;}
          try{finish(null,publication(parse(Buffer.concat(chunks,size),true),r,res.statusCode));}catch(e){finish(e);}
        });
      });
      signal?.addEventListener('abort',abort,{once:true});timer=setTimeout(()=>finish(problem('timeout')),timeoutMs);
      if(signal?.aborted)abort();else req.end(r.body);
    }catch{finish(problem('transport'));}
  });
}
export async function operateBranch(raw, token, options = {}) {
  const r=checkedRequest(raw); pin(token);
  fields(options,['send','timeoutMs','signal','ca','known','publication'],[]);
  const signal=options.signal, send=options.send??false;if(typeof send!=='boolean')fail('send');
  const timeoutMs=bounded(options.timeoutMs??30000,1,300000), deadline=performance.now()+timeoutMs;
  if(signal!==undefined && !(signal instanceof AbortSignal))fail('signal');
  const ca=options.ca===undefined?undefined:Buffer.isBuffer(options.ca)&&options.ca.length>0&&options.ca.length<=128*1024?Buffer.from(options.ca):fail('ca');
  if(send && hash(Buffer.from(token))!==r.credential_sha256)fail('original_credential');
  const s=outcomeBinding(r.scope);
  let observed=options.known==null?null:validateOutcomeReply(options.known,s);
  let pub=options.publication==null?null:publication(options.publication,r,options.publication.outcome==='committed'?200:409);
  matchOutcome(observed,pub);let dispatched=false,phase='preflight';
  const remaining=()=>{
    signal?.throwIfAborted();const left=Math.ceil(deadline-performance.now());if(left<1)fail('timeout');return {timeoutMs:left,signal,ca};
  };
  const lookup=()=>lookupOutcome(r.endpoint,token,{...s,key:r.key},{...remaining(),known:observed});
  try {
    observed=await lookup();matchOutcome(observed,pub);
    if(!send||observed.terminal||pub!==null)return {outcome:observed,publication:pub,dispatched};
    phase='publication';const budget=remaining();dispatched=true;pub=await post(r,token,budget);
    phase='confirmation';observed=await lookup();matchOutcome(observed,pub);
    if(!observed.terminal)fail('confirmation_incomplete');
    return {outcome:observed,publication:pub,dispatched};
  }catch(cause){
    const e=new Error(typeof cause.code==='string'&&/^[a-z_]{1,128}$/.test(cause.code)?cause.code:'branch_bootstrap_operation_unavailable');
    e.code=e.message;e.observation={outcome:observed,publication:pub,dispatched};e.phase=phase;throw e;
  }
}
