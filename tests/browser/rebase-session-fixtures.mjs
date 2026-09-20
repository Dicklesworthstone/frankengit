// Explicit protocol/HTTP doubles, NOT native Rust replay or Git pack validation.
// Commit object IDs are real hashes of the emitted commit bodies.
import { webcrypto } from 'node:crypto';
import { utf8, hex } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { digest } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-candidate.mjs';
import { objectHash } from '../../crates/fgit-node/src/smart_http/server/browser/rebase-data.mjs';
import { multipart, response } from './source-edit-fixtures.mjs';
export const crypto = webcrypto, token = '7'.repeat(64), actor = '9'.repeat(32);
export const href = 'http://127.0.0.1:9418/repo.git/ui/rebase/';
export function decodeBody(options) {
  const type = new Headers(options.headers).get('Content-Type') ?? '';
  if (!type.startsWith('multipart/')) return { command: new URLSearchParams(options.body), files: new Map() };
  const b = type.split('boundary=')[1], bytes = Buffer.from(options.body), files = new Map();
  let start = 0, command;
  while (true) {
    const headerStart = bytes.indexOf(`--${b}\r\n`, start); if (headerStart < 0) break;
    const contentStart = bytes.indexOf('\r\n\r\n', headerStart) + 4;
    const end = bytes.indexOf(`\r\n--${b}`, contentStart); if (end < 0) throw new Error('truncated test MIME');
    const header = bytes.subarray(headerStart, contentStart).toString(), name = /name="([^"]+)"/.exec(header)[1];
    const part = bytes.subarray(contentStart, end);
    if (name === 'command') command = new URLSearchParams(part.toString()); else files.set(name, new Uint8Array(part));
    start = end + 2;
  }
  return { command, files };
}
export async function fixture(algorithm = 'sha1') {
  const width = algorithm === 'sha1' ? 40 : 64, id = n => n.toString(16).padStart(2,'0').repeat(width / 2);
  const original = [id(1), id(2)], upstream = id(3), onto = id(4), trees = [id(5),id(6),id(7)], sourceTree = id(8);
  const common = { schema_version:1, tenant_id:'1'.repeat(32), repository_id:'2'.repeat(32), repository_incarnation:'3'.repeat(32), object_format:algorithm };
  const head = `alg:2:${'4'.repeat(64)}`, sourceHead = 'head-test';
  const input = { upstream, empty:'stop', committer:'Rebaser <r@example.invalid>', timestamp:10, max_commits:32 };
  const command = { object_format:algorithm, profile:'linear-v1', source_ref:'refs/heads/topic', onto_ref:'refs/heads/main',
    expected_source:original[1], expected_onto:onto, expected_head:head, ...input };
  const bundle = utf8.encode('Explicit synthetic rebase bundle transport fixture\n'), sha256 = await digest(bundle, crypto);
  const flags = { read_only:true, objects_staged:false, transaction_created:false, published:false, publication_authorized:false };
  const commits = []; let parent = onto;
  for (let i=0; i<2; i++) {
    const body = utf8.encode(`tree ${trees[i+1]}\nparent ${parent}\nauthor Original <o@example.invalid> ${i+1} +0130\ncommitter ${input.committer} ${input.timestamp} +0000\n\nOriginal message ${i}\n`);
    const commit = await objectHash('commit', body, algorithm, crypto);
    commits.push({ index:i,commit,parent,tree:trees[i+1],body_hex:hex(body) }); parent=commit;
  }
  const clean = { type:'rebase_preparation', ...common, source_head:sourceHead,snapshot_token:head,profile:'linear-v1',
    source_ref:command.source_ref,source_ref_hex:hex(utf8.encode(command.source_ref)),onto_ref:command.onto_ref,onto_ref_hex:hex(utf8.encode(command.onto_ref)),
    expected_source:command.expected_source,upstream,onto,empty:input.empty,committer:input.committer,timestamp:input.timestamp,...flags,
    original_authors_preserved:true,original_messages_preserved:true,original_signatures_copied:false,author_identity_verified:false,
    state:'clean',series_complete:true,provisional_steps:false,candidate_commit:parent,root_tree:trees[2],generated_objects:6,
    pack_objects:6,borrowed_objects:0,bundle:{bytes:bundle.length,sha256},stopped_commit:null,conflicts:[],step_count:2,
    steps:commits.map((c,i)=>({original:original[i],rewritten:c.commit,tree:c.tree,kind:'replayed'})) };
  const changed = (from, to) => ({ path_hex:hex(utf8.encode('file.bin')),kind:'modified',
    before:{mode:'100644',object_id:from},after:{mode:'100644',object_id:to},content:{kind:'binary',before_bytes:2,after_bytes:2} });
  const diff = (before,after,beforeTree,afterTree) => ({ type:'source_diff', ...common, source_head:sourceHead,snapshot_token:head,
    profile:'native-tree-review-v1',mode:'direct',pull_request:null,read_only:true,transaction_created:false,published:false,
    approval_created:false,complete:true,line_origin:0,context_lines:3,before_ref_hex:clean.source_ref_hex,after_ref_hex:clean.source_ref_hex,
    requested_before:before,requested_after:after,compared_before:before,before_tree:beforeTree,after_tree:afterTree,
    entry_count:beforeTree===afterTree?0:1,path_prefixes_hex:[],entries:beforeTree===afterTree?[]:[changed(beforeTree,afterTree)] });
  const inspected = {type:'rebase_inspection',...common,profile:'linear-v1',source_head:sourceHead,snapshot_token:head,
    expected_source:command.expected_source,onto,candidate_commit:parent,...flags,approval_created:false,replay_equivalence_verified:false,
    complete:true,all_changed_paths:true,all_rewritten_commits:true,binary_bodies_included:false,
    source_ref_hex:clean.source_ref_hex,onto_ref_hex:clean.onto_ref_hex,bundle:{bytes:bundle.length,pack_bytes:10,pack_objects:6,
      expanded_bytes:1024,closure_objects:8,transport_only_objects:0,sha256},commit_count:2,
    net_change:diff(command.expected_source,parent,sourceTree,trees[2]),commits:commits.map((c,i)=>({...c,diff:diff(c.parent,c.commit,trees[i],c.tree)}))};
  const conflict = i => ({path_hex:'66696c652eff',kind:'content',base:{mode:0o100644,oid:id(12+i)},
    ours:{mode:0o100755,oid:id(14+i)},theirs:{mode:0o100644,oid:id(16+i)}});
  function stopped(index=0,state='conflicted') {
    const r=structuredClone(clean); for(const k of ['generated_objects','pack_objects','borrowed_objects']) delete r[k];
    return Object.assign(r,{state,series_complete:false,provisional_steps:true,candidate_commit:null,root_tree:null,bundle:null,
      stopped_commit:original[index],conflicts:state==='conflicted'?[conflict(index)]:[],step_count:index,steps:r.steps.slice(0,index)});
  }
  const calls=[], config={ sequence:[],prepare:null,inspect:null,root:null,apply:null,lose:false,outcome:'key_not_observed',wait:null };
  async function fetchImpl(url,options) {
    const endpoint=new URL(url).pathname.split('/api/v1/')[1], decoded=decodeBody(options);
    calls.push({endpoint,options:{...options,body:options.body instanceof Uint8Array?options.body.slice():options.body},...decoded});
    if(config.wait) await config.wait(endpoint);
    if(endpoint==='source/tree') {
      const ref=decoded.command.get('ref'),isSource=ref===command.source_ref;
      const r={...common,type:'source_tree',source_head:sourceHead,snapshot_token:head,source_rcr:'rcr-test',ref,ref_hex:hex(utf8.encode(ref)),
        source_commit:isSource?command.expected_source:onto,root_tree:isSource?sourceTree:trees[0],object_id:isSource?sourceTree:trees[0],
        read_only:true,transaction_created:false,published:false,path_hex:null,after_hex:null,limit:1,entries:[],next_after_hex:null};
      config.root?.(r,calls.length); return response(r);
    }
    if(['source/rebase/prepare','source/rebase/resolve'].includes(endpoint)) {
      let r=structuredClone(config.sequence.length?config.sequence.shift():clean);r.empty=decoded.command.get('empty');
      const descriptors=decoded.command.getAll('resolution');
      if(descriptors.length) {
        const groups=new Map();
        for(const d of descriptors) {
          const [originalId,path,choice,mode,file]=d.split(':');
          const i=original.indexOf(originalId); const c=conflict(i);
          let result=choice==='delete'?null:choice==='file'?{mode:Number.parseInt(mode,8),oid:await objectHash('blob',decoded.files.get(file),algorithm,crypto)}:c[choice];
          if(!groups.has(originalId)) groups.set(originalId,[]);groups.get(originalId).push({conflict:c,choice,result});
        }
        r.resolution_profile='original-commit-path-v1';r.resolution_input_commits=groups.size;
        const consumed=r.steps.map(s=>s.original);if(r.state==='became_empty')consumed.push(r.stopped_commit);
        r.resolutions=[...groups].filter(([id])=>consumed.includes(id)).sort((a,b)=>consumed.indexOf(a[0])-consumed.indexOf(b[0])).map(([original,paths])=>({original,paths:paths.sort((a,b)=>a.conflict.path_hex.localeCompare(b.conflict.path_hex))}));
        r.resolution_consumed_commits=r.resolutions.length;
      }
      await config.prepare?.(r,decoded);
      if(r.state!=='clean')return response(r,409);
      const e=multipart(r,bundle,sha256);return new Response(e.value,{status:200,headers:{'Content-Type':e.type}});
    }
    if(endpoint==='source/rebase/inspect') { const r=structuredClone(inspected);await config.inspect?.(r,decoded);return response(r); }
    if(endpoint==='source/rebase/apply') {
      if(config.lose) throw new TypeError('Simulated lost publication reply');
      const r={type:'rebase_publication',...common,principal_id:actor,ref:command.source_ref,ref_hex:clean.source_ref_hex,
        expected_source:command.expected_source,onto,candidate_commit:clean.candidate_commit,tx_id:'tx-original',outcome:'committed',
        decision_sequence:1,decision_record:'rcr-new',refusal_code:null,delivery_acknowledged:null};
      config.apply?.(r);return response(r,r.outcome==='refused'?409:200);
    }
    if(endpoint==='outcomes') {
      const state=config.outcome,terminal=['committed','refused'].includes(state);
      return response({type:'transaction_outcome',...common,principal_id:actor,selector:'transaction',command_index:null,state,terminal,
        transaction:['undecided','committed','refused'].includes(state)?{tx_id:'tx-original',seal_id:'seal',request_schema:'rebase-v1',canonical_request_digest:{algorithm:2,hex:'a'.repeat(64)}}:null,
        decision:!terminal?null:state==='committed'?{kind:'committed',decision_sequence:1,repository_commit_id:'rcr-new'}:
          {kind:'refused',decision_sequence:1,code:'TargetRefMoved',code_point:1,refusal_record_id:'rcr-refusal'},
        read_only:true,request_reexecuted:false,absence_proves_non_commit:false,session_completeness_established:false});
    }
    throw new Error(`Unexpected endpoint ${endpoint}`);
  }
  return {algorithm,id,common,command,input,original,onto,upstream,sourceTree,trees,clean,inspected,bundle,sha256,
    commits,conflict,stopped,diff,calls,config,fetchImpl};
}
