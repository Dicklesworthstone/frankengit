// Foreign aliases remain provenance. Only native open/comment/close commands are
// compiled; never synthesize native snapshots, actors, approvals or merge events.
import { pullFields,pullScope,pullU64,pullCommand,pullHash } from '../operator/pull_command.mjs';
import { outcomeEndpoint } from '../operator/transaction_outcome.mjs';
import { githubPullCaptureBytes,parseGithubPullCapture,encodeGithubPulls,pullSourceNumber,githubPullFail as fail } from './github-pull-source.mjs';

export const GITHUB_PULL_IMPORT_SCHEMA='frankengit-github-pull-import-v1';
export const GITHUB_PULL_IMPORT_LIMITS=Object.freeze({steps:8192,requestBytes:64*1024*1024});
const L=GITHUB_PULL_IMPORT_LIMITS;
export function githubPullImportSelection(raw){
  const required=['endpoint','scope','number_start','namespace'];
  pullFields(raw,[...required,'merged','drafts','max_steps','max_request_bytes'],required);
  const scope=pullScope(raw.scope),endpoint=outcomeEndpoint(raw.endpoint),number_start=pullU64(raw.number_start,1n);
  if(scope.object_format!=='sha1')fail('destination_hash_domain');
  // This deliberately narrow generated-name namespace has no escaping or lossy
  // conversion of GitHub fork/ref labels. Actual commands use the native codec.
  if(typeof raw.namespace!=='string'||raw.namespace.length>900||!/^refs\/heads\/(?:[A-Za-z0-9_-]+\/)+$/.test(raw.namespace))fail('destination_namespace');
  const merged=raw.merged??'refuse',drafts=raw.drafts??'refuse';
  if(!['refuse','as-closed'].includes(merged)||!['refuse','as-ordinary'].includes(drafts))fail('lifecycle_consent');
  return {endpoint,scope,number_start,namespace:raw.namespace,merged,drafts,
    max_steps:pullSourceNumber(raw.max_steps??L.steps,1,L.steps),
    max_request_bytes:pullSourceNumber(raw.max_request_bytes??L.requestBytes,1,L.requestBytes)};
}
function parts(value){
  const bytes=Buffer.from(JSON.stringify(value)),result=[];
  for(let at=0;at<bytes.length;){let end=Math.min(at+32*1024,bytes.length);
    while(end<bytes.length&&(bytes[end]&0xc0)===0x80)end--;
    result.push(bytes.subarray(at,end).toString('utf8'));at=end;}
  return {parts:result,sha256:pullHash(bytes)};
}
export function compileGithubPullImport(rawCapture,rawSelection){
  // Detach and fully validate source before any caller can mutate its nested data.
  const bytes=githubPullCaptureBytes(rawCapture),capture=parseGithubPullCapture(bytes),selection=githubPullImportSelection(rawSelection);
  const captureSha256=pullHash(bytes),steps=[],mapping=[],refs=[];let encodedBytes=0;
  const add=(sourceNumber,number,action,fields)=>{
    if(steps.length===selection.max_steps)fail('import_step_limit');
    const command=pullCommand(number,action,fields,selection.scope.object_format);
    encodedBytes+=Buffer.byteLength(command.body);if(encodedBytes>selection.max_request_bytes)fail('import_request_limit');
    steps.push({source_number:sourceNumber,...command});
  };
  for(const [index,entry] of capture.pulls.entries()){
    const p=entry.pull,number=pullU64(String(BigInt(selection.number_start)+BigInt(index)),1n);
    if(p.merged&&selection.merged!=='as-closed')fail('merged_requires_consent');
    if(p.draft&&selection.drafts!=='as-ordinary')fail('draft_requires_consent');
    const source_ref=`${selection.namespace}pr-${p.number}/head`,target_ref=`${selection.namespace}pr-${p.number}/base`;
    const fields={source_ref,target_ref,source_tip:p.head.sha,target_tip:p.base.sha,title:p.title,body:p.body??''};
    add(p.number,number,'open',{expected_version:'0',...fields});
    refs.push({ref:source_ref,new_commit:p.head.sha},{ref:target_ref,new_commit:p.base.sha});
    mapping.push({source:p.number,source_id:p.id,destination:number,source_state:p.merged?'merged':p.state,
      source_draft:p.draft,destination_state:p.state,source_ref,target_ref});
    let discussion=0;
    const observation=(kind,record)=>{
      const encoded=parts(record);
      for(const [part,payload] of encoded.parts.entries()){
        const header={schema:'frankengit-imported-github-observation-v1',capture_sha256:captureSha256,
          repository:capture.source,source_number:p.number,kind,source_id:record.id,
          encoding:'utf8-json-fragment',sha256:encoded.sha256,part:part+1,parts:encoded.parts.length};
        const body=`Imported GitHub ${kind}. Historical attribution only; not native approval, authority or audit history.\n${JSON.stringify(header)}\n\n${payload}`;
        add(p.number,number,'comment',{expected_version:String(discussion++),body});
      }
    };
    observation('pull-metadata',p);
    for(const row of entry.discussion)observation('discussion-comment',row);
    for(const row of entry.reviews)observation('review',row);
    for(const row of entry.inline)observation('inline-review-comment',row);
    if(p.state==='closed')add(p.number,number,'close',{expected_version:'1',...fields});
  }
  refs.sort((a,b)=>Buffer.compare(Buffer.from(a.ref),Buffer.from(b.ref)));
  return {selection,captureSha256,steps,mapping,refs,encodedBytes,stepsSha256:pullHash(encodeGithubPulls(steps))};
}
