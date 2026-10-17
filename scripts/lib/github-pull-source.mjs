// FG-049: foreign PR observations. GitHub aliases, draft/merge observations and
// review locations never become native principals, approvals or snapshot tokens.
import { isDeepStrictEqual } from 'node:util';
import { createGithubSource, githubIdentity as id, githubRepository, GITHUB_API as API }
  from './github-source-http.mjs';
import { recordDigest, operatorError } from './forge-operator-io.mjs';

export const GITHUB_PULL_SCHEMA = 'frankengit-github-pull-capture-v1';
export const GITHUB_PULL_LIMITS = Object.freeze({ pulls:100, records:2000, bytes:1024*1024 });
const L = GITHUB_PULL_LIMITS, CONSISTENCY = 'two-equal-observations-not-atomic';
export const githubPullFail = code => { throw operatorError(`github_pull_${code}`); };
const fail = githubPullFail;
export const encodeGithubPulls = v => Buffer.from(`${JSON.stringify(v)}\n`);
export function pullSourceFields(v,names,required=names) {
  if (!v || typeof v!=='object' || Array.isArray(v) || ![Object.prototype,null].includes(Object.getPrototypeOf(v)) ||
      Object.keys(v).some(k=>!names.includes(k)) || required.some(k=>!Object.hasOwn(v,k)) ||
      Object.values(Object.getOwnPropertyDescriptors(v)).some(d=>!Object.hasOwn(d,'value'))) fail('fields');
  return v;
}
const object = v => { if(!v || typeof v!=='object' || Array.isArray(v))fail('object');return v; };
export function pullSourceNumber(v,min=0,max=Number.MAX_SAFE_INTEGER) {
  if(!Number.isSafeInteger(v)||v<min||v>max)fail('number');return v;
}
function text(v,max,single=false) {
  if(typeof v!=='string'||v.length>max||Buffer.byteLength(v)>max||/[\0\uD800-\uDFFF]/u.test(v)||
      single&&(!v.trim()||/[\x00-\x1f\x7f-\x9f]/u.test(v)))fail('text');return v;
}
function timestamp(v,nullable=false) {
  if(nullable&&v===null)return null;
  if(typeof v!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(v)||!Number.isFinite(Date.parse(v))||
      new Date(v).toISOString()!==v.replace('Z','.000Z'))fail('timestamp');return v;
}
function oid(v,nullable=false) {
  if(nullable&&v===null)return null;
  if(typeof v!=='string'||!/^[0-9a-f]{40}$/.test(v)||/^0+$/.test(v))fail('sha1_oid');return v;
}
function actor(v) { if(v===null)return null;object(v);return {id:id(v.id),login:text(v.login,100,true)}; }
function source(v) { object(v);return {id:id(v.id),full_name:githubRepository(v.full_name)}; }
function link(v,repository,number,fragment=false,api=false) {
  text(v,4096,true);let u;try{u=new URL(v);}catch{fail('link');}
  const path=`/${api?'repos/':''}${repository}/${api?'pulls':'pull'}/${number}`;
  if(u.origin!==(api?API:'https://github.com')||u.username||u.password||u.search||u.href!==v||u.pathname!==path||
      (fragment?!/^#[A-Za-z0-9_-]+$/.test(u.hash):Boolean(u.hash)))fail('link_scope');return v;
}
function labels(raw) {
  if(!Array.isArray(raw)||raw.length>100)fail('labels');
  const rows=raw.map(r=>{object(r);if(typeof r.color!=='string'||!/^[0-9a-fA-F]{6}$/.test(r.color))fail('label_color');
    return {id:id(r.id),name:text(r.name,256,true),color:r.color,description:r.description===null?null:text(r.description,4096)};
  }).sort((a,b)=>BigInt(a.id)<BigInt(b.id)?-1:1);
  if(new Set(rows.map(r=>r.id)).size!==rows.length)fail('duplicate_label');return rows;
}
function coordinate(v) {
  object(v);return {label:v.label===null?null:text(v.label,2048,true),ref:text(v.ref,1024,true),sha:oid(v.sha),repo:v.repo===null?null:source(v.repo)};
}
function metadata(raw,selected,number) {
  object(raw);const repository=selected.full_name;
  if(raw.number!==number||!['open','closed'].includes(raw.state)||
      ['merged','draft','locked'].some(k=>typeof raw[k]!=='boolean'))fail('pull_state');
  const created=timestamp(raw.created_at),updated=timestamp(raw.updated_at),closed=timestamp(raw.closed_at,true),merged=timestamp(raw.merged_at,true);
  if(created>updated||(raw.state==='open')!==(closed===null)||raw.merged!==(merged!==null)||raw.merged&&raw.state!=='closed')fail('pull_timestamps');
  const base=coordinate(raw.base),head=coordinate(raw.head);
  if(!isDeepStrictEqual(base.repo,selected))fail('base_repository');
  if(!Array.isArray(raw.assignees)||raw.assignees.length>100)fail('assignees');
  const assignees=raw.assignees.map(actor).sort((a,b)=>!a||!b?fail('assignee'):BigInt(a.id)<BigInt(b.id)?-1:1);
  if(assignees.includes(null)||new Set(assignees.map(a=>a.id)).size!==assignees.length)fail('assignee');
  let milestone=null;
  if(raw.milestone!==null){const m=object(raw.milestone);if(!['open','closed'].includes(m.state))fail('milestone');
    milestone={id:id(m.id),number:pullSourceNumber(m.number,1),title:text(m.title,4096),state:m.state};}
  return {id:id(raw.id),number,html_url:link(raw.html_url,repository,number),title:text(raw.title,1024,true),
    body:raw.body===null?null:text(raw.body,256*1024),state:raw.state,draft:raw.draft,merged:raw.merged,locked:raw.locked,
    user:actor(raw.user),merged_by:actor(raw.merged_by),created_at:created,updated_at:updated,closed_at:closed,merged_at:merged,
    merge_commit_sha:oid(raw.merge_commit_sha,true),base,head,labels:labels(raw.labels),assignees,milestone,
    comments:pullSourceNumber(raw.comments,0,L.records),review_comments:pullSourceNumber(raw.review_comments,0,L.records)};
}
function discussion(raw,repository,number) {
  object(raw);const identity=id(raw.id),created=timestamp(raw.created_at),updated=timestamp(raw.updated_at);
  if(created>updated||raw.issue_url!==`${API}/repos/${repository}/issues/${number}`)fail('discussion_scope');
  const html=link(raw.html_url,repository,number,true);
  if(!html.endsWith(`#issuecomment-${identity}`))fail('discussion_scope');
  return {id:identity,html_url:html,issue_url:raw.issue_url,user:actor(raw.user),created_at:created,updated_at:updated,body:text(raw.body,65536)};
}
function review(raw,repository,number) {
  object(raw);if(!['APPROVED','CHANGES_REQUESTED','COMMENTED','DISMISSED'].includes(raw.state))fail('unsubmitted_or_unknown_review');
  return {id:id(raw.id),html_url:link(raw.html_url,repository,number,true),pull_request_url:link(raw.pull_request_url,repository,number,false,true),
    user:actor(raw.user),body:text(raw.body,65536),state:raw.state,commit_id:oid(raw.commit_id),submitted_at:timestamp(raw.submitted_at)};
}
function inline(raw,repository,number) {
  object(raw);const created=timestamp(raw.created_at),updated=timestamp(raw.updated_at);if(created>updated)fail('comment_timestamps');
  const result={id:id(raw.id),html_url:link(raw.html_url,repository,number,true),pull_request_url:link(raw.pull_request_url,repository,number,false,true),
    user:actor(raw.user),body:text(raw.body,65536),created_at:created,updated_at:updated,
    path:text(raw.path,4096,true),diff_hunk:text(raw.diff_hunk,65536),commit_id:oid(raw.commit_id),original_commit_id:oid(raw.original_commit_id),
    pull_request_review_id:raw.pull_request_review_id==null?null:id(raw.pull_request_review_id),in_reply_to_id:raw.in_reply_to_id==null?null:id(raw.in_reply_to_id)};
  for(const k of ['position','original_position','line','original_line','start_line','original_start_line'])result[k]=raw[k]==null?null:pullSourceNumber(raw[k]);
  for(const k of ['side','start_side']){if(raw[k]!=null&&!['LEFT','RIGHT'].includes(raw[k]))fail('comment_side');result[k]=raw[k]??null;}
  if(raw.subject_type!=null&&!['line','file'].includes(raw.subject_type))fail('comment_subject');result.subject_type=raw.subject_type??null;
  return result;
}
const NORMALIZE={discussion, reviews:review, inline};
function numbers(v) {
  if(!Array.isArray(v)||!v.length||v.length>L.pulls)fail('selection');
  const result=v.map(n=>pullSourceNumber(n,1)).sort((a,b)=>a-b);
  if(new Set(result).size!==result.length)fail('duplicate_pull');return result;
}
export function githubPullCaptureBytes(value) {
  object(value);if(value.schema!==GITHUB_PULL_SCHEMA||value.consistency!==CONSISTENCY||!Array.isArray(value.pulls))fail('schema');
  const selected=source(value.source),order=numbers(value.pulls.map(e=>object(e).pull?.number)),seen=new Set(),ids={discussion:new Set(),reviews:new Set(),inline:new Set()};
  let count=0;
  const checked={schema:GITHUB_PULL_SCHEMA,consistency:CONSISTENCY,source:selected,pulls:value.pulls.map((e,i)=>{
    const pull=metadata(e.pull,selected,order[i]);if(seen.has(pull.id))fail('duplicate_pull_id');seen.add(pull.id);
    const entry={pull};
    for(const kind of Object.keys(NORMALIZE)){
      if(!Array.isArray(e[kind]))fail('records');count+=e[kind].length;if(count>L.records)fail('record_limit');
      entry[kind]=e[kind].map(r=>{const row=NORMALIZE[kind](r,selected.full_name,pull.number);
        if(ids[kind].has(row.id))fail('duplicate_record');ids[kind].add(row.id);return row;});
    }
    if(entry.discussion.length!==pull.comments||entry.inline.length!==pull.review_comments)fail('comment_count');return entry;
  })};
  const bytes=encodeGithubPulls(checked);if(bytes.length>L.bytes)fail('capture_bytes');
  if(!isDeepStrictEqual(checked,value))fail('noncanonical_capture');return bytes;
}
export function parseGithubPullCapture(bytes) {
  if(!(bytes instanceof Uint8Array)||bytes.length>L.bytes)fail('capture_bytes');
  const value=JSON.parse(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes));
  if(!githubPullCaptureBytes(value).equals(Buffer.from(bytes)))fail('noncanonical_capture');return value;
}
// Validate pagination links, but construct requests ourselves. The server cannot
// use a next-page URL to change repositories, credentials, selection or endpoint.
function hasNext(header,path,repoId,number,kind,page) {
  if(!header)return false;if(header.length>8192)fail('pagination');const seen=new Set();let next=false;
  for(const part of header.split(',')){
    const m=/^\s*<([^<>]+)>;\s*rel="(next|prev|first|last)"\s*$/.exec(part);
    if(!m||seen.has(m[2]))fail('pagination');seen.add(m[2]);
    const u=new URL(m[1]),q=u.searchParams,byId=`/repositories/${repoId}/${kind==='discussion'?`issues/${number}/comments`:`pulls/${number}/${kind==='reviews'?'reviews':'comments'}`}`;
    if(u.origin!==API||u.username||u.password||u.hash||![path,byId].includes(u.pathname)||
        [...q.keys()].length!==2||q.get('per_page')!=='100'||!/^\d+$/.test(q.get('page')??''))fail('pagination_scope');
    const n=Number(q.get('page'));pullSourceNumber(n,1,4096);
    if(m[2]==='next'){if(n!==page+1)fail('pagination_sequence');next=true;}
  }
  return next;
}
// An inventory pins membership/aliases, not mutable metadata or a GitHub snapshot.
// Own this selection before the first await; callers cannot change a later batch.
function expectedSelection(raw, selectedNumbers, repository) {
  if (raw === null) return null;
  pullSourceFields(raw, ['source', 'pulls']);
  pullSourceFields(raw.source, ['id', 'full_name']);
  const selected = source(raw.source);
  if (selected.full_name.toLowerCase() !== repository.toLowerCase() || !Array.isArray(raw.pulls) ||
      raw.pulls.length !== selectedNumbers.length) fail('inventory_selection');
  const seen = new Set();
  const pulls = raw.pulls.map((row, i) => {
    pullSourceFields(row, ['number', 'id']);
    const number = pullSourceNumber(row.number, 1), identity = id(row.id);
    if (number !== selectedNumbers[i] || seen.has(identity)) fail('inventory_selection');
    seen.add(identity); return { number, id: identity };
  });
  return { source: selected, pulls };
}
const SESSION_FIELDS = ['repository', 'token', 'signal', 'timeoutMs', 'maxReadBytes', 'maxRequests', 'fetchImpl'];

// One deadline and HTTP/response-byte allowance spans every batch in this owner.
// No transport supplied by a capture file and no budget renewal between batches.
export function createGithubPullCaptureSession(raw) {
  pullSourceFields(raw, SESSION_FIELDS, ['repository']);
  const repository = githubRepository(raw.repository);
  const owner = createGithubSource({ token: raw.token ?? null, signal: raw.signal, timeoutMs: raw.timeoutMs ?? 300000,
    maxReadBytes: raw.maxReadBytes ?? 64*1024*1024, maxRequests: raw.maxRequests ?? 4096, fetchImpl: raw.fetchImpl ?? globalThis.fetch });
  const repoPath = `/repos/${repository}`;
  let busy = false, closed = false;
  const close = () => { closed = true; owner.close(); };
  async function capture(selection, options = {}) {
    pullSourceFields(options, ['expectedSelection'], []);
    const selectedNumbers = numbers(selection), expected = expectedSelection(options.expectedSelection ?? null, selectedNumbers, repository);
    if (closed) fail('capture_session_closed');
    if (busy) fail('capture_session_busy');
    busy = true;
    try {
    const observe=async()=>{
      const selected=source((await owner.get(repoPath)).value);
      if(selected.full_name.toLowerCase()!==repository.toLowerCase())fail('repository_changed');
      if(expected && !isDeepStrictEqual(selected,expected.source))fail('inventory_repository_changed');
      const root=`/repos/${selected.full_name}`,pulls=[];let count=0;
      for(const n of selectedNumbers){
        owner.check();const pull=metadata((await owner.get(`${root}/pulls/${n}`)).value,selected,n),entry={pull};
        if(expected && pull.id!==expected.pulls.find(row=>row.number===n).id)fail('inventory_pull_changed');
        for(const kind of Object.keys(NORMALIZE)){
          const path=kind==='discussion'?`${root}/issues/${n}/comments`:`${root}/pulls/${n}/${kind==='reviews'?'reviews':'comments'}`;
          entry[kind]=[];let page=1;
          for(;;){
            const {value,link}=await owner.get(`${path}?per_page=100&page=${page}`);
            if(!Array.isArray(value)||value.length>100)fail('page');count+=value.length;if(count>L.records)fail('record_limit');
            const rows=value.map(r=>NORMALIZE[kind](r,selected.full_name,n));entry[kind].push(...rows);
            if(encodeGithubPulls([...pulls,entry]).length>L.bytes)fail('capture_bytes');
            if(!hasNext(link,path,selected.id,n,kind,page))break;
            if(value.length!==100)fail('incomplete_page');page++;
          }
        }
        if(!isDeepStrictEqual(pull,metadata((await owner.get(`${root}/pulls/${n}`)).value,selected,n)))fail('source_changed');
        pulls.push(entry);
      }
      if(!isDeepStrictEqual(selected,source((await owner.get(repoPath)).value)))fail('repository_changed');
      const capture={schema:GITHUB_PULL_SCHEMA,consistency:CONSISTENCY,source:selected,pulls};
      return {capture,bytes:githubPullCaptureBytes(capture)};
    };
    const first=await observe(),second=await observe();owner.check();
    if(!first.bytes.equals(second.bytes))fail('source_changed');
    return {...second,sha256:recordDigest(second.bytes),statistics:owner.statistics(),atomic_snapshot:false,mutation_submitted:false};
    } catch (error) { close(); throw error; }
    finally { busy = false; }
  }
  return Object.freeze({ capture, check: owner.check, statistics: owner.statistics, close });
}

export async function captureGithubPulls(raw) {
  pullSourceFields(raw, [...SESSION_FIELDS, 'numbers', 'expectedSelection'], ['repository', 'numbers']);
  const repository = githubRepository(raw.repository), selected = numbers(raw.numbers);
  const expected = expectedSelection(raw.expectedSelection ?? null, selected, repository);
  const config = Object.fromEntries(SESSION_FIELDS.filter(k => Object.hasOwn(raw, k)).map(k => [k, raw[k]]));
  const session = createGithubPullCaptureSession(config);
  try { return await session.capture(selected, { expectedSelection: expected }); }
  finally { session.close(); }
}
