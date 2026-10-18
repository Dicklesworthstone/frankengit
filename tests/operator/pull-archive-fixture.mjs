// Native HTTP response-schema peer, not the Rust server or an authority oracle.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, chmod, writeFile, rm, readFile, readdir, unlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

export const TEN='11'.repeat(16), REP='22'.repeat(16), INC='33'.repeat(16), ACT='44'.repeat(16);
export const HEAD='alg:2:'+ '66'.repeat(32), SOURCE='source-head-1', TOKEN='aa'.repeat(32);
export const encode=v=>Buffer.from(`${JSON.stringify(v)}\n`);
export const hash=b=>createHash('sha256').update(b).digest('hex');
const hex=s=>Buffer.from(s).toString('hex');
export function pullRow(n, format='sha1') {
  const tip=c=>`${format}:${c.repeat(format==='sha1'?40:64)}`;
  return {number:n,version:1,state:'open',merge_only:false,data:{object_format:format,
    source_ref:`refs/heads/topic${n}`,source_ref_hex:hex(`refs/heads/topic${n}`),target_ref:'refs/heads/main',target_ref_hex:hex('refs/heads/main'),
    source_tip:tip('a'),target_tip:tip('b'),title:`PR ${n}`,body:`Body ${n}\r\n雪`},opened_by:ACT,last_metadata_actor:ACT,merge:null};
}
export async function fixture(t,{format='sha1',pulls=2,reviews=2,comments=3,changeRow=null,alter=null}={}) {
  const root=await mkdtemp(join(tmpdir(),'fg-pull-archive-')); await chmod(root,0o700);
  const token=join(root,'token'); await writeFile(token,`${TOKEN}\n`,{mode:0o600});
  const requests=[], sockets=new Set();
  const common=()=>({schema_version:1,tenant_id:TEN,repository_id:REP,repository_incarnation:INC,object_format:format,source_head:SOURCE,snapshot_token:HEAD});
  function row(n){const v=pullRow(n,format);changeRow?.(v);return v;}
  const server=createServer(async(req,res)=>{
    try {
      const url=new URL(req.url,'http://127.0.0.1'), parts=url.pathname.split('/'), n=Number(parts[5]);
      assert.equal(req.method,'GET');assert.equal(req.headers.authorization,`Bearer ${TOKEN}`);assert.equal(req.headers['idempotency-key'],undefined);
      const kind=parts[5]===undefined?'list':parts[6]??'show', q=url.searchParams;
      requests.push({kind,number:n||null,after:q.get('after'),head:q.get('expected_head'),method:req.method});
      assert(q.get('expected_head')===HEAD || (kind==='list'&&q.get('after')==='0'&&q.get('expected_head')===null));
      const limit=Number(q.get('limit')??20), after=kind==='reviews'?q.get('after'):Number(q.get('after')??0);
      let reply;
      if(kind==='list'){
        const selected=Array.from({length:Math.min(limit,Math.max(pulls-after,0))},(_,i)=>row(after+i+1));
        reply={...common(),type:'pull_request_page',after,limit,pull_requests:selected,next_after:after+selected.length<pulls?selected.at(-1).number:null};
      }else if(kind==='show')reply={...common(),type:'pull_request',number:n,found:true,pull_request:row(n)};
      else if(kind==='reviews'){
        const all=Array.from({length:reviews},(_,i)=>({reviewer:(i+1).toString(16).padStart(32,'0'),version:1,
          subject:{number:n,source_ref:row(n).data ? row(n).data.source_ref : 'refs/heads/topic',source_ref_hex:row(n).data?.source_ref_hex??hex('refs/heads/topic'),
            target_ref:'refs/heads/main',target_ref_hex:hex('refs/heads/main'),pull_request_version:1,policy_epoch:1,
            source_tip:pullRow(n,format).data.source_tip,target_tip:pullRow(n,format).data.target_tip},
          candidate:null,decision:'approve',freshness:'current',reviewer_is_opener:false,reason:`review ${i}`}));
        const remaining=all.filter(r=>after===null||r.reviewer>after),rs=remaining.slice(0,limit);
        reply={...common(),type:'review_page',number:n,found:true,merge_authorized:false,after,limit,reviews:rs,
          next_after:remaining.length>limit?rs.at(-1).reviewer:null,pull_request_version:1,policy_epoch:1};
      }else if(kind==='comments'){
        const cs=Array.from({length:Math.min(limit,Math.max(comments-after,0))},(_,i)=>({version:after+i+1,actor:ACT,body:`comment ${after+i+1}`,body_rendered:null}));
        const next=after+cs.length<comments?after+cs.length:null;
        reply={...common(),type:'pull_request_comments',number:n,found:true,discussion_version:comments,after,limit,next_after:next,
          complete:next===null,merge_permission:null,transaction_created:false,comments:cs};
      } else throw new Error(`unhandled ${req.url}`);
      const changed=await alter?.({kind,n,after,reply,req,res,count:requests.length});
      if(changed===false)return;
      res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify(reply));
    } catch(error){res.writeHead(500,{'content-type':'application/json'});res.end(JSON.stringify({error:error.message}));}
  });
  server.on('connection',s=>{sockets.add(s);s.on('close',()=>sockets.delete(s));});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  let closed=false;
  const close=async()=>{if(closed)return;closed=true;for(const s of sockets)s.destroy();await new Promise(resolve=>server.close(resolve));};
  t.after(async()=>{await close();await rm(root,{recursive:true,force:true});});
  const out=join(root,'archive'), href=`http://127.0.0.1:${server.address().port}/repo/ui/pulls/`;
  return {root,token,out,href,requests,close,options:{workdir:out,href,tenant:TEN,repository:REP,tokenFile:token,pageSize:1}};
}

// Recompute every local commitment to test semantic refusal separately from pin refusal.
export async function rewriteArchive(root, transform) {
  const m=JSON.parse(await readFile(join(root,'archive.json'),'utf8'));
  let pages=await Promise.all(m.pages.map(async(d,i)=>({desc:{...d},reply:JSON.parse(await readFile(join(root,`page-${String(i+1).padStart(6,'0')}.json`),'utf8'))})));
  pages=transform(pages,m)??pages;
  for(const name of await readdir(root))await unlink(join(root,name));
  m.pages=[];m.pull_count=0;m.review_count=0;m.comment_count=0;m.data_bytes=0;
  for(const [i,p] of pages.entries()){
    const bytes=encode(p.reply);await writeFile(join(root,`page-${String(i+1).padStart(6,'0')}.json`),bytes,{mode:0o600});
    m.pages.push({...p.desc,sha256:hash(bytes),bytes:bytes.length});m.data_bytes+=bytes.length;
    if(p.desc.kind==='list')m.pull_count+=p.reply.pull_requests.length;
    if(p.desc.kind==='reviews')m.review_count+=p.reply.reviews.length;
    if(p.desc.kind==='comments')m.comment_count+=p.reply.comments.length;
  }
  const bytes=encode(m);await writeFile(join(root,'archive.json'),bytes,{mode:0o600});return hash(bytes);
}
