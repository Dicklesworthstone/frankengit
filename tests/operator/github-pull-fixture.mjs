// A real HTTP response-schema peer, not GitHub or a native admission engine.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
export const REPO='acme/project', TOKEN='github_pat_test', AT='2026-10-01T12:00:00Z';
export const ACTOR={id:7,login:'alice'}, SOURCE={id:123,full_name:REPO};
export function rawPull(n=9){return {id:900+n,number:n,html_url:`https://github.com/${REPO}/pull/${n}`,title:`Change ${n}`,
  body:'\ufeffexact body\r\nwith 雪\n',state:'open',draft:false,merged:false,locked:false,user:ACTOR,merged_by:null,
  created_at:AT,updated_at:AT,closed_at:null,merged_at:null,merge_commit_sha:null,
  base:{label:'acme:main',ref:'main',sha:'b'.repeat(40),repo:structuredClone(SOURCE)},
  head:{label:'alice:topic',ref:'topic',sha:'a'.repeat(40),repo:{id:456,full_name:'alice/project'}},
  labels:[{id:11,name:'bug',color:'abcdef',description:null}],assignees:[ACTOR],milestone:null,comments:1,review_comments:1};}
export function rawDiscussion(n=9,id=101){return {id,html_url:`https://github.com/${REPO}/pull/${n}#issuecomment-${id}`,
  issue_url:`https://api.github.com/repos/${REPO}/issues/${n}`,user:ACTOR,created_at:AT,updated_at:AT,body:'discussion\r\n'};}
export function rawReview(n=9,id=201){return {id,html_url:`https://github.com/${REPO}/pull/${n}#pullrequestreview-${id}`,
  pull_request_url:`https://api.github.com/repos/${REPO}/pulls/${n}`,user:ACTOR,body:'review\n',state:'APPROVED',commit_id:'a'.repeat(40),submitted_at:AT};}
export function rawInline(n=9,id=301){return {id,html_url:`https://github.com/${REPO}/pull/${n}#discussion_r${id}`,
  pull_request_url:`https://api.github.com/repos/${REPO}/pulls/${n}`,user:ACTOR,body:'inline\ufeff\r\n',created_at:AT,updated_at:AT,
  path:'src/main.rs',diff_hunk:'@@ -1 +1 @@\n-old\n+new\n',commit_id:'a'.repeat(40),original_commit_id:'c'.repeat(40),
  pull_request_review_id:201,in_reply_to_id:null,position:1,original_position:1,line:1,original_line:1,start_line:null,
  original_start_line:null,side:'RIGHT',start_side:null,subject_type:'line'};}
export async function githubPeer(t,{pulls=[9],discussions=1,reviews=1,inlines=1,alter=null}={}){
  const calls=[],sockets=new Set(),sourceFetch=globalThis.fetch;
  const server=createServer(async(req,res)=>{
    try{
      assert.equal(req.method,'GET');assert.equal(req.headers['idempotency-key'],undefined);
      const u=new URL(req.url,'http://127.0.0.1'),parts=u.pathname.split('/'),n=Number(parts[5]),page=Number(u.searchParams.get('page')??1);
      const kind=parts.length===4?'repository':parts[4]==='issues'?'discussion':parts.length===6?'pull':parts[6]==='reviews'?'reviews':'inline';
      assert.equal(parts[1],'repos');assert.equal(`${parts[2]}/${parts[3]}`,REPO);
      if(kind!=='repository')assert(pulls.includes(n));
      calls.push({kind,n,page,authorization:req.headers.authorization,version:req.headers['x-github-api-version']});
      let value,link=null;
      if(kind==='repository')value=structuredClone(SOURCE);
      else if(kind==='pull'){value=rawPull(n);value.comments=discussions;value.review_comments=inlines;}
      else{
        const total=kind==='discussion'?discussions:kind==='reviews'?reviews:inlines;
        const create=kind==='discussion'?rawDiscussion:kind==='reviews'?rawReview:rawInline;
        value=Array.from({length:Math.min(100,Math.max(total-(page-1)*100,0))},(_,i)=>create(n,n*10000+page*100+i+1));
        if(page*100<total)link=`<https://api.github.com${u.pathname}?per_page=100&page=${page+1}>; rel="next"`;
      }
      const state={value,link,kind,n,page,req,res,count:calls.length};
      if(await alter?.(state)===false)return;
      res.writeHead(200,{'content-type':'application/json',...(state.link?{link:state.link}:{})});res.end(JSON.stringify(state.value));
    }catch(e){res.writeHead(500,{'content-type':'application/json'});res.end(JSON.stringify({error:e.message}));}
  });
  server.on('connection',s=>{sockets.add(s);s.on('close',()=>sockets.delete(s));});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const origin=`http://127.0.0.1:${server.address().port}`;
  let closed=false;const close=async()=>{if(closed)return;closed=true;for(const s of sockets)s.destroy();await new Promise(r=>server.close(r));};
  t.after(close);
  const fetchImpl=async(url,init)=>{
    assert.equal(new URL(url).origin,'https://api.github.com');assert.equal(init.redirect,'error');assert.equal(init.credentials,'omit');
    const target=new URL(url),response=await sourceFetch(origin+target.pathname+target.search,init);
    return new Response(response.body,{status:response.status,headers:response.headers});
  };
  return {calls,close,origin,fetchImpl,options:{repository:REPO,numbers:pulls,token:TOKEN,fetchImpl}};
}
