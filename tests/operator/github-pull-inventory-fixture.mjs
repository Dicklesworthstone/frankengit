// Local schema peer; no live GitHub, Git object validation, or native authority.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { rawPull, rawDiscussion, rawReview, rawInline, SOURCE, REPO, TOKEN } from './github-pull-fixture.mjs';
export { REPO, TOKEN, SOURCE };
export async function inventoryPeer(t,{pulls=[9,17],records=0,alter=null}={}) {
  const calls=[],sockets=new Set(),fetch=globalThis.fetch;
  const server=createServer(async(req,res)=>{
    try {
      assert.equal(req.method,'GET');assert.equal(req.headers['idempotency-key'],undefined);
      const url=new URL(req.url,'http://127.0.0.1'),parts=url.pathname.split('/'),page=Number(url.searchParams.get('page')??1),n=Number(parts[5]);
      assert.equal(parts[1],'repos');assert.equal(`${parts[2]}/${parts[3]}`,REPO);
      const kind=parts.length===4?'repository':parts.length===5?'listing':parts[4]==='issues'?'discussion':parts.length===6?'pull':parts[6]==='reviews'?'reviews':'inline';
      calls.push({kind,n,page,path:req.url,authorization:req.headers.authorization});
      let value,link=null;
      if(kind==='repository')value=structuredClone(SOURCE);
      else if(kind==='listing') {
        assert.deepEqual(Object.fromEntries(url.searchParams),{state:'all',sort:'created',direction:'asc',per_page:'100',page:String(page)});
        value=pulls.slice((page-1)*100,page*100).map(number=>({id:900+number,number,state:'open',draft:false,
          url:`https://api.github.com/repos/${REPO}/pulls/${number}`,html_url:`https://github.com/${REPO}/pull/${number}`,base:{repo:structuredClone(SOURCE)}}));
        if(page*100<pulls.length) { url.searchParams.set('page',String(page+1));link=`<https://api.github.com${url.pathname}${url.search}>; rel="next"`; }
      } else {
        assert(pulls.includes(n));
        if(kind==='pull'){value=rawPull(n);value.comments=records;value.review_comments=records;}
        else {
          const create=kind==='discussion'?rawDiscussion:kind==='reviews'?rawReview:rawInline;
          value=Array.from({length:Math.min(100,Math.max(records-(page-1)*100,0))},(_,i)=>create(n,n*10000+page*100+i+1));
          if(page*100<records)link=`<https://api.github.com${url.pathname}?per_page=100&page=${page+1}>; rel="next"`;
        }
      }
      const state={kind,n,page,value,link,req,res,count:calls.length};if(await alter?.(state)===false)return;
      res.writeHead(200,{'content-type':'application/json',...(state.link?{link:state.link}:{})});res.end(JSON.stringify(state.value));
    }catch(error){res.writeHead(500,{'content-type':'application/json'});res.end(JSON.stringify({error:error.message}));}
  });
  server.on('connection',s=>{sockets.add(s);s.on('close',()=>sockets.delete(s));});
  await new Promise(r=>server.listen(0,'127.0.0.1',r));const origin=`http://127.0.0.1:${server.address().port}`;
  let closed=false;const close=async()=>{if(closed)return;closed=true;for(const s of sockets)s.destroy();await new Promise(r=>server.close(r));};t.after(close);
  const fetchImpl=async(input,options)=>{
    const url=new URL(input);assert.equal(url.origin,'https://api.github.com');assert.equal(options.redirect,'error');assert.equal(options.credentials,'omit');
    const response=await fetch(origin+url.pathname+url.search,options);
    return new Response(response.body,{status:response.status,headers:response.headers});
  };
  return {calls,origin,close,fetchImpl,options:{repository:REPO,token:TOKEN,fetchImpl}};
}
