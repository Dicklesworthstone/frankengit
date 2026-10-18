// A batch of independent native create-only branch operations. A crash or lost
// response retains the original key; only an explicit exact-key retry may send
// again. This coordinator cannot update/delete refs or import Git objects.
import { readPrivateOperatorFile } from './forge-operator-io.mjs';
import { fields, bounded, hash, fail, operateBranch } from './branch-bootstrap-protocol.mjs';
import { lifetime, path, loadBootstrap, journal, position, reserve, finishAttempt, summary, readToken }
  from './branch-bootstrap-store.mjs';
export { prepareBootstrap } from './branch-bootstrap-store.mjs';

export async function bootstrapStatus(raw) {
  fields(raw,['workdir','confirm','timeoutMs','signal'],['workdir','confirm']);
  raw={...raw};
  const life=lifetime(raw);
  try{
    const loaded=await loadBootstrap(raw.workdir,raw.confirm,life);
    return {...summary(loaded,await journal(loaded,life)),network_accessed:false,mutation_submitted:false,local_read_only:true};
  }finally{life.close();}
}
export async function runBootstrap(raw) {
  fields(raw,['workdir','confirm','operation','tokenFile','caFile','retryKey','maxOperations','timeoutMs','signal'],['workdir','confirm']);
  raw={...raw};
  const operation=raw.operation??'run';if(!['run','recover'].includes(operation))fail('operation');
  if(raw.retryKey!==undefined && (operation!=='run'||typeof raw.retryKey!=='string'||!/^fgbb1-[0-9a-f]{32}-[0-9a-f]{64}$/.test(raw.retryKey)))fail('retry_key');
  const max=bounded(raw.maxOperations??100,1,8192), life=lifetime(raw);let loaded, count=0, submitted=false;
  try{
    loaded=await loadBootstrap(raw.workdir,raw.confirm,life,true);
    let state=await journal(loaded,life,true), token, ca;
    const initial=position(state);
    if(raw.retryKey!==undefined && (initial===loaded.requests.length||state.steps[initial].attempts===0||loaded.requests[initial].key!==raw.retryKey))fail('retry_not_pending_key');
    while(count<max){
      const index=position(state), prior=state.steps[index];
      if(index===loaded.requests.length||prior.outcome?.state==='refused'||operation==='recover'&&prior.attempts===0)break;
      life.check();const request=loaded.requests[index];
      const sending=operation==='run'&&(prior.attempts===0||raw.retryKey===request.key);
      if(token===undefined){
        token=await readToken(raw.tokenFile,life.check);
        if(raw.caFile!==undefined)ca=await readPrivateOperatorFile(path(raw.caFile),128*1024,life.check);
      }
      // A rotated credential may recover an old key, but never create the next
      // branch or retransmit a body in a different principal's namespace.
      if(sending&&hash(Buffer.from(token))!==loaded.manifest.credential_sha256)fail('original_credential');
      const mode=sending?(prior.attempts?'retry':'send'):'recover';
      const reservation=await reserve(loaded,state,index,mode,life);count++;
      let result,error=null;
      try{
        result=await operateBranch(request,token,{send:sending,signal:life.signal,timeoutMs:life.remaining(),ca,
          known:prior.outcome,publication:prior.publication});
      }catch(cause){error=cause;result=cause.observation??{outcome:prior.outcome,publication:prior.publication,dispatched:false};}
      submitted ||= result.dispatched;
      await finishAttempt(loaded,reservation,result,error);
      // Always leave the received result in custody, even if the caller stops
      // before a full status readback or while the local finalizer is syncing.
      state=await journal(loaded,life,true);
      if(error||position(state)===index)break;
    }
    return {...summary(loaded,state),operations:count,network_accessed:count>0,mutation_submitted:submitted};
  }catch(cause){
    const e=cause instanceof Error?cause:new Error('branch_bootstrap_interrupted');
    e.bootstrap_progress={workdir:raw.workdir,plan_sha256:raw.confirm,plan_verified:Boolean(loaded),
      operations:count,mutation_may_have_been_submitted:count>0,complete:false};throw e;
  }finally{life.close();}
}

// Expose the complete immutable requirements for independent review. Execution
// history is still validated, but request bodies, tokens and credentials are not
// needed or printed. This never treats a historical terminal as current refs.
export async function inspectBootstrap(raw) {
  fields(raw,['workdir','confirm','timeoutMs','signal'],['workdir','confirm']);
  raw={...raw};const life=lifetime(raw);
  try {
    const loaded=await loadBootstrap(raw.workdir,raw.confirm,life);
    return { ...summary(loaded,await journal(loaded,life)), type:'branch_bootstrap_inspected',
      selection:loaded.selection, network_accessed:false,mutation_submitted:false,local_read_only:true };
  } finally { life.close(); }
}
