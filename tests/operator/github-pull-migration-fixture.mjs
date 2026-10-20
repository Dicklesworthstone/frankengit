// Complete source-collection fixture built from the actual capture transport and
// canonical custody codecs. HTTP peers implement response schemas, not authority.
import { mkdtemp, mkdir, writeFile, chmod, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { captureGithubPulls } from '../../scripts/lib/github-pull-source.mjs';
import { githubPullInventoryBytes, GITHUB_PULL_INVENTORY_SCHEMA } from '../../scripts/lib/github-pull-inventory.mjs';
import { collectionPlan, collectionCapture, collectionCheckpoint, completeCollectionBytes,
  encode, hash, batchName } from '../../scripts/lib/github-pull-collection-store.mjs';
import { prepareGithubPullMigration } from '../../scripts/lib/github-pull-migration.mjs';
import { githubPeer, REPO } from './github-pull-fixture.mjs';
import { destinationPeer, selection, NATIVE_TOKEN } from './github-pull-import-fixture.mjs';
export { NATIVE_TOKEN, ROTATED, SCOPE } from './github-pull-import-fixture.mjs';
export const childPath=(f,i)=>join(f.workdir,'batches',`batch-${String(i+1).padStart(6,'0')}`);
export const readJson=async p=>JSON.parse(await readFile(p,'utf8'));
export async function wholeMigrationFixture(t,{pulls=[9,17,23],batchSize=1,source={},destination={},select={},limits={},prepare=true}={}) {
  const root=await mkdtemp(join(tmpdir(),'fg-whole-pr-migration-'));await chmod(root,0o700);
  t.after(()=>rm(root,{recursive:true,force:true}));
  const upstream=await githubPeer(t,{...source,pulls});
  const collectionDir=join(root,'collection');await mkdir(collectionDir,{mode:0o700});
  for(const name of ['captures','journal'])await mkdir(join(collectionDir,name),{mode:0o700});
  const inventory={schema:GITHUB_PULL_INVENTORY_SCHEMA,consistency:'two-equal-membership-observations-not-atomic',
    source:{id:'123',full_name:REPO},batch_size:batchSize,pulls:pulls.map(n=>({number:n,id:String(900+n)})),complete:true};
  const inventoryBytes=githubPullInventoryBytes(inventory),plan=collectionPlan(inventory,hash(inventoryBytes),{}),planBytes=encode(plan),confirm=hash(planBytes);
  await writeFile(join(collectionDir,'inventory.json'),inventoryBytes,{mode:0o600});
  await writeFile(join(collectionDir,'plan.json'),planBytes,{mode:0o600});
  const loaded={inventory,plan,confirm,rows:[],tip:confirm,bytes:0,records:0,pulls:0,tail:null,
    seen:{discussion:new Set(),reviews:new Set(),inline:new Set()}};
  for(let i=0;i<plan.batches;i++) {
    const captured=await captureGithubPulls({...upstream.options,numbers:pulls.slice(i*batchSize,(i+1)*batchSize)});
    const desc=collectionCapture(loaded,i,captured.bytes),checkpoint=collectionCheckpoint(loaded,i,loaded.tip,desc);
    await writeFile(join(collectionDir,'captures',batchName(i)),captured.bytes,{mode:0o600});
    await writeFile(join(collectionDir,'journal',batchName(i)),checkpoint,{mode:0o600});
    loaded.tip=hash(checkpoint);loaded.rows.push(desc);loaded.bytes+=desc.bytes;loaded.records+=desc.records;loaded.pulls+=desc.pulls;
  }
  const complete=completeCollectionBytes(loaded);await writeFile(join(collectionDir,'complete.json'),complete,{mode:0o600});await upstream.close();
  const peer=await destinationPeer(t,destination),tokenFile=join(root,'native.token'),workdir=join(root,'migration');
  await writeFile(tokenFile,NATIVE_TOKEN+'\n',{mode:0o600});
  const input={workdir,collectionDir,collectionConfirm:confirm,completeConfirm:hash(complete),selection:{...selection(peer.endpoint),...select},tokenFile,...limits};
  const prepared=prepare?await prepareGithubPullMigration(input):null;
  return {root,workdir,collectionDir,tokenFile,upstream,peer,input,prepared,
    run:{workdir,confirm:prepared?.plan_sha256,operation:'run',tokenFile}};
}
