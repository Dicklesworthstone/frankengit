import { mkdtemp, chmod, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { discoverGithubPulls } from '../../scripts/lib/github-pull-inventory.mjs';
import { prepareGithubPullCollection } from '../../scripts/lib/github-pull-collection.mjs';
import { inventoryPeer, TOKEN } from './github-pull-inventory-fixture.mjs';
export async function collectionFixture(t,source={},options={}) {
  const peer=await inventoryPeer(t,source),inventory=await discoverGithubPulls({...peer.options,batchSize:options.batchSize??1});
  const root=await mkdtemp(join(tmpdir(),'fg-pull-collection-'));await chmod(root,0o700);t.after(()=>rm(root,{recursive:true,force:true}));
  const inventoryFile=join(root,'inventory.json'),tokenFile=join(root,'token'),workdir=join(root,'job');
  await writeFile(inventoryFile,inventory.bytes,{mode:0o600});await writeFile(tokenFile,TOKEN,{mode:0o600});
  const {batchSize,...limits}=options;
  const prepared=await prepareGithubPullCollection({workdir,inventoryFile,inventoryConfirm:inventory.sha256,...limits});
  return {...peer,root,inventoryFile,tokenFile,workdir,inventory,prepared,
    run:{workdir,confirm:prepared.plan_sha256,tokenFile,fetchImpl:peer.fetchImpl},status:{workdir,confirm:prepared.plan_sha256}};
}
