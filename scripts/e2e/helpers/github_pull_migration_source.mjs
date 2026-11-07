// Synthetic GitHub INPUT only. Actual source/destination CLIs run separately.
import { writeFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { REPO, TOKEN } from '../../../tests/operator/github-pull-inventory-fixture.mjs';
import { batchName } from '../../lib/github-pull-collection-store.mjs';
import { parseGithubPullCapture } from '../../lib/github-pull-source.mjs';
import { recordDigest } from '../../lib/forge-operator-io.mjs';

const [mode, root, head, base] = process.argv.slice(2);
if (mode === 'setup' && process.argv.length === 6 && [head, base].every(s => /^[0-9a-f]{40}$/.test(s))) {
  const preload = join(root, 'source-peer.mjs'), log = join(root, 'source-requests.ndjson');
  const token = join(root, 'source-token');
  const fixture = new URL('../../../tests/operator/github-pull-inventory-fixture.mjs', import.meta.url).href;
  await writeFile(preload, `import { inventoryPeer } from ${JSON.stringify(fixture)};
import { appendFile } from 'node:fs/promises';
const head=${JSON.stringify(head)},base=${JSON.stringify(base)};
const peer=await inventoryPeer({after(){}},{pulls:[9,17],records:1,alter:({kind,n,value})=>{
  if(kind==='pull'){
    value.head.sha=head;value.base.sha=base;value.title+=' 雪';
    if(n===17){value.state='closed';value.closed_at=value.updated_at;}
  }else if(kind==='reviews'||kind==='inline'){
    for(const row of value){row.commit_id=head;if(kind==='inline')row.original_commit_id=base;}
  }
}});
peer.unref();process.once('beforeExit',()=>peer.close());
globalThis.fetch=async(address,options)=>{
  await appendFile(${JSON.stringify(log)},JSON.stringify({address})+'\\n',{mode:0o600});
  return peer.fetchImpl(address,options);
};
`, { mode: 0o600, flag: 'wx' });
  await writeFile(token, TOKEN, { mode: 0o600, flag: 'wx' });
  console.log(JSON.stringify({ preload, log, token, repository: REPO, inventory: join(root, 'inventory.json'),
    collection: join(root, 'collection') }));
} else if (mode === 'inspect' && process.argv.length === 4) {
  const collectionDir = join(root, 'collection');
  const captures = await Promise.all([0, 1].map(async index => {
    const path = join(collectionDir, 'captures', batchName(index)), bytes = await readFile(path);
    return { path, sha256: recordDigest(bytes), capture: parseGithubPullCapture(bytes) };
  }));
  console.log(JSON.stringify({ source_class: 'synthetic-github-input-only', collection_dir: collectionDir,
    collection_confirm: recordDigest(await readFile(join(collectionDir, 'plan.json'))),
    complete_confirm: recordDigest(await readFile(join(collectionDir, 'complete.json'))),
    single_capture: join(root, 'single-capture.json'),
    single_capture_sha256: recordDigest(await readFile(join(root, 'single-capture.json'))),
    pulls: captures.flatMap(item => item.capture.pulls) }));
} else throw new Error('setup ROOT HEAD BASE or inspect ROOT required');
