import concurrent.futures,hashlib,json,os,pathlib,re,shutil,signal,subprocess,tempfile,urllib.request,sys
ROOT=pathlib.Path.cwd();BASE='9b0120208aa6a4567567f273bf276bd0936064a3'
def git(*args,cwd=ROOT):return subprocess.check_output(['git',*args],cwd=cwd,text=True).strip()
def run(work,td,label,command,timeout=900,env=None):
    log=pathlib.Path(td)/(label+'.log')
    with log.open('w') as out:
        p=subprocess.Popen(command,cwd=work,stdout=out,stderr=subprocess.STDOUT,start_new_session=True,env=env)
        try:code=p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid,signal.SIGTERM)
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
            code=124
    lines=log.read_text(errors='replace').splitlines();summaries=[x for x in lines if x.startswith('test result:')]
    totals=[0,0,0]
    for line in summaries:
        m=re.search(r'(\d+) passed; (\d+) failed; (\d+) ignored;',line)
        if m:
            for i,value in enumerate(m.groups()):totals[i]+=int(value)
    item={'label':label,'command':' '.join(command),'revision':git('rev-parse','HEAD',cwd=work),'exit':code,'totals':totals,'summaries':summaries}
    print('VERIFICATION',json.dumps(item),flush=True)
    print('\n'.join(lines[-200:] if code else [x for x in lines if x.startswith('test result:') or 'PINNED_SHALLOW_' in x or 'PINNED_PARTIAL_CELL' in x or 'FGIT_ORACLE_' in x or 'Finished ' in x]),flush=True)
    return item
with tempfile.TemporaryDirectory(prefix='fg-shallow-final-') as td:
    work=pathlib.Path(td)/'source';subprocess.run(['git','worktree','add','--detach',str(work),BASE],check=True)
    applier=ROOT/'tools/shallow-finish.py';code=applier.read_text()
    old='edit(c,\'"unshallow", "fetch",\', \'"unshallow", "fetch", "fetch-private",\',3)'
    new='edit(c,\'"unshallow", "fetch",\', \'"unshallow", "fetch", "fetch-private",\',2)'
    assert code.count(old)==1;code=code.replace(old,new)
    sys.argv=[str(applier),str(work)];exec(compile(code,str(applier),'exec'),{'__name__':'__main__','__file__':str(applier)})
    paths=['crates/fgit-node/src/upload_visibility/shallow.rs','crates/fgit-node/src/upload_visibility/shallow/tests.rs','crates/fgit-node/src/upload_visibility/tests/shallow_oracle.rs','scripts/e2e/oracle/partial_clone_client.py']
    for path in paths:
        if path.endswith('.rs'):subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true',path],cwd=work,check=True)
    script=work/paths[-1];compile(script.read_text(),str(script),'exec')
    assert set(git('diff','--name-only',cwd=work).splitlines())==set(paths)
    subprocess.run(['git','diff','--check'],cwd=work,check=True)
    git('config','user.name','Jeff Emanuel',cwd=work);git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    git('add','--',*paths,cwd=work)
    git('commit','-m','fix(fetch): complete every authorized client history during unshallow','-m','Match pinned Git upload-pack infinite-depth semantics without widening disclosure: remove every supplied boundary inside the exact visible graph and add its verified parents to desired transfer roots. Keep finite-depth updates confined to reached boundaries. Correct the saved natural-root expectation and add a disjoint-history permitted/refused twin plus real pinned multi-branch fetch/unshallow tests.',cwd=work)
    source=git('rev-parse','HEAD',cwd=work);branch='tooling/shallow-final-source-'+os.environ['GITHUB_SHA'][:12]
    subprocess.run(['git','push','origin',source+':refs/heads/'+branch],cwd=work,check=True)
    print('PRODUCT_SOURCE',source,branch,flush=True)
    evidence=[]
    if not shutil.which('bwrap'):
        for label,cmd in [('sandbox-index',['sudo','apt-get','update','-qq']),('sandbox-install',['sudo','apt-get','install','-y','bubblewrap'])]:
            item=run(work,td,label,cmd,180);evidence.append(item)
            if item['exit']:raise SystemExit(item['exit'])
    oracle_root=pathlib.Path('/tmp')/('fg-shallow-final-'+os.environ['GITHUB_SHA'][:12]);oracle_root.mkdir(exist_ok=False)
    env=os.environ.copy();env['FGIT_ORACLE_ROOT']=str(oracle_root);env['FGIT_ORACLE_JOBS']='2'
    def build_oracle():
        pin=next(line.split('\t') for line in (work/'scripts/e2e/oracle/pins.tsv').read_text().splitlines() if line.startswith('git-2.54.0\t'))
        url,expected,filename=pin[4:7];download=oracle_root/'downloads'/filename;download.parent.mkdir()
        req=urllib.request.Request(url,headers={'User-Agent':'OpenAI File Downloader, XaiImageApiFetch/1.0'});digest=hashlib.sha256();count=0
        with urllib.request.urlopen(req,timeout=60) as response,download.open('xb') as out:
            while chunk:=response.read(1024*1024):
                count+=len(chunk);assert count<=128*1024*1024;out.write(chunk);digest.update(chunk)
        assert digest.hexdigest()==expected,(digest.hexdigest(),expected)
        print('ORACLE_SOURCE',url,'SHA256',expected,'BYTES',count,flush=True)
        return run(work,td,'oracle-build',['scripts/e2e/oracle/oracle.sh','build','git-2.54.0'],900,env)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        oracle=pool.submit(build_oracle)
        for label,cmd in [
            ('cli-check',['cargo','check','--locked','-p','fgit-cli','--all-targets']),
            ('node-library',['cargo','test','--locked','-p','fgit-node','--lib']),
            ('wire',['cargo','test','--locked','-p','fgit-wire','--all-targets']),
            ('daemon-integration',['cargo','test','--locked','-p','fgit-node','--test','git_daemon_deadline','--test','git_daemon_receive_transport','--test','git_daemon_v1','--test','git_daemon_v2','--test','hidden_ref_policy_end_to_end','--no-fail-fast'])]:
            item=run(work,td,label,cmd);evidence.append(item)
            if item['exit']:break
        evidence.append(oracle.result())
    if all(item['exit']==0 for item in evidence):
        evidence.append(run(work,td,'pinned-clients',['cargo','test','--locked','-p','fgit-node','--lib','pinned_git_','--','--ignored','--nocapture','--test-threads=1'],1200,env))
    print('FINAL_EVIDENCE',json.dumps({'revision':source,'commands':evidence}),flush=True)
    for receipt in sorted((oracle_root/'runs').glob('*/transcripts/*.json')):
        value=json.loads(receipt.read_text())
        if value['exit']:print('FAILED_RECEIPT',json.dumps(value),flush=True)
    if any(item['exit'] for item in evidence):
        for log in sorted((oracle_root/'runs').glob('*/transcripts/*.packets'))[-5:]:
            print('WIRE_TRACE',log.name,'\n'.join(log.read_text(errors='replace').splitlines()[-100:]),flush=True)
        raise SystemExit(1)
    assert not git('status','--porcelain',cwd=work)
    text='''# Native shallow clone, fetch and unshallow

The bounded raw Git daemon now supports absolute depth-limited clone/fetch,
ordinary incremental fetch from a shallow client, and unshallow. It uses the
native object graph, wire state machines and pack writer; production never
invokes upstream Git. SHA-1/SHA-256 and upload-pack v0/v1/v2 are supported by
this profile. The implementation does not add HTTP or SSH transports.

```sh
git -c protocol.version=2 clone --depth=1 --branch=main \\
  git://127.0.0.1:9418/22222222222222222222222222222222.git work
cd work
git fetch --depth=50
git fetch --unshallow
```

## History and transfer selection

The node derives one private complete visible-graph proof from its exact
materialized authority snapshot. Depth follows the shortest parent path from
all wanted tips, preserving merge ancestry and annotated-tag roots. Each
selected commit retains its tree contents; gitlinks remain foreign-repository
identities rather than local history edges. A natural root at the exact
requested depth is still a shallow boundary.

Desired history stops at the NEW boundary. Common history stops at the
CLIENT'S OLD boundary. Treating those as the same set can subtract exactly
the missing ancestors a deepening client needs when it already has the tip.
The native selector performs both bounded traversals against the same proof.

Infinite depth removes every client-supplied boundary inside the visible
graph, including other visible client branches, matching the pinned Git
upload-pack rule. Removed boundaries add their verified parents to desired
transfer roots so the response supplies the history it promises. Finite-depth
changes remove only boundaries reached by that depth computation. Unknown,
hidden-only and disconnected markers are not echoed and grant no access.

Selection precedes existing partial-clone filters and requested tag expansion.
Blobless and treeless shallow clones can hydrate their checkout normally;
a have commit does not prove a partial client possesses its blobs or trees.
Canonical object retention, repository decisions, refs and forge state are
not changed by shallow serving.

## Wire handshake

Legacy clients receive shallow/unshallow records and the required terminating
flush before the server waits for haves. Protocol v2 receives the delimited
shallow-info section before packfile. Both use the private graph provider,
including through the legacy peeled-tag advertisement adapter. Wire framing
checks authorization, object format, ordering, duplicates, original unshallow
membership and response limits before returning a successful transition.
Low-level parser-only machines retain their existing default behavior; native
adapters explicitly opt into resolved shallow responses.

Cancellation and finite graph/work/byte limits remain enforced. Selected
object lists are installed only after successful complete computation.
Serving still verifies the entire visible graph before advertisement; smaller
transfers do not imply reduced server-side scanning cost or a larger admitted
repository envelope.

## Verification

The recorded commands below ran against source `'''+source+'''` on Ubuntu 22.04,
with repository-pinned nightly-2026-08-31 and locked dependencies. The optional
oracle uses source/binary-verified Git 2.54.0 and Bubblewrap, with no ambient-Git
fallback or isolation bypass. Its tests invoke ordinary clients over real TCP
and inspect resulting native object inventories, worktree bytes, shallow files,
reachable history and strict fsck outcomes.

The shallow lifecycle test covers full/blobless/treeless profiles across both
hashes and all three protocols. Each cell clones at depth one, checks out,
deepens an already-known tip, fetches newly published server history without
changing its old boundary, and unshallows. The separate multi-branch campaign
requires unshallow to clear both visible client boundaries, not merely the
requested branch. The existing partial-clone/lazy-read campaign is rerun.

'''
    text+='| Command | Exit | Passed | Failed | Ignored |\n|---|---:|---:|---:|---:|\n'
    for item in evidence:
        text+='| `'+item['command']+'` | '+str(item['exit'])+' | '+' | '.join(map(str,item['totals']))+' |\n'
    text+='''
Counts sum completed test-target summaries; these are revision-bound command
observations, not a full-workspace, lint, independent batch, release or broad
protocol-differential gate. Existing ignored wire-oracle tests remain outside
ordinary all-target execution. Run the registered optional client tests with:

```sh
cargo test --locked -p fgit-node --lib pinned_git_ -- --ignored --nocapture --test-threads=1
```

Relative `--deepen`, time/ref-exclusion boundaries, shallow-server source
storage, remote authentication, repository-wide protection activation and
full Git compatibility remain unfinished. Unsupported controls refuse rather
than silently producing an unlimited pack. No dependency, lockfile or
canonical schema changed, and no bead is closed by this implementation.
'''
    doc=work/'docs/SHALLOW_FETCH_SERVING.md';assert not doc.exists();doc.write_text(text)
    partial=work/'docs/PARTIAL_CLONE_SERVING.md';partial.write_text(partial.read_text()+'\n## Shallow-history composition\n\nThe native depth, ordinary shallow fetch and unshallow integration now composes\nwith this filter engine. See [native shallow serving](SHALLOW_FETCH_SERVING.md)\nfor the exact supported scope, protocol handshake and later revision-bound\nclient results. Earlier historical non-claims above remain tied to their\nrecorded source revisions. Relative/time/ref-exclusion controls remain\nunsupported by the current production profile.\n')
    git('diff','--check',cwd=work);git('add','--','docs/SHALLOW_FETCH_SERVING.md','docs/PARTIAL_CLONE_SERVING.md',cwd=work)
    git('commit','-m','docs(fetch): record native shallow serving and measured client lifecycles',cwd=work)
    result=git('rev-parse','HEAD',cwd=work);branch='tooling/shallow-final-result-'+os.environ['GITHUB_SHA'][:12]
    subprocess.run(['git','push','origin',result+':refs/heads/'+branch],cwd=work,check=True)
    print('PRODUCT_RESULT',result,branch,flush=True)
