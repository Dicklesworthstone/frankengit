import hashlib,json,os,pathlib,re,shutil,signal,subprocess,tempfile,urllib.request
ROOT=pathlib.Path.cwd(); BASE='512fb877826d4a6fc47d4e53e815135c7e411fb9'
def git(*args,cwd=ROOT): return subprocess.check_output(['git',*args],cwd=cwd,text=True).strip()
def run(work,td,label,command,timeout=720,env=None):
    log=pathlib.Path(td)/(label+'.log')
    with log.open('w') as out:
        process=subprocess.Popen(command,cwd=work,stdout=out,stderr=subprocess.STDOUT,start_new_session=True,env=env)
        try: code=process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid,signal.SIGTERM)
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: os.killpg(process.pid,signal.SIGKILL); process.wait()
            code=124
    lines=log.read_text(errors='replace').splitlines()
    summaries=[line for line in lines if line.startswith('test result:')]
    print('VERIFICATION',label,'REVISION',git('rev-parse','HEAD',cwd=work),'EXIT',code,'COMMAND',' '.join(command),flush=True)
    if code or label.startswith('oracle'):
        print('\n'.join(lines[-220:]),flush=True)
    else:
        print('\n'.join(line for line in lines if line.startswith('test result:') or 'Finished ' in line or 'partial_clone' in line),flush=True)
    return {'label':label,'command':' '.join(command),'exit':code,'summaries':summaries}
with tempfile.TemporaryDirectory(prefix='fg-partial-final-source-') as td:
    work=pathlib.Path(td)/'source'; payload=ROOT/'tools/partial-payload'
    subprocess.run(['git','worktree','add','--detach',str(work),BASE],check=True)
    p=work/'crates/fgit-node/src/upload_visibility/tests/partial_clone.rs'; text=p.read_text(); old='        node = OneNode::open_existing(config).unwrap();'; assert text.count(old)==1
    p.write_text(text.replace(old,old+'\n        node.bring_into_service(HeadGeneration::FIRST).unwrap();'))
    p=work/'scripts/e2e/oracle/partial_clone_client.py'; text=p.read_text(); old='        config += [("protocol.version", protocol), ("remote.origin.url", url), ("remote.origin.promisor", "true")]'; assert text.count(old)==1
    p.write_text(text.replace(old,'''        config.append(("protocol.version", protocol))
        if operation == "read":
            config += [("remote.origin.url", url), ("remote.origin.promisor", "true")]'''))
    p=work/'docs/PARTIAL_CLONE_SERVING.md'; assert not p.exists(); p.write_text((payload/'PARTIAL_CLONE_SERVING.md').read_text())
    p=work/'docs/UPLOAD_PACK_VISIBILITY_AND_TAGS.md'; text=p.read_text(); old='## Native annotated-tag serving'; assert text.count(old)==1
    text=text.replace(old,'''## Partial-clone extension

The current node adds filtered packs and capability-gated lazy retrieval as
specified in [Partial-clone serving](PARTIAL_CLONE_SERVING.md). In particular,
it now advertises `allow-reachable-sha1-in-want`; the advertisement-bound legacy
behavior described below is the earlier implementation's measured baseline,
not the current production capability set. The strict no-capability refusal
remains covered in wire tests. Current visibility and historical-retention
boundaries are unchanged.

## Native annotated-tag serving'''); p.write_text(text)
    p=work/'crates/fgit-wire/src/lib.rs'; text=p.read_text(); old='''//! V0/v1 wants are required to have appeared in the advertised refs; v2 wants
//! are instead checked against the repository's canonical permitted closure,
//! matching the protocol-v2 distinction.'''; new='''//! V0/v1 wants must be advertised unless the server explicitly enables
//! `allow-reachable-sha1-in-want`; that extension also requires repository
//! permission. V2 wants are checked against the repository's permitted closure.
//! Neither protocol obtains authority from client text or physical storage.'''; assert text.count(old)==1; p.write_text(text.replace(old,new))
    p=work/'crates/fgit-node/src/lib.rs'; text=p.read_text(); old='''/// authority basis.  The first-clone git-daemon transport serves the legacy
/// V0/V1 packet grammar, whose wants must name an advertised ref; therefore
/// this view deliberately refuses every non-advertised want until the
/// decision-history closure reader is wired as a separate production slice.'''; new='''/// authority basis. The production daemon attaches its private exact-head
/// visible-graph proof before negotiation. That proof authorizes v2 and
/// explicitly enabled legacy reachable wants, common haves, and partial-clone
/// follow-ups; cumulative admission alone is not disclosure permission.'''; assert text.count(old)==1; p.write_text(text.replace(old,new))
    paths=['crates/fgit-node/src/upload_visibility/tests/partial_clone.rs','scripts/e2e/oracle/partial_clone_client.py','docs/PARTIAL_CLONE_SERVING.md','docs/UPLOAD_PACK_VISIBILITY_AND_TAGS.md','crates/fgit-wire/src/lib.rs','crates/fgit-node/src/lib.rs']
    subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true',paths[0]],cwd=work,check=True)
    subprocess.run(['git','diff','--check'],cwd=work,check=True)
    git('config','user.name','Jeff Emanuel',cwd=work); git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    git('add','--',*paths,cwd=work)
    git('commit','-m','test(fetch): preserve reopened-node lifecycle in partial-clone revocation campaign','-m','Bring the reopened fixture into service before its later canonical deletion, retaining the production bootstrapping staging refusal. Keep the pinned clone configuration operation-specific. Document the actual filtered and lazy serving profile and update stale capability comments without altering production guards or assertions.',cwd=work)
    result=git('rev-parse','HEAD',cwd=work); branch='tooling/partial-result-'+os.environ['GITHUB_SHA'][:12]
    subprocess.run(['git','push','origin',f'{result}:refs/heads/{branch}'],cwd=work,check=True)
    print('PRODUCT_RESULT',result,branch,flush=True)
    evidence=[]
    for label,command,seconds in [('node-library',['cargo','test','--locked','-p','fgit-node','--lib'],900),('daemon-integration',['cargo','test','--locked','-p','fgit-node','--test','git_daemon_deadline','--test','git_daemon_receive_transport','--test','git_daemon_v1','--test','git_daemon_v2','--test','hidden_ref_policy_end_to_end','--no-fail-fast'],300),('wire',['cargo','test','--locked','-p','fgit-wire','--all-targets'],180)]:
        item=run(work,td,label,command,seconds); evidence.append(item)
        if item['exit']: raise SystemExit(item['exit'])
    if not shutil.which('bwrap'):
        item=run(work,td,'oracle-package-index',['sudo','apt-get','update','-qq'],180)
        if not item['exit']: item=run(work,td,'oracle-sandbox-install',['sudo','apt-get','install','-y','bubblewrap'],180)
        if item['exit']: raise SystemExit(item['exit'])
    oracle_root=pathlib.Path('/tmp')/('fg-partial-pinned-'+os.environ['GITHUB_SHA'][:12]); oracle_root.mkdir(exist_ok=False)
    env=os.environ.copy(); env['FGIT_ORACLE_ROOT']=str(oracle_root); env['FGIT_ORACLE_JOBS']='2'
    pin=next(line.split('\t') for line in (work/'scripts/e2e/oracle/pins.tsv').read_text().splitlines() if line.startswith('git-2.54.0\t'))
    url,expected,filename=pin[4:7]; download=oracle_root/'downloads'/filename; download.parent.mkdir()
    req=urllib.request.Request(url,headers={'User-Agent':'OpenAI File Downloader, XaiImageApiFetch/1.0'}); digest=hashlib.sha256(); count=0
    with urllib.request.urlopen(req,timeout=60) as response, download.open('xb') as out:
        while chunk:=response.read(1024*1024):
            count+=len(chunk); assert count<=128*1024*1024; out.write(chunk); digest.update(chunk)
    assert digest.hexdigest()==expected,(digest.hexdigest(),expected)
    print('ORACLE_SOURCE',url,'SHA256',expected,'BYTES',count,flush=True)
    item=run(work,td,'oracle-build',['scripts/e2e/oracle/oracle.sh','build','git-2.54.0'],720,env); evidence.append(item)
    if not item['exit']:
        item=run(work,td,'oracle-native-partial',['cargo','test','--locked','-p','fgit-node','--lib','pinned_git_partial_clone_promisor_and_lazy_read_round_trip','--','--ignored','--nocapture'],900,env); evidence.append(item)
    print('ORACLE_ARTIFACT_ROOT',str(oracle_root),flush=True)
    for receipt in sorted((oracle_root/'runs').glob('*/transcripts/*.json')):
        print('PINNED_RECEIPT',receipt.read_text().strip(),flush=True)
    assert not git('status','--porcelain',cwd=work)
    print('FINAL_EVIDENCE',json.dumps({'revision':result,'commands':evidence}),flush=True)
    raise SystemExit(item['exit'])
