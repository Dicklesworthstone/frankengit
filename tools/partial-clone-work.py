import hashlib,json,os,pathlib,shutil,signal,subprocess,tempfile,time,urllib.request
ROOT=pathlib.Path.cwd(); BASE='1b969e534208a660f7dda99d48c61ed0ac97ea8b'
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
    print('VERIFICATION',label,'REVISION',git('rev-parse','HEAD',cwd=work),'EXIT',code,'COMMAND',' '.join(command),flush=True)
    if code or label.startswith('oracle'):
        print('\n'.join(lines[-200:]),flush=True)
    else:
        print('\n'.join(line for line in lines if line.startswith('test result:') or 'Finished ' in line or 'partial_clone' in line),flush=True)
    return code
with tempfile.TemporaryDirectory(prefix='fg-partial-oracle-source-') as td:
    work=pathlib.Path(td)/'source'; payload=ROOT/'tools/partial-payload'
    subprocess.run(['git','worktree','add','--detach',str(work),BASE],check=True)
    paths=['scripts/e2e/oracle/partial_clone_client.py','crates/fgit-node/src/upload_visibility/tests/partial_oracle.rs','crates/fgit-node/src/upload_visibility/tests.rs']
    for source,dest in [('partial_clone_client.py',paths[0]),('oracle_tests.rs',paths[1])]:
        p=work/dest; assert not p.exists(); p.write_text((payload/source).read_text())
    p=work/paths[2]; p.write_text(p.read_text()+'\nmod partial_oracle;\n')
    subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true',paths[1]],cwd=work,check=True)
    subprocess.run(['python3','-c','import ast,pathlib; ast.parse(pathlib.Path("scripts/e2e/oracle/partial_clone_client.py").read_text())'],cwd=work,check=True)
    subprocess.run(['git','diff','--check'],cwd=work,check=True)
    git('config','user.name','Jeff Emanuel',cwd=work); git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    git('add','--',*paths,cwd=work)
    git('commit','-m','test(fetch): exercise partial clones and lazy reads with pinned sandboxed Git','-m','Add an explicitly opt-in real-client campaign using the existing verified Git 2.54.0 source/binary receipt and Bubblewrap. Fixed clone/read operations permit only numeric loopback, fixed native repository paths and protocol/filter choices; inventory/fsck remain networkless. Compare initial object sets, actual .promisor marking, native blob bytes and exact one-object lazy hydration across both hashes and all three protocols. This commit does not assert execution success.',cwd=work)
    result=git('rev-parse','HEAD',cwd=work); branch='tooling/partial-result-'+os.environ['GITHUB_SHA'][:12]
    subprocess.run(['git','push','origin',f'{result}:refs/heads/{branch}'],cwd=work,check=True)
    print('PRODUCT_RESULT',result,branch,flush=True)
    code=run(work,td,'node-check',['cargo','check','--locked','-p','fgit-node','--all-targets'])
    if code: raise SystemExit(code)
    code=run(work,td,'node-visibility',['cargo','test','--locked','-p','fgit-node','--lib','upload_visibility','--','--nocapture'])
    if code: raise SystemExit(code)
    if not shutil.which('bwrap'):
        code=run(work,td,'oracle-package-index',['sudo','apt-get','update','-qq'],180)
        if not code: code=run(work,td,'oracle-sandbox-install',['sudo','apt-get','install','-y','bubblewrap'],180)
        if code: raise SystemExit(code)
    oracle_root=pathlib.Path('/tmp')/('fg-partial-pinned-'+os.environ['GITHUB_SHA'][:12])
    oracle_root.mkdir(exist_ok=False)
    env=os.environ.copy(); env['FGIT_ORACLE_ROOT']=str(oracle_root); env['FGIT_ORACLE_JOBS']='2'
    pin=next(line.split('\t') for line in (work/'scripts/e2e/oracle/pins.tsv').read_text().splitlines() if line.startswith('git-2.54.0\t'))
    url,expected,filename=pin[4:7]
    download=oracle_root/'downloads'/filename; download.parent.mkdir()
    req=urllib.request.Request(url,headers={'User-Agent':'OpenAI File Downloader, XaiImageApiFetch/1.0'})
    digest=hashlib.sha256(); count=0
    with urllib.request.urlopen(req,timeout=60) as response, download.open('xb') as out:
        while chunk:=response.read(1024*1024):
            count+=len(chunk); assert count<=128*1024*1024
            out.write(chunk); digest.update(chunk)
    assert digest.hexdigest()==expected,(digest.hexdigest(),expected)
    print('ORACLE_SOURCE',url,'SHA256',expected,'BYTES',count,flush=True)
    code=run(work,td,'oracle-build',['scripts/e2e/oracle/oracle.sh','build','git-2.54.0'],720,env)
    if code: raise SystemExit(code)
    code=run(work,td,'oracle-native-partial',['cargo','test','--locked','-p','fgit-node','--lib','pinned_git_partial_clone_promisor_and_lazy_read_round_trip','--','--ignored','--nocapture'],900,env)
    print('ORACLE_ARTIFACT_ROOT',str(oracle_root),flush=True)
    for receipt in sorted((oracle_root/'runs').glob('*/transcripts/*.json')):
        print('PINNED_RECEIPT',receipt.read_text().strip(),flush=True)
    assert not git('status','--porcelain',cwd=work)
    raise SystemExit(code)
