import hashlib,json,pathlib,subprocess,tarfile,tempfile,urllib.request
root=pathlib.Path.cwd()
print('SOURCE',subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),flush=True)
with tempfile.TemporaryDirectory(prefix='fg-partial-triage-') as td:
    archive=pathlib.Path(td)/'br.tar.gz'
    req=urllib.request.Request('https://github.com/Dicklesworthstone/beads_rust/releases/download/v0.5.7/br-0.5.7-linux_amd64.tar.gz',headers={'User-Agent':'OpenAI File Downloader, XaiImageApiFetch/1.0'})
    with urllib.request.urlopen(req,timeout=60) as response: archive.write_bytes(response.read())
    assert hashlib.sha256(archive.read_bytes()).hexdigest()=='634aaacd0aac256b2be7250af9fe1e863e8a0316875c20959a6a1c2da75bf843'
    with tarfile.open(archive) as tar: tar.extractall(td,filter='data')
    br=next(pathlib.Path(td).rglob('br')); br.chmod(0o755)
    for args in [('ready','--unassigned'),('list','--status','all','--limit','0')]:
        p=subprocess.run([str(br),*args,'--no-db','--json'],text=True,capture_output=True)
        print('TRACKER',args,'EXIT',p.returncode,p.stderr,flush=True)
        if p.returncode: print(p.stdout,flush=True); continue
        data=json.loads(p.stdout)
        if args[0]=='ready': print('READY',json.dumps(data),flush=True); continue
        rows=data if isinstance(data,list) else data.get('issues',data.get('items',[]))
        for row in rows:
            if any(term in row.get('title','').lower() for term in ['partial','promisor','fg-018','fg-105']):
                print('BEAD',json.dumps({k:row.get(k) for k in ['id','title','status','assignee','priority','description','acceptance_criteria','dependencies']}),flush=True)
for name,terms in [('crates/fgit-wire/src/lib.rs',['fn push_fetch','fn finish_fetch','fn contains','filter ','allow-reachable','allow-tip']),('scripts/e2e/suites/node/incremental_fetch.sh',['oracle','git_bin','ORACLE']),('scripts/e2e/lib.sh',['oracle','pinned'])]:
    lines=(root/name).read_text().splitlines(); seen=set()
    for i,line in enumerate(lines):
        if any(term in line for term in terms):
            start=max(0,i-4); end=min(len(lines),i+45)
            if start in seen: continue
            seen.update(range(start,end))
            print('SOURCE_RANGE',name,start+1,end,flush=True)
            print('\n'.join(f'{j+1}: {lines[j]}' for j in range(start,end)),flush=True)
print('PLAN_FILTERS',flush=True)
for name in ['COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md','docs/GIT_COMPATIBILITY_MATRIX.md']:
    lines=(root/name).read_text().splitlines()
    for i,line in enumerate(lines):
        if 'partial' in line.lower() or 'promisor' in line.lower():
            print(name,i+1,'\n'.join(lines[max(0,i-2):min(len(lines),i+6)]),flush=True)
