import base64, bz2, hashlib, json, os, pathlib, re, subprocess, tempfile
ROOT = pathlib.Path.cwd()
BASE = 'e1b8180e604fb65d0796af3bcc1026f3f5545ee7'
ORIGINAL = '5a84924788fc00c014e77080469342ec0a595e00'
PATCH_SHA = '3d7a084a4a17e93d9aa8a67de482e9c677592f18828388f02b8262b3fa0b2e19'
def git(*args, cwd=ROOT):
    return subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', *args], cwd=cwd, text=True).strip()
def blob(ref, path):
    p = subprocess.run(['git', 'rev-parse', '--verify', f'{ref}:{path}'], cwd=ROOT, text=True, capture_output=True)
    return p.stdout.strip() if p.returncode == 0 else None
payload = pathlib.Path(__file__).resolve().parent
first = (payload/'part0').read_bytes()
second = (payload/'part1').read_bytes()
# Undo the one detected transport transcription error, then require the
# complete saved patch's independently computed length and SHA-256 below.
encoded = base64.b64encode(second).decode('ascii')
assert encoded.count('HY0wiallj1nUGG') == 1
encoded = encoded.replace('HY0wiallj1nUGG', 'HY0wialj1nUGG')
encoded += '=' * (-len(encoded) % 4)
second = base64.b64decode(encoded, validate=True)
assert hashlib.sha1(b'blob '+str(len(second)).encode()+b'\0'+second).hexdigest() == '557829b5d0a40db7b6da560ecfffd43032eb45b0'
patch = bz2.decompress(first+second)
assert len(patch) == 56011 and hashlib.sha256(patch).hexdigest() == PATCH_SHA
paths=[]
for a,b in re.findall(rb'^diff --git a/([^\n ]+) b/([^\n ]+)$',patch,re.M):
    assert a==b
    path=a.decode('ascii')
    assert not pathlib.PurePosixPath(path).is_absolute() and '..' not in pathlib.PurePosixPath(path).parts
    assert blob(BASE,path)==blob(ORIGINAL,path),(path,blob(BASE,path),blob(ORIGINAL,path))
    paths.append(path)
assert len(paths)==len(set(paths))==17
expected={}
for section in patch.decode('utf-8').split('diff --git ')[1:]:
    path=section.splitlines()[0].split(' b/')[1]
    expected[path]=re.search(r'^index [0-9a-f]{40}\.\.([0-9a-f]{40})',section,re.M).group(1)
subprocess.run(['git','merge-base','--is-ancestor',ORIGINAL,BASE],check=True)
for name in ['AGENTS.md','COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md','.beads/issues.jsonl']:
    print('INPUT_IDENTITY', name, blob(BASE,name), flush=True)
# Print the exact current owner bead without editing the shared tracker.
for line in subprocess.check_output(['git','show',BASE+':.beads/issues.jsonl'],text=True).splitlines():
    item=json.loads(line)
    if item.get('id') in ['frankengit-fg019-receive-pack-c4k','frankengit-fg019c-receivepack-adversarial-sht']:
        print('CURRENT_BEAD',json.dumps(item),flush=True)
with tempfile.TemporaryDirectory(prefix='fg-ref-kind-product-') as td:
    work=pathlib.Path(td)/'source'; local_patch=pathlib.Path(td)/'implementation.patch';local_patch.write_bytes(patch)
    git('worktree','add','--detach',str(work),BASE)
    subprocess.run(['git','apply','--check','--whitespace=error',str(local_patch)],cwd=work,check=True)
    subprocess.run(['git','apply','--whitespace=error',str(local_patch)],cwd=work,check=True)
    observed=set(git('diff','--name-only',cwd=work).splitlines())|set(git('ls-files','--others','--exclude-standard',cwd=work).splitlines())
    assert observed==set(paths),observed
    for path,sha in expected.items():assert git('hash-object',path,cwd=work)==sha,path
    git('diff','--check',cwd=work)
    git('config','user.name','Jeff Emanuel',cwd=work)
    git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    groups=[('core',[p for p in paths if p.startswith('crates/fgit-git-object/')],'feat(git-object): define native branch target kind constraints (FG-019)'),('node',[p for p in paths if p.startswith('crates/fgit-node/')],'fix(node): enforce commit-only branch roots across import and receive (FG-019)'),('guide',[p for p in paths if p.startswith(('docs/','scripts/'))],'docs(receive): add native branch-target integrity campaign and scope (FG-019)')]
    assert set(p for _,group,_ in groups for p in group)==set(paths)
    results={}
    for label,group,title in groups:
        before=git('rev-parse','HEAD',cwd=work)
        git('add','--',*group,cwd=work)
        git('commit','-m',title,'-m','Recover the complete saved implementation with exact original-file, patch and resulting-file identities. Preserve concurrent bundle/fetch/inventory changes. Original-input authorization precedes branch-kind verdicts; source import retains every ref root constraint through its existing bounded graph. No dependencies, lockfile changes, weakened branch checks or production Git process. Native verification is run separately and is not claimed by this commit.',cwd=work)
        sha=git('rev-parse','HEAD',cwd=work)
        assert set(git('diff','--name-only',before,sha,cwd=work).splitlines())==set(group)
        branch='tooling/ref-kind-'+label+'-'+os.environ['GITHUB_SHA'][:12]
        git('push','origin',sha+':refs/heads/'+branch,cwd=work)
        results[label]=sha
        print('PRODUCT_COMMIT',label,sha,branch,flush=True)
    assert not git('status','--porcelain',cwd=work)
    print('PRODUCT_FILES',json.dumps(expected),flush=True)
    with open(os.environ['GITHUB_OUTPUT'],'a') as output:
        for label,sha in results.items():output.write(label+'='+sha+'\n')
        output.write('source='+results['guide']+'\n')
