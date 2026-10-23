"""Actual operator CLI -> actual Rust HTTP -> durable custody and key recovery."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from source_binary_refactor_http import BinaryFixture,HTTP,PROFILE,REPO,PRINCIPAL
FG,NODE,ROOT=str(Path(sys.argv[1]).resolve()),str(Path(sys.argv[2]).resolve()),Path(sys.argv[3]).resolve()
ROOT.mkdir(parents=True,exist_ok=True)
CLI=REPO/'scripts/fg_source_edit.mjs'
RESULTS=[]
def record(f,case,**detail):
    row=dict(format=f.fmt,case=case,**detail);RESULTS.append(row);print(json.dumps(row),flush=True)
def private(path,data):
    path.write_bytes(data);path.chmod(0o600);return path
def command(f,label,args,code=0,closed=False):
    f.sequence+=1;prefix=f.root/f'{f.sequence:03d}-client-{label}'
    full=[NODE,str(CLI),*map(str,args)]
    if closed:
        with prefix.with_suffix('.err').open('wb') as err:
            process=subprocess.Popen(full,stdout=subprocess.PIPE,stderr=err)
            process.stdout.close();actual=process.wait(timeout=120)
        out=b'';error=prefix.with_suffix('.err').read_bytes()
    else:
        result=subprocess.run(full,capture_output=True,timeout=120);actual=result.returncode;out,error=result.stdout,result.stderr
        prefix.with_suffix('.out').write_bytes(out);prefix.with_suffix('.err').write_bytes(error)
    assert actual==code,(label,actual,out[-2500:],error[-2500:])
    return json.loads(out) if out else json.loads(error)
for fmt in ['sha1','sha256']:
    f=BinaryFixture(FG,NODE,ROOT,fmt,'delta-runs');basis=f.basis()
    token=private(f.root/'read-token',f.read_token.encode())
    write_token=private(f.root/'write-token',f.write_token.encode())
    recovery=private(f.root/'recovery-token',f.token.encode())
    with HTTP(f,'operator') as server:
        wanted=sorted((set(f.files)|set(f.expected_files))-{b'keep.bin'})
        selection=dict(endpoint=server.url.geturl(),scope=dict(tenant_id=f.scope[1],repository_id=f.scope[2],repository_incarnation=f.incarnation,object_format=fmt),ref='refs/heads/main',expected_commit=f.base,
            metadata=dict(author=f.form()['author'],committer=f.form()['committer'],timestamp=2,message=f.form()['message']),paths_hex=[p.hex()for p in wanted],expected_result_tree=f.expected_tree,patch_profile=PROFILE)
        selected=private(f.root/'selection.json',json.dumps(selection).encode())
        patch=f.root/'change.patch';candidate=f.root/'candidate'
        args=['prepare','--selection',selected,'--patch-file',patch,'--token-file',token,'--output',candidate]
        receipt=command(f,'prepare',args)
        assert receipt['candidate_commit']==f.candidate and receipt['metrics']['requests']==2 and not receipt['publication_attempted']
        capture=json.loads((candidate/'capture.json').read_bytes());bundle=(candidate/'candidate.bundle').read_bytes()
        assert capture['schema']=='frankengit-source-edit-capture-v3'
        assert capture['request']['patch_profile']==capture['preparation']['patch_profile']==PROFILE
        assert capture['request']['expected_result_tree']==capture['preparation']['expected_result_tree']==f.expected_tree
        f.validate(capture['preparation'],bundle)
        record(f,'actual-cli-capture-verified-against-independent-tree')
        inspect=['inspect','--candidate',candidate,'--sha256',receipt['manifest_sha256']]
        assert command(f,'inspect',inspect)['candidate_commit']==f.candidate
        wrong=json.loads(selected.read_bytes());wrong['expected_result_tree']=f.old_tree
        selected.write_text(json.dumps(wrong));bad=list(args);bad[-1]=f.root/'wrong-intent'
        command(f,'wrong-result',bad,2);assert not Path(bad[-1]).exists()
        selected.write_text(json.dumps(selection))
        record(f,'server-side-result-mismatch-cannot-enter-client-custody')
        lost=list(args);lost[-1]=f.root/'lost-response'
        err=command(f,'lost-preparation-output',lost,4,closed=True)
        assert err['retained_result']['candidate_commit']==f.candidate
        assert (Path(lost[-1])/'candidate.bundle').read_bytes()==bundle
        command(f,'no-overwrite',lost,2)
        record(f,'lost-preparation-output-retains-exact-profile-and-bundle')
        original=(candidate/'capture.json').read_bytes()
        changed=json.loads(original);changed['request']['patch_profile']='exact-tree-v1'
        (candidate/'capture.json').write_text(json.dumps(changed)+'\n')
        journal=f.root/'journal'
        stage=['stage','--candidate',candidate,'--sha256',receipt['manifest_sha256'],'--principal',PRINCIPAL,'--confirm-candidate',f.candidate,'--journal',journal]
        command(f,'tampered-profile',stage,2);assert not journal.exists()
        (candidate/'capture.json').write_bytes(original)
        staged=command(f,'stage',stage);assert staged['candidate_commit']==f.candidate and not staged['transmission_attempted']
        record(f,'original-manifest-fences-profile-tampering-before-staging')
        shutil.rmtree(candidate)
        apply=['apply','--journal',journal,'--request-sha256',staged['request_sha256'],'--token-file',write_token]
        err=command(f,'lost-apply-output',apply,4,closed=True)
        accepted=err['retained_result'];assert accepted['decision']['outcome']=='committed'
        terminal=journal/'terminal.json';assert terminal.exists()
        terminal.unlink()
        command(f,'no-resend-after-lost-terminal',apply,2)
        recover=['recover','--journal',journal,'--request-sha256',staged['request_sha256'],'--token-file',recovery]
        recovered=command(f,'recover-original-key',recover)
        assert recovered['decision']['outcome']=='committed' and recovered['decision']['tx_id']==accepted['decision']['tx_id']
        assert recovered['request_sha256']==staged['request_sha256'] and recovered['key']==staged['key']
        assert recovered['submission_retried'] is False
        record(f,'lost-terminal-recovers-original-key-without-repreparing-or-resending')
        status=command(f,'status',['status','--journal',journal,'--request-sha256',staged['request_sha256']])
        assert status['state']=='terminal' and status['decision']['tx_id']==accepted['decision']['tx_id']
    after=f.basis();assert after!=basis
    shutil.rmtree(f.source)
    offline=command(f,'offline-terminal',apply)
    assert offline['decision']['tx_id']==accepted['decision']['tx_id'] and f.basis()==after
    for identity in [f.candidate,f.expected_tree]:
        observed=f.command('native-object',['doctor',*f.scope,identity]);assert b'verified object sample'in observed
    record(f,'source-and-server-free-terminal-reopen-preserves-canonical-result')
(ROOT/'results.json').write_text(json.dumps(RESULTS,indent=2)+'\n')
