"""Actual Node custody -> native HTTP publication over 140 MiB inherited blobs.
Python builds native object identities; no fake service or production Git helper.
"""
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from candidate_frontier_bytes import LargeFixture,HTTP,bundle,tree_bytes,oid,PRINCIPAL,AUTHOR
from patch_smoke import bundle_objects
REPO=Path(__file__).resolve().parents[3]
CLI=REPO/'scripts/fg_source_edit.mjs'
RESULTS=[]

def record(f,case,**detail):
    row=dict(format=f.fmt,case=case,**detail);RESULTS.append(row);print(json.dumps(row),flush=True)

def private(path,data):
    path.write_bytes(data);path.chmod(0o600);return path

def command(node,f,label,args,code=0,closed=False):
    f.sequence+=1;prefix=f.root/f'{f.sequence:03d}-operator-{label}'
    full=[node,str(CLI),*map(str,args)]
    if closed:
        with prefix.with_suffix('.err').open('wb')as err:
            process=subprocess.Popen(full,stdout=subprocess.PIPE,stderr=err)
            process.stdout.close();actual=process.wait(timeout=120)
        out=b'';error=prefix.with_suffix('.err').read_bytes()
    else:
        result=subprocess.run(full,capture_output=True,timeout=120)
        actual=result.returncode;out,error=result.stdout,result.stderr
        prefix.with_suffix('.out').write_bytes(out);prefix.with_suffix('.err').write_bytes(error)
    assert actual==code,(label,actual,out[-2500:],error[-2500:])
    return json.loads(out)if out else json.loads(error)

def campaign(f,node):
    assert f.shared_bytes>128*1024*1024
    before=f.basis()
    read_token,write_token=secrets.token_hex(32),secrets.token_hex(32)
    with f.grants.open('a')as grants:
        for token,rights in [(read_token,'read'),(write_token,'receive')]:
            grants.write(hashlib.sha256(token.encode()).hexdigest()+f' {PRINCIPAL} {rights}\n')
    read_file=private(f.root/'read-token',read_token.encode())
    write_file=private(f.root/'write-token',write_token.encode())
    recovery_file=private(f.root/'recovery-token',f.token.encode())
    patch=private(f.root/'change.patch',f.patch)
    with HTTP(f,'operator')as server:
        selection=dict(endpoint=server.url.geturl(),scope=dict(tenant_id=f.scope[1],repository_id=f.scope[2],repository_incarnation=f.incarnation,object_format=f.fmt),ref='refs/heads/main',expected_commit=f.base,
            metadata=dict(author=AUTHOR,committer=AUTHOR,timestamp=2,message=f.form()['message']),paths_hex=[b'file'.hex()],patch_profile='exact-tree-v1',expected_result_tree=f.expected_tree)
        selected=private(f.root/'selection.json',json.dumps(selection).encode());candidate=f.root/'candidate'
        receipt=command(node,f,'prepare',['prepare','--selection',selected,'--patch-file',patch,'--token-file',read_file,'--output',candidate])
        assert receipt['candidate_commit']==f.candidate and not receipt['publication_attempted']
        capture=json.loads((candidate/'capture.json').read_bytes());saved=(candidate/'candidate.bundle').read_bytes()
        assert capture['schema']=='frankengit-source-edit-capture-v3'
        assert capture['request']['expected_result_tree']==capture['preparation']['expected_result_tree']==f.expected_tree
        packed=bundle_objects(saved,f.fmt,f.base,f.candidate)
        for kind,body in f.objects:assert packed[oid(f.fmt,kind,body)]==(kind,body)
        assert set(packed)=={oid(f.fmt,kind,body)for kind,body in f.objects}
        record(f,'actual-operator-prepares-and-retains-independent-large-repository-candidate')
        wrong=json.loads(selected.read_bytes());wrong['expected_result_tree']=f.old_tree
        selected.write_text(json.dumps(wrong));bad=f.root/'wrong-result'
        command(node,f,'wrong-result',['prepare','--selection',selected,'--patch-file',patch,'--token-file',read_file,'--output',bad],2)
        assert not bad.exists();selected.write_text(json.dumps(selection))
        record(f,'wrong-whole-tree-intent-cannot-enter-candidate-custody')
        server.request('apply',f.inspect_form(),saved,code=403,key='read-only-denied',token=read_token)
        record(f,'read-credential-cannot-publish-the-reviewed-candidate')
        journal=f.root/'journal'
        staged=command(node,f,'stage',['stage','--candidate',candidate,'--sha256',receipt['manifest_sha256'],'--principal',PRINCIPAL,'--confirm-candidate',f.candidate,'--journal',journal])
        assert not staged['transmission_attempted']
        shutil.rmtree(candidate);patch.unlink();selected.unlink()
        apply=['apply','--journal',journal,'--request-sha256',staged['request_sha256'],'--token-file',write_file]
        start=time.monotonic()
        err=command(node,f,'lost-response',apply,4,closed=True)
        accepted=err['retained_result'];assert accepted['decision']['outcome']=='committed'
        bound=json.loads((journal/'request.json').read_bytes())
        assert bound['candidate_commit']==f.candidate and bound['expected_commit']==f.base
        assert accepted['request_sha256']==staged['request_sha256'] and accepted['key']==staged['key']
        assert (journal/'terminal.json').is_file()
        record(f,'large-publication-commits-after-source-recipe-removal-and-lost-stdout',shared_bytes=f.shared_bytes,seconds=time.monotonic()-start)
        next_body=b'later independent edit\n';next_blob=oid(f.fmt,'blob',next_body)
        next_tree_body=tree_bytes([*f.rows,(b'file',b'100644',next_blob)])
        next_tree=oid(f.fmt,'tree',next_tree_body)
        next_commit_body=f'tree {next_tree}\nparent {f.candidate}\nauthor {AUTHOR} 3 +0000\ncommitter {AUTHOR} 3 +0000\n\nlater\n'.encode()
        next_commit=oid(f.fmt,'commit',next_commit_body)
        next_bundle=bundle(f.fmt,f.candidate,next_commit,[('blob',next_body),('tree',next_tree_body),('commit',next_commit_body)])
        next_form=dict(f.inspect_form(),expected_commit=f.candidate,candidate_commit=next_commit)
        successor=server.request('apply',next_form,next_bundle,key='independent-successor',token=write_token)
        assert successor['outcome']=='committed'
        record(f,'independent-large-successor-publishes-through-ordinary-admission')
        (journal/'terminal.json').unlink()
        command(node,f,'no-resend',apply,2)
        recovered=command(node,f,'recover',['recover','--journal',journal,'--request-sha256',staged['request_sha256'],'--token-file',recovery_file])
        assert recovered['decision']['tx_id']==accepted['decision']['tx_id']
        assert recovered['decision']['outcome']=='committed' and recovered['submission_retried']is False
        assert recovered['key']==staged['key'] and recovered['request_sha256']==staged['request_sha256']
        record(f,'lost-terminal-recovers-original-key-after-a-newer-branch-commit-without-resend')
        status=command(node,f,'status',['status','--journal',journal,'--request-sha256',staged['request_sha256']])
        assert status['state']=='terminal' and status['decision']['tx_id']==accepted['decision']['tx_id']
    after=f.basis();assert after!=before
    shutil.rmtree(f.source)
    offline=command(node,f,'offline',apply)
    assert offline['decision']['tx_id']==accepted['decision']['tx_id'] and f.basis()==after
    record(f,'source-and-server-free-terminal-reopen-does-not-change-canonical-state')
    for identity in [f.candidate,f.expected_tree,next_commit,next_tree,*f.shared]:
        observed=f.command('native-object',['doctor',*f.scope,identity])
        assert b'verified object sample'in observed and identity.encode()in observed
    assert f.basis()==after
    record(f,'every-inherited-blob-and-both-candidate-roots-reread-through-native-verification')

if __name__=='__main__':
    fg,node,root=str(Path(sys.argv[1]).resolve()),str(Path(sys.argv[2]).resolve()),Path(sys.argv[3]).resolve()
    root.mkdir(parents=True,exist_ok=True)
    for fmt in ['sha1','sha256']:campaign(LargeFixture(fg,root,fmt),node)
    (root/'results.json').write_text(json.dumps(RESULTS,indent=2)+'\n')
