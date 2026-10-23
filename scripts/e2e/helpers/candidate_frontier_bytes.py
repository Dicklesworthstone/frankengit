"""Actual native HTTP candidate inspection above a large shared blob frontier.
Python constructs native objects and candidate packs; no mock node or Git engine.
"""
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time
import zlib
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from patch_smoke import oid,loose,bundle_objects
from source_result_tree import Fixture,HTTP,tree_bytes,AUTHOR,MESSAGE,TENANT,REPOSITORY,PRINCIPAL
RESULTS=[]

def record(f,case,**detail):
    row=dict(format=f.fmt,case=case,**detail);RESULTS.append(row);print(json.dumps(row),flush=True)

def bundle(fmt,base,candidate,objects):
    packed=bytearray(b'PACK'+(2).to_bytes(4,'big')+len(objects).to_bytes(4,'big'))
    for kind,body in objects:
        code={'commit':1,'tree':2,'blob':3}[kind];size=len(body);first=(code<<4)|(size&15);size>>=4
        packed.append(first|(128 if size else 0))
        while size:
            byte=size&127;size>>=7;packed.append(byte|(128 if size else 0))
        packed.extend(zlib.compress(body))
    packed.extend(hashlib.new(fmt,packed).digest())
    header=('# v2 git bundle\n' if fmt=='sha1' else '# v3 git bundle\n@object-format=sha256\n')
    return (header+f'-{base} base\n{candidate} refs/heads/main\n\n').encode()+packed

class LargeFixture(Fixture):
    def __init__(self,fg,root,fmt,count=7,blob_bytes=20*1024*1024):
        self.fg,self.root,self.fmt,self.sequence=fg,root/fmt,fmt,0
        self.root.mkdir(parents=True,mode=0o700)
        self.source,self.node=self.root/'source',self.root/'node';self.scope=[self.node,TENANT,REPOSITORY]
        (self.source/'refs/heads').mkdir(parents=True)
        (self.source/'HEAD').write_text('ref: refs/heads/main\n')
        (self.source/'config').write_text('[core]\nbare=true\nrepositoryformatversion='+('0\n'if fmt=='sha1'else'1\n[extensions]\nobjectformat=sha256\n'))
        self.rows=[];self.shared=[];self.shared_bytes=count*blob_bytes
        for index in range(count):
            body=bytes([65+index])*blob_bytes
            identity=loose(self.source,fmt,'blob',body);self.shared.append(identity)
            self.rows.append((f'asset-{index}'.encode(),b'100644',identity))
        self.old=b'before\n';self.new=b'after\n'
        self.old_blob=loose(self.source,fmt,'blob',self.old)
        self.old_tree=loose(self.source,fmt,'tree',tree_bytes([*self.rows,(b'file',b'100644',self.old_blob)]))
        self.base=loose(self.source,fmt,'commit',f'tree {self.old_tree}\nauthor {AUTHOR} 1 +0000\ncommitter {AUTHOR} 1 +0000\n\nbase\n'.encode())
        (self.source/'refs/heads/main').write_text(self.base+'\n')
        self.hidden_body=b'private original\n';self.hidden_blob=loose(self.source,fmt,'blob',self.hidden_body)
        hidden_tree=loose(self.source,fmt,'tree',tree_bytes([(b'secret',b'100644',self.hidden_blob)]))
        hidden_commit=loose(self.source,fmt,'commit',f'tree {hidden_tree}\nauthor {AUTHOR} 1 +0000\ncommitter {AUTHOR} 1 +0000\n\nprivate\n'.encode())
        (self.source/'refs/heads/private').write_text(hidden_commit+'\n')
        self.new_blob=oid(fmt,'blob',self.new)
        self.new_tree_body=tree_bytes([*self.rows,(b'file',b'100644',self.new_blob)])
        self.expected_tree=oid(fmt,'tree',self.new_tree_body)
        self.commit_body=f'tree {self.expected_tree}\nparent {self.base}\nauthor {AUTHOR} 2 +0000\ncommitter {AUTHOR} 2 +0000\n\n{MESSAGE}'.encode()
        self.candidate=oid(fmt,'commit',self.commit_body)
        self.objects=[('blob',self.new),('tree',self.new_tree_body),('commit',self.commit_body)]
        self.minimal=bundle(fmt,self.base,self.candidate,self.objects)
        self.thick=bundle(fmt,self.base,self.candidate,[*self.objects,('blob',bytes([65])*blob_bytes)])
        self.patch=(f'diff --git a/file b/file\nindex {self.old_blob}..{self.new_blob} 100644\n--- a/file\n+++ b/file\n@@ -1 +1 @@\n-before\n+after\n').encode()
        self.command('init',['init',*self.scope,fmt])
        imported=json.loads(self.command('import',['import',*self.scope,PRINCIPAL,'large-frontier',self.source,'--json']))
        self.incarnation=imported['repository_incarnation_id']
        self.token=secrets.token_hex(32)
        header=self.command('header',['serve-http',*self.scope,'127.0.0.1:0','--trusted-local','--print-credentials-header']).decode().strip()
        self.grants=self.root/'grants';self.grants.write_text(header+'\n'+hashlib.sha256(self.token.encode()).hexdigest()+f' {PRINCIPAL} read,receive,outcomes-read\n');self.grants.chmod(0o600)
    def inspect_form(self):
        return dict(object_format=self.fmt,ref='refs/heads/main',expected_commit=self.base,candidate_commit=self.candidate)
    def validate_inspection(self,value):
        assert value['candidate_commit']==self.candidate and value['expected_commit']==self.base
        assert value['parents']==[self.base] and value['read_only'] and not value['published'] and not value['objects_staged']
        assert bytes.fromhex(value['candidate_commit_body_hex'])==self.commit_body
        comparison=value['comparison'];assert comparison['before_tree']==self.old_tree and comparison['after_tree']==self.expected_tree
        assert comparison['entry_count']==len(comparison['entries'])==1
        row=comparison['entries'][0];assert row['path_hex']==b'file'.hex() and row['kind']=='modified'
        assert row['before']==dict(mode=0o100644,oid=self.old_blob) and row['after']==dict(mode=0o100644,oid=self.new_blob)
        assert row['content']['type']=='text'
        assert b''.join(bytes.fromhex(h['before_hex'])for h in row['content']['hunks'])==self.old
        assert b''.join(bytes.fromhex(h['after_hex'])for h in row['content']['hunks'])==self.new

def campaign(f):
    assert f.shared_bytes>128*1024*1024
    basis=f.basis();form=f.inspect_form()
    for identity in [f.candidate,f.expected_tree,f.new_blob]:assert not (f.source/'objects'/identity[:2]/identity[2:]).exists()
    with HTTP(f,'inspection')as server:
        def read_chars():
            lines=Path(f'/proc/{server.process.pid}/io').read_text().splitlines()
            return int(next(line.split(':',1)[1]for line in lines if line.startswith('rchar:')))
        previous_io=read_chars()
        started=time.monotonic();minimal=server.request('inspect',form,f.minimal);elapsed=time.monotonic()-started
        read_bytes=read_chars()-previous_io
        assert read_bytes < 8*1024*1024, ('unchanged blob payloads were read',read_bytes)
        f.validate_inspection(minimal)
        record(f,'minimal-candidate-review-above-128-mib-shared-payload',shared_bytes=f.shared_bytes,seconds=elapsed,process_read_characters=read_bytes)
        thick=server.request('inspect',form,f.thick);f.validate_inspection(thick)
        assert thick['comparison']==minimal['comparison'] and thick['candidate_commit_body_hex']==minimal['candidate_commit_body_hex']
        record(f,'thick-and-minimal-bundles-have-identical-whole-result-review')
        meta,prepared=server.request('prepare',dict(f.form(),expected_result_tree=f.expected_tree),f.patch)
        assert meta['candidate_commit']==f.candidate and meta['root_tree']==f.expected_tree
        packed=bundle_objects(prepared,f.fmt,f.base,f.candidate)
        for kind,body in f.objects:assert packed[oid(f.fmt,kind,body)]==(kind,body)
        f.validate_inspection(server.request('inspect',form,prepared,chunked=True))
        record(f,'actual-native-preparation-produces-the-independently-reviewed-result')
        bad=f.minimal[:-1]+bytes([f.minimal[-1]^1])
        server.request('inspect',form,bad,code=503)
        record(f,'corrupt-candidate-pack-cannot-become-a-partial-review')
        hidden_tree=tree_bytes([*f.rows,(b'file',b'100644',f.hidden_blob)])
        hidden_root=oid(f.fmt,'tree',hidden_tree)
        hidden_body=f'tree {hidden_root}\nparent {f.base}\nauthor {AUTHOR} 2 +0000\ncommitter {AUTHOR} 2 +0000\n\n{MESSAGE}'.encode()
        hidden_id=oid(f.fmt,'commit',hidden_body)
        hidden_form=dict(form,candidate_commit=hidden_id)
        incomplete=bundle(f.fmt,f.base,hidden_id,[('tree',hidden_tree),('commit',hidden_body)])
        server.request('inspect',hidden_form,incomplete,code=503)
        complete=bundle(f.fmt,f.base,hidden_id,[('blob',f.hidden_body),('tree',hidden_tree),('commit',hidden_body)])
        permitted=server.request('inspect',hidden_form,complete)
        assert permitted['candidate_commit']==hidden_id and permitted['comparison']['after_tree']==hidden_root
        assert permitted['comparison']['entry_count']==1
        record(f,'unrelated-admitted-blob-refuses-unless-its-bytes-are-supplied')
        badrows=[(name,b'40000'if name==b'asset-0'else mode,identity)for name,mode,identity in f.rows]
        wrong_tree=tree_bytes([*badrows,(b'file',b'100644',f.new_blob)])
        wrong_root=oid(f.fmt,'tree',wrong_tree)
        wrong_body=f'tree {wrong_root}\nparent {f.base}\nauthor {AUTHOR} 2 +0000\ncommitter {AUTHOR} 2 +0000\n\n{MESSAGE}'.encode()
        wrong_id=oid(f.fmt,'commit',wrong_body)
        wrong=bundle(f.fmt,f.base,wrong_id,[('blob',f.new),('tree',wrong_tree),('commit',wrong_body)])
        server.request('inspect',dict(form,candidate_commit=wrong_id),wrong,code=503)
        record(f,'typed-original-edge-rejects-blob-as-directory')
    assert f.basis()==basis
    with HTTP(f,'reopen')as server:
        again=server.request('inspect',form,f.minimal);assert again==minimal
        record(f,'fresh-process-reproduces-the-exact-read-only-inspection')
    assert f.basis()==basis
    shutil.rmtree(f.source)
    with HTTP(f,'source-free')as server:
        again=server.request('inspect',form,f.minimal);assert again==minimal
    assert f.basis()==basis
    record(f,'source-free-inspection-keeps-canonical-state-unchanged')

def publication_control(f):
    # Receive quarantine has its own original-payload obligation/byte limit.
    # Do not silently widen it or present the large inspector as a large push.
    basis=f.basis();form=f.inspect_form()
    with HTTP(f,'publish-control')as server:
        reviewed=server.request('inspect',form,f.minimal);f.validate_inspection(reviewed)
        accepted=server.request('apply',form,f.minimal,key='frontier-reviewed-control')
        assert accepted['outcome']=='committed'
        assert server.request('apply',form,f.thick,key='frontier-reviewed-control')==accepted
        record(f,'bounded-publication-control-keeps-original-key-across-encodings',shared_bytes=f.shared_bytes)
    current=f.basis();assert current!=basis
    shutil.rmtree(f.source)
    with HTTP(f,'recover-control')as server:
        assert server.request('apply',form,f.minimal,key='frontier-reviewed-control')==accepted
    for identity in [f.candidate,f.expected_tree,f.new_blob,f.shared[0]]:
        result=f.command('object',['doctor',*f.scope,identity]);assert b'verified object sample'in result and identity.encode()in result
    assert f.basis()==current
    record(f,'bounded-source-free-publication-control-recovers-original-result')

if __name__=='__main__':
    fg,root=str(Path(sys.argv[1]).resolve()),Path(sys.argv[2]).resolve();root.mkdir(parents=True,exist_ok=True)
    for fmt in ['sha1','sha256']:
        campaign(LargeFixture(fg,root,fmt))
        publication_control(LargeFixture(fg,root/'publication-control',fmt,count=1))
    (root/'results.json').write_text(json.dumps(RESULTS,indent=2)+'\n')
