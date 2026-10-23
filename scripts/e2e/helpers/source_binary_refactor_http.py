"""Actual Node patch author and Rust HTTP preparation/publication, no stand-in peer."""
import base64
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import zlib
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patch_smoke import oid, loose, bundle_objects
from source_result_tree import Fixture, HTTP, complete_tree, AUTHOR, MESSAGE, TENANT, REPOSITORY, PRINCIPAL
REPO = Path(__file__).resolve().parents[3]
RESULTS = []
PROFILE = 'exact-tree-binary-v1'
def record(f, case, **detail):
    row = dict(format=f.fmt, encoding=f.encoding, case=case, **detail)
    RESULTS.append(row); print(json.dumps(row), flush=True)
def member(body):
    compressed = zlib.compress(body); rows = [f'literal {len(body)}\n'.encode()]
    for start in range(0, len(compressed), 52):
        block = compressed[start:start+52]; n = len(block)
        rows.append(bytes([65+n-1 if n <= 26 else 97+n-27])+base64.b85encode(block, pad=True)+b'\n')
    return b''.join(rows)+b'\n'
class BinaryFixture(Fixture):
    def __init__(self, fg, node_bin, root, fmt, encoding):
        self.fg, self.node_bin, self.fmt, self.encoding, self.sequence = fg, node_bin, fmt, encoding, 0
        self.root = root / (fmt+'-'+encoding); self.root.mkdir(mode=0o700)
        self.source, self.node = self.root/'source', self.root/'node'
        self.scope = [self.node, TENANT, REPOSITORY]
        old = b'\0' + b'A'*(4095 if encoding == 'literal' else 1048575)
        new = bytearray(old); new[len(new)//2] = 66
        if encoding == 'delta-runs': new[100] = 67; new[-100] = 68
        new = bytes(new)
        self.old_path, self.new_path = b'old/data \xff.bin', b'lib/image \xfe.bin'
        self.files = {self.old_path:(b'100644', old), b'old/tool.txt':(b'100644', b'before\n'),
            b'ordinary.bin':(b'100644', b'old\0body'), b'obsolete.txt':(b'100644', b'delete\n'), b'keep.bin':(b'100644', b'keep\0sibling')}
        self.expected_files = {self.new_path:(b'100755', new), b'lib/tool.txt':(b'100755', b'after\n'),
            b'ordinary.bin':(b'100644', b'new\0body'), b'created.txt':(b'100644', b'created\n'), b'keep.bin':self.files[b'keep.bin']}
        (self.source/'refs/heads').mkdir(parents=True)
        (self.source/'HEAD').write_text('ref: refs/heads/main\n')
        (self.source/'config').write_text('[core]\nbare=true\nrepositoryformatversion='+('0\n' if fmt=='sha1' else '1\n[extensions]\nobjectformat=sha256\n'))
        self.original_objects = {}
        def store(kind, body):
            identity = loose(self.source, fmt, kind, body); self.original_objects[identity] = (kind, body); return identity
        self.old_tree = complete_tree(fmt, self.files, store)
        self.base = store('commit', f'tree {self.old_tree}\nauthor {AUTHOR} 1 +0000\ncommitter {AUTHOR} 1 +0000\n\nbase\n'.encode())
        (self.source/'refs/heads/main').write_text(self.base+'\n')
        self.objects = {}
        def expect(kind, body):
            identity = oid(fmt, kind, body); self.objects[identity] = (kind, body); return identity
        self.expected_tree = complete_tree(fmt, self.expected_files, expect)
        self.commit_body = f'tree {self.expected_tree}\nparent {self.base}\nauthor {AUTHOR} 2 +0000\ncommitter {AUTHOR} 2 +0000\n\n{MESSAGE}'.encode()
        self.candidate = expect('commit', self.commit_body)
        for identity in set(self.objects)-set(self.original_objects): assert not (self.source/'objects'/identity[:2]/identity[2:]).exists()
        changes = []
        for i, (before_path, after_path) in enumerate([(self.old_path,self.new_path),(b'old/tool.txt',b'lib/tool.txt'),(b'ordinary.bin',b'ordinary.bin'),(b'obsolete.txt',None),(None,b'created.txt')]):
            row = dict(path_hex=(before_path or after_path).hex(), before=None, after=None)
            for side, path, files in [('before',before_path,self.files), ('after',after_path,self.expected_files)]:
                if path is None: continue
                mode, body = files[path]; file = self.root/f'{side}-{i}'; file.write_bytes(body); file.chmod(0o600)
                row[side] = dict(file=str(file),mode=int(mode,8))
                if side == 'before': row[side]['blob'] = oid(fmt,'blob',body)
            if before_path and after_path and before_path != after_path: row['destination_hex'] = after_path.hex()
            changes.append(row)
        plan = self.root/'plan.json'; plan.write_text(json.dumps(dict(schema='frankengit-source-refactoring-v1',object_format=fmt,changes=changes))); plan.chmod(0o600)
        patch = self.root/'change.patch'
        result = subprocess.run([node_bin,str(REPO/'scripts/fg_source_refactor.mjs'),'compile','--plan-file',str(plan),'--output',str(patch),'--profile',PROFILE,'--binary',encoding],capture_output=True,timeout=90)
        assert result.returncode == 0, result.stderr
        self.authored = json.loads(result.stdout); self.patch = patch.read_bytes()
        assert self.authored['patch_sha256'] == hashlib.sha256(self.patch).hexdigest()
        if encoding != 'literal': assert len(self.patch) < 2500
        self.command('init',['init',*self.scope,fmt])
        imported = json.loads(self.command('import',['import',*self.scope,PRINCIPAL,'fixture',self.source,'--json']))
        self.incarnation = imported['repository_incarnation_id']
        self.token, self.read_token, self.write_token = (secrets.token_hex(32) for _ in range(3))
        header = self.command('header',['serve-http',*self.scope,'127.0.0.1:0','--trusted-local','--print-credentials-header']).decode().strip()
        self.grants = self.root/'grants'
        self.grants.write_text(header+'\n'+''.join(hashlib.sha256(token.encode()).hexdigest()+f' {PRINCIPAL} {permissions}\n' for token,permissions in [(self.token,'read,receive,outcomes-read'),(self.read_token,'read'),(self.write_token,'receive')]))
        self.grants.chmod(0o600)
    def validate(self, metadata, bundle):
        assert metadata['root_tree'] == self.expected_tree and metadata['candidate_commit'] == self.candidate
        assert metadata['source_commit'] == self.base and metadata['patch_profile'] == PROFILE
        for key in ['published','objects_staged','transaction_created','publication_authorized']: assert metadata[key] is False
        assert metadata['bundle'] == dict(bytes=len(bundle),sha256=hashlib.sha256(bundle).hexdigest())
        packed = bundle_objects(bundle,self.fmt,self.base,self.candidate)
        for identity,value in self.objects.items(): assert packed.get(identity,self.original_objects.get(identity)) == value
        paths = {bytes.fromhex(row['path_hex']):row for row in metadata['paths']}
        assert set(paths) == (set(self.files)|set(self.expected_files))-{b'keep.bin'}
        for path,row in paths.items():
            assert row['old_blob'] == (oid(self.fmt,'blob',self.files[path][1]) if path in self.files else None)
            assert row['new_blob'] == (oid(self.fmt,'blob',self.expected_files[path][1]) if path in self.expected_files else None)
            assert row['new_mode'] == (int(self.expected_files[path][0],8) if path in self.expected_files else None)

def campaign(f):
    basis = f.basis(); form = f.form(); explicit = dict(form,patch_profile=PROFILE,expected_result_tree=f.expected_tree)
    with HTTP(f,'prepare') as server:
        meta,bundle = server.request('prepare',explicit,f.patch,chunked=True,token=f.read_token)
        f.validate(meta,bundle); assert meta['expected_result_tree'] == f.expected_tree
        record(f,'real-author-http-independent-complete-result',patch_bytes=len(f.patch),moved_bytes=len(f.files[f.old_path][1]))
        assert server.request('prepare',explicit,f.patch) == (meta,bundle)
        record(f,'chunked-and-length-framed-preparation-identical')
        for label,selected in [('absent',form),('legacy',dict(form,patch_profile='exact-tree-v1'))]:
            error = server.request('prepare',selected,f.patch,code=400)
            assert b'invalid_source_patch' in error
            record(f,label+'-profile-refuses-edited-binary-move')
        for label,value in [('empty',''),('unknown','exact-tree-binary-v2'),('case','Exact-tree-binary-v1')]:
            error = server.request('prepare',dict(form,patch_profile=value),f.patch,code=400)
            assert b'unsupported_source_patch_profile' in error
            record(f,label+'-profile-not-defaulted')
        server.request('prepare',list(form.items())+[('patch_profile',PROFILE),('patch_profile',PROFILE)],f.patch,code=400)
        record(f,'duplicate-profile-refuses')
        error = server.request('prepare',dict(explicit,expected_result_tree=f.old_tree),f.patch,code=409)
        assert b'patch_result_tree_mismatch' in error
        record(f,'whole-result-intent-still-enforced')
        marker = f.patch.index(b'GIT binary patch\n')+len(b'GIT binary patch\n')
        start = f.patch.index(b'\n\n',marker)+2; end = f.patch.index(b'\n\n',start)+2
        corrupt = f.patch[:start]+member(b'wrong\0reverse')+f.patch[end:]
        occupied = f.patch.replace(b'lib/image\\040\\376.bin',b'keep.bin'); assert occupied != f.patch
        for label,data in [('reverse-corruption',corrupt),('occupied-destination',occupied)]:
            error = server.request('prepare',explicit,data,code=400); assert b'invalid_source_patch' in error
            record(f,label+'-returns-no-candidate')
        server.request('prepare',explicit,f.patch,code=401,token='invalid-fixture-token')
        server.request('prepare',explicit,f.patch,code=403,token=f.write_token)
        record(f,'profile-cannot-grant-source-read')
        ordinary = b'diff --git a/old/tool.txt b/old/tool.txt\n--- a/old/tool.txt\n+++ b/old/tool.txt\n@@ -1 +1 @@\n-before\n+after\n'
        old,old_bundle = server.request('prepare',form,ordinary)
        assert 'patch_profile' not in old
        for value in ['exact-tree-v1',PROFILE]:
            current,same = server.request('prepare',dict(form,patch_profile=value),ordinary)
            assert current.pop('patch_profile') == value and current == old and same == old_bundle
        record(f,'explicit-profile-preserves-ordinary-candidate-and-legacy-receipt')
        coordinates = dict(object_format=f.fmt,ref='refs/heads/main',expected_commit=f.base,candidate_commit=f.candidate)
        server.request('inspect',dict(coordinates,patch_profile=PROFILE),bundle,code=400)
        inspection = server.request('inspect',coordinates,bundle)
        assert inspection['candidate_commit'] == f.candidate and inspection['comparison']['after_tree'].split(':')[-1] == f.expected_tree
        assert bytes.fromhex(inspection['candidate_commit_body_hex']) == f.commit_body
        record(f,'inspection-still-binds-reviewed-bundle-not-profile')
    assert f.basis() == basis
    record(f,'preparation-and-all-refusals-preserve-authority')
    with HTTP(f,'reopen') as server:
        assert server.request('prepare',explicit,f.patch) == (meta,bundle)
        record(f,'fresh-process-reproduces-original-candidate')
        server.request('apply',dict(coordinates,patch_profile=PROFILE),bundle,code=400,key='unused-profile')
        server.request('apply',coordinates,bundle,code=403,key='unused-read-token',token=f.read_token)
        accepted = server.request('apply',coordinates,bundle,key='reviewed-binary-move',token=f.write_token)
        assert accepted['outcome'] == 'committed'
        assert server.request('apply',coordinates,bundle,key='reviewed-binary-move',token=f.write_token) == accepted
        server.request('prepare',explicit,f.patch,code=409)
        record(f,'ordinary-reviewed-admission-and-original-key-retry')
    after = f.basis(); assert after != basis
    shutil.rmtree(f.source)
    with HTTP(f,'recover') as server:
        assert server.request('apply',coordinates,bundle,key='reviewed-binary-move',token=f.write_token) == accepted
    assert f.basis() == after
    for identity in [f.candidate,f.expected_tree,oid(f.fmt,'blob',f.expected_files[f.new_path][1]),oid(f.fmt,'blob',f.files[b'keep.bin'][1])]:
        result = f.command('canonical-reread',['doctor',*f.scope,identity]); assert b'verified object sample' in result
    record(f,'source-free-native-object-reread-and-publication-recovery')

if __name__ == '__main__':
    fg,node_bin,root = str(Path(sys.argv[1]).resolve()),str(Path(sys.argv[2]).resolve()),Path(sys.argv[3]).resolve()
    root.mkdir(parents=True,exist_ok=True)
    for fmt in ('sha1','sha256'):
        for encoding in ('literal','delta','delta-runs'): campaign(BinaryFixture(fg,node_bin,root,fmt,encoding))
    (root/'results.json').write_text(json.dumps(RESULTS,indent=2)+'\n')
