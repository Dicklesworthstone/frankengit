"""Actual Node author -> native fg preparation/admission, independent object oracle.
No HTTP stand-in or stock Git engine participates in this campaign.
"""
import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import zlib
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patch_smoke import loose, oid, bundle_objects
FG, NODE, ROOT = str(Path(sys.argv[1]).resolve()), str(Path(sys.argv[2]).resolve()), Path(sys.argv[3]).resolve()
REPO = Path(__file__).resolve().parents[3]
AUTHOR = REPO / 'scripts/fg_source_refactor.mjs'
ROOT.mkdir(parents=True, exist_ok=True)
SEQUENCE, RESULTS = 0, []
def invoke(label, executable, args, code=0):
    global SEQUENCE
    SEQUENCE += 1
    out, err = (ROOT / f'{SEQUENCE:04d}-{label}.{s}' for s in ('out', 'err'))
    with out.open('wb') as stdout, err.open('wb') as stderr:
        result = subprocess.run([executable, *map(str, args)], stdout=stdout, stderr=stderr, timeout=90)
    diagnostic = err.read_bytes()
    if diagnostic: sys.stderr.buffer.write(diagnostic); sys.stderr.buffer.flush()
    assert result.returncode == code, (label, result.returncode, out.read_bytes()[-4000:], diagnostic[-3000:])
    return out.read_bytes()
def record(fmt, encoding, case, **values):
    row = dict(format=fmt, encoding=encoding, case=case, **values)
    RESULTS.append(row); print(json.dumps(row), flush=True)
def member(body):
    compressed = zlib.compress(body)
    rows = [f'literal {len(body)}\n'.encode()]
    for start in range(0, len(compressed), 52):
        block = compressed[start:start+52]; n = len(block)
        rows.append(bytes([65+n-1 if n <= 26 else 97+n-27])+base64.b85encode(block, pad=True)+b'\n')
    return b''.join(rows)+b'\n'
def object_tree(fmt, files, source=None):
    objects = {}
    def store(kind, body):
        identity = oid(fmt, kind, body); objects[identity] = (kind, body)
        if source is not None: assert loose(source, fmt, kind, body) == identity
        return identity
    def directory(prefix):
        names = {p[len(prefix):].split(b'/',1)[0] for p in files if p.startswith(prefix)}
        entries = []
        for name in names:
            path = prefix+name
            if path in files:
                mode, body = files[path]; identity = store('blob', body)
            else: mode = b'40000'; identity = directory(path+b'/')
            entries.append((mode, name, identity))
        entries.sort(key=lambda row: row[1]+(b'/' if row[0] == b'40000' else b'\0'))
        body = b''.join(mode+b' '+name+b'\0'+bytes.fromhex(identity) for mode,name,identity in entries)
        return store('tree', body)
    return directory(b''), objects
for fmt in ('sha1', 'sha256'):
    for encoding in ('literal', 'delta', 'delta-runs'):
        home = ROOT / f'{fmt}-{encoding}'; home.mkdir(mode=0o700)
        source, node = home/'source', home/'node'
        (source/'refs/heads').mkdir(parents=True)
        (source/'HEAD').write_text('ref: refs/heads/main\n')
        (source/'config').write_text('[core]\nbare=true\nrepositoryformatversion='+('0\n' if fmt=='sha1' else '1\n[extensions]\nobjectformat=sha256\n'))
        original = b'\0'+b'A'*(4095 if encoding=='literal' else 1048575)
        edited = bytearray(original); edited[len(edited)//2] = 66
        if encoding=='delta-runs': edited[100] = 67; edited[-100] = 68
        edited = bytes(edited)
        old_path, new_path = b'old/asset \xff.bin', b'lib/image \xfe.bin'
        before = {old_path:(b'100644',original), b'old/text.txt':(b'100644',b'before\n'),
            b'same.bin':(b'100644',b'old\0same'), b'obsolete.txt':(b'100644',b'delete\n'), b'keep.bin':(b'100644',b'keep\0sibling')}
        after = {new_path:(b'100755',edited), b'lib/tool.txt':(b'100755',b'after\n'),
            b'same.bin':(b'100644',b'new\0same'), b'README.md':(b'100644',b'created\n'), b'keep.bin':before[b'keep.bin']}
        base_tree, original_objects = object_tree(fmt, before, source)
        author = 'Binary Refactor <test@example.invalid>'
        base = loose(source, fmt, 'commit', f'tree {base_tree}\nauthor {author} 1 +0000\ncommitter {author} 1 +0000\n\nbase\n'.encode())
        (source/'refs/heads/main').write_text(base+'\n')
        result_tree, expected_objects = object_tree(fmt, after)
        commit_body = f'tree {result_tree}\nparent {base}\nauthor {author} 2 +0000\ncommitter {author} 2 +0000\n\nbinary refactor\n'.encode()
        candidate = oid(fmt,'commit',commit_body); expected_objects[candidate] = ('commit',commit_body)
        for identity in set(expected_objects)-set(original_objects): assert not (source/'objects'/identity[:2]/identity[2:]).exists()
        changes = []
        for index, (oldpath,newpath) in enumerate([(old_path,new_path),(b'old/text.txt',b'lib/tool.txt'),(b'same.bin',b'same.bin'),(b'obsolete.txt',None),(None,b'README.md')]):
            row = dict(path_hex=(oldpath or newpath).hex(),before=None,after=None)
            if oldpath is not None:
                mode, body = before[oldpath]; file = home/f'old-{index}'; file.write_bytes(body); file.chmod(0o600)
                row['before'] = dict(file=str(file),mode=int(mode,8),blob=oid(fmt,'blob',body))
            if newpath is not None:
                mode, body = after[newpath]; file = home/f'new-{index}'; file.write_bytes(body); file.chmod(0o600)
                row['after'] = dict(file=str(file),mode=int(mode,8))
            if oldpath and newpath and oldpath != newpath: row['destination_hex'] = newpath.hex()
            changes.append(row)
        plan = home/'plan.json'; plan.write_text(json.dumps(dict(schema='frankengit-source-refactoring-v1',object_format=fmt,changes=changes))); plan.chmod(0o600)
        patch = home/'change.patch'
        compile_args = [AUTHOR,'compile','--plan-file',plan,'--output',patch,'--profile','exact-tree-binary-v1','--binary',encoding]
        old_args = list(compile_args); old_args[old_args.index('--profile')+1] = 'exact-tree-v1'
        invoke('legacy-author',NODE,old_args,2); assert not patch.exists()
        authored = json.loads(invoke('author',NODE,compile_args)); patch_bytes = patch.read_bytes()
        assert authored['profile']=='frankengit-source-refactoring-binary-v1' and authored['native_patch_profile']=='exact-tree-binary-v1'
        assert authored['plan_sha256']==hashlib.sha256(plan.read_bytes()).hexdigest() and authored['patch_sha256']==hashlib.sha256(patch_bytes).hexdigest()
        assert authored['move_count']==2 and authored['file_sections']==5 and authored['changed_paths']==7
        assert not authored['source_membership_verified'] and not authored['destinations_absent_verified'] and not authored['publication_attempted']
        if encoding!='literal': assert len(patch_bytes)<2500 and authored['delta_members']>=2
        invoke('no-overwrite',NODE,compile_args,2); assert patch.read_bytes()==patch_bytes
        record(fmt,encoding,'actual-author-and-legacy-refusal',patch_bytes=len(patch_bytes),moved_source_bytes=len(original))
        scope = [node,'b1'*16,'b2'*16]; principal='b3'*16
        invoke('init',FG,['init',*scope,fmt]); invoke('import',FG,['import',*scope,principal,'fixture',source])
        listing = ['pr','list',*scope,'--trusted-local','--object-format',fmt]
        authority = invoke('basis',FG,listing)
        output = home/'candidate.bundle'
        args = ['patch','prepare',*scope,'refs/heads/main',patch,output,'--trusted-local','--profile','exact-tree-binary-v1',
            '--workspace-id','b4'*16,'--expected-base',base,'--expected-result-tree',result_tree,'--author',author,'--timestamp','2','--message','binary refactor\n']
        for profile in ('exact-v1','exact-binary-v1','exact-tree-v1'):
            bad = list(args); bad[bad.index('--profile')+1]=profile
            invoke('legacy-native',FG,bad,2); assert not output.exists() and invoke('basis',FG,listing)==authority
            record(fmt,encoding,'native-legacy-refusal',profile=profile)
        prepared = json.loads(invoke('prepare',FG,args))
        assert prepared['profile']=='exact-tree-binary-v1' and prepared['candidate_commit']==candidate and prepared['root_tree']==result_tree
        assert prepared['expected_result_tree']==result_tree and prepared['node_closed'] and not prepared['published_to_repository']
        packed = bundle_objects(output.read_bytes(),fmt,base,candidate)
        for identity, wanted in expected_objects.items(): assert packed.get(identity,original_objects.get(identity))==wanted,(identity,wanted[0])
        effects = {bytes.fromhex(r['path_hex']):r for r in prepared['paths']}
        wanted_paths = set(before)|set(after); wanted_paths.remove(b'keep.bin')
        assert set(effects)==wanted_paths
        for path, effect in effects.items():
            assert effect['old_blob']==(oid(fmt,'blob',before[path][1]) if path in before else None)
            assert effect['new_blob']==(oid(fmt,'blob',after[path][1]) if path in after else None)
            assert effect['new_mode']==(after[path][0].decode() if path in after else None)
        assert invoke('basis',FG,listing)==authority
        record(fmt,encoding,'independent-complete-tree-blob-mode-and-commit')
        again = list(args); again[7]=home/'again.bundle'; again+=['--max-files','5','--max-input-bytes',str(len(patch_bytes))]
        assert json.loads(invoke('repeat-prepare',FG,again))==prepared and again[7].read_bytes()==output.read_bytes()
        record(fmt,encoding,'exact-budgets-and-deterministic-native-reopen')
        bad = list(args); bad[7]=home/'wrong-tree.bundle'; bad[bad.index('--expected-result-tree')+1]=base_tree
        invoke('wrong-result-tree',FG,bad,2); assert not bad[7].exists() and invoke('basis',FG,listing)==authority
        bad = list(args); bad[7]=home/'small.bundle'; bad+=['--max-input-bytes',str(len(patch_bytes)-1)]
        invoke('one-byte-over-budget',FG,bad,2); assert not bad[7].exists() and invoke('basis',FG,listing)==authority
        record(fmt,encoding,'result-intent-and-budget-refuse-before-output')
        marker = patch_bytes.index(b'GIT binary patch\n')+len(b'GIT binary patch\n')
        reverse_start = patch_bytes.index(b'\n\n',marker)+2
        reverse_end = patch_bytes.index(b'\n\n',reverse_start)+2
        corrupt_reverse = patch_bytes[:reverse_start]+member(b'wrong\0reverse')+patch_bytes[reverse_end:]
        occupied = patch_bytes.replace(b'lib/image\\040\\376.bin',b'keep.bin')
        assert occupied != patch_bytes
        late = patch_bytes+b'diff --git a/zzz b/zzz\n--- a/zzz\n+++ b/zzz\n@@ -1 +1 @@\n-missing\n+bad\n'
        for label, data in [('corrupt-reverse',corrupt_reverse),('occupied-destination',occupied),('late-file-failure',late)]:
            badpatch = home/(label+'.patch'); badpatch.write_bytes(data)
            bad = list(args); bad[6]=badpatch; bad[7]=home/(label+'.bundle')
            invoke(label,FG,bad,2); assert not bad[7].exists() and invoke('basis',FG,listing)==authority
            record(fmt,encoding,label+'-no-partial-publication')
        lost = list(args); lost[7]=home/'lost.bundle'
        with (home/'lost.err').open('wb') as err:
            child = subprocess.Popen([FG,*map(str,lost)],stdout=subprocess.PIPE,stderr=err)
            child.stdout.close(); assert child.wait(timeout=90)==2
        assert lost[7].read_bytes()==output.read_bytes() and invoke('basis',FG,listing)==authority
        invoke('lost-retry',FG,lost,2); assert lost[7].read_bytes()==output.read_bytes()
        record(fmt,encoding,'lost-stdout-retains-exact-bundle-and-refuses-overwrite')
        apply = ['patch','apply',*scope,'refs/heads/main',output,'--trusted-local','--principal',principal,'--idempotency-key','binary-refactor',
            '--expected-base',base,'--expected-commit',candidate]
        bad = list(apply); bad[-1]=base
        invoke('wrong-reviewed-commit',FG,bad,2); assert invoke('basis',FG,listing)==authority
        terminal = json.loads(invoke('apply',FG,apply)); assert terminal['outcome']=='committed' and terminal['candidate_commit']==candidate
        current = invoke('basis',FG,listing); assert current!=authority
        shutil.rmtree(source)
        for identity in [candidate,result_tree,oid(fmt,'blob',edited),oid(fmt,'blob',after[b'keep.bin'][1])]:
            checked = invoke('native-object-read',FG,['doctor',*scope,identity])
            assert b'verified object sample' in checked and identity.encode() in checked
        record(fmt,encoding,'native-reopened-canonical-object-verification')
        assert json.loads(invoke('source-free-retry',FG,apply))==terminal and invoke('basis',FG,listing)==current
        record(fmt,encoding,'reviewed-native-publication-and-source-free-recovery')
        stale = list(args); stale[7]=home/'stale.bundle'
        invoke('stale-source',FG,stale,2); assert not stale[7].exists() and invoke('basis',FG,listing)==current
        record(fmt,encoding,'moved-source-cannot-replay-refactoring')
(ROOT/'results.json').write_text(json.dumps(RESULTS,indent=2)+'\n')
