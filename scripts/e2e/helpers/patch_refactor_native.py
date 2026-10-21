"""Real fg atomic refactoring; independent native object/tree/bundle expectations.
No Git executable, mock node, source script or network service is used.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patch_smoke import loose, oid, bundle_objects
FG, ROOT = str(Path(sys.argv[1]).resolve()), Path(sys.argv[2]).resolve()
ROOT.mkdir(parents=True, exist_ok=True)
SEQUENCE, RESULTS = 0, []
def run(label, args, code=0):
    global SEQUENCE
    SEQUENCE += 1
    out, err = (ROOT / f'{SEQUENCE:03d}-{label}.{suffix}' for suffix in ('out', 'err'))
    with out.open('wb') as stdout, err.open('wb') as stderr:
        result = subprocess.run([FG, *map(str, args)], stdout=stdout, stderr=stderr, timeout=90)
    diagnostic = err.read_bytes()
    if diagnostic: sys.stderr.buffer.write(diagnostic); sys.stderr.buffer.flush()
    assert result.returncode == code, (label, result.returncode, out.read_bytes()[-3000:], diagnostic[-3000:])
    return out.read_bytes()
def record(fmt, scenario, name, **detail):
    row = dict(format=fmt, scenario=scenario, case=name, **detail)
    RESULTS.append(row); print(json.dumps(row), flush=True)
def tree(rows):
    return b''.join(mode+b' '+name+b'\0'+bytes.fromhex(identity) for name,mode,identity in
        sorted(rows, key=lambda row: row[0]+(b'/' if row[1]==b'40000' else b'')))
def quoted(name):
    return '"'+''.join(chr(b) if 33<=b<=126 and b not in (34,92) else '\\'+format(b,'03o') for b in name)+'"'
def relocation(source, target, old, new=None):
    a,b=quoted(b'a/'+source),quoted(b'b/'+target)
    changed=new is not None
    return (f'diff --git {a} {b}\n'+('old mode 100644\nnew mode 100755\n' if changed else '')+
        f'similarity index {50 if changed else 100}%\nrename from {quoted(source)}\nrename to {quoted(target)}\n'+
        f'index {old}..{new or old}'+('' if changed else ' 100644')+'\n'+
        (f'--- {a}\n+++ {b}\n@@ -1 +1 @@\n-before\n+after\n' if changed else '')).encode()
for fmt in ('sha1','sha256'):
    for scenario in ('siblings','prune'):
        home=ROOT/(fmt+'-'+scenario);home.mkdir(mode=0o700)
        source,node=home/'source',home/'node';(source/'refs/heads').mkdir(parents=True)
        (source/'HEAD').write_text('ref: refs/heads/main\n')
        (source/'config').write_text('[core]\nbare=true\nrepositoryformatversion='+('0\n' if fmt=='sha1' else '1\n[extensions]\nobjectformat=sha256\n'))
        blobs={name:loose(source,fmt,'blob',body) for name,body in {
            'old':b'before\n','binary':b'\0exact\xffbinary\r\n','keep':b'untouched\0sibling',
            'inner':b'inner sibling\n','obsolete':b'delete\n'}.items()}
        children=[(b'file.txt',b'100644',blobs['old']),(b'\xff.bin',b'100644',blobs['binary'])]
        if scenario=='siblings':children.append((b'keep.txt',b'100644',blobs['inner']))
        src=loose(source,fmt,'tree',tree(children))
        root=loose(source,fmt,'tree',tree([(b'keep.bin',b'100644',blobs['keep']),
            (b'obsolete.txt',b'100644',blobs['obsolete']),(b'src',b'40000',src)]))
        author='Refactor <test@example.invalid>'
        base=loose(source,fmt,'commit',f'tree {root}\nauthor {author} 1 +0000\ncommitter {author} 1 +0000\n\nbase\n'.encode())
        (source/'refs/heads/main').write_text(base+'\n')
        scope=[node,'b1'*16,'b2'*16];principal='b3'*16
        run('init',['init',*scope,fmt]);run('import',['import',*scope,principal,'fixture',source])
        listing=['pr','list',*scope,'--trusted-local','--object-format',fmt]
        authority=run('basis',listing)
        new=oid(fmt,'blob',b'after\n');readme=oid(fmt,'blob',b'refactored\n');zero='0'*(40 if fmt=='sha1' else 64)
        patch_bytes=relocation(b'src/file.txt',b'lib/tool.txt',blobs['old'],new)+relocation(b'src/\xff.bin',b'lib/data.bin',blobs['binary'])
        patch_bytes+=(f'diff --git a/obsolete.txt b/obsolete.txt\ndeleted file mode 100644\nindex {blobs["obsolete"]}..{zero}\n--- a/obsolete.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-delete\n'+
            f'diff --git a/README.md b/README.md\nnew file mode 100644\nindex {zero}..{readme}\n--- /dev/null\n+++ b/README.md\n@@ -0,0 +1 @@\n+refactored\n').encode()
        patch=home/'refactor.patch';patch.write_bytes(patch_bytes)
        output=home/'refactor.bundle'
        args=['patch','prepare',*scope,'refs/heads/main',patch,output,'--trusted-local','--profile','exact-tree-v1',
            '--workspace-id','b4'*16,'--expected-base',base,'--author',author,'--timestamp','2','--message','refactor\n']
        for profile in ('exact-v1','exact-binary-v1'):
            rejected=list(args);rejected[rejected.index('--profile')+1]=profile
            run('legacy-profile',rejected,2);assert not output.exists() and run('basis',listing)==authority
            record(fmt,scenario,'legacy-profile-refuses-relocation',profile=profile)
        prepared=json.loads(run('prepare',args))
        lib_body=tree([(b'data.bin',b'100644',blobs['binary']),(b'tool.txt',b'100755',new)])
        lib=oid(fmt,'tree',lib_body)
        result_rows=[(b'README.md',b'100644',readme),(b'keep.bin',b'100644',blobs['keep']),(b'lib',b'40000',lib)]
        if scenario=='siblings':
            remaining_body=tree([(b'keep.txt',b'100644',blobs['inner'])]);remaining=oid(fmt,'tree',remaining_body)
            result_rows.append((b'src',b'40000',remaining))
        root_body=tree(result_rows);result_tree=oid(fmt,'tree',root_body)
        body=f'tree {result_tree}\nparent {base}\nauthor {author} 2 +0000\ncommitter {author} 2 +0000\n\nrefactor\n'.encode()
        candidate=oid(fmt,'commit',body)
        assert prepared['profile']=='exact-tree-v1' and prepared['root_tree']==result_tree and prepared['candidate_commit']==candidate
        assert not prepared['published_to_repository'] and prepared['node_closed']
        assert prepared['patch_sha256']==hashlib.sha256(patch_bytes).hexdigest()
        packed=bundle_objects(output.read_bytes(),fmt,base,candidate)
        for identity,wanted in [(candidate,('commit',body)),(result_tree,('tree',root_body)),(lib,('tree',lib_body)),(new,('blob',b'after\n')),(readme,('blob',b'refactored\n'))]:assert packed[identity]==wanted
        if scenario=='siblings':assert packed[remaining]==('tree',remaining_body)
        effects={bytes.fromhex(row['path_hex']):row for row in prepared['paths']}
        assert set(effects)=={b'README.md',b'lib/data.bin',b'lib/tool.txt',b'obsolete.txt',b'src/file.txt',b'src/\xff.bin'}
        for oldpath,oldoid,newpath,newoid,mode in [(b'src/file.txt',blobs['old'],b'lib/tool.txt',new,'100755'),(b'src/\xff.bin',blobs['binary'],b'lib/data.bin',blobs['binary'],'100644')]:
            assert effects[oldpath]['old_blob']==oldoid and effects[oldpath]['new_blob'] is None
            assert effects[newpath]['old_blob'] is None and effects[newpath]['new_blob']==newoid and effects[newpath]['new_mode']==mode
        assert run('basis',listing)==authority
        record(fmt,scenario,'atomic-refactoring-matches-independent-tree',effects=len(effects))
        again=list(args);again[7]=home/'again.bundle';again+=['--max-files','4','--max-input-bytes',str(len(patch_bytes))]
        assert json.loads(run('reopen',again))==prepared and again[7].read_bytes()==output.read_bytes()
        record(fmt,scenario,'exact-budget-and-reopen-determinism')
        occupied=patch_bytes.replace(b'lib/tool.txt',b'keep.bin')
        wrong_old=patch_bytes.replace(blobs['old'].encode(),blobs['keep'].encode())
        late_bad=patch_bytes.replace(b'+refactored\n',b'+wrong\n')
        chain=relocation(b'src/file.txt',b'lib/tool.txt',blobs['old'])+relocation(b'lib/tool.txt',b'next.txt',blobs['old'])
        for name,badbytes in [('occupied-destination',occupied),('wrong-source-identity',wrong_old),('late-file-mismatch',late_bad),('rename-chain',chain)]:
            badpatch=home/(name+'.patch');badpatch.write_bytes(badbytes)
            bad=list(args);bad[6]=badpatch;bad[7]=home/(name+'.bundle')
            run(name,bad,2);assert not bad[7].exists() and run('basis',listing)==authority
            record(fmt,scenario,name+'-refuses-without-partial-state')
        for flag,limit in [('--max-files','3'),('--max-input-bytes',str(len(patch_bytes)-1))]:
            bad=list(args);bad[7]=home/(flag[2:]+'.bundle');bad+=[flag,limit]
            run('budget',bad,2);assert not bad[7].exists() and run('basis',listing)==authority
            record(fmt,scenario,'narrow-budget-refuses',limit=flag)
        wrong=list(args);wrong[7]=home/'wrong-profile.bundle';wrong[wrong.index('--profile')+1]='exact-tree-v2'
        run('unknown-profile',wrong,2);assert not wrong[7].exists()
        record(fmt,scenario,'unknown-profile-refuses')
        apply=['patch','apply',*scope,'refs/heads/main',output,'--trusted-local','--principal',principal,'--idempotency-key','refactor-apply',
            '--expected-base',base,'--expected-commit',candidate]
        rejected=list(apply);rejected[-1]=blobs['keep'];run('wrong-review',rejected,2)
        assert run('basis',listing)==authority
        terminal=json.loads(run('apply',apply));assert terminal['outcome']=='committed' and terminal['candidate_commit']==candidate
        after=run('basis',listing);assert after!=authority
        assert json.loads(run('original-outcome',apply))==terminal and run('basis',listing)==after
        record(fmt,scenario,'reviewed-atomic-publication-and-original-outcome-recovery')
        stale=list(args);stale[7]=home/'stale.bundle';run('stale-source',stale,2)
        assert not stale[7].exists() and run('basis',listing)==after
        record(fmt,scenario,'moved-source-never-replays-refactoring')
(ROOT/'results.json').write_text(json.dumps(RESULTS,indent=2)+'\n')
