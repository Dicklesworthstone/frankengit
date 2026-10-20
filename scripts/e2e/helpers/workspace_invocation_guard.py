"""Real native retry refusal after a tool completed but bundle publication failed."""
import json
from pathlib import Path
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from workspace_tool_smoke import AUTHOR,TENANT,REPOSITORY,PRINCIPAL,REF,write_object,tree,commit
fg,root=sys.argv[1],Path(sys.argv[2]).resolve()
root.mkdir(parents=True,exist_ok=True)
expected_replay=len(sys.argv)>3 and sys.argv[3]=='baseline'
rows=[]
for fmt in ('sha1','sha256'):
    source,node,parent=(root/f'{fmt}-{name}' for name in ('source','node','private'))
    parent.mkdir(mode=0o700)
    (source/'refs/heads').mkdir(parents=True)
    (source/'HEAD').write_text(f'ref: {REF}\n')
    blob=write_object(source,fmt,'blob',b'before\n')
    tree_id=write_object(source,fmt,'tree',tree([(b'100644',b'edit.txt',blob)]))
    base=write_object(source,fmt,'commit',commit(tree_id,None,0,b'base\n'))
    (source/REF).write_text(base+'\n')
    def invoke(label,args,ok=True):
        result=subprocess.run([fg,*map(str,args)],capture_output=True,timeout=40)
        (root/f'{fmt}-{label}.out').write_bytes(result.stdout)
        (root/f'{fmt}-{label}.err').write_bytes(result.stderr)
        sys.stderr.buffer.write(result.stderr)
        assert (result.returncode==0)==ok,(label,result.returncode,result.stderr)
        return result
    scope=[node,TENANT,REPOSITORY]
    invoke('init',['init',*scope,fmt])
    invoke('import',['import',*scope,PRINCIPAL,'invocation-fixture',source])
    listing=['at',*scope,'latest','refs']
    before=invoke('refs-before',listing).stdout
    counter=root/f'{fmt}-effects'
    destination=parent/'candidate.bundle'
    script=(f"from pathlib import Path; p=Path({str(counter)!r}); p.write_text(p.read_text()+'x' if p.exists() else 'x'); "
            "Path('edit.txt').write_bytes(b'after\\n'); "
            f"Path({str(destination)!r}).mkdir()")
    args=['workspace','run',*scope,REF,parent,'ab'*16,'candidate.bundle','--trusted-local',
          '--read','edit.txt','--write','edit.txt','--author',AUTHOR,'--timestamp','1','--message','candidate\n',
          '--',sys.executable,'-c',script]
    first=invoke('failed-publication',args,False)
    assert counter.read_text()=='x' and destination.is_dir()
    assert not (parent/('workspace-'+'ab'*16)).exists(),'workspace must already have closed'
    destination.rmdir()
    second=invoke('retry',args,False)
    assert counter.read_text()==('xx' if expected_replay else 'x')
    if not expected_replay: assert b'invocation already reserved' in second.stderr and not destination.exists()
    assert invoke('refs-after',listing).stdout==before
    rows.append({'format':fmt,'counter':counter.read_text(),'source_refs_unchanged':True,'duplicate_effect':expected_replay})
    print(json.dumps(rows[-1]),flush=True)
(root/'results.json').write_text(json.dumps(rows,indent=2)+'\n')
