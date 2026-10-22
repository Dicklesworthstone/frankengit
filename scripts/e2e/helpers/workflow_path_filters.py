"""Actual native PR path selection and check recovery, no mock server or Git engine."""
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from workspace_tool_smoke import TENANT, REPOSITORY, PRINCIPAL, write_object, tree, commit
FG, ROOT = str(Path(sys.argv[1]).resolve()), Path(sys.argv[2]).resolve()
ROOT.mkdir(parents=True, exist_ok=True)
SEQUENCE, RESULTS = 0, []
def invoke(label, args, code=0):
    global SEQUENCE
    SEQUENCE += 1
    out, err = (ROOT / f'{SEQUENCE:03d}-{label}.{s}' for s in ('out', 'err'))
    with out.open('wb') as stdout, err.open('wb') as stderr:
        result = subprocess.run([FG, *map(str,args)],stdout=stdout,stderr=stderr,timeout=90)
    diagnostic=err.read_bytes()
    if diagnostic:sys.stderr.buffer.write(diagnostic);sys.stderr.buffer.flush()
    assert result.returncode==code,(label,result.returncode,out.read_bytes()[-3000:],diagnostic[-3000:])
    return out.read_bytes()
def record(fmt,name,**values):
    row=dict(format=fmt,case=name,**values);RESULTS.append(row);print(json.dumps(row),flush=True)
def rows(data):return [json.loads(l)for l in data.splitlines()if l]
def path_digest(paths):
    body=b'frankengit/workflow-changed-paths/v1\0'
    for path in sorted(paths):body+=len(path).to_bytes(8,'big')+path
    return hashlib.sha256(body).hexdigest()
class Fixture:
    def __init__(self,fmt):
        self.fmt=fmt;self.home=ROOT/fmt;self.home.mkdir()
        self.source,self.node,self.runs,self.effects=(self.home/n for n in ('source','node','runs','effects'))
        self.runs.mkdir(mode=0o700);(self.source/'refs/heads').mkdir(parents=True)
        (self.source/'HEAD').write_text('ref: refs/heads/main\n')
        (self.source/'config').write_text('[core]\nbare=true\nrepositoryformatversion='+('0\n'if fmt=='sha1'else'1\n[extensions]\nobjectformat=sha256\n'))
        filters={
          'code':"    branches:\n      - main\n    paths:\n      - 'src/**'\n      - '!src/private/**'\n      - 'src/private/public.rs'",
          'docs':"    paths:\n      - 'docs/**'",
          'non_docs':"    paths-ignore:\n      - 'docs/**'",
          'wrong_branch':"    branches:\n      - never\n    paths:\n      - '**'",
          'raw':"    paths:\n      - 'raw/**'",
        }
        self.files={b'src/unit.rs':(b'100644',b'original\n'),b'docs/manual.md':(b'100644',b'old docs\n'),b'asset.bin':(b'100644',b'\0'+b'x'*(2*1024*1024))}
        for name,filter in filters.items():
            workflow=f"name: {name}\non:\n  pull_request:\n{filter}\njobs:\n  {name}:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf '{name}\\n' >> {shlex.quote(str(self.effects))}\n"
            self.files[f'ci/{name}.yml'.encode()]=(b'100644',workflow.encode())
        self.base=self.new_commit(self.files,None,1,'base')
        target=dict(self.files);target[b'docs/target-only.md']=(b'100644',b'target only\n')
        self.target=self.new_commit(target,self.base,2,'target')
        variants={}
        changed=dict(self.files);changed[b'src/unit.rs']=(b'100644',b'changed\n');variants['topic']=changed
        docs=dict(self.files);docs[b'docs/manual.md']=(b'100644',b'new docs\n');variants['docs-only']=docs
        variants['empty']=dict(self.files)
        deleted=dict(self.files);del deleted[b'src/unit.rs'];variants['deleted']=deleted
        mode=dict(self.files);mode[b'src/unit.rs']=(b'100755',b'original\n');variants['mode']=mode
        private=dict(self.files);private[b'src/private/a.rs']=(b'100644',b'private\n');variants['private']=private
        public=dict(self.files);public[b'src/private/public.rs']=(b'100644',b'public\n');variants['public']=public
        raw=dict(self.files);raw[b'raw/\xff.bin']=(b'100644',b'\0binary\xff');variants['raw']=raw
        binary=dict(self.files);binary[b'asset.bin']=(b'100644',b'\0'+b'y'*(2*1024*1024));variants['binary']=binary
        self.tips={name:self.new_commit(files,self.base,i+3,name)for i,(name,files)in enumerate(variants.items())}
        self.tips['disconnected']=self.new_commit(changed,None,30,'disconnected')
        self.tips['main']=self.target
        for name,tip in self.tips.items():(self.source/'refs/heads'/name).write_text(tip+'\n')
        self.scope=[self.node,TENANT,REPOSITORY]
        invoke('init',['init',*self.scope,fmt]);invoke('import',['import',*self.scope,PRINCIPAL,'path-fixture',self.source])
        self.listing=['pr','list',*self.scope,'--trusted-local','--object-format',fmt]
    def new_commit(self,files,parent,number,label):
        def directory(prefix):
            names={p[len(prefix):].split(b'/',1)[0]for p in files if p.startswith(prefix)};entries=[]
            for name in names:
                full=prefix+name
                if full in files:
                    mode,body=files[full];oid=write_object(self.source,self.fmt,'blob',body)
                else:mode=b'40000';oid=directory(full+b'/')
                entries.append((mode,name,oid))
            entries.sort(key=lambda e:e[1]+(b'/'if e[0]==b'40000'else b'\0'))
            return write_object(self.source,self.fmt,'tree',tree(entries))
        return write_object(self.source,self.fmt,'commit',commit(directory(b''),parent,number,(label+'\n').encode()))
    def count(self):return self.effects.read_text().splitlines()if self.effects.exists()else[]
    def pr(self,branch,number):
        return invoke('open',['pr','open',*self.scope,str(number),'--trusted-local','--principal',PRINCIPAL,'--idempotency-key',f'open-{number}','--expected-version','0','--source-ref','refs/heads/'+branch,'--target-ref','refs/heads/main','--expected-source',self.tips[branch],'--expected-target',self.target,'--title','Path selection','--body','Native complete comparison','--object-format',self.fmt])
    def watch(self,branch,number,incarnation=None,code=0):
        args=['workflow','watch',*self.scope,'refs/heads/'+branch,'--trusted-local','--workflow','ci','--input','ci','--run-parent',self.runs,'--pull-request',str(number),'--object-format',self.fmt]
        if incarnation:args+=['--publish-checks','--principal-id',PRINCIPAL,'--expected-incarnation',incarnation]
        output=rows(invoke('watch',args,code))
        if code:return output
        assert output[-1]['node_closed'];return next(r['poll']for r in output if r['type']=='workflow_watch_poll'),output
for fmt in ('sha1','sha256'):
    f=Fixture(fmt)
    cases=[('topic',['code','non_docs'],[b'src/unit.rs']),('docs-only',['docs'],[b'docs/manual.md']),('empty',[],[]),('deleted',['code','non_docs'],[b'src/unit.rs']),('mode',['code','non_docs'],[b'src/unit.rs']),('private',['non_docs'],[b'src/private/a.rs']),('public',['code','non_docs'],[b'src/private/public.rs']),('raw',['non_docs','raw'],[b'raw/\xff.bin']),('binary',['non_docs'],[b'asset.bin'])]
    for number,(branch,wanted,paths)in enumerate(cases,1):
        f.pr(branch,number);before=f.count();authority=invoke('basis',f.listing)
        poll,_=f.watch(branch,number);d=poll['dispatch'];proof=d['plan']['changed_paths']
        assert [r['workflow_path_hex'] for r in d['runs']]==[f'ci/{name}.yml'.encode().hex()for name in wanted]
        assert d['matched_count']==d['executed_count']==len(wanted) and f.count()==before+wanted
        assert proof['requested_before']==f.target and proof['compared_before']==f.base and proof['after']==f.tips[branch]
        assert proof['count']==len(paths) and proof['sha256']==path_digest(paths) and proof['complete']
        assert invoke('basis',f.listing)==authority
        record(fmt,branch+'-selects-exact-merge-base-paths',selected=wanted)
        again,_=f.watch(branch,number);assert again['state']=='previously_settled'and f.count()==before+wanted
        record(fmt,branch+'-restart-does-not-repeat-scripts')
        incarnation=poll['event']['repository_incarnation']
        again,output=f.watch(branch,number,incarnation);assert again['state']=='previously_settled'and f.count()==before+wanted
        checks=json.loads(invoke('checks',['pr','checks',*f.scope,str(number),'--trusted-local','--object-format',fmt]))['checks']
        assert sorted(c['job']for c in checks)==sorted(wanted) and all(c['conclusion']=='success'for c in checks)
        if not wanted:assert not any(r['type']=='workflow_check_set_decision'for r in output)
        record(fmt,branch+'-only-selected-original-checks-published')
    f.pr('disconnected',100);before=f.count();authority=invoke('basis',f.listing)
    f.watch('disconnected',100,code=2);assert f.count()==before and invoke('basis',f.listing)==authority
    record(fmt,'missing-merge-base-refuses-without-execution-or-false-empty-result')
(ROOT/'results.json').write_text(json.dumps(RESULTS,indent=2)+'\n')
