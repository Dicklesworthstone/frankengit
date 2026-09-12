import json,pathlib,re,shutil,subprocess
root=pathlib.Path.cwd()
for name,args in [('bv',['scripts/bv_compat.sh','--robot-triage']),('br',['br','ready','--unassigned','--no-db','--json'])]:
    if shutil.which(name):
        result=subprocess.run(args,text=True,capture_output=True,timeout=45)
        print('TRACKER',name,result.returncode,result.stdout,result.stderr,flush=True)
    else: print('TRACKER_UNAVAILABLE',name,flush=True)
for raw in (root/'.beads/issues.jsonl').read_text().splitlines():
    row=json.loads(raw)
    if re.search(r'shallow|FG-018|FG-082|FG-083|FG-084',row.get('title','')+' '+row.get('description',''),re.I):
        print('BEAD',json.dumps(row),flush=True)
for name,sections in [('COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md',['## 18.']),('docs/NORMATIVE_PROTOCOL_CONTRACTS.md',[])]:
    lines=(root/name).read_text().splitlines()
    if sections:
        for i,line in enumerate(lines):
            if any(line.startswith(s) for s in sections):
                end=next((j for j in range(i+1,len(lines)) if lines[j].startswith('## ')),len(lines))
                print('SPEC',name,'\n'+'\n'.join(f'{j+1}: {lines[j]}' for j in range(i,end)),flush=True)
    else:
        for i,line in enumerate(lines):
            if re.search(r'shallow|disclosure|fetch',line,re.I): print('NORM',name,i+1,line,flush=True)
for name in ['crates/fgit-node/src/upload_visibility.rs','crates/fgit-node/src/upload_visibility/partial_clone.rs','crates/fgit-node/src/upload_visibility/shallow.rs','crates/fgit-git-object/src/lib.rs','crates/fgit-wire/src/lib.rs','crates/fgit-node/src/lib.rs']:
    lines=(root/name).read_text().splitlines()
    terms=['struct FilterObject','fn project_visible_graph','fn history(', 'pub fn parse_commit','struct Commit','pub fn committer','deepen-since','deepen-not','GIT_DAEMON_CAPABILITIES','fn parse_timestamp']
    print('SYMBOL_INDEX',name,[(i+1,line) for i,line in enumerate(lines) if any(t in line for t in terms)],flush=True)
    if name.endswith('/shallow.rs'):
        print('SHALLOW_FULL','\n'.join(f'{i+1}: {line}' for i,line in enumerate(lines)),flush=True)
    if name.endswith('upload_visibility.rs'):
        print('VISIBILITY_FULL','\n'.join(f'{i+1}: {line}' for i,line in enumerate(lines)),flush=True)
