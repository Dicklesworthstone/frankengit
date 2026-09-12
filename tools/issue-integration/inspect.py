import json,pathlib,shutil,subprocess
root=pathlib.Path.cwd()
for tool in ['br','bv']:
    print('TRACKER_TOOL',tool,shutil.which(tool),flush=True)
if shutil.which('br'):
    subprocess.run(['br','ready','--unassigned','--no-db','--json'],check=True,timeout=30)
for path in ['COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md','docs/NORMATIVE_PROTOCOL_CONTRACTS.md']:
    lines=(root/path).read_text().splitlines()
    for i,line in enumerate(lines):
        if (path.startswith('COMPREHENSIVE') and line.startswith('## 24.')) or ('normative' in path.lower() and line.startswith('#') and any(word in line.lower() for word in ['forge','intent','schema'])):
            end=next((j for j in range(i+1,len(lines)) if lines[j].startswith('## ')),min(len(lines),i+160))
            print('SPEC_SECTION',path,i+1,flush=True)
            print('\n'.join(f'{j+1}: {lines[j]}' for j in range(i,min(end,i+200))),flush=True)
for line in (root/'.beads/issues.jsonl').read_text().splitlines():
    row=json.loads(line)
    if 'FG-045' in row.get('title','') or row.get('id')=='frankengit-asa3':
        print('TRACKER_RECORD',json.dumps(row),flush=True)
for path in ['crates/fgit-node/src/treefs_workspace/pull_request.rs','crates/fgit-node/src/lib.rs','crates/fgit-cli/src/lib.rs','crates/fgit-reference/src/intent.rs','crates/fgit-admission/src/merge/native/storage.rs']:
    lines=(root/path).read_text().splitlines()
    print('SOURCE_INDEX',path,'LINES',len(lines),flush=True)
    keys=['fn ', 'enum ', 'struct ', 'pub mod '] if path.endswith('pull_request.rs') else ['PullRequestProjection','validate_pull_request_async','CliOutcome::','PullRequest(','enum ForgeEventKind','aggregate_label','PullRequestReviewed','pull_request_command','mod pull_request','"pr"']
    for i,line in enumerate(lines):
        if any(word in line for word in keys):
            print(f'{i+1}: {line}',flush=True)
