import json,pathlib,subprocess
root=pathlib.Path.cwd()
checks={
 'crates/fgit-admission/src/lib.rs':['async fn admit_input_async','materialize_commit_async(','fn evaluate_request','fn materialize_commit('],
 'crates/fgit-forge/src/snapshot.rs':['AggregateId::Issue','AGGREGATE_KIND_ISSUE'],
 'crates/fgit-reference/src/trace.rs':['ForgeEventKind::IssueChanged'],
 'crates/fgit-reference/src/transition.rs':['ForgeEventKind::IssueChanged'],
 'crates/fgit-txn/src/lib.rs':['ForgeEventKind::IssueChanged'],
 'crates/fgit-admission/src/merge/native.rs':['validate_merge_async(store','validate_merge_async(','let prepared = prepare_event'],
 'crates/fgit-admission/src/merge/native/storage.rs':['pub(super) async fn read_events','pub async fn load_forge_positions','fn aggregate_label'],
 'crates/fgit-node/src/treefs_workspace.rs':['mod issues','mod native_merge','mod reviews','IssueReadRefusal'],
 'crates/fgit-node/src/lib.rs':['pub use treefs_workspace','mod treefs_workspace'],
}
for name,terms in checks.items():
 lines=(root/name).read_text().splitlines();seen=set()
 for i,line in enumerate(lines):
  if any(term in line for term in terms):
   print('SOURCE',name,'LINE',i+1,flush=True)
   for j in range(max(0,i-6),min(len(lines),i+35)):
    if j not in seen: print(f'{j+1}: {lines[j]}');seen.add(j)
for name in ['crates/fgit-node/src/treefs_workspace/review_tests.rs','crates/fgit-forge/src/snapshot.rs']:
 print('FULL_SOURCE',name,flush=True);print((root/name).read_text(),flush=True)
for line in (root/'.beads/issues.jsonl').read_text().splitlines():
 issue=json.loads(line)
 if 'fg043r' in issue['id'] or 'fg043c' in issue['id']:
  print('OWNING_BEAD',json.dumps({k:issue.get(k) for k in ['id','title','status','assignee','description']}),flush=True)
print('EXHAUSTIVE_MATCH_SITES',flush=True)
subprocess.run(['git','grep','-n','IssueChanged','--','crates'],check=False)
