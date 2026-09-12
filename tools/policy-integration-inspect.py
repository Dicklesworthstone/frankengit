import json, pathlib, re, shutil, subprocess
root = pathlib.Path.cwd()
print('TRACKER_TOOLS', {name: shutil.which(name) for name in ['br','bv']})
if shutil.which('br'):
    subprocess.run(['br','ready','--unassigned','--no-db','--json'], check=True, timeout=30)
else:
    print('TRACKER_READ_ONLY: br unavailable; no readiness, claim, transition or closure inferred')
for i,line in enumerate((root/'.beads/issues.jsonl').read_text().splitlines(),1):
    item=json.loads(line)
    if item.get('id') in ['frankengit-fg043r','frankengit-asa3'] or ('policy' in item.get('title','').lower() and item.get('status') != 'closed'):
        print('BEAD_RECORD', i, json.dumps(item))
for rel, needles in {
    'COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md':['## 32.','### 32.','## 25.','## 18.'],
    'docs/NORMATIVE_PROTOCOL_CONTRACTS.md':['policy_epoch','configuration_root','policy_root','PolicySnapshot','promotion','protection'],
    'crates/fgit-node/src/lib.rs':['pub struct OneNodeConfig','pub struct NodeConfig','struct NodeAdmission','struct DurableAdmission','impl AdmissionEvidence','fn commit_evidence','ProtectionRule','policy_root','configuration_root','impl AsyncAdmissionProjection'],
    'crates/fgit-admission/src/lib.rs':['pub struct ProtectionRule','protection','policy_epoch','fn evaluate_lowered'],
    'crates/fgit-codec/src/lib.rs':['struct RepositoryIncarnation','configuration_root','struct RepositoryConfiguration'],
    'crates/fgit-chronicle/src/lib.rs':['configuration_root','policy_epoch','struct ResultingRoots'],
}.items():
    path=root/rel
    if not path.exists():continue
    lines=path.read_text().splitlines()
    for i,line in enumerate(lines):
        if any(needle in line for needle in needles):
            print('MATCH',rel,i+1,line)
            if any(needle in line for needle in ['pub struct','struct NodeAdmission','struct DurableAdmission','fn commit_evidence','impl AdmissionEvidence','impl AsyncAdmissionProjection','## 32.','### 32.']):
                print('\n'.join(f'{j+1}: {lines[j]}' for j in range(i+1,min(i+45,len(lines)))))
for path in sorted((root/'crates').glob('*/src/**/*.rs')):
    if 'fgit-node' not in str(path) and 'fgit-codec' not in str(path):continue
    text=path.read_text()
    if any(needle in text for needle in ['pub struct RepositoryIncarnation','pub struct ProtectionRule','struct IncarnationConfiguration']):
        print('DEFINITION_FILE',path.relative_to(root))
