import pathlib
root=pathlib.Path.cwd()
for name, needles, width in [
 ('crates/fgit-admission/src/lib.rs',['fn prepare_publication_from_snapshot','impl CanonicalAdmissionStore','resolve_hidden_ref_policy','fn snapshot_from','struct RefIntentEvaluator'],80),
 ('crates/fgit-node/src/lib.rs',['pub struct NodeConfig','fn snapshot_for','fn materialize_selected_in','let configuration = read_repository','hidden_refs:','record_creation_attempt_async','pub enum NodeRefusal','pub struct AsyncMaterializedBasis'],30),
 ('crates/fgit-cli/src/main.rs',['fn run_init','fn parse_init','init-protected','Command::Init','enum Command'],35),
 ('crates/fgit-authority/src/lib.rs',['repository_configuration','CreationAttempt'],15),
 ('crates/fgit-codec/src/lib.rs',['repository_configuration','CreationAttempt'],12),
 ('crates/fgit-admission/src/evidence.rs',['fn principal_snapshot_id'],18),
]:
 path=root/name
 if not path.exists():continue
 lines=path.read_text().splitlines()
 for i,line in enumerate(lines):
  if any(n in line for n in needles):
   print('SOURCE',name,i+1,'\n'+'\n'.join(f'{j+1}: {lines[j]}' for j in range(i,min(i+width,len(lines)))))
for name in ['fgit-authority','fgit-codec','fgit-node']:
 for path in sorted((root/'crates'/name/'src').rglob('*.rs')):
  if any(word in str(path) for word in ['/tests/']):continue
  for i,line in enumerate(path.read_text().splitlines()):
   if any(n in line for n in ['struct CreationAttemptBody','fn record_creation_attempt','enum CreationAttempt','fn prepare_publication_from_snapshot']):
    print('LOCATE',path.relative_to(root),i+1,line)
print('CLI_FILES', [str(p.relative_to(root)) for p in (root/'crates/fgit-cli/src').glob('*.rs')])
