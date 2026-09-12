import pathlib, re
root=pathlib.Path.cwd()
needles=['pub struct Publication','pub struct ResultingRoots','pub enum Intent','pub enum Lowered','pub struct ProtectionRule','pub fn read_repository_incarnation_configuration','pub async fn read_repository_incarnation_configuration','struct NormalizedRepository','pub struct RepositoryConfiguration','configuration_root:', 'fn evaluate_lowered','fn admit_sealed','fn prepare_native_merge']
for dirname in ['fgit-authority','fgit-txn','fgit-reference','fgit-admission']:
    for path in sorted((root/'crates'/dirname/'src').rglob('*.rs')):
        if 'tests' in str(path):continue
        lines=path.read_text().splitlines()
        for i,line in enumerate(lines):
            match=next((needle for needle in needles if needle in line),None)
            if not match:continue
            print('LOCATION',path.relative_to(root),i+1,line)
            if match != 'configuration_root:':
                print('\n'.join(f'{j+1}: {lines[j]}' for j in range(i+1,min(i+65,len(lines)))))
for rel in ['crates/fgit-reference/src/state.rs','crates/fgit-authority/src/capability_revocation.rs']:
    path=root/rel
    if not path.exists():continue
    lines=path.read_text().splitlines()
    for i,line in enumerate(lines):
        if ('pub ' in line or 'pub(' in line) and any(word in line.lower() for word in ['policy','activat','publish','change','update','config','revok']):
            print('API',rel,i+1,line)
            print('\n'.join(f'{j+1}: {lines[j]}' for j in range(i+1,min(i+28,len(lines)))))
