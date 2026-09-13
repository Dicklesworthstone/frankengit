import json, os, pathlib, subprocess, tempfile
ROOT=pathlib.Path.cwd()
BASE='5a84924788fc00c014e77080469342ec0a595e00'
ORIGINAL='80e4a75fa582df39a74792adb29ef8df45726b16'
PRODUCT='705da940f063a50b228e37265977d53cb5700ee3'
CLI='crates/fgit-cli/src/bundle.rs'
LIB='crates/fgit-node/src/lib.rs'
CORE={'crates/fgit-pack/src/full_bundle.rs','crates/fgit-pack/tests/incremental_bundle.rs'}
def git(*args,cwd=ROOT):
    return subprocess.check_output(['git','-c','core.hooksPath=/dev/null',*args],cwd=cwd,text=True).strip()
def oid(ref,path):
    p=subprocess.run(['git','rev-parse','--verify',ref+':'+path],cwd=ROOT,text=True,capture_output=True)
    return p.stdout.strip() if p.returncode==0 else None
paths=set(git('diff','--name-only',ORIGINAL,PRODUCT).splitlines())
assert len(paths)==16
for path in CORE:assert oid(BASE,path)==oid(PRODUCT,path)
assert oid(BASE,CLI)=='f25a7a15fd4142adb5be69d697ad0721d9fae314'
for path in paths-CORE-{CLI}:assert oid(BASE,path)==oid(ORIGINAL,path),(path,oid(BASE,path),oid(ORIGINAL,path))
with tempfile.TemporaryDirectory(prefix='fg-incremental-final-') as td:
    work=pathlib.Path(td)/'source';git('worktree','add','--detach',str(work),BASE)
    for name in paths-CORE-{CLI}:
        path=work/name;path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(subprocess.check_output(['git','show',PRODUCT+':'+name],cwd=ROOT))
        if name.endswith('.sh'):path.chmod(0o755)
    def replace(name,old,new):
        path=work/name;text=path.read_text();assert text.count(old)==1,(name,old[:120],text.count(old));path.write_text(text.replace(old,new))
    replace(CLI,'mod fetch;','mod fetch;\nmod incremental;')
    replace(CLI,'pub(super) fn run(args: &[String]) -> Result<u8, String> {','pub(super) fn run(args: &[String]) -> Result<u8, String> {\n    if args.first().is_some_and(|arg| matches!(arg.as_str(), "sync-export" | "sync-import")) {\n        return incremental::run(args);\n    }')
    replace(CLI,'"{USAGE}\\n\\n{}", fetch::USAGE','"{USAGE}\\n\\n{}\\n\\n{}", fetch::USAGE, incremental::USAGE')
    NODE='crates/fgit-node/src/treefs_workspace/full_bundle.rs'
    replace(NODE,'        bundle_limits.max_references = bundle_limits.max_references.min(limits.max_commands);','''        // Advertisements and mutation commands have distinct bounds. Mapped
        // full fetch can select one command out of many advertised refs. The
        // incremental profile names every direct ref, plus at most one HEAD.
        if expectations.is_some() {
            bundle_limits.max_references = bundle_limits.max_references
                .min(limits.max_commands.saturating_add(1));
        }''')
    replace(NODE,'if mappings.is_some() && commands.iter().any(|command|','if (mappings.is_some() || expectations.is_some()) && commands.iter().any(|command|')
    # The existing selected-pack source intentionally does not fill closure
    # metadata. Bundles need those exact edges to verify their transmitted graph.
    # Factor byte parsing without a second fabric read or changing daemon plans.
    replace(LIB,'''    fn object_references(&self, id: &GitOid) -> Result<Vec<GitOid>, PackWriteError> {
        let (object_type, body) = self.read_object(id)?;
        self.session_checkpoint()?;''','''    fn object_references(&self, id: &GitOid) -> Result<Vec<GitOid>, PackWriteError> {
        let (object_type, body) = self.read_object(id)?;
        self.object_references_from_body(object_type, &body)
    }

    fn object_references_from_body(
        &self, object_type: ObjectType, body: &[u8],
    ) -> Result<Vec<GitOid>, PackWriteError> {
        self.session_checkpoint()?;''')
    adapter='''
// Bundle writers verify closure independently from the selected-ID traversal.
// Keep native dependency metadata on the plan, deriving it from the exact body
// that is already being loaded. Do not reread object fabric or widen selection.
struct BundleObjectSource<'source, 'context>(&'source VerifiedFabricPackSource<'context>);
impl fgit_pack::CanonicalObjectSource for BundleObjectSource<'_, '_> {
    fn load(&self, id: &fgit_types::GitOid) -> Result<fgit_pack::CanonicalPackObject, fgit_pack::PackWriteError> {
        let (kind, body) = self.0.read_object(id)?;
        let references = self.0.object_references_from_body(kind, &body)?;
        if !self.0.database_read_is_live() {
            return Err(fgit_pack::PackError::DeadlineExceeded.into());
        }
        Ok(fgit_pack::CanonicalPackObject::new(*id, kind, body, references, 0, 0))
    }
}
'''
    path=work/NODE;path.write_text(path.read_text()+adapter)
    replace(NODE,'.plan_selected(&source, &ids, &mut live)','.plan_selected(&BundleObjectSource(&source), &ids, &mut live)')
    replace('crates/fgit-node/src/treefs_workspace/full_bundle/incremental.rs','.plan_selected(&source, &ids, &mut live)','.plan_selected(&BundleObjectSource(&source), &ids, &mut live)')
    tests=work/'crates/fgit-node/src/treefs_workspace/full_bundle/incremental_tests.rs'
    tests.write_bytes(tests.read_bytes()+(ROOT/'tools/incremental-bundle-session/header_tests.rs').read_bytes())
    script=work/'scripts/verify_incremental_bundle.sh'
    script.write_text('''#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
cargo test --locked -p fgit-pack --test incremental_bundle --test full_bundle
cargo check --locked -p fgit-cli --all-targets
cargo test --locked -p fgit-node --lib treefs_workspace::full_bundle -- --nocapture
cargo test --locked -p fgit-cli --bin fg bundle:: -- --nocapture
cargo test --locked -p fgit-cli --test native_incremental_bundle_smoke --test native_full_bundle_smoke --test native_bundle_fetch_smoke -- --nocapture
''')
    script.chmod(0o755)
    subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true',str(tests)],cwd=work,check=True,timeout=180)
    changed=set(git('diff','--name-only',cwd=work).splitlines())|set(git('ls-files','--others','--exclude-standard',cwd=work).splitlines())
    assert changed==(paths-CORE)|{LIB},changed
    git('diff','--check',cwd=work)
    git('config','user.name','Jeff Emanuel',cwd=work)
    git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    results={'core':BASE}
    for label,group,title in [
      ('node',sorted(p for p in changed if p.startswith('crates/fgit-node/')),'feat(node): synchronize incremental bundles through prerequisite-scoped admission'),
      ('cli',sorted(p for p in changed if not p.startswith('crates/fgit-node/')),'feat(cli): expose incremental bundle synchronization with explicit old-tip leases')]:
        before=git('rev-parse','HEAD',cwd=work)
        git('add','--',*group,cwd=work)
        git('commit','-m',title,'-m','Extend the existing native bundle parser, original-input accounting and quarantine validation; reuse exact-basis atomic admission and mandatory review protection. Preserve concurrent mapped full-bundle fetch and request cancellation APIs. Fix the real full-export defect by retaining native edge metadata from already loaded object bytes without a second fabric read or relaxing reachability validation. Distinguish advertisements from selected commands and optional HEAD. Native tests run separately without write credentials; no full gate or bead closure is asserted by this commit.',cwd=work)
        sha=git('rev-parse','HEAD',cwd=work);assert set(git('diff','--name-only',before,sha,cwd=work).splitlines())==set(group)
        branch='tooling/incremental-bundle-'+label+'-'+os.environ['GITHUB_SHA'][:12]
        git('push','origin',sha+':refs/heads/'+branch,cwd=work);results[label]=sha
        print('PRODUCT_COMMIT',label,sha,branch,flush=True)
    assert not git('status','--porcelain',cwd=work)
    print('PRODUCT_FILES',json.dumps({p:git('rev-parse','HEAD:'+p,cwd=work) for p in sorted(changed)}),flush=True)
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:
        for label,sha in results.items():out.write(label+'='+sha+'\n')
        out.write('source='+results['cli']+'\n')
