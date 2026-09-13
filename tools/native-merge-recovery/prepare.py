import os, pathlib, subprocess, tempfile
ROOT=pathlib.Path.cwd()
BASE='d438760435c80afad82e0e5e768599939edc9204'
SOURCE='crates/fgit-node/src/treefs_workspace/native_merge.rs'
TESTS='crates/fgit-node/src/treefs_workspace/mandatory_protection_tests.rs'
def git(*args,cwd=ROOT):
    return subprocess.check_output(['git','-c','core.hooksPath=/dev/null',*args],cwd=cwd,text=True).strip()
with tempfile.TemporaryDirectory(prefix='fg-native-merge-recovery-') as td:
    work=pathlib.Path(td)/'source'
    git('worktree','add','--detach',str(work),BASE)
    assert git('rev-parse',f'{BASE}:{SOURCE}')=='b976d9482be764d2df49abbe7c994a4980b722b5'
    assert git('rev-parse',f'{BASE}:{TESTS}')=='7e4dc64e610b148d4e26548850d6a712b42da755'
    path=work/SOURCE
    text=path.read_text()
    before,marker,tail=text.partition('    pub async fn admit_native_merge_durable_in(')
    assert marker and tail.count('pub async fn admit_native_merge_durable_in(')==0
    old='''        self.push_quota.evaluate(&authenticated.principal_id())?;
        self.receive_publication_admitted()?;
'''
    assert tail.count(old)==1
    tail=tail.replace(old,'',1)
    old='''        let inner = self
            .durable_admission_projection(&context)'''
    new='''        // A retry is an outcome read, not a new mutation admission. Recover
        // the same native seal used by bundle publication before service,
        // quota, policy, or candidate-object checks can hide its decision.
        // Authentication and semantic identity still precede this lookup.
        let map_admission = |error| NodeReceiveTransportRefusal::Admission(Box::new(error));
        let attempt = intent.seal_attempt(&context).map_err(map_admission)?;
        let tx_id = attempt.derive().map_err(|_| map_admission(
            AdmissionError::AsyncProjectionUnavailable(RefusalCode::CanonicalFramingInvalid),
        ))?.0;
        if let fgit_authority::OutcomeLookup::Decided(terminal) =
            fgit_authority::resolve_outcome_async(
                &self.authority, request.authority(), &self.head_key,
                self.tenant_id, self.repository_id, tx_id,
            ).await.map_err(|error| map_admission(error.into()))?
        {
            // Reconfirm the exact principal/key/request binding. This is not
            // permission to reuse a different request under the same key.
            fgit_authority::seal_request_async(&self.authority, request.authority(), &attempt)
                .await.map_err(|error| map_admission(error.into()))?;
            return Ok(terminal);
        }
        self.push_quota.evaluate(&authenticated.principal_id())?;
        self.receive_publication_admitted()?;
        let inner = self
            .durable_admission_projection(&context)'''
    assert tail.count(old)==1
    path.write_text(before+marker+tail.replace(old,new,1))
    tests=work/TESTS
    tests.write_bytes(tests.read_bytes()+b'\n'+(ROOT/'tools/native-merge-recovery/tests.rs').read_bytes())
    assert set(git('diff','--name-only',cwd=work).splitlines())=={SOURCE,TESTS}
    git('diff','--check',cwd=work)
    git('config','user.name','Jeff Emanuel',cwd=work)
    git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    git('add','--',SOURCE,TESTS,cwd=work)
    git('commit','-m','fix(node): recover direct native merge decisions before mutation gates (FG-043r)','-m','Use the exact native seal shared with bundle publication for authenticated terminal recovery before service/quota/policy/object checks. Preserve every undecided-request admission gate and re-confirm key/principal/request binding. Add both-hash file-backed regressions for committed and refused recovery after policy changes and reopen, exhausted quota, changed identity and new-request refusal. Native test execution is recorded separately.',cwd=work)
    result=git('rev-parse','HEAD',cwd=work)
    branch='tooling/native-merge-recovery-result-'+os.environ['GITHUB_SHA'][:12]
    git('push','origin',result+':refs/heads/'+branch,cwd=work)
    with open(os.environ['GITHUB_OUTPUT'],'a') as output: output.write('source='+result+'\n')
    print('PRODUCT_RESULT',result,branch,flush=True)
