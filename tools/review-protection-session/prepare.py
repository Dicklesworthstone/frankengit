import os, pathlib, subprocess, tempfile
ROOT=pathlib.Path.cwd()
BASE='8262f91d25dbdd054a8e117afb3560286deeca17'
PATH='crates/fgit-forge/src/preparation/rebase/tests/resolutions.rs'
def git(*args,cwd=ROOT):
    return subprocess.check_output(['git','-c','core.hooksPath=/dev/null',*args],cwd=cwd,text=True).strip()
with tempfile.TemporaryDirectory(prefix='fg-rebase-fixture-') as td:
    work=pathlib.Path(td)/'source'
    git('worktree','add','--detach',str(work),BASE)
    assert git('rev-parse',BASE+':'+PATH)=='49e1bb4f54dab9f27e653770188d63038eea1e8a'
    path=work/PATH;text=path.read_text()
    old='''    let choices = [
        recipe(originals[0], ResolutionChoice::Theirs),
        recipe(originals[1], ResolutionChoice::Theirs),
    ];'''
    new='''    // Keep a distinct resolved first-line value, so the second original
    // really conflicts too. Choosing Theirs here reproduces the second
    // commit's exact base and correctly makes its later recipe invalid.
    let choices = [
        recipe(originals[0], ResolutionChoice::File {
            mode: 0o100644,
            bytes: b"R\\nb\\nc\\nd\\ne\\nf\\n".to_vec(),
        }),
        recipe(originals[1], ResolutionChoice::Theirs),
    ];'''
    assert text.count(old)==2
    text=text.replace(old,new)
    old='''    let RebasePreparation::Clean(plan) = resolved(&source, inputs, &choices).preparation else {
        panic!();
    };
    let limits = PreparationLimits {'''
    new='''    let baseline = resolved(&source, inputs, &choices);
    assert_eq!(baseline.resolutions.iter().map(|step| step.original).collect::<Vec<_>>(), originals);
    let RebasePreparation::Clean(plan) = baseline.preparation else {
        panic!();
    };
    assert_eq!(plan.steps.len(), 2);
    assert_eq!(final_file(&source, &plan), Some((0o100644, b"Y\\nb\\nc\\nd\\ne\\nf\\n".to_vec())));
    let limits = PreparationLimits {'''
    assert text.count(old)==1;text=text.replace(old,new)
    old='''    resolved(&source, inputs, &choices);
    let polls = source.polls.get();'''
    new='''    let baseline = resolved(&source, inputs, &choices);
    assert_eq!(baseline.resolutions.iter().map(|step| step.original).collect::<Vec<_>>(), originals);
    assert!(matches!(baseline.preparation, RebasePreparation::Clean(_)));
    let polls = source.polls.get();'''
    assert text.count(old)==1;text=text.replace(old,new)
    text+='''
#[test]
fn selecting_original_first_tree_requires_no_resolution_of_clean_second_replay() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (source, inputs, originals) = conflicted(format, true);
        let first = recipe(originals[0], ResolutionChoice::Theirs);
        let result = resolved(&source, inputs, std::slice::from_ref(&first));
        assert_eq!(result.resolutions.len(), 1);
        let RebasePreparation::Clean(plan) = result.preparation else { panic!(); };
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(final_file(&source, &plan), Some((0o100644, b"Y\\nb\\nc\\nd\\ne\\nf\\n".to_vec())));
        assert!(matches!(prepare_resolved_rebase(&source, format, inputs, &committer(),
            PreparationLimits::default(), &[first, recipe(originals[1], ResolutionChoice::Theirs)]),
            Err(RebaseError::Resolution { original, error: ResolutionError::NoConflicts }) if original == originals[1]));
    }
}
'''
    path.write_text(text)
    subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true',PATH],cwd=work,check=True,timeout=180)
    assert git('diff','--name-only',cwd=work)==PATH
    git('diff','--check',cwd=work)
    git('config','user.name','Jeff Emanuel',cwd=work)
    git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    git('add','--',PATH,cwd=work)
    git('commit','-m','test(rebase): exercise genuine two-step conflicts in budget and cancellation cases','-m','Native verification at 059d8fe exposed two saved fixtures whose first Theirs choice removed the second conflict, causing NoConflicts before they could test resource behavior. Use a distinct exact first result and assert both resolution receipts plus final tree. Retain all intake/output/cancellation refusal assertions and add a both-hash permitted-clean/redundant-recipe-refused twin. Production rebase logic is unchanged.',cwd=work)
    source=git('rev-parse','HEAD',cwd=work)
    branch='tooling/review-protection-fix-'+os.environ['GITHUB_SHA'][:12]
    git('push','origin',source+':refs/heads/'+branch,cwd=work)
    print('PRODUCT_COMMIT fixture',source,branch,flush=True)
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:out.write('source='+source+'\n')
    assert not git('status','--porcelain',cwd=work)
