import json, os, pathlib, shutil, subprocess, tempfile
ROOT=pathlib.Path.cwd(); BASE='3483c798f4885728005d2e45b1e967c6fc66fc17'
def git(*args,cwd=ROOT): return subprocess.check_output(['git',*args],cwd=cwd,text=True).strip()
with tempfile.TemporaryDirectory(prefix='fg-fetch-stream-') as td:
    work=pathlib.Path(td)/'source';git('worktree','add','--detach',str(work),BASE)
    print('TRACKER_TOOLS', {name:shutil.which(name) for name in ['br','bv']},flush=True)
    if shutil.which('br'):
        subprocess.run(['br','ready','--unassigned','--no-db','--json'],cwd=work,check=True)
    else:
        for line in (work/'.beads/issues.jsonl').read_text().splitlines():
            row=json.loads(line)
            if any(term in (row.get('title','')+' '+row.get('description','')).lower() for term in ['shallow','protocol-v2','smart-http']):
                print('TRACKER_EXPORT_READ_ONLY',json.dumps({key:row.get(key) for key in ['id','title','status','assignee','priority','description']}),flush=True)
    def edit(path,old,new):
        p=work/path;text=p.read_text();assert text.count(old)==1,(path,old[:80],text.count(old));p.write_text(text.replace(old,new))
    wire='crates/fgit-wire/src/lib.rs';node='crates/fgit-node/src/lib.rs';test='crates/fgit-node/tests/git_daemon_v2_fragments.rs'
    assert git('rev-parse',f'{BASE}:{wire}')=='ec0ae11bf72e419be46f2164357de046933007bc'
    assert git('rev-parse',f'{BASE}:{node}')=='30c6441b97d509d36000587a34664c28c633a0b5'
    text=(work/wire).read_text();start=text.index('impl V2UploadPack {');offset=text.index('    /// Feeds arbitrary pkt-line fragments',start)
    text=text[:offset]+'''    /// Whether no command is in progress. Pair with `finish` to detect a
    /// partial next frame; a completed ls-refs response is not a stream reset.
    #[must_use]
    pub fn is_awaiting_command(&self) -> bool {
        self.state == V2State::AwaitCommand
    }

'''+text[offset:];(work/wire).write_text(text)
    edit(node,'''        if read == 0 {
            if ls_refs_completed {''','''        if read == 0 {
            machine.finish().map_err(|error| GitDaemonServeError::Transport(
                GitDaemonTransportRefusal::Wire(error)))?;
            if ls_refs_completed && machine.is_awaiting_command() {''')
    edit(node,'        let mut next_command = false;\n','')
    edit(node,'                    next_command = true;\n','')
    edit(node,'''        if next_command {
            machine = fresh_machine()?;
        }
''','')
    assert not (work/test).exists();(work/test).write_bytes((ROOT/'tools/fetch-continuation/stream-test.rs').read_bytes())
    subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true',test],cwd=work,check=True)
    git('diff','--check',cwd=work);git('config','user.name','Jeff Emanuel',cwd=work);git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    paths={wire,node,test};assert set(git('diff','--name-only',cwd=work).splitlines())|set(git('ls-files','--others','--exclude-standard',cwd=work).splitlines())==paths
    git('add','--',*sorted(paths),cwd=work);git('commit','-m','fix(fetch): preserve v2 command state across arbitrary transport fragments','-m','Retain the already-reset SANS-I/O command machine instead of dropping next-command bytes coalesced with an ls-refs flush. Distinguish clean between-command EOF from truncated framing and unfinished requests. Add every-split and one-byte both-hash transport regressions plus incomplete-stream and refused-want twins. No authorization, retention or dependency change.',cwd=work)
    sha=git('rev-parse','HEAD',cwd=work);branch='tooling/fetch-progress-source-'+os.environ['GITHUB_SHA'][:12]
    git('push','origin',sha+':refs/heads/'+branch,cwd=work)
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:out.write('source='+sha+'\n')
    print('PRODUCT_SOURCE',sha,branch,flush=True)
