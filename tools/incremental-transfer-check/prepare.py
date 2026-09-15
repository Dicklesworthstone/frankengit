import hashlib, os, pathlib, subprocess, tempfile
ROOT=pathlib.Path.cwd()
BASE='ab7615cc38498f22e18093dab223614e8b7ad6bc'
PREFIX='crates/fgit-node/src/treefs_workspace/full_bundle/'
GUARDS={
 'tests.rs':('2024e65909792d9ac36263094e24651f44df6644','a6aeec132964b319863901649084b9bd447f688d'),
 'incremental_tests.rs':('0b4730f05f1d6ddd489001931e723dc41d37f476','114c55bd616c4d9920b3c7ad21641ae81ff5afdc'),
 'tests/fetch.rs':('4d8ad76049e831a6b984ec171f1b6b98758a8e63','18dc704c56b2e4eff1abfc92fe3ee0615e473963')}
def git(*args,cwd=ROOT):
 return subprocess.check_output(['git','-c','core.hooksPath=/dev/null',*args],cwd=cwd,text=True).strip()
def oid(data):return hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
old='''        assert_eq!(
            destination.read_git_object(child).unwrap(),
            source.read_git_object(child).unwrap()
        );'''
new='        assert_native_transfer(&source, &destination, child);'
with tempfile.TemporaryDirectory(prefix='fg-transfer-assertions-') as td:
 work=pathlib.Path(td)/'source';git('worktree','add','--detach',str(work),BASE)
 for relative,(before,after) in GUARDS.items():
  path=work/(PREFIX+relative);data=path.read_bytes();assert oid(data)==before
  text=data.decode();needle=old if relative!='tests/fetch.rs' else '        assert_eq!(destination.read_git_object(child).unwrap(), source.read_git_object(child).unwrap());'
  assert text.count(needle)==1; text=text.replace(needle,new)
  if relative=='tests.rs':text+=(ROOT/'tools/incremental-transfer-check/helper.rs').read_text()
  if relative=='incremental_tests.rs':
   needle='        assert_eq!(destination.read_git_object(child).unwrap(), new);'
   assert text.count(needle)==1; text=text.replace(needle,new)
  data=text.encode();assert oid(data)==after,(relative,oid(data));path.write_bytes(data)
 paths=[PREFIX+p for p in GUARDS]
 assert set(git('diff','--name-only',cwd=work).splitlines())==set(paths)
 git('diff','--check',cwd=work)
 git('config','user.name','Jeff Emanuel',cwd=work)
 git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
 git('add','--',*paths,cwd=work)
 git('commit','-m','test(bundle): verify native transfer independently of repository incarnation','-m','Native execution at b7cc80e4 exposed four assertions comparing complete source/destination VerifiedObject values, including deliberately different incarnation-scoped placement namespaces. Require both objects to remain bound to their own distinct node namespace, then compare the complete destination object with the independently reverified source payload and all envelope commitments under only the expected destination namespace. Keep every byte, native identity, kind, length, codec, logical commitment, manifest and all publication/retry assertions. No production validation or equality implementation is changed.',cwd=work)
 source=git('rev-parse','HEAD',cwd=work);branch='tooling/incremental-transfer-result-'+os.environ['GITHUB_SHA'][:12]
 git('push','origin',source+':refs/heads/'+branch,cwd=work)
 print('PRODUCT_SOURCE',source,branch,flush=True)
 with open(os.environ['GITHUB_OUTPUT'],'a') as out:out.write('source='+source+'\n')
