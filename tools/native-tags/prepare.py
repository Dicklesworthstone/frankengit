import base64,gzip,hashlib,json,os,pathlib,subprocess,sys
base=sys.argv[1];phase=sys.argv[2];digest=sys.argv[3];message=sys.argv[4]
work=pathlib.Path(os.environ['RUNNER_TEMP'])/('tag-source-'+phase)
def git(*args,cwd=None):return subprocess.check_output(['git',*args],cwd=cwd,text=True).strip()
patch=gzip.decompress(base64.b64decode(pathlib.Path('tools/native-tags/phase'+phase+'.patch.b64').read_text()))
assert hashlib.sha256(patch).hexdigest()==digest,'exact patch checksum mismatch'
git('worktree','add','--detach',str(work),base)
p=work.parent/('tags-'+phase+'.patch');p.write_bytes(patch)
git('apply','--check',str(p),cwd=work);git('apply','--index',str(p),cwd=work);git('diff','--cached','--check',cwd=work)
git('config','user.name','Jeff Emanuel',cwd=work);git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
git('commit','-m',message,cwd=work)
sha=git('rev-parse','HEAD',cwd=work);ref='tooling/native-tags-product-'+phase
git('push','origin','HEAD:refs/heads/'+ref,cwd=work)
print(json.dumps({'sha':sha,'base':base,'tree':git('rev-parse','HEAD^{tree}',cwd=work),'paths':git('diff','--name-only',base,'HEAD',cwd=work).splitlines()}))
with open(os.environ['GITHUB_OUTPUT'],'a') as out:out.write('source='+sha+'\n')
