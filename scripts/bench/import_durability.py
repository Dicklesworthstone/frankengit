"""Measure native import on fresh synthetic histories; not a Git differential benchmark.
Usage: python3 scripts/bench/import_durability.py FG_BIN NEW_ROOT COMMITS [sha1|sha256] [trace]
Use distinct empty roots for alternating baseline/candidate and same-binary controls.
The trace option requires strace. Keep traced and untraced timings separate.
"""
import hashlib,json,pathlib,subprocess,sys,time,zlib
fg,root,n=sys.argv[1],pathlib.Path(sys.argv[2]),int(sys.argv[3]);fmt=sys.argv[4] if len(sys.argv)>4 else 'sha1';trace=len(sys.argv)>5
root.mkdir(parents=True,exist_ok=True); source=root/'source'; node=root/'node';tenant='11'*16; repo='22'*16; principal='33'*16

def obj(kind,body):
 raw=kind.encode()+b' '+str(len(body)).encode()+b'\0'+body;oid=hashlib.new(fmt,raw).hexdigest();p=source/'objects'/oid[:2]/oid[2:];p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(zlib.compress(raw));return oid
parent=None
for i in range(n):
 blob=obj('blob',f'line {i}\n'.encode());tree=obj('tree',b'100644 file\0'+bytes.fromhex(blob));body=f'tree {tree}\n'+(f'parent {parent}\n' if parent else '')+f'author Fixture <fixture@example.invalid> {i+1} +0000\ncommitter Fixture <fixture@example.invalid> {i+1} +0000\n\ncommit {i}\n';parent=obj('commit',body.encode())
(source/'refs/heads').mkdir(parents=True);(source/'refs/heads/main').write_text(parent+'\n');(source/'HEAD').write_text('ref: refs/heads/main\n')
subprocess.run([fg,'init',str(node),tenant,repo,fmt],check=True,capture_output=True)
args=[fg,'--timeout-secs','300','import',str(node),tenant,repo,principal,'measure-import',str(source),'--json'];cmd=(['strace','-f','-T','-e','trace=fsync','-o',str(root/'fsync.trace')]+args) if trace else args
start=time.monotonic();r=subprocess.run(cmd,capture_output=True,timeout=360);elapsed=time.monotonic()-start;(root/'import.out').write_bytes(r.stdout);(root/'import.err').write_bytes(r.stderr)
result={'format':fmt,'commits':n,'objects':3*n,'elapsed_seconds':elapsed,'exit':r.returncode,'binary_sha256':hashlib.sha256(pathlib.Path(fg).read_bytes()).hexdigest()}
if trace:
 import re
 lines=(root/'fsync.trace').read_text().splitlines();result['fsync_calls']=sum('fsync(' in s for s in lines);result['fsync_seconds']=sum(float(m.group(1)) for s in lines if (m:=re.search(r'<([0-9.]+)>$',s)))
(root/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
if r.returncode:print(r.stderr.decode(),r.stdout.decode(),flush=True);raise SystemExit(r.returncode)
