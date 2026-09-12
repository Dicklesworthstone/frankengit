import pathlib,sys
root=pathlib.Path(sys.argv[1]).resolve()
payload=pathlib.Path(__file__).resolve().parent
def edit(path,old,new,count=1):
    p=root/path;s=p.read_text();assert s.count(old)==count,(path,old[:100],s.count(old));p.write_text(s.replace(old,new))
r='crates/fgit-node/src/upload_visibility/tests/partial_oracle.rs'
for name in ['command','checked','live_client','inventory']:
    edit(r,'fn '+name+'(','pub(super) fn '+name+'(')
t='crates/fgit-node/src/upload_visibility/tests.rs'
edit(t,'mod partial_oracle;','mod partial_oracle;\n#[cfg(target_os = "linux")]\nmod shallow_oracle;')
p=root/'crates/fgit-node/src/upload_visibility/tests/shallow_oracle.rs'
assert not p.exists();p.write_bytes((payload/'shallow_oracle.rs').read_bytes())
c='scripts/e2e/oracle/partial_clone_client.py'
edit(c,'RUN clone|read|checkout|inventory|fsck CLIENT [ENDPOINT REPOSITORY VERSION FILTER|OID]','RUN clone|shallow-clone|depth|unshallow|fetch|read|checkout|inventory|history|fsck CLIENT [ENDPOINT REPOSITORY VERSION VALUE]')
edit(c,'if operation not in {"clone", "read", "checkout", "inventory", "fsck"}:','if operation not in {"clone", "shallow-clone", "depth", "unshallow", "fetch", "read", "checkout", "inventory", "history", "fsck"}:')
edit(c,'    if operation == "clone":\n        if destination.exists()', '    cloning = operation in {"clone", "shallow-clone"}\n    if cloning:\n        if destination.exists()')
edit(c,'    network = operation in {"clone", "read", "checkout"}','    network = operation in {"clone", "shallow-clone", "depth", "unshallow", "fetch", "read", "checkout"}')
edit(c,'        if operation == "clone":\n            if value not in', '''        if operation in {"depth", "unshallow", "fetch"}:
            config.append(("remote.origin.url", url))
        if operation == "shallow-clone":
            depth = re.fullmatch(r"([1-9][0-9]{0,9})(?:,(blob:none|tree:0))?", value)
            if not depth or int(depth[1]) > 2147483647:
                refuse("shallow clone needs a bounded positive depth and optional campaign filter")
            command = ["clone", "--no-local", "--no-checkout", "--single-branch", "--branch=public", "--depth=" + depth[1]]
            if depth[2]:
                command.append("--filter=" + depth[2])
            command += [url, client]
        elif operation == "depth":
            if not re.fullmatch(r"[1-9][0-9]{0,9}", value) or int(value) > 2147483647:
                refuse("absolute depth must be a bounded positive integer")
            command = ["fetch", "--no-tags", "--depth=" + value, "origin"]
        elif operation in {"unshallow", "fetch"}:
            if value != "-":
                refuse("this fetch operation takes only the fixed no-value marker")
            command = ["fetch", "--no-tags"]
            if operation == "unshallow":
                command.append("--unshallow")
            command.append("origin")
        elif operation == "clone":
            if value not in''')
edit(c,'        command = ["cat-file", "--batch-all-objects", "--batch-check=%(objectname)"] if operation == "inventory" else ["fsck", "--strict"]','''        command = {"inventory": ["cat-file", "--batch-all-objects", "--batch-check=%(objectname)"],
                   "history": ["rev-list", "refs/remotes/origin/public"],
                   "fsck": ["fsck", "--strict"]}[operation]''')
edit(c,'"--chdir", "/work" if operation == "clone" else "/work/" + client]','"--chdir", "/work" if cloning else "/work/" + client]')
print('Pinned shallow lifecycle reuses the existing sandbox, digest validation, transcripts and bounded real-session driver',flush=True)
