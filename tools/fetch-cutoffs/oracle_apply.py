import pathlib
root=pathlib.Path.cwd()
def edit(name,old,new,count=1):
    path=root/name;text=path.read_text();assert text.count(old)==count,(name,old,text.count(old));path.write_text(text.replace(old,new))
p='scripts/e2e/oracle/partial_clone_client.py'
edit(p,'import time\n','import time\nfrom cutoff_client import cutoff_arguments\n')
edit(p,'"clone", "shallow-clone",','"cutoff-clone", "cutoff-fetch", "clone", "shallow-clone",',2)
edit(p,'cloning = operation in {"clone", "shallow-clone"}','cloning = operation in {"clone", "shallow-clone", "cutoff-clone"}')
edit(p,'        if operation in {"depth", "deepen", "unshallow", "fetch", "fetch-private"}:','        if operation in {"cutoff-fetch", "depth", "deepen", "unshallow", "fetch", "fetch-private"}:')
edit(p,'        if operation == "shallow-clone":', '''        if operation == "cutoff-clone":
            command = ["clone", "--no-local", "--no-checkout", "--single-branch", "--branch=public", "--no-tags", *cutoff_arguments(value), url, client]
        elif operation == "cutoff-fetch":
            command = ["fetch", "--no-tags", *cutoff_arguments(value), "origin"]
        elif operation == "shallow-clone":''')
edit('crates/fgit-node/src/upload_visibility/tests/shallow_oracle.rs','use super::partial_oracle::{','mod cutoff_oracle;\nuse super::partial_oracle::{')
