#!/usr/bin/env python3
import argparse
from pathlib import Path
import tempfile
from full_bundle_smoke import invoke, decode_export
from pull_request_smoke import TENANT, REPOSITORY, PRINCIPAL, fixture, document, require


def run_format(binary, algorithm):
    with tempfile.TemporaryDirectory(prefix="fg-bundle-fetch-") as directory:
        root=Path(directory)
        original,destination,loose=root/"original",root/"destination",root/"loose"
        f=fixture(loose,algorithm)
        invoke(binary,["init",original,TENANT,REPOSITORY,algorithm])
        invoke(binary,["import",original,TENANT,REPOSITORY,PRINCIPAL,"fixture",loose])
        def branch(op,name,*extra):
            return ["branch",op,original,TENANT,REPOSITORY,"--trusted-local","--object-format",algorithm,"--principal",PRINCIPAL,"--ref",name,*extra]
        invoke(binary,branch("create","refs/heads/feed","--target",f["base"],"--idempotency-key","feed"))
        def bundle(op,node,path,*extra):
            return ["bundle",op,node,TENANT,REPOSITORY,path,"--trusted-local","--object-format",algorithm,*extra]
        old=root/"old.bundle"
        document(invoke(binary,bundle("export",original,old)))
        invoke(binary,["init",destination,TENANT,REPOSITORY,algorithm])
        def fetch(path,maps,key,code=0,raw=False):
            args=bundle("fetch",destination,path,"--principal",PRINCIPAL,"--key-stdin")
            for source,target,previous in maps:
                args += ["--map-hex" if raw else "--map",source.hex() if raw else source,target.hex() if raw else target,previous]
            return document(invoke(binary,args,code=code,data=key))
        def exported(label):
            path=root/(label+".bundle")
            report=document(invoke(binary,bundle("export",destination,path)))
            refs,objects=decode_export(path.read_bytes(),algorithm)
            return report,refs,objects
        local=b"refs/remotes/origin/\xff"
        initial=[(b"refs/heads/feed",local,"absent")]
        first=fetch(old,initial,b"private-fetch-initial\n",raw=True)
        require(first["type"]=="git_bundle_fetch" and first["atomic"] and first["command_committed"],"fetch result")
        require(first["reference_count"]==1 and first["mappings"][0]["destination_hex"]==local.hex(),"raw mapping")
        require(first["principal_id"]==PRINCIPAL and first["tenant_id"]==TENANT and first["repository_id"]==REPOSITORY,"identity binding")
        require("private-fetch-initial" not in str(first),"key disclosure")
        report,refs,objects=exported("initial")
        require(refs=={local:f["base"]},"fetch copied unselected refs or HEAD")
        require(set(objects)=={f[k] for k in ("base","tree","blob")},"unselected branch objects published")
        require(fetch(old,initial,b"private-fetch-initial\n",raw=True)==first,"initial retry")
        invoke(binary,branch("update","refs/heads/feed","--expected-tip",f["base"],"--target",f["source"],"--idempotency-key","advance-feed"))
        new=root/"new.bundle";document(invoke(binary,bundle("export",original,new)))
        maps=[(b"refs/heads/feed",local,f["base"]),(b"refs/heads/main",b"refs/heads/review","absent")]
        advanced=fetch(new,maps,b"private-fetch-advance\n",raw=True)
        require(advanced["reference_count"]==2 and advanced["command_committed"],"atomic advance")
        after,refs,objects=exported("advanced")
        require(refs[local]==f["source"] and refs[b"refs/heads/review"]==f["target"] and len(refs)==2,"exact updated refs")
        require(set(objects)=={f[k] for k in ("blob","tree","base","source","target")},"complete verified native closure")
        require(fetch(new,list(reversed(maps)),b"private-fetch-advance\n",raw=True)==advanced,"reordered exact retry")
        replay,_,_=exported("replay");require(replay["source_head"]==after["source_head"],"retry advanced authority")
        stale=[(b"refs/heads/feed",local,f["base"]),(b"refs/heads/main",b"refs/heads/should-not-exist","absent")]
        refused=fetch(new,stale,b"stale\n",code=3,raw=True)
        require(refused["outcome"]=="refused" and not refused["command_committed"],"stale expected old")
        refused_snapshot,refused_refs,_=exported("stale")
        require(refused_refs==refs,"partial stale batch publication")
        require(fetch(new,stale,b"stale\n",code=3,raw=True)==refused,"refused retry")
        invoke(binary,bundle("fetch",destination,new,"--principal",PRINCIPAL,"--key-stdin","--map","refs/heads/feed","refs/heads/changed","absent"),code=2,data=b"private-fetch-advance\n")
        invoke(binary,bundle("fetch",destination,old,"--principal",PRINCIPAL,"--idempotency-key","rewind","--map-hex",b"refs/heads/feed".hex(),local.hex(),f["source"]),code=2)
        bad=root/"corrupt.bundle";data=new.read_bytes();bad.write_bytes(data[:-1]+bytes([data[-1]^1]))
        invoke(binary,bundle("fetch",destination,bad,"--principal",PRINCIPAL,"--idempotency-key","bad","--map","refs/heads/main","refs/heads/bad","absent"),code=2)
        final,final_refs,_=exported("final")
        require(final["source_head"]==refused_snapshot["source_head"] and final_refs==refs,"invalid intake changed authority")
        print(f"BUNDLE_FETCH_CLI format={algorithm} selection_fast_forward_atomicity_raw_refs_retry=passed")


def main():
    parser=argparse.ArgumentParser();parser.add_argument("--fg",required=True,type=Path)
    binary=parser.parse_args().fg.resolve()
    for algorithm in ("sha1","sha256"):run_format(binary,algorithm)


if __name__=="__main__":main()
