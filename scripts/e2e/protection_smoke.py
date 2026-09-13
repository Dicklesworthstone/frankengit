#!/usr/bin/env python3
"""Fresh-process administration with the real embedded node and native fg."""
import argparse,json,pathlib,subprocess,tempfile

def run_case(fg,root,fmt):
    tenant,repo='11'*16,'22'*16
    def invoke(args,exit=0,decode=True):
        result=subprocess.run([str(fg),*map(str,args)],capture_output=True,timeout=90)
        assert result.returncode==exit,(args[:2],result.returncode,exit,result.stdout,result.stderr)
        return json.loads(result.stdout) if decode else result
    invoke(['init',root,tenant,repo,fmt],decode=False)
    base=['protection','show',root,tenant,repo,'--trusted-local','--object-format',fmt]
    show=lambda:invoke(base)
    def command(version,epoch,who,key,admins=('99',),rules=True):
        args=['protection','set',root,tenant,repo,'--trusted-local','--object-format',fmt,
            '--principal',who*16,'--idempotency-key',key,'--expected-version',version,'--expected-policy-epoch',epoch]
        for admin in admins:args+=['--administrator',admin*16]
        if rules:args+=['--rule','refs/heads/main','33'*16]
        else:args+=['--clear-rules']
        return args
    empty=show();assert not empty['configured'] and empty['version']==0 and empty['policy'] is None
    first=command(0,empty['policy_epoch'],'99','first-private-key')
    enabled=invoke(first);assert enabled['outcome']=='committed' and enabled['node_closed']
    active=show();assert active['version']==1 and active['policy_epoch']==empty['policy_epoch']+1
    assert active['policy']=={'administrators':['99'*16],'branches':[{'target':'refs/heads/main','target_hex':b'refs/heads/main'.hex(),'reviewers':['33'*16]}]}
    assert show()['source_head']==active['source_head']
    unauthorized=command(1,active['policy_epoch'],'22','unauthorized-private-key',rules=False)
    denied=invoke(unauthorized,3);assert denied['refusal_code']=='ProtectedRefTransitionDenied'
    assert show()['policy']==active['policy'] and show()['version']==1
    rotate=command(1,active['policy_epoch'],'99','rotate-private-key',admins=('88',))
    invoke(rotate);rotated=show();assert rotated['version']==2
    retry=invoke(first)
    for field in ['tx_id','decision_sequence','repository_commit_id','refusal_record_id','outcome']:
        assert retry[field]==enabled[field]
    assert show()['source_head']==rotated['source_head']
    old_admin=command(2,rotated['policy_epoch'],'99','removed-admin-private-key',rules=False)
    assert invoke(old_admin,3)['refusal_code']=='ProtectedRefTransitionDenied'
    clear=command(2,rotated['policy_epoch'],'88','clear-private-key',admins=('88',),rules=False)
    invoke(clear);final=show();assert final['configured'] and final['version']==3 and not final['policy']['branches']
    assert final['policy_epoch']==empty['policy_epoch']+3
    changed=first.copy();changed[-1]='44'*16
    assert invoke(changed,2,False).stdout==b''
    assert show()['source_head']==final['source_head']
    recover=invoke(['outcome',root,tenant,repo,'--trusted-local','--object-format',fmt,
        '--principal','99'*16,'--idempotency-key','first-private-key'])
    assert recover['transaction']['tx_id']==enabled['tx_id']
    assert show()['source_head']==final['source_head']
    print(f'PROTECTION_CLI format={fmt} activation_admin_rotation_historical_retry=passed',flush=True)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--fg',type=pathlib.Path,required=True)
    args=parser.parse_args();fg=args.fg.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='fg-protection-cli-') as tmp:
        for fmt in ['sha1','sha256']:run_case(fg,pathlib.Path(tmp)/fmt,fmt)
if __name__=='__main__':main()
