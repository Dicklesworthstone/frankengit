use std::{collections::BTreeMap,path::PathBuf};
use fgit_authority::{ExpectedOld,ProposedNew,RefCommand,MAX_IDEMPOTENCY_KEY_BYTES};
use fgit_types::{CANONICAL_CODEC_VERSION,GitHashAlgorithm,GitOid,PrincipalId,RefName,RepositoryAuthorityHeadId,RepositoryId,TenantId};
use fgit_types::hash::{DigestAlgorithmId,DigestBytes};

pub(super) struct Options {
    pub storage:PathBuf,pub tenant:TenantId,pub repository:RepositoryId,pub format:GitHashAlgorithm,pub operation:Operation,
}
pub(super) enum KeyInput { Bytes(Vec<u8>),Stdin }
pub(super) enum Operation {
    Mutate{action:String,principal:PrincipalId,key:KeyInput,commands:Vec<RefCommand>},
    List{after:Option<RefName>,limit:u16,expected_head:Option<RepositoryAuthorityHeadId>},
}
pub(super) fn parse(args:&[String])->Result<Options,String> {
    if args.len()<4 {return Err(super::USAGE.into());}
    if args.len()>28 || args.iter().any(|arg|arg.len()>8192) || args.iter().map(String::len).sum::<usize>()>32768 {
        return Err("branch arguments exceed the bounded profile".into());
    }
    let action=args[0].as_str();
    if !matches!(action,"list"|"create"|"update"|"delete"|"rename") {return Err(super::USAGE.into());}
    if args[1].is_empty() || args[1].len()>4096 {return Err("invalid branch storage path".into());}
    let tenant=TenantId::from_hex(&args[2]).map_err(|_|"invalid tenant ID")?;
    let repository=RepositoryId::from_hex(&args[3]).map_err(|_|"invalid repository ID")?;
    let mut flags=BTreeMap::new();let mut index=4;
    while index<args.len() {
        let flag=args[index].as_str();index+=1;
        let common=matches!(flag,"--trusted-local"|"--object-format");
        let permitted=if action=="list" {matches!(flag,"--after"|"--after-hex"|"--limit"|"--expected-head")}
            else {matches!(flag,"--principal"|"--idempotency-key"|"--key-stdin"|"--ref"|"--ref-hex")
                || (matches!(action,"create"|"update") && flag=="--target")
                || (matches!(action,"update"|"delete"|"rename") && flag=="--expected-tip")
                || (action=="rename" && matches!(flag,"--destination"|"--destination-hex"))};
        if !common && !permitted {return Err(format!("inapplicable branch option {flag:?}"));}
        let value=if matches!(flag,"--trusted-local"|"--key-stdin") {""} else {
            let value=args.get(index).ok_or_else(||format!("missing value for {flag}"))?;index+=1;value.as_str()
        };
        if flags.insert(flag,value).is_some() {return Err(format!("duplicate branch option {flag}"));}
    }
    if !flags.contains_key("--trusted-local") {return Err("--trusted-local is required; branch names and keys are not credentials".into());}
    let format=match flags.get("--object-format").copied().unwrap_or("sha1") {
        "sha1"=>GitHashAlgorithm::Sha1,"sha256"=>GitHashAlgorithm::Sha256,_=>return Err("object format must be sha1 or sha256".into()),
    };
    let operation=if action=="list" {
        let after=if flags.contains_key("--after") || flags.contains_key("--after-hex") {Some(reference(&flags,"--after","--after-hex")?)}else{None};
        let expected_head=flags.get("--expected-head").map(|value|parse_head(value)).transpose()?;
        if after.is_some() && expected_head.is_none() {return Err("branch continuation requires --expected-head from the first page".into());}
        let limit=flags.get("--limit").map(|value|decimal(value)).transpose()?.unwrap_or(50);
        if !(1..=100).contains(&limit) {return Err("branch limit must be 1..100".into());}
        Operation::List{after,limit:limit as u16,expected_head}
    } else {
        let principal=PrincipalId::from_hex(required(&flags,"--principal")?).map_err(|_|"invalid principal ID")?;
        let key=match (flags.get("--idempotency-key"),flags.contains_key("--key-stdin")) {
            (Some(key),false) if !key.is_empty() && key.len()<=MAX_IDEMPOTENCY_KEY_BYTES=>KeyInput::Bytes(key.as_bytes().to_vec()),
            (None,true)=>KeyInput::Stdin,_=>return Err("supply exactly one bounded key or --key-stdin".into()),
        };
        let name=reference(&flags,"--ref","--ref-hex")?;
        let oid=|flag|->Result<GitOid,String> {
            let value=GitOid::from_hex(format,required(&flags,flag)?).map_err(|_|"invalid native object ID")?;
            if value.is_zero() {return Err("branch tips must be nonzero".into());}Ok(value)
        };
        let commands=match action {
            "create"=>vec![RefCommand{name,expected_old:ExpectedOld::Absent,proposed_new:ProposedNew::Update(oid("--target")?),force:false}],
            "update"=>vec![RefCommand{name,expected_old:ExpectedOld::Exactly(oid("--expected-tip")?),proposed_new:ProposedNew::Update(oid("--target")?),force:false}],
            "delete"=>vec![RefCommand{name,expected_old:ExpectedOld::Exactly(oid("--expected-tip")?),proposed_new:ProposedNew::Delete,force:false}],
            "rename"=>{
                let destination=reference(&flags,"--destination","--destination-hex")?;
                if destination==name {return Err("rename requires distinct source and destination branches".into());}
                let tip=oid("--expected-tip")?;
                vec![RefCommand{name,expected_old:ExpectedOld::Exactly(tip),proposed_new:ProposedNew::Delete,force:false},
                    RefCommand{name:destination,expected_old:ExpectedOld::Absent,proposed_new:ProposedNew::Update(tip),force:false}]
            }
            _=>return Err("invalid branch action".into()),
        };
        Operation::Mutate{action:action.into(),principal,key,commands}
    };
    Ok(Options{storage:args[1].clone().into(),tenant,repository,format,operation})
}
fn required<'a>(flags:&BTreeMap<&str,&'a str>,flag:&str)->Result<&'a str,String> {
    flags.get(flag).copied().ok_or_else(||format!("{flag} is required"))
}
fn reference(flags:&BTreeMap<&str,&str>,plain:&str,encoded:&str)->Result<RefName,String> {
    let bytes=match (flags.get(plain),flags.get(encoded)) {
        (Some(value),None) if value.len()<=4096=>value.as_bytes().to_vec(),
        (None,Some(value))=>unhex(value,4096)?,_=>return Err(format!("supply exactly one of {plain} or {encoded}")),
    };
    if !bytes.starts_with(b"refs/heads/") {return Err("a full refs/heads/ reference is required".into());}
    RefName::try_new(&bytes).map_err(|_|"invalid branch reference bytes".into())
}
fn decimal(value:&str)->Result<u64,String> {
    if value.is_empty() || !value.bytes().all(|byte|byte.is_ascii_digit()) || (value.len()>1 && value.starts_with('0')) {
        return Err("expected canonical unsigned decimal".into());
    }
    value.parse().map_err(|_|"decimal overflow".into())
}
fn unhex(value:&str,limit:usize)->Result<Vec<u8>,String> {
    if value.is_empty() || value.len()>2*limit || value.len()%2!=0 || !value.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("expected bounded nonempty lowercase hex bytes".into());
    }
    let digit=|b|if b<=b'9'{b-b'0'}else{b-b'a'+10};
    Ok(value.as_bytes().chunks_exact(2).map(|pair|16*digit(pair[0])+digit(pair[1])).collect())
}
pub(super) fn hex(bytes:&[u8])->String { bytes.iter().map(|b|format!("{b:02x}")).collect() }
pub(super) fn head_token(head:RepositoryAuthorityHeadId)->String {
    let id=head.as_internal_object_id();format!("alg:{}:{}",id.algorithm().code_point(),hex(id.digest().as_bytes()))
}
fn parse_head(text:&str)->Result<RepositoryAuthorityHeadId,String> {
    let (algorithm,digest)=text.strip_prefix("alg:").and_then(|value|value.split_once(':')).ok_or("expected exact algorithm-qualified snapshot_token")?;
    let algorithm=u16::try_from(decimal(algorithm)?).map_err(|_|"head algorithm overflow")?;
    let algorithm=DigestAlgorithmId::try_new(algorithm).map_err(|_|"invalid head algorithm")?;
    let digest=DigestBytes::try_new(&unhex(digest,64)?).map_err(|_|"invalid head digest width")?;
    Ok(RepositoryAuthorityHeadId::from_digest(algorithm,CANONICAL_CODEC_VERSION,digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(action:&str)->Vec<String> {
        let mut args=vec![action.into(),"unopened".into(),"11".repeat(16),"22".repeat(16),"--trusted-local".into()];
        if action!="list" {args.extend(["--principal".into(),"33".repeat(16),"--idempotency-key".into(),"private".into(),"--ref".into(),"refs/heads/topic".into()]);}
        args
    }
    #[test]
    fn parse_exact_atomic_rename_and_non_utf8_reference() {
        let mut args=args("rename");args.extend(["--expected-tip".into(),"1".repeat(40),"--destination-hex".into(),hex(b"refs/heads/\xff")]);
        let options=parse(&args).unwrap();let Operation::Mutate{commands,..}=options.operation else{panic!()};
        assert_eq!(commands.len(),2);assert_eq!(commands[1].name.as_bytes(),b"refs/heads/\xff");
        assert!(matches!(commands[1].expected_old,ExpectedOld::Absent));assert!(matches!(commands[0].proposed_new,ProposedNew::Delete));
    }
    #[test]
    fn mutation_flags_are_action_specific_and_duplicates_refuse() {
        let mut args=args("create");args.extend(["--target".into(),"1".repeat(40)]);assert!(parse(&args).is_ok());
        let mut wrong=args.clone();wrong.extend(["--expected-tip".into(),"2".repeat(40)]);assert!(parse(&wrong).is_err());
        let mut duplicate=args.clone();duplicate.extend(["--ref-hex".into(),hex(b"refs/heads/other")]);assert!(parse(&duplicate).is_err());
        let mut both=args.clone();both.push("--key-stdin".into());assert!(parse(&both).is_err());
        let mut zero=args.clone();*zero.last_mut().unwrap()="0".repeat(40);assert!(parse(&zero).is_err());
        let mut force=args.clone();force.push("--force".into());assert!(parse(&force).is_err());
        args.retain(|arg|arg!="--trusted-local");assert!(parse(&args).is_err());
    }
    #[test]
    fn listing_requires_snapshot_pins_and_bounded_canonical_limits() {
        let base=args("list");assert!(parse(&base).is_ok());
        for value in ["0","101","01","-1"] {let mut args=base.clone();args.extend(["--limit".into(),value.into()]);assert!(parse(&args).is_err());}
        let mut args=base;args.extend(["--after".into(),"refs/heads/a".into()]);assert!(parse(&args).is_err());
        args.extend(["--expected-head".into(),format!("alg:1:{}","ab".repeat(32))]);assert!(parse(&args).is_ok());
    }
}
