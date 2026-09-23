//! Real file lifecycle tests and explicitly labelled executor fixtures.
use super::*;
use crate::workflow::{WorkflowExecutor,WorkflowPlan,WorkflowLimits,StepLimits,StepOutcome,WorkerFailure};
use std::os::unix::fs::{DirBuilderExt,PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64,Ordering};

const SOURCE:&str="name: durable\non: push\njobs:\n  first:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: echo first\n  second:\n    runs-on: fgit-trusted-local\n    needs: first\n    steps:\n      - run: echo second\n";
static NEXT:AtomicU64=AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new()->Self {
        let p=std::env::temp_dir().join(format!("fgit-durable-attempt-{}-{}",std::process::id(),NEXT.fetch_add(1,Ordering::Relaxed)));
        fs::DirBuilder::new().mode(0o700).create(&p).unwrap();Self(p)
    }
    fn attempt(&self)->PathBuf { self.0.join("attempt") }
    fn journal(&self)->PathBuf { self.0.join("journal") }
}
impl Drop for Temp {fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}
fn scope()->CheckJournalScope {
    CheckJournalScope{tenant:TenantId::from_bytes([1;16]),repository:RepositoryId::from_bytes([2;16]),journal_id:Commitment::of_bytes(b"attempt-tests")}
}
fn fixture_binding()->WorkflowAttemptBinding {
    WorkflowAttemptBinding{scope:scope(),run:WorkflowRunId(Commitment::of_bytes(b"run")),attempt:AttemptId(Commitment::of_bytes(b"attempt")),request:Commitment::of_bytes(b"request")}
}
fn header_pin()->CheckJournalPin {CheckJournalPin::new(HEADER_BYTES,Commitment::of_bytes(&scope().bytes()))}
fn write_fixture(path:&Path,bytes:&[u8]) {
    let mut file=OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path).unwrap();
    file.write_all(bytes).unwrap();file.sync_all().unwrap();
}
fn coordinator()->WorkflowCoordinator {
    WorkflowCoordinator::new(CoordinatorLimits::default(),ResourceCeilings::new(100_000,512*1024*1024,1024*1024*1024,0,16,60_000).unwrap(),4).unwrap()
}
fn enqueue(c:&mut WorkflowCoordinator,sequence:u64,source:&str)->PreparedTrustedWorkflow {
    c.enqueue_trusted_workflow(scope().tenant,scope().repository,Commitment::of_bytes(b"head"),
        GitOid::Sha1(GitOidSha1::from_bytes([3;20])),WorkflowPlan::compile(source).unwrap(),
        WorkflowLimits{stream_bytes:512,total_output_bytes:1024,..WorkflowLimits::default()},
        TriggerContext::trusted_push("tester"),sequence,100).unwrap()
}
struct Executor {owner:PathBuf,starts:usize,closes:usize,panic_step:bool,retain:bool}
impl Executor {fn new(owner:PathBuf)->Self {Self{owner,starts:0,closes:0,panic_step:false,retain:false}}}
impl WorkflowExecutor for Executor {
    fn begin_job(&mut self,_:usize,_:&fgit_schema::workflow::Job,_:&dyn Fn()->bool)->Result<(),WorkerFailure> {
        // The complete Started record must exist BEFORE any user callback.
        assert!(fs::metadata(&self.owner).unwrap().len()>=ATTEMPT_HEADER_BYTES+77);
        self.starts+=1;Ok(())
    }
    fn execute_step(&mut self,_:usize,script:&str,_:StepLimits,_:&dyn Fn()->bool)->Result<StepObservation,WorkerFailure> {
        assert!(!self.panic_step,"fixture process-boundary panic");
        Ok(StepObservation{outcome:StepOutcome::Succeeded,exit_code:Some(0),stdout:script.as_bytes().to_vec(),stderr:Vec::new(),elapsed_millis:1,output_complete:true,retain_workspace:self.retain})
    }
    fn finish_job(&mut self,_:bool)->Result<(),WorkerFailure> {self.closes+=1;Ok(())}
}

#[test]
fn header_and_start_hash_match_independent_python_golden() {
    let binding=fixture_binding();assert_eq!(binding.bytes().len(),168);
    assert_eq!(Commitment::of_bytes(&binding.bytes()).digest().bytes().as_bytes(),&HEADER_GOLDEN);
    let temp=Temp::new();let mut owner=FileWorkflowAttempt::create(&temp.attempt(),binding).unwrap();
    owner.start(header_pin()).unwrap();
    assert_eq!(owner.pin().tail().digest().bytes().as_bytes(),&START_GOLDEN);
}

#[test]
fn started_is_irreversible_after_reopen_and_does_not_grant_retry() {
    let temp=Temp::new();let binding=fixture_binding();let mut owner=FileWorkflowAttempt::create(&temp.attempt(),binding).unwrap();
    assert_eq!(owner.status(),WorkflowAttemptStatus::Prepared);owner.start(header_pin()).unwrap();
    let pin=owner.pin();drop(owner);
    let mut owner=FileWorkflowAttempt::open(&temp.attempt(),binding,Some(pin),&||true).unwrap();
    assert_eq!(owner.status(),WorkflowAttemptStatus::Started);
    assert_eq!(owner.start(header_pin()).err(),Some(WorkflowAttemptRefusal::ReconciliationRequired));
    assert_eq!(owner.pin(),pin);assert!(owner.completed_receipt().unwrap().is_none());
}

#[test]
fn completed_bytes_and_containment_flag_survive_lost_response() {
    let temp=Temp::new();let binding=fixture_binding();let mut owner=FileWorkflowAttempt::create(&temp.attempt(),binding).unwrap();
    owner.start(header_pin()).unwrap();owner.finish_bytes(b"local-observation-fixture",true,header_pin()).unwrap();
    let pin=owner.pin();drop(owner);
    let mut owner=FileWorkflowAttempt::open(&temp.attempt(),binding,Some(pin),&||true).unwrap();
    let receipt=owner.completed_receipt().unwrap().unwrap();
    assert_eq!(receipt.frame(),b"local-observation-fixture");assert!(receipt.requires_containment());
    assert_eq!(receipt.binding(),binding);assert_eq!(owner.status(),WorkflowAttemptStatus::Completed);
}

#[test]
fn wrong_request_or_journal_instance_cannot_adopt_an_attempt() {
    let temp=Temp::new();let binding=fixture_binding();drop(FileWorkflowAttempt::create(&temp.attempt(),binding).unwrap());
    for other in [WorkflowAttemptBinding{request:Commitment::of_bytes(b"changed"),..binding},
        WorkflowAttemptBinding{scope:CheckJournalScope{journal_id:Commitment::of_bytes(b"other"),..scope()},..binding}] {
        assert_eq!(FileWorkflowAttempt::open(&temp.attempt(),other,None,&||true).err(),Some(WorkflowAttemptRefusal::IdentityMismatch));
    }
}

#[test]
fn lock_no_overwrite_and_missing_file_are_fail_closed() {
    let temp=Temp::new();let binding=fixture_binding();
    assert!(FileWorkflowAttempt::open(&temp.attempt(),binding,None,&||true).is_err());assert!(!temp.attempt().exists());
    let owner=FileWorkflowAttempt::create(&temp.attempt(),binding).unwrap();
    assert!(FileWorkflowAttempt::create(&temp.attempt(),binding).is_err());
    assert_eq!(FileWorkflowAttempt::open(&temp.attempt(),binding,None,&||true).err(),Some(WorkflowAttemptRefusal::Custody(CheckDeliveryRefusal::LockUnavailable)));
    drop(owner);assert!(FileWorkflowAttempt::open(&temp.attempt(),binding,None,&||true).is_ok());
}

#[test]
fn unsafe_file_kinds_and_permissions_are_not_adopted() {
    let temp=Temp::new();let binding=fixture_binding();drop(FileWorkflowAttempt::create(&temp.attempt(),binding).unwrap());
    let alias=temp.0.join("alias");std::os::unix::fs::symlink(temp.attempt(),&alias).unwrap();
    assert!(FileWorkflowAttempt::open(&alias,binding,None,&||true).is_err());fs::remove_file(&alias).unwrap();
    fs::hard_link(temp.attempt(),&alias).unwrap();assert!(FileWorkflowAttempt::open(&temp.attempt(),binding,None,&||true).is_err());fs::remove_file(&alias).unwrap();
    fs::set_permissions(temp.attempt(),fs::Permissions::from_mode(0o640)).unwrap();
    assert!(FileWorkflowAttempt::open(&temp.attempt(),binding,None,&||true).is_err());
}

#[test]
fn rollback_to_valid_prepared_prefix_requires_the_independent_witness() {
    let temp=Temp::new();let binding=fixture_binding();let mut owner=FileWorkflowAttempt::create(&temp.attempt(),binding).unwrap();
    owner.start(header_pin()).unwrap();let pin=owner.pin();drop(owner);
    write_fixture(&temp.attempt(),&binding.bytes());
    assert_eq!(FileWorkflowAttempt::open(&temp.attempt(),binding,Some(pin),&||true).err(),Some(WorkflowAttemptRefusal::Custody(CheckDeliveryRefusal::CorruptJournal)));
    assert_eq!(FileWorkflowAttempt::open(&temp.attempt(),binding,None,&||true).unwrap().status(),WorkflowAttemptStatus::Prepared);
}

#[test]
fn every_nonboundary_torn_prefix_is_refused_without_modifying_it() {
    let temp=Temp::new();let binding=fixture_binding();let mut owner=FileWorkflowAttempt::create(&temp.attempt(),binding).unwrap();
    owner.start(header_pin()).unwrap();let start=owner.pin().byte_len() as usize;
    owner.finish_bytes(b"fixture result",false,header_pin()).unwrap();drop(owner);
    let full=fs::read(temp.attempt()).unwrap();let path=temp.0.join("damaged");
    for end in 0..full.len() {
        if [168,start].contains(&end) {continue;}
        write_fixture(&path,&full[..end]);
        assert_eq!(FileWorkflowAttempt::open(&path,binding,None,&||true).err(),Some(WorkflowAttemptRefusal::Custody(CheckDeliveryRefusal::CorruptJournal)),"prefix {end}");
        assert_eq!(fs::read(&path).unwrap(),full[..end]);
    }
}

#[test]
fn readback_corruption_poisons_the_open_owner() {
    let temp=Temp::new();let mut owner=FileWorkflowAttempt::create(&temp.attempt(),fixture_binding()).unwrap();
    owner.start(header_pin()).unwrap();owner.finish_bytes(b"fixture result",false,header_pin()).unwrap();
    let mut bytes=fs::read(temp.attempt()).unwrap();let at=bytes.len()-33;bytes[at]^=1;write_fixture(&temp.attempt(),&bytes);
    assert!(owner.completed_receipt().is_err());assert!(owner.is_failed());
    assert_eq!(owner.completed_receipt().err(),Some(WorkflowAttemptRefusal::Custody(CheckDeliveryRefusal::FailedJournal)));
}

#[test]
fn duplicate_start_and_unknown_completion_tag_refuse_even_with_valid_hashes() {
    for bad in [1,3] {
        let temp=Temp::new();let binding=fixture_binding();let mut owner=FileWorkflowAttempt::create(&temp.attempt(),binding).unwrap();
        owner.start(header_pin()).unwrap();let previous=owner.pin().tail();drop(owner);
        let mut payload=pin_payload(bad,header_pin());if bad==3 {payload.push(0);payload.extend_from_slice(b"fixture");}
        let mut file=OpenOptions::new().append(true).open(temp.attempt()).unwrap();
        write_frame(&mut file,&payload,attempt_hash(previous,&payload),|f|f.sync_all()).unwrap();drop(file);
        assert_eq!(FileWorkflowAttempt::open(&temp.attempt(),binding,None,&||true).err(),Some(WorkflowAttemptRefusal::Custody(CheckDeliveryRefusal::CorruptJournal)));
    }
}

#[test]
fn full_execution_replays_after_discarding_all_in_memory_handles_without_work() {
    let temp=Temp::new();let mut c=coordinator();let mut p=enqueue(&mut c,1,SOURCE);
    let binding=c.trusted_attempt_binding(&p,scope(),200).unwrap();
    let mut journal=FileCheckJournal::create(&temp.journal(),scope(),CheckJournalLimits::default()).unwrap();
    let mut owner=FileWorkflowAttempt::create(&temp.attempt(),binding).unwrap();let mut executor=Executor::new(temp.attempt());
    let receipt=c.execute_trusted_workflow_durable(&mut p,&mut executor,&mut journal,&mut owner,200,&||true).unwrap();
    assert_eq!(executor.starts,2);assert_eq!(executor.closes,2);assert_eq!(receipt.frame(),p.receipt().unwrap().frame());
    c.verify_quiescence().unwrap();let pin=owner.pin();drop(owner);drop(journal);drop(p);drop(c);
    let mut c=coordinator();let mut p=enqueue(&mut c,1,SOURCE);let mut executor=Executor::new(temp.attempt());
    let mut owner=FileWorkflowAttempt::open(&temp.attempt(),binding,Some(pin),&||true).unwrap();
    let mut journal=FileCheckJournal::open(&temp.journal(),scope(),CheckJournalLimits::default(),Some(receipt.journal_pin()),&||true).unwrap();
    let again=c.execute_trusted_workflow_durable(&mut p,&mut executor,&mut journal,&mut owner,200,&||false).unwrap();
    assert_eq!(again,receipt);assert_eq!(executor.starts,0);assert_eq!(owner.pin(),pin);
    assert!(c.eligible_jobs(p.run_id()).unwrap().is_empty());
}

#[test]
fn unknown_started_attempt_blocks_rerun_and_fences_other_work_on_the_coordinator() {
    let temp=Temp::new();let mut c=coordinator();let p=enqueue(&mut c,1,SOURCE);
    let binding=c.trusted_attempt_binding(&p,scope(),200).unwrap();
    let mut journal=FileCheckJournal::create(&temp.journal(),scope(),CheckJournalLimits::default()).unwrap();
    let mut owner=FileWorkflowAttempt::create(&temp.attempt(),binding).unwrap();owner.start(journal.pin()).unwrap();drop(owner);drop(p);drop(c);
    let mut c=coordinator();let mut p=enqueue(&mut c,1,SOURCE);let mut executor=Executor::new(temp.attempt());
    let mut owner=FileWorkflowAttempt::open(&temp.attempt(),binding,None,&||true).unwrap();
    assert_eq!(c.execute_trusted_workflow_durable(&mut p,&mut executor,&mut journal,&mut owner,200,&||true).err(),Some(WorkflowAttemptRefusal::ReconciliationRequired));
    assert_eq!(executor.starts,0);let other=enqueue(&mut c,2,SOURCE);
    assert!(c.eligible_jobs(other.run_id()).unwrap().is_empty());
    assert!(c.obligations.workflow_scopes_opened>c.obligations.workflow_scopes_closed);
}

#[test]
fn completed_outcome_refuses_a_recreated_or_rolled_back_custody_journal() {
    let temp=Temp::new();let mut c=coordinator();let mut p=enqueue(&mut c,1,SOURCE);
    let binding=c.trusted_attempt_binding(&p,scope(),200).unwrap();
    let mut journal=FileCheckJournal::create(&temp.journal(),scope(),CheckJournalLimits::default()).unwrap();
    let mut owner=FileWorkflowAttempt::create(&temp.attempt(),binding).unwrap();let mut executor=Executor::new(temp.attempt());
    c.execute_trusted_workflow_durable(&mut p,&mut executor,&mut journal,&mut owner,200,&||true).unwrap();drop(journal);
    let mut empty=FileCheckJournal::create(&temp.0.join("recreated"),scope(),CheckJournalLimits::default()).unwrap();
    assert!(c.execute_trusted_workflow_durable(&mut p,&mut executor,&mut empty,&mut owner,200,&||true).is_err());
    assert_eq!(executor.starts,2);
}

#[test]
fn conservative_capacity_preflight_refuses_before_start_or_queue_acceptance() {
    let temp=Temp::new();let mut c=coordinator();let mut p=enqueue(&mut c,1,SOURCE);
    let binding=c.trusted_attempt_binding(&p,scope(),200).unwrap();
    let mut journal=FileCheckJournal::create(&temp.journal(),scope(),CheckJournalLimits{records:1,..CheckJournalLimits::default()}).unwrap();
    let mut owner=FileWorkflowAttempt::create(&temp.attempt(),binding).unwrap();let mut executor=Executor::new(temp.attempt());let pin=journal.pin();
    assert_eq!(c.execute_trusted_workflow_durable(&mut p,&mut executor,&mut journal,&mut owner,200,&||true).err(),Some(WorkflowAttemptRefusal::Custody(CheckDeliveryRefusal::JournalFull)));
    assert_eq!(owner.status(),WorkflowAttemptStatus::Prepared);assert_eq!(executor.starts,0);assert_eq!(journal.pin(),pin);
}

#[test]
fn executor_panic_leaves_durable_started_and_restart_never_reexecutes() {
    let temp=Temp::new();let mut c=coordinator();let mut p=enqueue(&mut c,1,SOURCE);
    let binding=c.trusted_attempt_binding(&p,scope(),200).unwrap();
    let mut journal=FileCheckJournal::create(&temp.journal(),scope(),CheckJournalLimits::default()).unwrap();
    let mut owner=FileWorkflowAttempt::create(&temp.attempt(),binding).unwrap();let mut executor=Executor::new(temp.attempt());executor.panic_step=true;
    assert!(c.execute_trusted_workflow_durable(&mut p,&mut executor,&mut journal,&mut owner,200,&||true).is_err());
    assert_eq!(owner.status(),WorkflowAttemptStatus::Started);assert_eq!(executor.starts,1);assert_eq!(executor.closes,1);
    drop(owner);drop(p);drop(c);
    let mut c=coordinator();let mut p=enqueue(&mut c,1,SOURCE);let mut executor=Executor::new(temp.attempt());
    let mut owner=FileWorkflowAttempt::open(&temp.attempt(),binding,None,&||true).unwrap();
    assert_eq!(c.execute_trusted_workflow_durable(&mut p,&mut executor,&mut journal,&mut owner,200,&||true).err(),Some(WorkflowAttemptRefusal::ReconciliationRequired));
    assert_eq!(executor.starts,0);
}

#[test]
fn retained_in_process_receipt_can_finish_started_without_reexecution() {
    let temp=Temp::new();let mut c=coordinator();let mut p=enqueue(&mut c,1,SOURCE);
    let binding=c.trusted_attempt_binding(&p,scope(),200).unwrap();
    let mut journal=FileCheckJournal::create(&temp.journal(),scope(),CheckJournalLimits::default()).unwrap();
    let mut owner=FileWorkflowAttempt::create(&temp.attempt(),binding).unwrap();owner.start(journal.pin()).unwrap();let mut executor=Executor::new(temp.attempt());
    c.execute_trusted_workflow_journaled(&mut p,&mut executor,&mut journal,200,&||true).unwrap();
    let receipt=c.execute_trusted_workflow_durable(&mut p,&mut executor,&mut journal,&mut owner,200,&||false).unwrap();
    assert_eq!(executor.starts,2);assert_eq!(receipt.frame(),p.receipt().unwrap().frame());assert_eq!(owner.status(),WorkflowAttemptStatus::Completed);
}

#[test]
fn recovered_retention_stays_an_unresolved_host_responsibility() {
    let temp=Temp::new();let mut c=coordinator();let mut p=enqueue(&mut c,1,SOURCE);
    let binding=c.trusted_attempt_binding(&p,scope(),200).unwrap();
    let mut journal=FileCheckJournal::create(&temp.journal(),scope(),CheckJournalLimits::default()).unwrap();
    let mut owner=FileWorkflowAttempt::create(&temp.attempt(),binding).unwrap();let mut executor=Executor::new(temp.attempt());executor.retain=true;
    assert!(c.execute_trusted_workflow_durable(&mut p,&mut executor,&mut journal,&mut owner,200,&||true).unwrap().requires_containment());
    drop(owner);drop(p);drop(c);
    let mut c=coordinator();let mut p=enqueue(&mut c,1,SOURCE);let mut executor=Executor::new(temp.attempt());
    let mut owner=FileWorkflowAttempt::open(&temp.attempt(),binding,None,&||true).unwrap();
    assert!(c.execute_trusted_workflow_durable(&mut p,&mut executor,&mut journal,&mut owner,200,&||true).unwrap().requires_containment());
    let other=enqueue(&mut c,2,SOURCE);assert!(c.eligible_jobs(other.run_id()).unwrap().is_empty());assert_eq!(executor.starts,0);
}

#[test]
fn checkpoint_ancestry_is_verified_even_after_later_downstream_acknowledgements() {
    let temp=Temp::new();let mut c=coordinator();let mut p=enqueue(&mut c,1,SOURCE);
    let binding=c.trusted_attempt_binding(&p,scope(),200).unwrap();
    let mut journal=FileCheckJournal::create(&temp.journal(),scope(),CheckJournalLimits::default()).unwrap();
    let mut owner=FileWorkflowAttempt::create(&temp.attempt(),binding).unwrap();let mut executor=Executor::new(temp.attempt());
    let receipt=c.execute_trusted_workflow_durable(&mut p,&mut executor,&mut journal,&mut owner,200,&||true).unwrap();
    while let Some(batch)=journal.next_batch().unwrap() {
        journal.record_delivery(CheckDeliveryAcknowledgement::after_durable_acceptance(&batch,Commitment::of_bytes(b"fixture-sink"))).unwrap();
    }
    assert!(journal.pin().byte_len()>receipt.journal_pin().byte_len());
    journal.verify_checkpoint(receipt.journal_pin()).unwrap();
    assert!(journal.verify_checkpoint(CheckJournalPin::new(receipt.journal_pin().byte_len(),Commitment::of_bytes(b"wrong-prefix"))).is_err());
}

#[test]
fn changed_actor_limits_source_or_logical_time_changes_the_attempt_binding() {
    let mut c=coordinator();let p=enqueue(&mut c,1,SOURCE);let original=c.trusted_attempt_binding(&p,scope(),200).unwrap();
    assert_ne!(original,c.trusted_attempt_binding(&p,scope(),201).unwrap());
    c.active_runs.get_mut(&p.run_id()).unwrap().trigger_ctx.actor="other".into();
    assert_ne!(original,c.trusted_attempt_binding(&p,scope(),200).unwrap());
    let mut c2=coordinator();let p2=enqueue(&mut c2,1,&format!("# different raw source\n{SOURCE}"));
    assert_ne!(original,c2.trusted_attempt_binding(&p2,scope(),200).unwrap());
    let mut c3=coordinator();
    let p3=c3.enqueue_trusted_workflow(scope().tenant,scope().repository,Commitment::of_bytes(b"head"),
        GitOid::Sha1(GitOidSha1::from_bytes([3;20])),WorkflowPlan::compile(SOURCE).unwrap(),
        WorkflowLimits{stream_bytes:256,total_output_bytes:1024,..WorkflowLimits::default()},
        TriggerContext::trusted_push("tester"),1,100).unwrap();
    assert_ne!(original,c3.trusted_attempt_binding(&p3,scope(),200).unwrap());
}

#[cfg(target_os="linux")]
#[test]
fn real_trusted_shell_side_effect_is_not_repeated_after_disk_reopen() {
    struct Process {directory:PathBuf,starts:usize}
    impl WorkflowExecutor for Process {
        fn begin_job(&mut self,_:usize,_:&fgit_schema::workflow::Job,_:&dyn Fn()->bool)->Result<(),WorkerFailure>{self.starts+=1;Ok(())}
        fn execute_step(&mut self,index:usize,script:&str,limits:StepLimits,live:&dyn Fn()->bool)->Result<StepObservation,WorkerFailure>{
            let open=|name:&str|OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(self.directory.join(format!("{name}-{index}"))).unwrap();
            crate::workflow::run_trusted_step(&self.directory,script,limits,&open("stdout"),&open("stderr"),live)
        }
        fn finish_job(&mut self,_:bool)->Result<(),WorkerFailure>{Ok(())}
    }
    let source="name: process\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf x >> marker\n      - run: printf x >> marker\n";
    let temp=Temp::new();let mut c=coordinator();let mut p=enqueue(&mut c,1,source);
    let binding=c.trusted_attempt_binding(&p,scope(),200).unwrap();
    let mut journal=FileCheckJournal::create(&temp.journal(),scope(),CheckJournalLimits::default()).unwrap();
    let mut owner=FileWorkflowAttempt::create(&temp.attempt(),binding).unwrap();let mut executor=Process{directory:temp.0.clone(),starts:0};
    c.execute_trusted_workflow_durable(&mut p,&mut executor,&mut journal,&mut owner,200,&||true).unwrap();
    assert_eq!(fs::read(temp.0.join("marker")).unwrap(),b"xx");drop(owner);drop(p);drop(c);drop(journal);
    let mut c=coordinator();let mut p=enqueue(&mut c,1,source);let mut executor=Process{directory:temp.0.clone(),starts:0};
    let mut journal=FileCheckJournal::open(&temp.journal(),scope(),CheckJournalLimits::default(),None,&||true).unwrap();
    let mut owner=FileWorkflowAttempt::open(&temp.attempt(),binding,None,&||true).unwrap();
    c.execute_trusted_workflow_durable(&mut p,&mut executor,&mut journal,&mut owner,200,&||true).unwrap();
    assert_eq!(executor.starts,0);assert_eq!(fs::read(temp.0.join("marker")).unwrap(),b"xx");
}

// Independently derived in Python, not by the Rust codec under test.
const HEADER_GOLDEN:[u8;32]=[0xd3,0xa1,0x40,0x30,0x69,0xa4,0xb5,0xfb,0x76,0xe8,0x5d,0x8e,0xc4,0x04,0x21,0x59,0x06,0xc1,0x1a,0xca,0x9b,0x7e,0x22,0xaf,0x1a,0x84,0x3d,0x74,0x17,0xb5,0xbc,0xe3];
const START_GOLDEN:[u8;32]=[0x33,0x82,0xc3,0x04,0x16,0x2a,0xe3,0xc0,0xce,0x2b,0xa2,0x06,0xa8,0x6d,0x2f,0x94,0x14,0x4e,0x3f,0xe5,0x2f,0xe7,0xd2,0x94,0x0b,0x59,0x70,0x90,0x34,0x2b,0xda,0x18];
