use super::*;
use crate::{AdmissionInput, AdmissionLimits, RefUpdateView, ValidatedClosure, plan_session};
use fgit_authority::{HeadKey, IdempotencyKey, RefCommand};
use fgit_types::{GitHashAlgorithm, GitOid, PrincipalId, RepositoryId, TenantId};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Fixture {
    context: AdmissionContext,
    names: Vec<Vec<u8>>,
    options: Vec<Vec<u8>>,
    closure: ValidatedClosure,
}
impl Fixture {
    fn new(format: GitHashAlgorithm, count: usize) -> Self {
        let objects =
            BTreeSet::from([
                GitOid::from_hex(format, &"1".repeat(format.digest_len() * 2)).unwrap(),
            ]);
        Self {
            context: AdmissionContext {
                head_key: HeadKey::new(b"fg/head/large-session".to_vec()).unwrap(),
                tenant_id: TenantId::from_bytes([1; 16]),
                repository_id: RepositoryId::from_bytes([2; 16]),
                principal_id: PrincipalId::from_bytes([3; 16]),
                idempotency_key: IdempotencyKey::new(b"original\0binary\xffkey".to_vec()).unwrap(),
                object_format: format,
            },
            names: (0..count)
                .rev()
                .map(|n| format!("refs/tags/t{n:05}").into_bytes())
                .collect(),
            options: vec![b"ordered-option".to_vec()],
            closure: ValidatedClosure {
                object_closure_root: crate::permitted_object_closure_root(
                    &crate::PermittedObjectClosure::new(objects.clone()),
                )
                .unwrap(),
                objects,
            },
        }
    }
    fn input(&self, atomic: bool) -> AdmissionInput<'_> {
        let format = self.context.object_format;
        let zero = GitOid::from_hex(format, &"0".repeat(format.digest_len() * 2)).unwrap();
        let oid = *self.closure.objects.first().unwrap();
        AdmissionInput {
            updates: self
                .names
                .iter()
                .map(|name| RefUpdateView {
                    old: zero,
                    new: oid,
                    ref_name: name,
                })
                .collect(),
            push_options: &self.options,
            object_format: format,
            atomic,
            deletes_only: false,
            declared_delete_only: false,
            delete_only_label: "large fixture",
            closure: &self.closure,
            validation_basis: None,
        }
    }
    fn plan(&self, atomic: bool) -> Result<SessionPlan, AdmissionError> {
        plan_session(
            &self.context,
            &self.input(atomic),
            AdmissionLimits::default(),
        )
    }
    fn descriptor(&self) -> Descriptor {
        Descriptor::from_plan(&self.context, &self.plan(false).unwrap(), &|| Ok(())).unwrap()
    }
}

fn unchecked_bytes(value: &Descriptor) -> Vec<u8> {
    let mut out = Encoder::new();
    out.write_scalar(VERSION);
    let chunks: Vec<_> = value
        .chunks
        .iter()
        .map(|chunk| encode_body(chunk).unwrap())
        .collect();
    out.write_sequence("chunks", &chunks, |out, bytes| {
        out.write_bytes("chunk", bytes)
    })
    .unwrap();
    let indices: Vec<_> = value.wire_order.iter().map(|n| *n as u16).collect();
    out.write_sequence("order", &indices, |out, index| {
        out.write_scalar(*index);
        Ok(())
    })
    .unwrap();
    out.into_bytes()
}

#[test]
fn boundary_shapes_keep_atomic_cap_v1_bytes_and_all_large_child_identities() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for count in [
            MAX_ADMISSION_COMMANDS,
            MAX_ADMISSION_COMMANDS + 1,
            MAX_RECEIVE_SESSION_COMMANDS,
        ] {
            let fixture = Fixture::new(format, count);
            let plan = fixture.plan(false).unwrap();
            let prepared = super::super::prepare_session(
                &fixture.context,
                &fixture.input(false),
                &plan,
                &|| Ok(()),
            )
            .unwrap();
            let decoded =
                super::super::SessionDescriptor::decode(&prepared.bytes, &|| Ok(())).unwrap();
            assert_eq!(decoded.len(), count);
            assert_eq!(
                decoded.whole_attempt(&fixture.context, &|| Ok(())).unwrap(),
                prepared.whole
            );
            if count == MAX_ADMISSION_COMMANDS {
                assert!(fixture.plan(true).is_ok());
                let request = SemanticRequest::build(
                    fgit_authority::RECEIVE_ADMISSION_SCHEMA,
                    format,
                    false,
                    fixture
                        .input(false)
                        .updates
                        .iter()
                        .map(|u| crate::lower_ref_update(u.old, u.new, u.ref_name).unwrap())
                        .collect(),
                    fixture
                        .options
                        .iter()
                        .cloned()
                        .map(PushOption::new)
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap(),
                    Vec::new(),
                )
                .unwrap();
                let legacy = super::super::Descriptor {
                    request: request.clone(),
                    wire_order: (0..count).rev().collect(),
                };
                assert_eq!(
                    prepared.bytes,
                    legacy.encode().unwrap(),
                    "legacy carrier bytes are unchanged"
                );
                assert_eq!(
                    prepared.whole.request, request,
                    "legacy binding identity is unchanged"
                );
            } else {
                assert!(
                    matches!(fixture.plan(true), Err(AdmissionError::CommandLimitExceeded { limit }) if limit == MAX_ADMISSION_COMMANDS)
                );
                assert_eq!(prepared.whole.request.request_schema(), BINDING_SCHEMA);
                assert!(prepared.whole.request.ref_commands().is_empty());
                assert!(prepared.whole.request.scoped_entries().len() <= 13);
                assert!(
                    prepared
                        .whole
                        .request
                        .scoped_entries()
                        .iter()
                        .all(|entry| entry.value.len() <= fgit_authority::MAX_SCOPED_VALUE_BYTES)
                );
                assert!(matches!(
                    &decoded,
                    super::super::SessionDescriptor::Large(_)
                ));
            }
            for index in [0, 1, MAX_ADMISSION_COMMANDS - 1, count - 1] {
                let child = decoded.child_attempt(&fixture.context, index).unwrap();
                assert_eq!(child, seal_attempt(&fixture.context, &plan.lowered[index]));
                assert_eq!(child.derive().unwrap().0, plan.tx_ids[index]);
                assert_eq!(
                    child.request.ref_commands()[0].name.as_bytes(),
                    fixture.names[index]
                );
            }
        }
        let over = Fixture::new(format, MAX_RECEIVE_SESSION_COMMANDS + 1);
        assert!(
            matches!(over.plan(false), Err(AdmissionError::CommandLimitExceeded { limit }) if limit == MAX_RECEIVE_SESSION_COMMANDS)
        );
    }
    let narrowed = AdmissionLimits {
        max_commands: 7,
        ..AdmissionLimits::default()
    };
    assert_eq!(narrowed.command_limit(true), 7);
    assert_eq!(narrowed.command_limit(false), 7);
}

#[test]
fn canonical_chunk_and_wire_order_validation_refuse_hostile_carriers() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256, MAX_ADMISSION_COMMANDS + 1);
    let descriptor = fixture.descriptor();
    let bytes = descriptor.encode(&|| Ok(())).unwrap();
    for cut in [0, 3, 4, 7, 11, bytes.len() / 2, bytes.len() - 1] {
        assert!(Descriptor::decode(&bytes[..cut], &|| Ok(())).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(Descriptor::decode(&trailing, &|| Ok(())).is_err());
    let mut unknown = bytes.clone();
    unknown[3] = 99;
    assert!(super::super::SessionDescriptor::decode(&unknown, &|| Ok(())).is_err());
    for mutate in 0..6 {
        let mut value = Descriptor::decode(&bytes, &|| Ok(())).unwrap();
        match mutate {
            0 => value.wire_order[0] = value.wire_order[1],
            1 => value.wire_order[0] = value.len(),
            2 => {
                value.wire_order.pop();
            }
            3 => value.chunks.swap(0, 1),
            4 => {
                let repeated = value.chunks[0].ref_commands().last().unwrap().clone();
                value.chunks[1] = SemanticRequest::build(
                    fgit_authority::RECEIVE_ADMISSION_SCHEMA,
                    fixture.context.object_format,
                    false,
                    vec![repeated],
                    value.chunks[0].push_options().to_vec(),
                    Vec::new(),
                )
                .unwrap();
            }
            _ => {
                value.chunks[1] = SemanticRequest::build(
                    fgit_authority::RECEIVE_ADMISSION_SCHEMA,
                    fixture.context.object_format,
                    false,
                    value.chunks[1].ref_commands().to_vec(),
                    Vec::new(),
                    Vec::new(),
                )
                .unwrap();
            }
        }
        assert!(
            Descriptor::decode(&unchecked_bytes(&value), &|| Ok(())).is_err(),
            "mutation {mutate}"
        );
    }
    let one_chunk = Fixture::new(GitHashAlgorithm::Sha1, MAX_ADMISSION_COMMANDS);
    assert!(
        Descriptor::from_plan(&one_chunk.context, &one_chunk.plan(false).unwrap(), &|| Ok(
            ()
        ))
        .is_err(),
        "v2 cannot shadow v1"
    );
}

#[test]
fn changing_chunks_options_or_wire_order_changes_the_original_key_binding() {
    let mut fixture = Fixture::new(GitHashAlgorithm::Sha1, MAX_ADMISSION_COMMANDS + 1);
    let original = fixture
        .descriptor()
        .whole_attempt(&fixture.context, &|| Ok(()))
        .unwrap()
        .derive()
        .unwrap()
        .0;
    fixture.names.swap(0, 1);
    let reordered = fixture
        .descriptor()
        .whole_attempt(&fixture.context, &|| Ok(()))
        .unwrap()
        .derive()
        .unwrap()
        .0;
    assert_ne!(original, reordered);
    fixture.names.swap(0, 1);
    fixture.options.push(b"second-option".to_vec());
    let options = fixture
        .descriptor()
        .whole_attempt(&fixture.context, &|| Ok(()))
        .unwrap()
        .derive()
        .unwrap()
        .0;
    assert_ne!(original, options);
    fixture.options.pop();
    let mut descriptor = fixture.descriptor();
    let changed = RefCommand {
        proposed_new: ProposedNew::Delete,
        ..descriptor.chunks[0].ref_commands()[0].clone()
    };
    let mut commands = descriptor.chunks[0].ref_commands().to_vec();
    commands[0] = changed;
    descriptor.chunks[0] = SemanticRequest::build(
        fgit_authority::RECEIVE_ADMISSION_SCHEMA,
        fixture.context.object_format,
        false,
        commands,
        descriptor.chunks[0].push_options().to_vec(),
        Vec::new(),
    )
    .unwrap();
    let changed_body = descriptor
        .whole_attempt(&fixture.context, &|| Ok(()))
        .unwrap()
        .derive()
        .unwrap()
        .0;
    assert_ne!(
        original, changed_body,
        "the session binding covers each canonical chunk digest"
    );
}

#[test]
fn exact_large_descriptor_byte_boundary_has_a_one_byte_refused_twin() {
    let mut fixture = Fixture::new(GitHashAlgorithm::Sha256, MAX_RECEIVE_SESSION_COMMANDS);
    let base = fixture.descriptor().encode(&|| Ok(())).unwrap().len();
    let remaining = MAX_BYTES - base;
    for (index, name) in fixture.names.iter_mut().enumerate() {
        name.extend(std::iter::repeat_n(
            b'x',
            remaining / MAX_RECEIVE_SESSION_COMMANDS
                + usize::from(index < remaining % MAX_RECEIVE_SESSION_COMMANDS),
        ));
    }
    let descriptor = fixture.descriptor();
    let bytes = descriptor.encode(&|| Ok(())).unwrap();
    assert_eq!(bytes.len(), MAX_BYTES);
    assert_eq!(
        Descriptor::decode(&bytes, &|| Ok(())).unwrap().len(),
        MAX_RECEIVE_SESSION_COMMANDS
    );
    fixture.names[0].push(b'x');
    assert!(
        matches!(fixture.descriptor().encode(&|| Ok(())), Err(AdmissionError::SessionDescriptorBytesExceeded { limit: MAX_BYTES, observed }) if observed == MAX_BYTES + 1)
    );
}

#[test]
fn cancellation_interrupts_large_preflight_and_recovery_cpu_loops() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1, MAX_ADMISSION_COMMANDS + 1);
    let plan = fixture.plan(false).unwrap();
    let probes = AtomicUsize::new(0);
    let stop = || {
        if probes.fetch_add(1, Ordering::SeqCst) >= 31 {
            Err(RefusalCode::CancellationInProgress)
        } else {
            Ok(())
        }
    };
    assert!(matches!(
        Descriptor::from_plan(&fixture.context, &plan, &stop),
        Err(AdmissionError::AsyncProjectionUnavailable(
            RefusalCode::CancellationInProgress
        ))
    ));
    let bytes = fixture.descriptor().encode(&|| Ok(())).unwrap();
    probes.store(0, Ordering::SeqCst);
    assert!(matches!(
        Descriptor::decode(&bytes, &stop),
        Err(AdmissionError::AsyncProjectionUnavailable(
            RefusalCode::CancellationInProgress
        ))
    ));
    assert_eq!(probes.load(Ordering::SeqCst), 32);
}

#[test]
fn decoded_empty_options_cannot_bypass_the_repeated_header_budget() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1, MAX_RECEIVE_SESSION_COMMANDS);
    let mut descriptor = fixture.descriptor();
    let allowed =
        MAX_SESSION_OPTION_COPY_BYTES / (MAX_RECEIVE_SESSION_COMMANDS * size_of::<PushOption>());
    for count in [allowed, allowed + 1] {
        for chunk in &mut descriptor.chunks {
            *chunk = SemanticRequest::build(
                fgit_authority::RECEIVE_ADMISSION_SCHEMA,
                fixture.context.object_format,
                false,
                chunk.ref_commands().to_vec(),
                vec![PushOption::new(Vec::new()).unwrap(); count],
                Vec::new(),
            )
            .unwrap();
        }
        let decoded = Descriptor::decode(&unchecked_bytes(&descriptor), &|| Ok(()));
        if count == allowed {
            assert!(decoded.is_ok());
        } else {
            assert!(
                matches!(decoded, Err(AdmissionError::PushOptionWorkExceeded { limit, observed }) if limit == MAX_SESSION_OPTION_COPY_BYTES && observed > limit)
            );
        }
    }
}
