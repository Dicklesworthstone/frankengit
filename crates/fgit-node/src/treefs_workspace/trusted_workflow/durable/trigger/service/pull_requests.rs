//! One native controller owns a bounded, durable collection of native PR
//! watchers. Discovery can add responsibility; closure/visibility never erases
//! it. Each child still selects canonical work and publishes through admission.
use super::super::{cancellation, commitment, prestart, pull_request, reporting};
use super::{
    Custody, WorkflowWatchConfig, WorkflowWatchControl, WorkflowWatchError, WorkflowWatchReceipt,
    attempt, controlled_operation, publish,
};
use crate::treefs_workspace::pull_request::PullRequestReadRefusal;
use crate::{NodeRequestContext, OneNode};
use fgit_forge::event::pull_request::PullRequestAction;
use fgit_forge::{AggregateId, ForgeEventPayload};
use fgit_types::{RefName, RepositoryAuthorityHeadId};
use fgit_wire::visibility::RefVisibility;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt;

mod inventory;
use inventory::{Entry, Inventory};
const MAX_DISCOVERY_PAGES: usize = 10;
const PAGE_SIZE: u16 = 100;

enum Discovery {
    Complete(BTreeMap<u64, RefName>),
    Moved,
}

pub(super) fn checkpoint(live: &dyn Fn() -> bool) -> Result<(), WorkflowWatchError> {
    if live() {
        Ok(())
    } else {
        Err(WorkflowWatchError::CollectionSelectionStopped)
    }
}
fn custody(error: impl ToString) -> WorkflowWatchError {
    WorkflowWatchError::Custody(error.to_string())
}
fn selection(error: impl ToString) -> WorkflowWatchError {
    WorkflowWatchError::Attempt(format!("PR collection discovery: {}", error.to_string()))
}

struct Member {
    config: WorkflowWatchConfig,
    custody: Custody,
    receipt: WorkflowWatchReceipt,
}
pub(super) struct Controller {
    inventory: Inventory,
    members: BTreeMap<u64, Member>,
    after: u64,
}

impl Controller {
    pub(super) fn open(
        node: &OneNode,
        config: &WorkflowWatchConfig,
        control: &WorkflowWatchControl,
        receipt: &mut WorkflowWatchReceipt,
    ) -> Result<Self, WorkflowWatchError> {
        let mut controller = None;
        let result = controlled_operation(node, config, control, |request| {
            let live = || !control.is_stopped() && request.checkpoint_is_live();
            checkpoint(&live)?;
            let scope = scope(node, config);
            let inventory = Inventory::open(
                &config.run_parent,
                scope,
                binding(config, &scope),
                config
                    .pull_requests
                    .ok_or_else(|| custody("missing collection member bound"))?,
                &live,
            )?;
            controller = Some(Self {
                inventory,
                members: BTreeMap::new(),
                after: 0,
            });
            let owner = controller.as_mut().expect("inventory opened");
            owner.reconcile_members(node, config, control, request)?;
            // Ordinary canonical writes may race readiness. Retry only inside
            // this same finite request and its total ten-page scan allowance.
            let mut pages = MAX_DISCOVERY_PAGES;
            while !owner.discover(node, config, control, request, &mut pages)? {}
            Ok(())
        });
        if let Some(owner) = &controller {
            owner.aggregate(receipt)?;
        }
        match result {
            Err(WorkflowWatchError::CollectionSelectionStopped) if control.is_stopped() => {
                Err(WorkflowWatchError::StoppedBeforeReadiness)
            }
            Err(error) => Err(error),
            Ok(()) => controller.ok_or_else(|| custody("collection did not establish ownership")),
        }
    }

    pub(super) fn poll(
        &mut self,
        node: &OneNode,
        config: &WorkflowWatchConfig,
        control: &WorkflowWatchControl,
        receipt: &mut WorkflowWatchReceipt,
    ) -> Result<(), WorkflowWatchError> {
        let result = controlled_operation(node, config, control, |request| {
            // Full retained-member validation/publication precedes ALL new
            // admission, even when the next selected PR is unrelated.
            self.reconcile_members(node, config, control, request)?;
            let mut pages = MAX_DISCOVERY_PAGES;
            if !self.discover(node, config, control, request, &mut pages)? {
                // A moved snapshot authorizes no additions or dispatch. A
                // later normal poll gets a fresh, still bounded attempt.
                return Ok(());
            }
            let live = || !control.is_stopped() && request.checkpoint_is_live();
            checkpoint(&live)?;
            let next = self
                .members
                .keys()
                .copied()
                .find(|number| *number > self.after)
                .or_else(|| self.members.keys().next().copied());
            let Some(next) = next else {
                return Ok(());
            };
            let member = self
                .members
                .get_mut(&next)
                .expect("selected retained member");
            member.custody.check()?;
            self.after = next;
            attempt(
                node,
                request,
                &member.config,
                control,
                &mut member.receipt,
                true,
            )
        });
        self.aggregate(receipt)?;
        match result {
            Err(
                WorkflowWatchError::CollectionSelectionStopped
                | WorkflowWatchError::StoppedBeforeReadiness,
            ) if control.is_stopped() => Ok(()),
            result => result,
        }
    }

    fn reconcile_members(
        &mut self,
        node: &OneNode,
        config: &WorkflowWatchConfig,
        control: &WorkflowWatchControl,
        request: &NodeRequestContext,
    ) -> Result<(), WorkflowWatchError> {
        let live = || !control.is_stopped() && request.checkpoint_is_live();
        self.inventory.check(&live)?;
        let mut entries = self.inventory.entries().to_vec();
        for entry in &mut entries {
            checkpoint(&live)?;
            if !self.members.contains_key(&entry.number) {
                let child = member_config(config, entry);
                if entry.initialized {
                    require_original_custody(node, &child)?;
                }
                let owned = Custody::open_in(node, &child, control, request)?;
                self.members.insert(
                    entry.number,
                    Member {
                        config: child,
                        custody: owned,
                        receipt: WorkflowWatchReceipt::default(),
                    },
                );
            } else {
                let member = self
                    .members
                    .get_mut(&entry.number)
                    .expect("retained member");
                member
                    .custody
                    .reconcile_execution(node, &member.config, control, request)?;
            }
            let member = self.members.get_mut(&entry.number).expect("opened member");
            member.receipt.pending_execution = member.custody.pending_execution;
            if publish(node, request, &member.config, &mut member.receipt)? {
                return Err(WorkflowWatchError::CollectionSelectionStopped);
            }
            if member.receipt.requires_reconciliation {
                return Err(custody(
                    "a retained PR requires reconciliation; no later member admitted",
                ));
            }
            entry.initialized = true;
        }
        // A crash before this sync leaves explicit pending members. Native
        // custody must be checked again; no script started under that phase.
        self.inventory.replace(entries, &live)?;
        self.inventory.check(&live)
    }

    fn discover(
        &mut self,
        node: &OneNode,
        config: &WorkflowWatchConfig,
        control: &WorkflowWatchControl,
        request: &NodeRequestContext,
        pages: &mut usize,
    ) -> Result<bool, WorkflowWatchError> {
        let live = || !control.is_stopped() && request.checkpoint_is_live();
        let selected = match discover(node, request, config, pages, &live)? {
            Discovery::Complete(selected) => selected,
            Discovery::Moved => return Ok(false),
        };
        let mut entries = self.inventory.entries().to_vec();
        for (number, reference) in selected {
            if let Some(existing) = entries.iter().find(|row| row.number == number) {
                if existing.reference != reference {
                    return Err(custody(
                        "canonical PR source differs from retained membership",
                    ));
                }
            } else {
                entries.push(Entry {
                    number,
                    reference,
                    initialized: false,
                });
            }
        }
        entries.sort_by_key(|entry| entry.number);
        if entries.len() > config.pull_requests.expect("collection configuration") {
            return Err(custody(
                "PR collection retained member limit exceeded; no new member admitted",
            ));
        }
        checkpoint(&live)?;
        if entries == self.inventory.entries() {
            return Ok(true);
        }
        // Complete discovery and current-head verification have succeeded.
        // The complete set becomes durable BEFORE opening any new child.
        self.inventory.replace(entries, &live)?;
        self.reconcile_members(node, config, control, request)?;
        Ok(true)
    }

    fn aggregate(&self, receipt: &mut WorkflowWatchReceipt) -> Result<(), WorkflowWatchError> {
        let mut total = WorkflowWatchReceipt::default();
        for member in self.members.values() {
            let row = &member.receipt;
            for (sum, value) in [
                (&mut total.polls, row.polls),
                (&mut total.dispatched, row.dispatched),
                (&mut total.checks_committed, row.checks_committed),
                (&mut total.checks_refused, row.checks_refused),
                (&mut total.pending_execution, row.pending_execution),
            ] {
                *sum = sum
                    .checked_add(value)
                    .ok_or_else(|| selection("collection observation counter exhausted"))?;
            }
            total.non_green |= row.non_green;
            total.interrupted |= row.interrupted;
            total.requires_reconciliation |= row.requires_reconciliation;
            total.publication_pending |= row.publication_pending;
        }
        // Each member retains its own pending flags; another member's complete
        // scan can never clear responsibility it has not inspected.
        *receipt = total;
        Ok(())
    }
}

fn member_config(config: &WorkflowWatchConfig, entry: &Entry) -> WorkflowWatchConfig {
    let mut child = config.clone();
    child.pull_requests = None;
    child.pull_request = Some(entry.number);
    child.reference = entry.reference.clone();
    child
}
fn scope(node: &OneNode, config: &WorkflowWatchConfig) -> [u8; 32] {
    commitment(&[
        b"frankengit/pull-request-workflow-collection/v1",
        &reporting::scope(node, &config.reference, &config.directory),
        config.format.as_str().as_bytes(),
    ])
}
fn binding(config: &WorkflowWatchConfig, scope: &[u8; 32]) -> [u8; 32] {
    let publisher = config.publisher.map(|value| *value.as_bytes());
    commitment(&[
        b"frankengit/pull-request-workflow-collection-config/v1",
        scope,
        &prestart::execution_identity(
            &config.directory,
            &config.inputs,
            config.limits,
            config.artifacts.as_ref(),
        ),
        &[u8::from(publisher.is_some())],
        publisher.as_ref().map_or(&[][..], |value| &value[..]),
    ])
}
fn require_original_custody(
    node: &OneNode,
    config: &WorkflowWatchConfig,
) -> Result<(), WorkflowWatchError> {
    let scope = pull_request::scope(
        node,
        &config.reference,
        &config.directory,
        config.pull_request.expect("member PR"),
    );
    for prefix in ["service", "watch"] {
        let root = config
            .run_parent
            .join(format!("{prefix}-{}", super::super::hex(&scope)));
        super::super::check_directory(&root).map_err(custody)?;
        let lock = fs::symlink_metadata(root.join("owner.lock")).map_err(custody)?;
        if !lock.is_file() || lock.mode() & 0o777 != 0o600 || lock.nlink() != 1 {
            return Err(custody(
                "initialized PR member lost its original custody owner",
            ));
        }
    }
    Ok(())
}

fn discover(
    node: &OneNode,
    request: &NodeRequestContext,
    config: &WorkflowWatchConfig,
    pages: &mut usize,
    live: &dyn Fn() -> bool,
) -> Result<Discovery, WorkflowWatchError> {
    let mut selected = BTreeMap::new();
    let mut head: Option<RepositoryAuthorityHeadId> = None;
    let mut after = 0;
    loop {
        checkpoint(live)?;
        *pages = pages
            .checked_sub(1)
            .ok_or_else(|| selection("complete discovery page/row budget exhausted"))?;
        let page = match node.runtime().block_on(node.read_pull_requests_in(
            request,
            &RefVisibility::new(),
            after,
            PAGE_SIZE,
            head,
        )) {
            Ok(page) => page,
            Err(PullRequestReadRefusal::SnapshotMoved) => return Ok(Discovery::Moved),
            Err(error) if cancellation::pull_request_read(&error) => {
                return Err(WorkflowWatchError::CollectionSelectionStopped);
            }
            Err(error) => return Err(selection(error)),
        };
        checkpoint(live)?;
        if page.pull_requests.len() > usize::from(PAGE_SIZE)
            || head.is_some_and(|head| head != page.source_head)
        {
            return Err(selection("inconsistent snapshot page"));
        }
        head = Some(page.source_head);
        let mut previous = after;
        for row in &page.pull_requests {
            checkpoint(live)?;
            if row.number.get() <= previous
                || row.event.aggregate != AggregateId::PullRequest(row.number)
            {
                return Err(selection("invalid PR order or aggregate"));
            }
            previous = row.number.get();
            let ForgeEventPayload::PullRequestChangedNative(change) = &row.event.payload else {
                continue;
            };
            if change.action == PullRequestAction::Close
                || change.data.target_ref != config.reference
            {
                continue;
            }
            if selected
                .insert(row.number.get(), change.data.source_ref.clone())
                .is_some()
            {
                return Err(selection("duplicate PR"));
            }
            if selected.len() > config.pull_requests.expect("collection configuration") {
                return Err(selection(
                    "open PR population exceeds retained member bound",
                ));
            }
        }
        if let Some(next) = page.next_after {
            if page.pull_requests.len() != usize::from(PAGE_SIZE)
                || next != previous
                || next <= after
                || *pages == 0
            {
                return Err(selection(
                    "complete discovery page/row budget exceeded or invalid cursor",
                ));
            }
            after = next;
        } else {
            checkpoint(live)?;
            let current = node
                .runtime()
                .block_on(node.materialize_admission_in(request))
                .map_err(|error| {
                    if cancellation::materialization(&error) {
                        WorkflowWatchError::CollectionSelectionStopped
                    } else {
                        selection(error)
                    }
                })?;
            checkpoint(live)?;
            if Some(current.basis().id()) != head {
                return Ok(Discovery::Moved);
            }
            return Ok(Discovery::Complete(selected));
        }
    }
}

#[cfg(test)]
mod tests;
