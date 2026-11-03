//! Actual catalog construction and protocol discovery without node effects.
use super::*;
use crate::mcp::protocol::Server;
use fgit_types::{GitHashAlgorithm, PrincipalId, RepositoryId, RepositoryIncarnationId, TenantId};

fn options() -> Options {
    Options {
        storage: std::path::PathBuf::new(),
        tenant: TenantId::from_bytes([1; 16]),
        repository: RepositoryId::from_bytes([2; 16]),
        format: GitHashAlgorithm::Sha1,
        incarnation: Some(RepositoryIncarnationId::from_bytes([3; 16])),
        issues: false,
        pulls: false,
        source: false,
        writes: Default::default(),
        queues: Default::default(),
        outcomes: false,
        principal: Some(PrincipalId::from_bytes([4; 16])),
        agent_context: false,
        artifacts: false,
        artifact_root: None,
        max_messages: 10,
    }
}
struct Catalog(Options);
impl ReadTools for Catalog {
    fn tools(&self) -> Vec<Tool> {
        let mut tools = tools_for_options(&self.0);
        tools.extend(protection::registered_tools());
        tools
    }
    fn call(&mut self, _: &str, _: &Object) -> Result<Value, ToolError> {
        panic!("discovery must never dispatch a native operation")
    }
    fn is_mutation(&self, name: &str) -> bool {
        fgit_schema::mcp::find_tool(name).unwrap().read_mutation
            == fgit_schema::mcp::ReadMutationClass::Mutation
    }
}

#[test]
fn every_active_native_tool_fits_one_bounded_protocol_discovery() {
    let mut full = options();
    full.issues = true;
    full.pulls = true;
    full.source = true;
    full.agent_context = true;
    full.artifacts = true;
    full.outcomes = true;
    full.writes = crate::mcp::WriteGrants {
        issues: true,
        notifications: true,
        pulls: true,
        source: true,
        reviews: true,
        merges: true,
    };
    full.queues = crate::mcp::QueueGrants {
        read: true,
        write: true,
        land: true,
    };
    let mut catalog = Catalog(full);
    let mut server = Server::new(&catalog).unwrap();
    let init=br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"catalog","version":"1"}}}"#;
    assert!(
        server
            .receive(&mut catalog, init)
            .unwrap()
            .object()
            .unwrap()
            .contains_key("result")
    );
    assert!(
        server
            .receive(
                &mut catalog,
                br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
            )
            .is_none()
    );
    let reply = server
        .receive(
            &mut catalog,
            br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        )
        .unwrap();
    let Value::Array(tools) = &reply.object().unwrap()["result"].object().unwrap()["tools"] else {
        panic!("missing discovery")
    };
    assert_eq!(tools.len(), 75);
    let names: std::collections::BTreeSet<_> = tools
        .iter()
        .map(|tool| tool.object().unwrap()["name"].text().unwrap())
        .collect();
    assert_eq!(names, all_registered_tool_names().into_iter().collect());
    for tool in tools {
        let fields = tool.object().unwrap();
        let name = fields["name"].text().unwrap();
        if milestones::is_write(name)
            || notifications::is_write(name)
            || matches!(
                name,
                "frankengit_issue_set_milestone" | "frankengit_issue_clear_milestone"
            )
        {
            assert_eq!(
                fields["annotations"].object().unwrap()["readOnlyHint"],
                Value::Bool(false)
            );
        }
    }
    assert!(reply.encode(crate::mcp::protocol::MAX_RESPONSE).is_ok());
}

#[test]
fn milestone_catalog_reuses_only_each_explicit_issue_grant_and_declares_exact_fields() {
    for read in [false, true] {
        for write in [false, true] {
            let mut launch = options();
            launch.issues = read;
            launch.writes.issues = write;
            // Adjacent capabilities do not imply issue/milestone access.
            launch.source = true;
            launch.pulls = true;
            launch.writes.pulls = true;
            launch.outcomes = true;
            let tools = tools_for_options(&launch);
            for name in ["frankengit_milestone_list", "frankengit_milestone_show"] {
                assert_eq!(tools.iter().any(|tool| tool.name == name), read);
            }
            for name in [
                "frankengit_milestone_open",
                "frankengit_milestone_edit",
                "frankengit_milestone_close",
                "frankengit_milestone_reopen",
                "frankengit_issue_set_milestone",
                "frankengit_issue_clear_milestone",
            ] {
                assert_eq!(tools.iter().any(|tool| tool.name == name), write);
            }
            for tool in tools
                .into_iter()
                .filter(|tool| milestones::is_read(tool.name) || milestones::is_write(tool.name))
            {
                let declared: std::collections::BTreeSet<_> =
                    fgit_schema::mcp::find_tool(tool.name)
                        .unwrap()
                        .input_fields
                        .iter()
                        .map(|field| field.name)
                        .collect();
                let schema = tool.schema.object().unwrap();
                let served: std::collections::BTreeSet<_> = schema["properties"]
                    .object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect();
                assert_eq!(served, declared);
                assert_eq!(schema["additionalProperties"], Value::Bool(false));
            }
        }
    }
}
