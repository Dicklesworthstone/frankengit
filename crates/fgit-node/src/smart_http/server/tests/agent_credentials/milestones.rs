#![forbid(unsafe_code)]
//! Sponsored milestone planning through real HTTP, canonical admission and restart.

use super::*;
use fgit_identity::agent::{MILESTONES_READ, MILESTONES_WRITE, OUTCOMES_READ};

const PLANNING: u16 =
    MILESTONES_READ | MILESTONES_WRITE | ISSUES_READ | ISSUES_WRITE | OUTCOMES_READ;
const OPEN: &str = "expected_version=0&title=Agent+release&body=Native+planning&due_at=0";

struct Fixture {
    selected: Profile,
    config: NodeConfig,
    grant: AgentCredentialGrant,
    planner: String,
    reader: String,
    writer: String,
    legacy: String,
    expired: String,
}

impl Fixture {
    fn new(root: &Scratch, format: GitHashAlgorithm) -> Self {
        let config = root.config("repository").with_object_format(format);
        let (mut node, _) = OneNode::init(config.clone()).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let config = config.with_expected_repository_incarnation(node.repository_incarnation_id());
        let now = crate::agent_credentials::epoch_seconds().unwrap();
        let grant = AgentCredentialGrant {
            agent: actor(2),
            sponsor: actor(1),
            sponsor_kind: SponsorKind::Human,
            tenant: TenantId::from_bytes([0xb1; 16]),
            repository: RepositoryId::from_bytes([0xb2; 16]),
            incarnation: node.repository_incarnation_id(),
            issued_at: now - 1,
            expires_at: now + 3600,
            operations: PLANNING,
        };
        let token = |digit: char| format!("fgagent_{}", digit.to_string().repeat(64));
        let planner = token('a');
        let reader = token('b');
        let writer = token('c');
        let legacy = token('d');
        let expired = token('e');
        for (bearer, issued, key) in [
            (planner.as_str(), grant, "milestone-planner"),
            (
                reader.as_str(),
                AgentCredentialGrant {
                    operations: MILESTONES_READ,
                    ..grant
                },
                "milestone-reader",
            ),
            (
                writer.as_str(),
                AgentCredentialGrant {
                    operations: MILESTONES_WRITE,
                    ..grant
                },
                "milestone-writer",
            ),
            // The complete former mask must not acquire the new operations.
            (
                legacy.as_str(),
                AgentCredentialGrant {
                    operations: 0x03ff,
                    ..grant
                },
                "milestone-legacy",
            ),
            (
                expired.as_str(),
                AgentCredentialGrant {
                    issued_at: now - 120,
                    expires_at: now - 60,
                    ..grant
                },
                "milestone-expired",
            ),
        ] {
            credential(
                &node,
                &AgentCredentialCommand {
                    id: agent_credential_id(bearer.as_bytes()).unwrap(),
                    expected_version: ExpectedVersion::NewStream,
                    action: AgentCredentialAction::Issue(issued),
                },
                grant.sponsor,
                key,
            );
        }
        let mut selected = profile();
        selected.route = node.git_daemon_repository_path().as_bytes().to_vec();
        selected.config = config.clone();
        // A broad ordinary-token collision must never rescue a revoked agent.
        selected.credentials = CredentialSource::Static {
            digest: sha256_digest(planner.as_bytes()),
            principal: actor(4),
        };
        selected.services = RepositoryHttpServices::NONE
            .with(RepositoryHttpService::Issues, true)
            .with(RepositoryHttpService::Outcomes, true);
        selected.maximum_response_bytes = 64 * 1024;
        selected.timeout = GitDaemonSessionTimeout::try_new(Duration::from_secs(60)).unwrap();
        selected.nodes = Arc::new(NodeLanes::new(
            config.clone(),
            1,
            "agent milestone HTTP test",
        ));
        node.shutdown().unwrap();
        Self {
            selected,
            config,
            grant,
            planner,
            reader,
            writer,
            legacy,
            expired,
        }
    }

    fn request(
        &self,
        token: &str,
        method: &str,
        suffix: &str,
        body: &str,
        key: Option<&str>,
    ) -> String {
        let route = std::str::from_utf8(&self.selected.route).unwrap();
        exchange(
            &self.selected,
            token,
            method,
            &format!("{route}{suffix}"),
            body,
            key,
        )
    }

    fn get(&self, token: &str, suffix: &str) -> String {
        self.request(token, "GET", suffix, "", None)
    }

    fn post(&self, token: &str, suffix: &str, body: &str, key: &str) -> String {
        self.request(token, "POST", suffix, body, Some(key))
    }
}

fn body(response: &str) -> &str {
    response.split_once("\r\n\r\n").unwrap().1
}

fn assert_counts(response: &str, open: u64, closed: u64) {
    status(response, 200);
    assert!(
        response.contains(&format!(
            "\"open_issues\":{open},\"closed_issues\":{closed}"
        )),
        "{response}"
    );
}

#[test]
fn sponsored_milestone_scopes_are_independent_and_expiry_and_service_ceiling_apply() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let fixture = Fixture::new(&root, format);
        let endpoint = "/api/v1/milestones/7/open";
        // Each forbidden operation has its permitted twin on the same native service.
        status(&fixture.get(&fixture.reader, "/api/v1/milestones"), 200);
        status(
            &fixture.post(&fixture.reader, endpoint, OPEN, "reader-cannot-open"),
            403,
        );
        committed(&fixture.post(&fixture.writer, endpoint, OPEN, "writer-opens"));
        status(&fixture.get(&fixture.writer, "/api/v1/milestones/7"), 403);
        let read = fixture.get(&fixture.reader, "/api/v1/milestones/7");
        assert_counts(&read, 0, 0);
        assert!(
            read.contains(&format!("\"opened_by\":\"{}\"", fixture.grant.agent)),
            "{read}"
        );
        for bearer in [&fixture.reader, &fixture.writer] {
            status(&fixture.get(bearer, "/api/v1/issues"), 403);
            status(
                &fixture.post(
                    bearer,
                    "/api/v1/issues/1/open",
                    "expected_version=0&title=No&body=No",
                    "milestone-not-issue",
                ),
                403,
            );
            status(
                &fixture.post(bearer, "/api/v1/outcomes", "", "writer-opens"),
                403,
            );
        }
        for (bearer, denied) in [(&fixture.legacy, 403), (&fixture.expired, 401)] {
            status(&fixture.get(bearer, "/api/v1/milestones"), denied);
            status(
                &fixture.post(bearer, "/api/v1/milestones/8/open", OPEN, "ungranted-open"),
                denied,
            );
        }
        // The former issue grant still serves its original API, not milestones.
        status(&fixture.get(&fixture.legacy, "/api/v1/issues"), 200);
        status(
            &fixture.request(
                &fixture.writer,
                "POST",
                "/api/v1/milestones/8/open",
                OPEN,
                None,
            ),
            400,
        );
        status(
            &fixture.post(
                &fixture.writer,
                "/api/v1/milestones/8/open",
                &format!("{OPEN}&principal={}", actor(1)),
                "cannot-spoof-sponsor",
            ),
            400,
        );

        let mut disabled = fixture.selected.clone();
        disabled.services =
            RepositoryHttpServices::NONE.with(RepositoryHttpService::Outcomes, true);
        let route = std::str::from_utf8(&disabled.route).unwrap();
        status(
            &exchange(
                &disabled,
                &fixture.reader,
                "GET",
                &format!("{route}/api/v1/milestones"),
                "",
                None,
            ),
            403,
        );
        status(
            &exchange(
                &disabled,
                &fixture.writer,
                "POST",
                &format!("{route}/api/v1/milestones/8/open"),
                OPEN,
                Some("disabled-open"),
            ),
            403,
        );
        status(&fixture.get(&fixture.reader, "/api/v1/milestones/7"), 200);
        let absent = fixture.get(&fixture.reader, "/api/v1/milestones/8");
        status(&absent, 404);
        assert!(absent.contains("\"found\":false"), "{absent}");
        fixture.selected.nodes.close().unwrap();
    }
}

#[test]
fn sponsored_milestone_planning_recovers_exact_outcomes_after_rotation_and_cold_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let mut fixture = Fixture::new(&root, format);
        let opening = fixture.post(
            &fixture.planner,
            "/api/v1/milestones/7/open",
            OPEN,
            "original-open",
        );
        committed(&opening);
        let outcome = fixture.post(&fixture.planner, "/api/v1/outcomes", "", "original-open");
        let provenance = original_provenance(&outcome).to_owned();
        for field in [
            "\"authentication\":\"agent_credential\"".to_owned(),
            format!("\"agent\":\"{}\"", fixture.grant.agent),
            format!("\"sponsor\":\"{}\"", fixture.grant.sponsor),
            format!(
                "\"credential_id\":\"{}\"",
                agent_credential_id(fixture.planner.as_bytes()).unwrap()
            ),
        ] {
            assert!(provenance.contains(&field), "missing {field}: {provenance}");
        }
        committed(&fixture.post(
            &fixture.planner,
            "/api/v1/issues/1/open",
            "expected_version=0&title=Implementation&body=Assigned+work",
            "planning-issue",
        ));
        committed(&fixture.post(
            &fixture.planner,
            "/api/v1/issues/1/set-milestone",
            "expected_version=1&milestone=7&expected_milestone_version=1",
            "planning-membership",
        ));
        let before = fixture.get(&fixture.reader, "/api/v1/milestones");
        assert_counts(&before, 1, 0);
        let pin = body(&before)
            .split_once("\"snapshot_token\":\"")
            .unwrap()
            .1
            .split('"')
            .next()
            .unwrap();
        committed(&fixture.post(
            &fixture.writer,
            "/api/v1/milestones/7/edit",
            "expected_version=1&title=Prepared+release&clear_due_at=true",
            "planning-edit",
        ));
        status(
            &fixture.post(
                &fixture.writer,
                "/api/v1/milestones/7/close",
                "expected_version=1",
                "stale-close",
            ),
            409,
        );
        committed(&fixture.post(
            &fixture.writer,
            "/api/v1/milestones/7/close",
            "expected_version=2",
            "planning-close",
        ));
        committed(&fixture.post(
            &fixture.writer,
            "/api/v1/milestones/7/reopen",
            "expected_version=3",
            "planning-reopen",
        ));
        committed(&fixture.post(
            &fixture.planner,
            "/api/v1/issues/1/close",
            "expected_version=2",
            "planning-complete",
        ));
        assert_counts(&fixture.get(&fixture.reader, "/api/v1/milestones/7"), 0, 1);
        assert_eq!(
            body(&fixture.get(
                &fixture.reader,
                &format!("/api/v1/milestones?expected_head={pin}")
            )),
            body(&before)
        );
        assert_eq!(
            body(&fixture.post(
                &fixture.planner,
                "/api/v1/milestones/7/open",
                OPEN,
                "original-open"
            )),
            body(&opening)
        );
        status(
            &fixture.post(
                &fixture.planner,
                "/api/v1/milestones/7/open",
                "expected_version=0&title=Substitution&body=No",
                "original-open",
            ),
            409,
        );

        // Live canonical revocation must be seen even by a retained node lane.
        let node = reopen(fixture.config.clone());
        credential(
            &node,
            &AgentCredentialCommand {
                id: agent_credential_id(fixture.planner.as_bytes()).unwrap(),
                expected_version: ExpectedVersion::Exactly(AggregateVersion::try_new(1).unwrap()),
                action: AgentCredentialAction::Revoke(fixture.grant),
            },
            fixture.grant.sponsor,
            "revoke-planner",
        );
        let rotated = format!("fgagent_{}", "f".repeat(64));
        credential(
            &node,
            &AgentCredentialCommand {
                id: agent_credential_id(rotated.as_bytes()).unwrap(),
                expected_version: ExpectedVersion::NewStream,
                action: AgentCredentialAction::Issue(fixture.grant),
            },
            fixture.grant.sponsor,
            "rotated-planner",
        );
        node.shutdown().unwrap();
        status(&fixture.get(&fixture.planner, "/api/v1/milestones/7"), 401);
        status(
            &fixture.post(
                &fixture.planner,
                "/api/v1/milestones/7/open",
                OPEN,
                "original-open",
            ),
            401,
        );
        let recovered = fixture.post(&rotated, "/api/v1/outcomes", "", "original-open");
        assert_eq!(original_provenance(&recovered), provenance);

        fixture.selected.nodes.close().unwrap();
        fixture.selected.nodes = Arc::new(NodeLanes::new(
            fixture.config.clone(),
            1,
            "cold agent milestone recovery",
        ));
        assert_eq!(
            body(&fixture.post(&rotated, "/api/v1/milestones/7/open", OPEN, "original-open")),
            body(&opening)
        );
        assert_eq!(
            original_provenance(&fixture.post(&rotated, "/api/v1/outcomes", "", "original-open")),
            provenance
        );
        let restored = fixture.get(&rotated, "/api/v1/milestones/7");
        assert_counts(&restored, 0, 1);
        for field in [
            "\"title\":\"Prepared release\"",
            "\"due_at\":null",
            "\"version\":4",
            "\"state\":\"open\"",
        ] {
            assert!(restored.contains(field), "missing {field}: {restored}");
        }
        fixture.selected.nodes.close().unwrap();
    }
}
