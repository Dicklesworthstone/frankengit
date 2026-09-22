#![forbid(unsafe_code)]
//! Native byte-regex source queries through imported SHA-1/SHA-256 objects,
//! embedded authority, scoped TreeFS reads, authenticated HTTP and reopen.
#[path = "source_http/support.rs"]
mod support;
use fgit_authority::{IdempotencyKey, key_recovery::RequestRecovery};
use fgit_crypto::{GitHashAlgorithm as Algorithm, GitObjectKind, Sha1, Sha256, git_object_id};
use fgit_forge::source_search::regex::{MAX_REGEX_STEPS, RegexQuery, RegexSearchReport};
use fgit_forge::source_search::{SearchCase, SearchCompletion, SearchError, SearchLimits};
use fgit_node::{LoopbackReceiveSession, NodeWorkspaceRefusal, OneNode};
use fgit_treefs::{TreeCapability, TreePath, WorkspaceId};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, RefName, RepositoryId};
use fgit_wire::visibility::RefVisibility;
use std::{fs, path::Path};
use support::*;

fn reference() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}
fn query(pattern: &[u8], case: SearchCase, paths: &[Vec<u8>]) -> RegexQuery {
    RegexQuery::new(pattern, case, paths, MAX_REGEX_STEPS).unwrap()
}
fn local(
    node: &OneNode,
    query: &RegexQuery,
    limits: SearchLimits,
) -> Result<RegexSearchReport, NodeWorkspaceRefusal> {
    node.runtime()
        .block_on(node.search_source_regex_snapshot_local_in(
            &node.request_context(),
            &reference(),
            None,
            None,
            query,
            limits,
        ))
        .map(|(_, report)| report)
}
fn scoped<A: Algorithm>(
    node: &OneNode,
    cap: &mut TreeCapability,
    visibility: &RefVisibility,
) -> Result<RegexSearchReport, NodeWorkspaceRefusal> {
    node.runtime().block_on(node.search_source_regex_in::<A>(
        &node.request_context(),
        &reference(),
        visibility,
        cap,
        0,
        &query(br"\bneedle\b", SearchCase::AsciiInsensitive, &[]),
        SearchLimits::default(),
    ))
}
fn cap(repository: RepositoryId) -> TreeCapability {
    TreeCapability::new(
        WorkspaceId::from_bytes([0x79; 16]),
        repository,
        vec![TreePath::parse_default(b"dir").unwrap()],
        Vec::new(),
    )
}
fn form(format: GitHashAlgorithm, pattern: &[u8]) -> String {
    format!("{}&pattern_hex={}", common(format), hex(pattern))
}

#[test]
fn real_regex_reads_preserve_one_snapshot_raw_bytes_and_one_match_per_line() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, commit) = fixture(&root, format);
        let before = generation(&node);
        let q = query(br"\bneedle\b", SearchCase::AsciiInsensitive, &[]);
        let result = local(&node, &q, SearchLimits::default()).unwrap();
        assert_eq!(result.source.source_commit, commit);
        assert_eq!(result.source.completion, SearchCompletion::Complete);
        assert_eq!(result.source.files_selected, 5);
        assert_eq!(result.source.files_read, 5);
        assert_eq!(result.source.non_regular_entries, 2);
        assert_eq!(result.source.matches.len(), 4);
        assert_eq!(result.lines_searched, 6);
        assert!(result.steps > 0 && result.steps <= MAX_REGEX_STEPS);
        assert_eq!(result.source.matches[0].path, b"alpha.txt");
        assert_eq!(
            (
                result.source.matches[0].byte_offset,
                result.source.matches[0].match_length
            ),
            (0, 6)
        );
        assert_eq!(result.source.matches[1].path, BINARY_PATH);
        assert_eq!(result.source.matches[1].byte_offset, 2);
        assert!(result.source.matches[1].excerpt.starts_with(b"\0\xff"));
        assert_eq!(result.source.bytes_read, result.source.bytes_searched);
        assert_eq!(local(&node, &q, SearchLimits::default()).unwrap(), result);
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
        let node = reopen(&config);
        assert_eq!(local(&node, &q, SearchLimits::default()).unwrap(), result);
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}

#[test]
fn capabilities_hidden_refs_and_revocation_remain_separate_from_regex_predicates() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, _) = fixture(&root, format);
        let mut capability = cap(RepositoryId::from_bytes([0x32; 16]));
        let selected = match format {
            GitHashAlgorithm::Sha1 => scoped::<Sha1>(&node, &mut capability, &RefVisibility::new()),
            GitHashAlgorithm::Sha256 => {
                scoped::<Sha256>(&node, &mut capability, &RefVisibility::new())
            }
        }
        .unwrap();
        assert_eq!(selected.source.files_selected, 1);
        assert_eq!(selected.source.matches.len(), 1);
        assert_eq!(selected.source.matches[0].path, b"dir/nested.txt");
        assert_eq!(selected.source.non_regular_entries, 0);
        let q = query(
            br"\bneedle\b",
            SearchCase::AsciiInsensitive,
            &[b"dir".to_vec()],
        );
        assert_eq!(
            local(&node, &q, SearchLimits::default())
                .unwrap()
                .source
                .matches,
            selected.source.matches
        );
        let mut hidden = RefVisibility::new();
        hidden
            .push_rule(reference().as_bytes(), &Default::default())
            .unwrap();
        let mut foreign = cap(RepositoryId::from_bytes([0x99; 16]));
        let mut revoked = cap(RepositoryId::from_bytes([0x32; 16]));
        revoked.revoke();
        let visible = RefVisibility::new();
        for (capability, visibility) in [
            (&mut capability, &hidden),
            (&mut foreign, &visible),
            (&mut revoked, &visible),
        ] {
            let refused = match format {
                GitHashAlgorithm::Sha1 => scoped::<Sha1>(&node, capability, visibility),
                GitHashAlgorithm::Sha256 => scoped::<Sha256>(&node, capability, visibility),
            };
            assert!(refused.is_err());
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn limits_require_real_lookahead_and_work_exhaustion_does_not_claim_absence() {
    let root = Scratch::new();
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha1);
    let q = query(b"needle", SearchCase::Exact, &[]);
    let limited = local(
        &node,
        &q,
        SearchLimits {
            max_matches: 3,
            ..SearchLimits::default()
        },
    )
    .unwrap();
    assert_eq!(limited.source.matches.len(), 3);
    assert_eq!(limited.source.completion, SearchCompletion::MatchLimit);
    let full = local(
        &node,
        &q,
        SearchLimits {
            max_matches: 4,
            ..SearchLimits::default()
        },
    )
    .unwrap();
    assert_eq!(full.source.matches.len(), 4);
    assert_eq!(full.source.completion, SearchCompletion::Complete);
    let short = RegexQuery::new(b"(a|aa)*Z", SearchCase::Exact, &[], 1).unwrap();
    assert!(matches!(local(&node, &short, SearchLimits::default()),
        Err(NodeWorkspaceRefusal::SourceSearch(error)) if matches!(*error, SearchError::Budget("regex VM work"))));
    assert!(
        local(
            &node,
            &q,
            SearchLimits {
                max_total_bytes: 1,
                ..SearchLimits::default()
            }
        )
        .is_err()
    );
    let absent = local(
        &node,
        &query(b"never_present", SearchCase::Exact, &[]),
        SearchLimits::default(),
    )
    .unwrap();
    assert!(absent.source.matches.is_empty());
    assert_eq!(absent.source.completion, SearchCompletion::Complete);
    let empty = local(
        &node,
        &query(b"^$", SearchCase::Exact, &[b"empty".to_vec()]),
        SearchLimits::default(),
    )
    .unwrap();
    assert!(empty.source.matches.is_empty());
    assert_eq!(empty.lines_searched, 0);
    let missing = local(
        &node,
        &query(b"a", SearchCase::Exact, &[b"absent".to_vec()]),
        SearchLimits::default(),
    )
    .unwrap();
    assert!(missing.source.matches.is_empty());
    assert_eq!(missing.steps, 0);
    node.shutdown().unwrap();
}

#[test]
fn real_http_supports_both_framings_line_anchors_and_binary_patterns_without_publication() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, _) = fixture(&root, format);
        let before = generation(&node);
        let q = query(br"\bneedle\b", SearchCase::AsciiInsensitive, &[]);
        let native = local(&node, &q, SearchLimits::default()).unwrap();
        let path = root.0.join("credentials");
        credentials(&node, &path);
        let server = Server::start(node, &path, 5, true, false);
        let input = form(format, br"\bneedle\b") + "&case=ascii-insensitive";
        let first = post(&server.client, "search-regex", 'a', &input, false);
        status(&first, 200);
        assert_eq!(text(&first.body, "profile"), "byte-regex-lines-v1");
        assert_eq!(number(&first.body, "returned_matches"), 4);
        assert_eq!(number(&first.body, "vm_steps"), native.steps);
        assert_eq!(number(&first.body, "lines_searched"), 6);
        assert!(first.body.contains(&hex(BINARY_PATH)));
        assert!(
            first
                .body
                .contains("\"read_only\":true,\"transaction_created\":false,\"published\":false")
        );
        let anchored = post(
            &server.client,
            "search-regex",
            'a',
            &form(format, b"^ab(a|b)*a$"),
            true,
        );
        status(&anchored, 200);
        assert_eq!(number(&anchored.body, "returned_matches"), 1);
        assert_eq!(number(&anchored.body, "byte_offset"), 15);
        assert_eq!(number(&anchored.body, "match_length"), 5);
        let zero = post(
            &server.client,
            "search-regex",
            'a',
            &(form(format, b"^") + "&max_matches=6"),
            false,
        );
        status(&zero, 200);
        assert_eq!(number(&zero.body, "returned_matches"), 6);
        assert_eq!(number(&zero.body, "match_length"), 0);
        assert_eq!(text(&zero.body, "completion"), "complete");
        let empty = post(
            &server.client,
            "search-regex",
            'a',
            &(form(format, b"^$") + "&path_prefix_hex=656d707479"),
            true,
        );
        status(&empty, 200);
        assert_eq!(number(&empty.body, "returned_matches"), 0);
        let binary = post(
            &server.client,
            "search-regex",
            'a',
            &form(format, br"\x00\xff"),
            true,
        );
        status(&binary, 200);
        assert_eq!(number(&binary.body, "returned_matches"), 1);
        assert_eq!(number(&binary.body, "byte_offset"), 0);
        assert_eq!(number(&binary.body, "match_length"), 2);
        assert_eq!(server.finish().accepted_sessions(), 5);
        let node = reopen(&config);
        assert_eq!(generation(&node), before);
        let session = LoopbackReceiveSession::authenticated(
            OWNER,
            IdempotencyKey::new(b"read-only-source-query".to_vec()).unwrap(),
        );
        assert!(matches!(
            node.runtime()
                .block_on(node.recover_transaction_in(&node.request_context(), &session))
                .unwrap(),
            RequestRecovery::KeyNotObserved
        ));
        let server = Server::start(node, &path, 1, true, false);
        assert_eq!(
            post(&server.client, "search-regex", 'a', &input, false),
            first
        );
        assert_eq!(server.finish().accepted_sessions(), 1);
    }
}

#[test]
fn authenticated_http_refuses_unsupported_patterns_limits_and_non_read_grants() {
    let format = GitHashAlgorithm::Sha1;
    let root = Scratch::new();
    let config = root.config(format);
    let (node, _) = fixture(&root, format);
    let before = generation(&node);
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let server = Server::start(node, &path, 8, true, false);
    status(
        &post(
            &server.client,
            "search-regex",
            'z',
            &form(format, b"a"),
            false,
        ),
        401,
    );
    status(
        &post(
            &server.client,
            "search-regex",
            'b',
            &form(format, b"a"),
            false,
        ),
        403,
    );
    let before_continue = exchange(
        &server.client,
        &request(
            &server.client,
            "/api/v1/source/search-regex",
            'b',
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\nExpect: 100-continue\r\n",
            &[],
        ),
        true,
    );
    status(&before_continue, 403);
    assert!(!before_continue.raw.contains("100 Continue"));
    let invalid = post(
        &server.client,
        "search-regex",
        'a',
        &form(format, br"(a)\1"),
        false,
    );
    status(&invalid, 400);
    assert!(invalid.body.contains("invalid_regex_pattern"));
    let exhausted = post(
        &server.client,
        "search-regex",
        'a',
        &(form(format, b"a*") + "&max_steps=1"),
        true,
    );
    status(&exhausted, 413);
    assert!(!exhausted.body.contains("\"matches\":[]"));
    status(
        &post(
            &server.client,
            "search-regex",
            'a',
            &(form(format, b"a") + "&max_bytes=1"),
            false,
        ),
        413,
    );
    let input = form(format, b"a");
    let keyed = exchange(
        &server.client,
        &request(
            &server.client,
            "/api/v1/source/search-regex",
            'a',
            &format!(
                "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: forbidden-read-key\r\n",
                input.len()
            ),
            input.as_bytes(),
        ),
        true,
    );
    status(&keyed, 400);
    let neighboring = post(
        &server.client,
        "search-regex",
        'a',
        &(form(format, b"needle") + "&path_prefix_hex=6469"),
        false,
    );
    status(&neighboring, 200);
    assert_eq!(number(&neighboring.body, "returned_matches"), 0);
    assert_eq!(server.finish().accepted_sessions(), 8);
    let node = reopen(&config);
    assert_eq!(generation(&node), before);
    let server = Server::start(node, &path, 1, false, false);
    status(
        &post(
            &server.client,
            "search-regex",
            'a',
            &form(format, b"a"),
            false,
        ),
        403,
    );
    assert_eq!(server.finish().accepted_sessions(), 1);
}

#[test]
fn regex_head_pins_refuse_intervening_forge_writes_even_when_git_commit_is_unchanged() {
    let format = GitHashAlgorithm::Sha256;
    let root = Scratch::new();
    let config = root.config(format);
    let (node, commit) = fixture(&root, format);
    let before = generation(&node);
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let server = Server::start(node, &path, 5, true, true);
    let input = form(format, b"needle");
    let first = post(&server.client, "search-regex", 'a', &input, false);
    status(&first, 200);
    let old = token(&first);
    let body = b"expected_version=0&title=Intervening+write&body=";
    let issue = exchange(
        &server.client,
        &request(
            &server.client,
            "/api/v1/issues/1/open",
            'b',
            &format!(
                "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: regex-intervening-issue\r\n",
                body.len()
            ),
            body,
        ),
        true,
    );
    status(&issue, 200);
    let stale = post(
        &server.client,
        "search-regex",
        'a',
        &format!("{input}&expected_head={old}"),
        true,
    );
    status(&stale, 409);
    assert!(stale.body.contains("source_snapshot_moved"));
    let fresh = post(
        &server.client,
        "search-regex",
        'a',
        &format!("{input}&expected_commit={commit}"),
        false,
    );
    status(&fresh, 200);
    assert_ne!(token(&fresh), old);
    assert_eq!(text(&fresh.body, "source_commit"), commit.to_string());
    let wrong = post(
        &server.client,
        "search-regex",
        'a',
        &format!("{input}&expected_commit={}", "1".repeat(64)),
        false,
    );
    status(&wrong, 409);
    assert!(wrong.body.contains("source_commit_moved"));
    assert_eq!(server.finish().accepted_sessions(), 5);
    let node = reopen(&config);
    assert_eq!(generation(&node), before + 1);
    node.shutdown().unwrap();
}

// Test-only loose-object encoder; native import still hashes, parses and
// admits the bytes. It is not a production object-store implementation.
fn loose(
    root: &Path,
    format: GitHashAlgorithm,
    kind: GitObjectKind,
    name: &str,
    body: &[u8],
) -> GitOid {
    let id = git_object_id(format, kind, body);
    let raw = [format!("{name} {}\0", body.len()).as_bytes(), body].concat();
    let length = u16::try_from(raw.len()).unwrap();
    let mut zlib = vec![0x78, 0x01, 0x01];
    zlib.extend(length.to_le_bytes());
    zlib.extend((!length).to_le_bytes());
    zlib.extend(&raw);
    let (a, b) = raw.iter().fold((1u32, 0u32), |(a, b), x| {
        let a = (a + u32::from(*x)) % 65521;
        (a, (b + a) % 65521)
    });
    zlib.extend(((b << 16) | a).to_be_bytes());
    let text = id.to_string();
    let dir = root.join("objects").join(&text[..2]);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(&text[2..]), zlib).unwrap();
    id
}
#[test]
fn long_source_spans_empty_physical_lines_and_missing_final_lf_survive_native_http() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (mut node, _) = OneNode::init(root.config(format)).unwrap();
        let selected = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        node.bring_into_service(selected.receipt().generation())
            .unwrap();
        let git = root.0.join("regex-source");
        fs::create_dir_all(git.join("refs/heads")).unwrap();
        fs::write(git.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::write(git.join("config"), match format {
            GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion=0\nbare=true\n",
            GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion=1\nbare=true\n[extensions]\nobjectformat=sha256\n",
        }).unwrap();
        let body = [vec![b'a'; 1024], b"\n\nz".to_vec()].concat();
        let blob = loose(&git, format, GitObjectKind::Blob, "blob", &body);
        let tree = loose(
            &git,
            format,
            GitObjectKind::Tree,
            "tree",
            &[b"100644 long\0".as_slice(), blob.as_bytes()].concat(),
        );
        let commit = loose(&git, format, GitObjectKind::Commit, "commit",
            format!("tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nregex fixture\n").as_bytes());
        fs::write(git.join("refs/heads/main"), format!("{commit}\n")).unwrap();
        let result = node
            .runtime()
            .block_on(node.import_loose_git_directory_durable_in(
                &node.request_context(),
                &git,
                OWNER,
                b"regex-lines",
            ))
            .unwrap();
        assert!(
            result
                .commands
                .iter()
                .all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. }))
        );
        let path = root.0.join("credentials");
        credentials(&node, &path);
        let server = Server::start(node, &path, 2, true, false);
        let matched = post(
            &server.client,
            "search-regex",
            'a',
            &form(format, b"a+|^$|z$"),
            true,
        );
        status(&matched, 200);
        assert_eq!(number(&matched.body, "returned_matches"), 3);
        assert_eq!(number(&matched.body, "match_length"), 1024);
        assert_eq!(text(&matched.body, "excerpt_hex").len(), 416 * 2);
        assert!(matched.body.contains("\"match_truncated_in_excerpt\":true"));
        assert!(
            matched
                .body
                .contains("\"byte_offset\":1025,\"line\":2,\"byte_column\":1,\"match_length\":0")
        );
        assert!(
            matched
                .body
                .contains("\"byte_offset\":1026,\"line\":3,\"byte_column\":1,\"match_length\":1")
        );
        let cross_line = post(
            &server.client,
            "search-regex",
            'a',
            &form(format, br"a\n.*z"),
            false,
        );
        status(&cross_line, 200);
        assert_eq!(number(&cross_line.body, "returned_matches"), 0);
        assert_eq!(server.finish().accepted_sessions(), 2);
    }
}
