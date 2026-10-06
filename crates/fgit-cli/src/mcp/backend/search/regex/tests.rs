use super::*;
use fgit_types::{CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, RepositoryCommitId};

fn fields<const N: usize>(pairs: [(&str, Value); N]) -> Object {
    let Value::Object(fields) = object(pairs) else { unreachable!() }; fields
}
fn args(pattern: &str) -> Object {
    fields([("operation", text("regex")), ("reference", text("refs/heads/main")), ("pattern", text(pattern))])
}
fn head() -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(DigestAlgorithmId::try_new(1).unwrap(), CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[1; 32]).unwrap())
}
fn oid(byte: u8) -> GitOid {
    GitOid::from_hex(GitHashAlgorithm::Sha256, &format!("{byte:02x}").repeat(32)).unwrap()
}
fn report() -> RegexSearchReport {
    let (_, query) = parse(&args("x*"), GitHashAlgorithm::Sha256).unwrap();
    RegexSearchReport {
        source: SourceSearchReport {
            repository: RepositoryId::from_bytes([2; 16]),
            source_rcr: RepositoryCommitId::from_digest(DigestAlgorithmId::try_new(1).unwrap(), CANONICAL_CODEC_VERSION,
                DigestBytes::try_new(&[3; 32]).unwrap()),
            source_commit: oid(1), source_tree: oid(2),
            matches: vec![SourceMatch { path: b"file".to_vec(), blob: oid(3), byte_offset: 0,
                line: 1, byte_column: 1, match_length: 1000, excerpt: vec![b'x'; 416], excerpt_offset: 0 }],
            completion: SearchCompletion::Complete, files_selected: 1, files_read: 1,
            bytes_read: 1000, bytes_searched: 1000, non_regular_entries: 0,
        }, program_states: query.state_count(), steps: 4000, lines_searched: 1,
    }
}
fn rendered(report: &RegexSearchReport) -> Result<Object, ToolError> {
    let (selected, query) = parse(&args("x*"), GitHashAlgorithm::Sha256)?;
    render(RepositoryId::from_bytes([2; 16]), GitHashAlgorithm::Sha256, head(), &selected, &query, report)
}

#[test]
fn patterns_and_scope_are_exact_and_do_not_reinterpret_literal_arguments() {
    let mut input = args("^(ab|a)+$");
    input.insert("ignore_ascii_case".into(), Value::Bool(true));
    input.insert("path_prefixes_hex".into(), Value::Array(vec![text(hex(b"src")), text(hex(b"src"))]));
    let (_, query) = parse(&input, GitHashAlgorithm::Sha1).unwrap();
    assert_eq!(query.pattern(), b"^(ab|a)+$");
    assert_eq!(query.case(), SearchCase::AsciiInsensitive);
    assert_eq!(query.prefixes().len(), 1);
    input.remove("pattern"); input.insert("pattern_hex".into(), text("ff00"));
    assert_eq!(parse(&input, GitHashAlgorithm::Sha1).unwrap().1.pattern(), &[255, 0]);
    input.insert("pattern".into(), text("a"));
    assert!(parse(&input, GitHashAlgorithm::Sha1).is_err());
    let literal = fields([("reference", text("refs/heads/main")), ("needle_hex", text(hex(b"a.*")))]);
    assert_eq!(super::super::parse(&literal, GitHashAlgorithm::Sha1).unwrap().1.needle(), b"a.*");
    assert!(parse(&literal, GitHashAlgorithm::Sha1).is_err());
}

#[test]
fn unsupported_patterns_authority_and_budgets_refuse_before_node_access() {
    for pattern in ["", "(?=a)", "(a)\\1", "[", "a{65}", &"x".repeat(257)] {
        assert!(parse(&args(pattern), GitHashAlgorithm::Sha1).is_err(), "{pattern}");
    }
    for field in ["principal", "storage", "repository_id", "needle_hex", "after", "generation"] {
        let mut input = args("a"); input.insert(field.into(), text("not permitted"));
        assert_eq!(parse(&input, GitHashAlgorithm::Sha1).err().unwrap().code, "unknown_argument");
    }
    for value in [json::number(0), json::number(MAX_REGEX_STEPS + 1), text("1"), Value::Null] {
        let mut input = args("a"); input.insert("max_regex_steps".into(), value);
        assert!(parse(&input, GitHashAlgorithm::Sha1).is_err());
    }
    for value in [Value::Null, text("indexed"), json::number(1)] {
        let mut input = args("a"); input.insert("operation".into(), value);
        assert!(parse(&input, GitHashAlgorithm::Sha1).is_err());
    }
    let mut input = args("a"); input.insert("expected_commit".into(), text("00".repeat(20)));
    assert!(parse(&input, GitHashAlgorithm::Sha1).is_err());
}

#[test]
fn long_and_zero_width_matches_preserve_spans_without_fabricating_complete_excerpts() {
    let mut native = report();
    let value = rendered(&native).unwrap();
    let Value::Array(rows) = &value["matches"] else { unreachable!() };
    let row = rows[0].object().unwrap();
    assert_eq!(row["match_length"].text(), Some("1000"));
    assert_eq!(row["match_fully_in_excerpt"], Value::Bool(false));
    assert_eq!(row["match_bytes_hex"], Value::Null);
    native.source.matches[0].match_length = 0;
    native.source.matches[0].excerpt.clear();
    native.source.bytes_read = 1; native.source.bytes_searched = 1;
    let value = rendered(&native).unwrap();
    let Value::Array(rows) = &value["matches"] else { unreachable!() };
    assert_eq!(rows[0].object().unwrap()["match_bytes_hex"].text(), Some(""));
    assert_eq!(rows[0].object().unwrap()["match_fully_in_excerpt"], Value::Bool(true));
}

#[test]
fn malformed_spans_work_and_truncation_never_become_successful_output() {
    for change in 0..10 {
        let mut native = report();
        match change {
            0 => native.source.matches[0].byte_offset = usize::MAX,
            1 => native.source.matches[0].excerpt_offset = 1,
            2 => native.source.matches[0].byte_column = 0,
            3 => native.source.matches[0].excerpt.push(b'\n'),
            4 => native.source.matches[0].path = b"../private".to_vec(),
            5 => native.program_states += 1,
            6 => native.steps = MAX_REGEX_STEPS + 1,
            7 => native.lines_searched = 0,
            8 => native.source.completion = SearchCompletion::MatchLimit,
            _ => native.source.bytes_searched -= 1,
        }
        assert!(rendered(&native).is_err(), "variant {change}");
    }
    let mut native = report(); native.source.matches.push(native.source.matches[0].clone());
    native.lines_searched = 2;
    assert!(rendered(&native).is_err());
}

#[test]
fn schema_retains_closed_literal_and_regex_alternatives_without_adding_a_tool() {
    let tools = super::super::tools();
    assert_eq!(tools.len(), 2);
    let schema = tools[0].schema.object().unwrap();
    assert_eq!(schema["additionalProperties"], Value::Bool(false));
    assert!(schema["properties"].object().unwrap().contains_key("needle_hex"));
    let Value::Array(variants) = &schema["oneOf"] else { unreachable!() };
    assert_eq!(variants.len(), 2);
    assert_eq!(variants[0], super::super::input_schema());
    assert_eq!(variants[1].object().unwrap()["additionalProperties"], Value::Bool(false));
    let encoded = tools[0].schema.encode(json::MAX_INPUT).unwrap();
    assert_eq!(json::parse(encoded.as_bytes()).unwrap(), tools[0].schema);
}
