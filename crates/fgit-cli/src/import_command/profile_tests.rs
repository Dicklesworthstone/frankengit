use super::*;
fn args(value: &str) -> Vec<String> {
    [
        "node",
        "11111111111111111111111111111111",
        "22222222222222222222222222222222",
        "33333333333333333333333333333333",
        "key",
        "source",
        "--max-expanded-mib",
        value,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}
#[test]
fn expanded_profile_bounds_refuse_bad_values_and_accept_exact_endpoints() {
    for value in [
        "",
        "0",
        "-1",
        "+1",
        "1.5",
        "16385",
        "18446744073709551615",
        "99999999999999999999999",
    ] {
        assert!(parse(&args(value)).is_err(), "{value}");
    }
    for value in [1_u64, 512, 1024, 16384] {
        assert_eq!(
            parse(&args(&value.to_string())).unwrap().maximum_bytes,
            Some(value * 1024 * 1024)
        );
    }
    let mut input = args("1024");
    input.extend(["--max-expanded-mib".into(), "1024".into()]);
    assert!(parse(&input).is_err());
}
#[test]
fn explicit_size_timeout_incarnation_and_json_coexist_without_changing_identity() {
    let mut input = args("1024");
    input.extend(
        [
            "--expected-incarnation",
            "44444444444444444444444444444444",
            "--timeout-secs",
            "30",
            "--json",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    let parsed = parse(&input).unwrap();
    assert_eq!(parsed.maximum_bytes, Some(1024 * 1024 * 1024));
    assert!(parsed.timeout.is_some());
    assert!(parsed.incarnation.is_some());
    assert!(parsed.json);
    assert_eq!(parsed.key, b"key");
    assert!(parse(&args("1024")[..6]).unwrap().maximum_bytes.is_none());
}
