use super::*;
use std::cell::Cell;

#[test]
fn progressive_is_an_explicit_closed_variant_without_changing_other_context_schemas() {
    let tools = super::super::tools();
    assert_eq!(tools.len(), 2);
    assert_eq!(tools[0].schema, input_schema(false));
    let schema = tools[1].schema.object().unwrap();
    let Value::Array(variants) = &schema["oneOf"] else {
        panic!("closed context variants");
    };
    assert_eq!(variants.len(), 2);
    assert_eq!(variants[0], input_schema(true));
    for variant in variants {
        assert_eq!(
            variant.object().unwrap()["additionalProperties"],
            Value::Bool(false)
        );
    }
    let progressive = variants[1].object().unwrap();
    let properties = progressive["properties"].object().unwrap();
    assert_eq!(
        properties["operation"].object().unwrap()["const"],
        text("progressive")
    );
    assert_eq!(
        properties["context_selection"].object().unwrap()["const"],
        text(ranked::PROFILE)
    );
    assert_eq!(
        progressive["required"],
        Value::Array(vec![
            text("operation"),
            text("reference"),
            text("terms_hex")
        ])
    );
    let agent = crate::mcp::backend::agent_context::tool();
    assert!(
        !agent.schema.object().unwrap()["properties"]
            .object()
            .unwrap()
            .contains_key("operation")
    );
    assert!(!agent.schema.object().unwrap().contains_key("oneOf"));
}

#[test]
fn bounded_sink_stops_on_exhaustion_or_cancellation_and_wrapper_reserve_covers_framing() {
    let active = Cell::new(true);
    let live = || active.get();
    let mut output = BoundedOutput {
        bytes: Vec::new(),
        maximum: 4,
        live: &live,
    };
    output.write_all(b"1234").unwrap();
    assert!(output.write_all(b"5").is_err());
    assert_eq!(output.bytes, b"1234");
    active.set(false);
    assert_eq!(
        output.flush().unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!(
        output.write_all(b"5").unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    assert!(output.write(b"").is_err());
    assert_eq!(
        checkpoint(&live).unwrap_err().code,
        "progressive_context_cancelled"
    );
    assert_eq!(output.bytes, b"1234");
    let empty = envelope(Vec::new(), false, false)
        .encode(ENVELOPE_RESERVE)
        .unwrap();
    assert!(empty.len() + 2 < ENVELOPE_RESERVE);
}

#[test]
fn truncated_or_extra_native_records_never_become_successful_empty_phases() {
    let valid = b"{\"phase\":\"Initial\",\"answer\":{}}\n{\"phase\":\"RefinementFailed\",\"code\":\"resource_limit\"}\n";
    let parsed = records(valid).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(answer(&parsed[0], "Initial").unwrap(), &object([]));
    assert!(answer(&parsed[1], "Refined").is_err());
    for bytes in [
        b"".as_slice(),
        b"{}\n",
        &valid[..valid.len() - 1],
        b"{}\n{}\n{}\n",
        b"{\"phase\":\"Initial\",\"phase\":\"Refined\"}\n{}\n",
    ] {
        assert_eq!(
            records(bytes).unwrap_err().code,
            "invalid_progressive_report"
        );
    }
}
