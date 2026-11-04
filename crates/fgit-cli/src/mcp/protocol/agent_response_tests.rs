//! Transport reservation tests use deterministic checkpoints, never sleeps.
use super::*;
use std::cell::Cell;
use std::io::Cursor;
use std::rc::Rc;

#[derive(Default)]
struct Gate {
    active: Cell<bool>,
    expired: Cell<bool>,
    max_bytes: Cell<u64>,
}
struct Reserved {
    gate: Rc<Gate>,
    calls: usize,
    finished: usize,
    expire_at_return: bool,
}
impl Reserved {
    fn new() -> Self {
        let gate = Rc::new(Gate::default());
        gate.max_bytes.set(MAX_RESPONSE as u64 + 1);
        Self {
            gate,
            calls: 0,
            finished: 0,
            expire_at_return: false,
        }
    }
}
impl ReadTools for Reserved {
    fn tools(&self) -> Vec<Tool> {
        vec![Tool {
            name: "reserved_read",
            description: "Reserved response fixture",
            schema: object([("type", text("object"))]),
        }]
    }
    fn call(&mut self, _: &str, _: &Object) -> Result<Value, ToolError> {
        self.calls += 1;
        self.gate.active.set(true);
        self.gate.expired.set(self.expire_at_return);
        Ok(object([("repository_text", text("x".repeat(64 * 1024)))]))
    }
    fn begin_message(&mut self) {
        self.gate.active.set(false);
    }
    fn response_checkpoint(&self, bytes: u64) -> Result<(), &'static str> {
        if self.gate.active.get() && (self.gate.expired.get() || bytes > self.gate.max_bytes.get())
        {
            Err("reservation_expired_or_exhausted")
        } else {
            Ok(())
        }
    }
    fn finish_response(&mut self) {
        self.finished += 1;
        self.gate.active.set(false);
        // The next static message must not inherit this expired reservation.
        self.gate.expired.set(true);
    }
}
const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"reservation","version":"1"}}}"#;
const READY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
const CALL: &str =
    r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"reserved_read"}}"#;
const NEXT: &str =
    r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"reserved_read"}}"#;

#[test]
fn expired_result_is_never_emitted_and_the_following_request_is_not_executed() {
    let mut backend = Reserved::new();
    backend.expire_at_return = true;
    let mut output = Vec::new();
    let error = serve(
        &mut Cursor::new(format!("{INIT}\n{READY}\n{CALL}\n{NEXT}\n")),
        &mut output,
        &mut backend,
        10,
    )
    .unwrap_err();
    assert!(error.contains("may have committed"));
    assert_eq!(backend.calls, 1);
    assert_eq!(backend.finished, 2);
    assert_eq!(String::from_utf8(output).unwrap().lines().count(), 1);
    assert!(!backend.gate.active.get());
}

struct ExpiringWriter {
    gate: Rc<Gate>,
    output: Vec<u8>,
    reserved_writes: Vec<usize>,
    expire_on_flush: bool,
    interrupted: bool,
}
impl Write for ExpiringWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.gate.active.get() {
            if self.interrupted {
                self.interrupted = false;
                return Err(io::ErrorKind::Interrupted.into());
            }
            // A partial blocking-write completion is represented without a
            // sleep. The post-write checkpoint must stop every later handoff.
            let count = bytes.len().min(17);
            self.reserved_writes.push(bytes.len());
            self.output.extend_from_slice(&bytes[..count]);
            if !self.expire_on_flush {
                self.gate.expired.set(true);
            }
            Ok(count)
        } else {
            self.output.extend_from_slice(bytes);
            Ok(bytes.len())
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.gate.active.get() && self.expire_on_flush {
            self.gate.expired.set(true);
        }
        Ok(())
    }
}

#[test]
fn expiry_after_partial_write_or_flush_closes_before_the_next_tool() {
    for expire_on_flush in [false, true] {
        let mut backend = Reserved::new();
        let mut writer = ExpiringWriter {
            gate: backend.gate.clone(),
            output: Vec::new(),
            reserved_writes: Vec::new(),
            expire_on_flush,
            interrupted: true,
        };
        let result = serve(
            &mut Cursor::new(format!("{INIT}\n{READY}\n{CALL}\n{NEXT}\n")),
            &mut writer,
            &mut backend,
            10,
        );
        assert!(result.unwrap_err().contains("may have committed"));
        assert_eq!(backend.calls, 1);
        assert!(!backend.gate.active.get());
        assert!(writer.reserved_writes.iter().all(|size| *size <= 16 * 1024));
        if expire_on_flush {
            assert!(writer.reserved_writes.len() > 1);
            assert_eq!(String::from_utf8(writer.output).unwrap().lines().count(), 2);
        } else {
            assert_eq!(writer.reserved_writes, [16 * 1024]);
            assert!(!writer.output.ends_with(b"\n"));
        }
    }
}

#[test]
fn complete_envelope_includes_final_lf_and_releases_each_finished_reservation() {
    let backend = Reserved::new();
    backend.gate.active.set(true);
    backend.gate.max_bytes.set(2);
    let mut out = Vec::new();
    assert!(emit_response(&mut out, &backend, b"{}").is_err());
    assert!(out.is_empty());
    backend.gate.max_bytes.set(3);
    emit_response(&mut out, &backend, b"{}").unwrap();
    assert_eq!(out, b"{}\n");

    let mut backend = Reserved::new();
    let mut out = Vec::new();
    let list = r#"{"jsonrpc":"2.0","id":4,"method":"tools/list"}"#;
    serve(
        &mut Cursor::new(format!("{INIT}\n{READY}\n{CALL}\n{NEXT}\n{list}\n")),
        &mut out,
        &mut backend,
        10,
    )
    .unwrap();
    assert_eq!(backend.calls, 2);
    assert_eq!(backend.finished, 4);
    assert!(!backend.gate.active.get());
    assert_eq!(String::from_utf8(out).unwrap().lines().count(), 4);
}
