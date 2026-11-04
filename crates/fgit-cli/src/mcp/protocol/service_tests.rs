//! The launch barrier follows actual output acknowledgement, not parsing.
use super::*;
use std::cell::Cell;
use std::io::Cursor;
use std::rc::Rc;

const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"service","version":"1"}}}"#;
#[derive(Default)]
struct State {
    flushed: Cell<bool>,
    stopped: Cell<bool>,
}
struct Backend {
    state: Rc<State>,
    ready: usize,
    calls: usize,
}
impl ReadTools for Backend {
    fn service_ready(&mut self) -> Result<(), &'static str> {
        assert!(self.state.flushed.get());
        self.ready += 1;
        Ok(())
    }
    fn service_checkpoint(&self) -> Result<(), &'static str> {
        if self.state.stopped.get() {
            Err("stopped")
        } else {
            Ok(())
        }
    }
    fn tools(&self) -> Vec<Tool> {
        vec![Tool {
            name: "read",
            description: "read",
            schema: object([("type", text("object"))]),
        }]
    }
    fn call(&mut self, _: &str, _: &Object) -> Result<Value, ToolError> {
        self.calls += 1;
        Ok(Value::Null)
    }
}
struct Output {
    state: Rc<State>,
    fail_write: bool,
    fail_flush: bool,
    bytes: Vec<u8>,
}
impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.fail_write {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.fail_flush {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        self.state.flushed.set(true);
        Ok(())
    }
}
fn pair() -> (Backend, Output) {
    let state = Rc::new(State::default());
    (
        Backend {
            state: state.clone(),
            ready: 0,
            calls: 0,
        },
        Output {
            state,
            fail_write: false,
            fail_flush: false,
            bytes: Vec::new(),
        },
    )
}

#[test]
fn launch_happens_once_only_after_a_successfully_flushed_initialize_response() {
    let (mut backend, mut output) = pair();
    serve(
        &mut Cursor::new(format!("{INIT}\n{INIT}\n")),
        &mut output,
        &mut backend,
        3,
    )
    .unwrap();
    assert_eq!(backend.ready, 1);
    assert_eq!(backend.calls, 0);
    assert_eq!(
        output.bytes.iter().filter(|byte| **byte == b'\n').count(),
        2
    );
}
#[test]
fn initial_eof_and_failed_write_or_flush_never_release_the_launch_barrier() {
    let (mut backend, mut output) = pair();
    serve(
        &mut Cursor::new(Vec::<u8>::new()),
        &mut output,
        &mut backend,
        2,
    )
    .unwrap();
    assert_eq!(backend.ready, 0);
    for flush in [false, true] {
        let (mut backend, mut output) = pair();
        output.fail_write = !flush;
        output.fail_flush = flush;
        assert!(
            serve(
                &mut Cursor::new(format!("{INIT}\n")),
                &mut output,
                &mut backend,
                2
            )
            .unwrap_err()
            .contains("output failed")
        );
        assert_eq!(backend.ready, 0);
    }
    let (mut backend, mut output) = pair();
    serve(
        &mut Cursor::new(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n",
        ),
        &mut output,
        &mut backend,
        2,
    )
    .unwrap();
    assert_eq!(backend.ready, 0);
}
struct StopsWhileReading {
    bytes: Cursor<Vec<u8>>,
    state: Rc<State>,
}
impl io::Read for StopsWhileReading {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        io::Read::read(&mut self.bytes, bytes)
    }
}
impl BufRead for StopsWhileReading {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.state.stopped.set(true);
        self.bytes.fill_buf()
    }
    fn consume(&mut self, amount: usize) {
        self.bytes.consume(amount);
    }
}
#[test]
fn controller_failure_while_blocked_on_input_precedes_parsing_and_dispatch() {
    let (mut backend, mut output) = pair();
    let mut input = StopsWhileReading {
        bytes: Cursor::new(format!("{INIT}\n").into_bytes()),
        state: backend.state.clone(),
    };
    assert!(
        serve(&mut input, &mut output, &mut backend, 2)
            .unwrap_err()
            .contains("background service stopped")
    );
    assert_eq!(backend.ready, 0);
    assert!(output.bytes.is_empty());
}
