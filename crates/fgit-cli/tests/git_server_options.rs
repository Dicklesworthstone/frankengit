#![forbid(unsafe_code)]
//! Focused validation of the executable's SSH and guarded Git deployment code.
//!
//! These are the production modules used by `fg`, including their original
//! tests. Keeping this target separate lets those tests run without linking
//! unrelated command tests into the same executable. No service, credential,
//! repository, or runtime implementation is substituted here.

#[path = "../src/guarded_git_server.rs"]
pub mod guarded_git_server;
#[path = "../src/service_stop.rs"]
pub mod service_stop;
#[path = "../src/ssh_server.rs"]
pub mod ssh_server;
