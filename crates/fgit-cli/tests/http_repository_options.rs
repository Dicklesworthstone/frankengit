#![forbid(unsafe_code)]
//! Focused executable HTTP catalog validation using the production modules.

#[path = "../src/smart_http_server/repositories.rs"]
mod repositories;
#[path = "../src/service_stop.rs"]
pub mod service_stop;

#[cfg(unix)]
#[path = "http_repository_options/binary.rs"]
mod binary;
