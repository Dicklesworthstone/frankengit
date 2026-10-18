#![forbid(unsafe_code)]
//! Actual native publication, file-ownership and pack-binding components.
//! This target uses no node/runtime stand-in or foreign Git implementation.

#[path = "../src/bundle/verify/local_files.rs"]
pub mod local_files;

mod bundle {
    pub mod verify {
        pub use crate::local_files;
    }
}

#[path = "../src/bundle/recover/filesystem.rs"]
mod filesystem;
#[path = "../src/bundle/recover/pack_source.rs"]
mod pack_source;
