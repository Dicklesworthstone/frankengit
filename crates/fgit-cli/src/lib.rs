#![forbid(unsafe_code)]

//! Minimal command-line surface for the one-process node slice.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::PathBuf;

use fgit_node::{NodeConfig, NodeInitialization, OneNode};
use fgit_types::{RepositoryId, TenantId};

/// Typed refusal from the minimal `fg` command parser.
#[derive(Debug)]
pub enum CliRefusal {
    /// The command line did not identify a supported command.
    Usage,
    /// The supplied tenant identity was not canonical lowercase hex.
    Tenant(fgit_types::TypeRefusal),
    /// The supplied repository identity was not canonical lowercase hex.
    Repository(fgit_types::TypeRefusal),
    /// Node initialization refused before a usable service existed.
    Node(fgit_node::NodeRefusal),
}

impl Display for CliRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => formatter.write_str(
                "usage: fg init <storage-root> <tenant-id-hex> <repository-id-hex>; fg serve is not yet available",
            ),
            Self::Tenant(error) => Display::fmt(error, formatter),
            Self::Repository(error) => Display::fmt(error, formatter),
            Self::Node(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for CliRefusal {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Tenant(error) | Self::Repository(error) => Some(error),
            Self::Node(error) => Some(error),
            Self::Usage => None,
        }
    }
}

/// Executes a bounded command invocation without ambient configuration.
pub fn run(arguments: &[String]) -> Result<NodeInitialization, CliRefusal> {
    let [command, storage_root, tenant, repository] = arguments else {
        return Err(CliRefusal::Usage);
    };
    if command != "init" {
        return Err(CliRefusal::Usage);
    }
    let tenant_id = TenantId::from_hex(tenant).map_err(CliRefusal::Tenant)?;
    let repository_id = RepositoryId::from_hex(repository).map_err(CliRefusal::Repository)?;
    let (_node, initialization) = OneNode::init(NodeConfig::new(
        PathBuf::from(storage_root),
        tenant_id,
        repository_id,
    ))
    .map_err(CliRefusal::Node)?;
    Ok(initialization)
}
