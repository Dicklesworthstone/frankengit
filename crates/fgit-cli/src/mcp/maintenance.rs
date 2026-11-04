//! Operator-selected background scope, independent of every MCP tool grant.
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use fgit_node::index_maintenance::{IndexKind, MaintenanceConfig, MaintenanceGroup};
use fgit_types::{GitHashAlgorithm, RefName};

pub(super) fn parse(
    flags: &BTreeMap<&str, &str>,
    refs: Vec<RefName>,
    format: GitHashAlgorithm,
) -> Result<Option<MaintenanceGroup>, String> {
    if refs.is_empty() && !flags.keys().any(|name| name.starts_with("--index-")) {
        return Ok(None);
    }
    let required = |name: &str| -> Result<&str, String> {
        flags
            .get(name)
            .copied()
            .ok_or_else(|| format!("index maintenance requires {name}"))
    };
    let profiles: &[IndexKind] = match required("--index-profile")? {
        "lexical" => &[IndexKind::Lexical],
        "symbols" => &[IndexKind::Symbols],
        "both" => &[IndexKind::Lexical, IndexKind::Symbols],
        _ => return Err("--index-profile must be lexical, symbols or both".into()),
    };
    if profiles.len() == 1 && flags.contains_key("--index-symbol-state-dir") {
        return Err("--index-symbol-state-dir requires --index-profile both".into());
    }
    let selected_format = match required("--index-format")? {
        "sha1" => GitHashAlgorithm::Sha1,
        "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("--index-format must be sha1 or sha256".into()),
    };
    if selected_format != format {
        return Err("MCP index format must match --object-format".into());
    }
    let initialize = match required("--index-state")? {
        "init" => true,
        "resume" => false,
        _ => return Err("--index-state must be init or resume".into()),
    };
    let seconds = |name: &str, default| -> Result<Duration, String> {
        let value = flags
            .get(name)
            .map(|value| super::json::decimal(value))
            .transpose()?
            .unwrap_or(default);
        if !(1..=3600).contains(&value) {
            return Err(format!("{name} must be 1..3600 whole seconds"));
        }
        Ok(Duration::from_secs(value))
    };
    let interval = seconds("--index-interval-secs", 5)?;
    let timeout = seconds("--index-attempt-timeout-secs", 300)?;
    let mut configs = Vec::with_capacity(profiles.len());
    for (index, &kind) in profiles.iter().enumerate() {
        let directory = required(if index == 0 {
            "--index-state-dir"
        } else {
            "--index-symbol-state-dir"
        })?;
        configs.push(
            MaintenanceConfig::try_new(
                kind,
                format,
                PathBuf::from(directory),
                initialize,
                interval,
                refs.clone(),
            )
            .and_then(|config| config.with_attempt_timeout(timeout))
            .map_err(|error| error.to_string())?,
        );
    }
    MaintenanceGroup::try_new(configs)
        .map(Some)
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests;
