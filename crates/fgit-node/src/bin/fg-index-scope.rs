#![forbid(unsafe_code)]
//! Explicit scoped lexical build, query and original-candidate recovery.
//! No server, scanner fallback, subprocess, second runtime or remote grant.
#[path = "index_scope/checkpoint.rs"]
mod checkpoint;
#[path = "index_scope/options.rs"]
mod options;
#[path = "index_scope/output.rs"]
mod output;
use fgit_node::{NodeConfig, NodeWorkspaceRefusal, OneNode};
use options::{Command, Options, failure};
use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

fn execute(node: &OneNode, options: &Options) -> io::Result<(String, bool)> {
    let incarnation = node.repository_incarnation_id();
    match &options.command {
        Command::Build {
            predecessor,
            record,
            limits,
        } => {
            let request = node.outbox_delivery_context();
            let mut saved = None;
            let mut recording_error = None;
            let result = node
                .runtime()
                .block_on(node.build_scoped_source_index_guarded_local_in(
                    &request,
                    &options.reference,
                    &options.scope,
                    options.head,
                    options.commit,
                    *predecessor,
                    *limits,
                    &mut |candidate| {
                        let result =
                            output::candidate(options, incarnation, candidate, *predecessor)
                                .and_then(|json| checkpoint::record(record, json.as_bytes()));
                        match result {
                            Ok(()) => {
                                saved = Some(candidate);
                                Ok(())
                            }
                            Err(error) => {
                                recording_error = Some(error);
                                // The exact I/O error remains owned by this command.
                                // Any barrier error prevents native index effects.
                                Err(NodeWorkspaceRefusal::RefUnavailable)
                            }
                        }
                    },
                ));
            if let Some(error) = recording_error {
                return Err(error);
            }
            let (source, activation) = result.map_err(failure)?;
            if saved != Some(activation.generation_id) {
                return Err(io::Error::other(
                    "Confirmed index differs from the recorded candidate; inspect the retained record.",
                ));
            }
            Ok((
                output::built(options, incarnation, &source, &activation)?,
                true,
            ))
        }
        Command::Search {
            query,
            generation,
            minimum,
            after,
            limits,
            reads,
        } => {
            let report = node
                .runtime()
                .block_on(node.search_scoped_source_index_local_in(
                    &node.request_context(),
                    &options.reference,
                    &options.scope,
                    options.head,
                    options.commit,
                    generation.as_ref(),
                    minimum.as_ref(),
                    query,
                    *after,
                    *limits,
                    *reads,
                ))
                .map_err(failure)?;
            Ok((
                output::searched(options, incarnation, &report, *after)?,
                true,
            ))
        }
        Command::Recover { candidate, minimum } => {
            let result = node
                .runtime()
                .block_on(node.recover_scoped_source_index_local_in(
                    &node.request_context(),
                    &options.reference,
                    &options.scope,
                    *candidate,
                    minimum.as_ref(),
                    Default::default(),
                ))
                .map_err(failure)?;
            output::recovered(options, incarnation, *candidate, &result)
        }
    }
}
fn run(options: &Options) -> io::Result<(String, bool)> {
    if let Command::Build { record, .. } = &options.command {
        checkpoint::preflight(record)?;
    }
    let mut node = OneNode::open_existing(
        NodeConfig::new(options.root.clone(), options.tenant, options.repository)
            .with_object_format(options.format)
            .with_worker_threads(2),
    )
    .map_err(failure)?;
    let outcome = (|| {
        let selected = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .map_err(failure)?;
        node.bring_into_service(selected.receipt().generation())
            .map_err(failure)?;
        execute(&node, options)
    })();
    // Always finish node shutdown after the native future settles. Do not
    // report a committed index as rolled back when output or shutdown fails.
    let shutdown = node.shutdown().map(|_| ()).map_err(failure);
    match (outcome, shutdown) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(io::Error::other(format!(
            "Operation settled but shutdown failed: {error}; retain candidate records."
        ))),
        (Err(error), Err(stop)) => Err(io::Error::other(format!(
            "{error}; shutdown also failed: {stop}"
        ))),
    }
}
fn main() -> ExitCode {
    // Bound collection before retaining arbitrarily many command arguments.
    let args: Vec<OsString> = std::env::args_os().skip(1).take(701).collect();
    if args.len() == 1 && args[0] == "--help" {
        println!("{}", options::USAGE);
        return ExitCode::SUCCESS;
    }
    let result = options::parse(&args).and_then(|options| run(&options));
    match result {
        Ok((json, resolved)) => {
            let mut stdout = io::stdout().lock();
            if let Err(error) = stdout
                .write_all(json.as_bytes())
                .and_then(|()| stdout.flush())
            {
                eprintln!(
                    "fg-index-scope: output failed after operation settled: {error}; inspect retained candidate records."
                );
                return ExitCode::FAILURE;
            }
            if resolved {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
        Err(error) => {
            // Never interpolate repository-controlled control bytes into a terminal.
            let message: String = error
                .to_string()
                .chars()
                .take(8192)
                .flat_map(char::escape_default)
                .collect();
            eprintln!("fg-index-scope: {message}");
            ExitCode::FAILURE
        }
    }
}
