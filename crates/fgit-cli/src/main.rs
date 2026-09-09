#![forbid(unsafe_code)]

mod merge_apply;
mod publication_support;
mod source_search;
#[cfg(target_os = "linux")]
mod workspace;
#[cfg(target_os = "linux")]
mod workspace_apply;

use std::process::ExitCode;

fn main() -> ExitCode {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.first().is_some_and(|argument| argument == "search") {
        return match source_search::run(&arguments[1..]) {
            Ok(code) => ExitCode::from(code),
            Err(error) => { eprintln!("fg: {error}"); ExitCode::from(2) }
        };
    }
    if arguments.first().is_some_and(|argument| argument == "merge") {
        return match merge_apply::run(&arguments[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => { eprintln!("fg: {error}"); ExitCode::from(2) }
        };
    }
    if arguments.first().is_some_and(|argument| argument == "workspace") {
        #[cfg(target_os = "linux")]
        {
            let outcome = if arguments.get(1).is_some_and(|argument| argument == "apply") {
                workspace_apply::run(&arguments[1..])
            } else {
                workspace::run(&arguments[1..])
            };
            return match outcome {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => { eprintln!("fg: {error}"); ExitCode::from(2) }
            };
        }
        #[cfg(not(target_os = "linux"))]
        {
            eprintln!("fg: the trusted sparse workspace host adapter is supported only on Linux");
            return ExitCode::from(2);
        }
    }
    match fgit_cli::run(&arguments) {
        Ok(fgit_cli::CliOutcome::Initialized(fgit_node::NodeInitialization::Created)) => {
            println!("initialized authority head");
            ExitCode::SUCCESS
        }
        Ok(fgit_cli::CliOutcome::Initialized(fgit_node::NodeInitialization::IdenticalRetry)) => {
            println!("authority head already initialized");
            ExitCode::SUCCESS
        }
        Ok(fgit_cli::CliOutcome::Imported { command_count }) => {
            println!("published {command_count} source-import ref commands");
            ExitCode::SUCCESS
        }
        Ok(fgit_cli::CliOutcome::Doctor(report)) => {
            println!(
                "authenticated authority head at generation {}{}",
                report.authority_head().receipt().generation().get(),
                report
                    .sampled_object()
                    .map_or_else(String::new, |identity| format!(
                        "; verified object sample {identity}"
                    ),)
            );
            ExitCode::SUCCESS
        }
        Ok(fgit_cli::CliOutcome::Served {
            listen_address,
            service,
        }) => {
            println!(
                "served bounded git-daemon run on {listen_address}: accepted={}, completed={}, refused={}",
                service.accepted_sessions(),
                service.completed_sessions(),
                service.refused_sessions(),
            );
            ExitCode::SUCCESS
        }
        Ok(fgit_cli::CliOutcome::Exported { destination, bytes }) => {
            println!(
                "exported {bytes} authority-selected pack bytes to {}",
                destination.display()
            );
            ExitCode::SUCCESS
        }
        Ok(fgit_cli::CliOutcome::At(report)) => {
            match report {
                fgit_cli::AtReport::Summary {
                    snapshot_summary,
                    target,
                    head_id,
                    decision_sequence,
                    refs_count,
                    prs_count,
                } => {
                    println!(
                        "snapshot at {target} (head {head_id}, decision {:?}): {refs_count} refs, {prs_count} pull requests; {snapshot_summary}",
                        decision_sequence
                    );
                }
                fgit_cli::AtReport::Refs { position, refs } => {
                    println!("references at {position} ({} total):", refs.len());
                    for (name, oid) in refs {
                        println!("  {name} -> {oid}");
                    }
                }
                fgit_cli::AtReport::PullRequests {
                    position,
                    pull_requests,
                } => {
                    println!(
                        "pull requests at {position} ({} total):",
                        pull_requests.len()
                    );
                    for (number, title, state, branch) in pull_requests {
                        println!("  #{number} [{state}] {title} (into {branch})");
                    }
                }
                fgit_cli::AtReport::Diff {
                    older,
                    newer,
                    ref_changes_count,
                    pr_changes_count,
                } => {
                    println!(
                        "diff between {older} and {newer}: {ref_changes_count} ref changes, {pr_changes_count} pull request changes"
                    );
                }
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("fg: {error}");
            ExitCode::from(2)
        }
    }
}
