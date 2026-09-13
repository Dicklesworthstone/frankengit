#![forbid(unsafe_code)]

mod branches;
mod commit_replay;
mod rebase;
mod issues;
mod merge_apply;
mod publication_support;
mod pull_request;
mod review_commands;
mod source_history;
mod source_review;
mod source_search;
mod transaction_outcome;
#[cfg(target_os = "linux")]
mod workspace;
#[cfg(target_os = "linux")]
mod workspace_apply;

use std::process::ExitCode;

fn main() -> ExitCode {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.first().is_some_and(|argument| argument == "branch") {
        return match branches::run(&arguments[1..]) {
            Ok(code) => ExitCode::from(code),
            Err(error) => {
                eprintln!("{{\"type\":\"branch_error\",\"schema_version\":1,\"error\":{}}}", publication_support::quote(&error));
                ExitCode::from(2)
            }
        };
    }
    if arguments.first().is_some_and(|argument| argument == "rebase") {
        return match rebase::run(&arguments[1..]) {
            Ok(code) => ExitCode::from(code),
            Err(error) => { eprintln!("fg: {error}"); ExitCode::from(2) }
        };
    }
    if arguments.first().is_some_and(|argument| argument == "issue") {
        return match issues::run(&arguments[1..]) {
            Ok(code) => ExitCode::from(code),
            Err(error) => { eprintln!("fg: {error}"); ExitCode::from(2) }
        };
    }
    if let Some(command @ ("cherry-pick" | "revert")) = arguments.first().map(String::as_str) {
        let direction = if command == "revert" { fgit_forge::preparation::replay::ReplayDirection::Revert }
            else { fgit_forge::preparation::replay::ReplayDirection::CherryPick };
        return match commit_replay::run(&arguments[1..], direction) {
            Ok(code) => ExitCode::from(code),
            Err(error) => { eprintln!("fg: {error}"); ExitCode::from(2) }
        };
    }
    if arguments.first().is_some_and(|argument| argument == "outcome") {
        return match transaction_outcome::run(&arguments[1..]) {
            Ok(code) => ExitCode::from(code),
            Err(error) => { eprintln!("fg: {error}"); ExitCode::from(2) }
        };
    }
    let review_mode = match (arguments.first().map(String::as_str), arguments.get(1).map(String::as_str)) {
        (Some("pr"), Some("review")) => Some(review_commands::Mode::Review),
        (Some("pr"), Some("reviews")) => Some(review_commands::Mode::Reviews),
        (Some("merge"), Some("apply-reviewed")) => Some(review_commands::Mode::Apply),
        _ => None,
    };
    if let Some(mode) = review_mode {
        return match review_commands::run(&arguments[2..], mode) {
            Ok(code) => ExitCode::from(code),
            Err(error) => { eprintln!("fg: {error}"); ExitCode::from(2) }
        };
    }
    if arguments.first().is_some_and(|argument| matches!(argument.as_str(), "log" | "blame")) {
        return match source_history::run(&arguments[1..], arguments[0] == "blame") {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => { eprintln!("fg: {error}"); ExitCode::from(2) }
        };
    }
    // Read-only artifact inspection is independent of the Linux host-tool adapter.
    if arguments.first().is_some_and(|argument| argument == "workspace" || argument == "merge")
        && arguments.get(1).is_some_and(|argument| argument == "inspect")
    {
        return match source_review::inspect_bundle(&arguments[2..], arguments[0] == "merge") {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => { eprintln!("fg: {error}"); ExitCode::from(2) }
        };
    }
    let pr_diff = arguments.first().is_some_and(|argument| argument == "pr")
        && arguments.get(1).is_some_and(|argument| argument == "diff");
    if pr_diff || arguments.first().is_some_and(|argument| argument == "diff") {
        return match source_review::run(&arguments[if pr_diff { 2 } else { 1 }..], pr_diff) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => { eprintln!("fg: {error}"); ExitCode::from(2) }
        };
    }
    if arguments.first().is_some_and(|argument| argument == "pr") {
        return match pull_request::run(&arguments[1..]) {
            Ok(code) => ExitCode::from(code),
            Err(error) => { eprintln!("fg: {error}"); ExitCode::from(2) }
        };
    }
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
