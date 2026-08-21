#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match fgit_cli::run(&arguments) {
        Ok(fgit_cli::CliOutcome::Initialized(fgit_node::NodeInitialization::Created)) => {
            println!("initialized authority head");
            ExitCode::SUCCESS
        }
        Ok(fgit_cli::CliOutcome::Initialized(fgit_node::NodeInitialization::IdenticalRetry)) => {
            println!("authority head already initialized");
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
        Err(error) => {
            eprintln!("fg: {error}");
            ExitCode::from(2)
        }
    }
}
