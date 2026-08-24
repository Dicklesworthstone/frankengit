#![forbid(unsafe_code)]
//! A std-only child-process consumer for verified-read frames.

use std::io::{self, Read};
use std::process::ExitCode;

const MAX_INPUT: u64 = (1 << 20) + 1;
const VERIFIED_READ_DOMAIN: &str = "frankengit/verified-read-envelope/v1";
const VERIFIED_READ_FAMILY: &str = "verified-read-envelope";

fn main() -> ExitCode {
    let max_input = usize::try_from(MAX_INPUT).expect("1 MiB bound fits supported platforms");
    let mut bytes = Vec::new();
    if let Err(error) = io::stdin().take(MAX_INPUT).read_to_end(&mut bytes) {
        eprintln!("verified-read-frame: could not read stdin: {error}");
        return ExitCode::from(1);
    }
    if bytes.len() == max_input {
        eprintln!("verified-read-frame: input exceeds the 1 MiB frame bound");
        return ExitCode::from(1);
    }

    let frame = match fgit_codec_verify::parse_frame(&bytes) {
        Ok(frame) => frame,
        Err(error) => {
            eprintln!("verified-read-frame: frame refused: {error}");
            return ExitCode::from(1);
        }
    };
    if frame.domain != VERIFIED_READ_DOMAIN || frame.family != VERIFIED_READ_FAMILY {
        eprintln!(
            "verified-read-frame: expected {VERIFIED_READ_DOMAIN}/{VERIFIED_READ_FAMILY}, got {}/{}",
            frame.domain, frame.family
        );
        return ExitCode::from(1);
    }

    println!(
        "{}|{}|{}|{}|{}",
        frame.domain,
        frame.family,
        frame.schema_major,
        frame.schema_minor,
        frame.payload.len()
    );
    ExitCode::SUCCESS
}
