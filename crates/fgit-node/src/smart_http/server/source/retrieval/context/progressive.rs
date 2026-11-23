//! Ranked context streaming over one exact, authorized Initial report.
use super::{
    ApiError, OneNode, SourceReadContext, Status, command_fields, quote, ranked, run_context,
};
use std::io::Write;

const INITIAL: &str = r#"{"phase":"Initial","answer":"#;
const REFINED: &str = r#"{"phase":"Refined","answer":"#;
const FAILED: &str = r#"{"phase":"RefinementFailed","code":"#;
// ApiError codes are static identifiers. Reserve a terminal record before any
// Initial bytes are sent, including the closing brace and newline of each row.
const ERROR_RESERVE: usize = 128;
const END: &str = "}\n";
pub(super) struct ProgressOutput<'a> {
    writer: &'a mut dyn Write,
    remaining: usize,
    initial_sent: bool,
}
impl ProgressOutput<'_> {
    fn record(&mut self, prefix: &str, json: &str) -> Result<(), ApiError> {
        let remaining = self
            .remaining
            .checked_sub(prefix.len())
            .and_then(|n| n.checked_sub(json.len()))
            .and_then(|n| n.checked_sub(END.len()))
            .ok_or_else(ApiError::too_large)?;
        for part in [prefix, json, END] {
            self.writer
                .write_all(part.as_bytes())
                .map_err(|_| ApiError::new(Status::Unavailable, "source_output_failed"))?;
        }
        self.writer
            .flush()
            .map_err(|_| ApiError::new(Status::Unavailable, "source_output_failed"))?;
        self.remaining = remaining;
        Ok(())
    }
    pub(super) fn initial(&mut self, document: &str) -> Result<usize, ApiError> {
        self.record(INITIAL, document)?;
        self.initial_sent = true;
        self.remaining
            .checked_sub(REFINED.len() + END.len())
            .ok_or_else(ApiError::too_large)
    }
}

impl OneNode {
    /// Flush the exact Initial answer to a host-authorized sink before ranking
    /// its original rows and reading selected excerpts. The second NDJSON record
    /// is Refined or RefinementFailed. Invalid Initial requests emit no record.
    /// A sink failure ends delivery. The single output budget covers both rows.
    /// The return value is the ranked context's completeness flag.
    pub fn write_progressive_source_context(
        &self,
        read: &SourceReadContext,
        fields: Vec<(String, String)>,
        maximum: usize,
        writer: &mut impl Write,
    ) -> Result<bool, &'static str> {
        let mut fields = super::super::source_fields(self, read, fields)?;
        if !fields.iter().any(|(key, _)| key == "context_selection") {
            fields.push(("context_selection".into(), ranked::PROFILE.into()));
        }
        let command = command_fields(fields, self.object_format).map_err(|error| error.code)?;
        if !command.ranked {
            return Err("unsupported_context_selection");
        }
        let initial_maximum = maximum
            .checked_sub(INITIAL.len() + END.len() + FAILED.len() + ERROR_RESERVE + END.len())
            .ok_or_else(|| ApiError::too_large().code)?;
        let mut stream = ProgressOutput {
            writer,
            remaining: maximum,
            initial_sent: false,
        };
        match run_context(self, read, &command, initial_maximum, Some(&mut stream)) {
            Ok((document, complete)) => {
                stream
                    .record(REFINED, &document)
                    .map_err(|error| error.code)?;
                Ok(complete)
            }
            Err(error) => {
                if stream.initial_sent {
                    let code = quote(error.code);
                    let code = if code.len() <= ERROR_RESERVE {
                        &code
                    } else {
                        r#""refinement_failed""#
                    };
                    stream.record(FAILED, code).map_err(|error| error.code)?;
                }
                Err(error.code)
            }
        }
    }
}
