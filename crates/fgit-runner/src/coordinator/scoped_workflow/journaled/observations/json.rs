//! Decoder for the exact version-one WorkflowReport emitter, not general JSON.
use super::{MAX_JOB_BYTES, ObservationRefusal, checkpoint, commitment, valid_job};
use crate::Commitment;
use crate::workflow::{
    JobOutcome, JobReport, MAX_JOBS, MAX_STEPS, StepObservation, StepOutcome, StepReport,
    WorkerFailure, WorkflowLimits, WorkflowReport,
};
use std::time::Duration;

type Result<T> = std::result::Result<T, ObservationRefusal>;
const BAD: ObservationRefusal = ObservationRefusal::InvalidReport;
const MAX_NAME_BYTES: usize = fgit_schema::workflow::Limits::DEFAULT.max_scalar_bytes;

pub(super) fn report(
    bytes: &[u8],
    step_timeout: Duration,
    run_timeout: Duration,
    live: &dyn Fn() -> bool,
) -> Result<WorkflowReport> {
    let mut input = Json {
        bytes,
        position: 0,
        live,
    };
    input.literal(br#"{"schema_version":1,"profile":"trusted-local-foreground-v1","authoritative_check":false,"workflow_source":"#)?;
    let source = input.root()?;
    input.literal(b",\"workflow_graph\":")?;
    let graph = input.root()?;
    input.literal(b",\"shell\":\"/bin/sh\",\"shell_flags\":[\"-eu\",\"-c\"],\"environment\":{\"PATH\":\"/usr/bin:/bin\",\"LANG\":\"C\"},\"step_timeout_millis\":")?;
    if u128::from(input.number()?) != step_timeout.as_millis() {
        return Err(BAD);
    }
    input.literal(b",\"run_timeout_millis\":")?;
    if u128::from(input.number()?) != run_timeout.as_millis() {
        return Err(BAD);
    }
    input.literal(b",\"stream_bytes\":")?;
    let stream_bytes = input.size()?;
    input.literal(b",\"total_output_bytes\":")?;
    let total_output_bytes = input.size()?;
    let limits = WorkflowLimits {
        step_timeout,
        run_timeout,
        stream_bytes,
        total_output_bytes,
    };
    limits.validate().map_err(|_| BAD)?;
    input.literal(b",\"succeeded\":")?;
    let succeeded = input.boolean()?;
    input.literal(b",\"jobs\":[")?;
    let mut jobs = Vec::new();
    let mut remaining_output = limits.total_output_bytes;
    let mut remaining_steps = MAX_STEPS;
    if input.peek() != Some(b']') {
        loop {
            checkpoint(live)?;
            if jobs.len() == MAX_JOBS {
                return Err(BAD);
            }
            jobs.try_reserve(1)
                .map_err(|_| ObservationRefusal::AllocationFailed)?;
            jobs.push(input.job(limits, &mut remaining_output, &mut remaining_steps)?);
            if input.peek() == Some(b']') {
                break;
            }
            input.literal(b",")?;
        }
    }
    input.literal(b"]}")?;
    let report = WorkflowReport {
        source,
        graph,
        limits,
        jobs,
    };
    if input.position != bytes.len() || report.succeeded() != succeeded {
        return Err(BAD);
    }
    Ok(report)
}

struct Json<'a> {
    bytes: &'a [u8],
    position: usize,
    live: &'a dyn Fn() -> bool,
}
impl Json<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }
    fn literal(&mut self, literal: &[u8]) -> Result<()> {
        if !self.bytes[self.position..].starts_with(literal) {
            return Err(BAD);
        }
        self.position += literal.len();
        Ok(())
    }
    fn boolean(&mut self) -> Result<bool> {
        if self.peek() == Some(b't') {
            self.literal(b"true")?;
            Ok(true)
        } else {
            self.literal(b"false")?;
            Ok(false)
        }
    }
    fn number(&mut self) -> Result<u64> {
        let start = self.position;
        let mut value = 0u64;
        while let Some(byte @ b'0'..=b'9') = self.peek() {
            if self.position - start == 20 {
                return Err(BAD);
            }
            value = value
                .checked_mul(10)
                .and_then(|n| n.checked_add(u64::from(byte - b'0')))
                .ok_or(BAD)?;
            self.position += 1;
        }
        if start == self.position || (self.position - start > 1 && self.bytes[start] == b'0') {
            return Err(BAD);
        }
        Ok(value)
    }
    fn size(&mut self) -> Result<usize> {
        usize::try_from(self.number()?).map_err(|_| BAD)
    }
    fn exit(&mut self) -> Result<Option<i32>> {
        if self.peek() == Some(b'n') {
            self.literal(b"null")?;
            return Ok(None);
        }
        let negative = self.peek() == Some(b'-');
        if negative {
            self.position += 1;
        }
        let absolute = i64::try_from(self.number()?).map_err(|_| BAD)?;
        let value = if negative { -absolute } else { absolute };
        Ok(Some(i32::try_from(value).map_err(|_| BAD)?))
    }
    fn text(&mut self, maximum: usize) -> Result<String> {
        self.literal(b"\"")?;
        let mut result = Vec::new();
        loop {
            if self.position % 1024 == 0 {
                checkpoint(self.live)?;
            }
            let byte = self.peek().ok_or(BAD)?;
            self.position += 1;
            if byte == b'"' {
                break;
            }
            let decoded = match byte {
                0..=31 => return Err(BAD),
                b'\\' => {
                    let escaped = self.peek().ok_or(BAD)?;
                    self.position += 1;
                    match escaped {
                        b'"' | b'\\' => escaped,
                        b'u' => {
                            // The emitter escapes only U+0000..U+001F. Other
                            // scalars are UTF-8, not surrogate or escape aliases.
                            self.literal(b"00")?;
                            let high = nibble(self.peek().ok_or(BAD)?)?;
                            self.position += 1;
                            let low = nibble(self.peek().ok_or(BAD)?)?;
                            self.position += 1;
                            let value = high * 16 + low;
                            if value >= 32 {
                                return Err(BAD);
                            }
                            value
                        }
                        _ => return Err(BAD),
                    }
                }
                byte => byte,
            };
            if result.len() == maximum {
                return Err(BAD);
            }
            result
                .try_reserve(1)
                .map_err(|_| ObservationRefusal::AllocationFailed)?;
            result.push(decoded);
        }
        String::from_utf8(result).map_err(|_| BAD)
    }
    fn optional_text(&mut self, maximum: usize) -> Result<Option<String>> {
        if self.peek() == Some(b'n') {
            self.literal(b"null")?;
            Ok(None)
        } else {
            self.text(maximum).map(Some)
        }
    }
    fn root(&mut self) -> Result<Commitment> {
        let text = self.text(128)?;
        // Display's tagged digest spelling remains owned by fgit-crypto. Only
        // its final fixed-width hex field is decoded, then the whole spelling
        // is checked against that same Display implementation.
        let hex = text.rsplit(':').next().ok_or(BAD)?.as_bytes();
        if hex.len() != 64 {
            return Err(BAD);
        }
        let mut bytes = [0u8; 32];
        for (slot, pair) in bytes.iter_mut().zip(hex.chunks_exact(2)) {
            *slot = nibble(pair[0])? * 16 + nibble(pair[1])?;
        }
        let root = commitment(&bytes)?;
        if root.to_string() != text {
            return Err(BAD);
        }
        Ok(root)
    }
    fn output(&mut self, maximum: usize, remaining: &mut usize) -> Result<Vec<u8>> {
        self.literal(b"\"")?;
        // Scan the borrowed field before any allocation. No escaped hex and
        // no odd nibble or alternate-case spelling can hide a different body.
        let start = self.position;
        let ceiling = maximum.min(*remaining).checked_mul(2).ok_or(BAD)?;
        loop {
            if self.position % 1024 == 0 {
                checkpoint(self.live)?;
            }
            let byte = self.peek().ok_or(BAD)?;
            if byte == b'"' {
                break;
            }
            if self.position - start == ceiling {
                return Err(BAD);
            }
            nibble(byte)?;
            self.position += 1;
        }
        let length = self.position - start;
        if length % 2 != 0 {
            return Err(BAD);
        }
        let mut output = Vec::new();
        output
            .try_reserve_exact(length / 2)
            .map_err(|_| ObservationRefusal::AllocationFailed)?;
        for (index, pair) in self.bytes[start..self.position].chunks_exact(2).enumerate() {
            if index % 1024 == 0 {
                checkpoint(self.live)?;
            }
            output.push(nibble(pair[0])? * 16 + nibble(pair[1])?);
        }
        self.position += 1;
        *remaining -= output.len();
        Ok(output)
    }
    fn job(
        &mut self,
        limits: WorkflowLimits,
        remaining: &mut usize,
        steps_left: &mut usize,
    ) -> Result<JobReport> {
        self.literal(b"{\"id\":")?;
        let id = self.text(MAX_JOB_BYTES)?;
        if !valid_job(&id) {
            return Err(BAD);
        }
        self.literal(b",\"outcome\":")?;
        let outcome = match self.text(32)?.as_str() {
            "succeeded" => JobOutcome::Succeeded,
            "failed" => JobOutcome::Failed,
            "skipped" => JobOutcome::Skipped,
            "cancelled" => JobOutcome::Cancelled,
            "timed_out" => JobOutcome::TimedOut,
            "output_limit" => JobOutcome::OutputLimit,
            "refused" => JobOutcome::Refused,
            _ => return Err(BAD),
        };
        self.literal(b",\"steps\":[")?;
        let mut steps: Vec<StepReport> = Vec::new();
        if self.peek() != Some(b']') {
            loop {
                checkpoint(self.live)?;
                if *steps_left == 0 {
                    return Err(BAD);
                }
                *steps_left -= 1;
                let step = self.step(limits, remaining)?;
                if steps
                    .last()
                    .is_some_and(|previous| previous.index >= step.index)
                {
                    return Err(BAD);
                }
                steps
                    .try_reserve(1)
                    .map_err(|_| ObservationRefusal::AllocationFailed)?;
                steps.push(step);
                if self.peek() == Some(b']') {
                    break;
                }
                self.literal(b",")?;
            }
        }
        self.literal(b"],\"failure\":")?;
        let failure = if self.peek() == Some(b'n') {
            self.literal(b"null")?;
            None
        } else {
            self.literal(b"{\"detail\":")?;
            let detail = self.text(4096)?;
            self.literal(b",\"workspace_retained\":")?;
            let retain_workspace = self.boolean()?;
            self.literal(b"}")?;
            Some(WorkerFailure {
                detail,
                retain_workspace,
            })
        };
        self.literal(b"}")?;
        if outcome == JobOutcome::Succeeded
            && (failure.is_some()
                || steps
                    .iter()
                    .any(|step| step.observation.outcome != StepOutcome::Succeeded))
        {
            return Err(BAD);
        }
        Ok(JobReport {
            id,
            outcome,
            steps,
            failure,
        })
    }
    fn step(&mut self, limits: WorkflowLimits, remaining: &mut usize) -> Result<StepReport> {
        self.literal(b"{\"index\":")?;
        let index = self.size()?;
        if index >= MAX_STEPS {
            return Err(BAD);
        }
        self.literal(b",\"name\":")?;
        let name = self.optional_text(MAX_NAME_BYTES)?;
        self.literal(b",\"script\":")?;
        let script = self.root()?;
        self.literal(b",\"outcome\":")?;
        let outcome = match self.text(32)?.as_str() {
            "succeeded" => StepOutcome::Succeeded,
            "failed" => StepOutcome::Failed,
            "cancelled" => StepOutcome::Cancelled,
            "timed_out" => StepOutcome::TimedOut,
            "output_limit" => StepOutcome::OutputLimit,
            "containment_failure" => StepOutcome::ContainmentFailure,
            _ => return Err(BAD),
        };
        self.literal(b",\"exit_code\":")?;
        let exit_code = self.exit()?;
        self.literal(b",\"stdout_hex\":")?;
        let stdout = self.output(limits.stream_bytes, remaining)?;
        self.literal(b",\"stderr_hex\":")?;
        let stderr = self.output(limits.stream_bytes, remaining)?;
        self.literal(b",\"elapsed_millis\":")?;
        let elapsed_millis = self.number()?;
        self.literal(b",\"output_complete\":")?;
        let output_complete = self.boolean()?;
        self.literal(b",\"workspace_retained\":")?;
        let retain_workspace = self.boolean()?;
        self.literal(b"}")?;
        if outcome == StepOutcome::Succeeded
            && (exit_code != Some(0) || !output_complete || retain_workspace)
        {
            return Err(BAD);
        }
        Ok(StepReport {
            index,
            name,
            script,
            observation: StepObservation {
                outcome,
                exit_code,
                stdout,
                stderr,
                elapsed_millis,
                output_complete,
                retain_workspace,
            },
        })
    }
}
fn nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(BAD),
    }
}
