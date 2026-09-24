//! Bounded byte-regex compiler and Thompson state-set executor.
//!
//! Each line returns its leftmost-longest span, not captures or a backtracking
//! trace. Threads are ordered by start offset; the first thread visiting a
//! state dominates later starts at that same state and input position.

pub(super) const MAX_PATTERN: usize = 256;
pub(super) const MAX_STATES: usize = 512;
pub(super) const MAX_NESTING: usize = 16;
const MAX_REPEAT: usize = 64;
const MAX_COMPILE_STEPS: usize = 8192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegexErrorKind {
    EmptyPattern,
    PatternLimit,
    StateLimit,
    CompileWorkLimit,
    NestingLimit,
    UnexpectedToken,
    UnclosedGroup,
    UnclosedClass,
    EmptyClass,
    InvalidRange,
    InvalidEscape,
    UnsupportedExtension,
    InvalidRepetition,
}

/// Offsets identify pattern bytes, never repository paths or source content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegexError {
    pub byte_offset: usize,
    pub kind: RegexErrorKind,
}
impl std::fmt::Display for RegexError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            out,
            "byte regex refused at {}: {:?}",
            self.byte_offset, self.kind
        )
    }
}
impl std::error::Error for RegexError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Bytes([u64; 4]);
impl Bytes {
    const fn empty() -> Self {
        Self([0; 4])
    }
    fn insert(&mut self, byte: u8) {
        self.0[usize::from(byte / 64)] |= 1u64 << (byte % 64);
    }
    fn contains(self, byte: u8) -> bool {
        self.0[usize::from(byte / 64)] & (1u64 << (byte % 64)) != 0
    }
    fn union(&mut self, other: Self) {
        for (held, offered) in self.0.iter_mut().zip(other.0) {
            *held |= offered;
        }
    }
    fn invert(&mut self) {
        for word in &mut self.0 {
            *word = !*word;
        }
    }
    fn ascii_fold(&mut self) {
        for byte in b'A'..=b'Z' {
            if self.contains(byte) || self.contains(byte.to_ascii_lowercase()) {
                self.insert(byte);
                self.insert(byte.to_ascii_lowercase());
            }
        }
    }
    fn single(byte: u8) -> Self {
        let mut set = Self::empty();
        set.insert(byte);
        set
    }
}
const fn word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[derive(Debug)]
enum Expr {
    Empty,
    Byte(Bytes),
    Start,
    End,
    Boundary(bool),
    Sequence(Vec<Self>),
    Alternative(Vec<Self>),
    Repeat(Box<Self>, usize, Option<usize>),
}
struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
    insensitive: bool,
}
impl Parser<'_> {
    const fn error(&self, kind: RegexErrorKind) -> RegexError {
        RegexError {
            byte_offset: self.at,
            kind,
        }
    }
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }
    fn take(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.at += 1;
        Some(byte)
    }
    fn expression(&mut self, depth: usize) -> Result<Expr, RegexError> {
        if depth > MAX_NESTING {
            return Err(self.error(RegexErrorKind::NestingLimit));
        }
        let mut alternatives = vec![self.sequence(depth)?];
        while self.peek() == Some(b'|') {
            self.at += 1;
            alternatives.push(self.sequence(depth)?);
        }
        if alternatives.len() == 1 {
            Ok(alternatives.remove(0))
        } else {
            Ok(Expr::Alternative(alternatives))
        }
    }
    fn sequence(&mut self, depth: usize) -> Result<Expr, RegexError> {
        let mut items = Vec::new();
        while self.peek().is_some_and(|byte| !matches!(byte, b')' | b'|')) {
            let atom = self.atom(depth)?;
            let repeated = match self.peek() {
                Some(b'*') => {
                    self.at += 1;
                    Expr::Repeat(Box::new(atom), 0, None)
                }
                Some(b'+') => {
                    self.at += 1;
                    Expr::Repeat(Box::new(atom), 1, None)
                }
                Some(b'?') => {
                    self.at += 1;
                    Expr::Repeat(Box::new(atom), 0, Some(1))
                }
                Some(b'{') => {
                    self.at += 1;
                    let minimum = self.decimal()?;
                    let maximum = if self.peek() == Some(b',') {
                        self.at += 1;
                        if self.peek() == Some(b'}') {
                            None
                        } else {
                            Some(self.decimal()?)
                        }
                    } else {
                        Some(minimum)
                    };
                    if self.take() != Some(b'}') || maximum.is_some_and(|n| n < minimum) {
                        return Err(self.error(RegexErrorKind::InvalidRepetition));
                    }
                    Expr::Repeat(Box::new(atom), minimum, maximum)
                }
                _ => atom,
            };
            if self
                .peek()
                .is_some_and(|byte| matches!(byte, b'*' | b'+' | b'?' | b'{'))
            {
                return Err(self.error(RegexErrorKind::InvalidRepetition));
            }
            items.push(repeated);
        }
        match items.len() {
            0 => Ok(Expr::Empty),
            1 => Ok(items.remove(0)),
            _ => Ok(Expr::Sequence(items)),
        }
    }
    fn decimal(&mut self) -> Result<usize, RegexError> {
        let begin = self.at;
        let mut value = 0usize;
        while let Some(byte @ b'0'..=b'9') = self.peek() {
            self.at += 1;
            value = value * 10 + usize::from(byte - b'0');
            if value > MAX_REPEAT {
                return Err(self.error(RegexErrorKind::InvalidRepetition));
            }
        }
        if self.at == begin {
            Err(self.error(RegexErrorKind::InvalidRepetition))
        } else {
            Ok(value)
        }
    }
    fn atom(&mut self, depth: usize) -> Result<Expr, RegexError> {
        let byte = self
            .take()
            .ok_or_else(|| self.error(RegexErrorKind::UnexpectedToken))?;
        match byte {
            b'(' => {
                if self.peek() == Some(b'?') {
                    return Err(self.error(RegexErrorKind::UnsupportedExtension));
                }
                let nested = self.expression(depth + 1)?;
                if self.take() != Some(b')') {
                    return Err(self.error(RegexErrorKind::UnclosedGroup));
                }
                Ok(nested)
            }
            b'[' => self.class(),
            b'.' => Ok(Expr::Byte(Bytes([u64::MAX; 4]))),
            b'^' => Ok(Expr::Start),
            b'$' => Ok(Expr::End),
            b'\\' if matches!(self.peek(), Some(b'b' | b'B')) => {
                Ok(Expr::Boundary(self.take() == Some(b'b')))
            }
            b'\\' => {
                let (mut bytes, _) = self.escape()?;
                if self.insensitive {
                    bytes.ascii_fold();
                }
                Ok(Expr::Byte(bytes))
            }
            b')' | b'*' | b'+' | b'?' | b'{' | b'}' | b']' | b'\n' => {
                Err(self.error(RegexErrorKind::UnexpectedToken))
            }
            _ => {
                let mut bytes = Bytes::single(byte);
                if self.insensitive {
                    bytes.ascii_fold();
                }
                Ok(Expr::Byte(bytes))
            }
        }
    }
    fn escape(&mut self) -> Result<(Bytes, Option<u8>), RegexError> {
        let escaped = self
            .take()
            .ok_or_else(|| self.error(RegexErrorKind::InvalidEscape))?;
        let byte = match escaped {
            b'x' => {
                let mut value = 0;
                for _ in 0..2 {
                    let digit = match self.take() {
                        Some(b @ b'0'..=b'9') => b - b'0',
                        Some(b @ b'a'..=b'f') => b - b'a' + 10,
                        Some(b @ b'A'..=b'F') => b - b'A' + 10,
                        _ => return Err(self.error(RegexErrorKind::InvalidEscape)),
                    };
                    value = (value << 4) | digit;
                }
                value
            }
            b'd' | b'D' | b'w' | b'W' | b's' | b'S' => {
                let mut set = Bytes::empty();
                for byte in 0..=u8::MAX {
                    let yes = match escaped.to_ascii_lowercase() {
                        b'd' => byte.is_ascii_digit(),
                        b'w' => word(byte),
                        _ => matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | 11 | 12),
                    };
                    if yes {
                        set.insert(byte);
                    }
                }
                if escaped.is_ascii_uppercase() {
                    set.invert();
                }
                return Ok((set, None));
            }
            b'n' => b'\n',
            b'r' => b'\r',
            b't' => b'\t',
            b'0' => 0,
            b'a' => 7,
            b'b' => 8,
            b'f' => 12,
            b'v' => 11,
            b if b.is_ascii_punctuation() => b,
            _ => return Err(self.error(RegexErrorKind::InvalidEscape)),
        };
        Ok((Bytes::single(byte), Some(byte)))
    }
    fn class_item(&mut self) -> Result<(Bytes, Option<u8>), RegexError> {
        match self.take() {
            Some(b'\\') => self.escape(),
            Some(b'[') if self.peek() == Some(b':') => {
                Err(self.error(RegexErrorKind::UnsupportedExtension))
            }
            Some(b'\n') | None => Err(self.error(RegexErrorKind::UnclosedClass)),
            Some(byte) => Ok((Bytes::single(byte), Some(byte))),
        }
    }
    fn class(&mut self) -> Result<Expr, RegexError> {
        let negated = self.peek() == Some(b'^');
        if negated {
            self.at += 1;
        }
        let mut bytes = Bytes::empty();
        let mut count = 0usize;
        loop {
            if self.peek() == Some(b']') {
                self.at += 1;
                if count == 0 {
                    return Err(self.error(RegexErrorKind::EmptyClass));
                }
                break;
            }
            if self.peek().is_none() {
                return Err(self.error(RegexErrorKind::UnclosedClass));
            }
            if self
                .bytes
                .get(self.at..self.at + 2)
                .is_some_and(|v| v == b"&&" || v == b"--")
            {
                return Err(self.error(RegexErrorKind::UnsupportedExtension));
            }
            let (item, first) = self.class_item()?;
            if self.peek() == Some(b'-') && self.bytes.get(self.at + 1) != Some(&b']') {
                self.at += 1;
                let (_, last) = self.class_item()?;
                let (Some(first), Some(last)) = (first, last) else {
                    return Err(self.error(RegexErrorKind::InvalidRange));
                };
                if first > last {
                    return Err(self.error(RegexErrorKind::InvalidRange));
                }
                for byte in first..=last {
                    bytes.insert(byte);
                }
            } else {
                bytes.union(item);
            }
            count += 1;
        }
        // Fold the positive set BEFORE complementing it: [^a] must exclude A.
        if self.insensitive {
            bytes.ascii_fold();
        }
        if negated {
            bytes.invert();
        }
        Ok(Expr::Byte(bytes))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Byte(Bytes, usize),
    Split(usize, usize),
    Start(usize),
    End(usize),
    Boundary(bool, usize),
    Accept,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Program {
    states: Vec<State>,
    start: usize,
}
impl Program {
    pub(super) fn compile(pattern: &[u8], insensitive: bool) -> Result<Self, RegexError> {
        if pattern.is_empty() || pattern.len() > MAX_PATTERN {
            return Err(RegexError {
                byte_offset: 0,
                kind: if pattern.is_empty() {
                    RegexErrorKind::EmptyPattern
                } else {
                    RegexErrorKind::PatternLimit
                },
            });
        }
        let mut parser = Parser {
            bytes: pattern,
            at: 0,
            insensitive,
        };
        let expression = parser.expression(0)?;
        if parser.at != pattern.len() {
            return Err(parser.error(RegexErrorKind::UnexpectedToken));
        }
        let mut program = Self {
            states: vec![State::Accept],
            start: 0,
        };
        let mut work = 0;
        program.start = program.compile_expr(&expression, 0, &mut work)?;
        Ok(program)
    }
    pub(super) const fn states(&self) -> usize {
        self.states.len()
    }
    fn emit(&mut self, state: State) -> Result<usize, RegexError> {
        if self.states.len() == MAX_STATES {
            return Err(RegexError {
                byte_offset: 0,
                kind: RegexErrorKind::StateLimit,
            });
        }
        let at = self.states.len();
        self.states.push(state);
        Ok(at)
    }
    fn compile_expr(
        &mut self,
        expr: &Expr,
        next: usize,
        work: &mut usize,
    ) -> Result<usize, RegexError> {
        // Empty/zero-count expressions can expand without emitting a state.
        // State bounds alone therefore do not bound nested repetition work.
        if *work == MAX_COMPILE_STEPS {
            return Err(RegexError {
                byte_offset: 0,
                kind: RegexErrorKind::CompileWorkLimit,
            });
        }
        *work += 1;
        match expr {
            Expr::Empty => Ok(next),
            Expr::Byte(bytes) => self.emit(State::Byte(*bytes, next)),
            Expr::Start => self.emit(State::Start(next)),
            Expr::End => self.emit(State::End(next)),
            Expr::Boundary(positive) => self.emit(State::Boundary(*positive, next)),
            Expr::Sequence(items) => {
                let mut start = next;
                for item in items.iter().rev() {
                    start = self.compile_expr(item, start, work)?;
                }
                Ok(start)
            }
            Expr::Alternative(items) => {
                let mut start = self.compile_expr(&items[0], next, work)?;
                for item in &items[1..] {
                    let branch = self.compile_expr(item, next, work)?;
                    start = self.emit(State::Split(start, branch))?;
                }
                Ok(start)
            }
            Expr::Repeat(item, minimum, maximum) => {
                let mut start = next;
                if let Some(maximum) = maximum {
                    for _ in *minimum..*maximum {
                        let branch = self.compile_expr(item, start, work)?;
                        start = self.emit(State::Split(branch, start))?;
                    }
                    for _ in 0..*minimum {
                        start = self.compile_expr(item, start, work)?;
                    }
                } else {
                    let split = self.emit(State::Split(next, next))?;
                    let body = self.compile_expr(item, split, work)?;
                    self.states[split] = State::Split(body, next);
                    start = if *minimum == 0 { split } else { body };
                    for _ in 1..*minimum {
                        start = self.compile_expr(item, start, work)?;
                    }
                }
                Ok(start)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ScanError {
    Cancelled,
    WorkLimit,
    Allocation,
}
pub(super) struct Budget {
    pub used: u64,
    pub maximum: u64,
}
impl Budget {
    fn charge(&mut self, cancelled: &dyn Fn() -> bool) -> Result<(), ScanError> {
        if self.used.is_multiple_of(1024) && cancelled() {
            return Err(ScanError::Cancelled);
        }
        if self.used == self.maximum {
            return Err(ScanError::WorkLimit);
        }
        self.used += 1;
        Ok(())
    }
}
#[derive(Clone, Copy)]
struct Thread {
    state: usize,
    start: usize,
}

/// Allocated once per source search and reused across every LF-delimited line.
/// There are no source-length-sized VM tables, captures or recursion at run time.
pub(super) struct Runner<'a> {
    program: &'a Program,
    seen: Vec<u64>,
    epoch: u64,
    seeds: Vec<Thread>,
    next: Vec<Thread>,
    active: Vec<Thread>,
    stack: Vec<Thread>,
}
fn reserved<T>(capacity: usize) -> Result<Vec<T>, ScanError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| ScanError::Allocation)?;
    Ok(values)
}
impl<'a> Runner<'a> {
    pub(super) fn new(program: &'a Program) -> Result<Self, ScanError> {
        let n = program.states();
        let mut seen = reserved(n)?;
        seen.resize(n, 0);
        Ok(Self {
            program,
            seen,
            epoch: 0,
            seeds: reserved(n + 1)?,
            next: reserved(n + 1)?,
            active: reserved(n)?,
            stack: reserved(n * 2 + 2)?,
        })
    }
    pub(super) fn find_line(
        &mut self,
        bytes: &[u8],
        budget: &mut Budget,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Option<(usize, usize)>, ScanError> {
        if cancelled() {
            return Err(ScanError::Cancelled);
        }
        self.seeds.clear();
        let mut best: Option<(usize, usize)> = None;
        for position in 0..=bytes.len() {
            budget.charge(cancelled)?;
            // The overall search budget bounds epochs well below u64::MAX.
            self.epoch += 1;
            if best.is_none() {
                self.seeds.push(Thread {
                    state: self.program.start,
                    start: position,
                });
            }
            self.active.clear();
            for &seed in &self.seeds {
                if best.is_some_and(|(start, _)| seed.start > start) {
                    continue;
                }
                self.stack.clear();
                self.stack.push(seed);
                while let Some(thread) = self.stack.pop() {
                    budget.charge(cancelled)?;
                    if self.seen[thread.state] == self.epoch {
                        continue;
                    }
                    self.seen[thread.state] = self.epoch;
                    let mut follow = |state| {
                        self.stack.push(Thread {
                            state,
                            start: thread.start,
                        });
                    };
                    match self.program.states[thread.state] {
                        State::Byte(_, _) => self.active.push(thread),
                        State::Split(left, right) => {
                            follow(right);
                            follow(left);
                        }
                        State::Start(next) if position == 0 => follow(next),
                        State::End(next) if position == bytes.len() => follow(next),
                        State::Boundary(positive, next) => {
                            let left = position.checked_sub(1).is_some_and(|at| word(bytes[at]));
                            let right = bytes.get(position).is_some_and(|byte| word(*byte));
                            if (left != right) == positive {
                                follow(next);
                            }
                        }
                        State::Accept
                            if best.is_none_or(|(start, end)| {
                                thread.start < start || (thread.start == start && position > end)
                            }) =>
                        {
                            best = Some((thread.start, position));
                        }
                        _ => {}
                    }
                }
            }
            self.next.clear();
            if let Some(&byte) = bytes.get(position) {
                for thread in &self.active {
                    budget.charge(cancelled)?;
                    if best.is_some_and(|(start, _)| thread.start > start) {
                        continue;
                    }
                    if let State::Byte(set, next) = self.program.states[thread.state]
                        && set.contains(byte)
                    {
                        self.next.push(Thread {
                            state: next,
                            start: thread.start,
                        });
                    }
                }
            }
            std::mem::swap(&mut self.seeds, &mut self.next);
        }
        if cancelled() {
            return Err(ScanError::Cancelled);
        }
        Ok(best)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn find(pattern: &[u8], bytes: &[u8], insensitive: bool) -> Option<(usize, usize)> {
        let program = Program::compile(pattern, insensitive).unwrap();
        Runner::new(&program)
            .unwrap()
            .find_line(
                bytes,
                &mut Budget {
                    used: 0,
                    maximum: 10_000_000,
                },
                &|| false,
            )
            .unwrap()
    }
    #[test]
    fn leftmost_longest_not_alternation_order_or_last_start() {
        for pattern in [b"a|ab+".as_slice(), b"ab+|a", b"(a|ab+)"] {
            assert_eq!(find(pattern, b"xxabbb ax", false), Some((2, 6)));
        }
        assert_eq!(find(b"a.*z|b", b"abzz", false), Some((0, 4)));
        assert_eq!(find(b"a.*z|b", b"abc", false), Some((1, 2)));
        assert_eq!(find(b"a*", b"bbb", false), Some((0, 0)));
        assert_eq!(find(b"(a*)*", b"aaa", false), Some((0, 3)));
    }
    #[test]
    fn anchors_boundaries_binary_and_ascii_case_are_byte_exact() {
        assert_eq!(
            find(br"^\w+\s+\d{2,3}$", b"item_1 \t123", false),
            Some((0, 11))
        );
        assert_eq!(find(br"\bfoo\b", b"xfoo foo_", false), None);
        assert_eq!(find(br"\bfoo\b", b"xfoo foo!", false), Some((5, 8)));
        assert_eq!(find(br"\Bfoo", b"xfoo", false), Some((1, 4)));
        assert_eq!(
            find(br"^\x00[\x80-\xff]+$", &[0, 128, 255], false),
            Some((0, 3))
        );
        assert_eq!(find(br"[^a]+", b"AAaBc", true), Some((3, 5)));
        assert_eq!(find(br"^[a-z]+$", b"AbC", true), Some((0, 3)));
        assert_eq!(find(br"^x$", b"x\r", false), None);
        assert_eq!(find(br"^x\r?$", b"x\r", false), Some((0, 2)));
        assert_eq!(find("é".as_bytes(), "É".as_bytes(), true), None);
    }
    #[test]
    fn finite_and_unbounded_repetition_preserve_empty_alternatives() {
        assert_eq!(find(b"ab{2,4}c", b"abbbbc abbc", false), Some((0, 6)));
        assert_eq!(find(b"(ab){2,}", b"xababab", false), Some((1, 7)));
        assert_eq!(find(b"^a{0}b$", b"b", false), Some((0, 1)));
        assert_eq!(find(b"(|a)+", b"aa", false), Some((0, 2)));
        assert_eq!(find(b"^$", b"", false), Some((0, 0)));
        assert_eq!(find(b"(a?)*b", b"aaab", false), Some((0, 4)));
        assert_eq!(find(b"[a-c-]+", b"abc--z", false), Some((0, 5)));
        assert_eq!(find(br"[\]\[]+", b"[]", false), Some((0, 2)));
    }
    #[test]
    fn malformed_or_unsupported_patterns_never_become_literals() {
        for pattern in [
            b"".as_slice(),
            b"(",
            b")",
            b"[",
            b"[]",
            b"[^]",
            b"[z-a]",
            br"\",
            br"\1",
            br"\p{L}",
            br"\x0",
            br"\xgg",
            b"(?=a)",
            b"(?:a)",
            b"(?i)a",
            b"a*?",
            b"a++",
            b"a{",
            b"a{65}",
            b"a{2,1}",
            b"a{,2}",
            b"*a",
            b"a\nb",
            b"[[:alpha:]]",
            b"[a&&b]",
            br"[\d-a]",
        ] {
            assert!(Program::compile(pattern, false).is_err(), "{pattern:?}");
        }
        assert_eq!(
            Program::compile(&vec![b'a'; MAX_PATTERN + 1], false)
                .unwrap_err()
                .kind,
            RegexErrorKind::PatternLimit
        );
        assert_eq!(
            Program::compile(b"((a{64}){64})", false).unwrap_err().kind,
            RegexErrorKind::StateLimit
        );
        let deep = format!(
            "{}a{}",
            "(".repeat(MAX_NESTING + 1),
            ")".repeat(MAX_NESTING + 1)
        );
        assert_eq!(
            Program::compile(deep.as_bytes(), false).unwrap_err().kind,
            RegexErrorKind::NestingLimit
        );
    }
    #[test]
    fn nested_empty_repetition_has_a_compile_work_bound_without_state_growth() {
        for pattern in [
            b"((((){64}){64}){64})".as_slice(),
            b"((((a{0}){64}){64}){64})",
            b"((((a|){0}){64}){64}){64}",
        ] {
            assert_eq!(
                Program::compile(pattern, false).unwrap_err().kind,
                RegexErrorKind::CompileWorkLimit
            );
        }
        // The corresponding bounded expansion is valid and still matches.
        assert_eq!(find(b"((){64}){64}", b"x", false), Some((0, 0)));
        assert_eq!(find(b"((a{0}){64})b", b"xb", false), Some((1, 2)));
        let mut program = Program {
            states: vec![State::Accept],
            start: 0,
        };
        let mut work = MAX_COMPILE_STEPS - 1;
        assert_eq!(program.compile_expr(&Expr::Empty, 0, &mut work).unwrap(), 0);
        assert_eq!(work, MAX_COMPILE_STEPS);
        assert_eq!(
            program
                .compile_expr(&Expr::Empty, 0, &mut work)
                .unwrap_err()
                .kind,
            RegexErrorKind::CompileWorkLimit
        );
    }
    #[test]
    fn budget_has_an_exact_permitted_twin_and_cancellation_is_not_absence() {
        let program = Program::compile(b"(a|aa)*b", false).unwrap();
        let mut runner = Runner::new(&program).unwrap();
        let bytes = vec![b'a'; 1000];
        let mut budget = Budget {
            used: 0,
            maximum: 1_000_000,
        };
        assert_eq!(
            runner.find_line(&bytes, &mut budget, &|| false).unwrap(),
            None
        );
        let used = budget.used;
        assert!(used <= (bytes.len() as u64 + 1) * (program.states() as u64 * 4 + 2));
        assert_eq!(
            runner
                .find_line(
                    &bytes,
                    &mut Budget {
                        used: 0,
                        maximum: used
                    },
                    &|| false
                )
                .unwrap(),
            None
        );
        assert_eq!(
            runner.find_line(
                &bytes,
                &mut Budget {
                    used: 0,
                    maximum: used - 1
                },
                &|| false
            ),
            Err(ScanError::WorkLimit)
        );
        assert_eq!(
            runner.find_line(
                b"a",
                &mut Budget {
                    used: 0,
                    maximum: used
                },
                &|| true
            ),
            Err(ScanError::Cancelled)
        );
        let polls = std::cell::Cell::new(0);
        let cancel = || {
            polls.set(polls.get() + 1);
            polls.get() > 2
        };
        assert_eq!(
            runner.find_line(
                &bytes,
                &mut Budget {
                    used: 0,
                    maximum: 1_000_000
                },
                &cancel
            ),
            Err(ScanError::Cancelled)
        );
    }
    #[test]
    fn ambiguous_patterns_do_not_create_exponential_threads() {
        for size in [8, 64, 1024] {
            for pattern in [b"(a+)+b".as_slice(), b"(a|aa)*b", b"((a?)*)*b"] {
                let program = Program::compile(pattern, false).unwrap();
                let mut runner = Runner::new(&program).unwrap();
                let mut budget = Budget {
                    used: 0,
                    maximum: 1_000_000,
                };
                assert_eq!(
                    runner
                        .find_line(&vec![b'a'; size], &mut budget, &|| false)
                        .unwrap(),
                    None
                );
                assert!(budget.used <= (size as u64 + 1) * (program.states() as u64 * 4 + 2));
            }
        }
    }
    #[test]
    fn literal_programs_agree_with_independent_scalar_windows() {
        for size in 0..8 {
            for bits in 0..(1usize << size) {
                let bytes: Vec<_> = (0..size)
                    .map(|i| if bits & (1 << i) == 0 { b'a' } else { b'B' })
                    .collect();
                for pattern in [b"a".as_slice(), b"B", b"aa", b"AbA", b"BBBB"] {
                    for insensitive in [false, true] {
                        let expected = bytes
                            .windows(pattern.len())
                            .position(|candidate| {
                                candidate.iter().zip(pattern).all(|(a, b)| {
                                    if insensitive {
                                        a.eq_ignore_ascii_case(b)
                                    } else {
                                        a == b
                                    }
                                })
                            })
                            .map(|start| (start, start + pattern.len()));
                        assert_eq!(find(pattern, &bytes, insensitive), expected);
                    }
                }
            }
        }
    }
}
