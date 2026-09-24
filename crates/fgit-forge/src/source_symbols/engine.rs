#![forbid(unsafe_code)]
//! `rust-declaration-heads-v1`: source-level declaration heads, NOT compiler
//! name resolution or macro expansion. ASCII names; comments/string contents
//! may be UTF-8. Attributes and macro token trees are opaque. All configurations
//! are searched, including cfg-disabled source. No source code is executed.

pub const MAX_WORK: u64 = 64 * 1024 * 1024;
pub const MAX_FILE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_DECLARATIONS: usize = 20_000;
pub const MAX_NAME_BYTES: usize = 128;
const MAX_DEPTH: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Function,
    Struct,
    Enum,
    Trait,
    Type,
    Module,
    Union,
    Macro,
}
impl Kind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Function => "function",
            Self::Struct => "struct",
            Self::Enum => "enum",
            Self::Trait => "trait",
            Self::Type => "type",
            Self::Module => "module",
            Self::Union => "union",
            Self::Macro => "macro",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    Cancelled,
    WorkLimit,
    FileLimit,
    DepthLimit,
    DeclarationLimit,
    NameLimit,
    InvalidUtf8,
    UnsupportedIdentifier,
    UnterminatedComment,
    UnterminatedLiteral,
    UnbalancedDelimiter,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error {
    pub kind: ErrorKind,
    pub byte_offset: usize,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Rust declaration scan refused at byte {}: {:?}",
            self.byte_offset, self.kind
        )
    }
}
impl std::error::Error for Error {}

/// Coordinates cover only the name, excluding a raw identifier's `r#` prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Declaration {
    pub kind: Kind,
    pub byte_offset: usize,
    pub byte_length: usize,
    pub line: usize,
    pub byte_column: usize,
    pub raw_identifier: bool,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Scan {
    pub declarations: Vec<Declaration>,
    pub macro_bodies_skipped: usize,
    pub attributes_skipped: usize,
}
/// Shared across every file in a query; callers may narrow but not widen it.
#[derive(Clone, Debug)]
pub struct Budget {
    maximum: u64,
    pub work: u64,
    pub declarations: usize,
}
impl Budget {
    pub const fn new(maximum: u64) -> Result<Self, Error> {
        if maximum == 0 || maximum > MAX_WORK {
            return Err(Error {
                kind: ErrorKind::WorkLimit,
                byte_offset: 0,
            });
        }
        Ok(Self {
            maximum,
            work: 0,
            declarations: 0,
        })
    }
    fn charge(&mut self, n: usize, at: usize, cancelled: &dyn Fn() -> bool) -> Result<(), Error> {
        if cancelled() {
            return Err(Error {
                kind: ErrorKind::Cancelled,
                byte_offset: at,
            });
        }
        self.work = self
            .work
            .checked_add(n as u64)
            .filter(|w| *w <= self.maximum)
            .ok_or(Error {
                kind: ErrorKind::WorkLimit,
                byte_offset: at,
            })?;
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TokenKind {
    Word(bool),
    Punct(u8),
    Opaque,
}
#[derive(Clone, Copy, Debug)]
struct Token {
    kind: TokenKind,
    start: usize,
    end: usize,
    line: usize,
    column: usize,
}
impl Token {
    fn text(self, bytes: &[u8]) -> &[u8] {
        &bytes[self.start..self.end]
    }
    fn punct(self, byte: u8) -> bool {
        self.kind == TokenKind::Punct(byte)
    }
    fn word(self, bytes: &[u8], text: &[u8]) -> bool {
        self.kind == TokenKind::Word(false) && self.text(bytes) == text
    }
}
const fn start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}
const fn continuation(b: u8) -> bool {
    start(b) || b.is_ascii_digit()
}
const fn keyword(bytes: &[u8]) -> bool {
    matches!(
        bytes,
        b"as"
            | b"async"
            | b"await"
            | b"break"
            | b"const"
            | b"continue"
            | b"crate"
            | b"dyn"
            | b"else"
            | b"enum"
            | b"extern"
            | b"false"
            | b"fn"
            | b"for"
            | b"if"
            | b"impl"
            | b"in"
            | b"let"
            | b"loop"
            | b"match"
            | b"mod"
            | b"move"
            | b"mut"
            | b"pub"
            | b"ref"
            | b"return"
            | b"self"
            | b"Self"
            | b"static"
            | b"struct"
            | b"super"
            | b"trait"
            | b"true"
            | b"type"
            | b"unsafe"
            | b"use"
            | b"where"
            | b"while"
            | b"abstract"
            | b"become"
            | b"box"
            | b"do"
            | b"final"
            | b"gen"
            | b"macro"
            | b"override"
            | b"priv"
            | b"try"
            | b"typeof"
            | b"unsized"
            | b"virtual"
            | b"yield"
    )
}
fn identifier(token: Token, bytes: &[u8]) -> bool {
    match token.kind {
        TokenKind::Word(raw) => token.text(bytes) != b"_" && (raw || !keyword(token.text(bytes))),
        _ => false,
    }
}
const fn close(open: u8) -> Option<u8> {
    match open {
        b'(' => Some(b')'),
        b'[' => Some(b']'),
        b'{' => Some(b'}'),
        _ => None,
    }
}
struct Lexer<'a, 'b> {
    bytes: &'a [u8],
    at: usize,
    line: usize,
    line_start: usize,
    budget: &'b mut Budget,
    cancelled: &'b dyn Fn() -> bool,
    look: Option<Token>,
}
impl Lexer<'_, '_> {
    const fn error(&self, kind: ErrorKind) -> Error {
        Error {
            kind,
            byte_offset: self.at,
        }
    }
    fn byte(&self, n: usize) -> Option<u8> {
        self.bytes.get(n).copied()
    }
    fn bump(&mut self) -> Result<(), Error> {
        if self.at.is_multiple_of(1024) {
            self.budget.charge(0, self.at, self.cancelled)?;
        }
        self.budget.work = self
            .budget
            .work
            .checked_add(1)
            .filter(|w| *w <= self.budget.maximum)
            .ok_or_else(|| self.error(ErrorKind::WorkLimit))?;
        if self.byte(self.at) == Some(b'\n') {
            self.line += 1;
            self.line_start = self.at + 1;
        }
        self.at += 1;
        Ok(())
    }
    fn advance(&mut self, n: usize) -> Result<(), Error> {
        for _ in 0..n {
            self.bump()?;
        }
        Ok(())
    }
    fn comment(&mut self) -> Result<(), Error> {
        self.advance(2)?;
        let mut depth = 1;
        while self.at < self.bytes.len() {
            match (self.byte(self.at), self.byte(self.at + 1)) {
                (Some(b'/'), Some(b'*')) => {
                    if depth == MAX_DEPTH {
                        return Err(self.error(ErrorKind::DepthLimit));
                    }
                    depth += 1;
                    self.advance(2)?;
                }
                (Some(b'*'), Some(b'/')) => {
                    depth -= 1;
                    self.advance(2)?;
                    if depth == 0 {
                        return Ok(());
                    }
                }
                _ => self.bump()?,
            }
        }
        Err(self.error(ErrorKind::UnterminatedComment))
    }
    fn quoted(&mut self, quote: u8) -> Result<(), Error> {
        self.bump()?;
        while let Some(byte) = self.byte(self.at) {
            self.bump()?;
            if byte == quote {
                return Ok(());
            }
            if byte == b'\\' {
                if self.at == self.bytes.len() {
                    break;
                }
                self.bump()?;
            } else if quote == b'\'' && byte == b'\n' {
                break;
            }
        }
        Err(self.error(ErrorKind::UnterminatedLiteral))
    }
    fn raw(&mut self, prefix: usize, hashes: usize) -> Result<(), Error> {
        self.advance(prefix + hashes + 1)?;
        while let Some(byte) = self.byte(self.at) {
            if byte == b'"' {
                self.budget.charge(hashes + 1, self.at, self.cancelled)?;
                let end = self.at + 1 + hashes;
                if end <= self.bytes.len()
                    && self.bytes[self.at + 1..end].iter().all(|b| *b == b'#')
                {
                    return self.advance(hashes + 1);
                }
            }
            self.bump()?;
        }
        Err(self.error(ErrorKind::UnterminatedLiteral))
    }
    fn suffix(&mut self) -> Result<(), Error> {
        if self.byte(self.at).is_some_and(start) {
            while self.byte(self.at).is_some_and(continuation) {
                self.bump()?;
            }
        }
        if self.byte(self.at).is_some_and(|b| b >= 128) {
            return Err(self.error(ErrorKind::UnsupportedIdentifier));
        }
        Ok(())
    }
    fn next(&mut self) -> Result<Option<Token>, Error> {
        if let Some(token) = self.look.take() {
            return Ok(Some(token));
        }
        loop {
            let Some(byte) = self.byte(self.at) else {
                return Ok(None);
            };
            if byte.is_ascii_whitespace() {
                self.bump()?;
                continue;
            }
            if (byte, self.byte(self.at + 1)) == (b'/', Some(b'/')) {
                while self.byte(self.at).is_some_and(|b| b != b'\n') {
                    self.bump()?;
                }
                continue;
            }
            if (byte, self.byte(self.at + 1)) == (b'/', Some(b'*')) {
                self.comment()?;
                continue;
            }
            break;
        }
        self.budget.charge(1, self.at, self.cancelled)?;
        let from = self.at;
        let line = self.line;
        let column = from - self.line_start + 1;
        let byte = self.bytes[from];
        let raw_prefix = if byte == b'r' {
            1
        } else if matches!(byte, b'b' | b'c') && self.byte(from + 1) == Some(b'r') {
            2
        } else {
            0
        };
        if raw_prefix > 0 {
            let mut hashes = 0;
            while self.byte(from + raw_prefix + hashes) == Some(b'#') {
                if hashes == 255 {
                    return Err(self.error(ErrorKind::DepthLimit));
                }
                hashes += 1;
            }
            if self.byte(from + raw_prefix + hashes) == Some(b'"') {
                self.raw(raw_prefix, hashes)?;
                self.suffix()?;
                return Ok(Some(Token {
                    kind: TokenKind::Opaque,
                    start: from,
                    end: self.at,
                    line,
                    column,
                }));
            }
        }
        let quote = if byte == b'"' {
            Some((0, b'"'))
        } else if matches!(byte, b'b' | b'c') && self.byte(from + 1) == Some(b'"') {
            Some((1, b'"'))
        } else if byte == b'b' && self.byte(from + 1) == Some(b'\'') {
            Some((1, b'\''))
        } else {
            None
        };
        if let Some((prefix, quote)) = quote {
            self.advance(prefix)?;
            self.quoted(quote)?;
            self.suffix()?;
            return Ok(Some(Token {
                kind: TokenKind::Opaque,
                start: from,
                end: self.at,
                line,
                column,
            }));
        }
        if byte == b'\'' {
            // Lifetimes/labels must not swallow later declaration heads. A
            // closing quote immediately after the name instead forms a literal.
            if self.byte(from + 1).is_some_and(start) {
                self.bump()?;
                if self.byte(self.at) == Some(b'r') && self.byte(self.at + 1) == Some(b'#') {
                    self.advance(2)?;
                }
                self.suffix()?;
                if self.byte(self.at) == Some(b'\'') {
                    self.bump()?;
                    self.suffix()?;
                }
            } else {
                if self.byte(from + 1).is_some_and(|b| b >= 128) {
                    let width = match self.bytes[from + 1] {
                        0xc0..=0xdf => 2,
                        0xe0..=0xef => 3,
                        _ => 4,
                    };
                    if self.byte(from + 1 + width) != Some(b'\'') {
                        return Err(self.error(ErrorKind::UnsupportedIdentifier));
                    }
                }
                self.quoted(b'\'')?;
                self.suffix()?;
            }
            return Ok(Some(Token {
                kind: TokenKind::Opaque,
                start: from,
                end: self.at,
                line,
                column,
            }));
        }
        if byte >= 128 {
            return Err(self.error(ErrorKind::UnsupportedIdentifier));
        }
        if start(byte) {
            let raw = byte == b'r'
                && self.byte(from + 1) == Some(b'#')
                && self.byte(from + 2).is_some_and(start);
            if raw {
                self.advance(2)?;
            }
            let name_start = self.at;
            self.suffix()?;
            if self.at - name_start > MAX_NAME_BYTES {
                return Err(self.error(ErrorKind::NameLimit));
            }
            return Ok(Some(Token {
                kind: TokenKind::Word(raw),
                start: name_start,
                end: self.at,
                line,
                column: column + usize::from(raw) * 2,
            }));
        }
        if byte.is_ascii_digit() {
            while self
                .byte(self.at)
                .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.'))
            {
                self.bump()?;
            }
            return Ok(Some(Token {
                kind: TokenKind::Opaque,
                start: from,
                end: self.at,
                line,
                column,
            }));
        }
        self.bump()?;
        Ok(Some(Token {
            kind: TokenKind::Punct(byte),
            start: from,
            end: self.at,
            line,
            column,
        }))
    }
    fn peek(&mut self) -> Result<Option<Token>, Error> {
        if self.look.is_none() {
            self.look = self.next()?;
        }
        Ok(self.look)
    }
    fn group(&mut self, open: u8) -> Result<(), Error> {
        let mut stack =
            vec![close(open).ok_or_else(|| self.error(ErrorKind::UnbalancedDelimiter))?];
        while let Some(token) = self.next()? {
            if let TokenKind::Punct(byte) = token.kind {
                if let Some(end) = close(byte) {
                    if stack.len() == MAX_DEPTH {
                        return Err(self.error(ErrorKind::DepthLimit));
                    }
                    stack.push(end);
                } else if matches!(byte, b')' | b']' | b'}') {
                    if stack.pop() != Some(byte) {
                        return Err(self.error(ErrorKind::UnbalancedDelimiter));
                    }
                    if stack.is_empty() {
                        return Ok(());
                    }
                }
            }
        }
        Err(self.error(ErrorKind::UnbalancedDelimiter))
    }
    fn emit(&mut self, out: &mut Scan, kind: Kind, name: Token) -> Result<(), Error> {
        if self.budget.declarations == MAX_DECLARATIONS {
            return Err(self.error(ErrorKind::DeclarationLimit));
        }
        self.budget.declarations += 1;
        out.declarations
            .try_reserve(1)
            .map_err(|_| self.error(ErrorKind::DeclarationLimit))?;
        out.declarations.push(Declaration {
            kind,
            byte_offset: name.start,
            byte_length: name.end - name.start,
            line: name.line,
            byte_column: name.column,
            raw_identifier: name.kind == TokenKind::Word(true),
        });
        Ok(())
    }
}
fn head_kind(token: Token, bytes: &[u8]) -> Option<Kind> {
    if token.kind != TokenKind::Word(false) {
        return None;
    }
    match token.text(bytes) {
        b"fn" => Some(Kind::Function),
        b"struct" => Some(Kind::Struct),
        b"enum" => Some(Kind::Enum),
        b"trait" => Some(Kind::Trait),
        b"type" => Some(Kind::Type),
        b"mod" => Some(Kind::Module),
        b"union" => Some(Kind::Union),
        _ => None,
    }
}
fn tail(kind: Kind, token: Token, bytes: &[u8]) -> bool {
    if token.word(bytes, b"where") {
        return matches!(
            kind,
            Kind::Struct | Kind::Enum | Kind::Trait | Kind::Type | Kind::Union
        );
    }
    let TokenKind::Punct(byte) = token.kind else {
        return false;
    };
    match kind {
        Kind::Function => matches!(byte, b'(' | b'<'),
        Kind::Struct => matches!(byte, b'{' | b'(' | b';' | b'<'),
        Kind::Enum | Kind::Union => matches!(byte, b'{' | b'<'),
        Kind::Trait => matches!(byte, b'{' | b'<' | b':' | b'='),
        Kind::Type => matches!(byte, b'<' | b'=' | b':' | b';'),
        Kind::Module => matches!(byte, b'{' | b';'),
        Kind::Macro => close(byte).is_some(),
    }
}

pub fn extract(
    bytes: &[u8],
    budget: &mut Budget,
    cancelled: &dyn Fn() -> bool,
) -> Result<Scan, Error> {
    budget.charge(0, 0, cancelled)?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(Error {
            kind: ErrorKind::FileLimit,
            byte_offset: 0,
        });
    }
    budget.charge(bytes.len(), 0, cancelled)?; // Charge full UTF-8 validation separately.
    std::str::from_utf8(bytes).map_err(|e| Error {
        kind: ErrorKind::InvalidUtf8,
        byte_offset: e.valid_up_to(),
    })?;
    let mut lex = Lexer {
        bytes,
        at: 0,
        line: 1,
        line_start: 0,
        budget,
        cancelled,
        look: None,
    };
    if bytes.starts_with(b"\xef\xbb\xbf") {
        lex.advance(3)?;
    }
    if bytes.get(lex.at..lex.at + 2) == Some(b"#!") {
        let mut next = lex.at + 2;
        while bytes.get(next).is_some_and(u8::is_ascii_whitespace) {
            next += 1;
        }
        lex.budget.charge(next - lex.at, lex.at, cancelled)?;
        if bytes.get(next) != Some(&b'[') {
            while lex.byte(lex.at).is_some_and(|b| b != b'\n') {
                lex.bump()?;
            }
        }
    }
    let mut out = Scan::default();
    let mut stack = Vec::new();
    let mut macro_name = false;
    while let Some(token) = lex.next()? {
        if token.punct(b'#') {
            if lex.peek()?.is_some_and(|t| t.punct(b'!')) {
                lex.next()?;
            }
            if lex.peek()?.is_some_and(|t| t.punct(b'[')) {
                lex.next()?;
                lex.group(b'[')?;
                out.attributes_skipped += 1;
                macro_name = false;
                continue;
            }
        }
        if token.word(bytes, b"macro_rules") && lex.peek()?.is_some_and(|t| t.punct(b'!')) {
            lex.next()?;
            if let Some(name) = lex.peek()?
                && identifier(name, bytes)
            {
                lex.next()?;
                if let Some(open) = lex.peek()?
                    && tail(Kind::Macro, open, bytes)
                {
                    lex.emit(&mut out, Kind::Macro, name)?;
                    lex.next()?;
                    let TokenKind::Punct(byte) = open.kind else {
                        return Err(lex.error(ErrorKind::UnbalancedDelimiter));
                    };
                    lex.group(byte)?;
                    out.macro_bodies_skipped += 1;
                    macro_name = false;
                    continue;
                }
            }
        }
        if token.punct(b'!')
            && macro_name
            && let Some(open) = lex.peek()?
            && let TokenKind::Punct(byte) = open.kind
            && close(byte).is_some()
        {
            lex.next()?;
            lex.group(byte)?;
            out.macro_bodies_skipped += 1;
            macro_name = false;
            continue;
        }
        if let Some(kind) = head_kind(token, bytes)
            && let Some(name) = lex.peek()?
            && identifier(name, bytes)
        {
            lex.next()?;
            if lex.peek()?.is_some_and(|next| tail(kind, next, bytes)) {
                lex.emit(&mut out, kind, name)?;
            }
        }
        if let TokenKind::Punct(byte) = token.kind {
            if let Some(end) = close(byte) {
                if stack.len() == MAX_DEPTH {
                    return Err(lex.error(ErrorKind::DepthLimit));
                }
                stack.push(end);
            } else if matches!(byte, b')' | b']' | b'}') && stack.pop() != Some(byte) {
                return Err(lex.error(ErrorKind::UnbalancedDelimiter));
            }
        }
        macro_name = identifier(token, bytes);
    }
    if !stack.is_empty() {
        return Err(lex.error(ErrorKind::UnbalancedDelimiter));
    }
    lex.budget.charge(0, bytes.len(), cancelled)?;
    Ok(out)
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
