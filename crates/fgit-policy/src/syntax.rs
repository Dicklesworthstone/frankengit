//! The source form of a policy: tokens, a grammar, and the tree a compiler
//! resolves.
//!
//! ```text
//! policy protected_main {
//!   aggregate open_incidents
//!   evidence code_review { issuer forge.review-service max_age 3600 }
//!
//!   rule deny_force_on_protected {
//!     when ref.name matches "refs/heads/main" and ref.force_requested
//!     then deny "forced update to a protected ref"
//!   }
//!
//!   rule allow_reviewed_fast_forward {
//!     when ref.name matches "refs/heads/**"
//!          and ref.update == fast_forward
//!          and evidence code_review
//!          and aggregate.open_incidents == 0
//!     then allow
//!   }
//!
//!   default deny "no rule permits this update"
//! }
//! ```
//!
//! ## What the grammar cannot say
//!
//! There is no call form, no assignment, no import, no path, and no free
//! identifier. An identifier in operand position is a bare literal for a
//! closed enumeration; an identifier in condition position is a selector name,
//! and the compiler resolves it against a closed list. That is the whole
//! surface, which is why "read the clock" is not a thing this grammar can be
//! made to say — `now.seconds` parses fine and then fails to resolve.
//!
//! ## The default is not optional
//!
//! A policy states what happens when no rule matches. Leaving it out is
//! [`PolicySyntaxRefusal::MissingDefaultDecision`], not an implied deny: which
//! way a policy fails is its author's decision to record, not this crate's to
//! supply.

use crate::error::PolicySyntaxRefusal;
use crate::program::{MAX_PREDICATE_DEPTH, MAX_SET_ELEMENTS, MAX_TEXT_LITERAL_LEN};

/// Largest accepted policy source, in bytes.
pub const MAX_SOURCE_LEN: usize = 64 * 1024;

/// A value together with where it was written.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Spanned<T> {
    /// The value.
    pub value: T,
    /// Byte offset of the value in the source.
    pub offset: usize,
}

impl<T> Spanned<T> {
    /// Pairs a value with its offset.
    pub const fn new(value: T, offset: usize) -> Self {
        Self { value, offset }
    }
}

/// A lexical token.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TokenKind {
    /// A bare name: keyword, selector, or enumeration literal.
    Name(Box<str>),
    /// A quoted string.
    Text(Box<str>),
    /// A decimal integer.
    Integer(u64),
    /// `{`
    OpenBrace,
    /// `}`
    CloseBrace,
    /// `(`
    OpenParen,
    /// `)`
    CloseParen,
    /// `,`
    Comma,
    /// `==`
    Equal,
    /// `!=`
    NotEqual,
    /// `>=`
    GreaterOrEqual,
    /// `<=`
    LessOrEqual,
    /// `>`
    Greater,
    /// `<`
    Less,
}

impl TokenKind {
    /// How the token reads in a refusal message.
    #[must_use]
    pub fn describe(&self) -> Box<str> {
        match self {
            Self::Name(name) => name.clone(),
            Self::Text(text) => format!("\"{text}\"").into_boxed_str(),
            Self::Integer(value) => value.to_string().into_boxed_str(),
            Self::OpenBrace => "{".into(),
            Self::CloseBrace => "}".into(),
            Self::OpenParen => "(".into(),
            Self::CloseParen => ")".into(),
            Self::Comma => ",".into(),
            Self::Equal => "==".into(),
            Self::NotEqual => "!=".into(),
            Self::GreaterOrEqual => ">=".into(),
            Self::LessOrEqual => "<=".into(),
            Self::Greater => ">".into(),
            Self::Less => "<".into(),
        }
    }
}

/// One token and where it started.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Token {
    /// What the token is.
    pub kind: TokenKind,
    /// Byte offset of its first byte.
    pub offset: usize,
}

/// A comparison operator as written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SourceOperator {
    /// `==`
    Equal,
    /// `!=`
    NotEqual,
    /// `matches`
    Matches,
    /// `in`
    In,
    /// `contains`
    Contains,
    /// `<`
    Less,
    /// `<=`
    LessOrEqual,
    /// `>`
    Greater,
    /// `>=`
    GreaterOrEqual,
}

impl SourceOperator {
    /// The stable token used in source text and in refusal messages.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Equal => "==",
            Self::NotEqual => "!=",
            Self::Matches => "matches",
            Self::In => "in",
            Self::Contains => "contains",
            Self::Less => "<",
            Self::LessOrEqual => "<=",
            Self::Greater => ">",
            Self::GreaterOrEqual => ">=",
        }
    }
}

/// An operand as written.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SourceOperand {
    /// A quoted string.
    Text(Spanned<Box<str>>),
    /// A decimal integer.
    Integer(Spanned<u64>),
    /// A bare name standing for a closed-enumeration value.
    Name(Spanned<Box<str>>),
    /// A brace-delimited set of the above.
    Set(Spanned<Vec<Self>>),
}

impl SourceOperand {
    /// Where the operand was written.
    #[must_use]
    pub const fn offset(&self) -> usize {
        match self {
            Self::Text(value) => value.offset,
            Self::Integer(value) => value.offset,
            Self::Name(value) => value.offset,
            Self::Set(value) => value.offset,
        }
    }

    /// How the operand's shape reads in a refusal message.
    #[must_use]
    pub const fn shape(&self) -> &'static str {
        match self {
            Self::Text(_) => "a quoted string",
            Self::Integer(_) => "an integer",
            Self::Name(_) => "a bare name",
            Self::Set(_) => "a set literal",
        }
    }
}

/// A condition as written.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SourceExpr {
    /// `true` or `false`.
    Literal(bool),
    /// `a and b and ...`
    All(Vec<Self>),
    /// `a or b or ...`
    Any(Vec<Self>),
    /// `not a`
    Not(Box<Self>),
    /// A selector used bare, which only a truth-valued selector admits.
    Bare(Spanned<Box<str>>),
    /// A selector compared against an operand.
    Comparison {
        /// The selector as written.
        selector: Spanned<Box<str>>,
        /// The operator.
        operator: SourceOperator,
        /// Where the operator was written.
        operator_offset: usize,
        /// The operand.
        operand: SourceOperand,
    },
    /// `evidence <kind>`
    Evidence(Spanned<Box<str>>),
}

/// What a rule or a policy says.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SourceOutcome {
    /// `allow`
    Allow,
    /// `deny "..."`
    Deny(Box<str>),
}

/// A declaration inside a policy.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SourceDeclaration {
    /// `aggregate <name>`
    Aggregate(Spanned<Box<str>>),
    /// `evidence <kind> { issuer <issuer> [max_age <seconds>] }`
    Evidence {
        /// The evidence class.
        kind: Spanned<Box<str>>,
        /// The accepted issuer.
        issuer: Spanned<Box<str>>,
        /// An additional age bound, if declared.
        max_age_seconds: Option<u64>,
    },
}

/// A rule as written.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SourceRule {
    /// The rule identifier.
    pub id: Spanned<Box<str>>,
    /// The condition.
    pub predicate: SourceExpr,
    /// What the rule says when the condition holds.
    pub outcome: SourceOutcome,
}

/// A policy as written.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SourcePolicy {
    /// The policy name.
    pub name: Spanned<Box<str>>,
    /// Declarations, in source order.
    pub declarations: Vec<SourceDeclaration>,
    /// Rules, in source order.
    pub rules: Vec<SourceRule>,
    /// What the policy says when no rule matches.
    pub default_outcome: SourceOutcome,
}

/// Reads a policy source text into its source form.
pub fn parse(source: &str) -> Result<SourcePolicy, PolicySyntaxRefusal> {
    let tokens = tokenize(source)?;
    Parser::new(&tokens).policy()
}

/// Splits a policy source text into tokens.
pub fn tokenize(source: &str) -> Result<Vec<Token>, PolicySyntaxRefusal> {
    if source.len() > MAX_SOURCE_LEN {
        return Err(PolicySyntaxRefusal::SourceTooLarge {
            observed: source.len(),
            limit: MAX_SOURCE_LEN,
        });
    }
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut at = 0_usize;

    while at < bytes.len() {
        let byte = bytes[at];
        if matches!(byte, b' ' | b'\t' | b'\r' | b'\n') {
            at += 1;
            continue;
        }
        if byte == b'#' {
            while at < bytes.len() && bytes[at] != b'\n' {
                at += 1;
            }
            continue;
        }
        let offset = at;
        let kind = match byte {
            b'{' => {
                at += 1;
                TokenKind::OpenBrace
            }
            b'}' => {
                at += 1;
                TokenKind::CloseBrace
            }
            b'(' => {
                at += 1;
                TokenKind::OpenParen
            }
            b')' => {
                at += 1;
                TokenKind::CloseParen
            }
            b',' => {
                at += 1;
                TokenKind::Comma
            }
            b'=' | b'!' | b'>' | b'<' => {
                let followed_by_equals = bytes.get(at + 1) == Some(&b'=');
                match (byte, followed_by_equals) {
                    (b'=', true) => {
                        at += 2;
                        TokenKind::Equal
                    }
                    (b'!', true) => {
                        at += 2;
                        TokenKind::NotEqual
                    }
                    (b'>', true) => {
                        at += 2;
                        TokenKind::GreaterOrEqual
                    }
                    (b'<', true) => {
                        at += 2;
                        TokenKind::LessOrEqual
                    }
                    (b'>', false) => {
                        at += 1;
                        TokenKind::Greater
                    }
                    (b'<', false) => {
                        at += 1;
                        TokenKind::Less
                    }
                    _ => return Err(PolicySyntaxRefusal::ByteNotPermitted { offset, byte }),
                }
            }
            b'"' => {
                let (text, next) = read_text(bytes, at)?;
                at = next;
                TokenKind::Text(text)
            }
            b'0'..=b'9' => {
                let (value, next) = read_integer(bytes, at)?;
                at = next;
                TokenKind::Integer(value)
            }
            byte if name_byte(byte) => {
                let start = at;
                while at < bytes.len() && name_byte(bytes[at]) {
                    at += 1;
                }
                let name = core::str::from_utf8(&bytes[start..at])
                    .map_err(|_| PolicySyntaxRefusal::ByteNotPermitted { offset, byte })?;
                TokenKind::Name(name.to_owned().into_boxed_str())
            }
            _ => return Err(PolicySyntaxRefusal::ByteNotPermitted { offset, byte }),
        };
        tokens.push(Token { kind, offset });
    }

    Ok(tokens)
}

/// Bytes a bare name may contain.
///
/// Exactly the canonical label character set, so a name that lexes is a name
/// that can become an `AsciiSlug` without a second opinion about case or
/// separators.
const fn name_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.' | b'/')
}

fn read_text(bytes: &[u8], open: usize) -> Result<(Box<str>, usize), PolicySyntaxRefusal> {
    let mut at = open + 1;
    let mut text = String::new();
    loop {
        let Some(byte) = bytes.get(at).copied() else {
            return Err(PolicySyntaxRefusal::UnterminatedString { offset: open });
        };
        match byte {
            b'"' => {
                at += 1;
                break;
            }
            b'\\' => {
                let Some(escaped) = bytes.get(at + 1).copied() else {
                    return Err(PolicySyntaxRefusal::UnterminatedString { offset: open });
                };
                if escaped != b'\\' && escaped != b'"' {
                    return Err(PolicySyntaxRefusal::UnsupportedEscape {
                        offset: at,
                        byte: escaped,
                    });
                }
                text.push(char::from(escaped));
                at += 2;
            }
            byte if byte.is_ascii_graphic() || byte == b' ' => {
                text.push(char::from(byte));
                at += 1;
            }
            byte => return Err(PolicySyntaxRefusal::ByteNotPermitted { offset: at, byte }),
        }
        if text.len() > MAX_TEXT_LITERAL_LEN {
            return Err(PolicySyntaxRefusal::StringTooLong {
                offset: open,
                observed: text.len(),
                limit: MAX_TEXT_LITERAL_LEN,
            });
        }
    }
    Ok((text.into_boxed_str(), at))
}

fn read_integer(bytes: &[u8], start: usize) -> Result<(u64, usize), PolicySyntaxRefusal> {
    let mut at = start;
    while at < bytes.len() && bytes[at].is_ascii_digit() {
        at += 1;
    }
    let digits = &bytes[start..at];
    if digits.len() > 1 && digits[0] == b'0' {
        return Err(PolicySyntaxRefusal::IntegerLeadingZero { offset: start });
    }
    let mut value = 0_u64;
    for digit in digits {
        value = value
            .checked_mul(10)
            .and_then(|scaled| scaled.checked_add(u64::from(digit - b'0')))
            .ok_or(PolicySyntaxRefusal::IntegerOutOfRange { offset: start })?;
    }
    Ok((value, at))
}

/// Names the grammar reserves.
///
/// A reserved name cannot be a policy name, a rule identifier, an aggregate
/// name, or an evidence kind. Allowing one would produce a source text whose
/// meaning depends on where the reader is in the grammar.
pub const KEYWORDS: [&str; 19] = [
    "policy",
    "rule",
    "when",
    "then",
    "default",
    "allow",
    "deny",
    "aggregate",
    "evidence",
    "issuer",
    "max_age",
    "and",
    "or",
    "not",
    "in",
    "matches",
    "contains",
    "true",
    "false",
];

/// True when `name` is reserved and so cannot be used as a declared name.
#[must_use]
pub fn is_keyword(name: &str) -> bool {
    KEYWORDS.contains(&name)
}

struct Parser<'a> {
    tokens: &'a [Token],
    at: usize,
    end_offset: usize,
}

impl<'a> Parser<'a> {
    fn new(tokens: &'a [Token]) -> Self {
        let end_offset = tokens
            .last()
            .map_or(0, |token| token.offset + token.kind.describe().len());
        Self {
            tokens,
            at: 0,
            end_offset,
        }
    }

    fn peek(&self) -> Option<&'a Token> {
        self.tokens.get(self.at)
    }

    fn next(&mut self, expected: &'static str) -> Result<&'a Token, PolicySyntaxRefusal> {
        let token = self
            .tokens
            .get(self.at)
            .ok_or(PolicySyntaxRefusal::UnexpectedEnd { expected })?;
        self.at += 1;
        Ok(token)
    }

    fn expect(
        &mut self,
        kind: &TokenKind,
        expected: &'static str,
    ) -> Result<usize, PolicySyntaxRefusal> {
        let token = self.next(expected)?;
        if token.kind == *kind {
            Ok(token.offset)
        } else {
            Err(PolicySyntaxRefusal::UnexpectedToken {
                offset: token.offset,
                expected,
                found: token.kind.describe(),
            })
        }
    }

    fn name(&mut self, expected: &'static str) -> Result<Spanned<Box<str>>, PolicySyntaxRefusal> {
        let token = self.next(expected)?;
        match &token.kind {
            TokenKind::Name(name) => Ok(Spanned::new(name.clone(), token.offset)),
            other => Err(PolicySyntaxRefusal::UnexpectedToken {
                offset: token.offset,
                expected,
                found: other.describe(),
            }),
        }
    }

    fn keyword(&mut self, word: &str) -> bool {
        matches!(self.peek(), Some(Token { kind: TokenKind::Name(name), .. }) if &**name == word)
    }

    fn policy(&mut self) -> Result<SourcePolicy, PolicySyntaxRefusal> {
        let header = self.name("the `policy` keyword")?;
        if &*header.value != "policy" {
            return Err(PolicySyntaxRefusal::UnknownDeclaration {
                offset: header.offset,
                keyword: header.value,
            });
        }
        let name = self.name("a policy name")?;
        self.expect(&TokenKind::OpenBrace, "`{` after the policy name")?;

        let mut declarations = Vec::new();
        let mut rules = Vec::new();

        loop {
            let token = self.next("a declaration, a rule, `default`, or `}`")?;
            match &token.kind {
                // Reaching `}` means the policy never stated a default: the
                // `default` arm below is the only way out of this loop with a
                // policy, and it consumes the closing brace itself.
                TokenKind::CloseBrace => {
                    return Err(PolicySyntaxRefusal::MissingDefaultDecision {
                        offset: token.offset,
                    });
                }
                TokenKind::Name(word) if &**word == "aggregate" => {
                    declarations.push(SourceDeclaration::Aggregate(
                        self.name("an aggregate name")?,
                    ));
                }
                TokenKind::Name(word) if &**word == "evidence" => {
                    declarations.push(self.evidence_declaration()?);
                }
                TokenKind::Name(word) if &**word == "rule" => {
                    rules.push(self.rule()?);
                }
                TokenKind::Name(word) if &**word == "default" => {
                    let default_outcome = self.outcome()?;
                    self.expect(&TokenKind::CloseBrace, "`}` after `default`")?;
                    if let Some(trailing) = self.peek() {
                        return Err(PolicySyntaxRefusal::TrailingSource {
                            offset: trailing.offset,
                        });
                    }
                    return Ok(SourcePolicy {
                        name,
                        declarations,
                        rules,
                        default_outcome,
                    });
                }
                TokenKind::Name(word) => {
                    return Err(PolicySyntaxRefusal::UnknownDeclaration {
                        offset: token.offset,
                        keyword: word.clone(),
                    });
                }
                other => {
                    return Err(PolicySyntaxRefusal::UnexpectedToken {
                        offset: token.offset,
                        expected: "a declaration, a rule, `default`, or `}`",
                        found: other.describe(),
                    });
                }
            }
        }
    }

    fn evidence_declaration(&mut self) -> Result<SourceDeclaration, PolicySyntaxRefusal> {
        let kind = self.name("an evidence kind")?;
        self.expect(&TokenKind::OpenBrace, "`{` after the evidence kind")?;
        let mut issuer = None;
        let mut max_age_seconds = None;
        loop {
            let token = self.next("`issuer`, `max_age`, or `}`")?;
            match &token.kind {
                TokenKind::CloseBrace => break,
                TokenKind::Name(word) if &**word == "issuer" => {
                    issuer = Some(self.name("an issuer name")?);
                }
                TokenKind::Name(word) if &**word == "max_age" => {
                    let seconds = self.next("a number of seconds")?;
                    let TokenKind::Integer(value) = seconds.kind else {
                        return Err(PolicySyntaxRefusal::UnexpectedToken {
                            offset: seconds.offset,
                            expected: "a number of seconds",
                            found: seconds.kind.describe(),
                        });
                    };
                    max_age_seconds = Some(value);
                }
                TokenKind::Name(word) => {
                    return Err(PolicySyntaxRefusal::UnknownDeclaration {
                        offset: token.offset,
                        keyword: word.clone(),
                    });
                }
                other => {
                    return Err(PolicySyntaxRefusal::UnexpectedToken {
                        offset: token.offset,
                        expected: "`issuer`, `max_age`, or `}`",
                        found: other.describe(),
                    });
                }
            }
        }
        let Some(issuer) = issuer else {
            return Err(PolicySyntaxRefusal::UnexpectedToken {
                offset: kind.offset,
                expected: "an `issuer` clause in the evidence declaration",
                found: kind.value.clone(),
            });
        };
        Ok(SourceDeclaration::Evidence {
            kind,
            issuer,
            max_age_seconds,
        })
    }

    fn rule(&mut self) -> Result<SourceRule, PolicySyntaxRefusal> {
        let id = self.name("a rule identifier")?;
        self.expect(&TokenKind::OpenBrace, "`{` after the rule identifier")?;
        let when = self.name("the `when` keyword")?;
        if &*when.value != "when" {
            return Err(PolicySyntaxRefusal::UnexpectedToken {
                offset: when.offset,
                expected: "the `when` keyword",
                found: when.value,
            });
        }
        let predicate = self.expression(1)?;
        let then = self.name("the `then` keyword")?;
        if &*then.value != "then" {
            return Err(PolicySyntaxRefusal::UnexpectedToken {
                offset: then.offset,
                expected: "the `then` keyword",
                found: then.value,
            });
        }
        let outcome = self.outcome()?;
        self.expect(&TokenKind::CloseBrace, "`}` at the end of the rule")?;
        Ok(SourceRule {
            id,
            predicate,
            outcome,
        })
    }

    fn outcome(&mut self) -> Result<SourceOutcome, PolicySyntaxRefusal> {
        let word = self.name("`allow` or `deny`")?;
        match &*word.value {
            "allow" => Ok(SourceOutcome::Allow),
            "deny" => {
                let token = self.next("a quoted reason after `deny`")?;
                let TokenKind::Text(reason) = &token.kind else {
                    return Err(PolicySyntaxRefusal::UnexpectedToken {
                        offset: token.offset,
                        expected: "a quoted reason after `deny`",
                        found: token.kind.describe(),
                    });
                };
                Ok(SourceOutcome::Deny(reason.clone()))
            }
            _ => Err(PolicySyntaxRefusal::UnknownDecision {
                offset: word.offset,
                keyword: word.value,
            }),
        }
    }

    fn expression(&mut self, depth: u32) -> Result<SourceExpr, PolicySyntaxRefusal> {
        self.disjunction(depth)
    }

    fn disjunction(&mut self, depth: u32) -> Result<SourceExpr, PolicySyntaxRefusal> {
        let mut operands = vec![self.conjunction(depth)?];
        while self.keyword("or") {
            self.at += 1;
            operands.push(self.conjunction(depth)?);
        }
        if operands.len() == 1 {
            Ok(operands.remove(0))
        } else {
            Ok(SourceExpr::Any(operands))
        }
    }

    fn conjunction(&mut self, depth: u32) -> Result<SourceExpr, PolicySyntaxRefusal> {
        let mut operands = vec![self.unary(depth)?];
        while self.keyword("and") {
            self.at += 1;
            operands.push(self.unary(depth)?);
        }
        if operands.len() == 1 {
            Ok(operands.remove(0))
        } else {
            Ok(SourceExpr::All(operands))
        }
    }

    fn unary(&mut self, depth: u32) -> Result<SourceExpr, PolicySyntaxRefusal> {
        if self.keyword("not") {
            let offset = self.peek().map_or(self.end_offset, |token| token.offset);
            self.at += 1;
            let inner = self.guarded(depth, offset)?;
            return Ok(SourceExpr::Not(Box::new(inner)));
        }
        self.primary(depth)
    }

    fn guarded(&mut self, depth: u32, offset: usize) -> Result<SourceExpr, PolicySyntaxRefusal> {
        if depth >= MAX_PREDICATE_DEPTH {
            return Err(PolicySyntaxRefusal::NestingTooDeep {
                offset,
                limit: MAX_PREDICATE_DEPTH,
            });
        }
        self.unary(depth + 1)
    }

    fn primary(&mut self, depth: u32) -> Result<SourceExpr, PolicySyntaxRefusal> {
        let token = self.next("a condition")?;
        match &token.kind {
            TokenKind::OpenParen => {
                if depth >= MAX_PREDICATE_DEPTH {
                    return Err(PolicySyntaxRefusal::NestingTooDeep {
                        offset: token.offset,
                        limit: MAX_PREDICATE_DEPTH,
                    });
                }
                let inner = self.expression(depth + 1)?;
                self.expect(&TokenKind::CloseParen, "`)` closing the condition")?;
                Ok(inner)
            }
            TokenKind::Name(word) if &**word == "true" => Ok(SourceExpr::Literal(true)),
            TokenKind::Name(word) if &**word == "false" => Ok(SourceExpr::Literal(false)),
            TokenKind::Name(word) if &**word == "evidence" => {
                Ok(SourceExpr::Evidence(self.name("an evidence kind")?))
            }
            TokenKind::Name(word) => {
                let selector = Spanned::new(word.clone(), token.offset);
                self.comparison_or_bare(selector)
            }
            other => Err(PolicySyntaxRefusal::UnexpectedToken {
                offset: token.offset,
                expected: "a condition",
                found: other.describe(),
            }),
        }
    }

    fn comparison_or_bare(
        &mut self,
        selector: Spanned<Box<str>>,
    ) -> Result<SourceExpr, PolicySyntaxRefusal> {
        let Some(token) = self.peek() else {
            return Ok(SourceExpr::Bare(selector));
        };
        let (operator, consumed) = match &token.kind {
            TokenKind::Equal => (SourceOperator::Equal, true),
            TokenKind::NotEqual => (SourceOperator::NotEqual, true),
            TokenKind::Greater => (SourceOperator::Greater, true),
            TokenKind::GreaterOrEqual => (SourceOperator::GreaterOrEqual, true),
            TokenKind::Less => (SourceOperator::Less, true),
            TokenKind::LessOrEqual => (SourceOperator::LessOrEqual, true),
            TokenKind::Name(word) => match &**word {
                "in" => (SourceOperator::In, true),
                "matches" => (SourceOperator::Matches, true),
                "contains" => (SourceOperator::Contains, true),
                "and" | "or" | "then" => return Ok(SourceExpr::Bare(selector)),
                // A bare name after a selector is a construct this language
                // does not define. Refusing it here is what makes an invented
                // operator a compile-time refusal rather than something the
                // parser silently reads as two conditions.
                other => {
                    return Err(PolicySyntaxRefusal::UnknownOperator {
                        offset: token.offset,
                        operator: other.to_owned().into_boxed_str(),
                    });
                }
            },
            TokenKind::CloseParen | TokenKind::CloseBrace => {
                return Ok(SourceExpr::Bare(selector));
            }
            other => {
                return Err(PolicySyntaxRefusal::UnexpectedToken {
                    offset: token.offset,
                    expected: "a comparison operator, `and`, `or`, or `then`",
                    found: other.describe(),
                });
            }
        };
        let operator_offset = token.offset;
        if consumed {
            self.at += 1;
        }
        let operand = self.operand()?;
        Ok(SourceExpr::Comparison {
            selector,
            operator,
            operator_offset,
            operand,
        })
    }

    fn operand(&mut self) -> Result<SourceOperand, PolicySyntaxRefusal> {
        let token = self.next("an operand")?;
        match &token.kind {
            TokenKind::Text(text) => Ok(SourceOperand::Text(Spanned::new(
                text.clone(),
                token.offset,
            ))),
            TokenKind::Integer(value) => {
                Ok(SourceOperand::Integer(Spanned::new(*value, token.offset)))
            }
            TokenKind::Name(name) => Ok(SourceOperand::Name(Spanned::new(
                name.clone(),
                token.offset,
            ))),
            TokenKind::OpenBrace => {
                let open = token.offset;
                let mut elements = Vec::new();
                loop {
                    if matches!(
                        self.peek(),
                        Some(Token {
                            kind: TokenKind::CloseBrace,
                            ..
                        })
                    ) {
                        self.at += 1;
                        break;
                    }
                    if !elements.is_empty() {
                        self.expect(&TokenKind::Comma, "`,` between set elements")?;
                    }
                    let element = self.scalar_operand()?;
                    elements.push(element);
                    if elements.len() > MAX_SET_ELEMENTS {
                        return Err(PolicySyntaxRefusal::SetTooLarge {
                            offset: open,
                            observed: elements.len(),
                            limit: MAX_SET_ELEMENTS,
                        });
                    }
                }
                Ok(SourceOperand::Set(Spanned::new(elements, open)))
            }
            other => Err(PolicySyntaxRefusal::UnexpectedToken {
                offset: token.offset,
                expected: "an operand",
                found: other.describe(),
            }),
        }
    }

    fn scalar_operand(&mut self) -> Result<SourceOperand, PolicySyntaxRefusal> {
        let token = self.next("a set element")?;
        match &token.kind {
            TokenKind::Text(text) => Ok(SourceOperand::Text(Spanned::new(
                text.clone(),
                token.offset,
            ))),
            TokenKind::Integer(value) => {
                Ok(SourceOperand::Integer(Spanned::new(*value, token.offset)))
            }
            TokenKind::Name(name) => Ok(SourceOperand::Name(Spanned::new(
                name.clone(),
                token.offset,
            ))),
            other => Err(PolicySyntaxRefusal::UnexpectedToken {
                offset: token.offset,
                expected: "a set element",
                found: other.describe(),
            }),
        }
    }
}
