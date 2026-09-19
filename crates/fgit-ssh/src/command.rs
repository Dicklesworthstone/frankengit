//! Pure-Rust typed shell-free Git SSH command parser.
//!
//! Upstream `git-shell` or an SSH server that spawns `/bin/sh -c "$SSH_ORIGINAL_COMMAND"`
//! is inherently susceptible to argument injection, shell metacharacter expansion, and
//! arbitrary process execution. FrankenGit forbids any shell execution in production.
//!
//! This module provides a strictly typed, shell-free command parser that accepts only:
//! - `git-upload-pack '<path>'` (or double-quoted / unquoted path)
//! - `git-receive-pack '<path>'` (or double-quoted / unquoted path)
//!
//! Every command is verified against hostile quoting, option injection (leading `-`),
//! directory traversal (`..`), null bytes, and shell metacharacters.

use core::fmt::{self, Display, Formatter};

/// The typed Git service requested over SSH.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SshGitService {
    /// Read-only fetch/clone advertisement and pack extraction (`git-upload-pack`).
    UploadPack,
    /// Reference advance and pack delivery (`git-receive-pack`).
    ReceivePack,
}

impl Display for SshGitService {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UploadPack => formatter.write_str("git-upload-pack"),
            Self::ReceivePack => formatter.write_str("git-receive-pack"),
        }
    }
}

/// A parsed, strictly validated Git SSH execution command.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SshGitCommand {
    service: SshGitService,
    repository_path: String,
}

impl SshGitCommand {
    /// Creates a new command from validated parts.
    #[must_use]
    pub const fn new(service: SshGitService, repository_path: String) -> Self {
        Self {
            service,
            repository_path,
        }
    }

    /// The Git service requested.
    #[must_use]
    pub const fn service(&self) -> SshGitService {
        self.service
    }

    /// The normalized repository path.
    #[must_use]
    pub fn repository_path(&self) -> &str {
        &self.repository_path
    }

    /// Parses an incoming raw SSH exec command string.
    ///
    /// # Errors
    ///
    /// Returns [`CommandParseRefusal`] if the command is malformed, names an unsupported service,
    /// contains shell metacharacters, directory traversal, or option injection attempts.
    pub fn parse(raw: &str) -> Result<Self, CommandParseRefusal> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(CommandParseRefusal::EmptyCommand);
        }

        // 1. Identify service prefix
        let (service, remainder) = if let Some(rest) = trimmed.strip_prefix("git-upload-pack ") {
            (SshGitService::UploadPack, rest)
        } else if let Some(rest) = trimmed.strip_prefix("git upload-pack ") {
            (SshGitService::UploadPack, rest)
        } else if let Some(rest) = trimmed.strip_prefix("git-receive-pack ") {
            (SshGitService::ReceivePack, rest)
        } else if let Some(rest) = trimmed.strip_prefix("git receive-pack ") {
            (SshGitService::ReceivePack, rest)
        } else {
            // Find first token to report unsupported service
            let token = trimmed.split_whitespace().next().unwrap_or(trimmed);
            return Err(CommandParseRefusal::UnsupportedService {
                observed: token.to_owned(),
            });
        };

        // 2. Parse path argument
        let path = parse_quoted_path(remainder)?;

        // 3. Strict security validation
        validate_repository_path(&path)?;

        // 4. Normalize repository path: strip leading slash for routing consistency
        let normalized = path.strip_prefix('/').unwrap_or(&path).to_owned();

        Ok(Self {
            service,
            repository_path: normalized,
        })
    }
}

/// Reasons why a raw command string is refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandParseRefusal {
    /// The command string was empty or purely whitespace.
    EmptyCommand,
    /// The command does not invoke git-upload-pack or git-receive-pack.
    UnsupportedService {
        observed: String,
    },
    /// The path quotation was unclosed or malformed.
    InvalidQuoting,
    /// The extracted repository path was empty.
    EmptyPath,
    /// Path starts with `-`, attempting option injection (e.g. `--exec`).
    OptionInjection {
        observed: String,
    },
    /// A forbidden shell metacharacter was observed.
    ShellMetacharacterForbidden {
        character: char,
    },
    /// Directory traversal (`..`) was detected in the repository path.
    PathTraversalForbidden,
    /// A null byte (`\0`) was detected.
    NullByteForbidden,
    /// Extraneous arguments followed the repository path.
    TrailingArgumentsForbidden,
}

impl Display for CommandParseRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCommand => formatter.write_str("empty SSH exec command is refused"),
            Self::UnsupportedService { observed } => {
                write!(formatter, "unsupported SSH service `{observed}`: only git-upload-pack and git-receive-pack are admitted")
            }
            Self::InvalidQuoting => formatter.write_str("malformed path quotation in SSH command"),
            Self::EmptyPath => formatter.write_str("empty repository path in SSH command is refused"),
            Self::OptionInjection { observed } => {
                write!(formatter, "leading option flag `{observed}` in repository path is refused")
            }
            Self::ShellMetacharacterForbidden { character } => {
                write!(formatter, "forbidden shell metacharacter `{character}` in SSH command")
            }
            Self::PathTraversalForbidden => {
                formatter.write_str("directory traversal component `..` in repository path is refused")
            }
            Self::NullByteForbidden => formatter.write_str("null byte in repository path is refused"),
            Self::TrailingArgumentsForbidden => {
                formatter.write_str("unexpected trailing arguments after repository path")
            }
        }
    }
}

impl core::error::Error for CommandParseRefusal {}

/// Parses single-quoted, double-quoted, or unquoted path.
fn parse_quoted_path(input: &str) -> Result<String, CommandParseRefusal> {
    let trimmed = input.trim_start();
    if trimmed.is_empty() {
        return Err(CommandParseRefusal::EmptyPath);
    }

    if trimmed.starts_with('\'') {
        parse_single_quoted(trimmed)
    } else if trimmed.starts_with('"') {
        parse_double_quoted(trimmed)
    } else {
        parse_bare(trimmed)
    }
}

/// Parses single-quoted Git path: `'path'`.
/// Upstream Git uses `sq_quote_buf` which escapes single quotes as `'\''`.
fn parse_single_quoted(input: &str) -> Result<String, CommandParseRefusal> {
    let mut out = String::new();
    let mut chars = input.chars();
    assert_eq!(chars.next(), Some('\''));

    let mut closed = false;
    while let Some(c) = chars.next() {
        if c == '\'' {
            // Check for Git's escaped quote: '\''
            let remainder: String = chars.clone().collect();
            if remainder.starts_with("\\''") {
                out.push('\'');
                chars.next(); // consume '\'
                chars.next(); // consume literal '\''
                chars.next(); // consume re-opening '\''
            } else {
                closed = true;
                break;
            }
        } else {
            out.push(c);
        }
    }

    if !closed {
        return Err(CommandParseRefusal::InvalidQuoting);
    }

    // Ensure no trailing tokens
    let remainder: String = chars.collect();
    if !remainder.trim().is_empty() {
        return Err(CommandParseRefusal::TrailingArgumentsForbidden);
    }

    Ok(out)
}

/// Parses double-quoted Git path: `"path"`.
fn parse_double_quoted(input: &str) -> Result<String, CommandParseRefusal> {
    let mut out = String::new();
    let mut chars = input.chars();
    assert_eq!(chars.next(), Some('"'));

    let mut closed = false;
    let mut escaped = false;
    for c in chars.by_ref() {
        if escaped {
            out.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            closed = true;
            break;
        } else {
            out.push(c);
        }
    }

    if !closed || escaped {
        return Err(CommandParseRefusal::InvalidQuoting);
    }

    let remainder: String = chars.collect();
    if !remainder.trim().is_empty() {
        return Err(CommandParseRefusal::TrailingArgumentsForbidden);
    }

    Ok(out)
}

/// Parses unquoted/bare Git path: `repo.git`.
fn parse_bare(input: &str) -> Result<String, CommandParseRefusal> {
    let mut parts = input.split_whitespace();
    let Some(first) = parts.next() else {
        return Err(CommandParseRefusal::EmptyPath);
    };

    if parts.next().is_some() {
        return Err(CommandParseRefusal::TrailingArgumentsForbidden);
    }

    Ok(first.to_owned())
}

/// Security validation of the repository path.
fn validate_repository_path(path: &str) -> Result<(), CommandParseRefusal> {
    if path.is_empty() {
        return Err(CommandParseRefusal::EmptyPath);
    }

    if path.starts_with('-') {
        return Err(CommandParseRefusal::OptionInjection {
            observed: path.chars().take(16).collect(),
        });
    }

    // Check for null bytes
    if path.contains('\0') {
        return Err(CommandParseRefusal::NullByteForbidden);
    }

    // Check for forbidden shell metacharacters
    const FORBIDDEN_METACHARS: &[char] = &[
        ';', '&', '|', '`', '$', '(', ')', '<', '>', '\n', '\r', '\t', '!', '{', '}', '*', '?',
        '[', ']',
    ];
    for &ch in FORBIDDEN_METACHARS {
        if path.contains(ch) {
            return Err(CommandParseRefusal::ShellMetacharacterForbidden { character: ch });
        }
    }

    // Check for directory traversal
    for segment in path.split('/') {
        if segment == ".." {
            return Err(CommandParseRefusal::PathTraversalForbidden);
        }
    }
    // Also check Windows backslash if present
    for segment in path.split('\\') {
        if segment == ".." {
            return Err(CommandParseRefusal::PathTraversalForbidden);
        }
    }

    Ok(())
}
