//! Typed errors exposed by the core domain layer.

use std::fmt;
use std::io;
use std::path::PathBuf;
use std::string::FromUtf8Error;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A machine-readable category for a configuration validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ValidationCode {
    /// The top-level schema version is not supported.
    UnsupportedSchema,
    /// A required value is empty.
    Empty,
    /// A value is not a valid identifier for its domain.
    InvalidIdentifier,
    /// A sequence contains the same value more than once.
    Duplicate,
    /// A value references an object that does not exist.
    MissingReference,
    /// A filesystem path is not valid in committed project configuration.
    InvalidPath,
    /// A network port is outside the valid range.
    InvalidPort,
    /// Health-check settings are internally inconsistent.
    InvalidHealthCheck,
    /// An environment-variable name is invalid.
    InvalidEnvironmentKey,
    /// A plugin-settings capability is unknown.
    UnknownCapability,
}

/// One configuration validation problem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationIssue {
    /// A dotted path to the invalid field.
    pub path: String,
    /// A stable, machine-readable failure category.
    pub code: ValidationCode,
    /// A concise, user-facing explanation.
    pub message: String,
}

impl ValidationIssue {
    /// Creates a validation issue.
    #[must_use]
    pub fn new(path: impl Into<String>, code: ValidationCode, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            code,
            message: message.into(),
        }
    }
}

/// All validation problems found in a configuration.
///
/// Validation deliberately reports every independent issue in one pass so an
/// interactive initializer and a human editing TOML can fix them together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationErrors {
    issues: Vec<ValidationIssue>,
}

impl ValidationErrors {
    /// Creates a non-empty validation error collection.
    ///
    /// Returns `None` when `issues` is empty.
    #[must_use]
    pub fn from_issues(issues: Vec<ValidationIssue>) -> Option<Self> {
        (!issues.is_empty()).then_some(Self { issues })
    }

    /// Returns all validation issues.
    #[must_use]
    pub fn issues(&self) -> &[ValidationIssue] {
        &self.issues
    }

    /// Consumes the collection and returns its issues.
    #[must_use]
    pub fn into_issues(self) -> Vec<ValidationIssue> {
        self.issues
    }
}

impl fmt::Display for ValidationErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "configuration has {} validation error{}",
            self.issues.len(),
            if self.issues.len() == 1 { "" } else { "s" }
        )?;

        for issue in &self.issues {
            write!(formatter, "\n- {}: {}", issue.path, issue.message)?;
        }

        Ok(())
    }
}

impl std::error::Error for ValidationErrors {}

/// Loading, parsing, validating, or serializing a Lightrail configuration failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The configuration file could not be read.
    #[error("failed to read Lightrail configuration `{path}`: {source}")]
    Read {
        /// Path that was being read.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        source: io::Error,
    },

    /// TOML could not be deserialized into the configuration model.
    #[error("failed to parse Lightrail configuration from {origin}: {source}")]
    Parse {
        /// Human-readable input origin, such as a path or `<memory>`.
        origin: String,
        /// Underlying TOML error.
        #[source]
        source: toml::de::Error,
    },

    /// A validated configuration could not be serialized.
    #[error("failed to serialize Lightrail configuration: {0}")]
    Serialize(#[from] toml::ser::Error),

    /// The parsed configuration violates one or more domain invariants.
    #[error(transparent)]
    Validation(#[from] ValidationErrors),
}

/// Conversion of arbitrary plugin settings failed.
#[derive(Debug, Error)]
#[error("failed to convert plugin settings to JSON: {0}")]
pub struct SettingsConversionError(#[from] pub serde_json::Error);

/// A DNS or provider-safe name could not be constructed.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NamingError {
    /// A nil UUID cannot identify a project.
    #[error("project UUID must not be nil")]
    NilProjectId,

    /// A semantic value used to form a name is empty.
    #[error("{kind} must not be empty")]
    Empty {
        /// The kind of value, for example `branch` or `app`.
        kind: &'static str,
    },

    /// A complete DNS name exceeds the protocol limit.
    #[error("DNS name is {length} bytes; the maximum is {maximum}")]
    DnsNameTooLong {
        /// Actual encoded length, excluding a trailing dot.
        length: usize,
        /// Maximum accepted encoded length.
        maximum: usize,
    },

    /// A DNS suffix other than `sslip.io` or `nip.io` was requested.
    #[error("unsupported IP DNS domain `{0}`; expected `sslip.io` or `nip.io`")]
    UnsupportedIpDnsDomain(String),
}

/// Discovering Git state from the current checkout failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GitError {
    /// The `git` executable is unavailable.
    #[error("Git is required but could not be executed: {0}")]
    Unavailable(#[source] io::Error),

    /// A Git process could not be spawned or waited on.
    #[error("failed to run Git while {operation}: {source}")]
    CommandIo {
        /// Description of the attempted operation.
        operation: &'static str,
        /// Underlying process error.
        #[source]
        source: io::Error,
    },

    /// The starting path is not inside a Git working tree.
    #[error("`{start}` is not inside a Git working tree: {stderr}")]
    NotRepository {
        /// Path from which discovery started.
        start: PathBuf,
        /// Diagnostic emitted by Git.
        stderr: String,
    },

    /// Git returned a non-zero exit status.
    #[error("Git failed while {operation} (exit {status:?}): {stderr}")]
    CommandFailed {
        /// Description of the attempted operation.
        operation: &'static str,
        /// Portable process exit code, when available.
        status: Option<i32>,
        /// Diagnostic emitted by Git.
        stderr: String,
    },

    /// Git emitted output that is not valid UTF-8.
    #[error("Git emitted non-UTF-8 output while {operation}: {source}")]
    InvalidUtf8 {
        /// Description of the attempted operation.
        operation: &'static str,
        /// UTF-8 decoding error.
        #[source]
        source: FromUtf8Error,
    },

    /// Git emitted no usable value for a required field.
    #[error("Git emitted empty output while {operation}")]
    EmptyOutput {
        /// Description of the attempted operation.
        operation: &'static str,
    },

    /// The commit identifier emitted by Git is malformed.
    #[error("Git emitted an invalid commit identifier `{0}`")]
    InvalidCommit(String),
}
