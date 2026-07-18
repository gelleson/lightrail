use std::{fmt, io, time::Duration};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{ProtocolVersion, RequestId};

/// Stable error categories understood by core retry/UX policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// Input or plugin configuration is invalid.
    Validation,
    /// A requested capability or operation is not implemented.
    Unsupported,
    /// Authentication or authorization failed.
    Authentication,
    /// A required object does not exist.
    NotFound,
    /// Current state conflicts with the requested transition.
    Conflict,
    /// A mutation lock could not be acquired.
    LockUnavailable,
    /// A dependency timed out.
    Timeout,
    /// Provider throttling or quota pressure.
    RateLimited,
    /// Temporary network/provider failure.
    Unavailable,
    /// The operation was cancelled.
    Cancelled,
    /// An invariant or plugin implementation failed.
    Internal,
}

/// Structured plugin error transported in the JSON-RPC error `data` field.
#[derive(Clone, Debug, Deserialize, Error, Serialize)]
#[error("{message}")]
pub struct PluginError {
    /// Machine-readable category.
    pub kind: ErrorKind,
    /// Stable plugin-defined error code.
    pub code: String,
    /// Safe, actionable message.
    pub message: String,
    /// Whether retrying the same operation may succeed.
    #[serde(default)]
    pub retryable: bool,
    /// Provider-suggested delay before retrying.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    /// Non-sensitive structured context.
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub details: Value,
}

impl PluginError {
    /// Construct a permanent plugin error.
    #[must_use]
    pub fn permanent(kind: ErrorKind, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind,
            code: code.into(),
            message: message.into(),
            retryable: false,
            retry_after_ms: None,
            details: Value::Null,
        }
    }

    /// Construct a transient plugin error.
    #[must_use]
    pub fn retryable(kind: ErrorKind, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            retryable: true,
            ..Self::permanent(kind, code, message)
        }
    }

    /// Error used by default trait implementations.
    #[must_use]
    pub fn unsupported(method: &str) -> Self {
        Self::permanent(
            ErrorKind::Unsupported,
            "method_unsupported",
            format!("plugin does not implement `{method}`"),
        )
    }

    /// Set structured, non-sensitive details.
    #[must_use]
    pub fn with_details(mut self, details: Value) -> Self {
        self.details = details;
        self
    }

    /// Set a suggested retry delay.
    #[must_use]
    pub const fn with_retry_after(mut self, delay_ms: u64) -> Self {
        self.retry_after_ms = Some(delay_ms);
        self
    }
}

/// Result returned by plugin handler methods.
pub type PluginResult<T> = Result<T, PluginError>;

/// Fatal transport failure while serving a Rust plugin.
#[derive(Debug, Error)]
pub enum ServeError {
    /// Standard input/output failed.
    #[error("plugin stdio failed: {0}")]
    Io(#[from] io::Error),
    /// A server response/event could not be serialized.
    #[error("failed to serialize plugin JSON-RPC output: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Failures observed by a core-side [`crate::PluginClient`].
#[derive(Debug, Error)]
pub enum ClientError {
    /// The plugin could not be started.
    #[error("failed to spawn plugin `{program}`: {source}")]
    Spawn {
        /// Executable shown to the caller.
        program: String,
        /// Operating-system failure.
        #[source]
        source: io::Error,
    },
    /// Protocol input/output failed.
    #[error("plugin transport failed: {0}")]
    Io(#[from] io::Error),
    /// A request or response could not be encoded/decoded.
    #[error("invalid JSON-RPC payload: {0}")]
    Serialization(#[from] serde_json::Error),
    /// Stdout violated the newline-delimited JSON-RPC contract.
    #[error("plugin stdout protocol corruption: {0}")]
    Protocol(String),
    /// The plugin returned a structured application error.
    #[error("plugin request failed: {0}")]
    Remote(PluginError),
    /// The plugin returned a JSON-RPC error without valid structured data.
    #[error("plugin returned JSON-RPC error {code}: {message}")]
    RemoteRpc {
        /// Standard or implementation-defined JSON-RPC code.
        code: i64,
        /// Remote error message.
        message: String,
        /// Optional untyped data.
        data: Option<Value>,
    },
    /// The negotiated protocol is incompatible.
    #[error("plugin protocol mismatch: core requested {requested}, plugin selected {selected}")]
    ProtocolMismatch {
        /// Core-requested version.
        requested: ProtocolVersion,
        /// Plugin-selected version.
        selected: ProtocolVersion,
    },
    /// No response arrived before the configured deadline.
    #[error("plugin method `{method}` (request {id}) timed out after {timeout:?}")]
    Timeout {
        /// RPC method.
        method: String,
        /// Correlation ID.
        id: RequestId,
        /// Configured timeout.
        timeout: Duration,
    },
    /// A pending operation was cancelled.
    #[error("plugin request was cancelled")]
    Cancelled,
    /// The process or protocol stream closed.
    #[error("plugin connection is closed")]
    Closed,
}

impl ClientError {
    /// Whether retry policy may safely consider this failure transient.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Remote(error) => error.retryable,
            Self::Timeout { .. } | Self::Io(_) => true,
            Self::Spawn { .. }
            | Self::Serialization(_)
            | Self::Protocol(_)
            | Self::RemoteRpc { .. }
            | Self::ProtocolMismatch { .. }
            | Self::Cancelled
            | Self::Closed => false,
        }
    }
}

/// Internal cloneable failure used to wake correlated requests.
#[derive(Clone, Debug)]
pub(crate) enum TerminalFailure {
    Protocol(String),
    Closed,
}

impl From<TerminalFailure> for ClientError {
    fn from(value: TerminalFailure) -> Self {
        match value {
            TerminalFailure::Protocol(message) => Self::Protocol(message),
            TerminalFailure::Closed => Self::Closed,
        }
    }
}

impl fmt::Display for TerminalFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(message) => write!(formatter, "{message}"),
            Self::Closed => formatter.write_str("connection closed"),
        }
    }
}
