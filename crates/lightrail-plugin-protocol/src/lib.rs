//! Lightrail's language-neutral external plugin protocol.
//!
//! Plugins are normal executables. The core starts a plugin with piped standard
//! input, standard output, and standard error, clears the inherited environment,
//! and writes one UTF-8 JSON-RPC 2.0 object per line to stdin. Plugins must write
//! exactly one JSON-RPC object per line to stdout. Human-readable diagnostics go
//! to stderr; structured progress, log, and journal updates use the
//! [`methods::EVENT`] notification.
//!
//! The JSON representation intentionally avoids Rust-specific encodings:
//!
//! - protocol versions are semantic-version strings such as `"1.0.0"`;
//! - capabilities are stable kebab-case strings such as `"operation-lock"`;
//! - enums use a `kind` discriminator and `snake_case` variant names;
//! - durations are integer milliseconds;
//! - timestamps, when supplied, are RFC 3339 strings;
//! - opaque provider data is JSON under `metadata` or `state`;
//! - secrets are JSON strings on the wire, but [`SecretValue`] redacts `Debug`
//!   and `Display` output in Rust.
//!
//! Request methods and their parameter/result types are listed in [`methods`].
//! Unknown fields are accepted for forward compatibility. A new incompatible
//! wire shape requires a new protocol major version.

mod client;
mod error;
mod server;
mod types;
mod version;
mod wire;

pub use client::{
    ClientEvent, ClientOptions, DEFAULT_REQUEST_TIMEOUT, MAX_OPERATION_REQUEST_TIMEOUT,
    PluginClient, SpawnOptions, operation_request_timeout,
};
pub use error::{ClientError, ErrorKind, PluginError, PluginResult, ServeError};
pub use server::{EventSink, PluginHandler, serve, serve_stdio};
pub use types::*;
pub use version::{
    PROTOCOL_VERSION, PROTOCOL_VERSION_STRING, ProtocolCompatibility, ProtocolRequirement,
    ProtocolVersion, VersionParseError,
};
pub use wire::{JsonRpcError, RequestId};

/// Stable JSON-RPC method names.
pub mod methods {
    /// Negotiate the protocol and obtain the plugin manifest.
    pub const INITIALIZE: &str = "plugin.initialize";
    /// Validate plugin configuration and deployment input.
    pub const VALIDATE: &str = "plugin.validate";
    /// Compute an idempotent change plan.
    pub const PLAN: &str = "plugin.plan";
    /// Apply a previously computed plan.
    pub const APPLY: &str = "plugin.apply";
    /// Rediscover current provider/runtime state.
    pub const INSPECT: &str = "plugin.inspect";
    /// Destroy managed resources.
    pub const DESTROY: &str = "plugin.destroy";
    /// Cancel an operation by its stable operation ID.
    pub const CANCEL: &str = "plugin.cancel";
    /// Acquire an authoritative mutation lock.
    pub const LOCK_ACQUIRE: &str = "plugin.lock.acquire";
    /// Release an authoritative mutation lock.
    pub const LOCK_RELEASE: &str = "plugin.lock.release";
    /// Start or query a log stream.
    pub const LOGS: &str = "plugin.logs";
    /// Gracefully stop a plugin process.
    pub const SHUTDOWN: &str = "plugin.shutdown";
    /// Structured plugin-to-core event notification.
    pub const EVENT: &str = "plugin.event";
    /// JSON-RPC request cancellation notification.
    pub const CANCEL_REQUEST: &str = "$/cancelRequest";
}

/// Maximum accepted newline-delimited JSON-RPC message size.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
