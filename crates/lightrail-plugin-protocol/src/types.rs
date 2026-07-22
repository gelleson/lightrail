use std::{collections::BTreeMap, fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use serde_json::Value;

use crate::{ProtocolCompatibility, ProtocolVersion};

/// A plugin capability encoded as a stable string.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum Capability {
    /// Resolve a source checkout/current working tree.
    Source,
    /// Build deployable artifacts.
    Builder,
    /// Provision or connect to infrastructure.
    Target,
    /// Run workloads on a target.
    Runtime,
    /// Expose applications publicly or privately.
    Exposure,
    /// Produce application hostnames.
    Dns,
    /// Resolve or provide secret material.
    Secrets,
    /// Coordinate authoritative mutation locks.
    OperationLock,
    /// Future provider/runtime usage reporting.
    Usage,
    /// Namespaced extension capability.
    Other(String),
}

impl Capability {
    /// Wire name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Source => "source",
            Self::Builder => "builder",
            Self::Target => "target",
            Self::Runtime => "runtime",
            Self::Exposure => "exposure",
            Self::Dns => "dns",
            Self::Secrets => "secrets",
            Self::OperationLock => "operation-lock",
            Self::Usage => "usage",
            Self::Other(value) => value,
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Capability {
    type Err = std::convert::Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(match value {
            "source" => Self::Source,
            "builder" => Self::Builder,
            "target" => Self::Target,
            "runtime" => Self::Runtime,
            "exposure" => Self::Exposure,
            "dns" => Self::Dns,
            "secrets" => Self::Secrets,
            "operation-lock" => Self::OperationLock,
            "usage" => Self::Usage,
            other => Self::Other(other.to_owned()),
        })
    }
}

impl Serialize for Capability {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Capability {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(de::Error::custom)
    }
}

/// A secret whose Rust diagnostics never reveal the plaintext.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SecretValue(String);

impl SecretValue {
    /// Wrap plaintext for transport to an explicitly authorized plugin.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Explicitly expose the plaintext.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue([REDACTED])")
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

/// OS/architecture supported by a distributed executable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Platform {
    /// Operating-system identifier (`linux`, `macos`, and so on).
    pub os: String,
    /// Architecture identifier (`amd64`, `arm64`, and so on).
    pub arch: String,
}

/// Distribution metadata for the plugin executable.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutableMetadata {
    /// Executable basename or package entrypoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Fixed arguments required before protocol traffic begins.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Supported host platforms; empty means unspecified.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub platforms: Vec<Platform>,
    /// Optional lowercase SHA-256 digest of the distributed executable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Optional human-facing project URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
}

/// Secret a plugin is permitted to receive.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SecretRequirement {
    /// Stable configuration name.
    pub name: String,
    /// Human-readable purpose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether validation fails when the secret is unavailable.
    #[serde(default = "default_true")]
    pub required: bool,
}

const fn default_true() -> bool {
    true
}

/// Manifest returned during initialization.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PluginManifest {
    /// Globally unique, reverse-DNS-style plugin ID.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Plugin semantic version.
    pub version: String,
    /// Exact and accepted protocol versions.
    pub protocol: ProtocolCompatibility,
    /// Executable distribution metadata.
    #[serde(default)]
    pub executable: ExecutableMetadata,
    /// Implemented capabilities.
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    /// Optional namespaced behavior contracts implemented by this plugin.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    /// Secrets core may resolve and pass to this plugin.
    #[serde(default)]
    pub required_secrets: Vec<SecretRequirement>,
    /// Draft 2020-12-compatible JSON Schema for plugin configuration.
    #[serde(default = "empty_object")]
    pub config_schema: Value,
    /// Optional renderer-neutral UI annotations keyed by schema path.
    #[serde(default = "empty_object")]
    pub config_ui_hints: Value,
}

fn empty_object() -> Value {
    Value::Object(serde_json::Map::new())
}

/// Core-to-plugin protocol negotiation request.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InitializeRequest {
    /// Lightrail core semantic version.
    pub core_version: String,
    /// Preferred protocol version.
    pub protocol_version: ProtocolVersion,
    /// All protocol versions core can speak, in preference order.
    #[serde(default)]
    pub supported_protocol_versions: Vec<ProtocolVersion>,
}

impl InitializeRequest {
    /// Request negotiation using the crate's current protocol.
    #[must_use]
    pub fn current(core_version: impl Into<String>) -> Self {
        Self {
            core_version: core_version.into(),
            protocol_version: crate::PROTOCOL_VERSION,
            supported_protocol_versions: vec![crate::PROTOCOL_VERSION],
        }
    }
}

/// Successful protocol negotiation.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InitializeResult {
    /// Agreed wire protocol.
    pub protocol_version: ProtocolVersion,
    /// Per-process opaque session identifier.
    pub session_id: String,
    /// Plugin declaration.
    pub manifest: PluginManifest,
}

/// Shared data passed to mutating and inspection operations.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct OperationContext {
    /// Stable ID shared by progress, journal, cancel, and result messages.
    pub operation_id: String,
    /// Deterministic Lightrail environment ID.
    pub environment_id: String,
    /// Selected profile.
    pub profile: String,
    /// Project root as a platform-native absolute string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_root: Option<String>,
    /// Plugin-specific validated configuration.
    #[serde(default = "empty_object")]
    pub config: Value,
    /// Only manifest-declared secrets, resolved by core.
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretValue>,
    /// Extensible non-sensitive operation input.
    #[serde(default = "empty_object")]
    pub metadata: Value,
}

/// Severity used by validation and runtime diagnostics.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    /// Informational observation.
    Info,
    /// Non-blocking concern.
    Warning,
    /// Blocking invalid state.
    Error,
}

/// Structured actionable diagnostic.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Diagnostic {
    /// Severity.
    pub severity: DiagnosticSeverity,
    /// Stable code.
    pub code: String,
    /// Human-readable message.
    pub message: String,
    /// Optional JSON pointer/config path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Optional suggested remediation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
}

/// Validate plugin configuration and desired input.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ValidateRequest {
    /// Operation context.
    pub context: OperationContext,
    /// Desired plugin-specific state.
    #[serde(default = "empty_object")]
    pub desired: Value,
}

/// Validation output.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ValidateResult {
    /// Whether deployment may continue.
    pub valid: bool,
    /// All discovered problems and warnings.
    #[serde(default)]
    pub diagnostics: Vec<Diagnostic>,
    /// Optional normalized non-secret configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normalized_config: Option<Value>,
}

/// Metadata sufficient to reverse one applied action.
#[derive(Clone, Deserialize, Serialize)]
pub struct RollbackMetadata {
    /// Whether the action has an automatic inverse.
    pub supported: bool,
    /// Inverse action kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Opaque rollback token. It is treated as sensitive in Rust diagnostics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<SecretValue>,
    /// Non-sensitive inverse parameters.
    #[serde(default = "empty_object")]
    pub metadata: Value,
}

impl fmt::Debug for RollbackMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RollbackMetadata")
            .field("supported", &self.supported)
            .field("action", &self.action)
            .field("token", &self.token)
            .field("metadata", &self.metadata)
            .finish()
    }
}

/// One deterministic action in a plan.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PlannedAction {
    /// Stable action ID within the plan.
    pub id: String,
    /// Plugin-defined action kind.
    pub kind: String,
    /// User-facing summary.
    pub summary: String,
    /// Whether this action deletes or irreversibly mutates resources.
    #[serde(default)]
    pub destructive: bool,
    /// Action IDs that must complete first.
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// Rollback contract known before apply, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback: Option<RollbackMetadata>,
    /// Provider/runtime-specific non-sensitive input.
    #[serde(default = "empty_object")]
    pub metadata: Value,
}

/// Compute changes for a desired state.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PlanRequest {
    /// Operation context.
    pub context: OperationContext,
    /// Desired state.
    #[serde(default = "empty_object")]
    pub desired: Value,
    /// Last inspected state, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<Value>,
}

/// Deterministic idempotent change plan.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PlanResult {
    /// Stable digest/ID used to reject stale apply requests.
    pub plan_id: String,
    /// Ordered/dependency-linked actions.
    #[serde(default)]
    pub actions: Vec<PlannedAction>,
    /// Whether apply would change anything.
    pub has_changes: bool,
    /// Plugin-specific non-sensitive plan data.
    #[serde(default = "empty_object")]
    pub metadata: Value,
}

/// Journal action status.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalStatus {
    /// Execution began.
    Started,
    /// Execution succeeded.
    Succeeded,
    /// Execution failed.
    Failed,
    /// Rollback began.
    RollingBack,
    /// Rollback succeeded.
    RolledBack,
    /// Rollback failed.
    RollbackFailed,
    /// Action was skipped.
    Skipped,
}

/// Durable action journal record emitted during apply/destroy.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ActionJournalEntry {
    /// Monotonic sequence within the operation.
    pub sequence: u64,
    /// Planned action ID.
    pub action_id: String,
    /// Current action status.
    pub status: JournalStatus,
    /// Optional RFC 3339 timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    /// Safe status text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Actual rollback metadata discovered during apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback: Option<RollbackMetadata>,
    /// Non-sensitive provider identifiers.
    #[serde(default = "empty_object")]
    pub metadata: Value,
}

/// Apply a plan.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ApplyRequest {
    /// Operation context.
    pub context: OperationContext,
    /// Exact plan returned by `plugin.plan`.
    pub plan: PlanResult,
    /// Existing journal when resuming an interrupted operation.
    #[serde(default)]
    pub journal: Vec<ActionJournalEntry>,
}

/// Apply result.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ApplyResult {
    /// Plugin-defined revision/digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    /// Rediscoverable provider/runtime state.
    #[serde(default = "empty_object")]
    pub state: Value,
    /// Final journal snapshot.
    #[serde(default)]
    pub journal: Vec<ActionJournalEntry>,
}

/// Inspect current environment state.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InspectRequest {
    /// Operation context.
    pub context: OperationContext,
}

/// Coarse resource lifecycle state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceStatus {
    /// No managed resources found.
    Absent,
    /// Provisioning or update in progress.
    Pending,
    /// Present and expected to operate.
    Ready,
    /// Present but unhealthy/partially configured.
    Degraded,
    /// Destruction in progress.
    Destroying,
    /// Provider state could not be determined.
    Unknown,
}

/// One public application endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Endpoint {
    /// Application identifier.
    pub app: String,
    /// Absolute URL.
    pub url: String,
}

/// Inspection result.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InspectResult {
    /// Coarse lifecycle state.
    pub status: ResourceStatus,
    /// Public application URLs.
    #[serde(default)]
    pub endpoints: Vec<Endpoint>,
    /// Provider/runtime state used by later planning.
    #[serde(default = "empty_object")]
    pub state: Value,
    /// Non-blocking observations.
    #[serde(default)]
    pub diagnostics: Vec<Diagnostic>,
}

/// Destroy resources for an environment.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DestroyRequest {
    /// Operation context.
    pub context: OperationContext,
    /// Previously inspected state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<Value>,
    /// Explicit recovery override.
    #[serde(default)]
    pub force: bool,
    /// Existing journal when resuming destruction.
    #[serde(default)]
    pub journal: Vec<ActionJournalEntry>,
}

/// Destruction result.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DestroyResult {
    /// Whether all owned resources are absent.
    pub destroyed: bool,
    /// Final journal snapshot.
    #[serde(default)]
    pub journal: Vec<ActionJournalEntry>,
    /// Resources that could not be removed.
    #[serde(default)]
    pub remaining: Vec<String>,
}

/// Cancel a logical operation.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CancelRequest {
    /// Stable operation ID.
    pub operation_id: String,
    /// Safe reason shown to plugin logs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Cancellation acknowledgement.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CancelResult {
    /// Whether a live operation was found and signalled.
    pub acknowledged: bool,
}

/// Scope protected by an authoritative mutation lock.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LockScope {
    /// One deterministic branch/profile environment.
    #[default]
    Environment,
    /// Every environment owned by one project.
    Project,
    /// Shared target-wide resources such as a host ingress controller.
    Target,
}

/// Acquire an authoritative mutation lock.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LockAcquireRequest {
    /// Current environment identity used to resolve the target.
    pub environment_id: String,
    /// Mutation aggregate being protected.
    #[serde(default)]
    pub scope: LockScope,
    /// Stable scope identity. Plugins may further strengthen target-wide scope.
    #[serde(default)]
    pub scope_id: String,
    /// Logical operation taking ownership.
    pub operation_id: String,
    /// Maximum wait in milliseconds.
    pub timeout_ms: u64,
    /// Lease request. `None` allows a connection-scoped lock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_ms: Option<u64>,
}

/// Acquired lock.
#[derive(Clone, Deserialize, Serialize)]
pub struct LockAcquireResult {
    /// Whether ownership was acquired.
    pub acquired: bool,
    /// Opaque release/renewal token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<SecretValue>,
    /// Optional RFC 3339 lease expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Current holder description when acquisition failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
}

impl fmt::Debug for LockAcquireResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LockAcquireResult")
            .field("acquired", &self.acquired)
            .field("token", &self.token)
            .field("expires_at", &self.expires_at)
            .field("holder", &self.holder)
            .finish()
    }
}

/// Release an authoritative environment mutation lock.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LockReleaseRequest {
    /// Current environment identity used to resolve the target.
    pub environment_id: String,
    /// Mutation aggregate that was protected.
    #[serde(default)]
    pub scope: LockScope,
    /// Stable scope identity supplied at acquisition.
    #[serde(default)]
    pub scope_id: String,
    /// Logical owner.
    pub operation_id: String,
    /// Token returned by acquire.
    pub token: SecretValue,
}

/// Lock release result.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LockReleaseResult {
    /// Whether this call released the lock. Already-absent is also successful.
    pub released: bool,
}

/// Request application/runtime logs.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LogsRequest {
    /// Operation context.
    pub context: OperationContext,
    /// Optional service filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// Number of historical records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tail: Option<u64>,
    /// RFC 3339 or runtime-defined cursor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    /// Keep emitting [`PluginEvent::Log`] records.
    #[serde(default)]
    pub follow: bool,
}

/// One log record.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LogRecord {
    /// Service/application source.
    pub service: String,
    /// Optional RFC 3339 timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    /// Raw logical line without a newline.
    pub line: String,
    /// Stream (`stdout`, `stderr`, or plugin-defined).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<String>,
}

/// Initial logs response; follow-up records arrive as events.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct LogsResult {
    /// Stream identifier used to correlate follow events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    /// Initial historical records.
    #[serde(default)]
    pub records: Vec<LogRecord>,
}

/// Structured plugin notification.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PluginEvent {
    /// Progress for a long-running logical operation.
    Progress {
        /// Stable operation ID.
        operation_id: String,
        /// Current safe human-readable activity.
        message: String,
        /// Completed work units.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        completed: Option<u64>,
        /// Total work units.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        total: Option<u64>,
    },
    /// Live log stream record.
    Log {
        /// Correlates with [`LogsResult::stream_id`].
        stream_id: String,
        /// Log data.
        record: LogRecord,
    },
    /// Durable action journal update.
    Journal {
        /// Stable operation ID.
        operation_id: String,
        /// Journal record.
        entry: ActionJournalEntry,
    },
    /// Actionable non-secret diagnostic.
    Diagnostic {
        /// Optional operation association.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        operation_id: Option<String>,
        /// Diagnostic data.
        diagnostic: Diagnostic,
    },
}

/// Empty request/result object used by shutdown.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
pub struct Empty {}
