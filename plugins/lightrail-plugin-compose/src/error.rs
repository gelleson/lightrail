use std::path::PathBuf;

use lightrail_plugin_protocol::{ErrorKind, PluginError};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ComposePluginError {
    #[error("invalid operation metadata: {source}")]
    Metadata { source: serde_json::Error },
    #[error("invalid desired Compose deployment: {source}")]
    Desired { source: serde_json::Error },
    #[error("invalid Compose plugin configuration: {source}")]
    Configuration { source: serde_json::Error },
    #[error("invalid target state: {source}")]
    Target { source: serde_json::Error },
    #[error("unsupported desired schema {0}; expected 1")]
    UnsupportedDesiredSchema(u32),
    #[error("project root was not supplied")]
    MissingProjectRoot,
    #[error("invalid Compose path `{0}`")]
    InvalidComposePath(PathBuf),
    #[error("{0}")]
    InvalidDesired(String),
    #[error("{0}")]
    InvalidTarget(String),
    #[error("Compose service `{0}` does not exist")]
    MissingService(String),
    #[error("service `{service}` uses forbidden host networking")]
    HostNetwork { service: String },
    #[error("service `{service}` uses local bind mount `{mount_source}`")]
    BindMount {
        service: String,
        mount_source: String,
    },
    #[error("named volume `{volume}` is external and cannot be environment-isolated")]
    ExternalVolume { volume: String },
    #[error("secret `{0}` was not supplied to the plugin")]
    MissingSecret(String),
    #[error("failed to serialize generated deployment: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("failed to create a local temporary file: {0}")]
    TemporaryFile(#[from] std::io::Error),
    #[error("could not start `{program}`: {source}")]
    CommandSpawn {
        program: String,
        source: std::io::Error,
    },
    #[error("`{program}` exited unsuccessfully ({status})")]
    CommandFailed { program: String, status: String },
    #[error("`{program}` did not provide its expected standard stream")]
    MissingPipe { program: String },
    #[error("SSH target is unavailable while running `{operation}`")]
    SshUnavailable { operation: String },
    #[error("readiness deadline expired for {0}")]
    ReadinessTimeout(String),
    #[error("generated remote path is unsafe")]
    UnsafeRemotePath,
    #[error("plan metadata is missing the desired deployment")]
    MissingPlanDesired,
    #[error("invalid or stale Compose plan: {0}")]
    InvalidPlan(String),
}

impl ComposePluginError {
    pub fn into_plugin_error(self) -> PluginError {
        let (kind, code, retryable) = match self {
            Self::Metadata { .. }
            | Self::Desired { .. }
            | Self::Configuration { .. }
            | Self::Target { .. }
            | Self::UnsupportedDesiredSchema(_)
            | Self::MissingProjectRoot
            | Self::InvalidComposePath(_)
            | Self::InvalidDesired(_)
            | Self::InvalidTarget(_)
            | Self::MissingService(_)
            | Self::HostNetwork { .. }
            | Self::BindMount { .. }
            | Self::ExternalVolume { .. }
            | Self::MissingSecret(_)
            | Self::UnsafeRemotePath
            | Self::MissingPlanDesired
            | Self::InvalidPlan(_) => (ErrorKind::Validation, "invalid_deployment", false),
            Self::Serialization(_) | Self::TemporaryFile(_) | Self::MissingPipe { .. } => {
                (ErrorKind::Internal, "plugin_internal", false)
            }
            Self::CommandSpawn { .. } => (ErrorKind::NotFound, "command_unavailable", false),
            Self::CommandFailed { .. } => (ErrorKind::Conflict, "command_failed", false),
            Self::SshUnavailable { .. } | Self::ReadinessTimeout(_) => {
                (ErrorKind::Unavailable, "target_unavailable", true)
            }
        };
        let message = self.to_string();
        let details = match &self {
            Self::CommandFailed { program, status } => {
                json!({"program": program, "status": status})
            }
            Self::MissingService(service) | Self::HostNetwork { service } => {
                json!({"service": service})
            }
            Self::BindMount {
                service,
                mount_source,
            } => {
                json!({"service": service, "source": mount_source})
            }
            Self::ExternalVolume { volume } => json!({"volume": volume}),
            _ => serde_json::Value::Null,
        };
        let mut error = if retryable {
            PluginError::retryable(kind, code, message)
        } else {
            PluginError::permanent(kind, code, message)
        };
        if !details.is_null() {
            error = error.with_details(details);
        }
        error
    }
}
