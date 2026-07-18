use std::path::PathBuf;

/// Errors that can be presented directly by the command-line application.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("{0}")]
    Usage(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("project not initialized (could not find lightrail.toml from {start})")]
    ProjectNotInitialized { start: PathBuf },

    #[error("required tool `{tool}` is unavailable: {detail}")]
    MissingTool { tool: &'static str, detail: String },

    #[error("secret `{name}` is unavailable; set it with `lightrail secret set {name}` or {env}")]
    SecretUnavailable { name: String, env: String },

    #[error("plugin error: {0}")]
    Plugin(String),

    #[error("operation failed: {0}")]
    Operation(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    TomlDecode(#[from] toml::de::Error),

    #[error(transparent)]
    TomlEncode(#[from] toml::ser::Error),
}

impl CliError {
    /// Stable process exit status by error category.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) | Self::Config(_) | Self::ProjectNotInitialized { .. } => 2,
            Self::MissingTool { .. } => 3,
            Self::SecretUnavailable { .. } => 4,
            Self::Plugin(_) => 5,
            Self::Operation(_)
            | Self::Io(_)
            | Self::Json(_)
            | Self::TomlDecode(_)
            | Self::TomlEncode(_) => 1,
        }
    }
}
