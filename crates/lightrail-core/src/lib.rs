//! Validated, provider-independent domain types for Lightrail.
//!
//! The crate owns configuration schema validation, current-checkout discovery,
//! deterministic environment identity, and collision-safe hostname generation.
//! Provider APIs and deployment side effects intentionally live outside this
//! boundary.

pub mod config;
pub mod error;
pub mod git;
pub mod identity;
pub mod naming;

pub use config::{
    App, CONFIG_SCHEMA_VERSION, Capability, EnvironmentValue, IdentifierError, Isolation,
    LightrailConfig, PluginId, PluginPipeline, Profile, Project, ProjectId, SecretName,
    SecretReference, UnknownCapability,
};
pub use error::{
    ConfigError, GitError, NamingError, SettingsConversionError, ValidationCode, ValidationErrors,
    ValidationIssue,
};
pub use git::GitContext;
pub use identity::{
    EnvironmentId, EnvironmentIdentity, LABEL_BRANCH, LABEL_ENVIRONMENT_ID, LABEL_MANAGED,
    LABEL_PROFILE, LABEL_PROJECT, LABEL_PROJECT_ID,
};
pub use naming::{
    DNS_LABEL_MAX_BYTES, DNS_NAME_MAX_BYTES, DnsLabel, Hostname, IpDnsDomain, ipv4_hex,
};
