//! Versioned, provider-independent project configuration.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use uuid::Uuid;

use crate::error::{
    ConfigError, SettingsConversionError, ValidationCode, ValidationErrors, ValidationIssue,
};

/// The only configuration schema understood by this release.
pub const CONFIG_SCHEMA_VERSION: u32 = 1;

const MAX_SEMANTIC_NAME_BYTES: usize = 255;
const MAX_PLUGIN_ID_BYTES: usize = 128;
const MAX_SECRET_NAME_BYTES: usize = 128;

/// Stable project identity.
///
/// Unlike a project slug, this value is never derived from a directory name and
/// must remain unchanged when the project is renamed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProjectId(Uuid);

impl ProjectId {
    /// Generates a new random project identity.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Wraps an existing UUID.
    #[must_use]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Returns the underlying UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }

    /// Returns the UUID without hyphens, suitable for resource labels.
    #[must_use]
    pub fn simple(self) -> String {
        self.0.simple().to_string()
    }
}

impl Default for ProjectId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ProjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for ProjectId {
    type Err = uuid::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
    }
}

impl From<Uuid> for ProjectId {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl From<ProjectId> for Uuid {
    fn from(value: ProjectId) -> Self {
        value.0
    }
}

/// A failure to construct a semantic identifier.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentifierError {
    /// The identifier is empty.
    #[error("{kind} must not be empty")]
    Empty {
        /// Identifier category.
        kind: &'static str,
    },

    /// The identifier is longer than its protocol limit.
    #[error("{kind} is {length} bytes; the maximum is {maximum}")]
    TooLong {
        /// Identifier category.
        kind: &'static str,
        /// Actual byte length.
        length: usize,
        /// Maximum byte length.
        maximum: usize,
    },

    /// The identifier contains characters outside its safe alphabet.
    #[error("{kind} `{value}` must use lowercase ASCII letters, digits, `.`, `_`, or `-`")]
    InvalidCharacters {
        /// Identifier category.
        kind: &'static str,
        /// Invalid value.
        value: String,
    },
}

/// Stable identifier of an executable plugin.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PluginId(String);

impl PluginId {
    /// Validates and creates a plugin identifier.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError`] when the value is empty, too long, or
    /// outside the lowercase protocol-safe alphabet.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        let value = value.into();
        validate_protocol_identifier("plugin ID", &value, MAX_PLUGIN_ID_BYTES)?;
        Ok(Self(value))
    }

    /// Returns the identifier as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PluginId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for PluginId {
    type Err = IdentifierError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for PluginId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PluginId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Name of a secret resolved by the core before a plugin is launched.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretName(String);

impl SecretName {
    /// Validates and creates a secret name.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError`] when the value is empty, too long, or
    /// outside the lowercase protocol-safe alphabet.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        let value = value.into();
        validate_protocol_identifier("secret name", &value, MAX_SECRET_NAME_BYTES)?;
        Ok(Self(value))
    }

    /// Returns the secret name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecretName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for SecretName {
    type Err = IdentifierError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for SecretName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// A literal environment value or a reference to a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EnvironmentValue {
    /// A value committed directly to `lightrail.toml`.
    Literal(String),
    /// A value resolved from the configured secret sources.
    Secret(SecretReference),
}

impl EnvironmentValue {
    /// Creates a literal environment value.
    #[must_use]
    pub fn literal(value: impl Into<String>) -> Self {
        Self::Literal(value.into())
    }

    /// Creates a secret-backed environment value.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError`] when `name` is not protocol-safe.
    pub fn secret(name: impl Into<String>) -> Result<Self, IdentifierError> {
        Ok(Self::Secret(SecretReference {
            secret: SecretName::new(name)?,
        }))
    }

    /// Returns the literal value, when this is not a secret reference.
    #[must_use]
    pub fn as_literal(&self) -> Option<&str> {
        match self {
            Self::Literal(value) => Some(value),
            Self::Secret(_) => None,
        }
    }

    /// Returns the referenced secret name, when present.
    #[must_use]
    pub fn secret_name(&self) -> Option<&SecretName> {
        match self {
            Self::Literal(_) => None,
            Self::Secret(reference) => Some(&reference.secret),
        }
    }
}

/// Serialized shape of `{ secret = "name" }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretReference {
    /// Name resolved from environment overrides, the OS keyring, or a prompt.
    pub secret: SecretName,
}

/// The isolation boundary used by a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Isolation {
    /// Multiple environments share a host but have isolated Compose resources.
    Project,
    /// Each environment owns a provider-native namespace or application boundary.
    Environment,
    /// The environment owns a complete machine.
    Machine,
}

/// A capability filled by one plugin in a deployment pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    /// Discovers source from the checkout.
    Source,
    /// Builds deployable artifacts.
    Builder,
    /// Provisions or locates infrastructure.
    Target,
    /// Runs application services.
    Runtime,
    /// Publishes application routes.
    Exposure,
    /// Maps routes to an IP-derived DNS name.
    Dns,
}

impl Capability {
    /// All pipeline capabilities in execution order.
    pub const ALL: [Self; 6] = [
        Self::Source,
        Self::Builder,
        Self::Target,
        Self::Runtime,
        Self::Exposure,
        Self::Dns,
    ];

    /// Returns the stable configuration key for this capability.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Builder => "builder",
            Self::Target => "target",
            Self::Runtime => "runtime",
            Self::Exposure => "exposure",
            Self::Dns => "dns",
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Capability {
    type Err = UnknownCapability;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "source" => Ok(Self::Source),
            "builder" => Ok(Self::Builder),
            "target" => Ok(Self::Target),
            "runtime" => Ok(Self::Runtime),
            "exposure" => Ok(Self::Exposure),
            "dns" => Ok(Self::Dns),
            _ => Err(UnknownCapability(value.to_owned())),
        }
    }
}

/// A plugin-settings key does not name a pipeline capability.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("unknown pipeline capability `{0}`")]
pub struct UnknownCapability(pub String);

/// Complete plugin selection for one profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginPipeline {
    /// Checkout/source plugin.
    pub source: PluginId,
    /// Artifact builder plugin.
    pub builder: PluginId,
    /// Infrastructure target plugin.
    pub target: PluginId,
    /// Workload runtime plugin.
    pub runtime: PluginId,
    /// Public or private exposure plugin.
    pub exposure: PluginId,
    /// IP-DNS plugin.
    pub dns: PluginId,
}

impl PluginPipeline {
    /// Returns the plugin assigned to a capability.
    #[must_use]
    pub const fn plugin(&self, capability: Capability) -> &PluginId {
        match capability {
            Capability::Source => &self.source,
            Capability::Builder => &self.builder,
            Capability::Target => &self.target,
            Capability::Runtime => &self.runtime,
            Capability::Exposure => &self.exposure,
            Capability::Dns => &self.dns,
        }
    }
}

/// Project-level metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    /// Immutable UUID generated by `lightrail init`.
    pub id: ProjectId,
    /// Human-facing project name used in hostnames.
    pub slug: String,
    /// Compose files, in merge order, relative to the repository root.
    pub compose: Vec<PathBuf>,
    /// Profile used when no CLI or environment override is provided.
    pub default_profile: String,
}

/// One public application route backed by a Compose service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct App {
    /// Compose service name.
    pub service: String,
    /// Internal container port routed by the exposure plugin.
    pub port: u16,
    /// Optional readiness endpoint path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_path: Option<String>,
    /// Optional exact HTTP status expected from the readiness endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_status: Option<u16>,
    /// Optional readiness polling interval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_interval_seconds: Option<u64>,
    /// Optional per-request readiness timeout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_timeout_seconds: Option<u64>,
    /// Environment defaults applied whenever this app is selected.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, EnvironmentValue>,
}

/// One reusable environment profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Shared-project, provider-environment, or machine isolation boundary.
    pub isolation: Isolation,
    /// Public apps selected from the top-level app map.
    pub apps: Vec<String>,
    /// Capability-to-plugin assignment.
    pub pipeline: PluginPipeline,
    /// Opaque settings passed to each capability plugin.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub settings: BTreeMap<String, toml::Value>,
    /// Environment values applied to all services in this profile.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, EnvironmentValue>,
    /// Per-app environment overrides for this profile.
    ///
    /// TOML uses `[profiles.<profile>.app_env.<app>]` to avoid colliding with
    /// the `apps = [...]` selection list.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub app_env: BTreeMap<String, BTreeMap<String, EnvironmentValue>>,
}

impl Profile {
    /// Returns opaque TOML settings for a capability.
    #[must_use]
    pub fn settings(&self, capability: Capability) -> Option<&toml::Value> {
        self.settings.get(capability.as_str())
    }

    /// Converts one capability's settings to the JSON value sent to a plugin.
    ///
    /// `Ok(None)` means that the profile did not configure the capability.
    ///
    /// # Errors
    ///
    /// Returns [`SettingsConversionError`] if the TOML value cannot be
    /// represented by `serde_json::Value`.
    pub fn settings_json(
        &self,
        capability: Capability,
    ) -> Result<Option<serde_json::Value>, SettingsConversionError> {
        self.settings(capability)
            .map(serde_json::to_value)
            .transpose()
            .map_err(SettingsConversionError::from)
    }
}

/// Root of a committed `lightrail.toml`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LightrailConfig {
    /// Configuration schema version. This release accepts only `1`.
    pub schema: u32,
    /// Stable project metadata.
    pub project: Project,
    /// Public applications keyed by app name.
    #[serde(default)]
    pub apps: BTreeMap<String, App>,
    /// Reusable profiles keyed by profile name.
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

impl LightrailConfig {
    /// Parses and validates a TOML configuration held in memory.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Parse`] for malformed TOML or
    /// [`ConfigError::Validation`] when domain invariants do not hold.
    pub fn parse(source: &str) -> Result<Self, ConfigError> {
        Self::parse_from(source, "<memory>")
    }

    /// Loads and validates a TOML configuration from disk.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Read`] when the file cannot be read, or the same
    /// parse and validation errors as [`Self::parse`].
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let source = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse_from(&source, &path.display().to_string())
    }

    /// Validates all provider-independent configuration invariants.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationErrors`] containing every independent problem found.
    pub fn validate(&self) -> Result<(), ValidationErrors> {
        let mut issues = Vec::new();

        if self.schema != CONFIG_SCHEMA_VERSION {
            issues.push(ValidationIssue::new(
                "schema",
                ValidationCode::UnsupportedSchema,
                format!(
                    "schema {} is unsupported; expected {CONFIG_SCHEMA_VERSION}",
                    self.schema
                ),
            ));
        }

        validate_project(&self.project, &self.profiles, &mut issues);
        validate_apps(&self.apps, &mut issues);
        validate_profiles(&self.profiles, &self.apps, &mut issues);

        match ValidationErrors::from_issues(issues) {
            Some(errors) => Err(errors),
            None => Ok(()),
        }
    }

    /// Serializes a valid configuration as pretty TOML.
    ///
    /// # Errors
    ///
    /// Returns validation errors for an invalid in-memory value, or
    /// [`ConfigError::Serialize`] if TOML serialization fails.
    pub fn to_toml_pretty(&self) -> Result<String, ConfigError> {
        self.validate()?;
        toml::to_string_pretty(self).map_err(ConfigError::from)
    }

    /// Returns the configured default profile.
    #[must_use]
    pub fn default_profile(&self) -> Option<(&str, &Profile)> {
        self.profiles
            .get_key_value(&self.project.default_profile)
            .map(|(name, profile)| (name.as_str(), profile))
    }

    /// Returns a named profile.
    #[must_use]
    pub fn profile(&self, name: &str) -> Option<&Profile> {
        self.profiles.get(name)
    }

    /// Returns a named public app.
    #[must_use]
    pub fn app(&self, name: &str) -> Option<&App> {
        self.apps.get(name)
    }

    fn parse_from(source: &str, origin: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(source).map_err(|source| ConfigError::Parse {
            origin: origin.to_owned(),
            source,
        })?;
        config.validate()?;
        Ok(config)
    }
}

fn validate_protocol_identifier(
    kind: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), IdentifierError> {
    if value.is_empty() {
        return Err(IdentifierError::Empty { kind });
    }
    if value.len() > maximum {
        return Err(IdentifierError::TooLong {
            kind,
            length: value.len(),
            maximum,
        });
    }

    let bytes = value.as_bytes();
    let has_safe_edges = bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric);
    let safe_characters = bytes.iter().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
    });
    let has_empty_segment = value.split('.').any(str::is_empty);

    if !has_safe_edges || !safe_characters || has_empty_segment {
        return Err(IdentifierError::InvalidCharacters {
            kind,
            value: value.to_owned(),
        });
    }

    Ok(())
}

fn validate_project(
    project: &Project,
    profiles: &BTreeMap<String, Profile>,
    issues: &mut Vec<ValidationIssue>,
) {
    if project.id.as_uuid().is_nil() {
        issues.push(ValidationIssue::new(
            "project.id",
            ValidationCode::InvalidIdentifier,
            "project UUID must not be nil",
        ));
    }
    validate_semantic_name("project.slug", &project.slug, issues);
    validate_semantic_name("project.default_profile", &project.default_profile, issues);

    if project.compose.is_empty() {
        issues.push(ValidationIssue::new(
            "project.compose",
            ValidationCode::Empty,
            "at least one Compose file is required",
        ));
    }

    let mut compose_paths = BTreeSet::new();
    for (index, path) in project.compose.iter().enumerate() {
        let field = format!("project.compose[{index}]");
        let valid_components = !path.as_os_str().is_empty()
            && !path.is_absolute()
            && path
                .components()
                .all(|component| matches!(component, Component::Normal(_)));
        if !valid_components {
            issues.push(ValidationIssue::new(
                &field,
                ValidationCode::InvalidPath,
                "Compose paths must be non-empty, normalized paths relative to the repository root",
            ));
        }
        if !compose_paths.insert(path) {
            issues.push(ValidationIssue::new(
                field,
                ValidationCode::Duplicate,
                format!("Compose path `{}` is listed more than once", path.display()),
            ));
        }
    }

    if !project.default_profile.is_empty()
        && !profiles.contains_key(project.default_profile.as_str())
    {
        issues.push(ValidationIssue::new(
            "project.default_profile",
            ValidationCode::MissingReference,
            format!(
                "profile `{}` does not exist",
                project.default_profile.as_str()
            ),
        ));
    }
}

fn validate_apps(apps: &BTreeMap<String, App>, issues: &mut Vec<ValidationIssue>) {
    if apps.is_empty() {
        issues.push(ValidationIssue::new(
            "apps",
            ValidationCode::Empty,
            "at least one public app is required",
        ));
    }

    for (name, app) in apps {
        let base = format!("apps.{name}");
        validate_semantic_name(&format!("{base} (name)"), name, issues);

        if !is_compose_service_name(&app.service) {
            issues.push(ValidationIssue::new(
                format!("{base}.service"),
                ValidationCode::InvalidIdentifier,
                "service must begin with an ASCII letter or digit and contain only letters, digits, `.`, `_`, or `-`",
            ));
        }
        if app.port == 0 {
            issues.push(ValidationIssue::new(
                format!("{base}.port"),
                ValidationCode::InvalidPort,
                "internal app port must be between 1 and 65535",
            ));
        }

        validate_health(app, &base, issues);
        validate_environment(&app.env, &format!("{base}.env"), issues);
    }
}

fn validate_health(app: &App, base: &str, issues: &mut Vec<ValidationIssue>) {
    if let Some(path) = &app.health_path {
        if !path.starts_with('/')
            || path.chars().any(char::is_control)
            || path.chars().any(char::is_whitespace)
        {
            issues.push(ValidationIssue::new(
                format!("{base}.health_path"),
                ValidationCode::InvalidHealthCheck,
                "health path must begin with `/` and contain no whitespace or control characters",
            ));
        }
    }

    if let Some(status) = app.health_status {
        if !(100..=599).contains(&status) {
            issues.push(ValidationIssue::new(
                format!("{base}.health_status"),
                ValidationCode::InvalidHealthCheck,
                "health status must be between 100 and 599",
            ));
        }
    }

    let has_health_tuning = app.health_status.is_some()
        || app.health_interval_seconds.is_some()
        || app.health_timeout_seconds.is_some();
    if has_health_tuning && app.health_path.is_none() {
        issues.push(ValidationIssue::new(
            format!("{base}.health_path"),
            ValidationCode::InvalidHealthCheck,
            "health_path is required when other health-check settings are present",
        ));
    }

    for (field, value) in [
        ("health_interval_seconds", app.health_interval_seconds),
        ("health_timeout_seconds", app.health_timeout_seconds),
    ] {
        if value == Some(0) {
            issues.push(ValidationIssue::new(
                format!("{base}.{field}"),
                ValidationCode::InvalidHealthCheck,
                format!("{field} must be greater than zero"),
            ));
        }
    }
}

fn validate_profiles(
    profiles: &BTreeMap<String, Profile>,
    apps: &BTreeMap<String, App>,
    issues: &mut Vec<ValidationIssue>,
) {
    if profiles.is_empty() {
        issues.push(ValidationIssue::new(
            "profiles",
            ValidationCode::Empty,
            "at least one profile is required",
        ));
    }

    for (name, profile) in profiles {
        let base = format!("profiles.{name}");
        validate_semantic_name(&format!("{base} (name)"), name, issues);

        if profile.apps.is_empty() {
            issues.push(ValidationIssue::new(
                format!("{base}.apps"),
                ValidationCode::Empty,
                "profile must select at least one public app",
            ));
        }

        let mut selected = BTreeSet::new();
        for (index, app_name) in profile.apps.iter().enumerate() {
            let field = format!("{base}.apps[{index}]");
            if !selected.insert(app_name.as_str()) {
                issues.push(ValidationIssue::new(
                    &field,
                    ValidationCode::Duplicate,
                    format!("app `{app_name}` is selected more than once"),
                ));
            }
            if !apps.contains_key(app_name) {
                issues.push(ValidationIssue::new(
                    field,
                    ValidationCode::MissingReference,
                    format!("app `{app_name}` does not exist"),
                ));
            }
        }

        for key in profile.settings.keys() {
            if Capability::from_str(key).is_err() {
                issues.push(ValidationIssue::new(
                    format!("{base}.settings.{key}"),
                    ValidationCode::UnknownCapability,
                    format!(
                        "`{key}` is not one of source, builder, target, runtime, exposure, or dns"
                    ),
                ));
            }
        }

        validate_environment(&profile.env, &format!("{base}.env"), issues);
        for (app_name, environment) in &profile.app_env {
            let field = format!("{base}.app_env.{app_name}");
            if !apps.contains_key(app_name) {
                issues.push(ValidationIssue::new(
                    &field,
                    ValidationCode::MissingReference,
                    format!("app `{app_name}` does not exist"),
                ));
            } else if !selected.contains(app_name.as_str()) {
                issues.push(ValidationIssue::new(
                    &field,
                    ValidationCode::MissingReference,
                    format!("app `{app_name}` is not selected by this profile"),
                ));
            }
            validate_environment(environment, &field, issues);
        }
    }
}

fn validate_environment(
    environment: &BTreeMap<String, EnvironmentValue>,
    base: &str,
    issues: &mut Vec<ValidationIssue>,
) {
    for key in environment.keys() {
        if !is_environment_key(key) {
            issues.push(ValidationIssue::new(
                format!("{base}.{key}"),
                ValidationCode::InvalidEnvironmentKey,
                "environment keys must match [A-Za-z_][A-Za-z0-9_]*",
            ));
        }
    }
}

fn validate_semantic_name(path: &str, value: &str, issues: &mut Vec<ValidationIssue>) {
    if value.is_empty() {
        issues.push(ValidationIssue::new(
            path,
            ValidationCode::Empty,
            "value must not be empty",
        ));
    } else if value.trim() != value
        || value.len() > MAX_SEMANTIC_NAME_BYTES
        || value.chars().any(char::is_control)
    {
        issues.push(ValidationIssue::new(
            path,
            ValidationCode::InvalidIdentifier,
            format!(
                "value must be at most {MAX_SEMANTIC_NAME_BYTES} bytes with no surrounding whitespace or control characters"
            ),
        ));
    }
}

fn is_compose_service_name(value: &str) -> bool {
    value
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn is_environment_key(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    const VALID_CONFIG: &str = r#"
schema = 1

[project]
id = "2f1c30f5-dce1-4a5c-a751-3a766f6b48ea"
slug = "myproject"
compose = ["compose.yaml"]
default_profile = "preview"

[apps.frontend]
service = "frontend"
port = 3000

[apps.frontend.env]
PUBLIC_NAME = "preview"

[apps.api]
service = "api"
port = 8080
health_path = "/health"
health_status = 200
health_interval_seconds = 2
health_timeout_seconds = 1

[profiles.preview]
isolation = "machine"
apps = ["frontend", "api"]

[profiles.preview.pipeline]
source = "lightrail.source.cwd-git"
builder = "lightrail.builder.buildx"
target = "lightrail.target.hetzner"
runtime = "lightrail.runtime.compose"
exposure = "lightrail.exposure.traefik"
dns = "lightrail.dns.ip"

[profiles.preview.settings.target]
server_type = "cx22"
token = { secret = "hetzner-token" }

[profiles.preview.settings.exposure]
mode = "public"
tls = "acme-http-01"

[profiles.preview.settings.dns]
domain = "sslip.io"
encoding = "hex-ipv4"

[profiles.preview.env]
RUST_LOG = "info"

[profiles.preview.app_env.api]
DATABASE_URL = { secret = "preview-database-url" }
"#;

    fn valid_config() -> LightrailConfig {
        LightrailConfig::parse(VALID_CONFIG).expect("valid configuration")
    }

    #[test]
    fn parses_locked_schema_and_secret_references() {
        let config = valid_config();
        let profile = config.profile("preview").expect("preview profile");
        let database_url = &profile.app_env["api"]["DATABASE_URL"];

        assert_eq!(config.schema, CONFIG_SCHEMA_VERSION);
        assert_eq!(config.project.slug, "myproject");
        assert_eq!(
            config.default_profile().expect("default profile exists").0,
            "preview"
        );
        assert_eq!(
            database_url
                .secret_name()
                .expect("secret reference")
                .as_str(),
            "preview-database-url"
        );
        assert_eq!(
            config.apps["frontend"].env["PUBLIC_NAME"].as_literal(),
            Some("preview")
        );
    }

    #[test]
    fn preserves_opaque_settings_and_converts_them_to_json() {
        let config = valid_config();
        let target = config.profiles["preview"]
            .settings_json(Capability::Target)
            .expect("JSON conversion")
            .expect("target settings");

        assert_eq!(target["server_type"], "cx22");
        assert_eq!(target["token"]["secret"], "hetzner-token");
    }

    #[test]
    fn pretty_toml_round_trips() {
        let config = valid_config();
        let serialized = config.to_toml_pretty().expect("serialize");
        let reparsed = LightrailConfig::parse(&serialized).expect("reparse");

        assert_eq!(reparsed, config);
    }

    #[test]
    fn parses_provider_environment_isolation() {
        let source = VALID_CONFIG.replace("isolation = \"machine\"", "isolation = \"environment\"");
        let config = LightrailConfig::parse(&source).expect("environment isolation");

        assert_eq!(config.profiles["preview"].isolation, Isolation::Environment);
    }

    #[test]
    fn loads_configuration_from_disk() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let path = temp.path().join("lightrail.toml");
        fs::write(&path, VALID_CONFIG).expect("fixture");

        let loaded = LightrailConfig::load(&path).expect("load");

        assert_eq!(loaded.project.slug, "myproject");
    }

    #[test]
    fn rejects_unknown_fields_and_invalid_value_objects_during_parse() {
        let unknown = VALID_CONFIG.replace(
            "default_profile = \"preview\"",
            "default_profile = \"preview\"\nunknown = true",
        );
        assert!(matches!(
            LightrailConfig::parse(&unknown),
            Err(ConfigError::Parse { .. })
        ));

        let invalid_plugin = VALID_CONFIG.replace("lightrail.target.hetzner", "Lightrail Target");
        assert!(matches!(
            LightrailConfig::parse(&invalid_plugin),
            Err(ConfigError::Parse { .. })
        ));

        let invalid_secret = VALID_CONFIG.replace("preview-database-url", "PREVIEW DATABASE URL");
        assert!(matches!(
            LightrailConfig::parse(&invalid_secret),
            Err(ConfigError::Parse { .. })
        ));
    }

    #[test]
    fn reports_all_independent_domain_violations() {
        let mut config = valid_config();
        config.schema = 99;
        config.project.id = ProjectId::from_uuid(Uuid::nil());
        config.project.compose = vec![
            PathBuf::from("../compose.yaml"),
            PathBuf::from("../compose.yaml"),
        ];
        config.project.default_profile = "missing".to_owned();

        let api = config.apps.get_mut("api").expect("api");
        api.port = 0;
        api.health_path = None;
        api.health_status = Some(700);

        let profile = config.profiles.get_mut("preview").expect("preview");
        profile.apps.push("api".to_owned());
        profile.apps.push("missing-app".to_owned());
        profile
            .settings
            .insert("unknown".to_owned(), toml::Value::Boolean(true));
        profile
            .env
            .insert("INVALID-KEY".to_owned(), EnvironmentValue::literal("x"));
        profile
            .app_env
            .insert("missing-app".to_owned(), BTreeMap::new());

        let errors = config.validate().expect_err("invalid config");
        let codes: Vec<_> = errors.issues().iter().map(|issue| issue.code).collect();

        for expected in [
            ValidationCode::UnsupportedSchema,
            ValidationCode::InvalidIdentifier,
            ValidationCode::InvalidPath,
            ValidationCode::Duplicate,
            ValidationCode::MissingReference,
            ValidationCode::InvalidPort,
            ValidationCode::InvalidHealthCheck,
            ValidationCode::UnknownCapability,
            ValidationCode::InvalidEnvironmentKey,
        ] {
            assert!(
                codes.contains(&expected),
                "missing validation code {expected:?}: {errors}"
            );
        }
        assert!(errors.issues().len() >= 10, "{errors}");
    }

    #[test]
    fn rejects_empty_required_collections() {
        let mut config = valid_config();
        config.project.compose.clear();
        config.apps.clear();
        config.profiles.clear();

        let errors = config.validate().expect_err("empty config");

        assert!(
            errors
                .issues()
                .iter()
                .filter(|issue| issue.code == ValidationCode::Empty)
                .count()
                >= 3
        );
    }

    #[test]
    fn identifier_constructors_enforce_protocol_safe_alphabets() {
        assert!(PluginId::new("vendor.target.plugin").is_ok());
        assert!(PluginId::new("Vendor.target.plugin").is_err());
        assert!(PluginId::new(".vendor").is_err());
        assert!(SecretName::new("hetzner-token").is_ok());
        assert!(SecretName::new("hetzner token").is_err());
    }
}
