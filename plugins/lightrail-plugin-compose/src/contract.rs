//! Serde contract shared with the Lightrail orchestrator.
//!
//! `OperationContext.metadata` has this stable shape:
//!
//! ```json
//! {
//!   "capability": "source|builder|runtime|exposure|dns",
//!   "operation": "up|inspect|destroy|logs",
//!   "target": { "...target plugin state..." },
//!   "all": false
//! }
//! ```
//!
//! The `desired` value accepted by validation/planning is [`DesiredState`].
//! Target state can be either flat or under an `ssh` object. The plugin needs
//! `host`, `public_ipv4`, and `architecture`; SSH user/port/path settings are
//! optional.

use std::{
    collections::BTreeMap,
    net::Ipv4Addr,
    path::{Component, Path, PathBuf},
};

use lightrail_plugin_protocol::{Capability, OperationContext, PluginError, SecretValue};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::ComposePluginError;

pub const DESIRED_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ContextMetadata {
    pub capability: Capability,
    #[serde(default)]
    pub operation: Operation,
    #[serde(default)]
    pub target: Value,
    #[serde(default)]
    pub all: bool,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    #[default]
    Up,
    Inspect,
    Destroy,
    Rollback,
    RollbackCleanup,
    Logs,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DesiredState {
    pub schema: u32,
    pub project: ProjectSpec,
    pub environment: EnvironmentSpec,
    /// Ephemeral core-rendered Compose JSON with original-shell interpolation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_compose_path: Option<PathBuf>,
    #[serde(default)]
    pub apps: Vec<AppSpec>,
    #[serde(default)]
    pub target: Value,
    #[serde(default)]
    pub destroy: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProjectSpec {
    pub id: String,
    pub slug: String,
    #[serde(default)]
    pub root: Option<PathBuf>,
    pub compose: Vec<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EnvironmentSpec {
    pub id: String,
    pub profile: String,
    pub branch: String,
    #[serde(default)]
    pub commit: Option<String>,
    #[serde(default)]
    pub dirty: bool,
    pub isolation: Isolation,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Isolation {
    Project,
    Machine,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AppSpec {
    pub name: String,
    pub service: String,
    pub port: u16,
    #[serde(default)]
    pub health_path: Option<String>,
    #[serde(default)]
    pub health_status: Option<u16>,
    #[serde(default)]
    pub health_interval_seconds: Option<u64>,
    #[serde(default)]
    pub health_timeout_seconds: Option<u64>,
    #[serde(default)]
    pub environment: BTreeMap<String, EnvironmentInput>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EnvironmentInput {
    Literal(String),
    Secret { secret: String },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PluginConfig {
    #[serde(default = "default_dns_domain", alias = "domain")]
    pub dns_domain: String,
    #[serde(default)]
    pub acme_email: Option<String>,
    #[serde(default = "default_ingress_image")]
    pub ingress_image: String,
    #[serde(default = "default_ingress_network")]
    pub ingress_network: String,
    #[serde(default = "default_cert_resolver")]
    pub certificate_resolver: String,
    #[serde(default = "default_readiness_timeout")]
    pub readiness_timeout_seconds: u64,
    #[serde(default = "default_stable_window")]
    pub stable_window_seconds: u64,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            dns_domain: default_dns_domain(),
            acme_email: None,
            ingress_image: default_ingress_image(),
            ingress_network: default_ingress_network(),
            certificate_resolver: default_cert_resolver(),
            readiness_timeout_seconds: default_readiness_timeout(),
            stable_window_seconds: default_stable_window(),
        }
    }
}

fn default_dns_domain() -> String {
    "sslip.io".to_owned()
}

fn default_ingress_image() -> String {
    "traefik:v3.7.8".to_owned()
}

fn default_ingress_network() -> String {
    "lightrail-ingress".to_owned()
}

fn default_cert_resolver() -> String {
    "letsencrypt".to_owned()
}

const fn default_readiness_timeout() -> u64 {
    300
}

const fn default_stable_window() -> u64 {
    10
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TargetState {
    pub host: String,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    pub public_ipv4: Ipv4Addr,
    #[serde(default = "default_architecture", alias = "arch")]
    pub architecture: String,
    #[serde(default)]
    pub identity_file: Option<PathBuf>,
    #[serde(default)]
    pub known_hosts_file: Option<PathBuf>,
    #[serde(default)]
    pub docker: DockerAccess,
    #[serde(default = "default_remote_root")]
    pub remote_root: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DockerAccess {
    #[serde(default)]
    pub requires_sudo: bool,
}

const fn default_ssh_port() -> u16 {
    22
}

fn default_architecture() -> String {
    "amd64".to_owned()
}

fn default_remote_root() -> String {
    ".lightrail".to_owned()
}

impl ContextMetadata {
    /// Decode plugin routing metadata attached by core.
    ///
    /// # Errors
    ///
    /// Returns an error when metadata does not match the versioned contract.
    pub fn from_context(context: &OperationContext) -> Result<Self, ComposePluginError> {
        serde_json::from_value(context.metadata.clone())
            .map_err(|source| ComposePluginError::Metadata { source })
    }

    /// Resolve target state from metadata, falling back to desired state.
    ///
    /// # Errors
    ///
    /// Returns an error when required SSH target fields are missing or unsafe.
    pub fn target(
        &self,
        desired: Option<&DesiredState>,
    ) -> Result<TargetState, ComposePluginError> {
        self.optional_target(desired)?.ok_or_else(|| {
            ComposePluginError::InvalidTarget(
                "target state is unavailable; the target capability must apply first".to_owned(),
            )
        })
    }

    /// Resolve target state when infrastructure already exists.
    ///
    /// # Errors
    ///
    /// Returns an error when present target state contains invalid SSH fields.
    pub fn optional_target(
        &self,
        desired: Option<&DesiredState>,
    ) -> Result<Option<TargetState>, ComposePluginError> {
        let raw = if target_has_host(&self.target) {
            &self.target
        } else {
            desired.map_or(&Value::Null, |desired| &desired.target)
        };
        if !target_has_host(raw) {
            return Ok(None);
        }
        TargetState::from_value(raw).map(Some)
    }
}

impl DesiredState {
    /// Decode and structurally validate desired deployment state.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema or invalid deployment input.
    pub fn parse(value: Value) -> Result<Self, ComposePluginError> {
        let desired: Self = serde_json::from_value(value)
            .map_err(|source| ComposePluginError::Desired { source })?;
        desired.validate_shape()?;
        Ok(desired)
    }

    /// Select the explicitly supplied project root.
    ///
    /// # Errors
    ///
    /// Returns an error when neither desired state nor context has a root.
    pub fn project_root<'a>(
        &'a self,
        context: &'a OperationContext,
    ) -> Result<&'a Path, ComposePluginError> {
        self.project
            .root
            .as_deref()
            .or_else(|| context.project_root.as_deref().map(Path::new))
            .ok_or(ComposePluginError::MissingProjectRoot)
    }

    /// Resolve committed relative Compose paths beneath the project root.
    ///
    /// # Errors
    ///
    /// Returns an error when the project root is unavailable.
    pub fn compose_paths(
        &self,
        context: &OperationContext,
    ) -> Result<Vec<PathBuf>, ComposePluginError> {
        let root = self.project_root(context)?;
        Ok(self
            .project
            .compose
            .iter()
            .map(|path| root.join(path))
            .collect())
    }

    fn validate_shape(&self) -> Result<(), ComposePluginError> {
        if self.schema != DESIRED_SCHEMA_VERSION {
            return Err(ComposePluginError::UnsupportedDesiredSchema(self.schema));
        }
        if self.project.id.is_empty()
            || self.project.slug.is_empty()
            || self.environment.id.is_empty()
            || self.environment.profile.is_empty()
            || self.environment.branch.is_empty()
        {
            return Err(ComposePluginError::InvalidDesired(
                "project/environment identity values must not be empty".to_owned(),
            ));
        }
        if self.project.compose.is_empty() {
            return Err(ComposePluginError::InvalidDesired(
                "project.compose must contain at least one file".to_owned(),
            ));
        }
        for path in &self.project.compose {
            if path.as_os_str().is_empty()
                || path.is_absolute()
                || !path
                    .components()
                    .all(|component| matches!(component, Component::Normal(_)))
            {
                return Err(ComposePluginError::InvalidComposePath(path.clone()));
            }
        }
        if self
            .resolved_compose_path
            .as_ref()
            .is_some_and(|path| !path.is_absolute())
        {
            return Err(ComposePluginError::InvalidDesired(
                "resolved_compose_path must be an absolute ephemeral path".to_owned(),
            ));
        }
        for app in &self.apps {
            if app.name.is_empty() || app.service.is_empty() || app.port == 0 {
                return Err(ComposePluginError::InvalidDesired(format!(
                    "app names/services must not be empty and ports must be non-zero (app `{}`)",
                    app.name
                )));
            }
            if app
                .health_path
                .as_ref()
                .is_some_and(|path| !path.starts_with('/'))
            {
                return Err(ComposePluginError::InvalidDesired(format!(
                    "health path for app `{}` must start with `/`",
                    app.name
                )));
            }
        }
        Ok(())
    }

    /// Resolve app environment values without exposing secrets in argv.
    ///
    /// # Errors
    ///
    /// Returns an error when a referenced secret was not supplied by core.
    pub fn resolve_app_environment(
        &self,
        secrets: &BTreeMap<String, SecretValue>,
    ) -> Result<BTreeMap<String, BTreeMap<String, String>>, ComposePluginError> {
        let mut services = BTreeMap::<String, BTreeMap<String, String>>::new();
        for app in &self.apps {
            let environment = services.entry(app.service.clone()).or_default();
            for (name, input) in &app.environment {
                let value = match input {
                    EnvironmentInput::Literal(value) => value.clone(),
                    EnvironmentInput::Secret { secret } => secrets
                        .get(secret)
                        .ok_or_else(|| ComposePluginError::MissingSecret(secret.clone()))?
                        .expose_secret()
                        .to_owned(),
                };
                environment.insert(name.clone(), value);
            }
        }
        Ok(services)
    }
}

impl PluginConfig {
    /// Decode capability settings and apply safe defaults.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported DNS or unsafe resource identifiers.
    pub fn from_context(context: &OperationContext) -> Result<Self, ComposePluginError> {
        if context.config.is_null()
            || context
                .config
                .as_object()
                .is_some_and(serde_json::Map::is_empty)
        {
            return Ok(Self::default());
        }
        let config: Self = serde_json::from_value(context.config.clone())
            .map_err(|source| ComposePluginError::Configuration { source })?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ComposePluginError> {
        if !matches!(self.dns_domain.as_str(), "sslip.io" | "nip.io") {
            return Err(ComposePluginError::InvalidDesired(
                "dns_domain must be exactly `sslip.io` or `nip.io`".to_owned(),
            ));
        }
        for (name, value) in [
            ("ingress_network", self.ingress_network.as_str()),
            ("certificate_resolver", self.certificate_resolver.as_str()),
        ] {
            if !is_safe_identifier(value) {
                return Err(ComposePluginError::InvalidDesired(format!(
                    "{name} contains unsafe characters"
                )));
            }
        }
        if self.readiness_timeout_seconds == 0 {
            return Err(ComposePluginError::InvalidDesired(
                "readiness_timeout_seconds must be greater than zero".to_owned(),
            ));
        }
        Ok(())
    }
}

impl TargetState {
    fn from_value(value: &Value) -> Result<Self, ComposePluginError> {
        let value = value.get("ssh").unwrap_or(value).clone();
        let target: Self = serde_json::from_value(value)
            .map_err(|source| ComposePluginError::Target { source })?;
        target.validate()?;
        Ok(target)
    }

    fn validate(&self) -> Result<(), ComposePluginError> {
        if self.host.is_empty()
            || self.host.starts_with('-')
            || self
                .host
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err(ComposePluginError::InvalidTarget(
                "SSH host is empty or contains unsafe characters".to_owned(),
            ));
        }
        let localhost_name = self.host.eq_ignore_ascii_case("localhost")
            || self.host.to_ascii_lowercase().ends_with(".localhost");
        let loopback_address = self
            .host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback());
        if localhost_name || loopback_address {
            return Err(ComposePluginError::InvalidTarget(
                "localhost and loopback SSH targets are not allowed".to_owned(),
            ));
        }
        if let Some(user) = &self.user {
            if user.is_empty() || !is_safe_identifier(user) {
                return Err(ComposePluginError::InvalidTarget(
                    "SSH user contains unsafe characters".to_owned(),
                ));
            }
        }
        if self.port == 0 {
            return Err(ComposePluginError::InvalidTarget(
                "SSH port must be non-zero".to_owned(),
            ));
        }
        if !is_public_ipv4(self.public_ipv4) {
            return Err(ComposePluginError::InvalidTarget(
                "target public_ipv4 must not be localhost or a non-public address".to_owned(),
            ));
        }
        if !matches!(
            self.architecture.as_str(),
            "amd64" | "arm64" | "x86_64" | "aarch64"
        ) {
            return Err(ComposePluginError::InvalidTarget(format!(
                "unsupported target architecture `{}`",
                self.architecture
            )));
        }
        if self.remote_root.is_empty()
            || self.remote_root.contains('\0')
            || self.remote_root.contains('\n')
        {
            return Err(ComposePluginError::InvalidTarget(
                "remote_root is empty or contains control characters".to_owned(),
            ));
        }
        validate_local_ssh_path("identity_file", self.identity_file.as_deref())?;
        validate_local_ssh_path("known_hosts_file", self.known_hosts_file.as_deref())?;
        Ok(())
    }

    #[must_use]
    pub fn platform(&self) -> &'static str {
        match self.architecture.as_str() {
            "arm64" | "aarch64" => "linux/arm64",
            _ => "linux/amd64",
        }
    }

    #[must_use]
    pub fn destination(&self) -> String {
        self.user
            .as_ref()
            .map_or_else(|| self.host.clone(), |user| format!("{user}@{}", self.host))
    }

    #[must_use]
    pub fn docker_arguments<I, S>(&self, arguments: I) -> Vec<String>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut command = if self.docker.requires_sudo {
            vec!["sudo".to_owned(), "-n".to_owned(), "docker".to_owned()]
        } else {
            vec!["docker".to_owned()]
        };
        command.extend(arguments.into_iter().map(Into::into));
        command
    }

    #[must_use]
    pub fn docker_shell(&self) -> &'static str {
        if self.docker.requires_sudo {
            "sudo -n docker"
        } else {
            "docker"
        }
    }
}

fn validate_local_ssh_path(name: &str, path: Option<&Path>) -> Result<(), ComposePluginError> {
    let Some(path) = path else {
        return Ok(());
    };
    let value = path.to_string_lossy();
    if !path.is_absolute() || value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ComposePluginError::InvalidTarget(format!(
            "{name} must be an absolute local path without unsafe option characters"
        )));
    }
    Ok(())
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, _, _] = address.octets();
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_multicast()
        || address.is_broadcast()
        || address.is_documentation()
        || a == 0
        || a >= 240
        || a == 100 && (64..=127).contains(&b)
        || a == 192 && b == 0
        || a == 198 && matches!(b, 18 | 19))
}

fn is_safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn target_has_host(value: &Value) -> bool {
    value
        .get("host")
        .or_else(|| value.get("ssh").and_then(|ssh| ssh.get("host")))
        .and_then(Value::as_str)
        .is_some_and(|host| !host.is_empty())
}

impl From<ComposePluginError> for PluginError {
    fn from(error: ComposePluginError) -> Self {
        error.into_plugin_error()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn context(metadata: Value) -> OperationContext {
        OperationContext {
            operation_id: "op".to_owned(),
            environment_id: "lr-env".to_owned(),
            profile: "preview".to_owned(),
            metadata,
            ..OperationContext::default()
        }
    }

    #[test]
    fn target_is_optional_before_machine_provisioning() {
        let metadata = ContextMetadata::from_context(&context(json!({
            "capability": "runtime",
            "operation": "up",
            "target": {}
        })))
        .expect("metadata");

        assert!(metadata.optional_target(None).expect("optional").is_none());
        assert!(metadata.target(None).is_err());
    }

    #[test]
    fn accepts_flat_target_plugin_state() {
        let metadata = ContextMetadata::from_context(&context(json!({
            "capability": "runtime",
            "target": {
                "host": "8.8.8.8",
                "user": "deploy",
                "public_ipv4": "8.8.8.8",
                "architecture": "amd64",
                "remote_root": "/var/lib/lightrail",
                "identity_file": "/home/me/.ssh/id_ed25519",
                "known_hosts_file": "/home/me/.ssh/known_hosts",
                "docker": {"requires_sudo": true}
            }
        })))
        .expect("metadata");
        let target = metadata
            .optional_target(None)
            .expect("valid target")
            .expect("present");

        assert_eq!(target.host, "8.8.8.8");
        assert_eq!(target.platform(), "linux/amd64");
        assert!(target.docker.requires_sudo);
        assert_eq!(
            target.docker_arguments(["compose", "version"]),
            ["sudo", "-n", "docker", "compose", "version"]
        );
    }

    #[test]
    fn rejects_relative_or_control_character_ssh_paths() {
        for target in [
            json!({
                "host": "8.8.8.8",
                "public_ipv4": "8.8.8.8",
                "identity_file": ".ssh/id_ed25519"
            }),
            json!({
                "host": "8.8.8.8",
                "public_ipv4": "8.8.8.8",
                "known_hosts_file": "/tmp/known_hosts\nProxyCommand=bad"
            }),
        ] {
            assert!(TargetState::from_value(&target).is_err());
        }
    }

    #[test]
    fn accepts_quotable_known_hosts_paths() {
        let target = json!({
            "host": "8.8.8.8",
            "public_ipv4": "8.8.8.8",
            "known_hosts_file": "/tmp/My Project=100%/known_hosts"
        });
        assert!(TargetState::from_value(&target).is_ok());
    }

    #[test]
    fn rejects_localhost_and_non_public_addresses_from_external_targets() {
        for (host, public_ipv4) in [
            ("localhost", "8.8.8.8"),
            ("8.8.8.8", "127.0.0.1"),
            ("8.8.8.8", "10.0.0.1"),
            ("8.8.8.8", "100.64.0.1"),
            ("8.8.8.8", "192.0.2.1"),
            ("8.8.8.8", "198.18.0.1"),
            ("8.8.8.8", "240.0.0.1"),
        ] {
            let target = json!({
                "host": host,
                "public_ipv4": public_ipv4
            });
            assert!(
                TargetState::from_value(&target).is_err(),
                "{host}/{public_ipv4} must not be accepted as a public target"
            );
        }
        for target in [
            json!({
                "host": "8.8.8.8",
                "public_ipv4": "8.8.8.8"
            }),
            json!({
                "host": "1.1.1.1",
                "public_ipv4": "1.1.1.1"
            }),
        ] {
            assert!(TargetState::from_value(&target).is_ok());
        }
    }
}
