use std::{
    collections::BTreeSet,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use lightrail_plugin_protocol::{ErrorKind, OperationContext, PluginError};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const DEFAULT_COMMAND_TIMEOUT_SECONDS: u64 = 300;
const DEFAULT_READINESS_TIMEOUT_SECONDS: u64 = 300;
const DEFAULT_TTL_HOURS: u64 = 72;

/// Validated settings merged from every capability slot served by this plugin.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    /// Existing kubeconfig context. It is always passed explicitly to kubectl.
    pub context: String,
    /// Optional absolute kubeconfig path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kubeconfig: Option<PathBuf>,
    /// OCI registry host, without a URL scheme.
    pub registry: String,
    /// Repository prefix beneath the registry.
    pub repository: String,
    /// Existing Kubernetes `IngressClass`.
    pub ingress_class: String,
    /// Namespace of the exact `LoadBalancer` Service owned by that ingress controller.
    pub ingress_service_namespace: String,
    /// Name of the exact `LoadBalancer` Service owned by that ingress controller.
    pub ingress_service_name: String,
    /// Existing Traefik HTTP entrypoint used by redirect-only Ingresses.
    pub traefik_http_entrypoint: String,
    /// Existing Traefik HTTPS entrypoint used by public TLS Ingresses.
    pub traefik_https_entrypoint: String,
    /// Prefix for environment-owned namespaces.
    pub namespace_prefix: String,
    /// Existing namespace that stores authoritative Lease locks.
    pub control_namespace: String,
    /// IP-derived DNS routing domain.
    pub dns_domain: String,
    /// Existing cert-manager `ClusterIssuer` used for every public app.
    pub cluster_issuer: String,
    /// Optional image-pull Secret name made available by cluster setup/policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_pull_secret: Option<String>,
    /// Explicit image platforms. Empty means discover schedulable node arches.
    pub platforms: Vec<String>,
    /// Replica count for ordinary long-running workloads.
    pub replicas: u32,
    /// Agentless expiry metadata refreshed by `up`.
    pub ttl_hours: u64,
    /// Bound for one kubectl/docker subprocess.
    pub command_timeout_seconds: u64,
    /// Bound for rollout, Job, and endpoint readiness.
    pub readiness_timeout_seconds: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            context: String::new(),
            kubeconfig: None,
            registry: String::new(),
            repository: String::new(),
            ingress_class: String::new(),
            ingress_service_namespace: String::new(),
            ingress_service_name: String::new(),
            traefik_http_entrypoint: "web".to_owned(),
            traefik_https_entrypoint: "websecure".to_owned(),
            namespace_prefix: "lr".to_owned(),
            control_namespace: "lightrail-system".to_owned(),
            dns_domain: "sslip.io".to_owned(),
            cluster_issuer: String::new(),
            image_pull_secret: None,
            platforms: Vec::new(),
            replicas: 1,
            ttl_hours: DEFAULT_TTL_HOURS,
            command_timeout_seconds: DEFAULT_COMMAND_TIMEOUT_SECONDS,
            readiness_timeout_seconds: DEFAULT_READINESS_TIMEOUT_SECONDS,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConfigIssue {
    pub code: &'static str,
    pub message: String,
    pub path: Option<&'static str>,
}

impl ConfigIssue {
    fn at(code: &'static str, message: impl Into<String>, path: &'static str) -> Self {
        Self {
            code,
            message: message.into(),
            path: Some(path),
        }
    }

    pub(crate) fn plugin_error(&self) -> PluginError {
        PluginError::permanent(ErrorKind::Validation, self.code, self.message.clone())
    }
}

impl Settings {
    pub(crate) fn parse(context: &OperationContext) -> Result<Self, ConfigIssue> {
        let settings: Self =
            serde_json::from_value(context.config.clone()).map_err(|error| ConfigIssue {
                code: "invalid_config",
                message: format!("invalid Kubernetes configuration: {error}"),
                path: None,
            })?;
        settings.validate()?;
        Ok(settings)
    }

    fn validate(&self) -> Result<(), ConfigIssue> {
        validate_argument("context", &self.context, "/context")?;
        if let Some(path) = self.kubeconfig.as_deref() {
            validate_absolute_path(path)?;
        }
        validate_registry(&self.registry)?;
        validate_repository(&self.repository)?;
        validate_dns_subdomain("ingress_class", &self.ingress_class, "/ingress_class")?;
        validate_dns_subdomain(
            "ingress_service_namespace",
            &self.ingress_service_namespace,
            "/ingress_service_namespace",
        )?;
        validate_dns_label(
            "ingress_service_name",
            &self.ingress_service_name,
            "/ingress_service_name",
        )?;
        validate_dns_label(
            "traefik_http_entrypoint",
            &self.traefik_http_entrypoint,
            "/traefik_http_entrypoint",
        )?;
        validate_dns_label(
            "traefik_https_entrypoint",
            &self.traefik_https_entrypoint,
            "/traefik_https_entrypoint",
        )?;
        if self.traefik_http_entrypoint == self.traefik_https_entrypoint {
            return Err(ConfigIssue::at(
                "traefik_entrypoints_must_differ",
                "Traefik HTTP and HTTPS entrypoints must be distinct",
                "/traefik_https_entrypoint",
            ));
        }
        validate_dns_label(
            "namespace_prefix",
            &self.namespace_prefix,
            "/namespace_prefix",
        )?;
        if self.namespace_prefix.len() > 32 {
            return Err(ConfigIssue::at(
                "namespace_prefix_too_long",
                "namespace_prefix must be at most 32 characters",
                "/namespace_prefix",
            ));
        }
        validate_dns_subdomain(
            "control_namespace",
            &self.control_namespace,
            "/control_namespace",
        )?;
        if !matches!(self.dns_domain.as_str(), "sslip.io" | "nip.io") {
            return Err(ConfigIssue::at(
                "unsupported_dns_domain",
                "dns_domain must be exactly `sslip.io` or `nip.io`",
                "/dns_domain",
            ));
        }
        validate_dns_subdomain("cluster_issuer", &self.cluster_issuer, "/cluster_issuer")?;
        if let Some(secret) = self.image_pull_secret.as_deref() {
            validate_dns_subdomain("image_pull_secret", secret, "/image_pull_secret")?;
        }
        validate_platforms(&self.platforms)?;
        if !(1..=100).contains(&self.replicas) {
            return Err(ConfigIssue::at(
                "invalid_replicas",
                "replicas must be between 1 and 100",
                "/replicas",
            ));
        }
        if !(1..=24 * 365).contains(&self.ttl_hours) {
            return Err(ConfigIssue::at(
                "invalid_ttl",
                "ttl_hours must be between 1 and 8760",
                "/ttl_hours",
            ));
        }
        validate_timeout(
            self.command_timeout_seconds,
            "command_timeout_seconds",
            "/command_timeout_seconds",
        )?;
        validate_timeout(
            self.readiness_timeout_seconds,
            "readiness_timeout_seconds",
            "/readiness_timeout_seconds",
        )?;
        Ok(())
    }

    pub(crate) fn command_timeout(&self) -> Duration {
        Duration::from_secs(self.command_timeout_seconds)
    }

    pub(crate) fn readiness_timeout(&self) -> Duration {
        Duration::from_secs(self.readiness_timeout_seconds)
    }

    pub(crate) fn image_prefix(&self) -> String {
        format!(
            "{}/{}/",
            self.registry.trim_end_matches('/'),
            self.repository.trim_matches('/')
        )
    }

    pub(crate) fn kubectl_prefix(&self) -> Vec<String> {
        let mut arguments = Vec::with_capacity(4);
        if let Some(path) = &self.kubeconfig {
            arguments.push("--kubeconfig".to_owned());
            arguments.push(path.to_string_lossy().into_owned());
        }
        arguments.push("--context".to_owned());
        arguments.push(self.context.clone());
        arguments
    }

    pub(crate) fn normalized_value(&self) -> Value {
        json!({
            "context": self.context,
            "kubeconfig": self.kubeconfig,
            "registry": self.registry,
            "repository": self.repository,
            "ingress_class": self.ingress_class,
            "ingress_service_namespace": self.ingress_service_namespace,
            "ingress_service_name": self.ingress_service_name,
            "traefik_http_entrypoint": self.traefik_http_entrypoint,
            "traefik_https_entrypoint": self.traefik_https_entrypoint,
            "namespace_prefix": self.namespace_prefix,
            "control_namespace": self.control_namespace,
            "dns_domain": self.dns_domain,
            "cluster_issuer": self.cluster_issuer,
            "image_pull_secret": self.image_pull_secret,
            "platforms": self.platforms,
            "replicas": self.replicas,
            "ttl_hours": self.ttl_hours,
            "command_timeout_seconds": self.command_timeout_seconds,
            "readiness_timeout_seconds": self.readiness_timeout_seconds,
        })
    }
}

pub(crate) fn config_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "context",
            "registry",
            "repository",
            "ingress_class",
            "ingress_service_namespace",
            "ingress_service_name",
            "cluster_issuer"
        ],
        "properties": {
            "context": {"type": "string", "minLength": 1},
            "kubeconfig": {"type": "string", "minLength": 1},
            "registry": {"type": "string", "minLength": 1},
            "repository": {"type": "string", "minLength": 1},
            "ingress_class": {"type": "string", "minLength": 1},
            "ingress_service_namespace": {
                "type": "string",
                "minLength": 1,
                "description": "Namespace of the exact LoadBalancer Service for the selected IngressClass"
            },
            "ingress_service_name": {
                "type": "string",
                "minLength": 1,
                "description": "Name of the exact LoadBalancer Service for the selected IngressClass"
            },
            "traefik_http_entrypoint": {
                "type": "string",
                "default": "web",
                "description": "Existing Traefik cleartext HTTP entrypoint"
            },
            "traefik_https_entrypoint": {
                "type": "string",
                "default": "websecure",
                "description": "Existing Traefik HTTPS entrypoint"
            },
            "namespace_prefix": {"type": "string", "default": "lr"},
            "control_namespace": {"type": "string", "default": "lightrail-system"},
            "dns_domain": {"enum": ["sslip.io", "nip.io"], "default": "sslip.io"},
            "cluster_issuer": {
                "type": "string",
                "minLength": 1,
                "description": "Existing cert-manager ClusterIssuer used for ACME HTTP-01 certificates"
            },
            "image_pull_secret": {"type": ["string", "null"]},
            "platforms": {
                "type": "array",
                "items": {"enum": ["linux/amd64", "linux/arm64"]},
                "uniqueItems": true,
                "default": []
            },
            "replicas": {"type": "integer", "minimum": 1, "maximum": 100, "default": 1},
            "ttl_hours": {"type": "integer", "minimum": 1, "maximum": 8760, "default": 72},
            "command_timeout_seconds": {
                "type": "integer",
                "minimum": 1,
                "maximum": 3600,
                "default": 300
            },
            "readiness_timeout_seconds": {
                "type": "integer",
                "minimum": 1,
                "maximum": 3600,
                "default": 300
            }
        }
    })
}

fn validate_argument(name: &str, value: &str, path: &'static str) -> Result<(), ConfigIssue> {
    if value.trim().is_empty()
        || value != value.trim()
        || value.starts_with('-')
        || value.len() > 253
        || value.chars().any(char::is_control)
    {
        return Err(ConfigIssue::at(
            "invalid_argument",
            format!("{name} is empty or contains unsafe characters"),
            path,
        ));
    }
    Ok(())
}

fn validate_absolute_path(path: &Path) -> Result<(), ConfigIssue> {
    if !path.is_absolute()
        || path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        || path
            .to_string_lossy()
            .chars()
            .any(|character| character == '\0' || matches!(character, '\r' | '\n'))
    {
        return Err(ConfigIssue::at(
            "invalid_kubeconfig",
            "kubeconfig must be an absolute normalized path without control characters",
            "/kubeconfig",
        ));
    }
    Ok(())
}

fn validate_registry(value: &str) -> Result<(), ConfigIssue> {
    validate_argument("registry", value, "/registry")?;
    let colon_count = value.bytes().filter(|byte| *byte == b':').count();
    let (host, port_valid) = value
        .rsplit_once(':')
        .map_or((value, true), |(host, port)| {
            (
                host,
                colon_count == 1
                    && !port.is_empty()
                    && port.parse::<u16>().is_ok_and(|port| port > 0),
            )
        });
    let parsed_ipv4 = host.parse::<std::net::Ipv4Addr>().ok();
    let valid_host = parsed_ipv4.map_or_else(
        || {
            !host
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.')
                && host.len() <= 253
                && host.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && label
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                        && label
                            .as_bytes()
                            .first()
                            .is_some_and(u8::is_ascii_alphanumeric)
                        && label
                            .as_bytes()
                            .last()
                            .is_some_and(u8::is_ascii_alphanumeric)
                })
        },
        |address| !address.is_loopback() && !address.is_unspecified(),
    );
    if value.contains('/')
        || value.contains("://")
        || host.eq_ignore_ascii_case("localhost")
        || host.eq_ignore_ascii_case("localhost.localdomain")
        || !port_valid
        || matches!(value, "::1" | "[::1]")
        || !valid_host
    {
        return Err(ConfigIssue::at(
            "invalid_registry",
            "registry must be a non-loopback OCI registry host without a URL scheme or path",
            "/registry",
        ));
    }
    Ok(())
}

fn validate_repository(value: &str) -> Result<(), ConfigIssue> {
    validate_argument("repository", value, "/repository")?;
    if value.starts_with('/')
        || value.ends_with('/')
        || value.split('/').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || !part.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
                })
        })
    {
        return Err(ConfigIssue::at(
            "invalid_repository",
            "repository must contain lowercase OCI path segments",
            "/repository",
        ));
    }
    Ok(())
}

fn validate_platforms(platforms: &[String]) -> Result<(), ConfigIssue> {
    let mut unique = BTreeSet::new();
    for platform in platforms {
        if !matches!(platform.as_str(), "linux/amd64" | "linux/arm64") || !unique.insert(platform) {
            return Err(ConfigIssue::at(
                "invalid_platforms",
                "platforms may contain unique `linux/amd64` and `linux/arm64` entries only",
                "/platforms",
            ));
        }
    }
    Ok(())
}

fn validate_timeout(value: u64, name: &str, path: &'static str) -> Result<(), ConfigIssue> {
    if !(1..=3600).contains(&value) {
        return Err(ConfigIssue::at(
            "invalid_timeout",
            format!("{name} must be between 1 and 3600 seconds"),
            path,
        ));
    }
    Ok(())
}

pub(crate) fn validate_dns_label(
    name: &str,
    value: &str,
    path: &'static str,
) -> Result<(), ConfigIssue> {
    if value.is_empty()
        || value.len() > 63
        || value.starts_with('-')
        || value.ends_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(ConfigIssue::at(
            "invalid_dns_label",
            format!("{name} must be a lowercase Kubernetes DNS label"),
            path,
        ));
    }
    Ok(())
}

fn validate_dns_subdomain(name: &str, value: &str, path: &'static str) -> Result<(), ConfigIssue> {
    if value.is_empty()
        || value.len() > 253
        || value
            .split('.')
            .any(|label| validate_dns_label(name, label, path).is_err())
    {
        return Err(ConfigIssue::at(
            "invalid_dns_subdomain",
            format!("{name} must be a lowercase Kubernetes DNS subdomain"),
            path,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lightrail_plugin_protocol::OperationContext;

    fn context(value: Value) -> OperationContext {
        OperationContext {
            config: value,
            ..OperationContext::default()
        }
    }

    #[test]
    fn parses_product_defaults() {
        let settings = Settings::parse(&context(json!({
            "context": "rackspace-spot",
            "registry": "ghcr.io",
            "repository": "gelleson/lightrail",
            "ingress_class": "nginx",
            "ingress_service_namespace": "ingress-nginx",
            "ingress_service_name": "ingress-nginx-controller",
            "cluster_issuer": "letsencrypt"
        })))
        .expect("valid settings");
        assert_eq!(settings.ttl_hours, 72);
        assert_eq!(settings.control_namespace, "lightrail-system");
        assert_eq!(settings.cluster_issuer, "letsencrypt");
        assert_eq!(settings.ingress_service_namespace, "ingress-nginx");
        assert_eq!(settings.ingress_service_name, "ingress-nginx-controller");
        assert_eq!(settings.traefik_http_entrypoint, "web");
        assert_eq!(settings.traefik_https_entrypoint, "websecure");
    }

    #[test]
    fn requires_a_cluster_issuer_for_public_https() {
        let issue = Settings::parse(&context(json!({
            "context": "rackspace-spot",
            "registry": "ghcr.io",
            "repository": "gelleson/lightrail",
            "ingress_class": "nginx",
            "ingress_service_namespace": "ingress-nginx",
            "ingress_service_name": "ingress-nginx-controller"
        })))
        .expect_err("missing ClusterIssuer must not render an unprovisioned TLS Secret");
        assert_eq!(issue.path, Some("/cluster_issuer"));
    }

    #[test]
    fn rejects_implicit_or_loopback_targets() {
        let missing = Settings::parse(&context(json!({
            "registry": "ghcr.io",
            "repository": "team/lightrail",
            "ingress_class": "nginx"
        })))
        .expect_err("context is explicit");
        assert_eq!(missing.path, Some("/context"));

        let local_registry = Settings::parse(&context(json!({
            "context": "spot",
            "registry": "localhost",
            "repository": "team/lightrail",
            "ingress_class": "nginx"
        })))
        .expect_err("loopback registry is not cluster pullable");
        assert_eq!(local_registry.code, "invalid_registry");

        let local_registry_with_port = Settings::parse(&context(json!({
            "context": "spot",
            "registry": "localhost:5000",
            "repository": "team/lightrail",
            "ingress_class": "nginx",
            "cluster_issuer": "letsencrypt"
        })))
        .expect_err("loopback registry with a port is not cluster pullable");
        assert_eq!(local_registry_with_port.code, "invalid_registry");
    }

    #[test]
    fn registry_requires_a_nonempty_ipv4_or_dns_host_and_valid_optional_port() {
        assert!(validate_registry("registry.example:5000").is_ok());
        assert!(validate_registry("198.51.100.20:5000").is_ok());
        for registry in [
            "",
            ".",
            ":5000",
            "registry..example",
            "-registry.example",
            "registry-.example",
            "registry_name.example",
            "999.999.999.999",
            "127.0.0.1:5000",
            "0.0.0.0",
        ] {
            assert!(
                validate_registry(registry).is_err(),
                "{registry:?} must not be accepted as a registry host"
            );
        }
    }

    #[test]
    fn ingress_service_binding_uses_namespace_subdomain_and_service_label_shapes() {
        let mut settings = Settings {
            context: "spot".to_owned(),
            registry: "ghcr.io".to_owned(),
            repository: "team/lightrail".to_owned(),
            ingress_class: "nginx".to_owned(),
            ingress_service_namespace: "networking.ingress".to_owned(),
            ingress_service_name: "ingress-nginx-controller".to_owned(),
            cluster_issuer: "letsencrypt".to_owned(),
            ..Settings::default()
        };
        assert!(settings.validate().is_ok());
        settings.ingress_service_name = "networking.ingress".to_owned();
        assert_eq!(
            settings
                .validate()
                .expect_err("Service name is one DNS label")
                .path,
            Some("/ingress_service_name")
        );
    }

    #[test]
    fn traefik_entrypoints_are_explicit_and_distinct() {
        let issue = Settings::parse(&context(json!({
            "context": "spot",
            "registry": "ghcr.io",
            "repository": "team/lightrail",
            "ingress_class": "traefik",
            "ingress_service_namespace": "traefik",
            "ingress_service_name": "traefik",
            "cluster_issuer": "letsencrypt",
            "traefik_http_entrypoint": "edge",
            "traefik_https_entrypoint": "edge"
        })))
        .expect_err("one entrypoint cannot enforce HTTP redirect and HTTPS routing");
        assert_eq!(issue.code, "traefik_entrypoints_must_differ");
    }

    #[test]
    fn kubeconfig_must_be_absolute() {
        let issue = Settings::parse(&context(json!({
            "context": "spot",
            "kubeconfig": ".kube/config",
            "registry": "ghcr.io",
            "repository": "team/lightrail",
            "ingress_class": "nginx"
        })))
        .expect_err("relative kubeconfig");
        assert_eq!(issue.path, Some("/kubeconfig"));
    }

    #[test]
    fn rejects_unknown_settings_and_schema_is_closed() {
        let issue = Settings::parse(&context(json!({
            "context": "spot",
            "registry": "ghcr.io",
            "repository": "team/lightrail",
            "ingress_class": "nginx",
            "ingress_service_namespace": "ingress-nginx",
            "ingress_service_name": "ingress-nginx-controller",
            "cluster_issuer": "letsencrypt",
            "ingres_class": "typo"
        })))
        .expect_err("unknown settings must fail closed");
        assert_eq!(issue.code, "invalid_config");
        assert_eq!(config_schema()["additionalProperties"], false);
    }
}
