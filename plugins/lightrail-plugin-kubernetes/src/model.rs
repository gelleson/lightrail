use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use lightrail_core::{DnsLabel, Hostname, IpDnsDomain};
use lightrail_plugin_protocol::{
    Capability, Endpoint, ErrorKind, OperationContext, PluginError, PluginResult, SecretValue,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::config::Settings;

pub(crate) const MANAGED_LABEL: &str = "app.kubernetes.io/managed-by";
pub(crate) const PROJECT_LABEL: &str = "lightrail.dev/project-id";
pub(crate) const ENVIRONMENT_LABEL: &str = "lightrail.dev/environment-id";
pub(crate) const PROFILE_LABEL: &str = "lightrail.dev/profile";
pub(crate) const SERVICE_LABEL: &str = "lightrail.dev/service";
pub(crate) const REVISION_LABEL: &str = "lightrail.dev/revision";
pub(crate) const SPEC_HASH_ANNOTATION: &str = "lightrail.dev/spec-hash";
pub(crate) const BRANCH_ANNOTATION: &str = "lightrail.dev/branch";
pub(crate) const APP_ANNOTATION: &str = "lightrail.dev/app-name";
pub(crate) const EXPIRES_AT_ANNOTATION: &str = "lightrail.dev/expires-at-unix";
pub(crate) const CONTROL_NAMESPACE_ANNOTATION: &str = "lightrail.dev/control-namespace";
pub(crate) const RUNTIME_CONFIG_REVISION_ANNOTATION: &str = "lightrail.dev/runtime-config-revision";

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Operation {
    #[default]
    Up,
    Inspect,
    Destroy,
    Rollback,
    RollbackCleanup,
    Logs,
    Prune,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct Selection {
    #[serde(default)]
    pub schema: u32,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub environment_ids: Vec<String>,
}

impl Selection {
    pub(crate) fn validate_prune(&self) -> PluginResult<()> {
        if self.schema != 1
            || self.reason != "expired"
            || self.environment_ids.is_empty()
            || self
                .environment_ids
                .iter()
                .any(|environment| environment.trim().is_empty())
        {
            return Err(PluginError::permanent(
                ErrorKind::Validation,
                "invalid_prune_selection",
                "selected prune requires selection schema 1, reason `expired`, and non-empty exact environment_ids",
            ));
        }
        let unique = self.environment_ids.iter().collect::<BTreeSet<_>>();
        if unique.len() != self.environment_ids.len() {
            return Err(PluginError::permanent(
                ErrorKind::Validation,
                "duplicate_prune_selection",
                "selected prune environment_ids must be unique",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ContextMetadata {
    pub capability: Capability,
    #[serde(default)]
    pub operation: Operation,
    #[serde(default)]
    pub all: bool,
    #[serde(default)]
    pub project_id: String,
    #[serde(default)]
    pub project_slug: String,
    #[serde(default)]
    pub target: Value,
    #[serde(default)]
    pub selection: Selection,
}

impl ContextMetadata {
    pub(crate) fn parse(context: &OperationContext) -> PluginResult<Self> {
        let metadata: Self = serde_json::from_value(context.metadata.clone()).map_err(|error| {
            PluginError::permanent(
                ErrorKind::Validation,
                "invalid_operation_metadata",
                format!("invalid Kubernetes operation metadata: {error}"),
            )
        })?;
        if metadata.project_id.is_empty() {
            return Err(PluginError::permanent(
                ErrorKind::Validation,
                "project_id_required",
                "Kubernetes operations require immutable project_id metadata",
            ));
        }
        Ok(metadata)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct DesiredState {
    pub schema: u32,
    pub project: ProjectSpec,
    pub environment: EnvironmentSpec,
    #[serde(default)]
    pub resolved_compose_path: Option<PathBuf>,
    #[serde(default)]
    pub apps: Vec<AppSpec>,
    #[serde(default)]
    pub target: Value,
    #[serde(default)]
    pub destroy: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ProjectSpec {
    pub id: String,
    pub slug: String,
    #[serde(default)]
    pub root: Option<PathBuf>,
    #[serde(default)]
    pub compose: Vec<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct EnvironmentSpec {
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
pub(crate) enum Isolation {
    Environment,
    Project,
    Machine,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct AppSpec {
    pub name: String,
    pub service: String,
    pub port: u16,
    #[serde(default)]
    pub health_path: Option<String>,
    #[serde(default)]
    pub health_status: Option<u16>,
    #[serde(default)]
    pub environment: BTreeMap<String, EnvironmentInput>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub(crate) enum EnvironmentInput {
    Literal(String),
    Secret { secret: String },
}

impl DesiredState {
    #[allow(clippy::too_many_lines)]
    pub(crate) fn parse(value: Value, context: &OperationContext) -> PluginResult<Self> {
        let desired: Self = serde_json::from_value(value).map_err(|error| {
            PluginError::permanent(
                ErrorKind::Validation,
                "invalid_desired_state",
                format!("invalid Kubernetes desired state: {error}"),
            )
        })?;
        if desired.schema != 1 {
            return Err(PluginError::permanent(
                ErrorKind::Unsupported,
                "unsupported_desired_schema",
                format!(
                    "Kubernetes plugin supports desired schema 1, received {}",
                    desired.schema
                ),
            ));
        }
        if desired.project.id.is_empty()
            || desired.project.slug.is_empty()
            || desired.environment.id.is_empty()
            || desired.environment.profile.is_empty()
            || desired.environment.branch.is_empty()
        {
            return Err(PluginError::permanent(
                ErrorKind::Validation,
                "identity_required",
                "project and environment identity values must not be empty",
            ));
        }
        if desired.environment.id != context.environment_id {
            return Err(PluginError::permanent(
                ErrorKind::Conflict,
                "environment_identity_mismatch",
                "desired environment ID does not match the operation context",
            ));
        }
        if desired.environment.isolation != Isolation::Environment {
            return Err(PluginError::permanent(
                ErrorKind::Validation,
                "unsupported_isolation",
                "Kubernetes profiles require `environment` isolation",
            ));
        }
        let mut app_names = BTreeSet::new();
        let mut service_environment = BTreeMap::<(&str, &str), &EnvironmentInput>::new();
        for app in &desired.apps {
            if app.name.is_empty() || app.service.is_empty() || app.port == 0 {
                return Err(PluginError::permanent(
                    ErrorKind::Validation,
                    "invalid_app",
                    "app names and services must not be empty and app ports must be non-zero",
                ));
            }
            if !app_names.insert(app.name.as_str()) {
                return Err(PluginError::permanent(
                    ErrorKind::Validation,
                    "duplicate_app_name",
                    format!("app name `{}` is declared more than once", app.name),
                ));
            }
            if app.health_path.as_ref().is_some_and(|path| {
                !path.starts_with('/')
                    || path.chars().any(char::is_control)
                    || path.chars().any(char::is_whitespace)
            }) {
                return Err(PluginError::permanent(
                    ErrorKind::Validation,
                    "invalid_health_path",
                    format!("health path for app `{}` must start with `/`", app.name),
                ));
            }
            if app
                .health_status
                .is_some_and(|status| !(100..=599).contains(&status))
                || app.health_status.is_some() && app.health_path.is_none()
            {
                return Err(PluginError::permanent(
                    ErrorKind::Validation,
                    "invalid_health_status",
                    format!(
                        "health status for app `{}` must be 100-599 and requires health_path",
                        app.name
                    ),
                ));
            }
            for (name, input) in &app.environment {
                let key = (app.service.as_str(), name.as_str());
                if service_environment
                    .insert(key, input)
                    .is_some_and(|existing| existing != input)
                {
                    return Err(PluginError::permanent(
                        ErrorKind::Validation,
                        "conflicting_service_environment",
                        format!(
                            "apps sharing service `{}` configure environment variable `{name}` differently",
                            app.service
                        ),
                    ));
                }
            }
        }
        Ok(desired)
    }

    pub(crate) fn project_root<'a>(
        &'a self,
        context: &'a OperationContext,
    ) -> PluginResult<&'a Path> {
        let granted = context
            .project_root
            .as_deref()
            .map(Path::new)
            .ok_or_else(|| {
                PluginError::permanent(
                    ErrorKind::Validation,
                    "project_root_required",
                    "Kubernetes builds require the explicitly granted project root",
                )
            })?;
        if !granted.is_absolute() {
            return Err(PluginError::permanent(
                ErrorKind::Validation,
                "project_root_not_absolute",
                "the explicitly granted project root must be absolute",
            ));
        }
        let canonical_granted = granted.canonicalize().map_err(|error| {
            PluginError::permanent(
                ErrorKind::Validation,
                "project_root_unreadable",
                format!("the explicitly granted project root must be readable: {error}"),
            )
        })?;
        if let Some(claimed) = self.project.root.as_deref() {
            let canonical_claimed = claimed.canonicalize().map_err(|error| {
                PluginError::permanent(
                    ErrorKind::Validation,
                    "desired_project_root_unreadable",
                    format!("the desired project root must be readable: {error}"),
                )
            })?;
            if canonical_claimed != canonical_granted {
                return Err(PluginError::permanent(
                    ErrorKind::Conflict,
                    "project_root_authority_mismatch",
                    "desired project root does not match the operation context's granted Git root",
                ));
            }
        }
        Ok(granted)
    }

    pub(crate) fn resolve_app_environment(
        &self,
        secrets: &BTreeMap<String, SecretValue>,
    ) -> PluginResult<BTreeMap<String, BTreeMap<String, String>>> {
        let mut services = BTreeMap::<String, BTreeMap<String, String>>::new();
        for app in &self.apps {
            let environment = services.entry(app.service.clone()).or_default();
            for (name, input) in &app.environment {
                let value = match input {
                    EnvironmentInput::Literal(value) => value.clone(),
                    EnvironmentInput::Secret { secret } => secrets
                        .get(secret)
                        .ok_or_else(|| {
                            PluginError::permanent(
                                ErrorKind::Validation,
                                "missing_application_secret",
                                format!("application secret `{secret}` was not supplied by core"),
                            )
                        })?
                        .expose_secret()
                        .to_owned(),
                };
                environment.insert(name.clone(), value);
            }
        }
        Ok(services)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ComposeProject {
    pub document: Value,
    pub services: BTreeMap<String, ComposeService>,
}

#[derive(Clone, Debug)]
pub(crate) struct ComposeService {
    raw: Value,
}

impl ComposeProject {
    pub(crate) async fn load(desired: &DesiredState) -> PluginResult<Self> {
        let path = desired.resolved_compose_path.as_deref().ok_or_else(|| {
            PluginError::permanent(
                ErrorKind::Validation,
                "resolved_compose_required",
                "Kubernetes planning requires core's ephemeral resolved Compose document",
            )
        })?;
        if !path.is_absolute() {
            return Err(PluginError::permanent(
                ErrorKind::Validation,
                "resolved_compose_not_absolute",
                "resolved_compose_path must be absolute",
            ));
        }
        let bytes = tokio::fs::read(path).await.map_err(|error| {
            PluginError::permanent(
                ErrorKind::Validation,
                "resolved_compose_unreadable",
                format!("could not read resolved Compose input: {error}"),
            )
        })?;
        let document: Value = serde_json::from_slice(&bytes).map_err(|error| {
            PluginError::permanent(
                ErrorKind::Validation,
                "resolved_compose_invalid",
                format!("resolved Compose input is not valid JSON: {error}"),
            )
        })?;
        let raw_services = document
            .get("services")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                PluginError::permanent(
                    ErrorKind::Validation,
                    "compose_services_required",
                    "resolved Compose input must contain a services object",
                )
            })?;
        let mut services = BTreeMap::new();
        for (name, raw) in raw_services {
            if !raw.is_object() {
                return Err(PluginError::permanent(
                    ErrorKind::Validation,
                    "invalid_compose_service",
                    format!("Compose service `{name}` must be an object"),
                ));
            }
            services.insert(name.clone(), ComposeService { raw: raw.clone() });
        }
        Ok(Self { document, services })
    }

    pub(crate) fn validate(&self, desired: &DesiredState) -> PluginResult<()> {
        validate_top_level_networks(&self.document)?;
        validate_top_level_volumes(&self.document)?;
        for field in ["configs", "secrets"] {
            if self
                .document
                .get(field)
                .is_some_and(|value| !is_empty(value))
            {
                return Err(PluginError::permanent(
                    ErrorKind::Unsupported,
                    "compose_top_level_resource_unsupported",
                    format!(
                        "top-level Compose `{field}` entries are not supported by the native Kubernetes translator"
                    ),
                ));
            }
        }
        for (name, service) in &self.services {
            if !service.raw.is_object() {
                return Err(PluginError::permanent(
                    ErrorKind::Validation,
                    "invalid_compose_service",
                    format!("Compose service `{name}` must be an object"),
                ));
            }
        }
        for app in &desired.apps {
            let service = self.services.get(&app.service).ok_or_else(|| {
                PluginError::permanent(
                    ErrorKind::Validation,
                    "app_service_missing",
                    format!(
                        "app `{}` refers to missing Compose service `{}`",
                        app.name, app.service
                    ),
                )
            })?;
            if !service.ports().contains(&app.port) {
                // Compose does not require `expose`, but retain a strict upper
                // bound by accepting the explicitly configured app port.
            }
            if service.is_job() {
                return Err(unsupported_service(
                    &app.service,
                    &format!(
                        "Job services cannot back public app `{}` because they have no stable Service endpoints",
                        app.name
                    ),
                ));
            }
        }
        for (name, service) in &self.services {
            service.validate(name)?;
        }
        Ok(())
    }

    pub(crate) fn has_local_builds(&self) -> bool {
        self.services
            .values()
            .any(|service| service.build_value().is_some())
    }
}

fn reject_unsupported_service_fields(
    service_name: &str,
    service: &Map<String, Value>,
) -> PluginResult<()> {
    const TRANSLATED_OR_VALIDATED: &[&str] = &[
        "build",
        "command",
        "configs",
        "entrypoint",
        "environment",
        "expose",
        "healthcheck",
        "image",
        "network_mode",
        "networks",
        "ports",
        "privileged",
        "secrets",
        "volumes",
        "working_dir",
        "x-lightrail",
    ];
    let unsupported = service
        .iter()
        .filter(|(field, value)| {
            !TRANSLATED_OR_VALIDATED.contains(&field.as_str()) && !is_empty(value)
        })
        .map(|(field, _)| field.clone())
        .collect::<Vec<_>>();
    if unsupported.is_empty() {
        return Ok(());
    }
    Err(unsupported_service(
        service_name,
        &format!(
            "field(s) {} are not translated; remove them rather than deploying different semantics",
            unsupported.join(", ")
        ),
    ))
}

fn validate_extension(service_name: &str, extension: Option<&Value>) -> PluginResult<()> {
    let Some(extension) = extension else {
        return Ok(());
    };
    if is_empty(extension) {
        return Ok(());
    }
    let extension = extension.as_object().ok_or_else(|| {
        PluginError::permanent(
            ErrorKind::Validation,
            "invalid_lightrail_extension",
            format!("Compose service `{service_name}` x-lightrail must be an object"),
        )
    })?;
    let unsupported = extension
        .iter()
        .filter(|(field, value)| field.as_str() != "kind" && !is_empty(value))
        .map(|(field, _)| field.clone())
        .collect::<Vec<_>>();
    if !unsupported.is_empty() {
        return Err(unsupported_service(
            service_name,
            &format!(
                "x-lightrail field(s) {} are not translated",
                unsupported.join(", ")
            ),
        ));
    }
    match extension.get("kind") {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(kind)) if matches!(kind.as_str(), "job" | "stateful") => Ok(()),
        _ => Err(PluginError::permanent(
            ErrorKind::Validation,
            "invalid_lightrail_kind",
            format!(
                "Compose service `{service_name}` x-lightrail.kind must be `job` or `stateful`"
            ),
        )),
    }
}

fn external_enabled(value: &Value) -> bool {
    !matches!(value, Value::Null | Value::Bool(false))
}

fn compose_project_name<'a>(compose: &'a Value, resource: &str) -> PluginResult<&'a str> {
    compose
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            PluginError::permanent(
                ErrorKind::Validation,
                "compose_project_name_required",
                format!(
                    "resolved Compose must include its project name to verify generated {resource} names"
                ),
            )
        })
}

fn validate_top_level_networks(compose: &Value) -> PluginResult<()> {
    let Some(networks) = compose.get("networks") else {
        return Ok(());
    };
    let networks = networks.as_object().ok_or_else(|| {
        PluginError::permanent(
            ErrorKind::Validation,
            "invalid_compose_networks",
            "top-level Compose `networks` must be an object",
        )
    })?;
    if networks.is_empty() {
        return Ok(());
    }
    if networks.len() != 1 || !networks.contains_key("default") {
        return Err(PluginError::permanent(
            ErrorKind::Unsupported,
            "compose_network_topology_unsupported",
            "Kubernetes translation supports only Compose's implicit `default` network; custom or multiple networks cannot be preserved",
        ));
    }
    let definition = &networks["default"];
    if definition.is_null() {
        return Ok(());
    }
    let definition = definition.as_object().ok_or_else(|| {
        PluginError::permanent(
            ErrorKind::Validation,
            "invalid_compose_network",
            "top-level Compose network `default` must be an object",
        )
    })?;
    let unsupported = definition
        .iter()
        .filter(|(field, value)| {
            !matches!(field.as_str(), "name" | "ipam" | "external") && !is_empty(value)
        })
        .map(|(field, _)| field.clone())
        .collect::<Vec<_>>();
    if !unsupported.is_empty()
        || definition.get("ipam").is_some_and(|value| !is_empty(value))
        || definition.get("external").is_some_and(external_enabled)
    {
        return Err(PluginError::permanent(
            ErrorKind::Unsupported,
            "compose_network_options_unsupported",
            format!(
                "top-level Compose network `default` uses options Kubernetes translation cannot preserve{}",
                if unsupported.is_empty() {
                    String::new()
                } else {
                    format!(": {}", unsupported.join(", "))
                }
            ),
        ));
    }
    if let Some(name) = definition.get("name") {
        let name = name.as_str().ok_or_else(|| {
            PluginError::permanent(
                ErrorKind::Validation,
                "invalid_compose_network",
                "top-level Compose network `default.name` must be a string",
            )
        })?;
        let project_name = compose_project_name(compose, "network")?;
        if name != format!("{project_name}_default") {
            return Err(PluginError::permanent(
                ErrorKind::Unsupported,
                "compose_custom_network_name_unsupported",
                format!(
                    "top-level Compose network `default` has custom name `{name}`; only generated `{project_name}_default` is supported"
                ),
            ));
        }
    }
    Ok(())
}

fn validate_service_networks(service_name: &str, service: &Map<String, Value>) -> PluginResult<()> {
    let Some(networks) = service.get("networks") else {
        return Ok(());
    };
    if networks.is_null() {
        return Ok(());
    }
    let networks = networks.as_object().ok_or_else(|| {
        PluginError::permanent(
            ErrorKind::Validation,
            "invalid_compose_service_networks",
            format!("Compose service `{service_name}` networks must be an object"),
        )
    })?;
    if networks.is_empty() {
        return Ok(());
    }
    if networks.len() != 1 || !networks.contains_key("default") {
        return Err(unsupported_service(
            service_name,
            "only implicit `default` network membership is supported; custom or multiple network membership cannot be preserved",
        ));
    }
    if !is_empty(&networks["default"]) {
        return Err(unsupported_service(
            service_name,
            "aliases, static addresses, and other `default` network options cannot be preserved",
        ));
    }
    Ok(())
}

fn validate_top_level_volumes(compose: &Value) -> PluginResult<()> {
    let Some(volumes) = compose.get("volumes") else {
        return Ok(());
    };
    let volumes = volumes.as_object().ok_or_else(|| {
        PluginError::permanent(
            ErrorKind::Validation,
            "invalid_compose_volumes",
            "top-level Compose `volumes` must be an object",
        )
    })?;
    for (name, raw) in volumes {
        if raw.is_null() {
            continue;
        }
        let definition = raw.as_object().ok_or_else(|| {
            PluginError::permanent(
                ErrorKind::Validation,
                "invalid_compose_volume",
                format!("top-level Compose volume `{name}` must be an object"),
            )
        })?;
        if definition.get("external").is_some_and(external_enabled) {
            return Err(PluginError::permanent(
                ErrorKind::Unsupported,
                "external_volume_unsupported",
                format!(
                    "external Compose volume `{name}` is not owned by the Kubernetes environment"
                ),
            ));
        }
        let unsupported = definition
            .iter()
            .filter(|(field, value)| {
                !matches!(field.as_str(), "name" | "external") && !is_empty(value)
            })
            .map(|(field, _)| field.clone())
            .collect::<Vec<_>>();
        if !unsupported.is_empty() {
            return Err(PluginError::permanent(
                ErrorKind::Unsupported,
                "compose_volume_options_unsupported",
                format!(
                    "top-level Compose volume `{name}` uses unsupported field(s): {}",
                    unsupported.join(", ")
                ),
            ));
        }
        if let Some(generated_name) = definition.get("name") {
            let generated_name = generated_name.as_str().ok_or_else(|| {
                PluginError::permanent(
                    ErrorKind::Validation,
                    "invalid_compose_volume",
                    format!("top-level Compose volume `{name}.name` must be a string"),
                )
            })?;
            let project_name = compose_project_name(compose, "volume")?;
            let expected = format!("{project_name}_{name}");
            if generated_name != expected {
                return Err(PluginError::permanent(
                    ErrorKind::Unsupported,
                    "compose_custom_volume_name_unsupported",
                    format!(
                        "top-level Compose volume `{name}` has custom name `{generated_name}`; only generated `{expected}` is supported"
                    ),
                ));
            }
        }
    }
    Ok(())
}

impl ComposeService {
    fn object(&self) -> &Map<String, Value> {
        self.raw
            .as_object()
            .expect("Compose services are values from a services object")
    }

    fn validate(&self, name: &str) -> PluginResult<()> {
        let object = self.object();
        reject_unsupported_service_fields(name, object)?;
        validate_service_networks(name, object)?;
        if object
            .get("network_mode")
            .is_some_and(|value| !is_empty(value))
        {
            return Err(unsupported_service(
                name,
                "network_mode cannot be preserved by an environment-isolated Kubernetes Pod",
            ));
        }
        if let Some(privileged) = object.get("privileged") {
            match privileged {
                Value::Null | Value::Bool(false) => {}
                Value::Bool(true) => {
                    return Err(unsupported_service(
                        name,
                        "privileged containers are not supported by the native Kubernetes runtime",
                    ));
                }
                _ => {
                    return Err(PluginError::permanent(
                        ErrorKind::Validation,
                        "invalid_compose_privileged",
                        format!("Compose service `{name}` privileged must be a boolean"),
                    ));
                }
            }
        }
        for mount in self.mounts()? {
            if mount.kind == MountKind::Bind {
                return Err(unsupported_service(
                    name,
                    "local bind mounts are forbidden; package application source in an image",
                ));
            }
        }
        for field in ["configs", "secrets"] {
            if object.get(field).is_some_and(|value| !is_empty(value)) {
                return Err(unsupported_service(
                    name,
                    &format!("Compose `{field}` translation is not implemented yet"),
                ));
            }
        }
        if let Some(build) = self.build_value() {
            let _ = parse_build_input(name, build)?;
        }
        validate_extension(name, object.get("x-lightrail"))?;
        if let Some(image) = object.get("image") {
            if !image.is_null() && image.as_str().is_none_or(str::is_empty) {
                return Err(PluginError::permanent(
                    ErrorKind::Validation,
                    "invalid_compose_image",
                    format!("Compose service `{name}` image must be a non-empty string"),
                ));
            }
        }
        if self.image().is_none() && self.build_value().is_none() {
            return Err(unsupported_service(
                name,
                "every service needs either `image:` or `build:`",
            ));
        }
        Ok(())
    }

    pub(crate) fn image(&self) -> Option<&str> {
        self.object().get("image").and_then(Value::as_str)
    }

    fn build_value(&self) -> Option<&Value> {
        self.object().get("build")
    }

    fn extension_kind(&self) -> Option<&str> {
        self.object()
            .get("x-lightrail")
            .and_then(Value::as_object)
            .and_then(|extension| extension.get("kind"))
            .and_then(Value::as_str)
    }

    fn environment(&self) -> PluginResult<BTreeMap<String, String>> {
        let Some(value) = self.object().get("environment") else {
            return Ok(BTreeMap::new());
        };
        match value {
            Value::Object(values) => values
                .iter()
                .filter_map(|(name, value)| {
                    scalar_string(value).map(|value| value.map(|value| (name.clone(), value)))
                })
                .collect(),
            Value::Array(values) => {
                let mut environment = BTreeMap::new();
                for value in values {
                    let item = value.as_str().ok_or_else(|| {
                        PluginError::permanent(
                            ErrorKind::Validation,
                            "invalid_compose_environment",
                            "Compose environment arrays must contain strings",
                        )
                    })?;
                    let (name, value) = item.split_once('=').ok_or_else(|| {
                        PluginError::permanent(
                            ErrorKind::Validation,
                            "unresolved_compose_environment",
                            "resolved Compose environment entries must contain values",
                        )
                    })?;
                    environment.insert(name.to_owned(), value.to_owned());
                }
                Ok(environment)
            }
            _ => Err(PluginError::permanent(
                ErrorKind::Validation,
                "invalid_compose_environment",
                "Compose environment must be an object or array",
            )),
        }
    }

    fn ports(&self) -> BTreeSet<u16> {
        let mut ports = BTreeSet::new();
        for field in ["ports", "expose"] {
            if let Some(values) = self.object().get(field).and_then(Value::as_array) {
                for value in values {
                    if let Some(port) = port_value(value) {
                        ports.insert(port);
                    }
                }
            }
        }
        ports
    }

    fn mounts(&self) -> PluginResult<Vec<Mount>> {
        self.object()
            .get("volumes")
            .and_then(Value::as_array)
            .map_or_else(
                || Ok(Vec::new()),
                |mounts| mounts.iter().map(parse_mount).collect(),
            )
    }

    fn is_job(&self) -> bool {
        self.extension_kind() == Some("job")
    }

    fn is_stateful(&self) -> PluginResult<bool> {
        Ok(self.extension_kind() == Some("stateful")
            || (self.extension_kind().is_none()
                && self
                    .mounts()?
                    .iter()
                    .any(|mount| mount.kind == MountKind::Volume)))
    }
}

fn unsupported_service(service: &str, reason: &str) -> PluginError {
    PluginError::permanent(
        ErrorKind::Unsupported,
        "unsupported_compose_service",
        format!("Compose service `{service}` is unsupported: {reason}"),
    )
}

fn scalar_string(value: &Value) -> Option<PluginResult<String>> {
    match value {
        Value::Null => None,
        Value::String(value) => Some(Ok(value.clone())),
        Value::Bool(value) => Some(Ok(value.to_string())),
        Value::Number(value) => Some(Ok(value.to_string())),
        Value::Array(_) | Value::Object(_) => Some(Err(PluginError::permanent(
            ErrorKind::Validation,
            "invalid_environment_value",
            "Compose environment values must be scalar",
        ))),
    }
}

fn port_value(value: &Value) -> Option<u16> {
    match value {
        Value::Number(number) => number.as_u64().and_then(|port| u16::try_from(port).ok()),
        Value::String(value) => value
            .as_str()
            .split_once(':')
            .map_or(value.as_str(), |(_, target)| target)
            .split('/')
            .next()
            .and_then(|port| port.parse().ok()),
        Value::Object(object) => object
            .get("target")
            .and_then(Value::as_u64)
            .and_then(|port| u16::try_from(port).ok()),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MountKind {
    Volume,
    Bind,
    Tmpfs,
}

#[derive(Clone, Debug)]
struct Mount {
    kind: MountKind,
    source: Option<String>,
    target: String,
    read_only: bool,
}

fn parse_mount(value: &Value) -> PluginResult<Mount> {
    match value {
        Value::String(value) => {
            let parts = value.split(':').collect::<Vec<_>>();
            match parts.as_slice() {
                [target] => Ok(Mount {
                    kind: MountKind::Volume,
                    source: None,
                    target: (*target).to_owned(),
                    read_only: false,
                }),
                [source, target] | [source, target, _] => Ok(Mount {
                    kind: if source.starts_with('.') || source.starts_with('/') {
                        MountKind::Bind
                    } else {
                        MountKind::Volume
                    },
                    source: Some((*source).to_owned()),
                    target: (*target).to_owned(),
                    read_only: parts.get(2).is_some_and(|mode| mode.contains("ro")),
                }),
                _ => Err(invalid_mount()),
            }
        }
        Value::Object(object) => {
            let kind = match object
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("volume")
            {
                "volume" => MountKind::Volume,
                "bind" => MountKind::Bind,
                "tmpfs" => MountKind::Tmpfs,
                _ => return Err(invalid_mount()),
            };
            let target = object
                .get("target")
                .and_then(Value::as_str)
                .filter(|target| target.starts_with('/'))
                .ok_or_else(invalid_mount)?;
            Ok(Mount {
                kind,
                source: object
                    .get("source")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                target: target.to_owned(),
                read_only: object
                    .get("read_only")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            })
        }
        _ => Err(invalid_mount()),
    }
}

fn invalid_mount() -> PluginError {
    PluginError::permanent(
        ErrorKind::Validation,
        "invalid_compose_mount",
        "Compose volume mounts must use a supported resolved short or long syntax",
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct BuildSpec {
    pub service: String,
    pub image: String,
    pub context: PathBuf,
    pub dockerfile: Option<PathBuf>,
    pub arguments: BTreeMap<String, String>,
}

struct BuildInput<'a> {
    context: &'a str,
    dockerfile: Option<&'a str>,
    arguments: BTreeMap<String, String>,
}

struct ResolvedBuildInput {
    context: PathBuf,
    dockerfile: Option<PathBuf>,
    arguments: BTreeMap<String, String>,
}

fn parse_build_input<'a>(service_name: &str, raw: &'a Value) -> PluginResult<BuildInput<'a>> {
    let (context, dockerfile, arguments) = match raw {
        Value::String(context) if !context.is_empty() => (context.as_str(), None, BTreeMap::new()),
        Value::Object(object) => {
            let unsupported = object
                .iter()
                .filter(|(field, value)| {
                    !matches!(field.as_str(), "context" | "dockerfile" | "args") && !is_empty(value)
                })
                .map(|(field, _)| field.clone())
                .collect::<Vec<_>>();
            if !unsupported.is_empty() {
                return Err(unsupported_service(
                    service_name,
                    &format!(
                        "build field(s) {} are not translated by the registry builder",
                        unsupported.join(", ")
                    ),
                ));
            }
            let context = match object.get("context") {
                None => ".",
                Some(Value::String(context)) if !context.is_empty() => context,
                _ => {
                    return Err(PluginError::permanent(
                        ErrorKind::Validation,
                        "invalid_build_context",
                        format!(
                            "Compose service `{service_name}` build.context must be a non-empty path string"
                        ),
                    ));
                }
            };
            let dockerfile = match object.get("dockerfile") {
                None | Some(Value::Null) => None,
                Some(Value::String(dockerfile)) if !dockerfile.is_empty() => {
                    Some(dockerfile.as_str())
                }
                _ => {
                    return Err(PluginError::permanent(
                        ErrorKind::Validation,
                        "invalid_dockerfile",
                        format!(
                            "Compose service `{service_name}` build.dockerfile must be a non-empty path string"
                        ),
                    ));
                }
            };
            (
                context,
                dockerfile,
                parse_build_arguments(object.get("args"))?,
            )
        }
        _ => {
            return Err(unsupported_service(
                service_name,
                "build must be a non-empty path string or object",
            ));
        }
    };
    Ok(BuildInput {
        context,
        dockerfile,
        arguments,
    })
}

fn resolve_build_input(
    root: &Path,
    service_name: &str,
    raw: &Value,
) -> PluginResult<ResolvedBuildInput> {
    let input = parse_build_input(service_name, raw)?;
    let context = scoped_source_path(root, Path::new(input.context), "build context")?;
    if !context.is_dir() {
        return Err(PluginError::permanent(
            ErrorKind::Validation,
            "invalid_build_context",
            format!("Compose service `{service_name}` build context must be a directory"),
        ));
    }
    let dockerfile = input
        .dockerfile
        .map(|path| scoped_source_path(&context, Path::new(path), "Dockerfile"))
        .transpose()?;
    if dockerfile.as_ref().is_some_and(|path| !path.is_file()) {
        return Err(PluginError::permanent(
            ErrorKind::Validation,
            "invalid_dockerfile",
            format!("Compose service `{service_name}` Dockerfile must be a regular file"),
        ));
    }
    Ok(ResolvedBuildInput {
        context,
        dockerfile,
        arguments: input.arguments,
    })
}

pub(crate) fn build_specs(
    settings: &Settings,
    desired: &DesiredState,
    compose: &ComposeProject,
    context: &OperationContext,
    revision: &str,
) -> PluginResult<Vec<BuildSpec>> {
    let root = compose
        .has_local_builds()
        .then(|| desired.project_root(context))
        .transpose()?;
    let mut builds = Vec::new();
    for (service_name, service) in &compose.services {
        let Some(raw) = service.build_value() else {
            continue;
        };
        let root = root.ok_or_else(|| {
            PluginError::permanent(
                ErrorKind::Internal,
                "project_root_required",
                "local build discovery lost its granted project root",
            )
        })?;
        let input = resolve_build_input(root, service_name, raw)?;
        let service_label = dns_label(service_name);
        let project_label = dns_label(&desired.project.slug);
        builds.push(BuildSpec {
            service: service_name.clone(),
            image: format!(
                "{}{project_label}/{service_label}:{}",
                settings.image_prefix(),
                &revision[..16]
            ),
            context: input.context,
            dockerfile: input.dockerfile,
            arguments: input.arguments,
        });
    }
    Ok(builds)
}

fn parse_build_arguments(value: Option<&Value>) -> PluginResult<BTreeMap<String, String>> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    let object = value.as_object().ok_or_else(|| {
        PluginError::permanent(
            ErrorKind::Validation,
            "invalid_build_args",
            "resolved Compose build args must be an object",
        )
    })?;
    let mut arguments = BTreeMap::new();
    for (name, value) in object {
        if name.is_empty()
            || !name.bytes().enumerate().all(|(index, byte)| {
                byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
            })
        {
            return Err(PluginError::permanent(
                ErrorKind::Unsupported,
                "unsafe_build_arg_name",
                format!(
                    "build argument `{name}` cannot be passed without putting its value in argv"
                ),
            ));
        }
        let Some(value) = scalar_string(value) else {
            continue;
        };
        arguments.insert(name.clone(), value?);
    }
    Ok(arguments)
}

fn is_empty(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Array(values) => values.is_empty(),
        Value::Object(values) => values.is_empty(),
        Value::String(value) => value.is_empty(),
        Value::Bool(_) | Value::Number(_) => false,
    }
}

fn scoped_source_path(root: &Path, path: &Path, description: &str) -> PluginResult<PathBuf> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(PluginError::permanent(
            ErrorKind::Validation,
            "build_context_outside_project",
            format!("{description} must remain inside the current project root"),
        ));
    }
    let canonical_root = root.canonicalize().map_err(|error| {
        PluginError::permanent(
            ErrorKind::Validation,
            "project_root_unreadable",
            format!("the current project root must exist and be readable: {error}"),
        )
    })?;
    if !canonical_root.is_dir() {
        return Err(PluginError::permanent(
            ErrorKind::Validation,
            "project_root_unreadable",
            "the current project root must be a directory",
        ));
    }
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        canonical_root.join(path)
    };
    let canonical_candidate = candidate.canonicalize().map_err(|error| {
        PluginError::permanent(
            ErrorKind::Validation,
            "build_source_unreadable",
            format!("{description} must exist and be readable: {error}"),
        )
    })?;
    if !canonical_candidate.starts_with(&canonical_root) {
        return Err(PluginError::permanent(
            ErrorKind::Validation,
            "build_context_outside_project",
            format!(
                "{description} resolves outside the current project root, including through a symbolic link"
            ),
        ));
    }
    Ok(canonical_candidate)
}

fn project_relative_revision_path(
    project_root: &Path,
    path: &Path,
    description: &str,
) -> PluginResult<String> {
    let canonical_root = project_root.canonicalize().map_err(|error| {
        PluginError::permanent(
            ErrorKind::Validation,
            "project_root_unreadable",
            format!("the current project root must exist and be readable: {error}"),
        )
    })?;
    let relative = path.strip_prefix(&canonical_root).map_err(|_| {
        PluginError::permanent(
            ErrorKind::Validation,
            "build_context_outside_project",
            format!("{description} must remain inside the current project root"),
        )
    })?;
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => parts.push(part.to_str().ok_or_else(|| {
                PluginError::permanent(
                    ErrorKind::Validation,
                    "build_source_not_utf8",
                    format!("{description} must use UTF-8 path components"),
                )
            })?),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(PluginError::permanent(
                    ErrorKind::Validation,
                    "build_context_outside_project",
                    format!("{description} must remain inside the current project root"),
                ));
            }
        }
    }
    Ok(if parts.is_empty() {
        ".".to_owned()
    } else {
        parts.join("/")
    })
}

fn canonical_build_revision_value(
    root: &Path,
    service_name: &str,
    raw_build: &Value,
) -> PluginResult<Value> {
    let build = resolve_build_input(root, service_name, raw_build)?;
    let mut canonical = Map::new();
    canonical.insert(
        "context".to_owned(),
        Value::String(project_relative_revision_path(
            root,
            &build.context,
            "build context",
        )?),
    );
    if let Some(dockerfile) = build.dockerfile {
        canonical.insert(
            "dockerfile".to_owned(),
            Value::String(project_relative_revision_path(
                root,
                &dockerfile,
                "Dockerfile",
            )?),
        );
    }
    if !build.arguments.is_empty() {
        canonical.insert(
            "args".to_owned(),
            serde_json::to_value(build.arguments).map_err(serialization_error)?,
        );
    }
    Ok(Value::Object(canonical))
}

fn canonicalize_service_revision(
    service_name: &str,
    raw: &mut Value,
    project_root: Option<&Path>,
) -> PluginResult<()> {
    let service = raw.as_object_mut().ok_or_else(|| {
        PluginError::permanent(
            ErrorKind::Validation,
            "invalid_compose_service",
            format!("Compose service `{service_name}` must be an object"),
        )
    })?;
    if service.contains_key("environment") {
        let environment = ComposeService {
            raw: Value::Object(service.clone()),
        }
        .environment()?;
        service.insert(
            "environment".to_owned(),
            Value::Object(
                environment
                    .into_keys()
                    .map(|name| (name, Value::Null))
                    .collect(),
            ),
        );
    }
    if let Some(networks) = service.get_mut("networks") {
        *networks = json!({"default": null});
    }
    let Some(raw_build) = service.get("build").cloned() else {
        return Ok(());
    };
    let root = project_root.ok_or_else(|| {
        PluginError::permanent(
            ErrorKind::Validation,
            "project_root_required",
            "Kubernetes build revision normalization requires the explicitly granted project root",
        )
    })?;
    service.insert(
        "build".to_owned(),
        canonical_build_revision_value(root, service_name, &raw_build)?,
    );
    Ok(())
}

fn canonical_revision_document(
    desired: &DesiredState,
    compose: &ComposeProject,
    context: &OperationContext,
) -> PluginResult<Value> {
    // Canonicalization is deliberately downstream of the strict translator
    // validation. Unsupported intent must fail rather than disappear from the
    // revision input.
    compose.validate(desired)?;
    let project_root = if compose.has_local_builds() {
        Some(desired.project_root(context)?)
    } else {
        None
    };
    let mut stable = compose.document.clone();
    let document = stable.as_object_mut().ok_or_else(|| {
        PluginError::permanent(
            ErrorKind::Validation,
            "invalid_compose_document",
            "resolved Compose input must be an object",
        )
    })?;

    // Compose derives these from the checkout directory. Kubernetes uses its
    // own deterministic Namespace and network model.
    document.remove("name");
    if let Some(default) = document
        .get_mut("networks")
        .and_then(Value::as_object_mut)
        .and_then(|networks| networks.get_mut("default"))
    {
        *default = Value::Null;
    }
    if let Some(volumes) = document.get_mut("volumes").and_then(Value::as_object_mut) {
        for definition in volumes.values_mut() {
            *definition = Value::Null;
        }
    }

    let services = document
        .get_mut("services")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            PluginError::permanent(
                ErrorKind::Validation,
                "compose_services_required",
                "resolved Compose input must contain a services object",
            )
        })?;
    for (service_name, raw) in services {
        canonicalize_service_revision(service_name, raw, project_root)?;
    }
    Ok(stable)
}

pub(crate) fn revision(
    desired: &DesiredState,
    compose: &ComposeProject,
    build_platforms: &[String],
    context: &OperationContext,
    operation_id: &str,
) -> PluginResult<String> {
    let mut hasher = Sha256::new();
    hasher.update(
        serde_json::to_vec(&canonical_revision_document(desired, compose, context)?)
            .map_err(serialization_error)?,
    );
    hasher.update(desired.project.id.as_bytes());
    hasher.update(desired.environment.id.as_bytes());
    if let Some(commit) = &desired.environment.commit {
        hasher.update(commit.as_bytes());
    }
    if desired.environment.dirty || compose.has_local_builds() {
        // Git does not report ignored files, while Docker may include them in
        // a build context. Scope every local build revision to the operation
        // so distinct local bytes can never silently reuse one tag. Buildx
        // still provides content-addressed layer caching underneath the tag.
        // Dirty non-build inputs retain the same conservative behavior.
        hasher.update(operation_id.as_bytes());
    }
    if compose.has_local_builds() {
        // A multi-platform manifest is part of the immutable image artifact.
        // Canonicalize the set so ordering-only profile changes do not churn a
        // revision, while a real explicit or discovered platform change can
        // never overwrite a different image at the same revision tag.
        let mut platforms = build_platforms.to_vec();
        platforms.sort();
        platforms.dedup();
        hasher.update(b"\0lightrail-kubernetes-build-platforms-v1\0");
        hasher.update(serde_json::to_vec(&platforms).map_err(serialization_error)?);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResourceRole {
    Runtime,
    Exposure,
}

#[derive(Clone, Debug)]
pub(crate) struct RenderedResource {
    pub key: String,
    pub kind: String,
    pub name: String,
    pub role: ResourceRole,
    pub manifest: Value,
    pub spec_hash: String,
}

#[derive(Clone, Debug)]
pub(crate) struct RenderedEnvironment {
    pub namespace: String,
    pub resources: Vec<RenderedResource>,
    pub endpoints: Vec<Endpoint>,
    pub readiness_targets: Vec<ReadinessTarget>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReadinessTarget {
    pub app: String,
    pub base_url: String,
    pub probe_url: String,
    pub expected_status: Option<u16>,
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) fn render_environment(
    settings: &Settings,
    desired: &DesiredState,
    compose: &ComposeProject,
    context: &OperationContext,
    metadata: &ContextMetadata,
    revision: &str,
    resolve_secrets: bool,
) -> PluginResult<RenderedEnvironment> {
    let namespace = namespace_name(&settings.namespace_prefix, &desired.environment.id);
    let builds = build_specs(settings, desired, compose, context, revision)?;
    let built_images = builds
        .into_iter()
        .map(|build| (build.service, build.image))
        .collect::<BTreeMap<_, _>>();
    let app_environment = if resolve_secrets {
        desired.resolve_app_environment(&context.secrets)?
    } else {
        desired
            .apps
            .iter()
            .map(|app| {
                (
                    app.service.clone(),
                    app.environment
                        .keys()
                        .map(|name| (name.clone(), "[REDACTED]".to_owned()))
                        .collect(),
                )
            })
            .collect()
    };
    let labels = base_labels(desired, revision);
    let annotations = base_annotations(desired);
    let mut resources = Vec::new();
    let mut namespace_annotations = annotations.clone();
    namespace_annotations.insert(
        CONTROL_NAMESPACE_ANNOTATION.to_owned(),
        settings.control_namespace.clone(),
    );

    resources.push(resource(
        "Namespace",
        &namespace,
        ResourceRole::Runtime,
        false,
        json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": namespace,
                "labels": labels,
                "annotations": namespace_annotations,
            }
        }),
    )?);

    let mut claims = BTreeSet::new();
    for service in compose.services.values() {
        for mount in service.mounts()? {
            if mount.kind == MountKind::Volume {
                if let Some(source) = mount.source {
                    claims.insert(source);
                }
            }
        }
    }
    for claim in claims {
        let claim_name = resource_name("data", &claim);
        resources.push(resource(
            "PersistentVolumeClaim",
            &claim_name,
            ResourceRole::Runtime,
            false,
            json!({
                "apiVersion": "v1",
                "kind": "PersistentVolumeClaim",
                "metadata": resource_metadata(&claim_name, &namespace, &labels, &annotations, None),
                "spec": {
                    "accessModes": ["ReadWriteOnce"],
                    "resources": {"requests": {"storage": "1Gi"}}
                }
            }),
        )?);
    }

    let mut apps_by_service = BTreeMap::<&str, Vec<&AppSpec>>::new();
    for app in &desired.apps {
        apps_by_service
            .entry(app.service.as_str())
            .or_default()
            .push(app);
    }
    for (service_name, service) in &compose.services {
        let resource_service = dns_label(service_name);
        let service_labels = with_service_label(&labels, &resource_service);
        let mut environment = service.environment()?;
        if let Some(overrides) = app_environment.get(service_name) {
            environment.extend(overrides.clone());
        }
        let secret_name = resource_name("env", service_name);
        if !environment.is_empty() {
            let string_data = if resolve_secrets {
                serde_json::to_value(&environment).map_err(serialization_error)?
            } else {
                Value::Object(
                    environment
                        .keys()
                        .map(|name| (name.clone(), Value::String("[REDACTED]".to_owned())))
                        .collect(),
                )
            };
            resources.push(resource(
                "Secret",
                &secret_name,
                ResourceRole::Runtime,
                true,
                json!({
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "metadata": resource_metadata(
                        &secret_name,
                        &namespace,
                        &service_labels,
                        &annotations,
                        None
                    ),
                    "type": "Opaque",
                    "stringData": string_data,
                }),
            )?);
        }

        let mut ports = service.ports();
        if let Some(apps) = apps_by_service.get(service_name.as_str()) {
            ports.extend(apps.iter().map(|app| app.port));
        }
        let is_stateful = service.is_stateful()?;
        if is_stateful
            && settings.replicas > 1
            && service
                .mounts()?
                .iter()
                .any(|mount| mount.kind == MountKind::Volume && mount.source.is_some())
        {
            return Err(unsupported_service(
                service_name,
                "replicas greater than one with a shared ReadWriteOnce named volume are unsafe; use one replica or a future volumeClaimTemplates mapping",
            ));
        }
        if !service.is_job() {
            let service_ports = ports
                .iter()
                .enumerate()
                .map(|(index, port)| {
                    json!({
                        "name": format!("p{index}-{port}"),
                        "port": port,
                        "targetPort": port,
                        "protocol": "TCP"
                    })
                })
                .collect::<Vec<_>>();
            let mut service_spec = json!({
                "selector": {
                    ENVIRONMENT_LABEL: desired.environment.id,
                    SERVICE_LABEL: resource_service,
                }
            });
            if ports.is_empty() || is_stateful {
                service_spec["clusterIP"] = Value::String("None".to_owned());
            }
            if !service_ports.is_empty() {
                service_spec["ports"] = Value::Array(service_ports);
            }
            resources.push(resource(
                "Service",
                &resource_service,
                ResourceRole::Runtime,
                false,
                json!({
                    "apiVersion": "v1",
                    "kind": "Service",
                    "metadata": resource_metadata(
                        &resource_service,
                        &namespace,
                        &service_labels,
                        &annotations,
                        None
                    ),
                    "spec": service_spec
                }),
            )?);
        }

        let image = built_images
            .get(service_name)
            .cloned()
            .or_else(|| service.image().map(ToOwned::to_owned))
            .ok_or_else(|| unsupported_service(service_name, "image is unavailable"))?;
        let workload_kind = if service.is_job() {
            "Job"
        } else if is_stateful {
            "StatefulSet"
        } else {
            "Deployment"
        };
        let workload_name = resource_name("workload", service_name);
        let pod_spec = pod_spec(
            settings,
            service_name,
            service,
            &image,
            &secret_name,
            !environment.is_empty(),
            &ports,
        )?;
        let mut template_annotations = annotations.clone();
        if !environment.is_empty() && workload_kind != "Job" {
            template_annotations.insert(
                RUNTIME_CONFIG_REVISION_ANNOTATION.to_owned(),
                runtime_config_revision(&context.operation_id),
            );
        }
        let template = json!({
            "metadata": {
                "labels": service_labels,
                "annotations": template_annotations,
            },
            "spec": pod_spec
        });
        let manifest = match workload_kind {
            "Job" => json!({
                "apiVersion": "batch/v1",
                "kind": "Job",
                "metadata": resource_metadata(
                    &workload_name,
                    &namespace,
                    &service_labels,
                    &annotations,
                    None
                ),
                "spec": {
                    "backoffLimit": 1,
                    "template": template
                }
            }),
            "StatefulSet" => json!({
                "apiVersion": "apps/v1",
                "kind": "StatefulSet",
                "metadata": resource_metadata(
                    &workload_name,
                    &namespace,
                    &service_labels,
                    &annotations,
                    None
                ),
                "spec": {
                    "serviceName": resource_service,
                    "replicas": settings.replicas,
                    "selector": {"matchLabels": {
                        ENVIRONMENT_LABEL: desired.environment.id,
                        SERVICE_LABEL: resource_service,
                    }},
                    "template": template
                }
            }),
            _ => json!({
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": resource_metadata(
                    &workload_name,
                    &namespace,
                    &service_labels,
                    &annotations,
                    None
                ),
                "spec": {
                    "replicas": settings.replicas,
                    "selector": {"matchLabels": {
                        ENVIRONMENT_LABEL: desired.environment.id,
                        SERVICE_LABEL: resource_service,
                    }},
                    "template": template
                }
            }),
        };
        resources.push(resource(
            workload_kind,
            &workload_name,
            ResourceRole::Runtime,
            false,
            manifest,
        )?);
    }

    let (endpoints, readiness_targets, ingress_resources) = render_ingresses(
        settings,
        desired,
        metadata,
        &namespace,
        &labels,
        &annotations,
    )?;
    resources.extend(ingress_resources);
    Ok(RenderedEnvironment {
        namespace,
        resources,
        endpoints,
        readiness_targets,
    })
}

fn pod_spec(
    settings: &Settings,
    service_name: &str,
    service: &ComposeService,
    image: &str,
    secret_name: &str,
    has_environment: bool,
    ports: &BTreeSet<u16>,
) -> PluginResult<Value> {
    let object = service.object();
    let mut container = Map::new();
    container.insert("name".to_owned(), Value::String(dns_label(service_name)));
    container.insert("image".to_owned(), Value::String(image.to_owned()));
    container.insert(
        "imagePullPolicy".to_owned(),
        Value::String("IfNotPresent".to_owned()),
    );
    if has_environment {
        container.insert(
            "envFrom".to_owned(),
            json!([{"secretRef": {"name": secret_name}}]),
        );
    }
    if !ports.is_empty() {
        container.insert(
            "ports".to_owned(),
            Value::Array(
                ports
                    .iter()
                    .map(|port| json!({"containerPort": port, "protocol": "TCP"}))
                    .collect(),
            ),
        );
    }
    translate_command(object, &mut container)?;
    let mounts = service.mounts()?;
    let mut volume_mounts = Vec::new();
    let mut volumes = Vec::new();
    for (index, mount) in mounts.iter().enumerate() {
        let volume_name = format!("mount-{index}");
        volume_mounts.push(json!({
            "name": volume_name,
            "mountPath": mount.target,
            "readOnly": mount.read_only,
        }));
        let source = match mount.kind {
            MountKind::Volume => mount.source.as_ref().map_or_else(
                || json!({"emptyDir": {}}),
                |source| json!({"persistentVolumeClaim": {"claimName": resource_name("data", source)}}),
            ),
            MountKind::Tmpfs => json!({"emptyDir": {"medium": "Memory"}}),
            MountKind::Bind => return Err(unsupported_service(service_name, "bind mount")),
        };
        let mut volume = source.as_object().cloned().unwrap_or_default();
        volume.insert("name".to_owned(), Value::String(volume_name));
        volumes.push(Value::Object(volume));
    }
    if !volume_mounts.is_empty() {
        container.insert("volumeMounts".to_owned(), Value::Array(volume_mounts));
    }
    if let Some(app) = ports.iter().next() {
        if let Some(healthcheck) = object.get("healthcheck").and_then(Value::as_object) {
            if !healthcheck
                .get("disable")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                if let Some(probe) = health_probe(healthcheck, *app)? {
                    container.insert("readinessProbe".to_owned(), probe.clone());
                    container.insert("livenessProbe".to_owned(), probe);
                }
            }
        }
    }
    let mut spec = Map::new();
    spec.insert(
        "restartPolicy".to_owned(),
        Value::String(if service.is_job() {
            "Never".to_owned()
        } else {
            "Always".to_owned()
        }),
    );
    spec.insert(
        "containers".to_owned(),
        Value::Array(vec![Value::Object(container)]),
    );
    if !volumes.is_empty() {
        spec.insert("volumes".to_owned(), Value::Array(volumes));
    }
    if let Some(secret) = &settings.image_pull_secret {
        spec.insert("imagePullSecrets".to_owned(), json!([{"name": secret}]));
    }
    add_platform_scheduling(settings, &mut spec)?;
    Ok(Value::Object(spec))
}

fn add_platform_scheduling(settings: &Settings, spec: &mut Map<String, Value>) -> PluginResult<()> {
    let mut architectures = settings
        .platforms
        .iter()
        .map(|platform| match platform.as_str() {
            "linux/amd64" => Ok("amd64".to_owned()),
            "linux/arm64" => Ok("arm64".to_owned()),
            _ => Err(PluginError::permanent(
                ErrorKind::Validation,
                "invalid_platform",
                format!("unsupported Kubernetes image platform `{platform}`"),
            )),
        })
        .collect::<PluginResult<Vec<_>>>()?;
    architectures.sort();
    architectures.dedup();
    match architectures.as_slice() {
        [] => {}
        [architecture] => {
            spec.insert(
                "nodeSelector".to_owned(),
                json!({"kubernetes.io/arch": architecture}),
            );
        }
        _ => {
            spec.insert(
                "affinity".to_owned(),
                json!({
                    "nodeAffinity": {
                        "requiredDuringSchedulingIgnoredDuringExecution": {
                            "nodeSelectorTerms": [{
                                "matchExpressions": [{
                                    "key": "kubernetes.io/arch",
                                    "operator": "In",
                                    "values": architectures
                                }]
                            }]
                        }
                    }
                }),
            );
        }
    }
    Ok(())
}

fn runtime_config_revision(operation_id: &str) -> String {
    short_hash(
        &format!("lightrail-kubernetes-runtime-config-v1\0{operation_id}"),
        16,
    )
}

fn translate_command(
    object: &Map<String, Value>,
    container: &mut Map<String, Value>,
) -> PluginResult<()> {
    let entrypoint = object.get("entrypoint").filter(|value| !value.is_null());
    let command = object.get("command").filter(|value| !value.is_null());
    if let Some(value) = entrypoint {
        container.insert("command".to_owned(), command_array(value)?);
    }
    if let Some(value) = command {
        if value.is_string() && entrypoint.is_none() {
            container.insert("command".to_owned(), json!(["/bin/sh", "-c"]));
            container.insert("args".to_owned(), Value::Array(vec![value.clone()]));
        } else {
            container.insert("args".to_owned(), command_array(value)?);
        }
    }
    if let Some(directory) = object.get("working_dir").and_then(Value::as_str) {
        container.insert("workingDir".to_owned(), Value::String(directory.to_owned()));
    }
    Ok(())
}

fn command_array(value: &Value) -> PluginResult<Value> {
    match value {
        Value::String(value) => Ok(Value::Array(vec![Value::String(value.clone())])),
        Value::Array(values) if values.iter().all(Value::is_string) => Ok(value.clone()),
        _ => Err(PluginError::permanent(
            ErrorKind::Validation,
            "invalid_compose_command",
            "resolved Compose command and entrypoint must be strings or string arrays",
        )),
    }
}

fn health_probe(
    healthcheck: &Map<String, Value>,
    fallback_port: u16,
) -> PluginResult<Option<Value>> {
    let Some(test) = healthcheck.get("test").and_then(Value::as_array) else {
        return Ok(None);
    };
    let values = test
        .iter()
        .map(|value| value.as_str().map(ToOwned::to_owned))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| {
            PluginError::permanent(
                ErrorKind::Validation,
                "invalid_healthcheck",
                "Compose healthcheck test must contain strings",
            )
        })?;
    let probe = match values.as_slice() {
        [mode, command @ ..] if mode == "CMD" && !command.is_empty() => {
            json!({"exec": {"command": command}, "initialDelaySeconds": 2, "periodSeconds": 5})
        }
        [mode, command] if mode == "CMD-SHELL" => json!({
            "exec": {"command": ["/bin/sh", "-c", command]},
            "initialDelaySeconds": 2,
            "periodSeconds": 5
        }),
        [mode] if mode == "NONE" => return Ok(None),
        [] => return Ok(None),
        _ => json!({
            "tcpSocket": {"port": fallback_port},
            "initialDelaySeconds": 2,
            "periodSeconds": 5
        }),
    };
    Ok(Some(probe))
}

fn render_ingresses(
    settings: &Settings,
    desired: &DesiredState,
    metadata: &ContextMetadata,
    namespace: &str,
    labels: &BTreeMap<String, String>,
    annotations: &BTreeMap<String, String>,
) -> PluginResult<(Vec<Endpoint>, Vec<ReadinessTarget>, Vec<RenderedResource>)> {
    if desired.apps.is_empty() {
        return Ok((Vec::new(), Vec::new(), Vec::new()));
    }
    let address = ingress_ipv4(&metadata.target).ok_or_else(|| {
        PluginError::permanent(
            ErrorKind::Unavailable,
            "ingress_ipv4_unavailable",
            "the selected ingress controller has no public IPv4; generic native load-balancer hostnames are not delegated wildcard DNS zones, so configure an ingress with IPv4 or a future custom DNS plugin",
        )
    })?;
    let controller = ingress_controller(&metadata.target)?;
    let mut endpoints = Vec::new();
    let mut readiness_targets = Vec::new();
    let mut resources = Vec::new();
    let traefik_middleware =
        render_traefik_middleware(controller, &metadata.target, namespace, labels, annotations)?;
    if let Some((_, middleware)) = &traefik_middleware {
        resources.push(middleware.clone());
    }
    for app in &desired.apps {
        let host = app_hostname(
            &desired.environment.branch,
            &app.name,
            &desired.environment.profile,
            &desired.project.slug,
            address,
            &settings.dns_domain,
        )?;
        let name = resource_name("ingress", &app.name);
        let tls_name = resource_name("tls", &app.name);
        let mut ingress_annotations = public_ingress_annotations(settings, controller, annotations);
        ingress_annotations.insert(APP_ANNOTATION.to_owned(), app.name.clone());
        let ingress = json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
            "metadata": resource_metadata(
                &name,
                namespace,
                labels,
                &ingress_annotations,
                None
            ),
            "spec": {
                "ingressClassName": settings.ingress_class,
                "tls": [{"hosts": [host], "secretName": tls_name}],
                "rules": [{
                    "host": host,
                    "http": {"paths": [{
                        "path": "/",
                        "pathType": "Prefix",
                        "backend": {"service": {
                            "name": dns_label(&app.service),
                            "port": {"number": app.port}
                        }}
                    }]}
                }]
            }
        });
        resources.push(resource(
            "Ingress",
            &name,
            ResourceRole::Exposure,
            false,
            ingress,
        )?);
        if let Some((middleware_reference, _)) = &traefik_middleware {
            resources.push(render_traefik_redirect_ingress(
                settings,
                app,
                &host,
                namespace,
                labels,
                annotations,
                middleware_reference,
            )?);
        }
        endpoints.push(Endpoint {
            app: app.name.clone(),
            url: format!("https://{host}"),
        });
        let base_url = format!("https://{host}");
        readiness_targets.push(ReadinessTarget {
            app: app.name.clone(),
            probe_url: format!("{base_url}{}", app.health_path.as_deref().unwrap_or("/")),
            base_url,
            expected_status: app.health_status,
        });
    }
    Ok((endpoints, readiness_targets, resources))
}

fn render_traefik_middleware(
    controller: IngressController,
    target: &Value,
    namespace: &str,
    labels: &BTreeMap<String, String>,
    annotations: &BTreeMap<String, String>,
) -> PluginResult<Option<(String, RenderedResource)>> {
    if controller != IngressController::Traefik {
        return Ok(None);
    }
    let api_version = traefik_middleware_api(target)?;
    let name = resource_name("https", "redirect");
    let middleware = resource(
        "Middleware",
        &name,
        ResourceRole::Exposure,
        false,
        json!({
            "apiVersion": api_version,
            "kind": "Middleware",
            "metadata": resource_metadata(&name, namespace, labels, annotations, None),
            "spec": {
                "redirectScheme": {
                    "scheme": "https",
                    "permanent": true
                }
            }
        }),
    )?;
    Ok(Some((
        format!("{namespace}-{name}@kubernetescrd"),
        middleware,
    )))
}

fn public_ingress_annotations(
    settings: &Settings,
    controller: IngressController,
    annotations: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut result = annotations.clone();
    result.insert(
        "cert-manager.io/cluster-issuer".to_owned(),
        settings.cluster_issuer.clone(),
    );
    match controller {
        IngressController::Nginx => {
            result.insert(
                "nginx.ingress.kubernetes.io/ssl-redirect".to_owned(),
                "true".to_owned(),
            );
            result.insert(
                "nginx.ingress.kubernetes.io/force-ssl-redirect".to_owned(),
                "true".to_owned(),
            );
        }
        IngressController::Traefik => {
            result.insert(
                "traefik.ingress.kubernetes.io/router.entrypoints".to_owned(),
                settings.traefik_https_entrypoint.clone(),
            );
            result.insert(
                "traefik.ingress.kubernetes.io/router.tls".to_owned(),
                "true".to_owned(),
            );
        }
    }
    result
}

fn render_traefik_redirect_ingress(
    settings: &Settings,
    app: &AppSpec,
    host: &str,
    namespace: &str,
    labels: &BTreeMap<String, String>,
    annotations: &BTreeMap<String, String>,
    middleware_reference: &str,
) -> PluginResult<RenderedResource> {
    let name = resource_name("redirect", &app.name);
    let mut annotations = annotations.clone();
    annotations.insert(APP_ANNOTATION.to_owned(), app.name.clone());
    annotations.insert(
        "traefik.ingress.kubernetes.io/router.entrypoints".to_owned(),
        settings.traefik_http_entrypoint.clone(),
    );
    annotations.insert(
        "traefik.ingress.kubernetes.io/router.middlewares".to_owned(),
        middleware_reference.to_owned(),
    );
    resource(
        "Ingress",
        &name,
        ResourceRole::Exposure,
        false,
        json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
            "metadata": resource_metadata(&name, namespace, labels, &annotations, None),
            "spec": {
                "ingressClassName": settings.ingress_class,
                "rules": [{
                    "host": host,
                    "http": {"paths": [{
                        "path": "/",
                        "pathType": "Prefix",
                        "backend": {"service": {
                            "name": dns_label(&app.service),
                            "port": {"number": app.port}
                        }}
                    }]}
                }]
            }
        }),
    )
}

pub(crate) fn ingress_ipv4(target: &Value) -> Option<Ipv4Addr> {
    target
        .pointer("/ingress/addresses")
        .or_else(|| target.get("ingress_addresses"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(|address| address.parse::<IpAddr>().ok())
        .find_map(|address| match address {
            IpAddr::V4(address) if is_public_ipv4(address) => Some(address),
            IpAddr::V4(_) | IpAddr::V6(_) => None,
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IngressController {
    Nginx,
    Traefik,
}

pub(crate) fn ingress_controller(target: &Value) -> PluginResult<IngressController> {
    let controller = target
        .pointer("/ingress/controller")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    match controller.as_str() {
        "k8s.io/ingress-nginx" => Ok(IngressController::Nginx),
        "traefik.io/ingress-controller" => Ok(IngressController::Traefik),
        _ => Err(PluginError::permanent(
            ErrorKind::Unsupported,
            "unsupported_ingress_controller",
            "the explicit IngressClass must use `k8s.io/ingress-nginx` or `traefik.io/ingress-controller` so Lightrail can apply the matching redirect contract without editing global controller configuration",
        )),
    }
}

fn traefik_middleware_api(target: &Value) -> PluginResult<&str> {
    match target
        .pointer("/ingress/traefik_middleware_api_version")
        .and_then(Value::as_str)
    {
        Some(version @ ("traefik.io/v1alpha1" | "traefik.containo.us/v1alpha1")) => Ok(version),
        _ => Err(PluginError::permanent(
            ErrorKind::Unavailable,
            "traefik_middleware_crd_missing",
            "the selected Traefik target did not report a supported Middleware CRD API version",
        )),
    }
}

fn app_hostname(
    branch: &str,
    app: &str,
    profile: &str,
    project: &str,
    address: Ipv4Addr,
    domain: &str,
) -> PluginResult<String> {
    let invalid = |message: String| {
        PluginError::permanent(
            ErrorKind::Validation,
            "invalid_application_hostname",
            message,
        )
    };
    let branch = DnsLabel::new(branch).map_err(|error| invalid(error.to_string()))?;
    let app = DnsLabel::new(app).map_err(|error| invalid(error.to_string()))?;
    let profile = DnsLabel::new(profile).map_err(|error| invalid(error.to_string()))?;
    let project = DnsLabel::new(project).map_err(|error| invalid(error.to_string()))?;
    let domain = domain
        .parse::<IpDnsDomain>()
        .map_err(|error| invalid(error.to_string()))?;
    Hostname::new(&branch, &app, &profile, &project, address, domain)
        .map(|hostname| hostname.as_str().to_owned())
        .map_err(|error| invalid(error.to_string()))
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

fn base_labels(desired: &DesiredState, revision: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (MANAGED_LABEL.to_owned(), "lightrail".to_owned()),
        (PROJECT_LABEL.to_owned(), desired.project.id.clone()),
        (ENVIRONMENT_LABEL.to_owned(), desired.environment.id.clone()),
        (
            PROFILE_LABEL.to_owned(),
            dns_label(&desired.environment.profile),
        ),
        (REVISION_LABEL.to_owned(), revision[..16].to_owned()),
    ])
}

fn with_service_label(
    labels: &BTreeMap<String, String>,
    service: &str,
) -> BTreeMap<String, String> {
    let mut labels = labels.clone();
    labels.insert(SERVICE_LABEL.to_owned(), service.to_owned());
    labels
}

fn base_annotations(desired: &DesiredState) -> BTreeMap<String, String> {
    BTreeMap::from([(
        BRANCH_ANNOTATION.to_owned(),
        desired.environment.branch.clone(),
    )])
}

fn resource_metadata(
    name: &str,
    namespace: &str,
    labels: &BTreeMap<String, String>,
    annotations: &BTreeMap<String, String>,
    spec_hash: Option<&str>,
) -> Value {
    let mut annotations = annotations.clone();
    if let Some(spec_hash) = spec_hash {
        annotations.insert(SPEC_HASH_ANNOTATION.to_owned(), spec_hash.to_owned());
    }
    json!({
        "name": name,
        "namespace": namespace,
        "labels": labels,
        "annotations": annotations,
    })
}

fn resource(
    kind: &str,
    name: &str,
    role: ResourceRole,
    sensitive: bool,
    mut manifest: Value,
) -> PluginResult<RenderedResource> {
    let hash_input = if sensitive {
        redacted_secret_shape(&manifest)
    } else {
        manifest.clone()
    };
    let spec_hash = hash_value(&hash_input)?;
    let metadata = manifest
        .get_mut("metadata")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| serialization_error("rendered resource has no metadata"))?;
    let annotations = metadata
        .entry("annotations")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| serialization_error("rendered resource annotations are not an object"))?;
    annotations.insert(
        SPEC_HASH_ANNOTATION.to_owned(),
        Value::String(spec_hash.clone()),
    );
    Ok(RenderedResource {
        key: format!("{kind}/{name}"),
        kind: kind.to_owned(),
        name: name.to_owned(),
        role,
        manifest,
        spec_hash,
    })
}

fn redacted_secret_shape(value: &Value) -> Value {
    let mut value = value.clone();
    if let Some(object) = value.get_mut("stringData").and_then(Value::as_object_mut) {
        for value in object.values_mut() {
            *value = Value::String("[REDACTED]".to_owned());
        }
    }
    value
}

pub(crate) fn manifest_list<'a>(
    resources: impl IntoIterator<Item = &'a RenderedResource>,
) -> PluginResult<Vec<u8>> {
    let items = resources
        .into_iter()
        .map(|resource| resource.manifest.clone())
        .collect::<Vec<_>>();
    serde_json::to_vec(&json!({
        "apiVersion": "v1",
        "kind": "List",
        "items": items,
    }))
    .map_err(serialization_error)
}

pub(crate) fn expiry_unix(ttl_hours: u64) -> PluginResult<u64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            PluginError::permanent(
                ErrorKind::Internal,
                "system_clock_before_epoch",
                format!("system clock cannot produce expiry metadata: {error}"),
            )
        })?
        .as_secs();
    now.checked_add(ttl_hours.saturating_mul(3600))
        .ok_or_else(|| {
            PluginError::permanent(
                ErrorKind::Internal,
                "expiry_overflow",
                "TTL expiry timestamp overflowed",
            )
        })
}

pub(crate) fn namespace_name(prefix: &str, environment_id: &str) -> String {
    let hash = short_hash(environment_id, 12);
    let readable = dns_label(environment_id);
    let available = 63usize.saturating_sub(prefix.len() + hash.len() + 2);
    let readable = readable
        .chars()
        .take(available)
        .collect::<String>()
        .trim_matches('-')
        .to_owned();
    if readable.is_empty() {
        format!("{prefix}-{hash}")
    } else {
        format!("{prefix}-{readable}-{hash}")
    }
}

pub(crate) fn resource_name(prefix: &str, source: &str) -> String {
    let readable = dns_label(source);
    let hash = short_hash(source, 8);
    let available = 63usize.saturating_sub(prefix.len() + hash.len() + 2);
    let readable = readable
        .chars()
        .take(available)
        .collect::<String>()
        .trim_matches('-')
        .to_owned();
    format!("{prefix}-{readable}-{hash}")
}

pub(crate) fn dns_label(source: &str) -> String {
    let mut output = String::new();
    let mut dash = false;
    for character in source.chars().flat_map(char::to_lowercase) {
        if character.is_ascii_alphanumeric() {
            output.push(character);
            dash = false;
        } else if !dash && !output.is_empty() {
            output.push('-');
            dash = true;
        }
    }
    let output = output.trim_matches('-');
    if output.is_empty() {
        format!("x-{}", short_hash(source, 8))
    } else if output.len() <= 63 && output == source {
        output.to_owned()
    } else {
        let hash = short_hash(source, 8);
        let available = 63usize.saturating_sub(hash.len() + 1);
        format!(
            "{}-{hash}",
            output
                .chars()
                .take(available)
                .collect::<String>()
                .trim_matches('-')
        )
    }
}

pub(crate) fn short_hash(value: &str, length: usize) -> String {
    let digest = Sha256::digest(value.as_bytes());
    hex::encode(digest)[..length].to_owned()
}

pub(crate) fn hash_value(value: &Value) -> PluginResult<String> {
    let bytes = serde_json::to_vec(value).map_err(serialization_error)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn serialization_error(error: impl std::fmt::Display) -> PluginError {
    PluginError::permanent(
        ErrorKind::Internal,
        "serialization_failed",
        format!("failed to serialize Kubernetes model: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use lightrail_plugin_protocol::OperationContext;
    use tempfile::tempdir;

    fn desired(root: &Path, compose: &Path) -> DesiredState {
        DesiredState {
            schema: 1,
            project: ProjectSpec {
                id: "018f6f9f-21aa-7da8-a1b2-31da91ed5148".to_owned(),
                slug: "demo".to_owned(),
                root: Some(root.to_path_buf()),
                compose: vec![PathBuf::from("compose.yaml")],
            },
            environment: EnvironmentSpec {
                id: "lr-58ce76e3c31e120f98bb2140".to_owned(),
                profile: "preview".to_owned(),
                branch: "feature/login".to_owned(),
                commit: Some("aabbcc".to_owned()),
                dirty: false,
                isolation: Isolation::Environment,
                labels: BTreeMap::new(),
            },
            resolved_compose_path: Some(compose.to_path_buf()),
            apps: vec![AppSpec {
                name: "api".to_owned(),
                service: "web".to_owned(),
                port: 8080,
                health_path: Some("/health".to_owned()),
                health_status: Some(200),
                environment: BTreeMap::new(),
            }],
            target: Value::Null,
            destroy: false,
        }
    }

    fn test_settings() -> Settings {
        Settings {
            context: "spot".to_owned(),
            registry: "ghcr.io".to_owned(),
            repository: "team/lightrail".to_owned(),
            ingress_class: "traefik".to_owned(),
            cluster_issuer: "letsencrypt".to_owned(),
            ..Settings::default()
        }
    }

    fn test_metadata(desired: &DesiredState) -> ContextMetadata {
        ContextMetadata {
            capability: Capability::Runtime,
            operation: Operation::Up,
            all: false,
            project_id: desired.project.id.clone(),
            project_slug: desired.project.slug.clone(),
            target: json!({
                "ingress": {
                    "controller": "traefik.io/ingress-controller",
                    "addresses": ["8.8.8.8"],
                    "traefik_middleware_api_version": "traefik.io/v1alpha1"
                }
            }),
            selection: Selection::default(),
        }
    }

    fn compose_project(document: Value) -> ComposeProject {
        let services = document["services"]
            .as_object()
            .expect("test Compose services")
            .iter()
            .map(|(name, raw)| (name.clone(), ComposeService { raw: raw.clone() }))
            .collect();
        ComposeProject { document, services }
    }

    fn operation_context(desired: &DesiredState, operation_id: &str) -> OperationContext {
        OperationContext {
            operation_id: operation_id.to_owned(),
            environment_id: desired.environment.id.clone(),
            project_root: desired
                .project
                .root
                .as_ref()
                .map(|root| root.display().to_string()),
            ..OperationContext::default()
        }
    }

    fn workload_resource<'a>(
        rendered: &'a RenderedEnvironment,
        service: &str,
    ) -> &'a RenderedResource {
        let name = resource_name("workload", service);
        rendered
            .resources
            .iter()
            .find(|resource| {
                resource.name == name
                    && matches!(resource.kind.as_str(), "Deployment" | "StatefulSet" | "Job")
            })
            .unwrap_or_else(|| panic!("missing rendered workload {name}"))
    }

    fn workload_hash<'a>(rendered: &'a RenderedEnvironment, service: &str) -> &'a str {
        workload_resource(rendered, service).spec_hash.as_str()
    }

    fn exposure_hashes(rendered: &RenderedEnvironment) -> BTreeMap<String, String> {
        rendered
            .resources
            .iter()
            .filter(|resource| resource.role == ResourceRole::Exposure)
            .map(|resource| (resource.key.clone(), resource.spec_hash.clone()))
            .collect()
    }

    #[test]
    fn namespace_is_stable_and_bounded() {
        let first = namespace_name(
            "lr",
            "lr-a-very-long-environment-name-with-many-branch-components-and-identity",
        );
        let second = namespace_name(
            "lr",
            "lr-a-very-long-environment-name-with-many-branch-components-and-identity",
        );
        assert_eq!(first, second);
        assert!(first.len() <= 63);
        assert!(first.starts_with("lr-"));
    }

    #[test]
    fn hostname_is_branch_then_app_and_uses_hex_ip() {
        let settings = Settings {
            context: "spot".to_owned(),
            registry: "ghcr.io".to_owned(),
            repository: "team/lightrail".to_owned(),
            ingress_class: "nginx".to_owned(),
            cluster_issuer: "letsencrypt".to_owned(),
            ..Settings::default()
        };
        let directory = tempdir().expect("tempdir");
        let compose_path = directory.path().join("resolved.json");
        let desired = desired(directory.path(), &compose_path);
        let compose = ComposeProject {
            document: json!({}),
            services: BTreeMap::from([(
                "web".to_owned(),
                ComposeService {
                    raw: json!({"image": "example/web:1", "expose": [8080]}),
                },
            )]),
        };
        let metadata = ContextMetadata {
            capability: Capability::Exposure,
            operation: Operation::Up,
            all: false,
            project_id: desired.project.id.clone(),
            project_slug: desired.project.slug.clone(),
            target: json!({
                "ingress": {
                    "controller": "k8s.io/ingress-nginx",
                    "addresses": ["8.8.8.8"]
                }
            }),
            selection: Selection::default(),
        };
        let rendered = render_environment(
            &settings,
            &desired,
            &compose,
            &OperationContext {
                environment_id: desired.environment.id.clone(),
                ..OperationContext::default()
            },
            &metadata,
            &"a".repeat(64),
            false,
        )
        .expect("render");
        assert_eq!(
            rendered.endpoints[0].url,
            "https://feature-login-df7c7aeb.api.preview.demo.08080808.sslip.io"
        );
        assert_eq!(
            rendered.readiness_targets,
            vec![ReadinessTarget {
                app: "api".to_owned(),
                base_url: "https://feature-login-df7c7aeb.api.preview.demo.08080808.sslip.io"
                    .to_owned(),
                probe_url:
                    "https://feature-login-df7c7aeb.api.preview.demo.08080808.sslip.io/health"
                        .to_owned(),
                expected_status: Some(200),
            }]
        );
        let ingress = rendered
            .resources
            .iter()
            .find(|resource| resource.kind == "Ingress")
            .expect("ingress");
        assert_eq!(
            ingress.manifest["metadata"]["annotations"]["nginx.ingress.kubernetes.io/force-ssl-redirect"],
            "true"
        );
        assert_eq!(
            ingress.manifest["metadata"]["annotations"][APP_ANNOTATION],
            "api"
        );
        assert!(rendered.resources.iter().all(|resource| {
            !resource
                .manifest
                .to_string()
                .contains(EXPIRES_AT_ANNOTATION)
        }));
    }

    #[test]
    fn multiple_apps_have_independent_base_urls_and_health_targets() {
        let settings = Settings {
            context: "spot".to_owned(),
            registry: "ghcr.io".to_owned(),
            repository: "team/lightrail".to_owned(),
            ingress_class: "nginx".to_owned(),
            cluster_issuer: "letsencrypt".to_owned(),
            ..Settings::default()
        };
        let directory = tempdir().expect("tempdir");
        let compose_path = directory.path().join("resolved.json");
        let mut desired = desired(directory.path(), &compose_path);
        desired.apps.push(AppSpec {
            name: "admin".to_owned(),
            service: "admin".to_owned(),
            port: 9090,
            health_path: None,
            health_status: None,
            environment: BTreeMap::new(),
        });
        let compose = ComposeProject {
            document: json!({}),
            services: BTreeMap::from([
                (
                    "web".to_owned(),
                    ComposeService {
                        raw: json!({"image": "example/web:1", "expose": [8080]}),
                    },
                ),
                (
                    "admin".to_owned(),
                    ComposeService {
                        raw: json!({"image": "example/admin:1", "expose": [9090]}),
                    },
                ),
            ]),
        };
        let metadata = ContextMetadata {
            capability: Capability::Exposure,
            operation: Operation::Up,
            all: false,
            project_id: desired.project.id.clone(),
            project_slug: desired.project.slug.clone(),
            target: json!({
                "ingress": {
                    "controller": "k8s.io/ingress-nginx",
                    "addresses": ["8.8.8.8"]
                }
            }),
            selection: Selection::default(),
        };
        let rendered = render_environment(
            &settings,
            &desired,
            &compose,
            &OperationContext {
                environment_id: desired.environment.id.clone(),
                ..OperationContext::default()
            },
            &metadata,
            &"d".repeat(64),
            false,
        )
        .expect("render");
        assert_eq!(rendered.endpoints.len(), 2);
        assert_eq!(rendered.readiness_targets.len(), 2);
        let api = rendered
            .readiness_targets
            .iter()
            .find(|target| target.app == "api")
            .expect("api target");
        assert!(api.probe_url.ends_with("/health"));
        assert_eq!(api.expected_status, Some(200));
        let admin = rendered
            .readiness_targets
            .iter()
            .find(|target| target.app == "admin")
            .expect("admin target");
        assert!(admin.probe_url.ends_with('/'));
        assert_eq!(admin.expected_status, None);
        assert!(
            rendered
                .endpoints
                .iter()
                .all(|endpoint| !endpoint.url.ends_with("/health"))
        );
    }

    #[test]
    fn exposure_render_never_resolves_application_secrets() {
        let settings = Settings {
            context: "spot".to_owned(),
            registry: "ghcr.io".to_owned(),
            repository: "team/lightrail".to_owned(),
            ingress_class: "nginx".to_owned(),
            cluster_issuer: "letsencrypt".to_owned(),
            ..Settings::default()
        };
        let directory = tempdir().expect("tempdir");
        let compose_path = directory.path().join("resolved.json");
        let mut desired = desired(directory.path(), &compose_path);
        desired.apps[0].environment.insert(
            "TOKEN".to_owned(),
            EnvironmentInput::Secret {
                secret: "missing-from-exposure".to_owned(),
            },
        );
        let compose = ComposeProject {
            document: json!({}),
            services: BTreeMap::from([(
                "web".to_owned(),
                ComposeService {
                    raw: json!({"image": "example/web:1", "expose": [8080]}),
                },
            )]),
        };
        let metadata = ContextMetadata {
            capability: Capability::Exposure,
            operation: Operation::Up,
            all: false,
            project_id: desired.project.id.clone(),
            project_slug: desired.project.slug.clone(),
            target: json!({
                "ingress": {
                    "controller": "k8s.io/ingress-nginx",
                    "addresses": ["8.8.8.8"]
                }
            }),
            selection: Selection::default(),
        };
        let rendered = render_environment(
            &settings,
            &desired,
            &compose,
            &OperationContext {
                environment_id: desired.environment.id.clone(),
                ..OperationContext::default()
            },
            &metadata,
            &"e".repeat(64),
            false,
        )
        .expect("exposure render must not need Runtime secrets");
        let secret = rendered
            .resources
            .iter()
            .find(|resource| resource.kind == "Secret")
            .expect("redacted model secret");
        assert_eq!(secret.manifest["stringData"]["TOKEN"], "[REDACTED]");
    }

    #[test]
    fn secret_hash_does_not_depend_on_plaintext() {
        let first = resource(
            "Secret",
            "env-api",
            ResourceRole::Runtime,
            true,
            json!({
                "metadata": {"name": "env-api", "annotations": {}},
                "stringData": {"TOKEN": "first"}
            }),
        )
        .expect("first");
        let second = resource(
            "Secret",
            "env-api",
            ResourceRole::Runtime,
            true,
            json!({
                "metadata": {"name": "env-api", "annotations": {}},
                "stringData": {"TOKEN": "second"}
            }),
        )
        .expect("second");
        assert_eq!(first.spec_hash, second.spec_hash);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn environment_rollout_revision_is_operation_scoped_and_secret_safe() {
        let directory = tempdir().expect("tempdir");
        let compose_path = directory.path().join("resolved.json");
        let mut desired = desired(directory.path(), &compose_path);
        desired.apps[0].environment.insert(
            "TOKEN".to_owned(),
            EnvironmentInput::Secret {
                secret: "api-token".to_owned(),
            },
        );
        let compose = ComposeProject {
            document: json!({}),
            services: BTreeMap::from([
                (
                    "web".to_owned(),
                    ComposeService {
                        raw: json!({"image": "example/web:1", "expose": [8080]}),
                    },
                ),
                (
                    "db".to_owned(),
                    ComposeService {
                        raw: json!({
                            "image": "example/db:1",
                            "environment": {"MODE": "preview"},
                            "x-lightrail": {"kind": "stateful"}
                        }),
                    },
                ),
                (
                    "migrate".to_owned(),
                    ComposeService {
                        raw: json!({
                            "image": "example/migrate:1",
                            "environment": {"MODE": "preview"},
                            "x-lightrail": {"kind": "job"}
                        }),
                    },
                ),
            ]),
        };
        let context = |operation_id: &str, plaintext: &str| OperationContext {
            operation_id: operation_id.to_owned(),
            environment_id: desired.environment.id.clone(),
            secrets: BTreeMap::from([("api-token".to_owned(), SecretValue::new(plaintext))]),
            ..OperationContext::default()
        };
        let settings = test_settings();
        let metadata = test_metadata(&desired);
        let first = render_environment(
            &settings,
            &desired,
            &compose,
            &context("operation-a", "first-private-value"),
            &metadata,
            &"a".repeat(64),
            true,
        )
        .expect("first render");
        let rotated = render_environment(
            &settings,
            &desired,
            &compose,
            &context("operation-a", "second-private-value"),
            &metadata,
            &"a".repeat(64),
            true,
        )
        .expect("rotated render");
        let next_operation = render_environment(
            &settings,
            &desired,
            &compose,
            &context("operation-b", "second-private-value"),
            &metadata,
            &"a".repeat(64),
            true,
        )
        .expect("next operation render");

        let hashes = |rendered: &RenderedEnvironment| {
            rendered
                .resources
                .iter()
                .map(|resource| (resource.key.clone(), resource.spec_hash.clone()))
                .collect::<BTreeMap<_, _>>()
        };
        assert_eq!(hashes(&first), hashes(&rotated));
        assert_ne!(
            workload_hash(&rotated, "web"),
            workload_hash(&next_operation, "web")
        );
        assert_ne!(
            workload_hash(&rotated, "db"),
            workload_hash(&next_operation, "db")
        );
        assert_eq!(
            workload_hash(&rotated, "migrate"),
            workload_hash(&next_operation, "migrate")
        );
        for service in ["web", "db"] {
            assert_eq!(
                workload_resource(&first, service).manifest["spec"]["template"]["metadata"]["annotations"]
                    [RUNTIME_CONFIG_REVISION_ANNOTATION],
                runtime_config_revision("operation-a")
            );
        }
        assert!(
            workload_resource(&first, "migrate").manifest["spec"]["template"]["metadata"]
                ["annotations"]
                .get(RUNTIME_CONFIG_REVISION_ANNOTATION)
                .is_none()
        );

        let plan = render_environment(
            &settings,
            &desired,
            &compose,
            &context("operation-a", "first-private-value"),
            &metadata,
            &"a".repeat(64),
            false,
        )
        .expect("redacted plan render");
        let plan_json = serde_json::to_string(
            &plan
                .resources
                .iter()
                .map(|resource| &resource.manifest)
                .collect::<Vec<_>>(),
        )
        .expect("serialize plan manifests");
        assert!(!plan_json.contains("first-private-value"));
        assert!(!plan_json.contains("second-private-value"));
        assert!(plan_json.contains("[REDACTED]"));
    }

    #[test]
    fn explicit_platforms_constrain_workload_scheduling() {
        let directory = tempdir().expect("tempdir");
        let compose_path = directory.path().join("resolved.json");
        let desired = desired(directory.path(), &compose_path);
        let compose = ComposeProject {
            document: json!({}),
            services: BTreeMap::from([(
                "web".to_owned(),
                ComposeService {
                    raw: json!({"image": "example/web:1", "expose": [8080]}),
                },
            )]),
        };
        let context = OperationContext {
            operation_id: "platform-test".to_owned(),
            environment_id: desired.environment.id.clone(),
            ..OperationContext::default()
        };
        let metadata = test_metadata(&desired);
        let render = |platforms: Vec<&str>| {
            let mut settings = test_settings();
            settings.platforms = platforms.into_iter().map(ToOwned::to_owned).collect();
            render_environment(
                &settings,
                &desired,
                &compose,
                &context,
                &metadata,
                &"b".repeat(64),
                false,
            )
            .expect("render")
        };

        let discovered = render(Vec::new());
        let discovered_spec =
            &workload_resource(&discovered, "web").manifest["spec"]["template"]["spec"];
        assert!(discovered_spec.get("nodeSelector").is_none());
        assert!(discovered_spec.get("affinity").is_none());

        let single = render(vec!["linux/arm64"]);
        let single_spec = &workload_resource(&single, "web").manifest["spec"]["template"]["spec"];
        assert_eq!(single_spec["nodeSelector"]["kubernetes.io/arch"], "arm64");
        assert!(single_spec.get("affinity").is_none());

        let multiple = render(vec!["linux/arm64", "linux/amd64"]);
        let multiple_spec =
            &workload_resource(&multiple, "web").manifest["spec"]["template"]["spec"];
        assert!(multiple_spec.get("nodeSelector").is_none());
        assert_eq!(
            multiple_spec["affinity"]["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]
                ["nodeSelectorTerms"][0]["matchExpressions"][0],
            json!({
                "key": "kubernetes.io/arch",
                "operator": "In",
                "values": ["amd64", "arm64"]
            })
        );
    }

    #[test]
    fn private_portless_service_gets_selector_backed_headless_dns() {
        let directory = tempdir().expect("tempdir");
        let compose_path = directory.path().join("resolved.json");
        let mut desired = desired(directory.path(), &compose_path);
        desired.apps.clear();
        let compose = ComposeProject {
            document: json!({}),
            services: BTreeMap::from([(
                "db".to_owned(),
                ComposeService {
                    raw: json!({"image": "postgres:17"}),
                },
            )]),
        };
        let rendered = render_environment(
            &test_settings(),
            &desired,
            &compose,
            &OperationContext {
                operation_id: "portless-service".to_owned(),
                environment_id: desired.environment.id.clone(),
                ..OperationContext::default()
            },
            &test_metadata(&desired),
            &"c".repeat(64),
            false,
        )
        .expect("render");
        let service = rendered
            .resources
            .iter()
            .find(|resource| resource.kind == "Service" && resource.name == "db")
            .expect("private db Service");
        assert_eq!(service.manifest["spec"]["clusterIP"], "None");
        assert_eq!(
            service.manifest["spec"]["selector"],
            json!({
                ENVIRONMENT_LABEL: desired.environment.id,
                SERVICE_LABEL: "db"
            })
        );
        assert!(service.manifest["spec"].get("ports").is_none());
        assert!(
            workload_resource(&rendered, "db").manifest["spec"]["template"]["spec"]["containers"]
                [0]
            .get("ports")
            .is_none()
        );
    }

    #[test]
    fn completed_jobs_persist_without_a_ttl_or_service() {
        let directory = tempdir().expect("tempdir");
        let compose_path = directory.path().join("resolved.json");
        let mut desired = desired(directory.path(), &compose_path);
        desired.apps.clear();
        let compose = ComposeProject {
            document: json!({}),
            services: BTreeMap::from([(
                "migrate".to_owned(),
                ComposeService {
                    raw: json!({
                        "image": "example/migrate:1",
                        "x-lightrail": {"kind": "job"}
                    }),
                },
            )]),
        };
        let rendered = render_environment(
            &test_settings(),
            &desired,
            &compose,
            &OperationContext {
                operation_id: "persistent-job".to_owned(),
                environment_id: desired.environment.id.clone(),
                ..OperationContext::default()
            },
            &test_metadata(&desired),
            &"d".repeat(64),
            false,
        )
        .expect("render");
        let job = workload_resource(&rendered, "migrate");
        assert_eq!(job.kind, "Job");
        assert!(
            job.manifest["spec"]
                .get("ttlSecondsAfterFinished")
                .is_none()
        );
        assert!(
            rendered
                .resources
                .iter()
                .all(|resource| resource.kind != "Service")
        );
    }

    #[test]
    fn namespace_records_the_control_namespace_lock_authority() {
        let directory = tempdir().expect("tempdir");
        let compose_path = directory.path().join("resolved.json");
        let mut desired = desired(directory.path(), &compose_path);
        desired.apps.clear();
        let compose = ComposeProject {
            document: json!({}),
            services: BTreeMap::new(),
        };
        let mut settings = test_settings();
        settings.control_namespace = "preview-locks".to_owned();
        let rendered = render_environment(
            &settings,
            &desired,
            &compose,
            &OperationContext {
                operation_id: "namespace-authority".to_owned(),
                environment_id: desired.environment.id.clone(),
                ..OperationContext::default()
            },
            &test_metadata(&desired),
            &"e".repeat(64),
            false,
        )
        .expect("render");
        let namespace = rendered
            .resources
            .iter()
            .find(|resource| resource.kind == "Namespace")
            .expect("Namespace");
        assert_eq!(
            namespace.manifest["metadata"]["annotations"][CONTROL_NAMESPACE_ANNOTATION],
            "preview-locks"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn clean_revision_is_portable_across_equivalent_checkout_roots() {
        let sandbox = tempdir().expect("tempdir");
        let first_root = sandbox.path().join("first-checkout");
        let second_root = sandbox.path().join("different-directory");
        for root in [&first_root, &second_root] {
            let context = root.join("apps/web");
            std::fs::create_dir_all(&context).expect("build context");
            std::fs::write(context.join("Dockerfile"), "FROM scratch\n").expect("test Dockerfile");
        }

        let document = |root: &Path, project_name: &str, absolute_dockerfile: bool| {
            let context = root.join("apps/web");
            let dockerfile = if absolute_dockerfile {
                context.join("Dockerfile")
            } else {
                PathBuf::from("Dockerfile")
            };
            json!({
                "name": project_name,
                "networks": {
                    "default": {
                        "name": format!("{project_name}_default"),
                        "ipam": {}
                    }
                },
                "volumes": {
                    "data": {"name": format!("{project_name}_data")}
                },
                "services": {
                    "web": {
                        "build": {
                            "context": context,
                            "dockerfile": dockerfile,
                            "args": {"PROFILE": "release"}
                        },
                        "expose": [8080],
                        "networks": {"default": null},
                        "volumes": ["data:/var/lib/data"]
                    }
                }
            })
        };
        let first_compose = compose_project(document(&first_root, "first-checkout", true));
        let second_compose = compose_project(document(&second_root, "different-directory", false));
        let first_desired = desired(&first_root, &sandbox.path().join("first-resolved.json"));
        let second_desired = desired(&second_root, &sandbox.path().join("second-resolved.json"));
        let first_context = operation_context(&first_desired, "operation");
        let second_context = operation_context(&second_desired, "operation");
        let platforms = ["linux/amd64".to_owned()];

        let first_revision = revision(
            &first_desired,
            &first_compose,
            &platforms,
            &first_context,
            "operation",
        )
        .expect("first");
        let second_revision = revision(
            &second_desired,
            &second_compose,
            &platforms,
            &second_context,
            "operation",
        )
        .expect("second");
        assert_eq!(first_revision, second_revision);

        let mut changed = document(&second_root, "different-directory", false);
        changed["services"]["web"]["build"]["args"]["PROFILE"] = Value::String("debug".to_owned());
        assert_ne!(
            first_revision,
            revision(
                &second_desired,
                &compose_project(changed),
                &platforms,
                &second_context,
                "operation"
            )
            .expect("semantic build change")
        );
    }

    #[test]
    fn runtime_environment_plaintext_does_not_enter_revision_metadata() {
        let directory = tempdir().expect("tempdir");
        let desired = desired(directory.path(), &directory.path().join("resolved.json"));
        let compose = |name: &str, value: &str| {
            let environment = BTreeMap::from([(name, value)]);
            compose_project(json!({
                "services": {
                    "web": {
                        "image": "example/web:1",
                        "environment": environment
                    }
                }
            }))
        };
        let context = operation_context(&desired, "same-operation");
        let first = revision(
            &desired,
            &compose("TOKEN", "first-secret"),
            &[],
            &context,
            "same-operation",
        )
        .expect("first revision");
        let changed_value = revision(
            &desired,
            &compose("TOKEN", "different-secret"),
            &[],
            &context,
            "same-operation",
        )
        .expect("changed value");
        assert_eq!(first, changed_value);
        assert_eq!(
            base_labels(&desired, &first)[REVISION_LABEL],
            base_labels(&desired, &changed_value)[REVISION_LABEL]
        );
        assert_ne!(
            first,
            revision(
                &desired,
                &compose("OTHER_TOKEN", "first-secret"),
                &[],
                &context,
                "same-operation",
            )
            .expect("changed environment shape")
        );
    }

    #[test]
    fn every_local_build_revision_is_operation_scoped() {
        let directory = tempdir().expect("tempdir");
        let desired = desired(directory.path(), &directory.path().join("resolved.json"));
        let compose = compose_project(json!({
            "services": {"web": {"build": {"context": directory.path()}}}
        }));
        let context = operation_context(&desired, "operation-a");
        let first = revision(
            &desired,
            &compose,
            &["linux/amd64".to_owned()],
            &context,
            "operation-a",
        )
        .expect("first operation");
        let second = revision(
            &desired,
            &compose,
            &["linux/amd64".to_owned()],
            &context,
            "operation-b",
        )
        .expect("second operation");
        assert_ne!(first, second);
    }

    #[test]
    fn existing_local_build_job_gets_a_new_immutable_spec_each_operation() {
        let directory = tempdir().expect("tempdir");
        let mut desired = desired(directory.path(), &directory.path().join("resolved.json"));
        desired.apps.clear();
        let service = json!({
            "build": {"context": directory.path()},
            "x-lightrail": {"kind": "job"}
        });
        let compose = compose_project(json!({"services": {"migrate": service}}));
        let first_context = operation_context(&desired, "operation-a");
        let second_context = operation_context(&desired, "operation-b");
        let platforms = ["linux/amd64".to_owned()];
        let first_revision = revision(
            &desired,
            &compose,
            &platforms,
            &first_context,
            "operation-a",
        )
        .expect("first revision");
        let second_revision = revision(
            &desired,
            &compose,
            &platforms,
            &second_context,
            "operation-b",
        )
        .expect("second revision");
        let metadata = test_metadata(&desired);
        let first = render_environment(
            &test_settings(),
            &desired,
            &compose,
            &first_context,
            &metadata,
            &first_revision,
            false,
        )
        .expect("first Job");
        let second = render_environment(
            &test_settings(),
            &desired,
            &compose,
            &second_context,
            &metadata,
            &second_revision,
            false,
        )
        .expect("second Job");
        assert_ne!(
            workload_hash(&first, "migrate"),
            workload_hash(&second, "migrate"),
            "the immutable Job guard must require down then up"
        );
    }

    #[cfg(unix)]
    #[test]
    fn revision_rejects_build_context_and_dockerfile_symlink_escape() {
        use std::os::unix::fs::symlink;

        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("project");
        let outside = sandbox.path().join("outside");
        std::fs::create_dir_all(&root).expect("project");
        std::fs::create_dir_all(&outside).expect("outside");
        std::fs::write(outside.join("Dockerfile"), "FROM scratch\n").expect("outside Dockerfile");
        let desired = desired(&root, &sandbox.path().join("resolved.json"));
        let context = operation_context(&desired, "operation");
        let compose_with_build = |build: Value| {
            compose_project(json!({
                "name": "project",
                "services": {"web": {"build": build, "expose": [8080]}}
            }))
        };

        symlink(&outside, root.join("escaped-context")).expect("context symlink");
        let context_error = revision(
            &desired,
            &compose_with_build(json!({"context": root.join("escaped-context")})),
            &["linux/amd64".to_owned()],
            &context,
            "operation",
        )
        .expect_err("symlinked build context outside the project must fail");
        assert_eq!(context_error.code, "build_context_outside_project");

        let inside = root.join("inside");
        std::fs::create_dir_all(&inside).expect("inside context");
        symlink(outside.join("Dockerfile"), inside.join("Dockerfile")).expect("Dockerfile symlink");
        let dockerfile_error = revision(
            &desired,
            &compose_with_build(json!({
                "context": inside,
                "dockerfile": "Dockerfile"
            })),
            &["linux/amd64".to_owned()],
            &context,
            "operation",
        )
        .expect_err("symlinked Dockerfile outside the project must fail");
        assert_eq!(dockerfile_error.code, "build_context_outside_project");
    }

    #[tokio::test]
    async fn compose_load_rejects_non_object_services_without_panicking() {
        let directory = tempdir().expect("tempdir");
        let compose_path = directory.path().join("resolved.json");
        std::fs::write(
            &compose_path,
            serde_json::to_vec(&json!({"services": {"web": "not-an-object"}})).expect("serialize"),
        )
        .expect("resolved Compose");
        let desired = desired(directory.path(), &compose_path);
        let error = ComposeProject::load(&desired)
            .await
            .expect_err("malformed service must fail closed");
        assert_eq!(error.code, "invalid_compose_service");
    }

    #[test]
    fn desired_project_root_cannot_replace_context_source_authority() {
        let sandbox = tempdir().expect("tempdir");
        let claimed = sandbox.path().join("claimed");
        let granted = sandbox.path().join("granted");
        std::fs::create_dir_all(&claimed).expect("claimed root");
        std::fs::create_dir_all(&granted).expect("granted root");
        let desired = desired(&claimed, &sandbox.path().join("resolved.json"));
        let compose = compose_project(json!({
            "services": {"web": {"build": {"context": claimed}}}
        }));
        let context = OperationContext {
            project_root: Some(granted.display().to_string()),
            ..operation_context(&desired, "operation")
        };
        let error = revision(
            &desired,
            &compose,
            &["linux/amd64".to_owned()],
            &context,
            "operation",
        )
        .expect_err("desired root must not expand the granted source boundary");
        assert_eq!(error.code, "project_root_authority_mismatch");
    }

    #[test]
    fn compose_validation_accepts_only_normalized_implicit_network_and_volumes() {
        let directory = tempdir().expect("tempdir");
        let desired = desired(directory.path(), &directory.path().join("resolved.json"));
        let compose = compose_project(json!({
            "name": "demo",
            "networks": {
                "default": {"name": "demo_default", "ipam": {}}
            },
            "volumes": {
                "data": {"name": "demo_data"}
            },
            "services": {
                "web": {
                    "image": "example/web:1",
                    "expose": [8080],
                    "networks": {"default": null},
                    "volumes": ["data:/var/lib/data"]
                }
            }
        }));
        compose
            .validate(&desired)
            .expect("ordinary Compose normalization is supported");
    }

    #[test]
    fn compose_validation_rejects_untranslated_service_and_build_fields() {
        let directory = tempdir().expect("tempdir");
        let desired = desired(directory.path(), &directory.path().join("resolved.json"));
        for (field, value) in [
            ("deploy", json!({"replicas": 2})),
            ("restart", json!("always")),
            ("user", json!("1000")),
            ("labels", json!({"example": "value"})),
            ("security_opt", json!(["no-new-privileges"])),
        ] {
            let mut service = json!({"image": "example/web:1"});
            service[field] = value;
            let compose = compose_project(json!({"services": {"web": service}}));
            let error = compose
                .validate(&desired)
                .expect_err("untranslated service semantics must fail");
            assert_eq!(error.code, "unsupported_compose_service", "{field}");
        }
        let unsupported_build = compose_project(json!({
            "services": {
                "web": {
                    "build": {"context": ".", "target": "release"}
                }
            }
        }));
        let error = unsupported_build
            .validate(&desired)
            .expect_err("untranslated build semantics must fail");
        assert_eq!(error.code, "unsupported_compose_service");
    }

    #[test]
    fn compose_validation_rejects_custom_network_semantics() {
        let directory = tempdir().expect("tempdir");
        let desired = desired(directory.path(), &directory.path().join("resolved.json"));
        for networks in [
            json!({"backend": null}),
            json!({"default": null, "backend": null}),
            json!({"default": {"aliases": ["api"]}}),
            json!({"default": {"ipv4_address": "10.0.0.2"}}),
        ] {
            let compose = compose_project(json!({
                "name": "demo",
                "networks": {"default": {"name": "demo_default", "ipam": {}}},
                "services": {
                    "web": {
                        "image": "example/web:1",
                        "networks": networks
                    }
                }
            }));
            let error = compose
                .validate(&desired)
                .expect_err("custom service network semantics must fail");
            assert_eq!(error.code, "unsupported_compose_service");
        }
        for network in [
            json!({"default": {"name": "custom", "ipam": {}}}),
            json!({"default": {"name": "demo_default", "external": true}}),
            json!({"default": {"name": "demo_default", "driver": "bridge"}}),
            json!({
                "default": {"name": "demo_default", "ipam": {}},
                "backend": {"name": "demo_backend", "ipam": {}}
            }),
        ] {
            let compose = compose_project(json!({
                "name": "demo",
                "networks": network,
                "services": {"web": {"image": "example/web:1"}}
            }));
            assert!(
                compose.validate(&desired).is_err(),
                "custom top-level network semantics must fail"
            );
        }
    }

    #[test]
    fn compose_validation_rejects_unowned_volume_and_resource_declarations() {
        let directory = tempdir().expect("tempdir");
        let desired = desired(directory.path(), &directory.path().join("resolved.json"));
        for volume in [
            json!({"name": "demo_data", "external": true}),
            json!({"name": "custom"}),
            json!({"name": "demo_data", "driver": "local"}),
            json!({"name": "demo_data", "driver_opts": {"type": "nfs"}}),
        ] {
            let compose = compose_project(json!({
                "name": "demo",
                "volumes": {"data": volume},
                "services": {"web": {"image": "example/web:1"}}
            }));
            assert!(
                compose.validate(&desired).is_err(),
                "unowned or custom volume semantics must fail"
            );
        }
        for field in ["configs", "secrets"] {
            let mut document = json!({"services": {"web": {"image": "example/web:1"}}});
            document[field] = json!({"shared": {"file": "./value"}});
            let error = compose_project(document)
                .validate(&desired)
                .expect_err("top-level resource declarations must fail");
            assert_eq!(error.code, "compose_top_level_resource_unsupported");
        }
    }

    #[test]
    fn build_tags_are_registry_scoped_and_revision_scoped() {
        let directory = tempdir().expect("tempdir");
        let compose_path = directory.path().join("resolved.json");
        let desired = desired(directory.path(), &compose_path);
        let compose = ComposeProject {
            document: json!({}),
            services: BTreeMap::from([(
                "web".to_owned(),
                ComposeService {
                    raw: json!({"build": {"context": "."}}),
                },
            )]),
        };
        let settings = Settings {
            context: "spot".to_owned(),
            registry: "registry.example.com".to_owned(),
            repository: "team/previews".to_owned(),
            ingress_class: "nginx".to_owned(),
            cluster_issuer: "letsencrypt".to_owned(),
            ..Settings::default()
        };
        let builds = build_specs(
            &settings,
            &desired,
            &compose,
            &operation_context(&desired, "build"),
            &"b".repeat(64),
        )
        .expect("build specs");
        assert_eq!(
            builds[0].image,
            "registry.example.com/team/previews/demo/web:bbbbbbbbbbbbbbbb"
        );
    }

    #[test]
    fn build_platform_change_moves_image_tag_and_workload_spec() {
        let directory = tempdir().expect("tempdir");
        let compose_path = directory.path().join("resolved.json");
        let desired = desired(directory.path(), &compose_path);
        let service = json!({"build": {"context": "."}, "expose": [8080]});
        let compose = ComposeProject {
            document: json!({"services": {"web": service.clone()}}),
            services: BTreeMap::from([("web".to_owned(), ComposeService { raw: service })]),
        };
        let amd64 = vec!["linux/amd64".to_owned()];
        let arm64 = vec!["linux/arm64".to_owned()];
        let context = operation_context(&desired, "same-operation");
        let amd64_revision = revision(&desired, &compose, &amd64, &context, "same-operation")
            .expect("amd64 revision");
        let arm64_revision = revision(&desired, &compose, &arm64, &context, "same-operation")
            .expect("arm64 revision");
        assert_ne!(amd64_revision, arm64_revision);
        assert_eq!(
            revision(
                &desired,
                &compose,
                &["linux/arm64".to_owned(), "linux/amd64".to_owned()],
                &context,
                "same-operation",
            )
            .expect("ordered revision"),
            revision(
                &desired,
                &compose,
                &["linux/amd64".to_owned(), "linux/arm64".to_owned()],
                &context,
                "same-operation",
            )
            .expect("reordered revision")
        );

        let settings = test_settings();
        let amd64_builds = build_specs(&settings, &desired, &compose, &context, &amd64_revision)
            .expect("amd64 build");
        let arm64_builds = build_specs(&settings, &desired, &compose, &context, &arm64_revision)
            .expect("arm64 build");
        assert_ne!(amd64_builds[0].image, arm64_builds[0].image);

        let metadata = test_metadata(&desired);
        let amd64_rendered = render_environment(
            &settings,
            &desired,
            &compose,
            &context,
            &metadata,
            &amd64_revision,
            false,
        )
        .expect("amd64 render");
        let arm64_rendered = render_environment(
            &settings,
            &desired,
            &compose,
            &context,
            &metadata,
            &arm64_revision,
            false,
        )
        .expect("arm64 render");
        assert_ne!(
            workload_hash(&amd64_rendered, "web"),
            workload_hash(&arm64_rendered, "web")
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn profile_render_settings_change_their_owned_specs() {
        let directory = tempdir().expect("tempdir");
        let compose_path = directory.path().join("resolved.json");
        let desired = desired(directory.path(), &compose_path);
        let service = json!({"build": {"context": "."}, "expose": [8080]});
        let compose = ComposeProject {
            document: json!({"services": {"web": service.clone()}}),
            services: BTreeMap::from([("web".to_owned(), ComposeService { raw: service })]),
        };
        let context = operation_context(&desired, "profile-render");
        let metadata = test_metadata(&desired);
        let baseline_settings = test_settings();
        let render = |settings: &Settings| {
            render_environment(
                settings,
                &desired,
                &compose,
                &context,
                &metadata,
                &"a".repeat(64),
                false,
            )
            .expect("render")
        };
        let baseline = render(&baseline_settings);
        let baseline_runtime_hash = workload_hash(&baseline, "web").to_owned();

        let mut registry = baseline_settings.clone();
        registry.registry = "registry.example.com".to_owned();
        let mut repository = baseline_settings.clone();
        repository.repository = "other/previews".to_owned();
        let mut replicas = baseline_settings.clone();
        replicas.replicas = 2;
        let mut pull_secret = baseline_settings.clone();
        pull_secret.image_pull_secret = Some("registry-pull".to_owned());
        for changed in [registry, repository, replicas, pull_secret] {
            assert_ne!(
                workload_hash(&render(&changed), "web"),
                baseline_runtime_hash
            );
        }

        let baseline_exposure_hashes = exposure_hashes(&baseline);
        let mut ingress_class = baseline_settings.clone();
        ingress_class.ingress_class = "edge".to_owned();
        let mut issuer = baseline_settings.clone();
        issuer.cluster_issuer = "letsencrypt-staging".to_owned();
        let mut cleartext_entrypoint = baseline_settings.clone();
        cleartext_entrypoint.traefik_http_entrypoint = "http".to_owned();
        let mut tls_entrypoint = baseline_settings.clone();
        tls_entrypoint.traefik_https_entrypoint = "https".to_owned();
        let mut dns_domain = baseline_settings.clone();
        dns_domain.dns_domain = "nip.io".to_owned();
        for changed in [
            ingress_class,
            issuer,
            cleartext_entrypoint,
            tls_entrypoint,
            dns_domain,
        ] {
            assert_ne!(exposure_hashes(&render(&changed)), baseline_exposure_hashes);
        }

        let mut namespace_prefix = baseline_settings;
        namespace_prefix.namespace_prefix = "preview".to_owned();
        assert_ne!(render(&namespace_prefix).namespace, baseline.namespace);
    }

    #[test]
    fn volume_topology_changes_revision_and_runtime_shape() {
        let directory = tempdir().expect("tempdir");
        let compose_path = directory.path().join("resolved.json");
        let desired = desired(directory.path(), &compose_path);
        let baseline_service = json!({"build": {"context": "."}, "expose": [8080]});
        let volume_service = json!({
            "build": {"context": "."},
            "expose": [8080],
            "volumes": ["data:/var/lib/data"]
        });
        let baseline_compose = ComposeProject {
            document: json!({"services": {"web": baseline_service.clone()}}),
            services: BTreeMap::from([(
                "web".to_owned(),
                ComposeService {
                    raw: baseline_service,
                },
            )]),
        };
        let volume_compose = ComposeProject {
            document: json!({"services": {"web": volume_service.clone()}}),
            services: BTreeMap::from([(
                "web".to_owned(),
                ComposeService {
                    raw: volume_service,
                },
            )]),
        };
        let platforms = vec!["linux/amd64".to_owned()];
        let context = operation_context(&desired, "operation");
        let baseline_revision = revision(
            &desired,
            &baseline_compose,
            &platforms,
            &context,
            "operation",
        )
        .expect("baseline");
        let volume_revision =
            revision(&desired, &volume_compose, &platforms, &context, "operation").expect("volume");
        assert_ne!(baseline_revision, volume_revision);

        let settings = test_settings();
        let metadata = test_metadata(&desired);
        let baseline = render_environment(
            &settings,
            &desired,
            &baseline_compose,
            &context,
            &metadata,
            &baseline_revision,
            false,
        )
        .expect("baseline render");
        let with_volume = render_environment(
            &settings,
            &desired,
            &volume_compose,
            &context,
            &metadata,
            &volume_revision,
            false,
        )
        .expect("volume render");
        assert!(
            baseline
                .resources
                .iter()
                .all(|resource| resource.kind != "PersistentVolumeClaim")
        );
        assert!(
            with_volume
                .resources
                .iter()
                .any(|resource| resource.kind == "PersistentVolumeClaim")
        );
        assert_ne!(
            workload_hash(&baseline, "web"),
            workload_hash(&with_volume, "web")
        );
    }

    #[test]
    fn traefik_renders_environment_owned_redirect_middleware() {
        let settings = Settings {
            context: "spot".to_owned(),
            registry: "ghcr.io".to_owned(),
            repository: "team/lightrail".to_owned(),
            ingress_class: "traefik".to_owned(),
            cluster_issuer: "letsencrypt".to_owned(),
            traefik_http_entrypoint: "plain".to_owned(),
            traefik_https_entrypoint: "tls".to_owned(),
            ..Settings::default()
        };
        let directory = tempdir().expect("tempdir");
        let compose_path = directory.path().join("resolved.json");
        let desired = desired(directory.path(), &compose_path);
        let compose = ComposeProject {
            document: json!({}),
            services: BTreeMap::from([(
                "web".to_owned(),
                ComposeService {
                    raw: json!({"image": "example/web:1", "expose": [8080]}),
                },
            )]),
        };
        let metadata = ContextMetadata {
            capability: Capability::Exposure,
            operation: Operation::Up,
            all: false,
            project_id: desired.project.id.clone(),
            project_slug: desired.project.slug.clone(),
            target: json!({
                "ingress": {
                    "controller": "traefik.io/ingress-controller",
                    "addresses": ["8.8.4.4"],
                    "traefik_middleware_api_version": "traefik.io/v1alpha1"
                }
            }),
            selection: Selection::default(),
        };
        let rendered = render_environment(
            &settings,
            &desired,
            &compose,
            &OperationContext {
                environment_id: desired.environment.id.clone(),
                ..OperationContext::default()
            },
            &metadata,
            &"c".repeat(64),
            false,
        )
        .expect("render");
        let middleware = rendered
            .resources
            .iter()
            .find(|resource| resource.kind == "Middleware")
            .expect("middleware");
        assert_eq!(middleware.manifest["apiVersion"], "traefik.io/v1alpha1");
        assert_eq!(
            middleware.manifest["spec"]["redirectScheme"]["scheme"],
            "https"
        );
        assert_eq!(
            middleware.manifest["spec"]["redirectScheme"]["permanent"],
            true
        );
        let tls_ingress = rendered
            .resources
            .iter()
            .find(|resource| resource.name.starts_with("ingress-"))
            .expect("TLS ingress");
        assert_eq!(
            tls_ingress.manifest["metadata"]["annotations"]["traefik.ingress.kubernetes.io/router.entrypoints"],
            "tls"
        );
        let redirect = rendered
            .resources
            .iter()
            .find(|resource| resource.name.starts_with("redirect-"))
            .expect("plain HTTP redirect ingress");
        assert_eq!(
            redirect.manifest["metadata"]["annotations"]["traefik.ingress.kubernetes.io/router.middlewares"],
            format!("{}-{}@kubernetescrd", rendered.namespace, middleware.name)
        );
        assert_eq!(
            redirect.manifest["metadata"]["annotations"]["traefik.ingress.kubernetes.io/router.entrypoints"],
            "plain"
        );
        assert!(redirect.manifest["spec"].get("tls").is_none());
    }

    #[test]
    fn ingress_annotations_are_limited_to_exact_supported_controllers() {
        assert_eq!(
            ingress_controller(&json!({"ingress": {"controller": "k8s.io/ingress-nginx"}}))
                .expect("community ingress-nginx"),
            IngressController::Nginx
        );
        assert_eq!(
            ingress_controller(
                &json!({"ingress": {"controller": "traefik.io/ingress-controller"}})
            )
            .expect("Traefik"),
            IngressController::Traefik
        );
        assert_eq!(
            ingress_controller(&json!({"ingress": {"controller": "nginx.org/ingress-controller"}}))
                .expect_err("different NGINX annotations must not be guessed")
                .code,
            "unsupported_ingress_controller"
        );
    }

    #[test]
    fn hostname_normalization_matches_the_shared_ip_dns_contract() {
        let valid = "a".repeat(49);
        let hostname = app_hostname(
            &valid,
            &valid,
            &valid,
            &valid,
            Ipv4Addr::new(8, 8, 8, 8),
            "sslip.io",
        )
        .expect("49-byte labels fit the complete hostname unchanged");
        assert_eq!(hostname.split('.').next(), Some(valid.as_str()));

        let too_long = "a".repeat(63);
        assert!(
            app_hostname(
                &too_long,
                &too_long,
                &too_long,
                &too_long,
                Ipv4Addr::new(8, 8, 8, 8),
                "sslip.io",
            )
            .is_err(),
            "the shared hostname builder rejects a complete name over 253 bytes"
        );
    }

    #[test]
    fn ip_derived_ingress_dns_rejects_non_public_addresses() {
        for address in ["127.0.0.1", "10.0.0.1", "169.254.1.1", "203.0.113.10"] {
            assert!(ingress_ipv4(&json!({"ingress": {"addresses": [address]}})).is_none());
        }
        assert_eq!(
            ingress_ipv4(&json!({"ingress": {"addresses": ["8.8.8.8"]}})),
            Some(Ipv4Addr::new(8, 8, 8, 8))
        );
    }
}
