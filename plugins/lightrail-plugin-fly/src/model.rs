use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use lightrail_plugin_protocol::{
    Capability, ErrorKind, OperationContext, PluginError, PluginResult, SecretValue,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

pub const MANAGED_KEY: &str = "lightrail-managed";
pub const PROJECT_KEY: &str = "lightrail-project-id";
pub const ENVIRONMENT_KEY: &str = "lightrail-environment-id";
pub const PROFILE_KEY: &str = "lightrail-profile";
pub const BRANCH_KEY: &str = "lightrail-branch";
pub const SERVICE_KEY: &str = "lightrail-service";
pub const ROLE_KEY: &str = "lightrail-role";
pub const REVISION_KEY: &str = "lightrail-revision";
pub const EXPIRES_KEY: &str = "lightrail-expires-at-unix";
pub const PUBLIC_APP_KEY: &str = "lightrail-public-app";
pub const PORT_KEY: &str = "lightrail-port";

const MAX_FLY_NAME: usize = 63;
const PROJECT_MARKER_HEX: usize = 20;
const RESOURCE_SUFFIX_HEX: usize = 12;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenReference {
    #[serde(default = "default_token_name")]
    pub secret: String,
}

impl Default for TokenReference {
    fn default() -> Self {
        Self {
            secret: default_token_name(),
        }
    }
}

fn default_token_name() -> String {
    "fly-token".to_owned()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub organization: String,
    pub region: Option<String>,
    pub token: TokenReference,
    pub registry: String,
    pub platform: String,
    pub app_prefix: String,
    pub cpu_kind: String,
    pub cpus: u16,
    pub memory_mb: u32,
    pub auto_stop: bool,
    pub lock_ttl_seconds: u64,
    pub ttl_hours: u64,
    pub volume_size_gb: u32,
    pub command_timeout_seconds: u64,
    pub readiness_timeout_seconds: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            organization: "personal".to_owned(),
            region: None,
            token: TokenReference::default(),
            registry: "registry.fly.io".to_owned(),
            platform: "linux/amd64".to_owned(),
            app_prefix: "lr".to_owned(),
            cpu_kind: "shared".to_owned(),
            cpus: 1,
            memory_mb: 256,
            auto_stop: true,
            lock_ttl_seconds: 3_600,
            ttl_hours: 72,
            volume_size_gb: 3,
            command_timeout_seconds: 300,
            readiness_timeout_seconds: 300,
        }
    }
}

impl Settings {
    pub fn from_context(context: &OperationContext) -> PluginResult<Self> {
        let settings: Self = serde_json::from_value(context.config.clone()).map_err(|error| {
            validation(
                "invalid_fly_config",
                format!("invalid Fly.io plugin configuration: {error}"),
            )
        })?;
        settings.validate()?;
        Ok(settings)
    }

    pub fn validate(&self) -> PluginResult<()> {
        validate_slug("organization", &self.organization, 128)?;
        validate_slug("app_prefix", &self.app_prefix, 16)?;
        if let Some(region) = &self.region {
            validate_slug("region", region, 16)?;
        }
        if self.token.secret != "fly-token" {
            return Err(validation(
                "undeclared_fly_token",
                "`token.secret` must be `fly-token`",
            ));
        }
        if self.registry != "registry.fly.io" {
            return Err(validation(
                "unsupported_fly_registry",
                "`registry` must be `registry.fly.io` for Fly App repositories",
            ));
        }
        if !matches!(self.platform.as_str(), "linux/amd64" | "linux/arm64") {
            return Err(validation(
                "unsupported_fly_platform",
                "`platform` must be `linux/amd64` or `linux/arm64`",
            ));
        }
        if self.cpu_kind.trim().is_empty() {
            return Err(validation(
                "cpu_kind_required",
                "`cpu_kind` must not be empty",
            ));
        }
        if self.cpus == 0 {
            return Err(validation("cpus_invalid", "`cpus` must be at least 1"));
        }
        if self.memory_mb < 256 || self.memory_mb % 256 != 0 {
            return Err(validation(
                "memory_invalid",
                "`memory_mb` must be at least 256 and a multiple of 256",
            ));
        }
        if !(60..=86_400).contains(&self.lock_ttl_seconds) {
            return Err(validation(
                "lock_ttl_invalid",
                "`lock_ttl_seconds` must be between 60 and 86400",
            ));
        }
        if self.ttl_hours == 0 {
            return Err(validation(
                "ttl_hours_invalid",
                "`ttl_hours` must be at least 1",
            ));
        }
        if self.volume_size_gb == 0 {
            return Err(validation(
                "volume_size_invalid",
                "`volume_size_gb` must be at least 1",
            ));
        }
        if !(10..=3_000).contains(&self.command_timeout_seconds) {
            return Err(validation(
                "command_timeout_invalid",
                "`command_timeout_seconds` must be between 10 and 3000",
            ));
        }
        if !(10..=3_000).contains(&self.readiness_timeout_seconds) {
            return Err(validation(
                "readiness_timeout_invalid",
                "`readiness_timeout_seconds` must be between 10 and 3000",
            ));
        }
        let longest_step = self
            .command_timeout_seconds
            .max(self.readiness_timeout_seconds);
        if self.lock_ttl_seconds <= longest_step.saturating_add(180) {
            return Err(validation(
                "lock_ttl_too_short",
                "`lock_ttl_seconds` must exceed command/readiness timeouts plus provider-call and rollback margins by more than 180 seconds",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ContextMetadata {
    pub capability: Option<Capability>,
    #[serde(default)]
    pub operation: String,
    #[serde(default)]
    pub all: bool,
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub selection: Option<Selection>,
}

impl ContextMetadata {
    pub fn from_context(context: &OperationContext) -> PluginResult<Self> {
        serde_json::from_value(context.metadata.clone()).map_err(|error| {
            validation(
                "invalid_operation_metadata",
                format!("invalid Fly.io operation metadata: {error}"),
            )
        })
    }

    pub fn capability(&self) -> PluginResult<Capability> {
        self.capability
            .clone()
            .ok_or_else(|| validation("capability_required", "operation capability is required"))
    }

    pub fn validate_selection(&self) -> PluginResult<Option<&BTreeSet<String>>> {
        if self.operation != "prune" {
            return Ok(None);
        }
        if self.all {
            return Err(validation(
                "invalid_prune_scope",
                "selected prune must use `all = false`",
            ));
        }
        let selection = self.selection.as_ref().ok_or_else(|| {
            validation(
                "prune_selection_required",
                "selected prune requires `metadata.selection`",
            )
        })?;
        if selection.schema != 1 || selection.reason != "expired" {
            return Err(validation(
                "unsupported_prune_selection",
                "selected prune requires schema 1 and reason `expired`",
            ));
        }
        if selection.environment_ids.is_empty()
            || selection
                .environment_ids
                .iter()
                .any(|value| value.trim().is_empty())
        {
            return Err(validation(
                "invalid_prune_environments",
                "selected prune requires non-empty environment IDs",
            ));
        }
        Ok(Some(&selection.environment_ids))
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Selection {
    pub schema: u32,
    pub reason: String,
    pub environment_ids: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DesiredState {
    pub schema: u32,
    pub project: ProjectSpec,
    pub environment: EnvironmentSpec,
    #[serde(default)]
    pub resolved_compose_path: Option<PathBuf>,
    #[serde(default)]
    pub apps: Vec<AppSpec>,
    #[serde(default)]
    pub destroy: bool,
}

impl DesiredState {
    pub fn parse(value: Value, context: &OperationContext) -> PluginResult<Self> {
        let mut desired: Self = serde_json::from_value(value).map_err(|error| {
            validation(
                "invalid_fly_desired",
                format!("invalid Fly.io desired state: {error}"),
            )
        })?;
        if desired.schema != 1 {
            return Err(validation(
                "unsupported_desired_schema",
                format!("unsupported desired schema {}; expected 1", desired.schema),
            ));
        }
        if desired.environment.id != context.environment_id
            || desired.environment.profile != context.profile
        {
            return Err(validation(
                "desired_identity_mismatch",
                "desired environment identity does not match the operation context",
            ));
        }
        if desired.environment.isolation != Isolation::Environment {
            return Err(validation(
                "fly_isolation_required",
                "Fly.io profiles require `isolation = \"environment\"`",
            ));
        }
        if let Some(granted) = context.project_root.as_deref() {
            let granted = Path::new(granted);
            if !granted.is_absolute()
                || granted.components().any(|component| {
                    matches!(component, Component::ParentDir | Component::Prefix(_))
                })
            {
                return Err(validation(
                    "invalid_project_root_authority",
                    "the operation context project root must be an absolute normalized path",
                ));
            }
            if let Some(requested) = desired.project.root.as_deref() {
                if !same_source_root(requested, granted) {
                    return Err(validation(
                        "project_root_authority_mismatch",
                        "desired project root does not match the Git project root granted by the operation context",
                    ));
                }
            }
            desired.project.root = Some(granted.to_path_buf());
        } else if desired.project.root.is_some() {
            return Err(validation(
                "project_root_authority_required",
                "the operation context must explicitly grant the Git project root",
            ));
        }
        Ok(desired)
    }

    pub fn project_root<'a>(&'a self, context: &'a OperationContext) -> PluginResult<&'a Path> {
        self.project
            .root
            .as_deref()
            .or_else(|| context.project_root.as_deref().map(Path::new))
            .ok_or_else(|| validation("project_root_required", "project root is required"))
    }
}

fn same_source_root(requested: &Path, granted: &Path) -> bool {
    if !requested.is_absolute()
        || requested
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return false;
    }
    match (
        std::fs::canonicalize(requested),
        std::fs::canonicalize(granted),
    ) {
        (Ok(requested), Ok(granted)) => requested == granted,
        _ => requested == granted,
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProjectSpec {
    pub id: String,
    pub slug: String,
    #[serde(default)]
    pub root: Option<PathBuf>,
    #[serde(default)]
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
    Environment,
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

#[derive(Clone, Debug, Serialize)]
pub struct Workload {
    pub service: String,
    pub app_name: String,
    pub public_app: Option<String>,
    pub port: Option<u16>,
    pub health_path: Option<String>,
    pub health_status: Option<u16>,
    pub health_interval_seconds: Option<u64>,
    pub health_timeout_seconds: Option<u64>,
    pub build: bool,
    pub image: String,
    pub volume: Option<VolumeMount>,
    #[serde(skip_serializing)]
    pub environment: BTreeMap<String, String>,
    #[serde(skip_serializing)]
    pub init: Option<Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct VolumeMount {
    pub name: String,
    pub path: String,
}

#[allow(clippy::too_many_lines)]
pub fn workloads(
    desired: &DesiredState,
    settings: &Settings,
    compose: &Value,
    revision: &str,
) -> PluginResult<Vec<Workload>> {
    validate_top_level_networks(compose)?;
    validate_top_level_volumes(compose)?;
    for field in ["configs", "secrets"] {
        if compose.get(field).is_some_and(|value| !is_empty(value)) {
            return Err(validation(
                "compose_top_level_resource_unsupported",
                format!(
                    "top-level Compose `{field}` entries are not supported by the Fly translator"
                ),
            ));
        }
    }
    let services = compose
        .get("services")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            validation(
                "compose_services_required",
                "resolved Compose must contain a services object",
            )
        })?;
    let mut public = BTreeMap::new();
    for app in &desired.apps {
        if let Some(existing) = public.insert(app.service.as_str(), app) {
            return Err(validation(
                "duplicate_public_service",
                format!(
                    "public apps `{}` and `{}` both select service `{}`; Fly.io requires one selected app per Compose service",
                    existing.name, app.name, app.service
                ),
            ));
        }
    }
    for app in &desired.apps {
        if app.health_path.as_deref().is_some_and(|path| {
            !path.starts_with('/') || path.contains('\r') || path.contains('\n')
        }) {
            return Err(validation(
                "invalid_health_path",
                format!(
                    "public app `{}` health_path must begin with `/` and contain no line breaks",
                    app.name
                ),
            ));
        }
        if !services.contains_key(&app.service) {
            return Err(validation(
                "app_service_missing",
                format!(
                    "public app `{}` selects missing service `{}`",
                    app.name, app.service
                ),
            ));
        }
    }

    let mut output = Vec::with_capacity(services.len());
    for (service_name, raw) in services {
        let service = raw.as_object().ok_or_else(|| {
            validation(
                "invalid_compose_service",
                format!("Compose service `{service_name}` must be an object"),
            )
        })?;
        reject_unsupported_service_fields(service_name, service)?;
        validate_service_networks(service_name, service)?;
        if service
            .get("network_mode")
            .is_some_and(|value| !is_empty(value))
        {
            return Err(validation(
                "compose_network_mode_unsupported",
                format!(
                    "Compose service `{service_name}` declares `network_mode`, which cannot be translated to the environment's Fly 6PN"
                ),
            ));
        }
        if service
            .get("privileged")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err(validation(
                "privileged_service_unsupported",
                format!("Compose service `{service_name}` requests privileged mode"),
            ));
        }
        if service.get("secrets").is_some_and(|value| !is_empty(value)) {
            return Err(validation(
                "compose_service_secrets_unsupported",
                format!(
                    "Compose service `{service_name}` declares `secrets`; Fly workload secrets are not supported yet"
                ),
            ));
        }
        if service
            .get("env_file")
            .is_some_and(|value| !is_empty(value))
        {
            return Err(validation(
                "compose_env_file_unsupported",
                format!(
                    "Compose service `{service_name}` declares `env_file`; Fly config.env would expose resolved values through the provider API"
                ),
            ));
        }
        if service.get("configs").is_some_and(|value| !is_empty(value)) {
            return Err(validation(
                "compose_service_configs_unsupported",
                format!(
                    "Compose service `{service_name}` declares `configs`, which Fly Machines cannot translate safely"
                ),
            ));
        }
        if let Some(replicas) = service
            .get("deploy")
            .and_then(|deploy| deploy.get("replicas"))
            .and_then(Value::as_u64)
            .filter(|replicas| *replicas != 1)
        {
            return Err(validation(
                "compose_replicas_unsupported",
                format!(
                    "Compose service `{service_name}` requests {replicas} replicas; this Fly plugin currently supports exactly one Machine per service"
                ),
            ));
        }
        if let Some(deploy) = service.get("deploy").and_then(Value::as_object) {
            let unsupported = deploy
                .keys()
                .filter(|field| field.as_str() != "replicas")
                .cloned()
                .collect::<Vec<_>>();
            if !unsupported.is_empty() {
                return Err(validation(
                    "compose_deploy_unsupported",
                    format!(
                        "Compose service `{service_name}` uses unsupported deploy field(s): {}",
                        unsupported.join(", ")
                    ),
                ));
            }
        }
        let app = public.get(service_name.as_str()).copied();
        if let Some(status) = app.and_then(|app| app.health_status) {
            if !(200..=299).contains(&status) {
                return Err(validation(
                    "fly_health_status_unsupported",
                    format!(
                        "public app `{}` health_status must be a 2xx status for Fly proxy health checks",
                        app.map_or("", |app| app.name.as_str())
                    ),
                ));
            }
        }
        let app_name = fly_app_name(
            desired,
            service_name,
            app.map(|app| app.name.as_str()),
            settings,
        );
        let build = service.get("build").is_some_and(|value| !value.is_null());
        let image = if build {
            format!(
                "{}/{app_name}:lr-{}",
                settings.registry,
                revision.get(..20).unwrap_or(revision)
            )
        } else {
            service
                .get("image")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    validation(
                        "service_image_required",
                        format!("Compose service `{service_name}` must declare `build` or `image`"),
                    )
                })?
                .to_owned()
        };
        let volume = service_volume(service_name, service)?;
        let environment = literal_environment(service_name, service)?;
        let init = machine_init(service_name, service)?;
        output.push(Workload {
            service: service_name.clone(),
            app_name,
            public_app: app.map(|app| app.name.clone()),
            port: app.map(|app| app.port),
            health_path: app.and_then(|app| app.health_path.clone()),
            health_status: app.and_then(|app| app.health_status),
            health_interval_seconds: app.and_then(|app| app.health_interval_seconds),
            health_timeout_seconds: app.and_then(|app| app.health_timeout_seconds),
            build,
            image,
            volume,
            environment,
            init,
        });
    }
    output.sort_by(|left, right| left.service.cmp(&right.service));
    Ok(output)
}

fn external_enabled(value: &Value) -> bool {
    !matches!(value, Value::Null | Value::Bool(false))
}

fn validate_top_level_networks(compose: &Value) -> PluginResult<()> {
    let Some(networks) = compose.get("networks") else {
        return Ok(());
    };
    let networks = networks.as_object().ok_or_else(|| {
        validation(
            "invalid_compose_networks",
            "top-level Compose `networks` must be an object",
        )
    })?;
    if networks.len() != 1 || !networks.contains_key("default") {
        return Err(validation(
            "compose_network_topology_unsupported",
            "Fly translates only Compose's implicit `default` network; custom or multiple networks cannot be preserved in the environment 6PN",
        ));
    }

    let definition = &networks["default"];
    if definition.is_null() {
        return Ok(());
    }
    let definition = definition.as_object().ok_or_else(|| {
        validation(
            "invalid_compose_network",
            "top-level Compose network `default` must be an object",
        )
    })?;
    let unsupported = definition
        .keys()
        .filter(|field| !matches!(field.as_str(), "name" | "ipam"))
        .cloned()
        .collect::<Vec<_>>();
    if !unsupported.is_empty() {
        return Err(validation(
            "compose_network_options_unsupported",
            format!(
                "top-level Compose network `default` uses unsupported field(s): {}",
                unsupported.join(", ")
            ),
        ));
    }
    if definition.get("ipam").is_some_and(|value| !is_empty(value)) {
        return Err(validation(
            "compose_network_options_unsupported",
            "top-level Compose network `default` declares IPAM options that Fly 6PN cannot preserve",
        ));
    }
    if let Some(name) = definition.get("name") {
        let name = name.as_str().ok_or_else(|| {
            validation(
                "invalid_compose_network",
                "top-level Compose network `default.name` must be a string",
            )
        })?;
        let project_name = compose.get("name").and_then(Value::as_str).ok_or_else(|| {
            validation(
                "compose_network_name_unverifiable",
                "resolved Compose with a generated default network name must include its project name",
            )
        })?;
        if name != format!("{project_name}_default") {
            return Err(validation(
                "compose_custom_network_name_unsupported",
                format!(
                    "top-level Compose network `default` has custom name `{name}`; Fly translates only the generated `{project_name}_default` network"
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
        validation(
            "invalid_compose_service_networks",
            format!("Compose service `{service_name}` networks must be an object"),
        )
    })?;
    if networks.len() != 1 || !networks.contains_key("default") {
        return Err(validation(
            "compose_service_network_topology_unsupported",
            format!(
                "Compose service `{service_name}` must use only the implicit `default` network; Fly cannot preserve custom or multiple network membership"
            ),
        ));
    }
    if !is_empty(&networks["default"]) {
        return Err(validation(
            "compose_service_network_options_unsupported",
            format!(
                "Compose service `{service_name}` declares aliases, addresses, or other options on `default`; Fly 6PN cannot preserve those semantics"
            ),
        ));
    }
    Ok(())
}

fn validate_top_level_volumes(compose: &Value) -> PluginResult<()> {
    let Some(volumes) = compose.get("volumes") else {
        return Ok(());
    };
    let volumes = volumes.as_object().ok_or_else(|| {
        validation(
            "invalid_compose_volumes",
            "top-level Compose `volumes` must be an object",
        )
    })?;
    for (name, raw) in volumes {
        if raw.get("external").is_some_and(external_enabled) {
            return Err(validation(
                "external_volume_unsupported",
                format!("external Compose volume `{name}` is not owned by the Fly environment"),
            ));
        }
        let Some(definition) = raw.as_object() else {
            if raw.is_null() {
                continue;
            }
            return Err(validation(
                "invalid_compose_volume",
                format!("top-level Compose volume `{name}` must be an object"),
            ));
        };
        let unsupported = definition
            .iter()
            .filter(|(field, value)| {
                !matches!(field.as_str(), "name" | "external") && !is_empty(value)
            })
            .map(|(field, _)| field.clone())
            .collect::<Vec<_>>();
        if !unsupported.is_empty() {
            return Err(validation(
                "compose_volume_options_unsupported",
                format!(
                    "top-level Compose volume `{name}` uses unsupported field(s): {}",
                    unsupported.join(", ")
                ),
            ));
        }
        if let Some(volume_name) = definition.get("name") {
            let volume_name = volume_name.as_str().ok_or_else(|| {
                validation(
                    "invalid_compose_volume",
                    format!("top-level Compose volume `{name}.name` must be a string"),
                )
            })?;
            let project_name = compose.get("name").and_then(Value::as_str).ok_or_else(|| {
                validation(
                    "compose_volume_name_unverifiable",
                    "resolved Compose with generated volume names must include its project name",
                )
            })?;
            let generated = format!("{project_name}_{name}");
            if volume_name != generated {
                return Err(validation(
                    "custom_volume_name_unsupported",
                    format!(
                        "top-level Compose volume `{name}` has custom name `{volume_name}`; Fly can own only the generated `{generated}` volume"
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn reject_unsupported_service_fields(
    service_name: &str,
    service: &Map<String, Value>,
) -> PluginResult<()> {
    const SUPPORTED: &[&str] = &[
        "build",
        "command",
        "configs",
        "deploy",
        "entrypoint",
        "environment",
        "env_file",
        "expose",
        "healthcheck",
        "image",
        "labels",
        "network_mode",
        "networks",
        "ports",
        "privileged",
        "secrets",
        "volumes",
    ];
    if service
        .get("x-lightrail")
        .is_some_and(|value| !is_empty(value))
    {
        return Err(validation(
            "fly_x_lightrail_unsupported",
            format!(
                "Compose service `{service_name}` declares `x-lightrail` workload semantics that the Fly provider cannot translate"
            ),
        ));
    }
    if service.get("labels").is_some_and(|value| !is_empty(value)) {
        return Err(validation(
            "compose_service_labels_unsupported",
            format!(
                "Compose service `{service_name}` declares labels that the Fly Machine translator does not preserve"
            ),
        ));
    }
    let extensions = service
        .iter()
        .filter(|(field, value)| field.starts_with("x-") && !is_empty(value))
        .map(|(field, _)| field.clone())
        .collect::<Vec<_>>();
    if !extensions.is_empty() {
        return Err(validation(
            "compose_service_extensions_unsupported",
            format!(
                "Compose service `{service_name}` uses unsupported extension field(s): {}",
                extensions.join(", ")
            ),
        ));
    }
    let unsupported = service
        .iter()
        .filter(|(field, value)| !SUPPORTED.contains(&field.as_str()) && !is_empty(value))
        .map(|(field, _)| field.clone())
        .collect::<Vec<_>>();
    if unsupported.is_empty() {
        return Ok(());
    }
    Err(validation(
        "compose_service_fields_unsupported",
        format!(
            "Compose service `{service_name}` uses unsupported field(s): {}; remove them or use another runtime",
            unsupported.join(", ")
        ),
    ))
}

fn is_empty(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Array(values) => values.is_empty(),
        Value::Object(values) => values.is_empty(),
        Value::String(value) => value.is_empty(),
        _ => false,
    }
}

fn service_volume(
    service_name: &str,
    service: &Map<String, Value>,
) -> PluginResult<Option<VolumeMount>> {
    let mut mounts = Vec::new();
    for raw in service
        .get("volumes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(mount) = parse_mount(raw)? else {
            continue;
        };
        mounts.push(mount);
    }
    if mounts.len() > 1 {
        return Err(validation(
            "fly_single_volume_limit",
            format!(
                "Compose service `{service_name}` has multiple named volumes; Fly Machines support one volume per Machine"
            ),
        ));
    }
    Ok(mounts.pop())
}

fn parse_mount(raw: &Value) -> PluginResult<Option<VolumeMount>> {
    if let Some(value) = raw.as_str() {
        let mut parts = value.split(':');
        let source = parts.next().unwrap_or_default();
        let target = parts.next().unwrap_or_default();
        if parts.next().is_some() {
            return Err(validation(
                "fly_volume_options_unsupported",
                "Compose volume access modes and mount options are not supported by Fly.io",
            ));
        }
        if source.starts_with('.') || source.starts_with('/') || source.contains('\\') {
            return Err(validation(
                "bind_mount_unsupported",
                "local bind mounts cannot be deployed to Fly.io",
            ));
        }
        if source.is_empty() || target.is_empty() {
            return Ok(None);
        }
        return Ok(Some(VolumeMount {
            name: safe_label(source, 30),
            path: target.to_owned(),
        }));
    }
    let Some(object) = raw.as_object() else {
        return Err(validation(
            "invalid_compose_mount",
            "Compose volume entries must be strings or objects",
        ));
    };
    let unsupported = object
        .iter()
        .filter(|(field, value)| {
            !matches!(
                field.as_str(),
                "type" | "source" | "target" | "read_only" | "volume" | "consistency"
            ) && !is_empty(value)
        })
        .map(|(field, _)| field.clone())
        .collect::<Vec<_>>();
    if !unsupported.is_empty() {
        return Err(validation(
            "compose_mount_options_unsupported",
            format!(
                "Compose volume mount uses unsupported field(s): {}",
                unsupported.join(", ")
            ),
        ));
    }
    match object.get("type").and_then(Value::as_str) {
        Some("bind") => Err(validation(
            "bind_mount_unsupported",
            "local bind mounts cannot be deployed to Fly.io",
        )),
        Some("volume") | None => {
            if object
                .get("read_only")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                || object.get("volume").is_some_and(|value| !is_empty(value))
                || object
                    .get("consistency")
                    .is_some_and(|value| !is_empty(value))
            {
                return Err(validation(
                    "fly_volume_options_unsupported",
                    "Compose volume access modes and mount options are not supported by Fly.io",
                ));
            }
            let Some(source) = object.get("source").and_then(Value::as_str) else {
                return Ok(None);
            };
            let target = object
                .get("target")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    validation(
                        "volume_target_required",
                        "named Compose volumes require a target path",
                    )
                })?;
            Ok(Some(VolumeMount {
                name: safe_label(source, 30),
                path: target.to_owned(),
            }))
        }
        Some(other) => Err(validation(
            "unsupported_compose_mount",
            format!("Compose mount type `{other}` is not supported by Fly.io"),
        )),
    }
}

fn literal_environment(
    service_name: &str,
    service: &Map<String, Value>,
) -> PluginResult<BTreeMap<String, String>> {
    let mut output = BTreeMap::new();
    let Some(environment) = service.get("environment") else {
        return Ok(output);
    };
    let object = environment.as_object().ok_or_else(|| {
        validation(
            "invalid_service_environment",
            format!("service `{service_name}` environment must resolve to an object"),
        )
    })?;
    for (key, value) in object {
        let value = match value {
            Value::String(value) => value.clone(),
            Value::Number(value) => value.to_string(),
            Value::Bool(value) => value.to_string(),
            Value::Null => String::new(),
            Value::Array(_) | Value::Object(_) => {
                return Err(validation(
                    "invalid_environment_value",
                    format!("service `{service_name}` environment `{key}` is not scalar"),
                ));
            }
        };
        output.insert(key.clone(), value);
    }
    Ok(output)
}

fn machine_init(service_name: &str, service: &Map<String, Value>) -> PluginResult<Option<Value>> {
    let entrypoint = command_array(service_name, "entrypoint", service.get("entrypoint"))?;
    let cmd = command_array(service_name, "command", service.get("command"))?;
    if entrypoint.is_none() && cmd.is_none() {
        return Ok(None);
    }
    Ok(Some(json!({
        "entrypoint": entrypoint,
        "cmd": cmd
    })))
}

fn command_array(
    service: &str,
    field: &str,
    value: Option<&Value>,
) -> PluginResult<Option<Vec<String>>> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let array = value.as_array().ok_or_else(|| {
        validation(
            "string_command_unsupported",
            format!("service `{service}` `{field}` must use Compose list form for Fly.io"),
        )
    })?;
    array
        .iter()
        .map(|part| {
            part.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                validation(
                    "invalid_command",
                    format!("service `{service}` `{field}` entries must be strings"),
                )
            })
        })
        .collect::<PluginResult<Vec<_>>>()
        .map(Some)
}

pub fn resolve_app_environment(
    desired: &DesiredState,
    secrets: &BTreeMap<String, SecretValue>,
) -> PluginResult<BTreeMap<String, BTreeMap<String, String>>> {
    let mut output = BTreeMap::new();
    for app in &desired.apps {
        let mut environment = BTreeMap::new();
        for (name, input) in &app.environment {
            match input {
                EnvironmentInput::Literal(value) => {
                    environment.insert(name.clone(), value.clone());
                }
                EnvironmentInput::Secret { secret } => {
                    if secrets.contains_key(secret) {
                        return Err(PluginError::permanent(
                            ErrorKind::Unsupported,
                            "fly_app_secrets_unsupported",
                            format!(
                                "app `{}` references Fly secret `{secret}`; safe app-secret mutation is not implemented yet",
                                app.name
                            ),
                        ));
                    }
                    return Err(validation(
                        "app_secret_missing",
                        format!("app `{}` secret `{secret}` was not resolved", app.name),
                    ));
                }
            }
        }
        output.insert(app.service.clone(), environment);
    }
    Ok(output)
}

#[derive(Clone, Debug)]
pub struct Identity {
    pub project_id: String,
    pub environment_id: String,
    pub profile: String,
    pub branch: String,
}

impl Identity {
    pub fn from_context(
        context: &OperationContext,
        desired: Option<&DesiredState>,
    ) -> PluginResult<Self> {
        let metadata = ContextMetadata::from_context(context)?;
        let project_id = desired
            .map(|desired| desired.project.id.clone())
            .or(metadata.project_id)
            .ok_or_else(|| {
                validation(
                    "project_id_required",
                    "immutable project ID is required for Fly ownership metadata",
                )
            })?;
        Ok(Self {
            project_id,
            environment_id: context.environment_id.clone(),
            profile: context.profile.clone(),
            branch: desired
                .map(|desired| desired.environment.branch.clone())
                .unwrap_or_default(),
        })
    }

    pub fn metadata(
        &self,
        service: &str,
        role: &str,
        revision: &str,
        expires_at_unix: Option<&str>,
    ) -> BTreeMap<String, String> {
        let mut metadata = BTreeMap::from([
            (MANAGED_KEY.to_owned(), "true".to_owned()),
            (PROJECT_KEY.to_owned(), self.project_id.clone()),
            (ENVIRONMENT_KEY.to_owned(), self.environment_id.clone()),
            (PROFILE_KEY.to_owned(), self.profile.clone()),
            (BRANCH_KEY.to_owned(), self.branch.clone()),
            (SERVICE_KEY.to_owned(), service.to_owned()),
            (ROLE_KEY.to_owned(), role.to_owned()),
            (REVISION_KEY.to_owned(), revision.to_owned()),
        ]);
        if let Some(expires_at_unix) = expires_at_unix {
            metadata.insert(EXPIRES_KEY.to_owned(), expires_at_unix.to_owned());
        }
        metadata
    }
}

pub fn fly_app_name(
    desired: &DesiredState,
    service: &str,
    public_name: Option<&str>,
    settings: &Settings,
) -> String {
    let app = public_name.unwrap_or(service);
    let suffix = short_hash(
        &format!(
            "{}\0{}\0{}\0{}\0{}",
            settings.organization,
            desired.project.id,
            desired.environment.profile,
            desired.environment.branch,
            service
        ),
        RESOURCE_SUFFIX_HEX,
    );
    let prefix = safe_label(&settings.app_prefix, 16);
    let project = format!(
        "p{}",
        project_marker(&desired.project.id, &settings.organization)
    );
    let fixed = prefix.len() + project.len() + suffix.len() + 4;
    let readable = MAX_FLY_NAME.saturating_sub(fixed).max(2);
    let branch_budget = readable.div_ceil(2);
    let app_budget = readable.saturating_sub(branch_budget).max(1);
    let branch = safe_label(&desired.environment.branch, branch_budget);
    let app = safe_label(app, app_budget);
    format!("{prefix}-{project}-{branch}-{app}-{suffix}")
}

pub fn lock_app_name(project_id: &str, settings: &Settings) -> String {
    format!(
        "lightrail-lock-{}",
        project_marker(project_id, &settings.organization)
    )
}

pub fn network_name(project_id: &str, environment_id: &str, settings: &Settings) -> String {
    format!(
        "{}{}",
        network_prefix(project_id, settings),
        short_hash(
            &format!(
                "{}\0{}\0{environment_id}",
                settings.organization, project_id
            ),
            20
        )
    )
}

pub fn network_prefix(project_id: &str, settings: &Settings) -> String {
    format!(
        "lr-net-{}-",
        project_marker(project_id, &settings.organization)
    )
}

pub fn project_app_marker(project_id: &str, settings: &Settings) -> String {
    format!("-p{}-", project_marker(project_id, &settings.organization))
}

fn project_marker(project_id: &str, organization: &str) -> String {
    short_hash(&format!("{organization}\0{project_id}"), PROJECT_MARKER_HEX)
}

pub fn volume_name(environment_id: &str, service: &str, mount: &str) -> String {
    let suffix = short_hash(&format!("{environment_id}\0{service}\0{mount}"), 12);
    truncate_name(
        &format!("lr-{}-{}", safe_label(mount, 24).replace('-', "_"), suffix),
        30,
    )
}

pub fn revision(
    desired: &DesiredState,
    compose: &Value,
    settings: &Settings,
    operation_id: &str,
) -> PluginResult<String> {
    validate_build_sources(desired, compose)?;
    let operation_scoped = desired.environment.dirty
        || compose_has_local_builds(compose)
        || compose_has_resolved_environment(compose)
        || desired.apps.iter().any(|app| !app.environment.is_empty());
    let stable = desired_for_revision(desired);
    let compose = compose_for_revision(compose, desired.project.root.as_deref());
    let mut hash = Sha256::new();
    hash.update(b"lightrail/fly/revision/v3\0");
    hash.update(serde_json::to_vec(&stable).unwrap_or_default());
    hash.update(serde_json::to_vec(&compose).unwrap_or_default());
    hash.update(
        serde_json::to_vec(&json!({
            "platform": settings.platform,
            "cpu_kind": settings.cpu_kind,
            "cpus": settings.cpus,
            "memory_mb": settings.memory_mb,
            "auto_stop": settings.auto_stop,
        }))
        .unwrap_or_default(),
    );
    if operation_scoped {
        // Git and resolved Compose cannot prove all Docker-visible ignored
        // bytes, and resolved environment plaintext must never influence
        // provider-visible revision metadata.
        hash.update(operation_id.as_bytes());
    }
    Ok(hex::encode(hash.finalize()))
}

fn validate_build_sources(desired: &DesiredState, compose: &Value) -> PluginResult<()> {
    let Some(services) = compose.get("services").and_then(Value::as_object) else {
        return Ok(());
    };
    for (service_name, service) in services {
        let Some(build) = service.get("build").filter(|build| !build.is_null()) else {
            continue;
        };
        let build = build.as_object().ok_or_else(|| {
            validation(
                "invalid_compose_build",
                format!("resolved Compose build for service `{service_name}` must be an object"),
            )
        })?;
        let context = build.get("context").and_then(Value::as_str).ok_or_else(|| {
            validation(
                "build_context_required",
                format!(
                    "resolved Compose build for service `{service_name}` must contain a context path"
                ),
            )
        })?;
        let root = desired.project.root.as_deref().ok_or_else(|| {
            validation(
                "project_root_required",
                "Fly builds require the explicitly granted Git project root",
            )
        })?;
        let canonical_root = canonical_source(root, "Git project root")?;
        let context = scoped_source_path(
            root,
            &canonical_root,
            root,
            Path::new(context),
            "build context",
        )?;
        if let Some(dockerfile) = build.get("dockerfile") {
            let dockerfile = dockerfile.as_str().ok_or_else(|| {
                validation(
                    "invalid_compose_dockerfile",
                    format!(
                        "resolved Compose dockerfile for service `{service_name}` must be a path string"
                    ),
                )
            })?;
            scoped_source_path(
                root,
                &canonical_root,
                &context,
                Path::new(dockerfile),
                "build dockerfile",
            )?;
        }
    }
    Ok(())
}

fn scoped_source_path(
    root: &Path,
    canonical_root: &Path,
    base: &Path,
    path: &Path,
    description: &str,
) -> PluginResult<PathBuf> {
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    if !root.is_absolute()
        || root
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
        || candidate
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(validation(
            "build_source_outside_project",
            format!("{description} must remain inside the current Git project root"),
        ));
    }
    let canonical = canonical_source(&candidate, description)?;
    if !canonical.starts_with(canonical_root) {
        return Err(validation(
            "build_source_outside_project",
            format!("{description} must remain inside the current Git project root"),
        ));
    }
    Ok(canonical)
}

fn canonical_source(path: &Path, description: &str) -> PluginResult<PathBuf> {
    std::fs::canonicalize(path).map_err(|_| {
        validation(
            "build_source_unreadable",
            format!("{description} must exist and be readable before a Fly build is planned"),
        )
    })
}

fn desired_for_revision(desired: &DesiredState) -> DesiredState {
    let mut stable = desired.clone();
    stable.resolved_compose_path = None;
    let root = stable.project.root.take();
    for path in &mut stable.project.compose {
        *path = source_relative_path(path, root.as_deref());
    }
    for app in &mut stable.apps {
        for input in app.environment.values_mut() {
            if matches!(input, EnvironmentInput::Literal(_)) {
                *input = EnvironmentInput::Literal("present".to_owned());
            }
        }
    }
    stable
}

fn compose_for_revision(compose: &Value, root: Option<&Path>) -> Value {
    let mut stable = compose.clone();
    let Some(document) = stable.as_object_mut() else {
        return stable;
    };

    // Compose derives these values from the checkout directory. Fly does not
    // use either value: every workload receives its own deterministic App and
    // the environment uses a deterministic custom 6PN.
    document.remove("name");
    if let Some(networks) = document.get_mut("networks").and_then(Value::as_object_mut) {
        if let Some(default) = networks.get_mut("default") {
            *default = Value::Null;
        }
    }
    if let Some(volumes) = document.get_mut("volumes").and_then(Value::as_object_mut) {
        for definition in volumes.values_mut().filter_map(Value::as_object_mut) {
            definition.remove("name");
        }
    }

    if let Some(services) = document.get_mut("services").and_then(Value::as_object_mut) {
        for service in services.values_mut().filter_map(Value::as_object_mut) {
            if let Some(networks) = service.get_mut("networks") {
                if networks
                    .as_object()
                    .is_some_and(|networks| networks.len() == 1 && networks.contains_key("default"))
                    || networks.is_null()
                {
                    *networks = json!({"default": null});
                }
            }
            if let Some(build) = service.get_mut("build").and_then(Value::as_object_mut) {
                for field in ["context", "dockerfile"] {
                    if let Some(value) = build.get_mut(field) {
                        if let Some(path) = value.as_str() {
                            *value = Value::String(path_string(&source_relative_path(
                                Path::new(path),
                                root,
                            )));
                        }
                    }
                }
            }
            if let Some(environment) = service
                .get_mut("environment")
                .and_then(Value::as_object_mut)
            {
                for value in environment.values_mut() {
                    *value = Value::String("present".to_owned());
                }
            }
        }
    }
    stable
}

fn compose_has_local_builds(compose: &Value) -> bool {
    compose
        .get("services")
        .and_then(Value::as_object)
        .is_some_and(|services| {
            services
                .values()
                .any(|service| service.get("build").is_some_and(|build| !build.is_null()))
        })
}

fn compose_has_resolved_environment(compose: &Value) -> bool {
    compose
        .get("services")
        .and_then(Value::as_object)
        .is_some_and(|services| {
            services.values().any(|service| {
                service
                    .get("environment")
                    .is_some_and(|environment| !is_empty(environment))
            })
        })
}

fn source_relative_path(path: &Path, root: Option<&Path>) -> PathBuf {
    root.filter(|_| path.is_absolute())
        .and_then(|root| path.strip_prefix(root).ok())
        .map_or_else(
            || path.to_path_buf(),
            |path| {
                if path.as_os_str().is_empty() {
                    PathBuf::from(".")
                } else {
                    path.to_path_buf()
                }
            },
        )
}

fn path_string(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

pub fn plan_id(metadata: &Value, actions: &[lightrail_plugin_protocol::PlannedAction]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"lightrail/fly/plan/v1\0");
    hash.update(serde_json::to_vec(metadata).unwrap_or_default());
    hash.update(serde_json::to_vec(actions).unwrap_or_default());
    format!("fly-{}", &hex::encode(hash.finalize())[..24])
}

pub fn safe_label(value: &str, maximum: usize) -> String {
    let mut output = String::new();
    let mut hyphen = false;
    for character in value.chars() {
        let character = character.to_ascii_lowercase();
        if character.is_ascii_lowercase() || character.is_ascii_digit() {
            output.push(character);
            hyphen = false;
        } else if !output.is_empty() && !hyphen {
            output.push('-');
            hyphen = true;
        }
    }
    let output = output.trim_matches('-');
    let output = if output.is_empty() { "x" } else { output };
    truncate_name(output, maximum)
}

fn truncate_name(value: &str, maximum: usize) -> String {
    value
        .chars()
        .take(maximum)
        .collect::<String>()
        .trim_matches('-')
        .to_owned()
}

pub fn short_hash(value: &str, length: usize) -> String {
    let digest = hex::encode(Sha256::digest(value.as_bytes()));
    digest[..length.min(digest.len())].to_owned()
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn validate_slug(field: &str, value: &str, maximum: usize) -> PluginResult<()> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || value.starts_with('-')
        || value.ends_with('-')
    {
        return Err(validation(
            "invalid_fly_slug",
            format!("`{field}` must be a lowercase DNS label no longer than {maximum} characters"),
        ));
    }
    Ok(())
}

pub fn validation(code: impl Into<String>, message: impl Into<String>) -> PluginError {
    PluginError::permanent(ErrorKind::Validation, code, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn desired() -> DesiredState {
        DesiredState {
            schema: 1,
            project: ProjectSpec {
                id: "018f6f9f-21aa-7da8-a1b2-31da91ed5148".to_owned(),
                slug: "demo".to_owned(),
                root: None,
                compose: Vec::new(),
            },
            environment: EnvironmentSpec {
                id: "lr-env".to_owned(),
                profile: "preview".to_owned(),
                branch: "feature/login".to_owned(),
                commit: None,
                dirty: false,
                isolation: Isolation::Environment,
                labels: BTreeMap::new(),
            },
            resolved_compose_path: None,
            apps: vec![AppSpec {
                name: "web".to_owned(),
                service: "frontend".to_owned(),
                port: 8080,
                health_path: None,
                health_status: None,
                health_interval_seconds: None,
                health_timeout_seconds: None,
                environment: BTreeMap::new(),
            }],
            destroy: false,
        }
    }

    fn computed_revision(
        desired: &DesiredState,
        compose: &Value,
        settings: &Settings,
        operation_id: &str,
    ) -> String {
        revision(desired, compose, settings, operation_id).expect("revision")
    }

    #[test]
    fn native_name_keeps_branch_before_app_and_adds_identity_hash() {
        let name = fly_app_name(&desired(), "frontend", Some("web"), &Settings::default());
        let branch = name.find("feature-log").expect("branch in readable name");
        let app = name.find("-web-").expect("app in readable name");
        assert!(branch < app);
        assert!(name.starts_with("lr-p"));
        assert_eq!(
            name.rsplit('-').next().map(str::len),
            Some(RESOURCE_SUFFIX_HEX)
        );
        assert!(name.len() <= MAX_FLY_NAME);
    }

    #[test]
    fn native_name_reserves_the_full_identity_suffix_at_maximum_length() {
        let mut desired = desired();
        desired.environment.branch = "x".repeat(200);
        desired.apps[0].name = "y".repeat(200);
        let settings = Settings {
            app_prefix: "abcdefghijklmnop".to_owned(),
            ..Settings::default()
        };
        let name = fly_app_name(
            &desired,
            "service-with-an-extremely-long-name",
            Some(&desired.apps[0].name),
            &settings,
        );
        assert!(name.len() <= MAX_FLY_NAME);
        assert_eq!(
            name.rsplit('-').next().map(str::len),
            Some(RESOURCE_SUFFIX_HEX)
        );
    }

    #[test]
    fn project_identity_names_ignore_mutable_display_prefix() {
        let first = Settings::default();
        let mut second = first.clone();
        second.app_prefix = "preview".to_owned();
        let project = &desired().project.id;
        assert_eq!(
            lock_app_name(project, &first),
            lock_app_name(project, &second)
        );
        assert_eq!(
            network_name(project, "environment", &first),
            network_name(project, "environment", &second)
        );
        assert_eq!(
            project_app_marker(project, &first),
            project_app_marker(project, &second)
        );
    }

    #[test]
    fn provider_identity_names_are_scoped_by_organization() {
        let first = Settings::default();
        let mut second = first.clone();
        second.organization = "team".to_owned();
        let project = &desired().project.id;
        assert_ne!(
            lock_app_name(project, &first),
            lock_app_name(project, &second)
        );
        assert_ne!(
            network_name(project, "environment", &first),
            network_name(project, "environment", &second)
        );
    }

    #[test]
    fn dirty_revision_is_unique_per_operation_but_clean_revision_is_stable() {
        let compose = json!({"services": {"frontend": {"image": "example/web:1"}}});
        let clean = desired();
        let settings = Settings::default();
        assert_eq!(
            computed_revision(&clean, &compose, &settings, "operation-a"),
            computed_revision(&clean, &compose, &settings, "operation-b")
        );
        let mut dirty = clean;
        dirty.environment.dirty = true;
        assert_ne!(
            computed_revision(&dirty, &compose, &settings, "operation-a"),
            computed_revision(&dirty, &compose, &settings, "operation-b")
        );
    }

    #[test]
    fn local_builds_and_resolved_environment_are_operation_scoped() {
        let directory = tempdir().expect("project");
        std::fs::write(directory.path().join("Dockerfile"), b"FROM scratch\n").expect("dockerfile");
        let mut desired = desired();
        desired.project.root = Some(directory.path().to_path_buf());
        let build = json!({
            "services": {
                "frontend": {
                    "build": {
                        "context": directory.path(),
                        "dockerfile": "Dockerfile"
                    }
                }
            }
        });
        assert_ne!(
            computed_revision(&desired, &build, &Settings::default(), "operation-a"),
            computed_revision(&desired, &build, &Settings::default(), "operation-b")
        );

        let first_environment = json!({
            "services": {
                "frontend": {
                    "image": "example/web:1",
                    "environment": {"API_TOKEN": "first-sensitive-value"}
                }
            }
        });
        let second_environment = json!({
            "services": {
                "frontend": {
                    "image": "example/web:1",
                    "environment": {"API_TOKEN": "second-sensitive-value"}
                }
            }
        });
        assert_eq!(
            computed_revision(
                &desired,
                &first_environment,
                &Settings::default(),
                "same-operation"
            ),
            computed_revision(
                &desired,
                &second_environment,
                &Settings::default(),
                "same-operation"
            ),
            "environment plaintext must not influence provider-visible revision metadata"
        );
        assert_ne!(
            computed_revision(
                &desired,
                &first_environment,
                &Settings::default(),
                "operation-a"
            ),
            computed_revision(
                &desired,
                &first_environment,
                &Settings::default(),
                "operation-b"
            )
        );

        let mut first_desired = desired.clone();
        first_desired.apps[0].environment.insert(
            "APP_TOKEN".to_owned(),
            EnvironmentInput::Literal("first-app-sensitive-value".to_owned()),
        );
        let mut second_desired = first_desired.clone();
        second_desired.apps[0].environment.insert(
            "APP_TOKEN".to_owned(),
            EnvironmentInput::Literal("second-app-sensitive-value".to_owned()),
        );
        let external = json!({
            "services": {"frontend": {"image": "example/web:1"}}
        });
        assert_eq!(
            computed_revision(
                &first_desired,
                &external,
                &Settings::default(),
                "same-operation"
            ),
            computed_revision(
                &second_desired,
                &external,
                &Settings::default(),
                "same-operation"
            ),
            "app environment plaintext must not influence revision metadata"
        );
    }

    #[test]
    fn execution_settings_change_revision_but_operational_timeouts_do_not() {
        let compose = json!({"services": {"frontend": {"image": "example/web:1"}}});
        let desired = desired();
        let baseline = Settings::default();
        let baseline_revision = computed_revision(&desired, &compose, &baseline, "operation");
        for changed in [
            Settings {
                platform: "linux/arm64".to_owned(),
                ..baseline.clone()
            },
            Settings {
                cpu_kind: "performance".to_owned(),
                ..baseline.clone()
            },
            Settings {
                cpus: 2,
                ..baseline.clone()
            },
            Settings {
                memory_mb: 512,
                ..baseline.clone()
            },
            Settings {
                auto_stop: false,
                ..baseline.clone()
            },
        ] {
            assert_ne!(
                baseline_revision,
                computed_revision(&desired, &compose, &changed, "operation")
            );
        }
        let operational_only = Settings {
            command_timeout_seconds: baseline.command_timeout_seconds + 1,
            ..baseline.clone()
        };
        assert_eq!(
            baseline_revision,
            computed_revision(&desired, &compose, &operational_only, "operation")
        );
    }

    #[test]
    fn clean_revision_is_portable_across_equivalent_checkout_roots() {
        let first_checkout = tempdir().expect("first checkout");
        let second_parent = tempdir().expect("second checkout parent");
        let second_checkout = second_parent.path().join("nested").join("second");
        for root in [first_checkout.path(), second_checkout.as_path()] {
            std::fs::create_dir_all(root.join("apps/frontend")).expect("build context");
            std::fs::write(root.join("apps/frontend/Dockerfile"), b"FROM scratch\n")
                .expect("dockerfile");
        }

        let mut first = desired();
        first.project.root = Some(first_checkout.path().to_path_buf());
        first.project.compose = vec![PathBuf::from("compose.yaml")];
        first.resolved_compose_path = Some(PathBuf::from("/tmp/resolved-first.json"));
        let first_compose = json!({
            "name": "first-checkout",
            "networks": {
                "default": {
                    "name": "first-checkout_default",
                    "ipam": {}
                }
            },
            "volumes": {
                "data": {"name": "first-checkout_data"}
            },
            "services": {
                "frontend": {
                    "build": {
                        "context": first_checkout.path().join("apps/frontend"),
                        "dockerfile": "Dockerfile"
                    },
                    "networks": {"default": null},
                    "volumes": [{
                        "type": "volume",
                        "source": "data",
                        "target": "/data",
                        "volume": {}
                    }]
                }
            }
        });

        let mut second = first.clone();
        second.project.root = Some(second_checkout.clone());
        second.resolved_compose_path = Some(PathBuf::from("/tmp/resolved-second.json"));
        let second_compose = json!({
            "name": "second",
            "networks": {
                "default": {
                    "name": "second_default",
                    "ipam": {}
                }
            },
            "volumes": {
                "data": {"name": "second_data"}
            },
            "services": {
                "frontend": {
                    "build": {
                        "context": second_checkout.join("apps/frontend"),
                        "dockerfile": "Dockerfile"
                    },
                    "networks": {"default": null},
                    "volumes": [{
                        "type": "volume",
                        "source": "data",
                        "target": "/data",
                        "volume": {}
                    }]
                }
            }
        });

        assert_eq!(
            computed_revision(&first, &first_compose, &Settings::default(), "operation"),
            computed_revision(&second, &second_compose, &Settings::default(), "operation")
        );

        let mut changed_compose = second_compose;
        std::fs::create_dir_all(second_checkout.join("apps/other")).expect("other context");
        std::fs::write(
            second_checkout.join("apps/other/Dockerfile"),
            b"FROM scratch\n",
        )
        .expect("other dockerfile");
        changed_compose["services"]["frontend"]["build"]["context"] =
            Value::String(second_checkout.join("apps/other").display().to_string());
        assert_ne!(
            computed_revision(&first, &first_compose, &Settings::default(), "operation"),
            computed_revision(&second, &changed_compose, &Settings::default(), "operation")
        );
    }

    #[test]
    fn revision_rejects_build_context_and_dockerfile_outside_project() {
        let directory = tempdir().expect("workspace");
        let root = directory.path().join("project");
        let outside = directory.path().join("outside");
        std::fs::create_dir_all(root.join("app")).expect("project context");
        std::fs::create_dir_all(&outside).expect("outside context");
        std::fs::write(root.join("app/Dockerfile"), b"FROM scratch\n").expect("dockerfile");
        std::fs::write(outside.join("Dockerfile"), b"FROM scratch\n").expect("outside dockerfile");
        let mut desired = desired();
        desired.project.root = Some(root.clone());

        let outside_context = json!({
            "services": {
                "frontend": {
                    "build": {
                        "context": outside,
                        "dockerfile": "Dockerfile"
                    }
                }
            }
        });
        assert_eq!(
            revision(
                &desired,
                &outside_context,
                &Settings::default(),
                "operation"
            )
            .expect_err("outside context must fail")
            .code,
            "build_source_outside_project"
        );

        let outside_dockerfile = json!({
            "services": {
                "frontend": {
                    "build": {
                        "context": root.join("app"),
                        "dockerfile": directory.path().join("outside/Dockerfile")
                    }
                }
            }
        });
        assert_eq!(
            revision(
                &desired,
                &outside_dockerfile,
                &Settings::default(),
                "operation"
            )
            .expect_err("outside Dockerfile must fail")
            .code,
            "build_source_outside_project"
        );
    }

    #[test]
    fn desired_root_cannot_exceed_the_context_project_authority() {
        let granted = tempdir().expect("granted root");
        let requested = tempdir().expect("requested root");
        let mut desired = desired();
        desired.project.root = Some(requested.path().to_path_buf());
        let context = OperationContext {
            environment_id: desired.environment.id.clone(),
            profile: desired.environment.profile.clone(),
            project_root: Some(granted.path().display().to_string()),
            ..OperationContext::default()
        };
        let error = DesiredState::parse(serde_json::to_value(desired).expect("desired"), &context)
            .expect_err("desired root must not override context authority");
        assert_eq!(error.code, "project_root_authority_mismatch");
    }

    #[cfg(unix)]
    #[test]
    fn revision_rejects_build_context_symlink_escape() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().expect("workspace");
        let root = directory.path().join("project");
        let outside = directory.path().join("outside");
        std::fs::create_dir_all(&root).expect("project");
        std::fs::create_dir_all(&outside).expect("outside");
        std::fs::write(outside.join("Dockerfile"), b"FROM scratch\n").expect("dockerfile");
        symlink(&outside, root.join("escaped")).expect("symlink");
        let mut desired = desired();
        desired.project.root = Some(root.clone());
        let compose = json!({
            "services": {
                "frontend": {
                    "build": {
                        "context": root.join("escaped"),
                        "dockerfile": "Dockerfile"
                    }
                }
            }
        });
        assert_eq!(
            revision(&desired, &compose, &Settings::default(), "operation")
                .expect_err("symlink escape must fail")
                .code,
            "build_source_outside_project"
        );
    }

    #[test]
    fn workload_accepts_only_normalized_implicit_default_network() {
        let compose = json!({
            "name": "demo",
            "networks": {
                "default": {
                    "name": "demo_default",
                    "ipam": {}
                }
            },
            "services": {
                "frontend": {
                    "image": "example/web:1",
                    "networks": {"default": null}
                }
            }
        });
        workloads(&desired(), &Settings::default(), &compose, "abc")
            .expect("ordinary normalized Compose default network is supported");
    }

    #[test]
    fn workload_rejects_custom_or_optioned_top_level_networks() {
        for (network, expected_code) in [
            (
                json!({
                    "default": {"name": "custom", "ipam": {}}
                }),
                "compose_custom_network_name_unsupported",
            ),
            (
                json!({
                    "default": {"name": "demo_default", "ipam": {}, "external": true}
                }),
                "compose_network_options_unsupported",
            ),
            (
                json!({
                    "default": {
                        "name": "demo_default",
                        "ipam": {"config": [{"subnet": "10.0.0.0/24"}]}
                    }
                }),
                "compose_network_options_unsupported",
            ),
            (
                json!({
                    "default": {"name": "demo_default", "ipam": {}},
                    "backend": {"name": "demo_backend", "ipam": {}}
                }),
                "compose_network_topology_unsupported",
            ),
        ] {
            let compose = json!({
                "name": "demo",
                "networks": network,
                "services": {
                    "frontend": {
                        "image": "example/web:1",
                        "networks": {"default": null}
                    }
                }
            });
            let error = workloads(&desired(), &Settings::default(), &compose, "abc")
                .expect_err("network semantics must not be silently flattened");
            assert_eq!(error.code, expected_code);
        }
    }

    #[test]
    fn workload_rejects_custom_or_optioned_service_networks() {
        for networks in [
            json!({"backend": null}),
            json!({"default": null, "backend": null}),
            json!({"default": {"aliases": ["frontend"]}}),
            json!({"default": {"ipv4_address": "10.0.0.2"}}),
        ] {
            let compose = json!({
                "name": "demo",
                "networks": {
                    "default": {"name": "demo_default", "ipam": {}}
                },
                "services": {
                    "frontend": {
                        "image": "example/web:1",
                        "networks": networks
                    }
                }
            });
            let error = workloads(&desired(), &Settings::default(), &compose, "abc")
                .expect_err("service network semantics must not be silently flattened");
            assert!(
                matches!(
                    error.code.as_str(),
                    "compose_service_network_topology_unsupported"
                        | "compose_service_network_options_unsupported"
                ),
                "unexpected code: {}",
                error.code
            );
        }
    }

    #[test]
    fn workload_rejects_more_than_one_volume() {
        let compose = json!({
            "services": {
                "frontend": {
                    "image": "example/web:1",
                    "volumes": ["one:/one", "two:/two"]
                }
            }
        });
        let error = workloads(&desired(), &Settings::default(), &compose, "abc")
            .expect_err("multiple volumes must fail");
        assert_eq!(error.code, "fly_single_volume_limit");
    }

    #[test]
    fn workload_rejects_untranslated_compose_fields() {
        let compose = json!({
            "services": {
                "frontend": {
                    "image": "example/web:1",
                    "pid": "host"
                }
            }
        });
        let error = workloads(&desired(), &Settings::default(), &compose, "abc")
            .expect_err("unsupported service semantics must fail closed");
        assert_eq!(error.code, "compose_service_fields_unsupported");
    }

    #[test]
    fn workload_rejects_ignored_labels_and_extensions() {
        for (field, value, expected) in [
            (
                "labels",
                json!({"com.example.policy": "required"}),
                "compose_service_labels_unsupported",
            ),
            (
                "x-provider-policy",
                json!({"placement": "special"}),
                "compose_service_extensions_unsupported",
            ),
        ] {
            let mut service = serde_json::Map::from_iter([(
                "image".to_owned(),
                Value::String("example/web:1".to_owned()),
            )]);
            service.insert(field.to_owned(), value);
            let compose = json!({"services": {"frontend": service}});
            let error = workloads(&desired(), &Settings::default(), &compose, "abc")
                .expect_err("ignored Compose metadata must fail closed");
            assert_eq!(error.code, expected);
        }
    }

    #[test]
    fn workload_rejects_untranslated_lightrail_extensions() {
        let compose = json!({
            "services": {
                "frontend": {
                    "image": "example/web:1",
                    "x-lightrail": {"kind": "job"}
                }
            }
        });
        let error = workloads(&desired(), &Settings::default(), &compose, "abc")
            .expect_err("Fly must not silently turn a Lightrail Job into a service");
        assert_eq!(error.code, "fly_x_lightrail_unsupported");
    }

    #[test]
    fn copy_ready_examples_accept_compose_healthchecks_as_source_metadata() {
        let example_healthcheck = json!({
            "test": ["CMD-SHELL", "wget -q -O /dev/null http://host:8080/health"],
            "interval": "5s",
            "timeout": "2s",
            "retries": 12,
            "start_period": "2s"
        });
        let single = json!({
            "services": {
                "web": {
                    "build": {"context": "."},
                    "expose": ["8080"],
                    "healthcheck": example_healthcheck.clone()
                }
            }
        });
        let mut single_desired = desired();
        single_desired.apps[0].service = "web".to_owned();
        workloads(&single_desired, &Settings::default(), &single, "abc")
            .expect("single-app example healthcheck is accepted");

        let mut multi_desired = desired();
        multi_desired.apps.push(AppSpec {
            name: "api".to_owned(),
            service: "api".to_owned(),
            port: 8080,
            health_path: Some("/health".to_owned()),
            health_status: None,
            health_interval_seconds: None,
            health_timeout_seconds: None,
            environment: BTreeMap::new(),
        });
        let multi = json!({
            "services": {
                "frontend": {
                    "build": {"context": "apps/frontend"},
                    "expose": ["8080"],
                    "healthcheck": example_healthcheck.clone()
                },
                "api": {
                    "build": {"context": "apps/api"},
                    "expose": ["8080"],
                    "healthcheck": example_healthcheck
                }
            }
        });
        workloads(&multi_desired, &Settings::default(), &multi, "abc")
            .expect("multi-app example healthchecks are accepted");
    }

    #[test]
    fn workload_rejects_named_volume_options() {
        let compose = json!({
            "services": {
                "frontend": {
                    "image": "example/web:1",
                    "volumes": ["data:/data:ro"]
                }
            }
        });
        let error = workloads(&desired(), &Settings::default(), &compose, "abc")
            .expect_err("untranslated volume options must fail closed");
        assert_eq!(error.code, "fly_volume_options_unsupported");
    }

    #[test]
    fn workload_rejects_top_level_volume_driver_options() {
        let compose = json!({
            "services": {
                "frontend": {
                    "image": "example/web:1",
                    "volumes": ["data:/data"]
                }
            },
            "volumes": {
                "data": {
                    "driver": "local",
                    "driver_opts": {"type": "nfs"}
                }
            }
        });
        let error = workloads(&desired(), &Settings::default(), &compose, "abc")
            .expect_err("untranslated volume drivers must fail closed");
        assert_eq!(error.code, "compose_volume_options_unsupported");
    }

    #[test]
    fn workload_rejects_invalid_or_custom_top_level_volume_shape() {
        let invalid = json!({
            "services": {"frontend": {"image": "example/web:1"}},
            "volumes": ["data"]
        });
        assert_eq!(
            workloads(&desired(), &Settings::default(), &invalid, "abc")
                .expect_err("top-level volumes must be an object")
                .code,
            "invalid_compose_volumes"
        );

        let custom = json!({
            "name": "demo",
            "services": {
                "frontend": {
                    "image": "example/web:1",
                    "volumes": ["data:/data"]
                }
            },
            "volumes": {
                "data": {
                    "name": "shared-data"
                }
            }
        });
        assert_eq!(
            workloads(&desired(), &Settings::default(), &custom, "abc")
                .expect_err("custom volume names imply sharing outside Fly ownership")
                .code,
            "custom_volume_name_unsupported"
        );

        let generated = json!({
            "name": "demo",
            "services": {
                "frontend": {
                    "image": "example/web:1",
                    "volumes": ["data:/data"]
                }
            },
            "volumes": {
                "data": {
                    "name": "demo_data"
                }
            }
        });
        workloads(&desired(), &Settings::default(), &generated, "abc")
            .expect("Compose-generated volume name is environment-owned");
    }

    #[test]
    fn secret_backed_app_environment_never_becomes_plain_machine_env() {
        let mut desired = desired();
        desired.apps[0].environment.insert(
            "TOKEN".to_owned(),
            EnvironmentInput::Secret {
                secret: "preview-token".to_owned(),
            },
        );
        let secrets =
            BTreeMap::from([("preview-token".to_owned(), SecretValue::new("do-not-leak"))]);
        let error = resolve_app_environment(&desired, &secrets)
            .expect_err("secret-backed env must fail closed");
        assert_eq!(error.code, "fly_app_secrets_unsupported");
        assert!(!error.message.contains("do-not-leak"));
    }

    #[test]
    fn lock_ttl_boundary_includes_provider_and_rollback_margins() {
        let too_short = Settings {
            lock_ttl_seconds: 480,
            ..Settings::default()
        };
        assert_eq!(
            too_short
                .validate()
                .expect_err("timeout plus 180 seconds is not enough")
                .code,
            "lock_ttl_too_short"
        );
        Settings {
            lock_ttl_seconds: 481,
            ..Settings::default()
        }
        .validate()
        .expect("one second beyond the strict boundary is valid");
    }
}
