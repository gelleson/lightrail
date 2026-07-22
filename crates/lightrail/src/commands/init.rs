//! `lightrail init` discovery and configuration generation.

use std::{
    collections::BTreeMap,
    fmt,
    path::{Path, PathBuf},
};

use dialoguer::{Input, MultiSelect, Select, theme::ColorfulTheme};
use lightrail_core::{
    App, CONFIG_SCHEMA_VERSION, DnsLabel, Isolation, LightrailConfig, PluginId, PluginPipeline,
    Profile, Project, ProjectId,
};
use serde::{Deserialize, Serialize};

use crate::{
    compose::{ComposeInspector, ComposeInventory, ServiceInventory},
    error::CliError,
    plugin_host::{
        COMPOSE_PLUGIN_ID, FLY_PLUGIN_ID, HETZNER_PLUGIN_ID, KUBERNETES_PLUGIN_ID, SSH_PLUGIN_ID,
    },
    plugin_registry::PluginLock,
    process::TokioCommandRunner,
    workspace::{CONFIG_FILE, ProjectPaths},
};

/// Inputs supplied by the command-line dispatcher.
#[derive(Clone, Debug)]
pub struct InitOptions {
    /// Directory from which repository discovery starts.
    pub start: PathBuf,
    /// First committed profile name.
    pub profile: String,
    /// Optional target override from the command line.
    pub target: Option<TargetKind>,
    /// Optional DNS-domain override from the command line.
    pub dns_domain: Option<String>,
    /// Do not open a terminal prompt.
    pub non_interactive: bool,
    /// Optional TOML or JSON answers file.
    pub answers_file: Option<PathBuf>,
    /// Explicitly permit replacement of an existing `lightrail.toml`.
    pub force: bool,
}

/// Declarative answers accepted by `init --from`.
///
/// TOML uses `[[apps]]` for application entries and `[settings.<capability>]`
/// for opaque plugin settings.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InitAnswers {
    /// Project slug. Defaults to the Compose project name or repository name.
    pub project_slug: Option<String>,
    /// Compose files in merge order, relative to the repository root.
    #[serde(default)]
    pub compose: Vec<PathBuf>,
    /// Target provider. Defaults to generic SSH.
    pub target: Option<TargetKind>,
    /// Isolation override. Defaults to the selected target's supported boundary.
    pub isolation: Option<Isolation>,
    /// Explicit public application routes.
    #[serde(default)]
    pub apps: Vec<AppAnswer>,
    /// IP-derived DNS suffix. Only `sslip.io` and `nip.io` are accepted.
    pub dns_domain: Option<String>,
    /// Opaque settings merged over generated capability defaults.
    #[serde(default)]
    pub settings: BTreeMap<String, toml::Value>,
}

/// One public application answer.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AppAnswer {
    /// Public app name; defaults to `service`.
    #[serde(default)]
    pub name: Option<String>,
    /// Compose service backing this route.
    pub service: String,
    /// Internal container port. Required when the service exposes several.
    #[serde(default)]
    pub port: Option<u16>,
    /// Optional HTTP readiness path.
    #[serde(default)]
    pub health_path: Option<String>,
    /// Optional exact readiness status.
    #[serde(default)]
    pub health_status: Option<u16>,
}

/// Supported initial target choices.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    /// An existing generic Linux host reached with OpenSSH.
    Ssh,
    /// A dedicated Hetzner Cloud server.
    Hetzner,
    /// An existing Kubernetes cluster selected through kubeconfig.
    Kubernetes,
    /// Agentless Fly.io Apps and Machines.
    Fly,
}

impl TargetKind {
    const fn target_plugin(self) -> &'static str {
        match self {
            Self::Ssh => SSH_PLUGIN_ID,
            Self::Hetzner => HETZNER_PLUGIN_ID,
            Self::Kubernetes => KUBERNETES_PLUGIN_ID,
            Self::Fly => FLY_PLUGIN_ID,
        }
    }

    const fn default_isolation(self) -> Isolation {
        match self {
            Self::Ssh => Isolation::Project,
            Self::Hetzner => Isolation::Machine,
            Self::Kubernetes | Self::Fly => Isolation::Environment,
        }
    }
}

impl fmt::Display for TargetKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ssh => formatter.write_str("Generic SSH host"),
            Self::Hetzner => formatter.write_str("Hetzner Cloud"),
            Self::Kubernetes => formatter.write_str("Existing Kubernetes cluster"),
            Self::Fly => formatter.write_str("Fly.io"),
        }
    }
}

/// Stable data returned to human or JSON output renderers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InitSummary {
    pub config_path: PathBuf,
    pub project_id: String,
    pub project_slug: String,
    pub profile: String,
    pub compose: Vec<PathBuf>,
    pub apps: Vec<InitializedApp>,
    pub target: TargetKind,
    pub isolation: Isolation,
    pub dns_domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_detail: Option<String>,
}

/// One app created by initialization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InitializedApp {
    pub name: String,
    pub service: String,
    pub port: u16,
}

/// Discovers the current repository and Compose model, prompts when requested,
/// validates the complete configuration, then writes it atomically.
///
/// # Errors
///
/// Returns an error when Git or Compose discovery fails, answers are invalid,
/// a required tool is missing, prompting fails, or configuration cannot be
/// written safely.
pub async fn run(options: InitOptions) -> Result<InitSummary, CliError> {
    let git = lightrail_core::GitContext::discover(&options.start)
        .map_err(|error| CliError::Usage(error.to_string()))?;
    let root = git.repo_root();
    let paths = ProjectPaths::at(root);
    let _ = existing_project_id(&paths.config, options.force)?;

    let answers = load_answers(options.answers_file.as_deref(), &options.start).await?;
    let discovered = discover_compose_files(root)?;
    let compose =
        choose_compose_files(root, &discovered, &answers.compose, options.non_interactive)?;

    let inspector = ComposeInspector::new(TokioCommandRunner);
    let inventory = inspector.inspect(root, &compose).await?;
    initialize_from_inventory(&options, root, compose, inventory, answers).await
}

/// Completes initialization from an already-resolved Compose inventory.
///
/// This boundary keeps provider-free configuration generation independently
/// testable and lets callers reuse a cached Compose inspection.
///
/// # Errors
///
/// Returns an error when the inventory is unsafe for a remote target, answers
/// do not map to Compose services and ports, validation fails, or project files
/// cannot be written safely.
pub async fn initialize_from_inventory(
    options: &InitOptions,
    root: &Path,
    compose: Vec<PathBuf>,
    inventory: ComposeInventory,
    mut answers: InitAnswers,
) -> Result<InitSummary, CliError> {
    let paths = ProjectPaths::at(root);
    let project_id =
        existing_project_id(&paths.config, options.force)?.unwrap_or_else(ProjectId::new);
    inventory.validate_remote_safety()?;

    let interactive = !options.non_interactive;
    let default_slug = default_project_slug(root, inventory.project_name.as_deref())?;
    let project_slug = choose_project_slug(answers.project_slug.take(), default_slug, interactive)?;
    let target = choose_target(options.target.or(answers.target), interactive)?;
    let isolation = answers
        .isolation
        .unwrap_or_else(|| target.default_isolation());
    validate_target_isolation(target, isolation)?;
    let apps = choose_apps(&inventory, answers.apps, interactive)?;
    let app_names = apps.keys().cloned().collect::<Vec<_>>();
    let dns_domain = options
        .dns_domain
        .as_deref()
        .or(answers.dns_domain.as_deref());
    let settings = build_settings(target, dns_domain, answers.settings, interactive)?;
    let pipeline = build_pipeline(target)?;

    let config = LightrailConfig {
        schema: CONFIG_SCHEMA_VERSION,
        project: Project {
            id: project_id,
            slug: project_slug.clone(),
            compose: compose.clone(),
            default_profile: options.profile.clone(),
        },
        apps,
        profiles: BTreeMap::from([(
            options.profile.clone(),
            Profile {
                isolation,
                apps: app_names,
                pipeline,
                settings,
                env: BTreeMap::new(),
                app_env: BTreeMap::new(),
            },
        )]),
    };
    let encoded = config
        .to_toml_pretty()
        .map_err(|error| CliError::Config(error.to_string()))?;
    write_config(&paths.config, &encoded, options.force).await?;
    ensure_lock_file(&paths.lock).await?;
    ensure_local_state_ignored(root).await?;

    let initialized_apps = config
        .apps
        .iter()
        .map(|(name, app)| InitializedApp {
            name: name.clone(),
            service: app.service.clone(),
            port: app.port,
        })
        .collect();
    let initialized_profile = config
        .profile(&options.profile)
        .expect("the initial profile was inserted above");
    let dns_domain = match target {
        TargetKind::Fly => "fly.dev",
        TargetKind::Kubernetes => initialized_profile
            .settings
            .get("target")
            .and_then(toml::Value::as_table)
            .and_then(|settings| settings.get("dns_domain"))
            .and_then(toml::Value::as_str)
            .unwrap_or("sslip.io"),
        TargetKind::Ssh | TargetKind::Hetzner => initialized_profile
            .settings
            .get("dns")
            .and_then(toml::Value::as_table)
            .and_then(|settings| settings.get("domain"))
            .and_then(toml::Value::as_str)
            .unwrap_or("sslip.io"),
    }
    .to_owned();
    let target_detail = summarize_target(target, initialized_profile.settings.get("target"));
    Ok(InitSummary {
        config_path: paths.config,
        project_id: config.project.id.to_string(),
        project_slug,
        profile: options.profile.clone(),
        compose,
        apps: initialized_apps,
        target,
        isolation,
        dns_domain,
        target_detail,
    })
}

fn summarize_target(target: TargetKind, settings: Option<&toml::Value>) -> Option<String> {
    let settings = settings.and_then(toml::Value::as_table)?;
    match target {
        TargetKind::Ssh => {
            let host = settings.get("host").and_then(toml::Value::as_str)?;
            let user = settings
                .get("user")
                .and_then(toml::Value::as_str)
                .unwrap_or("root");
            Some(format!("{user}@{host}"))
        }
        TargetKind::Hetzner => {
            let server_type = settings
                .get("server_type")
                .and_then(toml::Value::as_str)
                .unwrap_or("cx23");
            let location = settings
                .get("location")
                .and_then(toml::Value::as_str)
                .map_or_else(
                    || "provider-selected location".to_owned(),
                    |location| format!("location {location}"),
                );
            Some(format!("{server_type}, {location}"))
        }
        TargetKind::Kubernetes => {
            let context = settings.get("context").and_then(toml::Value::as_str)?;
            let ingress_class = settings
                .get("ingress_class")
                .and_then(toml::Value::as_str)
                .unwrap_or("not configured");
            Some(format!("context {context}, ingress class {ingress_class}"))
        }
        TargetKind::Fly => {
            let organization = settings
                .get("organization")
                .and_then(toml::Value::as_str)
                .unwrap_or("personal");
            let region = settings
                .get("region")
                .and_then(toml::Value::as_str)
                .map_or_else(
                    || "provider-selected region".to_owned(),
                    |region| format!("region {region}"),
                );
            Some(format!("organization {organization}, {region}"))
        }
    }
}

/// Finds root-level Compose files in deterministic merge-candidate order.
///
/// # Errors
///
/// Returns an error when `root` cannot be read or contains no recognized
/// Compose file.
pub fn discover_compose_files(root: &Path) -> Result<Vec<PathBuf>, CliError> {
    let mut candidates = Vec::new();
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        if is_compose_filename(&name) {
            candidates.push(PathBuf::from(name));
        }
    }
    candidates.sort_by_key(|path| compose_sort_key(path));
    if candidates.is_empty() {
        return Err(CliError::Config(format!(
            "no Compose file found in {}; expected compose.yaml, compose.yml, docker-compose.yaml, or docker-compose.yml",
            root.display()
        )));
    }
    Ok(candidates)
}

async fn load_answers(path: Option<&Path>, start: &Path) -> Result<InitAnswers, CliError> {
    let Some(path) = path else {
        return Ok(InitAnswers::default());
    };
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        start.join(path)
    };
    let source = tokio::fs::read_to_string(&path).await.map_err(|error| {
        CliError::Config(format!(
            "could not read init answers from {}: {error}",
            path.display()
        ))
    })?;
    if path
        .extension()
        .is_some_and(|extension| extension == "json")
    {
        serde_json::from_str(&source).map_err(|error| {
            CliError::Config(format!(
                "could not parse JSON init answers in {}: {error}",
                path.display()
            ))
        })
    } else {
        toml::from_str(&source).map_err(|error| {
            CliError::Config(format!(
                "could not parse TOML init answers in {}: {error}",
                path.display()
            ))
        })
    }
}

fn choose_compose_files(
    root: &Path,
    discovered: &[PathBuf],
    requested: &[PathBuf],
    non_interactive: bool,
) -> Result<Vec<PathBuf>, CliError> {
    if !requested.is_empty() {
        for path in requested {
            let valid = !path.as_os_str().is_empty()
                && !path.is_absolute()
                && path
                    .components()
                    .all(|component| matches!(component, std::path::Component::Normal(_)));
            if !valid || !root.join(path).is_file() {
                return Err(CliError::Config(format!(
                    "Compose file `{}` must be an existing normalized path relative to {}",
                    path.display(),
                    root.display()
                )));
            }
        }
        return Ok(requested.to_vec());
    }

    if non_interactive || discovered.len() == 1 {
        return discovered
            .first()
            .cloned()
            .map(|path| vec![path])
            .ok_or_else(|| CliError::Config("no Compose files were discovered".into()));
    }

    let labels = discovered
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>();
    let defaults = (0..discovered.len())
        .map(|index| index == 0)
        .collect::<Vec<_>>();
    let selected = MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Compose files (merge order follows this list)")
        .items(&labels)
        .defaults(&defaults)
        .interact()
        .map_err(|error| prompt_error(&error))?;
    if selected.is_empty() {
        return Err(CliError::Usage(
            "initialization needs at least one Compose file".into(),
        ));
    }
    Ok(selected
        .into_iter()
        .map(|index| discovered[index].clone())
        .collect())
}

fn choose_project_slug(
    answer: Option<String>,
    default: String,
    interactive: bool,
) -> Result<String, CliError> {
    if let Some(answer) = answer {
        return Ok(answer);
    }
    if !interactive {
        return Ok(default);
    }
    Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("Project slug")
        .default(default)
        .interact_text()
        .map_err(|error| prompt_error(&error))
}

fn choose_target(answer: Option<TargetKind>, interactive: bool) -> Result<TargetKind, CliError> {
    if let Some(answer) = answer {
        return Ok(answer);
    }
    if !interactive {
        return Ok(TargetKind::Ssh);
    }
    let targets = [
        TargetKind::Ssh,
        TargetKind::Hetzner,
        TargetKind::Kubernetes,
        TargetKind::Fly,
    ];
    let selected = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Deployment target")
        .items(&targets)
        .default(0)
        .interact()
        .map_err(|error| prompt_error(&error))?;
    Ok(targets[selected])
}

fn validate_target_isolation(target: TargetKind, isolation: Isolation) -> Result<(), CliError> {
    if isolation == target.default_isolation() {
        return Ok(());
    }
    let supported = match target {
        TargetKind::Ssh => "project",
        TargetKind::Hetzner => "machine",
        TargetKind::Kubernetes | TargetKind::Fly => "environment",
    };
    Err(CliError::Config(format!(
        "{target} supports only `{supported}` isolation"
    )))
}

fn choose_apps(
    inventory: &ComposeInventory,
    answers: Vec<AppAnswer>,
    interactive: bool,
) -> Result<BTreeMap<String, App>, CliError> {
    if !answers.is_empty() {
        let mut apps = BTreeMap::new();
        for answer in answers {
            let (name, app) = app_from_answer(inventory, answer)?;
            if apps.insert(name.clone(), app).is_some() {
                return Err(CliError::Config(format!(
                    "public app name `{name}` occurs more than once"
                )));
            }
        }
        return Ok(apps);
    }

    let candidates = inventory.public_app_candidates();
    if candidates.is_empty() {
        return Err(CliError::Config(
            "Compose has no services with an exposed internal port; add a port or provide explicit [[apps]] answers"
                .into(),
        ));
    }

    let selected = if interactive {
        select_app_candidates(&candidates)?
    } else {
        let likely = candidates
            .iter()
            .copied()
            .filter(|service| likely_public_service(service))
            .collect::<Vec<_>>();
        if likely.is_empty() {
            return Err(CliError::Config(
                "could not safely infer a public app; provide [[apps]] in an init answers file"
                    .into(),
            ));
        }
        likely
    };

    let mut apps = BTreeMap::new();
    for service in selected {
        let port = choose_service_port(service, interactive)?;
        let name = service.name.clone();
        let app = App {
            service: service.name.clone(),
            port,
            health_path: None,
            health_status: None,
            health_interval_seconds: None,
            health_timeout_seconds: None,
            env: BTreeMap::new(),
        };
        if apps.insert(name.clone(), app).is_some() {
            return Err(CliError::Config(format!(
                "public app name `{name}` occurs more than once"
            )));
        }
    }
    Ok(apps)
}

fn select_app_candidates<'a>(
    candidates: &[&'a ServiceInventory],
) -> Result<Vec<&'a ServiceInventory>, CliError> {
    let labels = candidates
        .iter()
        .map(|service| {
            format!(
                "{} ({})",
                service.name,
                service
                    .internal_ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
        .collect::<Vec<_>>();
    let defaults = candidates
        .iter()
        .map(|service| likely_public_service(service))
        .collect::<Vec<_>>();
    let selected = MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Public application services")
        .items(&labels)
        .defaults(&defaults)
        .interact()
        .map_err(|error| prompt_error(&error))?;
    if selected.is_empty() {
        return Err(CliError::Usage(
            "select at least one public application service".into(),
        ));
    }
    Ok(selected
        .into_iter()
        .map(|index| candidates[index])
        .collect())
}

fn choose_service_port(service: &ServiceInventory, interactive: bool) -> Result<u16, CliError> {
    match service.internal_ports.as_slice() {
        [] => Err(CliError::Config(format!(
            "service `{}` has no internal port",
            service.name
        ))),
        [port] => Ok(*port),
        ports if !interactive => Err(CliError::Config(format!(
            "service `{}` exposes multiple ports ({}); choose one in [[apps]] answers",
            service.name,
            ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ))),
        ports => {
            let labels = ports.iter().map(u16::to_string).collect::<Vec<_>>();
            let selected = Select::with_theme(&ColorfulTheme::default())
                .with_prompt(format!("Internal HTTP port for `{}`", service.name))
                .items(&labels)
                .default(0)
                .interact()
                .map_err(|error| prompt_error(&error))?;
            Ok(ports[selected])
        }
    }
}

fn app_from_answer(
    inventory: &ComposeInventory,
    answer: AppAnswer,
) -> Result<(String, App), CliError> {
    let service = inventory.service(&answer.service).ok_or_else(|| {
        CliError::Config(format!(
            "public app refers to unknown Compose service `{}`",
            answer.service
        ))
    })?;
    let port = match answer.port {
        Some(port) if service.internal_ports.contains(&port) => port,
        Some(port) => {
            return Err(CliError::Config(format!(
                "port {port} is not exposed internally by Compose service `{}`",
                answer.service
            )));
        }
        None => match service.internal_ports.as_slice() {
            [port] => *port,
            [] => {
                return Err(CliError::Config(format!(
                    "Compose service `{}` has no internal port",
                    answer.service
                )));
            }
            ports => {
                return Err(CliError::Config(format!(
                    "Compose service `{}` exposes multiple ports ({}); set `port` in its [[apps]] answer",
                    answer.service,
                    ports
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
        },
    };
    let name = answer.name.unwrap_or_else(|| answer.service.clone());
    Ok((
        name,
        App {
            service: answer.service,
            port,
            health_path: answer.health_path,
            health_status: answer.health_status,
            health_interval_seconds: None,
            health_timeout_seconds: None,
            env: BTreeMap::new(),
        },
    ))
}

fn build_pipeline(target: TargetKind) -> Result<PluginPipeline, CliError> {
    let plugin = |identifier: &str| {
        PluginId::new(identifier).map_err(|error| CliError::Config(error.to_string()))
    };
    let provider_native = matches!(target, TargetKind::Kubernetes | TargetKind::Fly);
    let provider = target.target_plugin();
    Ok(PluginPipeline {
        source: plugin(COMPOSE_PLUGIN_ID)?,
        builder: plugin(if provider_native {
            provider
        } else {
            COMPOSE_PLUGIN_ID
        })?,
        target: plugin(provider)?,
        runtime: plugin(if provider_native {
            provider
        } else {
            COMPOSE_PLUGIN_ID
        })?,
        exposure: plugin(if provider_native {
            provider
        } else {
            COMPOSE_PLUGIN_ID
        })?,
        dns: plugin(if provider_native {
            provider
        } else {
            COMPOSE_PLUGIN_ID
        })?,
    })
}

fn build_settings(
    target: TargetKind,
    dns_domain: Option<&str>,
    answers: BTreeMap<String, toml::Value>,
    interactive: bool,
) -> Result<BTreeMap<String, toml::Value>, CliError> {
    let explicit_target_dns_domain = answers
        .get("target")
        .and_then(toml::Value::as_table)
        .map(|target| optional_string_setting(target, "dns_domain", "settings.target.dns_domain"))
        .transpose()?
        .flatten();
    let explicit_target_declares_dns = answers
        .get("target")
        .and_then(toml::Value::as_table)
        .is_some_and(|target| target.contains_key("dns_domain"));
    let target_defaults = match target {
        TargetKind::Ssh => ssh_settings(answers.get("target"), interactive)?,
        TargetKind::Hetzner => hetzner_settings(answers.get("target"), interactive)?,
        TargetKind::Kubernetes => kubernetes_settings(answers.get("target"), interactive)?,
        TargetKind::Fly => fly_settings(answers.get("target"))?,
    };
    let (exposure_defaults, dns_defaults) = match target {
        TargetKind::Ssh | TargetKind::Hetzner => (
            toml::Table::from_iter([
                ("mode".into(), toml::Value::String("public".into())),
                ("tls".into(), toml::Value::String("acme-http-01".into())),
            ]),
            toml::Table::from_iter([
                ("domain".into(), toml::Value::String("sslip.io".into())),
                ("encoding".into(), toml::Value::String("hex-ipv4".into())),
            ]),
        ),
        TargetKind::Kubernetes | TargetKind::Fly => (toml::Table::new(), toml::Table::new()),
    };
    let mut settings = BTreeMap::from([
        ("target".into(), target_defaults),
        ("exposure".into(), toml::Value::Table(exposure_defaults)),
        ("dns".into(), toml::Value::Table(dns_defaults)),
    ]);

    for (capability, answer) in answers {
        merge_value(
            settings
                .entry(capability)
                .or_insert(toml::Value::Table(toml::Table::new())),
            answer,
        );
    }
    match target {
        TargetKind::Hetzner => {
            enforce_target_secret_reference(&mut settings, "hetzner-token")?;
        }
        TargetKind::Fly => {
            enforce_target_secret_reference(&mut settings, "fly-token")?;
        }
        TargetKind::Ssh | TargetKind::Kubernetes => {}
    }

    let dns = settings
        .get_mut("dns")
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| CliError::Config("`settings.dns` must be a table".into()))?;
    if target == TargetKind::Fly {
        if dns_domain.is_some() || !dns.is_empty() || explicit_target_declares_dns {
            return Err(CliError::Config(
                "Fly.io uses its native `fly.dev` hostname; custom DNS settings and `--domain` are not applicable"
                    .into(),
            ));
        }
        return Ok(settings);
    }
    let capability_dns_domain = optional_string_setting(dns, "domain", "settings.dns.domain")?;
    if target == TargetKind::Kubernetes {
        if let Some(key) = dns
            .keys()
            .find(|key| !matches!(key.as_str(), "domain" | "encoding"))
        {
            return Err(CliError::Config(format!(
                "unknown Kubernetes DNS setting `settings.dns.{key}`"
            )));
        }
        if let Some(encoding) = dns.get("encoding") {
            if encoding.as_str() != Some("hex-ipv4") {
                return Err(CliError::Config(
                    "`settings.dns.encoding` must be `hex-ipv4`".into(),
                ));
            }
        }
    }
    if target == TargetKind::Kubernetes
        && dns_domain.is_none()
        && explicit_target_dns_domain.is_some()
        && capability_dns_domain.is_some()
        && explicit_target_dns_domain != capability_dns_domain
    {
        return Err(CliError::Config(
            "`settings.target.dns_domain` and `settings.dns.domain` disagree; keep one value or make them identical"
                .into(),
        ));
    }
    let effective_domain = dns_domain
        .or(explicit_target_dns_domain.as_deref())
        .or(capability_dns_domain.as_deref())
        .unwrap_or("sslip.io");
    let effective_domain = validate_dns_domain(effective_domain)?;
    if target == TargetKind::Kubernetes {
        // The Kubernetes executable owns target, runtime, exposure, and DNS
        // as one aggregate plugin. Core merges settings for those capability
        // slots before every request, so legacy Compose DNS fields would
        // become unknown Kubernetes settings. Accept the old answer shape as
        // input, normalize it into the native target field, and keep the DNS
        // capability table empty.
        dns.clear();
        let target_settings = settings
            .get_mut("target")
            .and_then(toml::Value::as_table_mut)
            .ok_or_else(|| CliError::Config("`settings.target` must be a table".into()))?;
        target_settings.insert("dns_domain".into(), toml::Value::String(effective_domain));
    } else {
        dns.insert("domain".into(), toml::Value::String(effective_domain));
        dns.insert("encoding".into(), toml::Value::String("hex-ipv4".into()));
    }
    Ok(settings)
}

fn optional_string_setting(
    table: &toml::Table,
    key: &str,
    field: &str,
) -> Result<Option<String>, CliError> {
    match table.get(key) {
        None => Ok(None),
        Some(toml::Value::String(value)) if !value.trim().is_empty() => {
            Ok(Some(value.trim().to_owned()))
        }
        Some(_) => Err(CliError::Config(format!(
            "`{field}` must be a non-empty string"
        ))),
    }
}

fn enforce_target_secret_reference(
    settings: &mut BTreeMap<String, toml::Value>,
    secret: &str,
) -> Result<(), CliError> {
    let target = settings
        .get_mut("target")
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| CliError::Config("`settings.target` must be a table".into()))?;
    target.insert(
        "token".into(),
        toml::Value::Table(toml::Table::from_iter([(
            "secret".into(),
            toml::Value::String(secret.to_owned()),
        )])),
    );
    Ok(())
}

fn kubernetes_settings(
    supplied: Option<&toml::Value>,
    interactive: bool,
) -> Result<toml::Value, CliError> {
    let mut table = supplied_table(supplied, "settings.target")?;
    let context = required_setting(&table, "context", interactive, "Kubernetes context", None)?;
    let registry = required_setting(
        &table,
        "registry",
        interactive,
        "OCI registry host",
        Some("ghcr.io"),
    )?;
    let repository = required_setting(
        &table,
        "repository",
        interactive,
        "OCI repository prefix",
        None,
    )?;
    let ingress_class = required_setting(
        &table,
        "ingress_class",
        interactive,
        "Existing Kubernetes IngressClass",
        None,
    )?;
    let ingress_service_namespace = required_setting(
        &table,
        "ingress_service_namespace",
        interactive,
        "Namespace of the LoadBalancer Service backing that IngressClass",
        None,
    )?;
    let ingress_service_name = required_setting(
        &table,
        "ingress_service_name",
        interactive,
        "Name of the LoadBalancer Service backing that IngressClass",
        None,
    )?;

    if let Some(kubeconfig) = table.get("kubeconfig").and_then(toml::Value::as_str) {
        if !Path::new(kubeconfig).is_absolute() {
            return Err(CliError::Config(
                "`settings.target.kubeconfig` must be an absolute path".into(),
            ));
        }
    }

    table.insert("context".into(), toml::Value::String(context));
    table.insert("registry".into(), toml::Value::String(registry));
    table.insert("repository".into(), toml::Value::String(repository));
    table.insert("ingress_class".into(), toml::Value::String(ingress_class));
    table.insert(
        "ingress_service_namespace".into(),
        toml::Value::String(ingress_service_namespace),
    );
    table.insert(
        "ingress_service_name".into(),
        toml::Value::String(ingress_service_name),
    );
    insert_default_string(&mut table, "namespace_prefix", "lr");
    insert_default_string(&mut table, "control_namespace", "lightrail-system");
    insert_default_string(&mut table, "dns_domain", "sslip.io");
    insert_default_string(&mut table, "cluster_issuer", "letsencrypt");
    insert_default_integer(&mut table, "replicas", 1);
    insert_default_integer(&mut table, "ttl_hours", 72);
    insert_default_integer(&mut table, "command_timeout_seconds", 300);
    insert_default_integer(&mut table, "readiness_timeout_seconds", 300);
    validate_kubernetes_init_settings(&table)?;
    Ok(toml::Value::Table(table))
}

fn fly_settings(supplied: Option<&toml::Value>) -> Result<toml::Value, CliError> {
    let mut table = supplied_table(supplied, "settings.target")?;
    insert_default_string(&mut table, "organization", "personal");
    insert_default_string(&mut table, "registry", "registry.fly.io");
    insert_default_string(&mut table, "platform", "linux/amd64");
    insert_default_string(&mut table, "app_prefix", "lr");
    insert_default_string(&mut table, "cpu_kind", "shared");
    insert_default_integer(&mut table, "cpus", 1);
    insert_default_integer(&mut table, "memory_mb", 256);
    insert_default_integer(&mut table, "ttl_hours", 72);
    insert_default_integer(&mut table, "lock_ttl_seconds", 3600);
    table
        .entry("auto_stop")
        .or_insert(toml::Value::Boolean(true));
    table.insert(
        "token".into(),
        toml::Value::Table(toml::Table::from_iter([(
            "secret".into(),
            toml::Value::String("fly-token".into()),
        )])),
    );
    validate_fly_init_settings(&table)?;
    Ok(toml::Value::Table(table))
}

fn supplied_table(supplied: Option<&toml::Value>, field: &str) -> Result<toml::Table, CliError> {
    match supplied {
        None => Ok(toml::Table::new()),
        Some(toml::Value::Table(table)) => Ok(table.clone()),
        Some(_) => Err(CliError::Config(format!("`{field}` must be a table"))),
    }
}

fn required_setting(
    table: &toml::Table,
    key: &str,
    interactive: bool,
    prompt: &str,
    default: Option<&str>,
) -> Result<String, CliError> {
    if let Some(value) = table
        .get(key)
        .and_then(toml::Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        return Ok(value.trim().to_owned());
    }
    if !interactive {
        return Err(CliError::Config(format!(
            "Kubernetes init needs non-empty `settings.target.{key}`"
        )));
    }
    let theme = ColorfulTheme::default();
    let mut input = Input::<String>::with_theme(&theme).with_prompt(prompt);
    if let Some(default) = default {
        input = input.default(default.to_owned());
    }
    let value = input
        .interact_text()
        .map_err(|error| prompt_error(&error))?;
    if value.trim().is_empty() {
        return Err(CliError::Config(format!(
            "`settings.target.{key}` must not be empty"
        )));
    }
    Ok(value.trim().to_owned())
}

fn insert_default_string(table: &mut toml::Table, key: &str, value: &str) {
    table
        .entry(key)
        .or_insert_with(|| toml::Value::String(value.to_owned()));
}

fn insert_default_integer(table: &mut toml::Table, key: &str, value: i64) {
    table.entry(key).or_insert(toml::Value::Integer(value));
}

fn validate_kubernetes_init_settings(table: &toml::Table) -> Result<(), CliError> {
    const ALLOWED: &[&str] = &[
        "context",
        "kubeconfig",
        "registry",
        "repository",
        "ingress_class",
        "ingress_service_namespace",
        "ingress_service_name",
        "namespace_prefix",
        "control_namespace",
        "dns_domain",
        "cluster_issuer",
        "image_pull_secret",
        "platforms",
        "replicas",
        "ttl_hours",
        "traefik_http_entrypoint",
        "traefik_https_entrypoint",
        "command_timeout_seconds",
        "readiness_timeout_seconds",
    ];
    if let Some(key) = table.keys().find(|key| !ALLOWED.contains(&key.as_str())) {
        return Err(CliError::Config(format!(
            "unknown Kubernetes setting `settings.target.{key}`"
        )));
    }

    let context = provider_string(table, "context", "settings.target.context")?;
    validate_safe_provider_argument(context, "settings.target.context", 253)?;

    if let Some(kubeconfig) =
        optional_provider_string(table, "kubeconfig", "settings.target.kubeconfig")?
    {
        let path = Path::new(kubeconfig);
        if !path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
            || kubeconfig.chars().any(char::is_control)
        {
            return Err(CliError::Config(
                "`settings.target.kubeconfig` must be an absolute normalized path without control characters"
                    .into(),
            ));
        }
    }

    let registry = provider_string(table, "registry", "settings.target.registry")?;
    validate_registry_setting(registry)?;
    let repository = provider_string(table, "repository", "settings.target.repository")?;
    validate_repository_setting(repository)?;
    validate_dns_subdomain_setting(
        provider_string(table, "ingress_class", "settings.target.ingress_class")?,
        "settings.target.ingress_class",
    )?;
    validate_dns_subdomain_setting(
        provider_string(
            table,
            "ingress_service_namespace",
            "settings.target.ingress_service_namespace",
        )?,
        "settings.target.ingress_service_namespace",
    )?;
    validate_dns_label_setting(
        provider_string(
            table,
            "ingress_service_name",
            "settings.target.ingress_service_name",
        )?,
        "settings.target.ingress_service_name",
    )?;
    let cleartext_entrypoint = optional_provider_string(
        table,
        "traefik_http_entrypoint",
        "settings.target.traefik_http_entrypoint",
    )?
    .unwrap_or("web");
    let tls_entrypoint = optional_provider_string(
        table,
        "traefik_https_entrypoint",
        "settings.target.traefik_https_entrypoint",
    )?
    .unwrap_or("websecure");
    validate_dns_label_setting(
        cleartext_entrypoint,
        "settings.target.traefik_http_entrypoint",
    )?;
    validate_dns_label_setting(tls_entrypoint, "settings.target.traefik_https_entrypoint")?;
    if cleartext_entrypoint == tls_entrypoint {
        return Err(CliError::Config(
            "Kubernetes Traefik HTTP and HTTPS entrypoints must be distinct".into(),
        ));
    }
    let namespace_prefix = provider_string(
        table,
        "namespace_prefix",
        "settings.target.namespace_prefix",
    )?;
    validate_dns_label_setting(namespace_prefix, "settings.target.namespace_prefix")?;
    if namespace_prefix.len() > 32 {
        return Err(CliError::Config(
            "`settings.target.namespace_prefix` must be at most 32 characters".into(),
        ));
    }
    validate_dns_subdomain_setting(
        provider_string(
            table,
            "control_namespace",
            "settings.target.control_namespace",
        )?,
        "settings.target.control_namespace",
    )?;
    let dns_domain = provider_string(table, "dns_domain", "settings.target.dns_domain")?;
    if !matches!(dns_domain, "sslip.io" | "nip.io") {
        return Err(CliError::Config(
            "`settings.target.dns_domain` must be `sslip.io` or `nip.io`".into(),
        ));
    }
    validate_dns_subdomain_setting(
        provider_string(table, "cluster_issuer", "settings.target.cluster_issuer")?,
        "settings.target.cluster_issuer",
    )?;
    if let Some(secret) = optional_provider_string(
        table,
        "image_pull_secret",
        "settings.target.image_pull_secret",
    )? {
        validate_dns_subdomain_setting(secret, "settings.target.image_pull_secret")?;
    }
    if let Some(platforms) = table.get("platforms") {
        let platforms = platforms.as_array().ok_or_else(|| {
            CliError::Config("`settings.target.platforms` must be an array of strings".into())
        })?;
        let mut seen = std::collections::BTreeSet::new();
        for platform in platforms {
            let platform = platform.as_str().ok_or_else(|| {
                CliError::Config("`settings.target.platforms` entries must be strings".into())
            })?;
            if !matches!(platform, "linux/amd64" | "linux/arm64") || !seen.insert(platform) {
                return Err(CliError::Config(
                    "`settings.target.platforms` may contain unique `linux/amd64` and `linux/arm64` entries only"
                        .into(),
                ));
            }
        }
    }
    validate_integer_range(table, "replicas", 1, 100)?;
    validate_integer_range(table, "ttl_hours", 1, 8_760)?;
    validate_integer_range(table, "command_timeout_seconds", 1, 3_600)?;
    validate_integer_range(table, "readiness_timeout_seconds", 1, 3_600)?;
    Ok(())
}

fn validate_fly_init_settings(table: &toml::Table) -> Result<(), CliError> {
    const ALLOWED: &[&str] = &[
        "organization",
        "region",
        "token",
        "registry",
        "platform",
        "app_prefix",
        "cpu_kind",
        "cpus",
        "memory_mb",
        "auto_stop",
        "lock_ttl_seconds",
        "ttl_hours",
        "volume_size_gb",
        "command_timeout_seconds",
        "readiness_timeout_seconds",
    ];
    if let Some(key) = table.keys().find(|key| !ALLOWED.contains(&key.as_str())) {
        return Err(CliError::Config(format!(
            "unknown Fly.io setting `settings.target.{key}`"
        )));
    }

    validate_fly_slug(
        provider_string(table, "organization", "settings.target.organization")?,
        "settings.target.organization",
        128,
    )?;
    if let Some(region) = optional_provider_string(table, "region", "settings.target.region")? {
        validate_fly_slug(region, "settings.target.region", 16)?;
    }
    validate_fly_slug(
        provider_string(table, "app_prefix", "settings.target.app_prefix")?,
        "settings.target.app_prefix",
        16,
    )?;
    let registry = provider_string(table, "registry", "settings.target.registry")?;
    if registry != "registry.fly.io" {
        return Err(CliError::Config(
            "`settings.target.registry` must be `registry.fly.io` for Fly.io".into(),
        ));
    }
    let platform = provider_string(table, "platform", "settings.target.platform")?;
    if !matches!(platform, "linux/amd64" | "linux/arm64") {
        return Err(CliError::Config(
            "`settings.target.platform` must be `linux/amd64` or `linux/arm64`".into(),
        ));
    }
    let cpu_kind = provider_string(table, "cpu_kind", "settings.target.cpu_kind")?;
    if cpu_kind.trim().is_empty() || cpu_kind.chars().any(char::is_control) {
        return Err(CliError::Config(
            "`settings.target.cpu_kind` must be a non-empty safe string".into(),
        ));
    }
    validate_integer_range(table, "cpus", 1, i64::from(u16::MAX))?;
    let memory_mb = validate_integer_range(table, "memory_mb", 256, i64::from(u32::MAX))?;
    if memory_mb % 256 != 0 {
        return Err(CliError::Config(
            "`settings.target.memory_mb` must be a multiple of 256".into(),
        ));
    }
    provider_boolean(table, "auto_stop", "settings.target.auto_stop")?;
    let lock_ttl = validate_integer_range(table, "lock_ttl_seconds", 60, 86_400)?;
    validate_integer_range(table, "ttl_hours", 1, i64::MAX)?;
    if table.contains_key("volume_size_gb") {
        validate_integer_range(table, "volume_size_gb", 1, i64::from(u32::MAX))?;
    }
    let command_timeout = if table.contains_key("command_timeout_seconds") {
        validate_integer_range(table, "command_timeout_seconds", 10, 3_000)?
    } else {
        300
    };
    let readiness_timeout = if table.contains_key("readiness_timeout_seconds") {
        validate_integer_range(table, "readiness_timeout_seconds", 10, 3_000)?
    } else {
        300
    };
    if lock_ttl <= command_timeout.max(readiness_timeout).saturating_add(180) {
        return Err(CliError::Config(
            "`settings.target.lock_ttl_seconds` must exceed command/readiness timeouts by more than 180 seconds"
                .into(),
        ));
    }
    Ok(())
}

fn provider_string<'a>(
    table: &'a toml::Table,
    key: &str,
    field: &str,
) -> Result<&'a str, CliError> {
    optional_provider_string(table, key, field)?
        .ok_or_else(|| CliError::Config(format!("`{field}` must be a non-empty string")))
}

fn optional_provider_string<'a>(
    table: &'a toml::Table,
    key: &str,
    field: &str,
) -> Result<Option<&'a str>, CliError> {
    match table.get(key) {
        None => Ok(None),
        Some(toml::Value::String(value))
            if !value.is_empty()
                && value == value.trim()
                && !value.chars().any(char::is_control) =>
        {
            Ok(Some(value))
        }
        Some(_) => Err(CliError::Config(format!(
            "`{field}` must be a non-empty string without surrounding whitespace or control characters"
        ))),
    }
}

fn provider_boolean(table: &toml::Table, key: &str, field: &str) -> Result<bool, CliError> {
    table
        .get(key)
        .and_then(toml::Value::as_bool)
        .ok_or_else(|| CliError::Config(format!("`{field}` must be a boolean")))
}

fn validate_integer_range(
    table: &toml::Table,
    key: &str,
    minimum: i64,
    maximum: i64,
) -> Result<i64, CliError> {
    let field = format!("settings.target.{key}");
    let value = table
        .get(key)
        .and_then(toml::Value::as_integer)
        .ok_or_else(|| CliError::Config(format!("`{field}` must be an integer")))?;
    if !(minimum..=maximum).contains(&value) {
        return Err(CliError::Config(format!(
            "`{field}` must be between {minimum} and {maximum}"
        )));
    }
    Ok(value)
}

fn validate_safe_provider_argument(
    value: &str,
    field: &str,
    maximum: usize,
) -> Result<(), CliError> {
    if value.starts_with('-') || value.len() > maximum {
        return Err(CliError::Config(format!(
            "`{field}` is too long or starts with an option prefix"
        )));
    }
    Ok(())
}

fn validate_dns_label_setting(value: &str, field: &str) -> Result<(), CliError> {
    if value.is_empty()
        || value.len() > 63
        || value.starts_with('-')
        || value.ends_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(CliError::Config(format!(
            "`{field}` must be a lowercase DNS label"
        )));
    }
    Ok(())
}

fn validate_dns_subdomain_setting(value: &str, field: &str) -> Result<(), CliError> {
    if value.len() > 253
        || value
            .split('.')
            .any(|label| validate_dns_label_setting(label, field).is_err())
    {
        return Err(CliError::Config(format!(
            "`{field}` must be a lowercase DNS subdomain"
        )));
    }
    Ok(())
}

fn validate_registry_setting(value: &str) -> Result<(), CliError> {
    if !valid_registry_authority(value) {
        return Err(CliError::Config(
            "`settings.target.registry` must be a non-loopback OCI registry host without a URL scheme or path"
                .into(),
        ));
    }
    Ok(())
}

fn valid_registry_authority(value: &str) -> bool {
    if value.is_empty() || value.contains('/') || value.contains("://") {
        return false;
    }
    if value.starts_with('[') {
        return false;
    }

    let (host, port_valid) = match value.bytes().filter(|byte| *byte == b':').count() {
        0 => (value, true),
        1 => value
            .rsplit_once(':')
            .map_or((value, false), |(host, port)| {
                (host, valid_registry_port(port))
            }),
        _ => (value, false),
    };
    if !port_valid
        || host.is_empty()
        || host.eq_ignore_ascii_case("localhost")
        || host.eq_ignore_ascii_case("localhost.localdomain")
    {
        return false;
    }
    if let Ok(address) = host.parse::<std::net::Ipv4Addr>() {
        return !address.is_loopback() && !address.is_unspecified();
    }
    if host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return false;
    }
    host.len() <= 253
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
}

fn valid_registry_port(port: &str) -> bool {
    !port.is_empty() && port.parse::<u16>().is_ok_and(|port| port > 0)
}

fn validate_repository_setting(value: &str) -> Result<(), CliError> {
    if value.starts_with('/')
        || value.ends_with('/')
        || value.split('/').any(|part| {
            part.is_empty()
                || matches!(part, "." | "..")
                || !part.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
                })
        })
    {
        return Err(CliError::Config(
            "`settings.target.repository` must contain lowercase OCI path segments".into(),
        ));
    }
    Ok(())
}

fn validate_fly_slug(value: &str, field: &str, maximum: usize) -> Result<(), CliError> {
    if value.len() > maximum
        || value.starts_with('-')
        || value.ends_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(CliError::Config(format!(
            "`{field}` must be a lowercase provider slug no longer than {maximum} characters"
        )));
    }
    Ok(())
}

fn ssh_settings(
    supplied: Option<&toml::Value>,
    interactive: bool,
) -> Result<toml::Value, CliError> {
    let supplied_table = supplied.and_then(toml::Value::as_table);
    let host = supplied_table
        .and_then(|table| table.get("host"))
        .and_then(toml::Value::as_str)
        .map(ToOwned::to_owned);
    let user = supplied_table
        .and_then(|table| table.get("user"))
        .and_then(toml::Value::as_str)
        .map(ToOwned::to_owned);
    let public_ipv4 = supplied_table
        .and_then(|table| table.get("public_ipv4"))
        .and_then(toml::Value::as_str)
        .map(ToOwned::to_owned);

    let host = match (host, interactive) {
        (Some(host), _) => Some(host),
        (None, true) => Some(
            Input::<String>::with_theme(&ColorfulTheme::default())
                .with_prompt("SSH host or IPv4 address")
                .interact_text()
                .map_err(|error| prompt_error(&error))?,
        ),
        (None, false) => {
            return Err(CliError::Config(
                "generic SSH init needs `settings.target.host` in a non-interactive answers file"
                    .into(),
            ));
        }
    };
    let user = match (user, interactive) {
        (Some(user), _) => Some(user),
        (None, true) => Some(
            Input::<String>::with_theme(&ColorfulTheme::default())
                .with_prompt("SSH user")
                .default("root".into())
                .interact_text()
                .map_err(|error| prompt_error(&error))?,
        ),
        (None, false) => None,
    };
    if host.as_deref().is_some_and(is_localhost_target) {
        return Err(CliError::Config(
            "localhost and loopback SSH targets are not allowed".into(),
        ));
    }
    let host_is_public_ipv4 = host
        .as_deref()
        .and_then(|host| host.parse::<std::net::Ipv4Addr>().ok())
        .is_some_and(is_public_ipv4);
    let public_ipv4 = match (public_ipv4, host_is_public_ipv4, interactive) {
        (Some(address), _, _) => Some(address),
        (None, true, _) => None,
        (None, false, true) => Some(
            Input::<String>::with_theme(&ColorfulTheme::default())
                .with_prompt("Public IPv4 used by sslip.io/nip.io")
                .interact_text()
                .map_err(|error| prompt_error(&error))?,
        ),
        (None, false, false) => {
            return Err(CliError::Config(
                "generic SSH init needs `settings.target.public_ipv4` when host is not itself a public IPv4 address".into(),
            ));
        }
    };
    if let Some(address) = &public_ipv4 {
        let parsed = address.parse::<std::net::Ipv4Addr>().map_err(|_| {
            CliError::Config("`settings.target.public_ipv4` must be an IPv4 address".into())
        })?;
        if !is_public_ipv4(parsed) {
            return Err(CliError::Config(
                "`settings.target.public_ipv4` must be publicly routable".into(),
            ));
        }
    }

    let mut table =
        toml::Table::from_iter([("bootstrap".into(), toml::Value::String("auto".into()))]);
    if let Some(host) = host {
        table.insert("host".into(), toml::Value::String(host));
    }
    if let Some(user) = user {
        table.insert("user".into(), toml::Value::String(user));
    }
    if let Some(public_ipv4) = public_ipv4 {
        table.insert("public_ipv4".into(), toml::Value::String(public_ipv4));
    }
    Ok(toml::Value::Table(table))
}

fn is_localhost_target(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.to_ascii_lowercase().ends_with(".localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn is_public_ipv4(address: std::net::Ipv4Addr) -> bool {
    !(address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_broadcast()
        || address.is_documentation()
        || address.is_unspecified()
        || address.is_multicast()
        || address.octets()[0] == 0)
}

fn hetzner_settings(
    supplied: Option<&toml::Value>,
    interactive: bool,
) -> Result<toml::Value, CliError> {
    let supplied_table = supplied.and_then(toml::Value::as_table);
    let server_type = supplied_table
        .and_then(|table| table.get("server_type"))
        .and_then(toml::Value::as_str)
        .map(ToOwned::to_owned);
    let location = supplied_table
        .and_then(|table| table.get("location"))
        .and_then(toml::Value::as_str)
        .map(ToOwned::to_owned);
    let ssh_keys = supplied_table
        .and_then(|table| table.get("ssh_keys"))
        .map(|value| string_list(value, "settings.target.ssh_keys"))
        .transpose()?;
    let allowed_ssh_cidrs = supplied_table
        .and_then(|table| table.get("allowed_ssh_cidrs"))
        .map(|value| string_list(value, "settings.target.allowed_ssh_cidrs"))
        .transpose()?;

    let server_type = server_type.unwrap_or_else(|| "cx23".into());
    let location = match (location, interactive) {
        (Some(location), _) => Some(location),
        (None, true) => Some("nbg1".into()),
        (None, false) => None,
    };
    let ssh_keys = match (ssh_keys, interactive) {
        (Some(keys), _) if !keys.is_empty() => keys,
        (_, true) => {
            comma_separated_prompt("Hetzner SSH key names or IDs (comma-separated)", "ssh_keys")?
        }
        _ => {
            return Err(CliError::Config(
                "Hetzner init needs at least one `settings.target.ssh_keys` entry".into(),
            ));
        }
    };
    let allowed_ssh_cidrs = match (allowed_ssh_cidrs, interactive) {
        (Some(cidrs), _) if !cidrs.is_empty() => cidrs,
        (_, true) => normalize_interactive_ssh_sources(comma_separated_prompt(
            "IP addresses or CIDRs allowed to reach SSH",
            "allowed_ssh_cidrs",
        )?)?,
        _ => {
            return Err(CliError::Config(
                "Hetzner init needs `settings.target.allowed_ssh_cidrs`; use a narrow source CIDR, never 0.0.0.0/0".into(),
            ));
        }
    };
    validate_ssh_cidrs(&allowed_ssh_cidrs)?;

    let mut table = toml::Table::from_iter([
        ("server_type".into(), toml::Value::String(server_type)),
        (
            "token".into(),
            toml::Value::Table(toml::Table::from_iter([(
                "secret".into(),
                toml::Value::String("hetzner-token".into()),
            )])),
        ),
        ("bootstrap".into(), toml::Value::String("cloud-init".into())),
        (
            "ssh_keys".into(),
            toml::Value::Array(ssh_keys.into_iter().map(toml::Value::String).collect()),
        ),
        (
            "allowed_ssh_cidrs".into(),
            toml::Value::Array(
                allowed_ssh_cidrs
                    .into_iter()
                    .map(toml::Value::String)
                    .collect(),
            ),
        ),
    ]);
    if let Some(location) = location {
        table.insert("location".into(), toml::Value::String(location));
    }
    Ok(toml::Value::Table(table))
}

fn string_list(value: &toml::Value, field: &str) -> Result<Vec<String>, CliError> {
    let values = value
        .as_array()
        .ok_or_else(|| CliError::Config(format!("`{field}` must be an array of strings")))?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.trim().is_empty())
                .map(|value| value.trim().to_owned())
                .ok_or_else(|| {
                    CliError::Config(format!("`{field}` entries must be non-empty strings"))
                })
        })
        .collect()
}

fn comma_separated_prompt(prompt: &str, field: &str) -> Result<Vec<String>, CliError> {
    let value = Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .interact_text()
        .map_err(|error| prompt_error(&error))?;
    let values = value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if values.is_empty() {
        return Err(CliError::Config(format!(
            "`settings.target.{field}` must not be empty"
        )));
    }
    Ok(values)
}

fn validate_ssh_cidrs(cidrs: &[String]) -> Result<(), CliError> {
    for cidr in cidrs {
        let (address, prefix) = cidr.split_once('/').ok_or_else(|| {
            CliError::Config(format!(
                "SSH source `{cidr}` must use CIDR notation such as 198.51.100.42/32"
            ))
        })?;
        let address = address.parse::<std::net::IpAddr>().map_err(|_| {
            CliError::Config(format!("SSH source CIDR `{cidr}` has an invalid address"))
        })?;
        let prefix = prefix.parse::<u8>().map_err(|_| {
            CliError::Config(format!("SSH source CIDR `{cidr}` has an invalid prefix"))
        })?;
        let maximum = if address.is_ipv4() { 32 } else { 128 };
        if prefix > maximum || prefix == 0 {
            return Err(CliError::Config(format!(
                "SSH source CIDR `{cidr}` is invalid or world-open"
            )));
        }
    }
    Ok(())
}

fn normalize_interactive_ssh_sources(sources: Vec<String>) -> Result<Vec<String>, CliError> {
    sources
        .into_iter()
        .map(|source| {
            if source.contains('/') {
                return Ok(source);
            }
            let address = source.parse::<std::net::IpAddr>().map_err(|_| {
                CliError::Config(format!(
                    "SSH source `{source}` must be an IP address or CIDR"
                ))
            })?;
            let prefix = if address.is_ipv4() { 32 } else { 128 };
            Ok(format!("{address}/{prefix}"))
        })
        .collect()
}

fn merge_value(base: &mut toml::Value, overlay: toml::Value) {
    match (base, overlay) {
        (toml::Value::Table(base), toml::Value::Table(overlay)) => {
            for (key, value) in overlay {
                merge_value(
                    base.entry(key)
                        .or_insert_with(|| toml::Value::Table(toml::Table::new())),
                    value,
                );
            }
        }
        (base, overlay) => *base = overlay,
    }
}

fn validate_dns_domain(domain: &str) -> Result<String, CliError> {
    match domain {
        "sslip.io" | "nip.io" => Ok(domain.to_owned()),
        _ => Err(CliError::Config(format!(
            "unsupported DNS domain `{domain}`; use sslip.io or nip.io"
        ))),
    }
}

fn default_project_slug(root: &Path, compose_name: Option<&str>) -> Result<String, CliError> {
    let raw = compose_name
        .filter(|name| !name.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            root.file_name()
                .and_then(|name| name.to_str())
                .map(ToOwned::to_owned)
        })
        .ok_or_else(|| CliError::Config("could not infer a project slug".into()))?;
    DnsLabel::new(&raw)
        .map(|label| label.as_str().to_owned())
        .map_err(|error| CliError::Config(error.to_string()))
}

fn likely_public_service(service: &ServiceInventory) -> bool {
    const PRIVATE_PORTS: [u16; 8] = [3306, 5432, 5672, 6379, 9200, 11211, 27017, 27018];
    const PRIVATE_NAMES: [&str; 9] = [
        "cache", "database", "db", "mongo", "mysql", "postgres", "queue", "rabbitmq", "redis",
    ];
    !PRIVATE_NAMES.contains(&service.name.to_ascii_lowercase().as_str())
        && service
            .internal_ports
            .iter()
            .any(|port| !PRIVATE_PORTS.contains(port))
}

fn existing_project_id(path: &Path, force: bool) -> Result<Option<ProjectId>, CliError> {
    if !path.try_exists()? {
        return Ok(None);
    }
    if !force {
        return Err(CliError::Usage(format!(
            "{} already exists; pass --force to replace it",
            path.display()
        )));
    }
    LightrailConfig::load(path)
        .map(|config| Some(config.project.id))
        .map_err(|error| {
            CliError::Config(format!(
                "refusing to replace invalid existing configuration at {}: {error}",
                path.display()
            ))
        })
}

async fn write_config(path: &Path, contents: &str, force: bool) -> Result<(), CliError> {
    let _ = existing_project_id(path, force)?;
    let project_id = ProjectId::new().simple();
    let temporary = path.with_file_name(format!(".{CONFIG_FILE}.{project_id}.tmp"));
    tokio::fs::write(&temporary, contents).await?;
    if let Err(error) = tokio::fs::rename(&temporary, path).await {
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(error.into());
    }
    Ok(())
}

async fn ensure_local_state_ignored(root: &Path) -> Result<(), CliError> {
    let path = root.join(".gitignore");
    let existing = match tokio::fs::read_to_string(&path).await {
        Ok(existing) => existing,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error.into()),
    };
    if existing
        .lines()
        .map(str::trim)
        .any(|line| matches!(line, ".lightrail" | ".lightrail/"))
    {
        return Ok(());
    }
    let mut updated = existing;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(".lightrail/\n");
    tokio::fs::write(path, updated).await?;
    Ok(())
}

async fn ensure_lock_file(path: &Path) -> Result<(), CliError> {
    if path.is_file() {
        PluginLock::load(path).await?;
    } else {
        PluginLock::default().save(path).await?;
    }
    Ok(())
}

fn is_compose_filename(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let supported_extension = Path::new(name)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("yaml") || extension.eq_ignore_ascii_case("yml")
        });
    supported_extension
        && (lower == "compose.yaml"
            || lower == "compose.yml"
            || lower == "docker-compose.yaml"
            || lower == "docker-compose.yml"
            || lower.starts_with("compose.")
            || lower.starts_with("docker-compose."))
}

fn compose_sort_key(path: &Path) -> (u8, String) {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let priority = match name.as_str() {
        "compose.yaml" => 0,
        "compose.yml" => 1,
        "docker-compose.yaml" => 2,
        "docker-compose.yml" => 3,
        _ => 4,
    };
    (priority, name)
}

fn prompt_error(error: &dialoguer::Error) -> CliError {
    CliError::Operation(format!("interactive prompt failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compose::{ComposeDocument, ComposeService, inventory};
    use serde_json::json;

    fn inventory_fixture() -> ComposeInventory {
        inventory(ComposeDocument {
            name: Some("shop".into()),
            services: BTreeMap::from([
                (
                    "db".into(),
                    ComposeService {
                        image: Some("postgres:17".into()),
                        build: None,
                        ports: Vec::new(),
                        expose: vec![json!("5432/tcp")],
                        volumes: Vec::new(),
                        healthcheck: None,
                        network_mode: None,
                    },
                ),
                (
                    "frontend".into(),
                    ComposeService {
                        image: None,
                        build: Some(json!({"context": "."})),
                        ports: vec![json!({"target": 3000})],
                        expose: Vec::new(),
                        volumes: Vec::new(),
                        healthcheck: Some(json!({"test": ["CMD", "true"]})),
                        network_mode: None,
                    },
                ),
            ]),
        })
    }

    fn options(root: &Path) -> InitOptions {
        InitOptions {
            start: root.to_path_buf(),
            profile: "preview".into(),
            target: None,
            dns_domain: None,
            non_interactive: true,
            answers_file: None,
            force: false,
        }
    }

    fn noninteractive_ssh_answers() -> InitAnswers {
        InitAnswers {
            settings: BTreeMap::from([(
                "target".into(),
                toml::Value::Table(toml::Table::from_iter([(
                    "host".into(),
                    toml::Value::String("8.8.8.8".into()),
                )])),
            )]),
            ..InitAnswers::default()
        }
    }

    #[test]
    fn rejects_world_open_hetzner_ssh_cidr() {
        assert!(validate_ssh_cidrs(&["198.51.100.42/32".into()]).is_ok());
        assert!(validate_ssh_cidrs(&["198.51.100.42".into()]).is_err());
        assert!(validate_ssh_cidrs(&["0.0.0.0/0".into()]).is_err());
        assert!(validate_ssh_cidrs(&["::/0".into()]).is_err());
    }

    #[test]
    fn interactive_ssh_sources_accept_bare_addresses() {
        let normalized = normalize_interactive_ssh_sources(vec![
            "198.51.100.42".into(),
            "2001:db8::1".into(),
            "203.0.113.0/24".into(),
        ])
        .expect("normalize");

        assert_eq!(
            normalized,
            ["198.51.100.42/32", "2001:db8::1/128", "203.0.113.0/24"]
        );
        assert!(validate_ssh_cidrs(&normalized).is_ok());
    }

    #[test]
    fn interactive_hetzner_uses_existing_type_and_location_defaults() {
        let supplied = toml::Value::Table(toml::Table::from_iter([
            (
                "ssh_keys".into(),
                toml::Value::Array(vec![toml::Value::String("developer".into())]),
            ),
            (
                "allowed_ssh_cidrs".into(),
                toml::Value::Array(vec![toml::Value::String("198.51.100.42/32".into())]),
            ),
        ]));

        let settings = hetzner_settings(Some(&supplied), true).expect("settings");
        let settings = settings.as_table().expect("table");
        assert_eq!(
            settings.get("server_type").and_then(toml::Value::as_str),
            Some("cx23")
        );
        assert_eq!(
            settings.get("location").and_then(toml::Value::as_str),
            Some("nbg1")
        );
        assert_eq!(
            summarize_target(
                TargetKind::Hetzner,
                Some(&toml::Value::Table(settings.clone()))
            ),
            Some("cx23, location nbg1".into())
        );
    }

    #[test]
    fn noninteractive_hetzner_can_leave_location_to_the_provider() {
        let supplied = toml::Value::Table(toml::Table::from_iter([
            (
                "ssh_keys".into(),
                toml::Value::Array(vec![toml::Value::String("developer".into())]),
            ),
            (
                "allowed_ssh_cidrs".into(),
                toml::Value::Array(vec![toml::Value::String("198.51.100.42/32".into())]),
            ),
        ]));

        let settings = hetzner_settings(Some(&supplied), false).expect("settings");
        let settings = settings.as_table().expect("table");
        assert!(!settings.contains_key("location"));
        assert_eq!(
            summarize_target(
                TargetKind::Hetzner,
                Some(&toml::Value::Table(settings.clone()))
            ),
            Some("cx23, provider-selected location".into())
        );
    }

    #[test]
    fn bundled_targets_reject_incompatible_isolation_early() {
        assert!(validate_target_isolation(TargetKind::Ssh, Isolation::Project).is_ok());
        assert!(validate_target_isolation(TargetKind::Hetzner, Isolation::Machine).is_ok());
        assert!(validate_target_isolation(TargetKind::Kubernetes, Isolation::Environment).is_ok());
        assert!(validate_target_isolation(TargetKind::Fly, Isolation::Environment).is_ok());
        assert!(validate_target_isolation(TargetKind::Ssh, Isolation::Machine).is_err());
        assert!(validate_target_isolation(TargetKind::Hetzner, Isolation::Project).is_err());
        assert!(validate_target_isolation(TargetKind::Fly, Isolation::Machine).is_err());
    }

    #[test]
    fn kubernetes_settings_require_explicit_cluster_and_registry_boundaries() {
        let supplied = toml::Value::Table(toml::Table::from_iter([
            (
                "context".into(),
                toml::Value::String("rackspace-spot".into()),
            ),
            ("registry".into(), toml::Value::String("ghcr.io".into())),
            (
                "repository".into(),
                toml::Value::String("team/lightrail".into()),
            ),
            ("ingress_class".into(), toml::Value::String("nginx".into())),
            (
                "ingress_service_namespace".into(),
                toml::Value::String("ingress-nginx".into()),
            ),
            (
                "ingress_service_name".into(),
                toml::Value::String("ingress-nginx-controller".into()),
            ),
        ]));

        let generated = build_settings(
            TargetKind::Kubernetes,
            Some("nip.io"),
            BTreeMap::from([("target".into(), supplied.clone())]),
            false,
        )
        .expect("Kubernetes settings");
        let target = generated["target"].as_table().expect("target table");

        assert_eq!(
            target.get("context").and_then(toml::Value::as_str),
            Some("rackspace-spot")
        );
        assert_eq!(
            target.get("dns_domain").and_then(toml::Value::as_str),
            Some("nip.io")
        );
        assert_eq!(
            target
                .get("ingress_service_namespace")
                .and_then(toml::Value::as_str),
            Some("ingress-nginx")
        );
        assert_eq!(
            target
                .get("ingress_service_name")
                .and_then(toml::Value::as_str),
            Some("ingress-nginx-controller")
        );
        assert_eq!(
            target
                .get("control_namespace")
                .and_then(toml::Value::as_str),
            Some("lightrail-system")
        );
        assert_eq!(
            target.get("ttl_hours").and_then(toml::Value::as_integer),
            Some(72)
        );
        assert!(
            generated["dns"]
                .as_table()
                .is_some_and(toml::Table::is_empty),
            "aggregate Kubernetes settings must not contain legacy DNS fields"
        );

        let target_dns = toml::Value::Table(toml::Table::from_iter([
            (
                "context".into(),
                toml::Value::String("rackspace-spot".into()),
            ),
            ("registry".into(), toml::Value::String("ghcr.io".into())),
            (
                "repository".into(),
                toml::Value::String("team/lightrail".into()),
            ),
            ("ingress_class".into(), toml::Value::String("nginx".into())),
            (
                "ingress_service_namespace".into(),
                toml::Value::String("ingress-nginx".into()),
            ),
            (
                "ingress_service_name".into(),
                toml::Value::String("ingress-nginx-controller".into()),
            ),
            ("dns_domain".into(), toml::Value::String("nip.io".into())),
        ]));
        let generated = build_settings(
            TargetKind::Kubernetes,
            None,
            BTreeMap::from([("target".into(), target_dns)]),
            false,
        )
        .expect("target DNS setting");
        assert_eq!(
            generated["target"]
                .as_table()
                .and_then(|target| target.get("dns_domain"))
                .and_then(toml::Value::as_str),
            Some("nip.io")
        );
        assert!(
            generated["dns"]
                .as_table()
                .is_some_and(toml::Table::is_empty)
        );

        let generated = build_settings(
            TargetKind::Kubernetes,
            None,
            BTreeMap::from([
                ("target".into(), supplied.clone()),
                (
                    "dns".into(),
                    toml::Value::Table(toml::Table::from_iter([(
                        "domain".into(),
                        toml::Value::String("nip.io".into()),
                    )])),
                ),
            ]),
            false,
        )
        .expect("capability DNS setting");
        assert_eq!(
            generated["target"]
                .as_table()
                .and_then(|target| target.get("dns_domain"))
                .and_then(toml::Value::as_str),
            Some("nip.io")
        );
        assert!(
            generated["dns"]
                .as_table()
                .is_some_and(toml::Table::is_empty),
            "legacy Kubernetes DNS answers are normalized into target.dns_domain"
        );

        assert!(
            build_settings(
                TargetKind::Kubernetes,
                None,
                BTreeMap::from([
                    ("target".into(), supplied.clone()),
                    (
                        "dns".into(),
                        toml::Value::Table(toml::Table::from_iter([(
                            "provider".into(),
                            toml::Value::String("custom".into()),
                        )])),
                    ),
                ]),
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn kubernetes_init_rejects_invalid_provider_values_before_writing_config() {
        let base = toml::Table::from_iter([
            (
                "context".into(),
                toml::Value::String("rackspace-spot".into()),
            ),
            ("registry".into(), toml::Value::String("ghcr.io".into())),
            (
                "repository".into(),
                toml::Value::String("team/lightrail".into()),
            ),
            ("ingress_class".into(), toml::Value::String("nginx".into())),
            (
                "ingress_service_namespace".into(),
                toml::Value::String("ingress-nginx".into()),
            ),
            (
                "ingress_service_name".into(),
                toml::Value::String("ingress-nginx-controller".into()),
            ),
        ]);
        for (key, value) in [
            ("registry", toml::Value::String("localhost:5000".into())),
            ("registry", toml::Value::String(":5000".into())),
            ("registry", toml::Value::String(".".into())),
            (
                "registry",
                toml::Value::String("registry_with_underscore.example".into()),
            ),
            (
                "ingress_service_namespace",
                toml::Value::String("ingress..nginx".into()),
            ),
            ("ingress_service_name", toml::Value::String(String::new())),
            ("replicas", toml::Value::Integer(0)),
            ("kubeconfig", toml::Value::Integer(42)),
            ("unknown", toml::Value::Boolean(true)),
            (
                "platforms",
                toml::Value::Array(vec![
                    toml::Value::String("linux/amd64".into()),
                    toml::Value::String("linux/amd64".into()),
                ]),
            ),
        ] {
            let mut target = base.clone();
            target.insert(key.into(), value);
            assert!(
                build_settings(
                    TargetKind::Kubernetes,
                    None,
                    BTreeMap::from([("target".into(), toml::Value::Table(target))]),
                    false,
                )
                .is_err(),
                "invalid Kubernetes setting {key} must fail during init"
            );
        }
    }

    #[test]
    fn kubernetes_init_requires_explicit_ingress_service_identity() {
        let base = toml::Table::from_iter([
            (
                "context".into(),
                toml::Value::String("rackspace-spot".into()),
            ),
            ("registry".into(), toml::Value::String("ghcr.io".into())),
            (
                "repository".into(),
                toml::Value::String("team/lightrail".into()),
            ),
            ("ingress_class".into(), toml::Value::String("nginx".into())),
        ]);

        let error = build_settings(
            TargetKind::Kubernetes,
            None,
            BTreeMap::from([("target".into(), toml::Value::Table(base.clone()))]),
            false,
        )
        .expect_err("missing ingress Service namespace");
        assert!(
            error
                .to_string()
                .contains("settings.target.ingress_service_namespace")
        );

        let mut with_namespace = base;
        with_namespace.insert(
            "ingress_service_namespace".into(),
            toml::Value::String("ingress-nginx".into()),
        );
        let error = build_settings(
            TargetKind::Kubernetes,
            None,
            BTreeMap::from([("target".into(), toml::Value::Table(with_namespace))]),
            false,
        )
        .expect_err("missing ingress Service name");
        assert!(
            error
                .to_string()
                .contains("settings.target.ingress_service_name")
        );
    }

    #[test]
    fn kubernetes_registry_and_dns_validators_reject_empty_or_malformed_hosts() {
        assert!(validate_registry_setting("registry.example:5000").is_ok());
        assert!(validate_registry_setting("198.51.100.20:5000").is_ok());
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
            "[::1]:5000",
            "[::]:5000",
            "[::ffff:127.0.0.1]:5000",
            "[2001:db8::20]:5000",
            "2001:db8::20",
        ] {
            assert!(
                validate_registry_setting(registry).is_err(),
                "{registry:?} must not be accepted as a registry host"
            );
        }
        assert!(validate_dns_label_setting("", "field").is_err());
        assert!(validate_dns_subdomain_setting(".nginx", "field").is_err());
        assert!(validate_dns_subdomain_setting("nginx.", "field").is_err());
        assert!(validate_dns_subdomain_setting("nginx..internal", "field").is_err());
    }

    #[test]
    fn fly_settings_use_native_dns_and_a_secret_reference() {
        let generated = build_settings(
            TargetKind::Fly,
            None,
            BTreeMap::from([(
                "target".into(),
                toml::Value::Table(toml::Table::from_iter([(
                    "token".into(),
                    toml::Value::String("must-not-be-committed".into()),
                )])),
            )]),
            false,
        )
        .expect("Fly settings");
        let target = generated["target"].as_table().expect("target table");

        assert!(
            generated["dns"]
                .as_table()
                .is_some_and(toml::Table::is_empty)
        );
        assert_eq!(
            target
                .get("token")
                .and_then(toml::Value::as_table)
                .and_then(|token| token.get("secret"))
                .and_then(toml::Value::as_str),
            Some("fly-token")
        );
        assert!(build_settings(TargetKind::Fly, Some("sslip.io"), BTreeMap::new(), false).is_err());
        assert!(
            build_settings(
                TargetKind::Fly,
                None,
                BTreeMap::from([(
                    "dns".into(),
                    toml::Value::Table(toml::Table::from_iter([(
                        "domain".into(),
                        toml::Value::String("sslip.io".into()),
                    )])),
                )]),
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn fly_init_rejects_values_the_bundled_plugin_cannot_use() {
        for (key, value) in [
            ("registry", toml::Value::String("docker.io".into())),
            ("memory_mb", toml::Value::Integer(300)),
            ("lock_ttl_seconds", toml::Value::Integer(300)),
            ("unknown", toml::Value::Boolean(true)),
        ] {
            assert!(
                build_settings(
                    TargetKind::Fly,
                    None,
                    BTreeMap::from([(
                        "target".into(),
                        toml::Value::Table(toml::Table::from_iter([(key.into(), value)])),
                    )]),
                    false,
                )
                .is_err(),
                "invalid Fly.io setting {key} must fail during init"
            );
        }
    }

    #[test]
    fn fly_lock_ttl_exceeds_the_longest_phase_by_more_than_three_minutes() {
        let target_with_lock_ttl = |lock_ttl_seconds| {
            toml::Value::Table(toml::Table::from_iter([
                ("command_timeout_seconds".into(), toml::Value::Integer(300)),
                (
                    "readiness_timeout_seconds".into(),
                    toml::Value::Integer(300),
                ),
                (
                    "lock_ttl_seconds".into(),
                    toml::Value::Integer(lock_ttl_seconds),
                ),
            ]))
        };

        assert!(
            build_settings(
                TargetKind::Fly,
                None,
                BTreeMap::from([("target".into(), target_with_lock_ttl(480))]),
                false,
            )
            .is_err()
        );
        assert!(
            build_settings(
                TargetKind::Fly,
                None,
                BTreeMap::from([("target".into(), target_with_lock_ttl(481))]),
                false,
            )
            .is_ok()
        );
    }

    #[test]
    fn explicit_dns_choice_wins_and_hex_encoding_cannot_be_overridden() {
        let settings = BTreeMap::from([
            (
                "target".into(),
                toml::Value::Table(toml::Table::from_iter([(
                    "host".into(),
                    toml::Value::String("8.8.8.8".into()),
                )])),
            ),
            (
                "dns".into(),
                toml::Value::Table(toml::Table::from_iter([
                    ("domain".into(), toml::Value::String("sslip.io".into())),
                    ("encoding".into(), toml::Value::String("decimal".into())),
                ])),
            ),
        ]);

        let generated =
            build_settings(TargetKind::Ssh, Some("nip.io"), settings, false).expect("settings");
        let dns = generated["dns"].as_table().expect("DNS table");

        assert_eq!(dns["domain"].as_str(), Some("nip.io"));
        assert_eq!(dns["encoding"].as_str(), Some("hex-ipv4"));
    }

    #[tokio::test]
    async fn answers_create_a_valid_committed_configuration() {
        let temp = tempfile::tempdir().expect("temp");
        tokio::fs::write(temp.path().join("compose.yaml"), "services: {}\n")
            .await
            .expect("fixture");
        let answers = InitAnswers {
            project_slug: Some("storefront".into()),
            compose: Vec::new(),
            target: Some(TargetKind::Ssh),
            isolation: None,
            apps: vec![AppAnswer {
                name: Some("web".into()),
                service: "frontend".into(),
                port: Some(3000),
                health_path: Some("/health".into()),
                health_status: Some(200),
            }],
            dns_domain: Some("nip.io".into()),
            settings: BTreeMap::from([(
                "target".into(),
                toml::Value::Table(toml::Table::from_iter([
                    ("host".into(), toml::Value::String("8.8.8.8".into())),
                    ("user".into(), toml::Value::String("deploy".into())),
                ])),
            )]),
        };

        let summary = initialize_from_inventory(
            &options(temp.path()),
            temp.path(),
            vec![PathBuf::from("compose.yaml")],
            inventory_fixture(),
            answers,
        )
        .await
        .expect("initialize");

        assert_eq!(summary.project_slug, "storefront");
        assert_eq!(summary.apps[0].name, "web");
        assert_eq!(summary.dns_domain, "nip.io");
        assert_eq!(summary.target_detail.as_deref(), Some("deploy@8.8.8.8"));
        let config =
            LightrailConfig::load(temp.path().join(CONFIG_FILE)).expect("valid persisted config");
        assert_eq!(config.apps.len(), 1);
        assert_eq!(config.apps["web"].service, "frontend");
        let profile = config.default_profile().expect("default").1;
        assert_eq!(profile.isolation, Isolation::Project);
        assert_eq!(profile.pipeline.target.as_str(), SSH_PLUGIN_ID);
        assert_eq!(
            profile.settings["dns"].as_table().expect("table")["domain"].as_str(),
            Some("nip.io")
        );
        assert!(
            tokio::fs::read_to_string(temp.path().join(".gitignore"))
                .await
                .expect("gitignore")
                .contains(".lightrail/")
        );
        assert_eq!(
            PluginLock::load(&temp.path().join("lightrail.lock"))
                .await
                .expect("lock"),
            PluginLock::default()
        );
    }

    #[tokio::test]
    async fn inventory_boundary_applies_cli_target_and_domain_overrides() {
        let temp = tempfile::tempdir().expect("temp");
        tokio::fs::write(temp.path().join("compose.yaml"), "services: {}\n")
            .await
            .expect("fixture");
        let mut init_options = options(temp.path());
        init_options.target = Some(TargetKind::Ssh);
        init_options.dns_domain = Some("nip.io".into());
        let mut answers = noninteractive_ssh_answers();
        answers.target = Some(TargetKind::Hetzner);
        answers.dns_domain = Some("sslip.io".into());

        let summary = initialize_from_inventory(
            &init_options,
            temp.path(),
            vec![PathBuf::from("compose.yaml")],
            inventory_fixture(),
            answers,
        )
        .await
        .expect("initialize with CLI overrides");

        assert_eq!(summary.target, TargetKind::Ssh);
        assert_eq!(summary.isolation, Isolation::Project);
        assert_eq!(summary.dns_domain, "nip.io");
    }

    #[tokio::test]
    async fn init_refuses_to_overwrite_without_explicit_force() {
        let temp = tempfile::tempdir().expect("temp");
        tokio::fs::write(temp.path().join("compose.yaml"), "services: {}\n")
            .await
            .expect("fixture");
        let first = options(temp.path());
        initialize_from_inventory(
            &first,
            temp.path(),
            vec![PathBuf::from("compose.yaml")],
            inventory_fixture(),
            noninteractive_ssh_answers(),
        )
        .await
        .expect("first init");
        let error = initialize_from_inventory(
            &first,
            temp.path(),
            vec![PathBuf::from("compose.yaml")],
            inventory_fixture(),
            noninteractive_ssh_answers(),
        )
        .await
        .expect_err("must refuse");
        assert!(error.to_string().contains("--force"));

        let mut forced = first;
        forced.force = true;
        initialize_from_inventory(
            &forced,
            temp.path(),
            vec![PathBuf::from("compose.yaml")],
            inventory_fixture(),
            noninteractive_ssh_answers(),
        )
        .await
        .expect("forced replacement");
    }

    #[tokio::test]
    async fn force_reconfiguration_preserves_project_id() {
        let temp = tempfile::tempdir().expect("temp");
        tokio::fs::write(temp.path().join("compose.yaml"), "services: {}\n")
            .await
            .expect("fixture");
        let initial = options(temp.path());
        initialize_from_inventory(
            &initial,
            temp.path(),
            vec![PathBuf::from("compose.yaml")],
            inventory_fixture(),
            noninteractive_ssh_answers(),
        )
        .await
        .expect("initial configuration");
        let original = LightrailConfig::load(temp.path().join(CONFIG_FILE)).expect("original");

        let mut forced = options(temp.path());
        forced.force = true;
        let mut answers = noninteractive_ssh_answers();
        answers.project_slug = Some("renamed-shop".into());
        let summary = initialize_from_inventory(
            &forced,
            temp.path(),
            vec![PathBuf::from("compose.yaml")],
            inventory_fixture(),
            answers,
        )
        .await
        .expect("forced reconfiguration");
        let replaced = LightrailConfig::load(temp.path().join(CONFIG_FILE)).expect("replacement");

        assert_eq!(replaced.project.id, original.project.id);
        assert_eq!(summary.project_id, original.project.id.to_string());
        assert_eq!(replaced.project.slug, "renamed-shop");
    }

    #[tokio::test]
    async fn force_reconfiguration_refuses_an_invalid_existing_config() {
        let temp = tempfile::tempdir().expect("temp");
        tokio::fs::write(temp.path().join("compose.yaml"), "services: {}\n")
            .await
            .expect("fixture");
        let invalid = "schema = [\n";
        tokio::fs::write(temp.path().join(CONFIG_FILE), invalid)
            .await
            .expect("invalid config");
        let mut forced = options(temp.path());
        forced.force = true;

        let error = initialize_from_inventory(
            &forced,
            temp.path(),
            vec![PathBuf::from("compose.yaml")],
            inventory_fixture(),
            noninteractive_ssh_answers(),
        )
        .await
        .expect_err("invalid existing config must be preserved");

        assert!(
            error
                .to_string()
                .contains("refusing to replace invalid existing configuration")
        );
        assert_eq!(
            tokio::fs::read_to_string(temp.path().join(CONFIG_FILE))
                .await
                .expect("preserved config"),
            invalid
        );
    }

    #[test]
    fn compose_discovery_prefers_canonical_base_file() {
        let temp = tempfile::tempdir().expect("temp");
        std::fs::write(temp.path().join("compose.prod.yaml"), "").expect("fixture");
        std::fs::write(temp.path().join("docker-compose.yml"), "").expect("fixture");
        std::fs::write(temp.path().join("compose.yaml"), "").expect("fixture");
        std::fs::write(temp.path().join("notes.yaml"), "").expect("fixture");

        let files = discover_compose_files(temp.path()).expect("discover");

        assert_eq!(
            files,
            vec![
                PathBuf::from("compose.yaml"),
                PathBuf::from("docker-compose.yml"),
                PathBuf::from("compose.prod.yaml"),
            ]
        );
    }

    #[test]
    fn detected_apps_use_service_names_and_keep_private_database_internal() {
        let apps = choose_apps(&inventory_fixture(), Vec::new(), false).expect("apps");

        assert_eq!(apps.len(), 1);
        assert!(apps.contains_key("frontend"));
        assert_eq!(apps["frontend"].service, "frontend");
        assert!(!apps.contains_key("db"));
    }

    #[test]
    fn localhost_targets_are_rejected_during_initialization() {
        for host in ["localhost", "api.localhost", "127.0.0.1", "::1"] {
            assert!(is_localhost_target(host));
        }
        assert!(!is_localhost_target("server.example.com"));
    }
}
