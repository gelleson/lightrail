use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    io::{self, IsTerminal},
    path::{Path, PathBuf},
};

use dialoguer::Password;
use lightrail_core::{LightrailConfig, SecretName};
use lightrail_plugin_protocol::{InitializeRequest, PluginClient, PluginManifest, SpawnOptions};
use secrecy::SecretString;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    cli::{PluginCommand, SecretCommand},
    doctor::{CheckStatus, Doctor, DoctorCheck, DoctorReport},
    error::CliError,
    output::{self, OutputFormat},
    plugin_host::PluginResolver,
    plugin_registry::{LockedPlugin, PluginLock, PluginStore, sha256_file},
    process::TokioCommandRunner,
    project::LoadedProject,
    secrets::{KeyringBackend, SecretStore},
    workspace::ProjectPaths,
};

#[derive(Debug, Serialize)]
struct SecretResult<'a> {
    name: &'a str,
    stored: bool,
}

#[derive(Debug, Serialize)]
struct PluginStatus {
    #[serde(flatten)]
    locked: LockedPlugin,
    installed: bool,
}

#[derive(Debug, Serialize)]
struct PluginInspection {
    #[serde(flatten)]
    status: PluginStatus,
    manifest: Option<PluginManifest>,
}

pub async fn doctor(
    format: OutputFormat,
    check_target: bool,
    selected_profile: Option<&str>,
) -> Result<DoctorReport, CliError> {
    let mut report = Doctor::new(TokioCommandRunner).local().await;
    if check_target {
        let target_check = match LoadedProject::discover(selected_profile) {
            Ok(project) => match crate::orchestrator::inspect_target(project).await {
                Ok(inspection) => DoctorCheck {
                    name: "target",
                    status: target_check_status(inspection.status),
                    detail: format!("{:?}", inspection.status),
                    remediation: (target_check_status(inspection.status) == CheckStatus::Failed)
                        .then_some("Check the selected profile credentials and target settings."),
                },
                Err(error) => DoctorCheck {
                    name: "target",
                    status: CheckStatus::Failed,
                    detail: error.to_string(),
                    remediation: Some(
                        "Check the selected profile credentials and target settings.",
                    ),
                },
            },
            Err(error) => DoctorCheck {
                name: "target",
                status: CheckStatus::Failed,
                detail: error.to_string(),
                remediation: Some("Run this command inside an initialized Lightrail project."),
            },
        };
        report.checks.push(target_check);
    }
    match format {
        OutputFormat::Json => output::json(&report)?,
        OutputFormat::Plain => {
            for check in &report.checks {
                output::line(format!(
                    "{}\t{}",
                    check.name,
                    if check.status == crate::doctor::CheckStatus::Ok {
                        "ok"
                    } else {
                        "failed"
                    }
                ))?;
            }
        }
        OutputFormat::Human => {
            for check in &report.checks {
                let detail = if check.name == "target" {
                    check.detail.to_ascii_lowercase()
                } else {
                    check.detail.clone()
                };
                output::line(format!(
                    "{:<16} {:<6} {}",
                    check.name,
                    if check.status == crate::doctor::CheckStatus::Ok {
                        "ok"
                    } else {
                        "failed"
                    },
                    detail
                ))?;
                if let Some(remediation) = check.remediation {
                    output::line(format!("  help: {remediation}"))?;
                }
            }
        }
    }
    Ok(report)
}

const fn target_check_status(status: lightrail_plugin_protocol::ResourceStatus) -> CheckStatus {
    match status {
        // A machine-isolated provider is expected to be absent before the
        // first `up`; a successful absent inspection still proves that plugin
        // configuration and provider credentials work.
        lightrail_plugin_protocol::ResourceStatus::Ready
        | lightrail_plugin_protocol::ResourceStatus::Absent => CheckStatus::Ok,
        lightrail_plugin_protocol::ResourceStatus::Pending
        | lightrail_plugin_protocol::ResourceStatus::Degraded
        | lightrail_plugin_protocol::ResourceStatus::Destroying
        | lightrail_plugin_protocol::ResourceStatus::Unknown => CheckStatus::Failed,
    }
}

pub async fn secret(command: SecretCommand, format: OutputFormat) -> Result<(), CliError> {
    let paths = discover_project()?;
    let config = load_config(&paths)?;
    let store = SecretStore::new(KeyringBackend, config.project.id.to_string(), &paths.local);

    match command {
        SecretCommand::Set { name, stdin } => {
            validate_secret_name(&name)?;
            let value = if stdin {
                let mut value = String::new();
                tokio::io::stdin().read_to_string(&mut value).await?;
                while value.ends_with(['\r', '\n']) {
                    value.pop();
                }
                if value.is_empty() {
                    return Err(CliError::Usage(
                        "refusing to store an empty secret from stdin".into(),
                    ));
                }
                value
            } else {
                if !io::stdin().is_terminal() {
                    return Err(CliError::Usage(
                        "`secret set` requires a terminal or `--stdin`".into(),
                    ));
                }
                Password::new()
                    .with_prompt(format!("Secret {name}"))
                    .with_confirmation("Confirm secret", "secret values did not match")
                    .interact()
                    .map_err(|error| {
                        CliError::Operation(format!("could not read secret: {error}"))
                    })?
            };
            store.set(&name, SecretString::from(value)).await?;
            match format {
                OutputFormat::Json => output::json(&SecretResult {
                    name: &name,
                    stored: true,
                }),
                OutputFormat::Human | OutputFormat::Plain => {
                    output::line(format!("stored secret `{name}`"))
                }
            }
        }
        SecretCommand::List => {
            let names = store.list().await?;
            match format {
                OutputFormat::Json => output::json(&names),
                OutputFormat::Plain => {
                    for name in names {
                        output::line(name)?;
                    }
                    Ok(())
                }
                OutputFormat::Human if names.is_empty() => output::line("No stored secrets."),
                OutputFormat::Human => {
                    for name in names {
                        output::line(name)?;
                    }
                    Ok(())
                }
            }
        }
        SecretCommand::Delete { name } => {
            validate_secret_name(&name)?;
            store.delete(&name).await?;
            match format {
                OutputFormat::Json => output::json(&SecretResult {
                    name: &name,
                    stored: false,
                }),
                OutputFormat::Human | OutputFormat::Plain => {
                    output::line(format!("deleted secret `{name}`"))
                }
            }
        }
    }
}

pub async fn plugin(command: PluginCommand, format: OutputFormat) -> Result<(), CliError> {
    let paths = discover_project()?;
    let store = PluginStore::from_os()?;
    match command {
        PluginCommand::Install { source } => {
            let locked = inspect_source(&source, &paths).await?;
            let mut lock = load_lock_or_default(&paths.lock).await?;
            if lock.plugins.iter().any(|plugin| plugin.id == locked.id) {
                return Err(CliError::Usage(format!(
                    "plugin `{}` is already pinned; use `plugin update {}`",
                    locked.id, locked.id
                )));
            }
            store.install(&locked, &paths.root).await?;
            lock.plugins.push(locked.clone());
            lock.plugins.sort_by(|left, right| left.id.cmp(&right.id));
            lock.save(&paths.lock).await?;
            print_plugin_status(
                &PluginStatus {
                    locked,
                    installed: true,
                },
                format,
            )
        }
        PluginCommand::Sync => {
            let lock = load_lock_or_default(&paths.lock).await?;
            let mut statuses = Vec::new();
            for plugin in lock.plugins {
                store.install(&plugin, &paths.root).await?;
                statuses.push(PluginStatus {
                    locked: plugin,
                    installed: true,
                });
            }
            if statuses.is_empty() && format == OutputFormat::Human {
                output::line("No third-party plugins are pinned.")
            } else {
                print_plugin_statuses(&statuses, format)
            }
        }
        PluginCommand::List => {
            let lock = load_lock_or_default(&paths.lock).await?;
            let mut statuses = Vec::new();
            for plugin in lock.plugins {
                let installed = store.is_installed(&plugin).await?;
                statuses.push(PluginStatus {
                    locked: plugin,
                    installed,
                });
            }
            if statuses.is_empty() && format == OutputFormat::Human {
                output::line("No third-party plugins are pinned.")
            } else {
                print_plugin_statuses(&statuses, format)
            }
        }
        PluginCommand::Inspect { id } => {
            let lock = load_lock_or_default(&paths.lock).await?;
            let locked = lock
                .plugins
                .into_iter()
                .find(|plugin| plugin.id == id)
                .ok_or_else(|| CliError::Usage(format!("plugin `{id}` is not pinned")))?;
            let installed = store.is_installed(&locked).await?;
            let manifest = if installed {
                let resolver = PluginResolver::with_store(paths.clone(), store.clone());
                let session = resolver.spawn(&id).await?;
                let manifest = session.manifest.clone();
                session.shutdown().await?;
                Some(manifest)
            } else {
                None
            };
            let inspection = PluginInspection {
                status: PluginStatus { locked, installed },
                manifest,
            };
            match format {
                OutputFormat::Json => output::json(&inspection),
                OutputFormat::Plain | OutputFormat::Human => {
                    print_plugin_status(&inspection.status, format)?;
                    if let Some(manifest) = inspection.manifest {
                        output::line(format!(
                            "  capabilities: {}",
                            manifest
                                .capabilities
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(", ")
                        ))?;
                    }
                    Ok(())
                }
            }
        }
        PluginCommand::Update { id } => {
            let mut lock = load_lock_or_default(&paths.lock).await?;
            let index = lock
                .plugins
                .iter()
                .position(|plugin| plugin.id == id)
                .ok_or_else(|| CliError::Usage(format!("plugin `{id}` is not pinned")))?;
            let source = lock.plugins[index].source.clone();
            let updated = inspect_source(&source, &paths).await?;
            if updated.id != id {
                return Err(CliError::Plugin(format!(
                    "updated source changed identity from `{id}` to `{}`",
                    updated.id
                )));
            }
            store.install(&updated, &paths.root).await?;
            lock.plugins[index] = updated.clone();
            lock.save(&paths.lock).await?;
            print_plugin_status(
                &PluginStatus {
                    locked: updated,
                    installed: true,
                },
                format,
            )
        }
        PluginCommand::Remove { id } => {
            let mut lock = load_lock_or_default(&paths.lock).await?;
            let index = lock
                .plugins
                .iter()
                .position(|plugin| plugin.id == id)
                .ok_or_else(|| CliError::Usage(format!("plugin `{id}` is not pinned")))?;
            let plugin = lock.plugins.remove(index);
            store.remove(&plugin).await?;
            lock.save(&paths.lock).await?;
            match format {
                OutputFormat::Json => output::json(&serde_json::json!({
                    "id": id,
                    "removed": true,
                })),
                OutputFormat::Human | OutputFormat::Plain => {
                    output::line(format!("removed plugin `{id}`"))
                }
            }
        }
    }
}

fn discover_project() -> Result<ProjectPaths, CliError> {
    ProjectPaths::discover(&env::current_dir()?)
}

fn load_config(paths: &ProjectPaths) -> Result<LightrailConfig, CliError> {
    LightrailConfig::load(&paths.config).map_err(|error| CliError::Config(error.to_string()))
}

fn validate_secret_name(name: &str) -> Result<(), CliError> {
    SecretName::new(name)
        .map(|_| ())
        .map_err(|error| CliError::Usage(error.to_string()))
}

async fn inspect_source(source: &str, paths: &ProjectPaths) -> Result<LockedPlugin, CliError> {
    paths.ensure_local_layout().await?;
    let probe_directory = paths.local.join("cache/plugin-probe");
    tokio::fs::create_dir_all(&probe_directory).await?;
    let probe = probe_directory.join(format!("plugin-{}", UuidName::new()));
    if source.starts_with("http://") {
        return Err(CliError::Config(
            "plugin sources must use HTTPS or a local path".into(),
        ));
    }
    if source.starts_with("https://") {
        download(source, &probe).await?;
    } else {
        let local = resolve_local_source(source, &paths.root)?;
        tokio::fs::copy(local, &probe).await?;
    }
    make_executable(&probe).await?;
    let checksum = sha256_file(&probe).await?;
    let manifest_result = probe_manifest(&probe, &paths.root).await;
    let _ = tokio::fs::remove_file(&probe).await;
    let manifest = manifest_result?;
    let locked = LockedPlugin {
        id: manifest.id,
        version: manifest.version,
        protocol: manifest.protocol.version.to_string(),
        source: source.to_owned(),
        sha256: checksum,
    };
    locked.validate()?;
    Ok(locked)
}

async fn probe_manifest(path: &Path, project_root: &Path) -> Result<PluginManifest, CliError> {
    let mut options = SpawnOptions::new(path);
    options.current_dir = Some(project_root.to_path_buf());
    options.env = probe_environment();
    let client = PluginClient::spawn(options)
        .await
        .map_err(|error| CliError::Plugin(format!("start candidate plugin: {error}")))?;
    let initialized = client
        .initialize(InitializeRequest::current(env!("CARGO_PKG_VERSION")))
        .await
        .map_err(|error| CliError::Plugin(format!("inspect candidate plugin: {error}")));
    let shutdown = client.shutdown().await;
    match (initialized, shutdown) {
        (Ok(result), Ok(())) => Ok(result.manifest),
        (Ok(_), Err(error)) => Err(CliError::Plugin(error.to_string())),
        (Err(error), _) => Err(error),
    }
}

fn probe_environment() -> BTreeMap<OsString, OsString> {
    let mut values = BTreeMap::new();
    for key in ["PATH", "HOME", "TMPDIR"] {
        if let Some(value) = env::var_os(key) {
            values.insert(OsString::from(key), value);
        }
    }
    values
}

async fn download(source: &str, destination: &Path) -> Result<(), CliError> {
    let response = reqwest::Client::builder()
        .user_agent(concat!("lightrail/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| CliError::Plugin(error.to_string()))?
        .get(source)
        .send()
        .await
        .map_err(|error| CliError::Plugin(format!("download `{source}`: {error}")))?
        .error_for_status()
        .map_err(|error| CliError::Plugin(format!("download `{source}`: {error}")))?;
    let mut stream = response;
    let mut file = tokio::fs::File::create(destination).await?;
    while let Some(bytes) = stream
        .chunk()
        .await
        .map_err(|error| CliError::Plugin(format!("download `{source}`: {error}")))?
    {
        file.write_all(&bytes).await?;
    }
    file.sync_all().await?;
    Ok(())
}

fn resolve_local_source(source: &str, root: &Path) -> Result<PathBuf, CliError> {
    let source = source.strip_prefix("file:").unwrap_or(source);
    let path = PathBuf::from(source);
    let resolved = if path.is_absolute() {
        path
    } else {
        root.join(path)
    };
    if !resolved.is_file() {
        return Err(CliError::Plugin(format!(
            "plugin source does not exist: {}",
            resolved.display()
        )));
    }
    Ok(resolved)
}

async fn load_lock_or_default(path: &Path) -> Result<PluginLock, CliError> {
    match PluginLock::load(path).await {
        Ok(lock) => Ok(lock),
        Err(CliError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            Ok(PluginLock::default())
        }
        Err(error) => Err(error),
    }
}

fn print_plugin_status(status: &PluginStatus, format: OutputFormat) -> Result<(), CliError> {
    match format {
        OutputFormat::Json => output::json(status),
        OutputFormat::Plain => output::line(&status.locked.id),
        OutputFormat::Human => output::line(format!(
            "{:<32} {:<12} {}",
            status.locked.id,
            status.locked.version,
            if status.installed {
                "installed"
            } else {
                "missing"
            }
        )),
    }
}

fn print_plugin_statuses(statuses: &[PluginStatus], format: OutputFormat) -> Result<(), CliError> {
    if format == OutputFormat::Json {
        return output::json(statuses);
    }
    for status in statuses {
        print_plugin_status(status, format)?;
    }
    Ok(())
}

#[cfg(unix)]
async fn make_executable(path: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = tokio::fs::metadata(path).await?.permissions();
    permissions.set_mode(0o700);
    tokio::fs::set_permissions(path, permissions).await?;
    Ok(())
}

#[cfg(not(unix))]
async fn make_executable(_path: &Path) -> Result<(), CliError> {
    Ok(())
}

struct UuidName(String);

impl UuidName {
    fn new() -> Self {
        Self(uuid::Uuid::new_v4().simple().to_string())
    }
}

impl std::fmt::Display for UuidName {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_source_resolution_is_project_relative() {
        let temp = tempfile::tempdir().expect("temp");
        let plugin = temp.path().join("plugin");
        std::fs::write(&plugin, b"test").expect("write");
        assert_eq!(
            resolve_local_source("plugin", temp.path()).expect("resolve"),
            plugin
        );
    }

    #[test]
    fn secret_names_are_validated_before_keyring_access() {
        assert!(validate_secret_name("api-token").is_ok());
        assert!(validate_secret_name("API TOKEN").is_err());
    }

    #[test]
    fn absent_machine_target_is_a_healthy_doctor_result() {
        assert_eq!(
            target_check_status(lightrail_plugin_protocol::ResourceStatus::Absent),
            CheckStatus::Ok
        );
        assert_eq!(
            target_check_status(lightrail_plugin_protocol::ResourceStatus::Degraded),
            CheckStatus::Failed
        );
    }
}
