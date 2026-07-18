//! Named profile selection and committed profile CRUD.

use std::path::{Path, PathBuf};

use lightrail_core::{Isolation, LightrailConfig, Profile};
use serde::Serialize;

use crate::error::CliError;

/// A selected profile after applying CLI/environment/project precedence.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SelectedProfile {
    pub name: String,
    pub is_default: bool,
    pub profile: Profile,
}

/// Compact row returned by `profile list`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProfileSummary {
    pub name: String,
    pub is_default: bool,
    pub isolation: Isolation,
    pub apps: Vec<String>,
    pub target_plugin: String,
}

/// Result of a committed profile mutation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProfileMutation {
    pub name: String,
    pub config_path: PathBuf,
}

/// Applies the required `CLI > environment > project default` precedence.
///
/// Passing environment explicitly keeps the behavior deterministic in tests
/// and in embedding callers.
///
/// # Errors
///
/// Returns an error when the selected profile is not present in `config`.
pub fn resolve_profile_name(
    config: &LightrailConfig,
    cli_profile: Option<&str>,
    environment_profile: Option<&str>,
) -> Result<String, CliError> {
    let name = cli_profile
        .or(environment_profile)
        .unwrap_or(&config.project.default_profile);
    if config.profile(name).is_none() {
        return Err(CliError::Config(format!(
            "profile `{name}` does not exist; available profiles: {}",
            config
                .profiles
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    Ok(name.to_owned())
}

/// Resolves a profile using the process `LIGHTRAIL_PROFILE` value.
///
/// Dispatchers using Clap's `env` support may pass the already-resolved global
/// `--profile` value to [`resolve_profile_name`] instead.
///
/// # Errors
///
/// Returns an error when the selected profile is not present in `config`.
pub fn resolve_profile(
    config: &LightrailConfig,
    cli_profile: Option<&str>,
) -> Result<SelectedProfile, CliError> {
    let environment = std::env::var("LIGHTRAIL_PROFILE").ok();
    let name = resolve_profile_name(config, cli_profile, environment.as_deref())?;
    show(config, &name)
}

/// Lists profiles in deterministic name order.
#[must_use]
pub fn list(config: &LightrailConfig) -> Vec<ProfileSummary> {
    config
        .profiles
        .iter()
        .map(|(name, profile)| ProfileSummary {
            name: name.clone(),
            is_default: name == &config.project.default_profile,
            isolation: profile.isolation,
            apps: profile.apps.clone(),
            target_plugin: profile.pipeline.target.as_str().to_owned(),
        })
        .collect()
}

/// Returns one profile in a serializable wrapper.
///
/// # Errors
///
/// Returns an error when `name` is not present in `config`.
pub fn show(config: &LightrailConfig, name: &str) -> Result<SelectedProfile, CliError> {
    let profile = config.profile(name).cloned().ok_or_else(|| {
        CliError::Config(format!(
            "profile `{name}` does not exist; available profiles: {}",
            config
                .profiles
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ))
    })?;
    Ok(SelectedProfile {
        name: name.to_owned(),
        is_default: name == config.project.default_profile,
        profile,
    })
}

/// Loads a validated project configuration.
///
/// # Errors
///
/// Returns an error when the file cannot be read, parsed, or validated.
pub fn load(path: &Path) -> Result<LightrailConfig, CliError> {
    LightrailConfig::load(path).map_err(|error| CliError::Config(error.to_string()))
}

/// Adds `name` by cloning a selected template profile.
///
/// If `template_name` is absent, the project default profile is cloned. This
/// makes the minimal `profile add <name>` command useful while retaining every
/// provider-specific setting for subsequent edits.
///
/// # Errors
///
/// Returns an error when the configuration is invalid, `name` already exists,
/// the template is missing, or the updated file cannot be written atomically.
pub async fn add(
    config_path: &Path,
    name: &str,
    template_name: Option<&str>,
) -> Result<ProfileMutation, CliError> {
    let mut config = load(config_path)?;
    if config.profiles.contains_key(name) {
        return Err(CliError::Usage(format!("profile `{name}` already exists")));
    }
    let template_name = template_name.unwrap_or(&config.project.default_profile);
    let template = config.profile(template_name).cloned().ok_or_else(|| {
        CliError::Config(format!("template profile `{template_name}` does not exist"))
    })?;
    config.profiles.insert(name.to_owned(), template);
    save(config_path, &config).await?;
    Ok(ProfileMutation {
        name: name.to_owned(),
        config_path: config_path.to_path_buf(),
    })
}

/// Removes a profile after the caller has rediscovered provider state.
///
/// `live_environment_count` must come from target/runtime inspection. A
/// positive value is always refused so profile deletion cannot orphan remote
/// resources.
///
/// # Errors
///
/// Returns an error when the profile is missing, is the project default, still
/// has live environments, or the updated file cannot be written atomically.
pub async fn remove(
    config_path: &Path,
    name: &str,
    live_environment_count: usize,
) -> Result<ProfileMutation, CliError> {
    let mut config = load(config_path)?;
    if !config.profiles.contains_key(name) {
        return Err(CliError::Config(format!("profile `{name}` does not exist")));
    }
    if name == config.project.default_profile {
        return Err(CliError::Usage(format!(
            "cannot remove default profile `{name}`; choose another project.default_profile first"
        )));
    }
    if live_environment_count > 0 {
        return Err(CliError::Usage(format!(
            "cannot remove profile `{name}`: {live_environment_count} live environment(s) still use it; destroy them first"
        )));
    }

    config.profiles.remove(name);
    save(config_path, &config).await?;
    Ok(ProfileMutation {
        name: name.to_owned(),
        config_path: config_path.to_path_buf(),
    })
}

async fn save(path: &Path, config: &LightrailConfig) -> Result<(), CliError> {
    let encoded = config
        .to_toml_pretty()
        .map_err(|error| CliError::Config(error.to_string()))?;
    let suffix = lightrail_core::ProjectId::new().simple();
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("lightrail.toml");
    let temporary = path.with_file_name(format!(".{filename}.{suffix}.tmp"));
    tokio::fs::write(&temporary, encoded).await?;
    if let Err(error) = tokio::fs::rename(&temporary, path).await {
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(error.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use lightrail_core::{
        App, CONFIG_SCHEMA_VERSION, PluginId, PluginPipeline, Project, ProjectId,
    };

    use super::*;

    fn pipeline(target: &str) -> PluginPipeline {
        let plugin = |id| PluginId::new(id).expect("plugin ID");
        PluginPipeline {
            source: plugin("lightrail.source.cwd-git"),
            builder: plugin("lightrail.builder.buildx"),
            target: plugin(target),
            runtime: plugin("lightrail.runtime.compose"),
            exposure: plugin("lightrail.exposure.traefik"),
            dns: plugin("lightrail.dns.ip"),
        }
    }

    fn profile(target: &str) -> Profile {
        Profile {
            isolation: Isolation::Project,
            apps: vec!["web".into()],
            pipeline: pipeline(target),
            settings: BTreeMap::new(),
            env: BTreeMap::new(),
            app_env: BTreeMap::new(),
        }
    }

    fn config() -> LightrailConfig {
        LightrailConfig {
            schema: CONFIG_SCHEMA_VERSION,
            project: Project {
                id: ProjectId::new(),
                slug: "shop".into(),
                compose: vec![PathBuf::from("compose.yaml")],
                default_profile: "preview".into(),
            },
            apps: BTreeMap::from([(
                "web".into(),
                App {
                    service: "frontend".into(),
                    port: 3000,
                    health_path: None,
                    health_status: None,
                    health_interval_seconds: None,
                    health_timeout_seconds: None,
                    env: BTreeMap::new(),
                },
            )]),
            profiles: BTreeMap::from([
                ("preview".into(), profile("lightrail.target.ssh")),
                ("staging".into(), profile("lightrail.target.hetzner")),
            ]),
        }
    }

    async fn fixture() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().expect("temp");
        let path = temp.path().join("lightrail.toml");
        tokio::fs::write(&path, config().to_toml_pretty().expect("serialize fixture"))
            .await
            .expect("write fixture");
        (temp, path)
    }

    #[test]
    fn selection_precedence_is_cli_then_environment_then_default() {
        let config = config();

        assert_eq!(
            resolve_profile_name(&config, Some("staging"), Some("preview")).expect("CLI"),
            "staging"
        );
        assert_eq!(
            resolve_profile_name(&config, None, Some("staging")).expect("environment"),
            "staging"
        );
        assert_eq!(
            resolve_profile_name(&config, None, None).expect("default"),
            "preview"
        );
    }

    #[test]
    fn selection_reports_unknown_profile() {
        let error =
            resolve_profile_name(&config(), Some("missing"), None).expect_err("must reject");

        assert!(error.to_string().contains("preview"));
        assert!(error.to_string().contains("staging"));
    }

    #[tokio::test]
    async fn add_clones_selected_template_and_persists_valid_config() {
        let (_temp, path) = fixture().await;

        add(&path, "production", Some("staging"))
            .await
            .expect("add");

        let config = load(&path).expect("load");
        assert_eq!(
            config.profiles["production"].pipeline.target.as_str(),
            "lightrail.target.hetzner"
        );
        assert_eq!(list(&config).len(), 3);
    }

    #[tokio::test]
    async fn remove_refuses_default_and_live_environments() {
        let (_temp, path) = fixture().await;

        let default_error = remove(&path, "preview", 0)
            .await
            .expect_err("default must remain");
        assert!(default_error.to_string().contains("default profile"));

        let live_error = remove(&path, "staging", 2)
            .await
            .expect_err("live profile must remain");
        assert!(live_error.to_string().contains("2 live environment"));

        remove(&path, "staging", 0).await.expect("remove");
        let config = load(&path).expect("load");
        assert!(!config.profiles.contains_key("staging"));
        assert!(config.profile("preview").is_some());
    }
}
