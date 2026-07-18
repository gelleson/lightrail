use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    path::Path,
};

use lightrail_core::{
    Capability, EnvironmentIdentity, EnvironmentValue, GitContext, LightrailConfig, Profile,
};
use serde_json::{Value, json};

use crate::{error::CliError, workspace::ProjectPaths};

#[derive(Debug)]
pub struct LoadedProject {
    pub paths: ProjectPaths,
    pub config: LightrailConfig,
    pub profile_name: String,
    pub git: GitContext,
    pub identity: EnvironmentIdentity,
}

impl LoadedProject {
    pub fn discover(selected_profile: Option<&str>) -> Result<Self, CliError> {
        let current = env::current_dir()?;
        Self::discover_from(&current, selected_profile)
    }

    pub fn discover_from(start: &Path, selected_profile: Option<&str>) -> Result<Self, CliError> {
        let paths = ProjectPaths::discover(start)?;
        let config = LightrailConfig::load(&paths.config)
            .map_err(|error| CliError::Config(error.to_string()))?;
        let git =
            GitContext::discover(start).map_err(|error| CliError::Config(error.to_string()))?;

        let project_root = paths.root.canonicalize()?;
        let repository_root = git.repo_root().canonicalize()?;
        if project_root != repository_root {
            return Err(CliError::Config(format!(
                "{} must be at the current Git worktree root ({})",
                paths.config.display(),
                repository_root.display()
            )));
        }

        let profile_name = selected_profile
            .unwrap_or(&config.project.default_profile)
            .to_owned();
        if !config.profiles.contains_key(&profile_name) {
            return Err(CliError::Config(format!(
                "profile `{profile_name}` does not exist"
            )));
        }
        let identity = EnvironmentIdentity::from_git(&config.project, &profile_name, &git)
            .map_err(|error| CliError::Config(error.to_string()))?;

        Ok(Self {
            paths,
            config,
            profile_name,
            git,
            identity,
        })
    }

    #[must_use]
    pub fn profile(&self) -> &Profile {
        self.config
            .profile(&self.profile_name)
            .expect("LoadedProject validates the selected profile")
    }

    #[must_use]
    pub fn plugin_id(&self, capability: Capability) -> &str {
        self.profile().pipeline.plugin(capability).as_str()
    }

    pub fn capability_config(&self, capability: Capability) -> Result<Value, CliError> {
        self.profile()
            .settings_json(capability)
            .map_err(|error| CliError::Config(error.to_string()))
            .map(|settings| settings.unwrap_or_else(|| json!({})))
    }

    #[must_use]
    pub fn base_desired(&self) -> Value {
        let apps = self
            .profile()
            .apps
            .iter()
            .filter_map(|name| {
                self.config.app(name).map(|app| {
                    json!({
                        "name": name,
                        "service": app.service,
                        "port": app.port,
                        "health_path": app.health_path,
                        "health_status": app.health_status,
                        "health_interval_seconds": app.health_interval_seconds,
                        "health_timeout_seconds": app.health_timeout_seconds,
                        "environment": merged_app_environment(self.profile(), name, app),
                    })
                })
            })
            .collect::<Vec<_>>();

        json!({
            "schema": 1,
            "project": {
                "id": self.config.project.id.to_string(),
                "slug": self.config.project.slug,
                "root": self.paths.root,
                "compose": self.config.project.compose,
            },
            "environment": {
                "id": self.identity.id().as_str(),
                "profile": self.profile_name,
                "branch": self.git.branch(),
                "commit": self.git.commit(),
                "dirty": self.git.is_dirty(),
                "isolation": self.profile().isolation,
                "labels": self.identity.resource_labels(),
            },
            "apps": apps,
        })
    }

    #[must_use]
    pub fn referenced_secrets(&self) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        for value in self.profile().env.values() {
            collect_environment_secret(value, &mut names);
        }
        for app_name in &self.profile().apps {
            if let Some(app) = self.config.app(app_name) {
                for value in app.env.values() {
                    collect_environment_secret(value, &mut names);
                }
            }
            if let Some(overrides) = self.profile().app_env.get(app_name) {
                for value in overrides.values() {
                    collect_environment_secret(value, &mut names);
                }
            }
        }
        for settings in self.profile().settings.values() {
            if let Ok(value) = serde_json::to_value(settings) {
                collect_json_secrets(&value, &mut names);
            }
        }
        names
    }
}

fn merged_app_environment(
    profile: &Profile,
    app_name: &str,
    app: &lightrail_core::App,
) -> BTreeMap<String, EnvironmentValue> {
    let mut environment = app.env.clone();
    environment.extend(profile.env.clone());
    if let Some(overrides) = profile.app_env.get(app_name) {
        environment.extend(overrides.clone());
    }
    environment
}

fn collect_environment_secret(value: &EnvironmentValue, names: &mut BTreeSet<String>) {
    if let Some(name) = value.secret_name() {
        names.insert(name.as_str().to_owned());
    }
}

fn collect_json_secrets(value: &Value, names: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            if let Some(name) = object.get("secret").and_then(Value::as_str) {
                names.insert(name.to_owned());
            }
            for child in object.values() {
                collect_json_secrets(child, names);
            }
        }
        Value::Array(array) => {
            for child in array {
                collect_json_secrets(child, names);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use lightrail_core::{App, Isolation, PluginId, PluginPipeline, Profile, Project, ProjectId};

    use super::*;

    fn profile() -> Profile {
        let compose = PluginId::new("dev.lightrail.compose").expect("plugin");
        Profile {
            isolation: Isolation::Project,
            apps: vec!["api".into()],
            pipeline: PluginPipeline {
                source: compose.clone(),
                builder: compose.clone(),
                target: PluginId::new("dev.lightrail.ssh").expect("plugin"),
                runtime: compose.clone(),
                exposure: compose.clone(),
                dns: compose,
            },
            settings: BTreeMap::new(),
            env: BTreeMap::from([(
                "DATABASE_URL".into(),
                EnvironmentValue::secret("database-url").expect("secret"),
            )]),
            app_env: BTreeMap::new(),
        }
    }

    #[test]
    fn app_environment_precedence_is_app_then_profile_then_override() {
        let mut profile = profile();
        profile
            .env
            .insert("LOG".into(), EnvironmentValue::literal("profile"));
        profile.app_env.insert(
            "api".into(),
            BTreeMap::from([("LOG".into(), EnvironmentValue::literal("app override"))]),
        );
        let app = App {
            service: "api".into(),
            port: 8080,
            health_path: None,
            health_status: None,
            health_interval_seconds: None,
            health_timeout_seconds: None,
            env: BTreeMap::from([("LOG".into(), EnvironmentValue::literal("app"))]),
        };

        let merged = merged_app_environment(&profile, "api", &app);
        assert_eq!(
            merged.get("LOG").and_then(EnvironmentValue::as_literal),
            Some("app override")
        );
    }

    #[test]
    fn config_fixture_remains_constructible() {
        let config = LightrailConfig {
            schema: 1,
            project: Project {
                id: ProjectId::from_str("2f1c30f5-dce1-4a5c-a751-3a766f6b48ea").expect("project"),
                slug: "demo".into(),
                compose: vec!["compose.yaml".into()],
                default_profile: "preview".into(),
            },
            apps: BTreeMap::from([(
                "api".into(),
                App {
                    service: "api".into(),
                    port: 8080,
                    health_path: None,
                    health_status: None,
                    health_interval_seconds: None,
                    health_timeout_seconds: None,
                    env: BTreeMap::new(),
                },
            )]),
            profiles: BTreeMap::from([("preview".into(), profile())]),
        };
        config.validate().expect("valid");
    }
}
