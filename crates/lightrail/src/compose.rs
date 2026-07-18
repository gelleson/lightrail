use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    io::Write,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    error::CliError,
    process::{CommandRunner, CommandSpec, path_argument},
};

#[derive(Clone, Debug, Deserialize)]
pub struct ComposeDocument {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub services: BTreeMap<String, ComposeService>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ComposeService {
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub build: Option<Value>,
    #[serde(default)]
    pub ports: Vec<Value>,
    #[serde(default)]
    pub expose: Vec<Value>,
    #[serde(default)]
    pub volumes: Vec<Value>,
    #[serde(default)]
    pub healthcheck: Option<Value>,
    #[serde(default)]
    pub network_mode: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ComposeInventory {
    pub project_name: Option<String>,
    pub services: Vec<ServiceInventory>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ServiceInventory {
    pub name: String,
    pub has_build: bool,
    pub image: Option<String>,
    pub internal_ports: Vec<u16>,
    pub has_healthcheck: bool,
    pub local_bind_mounts: Vec<String>,
    pub uses_host_network: bool,
}

impl ComposeInventory {
    #[must_use]
    pub fn service(&self, name: &str) -> Option<&ServiceInventory> {
        self.services.iter().find(|service| service.name == name)
    }

    #[must_use]
    pub fn public_app_candidates(&self) -> Vec<&ServiceInventory> {
        self.services
            .iter()
            .filter(|service| !service.internal_ports.is_empty())
            .collect()
    }

    pub fn validate_remote_safety(&self) -> Result<(), CliError> {
        let host_networked = self
            .services
            .iter()
            .filter(|service| service.uses_host_network)
            .map(|service| service.name.as_str())
            .collect::<Vec<_>>();
        if !host_networked.is_empty() {
            return Err(CliError::Config(format!(
                "remote deployment rejects network_mode=host in services: {}",
                host_networked.join(", ")
            )));
        }

        let mounted = self
            .services
            .iter()
            .filter(|service| !service.local_bind_mounts.is_empty())
            .map(|service| {
                format!(
                    "{} ({})",
                    service.name,
                    service.local_bind_mounts.join(", ")
                )
            })
            .collect::<Vec<_>>();
        if !mounted.is_empty() {
            return Err(CliError::Config(format!(
                "remote deployment rejects local bind mounts: {}",
                mounted.join("; ")
            )));
        }
        Ok(())
    }
}

pub struct ComposeInspector<R> {
    runner: R,
}

pub struct ResolvedCompose {
    file: tempfile::NamedTempFile,
    pub inventory: ComposeInventory,
}

impl ResolvedCompose {
    #[must_use]
    pub fn path(&self) -> &Path {
        self.file.path()
    }
}

impl<R: CommandRunner> ComposeInspector<R> {
    #[must_use]
    pub const fn new(runner: R) -> Self {
        Self { runner }
    }

    pub async fn inspect(
        &self,
        project_root: &Path,
        files: &[PathBuf],
    ) -> Result<ComposeInventory, CliError> {
        if files.is_empty() {
            return Err(CliError::Config(
                "at least one Compose file is required".into(),
            ));
        }
        let mut arguments = vec![OsString::from("compose")];
        for file in files {
            arguments.push(OsString::from("-f"));
            arguments.push(path_argument(file));
        }
        arguments.extend([
            OsString::from("config"),
            OsString::from("--format"),
            OsString::from("json"),
        ]);
        let spec = CommandSpec::new("docker").args(arguments).cwd(project_root);
        let output = self.runner.run(&spec).await?;
        output.success(&spec)?;
        let document: ComposeDocument =
            serde_json::from_slice(&output.stdout).map_err(|error| {
                CliError::Config(format!(
                    "could not decode `docker compose config --format json`: {error}"
                ))
            })?;
        Ok(inventory(document))
    }

    pub async fn resolve_ephemeral(
        &self,
        project_root: &Path,
        files: &[PathBuf],
    ) -> Result<ResolvedCompose, CliError> {
        if files.is_empty() {
            return Err(CliError::Config(
                "at least one Compose file is required".into(),
            ));
        }
        let mut arguments = vec![OsString::from("compose")];
        for file in files {
            arguments.push(OsString::from("-f"));
            arguments.push(path_argument(file));
        }
        arguments.extend([
            OsString::from("config"),
            OsString::from("--format"),
            OsString::from("json"),
        ]);
        let spec = CommandSpec::new("docker").args(arguments).cwd(project_root);
        let output = self.runner.run(&spec).await?;
        output.success(&spec)?;
        let document: ComposeDocument =
            serde_json::from_slice(&output.stdout).map_err(|error| {
                CliError::Config(format!(
                    "could not decode `docker compose config --format json`: {error}"
                ))
            })?;
        let inventory = inventory(document);
        inventory.validate_remote_safety()?;

        let mut file = tempfile::Builder::new()
            .prefix("lightrail-compose-")
            .suffix(".json")
            .tempfile()?;
        file.write_all(&output.stdout)?;
        file.as_file().sync_all()?;
        Ok(ResolvedCompose { file, inventory })
    }
}

#[must_use]
pub fn inventory(document: ComposeDocument) -> ComposeInventory {
    let services = document
        .services
        .into_iter()
        .map(|(name, service)| {
            let internal_ports = service
                .ports
                .iter()
                .chain(&service.expose)
                .filter_map(port_target)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let local_bind_mounts = service.volumes.iter().filter_map(bind_source).collect();
            ServiceInventory {
                name,
                has_build: service.build.is_some(),
                image: service.image,
                internal_ports,
                has_healthcheck: service.healthcheck.is_some(),
                local_bind_mounts,
                uses_host_network: service.network_mode.as_deref() == Some("host"),
            }
        })
        .collect();
    ComposeInventory {
        project_name: document.name,
        services,
    }
}

fn port_target(value: &Value) -> Option<u16> {
    match value {
        Value::Number(number) => number.as_u64().and_then(|port| u16::try_from(port).ok()),
        Value::String(value) => value
            .split_once('/')
            .map_or(value.as_str(), |(port, _)| port)
            .parse()
            .ok(),
        Value::Object(object) => object.get("target").and_then(port_target),
        _ => None,
    }
}

fn bind_source(value: &Value) -> Option<String> {
    match value {
        Value::Object(object) if object.get("type").and_then(Value::as_str) == Some("bind") => {
            object
                .get("source")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        }
        Value::String(value) => {
            let source = value.split(':').next().unwrap_or_default();
            (source.starts_with('.')
                || source.starts_with('/')
                || source.starts_with('~')
                || source.contains('\\'))
            .then(|| source.to_owned())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_builds_ports_and_unsafe_mounts() {
        let document: ComposeDocument = serde_json::from_value(serde_json::json!({
            "name": "shop",
            "services": {
                "api": {
                    "build": {"context": "."},
                    "ports": [{"target": 8080, "published": "8080"}],
                    "healthcheck": {"test": ["CMD", "true"]}
                },
                "db": {
                    "image": "postgres:17",
                    "expose": ["5432/tcp"],
                    "volumes": [{"type": "volume", "source": "db", "target": "/data"}]
                },
                "dev": {
                    "image": "node",
                    "volumes": [{"type": "bind", "source": "/src", "target": "/app"}],
                    "network_mode": "host"
                }
            }
        }))
        .expect("document");
        let inventory = inventory(document);

        let api = inventory.service("api").expect("api");
        assert!(api.has_build);
        assert_eq!(api.internal_ports, vec![8080]);
        assert!(api.has_healthcheck);
        assert_eq!(
            inventory.service("db").expect("db").internal_ports,
            vec![5432]
        );
        assert!(inventory.validate_remote_safety().is_err());
    }

    #[test]
    fn short_bind_mount_is_detected_but_named_volume_is_not() {
        assert_eq!(
            bind_source(&Value::String("./src:/app".into())).as_deref(),
            Some("./src")
        );
        assert_eq!(bind_source(&Value::String("data:/data".into())), None);
    }
}
