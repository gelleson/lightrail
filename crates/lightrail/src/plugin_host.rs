use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    path::{Path, PathBuf},
};

use lightrail_plugin_protocol::{
    Capability, InitializeRequest, PluginClient, PluginManifest, SpawnOptions,
};

use crate::{
    error::CliError,
    plugin_registry::{LockedPlugin, PluginLock, PluginStore},
    workspace::ProjectPaths,
};

pub const COMPOSE_PLUGIN_ID: &str = "dev.lightrail.compose";
pub const SSH_PLUGIN_ID: &str = "dev.lightrail.ssh";
pub const HETZNER_PLUGIN_ID: &str = "dev.lightrail.hetzner";

#[derive(Clone, Debug)]
pub struct PluginLaunch {
    pub id: String,
    pub program: PathBuf,
    pub arguments: Vec<OsString>,
    pub expected_version: Option<String>,
    pub expected_protocol: Option<String>,
}

pub struct PluginSession {
    pub client: PluginClient,
    pub manifest: PluginManifest,
}

impl PluginSession {
    pub fn require_capability(&self, capability: &Capability) -> Result<(), CliError> {
        if self.manifest.capabilities.contains(capability) {
            Ok(())
        } else {
            Err(CliError::Plugin(format!(
                "plugin `{}` does not provide capability `{capability}`",
                self.manifest.id
            )))
        }
    }

    pub async fn shutdown(self) -> Result<(), CliError> {
        self.client
            .shutdown()
            .await
            .map_err(|error| CliError::Plugin(error.to_string()))
    }
}

#[derive(Clone, Debug)]
pub struct PluginResolver {
    project: ProjectPaths,
    store: PluginStore,
}

impl PluginResolver {
    pub fn new(project: ProjectPaths) -> Result<Self, CliError> {
        Ok(Self {
            project,
            store: PluginStore::from_os()?,
        })
    }

    #[must_use]
    pub fn with_store(project: ProjectPaths, store: PluginStore) -> Self {
        Self { project, store }
    }

    pub async fn resolve(&self, id: &str) -> Result<PluginLaunch, CliError> {
        if let Some(name) = bundled_executable(id) {
            return Ok(PluginLaunch {
                id: id.to_owned(),
                program: find_bundled_executable(name)?,
                arguments: Vec::new(),
                expected_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
                expected_protocol: Some(
                    lightrail_plugin_protocol::PROTOCOL_VERSION_STRING.to_owned(),
                ),
            });
        }

        let lock = self.load_lock().await?;
        let locked = lock
            .plugins
            .iter()
            .find(|plugin| plugin.id == id)
            .ok_or_else(|| {
                CliError::Plugin(format!(
                    "plugin `{id}` is neither bundled nor pinned in {}",
                    self.project.lock.display()
                ))
            })?;
        if !self.store.is_installed(locked).await? {
            return Err(CliError::Plugin(format!(
                "plugin `{id}` is pinned but not installed; run `lightrail plugin sync`"
            )));
        }
        Ok(launch_from_lock(locked, &self.store))
    }

    pub async fn spawn(&self, id: &str) -> Result<PluginSession, CliError> {
        let launch = self.resolve(id).await?;
        let mut options = SpawnOptions::new(&launch.program);
        options.args = launch.arguments;
        options.current_dir = Some(self.project.root.clone());
        options.env = sanitized_environment(id);

        let client = PluginClient::spawn(options)
            .await
            .map_err(|error| CliError::Plugin(format!("start plugin `{id}`: {error}")))?;
        let initialized = match client
            .initialize(InitializeRequest::current(env!("CARGO_PKG_VERSION")))
            .await
        {
            Ok(initialized) => initialized,
            Err(error) => {
                let _ = client.shutdown().await;
                return Err(CliError::Plugin(format!(
                    "initialize plugin `{id}`: {error}"
                )));
            }
        };

        if initialized.manifest.id != launch.id {
            let actual = initialized.manifest.id.clone();
            let _ = client.shutdown().await;
            return Err(CliError::Plugin(format!(
                "plugin identity mismatch: requested `{}`, executable declared `{actual}`",
                launch.id
            )));
        }
        if let Some(expected) = launch.expected_version {
            if initialized.manifest.version != expected {
                let actual = initialized.manifest.version.clone();
                let _ = client.shutdown().await;
                return Err(CliError::Plugin(format!(
                    "plugin `{id}` version mismatch: expected `{expected}`, got `{actual}`"
                )));
            }
        }
        if let Some(expected) = launch.expected_protocol {
            let actual = initialized.manifest.protocol.version.to_string();
            if actual != expected {
                let _ = client.shutdown().await;
                return Err(CliError::Plugin(format!(
                    "plugin `{id}` protocol mismatch: lock pins `{expected}`, executable declared `{actual}`"
                )));
            }
        }

        Ok(PluginSession {
            client,
            manifest: initialized.manifest,
        })
    }

    async fn load_lock(&self) -> Result<PluginLock, CliError> {
        match PluginLock::load(&self.project.lock).await {
            Ok(lock) => Ok(lock),
            Err(CliError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(PluginLock::default())
            }
            Err(error) => Err(error),
        }
    }
}

fn launch_from_lock(plugin: &LockedPlugin, store: &PluginStore) -> PluginLaunch {
    PluginLaunch {
        id: plugin.id.clone(),
        program: store.executable_path(plugin),
        arguments: Vec::new(),
        expected_version: Some(plugin.version.clone()),
        expected_protocol: Some(plugin.protocol.clone()),
    }
}

fn bundled_executable(id: &str) -> Option<&'static str> {
    match id {
        COMPOSE_PLUGIN_ID => Some("lightrail-plugin-compose"),
        SSH_PLUGIN_ID => Some("lightrail-plugin-ssh"),
        HETZNER_PLUGIN_ID => Some("lightrail-plugin-hetzner"),
        _ => None,
    }
}

fn find_bundled_executable(name: &str) -> Result<PathBuf, CliError> {
    let executable_name = platform_executable(name);
    let current_executable = env::current_exe().ok();
    let workspace_candidate = cfg!(debug_assertions).then(|| {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("target")
            .join("debug")
            .join(&executable_name)
    });

    find_bundled_executable_from(
        &executable_name,
        current_executable.as_deref(),
        workspace_candidate.as_deref(),
    )
}

fn find_bundled_executable_from(
    executable_name: &str,
    current_executable: Option<&Path>,
    workspace_candidate: Option<&Path>,
) -> Result<PathBuf, CliError> {
    let mut checked = Vec::new();

    if let Some(sibling) = current_executable
        .and_then(Path::parent)
        .map(|directory| directory.join(executable_name))
    {
        if let Some(executable) = trusted_existing_executable(&sibling) {
            return Ok(executable);
        }
        checked.push(sibling);
    }

    if let Some(candidate) = workspace_candidate {
        if let Some(executable) = trusted_existing_executable(candidate) {
            return Ok(executable);
        }
        checked.push(candidate.to_path_buf());
    }

    let checked = if checked.is_empty() {
        "no trusted candidate paths were available".to_owned()
    } else {
        checked
            .iter()
            .map(|candidate| format!("`{}`", candidate.display()))
            .collect::<Vec<_>>()
            .join(", ")
    };
    Err(CliError::Plugin(format!(
        "bundled executable `{executable_name}` was not found in a trusted location; checked {checked}. Reinstall Lightrail with its bundled plugins beside the CLI executable, or run `cargo build --workspace` in a source checkout"
    )))
}

fn trusted_existing_executable(candidate: &Path) -> Option<PathBuf> {
    if !candidate.is_absolute() {
        return None;
    }

    candidate
        .canonicalize()
        .ok()
        .filter(|resolved| resolved.is_absolute() && resolved.is_file())
}

#[cfg(windows)]
fn platform_executable(name: &str) -> String {
    format!("{name}.exe")
}

#[cfg(not(windows))]
fn platform_executable(name: &str) -> String {
    name.to_owned()
}

fn sanitized_environment(plugin_id: &str) -> BTreeMap<OsString, OsString> {
    let mut environment = BTreeMap::new();
    copy_environment(&mut environment, "PATH");
    copy_environment(&mut environment, "HOME");
    copy_environment(&mut environment, "USER");
    copy_environment(&mut environment, "TMPDIR");
    copy_environment(&mut environment, "DOCKER_HOST");
    copy_environment(&mut environment, "DOCKER_CONTEXT");

    if matches!(
        plugin_id,
        COMPOSE_PLUGIN_ID | SSH_PLUGIN_ID | HETZNER_PLUGIN_ID
    ) {
        copy_environment(&mut environment, "SSH_AUTH_SOCK");
    }
    environment.insert(
        OsString::from("LIGHTRAIL_PLUGIN_PROTOCOL"),
        OsString::from(lightrail_plugin_protocol::PROTOCOL_VERSION_STRING),
    );
    environment
}

fn copy_environment(target: &mut BTreeMap<OsString, OsString>, key: &str) {
    if let Some(value) = env::var_os(key) {
        target.insert(OsString::from(key), value);
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{File, create_dir_all};

    use super::*;

    #[test]
    fn maps_only_bundled_plugin_ids() {
        assert_eq!(
            bundled_executable(COMPOSE_PLUGIN_ID),
            Some("lightrail-plugin-compose")
        );
        assert_eq!(bundled_executable("third.party"), None);
    }

    #[test]
    fn bundled_plugin_uses_absolute_sibling_path() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let bin = temp.path().join("bin");
        create_dir_all(&bin).expect("create bin directory");
        let current = bin.join(platform_executable("lightrail"));
        let plugin = bin.join(platform_executable("lightrail-plugin-compose"));
        File::create(&plugin).expect("create plugin");

        let resolved = find_bundled_executable_from(
            &platform_executable("lightrail-plugin-compose"),
            Some(&current),
            None,
        )
        .expect("resolve trusted sibling");

        assert!(resolved.is_absolute());
        assert_eq!(resolved, plugin.canonicalize().expect("canonical plugin"));
    }

    #[test]
    fn bundled_plugin_allows_explicit_workspace_development_candidate() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let current = temp
            .path()
            .join("target")
            .join("debug")
            .join("deps")
            .join(platform_executable("lightrail"));
        let plugin = temp
            .path()
            .join("target")
            .join("debug")
            .join(platform_executable("lightrail-plugin-compose"));
        create_dir_all(plugin.parent().expect("plugin parent")).expect("create target directory");
        File::create(&plugin).expect("create plugin");

        let resolved = find_bundled_executable_from(
            &platform_executable("lightrail-plugin-compose"),
            Some(&current),
            Some(&plugin),
        )
        .expect("resolve workspace plugin");

        assert!(resolved.is_absolute());
        assert_eq!(resolved, plugin.canonicalize().expect("canonical plugin"));
    }

    #[test]
    fn missing_bundled_plugin_fails_instead_of_using_path() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let executable_name = platform_executable("lightrail-plugin-compose");
        let current = temp
            .path()
            .join("bin")
            .join(platform_executable("lightrail"));
        let workspace = temp
            .path()
            .join("target")
            .join("debug")
            .join(&executable_name);

        let error =
            find_bundled_executable_from(&executable_name, Some(&current), Some(&workspace))
                .expect_err("missing plugin must fail closed");
        let message = error.to_string();

        assert!(message.contains(&executable_name));
        assert!(message.contains("trusted location"));
        assert!(message.contains("checked"));
        assert!(message.contains("cargo build --workspace"));
    }

    #[test]
    fn plugin_environment_is_explicit_and_does_not_forward_secrets() {
        let environment = sanitized_environment(COMPOSE_PLUGIN_ID);
        assert!(environment.contains_key(&OsString::from("LIGHTRAIL_PLUGIN_PROTOCOL")));
        assert!(!environment.contains_key(&OsString::from("LIGHTRAIL_SECRET_TOKEN")));
        assert!(!environment.contains_key(&OsString::from("SSH_AUTH_SOCK")));
    }
}
