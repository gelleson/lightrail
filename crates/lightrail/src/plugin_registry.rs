use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use directories::ProjectDirs;
use lightrail_plugin_protocol::ProtocolVersion;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::CliError;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PluginLock {
    pub schema: u32,
    #[serde(default)]
    pub plugins: Vec<LockedPlugin>,
}

impl Default for PluginLock {
    fn default() -> Self {
        Self {
            schema: 1,
            plugins: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LockedPlugin {
    pub id: String,
    pub version: String,
    pub protocol: String,
    pub source: String,
    pub sha256: String,
}

impl LockedPlugin {
    pub fn validate(&self) -> Result<(), CliError> {
        validate_plugin_id(&self.id)?;
        validate_plugin_version(&self.id, &self.version)?;
        self.protocol.parse::<ProtocolVersion>().map_err(|error| {
            CliError::Config(format!(
                "plugin `{}` has invalid pinned protocol: {error}",
                self.id
            ))
        })?;
        if self.sha256.len() != 64 || !self.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(CliError::Config(format!(
                "plugin `{}` must have a 64-character SHA-256 checksum",
                self.id
            )));
        }
        if self.source.starts_with("http://")
            || (self.source.contains("://") && !self.source.starts_with("https://"))
        {
            return Err(CliError::Config(format!(
                "plugin `{}` source must be HTTPS or a local path",
                self.id
            )));
        }
        Ok(())
    }
}

impl PluginLock {
    pub async fn load(path: &Path) -> Result<Self, CliError> {
        let source = tokio::fs::read_to_string(path).await?;
        let lock: Self = toml::from_str(&source)?;
        lock.validate()?;
        Ok(lock)
    }

    pub fn validate(&self) -> Result<(), CliError> {
        if self.schema != 1 {
            return Err(CliError::Config(format!(
                "unsupported lightrail.lock schema {}; expected 1",
                self.schema
            )));
        }
        let mut identifiers = std::collections::BTreeSet::new();
        for plugin in &self.plugins {
            plugin.validate()?;
            if !identifiers.insert(&plugin.id) {
                return Err(CliError::Config(format!(
                    "plugin `{}` occurs more than once in lightrail.lock",
                    plugin.id
                )));
            }
        }
        Ok(())
    }

    pub async fn save(&self, path: &Path) -> Result<(), CliError> {
        self.validate()?;
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let temporary = path.with_extension("lock.tmp");
        tokio::fs::write(&temporary, toml::to_string_pretty(self)?).await?;
        tokio::fs::rename(temporary, path).await?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct PluginStore {
    root: PathBuf,
    http: reqwest::Client,
}

impl PluginStore {
    pub fn from_os() -> Result<Self, CliError> {
        let directories = ProjectDirs::from("dev", "lightrail", "lightrail")
            .ok_or_else(|| CliError::Operation("could not determine user data directory".into()))?;
        Self::at(directories.data_dir().join("plugins"))
    }

    pub fn at(root: PathBuf) -> Result<Self, CliError> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(300))
            .user_agent(concat!("lightrail/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| CliError::Operation(format!("HTTP client: {error}")))?;
        Ok(Self { root, http })
    }

    #[must_use]
    pub fn executable_path(&self, plugin: &LockedPlugin) -> PathBuf {
        self.root
            .join(&plugin.id)
            .join(&plugin.version)
            .join(executable_filename())
    }

    pub async fn is_installed(&self, plugin: &LockedPlugin) -> Result<bool, CliError> {
        plugin.validate()?;
        let path = self.executable_path(plugin);
        if !path.is_file() {
            return Ok(false);
        }
        Ok(sha256_file(&path).await? == plugin.sha256.to_ascii_lowercase())
    }

    /// Install an explicitly pinned plugin. This is called only by `plugin install/sync`.
    pub async fn install(
        &self,
        plugin: &LockedPlugin,
        project_root: &Path,
    ) -> Result<PathBuf, CliError> {
        plugin.validate()?;
        if self.is_installed(plugin).await? {
            return Ok(self.executable_path(plugin));
        }

        let destination = self.executable_path(plugin);
        let parent = destination
            .parent()
            .ok_or_else(|| CliError::Operation("invalid plugin destination".into()))?;
        tokio::fs::create_dir_all(parent).await?;
        let temporary = parent.join(format!(".{}.download", uuid::Uuid::new_v4()));

        let install_result = if plugin.source.starts_with("https://") {
            self.download(&plugin.source, &temporary).await
        } else {
            let source = local_source_path(&plugin.source, project_root)?;
            copy_file(&source, &temporary).await
        };
        if let Err(error) = install_result {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(error);
        }

        let actual = sha256_file(&temporary).await?;
        let expected = plugin.sha256.to_ascii_lowercase();
        if actual != expected {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(CliError::Plugin(format!(
                "checksum mismatch for `{}`: expected {expected}, got {actual}",
                plugin.id
            )));
        }

        make_executable(&temporary).await?;
        if destination.exists() {
            return Err(CliError::Plugin(format!(
                "refusing to replace mismatched installed plugin at {}",
                destination.display()
            )));
        }
        tokio::fs::rename(&temporary, &destination).await?;
        Ok(destination)
    }

    /// Remove one installed version. Already-absent files are successful.
    pub async fn remove(&self, plugin: &LockedPlugin) -> Result<(), CliError> {
        plugin.validate()?;
        let version_directory = self
            .executable_path(plugin)
            .parent()
            .ok_or_else(|| CliError::Operation("invalid plugin installation path".into()))?
            .to_path_buf();
        match tokio::fs::remove_dir_all(version_directory).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    async fn download(&self, source: &str, destination: &Path) -> Result<(), CliError> {
        let response = self
            .http
            .get(source)
            .send()
            .await
            .map_err(|error| CliError::Plugin(format!("download `{source}`: {error}")))?
            .error_for_status()
            .map_err(|error| CliError::Plugin(format!("download `{source}`: {error}")))?;
        let bytes = response
            .bytes()
            .await
            .map_err(|error| CliError::Plugin(format!("read `{source}`: {error}")))?;
        let mut file = tokio::fs::File::create(destination).await?;
        file.write_all(&bytes).await?;
        file.sync_all().await?;
        Ok(())
    }
}

fn validate_plugin_id(identifier: &str) -> Result<(), CliError> {
    let valid = !identifier.is_empty()
        && identifier.len() <= 128
        && identifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        && identifier
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && identifier
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric);
    if valid {
        Ok(())
    } else {
        Err(CliError::Config(format!(
            "invalid plugin ID `{identifier}`"
        )))
    }
}

fn validate_plugin_version(plugin_id: &str, version: &str) -> Result<(), CliError> {
    let valid = !version.is_empty()
        && version.len() <= 128
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+'))
        && version
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && version
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric);
    if valid {
        Ok(())
    } else {
        Err(CliError::Config(format!(
            "plugin `{plugin_id}` has invalid version `{version}`; expected one safe path component"
        )))
    }
}

fn local_source_path(source: &str, project_root: &Path) -> Result<PathBuf, CliError> {
    let source = source.strip_prefix("file:").unwrap_or(source);
    let path = PathBuf::from(source);
    let resolved = if path.is_absolute() {
        path
    } else {
        project_root.join(path)
    };
    if !resolved.is_file() {
        return Err(CliError::Plugin(format!(
            "plugin source does not exist: {}",
            resolved.display()
        )));
    }
    Ok(resolved)
}

async fn copy_file(source: &Path, destination: &Path) -> Result<(), CliError> {
    let mut input = tokio::fs::File::open(source).await?;
    let mut output = tokio::fs::File::create(destination).await?;
    tokio::io::copy(&mut input, &mut output).await?;
    output.sync_all().await?;
    Ok(())
}

pub async fn sha256_file(path: &Path) -> Result<String, CliError> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(hex::encode(digest.finalize()))
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

#[cfg(windows)]
fn executable_filename() -> &'static str {
    "plugin.exe"
}

#[cfg(not(windows))]
fn executable_filename() -> &'static str {
    "plugin"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locked(source: &Path, sha256: String) -> LockedPlugin {
        LockedPlugin {
            id: "example.target".into(),
            version: "1.2.3".into(),
            protocol: "1.0.0".into(),
            source: source.display().to_string(),
            sha256,
        }
    }

    #[tokio::test]
    async fn installs_verified_local_plugin() {
        let temp = tempfile::tempdir().expect("temp");
        let source = temp.path().join("source-plugin");
        tokio::fs::write(&source, b"plugin bytes")
            .await
            .expect("write");
        let checksum = sha256_file(&source).await.expect("checksum");
        let plugin = locked(&source, checksum);
        let store = PluginStore::at(temp.path().join("store")).expect("store");

        let installed = store
            .install(&plugin, temp.path())
            .await
            .expect("installed");
        assert!(installed.is_file());
        assert!(store.is_installed(&plugin).await.expect("inspect"));
    }

    #[tokio::test]
    async fn rejects_checksum_mismatch() {
        let temp = tempfile::tempdir().expect("temp");
        let source = temp.path().join("source-plugin");
        tokio::fs::write(&source, b"plugin bytes")
            .await
            .expect("write");
        let plugin = locked(&source, "00".repeat(32));
        let store = PluginStore::at(temp.path().join("store")).expect("store");

        let error = store
            .install(&plugin, temp.path())
            .await
            .expect_err("must reject");
        assert!(error.to_string().contains("checksum mismatch"));
    }

    #[test]
    fn lock_rejects_duplicate_ids_and_insecure_urls() {
        let plugin = LockedPlugin {
            id: "example".into(),
            version: "1".into(),
            protocol: "1.0.0".into(),
            source: "http://example.invalid/plugin".into(),
            sha256: "00".repeat(32),
        };
        assert!(plugin.validate().is_err());

        let mut duplicate = plugin;
        duplicate.source = "/tmp/plugin".into();
        let lock = PluginLock {
            schema: 1,
            plugins: vec![duplicate.clone(), duplicate],
        };
        assert!(lock.validate().is_err());
    }

    #[tokio::test]
    async fn rejects_version_path_traversal_before_store_access() {
        let temp = tempfile::tempdir().expect("temp");
        let source = temp.path().join("source-plugin");
        tokio::fs::write(&source, b"plugin bytes")
            .await
            .expect("write");
        let store = PluginStore::at(temp.path().join("store")).expect("store");
        let mut plugin = locked(&source, "00".repeat(32));
        plugin.version = "../../outside".to_owned();

        assert!(store.is_installed(&plugin).await.is_err());
        assert!(store.install(&plugin, temp.path()).await.is_err());
        assert!(store.remove(&plugin).await.is_err());
        assert!(!temp.path().join("outside").exists());
    }

    #[test]
    fn accepts_semver_like_safe_versions() {
        for version in ["1", "1.2.3", "2.0.0-rc.1", "1.0.0+linux_amd64"] {
            assert!(validate_plugin_version("example", version).is_ok());
        }
        for version in ["", ".", "..", "/1", "1/", "1 2", "../1", "1\n2"] {
            assert!(validate_plugin_version("example", version).is_err());
        }
    }
}
