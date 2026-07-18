use std::{
    collections::{BTreeSet, HashMap},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::error::CliError;

const KEYRING_SERVICE: &str = "lightrail";

#[async_trait]
pub trait SecretBackend: Send + Sync {
    async fn get(&self, project_id: &str, name: &str) -> Result<Option<SecretString>, CliError>;
    async fn set(&self, project_id: &str, name: &str, value: SecretString) -> Result<(), CliError>;
    async fn delete(&self, project_id: &str, name: &str) -> Result<(), CliError>;
}

#[derive(Clone, Debug, Default)]
pub struct KeyringBackend;

fn keyring_account(project_id: &str, name: &str) -> String {
    format!("{project_id}:{name}")
}

#[async_trait]
impl SecretBackend for KeyringBackend {
    async fn get(&self, project_id: &str, name: &str) -> Result<Option<SecretString>, CliError> {
        let account = keyring_account(project_id, name);
        tokio::task::spawn_blocking(move || {
            let entry = keyring::Entry::new(KEYRING_SERVICE, &account)
                .map_err(|error| CliError::Operation(error.to_string()))?;
            match entry.get_password() {
                Ok(value) => Ok(Some(SecretString::from(value))),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(error) => Err(CliError::Operation(format!(
                    "could not read OS keyring: {error}"
                ))),
            }
        })
        .await
        .map_err(|error| CliError::Operation(format!("keyring task failed: {error}")))?
    }

    async fn set(&self, project_id: &str, name: &str, value: SecretString) -> Result<(), CliError> {
        let account = keyring_account(project_id, name);
        tokio::task::spawn_blocking(move || {
            let entry = keyring::Entry::new(KEYRING_SERVICE, &account)
                .map_err(|error| CliError::Operation(error.to_string()))?;
            entry.set_password(value.expose_secret()).map_err(|error| {
                CliError::Operation(format!("could not write OS keyring: {error}"))
            })
        })
        .await
        .map_err(|error| CliError::Operation(format!("keyring task failed: {error}")))?
    }

    async fn delete(&self, project_id: &str, name: &str) -> Result<(), CliError> {
        let account = keyring_account(project_id, name);
        tokio::task::spawn_blocking(move || {
            let entry = keyring::Entry::new(KEYRING_SERVICE, &account)
                .map_err(|error| CliError::Operation(error.to_string()))?;
            match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(error) => Err(CliError::Operation(format!(
                    "could not delete OS keyring entry: {error}"
                ))),
            }
        })
        .await
        .map_err(|error| CliError::Operation(format!("keyring task failed: {error}")))?
    }
}

#[derive(Clone, Debug, Default)]
pub struct MemoryBackend {
    values: Arc<Mutex<HashMap<(String, String), SecretString>>>,
}

#[async_trait]
impl SecretBackend for MemoryBackend {
    async fn get(&self, project_id: &str, name: &str) -> Result<Option<SecretString>, CliError> {
        Ok(self
            .values
            .lock()
            .map_err(|_| CliError::Operation("memory secret store poisoned".into()))?
            .get(&(project_id.into(), name.into()))
            .cloned())
    }

    async fn set(&self, project_id: &str, name: &str, value: SecretString) -> Result<(), CliError> {
        self.values
            .lock()
            .map_err(|_| CliError::Operation("memory secret store poisoned".into()))?
            .insert((project_id.into(), name.into()), value);
        Ok(())
    }

    async fn delete(&self, project_id: &str, name: &str) -> Result<(), CliError> {
        self.values
            .lock()
            .map_err(|_| CliError::Operation("memory secret store poisoned".into()))?
            .remove(&(project_id.into(), name.into()));
        Ok(())
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct SecretIndex {
    names: BTreeSet<String>,
}

pub struct SecretStore<B> {
    backend: B,
    project_id: String,
    index_path: PathBuf,
}

impl<B: SecretBackend> SecretStore<B> {
    #[must_use]
    pub fn new(backend: B, project_id: impl Into<String>, local_dir: &Path) -> Self {
        Self {
            backend,
            project_id: project_id.into(),
            index_path: local_dir.join("secrets.json"),
        }
    }

    pub async fn resolve(&self, name: &str) -> Result<SecretString, CliError> {
        let env = environment_name(name);
        if let Ok(value) = std::env::var(&env) {
            return Ok(SecretString::from(value));
        }
        self.backend
            .get(&self.project_id, name)
            .await?
            .ok_or_else(|| CliError::SecretUnavailable {
                name: name.into(),
                env,
            })
    }

    pub async fn set(&self, name: &str, value: SecretString) -> Result<(), CliError> {
        self.backend.set(&self.project_id, name, value).await?;
        let mut index = self.load_index().await?;
        index.names.insert(name.into());
        self.save_index(&index).await
    }

    pub async fn delete(&self, name: &str) -> Result<(), CliError> {
        self.backend.delete(&self.project_id, name).await?;
        let mut index = self.load_index().await?;
        index.names.remove(name);
        self.save_index(&index).await
    }

    pub async fn list(&self) -> Result<Vec<String>, CliError> {
        Ok(self.load_index().await?.names.into_iter().collect())
    }

    async fn load_index(&self) -> Result<SecretIndex, CliError> {
        match tokio::fs::read(&self.index_path).await {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(SecretIndex::default())
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn save_index(&self, index: &SecretIndex) -> Result<(), CliError> {
        if let Some(parent) = self.index_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let bytes = serde_json::to_vec_pretty(index)?;
        tokio::fs::write(&self.index_path, bytes).await?;
        Ok(())
    }
}

#[must_use]
pub fn environment_name(name: &str) -> String {
    let normalized = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    format!("LIGHTRAIL_SECRET_{normalized}")
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    #[tokio::test]
    async fn set_list_resolve_and_delete() {
        let temp = tempfile::tempdir().expect("temp dir");
        let store = SecretStore::new(MemoryBackend::default(), "project", temp.path());
        store
            .set("api-token", SecretString::from("secret".to_owned()))
            .await
            .expect("set");
        assert_eq!(store.list().await.expect("list"), vec!["api-token"]);
        assert_eq!(
            store
                .resolve("api-token")
                .await
                .expect("resolve")
                .expose_secret(),
            "secret"
        );
        store.delete("api-token").await.expect("delete");
        assert!(store.list().await.expect("list").is_empty());
    }

    #[test]
    fn normalizes_environment_name() {
        assert_eq!(
            environment_name("hetzner-token"),
            "LIGHTRAIL_SECRET_HETZNER_TOKEN"
        );
    }
}
