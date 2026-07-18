use std::path::{Path, PathBuf};

use crate::error::CliError;

pub const CONFIG_FILE: &str = "lightrail.toml";
pub const LOCK_FILE: &str = "lightrail.lock";
pub const LOCAL_DIR: &str = ".lightrail";

/// Paths rooted at an initialized Lightrail project.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectPaths {
    pub root: PathBuf,
    pub config: PathBuf,
    pub lock: PathBuf,
    pub local: PathBuf,
}

impl ProjectPaths {
    pub fn discover(start: &Path) -> Result<Self, CliError> {
        let start = start.canonicalize()?;
        for directory in start.ancestors() {
            let config = directory.join(CONFIG_FILE);
            if config.is_file() {
                return Ok(Self {
                    root: directory.to_path_buf(),
                    lock: directory.join(LOCK_FILE),
                    local: directory.join(LOCAL_DIR),
                    config,
                });
            }
        }
        Err(CliError::ProjectNotInitialized { start })
    }

    #[must_use]
    pub fn at(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            config: root.join(CONFIG_FILE),
            lock: root.join(LOCK_FILE),
            local: root.join(LOCAL_DIR),
            root,
        }
    }

    pub async fn ensure_local_layout(&self) -> Result<(), CliError> {
        tokio::fs::create_dir_all(self.local.join("operations")).await?;
        tokio::fs::create_dir_all(self.local.join("cache")).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_project_from_nested_directory() {
        let temp = tempfile::tempdir().expect("temp dir");
        std::fs::write(temp.path().join(CONFIG_FILE), "schema = 1").expect("config");
        let nested = temp.path().join("apps/api");
        std::fs::create_dir_all(&nested).expect("nested");

        let paths = ProjectPaths::discover(&nested).expect("discovered");
        assert_eq!(
            paths.root,
            temp.path().canonicalize().expect("canonical root")
        );
    }
}
