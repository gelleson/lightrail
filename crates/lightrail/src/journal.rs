use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::error::CliError;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Up,
    Down,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Planning,
    Applying,
    Verifying,
    RollingBack,
    Succeeded,
    Failed,
    Interrupted,
}

/// Non-secret record of an applied or planned plugin action.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JournalAction {
    pub plugin_id: String,
    pub action_id: String,
    pub summary: String,
    #[serde(default)]
    pub public_metadata: Value,
    pub completed: bool,
}

/// A cache and recovery aid, never the source of truth for deployed resources.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperationJournal {
    pub schema: u32,
    pub operation_id: Uuid,
    pub environment_id: String,
    pub kind: OperationKind,
    pub status: OperationStatus,
    pub actions: Vec<JournalAction>,
    pub error: Option<String>,
}

impl OperationJournal {
    #[must_use]
    pub fn new(environment_id: impl Into<String>, kind: OperationKind) -> Self {
        Self {
            schema: 1,
            operation_id: Uuid::new_v4(),
            environment_id: environment_id.into(),
            kind,
            status: OperationStatus::Planning,
            actions: Vec::new(),
            error: None,
        }
    }

    #[must_use]
    pub fn path(&self, operations_dir: &Path) -> PathBuf {
        operations_dir.join(format!("{}.json", self.operation_id))
    }

    /// Persist atomically without ever serializing resolved secret values.
    pub async fn save(&self, operations_dir: &Path) -> Result<PathBuf, CliError> {
        tokio::fs::create_dir_all(operations_dir).await?;
        let final_path = self.path(operations_dir);
        let temporary_path = operations_dir.join(format!(".{}.json.tmp", self.operation_id));
        let bytes = serde_json::to_vec_pretty(self)?;
        let mut file = tokio::fs::File::create(&temporary_path).await?;
        file.write_all(&bytes).await?;
        file.write_all(b"\n").await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&temporary_path, &final_path).await?;
        Ok(final_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn journal_round_trips() {
        let temp = tempfile::tempdir().expect("temp dir");
        let mut journal = OperationJournal::new("env-1", OperationKind::Up);
        journal.actions.push(JournalAction {
            plugin_id: "test.plugin".into(),
            action_id: "create".into(),
            summary: "create test resource".into(),
            public_metadata: serde_json::json!({"resource_id": "42"}),
            completed: true,
        });

        let path = journal.save(temp.path()).await.expect("saved");
        let decoded: OperationJournal =
            serde_json::from_slice(&tokio::fs::read(path).await.expect("read")).expect("decode");
        assert_eq!(decoded, journal);
    }
}
