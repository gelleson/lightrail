use serde::Serialize;

use crate::{
    error::CliError,
    process::{CommandRunner, CommandSpec},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Ok,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DoctorCheck {
    pub name: &'static str,
    pub status: CheckStatus,
    pub detail: String,
    pub remediation: Option<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DoctorReport {
    pub checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    #[must_use]
    pub fn healthy(&self) -> bool {
        self.checks
            .iter()
            .all(|check| check.status == CheckStatus::Ok)
    }
}

pub struct Doctor<R> {
    runner: R,
}

impl<R: CommandRunner> Doctor<R> {
    #[must_use]
    pub const fn new(runner: R) -> Self {
        Self { runner }
    }

    pub async fn local(&self) -> DoctorReport {
        let specifications = [
            (
                "git",
                CommandSpec::new("git").args(["--version"]),
                "Install Git and ensure it is on PATH.",
            ),
            (
                "docker",
                CommandSpec::new("docker").args(["--version"]),
                "Install Docker Engine or Docker Desktop.",
            ),
            (
                "docker daemon",
                CommandSpec::new("docker").args(["info", "--format", "{{.ServerVersion}}"]),
                "Start Docker Engine or Docker Desktop and ensure this user can access its daemon.",
            ),
            (
                "docker buildx",
                CommandSpec::new("docker").args(["buildx", "version"]),
                "Install or enable the Docker Buildx plugin.",
            ),
            (
                "docker compose",
                CommandSpec::new("docker").args(["compose", "version", "--short"]),
                "Install or enable the Docker Compose plugin.",
            ),
            (
                "ssh",
                CommandSpec::new("ssh").args(["-V"]),
                "Install an OpenSSH-compatible client.",
            ),
        ];
        let mut checks = Vec::with_capacity(specifications.len());
        for (name, specification, remediation) in specifications {
            let check = match self.runner.run(&specification).await {
                Ok(output) if output.status.success() => DoctorCheck {
                    name,
                    status: CheckStatus::Ok,
                    detail: output.combined_text(),
                    remediation: None,
                },
                Ok(output) => DoctorCheck {
                    name,
                    status: CheckStatus::Failed,
                    detail: output.combined_text(),
                    remediation: Some(remediation),
                },
                Err(error) => DoctorCheck {
                    name,
                    status: CheckStatus::Failed,
                    detail: error.to_string(),
                    remediation: Some(remediation),
                },
            };
            checks.push(check);
        }
        DoctorReport { checks }
    }
}

pub fn ensure_healthy(report: &DoctorReport) -> Result<(), CliError> {
    if report.healthy() {
        Ok(())
    } else {
        let failed = report
            .checks
            .iter()
            .filter(|check| check.status == CheckStatus::Failed)
            .map(|check| check.name)
            .collect::<Vec<_>>();
        Err(CliError::Operation(format!(
            "prerequisite checks failed: {}",
            failed.join(", ")
        )))
    }
}
