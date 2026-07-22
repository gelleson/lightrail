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
        self.local_for(None).await
    }

    /// Checks the common local tools plus those needed by one configured
    /// target. `None` is the provider-neutral pre-initialization check.
    pub async fn local_for(&self, target_plugin: Option<&str>) -> DoctorReport {
        let mut specifications = vec![
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
        ];
        if let Some(target) = target_specific_check(target_plugin) {
            specifications.push(target);
        }
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

fn target_specific_check(
    target_plugin: Option<&str>,
) -> Option<(&'static str, CommandSpec, &'static str)> {
    match target_plugin {
        Some(crate::plugin_host::KUBERNETES_PLUGIN_ID) => Some((
            "kubectl",
            CommandSpec::new("kubectl").args(["version", "--client"]),
            "Install kubectl and ensure it is on PATH.",
        )),
        Some(crate::plugin_host::SSH_PLUGIN_ID | crate::plugin_host::HETZNER_PLUGIN_ID) => Some((
            "ssh",
            CommandSpec::new("ssh").args(["-V"]),
            "Install an OpenSSH-compatible client.",
        )),
        None | Some(_) => None,
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
            "{} prerequisite check(s) failed: {}; fix the checks above, then rerun `lightrail doctor`",
            failed.len(),
            failed.join(", "),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::target_specific_check;
    use crate::plugin_host::{
        FLY_PLUGIN_ID, HETZNER_PLUGIN_ID, KUBERNETES_PLUGIN_ID, SSH_PLUGIN_ID,
    };

    fn selected_tool(plugin: Option<&str>) -> Option<&'static str> {
        target_specific_check(plugin).map(|(name, _, _)| name)
    }

    #[test]
    fn target_tool_checks_are_selected_only_after_initialization() {
        assert_eq!(selected_tool(None), None);
        assert_eq!(selected_tool(Some(FLY_PLUGIN_ID)), None);
        assert_eq!(selected_tool(Some(KUBERNETES_PLUGIN_ID)), Some("kubectl"));
        assert_eq!(selected_tool(Some(SSH_PLUGIN_ID)), Some("ssh"));
        assert_eq!(selected_tool(Some(HETZNER_PLUGIN_ID)), Some("ssh"));
    }
}
