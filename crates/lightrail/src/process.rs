use std::{
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    process::ExitStatus,
};

use async_trait::async_trait;
use tokio::process::Command;

use crate::error::CliError;

#[derive(Clone, Debug)]
pub struct CommandSpec {
    pub program: OsString,
    pub arguments: Vec<OsString>,
    pub cwd: Option<PathBuf>,
    pub clear_environment: bool,
    pub environment: Vec<(OsString, OsString)>,
}

impl CommandSpec {
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            arguments: Vec::new(),
            cwd: None,
            clear_environment: false,
            environment: Vec::new(),
        }
    }

    #[must_use]
    pub fn args<I, S>(mut self, arguments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.arguments.extend(arguments.into_iter().map(Into::into));
        self
    }

    #[must_use]
    pub fn cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    #[must_use]
    pub fn clear_environment(mut self) -> Self {
        self.clear_environment = true;
        self
    }

    #[must_use]
    pub fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.environment.push((key.into(), value.into()));
        self
    }

    #[must_use]
    pub fn display(&self) -> String {
        let mut rendered = self.program.to_string_lossy().into_owned();
        for argument in &self.arguments {
            rendered.push(' ');
            rendered.push_str(&shell_display(argument));
        }
        rendered
    }
}

fn shell_display(value: &OsStr) -> String {
    let value = value.to_string_lossy();
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"-_./:=,@".contains(&byte))
    {
        value.into_owned()
    } else {
        format!("{value:?}")
    }
}

#[derive(Clone, Debug)]
pub struct ProcessOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl ProcessOutput {
    pub fn success(&self, spec: &CommandSpec) -> Result<&Self, CliError> {
        if self.status.success() {
            Ok(self)
        } else {
            let detail = String::from_utf8_lossy(&self.stderr).trim().to_owned();
            Err(CliError::Operation(format!(
                "`{}` exited with {}{}",
                spec.display(),
                self.status,
                if detail.is_empty() {
                    String::new()
                } else {
                    format!(": {detail}")
                }
            )))
        }
    }

    pub fn stdout_text(&self) -> Result<String, CliError> {
        String::from_utf8(self.stdout.clone())
            .map_err(|error| CliError::Operation(format!("command emitted invalid UTF-8: {error}")))
    }

    #[must_use]
    pub fn combined_text(&self) -> String {
        let stdout = String::from_utf8_lossy(&self.stdout);
        let stderr = String::from_utf8_lossy(&self.stderr);
        format!("{stdout}{stderr}").trim().to_owned()
    }
}

#[async_trait]
pub trait CommandRunner: Send + Sync {
    async fn run(&self, spec: &CommandSpec) -> Result<ProcessOutput, CliError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TokioCommandRunner;

#[async_trait]
impl CommandRunner for TokioCommandRunner {
    async fn run(&self, spec: &CommandSpec) -> Result<ProcessOutput, CliError> {
        let mut command = Command::new(&spec.program);
        command.args(&spec.arguments);
        if let Some(cwd) = &spec.cwd {
            command.current_dir(cwd);
        }
        if spec.clear_environment {
            command.env_clear();
        }
        for (key, value) in &spec.environment {
            command.env(key, value);
        }
        let output = command.output().await.map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                CliError::MissingTool {
                    tool: "external command",
                    detail: format!("{}: {error}", spec.program.to_string_lossy()),
                }
            } else {
                error.into()
            }
        })?;
        Ok(ProcessOutput {
            status: output.status,
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

#[must_use]
pub fn path_argument(path: &Path) -> OsString {
    path.as_os_str().to_owned()
}
