use std::{
    ffi::{OsStr, OsString},
    io,
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    time::Duration,
};

use async_trait::async_trait;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::{Child, Command},
    sync::oneshot,
    task::JoinHandle,
    time::Instant,
};

use crate::error::CliError;

const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const PROCESS_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub struct CommandSpec {
    pub program: OsString,
    pub arguments: Vec<OsString>,
    pub cwd: Option<PathBuf>,
    pub clear_environment: bool,
    pub environment: Vec<(OsString, OsString)>,
    pub timeout: Duration,
}

impl CommandSpec {
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            arguments: Vec::new(),
            cwd: None,
            clear_environment: false,
            environment: Vec::new(),
            timeout: DEFAULT_COMMAND_TIMEOUT,
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
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
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
        let deadline = Instant::now().checked_add(spec.timeout).ok_or_else(|| {
            CliError::Operation(format!(
                "`{}` timeout exceeds the supported duration",
                spec.display()
            ))
        })?;
        let mut command = Command::new(&spec.program);
        command
            .args(&spec.arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(cwd) = &spec.cwd {
            command.current_dir(cwd);
        }
        if spec.clear_environment {
            command.env_clear();
        }
        for (key, value) in &spec.environment {
            command.env(key, value);
        }

        let mut child = command.spawn().map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                CliError::MissingTool {
                    tool: "external command",
                    detail: format!("{}: {error}", spec.program.to_string_lossy()),
                }
            } else {
                error.into()
            }
        })?;
        let stdout = take_stdout(&mut child).await?;
        let stderr = take_stderr(&mut child).await?;
        let stdout_reader = spawn_reader(stdout);
        let stderr_reader = spawn_reader(stderr);

        // The supervisor remains alive if the caller future is cancelled. Dropping
        // this sender then selects the explicit terminate-and-reap path.
        let (caller_alive, caller_cancelled) = oneshot::channel();
        let supervisor = tokio::spawn(supervise(
            child,
            stdout_reader,
            stderr_reader,
            deadline,
            caller_cancelled,
        ));
        let outcome = supervisor.await.map_err(|error| {
            CliError::Operation(format!("failed to supervise `{}`: {error}", spec.display()))
        })?;
        drop(caller_alive);

        match outcome {
            SupervisionOutcome::Exited(output) => Ok(output),
            SupervisionOutcome::TimedOut { cleanup_error } => {
                let cleanup = cleanup_error.map_or_else(String::new, |error| {
                    format!("; process cleanup also failed: {error}")
                });
                Err(CliError::Operation(format!(
                    "`{}` timed out after {:?}{cleanup}",
                    spec.display(),
                    spec.timeout
                )))
            }
            SupervisionOutcome::Cancelled { cleanup_error } => {
                let cleanup = cleanup_error.map_or_else(String::new, |error| {
                    format!("; process cleanup also failed: {error}")
                });
                Err(CliError::Operation(format!(
                    "`{}` was cancelled{cleanup}",
                    spec.display()
                )))
            }
            SupervisionOutcome::Io(error) => Err(error.into()),
        }
    }
}

enum SupervisionOutcome {
    Exited(ProcessOutput),
    TimedOut { cleanup_error: Option<io::Error> },
    Cancelled { cleanup_error: Option<io::Error> },
    Io(io::Error),
}

async fn take_stdout(child: &mut Child) -> Result<tokio::process::ChildStdout, CliError> {
    if let Some(stdout) = child.stdout.take() {
        Ok(stdout)
    } else {
        let cleanup = terminate_and_reap(child).await.err();
        Err(CliError::Operation(format!(
            "spawned command has no captured stdout{}",
            cleanup.map_or_else(String::new, |error| {
                format!("; process cleanup also failed: {error}")
            })
        )))
    }
}

async fn take_stderr(child: &mut Child) -> Result<tokio::process::ChildStderr, CliError> {
    if let Some(stderr) = child.stderr.take() {
        Ok(stderr)
    } else {
        let cleanup = terminate_and_reap(child).await.err();
        Err(CliError::Operation(format!(
            "spawned command has no captured stderr{}",
            cleanup.map_or_else(String::new, |error| {
                format!("; process cleanup also failed: {error}")
            })
        )))
    }
}

fn spawn_reader<R>(mut reader: R) -> JoinHandle<io::Result<Vec<u8>>>
where
    R: AsyncRead + Send + Unpin + 'static,
{
    tokio::spawn(async move {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).await?;
        Ok(bytes)
    })
}

async fn supervise(
    mut child: Child,
    mut stdout_reader: JoinHandle<io::Result<Vec<u8>>>,
    mut stderr_reader: JoinHandle<io::Result<Vec<u8>>>,
    deadline: Instant,
    mut caller_cancelled: oneshot::Receiver<()>,
) -> SupervisionOutcome {
    let process = tokio::select! {
        status = child.wait() => Some(status),
        () = tokio::time::sleep_until(deadline) => None,
        _ = &mut caller_cancelled => {
            let cleanup_error = terminate_and_reap(&mut child).await.err();
            drain_or_abort(&mut stdout_reader, &mut stderr_reader).await;
            return SupervisionOutcome::Cancelled { cleanup_error };
        }
    };

    let Some(status) = process else {
        let cleanup_error = terminate_and_reap(&mut child).await.err();
        drain_or_abort(&mut stdout_reader, &mut stderr_reader).await;
        return SupervisionOutcome::TimedOut { cleanup_error };
    };
    let status = match status {
        Ok(status) => status,
        Err(error) => {
            let _ = terminate_and_reap(&mut child).await;
            drain_or_abort(&mut stdout_reader, &mut stderr_reader).await;
            return SupervisionOutcome::Io(error);
        }
    };

    match tokio::time::timeout_at(
        deadline,
        collect_output(&mut stdout_reader, &mut stderr_reader),
    )
    .await
    {
        Ok(Ok((stdout, stderr))) => SupervisionOutcome::Exited(ProcessOutput {
            status,
            stdout,
            stderr,
        }),
        Ok(Err(error)) => SupervisionOutcome::Io(error),
        Err(_) => {
            stdout_reader.abort();
            stderr_reader.abort();
            SupervisionOutcome::TimedOut {
                cleanup_error: None,
            }
        }
    }
}

async fn collect_output(
    stdout_reader: &mut JoinHandle<io::Result<Vec<u8>>>,
    stderr_reader: &mut JoinHandle<io::Result<Vec<u8>>>,
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let (stdout, stderr) = tokio::join!(stdout_reader, stderr_reader);
    let stdout = stdout.map_err(|error| join_error(&error))??;
    let stderr = stderr.map_err(|error| join_error(&error))??;
    Ok((stdout, stderr))
}

async fn drain_or_abort(
    stdout_reader: &mut JoinHandle<io::Result<Vec<u8>>>,
    stderr_reader: &mut JoinHandle<io::Result<Vec<u8>>>,
) {
    if tokio::time::timeout(
        PROCESS_CLEANUP_TIMEOUT,
        collect_output(stdout_reader, stderr_reader),
    )
    .await
    .is_err()
    {
        stdout_reader.abort();
        stderr_reader.abort();
    }
}

fn join_error(error: &tokio::task::JoinError) -> io::Error {
    io::Error::other(format!("command output reader failed: {error}"))
}

async fn terminate_and_reap(child: &mut Child) -> io::Result<()> {
    let kill_error = child.start_kill().err();
    let wait_result = tokio::time::timeout(PROCESS_CLEANUP_TIMEOUT, child.wait()).await;
    match wait_result {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(kill_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out while reaping terminated command",
            )
        })),
    }
}

#[must_use]
pub fn path_argument(path: &Path) -> OsString {
    path.as_os_str().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    use std::path::Path;

    #[tokio::test]
    async fn captures_stdout_and_stderr_separately() {
        let spec = CommandSpec::new("sh")
            .args(["-c", "printf stdout-value; printf stderr-value >&2"])
            .timeout(Duration::from_secs(2));

        let output = TokioCommandRunner
            .run(&spec)
            .await
            .expect("command succeeds");

        assert!(output.status.success());
        assert_eq!(output.stdout, b"stdout-value");
        assert_eq!(output.stderr, b"stderr-value");
    }

    #[tokio::test]
    async fn child_stdin_is_closed_instead_of_inheriting_the_terminal() {
        let spec = CommandSpec::new("sh")
            .args([
                "-c",
                "if IFS= read -r value; then printf inherited; else printf closed; fi",
            ])
            .timeout(Duration::from_secs(2));

        let output = TokioCommandRunner
            .run(&spec)
            .await
            .expect("command observes EOF");

        assert_eq!(output.stdout, b"closed");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn timeout_terminates_and_reaps_the_child() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let pid_file = directory.path().join("child.pid");
        let spec = CommandSpec::new("sh")
            .args([
                OsString::from("-c"),
                OsString::from("echo $$ > \"$1\"; exec sleep 30"),
                OsString::from("sh"),
                path_argument(&pid_file),
            ])
            .timeout(Duration::from_millis(300));

        let error = TokioCommandRunner
            .run(&spec)
            .await
            .expect_err("command must time out");
        assert!(error.to_string().contains("timed out after 300ms"));

        let pid = read_pid(&pid_file).await;
        assert_process_reaped(pid).await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn dropping_the_run_future_terminates_and_reaps_the_child() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let pid_file = directory.path().join("child.pid");
        let spec = CommandSpec::new("sh")
            .args([
                OsString::from("-c"),
                OsString::from("echo $$ > \"$1\"; exec sleep 30"),
                OsString::from("sh"),
                path_argument(&pid_file),
            ])
            .timeout(Duration::from_secs(30));

        let running = tokio::spawn(async move { TokioCommandRunner.run(&spec).await });
        let pid = read_pid(&pid_file).await;
        running.abort();
        assert!(
            running
                .await
                .expect_err("runner task was cancelled")
                .is_cancelled()
        );
        assert_process_reaped(pid).await;
    }

    #[cfg(target_os = "linux")]
    async fn read_pid(path: &Path) -> u32 {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Ok(value) = tokio::fs::read_to_string(path).await {
                return value.trim().parse().expect("child PID");
            }
            assert!(
                Instant::now() < deadline,
                "child did not publish its PID before the test deadline"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[cfg(target_os = "linux")]
    async fn assert_process_reaped(pid: u32) {
        let process = PathBuf::from(format!("/proc/{pid}"));
        let deadline = Instant::now() + Duration::from_secs(2);
        while process.exists() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            !process.exists(),
            "child process {pid} was still present after command cleanup"
        );
    }
}
