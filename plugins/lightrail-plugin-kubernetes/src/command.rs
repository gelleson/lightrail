use std::{
    collections::{BTreeMap, HashMap},
    future::pending,
    process::Stdio,
    sync::{
        Arc, Mutex as StdMutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use lightrail_plugin_protocol::{ErrorKind, PluginError, PluginResult};
use serde_json::Value;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
    sync::Notify,
    time::sleep,
};

use crate::config::Settings;

#[derive(Default)]
struct RegistryInner {
    active: StdMutex<HashMap<String, Weak<CancelState>>>,
}

/// Logical-operation cancellation shared by semantic cancellation and child
/// process waits. A dropped command future kills its child through
/// `kill_on_drop` as a second line of defence.
#[derive(Clone, Default)]
pub(crate) struct CancellationRegistry {
    inner: Arc<RegistryInner>,
}

pub(crate) struct OperationGuard {
    operation_id: String,
    registry: CancellationRegistry,
    state: Arc<CancelState>,
}

impl OperationGuard {
    pub(crate) fn state(&self) -> &CancelState {
        &self.state
    }
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        let mut active = lock_unpoisoned(&self.registry.inner.active);
        if active
            .get(&self.operation_id)
            .and_then(Weak::upgrade)
            .is_some_and(|state| Arc::ptr_eq(&state, &self.state))
        {
            active.remove(&self.operation_id);
        }
    }
}

pub(crate) struct CancelState {
    cancelled: AtomicBool,
    notify: Notify,
}

impl CancelState {
    fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    pub(crate) async fn cancelled(&self) {
        let notified = self.notify.notified();
        tokio::pin!(notified);
        if self.cancelled.load(Ordering::Acquire) {
            return;
        }
        notified.await;
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }
}

impl CancellationRegistry {
    pub(crate) fn begin(&self, operation_id: &str) -> OperationGuard {
        let state = Arc::new(CancelState::new());
        lock_unpoisoned(&self.inner.active).insert(operation_id.to_owned(), Arc::downgrade(&state));
        OperationGuard {
            operation_id: operation_id.to_owned(),
            registry: self.clone(),
            state,
        }
    }

    pub(crate) fn cancel(&self, operation_id: &str) -> bool {
        let state = lock_unpoisoned(&self.inner.active)
            .get(operation_id)
            .and_then(Weak::upgrade);
        if let Some(state) = state {
            state.cancel();
            true
        } else {
            false
        }
    }
}

fn lock_unpoisoned<T>(mutex: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandOutcome {
    Completed,
    Cancelled,
    TimedOut,
}

/// Run a local executable with bounded lifetime and protocol-safe output.
///
/// Arbitrary child stderr is deliberately not copied into the plugin error:
/// kubectl admission errors can echo submitted environment values. Callers get
/// a stable classification and can rerun kubectl explicitly for raw details.
#[allow(clippy::too_many_lines)]
pub(crate) async fn run(
    program: &str,
    arguments: &[String],
    input: Option<Vec<u8>>,
    environment: &BTreeMap<String, String>,
    deadline: Duration,
    cancellation: Option<&CancelState>,
) -> PluginResult<Vec<u8>> {
    let mut command = Command::new(program);
    command
        .args(arguments)
        .envs(environment)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().map_err(|error| {
        PluginError::permanent(
            ErrorKind::NotFound,
            "command_spawn_failed",
            format!("could not start required executable `{program}`: {error}"),
        )
    })?;

    let stdout = child.stdout.take().ok_or_else(|| {
        PluginError::permanent(
            ErrorKind::Internal,
            "command_pipe_failed",
            format!("`{program}` did not expose stdout"),
        )
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        PluginError::permanent(
            ErrorKind::Internal,
            "command_pipe_failed",
            format!("`{program}` did not expose stderr"),
        )
    })?;
    let stdout_task = tokio::spawn(read_pipe(stdout));
    let stderr_task = tokio::spawn(read_pipe(stderr));
    let stdin_task = input.map(|input| {
        child.stdin.take().map(|mut stdin| {
            tokio::spawn(async move {
                stdin.write_all(&input).await?;
                stdin.shutdown().await
            })
        })
    });

    let wait_result;
    let outcome;
    {
        let cancelled = async {
            if let Some(cancellation) = cancellation {
                cancellation.cancelled().await;
            } else {
                pending::<()>().await;
            }
        };
        tokio::pin!(cancelled);
        let timer = sleep(deadline);
        tokio::pin!(timer);
        tokio::select! {
            status = child.wait() => {
                wait_result = status;
                outcome = CommandOutcome::Completed;
            }
            () = &mut cancelled => {
                let _ = child.kill().await;
                wait_result = child.wait().await;
                outcome = CommandOutcome::Cancelled;
            }
            () = &mut timer => {
                let _ = child.kill().await;
                wait_result = child.wait().await;
                outcome = CommandOutcome::TimedOut;
            }
        }
    }

    let status = wait_result.map_err(|error| {
        PluginError::retryable(
            ErrorKind::Unavailable,
            "command_wait_failed",
            format!("failed waiting for `{program}`: {error}"),
        )
    })?;
    let stdout = join_pipe(program, stdout_task).await?;
    let stderr = join_pipe(program, stderr_task).await?;
    if let Some(Some(stdin_task)) = stdin_task {
        let write_result = stdin_task.await.map_err(|error| {
            PluginError::permanent(
                ErrorKind::Internal,
                "command_input_task_failed",
                format!("failed joining `{program}` input: {error}"),
            )
        })?;
        if outcome == CommandOutcome::Completed {
            write_result.map_err(|error| {
                PluginError::retryable(
                    ErrorKind::Unavailable,
                    "command_input_failed",
                    format!("failed writing input to `{program}`: {error}"),
                )
            })?;
        }
    }

    match outcome {
        CommandOutcome::Cancelled => Err(PluginError::permanent(
            ErrorKind::Cancelled,
            "operation_cancelled",
            format!("`{program}` operation was cancelled"),
        )),
        CommandOutcome::TimedOut => Err(PluginError::retryable(
            ErrorKind::Timeout,
            "command_timeout",
            format!(
                "`{program}` did not finish within {} seconds",
                deadline.as_secs()
            ),
        )),
        CommandOutcome::Completed if !status.success() => {
            Err(classify_failure(program, status.code(), &stderr))
        }
        CommandOutcome::Completed => Ok(stdout),
    }
}

async fn read_pipe(mut pipe: impl AsyncReadExt + Unpin) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    pipe.read_to_end(&mut output).await?;
    Ok(output)
}

async fn join_pipe(
    program: &str,
    task: tokio::task::JoinHandle<std::io::Result<Vec<u8>>>,
) -> PluginResult<Vec<u8>> {
    task.await
        .map_err(|error| {
            PluginError::permanent(
                ErrorKind::Internal,
                "command_output_task_failed",
                format!("failed joining `{program}` output reader: {error}"),
            )
        })?
        .map_err(|error| {
            PluginError::retryable(
                ErrorKind::Unavailable,
                "command_output_failed",
                format!("failed reading `{program}` output: {error}"),
            )
        })
}

fn classify_failure(program: &str, status: Option<i32>, stderr: &[u8]) -> PluginError {
    let lower = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    let (kind, code, retryable) = if lower.contains("unauthorized") || lower.contains("forbidden") {
        (
            ErrorKind::Authentication,
            "command_authentication_failed",
            false,
        )
    } else if lower.contains("conflict")
        || lower.contains("object has been modified")
        || lower.contains("alreadyexists")
        || lower.contains("already exists")
    {
        (ErrorKind::Conflict, "command_conflict", true)
    } else if lower.contains("timeout")
        || lower.contains("timed out")
        || lower.contains("connection refused")
        || lower.contains("temporarily unavailable")
    {
        (ErrorKind::Unavailable, "command_unavailable", true)
    } else if lower.contains("notfound") || lower.contains("not found") {
        (ErrorKind::NotFound, "command_resource_not_found", false)
    } else {
        (ErrorKind::Validation, "command_failed", false)
    };
    let message = format!(
        "`{program}` failed{}; raw stderr was suppressed because it may contain application values",
        status.map_or_else(String::new, |code| format!(" with exit code {code}"))
    );
    if retryable {
        PluginError::retryable(kind, code, message)
    } else {
        PluginError::permanent(kind, code, message)
    }
}

pub(crate) async fn kubectl(
    settings: &Settings,
    arguments: &[String],
    input: Option<Vec<u8>>,
    deadline: Duration,
    cancellation: Option<&CancelState>,
) -> PluginResult<Vec<u8>> {
    let mut complete = settings.kubectl_prefix();
    complete.extend_from_slice(arguments);
    run(
        "kubectl",
        &complete,
        input,
        &BTreeMap::new(),
        deadline,
        cancellation,
    )
    .await
}

pub(crate) async fn kubectl_json(
    settings: &Settings,
    arguments: &[String],
    deadline: Duration,
) -> PluginResult<Value> {
    let output = kubectl(settings, arguments, None, deadline, None).await?;
    serde_json::from_slice(&output).map_err(|error| {
        PluginError::permanent(
            ErrorKind::Internal,
            "invalid_kubectl_json",
            format!("kubectl returned invalid JSON: {error}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn semantic_cancellation_is_sticky_for_a_live_operation() {
        let registry = CancellationRegistry::default();
        let guard = registry.begin("operation-1");
        assert!(registry.cancel("operation-1"));
        tokio::time::timeout(Duration::from_millis(10), guard.state().cancelled())
            .await
            .expect("cancel state remains observable");
        drop(guard);
        assert!(!registry.cancel("operation-1"));
    }

    #[test]
    fn child_stderr_is_not_returned_verbatim() {
        let error = classify_failure(
            "kubectl",
            Some(1),
            b"forbidden: environment SECRET=do-not-copy",
        );
        assert_eq!(error.kind, ErrorKind::Authentication);
        assert!(!error.message.contains("do-not-copy"));
        assert_eq!(
            classify_failure("kubectl", Some(1), b"leases already exists").kind,
            ErrorKind::Conflict
        );
    }
}
