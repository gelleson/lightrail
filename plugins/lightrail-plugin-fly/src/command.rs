//! Local Docker Buildx boundary.
//!
//! Registry credentials are written only to Docker's standard input. Every
//! operation uses a fresh private Docker configuration directory so a Fly
//! token never appears in argv or the user's global Docker configuration.

use std::{
    collections::BTreeMap,
    path::Path,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use lightrail_plugin_protocol::{ErrorKind, PluginError, PluginResult};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::{
    io::AsyncWriteExt,
    process::{Child, Command},
    sync::Notify,
};

use crate::model::{Settings, Workload};

pub struct DockerSession {
    config: TempDir,
    timeout: Duration,
}

impl DockerSession {
    pub async fn login(
        settings: &Settings,
        token: &str,
        cancellation: &Cancellation,
    ) -> PluginResult<Self> {
        let config = tempfile::tempdir().map_err(local_io_error)?;
        make_private(config.path())?;
        let args = login_args(config.path(), &settings.registry);
        let timeout = Duration::from_secs(settings.command_timeout_seconds);
        run(
            "docker",
            &args,
            None,
            Some(token.as_bytes()),
            timeout,
            cancellation,
        )
        .await?;
        Ok(Self { config, timeout })
    }

    pub async fn build_and_push(
        &self,
        project_root: &Path,
        resolved_compose: &Path,
        settings: &Settings,
        workloads: &[Workload],
        cancellation: &Cancellation,
    ) -> PluginResult<()> {
        let built = workloads
            .iter()
            .filter(|workload| workload.build)
            .collect::<Vec<_>>();
        if built.is_empty() {
            return Ok(());
        }
        let overrides = tempfile::NamedTempFile::new().map_err(local_io_error)?;
        let services = built
            .iter()
            .map(|workload| (workload.service.clone(), json!({"image": workload.image})))
            .collect::<BTreeMap<_, _>>();
        serde_json::to_writer(overrides.as_file(), &json!({"services": services})).map_err(
            |_| {
                PluginError::permanent(
                    ErrorKind::Internal,
                    "build_override_failed",
                    "could not render the temporary Buildx override",
                )
            },
        )?;
        let mut args = vec![
            "--config".to_owned(),
            self.config.path().display().to_string(),
            "buildx".to_owned(),
            "bake".to_owned(),
            "--file".to_owned(),
            resolved_compose.display().to_string(),
            "--file".to_owned(),
            overrides.path().display().to_string(),
            "--set".to_owned(),
            format!("*.platform={}", settings.platform),
            "--push".to_owned(),
        ];
        args.extend(built.into_iter().map(|workload| workload.service.clone()));
        run(
            "docker",
            &args,
            Some(project_root),
            None,
            self.timeout,
            cancellation,
        )
        .await?;
        Ok(())
    }

    pub async fn resolve_digest(
        &self,
        image: &str,
        cancellation: &Cancellation,
    ) -> PluginResult<String> {
        let args = vec![
            "--config".to_owned(),
            self.config.path().display().to_string(),
            "buildx".to_owned(),
            "imagetools".to_owned(),
            "inspect".to_owned(),
            image.to_owned(),
            "--format".to_owned(),
            "{{json .Manifest}}".to_owned(),
        ];
        let output = run("docker", &args, None, None, self.timeout, cancellation).await?;
        let value: Value = serde_json::from_slice(&output).map_err(|_| {
            PluginError::retryable(
                ErrorKind::Unavailable,
                "image_digest_unavailable",
                "Docker Buildx did not return image manifest JSON",
            )
        })?;
        let digest = find_digest(&value).ok_or_else(|| {
            PluginError::retryable(
                ErrorKind::Unavailable,
                "image_digest_unavailable",
                "Docker Buildx did not return an immutable image digest",
            )
        })?;
        validate_digest(digest)?;
        let repository = image
            .split_once(':')
            .map_or(image, |(repository, _)| repository);
        Ok(format!("{repository}@{digest}"))
    }
}

#[derive(Default)]
pub struct Cancellation {
    cancelled: AtomicBool,
    notify: Notify,
}

impl Cancellation {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    pub fn check(&self) -> PluginResult<()> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(PluginError::permanent(
                ErrorKind::Cancelled,
                "operation_cancelled",
                "the Fly.io operation was cancelled",
            ));
        }
        Ok(())
    }

    pub(crate) async fn cancelled(&self) {
        if self.cancelled.load(Ordering::Acquire) {
            return;
        }
        self.notify.notified().await;
    }
}

pub type SharedCancellation = Arc<Cancellation>;

fn login_args(config: &Path, registry: &str) -> Vec<String> {
    vec![
        "--config".to_owned(),
        config.display().to_string(),
        "login".to_owned(),
        registry.to_owned(),
        "--username".to_owned(),
        "x".to_owned(),
        "--password-stdin".to_owned(),
    ]
}

async fn run(
    program: &str,
    args: &[String],
    current_dir: Option<&Path>,
    stdin: Option<&[u8]>,
    timeout: Duration,
    cancellation: &Cancellation,
) -> PluginResult<Vec<u8>> {
    cancellation.check()?;
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(current_dir) = current_dir {
        command.current_dir(current_dir);
    }
    let mut child = command
        .spawn()
        .map_err(|error| command_spawn_error(program, &error))?;
    if let Some(input) = stdin {
        write_stdin(&mut child, input).await?;
    }
    let wait = child.wait_with_output();
    tokio::pin!(wait);
    let timer = tokio::time::sleep(timeout);
    tokio::pin!(timer);
    let output = tokio::select! {
        result = &mut wait => result.map_err(|error| {
            PluginError::retryable(
                ErrorKind::Unavailable,
                "local_command_failed",
                format!("failed while waiting for local `{program}`: {error}"),
            )
        })?,
        () = cancellation.cancelled() => {
            return Err(PluginError::permanent(
                ErrorKind::Cancelled,
                "operation_cancelled",
                "the local Docker operation was cancelled",
            ));
        }
        () = &mut timer => {
            return Err(PluginError::retryable(
                ErrorKind::Timeout,
                "docker_command_timeout",
                format!("local `{program}` exceeded its configured timeout"),
            ));
        }
    };
    if !output.status.success() {
        return Err(PluginError::permanent(
            ErrorKind::Validation,
            "docker_command_failed",
            format!(
                "local `{program}` command failed with status {}",
                output.status
            ),
        ));
    }
    Ok(output.stdout)
}

async fn write_stdin(child: &mut Child, input: &[u8]) -> PluginResult<()> {
    let mut stdin = child.stdin.take().ok_or_else(|| {
        PluginError::permanent(
            ErrorKind::Internal,
            "docker_stdin_unavailable",
            "could not open Docker standard input",
        )
    })?;
    stdin.write_all(input).await.map_err(|_| {
        PluginError::retryable(
            ErrorKind::Unavailable,
            "docker_stdin_failed",
            "could not send the registry credential to Docker",
        )
    })?;
    stdin.write_all(b"\n").await.map_err(|_| {
        PluginError::retryable(
            ErrorKind::Unavailable,
            "docker_stdin_failed",
            "could not finish sending the registry credential to Docker",
        )
    })?;
    drop(stdin);
    Ok(())
}

fn find_digest(value: &Value) -> Option<&str> {
    match value {
        Value::Object(object) => object
            .get("digest")
            .or_else(|| object.get("Digest"))
            .and_then(Value::as_str)
            .or_else(|| object.values().find_map(find_digest)),
        Value::Array(array) => array.iter().find_map(find_digest),
        _ => None,
    }
}

fn validate_digest(digest: &str) -> PluginResult<()> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(invalid_digest());
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_digest());
    }
    Ok(())
}

fn invalid_digest() -> PluginError {
    PluginError::retryable(
        ErrorKind::Unavailable,
        "invalid_image_digest",
        "Docker Buildx returned an invalid image digest",
    )
}

fn command_spawn_error(program: &str, error: &std::io::Error) -> PluginError {
    let kind = if error.kind() == std::io::ErrorKind::NotFound {
        ErrorKind::Validation
    } else {
        ErrorKind::Unavailable
    };
    PluginError::permanent(
        kind,
        "docker_unavailable",
        format!("could not start local `{program}`: {error}"),
    )
}

#[allow(clippy::needless_pass_by_value)]
fn local_io_error(error: std::io::Error) -> PluginError {
    PluginError::permanent(
        ErrorKind::Internal,
        "temporary_file_failed",
        format!("could not prepare a private temporary file: {error}"),
    )
}

#[cfg(unix)]
fn make_private(path: &Path) -> PluginResult<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(local_io_error)
}

#[cfg(not(unix))]
fn make_private(_path: &Path) -> PluginResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use serde_json::json;

    use super::{Cancellation, find_digest, login_args, validate_digest};

    #[test]
    fn registry_token_is_never_a_login_argument() {
        let args = login_args(Path::new("/private/docker"), "registry.fly.io");
        assert!(args.contains(&"--password-stdin".to_owned()));
        assert!(!args.iter().any(|argument| argument == "super-secret"));
    }

    #[test]
    fn parses_nested_manifest_digest() {
        let value = json!({
            "Descriptor": {
                "digest": format!("sha256:{}", "a".repeat(64))
            }
        });
        assert_eq!(
            find_digest(&value),
            Some(format!("sha256:{}", "a".repeat(64)).as_str())
        );
    }

    #[test]
    fn rejects_non_sha256_digest() {
        assert!(validate_digest("sha1:abc").is_err());
    }

    #[tokio::test]
    async fn cancellation_wakes_waiters_and_fails_checks() {
        let cancellation = Cancellation::default();
        cancellation.cancel();
        cancellation.cancelled().await;
        let error = cancellation.check().expect_err("cancelled");
        assert_eq!(error.kind, lightrail_plugin_protocol::ErrorKind::Cancelled);
    }
}
