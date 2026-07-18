use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    time::{Duration, Instant},
};

use lightrail_plugin_protocol::{ErrorKind, PluginError, PluginResult};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, Command},
    time::{sleep, timeout},
};

use crate::model::{BootstrapMode, Settings, short_hash};

const READINESS_POLL_INTERVAL: Duration = Duration::from_millis(200);
const READINESS_RETRY_DELAY: Duration = Duration::from_secs(3);
const READINESS_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
const CHILD_REAP_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct SshTarget {
    pub host: String,
    pub user: String,
    pub port: u16,
    pub identity_file: Option<PathBuf>,
    pub known_hosts_file: PathBuf,
    pub remote_root: String,
    pub lock_key: String,
}

impl SshTarget {
    pub fn from_parts(
        host: impl Into<String>,
        settings: &Settings,
        remote_root: impl Into<String>,
        environment_id: &str,
        known_hosts_file: PathBuf,
    ) -> Self {
        Self {
            host: host.into(),
            user: settings.ssh_user.clone(),
            port: 22,
            identity_file: settings.identity_file.clone(),
            known_hosts_file,
            remote_root: remote_root.into(),
            lock_key: short_hash(environment_id, 32),
        }
    }
}

pub fn prepare_known_hosts_file(
    project_root: &Path,
    environment_scope: &str,
    server_id: u64,
) -> PluginResult<PathBuf> {
    if !project_root.is_absolute() {
        return Err(PluginError::permanent(
            ErrorKind::Validation,
            "project_root_not_absolute",
            "the project root must be absolute before preparing SSH host-key state",
        ));
    }
    let project_root_text = project_root.to_string_lossy();
    if project_root_text
        .bytes()
        .any(|byte| byte.is_ascii_control())
    {
        return Err(PluginError::permanent(
            ErrorKind::Validation,
            "project_root_unsafe_for_ssh",
            "the project root contains control characters unsupported by OpenSSH",
        ));
    }

    let state_directory = project_root.join(".lightrail");
    reject_symlink(&state_directory)?;
    let known_hosts_directory = state_directory.join("known_hosts");
    reject_symlink(&known_hosts_directory)?;
    fs::create_dir_all(&known_hosts_directory)
        .map_err(|error| known_hosts_io_error("create the host-key state directory", &error))?;
    reject_symlink(&state_directory)?;
    reject_symlink(&known_hosts_directory)?;
    set_private_directory_permissions(&known_hosts_directory)?;

    let path = known_hosts_directory.join(format!(
        "hetzner-{}-server-{server_id}",
        short_hash(environment_scope, 24)
    ));
    reject_symlink(&path)?;
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(&path)
        .map_err(|error| known_hosts_io_error("open the scoped host-key file", &error))?;
    reject_symlink(&path)?;
    set_private_file_permissions(&path)?;
    Ok(path)
}

fn reject_symlink(path: &Path) -> PluginResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(PluginError::permanent(
            ErrorKind::Validation,
            "known_hosts_symlink_rejected",
            "the managed SSH host-key path must not contain symbolic links",
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(known_hosts_io_error(
            "inspect the managed host-key path",
            &error,
        )),
    }
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> PluginResult<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| known_hosts_io_error("secure the host-key state directory", &error))
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> PluginResult<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> PluginResult<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| known_hosts_io_error("secure the scoped host-key file", &error))
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> PluginResult<()> {
    Ok(())
}

fn known_hosts_io_error(action: &str, error: &std::io::Error) -> PluginError {
    PluginError::permanent(
        ErrorKind::Internal,
        "known_hosts_state_unavailable",
        format!("could not {action}: {error}"),
    )
}

pub fn cloud_init(settings: &Settings, remote_root: &str) -> String {
    let install = match settings.bootstrap {
        BootstrapMode::Install => {
            r#"
if command -v docker >/dev/null 2>&1; then
  docker compose version >/dev/null 2>&1 || {
    echo "an existing Docker installation lacks a compatible Compose plugin" >&2
    exit 42
  }
else
  . /etc/os-release
  case "${ID:-}" in
    ubuntu|debian) ;;
    *) echo "only Ubuntu and Debian are supported" >&2; exit 43 ;;
  esac
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y ca-certificates curl
  curl -fsSL https://get.docker.com -o /tmp/lightrail-get-docker.sh
  sh /tmp/lightrail-get-docker.sh
  rm -f /tmp/lightrail-get-docker.sh
fi
systemctl enable --now docker
docker compose version >/dev/null
docker buildx version >/dev/null
"#
        }
        BootstrapMode::Verify => {
            r#"
command -v docker >/dev/null 2>&1 || {
  echo "Docker is required when bootstrap=verify" >&2
  exit 42
}
docker compose version >/dev/null 2>&1 || {
  echo "the Docker Compose plugin is required when bootstrap=verify" >&2
  exit 42
}
docker buildx version >/dev/null 2>&1 || {
  echo "Docker Buildx is required when bootstrap=verify" >&2
  exit 42
}
docker info >/dev/null
"#
        }
    };
    let user_setup = if settings.ssh_user == "root" {
        String::new()
    } else {
        format!(
            r"
if ! id -u {user} >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash {user}
fi
usermod -aG docker {user}
install -d -m 0700 -o {user} -g {user} /home/{user}/.ssh
if [ -f /root/.ssh/authorized_keys ]; then
  install -m 0600 -o {user} -g {user} /root/.ssh/authorized_keys /home/{user}/.ssh/authorized_keys
fi
",
            user = settings.ssh_user
        )
    };
    let root_mode = if settings.ssh_user == "root" {
        "0755"
    } else {
        "0775"
    };
    let root_owner = if settings.ssh_user == "root" {
        "root:root".to_owned()
    } else {
        format!("{}:docker", settings.ssh_user)
    };

    format!(
        r#"#cloud-config
write_files:
  - path: /usr/local/sbin/lightrail-bootstrap
    owner: root:root
    permissions: '0755'
    content: |
      #!/bin/sh
      set -eu
{script}
{user_setup}
      install -d -m {root_mode} -o {owner_user} -g {owner_group} {remote_root}
      docker info >/dev/null
      docker compose version >/dev/null
      docker buildx version >/dev/null
runcmd:
  - ["/usr/local/sbin/lightrail-bootstrap"]
"#,
        script = indent_script(install, 6),
        user_setup = indent_script(&user_setup, 6),
        root_mode = root_mode,
        owner_user = root_owner.split_once(':').map_or("root", |parts| parts.0),
        owner_group = root_owner.split_once(':').map_or("root", |parts| parts.1),
        remote_root = remote_root,
    )
}

fn indent_script(script: &str, spaces: usize) -> String {
    let prefix = " ".repeat(spaces);
    script
        .trim_matches('\n')
        .lines()
        .map(|line| format!("{prefix}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

pub async fn wait_until_ready(
    target: &SshTarget,
    maximum: Duration,
    mut cancelled: impl FnMut() -> bool,
) -> PluginResult<()> {
    let deadline = Instant::now() + maximum;
    let command = concat!(
        "cloud-init status --wait >/dev/null 2>&1 && ",
        "docker info >/dev/null 2>&1 && ",
        "docker compose version >/dev/null 2>&1 && ",
        "docker buildx version >/dev/null 2>&1"
    );
    loop {
        if cancelled() {
            return Err(PluginError::permanent(
                ErrorKind::Cancelled,
                "operation_cancelled",
                "the operation was cancelled",
            ));
        }
        let mut process = Command::new("ssh");
        add_ssh_args(&mut process, target);
        let child = process
            .arg(command)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn();
        if let Ok(mut child) = child {
            let attempt_deadline = (Instant::now() + READINESS_ATTEMPT_TIMEOUT).min(deadline);
            let status =
                wait_for_readiness_child(&mut child, attempt_deadline, &mut cancelled).await?;
            if status.is_some_and(|status| status.success()) {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err(bootstrap_timeout());
        }
        wait_before_retry(deadline, &mut cancelled).await?;
    }
}

async fn wait_for_readiness_child(
    child: &mut Child,
    deadline: Instant,
    cancelled: &mut impl FnMut() -> bool,
) -> PluginResult<Option<ExitStatus>> {
    loop {
        if cancelled() {
            terminate_child(child).await;
            return Err(operation_cancelled());
        }
        match child.try_wait() {
            Ok(Some(status)) => return Ok(Some(status)),
            Ok(None) => {}
            Err(_) => {
                terminate_child(child).await;
                return Ok(None);
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            terminate_child(child).await;
            return Ok(None);
        }
        sleep(remaining.min(READINESS_POLL_INTERVAL)).await;
    }
}

async fn wait_before_retry(
    deadline: Instant,
    cancelled: &mut impl FnMut() -> bool,
) -> PluginResult<()> {
    let retry_deadline = (Instant::now() + READINESS_RETRY_DELAY).min(deadline);
    loop {
        if cancelled() {
            return Err(operation_cancelled());
        }
        let remaining = retry_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return if Instant::now() >= deadline {
                Err(bootstrap_timeout())
            } else {
                Ok(())
            };
        }
        sleep(remaining.min(READINESS_POLL_INTERVAL)).await;
    }
}

async fn terminate_child(child: &mut Child) {
    let _ = child.start_kill();
    let _ = timeout(CHILD_REAP_TIMEOUT, child.wait()).await;
}

fn bootstrap_timeout() -> PluginError {
    PluginError::retryable(
        ErrorKind::Timeout,
        "bootstrap_timeout",
        "the server became reachable, but Docker and Compose did not become ready in time",
    )
}

fn operation_cancelled() -> PluginError {
    PluginError::permanent(
        ErrorKind::Cancelled,
        "operation_cancelled",
        "the operation was cancelled",
    )
}

pub async fn acquire_remote_flock(
    target: &SshTarget,
    timeout_duration: Duration,
) -> PluginResult<Child> {
    let wait_seconds = timeout_duration.as_secs_f64().max(0.001);
    let remote_command = format!(
        "flock -w {wait_seconds:.3} /tmp/lightrail-{}.lock sh -c \
         'printf \"LIGHTRAIL_LOCKED\\\\n\"; cat >/dev/null' || {{ \
         status=$?; if [ \"$status\" -eq 1 ]; then printf 'LIGHTRAIL_BUSY\\n'; fi; \
         exit \"$status\"; }}",
        target.lock_key
    );
    let mut command = Command::new("ssh");
    add_ssh_args(&mut command, target);
    let mut child = command
        .arg(remote_command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| {
            PluginError::permanent(
                ErrorKind::Unsupported,
                "ssh_unavailable",
                format!("could not start OpenSSH: {error}"),
            )
        })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        PluginError::permanent(
            ErrorKind::Internal,
            "ssh_stdout_missing",
            "could not observe the remote lock acknowledgement",
        )
    })?;
    let mut line = String::new();
    let read_result = timeout(
        timeout_duration,
        BufReader::new(stdout).read_line(&mut line),
    )
    .await;
    match read_result {
        Ok(Ok(_)) if line.trim() == "LIGHTRAIL_LOCKED" => Ok(child),
        Ok(Ok(_)) if line.trim() == "LIGHTRAIL_BUSY" => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err(PluginError::permanent(
                ErrorKind::LockUnavailable,
                "remote_lock_busy",
                "another operation holds the remote mutation lock",
            ))
        }
        _ => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err(PluginError::retryable(
                ErrorKind::Unavailable,
                "ssh_lock_unreachable",
                "the remote lock authority could not be reached",
            ))
        }
    }
}

fn add_ssh_args(command: &mut Command, target: &SshTarget) {
    command.args(ssh_arguments(target));
}

fn ssh_arguments(target: &SshTarget) -> Vec<OsString> {
    let mut arguments = vec![
        OsString::from("-F"),
        OsString::from("/dev/null"),
        OsString::from("-o"),
        OsString::from("BatchMode=yes"),
        OsString::from("-o"),
        OsString::from("StrictHostKeyChecking=accept-new"),
        OsString::from("-o"),
        OsString::from(format!(
            "UserKnownHostsFile={}",
            openssh_quoted_path(&target.known_hosts_file)
        )),
        OsString::from("-o"),
        OsString::from("GlobalKnownHostsFile=/dev/null"),
        OsString::from("-o"),
        OsString::from("ConnectTimeout=10"),
        OsString::from("-p"),
        OsString::from(target.port.to_string()),
    ];
    if let Some(identity_file) = &target.identity_file {
        arguments.push(OsString::from("-i"));
        arguments.push(identity_file.as_os_str().to_owned());
    }
    arguments.push(OsString::from(format!("{}@{}", target.user, target.host)));
    arguments
}

fn openssh_quoted_path(path: &Path) -> String {
    let escaped = path
        .to_string_lossy()
        .replace('%', "%%")
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn install_cloud_init_is_idempotent_and_contains_no_secret() {
        let settings = Settings {
            allowed_ssh_cidrs: vec!["203.0.113.9/32".to_owned()],
            ..Settings::default()
        };
        let generated = cloud_init(&settings, "/opt/lightrail/e-abc");
        assert!(generated.starts_with("#cloud-config"));
        assert!(generated.contains("if command -v docker"));
        assert!(generated.contains("docker compose version"));
        assert!(generated.contains("docker buildx version"));
        assert!(generated.contains("/opt/lightrail/e-abc"));
        assert!(!generated.contains("hetzner-token"));
        assert!(!generated.contains("203.0.113.9"));
    }

    #[test]
    fn verify_cloud_init_never_installs_packages() {
        let settings = Settings {
            bootstrap: BootstrapMode::Verify,
            allowed_ssh_cidrs: vec!["203.0.113.9/32".to_owned()],
            ..Settings::default()
        };
        let generated = cloud_init(&settings, "/opt/lightrail/e-abc");
        assert!(generated.contains("bootstrap=verify"));
        assert!(!generated.contains("get.docker.com"));
        assert!(!generated.contains("apt-get"));
    }

    #[test]
    fn non_root_user_is_created_without_shell_interpolation() {
        let settings = Settings {
            ssh_user: "deployer".to_owned(),
            ssh_keys: vec!["operator".to_owned()],
            allowed_ssh_cidrs: vec!["203.0.113.9/32".to_owned()],
            ..Settings::default()
        };
        settings.validate().unwrap();
        let generated = cloud_init(&settings, "/opt/lightrail/e-abc");
        assert!(generated.contains("useradd --create-home --shell /bin/bash deployer"));
        assert!(generated.contains("-o deployer -g docker"));
    }

    #[test]
    fn known_hosts_file_is_private_scoped_and_never_truncated() {
        let project = tempdir().unwrap();
        let first = prepare_known_hosts_file(project.path(), "../../environment one", 7).unwrap();
        assert!(first.is_absolute());
        assert!(first.starts_with(project.path().join(".lightrail/known_hosts")));
        assert!(!first.to_string_lossy().contains("environment one"));

        fs::write(&first, "preserved-key\n").unwrap();
        let repeated =
            prepare_known_hosts_file(project.path(), "../../environment one", 7).unwrap();
        let other_environment =
            prepare_known_hosts_file(project.path(), "other-environment", 7).unwrap();
        let other_server =
            prepare_known_hosts_file(project.path(), "../../environment one", 8).unwrap();
        assert_eq!(first, repeated);
        assert_ne!(first, other_environment);
        assert_ne!(first, other_server);
        assert_eq!(fs::read_to_string(first).unwrap(), "preserved-key\n");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let directory_mode = fs::metadata(project.path().join(".lightrail/known_hosts"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            let file_mode = fs::metadata(repeated).unwrap().permissions().mode() & 0o777;
            assert_eq!(directory_mode, 0o700);
            assert_eq!(file_mode, 0o600);
        }
    }

    #[test]
    fn known_hosts_file_requires_an_absolute_control_free_project_root() {
        assert!(prepare_known_hosts_file(Path::new("relative"), "environment", 7).is_err());
        assert!(
            prepare_known_hosts_file(Path::new("/tmp/project\nbad"), "environment", 7).is_err()
        );
    }

    #[test]
    fn known_hosts_file_supports_valid_project_root_characters() {
        let parent = tempdir().unwrap();
        let project = parent.path().join("project with spaces=100%");
        fs::create_dir(&project).unwrap();
        let path = prepare_known_hosts_file(&project, "environment", 7).unwrap();
        assert!(path.starts_with(project.join(".lightrail/known_hosts")));
    }

    #[test]
    fn ssh_uses_only_the_scoped_host_key_authority() {
        let target = SshTarget::from_parts(
            "203.0.113.7",
            &Settings::default(),
            "/opt/lightrail/e-def",
            "environment",
            PathBuf::from("/tmp/project/.lightrail/known_hosts/server-7"),
        );
        let arguments = ssh_arguments(&target);
        assert_eq!(arguments[0], "-F");
        assert_eq!(arguments[1], "/dev/null");
        assert!(arguments.iter().any(|argument| {
            argument == "UserKnownHostsFile=\"/tmp/project/.lightrail/known_hosts/server-7\""
        }));
        assert!(
            arguments
                .iter()
                .any(|argument| argument == "GlobalKnownHostsFile=/dev/null")
        );
        assert!(
            arguments
                .iter()
                .any(|argument| argument == "StrictHostKeyChecking=accept-new")
        );
        assert!(
            arguments
                .iter()
                .all(|argument| argument != "StrictHostKeyChecking=no")
        );
    }

    #[tokio::test]
    async fn readiness_child_is_killed_at_the_deadline() {
        let mut child = Command::new("sh")
            .args(["-c", "sleep 30"])
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let started = Instant::now();
        let status =
            wait_for_readiness_child(&mut child, started + Duration::from_millis(50), &mut || {
                false
            })
            .await
            .unwrap();
        assert!(status.is_none());
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(child.try_wait().unwrap().is_some());
    }

    #[tokio::test]
    async fn readiness_child_responds_to_cancellation() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&cancelled);
        tokio::spawn(async move {
            sleep(Duration::from_millis(25)).await;
            signal.store(true, Ordering::SeqCst);
        });
        let mut child = Command::new("sh")
            .args(["-c", "sleep 30"])
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let started = Instant::now();
        let error =
            wait_for_readiness_child(&mut child, started + Duration::from_secs(30), &mut || {
                cancelled.load(Ordering::SeqCst)
            })
            .await
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Cancelled);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(child.try_wait().unwrap().is_some());
    }

    #[test]
    fn openssh_path_quoting_preserves_option_boundaries() {
        assert_eq!(
            openssh_quoted_path(Path::new("/tmp/My Project=a%b\\c\"d")),
            "\"/tmp/My Project=a%%b\\\\c\\\"d\""
        );
    }
}
