use std::{
    path::PathBuf,
    process::Stdio,
    time::{Duration, Instant},
};

use lightrail_plugin_protocol::{ErrorKind, PluginError, PluginResult};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, Command},
    time::{sleep, timeout},
};

use crate::model::{BootstrapMode, Settings, short_hash};

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct SshTarget {
    pub host: String,
    pub user: String,
    pub port: u16,
    pub identity_file: Option<PathBuf>,
    pub remote_root: String,
    pub lock_key: String,
}

impl SshTarget {
    pub fn from_parts(
        host: impl Into<String>,
        settings: &Settings,
        remote_root: impl Into<String>,
        environment_id: &str,
    ) -> Self {
        Self {
            host: host.into(),
            user: settings.ssh_user.clone(),
            port: 22,
            identity_file: settings.identity_file.clone(),
            remote_root: remote_root.into(),
            lock_key: short_hash(environment_id, 32),
        }
    }
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
        let status = process
            .arg(command)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
        if status.is_ok_and(|status| status.success()) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(PluginError::retryable(
                ErrorKind::Timeout,
                "bootstrap_timeout",
                "the server became reachable, but Docker and Compose did not become ready in time",
            ));
        }
        sleep(Duration::from_secs(3)).await;
    }
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
    command
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("StrictHostKeyChecking=accept-new")
        .arg("-o")
        .arg("ConnectTimeout=10")
        .arg("-p")
        .arg(target.port.to_string());
    if let Some(identity_file) = &target.identity_file {
        command.arg("-i").arg(identity_file);
    }
    command.arg(format!("{}@{}", target.user, target.host));
}

#[cfg(test)]
mod tests {
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
}
