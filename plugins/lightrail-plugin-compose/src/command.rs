use std::{
    ffi::{OsStr, OsString},
    net::{IpAddr, ToSocketAddrs},
    path::Path,
    process::Stdio,
    time::Duration,
};

use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
};

use crate::{contract::TargetState, error::ComposePluginError};

const SSH_CONNECT_TIMEOUT_SECONDS: u64 = 15;

#[derive(Clone, Debug)]
pub struct CommandOutput {
    pub stdout: Vec<u8>,
}

pub async fn run_local<I, S>(
    program: &str,
    arguments: I,
    current_dir: Option<&Path>,
    input: Option<&[u8]>,
) -> Result<CommandOutput, ComposePluginError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = Command::new(program);
    command.args(arguments);
    if let Some(current_dir) = current_dir {
        command.current_dir(current_dir);
    }
    command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = command
        .spawn()
        .map_err(|source| ComposePluginError::CommandSpawn {
            program: program.to_owned(),
            source,
        })?;
    if let Some(input) = input {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| ComposePluginError::MissingPipe {
                program: program.to_owned(),
            })?;
        stdin
            .write_all(input)
            .await
            .map_err(ComposePluginError::TemporaryFile)?;
        stdin
            .shutdown()
            .await
            .map_err(ComposePluginError::TemporaryFile)?;
    }
    let output = child
        .wait_with_output()
        .await
        .map_err(ComposePluginError::TemporaryFile)?;
    if !output.status.success() {
        return Err(ComposePluginError::CommandFailed {
            program: program.to_owned(),
            status: status_text(output.status.code()),
        });
    }
    Ok(CommandOutput {
        stdout: output.stdout,
    })
}

pub async fn run_ssh<I, S>(
    target: &TargetState,
    remote_arguments: I,
) -> Result<CommandOutput, ComposePluginError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    run_ssh_with_input(target, remote_arguments, None).await
}

pub async fn run_ssh_with_input<I, S>(
    target: &TargetState,
    remote_arguments: I,
    input: Option<&[u8]>,
) -> Result<CommandOutput, ComposePluginError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    ensure_nonlocal_ssh_target(target).await?;
    let remote_arguments = remote_arguments
        .into_iter()
        .map(|argument| argument.as_ref().to_owned())
        .collect::<Vec<_>>();
    let remote_arguments = docker_aware_arguments(target, remote_arguments);
    let remote_command = remote_arguments
        .iter()
        .map(|argument| shell_quote(argument))
        .collect::<Vec<_>>()
        .join(" ");
    let arguments = ssh_arguments(target, &remote_command);
    run_local("ssh", arguments, None, input)
        .await
        .map_err(|error| map_ssh_error(error, &remote_command))
}

pub async fn run_ssh_script(
    target: &TargetState,
    script: &str,
    input: Option<&[u8]>,
) -> Result<CommandOutput, ComposePluginError> {
    ensure_nonlocal_ssh_target(target).await?;
    let arguments = ssh_arguments(target, script);
    run_local("ssh", arguments, None, input)
        .await
        .map_err(|error| map_ssh_error(error, "remote script"))
}

pub async fn upload_atomic(
    target: &TargetState,
    directory: &str,
    path: &str,
    contents: &[u8],
    mode: u16,
) -> Result<(), ComposePluginError> {
    validate_managed_path(directory)?;
    validate_managed_path(path)?;
    let temporary = format!("{path}.tmp");
    let script = format!(
        "umask 077 && mkdir -p -- {directory} && cat > {temporary} && chmod {mode:o} -- \
         {temporary} && mv -f -- {temporary} {path}",
        directory = shell_quote(directory),
        temporary = shell_quote(&temporary),
        path = shell_quote(path),
    );
    run_ssh_script(target, &script, Some(contents)).await?;
    Ok(())
}

pub async fn stream_image(target: &TargetState, image: &str) -> Result<(), ComposePluginError> {
    ensure_nonlocal_ssh_target(target).await?;
    let mut save = Command::new("docker");
    save.args(["image", "save", "--", image])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut save = save
        .spawn()
        .map_err(|source| ComposePluginError::CommandSpawn {
            program: "docker".to_owned(),
            source,
        })?;
    let mut save_stdout = save
        .stdout
        .take()
        .ok_or_else(|| ComposePluginError::MissingPipe {
            program: "docker image save".to_owned(),
        })?;

    let remote_command = format!("{} image load", target.docker_shell());
    let mut load = Command::new("ssh");
    load.args(ssh_arguments(target, &remote_command))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut load = load
        .spawn()
        .map_err(|source| ComposePluginError::CommandSpawn {
            program: "ssh".to_owned(),
            source,
        })?;
    let mut load_stdin = load
        .stdin
        .take()
        .ok_or_else(|| ComposePluginError::MissingPipe {
            program: "ssh docker image load".to_owned(),
        })?;

    tokio::io::copy(&mut save_stdout, &mut load_stdin)
        .await
        .map_err(ComposePluginError::TemporaryFile)?;
    load_stdin
        .shutdown()
        .await
        .map_err(ComposePluginError::TemporaryFile)?;
    drop(load_stdin);

    let (save_status, load_output) = tokio::join!(save.wait(), load.wait_with_output());
    let save_status = save_status.map_err(ComposePluginError::TemporaryFile)?;
    let load_output = load_output.map_err(ComposePluginError::TemporaryFile)?;
    if !save_status.success() {
        return Err(ComposePluginError::CommandFailed {
            program: "docker image save".to_owned(),
            status: status_text(save_status.code()),
        });
    }
    if !load_output.status.success() {
        return Err(ComposePluginError::SshUnavailable {
            operation: "docker image load".to_owned(),
        });
    }
    Ok(())
}

pub async fn read_ssh_lines(
    target: TargetState,
    remote_arguments: Vec<String>,
) -> Result<tokio::sync::mpsc::Receiver<String>, ComposePluginError> {
    ensure_nonlocal_ssh_target(&target).await?;
    let remote_arguments = docker_aware_arguments(&target, remote_arguments);
    let remote_command = remote_arguments
        .iter()
        .map(|argument| shell_quote(argument))
        .collect::<Vec<_>>()
        .join(" ");
    let mut command = Command::new("ssh");
    command
        .args(ssh_arguments(&target, &remote_command))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|source| ComposePluginError::CommandSpawn {
            program: "ssh".to_owned(),
            source,
        })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ComposePluginError::MissingPipe {
            program: "ssh".to_owned(),
        })?;
    let (sender, receiver) = tokio::sync::mpsc::channel(128);
    tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if sender.send(line).await.is_err() {
                break;
            }
        }
        let _ = child.wait().await;
    });
    Ok(receiver)
}

async fn ensure_nonlocal_ssh_target(target: &TargetState) -> Result<(), ComposePluginError> {
    if let Ok(address) = target.host.parse::<IpAddr>() {
        return validate_resolved_addresses(&target.host, [address]);
    }

    let host = target.host.clone();
    let port = target.port;
    let resolution_host = host.clone();
    let resolution = tokio::task::spawn_blocking(move || {
        (resolution_host.as_str(), port)
            .to_socket_addrs()
            .map(Iterator::collect::<Vec<_>>)
    });
    let addresses =
        tokio::time::timeout(Duration::from_secs(SSH_CONNECT_TIMEOUT_SECONDS), resolution)
            .await
            .map_err(|_| ComposePluginError::SshUnavailable {
                operation: format!(
                    "DNS resolution for SSH host `{host}` timed out after \
             {SSH_CONNECT_TIMEOUT_SECONDS} seconds"
                ),
            })?
            .map_err(|_| ComposePluginError::SshUnavailable {
                operation: format!("DNS resolution for SSH host `{host}`"),
            })?
            .map_err(|_| ComposePluginError::SshUnavailable {
                operation: format!("DNS resolution for SSH host `{host}`"),
            })?;
    validate_resolved_addresses(&host, addresses.into_iter().map(|address| address.ip()))
}

fn validate_resolved_addresses(
    host: &str,
    addresses: impl IntoIterator<Item = IpAddr>,
) -> Result<(), ComposePluginError> {
    let addresses = addresses.into_iter().collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(ComposePluginError::SshUnavailable {
            operation: format!("DNS resolution for SSH host `{host}` returned no addresses"),
        });
    }
    if addresses.iter().copied().any(is_loopback_address) {
        return Err(ComposePluginError::InvalidTarget(format!(
            "SSH host `{host}` resolves to a loopback address; local runtimes are not allowed"
        )));
    }
    Ok(())
}

fn is_loopback_address(address: IpAddr) -> bool {
    address.is_loopback()
        || matches!(
            address,
            IpAddr::V6(address)
                if address
                    .to_ipv4_mapped()
                    .is_some_and(|address| address.is_loopback())
        )
}

fn ssh_arguments(target: &TargetState, remote_command: &str) -> Vec<OsString> {
    let mut arguments = vec![
        OsString::from("-F"),
        OsString::from("/dev/null"),
        OsString::from("-o"),
        OsString::from("BatchMode=yes"),
        OsString::from("-o"),
        OsString::from(format!("ConnectTimeout={SSH_CONNECT_TIMEOUT_SECONDS}")),
        OsString::from("-o"),
        OsString::from("StrictHostKeyChecking=accept-new"),
        OsString::from("-o"),
        OsString::from("GlobalKnownHostsFile=/dev/null"),
        OsString::from("-p"),
        OsString::from(target.port.to_string()),
    ];
    if let Some(identity_file) = &target.identity_file {
        arguments.push(OsString::from("-i"));
        arguments.push(identity_file.as_os_str().to_owned());
    }
    if let Some(known_hosts_file) = &target.known_hosts_file {
        arguments.push(OsString::from("-o"));
        arguments.push(OsString::from(format!(
            "UserKnownHostsFile={}",
            openssh_quoted_path(known_hosts_file)
        )));
    }
    arguments.push(OsString::from(target.destination()));
    arguments.push(OsString::from(remote_command));
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

fn docker_aware_arguments(target: &TargetState, arguments: Vec<String>) -> Vec<String> {
    if arguments
        .first()
        .is_some_and(|argument| argument == "docker")
    {
        target.docker_arguments(arguments.into_iter().skip(1))
    } else {
        arguments
    }
}

pub fn shell_quote(value: &str) -> String {
    if !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b':' | b'=')
        })
    {
        return value.to_owned();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn validate_managed_path(value: &str) -> Result<(), ComposePluginError> {
    if value.is_empty()
        || value.contains('\0')
        || value.contains('\r')
        || value.contains('\n')
        || value.split('/').any(|part| part == "..")
    {
        return Err(ComposePluginError::UnsafeRemotePath);
    }
    Ok(())
}

fn map_ssh_error(error: ComposePluginError, operation: &str) -> ComposePluginError {
    match error {
        ComposePluginError::CommandFailed { .. } => ComposePluginError::SshUnavailable {
            operation: operation.to_owned(),
        },
        error => error,
    }
}

fn status_text(code: Option<i32>) -> String {
    code.map_or_else(
        || "terminated by signal".to_owned(),
        |code| code.to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn target(requires_sudo: bool) -> TargetState {
        serde_json::from_value(json!({
            "host": "8.8.8.8",
            "user": "deploy",
            "port": 2222,
            "public_ipv4": "8.8.8.8",
            "identity_file": "/home/me/.ssh/id_ed25519",
            "known_hosts_file": "/home/me/.ssh/known_hosts",
            "docker": {"requires_sudo": requires_sudo}
        }))
        .expect("target")
    }

    #[test]
    fn quotes_remote_shell_arguments_without_interpolation() {
        assert_eq!(shell_quote("docker"), "docker");
        assert_eq!(shell_quote("hello world"), "'hello world'");
        assert_eq!(shell_quote("it's"), "'it'\"'\"'s'");
        assert_eq!(shell_quote("$(touch /tmp/bad)"), "'$(touch /tmp/bad)'");
    }

    #[test]
    fn rejects_parent_traversal_in_managed_remote_paths() {
        assert!(validate_managed_path(".lightrail/env").is_ok());
        assert!(validate_managed_path(".lightrail/../etc").is_err());
    }

    #[test]
    fn ssh_arguments_ignore_user_configuration_and_preserve_target_transport() {
        let arguments = ssh_arguments(&target(false), "true");
        assert_eq!(arguments[0], "-F");
        assert_eq!(arguments[1], "/dev/null");
        assert!(arguments.windows(2).any(|pair| {
            pair == [
                OsString::from("-i"),
                OsString::from("/home/me/.ssh/id_ed25519"),
            ]
        }));
        assert!(
            arguments
                .iter()
                .any(|argument| { argument == "UserKnownHostsFile=\"/home/me/.ssh/known_hosts\"" })
        );
        assert!(
            arguments
                .iter()
                .any(|argument| argument == "GlobalKnownHostsFile=/dev/null")
        );
        assert!(
            arguments
                .iter()
                .any(|argument| argument == "deploy@8.8.8.8")
        );
    }

    #[test]
    fn resolved_alias_rejects_any_loopback_candidate() {
        let error = validate_resolved_addresses(
            "remote.example",
            [IpAddr::from([8, 8, 8, 8]), IpAddr::from([127, 0, 0, 1])],
        )
        .expect_err("an alias with any loopback candidate must be rejected");
        assert!(matches!(error, ComposePluginError::InvalidTarget(_)));

        let mapped = "::ffff:127.0.0.1"
            .parse::<IpAddr>()
            .expect("mapped loopback address");
        assert!(
            validate_resolved_addresses("mapped.example", [mapped]).is_err(),
            "IPv4-mapped loopback addresses must also be rejected"
        );
        assert!(
            validate_resolved_addresses("remote.example", [IpAddr::from([8, 8, 8, 8])]).is_ok()
        );
    }

    #[test]
    fn ssh_option_paths_are_quoted_without_creating_new_options() {
        assert_eq!(
            openssh_quoted_path(Path::new("/tmp/My Project=a%b\\c\"d")),
            "\"/tmp/My Project=a%%b\\\\c\\\"d\""
        );
    }

    #[test]
    fn empty_host_resolution_is_unavailable() {
        let error = validate_resolved_addresses("missing.example", Vec::<IpAddr>::new())
            .expect_err("an empty resolution must fail before SSH");
        assert!(matches!(error, ComposePluginError::SshUnavailable { .. }));
    }

    #[test]
    fn remote_docker_commands_follow_target_sudo_policy() {
        assert_eq!(
            docker_aware_arguments(&target(true), vec!["docker".to_owned(), "ps".to_owned()]),
            ["sudo", "-n", "docker", "ps"]
        );
        assert_eq!(
            docker_aware_arguments(&target(false), vec!["rm".to_owned(), "-f".to_owned()]),
            ["rm", "-f"]
        );
    }
}
