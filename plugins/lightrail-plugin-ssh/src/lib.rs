//! Agentless generic SSH target and authoritative remote operation locks.
//!
//! The plugin never installs a Lightrail agent. It invokes the local OpenSSH
//! client with fixed options, probes the remote host using POSIX shell, and can
//! bootstrap Docker on supported Ubuntu and Debian hosts.

use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, Ipv4Addr, ToSocketAddrs},
    path::{Component, Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use lightrail_plugin_protocol::{
    ActionJournalEntry, ApplyRequest, ApplyResult, Capability, DestroyRequest, DestroyResult,
    Diagnostic, DiagnosticSeverity, EventSink, ExecutableMetadata, InspectRequest, InspectResult,
    JournalStatus, LockAcquireRequest, LockAcquireResult, LockReleaseRequest, LockReleaseResult,
    LockScope, OperationContext, PlanRequest, PlanResult, PlannedAction, Platform, PluginError,
    PluginEvent, PluginHandler, PluginManifest, PluginResult, ProtocolCompatibility,
    ResourceStatus, SecretValue, ValidateRequest, ValidateResult,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, Command},
    sync::{Mutex, RwLock},
    time::timeout,
};
use uuid::Uuid;

const CONNECT_TIMEOUT_SECONDS: u64 = 15;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(90);
const HOST_LOCK_DIRECTORY: &str = "/tmp/lightrail-host.operation.lock";
const PROBE_SCRIPT: &str = include_str!("remote/probe.sh");
const BOOTSTRAP_SCRIPT: &str = include_str!("remote/bootstrap.sh");

/// Docker bootstrap policy for a generic host.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapMode {
    /// Install missing Docker Engine, Compose, and Buildx components.
    #[serde(alias = "auto")]
    #[default]
    Install,
    /// Inspect requirements without changing the host.
    Verify,
}

/// How privileged remote commands may be executed.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SudoMode {
    /// Use direct access as root and otherwise use passwordless `sudo` when needed.
    #[default]
    Auto,
    /// Require root or passwordless `sudo` for privileged operations.
    Required,
    /// Never invoke `sudo`; installation is possible only as root.
    Never,
}

impl SudoMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Required => "required",
            Self::Never => "never",
        }
    }
}

/// Isolation supported by the generic SSH target.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Isolation {
    /// Multiple Lightrail environments share one host and its Traefik instance.
    #[default]
    Project,
    /// Reserved for providers that can own and destroy a complete machine.
    Machine,
}

/// Validated plugin configuration supplied in `OperationContext.config`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct Settings {
    /// SSH host name or address.
    pub host: String,
    /// Remote login user.
    pub user: String,
    /// SSH TCP port.
    pub port: u16,
    /// Optional local private-key path passed to OpenSSH.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_file: Option<PathBuf>,
    /// Optional dedicated known-hosts file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub known_hosts_file: Option<PathBuf>,
    /// Directory in which runtime plugins place environment data.
    pub remote_root: String,
    /// Docker bootstrap policy.
    pub bootstrap: BootstrapMode,
    /// Privilege escalation policy.
    pub sudo: SudoMode,
    /// Public IPv4 used for sslip.io/nip.io hostnames.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_ipv4: Option<Ipv4Addr>,
    /// Resource isolation. Generic SSH supports only `project`.
    pub isolation: Isolation,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            host: String::new(),
            user: "root".to_owned(),
            port: 22,
            identity_file: None,
            known_hosts_file: None,
            remote_root: "/var/lib/lightrail".to_owned(),
            bootstrap: BootstrapMode::Install,
            sudo: SudoMode::Auto,
            public_ipv4: None,
            isolation: Isolation::Project,
        }
    }
}

impl Settings {
    fn parse(value: Value) -> Result<Self, ConfigIssue> {
        let settings: Self = serde_json::from_value(value).map_err(|error| ConfigIssue {
            code: "invalid_config",
            message: format!("invalid SSH target configuration: {error}"),
            path: None,
        })?;
        settings.validate()?;
        Ok(settings)
    }

    fn validate(&self) -> Result<(), ConfigIssue> {
        validate_host(&self.host)?;
        validate_user(&self.user)?;
        if self.port == 0 {
            return Err(ConfigIssue::at(
                "invalid_port",
                "SSH port must be between 1 and 65535",
                "/port",
            ));
        }
        validate_local_path(self.identity_file.as_deref(), "/identity_file")?;
        validate_known_hosts_path(self.known_hosts_file.as_deref())?;
        validate_remote_root(&self.remote_root)?;
        if self.isolation != Isolation::Project {
            return Err(ConfigIssue::at(
                "unsupported_isolation",
                "generic SSH targets support only project isolation; use the Hetzner target for machine isolation",
                "/isolation",
            ));
        }
        if let Some(address) = self.effective_public_ipv4() {
            if !is_public_ipv4(address) {
                return Err(ConfigIssue::at(
                    "invalid_public_ipv4",
                    "public_ipv4 must be a publicly routable unicast IPv4 address",
                    "/public_ipv4",
                ));
            }
        }
        if self.effective_public_ipv4().is_none() {
            return Err(ConfigIssue::at(
                "missing_public_ipv4",
                "public_ipv4 is required when host is not a public IPv4 address",
                "/public_ipv4",
            ));
        }
        Ok(())
    }

    fn effective_public_ipv4(&self) -> Option<Ipv4Addr> {
        self.public_ipv4.or_else(|| {
            self.host
                .parse::<IpAddr>()
                .ok()
                .and_then(|address| match address {
                    IpAddr::V4(address) => Some(address),
                    IpAddr::V6(_) => None,
                })
        })
    }
}

#[derive(Debug)]
struct ConfigIssue {
    code: &'static str,
    message: String,
    path: Option<&'static str>,
}

impl ConfigIssue {
    fn at(code: &'static str, message: impl Into<String>, path: &'static str) -> Self {
        Self {
            code,
            message: message.into(),
            path: Some(path),
        }
    }

    fn diagnostic(&self) -> Diagnostic {
        Diagnostic {
            severity: DiagnosticSeverity::Error,
            code: self.code.to_owned(),
            message: self.message.clone(),
            path: self.path.map(str::to_owned),
            help: None,
        }
    }

    fn plugin_error(&self) -> PluginError {
        PluginError::permanent(ErrorKind::Validation, self.code, self.message.clone())
    }
}

use lightrail_plugin_protocol::ErrorKind;

#[derive(Clone, Debug, Eq, PartialEq)]
struct SshInvocation {
    args: Vec<String>,
    remote_command: String,
}

impl SshInvocation {
    fn new(settings: &Settings, remote_command: impl Into<String>) -> Self {
        let remote_command = remote_command.into();
        let mut args = vec![
            "-F".to_owned(),
            "/dev/null".to_owned(),
            "-o".to_owned(),
            "BatchMode=yes".to_owned(),
            "-o".to_owned(),
            "StrictHostKeyChecking=accept-new".to_owned(),
            "-o".to_owned(),
            format!("ConnectTimeout={CONNECT_TIMEOUT_SECONDS}"),
            "-o".to_owned(),
            "ServerAliveInterval=15".to_owned(),
            "-o".to_owned(),
            "ServerAliveCountMax=2".to_owned(),
            "-o".to_owned(),
            "LogLevel=ERROR".to_owned(),
            "-p".to_owned(),
            settings.port.to_string(),
        ];
        if let Some(path) = &settings.identity_file {
            args.push("-i".to_owned());
            args.push(path.to_string_lossy().into_owned());
        }
        if let Some(path) = &settings.known_hosts_file {
            args.push("-o".to_owned());
            args.push(format!("UserKnownHostsFile={}", path.to_string_lossy()));
        }
        args.push("--".to_owned());
        args.push(format!("{}@{}", settings.user, settings.host));
        args.push(remote_command.clone());
        Self {
            args,
            remote_command,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new("ssh");
        command
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        command
    }
}

// These are independent observations from a shell probe, not mutually
// exclusive state-machine transitions.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Probe {
    os_id: String,
    os_version: String,
    arch: String,
    uid: u32,
    sudo_available: bool,
    docker_cli: bool,
    docker_ready: bool,
    docker_via_sudo: bool,
    compose: bool,
    buildx: bool,
    remote_root_ready: bool,
    port_80_in_use: bool,
    port_443_in_use: bool,
    firewall: String,
    firewall_80: FirewallAccess,
    firewall_443: FirewallAccess,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum FirewallAccess {
    Allow,
    Deny,
    #[default]
    Unknown,
}

impl Probe {
    fn parse(output: &str) -> Result<Self, PluginError> {
        let fields: BTreeMap<&str, &str> = output
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect();
        let required = |name: &str| {
            fields.get(name).copied().ok_or_else(|| {
                PluginError::permanent(
                    ErrorKind::Internal,
                    "invalid_probe_output",
                    format!("remote host probe did not return `{name}`"),
                )
            })
        };
        let boolean = |name: &str| -> PluginResult<bool> {
            match required(name)? {
                "0" => Ok(false),
                "1" => Ok(true),
                _ => Err(PluginError::permanent(
                    ErrorKind::Internal,
                    "invalid_probe_output",
                    format!("remote host probe returned an invalid `{name}` value"),
                )),
            }
        };
        let access = |name: &str| -> PluginResult<FirewallAccess> {
            match required(name)? {
                "allow" => Ok(FirewallAccess::Allow),
                "deny" => Ok(FirewallAccess::Deny),
                "unknown" => Ok(FirewallAccess::Unknown),
                _ => Err(PluginError::permanent(
                    ErrorKind::Internal,
                    "invalid_probe_output",
                    format!("remote host probe returned an invalid `{name}` value"),
                )),
            }
        };
        let raw_arch = required("arch")?;
        let arch = match raw_arch {
            "x86_64" | "amd64" => "amd64",
            "aarch64" | "arm64" => "arm64",
            other => other,
        }
        .to_owned();
        Ok(Self {
            os_id: required("os_id")?.to_owned(),
            os_version: required("os_version")?.to_owned(),
            arch,
            uid: required("uid")?.parse().map_err(|_| {
                PluginError::permanent(
                    ErrorKind::Internal,
                    "invalid_probe_output",
                    "remote host probe returned an invalid uid",
                )
            })?,
            sudo_available: boolean("sudo_available")?,
            docker_cli: boolean("docker_cli")?,
            docker_ready: boolean("docker_ready")?,
            docker_via_sudo: boolean("docker_via_sudo")?,
            compose: boolean("compose")?,
            buildx: boolean("buildx")?,
            remote_root_ready: boolean("remote_root_ready")?,
            port_80_in_use: boolean("port_80_in_use")?,
            port_443_in_use: boolean("port_443_in_use")?,
            firewall: required("firewall")?.to_owned(),
            firewall_80: access("firewall_80")?,
            firewall_443: access("firewall_443")?,
        })
    }

    fn supported_os(&self) -> bool {
        matches!(self.os_id.as_str(), "ubuntu" | "debian")
    }

    fn supported_arch(&self) -> bool {
        matches!(self.arch.as_str(), "amd64" | "arm64")
    }

    fn runtime_ready(&self, settings: &Settings) -> bool {
        self.docker_stack_ready(settings) && self.remote_root_ready
    }

    fn docker_stack_ready(&self, settings: &Settings) -> bool {
        self.docker_cli
            && self.docker_ready
            && self.compose
            && self.buildx
            && !(self.docker_via_sudo && settings.sudo == SudoMode::Never)
    }

    fn can_elevate(&self, settings: &Settings) -> bool {
        self.uid == 0
            || (settings.sudo != SudoMode::Never
                && self.sudo_available
                && matches!(settings.sudo, SudoMode::Auto | SudoMode::Required))
    }
}

#[derive(Debug)]
struct HeldLock {
    scope: String,
    request_scope: LockScope,
    scope_id: String,
    environment_id: String,
    operation_id: String,
    child: Child,
    stdin: Option<ChildStdin>,
}

/// External SSH target plugin.
pub struct SshPlugin {
    settings: RwLock<HashMap<String, Settings>>,
    locks: Mutex<HashMap<String, HeldLock>>,
}

impl Default for SshPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl SshPlugin {
    /// Create a process-local plugin session.
    #[must_use]
    pub fn new() -> Self {
        Self {
            settings: RwLock::new(HashMap::new()),
            locks: Mutex::new(HashMap::new()),
        }
    }

    async fn remember_settings(&self, context: &OperationContext) -> PluginResult<Arc<Settings>> {
        let settings = Arc::new(
            Settings::parse(context.config.clone()).map_err(|error| error.plugin_error())?,
        );
        self.settings
            .write()
            .await
            .insert(context.environment_id.clone(), (*settings).clone());
        Ok(settings)
    }

    async fn probe(&self, settings: &Settings) -> PluginResult<Probe> {
        let remote_command = format!(
            "LIGHTRAIL_REMOTE_ROOT={} LIGHTRAIL_SUDO_MODE={} sh -s",
            shell_quote(&settings.remote_root),
            shell_quote(settings.sudo.as_str())
        );
        let output = run_ssh(
            settings,
            &remote_command,
            PROBE_SCRIPT.as_bytes(),
            COMMAND_TIMEOUT,
        )
        .await?;
        Probe::parse(&output)
    }

    async fn inspect_inner(&self, settings: &Settings) -> PluginResult<(Probe, InspectResult)> {
        let probe = self.probe(settings).await?;
        let diagnostics = diagnostics(settings, &probe);
        let blocking = diagnostics
            .iter()
            .any(|item| item.severity == DiagnosticSeverity::Error);
        let status = if probe.runtime_ready(settings) && !blocking {
            ResourceStatus::Ready
        } else {
            ResourceStatus::Degraded
        };
        let state = target_state(settings, &probe);
        Ok((
            probe,
            InspectResult {
                status,
                endpoints: Vec::new(),
                state,
                diagnostics,
            },
        ))
    }

    async fn apply_bootstrap(
        &self,
        settings: &Settings,
        operation_id: &str,
        events: &EventSink,
    ) -> PluginResult<()> {
        events
            .emit(&PluginEvent::Progress {
                operation_id: operation_id.to_owned(),
                message: "Bootstrapping Docker and the remote deployment root".to_owned(),
                completed: Some(0),
                total: Some(1),
            })
            .await
            .map_err(serve_to_plugin_error)?;
        let remote_command = format!(
            "LIGHTRAIL_REMOTE_ROOT={} LIGHTRAIL_SUDO_MODE={} sh -s",
            shell_quote(&settings.remote_root),
            shell_quote(settings.sudo.as_str())
        );
        run_ssh(
            settings,
            &remote_command,
            BOOTSTRAP_SCRIPT.as_bytes(),
            Duration::from_secs(15 * 60),
        )
        .await?;
        events
            .emit(&PluginEvent::Progress {
                operation_id: operation_id.to_owned(),
                message: "Remote Docker prerequisites are ready".to_owned(),
                completed: Some(1),
                total: Some(1),
            })
            .await
            .map_err(serve_to_plugin_error)
    }

    async fn spawn_lock(
        &self,
        settings: &Settings,
        request: &LockAcquireRequest,
    ) -> PluginResult<Option<(Child, ChildStdin)>> {
        ensure_nonlocal_host(settings).await?;
        let script = lock_script(request.timeout_ms);
        let remote_command = format!("sh -c {}", shell_quote(&script));
        let invocation = SshInvocation::new(settings, remote_command);
        let mut child = invocation.command().spawn().map_err(|error| {
            PluginError::retryable(
                ErrorKind::Unavailable,
                "ssh_spawn_failed",
                format!("could not start OpenSSH: {error}"),
            )
        })?;
        let stdin = child.stdin.take().ok_or_else(|| {
            PluginError::permanent(
                ErrorKind::Internal,
                "ssh_pipe_failed",
                "OpenSSH lock process did not expose stdin",
            )
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            PluginError::permanent(
                ErrorKind::Internal,
                "ssh_pipe_failed",
                "OpenSSH lock process did not expose stdout",
            )
        })?;
        let mut reader = BufReader::new(stdout);
        let mut marker = String::new();
        // The user-supplied budget applies to contention on the remote host.
        // Allow separate bounded time for establishing SSH and returning the
        // final BUSY/LOCKED marker.
        let response_timeout = Duration::from_millis(request.timeout_ms.max(1))
            .saturating_add(Duration::from_secs(CONNECT_TIMEOUT_SECONDS + 5));
        let read = timeout(response_timeout, reader.read_line(&mut marker))
            .await
            .map_err(|_| {
                PluginError::retryable(
                    ErrorKind::Timeout,
                    "lock_timeout",
                    "timed out waiting for the remote operation lock",
                )
            })?
            .map_err(|error| {
                PluginError::retryable(
                    ErrorKind::Unavailable,
                    "ssh_read_failed",
                    format!("failed reading the remote lock response: {error}"),
                )
            })?;
        match marker.trim_end() {
            "LIGHTRAIL_LOCKED" => Ok(Some((child, stdin))),
            "LIGHTRAIL_BUSY" => Ok(None),
            _ if read == 0 => {
                let stderr = read_child_stderr(&mut child).await;
                let status = child
                    .try_wait()
                    .ok()
                    .flatten()
                    .and_then(|status| status.code());
                Err(classify_ssh_failure(status, &stderr))
            }
            _ => Err(PluginError::permanent(
                ErrorKind::Internal,
                "invalid_lock_response",
                "remote lock process returned an invalid response",
            )),
        }
    }

    async fn existing_lock_result(
        &self,
        settings: &Settings,
        request: &LockAcquireRequest,
    ) -> PluginResult<Option<LockAcquireResult>> {
        let scope = lock_scope(settings);
        let mut locks = self.locks.lock().await;
        let Some(token) = locks
            .iter()
            .find_map(|(token, lock)| (lock.scope == scope).then(|| token.clone()))
        else {
            return Ok(None);
        };

        let process_failure = {
            let lock = locks
                .get_mut(&token)
                .expect("lock token came from the same map");
            match lock.child.try_wait() {
                Ok(None) => None,
                Ok(Some(status)) => Some(format!(
                    "the SSH process holding the remote operation lock exited with {status}"
                )),
                Err(error) => Some(format!(
                    "the SSH process holding the remote operation lock could not be checked: {error}"
                )),
            }
        };
        if let Some(message) = process_failure {
            let mut lost = locks
                .remove(&token)
                .expect("lock exists after its process was checked");
            drop(lost.stdin.take());
            let _ = lost.child.start_kill();
            drop(locks);
            return Err(PluginError::retryable(
                ErrorKind::Unavailable,
                "lock_lost",
                message,
            ));
        }

        let lock = locks
            .get(&token)
            .expect("live lock exists after its process was checked");
        if lock.environment_id == request.environment_id
            && lock.operation_id == request.operation_id
        {
            if lock.request_scope != request.scope || lock.scope_id != request.scope_id {
                return Err(PluginError::permanent(
                    ErrorKind::Conflict,
                    "lock_scope_mismatch",
                    "operation lock scope changed while reasserting the same lock owner",
                ));
            }
            return Ok(Some(LockAcquireResult {
                acquired: true,
                token: Some(SecretValue::new(token)),
                expires_at: None,
                holder: None,
            }));
        }
        Ok(Some(LockAcquireResult {
            acquired: false,
            token: None,
            expires_at: None,
            holder: Some(format!("operation {}", lock.operation_id)),
        }))
    }

    fn validate_apply_plan(settings: &Settings, plan: &PlanResult) -> PluginResult<bool> {
        let expected_digest = settings_digest(settings)?;
        if plan.metadata.get("config_digest").and_then(Value::as_str)
            != Some(expected_digest.as_str())
        {
            return Err(PluginError::permanent(
                ErrorKind::Conflict,
                "stale_plan",
                "SSH target configuration changed after the plan was created",
            ));
        }
        let planned_bootstrap = plan
            .metadata
            .get("needs_bootstrap")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let action_has_bootstrap = plan
            .actions
            .iter()
            .any(|action| action.kind == "ssh.bootstrap");
        if plan.plan_id != plan_id(settings, planned_bootstrap)?
            || planned_bootstrap != action_has_bootstrap
        {
            return Err(PluginError::permanent(
                ErrorKind::Conflict,
                "stale_plan",
                "SSH target plan ID or action set is inconsistent with its configuration",
            ));
        }
        if plan
            .actions
            .iter()
            .any(|action| action.kind != "ssh.bootstrap")
        {
            return Err(PluginError::permanent(
                ErrorKind::Validation,
                "unknown_action",
                "SSH target plan contains an unsupported action",
            ));
        }
        Ok(planned_bootstrap)
    }
}

#[async_trait]
impl PluginHandler for SshPlugin {
    fn manifest(&self) -> PluginManifest {
        PluginManifest {
            id: "dev.lightrail.ssh".to_owned(),
            name: "Lightrail generic SSH target".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            protocol: ProtocolCompatibility::default(),
            executable: ExecutableMetadata {
                command: Some("lightrail-plugin-ssh".to_owned()),
                args: Vec::new(),
                platforms: vec![
                    Platform {
                        os: "linux".to_owned(),
                        arch: "amd64".to_owned(),
                    },
                    Platform {
                        os: "linux".to_owned(),
                        arch: "arm64".to_owned(),
                    },
                    Platform {
                        os: "macos".to_owned(),
                        arch: "amd64".to_owned(),
                    },
                    Platform {
                        os: "macos".to_owned(),
                        arch: "arm64".to_owned(),
                    },
                ],
                sha256: None,
                homepage: None,
            },
            capabilities: vec![Capability::Target, Capability::OperationLock],
            required_secrets: Vec::new(),
            config_schema: config_schema(),
            config_ui_hints: json!({
                "/identity_file": {"widget": "file"},
                "/known_hosts_file": {"widget": "file"},
                "/public_ipv4": {"placeholder": "203.0.113.10"}
            }),
        }
    }

    async fn validate(
        &self,
        request: ValidateRequest,
        _events: &EventSink,
    ) -> PluginResult<ValidateResult> {
        let settings = match Settings::parse(request.context.config.clone()) {
            Ok(settings) => settings,
            Err(error) => {
                return Ok(ValidateResult {
                    valid: false,
                    diagnostics: vec![error.diagnostic()],
                    normalized_config: None,
                });
            }
        };
        self.settings
            .write()
            .await
            .insert(request.context.environment_id, settings.clone());
        match self.probe(&settings).await {
            Ok(probe) => {
                let diagnostics = diagnostics(&settings, &probe);
                let valid = !diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error);
                Ok(ValidateResult {
                    valid,
                    diagnostics,
                    normalized_config: Some(
                        serde_json::to_value(settings)
                            .map_err(|error| serialization_error(&error))?,
                    ),
                })
            }
            Err(error) => Ok(ValidateResult {
                valid: false,
                diagnostics: vec![Diagnostic {
                    severity: DiagnosticSeverity::Error,
                    code: error.code,
                    message: error.message,
                    path: None,
                    help: Some(
                        "Check the SSH host, user, key, port, host key, and network route"
                            .to_owned(),
                    ),
                }],
                normalized_config: Some(
                    serde_json::to_value(settings).map_err(|error| serialization_error(&error))?,
                ),
            }),
        }
    }

    async fn plan(&self, request: PlanRequest, _events: &EventSink) -> PluginResult<PlanResult> {
        let settings = self.remember_settings(&request.context).await?;
        if request
            .desired
            .get("destroy")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Ok(PlanResult {
                plan_id: destroy_plan_id(&settings)?,
                actions: Vec::new(),
                has_changes: false,
                metadata: json!({
                    "config_digest": settings_digest(&settings)?,
                    "destroy": true,
                    "retained": true,
                }),
            });
        }
        let probe = self.probe(&settings).await?;
        let diagnostics = diagnostics(&settings, &probe);
        if let Some(error) = diagnostics
            .iter()
            .find(|item| item.severity == DiagnosticSeverity::Error)
        {
            return Err(PluginError::permanent(
                ErrorKind::Validation,
                &error.code,
                &error.message,
            ));
        }
        let needs_bootstrap = !probe.runtime_ready(&settings);
        let actions = if needs_bootstrap {
            vec![PlannedAction {
                id: "bootstrap-remote".to_owned(),
                kind: "ssh.bootstrap".to_owned(),
                summary: "Install or verify Docker prerequisites and prepare remote_root"
                    .to_owned(),
                destructive: false,
                depends_on: Vec::new(),
                rollback: None,
                metadata: json!({
                    "bootstrap": settings.bootstrap,
                    "remote_root": settings.remote_root,
                }),
            }]
        } else {
            Vec::new()
        };
        let plan_id = plan_id(&settings, needs_bootstrap)?;
        Ok(PlanResult {
            plan_id,
            has_changes: !actions.is_empty(),
            actions,
            metadata: json!({
                "config_digest": settings_digest(&settings)?,
                "needs_bootstrap": needs_bootstrap,
                "state": target_state(&settings, &probe),
            }),
        })
    }

    async fn apply(&self, request: ApplyRequest, events: &EventSink) -> PluginResult<ApplyResult> {
        let settings = self.remember_settings(&request.context).await?;
        let planned_bootstrap = Self::validate_apply_plan(&settings, &request.plan)?;
        let (probe, inspected) = self.inspect_inner(&settings).await?;
        let mut journal = request.journal;
        if !probe.runtime_ready(&settings) {
            if !planned_bootstrap {
                return Err(PluginError::permanent(
                    ErrorKind::Conflict,
                    "stale_plan",
                    "remote prerequisites changed after planning; create a new plan",
                ));
            }
            if settings.bootstrap == BootstrapMode::Verify {
                return Err(PluginError::permanent(
                    ErrorKind::Validation,
                    "bootstrap_verify_failed",
                    "remote Docker prerequisites or remote_root are not ready and bootstrap is verify",
                ));
            }
            let started = journal_entry(1, JournalStatus::Started, "Bootstrapping remote host");
            events
                .emit(&PluginEvent::Journal {
                    operation_id: request.context.operation_id.clone(),
                    entry: started.clone(),
                })
                .await
                .map_err(serve_to_plugin_error)?;
            journal.push(started);
            if let Err(error) = self
                .apply_bootstrap(&settings, &request.context.operation_id, events)
                .await
            {
                let failed = journal_entry(2, JournalStatus::Failed, &error.message);
                let _ = events
                    .emit(&PluginEvent::Journal {
                        operation_id: request.context.operation_id.clone(),
                        entry: failed,
                    })
                    .await;
                return Err(error);
            }
            let succeeded = journal_entry(
                2,
                JournalStatus::Succeeded,
                "Remote host prerequisites ready",
            );
            events
                .emit(&PluginEvent::Journal {
                    operation_id: request.context.operation_id.clone(),
                    entry: succeeded.clone(),
                })
                .await
                .map_err(serve_to_plugin_error)?;
            journal.push(succeeded);
        }
        let (_, inspected) = if probe.runtime_ready(&settings) {
            (probe, inspected)
        } else {
            self.inspect_inner(&settings).await?
        };
        if inspected.status != ResourceStatus::Ready {
            return Err(PluginError::permanent(
                ErrorKind::Unavailable,
                "bootstrap_incomplete",
                "remote host is still missing required Docker components after bootstrap",
            )
            .with_details(json!({"diagnostics": inspected.diagnostics})));
        }
        Ok(ApplyResult {
            revision: Some(settings_digest(&settings)?),
            state: inspected.state,
            journal,
        })
    }

    async fn inspect(
        &self,
        request: InspectRequest,
        _events: &EventSink,
    ) -> PluginResult<InspectResult> {
        let settings = self.remember_settings(&request.context).await?;
        self.inspect_inner(&settings)
            .await
            .map(|(_, result)| result)
    }

    async fn destroy(
        &self,
        request: DestroyRequest,
        events: &EventSink,
    ) -> PluginResult<DestroyResult> {
        let settings = self.remember_settings(&request.context).await?;
        let entry = ActionJournalEntry {
            sequence: request.journal.len() as u64 + 1,
            action_id: "retain-shared-host".to_owned(),
            status: JournalStatus::Skipped,
            timestamp: None,
            message: Some(format!(
                "Retained shared SSH host {}@{}; the runtime plugin owns environment cleanup",
                settings.user, settings.host
            )),
            rollback: None,
            metadata: json!({"retained": true, "isolation": "project"}),
        };
        events
            .emit(&PluginEvent::Journal {
                operation_id: request.context.operation_id,
                entry: entry.clone(),
            })
            .await
            .map_err(serve_to_plugin_error)?;
        let mut journal = request.journal;
        journal.push(entry);
        Ok(DestroyResult {
            destroyed: true,
            journal,
            remaining: Vec::new(),
        })
    }

    async fn lock_acquire(
        &self,
        request: LockAcquireRequest,
        _events: &EventSink,
    ) -> PluginResult<LockAcquireResult> {
        if request.scope_id.trim().is_empty() {
            return Err(PluginError::permanent(
                ErrorKind::Validation,
                "lock_scope_id_required",
                "operation lock `scope_id` must not be empty",
            ));
        }
        let settings = self
            .settings
            .read()
            .await
            .get(&request.environment_id)
            .cloned()
            .ok_or_else(|| {
                PluginError::permanent(
                    ErrorKind::Validation,
                    "lock_target_unknown",
                    "validate, plan, or inspect the SSH target before acquiring its operation lock",
                )
            })?;
        if let Some(result) = self.existing_lock_result(&settings, &request).await? {
            return Ok(result);
        }
        let Some((child, stdin)) = self.spawn_lock(&settings, &request).await? else {
            return Ok(LockAcquireResult {
                acquired: false,
                token: None,
                expires_at: None,
                holder: Some("another remote Lightrail operation".to_owned()),
            });
        };
        let token = Uuid::new_v4().to_string();
        let scope = lock_scope(&settings);
        self.locks.lock().await.insert(
            token.clone(),
            HeldLock {
                scope,
                request_scope: request.scope,
                scope_id: request.scope_id,
                environment_id: request.environment_id,
                operation_id: request.operation_id,
                child,
                stdin: Some(stdin),
            },
        );
        Ok(LockAcquireResult {
            acquired: true,
            token: Some(SecretValue::new(token)),
            expires_at: None,
            holder: None,
        })
    }

    async fn lock_release(
        &self,
        request: LockReleaseRequest,
        _events: &EventSink,
    ) -> PluginResult<LockReleaseResult> {
        let token = request.token.expose_secret();
        let mut locks = self.locks.lock().await;
        let Some(lock) = locks.get(token) else {
            return Ok(LockReleaseResult { released: true });
        };
        if lock.environment_id != request.environment_id
            || lock.operation_id != request.operation_id
            || lock.request_scope != request.scope
            || lock.scope_id != request.scope_id
        {
            return Err(PluginError::permanent(
                ErrorKind::Conflict,
                "lock_owner_mismatch",
                "operation lock token does not belong to this environment and operation",
            ));
        }
        let mut lock = locks
            .remove(token)
            .expect("lock exists after ownership validation");
        drop(locks);
        drop(lock.stdin.take());
        if timeout(Duration::from_secs(5), lock.child.wait())
            .await
            .is_err()
        {
            let _ = lock.child.kill().await;
            let _ = lock.child.wait().await;
        }
        Ok(LockReleaseResult { released: true })
    }
}

fn config_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "required": ["host"],
        "properties": {
            "host": {"type": "string", "minLength": 1},
            "user": {"type": "string", "default": "root"},
            "port": {"type": "integer", "minimum": 1, "maximum": 65535, "default": 22},
            "identity_file": {"type": "string", "minLength": 1},
            "known_hosts_file": {"type": "string", "minLength": 1},
            "remote_root": {"type": "string", "default": "/var/lib/lightrail"},
            "bootstrap": {"enum": ["auto", "install", "verify"], "default": "auto"},
            "sudo": {"enum": ["auto", "required", "never"], "default": "auto"},
            "public_ipv4": {"type": "string", "format": "ipv4"},
            "isolation": {"const": "project", "default": "project"}
        }
    })
}

fn validate_host(host: &str) -> Result<(), ConfigIssue> {
    if host.is_empty()
        || host.len() > 253
        || host.starts_with('-')
        || host
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':')))
    {
        return Err(ConfigIssue::at(
            "invalid_host",
            "host must be a DNS name or IP address without whitespace, shell syntax, or an SSH user prefix",
            "/host",
        ));
    }
    if let Ok(address) = host.parse::<IpAddr>() {
        if address.is_loopback() {
            return Err(ConfigIssue::at(
                "localhost_forbidden",
                "localhost and loopback SSH targets are not allowed",
                "/host",
            ));
        }
        return Ok(());
    }
    if host.eq_ignore_ascii_case("localhost") || host.to_ascii_lowercase().ends_with(".localhost") {
        return Err(ConfigIssue::at(
            "localhost_forbidden",
            "localhost and .localhost SSH targets are not allowed",
            "/host",
        ));
    }
    if host.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return Err(ConfigIssue::at(
            "invalid_host",
            "host is not a valid DNS name or IP address",
            "/host",
        ));
    }
    Ok(())
}

fn validate_user(user: &str) -> Result<(), ConfigIssue> {
    let mut bytes = user.bytes();
    let first = bytes.next();
    if user.len() > 64
        || !first.is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(ConfigIssue::at(
            "invalid_user",
            "user must be a safe POSIX login name",
            "/user",
        ));
    }
    Ok(())
}

fn validate_local_path(path: Option<&Path>, pointer: &'static str) -> Result<(), ConfigIssue> {
    if let Some(path) = path {
        let value = path.to_string_lossy();
        if value.is_empty() || value.contains('\0') || value.contains(['\r', '\n']) {
            return Err(ConfigIssue::at(
                "invalid_local_path",
                "local SSH paths cannot be empty or contain control characters",
                pointer,
            ));
        }
    }
    Ok(())
}

fn validate_known_hosts_path(path: Option<&Path>) -> Result<(), ConfigIssue> {
    validate_local_path(path, "/known_hosts_file")?;
    if path.is_some_and(|path| {
        path.to_string_lossy()
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == b'=')
    }) {
        return Err(ConfigIssue::at(
            "invalid_known_hosts_path",
            "known_hosts_file cannot contain whitespace or `=` because it is passed as an OpenSSH option",
            "/known_hosts_file",
        ));
    }
    Ok(())
}

fn validate_remote_root(path: &str) -> Result<(), ConfigIssue> {
    let parsed = Path::new(path);
    if !parsed.is_absolute()
        || matches!(
            path.trim_end_matches('/'),
            "" | "/etc" | "/usr" | "/var" | "/home" | "/root" | "/tmp"
        )
        || path.len() > 512
        || path.contains(['\0', '\r', '\n'])
        || parsed
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(ConfigIssue::at(
            "invalid_remote_root",
            "remote_root must be an absolute normalized path without parent traversal or control characters",
            "/remote_root",
        ));
    }
    Ok(())
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, _, _] = address.octets();
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_multicast()
        || address.is_broadcast()
        || address.is_documentation()
        || a == 0
        || a >= 240
        || a == 100 && (64..=127).contains(&b)
        || a == 192 && b == 0
        || a == 198 && matches!(b, 18 | 19))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

async fn ensure_nonlocal_host(settings: &Settings) -> PluginResult<()> {
    if let Ok(address) = settings.host.parse::<IpAddr>() {
        return validate_resolved_addresses(&settings.host, [address]);
    }

    let host = settings.host.clone();
    let port = settings.port;
    let resolved_host = host.clone();
    let resolution = tokio::task::spawn_blocking(move || {
        (resolved_host.as_str(), port)
            .to_socket_addrs()
            .map(Iterator::collect)
    });
    let addresses: Vec<std::net::SocketAddr> =
        timeout(Duration::from_secs(CONNECT_TIMEOUT_SECONDS), resolution)
            .await
            .map_err(|_| {
                PluginError::retryable(
                    ErrorKind::Timeout,
                    "host_resolution_timeout",
                    format!("timed out resolving SSH host `{host}`"),
                )
            })?
            .map_err(|error| {
                PluginError::retryable(
                    ErrorKind::Unavailable,
                    "host_resolution_failed",
                    format!("could not join DNS resolution for SSH host `{host}`: {error}"),
                )
            })?
            .map_err(|error| {
                PluginError::retryable(
                    ErrorKind::Unavailable,
                    "host_resolution_failed",
                    format!("could not resolve SSH host `{host}`: {error}"),
                )
            })?;
    validate_resolved_addresses(&host, addresses.into_iter().map(|address| address.ip()))
}

fn validate_resolved_addresses(
    host: &str,
    addresses: impl IntoIterator<Item = IpAddr>,
) -> PluginResult<()> {
    let addresses = addresses.into_iter().collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(PluginError::retryable(
            ErrorKind::Unavailable,
            "host_resolution_empty",
            format!("SSH host `{host}` did not resolve to any address"),
        ));
    }
    if addresses.iter().copied().any(is_loopback_address) {
        return Err(PluginError::permanent(
            ErrorKind::Validation,
            "localhost_forbidden",
            format!(
                "SSH host `{host}` resolves to a loopback address; local runtimes are not allowed"
            ),
        ));
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

async fn run_ssh(
    settings: &Settings,
    remote_command: &str,
    input: &[u8],
    deadline: Duration,
) -> PluginResult<String> {
    ensure_nonlocal_host(settings).await?;
    let invocation = SshInvocation::new(settings, remote_command);
    let mut child = invocation.command().spawn().map_err(|error| {
        PluginError::retryable(
            ErrorKind::Unavailable,
            "ssh_spawn_failed",
            format!("could not start OpenSSH: {error}"),
        )
    })?;
    let mut stdin = child.stdin.take().ok_or_else(|| {
        PluginError::permanent(
            ErrorKind::Internal,
            "ssh_pipe_failed",
            "OpenSSH process did not expose stdin",
        )
    })?;
    let input = input.to_vec();
    let writer = tokio::spawn(async move {
        stdin.write_all(&input).await?;
        stdin.shutdown().await
    });
    let output = timeout(deadline, child.wait_with_output())
        .await
        .map_err(|_| {
            PluginError::retryable(ErrorKind::Timeout, "ssh_timeout", "SSH operation timed out")
        })?
        .map_err(|error| {
            PluginError::retryable(
                ErrorKind::Unavailable,
                "ssh_failed",
                format!("OpenSSH failed: {error}"),
            )
        })?;
    writer
        .await
        .map_err(|error| {
            PluginError::permanent(
                ErrorKind::Internal,
                "ssh_stdin_task_failed",
                format!("failed joining the SSH input writer: {error}"),
            )
        })?
        .map_err(|error| {
            PluginError::retryable(
                ErrorKind::Unavailable,
                "ssh_write_failed",
                format!("failed writing the remote script: {error}"),
            )
        })?;
    if !output.status.success() {
        return Err(classify_ssh_failure(
            output.status.code(),
            &String::from_utf8_lossy(&output.stderr),
        ));
    }
    String::from_utf8(output.stdout).map_err(|_| {
        PluginError::permanent(
            ErrorKind::Internal,
            "invalid_ssh_output",
            "remote probe returned non-UTF-8 output",
        )
    })
}

async fn read_child_stderr(child: &mut Child) -> String {
    let Some(mut stderr) = child.stderr.take() else {
        return String::new();
    };
    let mut bytes = Vec::new();
    let _ = timeout(Duration::from_secs(2), stderr.read_to_end(&mut bytes)).await;
    String::from_utf8_lossy(&bytes).into_owned()
}

fn classify_ssh_failure(status: Option<i32>, stderr: &str) -> PluginError {
    let summary = safe_stderr(stderr);
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("permission denied") || lower.contains("authentication failed") {
        PluginError::permanent(
            ErrorKind::Authentication,
            "ssh_authentication_failed",
            format!("SSH authentication failed: {summary}"),
        )
    } else if lower.contains("host key verification failed")
        || lower.contains("remote host identification has changed")
    {
        PluginError::permanent(
            ErrorKind::Conflict,
            "ssh_host_key_failed",
            format!("SSH host-key verification failed: {summary}"),
        )
    } else {
        PluginError::retryable(
            ErrorKind::Unavailable,
            "ssh_remote_failed",
            format!(
                "SSH command failed{}: {summary}",
                status.map_or_else(String::new, |code| format!(" with exit code {code}"))
            ),
        )
    }
}

fn safe_stderr(stderr: &str) -> String {
    let collapsed = stderr
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let mut chars = collapsed.chars();
    let prefix: String = chars.by_ref().take(500).collect();
    if chars.next().is_some() {
        format!("{prefix}…")
    } else if prefix.is_empty() {
        "no diagnostic output".to_owned()
    } else {
        prefix
    }
}

fn diagnostics(settings: &Settings, probe: &Probe) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    add_platform_diagnostics(&mut diagnostics, settings, probe);
    add_runtime_diagnostics(&mut diagnostics, settings, probe);
    add_network_diagnostics(&mut diagnostics, probe);
    diagnostics
}

fn add_platform_diagnostics(diagnostics: &mut Vec<Diagnostic>, settings: &Settings, probe: &Probe) {
    if !probe.supported_os() {
        diagnostics.push(error_diagnostic(
            "unsupported_distribution",
            format!(
                "remote distribution `{}` is unsupported; expected Ubuntu or Debian",
                probe.os_id
            ),
            Some("Use a supported Ubuntu or Debian host".to_owned()),
        ));
    }
    if !probe.supported_arch() {
        diagnostics.push(error_diagnostic(
            "unsupported_architecture",
            format!(
                "remote architecture `{}` is unsupported; expected amd64 or arm64",
                probe.arch
            ),
            None,
        ));
    }
    if settings.sudo == SudoMode::Required && !probe.can_elevate(settings) {
        diagnostics.push(error_diagnostic(
            "sudo_unavailable",
            "sudo is required but the remote user is neither root nor allowed passwordless sudo",
            Some(
                "Grant passwordless sudo or select sudo = \"never\" with preinstalled Docker"
                    .to_owned(),
            ),
        ));
    }
}

fn add_runtime_diagnostics(diagnostics: &mut Vec<Diagnostic>, settings: &Settings, probe: &Probe) {
    if probe.docker_via_sudo && settings.sudo == SudoMode::Never {
        diagnostics.push(error_diagnostic(
            "docker_requires_sudo",
            "Docker is accessible only through sudo, but this profile sets sudo = \"never\"",
            Some(
                "Grant direct Docker access to the SSH user or select sudo = \"auto\" or \"required\""
                    .to_owned(),
            ),
        ));
        return;
    }
    if !probe.runtime_ready(settings) {
        match settings.bootstrap {
            BootstrapMode::Verify => diagnostics.push(error_diagnostic(
                "docker_prerequisites_missing",
                missing_requirements(probe),
                Some(
                    "Install a working Docker Engine, Compose v2, Buildx, and a writable remote_root, or use bootstrap = \"install\""
                        .to_owned(),
                ),
            )),
            BootstrapMode::Install
                if !probe.docker_stack_ready(settings)
                    && !probe.can_elevate(settings)
                    && probe.uid != 0 =>
            {
                diagnostics.push(error_diagnostic(
                    "bootstrap_privilege_unavailable",
                    "Docker prerequisites are missing and the remote user cannot install them",
                    Some(
                        "Grant passwordless sudo, connect as root, preinstall Docker, or use a writable remote_root"
                            .to_owned(),
                    ),
                ));
            }
            BootstrapMode::Install => diagnostics.push(info_diagnostic(
                "bootstrap_required",
                missing_requirements(probe),
                Some("`lightrail up` will bootstrap these prerequisites idempotently".to_owned()),
            )),
        }
    }
}

fn add_network_diagnostics(diagnostics: &mut Vec<Diagnostic>, probe: &Probe) {
    if probe.port_80_in_use || probe.port_443_in_use {
        diagnostics.push(Diagnostic {
            severity: DiagnosticSeverity::Warning,
            code: "public_ports_in_use".to_owned(),
            message: format!(
                "public listener check: port 80 in use = {}, port 443 in use = {}",
                probe.port_80_in_use, probe.port_443_in_use
            ),
            path: None,
            help: Some(
                "Confirm the listeners are Lightrail's shared Traefik; otherwise free both ports"
                    .to_owned(),
            ),
        });
    }
    match (
        probe.firewall.as_str(),
        probe.firewall_80,
        probe.firewall_443,
    ) {
        ("ufw" | "firewalld", FirewallAccess::Deny, _)
        | ("ufw" | "firewalld", _, FirewallAccess::Deny) => {
            diagnostics.push(error_diagnostic(
                "firewall_ports_blocked",
                format!(
                    "{} does not allow both TCP ports 80 and 443",
                    probe.firewall
                ),
                Some(
                    "Allow inbound TCP 80/443 in the host and provider firewalls; Lightrail will not rewrite a generic host firewall"
                        .to_owned(),
                ),
            ));
        }
        ("ufw" | "firewalld", FirewallAccess::Allow, FirewallAccess::Allow) => {
            diagnostics.push(info_diagnostic(
                "host_firewall_ready",
                format!("{} allows inbound TCP ports 80 and 443", probe.firewall),
                Some("Also verify any upstream/provider firewall".to_owned()),
            ));
        }
        _ => diagnostics.push(Diagnostic {
            severity: DiagnosticSeverity::Warning,
            code: "firewall_reachability_unverified".to_owned(),
            message:
                "could not prove inbound TCP 80/443 reachability from the remote host inspection"
                    .to_owned(),
            path: None,
            help: Some(
                "Allow inbound TCP 80/443 in host and provider firewalls; Lightrail does not rewrite generic host firewall rules"
                    .to_owned(),
            ),
        }),
    }
}

fn missing_requirements(probe: &Probe) -> String {
    let mut missing = Vec::new();
    if !probe.docker_cli {
        missing.push("Docker CLI");
    }
    if !probe.docker_ready {
        missing.push("Docker daemon access");
    }
    if !probe.compose {
        missing.push("Compose v2");
    }
    if !probe.buildx {
        missing.push("Buildx");
    }
    if !probe.remote_root_ready {
        missing.push("writable remote_root");
    }
    format!("remote host is missing {}", missing.join(", "))
}

fn error_diagnostic(code: &str, message: impl Into<String>, help: Option<String>) -> Diagnostic {
    Diagnostic {
        severity: DiagnosticSeverity::Error,
        code: code.to_owned(),
        message: message.into(),
        path: None,
        help,
    }
}

fn info_diagnostic(code: &str, message: impl Into<String>, help: Option<String>) -> Diagnostic {
    Diagnostic {
        severity: DiagnosticSeverity::Info,
        code: code.to_owned(),
        message: message.into(),
        path: None,
        help,
    }
}

fn target_state(settings: &Settings, probe: &Probe) -> Value {
    let state = serde_json::Map::from_iter([
        ("kind".to_owned(), json!("ssh")),
        ("host".to_owned(), json!(settings.host)),
        ("user".to_owned(), json!(settings.user)),
        ("port".to_owned(), json!(settings.port)),
        (
            "public_ipv4".to_owned(),
            json!(settings.effective_public_ipv4()),
        ),
        ("architecture".to_owned(), json!(probe.arch)),
        (
            "platform".to_owned(),
            json!({"os": "linux", "arch": probe.arch}),
        ),
        ("isolation".to_owned(), json!("project")),
        ("remote_root".to_owned(), json!(settings.remote_root)),
        ("identity_file".to_owned(), json!(settings.identity_file)),
        (
            "known_hosts_file".to_owned(),
            json!(settings.known_hosts_file),
        ),
        (
            "docker_requires_sudo".to_owned(),
            json!(probe.docker_via_sudo),
        ),
        (
            "docker".to_owned(),
            json!({
                "installed": probe.docker_cli,
                "ready": probe.docker_ready
                    && !(probe.docker_via_sudo && settings.sudo == SudoMode::Never),
                "compose": probe.compose,
                "buildx": probe.buildx,
                "requires_sudo": probe.docker_via_sudo,
            }),
        ),
        (
            "operation_lock".to_owned(),
            json!({
                "kind": "ssh-session-posix-mkdir",
                "ready": true,
                "scope": "host",
            }),
        ),
        (
            "system".to_owned(),
            json!({
                "distribution": probe.os_id,
                "version": probe.os_version,
                "uid": probe.uid,
                "firewall": probe.firewall,
            }),
        ),
    ]);
    Value::Object(state)
}

fn settings_digest(settings: &Settings) -> PluginResult<String> {
    let encoded = serde_json::to_vec(settings).map_err(|error| serialization_error(&error))?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

fn plan_id(settings: &Settings, needs_bootstrap: bool) -> PluginResult<String> {
    let mut digest = Sha256::new();
    digest.update(b"lightrail-ssh-plan-v1\0");
    digest.update(settings_digest(settings)?.as_bytes());
    digest.update([u8::from(needs_bootstrap)]);
    Ok(hex::encode(digest.finalize()))
}

fn destroy_plan_id(settings: &Settings) -> PluginResult<String> {
    let mut digest = Sha256::new();
    digest.update(b"lightrail-ssh-destroy-plan-v1\0");
    digest.update(settings_digest(settings)?.as_bytes());
    Ok(hex::encode(digest.finalize()))
}

fn lock_scope(settings: &Settings) -> String {
    let mut digest = Sha256::new();
    digest.update(b"lightrail-ssh-host-lock-scope-v1\0");
    digest.update(settings.host.to_ascii_lowercase().as_bytes());
    hex::encode(digest.finalize())
}

fn lock_attempts(timeout_ms: u64) -> u64 {
    timeout_ms
        .saturating_add(999)
        .checked_div(1_000)
        .unwrap_or(0)
        .max(1)
}

fn lock_script(timeout_ms: u64) -> String {
    lock_script_for(timeout_ms, HOST_LOCK_DIRECTORY)
}

fn lock_script_for(timeout_ms: u64, lock_directory: &str) -> String {
    let attempts = lock_attempts(timeout_ms);
    let lock_directory = shell_quote(lock_directory);
    format!(
        "umask 077; lock={lock_directory}; n=0; \
         trap '' 1 2 13 15; \
         while ! mkdir \"$lock\" 2>/dev/null; do \
           n=$((n + 1)); \
           if [ \"$n\" -ge {attempts} ]; then \
             printf 'LIGHTRAIL_BUSY\\n'; exit 75; \
           fi; \
           sleep 1; \
         done; \
         chmod 700 \"$lock\" || {{ rmdir \"$lock\"; exit 73; }}; \
         cleanup() {{ rmdir \"$lock\" 2>/dev/null || :; }}; \
         trap 'cleanup' 0; \
         trap 'exit 129' 1; trap 'exit 130' 2; \
         trap 'exit 141' 13; trap 'exit 143' 15; \
         printf 'LIGHTRAIL_LOCKED\\n'; \
         while IFS= read -r keepalive; do :; done"
    )
}

fn journal_entry(sequence: u64, status: JournalStatus, message: &str) -> ActionJournalEntry {
    ActionJournalEntry {
        sequence,
        action_id: "bootstrap-remote".to_owned(),
        status,
        timestamp: None,
        message: Some(message.to_owned()),
        rollback: None,
        metadata: Value::Object(serde_json::Map::new()),
    }
}

fn serialization_error(error: &serde_json::Error) -> PluginError {
    PluginError::permanent(
        ErrorKind::Internal,
        "serialization_failed",
        format!("could not serialize SSH plugin data: {error}"),
    )
}

fn serve_to_plugin_error(error: impl std::fmt::Display) -> PluginError {
    PluginError::retryable(
        ErrorKind::Unavailable,
        "event_output_failed",
        format!("could not emit plugin event: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> Settings {
        Settings {
            host: "203.0.113.42".to_owned(),
            user: "deploy".to_owned(),
            port: 2222,
            identity_file: Some(PathBuf::from("/home/me/.ssh/id_ed25519")),
            known_hosts_file: Some(PathBuf::from("/home/me/.ssh/known_hosts")),
            remote_root: "/srv/lightrail".to_owned(),
            bootstrap: BootstrapMode::Install,
            sudo: SudoMode::Auto,
            public_ipv4: Some(Ipv4Addr::new(8, 8, 8, 8)),
            isolation: Isolation::Project,
        }
    }

    fn probe_text() -> &'static str {
        "os_id=ubuntu\n\
         os_version=24.04\n\
         arch=x86_64\n\
         uid=1000\n\
         sudo_available=1\n\
         docker_cli=1\n\
         docker_ready=1\n\
         docker_via_sudo=1\n\
         compose=1\n\
         buildx=1\n\
         remote_root_ready=1\n\
         port_80_in_use=0\n\
         port_443_in_use=1\n\
         firewall=ufw\n\
         firewall_80=allow\n\
         firewall_443=allow\n"
    }

    #[test]
    fn parses_settings_with_defaults() {
        let parsed = Settings::parse(json!({
            "host": "8.8.8.8",
        }))
        .expect("valid settings");
        assert_eq!(parsed.user, "root");
        assert_eq!(parsed.port, 22);
        assert_eq!(parsed.remote_root, "/var/lib/lightrail");
        assert_eq!(
            parsed.effective_public_ipv4(),
            Some(Ipv4Addr::new(8, 8, 8, 8))
        );
    }

    #[test]
    fn accepts_auto_as_install_bootstrap_alias() {
        let parsed = Settings::parse(json!({
            "host": "8.8.8.8",
            "bootstrap": "auto",
        }))
        .expect("auto bootstrap alias");
        assert_eq!(parsed.bootstrap, BootstrapMode::Install);
    }

    #[test]
    fn builds_ssh_command_as_separate_argv() {
        let settings = settings();
        let invocation = SshInvocation::new(&settings, "sh -s");
        assert!(
            invocation
                .args
                .windows(2)
                .any(|args| args == ["-p", "2222"])
        );
        assert!(
            invocation
                .args
                .windows(2)
                .any(|args| { args == ["-i", "/home/me/.ssh/id_ed25519"] })
        );
        assert!(invocation.args.contains(&"deploy@203.0.113.42".to_owned()));
        assert_eq!(invocation.args.last(), Some(&"sh -s".to_owned()));
    }

    #[test]
    fn parses_probe_and_maps_architecture() {
        let probe = Probe::parse(probe_text()).expect("valid probe");
        assert_eq!(probe.arch, "amd64");
        assert!(probe.runtime_ready(&settings()));
        assert!(probe.docker_via_sudo);
        assert_eq!(probe.firewall_443, FirewallAccess::Allow);
    }

    #[test]
    fn rejects_injection_in_host_and_user() {
        for (field, value) in [
            ("host", "host;touch /tmp/pwned"),
            ("host", "deploy@example.com"),
            ("user", "deploy$(id)"),
            ("user", "-oProxyCommand=evil"),
        ] {
            let mut value_json = json!({
                "host": "8.8.8.8",
                "user": "deploy",
                "public_ipv4": "8.8.8.8",
            });
            value_json[field] = json!(value);
            assert!(
                Settings::parse(value_json).is_err(),
                "{field} accepted {value}"
            );
        }
    }

    #[test]
    fn rejects_remote_root_traversal_and_machine_isolation() {
        assert!(
            Settings::parse(json!({
                "host": "8.8.8.8",
                "remote_root": "/srv/../root",
            }))
            .is_err()
        );
        assert!(
            Settings::parse(json!({
                "host": "8.8.8.8",
                "remote_root": "/",
            }))
            .is_err()
        );
        assert!(
            Settings::parse(json!({
                "host": "8.8.8.8",
                "isolation": "machine",
            }))
            .is_err()
        );
    }

    #[test]
    fn rejects_localhost_and_known_hosts_option_injection() {
        assert!(
            Settings::parse(json!({
                "host": "LOCALHOST",
                "public_ipv4": "8.8.8.8",
            }))
            .is_err()
        );
        assert!(
            Settings::parse(json!({
                "host": "8.8.8.8",
                "known_hosts_file": "/tmp/known_hosts ProxyCommand=evil",
            }))
            .is_err()
        );
        for address in ["192.0.2.1", "198.51.100.4", "203.0.113.42"] {
            assert!(
                Settings::parse(json!({
                    "host": address,
                }))
                .is_err(),
                "accepted documentation address {address}"
            );
        }
    }

    #[test]
    fn resolved_alias_rejects_any_loopback_candidate() {
        let error = validate_resolved_addresses(
            "remote.example",
            [
                IpAddr::from([203, 0, 113, 42]),
                IpAddr::from([127, 0, 0, 1]),
            ],
        )
        .expect_err("an alias with any loopback candidate must be rejected");
        assert_eq!(error.kind, ErrorKind::Validation);
        assert_eq!(error.code, "localhost_forbidden");

        let mapped = "::ffff:127.0.0.1".parse().expect("mapped loopback address");
        assert!(
            validate_resolved_addresses("remote.example", [mapped]).is_err(),
            "IPv4-mapped loopback addresses must also be rejected"
        );

        assert!(
            validate_resolved_addresses("remote.example", [IpAddr::from([8, 8, 8, 8])]).is_ok()
        );
    }

    #[tokio::test]
    async fn system_localhost_resolution_is_rejected_before_ssh() {
        let mut settings = settings();
        settings.host = "localhost".to_owned();

        let error = ensure_nonlocal_host(&settings)
            .await
            .expect_err("the system localhost alias must resolve only to a rejected target");
        assert_eq!(error.kind, ErrorKind::Validation);
        assert_eq!(error.code, "localhost_forbidden");
    }

    #[test]
    fn empty_host_resolution_is_unavailable() {
        let error = validate_resolved_addresses("missing.example", Vec::<IpAddr>::new())
            .expect_err("an empty resolution must fail before SSH");
        assert_eq!(error.kind, ErrorKind::Unavailable);
        assert_eq!(error.code, "host_resolution_empty");
        assert!(error.retryable);
    }

    #[test]
    fn shell_quote_round_trips_shell_metacharacters_as_data() {
        assert_eq!(shell_quote("a'b;$(id)"), "'a'\"'\"'b;$(id)'");
    }

    #[test]
    fn lock_scope_is_host_wide_and_not_environment_specific() {
        let first = lock_scope(&settings());
        let mut same_host = settings();
        same_host.remote_root = "/another/project/root".to_owned();
        same_host.user = "another-login".to_owned();
        same_host.port = 22;
        assert_eq!(first, lock_scope(&same_host));

        let mut other_host = settings();
        other_host.host = "203.0.113.43".to_owned();
        assert_ne!(first, lock_scope(&other_host));
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    fn lock_request(operation_id: &str) -> LockAcquireRequest {
        LockAcquireRequest {
            environment_id: "environment-one".to_owned(),
            scope: LockScope::Target,
            scope_id: "target:dev.lightrail.ssh".to_owned(),
            operation_id: operation_id.to_owned(),
            timeout_ms: 1,
            lease_ms: None,
        }
    }

    #[tokio::test]
    async fn existing_live_lock_is_idempotent_only_for_the_same_owner() {
        let plugin = SshPlugin::new();
        let settings = settings();
        let request = lock_request("operation-one");
        let mut child = Command::new("sh")
            .arg("-c")
            .arg("while IFS= read -r line; do :; done")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn held lock process");
        let stdin = child.stdin.take().expect("held lock stdin");
        plugin.locks.lock().await.insert(
            "existing-token".to_owned(),
            HeldLock {
                scope: lock_scope(&settings),
                request_scope: request.scope,
                scope_id: request.scope_id.clone(),
                environment_id: request.environment_id.clone(),
                operation_id: request.operation_id.clone(),
                child,
                stdin: Some(stdin),
            },
        );

        let same_owner = plugin
            .existing_lock_result(&settings, &request)
            .await
            .expect("same-owner check")
            .expect("existing lock result");
        assert!(same_owner.acquired);
        assert_eq!(
            same_owner.token.as_ref().map(SecretValue::expose_secret),
            Some("existing-token")
        );

        let other_owner = plugin
            .existing_lock_result(&settings, &lock_request("operation-two"))
            .await
            .expect("other-owner check")
            .expect("existing lock result");
        assert!(!other_owner.acquired);
        assert!(other_owner.token.is_none());

        let mut held = plugin
            .locks
            .lock()
            .await
            .remove("existing-token")
            .expect("remove test lock");
        drop(held.stdin.take());
        timeout(Duration::from_secs(2), held.child.wait())
            .await
            .expect("lock process stopped before timeout")
            .expect("wait for lock process");
    }

    #[tokio::test]
    async fn exited_existing_lock_reports_lock_lost_without_reacquiring() {
        let plugin = SshPlugin::new();
        let settings = settings();
        let request = lock_request("operation-one");
        let mut child = Command::new("sh")
            .arg("-c")
            .arg("exit 0")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn exited lock process");
        let stdin = child.stdin.take();
        child.wait().await.expect("wait for exited lock process");
        plugin.locks.lock().await.insert(
            "lost-token".to_owned(),
            HeldLock {
                scope: lock_scope(&settings),
                request_scope: request.scope,
                scope_id: request.scope_id.clone(),
                environment_id: request.environment_id.clone(),
                operation_id: request.operation_id.clone(),
                child,
                stdin,
            },
        );

        let error = plugin
            .existing_lock_result(&settings, &request)
            .await
            .expect_err("exited child must report lock loss");
        assert_eq!(error.kind, ErrorKind::Unavailable);
        assert_eq!(error.code, "lock_lost");
        assert!(plugin.locks.lock().await.is_empty());
    }

    #[test]
    fn lock_script_uses_posix_host_lock_with_bounded_wait_and_cleanup() {
        let script = lock_script(30_000);
        assert!(script.contains(&format!("lock='{HOST_LOCK_DIRECTORY}'")));
        assert!(script.contains("[ \"$n\" -ge 30 ]"));
        assert!(script.contains("trap 'cleanup' 0"));
        assert!(script.contains("while IFS= read -r keepalive"));
        assert!(!script.contains("flock"));
        assert!(!script.contains("environment"));
        assert_eq!(lock_attempts(0), 1);
        assert_eq!(lock_attempts(1), 1);
        assert_eq!(lock_attempts(1_001), 2);
    }

    #[test]
    fn lock_lifetime_follows_connection_stdin_and_removes_directory() {
        let lock_path =
            std::env::temp_dir().join(format!("lightrail-lock-test-{}", Uuid::new_v4()));
        let lock_path_text = lock_path.to_string_lossy();
        let script = lock_script_for(1_000, &lock_path_text);
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg(&script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn lock shell");
        let stdin = child.stdin.take().expect("lock stdin");
        let stdout = child.stdout.take().expect("lock stdout");
        let mut reader = std::io::BufReader::new(stdout);
        let mut marker = String::new();
        std::io::BufRead::read_line(&mut reader, &mut marker).expect("read acquired marker");

        let contender = std::process::Command::new("sh")
            .arg("-c")
            .arg(lock_script_for(0, &lock_path_text))
            .output()
            .expect("run lock contender");
        let held = lock_path.is_dir();
        drop(stdin);
        let released = child.wait().expect("wait for lock shell").success();
        let removed = !lock_path.exists();
        let _ = std::fs::remove_dir(&lock_path);

        assert_eq!(marker, "LIGHTRAIL_LOCKED\n");
        assert!(held);
        assert_eq!(contender.status.code(), Some(75));
        assert_eq!(contender.stdout, b"LIGHTRAIL_BUSY\n");
        assert!(released);
        assert!(removed);
    }

    #[test]
    fn emits_target_state_contract() {
        let state = target_state(
            &settings(),
            &Probe::parse(probe_text()).expect("valid probe"),
        );
        assert_eq!(state["kind"], "ssh");
        assert_eq!(state["architecture"], "amd64");
        assert_eq!(state["platform"]["arch"], "amd64");
        assert_eq!(state["isolation"], "project");
        assert_eq!(state["remote_root"], "/srv/lightrail");
        assert_eq!(state["identity_file"], "/home/me/.ssh/id_ed25519");
        assert_eq!(state["known_hosts_file"], "/home/me/.ssh/known_hosts");
        assert_eq!(state["docker_requires_sudo"], true);
        assert_eq!(state["operation_lock"]["scope"], "host");
        assert_eq!(state["operation_lock"]["kind"], "ssh-session-posix-mkdir");
    }

    #[test]
    fn sudo_never_rejects_docker_available_only_through_sudo() {
        let probe = Probe::parse(probe_text()).expect("valid probe");
        let mut settings = settings();
        settings.sudo = SudoMode::Never;

        assert!(!probe.runtime_ready(&settings));
        let diagnostics = diagnostics(&settings, &probe);
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.severity == DiagnosticSeverity::Error
                && diagnostic.code == "docker_requires_sudo"
        }));

        let state = target_state(&settings, &probe);
        assert_eq!(state["docker_requires_sudo"], true);
        assert_eq!(state["docker"]["ready"], false);
    }
}
