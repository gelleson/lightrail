//! Hetzner target lifecycle and machine-backed operation-lock authority.
//!
//! `PluginHandler` implements the wire-facing operations. The inherent
//! `HetznerPlugin` methods perform provider discovery and reconciliation,
//! teardown, and remote lock continuity. Pure state, plan, and journal helpers
//! follow those lifecycle methods. Keep provider ownership checks and the
//! remote/in-process lock transition together when changing this module.

use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::Mutex as StdMutex,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use lightrail_plugin_protocol::{
    ActionJournalEntry, ApplyRequest, ApplyResult, CancelRequest, CancelResult, Capability,
    DestroyRequest, DestroyResult, Diagnostic, DiagnosticSeverity, ErrorKind, EventSink,
    ExecutableMetadata, InspectRequest, InspectResult, JournalStatus, LockAcquireRequest,
    LockAcquireResult, LockReleaseRequest, LockReleaseResult, LockScope, OperationContext,
    PlanRequest, PlanResult, PlannedAction, PluginError, PluginEvent, PluginHandler,
    PluginManifest, PluginResult, ProtocolCompatibility, ResourceStatus, RollbackMetadata,
    SecretRequirement, SecretValue, ValidateRequest, ValidateResult,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{process::Child, sync::Mutex, time::sleep};
use uuid::Uuid;

use crate::{
    api::{
        ApiAction, ApiClient, CreateFirewall, CreatePublicNet, CreateServer, CreateServerFirewall,
        Firewall, Server, canonical_rules, firewall_rules,
    },
    model::{
        ENVIRONMENT_LABEL, ResourceIdentity, Settings, config_schema, hash_json, short_hash, token,
        validation,
    },
    ssh::{
        SshTarget, acquire_remote_flock, cloud_init, prepare_known_hosts_file, wait_until_ready,
    },
};

const PLUGIN_ID: &str = "dev.lightrail.hetzner";
const ACTION_TIMEOUT: Duration = Duration::from_secs(10 * 60);

pub struct HetznerPlugin {
    api: ApiClient,
    targets: Mutex<HashMap<String, SshTarget>>,
    lock_snapshots: Mutex<HashMap<String, ResourceSnapshot>>,
    environment_projects: Mutex<HashMap<String, String>>,
    locks: Mutex<HashMap<String, HeldLock>>,
    cancelled: StdMutex<HashSet<String>>,
}

struct HeldLock {
    scope: LockScope,
    scope_id: String,
    project_id: Option<String>,
    operation_id: String,
    token: String,
    remote_lock_timeout: Duration,
    remote_upgrade_in_progress: bool,
    remote_processes: Vec<Child>,
    snapshot: Option<ResourceSnapshot>,
}

#[derive(Clone, Copy)]
struct LockOwnerRef<'a> {
    scope: LockScope,
    scope_id: &'a str,
    operation_id: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RemoteLockStatus {
    Missing,
    Acquiring,
    Authoritative,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RemoteLockUpgradeDecision {
    Acquire,
    AlreadyAuthoritative,
}

#[derive(Clone, Copy)]
enum HeldLockCheck {
    Valid,
    MissingOrWrongOwner,
    UpgradeInProgress,
    RemoteAuthorityLost,
}

struct RemoteLockUpgradeLease {
    token: String,
    timeout: Duration,
}

impl Default for HetznerPlugin {
    fn default() -> Self {
        Self {
            api: ApiClient::default(),
            targets: Mutex::new(HashMap::new()),
            lock_snapshots: Mutex::new(HashMap::new()),
            environment_projects: Mutex::new(HashMap::new()),
            locks: Mutex::new(HashMap::new()),
            cancelled: StdMutex::new(HashSet::new()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PlanMetadata {
    present: bool,
    #[serde(default)]
    all: bool,
    settings: Settings,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct TargetState {
    kind: String,
    provider: String,
    server_id: u64,
    firewall_id: Option<u64>,
    host: String,
    user: String,
    port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_file: Option<String>,
    known_hosts_file: Option<String>,
    docker: DockerTargetState,
    public_ipv4: String,
    architecture: String,
    platform: String,
    isolation: String,
    remote_root: String,
    server_name: String,
    server_status: String,
    server_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    config_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    firewall_fingerprint: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
struct DockerTargetState {
    requires_sudo: bool,
}

struct Discovery {
    server: Option<Server>,
    firewall: Option<Firewall>,
}

struct ProjectResources {
    servers: Vec<Server>,
    firewalls: Vec<Firewall>,
}

#[derive(Clone)]
struct ResourceSnapshot {
    server_ids: Vec<u64>,
    firewall_ids: Vec<u64>,
    targets: Vec<SnapshotTarget>,
}

#[derive(Clone)]
struct SnapshotTarget {
    server_id: u64,
    target: Option<SshTarget>,
}

#[async_trait]
impl PluginHandler for HetznerPlugin {
    fn manifest(&self) -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID.to_owned(),
            name: "Lightrail Hetzner Cloud target".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            protocol: ProtocolCompatibility::default(),
            executable: ExecutableMetadata {
                command: Some("lightrail-plugin-hetzner".to_owned()),
                homepage: Some("https://github.com/gelleson/lightrail".to_owned()),
                ..ExecutableMetadata::default()
            },
            capabilities: vec![Capability::Target, Capability::OperationLock],
            required_secrets: vec![SecretRequirement {
                name: "hetzner-token".to_owned(),
                description: Some(
                    "Hetzner Cloud API token used only in the Authorization header".to_owned(),
                ),
                required: true,
            }],
            config_schema: config_schema(),
            config_ui_hints: json!({
                "/token/secret": { "control": "secret-reference" },
                "/identity_file": { "control": "file" },
                "/allowed_ssh_cidrs": {
                    "sensitive": false,
                    "help": "Required. Use the operator/network CIDRs that may reach SSH."
                }
            }),
        }
    }

    async fn validate(
        &self,
        request: ValidateRequest,
        _events: &EventSink,
    ) -> PluginResult<ValidateResult> {
        let settings = match Settings::from_context(&request.context) {
            Ok(settings) => settings,
            Err(error) => {
                return Ok(ValidateResult {
                    valid: false,
                    diagnostics: vec![Diagnostic {
                        severity: DiagnosticSeverity::Error,
                        code: error.code,
                        message: error.message,
                        path: config_error_path(&error.details),
                        help: Some(
                            "Fix the profile target settings before planning or provisioning."
                                .to_owned(),
                        ),
                    }],
                    normalized_config: None,
                });
            }
        };
        let mut diagnostics = Vec::new();
        if !request.context.secrets.contains_key(&settings.token.secret) {
            diagnostics.push(Diagnostic {
                severity: DiagnosticSeverity::Error,
                code: "hetzner_token_required".to_owned(),
                message: "the `hetzner-token` secret has not been resolved".to_owned(),
                path: Some("/token/secret".to_owned()),
                help: Some("Run `lightrail secret set hetzner-token`.".to_owned()),
            });
        }
        if request.context.metadata.get("project_id").is_none()
            && request.context.metadata.pointer("/project/id").is_none()
        {
            diagnostics.push(Diagnostic {
                severity: DiagnosticSeverity::Error,
                code: "project_id_required".to_owned(),
                message: "immutable project metadata is required for provider labels".to_owned(),
                path: None,
                help: None,
            });
        }
        Ok(ValidateResult {
            valid: diagnostics.is_empty(),
            diagnostics,
            normalized_config: Some(
                serde_json::to_value(settings).map_err(|error| internal_json(&error))?,
            ),
        })
    }

    async fn inspect(
        &self,
        request: InspectRequest,
        _events: &EventSink,
    ) -> PluginResult<InspectResult> {
        let settings = Settings::from_context(&request.context)?;
        let identity = ResourceIdentity::from_context(&request.context)?;
        let token = token(&request.context, &settings)?;
        let project_root = context_project_root(&request.context)?;
        self.remember_environment_project(&request.context.environment_id, &identity.project_id)
            .await;
        if all_context(&request.context.metadata) {
            let resources = self.project_resources(token, &identity).await?;
            self.cache_project_snapshot(&identity, &settings, &resources, project_root)
                .await?;
            return aggregate_inspection(&settings, &identity, &resources, project_root);
        }
        let discovery = self.discover(token, &identity).await?;
        self.cache_environment_snapshot(
            &request.context.environment_id,
            &settings,
            &discovery,
            project_root,
        )
        .await?;
        self.inspection_result(
            &request.context.environment_id,
            &settings,
            &identity,
            discovery,
            project_root,
        )
        .await
    }

    async fn plan(&self, request: PlanRequest, _events: &EventSink) -> PluginResult<PlanResult> {
        let settings = Settings::from_context(&request.context)?;
        let identity = ResourceIdentity::from_context(&request.context)?;
        let token = token(&request.context, &settings)?;
        let project_root = context_project_root(&request.context)?;
        let present = desired_present(&request.desired, &request.context.metadata);
        let all = all_context(&request.context.metadata);
        self.remember_environment_project(&request.context.environment_id, &identity.project_id)
            .await;
        let metadata = PlanMetadata {
            present,
            all,
            settings: settings.clone(),
        };
        let mut actions = Vec::new();
        if !present && all {
            let resources = self.project_resources(token, &identity).await?;
            self.cache_project_snapshot(&identity, &settings, &resources, project_root)
                .await?;
            project_delete_actions(&resources, &mut actions);
        } else {
            let discovery = self.discover(token, &identity).await?;
            self.cache_environment_snapshot(
                &request.context.environment_id,
                &settings,
                &discovery,
                project_root,
            )
            .await?;
            if present {
                Self::plan_present(&settings, &discovery, &mut actions);
            } else {
                if discovery.server.is_some() {
                    actions.push(delete_action(
                        "delete-server",
                        "Delete the Hetzner Cloud server",
                    ));
                }
                if discovery.firewall.is_some() {
                    actions.push(delete_action(
                        "delete-firewall",
                        "Delete the managed Hetzner Cloud firewall",
                    ));
                }
            }
        }
        let metadata_value =
            serde_json::to_value(&metadata).map_err(|error| internal_json(&error))?;
        let plan_id = plan_id(&request.context.environment_id, &metadata_value, &actions);
        Ok(PlanResult {
            plan_id,
            has_changes: !actions.is_empty(),
            actions,
            metadata: metadata_value,
        })
    }

    #[allow(clippy::too_many_lines)]
    async fn apply(&self, request: ApplyRequest, events: &EventSink) -> PluginResult<ApplyResult> {
        let metadata: PlanMetadata = serde_json::from_value(request.plan.metadata.clone())
            .map_err(|error| {
                validation(
                    "invalid_plan_metadata",
                    format!("the plan does not contain valid Hetzner settings: {error}"),
                )
            })?;
        metadata.settings.validate()?;
        let identity = ResourceIdentity::from_context(&request.context)?;
        let project_root = context_project_root(&request.context)?.to_path_buf();
        let (lock_scope, lock_scope_id) = if metadata.all {
            (LockScope::Project, identity.project_id.as_str())
        } else {
            (
                LockScope::Environment,
                request.context.environment_id.as_str(),
            )
        };
        self.ensure_lock(lock_scope, lock_scope_id, &request.context.operation_id)
            .await?;
        let expected_plan_id = plan_id(
            &request.context.environment_id,
            &request.plan.metadata,
            &request.plan.actions,
        );
        if expected_plan_id != request.plan.plan_id {
            return Err(PluginError::permanent(
                ErrorKind::Conflict,
                "stale_or_modified_plan",
                "the supplied plan ID does not match its actions and settings",
            ));
        }
        let token = token(&request.context, &metadata.settings)?;
        if !metadata.present && metadata.all {
            let resources = self
                .verify_project_snapshot(token, &identity, &request.context.operation_id)
                .await?;
            let journal = self
                .delete_project_resources(
                    token,
                    resources,
                    request.journal,
                    &request.context.operation_id,
                    events,
                )
                .await?;
            return Ok(ApplyResult {
                revision: None,
                state: absent_state(&identity),
                journal,
            });
        }
        let initial = self.discover(token, &identity).await?;
        if !metadata.present {
            let journal = self
                .delete_discovery(
                    token,
                    initial,
                    request.journal,
                    &request.context.operation_id,
                    events,
                )
                .await?;
            return Ok(ApplyResult {
                revision: None,
                state: absent_state(&identity),
                journal,
            });
        }

        let initially_had_server = initial.server.is_some();
        let result = self
            .reconcile_present(
                &request.context.operation_id,
                &request.context.environment_id,
                token,
                &identity,
                &metadata.settings,
                &project_root,
                initial,
                request.journal,
                events,
            )
            .await;
        match result {
            Ok((state, journal)) => Ok(ApplyResult {
                revision: Some(format!("server:{}", state.server_id)),
                state: serde_json::to_value(state).map_err(|error| internal_json(&error))?,
                journal,
            }),
            Err(error) if !initially_had_server && !must_preserve_provider_resources(&error) => {
                // Initial provisioning is transactional at the environment level:
                // best-effort cleanup avoids charging for a half-created machine.
                if let Ok(discovery) = self.discover(token, &identity).await {
                    let _ = self
                        .delete_discovery(
                            token,
                            discovery,
                            Vec::new(),
                            &request.context.operation_id,
                            events,
                        )
                        .await;
                }
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    async fn destroy(
        &self,
        request: DestroyRequest,
        events: &EventSink,
    ) -> PluginResult<DestroyResult> {
        let settings = Settings::from_context(&request.context)?;
        let identity = ResourceIdentity::from_context(&request.context)?;
        let all = all_context(&request.context.metadata);
        if !request.force {
            let (scope, scope_id) = if all {
                (LockScope::Project, identity.project_id.as_str())
            } else {
                (
                    LockScope::Environment,
                    request.context.environment_id.as_str(),
                )
            };
            self.ensure_lock(scope, scope_id, &request.context.operation_id)
                .await?;
        }
        let token = token(&request.context, &settings)?;
        let project_resources = if all {
            Some(if request.force {
                self.project_resources(token, &identity).await?
            } else {
                self.verify_project_snapshot(token, &identity, &request.context.operation_id)
                    .await?
            })
        } else {
            None
        };
        let journal = if all {
            self.delete_project_resources(
                token,
                project_resources.expect("project resources loaded above"),
                request.journal,
                &request.context.operation_id,
                events,
            )
            .await?
        } else {
            let discovery = self.discover(token, &identity).await?;
            self.delete_discovery(
                token,
                discovery,
                request.journal,
                &request.context.operation_id,
                events,
            )
            .await?
        };
        if all {
            self.targets.lock().await.clear();
        } else {
            self.targets
                .lock()
                .await
                .remove(&request.context.environment_id);
        }
        let names = if all {
            let servers = self
                .api
                .servers(token, &identity.project_selector())
                .await?;
            let firewalls = self
                .api
                .firewalls(token, &identity.project_selector())
                .await?;
            servers
                .into_iter()
                .map(|server| format!("server:{}", server.id))
                .chain(
                    firewalls
                        .into_iter()
                        .map(|firewall| format!("firewall:{}", firewall.id)),
                )
                .collect()
        } else {
            let remaining = self.discover(token, &identity).await?;
            let mut names = Vec::new();
            if let Some(server) = remaining.server {
                names.push(format!("server:{}", server.id));
            }
            if let Some(firewall) = remaining.firewall {
                names.push(format!("firewall:{}", firewall.id));
            }
            names
        };
        Ok(DestroyResult {
            destroyed: names.is_empty(),
            journal,
            remaining: names,
        })
    }

    async fn cancel(
        &self,
        request: CancelRequest,
        _events: &EventSink,
    ) -> PluginResult<CancelResult> {
        let acknowledged = self
            .cancelled
            .lock()
            .expect("cancel mutex poisoned")
            .insert(request.operation_id);
        Ok(CancelResult { acknowledged })
    }

    #[allow(clippy::too_many_lines)]
    async fn lock_acquire(
        &self,
        request: LockAcquireRequest,
        _events: &EventSink,
    ) -> PluginResult<LockAcquireResult> {
        if request.scope_id.trim().is_empty() {
            return Err(validation(
                "lock_scope_id_required",
                "operation lock `scope_id` must not be empty",
            ));
        }
        let key = scope_key(request.scope, &request.scope_id);
        if let Some(result) = self
            .existing_lock_acquire_result(&key, &request.operation_id)
            .await?
        {
            return Ok(result);
        }
        let project_id = match request.scope {
            LockScope::Project => Some(request.scope_id.clone()),
            LockScope::Environment => self
                .environment_projects
                .lock()
                .await
                .get(&request.environment_id)
                .cloned(),
            LockScope::Target => None,
        };
        let snapshot = self.lock_snapshots.lock().await.get(&key).cloned();
        if snapshot.is_none() {
            return Err(PluginError::permanent(
                ErrorKind::NotFound,
                "lock_snapshot_required",
                "inspect the requested lock scope through this plugin session before acquiring it",
            ));
        }
        let remote_targets =
            remote_lock_targets(snapshot.as_ref().expect("snapshot checked above"))?;
        let timeout = Duration::from_millis(request.timeout_ms.max(1));
        let lock_token = Uuid::new_v4().to_string();
        loop {
            let mut locks = self.locks.lock().await;
            if locks.contains_key(&key) {
                drop(locks);
                if let Some(result) = self
                    .existing_lock_acquire_result(&key, &request.operation_id)
                    .await?
                {
                    return Ok(result);
                }
                continue;
            }
            if let Some(existing) = locks.values().find(|existing| {
                scopes_overlap(
                    request.scope,
                    project_id.as_deref(),
                    existing.scope,
                    existing.project_id.as_deref(),
                )
            }) {
                return Ok(LockAcquireResult {
                    acquired: false,
                    token: None,
                    expires_at: None,
                    holder: Some(existing.operation_id.clone()),
                });
            }
            locks.insert(
                key.clone(),
                HeldLock {
                    scope: request.scope,
                    scope_id: request.scope_id.clone(),
                    project_id: project_id.clone(),
                    operation_id: request.operation_id.clone(),
                    token: lock_token.clone(),
                    remote_lock_timeout: timeout,
                    remote_upgrade_in_progress: false,
                    remote_processes: Vec::new(),
                    snapshot: snapshot.clone(),
                },
            );
            break;
        }

        let mut processes = match acquire_remote_processes(
            request.scope,
            &request.scope_id,
            remote_targets,
            timeout,
        )
        .await
        {
            Ok(processes) => processes,
            Err(error) => {
                let mut locks = self.locks.lock().await;
                if locks.get(&key).is_some_and(|lock| {
                    lock.operation_id == request.operation_id && lock.token == lock_token
                }) {
                    locks.remove(&key);
                }
                return Err(error);
            }
        };
        let attached = {
            let mut locks = self.locks.lock().await;
            locks.get_mut(&key).is_some_and(|lock| {
                if lock.operation_id == request.operation_id && lock.token == lock_token {
                    lock.remote_processes.append(&mut processes);
                    true
                } else {
                    false
                }
            })
        };
        if !attached {
            release_remote_processes(&mut processes).await;
            return Err(PluginError::permanent(
                ErrorKind::Cancelled,
                "lock_released_during_acquisition",
                "the lock was released while remote acquisition was still running",
            ));
        }
        Ok(LockAcquireResult {
            acquired: true,
            token: Some(SecretValue::new(lock_token)),
            expires_at: None,
            holder: None,
        })
    }

    async fn lock_release(
        &self,
        request: LockReleaseRequest,
        _events: &EventSink,
    ) -> PluginResult<LockReleaseResult> {
        let key = scope_key(request.scope, &request.scope_id);
        let mut held = {
            let mut locks = self.locks.lock().await;
            let Some(existing) = locks.get(&key) else {
                return Ok(LockReleaseResult { released: true });
            };
            if existing.operation_id != request.operation_id
                || existing.token != request.token.expose_secret()
                || existing.scope != request.scope
                || existing.scope_id != request.scope_id
            {
                return Err(PluginError::permanent(
                    ErrorKind::LockUnavailable,
                    "lock_owner_mismatch",
                    "the lock is owned by another operation",
                ));
            }
            locks.remove(&key).expect("lock checked above")
        };
        release_remote_processes(&mut held.remote_processes).await;
        Ok(LockReleaseResult { released: true })
    }
}

impl HetznerPlugin {
    fn plan_present(settings: &Settings, discovery: &Discovery, actions: &mut Vec<PlannedAction>) {
        let expected_config = settings.config_fingerprint();
        match &discovery.server {
            None => {
                if discovery.firewall.is_none() {
                    actions.push(create_action(
                        "create-firewall",
                        "Create a managed firewall for HTTP, HTTPS, and restricted SSH",
                    ));
                } else if discovery
                    .firewall
                    .as_ref()
                    .is_some_and(|firewall| !firewall.matches_rules(&firewall_rules(settings)))
                {
                    actions.push(update_action(
                        "update-firewall",
                        "Update the managed firewall rules",
                    ));
                }
                actions.push(create_action(
                    "create-server",
                    "Create and bootstrap the Hetzner Cloud server",
                ));
            }
            Some(server)
                if server
                    .config_fingerprint()
                    .is_none_or(|actual| actual != &expected_config[..32]) =>
            {
                actions.push(PlannedAction {
                    id: "replace-server".to_owned(),
                    kind: "replace".to_owned(),
                    summary: "Replace the server to apply immutable target settings".to_owned(),
                    destructive: true,
                    depends_on: Vec::new(),
                    rollback: Some(RollbackMetadata {
                        supported: false,
                        action: None,
                        token: None,
                        metadata: json!({
                            "reason": "machine-local volumes and database changes cannot be restored"
                        }),
                    }),
                    metadata: Value::Object(serde_json::Map::new()),
                });
            }
            Some(server) => match &discovery.firewall {
                None => {
                    actions.push(create_action(
                        "create-firewall",
                        "Create the managed firewall",
                    ));
                    actions.push(update_action(
                        "attach-firewall",
                        "Attach the managed firewall to the server",
                    ));
                }
                Some(firewall) => {
                    if !firewall.matches_rules(&firewall_rules(settings)) {
                        actions.push(update_action(
                            "update-firewall",
                            "Update the managed firewall rules",
                        ));
                    }
                    if !firewall.applies_to_server(server.id) {
                        actions.push(update_action(
                            "attach-firewall",
                            "Attach the managed firewall to the server",
                        ));
                    }
                }
            },
        }
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn reconcile_present(
        &self,
        operation_id: &str,
        environment_id: &str,
        token: &str,
        identity: &ResourceIdentity,
        settings: &Settings,
        project_root: &Path,
        mut discovery: Discovery,
        mut journal: Vec<ActionJournalEntry>,
        events: &EventSink,
    ) -> PluginResult<(TargetState, Vec<ActionJournalEntry>)> {
        let expected_config = settings.config_fingerprint();
        let server_requires_replacement = discovery.server.as_ref().is_some_and(|server| {
            server
                .config_fingerprint()
                .is_none_or(|actual| actual != &expected_config[..32])
        });
        let mut resolved_ssh_key_ids = if discovery.server.is_none() || server_requires_replacement
        {
            Some(
                self.api
                    .resolve_ssh_key_ids(token, &settings.ssh_keys)
                    .await?,
            )
        } else {
            None
        };
        if server_requires_replacement {
            journal = self
                .delete_discovery(
                    token,
                    Discovery {
                        server: discovery.server.take(),
                        firewall: None,
                    },
                    journal,
                    operation_id,
                    events,
                )
                .await?;
            discovery = self.discover(token, identity).await?;
        }

        let rules = firewall_rules(settings);
        // A host does not exist yet to act as lock authority. Recheck immutable
        // labels immediately before create, then adopt an exact label-owned
        // firewall if a concurrent create wins the remaining provider race.
        let rechecked_firewall = if discovery.firewall.is_some() {
            discovery.firewall.take()
        } else {
            self.discover(token, identity).await?.firewall
        };
        let firewall = if let Some(firewall) = rechecked_firewall {
            firewall
        } else {
            journal_event(
                &mut journal,
                events,
                operation_id,
                "create-firewall",
                JournalStatus::Started,
                Some("creating managed firewall"),
            )
            .await?;
            let create_result = self
                .api
                .create_firewall(
                    token,
                    &CreateFirewall {
                        name: identity.firewall_name.clone(),
                        labels: identity.labels(&expected_config),
                        rules: rules.clone(),
                    },
                )
                .await;
            let (firewall, message) = match create_result {
                Ok(created) => {
                    for action in created.actions {
                        self.wait_action(token, action.id, operation_id).await?;
                    }
                    (created.firewall, "managed firewall created")
                }
                Err(create_error) => {
                    let adopted = self
                        .discover(token, identity)
                        .await
                        .ok()
                        .and_then(|discovery| discovery.firewall);
                    let Some(firewall) = adopted else {
                        return Err(create_error);
                    };
                    (firewall, "concurrently created managed firewall adopted")
                }
            };
            journal_event(
                &mut journal,
                events,
                operation_id,
                "create-firewall",
                JournalStatus::Succeeded,
                Some(message),
            )
            .await?;
            firewall
        };
        if !firewall.matches_rules(&rules) {
            journal_event(
                &mut journal,
                events,
                operation_id,
                "update-firewall",
                JournalStatus::Started,
                Some("updating firewall rules"),
            )
            .await?;
            for action in self
                .api
                .set_firewall_rules(token, firewall.id, &rules)
                .await?
            {
                self.wait_action(token, action.id, operation_id).await?;
            }
            journal_event(
                &mut journal,
                events,
                operation_id,
                "update-firewall",
                JournalStatus::Succeeded,
                Some("firewall rules updated"),
            )
            .await?;
        }

        // Recheck provider state immediately before creation. Combined with the
        // deterministic server name this is the strongest available lock before
        // a host exists; Hetzner offers no cross-resource transactional mutex.
        let rechecked = self.discover(token, identity).await?;
        let server = if let Some(server) = rechecked.server {
            server
        } else {
            let ssh_key_ids = match resolved_ssh_key_ids.take() {
                Some(ids) => ids,
                None => {
                    self.api
                        .resolve_ssh_key_ids(token, &settings.ssh_keys)
                        .await?
                }
            };
            journal_event(
                &mut journal,
                events,
                operation_id,
                "create-server",
                JournalStatus::Started,
                Some("creating Hetzner Cloud server"),
            )
            .await?;
            let create_result = self
                .api
                .create_server(
                    token,
                    &server_payload(
                        settings,
                        identity,
                        &firewall,
                        &ssh_key_ids,
                        &expected_config,
                    ),
                )
                .await;
            let (server, message) = match create_result {
                Ok(created) => {
                    self.wait_action(token, created.action.id, operation_id)
                        .await?;
                    let server = self
                        .wait_server(token, created.server.id, operation_id)
                        .await?;
                    (server, "server created")
                }
                Err(create_error) => {
                    let adopted = self
                        .discover(token, identity)
                        .await
                        .ok()
                        .and_then(|discovery| discovery.server);
                    let Some(server) = adopted else {
                        return Err(create_error);
                    };
                    let server = self.wait_server(token, server.id, operation_id).await?;
                    (server, "concurrently created server adopted")
                }
            };
            journal_event(
                &mut journal,
                events,
                operation_id,
                "create-server",
                JournalStatus::Succeeded,
                Some(message),
            )
            .await?;
            server
        };

        let refreshed_firewall = self
            .api
            .firewalls(token, &identity.environment_selector())
            .await?
            .into_iter()
            .find(|candidate| candidate.id == firewall.id)
            .unwrap_or(firewall);
        if !refreshed_firewall.applies_to_server(server.id) {
            journal_event(
                &mut journal,
                events,
                operation_id,
                "attach-firewall",
                JournalStatus::Started,
                Some("attaching firewall to server"),
            )
            .await?;
            for action in self
                .api
                .apply_firewall(token, refreshed_firewall.id, server.id)
                .await?
            {
                self.wait_action(token, action.id, operation_id).await?;
            }
            journal_event(
                &mut journal,
                events,
                operation_id,
                "attach-firewall",
                JournalStatus::Succeeded,
                Some("firewall attached"),
            )
            .await?;
        }

        let host = server.public_ipv4().ok_or_else(|| {
            PluginError::retryable(
                ErrorKind::Unavailable,
                "public_ipv4_pending",
                "the server does not yet have a public IPv4 address",
            )
        })?;
        let known_hosts_file =
            prepare_known_hosts_file(project_root, &identity.environment_label, server.id)?;
        let target = SshTarget::from_parts(
            host,
            settings,
            identity.remote_root.clone(),
            environment_id,
            known_hosts_file,
        );
        self.targets
            .lock()
            .await
            .insert(environment_id.to_owned(), target.clone());
        events
            .emit(&PluginEvent::Progress {
                operation_id: operation_id.to_owned(),
                message: "waiting for cloud-init, Docker, and Compose".to_owned(),
                completed: None,
                total: None,
            })
            .await
            .map_err(event_error)?;
        wait_until_ready(&target, ACTION_TIMEOUT, || self.is_cancelled(operation_id)).await?;
        self.upgrade_environment_lock(environment_id, operation_id, server.id, &target)
            .await?;

        let discovery = self.discover(token, identity).await?;
        let state = target_state(
            discovery.server.as_ref().ok_or_else(|| {
                PluginError::retryable(
                    ErrorKind::Unavailable,
                    "server_disappeared",
                    "the server disappeared during provisioning",
                )
            })?,
            discovery.firewall.as_ref(),
            settings,
            identity,
            &target.known_hosts_file,
        );
        Ok((state, journal))
    }

    async fn inspection_result(
        &self,
        environment_id: &str,
        settings: &Settings,
        identity: &ResourceIdentity,
        discovery: Discovery,
        project_root: &Path,
    ) -> PluginResult<InspectResult> {
        let mut diagnostics = Vec::new();
        let Some(server) = discovery.server.as_ref() else {
            if discovery.firewall.is_some() {
                diagnostics.push(Diagnostic {
                    severity: DiagnosticSeverity::Warning,
                    code: "orphan_firewall".to_owned(),
                    message: "a managed firewall exists without its server".to_owned(),
                    path: None,
                    help: Some("Run `lightrail up` to reconcile or `lightrail down`.".to_owned()),
                });
            }
            self.targets.lock().await.remove(environment_id);
            return Ok(InspectResult {
                status: if discovery.firewall.is_some() {
                    ResourceStatus::Degraded
                } else {
                    ResourceStatus::Absent
                },
                endpoints: Vec::new(),
                state: absent_state(identity),
                diagnostics,
            });
        };
        if discovery.firewall.is_none() {
            diagnostics.push(Diagnostic {
                severity: DiagnosticSeverity::Warning,
                code: "firewall_missing".to_owned(),
                message: "the managed server has no matching Lightrail firewall".to_owned(),
                path: None,
                help: Some("Run `lightrail up` to reconcile the target.".to_owned()),
            });
        }
        let known_hosts_file =
            prepare_known_hosts_file(project_root, &identity.environment_label, server.id)?;
        let state = target_state(
            server,
            discovery.firewall.as_ref(),
            settings,
            identity,
            &known_hosts_file,
        );
        let status = if server.status == "running"
            && !state.public_ipv4.is_empty()
            && discovery.firewall.is_some()
        {
            ResourceStatus::Ready
        } else if matches!(
            server.status.as_str(),
            "initializing" | "starting" | "migrating" | "rebuilding"
        ) {
            ResourceStatus::Pending
        } else {
            ResourceStatus::Degraded
        };
        if !state.host.is_empty() {
            self.targets.lock().await.insert(
                environment_id.to_owned(),
                SshTarget::from_parts(
                    &state.host,
                    settings,
                    identity.remote_root.clone(),
                    environment_id,
                    known_hosts_file,
                ),
            );
        }
        Ok(InspectResult {
            status,
            endpoints: Vec::new(),
            state: serde_json::to_value(state).map_err(|error| internal_json(&error))?,
            diagnostics,
        })
    }

    async fn discover(&self, token: &str, identity: &ResourceIdentity) -> PluginResult<Discovery> {
        let selector = identity.environment_selector();
        let mut servers = self.api.servers(token, &selector).await?;
        let mut firewalls = self.api.firewalls(token, &selector).await?;
        if servers.len() > 1 || firewalls.len() > 1 {
            return Err(PluginError::permanent(
                ErrorKind::Conflict,
                "duplicate_managed_resources",
                "multiple Hetzner resources have the same immutable Lightrail environment labels",
            )
            .with_details(json!({
                "servers": servers.iter().map(|server| server.id).collect::<Vec<_>>(),
                "firewalls": firewalls.iter().map(|firewall| firewall.id).collect::<Vec<_>>()
            })));
        }
        Ok(Discovery {
            server: servers.pop(),
            firewall: firewalls.pop(),
        })
    }

    async fn project_resources(
        &self,
        token: &str,
        identity: &ResourceIdentity,
    ) -> PluginResult<ProjectResources> {
        let selector = identity.project_selector();
        Ok(ProjectResources {
            servers: self.api.servers(token, &selector).await?,
            firewalls: self.api.firewalls(token, &selector).await?,
        })
    }

    async fn remember_environment_project(&self, environment_id: &str, project_id: &str) {
        self.environment_projects
            .lock()
            .await
            .insert(environment_id.to_owned(), project_id.to_owned());
    }

    async fn cache_environment_snapshot(
        &self,
        environment_id: &str,
        settings: &Settings,
        discovery: &Discovery,
        project_root: &Path,
    ) -> PluginResult<()> {
        let resources = ProjectResources {
            servers: discovery.server.iter().cloned().collect(),
            firewalls: discovery.firewall.iter().cloned().collect(),
        };
        let snapshot = resource_snapshot(settings, &resources, project_root)?;
        self.lock_snapshots
            .lock()
            .await
            .insert(scope_key(LockScope::Environment, environment_id), snapshot);
        Ok(())
    }

    async fn cache_project_snapshot(
        &self,
        identity: &ResourceIdentity,
        settings: &Settings,
        resources: &ProjectResources,
        project_root: &Path,
    ) -> PluginResult<()> {
        let snapshot = resource_snapshot(settings, resources, project_root)?;
        let mut snapshots = self.lock_snapshots.lock().await;
        snapshots.insert(
            scope_key(LockScope::Project, &identity.project_id),
            snapshot.clone(),
        );
        snapshots.insert(
            scope_key(LockScope::Target, &format!("target:{PLUGIN_ID}")),
            snapshot,
        );
        Ok(())
    }

    async fn verify_project_snapshot(
        &self,
        token: &str,
        identity: &ResourceIdentity,
        operation_id: &str,
    ) -> PluginResult<ProjectResources> {
        let key = scope_key(LockScope::Project, &identity.project_id);
        let expected = {
            let locks = self.locks.lock().await;
            let lock = locks.get(&key).ok_or_else(|| {
                PluginError::permanent(
                    ErrorKind::LockUnavailable,
                    "project_lock_required",
                    "the project lock must remain held until project deletion completes",
                )
            })?;
            if lock.operation_id != operation_id {
                return Err(PluginError::permanent(
                    ErrorKind::LockUnavailable,
                    "project_lock_owner_mismatch",
                    "the project lock is owned by another operation",
                ));
            }
            lock.snapshot.clone().ok_or_else(|| {
                PluginError::permanent(
                    ErrorKind::Internal,
                    "project_lock_snapshot_missing",
                    "the project lock has no provider snapshot",
                )
            })?
        };
        let current = self.project_resources(token, identity).await?;
        let current_server_ids = sorted_server_ids(&current.servers);
        let current_firewall_ids = sorted_firewall_ids(&current.firewalls);
        if current_server_ids != expected.server_ids
            || current_firewall_ids != expected.firewall_ids
        {
            return Err(PluginError::permanent(
                ErrorKind::Conflict,
                "project_resources_changed_after_lock",
                "project resources changed between inspection and provider deletion; re-plan and retry",
            )
            .with_details(json!({
                "expected_server_ids": expected.server_ids,
                "current_server_ids": current_server_ids,
                "expected_firewall_ids": expected.firewall_ids,
                "current_firewall_ids": current_firewall_ids
            })));
        }
        Ok(current)
    }

    async fn delete_discovery(
        &self,
        token: &str,
        mut discovery: Discovery,
        mut journal: Vec<ActionJournalEntry>,
        operation_id: &str,
        events: &EventSink,
    ) -> PluginResult<Vec<ActionJournalEntry>> {
        if let Some(server) = discovery.server.take() {
            journal_event(
                &mut journal,
                events,
                operation_id,
                "delete-server",
                JournalStatus::Started,
                Some("deleting managed server"),
            )
            .await?;
            if let Some(action) = self.api.delete_server(token, server.id).await? {
                self.wait_action(token, action.id, operation_id).await?;
            }
            journal_event(
                &mut journal,
                events,
                operation_id,
                "delete-server",
                JournalStatus::Succeeded,
                Some("managed server deleted"),
            )
            .await?;
        }
        if let Some(firewall) = discovery.firewall.take() {
            journal_event(
                &mut journal,
                events,
                operation_id,
                "delete-firewall",
                JournalStatus::Started,
                Some("deleting managed firewall"),
            )
            .await?;
            self.api.delete_firewall(token, firewall.id).await?;
            journal_event(
                &mut journal,
                events,
                operation_id,
                "delete-firewall",
                JournalStatus::Succeeded,
                Some("managed firewall deleted"),
            )
            .await?;
        }
        Ok(journal)
    }

    async fn delete_project_resources(
        &self,
        token: &str,
        resources: ProjectResources,
        mut journal: Vec<ActionJournalEntry>,
        operation_id: &str,
        events: &EventSink,
    ) -> PluginResult<Vec<ActionJournalEntry>> {
        // Delete every server first because Hetzner rejects deletion of a
        // firewall while it remains applied to any server.
        for server in resources.servers {
            let action_id = format!("delete-server-{}", server.id);
            journal_event(
                &mut journal,
                events,
                operation_id,
                &action_id,
                JournalStatus::Started,
                Some("deleting project server"),
            )
            .await?;
            if let Some(action) = self.api.delete_server(token, server.id).await? {
                self.wait_action(token, action.id, operation_id).await?;
            }
            journal_event(
                &mut journal,
                events,
                operation_id,
                &action_id,
                JournalStatus::Succeeded,
                Some("project server deleted"),
            )
            .await?;
        }
        for firewall in resources.firewalls {
            let action_id = format!("delete-firewall-{}", firewall.id);
            journal_event(
                &mut journal,
                events,
                operation_id,
                &action_id,
                JournalStatus::Started,
                Some("deleting project firewall"),
            )
            .await?;
            self.api.delete_firewall(token, firewall.id).await?;
            journal_event(
                &mut journal,
                events,
                operation_id,
                &action_id,
                JournalStatus::Succeeded,
                Some("project firewall deleted"),
            )
            .await?;
        }
        Ok(journal)
    }

    async fn wait_action(
        &self,
        token: &str,
        action_id: u64,
        operation_id: &str,
    ) -> PluginResult<()> {
        let deadline = Instant::now() + ACTION_TIMEOUT;
        loop {
            if self.is_cancelled(operation_id) {
                return Err(cancelled_error());
            }
            let action = self.api.action(token, action_id).await?;
            match action.status.as_str() {
                "success" => return Ok(()),
                "error" => return Err(action_error(&action)),
                _ if Instant::now() >= deadline => {
                    return Err(PluginError::retryable(
                        ErrorKind::Timeout,
                        "provider_action_timeout",
                        format!("Hetzner action {action_id} did not finish in time"),
                    ));
                }
                _ => sleep(Duration::from_secs(1)).await,
            }
        }
    }

    async fn wait_server(
        &self,
        token: &str,
        server_id: u64,
        operation_id: &str,
    ) -> PluginResult<Server> {
        let deadline = Instant::now() + ACTION_TIMEOUT;
        loop {
            if self.is_cancelled(operation_id) {
                return Err(cancelled_error());
            }
            if let Some(server) = self.api.server(token, server_id).await? {
                if server.status == "running" && server.public_ipv4().is_some() {
                    return Ok(server);
                }
            }
            if Instant::now() >= deadline {
                return Err(PluginError::retryable(
                    ErrorKind::Timeout,
                    "server_start_timeout",
                    "the Hetzner server did not become running with a public IPv4 in time",
                ));
            }
            sleep(Duration::from_secs(2)).await;
        }
    }

    fn is_cancelled(&self, operation_id: &str) -> bool {
        self.cancelled
            .lock()
            .expect("cancel mutex poisoned")
            .contains(operation_id)
    }

    async fn ensure_lock(
        &self,
        scope: LockScope,
        scope_id: &str,
        operation_id: &str,
    ) -> PluginResult<()> {
        let key = scope_key(scope, scope_id);
        let (check, mut invalid) = {
            let mut locks = self.locks.lock().await;
            let check = match locks.get_mut(&key) {
                Some(lock)
                    if lock.scope == scope
                        && lock.scope_id == scope_id
                        && lock.operation_id == operation_id =>
                {
                    if lock.remote_upgrade_in_progress {
                        HeldLockCheck::UpgradeInProgress
                    } else if remote_lock_processes_alive(&mut lock.remote_processes) {
                        HeldLockCheck::Valid
                    } else {
                        HeldLockCheck::RemoteAuthorityLost
                    }
                }
                _ => HeldLockCheck::MissingOrWrongOwner,
            };
            let invalid = matches!(check, HeldLockCheck::RemoteAuthorityLost)
                .then(|| locks.remove(&key))
                .flatten();
            (check, invalid)
        };
        if let Some(invalid) = invalid.as_mut() {
            release_remote_processes(&mut invalid.remote_processes).await;
        }
        match check {
            HeldLockCheck::Valid => Ok(()),
            HeldLockCheck::MissingOrWrongOwner => Err(PluginError::permanent(
                ErrorKind::LockUnavailable,
                "operation_lock_required",
                format!(
                    "acquire the {} operation lock `{scope_id}` before apply or destroy",
                    lock_scope_name(scope)
                ),
            )),
            HeldLockCheck::UpgradeInProgress => Err(PluginError::permanent(
                ErrorKind::LockUnavailable,
                "remote_lock_upgrade_in_progress",
                "the remote operation lock is still being established",
            )),
            HeldLockCheck::RemoteAuthorityLost => Err(PluginError::permanent(
                ErrorKind::LockUnavailable,
                "remote_lock_authority_lost",
                "the SSH process holding the remote operation lock has exited",
            )),
        }
    }

    async fn upgrade_environment_lock(
        &self,
        environment_id: &str,
        operation_id: &str,
        server_id: u64,
        target: &SshTarget,
    ) -> PluginResult<()> {
        let key = scope_key(LockScope::Environment, environment_id);
        let lease = {
            let mut locks = self.locks.lock().await;
            let held = locks.get_mut(&key).ok_or_else(|| {
                PluginError::permanent(
                    ErrorKind::LockUnavailable,
                    "environment_lock_lost",
                    "the environment lock was released before the new server became ready",
                )
            });
            let held = match held {
                Ok(held) => held,
                Err(error) => return Err(remote_lock_upgrade_failure(error)),
            };
            let status = remote_lock_status(held);
            let decision = environment_lock_upgrade_decision(
                LockOwnerRef {
                    scope: held.scope,
                    scope_id: &held.scope_id,
                    operation_id: &held.operation_id,
                },
                environment_id,
                operation_id,
                status,
            );
            match decision {
                Err(error) => return Err(remote_lock_upgrade_failure(error)),
                Ok(RemoteLockUpgradeDecision::AlreadyAuthoritative) => return Ok(()),
                Ok(RemoteLockUpgradeDecision::Acquire) => {
                    held.remote_upgrade_in_progress = true;
                    RemoteLockUpgradeLease {
                        token: held.token.clone(),
                        timeout: held.remote_lock_timeout,
                    }
                }
            }
        };

        let snapshot = ResourceSnapshot {
            server_ids: vec![server_id],
            firewall_ids: Vec::new(),
            targets: vec![SnapshotTarget {
                server_id,
                target: Some(target.clone()),
            }],
        };
        let remote_targets = match remote_lock_targets(&snapshot) {
            Ok(targets) => targets,
            Err(error) => {
                self.invalidate_environment_lock(&key, operation_id, &lease.token)
                    .await;
                return Err(remote_lock_upgrade_failure(error));
            }
        };
        let mut processes = match acquire_remote_processes(
            LockScope::Environment,
            environment_id,
            remote_targets,
            lease.timeout,
        )
        .await
        {
            Ok(processes) => processes,
            Err(error) => {
                self.invalidate_environment_lock(&key, operation_id, &lease.token)
                    .await;
                return Err(remote_lock_upgrade_failure(error));
            }
        };

        let attached = {
            let mut locks = self.locks.lock().await;
            match locks.get_mut(&key) {
                Some(held)
                    if held.scope == LockScope::Environment
                        && held.scope_id == environment_id
                        && held.operation_id == operation_id
                        && held.token == lease.token =>
                {
                    held.remote_upgrade_in_progress = false;
                    if held.remote_processes.is_empty() {
                        held.remote_processes.append(&mut processes);
                    }
                    true
                }
                _ => false,
            }
        };
        release_remote_processes(&mut processes).await;
        if attached {
            Ok(())
        } else {
            self.invalidate_environment_lock(&key, operation_id, &lease.token)
                .await;
            Err(remote_lock_upgrade_failure(PluginError::permanent(
                ErrorKind::LockUnavailable,
                "environment_lock_lost_during_upgrade",
                "the environment lock changed owner while its remote authority was acquired",
            )))
        }
    }

    async fn invalidate_environment_lock(&self, key: &str, operation_id: &str, token: &str) {
        let mut held = {
            let mut locks = self.locks.lock().await;
            if locks
                .get(key)
                .is_some_and(|held| held.operation_id == operation_id && held.token == token)
            {
                locks.remove(key)
            } else {
                None
            }
        };
        if let Some(held) = held.as_mut() {
            release_remote_processes(&mut held.remote_processes).await;
        }
    }

    async fn existing_lock_acquire_result(
        &self,
        key: &str,
        operation_id: &str,
    ) -> PluginResult<Option<LockAcquireResult>> {
        let (result, mut invalid) = {
            let mut locks = self.locks.lock().await;
            let same_owner_remote_lost = locks.get_mut(key).is_some_and(|held| {
                held.operation_id == operation_id
                    && !held.remote_processes.is_empty()
                    && !remote_lock_processes_alive(&mut held.remote_processes)
            });
            if same_owner_remote_lost {
                (None, locks.remove(key))
            } else {
                let result = locks.get(key).map(|held| {
                    if held.operation_id == operation_id {
                        LockAcquireResult {
                            acquired: true,
                            token: Some(SecretValue::new(held.token.clone())),
                            expires_at: None,
                            holder: None,
                        }
                    } else {
                        LockAcquireResult {
                            acquired: false,
                            token: None,
                            expires_at: None,
                            holder: Some(held.operation_id.clone()),
                        }
                    }
                });
                (result, None)
            }
        };
        if let Some(invalid) = invalid.as_mut() {
            release_remote_processes(&mut invalid.remote_processes).await;
            return Err(PluginError::permanent(
                ErrorKind::LockUnavailable,
                "remote_lock_authority_lost",
                "the SSH process holding the remote operation lock has exited",
            ));
        }
        Ok(result)
    }
}

fn target_state(
    server: &Server,
    firewall: Option<&Firewall>,
    settings: &Settings,
    identity: &ResourceIdentity,
    known_hosts_file: &Path,
) -> TargetState {
    let public_ipv4 = server.public_ipv4().unwrap_or_default().to_owned();
    let architecture = server.architecture().to_owned();
    TargetState {
        kind: "ssh".to_owned(),
        provider: "hetzner".to_owned(),
        server_id: server.id,
        firewall_id: firewall.map(|firewall| firewall.id),
        host: public_ipv4.clone(),
        user: settings.ssh_user.clone(),
        port: 22,
        identity_file: settings
            .identity_file
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned()),
        known_hosts_file: Some(known_hosts_file.to_string_lossy().into_owned()),
        docker: DockerTargetState {
            requires_sudo: false,
        },
        public_ipv4,
        platform: format!("linux/{architecture}"),
        architecture,
        isolation: "machine".to_owned(),
        remote_root: identity.remote_root.clone(),
        server_name: server.name.clone(),
        server_status: server.status.clone(),
        server_type: server.flavor.name.clone(),
        image: server.image.as_ref().map(|image| image.name.clone()),
        location: server.location().map(ToOwned::to_owned),
        config_fingerprint: server.config_fingerprint().map(ToOwned::to_owned),
        firewall_fingerprint: firewall.map(|firewall| hash_json(&canonical_rules(&firewall.rules))),
    }
}

fn aggregate_inspection(
    settings: &Settings,
    identity: &ResourceIdentity,
    resources: &ProjectResources,
    project_root: &Path,
) -> PluginResult<InspectResult> {
    let mut diagnostics = Vec::new();
    let mut targets = Vec::new();
    for server in &resources.servers {
        let environment_label = server
            .labels
            .get(ENVIRONMENT_LABEL)
            .cloned()
            .unwrap_or_else(|| format!("unknown-{}", server.id));
        if !server.labels.contains_key(ENVIRONMENT_LABEL) {
            diagnostics.push(Diagnostic {
                severity: DiagnosticSeverity::Warning,
                code: "environment_label_missing".to_owned(),
                message: format!(
                    "managed server {} is missing its immutable environment label",
                    server.id
                ),
                path: None,
                help: None,
            });
        }
        let firewall = resources
            .firewalls
            .iter()
            .find(|firewall| firewall.labels.get(ENVIRONMENT_LABEL) == Some(&environment_label));
        let synthetic_identity = ResourceIdentity {
            project_id: identity.project_id.clone(),
            environment_id: environment_label.clone(),
            project_label: identity.project_label.clone(),
            environment_label: environment_label.clone(),
            server_name: server.name.clone(),
            firewall_name: firewall.map_or_else(
                || format!("{}-fw", server.name),
                |firewall| firewall.name.clone(),
            ),
            remote_root: format!("/opt/lightrail/{environment_label}"),
        };
        let known_hosts_file =
            prepare_known_hosts_file(project_root, &environment_label, server.id)?;
        let mut state = serde_json::to_value(target_state(
            server,
            firewall,
            settings,
            &synthetic_identity,
            &known_hosts_file,
        ))
        .map_err(|error| internal_json(&error))?;
        if let Some(object) = state.as_object_mut() {
            object.insert("environment_id".to_owned(), Value::Null);
            object.insert(
                "environment_label".to_owned(),
                Value::String(environment_label),
            );
        }
        targets.push(state);
    }
    targets.sort_by(|left, right| {
        left.get("server_id")
            .and_then(Value::as_u64)
            .cmp(&right.get("server_id").and_then(Value::as_u64))
    });

    let resource_count = resources
        .servers
        .len()
        .saturating_add(resources.firewalls.len());
    let status = if resource_count == 0 {
        ResourceStatus::Absent
    } else if resources.servers.iter().any(|server| {
        matches!(
            server.status.as_str(),
            "initializing" | "starting" | "migrating" | "rebuilding"
        )
    }) {
        ResourceStatus::Pending
    } else if resources
        .servers
        .iter()
        .any(|server| server.public_ipv4().is_none())
    {
        ResourceStatus::Degraded
    } else {
        ResourceStatus::Ready
    };
    Ok(InspectResult {
        status,
        endpoints: Vec::new(),
        state: json!({
            "kind": "hetzner-project",
            "provider": "hetzner",
            "scope": "project",
            "project_id": identity.project_id,
            "environment_count": resources.servers.len(),
            "server_count": resources.servers.len(),
            "firewall_count": resources.firewalls.len(),
            "resource_count": resource_count,
            "targets": targets
        }),
        diagnostics,
    })
}

fn project_delete_actions(resources: &ProjectResources, actions: &mut Vec<PlannedAction>) {
    for server_id in sorted_server_ids(&resources.servers) {
        actions.push(delete_action(
            &format!("delete-server-{server_id}"),
            &format!("Delete Hetzner Cloud server {server_id}"),
        ));
    }
    for firewall_id in sorted_firewall_ids(&resources.firewalls) {
        actions.push(delete_action(
            &format!("delete-firewall-{firewall_id}"),
            &format!("Delete managed Hetzner Cloud firewall {firewall_id}"),
        ));
    }
}

fn resource_snapshot(
    settings: &Settings,
    resources: &ProjectResources,
    project_root: &Path,
) -> PluginResult<ResourceSnapshot> {
    let targets = resources
        .servers
        .iter()
        .map(|server| -> PluginResult<SnapshotTarget> {
            let environment_label = server.labels.get(ENVIRONMENT_LABEL);
            let lock_key = environment_label
                .and_then(|label| label.strip_prefix("e-"))
                .map_or_else(
                    || short_hash(&format!("server:{}", server.id), 32),
                    ToOwned::to_owned,
                );
            let target = server
                .public_ipv4()
                .map(|host| {
                    let remote_root = environment_label.map_or_else(
                        || format!("/opt/lightrail/server-{}", server.id),
                        |label| format!("/opt/lightrail/{label}"),
                    );
                    let known_hosts_file = prepare_known_hosts_file(
                        project_root,
                        environment_label.map_or(lock_key.as_str(), String::as_str),
                        server.id,
                    )?;
                    let mut target = SshTarget::from_parts(
                        host,
                        settings,
                        remote_root,
                        &lock_key,
                        known_hosts_file,
                    );
                    target.lock_key = lock_key;
                    Ok(target)
                })
                .transpose()?;
            Ok(SnapshotTarget {
                server_id: server.id,
                target,
            })
        })
        .collect::<PluginResult<Vec<_>>>()?;
    Ok(ResourceSnapshot {
        server_ids: sorted_server_ids(&resources.servers),
        firewall_ids: sorted_firewall_ids(&resources.firewalls),
        targets,
    })
}

fn sorted_server_ids(servers: &[Server]) -> Vec<u64> {
    let mut ids: Vec<_> = servers.iter().map(|server| server.id).collect();
    ids.sort_unstable();
    ids
}

fn sorted_firewall_ids(firewalls: &[Firewall]) -> Vec<u64> {
    let mut ids: Vec<_> = firewalls.iter().map(|firewall| firewall.id).collect();
    ids.sort_unstable();
    ids
}

fn remote_lock_targets(snapshot: &ResourceSnapshot) -> PluginResult<Vec<(u64, SshTarget)>> {
    let mut targets = Vec::new();
    for entry in &snapshot.targets {
        let target = entry.target.clone().ok_or_else(|| {
            PluginError::retryable(
                ErrorKind::Unavailable,
                "server_lock_unreachable",
                format!(
                    "managed server {} has no reachable public IPv4 for its remote lock",
                    entry.server_id
                ),
            )
        })?;
        targets.push((entry.server_id, target));
    }
    targets.sort_unstable_by_key(|(server_id, _)| *server_id);
    Ok(targets)
}

fn scope_key(scope: LockScope, scope_id: &str) -> String {
    format!("{}:{scope_id}", lock_scope_name(scope))
}

const fn lock_scope_name(scope: LockScope) -> &'static str {
    match scope {
        LockScope::Environment => "environment",
        LockScope::Project => "project",
        LockScope::Target => "target",
    }
}

fn scopes_overlap(
    requested_scope: LockScope,
    requested_project: Option<&str>,
    existing_scope: LockScope,
    existing_project: Option<&str>,
) -> bool {
    if requested_scope == LockScope::Target || existing_scope == LockScope::Target {
        return true;
    }
    requested_project == existing_project
        && requested_project.is_some()
        && (requested_scope == LockScope::Project || existing_scope == LockScope::Project)
}

fn remote_lock_status(lock: &HeldLock) -> RemoteLockStatus {
    if !lock.remote_processes.is_empty() {
        RemoteLockStatus::Authoritative
    } else if lock.remote_upgrade_in_progress {
        RemoteLockStatus::Acquiring
    } else {
        RemoteLockStatus::Missing
    }
}

fn remote_lock_processes_alive(processes: &mut [Child]) -> bool {
    processes
        .iter_mut()
        .all(|process| process.try_wait().is_ok_and(|status| status.is_none()))
}

fn environment_lock_upgrade_decision(
    held: LockOwnerRef<'_>,
    environment_id: &str,
    operation_id: &str,
    status: RemoteLockStatus,
) -> PluginResult<RemoteLockUpgradeDecision> {
    if held.scope != LockScope::Environment || held.scope_id != environment_id {
        return Err(PluginError::permanent(
            ErrorKind::LockUnavailable,
            "environment_lock_scope_mismatch",
            "the held lock does not authorize this environment",
        ));
    }
    if held.operation_id != operation_id {
        return Err(PluginError::permanent(
            ErrorKind::LockUnavailable,
            "environment_lock_owner_mismatch",
            "the environment lock is owned by another operation",
        ));
    }
    match status {
        RemoteLockStatus::Missing => Ok(RemoteLockUpgradeDecision::Acquire),
        RemoteLockStatus::Authoritative => Ok(RemoteLockUpgradeDecision::AlreadyAuthoritative),
        RemoteLockStatus::Acquiring => Err(PluginError::permanent(
            ErrorKind::LockUnavailable,
            "environment_lock_upgrade_in_progress",
            "the environment lock is already being upgraded by this operation",
        )),
    }
}

async fn acquire_remote_processes(
    scope: LockScope,
    scope_id: &str,
    remote_targets: Vec<(u64, SshTarget)>,
    maximum: Duration,
) -> PluginResult<Vec<Child>> {
    let deadline = Instant::now() + maximum;
    let target_count = remote_targets.len();
    let mut processes = Vec::new();
    let mut selected_error = None;
    for (index, (server_id, target)) in remote_targets.into_iter().enumerate() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let targets_left = u32::try_from(target_count.saturating_sub(index)).unwrap_or(u32::MAX);
        if remaining.is_zero() {
            let error = PluginError::retryable(
                ErrorKind::Timeout,
                "remote_lock_timeout",
                "timed out while locking every server in the requested scope",
            )
            .with_details(json!({
                "scope": lock_scope_name(scope),
                "scope_id": scope_id,
                "server_id": server_id
            }));
            selected_error = Some(preferred_remote_lock_error(selected_error, error));
            continue;
        }
        let target_budget = remaining / targets_left.max(1);
        match acquire_remote_flock(&target, target_budget).await {
            Ok(process) => processes.push(process),
            Err(error) => {
                let error = error.with_details(json!({
                    "scope": lock_scope_name(scope),
                    "scope_id": scope_id,
                    "server_id": server_id
                }));
                selected_error = Some(preferred_remote_lock_error(selected_error, error));
            }
        }
    }
    if let Some(error) = selected_error {
        release_remote_processes(&mut processes).await;
        Err(error)
    } else {
        Ok(processes)
    }
}

fn preferred_remote_lock_error(
    current: Option<PluginError>,
    candidate: PluginError,
) -> PluginError {
    match current {
        Some(current)
            if remote_lock_error_priority(current.kind)
                >= remote_lock_error_priority(candidate.kind) =>
        {
            current
        }
        _ => candidate,
    }
}

const fn remote_lock_error_priority(kind: ErrorKind) -> u8 {
    match kind {
        ErrorKind::LockUnavailable => 4,
        ErrorKind::Authentication
        | ErrorKind::Validation
        | ErrorKind::Unsupported
        | ErrorKind::Conflict
        | ErrorKind::Internal
        | ErrorKind::Cancelled
        | ErrorKind::NotFound => 3,
        ErrorKind::Timeout | ErrorKind::RateLimited => 2,
        ErrorKind::Unavailable => 1,
    }
}

async fn release_remote_processes(processes: &mut Vec<Child>) {
    while let Some(mut process) = processes.pop() {
        let _ = process.kill().await;
        let _ = process.wait().await;
    }
}

fn remote_lock_upgrade_failure(mut error: PluginError) -> PluginError {
    const PRESERVE_KEY: &str = "preserve_provider_resources";
    let mut details = match std::mem::take(&mut error.details) {
        Value::Object(details) => details,
        Value::Null => serde_json::Map::new(),
        details => serde_json::Map::from_iter([("cause_details".to_owned(), details)]),
    };
    details.insert(PRESERVE_KEY.to_owned(), Value::Bool(true));
    error.details = Value::Object(details);
    error.retryable = false;
    error.message = format!(
        "{}; the provisioned server was preserved for explicit recovery",
        error.message
    );
    error
}

fn must_preserve_provider_resources(error: &PluginError) -> bool {
    error
        .details
        .get("preserve_provider_resources")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn absent_state(identity: &ResourceIdentity) -> Value {
    json!({
        "kind": "ssh",
        "provider": "hetzner",
        "status": "absent",
        "isolation": "machine",
        "remote_root": identity.remote_root
    })
}

fn desired_present(desired: &Value, operation_metadata: &Value) -> bool {
    let destroying = desired
        .get("destroy")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || operation_metadata
            .get("operation")
            .and_then(Value::as_str)
            .is_some_and(|operation| operation == "destroy");
    !destroying
        && desired
            .get("present")
            .and_then(Value::as_bool)
            .unwrap_or(true)
}

fn all_context(operation_metadata: &Value) -> bool {
    operation_metadata
        .get("all")
        .or_else(|| operation_metadata.get("destroy_all"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn context_project_root(context: &OperationContext) -> PluginResult<&Path> {
    let value = context.project_root.as_deref().ok_or_else(|| {
        validation(
            "project_root_required",
            "the Hetzner target requires an absolute project root for scoped SSH host-key state",
        )
    })?;
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(validation(
            "project_root_not_absolute",
            "the Hetzner target requires an absolute project root",
        ));
    }
    Ok(path)
}

fn server_payload(
    settings: &Settings,
    identity: &ResourceIdentity,
    firewall: &Firewall,
    ssh_key_ids: &[u64],
    fingerprint: &str,
) -> CreateServer {
    CreateServer {
        name: identity.server_name.clone(),
        server_type: settings.server_type.clone(),
        image: settings.image.clone(),
        location: settings.location.clone(),
        ssh_keys: ssh_key_ids.to_vec(),
        labels: identity.labels(fingerprint),
        firewalls: vec![CreateServerFirewall {
            firewall: firewall.id,
        }],
        user_data: cloud_init(settings, &identity.remote_root),
        start_after_create: true,
        public_net: CreatePublicNet {
            enable_ipv4: true,
            enable_ipv6: true,
        },
    }
}

fn plan_id(environment_id: &str, metadata: &Value, actions: &[PlannedAction]) -> String {
    let action_shape: Vec<_> = actions
        .iter()
        .map(|action| (&action.id, &action.kind, action.destructive))
        .collect();
    hash_json(&(environment_id, metadata, action_shape))
}

fn create_action(id: &str, summary: &str) -> PlannedAction {
    PlannedAction {
        id: id.to_owned(),
        kind: "create".to_owned(),
        summary: summary.to_owned(),
        destructive: false,
        depends_on: Vec::new(),
        rollback: Some(RollbackMetadata {
            supported: true,
            action: Some("delete".to_owned()),
            token: None,
            metadata: Value::Object(serde_json::Map::new()),
        }),
        metadata: Value::Object(serde_json::Map::new()),
    }
}

fn update_action(id: &str, summary: &str) -> PlannedAction {
    PlannedAction {
        id: id.to_owned(),
        kind: "update".to_owned(),
        summary: summary.to_owned(),
        destructive: false,
        depends_on: Vec::new(),
        rollback: None,
        metadata: Value::Object(serde_json::Map::new()),
    }
}

fn delete_action(id: &str, summary: &str) -> PlannedAction {
    PlannedAction {
        id: id.to_owned(),
        kind: "delete".to_owned(),
        summary: summary.to_owned(),
        destructive: true,
        depends_on: Vec::new(),
        rollback: Some(RollbackMetadata {
            supported: false,
            action: None,
            token: None,
            metadata: json!({
                "reason": "machine-local volumes and database changes cannot be restored"
            }),
        }),
        metadata: Value::Object(serde_json::Map::new()),
    }
}

async fn journal_event(
    journal: &mut Vec<ActionJournalEntry>,
    events: &EventSink,
    operation_id: &str,
    action_id: &str,
    status: JournalStatus,
    message: Option<&str>,
) -> PluginResult<()> {
    let sequence = journal
        .iter()
        .map(|entry| entry.sequence)
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    let entry = ActionJournalEntry {
        sequence,
        action_id: action_id.to_owned(),
        status,
        timestamp: None,
        message: message.map(ToOwned::to_owned),
        rollback: None,
        metadata: Value::Object(serde_json::Map::new()),
    };
    events
        .emit(&PluginEvent::Journal {
            operation_id: operation_id.to_owned(),
            entry: entry.clone(),
        })
        .await
        .map_err(event_error)?;
    journal.push(entry);
    Ok(())
}

fn action_error(action: &ApiAction) -> PluginError {
    let (code, message) = action.error.as_ref().map_or(
        ("unknown_action_error", "the provider action failed"),
        |error| (error.code.as_str(), error.message.as_str()),
    );
    PluginError::permanent(
        ErrorKind::Conflict,
        "hetzner_action_failed",
        format!("Hetzner action {} failed ({code}): {message}", action.id),
    )
}

fn cancelled_error() -> PluginError {
    PluginError::permanent(
        ErrorKind::Cancelled,
        "operation_cancelled",
        "the operation was cancelled",
    )
}

fn event_error(error: impl std::fmt::Display) -> PluginError {
    PluginError::permanent(
        ErrorKind::Internal,
        "event_transport_failed",
        format!("could not emit a plugin event: {error}"),
    )
}

fn internal_json(error: &serde_json::Error) -> PluginError {
    PluginError::permanent(
        ErrorKind::Internal,
        "json_encoding_failed",
        format!("could not encode provider state: {error}"),
    )
}

fn config_error_path(_details: &Value) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::PathBuf, process::Stdio};

    use super::*;
    use crate::api::{AppliedServer, AppliedTo, PublicIpv4, PublicNet, ServerType};
    use crate::model::CONFIG_LABEL;
    use tempfile::tempdir;

    fn settings() -> Settings {
        Settings {
            server_type: "cax11".to_owned(),
            ssh_keys: vec!["operator".to_owned()],
            allowed_ssh_cidrs: vec!["203.0.113.4/32".to_owned()],
            ..Settings::default()
        }
    }

    fn identity() -> ResourceIdentity {
        ResourceIdentity {
            project_id: "project-id".to_owned(),
            environment_id: "env-id".to_owned(),
            project_label: "p-abc".to_owned(),
            environment_label: "e-def".to_owned(),
            server_name: "lr-example-abc".to_owned(),
            firewall_name: "lr-example-abc-fw".to_owned(),
            remote_root: "/opt/lightrail/e-def".to_owned(),
        }
    }

    fn firewall() -> Firewall {
        Firewall {
            id: 8,
            name: "lr-example-abc-fw".to_owned(),
            labels: BTreeMap::from([(ENVIRONMENT_LABEL.to_owned(), "e-def".to_owned())]),
            rules: firewall_rules(&settings()),
            applied_to: vec![AppliedTo {
                kind: "server".to_owned(),
                server: Some(AppliedServer { id: 7 }),
            }],
        }
    }

    fn server() -> Server {
        let settings = settings();
        Server {
            id: 7,
            name: "lr-example-abc".to_owned(),
            status: "running".to_owned(),
            labels: BTreeMap::from([
                (
                    CONFIG_LABEL.to_owned(),
                    settings.config_fingerprint()[..32].to_owned(),
                ),
                (ENVIRONMENT_LABEL.to_owned(), "e-def".to_owned()),
            ]),
            public_net: PublicNet {
                ipv4: Some(PublicIpv4 {
                    ip: "203.0.113.7".to_owned(),
                }),
            },
            flavor: ServerType {
                name: "cax11".to_owned(),
                architecture: "arm".to_owned(),
            },
            image: None,
            datacenter: None,
        }
    }

    #[test]
    fn create_server_payload_contains_only_safe_configuration() {
        let settings = settings();
        let payload = server_payload(
            &settings,
            &identity(),
            &firewall(),
            &[41],
            &settings.config_fingerprint(),
        );
        let encoded = serde_json::to_value(&payload).unwrap();
        assert_eq!(encoded["ssh_keys"], json!([41]));
        assert_eq!(encoded["firewalls"], json!([{"firewall": 8}]));
        assert_eq!(encoded["public_net"]["enable_ipv4"], true);
        assert!(
            encoded["user_data"]
                .as_str()
                .is_some_and(|user_data| user_data.contains("#cloud-config"))
        );
        let encoded = encoded.to_string();
        assert!(!encoded.contains("hetzner-token"));
        assert!(!encoded.contains("actual-provider-token"));
    }

    #[test]
    fn target_state_is_compatible_with_agentless_ssh_runtime() {
        let known_hosts_file =
            Path::new("/tmp/project/.lightrail/known_hosts/hetzner-env-server-7");
        let value = serde_json::to_value(target_state(
            &server(),
            Some(&firewall()),
            &settings(),
            &identity(),
            known_hosts_file,
        ))
        .unwrap();
        assert_eq!(value["kind"], "ssh");
        assert_eq!(value["host"], "203.0.113.7");
        assert_eq!(value["user"], "root");
        assert_eq!(value["port"], 22);
        assert_eq!(value["architecture"], "arm64");
        assert_eq!(value["platform"], "linux/arm64");
        assert_eq!(value["isolation"], "machine");
        assert_eq!(value["remote_root"], "/opt/lightrail/e-def");
        assert_eq!(
            value["known_hosts_file"],
            known_hosts_file.to_string_lossy().as_ref()
        );
        assert_eq!(value["docker"]["requires_sudo"], false);
    }

    #[test]
    fn plan_id_changes_if_actions_are_modified() {
        let metadata = json!({"present": true});
        let create = vec![create_action("create-server", "create")];
        let delete = vec![delete_action("delete-server", "delete")];
        assert_ne!(
            plan_id("env", &metadata, &create),
            plan_id("env", &metadata, &delete)
        );
    }

    #[test]
    fn core_destroy_shape_plans_absence() {
        assert!(!desired_present(&json!({ "destroy": true }), &Value::Null));
        assert!(!desired_present(
            &Value::Null,
            &json!({ "operation": "destroy" })
        ));
        assert!(desired_present(&json!({ "present": true }), &Value::Null));
    }

    #[test]
    fn project_aggregate_reports_every_owned_resource_without_raw_environment_id() {
        let project = tempdir().unwrap();
        let resources = ProjectResources {
            servers: vec![server()],
            firewalls: vec![firewall()],
        };
        let inspection =
            aggregate_inspection(&settings(), &identity(), &resources, project.path()).unwrap();
        assert_eq!(inspection.status, ResourceStatus::Ready);
        assert_eq!(inspection.state["server_count"], 1);
        assert_eq!(inspection.state["firewall_count"], 1);
        assert_eq!(inspection.state["resource_count"], 2);
        assert_eq!(inspection.state["targets"][0]["server_id"], 7);
        assert_eq!(inspection.state["targets"][0]["environment_label"], "e-def");
        assert!(inspection.state["targets"][0]["environment_id"].is_null());
        assert_eq!(
            inspection.state["targets"][0]["docker"]["requires_sudo"],
            false
        );
    }

    #[test]
    fn project_destroy_plan_is_independent_of_current_environment() {
        let resources = ProjectResources {
            servers: vec![server()],
            firewalls: vec![firewall()],
        };
        let mut actions = Vec::new();
        project_delete_actions(&resources, &mut actions);
        assert_eq!(
            actions
                .iter()
                .map(|action| action.id.as_str())
                .collect::<Vec<_>>(),
            ["delete-server-7", "delete-firewall-8"]
        );
        assert!(actions.iter().all(|action| action.destructive));
        assert!(all_context(&json!({ "all": true })));
    }

    #[test]
    fn scoped_locks_overlap_at_project_boundaries() {
        assert!(scopes_overlap(
            LockScope::Project,
            Some("project"),
            LockScope::Environment,
            Some("project")
        ));
        assert!(!scopes_overlap(
            LockScope::Environment,
            Some("project"),
            LockScope::Environment,
            Some("project")
        ));
        assert!(scopes_overlap(
            LockScope::Target,
            None,
            LockScope::Environment,
            Some("project")
        ));
    }

    #[test]
    fn environment_lock_upgrade_requires_the_same_owner_and_only_runs_once() {
        let owner = LockOwnerRef {
            scope: LockScope::Environment,
            scope_id: "environment",
            operation_id: "operation",
        };
        assert_eq!(
            environment_lock_upgrade_decision(
                owner,
                "environment",
                "operation",
                RemoteLockStatus::Missing
            )
            .unwrap(),
            RemoteLockUpgradeDecision::Acquire
        );
        assert_eq!(
            environment_lock_upgrade_decision(
                owner,
                "environment",
                "operation",
                RemoteLockStatus::Authoritative
            )
            .unwrap(),
            RemoteLockUpgradeDecision::AlreadyAuthoritative
        );

        let wrong_owner = environment_lock_upgrade_decision(
            owner,
            "environment",
            "other-operation",
            RemoteLockStatus::Missing,
        )
        .unwrap_err();
        assert_eq!(wrong_owner.kind, ErrorKind::LockUnavailable);
        assert_eq!(wrong_owner.code, "environment_lock_owner_mismatch");

        let concurrent_upgrade = environment_lock_upgrade_decision(
            owner,
            "environment",
            "operation",
            RemoteLockStatus::Acquiring,
        )
        .unwrap_err();
        assert_eq!(concurrent_upgrade.kind, ErrorKind::LockUnavailable);
        assert_eq!(
            concurrent_upgrade.code,
            "environment_lock_upgrade_in_progress"
        );
    }

    #[test]
    fn environment_upgrade_locks_only_the_new_environment_machine() {
        let mut target = SshTarget::from_parts(
            "203.0.113.7",
            &settings(),
            "/opt/lightrail/e-def",
            "environment",
            PathBuf::from("/tmp/project/.lightrail/known_hosts/server-7"),
        );
        target.lock_key = short_hash("environment", 32);
        let snapshot = ResourceSnapshot {
            server_ids: vec![7],
            firewall_ids: Vec::new(),
            targets: vec![SnapshotTarget {
                server_id: 7,
                target: Some(target),
            }],
        };
        let targets = remote_lock_targets(&snapshot).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].1.lock_key, short_hash("environment", 32));
    }

    #[test]
    fn project_lock_uses_every_environment_key_in_server_order() {
        let project = tempdir().unwrap();
        let mut later_server = server();
        later_server.id = 9;
        later_server
            .labels
            .insert(ENVIRONMENT_LABEL.to_owned(), "e-later".to_owned());
        let resources = ProjectResources {
            servers: vec![later_server, server()],
            firewalls: vec![firewall()],
        };
        let snapshot = resource_snapshot(&settings(), &resources, project.path()).unwrap();
        let targets = remote_lock_targets(&snapshot).unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].0, 7);
        assert_eq!(targets[0].1.lock_key, "def");
        assert_eq!(targets[1].0, 9);
        assert_eq!(targets[1].1.lock_key, "later");
    }

    #[test]
    fn busy_remote_lock_error_wins_over_unreachable_or_timeout_errors() {
        let unavailable =
            PluginError::retryable(ErrorKind::Unavailable, "unreachable", "server unreachable");
        let timeout = PluginError::retryable(ErrorKind::Timeout, "timeout", "server timed out");
        let busy =
            PluginError::permanent(ErrorKind::LockUnavailable, "busy", "server lock is busy");

        let selected = preferred_remote_lock_error(Some(unavailable), timeout);
        let selected = preferred_remote_lock_error(Some(selected), busy);
        assert_eq!(selected.kind, ErrorKind::LockUnavailable);
        assert_eq!(selected.code, "busy");

        let later_unreachable = PluginError::retryable(
            ErrorKind::Unavailable,
            "later-unreachable",
            "later server unreachable",
        );
        let selected = preferred_remote_lock_error(Some(selected), later_unreachable);
        assert_eq!(selected.kind, ErrorKind::LockUnavailable);
        assert_eq!(selected.code, "busy");
    }

    #[tokio::test]
    async fn failed_upgrade_invalidates_only_its_exact_lock_instance() {
        let plugin = HetznerPlugin::default();
        let key = scope_key(LockScope::Environment, "environment");
        plugin.locks.lock().await.insert(
            key.clone(),
            HeldLock {
                scope: LockScope::Environment,
                scope_id: "environment".to_owned(),
                project_id: Some("project".to_owned()),
                operation_id: "operation".to_owned(),
                token: "token".to_owned(),
                remote_lock_timeout: Duration::from_secs(1),
                remote_upgrade_in_progress: true,
                remote_processes: Vec::new(),
                snapshot: None,
            },
        );

        plugin
            .invalidate_environment_lock(&key, "operation", "different-token")
            .await;
        assert!(plugin.locks.lock().await.contains_key(&key));
        plugin
            .invalidate_environment_lock(&key, "operation", "token")
            .await;
        assert!(!plugin.locks.lock().await.contains_key(&key));
    }

    #[tokio::test]
    async fn ensure_lock_fails_closed_when_an_attached_child_has_exited() {
        let plugin = HetznerPlugin::default();
        let key = scope_key(LockScope::Environment, "environment");
        let mut exited = tokio::process::Command::new("sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .unwrap();
        exited.wait().await.unwrap();
        plugin.locks.lock().await.insert(
            key.clone(),
            HeldLock {
                scope: LockScope::Environment,
                scope_id: "environment".to_owned(),
                project_id: Some("project".to_owned()),
                operation_id: "operation".to_owned(),
                token: "token".to_owned(),
                remote_lock_timeout: Duration::from_secs(1),
                remote_upgrade_in_progress: false,
                remote_processes: vec![exited],
                snapshot: None,
            },
        );

        let error = plugin
            .ensure_lock(LockScope::Environment, "environment", "operation")
            .await
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::LockUnavailable);
        assert_eq!(error.code, "remote_lock_authority_lost");
        assert!(!plugin.locks.lock().await.contains_key(&key));
    }

    #[tokio::test]
    async fn same_owner_reacquire_preserves_the_token_for_an_empty_or_live_lock() {
        let plugin = HetznerPlugin::default();
        let empty_key = scope_key(LockScope::Environment, "pre-provision");
        plugin.locks.lock().await.insert(
            empty_key.clone(),
            HeldLock {
                scope: LockScope::Environment,
                scope_id: "pre-provision".to_owned(),
                project_id: Some("project".to_owned()),
                operation_id: "operation".to_owned(),
                token: "empty-token".to_owned(),
                remote_lock_timeout: Duration::from_secs(1),
                remote_upgrade_in_progress: false,
                remote_processes: Vec::new(),
                snapshot: None,
            },
        );
        let empty = plugin
            .existing_lock_acquire_result(&empty_key, "operation")
            .await
            .unwrap()
            .unwrap();
        assert!(empty.acquired);
        assert_eq!(
            empty.token.as_ref().map(SecretValue::expose_secret),
            Some("empty-token")
        );

        let live_key = scope_key(LockScope::Environment, "provisioned");
        let live = tokio::process::Command::new("sh")
            .arg("-c")
            .arg("cat >/dev/null")
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        plugin.locks.lock().await.insert(
            live_key.clone(),
            HeldLock {
                scope: LockScope::Environment,
                scope_id: "provisioned".to_owned(),
                project_id: Some("project".to_owned()),
                operation_id: "operation".to_owned(),
                token: "live-token".to_owned(),
                remote_lock_timeout: Duration::from_secs(1),
                remote_upgrade_in_progress: false,
                remote_processes: vec![live],
                snapshot: None,
            },
        );
        let live = plugin
            .existing_lock_acquire_result(&live_key, "operation")
            .await
            .unwrap()
            .unwrap();
        assert!(live.acquired);
        assert_eq!(
            live.token.as_ref().map(SecretValue::expose_secret),
            Some("live-token")
        );
        plugin
            .invalidate_environment_lock(&live_key, "operation", "live-token")
            .await;
    }

    #[tokio::test]
    async fn same_owner_reacquire_invalidates_an_exited_remote_child() {
        let plugin = HetznerPlugin::default();
        let key = scope_key(LockScope::Environment, "environment");
        let mut exited = tokio::process::Command::new("sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .unwrap();
        exited.wait().await.unwrap();
        plugin.locks.lock().await.insert(
            key.clone(),
            HeldLock {
                scope: LockScope::Environment,
                scope_id: "environment".to_owned(),
                project_id: Some("project".to_owned()),
                operation_id: "operation".to_owned(),
                token: "token".to_owned(),
                remote_lock_timeout: Duration::from_secs(1),
                remote_upgrade_in_progress: false,
                remote_processes: vec![exited],
                snapshot: None,
            },
        );

        let error = plugin
            .existing_lock_acquire_result(&key, "operation")
            .await
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::LockUnavailable);
        assert_eq!(error.code, "remote_lock_authority_lost");
        assert!(!plugin.locks.lock().await.contains_key(&key));
    }

    #[test]
    fn upgrade_failures_require_explicit_recovery_without_automatic_cleanup() {
        let error = remote_lock_upgrade_failure(PluginError::permanent(
            ErrorKind::LockUnavailable,
            "busy",
            "server lock is busy",
        ));
        assert!(must_preserve_provider_resources(&error));
        assert!(!error.retryable);
        assert!(error.message.contains("preserved for explicit recovery"));
    }
}
