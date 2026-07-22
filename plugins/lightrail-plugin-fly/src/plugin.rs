use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    future::Future,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use futures::future::try_join_all;
use lightrail_plugin_protocol::{
    ActionJournalEntry, ApplyRequest, ApplyResult, CancelRequest, CancelResult, Capability,
    DestroyRequest, DestroyResult, Diagnostic, DiagnosticSeverity, Endpoint, ErrorKind, EventSink,
    ExecutableMetadata, InspectRequest, InspectResult, JournalStatus, LockAcquireRequest,
    LockAcquireResult, LockReleaseRequest, LockReleaseResult, LockScope, LogsRequest, LogsResult,
    PlanRequest, PlanResult, PlannedAction, PluginError, PluginEvent, PluginHandler,
    PluginManifest, PluginResult, ProtocolCompatibility, ResourceStatus, RollbackMetadata,
    SecretRequirement, SecretValue, ValidateRequest, ValidateResult,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

use crate::{
    api::{ApiClient, App, FlyApi, Machine, PublicResponse, Volume},
    command::{Cancellation, DockerSession, SharedCancellation},
    model::{
        BRANCH_KEY, ContextMetadata, DesiredState, ENVIRONMENT_KEY, EXPIRES_KEY, Identity,
        MANAGED_KEY, PORT_KEY, PROFILE_KEY, PROJECT_KEY, PUBLIC_APP_KEY, REVISION_KEY, ROLE_KEY,
        SERVICE_KEY, Settings, Workload, lock_app_name, network_name, network_prefix, plan_id,
        project_app_marker, resolve_app_environment, revision, safe_label, unix_now, validation,
        volume_name, workloads,
    },
};

pub const PLUGIN_ID: &str = "dev.lightrail.fly";
const SELECTED_DESTROY_FEATURE: &str = "dev.lightrail.selected-destroy.v1";
const PLACEHOLDER_IMAGE: &str = "registry-1.docker.io/library/busybox:1.36.1";
const LOCK_MARGIN_SECONDS: u64 = 90;
const PROVIDER_CALL_ALLOWANCE_SECONDS: u64 = 90;
const HEALTH_PATH_KEY: &str = "lightrail-health-path";
const HEALTH_STATUS_KEY: &str = "lightrail-health-status";

pub struct FlyPlugin {
    api: Arc<dyn FlyApi>,
    contexts: RwLock<HashMap<String, CachedContext>>,
    expiries: Mutex<HashMap<String, u64>>,
    locks: Mutex<HashMap<String, HeldLock>>,
    lease_checks: Mutex<()>,
    cancellations: Mutex<HashMap<String, SharedCancellation>>,
    provisional_apps: Mutex<HashMap<String, Vec<ProvisionalApp>>>,
    exposure_inverses: Mutex<HashMap<String, Vec<ExposureInverse>>>,
    expiry_inverses: Mutex<HashMap<String, Vec<ExpiryInverse>>>,
    runtime_versions: Mutex<HashMap<String, HashMap<String, String>>>,
}

impl Default for FlyPlugin {
    fn default() -> Self {
        Self {
            api: Arc::new(ApiClient::default()),
            contexts: RwLock::new(HashMap::new()),
            expiries: Mutex::new(HashMap::new()),
            locks: Mutex::new(HashMap::new()),
            lease_checks: Mutex::new(()),
            cancellations: Mutex::new(HashMap::new()),
            provisional_apps: Mutex::new(HashMap::new()),
            exposure_inverses: Mutex::new(HashMap::new()),
            expiry_inverses: Mutex::new(HashMap::new()),
            runtime_versions: Mutex::new(HashMap::new()),
        }
    }
}

#[derive(Clone)]
struct CachedContext {
    settings: Settings,
    identity: Identity,
    token: SecretValue,
}

#[derive(Clone)]
struct HeldLock {
    project_id: String,
    scope_id: String,
    operation_id: String,
    release_token: String,
    app: String,
    machine: String,
    nonce: String,
    expires_at_unix: u64,
}

#[derive(Clone)]
struct ProvisionalApp {
    project_id: String,
    environment_id: String,
    app: String,
    app_id: Option<String>,
    network: String,
    machine_ids: BTreeSet<String>,
    volume_ids: BTreeSet<String>,
}

#[derive(Clone)]
struct ExposureInverse {
    project_id: String,
    environment_id: String,
    app: String,
    service: String,
    public_app: String,
    machine_id: String,
    instance_id: String,
    address: Option<String>,
}

#[derive(Clone)]
struct ExpiryInverse {
    project_id: String,
    environment_id: String,
    app: String,
    service: String,
    machine_id: String,
    instance_id: String,
    prior_expiry: Option<String>,
    committed_expiry: String,
}

#[derive(Clone, Debug)]
struct OwnedApp {
    app: App,
    machines: Vec<Machine>,
    volumes: Vec<Volume>,
    environment_id: String,
    profile: String,
    branch: String,
    service: String,
}

#[derive(Clone, Debug)]
struct OrphanApp {
    app: App,
    volumes: Vec<Volume>,
    environment_id: Option<String>,
}

struct Discovery {
    owned: Vec<OwnedApp>,
    orphans: Vec<OrphanApp>,
    observed: HashMap<String, App>,
    conflicts: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CapturedApp {
    app: String,
    app_id: Option<String>,
    network: String,
    environment_id: Option<String>,
    service: Option<String>,
    machine_ids: BTreeSet<String>,
    volume_ids: BTreeSet<String>,
    orphan: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PlanData {
    schema: u32,
    capability: Capability,
    operation: String,
    all: bool,
    desired: DesiredState,
    revision: String,
    expires_at_unix: u64,
    network: String,
    #[serde(default)]
    selection: Option<BTreeSet<String>>,
}

#[async_trait]
impl PluginHandler for FlyPlugin {
    fn manifest(&self) -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID.to_owned(),
            name: "Lightrail Fly.io".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            protocol: ProtocolCompatibility::default(),
            executable: ExecutableMetadata {
                command: Some("lightrail-plugin-fly".to_owned()),
                homepage: Some("https://github.com/gelleson/lightrail".to_owned()),
                ..ExecutableMetadata::default()
            },
            capabilities: vec![
                Capability::Builder,
                Capability::Target,
                Capability::Runtime,
                Capability::Exposure,
                Capability::Dns,
                Capability::OperationLock,
            ],
            features: vec![SELECTED_DESTROY_FEATURE.to_owned()],
            required_secrets: vec![SecretRequirement {
                name: "fly-token".to_owned(),
                description: Some(
                    "Fly.io API and registry token; never written to argv or plans".to_owned(),
                ),
                required: true,
            }],
            config_schema: config_schema(),
            config_ui_hints: json!({
                "/token/secret": { "control": "secret-reference" },
                "/organization": { "label": "Fly organization slug" },
                "/region": { "label": "Fly region (required for volumes)" }
            }),
        }
    }

    async fn validate(
        &self,
        request: ValidateRequest,
        _events: &EventSink,
    ) -> PluginResult<ValidateResult> {
        match self.validate_inner(&request).await {
            Ok(settings) => Ok(ValidateResult {
                valid: true,
                diagnostics: Vec::new(),
                normalized_config: Some(serde_json::to_value(settings).map_err(internal_json)?),
            }),
            Err(error) => Ok(ValidateResult {
                valid: false,
                diagnostics: vec![diagnostic(error)],
                normalized_config: None,
            }),
        }
    }

    async fn inspect(
        &self,
        request: InspectRequest,
        _events: &EventSink,
    ) -> PluginResult<InspectResult> {
        self.inspect_inner(&request.context).await
    }

    async fn plan(&self, request: PlanRequest, _events: &EventSink) -> PluginResult<PlanResult> {
        self.plan_inner(request).await
    }

    async fn apply(&self, request: ApplyRequest, events: &EventSink) -> PluginResult<ApplyResult> {
        let data = decode_plan(&request.plan)?;
        let settings = Settings::from_context(&request.context)?;
        let desired = DesiredState::parse(
            serde_json::to_value(&data.desired).map_err(internal_json)?,
            &request.context,
        )?;
        let metadata = ContextMetadata::from_context(&request.context)?;
        if metadata.capability()? != data.capability {
            return Err(stale_plan(
                "the plan capability does not match the operation",
            ));
        }
        self.remember_context(&request.context, Some(&desired))
            .await?;
        verify_plan(&request.plan)?;
        self.ensure_lock(
            &request.context,
            settings
                .command_timeout_seconds
                .saturating_add(LOCK_MARGIN_SECONDS),
        )
        .await?;
        let cancellation = self.cancellation(&request.context.operation_id).await;
        cancellation.check()?;

        let mut journal = request.journal;
        match data.capability {
            Capability::Target => {
                self.apply_target(
                    &request.context,
                    &settings,
                    &data,
                    &request.plan.actions,
                    &mut journal,
                    events,
                    &cancellation,
                )
                .await?;
            }
            Capability::Builder => {
                self.apply_builder(
                    &request.context,
                    &settings,
                    &data,
                    &request.plan.actions,
                    &mut journal,
                    events,
                    &cancellation,
                )
                .await?;
            }
            Capability::Runtime => {
                self.apply_runtime(
                    &request.context,
                    &settings,
                    &data,
                    &request.plan.actions,
                    &mut journal,
                    events,
                    &cancellation,
                )
                .await?;
            }
            Capability::Exposure => {
                self.apply_exposure(
                    &request.context,
                    &settings,
                    &data,
                    &request.plan.actions,
                    &mut journal,
                    events,
                    &cancellation,
                )
                .await?;
            }
            Capability::Dns => {
                self.apply_expiry(
                    &request.context,
                    &settings,
                    &data,
                    &request.plan.actions,
                    &mut journal,
                    events,
                    &cancellation,
                )
                .await?;
            }
            _ => return Err(unsupported_capability(&data.capability)),
        }
        self.ensure_lock(&request.context, LOCK_MARGIN_SECONDS)
            .await?;
        let inspected = self.inspect_inner(&request.context).await?;
        Ok(ApplyResult {
            revision: (!data.revision.is_empty()).then_some(data.revision),
            state: inspected.state,
            journal,
        })
    }

    #[allow(clippy::too_many_lines)]
    async fn destroy(
        &self,
        request: DestroyRequest,
        events: &EventSink,
    ) -> PluginResult<DestroyResult> {
        let metadata = ContextMetadata::from_context(&request.context)?;
        let capability = metadata.capability()?;
        if capability == Capability::Exposure
            && matches!(metadata.operation.as_str(), "rollback" | "rollback_cleanup")
        {
            if request.force {
                return Err(PluginError::permanent(
                    ErrorKind::Unsupported,
                    "fly_force_destroy_unsupported",
                    "Fly exposure rollback requires the authoritative project lock",
                ));
            }
            let cached = self.remember_context(&request.context, None).await?;
            self.ensure_lock(&request.context, LOCK_MARGIN_SECONDS)
                .await?;
            return self.rollback_exposure(request, &cached, events).await;
        }
        if capability == Capability::Dns
            && matches!(metadata.operation.as_str(), "rollback" | "rollback_cleanup")
        {
            if request.force {
                return Err(PluginError::permanent(
                    ErrorKind::Unsupported,
                    "fly_force_destroy_unsupported",
                    "Fly expiry rollback requires the authoritative project lock",
                ));
            }
            let cached = self.remember_context(&request.context, None).await?;
            self.ensure_lock(&request.context, LOCK_MARGIN_SECONDS)
                .await?;
            return self.rollback_expiry(request, &cached, events).await;
        }
        if capability != Capability::Target {
            return Ok(DestroyResult {
                destroyed: true,
                journal: request.journal,
                remaining: Vec::new(),
            });
        }
        if request.force {
            return Err(PluginError::permanent(
                ErrorKind::Unsupported,
                "fly_force_destroy_unsupported",
                "Fly environment deletion always requires the authoritative project lock",
            ));
        }
        let cached = self.remember_context(&request.context, None).await?;
        let selected = metadata.validate_selection()?.cloned();
        let captured = captured_apps_from_state(request.current.as_ref(), &cached)?;
        let mut captured = select_captured(
            captured,
            &cached.identity.environment_id,
            metadata.all,
            selected.as_ref(),
        );
        let provisional = self
            .provisional_apps
            .lock()
            .await
            .get(&request.context.operation_id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|app| {
                app.project_id == cached.identity.project_id
                    && (metadata.all
                        || selected
                            .as_ref()
                            .is_some_and(|selection| selection.contains(&app.environment_id))
                        || app.environment_id == cached.identity.environment_id)
            })
            .map(CapturedApp::from_provisional)
            .collect::<Vec<_>>();
        merge_captured(&mut captured, provisional)?;
        self.ensure_lock(&request.context, LOCK_MARGIN_SECONDS)
            .await?;
        let discovery = self.discover_locked(&cached, &request.context).await?;
        require_clean_discovery(&discovery)?;
        let live = select_captured(
            captured_apps_from_discovery(&discovery),
            &cached.identity.environment_id,
            metadata.all,
            selected.as_ref(),
        );
        assert_destroy_continuity(&captured, &live)?;
        let cancellation = self.cancellation(&request.context.operation_id).await;
        let mut journal = request.journal;
        let mut remaining = Vec::new();
        for app in captured {
            cancellation.check()?;
            let action_id = format!("target.delete.{}", app.app);
            journal_event(
                events,
                &request.context.operation_id,
                &mut journal,
                &action_id,
                JournalStatus::Started,
                "Deleting owned Fly App",
            )
            .await?;
            match self
                .delete_captured_app(&request.context, &cached, &app)
                .await
            {
                Ok(()) => {
                    self.forget_provisional(&request.context.operation_id, &app.app)
                        .await;
                    journal_event(
                        events,
                        &request.context.operation_id,
                        &mut journal,
                        &action_id,
                        JournalStatus::Succeeded,
                        "Deleted owned Fly App",
                    )
                    .await?;
                }
                Err(error) => {
                    remaining.push(app.app.clone());
                    journal_event(
                        events,
                        &request.context.operation_id,
                        &mut journal,
                        &action_id,
                        JournalStatus::Failed,
                        &error.message,
                    )
                    .await?;
                }
            }
        }
        Ok(DestroyResult {
            destroyed: remaining.is_empty(),
            journal,
            remaining,
        })
    }

    async fn cancel(
        &self,
        request: CancelRequest,
        _events: &EventSink,
    ) -> PluginResult<CancelResult> {
        let cancellation = self
            .cancellations
            .lock()
            .await
            .get(&request.operation_id)
            .cloned();
        if let Some(cancellation) = cancellation {
            cancellation.cancel();
            Ok(CancelResult { acknowledged: true })
        } else {
            Ok(CancelResult {
                acknowledged: false,
            })
        }
    }

    async fn lock_acquire(
        &self,
        request: LockAcquireRequest,
        _events: &EventSink,
    ) -> PluginResult<LockAcquireResult> {
        self.acquire_lock(request).await
    }

    async fn lock_release(
        &self,
        request: LockReleaseRequest,
        _events: &EventSink,
    ) -> PluginResult<LockReleaseResult> {
        self.release_lock(request).await
    }

    async fn logs(&self, _request: LogsRequest, _events: &EventSink) -> PluginResult<LogsResult> {
        Err(PluginError::permanent(
            ErrorKind::Unsupported,
            "fly_logs_unsupported",
            "Fly log retrieval is deferred until a stable provider API is available",
        ))
    }
}

impl FlyPlugin {
    async fn validate_inner(&self, request: &ValidateRequest) -> PluginResult<Settings> {
        let settings = Settings::from_context(&request.context)?;
        let metadata = ContextMetadata::from_context(&request.context)?;
        require_capability(&metadata.capability()?)?;
        metadata.validate_selection()?;
        let desired = DesiredState::parse(request.desired.clone(), &request.context)?;
        let cached = self
            .remember_context(&request.context, Some(&desired))
            .await?;
        if desired.destroy {
            return Ok(settings);
        }
        let compose = read_compose(&desired).await?;
        let revision = revision(&desired, &compose, &settings, &request.context.operation_id)?;
        let workloads = workloads(&desired, &settings, &compose, &revision)?;
        validate_workloads(&desired, &settings, &workloads, &request.context)?;
        // Keep the context cache warm for the subsequent authoritative lock
        // acquisition, but do not contact Fly during validation.
        let _ = cached;
        Ok(settings)
    }

    async fn remember_context(
        &self,
        context: &lightrail_plugin_protocol::OperationContext,
        desired: Option<&DesiredState>,
    ) -> PluginResult<CachedContext> {
        let settings = Settings::from_context(context)?;
        let identity = Identity::from_context(context, desired)?;
        let token = context
            .secrets
            .get(&settings.token.secret)
            .cloned()
            .ok_or_else(|| {
                PluginError::permanent(
                    ErrorKind::Authentication,
                    "fly_token_required",
                    "the `fly-token` secret has not been resolved",
                )
            })?;
        if token.expose_secret().is_empty() {
            return Err(PluginError::permanent(
                ErrorKind::Authentication,
                "fly_token_empty",
                "the resolved `fly-token` secret is empty",
            ));
        }
        let cached = CachedContext {
            settings,
            identity,
            token,
        };
        self.contexts
            .write()
            .await
            .insert(context.environment_id.clone(), cached.clone());
        Ok(cached)
    }

    async fn cached_context(&self, environment_id: &str) -> PluginResult<CachedContext> {
        self.contexts
            .read()
            .await
            .get(environment_id)
            .cloned()
            .ok_or_else(|| {
                PluginError::permanent(
                    ErrorKind::NotFound,
                    "fly_lock_context_required",
                    "inspect the Fly target in this plugin session before acquiring its lock",
                )
            })
    }

    async fn operation_expiry(&self, operation_id: &str, settings: &Settings) -> u64 {
        let mut expiries = self.expiries.lock().await;
        *expiries
            .entry(operation_id.to_owned())
            .or_insert_with(|| unix_now().saturating_add(settings.ttl_hours.saturating_mul(3_600)))
    }

    async fn cancellation(&self, operation_id: &str) -> SharedCancellation {
        let mut cancellations = self.cancellations.lock().await;
        cancellations
            .entry(operation_id.to_owned())
            .or_insert_with(|| Arc::new(Cancellation::default()))
            .clone()
    }

    async fn discover(&self, cached: &CachedContext) -> PluginResult<Discovery> {
        self.discover_inner(cached).await
    }

    async fn discover_locked(
        &self,
        cached: &CachedContext,
        context: &lightrail_plugin_protocol::OperationContext,
    ) -> PluginResult<Discovery> {
        self.ensure_lock(
            context,
            cached
                .settings
                .command_timeout_seconds
                .saturating_add(LOCK_MARGIN_SECONDS),
        )
        .await?;
        let cancellation = self.cancellation(&context.operation_id).await;
        tokio::select! {
            result = tokio::time::timeout(
                Duration::from_secs(cached.settings.command_timeout_seconds),
                self.discover_inner(cached),
            ) => {
                result.unwrap_or_else(|_| {
                    Err(PluginError::retryable(
                        ErrorKind::Timeout,
                        "fly_discovery_timeout",
                        "bounded Fly ownership discovery timed out while the project lease was held",
                    ))
                })
            },
            () = cancellation.cancelled() => Err(PluginError::permanent(
                ErrorKind::Cancelled,
                "operation_cancelled",
                "the Fly.io operation was cancelled",
            )),
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn discover_inner(&self, cached: &CachedContext) -> PluginResult<Discovery> {
        let token = cached.token.expose_secret();
        let applications = self
            .api
            .list_apps(token, &cached.settings.organization)
            .await?;
        let marker = project_app_marker(&cached.identity.project_id, &cached.settings);
        let owned_network_prefix = network_prefix(&cached.identity.project_id, &cached.settings);
        let current_network = network_name(
            &cached.identity.project_id,
            &cached.identity.environment_id,
            &cached.settings,
        );
        let mut owned = Vec::new();
        let mut orphans = Vec::new();
        let mut observed = HashMap::new();
        let mut conflicts = Vec::new();
        for app in applications {
            if !app.name.contains(&marker) {
                continue;
            }
            if app.id.is_empty() {
                conflicts.push(format!(
                    "Fly App `{}` has the project name marker but no immutable App ID",
                    app.name
                ));
                continue;
            }
            observed.insert(app.name.clone(), app.clone());
            let machines = self.api.list_machines(token, &app.name).await?;
            let volumes = self.api.list_volumes(token, &app.name).await?;
            if machines.is_empty() {
                if app
                    .network
                    .as_deref()
                    .is_some_and(|network| network.starts_with(&owned_network_prefix))
                {
                    let environment_id = (app.network.as_deref() == Some(current_network.as_str()))
                        .then(|| cached.identity.environment_id.clone());
                    orphans.push(OrphanApp {
                        app,
                        volumes,
                        environment_id,
                    });
                } else {
                    conflicts.push(format!(
                        "zero-Machine Fly App `{}` has the project name marker but not its deterministic project network",
                        app.name
                    ));
                }
                continue;
            }
            let exact = machines
                .iter()
                .filter(|machine| {
                    machine.metadata().get(MANAGED_KEY).map(String::as_str) == Some("true")
                        && machine.metadata().get(PROJECT_KEY).map(String::as_str)
                            == Some(cached.identity.project_id.as_str())
                })
                .count();
            if exact == 0 {
                conflicts.push(format!(
                    "Fly App `{}` has the project name marker but no exactly owned Machine",
                    app.name
                ));
                continue;
            }
            if exact != machines.len() {
                conflicts.push(format!(
                    "Fly App `{}` mixes Lightrail-owned and foreign Machines",
                    app.name
                ));
                continue;
            }
            let environment_ids = metadata_values(&machines, ENVIRONMENT_KEY);
            let profiles = metadata_values(&machines, PROFILE_KEY);
            let branches = metadata_values(&machines, BRANCH_KEY);
            let services = metadata_values(&machines, SERVICE_KEY);
            if environment_ids.len() != 1
                || profiles.len() != 1
                || branches.len() != 1
                || services.len() != 1
            {
                conflicts.push(format!(
                    "Fly App `{}` has inconsistent immutable ownership metadata",
                    app.name
                ));
                continue;
            }
            let environment_id = first(&environment_ids).to_owned();
            let profile = first(&profiles).to_owned();
            let branch = first(&branches).to_owned();
            let service = first(&services).to_owned();
            let expected_network = network_name(
                &cached.identity.project_id,
                &environment_id,
                &cached.settings,
            );
            if app.network.as_deref() != Some(expected_network.as_str()) {
                conflicts.push(format!(
                    "Fly App `{}` has network `{}`, expected custom network `{expected_network}`",
                    app.name,
                    app.network.as_deref().unwrap_or("<missing>")
                ));
                continue;
            }
            owned.push(OwnedApp {
                app,
                machines,
                volumes,
                environment_id,
                profile,
                branch,
                service,
            });
        }
        owned.sort_by(|left, right| left.app.name.cmp(&right.app.name));
        orphans.sort_by(|left, right| left.app.name.cmp(&right.app.name));
        Ok(Discovery {
            owned,
            orphans,
            observed,
            conflicts,
        })
    }

    async fn inspect_inner(
        &self,
        context: &lightrail_plugin_protocol::OperationContext,
    ) -> PluginResult<InspectResult> {
        let cached = self.remember_context(context, None).await?;
        let metadata = ContextMetadata::from_context(context)?;
        let capability = metadata.capability()?;
        require_capability(&capability)?;
        let lock_held = self
            .locks
            .lock()
            .await
            .get(&cached.identity.project_id)
            .is_some_and(|held| held.operation_id == context.operation_id);
        let discovery = if lock_held {
            self.discover_locked(&cached, context).await?
        } else {
            self.discover(&cached).await?
        };
        let aggregate = metadata.all || metadata.operation == "prune";
        let owned = if aggregate {
            discovery.owned.clone()
        } else {
            discovery
                .owned
                .iter()
                .filter(|owned| owned.environment_id == context.environment_id)
                .cloned()
                .collect()
        };
        let orphans = if aggregate {
            discovery.orphans.clone()
        } else {
            discovery
                .orphans
                .iter()
                .filter(|orphan| {
                    orphan.environment_id.as_deref() == Some(context.environment_id.as_str())
                })
                .cloned()
                .collect()
        };
        self.inspection_from_discovery(
            &cached,
            &capability,
            owned,
            orphans,
            discovery.conflicts,
            &context.operation_id,
        )
        .await
    }

    #[allow(clippy::too_many_lines)]
    async fn inspection_from_discovery(
        &self,
        cached: &CachedContext,
        capability: &Capability,
        owned: Vec<OwnedApp>,
        orphans: Vec<OrphanApp>,
        conflicts: Vec<String>,
        operation_id: &str,
    ) -> PluginResult<InspectResult> {
        let mut diagnostics = conflicts
            .iter()
            .map(|message| Diagnostic {
                severity: DiagnosticSeverity::Error,
                code: "fly_ownership_conflict".to_owned(),
                message: message.clone(),
                path: None,
                help: Some(
                    "Do not adopt or delete the App; resolve its mixed ownership in Fly.io."
                        .to_owned(),
                ),
            })
            .collect::<Vec<_>>();
        let mut endpoints = Vec::new();
        let mut app_records = Vec::new();
        let mut runtime_revisions = BTreeSet::new();
        let mut runtime_environments = BTreeSet::new();
        let mut runtime_machine_count = 0_usize;
        let mut status = if owned.is_empty() {
            ResourceStatus::Absent
        } else {
            ResourceStatus::Ready
        };
        if !orphans.is_empty() {
            status = ResourceStatus::Degraded;
        }
        let probe_public = matches!(
            capability,
            Capability::Runtime | Capability::Exposure | Capability::Dns
        );
        let mut public_probe_specs = Vec::new();
        if probe_public {
            for owned_app in &owned {
                let machine = owned_app.machines.first().ok_or_else(|| {
                    PluginError::permanent(
                        ErrorKind::Internal,
                        "owned_app_without_machine",
                        "an owned Fly App has no ownership-bearing Machine",
                    )
                })?;
                if metadata(machine, PUBLIC_APP_KEY).is_some() {
                    public_probe_specs.push((
                        owned_app.app.name.clone(),
                        metadata(machine, HEALTH_PATH_KEY).unwrap_or("/").to_owned(),
                        metadata(machine, HEALTH_STATUS_KEY)
                            .and_then(|value| value.parse::<u16>().ok()),
                    ));
                }
            }
        }
        let cancellation = self.cancellation(operation_id).await;
        let public_probes = wait_all_inspection_probes(
            public_probe_specs
                .into_iter()
                .map(|(app_name, path, status)| {
                    let api = self.api.as_ref();
                    let token = cached.token.expose_secret();
                    async move {
                        let shared_ip = api.shared_ipv4(token, &app_name).await?;
                        let ready = if shared_ip.is_some() {
                            public_ready(api, &app_name, &path, status).await?
                        } else {
                            false
                        };
                        Ok(PublicInspection {
                            app_name,
                            shared_ip,
                            ready,
                        })
                    }
                }),
            Duration::from_secs(cached.settings.readiness_timeout_seconds),
            &cancellation,
        )
        .await?
        .into_iter()
        .map(|probe| (probe.app_name.clone(), probe))
        .collect::<BTreeMap<_, _>>();
        let mut environments: BTreeMap<String, EnvironmentSummary> = BTreeMap::new();
        let mut environment_revisions: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
        let mut environments_missing_revision = BTreeSet::new();
        let mut environment_expiries: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
        for owned_app in &owned {
            let machine = owned_app.machines.first().ok_or_else(|| {
                PluginError::permanent(
                    ErrorKind::Internal,
                    "owned_app_without_machine",
                    "an owned Fly App has no ownership-bearing Machine",
                )
            })?;
            let mut app_status = ResourceStatus::Ready;
            if owned_app.machines.len() != 1 {
                status = ResourceStatus::Degraded;
                app_status = ResourceStatus::Degraded;
                diagnostics.push(Diagnostic {
                    severity: DiagnosticSeverity::Error,
                    code: "fly_machine_count_mismatch".to_owned(),
                    message: format!(
                        "Fly App `{}` has {} owned Machines; exactly one is supported",
                        owned_app.app.name,
                        owned_app.machines.len()
                    ),
                    path: None,
                    help: None,
                });
            }
            let role = metadata(machine, ROLE_KEY).unwrap_or_default();
            let public_app = metadata(machine, PUBLIC_APP_KEY);
            if role == "workload" {
                runtime_machine_count = runtime_machine_count.saturating_add(1);
                runtime_environments.insert(owned_app.environment_id.as_str());
                if let Some(revision) = metadata(machine, REVISION_KEY) {
                    runtime_revisions.insert(revision);
                    environment_revisions
                        .entry(owned_app.environment_id.clone())
                        .or_default()
                        .insert(revision);
                } else {
                    environments_missing_revision.insert(owned_app.environment_id.clone());
                }
            }
            if role == "target-placeholder" {
                app_status = combine_status(app_status, ResourceStatus::Pending);
            } else if role != "workload" || !matches!(machine.state.as_str(), "started" | "stopped")
            {
                app_status = combine_status(app_status, ResourceStatus::Degraded);
            } else if machine.state == "stopped"
                && (public_app.is_none() || !cached.settings.auto_stop)
            {
                app_status = combine_status(app_status, ResourceStatus::Degraded);
                diagnostics.push(Diagnostic {
                    severity: DiagnosticSeverity::Error,
                    code: if public_app.is_none() {
                        "fly_private_machine_not_running".to_owned()
                    } else {
                        "fly_public_machine_unexpectedly_stopped".to_owned()
                    },
                    message: format!(
                        "Fly App `{}` has a stopped Machine without an enabled Proxy autostart contract",
                        owned_app.app.name,
                    ),
                    path: None,
                    help: None,
                });
            }
            let public_probe = public_probes.get(&owned_app.app.name);
            let shared_ip = public_probe.and_then(|probe| probe.shared_ip.clone());
            let mut environment_endpoint = None;
            if probe_public {
                if let Some(public_app) = public_app {
                    if shared_ip.is_some() {
                        let endpoint = Endpoint {
                            app: public_app.to_owned(),
                            url: format!("https://{}.fly.dev", owned_app.app.name),
                        };
                        endpoints.push(endpoint.clone());
                        environment_endpoint = Some(endpoint);
                        if public_probe.is_none_or(|probe| !probe.ready) {
                            app_status = combine_status(app_status, ResourceStatus::Pending);
                            diagnostics.push(Diagnostic {
                            severity: DiagnosticSeverity::Warning,
                            code: "fly_https_not_ready".to_owned(),
                            message: format!(
                                "trusted HTTPS or HTTP-to-HTTPS redirect is not ready for Fly App `{}`",
                                owned_app.app.name
                            ),
                            path: None,
                            help: None,
                        });
                        }
                    } else {
                        app_status = combine_status(app_status, ResourceStatus::Pending);
                    }
                }
            }
            let expiry = metadata(machine, EXPIRES_KEY).and_then(|value| value.parse::<u64>().ok());
            if let Some(expiry) = expiry {
                environment_expiries
                    .entry(owned_app.environment_id.clone())
                    .or_default()
                    .insert(expiry);
            }
            let summary = environments
                .entry(owned_app.environment_id.clone())
                .or_insert_with(|| EnvironmentSummary::new(cached, owned_app, expiry));
            if let Some(endpoint) = environment_endpoint {
                summary.endpoints.push(endpoint);
            }
            summary.status = combine_status(summary.status, app_status);
            if summary.profile != owned_app.profile || summary.branch != owned_app.branch {
                summary.mismatch = true;
            }
            if let Some(expiry) = expiry {
                // A partially refreshed multi-App environment must never be
                // pruned based on its stale member. The newest expiry wins.
                summary.expires_at_unix = Some(
                    summary
                        .expires_at_unix
                        .map_or(expiry, |old| old.max(expiry)),
                );
            } else {
                summary.missing_expiry = true;
            }
            status = combine_status(status, app_status);
            app_records.push(json!({
                "app": owned_app.app.name,
                "app_id": owned_app.app.id,
                "project_id": cached.identity.project_id,
                "environment_id": owned_app.environment_id,
                "service": owned_app.service,
                "machine_id": machine.id,
                "machine_ids": owned_app
                    .machines
                    .iter()
                    .map(|machine| machine.id.as_str())
                    .collect::<Vec<_>>(),
                "volume_ids": owned_app
                    .volumes
                    .iter()
                    .map(|volume| volume.id.as_str())
                    .collect::<Vec<_>>(),
                "machine_state": machine.state,
                "region": machine.region,
                "role": role,
                "revision": metadata(machine, REVISION_KEY),
                "expires_at_unix": expiry,
                "network": owned_app.app.network,
                "internal_host": format!("{}.internal", owned_app.app.name),
                "public_hostname": public_app.map(|_| format!("{}.fly.dev", owned_app.app.name)),
                "shared_ipv4": shared_ip,
                "orphan": false,
            }));
        }
        for orphan in &orphans {
            diagnostics.push(Diagnostic {
                severity: DiagnosticSeverity::Error,
                code: "fly_incomplete_owned_app".to_owned(),
                message: format!(
                    "Fly App `{}` has the deterministic project identity but no Machine; it is recoverable with `lightrail down`",
                    orphan.app.name
                ),
                path: None,
                help: Some(
                    "Run the matching environment teardown, or `down --all`, before retrying up."
                        .to_owned(),
                ),
            });
            if let Some(environment_id) = &orphan.environment_id {
                environments
                    .entry(environment_id.clone())
                    .or_insert_with(|| EnvironmentSummary {
                        project_id: cached.identity.project_id.clone(),
                        environment_id: environment_id.clone(),
                        profile: cached.identity.profile.clone(),
                        branch: cached.identity.branch.clone(),
                        status: ResourceStatus::Degraded,
                        endpoints: Vec::new(),
                        expires_at_unix: None,
                        mismatch: false,
                        missing_expiry: true,
                    })
                    .status = ResourceStatus::Degraded;
            }
            app_records.push(json!({
                "app": orphan.app.name,
                "app_id": orphan.app.id,
                "project_id": cached.identity.project_id,
                "environment_id": orphan.environment_id,
                "service": Value::Null,
                "machine_ids": [],
                "volume_ids": orphan
                    .volumes
                    .iter()
                    .map(|volume| volume.id.as_str())
                    .collect::<Vec<_>>(),
                "network": orphan.app.network,
                "orphan": true,
            }));
        }
        for summary in environments.values_mut() {
            if environment_expiries
                .get(&summary.environment_id)
                .is_some_and(|expiries| expiries.len() != 1)
            {
                summary.missing_expiry = true;
                summary.status = ResourceStatus::Degraded;
                status = ResourceStatus::Degraded;
                diagnostics.push(Diagnostic {
                    severity: DiagnosticSeverity::Error,
                    code: "fly_environment_expiry_mismatch".to_owned(),
                    message: format!(
                        "environment `{}` has mixed member expiry metadata and is not prune-eligible",
                        summary.environment_id
                    ),
                    path: None,
                    help: None,
                });
            }
            if environment_revisions
                .get(&summary.environment_id)
                .is_some_and(|revisions| revisions.len() != 1)
                || environments_missing_revision.contains(&summary.environment_id)
            {
                summary.status = ResourceStatus::Degraded;
                status = ResourceStatus::Degraded;
                diagnostics.push(Diagnostic {
                    severity: DiagnosticSeverity::Error,
                    code: "fly_environment_revision_mismatch".to_owned(),
                    message: format!(
                        "environment `{}` has missing or mixed workload revisions",
                        summary.environment_id
                    ),
                    path: None,
                    help: None,
                });
            }
            if summary.mismatch {
                summary.status = ResourceStatus::Degraded;
                status = ResourceStatus::Degraded;
                diagnostics.push(Diagnostic {
                    severity: DiagnosticSeverity::Error,
                    code: "fly_environment_metadata_mismatch".to_owned(),
                    message: format!(
                        "environment `{}` has inconsistent profile or branch metadata",
                        summary.environment_id
                    ),
                    path: None,
                    help: None,
                });
            }
            if summary.missing_expiry {
                summary.status = ResourceStatus::Degraded;
                status = ResourceStatus::Degraded;
                diagnostics.push(Diagnostic {
                    severity: DiagnosticSeverity::Error,
                    code: "fly_environment_expiry_missing".to_owned(),
                    message: format!(
                        "environment `{}` has an App without valid expiry metadata; it is not prune-eligible",
                        summary.environment_id
                    ),
                    path: None,
                    help: None,
                });
            }
            summary.endpoints.sort_by(|left, right| {
                left.app
                    .cmp(&right.app)
                    .then_with(|| left.url.cmp(&right.url))
            });
            summary.endpoints.dedup();
        }
        if !conflicts.is_empty() {
            status = ResourceStatus::Degraded;
        }
        endpoints.sort_by(|left, right| {
            left.app
                .cmp(&right.app)
                .then_with(|| left.url.cmp(&right.url))
        });
        endpoints.dedup();
        app_records.sort_by(|left, right| {
            left.get("app")
                .and_then(Value::as_str)
                .cmp(&right.get("app").and_then(Value::as_str))
        });
        let consistent_revision = (runtime_machine_count == owned.len()
            && runtime_environments.len() == 1
            && runtime_revisions.len() == 1)
            .then(|| runtime_revisions.first().copied())
            .flatten();
        let mut state = serde_json::Map::from_iter([
            ("provider".to_owned(), Value::String("fly".to_owned())),
            (
                "organization".to_owned(),
                Value::String(cached.settings.organization.clone()),
            ),
            (
                "project_id".to_owned(),
                Value::String(cached.identity.project_id.clone()),
            ),
            ("environment_contract".to_owned(), Value::from(1)),
            ("apps".to_owned(), Value::Array(app_records)),
            (
                "environments".to_owned(),
                Value::Array(
                    environments
                        .into_values()
                        .map(EnvironmentSummary::into_value)
                        .collect(),
                ),
            ),
        ]);
        if let Some(revision) = consistent_revision {
            state.insert("revision".to_owned(), Value::String(revision.to_owned()));
        }
        Ok(InspectResult {
            status,
            endpoints,
            state: Value::Object(state),
            diagnostics,
        })
    }

    async fn plan_inner(&self, request: PlanRequest) -> PluginResult<PlanResult> {
        let metadata = ContextMetadata::from_context(&request.context)?;
        let capability = metadata.capability()?;
        require_capability(&capability)?;
        let selection = metadata.validate_selection()?.cloned();
        let settings = Settings::from_context(&request.context)?;
        let desired = DesiredState::parse(request.desired, &request.context)?;
        let cached = self
            .remember_context(&request.context, Some(&desired))
            .await?;
        let expiry = self
            .operation_expiry(&request.context.operation_id, &settings)
            .await;
        let network = network_name(&desired.project.id, &desired.environment.id, &settings);
        let discovery = self.discover(&cached).await?;
        require_clean_discovery(&discovery)?;

        let (revision, workloads) = if desired.destroy {
            (String::new(), Vec::new())
        } else {
            let compose = read_compose(&desired).await?;
            let revision = revision(&desired, &compose, &settings, &request.context.operation_id)?;
            let workloads = workloads(&desired, &settings, &compose, &revision)?;
            validate_workloads(&desired, &settings, &workloads, &request.context)?;
            (revision, workloads)
        };
        let actions = if desired.destroy {
            plan_destroy_actions(
                &capability,
                &cached.identity.environment_id,
                metadata.all,
                selection.as_ref(),
                &discovery,
            )
        } else {
            self.plan_up_actions(
                &capability,
                &settings,
                &desired,
                &revision,
                expiry,
                &workloads,
                &discovery,
            )
            .await?
        };
        let data = PlanData {
            schema: 1,
            capability,
            operation: metadata.operation,
            all: metadata.all,
            desired,
            revision,
            expires_at_unix: expiry,
            network,
            selection,
        };
        let plan_metadata = serde_json::to_value(data).map_err(internal_json)?;
        let id = plan_id(&plan_metadata, &actions);
        Ok(PlanResult {
            plan_id: id,
            has_changes: !actions.is_empty(),
            actions,
            metadata: plan_metadata,
        })
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn plan_up_actions(
        &self,
        capability: &Capability,
        settings: &Settings,
        desired: &DesiredState,
        revision: &str,
        expiry: u64,
        workloads: &[Workload],
        discovery: &Discovery,
    ) -> PluginResult<Vec<PlannedAction>> {
        let expected_network = network_name(&desired.project.id, &desired.environment.id, settings);
        if discovery
            .orphans
            .iter()
            .any(|orphan| orphan.app.network.as_deref() == Some(expected_network.as_str()))
        {
            return Err(PluginError::permanent(
                ErrorKind::Conflict,
                "fly_incomplete_target_requires_down",
                "an incomplete Fly App remains on this environment network; run `lightrail down --yes` before retrying up",
            ));
        }
        let current = discovery
            .owned
            .iter()
            .filter(|owned| owned.environment_id == desired.environment.id)
            .map(|owned| (owned.app.name.as_str(), owned))
            .collect::<HashMap<_, _>>();
        let desired_apps = workloads
            .iter()
            .map(|workload| workload.app_name.as_str())
            .collect::<BTreeSet<_>>();
        let stale_apps = current
            .keys()
            .filter(|name| !desired_apps.contains(**name))
            .copied()
            .collect::<Vec<_>>();
        if !stale_apps.is_empty() {
            return Err(PluginError::permanent(
                ErrorKind::Conflict,
                "fly_removed_service_requires_down",
                format!(
                    "owned Fly App(s) no longer exist in Compose: {}; run `lightrail down --yes` before deploying the changed service set",
                    stale_apps.join(", ")
                ),
            ));
        }
        let added_apps = desired_apps
            .iter()
            .filter(|name| !current.contains_key(**name))
            .copied()
            .collect::<Vec<_>>();
        if !current.is_empty() && !added_apps.is_empty() {
            return Err(PluginError::permanent(
                ErrorKind::Conflict,
                "fly_added_service_requires_down",
                format!(
                    "new Fly App(s) would be added to an existing environment: {}; run `lightrail down --yes` before changing the service set",
                    added_apps.join(", ")
                ),
            ));
        }
        let token = self.context_token(&desired.environment.id).await?;
        let mut actions = Vec::new();
        for workload in workloads {
            let owned = current.get(workload.app_name.as_str()).copied();
            if owned.is_none() && discovery.observed.contains_key(&workload.app_name) {
                return Err(PluginError::permanent(
                    ErrorKind::Conflict,
                    "fly_app_name_occupied",
                    format!(
                        "Fly App name `{}` exists without exact Lightrail ownership",
                        workload.app_name
                    ),
                ));
            }
            if let Some(owned) = owned {
                if owned.service != workload.service {
                    return Err(PluginError::permanent(
                        ErrorKind::Conflict,
                        "fly_service_ownership_mismatch",
                        format!(
                            "Fly App `{}` is owned for service `{}`, expected `{}`",
                            workload.app_name, owned.service, workload.service
                        ),
                    ));
                }
                if owned.machines.len() != 1 {
                    return Err(PluginError::permanent(
                        ErrorKind::Conflict,
                        "fly_machine_count_mismatch",
                        format!(
                            "Fly App `{}` must contain exactly one owned Machine",
                            workload.app_name
                        ),
                    ));
                }
                let machine = &owned.machines[0];
                if let Some(region) = &settings.region {
                    if machine.region != *region {
                        return Err(PluginError::permanent(
                            ErrorKind::Conflict,
                            "fly_region_change_requires_down",
                            format!(
                                "Fly Machine for service `{}` is in region `{}`, but the profile selects `{region}`; run `lightrail down --yes` before changing regions",
                                workload.service, machine.region
                            ),
                        ));
                    }
                }
                if metadata(machine, PUBLIC_APP_KEY).is_some() && workload.public_app.is_none() {
                    return Err(PluginError::permanent(
                        ErrorKind::Conflict,
                        "fly_public_removal_requires_down",
                        format!(
                            "service `{}` still owns a Fly public address; run `lightrail down --yes` before making it private",
                            workload.service
                        ),
                    ));
                }
                let machine_mounts = &owned.machines[0].config.mounts;
                let topology_matches = match &workload.volume {
                    None => machine_mounts.is_empty(),
                    Some(expected) if machine_mounts.len() == 1 => {
                        let observed = &machine_mounts[0];
                        if observed.path == expected.path {
                            let volumes = self
                                .api
                                .list_volumes(token.expose_secret(), &workload.app_name)
                                .await?;
                            let expected_name = volume_name(
                                &desired.environment.id,
                                &workload.service,
                                &expected.name,
                            );
                            let matching = volumes
                                .iter()
                                .filter(|volume| {
                                    volume.id == observed.volume && volume.name == expected_name
                                })
                                .collect::<Vec<_>>();
                            if matching.len() == 1 {
                                validate_existing_volume_size(
                                    &workload.service,
                                    matching[0].size_gb,
                                    settings.volume_size_gb,
                                )?;
                            }
                            matching.len() == 1
                        } else {
                            false
                        }
                    }
                    Some(_) => false,
                };
                if !topology_matches {
                    return Err(PluginError::permanent(
                        ErrorKind::Conflict,
                        "fly_volume_topology_changed",
                        format!(
                            "named-volume topology changed for service `{}`; run `lightrail down --yes` before deploying it",
                            workload.service
                        ),
                    ));
                }
            }
            match capability {
                Capability::Target if owned.is_none() => {
                    actions.push(action(
                        format!("target.create.{}", workload.app_name),
                        "fly.target.create",
                        format!(
                            "Create Fly App and placeholder Machine for `{}`",
                            workload.service
                        ),
                        false,
                        workload,
                    ));
                }
                Capability::Builder if workload.build => {
                    let current_machine = owned.and_then(|owned| owned.machines.first());
                    let current_revision =
                        current_machine.and_then(|machine| metadata(machine, REVISION_KEY));
                    let current_role =
                        current_machine.and_then(|machine| metadata(machine, ROLE_KEY));
                    if desired.environment.dirty
                        || current_revision != Some(revision)
                        || current_role != Some("workload")
                    {
                        actions.push(action(
                            format!("builder.push.{}", workload.app_name),
                            "fly.builder.push",
                            format!(
                                "Build and push image for Compose service `{}`",
                                workload.service
                            ),
                            false,
                            workload,
                        ));
                    }
                }
                Capability::Runtime => {
                    if let Some(owned) = owned {
                        let machine = &owned.machines[0];
                        if metadata(machine, REVISION_KEY) == Some(revision)
                            && metadata(machine, ROLE_KEY) == Some("workload")
                        {
                            continue;
                        }
                        if machine.instance_id.is_empty() {
                            return Err(PluginError::retryable(
                                ErrorKind::Unavailable,
                                "fly_machine_version_missing",
                                format!(
                                    "Fly.io did not report the current Machine version for App `{}`",
                                    workload.app_name
                                ),
                            ));
                        }
                        let mut planned = action(
                            format!("runtime.reconcile.{}", workload.app_name),
                            "fly.runtime.reconcile",
                            format!("Reconcile Fly Machine for `{}`", workload.service),
                            false,
                            workload,
                        );
                        planned.metadata["machine_id"] = Value::String(machine.id.clone());
                        planned.metadata["instance_id"] =
                            Value::String(machine.instance_id.clone());
                        actions.push(planned);
                    } else {
                        let mut planned = action(
                            format!("runtime.reconcile.{}", workload.app_name),
                            "fly.runtime.reconcile",
                            format!(
                                "Launch Fly Machine for newly created service `{}`",
                                workload.service
                            ),
                            false,
                            workload,
                        );
                        planned.metadata["initial"] = Value::Bool(true);
                        actions.push(planned);
                    }
                }
                Capability::Exposure if workload.public_app.is_some() => {
                    let needs_address = if owned.is_some() {
                        self.api
                            .shared_ipv4(token.expose_secret(), &workload.app_name)
                            .await?
                            .is_none()
                    } else {
                        true
                    };
                    if needs_address {
                        let runtime_will_reconcile = owned.is_none_or(|owned| {
                            let machine = &owned.machines[0];
                            metadata(machine, REVISION_KEY) != Some(revision)
                                || metadata(machine, ROLE_KEY) != Some("workload")
                        });
                        let mut planned = action(
                            format!("exposure.allocate-ip.{}", workload.app_name),
                            "fly.exposure.allocate_ip",
                            format!(
                                "Allocate Fly shared IPv4 for public app `{}`",
                                workload.public_app.as_deref().unwrap_or_default()
                            ),
                            false,
                            workload,
                        );
                        planned.metadata["initial"] = Value::Bool(owned.is_none());
                        planned.metadata["runtime_reconcile"] = Value::Bool(runtime_will_reconcile);
                        if !runtime_will_reconcile {
                            let machine = &owned.expect("checked existing runtime").machines[0];
                            if machine.instance_id.is_empty() {
                                return Err(PluginError::retryable(
                                    ErrorKind::Unavailable,
                                    "fly_machine_version_missing",
                                    format!(
                                        "Fly.io did not report the current Machine version for App `{}`",
                                        workload.app_name
                                    ),
                                ));
                            }
                            planned.metadata["machine_id"] = Value::String(machine.id.clone());
                            planned.metadata["instance_id"] =
                                Value::String(machine.instance_id.clone());
                        }
                        actions.push(planned);
                    }
                }
                Capability::Dns => {
                    let runtime_will_reconcile = owned.is_none_or(|owned| {
                        let machine = &owned.machines[0];
                        metadata(machine, REVISION_KEY) != Some(revision)
                            || metadata(machine, ROLE_KEY) != Some("workload")
                    });
                    let mut planned = action(
                        format!("dns.refresh-expiry.{}", workload.app_name),
                        "fly.dns.refresh_expiry",
                        format!(
                            "Commit successful-up expiry metadata for `{}`",
                            workload.service
                        ),
                        false,
                        workload,
                    );
                    planned.metadata["expires_at_unix"] = Value::from(expiry);
                    planned.metadata["runtime_reconcile"] = Value::Bool(runtime_will_reconcile);
                    if let Some(owned) = owned {
                        let machine = &owned.machines[0];
                        planned.metadata["prior_expiry"] = metadata(machine, EXPIRES_KEY)
                            .map_or(Value::Null, |value| Value::String(value.to_owned()));
                        if !runtime_will_reconcile {
                            if machine.instance_id.is_empty() {
                                return Err(PluginError::retryable(
                                    ErrorKind::Unavailable,
                                    "fly_machine_version_missing",
                                    format!(
                                        "Fly.io did not report the current Machine version for App `{}`",
                                        workload.app_name
                                    ),
                                ));
                            }
                            planned.metadata["machine_id"] = Value::String(machine.id.clone());
                            planned.metadata["instance_id"] =
                                Value::String(machine.instance_id.clone());
                        }
                    } else {
                        planned.metadata["initial"] = Value::Bool(true);
                        planned.metadata["prior_expiry"] = Value::Null;
                    }
                    if let Some(rollback) = &mut planned.rollback {
                        rollback.metadata = planned.metadata.clone();
                    }
                    actions.push(planned);
                }
                Capability::Target | Capability::Builder => {}
                _ => return Err(unsupported_capability(capability)),
            }
        }
        Ok(actions)
    }

    async fn context_token(&self, environment_id: &str) -> PluginResult<SecretValue> {
        Ok(self.cached_context(environment_id).await?.token)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashMap};

    use async_trait::async_trait;
    use lightrail_plugin_protocol::{
        Capability, ErrorKind, OperationContext, PluginError, PluginHandler, ResourceStatus,
        SecretValue, ValidateRequest,
    };
    use serde_json::{Value, json};

    use super::{
        CachedContext, CapturedApp, Discovery, EnvironmentSummary, FlyPlugin, Identity,
        MachineMetadataApi, OwnedApp, PLUGIN_ID, ProvisionalApp, Settings, Workload, action,
        assert_destroy_continuity, exact_lock_sentinel, health_status_matches, lease_needs_refresh,
        lease_release_lost, merge_captured, plan_destroy_actions, redirect_is_https,
        required_lease_remaining, validate_existing_volume_size, volume_deletion_complete,
        wait_all_inspection_probes, wait_all_readiness, workload_machine_config,
        write_expiry_metadata,
    };
    use crate::api::{App, Machine, MachineConfig, PublicResponse, Volume};
    use crate::model::{
        AppSpec, DesiredState, EnvironmentSpec, Isolation, MANAGED_KEY, PROJECT_KEY,
        PUBLIC_APP_KEY, ProjectSpec, REVISION_KEY, ROLE_KEY, network_name,
    };

    fn desired() -> DesiredState {
        DesiredState {
            schema: 1,
            project: ProjectSpec {
                id: "018f6f9f-21aa-7da8-a1b2-31da91ed5148".to_owned(),
                slug: "demo".to_owned(),
                root: None,
                compose: vec!["compose.yaml".into()],
            },
            environment: EnvironmentSpec {
                id: "lr-env-a".to_owned(),
                profile: "preview".to_owned(),
                branch: "feature/login".to_owned(),
                commit: Some("abc".to_owned()),
                dirty: false,
                isolation: Isolation::Environment,
                labels: BTreeMap::new(),
            },
            resolved_compose_path: None,
            apps: vec![AppSpec {
                name: "web".to_owned(),
                service: "frontend".to_owned(),
                port: 8080,
                health_path: Some("/ready".to_owned()),
                health_status: Some(204),
                health_interval_seconds: Some(10),
                health_timeout_seconds: Some(3),
                environment: BTreeMap::new(),
            }],
            destroy: false,
        }
    }

    fn workload(public: bool) -> Workload {
        Workload {
            service: "frontend".to_owned(),
            app_name: "lr-feature-login-web-deadbeef".to_owned(),
            public_app: public.then(|| "web".to_owned()),
            port: public.then_some(8080),
            health_path: public.then(|| "/ready".to_owned()),
            health_status: public.then_some(204),
            health_interval_seconds: public.then_some(10),
            health_timeout_seconds: public.then_some(3),
            build: true,
            image: "registry.fly.io/demo:tag".to_owned(),
            volume: None,
            environment: BTreeMap::new(),
            init: None,
        }
    }

    fn identity() -> Identity {
        Identity {
            project_id: "018f6f9f-21aa-7da8-a1b2-31da91ed5148".to_owned(),
            environment_id: "lr-env-a".to_owned(),
            profile: "preview".to_owned(),
            branch: "feature/login".to_owned(),
        }
    }

    fn owned_app(
        app_name: &str,
        service: &str,
        state: &str,
        revision: &str,
        expiry: Option<&str>,
        public: bool,
    ) -> OwnedApp {
        let identity = identity();
        let mut metadata = identity.metadata(service, "workload", revision, expiry);
        if public {
            metadata.insert(PUBLIC_APP_KEY.to_owned(), service.to_owned());
        }
        OwnedApp {
            app: App {
                id: format!("{app_name}-id"),
                name: app_name.to_owned(),
                status: "deployed".to_owned(),
                organization: json!({"slug": "personal"}),
                network: Some(network_name(
                    &identity.project_id,
                    &identity.environment_id,
                    &Settings::default(),
                )),
            },
            machines: vec![Machine {
                id: format!("{app_name}-machine"),
                name: format!("{app_name}-machine"),
                state: state.to_owned(),
                region: "ord".to_owned(),
                instance_id: format!("{app_name}-instance"),
                config: MachineConfig {
                    image: "example/image:1".to_owned(),
                    metadata,
                    mounts: Vec::new(),
                },
            }],
            volumes: Vec::new(),
            environment_id: identity.environment_id,
            profile: identity.profile,
            branch: identity.branch,
            service: service.to_owned(),
        }
    }

    fn context(operation: &str) -> OperationContext {
        OperationContext {
            operation_id: "operation-1".to_owned(),
            environment_id: "lr-env-a".to_owned(),
            profile: "preview".to_owned(),
            project_root: Some("/tmp/project".to_owned()),
            config: serde_json::to_value(Settings::default()).expect("settings"),
            secrets: BTreeMap::from([("fly-token".to_owned(), SecretValue::new("test-token"))]),
            metadata: json!({
                "capability": "target",
                "operation": operation,
                "all": false,
                "project_id": "018f6f9f-21aa-7da8-a1b2-31da91ed5148",
                "project_slug": "demo"
            }),
        }
    }

    #[derive(Default)]
    struct MemoryMetadataApi {
        values: std::sync::Mutex<BTreeMap<(String, String), String>>,
        calls: std::sync::Mutex<Vec<(String, String, Option<String>)>>,
        fail_next_set: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl MachineMetadataApi for MemoryMetadataApi {
        async fn set_expiry(
            &self,
            _token: &str,
            app: &str,
            machine: &str,
            value: &str,
        ) -> lightrail_plugin_protocol::PluginResult<()> {
            if self
                .fail_next_set
                .swap(false, std::sync::atomic::Ordering::AcqRel)
            {
                return Err(PluginError::retryable(
                    ErrorKind::Unavailable,
                    "injected_metadata_failure",
                    "injected metadata failure",
                ));
            }
            self.values
                .lock()
                .expect("values")
                .insert((app.to_owned(), machine.to_owned()), value.to_owned());
            self.calls.lock().expect("calls").push((
                app.to_owned(),
                machine.to_owned(),
                Some(value.to_owned()),
            ));
            Ok(())
        }

        async fn delete_expiry(
            &self,
            _token: &str,
            app: &str,
            machine: &str,
        ) -> lightrail_plugin_protocol::PluginResult<()> {
            self.values
                .lock()
                .expect("values")
                .remove(&(app.to_owned(), machine.to_owned()));
            self.calls
                .lock()
                .expect("calls")
                .push((app.to_owned(), machine.to_owned(), None));
            Ok(())
        }
    }

    #[test]
    fn manifest_declares_agentless_pipeline_and_selected_destroy() {
        let manifest = FlyPlugin::default().manifest();
        assert_eq!(manifest.id, PLUGIN_ID);
        assert!(manifest.capabilities.contains(&Capability::Builder));
        assert!(manifest.capabilities.contains(&Capability::Target));
        assert!(manifest.capabilities.contains(&Capability::OperationLock));
        assert!(
            manifest
                .features
                .contains(&"dev.lightrail.selected-destroy.v1".to_owned())
        );
        assert!(
            manifest
                .required_secrets
                .iter()
                .all(|requirement| requirement.name != "*")
        );
    }

    #[tokio::test]
    async fn ttl_is_stable_for_every_plan_in_one_operation() {
        let plugin = FlyPlugin::default();
        let settings = Settings::default();
        let first = plugin.operation_expiry("same-operation", &settings).await;
        let second = plugin.operation_expiry("same-operation", &settings).await;
        assert_eq!(first, second);
    }

    #[test]
    fn lease_refresh_threshold_preserves_provider_and_rollback_budget_between_apps() {
        assert_eq!(required_lease_remaining(90), 180);
        assert!(lease_needs_refresh(1_269, 1_000, 90));
        assert!(!lease_needs_refresh(1_271, 1_000, 90));
        assert!(lease_needs_refresh(1_569, 1_000, 390));
        assert!(!lease_needs_refresh(4_600, 1_000, 390));
    }

    #[test]
    fn lock_sentinel_requires_exactly_one_owned_machine() {
        let project_id = identity().project_id;
        let sentinel = Machine {
            id: "sentinel".to_owned(),
            name: "lightrail-project-lock".to_owned(),
            state: "stopped".to_owned(),
            region: "ord".to_owned(),
            instance_id: "instance".to_owned(),
            config: MachineConfig {
                image: "busybox".to_owned(),
                metadata: BTreeMap::from([
                    (MANAGED_KEY.to_owned(), "true".to_owned()),
                    (PROJECT_KEY.to_owned(), project_id.clone()),
                    (ROLE_KEY.to_owned(), "project-lock".to_owned()),
                ]),
                mounts: Vec::new(),
            },
        };
        assert_eq!(
            exact_lock_sentinel(std::slice::from_ref(&sentinel), &project_id)
                .expect("owned sentinel")
                .expect("present")
                .id,
            "sentinel"
        );
        assert_eq!(
            exact_lock_sentinel(&[sentinel.clone(), sentinel], &project_id)
                .expect_err("racing duplicate sentinels must fail safely")
                .code,
            "fly_lock_ownership_mismatch"
        );
    }

    #[test]
    fn missing_or_replaced_local_lease_is_lock_loss() {
        for kind in [ErrorKind::NotFound, ErrorKind::Conflict] {
            let error = PluginError::permanent(kind, "provider", "provider");
            assert!(lease_release_lost(&error));
        }
        let transient = PluginError::retryable(ErrorKind::Unavailable, "provider", "provider");
        assert!(!lease_release_lost(&transient));
    }

    #[test]
    fn volume_size_drift_requires_environment_replacement() {
        validate_existing_volume_size("database", 3, 3).expect("same size");
        let error = validate_existing_volume_size("database", 3, 10)
            .expect_err("in-place size changes are not silently ignored");
        assert_eq!(error.code, "fly_volume_size_change_requires_down");
    }

    #[test]
    fn pending_destroy_is_a_terminal_fly_volume_deletion_state() {
        let volume = |state: &str| Volume {
            id: "volume-1".to_owned(),
            name: "data".to_owned(),
            state: state.to_owned(),
            region: "ord".to_owned(),
            attached_machine_id: None,
            size_gb: 3,
        };
        assert!(volume_deletion_complete(&volume("pending_destroy")));
        assert!(volume_deletion_complete(&volume("destroyed")));
        assert!(!volume_deletion_complete(&volume("created")));
    }

    #[test]
    fn environment_networks_are_shared_within_and_distinct_across_previews() {
        let settings = Settings::default();
        let project = "018f6f9f-21aa-7da8-a1b2-31da91ed5148";
        assert_eq!(
            network_name(project, "environment-a", &settings),
            network_name(project, "environment-a", &settings)
        );
        assert_ne!(
            network_name(project, "environment-a", &settings),
            network_name(project, "environment-b", &settings)
        );
    }

    #[test]
    fn public_machine_forces_https_and_records_exact_health_contract() {
        let desired = desired();
        let workload = workload(true);
        let config = workload_machine_config(
            &Settings::default(),
            &identity(),
            &desired,
            &workload,
            "registry.fly.io/demo@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Vec::new(),
            BTreeMap::new(),
            "revision",
            Some("123"),
        );
        assert_eq!(
            config.pointer("/services/0/ports/0/force_https"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            config.pointer("/services/0/ports/1/handlers"),
            Some(&json!(["tls", "http"]))
        );
        assert_eq!(
            config.pointer("/services/0/autostop"),
            Some(&Value::String("stop".to_owned()))
        );
        assert_eq!(
            config.pointer("/services/0/autostart"),
            Some(&Value::Bool(true))
        );
        assert!(config.pointer("/services/0/auto_stop_machines").is_none());
        assert_eq!(
            config.pointer("/checks/lightrail-http/path"),
            Some(&Value::String("/ready".to_owned()))
        );
        assert_eq!(
            config.pointer("/checks/lightrail-http/port"),
            Some(&Value::from(8080))
        );
        assert_eq!(
            config.pointer("/checks/lightrail-http/protocol"),
            Some(&Value::String("http".to_owned()))
        );
        assert_eq!(
            config.pointer("/metadata/lightrail-health-status"),
            Some(&Value::String("204".to_owned()))
        );
        assert_eq!(
            config.pointer("/checks/lightrail-http/interval"),
            Some(&Value::String("10s".to_owned()))
        );
        assert_eq!(
            config.pointer("/checks/lightrail-http/timeout"),
            Some(&Value::String("3s".to_owned()))
        );
        assert_eq!(
            config.pointer("/checks/lightrail-http/grace_period"),
            Some(&Value::String("5s".to_owned()))
        );
        assert_eq!(
            config.pointer("/metadata/lightrail-expires-at-unix"),
            Some(&Value::String("123".to_owned()))
        );
    }

    #[test]
    fn private_machine_has_no_public_service_registration() {
        let config = workload_machine_config(
            &Settings::default(),
            &identity(),
            &desired(),
            &workload(false),
            "example/private:1",
            Vec::new(),
            BTreeMap::new(),
            "revision",
            Some("123"),
        );
        assert_eq!(config.pointer("/services"), Some(&json!([])));
    }

    #[test]
    fn runtime_render_preserves_prior_expiry_until_final_commit() {
        let config = workload_machine_config(
            &Settings::default(),
            &identity(),
            &desired(),
            &workload(false),
            "example/private:2",
            Vec::new(),
            BTreeMap::new(),
            "new-revision",
            Some("111"),
        );
        assert_eq!(
            config.pointer("/metadata/lightrail-expires-at-unix"),
            Some(&json!("111")),
            "a later Exposure failure must leave the previous successful-up expiry intact"
        );
    }

    #[tokio::test]
    async fn failed_expiry_commit_preserves_prior_and_rollback_restores_exact_value() {
        let api = MemoryMetadataApi::default();
        api.values
            .lock()
            .expect("values")
            .insert(("app".to_owned(), "machine".to_owned()), "111".to_owned());
        api.fail_next_set
            .store(true, std::sync::atomic::Ordering::Release);

        write_expiry_metadata(&api, "token", "app", "machine", Some("222"))
            .await
            .expect_err("injected final commit failure");
        assert_eq!(
            api.values
                .lock()
                .expect("values")
                .get(&("app".to_owned(), "machine".to_owned()))
                .map(String::as_str),
            Some("111")
        );

        write_expiry_metadata(&api, "token", "app", "machine", Some("222"))
            .await
            .expect("commit");
        write_expiry_metadata(&api, "token", "app", "machine", Some("111"))
            .await
            .expect("restore");
        assert_eq!(
            api.values
                .lock()
                .expect("values")
                .get(&("app".to_owned(), "machine".to_owned()))
                .map(String::as_str),
            Some("111")
        );
    }

    #[tokio::test]
    async fn initial_expiry_rollback_deletes_only_the_exact_attempted_metadata() {
        let api = MemoryMetadataApi::default();
        write_expiry_metadata(&api, "token", "app-a", "machine-a", Some("222"))
            .await
            .expect("initial commit");
        api.values.lock().expect("values").insert(
            ("app-b".to_owned(), "machine-b".to_owned()),
            "999".to_owned(),
        );

        write_expiry_metadata(&api, "token", "app-a", "machine-a", None)
            .await
            .expect("initial rollback deletes exact key");
        let values = api.values.lock().expect("values");
        assert!(!values.contains_key(&("app-a".to_owned(), "machine-a".to_owned())));
        assert_eq!(
            values
                .get(&("app-b".to_owned(), "machine-b".to_owned()))
                .map(String::as_str),
            Some("999")
        );
    }

    #[test]
    fn missing_member_expiry_is_omitted_from_prune_contract() {
        let summary = EnvironmentSummary {
            project_id: "project".to_owned(),
            environment_id: "environment".to_owned(),
            profile: "preview".to_owned(),
            branch: "feature".to_owned(),
            status: ResourceStatus::Degraded,
            endpoints: Vec::new(),
            expires_at_unix: Some(123),
            mismatch: false,
            missing_expiry: true,
        };
        assert!(summary.into_value().get("expires_at_unix").is_none());
    }

    #[test]
    fn environment_contract_includes_status_and_endpoints() {
        let endpoint = lightrail_plugin_protocol::Endpoint {
            app: "web".to_owned(),
            url: "https://demo.fly.dev".to_owned(),
        };
        let summary = EnvironmentSummary {
            project_id: "project".to_owned(),
            environment_id: "environment".to_owned(),
            profile: "preview".to_owned(),
            branch: "feature".to_owned(),
            status: ResourceStatus::Ready,
            endpoints: vec![endpoint],
            expires_at_unix: Some(123),
            mismatch: false,
            missing_expiry: false,
        }
        .into_value();
        assert_eq!(summary["status"], json!("ready"));
        assert_eq!(
            summary.pointer("/endpoints/0/url"),
            Some(&json!("https://demo.fly.dev"))
        );
    }

    #[test]
    fn runtime_and_exposure_actions_publish_their_actual_inverse_contracts() {
        let target = action(
            "target".to_owned(),
            "fly.target.create",
            "summary".to_owned(),
            false,
            &workload(true),
        )
        .rollback
        .expect("explicit target rollback contract");
        assert!(target.supported);
        assert_eq!(target.action.as_deref(), Some("fly.target.cleanup"));

        let runtime = action(
            "runtime".to_owned(),
            "fly.runtime.reconcile",
            "summary".to_owned(),
            false,
            &workload(true),
        )
        .rollback
        .expect("explicit runtime rollback contract");
        assert!(!runtime.supported);
        assert!(runtime.action.is_none());

        let exposure = action(
            "exposure".to_owned(),
            "fly.exposure.allocate_ip",
            "summary".to_owned(),
            false,
            &workload(true),
        )
        .rollback
        .expect("explicit exposure rollback contract");
        assert!(exposure.supported);
        assert_eq!(exposure.action.as_deref(), Some("fly.exposure.release_ip"));
        assert_eq!(
            exposure.metadata.get("app").and_then(Value::as_str),
            Some("lr-feature-login-web-deadbeef")
        );

        let expiry = action(
            "expiry".to_owned(),
            "fly.dns.refresh_expiry",
            "summary".to_owned(),
            false,
            &workload(true),
        )
        .rollback
        .expect("explicit expiry rollback contract");
        assert!(expiry.supported);
        assert_eq!(expiry.action.as_deref(), Some("fly.dns.restore_expiry"));
    }

    #[test]
    fn destructive_target_actions_declare_irreversible_cleanup() {
        let orphan = super::OrphanApp {
            app: App {
                id: "app-id".to_owned(),
                name: "app".to_owned(),
                status: String::new(),
                organization: Value::Null,
                network: Some("network".to_owned()),
            },
            volumes: Vec::new(),
            environment_id: Some("lr-env-a".to_owned()),
        };
        let discovery = Discovery {
            owned: Vec::new(),
            orphans: vec![orphan],
            observed: HashMap::new(),
            conflicts: Vec::new(),
        };
        let planned =
            plan_destroy_actions(&Capability::Target, "lr-env-a", false, None, &discovery);
        let rollback = planned[0]
            .rollback
            .as_ref()
            .expect("destructive action contract");
        assert!(!rollback.supported);
        assert!(rollback.action.is_none());
    }

    #[tokio::test]
    async fn empty_target_inspection_is_an_absent_pre_apply_snapshot() {
        let plugin = FlyPlugin::default();
        let cached = CachedContext {
            settings: Settings::default(),
            identity: identity(),
            token: SecretValue::new("test-token"),
        };
        let inspected = plugin
            .inspection_from_discovery(
                &cached,
                &Capability::Target,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                "operation-1",
            )
            .await
            .expect("empty target inspection");
        assert_eq!(inspected.status, ResourceStatus::Absent);
        assert_eq!(inspected.state["apps"], json!([]));
    }

    #[tokio::test]
    async fn inspection_degrades_stopped_machines_without_proxy_autostart() {
        let settings = Settings {
            auto_stop: false,
            ..Settings::default()
        };
        let cached = CachedContext {
            settings,
            identity: identity(),
            token: SecretValue::new("test-token"),
        };
        for (public, expected_code) in [
            (false, "fly_private_machine_not_running"),
            (true, "fly_public_machine_unexpectedly_stopped"),
        ] {
            let inspected = FlyPlugin::default()
                .inspection_from_discovery(
                    &cached,
                    &Capability::Target,
                    vec![owned_app(
                        "app",
                        "frontend",
                        "stopped",
                        "revision",
                        Some("123"),
                        public,
                    )],
                    Vec::new(),
                    Vec::new(),
                    "operation-1",
                )
                .await
                .expect("bounded inspection");
            assert_eq!(inspected.status, ResourceStatus::Degraded);
            assert!(
                inspected
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == expected_code)
            );
        }

        let cached = CachedContext {
            settings: Settings::default(),
            identity: identity(),
            token: SecretValue::new("test-token"),
        };
        let inspected = FlyPlugin::default()
            .inspection_from_discovery(
                &cached,
                &Capability::Target,
                vec![owned_app(
                    "public",
                    "frontend",
                    "stopped",
                    "revision",
                    Some("123"),
                    true,
                )],
                Vec::new(),
                Vec::new(),
                "operation-1",
            )
            .await
            .expect("autostop-backed public Machine");
        assert_eq!(inspected.status, ResourceStatus::Ready);
    }

    #[tokio::test]
    async fn inspection_degrades_mixed_revision_and_expiry_metadata() {
        let cached = CachedContext {
            settings: Settings::default(),
            identity: identity(),
            token: SecretValue::new("test-token"),
        };
        let inspected = FlyPlugin::default()
            .inspection_from_discovery(
                &cached,
                &Capability::Target,
                vec![
                    owned_app(
                        "frontend",
                        "frontend",
                        "started",
                        "revision-a",
                        Some("123"),
                        false,
                    ),
                    owned_app(
                        "worker",
                        "worker",
                        "started",
                        "revision-b",
                        Some("456"),
                        false,
                    ),
                ],
                Vec::new(),
                Vec::new(),
                "operation-1",
            )
            .await
            .expect("mixed metadata inspection");
        assert_eq!(inspected.status, ResourceStatus::Degraded);
        assert!(inspected.state.get("revision").is_none());
        assert_eq!(
            inspected.state.pointer("/environments/0/status"),
            Some(&json!("degraded"))
        );
        assert!(
            inspected
                .state
                .pointer("/environments/0/expires_at_unix")
                .is_none(),
            "mixed expiry must not be prune-eligible"
        );
        assert!(
            inspected
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "fly_environment_revision_mismatch")
        );
        assert!(
            inspected
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "fly_environment_expiry_mismatch")
        );
    }

    #[tokio::test]
    async fn initial_capabilities_preplan_from_the_same_absent_snapshot() {
        let plugin = FlyPlugin::default();
        let settings = Settings::default();
        let desired = desired();
        plugin.contexts.write().await.insert(
            desired.environment.id.clone(),
            CachedContext {
                settings: settings.clone(),
                identity: identity(),
                token: SecretValue::new("test-token"),
            },
        );
        let discovery = Discovery {
            owned: Vec::new(),
            orphans: Vec::new(),
            observed: HashMap::new(),
            conflicts: Vec::new(),
        };
        let workloads = vec![workload(true)];
        let target = plugin
            .plan_up_actions(
                &Capability::Target,
                &settings,
                &desired,
                "revision",
                123,
                &workloads,
                &discovery,
            )
            .await
            .expect("initial Target plan");
        let runtime = plugin
            .plan_up_actions(
                &Capability::Runtime,
                &settings,
                &desired,
                "revision",
                123,
                &workloads,
                &discovery,
            )
            .await
            .expect("initial Runtime plan");
        let exposure = plugin
            .plan_up_actions(
                &Capability::Exposure,
                &settings,
                &desired,
                "revision",
                123,
                &workloads,
                &discovery,
            )
            .await
            .expect("initial Exposure plan");
        let dns = plugin
            .plan_up_actions(
                &Capability::Dns,
                &settings,
                &desired,
                "revision",
                123,
                &workloads,
                &discovery,
            )
            .await
            .expect("initial final-expiry plan");

        assert_eq!(target[0].kind, "fly.target.create");
        assert_eq!(runtime[0].kind, "fly.runtime.reconcile");
        assert_eq!(runtime[0].metadata["initial"], json!(true));
        assert_eq!(exposure[0].kind, "fly.exposure.allocate_ip");
        assert_eq!(exposure[0].metadata["initial"], json!(true));
        assert_eq!(exposure[0].metadata["runtime_reconcile"], json!(true));
        assert_eq!(dns[0].kind, "fly.dns.refresh_expiry");
        assert_eq!(dns[0].metadata["initial"], json!(true));
        assert_eq!(dns[0].metadata["runtime_reconcile"], json!(true));
        assert_eq!(dns[0].metadata["prior_expiry"], Value::Null);
        assert_eq!(dns[0].metadata["expires_at_unix"], json!(123));
    }

    #[tokio::test]
    async fn adding_service_to_existing_environment_fails_before_any_mutation_plan() {
        let plugin = FlyPlugin::default();
        let settings = Settings::default();
        let desired = desired();
        let existing = workload(true);
        let mut added = workload(false);
        added.service = "worker".to_owned();
        added.app_name = "lr-feature-login-worker-cafebabe".to_owned();
        let discovery = Discovery {
            owned: vec![super::OwnedApp {
                app: App {
                    id: "app-id".to_owned(),
                    name: existing.app_name.clone(),
                    status: "deployed".to_owned(),
                    organization: json!({"slug": "personal"}),
                    network: Some(network_name(
                        &desired.project.id,
                        &desired.environment.id,
                        &settings,
                    )),
                },
                machines: vec![Machine {
                    id: "machine-id".to_owned(),
                    name: "machine".to_owned(),
                    state: "started".to_owned(),
                    region: "ord".to_owned(),
                    instance_id: "instance-id".to_owned(),
                    config: MachineConfig::default(),
                }],
                volumes: Vec::new(),
                environment_id: desired.environment.id.clone(),
                profile: desired.environment.profile.clone(),
                branch: desired.environment.branch.clone(),
                service: existing.service.clone(),
            }],
            orphans: Vec::new(),
            observed: HashMap::new(),
            conflicts: Vec::new(),
        };
        let error = plugin
            .plan_up_actions(
                &Capability::Target,
                &settings,
                &desired,
                "revision",
                123,
                &[existing, added],
                &discovery,
            )
            .await
            .expect_err("an added service must require a clean environment replacement");
        assert_eq!(error.code, "fly_added_service_requires_down");
    }

    #[tokio::test]
    async fn expiry_refresh_is_planned_only_in_final_dns_phase() {
        let plugin = FlyPlugin::default();
        let settings = Settings::default();
        let desired = desired();
        plugin.contexts.write().await.insert(
            desired.environment.id.clone(),
            CachedContext {
                settings: settings.clone(),
                identity: identity(),
                token: SecretValue::new("test-token"),
            },
        );
        let existing = owned_app(
            "lr-feature-login-web-deadbeef",
            "frontend",
            "started",
            "revision",
            Some("111"),
            false,
        );
        let discovery = Discovery {
            owned: vec![existing],
            orphans: Vec::new(),
            observed: HashMap::new(),
            conflicts: Vec::new(),
        };
        let workloads = vec![workload(false)];
        let runtime = plugin
            .plan_up_actions(
                &Capability::Runtime,
                &settings,
                &desired,
                "revision",
                222,
                &workloads,
                &discovery,
            )
            .await
            .expect("Runtime plan");
        assert!(
            runtime.is_empty(),
            "expiry drift alone must not mutate Runtime before Exposure succeeds"
        );
        let dns = plugin
            .plan_up_actions(
                &Capability::Dns,
                &settings,
                &desired,
                "revision",
                222,
                &workloads,
                &discovery,
            )
            .await
            .expect("final expiry plan");
        assert_eq!(dns.len(), 1);
        assert_eq!(dns[0].kind, "fly.dns.refresh_expiry");
        assert_eq!(dns[0].metadata["runtime_reconcile"], json!(false));
        assert_eq!(
            dns[0].metadata["machine_id"],
            json!("lr-feature-login-web-deadbeef-machine")
        );
        assert_eq!(
            dns[0].metadata["instance_id"],
            json!("lr-feature-login-web-deadbeef-instance")
        );
        assert_eq!(dns[0].metadata["prior_expiry"], json!("111"));
        assert_eq!(dns[0].metadata["expires_at_unix"], json!(222));
        assert!(
            dns[0]
                .rollback
                .as_ref()
                .is_some_and(|rollback| rollback.supported)
        );
    }

    #[tokio::test]
    async fn expiry_rejects_an_out_of_band_version_when_runtime_was_already_current() {
        let plugin = FlyPlugin::default();
        let settings = Settings::default();
        let desired = desired();
        plugin.contexts.write().await.insert(
            desired.environment.id.clone(),
            CachedContext {
                settings: settings.clone(),
                identity: identity(),
                token: SecretValue::new("test-token"),
            },
        );
        let existing = owned_app(
            "lr-feature-login-web-deadbeef",
            "frontend",
            "started",
            "revision",
            Some("111"),
            false,
        );
        let mut changed = existing.machines[0].clone();
        let discovery = Discovery {
            owned: vec![existing],
            orphans: Vec::new(),
            observed: HashMap::new(),
            conflicts: Vec::new(),
        };
        let dns = plugin
            .plan_up_actions(
                &Capability::Dns,
                &settings,
                &desired,
                "revision",
                222,
                &[workload(false)],
                &discovery,
            )
            .await
            .expect("final expiry plan");

        plugin
            .verify_expiry_runtime("operation-1", "revision", &dns[0], &changed)
            .await
            .expect("the exact planned Machine version");
        changed.instance_id = "out-of-band-version".to_owned();
        let error = plugin
            .verify_expiry_runtime("operation-1", "revision", &dns[0], &changed)
            .await
            .expect_err("an out-of-band Machine update must invalidate expiry apply");
        assert_eq!(error.code, "stale_or_modified_plan");
    }

    #[tokio::test]
    async fn expiry_accepts_only_the_exact_runtime_reconciled_version_and_revision() {
        let plugin = FlyPlugin::default();
        let settings = Settings::default();
        let desired = desired();
        plugin.contexts.write().await.insert(
            desired.environment.id.clone(),
            CachedContext {
                settings: settings.clone(),
                identity: identity(),
                token: SecretValue::new("test-token"),
            },
        );
        let existing = owned_app(
            "lr-feature-login-web-deadbeef",
            "frontend",
            "started",
            "old-revision",
            Some("111"),
            false,
        );
        let mut reconciled = existing.machines[0].clone();
        let discovery = Discovery {
            owned: vec![existing],
            orphans: Vec::new(),
            observed: HashMap::new(),
            conflicts: Vec::new(),
        };
        let dns = plugin
            .plan_up_actions(
                &Capability::Dns,
                &settings,
                &desired,
                "revision",
                222,
                &[workload(false)],
                &discovery,
            )
            .await
            .expect("final expiry plan");
        assert_eq!(dns[0].metadata["runtime_reconcile"], json!(true));

        reconciled.instance_id = "runtime-version".to_owned();
        plugin
            .record_runtime_version(
                "operation-1",
                "lr-feature-login-web-deadbeef",
                &reconciled.instance_id,
            )
            .await;
        let stale_revision = plugin
            .verify_expiry_runtime("operation-1", "revision", &dns[0], &reconciled)
            .await
            .expect_err("Runtime continuity cannot replace desired-revision validation");
        assert_eq!(stale_revision.code, "stale_or_modified_plan");

        reconciled
            .config
            .metadata
            .insert(REVISION_KEY.to_owned(), "revision".to_owned());
        plugin
            .verify_expiry_runtime("operation-1", "revision", &dns[0], &reconciled)
            .await
            .expect("the exact Runtime-produced version at the desired revision");

        reconciled.instance_id = "out-of-band-version".to_owned();
        let stale_version = plugin
            .verify_expiry_runtime("operation-1", "revision", &dns[0], &reconciled)
            .await
            .expect_err("a post-Runtime Machine update must invalidate expiry apply");
        assert_eq!(stale_version.code, "stale_or_modified_plan");
    }

    #[test]
    fn default_health_accepts_every_non_server_error_but_configured_is_exact() {
        assert!(health_status_matches(204, None));
        assert!(health_status_matches(404, None));
        assert!(!health_status_matches(500, None));
        assert!(health_status_matches(204, Some(204)));
        assert!(!health_status_matches(200, Some(204)));
    }

    #[test]
    fn redirect_requires_the_exact_native_hostname() {
        let response = |location: &str| PublicResponse {
            status: 301,
            location: Some(location.to_owned()),
        };
        assert!(redirect_is_https(
            &response("https://demo.fly.dev/ready"),
            "demo.fly.dev"
        ));
        assert!(!redirect_is_https(
            &response("https://demo.fly.dev.attacker.example/ready"),
            "demo.fly.dev"
        ));
    }

    #[tokio::test]
    async fn multiple_public_readiness_checks_are_polled_concurrently() {
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));
        let readiness = wait_all_readiness((0..2).map(|_| {
            let barrier = barrier.clone();
            async move {
                barrier.wait().await;
                Ok(())
            }
        }));
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            let (result, _) = tokio::join!(readiness, barrier.wait());
            result
        })
        .await
        .expect("both readiness futures must be polled together");
        result.expect("readiness succeeds");
    }

    #[tokio::test]
    async fn inspection_probes_share_one_deadline_and_preserve_input_order() {
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));
        let cancellation = super::Cancellation::default();
        let probes = wait_all_inspection_probes(
            (0..2).map(|index| {
                let barrier = barrier.clone();
                async move {
                    barrier.wait().await;
                    Ok(index)
                }
            }),
            std::time::Duration::from_secs(1),
            &cancellation,
        );
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            let (result, _) = tokio::join!(probes, barrier.wait());
            result
        })
        .await
        .expect("all inspection probes must be polled together")
        .expect("inspection succeeds");
        assert_eq!(result, vec![0, 1]);
    }

    #[test]
    fn absent_pre_apply_snapshot_merges_exact_partial_initial_apply() {
        let provisional = ProvisionalApp {
            project_id: "project".to_owned(),
            environment_id: "environment".to_owned(),
            app: "app".to_owned(),
            app_id: Some("app-id".to_owned()),
            network: "network".to_owned(),
            machine_ids: BTreeSet::new(),
            volume_ids: BTreeSet::from(["volume-1".to_owned()]),
        };
        let expected = CapturedApp::from_provisional(provisional);
        let mut snapshot = Vec::new();
        merge_captured(&mut snapshot, vec![expected.clone()]).expect("merge provisional");
        assert_destroy_continuity(&snapshot, std::slice::from_ref(&expected))
            .expect("exact partial App is cleanup eligible");

        let mut drifted = expected.clone();
        drifted.machine_ids.insert("unplanned-machine".to_owned());
        let error = assert_destroy_continuity(&snapshot, &[drifted])
            .expect_err("unplanned resource must block cleanup");
        assert_eq!(error.code, "fly_destroy_plan_drift");

        let mut replaced = expected;
        replaced.app_id = Some("replacement-app-id".to_owned());
        let error = assert_destroy_continuity(&snapshot, &[replaced])
            .expect_err("same-name App replacement must block cleanup");
        assert_eq!(error.code, "fly_destroy_plan_drift");
    }

    #[tokio::test]
    async fn destroy_validation_never_requires_resolved_compose() {
        let mut desired = desired();
        desired.destroy = true;
        desired.resolved_compose_path = None;
        let request = ValidateRequest {
            context: context("destroy"),
            desired: serde_json::to_value(desired).expect("desired"),
        };
        let settings = FlyPlugin::default()
            .validate_inner(&request)
            .await
            .expect("destroy validates without Compose");
        assert_eq!(settings.organization, "personal");
    }
}

fn action_app(action: &PlannedAction) -> PluginResult<&str> {
    action
        .metadata
        .get("app")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| stale_plan("a Fly plan action is missing its App name"))
}

fn action_metadata_string<'a>(action: &'a PlannedAction, field: &str) -> PluginResult<&'a str> {
    action
        .metadata
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| stale_plan("a Fly plan action is missing exact resource continuity data"))
}

fn action_optional_string<'a>(
    action: &'a PlannedAction,
    field: &str,
) -> PluginResult<Option<&'a str>> {
    match action.metadata.get(field) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value)),
        _ => Err(stale_plan(
            "a Fly plan action has invalid optional resource continuity data",
        )),
    }
}

fn action_is_initial(action: &PlannedAction) -> bool {
    action
        .metadata
        .get("initial")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn find_workload<'a>(workloads: &'a [Workload], app_name: &str) -> PluginResult<&'a Workload> {
    workloads
        .iter()
        .find(|workload| workload.app_name == app_name)
        .ok_or_else(|| stale_plan("a Fly plan action selects an unknown workload"))
}

fn selected_workloads(
    actions: &[PlannedAction],
    workloads: &[Workload],
    expected_kind: &str,
) -> PluginResult<Vec<Workload>> {
    let mut selected = Vec::new();
    let mut seen = BTreeSet::new();
    for action in actions {
        if action.kind != expected_kind {
            return Err(stale_plan("Fly plan contains an unsupported action kind"));
        }
        let workload = find_workload(workloads, action_app(action)?)?;
        if !seen.insert(workload.app_name.clone()) {
            return Err(stale_plan("Fly plan contains duplicate workload actions"));
        }
        selected.push(workload.clone());
    }
    Ok(selected)
}

fn context_token(
    context: &lightrail_plugin_protocol::OperationContext,
    settings: &Settings,
) -> PluginResult<SecretValue> {
    context
        .secrets
        .get(&settings.token.secret)
        .cloned()
        .ok_or_else(|| {
            PluginError::permanent(
                ErrorKind::Authentication,
                "fly_token_required",
                "the `fly-token` secret has not been resolved",
            )
        })
}

fn exact_owned_machine<'a>(
    machines: &'a [Machine],
    identity: &Identity,
    workload: &Workload,
) -> PluginResult<&'a Machine> {
    if machines.len() != 1 {
        return Err(PluginError::permanent(
            ErrorKind::Conflict,
            "fly_machine_count_mismatch",
            format!(
                "Fly App `{}` must contain exactly one Machine",
                workload.app_name
            ),
        ));
    }
    let machine = &machines[0];
    if metadata(machine, MANAGED_KEY) != Some("true")
        || metadata(machine, PROJECT_KEY) != Some(identity.project_id.as_str())
        || metadata(machine, ENVIRONMENT_KEY) != Some(identity.environment_id.as_str())
        || metadata(machine, SERVICE_KEY) != Some(workload.service.as_str())
    {
        return Err(PluginError::permanent(
            ErrorKind::Conflict,
            "fly_machine_ownership_mismatch",
            format!(
                "Fly App `{}` Machine ownership changed before apply",
                workload.app_name
            ),
        ));
    }
    Ok(machine)
}

fn validate_existing_volume_size(
    service: &str,
    observed_size_gb: u32,
    requested_size_gb: u32,
) -> PluginResult<()> {
    if observed_size_gb == requested_size_gb {
        return Ok(());
    }
    Err(PluginError::permanent(
        ErrorKind::Conflict,
        "fly_volume_size_change_requires_down",
        format!(
            "Fly Volume for service `{service}` is {observed_size_gb} GiB, but the profile requests {requested_size_gb} GiB; run `lightrail down --yes` before changing `volume_size_gb`"
        ),
    ))
}

fn machine_metadata(
    identity: &Identity,
    workload: &Workload,
    role: &str,
    revision: &str,
    expires_at_unix: Option<&str>,
) -> BTreeMap<String, String> {
    let mut metadata = identity.metadata(&workload.service, role, revision, expires_at_unix);
    if let Some(public_app) = &workload.public_app {
        metadata.insert(PUBLIC_APP_KEY.to_owned(), public_app.clone());
    }
    if let Some(port) = workload.port {
        metadata.insert(PORT_KEY.to_owned(), port.to_string());
    }
    if let Some(path) = &workload.health_path {
        metadata.insert(HEALTH_PATH_KEY.to_owned(), path.clone());
    }
    if let Some(status) = workload.health_status {
        metadata.insert(HEALTH_STATUS_KEY.to_owned(), status.to_string());
    }
    metadata
}

fn placeholder_payload(
    settings: &Settings,
    identity: &Identity,
    workload: &Workload,
    volume: Option<(String, String)>,
) -> Value {
    let mounts = volume.map_or_else(Vec::new, |(volume, path)| {
        vec![json!({"volume": volume, "path": path})]
    });
    let mut payload = serde_json::Map::from_iter([
        (
            "name".to_owned(),
            Value::String(safe_label(&format!("lr-{}", workload.service), 63)),
        ),
        ("skip_launch".to_owned(), Value::Bool(true)),
        (
            "config".to_owned(),
            json!({
                "image": PLACEHOLDER_IMAGE,
                "auto_destroy": false,
                "metadata": machine_metadata(
                    identity,
                    workload,
                    "target-placeholder",
                    "pending",
                    None
                ),
                "guest": {
                    "cpu_kind": settings.cpu_kind,
                    "cpus": settings.cpus,
                    "memory_mb": settings.memory_mb,
                },
                "mounts": mounts,
            }),
        ),
    ]);
    if let Some(region) = &settings.region {
        payload.insert("region".to_owned(), Value::String(region.clone()));
    }
    Value::Object(payload)
}

#[allow(clippy::too_many_arguments)]
fn workload_machine_config(
    settings: &Settings,
    identity: &Identity,
    _desired: &DesiredState,
    workload: &Workload,
    image: &str,
    mounts: Vec<crate::api::MachineMount>,
    environment: BTreeMap<String, String>,
    revision: &str,
    expires_at_unix: Option<&str>,
) -> Value {
    let mounts = mounts
        .into_iter()
        .map(|mount| json!({"volume": mount.volume, "path": mount.path}))
        .collect::<Vec<_>>();
    let services = workload.port.map_or_else(Vec::new, |port| {
        vec![json!({
            "protocol": "tcp",
            "internal_port": port,
            "autostop": if settings.auto_stop { "stop" } else { "off" },
            "autostart": true,
            "min_machines_running": 0,
            "ports": [
                {
                    "port": 80,
                    "handlers": ["http"],
                    "force_https": true
                },
                {
                    "port": 443,
                    "handlers": ["tls", "http"]
                }
            ]
        })]
    });
    let mut config = serde_json::Map::from_iter([
        ("image".to_owned(), Value::String(image.to_owned())),
        (
            "metadata".to_owned(),
            serde_json::to_value(machine_metadata(
                identity,
                workload,
                "workload",
                revision,
                expires_at_unix,
            ))
            .unwrap_or_else(|_| json!({})),
        ),
        (
            "guest".to_owned(),
            json!({
                "cpu_kind": settings.cpu_kind,
                "cpus": settings.cpus,
                "memory_mb": settings.memory_mb,
            }),
        ),
        ("mounts".to_owned(), Value::Array(mounts)),
        ("services".to_owned(), Value::Array(services)),
        ("restart".to_owned(), json!({"policy": "always"})),
        ("auto_destroy".to_owned(), Value::Bool(false)),
    ]);
    if !environment.is_empty() {
        config.insert(
            "env".to_owned(),
            serde_json::to_value(environment).unwrap_or_else(|_| json!({})),
        );
    }
    if let Some(init) = &workload.init {
        config.insert("init".to_owned(), init.clone());
    }
    if let (Some(port), Some(path)) = (workload.port, workload.health_path.as_ref()) {
        config.insert(
            "checks".to_owned(),
            json!({
                "lightrail-http": {
                    "type": "http",
                    "port": port,
                    "protocol": "http",
                    "method": "GET",
                    "path": path,
                    "interval": format!(
                        "{}s",
                        workload.health_interval_seconds.unwrap_or(15)
                    ),
                    "timeout": format!(
                        "{}s",
                        workload.health_timeout_seconds.unwrap_or(2)
                    ),
                    "grace_period": "5s"
                }
            }),
        );
    }
    Value::Object(config)
}

async fn journal_event(
    events: &EventSink,
    operation_id: &str,
    journal: &mut Vec<ActionJournalEntry>,
    action_id: &str,
    status: JournalStatus,
    message: &str,
) -> PluginResult<()> {
    let entry = ActionJournalEntry {
        sequence: journal.len() as u64 + 1,
        action_id: action_id.to_owned(),
        status,
        timestamp: None,
        message: Some(message.to_owned()),
        rollback: None,
        metadata: json!({}),
    };
    events
        .emit(&PluginEvent::Journal {
            operation_id: operation_id.to_owned(),
            entry: entry.clone(),
        })
        .await
        .map_err(|_| {
            PluginError::retryable(
                ErrorKind::Unavailable,
                "fly_event_emit_failed",
                "could not emit the Fly operation journal event",
            )
        })?;
    journal.push(entry);
    Ok(())
}

impl FlyPlugin {
    #[allow(clippy::too_many_lines)]
    async fn acquire_lock(&self, request: LockAcquireRequest) -> PluginResult<LockAcquireResult> {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(request.timeout_ms);
        let cancellation = self.cancellation(&request.operation_id).await;
        let mut delay = Duration::from_millis(250);
        loop {
            cancellation.check()?;
            let result = match self.try_acquire_lock(&request).await {
                Ok(result) => Some(result),
                Err(error) if error.retryable && tokio::time::Instant::now() < deadline => None,
                Err(error) => return Err(error),
            };
            if let Some(result) = result {
                if result.acquired || tokio::time::Instant::now() >= deadline {
                    return Ok(result);
                }
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let sleep_for = delay.min(remaining);
            tokio::select! {
                () = tokio::time::sleep(sleep_for) => {}
                () = cancellation.cancelled() => {
                    cancellation.check()?;
                    continue;
                },
            }
            delay = (delay * 2).min(Duration::from_secs(2));
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn try_acquire_lock(
        &self,
        request: &LockAcquireRequest,
    ) -> PluginResult<LockAcquireResult> {
        if request.scope != LockScope::Project {
            return Err(validation(
                "fly_project_lock_required",
                "Fly environment isolation requires a project-scoped mutation lock",
            ));
        }
        let cached = self.cached_context(&request.environment_id).await?;
        if request.scope_id != cached.identity.project_id {
            return Err(validation(
                "fly_lock_scope_mismatch",
                "Fly project lock scope_id must equal the immutable project UUID",
            ));
        }
        if request.lease_ms.is_some_and(|lease_ms| {
            lease_ms > cached.settings.lock_ttl_seconds.saturating_mul(1_000)
        }) {
            return Err(PluginError::permanent(
                ErrorKind::LockUnavailable,
                "fly_lock_lease_too_short",
                "the configured Fly lock TTL is shorter than the requested mutation lease",
            ));
        }
        if let Some(existing) = self
            .locks
            .lock()
            .await
            .get(&cached.identity.project_id)
            .cloned()
        {
            if existing.operation_id != request.operation_id {
                return Ok(LockAcquireResult {
                    acquired: false,
                    token: None,
                    expires_at: None,
                    holder: Some(existing.operation_id),
                });
            }
            let _lease_check = self.lease_checks.lock().await;
            let existing = self
                .locks
                .lock()
                .await
                .get(&cached.identity.project_id)
                .cloned()
                .ok_or_else(|| {
                    PluginError::permanent(
                        ErrorKind::LockUnavailable,
                        "fly_lock_lost",
                        "the local Fly lease record disappeared during acquisition",
                    )
                })?;
            self.reassert_held(&cached, &existing, LOCK_MARGIN_SECONDS)
                .await?;
            return Ok(LockAcquireResult {
                acquired: true,
                token: Some(SecretValue::new(existing.release_token)),
                expires_at: None,
                holder: None,
            });
        }

        let token = cached.token.expose_secret();
        let app_name = lock_app_name(&cached.identity.project_id, &cached.settings);
        let lock_network = network_name(
            &cached.identity.project_id,
            &format!("project-lock:{}", cached.identity.project_id),
            &cached.settings,
        );
        let listed_lock = self
            .api
            .list_apps(token, &cached.settings.organization)
            .await?
            .into_iter()
            .find(|app| app.name == app_name);
        let existing_app = self.api.get_app(token, &app_name).await?;
        let created_app = existing_app.is_none();
        if let Some(existing_app) = &existing_app {
            let observed_network = listed_lock
                .as_ref()
                .and_then(|app| app.network.as_deref())
                .or(existing_app.network.as_deref());
            match observed_network {
                Some(network) if network != lock_network => {
                    return Err(PluginError::permanent(
                        ErrorKind::Conflict,
                        "fly_lock_network_mismatch",
                        "the deterministic Fly lock App belongs to an unexpected private network",
                    ));
                }
                None => {
                    return Ok(LockAcquireResult {
                        acquired: false,
                        token: None,
                        expires_at: None,
                        holder: Some("Fly lock App initialization in progress".to_owned()),
                    });
                }
                Some(_) => {}
            }
        }
        if created_app {
            match self
                .api
                .create_app(
                    token,
                    &cached.settings.organization,
                    &app_name,
                    &lock_network,
                )
                .await
            {
                Ok(_) => {}
                Err(error) if error.kind == ErrorKind::Conflict => {
                    return Ok(LockAcquireResult {
                        acquired: false,
                        token: None,
                        expires_at: None,
                        holder: Some("Fly lock App creation in progress".to_owned()),
                    });
                }
                Err(error) => return Err(error),
            }
        }
        let machines = match self.api.list_machines(token, &app_name).await {
            Ok(machines) => machines,
            Err(error) if error.kind == ErrorKind::NotFound => {
                return Ok(LockAcquireResult {
                    acquired: false,
                    token: None,
                    expires_at: None,
                    holder: Some("Fly lock App propagation in progress".to_owned()),
                });
            }
            Err(error) => return Err(error),
        };
        let machine =
            if let Some(machine) = exact_lock_sentinel(&machines, &cached.identity.project_id)? {
                machine
            } else {
                let metadata = BTreeMap::from([
                    (MANAGED_KEY.to_owned(), "true".to_owned()),
                    (PROJECT_KEY.to_owned(), cached.identity.project_id.clone()),
                    (ROLE_KEY.to_owned(), "project-lock".to_owned()),
                ]);
                let mut payload = serde_json::Map::from_iter([
                    (
                        "name".to_owned(),
                        Value::String("lightrail-project-lock".to_owned()),
                    ),
                    ("skip_launch".to_owned(), Value::Bool(true)),
                    (
                        "config".to_owned(),
                        json!({
                            "image": PLACEHOLDER_IMAGE,
                            "auto_destroy": false,
                            "metadata": metadata,
                            "guest": {
                                "cpu_kind": "shared",
                                "cpus": 1,
                                "memory_mb": 256
                            }
                        }),
                    ),
                ]);
                if let Some(region) = &cached.settings.region {
                    payload.insert("region".to_owned(), Value::String(region.clone()));
                }
                let creation = self
                    .api
                    .create_machine(token, &app_name, Value::Object(payload))
                    .await;
                match &creation {
                    Err(error) if error.kind == ErrorKind::Conflict => {
                        return Ok(LockAcquireResult {
                            acquired: false,
                            token: None,
                            expires_at: None,
                            holder: Some("Fly lock sentinel creation in progress".to_owned()),
                        });
                    }
                    Err(_) | Ok(_) => {}
                }
                let observed = self.api.list_machines(token, &app_name).await;
                match observed {
                    Ok(machines) => {
                        match exact_lock_sentinel(&machines, &cached.identity.project_id)? {
                            Some(machine) => machine,
                            None => {
                                return creation.map_or_else(Err, |_| {
                                    Err(PluginError::retryable(
                                        ErrorKind::Unavailable,
                                        "fly_lock_sentinel_propagating",
                                        "the Fly lock sentinel is not visible after creation",
                                    ))
                                });
                            }
                        }
                    }
                    Err(observation_error) => {
                        return match creation {
                            Ok(_) => Err(observation_error),
                            Err(creation_error) => Err(creation_error),
                        };
                    }
                }
            };
        let lease = match self
            .api
            .acquire_lease(
                token,
                &app_name,
                &machine.id,
                &request.operation_id,
                cached.settings.lock_ttl_seconds,
            )
            .await
        {
            Ok(lease) => lease,
            Err(error) if error.kind == ErrorKind::Conflict => {
                let holder = self
                    .api
                    .get_lease(token, &app_name, &machine.id)
                    .await?
                    .and_then(|lease| lease.owner);
                return Ok(LockAcquireResult {
                    acquired: false,
                    token: None,
                    expires_at: None,
                    holder,
                });
            }
            Err(error) => return Err(error),
        };
        let expires_at_unix = lease.expires_at_unix.ok_or_else(|| {
            PluginError::permanent(
                ErrorKind::LockUnavailable,
                "fly_lock_expiry_missing",
                "Fly.io returned a finite lease without its Unix expiry",
            )
        })?;
        if expires_at_unix
            <= unix_now()
                .saturating_add(
                    cached
                        .settings
                        .command_timeout_seconds
                        .max(cached.settings.readiness_timeout_seconds),
                )
                .saturating_add(LOCK_MARGIN_SECONDS)
                .saturating_add(PROVIDER_CALL_ALLOWANCE_SECONDS)
        {
            let _ = self
                .api
                .release_lease(token, &app_name, &machine.id, &lease.nonce)
                .await;
            return Err(PluginError::permanent(
                ErrorKind::LockUnavailable,
                "fly_lock_ttl_insufficient",
                "the acquired Fly lease is too short for a bounded provider operation",
            ));
        }
        let release_token = Uuid::new_v4().to_string();
        let held = HeldLock {
            project_id: cached.identity.project_id.clone(),
            scope_id: request.scope_id.clone(),
            operation_id: request.operation_id.clone(),
            release_token: release_token.clone(),
            app: app_name,
            machine: machine.id,
            nonce: lease.nonce,
            expires_at_unix,
        };
        self.locks
            .lock()
            .await
            .insert(cached.identity.project_id, held);
        Ok(LockAcquireResult {
            acquired: true,
            token: Some(SecretValue::new(release_token)),
            expires_at: None,
            holder: None,
        })
    }

    async fn release_lock(&self, request: LockReleaseRequest) -> PluginResult<LockReleaseResult> {
        if request.scope != LockScope::Project {
            return Err(validation(
                "fly_project_lock_required",
                "Fly mutation locks are project scoped",
            ));
        }
        let cached = self.cached_context(&request.environment_id).await?;
        let _lease_check = self.lease_checks.lock().await;
        let held = self
            .locks
            .lock()
            .await
            .get(&cached.identity.project_id)
            .cloned();
        let Some(held) = held else {
            return Ok(LockReleaseResult { released: true });
        };
        if held.scope_id != request.scope_id
            || held.operation_id != request.operation_id
            || held.release_token != request.token.expose_secret()
        {
            return Err(PluginError::permanent(
                ErrorKind::LockUnavailable,
                "fly_lock_owner_mismatch",
                "the Fly project lock is owned by another operation",
            ));
        }
        let released = self
            .api
            .release_lease(
                cached.token.expose_secret(),
                &held.app,
                &held.machine,
                &held.nonce,
            )
            .await;
        if let Err(error) = released {
            if lease_release_lost(&error) {
                self.locks.lock().await.remove(&cached.identity.project_id);
                return Err(PluginError::permanent(
                    ErrorKind::LockUnavailable,
                    "fly_lock_lost",
                    "the locally held Fly lease no longer exists or belongs to another nonce",
                ));
            }
            return Err(error);
        }
        self.locks.lock().await.remove(&cached.identity.project_id);
        Ok(LockReleaseResult { released: true })
    }

    async fn ensure_lock(
        &self,
        context: &lightrail_plugin_protocol::OperationContext,
        minimum_remaining_seconds: u64,
    ) -> PluginResult<()> {
        let cached = self.cached_context(&context.environment_id).await?;
        let _lease_check = self.lease_checks.lock().await;
        let held = self
            .locks
            .lock()
            .await
            .get(&cached.identity.project_id)
            .cloned()
            .ok_or_else(|| {
                PluginError::permanent(
                    ErrorKind::LockUnavailable,
                    "fly_lock_required",
                    "the authoritative Fly project lease is not held",
                )
            })?;
        if held.operation_id != context.operation_id {
            return Err(PluginError::permanent(
                ErrorKind::LockUnavailable,
                "fly_lock_owner_mismatch",
                "the authoritative Fly project lease belongs to another operation",
            ));
        }
        self.reassert_held(&cached, &held, minimum_remaining_seconds)
            .await
    }

    #[allow(clippy::too_many_lines)]
    async fn reassert_held(
        &self,
        cached: &CachedContext,
        held: &HeldLock,
        minimum_remaining_seconds: u64,
    ) -> PluginResult<()> {
        if held.project_id != cached.identity.project_id {
            return Err(PluginError::permanent(
                ErrorKind::LockUnavailable,
                "fly_lock_project_mismatch",
                "the cached Fly lease belongs to another project",
            ));
        }
        let required_remaining_seconds = required_lease_remaining(minimum_remaining_seconds);
        if cached.settings.lock_ttl_seconds <= required_remaining_seconds {
            return Err(PluginError::permanent(
                ErrorKind::LockUnavailable,
                "fly_lock_ttl_insufficient",
                "the configured Fly lease TTL is too short for the next bounded operation and rollback margin",
            ));
        }
        let now = unix_now();
        if lease_needs_refresh(held.expires_at_unix, now, minimum_remaining_seconds) {
            if held.expires_at_unix <= unix_now().saturating_add(PROVIDER_CALL_ALLOWANCE_SECONDS) {
                return Err(PluginError::permanent(
                    ErrorKind::LockUnavailable,
                    "fly_lock_expiring",
                    "the authoritative Fly lease is too close to expiry to refresh safely",
                ));
            }
            let refreshed = self
                .api
                .refresh_lease(
                    cached.token.expose_secret(),
                    &held.app,
                    &held.machine,
                    &held.nonce,
                    cached.settings.lock_ttl_seconds,
                )
                .await?;
            if refreshed.nonce != held.nonce {
                return Err(PluginError::permanent(
                    ErrorKind::LockUnavailable,
                    "fly_lock_nonce_changed",
                    "Fly.io changed the authoritative lease nonce during refresh",
                ));
            }
            let expiry = refreshed.expires_at_unix.ok_or_else(|| {
                PluginError::permanent(
                    ErrorKind::LockUnavailable,
                    "fly_lock_expiry_missing",
                    "Fly.io did not return the refreshed lease expiry",
                )
            })?;
            if expiry <= unix_now().saturating_add(required_remaining_seconds) {
                return Err(PluginError::permanent(
                    ErrorKind::LockUnavailable,
                    "fly_lock_expiring",
                    "the refreshed Fly lease is too short for the next bounded operation",
                ));
            }
            let mut locks = self.locks.lock().await;
            let stored = locks
                .get_mut(&cached.identity.project_id)
                .filter(|stored| {
                    stored.operation_id == held.operation_id && stored.nonce == held.nonce
                })
                .ok_or_else(|| {
                    PluginError::permanent(
                        ErrorKind::LockUnavailable,
                        "fly_lock_lost",
                        "the local Fly lease record changed during refresh",
                    )
                })?;
            stored.expires_at_unix = expiry;
            return Ok(());
        }
        let lease = self
            .api
            .get_lease(cached.token.expose_secret(), &held.app, &held.machine)
            .await?
            .ok_or_else(|| {
                PluginError::permanent(
                    ErrorKind::LockUnavailable,
                    "fly_lock_lost",
                    "the authoritative Fly Machine lease no longer exists",
                )
            })?;
        if lease.nonce != held.nonce {
            return Err(PluginError::permanent(
                ErrorKind::LockUnavailable,
                "fly_lock_nonce_changed",
                "the authoritative Fly Machine lease nonce changed",
            ));
        }
        let expiry = lease.expires_at_unix.ok_or_else(|| {
            PluginError::permanent(
                ErrorKind::LockUnavailable,
                "fly_lock_expiry_missing",
                "Fly.io did not return the lease expiry during continuity checking",
            )
        })?;
        if expiry != held.expires_at_unix
            || expiry <= unix_now().saturating_add(required_remaining_seconds)
        {
            return Err(PluginError::permanent(
                ErrorKind::LockUnavailable,
                "fly_lock_expiring",
                "the authoritative Fly lease does not have enough time remaining for the next bounded operation",
            ));
        }
        Ok(())
    }
}

#[derive(Clone)]
struct EnvironmentSummary {
    project_id: String,
    environment_id: String,
    profile: String,
    branch: String,
    status: ResourceStatus,
    endpoints: Vec<Endpoint>,
    expires_at_unix: Option<u64>,
    mismatch: bool,
    missing_expiry: bool,
}

impl EnvironmentSummary {
    fn new(cached: &CachedContext, owned: &OwnedApp, expiry: Option<u64>) -> Self {
        Self {
            project_id: cached.identity.project_id.clone(),
            environment_id: owned.environment_id.clone(),
            profile: owned.profile.clone(),
            branch: owned.branch.clone(),
            status: ResourceStatus::Ready,
            endpoints: Vec::new(),
            expires_at_unix: expiry,
            mismatch: false,
            missing_expiry: expiry.is_none(),
        }
    }

    fn into_value(self) -> Value {
        let mut value = serde_json::Map::from_iter([
            ("project_id".to_owned(), Value::String(self.project_id)),
            (
                "environment_id".to_owned(),
                Value::String(self.environment_id),
            ),
            ("profile".to_owned(), Value::String(self.profile)),
            ("branch".to_owned(), Value::String(self.branch)),
            (
                "status".to_owned(),
                serde_json::to_value(self.status).unwrap_or(Value::String("unknown".to_owned())),
            ),
            (
                "endpoints".to_owned(),
                serde_json::to_value(self.endpoints).unwrap_or_else(|_| Value::Array(Vec::new())),
            ),
        ]);
        if !self.missing_expiry {
            if let Some(expiry) = self.expires_at_unix {
                value.insert("expires_at_unix".to_owned(), Value::from(expiry));
            }
        }
        Value::Object(value)
    }
}

fn config_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "organization": { "type": "string", "default": "personal" },
            "region": { "type": ["string", "null"] },
            "token": {
                "type": "object",
                "properties": { "secret": { "const": "fly-token" } },
                "required": ["secret"],
                "additionalProperties": false
            },
            "registry": { "const": "registry.fly.io" },
            "platform": {
                "type": "string",
                "enum": ["linux/amd64", "linux/arm64"],
                "default": "linux/amd64"
            },
            "app_prefix": { "type": "string", "default": "lr" },
            "cpu_kind": { "type": "string", "default": "shared" },
            "cpus": { "type": "integer", "minimum": 1, "default": 1 },
            "memory_mb": {
                "type": "integer",
                "minimum": 256,
                "multipleOf": 256,
                "default": 256
            },
            "auto_stop": { "type": "boolean", "default": true },
            "lock_ttl_seconds": {
                "type": "integer",
                "minimum": 60,
                "maximum": 86400,
                "default": 3600,
                "description": "Must exceed max(command_timeout_seconds, readiness_timeout_seconds) by more than 180 seconds"
            },
            "ttl_hours": { "type": "integer", "minimum": 1, "default": 72 },
            "volume_size_gb": { "type": "integer", "minimum": 1, "default": 3 },
            "command_timeout_seconds": {
                "type": "integer",
                "minimum": 10,
                "maximum": 3000,
                "default": 300
            },
            "readiness_timeout_seconds": {
                "type": "integer",
                "minimum": 10,
                "maximum": 3000,
                "default": 300
            }
        }
    })
}

async fn read_compose(desired: &DesiredState) -> PluginResult<Value> {
    let path = desired.resolved_compose_path.as_deref().ok_or_else(|| {
        validation(
            "resolved_compose_required",
            "Fly up requires core's ephemeral resolved Compose document",
        )
    })?;
    if !path.is_absolute() {
        return Err(validation(
            "resolved_compose_must_be_absolute",
            "the ephemeral resolved Compose path must be absolute",
        ));
    }
    let bytes = tokio::fs::read(path).await.map_err(|error| {
        validation(
            "resolved_compose_unreadable",
            format!("could not read the ephemeral resolved Compose document: {error}"),
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        validation(
            "resolved_compose_invalid",
            format!("the ephemeral resolved Compose document is invalid JSON: {error}"),
        )
    })
}

fn validate_workloads(
    desired: &DesiredState,
    settings: &Settings,
    workloads: &[Workload],
    context: &lightrail_plugin_protocol::OperationContext,
) -> PluginResult<()> {
    if workloads.is_empty() {
        return Err(validation(
            "compose_services_required",
            "Fly deployment requires at least one Compose service",
        ));
    }
    if settings.region.is_none() && workloads.iter().any(|workload| workload.volume.is_some()) {
        return Err(validation(
            "fly_volume_region_required",
            "`region` is required when a Compose service uses a named volume",
        ));
    }
    let _ = resolve_app_environment(desired, &context.secrets)?;
    for workload in workloads {
        for value in workload.environment.values() {
            for secret in context.secrets.values() {
                let secret = secret.expose_secret();
                if !secret.is_empty() && value.contains(secret) {
                    return Err(PluginError::permanent(
                        ErrorKind::Unsupported,
                        "resolved_compose_secret_unsupported",
                        format!(
                            "service `{}` contains a resolved secret value; Fly Machine config.env is provider-readable",
                            workload.service
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn require_capability(capability: &Capability) -> PluginResult<()> {
    if matches!(
        capability,
        Capability::Builder
            | Capability::Target
            | Capability::Runtime
            | Capability::Exposure
            | Capability::Dns
    ) {
        Ok(())
    } else {
        Err(unsupported_capability(capability))
    }
}

fn unsupported_capability(capability: &Capability) -> PluginError {
    PluginError::permanent(
        ErrorKind::Unsupported,
        "fly_capability_unsupported",
        format!("Fly plugin does not implement capability `{capability}` operations"),
    )
}

fn metadata<'a>(machine: &'a Machine, key: &str) -> Option<&'a str> {
    machine.metadata().get(key).map(String::as_str)
}

fn exact_lock_sentinel(machines: &[Machine], project_id: &str) -> PluginResult<Option<Machine>> {
    if machines.is_empty() {
        return Ok(None);
    }
    if machines.len() == 1
        && metadata(&machines[0], MANAGED_KEY) == Some("true")
        && metadata(&machines[0], PROJECT_KEY) == Some(project_id)
        && metadata(&machines[0], ROLE_KEY) == Some("project-lock")
    {
        return Ok(Some(machines[0].clone()));
    }
    Err(PluginError::permanent(
        ErrorKind::Conflict,
        "fly_lock_ownership_mismatch",
        "the deterministic Fly lock App does not contain exactly one owned sentinel Machine",
    ))
}

fn lease_release_lost(error: &PluginError) -> bool {
    matches!(error.kind, ErrorKind::NotFound | ErrorKind::Conflict)
}

fn metadata_values<'a>(machines: &'a [Machine], key: &str) -> BTreeSet<&'a str> {
    machines
        .iter()
        .filter_map(|machine| metadata(machine, key))
        .collect()
}

fn first<'a>(values: &'a BTreeSet<&'a str>) -> &'a str {
    values.first().copied().unwrap_or_default()
}

fn require_clean_discovery(discovery: &Discovery) -> PluginResult<()> {
    if discovery.conflicts.is_empty() {
        return Ok(());
    }
    Err(PluginError::permanent(
        ErrorKind::Conflict,
        "fly_ownership_conflict",
        discovery.conflicts.join("; "),
    ))
}

impl CapturedApp {
    fn from_owned(owned: &OwnedApp) -> Self {
        Self {
            app: owned.app.name.clone(),
            app_id: Some(owned.app.id.clone()),
            network: owned.app.network.clone().unwrap_or_default(),
            environment_id: Some(owned.environment_id.clone()),
            service: Some(owned.service.clone()),
            machine_ids: owned
                .machines
                .iter()
                .map(|machine| machine.id.clone())
                .collect(),
            volume_ids: owned
                .volumes
                .iter()
                .map(|volume| volume.id.clone())
                .collect(),
            orphan: false,
        }
    }

    fn from_orphan(orphan: &OrphanApp) -> Self {
        Self {
            app: orphan.app.name.clone(),
            app_id: Some(orphan.app.id.clone()),
            network: orphan.app.network.clone().unwrap_or_default(),
            environment_id: orphan.environment_id.clone(),
            service: None,
            machine_ids: BTreeSet::new(),
            volume_ids: orphan
                .volumes
                .iter()
                .map(|volume| volume.id.clone())
                .collect(),
            orphan: true,
        }
    }

    fn from_provisional(provisional: ProvisionalApp) -> Self {
        let orphan = provisional.machine_ids.is_empty();
        Self {
            app: provisional.app,
            app_id: provisional.app_id,
            network: provisional.network,
            environment_id: Some(provisional.environment_id),
            service: None,
            machine_ids: provisional.machine_ids,
            volume_ids: provisional.volume_ids,
            orphan,
        }
    }
}

fn captured_apps_from_discovery(discovery: &Discovery) -> Vec<CapturedApp> {
    discovery
        .owned
        .iter()
        .map(CapturedApp::from_owned)
        .chain(discovery.orphans.iter().map(CapturedApp::from_orphan))
        .collect()
}

fn captured_apps_from_state(
    current: Option<&Value>,
    cached: &CachedContext,
) -> PluginResult<Vec<CapturedApp>> {
    let Some(current) = current else {
        return Ok(Vec::new());
    };
    if current.get("provider").and_then(Value::as_str) != Some("fly")
        || current.get("project_id").and_then(Value::as_str)
            != Some(cached.identity.project_id.as_str())
        || current.get("organization").and_then(Value::as_str)
            != Some(cached.settings.organization.as_str())
    {
        return Err(PluginError::permanent(
            ErrorKind::Conflict,
            "fly_destroy_snapshot_identity_mismatch",
            "the inspected Fly destroy snapshot does not match this project and organization",
        ));
    }
    let apps = current
        .get("apps")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            PluginError::permanent(
                ErrorKind::Conflict,
                "fly_destroy_snapshot_incomplete",
                "the inspected Fly state does not contain an exact App resource snapshot",
            )
        })?;
    let marker = project_app_marker(&cached.identity.project_id, &cached.settings);
    let network_prefix = network_prefix(&cached.identity.project_id, &cached.settings);
    let mut captured = Vec::with_capacity(apps.len());
    let mut names = BTreeSet::new();
    for item in apps {
        let app = required_state_string(item, "app")?;
        let app_id = required_state_string(item, "app_id")?;
        let network = required_state_string(item, "network")?;
        if item.get("project_id").and_then(Value::as_str)
            != Some(cached.identity.project_id.as_str())
            || !app.contains(&marker)
            || !network.starts_with(&network_prefix)
        {
            return Err(PluginError::permanent(
                ErrorKind::Conflict,
                "fly_destroy_snapshot_ownership_mismatch",
                format!(
                    "the inspected snapshot for Fly App `{app}` does not carry the exact project identity"
                ),
            ));
        }
        if !names.insert(app.to_owned()) {
            return Err(PluginError::permanent(
                ErrorKind::Conflict,
                "fly_destroy_snapshot_duplicate",
                format!("the inspected snapshot contains Fly App `{app}` more than once"),
            ));
        }
        let machine_ids = required_state_string_set(item, "machine_ids")?;
        let volume_ids = required_state_string_set(item, "volume_ids")?;
        let orphan = item.get("orphan").and_then(Value::as_bool).unwrap_or(false);
        if orphan != machine_ids.is_empty() {
            return Err(PluginError::permanent(
                ErrorKind::Conflict,
                "fly_destroy_snapshot_incomplete",
                format!(
                    "the inspected snapshot for Fly App `{app}` has inconsistent orphan and Machine identity"
                ),
            ));
        }
        captured.push(CapturedApp {
            app: app.to_owned(),
            app_id: Some(app_id.to_owned()),
            network: network.to_owned(),
            environment_id: item
                .get("environment_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            service: item
                .get("service")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            machine_ids,
            volume_ids,
            orphan,
        });
    }
    Ok(captured)
}

fn required_state_string<'a>(item: &'a Value, field: &str) -> PluginResult<&'a str> {
    item.get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            PluginError::permanent(
                ErrorKind::Conflict,
                "fly_destroy_snapshot_incomplete",
                format!("the inspected Fly destroy snapshot is missing `{field}`"),
            )
        })
}

fn required_state_string_set(item: &Value, field: &str) -> PluginResult<BTreeSet<String>> {
    let values = item.get(field).and_then(Value::as_array).ok_or_else(|| {
        PluginError::permanent(
            ErrorKind::Conflict,
            "fly_destroy_snapshot_incomplete",
            format!("the inspected Fly destroy snapshot is missing `{field}`"),
        )
    })?;
    let mut output = BTreeSet::new();
    for value in values {
        let value = value
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                PluginError::permanent(
                    ErrorKind::Conflict,
                    "fly_destroy_snapshot_incomplete",
                    format!("the inspected Fly destroy snapshot has an invalid `{field}` entry"),
                )
            })?;
        if !output.insert(value.to_owned()) {
            return Err(PluginError::permanent(
                ErrorKind::Conflict,
                "fly_destroy_snapshot_duplicate",
                format!("the inspected Fly destroy snapshot repeats `{field}` ID `{value}`"),
            ));
        }
    }
    Ok(output)
}

fn merge_captured(
    captured: &mut Vec<CapturedApp>,
    additional: Vec<CapturedApp>,
) -> PluginResult<()> {
    for item in additional {
        if let Some(existing) = captured
            .iter_mut()
            .find(|existing| existing.app == item.app)
        {
            if existing.app_id != item.app_id
                || existing.network != item.network
                || existing.environment_id != item.environment_id
                || existing.machine_ids != item.machine_ids
                || existing.volume_ids != item.volume_ids
                || existing.orphan != item.orphan
                || existing
                    .service
                    .as_ref()
                    .zip(item.service.as_ref())
                    .is_some_and(|(left, right)| left != right)
            {
                return Err(PluginError::permanent(
                    ErrorKind::Conflict,
                    "fly_destroy_snapshot_conflict",
                    format!(
                        "independent ownership snapshots disagree for Fly App `{}`",
                        item.app
                    ),
                ));
            }
            if existing.service.is_none() {
                existing.service = item.service;
            }
        } else {
            captured.push(item);
        }
    }
    captured.sort_by(|left, right| left.app.cmp(&right.app));
    Ok(())
}

fn select_captured(
    captured: Vec<CapturedApp>,
    current_environment: &str,
    all: bool,
    selection: Option<&BTreeSet<String>>,
) -> Vec<CapturedApp> {
    if let Some(selection) = selection {
        return captured
            .into_iter()
            .filter(|app| {
                app.environment_id
                    .as_ref()
                    .is_some_and(|environment| selection.contains(environment))
            })
            .collect();
    }
    if all {
        captured
    } else {
        captured
            .into_iter()
            .filter(|app| app.environment_id.as_deref() == Some(current_environment))
            .collect()
    }
}

fn assert_destroy_continuity(captured: &[CapturedApp], live: &[CapturedApp]) -> PluginResult<()> {
    for live_app in live {
        let Some(expected) = captured
            .iter()
            .find(|expected| expected.app == live_app.app)
        else {
            return Err(destroy_plan_drift(format!(
                "Fly App `{}` appeared after the inspected destroy snapshot",
                live_app.app
            )));
        };
        if expected.app_id != live_app.app_id
            || expected.network != live_app.network
            || expected.environment_id != live_app.environment_id
            || expected.machine_ids != live_app.machine_ids
            || expected.volume_ids != live_app.volume_ids
            || expected.orphan != live_app.orphan
            || expected
                .service
                .as_ref()
                .is_some_and(|service| live_app.service.as_ref() != Some(service))
        {
            return Err(destroy_plan_drift(format!(
                "Fly App `{}` changed Machines, Volumes, network, or ownership after inspection",
                live_app.app
            )));
        }
    }
    Ok(())
}

fn destroy_plan_drift(message: impl Into<String>) -> PluginError {
    PluginError::permanent(ErrorKind::Conflict, "fly_destroy_plan_drift", message)
}

fn plan_destroy_actions(
    capability: &Capability,
    current_environment: &str,
    all: bool,
    selection: Option<&BTreeSet<String>>,
    discovery: &Discovery,
) -> Vec<PlannedAction> {
    if capability != &Capability::Target {
        return Vec::new();
    }
    select_captured(
        captured_apps_from_discovery(discovery),
        current_environment,
        all,
        selection,
    )
    .into_iter()
    .map(|captured| PlannedAction {
        id: format!("target.delete.{}", captured.app),
        kind: "fly.target.delete".to_owned(),
        summary: format!("Delete owned Fly App `{}`", captured.app),
        destructive: true,
        depends_on: Vec::new(),
        rollback: Some(RollbackMetadata {
            supported: false,
            action: None,
            token: None,
            metadata: json!({
                "reason": "deleting an environment-owned Fly App, Machine, or volume has no exact inverse"
            }),
        }),
        metadata: json!({
        "app": captured.app,
        "environment_id": captured.environment_id,
        "service": captured.service,
        "machine_ids": captured.machine_ids,
        "volume_ids": captured.volume_ids,
        "orphan": captured.orphan,
        }),
    })
    .collect()
}

fn action(
    id: String,
    kind: &str,
    summary: String,
    destructive: bool,
    workload: &Workload,
) -> PlannedAction {
    let rollback = match kind {
        "fly.target.create" => Some(RollbackMetadata {
            supported: true,
            action: Some("fly.target.cleanup".to_owned()),
            token: None,
            metadata: json!({
                "app": workload.app_name,
                "scope": "whole_capability",
                "reason": "delete the exact provisional Apps, Machines, and volumes recorded during initial Target creation"
            }),
        }),
        "fly.runtime.reconcile" => Some(RollbackMetadata {
            supported: false,
            action: None,
            token: None,
            metadata: json!({
                "reason": "Fly Machine updates can change application data and have no exact automatic inverse"
            }),
        }),
        "fly.exposure.allocate_ip" => Some(RollbackMetadata {
            supported: true,
            action: Some("fly.exposure.release_ip".to_owned()),
            token: None,
            metadata: json!({
                "app": workload.app_name,
                "reason": "release the exact shared IPv4 allocated by this operation"
            }),
        }),
        "fly.dns.refresh_expiry" => Some(RollbackMetadata {
            supported: true,
            action: Some("fly.dns.restore_expiry".to_owned()),
            token: None,
            metadata: json!({
                "app": workload.app_name,
                "reason": "restore the exact prior expiry metadata after a failed final commit"
            }),
        }),
        _ => None,
    };
    PlannedAction {
        id,
        kind: kind.to_owned(),
        summary,
        destructive,
        depends_on: Vec::new(),
        rollback,
        metadata: json!({
            "app": workload.app_name,
            "service": workload.service,
        }),
    }
}

fn combine_status(current: ResourceStatus, next: ResourceStatus) -> ResourceStatus {
    use ResourceStatus::{Absent, Degraded, Destroying, Pending, Ready, Unknown};
    match (current, next) {
        (Unknown, _) | (_, Unknown) => Unknown,
        (Degraded, _) | (_, Degraded) => Degraded,
        (Destroying, _) | (_, Destroying) => Destroying,
        (Pending, _) | (_, Pending) => Pending,
        (Ready, Ready) => Ready,
        (Absent, value) | (value, Absent) => value,
    }
}

fn required_lease_remaining(minimum_remaining_seconds: u64) -> u64 {
    minimum_remaining_seconds.saturating_add(PROVIDER_CALL_ALLOWANCE_SECONDS)
}

fn lease_needs_refresh(
    expires_at_unix: u64,
    now_unix: u64,
    minimum_remaining_seconds: u64,
) -> bool {
    expires_at_unix
        <= now_unix
            .saturating_add(required_lease_remaining(minimum_remaining_seconds))
            .saturating_add(PROVIDER_CALL_ALLOWANCE_SECONDS)
}

struct PublicInspection {
    app_name: String,
    shared_ip: Option<String>,
    ready: bool,
}

#[async_trait]
trait MachineMetadataApi: Sync {
    async fn set_expiry(
        &self,
        token: &str,
        app: &str,
        machine: &str,
        value: &str,
    ) -> PluginResult<()>;

    async fn delete_expiry(&self, token: &str, app: &str, machine: &str) -> PluginResult<()>;
}

#[async_trait]
impl MachineMetadataApi for dyn FlyApi {
    async fn set_expiry(
        &self,
        token: &str,
        app: &str,
        machine: &str,
        value: &str,
    ) -> PluginResult<()> {
        self.set_machine_metadata(token, app, machine, EXPIRES_KEY, value)
            .await
    }

    async fn delete_expiry(&self, token: &str, app: &str, machine: &str) -> PluginResult<()> {
        self.delete_machine_metadata(token, app, machine, EXPIRES_KEY)
            .await
    }
}

async fn write_expiry_metadata<A>(
    metadata_api: &A,
    token: &str,
    app: &str,
    machine: &str,
    value: Option<&str>,
) -> PluginResult<()>
where
    A: MachineMetadataApi + ?Sized,
{
    match value {
        Some(value) => metadata_api.set_expiry(token, app, machine, value).await,
        None => metadata_api.delete_expiry(token, app, machine).await,
    }
}

async fn wait_all_inspection_probes<I, F, T>(
    futures: I,
    timeout: Duration,
    cancellation: &Cancellation,
) -> PluginResult<Vec<T>>
where
    I: IntoIterator<Item = F>,
    F: Future<Output = PluginResult<T>>,
{
    tokio::select! {
        result = tokio::time::timeout(timeout, try_join_all(futures)) => {
            result.unwrap_or_else(|_| {
                Err(PluginError::retryable(
                    ErrorKind::Timeout,
                    "fly_inspection_probe_timeout",
                    "Fly public App inspection exceeded the shared readiness deadline",
                ))
            })
        }
        () = cancellation.cancelled() => Err(PluginError::permanent(
            ErrorKind::Cancelled,
            "operation_cancelled",
            "the Fly.io operation was cancelled",
        )),
    }
}

async fn public_ready(
    api: &dyn FlyApi,
    app_name: &str,
    health_path: &str,
    expected_status: Option<u16>,
) -> PluginResult<bool> {
    let path = if health_path.starts_with('/') {
        health_path
    } else {
        return Err(validation(
            "invalid_health_path",
            "Fly health paths must begin with `/`",
        ));
    };
    let hostname = format!("{app_name}.fly.dev");
    let https = api
        .public_probe(&format!("https://{hostname}{path}"))
        .await?;
    if https.is_none_or(|response| !health_status_matches(response.status, expected_status)) {
        return Ok(false);
    }
    let http = api
        .public_probe(&format!("http://{hostname}{path}"))
        .await?;
    Ok(http.is_some_and(|response| redirect_is_https(&response, &hostname)))
}

async fn wait_all_readiness<I, F>(futures: I) -> PluginResult<()>
where
    I: IntoIterator<Item = F>,
    F: Future<Output = PluginResult<()>>,
{
    try_join_all(futures).await?;
    Ok(())
}

fn health_status_matches(status: u16, expected: Option<u16>) -> bool {
    expected.map_or(status < 500, |expected| status == expected)
}

fn redirect_is_https(response: &PublicResponse, hostname: &str) -> bool {
    matches!(response.status, 301 | 302 | 307 | 308)
        && response
            .location
            .as_deref()
            .and_then(|location| location.strip_prefix(&format!("https://{hostname}")))
            .is_some_and(|suffix| {
                suffix.is_empty()
                    || suffix.starts_with('/')
                    || suffix.starts_with('?')
                    || suffix.starts_with('#')
            })
}

fn volume_deletion_complete(volume: &Volume) -> bool {
    matches!(volume.state.as_str(), "pending_destroy" | "destroyed")
}

async fn wait_retry(cancellation: &Cancellation) -> PluginResult<()> {
    tokio::select! {
        () = tokio::time::sleep(Duration::from_secs(1)) => Ok(()),
        () = cancellation.cancelled() => cancellation.check(),
    }
}

fn diagnostic(error: PluginError) -> Diagnostic {
    Diagnostic {
        severity: DiagnosticSeverity::Error,
        code: error.code,
        message: error.message,
        path: None,
        help: None,
    }
}

#[allow(clippy::needless_pass_by_value)]
fn internal_json(error: serde_json::Error) -> PluginError {
    PluginError::permanent(
        ErrorKind::Internal,
        "fly_json_failed",
        format!("could not serialize internal Fly state: {error}"),
    )
}

fn stale_plan(message: &str) -> PluginError {
    PluginError::permanent(ErrorKind::Conflict, "stale_or_modified_plan", message)
}

fn decode_plan(plan: &PlanResult) -> PluginResult<PlanData> {
    let data: PlanData = serde_json::from_value(plan.metadata.clone()).map_err(|_| {
        validation(
            "invalid_fly_plan",
            "the Fly plan metadata is missing or invalid",
        )
    })?;
    if data.schema != 1 {
        return Err(validation(
            "invalid_fly_plan",
            "the Fly plan metadata schema is unsupported",
        ));
    }
    Ok(data)
}

fn verify_plan(plan: &PlanResult) -> PluginResult<()> {
    if plan.plan_id != plan_id(&plan.metadata, &plan.actions)
        || plan.has_changes == plan.actions.is_empty()
    {
        return Err(stale_plan(
            "the supplied Fly plan ID or change flag does not match its exact actions",
        ));
    }
    Ok(())
}

impl FlyPlugin {
    #[allow(clippy::too_many_arguments)]
    async fn apply_target(
        &self,
        context: &lightrail_plugin_protocol::OperationContext,
        settings: &Settings,
        data: &PlanData,
        actions: &[PlannedAction],
        journal: &mut Vec<ActionJournalEntry>,
        events: &EventSink,
        cancellation: &Cancellation,
    ) -> PluginResult<()> {
        if data.desired.destroy {
            if !actions.is_empty() {
                return Err(stale_plan(
                    "target destroy plans are applied through plugin.destroy",
                ));
            }
            return Ok(());
        }
        let compose = read_compose(&data.desired).await?;
        let observed_revision = revision(&data.desired, &compose, settings, &context.operation_id)?;
        if observed_revision != data.revision {
            return Err(stale_plan(
                "resolved Compose content changed after the target plan was created",
            ));
        }
        let workloads = workloads(&data.desired, settings, &compose, &data.revision)?;
        validate_workloads(&data.desired, settings, &workloads, context)?;
        for action in actions {
            if action.kind != "fly.target.create" {
                return Err(stale_plan("target plan contains an unsupported action"));
            }
            cancellation.check()?;
            let app_name = action_app(action)?;
            let workload = find_workload(&workloads, app_name)?;
            journal_event(
                events,
                &context.operation_id,
                journal,
                &action.id,
                JournalStatus::Started,
                "Creating Fly App and placeholder Machine",
            )
            .await?;
            let result = self
                .create_target_app(context, settings, data, workload)
                .await;
            match result {
                Ok(()) => {
                    journal_event(
                        events,
                        &context.operation_id,
                        journal,
                        &action.id,
                        JournalStatus::Succeeded,
                        "Created Fly App and placeholder Machine",
                    )
                    .await?;
                }
                Err(error) => {
                    journal_event(
                        events,
                        &context.operation_id,
                        journal,
                        &action.id,
                        JournalStatus::Failed,
                        &error.message,
                    )
                    .await?;
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    async fn create_target_app(
        &self,
        context: &lightrail_plugin_protocol::OperationContext,
        settings: &Settings,
        data: &PlanData,
        workload: &Workload,
    ) -> PluginResult<()> {
        let token = context_token(context, settings)?;
        self.ensure_lock(context, LOCK_MARGIN_SECONDS).await?;
        if self
            .api
            .get_app(token.expose_secret(), &workload.app_name)
            .await?
            .is_some()
        {
            return Err(stale_plan(
                "a planned Fly App name became occupied before apply",
            ));
        }
        self.ensure_lock(context, LOCK_MARGIN_SECONDS).await?;
        self.remember_provisional(
            &context.operation_id,
            ProvisionalApp {
                project_id: data.desired.project.id.clone(),
                environment_id: data.desired.environment.id.clone(),
                app: workload.app_name.clone(),
                app_id: None,
                network: data.network.clone(),
                machine_ids: BTreeSet::new(),
                volume_ids: BTreeSet::new(),
            },
        )
        .await?;
        let app = match self
            .api
            .create_app(
                token.expose_secret(),
                &settings.organization,
                &workload.app_name,
                &data.network,
            )
            .await
        {
            Ok(app) => app,
            Err(error) => {
                if error.retryable {
                    if let Ok(Some(observed)) = self
                        .api
                        .get_app(token.expose_secret(), &workload.app_name)
                        .await
                    {
                        if observed.network.as_deref() == Some(data.network.as_str())
                            && !observed.id.is_empty()
                        {
                            let _ = self
                                .record_provisional_app_id(
                                    &context.operation_id,
                                    &workload.app_name,
                                    &observed.id,
                                )
                                .await;
                        }
                    }
                } else {
                    self.forget_provisional(&context.operation_id, &workload.app_name)
                        .await;
                }
                return Err(error);
            }
        };
        self.record_provisional_app_id(&context.operation_id, &workload.app_name, &app.id)
            .await?;
        if app
            .network
            .as_deref()
            .is_some_and(|network| network != data.network)
        {
            if self
                .api
                .delete_app(token.expose_secret(), &workload.app_name, false)
                .await
                .is_ok()
            {
                self.forget_provisional(&context.operation_id, &workload.app_name)
                    .await;
            }
            return Err(PluginError::permanent(
                ErrorKind::Conflict,
                "fly_network_mismatch",
                "Fly.io created the App in an unexpected private network",
            ));
        }

        let result = async {
            let volume = if let Some(mount) = &workload.volume {
                self.ensure_lock(context, LOCK_MARGIN_SECONDS).await?;
                let region = settings.region.as_deref().ok_or_else(|| {
                    validation(
                        "fly_volume_region_required",
                        "`region` is required to create Fly volumes",
                    )
                })?;
                let expected_name =
                    volume_name(&data.desired.environment.id, &workload.service, &mount.name);
                let volume = match self
                    .api
                    .create_volume(
                        token.expose_secret(),
                        &workload.app_name,
                        json!({
                            "name": expected_name.clone(),
                            "region": region,
                            "size_gb": settings.volume_size_gb,
                        }),
                    )
                    .await
                {
                    Ok(volume) => volume,
                    Err(error) => {
                        if error.retryable {
                            if let Ok(volumes) = self
                                .api
                                .list_volumes(token.expose_secret(), &workload.app_name)
                                .await
                            {
                                let matching = volumes
                                    .iter()
                                    .filter(|volume| volume.name == expected_name)
                                    .collect::<Vec<_>>();
                                if matching.len() == 1 {
                                    self.record_provisional_volume(
                                        &context.operation_id,
                                        &workload.app_name,
                                        &matching[0].id,
                                    )
                                    .await?;
                                }
                            }
                        }
                        return Err(error);
                    }
                };
                self.record_provisional_volume(
                    &context.operation_id,
                    &workload.app_name,
                    &volume.id,
                )
                .await?;
                if volume.size_gb != settings.volume_size_gb {
                    return Err(PluginError::retryable(
                        ErrorKind::Unavailable,
                        "fly_volume_size_mismatch",
                        format!(
                            "Fly.io created Volume `{}` at {} GiB instead of the requested {} GiB",
                            volume.id, volume.size_gb, settings.volume_size_gb
                        ),
                    ));
                }
                Some((volume.id, mount.path.clone()))
            } else {
                None
            };
            self.ensure_lock(context, LOCK_MARGIN_SECONDS).await?;
            let identity = Identity::from_context(context, Some(&data.desired))?;
            let payload = placeholder_payload(settings, &identity, workload, volume);
            let machine = match self
                .api
                .create_machine(token.expose_secret(), &workload.app_name, payload)
                .await
            {
                Ok(machine) => machine,
                Err(error) => {
                    if error.retryable {
                        if let Ok(machines) = self
                            .api
                            .list_machines(token.expose_secret(), &workload.app_name)
                            .await
                        {
                            let matching = machines
                                .iter()
                                .filter(|machine| {
                                    metadata(machine, MANAGED_KEY) == Some("true")
                                        && metadata(machine, PROJECT_KEY)
                                            == Some(identity.project_id.as_str())
                                        && metadata(machine, ENVIRONMENT_KEY)
                                            == Some(identity.environment_id.as_str())
                                        && metadata(machine, SERVICE_KEY)
                                            == Some(workload.service.as_str())
                                        && metadata(machine, ROLE_KEY) == Some("target-placeholder")
                                })
                                .collect::<Vec<_>>();
                            if matching.len() == 1 {
                                self.record_provisional_machine(
                                    &context.operation_id,
                                    &workload.app_name,
                                    &matching[0].id,
                                )
                                .await?;
                            }
                        }
                    }
                    return Err(error);
                }
            };
            self.record_provisional_machine(&context.operation_id, &workload.app_name, &machine.id)
                .await?;
            Ok(())
        }
        .await;
        if result.is_err() {
            let provisional = self
                .provisional_apps
                .lock()
                .await
                .get(&context.operation_id)
                .and_then(|apps| {
                    apps.iter()
                        .find(|item| item.app == workload.app_name)
                        .cloned()
                });
            if let Some(provisional) = provisional {
                let cached = self.cached_context(&context.environment_id).await?;
                if self
                    .delete_provisional_app(context, &cached, &provisional)
                    .await
                    .is_ok()
                {
                    self.forget_provisional(&context.operation_id, &workload.app_name)
                        .await;
                }
            }
        }
        result
    }

    async fn remember_provisional(
        &self,
        operation_id: &str,
        planned: ProvisionalApp,
    ) -> PluginResult<()> {
        let mut provisional = self.provisional_apps.lock().await;
        let apps = provisional.entry(operation_id.to_owned()).or_default();
        if let Some(existing) = apps.iter().find(|item| item.app == planned.app) {
            if existing.project_id != planned.project_id
                || existing.environment_id != planned.environment_id
                || existing.network != planned.network
                || existing
                    .app_id
                    .as_ref()
                    .zip(planned.app_id.as_ref())
                    .is_some_and(|(left, right)| left != right)
            {
                return Err(PluginError::permanent(
                    ErrorKind::Conflict,
                    "fly_provisional_identity_conflict",
                    "the operation already recorded a different exact Fly App identity",
                ));
            }
            return Ok(());
        }
        apps.push(planned);
        Ok(())
    }

    async fn record_provisional_machine(
        &self,
        operation_id: &str,
        app: &str,
        machine_id: &str,
    ) -> PluginResult<()> {
        self.record_provisional_resource(operation_id, app, machine_id, true)
            .await
    }

    async fn record_provisional_app_id(
        &self,
        operation_id: &str,
        app: &str,
        app_id: &str,
    ) -> PluginResult<()> {
        if app_id.is_empty() {
            return Err(PluginError::retryable(
                ErrorKind::Unavailable,
                "created_fly_app_id_missing",
                "Fly.io did not report the immutable ID of the created App",
            ));
        }
        let mut provisional = self.provisional_apps.lock().await;
        let item = provisional
            .get_mut(operation_id)
            .and_then(|apps| apps.iter_mut().find(|item| item.app == app))
            .ok_or_else(|| {
                PluginError::permanent(
                    ErrorKind::Internal,
                    "fly_provisional_state_lost",
                    "the exact provisional Fly App record was lost during creation",
                )
            })?;
        if item
            .app_id
            .as_ref()
            .is_some_and(|existing| existing != app_id)
        {
            return Err(PluginError::permanent(
                ErrorKind::Conflict,
                "fly_provisional_app_id_conflict",
                "Fly.io reported two immutable IDs for the provisional App",
            ));
        }
        item.app_id = Some(app_id.to_owned());
        Ok(())
    }

    async fn record_provisional_volume(
        &self,
        operation_id: &str,
        app: &str,
        volume_id: &str,
    ) -> PluginResult<()> {
        self.record_provisional_resource(operation_id, app, volume_id, false)
            .await
    }

    async fn record_provisional_resource(
        &self,
        operation_id: &str,
        app: &str,
        resource_id: &str,
        machine: bool,
    ) -> PluginResult<()> {
        let mut provisional = self.provisional_apps.lock().await;
        let item = provisional
            .get_mut(operation_id)
            .and_then(|apps| apps.iter_mut().find(|item| item.app == app))
            .ok_or_else(|| {
                PluginError::permanent(
                    ErrorKind::Internal,
                    "fly_provisional_state_lost",
                    "the exact provisional Fly ownership record was lost during creation",
                )
            })?;
        if machine {
            item.machine_ids.insert(resource_id.to_owned());
        } else {
            item.volume_ids.insert(resource_id.to_owned());
        }
        Ok(())
    }

    async fn verify_initial_target(
        &self,
        context: &lightrail_plugin_protocol::OperationContext,
        data: &PlanData,
        workload: &Workload,
        machine: &Machine,
        token: &str,
    ) -> PluginResult<()> {
        let provisional = self
            .provisional_apps
            .lock()
            .await
            .get(&context.operation_id)
            .and_then(|apps| {
                apps.iter()
                    .find(|item| item.app == workload.app_name)
                    .cloned()
            })
            .ok_or_else(|| {
                stale_plan(
                    "a newly planned Fly runtime has no exact Target creation continuity record",
                )
            })?;
        if provisional.project_id != data.desired.project.id
            || provisional.environment_id != data.desired.environment.id
            || provisional.network != data.network
            || provisional.machine_ids != BTreeSet::from([machine.id.clone()])
        {
            return Err(stale_plan(
                "the newly created Fly App or Machine differs from the locked Target plan",
            ));
        }
        self.ensure_lock(context, LOCK_MARGIN_SECONDS).await?;
        let app = self
            .api
            .get_app(token, &workload.app_name)
            .await?
            .ok_or_else(|| stale_plan("the newly created Fly App disappeared before runtime"))?;
        if provisional.app_id.as_deref() != Some(app.id.as_str()) {
            return Err(stale_plan(
                "the newly created Fly App ID changed before runtime",
            ));
        }
        self.ensure_lock(context, LOCK_MARGIN_SECONDS).await?;
        let volumes = self.api.list_volumes(token, &workload.app_name).await?;
        let volume_ids = volumes
            .into_iter()
            .map(|volume| volume.id)
            .collect::<BTreeSet<_>>();
        if app.network.as_deref() != Some(data.network.as_str())
            || volume_ids != provisional.volume_ids
        {
            return Err(stale_plan(
                "the newly created Fly App network or Volume set changed before runtime",
            ));
        }
        if machine.instance_id.is_empty() {
            return Err(PluginError::retryable(
                ErrorKind::Unavailable,
                "fly_machine_version_missing",
                format!(
                    "Fly.io did not report the current Machine version for App `{}`",
                    workload.app_name
                ),
            ));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn verify_exposure_runtime<'a>(
        &self,
        context: &lightrail_plugin_protocol::OperationContext,
        data: &PlanData,
        action: &PlannedAction,
        workload: &Workload,
        identity: &Identity,
        machines: &'a [Machine],
        token: &str,
    ) -> PluginResult<&'a Machine> {
        let machine = exact_owned_machine(machines, identity, workload)?;
        let expected_port = workload.port.map(|port| port.to_string());
        if metadata(machine, ROLE_KEY) != Some("workload")
            || metadata(machine, REVISION_KEY) != Some(data.revision.as_str())
            || metadata(machine, PUBLIC_APP_KEY) != workload.public_app.as_deref()
            || metadata(machine, PORT_KEY) != expected_port.as_deref()
            || machine.state != "started"
        {
            return Err(stale_plan(
                "the Fly runtime no longer matches the locked exposure plan",
            ));
        }
        self.ensure_lock(context, LOCK_MARGIN_SECONDS).await?;
        let app = self
            .api
            .get_app(token, &workload.app_name)
            .await?
            .ok_or_else(|| stale_plan("the Fly App disappeared before exposure apply"))?;
        if app.network.as_deref() != Some(data.network.as_str()) {
            return Err(stale_plan(
                "the Fly App network changed before exposure apply",
            ));
        }
        if action_is_initial(action) {
            self.verify_initial_target(context, data, workload, machine, token)
                .await?;
        }
        let runtime_reconcile = action
            .metadata
            .get("runtime_reconcile")
            .and_then(Value::as_bool)
            .ok_or_else(|| {
                stale_plan("a Fly exposure action is missing Runtime continuity metadata")
            })?;
        if runtime_reconcile {
            let expected = self
                .runtime_version(&context.operation_id, &workload.app_name)
                .await
                .ok_or_else(|| {
                    stale_plan("the exact Fly Machine version produced by Runtime was not recorded")
                })?;
            if machine.instance_id != expected {
                return Err(stale_plan(
                    "the Fly Machine changed after Runtime and before exposure apply",
                ));
            }
        } else if action_metadata_string(action, "machine_id")? != machine.id
            || action_metadata_string(action, "instance_id")? != machine.instance_id
        {
            return Err(stale_plan(
                "the planned Fly Machine changed before exposure apply",
            ));
        }
        Ok(machine)
    }

    async fn verify_expiry_runtime(
        &self,
        operation_id: &str,
        revision: &str,
        action: &PlannedAction,
        machine: &Machine,
    ) -> PluginResult<()> {
        if metadata(machine, ROLE_KEY) != Some("workload")
            || metadata(machine, REVISION_KEY) != Some(revision)
            || machine.instance_id.is_empty()
        {
            return Err(stale_plan(
                "the Fly workload changed before final expiry commit",
            ));
        }
        let runtime_reconcile = action
            .metadata
            .get("runtime_reconcile")
            .and_then(Value::as_bool)
            .ok_or_else(|| {
                stale_plan("a Fly expiry action is missing Runtime continuity metadata")
            })?;
        if runtime_reconcile {
            let expected = self
                .runtime_version(operation_id, action_app(action)?)
                .await
                .ok_or_else(|| {
                    stale_plan("the exact Fly Machine version produced by Runtime was not recorded")
                })?;
            if machine.instance_id != expected {
                return Err(stale_plan(
                    "the Fly Machine changed after Runtime and before final expiry commit",
                ));
            }
        } else if action_metadata_string(action, "machine_id")? != machine.id
            || action_metadata_string(action, "instance_id")? != machine.instance_id
        {
            return Err(stale_plan(
                "the planned Fly Machine changed before final expiry commit",
            ));
        }
        Ok(())
    }

    async fn remember_exposure_inverse(
        &self,
        context: &lightrail_plugin_protocol::OperationContext,
        data: &PlanData,
        workload: &Workload,
        machine: &Machine,
    ) -> PluginResult<()> {
        let planned = ExposureInverse {
            project_id: data.desired.project.id.clone(),
            environment_id: data.desired.environment.id.clone(),
            app: workload.app_name.clone(),
            service: workload.service.clone(),
            public_app: workload
                .public_app
                .clone()
                .ok_or_else(|| stale_plan("a Fly exposure action selected a private workload"))?,
            machine_id: machine.id.clone(),
            instance_id: machine.instance_id.clone(),
            address: None,
        };
        let mut inverses = self.exposure_inverses.lock().await;
        let entries = inverses.entry(context.operation_id.clone()).or_default();
        if let Some(existing) = entries.iter().find(|entry| entry.app == planned.app) {
            if existing.project_id != planned.project_id
                || existing.environment_id != planned.environment_id
                || existing.service != planned.service
                || existing.public_app != planned.public_app
                || existing.machine_id != planned.machine_id
                || existing.instance_id != planned.instance_id
            {
                return Err(PluginError::permanent(
                    ErrorKind::Conflict,
                    "fly_exposure_inverse_conflict",
                    "the operation already recorded a different Fly exposure inverse",
                ));
            }
            return Ok(());
        }
        entries.push(planned);
        Ok(())
    }

    async fn record_exposure_inverse_address(
        &self,
        operation_id: &str,
        app: &str,
        address: String,
    ) -> PluginResult<()> {
        let mut inverses = self.exposure_inverses.lock().await;
        let inverse = inverses
            .get_mut(operation_id)
            .and_then(|entries| entries.iter_mut().find(|entry| entry.app == app))
            .ok_or_else(|| {
                PluginError::permanent(
                    ErrorKind::Internal,
                    "fly_exposure_inverse_lost",
                    "the exact Fly exposure inverse was lost after allocation",
                )
            })?;
        if inverse
            .address
            .as_ref()
            .is_some_and(|current| current != &address)
        {
            return Err(stale_plan(
                "Fly.io reported a different shared IPv4 for the same exposure operation",
            ));
        }
        inverse.address = Some(address);
        Ok(())
    }

    async fn reconcile_exposure_inverse_address(&self, operation_id: &str, app: &str, token: &str) {
        let Ok(Some(address)) = self.api.shared_ipv4(token, app).await else {
            return;
        };
        let _ = self
            .record_exposure_inverse_address(operation_id, app, address)
            .await;
    }

    async fn record_runtime_version(&self, operation_id: &str, app: &str, instance_id: &str) {
        self.runtime_versions
            .lock()
            .await
            .entry(operation_id.to_owned())
            .or_default()
            .insert(app.to_owned(), instance_id.to_owned());
    }

    async fn runtime_version(&self, operation_id: &str, app: &str) -> Option<String> {
        self.runtime_versions
            .lock()
            .await
            .get(operation_id)
            .and_then(|versions| versions.get(app))
            .cloned()
    }

    async fn forget_exposure_inverse(&self, operation_id: &str, app: &str) {
        let mut inverses = self.exposure_inverses.lock().await;
        if let Some(entries) = inverses.get_mut(operation_id) {
            entries.retain(|entry| entry.app != app);
            if entries.is_empty() {
                inverses.remove(operation_id);
            }
        }
    }

    async fn forget_provisional(&self, operation_id: &str, app: &str) {
        let mut provisional = self.provisional_apps.lock().await;
        if let Some(apps) = provisional.get_mut(operation_id) {
            apps.retain(|item| item.app != app);
            if apps.is_empty() {
                provisional.remove(operation_id);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn apply_builder(
        &self,
        context: &lightrail_plugin_protocol::OperationContext,
        settings: &Settings,
        data: &PlanData,
        actions: &[PlannedAction],
        journal: &mut Vec<ActionJournalEntry>,
        events: &EventSink,
        cancellation: &Cancellation,
    ) -> PluginResult<()> {
        if actions.is_empty() {
            return Ok(());
        }
        let compose = read_compose(&data.desired).await?;
        if revision(&data.desired, &compose, settings, &context.operation_id)? != data.revision {
            return Err(stale_plan(
                "resolved Compose content changed after the build plan was created",
            ));
        }
        let workloads = workloads(&data.desired, settings, &compose, &data.revision)?;
        validate_workloads(&data.desired, settings, &workloads, context)?;
        let selected = selected_workloads(actions, &workloads, "fly.builder.push")?;
        let token = context_token(context, settings)?;
        for action in actions {
            journal_event(
                events,
                &context.operation_id,
                journal,
                &action.id,
                JournalStatus::Started,
                "Building and pushing Fly image",
            )
            .await?;
        }
        self.ensure_lock(
            context,
            settings
                .command_timeout_seconds
                .saturating_add(LOCK_MARGIN_SECONDS),
        )
        .await?;
        let docker = DockerSession::login(settings, token.expose_secret(), cancellation).await?;
        self.ensure_lock(
            context,
            settings
                .command_timeout_seconds
                .saturating_add(LOCK_MARGIN_SECONDS),
        )
        .await?;
        let compose_path = data
            .desired
            .resolved_compose_path
            .as_deref()
            .ok_or_else(|| {
                validation("resolved_compose_required", "resolved Compose is required")
            })?;
        docker
            .build_and_push(
                data.desired.project_root(context)?,
                compose_path,
                settings,
                &selected,
                cancellation,
            )
            .await?;
        self.ensure_lock(context, LOCK_MARGIN_SECONDS).await?;
        for action in actions {
            journal_event(
                events,
                &context.operation_id,
                journal,
                &action.id,
                JournalStatus::Succeeded,
                "Built and pushed Fly image",
            )
            .await?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_lines)]
    async fn apply_runtime(
        &self,
        context: &lightrail_plugin_protocol::OperationContext,
        settings: &Settings,
        data: &PlanData,
        actions: &[PlannedAction],
        journal: &mut Vec<ActionJournalEntry>,
        events: &EventSink,
        cancellation: &Cancellation,
    ) -> PluginResult<()> {
        if actions.is_empty() {
            return Ok(());
        }
        let compose = read_compose(&data.desired).await?;
        if revision(&data.desired, &compose, settings, &context.operation_id)? != data.revision {
            return Err(stale_plan(
                "resolved Compose content changed after the runtime plan was created",
            ));
        }
        let workloads = workloads(&data.desired, settings, &compose, &data.revision)?;
        validate_workloads(&data.desired, settings, &workloads, context)?;
        let selected = selected_workloads(actions, &workloads, "fly.runtime.reconcile")?;
        let application_environment = resolve_app_environment(&data.desired, &context.secrets)?;
        let token = context_token(context, settings)?;
        let docker = if selected.iter().any(|workload| workload.build) {
            self.ensure_lock(
                context,
                settings
                    .command_timeout_seconds
                    .saturating_add(LOCK_MARGIN_SECONDS),
            )
            .await?;
            Some(DockerSession::login(settings, token.expose_secret(), cancellation).await?)
        } else {
            None
        };
        let identity = Identity::from_context(context, Some(&data.desired))?;
        self.ensure_lock(
            context,
            settings
                .readiness_timeout_seconds
                .max(settings.command_timeout_seconds)
                .saturating_add(LOCK_MARGIN_SECONDS),
        )
        .await?;
        for workload in &selected {
            cancellation.check()?;
            let action = actions
                .iter()
                .find(|action| action_app(action).ok() == Some(workload.app_name.as_str()))
                .ok_or_else(|| stale_plan("runtime action lost its workload"))?;
            journal_event(
                events,
                &context.operation_id,
                journal,
                &action.id,
                JournalStatus::Started,
                "Reconciling Fly Machine",
            )
            .await?;
            let image = if workload.build {
                self.ensure_lock(
                    context,
                    settings
                        .command_timeout_seconds
                        .saturating_add(LOCK_MARGIN_SECONDS),
                )
                .await?;
                let image = docker
                    .as_ref()
                    .expect("Docker session exists for built workload")
                    .resolve_digest(&workload.image, cancellation)
                    .await?;
                self.ensure_lock(context, LOCK_MARGIN_SECONDS).await?;
                image
            } else {
                workload.image.clone()
            };
            let machines = self
                .api
                .list_machines(token.expose_secret(), &workload.app_name)
                .await?;
            let machine = exact_owned_machine(&machines, &identity, workload)?;
            if action_is_initial(action) {
                self.verify_initial_target(context, data, workload, machine, token.expose_secret())
                    .await?;
            } else if action_metadata_string(action, "machine_id")? != machine.id.as_str()
                || action_metadata_string(action, "instance_id")? != machine.instance_id.as_str()
            {
                return Err(stale_plan(
                    "the planned Fly Machine or its current version changed before apply",
                ));
            }
            let mounts = machine.config.mounts.clone();
            let mut environment = workload.environment.clone();
            environment.extend(
                application_environment
                    .get(&workload.service)
                    .cloned()
                    .unwrap_or_default(),
            );
            let config = workload_machine_config(
                settings,
                &identity,
                &data.desired,
                workload,
                &image,
                mounts,
                environment,
                &data.revision,
                metadata(machine, EXPIRES_KEY),
            );
            let mut payload = serde_json::Map::from_iter([
                ("config".to_owned(), config),
                ("skip_launch".to_owned(), Value::Bool(false)),
            ]);
            payload.insert(
                "current_version".to_owned(),
                Value::String(machine.instance_id.clone()),
            );
            self.ensure_lock(
                context,
                settings
                    .readiness_timeout_seconds
                    .saturating_add(LOCK_MARGIN_SECONDS),
            )
            .await?;
            let updated = self
                .api
                .update_machine(
                    token.expose_secret(),
                    &workload.app_name,
                    &machine.id,
                    Value::Object(payload),
                )
                .await?;
            if updated.id != machine.id || updated.instance_id.is_empty() {
                return Err(PluginError::retryable(
                    ErrorKind::Unavailable,
                    "fly_updated_machine_version_missing",
                    format!(
                        "Fly.io did not return the exact updated version for App `{}`",
                        workload.app_name
                    ),
                ));
            }
            self.wait_machine_started(
                settings,
                token.expose_secret(),
                workload,
                &updated,
                cancellation,
            )
            .await?;
            self.record_runtime_version(
                &context.operation_id,
                &workload.app_name,
                &updated.instance_id,
            )
            .await;
            self.ensure_lock(context, LOCK_MARGIN_SECONDS).await?;
            journal_event(
                events,
                &context.operation_id,
                journal,
                &action.id,
                JournalStatus::Succeeded,
                "Reconciled Fly Machine",
            )
            .await?;
        }
        self.wait_public_workloads(context, settings, &selected, cancellation, true)
            .await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn apply_exposure(
        &self,
        context: &lightrail_plugin_protocol::OperationContext,
        settings: &Settings,
        data: &PlanData,
        actions: &[PlannedAction],
        journal: &mut Vec<ActionJournalEntry>,
        events: &EventSink,
        cancellation: &Cancellation,
    ) -> PluginResult<()> {
        if actions.is_empty() {
            return Ok(());
        }
        let compose = read_compose(&data.desired).await?;
        if revision(&data.desired, &compose, settings, &context.operation_id)? != data.revision {
            return Err(stale_plan(
                "resolved Compose content changed after the exposure plan was created",
            ));
        }
        let workloads = workloads(&data.desired, settings, &compose, &data.revision)?;
        validate_workloads(&data.desired, settings, &workloads, context)?;
        let selected = selected_workloads(actions, &workloads, "fly.exposure.allocate_ip")?;
        let token = context_token(context, settings)?;
        let identity = Identity::from_context(context, Some(&data.desired))?;
        for workload in &selected {
            cancellation.check()?;
            let action = actions
                .iter()
                .find(|action| action_app(action).ok() == Some(workload.app_name.as_str()))
                .ok_or_else(|| stale_plan("exposure action lost its workload"))?;
            self.ensure_lock(context, LOCK_MARGIN_SECONDS).await?;
            let machines = self
                .api
                .list_machines(token.expose_secret(), &workload.app_name)
                .await?;
            let machine = self
                .verify_exposure_runtime(
                    context,
                    data,
                    action,
                    workload,
                    &identity,
                    &machines,
                    token.expose_secret(),
                )
                .await?;
            self.ensure_lock(context, LOCK_MARGIN_SECONDS).await?;
            if self
                .api
                .shared_ipv4(token.expose_secret(), &workload.app_name)
                .await?
                .is_some()
            {
                return Err(stale_plan(
                    "the planned Fly shared IPv4 appeared before exposure apply",
                ));
            }
            self.remember_exposure_inverse(context, data, workload, machine)
                .await?;
            journal_event(
                events,
                &context.operation_id,
                journal,
                &action.id,
                JournalStatus::Started,
                "Allocating Fly shared IPv4",
            )
            .await?;
            self.ensure_lock(
                context,
                settings
                    .readiness_timeout_seconds
                    .saturating_add(LOCK_MARGIN_SECONDS),
            )
            .await?;
            let allocation = self
                .api
                .allocate_shared_ipv4(
                    token.expose_secret(),
                    &workload.app_name,
                    settings.region.as_deref(),
                )
                .await;
            match allocation {
                Ok(address) => {
                    self.record_exposure_inverse_address(
                        &context.operation_id,
                        &workload.app_name,
                        address,
                    )
                    .await?;
                }
                Err(error) => {
                    self.reconcile_exposure_inverse_address(
                        &context.operation_id,
                        &workload.app_name,
                        token.expose_secret(),
                    )
                    .await;
                    return Err(error);
                }
            }
        }
        self.wait_public_workloads(context, settings, &selected, cancellation, false)
            .await?;
        for workload in &selected {
            self.reconcile_exposure_inverse_address(
                &context.operation_id,
                &workload.app_name,
                token.expose_secret(),
            )
            .await;
            let action = actions
                .iter()
                .find(|action| action_app(action).ok() == Some(workload.app_name.as_str()))
                .ok_or_else(|| stale_plan("exposure action lost its workload"))?;
            journal_event(
                events,
                &context.operation_id,
                journal,
                &action.id,
                JournalStatus::Succeeded,
                "Allocated Fly shared IPv4 and verified HTTPS",
            )
            .await?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn apply_expiry(
        &self,
        context: &lightrail_plugin_protocol::OperationContext,
        settings: &Settings,
        data: &PlanData,
        actions: &[PlannedAction],
        journal: &mut Vec<ActionJournalEntry>,
        events: &EventSink,
        cancellation: &Cancellation,
    ) -> PluginResult<()> {
        let compose = read_compose(&data.desired).await?;
        if revision(&data.desired, &compose, settings, &context.operation_id)? != data.revision {
            return Err(stale_plan(
                "resolved Compose content changed after the expiry plan was created",
            ));
        }
        let workloads = workloads(&data.desired, settings, &compose, &data.revision)?;
        validate_workloads(&data.desired, settings, &workloads, context)?;
        let selected = selected_workloads(actions, &workloads, "fly.dns.refresh_expiry")?;
        if selected.len() != workloads.len() {
            return Err(stale_plan(
                "the final expiry plan must select every Fly workload",
            ));
        }
        let token = context_token(context, settings)?;
        let identity = Identity::from_context(context, Some(&data.desired))?;
        let committed_expiry = data.expires_at_unix.to_string();
        let mut failures = Vec::new();
        for workload in &selected {
            cancellation.check()?;
            let action = actions
                .iter()
                .find(|action| action_app(action).ok() == Some(workload.app_name.as_str()))
                .ok_or_else(|| stale_plan("expiry action lost its workload"))?;
            journal_event(
                events,
                &context.operation_id,
                journal,
                &action.id,
                JournalStatus::Started,
                "Committing successful-up expiry metadata",
            )
            .await?;
            let commit = async {
                self.ensure_lock(
                    context,
                    settings
                        .command_timeout_seconds
                        .saturating_add(LOCK_MARGIN_SECONDS),
                )
                .await?;
                let app = self
                    .api
                    .get_app(token.expose_secret(), &workload.app_name)
                    .await?
                    .ok_or_else(|| stale_plan("the Fly App disappeared before expiry commit"))?;
                if app.network.as_deref() != Some(data.network.as_str()) {
                    return Err(stale_plan(
                        "the Fly App network changed before expiry commit",
                    ));
                }
                let machines = self
                    .api
                    .list_machines(token.expose_secret(), &workload.app_name)
                    .await?;
                let machine = exact_owned_machine(&machines, &identity, workload)?;
                self.verify_expiry_runtime(&context.operation_id, &data.revision, action, machine)
                    .await?;
                let prior_expiry = action_optional_string(action, "prior_expiry")?;
                if metadata(machine, EXPIRES_KEY) != prior_expiry {
                    return Err(stale_plan(
                        "Fly expiry metadata changed after the locked plan",
                    ));
                }
                self.remember_expiry_inverse(
                    &context.operation_id,
                    ExpiryInverse {
                        project_id: identity.project_id.clone(),
                        environment_id: identity.environment_id.clone(),
                        app: workload.app_name.clone(),
                        service: workload.service.clone(),
                        machine_id: machine.id.clone(),
                        instance_id: machine.instance_id.clone(),
                        prior_expiry: prior_expiry.map(ToOwned::to_owned),
                        committed_expiry: committed_expiry.clone(),
                    },
                )
                .await;
                self.ensure_lock(context, LOCK_MARGIN_SECONDS).await?;
                write_expiry_metadata(
                    self.api.as_ref(),
                    token.expose_secret(),
                    &workload.app_name,
                    &machine.id,
                    Some(&committed_expiry),
                )
                .await
            };
            let result = tokio::select! {
                result = tokio::time::timeout(
                    Duration::from_secs(settings.command_timeout_seconds),
                    commit,
                ) => {
                    result.unwrap_or_else(|_| {
                        Err(PluginError::retryable(
                            ErrorKind::Timeout,
                            "fly_expiry_commit_timeout",
                            format!(
                                "Fly.io did not finish committing expiry for App `{}`",
                                workload.app_name
                            ),
                        ))
                    })
                }
                () = cancellation.cancelled() => cancellation.check(),
            };
            match result {
                Ok(()) => {
                    journal_event(
                        events,
                        &context.operation_id,
                        journal,
                        &action.id,
                        JournalStatus::Succeeded,
                        "Committed successful-up expiry metadata",
                    )
                    .await?;
                }
                Err(error) => {
                    journal_event(
                        events,
                        &context.operation_id,
                        journal,
                        &action.id,
                        JournalStatus::Failed,
                        &error.message,
                    )
                    .await?;
                    failures.push(error);
                }
            }
        }
        if let Some(error) = failures.into_iter().next() {
            return Err(error);
        }
        Ok(())
    }

    async fn remember_expiry_inverse(&self, operation_id: &str, inverse: ExpiryInverse) {
        let mut inverses = self.expiry_inverses.lock().await;
        let entries = inverses.entry(operation_id.to_owned()).or_default();
        entries.retain(|entry| entry.app != inverse.app);
        entries.push(inverse);
    }

    async fn forget_expiry_inverse(&self, operation_id: &str, app: &str) {
        let mut inverses = self.expiry_inverses.lock().await;
        if let Some(entries) = inverses.get_mut(operation_id) {
            entries.retain(|entry| entry.app != app);
            if entries.is_empty() {
                inverses.remove(operation_id);
            }
        }
    }

    async fn wait_machine_started(
        &self,
        settings: &Settings,
        token: &str,
        workload: &Workload,
        updated: &Machine,
        cancellation: &Cancellation,
    ) -> PluginResult<()> {
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(settings.readiness_timeout_seconds);
        loop {
            cancellation.check()?;
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(PluginError::retryable(
                    ErrorKind::Timeout,
                    "fly_machine_readiness_timeout",
                    format!(
                        "Machine readiness timed out for Fly App `{}`",
                        workload.app_name
                    ),
                ));
            }
            let wait = self.api.wait_machine(
                token,
                &workload.app_name,
                &updated.id,
                "started",
                (!updated.instance_id.is_empty()).then_some(updated.instance_id.as_str()),
                remaining.as_secs().max(1),
            );
            let result = tokio::select! {
                result = tokio::time::timeout(remaining, wait) => {
                    result.unwrap_or_else(|_| {
                        Err(PluginError::retryable(
                            ErrorKind::Timeout,
                            "fly_machine_readiness_timeout",
                            format!(
                                "Machine readiness timed out for Fly App `{}`",
                                workload.app_name
                            ),
                        ))
                    })
                },
                () = cancellation.cancelled() => return cancellation.check(),
            };
            match result {
                Ok(()) => return Ok(()),
                Err(error)
                    if error.retryable
                        && matches!(error.kind, ErrorKind::Timeout | ErrorKind::Unavailable)
                        && tokio::time::Instant::now() < deadline => {}
                Err(error) => return Err(error),
            }
            tokio::select! {
                () = tokio::time::sleep(Duration::from_secs(1)) => {}
                () = cancellation.cancelled() => return cancellation.check(),
            }
        }
    }

    async fn wait_public_workloads(
        &self,
        context: &lightrail_plugin_protocol::OperationContext,
        settings: &Settings,
        workloads: &[Workload],
        cancellation: &Cancellation,
        skip_without_address: bool,
    ) -> PluginResult<()> {
        let token = context_token(context, settings)?;
        let token_secret = token.expose_secret();
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(settings.readiness_timeout_seconds);
        self.ensure_lock(
            context,
            settings
                .readiness_timeout_seconds
                .saturating_add(LOCK_MARGIN_SECONDS),
        )
        .await?;
        let target_discovery = try_join_all(
            workloads
                .iter()
                .filter(|workload| workload.public_app.is_some())
                .map(|workload| async move {
                    if skip_without_address
                        && self
                            .api
                            .shared_ipv4(token_secret, &workload.app_name)
                            .await?
                            .is_none()
                    {
                        Ok(None)
                    } else {
                        Ok(Some(workload))
                    }
                }),
        );
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let targets = tokio::select! {
            result = tokio::time::timeout(remaining, target_discovery) => {
                result.map_err(|_| {
                    PluginError::retryable(
                        ErrorKind::Timeout,
                        "fly_https_readiness_timeout",
                        "Fly public address discovery exceeded the shared readiness deadline",
                    )
                })??
            },
            () = cancellation.cancelled() => return cancellation.check(),
        }
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        wait_all_readiness(targets.into_iter().map(|workload| {
            self.wait_public_ready(
                token_secret,
                workload,
                deadline,
                cancellation,
                !skip_without_address,
            )
        }))
        .await?;
        Ok(())
    }

    async fn wait_public_ready(
        &self,
        token: &str,
        workload: &Workload,
        deadline: tokio::time::Instant,
        cancellation: &Cancellation,
        require_address: bool,
    ) -> PluginResult<()> {
        loop {
            cancellation.check()?;
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(PluginError::retryable(
                    ErrorKind::Timeout,
                    "fly_https_readiness_timeout",
                    format!(
                        "trusted HTTPS readiness timed out for Fly App `{}`",
                        workload.app_name
                    ),
                ));
            }
            let check = async {
                let address_ready = !require_address
                    || self
                        .api
                        .shared_ipv4(token, &workload.app_name)
                        .await?
                        .is_some();
                if !address_ready {
                    return Ok(false);
                }
                public_ready(
                    self.api.as_ref(),
                    &workload.app_name,
                    workload.health_path.as_deref().unwrap_or("/"),
                    workload.health_status,
                )
                .await
            };
            let ready = tokio::select! {
                result = tokio::time::timeout(remaining, check) => {
                    result.unwrap_or(Ok(false))?
                },
                () = cancellation.cancelled() => return cancellation.check(),
            };
            if ready {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(PluginError::retryable(
                    ErrorKind::Timeout,
                    "fly_https_readiness_timeout",
                    format!(
                        "trusted HTTPS readiness timed out for Fly App `{}`",
                        workload.app_name
                    ),
                ));
            }
            tokio::select! {
                () = tokio::time::sleep(Duration::from_secs(2)) => {}
                () = cancellation.cancelled() => return cancellation.check(),
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn rollback_expiry(
        &self,
        request: DestroyRequest,
        cached: &CachedContext,
        events: &EventSink,
    ) -> PluginResult<DestroyResult> {
        let operation_id = request.context.operation_id.clone();
        let inverses = self
            .expiry_inverses
            .lock()
            .await
            .get(&operation_id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|inverse| {
                inverse.project_id == cached.identity.project_id
                    && inverse.environment_id == cached.identity.environment_id
            })
            .collect::<Vec<_>>();
        let cancellation = self.cancellation(&operation_id).await;
        let token = cached.token.expose_secret();
        let mut journal = request.journal;
        let mut remaining = Vec::new();
        for inverse in inverses {
            cancellation.check()?;
            let action_id = format!("dns.refresh-expiry.{}", inverse.app);
            journal_event(
                events,
                &operation_id,
                &mut journal,
                &action_id,
                JournalStatus::RollingBack,
                "Restoring prior Fly expiry metadata",
            )
            .await?;
            let restore = async {
                self.ensure_lock(
                    &request.context,
                    cached
                        .settings
                        .command_timeout_seconds
                        .saturating_add(LOCK_MARGIN_SECONDS),
                )
                .await?;
                let app = self
                    .api
                    .get_app(token, &inverse.app)
                    .await?
                    .ok_or_else(|| {
                        destroy_plan_drift(format!(
                            "Fly App `{}` disappeared before expiry rollback",
                            inverse.app
                        ))
                    })?;
                let expected_network = network_name(
                    &inverse.project_id,
                    &inverse.environment_id,
                    &cached.settings,
                );
                if app.network.as_deref() != Some(expected_network.as_str())
                    || !app
                        .name
                        .contains(&project_app_marker(&inverse.project_id, &cached.settings))
                {
                    return Err(destroy_plan_drift(format!(
                        "Fly App `{}` changed ownership before expiry rollback",
                        inverse.app
                    )));
                }
                let machines = self.api.list_machines(token, &inverse.app).await?;
                if machines.len() != 1
                    || machines[0].id != inverse.machine_id
                    || machines[0].instance_id != inverse.instance_id
                    || metadata(&machines[0], MANAGED_KEY) != Some("true")
                    || metadata(&machines[0], PROJECT_KEY) != Some(inverse.project_id.as_str())
                    || metadata(&machines[0], ENVIRONMENT_KEY)
                        != Some(inverse.environment_id.as_str())
                    || metadata(&machines[0], SERVICE_KEY) != Some(inverse.service.as_str())
                    || metadata(&machines[0], ROLE_KEY) != Some("workload")
                {
                    return Err(destroy_plan_drift(format!(
                        "Fly App `{}` Machine ownership changed before expiry rollback",
                        inverse.app
                    )));
                }
                let current = metadata(&machines[0], EXPIRES_KEY);
                if current == inverse.prior_expiry.as_deref() {
                    return Ok(());
                }
                if current != Some(inverse.committed_expiry.as_str()) {
                    return Err(destroy_plan_drift(format!(
                        "Fly App `{}` expiry changed before rollback",
                        inverse.app
                    )));
                }
                write_expiry_metadata(
                    self.api.as_ref(),
                    token,
                    &inverse.app,
                    &inverse.machine_id,
                    inverse.prior_expiry.as_deref(),
                )
                .await
            };
            let result = tokio::select! {
                result = tokio::time::timeout(
                    Duration::from_secs(cached.settings.command_timeout_seconds),
                    restore,
                ) => {
                    result.unwrap_or_else(|_| {
                        Err(PluginError::retryable(
                            ErrorKind::Timeout,
                            "fly_expiry_rollback_timeout",
                            format!(
                                "Fly.io did not finish restoring expiry for App `{}`",
                                inverse.app
                            ),
                        ))
                    })
                }
                () = cancellation.cancelled() => cancellation.check(),
            };
            match result {
                Ok(()) => {
                    self.forget_expiry_inverse(&operation_id, &inverse.app)
                        .await;
                    journal_event(
                        events,
                        &operation_id,
                        &mut journal,
                        &action_id,
                        JournalStatus::RolledBack,
                        "Restored prior Fly expiry metadata",
                    )
                    .await?;
                }
                Err(error) => {
                    remaining.push(inverse.app.clone());
                    journal_event(
                        events,
                        &operation_id,
                        &mut journal,
                        &action_id,
                        JournalStatus::RollbackFailed,
                        &error.message,
                    )
                    .await?;
                }
            }
        }
        Ok(DestroyResult {
            destroyed: remaining.is_empty(),
            journal,
            remaining,
        })
    }

    #[allow(clippy::too_many_lines)]
    async fn rollback_exposure(
        &self,
        request: DestroyRequest,
        cached: &CachedContext,
        events: &EventSink,
    ) -> PluginResult<DestroyResult> {
        let operation_id = request.context.operation_id.clone();
        let inverses = self
            .exposure_inverses
            .lock()
            .await
            .get(&operation_id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|inverse| {
                inverse.project_id == cached.identity.project_id
                    && inverse.environment_id == cached.identity.environment_id
            })
            .collect::<Vec<_>>();
        let cancellation = self.cancellation(&operation_id).await;
        let token = cached.token.expose_secret();
        let mut journal = request.journal;
        let mut remaining = Vec::new();
        for inverse in inverses {
            cancellation.check()?;
            let action_id = format!("exposure.allocate-ip.{}", inverse.app);
            journal_event(
                events,
                &operation_id,
                &mut journal,
                &action_id,
                JournalStatus::RollingBack,
                "Releasing the operation-owned Fly shared IPv4",
            )
            .await?;
            let result = async {
                self.ensure_lock(
                    &request.context,
                    cached
                        .settings
                        .command_timeout_seconds
                        .saturating_add(LOCK_MARGIN_SECONDS),
                )
                .await?;
                let release = async {
                    let Some(app) = self.api.get_app(token, &inverse.app).await? else {
                        return Ok(());
                    };
                    let expected_network = network_name(
                        &inverse.project_id,
                        &inverse.environment_id,
                        &cached.settings,
                    );
                    if app.network.as_deref() != Some(expected_network.as_str())
                        || !app.name.contains(&project_app_marker(
                            &inverse.project_id,
                            &cached.settings,
                        ))
                    {
                        return Err(destroy_plan_drift(format!(
                            "Fly App `{}` changed ownership before exposure rollback",
                            inverse.app
                        )));
                    }
                    let machines = self.api.list_machines(token, &inverse.app).await?;
                    if machines.len() != 1
                        || machines[0].id != inverse.machine_id
                        || machines[0].instance_id != inverse.instance_id
                        || metadata(&machines[0], MANAGED_KEY) != Some("true")
                        || metadata(&machines[0], PROJECT_KEY) != Some(inverse.project_id.as_str())
                        || metadata(&machines[0], ENVIRONMENT_KEY)
                            != Some(inverse.environment_id.as_str())
                        || metadata(&machines[0], SERVICE_KEY) != Some(inverse.service.as_str())
                        || metadata(&machines[0], ROLE_KEY) != Some("workload")
                        || metadata(&machines[0], PUBLIC_APP_KEY)
                            != Some(inverse.public_app.as_str())
                    {
                        return Err(destroy_plan_drift(format!(
                            "Fly App `{}` Machine ownership changed before exposure rollback",
                            inverse.app
                        )));
                    }
                    let Some(address) = self.api.shared_ipv4(token, &inverse.app).await? else {
                        return Ok(());
                    };
                    let Some(expected_address) = inverse.address.as_ref() else {
                        return Err(destroy_plan_drift(format!(
                            "Fly App `{}` has an address but the allocating operation did not capture it",
                            inverse.app
                        )));
                    };
                    if expected_address != &address {
                        return Err(destroy_plan_drift(format!(
                            "Fly App `{}` shared IPv4 changed before exposure rollback",
                            inverse.app
                        )));
                    }
                    self.api
                        .release_shared_ipv4(token, &inverse.app, &address)
                        .await?;
                    loop {
                        cancellation.check()?;
                        if self.api.shared_ipv4(token, &inverse.app).await?.is_none() {
                            return Ok(());
                        }
                        tokio::select! {
                            () = tokio::time::sleep(Duration::from_secs(1)) => {}
                            () = cancellation.cancelled() => return cancellation.check(),
                        }
                    }
                };
                tokio::select! {
                    result = tokio::time::timeout(
                        Duration::from_secs(cached.settings.command_timeout_seconds),
                        release,
                    ) => {
                        result.unwrap_or_else(|_| {
                            Err(PluginError::retryable(
                                ErrorKind::Timeout,
                                "fly_shared_ip_release_timeout",
                                format!(
                                    "Fly.io did not finish releasing the shared IPv4 for App `{}`",
                                    inverse.app
                                ),
                            ))
                        })
                    }
                    () = cancellation.cancelled() => cancellation.check(),
                }
            }
            .await;
            match result {
                Ok(()) => {
                    self.forget_exposure_inverse(&operation_id, &inverse.app)
                        .await;
                    journal_event(
                        events,
                        &operation_id,
                        &mut journal,
                        &action_id,
                        JournalStatus::RolledBack,
                        "Released the operation-owned Fly shared IPv4",
                    )
                    .await?;
                }
                Err(error) => {
                    remaining.push(inverse.app.clone());
                    journal_event(
                        events,
                        &operation_id,
                        &mut journal,
                        &action_id,
                        JournalStatus::RollbackFailed,
                        &error.message,
                    )
                    .await?;
                }
            }
        }
        Ok(DestroyResult {
            destroyed: remaining.is_empty(),
            journal,
            remaining,
        })
    }

    async fn delete_captured_app(
        &self,
        context: &lightrail_plugin_protocol::OperationContext,
        cached: &CachedContext,
        captured: &CapturedApp,
    ) -> PluginResult<()> {
        self.ensure_lock(
            context,
            cached
                .settings
                .command_timeout_seconds
                .saturating_add(LOCK_MARGIN_SECONDS),
        )
        .await?;
        let cancellation = self.cancellation(&context.operation_id).await;
        let deletion = self.delete_captured_app_bounded(cached, captured, &cancellation);
        tokio::select! {
            result = tokio::time::timeout(
                Duration::from_secs(cached.settings.command_timeout_seconds),
                deletion,
            ) => {
                result.unwrap_or_else(|_| {
                    Err(PluginError::retryable(
                        ErrorKind::Timeout,
                        "fly_destroy_timeout",
                        format!(
                            "timed out waiting for exact Fly App `{}` deletion",
                            captured.app
                        ),
                    ))
                })
            },
            () = cancellation.cancelled() => cancellation.check(),
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn delete_captured_app_bounded(
        &self,
        cached: &CachedContext,
        captured: &CapturedApp,
        cancellation: &Cancellation,
    ) -> PluginResult<()> {
        let token = cached.token.expose_secret();
        cancellation.check()?;
        let Some(app) = self.api.get_app(token, &captured.app).await? else {
            return Ok(());
        };
        let marker = project_app_marker(&cached.identity.project_id, &cached.settings);
        let project_network_prefix = network_prefix(&cached.identity.project_id, &cached.settings);
        if captured.app_id.as_deref() != Some(app.id.as_str())
            || !app.name.contains(&marker)
            || app.network.as_deref() != Some(captured.network.as_str())
            || !captured.network.starts_with(&project_network_prefix)
        {
            return Err(destroy_plan_drift(format!(
                "refusing to delete Fly App `{}` because its project marker or network changed",
                app.name
            )));
        }
        let machines = self.api.list_machines(token, &app.name).await?;
        let volumes = self.api.list_volumes(token, &app.name).await?;
        let machine_ids = machines
            .iter()
            .map(|machine| machine.id.clone())
            .collect::<BTreeSet<_>>();
        let volume_ids = volumes
            .iter()
            .map(|volume| volume.id.clone())
            .collect::<BTreeSet<_>>();
        if machine_ids != captured.machine_ids || volume_ids != captured.volume_ids {
            return Err(destroy_plan_drift(format!(
                "Fly App `{}` changed Machine or Volume identities before deletion",
                app.name
            )));
        }
        for machine in &machines {
            if metadata(machine, MANAGED_KEY) != Some("true")
                || metadata(machine, PROJECT_KEY) != Some(cached.identity.project_id.as_str())
                || captured.environment_id.as_ref().is_some_and(|environment| {
                    metadata(machine, ENVIRONMENT_KEY) != Some(environment.as_str())
                })
                || captured
                    .service
                    .as_ref()
                    .is_some_and(|service| metadata(machine, SERVICE_KEY) != Some(service.as_str()))
            {
                return Err(destroy_plan_drift(format!(
                    "Fly App `{}` Machine ownership changed before deletion",
                    app.name
                )));
            }
        }
        for machine in &captured.machine_ids {
            cancellation.check()?;
            self.api.delete_machine(token, &app.name, machine).await?;
        }
        loop {
            cancellation.check()?;
            let machines = self.api.list_machines(token, &app.name).await?;
            let observed = machines
                .iter()
                .map(|machine| machine.id.clone())
                .collect::<BTreeSet<_>>();
            if !observed.is_subset(&captured.machine_ids) {
                return Err(destroy_plan_drift(format!(
                    "Fly App `{}` gained a Machine during deletion",
                    app.name
                )));
            }
            if observed.is_empty() {
                break;
            }
            wait_retry(cancellation).await?;
        }
        for volume in &captured.volume_ids {
            loop {
                cancellation.check()?;
                match self.api.delete_volume(token, &app.name, volume).await {
                    Ok(()) => break,
                    Err(error)
                        if error.retryable
                            || matches!(error.kind, ErrorKind::Conflict | ErrorKind::NotFound) =>
                    {
                        wait_retry(cancellation).await?;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        loop {
            cancellation.check()?;
            let volumes = self.api.list_volumes(token, &app.name).await?;
            if volumes
                .iter()
                .any(|volume| !captured.volume_ids.contains(&volume.id))
            {
                return Err(destroy_plan_drift(format!(
                    "Fly App `{}` gained a Volume during deletion",
                    app.name
                )));
            }
            if volumes.iter().all(volume_deletion_complete) {
                break;
            }
            wait_retry(cancellation).await?;
        }
        let Some(rechecked) = self.api.get_app(token, &app.name).await? else {
            return Ok(());
        };
        if captured.app_id.as_deref() != Some(rechecked.id.as_str())
            || rechecked.network.as_deref() != Some(captured.network.as_str())
        {
            return Err(destroy_plan_drift(format!(
                "Fly App `{}` changed network during deletion",
                app.name
            )));
        }
        loop {
            cancellation.check()?;
            match self.api.delete_app(token, &app.name, false).await {
                Ok(()) => break,
                Err(error)
                    if error.retryable
                        || matches!(error.kind, ErrorKind::Conflict | ErrorKind::NotFound) =>
                {
                    if self.api.get_app(token, &app.name).await?.is_none() {
                        return Ok(());
                    }
                    wait_retry(cancellation).await?;
                }
                Err(error) => return Err(error),
            }
        }
        loop {
            cancellation.check()?;
            let Some(remaining) = self.api.get_app(token, &app.name).await? else {
                return Ok(());
            };
            if captured.app_id.as_deref() != Some(remaining.id.as_str())
                || remaining.network.as_deref() != Some(captured.network.as_str())
            {
                return Err(destroy_plan_drift(format!(
                    "Fly App `{}` changed network while deletion was pending",
                    app.name
                )));
            }
            wait_retry(cancellation).await?;
        }
    }

    async fn delete_provisional_app(
        &self,
        context: &lightrail_plugin_protocol::OperationContext,
        cached: &CachedContext,
        provisional: &ProvisionalApp,
    ) -> PluginResult<()> {
        self.delete_captured_app(
            context,
            cached,
            &CapturedApp::from_provisional(provisional.clone()),
        )
        .await
    }
}
