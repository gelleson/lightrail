//! Provider-independent lifecycle engine for user-facing environment commands.
//!
//! Read this file by workflow: `up`, read-only queries, `down`, and logs come
//! first; shared preparation, secrets, inspection, locking, and rollback
//! follow. Stable output DTOs, aggregation, and rendering live in `view` so
//! lifecycle control flow remains visible here.

use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    io::{self, IsTerminal},
    time::Duration,
};

use dialoguer::{Confirm, Password};
use lightrail_core::Capability as CoreCapability;
use lightrail_plugin_protocol::{
    ActionJournalEntry, ApplyRequest, ApplyResult, CancelRequest, Capability, ClientError,
    ClientEvent, DestroyRequest, DestroyResult, InspectRequest, InspectResult, LockAcquireRequest,
    LockAcquireResult, LockReleaseRequest, LockScope, LogsRequest, OperationContext, PlanRequest,
    PlanResult, PluginEvent, PluginManifest, ResourceStatus, SecretValue, ValidateRequest,
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use uuid::Uuid;

mod view;

pub use view::{
    ActionView, EnvironmentSummaryView, EnvironmentView, PlanView, PluginPlanView, PluginStatusView,
};

use crate::{
    compose::ComposeInspector,
    error::CliError,
    journal::{JournalAction, OperationJournal, OperationKind, OperationStatus},
    output::{self, OutputFormat},
    plugin_host::{PluginResolver, PluginSession},
    process::TokioCommandRunner,
    project::LoadedProject,
    secrets::{KeyringBackend, SecretBackend, SecretStore},
};

use self::view::{
    collect_endpoints, collect_environment_summaries, combined_status, print_environment,
    print_log_records, print_plan, print_urls,
};

const APPLY_ORDER: [CoreCapability; 6] = [
    CoreCapability::Source,
    CoreCapability::Target,
    CoreCapability::Builder,
    CoreCapability::Runtime,
    CoreCapability::Exposure,
    CoreCapability::Dns,
];

const DESTROY_ORDER: [CoreCapability; 4] = [
    CoreCapability::Dns,
    CoreCapability::Exposure,
    CoreCapability::Runtime,
    CoreCapability::Target,
];

const RETRY_ATTEMPTS: usize = 3;
const LOCK_CONTINUITY_TIMEOUT_MS: u64 = 1;

#[derive(Clone, Debug)]
pub struct UpOptions {
    pub dry_run: bool,
    pub keep_failed: bool,
    pub lock_timeout: Duration,
    pub output: OutputFormat,
}

#[derive(Clone, Debug)]
pub struct DownOptions {
    pub all: bool,
    pub dry_run: bool,
    pub yes: bool,
    pub force: bool,
    pub lock_timeout: Duration,
    pub output: OutputFormat,
}

#[derive(Clone, Debug)]
pub struct QueryOptions {
    pub all: bool,
    pub output: OutputFormat,
}

#[derive(Clone, Debug)]
pub struct LogOptions {
    pub service: Option<String>,
    pub follow: bool,
    pub tail: usize,
    pub output: OutputFormat,
}

struct PluginFleet {
    sessions: BTreeMap<String, PluginSession>,
    secret_cache: OperationSecretCache,
}

#[derive(Default)]
struct OperationSecretCache {
    values: tokio::sync::Mutex<BTreeMap<String, SecretString>>,
}

impl OperationSecretCache {
    async fn resolve<B: SecretBackend>(
        &self,
        store: &SecretStore<B>,
        name: &str,
    ) -> Result<SecretString, CliError> {
        // Keep the guard through the first lookup and possible prompt so two
        // concurrent capability contexts cannot ask for the same secret twice.
        let mut values = self.values.lock().await;
        if let Some(value) = values.get(name) {
            return Ok(value.clone());
        }

        let value = resolve_uncached_secret(store, name).await?;
        values.insert(name.to_owned(), value.clone());
        Ok(value)
    }
}

impl PluginFleet {
    async fn start(
        project: &LoadedProject,
        capabilities: &[CoreCapability],
    ) -> Result<Self, CliError> {
        let resolver = PluginResolver::new(project.paths.clone())?;
        let identifiers = capabilities
            .iter()
            .map(|capability| project.plugin_id(*capability).to_owned())
            .collect::<BTreeSet<_>>();
        let mut sessions = BTreeMap::new();
        for identifier in identifiers {
            match resolver.spawn(&identifier).await {
                Ok(session) => {
                    sessions.insert(identifier, session);
                }
                Err(error) => {
                    for (_, session) in sessions {
                        let _ = session.shutdown().await;
                    }
                    return Err(error);
                }
            }
        }

        for capability in capabilities {
            let identifier = project.plugin_id(*capability);
            let session = sessions
                .get(identifier)
                .expect("every selected plugin was started");
            session.require_capability(&protocol_capability(*capability))?;
        }
        Ok(Self {
            sessions,
            secret_cache: OperationSecretCache::default(),
        })
    }

    fn session(&self, identifier: &str) -> Result<&PluginSession, CliError> {
        self.sessions.get(identifier).ok_or_else(|| {
            CliError::Plugin(format!("plugin session `{identifier}` is unavailable"))
        })
    }

    async fn shutdown(self) -> Result<(), CliError> {
        let mut first_error = None;
        for (_, session) in self.sessions {
            if let Err(error) = session.shutdown().await {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

#[derive(Clone)]
struct PreparedCapability {
    capability: CoreCapability,
    plugin_id: String,
    context: OperationContext,
    current: InspectResult,
    plan: PlanResult,
}

#[derive(Clone)]
struct MutationLock {
    plugin_id: String,
    environment_id: String,
    scope: LockScope,
    scope_id: String,
    operation_id: String,
    token: SecretValue,
}

pub async fn up(project: LoadedProject, options: UpOptions) -> Result<EnvironmentView, CliError> {
    project.paths.ensure_local_layout().await?;
    let fleet = PluginFleet::start(&project, &APPLY_ORDER).await?;
    let operation_id = Uuid::new_v4().to_string();
    let result = up_with_fleet(&project, &fleet, &operation_id, &options).await;
    let shutdown = fleet.shutdown().await;
    match (result, shutdown) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) | (Err(error), _) => Err(error),
    }
}

async fn up_with_fleet(
    project: &LoadedProject,
    fleet: &PluginFleet,
    operation_id: &str,
    options: &UpOptions,
) -> Result<EnvironmentView, CliError> {
    let resolved_compose = ComposeInspector::new(TokioCommandRunner)
        .resolve_ephemeral(&project.paths.root, &project.config.project.compose)
        .await?;
    let mut base_desired = project.base_desired();
    base_desired["resolved_compose_path"] =
        Value::String(resolved_compose.path().display().to_string());
    let target = prepare_capability(
        project,
        fleet,
        CoreCapability::Target,
        operation_id,
        "up",
        false,
        &base_desired,
        &json!({}),
    )
    .await?;
    if options.dry_run {
        let (prepared, _) =
            prepare_up_from_target(project, fleet, operation_id, &base_desired, target).await?;
        let view = plan_view(project, "up", &prepared);
        print_plan(&view, options.output)?;
        if options.output == OutputFormat::Human {
            output::line("Dry run complete; no changes were made.")?;
        }
        return Ok(EnvironmentView {
            environment_id: project.identity.id().as_str().to_owned(),
            branch: project.git.branch().to_owned(),
            profile: project.profile_name.clone(),
            status: combined_status(prepared.iter().map(|item| item.current.status)),
            endpoints: collect_endpoints(prepared.iter().map(|item| &item.current)),
            plugins: prepared.iter().map(status_from_prepared).collect(),
            environments: Vec::new(),
        });
    }
    let lock = acquire_lock(
        project,
        fleet,
        operation_id,
        options.lock_timeout,
        false,
        false,
    )
    .await?;
    let result = async {
        // The first target inspection only teaches the target plugin how to
        // reach its lock authority. Everything displayed and applied is
        // re-inspected and re-planned while that lock is held.
        let locked_target = prepare_capability(
            project,
            fleet,
            CoreCapability::Target,
            operation_id,
            "up",
            false,
            &base_desired,
            &json!({}),
        )
        .await?;
        let (prepared, mut target_state) = prepare_up_from_target(
            project,
            fleet,
            operation_id,
            &base_desired,
            locked_target,
        )
        .await?;
        let view = plan_view(project, "up", &prepared);
        if view
            .plugins
            .iter()
            .flat_map(|plugin| &plugin.actions)
            .any(|action| action.destructive)
        {
            return Err(CliError::Operation(
                "`up` refused a destructive provider plan; inspect `up --dry-run`, then use `down` explicitly before recreating the environment".into(),
            ));
        }
        if options.output == OutputFormat::Human {
            print_plan(&view, options.output)?;
        }

        let mut journal =
            OperationJournal::new(project.identity.id().as_str(), OperationKind::Up);
        journal.operation_id = Uuid::parse_str(operation_id)
            .map_err(|error| CliError::Operation(format!("invalid operation ID: {error}")))?;
        for item in &prepared {
            for action in &item.plan.actions {
                journal.actions.push(JournalAction {
                    plugin_id: item.plugin_id.clone(),
                    action_id: action.id.clone(),
                    summary: action.summary.clone(),
                    public_metadata: action.metadata.clone(),
                    completed: false,
                });
            }
        }
        journal.status = OperationStatus::Applying;
        journal
            .save(&project.paths.local.join("operations"))
            .await?;

        let mut applied = Vec::new();
        let apply_result = async {
        for mut item in prepared.clone() {
            if item.capability != CoreCapability::Target {
                item.context.metadata["target"] = target_state.clone();
            }
            if !item.plan.has_changes {
                continue;
            }
            let session = fleet.session(&item.plugin_id)?;
            reassert_mutation_lock(fleet, lock.as_ref()).await?;
            // Record the capability before invoking it. A plugin can fail after
            // creating only part of its resources, and rollback must still give
            // that capability an opportunity to clean up.
            applied.push(item.clone());
            let request = ApplyRequest {
                context: item.context.clone(),
                plan: item.plan.clone(),
                journal: Vec::new(),
            };
            // Mutations are not blindly retried: a lost response is ambiguous
            // and repeating it can duplicate provider or runtime side effects.
            let result =
                apply_with_progress(session, request, operation_id, options.output).await?;
            mark_plugin_actions_completed(
                &mut journal,
                &item.plugin_id,
                &item.plan,
                &result.journal,
            );
            if item.capability == CoreCapability::Target {
                target_state = result.state.clone();
            }
            journal
                .save(&project.paths.local.join("operations"))
                .await?;
        }

        journal.status = OperationStatus::Verifying;
        journal
            .save(&project.paths.local.join("operations"))
            .await?;
        inspect_environment(project, fleet, operation_id, false, &target_state).await
        }
        .await;

        match apply_result {
            Ok(environment) if environment.status == ResourceStatus::Ready => {
                journal.status = OperationStatus::Succeeded;
                journal.error = None;
                journal
                    .save(&project.paths.local.join("operations"))
                    .await?;
                Ok(environment)
            }
            Ok(environment) => {
                let message = format!(
                    "environment readiness ended in state {:?}",
                    environment.status
                );
                rollback_after_failure(
                    project,
                    fleet,
                    operation_id,
                    &mut journal,
                    &applied,
                    &target_state,
                    lock.as_ref(),
                    options.keep_failed,
                    options.output,
                    &message,
                )
                .await?;
                Err(CliError::Operation(message))
            }
            Err(error) => {
                let message = error.to_string();
                rollback_after_failure(
                    project,
                    fleet,
                    operation_id,
                    &mut journal,
                    &applied,
                    &target_state,
                    lock.as_ref(),
                    options.keep_failed,
                    options.output,
                    &message,
                )
                .await?;
                Err(error)
            }
        }
    }
    .await;

    let release_result = release_lock(fleet, lock).await;
    let environment = finish_with_lock_release(result, release_result)?;
    print_environment(&environment, options.output)?;
    Ok(environment)
}

async fn apply_with_progress(
    session: &PluginSession,
    request: ApplyRequest,
    operation_id: &str,
    format: OutputFormat,
) -> Result<ApplyResult, CliError> {
    let mut events = session.client.subscribe();
    let apply = session.client.apply(request);
    tokio::pin!(apply);
    let interrupt = tokio::signal::ctrl_c();
    tokio::pin!(interrupt);
    let mut cancelled = false;
    let mut events_open = true;

    loop {
        tokio::select! {
            result = &mut apply => {
                let result = result.map_err(|error| CliError::Plugin(error.to_string()))?;
                if cancelled {
                    return Err(CliError::Operation(
                        "operation cancelled after the active plugin reached a safe stopping point"
                            .into(),
                    ));
                }
                return Ok(result);
            }
            signal = &mut interrupt, if !cancelled => {
                signal?;
                cancelled = true;
                eprintln!("cancellation requested; waiting for the active plugin to stop safely");
                let cancellation = session.client.cancel(CancelRequest {
                    operation_id: operation_id.to_owned(),
                    reason: Some("operator pressed Ctrl+C".to_owned()),
                });
                let _ = tokio::time::timeout(Duration::from_secs(5), cancellation).await;
            }
            event = events.recv(), if events_open => {
                match event {
                    Ok(ClientEvent::Plugin(PluginEvent::Progress {
                        message,
                        completed,
                        total,
                        ..
                    })) if format == OutputFormat::Human => {
                        match (completed, total) {
                            (Some(completed), Some(total)) => {
                                eprintln!("{message} ({completed}/{total})");
                            }
                            _ => eprintln!("{message}"),
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                        if format == OutputFormat::Human {
                            eprintln!("warning: skipped {count} plugin progress events");
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        events_open = false;
                    }
                }
            }
        }
    }
}

async fn prepare_up_from_target(
    project: &LoadedProject,
    fleet: &PluginFleet,
    operation_id: &str,
    base_desired: &Value,
    target: PreparedCapability,
) -> Result<(Vec<PreparedCapability>, Value), CliError> {
    let mut target_state = target.current.state.clone();
    if target_state.is_null() {
        target_state = json!({});
    }
    let mut prepared = Vec::with_capacity(APPLY_ORDER.len());
    for capability in APPLY_ORDER {
        if capability == CoreCapability::Target {
            prepared.push(target.clone());
        } else {
            prepared.push(
                prepare_capability(
                    project,
                    fleet,
                    capability,
                    operation_id,
                    "up",
                    false,
                    base_desired,
                    &target_state,
                )
                .await?,
            );
        }
    }
    Ok((prepared, target_state))
}

pub async fn query(
    project: LoadedProject,
    options: QueryOptions,
    urls_only: bool,
) -> Result<EnvironmentView, CliError> {
    let capabilities = [
        CoreCapability::Target,
        CoreCapability::Runtime,
        CoreCapability::Exposure,
        CoreCapability::Dns,
    ];
    let fleet = PluginFleet::start(&project, &capabilities).await?;
    let operation_id = Uuid::new_v4().to_string();
    let result =
        inspect_environment(&project, &fleet, &operation_id, options.all, &json!({})).await;
    let shutdown = fleet.shutdown().await;
    let environment = match (result, shutdown) {
        (Ok(environment), Ok(())) => environment,
        (Ok(_), Err(error)) | (Err(error), _) => return Err(error),
    };
    if urls_only {
        print_urls(&environment, options.output)?;
    } else {
        print_environment(&environment, options.output)?;
    }
    Ok(environment)
}

pub async fn inspect_readonly(
    project: LoadedProject,
    all: bool,
) -> Result<EnvironmentView, CliError> {
    let capabilities = [
        CoreCapability::Target,
        CoreCapability::Runtime,
        CoreCapability::Exposure,
        CoreCapability::Dns,
    ];
    let fleet = PluginFleet::start(&project, &capabilities).await?;
    let operation_id = Uuid::new_v4().to_string();
    let result = inspect_environment(&project, &fleet, &operation_id, all, &json!({})).await;
    let shutdown = fleet.shutdown().await;
    match (result, shutdown) {
        (Ok(environment), Ok(())) => Ok(environment),
        (Ok(_), Err(error)) | (Err(error), _) => Err(error),
    }
}

pub async fn inspect_target(project: LoadedProject) -> Result<InspectResult, CliError> {
    let fleet = PluginFleet::start(&project, &[CoreCapability::Target]).await?;
    let operation_id = Uuid::new_v4().to_string();
    let result = async {
        let plugin_id = project.plugin_id(CoreCapability::Target);
        let session = fleet.session(plugin_id)?;
        let context = operation_context(
            &project,
            &fleet,
            session,
            CoreCapability::Target,
            &operation_id,
            "inspect",
            false,
            &json!({}),
        )
        .await?;
        retry(|| {
            session.client.inspect(InspectRequest {
                context: context.clone(),
            })
        })
        .await
    }
    .await;
    let shutdown = fleet.shutdown().await;
    match (result, shutdown) {
        (Ok(inspection), Ok(())) => Ok(inspection),
        (Ok(_), Err(error)) | (Err(error), _) => Err(error),
    }
}

pub async fn live_environment_count(project: LoadedProject) -> Result<usize, CliError> {
    let environment = inspect_readonly(project, true).await?;
    for plugin in &environment.plugins {
        if let Some(environments) = plugin.state.get("environments").and_then(Value::as_array) {
            return Ok(environments.len());
        }
        if let Some(count) = plugin
            .state
            .get("environment_count")
            .and_then(Value::as_u64)
        {
            return usize::try_from(count)
                .map_err(|_| CliError::Operation("environment count is too large".into()));
        }
    }
    Ok(usize::from(environment.status != ResourceStatus::Absent))
}

pub async fn down(project: LoadedProject, options: DownOptions) -> Result<(), CliError> {
    project.paths.ensure_local_layout().await?;
    let fleet = PluginFleet::start(&project, &DESTROY_ORDER).await?;
    let operation_id = Uuid::new_v4().to_string();
    let result = down_with_fleet(&project, &fleet, &operation_id, &options).await;
    let shutdown = fleet.shutdown().await;
    match (result, shutdown) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(error)) | (Err(error), _) => Err(error),
    }
}

async fn down_with_fleet(
    project: &LoadedProject,
    fleet: &PluginFleet,
    operation_id: &str,
    options: &DownOptions,
) -> Result<(), CliError> {
    let mut desired = project.base_desired();
    desired["destroy"] = Value::Bool(true);
    let prepared =
        prepare_down_capabilities(project, fleet, operation_id, &desired, options).await?;
    let machine_isolation = project.profile().isolation == lightrail_core::Isolation::Machine;
    let displayed_contract = plan_contract(&prepared);

    let view = plan_view(project, "down", &prepared);
    if options.dry_run {
        print_plan(&view, options.output)?;
        if options.output == OutputFormat::Human {
            output::line("Dry run complete; no changes were made.")?;
        }
        return Ok(());
    }
    if options.output == OutputFormat::Human {
        print_plan(&view, options.output)?;
    }
    if !view.has_changes {
        print_destroyed(project, options, true)?;
        return Ok(());
    }
    if !options.yes {
        if !io::stdin().is_terminal() {
            return Err(CliError::Usage(
                "`down` needs confirmation; pass `--yes` in non-interactive use".into(),
            ));
        }
        let subject = if options.all {
            format!(
                "Destroy every project environment visible through profile `{}`'s target?",
                project.profile_name
            )
        } else {
            format!(
                "Destroy branch `{}` with profile `{}`?",
                project.git.branch(),
                project.profile_name
            )
        };
        if !Confirm::new()
            .with_prompt(subject)
            .default(false)
            .interact()
            .map_err(|error| CliError::Operation(format!("confirmation failed: {error}")))?
        {
            print_cancelled(options.output)?;
            return Ok(());
        }
    }

    let lock = acquire_lock(
        project,
        fleet,
        operation_id,
        options.lock_timeout,
        options.all,
        options.force && machine_isolation,
    )
    .await?;
    let bypassed_lock = lock.is_none();

    let result = async {
        let prepared =
            prepare_down_capabilities(project, fleet, operation_id, &desired, options).await?;
        if plan_contract(&prepared) != displayed_contract {
            let retry = down_retry_command(&project.profile_name, options, false);
            return Err(CliError::Operation(format!(
                "owned resources changed while waiting for the mutation lock; rerun `{retry}` to review the new plan"
            )));
        }
        let mut journal =
            OperationJournal::new(project.identity.id().as_str(), OperationKind::Down);
        journal.operation_id = Uuid::parse_str(operation_id)
            .map_err(|error| CliError::Operation(format!("invalid operation ID: {error}")))?;
        journal.status = OperationStatus::Applying;
        journal
            .save(&project.paths.local.join("operations"))
            .await?;

        let mut failures = Vec::new();
        for item in &prepared {
            let session = fleet.session(&item.plugin_id)?;
            if let Err(error) = reassert_mutation_lock(fleet, lock.as_ref()).await {
                failures.push(error.to_string());
                break;
            }
            let request = DestroyRequest {
                context: item.context.clone(),
                current: Some(item.current.state.clone()),
                // Recovery force is safe only when the target capability will
                // delete the machine that owns any skipped runtime resources.
                // A shared SSH host must never report successful cleanup while
                // leaving an unreachable environment behind. When the target
                // lock was acquired, keep its snapshot/ownership verification
                // enabled even if `--force` permits best-effort runtime cleanup.
                force: options.force
                    && machine_isolation
                    && (item.capability != CoreCapability::Target || bypassed_lock),
                journal: Vec::new(),
            };
            let attempt =
                destroy_with_progress(session, request, operation_id, options.output).await;
            if attempt.cancelled {
                failures.push(
                    "destruction cancelled after the active plugin reached a safe stopping point"
                        .to_owned(),
                );
                break;
            }
            match attempt.result {
                Ok(result) if result.destroyed && result.remaining.is_empty() => {}
                Ok(result) => failures.push(format!(
                    "{} left resources: {}",
                    item.plugin_id,
                    result.remaining.join(", ")
                )),
                Err(error)
                    if options.force
                        && machine_isolation
                        && item.capability != CoreCapability::Target =>
                {
                    eprintln!(
                        "warning: {} cleanup failed before forced machine deletion: {error}",
                        item.capability.as_str()
                    );
                }
                Err(error) => failures.push(format!("{}: {error}", item.plugin_id)),
            }
        }
        if failures.is_empty() {
            journal.status = OperationStatus::Succeeded;
            journal
                .save(&project.paths.local.join("operations"))
                .await?;
            Ok(())
        } else {
            let retry = down_retry_command(&project.profile_name, options, true);
            let message = format!(
                "destruction incomplete; rerun `{retry}`: {}",
                failures.join("; ")
            );
            journal.status = OperationStatus::Failed;
            journal.error = Some(message.clone());
            journal
                .save(&project.paths.local.join("operations"))
                .await?;
            Err(CliError::Operation(message))
        }
    }
    .await;

    let release = release_lock(fleet, lock).await;
    finish_with_lock_release(result, release)?;
    print_destroyed(project, options, false)?;
    Ok(())
}

struct DestroyAttempt {
    result: Result<DestroyResult, CliError>,
    cancelled: bool,
}

async fn destroy_with_progress(
    session: &PluginSession,
    request: DestroyRequest,
    operation_id: &str,
    format: OutputFormat,
) -> DestroyAttempt {
    let mut events = session.client.subscribe();
    let destroy = session.client.destroy(request);
    tokio::pin!(destroy);
    let interrupt = tokio::signal::ctrl_c();
    tokio::pin!(interrupt);
    let mut cancelled = false;
    let mut events_open = true;

    loop {
        tokio::select! {
            result = &mut destroy => {
                return DestroyAttempt {
                    result: result.map_err(|error| CliError::Plugin(error.to_string())),
                    cancelled,
                };
            }
            signal = &mut interrupt, if !cancelled => {
                match signal {
                    Ok(()) => {
                        cancelled = true;
                        eprintln!(
                            "cancellation requested; waiting for the active destroy step to stop safely"
                        );
                        let cancellation = session.client.cancel(CancelRequest {
                            operation_id: operation_id.to_owned(),
                            reason: Some("operator pressed Ctrl+C".to_owned()),
                        });
                        let _ = tokio::time::timeout(Duration::from_secs(5), cancellation).await;
                    }
                    Err(error) => {
                        return DestroyAttempt {
                            result: Err(error.into()),
                            cancelled: false,
                        };
                    }
                }
            }
            event = events.recv(), if events_open => {
                match event {
                    Ok(ClientEvent::Plugin(PluginEvent::Progress {
                        message,
                        completed,
                        total,
                        ..
                    })) if format == OutputFormat::Human => {
                        match (completed, total) {
                            (Some(completed), Some(total)) => {
                                eprintln!("{message} ({completed}/{total})");
                            }
                            _ => eprintln!("{message}"),
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                        if format == OutputFormat::Human {
                            eprintln!("warning: skipped {count} plugin progress events");
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        events_open = false;
                    }
                }
            }
        }
    }
}

async fn prepare_down_capabilities(
    project: &LoadedProject,
    fleet: &PluginFleet,
    operation_id: &str,
    desired: &Value,
    options: &DownOptions,
) -> Result<Vec<PreparedCapability>, CliError> {
    let target = prepare_capability(
        project,
        fleet,
        CoreCapability::Target,
        operation_id,
        "destroy",
        options.all,
        desired,
        &json!({}),
    )
    .await?;
    let target_state = target.current.state.clone();
    let machine_isolation = project.profile().isolation == lightrail_core::Isolation::Machine;
    let mut prepared = Vec::with_capacity(DESTROY_ORDER.len());
    for capability in DESTROY_ORDER {
        if capability == CoreCapability::Target {
            prepared.push(target.clone());
        } else if options.all && machine_isolation {
            // Each provider machine owns its runtime, ingress, files, and
            // volumes. Project-wide provider deletion is both sufficient and
            // the only safe way to handle environments spread across hosts.
            continue;
        } else {
            match prepare_capability(
                project,
                fleet,
                capability,
                operation_id,
                "destroy",
                options.all,
                desired,
                &target_state,
            )
            .await
            {
                Ok(item) => prepared.push(item),
                Err(error) if options.force && machine_isolation => {
                    eprintln!(
                        "warning: skipping {} cleanup before forced machine deletion: {error}",
                        capability.as_str()
                    );
                }
                Err(error) => return Err(error),
            }
        }
    }
    Ok(prepared)
}

fn print_destroyed(
    project: &LoadedProject,
    options: &DownOptions,
    already_absent: bool,
) -> Result<(), CliError> {
    match options.output {
        OutputFormat::Json => output::json(&json!({
            "destroyed": true,
            "already_absent": already_absent,
        })),
        OutputFormat::Plain => {
            if already_absent {
                output::line("environment is already absent")
            } else {
                output::line("environment destroyed")
            }
        }
        OutputFormat::Human if options.all && already_absent => output::line(format!(
            "Nothing to do: profile `{}`'s target has no environments for project `{}`.",
            project.profile_name, project.config.project.slug
        )),
        OutputFormat::Human if options.all => output::line(format!(
            "Destroyed all project environments visible through profile `{}`'s target.",
            project.profile_name
        )),
        OutputFormat::Human if already_absent => output::line(format!(
            "Nothing to do: {} / {} is already absent.",
            project.git.branch(),
            project.profile_name
        )),
        OutputFormat::Human => output::line(format!(
            "Destroyed {} / {}.",
            project.git.branch(),
            project.profile_name
        )),
    }
}

fn print_cancelled(format: OutputFormat) -> Result<(), CliError> {
    match format {
        OutputFormat::Json => output::json(&json!({
            "destroyed": false,
            "cancelled": true,
        })),
        OutputFormat::Plain => output::line("cancelled"),
        OutputFormat::Human => output::line("Cancelled; no resources were changed."),
    }
}

fn down_retry_command(profile: &str, options: &DownOptions, assume_yes: bool) -> String {
    let mut command = format!(
        "lightrail --profile={} down",
        shell_quote_command_value(profile)
    );
    if options.all {
        command.push_str(" --all");
    }
    if options.force {
        command.push_str(" --force");
    }
    command.push_str(&format!(
        " --lock-timeout {}s",
        options.lock_timeout.as_secs()
    ));
    if assume_yes {
        command.push_str(" --yes");
    }
    command
}

fn shell_quote_command_value(value: &str) -> String {
    if !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return value.to_owned();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

pub async fn logs(project: LoadedProject, options: LogOptions) -> Result<(), CliError> {
    let capabilities = [CoreCapability::Target, CoreCapability::Runtime];
    let fleet = PluginFleet::start(&project, &capabilities).await?;
    let operation_id = Uuid::new_v4().to_string();
    let result = logs_with_fleet(&project, &fleet, &operation_id, &options).await;
    let shutdown = fleet.shutdown().await;
    match (result, shutdown) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(error)) | (Err(error), _) => Err(error),
    }
}

async fn logs_with_fleet(
    project: &LoadedProject,
    fleet: &PluginFleet,
    operation_id: &str,
    options: &LogOptions,
) -> Result<(), CliError> {
    let target_id = project.plugin_id(CoreCapability::Target);
    let target_session = fleet.session(target_id)?;
    let target_context = operation_context(
        project,
        fleet,
        target_session,
        CoreCapability::Target,
        operation_id,
        "inspect",
        false,
        &json!({}),
    )
    .await?;
    let target = retry(|| {
        target_session.client.inspect(InspectRequest {
            context: target_context.clone(),
        })
    })
    .await?;

    let runtime_id = project.plugin_id(CoreCapability::Runtime);
    let runtime = fleet.session(runtime_id)?;
    let context = operation_context(
        project,
        fleet,
        runtime,
        CoreCapability::Runtime,
        operation_id,
        "logs",
        false,
        &target.state,
    )
    .await?;
    let mut events = runtime.client.subscribe();
    let result = retry(|| {
        runtime.client.logs(LogsRequest {
            context: context.clone(),
            service: options.service.clone(),
            tail: Some(u64::try_from(options.tail).unwrap_or(u64::MAX)),
            since: None,
            follow: options.follow,
        })
    })
    .await?;
    print_log_records(&result.records, options.output)?;

    if options.follow {
        loop {
            tokio::select! {
                signal = tokio::signal::ctrl_c() => {
                    signal?;
                    break;
                }
                event = events.recv() => {
                    match event {
                        Ok(lightrail_plugin_protocol::ClientEvent::Plugin(
                            lightrail_plugin_protocol::PluginEvent::Log { record, .. }
                        )) => print_log_records(&[record], options.output)?,
                        Ok(lightrail_plugin_protocol::ClientEvent::Stderr(_)) => {
                            eprintln!(
                                "warning: runtime plugin wrote to stderr; content was suppressed to avoid leaking sensitive values"
                            );
                        }
                        Ok(_) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                            eprintln!("warning: skipped {count} plugin log events");
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        }
    }
    Ok(())
}

async fn prepare_capability(
    project: &LoadedProject,
    fleet: &PluginFleet,
    capability: CoreCapability,
    operation_id: &str,
    operation: &str,
    all: bool,
    base_desired: &Value,
    target_state: &Value,
) -> Result<PreparedCapability, CliError> {
    let plugin_id = project.plugin_id(capability).to_owned();
    let session = fleet.session(&plugin_id)?;
    let context = operation_context(
        project,
        fleet,
        session,
        capability,
        operation_id,
        operation,
        all,
        target_state,
    )
    .await?;
    let desired = desired_with_target(base_desired, target_state);
    let validation = retry(|| {
        session.client.validate(ValidateRequest {
            context: context.clone(),
            desired: desired.clone(),
        })
    })
    .await?;
    if !validation.valid {
        let details = validation
            .diagnostics
            .iter()
            .map(|diagnostic| format!("{}: {}", diagnostic.code, diagnostic.message))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(CliError::Plugin(format!(
            "plugin `{plugin_id}` rejected {} configuration: {details}",
            capability.as_str()
        )));
    }

    let current = retry(|| {
        session.client.inspect(InspectRequest {
            context: context.clone(),
        })
    })
    .await?;
    let plan = retry(|| {
        session.client.plan(PlanRequest {
            context: context.clone(),
            desired: desired.clone(),
            current: Some(current.state.clone()),
        })
    })
    .await?;
    Ok(PreparedCapability {
        capability,
        plugin_id,
        context,
        current,
        plan,
    })
}

async fn operation_context(
    project: &LoadedProject,
    fleet: &PluginFleet,
    session: &PluginSession,
    capability: CoreCapability,
    operation_id: &str,
    operation: &str,
    all: bool,
    target_state: &Value,
) -> Result<OperationContext, CliError> {
    let secrets = resolve_plugin_secrets(
        project,
        &fleet.secret_cache,
        &session.manifest,
        capability,
        operation,
    )
    .await?;
    Ok(OperationContext {
        operation_id: operation_id.to_owned(),
        environment_id: project.identity.id().as_str().to_owned(),
        profile: project.profile_name.clone(),
        project_root: Some(project.paths.root.display().to_string()),
        config: merged_plugin_config(project, &session.manifest.id, capability)?,
        secrets,
        metadata: json!({
            "capability": capability.as_str(),
            "operation": operation,
            "all": all,
            "project_id": project.config.project.id.to_string(),
            "project_slug": project.config.project.slug,
            "labels": project.identity.resource_labels(),
            "target": target_state,
        }),
    })
}

async fn resolve_plugin_secrets(
    project: &LoadedProject,
    cache: &OperationSecretCache,
    manifest: &PluginManifest,
    capability: CoreCapability,
    operation: &str,
) -> Result<BTreeMap<String, SecretValue>, CliError> {
    let referenced = secrets_for_capability(project, capability, operation == "up")?;
    let wildcard = manifest
        .required_secrets
        .iter()
        .any(|requirement| requirement.name == "*");
    let mut requested = BTreeMap::new();
    for requirement in &manifest.required_secrets {
        if requirement.name != "*" {
            requested.insert(requirement.name.clone(), requirement.required);
        }
    }
    if wildcard {
        for name in referenced {
            *requested.entry(name).or_insert(false) = true;
        }
    } else {
        for name in referenced {
            let Some(required) = requested.get_mut(&name) else {
                return Err(CliError::Plugin(format!(
                    "plugin `{}` did not declare referenced secret `{name}` in its manifest",
                    manifest.id
                )));
            };
            *required = true;
        }
    }

    let store = SecretStore::new(
        KeyringBackend,
        project.config.project.id.to_string(),
        &project.paths.local,
    );
    let mut resolved = BTreeMap::new();
    for (name, required) in requested {
        match cache.resolve(&store, &name).await {
            Ok(value) => {
                resolved.insert(name, SecretValue::new(value.expose_secret().to_owned()));
            }
            Err(CliError::SecretUnavailable { .. }) if !required => {}
            Err(error) => return Err(error),
        }
    }
    Ok(resolved)
}

async fn resolve_uncached_secret<B: SecretBackend>(
    store: &SecretStore<B>,
    name: &str,
) -> Result<SecretString, CliError> {
    match store.resolve(name).await {
        Ok(value) => Ok(value),
        Err(error @ CliError::SecretUnavailable { .. }) if !io::stdin().is_terminal() => Err(error),
        Err(CliError::SecretUnavailable { .. }) => {
            let value = Password::new()
                .with_prompt(format!("Secret {name} (used for this command only)"))
                .interact()
                .map_err(|prompt| {
                    CliError::Operation(format!("could not read secret `{name}`: {prompt}"))
                })?;
            Ok(SecretString::from(value))
        }
        Err(error) => Err(error),
    }
}

fn secrets_for_capability(
    project: &LoadedProject,
    capability: CoreCapability,
    include_runtime_values: bool,
) -> Result<BTreeSet<String>, CliError> {
    let mut names = BTreeSet::new();
    let plugin_id = project.plugin_id(capability);
    collect_secret_references(
        &merged_plugin_config(project, plugin_id, capability)?,
        &mut names,
    );
    if capability == CoreCapability::Runtime && include_runtime_values {
        collect_secret_references(&project.base_desired(), &mut names);
    }
    Ok(names)
}

fn merged_plugin_config(
    project: &LoadedProject,
    plugin_id: &str,
    current: CoreCapability,
) -> Result<Value, CliError> {
    let mut merged = serde_json::Map::new();
    for capability in CoreCapability::ALL {
        if capability == current || project.plugin_id(capability) != plugin_id {
            continue;
        }
        merge_json_object(&mut merged, &project.capability_config(capability)?)?;
    }
    merge_json_object(&mut merged, &project.capability_config(current)?)?;
    Ok(Value::Object(merged))
}

fn merge_json_object(
    target: &mut serde_json::Map<String, Value>,
    source: &Value,
) -> Result<(), CliError> {
    let source = source.as_object().ok_or_else(|| {
        CliError::Config("plugin capability settings must serialize as an object".into())
    })?;
    for (key, value) in source {
        match (target.get_mut(key), value) {
            (Some(Value::Object(existing)), Value::Object(overlay)) => {
                for (nested_key, nested_value) in overlay {
                    existing.insert(nested_key.clone(), nested_value.clone());
                }
            }
            _ => {
                target.insert(key.clone(), value.clone());
            }
        }
    }
    Ok(())
}

fn collect_secret_references(value: &Value, names: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            if let Some(name) = object.get("secret").and_then(Value::as_str) {
                names.insert(name.to_owned());
            }
            for child in object.values() {
                collect_secret_references(child, names);
            }
        }
        Value::Array(array) => {
            for child in array {
                collect_secret_references(child, names);
            }
        }
        _ => {}
    }
}

async fn inspect_environment(
    project: &LoadedProject,
    fleet: &PluginFleet,
    operation_id: &str,
    all: bool,
    initial_target: &Value,
) -> Result<EnvironmentView, CliError> {
    let target_id = project.plugin_id(CoreCapability::Target);
    let target_session = fleet.session(target_id)?;
    let target_context = operation_context(
        project,
        fleet,
        target_session,
        CoreCapability::Target,
        operation_id,
        "inspect",
        all,
        initial_target,
    )
    .await?;
    let target = retry(|| {
        target_session.client.inspect(InspectRequest {
            context: target_context.clone(),
        })
    })
    .await?;
    let target_state = if target.state.is_null() {
        initial_target.clone()
    } else {
        target.state.clone()
    };

    let mut observations = vec![(CoreCapability::Target, target_id.to_owned(), target)];
    let target_states = if all && project.profile().isolation == lightrail_core::Isolation::Machine
    {
        target_state
            .get("targets")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    } else {
        vec![target_state]
    };
    for downstream_target in target_states {
        let mut inspected_plugins = BTreeSet::new();
        for capability in [
            CoreCapability::Runtime,
            CoreCapability::Exposure,
            CoreCapability::Dns,
        ] {
            let plugin_id = project.plugin_id(capability);
            if !inspected_plugins.insert(plugin_id.to_owned()) {
                continue;
            }
            let session = fleet.session(plugin_id)?;
            let context = operation_context(
                project,
                fleet,
                session,
                capability,
                operation_id,
                "inspect",
                all,
                &downstream_target,
            )
            .await?;
            let inspection = retry(|| {
                session.client.inspect(InspectRequest {
                    context: context.clone(),
                })
            })
            .await;
            let inspection = match inspection {
                Ok(inspection) => inspection,
                Err(error)
                    if all && project.profile().isolation == lightrail_core::Isolation::Machine =>
                {
                    let environment_id = downstream_target
                        .get("environment_id")
                        .and_then(Value::as_str)
                        .or_else(|| {
                            downstream_target
                                .get("environment_label")
                                .and_then(Value::as_str)
                        })
                        .map(ToOwned::to_owned)
                        .or_else(|| {
                            downstream_target
                                .get("server_id")
                                .and_then(Value::as_u64)
                                .map(|id| format!("hetzner-server-{id}"))
                        })
                        .unwrap_or_else(|| "unknown-machine".to_owned());
                    eprintln!("warning: could not inspect runtime on {environment_id}: {error}");
                    InspectResult {
                        status: ResourceStatus::Degraded,
                        endpoints: Vec::new(),
                        state: json!({
                            "environments": [{
                                "environment_id": environment_id,
                                "status": "degraded"
                            }]
                        }),
                        diagnostics: Vec::new(),
                    }
                }
                Err(error) => return Err(error),
            };
            observations.push((capability, plugin_id.to_owned(), inspection));
        }
    }

    let environments = if all {
        collect_environment_summaries(observations.iter().map(|(_, _, inspection)| inspection))
    } else {
        Vec::new()
    };
    let downstream_status = combined_status(
        observations
            .iter()
            .filter(|(capability, _, _)| *capability != CoreCapability::Target)
            .map(|(_, _, inspection)| inspection.status),
    );
    let status = if downstream_status == ResourceStatus::Absent
        && all
        && project.profile().isolation == lightrail_core::Isolation::Machine
    {
        observations
            .first()
            .map_or(ResourceStatus::Absent, |(_, _, target)| target.status)
    } else {
        downstream_status
    };
    Ok(EnvironmentView {
        environment_id: project.identity.id().as_str().to_owned(),
        branch: project.git.branch().to_owned(),
        profile: project.profile_name.clone(),
        status,
        endpoints: collect_endpoints(observations.iter().map(|(_, _, inspection)| inspection)),
        plugins: observations
            .into_iter()
            .map(|(capability, plugin, inspection)| PluginStatusView {
                capability: capability.as_str().to_owned(),
                plugin,
                status: inspection.status,
                state: inspection.state,
            })
            .collect(),
        environments,
    })
}

async fn acquire_lock(
    project: &LoadedProject,
    fleet: &PluginFleet,
    operation_id: &str,
    timeout: Duration,
    all: bool,
    force: bool,
) -> Result<Option<MutationLock>, CliError> {
    let plugin_id = project.plugin_id(CoreCapability::Target);
    let session = fleet.session(plugin_id)?;
    if !session
        .manifest
        .capabilities
        .contains(&Capability::OperationLock)
    {
        return Err(CliError::Plugin(format!(
            "target plugin `{plugin_id}` does not provide authoritative operation locks"
        )));
    }
    let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
    let (scope, scope_id) = match (project.profile().isolation, all) {
        (lightrail_core::Isolation::Project, _) => (
            LockScope::Target,
            format!("target:{}", project.plugin_id(CoreCapability::Target)),
        ),
        (lightrail_core::Isolation::Machine, true) => {
            (LockScope::Project, project.config.project.id.to_string())
        }
        (lightrail_core::Isolation::Machine, false) => (
            LockScope::Environment,
            project.identity.id().as_str().to_owned(),
        ),
    };
    let request = LockAcquireRequest {
        environment_id: project.identity.id().as_str().to_owned(),
        scope,
        scope_id: scope_id.clone(),
        operation_id: operation_id.to_owned(),
        timeout_ms,
        lease_ms: None,
    };
    let result = match session.client.lock_acquire(request).await {
        Ok(result) => result,
        Err(error) if force && lock_authority_unreachable(&error) => {
            eprintln!(
                "warning: target lock authority is unreachable; continuing forced machine deletion: {error}"
            );
            return Ok(None);
        }
        Err(error) => return Err(CliError::Plugin(error.to_string())),
    };
    if !result.acquired {
        return Err(CliError::Operation(format!(
            "environment lock is held{}; retry later or increase `--lock-timeout`",
            result
                .holder
                .as_deref()
                .map_or_else(String::new, |holder| format!(" by {holder}"))
        )));
    }
    let token = result.token.ok_or_else(|| {
        CliError::Plugin(format!(
            "target plugin `{plugin_id}` acquired a lock without a release token"
        ))
    })?;
    Ok(Some(MutationLock {
        plugin_id: plugin_id.to_owned(),
        environment_id: project.identity.id().as_str().to_owned(),
        scope,
        scope_id,
        operation_id: operation_id.to_owned(),
        token,
    }))
}

fn lock_authority_unreachable(error: &ClientError) -> bool {
    matches!(
        error,
        ClientError::Remote(remote)
            if matches!(
                remote.kind,
                lightrail_plugin_protocol::ErrorKind::Unavailable
            )
    )
}

#[derive(Debug, Eq, PartialEq)]
enum LockContinuity {
    Confirmed,
    NotAcquired { holder: Option<String> },
    MissingToken,
    TokenMismatch { unexpected: SecretValue },
}

fn classify_lock_continuity(
    result: LockAcquireResult,
    expected_token: &SecretValue,
) -> LockContinuity {
    if !result.acquired {
        return LockContinuity::NotAcquired {
            holder: result.holder,
        };
    }
    match result.token {
        Some(token) if token == *expected_token => LockContinuity::Confirmed,
        Some(unexpected) => LockContinuity::TokenMismatch { unexpected },
        None => LockContinuity::MissingToken,
    }
}

async fn reassert_mutation_lock(
    fleet: &PluginFleet,
    lock: Option<&MutationLock>,
) -> Result<(), CliError> {
    let Some(lock) = lock else {
        // Machine recovery can explicitly bypass an unreachable lock authority.
        return Ok(());
    };
    let session = fleet.session(&lock.plugin_id)?;
    let result = session
        .client
        .lock_acquire(LockAcquireRequest {
            environment_id: lock.environment_id.clone(),
            scope: lock.scope,
            scope_id: lock.scope_id.clone(),
            operation_id: lock.operation_id.clone(),
            timeout_ms: LOCK_CONTINUITY_TIMEOUT_MS,
            lease_ms: None,
        })
        .await
        .map_err(|error| {
            CliError::Operation(format!(
                "mutation lock continuity check failed before a provider change; no mutation was attempted: {error}"
            ))
        })?;

    match classify_lock_continuity(result, &lock.token) {
        LockContinuity::Confirmed => Ok(()),
        LockContinuity::NotAcquired { holder } => Err(CliError::Operation(format!(
            "mutation lock continuity was lost before a provider change; no mutation was attempted{}",
            holder
                .as_deref()
                .map_or_else(String::new, |holder| format!("; current holder: {holder}"))
        ))),
        LockContinuity::MissingToken => Err(CliError::Plugin(format!(
            "target plugin `{}` reasserted a mutation lock without a token; no mutation was attempted",
            lock.plugin_id
        ))),
        LockContinuity::TokenMismatch { unexpected } => {
            let cleanup = retry(|| {
                session.client.lock_release(LockReleaseRequest {
                    environment_id: lock.environment_id.clone(),
                    scope: lock.scope,
                    scope_id: lock.scope_id.clone(),
                    operation_id: lock.operation_id.clone(),
                    token: unexpected.clone(),
                })
            })
            .await;
            match cleanup {
                Ok(result) if result.released => Err(CliError::Operation(
                    "mutation lock continuity was lost before a provider change; the newly acquired mismatched lock was released and no mutation was attempted"
                        .into(),
                )),
                Ok(_) => Err(CliError::Operation(
                    "mutation lock continuity was lost before a provider change; the target did not release the newly acquired mismatched lock and no mutation was attempted"
                        .into(),
                )),
                Err(error) => Err(CliError::Operation(format!(
                    "mutation lock continuity was lost before a provider change; releasing the newly acquired mismatched lock failed and no mutation was attempted: {error}"
                ))),
            }
        }
    }
}

async fn release_lock(fleet: &PluginFleet, lock: Option<MutationLock>) -> Result<(), CliError> {
    let Some(lock) = lock else {
        return Ok(());
    };
    let session = fleet.session(&lock.plugin_id)?;
    let result = retry(|| {
        session.client.lock_release(LockReleaseRequest {
            environment_id: lock.environment_id.clone(),
            scope: lock.scope,
            scope_id: lock.scope_id.clone(),
            operation_id: lock.operation_id.clone(),
            token: lock.token.clone(),
        })
    })
    .await?;
    if result.released {
        Ok(())
    } else {
        Err(CliError::Operation(format!(
            "plugin `{}` did not release the environment lock",
            lock.plugin_id
        )))
    }
}

fn finish_with_lock_release<T>(
    operation: Result<T, CliError>,
    release: Result<(), CliError>,
) -> Result<T, CliError> {
    match (operation, release) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) | (Err(error), Ok(())) => Err(error),
        (Err(operation), Err(release)) => Err(CliError::Operation(format!(
            "{operation}; additionally failed to release the mutation lock: {release}"
        ))),
    }
}

async fn rollback_after_failure(
    project: &LoadedProject,
    fleet: &PluginFleet,
    _operation_id: &str,
    journal: &mut OperationJournal,
    applied: &[PreparedCapability],
    target_state: &Value,
    lock: Option<&MutationLock>,
    keep_failed: bool,
    format: OutputFormat,
    error: &str,
) -> Result<(), CliError> {
    journal.error = Some(error.to_owned());
    if keep_failed {
        journal.status = OperationStatus::Failed;
        journal
            .save(&project.paths.local.join("operations"))
            .await?;
        if format == OutputFormat::Human {
            eprintln!("warning: failed resources were preserved because --keep-failed was used");
        }
        return Ok(());
    }

    journal.status = OperationStatus::RollingBack;
    journal
        .save(&project.paths.local.join("operations"))
        .await?;
    let mut rollback_failures = Vec::new();
    for item in applied.iter().rev() {
        let operation = match item.capability {
            CoreCapability::Target if item.current.status == ResourceStatus::Absent => {
                "rollback_cleanup"
            }
            CoreCapability::Runtime if prior_runtime_revision(item).is_some() => {
                if !supports_previous_revision_rollback(item) {
                    rollback_failures.push(format!(
                        "{}: the runtime changed but its plan did not advertise prior-revision rollback",
                        item.plugin_id
                    ));
                    continue;
                }
                "rollback"
            }
            CoreCapability::Runtime => "rollback_cleanup",
            _ => continue,
        };
        let session = fleet.session(&item.plugin_id)?;
        let mut context = item.context.clone();
        if operation == "rollback" {
            context.metadata["rollback_desired"] = item
                .plan
                .metadata
                .get("desired")
                .cloned()
                .unwrap_or_else(|| json!({}));
        } else {
            scope_rollback_cleanup_secrets(item.capability, &mut context.secrets);
        }
        context.metadata["operation"] = Value::String(operation.into());
        context.metadata["target"] = target_state.clone();
        let request = DestroyRequest {
            context,
            current: Some(item.current.state.clone()),
            force: false,
            journal: Vec::new(),
        };
        if let Err(failure) = reassert_mutation_lock(fleet, lock).await {
            rollback_failures.push(format!("{}: {failure}", item.plugin_id));
            break;
        }
        // Rollback is also a mutation. Do not repeat it after a lost response:
        // continuity was checked for this one exact destroy invocation.
        if let Err(failure) = session.client.destroy(request).await {
            rollback_failures.push(format!("{}: {failure}", item.plugin_id));
        }
    }
    journal.status = OperationStatus::Failed;
    if !rollback_failures.is_empty() {
        let combined = format!(
            "{error}; rollback incomplete: {}",
            rollback_failures.join("; ")
        );
        journal.error = Some(combined.clone());
        journal
            .save(&project.paths.local.join("operations"))
            .await?;
        return Err(CliError::Operation(combined));
    }
    journal
        .save(&project.paths.local.join("operations"))
        .await?;
    if format == OutputFormat::Human {
        eprintln!("info: rollback completed; failed changes were cleaned up");
    }
    Ok(())
}

fn scope_rollback_cleanup_secrets(
    capability: CoreCapability,
    secrets: &mut BTreeMap<String, SecretValue>,
) {
    // Target contexts contain only provider secrets explicitly declared by
    // that plugin and resolved for the target capability. Provider cleanup
    // needs those credentials. Runtime cleanup must not receive app secrets.
    if capability != CoreCapability::Target {
        secrets.clear();
    }
}

fn prior_runtime_revision(item: &PreparedCapability) -> Option<&str> {
    item.current.state.get("revision").and_then(Value::as_str)
}

fn supports_previous_revision_rollback(item: &PreparedCapability) -> bool {
    item.plan.actions.iter().any(|action| {
        action.rollback.as_ref().is_some_and(|rollback| {
            rollback.supported && rollback.action.as_deref() == Some("runtime.restore-previous")
        })
    })
}

async fn retry<T, F, Fut>(mut operation: F) -> Result<T, CliError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, ClientError>>,
{
    let mut delay = Duration::from_millis(250);
    for attempt in 1..=RETRY_ATTEMPTS {
        match operation().await {
            Ok(value) => return Ok(value),
            Err(error) if error.is_retryable() && attempt < RETRY_ATTEMPTS => {
                let requested = match &error {
                    ClientError::Remote(remote) => remote.retry_after_ms.map(Duration::from_millis),
                    _ => None,
                };
                tokio::time::sleep(requested.unwrap_or(delay)).await;
                delay = delay.saturating_mul(2);
            }
            Err(error) => return Err(CliError::Plugin(error.to_string())),
        }
    }
    unreachable!("retry loop always returns")
}

fn protocol_capability(capability: CoreCapability) -> Capability {
    match capability {
        CoreCapability::Source => Capability::Source,
        CoreCapability::Builder => Capability::Builder,
        CoreCapability::Target => Capability::Target,
        CoreCapability::Runtime => Capability::Runtime,
        CoreCapability::Exposure => Capability::Exposure,
        CoreCapability::Dns => Capability::Dns,
    }
}

fn desired_with_target(base: &Value, target: &Value) -> Value {
    let mut desired = base.clone();
    desired["target"] = target.clone();
    desired
}

fn plan_view(
    project: &LoadedProject,
    operation: &'static str,
    prepared: &[PreparedCapability],
) -> PlanView {
    let plugins = prepared
        .iter()
        .map(|item| PluginPlanView {
            capability: item.capability.as_str().to_owned(),
            plugin: item.plugin_id.clone(),
            plan_id: item.plan.plan_id.clone(),
            has_changes: item.plan.has_changes,
            actions: item
                .plan
                .actions
                .iter()
                .map(|action| ActionView {
                    id: action.id.clone(),
                    summary: action.summary.clone(),
                    destructive: action.destructive,
                })
                .collect(),
        })
        .collect::<Vec<_>>();
    PlanView {
        environment_id: project.identity.id().as_str().to_owned(),
        branch: project.git.branch().to_owned(),
        profile: project.profile_name.clone(),
        operation,
        has_changes: plugins.iter().any(|plugin| plugin.has_changes),
        plugins,
    }
}

#[derive(Eq, PartialEq)]
struct PlanContractEntry {
    capability: String,
    plugin_id: String,
    plan_id: String,
    has_changes: bool,
    actions: Vec<PlanActionContract>,
}

#[derive(Eq, PartialEq)]
struct PlanActionContract {
    id: String,
    destructive: bool,
}

fn plan_contract(prepared: &[PreparedCapability]) -> Vec<PlanContractEntry> {
    prepared
        .iter()
        .map(|item| PlanContractEntry {
            capability: item.capability.as_str().to_owned(),
            plugin_id: item.plugin_id.clone(),
            plan_id: item.plan.plan_id.clone(),
            has_changes: item.plan.has_changes,
            actions: item
                .plan
                .actions
                .iter()
                .map(|action| PlanActionContract {
                    id: action.id.clone(),
                    destructive: action.destructive,
                })
                .collect(),
        })
        .collect()
}

fn status_from_prepared(item: &PreparedCapability) -> PluginStatusView {
    PluginStatusView {
        capability: item.capability.as_str().to_owned(),
        plugin: item.plugin_id.clone(),
        status: item.current.status,
        state: item.current.state.clone(),
    }
}

fn mark_plugin_actions_completed(
    journal: &mut OperationJournal,
    plugin_id: &str,
    plan: &PlanResult,
    plugin_journal: &[ActionJournalEntry],
) {
    let succeeded = if plugin_journal.is_empty() {
        plan.actions
            .iter()
            .map(|action| action.id.as_str())
            .collect::<BTreeSet<_>>()
    } else {
        plugin_journal
            .iter()
            .filter(|entry| entry.status == lightrail_plugin_protocol::JournalStatus::Succeeded)
            .map(|entry| entry.action_id.as_str())
            .collect::<BTreeSet<_>>()
    };
    for action in &mut journal.actions {
        if action.plugin_id == plugin_id && succeeded.contains(action.action_id.as_str()) {
            action.completed = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lightrail_plugin_protocol::Endpoint;

    #[test]
    fn combines_status_using_failure_severity() {
        assert_eq!(
            combined_status([ResourceStatus::Ready, ResourceStatus::Degraded].into_iter()),
            ResourceStatus::Degraded
        );
        assert_eq!(combined_status(std::iter::empty()), ResourceStatus::Absent);
    }

    #[test]
    fn collects_secret_references_recursively() {
        let value = json!({
            "token": {"secret": "hetzner-token"},
            "nested": [{"secret": "database-url"}],
        });
        let mut names = BTreeSet::new();
        collect_secret_references(&value, &mut names);
        assert_eq!(
            names,
            BTreeSet::from(["database-url".into(), "hetzner-token".into()])
        );
    }

    #[tokio::test]
    async fn operation_secret_cache_reuses_a_resolved_value_without_persisting_it() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let backend = crate::secrets::MemoryBackend::default();
        let store = SecretStore::new(backend, "project", temp.path());
        store
            .set(
                "hetzner-token",
                SecretString::from("provider-token".to_owned()),
            )
            .await
            .expect("seed backing store");
        let cache = OperationSecretCache::default();

        let first = cache
            .resolve(&store, "hetzner-token")
            .await
            .expect("initial resolution");
        store
            .delete("hetzner-token")
            .await
            .expect("remove persisted value");
        let repeated = cache
            .resolve(&store, "hetzner-token")
            .await
            .expect("cached resolution");

        assert_eq!(first.expose_secret(), "provider-token");
        assert_eq!(repeated.expose_secret(), "provider-token");
        assert!(
            matches!(
                store.resolve("hetzner-token").await,
                Err(CliError::SecretUnavailable { .. })
            ),
            "the operation cache must not write a value back to the secret store"
        );
        assert!(
            OperationSecretCache::default()
                .values
                .lock()
                .await
                .is_empty(),
            "a separate command cache must start empty"
        );
    }

    #[test]
    fn rollback_cleanup_keeps_target_credentials_and_clears_runtime_secrets() {
        let provider_token = SecretValue::new("provider-token");
        let mut target_secrets = BTreeMap::from([("hetzner-token".into(), provider_token.clone())]);
        scope_rollback_cleanup_secrets(CoreCapability::Target, &mut target_secrets);
        assert_eq!(
            target_secrets.get("hetzner-token"),
            Some(&provider_token),
            "target cleanup needs its already-scoped provider credential"
        );

        let mut runtime_secrets = BTreeMap::from([(
            "database-url".into(),
            SecretValue::new("runtime-application-secret"),
        )]);
        scope_rollback_cleanup_secrets(CoreCapability::Runtime, &mut runtime_secrets);
        assert!(
            runtime_secrets.is_empty(),
            "runtime cleanup must not receive application secrets"
        );
    }

    #[test]
    fn target_is_applied_before_builder_and_runtime() {
        assert_eq!(APPLY_ORDER[1], CoreCapability::Target);
        assert!(
            APPLY_ORDER
                .iter()
                .position(|capability| *capability == CoreCapability::Builder)
                < APPLY_ORDER
                    .iter()
                    .position(|capability| *capability == CoreCapability::Runtime)
        );
    }

    #[test]
    fn down_retry_commands_preserve_scope_and_quote_profile_names() {
        let options = DownOptions {
            all: true,
            dry_run: false,
            yes: false,
            force: true,
            lock_timeout: Duration::from_secs(125),
            output: OutputFormat::Human,
        };

        assert_eq!(
            down_retry_command("preview", &options, false),
            "lightrail --profile=preview down --all --force --lock-timeout 125s"
        );
        assert_eq!(
            down_retry_command("qa's $(touch unsafe)", &options, true),
            "lightrail --profile='qa'\"'\"'s $(touch unsafe)' down --all --force --lock-timeout 125s --yes"
        );
        assert_eq!(
            down_retry_command("-preview", &options, false),
            "lightrail --profile=-preview down --all --force --lock-timeout 125s"
        );
    }

    #[test]
    fn a_lock_release_error_does_not_hide_the_operation_error() {
        let error = finish_with_lock_release::<()>(
            Err(CliError::Operation("destroy failed".into())),
            Err(CliError::Operation("unlock failed".into())),
        )
        .expect_err("combined failure");

        assert!(error.to_string().contains("destroy failed"));
        assert!(error.to_string().contains("unlock failed"));
    }

    #[test]
    fn plugin_config_merge_overlays_objects() {
        let mut target = serde_json::Map::new();
        merge_json_object(
            &mut target,
            &json!({"domain": "nip.io", "nested": {"left": true}}),
        )
        .expect("first");
        merge_json_object(
            &mut target,
            &json!({"tls": "acme-http-01", "nested": {"right": true}}),
        )
        .expect("second");
        assert_eq!(
            Value::Object(target),
            json!({
                "domain": "nip.io",
                "tls": "acme-http-01",
                "nested": {"left": true, "right": true},
            })
        );
    }

    #[test]
    fn keeps_same_app_urls_from_multiple_environments() {
        let first = InspectResult {
            status: ResourceStatus::Ready,
            endpoints: vec![Endpoint {
                app: "api".into(),
                url: "https://feature.api.preview.demo.01020304.sslip.io".into(),
            }],
            state: json!({}),
            diagnostics: Vec::new(),
        };
        let second = InspectResult {
            status: ResourceStatus::Ready,
            endpoints: vec![Endpoint {
                app: "api".into(),
                url: "https://main.api.preview.demo.01020304.sslip.io".into(),
            }],
            state: json!({}),
            diagnostics: Vec::new(),
        };

        let endpoints = collect_endpoints([&first, &second].into_iter());
        assert_eq!(endpoints.len(), 2);
    }

    #[test]
    fn collects_and_merges_project_environment_summaries() {
        let target = InspectResult {
            status: ResourceStatus::Ready,
            endpoints: Vec::new(),
            state: json!({
                "environments": [{
                    "environment_id": "lr-one",
                    "status": "ready"
                }]
            }),
            diagnostics: Vec::new(),
        };
        let runtime = InspectResult {
            status: ResourceStatus::Ready,
            endpoints: Vec::new(),
            state: json!({
                "environments": [{
                    "environment_id": "lr-one",
                    "branch": "feature/login",
                    "profile": "preview",
                    "status": "ready",
                    "endpoints": [{
                        "app": "api",
                        "url": "https://feature-login.api.preview.demo.01020304.sslip.io"
                    }]
                }]
            }),
            diagnostics: Vec::new(),
        };

        let environments = collect_environment_summaries([&target, &runtime].into_iter());
        assert_eq!(environments.len(), 1);
        assert_eq!(environments[0].branch.as_deref(), Some("feature/login"));
        assert_eq!(environments[0].endpoints.len(), 1);
    }

    #[test]
    fn falls_back_to_privacy_preserving_machine_targets() {
        let target = InspectResult {
            status: ResourceStatus::Ready,
            endpoints: Vec::new(),
            state: json!({
                "targets": [{
                    "environment_id": null,
                    "environment_label": "e-deadbeef",
                    "server_id": 42,
                    "server_status": "running"
                }]
            }),
            diagnostics: Vec::new(),
        };

        let environments = collect_environment_summaries([&target].into_iter());
        assert_eq!(environments.len(), 1);
        assert_eq!(environments[0].environment_id, "e-deadbeef");
        assert_eq!(environments[0].status, ResourceStatus::Ready);
    }

    #[test]
    fn classifies_only_the_exact_lock_token_as_continuous() {
        let expected = SecretValue::new("expected-token");
        assert_eq!(
            classify_lock_continuity(
                LockAcquireResult {
                    acquired: true,
                    token: Some(expected.clone()),
                    expires_at: None,
                    holder: None,
                },
                &expected,
            ),
            LockContinuity::Confirmed
        );
        assert_eq!(
            classify_lock_continuity(
                LockAcquireResult {
                    acquired: true,
                    token: Some(SecretValue::new("replacement-token")),
                    expires_at: None,
                    holder: None,
                },
                &expected,
            ),
            LockContinuity::TokenMismatch {
                unexpected: SecretValue::new("replacement-token"),
            }
        );
    }

    #[test]
    fn classifies_unacquired_and_tokenless_locks_as_discontinuous() {
        let expected = SecretValue::new("expected-token");
        assert_eq!(
            classify_lock_continuity(
                LockAcquireResult {
                    acquired: false,
                    token: None,
                    expires_at: None,
                    holder: Some("another operation".into()),
                },
                &expected,
            ),
            LockContinuity::NotAcquired {
                holder: Some("another operation".into()),
            }
        );
        assert_eq!(
            classify_lock_continuity(
                LockAcquireResult {
                    acquired: true,
                    token: None,
                    expires_at: None,
                    holder: None,
                },
                &expected,
            ),
            LockContinuity::MissingToken
        );
    }
}
