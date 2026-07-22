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
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use dialoguer::{Confirm, Password};
use lightrail_core::Capability as CoreCapability;
use lightrail_plugin_protocol::{
    ActionJournalEntry, ApplyRequest, ApplyResult, CancelRequest, Capability, ClientError,
    ClientEvent, DestroyRequest, DestroyResult, InspectRequest, InspectResult, JournalStatus,
    LockAcquireRequest, LockAcquireResult, LockReleaseRequest, LockScope, LogsRequest,
    OperationContext, PlanRequest, PlanResult, PluginEvent, PluginManifest, ResourceStatus,
    RollbackMetadata, SecretValue, ValidateRequest, operation_request_timeout,
};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
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
const SELECTED_DESTROY_FEATURE: &str = "dev.lightrail.selected-destroy.v1";

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
pub struct PruneOptions {
    pub dry_run: bool,
    pub yes: bool,
    pub lock_timeout: Duration,
    pub output: OutputFormat,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct PruneCandidate {
    environment_id: String,
    branch: Option<String>,
    profile: Option<String>,
    expires_at: Option<String>,
    expires_at_unix: u64,
}

#[derive(Serialize)]
struct PrunePlan<'a> {
    operation: &'static str,
    expired_before_unix: u64,
    environments: &'a [PruneCandidate],
    plugin: &'a str,
    plan_id: &'a str,
    actions: Vec<ActionView>,
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
struct AppliedCapability {
    prepared: PreparedCapability,
    journal: Vec<ActionJournalEntry>,
    post_apply_state: Option<Value>,
}

impl AppliedCapability {
    fn new(prepared: PreparedCapability) -> Self {
        let journal = rollback_journal(&prepared.plan, &[]);
        Self {
            prepared,
            journal,
            post_apply_state: None,
        }
    }

    fn record_apply_result(&mut self, result: &ApplyResult) {
        self.journal = rollback_journal(&self.prepared.plan, &result.journal);
        self.post_apply_state = Some(result.state.clone());
    }
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
        record_planned_actions(&mut journal, &prepared);
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
            let applied_index = applied.len();
            applied.push(AppliedCapability::new(item.clone()));
            let request = ApplyRequest {
                context: item.context.clone(),
                plan: item.plan.clone(),
                journal: Vec::new(),
            };
            // Mutations are not blindly retried: a lost response is ambiguous
            // and repeating it can duplicate provider or runtime side effects.
            let attempt =
                apply_with_progress(session, request, operation_id, options.output).await;
            let (result, cancelled) = record_apply_attempt(
                &mut applied[applied_index],
                &mut journal,
                attempt,
            )?;
            if item.capability == CoreCapability::Target {
                target_state = result.state.clone();
            }
            journal
                .save(&project.paths.local.join("operations"))
                .await?;
            check_apply_cancellation(cancelled)?;
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

struct ApplyAttempt {
    result: Result<ApplyResult, CliError>,
    cancelled: bool,
}

async fn apply_with_progress(
    session: &PluginSession,
    request: ApplyRequest,
    operation_id: &str,
    format: OutputFormat,
) -> ApplyAttempt {
    let mut events = session.client.subscribe();
    let timeout = locked_plan_request_timeout(&request.context, &request.plan);
    let apply = session.client.apply_with_timeout(request, timeout);
    tokio::pin!(apply);
    let interrupt = tokio::signal::ctrl_c();
    tokio::pin!(interrupt);
    let mut cancelled = false;
    let mut events_open = true;

    loop {
        tokio::select! {
            biased;
            signal = &mut interrupt, if !cancelled => {
                match signal {
                    Ok(()) => {
                        cancelled = true;
                        eprintln!("cancellation requested; waiting for the active plugin to stop safely");
                        let cancellation = session.client.cancel(CancelRequest {
                            operation_id: operation_id.to_owned(),
                            reason: Some("operator pressed Ctrl+C".to_owned()),
                        });
                        let _ = tokio::time::timeout(Duration::from_secs(5), cancellation).await;
                    }
                    Err(error) => {
                        return ApplyAttempt {
                            result: Err(error.into()),
                            cancelled: false,
                        };
                    }
                }
            }
            result = &mut apply => {
                return ApplyAttempt {
                    result: result.map_err(|error| CliError::Plugin(error.to_string())),
                    cancelled,
                };
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

fn record_apply_attempt(
    item: &mut AppliedCapability,
    journal: &mut OperationJournal,
    attempt: ApplyAttempt,
) -> Result<(ApplyResult, bool), CliError> {
    let result = attempt.result?;
    item.record_apply_result(&result);
    mark_plugin_actions_completed(
        journal,
        item.prepared.capability,
        &item.prepared.plugin_id,
        &item.prepared.plan,
        &result.journal,
        result.journal.is_empty(),
    );
    Ok((result, attempt.cancelled))
}

fn check_apply_cancellation(cancelled: bool) -> Result<(), CliError> {
    if cancelled {
        Err(CliError::Operation(
            "operation cancelled after the active plugin reached a safe stopping point".into(),
        ))
    } else {
        Ok(())
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
    validate_down_force(project.profile().isolation, options.force)?;
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

fn validate_down_force(isolation: lightrail_core::Isolation, force: bool) -> Result<(), CliError> {
    if force && isolation != lightrail_core::Isolation::Machine {
        return Err(CliError::Usage(
            "`down --force` is available only for machine-isolated provider deletion when its remote lock authority is unavailable"
                .into(),
        ));
    }
    Ok(())
}

pub async fn prune(project: LoadedProject, options: PruneOptions) -> Result<(), CliError> {
    if project.profile().isolation != lightrail_core::Isolation::Environment {
        return Err(CliError::Usage(
            "`prune` currently supports only environment-isolated Kubernetes and Fly.io profiles"
                .into(),
        ));
    }
    let target_plugin = project.plugin_id(CoreCapability::Target);
    if DESTROY_ORDER
        .iter()
        .any(|capability| project.plugin_id(*capability) != target_plugin)
    {
        return Err(CliError::Plugin(
            "`prune` requires one aggregate provider plugin to own target, runtime, exposure, and DNS destruction"
                .into(),
        ));
    }

    project.paths.ensure_local_layout().await?;
    // Start the complete destruction surface even though one aggregate
    // provider owns it. Capability negotiation must prove that a plugin
    // advertising selected destroy can also perform an ordinary full down.
    let fleet = PluginFleet::start(&project, &DESTROY_ORDER).await?;
    let operation_id = Uuid::new_v4().to_string();
    let result = prune_with_fleet(&project, &fleet, &operation_id, &options).await;
    let shutdown = fleet.shutdown().await;
    match (result, shutdown) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(error)) | (Err(error), _) => Err(error),
    }
}

async fn prune_with_fleet(
    project: &LoadedProject,
    fleet: &PluginFleet,
    operation_id: &str,
    options: &PruneOptions,
) -> Result<(), CliError> {
    let plugin_id = project.plugin_id(CoreCapability::Target);
    let session = fleet.session(plugin_id)?;
    if !session
        .manifest
        .features
        .iter()
        .any(|feature| feature == SELECTED_DESTROY_FEATURE)
    {
        return Err(CliError::Plugin(format!(
            "target plugin `{plugin_id}` does not implement `{SELECTED_DESTROY_FEATURE}`; refusing to risk an unscoped deletion"
        )));
    }

    let now = unix_now()?;
    let inspected = inspect_target_all(project, fleet, session, operation_id).await?;
    let candidates = expired_candidates(
        &inspected.state,
        &project.config.project.id.to_string(),
        now,
    )?;
    if candidates.is_empty() {
        return print_prune_empty(project, options.output, now);
    }
    let prepared = prepare_prune_target(
        project,
        fleet,
        session,
        operation_id,
        &inspected,
        &candidates,
    )
    .await?;
    if !prepared.plan.has_changes || prepared.plan.actions.is_empty() {
        return Err(CliError::Plugin(format!(
            "target plugin `{plugin_id}` returned no destructive plan for {} expired environment(s)",
            candidates.len()
        )));
    }
    if prepared
        .plan
        .actions
        .iter()
        .any(|action| !action.destructive)
    {
        return Err(CliError::Plugin(format!(
            "target plugin `{plugin_id}` returned a non-destructive action in an expired-environment deletion plan"
        )));
    }
    if should_print_prune_plan(options.output, options.dry_run) {
        print_prune_plan(project, options.output, now, &candidates, &prepared)?;
    }
    if options.dry_run {
        if options.output == OutputFormat::Human {
            output::line("Dry run complete; no changes were made.")?;
        }
        return Ok(());
    }
    if !options.yes {
        if !io::stdin().is_terminal() {
            return Err(CliError::Usage(
                "`prune` needs confirmation; pass `--yes` in non-interactive use".into(),
            ));
        }
        if !Confirm::new()
            .with_prompt(format!(
                "Destroy {} expired environment(s) visible through profile `{}`?",
                candidates.len(),
                project.profile_name
            ))
            .default(false)
            .interact()
            .map_err(|error| CliError::Operation(format!("confirmation failed: {error}")))?
        {
            print_cancelled(options.output)?;
            return Ok(());
        }
    }

    let initial_contract = plan_contract(std::slice::from_ref(&prepared))?;
    let lock = acquire_lock(
        project,
        fleet,
        operation_id,
        options.lock_timeout,
        true,
        false,
    )
    .await?;
    let result = async {
        let locked_inspection =
            inspect_target_all(project, fleet, session, operation_id).await?;
        let locked_candidates = expired_candidates(
            &locked_inspection.state,
            &project.config.project.id.to_string(),
            now,
        )?;
        if locked_candidates != candidates {
            return Err(CliError::Operation(
                "expired environments changed while waiting for the project lock; rerun `lightrail prune --dry-run`"
                    .into(),
            ));
        }
        let locked = prepare_prune_target(
            project,
            fleet,
            session,
            operation_id,
            &locked_inspection,
            &locked_candidates,
        )
        .await?;
        if plan_contract(std::slice::from_ref(&locked))? != initial_contract {
            return Err(CliError::Operation(
                "the expired-environment destruction plan changed while waiting for the project lock; rerun `lightrail prune --dry-run`"
                    .into(),
            ));
        }

        let mut journal =
            OperationJournal::new(project.config.project.id.to_string(), OperationKind::Prune);
        journal.operation_id = Uuid::parse_str(operation_id)
            .map_err(|error| CliError::Operation(format!("invalid operation ID: {error}")))?;
        record_planned_actions(&mut journal, std::slice::from_ref(&locked));
        journal.status = OperationStatus::Applying;
        journal
            .save(&project.paths.local.join("operations"))
            .await?;

        reassert_mutation_lock(fleet, lock.as_ref()).await?;
        let timeout = locked_plan_request_timeout(&locked.context, &locked.plan);
        let attempt = destroy_with_progress(
            session,
            DestroyRequest {
                context: locked.context,
                current: Some(locked.current.state),
                force: false,
                journal: Vec::new(),
            },
            operation_id,
            options.output,
            timeout,
        )
        .await;
        if let Ok(result) = &attempt.result {
            mark_plugin_actions_completed(
                &mut journal,
                locked.capability,
                &locked.plugin_id,
                &locked.plan,
                &result.journal,
                result.destroyed && result.remaining.is_empty(),
            );
        }
        let outcome = match attempt.result {
            Ok(result) if !attempt.cancelled && result.destroyed && result.remaining.is_empty() => {
                journal.status = OperationStatus::Succeeded;
                journal.error = None;
                Ok(())
            }
            Ok(_) if attempt.cancelled => Err(CliError::Operation(
                "expired-environment destruction was cancelled at a safe stopping point".into(),
            )),
            Ok(result) => Err(CliError::Operation(format!(
                "expired-environment destruction left resources: {}",
                result.remaining.join(", ")
            ))),
            Err(error) => Err(error),
        };
        if let Err(error) = &outcome {
            journal.status = OperationStatus::Failed;
            journal.error = Some(error.to_string());
        }
        journal
            .save(&project.paths.local.join("operations"))
            .await?;
        outcome
    }
    .await;

    let release = release_lock(fleet, lock).await;
    finish_with_lock_release(result, release)?;
    print_pruned(project, options.output, &candidates)
}

fn unix_now() -> Result<u64, CliError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| CliError::Operation(format!("system clock is before Unix epoch: {error}")))
}

async fn inspect_target_all(
    project: &LoadedProject,
    fleet: &PluginFleet,
    session: &PluginSession,
    operation_id: &str,
) -> Result<InspectResult, CliError> {
    let context = operation_context(
        project,
        fleet,
        session,
        CoreCapability::Target,
        operation_id,
        "inspect",
        true,
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

fn expired_candidates(
    state: &Value,
    project_id: &str,
    expired_before_unix: u64,
) -> Result<Vec<PruneCandidate>, CliError> {
    let environments = match state.get("environments") {
        None => return Ok(Vec::new()),
        Some(environments) => environments.as_array().ok_or_else(|| {
            CliError::Plugin(
                "selected-destroy target returned a non-array `environments` field".into(),
            )
        })?,
    };
    if !environments.is_empty()
        && state.get("environment_contract").and_then(Value::as_u64) != Some(1)
    {
        return Err(CliError::Plugin(
            "target returned environments without `environment_contract = 1`; refusing to infer expiry ownership"
                .into(),
        ));
    }

    let mut candidates = Vec::new();
    let mut seen = BTreeSet::new();
    for item in environments {
        let item = item.as_object().ok_or_else(|| {
            CliError::Plugin(
                "selected-destroy target returned a non-object environment entry".into(),
            )
        })?;
        let environment_id = item
            .get("environment_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CliError::Plugin(
                    "selected-destroy target returned an environment without an ID".into(),
                )
            })?;
        let observed_project = item
            .get("project_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CliError::Plugin(format!(
                    "environment `{environment_id}` has no immutable project ownership field"
                ))
            })?;
        if observed_project != project_id {
            return Err(CliError::Plugin(format!(
                "environment `{environment_id}` reports project `{observed_project}`, expected `{project_id}`"
            )));
        }
        if !seen.insert(environment_id.to_owned()) {
            return Err(CliError::Plugin(format!(
                "target returned duplicate environment `{environment_id}`"
            )));
        }
        let expires_at_unix = match item.get("expires_at_unix") {
            None | Some(Value::Null) => continue,
            Some(expires_at_unix) => expires_at_unix.as_u64().ok_or_else(|| {
                CliError::Plugin(format!(
                    "environment `{environment_id}` has a malformed `expires_at_unix`; expected a non-negative integer"
                ))
            })?,
        };
        if expires_at_unix > expired_before_unix {
            continue;
        }
        candidates.push(PruneCandidate {
            environment_id: environment_id.to_owned(),
            branch: item
                .get("branch")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            profile: item
                .get("profile")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            expires_at: item
                .get("expires_at")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            expires_at_unix,
        });
    }
    candidates.sort_by(|left, right| left.environment_id.cmp(&right.environment_id));
    Ok(candidates)
}

async fn prepare_prune_target(
    project: &LoadedProject,
    fleet: &PluginFleet,
    session: &PluginSession,
    operation_id: &str,
    current: &InspectResult,
    candidates: &[PruneCandidate],
) -> Result<PreparedCapability, CliError> {
    let mut context = operation_context(
        project,
        fleet,
        session,
        CoreCapability::Target,
        operation_id,
        "prune",
        false,
        &current.state,
    )
    .await?;
    context.metadata["selection"] = json!({
        "schema": 1,
        "reason": "expired",
        "environment_ids": candidates
            .iter()
            .map(|candidate| candidate.environment_id.as_str())
            .collect::<Vec<_>>(),
    });
    let mut desired = desired_with_target(&project.base_desired(), &current.state);
    desired["destroy"] = Value::Bool(true);
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
            "plugin `{}` rejected the expired-environment selection: {details}",
            session.manifest.id
        )));
    }
    let plan = retry(|| {
        session.client.plan(PlanRequest {
            context: context.clone(),
            desired: desired.clone(),
            current: Some(current.state.clone()),
        })
    })
    .await?;
    Ok(PreparedCapability {
        capability: CoreCapability::Target,
        plugin_id: session.manifest.id.clone(),
        context,
        current: current.clone(),
        plan,
    })
}

fn print_prune_plan(
    project: &LoadedProject,
    format: OutputFormat,
    expired_before_unix: u64,
    candidates: &[PruneCandidate],
    prepared: &PreparedCapability,
) -> Result<(), CliError> {
    let actions = prepared
        .plan
        .actions
        .iter()
        .map(|action| ActionView {
            id: action.id.clone(),
            summary: action.summary.clone(),
            destructive: action.destructive,
        })
        .collect();
    let plan = PrunePlan {
        operation: "prune",
        expired_before_unix,
        environments: candidates,
        plugin: &prepared.plugin_id,
        plan_id: &prepared.plan.plan_id,
        actions,
    };
    match format {
        OutputFormat::Json => output::json(&plan),
        OutputFormat::Plain => {
            for candidate in candidates {
                output::line(&candidate.environment_id)?;
            }
            Ok(())
        }
        OutputFormat::Human => {
            output::line(format!(
                "Plan: prune {} expired environment(s) from profile `{}`",
                candidates.len(),
                project.profile_name
            ))?;
            for candidate in candidates {
                let label = match (&candidate.branch, &candidate.profile) {
                    (Some(branch), Some(profile)) => format!("{branch} / {profile}"),
                    _ => candidate.environment_id.clone(),
                };
                let expiry = candidate
                    .expires_at
                    .as_deref()
                    .map_or_else(|| candidate.expires_at_unix.to_string(), ToOwned::to_owned);
                output::line(format!("  - {label} (expired {expiry})"))?;
            }
            for action in &prepared.plan.actions {
                output::line(format!("    {}", action.summary))?;
            }
            Ok(())
        }
    }
}

const fn should_print_prune_plan(format: OutputFormat, dry_run: bool) -> bool {
    dry_run || matches!(format, OutputFormat::Human)
}

fn print_prune_empty(
    project: &LoadedProject,
    format: OutputFormat,
    expired_before_unix: u64,
) -> Result<(), CliError> {
    match format {
        OutputFormat::Json => output::json(&json!({
            "operation": "prune",
            "expired_before_unix": expired_before_unix,
            "environments": [],
            "destroyed": 0,
        })),
        OutputFormat::Plain => Ok(()),
        OutputFormat::Human => output::line(format!(
            "No expired environments are visible through profile `{}`.",
            project.profile_name
        )),
    }
}

fn print_pruned(
    project: &LoadedProject,
    format: OutputFormat,
    candidates: &[PruneCandidate],
) -> Result<(), CliError> {
    match format {
        OutputFormat::Json => output::json(&json!({
            "operation": "prune",
            "destroyed": candidates.len(),
            "environment_ids": candidates
                .iter()
                .map(|candidate| candidate.environment_id.as_str())
                .collect::<Vec<_>>(),
        })),
        OutputFormat::Plain => {
            for candidate in candidates {
                output::line(&candidate.environment_id)?;
            }
            Ok(())
        }
        OutputFormat::Human => output::line(format!(
            "Destroyed {} expired environment(s) visible through profile `{}`.",
            candidates.len(),
            project.profile_name
        )),
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
    let displayed_contract = plan_contract(&prepared)?;

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
        if plan_contract(&prepared)? != displayed_contract {
            let retry = down_retry_command(&project.profile_name, options, false);
            return Err(CliError::Operation(format!(
                "owned resources changed while waiting for the mutation lock; rerun `{retry}` to review the new plan"
            )));
        }
        let mut journal =
            OperationJournal::new(project.identity.id().as_str(), OperationKind::Down);
        journal.operation_id = Uuid::parse_str(operation_id)
            .map_err(|error| CliError::Operation(format!("invalid operation ID: {error}")))?;
        record_planned_actions(&mut journal, &prepared);
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
            let timeout = locked_plan_request_timeout(&item.context, &item.plan);
            let attempt = destroy_with_progress(
                session,
                request,
                operation_id,
                options.output,
                timeout,
            )
            .await;
            if let Ok(result) = &attempt.result {
                mark_plugin_actions_completed(
                    &mut journal,
                    item.capability,
                    &item.plugin_id,
                    &item.plan,
                    &result.journal,
                    result.destroyed && result.remaining.is_empty(),
                );
                journal
                    .save(&project.paths.local.join("operations"))
                    .await?;
            }
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
    timeout: Duration,
) -> DestroyAttempt {
    let mut events = session.client.subscribe();
    let destroy = session.client.destroy_with_timeout(request, timeout);
    tokio::pin!(destroy);
    let interrupt = tokio::signal::ctrl_c();
    tokio::pin!(interrupt);
    let mut cancelled = false;
    let mut events_open = true;

    loop {
        tokio::select! {
            biased;
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
            result = &mut destroy => {
                return DestroyAttempt {
                    result: result.map_err(|error| CliError::Plugin(error.to_string())),
                    cancelled,
                };
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
    let capability_config = project.capability_config(capability)?;
    let runtime_desired = (capability == CoreCapability::Runtime && include_runtime_values)
        .then(|| project.base_desired());
    Ok(secret_references_for_operation(
        &capability_config,
        runtime_desired.as_ref(),
    ))
}

fn secret_references_for_operation(
    capability_config: &Value,
    runtime_desired: Option<&Value>,
) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    // An aggregate executable may receive merged configuration so it can
    // coordinate capabilities, but wildcard secret authorization remains
    // scoped to the capability active in this request.
    collect_secret_references(capability_config, &mut names);
    if let Some(runtime_desired) = runtime_desired {
        collect_secret_references(runtime_desired, &mut names);
    }
    names
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
    let (scope, scope_id) = mutation_lock_scope(
        project.profile().isolation,
        all,
        &project.config.project.id.to_string(),
        project.identity.id().as_str(),
        project.plugin_id(CoreCapability::Target),
    );
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

fn mutation_lock_scope(
    isolation: lightrail_core::Isolation,
    all: bool,
    project_id: &str,
    environment_id: &str,
    target_plugin: &str,
) -> (LockScope, String) {
    match (isolation, all) {
        (lightrail_core::Isolation::Project, _) => {
            (LockScope::Target, format!("target:{target_plugin}"))
        }
        // Environment-isolated providers currently use one project-wide
        // authority. Separate environment and project Lease/App locks would
        // not overlap atomically, allowing `prune`/`down --all` to race an
        // environment `up`.
        (lightrail_core::Isolation::Environment, _)
        | (lightrail_core::Isolation::Machine, true) => (LockScope::Project, project_id.to_owned()),
        (lightrail_core::Isolation::Machine, false) => {
            (LockScope::Environment, environment_id.to_owned())
        }
    }
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
    applied: &[AppliedCapability],
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
    for applied_item in rollback_order(applied) {
        let classification = classify_rollback(applied_item);
        let item = &applied_item.prepared;
        rollback_failures.extend(classification.unsupported.into_iter().map(|limitation| {
            format!(
                "{}: action `{}` ({}) cannot be automatically rolled back: {}",
                item.plugin_id, limitation.action_id, limitation.kind, limitation.reason
            )
        }));
        let Some(operation) = classification.operation else {
            continue;
        };
        let session = match fleet.session(&item.plugin_id) {
            Ok(session) => session,
            Err(failure) => {
                rollback_failures.push(format!("{}: {failure}", item.plugin_id));
                continue;
            }
        };
        let mut context = item.context.clone();
        if operation == RollbackOperation::Rollback {
            context.metadata["rollback_desired"] = item
                .plan
                .metadata
                .get("desired")
                .cloned()
                .unwrap_or_else(|| json!({}));
        } else {
            scope_rollback_cleanup_secrets(&session.manifest, &mut context.secrets);
        }
        context.metadata["operation"] = Value::String(operation.context_name().into());
        context.metadata["target"] = target_state.clone();
        let request = DestroyRequest {
            context,
            current: Some(rollback_current_state(applied_item, operation)),
            force: false,
            journal: applied_item.journal.clone(),
        };
        if let Err(failure) = reassert_mutation_lock(fleet, lock).await {
            rollback_failures.push(format!("{}: {failure}", item.plugin_id));
            break;
        }
        // Rollback is also a mutation. Do not repeat it after a lost response:
        // continuity was checked for this one exact destroy invocation.
        let timeout = locked_plan_request_timeout(&item.context, &item.plan);
        match session.client.destroy_with_timeout(request, timeout).await {
            Ok(result) if result.destroyed && result.remaining.is_empty() => {}
            Ok(result) if result.remaining.is_empty() => rollback_failures.push(format!(
                "{}: rollback did not report completion",
                item.plugin_id
            )),
            Ok(result) => rollback_failures.push(format!(
                "{}: rollback left resources: {}",
                item.plugin_id,
                result.remaining.join(", ")
            )),
            Err(failure) => {
                rollback_failures.push(format!("{}: {failure}", item.plugin_id));
            }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RollbackOperation {
    Cleanup,
    Rollback,
}

impl RollbackOperation {
    const fn context_name(self) -> &'static str {
        match self {
            Self::Cleanup => "rollback_cleanup",
            Self::Rollback => "rollback",
        }
    }
}

fn rollback_current_state(item: &AppliedCapability, operation: RollbackOperation) -> Value {
    if operation == RollbackOperation::Cleanup {
        item.post_apply_state
            .clone()
            .unwrap_or_else(|| item.prepared.current.state.clone())
    } else {
        item.prepared.current.state.clone()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct UnsupportedRollback {
    action_id: String,
    kind: String,
    reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RollbackClassification {
    operation: Option<RollbackOperation>,
    unsupported: Vec<UnsupportedRollback>,
}

fn rollback_order(applied: &[AppliedCapability]) -> impl Iterator<Item = &AppliedCapability> {
    applied.iter().rev()
}

fn classify_rollback(item: &AppliedCapability) -> RollbackClassification {
    let prepared = &item.prepared;
    let claims = rollback_claims(item);
    let supported = claims
        .iter()
        .filter(|(_, rollback)| rollback.supported)
        .collect::<Vec<_>>();
    let mut unsupported = claims
        .iter()
        .filter(|(_, rollback)| !rollback.supported)
        .map(|(action_id, rollback)| UnsupportedRollback {
            action_id: (*action_id).to_owned(),
            kind: rollback_action_kind(item, action_id, rollback),
            reason: rollback
                .metadata
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("the plugin marked this action as non-reversible")
                .to_owned(),
        })
        .collect::<Vec<_>>();

    if matches!(
        prepared.capability,
        CoreCapability::Target | CoreCapability::Runtime
    ) && prepared.current.status == ResourceStatus::Absent
    {
        return RollbackClassification {
            operation: Some(RollbackOperation::Cleanup),
            // Whole-capability cleanup is the inverse for an initially absent
            // aggregate. Per-action limitations describe revision rollback,
            // not deletion of resources created by this failed operation.
            unsupported: Vec::new(),
        };
    }

    let missing_runtime_inverses = (prepared.capability == CoreCapability::Runtime).then(|| {
        missing_runtime_inverse_limitations(
            item,
            &claims,
            "the existing runtime plan advertised no supported inverse",
        )
    });
    let operation = match prepared.capability {
        // Source resolution has no remote side effects. Builder artifacts are
        // immutable cache and are deliberately retained.
        CoreCapability::Source | CoreCapability::Builder => {
            unsupported.clear();
            None
        }
        // A whole target may be removed only when it did not exist before this
        // operation. Generic target destroy can own much more than one action.
        CoreCapability::Target => {
            unsupported = claims
                .iter()
                .map(|(action_id, rollback)| UnsupportedRollback {
                    action_id: (*action_id).to_owned(),
                    kind: rollback_action_kind(item, action_id, rollback),
                    reason: if rollback.supported {
                        "the target already existed, so its aggregate destroy operation is not a safe action inverse"
                            .to_owned()
                    } else {
                        rollback
                            .metadata
                            .get("reason")
                            .and_then(Value::as_str)
                            .unwrap_or("the plugin marked this target action as non-reversible")
                            .to_owned()
                    },
                })
                .collect();
            unsupported.extend(
                prepared
                    .plan
                    .actions
                    .iter()
                    .filter(|action| !claims.contains_key(action.id.as_str()))
                    .filter(|action| rollback_action_may_have_run(item, &action.id))
                    .map(|action| UnsupportedRollback {
                        action_id: action.id.clone(),
                        kind: action.kind.clone(),
                        reason:
                            "the existing target action advertised no automatic rollback contract"
                                .to_owned(),
                    }),
            );
            None
        }
        // Newly created runtime state is safely removed as a whole. Existing
        // runtime state requires both a prior revision observation and an
        // explicitly supported action inverse.
        CoreCapability::Runtime if prior_runtime_revision(prepared).is_none() => {
            unsupported.extend(supported.into_iter().map(|(action_id, rollback)| {
                UnsupportedRollback {
                    action_id: (*action_id).to_owned(),
                    kind: rollback_action_kind(item, action_id, rollback),
                    reason: "the existing runtime has no observed prior revision to restore"
                        .to_owned(),
                }
            }));
            unsupported.extend(missing_runtime_inverses.unwrap_or_default());
            None
        }
        CoreCapability::Runtime if supported.is_empty() => {
            unsupported.extend(missing_runtime_inverses.unwrap_or_default());
            None
        }
        // Exposure and DNS actions are compensated only when a plugin
        // advertises an inverse. No-metadata observation/readiness actions are
        // intentionally skipped.
        CoreCapability::Exposure | CoreCapability::Dns if supported.is_empty() => None,
        CoreCapability::Exposure | CoreCapability::Dns
            if prepared.current.status == ResourceStatus::Absent =>
        {
            Some(RollbackOperation::Cleanup)
        }
        CoreCapability::Runtime => {
            unsupported.extend(missing_runtime_inverses.unwrap_or_default());
            Some(RollbackOperation::Rollback)
        }
        CoreCapability::Exposure | CoreCapability::Dns => Some(RollbackOperation::Rollback),
    };

    RollbackClassification {
        operation,
        unsupported,
    }
}

fn rollback_claims(item: &AppliedCapability) -> BTreeMap<&str, &RollbackMetadata> {
    let mut latest_status = BTreeMap::new();
    let mut latest_rollback = BTreeMap::new();
    for entry in &item.journal {
        let replace_status = latest_status
            .get(entry.action_id.as_str())
            .is_none_or(|(sequence, _)| entry.sequence >= *sequence);
        if replace_status {
            latest_status.insert(entry.action_id.as_str(), (entry.sequence, entry.status));
        }
        if let Some(rollback) = &entry.rollback {
            let replace_rollback = latest_rollback
                .get(entry.action_id.as_str())
                .is_none_or(|(sequence, _)| entry.sequence >= *sequence);
            if replace_rollback {
                latest_rollback.insert(entry.action_id.as_str(), (entry.sequence, rollback));
            }
        }
    }
    latest_rollback
        .into_iter()
        .filter_map(|(action_id, (_, rollback))| {
            let status = latest_status
                .get(action_id)
                .map_or(JournalStatus::Started, |(_, status)| *status);
            (!matches!(status, JournalStatus::Skipped | JournalStatus::RolledBack))
                .then_some((action_id, rollback))
        })
        .collect()
}

fn rollback_action_may_have_run(item: &AppliedCapability, action_id: &str) -> bool {
    item.journal
        .iter()
        .filter(|entry| entry.action_id == action_id)
        .max_by_key(|entry| entry.sequence)
        .is_none_or(|entry| {
            !matches!(
                entry.status,
                JournalStatus::Skipped | JournalStatus::RolledBack
            )
        })
}

fn rollback_action_kind(
    item: &AppliedCapability,
    action_id: &str,
    rollback: &RollbackMetadata,
) -> String {
    item.prepared
        .plan
        .actions
        .iter()
        .find(|action| action.id == action_id)
        .map(|action| action.kind.clone())
        .or_else(|| rollback.action.clone())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn missing_runtime_inverse_limitations(
    item: &AppliedCapability,
    claims: &BTreeMap<&str, &RollbackMetadata>,
    reason: &str,
) -> Vec<UnsupportedRollback> {
    if item.prepared.plan.actions.is_empty() {
        return vec![UnsupportedRollback {
            action_id: "runtime".to_owned(),
            kind: "runtime".to_owned(),
            reason: reason.to_owned(),
        }];
    }
    item.prepared
        .plan
        .actions
        .iter()
        .filter(|action| !claims.contains_key(action.id.as_str()))
        .filter(|action| rollback_action_may_have_run(item, &action.id))
        .map(|action| UnsupportedRollback {
            action_id: action.id.clone(),
            kind: action.kind.clone(),
            reason: reason.to_owned(),
        })
        .collect()
}

fn rollback_journal(
    plan: &PlanResult,
    plugin_journal: &[ActionJournalEntry],
) -> Vec<ActionJournalEntry> {
    let mut journal = plugin_journal.to_vec();
    let mut rollback_actions = journal
        .iter()
        .filter(|entry| entry.rollback.is_some())
        .map(|entry| entry.action_id.clone())
        .collect::<BTreeSet<_>>();
    let statuses = journal
        .iter()
        .map(|entry| (entry.action_id.clone(), entry.status))
        .collect::<BTreeMap<_, _>>();
    let mut sequence = journal
        .iter()
        .map(|entry| entry.sequence)
        .max()
        .unwrap_or(0);
    for action in &plan.actions {
        let Some(rollback) = &action.rollback else {
            continue;
        };
        if !rollback_actions.insert(action.id.clone()) {
            continue;
        }
        sequence = sequence.saturating_add(1);
        journal.push(ActionJournalEntry {
            sequence,
            action_id: action.id.clone(),
            status: statuses
                .get(&action.id)
                .copied()
                .unwrap_or(JournalStatus::Started),
            timestamp: None,
            message: None,
            rollback: Some(rollback.clone()),
            metadata: action.metadata.clone(),
        });
    }
    journal
}

fn scope_rollback_cleanup_secrets(
    manifest: &PluginManifest,
    secrets: &mut BTreeMap<String, SecretValue>,
) {
    // Keep exact provider credentials needed by plugin cleanup while dropping
    // application values admitted only through the constrained wildcard.
    let exact = manifest
        .required_secrets
        .iter()
        .filter(|requirement| requirement.name != "*")
        .map(|requirement| requirement.name.as_str())
        .collect::<BTreeSet<_>>();
    secrets.retain(|name, _| exact.contains(name.as_str()));
}

fn prior_runtime_revision(item: &PreparedCapability) -> Option<&str> {
    item.current.state.get("revision").and_then(Value::as_str)
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

#[derive(Debug, Eq, PartialEq)]
struct PlanContractEntry {
    capability: String,
    plugin_id: String,
    plan_digest: String,
}

fn plan_contract(prepared: &[PreparedCapability]) -> Result<Vec<PlanContractEntry>, CliError> {
    prepared
        .iter()
        .map(|item| {
            let serialized = serde_json::to_value(&item.plan)?;
            let canonical = canonical_json(&serialized);
            let encoded = serde_json::to_vec(&canonical)?;
            Ok(PlanContractEntry {
                capability: item.capability.as_str().to_owned(),
                plugin_id: item.plugin_id.clone(),
                plan_digest: hex::encode(Sha256::digest(encoded)),
            })
        })
        .collect()
}

fn canonical_json(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut entries = object.iter().collect::<Vec<_>>();
            entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key.clone(), canonical_json(value)))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical_json).collect()),
        _ => value.clone(),
    }
}

fn status_from_prepared(item: &PreparedCapability) -> PluginStatusView {
    PluginStatusView {
        capability: item.capability.as_str().to_owned(),
        plugin: item.plugin_id.clone(),
        status: item.current.status,
        state: item.current.state.clone(),
    }
}

fn locked_plan_request_timeout(context: &OperationContext, plan: &PlanResult) -> Duration {
    let selected = context
        .metadata
        .pointer("/selection/environment_ids")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let work_units = plan
        .actions
        .len()
        .saturating_add(selected)
        .saturating_add(1);
    operation_request_timeout(context, work_units)
}

fn record_planned_actions(journal: &mut OperationJournal, prepared: &[PreparedCapability]) {
    for item in prepared {
        for action in &item.plan.actions {
            journal.actions.push(JournalAction {
                plugin_id: item.plugin_id.clone(),
                capability: Some(item.capability.as_str().to_owned()),
                plan_id: Some(item.plan.plan_id.clone()),
                action_id: action.id.clone(),
                summary: action.summary.clone(),
                public_metadata: action.metadata.clone(),
                completed: false,
            });
        }
    }
}

fn mark_plugin_actions_completed(
    journal: &mut OperationJournal,
    capability: CoreCapability,
    plugin_id: &str,
    plan: &PlanResult,
    plugin_journal: &[ActionJournalEntry],
    complete_all_planned: bool,
) {
    let succeeded = if complete_all_planned {
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
        if action.plugin_id == plugin_id
            && action.capability.as_deref() == Some(capability.as_str())
            && action.plan_id.as_deref() == Some(plan.plan_id.as_str())
            && succeeded.contains(action.action_id.as_str())
        {
            action.completed = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lightrail_plugin_protocol::{
        Endpoint, ExecutableMetadata, PlannedAction, ProtocolCompatibility, SecretRequirement,
    };

    fn test_manifest(secret_names: &[&str]) -> PluginManifest {
        PluginManifest {
            id: "dev.lightrail.test".to_owned(),
            name: "Test".to_owned(),
            version: "0.0.0".to_owned(),
            protocol: ProtocolCompatibility::default(),
            executable: ExecutableMetadata::default(),
            capabilities: Vec::new(),
            features: Vec::new(),
            required_secrets: secret_names
                .iter()
                .map(|name| SecretRequirement {
                    name: (*name).to_owned(),
                    description: None,
                    required: true,
                })
                .collect(),
            config_schema: json!({}),
            config_ui_hints: json!({}),
        }
    }

    fn planned_action(id: &str, kind: &str, rollback: Option<RollbackMetadata>) -> PlannedAction {
        PlannedAction {
            id: id.to_owned(),
            kind: kind.to_owned(),
            summary: format!("Apply {id}"),
            destructive: false,
            depends_on: Vec::new(),
            rollback,
            metadata: json!({"resource": id}),
        }
    }

    fn rollback_metadata(
        supported: bool,
        action: Option<&str>,
        reason: Option<&str>,
    ) -> RollbackMetadata {
        RollbackMetadata {
            supported,
            action: action.map(ToOwned::to_owned),
            token: None,
            metadata: reason.map_or_else(|| json!({}), |reason| json!({"reason": reason})),
        }
    }

    fn prepared_for_rollback(
        capability: CoreCapability,
        status: ResourceStatus,
        state: Value,
        actions: Vec<PlannedAction>,
    ) -> PreparedCapability {
        PreparedCapability {
            capability,
            plugin_id: format!("dev.lightrail.{}", capability.as_str()),
            context: OperationContext {
                operation_id: "operation-id".to_owned(),
                environment_id: "environment-id".to_owned(),
                profile: "preview".to_owned(),
                project_root: None,
                config: json!({}),
                secrets: BTreeMap::new(),
                metadata: json!({}),
            },
            current: InspectResult {
                status,
                endpoints: Vec::new(),
                state,
                diagnostics: Vec::new(),
            },
            plan: PlanResult {
                plan_id: format!("plan-{}", capability.as_str()),
                has_changes: !actions.is_empty(),
                actions,
                metadata: json!({"desired": {}}),
            },
        }
    }

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

    #[test]
    fn aggregate_plugin_secret_selection_stays_capability_scoped() {
        let target_config = json!({
            "token": {"secret": "provider-token"},
        });
        let runtime_desired = json!({
            "apps": [{
                "environment": {
                    "DATABASE_URL": {"secret": "database-url"}
                }
            }]
        });

        assert_eq!(
            secret_references_for_operation(&target_config, None),
            BTreeSet::from(["provider-token".into()])
        );
        assert_eq!(
            secret_references_for_operation(&json!({}), Some(&runtime_desired)),
            BTreeSet::from(["database-url".into()])
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
    fn rollback_cleanup_keeps_exact_provider_credentials_and_drops_wildcard_secrets() {
        let provider_token = SecretValue::new("provider-token");
        let manifest = test_manifest(&["fly-token", "*"]);
        let mut secrets = BTreeMap::from([
            ("fly-token".into(), provider_token.clone()),
            (
                "database-url".into(),
                SecretValue::new("runtime-application-secret"),
            ),
        ]);

        scope_rollback_cleanup_secrets(&manifest, &mut secrets);

        assert_eq!(
            secrets.get("fly-token"),
            Some(&provider_token),
            "provider cleanup needs its exact manifest-declared credential"
        );
        assert!(
            !secrets.contains_key("database-url"),
            "cleanup must not receive application secrets admitted by a wildcard"
        );
    }

    #[test]
    fn mixed_runtime_rollback_compensates_supported_actions_and_reports_unsupported_ones() {
        let applied = AppliedCapability::new(prepared_for_rollback(
            CoreCapability::Runtime,
            ResourceStatus::Ready,
            json!({"revision": "previous"}),
            vec![
                planned_action(
                    "apply-deployment-web",
                    "kubernetes.apply",
                    Some(rollback_metadata(
                        true,
                        Some("runtime.restore-previous"),
                        None,
                    )),
                ),
                planned_action(
                    "apply-secret-web",
                    "kubernetes.apply",
                    Some(rollback_metadata(
                        false,
                        None,
                        Some("historical secret values are unavailable"),
                    )),
                ),
                planned_action(
                    "apply-pvc-data",
                    "kubernetes.apply",
                    Some(rollback_metadata(
                        false,
                        None,
                        Some("persistent data is not transactional"),
                    )),
                ),
                planned_action("apply-service-web", "kubernetes.apply", None),
            ],
        ));

        let classification = classify_rollback(&applied);

        assert_eq!(classification.operation, Some(RollbackOperation::Rollback));
        assert_eq!(
            classification
                .unsupported
                .iter()
                .map(|item| (item.action_id.as_str(), item.kind.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("apply-pvc-data", "kubernetes.apply"),
                ("apply-secret-web", "kubernetes.apply"),
                ("apply-service-web", "kubernetes.apply"),
            ]
        );
    }

    #[test]
    fn runtime_reports_missing_contract_alongside_an_unsupported_contract() {
        let applied = AppliedCapability::new(prepared_for_rollback(
            CoreCapability::Runtime,
            ResourceStatus::Ready,
            json!({"revision": "previous"}),
            vec![
                planned_action(
                    "replace-secret",
                    "runtime.replace-secret",
                    Some(rollback_metadata(
                        false,
                        None,
                        Some("historical secret values are unavailable"),
                    )),
                ),
                planned_action("replace-service", "runtime.replace-service", None),
            ],
        ));

        let classification = classify_rollback(&applied);

        assert_eq!(classification.operation, None);
        assert_eq!(
            classification
                .unsupported
                .iter()
                .map(|limitation| limitation.action_id.as_str())
                .collect::<Vec<_>>(),
            vec!["replace-secret", "replace-service"]
        );
    }

    #[test]
    fn runtime_missing_contracts_ignore_skipped_and_already_rolled_back_actions() {
        let mut applied = AppliedCapability::new(prepared_for_rollback(
            CoreCapability::Runtime,
            ResourceStatus::Ready,
            json!({"revision": "previous"}),
            ["ran", "skipped", "rolled-back"]
                .into_iter()
                .map(|id| planned_action(id, "runtime.reconcile", None))
                .collect(),
        ));
        applied.journal = vec![
            ActionJournalEntry {
                sequence: 1,
                action_id: "ran".to_owned(),
                status: JournalStatus::Succeeded,
                timestamp: None,
                message: None,
                rollback: None,
                metadata: json!({}),
            },
            ActionJournalEntry {
                sequence: 2,
                action_id: "skipped".to_owned(),
                status: JournalStatus::Skipped,
                timestamp: None,
                message: None,
                rollback: None,
                metadata: json!({}),
            },
            ActionJournalEntry {
                sequence: 3,
                action_id: "rolled-back".to_owned(),
                status: JournalStatus::RolledBack,
                timestamp: None,
                message: None,
                rollback: None,
                metadata: json!({}),
            },
        ];

        let classification = classify_rollback(&applied);

        assert_eq!(classification.operation, None);
        assert_eq!(classification.unsupported.len(), 1);
        assert_eq!(classification.unsupported[0].action_id, "ran");
    }

    #[test]
    fn existing_runtime_without_a_prior_revision_is_never_destroyed_as_cleanup() {
        let applied = AppliedCapability::new(prepared_for_rollback(
            CoreCapability::Runtime,
            ResourceStatus::Ready,
            json!({"provider": "native"}),
            vec![planned_action(
                "runtime-reconcile",
                "native.runtime.reconcile",
                Some(rollback_metadata(
                    true,
                    Some("runtime.restore-previous"),
                    None,
                )),
            )],
        ));

        let classification = classify_rollback(&applied);

        assert_eq!(classification.operation, None);
        assert_eq!(classification.unsupported.len(), 1);
        assert_eq!(classification.unsupported[0].action_id, "runtime-reconcile");
        assert!(
            classification.unsupported[0]
                .reason
                .contains("no observed prior revision")
        );
    }

    #[test]
    fn existing_runtime_without_an_advertised_inverse_is_reported() {
        let applied = AppliedCapability::new(prepared_for_rollback(
            CoreCapability::Runtime,
            ResourceStatus::Ready,
            json!({"revision": "previous"}),
            vec![planned_action(
                "runtime.reconcile.app",
                "fly.runtime.reconcile",
                None,
            )],
        ));

        let classification = classify_rollback(&applied);

        assert_eq!(classification.operation, None);
        assert_eq!(
            classification
                .unsupported
                .iter()
                .map(|item| (item.action_id.as_str(), item.kind.as_str()))
                .collect::<Vec<_>>(),
            vec![("runtime.reconcile.app", "fly.runtime.reconcile")]
        );
    }

    #[test]
    fn whole_capability_cleanup_requires_a_previously_absent_resource() {
        let inverse = Some(rollback_metadata(true, Some("delete"), None));
        let absent_target = AppliedCapability::new(prepared_for_rollback(
            CoreCapability::Target,
            ResourceStatus::Absent,
            json!({}),
            vec![planned_action(
                "create-firewall",
                "hetzner.create",
                inverse.clone(),
            )],
        ));
        let existing_target = AppliedCapability::new(prepared_for_rollback(
            CoreCapability::Target,
            ResourceStatus::Ready,
            json!({"server_id": 42}),
            vec![planned_action("create-firewall", "hetzner.create", inverse)],
        ));
        let absent_runtime = AppliedCapability::new(prepared_for_rollback(
            CoreCapability::Runtime,
            ResourceStatus::Absent,
            json!({}),
            vec![planned_action(
                "deploy",
                "runtime.deploy",
                Some(rollback_metadata(
                    false,
                    None,
                    Some("previous revision rollback is unavailable"),
                )),
            )],
        ));
        let builder = AppliedCapability::new(prepared_for_rollback(
            CoreCapability::Builder,
            ResourceStatus::Absent,
            json!({}),
            vec![planned_action("build", "builder.push", None)],
        ));

        assert_eq!(
            classify_rollback(&absent_target).operation,
            Some(RollbackOperation::Cleanup)
        );
        let existing = classify_rollback(&existing_target);
        assert_eq!(existing.operation, None);
        assert_eq!(existing.unsupported[0].action_id, "create-firewall");
        let existing_without_contract = AppliedCapability::new(prepared_for_rollback(
            CoreCapability::Target,
            ResourceStatus::Ready,
            json!({"server_id": 42}),
            vec![planned_action("update-firewall", "hetzner.update", None)],
        ));
        assert_eq!(
            classify_rollback(&existing_without_contract).unsupported,
            vec![UnsupportedRollback {
                action_id: "update-firewall".to_owned(),
                kind: "hetzner.update".to_owned(),
                reason: "the existing target action advertised no automatic rollback contract"
                    .to_owned(),
            }]
        );
        let mut skipped_without_contract = existing_without_contract.clone();
        skipped_without_contract.journal.push(ActionJournalEntry {
            sequence: 1,
            action_id: "update-firewall".to_owned(),
            status: JournalStatus::Skipped,
            timestamp: None,
            message: None,
            rollback: None,
            metadata: json!({}),
        });
        assert!(
            classify_rollback(&skipped_without_contract)
                .unsupported
                .is_empty()
        );
        assert_eq!(
            classify_rollback(&absent_runtime),
            RollbackClassification {
                operation: Some(RollbackOperation::Cleanup),
                unsupported: Vec::new(),
            }
        );
        assert_eq!(
            classify_rollback(&builder),
            RollbackClassification {
                operation: None,
                unsupported: Vec::new(),
            }
        );
    }

    #[test]
    fn cleanup_uses_post_apply_state_but_revision_rollback_uses_locked_prior_state() {
        let mut applied = AppliedCapability::new(prepared_for_rollback(
            CoreCapability::Runtime,
            ResourceStatus::Absent,
            json!({"present": false}),
            vec![planned_action("deploy", "runtime.deploy", None)],
        ));
        applied.record_apply_result(&ApplyResult {
            revision: Some("new".to_owned()),
            state: json!({"present": true, "resource_id": "exact-new-resource"}),
            journal: Vec::new(),
        });

        assert_eq!(
            rollback_current_state(&applied, RollbackOperation::Cleanup),
            json!({"present": true, "resource_id": "exact-new-resource"})
        );
        assert_eq!(
            rollback_current_state(&applied, RollbackOperation::Rollback),
            json!({"present": false})
        );
    }

    #[test]
    fn cancelled_success_is_recorded_before_entering_exact_state_cleanup() {
        let prepared = prepared_for_rollback(
            CoreCapability::Runtime,
            ResourceStatus::Absent,
            json!({"present": false}),
            vec![planned_action("deploy", "runtime.deploy", None)],
        );
        let mut applied = AppliedCapability::new(prepared.clone());
        let mut journal = OperationJournal::new("environment-id", OperationKind::Up);
        record_planned_actions(&mut journal, std::slice::from_ref(&prepared));
        let result = ApplyResult {
            revision: Some("new".to_owned()),
            state: json!({"present": true, "resource_id": "exact-created-resource"}),
            journal: vec![ActionJournalEntry {
                sequence: 1,
                action_id: "deploy".to_owned(),
                status: JournalStatus::Succeeded,
                timestamp: None,
                message: None,
                rollback: None,
                metadata: json!({"resource_id": "exact-created-resource"}),
            }],
        };

        let (returned, cancelled) = record_apply_attempt(
            &mut applied,
            &mut journal,
            ApplyAttempt {
                result: Ok(result),
                cancelled: true,
            },
        )
        .expect("successful plugin result remains available");

        assert!(cancelled);
        assert!(check_apply_cancellation(cancelled).is_err());
        assert_eq!(
            returned.state,
            applied.post_apply_state.clone().expect("state")
        );
        assert_eq!(
            rollback_current_state(&applied, RollbackOperation::Cleanup),
            json!({"present": true, "resource_id": "exact-created-resource"})
        );
        assert!(journal.actions[0].completed);
    }

    #[test]
    fn journal_completion_is_scoped_to_capability_and_exact_plan() {
        let runtime = prepared_for_rollback(
            CoreCapability::Runtime,
            ResourceStatus::Ready,
            json!({"revision": "previous"}),
            vec![planned_action("reconcile", "runtime.reconcile", None)],
        );
        let mut builder = prepared_for_rollback(
            CoreCapability::Builder,
            ResourceStatus::Ready,
            json!({}),
            vec![planned_action("reconcile", "builder.reconcile", None)],
        );
        builder.plugin_id.clone_from(&runtime.plugin_id);
        let mut stale_runtime_plan = runtime.clone();
        stale_runtime_plan.plan.plan_id = "plan-runtime-stale".to_owned();
        let mut journal = OperationJournal::new("environment-id", OperationKind::Up);
        record_planned_actions(
            &mut journal,
            &[builder, stale_runtime_plan, runtime.clone()],
        );

        mark_plugin_actions_completed(
            &mut journal,
            runtime.capability,
            &runtime.plugin_id,
            &runtime.plan,
            &[],
            true,
        );

        assert!(!journal.actions[0].completed);
        assert!(!journal.actions[1].completed);
        assert!(journal.actions[2].completed);
        assert_eq!(
            journal.actions[2].capability.as_deref(),
            Some(CoreCapability::Runtime.as_str())
        );
        assert_eq!(
            journal.actions[2].plan_id.as_deref(),
            Some(runtime.plan.plan_id.as_str())
        );
    }

    #[test]
    fn incomplete_destroy_marks_only_explicitly_succeeded_locked_plan_actions() {
        let prepared = prepared_for_rollback(
            CoreCapability::Runtime,
            ResourceStatus::Ready,
            json!({"revision": "previous"}),
            vec![
                planned_action("remove-web", "runtime.remove", None),
                planned_action("remove-worker", "runtime.remove", None),
            ],
        );
        let mut journal = OperationJournal::new("environment-id", OperationKind::Down);
        record_planned_actions(&mut journal, std::slice::from_ref(&prepared));

        mark_plugin_actions_completed(
            &mut journal,
            prepared.capability,
            &prepared.plugin_id,
            &prepared.plan,
            &[ActionJournalEntry {
                sequence: 1,
                action_id: "remove-web".to_owned(),
                status: JournalStatus::Succeeded,
                timestamp: None,
                message: None,
                rollback: None,
                metadata: json!({}),
            }],
            false,
        );

        assert!(journal.actions[0].completed);
        assert!(!journal.actions[1].completed);
        assert_eq!(
            journal.actions[0].plan_id.as_deref(),
            Some(prepared.plan.plan_id.as_str())
        );
    }

    #[test]
    fn completed_destroy_marks_the_entire_exact_locked_plan() {
        let prepared = prepared_for_rollback(
            CoreCapability::Runtime,
            ResourceStatus::Ready,
            json!({}),
            vec![
                planned_action("deleted-first", "runtime.delete", None),
                planned_action("already-absent-second", "runtime.delete", None),
            ],
        );
        let mut journal = OperationJournal::new("environment-id", OperationKind::Down);
        record_planned_actions(&mut journal, std::slice::from_ref(&prepared));
        let plugin_journal = vec![ActionJournalEntry {
            sequence: 1,
            action_id: "deleted-first".into(),
            status: JournalStatus::Succeeded,
            timestamp: None,
            message: None,
            rollback: None,
            metadata: json!({}),
        }];

        mark_plugin_actions_completed(
            &mut journal,
            prepared.capability,
            &prepared.plugin_id,
            &prepared.plan,
            &plugin_journal,
            true,
        );

        assert!(journal.actions.iter().all(|action| action.completed));
    }

    #[test]
    fn exposure_and_dns_use_only_advertised_inverses() {
        let existing_exposure = AppliedCapability::new(prepared_for_rollback(
            CoreCapability::Exposure,
            ResourceStatus::Ready,
            json!({}),
            vec![planned_action(
                "route",
                "exposure.route",
                Some(rollback_metadata(true, Some("exposure.remove-route"), None)),
            )],
        ));
        let absent_dns = AppliedCapability::new(prepared_for_rollback(
            CoreCapability::Dns,
            ResourceStatus::Absent,
            json!({}),
            vec![planned_action(
                "record",
                "dns.record",
                Some(rollback_metadata(true, Some("dns.remove-record"), None)),
            )],
        ));
        let readiness = AppliedCapability::new(prepared_for_rollback(
            CoreCapability::Exposure,
            ResourceStatus::Ready,
            json!({}),
            vec![planned_action("ready-web", "exposure.readiness", None)],
        ));

        assert_eq!(
            classify_rollback(&existing_exposure).operation,
            Some(RollbackOperation::Rollback)
        );
        assert_eq!(
            classify_rollback(&absent_dns).operation,
            Some(RollbackOperation::Cleanup)
        );
        assert_eq!(classify_rollback(&readiness).operation, None);
    }

    #[test]
    fn rollback_order_is_reverse_apply_order() {
        let applied = [
            AppliedCapability::new(prepared_for_rollback(
                CoreCapability::Target,
                ResourceStatus::Absent,
                json!({}),
                vec![planned_action("target", "target.create", None)],
            )),
            AppliedCapability::new(prepared_for_rollback(
                CoreCapability::Runtime,
                ResourceStatus::Absent,
                json!({}),
                vec![planned_action("runtime", "runtime.create", None)],
            )),
            AppliedCapability::new(prepared_for_rollback(
                CoreCapability::Exposure,
                ResourceStatus::Absent,
                json!({}),
                vec![planned_action("exposure", "exposure.create", None)],
            )),
        ];

        assert_eq!(
            rollback_order(&applied)
                .map(|item| item.prepared.capability)
                .collect::<Vec<_>>(),
            vec![
                CoreCapability::Exposure,
                CoreCapability::Runtime,
                CoreCapability::Target,
            ]
        );
    }

    #[test]
    fn rollback_journal_preserves_plugin_tokens_and_adds_locked_plan_fallbacks() {
        let plan = PlanResult {
            plan_id: "plan".to_owned(),
            actions: vec![
                planned_action(
                    "first",
                    "runtime.first",
                    Some(rollback_metadata(true, Some("runtime.restore"), None)),
                ),
                planned_action(
                    "second",
                    "runtime.second",
                    Some(rollback_metadata(
                        false,
                        None,
                        Some("second cannot be restored"),
                    )),
                ),
            ],
            has_changes: true,
            metadata: json!({}),
        };
        let token = SecretValue::new("opaque-token");
        let plugin_journal = vec![ActionJournalEntry {
            sequence: 7,
            action_id: "first".to_owned(),
            status: JournalStatus::Succeeded,
            timestamp: Some("2026-07-19T00:00:00Z".to_owned()),
            message: Some("applied".to_owned()),
            rollback: Some(RollbackMetadata {
                supported: true,
                action: Some("runtime.restore".to_owned()),
                token: Some(token.clone()),
                metadata: json!({"provider_id": "resource-1"}),
            }),
            metadata: json!({"observed": true}),
        }];

        let journal = rollback_journal(&plan, &plugin_journal);

        assert_eq!(journal.len(), 2);
        assert_eq!(journal[0].sequence, 7);
        assert_eq!(
            journal[0]
                .rollback
                .as_ref()
                .and_then(|rollback| rollback.token.as_ref()),
            Some(&token)
        );
        assert_eq!(journal[0].metadata, json!({"observed": true}));
        assert_eq!(journal[1].sequence, 8);
        assert_eq!(journal[1].action_id, "second");
        assert!(
            !journal[1]
                .rollback
                .as_ref()
                .expect("locked plan rollback metadata")
                .supported
        );
    }

    #[test]
    fn rollback_claims_ignore_skipped_and_already_rolled_back_actions() {
        let inverse = rollback_metadata(true, Some("runtime.restore"), None);
        let mut applied = AppliedCapability::new(prepared_for_rollback(
            CoreCapability::Runtime,
            ResourceStatus::Ready,
            json!({"revision": "previous"}),
            ["started", "succeeded", "skipped", "rolled-back"]
                .into_iter()
                .map(|id| planned_action(id, "runtime.reconcile", Some(inverse.clone())))
                .collect(),
        ));
        let entry = |sequence: u64,
                     action_id: &str,
                     status: JournalStatus,
                     rollback: Option<RollbackMetadata>| ActionJournalEntry {
            sequence,
            action_id: action_id.to_owned(),
            status,
            timestamp: None,
            message: None,
            rollback,
            metadata: json!({}),
        };
        applied.journal = vec![
            entry(1, "started", JournalStatus::Started, Some(inverse.clone())),
            entry(
                2,
                "succeeded",
                JournalStatus::Succeeded,
                Some(inverse.clone()),
            ),
            entry(3, "skipped", JournalStatus::Started, Some(inverse.clone())),
            entry(4, "skipped", JournalStatus::Skipped, None),
            entry(5, "rolled-back", JournalStatus::Succeeded, Some(inverse)),
            entry(6, "rolled-back", JournalStatus::RolledBack, None),
        ];

        let claims = rollback_claims(&applied);

        assert_eq!(
            claims.keys().copied().collect::<Vec<_>>(),
            vec!["started", "succeeded"]
        );
    }

    #[test]
    fn plan_contract_covers_the_full_serialized_plan() {
        let base = prepared_for_rollback(
            CoreCapability::Runtime,
            ResourceStatus::Ready,
            json!({"revision": "previous"}),
            vec![planned_action(
                "reconcile",
                "runtime.reconcile",
                Some(rollback_metadata(true, Some("runtime.restore"), None)),
            )],
        );
        let baseline = plan_contract(std::slice::from_ref(&base)).expect("baseline plan contract");
        let mut variants = Vec::new();

        let mut changed_kind = base.clone();
        changed_kind.plan.actions[0].kind = "runtime.replace".to_owned();
        variants.push(changed_kind);

        let mut changed_summary = base.clone();
        changed_summary.plan.actions[0].summary = "Replace runtime".to_owned();
        variants.push(changed_summary);

        let mut changed_dependencies = base.clone();
        changed_dependencies.plan.actions[0].depends_on = vec!["build".to_owned()];
        variants.push(changed_dependencies);

        let mut changed_rollback = base.clone();
        changed_rollback.plan.actions[0]
            .rollback
            .as_mut()
            .expect("rollback metadata")
            .metadata = json!({"provider_id": "resource-1"});
        variants.push(changed_rollback);

        let mut changed_action_metadata = base.clone();
        changed_action_metadata.plan.actions[0].metadata = json!({"resource": "replacement"});
        variants.push(changed_action_metadata);

        let mut changed_plan_metadata = base.clone();
        changed_plan_metadata.plan.metadata = json!({"desired": {"revision": "next"}});
        variants.push(changed_plan_metadata);

        for variant in variants {
            assert_ne!(
                plan_contract(std::slice::from_ref(&variant)).expect("variant plan contract"),
                baseline
            );
        }
    }

    #[test]
    fn plan_contract_canonicalizes_nested_object_key_order() {
        let mut left = prepared_for_rollback(
            CoreCapability::Runtime,
            ResourceStatus::Ready,
            json!({}),
            vec![planned_action("reconcile", "runtime.reconcile", None)],
        );
        let mut right = left.clone();
        left.plan.metadata =
            serde_json::from_str(r#"{"z":{"second":2,"first":1},"a":{"right":true,"left":false}}"#)
                .expect("left metadata");
        right.plan.metadata =
            serde_json::from_str(r#"{"a":{"left":false,"right":true},"z":{"first":1,"second":2}}"#)
                .expect("right metadata");

        assert_eq!(
            plan_contract(std::slice::from_ref(&left)).expect("left plan contract"),
            plan_contract(std::slice::from_ref(&right)).expect("right plan contract")
        );
    }

    #[test]
    fn mutation_timeout_counts_locked_actions_and_exact_destroy_selection() {
        let mut prepared = prepared_for_rollback(
            CoreCapability::Target,
            ResourceStatus::Ready,
            json!({}),
            vec![
                planned_action("first", "target.update", None),
                planned_action("second", "target.update", None),
            ],
        );
        prepared.context.config = json!({
            "command_timeout_seconds": 3_600,
            "readiness_timeout_seconds": 3_000,
        });
        prepared.context.metadata["selection"] = json!({
            "environment_ids": ["one", "two", "three"],
        });

        // Two locked actions + three exact selections + one final
        // observation/coordination unit.
        assert_eq!(
            locked_plan_request_timeout(&prepared.context, &prepared.plan),
            Duration::from_secs((3_600 + 3_000) * 6 + 300)
        );
    }

    #[test]
    fn prune_plan_output_is_single_document_for_machine_mutations() {
        for format in [OutputFormat::Human, OutputFormat::Json, OutputFormat::Plain] {
            assert!(should_print_prune_plan(format, true));
        }
        assert!(should_print_prune_plan(OutputFormat::Human, false));
        assert!(!should_print_prune_plan(OutputFormat::Json, false));
        assert!(!should_print_prune_plan(OutputFormat::Plain, false));
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
                    "expires_at": "2026-07-20T12:00:00Z",
                    "expires_at_unix": 1_784_548_800,
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
        assert_eq!(environments[0].expires_at_unix, Some(1_784_548_800));
    }

    #[test]
    fn prune_selects_only_expired_owned_environments() {
        let state = json!({
            "environment_contract": 1,
            "environments": [
                {
                    "environment_id": "lr-expired",
                    "project_id": "project-id",
                    "branch": "old",
                    "profile": "preview",
                    "expires_at": "2026-07-18T00:00:00Z",
                    "expires_at_unix": 100
                },
                {
                    "environment_id": "lr-live",
                    "project_id": "project-id",
                    "expires_at_unix": 300
                },
                {
                    "environment_id": "lr-retained",
                    "project_id": "project-id"
                },
                {
                    "environment_id": "lr-null-expiry",
                    "project_id": "project-id",
                    "expires_at_unix": null
                }
            ]
        });

        let selected = expired_candidates(&state, "project-id", 200).expect("selection");

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].environment_id, "lr-expired");
        assert_eq!(selected[0].expires_at_unix, 100);
    }

    #[test]
    fn prune_rejects_ambiguous_or_cross_project_observations() {
        let missing_contract = json!({
            "environments": [{
                "environment_id": "lr-expired",
                "project_id": "project-id",
                "expires_at_unix": 100
            }]
        });
        assert!(expired_candidates(&missing_contract, "project-id", 200).is_err());

        let wrong_project = json!({
            "environment_contract": 1,
            "environments": [{
                "environment_id": "lr-expired",
                "project_id": "another-project",
                "expires_at_unix": 100
            }]
        });
        assert!(expired_candidates(&wrong_project, "project-id", 200).is_err());
    }

    #[test]
    fn prune_fails_closed_for_malformed_environment_collections_and_expiry_values() {
        let malformed_environments = json!({
            "environment_contract": 1,
            "environments": {}
        });
        assert!(expired_candidates(&malformed_environments, "project-id", 200).is_err());

        for expires_at_unix in [json!("100"), json!(-1), json!(1.5), json!({})] {
            let malformed_expiry = json!({
                "environment_contract": 1,
                "environments": [{
                    "environment_id": "lr-expired",
                    "project_id": "project-id",
                    "expires_at_unix": expires_at_unix
                }]
            });
            assert!(expired_candidates(&malformed_expiry, "project-id", 200).is_err());
        }

        assert!(
            expired_candidates(&json!({"environment_contract": 1}), "project-id", 200)
                .expect("missing environments remain an empty observation")
                .is_empty()
        );
    }

    #[test]
    fn environment_isolation_serializes_every_mutation_at_project_scope() {
        for all in [false, true] {
            assert_eq!(
                mutation_lock_scope(
                    lightrail_core::Isolation::Environment,
                    all,
                    "project-id",
                    "environment-id",
                    "dev.lightrail.provider",
                ),
                (LockScope::Project, "project-id".to_owned())
            );
        }
    }

    #[test]
    fn force_recovery_is_rejected_outside_machine_isolation() {
        assert!(validate_down_force(lightrail_core::Isolation::Machine, true).is_ok());
        assert!(validate_down_force(lightrail_core::Isolation::Machine, false).is_ok());
        assert!(validate_down_force(lightrail_core::Isolation::Project, true).is_err());
        assert!(validate_down_force(lightrail_core::Isolation::Environment, true).is_err());
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
