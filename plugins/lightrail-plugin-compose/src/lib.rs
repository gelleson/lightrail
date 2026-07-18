//! Compose capability adapter and protocol boundary.
//!
//! This module translates protocol requests into the validated Compose
//! contract. Compose inspection and generated documents live in
//! `compose_model`; local/SSH process boundaries live in `command`; build,
//! transfer, Traefik, runtime inspection, rollback, and readiness live in
//! `runtime`.

mod command;
mod compose_model;
pub mod contract;
mod error;
mod runtime;

use std::collections::BTreeMap;

use async_trait::async_trait;
use compose_model::{endpoints, render_deployment, validate_apps};
use contract::{ContextMetadata, DesiredState, PluginConfig};
use error::ComposePluginError;
use lightrail_plugin_protocol::{
    ActionJournalEntry, ApplyRequest, ApplyResult, CancelRequest, CancelResult, Capability,
    DestroyRequest, DestroyResult, Diagnostic, DiagnosticSeverity, EventSink, ExecutableMetadata,
    InspectRequest, InspectResult, JournalStatus, LogsRequest, LogsResult, PlanRequest, PlanResult,
    PlannedAction, PluginError, PluginEvent, PluginHandler, PluginManifest, PluginResult,
    ProtocolCompatibility, ResourceStatus, RollbackMetadata, SecretRequirement, ValidateRequest,
    ValidateResult,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::runtime::{
    build_and_transfer, deploy, destroy_environment, fetch_logs, follow_logs,
    inspect_orphan_resources, inspect_project, inspect_remote, load_remote_manifest,
    resolve_compose, restore_previous, wait_for_endpoints,
};

pub const PLUGIN_ID: &str = "dev.lightrail.compose";

#[derive(Clone, Debug, Default)]
pub struct ComposePlugin;

#[async_trait]
impl PluginHandler for ComposePlugin {
    fn manifest(&self) -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID.to_owned(),
            name: "Lightrail Compose".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            protocol: ProtocolCompatibility::default(),
            executable: ExecutableMetadata {
                command: Some("lightrail-plugin-compose".to_owned()),
                homepage: Some("https://github.com/gelleson/lightrail".to_owned()),
                ..ExecutableMetadata::default()
            },
            capabilities: vec![
                Capability::Source,
                Capability::Builder,
                Capability::Runtime,
                Capability::Exposure,
                Capability::Dns,
            ],
            required_secrets: vec![SecretRequirement {
                name: "*".to_owned(),
                description: Some(
                    "Only app environment secret names explicitly referenced by lightrail.toml"
                        .to_owned(),
                ),
                required: false,
            }],
            config_schema: config_schema(),
            config_ui_hints: json!({
                "dns_domain": {
                    "label": "IP DNS domain",
                    "help": "Only sslip.io and nip.io are supported"
                },
                "acme_email": {
                    "label": "ACME account email"
                }
            }),
        }
    }

    async fn validate(
        &self,
        request: ValidateRequest,
        _events: &EventSink,
    ) -> PluginResult<ValidateResult> {
        Ok(validate_request(request).await)
    }

    async fn plan(&self, request: PlanRequest, _events: &EventSink) -> PluginResult<PlanResult> {
        plan_request(request).await.map_err(Into::into)
    }

    async fn apply(&self, request: ApplyRequest, events: &EventSink) -> PluginResult<ApplyResult> {
        apply_request(request, events).await
    }

    async fn inspect(
        &self,
        request: InspectRequest,
        _events: &EventSink,
    ) -> PluginResult<InspectResult> {
        inspect_request(request).await.map_err(Into::into)
    }

    async fn destroy(
        &self,
        request: DestroyRequest,
        events: &EventSink,
    ) -> PluginResult<DestroyResult> {
        destroy_request(request, events).await
    }

    async fn cancel(
        &self,
        _request: CancelRequest,
        _events: &EventSink,
    ) -> PluginResult<CancelResult> {
        // JSON-RPC request cancellation aborts the handler future. Every child
        // process is kill-on-drop, so no separate operation registry is needed.
        Ok(CancelResult {
            acknowledged: false,
        })
    }

    async fn logs(&self, request: LogsRequest, events: &EventSink) -> PluginResult<LogsResult> {
        logs_request(request, events).await.map_err(Into::into)
    }
}

async fn validate_request(request: ValidateRequest) -> ValidateResult {
    match validate_inner(&request).await {
        Ok((normalized, warnings)) => {
            let diagnostics = warnings
                .into_iter()
                .map(|message| Diagnostic {
                    severity: DiagnosticSeverity::Warning,
                    code: "undeclared_app_port".to_owned(),
                    message,
                    path: Some("/apps".to_owned()),
                    help: Some(
                        "Declare the container port with `expose` for clearer Compose intent"
                            .to_owned(),
                    ),
                })
                .collect();
            ValidateResult {
                valid: true,
                diagnostics,
                normalized_config: Some(normalized),
            }
        }
        Err(error) => ValidateResult {
            valid: false,
            diagnostics: vec![diagnostic_from_error(&error)],
            normalized_config: None,
        },
    }
}

async fn validate_inner(
    request: &ValidateRequest,
) -> Result<(Value, Vec<String>), ComposePluginError> {
    let metadata = ContextMetadata::from_context(&request.context)?;
    require_supported_capability(&metadata.capability)?;
    let config = PluginConfig::from_context(&request.context)?;
    let desired = DesiredState::parse(request.desired.clone())?;
    validate_context_identity(&request.context, &desired)?;
    if desired.destroy {
        return Ok((
            json!({
                "schema": desired.schema,
                "capability": metadata.capability,
                "destroy": true,
            }),
            Vec::new(),
        ));
    }
    let (_, inventory, _) = resolve_compose(&desired, &request.context).await?;
    let warnings = validate_apps(&desired, &inventory)?;
    if capability_needs_target(&metadata.capability) {
        let target = metadata.optional_target(Some(&desired))?;
        if matches!(
            metadata.capability,
            Capability::Runtime | Capability::Exposure | Capability::Dns
        ) {
            if let Some(target) = target {
                endpoints(&desired, &target, &config)?;
            }
        }
    }
    Ok((
        json!({
            "schema": desired.schema,
            "capability": metadata.capability,
            "dns_domain": config.dns_domain,
        }),
        warnings,
    ))
}

async fn plan_request(request: PlanRequest) -> Result<PlanResult, ComposePluginError> {
    let metadata = ContextMetadata::from_context(&request.context)?;
    require_supported_capability(&metadata.capability)?;
    let config = PluginConfig::from_context(&request.context)?;
    let desired_value = request.desired.clone();
    let desired = DesiredState::parse(desired_value.clone())?;
    validate_context_identity(&request.context, &desired)?;
    if desired.destroy {
        let already_absent = current_proves_absent(request.current.as_ref(), metadata.all);
        let actions = planned_actions(
            &metadata.capability,
            &desired,
            &compose_model::ComposeInventory {
                services: BTreeMap::new(),
            },
            already_absent,
        );
        let plan_metadata = json!({
            "schema": 1,
            "capability": metadata.capability,
            "operation": metadata.operation,
            "desired": desired_value,
            "destroy": true,
        });
        let has_changes = !actions.is_empty();
        return Ok(finalize_plan(actions, has_changes, plan_metadata));
    }
    let (document, inventory, revision) = resolve_compose(&desired, &request.context).await?;
    validate_apps(&desired, &inventory)?;
    let target = if capability_needs_target(&metadata.capability) {
        metadata.optional_target(Some(&desired))?
    } else {
        None
    };
    let endpoint_values = target
        .as_ref()
        .filter(|_| {
            matches!(
                metadata.capability,
                Capability::Runtime | Capability::Exposure | Capability::Dns
            )
        })
        .map(|target| endpoints(&desired, target, &config))
        .transpose()?
        .unwrap_or_default();
    let images = compose_model::image_map(&desired, &inventory, &revision)?;
    let current_revision = request
        .current
        .as_ref()
        .and_then(|current| current.get("revision"))
        .and_then(Value::as_str);
    let already_current = current_revision == Some(revision.as_str()) && !desired.environment.dirty;
    let actions = planned_actions(&metadata.capability, &desired, &inventory, already_current);
    let has_changes = !actions.is_empty() && !matches!(metadata.capability, Capability::Dns);
    let plan_metadata = json!({
        "schema": 1,
        "capability": metadata.capability,
        "operation": metadata.operation,
        "desired": desired_value,
        "revision": revision,
        "images": images,
        "endpoints": endpoint_values,
        "document_digest": digest_value(&document),
    });
    Ok(finalize_plan(actions, has_changes, plan_metadata))
}

fn current_proves_absent(current: Option<&Value>, all: bool) -> bool {
    let Some(current) = current else {
        return false;
    };
    current.get("status").and_then(Value::as_str) == Some("absent")
        || (all
            && current
                .get("environments")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty))
}

fn finalize_plan(actions: Vec<PlannedAction>, has_changes: bool, metadata: Value) -> PlanResult {
    let plan_id = plan_id(&metadata, &actions, has_changes);
    PlanResult {
        plan_id,
        actions,
        has_changes,
        metadata,
    }
}

fn plan_id(metadata: &Value, actions: &[PlannedAction], has_changes: bool) -> String {
    format!(
        "compose-{}",
        digest_value(&json!({
            "metadata": metadata,
            "actions": actions,
            "has_changes": has_changes,
        }))
    )
}

fn planned_actions(
    capability: &Capability,
    desired: &DesiredState,
    inventory: &compose_model::ComposeInventory,
    already_current: bool,
) -> Vec<PlannedAction> {
    if desired.destroy {
        return if capability == &Capability::Runtime && !already_current {
            vec![action(
                "destroy-compose-environment",
                "runtime.destroy",
                "Remove the environment Compose project, volumes, and isolated ingress network",
                true,
                Vec::new(),
                false,
            )]
        } else {
            Vec::new()
        };
    }
    match capability {
        Capability::Source if !already_current => vec![action(
            "resolve-compose",
            "source.resolve",
            "Resolve and validate the local Compose application",
            false,
            Vec::new(),
            false,
        )],
        Capability::Builder if !already_current => inventory
            .services
            .iter()
            .filter(|(_, service)| service.build)
            .flat_map(|(service, _)| {
                let build_id = format!("build-{service}");
                [
                    action(
                        &build_id,
                        "builder.buildx",
                        &format!("Build `{service}` for the target platform with Buildx"),
                        false,
                        Vec::new(),
                        false,
                    ),
                    action(
                        &format!("transfer-{service}"),
                        "builder.transfer",
                        &format!("Transfer missing `{service}` image over SSH"),
                        false,
                        vec![build_id],
                        false,
                    ),
                ]
            })
            .collect(),
        Capability::Runtime => vec![
            action(
                "ensure-shared-ingress",
                "runtime.ingress",
                "Reconcile shared Traefik ingress and ACME HTTP-01",
                false,
                Vec::new(),
                false,
            ),
            action(
                "deploy-compose",
                "runtime.compose",
                "Deploy the environment-scoped Compose project",
                false,
                vec!["ensure-shared-ingress".to_owned()],
                true,
            ),
        ],
        Capability::Exposure => desired
            .apps
            .iter()
            .map(|app| {
                action(
                    &format!("ready-{}", app.name),
                    "exposure.readiness",
                    &format!("Wait for valid HTTPS readiness of `{}`", app.name),
                    false,
                    Vec::new(),
                    false,
                )
            })
            .collect(),
        Capability::Dns => vec![action(
            "resolve-ip-dns",
            "dns.resolve",
            "Compute branch-first application URLs from the target IPv4 address",
            false,
            Vec::new(),
            false,
        )],
        _ => Vec::new(),
    }
}

fn action(
    id: &str,
    kind: &str,
    summary: &str,
    destructive: bool,
    depends_on: Vec<String>,
    rollback_supported: bool,
) -> PlannedAction {
    PlannedAction {
        id: id.to_owned(),
        kind: kind.to_owned(),
        summary: summary.to_owned(),
        destructive,
        depends_on,
        rollback: rollback_supported.then(|| RollbackMetadata {
            supported: true,
            action: Some("runtime.restore-previous".to_owned()),
            token: None,
            metadata: json!({}),
        }),
        metadata: json!({}),
    }
}

#[allow(clippy::too_many_lines)]
async fn apply_request(request: ApplyRequest, events: &EventSink) -> PluginResult<ApplyResult> {
    let metadata = ContextMetadata::from_context(&request.context).map_err(PluginError::from)?;
    require_supported_capability(&metadata.capability).map_err(PluginError::from)?;
    validate_plan_integrity(&request.plan, &metadata).map_err(PluginError::from)?;
    let desired_value = request
        .plan
        .metadata
        .get("desired")
        .cloned()
        .ok_or(ComposePluginError::MissingPlanDesired)
        .map_err(PluginError::from)?;
    let desired = DesiredState::parse(desired_value).map_err(PluginError::from)?;
    validate_context_identity(&request.context, &desired).map_err(PluginError::from)?;
    let config = PluginConfig::from_context(&request.context).map_err(PluginError::from)?;
    if desired.destroy {
        if request.plan.actions.is_empty() {
            return Ok(ApplyResult {
                revision: None,
                state: json!({"status": "absent", "unchanged": true}),
                journal: request.journal,
            });
        }
        return Err(PluginError::from(ComposePluginError::InvalidPlan(
            "destructive Compose plans must be executed through plugin.destroy".to_owned(),
        )));
    }
    progress(events, &request.context, "Resolving Compose deployment").await;
    let (document, inventory, revision) = resolve_compose(&desired, &request.context)
        .await
        .map_err(PluginError::from)?;
    validate_planned_document(&request.plan.metadata, &document, &revision)
        .map_err(PluginError::from)?;
    if request.plan.actions.is_empty() {
        return Ok(ApplyResult {
            revision: Some(revision.clone()),
            state: json!({
                "revision": revision,
                "capability": metadata.capability,
                "unchanged": true,
            }),
            journal: request.journal,
        });
    }

    let mut journal = request.journal.clone();
    let mut sequence = journal
        .iter()
        .map(|entry| entry.sequence)
        .max()
        .unwrap_or(0);
    for action in &request.plan.actions {
        sequence += 1;
        let entry = journal_entry(sequence, action, JournalStatus::Started, None);
        emit_journal(events, &request.context.operation_id, &entry).await?;
        journal.push(entry);
    }

    let result = apply_capability(
        &metadata.capability,
        &request.context,
        &desired,
        &config,
        &request.plan.metadata,
        &document,
        &inventory,
        &revision,
        events,
    )
    .await;
    match result {
        Ok((revision, state)) => {
            for action in &request.plan.actions {
                sequence += 1;
                let entry = journal_entry(
                    sequence,
                    action,
                    JournalStatus::Succeeded,
                    Some("action converged"),
                );
                emit_journal(events, &request.context.operation_id, &entry).await?;
                journal.push(entry);
            }
            Ok(ApplyResult {
                revision,
                state,
                journal,
            })
        }
        Err(error) => {
            if let Some(action) = request.plan.actions.last() {
                sequence += 1;
                let entry = journal_entry(
                    sequence,
                    action,
                    JournalStatus::Failed,
                    Some("action failed; safe details are in the structured error"),
                );
                emit_journal(events, &request.context.operation_id, &entry).await?;
            }
            Err(error.into())
        }
    }
}

fn validate_plan_integrity(
    plan: &PlanResult,
    metadata: &ContextMetadata,
) -> Result<(), ComposePluginError> {
    let expected_id = plan_id(&plan.metadata, &plan.actions, plan.has_changes);
    if plan.plan_id != expected_id {
        return Err(ComposePluginError::InvalidPlan(
            "plan_id does not match the plan payload".to_owned(),
        ));
    }
    if plan.metadata.get("schema").and_then(Value::as_u64) != Some(1) {
        return Err(ComposePluginError::InvalidPlan(
            "unsupported or missing plan schema".to_owned(),
        ));
    }
    if plan.metadata.get("capability")
        != Some(
            &serde_json::to_value(&metadata.capability)
                .map_err(ComposePluginError::Serialization)?,
        )
    {
        return Err(ComposePluginError::InvalidPlan(
            "plan capability does not match operation context".to_owned(),
        ));
    }
    if plan.metadata.get("operation")
        != Some(
            &serde_json::to_value(metadata.operation).map_err(ComposePluginError::Serialization)?,
        )
    {
        return Err(ComposePluginError::InvalidPlan(
            "plan operation does not match operation context".to_owned(),
        ));
    }
    if plan.actions.is_empty() && plan.has_changes {
        return Err(ComposePluginError::InvalidPlan(
            "an empty plan cannot claim provider changes".to_owned(),
        ));
    }
    Ok(())
}

fn validate_planned_document(
    plan_metadata: &Value,
    document: &Value,
    revision: &str,
) -> Result<(), ComposePluginError> {
    let expected_digest = plan_metadata
        .get("document_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ComposePluginError::InvalidPlan("plan has no Compose document digest".to_owned())
        })?;
    if expected_digest != digest_value(document) {
        return Err(ComposePluginError::InvalidPlan(
            "resolved Compose document changed after planning".to_owned(),
        ));
    }
    if plan_metadata.get("revision").and_then(Value::as_str) != Some(revision) {
        return Err(ComposePluginError::InvalidPlan(
            "deployment revision changed after planning".to_owned(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn apply_capability(
    capability: &Capability,
    context: &lightrail_plugin_protocol::OperationContext,
    desired: &DesiredState,
    config: &PluginConfig,
    plan_metadata: &Value,
    document: &Value,
    inventory: &compose_model::ComposeInventory,
    revision: &str,
    events: &EventSink,
) -> Result<(Option<String>, Value), ComposePluginError> {
    match capability {
        Capability::Source => Ok((
            Some(revision.to_owned()),
            json!({
                "revision": revision,
                "services": inventory.services.keys().collect::<Vec<_>>(),
                "compose_files": desired.project.compose,
            }),
        )),
        Capability::Builder => {
            if plan_metadata
                .get("images")
                .and_then(Value::as_object)
                .is_some_and(serde_json::Map::is_empty)
            {
                Ok((
                    Some(revision.to_owned()),
                    json!({"revision": revision, "images": {}}),
                ))
            } else {
                let target = ContextMetadata::from_context(context)?.target(Some(desired))?;
                progress(
                    events,
                    context,
                    "Building target-platform images with Buildx",
                )
                .await;
                let images =
                    build_and_transfer(desired, context, &target, document, inventory, revision)
                        .await?;
                Ok((
                    Some(revision.to_owned()),
                    json!({"revision": revision, "images": images}),
                ))
            }
        }
        Capability::Runtime => {
            let target = ContextMetadata::from_context(context)?.target(Some(desired))?;
            let environment = desired.resolve_app_environment(&context.secrets)?;
            let rendered = render_deployment(
                desired,
                document,
                inventory,
                &target,
                config,
                &environment,
                revision,
            )?;
            progress(events, context, "Deploying Compose and Traefik over SSH").await;
            let state = deploy(
                desired,
                &target,
                config,
                &rendered,
                revision,
                &context.operation_id,
            )
            .await?;
            Ok((Some(revision.to_owned()), state))
        }
        Capability::Exposure => {
            let target = ContextMetadata::from_context(context)?.target(Some(desired))?;
            progress(
                events,
                context,
                "Waiting for HTTPS certificates and application readiness",
            )
            .await;
            let endpoints = wait_for_endpoints(desired, &target, config).await?;
            Ok((
                Some(revision.to_owned()),
                json!({"revision": revision, "endpoints": endpoints}),
            ))
        }
        Capability::Dns => {
            let target = ContextMetadata::from_context(context)?.target(Some(desired))?;
            let endpoints = endpoints(desired, &target, config)?;
            Ok((
                Some(revision.to_owned()),
                json!({"revision": revision, "endpoints": endpoints}),
            ))
        }
        _ => Err(ComposePluginError::InvalidDesired(format!(
            "unsupported Compose capability `{capability}`"
        ))),
    }
}

async fn inspect_request(request: InspectRequest) -> Result<InspectResult, ComposePluginError> {
    let metadata = ContextMetadata::from_context(&request.context)?;
    require_supported_capability(&metadata.capability)?;
    if metadata.all {
        let project_id = project_id_from_context(&request.context)?;
        let config = PluginConfig::from_context(&request.context)?;
        let Some(target) = metadata.optional_target(None)? else {
            return Ok(InspectResult {
                status: ResourceStatus::Absent,
                endpoints: Vec::new(),
                state: json!({
                    "status": "absent",
                    "project_id": project_id,
                    "environments": []
                }),
                diagnostics: Vec::new(),
            });
        };
        return inspect_project(&target, &project_id, &config).await;
    }
    if matches!(
        metadata.capability,
        Capability::Source | Capability::Builder
    ) {
        return Ok(InspectResult {
            status: ResourceStatus::Unknown,
            endpoints: Vec::new(),
            state: json!({}),
            diagnostics: Vec::new(),
        });
    }
    let config = PluginConfig::from_context(&request.context)?;
    let Some(target) = metadata.optional_target(None)? else {
        return Ok(InspectResult {
            status: ResourceStatus::Absent,
            endpoints: Vec::new(),
            state: json!({
                "status": "absent",
                "environment_id": request.context.environment_id
            }),
            diagnostics: Vec::new(),
        });
    };
    let Some(manifest) = load_remote_manifest(&request.context, &target).await? else {
        let project_id = project_id_from_context(&request.context)?;
        return inspect_orphan_resources(&target, &project_id, &request.context.environment_id)
            .await;
    };
    validate_remote_manifest_identity(&request.context, &manifest.desired)?;
    let mut inspected = inspect_remote(&manifest.desired, &target, &config).await?;
    if let Some(state) = inspected.state.as_object_mut() {
        state.insert("revision".to_owned(), json!(manifest.revision));
        state.insert("images".to_owned(), manifest.images);
    }
    Ok(inspected)
}

fn project_id_from_context(
    context: &lightrail_plugin_protocol::OperationContext,
) -> Result<String, ComposePluginError> {
    context
        .metadata
        .get("project_id")
        .and_then(Value::as_str)
        .filter(|project_id| !project_id.trim().is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            ComposePluginError::InvalidDesired(
                "operation metadata must contain the immutable `project_id`".to_owned(),
            )
        })
}

fn validate_remote_manifest_identity(
    context: &lightrail_plugin_protocol::OperationContext,
    desired: &DesiredState,
) -> Result<(), ComposePluginError> {
    let expected_project_id = project_id_from_context(context)?;
    if desired.project.id != expected_project_id {
        return Err(ComposePluginError::InvalidDesired(
            "remote manifest project identity does not match immutable operation metadata"
                .to_owned(),
        ));
    }
    if desired.environment.id != context.environment_id {
        return Err(ComposePluginError::InvalidDesired(
            "remote manifest environment identity does not match its managed directory".to_owned(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn destroy_request(
    request: DestroyRequest,
    events: &EventSink,
) -> PluginResult<DestroyResult> {
    let metadata = ContextMetadata::from_context(&request.context).map_err(PluginError::from)?;
    require_supported_capability(&metadata.capability).map_err(PluginError::from)?;
    if metadata.capability != Capability::Runtime {
        return Ok(DestroyResult {
            destroyed: true,
            journal: request.journal,
            remaining: Vec::new(),
        });
    }
    let resolved_target = metadata.optional_target(None);
    if current_proves_absent(request.current.as_ref(), metadata.all)
        && matches!(&resolved_target, Ok(None))
    {
        return Ok(DestroyResult {
            destroyed: true,
            journal: request.journal,
            remaining: Vec::new(),
        });
    }
    let config = PluginConfig::from_context(&request.context).map_err(PluginError::from)?;
    let restoring_previous = metadata.operation == contract::Operation::Rollback;
    let action = action(
        if restoring_previous {
            "restore-previous-runtime"
        } else {
            "destroy-compose-environment"
        },
        if restoring_previous {
            "runtime.restore-previous"
        } else {
            "runtime.destroy"
        },
        if restoring_previous {
            "Restore the previous non-secret Compose revision"
        } else {
            "Remove only the selected Compose environment and its volumes"
        },
        !restoring_previous,
        Vec::new(),
        false,
    );
    let sequence = request
        .journal
        .iter()
        .map(|entry| entry.sequence)
        .max()
        .unwrap_or(0)
        + 1;
    let started = journal_entry(sequence, &action, JournalStatus::Started, None);
    emit_journal(events, &request.context.operation_id, &started).await?;
    let target = match resolved_target {
        Ok(Some(target)) => Some(target),
        Ok(None) | Err(_) if request.force => None,
        Ok(None) => {
            return Err(PluginError::from(ComposePluginError::InvalidTarget(
                "target state is unavailable for runtime cleanup".to_owned(),
            )));
        }
        Err(error) => return Err(PluginError::from(error)),
    };
    let cleanup_skipped = if let Some(target) = target {
        let result = if restoring_previous {
            let prior_revision = request
                .current
                .as_ref()
                .and_then(|current| current.get("revision"))
                .and_then(Value::as_str);
            restore_previous(&request.context, &target, &config, prior_revision).await
        } else {
            destroy_environment(
                &request.context,
                &target,
                &config,
                request.current.as_ref(),
                metadata.all,
            )
            .await
        };
        match result {
            Ok(()) => false,
            Err(error) if request.force && force_can_skip_cleanup_error(&error) => true,
            Err(error) => return Err(PluginError::from(error)),
        }
    } else {
        true
    };
    let succeeded = journal_entry(
        sequence + 1,
        &action,
        if cleanup_skipped {
            JournalStatus::Skipped
        } else {
            JournalStatus::Succeeded
        },
        Some(if cleanup_skipped {
            "forced destroy skipped unreachable runtime cleanup; the target plugin must remove the owning machine"
        } else if restoring_previous {
            "the previous non-secret Compose revision was restored"
        } else {
            "environment resources are absent; shared Traefik was preserved"
        }),
    );
    emit_journal(events, &request.context.operation_id, &succeeded).await?;
    let mut journal = request.journal;
    journal.extend([started, succeeded]);
    Ok(DestroyResult {
        destroyed: true,
        journal,
        remaining: Vec::new(),
    })
}

fn force_can_skip_cleanup_error(error: &ComposePluginError) -> bool {
    matches!(error, ComposePluginError::SshUnavailable { .. })
}

async fn logs_request(
    request: LogsRequest,
    events: &EventSink,
) -> Result<LogsResult, ComposePluginError> {
    let metadata = ContextMetadata::from_context(&request.context)?;
    let target = metadata.target(None)?;
    let records = fetch_logs(
        &request.context,
        &target,
        request.service.as_deref(),
        request.tail.unwrap_or(100),
    )
    .await?;
    let stream_id = request
        .follow
        .then(|| format!("compose-{}", request.context.operation_id));
    if let Some(stream_id) = stream_id.clone() {
        let mut lines = follow_logs(&request.context, target, request.service.clone()).await?;
        let events = events.clone();
        tokio::spawn(async move {
            while let Some(line) = lines.recv().await {
                let event = PluginEvent::Log {
                    stream_id: stream_id.clone(),
                    record: runtime::parse_log_line(&line),
                };
                if events.emit(&event).await.is_err() {
                    break;
                }
            }
        });
    }
    Ok(LogsResult { stream_id, records })
}

fn validate_context_identity(
    context: &lightrail_plugin_protocol::OperationContext,
    desired: &DesiredState,
) -> Result<(), ComposePluginError> {
    if context.environment_id != desired.environment.id {
        return Err(ComposePluginError::InvalidDesired(format!(
            "context environment `{}` does not match desired environment `{}`",
            context.environment_id, desired.environment.id
        )));
    }
    if context.profile != desired.environment.profile {
        return Err(ComposePluginError::InvalidDesired(format!(
            "context profile `{}` does not match desired profile `{}`",
            context.profile, desired.environment.profile
        )));
    }
    Ok(())
}

fn require_supported_capability(capability: &Capability) -> Result<(), ComposePluginError> {
    if matches!(
        capability,
        Capability::Source
            | Capability::Builder
            | Capability::Runtime
            | Capability::Exposure
            | Capability::Dns
    ) {
        Ok(())
    } else {
        Err(ComposePluginError::InvalidDesired(format!(
            "capability `{capability}` is not provided by this plugin"
        )))
    }
}

fn capability_needs_target(capability: &Capability) -> bool {
    matches!(
        capability,
        Capability::Builder | Capability::Runtime | Capability::Exposure | Capability::Dns
    )
}

fn digest_value(value: &Value) -> String {
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).unwrap_or_default())
    )
}

fn diagnostic_from_error(error: &ComposePluginError) -> Diagnostic {
    Diagnostic {
        severity: DiagnosticSeverity::Error,
        code: match error {
            ComposePluginError::HostNetwork { .. } => "host_network_forbidden",
            ComposePluginError::BindMount { .. } => "bind_mount_forbidden",
            ComposePluginError::MissingService(_) => "app_service_missing",
            _ => "invalid_compose_deployment",
        }
        .to_owned(),
        message: error.to_string(),
        path: None,
        help: Some(
            match error {
                ComposePluginError::HostNetwork { .. } => {
                    "remove `network_mode: host`; Lightrail supplies an isolated network"
                }
                ComposePluginError::BindMount { .. } => {
                    "put application source in its image; named volumes remain supported"
                }
                _ => "correct the project/profile configuration and retry validation",
            }
            .to_owned(),
        ),
    }
}

fn journal_entry(
    sequence: u64,
    action: &PlannedAction,
    status: JournalStatus,
    message: Option<&str>,
) -> ActionJournalEntry {
    ActionJournalEntry {
        sequence,
        action_id: action.id.clone(),
        status,
        timestamp: None,
        message: message.map(ToOwned::to_owned),
        rollback: action.rollback.clone(),
        metadata: json!({}),
    }
}

async fn emit_journal(
    events: &EventSink,
    operation_id: &str,
    entry: &ActionJournalEntry,
) -> PluginResult<()> {
    events
        .emit(&PluginEvent::Journal {
            operation_id: operation_id.to_owned(),
            entry: entry.clone(),
        })
        .await
        .map_err(|error| {
            PluginError::permanent(
                lightrail_plugin_protocol::ErrorKind::Internal,
                "event_transport",
                format!("could not emit action journal: {error}"),
            )
        })
}

async fn progress(
    events: &EventSink,
    context: &lightrail_plugin_protocol::OperationContext,
    message: &str,
) {
    let _ = events
        .emit(&PluginEvent::Progress {
            operation_id: context.operation_id.clone(),
            message: message.to_owned(),
            completed: None,
            total: None,
        })
        .await;
}

fn config_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "dns_domain": {
                "type": "string",
                "enum": ["sslip.io", "nip.io"],
                "default": "sslip.io"
            },
            "acme_email": {
                "type": ["string", "null"],
                "format": "email"
            },
            "ingress_image": {
                "type": "string",
                "default": "traefik:v3.7.8"
            },
            "ingress_network": {
                "type": "string",
                "default": "lightrail-ingress"
            },
            "certificate_resolver": {
                "type": "string",
                "default": "letsencrypt"
            },
            "readiness_timeout_seconds": {
                "type": "integer",
                "minimum": 1,
                "default": 300
            },
            "stable_window_seconds": {
                "type": "integer",
                "minimum": 0,
                "default": 10
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_declares_all_compose_pipeline_capabilities() {
        let manifest = ComposePlugin.manifest();
        assert_eq!(manifest.id, PLUGIN_ID);
        for capability in [
            Capability::Source,
            Capability::Builder,
            Capability::Runtime,
            Capability::Exposure,
            Capability::Dns,
        ] {
            assert!(manifest.capabilities.contains(&capability));
        }
        assert!(!manifest.capabilities.contains(&Capability::Target));
        assert_eq!(manifest.required_secrets[0].name, "*");
        assert!(!manifest.required_secrets[0].required);
    }

    #[test]
    fn plan_ids_are_stable_for_equal_json() {
        let value = json!({"a": 1, "b": [2, 3]});
        assert_eq!(digest_value(&value), digest_value(&value));
    }

    #[test]
    fn runtime_destroy_is_a_visible_destructive_plan() {
        let desired = DesiredState::parse(json!({
            "schema": 1,
            "project": {
                "id": "project-id",
                "slug": "project",
                "root": "/workspace",
                "compose": ["compose.yaml"]
            },
            "environment": {
                "id": "lr-environment",
                "profile": "preview",
                "branch": "main",
                "isolation": "project"
            },
            "destroy": true
        }))
        .expect("destroy desired");
        let actions = planned_actions(
            &Capability::Runtime,
            &desired,
            &compose_model::ComposeInventory {
                services: BTreeMap::new(),
            },
            false,
        );

        assert_eq!(actions.len(), 1);
        assert!(actions[0].destructive);
        assert_eq!(actions[0].kind, "runtime.destroy");
    }

    #[test]
    fn absent_current_state_makes_runtime_destroy_a_noop() {
        assert!(current_proves_absent(
            Some(&json!({"status": "absent"})),
            false
        ));
        assert!(current_proves_absent(
            Some(&json!({"environments": []})),
            true
        ));
        assert!(!current_proves_absent(
            Some(&json!({"containers": []})),
            false
        ));

        let desired = DesiredState::parse(json!({
            "schema": 1,
            "project": {
                "id": "project-id",
                "slug": "project",
                "root": "/workspace",
                "compose": ["compose.yaml"]
            },
            "environment": {
                "id": "lr-environment",
                "profile": "preview",
                "branch": "main",
                "isolation": "project"
            },
            "destroy": true
        }))
        .expect("destroy desired");
        assert!(
            planned_actions(
                &Capability::Runtime,
                &desired,
                &compose_model::ComposeInventory {
                    services: BTreeMap::new(),
                },
                true,
            )
            .is_empty()
        );
    }

    #[test]
    fn project_identity_comes_from_operation_metadata() {
        let context = lightrail_plugin_protocol::OperationContext {
            metadata: json!({"project_id": "immutable-project-id"}),
            ..lightrail_plugin_protocol::OperationContext::default()
        };
        assert_eq!(
            project_id_from_context(&context).expect("project id"),
            "immutable-project-id"
        );

        let missing = lightrail_plugin_protocol::OperationContext::default();
        assert!(project_id_from_context(&missing).is_err());
    }

    #[test]
    fn remote_manifest_identity_must_match_immutable_context() {
        let context = lightrail_plugin_protocol::OperationContext {
            environment_id: "lr-environment".to_owned(),
            metadata: json!({"project_id": "immutable-project-id"}),
            ..lightrail_plugin_protocol::OperationContext::default()
        };
        let desired = DesiredState::parse(json!({
            "schema": 1,
            "project": {
                "id": "immutable-project-id",
                "slug": "project",
                "root": "/workspace",
                "compose": ["compose.yaml"]
            },
            "environment": {
                "id": "lr-environment",
                "profile": "preview",
                "branch": "main",
                "isolation": "project"
            }
        }))
        .expect("manifest desired");
        assert!(validate_remote_manifest_identity(&context, &desired).is_ok());

        let mut wrong_project = desired.clone();
        wrong_project.project.id = "another-project".to_owned();
        assert!(
            validate_remote_manifest_identity(&context, &wrong_project).is_err(),
            "inspection and destruction must reject a foreign project manifest"
        );

        let mut wrong_environment = desired;
        wrong_environment.environment.id = "lr-another".to_owned();
        assert!(validate_remote_manifest_identity(&context, &wrong_environment).is_err());
    }

    #[test]
    fn force_never_swallows_identity_validation_failures() {
        assert!(!force_can_skip_cleanup_error(
            &ComposePluginError::InvalidDesired(
                "remote manifest project identity does not match immutable operation metadata"
                    .to_owned()
            )
        ));
        assert!(force_can_skip_cleanup_error(
            &ComposePluginError::SshUnavailable {
                operation: "remote cleanup".to_owned()
            }
        ));
    }

    #[test]
    fn apply_rejects_tampered_plan_payloads() {
        let metadata = ContextMetadata {
            capability: Capability::Runtime,
            operation: contract::Operation::Up,
            target: Value::Null,
            all: false,
        };
        let action = action(
            "deploy",
            "runtime.compose",
            "deploy",
            false,
            Vec::new(),
            false,
        );
        let mut plan = finalize_plan(
            vec![action],
            true,
            json!({
                "schema": 1,
                "capability": "runtime",
                "operation": "up",
                "desired": {},
            }),
        );
        assert!(validate_plan_integrity(&plan, &metadata).is_ok());

        plan.actions[0].kind = "runtime.injected".to_owned();
        assert!(validate_plan_integrity(&plan, &metadata).is_err());
    }

    #[test]
    fn apply_rejects_changed_compose_document_or_revision() {
        let document = json!({"services": {"web": {"image": "example/web:1"}}});
        let metadata = json!({
            "document_digest": digest_value(&document),
            "revision": "revision-one",
        });
        assert!(validate_planned_document(&metadata, &document, "revision-one").is_ok());
        assert!(
            validate_planned_document(
                &metadata,
                &json!({"services": {"web": {"image": "example/web:2"}}}),
                "revision-one",
            )
            .is_err()
        );
        assert!(validate_planned_document(&metadata, &document, "revision-two").is_err());
    }
}
