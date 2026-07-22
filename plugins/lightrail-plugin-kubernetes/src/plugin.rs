use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    future::Future,
    net::{IpAddr, ToSocketAddrs},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use futures::future::try_join_all;
use lightrail_plugin_protocol::{
    ActionJournalEntry, ApplyRequest, ApplyResult, CancelRequest, CancelResult, Capability,
    DestroyRequest, DestroyResult, Diagnostic, DiagnosticSeverity, Endpoint, ErrorKind, EventSink,
    ExecutableMetadata, InspectRequest, InspectResult, JournalStatus, LockAcquireRequest,
    LockAcquireResult, LockReleaseRequest, LockReleaseResult, LogRecord, LogsRequest, LogsResult,
    PlanRequest, PlanResult, PlannedAction, Platform, PluginError, PluginEvent, PluginHandler,
    PluginManifest, PluginResult, ProtocolCompatibility, ResourceStatus, RollbackMetadata,
    SecretRequirement, ValidateRequest, ValidateResult,
};
use reqwest::{Client, StatusCode, Url, header::LOCATION, redirect::Policy};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::{
    sync::RwLock,
    time::{sleep, timeout},
};

use crate::{
    PLUGIN_ID,
    command::{CancellationRegistry, kubectl, kubectl_json, run},
    config::{Settings, config_schema},
    lock::LeaseLocks,
    model::{
        BuildSpec, CONTROL_NAMESPACE_ANNOTATION, ComposeProject, ContextMetadata, DesiredState,
        ENVIRONMENT_LABEL, EXPIRES_AT_ANNOTATION, MANAGED_LABEL, Operation, PROFILE_LABEL,
        PROJECT_LABEL, ReadinessTarget, RenderedEnvironment, RenderedResource, ResourceRole,
        build_specs, expiry_unix, manifest_list, namespace_name, render_environment, revision,
    },
};

const SELECTED_DESTROY_FEATURE: &str = "dev.lightrail.selected-destroy.v1";

/// Kubernetes executable-plugin implementation.
pub struct KubernetesPlugin {
    settings: RwLock<HashMap<String, Settings>>,
    expiries: RwLock<HashMap<String, u64>>,
    cancellations: CancellationRegistry,
    locks: LeaseLocks,
}

impl Default for KubernetesPlugin {
    fn default() -> Self {
        let cancellations = CancellationRegistry::default();
        Self {
            settings: RwLock::default(),
            expiries: RwLock::default(),
            locks: LeaseLocks::new(cancellations.clone()),
            cancellations,
        }
    }
}

#[async_trait]
impl PluginHandler for KubernetesPlugin {
    fn manifest(&self) -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID.to_owned(),
            name: "Lightrail Kubernetes".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            protocol: ProtocolCompatibility::default(),
            executable: ExecutableMetadata {
                command: Some("lightrail-plugin-kubernetes".to_owned()),
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
                name: "*".to_owned(),
                description: Some(
                    "Only application environment secrets explicitly referenced by lightrail.toml"
                        .to_owned(),
                ),
                required: false,
            }],
            config_schema: config_schema(),
            config_ui_hints: json!({
                "/kubeconfig": {"widget": "file"},
                "/context": {
                    "label": "Existing kubeconfig context",
                    "help": "Lightrail never creates or resizes the cluster"
                },
                "/registry": {"label": "OCI registry host"},
                "/repository": {"label": "OCI repository prefix"},
                "/ingress_class": {"label": "Existing IngressClass"},
                "/ingress_service_namespace": {
                    "label": "Ingress Service namespace",
                    "help": "Exact namespace of the controller's existing LoadBalancer Service"
                },
                "/ingress_service_name": {
                    "label": "Ingress Service name",
                    "help": "Exact name of the controller's existing LoadBalancer Service"
                }
            }),
        }
    }

    async fn validate(
        &self,
        request: ValidateRequest,
        _events: &EventSink,
    ) -> PluginResult<ValidateResult> {
        match self.validate_inner(&request).await {
            Ok((settings, diagnostics)) => {
                self.settings
                    .write()
                    .await
                    .insert(request.context.environment_id.clone(), settings.clone());
                Ok(ValidateResult {
                    valid: !diagnostics
                        .iter()
                        .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error),
                    diagnostics,
                    normalized_config: Some(settings.normalized_value()),
                })
            }
            Err(error) => Ok(ValidateResult {
                valid: false,
                diagnostics: vec![Diagnostic {
                    severity: DiagnosticSeverity::Error,
                    code: error.code,
                    message: error.message,
                    path: None,
                    help: None,
                }],
                normalized_config: None,
            }),
        }
    }

    async fn inspect(
        &self,
        request: InspectRequest,
        _events: &EventSink,
    ) -> PluginResult<InspectResult> {
        let settings = self.remember_settings(&request.context).await?;
        let metadata = ContextMetadata::parse(&request.context)?;
        require_capability(&metadata.capability)?;
        if metadata.operation == Operation::Prune {
            metadata.selection.validate_prune()?;
        }
        match metadata.capability {
            Capability::Target => {
                self.inspect_target(&settings, &request.context, &metadata)
                    .await
            }
            Capability::Builder => Ok(InspectResult {
                status: ResourceStatus::Ready,
                endpoints: Vec::new(),
                state: json!({
                    "provider": "kubernetes",
                    "registry": settings.registry,
                    "repository": settings.repository,
                }),
                diagnostics: Vec::new(),
            }),
            Capability::Runtime | Capability::Exposure | Capability::Dns => {
                self.inspect_workloads(&settings, &request.context, &metadata)
                    .await
            }
            _ => Err(PluginError::unsupported("plugin.inspect")),
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn plan(&self, request: PlanRequest, _events: &EventSink) -> PluginResult<PlanResult> {
        let settings = self.remember_settings(&request.context).await?;
        let metadata = ContextMetadata::parse(&request.context)?;
        require_capability(&metadata.capability)?;
        ensure_control_namespace_continuity(request.current.as_ref(), &settings.control_namespace)?;
        if metadata.operation == Operation::Prune {
            metadata.selection.validate_prune()?;
            if metadata.capability != Capability::Target {
                return finalize_plan(
                    Vec::new(),
                    json!({
                        "schema": 1,
                        "capability": metadata.capability,
                        "selection": metadata.selection,
                    }),
                );
            }
            let selected = prune_namespaces_from_current(
                request.current.as_ref(),
                &metadata.selection.environment_ids,
            )?;
            let actions = selected
                .iter()
                .map(|(namespace, environment_id)| PlannedAction {
                    id: format!("delete-namespace-{namespace}"),
                    kind: "kubernetes.delete-namespace".to_owned(),
                    summary: format!("Delete expired Lightrail environment namespace {namespace}"),
                    destructive: true,
                    depends_on: Vec::new(),
                    rollback: Some(namespace_delete_rollback(namespace)),
                    metadata: json!({
                        "namespace": namespace,
                        "environment_id": environment_id,
                    }),
                })
                .collect();
            return finalize_plan(
                actions,
                json!({
                    "schema": 1,
                    "capability": "target",
                    "operation": "prune",
                    "selection": metadata.selection,
                }),
            );
        }

        let desired = DesiredState::parse(request.desired.clone(), &request.context)?;
        if metadata.capability == Capability::Target {
            return finalize_plan(
                Vec::new(),
                json!({
                    "schema": 1,
                    "capability": "target",
                    "existing_cluster": true,
                    "provisioning": false,
                    "desired": request.desired,
                }),
            );
        }

        if desired.destroy || metadata.operation == Operation::Destroy {
            return match metadata.capability {
                Capability::Exposure | Capability::Dns => finalize_plan(
                    Vec::new(),
                    json!({
                        "schema": 1,
                        "capability": metadata.capability,
                        "operation": "destroy",
                        "namespace_owned": true,
                        "desired": request.desired,
                    }),
                ),
                Capability::Runtime => {
                    let namespaces =
                        destroy_namespaces_from_current(request.current.as_ref(), metadata.all);
                    let actions = namespaces
                        .iter()
                        .map(|(namespace, environment_id)| PlannedAction {
                            id: format!("delete-namespace-{namespace}"),
                            kind: "kubernetes.delete-namespace".to_owned(),
                            summary: format!(
                                "Delete owned Kubernetes environment namespace {namespace}"
                            ),
                            destructive: true,
                            depends_on: Vec::new(),
                            rollback: Some(namespace_delete_rollback(namespace)),
                            metadata: json!({
                                "namespace": namespace,
                                "environment_id": environment_id,
                            }),
                        })
                        .collect();
                    finalize_plan(
                        actions,
                        json!({
                            "schema": 1,
                            "capability": "runtime",
                            "operation": "destroy",
                            "all": metadata.all,
                            "desired": request.desired,
                        }),
                    )
                }
                _ => Err(PluginError::permanent(
                    ErrorKind::Unsupported,
                    "destroy_capability_unsupported",
                    format!(
                        "Kubernetes capability `{}` does not own destruction",
                        metadata.capability
                    ),
                )),
            };
        }

        let compose = ComposeProject::load(&desired).await?;
        compose.validate(&desired)?;
        let build_platforms = effective_build_platforms(&settings, &metadata.target, &compose)?;
        let revision = revision(
            &desired,
            &compose,
            &build_platforms,
            &request.context,
            &request.context.operation_id,
        )?;
        if metadata.capability == Capability::Builder {
            let builds = build_specs(&settings, &desired, &compose, &request.context, &revision)?;
            let actions = builds
                .iter()
                .map(|build| PlannedAction {
                    id: format!("build-push-{}", safe_action_component(&build.service)),
                    kind: "kubernetes.build-push".to_owned(),
                    summary: format!(
                        "Build service {} locally and push {}",
                        build.service, build.image
                    ),
                    destructive: false,
                    depends_on: Vec::new(),
                    rollback: Some(RollbackMetadata {
                        supported: false,
                        action: None,
                        token: None,
                        metadata: json!({
                            "reason": "pushed OCI image tags and registry layers are intentionally retained"
                        }),
                    }),
                    metadata: json!({
                        "service": build.service,
                        "image": build.image,
                    }),
                })
                .collect();
            return finalize_plan(
                actions,
                json!({
                    "schema": 1,
                    "capability": "builder",
                    "desired": request.desired,
                    "revision": revision,
                    "platforms": build_platforms,
                }),
            );
        }
        if metadata.capability == Capability::Dns {
            let expiry = self
                .operation_expiry(&request.context.operation_id, settings.ttl_hours)
                .await?;
            let prior_expiry = request
                .current
                .as_ref()
                .and_then(|state| state.get("expires_at_unix"))
                .cloned()
                .unwrap_or(Value::Null);
            let namespace =
                namespace_name(&settings.namespace_prefix, &request.context.environment_id);
            ensure_namespace_continuity(request.current.as_ref(), &namespace)?;
            return finalize_plan(
                vec![PlannedAction {
                    id: "refresh-environment-expiry".to_owned(),
                    kind: "kubernetes.refresh-expiry".to_owned(),
                    summary: format!("Refresh expiry metadata on Kubernetes namespace {namespace}"),
                    destructive: false,
                    depends_on: Vec::new(),
                    rollback: Some(RollbackMetadata {
                        supported: true,
                        action: Some("dns.restore-expiry".to_owned()),
                        token: None,
                        metadata: json!({
                            "namespace": namespace,
                            "prior_expiry": prior_expiry,
                            "attempted_expiry": expiry,
                        }),
                    }),
                    metadata: json!({
                        "namespace": namespace,
                        "expires_at_unix": expiry,
                    }),
                }],
                json!({
                    "schema": 1,
                    "capability": "dns",
                    "desired": request.desired,
                    "revision": revision,
                    "namespace": namespace,
                    "expires_at_unix": expiry,
                }),
            );
        }

        let rendered = render_environment(
            &settings,
            &desired,
            &compose,
            &request.context,
            &metadata,
            &revision,
            false,
        )?;
        ensure_namespace_continuity(request.current.as_ref(), &rendered.namespace)?;
        let role = capability_role(&metadata.capability)?;
        let current_resources = request
            .current
            .as_ref()
            .and_then(|state| state.get("resources"))
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let desired_resources = rendered
            .resources
            .iter()
            .filter(|resource| resource.role == role)
            .map(|resource| (resource.key.clone(), resource))
            .collect::<BTreeMap<_, _>>();
        let prior_revision = request
            .current
            .as_ref()
            .and_then(|state| state.get("revision"))
            .and_then(Value::as_str);
        let prior_exposure_manifests = request
            .current
            .as_ref()
            .and_then(|state| state.get("exposure_manifests"))
            .and_then(Value::as_object);
        ensure_no_stale_resources(&current_resources, &desired_resources, role)?;
        let namespace_needs_apply = metadata.capability == Capability::Runtime
            && !current_resources.contains_key(&format!("Namespace/{}", rendered.namespace));
        if metadata.capability == Capability::Runtime {
            ensure_no_runtime_additions(&current_resources, &desired_resources, prior_revision)?;
        }
        let mut actions = Vec::new();
        for resource in desired_resources.values() {
            let observed = current_resources.get(&resource.key).and_then(Value::as_str);
            // Expiry is refreshed only by the final DNS capability. Reapplying an
            // existing Namespace here would let server-side apply remove the
            // previous expiry before the rest of `up` has succeeded.
            if resource.kind == "Namespace" && observed.is_some() {
                actions.push(PlannedAction {
                    id: format!("reconcile-namespace-metadata-{}", resource.name),
                    kind: "kubernetes.reconcile-namespace-metadata".to_owned(),
                    summary: format!(
                        "Reconcile identity metadata on Kubernetes Namespace {}",
                        resource.name
                    ),
                    destructive: false,
                    depends_on: Vec::new(),
                    rollback: Some(RollbackMetadata {
                        supported: false,
                        action: None,
                        token: None,
                        metadata: json!({
                            "resource_key": resource.key,
                            "reason": "exact prior Namespace metadata is not retained",
                        }),
                    }),
                    metadata: json!({
                        "resource_key": resource.key,
                        "spec_hash": resource.spec_hash,
                        "namespace": rendered.namespace,
                    }),
                });
                continue;
            }
            if resource.kind == "Job" && !job_needs_create(resource, observed)? {
                continue;
            }
            let rollback = rollback_for_resource(
                &metadata.capability,
                resource,
                &rendered.namespace,
                prior_exposure_manifests,
                observed.is_some(),
            );
            actions.push(PlannedAction {
                id: format!(
                    "apply-{}-{}",
                    resource.kind.to_ascii_lowercase(),
                    resource.name
                ),
                kind: "kubernetes.apply".to_owned(),
                summary: format!("Reconcile Kubernetes {} {}", resource.kind, resource.name),
                destructive: false,
                depends_on: dependencies(resource, &rendered.resources, namespace_needs_apply),
                rollback,
                metadata: json!({
                    "resource_key": resource.key,
                    "spec_hash": resource.spec_hash,
                    "namespace": rendered.namespace,
                }),
            });
        }
        finalize_plan(
            actions,
            json!({
                "schema": 1,
                "capability": metadata.capability,
                "desired": request.desired,
                "revision": revision,
                "namespace": rendered.namespace,
                "endpoints": rendered.endpoints,
            }),
        )
    }

    async fn apply(&self, request: ApplyRequest, events: &EventSink) -> PluginResult<ApplyResult> {
        validate_plan_digest(&request.plan)?;
        let settings = self.remember_settings(&request.context).await?;
        let metadata = ContextMetadata::parse(&request.context)?;
        require_capability(&metadata.capability)?;
        let guard = self.cancellations.begin(&request.context.operation_id);
        match metadata.capability {
            Capability::Target => Self::apply_target(request),
            Capability::Builder => {
                self.locks
                    .assert_authority(&settings, &request.context.operation_id)
                    .await?;
                self.apply_builder(&settings, request, events, guard.state())
                    .await
            }
            Capability::Runtime | Capability::Exposure => {
                self.locks
                    .assert_authority(&settings, &request.context.operation_id)
                    .await?;
                self.apply_resources(&settings, request, events, guard.state())
                    .await
            }
            Capability::Dns => {
                self.locks
                    .assert_authority(&settings, &request.context.operation_id)
                    .await?;
                self.apply_dns(&settings, request, events, guard.state())
                    .await
            }
            _ => Err(PluginError::unsupported("plugin.apply")),
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn destroy(
        &self,
        request: DestroyRequest,
        events: &EventSink,
    ) -> PluginResult<DestroyResult> {
        if request.force {
            return Err(PluginError::permanent(
                ErrorKind::Unsupported,
                "kubernetes_force_destroy_unsupported",
                "Kubernetes namespace deletion requires its authoritative Lease and never supports --force",
            ));
        }
        let settings = self.remember_settings(&request.context).await?;
        let metadata = ContextMetadata::parse(&request.context)?;
        require_capability(&metadata.capability)?;
        let guard = self.cancellations.begin(&request.context.operation_id);

        if metadata.operation == Operation::Prune {
            if metadata.capability != Capability::Target {
                return Err(PluginError::permanent(
                    ErrorKind::Validation,
                    "prune_target_required",
                    "selected Kubernetes prune is owned by the target capability",
                ));
            }
            metadata.selection.validate_prune()?;
            let selected = prune_namespaces_from_current(
                request.current.as_ref(),
                &metadata.selection.environment_ids,
            )?;
            let mut journal = request.journal;
            let mut remaining = Vec::new();
            for (namespace, environment_id) in selected {
                self.locks
                    .assert_authority(&settings, &request.context.operation_id)
                    .await?;
                if !delete_namespace_exact(
                    &settings,
                    &namespace,
                    &metadata.project_id,
                    &environment_id,
                    guard.state(),
                )
                .await?
                {
                    remaining.push(namespace.clone());
                }
                let absent = !remaining.contains(&namespace);
                let entry = journal_entry(
                    journal.len() as u64 + 1,
                    &format!("delete-namespace-{namespace}"),
                    if absent {
                        JournalStatus::Succeeded
                    } else {
                        JournalStatus::Failed
                    },
                    if absent {
                        "Expired Kubernetes environment namespace deleted"
                    } else {
                        "Expired Kubernetes environment namespace remained after deletion"
                    },
                );
                emit_journal(events, &request.context.operation_id, &entry).await?;
                journal.push(entry);
            }
            self.locks
                .assert_authority(&settings, &request.context.operation_id)
                .await?;
            return Ok(DestroyResult {
                destroyed: remaining.is_empty(),
                journal,
                remaining,
            });
        }

        match metadata.capability {
            Capability::Target => Ok(DestroyResult {
                destroyed: true,
                journal: append_skipped(
                    request.journal,
                    "retain-existing-cluster",
                    "Retained existing Kubernetes cluster and nodes",
                ),
                remaining: Vec::new(),
            }),
            Capability::Builder => Ok(DestroyResult {
                destroyed: true,
                journal: append_skipped(
                    request.journal,
                    "retain-registry-images",
                    "Retained immutable OCI images for registry retention policy",
                ),
                remaining: Vec::new(),
            }),
            Capability::Exposure if metadata.operation == Operation::Rollback => {
                self.locks
                    .assert_authority(&settings, &request.context.operation_id)
                    .await?;
                self.rollback_exposure(&settings, &request, guard.state())
                    .await
            }
            Capability::Dns if metadata.operation == Operation::Rollback => {
                self.locks
                    .assert_authority(&settings, &request.context.operation_id)
                    .await?;
                self.rollback_dns(&settings, &request, guard.state()).await
            }
            Capability::Exposure | Capability::Dns => Ok(DestroyResult {
                destroyed: true,
                journal: append_skipped(
                    request.journal,
                    "namespace-owned-exposure",
                    "Ingress resources remain scoped to runtime namespace deletion",
                ),
                remaining: Vec::new(),
            }),
            Capability::Runtime if metadata.operation == Operation::Rollback => {
                self.locks
                    .assert_authority(&settings, &request.context.operation_id)
                    .await?;
                Self::rollback_runtime(&settings, &request, guard.state())
            }
            Capability::Runtime => {
                self.locks
                    .assert_authority(&settings, &request.context.operation_id)
                    .await?;
                self.destroy_runtime(&settings, &request, &metadata, events, guard.state())
                    .await
            }
            _ => Err(PluginError::unsupported("plugin.destroy")),
        }
    }

    async fn cancel(
        &self,
        request: CancelRequest,
        _events: &EventSink,
    ) -> PluginResult<CancelResult> {
        Ok(CancelResult {
            acknowledged: self.cancellations.cancel(&request.operation_id),
        })
    }

    async fn lock_acquire(
        &self,
        request: LockAcquireRequest,
        _events: &EventSink,
    ) -> PluginResult<LockAcquireResult> {
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
                    "validate or inspect the Kubernetes target before acquiring its Lease",
                )
            })?;
        self.locks.acquire(&settings, request).await
    }

    async fn lock_release(
        &self,
        request: LockReleaseRequest,
        _events: &EventSink,
    ) -> PluginResult<LockReleaseResult> {
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
                    "Kubernetes target settings are unavailable for Lease release",
                )
            })?;
        self.locks.release(&settings, request).await
    }

    async fn logs(&self, request: LogsRequest, _events: &EventSink) -> PluginResult<LogsResult> {
        if request.follow {
            return Err(PluginError::permanent(
                ErrorKind::Unsupported,
                "kubernetes_follow_logs_deferred",
                "Kubernetes historical logs are implemented; live follow needs a streaming subprocess protocol adapter",
            ));
        }
        let settings = self.remember_settings(&request.context).await?;
        let metadata = ContextMetadata::parse(&request.context)?;
        let namespace = namespace_name(&settings.namespace_prefix, &request.context.environment_id);
        let mut selector = format!("{ENVIRONMENT_LABEL}={}", request.context.environment_id);
        if let Some(service) = &request.service {
            selector.push_str(&format!(",lightrail.dev/service={}", model_label(service)));
        }
        let output = kubectl(
            &settings,
            &[
                "logs".to_owned(),
                "--namespace".to_owned(),
                namespace,
                "--selector".to_owned(),
                selector,
                "--all-containers=true".to_owned(),
                "--prefix=true".to_owned(),
                "--tail".to_owned(),
                request.tail.unwrap_or(100).to_string(),
            ],
            None,
            settings.command_timeout(),
            None,
        )
        .await?;
        let service = request.service.unwrap_or_else(|| "kubernetes".to_owned());
        let records = String::from_utf8_lossy(&output)
            .lines()
            .map(|line| LogRecord {
                service: service.clone(),
                timestamp: None,
                line: line.to_owned(),
                stream: Some("stdout".to_owned()),
            })
            .collect();
        let _ = metadata;
        Ok(LogsResult {
            stream_id: None,
            records,
        })
    }
}

impl KubernetesPlugin {
    async fn validate_inner(
        &self,
        request: &ValidateRequest,
    ) -> PluginResult<(Settings, Vec<Diagnostic>)> {
        let settings = Settings::parse(&request.context).map_err(|issue| issue.plugin_error())?;
        let metadata = ContextMetadata::parse(&request.context)?;
        require_capability(&metadata.capability)?;
        if metadata.operation == Operation::Prune {
            metadata.selection.validate_prune()?;
        }
        let desired = DesiredState::parse(request.desired.clone(), &request.context)?;
        if matches!(
            metadata.capability,
            Capability::Builder | Capability::Runtime | Capability::Exposure | Capability::Dns
        ) && !desired.destroy
        {
            let compose = ComposeProject::load(&desired).await?;
            compose.validate(&desired)?;
            let build_platforms = effective_build_platforms(&settings, &metadata.target, &compose)?;
            let revision = revision(
                &desired,
                &compose,
                &build_platforms,
                &request.context,
                &request.context.operation_id,
            )?;
            let _ = build_specs(&settings, &desired, &compose, &request.context, &revision)?;
            if matches!(metadata.capability, Capability::Exposure | Capability::Dns)
                && !desired.apps.is_empty()
                && crate::model::ingress_ipv4(&metadata.target).is_none()
            {
                return Err(PluginError::permanent(
                    ErrorKind::Unavailable,
                    "ingress_ipv4_unavailable",
                    "the existing ingress controller must expose a public IPv4 for IP-derived sslip.io/nip.io routing",
                ));
            }
        }
        let diagnostics = if metadata.capability == Capability::Target {
            let facts = target_facts(&settings).await?;
            facts.diagnostics
        } else {
            Vec::new()
        };
        Ok((settings, diagnostics))
    }

    async fn remember_settings(
        &self,
        context: &lightrail_plugin_protocol::OperationContext,
    ) -> PluginResult<Settings> {
        let settings = Settings::parse(context).map_err(|issue| issue.plugin_error())?;
        self.settings
            .write()
            .await
            .insert(context.environment_id.clone(), settings.clone());
        Ok(settings)
    }

    async fn operation_expiry(&self, operation_id: &str, ttl_hours: u64) -> PluginResult<u64> {
        if let Some(expiry) = self.expiries.read().await.get(operation_id).copied() {
            return Ok(expiry);
        }
        let expiry = expiry_unix(ttl_hours)?;
        let mut expiries = self.expiries.write().await;
        Ok(*expiries.entry(operation_id.to_owned()).or_insert(expiry))
    }

    async fn inspect_target(
        &self,
        settings: &Settings,
        context: &lightrail_plugin_protocol::OperationContext,
        metadata: &ContextMetadata,
    ) -> PluginResult<InspectResult> {
        let facts = target_facts(settings).await?;
        let namespace = namespace_name(&settings.namespace_prefix, &context.environment_id);
        let mut state = json!({
            "kind": "kubernetes",
            "provider": "kubernetes",
            "existing_cluster": true,
            "provisioning": false,
            "context": settings.context,
            "namespace": namespace,
            "control_namespace": settings.control_namespace,
            "isolation": "environment",
            "platforms": facts.platforms,
            "ingress": {
                "class": settings.ingress_class,
                "controller": facts.ingress_controller,
                "service_namespace": settings.ingress_service_namespace,
                "service_name": settings.ingress_service_name,
                "addresses": facts.ingress_addresses,
                "traefik_middleware_api_version": facts.traefik_middleware_api_version,
            }
        });
        if metadata.all || metadata.operation == Operation::Prune {
            let namespaces = self
                .selected_namespaces(settings, metadata, metadata.operation == Operation::Prune)
                .await?;
            state["environment_contract"] = json!(1);
            state["environments"] = Value::Array(
                namespaces
                    .into_iter()
                    .map(|namespace| namespace.environment_value())
                    .collect(),
            );
        }
        Ok(InspectResult {
            status: ResourceStatus::Ready,
            endpoints: Vec::new(),
            state,
            diagnostics: facts.diagnostics,
        })
    }

    async fn inspect_workloads(
        &self,
        settings: &Settings,
        context: &lightrail_plugin_protocol::OperationContext,
        metadata: &ContextMetadata,
    ) -> PluginResult<InspectResult> {
        if metadata.all {
            let namespaces = self.selected_namespaces(settings, metadata, false).await?;
            let mut environments = Vec::new();
            let mut endpoints = Vec::new();
            let mut aggregate = ResourceStatus::Absent;
            for namespace in namespaces {
                let inspection = inspect_namespace(
                    settings,
                    &namespace.name,
                    &namespace.environment_id,
                    &metadata.project_id,
                    &metadata.target,
                    settings.command_timeout(),
                )
                .await?;
                aggregate = combine_status(aggregate, inspection.status);
                endpoints.extend(inspection.endpoints.clone());
                let mut environment = namespace.environment_value();
                environment["status"] =
                    serde_json::to_value(inspection.status).map_err(serialization_error)?;
                environment["endpoints"] =
                    serde_json::to_value(inspection.endpoints).map_err(serialization_error)?;
                environments.push(environment);
            }
            return Ok(InspectResult {
                status: aggregate,
                endpoints,
                state: json!({"environments": environments}),
                diagnostics: Vec::new(),
            });
        }
        let expected_namespace =
            namespace_name(&settings.namespace_prefix, &context.environment_id);
        let owned_namespaces = list_owned_namespaces(settings, &metadata.project_id).await?;
        let namespace = environment_namespace_from_inventory(
            &owned_namespaces,
            &expected_namespace,
            &context.environment_id,
        )?;
        let mut inspection = inspect_namespace(
            settings,
            &namespace,
            &context.environment_id,
            &metadata.project_id,
            &metadata.target,
            settings.command_timeout(),
        )
        .await?;
        match metadata.capability {
            Capability::Runtime => {
                inspection.endpoints.clear();
            }
            Capability::Exposure | Capability::Dns => {
                inspection.state["resources"] =
                    filter_resource_state(&inspection.state["resources"], ResourceRole::Exposure);
            }
            _ => {}
        }
        Ok(inspection)
    }

    async fn selected_namespaces(
        &self,
        settings: &Settings,
        metadata: &ContextMetadata,
        exact_selection: bool,
    ) -> PluginResult<Vec<OwnedNamespace>> {
        let mut namespaces = list_owned_namespaces(settings, &metadata.project_id).await?;
        if exact_selection {
            metadata.selection.validate_prune()?;
            let selected = metadata
                .selection
                .environment_ids
                .iter()
                .collect::<BTreeSet<_>>();
            let discovered = namespaces
                .iter()
                .map(|namespace| &namespace.environment_id)
                .collect::<BTreeSet<_>>();
            let unknown = selected
                .difference(&discovered)
                .copied()
                .collect::<Vec<_>>();
            if !unknown.is_empty() {
                return Err(PluginError::permanent(
                    ErrorKind::NotFound,
                    "prune_selection_unknown",
                    format!(
                        "selected Kubernetes environments are absent or not owned by this project: {}",
                        unknown
                            .into_iter()
                            .map(String::as_str)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                ));
            }
            namespaces.retain(|namespace| selected.contains(&namespace.environment_id));
            namespaces.sort_by(|left, right| left.environment_id.cmp(&right.environment_id));
        }
        Ok(namespaces)
    }

    fn apply_target(request: ApplyRequest) -> PluginResult<ApplyResult> {
        if request
            .plan
            .actions
            .iter()
            .any(|action| action.kind != "kubernetes.retain-cluster")
        {
            return Err(PluginError::permanent(
                ErrorKind::Validation,
                "unknown_target_action",
                "existing-cluster target plan contains an unsupported action",
            ));
        }
        Ok(ApplyResult {
            revision: None,
            state: json!({
                "provider": "kubernetes",
                "existing_cluster": true,
                "provisioning": false,
            }),
            journal: request.journal,
        })
    }

    async fn apply_builder(
        &self,
        settings: &Settings,
        request: ApplyRequest,
        events: &EventSink,
        cancellation: &crate::command::CancelState,
    ) -> PluginResult<ApplyResult> {
        let desired_value = request
            .plan
            .metadata
            .get("desired")
            .cloned()
            .ok_or_else(|| stale_plan("builder plan omitted desired state"))?;
        let desired = DesiredState::parse(desired_value, &request.context)?;
        let metadata = ContextMetadata::parse(&request.context)?;
        ensure_existing_environment_control_namespace(
            settings,
            &metadata.project_id,
            &request.context.environment_id,
        )
        .await?;
        let compose = ComposeProject::load(&desired).await?;
        compose.validate(&desired)?;
        let revision = request
            .plan
            .metadata
            .get("revision")
            .and_then(Value::as_str)
            .ok_or_else(|| stale_plan("builder plan omitted revision"))?;
        let builds = build_specs(settings, &desired, &compose, &request.context, revision)?;
        let platforms = request
            .plan
            .metadata
            .get("platforms")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>()
            })
            .filter(|items| !items.is_empty())
            .ok_or_else(|| stale_plan("builder plan omitted target platforms"))?;
        let mut journal = request.journal;
        let mut images = Map::new();
        for build in builds {
            self.locks
                .assert_authority(settings, &request.context.operation_id)
                .await?;
            emit_progress(
                events,
                &request.context.operation_id,
                &format!("Building and pushing {}", build.service),
            )
            .await?;
            let action_id = format!("build-push-{}", safe_action_component(&build.service));
            let started = journal_entry(
                journal.len() as u64 + 1,
                &action_id,
                JournalStatus::Started,
                "Local Buildx build and registry push started",
            );
            emit_journal(events, &request.context.operation_id, &started).await?;
            journal.push(started);
            build_and_push(settings, &build, &platforms, cancellation).await?;
            let succeeded = journal_entry(
                journal.len() as u64 + 1,
                &action_id,
                JournalStatus::Succeeded,
                "Image pushed to configured OCI registry",
            );
            emit_journal(events, &request.context.operation_id, &succeeded).await?;
            journal.push(succeeded);
            images.insert(build.service, Value::String(build.image));
        }
        self.locks
            .assert_authority(settings, &request.context.operation_id)
            .await?;
        Ok(ApplyResult {
            revision: Some(revision.to_owned()),
            state: json!({
                "revision": revision,
                "images": images,
                "registry_retained_on_down": true,
            }),
            journal,
        })
    }

    #[allow(clippy::too_many_lines)]
    async fn apply_resources(
        &self,
        settings: &Settings,
        request: ApplyRequest,
        events: &EventSink,
        cancellation: &crate::command::CancelState,
    ) -> PluginResult<ApplyResult> {
        let metadata = ContextMetadata::parse(&request.context)?;
        ensure_existing_environment_control_namespace(
            settings,
            &metadata.project_id,
            &request.context.environment_id,
        )
        .await?;
        let desired_value = request
            .plan
            .metadata
            .get("desired")
            .cloned()
            .ok_or_else(|| stale_plan("Kubernetes resource plan omitted desired state"))?;
        let desired = DesiredState::parse(desired_value, &request.context)?;
        let compose = ComposeProject::load(&desired).await?;
        let revision = request
            .plan
            .metadata
            .get("revision")
            .and_then(Value::as_str)
            .ok_or_else(|| stale_plan("Kubernetes resource plan omitted revision"))?;
        let rendered = render_environment(
            settings,
            &desired,
            &compose,
            &request.context,
            &metadata,
            revision,
            metadata.capability == Capability::Runtime,
        )?;
        let apply_keys = request
            .plan
            .actions
            .iter()
            .filter(|action| action.kind == "kubernetes.apply")
            .filter_map(|action| {
                action
                    .metadata
                    .get("resource_key")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .collect::<BTreeSet<_>>();
        let selected = rendered
            .resources
            .iter()
            .filter(|resource| apply_keys.contains(&resource.key))
            .collect::<Vec<_>>();
        let reconcile: PluginResult<()> = async {
            apply_in_order(
                settings,
                &selected,
                &self.locks,
                &request.context.operation_id,
                cancellation,
            )
            .await?;
            wait_for_resources(settings, &rendered, &selected, cancellation).await?;
            if metadata.capability == Capability::Exposure {
                wait_for_endpoints(settings, &rendered.readiness_targets, cancellation).await?;
            }
            if metadata.capability == Capability::Runtime
                && request
                    .plan
                    .actions
                    .iter()
                    .any(|action| action.kind == "kubernetes.reconcile-namespace-metadata")
            {
                self.locks
                    .assert_authority(settings, &request.context.operation_id)
                    .await?;
                reconcile_namespace_metadata(settings, &rendered, &desired, revision, cancellation)
                    .await?;
            }
            Ok(())
        }
        .await;
        if let Err(error) = reconcile {
            if error.kind != ErrorKind::Cancelled
                && metadata.capability == Capability::Exposure
                && self
                    .locks
                    .assert_authority(settings, &request.context.operation_id)
                    .await
                    .is_ok()
            {
                let rollback_entries = request
                    .plan
                    .actions
                    .iter()
                    .filter(|action| {
                        action.rollback.as_ref().is_some_and(|rollback| {
                            rollback.supported
                                && rollback.action.as_deref() == Some("exposure.restore-previous")
                        })
                    })
                    .map(|action| {
                        journal_entry_for_action(
                            0,
                            action,
                            JournalStatus::Succeeded,
                            "Exposure action selected for immediate compensation",
                        )
                    })
                    .collect::<Vec<_>>();
                restore_exposure_entries(
                    settings,
                    &rollback_entries,
                    &metadata.project_id,
                    &request.context.environment_id,
                    &self.locks,
                    &request.context.operation_id,
                    cancellation,
                )
                .await
                .map_err(|rollback_error| {
                    PluginError::permanent(
                        ErrorKind::Conflict,
                        "exposure_apply_rollback_failed",
                        format!(
                            "Kubernetes exposure apply failed and its exact compensation also failed: {}",
                            rollback_error.message
                        ),
                    )
                })?;
            }
            return Err(error);
        }
        let mut journal = request.journal;
        for action in &request.plan.actions {
            let entry = journal_entry_for_action(
                journal.len() as u64 + 1,
                action,
                JournalStatus::Succeeded,
                "Kubernetes action reconciled",
            );
            emit_journal(events, &request.context.operation_id, &entry).await?;
            journal.push(entry);
        }
        let inspection = inspect_namespace(
            settings,
            &rendered.namespace,
            &request.context.environment_id,
            &metadata.project_id,
            &metadata.target,
            settings.command_timeout(),
        )
        .await?;
        self.locks
            .assert_authority(settings, &request.context.operation_id)
            .await?;
        Ok(ApplyResult {
            revision: Some(revision.to_owned()),
            state: inspection.state,
            journal,
        })
    }

    async fn apply_dns(
        &self,
        settings: &Settings,
        request: ApplyRequest,
        events: &EventSink,
        cancellation: &crate::command::CancelState,
    ) -> PluginResult<ApplyResult> {
        let metadata = ContextMetadata::parse(&request.context)?;
        let action = request
            .plan
            .actions
            .iter()
            .find(|action| action.kind == "kubernetes.refresh-expiry")
            .ok_or_else(|| stale_plan("DNS plan omitted expiry refresh action"))?;
        let namespace = action
            .metadata
            .get("namespace")
            .and_then(Value::as_str)
            .ok_or_else(|| stale_plan("expiry refresh omitted namespace"))?;
        let expiry = action
            .metadata
            .get("expires_at_unix")
            .and_then(Value::as_u64)
            .ok_or_else(|| stale_plan("expiry refresh omitted expiry"))?;
        self.locks
            .assert_authority(settings, &request.context.operation_id)
            .await?;
        let namespace_owner = get_owned_namespace(
            settings,
            namespace,
            &metadata.project_id,
            Some(&request.context.environment_id),
        )
        .await?
        .ok_or_else(|| {
            PluginError::permanent(
                ErrorKind::NotFound,
                "expiry_namespace_missing",
                "Kubernetes namespace disappeared before expiry refresh",
            )
        })?;
        ensure_observed_control_namespace(
            namespace_owner.control_namespace.as_deref(),
            &settings.control_namespace,
            &namespace_owner.name,
        )?;
        annotate_namespace_expiry(settings, namespace, Some(expiry), cancellation).await?;

        let mut journal = request.journal;
        let entry = journal_entry_for_action(
            journal.len() as u64 + 1,
            action,
            JournalStatus::Succeeded,
            "Kubernetes environment expiry refreshed",
        );
        emit_journal(events, &request.context.operation_id, &entry).await?;
        journal.push(entry);
        let inspection = inspect_namespace(
            settings,
            namespace,
            &request.context.environment_id,
            &metadata.project_id,
            &metadata.target,
            settings.command_timeout(),
        )
        .await?;
        self.locks
            .assert_authority(settings, &request.context.operation_id)
            .await?;
        Ok(ApplyResult {
            revision: request
                .plan
                .metadata
                .get("revision")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            state: inspection.state,
            journal,
        })
    }

    async fn destroy_runtime(
        &self,
        settings: &Settings,
        request: &DestroyRequest,
        metadata: &ContextMetadata,
        events: &EventSink,
        cancellation: &crate::command::CancelState,
    ) -> PluginResult<DestroyResult> {
        let namespaces = runtime_destroy_targets(
            request.current.as_ref(),
            metadata.all,
            metadata.operation,
            &settings.namespace_prefix,
            &request.context.environment_id,
        );
        let mut journal = request.journal.clone();
        let mut remaining = Vec::new();
        for (namespace, environment_id) in namespaces {
            self.locks
                .assert_authority(settings, &request.context.operation_id)
                .await?;
            let absent = delete_namespace_exact(
                settings,
                &namespace,
                &metadata.project_id,
                &environment_id,
                cancellation,
            )
            .await?;
            if !absent {
                remaining.push(namespace.clone());
            }
            let entry = journal_entry(
                journal.len() as u64 + 1,
                &format!("delete-namespace-{namespace}"),
                if absent {
                    JournalStatus::Succeeded
                } else {
                    JournalStatus::Failed
                },
                if absent {
                    "Owned Kubernetes namespace deleted"
                } else {
                    "Owned Kubernetes namespace remained after deletion"
                },
            );
            emit_journal(events, &request.context.operation_id, &entry).await?;
            journal.push(entry);
        }
        self.locks
            .assert_authority(settings, &request.context.operation_id)
            .await?;
        Ok(DestroyResult {
            destroyed: remaining.is_empty(),
            journal,
            remaining,
        })
    }

    fn rollback_runtime(
        _settings: &Settings,
        request: &DestroyRequest,
        _cancellation: &crate::command::CancelState,
    ) -> PluginResult<DestroyResult> {
        if !attempted_rollback_entries(&request.journal, "runtime.restore-previous").is_empty() {
            return Err(PluginError::permanent(
                ErrorKind::Conflict,
                "runtime_exact_rollback_unavailable",
                "legacy Kubernetes workload rollback metadata cannot restore the full prior object and will not be executed",
            ));
        }
        Ok(DestroyResult {
            destroyed: true,
            journal: request.journal.clone(),
            remaining: Vec::new(),
        })
    }

    async fn rollback_exposure(
        &self,
        settings: &Settings,
        request: &DestroyRequest,
        cancellation: &crate::command::CancelState,
    ) -> PluginResult<DestroyResult> {
        let metadata = ContextMetadata::parse(&request.context)?;
        let entries = attempted_rollback_entries(&request.journal, "exposure.restore-previous");
        restore_exposure_entries(
            settings,
            &entries,
            &metadata.project_id,
            &request.context.environment_id,
            &self.locks,
            &request.context.operation_id,
            cancellation,
        )
        .await?;
        self.locks
            .assert_authority(settings, &request.context.operation_id)
            .await?;
        let mut journal = request.journal.clone();
        for entry in entries {
            journal.push(rollback_journal_entry(
                journal.len() as u64 + 1,
                &entry.action_id,
                "Kubernetes exposure restored to its previous manifest",
            ));
        }
        Ok(DestroyResult {
            destroyed: true,
            journal,
            remaining: Vec::new(),
        })
    }

    async fn rollback_dns(
        &self,
        settings: &Settings,
        request: &DestroyRequest,
        cancellation: &crate::command::CancelState,
    ) -> PluginResult<DestroyResult> {
        let metadata = ContextMetadata::parse(&request.context)?;
        let entries = attempted_rollback_entries(&request.journal, "dns.restore-expiry");
        let mut journal = request.journal.clone();
        for entry in entries {
            let rollback = entry
                .rollback
                .as_ref()
                .ok_or_else(|| stale_plan("DNS rollback journal omitted metadata"))?;
            let namespace = rollback
                .metadata
                .get("namespace")
                .and_then(Value::as_str)
                .ok_or_else(|| stale_plan("DNS rollback omitted namespace"))?;
            let current = get_owned_namespace(
                settings,
                namespace,
                &metadata.project_id,
                Some(&request.context.environment_id),
            )
            .await?
            .ok_or_else(|| {
                PluginError::permanent(
                    ErrorKind::NotFound,
                    "rollback_namespace_missing",
                    "Kubernetes namespace disappeared before expiry rollback",
                )
            })?;
            ensure_observed_control_namespace(
                current.control_namespace.as_deref(),
                &settings.control_namespace,
                &current.name,
            )?;
            let prior_expiry = rollback
                .metadata
                .get("prior_expiry")
                .and_then(Value::as_u64);
            let attempted_expiry = rollback
                .metadata
                .get("attempted_expiry")
                .and_then(Value::as_u64)
                .ok_or_else(|| stale_plan("DNS rollback omitted attempted expiry"))?;
            if expiry_rollback_needed(current.expires_at_unix, prior_expiry, attempted_expiry)? {
                self.locks
                    .assert_authority(settings, &request.context.operation_id)
                    .await?;
                annotate_namespace_expiry(settings, namespace, prior_expiry, cancellation).await?;
                let restored = get_owned_namespace(
                    settings,
                    namespace,
                    &metadata.project_id,
                    Some(&request.context.environment_id),
                )
                .await?
                .ok_or_else(|| {
                    PluginError::permanent(
                        ErrorKind::NotFound,
                        "rollback_namespace_missing",
                        "Kubernetes namespace disappeared during expiry rollback",
                    )
                })?;
                if restored.expires_at_unix != prior_expiry {
                    return Err(PluginError::retryable(
                        ErrorKind::Unavailable,
                        "rollback_not_ready",
                        "Kubernetes namespace did not restore its prior expiry",
                    ));
                }
            }
            journal.push(rollback_journal_entry(
                journal.len() as u64 + 1,
                &entry.action_id,
                "Kubernetes environment expiry restored",
            ));
        }
        self.locks
            .assert_authority(settings, &request.context.operation_id)
            .await?;
        Ok(DestroyResult {
            destroyed: true,
            journal,
            remaining: Vec::new(),
        })
    }
}

#[derive(Clone, Debug)]
struct TargetFacts {
    platforms: Vec<String>,
    ingress_controller: String,
    ingress_addresses: Vec<String>,
    traefik_middleware_api_version: Option<String>,
    diagnostics: Vec<Diagnostic>,
}

#[allow(clippy::too_many_lines)]
async fn target_facts(settings: &Settings) -> PluginResult<TargetFacts> {
    validate_cluster_endpoint(settings).await?;
    kubectl_json(
        settings,
        &["version".to_owned(), "-o".to_owned(), "json".to_owned()],
        settings.command_timeout(),
    )
    .await?;
    kubectl_json(
        settings,
        &[
            "get".to_owned(),
            "namespace".to_owned(),
            settings.control_namespace.clone(),
            "-o".to_owned(),
            "json".to_owned(),
        ],
        settings.command_timeout(),
    )
    .await
    .map_err(|error| {
        if error.kind == ErrorKind::NotFound {
            PluginError::permanent(
                ErrorKind::Validation,
                "control_namespace_missing",
                format!(
                    "control namespace `{}` is missing; ask the cluster operator to create it with the required Lightrail RBAC before deployment",
                    settings.control_namespace
                ),
            )
        } else {
            error
        }
    })?;
    let cluster_issuer = kubectl_json(
        settings,
        &[
            "get".to_owned(),
            "clusterissuer".to_owned(),
            settings.cluster_issuer.clone(),
            "-o".to_owned(),
            "json".to_owned(),
        ],
        settings.command_timeout(),
    )
    .await
    .map_err(|error| {
        if error.kind == ErrorKind::NotFound {
            PluginError::permanent(
                ErrorKind::Validation,
                "cluster_issuer_missing",
                format!(
                    "cert-manager ClusterIssuer `{}` is missing",
                    settings.cluster_issuer
                ),
            )
        } else {
            error
        }
    })?;
    let ingress_class = kubectl_json(
        settings,
        &[
            "get".to_owned(),
            "ingressclass".to_owned(),
            settings.ingress_class.clone(),
            "-o".to_owned(),
            "json".to_owned(),
        ],
        settings.command_timeout(),
    )
    .await?;
    let ingress_controller = ingress_class
        .pointer("/spec/controller")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned();
    let nodes = kubectl_json(
        settings,
        &[
            "get".to_owned(),
            "nodes".to_owned(),
            "-o".to_owned(),
            "json".to_owned(),
        ],
        settings.command_timeout(),
    )
    .await?;
    let platforms = node_platforms(&nodes)?;
    validate_explicit_platforms(&settings.platforms, &platforms)?;
    let ingress_service = kubectl_json(
        settings,
        &[
            "get".to_owned(),
            "service".to_owned(),
            settings.ingress_service_name.clone(),
            "--namespace".to_owned(),
            settings.ingress_service_namespace.clone(),
            "-o".to_owned(),
            "json".to_owned(),
        ],
        settings.command_timeout(),
    )
    .await
    .map_err(|error| {
        if error.kind == ErrorKind::NotFound {
            PluginError::permanent(
                ErrorKind::Validation,
                "ingress_service_missing",
                format!(
                    "configured ingress LoadBalancer Service `{}/{}` is missing",
                    settings.ingress_service_namespace, settings.ingress_service_name
                ),
            )
        } else {
            error
        }
    })?;
    let ingress_addresses = ingress_service_addresses(&ingress_service)?;
    let mut diagnostics = Vec::new();
    if !cluster_issuer_supports_http01(&cluster_issuer) {
        diagnostics.push(Diagnostic {
            severity: DiagnosticSeverity::Error,
            code: "cluster_issuer_http01_required".to_owned(),
            message: format!(
                "ClusterIssuer `{}` must be a ready ACME issuer with an HTTP-01 solver",
                settings.cluster_issuer
            ),
            path: Some("/cluster_issuer".to_owned()),
            help: Some(
                "configure an existing ready cert-manager ClusterIssuer with spec.acme.solvers[].http01"
                    .to_owned(),
            ),
        });
    }
    let is_traefik = ingress_controller == "traefik.io/ingress-controller";
    let is_ingress_nginx = ingress_controller == "k8s.io/ingress-nginx";
    let traefik_middleware_api_version = if is_traefik {
        discover_traefik_middleware_api(settings).await?
    } else {
        None
    };
    if is_traefik && traefik_middleware_api_version.is_none() {
        diagnostics.push(Diagnostic {
            severity: DiagnosticSeverity::Error,
            code: "traefik_middleware_crd_missing".to_owned(),
            message:
                "selected Traefik IngressClass requires the Middleware CRD for environment-owned HTTP-to-HTTPS redirects"
                    .to_owned(),
            path: Some("/ingress_class".to_owned()),
            help: Some(
                "install Traefik's traefik.io/v1alpha1 Middleware CRD (legacy traefik.containo.us/v1alpha1 is also supported)"
                    .to_owned(),
            ),
        });
    }
    if !is_ingress_nginx && !is_traefik {
        diagnostics.push(Diagnostic {
            severity: DiagnosticSeverity::Error,
            code: "unsupported_ingress_controller".to_owned(),
            message:
                "selected IngressClass must use `k8s.io/ingress-nginx` or `traefik.io/ingress-controller` for the matching HTTPS redirect policy"
                    .to_owned(),
            path: Some("/ingress_class".to_owned()),
            help: Some("select an existing NGINX or Traefik IngressClass".to_owned()),
        });
    }
    if crate::model::ingress_ipv4(&json!({"ingress": {"addresses": ingress_addresses}})).is_none() {
        diagnostics.push(Diagnostic {
            severity: DiagnosticSeverity::Error,
            code: "ingress_public_ipv4_missing".to_owned(),
            message:
                "selected ingress controller has no globally routable LoadBalancer IPv4 for IP-derived sslip.io/nip.io routing"
                    .to_owned(),
            path: Some("/ingress_service_name".to_owned()),
            help: Some(
                "ensure the existing ingress controller Service has a public IPv4; a load-balancer hostname alone is not a delegated wildcard DNS zone"
                    .to_owned(),
            ),
        });
    }
    Ok(TargetFacts {
        platforms,
        ingress_controller,
        ingress_addresses,
        traefik_middleware_api_version,
        diagnostics,
    })
}

fn cluster_issuer_supports_http01(cluster_issuer: &Value) -> bool {
    let ready = cluster_issuer
        .pointer("/status/conditions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|condition| {
            condition.get("type").and_then(Value::as_str) == Some("Ready")
                && condition.get("status").and_then(Value::as_str) == Some("True")
        });
    let http01 = cluster_issuer
        .pointer("/spec/acme/solvers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|solver| solver.get("http01").is_some_and(Value::is_object));
    ready && http01
}

async fn discover_traefik_middleware_api(settings: &Settings) -> PluginResult<Option<String>> {
    for api_version in ["traefik.io/v1alpha1", "traefik.containo.us/v1alpha1"] {
        let result = kubectl_json(
            settings,
            &["get".to_owned(), format!("--raw=/apis/{api_version}")],
            settings.command_timeout(),
        )
        .await;
        match result {
            Ok(resources) if has_middleware_resource(&resources) => {
                return Ok(Some(api_version.to_owned()));
            }
            Ok(_) => {}
            Err(error) if error.kind == ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(None)
}

fn has_middleware_resource(resources: &Value) -> bool {
    resources
        .get("resources")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|resource| {
            resource.get("name").and_then(Value::as_str) == Some("middlewares")
                && resource.get("kind").and_then(Value::as_str) == Some("Middleware")
        })
}

async fn validate_cluster_endpoint(settings: &Settings) -> PluginResult<()> {
    let view = kubectl_json(
        settings,
        &[
            "config".to_owned(),
            "view".to_owned(),
            "--minify".to_owned(),
            "-o".to_owned(),
            "json".to_owned(),
        ],
        settings.command_timeout(),
    )
    .await?;
    let server = view
        .pointer("/clusters/0/cluster/server")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            PluginError::permanent(
                ErrorKind::Validation,
                "cluster_server_missing",
                "selected kube context does not expose a cluster API server",
            )
        })?;
    let url = Url::parse(server).map_err(|error| {
        PluginError::permanent(
            ErrorKind::Validation,
            "cluster_server_invalid",
            format!("selected kube context has an invalid API server URL: {error}"),
        )
    })?;
    let host = url.host_str().ok_or_else(|| {
        PluginError::permanent(
            ErrorKind::Validation,
            "cluster_server_host_missing",
            "selected kube context API server URL has no host",
        )
    })?;
    if host.eq_ignore_ascii_case("localhost")
        || host.to_ascii_lowercase().ends_with(".localhost")
        || host.parse::<IpAddr>().is_ok_and(is_loopback_address)
    {
        return Err(local_cluster_error(host));
    }
    let port = url.port_or_known_default().ok_or_else(|| {
        PluginError::permanent(
            ErrorKind::Validation,
            "cluster_server_port_missing",
            "selected kube context API server URL has no usable port",
        )
    })?;
    let host_owned = host.to_owned();
    let lookup_host = host_owned.clone();
    let resolution = tokio::task::spawn_blocking(move || {
        (lookup_host.as_str(), port)
            .to_socket_addrs()
            .map(Iterator::collect::<Vec<_>>)
    });
    let addresses = timeout(Duration::from_secs(15), resolution)
        .await
        .map_err(|_| {
            PluginError::retryable(
                ErrorKind::Timeout,
                "cluster_server_resolution_timeout",
                format!("timed out resolving Kubernetes API host `{host_owned}`"),
            )
        })?
        .map_err(|error| {
            PluginError::retryable(
                ErrorKind::Unavailable,
                "cluster_server_resolution_failed",
                format!("could not join Kubernetes API host resolution: {error}"),
            )
        })?
        .map_err(|error| {
            PluginError::retryable(
                ErrorKind::Unavailable,
                "cluster_server_resolution_failed",
                format!("could not resolve Kubernetes API host `{host_owned}`: {error}"),
            )
        })?;
    if addresses.is_empty() {
        return Err(PluginError::retryable(
            ErrorKind::Unavailable,
            "cluster_server_resolution_empty",
            format!("Kubernetes API host `{host_owned}` resolved to no addresses"),
        ));
    }
    if addresses
        .iter()
        .any(|address| is_loopback_address(address.ip()))
    {
        return Err(local_cluster_error(&host_owned));
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

fn local_cluster_error(host: &str) -> PluginError {
    PluginError::permanent(
        ErrorKind::Validation,
        "localhost_cluster_forbidden",
        format!(
            "selected kube context API host `{host}` is loopback; Lightrail runtimes must be remote"
        ),
    )
}

fn node_platforms(nodes: &Value) -> PluginResult<Vec<String>> {
    let mut platforms = BTreeSet::new();
    for item in nodes
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if !node_is_schedulable(item) {
            continue;
        }
        let architecture = item
            .pointer("/status/nodeInfo/architecture")
            .and_then(Value::as_str);
        match architecture {
            Some("amd64" | "x86_64") => {
                platforms.insert("linux/amd64".to_owned());
            }
            Some("arm64" | "aarch64") => {
                platforms.insert("linux/arm64".to_owned());
            }
            Some(other) => {
                return Err(PluginError::permanent(
                    ErrorKind::Unsupported,
                    "unsupported_node_architecture",
                    format!("Kubernetes node architecture `{other}` is unsupported"),
                ));
            }
            None => {}
        }
    }
    if platforms.is_empty() {
        return Err(PluginError::permanent(
            ErrorKind::Unavailable,
            "node_architecture_unavailable",
            "the existing cluster has no schedulable node architecture observations",
        ));
    }
    Ok(platforms.into_iter().collect())
}

fn validate_explicit_platforms(requested: &[String], observed: &[String]) -> PluginResult<()> {
    let observed = observed.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let unavailable = requested
        .iter()
        .map(String::as_str)
        .filter(|platform| !observed.contains(platform))
        .collect::<Vec<_>>();
    if unavailable.is_empty() {
        Ok(())
    } else {
        Err(PluginError::permanent(
            ErrorKind::Unavailable,
            "explicit_platform_unavailable",
            format!(
                "configured Kubernetes platforms are not present on Ready schedulable nodes: {}",
                unavailable.join(", ")
            ),
        ))
    }
}

fn node_is_schedulable(node: &Value) -> bool {
    if node
        .pointer("/spec/unschedulable")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return false;
    }
    let ready = node
        .pointer("/status/conditions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|condition| {
            condition.get("type").and_then(Value::as_str) == Some("Ready")
                && condition.get("status").and_then(Value::as_str) == Some("True")
        });
    let repels_workloads = node
        .pointer("/spec/taints")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|taint| {
            matches!(
                taint.get("effect").and_then(Value::as_str),
                Some("NoSchedule" | "NoExecute")
            )
        });
    ready && !repels_workloads
}

fn ingress_service_addresses(service: &Value) -> PluginResult<Vec<String>> {
    if service.pointer("/spec/type").and_then(Value::as_str) != Some("LoadBalancer") {
        return Err(PluginError::permanent(
            ErrorKind::Validation,
            "ingress_service_not_load_balancer",
            "configured ingress Service must have spec.type=LoadBalancer",
        ));
    }
    let mut addresses = service
        .pointer("/status/loadBalancer/ingress")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|entry| {
            [
                entry.get("ip").and_then(Value::as_str),
                entry.get("hostname").and_then(Value::as_str),
            ]
            .into_iter()
            .flatten()
        })
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    addresses.sort();
    addresses.dedup();
    Ok(addresses)
}

#[derive(Clone, Debug)]
struct OwnedNamespace {
    name: String,
    environment_id: String,
    project_id: String,
    profile: Option<String>,
    branch: Option<String>,
    control_namespace: Option<String>,
    expires_at_unix: Option<u64>,
}

impl OwnedNamespace {
    fn environment_value(&self) -> Value {
        json!({
            "environment_contract": 1,
            "id": self.environment_id,
            "environment_id": self.environment_id,
            "project_id": self.project_id,
            "profile": self.profile,
            "branch": self.branch,
            "namespace": self.name,
            "control_namespace": self.control_namespace,
            "present": true,
            "status": "ready",
            "endpoints": [],
            "expires_at_unix": self.expires_at_unix,
        })
    }
}

fn environment_namespace_from_inventory(
    namespaces: &[OwnedNamespace],
    expected_namespace: &str,
    environment_id: &str,
) -> PluginResult<String> {
    let matches = namespaces
        .iter()
        .filter(|namespace| namespace.environment_id == environment_id)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Ok(expected_namespace.to_owned()),
        [namespace] => Ok(namespace.name.clone()),
        _ => Err(PluginError::permanent(
            ErrorKind::Conflict,
            "environment_namespace_ambiguous",
            format!(
                "multiple owned Kubernetes namespaces claim environment `{environment_id}`; refusing to choose a mutation target"
            ),
        )),
    }
}

async fn list_owned_namespaces(
    settings: &Settings,
    project_id: &str,
) -> PluginResult<Vec<OwnedNamespace>> {
    let namespaces = kubectl_json(
        settings,
        &[
            "get".to_owned(),
            "namespaces".to_owned(),
            "--selector".to_owned(),
            format!("{MANAGED_LABEL}=lightrail,{PROJECT_LABEL}={project_id}"),
            "-o".to_owned(),
            "json".to_owned(),
        ],
        settings.command_timeout(),
    )
    .await?;
    let mut owned = namespaces
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|namespace| parse_owned_namespace(namespace, project_id))
        .collect::<Vec<_>>();
    owned.sort_by(|left, right| left.environment_id.cmp(&right.environment_id));
    Ok(owned)
}

async fn get_owned_namespace(
    settings: &Settings,
    name: &str,
    project_id: &str,
    environment_id: Option<&str>,
) -> PluginResult<Option<OwnedNamespace>> {
    let result = kubectl_json(
        settings,
        &[
            "get".to_owned(),
            "namespace".to_owned(),
            name.to_owned(),
            "-o".to_owned(),
            "json".to_owned(),
        ],
        settings.command_timeout(),
    )
    .await;
    let namespace = match result {
        Ok(namespace) => namespace,
        Err(error) if error.kind == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let owned = parse_owned_namespace(&namespace, project_id).ok_or_else(|| {
        PluginError::permanent(
            ErrorKind::Conflict,
            "namespace_ownership_mismatch",
            format!("namespace `{name}` does not carry exact Lightrail project ownership"),
        )
    })?;
    if environment_id.is_some_and(|expected| owned.environment_id != expected) {
        return Err(PluginError::permanent(
            ErrorKind::Conflict,
            "namespace_environment_mismatch",
            format!("namespace `{name}` belongs to another Lightrail environment"),
        ));
    }
    Ok(Some(owned))
}

fn parse_owned_namespace(namespace: &Value, project_id: &str) -> Option<OwnedNamespace> {
    let labels = namespace.pointer("/metadata/labels")?.as_object()?;
    if labels.get(MANAGED_LABEL)?.as_str()? != "lightrail"
        || labels.get(PROJECT_LABEL)?.as_str()? != project_id
    {
        return None;
    }
    Some(OwnedNamespace {
        name: namespace.pointer("/metadata/name")?.as_str()?.to_owned(),
        environment_id: labels.get(ENVIRONMENT_LABEL)?.as_str()?.to_owned(),
        project_id: project_id.to_owned(),
        profile: labels
            .get(PROFILE_LABEL)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        branch: namespace
            .pointer("/metadata/annotations/lightrail.dev~1branch")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        control_namespace: namespace
            .pointer("/metadata/annotations/lightrail.dev~1control-namespace")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        expires_at_unix: namespace
            .pointer("/metadata/annotations/lightrail.dev~1expires-at-unix")
            .and_then(Value::as_str)
            .and_then(|value| value.parse().ok()),
    })
}

#[allow(clippy::too_many_lines)]
async fn inspect_namespace(
    settings: &Settings,
    namespace: &str,
    environment_id: &str,
    project_id: &str,
    target: &Value,
    deadline: Duration,
) -> PluginResult<InspectResult> {
    let namespace_value = match kubectl_json(
        settings,
        &[
            "get".to_owned(),
            "namespace".to_owned(),
            namespace.to_owned(),
            "-o".to_owned(),
            "json".to_owned(),
        ],
        deadline,
    )
    .await
    {
        Ok(value) => value,
        Err(error) if error.kind == ErrorKind::NotFound => {
            return Ok(InspectResult {
                status: ResourceStatus::Absent,
                endpoints: Vec::new(),
                state: json!({
                    "namespace": namespace,
                    "environment_id": environment_id,
                    "present": false,
                    "resources": {}
                }),
                diagnostics: Vec::new(),
            });
        }
        Err(error) => return Err(error),
    };
    let namespace_labels = namespace_value
        .pointer("/metadata/labels")
        .and_then(Value::as_object);
    let owned = namespace_labels.is_some_and(|labels| {
        labels.get(MANAGED_LABEL).and_then(Value::as_str) == Some("lightrail")
            && labels.get(PROJECT_LABEL).and_then(Value::as_str) == Some(project_id)
            && labels.get(ENVIRONMENT_LABEL).and_then(Value::as_str) == Some(environment_id)
    });
    if !owned {
        return Err(PluginError::permanent(
            ErrorKind::Conflict,
            "namespace_ownership_mismatch",
            format!(
                "namespace `{namespace}` does not carry exact project and environment ownership"
            ),
        ));
    }
    let mut resource_types =
        "deployments.apps,statefulsets.apps,services,jobs.batch,persistentvolumeclaims,ingresses.networking.k8s.io,secrets"
            .to_owned();
    if let Some(middleware) = traefik_middleware_resource_type(target) {
        resource_types.push(',');
        resource_types.push_str(middleware);
    }
    let objects = kubectl_json(
        settings,
        &[
            "get".to_owned(),
            resource_types,
            "--namespace".to_owned(),
            namespace.to_owned(),
            "--selector".to_owned(),
            format!("{ENVIRONMENT_LABEL}={environment_id}"),
            "-o".to_owned(),
            "json".to_owned(),
        ],
        deadline,
    )
    .await?;
    let mut resources = Map::new();
    if let (Some(name), Some(hash)) = (
        namespace_value
            .pointer("/metadata/name")
            .and_then(Value::as_str),
        namespace_value
            .pointer("/metadata/annotations/lightrail.dev~1spec-hash")
            .and_then(Value::as_str),
    ) {
        resources.insert(format!("Namespace/{name}"), Value::String(hash.to_owned()));
    }
    let mut endpoints = Vec::new();
    let mut exposure_manifests = Map::new();
    let mut status = ResourceStatus::Ready;
    for object in objects
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let labels = object
            .pointer("/metadata/labels")
            .and_then(Value::as_object);
        let owned = labels.is_some_and(|labels| {
            labels.get(MANAGED_LABEL).and_then(Value::as_str) == Some("lightrail")
                && labels.get(PROJECT_LABEL).and_then(Value::as_str) == Some(project_id)
                && labels.get(ENVIRONMENT_LABEL).and_then(Value::as_str) == Some(environment_id)
        });
        if !owned {
            return Err(PluginError::permanent(
                ErrorKind::Conflict,
                "resource_ownership_mismatch",
                format!(
                    "namespace `{namespace}` contains a resource using the environment selector without exact Lightrail ownership"
                ),
            ));
        }
        let kind = object
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("Unknown");
        let name = object
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        if let Some(hash) = object
            .pointer("/metadata/annotations/lightrail.dev~1spec-hash")
            .and_then(Value::as_str)
        {
            resources.insert(format!("{kind}/{name}"), Value::String(hash.to_owned()));
        }
        if matches!(kind, "Ingress" | "Middleware") {
            exposure_manifests.insert(format!("{kind}/{name}"), sanitized_owned_manifest(object)?);
        }
        status = combine_status(status, resource_status(object));
        if kind == "Ingress" {
            let app = object
                .pointer("/metadata/annotations/lightrail.dev~1app-name")
                .and_then(Value::as_str)
                .unwrap_or_else(|| name.strip_prefix("ingress-").unwrap_or(name))
                .to_owned();
            for host in object
                .pointer("/spec/tls")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .flat_map(|tls| {
                    tls.get("hosts")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                })
                .filter_map(Value::as_str)
            {
                endpoints.push(Endpoint {
                    app: app.clone(),
                    url: format!("https://{host}"),
                });
            }
        }
    }
    let revision = namespace_value
        .pointer("/metadata/labels/lightrail.dev~1revision")
        .and_then(Value::as_str);
    let expiry = namespace_value
        .pointer("/metadata/annotations/lightrail.dev~1expires-at-unix")
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<u64>().ok());
    let control_namespace = namespace_value
        .pointer("/metadata/annotations/lightrail.dev~1control-namespace")
        .and_then(Value::as_str);
    Ok(InspectResult {
        status,
        endpoints,
        state: json!({
            "namespace": namespace,
            "environment_id": environment_id,
            "present": true,
            "revision": revision,
            "control_namespace": control_namespace,
            "expires_at_unix": expiry,
            "resources": resources,
            "exposure_manifests": exposure_manifests,
        }),
        diagnostics: Vec::new(),
    })
}

fn sanitized_owned_manifest(object: &Value) -> PluginResult<Value> {
    let api_version = object
        .get("apiVersion")
        .and_then(Value::as_str)
        .ok_or_else(|| stale_plan("owned exposure resource omitted apiVersion"))?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| stale_plan("owned exposure resource omitted kind"))?;
    let metadata = object
        .get("metadata")
        .and_then(Value::as_object)
        .ok_or_else(|| stale_plan("owned exposure resource omitted metadata"))?;
    Ok(json!({
        "apiVersion": api_version,
        "kind": kind,
        "metadata": {
            "name": metadata.get("name"),
            "namespace": metadata.get("namespace"),
            "labels": metadata.get("labels").cloned().unwrap_or_else(|| json!({})),
            "annotations": metadata
                .get("annotations")
                .cloned()
                .unwrap_or_else(|| json!({})),
        },
        "spec": object.get("spec").cloned().unwrap_or_else(|| json!({})),
    }))
}

fn resource_status(resource: &Value) -> ResourceStatus {
    let kind = resource
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let desired = resource
        .pointer("/spec/replicas")
        .and_then(Value::as_u64)
        .unwrap_or(1);
    match kind {
        "Deployment" => {
            if resource
                .pointer("/status/availableReplicas")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                >= desired
            {
                ResourceStatus::Ready
            } else {
                ResourceStatus::Pending
            }
        }
        "StatefulSet" => {
            if resource
                .pointer("/status/readyReplicas")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                >= desired
            {
                ResourceStatus::Ready
            } else {
                ResourceStatus::Pending
            }
        }
        "Job" => {
            if resource
                .pointer("/status/succeeded")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                > 0
            {
                ResourceStatus::Ready
            } else if resource
                .pointer("/status/failed")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                > 0
            {
                ResourceStatus::Degraded
            } else {
                ResourceStatus::Pending
            }
        }
        "PersistentVolumeClaim"
            if resource.pointer("/status/phase").and_then(Value::as_str) != Some("Bound") =>
        {
            ResourceStatus::Pending
        }
        _ => ResourceStatus::Ready,
    }
}

fn combine_status(left: ResourceStatus, right: ResourceStatus) -> ResourceStatus {
    use ResourceStatus::{Absent, Degraded, Destroying, Pending, Ready, Unknown};
    match (left, right) {
        (Degraded, _) | (_, Degraded) => Degraded,
        (Unknown, _) | (_, Unknown) => Unknown,
        (Destroying, _) | (_, Destroying) => Destroying,
        (Pending, _) | (_, Pending) => Pending,
        (Ready, _) | (_, Ready) => Ready,
        (Absent, Absent) => Absent,
    }
}

fn effective_platforms(settings: &Settings, target: &Value) -> PluginResult<Vec<String>> {
    let mut platforms = if settings.platforms.is_empty() {
        target
            .get("platforms")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>()
    } else {
        settings.platforms.clone()
    };
    if platforms.is_empty() {
        return Err(PluginError::permanent(
            ErrorKind::Unavailable,
            "target_platforms_unavailable",
            "Kubernetes target did not report node platforms and none were configured",
        ));
    }
    platforms.sort();
    platforms.dedup();
    Ok(platforms)
}

fn effective_build_platforms(
    settings: &Settings,
    target: &Value,
    compose: &ComposeProject,
) -> PluginResult<Vec<String>> {
    if compose.has_local_builds() {
        effective_platforms(settings, target)
    } else {
        Ok(Vec::new())
    }
}

async fn build_and_push(
    settings: &Settings,
    build: &BuildSpec,
    platforms: &[String],
    cancellation: &crate::command::CancelState,
) -> PluginResult<()> {
    let mut arguments = vec![
        "buildx".to_owned(),
        "build".to_owned(),
        "--platform".to_owned(),
        platforms.join(","),
        "--push".to_owned(),
        "--tag".to_owned(),
        build.image.clone(),
    ];
    if let Some(dockerfile) = &build.dockerfile {
        arguments.push("--file".to_owned());
        arguments.push(dockerfile.to_string_lossy().into_owned());
    }
    let mut environment = BTreeMap::new();
    for (name, value) in &build.arguments {
        arguments.push("--build-arg".to_owned());
        arguments.push(name.clone());
        environment.insert(name.clone(), value.clone());
    }
    arguments.push(build.context.to_string_lossy().into_owned());
    run(
        "docker",
        &arguments,
        None,
        &environment,
        settings.command_timeout(),
        Some(cancellation),
    )
    .await?;
    Ok(())
}

async fn apply_in_order(
    settings: &Settings,
    resources: &[&RenderedResource],
    locks: &LeaseLocks,
    operation_id: &str,
    cancellation: &crate::command::CancelState,
) -> PluginResult<()> {
    for namespace in resources
        .iter()
        .copied()
        .filter(|resource| resource.kind == "Namespace")
    {
        locks.assert_authority(settings, operation_id).await?;
        claim_namespace(settings, namespace, cancellation).await?;
    }
    for phase in [
        &["PersistentVolumeClaim", "Secret", "Job"][..],
        &["Service", "Deployment", "StatefulSet"][..],
        &["Middleware"][..],
        &["Ingress"][..],
    ] {
        let selected = resources
            .iter()
            .copied()
            .filter(|resource| phase.contains(&resource.kind.as_str()))
            .collect::<Vec<_>>();
        if selected.is_empty() {
            continue;
        }
        locks.assert_authority(settings, operation_id).await?;
        kubectl(
            settings,
            &[
                "apply".to_owned(),
                "--server-side".to_owned(),
                "--field-manager=lightrail".to_owned(),
                "-f".to_owned(),
                "-".to_owned(),
            ],
            Some(manifest_list(selected)?),
            settings.command_timeout(),
            Some(cancellation),
        )
        .await?;
    }
    Ok(())
}

async fn claim_namespace(
    settings: &Settings,
    desired: &RenderedResource,
    cancellation: &crate::command::CancelState,
) -> PluginResult<()> {
    let name = desired
        .manifest
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .ok_or_else(|| stale_plan("rendered Namespace omitted metadata.name"))?;
    if let Some(current) = get_namespace(settings, name).await? {
        return validate_namespace_claim(&current, desired, settings);
    }

    let create_result = kubectl(
        settings,
        &["create".to_owned(), "-f".to_owned(), "-".to_owned()],
        Some(serde_json::to_vec(&desired.manifest).map_err(serialization_error)?),
        settings.command_timeout(),
        Some(cancellation),
    )
    .await;
    if let Err(create_error) = create_result {
        if create_error.kind == ErrorKind::Cancelled {
            return Err(create_error);
        }
        return match get_namespace(settings, name).await? {
            Some(current) => validate_namespace_claim(&current, desired, settings),
            None => Err(create_error),
        };
    }
    let current = get_namespace(settings, name).await?.ok_or_else(|| {
        PluginError::retryable(
            ErrorKind::Unavailable,
            "namespace_claim_not_observed",
            format!("created Kubernetes Namespace `{name}` was not observable"),
        )
    })?;
    validate_namespace_claim(&current, desired, settings)
}

async fn get_namespace(settings: &Settings, name: &str) -> PluginResult<Option<Value>> {
    match kubectl_json(
        settings,
        &[
            "get".to_owned(),
            "namespace".to_owned(),
            name.to_owned(),
            "-o".to_owned(),
            "json".to_owned(),
        ],
        settings.command_timeout(),
    )
    .await
    {
        Ok(namespace) => Ok(Some(namespace)),
        Err(error) if error.kind == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn validate_namespace_claim(
    current: &Value,
    desired: &RenderedResource,
    settings: &Settings,
) -> PluginResult<()> {
    let desired_name = desired
        .manifest
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .ok_or_else(|| stale_plan("rendered Namespace omitted metadata.name"))?;
    let desired_project = desired
        .manifest
        .pointer("/metadata/labels/lightrail.dev~1project-id")
        .and_then(Value::as_str)
        .ok_or_else(|| stale_plan("rendered Namespace omitted project ownership"))?;
    let desired_environment = desired
        .manifest
        .pointer("/metadata/labels/lightrail.dev~1environment-id")
        .and_then(Value::as_str)
        .ok_or_else(|| stale_plan("rendered Namespace omitted environment ownership"))?;
    let identity_matches = current.get("kind").and_then(Value::as_str) == Some("Namespace")
        && current.pointer("/metadata/name").and_then(Value::as_str) == Some(desired_name)
        && current
            .pointer("/metadata/labels/app.kubernetes.io~1managed-by")
            .and_then(Value::as_str)
            == Some("lightrail")
        && current
            .pointer("/metadata/labels/lightrail.dev~1project-id")
            .and_then(Value::as_str)
            == Some(desired_project)
        && current
            .pointer("/metadata/labels/lightrail.dev~1environment-id")
            .and_then(Value::as_str)
            == Some(desired_environment);
    if !identity_matches {
        return Err(PluginError::permanent(
            ErrorKind::Conflict,
            "namespace_claim_ownership_conflict",
            format!(
                "Kubernetes Namespace `{desired_name}` already exists without the exact planned ownership"
            ),
        ));
    }
    ensure_observed_control_namespace(
        current
            .pointer("/metadata/annotations/lightrail.dev~1control-namespace")
            .and_then(Value::as_str),
        &settings.control_namespace,
        desired_name,
    )?;
    if current
        .pointer("/metadata/annotations/lightrail.dev~1spec-hash")
        .and_then(Value::as_str)
        != Some(desired.spec_hash.as_str())
    {
        return Err(PluginError::permanent(
            ErrorKind::Conflict,
            "namespace_claim_spec_conflict",
            format!(
                "Kubernetes Namespace `{desired_name}` was concurrently claimed by a different deployment plan"
            ),
        ));
    }
    Ok(())
}

async fn wait_for_resources(
    settings: &Settings,
    rendered: &RenderedEnvironment,
    selected: &[&RenderedResource],
    cancellation: &crate::command::CancelState,
) -> PluginResult<()> {
    let kubectl_timeout = format!("{}s", settings.readiness_timeout().as_secs());
    let commands = selected
        .iter()
        .filter_map(|resource| {
            Some(match resource.kind.as_str() {
                "Deployment" | "StatefulSet" => vec![
                    "rollout".to_owned(),
                    "status".to_owned(),
                    format!("{}/{}", resource.kind.to_ascii_lowercase(), resource.name),
                    "--namespace".to_owned(),
                    rendered.namespace.clone(),
                    "--timeout".to_owned(),
                    kubectl_timeout.clone(),
                ],
                "Job" => vec![
                    "wait".to_owned(),
                    "--for=condition=complete".to_owned(),
                    format!("job/{}", resource.name),
                    "--namespace".to_owned(),
                    rendered.namespace.clone(),
                    "--timeout".to_owned(),
                    kubectl_timeout.clone(),
                ],
                _ => return None,
            })
        })
        .collect::<Vec<Vec<String>>>();
    join_runtime_checks(
        commands.into_iter().map(|arguments| async move {
            kubectl(
                settings,
                &arguments,
                None,
                settings.readiness_timeout(),
                Some(cancellation),
            )
            .await
            .map(|_| ())
        }),
        settings.readiness_timeout(),
    )
    .await
}

async fn join_runtime_checks<F>(
    checks: impl IntoIterator<Item = F>,
    deadline: Duration,
) -> PluginResult<()>
where
    F: Future<Output = PluginResult<()>>,
{
    timeout(deadline, try_join_all(checks))
        .await
        .map_err(|_| {
            PluginError::retryable(
                ErrorKind::Timeout,
                "runtime_readiness_timeout",
                "Kubernetes workloads did not become ready within the overall readiness deadline",
            )
        })?
        .map(|_| ())
}

async fn wait_for_endpoints(
    settings: &Settings,
    targets: &[ReadinessTarget],
    cancellation: &crate::command::CancelState,
) -> PluginResult<()> {
    let client = Client::builder()
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|error| {
            PluginError::permanent(
                ErrorKind::Internal,
                "https_client_failed",
                format!("could not construct trusted HTTPS client: {error}"),
            )
        })?;
    let deadline = Instant::now() + settings.readiness_timeout();
    join_endpoint_checks(
        targets
            .iter()
            .map(|target| wait_for_endpoint(&client, target, deadline, cancellation)),
    )
    .await?;
    Ok(())
}

async fn join_endpoint_checks<F>(checks: impl IntoIterator<Item = F>) -> PluginResult<()>
where
    F: Future<Output = PluginResult<()>>,
{
    try_join_all(checks).await.map(|_| ())
}

async fn wait_for_endpoint(
    client: &Client,
    target: &ReadinessTarget,
    deadline: Instant,
    cancellation: &crate::command::CancelState,
) -> PluginResult<()> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| endpoint_timeout(target))?;
        let check = timeout(remaining, verify_endpoint(client, target));
        tokio::pin!(check);
        let result = tokio::select! {
            result = &mut check => result,
            () = cancellation.cancelled() => {
                return Err(PluginError::permanent(
                    ErrorKind::Cancelled,
                    "operation_cancelled",
                    "Kubernetes endpoint readiness was cancelled",
                ));
            }
        };
        match result {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(error)) if !error.retryable => return Err(error),
            Ok(Err(_)) => {}
            Err(_) => return Err(endpoint_timeout(target)),
        }
        if Instant::now() >= deadline {
            return Err(endpoint_timeout(target));
        }
        let sleep_for = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or_default()
            .min(Duration::from_secs(2));
        tokio::select! {
            () = sleep(sleep_for) => {}
            () = cancellation.cancelled() => {
                return Err(PluginError::permanent(
                    ErrorKind::Cancelled,
                    "operation_cancelled",
                    "Kubernetes endpoint readiness was cancelled",
                ));
            }
        }
    }
}

fn endpoint_timeout(target: &ReadinessTarget) -> PluginError {
    PluginError::retryable(
        ErrorKind::Timeout,
        "https_readiness_timeout",
        format!(
            "trusted HTTPS endpoint for app `{}` did not become ready in time",
            target.app
        ),
    )
}

async fn verify_endpoint(client: &Client, target: &ReadinessTarget) -> PluginResult<()> {
    let base = Url::parse(&target.base_url).map_err(|error| {
        PluginError::permanent(
            ErrorKind::Internal,
            "invalid_endpoint_url",
            format!("plugin generated an invalid base endpoint URL: {error}"),
        )
    })?;
    let https = Url::parse(&target.probe_url).map_err(|error| {
        PluginError::permanent(
            ErrorKind::Internal,
            "invalid_endpoint_url",
            format!("plugin generated an invalid endpoint URL: {error}"),
        )
    })?;
    if https.scheme() != "https"
        || base.scheme() != "https"
        || https.host_str() != base.host_str()
        || https.port_or_known_default() != base.port_or_known_default()
    {
        return Err(PluginError::permanent(
            ErrorKind::Internal,
            "https_endpoint_required",
            "Kubernetes endpoint readiness requires an HTTPS URL",
        ));
    }
    let response = client.get(https.clone()).send().await.map_err(|_| {
        PluginError::retryable(
            ErrorKind::Unavailable,
            "https_endpoint_unavailable",
            format!(
                "trusted HTTPS endpoint for app `{}` is not ready",
                target.app
            ),
        )
    })?;
    if !health_status_matches(response.status(), target.expected_status) {
        return Err(PluginError::retryable(
            ErrorKind::Unavailable,
            "https_endpoint_unhealthy",
            format!(
                "HTTPS health check for app `{}` returned status {}",
                target.app,
                response.status()
            ),
        ));
    }

    let mut http = https.clone();
    http.set_scheme("http").map_err(|()| {
        PluginError::permanent(
            ErrorKind::Internal,
            "http_probe_url_failed",
            "could not derive HTTP redirect probe URL",
        )
    })?;
    let response = client.get(http).send().await.map_err(|_| {
        PluginError::retryable(
            ErrorKind::Unavailable,
            "http_redirect_unavailable",
            format!("HTTP redirect route for app `{}` is not ready", target.app),
        )
    })?;
    let status = response.status();
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok());
    if !redirect_location_valid(status, location, &https) {
        return Err(PluginError::retryable(
            ErrorKind::Unavailable,
            "http_redirect_invalid",
            format!(
                "HTTP route for app `{}` did not redirect to its trusted HTTPS hostname",
                target.app
            ),
        ));
    }
    Ok(())
}

fn health_status_matches(actual: StatusCode, expected: Option<u16>) -> bool {
    expected.map_or(actual.as_u16() < 500, |expected| {
        actual.as_u16() == expected
    })
}

fn redirect_location_valid(
    status: StatusCode,
    location: Option<&str>,
    expected_https: &Url,
) -> bool {
    status.is_redirection()
        && location
            .and_then(|value| Url::parse(value).ok())
            .is_some_and(|location| {
                location.scheme() == "https"
                    && location.host_str() == expected_https.host_str()
                    && location.port_or_known_default() == expected_https.port_or_known_default()
            })
}

fn attempted_rollback_entries(
    journal: &[ActionJournalEntry],
    rollback_action: &str,
) -> Vec<ActionJournalEntry> {
    let mut seen = HashSet::new();
    journal
        .iter()
        .rev()
        .filter(|entry| {
            matches!(
                entry.status,
                JournalStatus::Started | JournalStatus::Succeeded
            )
        })
        .filter(|entry| {
            entry.rollback.as_ref().is_some_and(|rollback| {
                rollback.supported && rollback.action.as_deref() == Some(rollback_action)
            })
        })
        .filter(|entry| seen.insert(entry.action_id.clone()))
        .cloned()
        .collect()
}

fn rollback_journal_entry(sequence: u64, action_id: &str, message: &str) -> ActionJournalEntry {
    ActionJournalEntry {
        sequence,
        action_id: action_id.to_owned(),
        status: JournalStatus::RolledBack,
        timestamp: None,
        message: Some(message.to_owned()),
        rollback: None,
        metadata: json!({}),
    }
}

fn expiry_rollback_needed(
    current: Option<u64>,
    prior: Option<u64>,
    attempted: u64,
) -> PluginResult<bool> {
    if current == prior {
        Ok(false)
    } else if current == Some(attempted) {
        Ok(true)
    } else {
        Err(PluginError::permanent(
            ErrorKind::Conflict,
            "rollback_continuity_lost",
            "Kubernetes namespace expiry no longer matches the prior or attempted plan",
        ))
    }
}

async fn annotate_namespace_expiry(
    settings: &Settings,
    namespace: &str,
    expiry: Option<u64>,
    cancellation: &crate::command::CancelState,
) -> PluginResult<()> {
    let annotation = expiry.map_or_else(
        || format!("{EXPIRES_AT_ANNOTATION}-"),
        |expiry| format!("{EXPIRES_AT_ANNOTATION}={expiry}"),
    );
    kubectl(
        settings,
        &[
            "annotate".to_owned(),
            "namespace".to_owned(),
            namespace.to_owned(),
            annotation,
            "--overwrite".to_owned(),
        ],
        None,
        settings.command_timeout(),
        Some(cancellation),
    )
    .await?;
    Ok(())
}

async fn reconcile_namespace_metadata(
    settings: &Settings,
    rendered: &RenderedEnvironment,
    desired: &DesiredState,
    revision: &str,
    cancellation: &crate::command::CancelState,
) -> PluginResult<()> {
    let namespace_owner = get_owned_namespace(
        settings,
        &rendered.namespace,
        &desired.project.id,
        Some(&desired.environment.id),
    )
    .await?
    .ok_or_else(|| {
        PluginError::permanent(
            ErrorKind::NotFound,
            "runtime_namespace_missing",
            "Kubernetes namespace disappeared before metadata reconciliation",
        )
    })?;
    ensure_observed_control_namespace(
        namespace_owner.control_namespace.as_deref(),
        &settings.control_namespace,
        &namespace_owner.name,
    )?;
    kubectl(
        settings,
        &[
            "label".to_owned(),
            "namespace".to_owned(),
            rendered.namespace.clone(),
            format!("{MANAGED_LABEL}=lightrail"),
            format!("{PROJECT_LABEL}={}", desired.project.id),
            format!("{ENVIRONMENT_LABEL}={}", desired.environment.id),
            format!(
                "{PROFILE_LABEL}={}",
                model_label(&desired.environment.profile)
            ),
            format!("lightrail.dev/revision={}", &revision[..16]),
            "--overwrite".to_owned(),
        ],
        None,
        settings.command_timeout(),
        Some(cancellation),
    )
    .await?;
    let namespace_hash = rendered
        .resources
        .iter()
        .find(|resource| resource.kind == "Namespace")
        .map(|resource| resource.spec_hash.as_str())
        .ok_or_else(|| stale_plan("rendered environment omitted Namespace"))?;
    kubectl(
        settings,
        &[
            "annotate".to_owned(),
            "namespace".to_owned(),
            rendered.namespace.clone(),
            format!("lightrail.dev/branch={}", desired.environment.branch),
            format!("lightrail.dev/spec-hash={namespace_hash}"),
            format!(
                "{CONTROL_NAMESPACE_ANNOTATION}={}",
                settings.control_namespace
            ),
            "--overwrite".to_owned(),
        ],
        None,
        settings.command_timeout(),
        Some(cancellation),
    )
    .await?;
    Ok(())
}

async fn ensure_owned_resource(
    settings: &Settings,
    namespace: &str,
    kind: &str,
    name: &str,
    project_id: &str,
    environment_id: &str,
) -> PluginResult<bool> {
    Ok(
        get_owned_resource(settings, namespace, kind, name, project_id, environment_id)
            .await?
            .is_some(),
    )
}

async fn get_owned_resource(
    settings: &Settings,
    namespace: &str,
    kind: &str,
    name: &str,
    project_id: &str,
    environment_id: &str,
) -> PluginResult<Option<Value>> {
    let result = kubectl_json(
        settings,
        &[
            "get".to_owned(),
            kind.to_ascii_lowercase(),
            name.to_owned(),
            "--namespace".to_owned(),
            namespace.to_owned(),
            "-o".to_owned(),
            "json".to_owned(),
        ],
        settings.command_timeout(),
    )
    .await;
    let object = match result {
        Ok(object) => object,
        Err(error) if error.kind == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let labels = object
        .pointer("/metadata/labels")
        .and_then(Value::as_object);
    let owned = labels.is_some_and(|labels| {
        labels.get(MANAGED_LABEL).and_then(Value::as_str) == Some("lightrail")
            && labels.get(PROJECT_LABEL).and_then(Value::as_str) == Some(project_id)
            && labels.get(ENVIRONMENT_LABEL).and_then(Value::as_str) == Some(environment_id)
    });
    if !owned {
        return Err(PluginError::permanent(
            ErrorKind::Conflict,
            "resource_ownership_mismatch",
            format!("Kubernetes {kind} `{namespace}/{name}` changed ownership before mutation"),
        ));
    }
    Ok(Some(object))
}

async fn delete_owned_resource_exact(
    settings: &Settings,
    namespace: &str,
    resource_key: &str,
    project_id: &str,
    environment_id: &str,
    cancellation: &crate::command::CancelState,
) -> PluginResult<()> {
    let (kind, name) = resource_key
        .split_once('/')
        .ok_or_else(|| stale_plan("rollback resource key is invalid"))?;
    if !ensure_owned_resource(settings, namespace, kind, name, project_id, environment_id).await? {
        return Ok(());
    }
    validate_selector_value("project ID", project_id)?;
    validate_selector_value("environment ID", environment_id)?;
    kubectl(
        settings,
        &[
            "delete".to_owned(),
            kind.to_ascii_lowercase(),
            "--namespace".to_owned(),
            namespace.to_owned(),
            "--selector".to_owned(),
            format!(
                "{MANAGED_LABEL}=lightrail,{PROJECT_LABEL}={project_id},{ENVIRONMENT_LABEL}={environment_id}"
            ),
            "--field-selector".to_owned(),
            format!("metadata.name={name}"),
            "--ignore-not-found=true".to_owned(),
            "--wait=true".to_owned(),
        ],
        None,
        settings.command_timeout(),
        Some(cancellation),
    )
    .await?;
    if ensure_owned_resource(settings, namespace, kind, name, project_id, environment_id).await? {
        return Err(PluginError::retryable(
            ErrorKind::Unavailable,
            "rollback_resource_remained",
            format!("Kubernetes {resource_key} remained after exact rollback deletion"),
        ));
    }
    Ok(())
}

fn validate_prior_manifest(
    manifest: &Value,
    namespace: &str,
    resource_key: &str,
    project_id: &str,
    environment_id: &str,
) -> PluginResult<()> {
    let (kind, name) = resource_key
        .split_once('/')
        .ok_or_else(|| stale_plan("rollback resource key is invalid"))?;
    let valid = manifest.get("kind").and_then(Value::as_str) == Some(kind)
        && manifest.pointer("/metadata/name").and_then(Value::as_str) == Some(name)
        && manifest
            .pointer("/metadata/namespace")
            .and_then(Value::as_str)
            == Some(namespace)
        && manifest
            .pointer("/metadata/labels/app.kubernetes.io~1managed-by")
            .and_then(Value::as_str)
            == Some("lightrail")
        && manifest
            .pointer("/metadata/labels/lightrail.dev~1project-id")
            .and_then(Value::as_str)
            == Some(project_id)
        && manifest
            .pointer("/metadata/labels/lightrail.dev~1environment-id")
            .and_then(Value::as_str)
            == Some(environment_id);
    if valid {
        Ok(())
    } else {
        Err(stale_plan(
            "exposure rollback manifest does not match exact owned resource identity",
        ))
    }
}

#[allow(clippy::too_many_lines)]
async fn restore_exposure_entries(
    settings: &Settings,
    entries: &[ActionJournalEntry],
    project_id: &str,
    environment_id: &str,
    locks: &LeaseLocks,
    operation_id: &str,
    cancellation: &crate::command::CancelState,
) -> PluginResult<()> {
    ensure_existing_environment_control_namespace(settings, project_id, environment_id).await?;
    let mut restores = Vec::new();
    let mut deletes = Vec::new();
    for entry in entries {
        let rollback = entry
            .rollback
            .as_ref()
            .ok_or_else(|| stale_plan("exposure rollback journal omitted metadata"))?;
        let namespace = rollback
            .metadata
            .get("namespace")
            .and_then(Value::as_str)
            .ok_or_else(|| stale_plan("exposure rollback omitted namespace"))?;
        let resource_key = rollback
            .metadata
            .get("resource_key")
            .and_then(Value::as_str)
            .ok_or_else(|| stale_plan("exposure rollback omitted resource key"))?;
        let prior_manifest = rollback
            .metadata
            .get("prior_manifest")
            .ok_or_else(|| stale_plan("exposure rollback omitted prior manifest"))?;
        if prior_manifest.is_null() {
            deletes.push((namespace, resource_key));
        } else {
            validate_prior_manifest(
                prior_manifest,
                namespace,
                resource_key,
                project_id,
                environment_id,
            )?;
            restores.push((namespace, resource_key, prior_manifest));
        }
    }
    restores.sort_by_key(|(_, resource_key, _)| !resource_key.starts_with("Middleware/"));
    for (namespace, resource_key, manifest) in restores {
        locks.assert_authority(settings, operation_id).await?;
        let (kind, name) = resource_key
            .split_once('/')
            .ok_or_else(|| stale_plan("rollback resource key is invalid"))?;
        let current =
            get_owned_resource(settings, namespace, kind, name, project_id, environment_id)
                .await?
                .ok_or_else(|| {
                    PluginError::permanent(
                        ErrorKind::Conflict,
                        "rollback_resource_missing",
                        format!("Kubernetes {resource_key} disappeared before exposure rollback"),
                    )
                })?;
        if !exposure_restore_needed(
            &sanitized_owned_manifest(&current)?,
            manifest,
            current
                .pointer("/metadata/annotations/lightrail.dev~1spec-hash")
                .and_then(Value::as_str),
            manifest_attempted_hash(entries, resource_key)?,
        )? {
            continue;
        }
        kubectl(
            settings,
            &[
                "apply".to_owned(),
                "--server-side".to_owned(),
                "--field-manager=lightrail".to_owned(),
                "-f".to_owned(),
                "-".to_owned(),
            ],
            Some(serde_json::to_vec(manifest).map_err(serialization_error)?),
            settings.command_timeout(),
            Some(cancellation),
        )
        .await?;
        let restored_object =
            get_owned_resource(settings, namespace, kind, name, project_id, environment_id)
                .await?
                .ok_or_else(|| {
                    PluginError::retryable(
                        ErrorKind::Unavailable,
                        "rollback_resource_missing",
                        format!("Kubernetes {resource_key} disappeared during exposure rollback"),
                    )
                })?;
        if !sanitized_owned_manifest(&restored_object)?.eq(manifest) {
            return Err(PluginError::retryable(
                ErrorKind::Unavailable,
                "rollback_not_ready",
                format!("Kubernetes {resource_key} did not restore its prior manifest"),
            ));
        }
    }
    deletes.sort_by_key(|(_, resource_key)| !resource_key.starts_with("Ingress/"));
    for (namespace, resource_key) in deletes {
        locks.assert_authority(settings, operation_id).await?;
        let (kind, name) = resource_key
            .split_once('/')
            .ok_or_else(|| stale_plan("rollback resource key is invalid"))?;
        let current =
            get_owned_resource(settings, namespace, kind, name, project_id, environment_id).await?;
        let Some(current) = current else {
            continue;
        };
        let attempted_spec_hash = manifest_attempted_hash(entries, resource_key)?;
        if current
            .pointer("/metadata/annotations/lightrail.dev~1spec-hash")
            .and_then(Value::as_str)
            != Some(attempted_spec_hash)
        {
            return Err(PluginError::permanent(
                ErrorKind::Conflict,
                "rollback_continuity_lost",
                format!("Kubernetes {resource_key} no longer matches the attempted exposure plan"),
            ));
        }
        delete_owned_resource_exact(
            settings,
            namespace,
            resource_key,
            project_id,
            environment_id,
            cancellation,
        )
        .await?;
    }
    locks.assert_authority(settings, operation_id).await?;
    Ok(())
}

fn manifest_attempted_hash<'a>(
    entries: &'a [ActionJournalEntry],
    resource_key: &str,
) -> PluginResult<&'a str> {
    entries
        .iter()
        .find_map(|entry| {
            let rollback = entry.rollback.as_ref()?;
            (rollback
                .metadata
                .get("resource_key")
                .and_then(Value::as_str)
                == Some(resource_key))
            .then(|| {
                rollback
                    .metadata
                    .get("attempted_spec_hash")
                    .and_then(Value::as_str)
            })
            .flatten()
        })
        .ok_or_else(|| stale_plan("exposure rollback omitted attempted spec hash"))
}

fn exposure_restore_needed(
    current_manifest: &Value,
    prior_manifest: &Value,
    current_spec_hash: Option<&str>,
    attempted_spec_hash: &str,
) -> PluginResult<bool> {
    if current_manifest == prior_manifest {
        Ok(false)
    } else if current_spec_hash == Some(attempted_spec_hash) {
        Ok(true)
    } else {
        Err(PluginError::permanent(
            ErrorKind::Conflict,
            "rollback_continuity_lost",
            "Kubernetes exposure resource no longer matches the prior or attempted plan",
        ))
    }
}

async fn delete_namespace_exact(
    settings: &Settings,
    namespace: &str,
    project_id: &str,
    environment_id: &str,
    cancellation: &crate::command::CancelState,
) -> PluginResult<bool> {
    validate_selector_value("namespace", namespace)?;
    validate_selector_value("project ID", project_id)?;
    validate_selector_value("environment ID", environment_id)?;
    let Some(owner) =
        get_owned_namespace(settings, namespace, project_id, Some(environment_id)).await?
    else {
        return Ok(true);
    };
    ensure_observed_control_namespace(
        owner.control_namespace.as_deref(),
        &settings.control_namespace,
        &owner.name,
    )?;
    kubectl(
        settings,
        &[
            "delete".to_owned(),
            "namespaces".to_owned(),
            "--selector".to_owned(),
            format!(
                "{MANAGED_LABEL}=lightrail,{PROJECT_LABEL}={project_id},{ENVIRONMENT_LABEL}={environment_id}"
            ),
            "--field-selector".to_owned(),
            format!("metadata.name={namespace}"),
            "--ignore-not-found=true".to_owned(),
            "--wait=true".to_owned(),
            "--timeout".to_owned(),
            format!("{}s", settings.readiness_timeout().as_secs()),
        ],
        None,
        settings.readiness_timeout(),
        Some(cancellation),
    )
    .await?;
    Ok(
        get_owned_namespace(settings, namespace, project_id, Some(environment_id))
            .await?
            .is_none(),
    )
}

fn destroy_namespaces_from_current(current: Option<&Value>, all: bool) -> Vec<(String, String)> {
    let Some(current) = current else {
        return Vec::new();
    };
    if all {
        let mut namespaces = current
            .get("environments")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|environment| {
                environment.get("present").and_then(Value::as_bool) != Some(false)
            })
            .filter_map(|environment| {
                Some((
                    environment.get("namespace")?.as_str()?.to_owned(),
                    environment
                        .get("environment_id")
                        .or_else(|| environment.get("id"))?
                        .as_str()?
                        .to_owned(),
                ))
            })
            .collect::<Vec<_>>();
        namespaces.sort();
        namespaces.dedup();
        return namespaces;
    }
    if current.get("present").and_then(Value::as_bool) != Some(true) {
        return Vec::new();
    }
    current
        .get("namespace")
        .and_then(Value::as_str)
        .map(|namespace| {
            (
                namespace.to_owned(),
                current
                    .get("environment_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            )
        })
        .into_iter()
        .collect()
}

fn runtime_destroy_targets(
    current: Option<&Value>,
    all: bool,
    operation: Operation,
    namespace_prefix: &str,
    environment_id: &str,
) -> Vec<(String, String)> {
    if operation == Operation::RollbackCleanup {
        return vec![(
            namespace_name(namespace_prefix, environment_id),
            environment_id.to_owned(),
        )];
    }
    destroy_namespaces_from_current(current, all)
}

fn prune_namespaces_from_current(
    current: Option<&Value>,
    selected_environment_ids: &[String],
) -> PluginResult<Vec<(String, String)>> {
    let selected = selected_environment_ids.iter().collect::<BTreeSet<_>>();
    let observed = destroy_namespaces_from_current(current, true);
    let observed_ids = observed
        .iter()
        .map(|(_, environment_id)| environment_id)
        .collect::<BTreeSet<_>>();
    let unknown = selected
        .difference(&observed_ids)
        .copied()
        .collect::<Vec<_>>();
    if !unknown.is_empty() {
        return Err(PluginError::permanent(
            ErrorKind::NotFound,
            "prune_selection_unknown",
            format!(
                "selected Kubernetes environments are absent from the locked inspection: {}",
                unknown
                    .into_iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
    }
    Ok(observed
        .into_iter()
        .filter(|(_, environment_id)| selected.contains(environment_id))
        .collect())
}

fn validate_selector_value(label: &str, value: &str) -> PluginResult<()> {
    let valid = !value.is_empty()
        && value.len() <= 63
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
        && value
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_alphanumeric())
        && value
            .chars()
            .last()
            .is_some_and(|character| character.is_ascii_alphanumeric());
    if valid {
        Ok(())
    } else {
        Err(PluginError::permanent(
            ErrorKind::Validation,
            "invalid_ownership_selector",
            format!("{label} cannot be represented as an exact Kubernetes ownership selector"),
        ))
    }
}

fn filter_resource_state(resources: &Value, role: ResourceRole) -> Value {
    let Some(resources) = resources.as_object() else {
        return json!({});
    };
    Value::Object(
        resources
            .iter()
            .filter(|(key, _)| resource_belongs_to_role(key, role))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    )
}

fn resource_belongs_to_role(key: &str, role: ResourceRole) -> bool {
    match role {
        ResourceRole::Exposure => key.starts_with("Ingress/") || key.starts_with("Middleware/"),
        ResourceRole::Runtime => !key.starts_with("Ingress/") && !key.starts_with("Middleware/"),
    }
}

fn ensure_namespace_continuity(
    current: Option<&Value>,
    desired_namespace: &str,
) -> PluginResult<()> {
    let Some(current) =
        current.filter(|state| state.get("present").and_then(Value::as_bool) == Some(true))
    else {
        return Ok(());
    };
    let observed_namespace = current
        .get("namespace")
        .and_then(Value::as_str)
        .ok_or_else(|| stale_plan("present Kubernetes state omitted its namespace"))?;
    if observed_namespace == desired_namespace {
        return Ok(());
    }
    Err(PluginError::permanent(
        ErrorKind::Conflict,
        "kubernetes_down_required",
        format!(
            "the existing environment owns namespace `{observed_namespace}`, but the active namespace_prefix selects `{desired_namespace}`; run `lightrail down` and then `lightrail up` before changing namespace identity"
        ),
    ))
}

fn ensure_control_namespace_continuity(
    current: Option<&Value>,
    configured: &str,
) -> PluginResult<()> {
    let Some(current) = current else {
        return Ok(());
    };
    if current.get("present").and_then(Value::as_bool) == Some(true) {
        ensure_observed_control_namespace(
            current.get("control_namespace").and_then(Value::as_str),
            configured,
            current
                .get("namespace")
                .and_then(Value::as_str)
                .unwrap_or("current environment"),
        )?;
    }
    for environment in current
        .get("environments")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|environment| environment.get("present").and_then(Value::as_bool) != Some(false))
    {
        ensure_observed_control_namespace(
            environment.get("control_namespace").and_then(Value::as_str),
            configured,
            environment
                .get("namespace")
                .and_then(Value::as_str)
                .unwrap_or("selected environment"),
        )?;
    }
    Ok(())
}

fn ensure_observed_control_namespace(
    observed: Option<&str>,
    configured: &str,
    namespace: &str,
) -> PluginResult<()> {
    if observed == Some(configured) {
        return Ok(());
    }
    Err(PluginError::permanent(
        ErrorKind::Conflict,
        "control_namespace_drift",
        format!(
            "owned Kubernetes namespace `{namespace}` records control namespace `{}`, but the active profile selects `{configured}`; restore the recorded profile setting before mutation",
            observed.unwrap_or("<missing>")
        ),
    ))
}

async fn ensure_existing_environment_control_namespace(
    settings: &Settings,
    project_id: &str,
    environment_id: &str,
) -> PluginResult<()> {
    let matches = list_owned_namespaces(settings, project_id)
        .await?
        .into_iter()
        .filter(|namespace| namespace.environment_id == environment_id)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Ok(()),
        [namespace] => ensure_observed_control_namespace(
            namespace.control_namespace.as_deref(),
            &settings.control_namespace,
            &namespace.name,
        ),
        _ => Err(PluginError::permanent(
            ErrorKind::Conflict,
            "environment_namespace_ambiguous",
            format!(
                "multiple owned Kubernetes namespaces claim environment `{environment_id}`; refusing to choose a lock authority"
            ),
        )),
    }
}

fn ensure_no_stale_resources(
    current_resources: &Map<String, Value>,
    desired_resources: &BTreeMap<String, &RenderedResource>,
    role: ResourceRole,
) -> PluginResult<()> {
    let stale_resources = current_resources
        .keys()
        .filter(|key| !desired_resources.contains_key(*key) && resource_belongs_to_role(key, role))
        .cloned()
        .collect::<Vec<_>>();
    if stale_resources.is_empty() {
        Ok(())
    } else {
        Err(PluginError::permanent(
            ErrorKind::Conflict,
            "kubernetes_down_required",
            format!(
                "the desired Compose model removes owned Kubernetes resources ({}); run `lightrail down` and then `lightrail up` so an up plan never performs destructive replacement",
                stale_resources.join(", ")
            ),
        ))
    }
}

fn ensure_no_runtime_additions(
    current_resources: &Map<String, Value>,
    desired_resources: &BTreeMap<String, &RenderedResource>,
    prior_revision: Option<&str>,
) -> PluginResult<()> {
    if prior_revision.is_none() {
        return Ok(());
    }
    let additions = desired_resources
        .keys()
        .filter(|key| !current_resources.contains_key(*key))
        .cloned()
        .collect::<Vec<_>>();
    if additions.is_empty() {
        Ok(())
    } else {
        Err(PluginError::permanent(
            ErrorKind::Conflict,
            "kubernetes_down_required",
            format!(
                "the desired Compose model adds Runtime resources that cannot be exactly rolled back ({}); run `lightrail down` and then `lightrail up`",
                additions.join(", ")
            ),
        ))
    }
}

fn job_needs_create(
    resource: &RenderedResource,
    observed_hash: Option<&str>,
) -> PluginResult<bool> {
    let Some(observed_hash) = observed_hash else {
        return Ok(true);
    };
    if observed_hash == resource.spec_hash {
        // Jobs are immutable and completed Jobs are retained only briefly.
        // Their pinned spec-hash is the continuity boundary: changing a
        // present Job requires an explicit environment teardown.
        Ok(false)
    } else {
        Err(PluginError::permanent(
            ErrorKind::Conflict,
            "kubernetes_job_replacement_requires_down",
            format!(
                "owned Kubernetes Job {} changed and cannot be replaced by a non-destructive up; run `lightrail down` and then `lightrail up`",
                resource.name
            ),
        ))
    }
}

fn rollback_for_resource(
    capability: &Capability,
    resource: &RenderedResource,
    namespace: &str,
    prior_exposure_manifests: Option<&Map<String, Value>>,
    resource_existed: bool,
) -> Option<RollbackMetadata> {
    match capability {
        Capability::Exposure => {
            let prior_manifest =
                prior_exposure_manifests.and_then(|manifests| manifests.get(&resource.key));
            if resource_existed && prior_manifest.is_none() {
                Some(RollbackMetadata {
                    supported: false,
                    action: None,
                    token: None,
                    metadata: json!({
                        "namespace": namespace,
                        "resource_key": resource.key,
                        "reason": "existing Kubernetes exposure state omitted its complete prior owned manifest",
                    }),
                })
            } else {
                Some(RollbackMetadata {
                    supported: true,
                    action: Some("exposure.restore-previous".to_owned()),
                    token: None,
                    metadata: json!({
                        "namespace": namespace,
                        "resource_key": resource.key,
                        "attempted_spec_hash": resource.spec_hash,
                        "prior_manifest": prior_manifest.cloned().unwrap_or(Value::Null),
                    }),
                })
            }
        }
        Capability::Runtime => Some(RollbackMetadata {
            supported: false,
            action: None,
            token: None,
            metadata: json!({
                "namespace": namespace,
                "resource_key": resource.key,
                "reason": format!(
                    "Kubernetes {} changes do not retain a complete, secret-safe prior object",
                    resource.kind
                ),
            }),
        }),
        _ => None,
    }
}

fn namespace_delete_rollback(namespace: &str) -> RollbackMetadata {
    RollbackMetadata {
        supported: false,
        action: None,
        token: None,
        metadata: json!({
            "namespace": namespace,
            "reason": "namespace deletion cannot be reversed exactly because Kubernetes does not retain the deleted workloads, Secrets, PVC objects, or application data",
        }),
    }
}

fn traefik_middleware_resource_type(target: &Value) -> Option<&'static str> {
    match target
        .pointer("/ingress/traefik_middleware_api_version")
        .and_then(Value::as_str)
    {
        Some("traefik.io/v1alpha1") => Some("middlewares.traefik.io"),
        Some("traefik.containo.us/v1alpha1") => Some("middlewares.traefik.containo.us"),
        _ => None,
    }
}

fn capability_role(capability: &Capability) -> PluginResult<ResourceRole> {
    match capability {
        Capability::Runtime => Ok(ResourceRole::Runtime),
        Capability::Exposure => Ok(ResourceRole::Exposure),
        _ => Err(PluginError::permanent(
            ErrorKind::Validation,
            "resource_capability_required",
            "capability does not own Kubernetes resources",
        )),
    }
}

fn dependencies(
    resource: &RenderedResource,
    resources: &[RenderedResource],
    namespace_needs_apply: bool,
) -> Vec<String> {
    if resource.kind == "Namespace" || !namespace_needs_apply {
        return Vec::new();
    }
    resources
        .iter()
        .find(|candidate| candidate.kind == "Namespace")
        .map(|namespace| vec![format!("apply-namespace-{}", namespace.name)])
        .unwrap_or_default()
}

fn finalize_plan(actions: Vec<PlannedAction>, metadata: Value) -> PluginResult<PlanResult> {
    let has_changes = !actions.is_empty();
    let plan_id = plan_digest(&actions, &metadata)?;
    Ok(PlanResult {
        plan_id,
        actions,
        has_changes,
        metadata,
    })
}

fn plan_digest(actions: &[PlannedAction], metadata: &Value) -> PluginResult<String> {
    let bytes = serde_json::to_vec(&json!({
        "actions": actions,
        "metadata": metadata,
    }))
    .map_err(serialization_error)?;
    Ok(format!("kubernetes-{}", hex::encode(Sha256::digest(bytes))))
}

fn validate_plan_digest(plan: &PlanResult) -> PluginResult<()> {
    if plan.plan_id != plan_digest(&plan.actions, &plan.metadata)? {
        return Err(stale_plan(
            "Kubernetes plan ID does not match its exact actions and metadata",
        ));
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
        Err(PluginError::permanent(
            ErrorKind::Unsupported,
            "unsupported_capability",
            format!("Kubernetes plugin does not serve capability `{capability}`"),
        ))
    }
}

fn safe_action_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_owned()
}

fn model_label(value: &str) -> String {
    crate::model::dns_label(value)
}

fn stale_plan(message: impl Into<String>) -> PluginError {
    PluginError::permanent(ErrorKind::Conflict, "stale_plan", message)
}

fn serialization_error(error: impl std::fmt::Display) -> PluginError {
    PluginError::permanent(
        ErrorKind::Internal,
        "serialization_failed",
        format!("failed to serialize Kubernetes protocol state: {error}"),
    )
}

fn journal_entry(
    sequence: u64,
    action_id: &str,
    status: JournalStatus,
    message: &str,
) -> ActionJournalEntry {
    ActionJournalEntry {
        sequence,
        action_id: action_id.to_owned(),
        status,
        timestamp: None,
        message: Some(message.to_owned()),
        rollback: None,
        metadata: json!({}),
    }
}

fn journal_entry_for_action(
    sequence: u64,
    action: &PlannedAction,
    status: JournalStatus,
    message: &str,
) -> ActionJournalEntry {
    ActionJournalEntry {
        sequence,
        action_id: action.id.clone(),
        status,
        timestamp: None,
        message: Some(message.to_owned()),
        rollback: action.rollback.clone(),
        metadata: action.metadata.clone(),
    }
}

fn append_skipped(
    mut journal: Vec<ActionJournalEntry>,
    action_id: &str,
    message: &str,
) -> Vec<ActionJournalEntry> {
    journal.push(journal_entry(
        journal.len() as u64 + 1,
        action_id,
        JournalStatus::Skipped,
        message,
    ));
    journal
}

async fn emit_progress(events: &EventSink, operation_id: &str, message: &str) -> PluginResult<()> {
    events
        .emit(&PluginEvent::Progress {
            operation_id: operation_id.to_owned(),
            message: message.to_owned(),
            completed: None,
            total: None,
        })
        .await
        .map_err(|error| {
            PluginError::permanent(
                ErrorKind::Internal,
                "event_output_failed",
                format!("failed emitting plugin progress: {error}"),
            )
        })
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
                ErrorKind::Internal,
                "event_output_failed",
                format!("failed emitting plugin journal: {error}"),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_is_existing_cluster_and_selected_destroy_capable() {
        let manifest = KubernetesPlugin::default().manifest();
        assert_eq!(manifest.id, PLUGIN_ID);
        assert!(manifest.capabilities.contains(&Capability::OperationLock));
        assert!(
            manifest
                .features
                .contains(&SELECTED_DESTROY_FEATURE.to_owned())
        );
    }

    #[test]
    fn plan_digest_rejects_modified_actions() {
        let mut plan = finalize_plan(
            vec![PlannedAction {
                id: "apply".to_owned(),
                kind: "kubernetes.apply".to_owned(),
                summary: "apply".to_owned(),
                destructive: false,
                depends_on: Vec::new(),
                rollback: None,
                metadata: json!({}),
            }],
            json!({"schema": 1}),
        )
        .expect("plan");
        assert!(validate_plan_digest(&plan).is_ok());
        plan.actions[0].summary = "modified".to_owned();
        assert_eq!(
            validate_plan_digest(&plan).expect_err("modified").kind,
            ErrorKind::Conflict
        );
    }

    #[test]
    fn selected_prune_requires_exact_contract() {
        let selection = crate::model::Selection {
            schema: 1,
            reason: "expired".to_owned(),
            environment_ids: vec!["lr-one".to_owned()],
        };
        assert!(selection.validate_prune().is_ok());
        let missing = crate::model::Selection::default();
        assert_eq!(
            missing.validate_prune().expect_err("missing").kind,
            ErrorKind::Validation
        );
    }

    #[test]
    fn ingress_addresses_come_only_from_the_exact_configured_service() {
        let service = json!({
            "metadata": {"namespace": "ingress-nginx", "name": "controller"},
            "spec": {"type": "LoadBalancer"},
            "status": {
                "loadBalancer": {
                    "ingress": [
                        {"ip": "1.2.3.4"},
                        {"hostname": "edge.example.test"}
                    ]
                }
            }
        });
        assert_eq!(
            ingress_service_addresses(&service).expect("exact LoadBalancer"),
            vec!["1.2.3.4".to_owned(), "edge.example.test".to_owned()]
        );
        assert_eq!(
            ingress_service_addresses(&json!({"spec": {"type": "ClusterIP"}}))
                .expect_err("ClusterIP must not be guessed as ingress")
                .code,
            "ingress_service_not_load_balancer"
        );
    }

    #[test]
    fn cluster_issuer_must_be_ready_and_offer_http01() {
        let ready = json!({
            "spec": {"acme": {"solvers": [{"http01": {"ingress": {}}}]}},
            "status": {"conditions": [{"type": "Ready", "status": "True"}]}
        });
        assert!(cluster_issuer_supports_http01(&ready));
        assert!(!cluster_issuer_supports_http01(&json!({
            "spec": {"acme": {"solvers": [{"dns01": {"route53": {}}}]}},
            "status": {"conditions": [{"type": "Ready", "status": "True"}]}
        })));
        assert!(!cluster_issuer_supports_http01(&json!({
            "spec": {"acme": {"solvers": [{"http01": {"ingress": {}}}]}},
            "status": {"conditions": [{"type": "Ready", "status": "False"}]}
        })));
    }

    #[test]
    fn middleware_discovery_requires_the_exact_traefik_resource() {
        assert!(has_middleware_resource(&json!({
            "resources": [{"name": "middlewares", "kind": "Middleware"}]
        })));
        assert!(!has_middleware_resource(&json!({
            "resources": [{"name": "middlewaretcps", "kind": "MiddlewareTCP"}]
        })));
        assert_eq!(
            traefik_middleware_resource_type(&json!({
                "ingress": {
                    "traefik_middleware_api_version": "traefik.io/v1alpha1"
                }
            })),
            Some("middlewares.traefik.io")
        );
    }

    #[test]
    fn platform_discovery_uses_only_ready_schedulable_nodes() {
        let nodes = json!({
            "items": [
                {
                    "spec": {},
                    "status": {
                        "conditions": [{"type": "Ready", "status": "True"}],
                        "nodeInfo": {"architecture": "amd64"}
                    }
                },
                {
                    "spec": {"unschedulable": true},
                    "status": {
                        "conditions": [{"type": "Ready", "status": "True"}],
                        "nodeInfo": {"architecture": "arm64"}
                    }
                },
                {
                    "spec": {"taints": [{"effect": "NoSchedule"}]},
                    "status": {
                        "conditions": [{"type": "Ready", "status": "True"}],
                        "nodeInfo": {"architecture": "arm64"}
                    }
                }
            ]
        });
        assert_eq!(
            node_platforms(&nodes).expect("one schedulable platform"),
            vec!["linux/amd64".to_owned()]
        );
        let settings = Settings {
            context: "spot".to_owned(),
            registry: "ghcr.io".to_owned(),
            repository: "team/lightrail".to_owned(),
            ingress_class: "nginx".to_owned(),
            cluster_issuer: "letsencrypt".to_owned(),
            platforms: vec!["linux/arm64".to_owned(), "linux/amd64".to_owned()],
            ..Settings::default()
        };
        assert_eq!(
            effective_platforms(&settings, &Value::Null).expect("explicit platforms"),
            vec!["linux/amd64".to_owned(), "linux/arm64".to_owned()]
        );
        assert!(
            validate_explicit_platforms(
                &["linux/amd64".to_owned()],
                &["linux/amd64".to_owned(), "linux/arm64".to_owned()]
            )
            .is_ok()
        );
        assert_eq!(
            validate_explicit_platforms(&["linux/arm64".to_owned()], &["linux/amd64".to_owned()])
                .expect_err("explicit platform must be schedulable")
                .code,
            "explicit_platform_unavailable"
        );
    }

    #[test]
    fn namespace_prefix_change_is_discovered_and_requires_down_then_up() {
        let old_namespace = OwnedNamespace {
            name: "old-lr-environment".to_owned(),
            environment_id: "lr-environment".to_owned(),
            project_id: "project".to_owned(),
            profile: Some("preview".to_owned()),
            branch: Some("feature".to_owned()),
            control_namespace: Some("lightrail-system".to_owned()),
            expires_at_unix: None,
        };
        assert_eq!(
            environment_namespace_from_inventory(
                std::slice::from_ref(&old_namespace),
                "new-lr-environment",
                "lr-environment",
            )
            .expect("owned prior namespace"),
            old_namespace.name
        );
        let current = json!({
            "present": true,
            "namespace": "old-lr-environment",
            "environment_id": "lr-environment"
        });
        assert_eq!(
            ensure_namespace_continuity(Some(&current), "new-lr-environment")
                .expect_err("changed namespace prefix")
                .code,
            "kubernetes_down_required"
        );

        let duplicate_namespace = OwnedNamespace {
            name: "duplicate-lr-environment".to_owned(),
            ..old_namespace
        };
        assert_eq!(
            environment_namespace_from_inventory(
                &[duplicate_namespace.clone(), duplicate_namespace],
                "new-lr-environment",
                "lr-environment",
            )
            .expect_err("ambiguous environment ownership")
            .code,
            "environment_namespace_ambiguous"
        );
    }

    #[test]
    fn control_namespace_drift_blocks_mutation_plans() {
        let current = json!({
            "present": true,
            "namespace": "lr-preview",
            "control_namespace": "original-locks"
        });
        assert_eq!(
            ensure_control_namespace_continuity(Some(&current), "new-locks")
                .expect_err("changed lock authority")
                .code,
            "control_namespace_drift"
        );
        assert_eq!(
            ensure_control_namespace_continuity(
                Some(&json!({
                    "environments": [{
                        "present": true,
                        "namespace": "lr-preview"
                    }]
                })),
                "original-locks"
            )
            .expect_err("missing authority annotation must fail closed")
            .code,
            "control_namespace_drift"
        );
        assert!(
            ensure_control_namespace_continuity(
                Some(&json!({
                    "present": true,
                    "namespace": "lr-preview",
                    "control_namespace": "original-locks"
                })),
                "original-locks"
            )
            .is_ok()
        );
    }

    #[test]
    fn concurrent_initial_namespace_claim_cannot_change_lock_authority() {
        let desired = RenderedResource {
            key: "Namespace/lr-preview".to_owned(),
            kind: "Namespace".to_owned(),
            name: "lr-preview".to_owned(),
            role: ResourceRole::Runtime,
            manifest: json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": "lr-preview",
                    "labels": {
                        MANAGED_LABEL: "lightrail",
                        PROJECT_LABEL: "project",
                        ENVIRONMENT_LABEL: "environment"
                    },
                    "annotations": {
                        CONTROL_NAMESPACE_ANNOTATION: "locks-a",
                        "lightrail.dev/spec-hash": "claim-a"
                    }
                }
            }),
            spec_hash: "claim-a".to_owned(),
        };
        let settings = Settings {
            control_namespace: "locks-a".to_owned(),
            ..Settings::default()
        };
        assert!(
            validate_namespace_claim(&desired.manifest, &desired, &settings).is_ok(),
            "an exact lost-response replay is idempotent"
        );

        let mut other_authority = desired.manifest.clone();
        other_authority["metadata"]["annotations"][CONTROL_NAMESPACE_ANNOTATION] =
            Value::String("locks-b".to_owned());
        assert_eq!(
            validate_namespace_claim(&other_authority, &desired, &settings)
                .expect_err("a competing first-up lock authority must fail")
                .code,
            "control_namespace_drift"
        );

        let mut other_plan = desired.manifest.clone();
        other_plan["metadata"]["annotations"]["lightrail.dev/spec-hash"] =
            Value::String("claim-b".to_owned());
        assert_eq!(
            validate_namespace_claim(&other_plan, &desired, &settings)
                .expect_err("a competing first-up plan must fail")
                .code,
            "namespace_claim_spec_conflict"
        );
    }

    #[test]
    fn destroy_plan_uses_only_observed_namespaces_without_compose() {
        let current = json!({
            "environments": [
                {"environment_id": "lr-b", "namespace": "lr-b-ns"},
                {"environment_id": "lr-a", "namespace": "lr-a-ns"}
            ]
        });
        assert_eq!(
            destroy_namespaces_from_current(Some(&current), true),
            vec![
                ("lr-a-ns".to_owned(), "lr-a".to_owned()),
                ("lr-b-ns".to_owned(), "lr-b".to_owned())
            ]
        );
        assert!(destroy_namespaces_from_current(None, false).is_empty());
    }

    #[test]
    fn namespace_deletion_declares_an_explicit_unsupported_inverse() {
        let rollback = namespace_delete_rollback("lr-preview");
        assert!(!rollback.supported);
        assert!(rollback.action.is_none());
        assert_eq!(rollback.metadata["namespace"], "lr-preview");
        assert!(
            rollback.metadata["reason"]
                .as_str()
                .is_some_and(|reason| !reason.is_empty())
        );
    }

    #[tokio::test]
    async fn repeated_plan_inputs_for_one_operation_keep_the_same_expiry_and_id() {
        let plugin = KubernetesPlugin::default();
        let first_expiry = plugin
            .operation_expiry("operation-stable", 72)
            .await
            .expect("first expiry");
        tokio::time::sleep(Duration::from_millis(1)).await;
        let second_expiry = plugin
            .operation_expiry("operation-stable", 72)
            .await
            .expect("second expiry");
        assert_eq!(first_expiry, second_expiry);

        let first = finalize_plan(Vec::new(), json!({"expires_at_unix": first_expiry}))
            .expect("first plan");
        let second = finalize_plan(Vec::new(), json!({"expires_at_unix": second_expiry}))
            .expect("second plan");
        assert_eq!(first.plan_id, second.plan_id);
    }

    #[test]
    fn kube_api_loopback_detection_includes_ipv4_mapped_ipv6() {
        assert!(is_loopback_address(IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST
        )));
        assert!(is_loopback_address(IpAddr::V6(std::net::Ipv6Addr::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1
        ]))));
        assert!(!is_loopback_address(IpAddr::V4(std::net::Ipv4Addr::new(
            10, 0, 0, 1
        ))));
    }

    #[test]
    fn redirect_probe_requires_same_host_trusted_https_location() {
        let expected = Url::parse("https://feature.example.test/path").expect("url");
        assert!(redirect_location_valid(
            StatusCode::PERMANENT_REDIRECT,
            Some("https://feature.example.test/path"),
            &expected
        ));
        assert!(!redirect_location_valid(
            StatusCode::OK,
            Some("https://feature.example.test/path"),
            &expected
        ));
        assert!(!redirect_location_valid(
            StatusCode::FOUND,
            Some("https://attacker.example/path"),
            &expected
        ));
        assert!(!redirect_location_valid(
            StatusCode::FOUND,
            Some("http://feature.example.test/path"),
            &expected
        ));
    }

    #[test]
    fn default_health_accepts_401_but_configured_status_is_exact() {
        assert!(health_status_matches(StatusCode::UNAUTHORIZED, None));
        assert!(health_status_matches(StatusCode::NO_CONTENT, Some(204)));
        assert!(!health_status_matches(StatusCode::OK, Some(204)));
        assert!(!health_status_matches(
            StatusCode::INTERNAL_SERVER_ERROR,
            None
        ));
    }

    #[tokio::test]
    async fn endpoint_checks_are_polled_concurrently() {
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let checks = (0..2).map(|_| {
            let barrier = std::sync::Arc::clone(&barrier);
            async move {
                barrier.wait().await;
                Ok(())
            }
        });
        timeout(Duration::from_millis(100), join_endpoint_checks(checks))
            .await
            .expect("concurrent checks must meet at the barrier")
            .expect("checks");
    }

    #[tokio::test]
    async fn runtime_readiness_checks_share_one_concurrent_phase_deadline() {
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let checks = (0..2).map(|_| {
            let barrier = std::sync::Arc::clone(&barrier);
            async move {
                barrier.wait().await;
                Ok(())
            }
        });
        timeout(
            Duration::from_millis(100),
            join_runtime_checks(checks, Duration::from_secs(1)),
        )
        .await
        .expect("workload checks must meet concurrently")
        .expect("checks");

        let error = join_runtime_checks(
            [std::future::pending::<PluginResult<()>>()],
            Duration::from_millis(10),
        )
        .await
        .expect_err("one overall deadline must bound the readiness phase");
        assert_eq!(error.code, "runtime_readiness_timeout");
    }

    #[test]
    fn destroy_includes_present_empty_namespace_and_skips_absent() {
        let present = json!({
            "namespace": "lr-empty",
            "environment_id": "lr-env",
            "present": true,
            "resources": {}
        });
        assert_eq!(
            destroy_namespaces_from_current(Some(&present), false),
            vec![("lr-empty".to_owned(), "lr-env".to_owned())]
        );
        let absent = json!({
            "namespace": "lr-empty",
            "environment_id": "lr-env",
            "present": false,
            "resources": {}
        });
        assert!(destroy_namespaces_from_current(Some(&absent), false).is_empty());
        assert_eq!(
            runtime_destroy_targets(
                Some(&absent),
                false,
                Operation::RollbackCleanup,
                "lr",
                "lr-new-environment",
            ),
            vec![(
                namespace_name("lr", "lr-new-environment"),
                "lr-new-environment".to_owned()
            )]
        );
    }

    #[test]
    fn prune_selection_is_limited_to_locked_current_state() {
        let current = json!({
            "environments": [
                {"environment_id": "lr-a", "namespace": "lr-a-ns", "present": true},
                {"environment_id": "lr-b", "namespace": "lr-b-ns", "present": true}
            ]
        });
        assert_eq!(
            prune_namespaces_from_current(Some(&current), &["lr-b".to_owned()]).expect("selection"),
            vec![("lr-b-ns".to_owned(), "lr-b".to_owned())]
        );
        assert_eq!(
            prune_namespaces_from_current(Some(&current), &["lr-c".to_owned()])
                .expect_err("unknown selection")
                .code,
            "prune_selection_unknown"
        );
    }

    #[test]
    fn journals_preserve_exact_plan_rollback_metadata() {
        let action = PlannedAction {
            id: "apply-ingress-api".to_owned(),
            kind: "kubernetes.apply".to_owned(),
            summary: "apply".to_owned(),
            destructive: false,
            depends_on: Vec::new(),
            rollback: Some(RollbackMetadata {
                supported: true,
                action: Some("exposure.restore-previous".to_owned()),
                token: None,
                metadata: json!({"resource_key": "Ingress/ingress-api"}),
            }),
            metadata: json!({"resource_key": "Ingress/ingress-api"}),
        };
        let entry = journal_entry_for_action(1, &action, JournalStatus::Succeeded, "reconciled");
        assert_eq!(
            entry
                .rollback
                .as_ref()
                .and_then(|rollback| rollback.action.as_deref()),
            Some("exposure.restore-previous")
        );
        assert_eq!(entry.metadata, action.metadata);
    }

    #[test]
    fn changed_existing_job_requires_down_then_up() {
        let job = RenderedResource {
            key: "Job/workload-migrate".to_owned(),
            kind: "Job".to_owned(),
            name: "workload-migrate".to_owned(),
            role: ResourceRole::Runtime,
            manifest: json!({}),
            spec_hash: "desired".to_owned(),
        };
        assert!(job_needs_create(&job, None).expect("absent Job"));
        assert!(!job_needs_create(&job, Some("desired")).expect("unchanged Job"));
        assert_eq!(
            job_needs_create(&job, Some("old"))
                .expect_err("changed Job")
                .code,
            "kubernetes_job_replacement_requires_down"
        );
    }

    #[test]
    fn every_runtime_action_reports_unsupported_exact_rollback() {
        let service = RenderedResource {
            key: "Deployment/api".to_owned(),
            kind: "Deployment".to_owned(),
            name: "api".to_owned(),
            role: ResourceRole::Runtime,
            manifest: json!({}),
            spec_hash: "desired".to_owned(),
        };
        let rollback = rollback_for_resource(&Capability::Runtime, &service, "lr-env", None, true)
            .expect("Runtime mutation must carry explicit rollback metadata");
        assert!(!rollback.supported);
        assert_eq!(rollback.action, None);
        assert!(
            rollback
                .metadata
                .get("reason")
                .and_then(Value::as_str)
                .is_some()
        );
    }

    #[test]
    fn existing_exposure_without_a_prior_manifest_never_advertises_exact_rollback() {
        let ingress = RenderedResource {
            key: "Ingress/api".to_owned(),
            kind: "Ingress".to_owned(),
            name: "api".to_owned(),
            role: ResourceRole::Exposure,
            manifest: json!({}),
            spec_hash: "desired".to_owned(),
        };
        let existing = rollback_for_resource(&Capability::Exposure, &ingress, "lr-env", None, true)
            .expect("Exposure mutation carries rollback metadata");
        assert!(!existing.supported);
        assert_eq!(existing.action, None);

        let created = rollback_for_resource(&Capability::Exposure, &ingress, "lr-env", None, false)
            .expect("new Exposure resource has an exact delete inverse");
        assert!(created.supported);
        assert_eq!(created.metadata.get("prior_manifest"), Some(&Value::Null));
    }

    #[test]
    fn stale_owned_resource_requires_down_then_up() {
        let current = Map::from_iter([(
            "Service/removed".to_owned(),
            Value::String("old".to_owned()),
        )]);
        let desired = BTreeMap::<String, &RenderedResource>::new();
        assert_eq!(
            ensure_no_stale_resources(&current, &desired, ResourceRole::Runtime)
                .expect_err("stale Runtime resource")
                .code,
            "kubernetes_down_required"
        );
    }

    #[test]
    fn runtime_volume_resource_addition_requires_down_then_up() {
        let claim = RenderedResource {
            key: "PersistentVolumeClaim/data-cache".to_owned(),
            kind: "PersistentVolumeClaim".to_owned(),
            name: "data-cache".to_owned(),
            role: ResourceRole::Runtime,
            manifest: json!({}),
            spec_hash: "desired".to_owned(),
        };
        let desired = BTreeMap::from([(claim.key.clone(), &claim)]);
        assert!(ensure_no_runtime_additions(&Map::new(), &desired, None).is_ok());
        assert_eq!(
            ensure_no_runtime_additions(&Map::new(), &desired, Some("prior"))
                .expect_err("existing Runtime topology cannot add a PVC")
                .code,
            "kubernetes_down_required"
        );
    }

    #[test]
    fn started_exposure_and_dns_entries_skip_prior_or_reverse_attempted_only() {
        let prior = json!({"kind": "Ingress", "spec": {"host": "prior"}});
        assert!(
            !exposure_restore_needed(&prior, &prior, Some("prior"), "attempted")
                .expect("unchanged prior exposure")
        );
        assert!(
            exposure_restore_needed(
                &json!({"kind": "Ingress", "spec": {"host": "attempted"}}),
                &prior,
                Some("attempted"),
                "attempted",
            )
            .expect("attempted exposure")
        );
        assert!(
            exposure_restore_needed(
                &json!({"kind": "Ingress", "spec": {"host": "foreign"}}),
                &prior,
                Some("foreign"),
                "attempted",
            )
            .is_err()
        );

        assert!(!expiry_rollback_needed(Some(10), Some(10), 20).expect("prior expiry"));
        assert!(expiry_rollback_needed(Some(20), Some(10), 20).expect("attempted expiry"));
        assert!(expiry_rollback_needed(Some(30), Some(10), 20).is_err());
    }

    #[test]
    fn started_plan_entries_are_not_dropped_from_rollback() {
        let rollback = Some(RollbackMetadata {
            supported: true,
            action: Some("runtime.restore-previous".to_owned()),
            token: None,
            metadata: json!({}),
        });
        let journal = vec![ActionJournalEntry {
            sequence: 1,
            action_id: "apply-deployment-api".to_owned(),
            status: JournalStatus::Started,
            timestamp: None,
            message: None,
            rollback,
            metadata: json!({}),
        }];
        assert_eq!(
            attempted_rollback_entries(&journal, "runtime.restore-previous").len(),
            1
        );
    }

    #[test]
    fn legacy_metadata_only_runtime_rollback_is_never_executed() {
        let rollback = RollbackMetadata {
            supported: true,
            action: Some("runtime.restore-previous".to_owned()),
            token: None,
            metadata: json!({}),
        };
        let request = DestroyRequest {
            context: lightrail_plugin_protocol::OperationContext::default(),
            current: None,
            force: false,
            journal: vec![ActionJournalEntry {
                sequence: 1,
                action_id: "apply-deployment-api".to_owned(),
                status: JournalStatus::Succeeded,
                timestamp: None,
                message: None,
                rollback: Some(rollback),
                metadata: json!({}),
            }],
        };
        let cancellations = CancellationRegistry::default();
        let guard = cancellations.begin("rollback-test");
        let error =
            KubernetesPlugin::rollback_runtime(&Settings::default(), &request, guard.state())
                .expect_err("metadata-only rollback must fail closed");
        assert_eq!(error.code, "runtime_exact_rollback_unavailable");
    }
}
