use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    path::{Path, PathBuf},
};

use lightrail_core::{DnsLabel, Hostname, IpDnsDomain};
use lightrail_plugin_protocol::{Endpoint, OperationContext};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::{
    contract::{
        DesiredState, EnvironmentInput, PluginConfig, TargetState, canonical_project_source,
        project_relative_source,
    },
    error::ComposePluginError,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComposeInventory {
    pub services: BTreeMap<String, ServiceInventory>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceInventory {
    pub build: bool,
    pub image: Option<String>,
    pub ports: BTreeSet<u16>,
    pub healthcheck: bool,
}

#[derive(Clone, Debug)]
pub struct RenderedDeployment {
    pub base: Value,
    pub runtime_override: Value,
    pub environment_override: Option<Value>,
    pub images: BTreeMap<String, String>,
}

pub fn compose_config_arguments(paths: &[PathBuf]) -> Vec<OsString> {
    let mut arguments = vec![OsString::from("compose")];
    for path in paths {
        arguments.push(OsString::from("-f"));
        arguments.push(path.as_os_str().to_owned());
    }
    arguments.extend([
        OsString::from("config"),
        OsString::from("--format"),
        OsString::from("json"),
    ]);
    arguments
}

pub fn inspect_document(document: &Value) -> Result<ComposeInventory, ComposePluginError> {
    validate_top_level_networks(document)?;
    validate_top_level_volumes(document)?;
    validate_top_level_assets(document)?;
    let services = document
        .get("services")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            ComposePluginError::InvalidDesired(
                "resolved Compose document must contain a services object".to_owned(),
            )
        })?;
    let mut inventory = BTreeMap::new();
    for (name, value) in services {
        let service = value.as_object().ok_or_else(|| {
            ComposePluginError::InvalidDesired(format!(
                "Compose service `{name}` must be an object"
            ))
        })?;
        if service
            .get("network_mode")
            .is_some_and(|value| !is_empty(value))
        {
            if service.get("network_mode").and_then(Value::as_str) == Some("host") {
                return Err(ComposePluginError::HostNetwork {
                    service: name.clone(),
                });
            }
            return Err(ComposePluginError::InvalidDesired(format!(
                "service `{name}` uses network_mode, which cannot be preserved by the isolated Compose runtime"
            )));
        }
        validate_service_networks(name, service)?;
        if let Some(volumes) = service.get("volumes").and_then(Value::as_array) {
            for volume in volumes {
                if let Some(source) = bind_mount_source(volume) {
                    return Err(ComposePluginError::BindMount {
                        service: name.clone(),
                        mount_source: source,
                    });
                }
            }
        }
        let ports = service
            .get("ports")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .chain(
                service
                    .get("expose")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten(),
            )
            .filter_map(port_target)
            .collect();
        inventory.insert(
            name.clone(),
            ServiceInventory {
                build: service.get("build").is_some_and(|value| !value.is_null()),
                image: service
                    .get("image")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                ports,
                healthcheck: service
                    .get("healthcheck")
                    .is_some_and(|value| !value.is_null()),
            },
        );
    }
    Ok(ComposeInventory {
        services: inventory,
    })
}

fn validate_top_level_networks(document: &Value) -> Result<(), ComposePluginError> {
    let Some(networks) = document.get("networks").filter(|value| !value.is_null()) else {
        return Ok(());
    };
    let networks = networks.as_object().ok_or_else(|| {
        ComposePluginError::InvalidDesired(
            "top-level Compose `networks` must be an object".to_owned(),
        )
    })?;
    if networks.is_empty() {
        return Ok(());
    }
    if networks.len() != 1 || !networks.contains_key("default") {
        return Err(ComposePluginError::InvalidDesired(
            "only Compose's implicit `default` network is supported; custom or multiple networks cannot be isolated safely"
                .to_owned(),
        ));
    }
    let definition = &networks["default"];
    if definition.is_null() {
        return Ok(());
    }
    let definition = definition.as_object().ok_or_else(|| {
        ComposePluginError::InvalidDesired(
            "top-level Compose network `default` must be an object".to_owned(),
        )
    })?;
    let unsupported = definition
        .iter()
        .filter(|(field, value)| {
            !matches!(field.as_str(), "name" | "ipam" | "external") && !is_empty(value)
        })
        .map(|(field, _)| field.as_str())
        .collect::<Vec<_>>();
    if !unsupported.is_empty()
        || definition.get("ipam").is_some_and(|value| !is_empty(value))
        || definition.get("external").is_some_and(external_enabled)
    {
        return Err(ComposePluginError::InvalidDesired(format!(
            "top-level Compose network `default` uses unsupported custom options{}",
            if unsupported.is_empty() {
                String::new()
            } else {
                format!(": {}", unsupported.join(", "))
            }
        )));
    }
    if let Some(name) = definition.get("name") {
        let name = name.as_str().ok_or_else(|| {
            ComposePluginError::InvalidDesired(
                "top-level Compose network `default.name` must be a string".to_owned(),
            )
        })?;
        let project_name = compose_project_name(document, "network")?;
        let expected = format!("{project_name}_default");
        if name != expected {
            return Err(ComposePluginError::InvalidDesired(format!(
                "top-level Compose network `default` has custom name `{name}`; only generated `{expected}` is supported"
            )));
        }
    }
    Ok(())
}

fn validate_service_networks(
    service_name: &str,
    service: &Map<String, Value>,
) -> Result<(), ComposePluginError> {
    let Some(networks) = service.get("networks").filter(|value| !value.is_null()) else {
        return Ok(());
    };
    let networks = networks.as_object().ok_or_else(|| {
        ComposePluginError::InvalidDesired(format!(
            "Compose service `{service_name}` networks must be an object"
        ))
    })?;
    if networks.is_empty() {
        return Ok(());
    }
    if networks.len() != 1 || !networks.contains_key("default") {
        return Err(ComposePluginError::InvalidDesired(format!(
            "service `{service_name}` must use only Compose's implicit `default` network"
        )));
    }
    if !is_empty(&networks["default"]) {
        return Err(ComposePluginError::InvalidDesired(format!(
            "service `{service_name}` uses aliases, static addresses, or other unsupported `default` network options"
        )));
    }
    Ok(())
}

fn validate_top_level_volumes(document: &Value) -> Result<(), ComposePluginError> {
    let Some(volumes) = document.get("volumes").filter(|value| !value.is_null()) else {
        return Ok(());
    };
    let volumes = volumes.as_object().ok_or_else(|| {
        ComposePluginError::InvalidDesired(
            "top-level Compose `volumes` must be an object".to_owned(),
        )
    })?;
    for (name, raw) in volumes {
        if raw.is_null() {
            continue;
        }
        let definition = raw.as_object().ok_or_else(|| {
            ComposePluginError::InvalidDesired(format!(
                "top-level Compose volume `{name}` must be an object"
            ))
        })?;
        if definition.get("external").is_some_and(external_enabled) {
            return Err(ComposePluginError::ExternalVolume {
                volume: name.clone(),
            });
        }
        let unsupported = definition
            .iter()
            .filter(|(field, value)| {
                !matches!(field.as_str(), "name" | "external") && !is_empty(value)
            })
            .map(|(field, _)| field.as_str())
            .collect::<Vec<_>>();
        if !unsupported.is_empty() {
            return Err(ComposePluginError::InvalidDesired(format!(
                "top-level Compose volume `{name}` uses unsupported custom options: {}",
                unsupported.join(", ")
            )));
        }
        validate_generated_resource_name(document, "volume", name, definition)?;
    }
    Ok(())
}

fn validate_top_level_assets(document: &Value) -> Result<(), ComposePluginError> {
    for kind in ["configs", "secrets"] {
        let Some(resources) = document.get(kind).filter(|value| !value.is_null()) else {
            continue;
        };
        let resources = resources.as_object().ok_or_else(|| {
            ComposePluginError::InvalidDesired(format!(
                "top-level Compose `{kind}` must be an object"
            ))
        })?;
        for (name, raw) in resources {
            let definition = raw.as_object().ok_or_else(|| {
                ComposePluginError::InvalidDesired(format!(
                    "top-level Compose {kind} entry `{name}` must be an object"
                ))
            })?;
            if definition.get("external").is_some_and(external_enabled) {
                return Err(ComposePluginError::InvalidDesired(format!(
                    "external Compose {kind} entry `{name}` is not owned by the environment"
                )));
            }
            let unsupported = definition
                .iter()
                .filter(|(field, value)| {
                    !matches!(field.as_str(), "file" | "name" | "external") && !is_empty(value)
                })
                .map(|(field, _)| field.as_str())
                .collect::<Vec<_>>();
            if !unsupported.is_empty() {
                return Err(ComposePluginError::InvalidDesired(format!(
                    "top-level Compose {kind} entry `{name}` uses unsupported options: {}",
                    unsupported.join(", ")
                )));
            }
            let file = definition
                .get("file")
                .and_then(Value::as_str)
                .filter(|file| !file.is_empty())
                .ok_or_else(|| {
                    ComposePluginError::InvalidDesired(format!(
                        "top-level Compose {kind} entry `{name}` must be backed by a file"
                    ))
                })?;
            if file.contains('\0') {
                return Err(ComposePluginError::InvalidDesired(format!(
                    "top-level Compose {kind} entry `{name}` has an invalid file path"
                )));
            }
            validate_generated_resource_name(document, kind, name, definition)?;
        }
    }
    Ok(())
}

fn validate_generated_resource_name(
    document: &Value,
    kind: &str,
    logical_name: &str,
    definition: &Map<String, Value>,
) -> Result<(), ComposePluginError> {
    let Some(name) = definition.get("name") else {
        return Ok(());
    };
    let name = name.as_str().ok_or_else(|| {
        ComposePluginError::InvalidDesired(format!(
            "top-level Compose {kind} `{logical_name}.name` must be a string"
        ))
    })?;
    let project_name = compose_project_name(document, kind)?;
    let expected = format!("{project_name}_{logical_name}");
    if name != expected {
        return Err(ComposePluginError::InvalidDesired(format!(
            "top-level Compose {kind} `{logical_name}` has custom name `{name}`; only generated `{expected}` is supported"
        )));
    }
    Ok(())
}

fn compose_project_name<'a>(
    document: &'a Value,
    resource: &str,
) -> Result<&'a str, ComposePluginError> {
    document
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            ComposePluginError::InvalidDesired(format!(
                "resolved Compose must include its project name to verify generated {resource} names"
            ))
        })
}

fn external_enabled(value: &Value) -> bool {
    !matches!(value, Value::Null | Value::Bool(false))
}

fn is_empty(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(false) => true,
        Value::String(value) => value.is_empty(),
        Value::Array(value) => value.is_empty(),
        Value::Object(value) => value.is_empty(),
        Value::Bool(true) | Value::Number(_) => false,
    }
}

pub fn validate_apps(
    desired: &DesiredState,
    inventory: &ComposeInventory,
) -> Result<Vec<String>, ComposePluginError> {
    let mut warnings = Vec::new();
    for app in &desired.apps {
        let service = inventory
            .services
            .get(&app.service)
            .ok_or_else(|| ComposePluginError::MissingService(app.service.clone()))?;
        if !service.ports.contains(&app.port) {
            warnings.push(format!(
                "app `{}` selects port {} which Compose does not expose; Lightrail will expose it",
                app.name, app.port
            ));
        }
    }
    Ok(warnings)
}

/// Derive a source-contained, checkout-portable deployment revision.
///
/// # Errors
///
/// Returns an error when the resolved Compose model is unsupported or any
/// local source resolves outside the operation's granted Git root.
pub fn deployment_revision(
    desired: &DesiredState,
    document: &Value,
    context: &OperationContext,
) -> Result<String, ComposePluginError> {
    inspect_document(document)?;
    let root = desired.project_root(context)?;
    let compose_paths = desired.compose_paths(context)?;
    let (stable_document, facts) = canonical_revision_document(document, &root)?;
    let stable_desired = canonical_revision_desired(desired, &root, &compose_paths)?;
    let mut hasher = Sha256::new();
    hasher.update(b"lightrail/compose/revision/v2\0");
    hasher.update(serde_json::to_vec(&stable_desired)?);
    hasher.update(serde_json::to_vec(&stable_document)?);
    if desired.environment.dirty
        || facts.local_build
        || facts.resolved_environment
        || facts.file_asset
        || desired.apps.iter().any(|app| !app.environment.is_empty())
    {
        // Git cannot prove that ignored files are excluded from Docker build
        // contexts. Environment and file-backed asset values are deliberately
        // absent from provider-visible revision input. An operation salt makes
        // every such `up` reconcile without exposing those bytes in metadata;
        // Buildx still reuses its content-addressed cache.
        hasher.update(context.operation_id.as_bytes());
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[derive(Clone, Copy, Debug, Default)]
struct RevisionFacts {
    local_build: bool,
    resolved_environment: bool,
    file_asset: bool,
}

fn canonical_revision_desired(
    desired: &DesiredState,
    root: &Path,
    compose_paths: &[PathBuf],
) -> Result<DesiredState, ComposePluginError> {
    let mut stable = desired.clone();
    stable.project.root = None;
    stable.resolved_compose_path = None;
    stable.project.compose = compose_paths
        .iter()
        .map(|path| {
            project_relative_source(root, path, &format!("Compose file `{}`", path.display()))
                .map(PathBuf::from)
        })
        .collect::<Result<_, _>>()?;
    for app in &mut stable.apps {
        for input in app.environment.values_mut() {
            if let EnvironmentInput::Literal(value) = input {
                "<literal>".clone_into(value);
            }
        }
    }
    Ok(stable)
}

fn canonical_revision_document(
    document: &Value,
    root: &Path,
) -> Result<(Value, RevisionFacts), ComposePluginError> {
    let mut stable = document.clone();
    let object = stable.as_object_mut().ok_or_else(|| {
        ComposePluginError::InvalidDesired("resolved Compose document must be an object".to_owned())
    })?;
    object.remove("name");
    object.insert("networks".to_owned(), json!({"default": null}));
    if let Some(volumes) = object.get_mut("volumes").and_then(Value::as_object_mut) {
        for definition in volumes.values_mut() {
            *definition = Value::Null;
        }
    }

    let mut facts = RevisionFacts::default();
    for kind in ["configs", "secrets"] {
        let Some(resources) = object.get_mut(kind).and_then(Value::as_object_mut) else {
            continue;
        };
        for (name, definition) in resources {
            let definition = definition.as_object_mut().ok_or_else(|| {
                ComposePluginError::InvalidDesired(format!(
                    "top-level Compose {kind} entry `{name}` must be an object"
                ))
            })?;
            definition.remove("name");
            definition.remove("external");
            let file = definition
                .get("file")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    ComposePluginError::InvalidDesired(format!(
                        "top-level Compose {kind} entry `{name}` must be backed by a file"
                    ))
                })?;
            let source = canonical_project_source(
                root,
                root,
                Path::new(file),
                &format!("Compose {kind} file `{name}`"),
            )?;
            if !source.is_file() {
                return Err(ComposePluginError::InvalidDesired(format!(
                    "Compose {kind} file `{name}` must be a regular file"
                )));
            }
            definition.insert(
                "file".to_owned(),
                Value::String(project_relative_source(
                    root,
                    &source,
                    &format!("Compose {kind} file `{name}`"),
                )?),
            );
            facts.file_asset = true;
        }
    }

    let services = object
        .get_mut("services")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            ComposePluginError::InvalidDesired(
                "resolved Compose document must contain a services object".to_owned(),
            )
        })?;
    for (service_name, raw) in services {
        let service = raw.as_object_mut().ok_or_else(|| {
            ComposePluginError::InvalidDesired(format!(
                "Compose service `{service_name}` must be an object"
            ))
        })?;
        service.insert("networks".to_owned(), json!({"default": null}));
        if let Some(environment) = service.get_mut("environment") {
            facts.resolved_environment |= !is_empty(environment);
            let environment = environment.as_object_mut().ok_or_else(|| {
                ComposePluginError::InvalidDesired(format!(
                    "Compose service `{service_name}` environment must be an object"
                ))
            })?;
            for value in environment.values_mut() {
                *value = Value::Null;
            }
        }
        let Some(build) = service.get("build").filter(|value| !value.is_null()) else {
            continue;
        };
        service.insert(
            "build".to_owned(),
            canonical_build_revision_value(root, service_name, build)?,
        );
        facts.local_build = true;
    }
    Ok((stable, facts))
}

fn canonical_build_revision_value(
    root: &Path,
    service_name: &str,
    raw: &Value,
) -> Result<Value, ComposePluginError> {
    if let Some(path) = raw.as_str() {
        let context = canonical_build_context(root, service_name, path)?;
        validate_default_dockerfile(root, service_name, &context, None)?;
        return Ok(Value::String(project_relative_source(
            root,
            &context,
            &format!("build context for service `{service_name}`"),
        )?));
    }
    let mut build = raw.as_object().cloned().ok_or_else(|| {
        ComposePluginError::InvalidDesired(format!(
            "resolved Compose build for service `{service_name}` must be a string or object"
        ))
    })?;
    let context_value = build
        .get("context")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ComposePluginError::InvalidDesired(format!(
                "resolved Compose build for service `{service_name}` must contain a context path"
            ))
        })?;
    let context = canonical_build_context(root, service_name, context_value)?;
    build.insert(
        "context".to_owned(),
        Value::String(project_relative_source(
            root,
            &context,
            &format!("build context for service `{service_name}`"),
        )?),
    );
    if let Some(dockerfile) = build.get("dockerfile").cloned() {
        let dockerfile = dockerfile.as_str().ok_or_else(|| {
            ComposePluginError::InvalidDesired(format!(
                "resolved Compose Dockerfile for service `{service_name}` must be a path string"
            ))
        })?;
        let source = canonical_project_source(
            root,
            &context,
            Path::new(dockerfile),
            &format!("Dockerfile for service `{service_name}`"),
        )?;
        if !source.is_file() {
            return Err(ComposePluginError::InvalidDesired(format!(
                "Dockerfile for service `{service_name}` must be a regular file"
            )));
        }
        build.insert(
            "dockerfile".to_owned(),
            Value::String(project_relative_source(
                root,
                &source,
                &format!("Dockerfile for service `{service_name}`"),
            )?),
        );
    } else if !build.contains_key("dockerfile_inline") {
        validate_default_dockerfile(root, service_name, &context, None)?;
    }
    canonicalize_additional_build_contexts(root, service_name, &mut build)?;
    Ok(Value::Object(build))
}

fn canonicalize_additional_build_contexts(
    root: &Path,
    service_name: &str,
    build: &mut Map<String, Value>,
) -> Result<(), ComposePluginError> {
    let Some(contexts) = build
        .get_mut("additional_contexts")
        .filter(|value| !is_empty(value))
    else {
        return Ok(());
    };
    let contexts = contexts.as_object_mut().ok_or_else(|| {
        ComposePluginError::InvalidDesired(format!(
            "additional build contexts for service `{service_name}` must be an object"
        ))
    })?;
    for (name, value) in contexts {
        let path = value.as_str().ok_or_else(|| {
            ComposePluginError::InvalidDesired(format!(
                "additional build context `{name}` for service `{service_name}` must be a local path"
            ))
        })?;
        let source = canonical_project_source(
            root,
            root,
            Path::new(path),
            &format!("additional build context `{name}` for service `{service_name}`"),
        )?;
        if !source.is_dir() {
            return Err(ComposePluginError::InvalidDesired(format!(
                "additional build context `{name}` for service `{service_name}` must be a directory"
            )));
        }
        *value = Value::String(project_relative_source(
            root,
            &source,
            &format!("additional build context `{name}` for service `{service_name}`"),
        )?);
    }
    Ok(())
}

fn canonical_build_context(
    root: &Path,
    service_name: &str,
    value: &str,
) -> Result<PathBuf, ComposePluginError> {
    let context = canonical_project_source(
        root,
        root,
        Path::new(value),
        &format!("build context for service `{service_name}`"),
    )?;
    if !context.is_dir() {
        return Err(ComposePluginError::InvalidDesired(format!(
            "build context for service `{service_name}` must be a directory"
        )));
    }
    Ok(context)
}

fn validate_default_dockerfile(
    root: &Path,
    service_name: &str,
    context: &Path,
    dockerfile: Option<&Path>,
) -> Result<(), ComposePluginError> {
    let source = canonical_project_source(
        root,
        context,
        dockerfile.unwrap_or_else(|| Path::new("Dockerfile")),
        &format!("Dockerfile for service `{service_name}`"),
    )?;
    if !source.is_file() {
        return Err(ComposePluginError::InvalidDesired(format!(
            "Dockerfile for service `{service_name}` must be a regular file"
        )));
    }
    Ok(())
}

pub fn image_map(
    desired: &DesiredState,
    inventory: &ComposeInventory,
    revision: &str,
) -> Result<BTreeMap<String, String>, ComposePluginError> {
    let environment = DnsLabel::new(&desired.environment.id)
        .map_err(|error| ComposePluginError::InvalidDesired(error.to_string()))?;
    let revision_tag = revision.get(..16).unwrap_or(revision);
    inventory
        .services
        .iter()
        .filter(|(_, service)| service.build)
        .map(|(service, _)| {
            let service_label = DnsLabel::new(service)
                .map_err(|error| ComposePluginError::InvalidDesired(error.to_string()))?;
            Ok((
                service.clone(),
                format!(
                    "lightrail/{}-{}:{revision_tag}",
                    environment.as_str(),
                    service_label.as_str()
                ),
            ))
        })
        .collect()
}

pub fn build_override(
    images: &BTreeMap<String, String>,
    platform: &str,
    desired: &DesiredState,
) -> Value {
    let services = images
        .iter()
        .map(|(service, image)| {
            (
                service.clone(),
                json!({
                    "image": image,
                    "platform": platform,
                    "build": {
                        "labels": {
                            "lightrail-managed": "true",
                            "lightrail-project-id": desired.project.id,
                            "lightrail-environment-id": desired.environment.id,
                        }
                    }
                }),
            )
        })
        .collect::<Map<_, _>>();
    json!({ "services": services })
}

#[allow(clippy::too_many_lines)]
pub fn render_deployment(
    desired: &DesiredState,
    document: &Value,
    inventory: &ComposeInventory,
    target: &TargetState,
    config: &PluginConfig,
    app_environment: &BTreeMap<String, BTreeMap<String, String>>,
    revision: &str,
) -> Result<RenderedDeployment, ComposePluginError> {
    let mut base = document.clone();
    let base_object = base.as_object_mut().ok_or_else(|| {
        ComposePluginError::InvalidDesired("resolved Compose root must be an object".to_owned())
    })?;
    base_object.insert(
        "name".to_owned(),
        Value::String(desired.environment.id.clone()),
    );
    scope_named_volumes(base_object, desired)?;
    scope_file_assets(base_object)?;
    let images = image_map(desired, inventory, revision)?;
    let mut sensitive_services = Map::new();

    let service_names = {
        let services = base_object
            .get_mut("services")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| {
                ComposePluginError::InvalidDesired(
                    "resolved Compose document must contain services".to_owned(),
                )
            })?;
        for (service_name, service_value) in services.iter_mut() {
            let service = service_value.as_object_mut().ok_or_else(|| {
                ComposePluginError::InvalidDesired(format!(
                    "Compose service `{service_name}` must be an object"
                ))
            })?;
            service.remove("build");
            service.remove("ports");
            service.remove("network_mode");
            service.remove("networks");
            service.remove("env_file");
            if let Some(image) = images.get(service_name) {
                service.insert("image".to_owned(), Value::String(image.clone()));
            }
            if let Some(environment) = service.remove("environment") {
                sensitive_services
                    .insert(service_name.clone(), json!({ "environment": environment }));
            }
        }
        services.keys().cloned().collect::<Vec<_>>()
    };

    for (service, environment) in app_environment {
        let entry = sensitive_services
            .entry(service.clone())
            .or_insert_with(|| json!({}));
        let object = entry.as_object_mut().ok_or_else(|| {
            ComposePluginError::InvalidDesired("invalid environment override".to_owned())
        })?;
        let environment_object = object
            .entry("environment")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or_else(|| {
                ComposePluginError::InvalidDesired(format!(
                    "service `{service}` environment is not an object"
                ))
            })?;
        for (name, value) in environment {
            environment_object.insert(name.clone(), Value::String(value.clone()));
        }
    }

    let mut environment_network_labels = desired.environment.labels.clone();
    environment_network_labels.insert("lightrail-managed".to_owned(), "true".to_owned());
    environment_network_labels.insert(
        "lightrail-project-id".to_owned(),
        desired.project.id.clone(),
    );
    environment_network_labels.insert(
        "lightrail-environment-id".to_owned(),
        desired.environment.id.clone(),
    );
    base_object.insert(
        "networks".to_owned(),
        json!({
            "lightrail_env": {
                "labels": environment_network_labels,
            }
        }),
    );

    let endpoints = endpoints(desired, target, config)?;
    let ingress_network = environment_ingress_network(config, &desired.environment.id)?;
    let endpoint_by_app = endpoints
        .iter()
        .map(|endpoint| (endpoint.app.as_str(), endpoint))
        .collect::<BTreeMap<_, _>>();
    let public_services = desired
        .apps
        .iter()
        .map(|app| app.service.as_str())
        .collect::<BTreeSet<_>>();
    let mut runtime_services = Map::new();
    for service_name in &service_names {
        let mut networks = Map::from_iter([("lightrail_env".to_owned(), json!({}))]);
        let mut labels = desired.environment.labels.clone();
        labels.insert("lightrail-managed".to_owned(), "true".to_owned());
        labels.insert(
            "lightrail-environment-id".to_owned(),
            desired.environment.id.clone(),
        );
        labels.insert(
            "lightrail-project-id".to_owned(),
            desired.project.id.clone(),
        );
        labels.insert(
            "lightrail-revision".to_owned(),
            revision.get(..63).unwrap_or(revision).to_owned(),
        );
        if public_services.contains(service_name.as_str()) {
            networks.insert("lightrail_ingress".to_owned(), json!({}));
            labels.insert("traefik.docker.network".to_owned(), ingress_network.clone());
        }
        runtime_services.insert(
            service_name.clone(),
            json!({
                "labels": labels,
                "networks": networks,
            }),
        );
    }

    for app in &desired.apps {
        let endpoint = endpoint_by_app
            .get(app.name.as_str())
            .ok_or_else(|| ComposePluginError::MissingService(app.name.clone()))?;
        let service = runtime_services
            .get_mut(&app.service)
            .and_then(Value::as_object_mut)
            .ok_or_else(|| ComposePluginError::MissingService(app.service.clone()))?;
        let labels = service
            .get_mut("labels")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| {
                ComposePluginError::InvalidDesired("generated labels are invalid".to_owned())
            })?;
        let router = router_name(&desired.environment.id, &app.name)?;
        let hostname = endpoint.url.trim_start_matches("https://");
        labels.extend([
            (
                "traefik.enable".to_owned(),
                Value::String("true".to_owned()),
            ),
            (
                format!("traefik.http.routers.{router}.rule"),
                Value::String(format!("Host(`{hostname}`)")),
            ),
            (
                format!("traefik.http.routers.{router}.entrypoints"),
                Value::String("websecure".to_owned()),
            ),
            (
                format!("traefik.http.routers.{router}.tls"),
                Value::String("true".to_owned()),
            ),
            (
                format!("traefik.http.routers.{router}.tls.certresolver"),
                Value::String(config.certificate_resolver.clone()),
            ),
            (
                format!("traefik.http.services.{router}.loadbalancer.server.port"),
                Value::String(app.port.to_string()),
            ),
        ]);
    }

    let runtime_override = json!({
        "services": runtime_services,
        "networks": {
            "lightrail_env": {},
            "lightrail_ingress": {
                "external": true,
                "name": ingress_network,
            },
        },
    });
    let environment_override =
        (!sensitive_services.is_empty()).then(|| json!({ "services": sensitive_services }));
    Ok(RenderedDeployment {
        base,
        runtime_override,
        environment_override,
        images,
    })
}

fn scope_named_volumes(
    document: &mut Map<String, Value>,
    desired: &DesiredState,
) -> Result<(), ComposePluginError> {
    let Some(volumes) = document.get_mut("volumes").and_then(Value::as_object_mut) else {
        return Ok(());
    };
    for (name, value) in volumes {
        if value.is_null() {
            *value = json!({});
        }
        let definition = value.as_object_mut().ok_or_else(|| {
            ComposePluginError::InvalidDesired(format!(
                "named volume `{name}` definition must be an object"
            ))
        })?;
        // `docker compose config` resolves implicit names using the local
        // project name. Removing it lets the remote environment project scope
        // the volume instead.
        definition.remove("name");
        let labels = definition
            .entry("labels")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or_else(|| {
                ComposePluginError::InvalidDesired(format!(
                    "named volume `{name}` labels must be an object"
                ))
            })?;
        for (key, value) in &desired.environment.labels {
            labels.insert(key.clone(), Value::String(value.clone()));
        }
        labels.insert(
            "lightrail-managed".to_owned(),
            Value::String("true".to_owned()),
        );
        labels.insert(
            "lightrail-project-id".to_owned(),
            Value::String(desired.project.id.clone()),
        );
        labels.insert(
            "lightrail-environment-id".to_owned(),
            Value::String(desired.environment.id.clone()),
        );
    }
    Ok(())
}

fn scope_file_assets(document: &mut Map<String, Value>) -> Result<(), ComposePluginError> {
    for kind in ["configs", "secrets"] {
        let Some(resources) = document.get_mut(kind).and_then(Value::as_object_mut) else {
            continue;
        };
        for (name, definition) in resources {
            let definition = definition.as_object_mut().ok_or_else(|| {
                ComposePluginError::InvalidDesired(format!(
                    "top-level Compose {kind} entry `{name}` must be an object"
                ))
            })?;
            // `docker compose config` materializes a checkout-derived name.
            // Removing it lets the remote environment project scope the
            // uploaded file-backed resource.
            definition.remove("name");
        }
    }
    Ok(())
}

pub fn ingress_compose(config: &PluginConfig) -> Value {
    let mut command = vec![
        "--api.dashboard=false".to_owned(),
        "--providers.docker=true".to_owned(),
        "--providers.docker.exposedbydefault=false".to_owned(),
        "--entrypoints.web.address=:80".to_owned(),
        "--entrypoints.web.http.redirections.entrypoint.to=websecure".to_owned(),
        "--entrypoints.web.http.redirections.entrypoint.scheme=https".to_owned(),
        "--entrypoints.websecure.address=:443".to_owned(),
        format!(
            "--certificatesresolvers.{}.acme.storage=/acme/acme.json",
            config.certificate_resolver
        ),
        format!(
            "--certificatesresolvers.{}.acme.httpchallenge=true",
            config.certificate_resolver
        ),
        format!(
            "--certificatesresolvers.{}.acme.httpchallenge.entrypoint=web",
            config.certificate_resolver
        ),
    ];
    if let Some(email) = &config.acme_email {
        command.push(format!(
            "--certificatesresolvers.{}.acme.email={email}",
            config.certificate_resolver
        ));
    }
    json!({
        "name": "lightrail-ingress",
        "services": {
            "traefik": {
                "image": config.ingress_image,
                "container_name": "lightrail-ingress-traefik",
                "restart": "unless-stopped",
                "command": command,
                "ports": [
                    {"target": 80, "published": "80", "protocol": "tcp", "mode": "ingress"},
                    {"target": 443, "published": "443", "protocol": "tcp", "mode": "ingress"}
                ],
                "volumes": [
                    {"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock", "read_only": true},
                    {"type": "volume", "source": "acme", "target": "/acme"}
                ],
                "labels": {
                    "lightrail-managed": "true",
                    "lightrail-role": "shared-ingress"
                }
            }
        },
        "volumes": {
            "acme": {
                "labels": {
                    "lightrail-managed": "true",
                    "lightrail-role": "acme-storage"
                }
            }
        }
    })
}

pub fn environment_ingress_network(
    config: &PluginConfig,
    environment_id: &str,
) -> Result<String, ComposePluginError> {
    let environment = DnsLabel::new(environment_id)
        .map_err(|error| ComposePluginError::InvalidDesired(error.to_string()))?;
    Ok(format!(
        "{}-{}",
        config.ingress_network,
        environment.as_str()
    ))
}

pub fn endpoints(
    desired: &DesiredState,
    target: &TargetState,
    config: &PluginConfig,
) -> Result<Vec<Endpoint>, ComposePluginError> {
    if target.public_ipv4.is_loopback() || target.public_ipv4.is_unspecified() {
        return Err(ComposePluginError::InvalidTarget(
            "public_ipv4 must not be localhost or unspecified".to_owned(),
        ));
    }
    let domain = config
        .dns_domain
        .parse::<IpDnsDomain>()
        .map_err(|error| ComposePluginError::InvalidDesired(error.to_string()))?;
    let branch = DnsLabel::new(&desired.environment.branch)
        .map_err(|error| ComposePluginError::InvalidDesired(error.to_string()))?;
    let profile = DnsLabel::new(&desired.environment.profile)
        .map_err(|error| ComposePluginError::InvalidDesired(error.to_string()))?;
    let project = DnsLabel::new(&desired.project.slug)
        .map_err(|error| ComposePluginError::InvalidDesired(error.to_string()))?;
    desired
        .apps
        .iter()
        .map(|app| {
            let app_label = DnsLabel::new(&app.name)
                .map_err(|error| ComposePluginError::InvalidDesired(error.to_string()))?;
            let hostname = Hostname::new(
                &branch,
                &app_label,
                &profile,
                &project,
                target.public_ipv4,
                domain,
            )
            .map_err(|error| ComposePluginError::InvalidDesired(error.to_string()))?;
            Ok(Endpoint {
                app: app.name.clone(),
                url: hostname.https_url(),
            })
        })
        .collect()
}

fn router_name(environment: &str, app: &str) -> Result<String, ComposePluginError> {
    let environment = DnsLabel::new(environment)
        .map_err(|error| ComposePluginError::InvalidDesired(error.to_string()))?;
    let app = DnsLabel::new(app)
        .map_err(|error| ComposePluginError::InvalidDesired(error.to_string()))?;
    Ok(format!("{}-{}", environment.as_str(), app.as_str()))
}

fn port_target(value: &Value) -> Option<u16> {
    match value {
        Value::Number(number) => number.as_u64().and_then(|port| u16::try_from(port).ok()),
        Value::String(value) => value
            .split_once('/')
            .map_or(value.as_str(), |(port, _)| port)
            .parse()
            .ok(),
        Value::Object(object) => object.get("target").and_then(port_target),
        _ => None,
    }
}

fn bind_mount_source(value: &Value) -> Option<String> {
    match value {
        Value::Object(object) if object.get("type").and_then(Value::as_str) == Some("bind") => {
            object
                .get("source")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        }
        Value::String(value) => {
            let source = value.split(':').next().unwrap_or_default();
            (source.starts_with('.')
                || source.starts_with('/')
                || source.starts_with('~')
                || source.contains('\\'))
            .then(|| source.to_owned())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, net::Ipv4Addr, path::Path, str::FromStr};

    use tempfile::TempDir;

    use super::*;
    use crate::contract::{AppSpec, EnvironmentSpec, Isolation, ProjectSpec};

    fn desired() -> DesiredState {
        DesiredState {
            schema: 1,
            project: ProjectSpec {
                id: "project-id".to_owned(),
                slug: "myproject".to_owned(),
                root: Some(PathBuf::from("/workspace")),
                compose: vec![PathBuf::from("compose.yaml")],
            },
            environment: EnvironmentSpec {
                id: "lr-abc".to_owned(),
                profile: "preview".to_owned(),
                branch: "feature-login".to_owned(),
                commit: None,
                dirty: false,
                isolation: Isolation::Project,
                labels: BTreeMap::new(),
            },
            resolved_compose_path: None,
            apps: vec![AppSpec {
                name: "frontend".to_owned(),
                service: "web".to_owned(),
                port: 3000,
                health_path: None,
                health_status: None,
                health_interval_seconds: None,
                health_timeout_seconds: None,
                environment: BTreeMap::new(),
            }],
            target: Value::Null,
            destroy: false,
        }
    }

    fn target() -> TargetState {
        TargetState {
            host: "203.0.113.10".to_owned(),
            user: Some("deploy".to_owned()),
            port: 22,
            public_ipv4: Ipv4Addr::from_str("203.0.113.10").expect("IP"),
            architecture: "amd64".to_owned(),
            identity_file: None,
            known_hosts_file: None,
            docker: crate::contract::DockerAccess::default(),
            remote_root: ".lightrail".to_owned(),
        }
    }

    fn source_fixture() -> (TempDir, DesiredState, OperationContext) {
        let root = tempfile::tempdir().expect("temporary project");
        fs::write(root.path().join("compose.yaml"), "services: {}\n").expect("Compose file");
        fs::create_dir(root.path().join("web")).expect("build context");
        fs::write(root.path().join("web/Dockerfile"), "FROM scratch\n").expect("Dockerfile");
        fs::create_dir(root.path().join("shared")).expect("additional build context");
        fs::write(root.path().join("shared/value.txt"), "fixture\n")
            .expect("additional context file");
        fs::write(root.path().join("settings.txt"), "fixture\n").expect("config");
        let mut desired = desired();
        desired.project.root = Some(root.path().to_path_buf());
        let context = operation_context(root.path(), "operation-one");
        (root, desired, context)
    }

    fn operation_context(root: &Path, operation_id: &str) -> OperationContext {
        OperationContext {
            operation_id: operation_id.to_owned(),
            environment_id: "lr-abc".to_owned(),
            profile: "preview".to_owned(),
            project_root: Some(root.display().to_string()),
            ..OperationContext::default()
        }
    }

    fn portable_document(root: &Path, project_name: &str, environment: &str) -> Value {
        json!({
            "name": project_name,
            "services": {
                "web": {
                    "build": {
                        "context": root.join("web"),
                        "dockerfile": root.join("web/Dockerfile"),
                        "additional_contexts": {
                            "shared": root.join("shared")
                        }
                    },
                    "environment": {"TOKEN": environment},
                    "networks": {"default": null},
                    "ports": [{"target": 3000}]
                }
            },
            "networks": {
                "default": {"name": format!("{project_name}_default")}
            },
            "volumes": {
                "data": {"name": format!("{project_name}_data")}
            },
            "configs": {
                "settings": {
                    "name": format!("{project_name}_settings"),
                    "file": root.join("settings.txt")
                }
            }
        })
    }

    #[test]
    fn validates_and_discovers_compose_services() {
        let document = json!({
            "services": {
                "web": {
                    "build": {"context": "."},
                    "ports": [{"target": 3000, "published": "3000"}],
                    "healthcheck": {"test": ["CMD", "true"]}
                },
                "db": {
                    "image": "postgres:17",
                    "volumes": [{"type": "volume", "source": "data", "target": "/data"}]
                }
            }
        });
        let inventory = inspect_document(&document).expect("valid Compose");
        assert!(inventory.services["web"].build);
        assert!(inventory.services["web"].healthcheck);
        assert_eq!(inventory.services["web"].ports, BTreeSet::from([3000]));
    }

    #[test]
    fn rejects_host_network_and_bind_mounts() {
        let host = json!({"services": {"bad": {"network_mode": "host"}}});
        assert!(matches!(
            inspect_document(&host),
            Err(ComposePluginError::HostNetwork { .. })
        ));

        let bind = json!({
            "services": {
                "bad": {"volumes": [{"type": "bind", "source": "./src", "target": "/src"}]}
            }
        });
        assert!(matches!(
            inspect_document(&bind),
            Err(ComposePluginError::BindMount { .. })
        ));
    }

    #[test]
    fn rejects_custom_network_and_volume_semantics() {
        for document in [
            json!({
                "services": {"web": {"image": "nginx", "networks": {"private": null}}},
                "networks": {"private": {}}
            }),
            json!({
                "name": "demo",
                "services": {
                    "web": {
                        "image": "nginx",
                        "networks": {"default": {"aliases": ["web.internal"]}}
                    }
                },
                "networks": {"default": {"name": "demo_default"}}
            }),
            json!({
                "name": "demo",
                "services": {"web": {"image": "nginx"}},
                "volumes": {"data": {"name": "shared-data"}}
            }),
            json!({
                "services": {"web": {"image": "nginx"}},
                "volumes": {"data": {"driver": "local"}}
            }),
        ] {
            assert!(
                inspect_document(&document).is_err(),
                "custom network and volume semantics must fail closed: {document}"
            );
        }
    }

    #[test]
    fn renders_private_network_and_traefik_without_published_app_ports() {
        let document = json!({
            "services": {
                "web": {
                    "build": {"context": "."},
                    "ports": [{"target": 3000, "published": "3000"}],
                    "environment": {"TOKEN": "sensitive"}
                },
                "db": {"image": "postgres:17"}
            }
        });
        let inventory = inspect_document(&document).expect("inventory");
        let rendered = render_deployment(
            &desired(),
            &document,
            &inventory,
            &target(),
            &PluginConfig::default(),
            &BTreeMap::new(),
            &"a".repeat(64),
        )
        .expect("render");

        assert!(
            rendered.base["services"]["web"].get("ports").is_none(),
            "published app ports must be stripped"
        );
        assert!(
            rendered.base["services"]["web"]
                .get("environment")
                .is_none()
        );
        assert!(rendered.environment_override.is_some());
        assert_eq!(
            rendered.runtime_override["networks"]["lightrail_ingress"]["external"],
            true
        );
        assert_eq!(
            rendered.runtime_override["networks"]["lightrail_ingress"]["name"],
            "lightrail-ingress-lr-abc"
        );
        assert!(
            rendered.runtime_override["services"]["db"]["networks"]
                .get("lightrail_ingress")
                .is_none()
        );
        let labels = rendered.runtime_override["services"]["web"]["labels"]
            .as_object()
            .expect("labels");
        assert_eq!(labels["traefik.docker.network"], "lightrail-ingress-lr-abc");
        assert_eq!(
            labels["traefik.http.routers.lr-abc-frontend.rule"],
            "Host(`feature-login.frontend.preview.myproject.cb00710a.sslip.io`)"
        );
    }

    #[test]
    fn produces_exact_hex_ip_branch_first_https_url() {
        let endpoints =
            endpoints(&desired(), &target(), &PluginConfig::default()).expect("endpoints");
        assert_eq!(
            endpoints[0].url,
            "https://feature-login.frontend.preview.myproject.cb00710a.sslip.io"
        );
    }

    #[test]
    fn ingress_network_is_unique_per_environment() {
        let config = PluginConfig::default();
        let first = environment_ingress_network(&config, "lr-first").expect("first network");
        let second = environment_ingress_network(&config, "lr-second").expect("second network");

        assert_ne!(first, second);
        assert_eq!(first, "lightrail-ingress-lr-first");
        assert_eq!(second, "lightrail-ingress-lr-second");
    }

    #[test]
    fn build_override_labels_images_for_exact_owned_cleanup() {
        let images = BTreeMap::from([("web".to_owned(), "lightrail/lr-abc-web:1234".to_owned())]);
        let override_value = build_override(&images, "linux/amd64", &desired());

        assert_eq!(
            override_value["services"]["web"]["build"]["labels"]["lightrail-project-id"],
            "project-id"
        );
        assert_eq!(
            override_value["services"]["web"]["build"]["labels"]["lightrail-environment-id"],
            "lr-abc"
        );
    }

    #[test]
    fn revision_is_checkout_portable_and_ignores_ephemeral_paths() {
        let (first_root, mut first, first_context) = source_fixture();
        let (second_root, mut second, second_context) = source_fixture();
        first.resolved_compose_path = Some(PathBuf::from("/tmp/first.json"));
        second.resolved_compose_path = Some(PathBuf::from("/tmp/second.json"));
        let first_document = portable_document(first_root.path(), "checkout-one", "first-secret");
        let second_document =
            portable_document(second_root.path(), "checkout-two", "second-secret");

        assert_eq!(
            deployment_revision(&first, &first_document, &first_context).expect("first revision"),
            deployment_revision(&second, &second_document, &second_context)
                .expect("second revision")
        );
    }

    #[test]
    fn local_builds_are_operation_scoped_but_stable_within_one_operation() {
        let (root, desired, context) = source_fixture();
        let document = json!({
            "services": {
                "web": {
                    "build": {
                        "context": root.path().join("web"),
                        "dockerfile": root.path().join("web/Dockerfile")
                    }
                }
            }
        });
        let first = deployment_revision(&desired, &document, &context).expect("plan revision");
        let repeated = deployment_revision(&desired, &document, &context).expect("apply revision");
        let next = deployment_revision(
            &desired,
            &document,
            &operation_context(root.path(), "operation-two"),
        )
        .expect("next operation revision");

        assert_eq!(
            first, repeated,
            "plan and apply must agree within one operation"
        );
        assert_ne!(
            first, next,
            "every local-build up gets an operation revision"
        );
    }

    #[test]
    fn ordinary_image_only_revision_is_reusable_across_operations() {
        let (root, desired, context) = source_fixture();
        let document = json!({"services": {"web": {"image": "nginx:stable"}}});
        let first = deployment_revision(&desired, &document, &context).expect("first revision");
        let next = deployment_revision(
            &desired,
            &document,
            &operation_context(root.path(), "operation-two"),
        )
        .expect("next revision");

        assert_eq!(first, next);
    }

    #[test]
    fn environment_values_never_influence_revision_metadata() {
        let (root, mut desired, context) = source_fixture();
        let first_document =
            json!({"services": {"web": {"image": "nginx", "environment": {"TOKEN": "first"}}}});
        let second_document =
            json!({"services": {"web": {"image": "nginx", "environment": {"TOKEN": "second"}}}});
        desired.apps[0].environment.insert(
            "APP_TOKEN".to_owned(),
            EnvironmentInput::Literal("first-app-value".to_owned()),
        );
        let first =
            deployment_revision(&desired, &first_document, &context).expect("first revision");
        desired.apps[0].environment.insert(
            "APP_TOKEN".to_owned(),
            EnvironmentInput::Literal("second-app-value".to_owned()),
        );
        let changed_plaintext =
            deployment_revision(&desired, &second_document, &context).expect("redacted revision");
        let next_operation = deployment_revision(
            &desired,
            &second_document,
            &operation_context(root.path(), "operation-two"),
        )
        .expect("next operation revision");

        assert_eq!(
            first, changed_plaintext,
            "resolved and desired environment plaintext must be absent from the digest"
        );
        assert_ne!(
            changed_plaintext, next_operation,
            "environment-bearing deployments must reconcile on each up"
        );
    }

    #[test]
    fn file_backed_assets_are_contained_and_operation_scoped() {
        let (root, desired, context) = source_fixture();
        let document = json!({
            "name": "demo",
            "services": {"web": {"image": "nginx"}},
            "configs": {
                "settings": {
                    "name": "demo_settings",
                    "file": root.path().join("settings.txt")
                }
            }
        });
        let first = deployment_revision(&desired, &document, &context).expect("first revision");
        let next = deployment_revision(
            &desired,
            &document,
            &operation_context(root.path(), "operation-two"),
        )
        .expect("next revision");

        assert_ne!(first, next);
    }

    #[test]
    fn rejects_sources_and_roots_outside_the_granted_checkout() {
        let (root, mut desired, context) = source_fixture();
        let outside = tempfile::tempdir().expect("outside source");
        fs::write(outside.path().join("Dockerfile"), "FROM scratch\n").expect("Dockerfile");
        let outside_build = json!({
            "services": {
                "web": {
                    "build": {
                        "context": outside.path(),
                        "dockerfile": outside.path().join("Dockerfile")
                    }
                }
            }
        });
        assert!(deployment_revision(&desired, &outside_build, &context).is_err());

        let outside_additional_context = json!({
            "services": {
                "web": {
                    "build": {
                        "context": root.path().join("web"),
                        "dockerfile": root.path().join("web/Dockerfile"),
                        "additional_contexts": {
                            "escaped": outside.path()
                        }
                    }
                }
            }
        });
        assert!(deployment_revision(&desired, &outside_additional_context, &context).is_err());

        desired.project.root = Some(outside.path().to_path_buf());
        let ordinary = json!({"services": {"web": {"image": "nginx"}}});
        assert!(deployment_revision(&desired, &ordinary, &context).is_err());

        // Keep both temporary directories live for the complete assertion.
        assert!(root.path().is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symbolic_link_source_escapes() {
        use std::os::unix::fs::symlink;

        let (root, mut desired, context) = source_fixture();
        let outside = tempfile::tempdir().expect("outside source");
        fs::write(outside.path().join("Dockerfile"), "FROM scratch\n").expect("Dockerfile");
        fs::write(outside.path().join("secret.txt"), "outside\n").expect("asset");

        symlink(outside.path(), root.path().join("escaped-build")).expect("build symlink");
        let escaped_build = json!({
            "services": {
                "web": {
                    "build": {
                        "context": root.path().join("escaped-build"),
                        "dockerfile": root.path().join("escaped-build/Dockerfile")
                    }
                }
            }
        });
        assert!(deployment_revision(&desired, &escaped_build, &context).is_err());

        symlink(
            outside.path().join("secret.txt"),
            root.path().join("escaped-secret.txt"),
        )
        .expect("asset symlink");
        let escaped_asset = json!({
            "name": "demo",
            "services": {"web": {"image": "nginx"}},
            "secrets": {
                "token": {
                    "name": "demo_token",
                    "file": root.path().join("escaped-secret.txt")
                }
            }
        });
        assert!(deployment_revision(&desired, &escaped_asset, &context).is_err());

        symlink(
            outside.path().join("secret.txt"),
            root.path().join("linked-compose.yaml"),
        )
        .expect("Compose symlink");
        desired.project.compose = vec![PathBuf::from("linked-compose.yaml")];
        let ordinary = json!({"services": {"web": {"image": "nginx"}}});
        assert!(deployment_revision(&desired, &ordinary, &context).is_err());
    }
}
