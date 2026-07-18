use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    time::Duration,
};

use lightrail_plugin_protocol::{
    Diagnostic, DiagnosticSeverity, Endpoint, InspectResult, LogRecord, ResourceStatus,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::time::{Instant, sleep};

use crate::{
    command::{read_ssh_lines, run_local, run_ssh, run_ssh_script, stream_image, upload_atomic},
    compose_model::{
        ComposeInventory, RenderedDeployment, build_override, compose_config_arguments,
        deployment_revision, endpoints, environment_ingress_network, ingress_compose,
        inspect_document,
    },
    contract::{AppSpec, DesiredState, PluginConfig, TargetState},
    error::ComposePluginError,
};

const ABSENT_MANIFEST_MARKER: &str = "__LIGHTRAIL_MANIFEST_ABSENT__";

#[derive(Clone, Debug)]
pub struct RemoteLayout {
    pub environment_directory: String,
    pub base: String,
    pub runtime_override: String,
    pub manifest: String,
    pub ingress_directory: String,
    pub ingress_compose: String,
    pub ingress_compatibility: String,
}

#[derive(Clone, Debug)]
pub struct RemoteManifest {
    pub desired: DesiredState,
    pub revision: Option<String>,
    pub images: Value,
}

impl RemoteLayout {
    pub fn new(target: &TargetState, environment_id: &str) -> Result<Self, ComposePluginError> {
        if !environment_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(ComposePluginError::UnsafeRemotePath);
        }
        let root = target.remote_root.trim_end_matches('/');
        let environment_directory = format!("{root}/environments/{environment_id}");
        let ingress_directory = format!("{root}/shared/ingress");
        Ok(Self {
            base: format!("{environment_directory}/compose.resolved.json"),
            runtime_override: format!("{environment_directory}/lightrail.override.json"),
            manifest: format!("{environment_directory}/manifest.json"),
            ingress_compose: format!("{ingress_directory}/compose.json"),
            ingress_compatibility: format!("{ingress_directory}/compatibility.json"),
            environment_directory,
            ingress_directory,
        })
    }

    pub fn compose_arguments(&self, environment_id: &str) -> Vec<String> {
        vec![
            "docker".to_owned(),
            "compose".to_owned(),
            "-p".to_owned(),
            environment_id.to_owned(),
            "-f".to_owned(),
            self.base.clone(),
            "-f".to_owned(),
            self.runtime_override.clone(),
        ]
    }

    pub fn operation_environment_override(&self, operation_id: &str) -> String {
        let digest = format!("{:x}", Sha256::digest(operation_id.as_bytes()));
        format!(
            "{}/environment.{}.tmp.json",
            self.environment_directory,
            &digest[..24]
        )
    }
}

pub async fn resolve_compose(
    desired: &DesiredState,
    context: &lightrail_plugin_protocol::OperationContext,
) -> Result<(Value, ComposeInventory, String), ComposePluginError> {
    let document: Value = if let Some(path) = &desired.resolved_compose_path {
        let contents = tokio::fs::read(path)
            .await
            .map_err(ComposePluginError::TemporaryFile)?;
        serde_json::from_slice(&contents)?
    } else {
        let root = desired.project_root(context)?;
        let paths = desired.compose_paths(context)?;
        let output =
            run_local("docker", compose_config_arguments(&paths), Some(root), None).await?;
        serde_json::from_slice(&output.stdout)?
    };
    let inventory = inspect_document(&document)?;
    let revision = deployment_revision(desired, &document);
    Ok((document, inventory, revision))
}

pub async fn build_and_transfer(
    desired: &DesiredState,
    context: &lightrail_plugin_protocol::OperationContext,
    target: &TargetState,
    document: &Value,
    inventory: &ComposeInventory,
    revision: &str,
) -> Result<BTreeMap<String, String>, ComposePluginError> {
    let images = crate::compose_model::image_map(desired, inventory, revision)?;
    if images.is_empty() {
        return Ok(images);
    }

    let root = desired.project_root(context)?;
    let mut build_document = document.clone();
    if let Some(services) = build_document
        .get_mut("services")
        .and_then(Value::as_object_mut)
    {
        for service in services.values_mut().filter_map(Value::as_object_mut) {
            for field in [
                "environment",
                "env_file",
                "ports",
                "labels",
                "networks",
                "volumes",
            ] {
                service.remove(field);
            }
        }
    }
    let build_source = temporary_compose_file("lightrail-compose-")?;
    std::fs::write(build_source.path(), serde_json::to_vec(&build_document)?)?;
    let override_value = build_override(&images, target.platform(), desired);
    let temporary = temporary_compose_file("lightrail-build-")?;
    std::fs::write(temporary.path(), serde_json::to_vec(&override_value)?)?;

    let mut arguments = vec![OsString::from("buildx"), OsString::from("bake")];
    arguments.push(OsString::from("-f"));
    arguments.push(build_source.path().as_os_str().to_owned());
    arguments.push(OsString::from("-f"));
    arguments.push(temporary.path().as_os_str().to_owned());
    arguments.push(OsString::from("--load"));
    arguments.extend(images.keys().map(OsString::from));
    run_local("docker", arguments, Some(root), None).await?;

    for image in images.values() {
        let local_id = run_local(
            "docker",
            ["image", "inspect", "--format", "{{.Id}}", "--", image],
            None,
            None,
        )
        .await?;
        let remote_id = run_ssh(
            target,
            [
                "docker", "image", "inspect", "--format", "{{.Id}}", "--", image,
            ],
        )
        .await;
        let is_same_image = remote_id
            .is_ok_and(|remote| trim_ascii(&remote.stdout) == trim_ascii(&local_id.stdout));
        if !is_same_image {
            stream_image(target, image).await?;
        }
    }
    Ok(images)
}

fn temporary_compose_file(prefix: &str) -> Result<tempfile::NamedTempFile, ComposePluginError> {
    // Buildx selects its Bake parser from the filename. JSON is valid YAML,
    // but a `.json` suffix is interpreted as native Bake JSON and ignores the
    // Compose `services` object entirely.
    Ok(tempfile::Builder::new()
        .prefix(prefix)
        .suffix(".compose.yaml")
        .tempfile()?)
}

#[allow(clippy::too_many_lines)]
pub async fn deploy(
    desired: &DesiredState,
    target: &TargetState,
    config: &PluginConfig,
    rendered: &RenderedDeployment,
    revision: &str,
    operation_id: &str,
) -> Result<Value, ComposePluginError> {
    let layout = RemoteLayout::new(target, &desired.environment.id)?;
    ensure_ingress(target, desired, config, &layout).await?;
    backup_previous(target, &layout, operation_id).await?;
    let mut base = rendered.base.clone();
    upload_compose_assets(target, desired, &layout, &mut base).await?;

    upload_json(
        target,
        &layout.environment_directory,
        &layout.base,
        &base,
        0o600,
    )
    .await?;
    upload_json(
        target,
        &layout.environment_directory,
        &layout.runtime_override,
        &rendered.runtime_override,
        0o600,
    )
    .await?;
    let initial_manifest = public_manifest(desired, revision, &json!({}));
    upload_json(
        target,
        &layout.environment_directory,
        &layout.manifest,
        &initial_manifest,
        0o600,
    )
    .await?;

    let mut arguments = layout.compose_arguments(&desired.environment.id);
    pull_external_images(target, &base, &rendered.images).await?;
    let environment_override = rendered
        .environment_override
        .as_ref()
        .map(|_| layout.operation_environment_override(operation_id));
    if let Some(environment_override) = environment_override.as_ref() {
        cleanup_stale_environment_overrides(target, &layout).await?;
        arguments.extend(["-f".to_owned(), environment_override.clone()]);
    }
    arguments.extend([
        "up".to_owned(),
        "-d".to_owned(),
        "--remove-orphans".to_owned(),
        "--wait".to_owned(),
        "--wait-timeout".to_owned(),
        config.readiness_timeout_seconds.to_string(),
    ]);
    if desired.environment.dirty {
        arguments.push("--force-recreate".to_owned());
    }

    let deployed = if let (Some(environment_override), Some(environment)) = (
        environment_override.as_deref(),
        rendered.environment_override.as_ref(),
    ) {
        run_compose_with_secret_environment(target, &arguments, environment_override, environment)
            .await
    } else {
        run_ssh(target, &arguments).await
    };
    if let Err(error) = deployed {
        let _ = rollback_previous(
            target,
            &layout,
            &desired.environment.id,
            operation_id,
            rendered.environment_override.as_ref(),
        )
        .await;
        return Err(error);
    }

    if config.stable_window_seconds > 0 {
        sleep(Duration::from_secs(config.stable_window_seconds)).await;
        let inspected = inspect_remote(desired, target, config).await?;
        if inspected.status != ResourceStatus::Ready {
            let _ = rollback_previous(
                target,
                &layout,
                &desired.environment.id,
                operation_id,
                rendered.environment_override.as_ref(),
            )
            .await;
            return Err(ComposePluginError::CommandFailed {
                program: "docker compose readiness".to_owned(),
                status: "containers did not remain ready during the stable window".to_owned(),
            });
        }
    }
    let resolved_images = resolve_remote_images(target, &base).await?;
    let public_manifest = public_manifest(desired, revision, &resolved_images);
    upload_json(
        target,
        &layout.environment_directory,
        &layout.manifest,
        &public_manifest,
        0o600,
    )
    .await?;

    Ok(json!({
        "revision": revision,
        "environment_id": desired.environment.id,
        "project_id": desired.project.id,
        "isolation": desired.environment.isolation,
        "remote_directory": layout.environment_directory,
        "images": resolved_images,
        "endpoints": endpoints(desired, target, config)?,
    }))
}

async fn cleanup_stale_environment_overrides(
    target: &TargetState,
    layout: &RemoteLayout,
) -> Result<(), ComposePluginError> {
    let directory = crate::command::shell_quote(&layout.environment_directory);
    let pattern = crate::command::shell_quote("environment.*.tmp.json*");
    let script = format!(
        "if [ -d {directory} ]; then find {directory} -maxdepth 1 -type f -name {pattern} \
         -exec rm -f -- {{}} +; fi"
    );
    run_ssh_script(target, &script, None).await?;
    Ok(())
}

async fn run_compose_with_secret_environment(
    target: &TargetState,
    arguments: &[String],
    environment_override: &str,
    environment: &Value,
) -> Result<crate::command::CommandOutput, ComposePluginError> {
    let script = secret_environment_script(target, arguments, environment_override);
    let mut contents = serde_json::to_vec(environment)?;
    contents.push(b'\n');
    run_ssh_script(target, &script, Some(&contents)).await
}

fn secret_environment_script(
    target: &TargetState,
    arguments: &[String],
    environment_override: &str,
) -> String {
    let command = target
        .docker_arguments(arguments.iter().skip(1).cloned())
        .iter()
        .map(|argument| crate::command::shell_quote(argument))
        .collect::<Vec<_>>()
        .join(" ");
    let environment_override = crate::command::shell_quote(environment_override);
    format!(
        "set -e; umask 077; \
         cleanup_lightrail_secret_env() {{ rm -f -- {environment_override}; }}; \
         trap cleanup_lightrail_secret_env EXIT; trap 'exit 129' HUP INT TERM; \
         cat > {environment_override}; chmod 600 -- {environment_override}; {command}"
    )
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    bytes.trim_ascii()
}

fn service_images(document: &Value) -> Result<BTreeMap<String, String>, ComposePluginError> {
    let services = document
        .get("services")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            ComposePluginError::InvalidDesired(
                "resolved deployment has no services object".to_owned(),
            )
        })?;
    services
        .iter()
        .map(|(service, value)| {
            let image = value.get("image").and_then(Value::as_str).ok_or_else(|| {
                ComposePluginError::InvalidDesired(format!(
                    "resolved service `{service}` has no image"
                ))
            })?;
            Ok((service.clone(), image.to_owned()))
        })
        .collect()
}

async fn pull_external_images(
    target: &TargetState,
    document: &Value,
    built_images: &BTreeMap<String, String>,
) -> Result<(), ComposePluginError> {
    for (service, image) in service_images(document)? {
        if !built_images.contains_key(&service) {
            run_ssh(
                target,
                [
                    "docker",
                    "image",
                    "pull",
                    "--platform",
                    target.platform(),
                    "--",
                    image.as_str(),
                ],
            )
            .await?;
        }
    }
    Ok(())
}

async fn resolve_remote_images(
    target: &TargetState,
    document: &Value,
) -> Result<Value, ComposePluginError> {
    let mut images = serde_json::Map::new();
    for (service, reference) in service_images(document)? {
        let id = run_ssh(
            target,
            [
                "docker",
                "image",
                "inspect",
                "--format",
                "{{.Id}}",
                "--",
                reference.as_str(),
            ],
        )
        .await?;
        let repo_digests = run_ssh(
            target,
            [
                "docker",
                "image",
                "inspect",
                "--format",
                "{{json .RepoDigests}}",
                "--",
                reference.as_str(),
            ],
        )
        .await?;
        let repo_digests: Vec<String> =
            serde_json::from_slice(trim_ascii(&repo_digests.stdout)).unwrap_or_default();
        images.insert(
            service,
            json!({
                "reference": reference,
                "id": String::from_utf8_lossy(trim_ascii(&id.stdout)),
                "repo_digests": repo_digests,
            }),
        );
    }
    Ok(Value::Object(images))
}

async fn upload_compose_assets(
    target: &TargetState,
    desired: &DesiredState,
    layout: &RemoteLayout,
    document: &mut Value,
) -> Result<(), ComposePluginError> {
    for kind in ["configs", "secrets"] {
        let assets = document
            .get(kind)
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(|definitions| definitions.iter())
            .filter_map(|(name, definition)| {
                definition
                    .get("file")
                    .and_then(Value::as_str)
                    .map(|file| (name.clone(), file.to_owned()))
            })
            .collect::<Vec<_>>();
        for (name, file) in assets {
            if !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            {
                return Err(ComposePluginError::InvalidDesired(format!(
                    "{kind} entry `{name}` has an unsafe name"
                )));
            }
            let local = std::path::PathBuf::from(&file);
            let local = if local.is_absolute() {
                local
            } else {
                desired
                    .project
                    .root
                    .as_ref()
                    .ok_or(ComposePluginError::MissingProjectRoot)?
                    .join(local)
            };
            let remote_directory = format!("{}/assets", layout.environment_directory);
            let remote = format!("{remote_directory}/{kind}-{name}");
            let contents = tokio::fs::read(&local)
                .await
                .map_err(ComposePluginError::TemporaryFile)?;
            upload_atomic(target, &remote_directory, &remote, &contents, 0o600).await?;
            document[kind][&name]["file"] = Value::String(remote);
        }
    }
    Ok(())
}

async fn ensure_ingress(
    target: &TargetState,
    desired: &DesiredState,
    config: &PluginConfig,
    layout: &RemoteLayout,
) -> Result<(), ComposePluginError> {
    ensure_ingress_compatibility(target, config, layout).await?;
    upload_json(
        target,
        &layout.ingress_directory,
        &layout.ingress_compose,
        &ingress_compose(config),
        0o600,
    )
    .await?;
    run_ssh(
        target,
        [
            "docker",
            "compose",
            "-p",
            "lightrail-ingress",
            "-f",
            layout.ingress_compose.as_str(),
            "up",
            "-d",
            "--remove-orphans",
        ],
    )
    .await?;
    let ingress_network = environment_ingress_network(config, &desired.environment.id)?;
    let docker = target.docker_shell();
    let network = crate::command::shell_quote(&ingress_network);
    let project_id =
        crate::command::shell_quote(&format!("lightrail-project-id={}", desired.project.id));
    let environment_id = crate::command::shell_quote(&format!(
        "lightrail-environment-id={}",
        desired.environment.id
    ));
    let script = format!(
        "{docker} network inspect {network} >/dev/null 2>&1 || {docker} network create \
         --label lightrail-managed=true --label {project_id} --label {environment_id} {network}"
    );
    run_ssh_script(target, &script, None).await?;
    let container = "lightrail-ingress-traefik";
    let format = crate::command::shell_quote(r"{{range .Containers}}{{println .Name}}{{end}}");
    let connect = format!(
        "{docker} network connect {network} {container} >/dev/null 2>&1 || \
         {docker} network inspect --format {format} {network} | grep -Fxq {container}"
    );
    run_ssh_script(target, &connect, None).await?;
    Ok(())
}

fn ingress_compatibility(config: &PluginConfig) -> Value {
    let model = json!({
        "schema": 1,
        "ingress_image": config.ingress_image,
        "certificate_resolver": config.certificate_resolver,
        "dns_domain": config.dns_domain,
        "acme_email": config.acme_email,
        "ingress_network": config.ingress_network,
        "network_model": "shared-traefik-per-environment-network-v1",
    });
    json!({
        "schema": 1,
        "fingerprint": format!("{:x}", Sha256::digest(
            serde_json::to_vec(&model).unwrap_or_default()
        )),
        "model": model,
    })
}

async fn ensure_ingress_compatibility(
    target: &TargetState,
    config: &PluginConfig,
    layout: &RemoteLayout,
) -> Result<(), ComposePluginError> {
    const COMPATIBLE: &str = "__LIGHTRAIL_INGRESS_COMPATIBLE__";
    const INCOMPATIBLE: &str = "__LIGHTRAIL_INGRESS_INCOMPATIBLE__";
    const UNTRACKED: &str = "__LIGHTRAIL_INGRESS_UNTRACKED__";
    let directory = crate::command::shell_quote(&layout.ingress_directory);
    let compatibility = crate::command::shell_quote(&layout.ingress_compatibility);
    let ingress_compose = crate::command::shell_quote(&layout.ingress_compose);
    let candidate =
        crate::command::shell_quote(&format!("{}.candidate.$$", layout.ingress_compatibility));
    let script = format!(
        "set -e; umask 077; mkdir -p -- {directory}; \
         cleanup_ingress_candidate() {{ rm -f -- {candidate}; }}; \
         trap cleanup_ingress_candidate EXIT; trap 'exit 129' HUP INT TERM; \
         cat > {candidate}; \
         if [ -e {ingress_compose} ] && [ ! -f {compatibility} ]; then \
             printf '%s\\n' {untracked}; \
         elif [ -f {compatibility} ] && ! cmp -s -- {compatibility} {candidate}; then \
             printf '%s\\n' {incompatible}; \
         else \
             if [ ! -f {compatibility} ]; then mv -f -- {candidate} {compatibility}; fi; \
             printf '%s\\n' {compatible}; \
         fi",
        compatible = crate::command::shell_quote(COMPATIBLE),
        incompatible = crate::command::shell_quote(INCOMPATIBLE),
        untracked = crate::command::shell_quote(UNTRACKED),
    );
    let mut contents = serde_json::to_vec_pretty(&ingress_compatibility(config))?;
    contents.push(b'\n');
    let output = run_ssh_script(target, &script, Some(&contents)).await?;
    match trim_ascii(&output.stdout) {
        marker if marker == COMPATIBLE.as_bytes() => Ok(()),
        marker if marker == INCOMPATIBLE.as_bytes() => Err(ComposePluginError::InvalidDesired(
            "shared Traefik already uses an incompatible ingress configuration on this host"
                .to_owned(),
        )),
        marker if marker == UNTRACKED.as_bytes() => Err(ComposePluginError::InvalidDesired(
            "shared Traefik exists without a Lightrail compatibility record; refusing to overwrite it"
                .to_owned(),
        )),
        _ => Err(ComposePluginError::CommandFailed {
            program: "shared ingress compatibility check".to_owned(),
            status: "remote check returned an invalid acknowledgement".to_owned(),
        }),
    }
}

async fn backup_previous(
    target: &TargetState,
    layout: &RemoteLayout,
    operation_id: &str,
) -> Result<(), ComposePluginError> {
    let marker = format!("{}/rollback.operation", layout.environment_directory);
    let completed = format!("{}/rollback.completed", layout.environment_directory);
    let mut script = format!(
        "set -e; mkdir -p -- {directory}; ",
        directory = crate::command::shell_quote(&layout.environment_directory),
    );
    for path in [&layout.base, &layout.runtime_override, &layout.manifest] {
        script.push_str(&format!(
            "if [ -f {path} ]; then cp -f -- {path} {previous}; else rm -f -- {previous}; fi; ",
            path = crate::command::shell_quote(path),
            previous = crate::command::shell_quote(&format!("{path}.previous")),
        ));
    }
    script.push_str(&format!(
        "rm -f -- {completed}; printf '%s\\n' {operation_id} > {marker}",
        operation_id = crate::command::shell_quote(operation_id),
        marker = crate::command::shell_quote(&marker),
        completed = crate::command::shell_quote(&completed),
    ));
    run_ssh_script(target, &script, None).await?;
    Ok(())
}

async fn rollback_previous(
    target: &TargetState,
    layout: &RemoteLayout,
    environment_id: &str,
    operation_id: &str,
    environment_override: Option<&Value>,
) -> Result<(), ComposePluginError> {
    let paths = [&layout.base, &layout.runtime_override, &layout.manifest];
    let marker = format!("{}/rollback.operation", layout.environment_directory);
    let completed = format!("{}/rollback.completed", layout.environment_directory);
    let restored_operation = format!("restored:{operation_id}");
    let mut script = format!(
        "set -e; state=$(cat -- {marker} 2>/dev/null || true); \
         completed=$(cat -- {completed} 2>/dev/null || true); \
         if [ \"$state\" = {operation_id} ]; then restored=0; ",
        marker = crate::command::shell_quote(&marker),
        completed = crate::command::shell_quote(&completed),
        operation_id = crate::command::shell_quote(operation_id),
    );
    for path in paths {
        script.push_str(&format!(
            "if [ -f {previous} ]; then mv -f -- {previous} {path}; restored=1; fi; ",
            path = crate::command::shell_quote(path),
            previous = crate::command::shell_quote(&format!("{path}.previous")),
        ));
    }
    script.push_str(&format!(
        "[ \"$restored\" -eq 1 ]; printf '%s\\n' {restored_operation} > {marker}; \
         elif [ \"$state\" = {restored_operation} ] || [ \"$completed\" = {operation_id} ]; \
         then :; else exit 74; fi",
        marker = crate::command::shell_quote(&marker),
        operation_id = crate::command::shell_quote(operation_id),
        restored_operation = crate::command::shell_quote(&restored_operation),
    ));
    run_ssh_script(target, &script, None).await?;
    let mut arguments = layout.compose_arguments(environment_id);
    let environment_override_path =
        environment_override.map(|_| layout.operation_environment_override(operation_id));
    if let Some(environment_override_path) = environment_override_path.as_ref() {
        cleanup_stale_environment_overrides(target, layout).await?;
        arguments.extend(["-f".to_owned(), environment_override_path.clone()]);
    }
    arguments.extend([
        "up".to_owned(),
        "-d".to_owned(),
        "--remove-orphans".to_owned(),
    ]);
    if let (Some(environment_override_path), Some(environment_override)) =
        (environment_override_path.as_deref(), environment_override)
    {
        run_compose_with_secret_environment(
            target,
            &arguments,
            environment_override_path,
            environment_override,
        )
        .await?;
    } else {
        run_ssh(target, arguments).await?;
    }
    let finish = format!(
        "set -e; printf '%s\\n' {operation_id} > {completed}; rm -f -- {marker}",
        operation_id = crate::command::shell_quote(operation_id),
        completed = crate::command::shell_quote(&completed),
        marker = crate::command::shell_quote(&marker),
    );
    run_ssh_script(target, &finish, None).await?;
    Ok(())
}

pub async fn restore_previous(
    context: &lightrail_plugin_protocol::OperationContext,
    target: &TargetState,
    config: &PluginConfig,
    prior_revision: Option<&str>,
) -> Result<(), ComposePluginError> {
    let layout = RemoteLayout::new(target, &context.environment_id)?;
    let marker_state = read_rollback_marker(target, &layout).await?;
    if marker_state.is_none() {
        let live_revision = load_remote_manifest_at(target, &layout)
            .await?
            .and_then(|manifest| manifest.revision);
        if rollback_is_already_complete(
            marker_state.as_deref(),
            live_revision.as_deref(),
            prior_revision,
        ) {
            return Ok(());
        }
    }
    let rollback_desired = context
        .metadata
        .get("rollback_desired")
        .cloned()
        .ok_or_else(|| {
            ComposePluginError::InvalidDesired(
                "rollback metadata is missing the desired secret references".to_owned(),
            )
        })?;
    let desired = DesiredState::parse(rollback_desired)?;
    if desired.environment.id != context.environment_id
        || desired.environment.profile != context.profile
    {
        return Err(ComposePluginError::InvalidDesired(
            "rollback desired identity does not match the operation context".to_owned(),
        ));
    }
    let (document, inventory, revision) = resolve_compose(&desired, context).await?;
    let environment = desired.resolve_app_environment(&context.secrets)?;
    let rendered = crate::compose_model::render_deployment(
        &desired,
        &document,
        &inventory,
        target,
        config,
        &environment,
        &revision,
    )?;
    rollback_previous(
        target,
        &layout,
        &context.environment_id,
        &context.operation_id,
        rendered.environment_override.as_ref(),
    )
    .await
}

async fn read_rollback_marker(
    target: &TargetState,
    layout: &RemoteLayout,
) -> Result<Option<String>, ComposePluginError> {
    const ABSENT_MARKER: &str = "__LIGHTRAIL_ROLLBACK_MARKER_ABSENT__";
    let marker_path = crate::command::shell_quote(&format!(
        "{}/rollback.operation",
        layout.environment_directory
    ));
    let absent = crate::command::shell_quote(ABSENT_MARKER);
    let script = format!(
        "if [ -f {marker_path} ]; then cat -- {marker_path}; \
         else printf '%s\\n' {absent}; fi"
    );
    let output = run_ssh_script(target, &script, None).await?;
    let state = String::from_utf8_lossy(trim_ascii(&output.stdout));
    Ok((state != ABSENT_MARKER).then(|| state.into_owned()))
}

fn rollback_is_already_complete(
    marker_state: Option<&str>,
    live_revision: Option<&str>,
    prior_revision: Option<&str>,
) -> bool {
    marker_state.is_none() && prior_revision.is_some() && live_revision == prior_revision
}

async fn upload_json(
    target: &TargetState,
    directory: &str,
    path: &str,
    value: &Value,
    mode: u16,
) -> Result<(), ComposePluginError> {
    let mut contents = serde_json::to_vec_pretty(value)?;
    contents.push(b'\n');
    upload_atomic(target, directory, path, &contents, mode).await
}

fn public_manifest(desired: &DesiredState, revision: &str, images: &Value) -> Value {
    let mut desired = desired.clone();
    desired.target = Value::Null;
    desired.resolved_compose_path = None;
    for app in &mut desired.apps {
        app.environment.clear();
    }
    json!({
        "schema": 1,
        "desired": desired,
        "revision": revision,
        "images": images,
    })
}

pub async fn load_remote_manifest(
    context: &lightrail_plugin_protocol::OperationContext,
    target: &TargetState,
) -> Result<Option<RemoteManifest>, ComposePluginError> {
    let layout = RemoteLayout::new(target, &context.environment_id)?;
    load_remote_manifest_at(target, &layout).await
}

async fn load_remote_manifest_at(
    target: &TargetState,
    layout: &RemoteLayout,
) -> Result<Option<RemoteManifest>, ComposePluginError> {
    let manifest_path = crate::command::shell_quote(&layout.manifest);
    let marker = crate::command::shell_quote(ABSENT_MANIFEST_MARKER);
    let script = format!(
        "if [ ! -e {manifest_path} ]; then printf '%s\\n' {marker}; \
         elif [ -f {manifest_path} ]; then cat -- {manifest_path}; else exit 66; fi"
    );
    let output = run_ssh_script(target, &script, None).await?;
    decode_remote_manifest(&output.stdout)
}

fn decode_remote_manifest(contents: &[u8]) -> Result<Option<RemoteManifest>, ComposePluginError> {
    if trim_ascii(contents) == ABSENT_MANIFEST_MARKER.as_bytes() {
        return Ok(None);
    }
    let manifest: Value = serde_json::from_slice(contents)?;
    let desired = manifest
        .get("desired")
        .cloned()
        .unwrap_or_else(|| manifest.clone());
    let desired = DesiredState::parse(desired)?;
    Ok(Some(RemoteManifest {
        desired,
        revision: manifest
            .get("revision")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        images: manifest.get("images").cloned().unwrap_or_else(|| json!({})),
    }))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct OrphanResourceCounts {
    containers: u64,
    images: u64,
    networks: u64,
    volumes: u64,
}

impl OrphanResourceCounts {
    const fn is_empty(self) -> bool {
        self.containers == 0 && self.images == 0 && self.networks == 0 && self.volumes == 0
    }
}

pub async fn inspect_orphan_resources(
    target: &TargetState,
    project_id: &str,
    environment_id: &str,
) -> Result<InspectResult, ComposePluginError> {
    let script = orphan_inspection_script(target, project_id, environment_id);
    let output = run_ssh_script(target, &script, None).await?;
    let counts = decode_orphan_resource_counts(&output.stdout)?;
    Ok(orphan_inspection_result(project_id, environment_id, counts))
}

fn orphan_inspection_script(
    target: &TargetState,
    project_id: &str,
    environment_id: &str,
) -> String {
    let docker = target.docker_shell();
    let managed_label = crate::command::shell_quote("lightrail-managed=true");
    let project_label = crate::command::shell_quote(&format!("lightrail-project-id={project_id}"));
    let environment_label =
        crate::command::shell_quote(&format!("lightrail-environment-id={environment_id}"));
    format!(
        "set -e; \
         containers=$({docker} ps -aq --filter label={managed_label} \
             --filter label={project_label} --filter label={environment_label}); \
         container_count=0; \
         for resource in $containers; do container_count=$((container_count + 1)); done; \
         networks=$({docker} network ls -q --filter label={managed_label} \
             --filter label={project_label} --filter label={environment_label}); \
         network_count=0; \
         for resource in $networks; do network_count=$((network_count + 1)); done; \
         volumes=$({docker} volume ls -q --filter label={managed_label} \
             --filter label={project_label} --filter label={environment_label}); \
         volume_count=0; \
         for resource in $volumes; do volume_count=$((volume_count + 1)); done; \
         images=$({docker} image ls --format '{{{{.Repository}}}}:{{{{.Tag}}}}' \
             --filter label={managed_label} --filter label={project_label} \
             --filter label={environment_label}); \
         image_count=0; \
         for image in $images; do \
             case \"$image\" in lightrail/*:*) image_count=$((image_count + 1));; esac; \
         done; \
         printf '{{\"containers\":%s,\"images\":%s,\"networks\":%s,\"volumes\":%s}}\\n' \
             \"$container_count\" \"$image_count\" \"$network_count\" \"$volume_count\""
    )
}

fn decode_orphan_resource_counts(
    contents: &[u8],
) -> Result<OrphanResourceCounts, ComposePluginError> {
    serde_json::from_slice(contents).map_err(ComposePluginError::Serialization)
}

fn orphan_inspection_result(
    project_id: &str,
    environment_id: &str,
    counts: OrphanResourceCounts,
) -> InspectResult {
    let (status, status_name, diagnostics) = if counts.is_empty() {
        (ResourceStatus::Absent, "absent", Vec::new())
    } else {
        (
            ResourceStatus::Degraded,
            "degraded",
            vec![Diagnostic {
                severity: DiagnosticSeverity::Warning,
                code: "remote_manifest_missing".to_owned(),
                message: "Managed Docker resources exist, but their Lightrail manifest is missing"
                    .to_owned(),
                path: None,
                help: Some(
                    "Run `lightrail down` to remove only resources carrying this project's exact environment labels"
                        .to_owned(),
                ),
            }],
        )
    };
    InspectResult {
        status,
        endpoints: Vec::new(),
        state: json!({
            "status": status_name,
            "project_id": project_id,
            "environment_id": environment_id,
            "manifest": "missing",
            "orphan_resources": {
                "containers": counts.containers,
                "images": counts.images,
                "networks": counts.networks,
                "volumes": counts.volumes,
            },
        }),
        diagnostics,
    }
}

pub async fn inspect_remote(
    desired: &DesiredState,
    target: &TargetState,
    config: &PluginConfig,
) -> Result<InspectResult, ComposePluginError> {
    let output = run_ssh(
        target,
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            &format!(
                "label=com.docker.compose.project={}",
                desired.environment.id
            ),
            "--format",
            "{{json .}}",
        ],
    )
    .await?;
    let lines = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    if lines.is_empty() {
        return Ok(InspectResult {
            status: ResourceStatus::Absent,
            endpoints: Vec::new(),
            state: json!({
                "environment_id": desired.environment.id,
                "project_id": desired.project.id,
                "isolation": desired.environment.isolation,
                "containers": [],
            }),
            diagnostics: Vec::new(),
        });
    }

    let live_count = lines
        .iter()
        .filter(|container| container.get("State").and_then(Value::as_str) == Some("running"))
        .count();
    let unhealthy = lines.iter().filter(|container| {
        container
            .get("State")
            .and_then(Value::as_str)
            .is_some_and(|state| state != "running")
            || container
                .get("Status")
                .and_then(Value::as_str)
                .is_some_and(|status| status.to_ascii_lowercase().contains("unhealthy"))
    });
    let unhealthy_count = unhealthy.count();
    let status = if unhealthy_count == 0 {
        ResourceStatus::Ready
    } else {
        ResourceStatus::Degraded
    };
    let diagnostics = (unhealthy_count > 0)
        .then(|| Diagnostic {
            severity: DiagnosticSeverity::Warning,
            code: "containers_not_ready".to_owned(),
            message: format!("{unhealthy_count} Compose container(s) are not ready"),
            path: None,
            help: Some("Inspect `lightrail logs` and container health checks".to_owned()),
        })
        .into_iter()
        .collect();
    Ok(InspectResult {
        status,
        endpoints: inspected_endpoints(desired, target, config, live_count)?,
        state: json!({
            "environment_id": desired.environment.id,
            "project_id": desired.project.id,
            "isolation": desired.environment.isolation,
            "containers": lines,
        }),
        diagnostics,
    })
}

fn inspected_endpoints(
    desired: &DesiredState,
    target: &TargetState,
    config: &PluginConfig,
    live_count: usize,
) -> Result<Vec<Endpoint>, ComposePluginError> {
    if live_count == 0 {
        Ok(Vec::new())
    } else {
        endpoints(desired, target, config)
    }
}

#[allow(clippy::too_many_lines)]
pub async fn inspect_project(
    target: &TargetState,
    project_id: &str,
    config: &PluginConfig,
) -> Result<InspectResult, ComposePluginError> {
    let mut environments = discover_labeled_environment_ids(target, project_id).await?;
    for environment_id in list_remote_environment_ids(target).await? {
        let layout = RemoteLayout::new(target, &environment_id)?;
        if load_remote_manifest_at(target, &layout)
            .await?
            .is_some_and(|manifest| {
                manifest.desired.project.id == project_id
                    && manifest.desired.environment.id == environment_id
            })
        {
            environments.insert(environment_id);
        }
    }

    let mut aggregate_endpoints = Vec::new();
    let mut environment_states = Vec::new();
    let mut any_ready = false;
    let mut any_degraded = false;
    for environment_id in environments {
        let layout = RemoteLayout::new(target, &environment_id)?;
        let Some(manifest) = load_remote_manifest_at(target, &layout).await? else {
            any_degraded = true;
            environment_states.push(json!({
                "environment_id": environment_id,
                "status": "degraded",
                "live": true,
                "reason": "managed Docker resources exist without a valid Lightrail manifest",
                "endpoints": [],
            }));
            continue;
        };
        if manifest.desired.project.id != project_id
            || manifest.desired.environment.id != environment_id
        {
            any_degraded = true;
            continue;
        }
        let inspected = inspect_remote(&manifest.desired, target, config).await?;
        any_ready |= inspected.status == ResourceStatus::Ready;
        any_degraded |= inspected.status == ResourceStatus::Degraded;
        aggregate_endpoints.extend(inspected.endpoints.iter().cloned());
        environment_states.push(json!({
            "environment_id": environment_id,
            "branch": manifest.desired.environment.branch,
            "profile": manifest.desired.environment.profile,
            "status": inspected.status,
            "live": !matches!(inspected.status, ResourceStatus::Absent),
            "revision": manifest.revision,
            "endpoints": inspected.endpoints,
        }));
    }
    let status = if environment_states.is_empty() {
        ResourceStatus::Absent
    } else if any_degraded {
        ResourceStatus::Degraded
    } else if any_ready {
        ResourceStatus::Ready
    } else {
        ResourceStatus::Pending
    };
    Ok(InspectResult {
        status,
        endpoints: aggregate_endpoints,
        state: json!({
            "project_id": project_id,
            "environments": environment_states,
        }),
        diagnostics: Vec::new(),
    })
}

async fn discover_labeled_environment_ids(
    target: &TargetState,
    project_id: &str,
) -> Result<BTreeSet<String>, ComposePluginError> {
    let managed_filter = "label=lightrail-managed=true".to_owned();
    let project_filter = format!("label=lightrail-project-id={project_id}");
    let environment_format = r#"{{.Label "lightrail-environment-id"}}"#.to_owned();
    let mut environments = BTreeSet::new();
    for arguments in
        labeled_resource_discovery_commands(&managed_filter, &project_filter, &environment_format)
    {
        let output = run_ssh(target, arguments).await?;
        environments.extend(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(str::trim)
                .filter(|environment| {
                    !environment.is_empty() && RemoteLayout::new(target, environment).is_ok()
                })
                .map(ToOwned::to_owned),
        );
    }

    let image_script = labeled_image_inspection_script(target, project_id);
    let output = run_ssh_script(target, &image_script, None).await?;
    environments.extend(decode_owned_image_environment_ids(
        target,
        project_id,
        &output.stdout,
    )?);
    Ok(environments)
}

fn labeled_resource_discovery_commands(
    managed_filter: &str,
    project_filter: &str,
    environment_format: &str,
) -> [Vec<String>; 3] {
    [
        vec![
            "docker".to_owned(),
            "ps".to_owned(),
            "-a".to_owned(),
            "--filter".to_owned(),
            managed_filter.to_owned(),
            "--filter".to_owned(),
            project_filter.to_owned(),
            "--format".to_owned(),
            environment_format.to_owned(),
        ],
        vec![
            "docker".to_owned(),
            "network".to_owned(),
            "ls".to_owned(),
            "--filter".to_owned(),
            managed_filter.to_owned(),
            "--filter".to_owned(),
            project_filter.to_owned(),
            "--format".to_owned(),
            environment_format.to_owned(),
        ],
        vec![
            "docker".to_owned(),
            "volume".to_owned(),
            "ls".to_owned(),
            "--filter".to_owned(),
            managed_filter.to_owned(),
            "--filter".to_owned(),
            project_filter.to_owned(),
            "--format".to_owned(),
            environment_format.to_owned(),
        ],
    ]
}

fn labeled_image_inspection_script(target: &TargetState, project_id: &str) -> String {
    let docker = target.docker_shell();
    let managed_filter = crate::command::shell_quote("label=lightrail-managed=true");
    let project_filter =
        crate::command::shell_quote(&format!("label=lightrail-project-id={project_id}"));
    let json_format = crate::command::shell_quote("{{json .}}");
    format!(
        "set -e; \
         image_ids=$({docker} image ls --quiet --no-trunc \
             --filter {managed_filter} --filter {project_filter}); \
         for image_id in $image_ids; do \
             {docker} image inspect --format {json_format} \"$image_id\"; \
         done"
    )
}

#[derive(Debug, Deserialize)]
struct InspectedImage {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "RepoTags", default)]
    repo_tags: Option<Vec<String>>,
    #[serde(rename = "Config")]
    config: InspectedImageConfig,
}

#[derive(Debug, Deserialize)]
struct InspectedImageConfig {
    #[serde(rename = "Labels")]
    labels: BTreeMap<String, String>,
}

fn decode_owned_image_environment_ids(
    target: &TargetState,
    project_id: &str,
    contents: &[u8],
) -> Result<BTreeSet<String>, ComposePluginError> {
    let contents = std::str::from_utf8(contents).map_err(|_| {
        ComposePluginError::InvalidDesired(
            "Docker image discovery returned non-UTF-8 output".to_owned(),
        )
    })?;
    let mut environments = BTreeSet::new();
    let mut image_ids = BTreeMap::new();
    for line in contents.lines().filter(|line| !line.is_empty()) {
        let image: InspectedImage = serde_json::from_str(line).map_err(|_| {
            ComposePluginError::InvalidDesired(
                "Docker image inspection returned malformed output".to_owned(),
            )
        })?;
        if image.id.trim().is_empty() {
            return Err(ComposePluginError::InvalidDesired(
                "Docker image inspection returned an empty image ID".to_owned(),
            ));
        }
        let labels = &image.config.labels;
        if labels.get("lightrail-managed").map(String::as_str) != Some("true")
            || labels.get("lightrail-project-id").map(String::as_str) != Some(project_id)
        {
            return Err(ComposePluginError::InvalidDesired(
                "Docker image ownership labels changed during discovery".to_owned(),
            ));
        }
        let environment_id = labels
            .get("lightrail-environment-id")
            .filter(|environment_id| RemoteLayout::new(target, environment_id).is_ok())
            .ok_or_else(|| {
                ComposePluginError::InvalidDesired(
                    "Docker image has an invalid Lightrail environment label".to_owned(),
                )
            })?;
        let owned_environment = image
            .repo_tags
            .as_deref()
            .unwrap_or_default()
            .iter()
            .any(|tag| is_lightrail_image_reference(tag))
            .then(|| environment_id.clone());
        if let Some(previous) = image_ids.insert(image.id, owned_environment.clone()) {
            if previous != owned_environment {
                return Err(ComposePluginError::InvalidDesired(
                    "duplicate Docker image inspection records disagree on ownership".to_owned(),
                ));
            }
        }
        if let Some(environment_id) = owned_environment {
            environments.insert(environment_id.clone());
        }
    }
    Ok(environments)
}

fn is_lightrail_image_reference(image: &str) -> bool {
    image.rsplit_once(':').is_some_and(|(repository, tag)| {
        repository
            .strip_prefix("lightrail/")
            .is_some_and(|name| !name.is_empty())
            && !tag.is_empty()
            && tag != "<none>"
    })
}

async fn list_remote_environment_ids(
    target: &TargetState,
) -> Result<BTreeSet<String>, ComposePluginError> {
    let environments_root = format!("{}/environments", target.remote_root.trim_end_matches('/'));
    let environments_root = crate::command::shell_quote(&environments_root);
    let script = format!(
        "if [ -d {environments_root} ]; then \
         find {environments_root} -mindepth 1 -maxdepth 1 -type d -printf '%f\\n'; fi"
    );
    let output = run_ssh_script(target, &script, None).await?;
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|environment_id| !environment_id.is_empty())
        .filter(|environment_id| RemoteLayout::new(target, environment_id).is_ok())
        .map(ToOwned::to_owned)
        .collect())
}

pub async fn destroy_environment(
    context: &lightrail_plugin_protocol::OperationContext,
    target: &TargetState,
    _config: &PluginConfig,
    current: Option<&Value>,
    all: bool,
) -> Result<(), ComposePluginError> {
    let immutable_project_id = crate::project_id_from_context(context)?;
    if all {
        let project_id = current
            .and_then(|state| state.get("project_id"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ComposePluginError::InvalidDesired(
                    "project-wide destroy requires inspected state.project_id".to_owned(),
                )
            })?;
        if project_id != immutable_project_id {
            return Err(ComposePluginError::InvalidDesired(
                "inspected project identity does not match immutable operation metadata".to_owned(),
            ));
        }
        let environments =
            discover_owned_environments(target, &immutable_project_id, current).await?;
        for (environment_id, manifest_owned) in environments {
            let layout = RemoteLayout::new(target, &environment_id)?;
            destroy_owned_environment(
                target,
                &layout,
                &environment_id,
                &immutable_project_id,
                manifest_owned,
            )
            .await?;
        }
        return Ok(());
    }

    let layout = RemoteLayout::new(target, &context.environment_id)?;
    let manifest = load_remote_manifest_at(target, &layout).await?;
    let current_project_id = current
        .and_then(|state| state.get("project_id"))
        .and_then(Value::as_str);
    if let Some(manifest) = &manifest {
        crate::validate_remote_manifest_identity(context, &manifest.desired)?;
    }
    if current_project_id.is_some_and(|project_id| project_id != immutable_project_id) {
        return Err(ComposePluginError::InvalidDesired(
            "inspected project identity does not match immutable operation metadata".to_owned(),
        ));
    }
    destroy_owned_environment(
        target,
        &layout,
        &context.environment_id,
        &immutable_project_id,
        manifest.is_some(),
    )
    .await
}

async fn discover_owned_environments(
    target: &TargetState,
    project_id: &str,
    current: Option<&Value>,
) -> Result<BTreeMap<String, bool>, ComposePluginError> {
    let mut environments = BTreeMap::new();
    for environment_id in current
        .and_then(|state| state.get("environments"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|environment| {
            environment
                .as_str()
                .or_else(|| environment.get("environment_id").and_then(Value::as_str))
        })
    {
        if RemoteLayout::new(target, environment_id).is_ok() {
            environments.insert(environment_id.to_owned(), false);
        }
    }

    for environment_id in discover_labeled_environment_ids(target, project_id).await? {
        environments.insert(environment_id, false);
    }

    for environment_id in list_remote_environment_ids(target).await? {
        let layout = RemoteLayout::new(target, &environment_id)?;
        let Some(manifest) = load_remote_manifest_at(target, &layout).await? else {
            continue;
        };
        if manifest.desired.project.id == project_id
            && manifest.desired.environment.id == environment_id
        {
            environments.insert(environment_id, true);
        }
    }
    Ok(environments)
}

async fn destroy_owned_environment(
    target: &TargetState,
    layout: &RemoteLayout,
    environment_id: &str,
    project_id: &str,
    manifest_owned: bool,
) -> Result<(), ComposePluginError> {
    let script = destroy_owned_environment_script(
        target,
        layout,
        environment_id,
        project_id,
        manifest_owned,
    );
    run_ssh_script(target, &script, None).await?;
    Ok(())
}

fn destroy_owned_environment_script(
    target: &TargetState,
    layout: &RemoteLayout,
    environment_id: &str,
    project_id: &str,
    manifest_owned: bool,
) -> String {
    let docker = target.docker_shell();
    let mut compose = layout.compose_arguments(environment_id);
    compose.extend([
        "down".to_owned(),
        "--remove-orphans".to_owned(),
        "--volumes".to_owned(),
    ]);
    let compose_command = target
        .docker_arguments(compose.into_iter().skip(1))
        .iter()
        .map(|argument| crate::command::shell_quote(argument))
        .collect::<Vec<_>>()
        .join(" ");
    let directory = crate::command::shell_quote(&layout.environment_directory);
    let base = crate::command::shell_quote(&layout.base);
    let runtime_override = crate::command::shell_quote(&layout.runtime_override);
    let managed_label = crate::command::shell_quote("lightrail-managed=true");
    let project_label = crate::command::shell_quote(&format!("lightrail-project-id={project_id}"));
    let environment_label =
        crate::command::shell_quote(&format!("lightrail-environment-id={environment_id}"));
    let remove_directory = if manifest_owned {
        format!("rm -rf -- {directory}")
    } else {
        ":".to_owned()
    };
    format!(
        "set -e; \
         if [ -f {base} ] && [ -f {runtime_override} ] && [ {manifest_owned} = true ]; then \
             {compose_command} >/dev/null 2>&1 || true; \
         fi; \
         containers=$({docker} ps -aq --filter label={managed_label} \
             --filter label={project_label} --filter label={environment_label}); \
         if [ -n \"$containers\" ]; then {docker} rm -f -- $containers; fi; \
         volumes=$({docker} volume ls -q --filter label={managed_label} \
             --filter label={project_label} --filter label={environment_label}); \
         if [ -n \"$volumes\" ]; then {docker} volume rm -f -- $volumes; fi; \
         networks=$({docker} network ls -q --filter label={managed_label} \
             --filter label={project_label} --filter label={environment_label}); \
         for network in $networks; do \
             {docker} network disconnect -f \"$network\" lightrail-ingress-traefik \
                 >/dev/null 2>&1 || true; \
             {docker} network rm -- \"$network\"; \
         done; \
         images=$({docker} image ls --format '{{{{.Repository}}}}:{{{{.Tag}}}}' \
             --filter label={managed_label} --filter label={project_label} \
             --filter label={environment_label} | sort -u); \
         for image in $images; do \
             case \"$image\" in lightrail/*:*) {docker} image rm -- \"$image\";; esac; \
         done; \
         {remove_directory}",
        manifest_owned = if manifest_owned { "true" } else { "false" },
    )
}

pub async fn fetch_logs(
    context: &lightrail_plugin_protocol::OperationContext,
    target: &TargetState,
    service: Option<&str>,
    tail: u64,
) -> Result<Vec<LogRecord>, ComposePluginError> {
    let layout = RemoteLayout::new(target, &context.environment_id)?;
    let mut arguments = layout.compose_arguments(&context.environment_id);
    arguments.extend([
        "logs".to_owned(),
        "--no-color".to_owned(),
        "--timestamps".to_owned(),
        "--tail".to_owned(),
        tail.to_string(),
    ]);
    if let Some(service) = service {
        arguments.push(service.to_owned());
    }
    let output = run_ssh(target, arguments).await?;
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(parse_log_line)
        .collect())
}

pub async fn follow_logs(
    context: &lightrail_plugin_protocol::OperationContext,
    target: TargetState,
    service: Option<String>,
) -> Result<tokio::sync::mpsc::Receiver<String>, ComposePluginError> {
    let layout = RemoteLayout::new(&target, &context.environment_id)?;
    let mut arguments = layout.compose_arguments(&context.environment_id);
    arguments.extend([
        "logs".to_owned(),
        "--no-color".to_owned(),
        "--timestamps".to_owned(),
        "--tail".to_owned(),
        "0".to_owned(),
        "--follow".to_owned(),
    ]);
    if let Some(service) = service {
        arguments.push(service);
    }
    read_ssh_lines(target, arguments).await
}

pub fn parse_log_line(line: &str) -> LogRecord {
    let (service, rest) = line
        .split_once('|')
        .map_or(("compose", line), |(service, rest)| {
            (service.trim(), rest.trim_start())
        });
    let (timestamp, line) = rest
        .split_once(' ')
        .filter(|(timestamp, _)| timestamp.contains('T'))
        .map_or((None, rest), |(timestamp, line)| {
            (Some(timestamp.to_owned()), line)
        });
    LogRecord {
        service: service.to_owned(),
        timestamp,
        line: line.to_owned(),
        stream: None,
    }
}

pub async fn wait_for_endpoints(
    desired: &DesiredState,
    target: &TargetState,
    config: &PluginConfig,
) -> Result<Vec<Endpoint>, ComposePluginError> {
    let endpoints = endpoints(desired, target, config)?;
    let apps = desired
        .apps
        .iter()
        .map(|app| (app.name.as_str(), app))
        .collect::<BTreeMap<_, _>>();
    let deadline = Instant::now() + Duration::from_secs(config.readiness_timeout_seconds);
    let mut tasks = tokio::task::JoinSet::new();
    for endpoint in endpoints.clone() {
        let app = apps
            .get(endpoint.app.as_str())
            .copied()
            .ok_or_else(|| ComposePluginError::MissingService(endpoint.app.clone()))?
            .clone();
        tasks.spawn(wait_for_endpoint(endpoint, app, deadline));
    }
    while let Some(result) = tasks.join_next().await {
        result.map_err(|error| ComposePluginError::InvalidDesired(error.to_string()))??;
    }
    Ok(endpoints)
}

async fn wait_for_endpoint(
    endpoint: Endpoint,
    app: AppSpec,
    deadline: Instant,
) -> Result<(), ComposePluginError> {
    let per_request = Duration::from_secs(app.health_timeout_seconds.unwrap_or(10));
    let interval = Duration::from_secs(app.health_interval_seconds.unwrap_or(2));
    let client = reqwest::Client::builder()
        .timeout(per_request)
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|error| ComposePluginError::InvalidDesired(error.to_string()))?;
    let url = format!(
        "{}{}",
        endpoint.url,
        app.health_path.as_deref().unwrap_or("/")
    );
    loop {
        if Instant::now() >= deadline {
            return Err(ComposePluginError::ReadinessTimeout(endpoint.url));
        }
        if let Ok(response) = client.get(&url).send().await {
            let status = response.status().as_u16();
            let ready = app
                .health_status
                .map_or(status < 500, |expected| status == expected);
            if ready {
                return Ok(());
            }
        }
        sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(requires_sudo: bool) -> TargetState {
        serde_json::from_value(json!({
            "host": "8.8.8.8",
            "public_ipv4": "8.8.8.8",
            "docker": {"requires_sudo": requires_sudo}
        }))
        .expect("target")
    }

    fn desired() -> DesiredState {
        DesiredState::parse(json!({
            "schema": 1,
            "project": {
                "id": "project-id",
                "slug": "project",
                "root": "/workspace",
                "compose": ["compose.yaml"]
            },
            "environment": {
                "id": "lr-123",
                "profile": "preview",
                "branch": "feature",
                "isolation": "project"
            },
            "apps": [{
                "name": "web",
                "service": "web",
                "port": 3000
            }]
        }))
        .expect("desired")
    }

    #[test]
    fn buildx_bake_inputs_have_a_compose_recognized_suffix() {
        for prefix in ["lightrail-compose-", "lightrail-build-"] {
            let temporary = temporary_compose_file(prefix).expect("temporary Compose file");
            assert!(
                temporary
                    .path()
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(".compose.yaml"))
            );
        }
    }

    #[test]
    fn parses_compose_log_prefix_and_timestamp() {
        let record = parse_log_line("web-1 | 2026-07-18T12:34:56.000000000Z application started");
        assert_eq!(record.service, "web-1");
        assert_eq!(
            record.timestamp.as_deref(),
            Some("2026-07-18T12:34:56.000000000Z")
        );
        assert_eq!(record.line, "application started");
    }

    #[test]
    fn remote_layout_is_environment_scoped() {
        let target = target(false);
        let layout = RemoteLayout::new(&target, "lr-123").expect("layout");
        assert_eq!(
            layout.base,
            ".lightrail/environments/lr-123/compose.resolved.json"
        );
        assert!(RemoteLayout::new(&target, "../escape").is_err());
    }

    #[test]
    fn secret_environment_paths_are_operation_unique_and_scripts_trap_cleanup() {
        let target = target(true);
        let layout = RemoteLayout::new(&target, "lr-123").expect("layout");
        let first = layout.operation_environment_override("operation-one");
        let second = layout.operation_environment_override("operation-two");
        assert_ne!(first, second);
        assert!(first.ends_with(".tmp.json"));
        assert!(!first.contains("operation-one"));

        let mut arguments = layout.compose_arguments("lr-123");
        arguments.extend(["-f".to_owned(), first.clone(), "up".to_owned()]);
        let script = secret_environment_script(&target, &arguments, &first);
        assert!(script.contains("trap cleanup_lightrail_secret_env EXIT"));
        assert!(script.contains("trap 'exit 129' HUP INT TERM"));
        assert!(script.contains("cat >"));
        assert!(script.contains("chmod 600"));
        assert!(script.contains("sudo -n docker compose"));
    }

    #[test]
    fn absent_manifest_marker_is_not_an_ssh_error() {
        assert!(
            decode_remote_manifest(format!("{ABSENT_MANIFEST_MARKER}\n").as_bytes())
                .expect("absent")
                .is_none()
        );
        assert!(decode_remote_manifest(b"not-json").is_err());
    }

    #[test]
    fn orphan_inspection_uses_all_exact_ownership_labels_for_every_resource_kind() {
        let script = orphan_inspection_script(&target(true), "project-id", "lr-123");

        assert!(script.contains("sudo -n docker ps -aq"));
        assert!(script.contains("sudo -n docker image ls"));
        assert!(script.contains("sudo -n docker network ls -q"));
        assert!(script.contains("sudo -n docker volume ls -q"));
        assert!(script.contains("case \"$image\" in lightrail/*:*"));
        for label in [
            "lightrail-managed=true",
            "lightrail-project-id=project-id",
            "lightrail-environment-id=lr-123",
        ] {
            assert_eq!(
                script.matches(label).count(),
                4,
                "every Docker resource query must include `{label}`"
            );
        }
        assert!(!script.contains("com.docker.compose.project"));
    }

    #[test]
    fn orphan_count_decoder_is_strict() {
        assert_eq!(
            decode_orphan_resource_counts(
                br#"{"containers":2,"images":4,"networks":1,"volumes":3}
"#
            )
            .expect("counts"),
            OrphanResourceCounts {
                containers: 2,
                images: 4,
                networks: 1,
                volumes: 3,
            }
        );
        assert!(
            decode_orphan_resource_counts(br#"{"containers":2,"images":4,"networks":1}"#).is_err()
        );
        assert!(
            decode_orphan_resource_counts(
                br#"{"containers":2,"images":4,"networks":1,"volumes":3,"unknown":5}"#
            )
            .is_err()
        );
    }

    #[test]
    fn missing_manifest_inspection_distinguishes_absence_from_labeled_orphans() {
        let absent = orphan_inspection_result(
            "project-id",
            "lr-123",
            OrphanResourceCounts {
                containers: 0,
                images: 0,
                networks: 0,
                volumes: 0,
            },
        );
        assert_eq!(absent.status, ResourceStatus::Absent);
        assert!(absent.endpoints.is_empty());
        assert!(absent.diagnostics.is_empty());
        assert_eq!(absent.state["status"], "absent");
        assert_eq!(absent.state["project_id"], "project-id");
        assert_eq!(absent.state["environment_id"], "lr-123");

        let orphaned = orphan_inspection_result(
            "project-id",
            "lr-123",
            OrphanResourceCounts {
                containers: 0,
                images: 1,
                networks: 0,
                volumes: 0,
            },
        );
        assert_eq!(orphaned.status, ResourceStatus::Degraded);
        assert!(orphaned.endpoints.is_empty());
        assert_eq!(orphaned.diagnostics.len(), 1);
        assert_eq!(orphaned.diagnostics[0].code, "remote_manifest_missing");
        assert_eq!(orphaned.state["status"], "degraded");
        assert_eq!(orphaned.state["orphan_resources"]["containers"], 0);
        assert_eq!(orphaned.state["orphan_resources"]["images"], 1);
        assert_eq!(orphaned.state["orphan_resources"]["networks"], 0);
        assert_eq!(orphaned.state["orphan_resources"]["volumes"], 0);
    }

    #[test]
    fn project_discovery_requires_exact_managed_and_project_labels() {
        let managed = "label=lightrail-managed=true";
        let project = "label=lightrail-project-id=project-id";
        let format = r#"{{.Label "lightrail-environment-id"}}"#;
        let resource_commands = labeled_resource_discovery_commands(managed, project, format);
        assert_eq!(resource_commands.len(), 3);
        for command in resource_commands {
            assert!(command.windows(2).any(|pair| pair == ["--filter", managed]));
            assert!(command.windows(2).any(|pair| pair == ["--filter", project]));
            assert!(command.windows(2).any(|pair| pair == ["--format", format]));
        }

        let image_script = labeled_image_inspection_script(&target(true), "project-id");
        assert!(image_script.contains("sudo -n docker image ls --quiet --no-trunc"));
        assert!(image_script.contains("--filter label=lightrail-managed=true"));
        assert!(image_script.contains("--filter label=lightrail-project-id=project-id"));
        assert!(image_script.contains("sudo -n docker image inspect"));
        assert!(image_script.contains("--format '{{json .}}'"));
        assert!(
            !image_script.contains("{{.Label"),
            "docker image ls has no portable Label format placeholder"
        );
    }

    #[test]
    fn image_only_orphan_is_discovered_and_has_an_exact_cleanup_path() {
        let target = target(true);
        let owned = json!({
            "Id": "sha256:owned",
            "RepoTags": [
                "lightrail/lr-image-web:revision",
                "lightrail/lr-image-web:duplicate"
            ],
            "Config": {
                "Labels": {
                    "lightrail-managed": "true",
                    "lightrail-project-id": "project-id",
                    "lightrail-environment-id": "lr-image"
                }
            }
        });
        let unrelated = json!({
            "Id": "sha256:unrelated",
            "RepoTags": ["registry.example/unrelated/image:revision"],
            "Config": {
                "Labels": {
                    "lightrail-managed": "true",
                    "lightrail-project-id": "project-id",
                    "lightrail-environment-id": "lr-unrelated"
                }
            }
        });
        let inspection = format!("{owned}\n{owned}\n{unrelated}\n");
        let environments =
            decode_owned_image_environment_ids(&target, "project-id", inspection.as_bytes())
                .expect("image discovery output");
        assert_eq!(
            environments,
            BTreeSet::from(["lr-image".to_owned()]),
            "only the owned Lightrail image namespace may create a cleanup candidate"
        );

        let layout = RemoteLayout::new(&target, "lr-image").expect("layout");
        let script =
            destroy_owned_environment_script(&target, &layout, "lr-image", "project-id", false);
        for label in [
            "lightrail-managed=true",
            "lightrail-project-id=project-id",
            "lightrail-environment-id=lr-image",
        ] {
            assert!(script.contains(label));
        }
        assert!(script.contains("case \"$image\" in lightrail/*:*"));
        assert!(script.contains("sudo -n docker image rm -- \"$image\""));
        assert!(
            !script.contains("rm -rf -- .lightrail/environments/lr-image"),
            "an image-only orphan without a matching manifest must not authorize directory removal"
        );
    }

    #[test]
    fn malformed_image_discovery_output_fails_closed() {
        assert!(
            decode_owned_image_environment_ids(&target(false), "project-id", b"")
                .expect("zero images")
                .is_empty()
        );
        assert!(
            decode_owned_image_environment_ids(
                &target(false),
                "project-id",
                b"lightrail/web:tag lr-one\n"
            )
            .is_err()
        );
        assert!(
            decode_owned_image_environment_ids(&target(false), "project-id", b"\xff\n").is_err()
        );

        let wrong_labels = json!({
            "Id": "sha256:wrong",
            "RepoTags": ["lightrail/lr-one-web:revision"],
            "Config": {
                "Labels": {
                    "lightrail-managed": "true",
                    "lightrail-project-id": "another-project",
                    "lightrail-environment-id": "lr-one"
                }
            }
        });
        assert!(
            decode_owned_image_environment_ids(
                &target(false),
                "project-id",
                wrong_labels.to_string().as_bytes()
            )
            .is_err()
        );

        let owned = json!({
            "Id": "sha256:duplicate",
            "RepoTags": ["lightrail/lr-one-web:revision"],
            "Config": {
                "Labels": {
                    "lightrail-managed": "true",
                    "lightrail-project-id": "project-id",
                    "lightrail-environment-id": "lr-one"
                }
            }
        });
        let not_owned = json!({
            "Id": "sha256:duplicate",
            "RepoTags": ["registry.example/unrelated:revision"],
            "Config": {
                "Labels": {
                    "lightrail-managed": "true",
                    "lightrail-project-id": "project-id",
                    "lightrail-environment-id": "lr-one"
                }
            }
        });
        let inconsistent = format!("{owned}\n{not_owned}\n");
        assert!(
            decode_owned_image_environment_ids(
                &target(false),
                "project-id",
                inconsistent.as_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn absent_containers_never_publish_endpoints() {
        let desired = desired();
        let target = target(false);
        assert!(
            inspected_endpoints(&desired, &target, &PluginConfig::default(), 0)
                .expect("endpoints")
                .is_empty()
        );
        assert_eq!(
            inspected_endpoints(&desired, &target, &PluginConfig::default(), 1)
                .expect("endpoints")
                .len(),
            1
        );
    }

    #[test]
    fn owned_cleanup_is_exact_and_preserves_shared_ingress() {
        let target = target(true);
        let layout = RemoteLayout::new(&target, "lr-123").expect("layout");
        let script =
            destroy_owned_environment_script(&target, &layout, "lr-123", "project-id", true);
        for label in [
            "lightrail-managed=true",
            "lightrail-project-id=project-id",
            "lightrail-environment-id=lr-123",
        ] {
            assert!(script.contains(label));
        }
        assert!(script.contains("case \"$image\" in lightrail/*:*"));
        assert!(script.contains("rm -rf -- .lightrail/environments/lr-123"));
        assert!(!script.contains("rm -rf -- .lightrail/shared"));
        assert!(!script.contains("compose -p lightrail-ingress"));

        let unproven =
            destroy_owned_environment_script(&target, &layout, "lr-123", "project-id", false);
        assert!(!unproven.contains("rm -rf -- .lightrail/environments/lr-123"));
    }

    #[test]
    fn shared_ingress_fingerprint_covers_compatibility_model() {
        let first = ingress_compatibility(&PluginConfig::default());
        let different = PluginConfig {
            dns_domain: "nip.io".to_owned(),
            ..PluginConfig::default()
        };
        let second = ingress_compatibility(&different);
        assert_eq!(first, ingress_compatibility(&PluginConfig::default()));
        assert_ne!(first["fingerprint"], second["fingerprint"]);
        assert_eq!(
            first["model"]["network_model"],
            "shared-traefik-per-environment-network-v1"
        );
    }

    #[test]
    fn rollback_without_marker_accepts_the_live_prior_revision_only() {
        assert!(rollback_is_already_complete(
            None,
            Some("prior"),
            Some("prior")
        ));
        assert!(!rollback_is_already_complete(
            Some("another-operation"),
            Some("prior"),
            Some("prior")
        ));
        assert!(!rollback_is_already_complete(
            None,
            Some("attempted"),
            Some("prior")
        ));
        assert!(!rollback_is_already_complete(None, Some("prior"), None));
    }
}
