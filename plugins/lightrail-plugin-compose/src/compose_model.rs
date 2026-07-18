use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    path::PathBuf,
};

use lightrail_core::{DnsLabel, Hostname, IpDnsDomain};
use lightrail_plugin_protocol::Endpoint;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::{
    contract::{DesiredState, PluginConfig, TargetState},
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
    if let Some(volumes) = document.get("volumes").and_then(Value::as_object) {
        for (name, definition) in volumes {
            if definition
                .get("external")
                .is_some_and(|external| external == true)
            {
                return Err(ComposePluginError::ExternalVolume {
                    volume: name.clone(),
                });
            }
        }
    }
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
        if service.get("network_mode").and_then(Value::as_str) == Some("host") {
            return Err(ComposePluginError::HostNetwork {
                service: name.clone(),
            });
        }
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

pub fn deployment_revision(desired: &DesiredState, document: &Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"lightrail/compose/revision/v1\0");
    let mut stable_desired = desired.clone();
    stable_desired.resolved_compose_path = None;
    hasher.update(serde_json::to_vec(&stable_desired).unwrap_or_default());
    hasher.update(serde_json::to_vec(document).unwrap_or_default());
    format!("{:x}", hasher.finalize())
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
    use std::{net::Ipv4Addr, str::FromStr};

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
    fn ephemeral_resolved_path_does_not_change_revision() {
        let document = json!({"services": {"web": {"image": "nginx"}}});
        let mut first = desired();
        first.resolved_compose_path = Some(PathBuf::from("/tmp/first.json"));
        let mut second = first.clone();
        second.resolved_compose_path = Some(PathBuf::from("/tmp/second.json"));

        assert_eq!(
            deployment_revision(&first, &document),
            deployment_revision(&second, &document)
        );
    }
}
