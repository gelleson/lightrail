use std::{collections::BTreeMap, time::Duration};

use lightrail_plugin_protocol::{ErrorKind, PluginError, PluginResult};
use reqwest::{Method, RequestBuilder, StatusCode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;

use crate::model::{CONFIG_LABEL, Settings};

const DEFAULT_API_URL: &str = "https://api.hetzner.cloud/v1";

#[derive(Clone)]
pub struct ApiClient {
    http: reqwest::Client,
    base_url: String,
}

impl Default for ApiClient {
    fn default() -> Self {
        Self {
            http: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(15))
                .timeout(Duration::from_secs(60))
                .user_agent(concat!(
                    "lightrail-plugin-hetzner/",
                    env!("CARGO_PKG_VERSION")
                ))
                .build()
                .expect("static Hetzner HTTP client configuration"),
            base_url: DEFAULT_API_URL.to_owned(),
        }
    }
}

impl ApiClient {
    #[cfg(test)]
    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            ..Self::default()
        }
    }

    fn request(&self, method: Method, path: &str, token: &str) -> RequestBuilder {
        self.http
            .request(
                method,
                format!("{}/{}", self.base_url.trim_end_matches('/'), path),
            )
            .bearer_auth(token)
    }

    pub async fn servers(&self, token: &str, selector: &str) -> PluginResult<Vec<Server>> {
        let mut page = 1_u64;
        let mut output = Vec::new();
        loop {
            let response: ServerList = self
                .decode(self.request(Method::GET, "servers", token).query(&[
                    ("label_selector", selector),
                    ("per_page", "50"),
                    ("page", &page.to_string()),
                ]))
                .await?;
            output.extend(response.servers);
            match response.meta.and_then(|meta| meta.pagination.next_page) {
                Some(next) => page = next,
                None => return Ok(output),
            }
        }
    }

    pub async fn firewalls(&self, token: &str, selector: &str) -> PluginResult<Vec<Firewall>> {
        let mut page = 1_u64;
        let mut output = Vec::new();
        loop {
            let response: FirewallList = self
                .decode(self.request(Method::GET, "firewalls", token).query(&[
                    ("label_selector", selector),
                    ("per_page", "50"),
                    ("page", &page.to_string()),
                ]))
                .await?;
            output.extend(response.firewalls);
            match response.meta.and_then(|meta| meta.pagination.next_page) {
                Some(next) => page = next,
                None => return Ok(output),
            }
        }
    }

    pub async fn server(&self, token: &str, id: u64) -> PluginResult<Option<Server>> {
        let response = self
            .request(Method::GET, &format!("servers/{id}"), token)
            .send()
            .await
            .map_err(|error| network_error(&error))?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let response: ServerResponse = decode_response(response).await?;
        Ok(Some(response.server))
    }

    pub async fn action(&self, token: &str, id: u64) -> PluginResult<ApiAction> {
        let response: ActionResponse = self
            .decode(self.request(Method::GET, &format!("actions/{id}"), token))
            .await?;
        Ok(response.action)
    }

    pub async fn create_firewall(
        &self,
        token: &str,
        payload: &CreateFirewall,
    ) -> PluginResult<FirewallMutation> {
        self.decode(self.request(Method::POST, "firewalls", token).json(payload))
            .await
    }

    pub async fn set_firewall_rules(
        &self,
        token: &str,
        firewall_id: u64,
        rules: &[FirewallRule],
    ) -> PluginResult<Vec<ApiAction>> {
        let response: FirewallActionResponse = self
            .decode(
                self.request(
                    Method::POST,
                    &format!("firewalls/{firewall_id}/actions/set_rules"),
                    token,
                )
                .json(&json!({ "rules": rules })),
            )
            .await?;
        Ok(response.actions)
    }

    pub async fn apply_firewall(
        &self,
        token: &str,
        firewall_id: u64,
        server_id: u64,
    ) -> PluginResult<Vec<ApiAction>> {
        let response: FirewallActionResponse = self
            .decode(
                self.request(
                    Method::POST,
                    &format!("firewalls/{firewall_id}/actions/apply_to_resources"),
                    token,
                )
                .json(&json!({
                    "apply_to": [{
                        "type": "server",
                        "server": { "id": server_id }
                    }]
                })),
            )
            .await?;
        Ok(response.actions)
    }

    pub async fn create_server(
        &self,
        token: &str,
        payload: &CreateServer,
    ) -> PluginResult<ServerMutation> {
        self.decode(self.request(Method::POST, "servers", token).json(payload))
            .await
    }

    pub async fn delete_server(&self, token: &str, id: u64) -> PluginResult<Option<ApiAction>> {
        let response = self
            .request(Method::DELETE, &format!("servers/{id}"), token)
            .send()
            .await
            .map_err(|error| network_error(&error))?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let response: ActionResponse = decode_response(response).await?;
        Ok(Some(response.action))
    }

    pub async fn delete_firewall(&self, token: &str, id: u64) -> PluginResult<()> {
        let response = self
            .request(Method::DELETE, &format!("firewalls/{id}"), token)
            .send()
            .await
            .map_err(|error| network_error(&error))?;
        if response.status() == StatusCode::NOT_FOUND || response.status().is_success() {
            return Ok(());
        }
        Err(response_error(response).await)
    }

    async fn decode<T>(&self, request: RequestBuilder) -> PluginResult<T>
    where
        T: DeserializeOwned,
    {
        let response = request
            .send()
            .await
            .map_err(|error| network_error(&error))?;
        decode_response(response).await
    }
}

async fn decode_response<T>(response: reqwest::Response) -> PluginResult<T>
where
    T: DeserializeOwned,
{
    if !response.status().is_success() {
        return Err(response_error(response).await);
    }
    response.json().await.map_err(|error| {
        PluginError::retryable(
            ErrorKind::Unavailable,
            "invalid_provider_response",
            format!("Hetzner Cloud returned an invalid response: {error}"),
        )
    })
}

fn network_error(error: &reqwest::Error) -> PluginError {
    if error.is_timeout() {
        PluginError::retryable(
            ErrorKind::Timeout,
            "hetzner_request_timeout",
            "the Hetzner Cloud API request timed out",
        )
    } else {
        PluginError::retryable(
            ErrorKind::Unavailable,
            "hetzner_unavailable",
            format!("could not reach the Hetzner Cloud API: {error}"),
        )
    }
}

async fn response_error(response: reqwest::Response) -> PluginError {
    let status = response.status();
    let retry_after_ms = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(|seconds| seconds.saturating_mul(1_000));
    let body = response.json::<ApiErrorEnvelope>().await.ok();
    let provider_code = body
        .as_ref()
        .map_or("unknown", |body| body.error.code.as_str());
    let provider_message = body
        .as_ref()
        .map_or("the provider did not return an error message", |body| {
            body.error.message.as_str()
        });
    let (kind, retryable) = match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => (ErrorKind::Authentication, false),
        StatusCode::NOT_FOUND => (ErrorKind::NotFound, false),
        StatusCode::CONFLICT => (ErrorKind::Conflict, false),
        StatusCode::TOO_MANY_REQUESTS => (ErrorKind::RateLimited, true),
        status if status.is_server_error() => (ErrorKind::Unavailable, true),
        _ => (ErrorKind::Validation, false),
    };
    let message = format!(
        "Hetzner Cloud API rejected the request ({status}, {provider_code}): {provider_message}"
    );
    let mut error = if retryable {
        PluginError::retryable(kind, "hetzner_api_error", message)
    } else {
        PluginError::permanent(kind, "hetzner_api_error", message)
    }
    .with_details(json!({
        "http_status": status.as_u16(),
        "provider_code": provider_code
    }));
    if let Some(delay) = retry_after_ms {
        error = error.with_retry_after(delay);
    }
    error
}

#[derive(Clone, Debug, Deserialize)]
pub struct ApiErrorEnvelope {
    pub error: ApiError,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize)]
struct PaginationEnvelope {
    pagination: Pagination,
}

#[derive(Clone, Debug, Deserialize)]
struct Pagination {
    next_page: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
struct ServerList {
    servers: Vec<Server>,
    meta: Option<PaginationEnvelope>,
}

#[derive(Clone, Debug, Deserialize)]
struct FirewallList {
    firewalls: Vec<Firewall>,
    meta: Option<PaginationEnvelope>,
}

#[derive(Clone, Debug, Deserialize)]
struct ServerResponse {
    server: Server,
}

#[derive(Clone, Debug, Deserialize)]
struct ActionResponse {
    action: ApiAction,
}

#[derive(Clone, Debug, Deserialize)]
struct FirewallActionResponse {
    #[serde(default)]
    actions: Vec<ApiAction>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServerMutation {
    pub server: Server,
    pub action: ApiAction,
}

#[derive(Clone, Debug, Deserialize)]
pub struct FirewallMutation {
    pub firewall: Firewall,
    #[serde(default)]
    pub actions: Vec<ApiAction>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ApiAction {
    pub id: u64,
    pub status: String,
    pub error: Option<ActionError>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ActionError {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Server {
    pub id: u64,
    pub name: String,
    pub status: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    pub public_net: PublicNet,
    #[serde(rename = "server_type")]
    pub flavor: ServerType,
    pub image: Option<Image>,
    pub datacenter: Option<Datacenter>,
}

impl Server {
    pub fn public_ipv4(&self) -> Option<&str> {
        self.public_net
            .ipv4
            .as_ref()
            .map(|address| address.ip.as_str())
            .filter(|address| !address.is_empty())
    }

    pub fn architecture(&self) -> &'static str {
        match self.flavor.architecture.as_str() {
            "arm" | "arm64" | "aarch64" => "arm64",
            _ => "amd64",
        }
    }

    pub fn config_fingerprint(&self) -> Option<&str> {
        self.labels.get(CONFIG_LABEL).map(String::as_str)
    }

    pub fn location(&self) -> Option<&str> {
        self.datacenter
            .as_ref()
            .and_then(|datacenter| datacenter.location.as_ref())
            .map(|location| location.name.as_str())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicNet {
    pub ipv4: Option<PublicIpv4>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicIpv4 {
    pub ip: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ServerType {
    pub name: String,
    pub architecture: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Image {
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Datacenter {
    pub location: Option<Location>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Location {
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Firewall {
    pub id: u64,
    pub name: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub rules: Vec<FirewallRule>,
    #[serde(default)]
    pub applied_to: Vec<AppliedTo>,
}

impl Firewall {
    pub fn applies_to_server(&self, server_id: u64) -> bool {
        self.applied_to.iter().any(|resource| {
            resource.kind == "server"
                && resource
                    .server
                    .as_ref()
                    .is_some_and(|server| server.id == server_id)
        })
    }

    pub fn matches_rules(&self, expected: &[FirewallRule]) -> bool {
        canonical_rules(&self.rules) == canonical_rules(expected)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AppliedTo {
    #[serde(rename = "type")]
    pub kind: String,
    pub server: Option<AppliedServer>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AppliedServer {
    pub id: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FirewallRule {
    pub direction: String,
    pub protocol: String,
    pub port: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destination_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

pub fn firewall_rules(settings: &Settings) -> Vec<FirewallRule> {
    let global = vec!["0.0.0.0/0".to_owned(), "::/0".to_owned()];
    vec![
        FirewallRule {
            direction: "in".to_owned(),
            protocol: "tcp".to_owned(),
            port: Some("80".to_owned()),
            source_ips: global.clone(),
            destination_ips: Vec::new(),
            description: Some("Lightrail HTTP-01 and HTTPS redirect".to_owned()),
        },
        FirewallRule {
            direction: "in".to_owned(),
            protocol: "tcp".to_owned(),
            port: Some("443".to_owned()),
            source_ips: global,
            destination_ips: Vec::new(),
            description: Some("Lightrail HTTPS".to_owned()),
        },
        FirewallRule {
            direction: "in".to_owned(),
            protocol: "tcp".to_owned(),
            port: Some("22".to_owned()),
            source_ips: settings.allowed_ssh_cidrs.clone(),
            destination_ips: Vec::new(),
            description: Some("Lightrail operator SSH".to_owned()),
        },
    ]
}

pub fn canonical_rules(rules: &[FirewallRule]) -> Vec<FirewallRule> {
    let mut rules = rules.to_vec();
    for rule in &mut rules {
        rule.source_ips.sort();
        rule.source_ips.dedup();
        rule.destination_ips.sort();
        rule.destination_ips.dedup();
        // Descriptions are human-facing and do not affect network policy.
        rule.description = None;
    }
    rules.sort_by_cached_key(|rule| {
        serde_json::to_string(rule).expect("firewall rule has a static serializable shape")
    });
    rules
}

#[derive(Clone, Debug, Serialize)]
pub struct CreateFirewall {
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub rules: Vec<FirewallRule>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CreateServer {
    pub name: String,
    pub server_type: String,
    pub image: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    pub ssh_keys: Vec<String>,
    pub labels: BTreeMap<String, String>,
    pub firewalls: Vec<u64>,
    pub user_data: String,
    pub start_after_create: bool,
    pub public_net: CreatePublicNet,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct CreatePublicNet {
    pub enable_ipv4: bool,
    pub enable_ipv6: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Settings;

    #[test]
    fn firewall_payload_only_opens_web_globally() {
        let settings = Settings {
            allowed_ssh_cidrs: vec!["198.51.100.8/32".to_owned()],
            ..Settings::default()
        };
        let rules = firewall_rules(&settings);
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].source_ips, ["0.0.0.0/0", "::/0"]);
        assert_eq!(rules[1].source_ips, ["0.0.0.0/0", "::/0"]);
        assert_eq!(rules[2].source_ips, ["198.51.100.8/32"]);
        assert_eq!(rules[2].port.as_deref(), Some("22"));
        let managed = Firewall {
            id: 1,
            name: "test".to_owned(),
            labels: BTreeMap::new(),
            rules: rules.clone(),
            applied_to: Vec::new(),
        };
        assert!(managed.matches_rules(&rules));
        let mut drifted = rules;
        drifted.pop();
        assert!(!managed.matches_rules(&drifted));
    }

    #[test]
    fn state_response_decodes_provider_architecture_and_address() {
        let server: Server = serde_json::from_value(json!({
            "id": 42,
            "name": "lr-example",
            "status": "running",
            "labels": { "lightrail-config": "abc" },
            "public_net": { "ipv4": { "ip": "203.0.113.7" } },
            "server_type": { "name": "cax11", "architecture": "arm" },
            "image": { "name": "ubuntu-24.04" },
            "datacenter": { "location": { "name": "fsn1" } }
        }))
        .unwrap();
        assert_eq!(server.public_ipv4(), Some("203.0.113.7"));
        assert_eq!(server.architecture(), "arm64");
        assert_eq!(server.location(), Some("fsn1"));
    }

    #[test]
    fn test_client_base_url_is_injectable_without_credentials() {
        let client = ApiClient::with_base_url("http://127.0.0.1:1/v1");
        assert_eq!(client.base_url, "http://127.0.0.1:1/v1");
    }
}
