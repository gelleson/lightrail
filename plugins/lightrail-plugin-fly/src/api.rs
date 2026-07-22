//! Narrow Fly Apps, Machines, Volumes, leases, and GraphQL API client.
//!
//! Tokens are accepted only as method parameters and are attached as bearer
//! headers. Provider response bodies are never copied wholesale into errors,
//! because they may contain Machine environment values.

use std::{collections::BTreeMap, time::Duration};

use async_trait::async_trait;
use lightrail_plugin_protocol::{ErrorKind, PluginError, PluginResult};
use reqwest::{Method, RequestBuilder, StatusCode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

const MACHINES_API_URL: &str = "https://api.machines.dev";
const GRAPHQL_API_URL: &str = "https://api.fly.io/graphql";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct App {
    #[serde(default)]
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub organization: Value,
    #[serde(default)]
    pub network: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Machine {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub instance_id: String,
    #[serde(default)]
    pub config: MachineConfig,
}

impl Machine {
    pub fn metadata(&self) -> &BTreeMap<String, String> {
        &self.config.metadata
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct MachineConfig {
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    #[serde(default)]
    pub mounts: Vec<MachineMount>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct MachineMount {
    #[serde(default)]
    pub volume: String,
    #[serde(default)]
    pub path: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Volume {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub attached_machine_id: Option<String>,
    #[serde(default)]
    pub size_gb: u32,
}

#[derive(Clone, Debug)]
pub struct Lease {
    pub nonce: String,
    pub expires_at_unix: Option<u64>,
    pub owner: Option<String>,
}

#[derive(Clone, Debug)]
pub struct PublicResponse {
    pub status: u16,
    pub location: Option<String>,
}

#[async_trait]
pub trait FlyApi: Send + Sync {
    async fn get_app(&self, token: &str, name: &str) -> PluginResult<Option<App>>;
    async fn list_apps(&self, token: &str, organization: &str) -> PluginResult<Vec<App>>;
    async fn create_app(
        &self,
        token: &str,
        organization: &str,
        name: &str,
        network: &str,
    ) -> PluginResult<App>;
    async fn delete_app(&self, token: &str, name: &str, force: bool) -> PluginResult<()>;
    async fn list_machines(&self, token: &str, app: &str) -> PluginResult<Vec<Machine>>;
    async fn create_machine(&self, token: &str, app: &str, payload: Value)
    -> PluginResult<Machine>;
    async fn update_machine(
        &self,
        token: &str,
        app: &str,
        machine: &str,
        payload: Value,
    ) -> PluginResult<Machine>;
    async fn set_machine_metadata(
        &self,
        token: &str,
        app: &str,
        machine: &str,
        key: &str,
        value: &str,
    ) -> PluginResult<()>;
    async fn delete_machine_metadata(
        &self,
        token: &str,
        app: &str,
        machine: &str,
        key: &str,
    ) -> PluginResult<()>;
    async fn delete_machine(&self, token: &str, app: &str, machine: &str) -> PluginResult<()>;
    async fn wait_machine(
        &self,
        token: &str,
        app: &str,
        machine: &str,
        state: &str,
        instance_id: Option<&str>,
        timeout_seconds: u64,
    ) -> PluginResult<()>;
    async fn list_volumes(&self, token: &str, app: &str) -> PluginResult<Vec<Volume>>;
    async fn create_volume(&self, token: &str, app: &str, payload: Value) -> PluginResult<Volume>;
    async fn delete_volume(&self, token: &str, app: &str, volume: &str) -> PluginResult<()>;
    async fn shared_ipv4(&self, token: &str, app: &str) -> PluginResult<Option<String>>;
    async fn allocate_shared_ipv4(
        &self,
        token: &str,
        app: &str,
        region: Option<&str>,
    ) -> PluginResult<String>;
    async fn release_shared_ipv4(&self, token: &str, app: &str, address: &str) -> PluginResult<()>;
    async fn acquire_lease(
        &self,
        token: &str,
        app: &str,
        machine: &str,
        description: &str,
        ttl_seconds: u64,
    ) -> PluginResult<Lease>;
    async fn get_lease(&self, token: &str, app: &str, machine: &str)
    -> PluginResult<Option<Lease>>;
    async fn refresh_lease(
        &self,
        token: &str,
        app: &str,
        machine: &str,
        nonce: &str,
        ttl_seconds: u64,
    ) -> PluginResult<Lease>;
    async fn release_lease(
        &self,
        token: &str,
        app: &str,
        machine: &str,
        nonce: &str,
    ) -> PluginResult<()>;
    async fn public_probe(&self, url: &str) -> PluginResult<Option<PublicResponse>>;
}

#[derive(Clone)]
pub struct ApiClient {
    http: reqwest::Client,
    machines_url: String,
    graphql_url: String,
}

impl Default for ApiClient {
    fn default() -> Self {
        Self {
            http: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(15))
                .timeout(Duration::from_secs(60))
                .user_agent(concat!("lightrail-plugin-fly/", env!("CARGO_PKG_VERSION")))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("static Fly.io HTTP client configuration"),
            machines_url: MACHINES_API_URL.to_owned(),
            graphql_url: GRAPHQL_API_URL.to_owned(),
        }
    }
}

impl ApiClient {
    #[cfg(test)]
    pub fn with_base_urls(machines_url: impl Into<String>, graphql_url: impl Into<String>) -> Self {
        Self {
            machines_url: machines_url.into(),
            graphql_url: graphql_url.into(),
            ..Self::default()
        }
    }

    fn machines_request(&self, method: Method, path: &str, token: &str) -> RequestBuilder {
        self.http
            .request(
                method,
                format!(
                    "{}/{}",
                    self.machines_url.trim_end_matches('/'),
                    path.trim_start_matches('/')
                ),
            )
            .bearer_auth(token)
    }

    fn refresh_lease_request(
        &self,
        token: &str,
        app: &str,
        machine: &str,
        nonce: &str,
        ttl_seconds: u64,
    ) -> RequestBuilder {
        self.machines_request(
            Method::POST,
            &format!("v1/apps/{app}/machines/{machine}/lease"),
            token,
        )
        .query(&[("ttl", ttl_seconds)])
        .header("fly-machine-lease-nonce", nonce)
    }

    fn set_machine_metadata_request(
        &self,
        token: &str,
        app: &str,
        machine: &str,
        key: &str,
        value: &str,
    ) -> RequestBuilder {
        self.machines_request(
            Method::POST,
            &format!("v1/apps/{app}/machines/{machine}/metadata/{key}"),
            token,
        )
        .json(&json!({"value": value}))
    }

    fn delete_machine_metadata_request(
        &self,
        token: &str,
        app: &str,
        machine: &str,
        key: &str,
    ) -> RequestBuilder {
        self.machines_request(
            Method::DELETE,
            &format!("v1/apps/{app}/machines/{machine}/metadata/{key}"),
            token,
        )
    }

    async fn decode<T>(&self, request: RequestBuilder) -> PluginResult<T>
    where
        T: DeserializeOwned,
    {
        let response = request.send().await.map_err(network_error)?;
        decode_response(response).await
    }

    async fn empty(&self, request: RequestBuilder) -> PluginResult<()> {
        let response = request.send().await.map_err(network_error)?;
        if response.status().is_success() || response.status() == StatusCode::NOT_FOUND {
            return Ok(());
        }
        Err(response_error(response).await)
    }

    async fn empty_strict(&self, request: RequestBuilder) -> PluginResult<()> {
        let response = request.send().await.map_err(network_error)?;
        if response.status().is_success() {
            return Ok(());
        }
        Err(response_error(response).await)
    }

    async fn graphql<T>(&self, token: &str, query: &str, variables: Value) -> PluginResult<T>
    where
        T: DeserializeOwned,
    {
        let response = self
            .http
            .post(&self.graphql_url)
            .bearer_auth(token)
            .json(&json!({"query": query, "variables": variables}))
            .send()
            .await
            .map_err(network_error)?;
        if !response.status().is_success() {
            return Err(response_error(response).await);
        }
        let envelope: GraphQlEnvelope<T> = response.json().await.map_err(|_| {
            PluginError::retryable(
                ErrorKind::Unavailable,
                "invalid_fly_response",
                "Fly.io returned an invalid GraphQL response",
            )
        })?;
        if !envelope.errors.is_empty() {
            return Err(PluginError::permanent(
                ErrorKind::Conflict,
                "fly_graphql_error",
                "Fly.io rejected the requested IP address operation",
            )
            .with_details(json!({
                "codes": envelope
                    .errors
                    .iter()
                    .filter_map(|error| error.extensions.as_ref())
                    .filter_map(|extensions| extensions.get("code"))
                    .cloned()
                    .collect::<Vec<_>>()
            })));
        }
        envelope.data.ok_or_else(|| {
            PluginError::retryable(
                ErrorKind::Unavailable,
                "missing_fly_graphql_data",
                "Fly.io returned no GraphQL data",
            )
        })
    }
}

#[async_trait]
impl FlyApi for ApiClient {
    async fn get_app(&self, token: &str, name: &str) -> PluginResult<Option<App>> {
        let response = self
            .machines_request(Method::GET, &format!("v1/apps/{name}"), token)
            .send()
            .await
            .map_err(network_error)?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        decode_response(response).await.map(Some)
    }

    async fn list_apps(&self, token: &str, organization: &str) -> PluginResult<Vec<App>> {
        let response: AppList = self
            .decode(
                self.machines_request(Method::GET, "v1/apps", token)
                    .query(&[("org_slug", organization)]),
            )
            .await?;
        Ok(response.apps)
    }

    async fn create_app(
        &self,
        token: &str,
        organization: &str,
        name: &str,
        network: &str,
    ) -> PluginResult<App> {
        let created: CreateAppResponse = self
            .decode(
                self.machines_request(Method::POST, "v1/apps", token)
                    .json(&json!({
                        "app_name": name,
                        "org_slug": organization,
                        "network": network,
                    })),
            )
            .await?;
        if created.id.is_empty() {
            return Err(PluginError::retryable(
                ErrorKind::Unavailable,
                "created_fly_app_id_missing",
                "Fly.io returned an App creation response without an ID",
            ));
        }
        Ok(App {
            id: created.id,
            name: name.to_owned(),
            status: "pending".to_owned(),
            organization: Value::Null,
            network: Some(network.to_owned()),
        })
    }

    async fn delete_app(&self, token: &str, name: &str, force: bool) -> PluginResult<()> {
        let request = self.machines_request(Method::DELETE, &format!("v1/apps/{name}"), token);
        let request = if force {
            request.query(&[("force", "true")])
        } else {
            request
        };
        self.empty(request).await
    }

    async fn list_machines(&self, token: &str, app: &str) -> PluginResult<Vec<Machine>> {
        self.decode(self.machines_request(Method::GET, &format!("v1/apps/{app}/machines"), token))
            .await
    }

    async fn create_machine(
        &self,
        token: &str,
        app: &str,
        payload: Value,
    ) -> PluginResult<Machine> {
        self.decode(
            self.machines_request(Method::POST, &format!("v1/apps/{app}/machines"), token)
                .json(&payload),
        )
        .await
    }

    async fn update_machine(
        &self,
        token: &str,
        app: &str,
        machine: &str,
        payload: Value,
    ) -> PluginResult<Machine> {
        self.decode(
            self.machines_request(
                Method::POST,
                &format!("v1/apps/{app}/machines/{machine}"),
                token,
            )
            .json(&payload),
        )
        .await
    }

    async fn set_machine_metadata(
        &self,
        token: &str,
        app: &str,
        machine: &str,
        key: &str,
        value: &str,
    ) -> PluginResult<()> {
        self.empty_strict(self.set_machine_metadata_request(token, app, machine, key, value))
            .await
    }

    async fn delete_machine_metadata(
        &self,
        token: &str,
        app: &str,
        machine: &str,
        key: &str,
    ) -> PluginResult<()> {
        self.empty_strict(self.delete_machine_metadata_request(token, app, machine, key))
            .await
    }

    async fn delete_machine(&self, token: &str, app: &str, machine: &str) -> PluginResult<()> {
        self.empty(
            self.machines_request(
                Method::DELETE,
                &format!("v1/apps/{app}/machines/{machine}"),
                token,
            )
            .query(&[("force", "true")]),
        )
        .await
    }

    async fn wait_machine(
        &self,
        token: &str,
        app: &str,
        machine: &str,
        state: &str,
        instance_id: Option<&str>,
        timeout_seconds: u64,
    ) -> PluginResult<()> {
        let query = machine_wait_query(state, instance_id, timeout_seconds);
        let response = self
            .machines_request(
                Method::GET,
                &format!("v1/apps/{app}/machines/{machine}/wait"),
                token,
            )
            .query(&query)
            .send()
            .await
            .map_err(network_error)?;
        let response: WaitResponse = decode_response(response).await?;
        if response.ok {
            Ok(())
        } else {
            Err(PluginError::retryable(
                ErrorKind::Unavailable,
                "fly_machine_wait_incomplete",
                "Fly.io returned an incomplete Machine wait result",
            ))
        }
    }

    async fn list_volumes(&self, token: &str, app: &str) -> PluginResult<Vec<Volume>> {
        self.decode(self.machines_request(Method::GET, &format!("v1/apps/{app}/volumes"), token))
            .await
    }

    async fn create_volume(&self, token: &str, app: &str, payload: Value) -> PluginResult<Volume> {
        self.decode(
            self.machines_request(Method::POST, &format!("v1/apps/{app}/volumes"), token)
                .json(&payload),
        )
        .await
    }

    async fn delete_volume(&self, token: &str, app: &str, volume: &str) -> PluginResult<()> {
        self.empty(self.machines_request(
            Method::DELETE,
            &format!("v1/apps/{app}/volumes/{volume}"),
            token,
        ))
        .await
    }

    async fn shared_ipv4(&self, token: &str, app: &str) -> PluginResult<Option<String>> {
        let data: SharedIpData = self
            .graphql(
                token,
                "query($appName:String!){app(name:$appName){sharedIpAddress}}",
                json!({"appName": app}),
            )
            .await?;
        Ok(data.app.and_then(|app| app.shared_ip_address))
    }

    async fn allocate_shared_ipv4(
        &self,
        token: &str,
        app: &str,
        region: Option<&str>,
    ) -> PluginResult<String> {
        let data: AllocateIpData = self
            .graphql(
                token,
                "mutation($input:AllocateIPAddressInput!){allocateIpAddress(input:$input){app{sharedIpAddress}}}",
                allocate_ip_variables(app, region),
            )
            .await?;
        data.allocate_ip_address
            .app
            .shared_ip_address
            .filter(|address| !address.is_empty())
            .ok_or_else(|| {
                PluginError::retryable(
                    ErrorKind::Unavailable,
                    "fly_allocated_ip_missing",
                    "Fly.io allocated a shared IPv4 without returning its exact address",
                )
            })
    }

    async fn release_shared_ipv4(&self, token: &str, app: &str, address: &str) -> PluginResult<()> {
        let _: ReleaseIpData = self
            .graphql(
                token,
                "mutation($input:ReleaseIPAddressInput!){releaseIpAddress(input:$input){clientMutationId}}",
                release_ip_variables(app, address),
            )
            .await?;
        Ok(())
    }

    async fn acquire_lease(
        &self,
        token: &str,
        app: &str,
        machine: &str,
        description: &str,
        ttl_seconds: u64,
    ) -> PluginResult<Lease> {
        let envelope: LeaseEnvelope = self
            .decode(
                self.machines_request(
                    Method::POST,
                    &format!("v1/apps/{app}/machines/{machine}/lease"),
                    token,
                )
                .json(&json!({
                    "description": description,
                    "ttl": ttl_seconds
                })),
            )
            .await?;
        envelope.into_lease()
    }

    async fn get_lease(
        &self,
        token: &str,
        app: &str,
        machine: &str,
    ) -> PluginResult<Option<Lease>> {
        let response = self
            .machines_request(
                Method::GET,
                &format!("v1/apps/{app}/machines/{machine}/lease"),
                token,
            )
            .send()
            .await
            .map_err(network_error)?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let envelope: LeaseEnvelope = decode_response(response).await?;
        envelope.into_lease().map(Some)
    }

    async fn refresh_lease(
        &self,
        token: &str,
        app: &str,
        machine: &str,
        nonce: &str,
        ttl_seconds: u64,
    ) -> PluginResult<Lease> {
        let envelope: LeaseEnvelope = self
            .decode(self.refresh_lease_request(token, app, machine, nonce, ttl_seconds))
            .await?;
        envelope.into_lease()
    }

    async fn release_lease(
        &self,
        token: &str,
        app: &str,
        machine: &str,
        nonce: &str,
    ) -> PluginResult<()> {
        self.empty_strict(
            self.machines_request(
                Method::DELETE,
                &format!("v1/apps/{app}/machines/{machine}/lease"),
                token,
            )
            .header("fly-machine-lease-nonce", nonce),
        )
        .await
    }

    async fn public_probe(&self, url: &str) -> PluginResult<Option<PublicResponse>> {
        let Ok(response) = self
            .http
            .get(url)
            .timeout(Duration::from_secs(10))
            .send()
            .await
        else {
            return Ok(None);
        };
        Ok(Some(PublicResponse {
            status: response.status().as_u16(),
            location: response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned),
        }))
    }
}

#[derive(Deserialize)]
struct GraphQlEnvelope<T> {
    data: Option<T>,
    #[serde(default)]
    errors: Vec<GraphQlError>,
}

#[derive(Deserialize)]
struct AppList {
    #[serde(default)]
    apps: Vec<App>,
}

#[derive(Deserialize)]
struct CreateAppResponse {
    id: String,
}

#[derive(Deserialize)]
struct WaitResponse {
    ok: bool,
}

#[derive(Deserialize)]
struct GraphQlError {
    #[serde(default)]
    extensions: Option<Value>,
}

#[derive(Deserialize)]
struct SharedIpData {
    #[serde(default)]
    app: Option<SharedIpApp>,
}

#[derive(Deserialize)]
struct AllocateIpData {
    #[serde(rename = "allocateIpAddress")]
    allocate_ip_address: AllocateIpAddress,
}

#[derive(Deserialize)]
struct AllocateIpAddress {
    app: SharedIpApp,
}

#[derive(Deserialize)]
struct ReleaseIpData {
    #[serde(rename = "releaseIpAddress")]
    _release_ip_address: Value,
}

#[derive(Deserialize)]
struct SharedIpApp {
    #[serde(default, rename = "sharedIpAddress")]
    shared_ip_address: Option<String>,
}

#[derive(Deserialize)]
struct LeaseEnvelope {
    #[serde(default)]
    data: Option<LeaseData>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    expires_at: Option<UnixTimestamp>,
    #[serde(default)]
    owner: Option<String>,
}

impl LeaseEnvelope {
    fn into_lease(self) -> PluginResult<Lease> {
        let data = self.data.unwrap_or(LeaseData {
            nonce: self.nonce,
            expires_at: self.expires_at,
            owner: self.owner,
        });
        let nonce = data
            .nonce
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                PluginError::retryable(
                    ErrorKind::Unavailable,
                    "invalid_fly_lease",
                    "Fly.io returned a lease without a nonce",
                )
            })?;
        Ok(Lease {
            nonce,
            expires_at_unix: data.expires_at.map(UnixTimestamp::into_u64),
            owner: data.owner,
        })
    }
}

#[derive(Deserialize)]
struct LeaseData {
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    expires_at: Option<UnixTimestamp>,
    #[serde(default)]
    owner: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum UnixTimestamp {
    Number(u64),
    String(String),
}

impl UnixTimestamp {
    fn into_u64(self) -> u64 {
        match self {
            Self::Number(value) => value,
            Self::String(value) => value.parse().unwrap_or_default(),
        }
    }
}

async fn decode_response<T>(response: reqwest::Response) -> PluginResult<T>
where
    T: DeserializeOwned,
{
    if !response.status().is_success() {
        return Err(response_error(response).await);
    }
    response.json().await.map_err(|_| {
        PluginError::retryable(
            ErrorKind::Unavailable,
            "invalid_fly_response",
            "Fly.io returned an invalid API response",
        )
    })
}

#[allow(clippy::needless_pass_by_value)]
fn network_error(error: reqwest::Error) -> PluginError {
    if error.is_timeout() {
        PluginError::retryable(
            ErrorKind::Timeout,
            "fly_request_timeout",
            "the Fly.io API request timed out",
        )
    } else {
        PluginError::retryable(
            ErrorKind::Unavailable,
            "fly_request_failed",
            "the Fly.io API request failed",
        )
    }
}

#[allow(clippy::unused_async)]
async fn response_error(response: reqwest::Response) -> PluginError {
    error_for_status(
        response.status(),
        response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok()),
    )
}

fn error_for_status(status: StatusCode, retry_after_seconds: Option<u64>) -> PluginError {
    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => PluginError::permanent(
            ErrorKind::Authentication,
            "fly_authentication_failed",
            "Fly.io rejected the configured token or organization",
        ),
        StatusCode::NOT_FOUND => PluginError::permanent(
            ErrorKind::NotFound,
            "fly_resource_not_found",
            "the requested Fly.io resource does not exist",
        ),
        StatusCode::CONFLICT | StatusCode::PRECONDITION_FAILED => PluginError::permanent(
            ErrorKind::Conflict,
            "fly_resource_conflict",
            "Fly.io reported a conflicting resource state",
        ),
        StatusCode::TOO_MANY_REQUESTS => {
            let error = PluginError::retryable(
                ErrorKind::RateLimited,
                "fly_rate_limited",
                "Fly.io rate limited the request",
            );
            retry_after_seconds.map_or(error.clone(), |seconds| {
                error.with_retry_after(seconds.saturating_mul(1_000))
            })
        }
        StatusCode::REQUEST_TIMEOUT | StatusCode::GATEWAY_TIMEOUT => PluginError::retryable(
            ErrorKind::Timeout,
            "fly_provider_timeout",
            "Fly.io timed out while processing the request",
        ),
        status if status.is_server_error() => PluginError::retryable(
            ErrorKind::Unavailable,
            "fly_provider_unavailable",
            "Fly.io is temporarily unavailable",
        ),
        _ => PluginError::permanent(
            ErrorKind::Validation,
            "fly_request_rejected",
            format!("Fly.io rejected the request with HTTP {status}"),
        ),
    }
}

fn machine_wait_query(
    state: &str,
    instance_id: Option<&str>,
    timeout_seconds: u64,
) -> Vec<(&'static str, String)> {
    let mut query = vec![
        ("state", state.to_owned()),
        ("timeout", timeout_seconds.clamp(1, 50).to_string()),
    ];
    if let Some(instance_id) = instance_id.filter(|value| !value.is_empty()) {
        query.push(("instance_id", instance_id.to_owned()));
    }
    query
}

fn allocate_ip_variables(app: &str, region: Option<&str>) -> Value {
    let mut input = serde_json::Map::from_iter([
        ("appId".to_owned(), Value::String(app.to_owned())),
        ("type".to_owned(), Value::String("shared_v4".to_owned())),
    ]);
    if let Some(region) = region {
        input.insert("region".to_owned(), Value::String(region.to_owned()));
    }
    json!({"input": input})
}

fn release_ip_variables(app: &str, address: &str) -> Value {
    json!({
        "input": {
            "appId": app,
            "ip": address,
        }
    })
}

#[cfg(test)]
mod tests {
    use lightrail_plugin_protocol::ErrorKind;
    use reqwest::StatusCode;

    use super::{
        ApiClient, LeaseEnvelope, allocate_ip_variables, error_for_status, machine_wait_query,
        release_ip_variables,
    };

    #[test]
    fn provider_error_mapping_does_not_include_response_body() {
        let error = error_for_status(StatusCode::UNAUTHORIZED, None);
        assert_eq!(error.kind, ErrorKind::Authentication);
        assert!(!error.message.contains("super-secret"));
    }

    #[test]
    fn rate_limit_preserves_retry_delay() {
        let error = error_for_status(StatusCode::TOO_MANY_REQUESTS, Some(7));
        assert_eq!(error.kind, ErrorKind::RateLimited);
        assert_eq!(error.retry_after_ms, Some(7_000));
    }

    #[test]
    fn provider_timeout_is_retryable_timeout() {
        let error = error_for_status(StatusCode::REQUEST_TIMEOUT, None);
        assert_eq!(error.kind, ErrorKind::Timeout);
        assert!(error.retryable);
    }

    #[test]
    fn machine_wait_targets_the_exact_updated_instance() {
        let query = machine_wait_query("started", Some("instance-2"), 300);
        assert!(query.contains(&("state", "started".to_owned())));
        assert!(query.contains(&("instance_id", "instance-2".to_owned())));
        assert!(query.contains(&("timeout", "50".to_owned())));
    }

    #[test]
    fn mock_base_urls_are_explicitly_test_only() {
        let client = ApiClient::with_base_urls("http://127.0.0.1:1", "http://127.0.0.1:2");
        assert_eq!(client.machines_url, "http://127.0.0.1:1");
        assert_eq!(client.graphql_url, "http://127.0.0.1:2");
    }

    #[test]
    fn lease_refresh_matches_current_fly_go_nonce_and_ttl_request() {
        let request = ApiClient::with_base_urls("https://machines.example", "https://fly.example")
            .refresh_lease_request("token", "demo-app", "machine-1", "nonce-1", 3600)
            .build()
            .expect("refresh request");
        assert_eq!(
            request.url().as_str(),
            "https://machines.example/v1/apps/demo-app/machines/machine-1/lease?ttl=3600"
        );
        assert_eq!(
            request
                .headers()
                .get("fly-machine-lease-nonce")
                .and_then(|value| value.to_str().ok()),
            Some("nonce-1")
        );
        assert!(request.body().is_none());
    }

    #[test]
    fn expiry_commit_uses_the_single_key_machine_metadata_api() {
        let client = ApiClient::with_base_urls("https://machines.example", "https://fly.example");
        let set = client
            .set_machine_metadata_request(
                "token",
                "demo-app",
                "machine-1",
                "lightrail-expires-at-unix",
                "123",
            )
            .build()
            .expect("set metadata request");
        assert_eq!(
            set.url().as_str(),
            "https://machines.example/v1/apps/demo-app/machines/machine-1/metadata/lightrail-expires-at-unix"
        );
        assert_eq!(set.method(), reqwest::Method::POST);
        assert_eq!(
            set.body().and_then(reqwest::Body::as_bytes),
            Some(br#"{"value":"123"}"#.as_slice())
        );

        let delete = client
            .delete_machine_metadata_request(
                "token",
                "demo-app",
                "machine-1",
                "lightrail-expires-at-unix",
            )
            .build()
            .expect("delete metadata request");
        assert_eq!(delete.url(), set.url());
        assert_eq!(delete.method(), reqwest::Method::DELETE);
        assert!(delete.body().is_none());
    }

    #[test]
    fn optional_ip_region_is_omitted_instead_of_sent_empty() {
        let variables = allocate_ip_variables("demo-app", None);
        assert_eq!(
            variables.pointer("/input/appId").and_then(|v| v.as_str()),
            Some("demo-app")
        );
        assert_eq!(
            variables.pointer("/input/type").and_then(|v| v.as_str()),
            Some("shared_v4")
        );
        assert!(variables.pointer("/input/region").is_none());
    }

    #[test]
    fn allocation_response_captures_the_exact_shared_ipv4() {
        let data: super::AllocateIpData = serde_json::from_value(serde_json::json!({
            "allocateIpAddress": {
                "app": {
                    "sharedIpAddress": "203.0.113.42"
                }
            }
        }))
        .expect("current Fly GraphQL allocation shape");
        assert_eq!(
            data.allocate_ip_address.app.shared_ip_address.as_deref(),
            Some("203.0.113.42")
        );
    }

    #[test]
    fn release_ip_uses_the_exact_app_and_address() {
        assert_eq!(
            release_ip_variables("demo-app", "203.0.113.42"),
            serde_json::json!({
                "input": {
                    "appId": "demo-app",
                    "ip": "203.0.113.42"
                }
            })
        );
    }

    #[test]
    fn official_numeric_lease_expiry_shape_decodes() {
        let envelope: LeaseEnvelope = serde_json::from_value(serde_json::json!({
            "status": "success",
            "data": {
                "nonce": "lease-nonce",
                "expires_at": 1_708_569_778,
                "owner": "operation"
            }
        }))
        .expect("official lease envelope");
        let lease = envelope.into_lease().expect("valid lease");
        assert_eq!(lease.expires_at_unix, Some(1_708_569_778));
    }

    #[test]
    fn official_app_envelopes_decode() {
        let list: super::AppList = serde_json::from_value(serde_json::json!({
            "total_apps": 1,
            "apps": [{
                "id": "app-id",
                "name": "demo-app",
                "status": "deployed",
                "organization": {"slug": "personal"}
            }]
        }))
        .expect("official list envelope");
        assert_eq!(list.apps[0].name, "demo-app");
        let created: super::CreateAppResponse = serde_json::from_value(serde_json::json!({
            "id": "app-id",
            "created_at": 1_700_000_000
        }))
        .expect("official create envelope");
        assert_eq!(created.id, "app-id");
    }

    #[test]
    fn official_machine_wait_shape_decodes() {
        let response: super::WaitResponse = serde_json::from_value(serde_json::json!({"ok": true}))
            .expect("official wait response");
        assert!(response.ok);
    }
}
