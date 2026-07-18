use std::{
    collections::{BTreeMap, HashMap, HashSet},
    ffi::OsString,
    path::PathBuf,
    process::Stdio,
    sync::{
        Arc, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    process::{Child, Command},
    sync::{Mutex, RwLock, broadcast, oneshot},
};

use crate::{
    ApplyRequest, ApplyResult, CancelRequest, CancelResult, ClientError, DestroyRequest,
    DestroyResult, Empty, InitializeRequest, InitializeResult, InspectRequest, InspectResult,
    JsonRpcError, LockAcquireRequest, LockAcquireResult, LockReleaseRequest, LockReleaseResult,
    LogsRequest, LogsResult, MAX_MESSAGE_BYTES, PlanRequest, PlanResult, PluginError, PluginEvent,
    RequestId, ValidateRequest, ValidateResult,
    error::TerminalFailure,
    methods,
    wire::{CancelRpcRequest, IncomingMessage, RpcNotification, RpcRequest},
};

type DynWriter = Box<dyn AsyncWrite + Send + Unpin>;

/// Core-side process behavior.
#[derive(Clone, Copy, Debug)]
pub struct ClientOptions {
    /// Default deadline for a request.
    pub request_timeout: Duration,
    /// Time allowed for process exit after `plugin.shutdown`.
    pub shutdown_timeout: Duration,
    /// Capacity of the lossy broadcast event channel.
    pub event_buffer: usize,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            // Provisioning, local image transfer, and remote readiness checks can
            // legitimately span several minutes. The timeout remains bounded and
            // the client sends `plugin.cancel` when it expires.
            request_timeout: Duration::from_secs(30 * 60),
            shutdown_timeout: Duration::from_secs(5),
            event_buffer: 256,
        }
    }
}

/// Explicit, sanitized process launch configuration.
///
/// [`PluginClient::spawn`] calls `env_clear` before adding exactly `env`, so a
/// plugin does not inherit credentials or ambient configuration by accident.
#[derive(Clone, Debug)]
pub struct SpawnOptions {
    /// Plugin executable.
    pub program: PathBuf,
    /// Fixed executable arguments.
    pub args: Vec<OsString>,
    /// Optional working directory.
    pub current_dir: Option<PathBuf>,
    /// Complete environment visible to the child.
    pub env: BTreeMap<OsString, OsString>,
    /// Client timing/channel behavior.
    pub client: ClientOptions,
}

impl SpawnOptions {
    /// Create launch options with no arguments and an empty child environment.
    #[must_use]
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            current_dir: None,
            env: BTreeMap::new(),
            client: ClientOptions::default(),
        }
    }
}

/// Asynchronous output observed from a plugin outside request responses.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum ClientEvent {
    /// Typed structured notification.
    Plugin(PluginEvent),
    /// A non-protocol stderr line.
    ///
    /// Plugins must redact secrets before writing stderr.
    Stderr(String),
    /// A valid extension notification not known to this protocol crate.
    Notification {
        /// Namespaced JSON-RPC method.
        method: String,
        /// Untyped notification parameters.
        params: Value,
    },
}

/// Async JSON-RPC client for one plugin process/stream.
#[derive(Clone)]
pub struct PluginClient {
    inner: Arc<Inner>,
}

struct Inner {
    writer: Mutex<Option<DynWriter>>,
    pending: Mutex<HashMap<RequestId, oneshot::Sender<Response>>>,
    retired: Mutex<HashSet<RequestId>>,
    terminal: RwLock<Option<TerminalFailure>>,
    events: broadcast::Sender<ClientEvent>,
    next_id: AtomicU64,
    request_timeout: Duration,
    shutdown_timeout: Duration,
    child: Mutex<Option<Child>>,
}

type Response = Result<Value, ResponseFailure>;

#[derive(Clone, Debug)]
enum ResponseFailure {
    Terminal(TerminalFailure),
    Remote(JsonRpcError),
}

impl PluginClient {
    /// Start an external executable with a cleared, caller-supplied environment.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Spawn`] when the executable cannot start or a
    /// protocol error when its standard streams cannot be captured.
    #[allow(clippy::unused_async)]
    pub async fn spawn(options: SpawnOptions) -> Result<Self, ClientError> {
        let display_program = options.program.display().to_string();
        let mut command = Command::new(&options.program);
        command
            .args(&options.args)
            .env_clear()
            .envs(&options.env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(current_dir) = &options.current_dir {
            command.current_dir(current_dir);
        }

        let mut child = command.spawn().map_err(|source| ClientError::Spawn {
            program: display_program,
            source,
        })?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| ClientError::Protocol("spawned plugin has no piped stdin".to_owned()))?;
        let stdout = child.stdout.take().ok_or_else(|| {
            ClientError::Protocol("spawned plugin has no piped stdout".to_owned())
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            ClientError::Protocol("spawned plugin has no piped stderr".to_owned())
        })?;

        let client = Self::from_parts(stdout, stdin, Some(child), &options.client);
        spawn_stderr_reader(stderr, Arc::downgrade(&client.inner));
        Ok(client)
    }

    /// Connect the client to arbitrary async streams.
    ///
    /// This is useful for embedded adapters and deterministic protocol tests.
    #[must_use]
    pub fn connect_io<R, W>(reader: R, writer: W, options: ClientOptions) -> Self
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        Self::from_parts(reader, writer, None, &options)
    }

    fn from_parts<R, W>(reader: R, writer: W, child: Option<Child>, options: &ClientOptions) -> Self
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let (events, _) = broadcast::channel(options.event_buffer.max(1));
        let inner = Arc::new(Inner {
            writer: Mutex::new(Some(Box::new(writer))),
            pending: Mutex::new(HashMap::new()),
            retired: Mutex::new(HashSet::new()),
            terminal: RwLock::new(None),
            events,
            next_id: AtomicU64::new(1),
            request_timeout: options.request_timeout,
            shutdown_timeout: options.shutdown_timeout,
            child: Mutex::new(child),
        });
        spawn_protocol_reader(reader, Arc::downgrade(&inner));
        Self { inner }
    }

    /// Subscribe to progress, logs, extension notifications, and stderr.
    ///
    /// This is a lossy broadcast channel. A lagging consumer receives Tokio's
    /// `Lagged` error and should rediscover authoritative state.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<ClientEvent> {
        self.inner.events.subscribe()
    }

    /// Send a typed request using the default timeout.
    ///
    /// # Errors
    ///
    /// Returns a transport, protocol, timeout, decoding, or remote plugin error.
    pub async fn request<P, R>(&self, method: &str, params: &P) -> Result<R, ClientError>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        self.request_with_timeout(method, params, self.inner.request_timeout)
            .await
    }

    /// Send a typed request with a call-specific timeout.
    ///
    /// # Errors
    ///
    /// Returns a transport, protocol, timeout, decoding, or remote plugin error.
    pub async fn request_with_timeout<P, R>(
        &self,
        method: &str,
        params: &P,
        timeout: Duration,
    ) -> Result<R, ClientError>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        if let Some(failure) = self.inner.terminal.read().await.clone() {
            return Err(failure.into());
        }

        let id = RequestId::Number(self.inner.next_id.fetch_add(1, Ordering::Relaxed));
        let (sender, receiver) = oneshot::channel();
        self.inner.pending.lock().await.insert(id.clone(), sender);

        let request = RpcRequest {
            jsonrpc: "2.0",
            id: &id,
            method,
            params,
        };
        if let Err(error) = self.write_message(&request).await {
            self.inner.pending.lock().await.remove(&id);
            mark_terminal(
                &self.inner,
                TerminalFailure::Protocol(format!("failed to write request: {error}")),
            )
            .await;
            return Err(error);
        }

        let response = match tokio::time::timeout(timeout, receiver).await {
            Ok(Ok(response)) => response,
            Ok(Err(_closed)) => {
                let failure = self
                    .inner
                    .terminal
                    .read()
                    .await
                    .clone()
                    .unwrap_or(TerminalFailure::Closed);
                return Err(failure.into());
            }
            Err(_elapsed) => {
                self.inner.pending.lock().await.remove(&id);
                self.inner.retired.lock().await.insert(id.clone());
                let cancellation = CancelRpcRequest { id: id.clone() };
                let client = self.clone();
                tokio::spawn(async move {
                    let _ = client.notify(methods::CANCEL_REQUEST, &cancellation).await;
                });
                return Err(ClientError::Timeout {
                    method: method.to_owned(),
                    id,
                    timeout,
                });
            }
        };

        match response {
            Ok(value) => serde_json::from_value(value).map_err(ClientError::Serialization),
            Err(ResponseFailure::Terminal(failure)) => Err(failure.into()),
            Err(ResponseFailure::Remote(error)) => Err(map_remote_error(error)),
        }
    }

    /// Send a JSON-RPC notification.
    ///
    /// # Errors
    ///
    /// Returns an encoding or transport error if the notification cannot be
    /// written atomically to the plugin.
    pub async fn notify<P>(&self, method: &str, params: &P) -> Result<(), ClientError>
    where
        P: Serialize,
    {
        let notification = RpcNotification {
            jsonrpc: "2.0",
            method,
            params,
        };
        self.write_message(&notification).await
    }

    async fn write_message<T>(&self, message: &T) -> Result<(), ClientError>
    where
        T: Serialize + ?Sized,
    {
        let mut encoded = serde_json::to_vec(message)?;
        if encoded.len() > MAX_MESSAGE_BYTES {
            return Err(ClientError::Protocol(format!(
                "outgoing message exceeds {MAX_MESSAGE_BYTES} bytes"
            )));
        }
        encoded.push(b'\n');
        let mut writer = self.inner.writer.lock().await;
        let writer = writer.as_mut().ok_or(ClientError::Closed)?;
        writer.write_all(&encoded).await?;
        writer.flush().await?;
        Ok(())
    }

    /// Negotiate protocol compatibility and return the plugin manifest.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::ProtocolMismatch`] for an incompatible result, or
    /// another client error when negotiation cannot complete.
    pub async fn initialize(
        &self,
        request: InitializeRequest,
    ) -> Result<InitializeResult, ClientError> {
        let preferred = request.protocol_version;
        let mut offered = request.supported_protocol_versions.clone();
        if !offered.contains(&preferred) {
            offered.push(preferred);
        }
        let result: InitializeResult = self.request(methods::INITIALIZE, &request).await?;
        let compatible = offered.contains(&result.protocol_version)
            && result.manifest.protocol.version == result.protocol_version
            && result
                .manifest
                .protocol
                .requires
                .contains(result.protocol_version);
        if !compatible {
            return Err(ClientError::ProtocolMismatch {
                requested: preferred,
                selected: result.protocol_version,
            });
        }
        Ok(result)
    }

    /// Validate plugin input.
    ///
    /// # Errors
    ///
    /// Returns a client or structured remote plugin error.
    pub async fn validate(&self, request: ValidateRequest) -> Result<ValidateResult, ClientError> {
        self.request(methods::VALIDATE, &request).await
    }

    /// Compute a change plan.
    ///
    /// # Errors
    ///
    /// Returns a client or structured remote plugin error.
    pub async fn plan(&self, request: PlanRequest) -> Result<PlanResult, ClientError> {
        self.request(methods::PLAN, &request).await
    }

    /// Apply a change plan.
    ///
    /// # Errors
    ///
    /// Returns a client or structured remote plugin error.
    pub async fn apply(&self, request: ApplyRequest) -> Result<ApplyResult, ClientError> {
        self.request(methods::APPLY, &request).await
    }

    /// Inspect provider/runtime state.
    ///
    /// # Errors
    ///
    /// Returns a client or structured remote plugin error.
    pub async fn inspect(&self, request: InspectRequest) -> Result<InspectResult, ClientError> {
        self.request(methods::INSPECT, &request).await
    }

    /// Destroy managed state.
    ///
    /// # Errors
    ///
    /// Returns a client or structured remote plugin error.
    pub async fn destroy(&self, request: DestroyRequest) -> Result<DestroyResult, ClientError> {
        self.request(methods::DESTROY, &request).await
    }

    /// Cancel a logical operation.
    ///
    /// # Errors
    ///
    /// Returns a client or structured remote plugin error.
    pub async fn cancel(&self, request: CancelRequest) -> Result<CancelResult, ClientError> {
        self.request(methods::CANCEL, &request).await
    }

    /// Acquire an authoritative mutation lock.
    ///
    /// # Errors
    ///
    /// Returns a client or structured remote plugin error.
    pub async fn lock_acquire(
        &self,
        request: LockAcquireRequest,
    ) -> Result<LockAcquireResult, ClientError> {
        self.request(methods::LOCK_ACQUIRE, &request).await
    }

    /// Release an authoritative mutation lock.
    ///
    /// # Errors
    ///
    /// Returns a client or structured remote plugin error.
    pub async fn lock_release(
        &self,
        request: LockReleaseRequest,
    ) -> Result<LockReleaseResult, ClientError> {
        self.request(methods::LOCK_RELEASE, &request).await
    }

    /// Query or start streaming logs.
    ///
    /// # Errors
    ///
    /// Returns a client or structured remote plugin error.
    pub async fn logs(&self, request: LogsRequest) -> Result<LogsResult, ClientError> {
        self.request(methods::LOGS, &request).await
    }

    /// Ask the plugin to exit, then terminate it if the grace period expires.
    ///
    /// # Errors
    ///
    /// Returns a shutdown protocol or process termination error. Process cleanup
    /// is still attempted after a shutdown protocol error.
    pub async fn shutdown(&self) -> Result<(), ClientError> {
        let shutdown_result: Result<Empty, ClientError> = self
            .request_with_timeout(methods::SHUTDOWN, &Empty {}, self.inner.shutdown_timeout)
            .await;

        self.inner.writer.lock().await.take();
        let mut child_guard = self.inner.child.lock().await;
        if let Some(child) = child_guard.as_mut() {
            match tokio::time::timeout(self.inner.shutdown_timeout, child.wait()).await {
                Ok(result) => {
                    result?;
                }
                Err(_elapsed) => {
                    child.kill().await?;
                    child.wait().await?;
                }
            }
            child_guard.take();
        }
        match shutdown_result {
            Ok(_) | Err(ClientError::Closed) => Ok(()),
            Err(error) => Err(error),
        }
    }
}

fn map_remote_error(error: JsonRpcError) -> ClientError {
    if let Some(data) = error.data.clone() {
        if let Ok(plugin_error) = serde_json::from_value::<PluginError>(data) {
            if plugin_error.code == "protocol_mismatch" {
                let requested = plugin_error
                    .details
                    .get("requested")
                    .and_then(Value::as_str)
                    .and_then(|value| value.parse().ok());
                let selected = plugin_error
                    .details
                    .get("plugin")
                    .and_then(Value::as_str)
                    .and_then(|value| value.parse().ok());
                if let (Some(requested), Some(selected)) = (requested, selected) {
                    return ClientError::ProtocolMismatch {
                        requested,
                        selected,
                    };
                }
            }
            return ClientError::Remote(plugin_error);
        }
    }
    ClientError::RemoteRpc {
        code: error.code,
        message: error.message,
        data: error.data,
    }
}

fn spawn_protocol_reader<R>(reader: R, inner: Weak<Inner>)
where
    R: AsyncRead + Send + Unpin + 'static,
{
    tokio::spawn(async move {
        let mut reader = BufReader::new(reader);
        let mut buffer = Vec::new();
        loop {
            buffer.clear();
            match reader.read_until(b'\n', &mut buffer).await {
                Ok(0) => {
                    if let Some(inner) = inner.upgrade() {
                        mark_terminal(&inner, TerminalFailure::Closed).await;
                    }
                    break;
                }
                Ok(_) if buffer.len() > MAX_MESSAGE_BYTES + 1 => {
                    if let Some(inner) = inner.upgrade() {
                        mark_terminal(
                            &inner,
                            TerminalFailure::Protocol(format!(
                                "message exceeds {MAX_MESSAGE_BYTES} bytes"
                            )),
                        )
                        .await;
                    }
                    break;
                }
                Ok(_) => {
                    trim_newline(&mut buffer);
                    let Some(inner) = inner.upgrade() else {
                        break;
                    };
                    if let Err(failure) = process_incoming(&inner, &buffer).await {
                        mark_terminal(&inner, failure).await;
                        break;
                    }
                }
                Err(error) => {
                    if let Some(inner) = inner.upgrade() {
                        mark_terminal(
                            &inner,
                            TerminalFailure::Protocol(format!("failed to read stdout: {error}")),
                        )
                        .await;
                    }
                    break;
                }
            }
        }
    });
}

fn spawn_stderr_reader<R>(reader: R, inner: Weak<Inner>)
where
    R: AsyncRead + Send + Unpin + 'static,
{
    tokio::spawn(async move {
        let mut reader = BufReader::new(reader);
        let mut buffer = Vec::new();
        loop {
            buffer.clear();
            let Ok(read) = reader.read_until(b'\n', &mut buffer).await else {
                break;
            };
            if read == 0 {
                break;
            }
            trim_newline(&mut buffer);
            let Some(inner) = inner.upgrade() else {
                break;
            };
            let line = String::from_utf8_lossy(&buffer).into_owned();
            let _ = inner.events.send(ClientEvent::Stderr(line));
        }
    });
}

fn trim_newline(buffer: &mut Vec<u8>) {
    if buffer.last() == Some(&b'\n') {
        buffer.pop();
    }
    if buffer.last() == Some(&b'\r') {
        buffer.pop();
    }
}

async fn process_incoming(inner: &Arc<Inner>, bytes: &[u8]) -> Result<(), TerminalFailure> {
    if bytes.is_empty() {
        return Err(TerminalFailure::Protocol(
            "empty line on protocol stdout".to_owned(),
        ));
    }
    let raw: Value = serde_json::from_slice(bytes).map_err(|error| {
        TerminalFailure::Protocol(format!("malformed JSON-RPC output: {error}"))
    })?;
    let object = raw.as_object().ok_or_else(|| {
        TerminalFailure::Protocol("JSON-RPC message must be an object".to_owned())
    })?;
    let has_result = object.contains_key("result");
    let has_error = object.contains_key("error");
    let message: IncomingMessage = serde_json::from_value(raw)
        .map_err(|error| TerminalFailure::Protocol(format!("invalid JSON-RPC object: {error}")))?;
    if message.jsonrpc != "2.0" {
        return Err(TerminalFailure::Protocol(
            "JSON-RPC version must be `2.0`".to_owned(),
        ));
    }

    if let Some(method) = message.method {
        if message.id.is_some() {
            return Err(TerminalFailure::Protocol(
                "plugin-to-core requests are not supported".to_owned(),
            ));
        }
        let params = message.params.unwrap_or(Value::Null);
        if method == methods::EVENT {
            let event: PluginEvent = serde_json::from_value(params).map_err(|error| {
                TerminalFailure::Protocol(format!("invalid plugin event: {error}"))
            })?;
            let _ = inner.events.send(ClientEvent::Plugin(event));
        } else {
            let _ = inner
                .events
                .send(ClientEvent::Notification { method, params });
        }
        return Ok(());
    }

    if has_result == has_error {
        return Err(TerminalFailure::Protocol(
            "response must contain exactly one of `result` or `error`".to_owned(),
        ));
    }
    let raw_id = message
        .id
        .ok_or_else(|| TerminalFailure::Protocol("response is missing request ID".to_owned()))?;
    let id: RequestId = serde_json::from_value(raw_id).map_err(|_| {
        TerminalFailure::Protocol("response ID must be a string or integer".to_owned())
    })?;

    let sender = inner.pending.lock().await.remove(&id);
    let Some(sender) = sender else {
        if inner.retired.lock().await.remove(&id) {
            return Ok(());
        }
        return Err(TerminalFailure::Protocol(format!(
            "response references unknown request ID `{id}`"
        )));
    };
    let response = if let Some(error) = message.error {
        Err(ResponseFailure::Remote(error))
    } else {
        Ok(message.result.unwrap_or(Value::Null))
    };
    let _ = sender.send(response);
    Ok(())
}

async fn mark_terminal(inner: &Arc<Inner>, failure: TerminalFailure) {
    let mut terminal = inner.terminal.write().await;
    if terminal.is_some() {
        return;
    }
    *terminal = Some(failure.clone());
    drop(terminal);

    let pending = std::mem::take(&mut *inner.pending.lock().await);
    for (_, sender) in pending {
        let _ = sender.send(Err(ResponseFailure::Terminal(failure.clone())));
    }
    if let Some(child) = inner.child.lock().await.as_mut() {
        let _ = child.start_kill();
    }
}
