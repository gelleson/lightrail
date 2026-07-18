use std::{collections::HashMap, future::Future, sync::Arc};

use async_trait::async_trait;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use tokio::{
    io::{self, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    sync::{Mutex, oneshot},
    task::{AbortHandle, JoinSet},
};
use uuid::Uuid;

use crate::{
    ApplyRequest, ApplyResult, CancelRequest, CancelResult, DestroyRequest, DestroyResult, Empty,
    ErrorKind, InitializeRequest, InitializeResult, InspectRequest, InspectResult, JsonRpcError,
    LockAcquireRequest, LockAcquireResult, LockReleaseRequest, LockReleaseResult, LogsRequest,
    LogsResult, MAX_MESSAGE_BYTES, PlanRequest, PlanResult, PluginError, PluginEvent,
    PluginManifest, PluginResult, RequestId, ServeError, ValidateRequest, ValidateResult, methods,
    wire::{CancelRpcRequest, ErrorResponse, IncomingMessage, RpcNotification, SuccessResponse},
};

type DynWriter = Box<dyn AsyncWrite + Send + Unpin>;
type SharedWriter = Arc<Mutex<DynWriter>>;

/// Atomic JSON-RPC notification writer passed to plugin handlers.
#[derive(Clone)]
pub struct EventSink {
    writer: SharedWriter,
}

impl EventSink {
    /// Emit a typed progress/log/journal/diagnostic event.
    ///
    /// # Errors
    ///
    /// Returns a serialization or protocol-output transport error.
    pub async fn emit(&self, event: &PluginEvent) -> Result<(), ServeError> {
        self.notify(methods::EVENT, event).await
    }

    /// Emit a namespaced extension notification.
    ///
    /// # Errors
    ///
    /// Returns a serialization or protocol-output transport error.
    pub async fn notify<P>(&self, method: &str, params: &P) -> Result<(), ServeError>
    where
        P: Serialize,
    {
        let notification = RpcNotification {
            jsonrpc: "2.0",
            method,
            params,
        };
        write_json_line(&self.writer, &notification).await
    }
}

/// Rust implementation interface for a Lightrail executable plugin.
///
/// Methods may execute concurrently. Implementations must therefore be
/// thread-safe and use `operation_id` for their own cancellation coordination.
/// Default operation methods return a structured `method_unsupported` error.
#[async_trait]
pub trait PluginHandler: Send + Sync + 'static {
    /// Static plugin declaration.
    fn manifest(&self) -> PluginManifest;

    /// Negotiate a protocol and create a process-local session.
    async fn initialize(
        &self,
        request: InitializeRequest,
        _events: &EventSink,
    ) -> PluginResult<InitializeResult> {
        let manifest = self.manifest();
        let plugin_version = manifest.protocol.version;
        let offered = request.protocol_version == plugin_version
            || request
                .supported_protocol_versions
                .contains(&plugin_version);
        if !offered || !manifest.protocol.requires.contains(plugin_version) {
            return Err(PluginError::permanent(
                ErrorKind::Validation,
                "protocol_mismatch",
                format!(
                    "plugin protocol {plugin_version} is not compatible with requested {}",
                    request.protocol_version
                ),
            )
            .with_details(json!({
                "requested": request.protocol_version,
                "plugin": plugin_version,
            })));
        }
        Ok(InitializeResult {
            protocol_version: plugin_version,
            session_id: Uuid::new_v4().to_string(),
            manifest,
        })
    }

    /// Validate configuration/input.
    async fn validate(
        &self,
        _request: ValidateRequest,
        _events: &EventSink,
    ) -> PluginResult<ValidateResult> {
        Err(PluginError::unsupported(methods::VALIDATE))
    }

    /// Compute an idempotent plan.
    async fn plan(&self, _request: PlanRequest, _events: &EventSink) -> PluginResult<PlanResult> {
        Err(PluginError::unsupported(methods::PLAN))
    }

    /// Apply a plan.
    async fn apply(
        &self,
        _request: ApplyRequest,
        _events: &EventSink,
    ) -> PluginResult<ApplyResult> {
        Err(PluginError::unsupported(methods::APPLY))
    }

    /// Rediscover managed state.
    async fn inspect(
        &self,
        _request: InspectRequest,
        _events: &EventSink,
    ) -> PluginResult<InspectResult> {
        Err(PluginError::unsupported(methods::INSPECT))
    }

    /// Destroy managed state.
    async fn destroy(
        &self,
        _request: DestroyRequest,
        _events: &EventSink,
    ) -> PluginResult<DestroyResult> {
        Err(PluginError::unsupported(methods::DESTROY))
    }

    /// Cancel a logical operation.
    async fn cancel(
        &self,
        _request: CancelRequest,
        _events: &EventSink,
    ) -> PluginResult<CancelResult> {
        Err(PluginError::unsupported(methods::CANCEL))
    }

    /// Acquire an authoritative mutation lock.
    async fn lock_acquire(
        &self,
        _request: LockAcquireRequest,
        _events: &EventSink,
    ) -> PluginResult<LockAcquireResult> {
        Err(PluginError::unsupported(methods::LOCK_ACQUIRE))
    }

    /// Release an authoritative mutation lock.
    async fn lock_release(
        &self,
        _request: LockReleaseRequest,
        _events: &EventSink,
    ) -> PluginResult<LockReleaseResult> {
        Err(PluginError::unsupported(methods::LOCK_RELEASE))
    }

    /// Return initial logs and optionally start emitting log events.
    async fn logs(&self, _request: LogsRequest, _events: &EventSink) -> PluginResult<LogsResult> {
        Err(PluginError::unsupported(methods::LOGS))
    }

    /// Handle an extension notification from core.
    async fn notification(
        &self,
        _method: &str,
        _params: Value,
        _events: &EventSink,
    ) -> PluginResult<()> {
        Ok(())
    }
}

/// Serve a Rust plugin on process stdin/stdout until EOF or shutdown.
///
/// # Errors
///
/// Returns when standard input/output or response serialization fails.
pub async fn serve_stdio<H>(handler: H) -> Result<(), ServeError>
where
    H: PluginHandler,
{
    serve(io::stdin(), io::stdout(), handler).await
}

/// Serve a Rust plugin on arbitrary async streams.
///
/// Each response/event is locked and written as one complete line, so handler
/// methods can safely execute concurrently.
///
/// # Errors
///
/// Returns when reading input, writing output, serializing a response, or a
/// request task fails.
#[allow(clippy::too_many_lines)]
pub async fn serve<R, W, H>(reader: R, writer: W, handler: H) -> Result<(), ServeError>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
    H: PluginHandler,
{
    let handler = Arc::new(handler);
    let writer: SharedWriter = Arc::new(Mutex::new(Box::new(writer)));
    let events = EventSink {
        writer: Arc::clone(&writer),
    };
    let active = Arc::new(Mutex::new(HashMap::<RequestId, AbortHandle>::new()));
    let mut tasks = JoinSet::new();
    let mut reader = BufReader::new(reader);
    let mut buffer = Vec::new();

    loop {
        buffer.clear();
        let read = reader.read_until(b'\n', &mut buffer).await?;
        if read == 0 {
            break;
        }
        if buffer.len() > MAX_MESSAGE_BYTES + 1 {
            write_rpc_error(
                &writer,
                &Value::Null,
                JsonRpcError {
                    code: -32_700,
                    message: format!("message exceeds {MAX_MESSAGE_BYTES} bytes"),
                    data: None,
                },
            )
            .await?;
            break;
        }
        trim_newline(&mut buffer);
        let raw: Value = match serde_json::from_slice(&buffer) {
            Ok(value) => value,
            Err(error) => {
                write_rpc_error(
                    &writer,
                    &Value::Null,
                    JsonRpcError {
                        code: -32_700,
                        message: "parse error".to_owned(),
                        data: Some(json!({ "error": error.to_string() })),
                    },
                )
                .await?;
                continue;
            }
        };
        let message: IncomingMessage = match serde_json::from_value::<IncomingMessage>(raw) {
            Ok(message) if message.jsonrpc == "2.0" => message,
            Ok(_) | Err(_) => {
                write_rpc_error(
                    &writer,
                    &Value::Null,
                    rpc_error(-32_600, "invalid JSON-RPC 2.0 request"),
                )
                .await?;
                continue;
            }
        };

        let Some(method) = message.method else {
            write_rpc_error(
                &writer,
                message.id.as_ref().unwrap_or(&Value::Null),
                rpc_error(-32_600, "plugin server accepts only requests/notifications"),
            )
            .await?;
            continue;
        };

        let params = message.params.unwrap_or_else(|| json!({}));
        let Some(raw_id) = message.id else {
            if method == methods::CANCEL_REQUEST {
                if let Ok(cancel) = serde_json::from_value::<CancelRpcRequest>(params) {
                    if let Some(handle) = active.lock().await.remove(&cancel.id) {
                        handle.abort();
                    }
                }
            } else {
                handler.notification(&method, params, &events).await.ok();
            }
            continue;
        };

        let Ok(id) = serde_json::from_value::<RequestId>(raw_id.clone()) else {
            write_rpc_error(
                &writer,
                &Value::Null,
                rpc_error(-32_600, "request ID must be a string or integer"),
            )
            .await?;
            continue;
        };

        if method == methods::SHUTDOWN {
            write_rpc_success(&writer, &raw_id, serde_json::to_value(Empty {})?).await?;
            break;
        }

        let (start_sender, start_receiver) = oneshot::channel();
        let task_handler = Arc::clone(&handler);
        let task_writer = Arc::clone(&writer);
        let task_events = events.clone();
        let task_active = Arc::clone(&active);
        let task_id = id.clone();
        let abort_handle = tasks.spawn(async move {
            let _ = start_receiver.await;
            let response = dispatch(&*task_handler, &method, params, &task_events).await;
            let write_result = match response {
                Ok(result) => write_rpc_success(&task_writer, &raw_id, result).await,
                Err(error) => write_rpc_error(&task_writer, &raw_id, error).await,
            };
            task_active.lock().await.remove(&task_id);
            write_result
        });
        active.lock().await.insert(id, abort_handle);
        let _ = start_sender.send(());
    }

    while let Some(join_result) = tasks.join_next().await {
        match join_result {
            Ok(task_result) => task_result?,
            Err(error) if error.is_cancelled() => {}
            Err(error) => {
                return Err(ServeError::Io(io::Error::other(format!(
                    "plugin request task failed: {error}"
                ))));
            }
        }
    }
    Ok(())
}

async fn dispatch<H>(
    handler: &H,
    method: &str,
    params: Value,
    events: &EventSink,
) -> Result<Value, JsonRpcError>
where
    H: PluginHandler,
{
    match method {
        methods::INITIALIZE => {
            call(parse_params(params)?, |request| {
                handler.initialize(request, events)
            })
            .await
        }
        methods::VALIDATE => {
            call(parse_params(params)?, |request| {
                handler.validate(request, events)
            })
            .await
        }
        methods::PLAN => {
            call(parse_params(params)?, |request| {
                handler.plan(request, events)
            })
            .await
        }
        methods::APPLY => {
            call(parse_params(params)?, |request| {
                handler.apply(request, events)
            })
            .await
        }
        methods::INSPECT => {
            call(parse_params(params)?, |request| {
                handler.inspect(request, events)
            })
            .await
        }
        methods::DESTROY => {
            call(parse_params(params)?, |request| {
                handler.destroy(request, events)
            })
            .await
        }
        methods::CANCEL => {
            call(parse_params(params)?, |request| {
                handler.cancel(request, events)
            })
            .await
        }
        methods::LOCK_ACQUIRE => {
            call(parse_params(params)?, |request| {
                handler.lock_acquire(request, events)
            })
            .await
        }
        methods::LOCK_RELEASE => {
            call(parse_params(params)?, |request| {
                handler.lock_release(request, events)
            })
            .await
        }
        methods::LOGS => {
            call(parse_params(params)?, |request| {
                handler.logs(request, events)
            })
            .await
        }
        _ => Err(rpc_error(-32_601, "method not found")),
    }
}

fn parse_params<T>(params: Value) -> Result<T, JsonRpcError>
where
    T: DeserializeOwned,
{
    serde_json::from_value(params).map_err(|error| JsonRpcError {
        code: -32_602,
        message: "invalid method parameters".to_owned(),
        data: Some(json!({ "error": error.to_string() })),
    })
}

async fn call<T, F, Fut, R>(request: T, callback: F) -> Result<Value, JsonRpcError>
where
    F: FnOnce(T) -> Fut,
    Fut: Future<Output = PluginResult<R>>,
    R: Serialize,
{
    match callback(request).await {
        Ok(result) => serde_json::to_value(result).map_err(|error| JsonRpcError {
            code: -32_603,
            message: "failed to serialize plugin result".to_owned(),
            data: Some(json!({ "error": error.to_string() })),
        }),
        Err(error) => Err(plugin_rpc_error(error)),
    }
}

fn plugin_rpc_error(error: PluginError) -> JsonRpcError {
    let data = serde_json::to_value(&error).ok();
    JsonRpcError {
        code: -32_000,
        message: error.message,
        data,
    }
}

fn rpc_error(code: i64, message: &str) -> JsonRpcError {
    JsonRpcError {
        code,
        message: message.to_owned(),
        data: None,
    }
}

async fn write_rpc_success(
    writer: &SharedWriter,
    id: &Value,
    result: Value,
) -> Result<(), ServeError> {
    write_json_line(
        writer,
        &SuccessResponse {
            jsonrpc: "2.0",
            id,
            result,
        },
    )
    .await
}

async fn write_rpc_error(
    writer: &SharedWriter,
    id: &Value,
    error: JsonRpcError,
) -> Result<(), ServeError> {
    write_json_line(
        writer,
        &ErrorResponse {
            jsonrpc: "2.0",
            id,
            error,
        },
    )
    .await
}

async fn write_json_line<T>(writer: &SharedWriter, value: &T) -> Result<(), ServeError>
where
    T: Serialize + ?Sized,
{
    let mut encoded = serde_json::to_vec(value)?;
    if encoded.len() > MAX_MESSAGE_BYTES {
        return Err(ServeError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("outgoing message exceeds {MAX_MESSAGE_BYTES} bytes"),
        )));
    }
    encoded.push(b'\n');
    let mut writer = writer.lock().await;
    writer.write_all(&encoded).await?;
    writer.flush().await?;
    Ok(())
}

fn trim_newline(buffer: &mut Vec<u8>) {
    if buffer.last() == Some(&b'\n') {
        buffer.pop();
    }
    if buffer.last() == Some(&b'\r') {
        buffer.pop();
    }
}
