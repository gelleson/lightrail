use std::time::Duration;

use async_trait::async_trait;
use lightrail_plugin_protocol::{
    Capability, ClientError, ClientEvent, ClientOptions, Diagnostic, DiagnosticSeverity, Empty,
    EventSink, ExecutableMetadata, InitializeRequest, MAX_OPERATION_REQUEST_TIMEOUT,
    OperationContext, PluginEvent, PluginHandler, PluginManifest, PluginResult,
    ProtocolCompatibility, ProtocolRequirement, ProtocolVersion, SecretValue, ValidateRequest,
    ValidateResult, operation_request_timeout, serve,
};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, duplex, split};

#[derive(Clone)]
struct TestHandler {
    delay: Duration,
    protocol: ProtocolVersion,
}

impl TestHandler {
    fn current() -> Self {
        Self {
            delay: Duration::ZERO,
            protocol: lightrail_plugin_protocol::PROTOCOL_VERSION,
        }
    }
}

#[async_trait]
impl PluginHandler for TestHandler {
    fn manifest(&self) -> PluginManifest {
        PluginManifest {
            id: "io.lightrail.test".to_owned(),
            name: "Test plugin".to_owned(),
            version: "0.1.0".to_owned(),
            protocol: ProtocolCompatibility {
                version: self.protocol,
                requires: ProtocolRequirement::compatible_with(self.protocol),
            },
            executable: ExecutableMetadata::default(),
            capabilities: vec![Capability::Other("test-echo".to_owned())],
            features: Vec::new(),
            required_secrets: Vec::new(),
            config_schema: json!({"type": "object"}),
            config_ui_hints: json!({}),
        }
    }

    async fn validate(
        &self,
        request: ValidateRequest,
        events: &EventSink,
    ) -> PluginResult<ValidateResult> {
        let requested_delay = request
            .desired
            .get("delay_ms")
            .and_then(serde_json::Value::as_u64)
            .map_or(self.delay, Duration::from_millis);
        events
            .emit(&PluginEvent::Progress {
                operation_id: request.context.operation_id,
                message: "validating".to_owned(),
                completed: Some(1),
                total: Some(1),
            })
            .await
            .expect("duplex event write should succeed");
        tokio::time::sleep(requested_delay).await;
        Ok(ValidateResult {
            valid: true,
            diagnostics: vec![Diagnostic {
                severity: DiagnosticSeverity::Info,
                code: "ok".to_owned(),
                message: "configuration is valid".to_owned(),
                path: None,
                help: None,
            }],
            normalized_config: Some(request.desired),
        })
    }
}

fn request() -> ValidateRequest {
    ValidateRequest {
        context: OperationContext {
            operation_id: "op-test".to_owned(),
            environment_id: "env-test".to_owned(),
            profile: "preview".to_owned(),
            ..OperationContext::default()
        },
        desired: json!({"answer": 42}),
    }
}

#[test]
fn manifest_without_features_remains_compatible() {
    let mut value =
        serde_json::to_value(TestHandler::current().manifest()).expect("manifest should serialize");
    value
        .as_object_mut()
        .expect("manifest should be an object")
        .remove("features");

    let manifest: PluginManifest =
        serde_json::from_value(value).expect("older manifest should deserialize");

    assert!(manifest.features.is_empty());
}

#[test]
fn default_request_timeout_is_the_fallback_for_short_protocol_calls() {
    assert_eq!(
        ClientOptions::default().request_timeout,
        Duration::from_secs(125 * 60)
    );
}

#[test]
fn operation_timeout_uses_exact_units_and_configured_phase_budgets() {
    let context = OperationContext {
        config: json!({
            "command_timeout_seconds": 3_600,
            "readiness_timeout_seconds": 3_000,
        }),
        ..OperationContext::default()
    };

    assert_eq!(
        operation_request_timeout(&context, 3),
        Duration::from_secs((3_600 + 3_000) * 3 + 300)
    );
}

#[test]
fn operation_timeout_saturates_at_the_explicit_request_ceiling() {
    let context = OperationContext {
        config: json!({
            "command_timeout_seconds": u64::MAX,
            "readiness_timeout_seconds": u64::MAX,
        }),
        ..OperationContext::default()
    };

    assert_eq!(
        operation_request_timeout(&context, usize::MAX),
        MAX_OPERATION_REQUEST_TIMEOUT
    );
}

fn connected(
    handler: TestHandler,
    timeout: Duration,
) -> (
    lightrail_plugin_protocol::PluginClient,
    tokio::task::JoinHandle<Result<(), lightrail_plugin_protocol::ServeError>>,
) {
    let (client_stream, server_stream) = duplex(64 * 1024);
    let (client_reader, client_writer) = split(client_stream);
    let (server_reader, server_writer) = split(server_stream);
    let client = lightrail_plugin_protocol::PluginClient::connect_io(
        client_reader,
        client_writer,
        ClientOptions {
            request_timeout: timeout,
            shutdown_timeout: timeout,
            event_buffer: 16,
        },
    );
    let server = tokio::spawn(serve(server_reader, server_writer, handler));
    (client, server)
}

#[tokio::test]
async fn request_response_and_notification_round_trip() {
    let (client, server) = connected(TestHandler::current(), Duration::from_secs(1));
    let mut events = client.subscribe();

    let initialized = client
        .initialize(InitializeRequest::current("0.1.0"))
        .await
        .expect("protocol should negotiate");
    assert_eq!(initialized.manifest.id, "io.lightrail.test");
    assert!(initialized.manifest.features.is_empty());

    let result = client
        .validate(request())
        .await
        .expect("validation succeeds");
    assert!(result.valid);
    assert_eq!(result.normalized_config, Some(json!({"answer": 42})));

    let event = events.recv().await.expect("progress should be delivered");
    assert!(matches!(
        event,
        ClientEvent::Plugin(PluginEvent::Progress {
            operation_id,
            message,
            completed: Some(1),
            total: Some(1),
        }) if operation_id == "op-test" && message == "validating"
    ));

    client.shutdown().await.expect("shutdown should succeed");
    server
        .await
        .expect("server task should join")
        .expect("serve");
}

#[tokio::test]
async fn concurrent_responses_are_correlated_by_id() {
    let (client, server) = connected(TestHandler::current(), Duration::from_secs(1));
    let mut slow = request();
    slow.desired = json!({"name": "slow", "delay_ms": 60});
    let mut fast = request();
    fast.desired = json!({"name": "fast", "delay_ms": 1});

    let (slow_result, fast_result) = tokio::join!(client.validate(slow), client.validate(fast));
    assert_eq!(
        slow_result.expect("slow response").normalized_config,
        Some(json!({"name": "slow", "delay_ms": 60}))
    );
    assert_eq!(
        fast_result.expect("fast response").normalized_config,
        Some(json!({"name": "fast", "delay_ms": 1}))
    );

    client.shutdown().await.expect("shutdown should succeed");
    server
        .await
        .expect("server task should join")
        .expect("serve");
}

#[tokio::test]
async fn incompatible_protocol_is_rejected() {
    let handler = TestHandler {
        delay: Duration::ZERO,
        protocol: ProtocolVersion::new(2, 0, 0),
    };
    let (client, server) = connected(handler, Duration::from_secs(1));

    let error = client
        .initialize(InitializeRequest::current("0.1.0"))
        .await
        .expect_err("major mismatch must fail");
    assert!(
        matches!(
            error,
            ClientError::ProtocolMismatch {
                requested: ProtocolVersion {
                    major: 1,
                    minor: 0,
                    patch: 0,
                },
                selected: ProtocolVersion {
                    major: 2,
                    minor: 0,
                    patch: 0,
                },
            }
        ),
        "unexpected error: {error:?}"
    );

    client.shutdown().await.expect("shutdown should succeed");
    server
        .await
        .expect("server task should join")
        .expect("serve");
}

#[tokio::test]
async fn timeout_cancels_the_rpc_request() {
    let handler = TestHandler {
        delay: Duration::from_millis(250),
        ..TestHandler::current()
    };
    let (client, server) = connected(handler, Duration::from_millis(30));
    let error = client
        .validate_with_timeout(request(), Duration::from_millis(30))
        .await
        .expect_err("slow response must time out");
    assert!(matches!(error, ClientError::Timeout { .. }));
    assert!(error.is_retryable());

    client.shutdown().await.expect("shutdown should succeed");
    server
        .await
        .expect("server task should join")
        .expect("serve");
}

#[tokio::test]
async fn call_specific_timeout_sends_the_standard_cancellation_notification() {
    let (client_stream, plugin_stream) = duplex(16 * 1024);
    let (client_reader, client_writer) = split(client_stream);
    let (plugin_reader, plugin_writer) = split(plugin_stream);
    let client = lightrail_plugin_protocol::PluginClient::connect_io(
        client_reader,
        client_writer,
        ClientOptions {
            request_timeout: Duration::from_secs(1),
            ..ClientOptions::default()
        },
    );

    let fake_plugin = tokio::spawn(async move {
        let mut reader = BufReader::new(plugin_reader);
        let mut request_line = String::new();
        reader
            .read_line(&mut request_line)
            .await
            .expect("read request");
        let request: serde_json::Value = serde_json::from_str(&request_line).expect("request JSON");

        let mut cancellation_line = String::new();
        reader
            .read_line(&mut cancellation_line)
            .await
            .expect("read cancellation");
        let cancellation: serde_json::Value =
            serde_json::from_str(&cancellation_line).expect("cancellation JSON");
        assert_eq!(cancellation["method"], "$/cancelRequest");
        assert_eq!(cancellation["params"]["id"], request["id"]);
        drop(plugin_writer);
    });

    let timeout = Duration::from_millis(30);
    let error = client
        .request_with_timeout::<_, Empty>("test.slow", &Empty {}, timeout)
        .await
        .expect_err("unanswered request must time out");
    assert!(matches!(
        error,
        ClientError::Timeout {
            timeout: actual,
            ..
        } if actual == timeout
    ));
    fake_plugin.await.expect("fake plugin joins");
}

#[tokio::test]
async fn malformed_stdout_is_a_terminal_protocol_error() {
    let (client_stream, plugin_stream) = duplex(16 * 1024);
    let (client_reader, client_writer) = split(client_stream);
    let (plugin_reader, mut plugin_writer) = split(plugin_stream);
    let client = lightrail_plugin_protocol::PluginClient::connect_io(
        client_reader,
        client_writer,
        ClientOptions {
            request_timeout: Duration::from_secs(1),
            ..ClientOptions::default()
        },
    );

    let fake_plugin = tokio::spawn(async move {
        let mut reader = BufReader::new(plugin_reader);
        let mut request_line = String::new();
        reader
            .read_line(&mut request_line)
            .await
            .expect("read request");
        assert!(request_line.contains("\"plugin.shutdown\""));
        plugin_writer
            .write_all(b"this-is-not-json\n")
            .await
            .expect("write malformed response");
    });

    let error = client
        .request::<_, Empty>("plugin.shutdown", &Empty {})
        .await
        .expect_err("malformed output must fail");
    assert!(matches!(error, ClientError::Protocol(_)));
    fake_plugin.await.expect("fake plugin joins");
}

#[test]
fn secrets_are_redacted_from_rust_diagnostics() {
    let secret = SecretValue::new("super-secret-token");
    assert_eq!(secret.expose_secret(), "super-secret-token");
    assert_eq!(secret.to_string(), "[REDACTED]");
    assert!(!format!("{secret:?}").contains("super-secret-token"));

    let context = OperationContext {
        secrets: [("token".to_owned(), secret)].into_iter().collect(),
        ..OperationContext::default()
    };
    assert!(!format!("{context:?}").contains("super-secret-token"));
    assert_eq!(
        serde_json::to_value(context).expect("serialize")["secrets"]["token"],
        "super-secret-token"
    );
}
