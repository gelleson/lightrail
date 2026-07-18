use serde::{Deserialize, Serialize};
use serde_json::Value;

/// JSON-RPC request/response correlation ID.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(untagged)]
pub enum RequestId {
    /// Core-generated numeric ID.
    Number(u64),
    /// Language-neutral caller-supplied ID.
    String(String),
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Number(value) => value.fmt(formatter),
            Self::String(value) => value.fmt(formatter),
        }
    }
}

/// JSON-RPC 2.0 error object.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JsonRpcError {
    /// Standard or implementation-defined code.
    pub code: i64,
    /// Human-readable description.
    pub message: String,
    /// Optional structured data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Debug, Serialize)]
pub(crate) struct RpcRequest<'a, P> {
    pub jsonrpc: &'static str,
    pub id: &'a RequestId,
    pub method: &'a str,
    pub params: &'a P,
}

#[derive(Debug, Serialize)]
pub(crate) struct RpcNotification<'a, P> {
    pub jsonrpc: &'static str,
    pub method: &'a str,
    pub params: &'a P,
}

#[derive(Debug, Deserialize)]
pub(crate) struct IncomingMessage {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<Value>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub params: Option<Value>,
    #[serde(default)]
    pub result: Option<Value>,
    #[serde(default)]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SuccessResponse<'a> {
    pub jsonrpc: &'static str,
    pub id: &'a Value,
    pub result: Value,
}

#[derive(Debug, Serialize)]
pub(crate) struct ErrorResponse<'a> {
    pub jsonrpc: &'static str,
    pub id: &'a Value,
    pub error: JsonRpcError,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct CancelRpcRequest {
    pub id: RequestId,
}
