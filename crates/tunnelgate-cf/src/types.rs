//! Request and response types for the Cloudflare endpoints tunnelgate uses. Only the fields we
//! read or write are modelled; unknown fields are ignored on input.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Cloudflare's response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope<T> {
    pub success: bool,
    #[serde(default)]
    pub errors: Vec<ApiMessage>,
    #[serde(default)]
    pub messages: Vec<ApiMessage>,
    pub result: Option<T>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_info: Option<ResultInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiMessage {
    pub code: i64,
    pub message: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResultInfo {
    #[serde(default)]
    pub page: u32,
    #[serde(default)]
    pub per_page: u32,
    #[serde(default)]
    pub count: u32,
    #[serde(default)]
    pub total_count: u32,
    #[serde(default)]
    pub total_pages: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Zone {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<ZoneAccount>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneAccount {
    pub id: String,
    #[serde(default)]
    pub name: String,
}

// ---------------------------------------------------------------------------------------------
// Tunnels

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tunnel {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub deleted_at: Option<String>,
    /// `inactive`, `degraded`, `healthy` or `down`.
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub config_src: Option<String>,
    #[serde(default)]
    pub connections: Vec<TunnelConnection>,
}

impl Tunnel {
    /// Connections that are up (not waiting to reconnect).
    pub fn active_connections(&self) -> usize {
        self.connections.iter().filter(|c| !c.is_pending_reconnect).count()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelConnection {
    pub id: String,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub colo_name: Option<String>,
    #[serde(default)]
    pub is_pending_reconnect: bool,
    #[serde(default)]
    pub opened_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateTunnel<'a> {
    pub name: &'a str,
    /// Always `cloudflare` (remote-managed).
    pub config_src: &'a str,
}

/// Body of `PUT …/cfd_tunnel/{id}/configurations`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TunnelConfigurationBody {
    pub config: TunnelConfig,
}

/// A remote-managed tunnel configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TunnelConfig {
    pub ingress: Vec<IngressRule>,
    #[serde(rename = "originRequest", default, skip_serializing_if = "OriginRequest::is_empty")]
    pub origin_request: OriginRequest,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct IngressRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub service: String,
    #[serde(rename = "originRequest", default, skip_serializing_if = "OriginRequest::is_empty")]
    pub origin_request: OriginRequest,
}

/// cloudflared `originRequest` settings. Durations are whole seconds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OriginRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_timeout: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_alive_timeout: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_alive_connections: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_happy_eyeballs: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_host_header: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_server_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_pool: Option<String>,
    #[serde(rename = "noTLSVerify", default, skip_serializing_if = "Option::is_none")]
    pub no_tls_verify: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_chunked_encoding: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http2_origin: Option<bool>,
}

impl OriginRequest {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// Result of `GET`/`PUT …/configurations`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TunnelConfiguration {
    #[serde(default)]
    pub tunnel_id: Option<String>,
    #[serde(default)]
    pub version: i64,
    #[serde(default)]
    pub config: Option<TunnelConfig>,
    #[serde(default)]
    pub source: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// DNS

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecord {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub content: String,
    #[serde(default)]
    pub proxied: bool,
    #[serde(default)]
    pub ttl: u32,
    #[serde(default)]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecordInput {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub content: String,
    pub proxied: bool,
    /// 1 = automatic.
    pub ttl: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl DnsRecordInput {
    /// A proxied CNAME with automatic TTL.
    pub fn proxied_cname(name: &str, target: &str, comment: &str) -> Self {
        Self {
            name: name.to_owned(),
            record_type: "CNAME".to_owned(),
            content: target.to_owned(),
            proxied: true,
            ttl: 1,
            comment: Some(comment.to_owned()),
        }
    }

    /// Whether `record` already has these values.
    pub fn matches(&self, record: &DnsRecord) -> bool {
        record.name.eq_ignore_ascii_case(&self.name)
            && record.record_type == self.record_type
            && record.content.eq_ignore_ascii_case(&self.content)
            && record.proxied == self.proxied
            && record.comment == self.comment
    }
}

#[derive(Debug, Clone, Default)]
pub struct DnsRecordFilter {
    pub name: Option<String>,
    pub record_type: Option<String>,
    pub comment_startswith: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// Access

/// A reusable Access policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessPolicy {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    pub name: String,
    pub decision: String,
    pub include: Vec<Value>,
    #[serde(default)]
    pub require: Vec<Value>,
    #[serde(default)]
    pub exclude: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_duration: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessApplication {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    pub name: String,
    #[serde(rename = "type")]
    pub app_type: String,
    /// Primary destination (Cloudflare still requires `domain` for self-hosted apps).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destinations: Vec<AccessDestination>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<AppPolicyRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_duration: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_idps: Vec<String>,
    #[serde(default)]
    pub app_launcher_visible: bool,
    /// Less common fields, passed through.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessDestination {
    #[serde(rename = "type")]
    pub destination_type: String,
    pub uri: String,
}

/// A reusable policy attached to an application. Responses carry the full policy; we only keep
/// what identifies the attachment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppPolicyRef {
    pub id: String,
    pub precedence: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceToken {
    pub id: String,
    pub name: String,
    pub client_id: String,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub duration: Option<String>,
}

/// The create response; the only time Cloudflare returns the client secret.
#[derive(Debug, Clone, Deserialize)]
pub struct CreatedServiceToken {
    #[serde(flatten)]
    pub token: ServiceToken,
    pub client_secret: secrecy::SecretString,
}
