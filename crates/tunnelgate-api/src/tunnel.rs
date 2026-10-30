use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{ResourceRequirements, Toleration};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::{CustomResource, KubeSchema};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::common::{CloudflareRef, DURATION_CEL, SecretKeyRef, impl_has_conditions};

/// One Cloudflare Tunnel (remote-managed) and its in-cluster `cloudflared` connector.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, KubeSchema)]
#[kube(
    group = "tunnelgate.geeko.me",
    version = "v1alpha1",
    kind = "Tunnel",
    namespaced,
    status = "TunnelStatus",
    shortname = "tun",
    category = "tunnelgate",
    printcolumn(name = "Tunnel ID", type_ = "string", json_path = ".status.tunnelId"),
    printcolumn(name = "Connectors", type_ = "integer", json_path = ".status.connectors"),
    printcolumn(name = "Routes", type_ = "integer", json_path = ".status.routes"),
    printcolumn(name = "Ready", type_ = "string", json_path = ".status.conditions[?(@.type==\"Ready\")].status"),
    printcolumn(name = "Age", type_ = "date", json_path = ".metadata.creationTimestamp"),
    doc = "A remote-managed Cloudflare Tunnel and its cloudflared connector Deployment."
)]
#[serde(rename_all = "camelCase")]
pub struct TunnelSpec {
    pub cloudflare: CloudflareRef,
    /// Cloudflare tunnel name. Defaults to `<namespace>-<name>-<clusterId[:8]>`. Immutable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[x_kube(validation = Rule::new("self == oldSelf").message("name is immutable"))]
    pub name: Option<String>,
    #[serde(default)]
    pub connector: ConnectorSpec,
    /// Origin settings applied to every route unless the route overrides them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_defaults: Option<OriginDefaults>,
    /// What unmatched requests get. Defaults to `{status: 404}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<Fallback>,
    #[serde(default)]
    pub deletion_policy: DeletionPolicy,
    /// Take over an existing Cloudflare tunnel with this name that isn't recorded as ours
    /// (tunnels with the default name, which includes the cluster ID, are always taken over).
    #[serde(default)]
    pub adopt: bool,
}

/// The managed cloudflared Deployment.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConnectorSpec {
    /// Defaults to the operator's configured default (2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<i32>,
    /// Official `cloudflare/cloudflared` image, pinned tag or digest. Defaults to the operator's
    /// configured image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default)]
    pub protocol: ConnectorProtocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceRequirements>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub node_selector: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tolerations: Vec<Toleration>,
    /// Extra arguments passed to `cloudflared tunnel` before `run`, e.g. `--edge-ip-version=6`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_args: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ConnectorProtocol {
    #[default]
    Auto,
    Quic,
    Http2,
}

impl ConnectorProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Quic => "quic",
            Self::Http2 => "http2",
        }
    }
}

/// Tunnel-wide origin request defaults (Cloudflare `originRequest`).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, KubeSchema)]
#[serde(rename_all = "camelCase")]
pub struct OriginDefaults {
    #[serde(default, rename = "noTLSVerify", skip_serializing_if = "Option::is_none")]
    pub no_tls_verify: Option<bool>,
    /// Go-style duration, whole seconds (e.g. `30s`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[x_kube(validation = DURATION_CEL)]
    pub connect_timeout: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[x_kube(validation = DURATION_CEL)]
    pub tls_timeout: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[x_kube(validation = DURATION_CEL)]
    pub keep_alive_timeout: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_alive_connections: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http2_origin: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_happy_eyeballs: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_chunked_encoding: Option<bool>,
    /// CA bundle (PEM) used to verify origin certificates; mounted into the cloudflared pods.
    /// Key defaults to `ca.crt`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_pool_secret_ref: Option<SecretKeyRef>,
}

/// Rule for requests no route matches: a fixed status or a service URL.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, KubeSchema)]
#[serde(rename_all = "camelCase")]
#[x_kube(validation = Rule::new("has(self.status) != has(self.service)").message("set exactly one of status or service"))]
pub struct Fallback {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 100, max = 599))]
    pub status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
}

impl Default for Fallback {
    fn default() -> Self {
        Self { status: Some(404), service: None }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq, JsonSchema)]
pub enum DeletionPolicy {
    /// Delete the tunnel in Cloudflare when the resource is deleted.
    #[default]
    Delete,
    /// Keep the tunnel and its configuration in Cloudflare.
    Retain,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TunnelStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_name: Option<String>,
    /// Account the tunnel lives in (resolved from the spec).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    /// `<tunnelId>.cfargotunnel.com`, the target of route DNS records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cname: Option<String>,
    /// Active connector connections as reported by Cloudflare.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connectors: Option<i32>,
    /// Cloudflare's configuration version last applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_version: Option<i64>,
    /// Hash of the last applied rendered configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
    /// Zones in which this tunnel has DNS records (for cleanup).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_zone_ids: Vec<String>,
    /// Routes included in the applied configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routes: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

impl_has_conditions!(TunnelStatus);
