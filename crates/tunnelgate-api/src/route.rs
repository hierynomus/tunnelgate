use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::{CustomResource, KubeSchema};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::common::{DURATION_CEL, ObjectRef, impl_has_conditions};

/// One public hostname (and optionally a path) mapped to an origin.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, KubeSchema)]
#[kube(
    group = "tunnelgate.geeko.me",
    version = "v1alpha1",
    kind = "TunnelRoute",
    namespaced,
    status = "TunnelRouteStatus",
    shortname = "tr",
    category = "tunnelgate",
    printcolumn(name = "Hostname", type_ = "string", json_path = ".spec.hostname"),
    printcolumn(name = "Path", type_ = "string", json_path = ".spec.path"),
    printcolumn(name = "Tunnel", type_ = "string", json_path = ".spec.tunnelRef.name"),
    printcolumn(name = "Ready", type_ = "string", json_path = ".status.conditions[?(@.type==\"Ready\")].status"),
    printcolumn(name = "Age", type_ = "date", json_path = ".metadata.creationTimestamp"),
    doc = "A public hostname (and optional path) routed through a Tunnel to an origin."
)]
#[serde(rename_all = "camelCase")]
pub struct TunnelRouteSpec {
    /// The Tunnel to publish on. Another namespace needs a RouteGrant/ReferenceGrant there.
    pub tunnel_ref: ObjectRef,
    /// Public hostname; `*.example.com` for a wildcard.
    #[x_kube(validation = Rule::new(
        "self.matches('^(\\\\*\\\\.)?([a-z0-9]([-a-z0-9]*[a-z0-9])?\\\\.)+[a-z]{2,}$')"
    ).message("must be a lowercase DNS name, optionally starting with '*.'"))]
    pub hostname: String,
    /// Cloudflare ingress path (a regular expression matched against the request path).
    /// Empty means the whole host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub service: RouteService,
    /// Overrides for `Tunnel.spec.originDefaults`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<RouteOrigin>,
    #[serde(default)]
    pub dns: RouteDns,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<RouteAccess>,
}

/// Where requests go: exactly one of `backendRef`, `url` or `status`.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, KubeSchema)]
#[serde(rename_all = "camelCase")]
#[x_kube(validation = Rule::new(
    "[has(self.backendRef), has(self.url), has(self.status)].filter(x, x).size() == 1"
).message("set exactly one of backendRef, url or status"))]
pub struct RouteService {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_ref: Option<BackendRef>,
    /// Any URL cloudflared can reach, e.g. `https://192.0.2.10:443`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// A fixed HTTP status (`http_status:<code>`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 100, max = 599))]
    pub status: Option<u16>,
}

/// A Kubernetes Service port.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackendRef {
    pub name: String,
    /// Defaults to the route's namespace. Another namespace needs a grant there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[schemars(range(min = 1, max = 65535))]
    pub port: i32,
}

/// Per-route origin settings.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, KubeSchema)]
#[serde(rename_all = "camelCase")]
pub struct RouteOrigin {
    /// Scheme used for `backendRef` (default `http`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<OriginProtocol>,
    /// SNI and the name the origin certificate is verified against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_host_header: Option<String>,
    #[serde(default, rename = "noTLSVerify", skip_serializing_if = "Option::is_none")]
    pub no_tls_verify: Option<bool>,
    /// HTTP/2 to the origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http2: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[x_kube(validation = DURATION_CEL)]
    pub connect_timeout: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[x_kube(validation = DURATION_CEL)]
    pub keep_alive_timeout: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_happy_eyeballs: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_chunked_encoding: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum OriginProtocol {
    #[default]
    Http,
    Https,
}

impl OriginProtocol {
    pub fn scheme(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RouteDns {
    /// Create the proxied CNAME to the tunnel (default true).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Zone to create the record in. Default: the longest zone suffix the token can see.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    /// Take over an existing record that isn't marked as owned by this route.
    #[serde(default)]
    pub adopt: bool,
}

impl Default for RouteDns {
    fn default() -> Self {
        Self { enabled: true, zone: None, adopt: false }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RouteAccess {
    /// AccessApplications protecting this route; `AccessReady` reflects their readiness.
    #[serde(default)]
    pub application_refs: Vec<ObjectRef>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TunnelRouteStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Origin service rendered into the tunnel configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_record_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

impl_has_conditions!(TunnelRouteStatus);
