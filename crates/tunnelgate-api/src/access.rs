use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::{CustomResource, KubeSchema};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::common::{CloudflareRef, DURATION_CEL, ObjectRef, impl_has_conditions};

/// A reusable Cloudflare Access policy (account level).
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, KubeSchema)]
#[kube(
    group = "tunnelgate.geeko.me",
    version = "v1alpha1",
    kind = "AccessPolicy",
    namespaced,
    status = "AccessPolicyStatus",
    shortname = "apol",
    category = "tunnelgate",
    printcolumn(name = "Decision", type_ = "string", json_path = ".spec.decision"),
    printcolumn(name = "Policy ID", type_ = "string", json_path = ".status.policyId"),
    printcolumn(name = "Ready", type_ = "string", json_path = ".status.conditions[?(@.type==\"Ready\")].status"),
    printcolumn(name = "Age", type_ = "date", json_path = ".metadata.creationTimestamp"),
    doc = "A reusable Cloudflare Access policy."
)]
#[serde(rename_all = "camelCase")]
pub struct AccessPolicySpec {
    pub cloudflare: CloudflareRef,
    /// Name shown in Cloudflare (an ownership suffix is appended). Defaults to `<namespace>/<name>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub decision: AccessDecision,
    /// Any of these rules must match.
    #[x_kube(validation = Rule::new("size(self) > 0").message("include needs at least one rule"))]
    pub include: Vec<AccessRule>,
    /// All of these rules must match.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub require: Vec<AccessRule>,
    /// None of these rules may match.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<AccessRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[x_kube(validation = DURATION_CEL)]
    pub session_duration: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AccessDecision {
    Allow,
    Deny,
    Bypass,
    NonIdentity,
}

impl AccessDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Bypass => "bypass",
            Self::NonIdentity => "non_identity",
        }
    }
}

/// One Access rule group. Each set field expands to one or more Cloudflare rules; a list item
/// normally sets a single field.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AccessRule {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub emails: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub email_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub everyone: bool,
    /// CIDRs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_ranges: Vec<String>,
    /// `AccessServiceToken` resources.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service_tokens: Vec<ObjectRef>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub any_valid_service_token: bool,
    /// Access group IDs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    /// Identity provider IDs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub login_methods: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AccessPolicyStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

impl_has_conditions!(AccessPolicyStatus);

/// A `self_hosted` Cloudflare Access application covering one or more destinations.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, KubeSchema)]
#[kube(
    group = "tunnelgate.geeko.me",
    version = "v1alpha1",
    kind = "AccessApplication",
    namespaced,
    status = "AccessApplicationStatus",
    shortname = "aapp",
    category = "tunnelgate",
    printcolumn(name = "App ID", type_ = "string", json_path = ".status.applicationId"),
    printcolumn(name = "Ready", type_ = "string", json_path = ".status.conditions[?(@.type==\"Ready\")].status"),
    printcolumn(name = "Age", type_ = "date", json_path = ".metadata.creationTimestamp"),
    doc = "A self-hosted Cloudflare Access application for hostnames or host/path destinations."
)]
#[serde(rename_all = "camelCase")]
pub struct AccessApplicationSpec {
    pub cloudflare: CloudflareRef,
    /// Name shown in Cloudflare (an ownership suffix is appended). Defaults to `<namespace>/<name>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `host` or `host/path` destinations.
    #[x_kube(validation = Rule::new("size(self) > 0").message("at least one destination is required"))]
    pub destinations: Vec<String>,
    /// Reusable `AccessPolicy` resources, in precedence order.
    #[serde(default)]
    pub policies: Vec<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[x_kube(validation = DURATION_CEL)]
    pub session_duration: Option<String>,
    /// Identity provider IDs; empty means all configured.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_idps: Vec<String>,
    #[serde(default)]
    pub app_launcher_visible: bool,
    /// Passthrough for less common Cloudflare application fields (camelCase or snake_case).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::schema::preserve_unknown_object")]
    pub options: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AccessApplicationStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    /// Application audience tag (for validating Access JWTs at the origin).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

impl_has_conditions!(AccessApplicationStatus);

/// A Cloudflare Access service token; the credentials are written to a Secret.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, KubeSchema)]
#[kube(
    group = "tunnelgate.geeko.me",
    version = "v1alpha1",
    kind = "AccessServiceToken",
    namespaced,
    status = "AccessServiceTokenStatus",
    shortname = "ast",
    category = "tunnelgate",
    printcolumn(name = "Secret", type_ = "string", json_path = ".spec.secretName"),
    printcolumn(name = "Expires", type_ = "string", json_path = ".status.expiresAt"),
    printcolumn(name = "Ready", type_ = "string", json_path = ".status.conditions[?(@.type==\"Ready\")].status"),
    doc = "A Cloudflare Access service token whose credentials are kept in a Secret."
)]
#[serde(rename_all = "camelCase")]
pub struct AccessServiceTokenSpec {
    pub cloudflare: CloudflareRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Default `8760h`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[x_kube(validation = DURATION_CEL)]
    pub duration: Option<String>,
    /// Secret receiving `CF-Access-Client-Id` and `CF-Access-Client-Secret`.
    pub secret_name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AccessServiceTokenStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

impl_has_conditions!(AccessServiceTokenStatus);
