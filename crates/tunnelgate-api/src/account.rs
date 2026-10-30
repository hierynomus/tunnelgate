use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::{CustomResource, KubeSchema};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::common::impl_has_conditions;

/// A Cloudflare account and its credentials, usable from other resources via
/// `cloudflare.accountRef`.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, KubeSchema)]
#[kube(
    group = "tunnelgate.geeko.me",
    version = "v1alpha1",
    kind = "CloudflareAccount",
    status = "CloudflareAccountStatus",
    shortname = "cfa",
    category = "tunnelgate",
    printcolumn(name = "Account ID", type_ = "string", json_path = ".status.accountId"),
    printcolumn(name = "Ready", type_ = "string", json_path = ".status.conditions[?(@.type==\"Ready\")].status"),
    doc = "Cluster-scoped Cloudflare account credentials shared by namespaced resources."
)]
#[serde(rename_all = "camelCase")]
#[x_kube(validation = Rule::new("has(self.accountId) != has(self.accountName)").message("set exactly one of accountId or accountName"))]
pub struct CloudflareAccountSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_name: Option<String>,
    pub credentials_secret_ref: NamespacedSecretKeyRef,
    /// Namespaces whose resources may use this account; `*` allows all. Default: only the
    /// credentials Secret's namespace.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_namespaces: Vec<String>,
}

impl CloudflareAccountSpec {
    pub fn allows_namespace(&self, ns: &str) -> bool {
        if self.allowed_namespaces.is_empty() {
            return self.credentials_secret_ref.namespace == ns;
        }
        self.allowed_namespaces.iter().any(|a| a == "*" || a == ns)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NamespacedSecretKeyRef {
    pub name: String,
    pub namespace: String,
    /// Defaults to `CLOUDFLARE_API_TOKEN`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CloudflareAccountStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

impl_has_conditions!(CloudflareAccountStatus);
