use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::KubeSchema;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Default Secret key holding the Cloudflare API token.
pub const DEFAULT_TOKEN_KEY: &str = "CLOUDFLARE_API_TOKEN";

/// Regex (CEL-compatible) for Go-style durations such as `30s`, `1h30m`, `8760h`.
pub(crate) const DURATION_CEL: &str = "self.matches('^([0-9]+(ms|s|m|h))+$')";

/// Which Cloudflare account to use and how to authenticate.
///
/// Either `accountRef` (a cluster-scoped `CloudflareAccount`) or an inline account
/// (`accountId` or `accountName`, plus `credentialsSecretRef`).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, KubeSchema)]
#[serde(rename_all = "camelCase")]
#[x_kube(
    validation = Rule::new("has(self.accountRef) != (has(self.accountId) || has(self.accountName))")
        .message("set either accountRef, or accountId/accountName with credentialsSecretRef"),
    validation = Rule::new("has(self.accountRef) || has(self.credentialsSecretRef)")
        .message("credentialsSecretRef is required with an inline accountId/accountName"),
)]
pub struct CloudflareRef {
    /// Name of a cluster-scoped `CloudflareAccount`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_ref: Option<String>,
    /// Cloudflare account ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    /// Cloudflare account name, looked up through the API (needs Account Settings: Read).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_name: Option<String>,
    /// Secret in the resource's namespace holding the API token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials_secret_ref: Option<SecretKeyRef>,
}

/// A key in a Secret in the same namespace as the referring resource.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretKeyRef {
    pub name: String,
    /// Key in the Secret's data; defaults depend on the field (`CLOUDFLARE_API_TOKEN`, `ca.crt`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

/// A reference to an object of a known kind, optionally in another namespace.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ObjectRef {
    pub name: String,
    /// Defaults to the referring resource's namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

impl ObjectRef {
    /// Namespace of the referent, defaulting to `default_ns`.
    pub fn namespace_or<'a>(&'a self, default_ns: &'a str) -> &'a str {
        self.namespace.as_deref().unwrap_or(default_ns)
    }
}

/// Status fields every tunnelgate resource has.
pub trait HasConditions {
    fn conditions(&self) -> &[Condition];
    fn observed_generation(&self) -> Option<i64>;
}

macro_rules! impl_has_conditions {
    ($($t:ty),*) => {$(
        impl $crate::common::HasConditions for $t {
            fn conditions(&self) -> &[k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition] {
                &self.conditions
            }
            fn observed_generation(&self) -> Option<i64> {
                self.observed_generation
            }
        }
    )*};
}
pub(crate) use impl_has_conditions;
