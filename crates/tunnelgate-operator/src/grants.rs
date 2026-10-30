//! Cross-namespace reference checks: Gateway API `ReferenceGrant` when installed, and the
//! operator's own `RouteGrant`.

use std::collections::HashMap;

use kube::api::{Api, ApiResource, DynamicObject, GroupVersionKind, ListParams};
use tunnelgate_api::v1alpha1::{RouteGrant, RouteGrantSpec, grants_permit};

use crate::context::Context;
use crate::error::Result;

/// Caches grants per namespace for one reconcile pass.
#[derive(Default)]
pub struct Grants {
    by_ns: HashMap<String, Vec<RouteGrantSpec>>,
}

pub fn reference_grant_resource() -> ApiResource {
    ApiResource::from_gvk(&GroupVersionKind::gvk("gateway.networking.k8s.io", "v1beta1", "ReferenceGrant"))
}

impl Grants {
    /// Whether an object `from` = (group, kind, namespace) may reference `to` = (group, kind,
    /// name) in namespace `to_ns`. Same-namespace references are always allowed.
    pub async fn permits(
        &mut self,
        ctx: &Context,
        from: (&str, &str, &str),
        to_ns: &str,
        to: (&str, &str, &str),
    ) -> Result<bool> {
        if from.2 == to_ns {
            return Ok(true);
        }
        if !self.by_ns.contains_key(to_ns) {
            let mut specs: Vec<RouteGrantSpec> = Api::<RouteGrant>::namespaced(ctx.client.clone(), to_ns)
                .list(&ListParams::default())
                .await?
                .into_iter()
                .map(|g| g.spec)
                .collect();
            if ctx.reference_grants() {
                let api: Api<DynamicObject> =
                    Api::namespaced_with(ctx.client.clone(), to_ns, &reference_grant_resource());
                for g in api.list(&ListParams::default()).await? {
                    if let Some(spec) = g.data.get("spec").cloned().and_then(|s| serde_json::from_value(s).ok()) {
                        specs.push(spec);
                    }
                }
            }
            self.by_ns.insert(to_ns.to_owned(), specs);
        }
        Ok(grants_permit(&self.by_ns[to_ns], from, to))
    }
}
