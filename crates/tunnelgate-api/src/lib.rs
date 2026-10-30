//! Custom resource types for `tunnelgate.geeko.me/v1alpha1`.
//!
//! The CRD YAML in `charts/tunnelgate/crds/` is generated from these types (`tunnelgate crdgen`);
//! never edit it by hand.

// kube's `printcolumn(...)` repeats `type_ = "string"`, which this lint misreads.
#![allow(clippy::duplicated_attributes)]

pub mod conditions;
mod schema;

pub mod v1alpha1 {
    pub use crate::access::*;
    pub use crate::account::*;
    pub use crate::common::*;
    pub use crate::grant::*;
    pub use crate::route::*;
    pub use crate::tunnel::*;
}

mod access;
mod account;
mod common;
mod grant;
mod route;
mod tunnel;

pub use common::HasConditions;

/// API group of all tunnelgate resources.
pub const GROUP: &str = "tunnelgate.geeko.me";
/// Prefix for tunnelgate labels, annotations and finalizers.
pub const DOMAIN: &str = "tunnelgate.geeko.me";

/// All CRDs, in a stable order.
pub fn crds() -> Vec<k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition> {
    use kube::CustomResourceExt;
    use v1alpha1::*;
    vec![
        CloudflareAccount::crd(),
        Tunnel::crd(),
        TunnelRoute::crd(),
        AccessPolicy::crd(),
        AccessApplication::crd(),
        AccessServiceToken::crd(),
        RouteGrant::crd(),
    ]
}

#[cfg(test)]
mod tests {
    #[test]
    fn crd_schemas() {
        for crd in super::crds() {
            insta::with_settings!({ prepend_module_to_snapshot => false }, {
                insta::assert_yaml_snapshot!(format!("crd-{}", crd.spec.names.kind), crd);
            });
        }
    }
}
