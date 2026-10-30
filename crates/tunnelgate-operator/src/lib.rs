//! tunnelgate controllers. The binary (`main.rs`) wires them up; tests run them in-process
//! against a k3d cluster and the fake Cloudflare API.

pub mod access;
pub mod account;
pub mod conditions;
pub mod context;
pub mod error;
pub mod gateway;
pub mod grants;
pub mod leader;
pub mod route;
pub mod tunnel;

use std::sync::Arc;

use k8s_openapi::api::core::v1::Namespace;
use kube::api::Api;
use kube::runtime::reflector;

use crate::context::{CloudflareFactory, Context, Settings};

/// The cluster ID: UID of the `kube-system` namespace (stable for the cluster's lifetime).
pub async fn cluster_id(client: &kube::Client) -> anyhow::Result<String> {
    let ns = Api::<Namespace>::all(client.clone()).get("kube-system").await?;
    ns.metadata.uid.ok_or_else(|| anyhow::anyhow!("kube-system namespace has no uid"))
}

/// Whether Gateway API's ReferenceGrant is served at `v1beta1` (the version we read). Not the
/// group's preferred version: that is `v1` since Gateway API v1.0, which has no ReferenceGrant.
pub async fn has_reference_grants(client: &kube::Client) -> bool {
    match kube::discovery::group(client, "gateway.networking.k8s.io").await {
        Ok(group) => group.versioned_resources("v1beta1").iter().any(|(ar, _)| ar.kind == "ReferenceGrant"),
        Err(_) => false,
    }
}

/// Runs all controllers until shutdown.
pub async fn run(
    client: kube::Client,
    settings: Settings,
    cluster_id: String,
    cloudflare: Arc<dyn CloudflareFactory>,
) -> anyhow::Result<()> {
    let reference_grants = has_reference_grants(&client).await;
    tracing::info!(%cluster_id, reference_grants, "starting controllers");
    let (routes, routes_writer) = reflector::store();
    let ctx = Arc::new(Context::new(client, settings, cluster_id, reference_grants, routes, cloudflare));
    tokio::join!(
        tunnel::run(ctx.clone(), routes_writer),
        route::run(ctx.clone()),
        access::policy::run(ctx.clone()),
        access::application::run(ctx.clone()),
        access::token::run(ctx.clone()),
        account::run(ctx.clone()),
        gateway::run(ctx),
    );
    Ok(())
}
