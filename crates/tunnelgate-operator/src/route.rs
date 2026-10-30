//! TunnelRoute controller. While a route's Tunnel exists, the Tunnel controller owns the route's
//! status and finalizer; this controller only handles routes whose Tunnel is missing.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use kube::api::Api;
use kube::runtime::controller::{Action, Controller};
use kube::runtime::reflector::ObjectRef;
use kube::runtime::watcher;
use kube::{Resource, ResourceExt};
use tracing::warn;
use tunnelgate_api::conditions::{reasons, types};
use tunnelgate_api::v1alpha1::{Tunnel, TunnelRoute};

use crate::conditions::{self, Cond};
use crate::context::Context;
use crate::error::{Error, Result};
use crate::tunnel::{patch_route_status, remove_route_finalizer};

pub async fn run(ctx: Arc<Context>) {
    let client = ctx.client.clone();
    let routes: Api<TunnelRoute> = Api::all(client.clone());
    let route_store = ctx.routes.clone();
    Controller::new(routes, watcher::Config::default())
        // A Tunnel going away (or appearing) changes who is responsible for its routes.
        .watches(Api::<Tunnel>::all(client), watcher::Config::default(), move |t| {
            let (ns, name) = (t.namespace().unwrap_or_default(), t.name_any());
            route_store
                .state()
                .into_iter()
                .filter(|r| {
                    let route_ns = r.namespace().unwrap_or_default();
                    r.spec.tunnel_ref.name == name && r.spec.tunnel_ref.namespace_or(&route_ns) == ns
                })
                .map(|r| ObjectRef::from_obj(&*r))
                .collect::<Vec<_>>()
        })
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|_| async {})
        .await;
}

fn error_policy(route: Arc<TunnelRoute>, error: &Error, _ctx: Arc<Context>) -> Action {
    warn!(route = %route.name_any(), namespace = ?route.namespace(), error = %error, "route reconcile failed");
    Action::requeue(Duration::from_secs(30))
}

pub async fn reconcile(route: Arc<TunnelRoute>, ctx: Arc<Context>) -> Result<Action> {
    let route_ns = route.namespace().unwrap_or_default();
    let tunnel_ns = route.spec.tunnel_ref.namespace_or(&route_ns).to_owned();
    let tunnels: Api<Tunnel> = Api::namespaced(ctx.client.clone(), &tunnel_ns);
    let tunnel = tunnels.get_opt(&route.spec.tunnel_ref.name).await?;
    if tunnel.as_ref().is_some_and(|t| t.meta().deletion_timestamp.is_none()) {
        return Ok(Action::await_change());
    }
    if tunnel.is_some() {
        // The tunnel's own cleanup releases its routes.
        return Ok(Action::requeue(Duration::from_secs(10)));
    }
    if route.meta().deletion_timestamp.is_some() {
        remove_route_finalizer(&ctx, &route).await?;
        return Ok(Action::await_change());
    }

    let generation = route.metadata.generation;
    let mut status = route.status.clone().unwrap_or_default();
    status.observed_generation = generation;
    status.tunnel_id = None;
    status.service = None;
    let msg = format!("Tunnel {tunnel_ns}/{} not found", route.spec.tunnel_ref.name);
    conditions::set_all_with_ready(
        &mut status.conditions,
        vec![
            Cond::fail(types::ACCEPTED, reasons::TUNNEL_NOT_FOUND, msg.clone()),
            Cond::fail(types::CONFIG_APPLIED, reasons::TUNNEL_NOT_FOUND, msg.clone()),
            Cond::fail(types::DNS_READY, reasons::TUNNEL_NOT_FOUND, msg),
        ],
        generation,
    );
    patch_route_status(&ctx, &route, &status).await?;
    Ok(Action::await_change())
}
