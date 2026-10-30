//! Tunnel controller: the Cloudflare tunnel, its connector, and the aggregation of all
//! TunnelRoutes that reference it into one remote configuration plus DNS records.
//!
//! This controller is the single writer of route status while the route's tunnel exists; the
//! TunnelRoute controller only reports routes whose tunnel is missing.

pub mod connector;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Secret, Service};
use k8s_openapi::api::policy::v1::PodDisruptionBudget;
use kube::api::{Api, DeleteParams, DynamicObject, Patch, PatchParams};
use kube::core::PartialObjectMeta;
use kube::runtime::controller::{Action, Controller};
use kube::runtime::finalizer::{Event, finalizer};
use kube::runtime::reflector;
use kube::runtime::reflector::{ObjectRef, store::Writer};
use kube::runtime::{WatchStreamExt, watcher};
use kube::{Resource, ResourceExt};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use tunnelgate_api::conditions::{reasons, types};
use tunnelgate_api::v1alpha1::{
    AccessApplication, DeletionPolicy, RouteGrant, Tunnel, TunnelRoute, TunnelRouteStatus, TunnelStatus,
};
use tunnelgate_api::{DOMAIN, GROUP};
use tunnelgate_cf::types::{DnsRecord, DnsRecordFilter, Zone};
use tunnelgate_render::dns::{self, DesiredRecord, DnsAction, HostOutcome};
use tunnelgate_render::ingress::{self, Rejection, RouteKey};
use tunnelgate_render::marker::{OwnerMarker, default_tunnel_name, is_default_tunnel_name};

use crate::conditions::{self, Cond};
use crate::context::{Account, Context};
use crate::error::{Error, Result};
use crate::grants::{Grants, reference_grant_resource};

pub const FINALIZER: &str = "tunnelgate.geeko.me/cleanup";
/// Added to every route of an existing tunnel, so its DNS record and config entry are removed
/// before the route goes.
pub const ROUTE_FINALIZER: &str = "tunnelgate.geeko.me/route";
const FIELD_MANAGER: &str = "tunnelgate";

/// Annotation that skips Cloudflare cleanup on deletion (leftovers are found by `sweep`).
pub fn skip_cleanup_annotation() -> String {
    format!("{DOMAIN}/skip-cloudflare-cleanup")
}

/// Runs the controller. `routes` is the writer of `ctx.routes`: the route watch that triggers
/// tunnel reconciles also fills the store, so a reconcile never sees an older route than the
/// event that triggered it.
pub async fn run(ctx: Arc<Context>, routes: Writer<TunnelRoute>) {
    let client = ctx.client.clone();
    let tunnels: Api<Tunnel> = Api::all(client.clone());
    let controller = Controller::new(tunnels, watcher::Config::default().any_semantic());
    let tunnel_store = controller.store();

    let managed = watcher::Config::default().labels("app.kubernetes.io/managed-by=tunnelgate");
    let route_watch = reflector(routes, watcher(Api::<TunnelRoute>::all(client.clone()), watcher::Config::default()))
        .touched_objects()
        .predicate_filter(kube::runtime::predicates::generation, Default::default());

    let routes_for_services = ctx.routes.clone();
    let routes_for_apps = ctx.routes.clone();
    let tunnels_for_secrets = tunnel_store.clone();
    let tunnels_for_grants = tunnel_store.clone();
    let tunnels_for_reference_grants = tunnel_store.clone();
    // ReferenceGrants count once their CRD is served, which may be after startup.
    let reference_grant_watch = {
        let (ctx, client) = (ctx.clone(), client.clone());
        futures::stream::once(async move {
            while !crate::has_reference_grants(&client).await {
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
            if !ctx.reference_grants() {
                info!("ReferenceGrant CRD found; honouring ReferenceGrants");
                ctx.set_reference_grants(true);
            }
            client
        })
        .flat_map(|client| {
            watcher(Api::<DynamicObject>::all_with(client, &reference_grant_resource()), watcher::Config::default())
                .touched_objects()
        })
    };

    controller
        .owns(Api::<Deployment>::all(client.clone()), managed.clone())
        .owns(Api::<Secret>::all(client.clone()), managed)
        .watches_stream(route_watch, |route: TunnelRoute| Some(tunnel_ref_of(&route)))
        .watches_stream(
            watcher(Api::<PartialObjectMeta<Service>>::all(client.clone()), watcher::Config::default())
                .touched_objects(),
            move |svc: PartialObjectMeta<Service>| {
                let (ns, name) = (svc.namespace().unwrap_or_default(), svc.name_any());
                routes_for_services
                    .state()
                    .into_iter()
                    .filter(|r| {
                        r.spec.service.backend_ref.as_ref().is_some_and(|b| {
                            b.name == name && b.namespace.as_deref().unwrap_or(&r.namespace().unwrap_or_default()) == ns
                        })
                    })
                    .map(|r| tunnel_ref_of(&r))
                    .collect::<Vec<_>>()
            },
        )
        .watches_stream(
            watcher(Api::<PartialObjectMeta<Secret>>::all(client.clone()), watcher::Config::default())
                .touched_objects(),
            move |secret: PartialObjectMeta<Secret>| {
                let (ns, name) = (secret.namespace().unwrap_or_default(), secret.name_any());
                tunnels_for_secrets
                    .state()
                    .into_iter()
                    .filter(|t| t.namespace().as_deref() == Some(ns.as_str()))
                    .filter(|t| {
                        let ca = t.spec.origin_defaults.as_ref().and_then(|o| o.ca_pool_secret_ref.as_ref());
                        let creds = t.spec.cloudflare.credentials_secret_ref.as_ref();
                        ca.is_some_and(|r| r.name == name) || creds.is_some_and(|r| r.name == name)
                    })
                    .map(|t| ObjectRef::from_obj(&*t))
                    .collect::<Vec<_>>()
            },
        )
        .watches(Api::<AccessApplication>::all(client.clone()), watcher::Config::default(), move |app| {
            let (ns, name) = (app.namespace().unwrap_or_default(), app.name_any());
            routes_for_apps
                .state()
                .into_iter()
                .filter(|r| {
                    let route_ns = r.namespace().unwrap_or_default();
                    r.spec
                        .access
                        .iter()
                        .flat_map(|a| &a.application_refs)
                        .any(|a| a.name == name && a.namespace_or(&route_ns) == ns)
                })
                .map(|r| tunnel_ref_of(&r))
                .collect::<Vec<_>>()
        })
        .watches(Api::<RouteGrant>::all(client.clone()), watcher::Config::default(), move |_| {
            tunnels_for_grants.state().iter().map(|t| ObjectRef::from_obj(&**t)).collect::<Vec<_>>()
        })
        .watches_stream_with(
            reference_grant_watch,
            move |_| tunnels_for_reference_grants.state().iter().map(|t| ObjectRef::from_obj(&**t)).collect::<Vec<_>>(),
            reference_grant_resource(),
        )
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            if let Err(e) = res {
                tracing::debug!(error = %e, "tunnel reconcile failed");
            }
        })
        .await;
}

fn tunnel_ref_of(route: &TunnelRoute) -> ObjectRef<Tunnel> {
    let ns = route.namespace().unwrap_or_default();
    ObjectRef::new(&route.spec.tunnel_ref.name).within(route.spec.tunnel_ref.namespace_or(&ns))
}

/// Routes (from the shared store) that reference `tunnel`.
pub fn routes_for(ctx: &Context, tunnel: &Tunnel) -> Vec<Arc<TunnelRoute>> {
    let (ns, name) = (tunnel.namespace().unwrap_or_default(), tunnel.name_any());
    let mut routes: Vec<_> = ctx
        .routes
        .state()
        .into_iter()
        .filter(|r| {
            let route_ns = r.namespace().unwrap_or_default();
            r.spec.tunnel_ref.name == name && r.spec.tunnel_ref.namespace_or(&route_ns) == ns
        })
        .collect();
    routes.sort_by_key(|r| (r.namespace(), r.name_any()));
    routes
}

pub fn error_policy(tunnel: Arc<Tunnel>, error: &Error, _ctx: Arc<Context>) -> Action {
    match error {
        Error::Pending(msg) => {
            info!(tunnel = %tunnel.name_any(), "{msg}");
            Action::requeue(Duration::from_secs(5))
        }
        _ => {
            warn!(tunnel = %tunnel.name_any(), namespace = ?tunnel.namespace(), error = %error, "reconcile failed");
            Action::requeue(Duration::from_secs(30))
        }
    }
}

pub async fn reconcile(tunnel: Arc<Tunnel>, ctx: Arc<Context>) -> Result<Action> {
    // Right after a start the route store may not have its first list yet. A reconcile that saw
    // no routes would take every hostname out of the tunnel configuration and DNS until it had.
    if tokio::time::timeout(Duration::from_secs(10), ctx.routes.wait_until_ready()).await.is_err() {
        return Err(Error::Pending("waiting for the TunnelRoute watch to list".into()));
    }
    let ns = tunnel.namespace().unwrap_or_default();
    let api: Api<Tunnel> = Api::namespaced(ctx.client.clone(), &ns);
    finalizer(&api, FINALIZER, tunnel, |event| async {
        match event {
            Event::Apply(t) => apply(&t, &ctx).await,
            Event::Cleanup(t) => cleanup(&t, &ctx).await,
        }
    })
    .await
    .or_else(crate::error::finalizer_result)
}

/// What happened to the tunnel itself, for route statuses.
struct TunnelOutcome {
    /// Set when the tunnel isn't usable yet; routes report it.
    blocked: Option<Cond>,
    connected: bool,
    config: Result<(), Cond>,
}

async fn apply(t: &Tunnel, ctx: &Context) -> Result<Action> {
    let ns = t.namespace().unwrap_or_default();
    let name = t.name_any();
    let api: Api<Tunnel> = Api::namespaced(ctx.client.clone(), &ns);
    let generation = t.metadata.generation;
    let mut status = t.status.clone().unwrap_or_default();
    status.observed_generation = generation;

    let routes = routes_for(ctx, t);
    ensure_route_finalizers(ctx, &routes).await?;

    // Credentials and the tunnel itself.
    let account = match ctx.account_for(&t.uid().unwrap_or_default(), &t.spec.cloudflare, &ns).await {
        Ok(a) => a,
        Err(e) => {
            let cond = Cond::fail(types::TUNNEL_CREATED, e.reason, e.message);
            return fail(ctx, t, &api, status, &routes, cond, Duration::from_secs(60)).await;
        }
    };
    status.account_id = Some(account.id.clone());
    let cf_tunnel = match ensure_tunnel(t, ctx, &account, &mut status, &api).await? {
        Ok(tun) => tun,
        Err(cond) => return fail(ctx, t, &api, status, &routes, cond, Duration::from_secs(30)).await,
    };
    let tunnel_id = cf_tunnel.id.clone();
    let target = format!("{tunnel_id}.cfargotunnel.com");

    // Connector.
    if let Err(cond) = ensure_connector(t, ctx, &account, &tunnel_id).await? {
        return fail(ctx, t, &api, status, &routes, cond, Duration::from_secs(30)).await;
    }
    let connections = cf_tunnel.active_connections();
    status.connectors = Some(connections as i32);
    let connector_cond = if connections > 0 {
        Cond::ok(
            types::CONNECTOR_READY,
            reasons::CONNECTED,
            format!("{connections} active connection(s) to Cloudflare"),
        )
    } else {
        Cond::fail(
            types::CONNECTOR_READY,
            reasons::NO_CONNECTIONS,
            format!("Cloudflare reports no active connections; check Deployment {}", connector::deployment_name(t)),
        )
    };

    // Routes → configuration.
    let live: Vec<&Arc<TunnelRoute>> = routes.iter().filter(|r| r.meta().deletion_timestamp.is_none()).collect();
    let needs_zones = live.iter().any(|r| r.spec.dns.enabled);
    let zones = if needs_zones {
        match ctx.zones(&account).await {
            Ok(z) => z,
            Err(Error::Cloudflare(e)) => {
                let cond = conditions::cf_cond(types::CONFIG_APPLIED, "listing zones", &e);
                return fail(ctx, t, &api, status, &routes, cond, Duration::from_secs(30)).await;
            }
            Err(e) => return Err(e),
        }
    } else {
        Vec::new()
    };

    let mut grants = Grants::default();
    let mut inputs = Vec::new();
    let mut rejected: BTreeMap<RouteKey, Rejection> = BTreeMap::new();
    for r in &live {
        let key = RouteKey::new(&r.namespace().unwrap_or_default(), &r.name_any());
        match evaluate_route(ctx, t, r, &zones, &mut grants).await? {
            Ok(input) => inputs.push(input),
            Err(rej) => {
                rejected.insert(key, rej);
            }
        }
    }
    let resolution = ingress::resolve(inputs, ctx.settings.max_rules);
    rejected.extend(resolution.rejected.clone());

    let defaults = match t.spec.origin_defaults.as_ref().map(ingress::origin_defaults).transpose() {
        Ok(d) => d.unwrap_or_default(),
        Err(msg) => {
            let cond = Cond::fail(types::CONFIG_APPLIED, reasons::INVALID_SPEC, msg);
            return fail(ctx, t, &api, status, &routes, cond, Duration::from_secs(300)).await;
        }
    };
    let config = ingress::render(&resolution.accepted, defaults, &t.spec.fallback.clone().unwrap_or_default());
    let hash = ingress::config_hash(&config);
    let config_result = apply_config(ctx, &account, &tunnel_id, &config, &hash, &mut status).await;
    let config_cond = match &config_result {
        Ok(()) => Cond::ok(
            types::CONFIG_APPLIED,
            reasons::APPLIED,
            format!(
                "configuration version {} with {} route(s)",
                status.config_version.unwrap_or_default(),
                resolution.accepted.len()
            ),
        ),
        Err(c) => c.clone(),
    };
    status.routes = Some(resolution.accepted.len() as i32);

    // DNS for accepted routes.
    let marker = OwnerMarker::new(&ctx.cluster_id, &ns, "Tunnel", &name).to_string();
    let mut desired: BTreeMap<String, DesiredRecord> = BTreeMap::new();
    for input in &resolution.accepted {
        let Some(route) = live
            .iter()
            .find(|r| r.namespace().as_deref() == Some(&input.key.namespace) && r.name_any() == input.key.name)
        else {
            continue;
        };
        if !route.spec.dns.enabled {
            continue;
        }
        let Ok(zone) = dns::pick_zone(&input.hostname, &zones, route.spec.dns.zone.as_deref()) else {
            continue; // rejected in evaluate_route
        };
        let entry = desired.entry(input.hostname.clone()).or_insert_with(|| DesiredRecord {
            hostname: input.hostname.clone(),
            zone_id: zone.id.clone(),
            adopt: false,
        });
        entry.adopt |= route.spec.dns.adopt;
    }
    let dns_result = sync_dns(&account, &desired, &status.dns_zone_ids, &target, &marker).await;
    let (dns_outcomes, dns_errors, stale_ok) = match dns_result {
        Ok(r) => r,
        Err(e) => {
            let msg = format!("syncing DNS records: {e}");
            let errors = desired.keys().map(|h| (h.clone(), msg.clone())).collect();
            (BTreeMap::new(), errors, false)
        }
    };
    let mut zone_ids: BTreeSet<String> = desired.values().map(|d| d.zone_id.clone()).collect();
    if !stale_ok {
        zone_ids.extend(status.dns_zone_ids.iter().cloned());
    }
    status.dns_zone_ids = zone_ids.into_iter().collect();

    // Route statuses.
    let outcome = TunnelOutcome { blocked: None, connected: connections > 0, config: config_result.clone() };
    for r in &live {
        let key = RouteKey::new(&r.namespace().unwrap_or_default(), &r.name_any());
        let host = r.spec.hostname.to_ascii_lowercase();
        let dns_cond = if !r.spec.dns.enabled {
            Cond::ok(types::DNS_READY, reasons::DNS_DISABLED, "DNS management is disabled for this route")
        } else if let Some(err) = dns_errors.get(&host) {
            Cond::fail(types::DNS_READY, reasons::CLOUDFLARE_ERROR, err.clone())
        } else {
            match dns_outcomes.get(&host) {
                Some(HostOutcome::Ready) => {
                    Cond::ok(types::DNS_READY, reasons::RECORD_READY, format!("proxied CNAME {host} → {target}"))
                }
                Some(HostOutcome::Conflict { message }) => {
                    Cond::fail(types::DNS_READY, reasons::CONFLICT, message.clone())
                }
                None => Cond::fail(types::DNS_READY, reasons::PENDING, "waiting for the route to be accepted"),
            }
        };
        let service = resolution.accepted.iter().find(|i| i.key == key).map(|i| i.service.clone());
        write_route_status(ctx, r, &tunnel_id, rejected.get(&key), service, dns_cond, &outcome).await?;
    }

    // Deleted routes: release them once they're out of the config and DNS.
    if config_result.is_ok() && stale_ok {
        for r in routes.iter().filter(|r| r.meta().deletion_timestamp.is_some()) {
            remove_route_finalizer(ctx, r).await?;
        }
    }

    // Tunnel status.
    let created_cond =
        Cond::ok(types::TUNNEL_CREATED, reasons::CREATED, format!("tunnel {} ({tunnel_id})", cf_tunnel.name));
    let ready = connections > 0 && config_result.is_ok();
    conditions::set_all_with_ready(&mut status.conditions, vec![created_cond, connector_cond, config_cond], generation);
    patch_status(&api, &name, t.status.as_ref(), &status).await?;

    Ok(if ready { Action::requeue(ctx.resync_jittered()) } else { Action::requeue(ctx.settings.not_ready_requeue) })
}

/// Reports a tunnel-level failure on the tunnel and all its routes.
#[allow(clippy::too_many_arguments)]
async fn fail(
    ctx: &Context,
    t: &Tunnel,
    api: &Api<Tunnel>,
    mut status: TunnelStatus,
    routes: &[Arc<TunnelRoute>],
    cond: Cond,
    retry: Duration,
) -> Result<Action> {
    let generation = t.metadata.generation;
    let outcome = TunnelOutcome {
        blocked: Some(Cond::fail(
            types::CONFIG_APPLIED,
            reasons::TUNNEL_NOT_READY,
            format!("Tunnel {}/{} is not ready: {}", t.namespace().unwrap_or_default(), t.name_any(), cond.message),
        )),
        connected: false,
        config: Err(cond.clone()),
    };
    conditions::set_all_with_ready(&mut status.conditions, vec![cond], generation);
    patch_status(api, &t.name_any(), t.status.as_ref(), &status).await?;
    for r in routes.iter().filter(|r| r.meta().deletion_timestamp.is_none()) {
        let dns = Cond::fail(types::DNS_READY, reasons::TUNNEL_NOT_READY, "waiting for the tunnel");
        write_route_status(ctx, r, status.tunnel_id.as_deref().unwrap_or_default(), None, None, dns, &outcome).await?;
    }
    Ok(Action::requeue(retry))
}

async fn patch_status(api: &Api<Tunnel>, name: &str, old: Option<&TunnelStatus>, new: &TunnelStatus) -> Result<()> {
    if let Some(old) = old {
        let mut a = old.clone();
        let mut b = new.clone();
        let same_conds = conditions::same(&a.conditions, &b.conditions);
        a.conditions.clear();
        b.conditions.clear();
        if same_conds && a == b {
            return Ok(());
        }
    }
    api.patch_status(name, &PatchParams::default(), &Patch::Merge(json!({ "status": new }))).await?;
    Ok(())
}

/// Finds, adopts or creates the Cloudflare tunnel and records its ID in status right away.
async fn ensure_tunnel(
    t: &Tunnel,
    ctx: &Context,
    account: &Account,
    status: &mut TunnelStatus,
    api: &Api<Tunnel>,
) -> Result<Result<tunnelgate_cf::types::Tunnel, Cond>> {
    let ns = t.namespace().unwrap_or_default();
    let name = t.name_any();
    let expected = t.spec.name.clone().unwrap_or_else(|| default_tunnel_name(&ns, &name, &ctx.cluster_id));

    if let Some(id) = status.tunnel_id.clone() {
        match account.api.get_tunnel(&account.id, &id).await {
            Ok(Some(tun)) if tun.deleted_at.is_none() => return Ok(Ok(tun)),
            Ok(_) => {
                warn!(tunnel = %name, %id, "Cloudflare tunnel recorded in status no longer exists; creating a new one");
                status.tunnel_id = None;
                status.config_hash = None;
                status.config_version = None;
            }
            Err(e) => return Ok(Err(conditions::cf_cond(types::TUNNEL_CREATED, "reading the tunnel", &e))),
        }
    }

    let existing = match account.api.list_tunnels(&account.id, Some(&expected)).await {
        Ok(list) => list.into_iter().find(|x| x.name == expected && x.deleted_at.is_none()),
        Err(e) => return Ok(Err(conditions::cf_cond(types::TUNNEL_CREATED, "listing tunnels", &e))),
    };
    let tun = match existing {
        Some(tun) => {
            let ours = t.spec.name.is_none() && is_default_tunnel_name(&expected, &ctx.cluster_id);
            if !(ours || t.spec.adopt) {
                return Ok(Err(Cond::fail(
                    types::TUNNEL_CREATED,
                    reasons::CONFLICT,
                    format!(
                        "a Cloudflare tunnel named {expected} already exists ({}) and is not recorded as owned by this \
                         Tunnel; set spec.adopt: true to take it over, or choose another spec.name",
                        tun.id
                    ),
                )));
            }
            info!(tunnel = %name, id = %tun.id, "adopting existing Cloudflare tunnel");
            tun
        }
        None => match account.api.create_tunnel(&account.id, &expected).await {
            Ok(tun) => {
                info!(tunnel = %name, id = %tun.id, cf_name = %expected, "created Cloudflare tunnel");
                tun
            }
            Err(e) => return Ok(Err(conditions::cf_cond(types::TUNNEL_CREATED, "creating the tunnel", &e))),
        },
    };
    status.tunnel_id = Some(tun.id.clone());
    status.tunnel_name = Some(tun.name.clone());
    status.cname = Some(format!("{}.cfargotunnel.com", tun.id));
    // Record the ID before anything else can fail, so the tunnel is never orphaned.
    api.patch_status(&name, &PatchParams::default(), &Patch::Merge(json!({ "status": {
        "tunnelId": status.tunnel_id, "tunnelName": status.tunnel_name, "cname": status.cname, "accountId": status.account_id,
    }})))
    .await?;
    Ok(Ok(tun))
}

/// Token Secret, cloudflared Deployment and PDB.
async fn ensure_connector(t: &Tunnel, ctx: &Context, account: &Account, tunnel_id: &str) -> Result<Result<(), Cond>> {
    use secrecy::ExposeSecret;
    let ns = t.namespace().unwrap_or_default();
    let pp = PatchParams::apply(FIELD_MANAGER).force();
    let secrets: Api<Secret> = Api::namespaced(ctx.client.clone(), &ns);

    let secret_name = connector::token_secret_name(t);
    let current = secrets.get_opt(&secret_name).await?;
    let up_to_date = current.as_ref().is_some_and(|s| {
        s.annotations().get(&connector::tunnel_id_annotation()).map(String::as_str) == Some(tunnel_id)
            && s.data.as_ref().is_some_and(|d| d.get(connector::TOKEN_KEY).is_some_and(|v| !v.0.is_empty()))
    });
    if !up_to_date {
        let token = match account.api.get_tunnel_token(&account.id, tunnel_id).await {
            Ok(tok) => tok,
            Err(e) => return Ok(Err(conditions::cf_cond(types::CONNECTOR_READY, "fetching the connector token", &e))),
        };
        let secret = connector::token_secret(t, tunnel_id, token.expose_secret());
        secrets.patch(&secret_name, &pp, &Patch::Apply(&secret)).await?;
    }

    let ca_pool = match t.spec.origin_defaults.as_ref().and_then(|o| o.ca_pool_secret_ref.as_ref()) {
        None => None,
        Some(r) => {
            let key = r.key.clone().unwrap_or_else(|| "ca.crt".to_owned());
            let data = secrets.get_opt(&r.name).await?.and_then(|s| s.data).and_then(|d| d.get(&key).cloned());
            let Some(data) = data else {
                return Ok(Err(Cond::fail(
                    types::CONNECTOR_READY,
                    reasons::CA_POOL_NOT_FOUND,
                    format!("CA pool Secret {ns}/{} with key {key} not found", r.name),
                )));
            };
            Some(connector::CaPool {
                secret_name: r.name.clone(),
                key,
                data_hash: hex::encode(&Sha256::digest(&data.0)[..8]),
            })
        }
    };

    let replicas = t.spec.connector.replicas.unwrap_or(ctx.settings.default_connector_replicas);
    let params = connector::ConnectorParams {
        image: t.spec.connector.image.clone().unwrap_or_else(|| ctx.settings.default_connector_image.clone()),
        replicas,
        ca_pool,
    };
    let deployments: Api<Deployment> = Api::namespaced(ctx.client.clone(), &ns);
    let deployment = connector::deployment(t, &params);
    deployments.patch(&connector::deployment_name(t), &pp, &Patch::Apply(&deployment)).await?;

    let pdbs: Api<PodDisruptionBudget> = Api::namespaced(ctx.client.clone(), &ns);
    match connector::pdb(t, replicas) {
        Some(pdb) => {
            pdbs.patch(&connector::deployment_name(t), &pp, &Patch::Apply(&pdb)).await?;
        }
        None => delete_ignore_missing(&pdbs, &connector::deployment_name(t)).await?,
    }
    Ok(Ok(()))
}

async fn delete_ignore_missing<K>(api: &Api<K>, name: &str) -> Result<()>
where
    K: Resource + Clone + serde::de::DeserializeOwned + std::fmt::Debug,
{
    match api.delete(name, &DeleteParams::background()).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(s)) if s.code == 404 => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// PUTs the configuration when it changed or Cloudflare's version moved (drift).
async fn apply_config(
    ctx: &Context,
    account: &Account,
    tunnel_id: &str,
    config: &tunnelgate_cf::types::TunnelConfig,
    hash: &str,
    status: &mut TunnelStatus,
) -> Result<(), Cond> {
    let remote = account
        .api
        .get_tunnel_configuration(&account.id, tunnel_id)
        .await
        .map_err(|e| conditions::cf_cond(types::CONFIG_APPLIED, "reading the tunnel configuration", &e))?;
    let known = ctx.applied_config(tunnel_id, (status.config_hash.as_deref(), status.config_version));
    if let (Some((known_hash, known_version)), Some(remote)) = (known, &remote)
        && known_hash == hash
        && remote.version == known_version
    {
        status.config_hash = Some(known_hash);
        status.config_version = Some(known_version);
        return Ok(());
    }
    // Nothing recorded (status lost, or a new operator version hashes differently), but Cloudflare
    // already has this configuration: GET returns exactly what was PUT.
    if let Some(remote) = &remote
        && remote.config.as_ref() == Some(config)
    {
        ctx.record_applied_config(tunnel_id, hash, remote.version);
        status.config_hash = Some(hash.to_owned());
        status.config_version = Some(remote.version);
        return Ok(());
    }
    let applied = account
        .api
        .put_tunnel_configuration(&account.id, tunnel_id, config)
        .await
        .map_err(|e| conditions::cf_cond(types::CONFIG_APPLIED, "applying the tunnel configuration", &e))?;
    info!(tunnel_id, version = applied.version, rules = config.ingress.len(), "applied tunnel configuration");
    ctx.record_applied_config(tunnel_id, hash, applied.version);
    status.config_hash = Some(hash.to_owned());
    status.config_version = Some(applied.version);
    Ok(())
}

type DnsSync = (BTreeMap<String, HostOutcome>, BTreeMap<String, String>, bool);

/// Plans and applies DNS changes. Returns per-host outcomes, per-host errors, and whether all
/// stale records were removed.
async fn sync_dns(
    account: &Account,
    desired: &BTreeMap<String, DesiredRecord>,
    known_zones: &[String],
    target: &str,
    marker: &str,
) -> Result<DnsSync, tunnelgate_cf::Error> {
    let zone_ids: BTreeSet<&str> =
        desired.values().map(|d| d.zone_id.as_str()).chain(known_zones.iter().map(String::as_str)).collect();
    let mut existing: BTreeMap<String, (String, DnsRecord)> = BTreeMap::new();
    for zone in &zone_ids {
        let filter = DnsRecordFilter { comment_startswith: Some(marker.to_owned()), ..Default::default() };
        for r in account.api.list_dns_records(zone, &filter).await? {
            existing.insert(r.id.clone(), ((*zone).to_owned(), r));
        }
    }
    for d in desired.values() {
        let filter = DnsRecordFilter { name: Some(d.hostname.clone()), ..Default::default() };
        for r in account.api.list_dns_records(&d.zone_id, &filter).await? {
            existing.insert(r.id.clone(), (d.zone_id.clone(), r));
        }
    }
    let existing: Vec<(String, DnsRecord)> = existing.into_values().collect();
    let desired: Vec<DesiredRecord> = desired.values().cloned().collect();
    let plan = dns::plan(&desired, &existing, target, marker);

    let mut errors = BTreeMap::new();
    let mut stale_ok = true;
    for action in plan.actions {
        let (host, result) = match &action {
            DnsAction::Create { zone_id, record } => {
                (record.name.clone(), account.api.create_dns_record(zone_id, record).await.map(drop))
            }
            DnsAction::Update { zone_id, record_id, record } => {
                (record.name.clone(), account.api.update_dns_record(zone_id, record_id, record).await.map(drop))
            }
            DnsAction::Delete { zone_id, record_id, name } => {
                (name.to_ascii_lowercase(), account.api.delete_dns_record(zone_id, record_id).await)
            }
        };
        match result {
            Ok(()) => info!(?action, "applied DNS change"),
            Err(e) => {
                warn!(?action, error = %e, "DNS change failed");
                if desired.iter().any(|d| d.hostname == host) {
                    errors.insert(host, e.to_string());
                } else {
                    stale_ok = false;
                }
            }
        }
    }
    Ok((plan.outcomes, errors, stale_ok))
}

/// Validates a route against the cluster: grants, backend Service, zone.
async fn evaluate_route(
    ctx: &Context,
    t: &Tunnel,
    r: &TunnelRoute,
    zones: &[Zone],
    grants: &mut Grants,
) -> Result<Result<ingress::RouteInput, Rejection>> {
    let route_ns = r.namespace().unwrap_or_default();
    let tunnel_ns = t.namespace().unwrap_or_default();
    let reject = |reason: &'static str, message: String| Ok(Err(Rejection { reason, message }));
    let from = (GROUP, "TunnelRoute", route_ns.as_str());

    // Generated from an HTTPRoute: the Gateway it attached through authorizes the tunnel, and
    // backend grants for HTTPRoutes apply too.
    let gateway = r.annotations().get(&tunnelgate_render::gateway::gateway_annotation()).cloned();
    let from_httproute = (tunnelgate_render::gateway::GROUP, "HTTPRoute", route_ns.as_str());
    if let Some(g) = &gateway {
        if let Err(msg) = crate::gateway::authorizes(ctx, g, &route_ns, &r.spec.hostname, t, grants).await? {
            return reject(reasons::REF_NOT_PERMITTED, msg);
        }
    } else if !grants.permits(ctx, from, &tunnel_ns, (GROUP, "Tunnel", &t.name_any())).await? {
        return reject(
            reasons::REF_NOT_PERMITTED,
            format!(
                "Tunnel {tunnel_ns}/{} is in another namespace; a RouteGrant or ReferenceGrant in {tunnel_ns} must allow \
                 TunnelRoutes from {route_ns}",
                t.name_any()
            ),
        );
    }

    let mut backend_ns = route_ns.clone();
    if let Some(b) = &r.spec.service.backend_ref {
        backend_ns = b.namespace.clone().unwrap_or_else(|| route_ns.clone());
        let to = ("", "Service", b.name.as_str());
        let permitted = grants.permits(ctx, from, &backend_ns, to).await?
            || (gateway.is_some() && grants.permits(ctx, from_httproute, &backend_ns, to).await?);
        if !permitted {
            return reject(
                reasons::REF_NOT_PERMITTED,
                format!(
                    "Service {backend_ns}/{} is in another namespace; a RouteGrant or ReferenceGrant in {backend_ns} must \
                     allow {} from {route_ns}",
                    b.name,
                    if gateway.is_some() { "HTTPRoutes" } else { "TunnelRoutes" }
                ),
            );
        }
        let services: Api<Service> = Api::namespaced(ctx.client.clone(), &backend_ns);
        match services.get_opt(&b.name).await? {
            None => {
                return reject(reasons::BACKEND_NOT_FOUND, format!("Service {backend_ns}/{} not found", b.name));
            }
            Some(svc) => {
                let has_port = svc.spec.iter().flat_map(|s| s.ports.iter().flatten()).any(|p| p.port == b.port);
                if !has_port {
                    return reject(
                        reasons::BACKEND_NOT_FOUND,
                        format!("Service {backend_ns}/{} has no port {}", b.name, b.port),
                    );
                }
            }
        }
    }

    if r.spec.dns.enabled
        && let Err(msg) = dns::pick_zone(&r.spec.hostname, zones, r.spec.dns.zone.as_deref())
    {
        return reject(reasons::ZONE_NOT_FOUND, msg);
    }

    let created = r.metadata.creation_timestamp.as_ref().map(|ts| ts.0.to_string()).unwrap_or_default();
    match ingress::route_input(RouteKey::new(&route_ns, &r.name_any()), created, &r.spec, &backend_ns) {
        Ok(input) => Ok(Ok(input)),
        Err(msg) => reject(reasons::INVALID_SPEC, msg),
    }
}

/// `AccessReady` from the referenced AccessApplications.
async fn access_condition(ctx: &Context, r: &TunnelRoute) -> Result<Cond> {
    let refs = r.spec.access.as_ref().map(|a| a.application_refs.as_slice()).unwrap_or_default();
    if refs.is_empty() {
        return Ok(Cond::ok(types::ACCESS_READY, reasons::NOT_REQUESTED, "no Access applications referenced"));
    }
    let route_ns = r.namespace().unwrap_or_default();
    for a in refs {
        let ns = a.namespace_or(&route_ns);
        let apps: Api<AccessApplication> = Api::namespaced(ctx.client.clone(), ns);
        match apps.get_opt(&a.name).await? {
            None => {
                return Ok(Cond::fail(
                    types::ACCESS_READY,
                    reasons::APPLICATION_NOT_FOUND,
                    format!("AccessApplication {ns}/{} not found", a.name),
                ));
            }
            Some(app) => {
                let ready = app.status.as_ref().is_some_and(|s| conditions::is_true(&s.conditions, types::READY));
                if !ready {
                    return Ok(Cond::fail(
                        types::ACCESS_READY,
                        reasons::APPLICATION_NOT_READY,
                        format!("AccessApplication {ns}/{} is not Ready", a.name),
                    ));
                }
            }
        }
    }
    Ok(Cond::ok(types::ACCESS_READY, reasons::RECONCILED, format!("{} Access application(s) ready", refs.len())))
}

async fn write_route_status(
    ctx: &Context,
    r: &TunnelRoute,
    tunnel_id: &str,
    rejection: Option<&Rejection>,
    service: Option<String>,
    dns_cond: Cond,
    outcome: &TunnelOutcome,
) -> Result<()> {
    let generation = r.metadata.generation;
    let mut status = r.status.clone().unwrap_or_default();
    status.observed_generation = generation;
    status.tunnel_id = (!tunnel_id.is_empty()).then(|| tunnel_id.to_owned());
    status.service = service;
    status.url = Some(match r.spec.path.as_deref().filter(|p| !p.is_empty()) {
        Some(p) => format!("https://{}{}", r.spec.hostname, p.trim_start_matches('^')),
        None => format!("https://{}", r.spec.hostname),
    });

    let accepted = match rejection {
        Some(rej) => Cond::fail(types::ACCEPTED, rej.reason, rej.message.clone()),
        None => Cond::ok(types::ACCEPTED, reasons::RECONCILED, "route is valid"),
    };
    let config = match (&outcome.blocked, rejection, &outcome.config) {
        (Some(blocked), _, _) => blocked.clone(),
        (None, Some(rej), _) => Cond::fail(types::CONFIG_APPLIED, rej.reason, "route is not accepted"),
        (None, None, Ok(())) => {
            Cond::ok(types::CONFIG_APPLIED, reasons::APPLIED, "route is in the tunnel configuration")
        }
        (None, None, Err(c)) => Cond { type_: types::CONFIG_APPLIED, ..c.clone() },
    };
    let dns_cond = match rejection {
        Some(rej) if r.spec.dns.enabled => Cond::fail(types::DNS_READY, rej.reason, "route is not accepted"),
        _ => dns_cond,
    };
    let access = access_condition(ctx, r).await?;
    conditions::set_all_with_ready(&mut status.conditions, vec![accepted, config, dns_cond, access], generation);
    if conditions::is_true(&status.conditions, types::READY) && !outcome.connected {
        conditions::set(
            &mut status.conditions,
            Cond::fail(types::READY, reasons::TUNNEL_NOT_READY, "the tunnel has no active connector connections"),
            generation,
        );
    }
    patch_route_status(ctx, r, &status).await
}

pub(crate) async fn patch_route_status(ctx: &Context, r: &TunnelRoute, status: &TunnelRouteStatus) -> Result<()> {
    if let Some(old) = &r.status {
        let mut a = old.clone();
        let mut b = status.clone();
        let same_conds = conditions::same(&a.conditions, &b.conditions);
        a.conditions.clear();
        b.conditions.clear();
        if same_conds && a == b {
            return Ok(());
        }
    }
    let api: Api<TunnelRoute> = Api::namespaced(ctx.client.clone(), &r.namespace().unwrap_or_default());
    api.patch_status(&r.name_any(), &PatchParams::default(), &Patch::Merge(json!({ "status": status }))).await?;
    Ok(())
}

async fn ensure_route_finalizers(ctx: &Context, routes: &[Arc<TunnelRoute>]) -> Result<()> {
    for r in routes.iter().filter(|r| r.meta().deletion_timestamp.is_none()) {
        if r.finalizers().iter().any(|f| f == ROUTE_FINALIZER) {
            continue;
        }
        let mut finalizers = r.finalizers().to_vec();
        finalizers.push(ROUTE_FINALIZER.to_owned());
        let api: Api<TunnelRoute> = Api::namespaced(ctx.client.clone(), &r.namespace().unwrap_or_default());
        let patch = json!({ "metadata": { "finalizers": finalizers, "resourceVersion": r.resource_version() } });
        api.patch(&r.name_any(), &PatchParams::default(), &Patch::Merge(patch)).await?;
    }
    Ok(())
}

pub(crate) async fn remove_route_finalizer(ctx: &Context, r: &TunnelRoute) -> Result<()> {
    if !r.finalizers().iter().any(|f| f == ROUTE_FINALIZER) {
        return Ok(());
    }
    let finalizers: Vec<&String> = r.finalizers().iter().filter(|f| *f != ROUTE_FINALIZER).collect();
    let api: Api<TunnelRoute> = Api::namespaced(ctx.client.clone(), &r.namespace().unwrap_or_default());
    let patch = json!({ "metadata": { "finalizers": finalizers, "resourceVersion": r.resource_version() } });
    match api.patch(&r.name_any(), &PatchParams::default(), &Patch::Merge(patch)).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(s)) if s.code == 404 => Ok(()),
        Err(e) => Err(e.into()),
    }
}

async fn cleanup(t: &Tunnel, ctx: &Context) -> Result<Action> {
    let ns = t.namespace().unwrap_or_default();
    let name = t.name_any();
    let routes = routes_for(ctx, t);
    let status = t.status.clone().unwrap_or_default();

    let skip = t.annotations().get(&skip_cleanup_annotation()).is_some_and(|v| v == "true");
    if t.spec.deletion_policy == DeletionPolicy::Retain || skip || status.tunnel_id.is_none() {
        info!(tunnel = %name, policy = ?t.spec.deletion_policy, skip, "leaving Cloudflare objects in place");
        for r in &routes {
            remove_route_finalizer(ctx, r).await?;
        }
        return Ok(Action::await_change());
    }
    let tunnel_id = status.tunnel_id.clone().unwrap_or_default();

    let uid = t.uid().unwrap_or_default();
    let account = ctx.cleanup_account(&uid, &t.spec.cloudflare, &ns).await.map_err(|e| {
        Error::Pending(format!(
            "cannot clean up tunnel {tunnel_id}: {} ({}); restore the credentials or annotate the Tunnel with {}=true",
            e.message,
            e.reason,
            skip_cleanup_annotation()
        ))
    })?;

    // DNS records first, so nothing points at a tunnel that's going away.
    let marker = OwnerMarker::new(&ctx.cluster_id, &ns, "Tunnel", &name).to_string();
    let (_, _, stale_ok) = sync_dns(&account, &BTreeMap::new(), &status.dns_zone_ids, "", &marker).await?;
    if !stale_ok {
        return Err(Error::Pending(format!("removing DNS records of tunnel {name}")));
    }

    // Stop the connectors, then drop their connections and the tunnel.
    let deployments: Api<Deployment> = Api::namespaced(ctx.client.clone(), &ns);
    delete_ignore_missing(&deployments, &connector::deployment_name(t)).await?;
    account.api.cleanup_tunnel_connections(&account.id, &tunnel_id).await?;
    match account.api.delete_tunnel(&account.id, &tunnel_id).await {
        Ok(()) => {
            ctx.forget_applied_config(&tunnel_id);
            info!(tunnel = %name, %tunnel_id, "deleted Cloudflare tunnel");
        }
        Err(e) if e.status() == Some(400) => {
            return Err(Error::Pending(format!("tunnel {tunnel_id} still has connections, retrying: {e}")));
        }
        Err(e) => return Err(e.into()),
    }

    for r in &routes {
        remove_route_finalizer(ctx, r).await?;
    }
    ctx.forget_object(&uid);
    Ok(Action::await_change())
}
