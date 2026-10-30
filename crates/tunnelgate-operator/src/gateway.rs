//! Gateway API adapter: GatewayClasses with `controllerName: tunnelgate.geeko.me/tunnel`,
//! their Gateways (each names a Tunnel in `spec.infrastructure.parametersRef` or an annotation),
//! and HTTPRoutes attached to them, which
//! become TunnelRoutes owned by the HTTPRoute.
//!
//! Only `gateway.networking.k8s.io/v1` fields of the v1.2 standard channel are read, through minimal
//! types (`tunnelgate_render::gateway`) on top of `kube`'s dynamic API, so any v1.x bundle works.
//! The adapter starts once the CRDs are served (checked at startup and then every 30 s); without
//! them the operator runs as before.
//!
//! Authorization follows Gateway API, not grants: a generated TunnelRoute carries the Gateway it
//! comes from (annotation), and route evaluation accepts its tunnelRef when that Gateway is ours,
//! names the Tunnel (same namespace, or a grant for the Gateway), and has a listener that admits
//! the route's namespace and hostname. That's exactly what an HTTPRoute in the namespace could get
//! anyway, so the annotation can't be used to reach further.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use k8s_openapi::api::core::v1::Namespace;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, OwnerReference};
use kube::ResourceExt;
use kube::api::{Api, ApiResource, DeleteParams, DynamicObject, GroupVersionKind, ListParams, Patch, PatchParams};
use kube::core::Object;
use kube::runtime::controller::{Action, Controller};
use kube::runtime::reflector::{self, ObjectRef};
use kube::runtime::{WatchStreamExt, watcher};
use serde_json::{Value, json};
use tracing::{info, warn};
use tunnelgate_api::GROUP;
use tunnelgate_api::conditions::{reasons as tg_reasons, types as tg_types};
use tunnelgate_api::v1alpha1::{RouteGrant, Tunnel, TunnelRoute};
use tunnelgate_render::gateway::{
    self as gw, CONTROLLER_NAME, GatewayClassSpec, GatewaySpec, HttpRouteSpec, ParentReference, reasons,
};

use crate::conditions::{self, Cond};
use crate::context::Context;
use crate::error::{Error, Result};
use crate::grants::{Grants, reference_grant_resource};

pub type GatewayClass = Object<GatewayClassSpec, Value>;
pub type Gateway = Object<GatewaySpec, Value>;
pub type HttpRoute = Object<HttpRouteSpec, Value>;

const FIELD_MANAGER: &str = "tunnelgate-gateway";

fn resource(kind: &str) -> ApiResource {
    ApiResource::from_gvk(&GroupVersionKind::gvk(gw::GROUP, "v1", kind))
}

pub fn gateway_class_resource() -> ApiResource {
    resource("GatewayClass")
}
pub fn gateway_resource() -> ApiResource {
    resource("Gateway")
}
pub fn httproute_resource() -> ApiResource {
    resource("HTTPRoute")
}

/// Whether GatewayClass, Gateway and HTTPRoute are served at `v1`.
pub async fn available(client: &kube::Client) -> bool {
    let Ok(group) = kube::discovery::group(client, gw::GROUP).await else { return false };
    let kinds: BTreeSet<String> = group.versioned_resources("v1").into_iter().map(|(ar, _)| ar.kind).collect();
    ["GatewayClass", "Gateway", "HTTPRoute"].iter().all(|k| kinds.contains(*k))
}

/// Waits for the Gateway API CRDs, then runs the adapter's controllers.
pub async fn run(ctx: Arc<Context>) {
    let mut logged = false;
    while !available(&ctx.client).await {
        if !logged {
            info!("Gateway API (v1 GatewayClass, Gateway, HTTPRoute) not installed; the adapter starts when it is");
            logged = true;
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(30)) => {}
            _ = tokio::signal::ctrl_c() => return,
        }
    }
    info!("Gateway API found; starting the Gateway API adapter");
    tokio::join!(run_classes(ctx.clone()), run_gateways(ctx.clone()), run_routes(ctx));
}

fn error_policy<K: ResourceExt>(obj: Arc<K>, error: &Error, _ctx: Arc<Context>) -> Action {
    warn!(name = %obj.name_any(), namespace = ?obj.namespace(), error = %error, "Gateway API reconcile failed");
    Action::requeue(Duration::from_secs(30))
}

/// The conditions in a status value, as typed conditions.
fn conditions_in(v: Option<&Value>) -> Vec<Condition> {
    v.and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default()
}

/// Whether a GatewayClass of this name is handled by tunnelgate.
async fn class_is_ours(ctx: &Context, name: &str) -> Result<bool> {
    let api: Api<GatewayClass> = Api::all_with(ctx.client.clone(), &gateway_class_resource());
    Ok(api.get_opt(name).await?.is_some_and(|c| c.spec.controller_name == CONTROLLER_NAME))
}

/// Labels of a namespace, cached for one reconcile.
async fn namespace_labels(
    ctx: &Context,
    cache: &mut HashMap<String, BTreeMap<String, String>>,
    ns: &str,
) -> Result<BTreeMap<String, String>> {
    if let Some(l) = cache.get(ns) {
        return Ok(l.clone());
    }
    let labels =
        Api::<Namespace>::all(ctx.client.clone()).get_opt(ns).await?.map(|n| n.labels().clone()).unwrap_or_default();
    cache.insert(ns.to_owned(), labels.clone());
    Ok(labels)
}

/// The Tunnel a Gateway of ours uses, if the Gateway may use it (same namespace or a grant).
async fn gateway_tunnel(ctx: &Context, g: &Gateway, grants: &mut Grants) -> Result<Result<Tunnel, Cond>> {
    let gns = g.namespace().unwrap_or_default();
    let tref = match gw::gateway_tunnel(&gns, &g.spec, g.annotations()) {
        Ok(r) => r,
        Err(msg) => return Ok(Err(Cond::fail(tg_types::ACCEPTED, reasons::INVALID_PARAMETERS, msg))),
    };
    let tns = tref.namespace_or(&gns).to_owned();
    if !grants.permits(ctx, (gw::GROUP, "Gateway", &gns), &tns, (GROUP, "Tunnel", &tref.name)).await? {
        return Ok(Err(Cond::fail(
            tg_types::ACCEPTED,
            reasons::REF_NOT_PERMITTED,
            format!(
                "Tunnel {tns}/{} is in another namespace; a RouteGrant or ReferenceGrant in {tns} must allow Gateways \
                 from {gns}",
                tref.name
            ),
        )));
    }
    match Api::<Tunnel>::namespaced(ctx.client.clone(), &tns).get_opt(&tref.name).await? {
        Some(t) => Ok(Ok(t)),
        None => Ok(Err(Cond::fail(
            tg_types::ACCEPTED,
            reasons::INVALID_PARAMETERS,
            format!("Tunnel {tns}/{} not found", tref.name),
        ))),
    }
}

/// Route evaluation for a TunnelRoute generated from an HTTPRoute (annotation
/// `tunnelgate.geeko.me/gateway`): whether that Gateway lets the route use Tunnel `t` for its
/// hostname. `Err(message)` when it doesn't.
pub async fn authorizes(
    ctx: &Context,
    gateway: &str,
    route_ns: &str,
    hostname: &str,
    t: &Tunnel,
    grants: &mut Grants,
) -> Result<Result<(), String>> {
    let (gns, gname) = gateway.split_once('/').unwrap_or((route_ns, gateway));
    let api: Api<Gateway> = Api::namespaced_with(ctx.client.clone(), gns, &gateway_resource());
    let g = match api.get_opt(gname).await {
        Ok(Some(g)) => g,
        Ok(None) => return Ok(Err(format!("Gateway {gns}/{gname} not found"))),
        Err(kube::Error::Api(s)) if s.code == 404 => {
            return Ok(Err("the Gateway API is not installed".to_owned()));
        }
        Err(e) => return Err(e.into()),
    };
    if !class_is_ours(ctx, &g.spec.gateway_class_name).await? {
        return Ok(Err(format!("Gateway {gns}/{gname} is not of a tunnelgate GatewayClass")));
    }
    let tunnel = match gateway_tunnel(ctx, &g, grants).await? {
        Ok(tunnel) => tunnel,
        Err(c) => return Ok(Err(format!("Gateway {gns}/{gname}: {}", c.message))),
    };
    if tunnel.uid() != t.uid() {
        return Ok(Err(format!(
            "Gateway {gns}/{gname} uses Tunnel {}/{}, not this one",
            tunnel.namespace().unwrap_or_default(),
            tunnel.name_any()
        )));
    }
    let labels = namespace_labels(ctx, &mut HashMap::new(), route_ns).await?;
    if !gw::gateway_permits(&g.spec, gns, route_ns, &labels, hostname) {
        return Ok(Err(format!(
            "no listener of Gateway {gns}/{gname} admits HTTPRoutes from namespace {route_ns} for hostname {hostname}"
        )));
    }
    Ok(Ok(()))
}

// == GatewayClass

async fn run_classes(ctx: Arc<Context>) {
    let ar = gateway_class_resource();
    let api: Api<GatewayClass> = Api::all_with(ctx.client.clone(), &ar);
    Controller::new_with(api, watcher::Config::default(), ar)
        .shutdown_on_signal()
        .run(reconcile_class, error_policy, ctx)
        .for_each(|_| async {})
        .await;
}

async fn reconcile_class(class: Arc<GatewayClass>, ctx: Arc<Context>) -> Result<Action> {
    if class.spec.controller_name != CONTROLLER_NAME {
        return Ok(Action::await_change());
    }
    let generation = class.metadata.generation;
    let mut conds = conditions_in(class.status.as_ref().and_then(|s| s.get("conditions")));
    let old = conds.clone();
    conditions::set(&mut conds, Cond::ok(tg_types::ACCEPTED, reasons::ACCEPTED, "handled by tunnelgate"), generation);
    if !conditions::same(&old, &conds) {
        let api: Api<GatewayClass> = Api::all_with(ctx.client.clone(), &gateway_class_resource());
        api.patch_status(
            &class.name_any(),
            &PatchParams::default(),
            &Patch::Merge(json!({ "status": { "conditions": conds } })),
        )
        .await?;
    }
    Ok(Action::await_change())
}

// == Gateway

async fn run_gateways(ctx: Arc<Context>) {
    let client = ctx.client.clone();
    let ar = gateway_resource();
    let api: Api<Gateway> = Api::all_with(client.clone(), &ar);
    let controller = Controller::new_with(api, watcher::Config::default(), ar.clone());
    let gateways = controller.store();

    // Attached routes count per listener, so the Gateway follows its HTTPRoutes.
    let routes_ar = httproute_resource();
    let writer = reflector::store::Writer::new(routes_ar.clone());
    let routes = writer.as_reader();
    let route_watch = reflector::reflector(
        writer,
        watcher(Api::<HttpRoute>::all_with(client.clone(), &routes_ar), watcher::Config::default()),
    )
    .touched_objects();
    let (ar_routes, ar_tunnels, ar_classes) = (ar.clone(), ar.clone(), ar.clone());
    let (gateways_t, gateways_c) = (gateways.clone(), gateways.clone());
    let (gateways_rg, gateways_refg) = (gateways.clone(), gateways.clone());
    let (ar_rg, ar_refg) = (ar.clone(), ar.clone());
    let all = |store: &reflector::Store<Gateway>, ar: &ApiResource| {
        store.state().iter().map(|g| ObjectRef::from_obj_with(&**g, ar.clone())).collect::<Vec<_>>()
    };
    // A Gateway using a Tunnel in another namespace follows the grants there. ReferenceGrant is in
    // Gateway API's standard channel, so it's served whenever the adapter runs.
    let reference_grants = watcher(
        Api::<DynamicObject>::all_with(client.clone(), &reference_grant_resource()),
        watcher::Config::default(),
    )
    .touched_objects();
    let ctx = Arc::new(GatewayCtx { ctx, routes });

    controller
        .watches_stream_with(
            route_watch,
            move |r: HttpRoute| {
                let ns = r.namespace().unwrap_or_default();
                r.spec
                    .parent_refs
                    .iter()
                    .filter_map(|p| p.gateway(&ns))
                    .map(|(gns, name)| ObjectRef::new_with(&name, ar_routes.clone()).within(&gns))
                    .collect::<Vec<_>>()
            },
            routes_ar,
        )
        .watches(Api::<Tunnel>::all(client.clone()), watcher::Config::default(), move |t| {
            let (tns, tname) = (t.namespace().unwrap_or_default(), t.name_any());
            gateways_t
                .state()
                .into_iter()
                .filter(|g| {
                    let gns = g.namespace().unwrap_or_default();
                    gw::gateway_tunnel(&gns, &g.spec, g.annotations())
                        .is_ok_and(|r| r.name == tname && r.namespace_or(&gns) == tns)
                })
                .map(|g| ObjectRef::from_obj_with(&*g, ar_tunnels.clone()))
                .collect::<Vec<_>>()
        })
        .watches_with(
            Api::<GatewayClass>::all_with(client.clone(), &gateway_class_resource()),
            gateway_class_resource(),
            watcher::Config::default(),
            move |c| {
                gateways_c
                    .state()
                    .into_iter()
                    .filter(|g| g.spec.gateway_class_name == c.name_any())
                    .map(|g| ObjectRef::from_obj_with(&*g, ar_classes.clone()))
                    .collect::<Vec<_>>()
            },
        )
        .watches(Api::<RouteGrant>::all(client), watcher::Config::default(), move |_| all(&gateways_rg, &ar_rg))
        .watches_stream_with(reference_grants, move |_| all(&gateways_refg, &ar_refg), reference_grant_resource())
        .shutdown_on_signal()
        .run(reconcile_gateway, gateway_error_policy, ctx)
        .for_each(|_| async {})
        .await;
}

struct GatewayCtx {
    ctx: Arc<Context>,
    routes: reflector::Store<HttpRoute>,
}

fn gateway_error_policy(g: Arc<Gateway>, error: &Error, ctx: Arc<GatewayCtx>) -> Action {
    error_policy(g, error, ctx.ctx.clone())
}

async fn reconcile_gateway(g: Arc<Gateway>, gctx: Arc<GatewayCtx>) -> Result<Action> {
    let ctx = &gctx.ctx;
    if !class_is_ours(ctx, &g.spec.gateway_class_name).await? {
        return Ok(Action::await_change());
    }
    let (gns, gname) = (g.namespace().unwrap_or_default(), g.name_any());
    let generation = g.metadata.generation;
    let old_status = g.status.clone().unwrap_or(Value::Null);
    let mut conds = conditions_in(old_status.get("conditions"));

    let mut grants = Grants::default();
    let tunnel = gateway_tunnel(ctx, &g, &mut grants).await?;
    let (accepted, programmed, addresses) = match &tunnel {
        Err(c) => (c.clone(), Cond::fail("Programmed", reasons::INVALID, "the Gateway is not accepted"), vec![]),
        Ok(t) => {
            let ready = t.status.as_ref().is_some_and(|s| conditions::is_true(&s.conditions, tg_types::READY));
            let tname = format!("{}/{}", t.namespace().unwrap_or_default(), t.name_any());
            let programmed = if ready {
                Cond::ok("Programmed", reasons::PROGRAMMED, format!("Tunnel {tname} is ready"))
            } else {
                Cond::fail("Programmed", reasons::PENDING, format!("waiting for Tunnel {tname} to be Ready"))
            };
            let cname = t.status.as_ref().and_then(|s| s.cname.clone());
            let addresses: Vec<Value> = cname.into_iter().map(|c| json!({ "type": "Hostname", "value": c })).collect();
            (Cond::ok(tg_types::ACCEPTED, reasons::ACCEPTED, format!("uses Tunnel {tname}")), programmed, addresses)
        }
    };
    let programmed_ok = programmed.status;
    conditions::set(&mut conds, accepted.clone(), generation);
    conditions::set(&mut conds, programmed.clone(), generation);

    // Listener status: supported kinds and attached routes.
    let old_listeners: Vec<Value> = old_status.get("listeners").and_then(Value::as_array).cloned().unwrap_or_default();
    let mut labels = HashMap::new();
    let mut listeners = Vec::new();
    for l in &g.spec.listeners {
        let http = matches!(l.protocol.as_str(), "HTTP" | "HTTPS");
        let mut attached = 0;
        for r in gctx.routes.state() {
            let rns = r.namespace().unwrap_or_default();
            let targets = r.spec.parent_refs.iter().any(|p| {
                p.gateway(&rns) == Some((gns.clone(), gname.clone()))
                    && p.section_name.as_ref().is_none_or(|s| *s == l.name)
                    && p.port.is_none_or(|port| port == l.port)
            });
            if targets && gw::listener_allows(l, &gns, &rns, &namespace_labels(ctx, &mut labels, &rns).await?) {
                attached += 1;
            }
        }
        let mut lconds = old_listeners
            .iter()
            .find(|o| o["name"] == json!(l.name))
            .map(|o| conditions_in(o.get("conditions")))
            .unwrap_or_default();
        let (acc, refs) = if http {
            (Cond::ok(tg_types::ACCEPTED, reasons::ACCEPTED, ""), Cond::ok("ResolvedRefs", reasons::RESOLVED_REFS, ""))
        } else {
            (
                Cond::fail(tg_types::ACCEPTED, "UnsupportedProtocol", format!("{} is not supported", l.protocol)),
                Cond::fail("ResolvedRefs", "InvalidRouteKinds", "only HTTPRoutes over HTTP/HTTPS are supported"),
            )
        };
        let lprog =
            if http && accepted.status { programmed.clone() } else { Cond::fail("Programmed", reasons::INVALID, "") };
        conditions::set(&mut lconds, acc, generation);
        conditions::set(&mut lconds, refs, generation);
        conditions::set(&mut lconds, lprog, generation);
        let kinds = if http { json!([{ "group": gw::GROUP, "kind": "HTTPRoute" }]) } else { json!([]) };
        listeners
            .push(json!({ "name": l.name, "supportedKinds": kinds, "attachedRoutes": attached, "conditions": lconds }));
    }

    // null removes addresses (merge patch) when the tunnel has no CNAME (yet).
    let addresses = if addresses.is_empty() { Value::Null } else { json!(addresses) };
    let status = json!({ "conditions": conds, "listeners": listeners, "addresses": addresses });
    if status_differs(&old_status, &status) {
        let api: Api<Gateway> = Api::namespaced_with(ctx.client.clone(), &gns, &gateway_resource());
        api.patch_status(&gname, &PatchParams::default(), &Patch::Merge(json!({ "status": status }))).await?;
    }
    Ok(if programmed_ok { Action::requeue(ctx.resync_jittered()) } else { Action::requeue(Duration::from_secs(30)) })
}

/// Whether `new` changes any field of `old` it sets, ignoring condition transition times.
fn status_differs(old: &Value, new: &Value) -> bool {
    fn strip(v: &Value) -> Value {
        match v {
            Value::Object(m) => Value::Object(
                m.iter()
                    .filter(|(k, _)| k.as_str() != "lastTransitionTime")
                    .map(|(k, v)| (k.clone(), strip(v)))
                    .collect(),
            ),
            Value::Array(a) => Value::Array(a.iter().map(strip).collect()),
            _ => v.clone(),
        }
    }
    let Some(fields) = new.as_object() else { return true };
    fields.iter().any(|(k, v)| strip(old.get(k).unwrap_or(&Value::Null)) != strip(v))
}

// == HTTPRoute

async fn run_routes(ctx: Arc<Context>) {
    let client = ctx.client.clone();
    let ar = httproute_resource();
    let api: Api<HttpRoute> = Api::all_with(client.clone(), &ar);
    let controller = Controller::new_with(api, watcher::Config::default(), ar.clone());
    let routes = controller.store();
    let (routes_g, routes_c) = (routes.clone(), routes);
    let (ar_g, ar_c) = (ar.clone(), ar);
    let generated = watcher::Config::default().labels(&gw::httproute_uid_label());

    controller
        .owns(Api::<TunnelRoute>::all(client.clone()), generated)
        .watches_with(
            Api::<Gateway>::all_with(client.clone(), &gateway_resource()),
            gateway_resource(),
            watcher::Config::default(),
            move |g| {
                let key = Some((g.namespace().unwrap_or_default(), g.name_any()));
                routes_g
                    .state()
                    .into_iter()
                    .filter(|r| {
                        let ns = r.namespace().unwrap_or_default();
                        r.spec.parent_refs.iter().any(|p| p.gateway(&ns) == key)
                    })
                    .map(|r| ObjectRef::from_obj_with(&*r, ar_g.clone()))
                    .collect::<Vec<_>>()
            },
        )
        .watches_with(
            Api::<GatewayClass>::all_with(client, &gateway_class_resource()),
            gateway_class_resource(),
            watcher::Config::default(),
            move |_| routes_c.state().iter().map(|r| ObjectRef::from_obj_with(&**r, ar_c.clone())).collect::<Vec<_>>(),
        )
        .shutdown_on_signal()
        .run(reconcile_route, error_policy, ctx)
        .for_each(|_| async {})
        .await;
}

/// What happened to one parentRef of ours.
struct ParentOutcome {
    parent: ParentReference,
    /// `Err` when the route doesn't attach through this parent.
    generated: Result<Vec<String>, (&'static str, String)>,
}

async fn reconcile_route(r: Arc<HttpRoute>, ctx: Arc<Context>) -> Result<Action> {
    let (ns, name) = (r.namespace().unwrap_or_default(), r.name_any());
    let uid = r.uid().unwrap_or_default();
    let generation = r.metadata.generation;
    let mut grants = Grants::default();
    let mut labels = HashMap::new();

    // Translate through every parentRef that is a Gateway of ours.
    let mut desired: BTreeMap<String, (tunnelgate_api::v1alpha1::TunnelRouteSpec, String)> = BTreeMap::new();
    let mut outcomes = Vec::new();
    for parent in &r.spec.parent_refs {
        let Some((gns, gname)) = parent.gateway(&ns) else { continue };
        let Some(g) =
            Api::<Gateway>::namespaced_with(ctx.client.clone(), &gns, &gateway_resource()).get_opt(&gname).await?
        else {
            continue;
        };
        if !class_is_ours(&ctx, &g.spec.gateway_class_name).await? {
            continue;
        }
        let generated = match gateway_tunnel(&ctx, &g, &mut grants).await? {
            Err(c) => Err((reasons::NO_MATCHING_PARENT, format!("Gateway {gns}/{gname}: {}", c.message))),
            Ok(tunnel) => {
                let ns_labels = namespace_labels(&ctx, &mut labels, &ns).await?;
                match gw::attach(&g.spec, &gns, parent, &ns, &ns_labels, &r.spec.hostnames) {
                    Err(n) => Err((n.reason, n.message)),
                    Ok(hostnames) => {
                        let tref = tunnelgate_api::v1alpha1::ObjectRef {
                            name: tunnel.name_any(),
                            namespace: tunnel.namespace(),
                        };
                        match gw::translate(&name, &ns, &r.spec, r.annotations(), &hostnames, &tref, (&gns, &gname)) {
                            Err(msg) => Err((reasons::UNSUPPORTED_VALUE, msg)),
                            Ok(routes) => {
                                let names = routes.iter().map(|g| g.name.clone()).collect();
                                for g in routes {
                                    desired.entry(g.name).or_insert((g.spec, format!("{gns}/{gname}")));
                                }
                                Ok(names)
                            }
                        }
                    }
                }
            }
        };
        outcomes.push(ParentOutcome { parent: parent.clone(), generated });
    }

    // Apply the generated TunnelRoutes and delete the ones no longer wanted.
    let api: Api<TunnelRoute> = Api::namespaced(ctx.client.clone(), &ns);
    let owner = OwnerReference {
        api_version: format!("{}/v1", gw::GROUP),
        kind: "HTTPRoute".to_owned(),
        name: name.clone(),
        uid: uid.clone(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    };
    let mut blocked = BTreeMap::new();
    for (rname, (spec, gateway)) in &desired {
        if let Some(existing) = api.get_opt(rname).await?
            && existing.labels().get(&gw::httproute_uid_label()) != Some(&uid)
        {
            blocked.insert(
                rname.clone(),
                format!("TunnelRoute {ns}/{rname} exists and wasn't generated from this HTTPRoute"),
            );
            continue;
        }
        let obj = json!({
            "apiVersion": format!("{GROUP}/v1alpha1"), "kind": "TunnelRoute",
            "metadata": {
                "name": rname,
                "labels": { gw::httproute_uid_label(): uid, "app.kubernetes.io/managed-by": "tunnelgate" },
                "annotations": { gw::gateway_annotation(): gateway },
                "ownerReferences": [owner],
            },
            "spec": spec,
        });
        api.patch(rname, &PatchParams::apply(FIELD_MANAGER).force(), &Patch::Apply(&obj)).await?;
    }
    let lp = ListParams::default().labels(&format!("{}={uid}", gw::httproute_uid_label()));
    let mut current = BTreeMap::new();
    for tr in api.list(&lp).await? {
        if desired.contains_key(&tr.name_any()) {
            current.insert(tr.name_any(), tr);
        } else {
            info!(httproute = %name, %ns, route = %tr.name_any(), "deleting TunnelRoute no longer generated");
            match api.delete(&tr.name_any(), &DeleteParams::default()).await {
                Ok(_) => {}
                Err(kube::Error::Api(s)) if s.code == 404 => {}
                Err(e) => return Err(e.into()),
            }
        }
    }

    // Status: our entries in status.parents, from the attach results and the TunnelRoutes.
    let old_parents: Vec<Value> =
        r.status.as_ref().and_then(|s| s.get("parents")).and_then(Value::as_array).cloned().unwrap_or_default();
    let mut parents: Vec<Value> =
        old_parents.iter().filter(|p| p["controllerName"] != json!(CONTROLLER_NAME)).cloned().collect();
    for o in &outcomes {
        let parent_json = serde_json::to_value(&o.parent).unwrap_or(Value::Null);
        let mut conds = old_parents
            .iter()
            .find(|p| p["controllerName"] == json!(CONTROLLER_NAME) && p["parentRef"] == parent_json)
            .map(|p| conditions_in(p.get("conditions")))
            .unwrap_or_default();
        let (accepted, resolved) = match &o.generated {
            Err((reason, msg)) => (
                Cond::fail(tg_types::ACCEPTED, reason, msg.clone()),
                Cond::ok("ResolvedRefs", reasons::RESOLVED_REFS, ""),
            ),
            Ok(names) => route_conditions(names, &current, &blocked),
        };
        conditions::set(&mut conds, accepted, generation);
        conditions::set(&mut conds, resolved, generation);
        parents.push(json!({ "parentRef": parent_json, "controllerName": CONTROLLER_NAME, "conditions": conds }));
    }
    let old = json!({ "parents": old_parents });
    let new = json!({ "parents": parents });
    if status_differs(&old, &new) {
        // parents is an atomic list shared with other controllers: write it with the
        // resourceVersion we read, and retry on a conflict.
        let routes: Api<HttpRoute> = Api::namespaced_with(ctx.client.clone(), &ns, &httproute_resource());
        let patch = json!({ "metadata": { "resourceVersion": r.resource_version() }, "status": new });
        match routes.patch_status(&name, &PatchParams::default(), &Patch::Merge(patch)).await {
            Ok(_) => {}
            Err(kube::Error::Api(s)) if s.code == 409 => return Ok(Action::requeue(Duration::from_secs(1))),
            Err(e) => return Err(e.into()),
        }
    }
    let settled = outcomes.iter().all(|o| o.generated.is_ok()) && blocked.is_empty();
    Ok(if settled { Action::requeue(ctx.resync_jittered()) } else { Action::requeue(Duration::from_secs(30)) })
}

/// `Accepted` and `ResolvedRefs` for one parent from the TunnelRoutes it generated.
fn route_conditions(
    names: &[String],
    current: &BTreeMap<String, TunnelRoute>,
    blocked: &BTreeMap<String, String>,
) -> (Cond, Cond) {
    let mut refs_problem = None;
    let mut other_problem = None;
    for n in names {
        if let Some(msg) = blocked.get(n) {
            other_problem.get_or_insert((tg_reasons::CONFLICT, msg.clone()));
            continue;
        }
        let Some(tr) = current.get(n) else { continue };
        let status = tr.status.as_ref();
        let Some(c) = status.and_then(|s| s.conditions.iter().find(|c| c.type_ == tg_types::ACCEPTED)) else {
            continue;
        };
        if c.status == "True" {
            continue;
        }
        let msg = format!("TunnelRoute {}: {}", n, c.message);
        match c.reason.as_str() {
            tg_reasons::REF_NOT_PERMITTED => {
                refs_problem.get_or_insert((reasons::REF_NOT_PERMITTED, msg));
            }
            tg_reasons::BACKEND_NOT_FOUND => {
                refs_problem.get_or_insert((reasons::BACKEND_NOT_FOUND, msg));
            }
            _ => {
                let reason = tg_reasons_static(&c.reason);
                other_problem.get_or_insert((reason, msg));
            }
        }
    }
    let accepted = match other_problem {
        Some((reason, msg)) => Cond::fail(tg_types::ACCEPTED, reason, msg),
        None => Cond::ok(
            tg_types::ACCEPTED,
            reasons::ACCEPTED,
            format!("published as {} TunnelRoute(s): {}", names.len(), names.join(", ")),
        ),
    };
    let resolved = match refs_problem {
        Some((reason, msg)) => Cond::fail("ResolvedRefs", reason, msg),
        None => Cond::ok("ResolvedRefs", reasons::RESOLVED_REFS, ""),
    };
    (accepted, resolved)
}

/// TunnelRoute rejection reasons carried over to the HTTPRoute (conditions need `&'static str`).
fn tg_reasons_static(reason: &str) -> &'static str {
    [
        tg_reasons::CONFLICT,
        tg_reasons::TUNNEL_NOT_FOUND,
        tg_reasons::ZONE_NOT_FOUND,
        tg_reasons::INVALID_SPEC,
        tg_reasons::CONFIG_LIMIT,
    ]
    .into_iter()
    .find(|r| *r == reason)
    .unwrap_or(reasons::INVALID)
}
