//! AccessApplication controller: one `self_hosted` Access application per resource, with
//! host or host/path destinations and reusable policies attached in order.

use std::sync::Arc;

use futures::StreamExt;
use kube::ResourceExt;
use kube::api::Api;
use kube::runtime::controller::{Action, Controller};
use kube::runtime::finalizer::{Event, finalizer};
use kube::runtime::reflector::ObjectRef;
use kube::runtime::watcher;
use tracing::{info, warn};
use tunnelgate_api::conditions::{reasons, types};
use tunnelgate_api::v1alpha1::{AccessApplication, AccessApplicationStatus, AccessPolicy};
use tunnelgate_render::access::{application_matches, render_application};
use tunnelgate_render::marker::has_name_suffix;

use super::{claimed_by_other, display_name, error_policy, patch_status, requeue, skip_cleanup};
use crate::conditions::{self, Cond};
use crate::context::Context;
use crate::error::{Error, Result, finalizer_result};
use crate::tunnel::{FINALIZER, skip_cleanup_annotation};

pub async fn run(ctx: Arc<Context>) {
    let client = ctx.client.clone();
    let controller = Controller::new(Api::<AccessApplication>::all(client.clone()), watcher::Config::default());
    let apps = controller.store();
    controller
        // A policy getting its ID or becoming Ready changes the applications that attach it.
        .watches(Api::<AccessPolicy>::all(client), watcher::Config::default(), move |policy| {
            let (ns, name) = (policy.namespace().unwrap_or_default(), policy.name_any());
            apps.state()
                .into_iter()
                .filter(|a| {
                    let ans = a.namespace().unwrap_or_default();
                    a.spec.policies.iter().any(|r| r.name == name && r.namespace_or(&ans) == ns)
                })
                .map(|a| ObjectRef::from_obj(&*a))
                .collect::<Vec<_>>()
        })
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|_| async {})
        .await;
}

pub async fn reconcile(app: Arc<AccessApplication>, ctx: Arc<Context>) -> Result<Action> {
    let api: Api<AccessApplication> = Api::namespaced(ctx.client.clone(), &app.namespace().unwrap_or_default());
    finalizer(&api, FINALIZER, app, |event| async {
        match event {
            Event::Apply(a) => apply(&a, &ctx).await,
            Event::Cleanup(a) => cleanup(&a, &ctx).await,
        }
    })
    .await
    .or_else(finalizer_result)
}

async fn apply(a: &AccessApplication, ctx: &Context) -> Result<Action> {
    let api: Api<AccessApplication> = Api::namespaced(ctx.client.clone(), &a.namespace().unwrap_or_default());
    let generation = a.metadata.generation;
    let mut status = a.status.clone().unwrap_or_default();
    status.observed_generation = generation;

    let outcome = ensure(a, ctx, &api, &mut status).await?;
    let ready = match &outcome {
        Ok(msg) => Cond::ok(types::READY, reasons::RECONCILED, msg.clone()),
        Err(c) => c.clone(),
    };
    conditions::set(&mut status.conditions, ready, generation);
    patch_status(&api, &a.name_any(), a.status.as_ref(), &status).await?;
    Ok(requeue(ctx, outcome.is_ok()))
}

async fn ensure(
    a: &AccessApplication,
    ctx: &Context,
    api: &Api<AccessApplication>,
    status: &mut AccessApplicationStatus,
) -> Result<Result<String, Cond>> {
    let ns = a.namespace().unwrap_or_default();
    let account = match ctx.account_for(&a.uid().unwrap_or_default(), &a.spec.cloudflare, &ns).await {
        Ok(acc) => acc,
        Err(e) => return Ok(Err(Cond::fail(types::READY, e.reason, e.message))),
    };
    if let (Some(old), Some(id)) = (&status.account_id, &status.application_id)
        && *old != account.id
    {
        warn!(app = %a.name_any(), %old, %id, "account changed; the old application stays behind (see tunnelgate sweep)");
        status.application_id = None;
        status.aud = None;
    }
    status.account_id = Some(account.id.clone());

    let mut policy_ids = Vec::new();
    for r in &a.spec.policies {
        match policy_id(ctx, r.namespace_or(&ns), &r.name, &account.id).await? {
            Ok(id) => policy_ids.push(id),
            Err(c) => return Ok(Err(c)),
        }
    }
    let name = display_name(a.spec.name.as_deref(), a, &ctx.cluster_id);
    let desired = match render_application(&a.spec, name, &policy_ids) {
        Ok(d) => d,
        Err(e) => return Ok(Err(Cond::fail(types::READY, reasons::INVALID_SPEC, e))),
    };

    let (cf, acc) = (&account.api, account.id.as_str());
    let current = match status.application_id.clone() {
        Some(id) => cf!(cf.get_access_app(acc, &id), "reading the Access application"),
        None => {
            let mut found = None;
            for c in cf!(cf.list_access_apps(acc), "listing Access applications") {
                if c.name == desired.name
                    && !claimed_by_other(ctx, a, &c.id, |o: &AccessApplication| {
                        o.status.as_ref()?.application_id.clone()
                    })
                    .await?
                {
                    info!(app = %a.name_any(), id = %c.id, "adopting Access application created earlier");
                    found = Some(c);
                    break;
                }
            }
            found
        }
    };
    let app = match current {
        Some(cur) if !has_name_suffix(&cur.name, &ctx.cluster_id) => {
            return Ok(Err(Cond::fail(
                types::READY,
                reasons::CONFLICT,
                format!(
                    "Access application {:?} ({}) lost its tunnelgate name suffix, so it is no longer treated as \
                     owned; restore the suffix to manage it again",
                    cur.name, cur.id
                ),
            )));
        }
        Some(cur) if application_matches(&cur, &desired) => cur,
        Some(cur) => {
            let updated = cf!(cf.update_access_app(acc, &cur.id, &desired), "updating the Access application");
            info!(app = %a.name_any(), id = %updated.id, "updated Access application");
            updated
        }
        None => {
            let created = cf!(cf.create_access_app(acc, &desired), "creating the Access application");
            info!(app = %a.name_any(), id = %created.id, "created Access application");
            let mut s = status.clone();
            s.application_id = Some(created.id.clone());
            s.aud = created.aud.clone();
            patch_status(api, &a.name_any(), a.status.as_ref(), &s).await?;
            created
        }
    };
    status.application_id = Some(app.id.clone());
    status.aud = app.aud.clone().or(status.aud.take());
    let n = desired.destinations.len();
    Ok(Ok(format!(
        "Access application {:?} ({}) with {n} destination{} and {} polic{}",
        app.name,
        app.id,
        if n == 1 { "" } else { "s" },
        policy_ids.len(),
        if policy_ids.len() == 1 { "y" } else { "ies" }
    )))
}

/// The Cloudflare ID of a Ready `AccessPolicy` in the same account.
async fn policy_id(ctx: &Context, ns: &str, name: &str, account_id: &str) -> Result<Result<String, Cond>> {
    let api: Api<AccessPolicy> = Api::namespaced(ctx.client.clone(), ns);
    let Some(p) = api.get_opt(name).await? else {
        return Ok(Err(Cond::fail(
            types::READY,
            reasons::POLICY_NOT_FOUND,
            format!("AccessPolicy {ns}/{name} not found"),
        )));
    };
    let s = p.status.unwrap_or_default();
    let not_ready = |msg: String| Ok(Err(Cond::fail(types::READY, reasons::POLICY_NOT_READY, msg)));
    match (&s.policy_id, &s.account_id) {
        (Some(_), Some(acc)) if acc != account_id => {
            not_ready(format!("AccessPolicy {ns}/{name} is in account {acc}, this application in {account_id}"))
        }
        (Some(id), Some(_)) if conditions::is_true(&s.conditions, types::READY) => Ok(Ok(id.clone())),
        _ => not_ready(format!("AccessPolicy {ns}/{name} is not Ready")),
    }
}

async fn cleanup(a: &AccessApplication, ctx: &Context) -> Result<Action> {
    let (ns, name) = (a.namespace().unwrap_or_default(), a.name_any());
    let uid = a.uid().unwrap_or_default();
    let Some(id) = a.status.as_ref().and_then(|s| s.application_id.clone()) else {
        return Ok(Action::await_change());
    };
    if skip_cleanup(a) {
        info!(app = %name, %id, "leaving the Access application in Cloudflare");
        ctx.forget_object(&uid);
        return Ok(Action::await_change());
    }
    let account = ctx.cleanup_account(&uid, &a.spec.cloudflare, &ns).await.map_err(|e| {
        Error::Pending(format!(
            "cannot delete Access application {id}: {} ({}); restore the credentials or annotate with {}=true",
            e.message,
            e.reason,
            skip_cleanup_annotation()
        ))
    })?;
    match account.api.get_access_app(&account.id, &id).await? {
        Some(cur) if has_name_suffix(&cur.name, &ctx.cluster_id) => {
            account.api.delete_access_app(&account.id, &id).await?;
            info!(app = %name, %id, "deleted Access application");
        }
        Some(cur) => {
            warn!(app = %name, %id, cf_name = %cur.name, "Access application is no longer marked as ours; left in place")
        }
        None => {}
    }
    ctx.forget_object(&uid);
    Ok(Action::await_change())
}
