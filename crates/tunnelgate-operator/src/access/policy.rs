//! AccessPolicy controller: one reusable Cloudflare Access policy per resource.

use std::collections::BTreeMap;
use std::sync::Arc;

use futures::StreamExt;
use kube::ResourceExt;
use kube::api::{Api, ListParams};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::finalizer::{Event, finalizer};
use kube::runtime::reflector::ObjectRef;
use kube::runtime::watcher;
use tracing::{info, warn};
use tunnelgate_api::conditions::{reasons, types};
use tunnelgate_api::v1alpha1::{
    AccessApplication, AccessPolicy, AccessPolicySpec, AccessServiceToken, ObjectRef as Ref,
};
use tunnelgate_render::access::{policy_matches, policy_warning, render_policy};
use tunnelgate_render::marker::has_name_suffix;

use super::{claimed_by_other, display_name, error_policy, patch_status, requeue, skip_cleanup};
use crate::conditions::{self, Cond};
use crate::context::Context;
use crate::error::{Error, Result, finalizer_result};
use crate::tunnel::FINALIZER;

pub async fn run(ctx: Arc<Context>) {
    let client = ctx.client.clone();
    let controller = Controller::new(Api::<AccessPolicy>::all(client.clone()), watcher::Config::default());
    let policies = controller.store();
    controller
        // A service token getting its ID changes the policies that include it.
        .watches(Api::<AccessServiceToken>::all(client), watcher::Config::default(), move |tok| {
            let (ns, name) = (tok.namespace().unwrap_or_default(), tok.name_any());
            policies
                .state()
                .into_iter()
                .filter(|p| {
                    let pns = p.namespace().unwrap_or_default();
                    token_refs(&p.spec).any(|r| r.name == name && r.namespace_or(&pns) == ns)
                })
                .map(|p| ObjectRef::from_obj(&*p))
                .collect::<Vec<_>>()
        })
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|_| async {})
        .await;
}

pub fn token_refs(spec: &AccessPolicySpec) -> impl Iterator<Item = &Ref> {
    spec.include.iter().chain(&spec.require).chain(&spec.exclude).flat_map(|r| &r.service_tokens)
}

pub async fn reconcile(policy: Arc<AccessPolicy>, ctx: Arc<Context>) -> Result<Action> {
    let api: Api<AccessPolicy> = Api::namespaced(ctx.client.clone(), &policy.namespace().unwrap_or_default());
    finalizer(&api, FINALIZER, policy, |event| async {
        match event {
            Event::Apply(p) => apply(&p, &ctx).await,
            Event::Cleanup(p) => cleanup(&p, &ctx).await,
        }
    })
    .await
    .or_else(finalizer_result)
}

async fn apply(p: &AccessPolicy, ctx: &Context) -> Result<Action> {
    let api: Api<AccessPolicy> = Api::namespaced(ctx.client.clone(), &p.namespace().unwrap_or_default());
    let generation = p.metadata.generation;
    let mut status = p.status.clone().unwrap_or_default();
    status.observed_generation = generation;

    let outcome = ensure(p, ctx, &api, &mut status).await?;
    let ready = match &outcome {
        Ok(msg) => Cond::ok(types::READY, reasons::RECONCILED, msg.clone()),
        Err(c) => c.clone(),
    };
    conditions::set(&mut status.conditions, ready, generation);
    match policy_warning(&p.spec) {
        Some(w) => {
            conditions::set(&mut status.conditions, Cond::ok(types::WARNING, reasons::ALLOW_EVERYONE, w), generation)
        }
        None => status.conditions.retain(|c| c.type_ != types::WARNING),
    }
    patch_status(&api, &p.name_any(), p.status.as_ref(), &status).await?;
    Ok(requeue(ctx, outcome.is_ok()))
}

/// Creates, adopts or updates the Cloudflare policy. `Ok(Err(cond))` is a failed `Ready`.
async fn ensure(
    p: &AccessPolicy,
    ctx: &Context,
    api: &Api<AccessPolicy>,
    status: &mut tunnelgate_api::v1alpha1::AccessPolicyStatus,
) -> Result<Result<String, Cond>> {
    let ns = p.namespace().unwrap_or_default();
    let account = match ctx.account_for(&p.uid().unwrap_or_default(), &p.spec.cloudflare, &ns).await {
        Ok(a) => a,
        Err(e) => return Ok(Err(Cond::fail(types::READY, e.reason, e.message))),
    };
    if let (Some(old), Some(id)) = (&status.account_id, &status.policy_id)
        && *old != account.id
    {
        warn!(policy = %p.name_any(), %old, %id, "account changed; the old policy stays behind (see tunnelgate sweep)");
        status.policy_id = None;
    }
    status.account_id = Some(account.id.clone());

    let mut token_ids = BTreeMap::new();
    for r in token_refs(&p.spec) {
        let tns = r.namespace_or(&ns).to_owned();
        match service_token_id(ctx, &tns, &r.name, &account.id).await? {
            Ok(id) => token_ids.insert((tns, r.name.clone()), id),
            Err(c) => return Ok(Err(c)),
        };
    }
    let name = display_name(p.spec.name.as_deref(), p, &ctx.cluster_id);
    let lookup = |r: &Ref| {
        token_ids
            .get(&(r.namespace_or(&ns).to_owned(), r.name.clone()))
            .cloned()
            .ok_or_else(|| format!("AccessServiceToken {} not resolved", r.name))
    };
    let desired = match render_policy(&p.spec, name, &lookup) {
        Ok(d) => d,
        Err(e) => return Ok(Err(Cond::fail(types::READY, reasons::INVALID_SPEC, e))),
    };

    let (cf, acc) = (&account.api, account.id.as_str());
    let current = match status.policy_id.clone() {
        // None: deleted in Cloudflare; it's recreated below.
        Some(id) => cf!(cf.get_access_policy(acc, &id), "reading the Access policy"),
        None => {
            let mut found = None;
            for c in cf!(cf.list_access_policies(acc), "listing Access policies") {
                if c.name == desired.name
                    && !claimed_by_other(ctx, p, &c.id, |o: &AccessPolicy| o.status.as_ref()?.policy_id.clone()).await?
                {
                    info!(policy = %p.name_any(), id = %c.id, "adopting Access policy created earlier");
                    found = Some(c);
                    break;
                }
            }
            found
        }
    };
    let policy = match current {
        Some(cur) if !has_name_suffix(&cur.name, &ctx.cluster_id) => {
            return Ok(Err(Cond::fail(
                types::READY,
                reasons::CONFLICT,
                format!(
                    "Access policy {:?} ({}) lost its tunnelgate name suffix, so it is no longer treated as owned; \
                     restore the suffix to manage it again",
                    cur.name, cur.id
                ),
            )));
        }
        Some(cur) if policy_matches(&cur, &desired) => cur,
        Some(cur) => {
            let updated = cf!(cf.update_access_policy(acc, &cur.id, &desired), "updating the Access policy");
            info!(policy = %p.name_any(), id = %updated.id, "updated Access policy");
            updated
        }
        None => {
            let created = cf!(cf.create_access_policy(acc, &desired), "creating the Access policy");
            info!(policy = %p.name_any(), id = %created.id, "created Access policy");
            // Record the ID right away so a failure later in this reconcile can't orphan it.
            let mut s = status.clone();
            s.policy_id = Some(created.id.clone());
            patch_status(api, &p.name_any(), p.status.as_ref(), &s).await?;
            created
        }
    };
    status.policy_id = Some(policy.id.clone());
    Ok(Ok(format!("Access policy {:?} ({})", policy.name, policy.id)))
}

/// The Cloudflare ID of an `AccessServiceToken`, which must use the same account.
async fn service_token_id(ctx: &Context, ns: &str, name: &str, account_id: &str) -> Result<Result<String, Cond>> {
    let api: Api<AccessServiceToken> = Api::namespaced(ctx.client.clone(), ns);
    let Some(t) = api.get_opt(name).await? else {
        return Ok(Err(Cond::fail(
            types::READY,
            reasons::SERVICE_TOKEN_NOT_FOUND,
            format!("AccessServiceToken {ns}/{name} not found"),
        )));
    };
    let s = t.status.unwrap_or_default();
    Ok(match (s.token_id, s.account_id) {
        (Some(id), Some(acc)) if acc == account_id => Ok(id),
        (Some(_), Some(acc)) => Err(Cond::fail(
            types::READY,
            reasons::SERVICE_TOKEN_NOT_READY,
            format!("AccessServiceToken {ns}/{name} is in account {acc}, this policy in {account_id}"),
        )),
        _ => Err(Cond::fail(
            types::READY,
            reasons::SERVICE_TOKEN_NOT_READY,
            format!("AccessServiceToken {ns}/{name} has no Cloudflare token yet"),
        )),
    })
}

async fn cleanup(p: &AccessPolicy, ctx: &Context) -> Result<Action> {
    let (ns, name) = (p.namespace().unwrap_or_default(), p.name_any());
    let uid = p.uid().unwrap_or_default();
    let Some(id) = p.status.as_ref().and_then(|s| s.policy_id.clone()) else {
        return Ok(Action::await_change());
    };
    if skip_cleanup(p) {
        info!(policy = %name, %id, "leaving the Access policy in Cloudflare");
        ctx.forget_object(&uid);
        return Ok(Action::await_change());
    }

    // Cloudflare refuses to delete a policy that applications still attach; say which ones.
    let users: Vec<String> = Api::<AccessApplication>::all(ctx.client.clone())
        .list(&ListParams::default())
        .await?
        .iter()
        .filter(|a| {
            let ans = a.namespace().unwrap_or_default();
            a.spec.policies.iter().any(|r| r.name == name && r.namespace_or(&ans) == ns)
        })
        .map(|a| format!("{}/{}", a.namespace().unwrap_or_default(), a.name_any()))
        .collect();
    if !users.is_empty() {
        let api: Api<AccessPolicy> = Api::namespaced(ctx.client.clone(), &ns);
        let mut status = p.status.clone().unwrap_or_default();
        let msg = format!("deletion waits until no AccessApplication uses this policy: {}", users.join(", "));
        let c = Cond::fail(types::READY, reasons::PENDING, msg.clone());
        conditions::set(&mut status.conditions, c, p.metadata.generation);
        patch_status(&api, &name, p.status.as_ref(), &status).await?;
        // An error keeps the finalizer: the finalizer helper removes it after any Ok.
        return Err(Error::Pending(msg));
    }

    let account = ctx.cleanup_account(&uid, &p.spec.cloudflare, &ns).await.map_err(|e| {
        Error::Pending(format!(
            "cannot delete Access policy {id}: {} ({}); restore the credentials or annotate with {}=true",
            e.message,
            e.reason,
            crate::tunnel::skip_cleanup_annotation()
        ))
    })?;
    match account.api.get_access_policy(&account.id, &id).await? {
        Some(cur) if has_name_suffix(&cur.name, &ctx.cluster_id) => {
            match account.api.delete_access_policy(&account.id, &id).await {
                Ok(()) => info!(policy = %name, %id, "deleted Access policy"),
                // 409 while an application still attaches it (one we don't manage, or a lagging one).
                Err(e) if e.is_conflict() => {
                    return Err(Error::Pending(format!("Cloudflare won't delete Access policy {id} yet: {e}")));
                }
                Err(e) => return Err(e.into()),
            }
        }
        Some(cur) => {
            warn!(policy = %name, %id, cf_name = %cur.name, "Access policy is no longer marked as ours; left in place")
        }
        None => {}
    }
    ctx.forget_object(&uid);
    Ok(Action::await_change())
}
