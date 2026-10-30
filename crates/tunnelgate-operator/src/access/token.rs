//! AccessServiceToken controller: a Cloudflare Access service token whose credentials live in a
//! Secret.
//!
//! Cloudflare returns the client secret only when the token is created. The Secret is written
//! before the token ID goes to status; if the Secret is lost later, a new token is created, the
//! Secret rewritten, and the old token deleted ("rotate rather than fail"). Deleting the Secret
//! is therefore also how to rotate by hand. Cloudflare refuses to delete a token a policy still
//! includes, so the old token goes once the policy controller has switched to the new ID.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::jiff::{SignedDuration, Timestamp};
use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::finalizer::{Event, finalizer};
use kube::runtime::watcher;
use kube::{Resource, ResourceExt};
use secrecy::ExposeSecret;
use tracing::{info, warn};
use tunnelgate_api::DOMAIN;
use tunnelgate_api::conditions::{reasons, types};
use tunnelgate_api::v1alpha1::{AccessPolicy, AccessServiceToken, AccessServiceTokenStatus};
use tunnelgate_cf::types::{CreatedServiceToken, ServiceToken};
use tunnelgate_render::duration::parse_seconds;
use tunnelgate_render::marker::has_name_suffix;

use super::{claimed_by_other, display_name, error_policy, patch_status, skip_cleanup};
use crate::conditions::{self, Cond};
use crate::context::{Account, Context};
use crate::error::{Error, Result, finalizer_result};
use crate::tunnel::{FINALIZER, skip_cleanup_annotation};

pub const CLIENT_ID_KEY: &str = "CF-Access-Client-Id";
pub const CLIENT_SECRET_KEY: &str = "CF-Access-Client-Secret";
const DEFAULT_DURATION: &str = "8760h";
const FIELD_MANAGER: &str = "tunnelgate";
/// Cloudflare: the token is still referenced by a policy, group or app.
const TOKEN_IN_USE: i64 = 12139;
/// How soon to retry deleting a replaced token that policies still include.
const RETIRE_RETRY: Duration = Duration::from_secs(10);

fn token_id_annotation() -> String {
    format!("{DOMAIN}/token-id")
}

pub async fn run(ctx: Arc<Context>) {
    let client = ctx.client.clone();
    let managed = watcher::Config::default().labels("app.kubernetes.io/managed-by=tunnelgate");
    Controller::new(Api::<AccessServiceToken>::all(client.clone()), watcher::Config::default())
        .owns(Api::<Secret>::all(client), managed)
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|_| async {})
        .await;
}

pub async fn reconcile(token: Arc<AccessServiceToken>, ctx: Arc<Context>) -> Result<Action> {
    let api: Api<AccessServiceToken> = Api::namespaced(ctx.client.clone(), &token.namespace().unwrap_or_default());
    finalizer(&api, FINALIZER, token, |event| async {
        match event {
            Event::Apply(t) => apply(&t, &ctx).await,
            Event::Cleanup(t) => cleanup(&t, &ctx).await,
        }
    })
    .await
    .or_else(finalizer_result)
}

/// What a reconcile found and did.
struct Outcome {
    token: ServiceToken,
    rotated: bool,
    /// Older tokens with our name are still in Cloudflare.
    retiring: bool,
}

async fn apply(t: &AccessServiceToken, ctx: &Context) -> Result<Action> {
    let api: Api<AccessServiceToken> = Api::namespaced(ctx.client.clone(), &t.namespace().unwrap_or_default());
    let generation = t.metadata.generation;
    let mut status = t.status.clone().unwrap_or_default();
    status.observed_generation = generation;

    let (ready, expiring, next) = match ensure(t, ctx, &api, &mut status).await? {
        Err(c) => (c, None, Duration::from_secs(30)),
        Ok(Outcome { token, rotated, retiring }) => {
            // Keep reporting a rotation for as long as its token is the current one.
            let rotated = rotated
                || status.conditions.iter().any(|c| {
                    c.type_ == types::READY && c.reason == reasons::SECRET_LOST_ROTATED && c.message.contains(&token.id)
                });
            let duration = token.duration.as_deref().or(t.spec.duration.as_deref()).unwrap_or(DEFAULT_DURATION);
            let expiry = token
                .expires_at
                .as_deref()
                .and_then(|e| e.parse::<Timestamp>().ok())
                .zip(parse_seconds(duration).ok())
                .map(|(at, secs)| (at, expiry(Timestamp::now(), at, SignedDuration::from_secs(secs as i64))));
            let secret = &t.spec.secret_name;
            let rotate_hint = format!("delete Secret {secret} to rotate");
            let (ready, expiring, next) = match expiry {
                Some((at, Expiry::Expired)) => (
                    Cond::fail(types::READY, reasons::EXPIRED, format!("the token expired at {at}; {rotate_hint}")),
                    Some(Cond::ok(types::EXPIRING, reasons::EXPIRED, format!("expired at {at}"))),
                    Duration::from_secs(300),
                ),
                Some((at, Expiry::Soon)) => (
                    ready_ok(&token, secret, rotated),
                    Some(Cond::ok(types::EXPIRING, reasons::EXPIRES_SOON, format!("expires at {at}; {rotate_hint}"))),
                    ctx.resync_jittered(),
                ),
                Some((at, Expiry::Later(until_soon))) => (
                    ready_ok(&token, secret, rotated),
                    Some(Cond::fail(types::EXPIRING, reasons::NOT_EXPIRING, format!("expires at {at}"))),
                    ctx.resync_jittered().min(until_soon + Duration::from_secs(1)),
                ),
                None => (ready_ok(&token, secret, rotated), None, ctx.resync_jittered()),
            };
            (ready, expiring, if retiring { next.min(RETIRE_RETRY) } else { next })
        }
    };
    conditions::set(&mut status.conditions, ready, generation);
    match expiring {
        Some(c) => conditions::set(&mut status.conditions, c, generation),
        None => status.conditions.retain(|c| c.type_ != types::EXPIRING),
    }
    patch_status(&api, &t.name_any(), t.status.as_ref(), &status).await?;
    Ok(Action::requeue(next))
}

fn ready_ok(token: &ServiceToken, secret: &str, rotated: bool) -> Cond {
    if rotated {
        Cond::ok(
            types::READY,
            reasons::SECRET_LOST_ROTATED,
            format!(
                "Secret {secret} was missing or stale: created service token {}; the old one is deleted once no \
                 policy includes it",
                token.id
            ),
        )
    } else {
        Cond::ok(types::READY, reasons::RECONCILED, format!("service token {} in Secret {secret}", token.id))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expiry {
    Expired,
    /// Less than 10% of the duration left.
    Soon,
    /// Fine; becomes `Soon` after this long.
    Later(Duration),
}

fn expiry(now: Timestamp, expires_at: Timestamp, duration: SignedDuration) -> Expiry {
    let left = expires_at.duration_since(now);
    let threshold = duration / 10;
    if left <= SignedDuration::ZERO {
        Expiry::Expired
    } else if left < threshold {
        Expiry::Soon
    } else {
        Expiry::Later((left - threshold).unsigned_abs())
    }
}

async fn ensure(
    t: &AccessServiceToken,
    ctx: &Context,
    api: &Api<AccessServiceToken>,
    status: &mut AccessServiceTokenStatus,
) -> Result<Result<Outcome, Cond>> {
    let ns = t.namespace().unwrap_or_default();
    let account = match ctx.account_for(&t.uid().unwrap_or_default(), &t.spec.cloudflare, &ns).await {
        Ok(a) => a,
        Err(e) => return Ok(Err(Cond::fail(types::READY, e.reason, e.message))),
    };
    if let (Some(old), Some(id)) = (&status.account_id, &status.token_id)
        && *old != account.id
    {
        warn!(token = %t.name_any(), %old, %id, "account changed; the old service token stays behind (see tunnelgate sweep)");
        status.token_id = None;
    }
    status.account_id = Some(account.id.clone());
    let duration = t.spec.duration.clone().unwrap_or_else(|| DEFAULT_DURATION.to_owned());
    if let Err(e) = parse_seconds(&duration) {
        return Ok(Err(Cond::fail(types::READY, reasons::INVALID_SPEC, format!("duration: {e}"))));
    }

    // The Secret must be ours (or absent) before anything else.
    let secrets: Api<Secret> = Api::namespaced(ctx.client.clone(), &ns);
    let secret = secrets.get_opt(&t.spec.secret_name).await?;
    let uid = t.uid();
    if let Some(s) = &secret
        && !s.owner_references().iter().any(|o| Some(&o.uid) == uid.as_ref())
    {
        return Ok(Err(Cond::fail(
            types::READY,
            reasons::CONFLICT,
            format!(
                "Secret {ns}/{} exists and isn't managed by this AccessServiceToken; pick another secretName",
                t.spec.secret_name
            ),
        )));
    }

    let (cf, acc) = (&account.api, account.id.as_str());
    let name = display_name(t.spec.name.as_deref(), t, &ctx.cluster_id);
    let tokens = cf!(cf.list_service_tokens(acc), "listing Access service tokens");
    let current = status.token_id.as_ref().and_then(|id| tokens.iter().find(|tok| &tok.id == id));

    if let Some(cur) = current {
        if !has_name_suffix(&cur.name, &ctx.cluster_id) {
            return Ok(Err(Cond::fail(
                types::READY,
                reasons::CONFLICT,
                format!(
                    "service token {:?} ({}) lost its tunnelgate name suffix, so it is no longer treated as owned; \
                     restore the suffix to manage it again",
                    cur.name, cur.id
                ),
            )));
        }
        if secret.as_ref().is_some_and(|s| secret_holds(s, cur)) {
            status.client_id = Some(cur.client_id.clone());
            status.expires_at = cur.expires_at.clone();
            let retiring = retire_others(ctx, t, &account, &tokens, &name, &cur.id).await?;
            return Ok(Ok(Outcome { token: cur.clone(), rotated: false, retiring }));
        }
    }

    // A create whose Secret was written but whose ID never reached status: adopt it.
    if current.is_none()
        && let Some(s) = &secret
        && let Some(tok) = tokens.iter().find(|tok| tok.name == name && secret_holds(s, tok))
    {
        info!(token = %t.name_any(), id = %tok.id, "adopting service token whose Secret was written earlier");
        status.token_id = Some(tok.id.clone());
        status.client_id = Some(tok.client_id.clone());
        status.expires_at = tok.expires_at.clone();
        let retiring = retire_others(ctx, t, &account, &tokens, &name, &tok.id).await?;
        return Ok(Ok(Outcome { token: tok.clone(), rotated: false, retiring }));
    }

    // Create a token and store its credentials before recording it.
    let created = cf!(cf.create_service_token(acc, &name, &duration), "creating the service token");
    let id = created.token.id.clone();
    if let Err(e) = write_secret(t, &secrets, &created).await {
        if let Err(del) = cf.delete_service_token(acc, &id).await {
            warn!(token = %t.name_any(), %id, error = %del, "couldn't delete the token whose Secret failed to write");
        }
        return Err(e);
    }
    info!(token = %t.name_any(), %id, secret = %t.spec.secret_name, "created service token");
    status.token_id = Some(id.clone());
    status.client_id = Some(created.token.client_id.clone());
    status.expires_at = created.token.expires_at.clone();
    if current.is_some() {
        let c = ready_ok(&created.token, &t.spec.secret_name, true);
        conditions::set(&mut status.conditions, c, status.observed_generation);
    }
    patch_status(api, &t.name_any(), t.status.as_ref(), status).await?;

    // The token this one replaces, and orphans of a create whose Secret was never written.
    let retiring = retire_others(ctx, t, &account, &tokens, &name, &id).await?;
    Ok(Ok(Outcome { token: created.token, rotated: current.is_some(), retiring }))
}

/// Whether the Secret holds credentials for `token`.
fn secret_holds(secret: &Secret, token: &ServiceToken) -> bool {
    let data = secret.data.as_ref();
    let has = |k: &str| data.and_then(|d| d.get(k)).is_some_and(|v| !v.0.is_empty());
    secret.annotations().get(&token_id_annotation()) == Some(&token.id)
        && data.and_then(|d| d.get(CLIENT_ID_KEY)).is_some_and(|v| v.0 == token.client_id.as_bytes())
        && has(CLIENT_SECRET_KEY)
}

async fn write_secret(t: &AccessServiceToken, secrets: &Api<Secret>, created: &CreatedServiceToken) -> Result<()> {
    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(t.spec.secret_name.clone()),
            namespace: t.namespace(),
            labels: Some(BTreeMap::from([
                ("app.kubernetes.io/managed-by".to_owned(), "tunnelgate".to_owned()),
                (format!("{DOMAIN}/access-service-token"), t.name_any()),
            ])),
            annotations: Some(BTreeMap::from([(token_id_annotation(), created.token.id.clone())])),
            owner_references: t.controller_owner_ref(&()).map(|o| vec![o]),
            ..Default::default()
        },
        type_: Some("Opaque".to_owned()),
        data: Some(BTreeMap::from([
            (CLIENT_ID_KEY.to_owned(), ByteString(created.token.client_id.as_bytes().to_vec())),
            (CLIENT_SECRET_KEY.to_owned(), ByteString(created.client_secret.expose_secret().as_bytes().to_vec())),
        ])),
        ..Default::default()
    };
    let pp = PatchParams::apply(FIELD_MANAGER).force();
    secrets.patch(&t.spec.secret_name, &pp, &Patch::Apply(&secret)).await?;
    Ok(())
}

/// Deletes the tokens named `name` other than `keep`: ones replaced by a rotation, and ones from
/// a create whose Secret was never written (their secret is unknown, so they're useless). Tokens
/// another resource records are left alone. Returns whether any remain: Cloudflare refuses while
/// a policy still includes one.
async fn retire_others(
    ctx: &Context,
    t: &AccessServiceToken,
    account: &Account,
    tokens: &[ServiceToken],
    name: &str,
    keep: &str,
) -> Result<bool> {
    let mut remaining = false;
    for old in tokens.iter().filter(|tok| tok.name == name && tok.id != keep) {
        if claimed_by_other(ctx, t, &old.id, |o: &AccessServiceToken| o.status.as_ref()?.token_id.clone()).await? {
            continue;
        }
        match account.api.delete_service_token(&account.id, &old.id).await {
            Ok(()) => info!(token = %t.name_any(), id = %old.id, "deleted replaced service token"),
            Err(e) if e.has_code(TOKEN_IN_USE) => {
                info!(token = %t.name_any(), id = %old.id, "replaced service token still in a policy; retrying");
                remaining = true;
            }
            Err(e) if e.is_not_found() => {}
            Err(e) => {
                warn!(token = %t.name_any(), id = %old.id, error = %e, "couldn't delete replaced service token");
                remaining = true;
            }
        }
    }
    Ok(remaining)
}

async fn cleanup(t: &AccessServiceToken, ctx: &Context) -> Result<Action> {
    let (ns, name) = (t.namespace().unwrap_or_default(), t.name_any());
    let uid = t.uid().unwrap_or_default();
    let Some(id) = t.status.as_ref().and_then(|s| s.token_id.clone()) else {
        return Ok(Action::await_change());
    };
    if skip_cleanup(t) {
        info!(token = %name, %id, "leaving the service token in Cloudflare");
        ctx.forget_object(&uid);
        return Ok(Action::await_change());
    }
    // Cloudflare refuses to delete a token that policies still include; say which ones.
    let users: Vec<String> = Api::<AccessPolicy>::all(ctx.client.clone())
        .list(&ListParams::default())
        .await?
        .iter()
        .filter(|p| {
            let pns = p.namespace().unwrap_or_default();
            super::policy::token_refs(&p.spec).any(|r| r.name == name && r.namespace_or(&pns) == ns)
        })
        .map(|p| format!("{}/{}", p.namespace().unwrap_or_default(), p.name_any()))
        .collect();
    if !users.is_empty() {
        let api: Api<AccessServiceToken> = Api::namespaced(ctx.client.clone(), &ns);
        let mut status = t.status.clone().unwrap_or_default();
        let msg = format!("deletion waits until no AccessPolicy includes this token: {}", users.join(", "));
        let c = Cond::fail(types::READY, reasons::PENDING, msg.clone());
        conditions::set(&mut status.conditions, c, t.metadata.generation);
        patch_status(&api, &name, t.status.as_ref(), &status).await?;
        // An error keeps the finalizer: the finalizer helper removes it after any Ok.
        return Err(Error::Pending(msg));
    }

    let account = ctx.cleanup_account(&uid, &t.spec.cloudflare, &ns).await.map_err(|e| {
        Error::Pending(format!(
            "cannot delete service token {id}: {} ({}); restore the credentials or annotate with {}=true",
            e.message,
            e.reason,
            skip_cleanup_annotation()
        ))
    })?;
    let tokens = account.api.list_service_tokens(&account.id).await?;
    match tokens.iter().find(|tok| tok.id == id) {
        Some(cur) if has_name_suffix(&cur.name, &ctx.cluster_id) => {
            match account.api.delete_service_token(&account.id, &id).await {
                Ok(()) => info!(token = %name, %id, "deleted service token"),
                // A policy that just went away in Kubernetes, or one we don't manage.
                Err(e) if e.has_code(TOKEN_IN_USE) => {
                    return Err(Error::Pending(format!("Cloudflare won't delete service token {id} yet: {e}")));
                }
                Err(e) => return Err(e.into()),
            }
        }
        Some(cur) => {
            warn!(token = %name, %id, cf_name = %cur.name, "service token is no longer marked as ours; left in place")
        }
        None => {}
    }
    ctx.forget_object(&uid);
    Ok(Action::await_change())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_thresholds() {
        let now: Timestamp = "2026-10-29T00:00:00Z".parse().unwrap();
        let year = SignedDuration::from_hours(8760);
        let at = |days: i64| now.checked_add(SignedDuration::from_hours(24 * days)).unwrap();
        assert_eq!(expiry(now, at(-1), year), Expiry::Expired);
        assert_eq!(expiry(now, now, year), Expiry::Expired);
        assert_eq!(expiry(now, at(30), year), Expiry::Soon);
        // 36.5 days is 10% of a year: 100 days left means Soon in 63.5 days.
        assert_eq!(expiry(now, at(100), year), Expiry::Later(Duration::from_secs(63 * 86400 + 43200)));
    }
}
