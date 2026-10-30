//! CloudflareAccount controller: verifies the credentials and reports the account ID.
//! It owns nothing in Cloudflare, so there is no finalizer.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use k8s_openapi::api::core::v1::Secret;
use kube::ResourceExt;
use kube::api::Api;
use kube::core::PartialObjectMeta;
use kube::runtime::controller::{Action, Controller};
use kube::runtime::reflector::ObjectRef;
use kube::runtime::{WatchStreamExt, watcher};
use tunnelgate_api::conditions::{reasons, types};
use tunnelgate_api::v1alpha1::{CloudflareAccount, CloudflareRef, SecretKeyRef};

use crate::access::{error_policy, patch_status};
use crate::conditions::{self, Cond};
use crate::context::Context;
use crate::error::Result;

pub async fn run(ctx: Arc<Context>) {
    let client = ctx.client.clone();
    let controller = Controller::new(Api::<CloudflareAccount>::all(client.clone()), watcher::Config::default());
    let accounts = controller.store();
    controller
        // Rotating the token in the Secret re-verifies right away.
        .watches_stream(
            watcher(Api::<PartialObjectMeta<Secret>>::all(client), watcher::Config::default()).touched_objects(),
            move |secret: PartialObjectMeta<Secret>| {
                let (ns, name) = (secret.namespace().unwrap_or_default(), secret.name_any());
                accounts
                    .state()
                    .into_iter()
                    .filter(|a| {
                        a.spec.credentials_secret_ref.namespace == ns && a.spec.credentials_secret_ref.name == name
                    })
                    .map(|a| ObjectRef::from_obj(&*a))
                    .collect::<Vec<_>>()
            },
        )
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|_| async {})
        .await;
}

pub async fn reconcile(account: Arc<CloudflareAccount>, ctx: Arc<Context>) -> Result<Action> {
    let api: Api<CloudflareAccount> = Api::all(ctx.client.clone());
    let generation = account.metadata.generation;
    let mut status = account.status.clone().unwrap_or_default();
    status.observed_generation = generation;

    // Resolved inline from the Secret's namespace: allowedNamespaces is about who may refer to
    // the account, not the account itself.
    let r = &account.spec.credentials_secret_ref;
    let cf = CloudflareRef {
        account_id: account.spec.account_id.clone(),
        account_name: account.spec.account_name.clone(),
        credentials_secret_ref: Some(SecretKeyRef { name: r.name.clone(), key: r.key.clone() }),
        ..Default::default()
    };
    let ready = match ctx.account(&cf, &r.namespace).await {
        Err(e) => Cond::fail(types::READY, e.reason, e.message),
        // Zone: Read is needed for routes anyway, and listing zones proves the token works for
        // this account (an accountName was already resolved through the API).
        Ok(a) => match a.api.list_zones(&a.id).await {
            Ok(zones) => {
                status.account_id = Some(a.id.clone());
                Cond::ok(
                    types::READY,
                    reasons::VERIFIED,
                    format!("account {}; the token can read {} zone(s)", a.id, zones.len()),
                )
            }
            Err(e) => conditions::cf_cond(types::READY, "verifying the token (listing zones)", &e),
        },
    };
    let ok = ready.status;
    conditions::set(&mut status.conditions, ready, generation);
    patch_status(&api, &account.name_any(), account.status.as_ref(), &status).await?;
    Ok(if ok { Action::requeue(ctx.resync_jittered()) } else { Action::requeue(Duration::from_secs(60)) })
}
