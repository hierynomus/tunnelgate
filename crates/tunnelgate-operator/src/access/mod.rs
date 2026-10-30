//! Access controllers: reusable policies, applications and service tokens.
//!
//! Each resource owns one Cloudflare object, named for humans with the ownership suffix
//! (` [tunnelgate:<clusterId[:8]>]`) and identified by the ID in status. Objects without the
//! suffix are never updated or deleted. The ID is written to status right after creation; if that
//! write is lost, the next reconcile adopts the object by its exact name unless another resource
//! already claims it.
//!
//! Access references (application → policy, policy → service token) may cross namespaces without
//! a grant: they reuse a Cloudflare object, they don't give access to anything the referring
//! resource's owner couldn't configure themselves. Both sides must use the same account.

/// Unwraps a Cloudflare call inside a function returning `Result<Result<_, Cond>>`: errors
/// become a failed `Ready` condition.
macro_rules! cf {
    ($call:expr, $what:expr) => {
        match $call.await {
            Ok(v) => v,
            Err(e) => return Ok(Err($crate::conditions::cf_cond(tunnelgate_api::conditions::types::READY, $what, &e))),
        }
    };
}

pub mod application;
pub mod policy;
pub mod token;

use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Resource, ResourceExt};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tracing::{info, warn};
use tunnelgate_api::v1alpha1::HasConditions;
use tunnelgate_render::marker::marked_name;

use crate::conditions;
use crate::context::Context;
use crate::error::{Error, Result};
use crate::tunnel::skip_cleanup_annotation;

/// Name shown in Cloudflare: `spec.name` (default `<namespace>/<name>`) plus the ownership suffix.
pub fn display_name<K: ResourceExt>(spec_name: Option<&str>, obj: &K, cluster_id: &str) -> String {
    let base = spec_name
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{}/{}", obj.namespace().unwrap_or_default(), obj.name_any()));
    marked_name(&base, cluster_id)
}

/// Writes `new` as the status unless it only differs from `old` in condition transition times.
pub async fn patch_status<K, S>(api: &Api<K>, name: &str, old: Option<&S>, new: &S) -> Result<()>
where
    K: Resource + Clone + DeserializeOwned + Debug,
    S: Serialize + HasConditions,
{
    let without_conditions = |s: &S| {
        let mut v = serde_json::to_value(s).unwrap_or(Value::Null);
        if let Some(o) = v.as_object_mut() {
            o.remove("conditions");
        }
        v
    };
    if let Some(old) = old
        && conditions::same(old.conditions(), new.conditions())
        && without_conditions(old) == without_conditions(new)
    {
        return Ok(());
    }
    api.patch_status(name, &PatchParams::default(), &Patch::Merge(json!({ "status": new }))).await?;
    Ok(())
}

/// Whether a resource of the same kind other than `me` has `id` recorded in its status.
pub async fn claimed_by_other<K>(ctx: &Context, me: &K, id: &str, id_of: impl Fn(&K) -> Option<String>) -> Result<bool>
where
    K: Resource<DynamicType = ()> + Clone + DeserializeOwned + Debug,
{
    let all: Api<K> = Api::all(ctx.client.clone());
    Ok(all.list(&ListParams::default()).await?.iter().any(|o| o.uid() != me.uid() && id_of(o).as_deref() == Some(id)))
}

/// Whether deletion should leave the Cloudflare object in place.
pub fn skip_cleanup<K: ResourceExt>(obj: &K) -> bool {
    obj.annotations().get(&skip_cleanup_annotation()).is_some_and(|v| v == "true")
}

/// Requeue after a successful or failed apply.
pub fn requeue(ctx: &Context, ok: bool) -> Action {
    if ok { Action::requeue(ctx.resync_jittered()) } else { Action::requeue(Duration::from_secs(30)) }
}

pub fn error_policy<K: Resource<DynamicType = ()> + ResourceExt>(
    obj: Arc<K>,
    error: &Error,
    _ctx: Arc<Context>,
) -> Action {
    let kind = K::kind(&());
    match error {
        Error::Pending(msg) => {
            info!(%kind, name = %obj.name_any(), namespace = ?obj.namespace(), "{msg}");
            Action::requeue(Duration::from_secs(5))
        }
        _ => {
            warn!(%kind, name = %obj.name_any(), namespace = ?obj.namespace(), error = %error, "reconcile failed");
            Action::requeue(Duration::from_secs(30))
        }
    }
}
