//! Helpers shared by the cluster, live API and end-to-end tests.
#![allow(dead_code)]

use std::future::Future;
use std::time::Duration;

use k8s_openapi::api::core::v1::Namespace;
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::ResourceExt;
use kube::api::{Api, DeleteParams, ListParams, Patch, PatchParams};
use serde_json::{Value, json};
use tunnelgate_api::v1alpha1::{
    AccessApplication, AccessPolicy, AccessServiceToken, CloudflareAccount, Tunnel, TunnelRoute,
};
use tunnelgate_cf::CloudflareApi;
use tunnelgate_cf::types::DnsRecordFilter;

/// Polls `f` every 250 ms until it returns `Some`, for up to 60 s.
pub async fn eventually<T, F, Fut>(what: &str, f: F) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Option<T>>,
{
    eventually_for(what, Duration::from_secs(60), f).await
}

pub async fn eventually_for<T, F, Fut>(what: &str, timeout: Duration, mut f: F) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Option<T>>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(v) = f().await {
            return v;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("timed out waiting for {what}");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// `(status, reason, message)` of a condition in a status value.
pub fn condition(status: &Option<Value>, type_: &str) -> Option<(String, String, String)> {
    let c = status.as_ref()?.get("conditions")?.as_array()?.iter().find(|c| c["type"] == type_)?;
    Some((
        c["status"].as_str()?.to_owned(),
        c["reason"].as_str()?.to_owned(),
        c["message"].as_str().unwrap_or_default().to_owned(),
    ))
}

pub async fn install_crds(client: &kube::Client) {
    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
    let pp = PatchParams::apply("tunnelgate-tests").force();
    for crd in tunnelgate_api::crds() {
        crds.patch(&crd.name_any(), &pp, &Patch::Apply(&crd)).await.unwrap();
    }
    for crd in tunnelgate_api::crds() {
        let name = crd.name_any();
        eventually(&format!("CRD {name} established"), || {
            let crds = crds.clone();
            let name = name.clone();
            async move {
                let c = crds.get(&name).await.ok()?;
                c.status?.conditions?.iter().any(|c| c.type_ == "Established" && c.status == "True").then_some(())
            }
        })
        .await;
    }
}

/// Removes namespaces and CloudflareAccounts starting with `prefix` left behind by earlier runs
/// that failed half-way. Their objects still carry our finalizers; without this the controllers
/// started afterwards would reconcile them too.
pub async fn purge_leftovers(client: &kube::Client, prefix: &str) {
    let namespaces: Api<Namespace> = Api::all(client.clone());
    let accounts: Api<CloudflareAccount> = Api::all(client.clone());
    for a in accounts.list(&ListParams::default()).await.unwrap() {
        if a.name_any().starts_with(prefix) {
            let _ = accounts.delete(&a.name_any(), &DeleteParams::default()).await;
        }
    }
    for ns in namespaces.list(&ListParams::default()).await.unwrap() {
        let ns = ns.name_any();
        if !ns.starts_with(prefix) {
            continue;
        }
        unfinalize_all(client, &ns).await;
        let _ = namespaces.delete(&ns, &DeleteParams::default()).await;
    }
    // Wait until they're gone, or the controllers would finalize them again.
    eventually_for("leftover test namespaces gone", Duration::from_secs(120), || async {
        let left = namespaces.list(&ListParams::default()).await.ok()?;
        (!left.iter().any(|n| n.name_any().starts_with(prefix))).then_some(())
    })
    .await;
}

/// Strips our finalizers from every tunnelgate object in a namespace.
pub async fn unfinalize_all(client: &kube::Client, ns: &str) {
    unfinalize::<Tunnel>(client, ns).await;
    unfinalize::<TunnelRoute>(client, ns).await;
    unfinalize::<AccessPolicy>(client, ns).await;
    unfinalize::<AccessApplication>(client, ns).await;
    unfinalize::<AccessServiceToken>(client, ns).await;
}

pub async fn unfinalize<K>(client: &kube::Client, ns: &str)
where
    K: kube::Resource<Scope = kube::core::NamespaceResourceScope, DynamicType = ()>
        + Clone
        + serde::de::DeserializeOwned
        + std::fmt::Debug,
{
    let api: Api<K> = Api::namespaced(client.clone(), ns);
    let patch = Patch::Merge(json!({ "metadata": { "finalizers": null } }));
    for o in api.list(&ListParams::default()).await.unwrap() {
        api.patch(&o.name_any(), &PatchParams::default(), &patch).await.unwrap();
    }
}

pub async fn apply<K>(api: &Api<K>, obj: Value) -> K
where
    K: kube::Resource + Clone + serde::de::DeserializeOwned + serde::Serialize + std::fmt::Debug,
{
    let name = obj["metadata"]["name"].as_str().unwrap().to_owned();
    api.patch(&name, &PatchParams::apply("tunnelgate-tests").force(), &Patch::Apply(&obj)).await.unwrap()
}

pub fn uuid_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    format!("{:x}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() % 0xffffff)
}

/// `(status, reason, message)` of a condition on any object.
pub async fn cond<K>(api: &Api<K>, name: &str, type_: &str) -> Option<(String, String, String)>
where
    K: kube::Resource + Clone + serde::de::DeserializeOwned + serde::Serialize + std::fmt::Debug,
{
    let obj = serde_json::to_value(api.get(name).await.ok()?).ok()?;
    condition(&obj.get("status").cloned(), type_)
}

pub async fn wait_cond<K>(api: &Api<K>, name: &str, type_: &str, want: &str) -> (String, String, String)
where
    K: kube::Resource + Clone + serde::de::DeserializeOwned + serde::Serialize + std::fmt::Debug,
{
    wait_cond_for(api, name, type_, want, Duration::from_secs(60)).await
}

pub async fn wait_cond_for<K>(
    api: &Api<K>,
    name: &str,
    type_: &str,
    want: &str,
    timeout: Duration,
) -> (String, String, String)
where
    K: kube::Resource + Clone + serde::de::DeserializeOwned + serde::Serialize + std::fmt::Debug,
{
    eventually_for(&format!("{name} {type_}={want}"), timeout, || async {
        let c = cond(api, name, type_).await?;
        (c.0 == want).then_some(c)
    })
    .await
}

pub async fn status_field<K>(api: &Api<K>, name: &str, field: &str) -> Option<String>
where
    K: kube::Resource + Clone + serde::de::DeserializeOwned + serde::Serialize + std::fmt::Debug,
{
    let obj = serde_json::to_value(api.get(name).await.ok()?).ok()?;
    obj["status"][field].as_str().map(str::to_owned)
}

/// Deletes the Cloudflare objects whose names start with `prefix`, and nothing else.
pub async fn cloudflare_cleanup(cf: &dyn CloudflareApi, acc: &str, zone_id: &str, prefix: &str) {
    for a in cf.list_access_apps(acc).await.unwrap_or_default().iter().filter(|a| a.name.starts_with(prefix)) {
        let _ = cf.delete_access_app(acc, &a.id).await;
    }
    for p in cf.list_access_policies(acc).await.unwrap_or_default().iter().filter(|p| p.name.starts_with(prefix)) {
        let _ = cf.delete_access_policy(acc, &p.id).await;
    }
    for t in cf.list_service_tokens(acc).await.unwrap_or_default().iter().filter(|t| t.name.starts_with(prefix)) {
        let _ = cf.delete_service_token(acc, &t.id).await;
    }
    let filter = DnsRecordFilter::default();
    for r in
        cf.list_dns_records(zone_id, &filter).await.unwrap_or_default().iter().filter(|r| r.name.starts_with(prefix))
    {
        let _ = cf.delete_dns_record(zone_id, &r.id).await;
    }
    for t in cf.list_tunnels(acc, None).await.unwrap_or_default().iter().filter(|t| t.name.starts_with(prefix)) {
        let _ = cf.cleanup_tunnel_connections(acc, &t.id).await;
        let _ = cf.delete_tunnel(acc, &t.id).await;
    }
}

/// Names of Cloudflare objects starting with `prefix`; listing errors are reported as entries.
pub async fn cloudflare_leftovers(cf: &dyn CloudflareApi, acc: &str, zone_id: &str, prefix: &str) -> Vec<String> {
    fn names<T>(what: &str, prefix: &str, r: tunnelgate_cf::Result<Vec<T>>, name: impl Fn(T) -> String) -> Vec<String> {
        match r {
            Ok(v) => v.into_iter().map(name).filter(|n| n.starts_with(prefix)).collect(),
            Err(err) => vec![format!("(could not list {what}: {err})")],
        }
    }
    let mut out = names("apps", prefix, cf.list_access_apps(acc).await, |a| a.name);
    out.extend(names("policies", prefix, cf.list_access_policies(acc).await, |p| p.name));
    out.extend(names("service tokens", prefix, cf.list_service_tokens(acc).await, |t| t.name));
    out.extend(names("DNS records", prefix, cf.list_dns_records(zone_id, &DnsRecordFilter::default()).await, |r| {
        r.name
    }));
    out.extend(names("tunnels", prefix, cf.list_tunnels(acc, None).await, |t| t.name));
    out
}
