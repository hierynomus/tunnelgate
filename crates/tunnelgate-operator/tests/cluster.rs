//! Controller tests: the controllers run in this process against a real API server (k3d, see
//! `mise run test-cluster`) and the fake Cloudflare API. Skipped unless TUNNELGATE_CLUSTER_TESTS=1.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Namespace, Secret, Service};
use kube::ResourceExt;
use kube::api::{Api, DeleteParams, DynamicObject, ListParams, Patch, PatchParams, PostParams};
use secrecy::SecretString;
use serde_json::{Value, json};
use tunnelgate_api::v1alpha1::{
    AccessApplication, AccessPolicy, AccessServiceToken, CloudflareAccount, Tunnel, TunnelRoute,
};
use tunnelgate_cf::{ClientConfig, CloudflareApi};
use tunnelgate_cf_fake::{ACCOUNT_ID, FakeCloudflare, TOKEN};
use tunnelgate_operator::context::{CloudflareFactory, Settings};
use tunnelgate_operator::error::Result;

fn enabled() -> bool {
    std::env::var("TUNNELGATE_CLUSTER_TESTS").is_ok_and(|v| v == "1")
}

struct FakeFactory(String);

impl CloudflareFactory for FakeFactory {
    fn client(&self, token: SecretString) -> Result<Arc<dyn CloudflareApi>> {
        let config = ClientConfig {
            base_url: self.0.clone(),
            initial_backoff: Duration::from_millis(5),
            max_backoff: Duration::from_millis(20),
            rate_limit: None,
            ..Default::default()
        };
        Ok(Arc::new(tunnelgate_cf::Client::with_config(token, config)?))
    }
}

fn route_status(r: &TunnelRoute) -> Option<Value> {
    r.status.as_ref().map(|s| serde_json::to_value(s).unwrap())
}

fn tunnel_status(t: &Tunnel) -> Option<Value> {
    t.status.as_ref().map(|s| serde_json::to_value(s).unwrap())
}

fn spawn_operator(
    client: &kube::Client,
    cluster_id: &str,
    fake: &FakeCloudflare,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    let settings = Settings {
        resync: Duration::from_secs(3600),
        default_connector_replicas: 1,
        not_ready_requeue: Duration::from_millis(500),
        ..Default::default()
    };
    tokio::spawn(tunnelgate_operator::run(
        client.clone(),
        settings,
        cluster_id.to_owned(),
        Arc::new(FakeFactory(fake.base_url())),
    ))
}

/// Starts the controllers against the fake API in a fresh namespace with a credentials Secret.
async fn start() -> Option<(kube::Client, FakeCloudflare, String, String, tokio::task::JoinHandle<anyhow::Result<()>>)>
{
    if !enabled() {
        eprintln!("skipped: set TUNNELGATE_CLUSTER_TESTS=1 (mise run test-cluster)");
        return None;
    }
    let _ = tracing_subscriber::fmt().with_env_filter("info,kube=warn").with_test_writer().try_init();
    let client = kube::Client::try_default().await.expect("KUBECONFIG for the k3d test cluster");
    install_crds(&client).await;
    purge_leftovers(&client, "tg-test-").await;

    let fake = FakeCloudflare::start().await;
    let cluster_id = tunnelgate_operator::cluster_id(&client).await.unwrap();
    let operator = spawn_operator(&client, &cluster_id, &fake);

    let ns = format!("tg-test-{}", &uuid_suffix());
    let namespaces: Api<Namespace> = Api::all(client.clone());
    namespaces
        .create(&PostParams::default(), &serde_json::from_value(json!({ "metadata": { "name": ns } })).unwrap())
        .await
        .unwrap();
    apply(
        &Api::<Secret>::namespaced(client.clone(), &ns),
        json!({
            "apiVersion": "v1", "kind": "Secret", "metadata": { "name": "cloudflare-api" },
            "stringData": { "CLOUDFLARE_API_TOKEN": TOKEN },
        }),
    )
    .await;
    Some((client, fake, cluster_id, ns, operator))
}

#[tokio::test]
async fn tunnel_routes_dns_and_cleanup() {
    let Some((client, fake, cluster_id, ns, operator)) = start().await else { return };
    let namespaces: Api<Namespace> = Api::all(client.clone());
    let secrets: Api<Secret> = Api::namespaced(client.clone(), &ns);
    let services: Api<Service> = Api::namespaced(client.clone(), &ns);
    let tunnels: Api<Tunnel> = Api::namespaced(client.clone(), &ns);
    let routes: Api<TunnelRoute> = Api::namespaced(client.clone(), &ns);

    apply(
        &services,
        json!({
            "apiVersion": "v1", "kind": "Service", "metadata": { "name": "demo" },
            "spec": { "selector": { "app": "demo" }, "ports": [{ "port": 80 }] },
        }),
    )
    .await;

    // A Tunnel: created in Cloudflare, token Secret and connector Deployment in the cluster.
    apply(
        &tunnels,
        json!({
            "apiVersion": "tunnelgate.geeko.me/v1alpha1", "kind": "Tunnel", "metadata": { "name": "main" },
            "spec": { "cloudflare": { "accountId": ACCOUNT_ID, "credentialsSecretRef": { "name": "cloudflare-api" } } },
        }),
    )
    .await;
    let tunnel_id =
        eventually("tunnel ID in status", || async { tunnels.get("main").await.ok()?.status?.tunnel_id }).await;
    assert_eq!(fake.live_tunnels().len(), 1);
    assert_eq!(fake.live_tunnels()[0].name, format!("{ns}-main-{}", &cluster_id[..8]));
    let token = eventually("token Secret", || async { secrets.get_opt("main-token").await.ok()? }).await;
    assert!(token.data.unwrap()["token"].0.ends_with(tunnel_id.as_bytes()));
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), &ns);
    eventually("cloudflared Deployment", || async { deployments.get_opt("main-cloudflared").await.ok()? }).await;

    let (status, reason, _) = eventually("ConnectorReady=False", || async {
        condition(&tunnel_status(&tunnels.get("main").await.ok()?), "ConnectorReady")
    })
    .await;
    assert_eq!((status.as_str(), reason.as_str()), ("False", "NoConnections"));
    fake.set_connections(&tunnel_id, 1);
    eventually("tunnel Ready", || async {
        let (s, _, _) = condition(&tunnel_status(&tunnels.get("main").await.ok()?), "Ready")?;
        (s == "True").then_some(())
    })
    .await;

    // A route: config entry, DNS record, Ready.
    apply(
        &routes,
        json!({
            "apiVersion": "tunnelgate.geeko.me/v1alpha1", "kind": "TunnelRoute", "metadata": { "name": "demo" },
            "spec": { "tunnelRef": { "name": "main" }, "hostname": format!("demo-{ns}.example.org"),
                      "service": { "backendRef": { "name": "demo", "port": 80 } } },
        }),
    )
    .await;
    let host = format!("demo-{ns}.example.org");
    wait_route(&routes, "demo", "Ready", "True").await;
    let config = fake.live_tunnels()[0].config.clone().unwrap();
    assert_eq!(config["ingress"][0]["hostname"], json!(host));
    assert_eq!(config["ingress"][0]["service"], json!(format!("http://demo.{ns}.svc:80")));
    assert_eq!(config["ingress"][1]["service"], json!("http_status:404"));
    let records = fake.dns_records("example.org");
    let record = records.iter().find(|r| r["name"] == json!(host)).expect("DNS record");
    assert_eq!(record["content"], json!(format!("{tunnel_id}.cfargotunnel.com")));
    assert_eq!(record["proxied"], json!(true));
    assert_eq!(record["comment"], json!(format!("tunnelgate:{cluster_id}/{ns}/Tunnel/main")));
    let route = routes.get("demo").await.unwrap();
    assert!(route.finalizers().contains(&"tunnelgate.geeko.me/route".to_owned()));

    // Same hostname on a newer route: rejected, the older one keeps working.
    apply(
        &routes,
        json!({
            "apiVersion": "tunnelgate.geeko.me/v1alpha1", "kind": "TunnelRoute", "metadata": { "name": "demo-dup" },
            "spec": { "tunnelRef": { "name": "main" }, "hostname": host, "service": { "status": 503 } },
        }),
    )
    .await;
    let (_, reason, msg) = wait_route(&routes, "demo-dup", "Accepted", "False").await;
    assert_eq!(reason, "Conflict");
    assert!(msg.contains(&format!("{ns}/demo")), "{msg}");

    // Missing backend.
    apply(
        &routes,
        json!({
            "apiVersion": "tunnelgate.geeko.me/v1alpha1", "kind": "TunnelRoute", "metadata": { "name": "nobackend" },
            "spec": { "tunnelRef": { "name": "main" }, "hostname": format!("nb-{ns}.example.org"),
                      "service": { "backendRef": { "name": "missing", "port": 80 } } },
        }),
    )
    .await;
    let (_, reason, _) = wait_route(&routes, "nobackend", "Accepted", "False").await;
    assert_eq!(reason, "BackendNotFound");

    // A foreign DNS record blocks a hostname until adopt: true.
    let taken = format!("taken-{ns}.example.org");
    fake.add_dns_record("example.org", json!({ "name": taken, "type": "A", "content": "203.0.113.7" }));
    let taken_route = |adopt: bool| {
        json!({
            "apiVersion": "tunnelgate.geeko.me/v1alpha1", "kind": "TunnelRoute", "metadata": { "name": "taken" },
            "spec": { "tunnelRef": { "name": "main" }, "hostname": taken, "service": { "status": 200 }, "dns": { "adopt": adopt } },
        })
    };
    apply(&routes, taken_route(false)).await;
    let (_, reason, _) = wait_route(&routes, "taken", "DNSReady", "False").await;
    assert_eq!(reason, "Conflict");
    assert!(fake.dns_records("example.org").iter().any(|r| r["name"] == json!(taken) && r["type"] == "A"));
    apply(&routes, taken_route(true)).await;
    wait_route(&routes, "taken", "DNSReady", "True").await;
    let taken_records: Vec<Value> =
        fake.dns_records("example.org").into_iter().filter(|r| r["name"] == json!(taken)).collect();
    assert_eq!(taken_records.len(), 1);
    assert_eq!(taken_records[0]["type"], "CNAME");

    // Steady state: a reconcile without changes writes nothing to Cloudflare.
    tokio::time::sleep(Duration::from_secs(2)).await;
    fake.clear_log();
    tunnels
        .patch(
            "main",
            &PatchParams::default(),
            &Patch::Merge(json!({ "metadata": { "annotations": { "test/poke": "1" } } })),
        )
        .await
        .unwrap();
    eventually("a reconcile after the poke", || async {
        fake.requests().iter().any(|r| r.path.ends_with("/configurations")).then_some(())
    })
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(fake.writes(), vec![], "no writes in steady state");

    // Deleting a route releases its hostname: the newer duplicate takes over the same record.
    routes.delete("demo", &DeleteParams::default()).await.unwrap();
    eventually("route gone", || async { routes.get_opt("demo").await.ok()?.is_none().then_some(()) }).await;
    wait_route(&routes, "demo-dup", "Ready", "True").await;
    assert!(fake.dns_records("example.org").iter().any(|r| r["name"] == json!(host)));
    let config = fake.live_tunnels()[0].config.clone().unwrap();
    assert!(config["ingress"].as_array().unwrap().iter().any(|r| r["service"] == json!("http_status:503")));

    // Deleting the last route for a hostname removes its record and config entry.
    routes.delete("taken", &DeleteParams::default()).await.unwrap();
    eventually("route gone", || async { routes.get_opt("taken").await.ok()?.is_none().then_some(()) }).await;
    assert!(!fake.dns_records("example.org").iter().any(|r| r["name"] == json!(taken)));
    let config = fake.live_tunnels()[0].config.clone().unwrap();
    assert!(!config["ingress"].as_array().unwrap().iter().any(|r| r["hostname"] == json!(taken)));

    // Every configuration PUT so far carried a change. Reconciles on a cached Tunnel whose status
    // lags behind our own patch must not mistake our previous PUT for an edit elsewhere.
    assert_eq!(fake.live_tunnels()[0].redundant_config_puts, 0, "PUTs of unchanged configuration");

    // Deleting the Tunnel removes DNS records and the Cloudflare tunnel.
    tunnels.delete("main", &DeleteParams::default()).await.unwrap();
    eventually("tunnel gone", || async { tunnels.get_opt("main").await.ok()?.is_none().then_some(()) }).await;
    assert!(fake.live_tunnels().is_empty());
    let marker = format!("tunnelgate:{cluster_id}/{ns}/");
    assert!(
        !fake.dns_records("example.org").iter().any(|r| r["comment"].as_str().is_some_and(|c| c.starts_with(&marker)))
    );
    // Remaining routes report the missing tunnel and can be deleted.
    let (_, reason, _) = wait_route(&routes, "demo-dup", "Accepted", "False").await;
    assert_eq!(reason, "TunnelNotFound");
    routes.delete("demo-dup", &DeleteParams::default()).await.unwrap();
    eventually("route without tunnel deleted", || async {
        routes.get_opt("demo-dup").await.ok()?.is_none().then_some(())
    })
    .await;

    // Deleting the namespace deletes the credentials Secret along with the Tunnel; cleanup still
    // removes the Cloudflare tunnel with the credentials it last used, and the namespace goes away.
    apply(
        &tunnels,
        json!({
            "apiVersion": "tunnelgate.geeko.me/v1alpha1", "kind": "Tunnel", "metadata": { "name": "lab2" },
            "spec": { "cloudflare": { "accountId": ACCOUNT_ID, "credentialsSecretRef": { "name": "cloudflare-api" } } },
        }),
    )
    .await;
    eventually("lab2 tunnel ID in status", || async { tunnels.get("lab2").await.ok()?.status?.tunnel_id }).await;
    assert_eq!(fake.live_tunnels().len(), 1);
    namespaces.delete(&ns, &DeleteParams::default()).await.unwrap();
    eventually("namespace gone", || async { namespaces.get_opt(&ns).await.ok()?.is_none().then_some(()) }).await;
    assert!(fake.live_tunnels().is_empty());
    operator.abort();
}

async fn wait_route(routes: &Api<TunnelRoute>, name: &str, type_: &str, want: &str) -> (String, String, String) {
    eventually(&format!("route {name} {type_}={want}"), || async {
        let c = condition(&route_status(&routes.get(name).await.ok()?), type_)?;
        (c.0 == want).then_some(c)
    })
    .await
}

#[tokio::test]
async fn access_policies_applications_and_service_tokens() {
    let Some((client, fake, cluster_id, ns, operator)) = start().await else { return };
    let suffix = format!(" [tunnelgate:{}]", &cluster_id[..8]);
    let accounts: Api<CloudflareAccount> = Api::all(client.clone());
    let tokens: Api<AccessServiceToken> = Api::namespaced(client.clone(), &ns);
    let policies: Api<AccessPolicy> = Api::namespaced(client.clone(), &ns);
    let apps: Api<AccessApplication> = Api::namespaced(client.clone(), &ns);
    let secrets: Api<Secret> = Api::namespaced(client.clone(), &ns);
    let account = format!("{ns}-account");
    let host = format!("rancher-{ns}.example.org");

    // A CloudflareAccount verifies the token; everything below refers to it.
    apply(
        &accounts,
        json!({
            "apiVersion": "tunnelgate.geeko.me/v1alpha1", "kind": "CloudflareAccount", "metadata": { "name": account },
            "spec": {
                "accountId": ACCOUNT_ID,
                "credentialsSecretRef": { "name": "cloudflare-api", "namespace": ns },
            },
        }),
    )
    .await;
    let (_, reason, _) = wait_cond(&accounts, &account, "Ready", "True").await;
    assert_eq!(reason, "Verified");
    assert_eq!(status_field(&accounts, &account, "accountId").await.as_deref(), Some(ACCOUNT_ID));
    let cf = json!({ "accountRef": account });

    // A service token: credentials in a Secret owned by the resource.
    apply(
        &tokens,
        json!({
            "apiVersion": "tunnelgate.geeko.me/v1alpha1", "kind": "AccessServiceToken", "metadata": { "name": "ci" },
            "spec": { "cloudflare": cf, "secretName": "ci-token" },
        }),
    )
    .await;
    wait_cond(&tokens, "ci", "Ready", "True").await;
    let (expiring, _, _) = cond(&tokens, "ci", "Expiring").await.unwrap();
    assert_eq!(expiring, "False");
    let token_id = status_field(&tokens, "ci", "tokenId").await.unwrap();
    let secret = secrets.get("ci-token").await.unwrap();
    let data = secret.data.clone().unwrap();
    assert_eq!(
        String::from_utf8(data["CF-Access-Client-Id"].0.clone()).unwrap(),
        status_field(&tokens, "ci", "clientId").await.unwrap()
    );
    assert!(!data["CF-Access-Client-Secret"].0.is_empty());
    assert_eq!(secret.owner_references()[0].name, "ci");
    let cf_tokens = fake.service_tokens();
    assert_eq!(cf_tokens.len(), 1);
    assert_eq!(cf_tokens[0]["name"], json!(format!("{ns}/ci{suffix}")));

    // Policies: one for admins, one for the CI token, one that draws a warning.
    for (name, spec) in [
        ("admins", json!({ "decision": "allow", "include": [{ "emails": ["admin@example.com"] }] })),
        ("ci-only", json!({ "decision": "non_identity", "include": [{ "serviceTokens": [{ "name": "ci" }] }] })),
        ("anyone", json!({ "decision": "allow", "include": [{ "everyone": true }] })),
    ] {
        let mut spec = spec;
        spec["cloudflare"] = cf.clone();
        apply(
            &policies,
            json!({
                "apiVersion": "tunnelgate.geeko.me/v1alpha1", "kind": "AccessPolicy", "metadata": { "name": name },
                "spec": spec,
            }),
        )
        .await;
    }
    for name in ["admins", "ci-only", "anyone"] {
        wait_cond(&policies, name, "Ready", "True").await;
    }
    let (_, reason, _) = wait_cond(&policies, "anyone", "Warning", "True").await;
    assert_eq!(reason, "AllowEveryone");
    assert!(cond(&policies, "admins", "Warning").await.is_none());
    let ci_policy = status_field(&policies, "ci-only", "policyId").await.unwrap();
    let rules =
        |id: &str| fake.access_policies().into_iter().find(|p| p["id"] == json!(id)).unwrap()["include"].clone();
    assert_eq!(rules(&ci_policy), json!([{ "service_token": { "token_id": token_id } }]));

    // Applications: the whole host for admins, agent paths for the CI token.
    for (name, destinations, refs) in [
        ("ui", json!([host]), json!([{ "name": "admins" }, { "name": "anyone" }])),
        ("agents", json!([format!("{host}/v3/connect"), format!("{host}/ping")]), json!([{ "name": "ci-only" }])),
    ] {
        apply(
            &apps,
            json!({
                "apiVersion": "tunnelgate.geeko.me/v1alpha1", "kind": "AccessApplication", "metadata": { "name": name },
                "spec": { "cloudflare": cf, "destinations": destinations, "policies": refs },
            }),
        )
        .await;
    }
    wait_cond(&apps, "ui", "Ready", "True").await;
    wait_cond(&apps, "agents", "Ready", "True").await;
    assert!(status_field(&apps, "ui", "aud").await.is_some());
    let app = |id: &str| fake.access_apps().into_iter().find(|a| a["id"] == json!(id)).unwrap();
    let ui_id = status_field(&apps, "ui", "applicationId").await.unwrap();
    let ui = app(&ui_id);
    assert_eq!(ui["name"], json!(format!("{ns}/ui{suffix}")));
    let precedence: Vec<_> = ui["policies"].as_array().unwrap().iter().map(|p| p["precedence"].clone()).collect();
    assert_eq!(precedence, vec![json!(1), json!(2)]);
    assert_eq!(ui["policies"][0]["id"], json!(status_field(&policies, "admins", "policyId").await.unwrap()));
    let agents_id = status_field(&apps, "agents", "applicationId").await.unwrap();
    assert_eq!(
        app(&agents_id)["destinations"],
        json!([
            { "type": "public", "uri": format!("{host}/v3/connect") },
            { "type": "public", "uri": format!("{host}/ping") },
        ])
    );

    // Steady state: reconciles without changes write nothing.
    tokio::time::sleep(Duration::from_secs(2)).await;
    fake.clear_log();
    let poke = Patch::Merge(json!({ "metadata": { "annotations": { "test/poke": "1" } } }));
    apps.patch("agents", &PatchParams::default(), &poke).await.unwrap();
    policies.patch("admins", &PatchParams::default(), &poke).await.unwrap();
    tokens.patch("ci", &PatchParams::default(), &poke).await.unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!fake.requests().is_empty(), "the pokes caused reconciles");
    assert_eq!(fake.writes(), vec![], "no writes in steady state");

    // Changing destinations updates the application in place.
    apps.patch(
        "agents",
        &PatchParams::default(),
        &Patch::Merge(
            json!({ "spec": { "destinations": [format!("{host}/v3/connect"), format!("{host}/v3/import")] } }),
        ),
    )
    .await
    .unwrap();
    eventually("agents destinations updated", || async {
        (app(&agents_id)["destinations"][1]["uri"] == json!(format!("{host}/v3/import"))).then_some(())
    })
    .await;
    assert_eq!(status_field(&apps, "agents", "applicationId").await.unwrap(), agents_id);

    // Losing the Secret rotates the token; the policy follows the new token ID.
    secrets.delete("ci-token", &DeleteParams::default()).await.unwrap();
    let new_token_id = eventually("token rotated", || async {
        status_field(&tokens, "ci", "tokenId").await.filter(|id| *id != token_id)
    })
    .await;
    let (_, reason, _) = wait_cond(&tokens, "ci", "Ready", "True").await;
    assert_eq!(reason, "SecretLostRotated");
    let secret = eventually("Secret rewritten", || async { secrets.get_opt("ci-token").await.ok()? }).await;
    assert_eq!(secret.annotations()["tunnelgate.geeko.me/token-id"], new_token_id);
    eventually("policy uses the new token", || async {
        (rules(&ci_policy) == json!([{ "service_token": { "token_id": new_token_id } }])).then_some(())
    })
    .await;
    // Cloudflare refuses to delete a token a policy includes, so the old one goes after the switch.
    eventually("the old token is deleted", || async {
        let ids: Vec<_> = fake.service_tokens().iter().map(|t| t["id"].as_str().unwrap().to_owned()).collect();
        (ids == vec![new_token_id.clone()]).then_some(())
    })
    .await;

    // A token close to expiry reports Expiring.
    let soon = k8s_openapi::jiff::Timestamp::now()
        .checked_add(k8s_openapi::jiff::SignedDuration::from_hours(24))
        .unwrap()
        .strftime("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    fake.set_service_token_expiry(&new_token_id, &soon);
    tokens
        .patch(
            "ci",
            &PatchParams::default(),
            &Patch::Merge(json!({ "metadata": { "annotations": { "test/poke": "2" } } })),
        )
        .await
        .unwrap();
    let (_, reason, _) = wait_cond(&tokens, "ci", "Expiring", "True").await;
    assert_eq!(reason, "ExpiresSoon");
    assert_eq!(cond(&tokens, "ci", "Ready").await.unwrap().0, "True");

    // A policy still attached to an application waits for it.
    policies.delete("admins", &DeleteParams::default()).await.unwrap();
    let (_, reason, message) = wait_cond(&policies, "admins", "Ready", "False").await;
    assert_eq!(reason, "Pending");
    assert!(message.contains(&format!("{ns}/ui")), "{message}");
    apps.delete("ui", &DeleteParams::default()).await.unwrap();
    eventually("admins policy gone", || async { policies.get_opt("admins").await.ok()?.is_none().then_some(()) }).await;

    // Deleting everything removes it from Cloudflare.
    for name in ["agents"] {
        apps.delete(name, &DeleteParams::default()).await.unwrap();
    }
    // A token still included by a policy waits for it.
    tokens.delete("ci", &DeleteParams::default()).await.unwrap();
    let (_, reason, message) = wait_cond(&tokens, "ci", "Ready", "False").await;
    assert_eq!(reason, "Pending");
    assert!(message.contains(&format!("{ns}/ci-only")), "{message}");
    for name in ["ci-only", "anyone"] {
        policies.delete(name, &DeleteParams::default()).await.unwrap();
    }
    eventually("Cloudflare Access objects gone", || async {
        (fake.access_apps().is_empty() && fake.access_policies().is_empty() && fake.service_tokens().is_empty())
            .then_some(())
    })
    .await;

    accounts.delete(&account, &DeleteParams::default()).await.unwrap();
    Api::<Namespace>::all(client.clone()).delete(&ns, &DeleteParams::default()).await.unwrap();
    operator.abort();
}

fn gateway_api(client: &kube::Client, ns: Option<&str>, ar: &kube::api::ApiResource) -> Api<DynamicObject> {
    match ns {
        Some(ns) => Api::namespaced_with(client.clone(), ns, ar),
        None => Api::all_with(client.clone(), ar),
    }
}

/// `(status, reason, message)` of a condition in a dynamic object's `status.<path>.conditions`.
fn dyn_condition(conditions: &Value, type_: &str) -> Option<(String, String, String)> {
    condition(&Some(json!({ "conditions": conditions })), type_)
}

/// Our entry in an HTTPRoute's `status.parents`.
async fn route_parent(api: &Api<DynamicObject>, name: &str) -> Option<Value> {
    let r = api.get(name).await.ok()?;
    r.data["status"]["parents"]
        .as_array()?
        .iter()
        .find(|p| p["controllerName"] == json!("tunnelgate.geeko.me/tunnel"))
        .cloned()
}

async fn wait_route_parent(api: &Api<DynamicObject>, name: &str, type_: &str, want: &str) -> (String, String, String) {
    eventually(&format!("HTTPRoute {name} {type_}={want}"), || async {
        let c = dyn_condition(&route_parent(api, name).await?["conditions"], type_)?;
        (c.0 == want).then_some(c)
    })
    .await
}

#[tokio::test]
async fn gateway_api_adapter() {
    use tunnelgate_operator::gateway::{gateway_class_resource, gateway_resource, httproute_resource};
    let Some((client, fake, _cluster_id, ns, operator)) = start().await else { return };
    let apps_ns = format!("{ns}-apps");
    let namespaces: Api<Namespace> = Api::all(client.clone());
    apply(
        &namespaces,
        json!({ "apiVersion": "v1", "kind": "Namespace", "metadata": { "name": apps_ns, "labels": { "team": "apps" } } }),
    )
    .await;
    let tunnels: Api<Tunnel> = Api::namespaced(client.clone(), &ns);
    let classes = gateway_api(&client, None, &gateway_class_resource());
    let gateways = gateway_api(&client, Some(&ns), &gateway_resource());
    let routes = gateway_api(&client, Some(&ns), &httproute_resource());
    let app_routes = gateway_api(&client, Some(&apps_ns), &httproute_resource());
    let tunnel_routes: Api<TunnelRoute> = Api::namespaced(client.clone(), &ns);
    let app_tunnel_routes: Api<TunnelRoute> = Api::namespaced(client.clone(), &apps_ns);
    for (namespace, name) in [(&ns, "demo"), (&apps_ns, "app")] {
        apply(
            &Api::<Service>::namespaced(client.clone(), namespace),
            json!({ "apiVersion": "v1", "kind": "Service", "metadata": { "name": name },
                    "spec": { "selector": { "app": name }, "ports": [{ "port": 80 }] } }),
        )
        .await;
    }

    apply(
        &tunnels,
        json!({
            "apiVersion": "tunnelgate.geeko.me/v1alpha1", "kind": "Tunnel", "metadata": { "name": "main" },
            "spec": { "cloudflare": { "accountId": ACCOUNT_ID, "credentialsSecretRef": { "name": "cloudflare-api" } } },
        }),
    )
    .await;
    let tunnel_id =
        eventually("tunnel ID in status", || async { tunnels.get("main").await.ok()?.status?.tunnel_id }).await;
    fake.set_connections(&tunnel_id, 1);

    // Our class and a foreign one.
    let class = format!("{ns}-tunnelgate");
    let foreign = format!("{ns}-other");
    for (name, controller) in [(&class, "tunnelgate.geeko.me/tunnel"), (&foreign, "example.com/other")] {
        apply(
            &classes,
            json!({ "apiVersion": "gateway.networking.k8s.io/v1", "kind": "GatewayClass", "metadata": { "name": name },
                    "spec": { "controllerName": controller } }),
        )
        .await;
    }
    eventually("GatewayClass accepted", || async {
        let c = classes.get(&class).await.ok()?;
        let (s, _, _) = dyn_condition(&c.data["status"]["conditions"], "Accepted")?;
        (s == "True").then_some(())
    })
    .await;

    // A Gateway: listener "web" for this namespace on *.example.org, "apps" for team=apps namespaces
    // on *.apps.example.org.
    let gateway = |class: &str, name: &str| {
        json!({
            "apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
            "metadata": { "name": name },
            "spec": { "gatewayClassName": class,
                      "infrastructure": { "parametersRef": { "group": "tunnelgate.geeko.me", "kind": "Tunnel", "name": "main" } },
                      "listeners": [
                { "name": "web", "port": 80, "protocol": "HTTP", "hostname": "*.example.org" },
                { "name": "apps", "port": 8080, "protocol": "HTTP", "hostname": "*.apps.example.org",
                  "allowedRoutes": { "namespaces": { "from": "Selector", "selector": { "matchLabels": { "team": "apps" } } } } },
            ] },
        })
    };
    apply(&gateways, gateway(&class, "gw")).await;
    apply(&gateways, gateway(&foreign, "foreign")).await;

    // An HTTPRoute in the Gateway's namespace: one TunnelRoute per path match.
    let web_host = format!("web-{ns}.example.org");
    apply(
        &routes,
        json!({
            "apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute", "metadata": { "name": "web" },
            "spec": {
                "parentRefs": [{ "name": "gw", "sectionName": "web" }],
                "hostnames": [web_host],
                "rules": [
                    { "matches": [{ "path": { "type": "PathPrefix", "value": "/api" } }],
                      "backendRefs": [{ "name": "demo", "port": 80 }] },
                    { "backendRefs": [{ "name": "demo", "port": 80 }] },
                ],
            },
        }),
    )
    .await;
    let (_, _, msg) = wait_route_parent(&routes, "web", "Accepted", "True").await;
    assert!(msg.contains("2 TunnelRoute(s)"), "{msg}");
    wait_route_parent(&routes, "web", "ResolvedRefs", "True").await;
    let web_uid = routes.get("web").await.unwrap().metadata.uid.unwrap();
    let generated = tunnel_routes
        .list(&ListParams::default().labels(&format!("tunnelgate.geeko.me/httproute-uid={web_uid}")))
        .await
        .unwrap();
    assert_eq!(generated.items.len(), 2);
    assert!(generated.iter().all(|r| r.owner_references()[0].kind == "HTTPRoute"));
    eventually("generated routes in the tunnel configuration", || async {
        let config = fake.live_tunnels().first()?.config.clone()?;
        let rules = config["ingress"].as_array()?.clone();
        rules.iter().any(|r| r["hostname"] == json!(web_host) && r["path"] == json!("^/api(/.*)?$")).then_some(())
    })
    .await;
    assert!(fake.dns_records("example.org").iter().any(|r| r["name"] == json!(web_host)));

    // Gateway status: accepted, programmed (the tunnel is connected), the tunnel CNAME as its
    // address, one route on "web".
    let gw_status = eventually("Gateway programmed", || async {
        let g = gateways.get("gw").await.ok()?;
        let (s, _, _) = dyn_condition(&g.data["status"]["conditions"], "Programmed")?;
        let web = g.data["status"]["listeners"].as_array()?.iter().find(|l| l["name"] == "web")?.clone();
        (s == "True" && web["attachedRoutes"] == json!(1)).then_some(g.data["status"].clone())
    })
    .await;
    assert_eq!(gw_status["addresses"][0]["value"], json!(format!("{tunnel_id}.cfargotunnel.com")));
    assert_eq!(dyn_condition(&gw_status["conditions"], "Accepted").unwrap().0, "True");

    // Settled: the adapter's controllers don't keep rewriting each other's status.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let versions = || async {
        (
            gateways.get("gw").await.unwrap().metadata.resource_version,
            routes.get("web").await.unwrap().metadata.resource_version,
        )
    };
    let before = versions().await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(versions().await, before, "Gateway and HTTPRoute unchanged in steady state");

    // From another namespace, through the listener that admits it; no grant needed for the tunnel.
    let app_host = format!("app-{ns}.apps.example.org");
    let app_route = |section: &str, backend: Value| {
        json!({
            "apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute", "metadata": { "name": format!("via-{section}") },
            "spec": { "parentRefs": [{ "name": "gw", "namespace": ns, "sectionName": section }],
                      "hostnames": [app_host], "rules": [{ "backendRefs": [backend] }] },
        })
    };
    apply(&app_routes, app_route("apps", json!({ "name": "app", "port": 80 }))).await;
    wait_route_parent(&app_routes, "via-apps", "Accepted", "True").await;
    let generated = app_tunnel_routes.list(&ListParams::default()).await.unwrap();
    let tr = generated.items.first().expect("generated TunnelRoute in the route's namespace").name_any();
    wait_route(&app_tunnel_routes, &tr, "Ready", "True").await;

    // A listener that doesn't admit the namespace.
    apply(&app_routes, app_route("web", json!({ "name": "app", "port": 80 }))).await;
    let (_, reason, _) = wait_route_parent(&app_routes, "via-web", "Accepted", "False").await;
    assert_eq!(reason, "NotAllowedByListeners");

    // A backend in another namespace needs a grant for HTTPRoutes.
    let cross = json!({
        "apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute", "metadata": { "name": "cross" },
        "spec": { "parentRefs": [{ "name": "gw", "namespace": ns, "sectionName": "apps" }],
                  "hostnames": [format!("cross-{ns}.apps.example.org")],
                  "rules": [{ "backendRefs": [{ "name": "demo", "namespace": ns, "port": 80 }] }] },
    });
    apply(&app_routes, cross).await;
    let (_, reason, msg) = wait_route_parent(&app_routes, "cross", "ResolvedRefs", "False").await;
    assert_eq!(reason, "RefNotPermitted");
    assert!(msg.contains("HTTPRoutes from"), "{msg}");
    let reference_grants = Api::<DynamicObject>::namespaced_with(
        client.clone(),
        &ns,
        &tunnelgate_operator::grants::reference_grant_resource(),
    );
    apply(
        &reference_grants,
        json!({
            "apiVersion": "gateway.networking.k8s.io/v1beta1", "kind": "ReferenceGrant", "metadata": { "name": "apps-to-demo" },
            "spec": { "from": [{ "group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "namespace": apps_ns }],
                      "to": [{ "group": "", "kind": "Service", "name": "demo" }] },
        }),
    )
    .await;
    wait_route_parent(&app_routes, "cross", "ResolvedRefs", "True").await;

    // A Gateway using a Tunnel in another namespace (only possible with the annotation:
    // parametersRef is local) needs a grant for Gateways.
    let app_gateways = gateway_api(&client, Some(&apps_ns), &gateway_resource());
    let mut remote = gateway(&class, "remote");
    remote["spec"].as_object_mut().unwrap().remove("infrastructure");
    remote["metadata"]["annotations"] = json!({ "tunnelgate.geeko.me/tunnel": format!("{ns}/main") });
    apply(&app_gateways, remote).await;
    let gateway_cond = |name: &'static str, want: &'static str| {
        let api = app_gateways.clone();
        async move {
            eventually(&format!("Gateway {name} Accepted={want}"), || async {
                let g = api.get(name).await.ok()?;
                let c = dyn_condition(&g.data["status"]["conditions"], "Accepted")?;
                (c.0 == want).then_some(c)
            })
            .await
        }
    };
    let (_, reason, _) = gateway_cond("remote", "False").await;
    assert_eq!(reason, "RefNotPermitted");
    // parametersRef must point at a Tunnel.
    let mut bad = gateway(&class, "bad-params");
    bad["spec"]["infrastructure"]["parametersRef"] = json!({ "group": "", "kind": "ConfigMap", "name": "main" });
    apply(&app_gateways, bad).await;
    let (_, reason, msg) = gateway_cond("bad-params", "False").await;
    assert_eq!(reason, "InvalidParameters", "{msg}");
    apply(
        &Api::<tunnelgate_api::v1alpha1::RouteGrant>::namespaced(client.clone(), &ns),
        json!({
            "apiVersion": "tunnelgate.geeko.me/v1alpha1", "kind": "RouteGrant", "metadata": { "name": "apps-gateways" },
            "spec": { "from": [{ "group": "gateway.networking.k8s.io", "kind": "Gateway", "namespace": apps_ns }],
                      "to": [{ "group": "tunnelgate.geeko.me", "kind": "Tunnel", "name": "main" }] },
        }),
    )
    .await;
    gateway_cond("remote", "True").await;

    // Unsupported features are reported, not dropped.
    apply(
        &routes,
        json!({
            "apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute", "metadata": { "name": "filtered" },
            "spec": { "parentRefs": [{ "name": "gw" }], "hostnames": [format!("f-{ns}.example.org")],
                      "rules": [{ "filters": [{ "type": "RequestHeaderModifier",
                                                "requestHeaderModifier": { "set": [{ "name": "x", "value": "y" }] } }],
                                  "backendRefs": [{ "name": "demo", "port": 80 }] }] },
        }),
    )
    .await;
    let (_, reason, msg) = wait_route_parent(&routes, "filtered", "Accepted", "False").await;
    assert_eq!(reason, "UnsupportedValue");
    assert!(msg.contains("filters"), "{msg}");

    // A hand-made TunnelRoute naming the Gateway gets no more than an HTTPRoute would.
    apply(
        &app_tunnel_routes,
        json!({
            "apiVersion": "tunnelgate.geeko.me/v1alpha1", "kind": "TunnelRoute",
            "metadata": { "name": "sneaky", "annotations": { "tunnelgate.geeko.me/gateway": format!("{ns}/gw") } },
            "spec": { "tunnelRef": { "name": "main", "namespace": ns }, "hostname": format!("sneaky-{ns}.example.org"),
                      "service": { "status": 200 } },
        }),
    )
    .await;
    let (_, reason, msg) = wait_route(&app_tunnel_routes, "sneaky", "Accepted", "False").await;
    assert_eq!(reason, "RefNotPermitted");
    assert!(msg.contains("no listener"), "{msg}");

    // Gateways of other classes are left alone.
    assert!(gateways.get("foreign").await.unwrap().data["status"]["listeners"].is_null());

    // One HTTPRoute on our Gateway and a foreign one (split horizon): published through ours only,
    // and the other implementation's status.parents entry survives our status writes.
    let shared_host = format!("shared-{ns}.example.org");
    let shared = |path: &str| {
        json!({
            "apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute", "metadata": { "name": "shared" },
            "spec": { "parentRefs": [{ "name": "gw", "sectionName": "web" }, { "name": "foreign", "sectionName": "web" }],
                      "hostnames": [shared_host],
                      "rules": [{ "matches": [{ "path": { "type": "PathPrefix", "value": path } }],
                                  "backendRefs": [{ "name": "demo", "port": 80 }] }] },
        })
    };
    apply(&routes, shared("/")).await;
    wait_route_parent(&routes, "shared", "Accepted", "True").await;
    // What the other implementation writes: its own entry, keeping everyone else's.
    let foreign_entry = json!({
        "parentRef": { "name": "foreign", "sectionName": "web" }, "controllerName": "example.com/other",
        "conditions": [{ "type": "Accepted", "status": "True", "reason": "Accepted", "message": "",
                         "lastTransitionTime": "2026-01-01T00:00:00Z" }],
    });
    eventually("foreign status entry written", || async {
        let r = routes.get("shared").await.ok()?;
        let mut parents = r.data["status"]["parents"].as_array().cloned().unwrap_or_default();
        parents.retain(|p| p["controllerName"] != json!("example.com/other"));
        parents.push(foreign_entry.clone());
        let patch =
            json!({ "metadata": { "resourceVersion": r.resource_version() }, "status": { "parents": parents } });
        routes.patch_status("shared", &PatchParams::default(), &Patch::Merge(patch)).await.ok().map(|_| ())
    })
    .await;
    // A spec change makes us rewrite our entry (new observedGeneration).
    apply(&routes, shared("/v2")).await;
    let generation = routes.get("shared").await.unwrap().metadata.generation.unwrap();
    let parents = eventually("our entry updated for the new generation", || async {
        let r = routes.get("shared").await.ok()?;
        let ours = route_parent(&routes, "shared").await?;
        let accepted = ours["conditions"].as_array()?.iter().find(|c| c["type"] == "Accepted")?.clone();
        (accepted["observedGeneration"] == json!(generation) && accepted["status"] == "True")
            .then(|| r.data["status"]["parents"].as_array().cloned())?
    })
    .await;
    assert_eq!(parents.len(), 2, "{parents:?}");
    // The API server fills in parentRef group and kind, so compare the rest.
    let kept = parents.iter().find(|p| p["controllerName"] == json!("example.com/other"));
    assert!(
        kept.is_some_and(|p| p["parentRef"]["name"] == "foreign" && p["conditions"] == foreign_entry["conditions"]),
        "foreign entry kept: {parents:?}"
    );
    let shared_uid = routes.get("shared").await.unwrap().metadata.uid.unwrap();
    let shared_label = format!("tunnelgate.geeko.me/httproute-uid={shared_uid}");
    // The "/" route from the first generation goes away once its finalizer has run.
    let generated = eventually("one TunnelRoute, from our parent only", || async {
        let items = tunnel_routes.list(&ListParams::default().labels(&shared_label)).await.ok()?.items;
        (items.len() == 1).then(|| items.into_iter().next())?
    })
    .await;
    assert_eq!(generated.annotations().get("tunnelgate.geeko.me/gateway"), Some(&format!("{ns}/gw")));
    assert!(gateways.get("foreign").await.unwrap().data["status"]["listeners"].is_null());

    // Dropping a rule deletes its TunnelRoute; deleting the HTTPRoute deletes the rest.
    apply(
        &routes,
        json!({
            "apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute", "metadata": { "name": "web" },
            "spec": { "parentRefs": [{ "name": "gw", "sectionName": "web" }], "hostnames": [web_host],
                      "rules": [{ "backendRefs": [{ "name": "demo", "port": 80 }] }] },
        }),
    )
    .await;
    let uid_label = format!("tunnelgate.geeko.me/httproute-uid={web_uid}");
    eventually("the /api TunnelRoute deleted", || async {
        let n = tunnel_routes.list(&ListParams::default().labels(&uid_label)).await.ok()?.items.len();
        (n == 1).then_some(())
    })
    .await;
    routes.delete("web", &DeleteParams::default()).await.unwrap();
    eventually("generated TunnelRoutes garbage-collected", || async {
        tunnel_routes.list(&ListParams::default().labels(&uid_label)).await.ok()?.items.is_empty().then_some(())
    })
    .await;
    eventually("hostname gone from Cloudflare", || async {
        (!fake.dns_records("example.org").iter().any(|r| r["name"] == json!(web_host))).then_some(())
    })
    .await;

    for c in [&class, &foreign] {
        classes.delete(c, &DeleteParams::default()).await.unwrap();
    }
    for n in [&apps_ns, &ns] {
        namespaces.delete(n, &DeleteParams::default()).await.unwrap();
    }
    operator.abort();
}

/// What an operator upgrade (or a restart, or a restore without status) must not do: create or
/// change anything in Cloudflare for resources that are already in place.
#[tokio::test]
async fn takeover_writes_nothing() {
    let Some((client, fake, cluster_id, ns, operator)) = start().await else { return };
    let services: Api<Service> = Api::namespaced(client.clone(), &ns);
    let tunnels: Api<Tunnel> = Api::namespaced(client.clone(), &ns);
    let routes: Api<TunnelRoute> = Api::namespaced(client.clone(), &ns);
    let tokens: Api<AccessServiceToken> = Api::namespaced(client.clone(), &ns);
    let policies: Api<AccessPolicy> = Api::namespaced(client.clone(), &ns);
    let apps: Api<AccessApplication> = Api::namespaced(client.clone(), &ns);
    let host = format!("app-{ns}.example.org");
    let cf = json!({ "accountId": ACCOUNT_ID, "credentialsSecretRef": { "name": "cloudflare-api" } });

    for obj in [json!({ "apiVersion": "v1", "kind": "Service", "metadata": { "name": "app" },
                "spec": { "selector": { "app": "app" }, "ports": [{ "port": 80 }] } })]
    {
        apply(&services, obj).await;
    }
    apply(
        &tunnels,
        json!({ "apiVersion": "tunnelgate.geeko.me/v1alpha1", "kind": "Tunnel",
                            "metadata": { "name": "main" }, "spec": { "cloudflare": cf } }),
    )
    .await;
    let tunnel_id =
        eventually("tunnel ID in status", || async { tunnels.get("main").await.ok()?.status?.tunnel_id }).await;
    fake.set_connections(&tunnel_id, 1);
    apply(
        &routes,
        json!({ "apiVersion": "tunnelgate.geeko.me/v1alpha1", "kind": "TunnelRoute",
                           "metadata": { "name": "app" },
                           "spec": { "tunnelRef": { "name": "main" }, "hostname": host,
                                     "service": { "backendRef": { "name": "app", "port": 80 } } } }),
    )
    .await;
    apply(
        &tokens,
        json!({ "apiVersion": "tunnelgate.geeko.me/v1alpha1", "kind": "AccessServiceToken",
                           "metadata": { "name": "ci" }, "spec": { "cloudflare": cf, "secretName": "ci-token" } }),
    )
    .await;
    apply(
        &policies,
        json!({ "apiVersion": "tunnelgate.geeko.me/v1alpha1", "kind": "AccessPolicy",
                             "metadata": { "name": "ci" },
                             "spec": { "cloudflare": cf, "decision": "non_identity",
                                       "include": [{ "serviceTokens": [{ "name": "ci" }] }] } }),
    )
    .await;
    apply(
        &apps,
        json!({ "apiVersion": "tunnelgate.geeko.me/v1alpha1", "kind": "AccessApplication",
                         "metadata": { "name": "app" },
                         "spec": { "cloudflare": cf, "destinations": [host], "policies": [{ "name": "ci" }] } }),
    )
    .await;
    wait_cond(&tunnels, "main", "Ready", "True").await;
    wait_cond(&routes, "app", "Ready", "True").await;
    wait_cond(&tokens, "ci", "Ready", "True").await;
    wait_cond(&policies, "ci", "Ready", "True").await;
    wait_cond(&apps, "app", "Ready", "True").await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    operator.abort();
    let _ = operator.await;

    // A new operator process takes over.
    let secrets: Api<Secret> = Api::namespaced(client.clone(), &ns);
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), &ns);
    let versions = || async {
        vec![
            secrets.get("main-token").await.unwrap().resource_version(),
            secrets.get("ci-token").await.unwrap().resource_version(),
            deployments.get("main-cloudflared").await.unwrap().resource_version(),
        ]
    };
    let before = versions().await;
    let operator = takeover("restart", &client, &cluster_id, &fake, &apps, &routes).await;
    assert_eq!(versions().await, before, "restart: Secrets and Deployment untouched");
    operator.abort();
    let _ = operator.await;

    // Restored from a backup without status: IDs come back from the names and markers.
    let wipe = Patch::Merge(json!({ "status": null }));
    let pp = PatchParams::default();
    tunnels.patch_status("main", &pp, &wipe).await.unwrap();
    routes.patch_status("app", &pp, &wipe).await.unwrap();
    tokens.patch_status("ci", &pp, &wipe).await.unwrap();
    policies.patch_status("ci", &pp, &wipe).await.unwrap();
    apps.patch_status("app", &pp, &wipe).await.unwrap();
    let operator = takeover("status lost", &client, &cluster_id, &fake, &apps, &routes).await;
    wait_cond(&tokens, "ci", "Ready", "True").await;
    assert_eq!(status_field(&tunnels, "main", "tunnelId").await.as_deref(), Some(tunnel_id.as_str()));
    assert_eq!(versions().await, before, "status lost: Secrets and Deployment untouched");
    assert_eq!(fake.live_tunnels().len(), 1);
    assert_eq!(fake.service_tokens().len(), 1);
    assert_eq!(fake.access_policies().len(), 1);
    assert_eq!(fake.access_apps().len(), 1);

    let namespaces: Api<Namespace> = Api::all(client.clone());
    namespaces.delete(&ns, &DeleteParams::default()).await.unwrap();
    eventually_for("namespace gone", Duration::from_secs(120), || async {
        namespaces.get_opt(&ns).await.ok()?.is_none().then_some(())
    })
    .await;
    assert!(fake.live_tunnels().is_empty());
    assert!(fake.access_apps().is_empty());
    operator.abort();
}

/// Starts a new operator and checks that its first round writes nothing to Cloudflare.
async fn takeover(
    what: &str,
    client: &kube::Client,
    cluster_id: &str,
    fake: &FakeCloudflare,
    apps: &Api<AccessApplication>,
    routes: &Api<TunnelRoute>,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    fake.clear_log();
    let operator = spawn_operator(client, cluster_id, fake);
    wait_cond(apps, "app", "Ready", "True").await;
    wait_cond(routes, "app", "Ready", "True").await;
    // Let every controller finish its first round.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(!fake.requests().is_empty(), "{what}: the new operator reconciled");
    assert_eq!(fake.writes(), vec![], "{what}: no Cloudflare writes");
    operator
}
